# Design: Post-quantum WireGuard via Rosenpass

Status: draft
Related: [milestones.md](milestones.md)

## 1. Motivation

innernet peers connect over WireGuard, whose handshake authenticates and derives
keys using Curve25519 (X25519). That is not post-quantum secure: traffic
recorded today could be decrypted later by an adversary with a cryptographically
relevant quantum computer ("harvest now, decrypt later"). [Rosenpass](https://github.com/rosenpass/rosenpass)
is a companion protocol that runs alongside WireGuard, negotiates a symmetric
key using post-quantum-secure primitives, and periodically feeds that key into
WireGuard as a **preshared key (PSK)**. It does not replace the WireGuard
handshake — it strengthens it. Per the Rosenpass design goal, the combination
is "cryptographically no less secure than using WireGuard on its own," so
enabling it can only help.

This doc proposes adding optional Rosenpass support to innernet: the server
becomes a discovery channel for peers' Rosenpass public keys/endpoints (the
same role it already plays for WireGuard endpoints), and the client manages a
per-interface Rosenpass process that keeps PSKs fresh. It also proposes a
`--rosenpass-permissive`-style fallback so a mixed fleet (some peers upgraded,
some not) keeps working, modeled on NetBird's approach.

## 2. Background: what Rosenpass actually does

- Each peer has a **separate** Rosenpass keypair (not the WireGuard keypair).
  Rosenpass runs a companion UDP listener, negotiates keys with each configured
  peer, and refreshes the resulting secret roughly every two minutes.
- The reference implementation ([rosenpass/rosenpass](https://github.com/rosenpass/rosenpass))
  is a Rust project using post-quantum KEMs (Classic McEliece + Kyber, hybrid
  with classical crypto) via `liboqs`. It ships an `rp` wrapper that can drive
  WireGuard directly, and a lower-level `rosenpass` binary for other
  integrations (e.g. writing the derived key to a file instead of calling
  `wg` itself).
- By convention, if a Rosenpass instance listens on UDP port `N`, the
  associated WireGuard interface listens on `N+1`. There is no hard
  client/server distinction — an instance either has a configured
  `listen`/endpoint (accepts connections) or doesn't (dials out).
- The output is applied to WireGuard purely as a PSK
  (`wg set <if> peer <pubkey> preshared-key <file>`); nothing else about the
  WireGuard config changes.
- **Known vulnerability, fixed upstream**: rosenpass versions before **0.2.1**
  did not validate buffer size when decoding messages, allowing a malformed
  UDP packet to crash the process (remote DoS) —
  [CVE-2023-53157](https://osv.dev/vulnerability/CVE-2023-53157) /
  GHSA-624c-2h52-gf7f, CVSS 7.5. Any vendored version **must** be pinned to
  ≥ 0.2.1 (latest at time of writing: 0.2.3); this is a hard M0 gate (see
  milestones.md), not just a "keep it updated" suggestion, and the M7 security
  pass should include a regression test that a truncated/malformed packet to
  the Rosenpass listener doesn't panic the process.

### 2.1 Prior art: how NetBird integrated it

NetBird's writeup ([how-we-integrated-rosenpass](https://netbird.io/knowledge-hub/how-we-integrated-rosenpass),
[docs](https://docs.netbird.io/client/post-quantum-cryptography)) is the
closest existing integration into a WireGuard mesh coordinator, and it maps
well onto innernet's architecture:

- **Key/endpoint exchange piggybacks on existing peer discovery.** NetBird
  extended its existing signaling exchange (the same channel that already
  carries WireGuard pubkeys/endpoints) to also carry each peer's Rosenpass
  public key. It deliberately did **not** build separate NAT traversal for
  Rosenpass — the Rosenpass endpoint just points at the peer's already-known
  WireGuard-reachable address.
- **Interim PSK.** Before the first Rosenpass exchange completes, both sides
  independently derive a deterministic placeholder PSK by lexicographically
  ordering the two peers' Rosenpass public keys and hashing the result (this
  is confirmed from NetBird's actual source,
  [`client/internal/rosenpass/seed.go`](https://github.com/netbirdio/netbird/blob/main/client/internal/rosenpass/seed.go)
  — a `DeterministicSeedKey()` producing a 32-byte PSK — rather than anything
  ad hoc like truncating one side's key). Both peers computing over the same
  sorted pair converge on an identical value with no round trip. This lets the
  WireGuard tunnel come up immediately instead of blocking on the PQ handshake,
  at the cost of that window not being PQ-secure — NetBird's docs describe
  WireGuard's own handshake-session lifetime as keeping a "no real PSK yet"
  window open for several minutes at connection start, which this interim key
  only shortens, not eliminates. innernet doesn't need bit-for-bit
  compatibility with NetBird's exact hash/ordering — only that its own two
  peers derive the same value — but should keep the same "sort, don't pick a
  side" shape to avoid the two ends silently deriving different keys due to
  which one dialed first.
- **Applying the PSK doesn't disrupt the tunnel.** Once Rosenpass produces a
  real key, the agent updates just the PSK field for that peer — a
  millisecond-scale operation, not a full reconnect.
- **`--rosenpass-permissive` is a client-side-only flag**, enabled together
  with `--enable-rosenpass`. It
  only changes what a Rosenpass-enabled peer does when the *other* side hasn't
  advertised Rosenpass support: fall back to a plain WireGuard connection
  (no PSK) instead of refusing to connect. There is no server-side equivalent
  in NetBird, because the coordinating server isn't in the data path and can't
  force two clients to run a local daemon — it can only tell them about each
  other.
- **Rosenpass is embedded, not spawned.** NetBird is written in Go, so it
  embeds a Go reimplementation (via the `cunicu` project) rather than shelling
  out to the Rust reference implementation, to avoid packaging a second
  binary.

Since innernet is already Rust, we don't have NetBird's language-mismatch
problem, and we should not repeat their choice by reimplementing Rosenpass's
protocol ourselves — that reimplements security-critical PQ crypto for no
benefit. See §5.7 for the resulting recommendation.

## 3. Relevant existing innernet architecture

(For readers unfamiliar with the codebase; skip to §5 if not.)

- **Workspace**: `wireguard-control` wraps the kernel/userspace WireGuard
  backends; `netlink-request`/`hostsfile` are its Linux/`/etc/hosts` helpers.
  `shared` holds cross-cutting types (`Peer`, `Cidr`, `InterfaceConfig`, CLI
  option structs) used by both `server` (binary `innernet-server`) and the
  client stack (`client-core` library + `client` binary `innernet`).
  `publicip` is a standalone IP-discovery helper.
- **Peer model** (`shared/src/types.rs:572`): `PeerContents` carries
  `name, ip, cidr_id, public_key, endpoint, persistent_keepalive_interval,
  is_admin, is_disabled, is_redeemed, invite_expires, candidates`. `Peer`
  wraps it with a DB `id`. The server's `/v1/user/state` endpoint
  (`server/src/api/user.rs:62`) returns a `State { peers, cidrs }`
  (`shared/src/types.rs:812`) — this is the entire "what should my interface
  look like" payload a client polls.
- **Candidate/endpoint discovery is the closest existing analog to what we're
  building.** `server/src/api/mod.rs` (`inject_endpoints`) merges each peer's
  self-reported endpoint override with the WireGuard-observed endpoint and a
  list of NAT candidates, entirely server-side, before the state response goes
  out. Clients report their own reachable addresses via
  `PUT /v1/user/candidates` and override endpoints via
  `PUT /v1/user/endpoint` (`server/src/api/user.rs:29-49`). A new Rosenpass
  pubkey/endpoint field would flow through the exact same
  report-then-broadcast pattern.
- **DB schema** (`server/src/db/peer.rs:13`): a flat SQLite `peers` table,
  columns listed in `COLUMNS` (`server/src/db/peer.rs:31`), read via
  `from_row` by fixed column index. New nullable columns are additive and
  don't require touching existing rows.
- **wireguard-control already supports PSKs.** `PeerConfigBuilder`
  (`wireguard-control/src/config.rs:42-181`) has `preshared_key: Option<Key>`
  with `set_preshared_key`/`unset_preshared_key`, and applying a builder
  updates settings "on top of" the existing peer config — it does not require
  removing/re-adding the peer. This is the one piece of plumbing the design
  needs that already exists end to end.
- **Client fetch loop** (`client-core/src/interface.rs:156` `fetch()`): pulls
  `State` from the server, diffs it against the live WireGuard device
  (`Device::diff`, producing `PeerDiff`/`PeerConfigBuilder`s per
  `shared/src/peer.rs:678-807`), applies the diff via
  `DeviceUpdate::apply`, updates the hosts file, persists to `DataStore`,
  then reports NAT candidates and runs NAT traversal. This is the natural
  place to also (a) push newly-discovered peers into a Rosenpass config and
  (b) reload/refresh that process.
- **Config storage**: `InterfaceConfig`/`ServerInfo`/`InterfaceInfo`
  (`shared/src/interface_config.rs`) hold the WireGuard keypair and server
  contact info as TOML at `<config_dir>/<interface>.conf`, mode `0o600`.
  `DataStore` (`client-core/src/data_store.rs`) caches the last-known peer/CIDR
  state per interface. Both are natural homes for Rosenpass keys/state,
  respectively.
- **Auth model**: the server trusts the *source IP* of a request as the peer's
  identity (`server/src/lib.rs:626` `get_session`) — it looks up
  `DatabasePeer::get_from_ip(remote_addr)`. This only works because the
  request already arrived over an authenticated WireGuard tunnel; the
  `X-Innernet-Server-Key` header is a sanity check that the client is talking
  to the right server, not the actual authentication. This matters for the
  security section below: Rosenpass strengthens the *WireGuard* tunnel's
  confidentiality/forward-secrecy, but the *API's* authentication model is
  unchanged and still ultimately rests on the classical WireGuard handshake
  until that specific peer↔server link also has a fresh Rosenpass PSK.
- **CLI conventions**: subcommands live in a `clap::Subcommand` enum in
  `client/src/main.rs`; per-command option structs live in
  `shared/src/types.rs` (e.g. `ListenPortOpts`, `NatOpts`, `NetworkOpts`) and
  are reused across `install`/`up`/`redeem-invite`/etc. via `#[clap(flatten)]`.
  A new `RosenpassOpts` (`--enable-rosenpass`, `--rosenpass-permissive`) fits
  this pattern directly, following the same shape as the recent
  `--listen-port` addition (`ListenPortOpts`, PR #409).
- **Testing infrastructure**: `server/src/test.rs` provides an in-process
  test server (SQLite in a tempdir, fixed test peers/CIDRs) used throughout
  `server/src/api/*.rs`'s `#[cfg(test)]` modules — this is where new endpoint
  tests belong. `docker-tests/` builds real Debian containers running actual
  `innernet`/`innernet-server` binaries over a Docker bridge network for
  full end-to-end coverage (`start-server.sh`, `start-client.sh`,
  `run-docker-tests.sh`); this is where a real two-peer Rosenpass handshake
  and permissive-mode fallback should be exercised.

## 4. Non-goals

- Not reimplementing the Rosenpass protocol/crypto in this repo.
- Not changing WireGuard key generation, the invite/redeem flow, or the
  server's peer-authorization/CIDR-visibility model.
- Not making Rosenpass mandatory for any existing network — it must be
  opt-in and fail open (see permissive mode) so current deployments are
  unaffected by default.
- Not solving NAT traversal for Rosenpass separately from what innernet
  already does for WireGuard (§5.5).

## 5. Proposed design

### 5.1 Data model & schema changes

Add to `PeerContents` (`shared/src/types.rs:572`), mirroring the existing
`candidates: Vec<Endpoint>` field's backward-compat pattern:

```rust
pub struct PeerContents {
    // ...existing fields...
    #[serde(default)]
    pub rosenpass_public_key: Option<String>, // base64, Rosenpass keypair pubkey (NOT the WG pubkey)
    #[serde(default)]
    pub rosenpass_addr: Option<Endpoint>,     // reuses the existing Endpoint type/parser
}
```

`#[serde(default)]` means old clients talking to a migrated server, and new
clients talking to an old server, both deserialize fine — the field is just
absent/`None`. This is the same trick already used for `candidates`.

Server DB: add nullable `rosenpass_public_key TEXT` and `rosenpass_addr TEXT`
columns to the `peers` table (`server/src/db/peer.rs:13`), append to
`COLUMNS`, thread through `create`/`update`/`from_row`. Because SQLite
`ALTER TABLE ADD COLUMN` is additive and the columns are nullable, this is a
plain migration with no backfill needed — see `server/src/db/mod.rs` for
where existing migrations are registered.

Extend `ServerCapabilities` (`shared/src/types.rs:824`) with a
`rosenpass: bool` flag, following the existing
`unspecified_ip_in_override_endpoint` precedent — lets a client detect "this
server understands Rosenpass fields" without a version bump, exactly how
`report_candidates` already probes for 404 to detect old servers
(`client-core/src/interface.rs:390`).

### 5.2 New server endpoints

Add `PUT /v1/user/rosenpass` to `server/src/api/user.rs`, structurally
identical to the existing `endpoint`/`candidates` handlers: authenticate via
the existing `Session`, validate the submitted public key (fixed-length
base64, same shape validation `Key::from_base64` already does for WireGuard
keys) and `rosenpass_addr` (reuses `Endpoint::from_str`), then
`DatabasePeer::update`. No new authorization model — visibility of the field
in `/v1/user/state` is already scoped correctly for free, because it rides
inside the existing `Peer`/`State` that `get_all_allowed_peers` (CIDR-scoped)
already filters (`server/src/db/peer.rs:293`).

### 5.3 Client: keypair lifecycle

On `install`/`redeem-invite`, generate a Rosenpass keypair (distinct from the
WireGuard keypair — Rosenpass explicitly requires its own keys) and store it
alongside the interface's data, e.g.
`<data_dir>/interfaces/<interface>/rosenpass/{public,secret}key`, secret key
mode `0o600` like the existing WireGuard private key handling in
`interface_config.rs:104`. Register the public key + Rosenpass listen address
with the server via a new `RestClient` method
(`rest_client.rs`, alongside `create_peer`/`get_peers`), called once at
install time and re-synced on `up` (mirrors how `report_candidates` re-reports
on every `fetch`).

### 5.4 Client: process lifecycle

Run one Rosenpass process per innernet interface, lifecycle tied to
`wg::up`/`wg::down` (`client-core/src/interface.rs:85-108`, `:402`
`interface_is_up`):

- On `up`: write a Rosenpass config listing every peer currently known from
  the last fetched `State` (public key + `rosenpass_addr`, skipping peers that
  haven't advertised one), start the process.
- On every subsequent `fetch()` (`interface.rs:156`): after applying the
  WireGuard peer diff, recompute the Rosenpass peer list from the new `State`
  and reload the process if the peer set or any peer's `rosenpass_addr`
  changed (same "only touch what changed" spirit as `PeerDiff`).
- On `down`: stop the process.

This slots into the same place `update_hosts_file` already gets called
(`interface.rs:264`), i.e. "things that get regenerated from the fetched
state."

### 5.5 Endpoint reuse (no separate NAT traversal) — and a critical asymmetry

Following NetBird's approach directly: don't build new NAT-traversal/endpoint
discovery for Rosenpass. A peer's `rosenpass_addr` should default to "same
host as my WireGuard endpoint, Rosenpass's own port," and reuse whatever
address the WireGuard endpoint/candidate system has already resolved. This
avoids duplicating `NatTraverse` (`client-core/src/nat.rs`) for a second
protocol.

**However — and this was not obvious from reading Rosenpass's source, only
discovered by actually running two real 0.2.3 processes against each other —
configuring *both* sides of a peer pair to dial each other is actively
broken, not merely redundant.** Each side ends up completing its own
independent handshake and deriving a **different** preshared key from the
other side — verified empirically: with both sides' peer entries carrying an
`endpoint`, the two `key_out` files stably (not transiently) disagreed, even
after the exchange settled. WireGuard requires an *identical* PSK configured
on both peers, so applying each side's own value would silently break that
tunnel with no visible error — the daemons look healthy, the files get
written, nothing logs a failure. Re-running with **exactly one** side's peer
entry carrying an `endpoint` (the other left unset, relying solely on its own
`listen` socket) produced identical keys on both sides, matching upstream's
own `tests/integration_test.rs`, which uses exactly this asymmetric shape.

The fix: for every peer pair, exactly one side must dial. Since both sides
must independently reach the same assignment without coordinating, it's
derived from something both already know — the lower peer ID always dials
the higher one (an arbitrary but deterministic, symmetric tie-break, the same
"sort, don't pick a side" principle already used for the interim PSK below).
Implemented in `client_core::rosenpass::sync`. A regression test
(`#[ignore]`d, requires the real binary —
`test_two_real_peers_converge_on_identical_psk_when_only_one_dials` in
`shared/src/rosenpass.rs`) runs two real processes end-to-end and asserts
their derived keys match, specifically to catch anyone "fixing" this back to
a symmetric configuration because it looks more natural.

A second, unrelated portability finding from the same testing: `listen`
should be **IPv4-any only**, not both IPv4-any and IPv6-any. Binding both on
the same port fails with "Address already in use" on Linux, because
dual-stack IPv6-any sockets also claim the IPv4 namespace there by default
(`IPV6_V6ONLY` defaults to off on Linux, on on macOS/OpenBSD) — there's no
single address pair that's portable across every OS this project supports.
IPv6-only peers can't dial a Rosenpass listener as a result; a known,
documented limitation rather than a silent gap.

### 5.6 Applying the PSK

**Resolved by the M0 spike, verified against the real 0.2.3 binary (not just
its source):** file handoff, not Rosenpass's direct `wg set` integration.
Rosenpass writes each peer's derived key, base64-encoded, to a `key_out` file
on every exchange, and separately prints
`output-key peer <id> key-file <path> exchanged|stale` to stdout — the
"exchanged"/"stale" distinction matters and isn't optional to observe:
upstream overwrites the *same* `key_out` file with random bytes on `stale`
(invalidating a dropped session), so the file's raw contents alone can't
distinguish a genuine PSK from that random overwrite. innernet redirects the
daemon's stdout to a persistent log file (see §5.4) and only ever applies a
key read after an `exchanged` line names that exact path.

Once read, the key is applied via
`PeerConfigBuilder::new(&pubkey).set_preshared_key(key)` +
`DeviceUpdate::new().add_peer(builder).apply(...)` — no interface disruption,
since wireguard-control merges peer settings onto the existing peer rather
than replacing it. Rosenpass's alternative direct-`wg`-integration mode
(`wg` field in its peer config, calling `wg set ... preshared-key /dev/stdin`
itself) was rejected: it requires the `wg` CLI tool as an extra packaging
dependency innernet doesn't otherwise need (wireguard-control talks to the
kernel directly via netlink), and it would apply PSKs through a second,
less-controlled code path outside innernet's own choke point for peer config.

Apply an **interim PSK** the same way NetBird does — a value both sides can
derive independently from the two Rosenpass public keys before the first
real exchange completes — so the tunnel isn't blocked waiting on Rosenpass.
Document (per NetBird's own admission) that this interim window is not
PQ-secure.

### 5.7 Subprocess vs. embedding

Recommendation: **shell out to the upstream `rosenpass` Rust binary as a
managed child process**, version-pinned (vendored source or pinned release
tag, analogous to how `wireguard-control` vendors the embeddable WireGuard C
library), rather than pulling it in as a Cargo library dependency or
reimplementing it.

Rationale:
- Rosenpass's own recommended deployment model is a companion process
  communicating over a defined boundary (config file in, PSK file/hook out) —
  we're not fighting the grain by doing the same.
- Running the newest, least-battle-tested crypto code (liboqs bindings, a
  young protocol) in a separate OS process is a meaningful security boundary
  for defense-in-depth, independent of Rust's memory safety guarantees for
  *logic* bugs and protocol issues, even though it isn't the privilege-boundary
  NetBird's Go embedding foreclosed.
- We inherit upstream security fixes by bumping a pinned version, rather than
  needing to track a library API that (per its own repo) is still stabilizing.
- If upstream later ships a stable, embeddable Rust crate, this can be
  revisited — the architecture above (config generation from `State`, PSK
  application via `PeerConfigBuilder`) doesn't change either way.

### 5.8 Permissive mode & flags

New CLI options (`shared/src/types.rs`, alongside `NatOpts`/`NetworkOpts`):

```rust
pub struct RosenpassOpts {
    #[clap(long = "enable-rosenpass")]
    pub enable_rosenpass: bool,

    #[clap(long = "rosenpass-permissive", requires = "enable_rosenpass")]
    pub rosenpass_permissive: bool,
}
```

(Matching NetBird's flag names, since that's what operators coming from
NetBird will already expect — see §2.1.)

Semantics: with Rosenpass enabled but *not* permissive, a peer with no
advertised `rosenpass_public_key_hash` is treated as **unreachable** (no
WireGuard peer entry is created for it) — this matches NetBird's documented
"connections will fail" behavior and is the strict/compliance mode. With
`--rosenpass-permissive`, such peers get a normal WireGuard peer entry with
no PSK, i.e. today's behavior, while peers that *do* advertise Rosenpass still
get PQ protection.

Implemented as `client_core::interface::apply_rosenpass_visibility_policy`,
called from `fetch()` right before diffing against the WireGuard device —
**not** inside `PeerDiff`/`peer_config_builder` (`shared/src/types.rs:715`,
the actual location of that logic — not `shared/src/peer.rs` as an earlier
draft of this doc said) as originally planned. A simpler mechanism was found
while implementing: the server already makes a disabled peer "disappear" by
filtering it out of `/state` at the SQL level (never present-but-flagged,
see `server/src/db/peer.rs`'s `get_all_allowed_peers`), and `Device::diff`'s
existing add/remove logic already turns a peer's absence into a clean
removal. Strict mode reuses that exact mechanism — removing peers with no
advertised key from the list *before* it reaches `diff()` — rather than
teaching `PeerDiff` a new code path.

**Mobile/non-innernet peers make permissive mode a permanent requirement, not
a transitional one.** There is no Rosenpass client for Android or iOS, and
innernet itself has no path today for a non-innernet WireGuard client (e.g.
the stock Android/iOS WireGuard app) to join a mesh at all — see §8. Any
network that includes phone peers, now or via a future static-config-export
feature, can **never** have those peers advertise a `rosenpass_public_key`.
Strict mode would not just delay those peers until they "upgrade" — it would
permanently and silently exclude every phone from the mesh, since there is
nothing for them to upgrade to. Operators with mobile peers must run
permissive mode indefinitely for that reason alone, independent of any
rollout/migration timeline; this should be called out in the user-facing docs
(M8) so it isn't mistaken for a temporary interop shim.

There is intentionally **no server-side enforcement flag** that blocks
non-compliant peers at the coordination layer — the server isn't in the data
path and can't force a client to run a local process (§2.1). What the server
*can* usefully offer is an **advisory, per-network policy bit** (e.g.
`require_rosenpass` on the `networks`/CIDR-root config) that `innernet show`
and `innernet-server`'s admin tooling surface as a warning for peers that
haven't enabled it — visibility, not enforcement.

### 5.9 Server as a mesh peer

`innernet-server` itself holds a WireGuard peer identity in the mesh (it's
`peers.id` row zero / the "innernet-server" peer seen in
`server/src/api/user.rs` tests). For full protection of the
coordination-API traffic itself (§3, auth model note), the server process
runs the same Rosenpass process-management logic as the client
(`server/src/rosenpass.rs`) — the daemon-lifecycle and PSK-application
pieces (`ensure_daemon_running`/`apply_psks`) are factored into `shared` so
both `client-core` and `server` call the identical code, differing only in
how they source data: the server has every peer's row (including its own)
directly in its database, so registering its own key or reading a peer's key
is a direct DB read/write, never an HTTP round trip.

**The server does not apply strict/permissive peer-exclusion to its own
device**, even without `--rosenpass-permissive` — this is a deliberate,
narrower scope than a first reading of "run the same logic as the client"
might suggest. Client-side strict mode (§5.8) excludes a peer from *that
client's* WireGuard interface, which only affects peer-to-peer connectivity
between two mesh members. Doing the equivalent on the server would make a
peer unable to reach the coordination API *at all* — breaking invite
redemption and state fetching for a reason unrelated to whether that
specific link happens to have post-quantum protection yet. That's a far more
severe and simply wrong consequence, so the server's Rosenpass sync only
ever adds PSK protection to server↔peer links; it never gates a peer's
visibility or reachability based on Rosenpass status.

### 5.10 Static config export for non-innernet peers (e.g. mobile) — implemented

Not required for Rosenpass itself, but directly motivated by §5.8's finding
that mobile peers can never run Rosenpass and today have no way to join an
innernet mesh at all. Implemented (M9) as a small, independent client-side
feature:

- `--export-wg-conf` on `innernet add-peer` (`shared/src/types.rs`
  `AddPeerOpts`) renders a standard `wg-quick`-compatible `.conf`
  (`shared::wg_export::render_wg_quick_conf`) instead of the innernet-native
  `PeerInvitation`:
  - `[Interface]`: the newly generated `PrivateKey` and the peer's allocated
    `Address`, both already produced by `create_peer()`
    (`client-core/src/peer.rs`) via `PeerInvitation::interface_config()`, a
    small accessor added for this purpose. No `DNS`/`PostUp` — hostsfile-style
    name resolution only works for innernet-managed peers; peer names appear
    only as `#` comments in the exported file, for readability.
  - `[Peer]` blocks: one per entry in the same already-fetched peer list
    `add_peer()` uses to build a normal invitation — no extra server round
    trip. Each peer's `PublicKey`, `AllowedIPs` (that peer's own `/32` or
    `/128`, matching exactly what `PeerDiff`/`peer_config_builder`
    (`shared/src/types.rs`) already computes for a normal client), and
    `Endpoint` when known (omitted, not defaulted to anything, when a peer
    has none yet). Disabled and not-yet-redeemed peers, and the exported
    peer's own entry, are excluded.
  - Never includes a Rosenpass field or PSK — an exported peer is, by
    construction, permissive-only (§5.8). The `require_rosenpass`
    "advisory policy bit" floated below was never actually built in this
    implementation (M1–M8's code has no such field), so there's no check to
    add here; the README documents the operational guidance instead.
- **Staleness is a first-class limitation, stated plainly, not an edge
  case.** Both the CLI's log output (at export and at refresh time) and the
  exported file's own header comment say this is a point-in-time snapshot
  with no auto-refresh. `innernet export-peer-config <interface> <path>`
  refreshes an already-exported file's `[Peer]` blocks from the current
  peer list, in place, without rotating its keys — implemented as a refresh
  of the *file* (via `shared::wg_export::parse_exported_interface`, which
  reads back the `[Interface]` section from a file this exporter itself
  produced), not a lookup by peer name as originally sketched: the private
  key was never sent to or stored by the server (the same property every
  other key in this design relies on), so there's no name-keyed lookup that
  could recover it — only the originally-exported file can.
- **Secret handling.** The rendered `.conf` contains a raw WireGuard private
  key in plaintext. `shared::wg_export::write_exported_conf` sets `0o600`
  before writing, matching `InterfaceConfig`'s existing discipline — an
  initial implementation missed this (defaulting to the OS's normal file
  permissions), caught by a permissions-asserting test before it shipped.
  QR code export (`--export-wg-conf-qr`) was not implemented in this pass.
- Entirely additive to `client/src/main.rs`'s existing `add_peer()` and a
  new `export-peer-config` subcommand — no new server endpoint, no schema
  change, and no dependency on any Rosenpass milestone (implemented after
  M8 here, but doesn't depend on it). See milestones.md M9.

## 6. Security considerations

- **Threat model delta**: Rosenpass adds forward secrecy / PQ resistance to
  the *transport* (WireGuard data plane) between two peers that both enable
  it. It does **not** by itself harden the innernet coordination API's
  authentication, which (§3) is IP-based over the existing tunnel — that only
  improves once the specific client↔server WireGuard link also carries a
  Rosenpass PSK (§5.9).
- **Key storage**: Rosenpass secret keys must never be sent to the server
  (only the public key + address are, exactly like the WireGuard model)
  and must be stored with the same `0o600`/owner-only discipline as the
  existing WireGuard private key (`interface_config.rs:104`,
  `chmod`/`ensure_dirs_exist` in `shared/src/lib.rs`).
- **New endpoint hardening**: `PUT /v1/user/rosenpass` needs the same input
  validation rigor as `PUT /v1/user/endpoint`/`candidates` — reject malformed
  base64/wrong-length keys, cap payload size, and reuse
  `subtle`'s constant-time comparison pattern already used for the server's
  own pubkey check (`server/src/lib.rs:637` `ct_eq`) for any new secret
  comparison this feature introduces.
- **No new SSRF surface**: `rosenpass_addr` is only ever consumed by other
  peers' local Rosenpass processes dialing out directly (mirroring how
  `Endpoint`/`candidates` already work) — the server never itself connects to
  a peer-supplied address, so this doesn't expand the existing candidate
  system's trust boundary.
- **Subprocess hardening — pinned version check implemented, privilege
  dropping NOT done, genuinely open.** `shared::rosenpass::check_rosenpass_version`
  now refuses to spawn a `rosenpass` binary older than 0.2.1 (verified
  against the real installed 0.2.3 binary), closing the "operator has an old
  binary" gap in CVE-2023-53157's mitigation. Running the child as an
  unprivileged user was investigated and deliberately **not** implemented:
  the child needs to read the secret key file (`0o600`, owned by whatever
  user runs `innernet`/`innernet-server`, frequently root) and write
  `key_out`/log/pid files back into the same directory, so naively dropping
  its privileges would either break those reads/writes or require first
  designing a shared-ownership model for the whole `rosenpass_dir` (e.g. a
  dedicated system group) — a real design task, not a one-line fix, and one
  that couldn't be validated in the environment this was implemented in (no
  root/CAP_NET_ADMIN available to test a live privilege-dropped process).
  Shipping an unvalidated privilege-drop risked silently breaking the
  feature rather than hardening it, so this remains explicitly open rather
  than half-implemented.
- **Fail-open, not fail-secure, by design** in permissive mode — document this
  tradeoff explicitly for operators (mirrors NetBird's own documented
  limitation) so it's a conscious choice per network, not a silent gap.
- **Static config export (§5.10) writes a plaintext private key to disk/QR.**
  Unlike every other key in this design, that key now leaves the machine that
  generated it by design (handed to a phone) — it should get the same
  `0o600`/owner-only file handling as `InterfaceConfig`, a loud CLI warning
  about the exposure, and no QR-to-image-file path by default (terminal
  rendering only) to reduce the chance of an accidental durable copy.
- **Testing plan** (detailed per-milestone in milestones.md):
  server-side unit tests for schema/serialization back-compat and
  CIDR-scoped visibility of the new fields (extending
  `server/src/api/user.rs`'s existing test module and `server/src/test.rs`
  fixtures); a real two-container `docker-tests/` scenario running actual
  `rosenpass` processes to verify PSK convergence and traffic continuity;
  a mixed-fleet scenario (one upgraded peer, one not) to verify permissive
  fallback and strict-mode blocking; and a security review pass (this repo's
  `/security-review` skill) focused on the new endpoint, the subprocess
  boundary, and key file permissions before the feature is enabled by
  default for any network.

## 7. Alternatives considered

- **Reimplement Rosenpass in Rust natively in this repo** (skip the
  subprocess). Rejected: duplicates security-critical PQ crypto that upstream
  already maintains and has had more scrutiny on; loses the ability to pick
  up upstream security fixes independently.
- **Embed a reimplementation like NetBird's Go/`cunicu` approach.** Rejected:
  innernet doesn't have NetBird's single-binary/cross-language constraint —
  we're already Rust, so shelling out to the upstream Rust implementation is
  strictly less risky than either reimplementing or embedding a second
  implementation.
- **Make Rosenpass mandatory network-wide with no fallback.** Rejected for
  the initial rollout: would make upgrading a live network a flag day
  (every peer must upgrade atomically), which doesn't fit how innernet
  networks are actually operated (peers added/upgraded independently over
  time). Permissive mode is the pragmatic default; strict mode remains
  available per-network for operators who want it.

## 8. Open questions / risks

- Exact vendored Rosenpass version/CLI surface (config file schema, whether
  a file-watch or exec-hook mechanism exists for PSK handoff) needs
  confirming against upstream during the milestone-0 spike — this doc's
  §5.6 intentionally leaves both sub-options open pending that.
- Whether `rosenpass_addr` needs its own port allocation story (default
  `wg_port + 1` per upstream convention) when the WireGuard listen port is
  randomized (`ListenPortOpts`) or behind NAT.
- Long-term: whether to also protect the coordination API's confidentiality
  independent of the mesh's WireGuard PSK (out of scope here; noted in §6).
- **Non-innernet WireGuard clients (e.g. the stock Android/iOS app) currently
  have no way to join an innernet mesh at all** — `innernet add-peer`
  produces an innernet-native invitation
  (`shared/src/interface_config.rs:18`), not a `wg-quick`-compatible static
  config. Proposed as its own client-side feature in §5.10 (tracked as M9);
  such peers are, by construction, permanently permissive-only (§5.8) and the
  exported config would go stale with no push mechanism as the mesh changes.
