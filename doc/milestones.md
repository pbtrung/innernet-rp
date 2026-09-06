# Milestones: Rosenpass integration

Companion to [design.md](design.md) — read that first for the full rationale.
Each milestone should land as its own PR(s) with tests, and should keep
`main` shippable throughout: the feature stays fully inert (no schema reads
matter, no new process spawned) until a network operator opts in, all the way
through M5.

## M0 — Spike: confirm upstream Rosenpass integration surface

Not user-facing; de-risks every later milestone's assumptions in design.md
§5.6/§5.7.

- Vendor/pin a specific `rosenpass` release, **≥ 0.2.1** (fixes
  [CVE-2023-53157](https://osv.dev/vulnerability/CVE-2023-53157), a
  remote-DoS-via-malformed-packet bug in earlier versions — non-negotiable
  floor, not just "use latest"; target the current stable 0.2.3 unless a
  newer release has shipped by implementation time). Source vendoring vs. a
  prebuilt binary fetched at build/package time — decide which fits this
  repo's existing `.deb`/`.rpm`/release process, see `release.sh` and the
  `package.metadata.deb`/`rpm` blocks in `server/Cargo.toml`/`client/Cargo.toml`.
- Confirm exact config file schema, CLI invocation, and whether a
  file-watch or exec-hook mechanism exists for PSK handoff (design.md §5.6
  options 1 vs 2).
- Manually reproduce, outside innernet: two local Rosenpass processes
  negotiating, feeding a PSK into two manually-configured WireGuard peers via
  `wireguard-control`'s existing `PeerConfigBuilder::set_preshared_key`, and
  confirm traffic keeps flowing when the PSK is swapped without touching
  `allowed_ips`/removing the peer.
- Write up findings as an update to design.md §5.6/§5.7 (resolve the two
  open sub-options) before starting M1.

**Acceptance**: a short writeup + a throwaway manual reproduction (doesn't
need to live in the repo) confirming the PSK-application mechanism works with
today's `wireguard-control` API with no interface disruption.

## M1 — Schema & API plumbing

- Add nullable `rosenpass_public_key`/`rosenpass_addr` columns to the
  `peers` table (`server/src/db/peer.rs`), threaded through
  `create`/`update`/`from_row`/`COLUMNS`.
- Add the two fields to `PeerContents` with `#[serde(default)]`
  (`shared/src/types.rs:572`).
- Add `rosenpass: bool` to `ServerCapabilities`
  (`shared/src/types.rs:824`, alongside `unspecified_ip_in_override_endpoint`).
- Add `PUT /v1/user/rosenpass` to `server/src/api/user.rs`, structurally
  matching the existing `endpoint`/`candidates` handlers, with input
  validation (key length/base64 shape, `Endpoint` parsing, payload size cap
  matching the existing 10-candidate cap's spirit).
- Tests (extend `server/src/api/user.rs`'s `#[cfg(test)]` module using the
  existing `test::Server` harness):
  - round-trip a peer's rosenpass fields through `/v1/user/rosenpass` then
    `/v1/user/state`;
  - old-shaped JSON (no rosenpass fields) still deserializes into
    `PeerContents` (back-compat);
  - a peer outside the requester's authorized CIDR set never has rosenpass
    fields leaked (same scoping test shape as
    `test_list_peers_for_developer_subcidr`);
  - malformed key/address input is rejected with 4xx, not a panic.

**Acceptance**: `cargo test --workspace --locked` green; a client on an old
binary can still talk to a migrated server and vice versa (verified by the
back-compat test above); no CLI/process-lifecycle behavior changed yet.

## M2 — Client keypair generation & registration

- Generate a Rosenpass keypair on `install`/`redeem-invite`, store secret key
  `0o600` under `<data_dir>/interfaces/<interface>/rosenpass/` (mirrors
  `interface_config.rs`'s handling of the WireGuard private key).
- Add a `RestClient` method to push the public key + `rosenpass_addr`
  (`client-core/src/rest_client.rs`, alongside `create_peer`), called once at
  install and re-synced on every `up`.
- `innernet show`: display whether the local interface and each visible peer
  has Rosenpass enabled (best-effort, no process running yet — this
  milestone is data-plumbing only).

**Acceptance**: `innernet install`/`redeem-invite` on a Rosenpass-flagged
network generates and registers a key; `innernet show` reflects it; no
WireGuard PSK is touched yet (that's M4).

## M3 — Rosenpass process lifecycle

- `RosenpassOpts` (`--enable-rosenpass`, `--rosenpass-permissive`) added to
  the relevant subcommands in `client/src/main.rs`
  (`install`/`up`/`redeem-invite`, matching how `NatOpts`/`NetworkOpts` are
  `#[clap(flatten)]`ed today).
- Spawn the managed Rosenpass child process on `up` using the peer list from
  the last fetched `State`; stop it on `down`
  (`client-core/src/interface.rs` `redeem_invite`/`fetch`, near the existing
  `wg::up`/`wg::down` calls).
- On every `fetch()`, regenerate the Rosenpass config from the new `State`
  and reload the process if the peer set or any peer's `rosenpass_addr`
  changed.
- Factor the process-lifecycle logic into `shared` (not `client-core`) per
  design.md §5.9, so M6 (server-as-peer) can reuse it without duplication.

**Acceptance**: on a real two-machine (or docker-tests) network with
`--enable-rosenpass`, both sides' Rosenpass processes start, see each other's
config, and negotiate — verified by process logs/exit status, independent of
whether the PSK is applied yet (that's M4).

## M4 — PSK application

- Wire the PSK-handoff mechanism decided in M0 into
  `PeerConfigBuilder::set_preshared_key` + `DeviceUpdate::apply`, applied
  without removing/re-adding the peer.
- Apply the deterministic interim PSK (derived from both sides' Rosenpass
  public keys, per design.md §5.6) immediately on peer add, before the first
  real Rosenpass exchange completes.
- `docker-tests/` scenario: two containers, both `--enable-rosenpass`,
  confirm (a) traffic flows immediately via the interim PSK, (b) the PSK
  changes after the first real Rosenpass exchange, (c) it continues rotating
  (~2 min cadence) without dropped traffic, (d) file/process permissions on
  the secret key and PSK handoff file are `0o600`/owner-only.

**Acceptance**: the `docker-tests/` scenario above passes reliably (run it
multiple times — this is the milestone most likely to be flaky, since it
depends on real timing/rotation); a captured packet trace or `wg show`
diff demonstrates the PSK actually changes over the test's lifetime.

## M5 — Permissive mode & mixed-fleet interop

- Implement the strict-vs-permissive branch in `PeerDiff`/
  `peer_config_builder` (`shared/src/peer.rs:715`): peers with no advertised
  `rosenpass_public_key` are skipped entirely in strict mode, get a normal
  no-PSK WireGuard entry in permissive mode.
- `docker-tests/` scenario: three peers — two with `--enable-rosenpass
  --rosenpass-permissive`, one plain/legacy — confirm the legacy peer
  connects fine to the permissive peers (no PSK) while the two
  Rosenpass-enabled peers still get PQ protection between themselves; and a
  second scenario without `--rosenpass-permissive` confirming the legacy peer
  is correctly excluded (strict mode).
- CLI docs/help text (`doc/innernet.8` source, `--help` output) explaining
  the fail-open tradeoff explicitly, per design.md §6.

**Acceptance**: both mixed-fleet scenarios above pass; this is the point at
which the feature is safe to recommend for real (partial) rollout on a live
network.

## M6 — Server as a mesh peer

- Apply the same process-lifecycle logic (factored into `shared` in M3) to
  `innernet-server` itself, so the coordination API's own WireGuard link can
  carry a Rosenpass PSK too (design.md §5.9).
- Extend `server/src/initialize.rs`/`lib.rs`'s direct `DeviceUpdate` calls
  to apply Rosenpass-derived PSKs the same way the client does.

**Acceptance**: on a Rosenpass-enabled network, `wg show` on the server
shows a non-empty, rotating PSK for enrolled peers, not just peer-to-peer.

## M7 — Security review & hardening

- Run this repo's `/security-review` skill against the full feature diff.
- Subprocess hardening pass per design.md §6 (capability dropping, restricted
  filesystem view for the Rosenpass child process, unprivileged user if
  feasible per the M0-selected handoff mechanism).
- Fuzz/property-test the new parsing paths (rosenpass key/address
  deserialization) the way `Endpoint`'s `FromStr` would warrant.
- Confirm the vendored version still resolves to ≥ 0.2.1
  ([CVE-2023-53157](https://osv.dev/vulnerability/CVE-2023-53157)) and add a
  regression test sending a truncated/malformed UDP packet at the Rosenpass
  listener, asserting the process doesn't panic/crash.
- Re-run `cargo clippy --workspace --locked --all-targets -- -D warnings` and
  the full `docker-tests/` suite as a final gate.

**Acceptance**: security review findings triaged (fixed or explicitly
accepted with rationale recorded); no outstanding high-severity findings on
the new endpoint, subprocess boundary, or key storage.

## M8 — Docs & release

- User-facing docs: README section, man page updates
  (`doc/innernet.8`, `doc/innernet-server.8` sources) and completions
  regenerated for the new flags.
- Changelog entry; decide and document the default (feature must ship
  opt-in/off by default per design.md §4).
- Tag release per existing `release.sh` process.

**Acceptance**: a new user following only the README/man pages can enable
Rosenpass on a fresh network end to end.

## M9 — Static config export for non-innernet peers (independent track)

Not part of the Rosenpass rollout and doesn't gate or depend on M0–M8 — can
ship before, after, or in parallel. Tracked here because it was motivated
directly by M5/§5.8's finding that mobile peers (no Rosenpass client exists
for Android/iOS) have no join path at all today, static or otherwise
(design.md §5.10).

- Add `--export-wg-conf <path>` (and optionally `--export-wg-conf-qr`) to
  `innernet add-peer` (`client/src/main.rs`), rendering a standard
  `wg-quick`-compatible `.conf` from the same `existing_peers`/
  `existing_cidrs` snapshot and freshly generated keypair `add_peer()`
  already produces (`client-core/src/peer.rs:37`), instead of an innernet
  `PeerInvitation`.
- Refuse (or loudly warn) if the target network/CIDR has `require_rosenpass`
  set (§5.8), since an exported peer can never satisfy it.
- Add `innernet export-peer-config <name>`: re-render a static config for an
  *already-registered* peer (no new keypair, no re-registration) so an
  operator can refresh a deployed phone's view of the mesh after peer/CIDR
  changes, without rotating its identity or breaking its current tunnel.
- CLI output must state plainly, every time, that the exported config is a
  point-in-time snapshot with no auto-refresh.
- Tests: round-trip the exported `.conf` through a real `wg-quick`/stock
  WireGuard client in `docker-tests/` (or the Android app manually) and
  confirm it can reach the mesh; confirm the `require_rosenpass` refusal;
  confirm secret-file permissions (`0o600`) on any saved output, and that the
  default QR path renders to the terminal only, not an image file.

**Acceptance**: a phone (or any stock WireGuard client) can join an innernet
network from a single exported config/QR code with no innernet client
installed; re-export reflects a since-changed peer list without touching the
phone's existing keys.
