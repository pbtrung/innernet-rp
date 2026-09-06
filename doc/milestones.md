# Milestones: Rosenpass integration

Companion to [design.md](design.md) — read that first for the full rationale.
Each milestone should land as its own PR(s) with tests, and should keep
`main` shippable throughout: the feature stays fully inert (no schema reads
matter, no new process spawned) until a network operator opts in, all the way
through M5.

## M0 — Spike: confirm upstream Rosenpass integration surface — DONE

Not user-facing; de-risked every later milestone's assumptions in design.md
§5.5/§5.6/§5.7. Resolved against the real `rosenpass` 0.2.3 binary (installed
via `cargo install rosenpass --locked --version 0.2.3`), not just its source:

- Pinned to **0.2.3** (≥ 0.2.1, fixing
  [CVE-2023-53157](https://osv.dev/vulnerability/CVE-2023-53157)).
- Confirmed the exact config schema (`shared::rosenpass::render_config`) is
  accepted by the real binary's own `validate` subcommand
  (`test_rendered_config_accepted_by_real_rosenpass_binary`).
- Confirmed the `key_out` file-handoff mechanism and its
  `output-key peer <id> key-file <path> exchanged|stale` stdout hook, by
  running two real processes end-to-end over loopback.
- Confirmed the real Classic McEliece 460896 key sizes (524160 raw /
  698880 base64 bytes for the public key) match what M1 already assumed.
- **Found two real bugs no amount of source-reading surfaced**, both now
  fixed and covered by `#[ignore]`d real-binary regression tests in
  `shared/src/rosenpass.rs` (run with `cargo test -- --ignored` after
  installing the binary):
  - Configuring both sides of a peer pair to dial each other makes each side
    derive a **different**, silently mismatched PSK — WireGuard would
    silently fail to handshake for that peer with no visible error. Fixed
    with a deterministic per-pair dial/listen tie-break (design.md §5.5).
  - Listening on both IPv4-any and IPv6-any on the same port fails outright
    on Linux (dual-stack conflict). Fixed by listening IPv4-any only, a
    documented limitation (design.md §5.5).
- Vendoring strategy (source vendoring vs. a prebuilt binary fetched at
  build/package time for `.deb`/`.rpm` packaging, see `release.sh`) is still
  open — deferred to M8 (docs & release), since it doesn't block functional
  development.

**Acceptance**: met. See `shared/src/rosenpass.rs`'s `#[ignore]`d tests for
the reproduction; design.md §5.5/§5.6 record the resolved decisions and the
two findings above.

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

## M3 — Rosenpass process lifecycle — DONE

- `RosenpassOpts` (`--enable-rosenpass`, `--rosenpass-permissive`) added to
  `install`/`up`/`fetch` in `client/src/main.rs`, flattened like
  `NatOpts`/`ListenPortOpts`.
- `shared::rosenpass::ensure_daemon_running` (re)starts the managed daemon
  whenever the rendered config changes or the previously-started process
  died — a full restart, not an incremental reload, since Rosenpass 0.2.3 has
  no reload mechanism (confirmed against its source: no signal handling, no
  `remove_peer`).
- `client_core::rosenpass::sync`, called from `fetch()` once the WireGuard
  peer list/listen port are known, builds the peer config from the just-
  fetched `State` (caching each peer's key on demand, keyed by hash) and
  calls `ensure_daemon_running`. Process-lifecycle logic lives in `shared`
  (not `client-core`) per design.md §5.9, so M6 can reuse it.
- Verified end-to-end against the real 0.2.3 binary (not docker-tests yet —
  those land in M4/M5's scenarios): two real processes negotiate and produce
  matching derived keys (see M0's two findings above, both fixed here).

**Acceptance**: met — both sides' Rosenpass processes start, see each
other's config, and negotiate, verified by real process runs and the
`#[ignore]`d tests in `shared/src/rosenpass.rs`.

## M4 — PSK application — mostly DONE (docker-tests scenario still open)

- `client_core::rosenpass::apply_psks` wires the PSK-handoff mechanism from
  M0 into `PeerConfigBuilder::set_preshared_key` + `DeviceUpdate::apply`,
  applied without removing/re-adding the peer, as its own follow-up device
  update after the main peer diff.
- A peer with no completed exchange yet gets `interim_preshared_key`
  (`shared::rosenpass`) applied immediately: both sides derive it
  independently from their sorted Rosenpass public keys (design.md §5.6),
  so the tunnel isn't left with zero PSK while waiting.
- Once a peer's exchange completes, `poll_new_events`'s `exchanged` line is
  what triggers reading its `key_out` file and applying the real key — a
  `stale` event is logged but deliberately does **not** touch the
  already-applied key (see design.md §5.6 on why the file's raw bytes alone
  can't distinguish the two cases).
- Covered by unit tests with synthetic log/event data (interim vs. real vs.
  stale branching) in `client-core/src/rosenpass.rs`, plus the real-binary
  convergence test from M3 that confirms the underlying mechanism (both
  sides' `key_out` files) actually produces applicable, matching keys.
- **Not yet done**: no real WireGuard interface was exercised end-to-end
  (this sandbox has no root/CAP_NET_ADMIN to create one) — the
  `DeviceUpdate`/`PeerConfigBuilder` calls themselves are exercised by
  wireguard-control's own existing test suite, but applying a
  rosenpass-derived key to a *live* interface and confirming traffic keeps
  flowing has not been verified. The `docker-tests/` scenario below (real
  containers, real interfaces) is what would close that gap and remains
  open:
  - two containers, both `--enable-rosenpass`, confirm (a) traffic flows
    immediately via the interim PSK, (b) the PSK changes after the first
    real Rosenpass exchange, (c) it continues rotating (~2 min cadence)
    without dropped traffic, (d) file/process permissions on the secret key
    and PSK handoff file are `0o600`/owner-only.

**Acceptance**: partially met — PSK selection/application logic is
implemented and unit-tested; the `docker-tests/` scenario above (real
interfaces, real traffic) has not been run and is the remaining gap before
this milestone is fully done.

## M5 — Permissive mode & mixed-fleet interop — mostly DONE (docker-tests scenario still open)

- Implemented as `client_core::interface::apply_rosenpass_visibility_policy`,
  called from `fetch()` right before diffing against the WireGuard device —
  **not** inside `PeerDiff`/`peer_config_builder` as originally sketched.
  Simpler approach found while implementing: the server already makes a
  disabled peer "disappear" by filtering it out of `/state` at the SQL
  level (never present-but-flagged), and `Device::diff`'s existing add/
  remove logic already turns a peer's absence into a clean removal. Strict
  mode reuses that exact mechanism — removing peers with no
  `rosenpass_public_key_hash` from the list *before* it reaches `diff()` —
  instead of teaching `PeerDiff` a new code path. Permissive mode (or
  Rosenpass disabled) leaves the list untouched.
- Covered by unit tests (`client-core/src/interface.rs`): strict mode
  excludes keyless peers (never excluding self), permissive mode and
  Rosenpass-disabled both keep everyone.
- `--rosenpass-permissive`'s `--help` text now explicitly states the
  fail-open tradeoff (design.md §6) rather than just describing the
  mechanism.
- **Not yet done**: the `docker-tests/` mixed-fleet scenario (three real
  containers — two Rosenpass-enabled with one permissive, one plain/legacy —
  confirming actual connectivity, not just the peer-list-filtering unit
  tests above) remains open, same real-interface gap noted in M4.

**Acceptance**: partially met — the policy logic is implemented and unit-
tested; real three-peer connectivity via `docker-tests/` has not been
verified and is the remaining gap.

## M6 — Server as a mesh peer — mostly DONE (docker-tests scenario still open)

- `server/src/rosenpass.rs`: a new periodic task (`spawn`, wired into
  `serve()` alongside the existing endpoint-refresher/invite-sweeper/
  hostfile-writer tasks) runs the server's own Rosenpass keypair lifecycle,
  daemon, and PSK application — reusing the exact same
  `rosenpass::ensure_daemon_running`/`apply_psks` from `shared` that the
  client uses (factored there during M4, not just "in M3" as originally
  planned, since PSK application landed in M4).
- Differs from the client only in *how* it sources data, exactly as
  design.md §5.9 anticipated: no HTTP round trip needed to register its own
  key or fetch a peer's key — both are direct reads/writes against its own
  database `Connection`, since the server already has every peer's row
  (including its own) locally.
- **Important scope narrowing found while implementing**: the server does
  *not* apply strict/permissive peer-exclusion to its own device, even
  without `--rosenpass-permissive`. Client-side strict mode excludes a peer
  from *that client's* WireGuard interface, which only affects P2P
  connectivity; doing the equivalent on the server would make a peer unable
  to reach the coordination API at all (breaking redemption/fetch for a
  reason unrelated to whether that link happens to have PQ protection) —
  a much more severe, wrong consequence. The server's own Rosenpass sync
  only ever adds PSK protection to server↔peer links; it never gates peer
  visibility.
- New `--enable-rosenpass`/`--rosenpass-permissive` flags on
  `innernet-server serve` (the permissive flag is accepted for CLI
  consistency but doesn't change server-side behavior, per the point above).
- Covered by unit tests for the DB-sourced key-caching logic
  (`server/src/rosenpass.rs`); the daemon-lifecycle/PSK-application code
  itself is the same already-tested `shared::rosenpass` code M3/M4 covered.
- **Not yet done**: same real-interface gap as M4/M5 — no live
  `innernet-server` process with a real WireGuard interface has exercised
  this end-to-end in this environment (no root/CAP_NET_ADMIN available).

**Acceptance**: partially met — the server-side sync logic is implemented,
reuses already-tested shared code, and is unit-tested where it doesn't
require a live interface; confirming `wg show` on a real running server
shows a non-empty, rotating PSK for enrolled peers remains open.

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
