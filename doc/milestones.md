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

## M4 — PSK application — DONE

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
- **`docker-tests/` scenario now implemented and passing**
  (`test_rosenpass_handshake` in `docker-tests/run-docker-tests.sh`): two
  real containers, both `--enable-rosenpass`, over a real (userspace)
  WireGuard interface, confirming (a) traffic flows immediately via the
  interim PSK, (b) the PSK changes after the first real Rosenpass exchange,
  (c) traffic keeps flowing after the rotation, (d) the secret key and PSK
  handoff (`key_out`) file are both `0o600`, and (e) the server's own
  Rosenpass sync (M6) also applies a PSK to that peer. Rotation cadence
  itself (~2 min, ongoing) isn't polled for multiple cycles — one real
  interim→real rotation is what the test asserts — since that's what
  distinguishes "the mechanism actually works end to end" from "the code
  compiles," and a multi-cycle wait would mostly just be a slower version
  of the same assertion.
- **Two real bugs found and fixed by finally running this against a real
  interface** (neither reproduced against the tempdir-backed unit
  tests/`#[ignore]`d real-binary tests, which never exercised a
  freshly-created multi-level data directory or a `key_out` file actually
  produced by a spawned `rosenpass` process):
  - `shared::ensure_dirs_exist` used `fs::create_dir` (single level), which
    fails with `ENOENT` whenever `<data_dir>/rosenpass/<interface>` is two
    levels deep and neither level exists yet — exactly the real-world case
    on a freshly-initialized node. A unit-test tempdir is always a single
    already-existing level, so this never reproduced there. Fixed to
    `fs::create_dir_all`.
  - The `key_out` PSK handoff file is created by the `rosenpass` subprocess
    itself (its own `output-key` config directive), under its own process
    umask — world-readable (`0o644`) by default, since rosenpass has no way
    to know the contents are a secret WireGuard PSK. `fresh_exchanged_psk`
    now tightens it to `0o600` immediately upon reading, matching every
    other key-bearing file in this codebase.

**Acceptance**: met — PSK selection/application logic is implemented,
unit-tested, and now also verified end to end against a real interface via
`docker-tests/`, which caught and led to fixing two real bugs neither the
unit tests nor manual real-binary testing had exercised.

## M5 — Permissive mode & mixed-fleet interop — DONE

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
- **`docker-tests/` mixed-fleet scenario now implemented and passing**
  (`test_rosenpass_permissive_fallback`): three real containers — one
  strict `--enable-rosenpass`, one `--enable-rosenpass --rosenpass-permissive`,
  one plain legacy peer with no Rosenpass at all — confirming actual
  connectivity, not just the peer-list-filtering unit tests above: the
  permissive peer reaches both the strict peer (with a real PSK) and the
  legacy peer (fail-open, no PSK at all); the strict peer's own WireGuard
  interface never lists the legacy peer as a peer at all, confirming strict
  exclusion is real, not just a unit-tested code path.

**Acceptance**: met — the policy logic is implemented, unit-tested, and now
also verified end to end via a real three-peer `docker-tests/` scenario.

## M6 — Server as a mesh peer — DONE

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
- **Closed via `docker-tests/`**: `run-docker-tests.sh` now runs the
  coordinating server itself with `--enable-rosenpass` for every test in the
  suite (safe to do unconditionally per the scope-narrowing above — it never
  gates any other test's peer visibility), and `test_rosenpass_handshake`
  confirms `wg show` on the real running server reports a non-`(none)`
  preshared key for an enrolled Rosenpass peer, closing the real-interface
  gap this milestone had been tracking.

**Acceptance**: met — the server-side sync logic is implemented, reuses
already-tested shared code, and is now also verified end to end: `wg show`
on a real running server (inside `docker-tests/`) shows a non-empty PSK for
an enrolled peer.

## M7 — Security review & hardening — mostly DONE (subprocess privilege-dropping still open)

- Ran a security review against the full diff (946d53f..HEAD), using the
  same methodology as this repo's `/security-review` skill (its own
  git-diff auto-detection only looks at uncommitted changes, so the range
  was reviewed directly). Two passes: identify candidates, then adversarially
  verify each. **Zero reportable findings.** The one candidate worth
  verifying — a peer can set its own `rosenpass_addr` to an arbitrary
  host:port, causing other peers' local `rosenpass` processes to send it UDP
  packets — was confirmed to be exactly equivalent to the pre-existing
  WireGuard `endpoint`/`candidates` mechanism (`client-core/src/nat.rs`
  already does this for the WireGuard protocol itself, with the same
  peer-self-reports-its-address trust model), not a new attack surface.
- Fuzz/property-tested the new parsing paths and, doing so, **found and
  fixed a real validation gap**: `is_valid_rosenpass_public_key` checked the
  base64 *string* length but not the *decoded byte* length, so a
  correctly-sized string with trailing `=` padding could pass while decoding
  to 1-2 bytes short of a real key. Fixed to check both. Also added a
  battery of malformed/adversarial inputs to `parse_output_key_line`
  (empty, truncated, wrong case, embedded nulls, unicode, ~2MB adversarial
  lines) confirming it never panics — this parses output from a subprocess
  that itself handles untrusted network input, so hostile-shaped log lines
  are an expected input to defend against, not an edge case to shrug off.
- Added a real version-pin enforcement: `check_rosenpass_version` (verified
  against the actual installed 0.2.3 binary) now refuses to spawn `rosenpass`
  if it's older than 0.2.1, closing the gap where an operator's old binary
  would otherwise be used silently despite CVE-2023-53157 being documented
  everywhere else.
- Re-ran `cargo clippy --workspace --locked --all-targets -- -D warnings`
  (clean) and the full `cargo test --workspace --locked` suite (all passing)
  after every change in this milestone.
- **Not done — subprocess privilege dropping**: investigated running the
  `rosenpass` child as an unprivileged user, but the child needs read access
  to the `0o600` secret key and write access to `key_out`/log/pid files in
  the same directory the parent (often root) owns; doing this safely needs
  a shared-ownership design for `rosenpass_dir` first, and couldn't be
  validated here anyway (no root/CAP_NET_ADMIN in this environment).
  Recorded as open in design.md §6 rather than shipped half-validated.
- **`docker-tests/` suite now implemented, run, and found two real bugs**
  (both fixed — see M4): the real-interface gap noted throughout M4-M6 is
  closed. This is exactly the kind of finding a purely source-level security
  review can't catch — both bugs were about real filesystem/process
  behavior (a directory-creation edge case and a subprocess's default file
  permissions), not logic visible in a diff.

**Acceptance**: partially met — security review complete with no open
findings, fuzzing found and fixed a real bug, version pinning is now
enforced in code (not just documented), and the `docker-tests/` suite is
now implemented and passing (having found and fixed two further real bugs).
Subprocess privilege-dropping remains open, tracked above rather than
silently dropped.

## M8 — Docs & release — partially DONE (man pages and the actual release deliberately not done)

- Added a README section ("Post-Quantum Key Exchange with Rosenpass") covering
  the two flags, the runtime dependency on the real `rosenpass` binary
  (>= 0.2.1), and a pointer to design.md for the full rationale; a
  "Runtime Dependencies" mention of installing `rosenpass`; and a
  "`--rosenpass-permissive` is fail-open" subsection under Security
  recommendations.
- Regenerated all 10 shell completion files
  (`doc/{innernet,innernet-server}.completions.{bash,zsh,fish,powershell,elvish}`)
  via each binary's own `completions <shell>` subcommand — the same command
  `release.sh` uses — picking up the new `--enable-rosenpass`/
  `--rosenpass-permissive` flags. This also incidentally regenerated
  pre-existing formatting drift from a `clap`/`clap_complete` dependency bump
  that predates this feature and had never been regenerated since; that's a
  byproduct of running the project's own real generation process, not scope
  creep.
- The default is already opt-in/off (`enable_rosenpass: bool` has no
  `default_value_t`, so clap defaults it to `false`) - satisfied by
  construction, nothing further to decide.
- **Not done — man pages** (`doc/innernet.8`/`doc/innernet-server.8`): these
  are generated by `help2man` per `release.sh`, and `help2man` isn't
  installed in this environment with no way to install it (no sudo).
  Regenerating them (`help2man --no-discard-stderr -s8 target/debug/<bin>
  -N > doc/<bin>.8 && gzip -fk doc/<bin>.8`, per `release.sh`) remains a
  manual step for whoever has `help2man` available, or for CI.
- **Not done — no CHANGELOG file exists in this repo** to add an entry to;
  this repo's release notes appear to come from `cargo-release`/git history
  instead, so there's nothing to add here beyond what the commit messages
  already record.
- **Deliberately not done — tagging/publishing a release**: running
  `release.sh`'s `cargo release`/tag/push step is an irreversible,
  externally-visible action; left for you to run when you're ready to
  actually ship this.

**Acceptance**: partially met — a new user following the README can enable
Rosenpass end to end; the man pages remain stale until regenerated with
`help2man`, and no release has been tagged.

## M9 — Static config export for non-innernet peers (independent track) — mostly DONE (QR and docker-tests round-trip not done)

Not part of the Rosenpass rollout and doesn't gate or depend on M0–M8, and
indeed shipped after them in this implementation. Tracked here because it
was motivated directly by M5/§5.8's finding that mobile peers (no Rosenpass
client exists for Android/iOS) have no join path at all today, static or
otherwise (design.md §5.10).

- `--export-wg-conf` added to `innernet add-peer` (`shared/src/types.rs`
  `AddPeerOpts`, wired in `client/src/main.rs`), rendering a standard
  `wg-quick`-compatible `.conf` (`shared::wg_export::render_wg_quick_conf`)
  from the same already-fetched peer list and freshly generated keypair
  `add_peer()`/`create_peer()` already produce — no extra server round trip,
  instead of an innernet `PeerInvitation`. Manually verified against a
  realistic peer list: produces a well-formed `[Interface]`/`[Peer]` config.
- `innernet export-peer-config <interface> <path>` implemented as a
  **refresh of an existing exported file**, not a lookup by peer name as
  originally sketched: the peer's private key can only ever come from the
  file the admin already exported (it was never sent to or stored by the
  server — the same "private keys never touch the server" property this
  whole design already relies on elsewhere), so re-deriving it from a "name"
  alone isn't possible. `shared::wg_export::parse_exported_interface` reads
  back just the `[Interface]` section from a file this exporter itself
  produced (deliberately not a general `wg-quick` parser for arbitrary
  third-party files), then `[Peer]` blocks are re-rendered from the current
  peer list and the file is overwritten in place — same keys, refreshed
  peers.
- CLI output states plainly, every time (both commands' log messages, and
  the exported file's own header comment), that this is a point-in-time
  snapshot with no auto-refresh.
- **Found and fixed a real gap while implementing**: the exported file
  contains a private key but was initially written with default file
  permissions, not `0o600` like every other file in this codebase holding a
  WireGuard private key. Added `wg_export::write_exported_conf` (used by
  both `add-peer --export-wg-conf` and `export-peer-config`) to fix this,
  with a regression test asserting the mode.
- The `require_rosenpass`/per-network-policy-bit idea from §5.8 was never
  actually built in this implementation (it was only ever a suggested
  "advisory" concept, not implemented in M1-M8's code) — there's no such
  field to check, so no refusal logic was added here either. The README
  documents the operational guidance instead (a network with any exported
  peers needs `--rosenpass-permissive` if Rosenpass is enabled).
- **Static preshared key for the admin's own link, added after the initial
  implementation above** (design.md §5.10): since a phone can never run
  Rosenpass and so can never get a PSK from that mechanism, `add-peer
  --export-wg-conf` now also generates a random PSK
  (`wireguard_control::Key::generate_preshared`) and attaches it to the
  exported peer's `[Peer]` block for the admin peer specifically — the same
  WireGuard PSK field Rosenpass itself uses, just manually provisioned. This
  is deliberately scoped to *one* link, not the whole mesh: the PSK is
  generated and persisted entirely locally
  (`shared::wg_export::save_exported_psk`/`get_exported_psk`, at
  `<data_dir>/exported-psks/<interface>.toml`, `0o600`) and never touches
  the coordination server — same "a PSK is exactly as sensitive as a
  private key, and private keys never touch the server" reasoning already
  used elsewhere in this design — so there's no channel to distribute it to
  any *other* peer. `client_core::interface::fetch` applies it as its own
  follow-up `DeviceUpdate` via the new `wg_export::apply_exported_psks`
  (same non-disruptive pattern as `rosenpass::apply_psks`), independent of
  whether Rosenpass is enabled at all. `export-peer-config` re-embeds the
  same stored PSK unchanged on refresh, never regenerating it — exactly
  like the private key it sits next to.
  Covered by unit tests in `shared/src/wg_export.rs`: the `PresharedKey`
  line lands only in the correct peer's block, the local store round-trips
  and defaults to `None` for pre-existing exports, overwrites cleanly on
  re-save, is `0o600`, and `apply_exported_psks` is a no-op when nothing's
  been saved.
- **Not done**: `--export-wg-conf-qr` (rendering a scannable QR code to the
  terminal) was not implemented - out of scope for this pass, left as a
  clearly separate follow-up rather than attempted half-done. Round-tripping
  the exported `.conf` (private key *and* now the static PSK) through a
  real `wg-quick`/stock WireGuard client in `docker-tests/` (or an actual
  phone) was not done - same real-interface gap noted throughout M4-M7,
  though M4-M6's equivalent gap for the Rosenpass-derived PSK mechanism has
  since been closed there.

**Acceptance**: partially met — an exported config renders correctly (unit-
tested and manually verified), refreshes in place without rotating keys or
the newly-added static PSK, and now gives the admin's own link to the
exported peer real PSK protection instead of none at all; actually joining
a real mesh with it (docker-tests or a real device) has not been verified.
