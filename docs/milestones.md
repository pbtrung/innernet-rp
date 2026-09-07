# Milestones: post-quantum PSK exchange

Companion to [design.md](design.md) — read that first for the full
rationale. Each milestone should land as its own PR(s) with tests, and
should keep `main` shippable throughout: the feature stays fully inert (no
schema reads matter, no new keypairs generated, no mailbox traffic) until a
network operator opts in, all the way through M6.

## M0 — Spike: integrate leancrypto (ML-KEM-1024, X448, HKDF-SHA3) and p521

Not user-facing; de-risks every later milestone's assumptions in design.md
§2.1/§5.1–§5.8.

- Integrate [leancrypto](https://github.com/smuellerDD/leancrypto)'s Rust
  bindings (ML-KEM-1024, X448, SHA3/HKDF) and pin a specific version/commit.
  Its Rust API is explicitly documented upstream as not yet stable — decide
  here whether to track upstream directly or vendor a pinned copy, and
  record the decision (design doc §10 flags this as an open risk to close
  out in this milestone).
- Separately integrate the [`p521`](https://crates.io/crates/p521)
  RustCrypto crate for the ECDSA signing scheme (§5.8) — a second,
  independent crypto dependency from leancrypto, since leancrypto doesn't
  implement NIST prime-field curves; confirm it interoperates cleanly with
  leancrypto's own RNG/byte conventions.
- Confirm actual key/ciphertext/signature byte sizes for ML-KEM-1024, X448,
  and P-521 against both libraries' own output (design.md §2/§8 state
  expected sizes; verify against the real implementations rather than the
  specs alone).
- Prototype the `Encapsulate`/`Decapsulate` round trip end-to-end in a
  throwaway test, confirming both sides converge on the identical shared
  secret.
- Prototype the §5.7 hybrid combiner (X448 ECDH + ML-KEM shared secret →
  HKDF-SHA3-256 → 32 bytes) and write down the exact `info` string/label so
  it's fixed before any real keys depend on it.
- Prototype P-521 ECDSA sign/verify over a `ciphertext || to_peer_id ||
  from_peer_id` message (§5.8) using a fixed-width raw `r || s` signature
  encoding (not DER), confirming the exact 132-byte signature length holds.
- Decide leancrypto's and `p521`'s minimum-supported-Rust-version and
  cross-compilation impact on this workspace's own MSRV and build tooling
  (relevant to M8's aarch64 target).

**Acceptance**: a throwaway integration test demonstrates two independent
`Encapsulate`/`Decapsulate` calls converging on the same derived PSK bytes,
and a sign/verify round trip over a sample message; crate/version choice and
exact sizes recorded back into design.md §2/§8 if they differ from the
estimates there.

## M1 — Schema & API plumbing

- Add nullable `pq_kem_public_key` and `pq_sig_public_key` columns to the
  `peers` table (`server/src/db/peer.rs`), threaded through
  `create`/`update`/`from_row`/`COLUMNS`.
- Add both fields to `PeerContents` with `#[serde(default)]`
  (`shared/src/types.rs`).
- Add `pq_kem: bool` to `ServerCapabilities` (`shared/src/types.rs`,
  alongside the other feature flags there).
- New `pq_handshake_mailbox` table (`to_peer_id`, `from_peer_id`,
  `ciphertext`, `signature`, `created_at`), primary-keyed on
  `(to_peer_id, from_peer_id)`.
- Add `PUT /v1/user/pq-handshake/{to_peer_id}` to `server/src/api/user.rs`,
  with input validation (exact expected ML-KEM-1024 ciphertext length,
  exact expected P-521 signature length, authorization check that the
  caller may see `to_peer_id` per existing CIDR rules).
- Embed any pending mailbox entry addressed to the requester into the
  existing `GET /v1/user/state` response; delete the row once served.
- A periodic sweep (mirroring the shape of other periodic server tasks
  already in `server/src/lib.rs`) deletes mailbox rows past the TTL.
- Tests (extend `server/src/api/user.rs`'s `#[cfg(test)]` module using the
  existing `test::Server` harness):
  - round-trip a peer's `pq_kem_public_key`/`pq_sig_public_key` through
    `PeerContents` then `/v1/user/state`;
  - old-shaped JSON (no PQ fields) still deserializes (back-compat);
  - a peer outside the requester's authorized CIDR set never has PQ fields
    or mailbox entries leaked;
  - malformed/wrong-length ciphertext or signature upload is rejected with
    4xx, not a panic;
  - a delivered mailbox entry is deleted and not served twice;
  - a TTL-expired, undelivered entry is swept.

**Acceptance**: `cargo test --workspace --locked` green; a client on an old
binary can still talk to a migrated server and vice versa (verified by the
back-compat test above); no CLI/keypair/PSK-application behavior changed
yet.

## M2 — Client keypair generation & registration

- Generate an ML-KEM-1024 keypair, a dedicated X448 keypair, and a
  dedicated P-521 signing keypair on `install`/`redeem-invite`, store all
  three secret keys `0o600` under
  `<data_dir>/interfaces/<interface>/pq-kem/` (mirrors
  `interface_config.rs`'s handling of the WireGuard private key).
- Add a `RestClient` method to push all three public keys
  (`client-core/src/rest_client.rs`, alongside `create_peer`), called once
  at install and idempotently re-checked on every `up`.
- `innernet show`: display whether the local interface and each visible
  peer has advertised PQ public keys (best-effort, no exchange running
  yet — this milestone is data-plumbing only).

**Acceptance**: `innernet install`/`redeem-invite` on a PQ-flagged network
generates and registers all three keypairs; `innernet show` reflects it; no
WireGuard PSK is touched yet (that's M4).

## M3 — Peer-to-peer exchange loop

- Implement the dial/listen (initiator/responder) tie-break from design.md
  §5.4: the coordinating server (peer id 1) is always responder; otherwise
  lower peer ID initiates.
- Add a `--pq-psk-rotation-interval <seconds>` flag (client `install`/`up`
  and server `serve`), default **5 minutes** (design.md §5.6) — independent
  of the general `up --daemon --interval`.
- On each rotation-interval tick:
  - as initiator for a given pair, fetch the responder's public keys,
    encapsulate, sign `ciphertext || to_peer_id || from_peer_id` with the
    local P-521 key, upload `{ciphertext, signature}`;
  - as responder, for any pending mailbox entry delivered in the state
    fetch: verify the signature against the sender's cached
    `pq_sig_public_key` first — on failure, log and discard without
    decapsulating; on success, decapsulate and derive the shared secret.
- Wire the derived shared secret through the §5.7 hybrid combiner into a
  32-byte value, but **do not yet apply it to WireGuard** — that's M4, kept
  separate so this milestone's tests can assert on the derived bytes
  directly without needing a real WireGuard interface.
- Tests: two simulated peers (initiator + responder) converge on an
  identical derived PSK end-to-end through the mailbox mechanism (using a
  fake/in-memory server for the mailbox, not a real network round trip); a
  tampered signature is rejected without panicking and without disturbing
  the previous derived value; a stale/wrong-length ciphertext delivered to
  the responder is rejected the same way.

**Acceptance**: two real client processes (or client+server) against a real
test server converge on identical derived secret bytes for a pair, verified
by a shared test assertion point (e.g. writing the derived value to a file
each side can compare, similar in spirit to the two-real-process test
pattern already used elsewhere in this codebase for other cross-process
convergence checks); a forged/tampered signature is provably rejected in
the same test run.

## M4 — PSK application

- Apply the M3-derived PSK to the relevant WireGuard peer via
  `PeerConfigBuilder::set_preshared_key` + `DeviceUpdate::apply`, on both
  initial exchange and each subsequent rotation.
- On a failed/rejected exchange (§5.6), leave the previously-applied PSK in
  place rather than clearing it.
- Before the very first successful exchange for a pair, apply a
  deterministic interim PSK derived locally from both sides' already-known
  public keys (no round trip needed) so the tunnel isn't left with no PSK
  at all while the first real exchange is still pending — same "sort, don't
  pick a side" shape needed to guarantee both ends converge on the same
  value independently.
- Tests: applying a derived PSK doesn't disrupt an already-up tunnel
  (existing peer config merge behavior, not a reconnect); a failed rotation
  leaves the prior PSK in place; the interim PSK is deterministic and
  identical when computed independently from either side's data.

**Acceptance**: a real two-peer test run shows the applied
`wg show <interface> preshared-keys` value change from the interim value to
the real derived value once the first exchange completes, and again on
subsequent rotations.

## M5 — Idle-detection pause/resume

- Add a `--pq-psk-idle-timeout <seconds>` flag, default **15 minutes**
  (design.md §5.12).
- Before each rotation tick for a given peer, check that peer's WireGuard
  transfer byte-count delta since the last check (`wg show <interface>
  transfer`); if unchanged for longer than the idle timeout, skip rotation
  for that pair only.
- Resume eagerly: the very next tick that observes a nonzero transfer delta
  for that peer resumes normal rotation for that pair, with no effect on
  any other peer's schedule.
- Tests: an idle peer's rotation pauses while a concurrently-active peer's
  rotation continues on schedule (directly exercises the design.md §5.12
  independence claim); resuming traffic on the idle peer resumes its
  rotation without needing to touch the active peer's state.

**Acceptance**: in a real multi-peer test run, one peer's rotation
demonstrably pauses and later resumes based on its own traffic alone, while
a second peer's rotation is unaffected throughout.

## M6 — Permissive mode & mixed-fleet interop

- Add `--enable-pq-psk` and `--pq-psk-permissive` flags, following the
  existing flag/opts pattern already used for other optional per-peer
  features in this codebase.
- A peer with `--enable-pq-psk` but not `--pq-psk-permissive` treats a peer
  with no advertised `pq_kem_public_key` as unreachable (fail-closed,
  matching the existing default for other optional protections in this
  codebase).
- With `--pq-psk-permissive`, fall back to a plain WireGuard connection (no
  PSK) for such peers instead.
- Tests: a mixed fleet (one peer with PQ enabled, one without) connects
  successfully only when permissive mode is set on the enabled side, and is
  treated as unreachable otherwise.

**Acceptance**: documented, tested fail-closed default with an explicit,
tested opt-in fallback — no silent degradation either direction.

## M7 — Server as a mesh peer

- The coordination server generates and registers its own PQ keypairs for
  its own coordination-API WireGuard link, and runs the same periodic
  exchange logic as any client interface (design.md §5.10) — no special
  casing beyond the responder role already assigned to it by §5.4.
- Tests: the server's own coordination-API link gets a real derived PSK
  applied and rotated, using the same test harness pattern as M3/M4.

**Acceptance**: `innernet-server serve --enable-pq-psk` results in the
server's own link to at least one enabled client carrying a real derived
PSK, verified the same way M4 verifies a client-side link.

## M8 — Build targets & platform support

- Confirm both `leancrypto` and the pure-Rust `p521` crate cross-compile
  cleanly for both target triples this project already ships
  (`bin/PKGBUILD`): `x86_64-unknown-linux-musl` and
  `aarch64-unknown-linux-musl` (design.md §5.13).
- Extend `bin/build-multiarch.sh` (or its successor) to build this
  feature's binaries for both targets; confirm no non-Linux build path is
  silently affected (this feature stays Linux-only per design.md §4).
- Tests: a build matrix (CI) covering both target triples, not just the
  developer's native architecture.

**Acceptance**: both `x86_64` and `aarch64` static binaries build in CI and
successfully run the M3/M4 convergence test under emulation or real
hardware for the non-native target.

## M9 — Security review & hardening

Implements design.md §7's full Docker-based test plan against real
processes, not just unit tests with fakes:

- Stand up the four-container topology from design.md §7.1
  (`peer-a`/`peer-b` cooperating, `peer-m` adversarial/cross-CIDR, `peer-x`
  flood-only) in a new `docker-tests/`-style harness.
- Automate all eleven cases from design.md §7.2: baseline convergence, PSK
  reaching WireGuard, rotation over time, cross-CIDR mailbox isolation,
  malformed-payload rejection, invalid-signature rejection, replay
  harmlessness, TTL sweep, idle-detection pause/resume independence,
  mailbox flood resilience, and permissive/mixed-fleet fallback.
- Confirm a compromised/malicious server's practical capability is bounded
  exactly as design.md §5.8/§6 claims (relay-level substitution without the
  signature hardening enabled; no forgery possible with it enabled) — write
  this up as a concrete test/documented finding, not just an assumption.
- Resolve the design.md §10 open question on whether the P-521
  signed-ciphertext hardening ships default-on or opt-in, based on what
  this review finds.
- Resolve the design.md §10 open question on whether the 5-minute
  rotation/15-minute idle defaults hold up, adjusting if the load/flood
  testing above suggests otherwise.
- Revisit whether carrying two independent crypto dependencies
  (`leancrypto` + `p521`, design.md §2.1/§10) is worth it versus
  consolidating on Ed448 within `leancrypto` alone, based on what this
  review finds about the practical audit/maintenance cost.

**Acceptance**: all eleven design.md §7.2 cases automated and green in CI,
including the security-negative ones (cross-CIDR isolation, malformed
payload, invalid signature, flood resilience) — a suite that only covers
the happy path does not close this milestone; findings and any resulting
default changes recorded back into design.md §6/§10.

## M10 — Docs & release

- README.md section documenting `--enable-pq-psk`, `--pq-psk-permissive`,
  `--pq-psk-rotation-interval`, and `--pq-psk-idle-timeout`, modeled on how
  any other optional feature is documented there.
- man page updates, if this project ships them for other flags.
- Migration note for existing deployments: this is purely additive/opt-in
  (new nullable columns, new table, no behavior change until a flag is
  passed) — confirm and document that an old server can run against a
  migrated database with the new columns simply unused.
