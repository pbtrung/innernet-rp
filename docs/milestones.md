# Milestones: post-quantum PSK exchange

Companion to [design.md](design.md) — read that first for the full
rationale. Each milestone should land as its own PR(s) with tests, and
should keep `main` shippable throughout: the feature stays fully inert (no
schema reads matter, no new keypairs generated, no mailbox traffic) until a
network operator opts in, all the way through M5.

## M0 — Spike: pick and integrate an ML-KEM crate

Not user-facing; de-risks every later milestone's assumptions in design.md
§5.1–§5.7.

- Evaluate ML-KEM (FIPS 203) Rust crate options (a pure-Rust implementation
  is strongly preferred over one wrapping a C library, to match this
  workspace's existing all-Rust dependency style) and pin a specific version.
- Confirm actual key/ciphertext byte sizes for ML-KEM-768 against the chosen
  crate's own output (design.md §2 states expected sizes; verify against the
  real implementation rather than the spec alone).
- Prototype the `Encapsulate`/`Decapsulate` round trip end-to-end in a
  throwaway test, confirming both sides converge on the identical shared
  secret.
- Prototype the §5.7 hybrid combiner (X25519 ECDH + ML-KEM shared secret →
  HKDF → 32 bytes) and write down the exact `info` string/label so it's
  fixed before any real keys depend on it.
- Decide the crate's minimum-supported-Rust-version impact on this
  workspace's own MSRV, if any.

**Acceptance**: a throwaway integration test demonstrates two independent
`Encapsulate`/`Decapsulate` calls converging on the same derived PSK bytes;
crate choice and exact sizes recorded back into design.md §2 if they differ
from the estimates there.

## M1 — Schema & API plumbing

- Add nullable `pq_kem_public_key` column to the `peers` table
  (`server/src/db/peer.rs`), threaded through `create`/`update`/`from_row`/
  `COLUMNS`.
- Add the field to `PeerContents` with `#[serde(default)]`
  (`shared/src/types.rs`).
- Add `pq_kem: bool` to `ServerCapabilities` (`shared/src/types.rs`,
  alongside the other feature flags there).
- New `pq_handshake_mailbox` table (`to_peer_id`, `from_peer_id`,
  `ciphertext`, `created_at`), primary-keyed on `(to_peer_id, from_peer_id)`.
- Add `PUT /v1/user/pq-handshake/{to_peer_id}` to `server/src/api/user.rs`,
  with input validation (exact expected ciphertext length, authorization
  check that the caller may see `to_peer_id` per existing CIDR rules).
- Embed any pending mailbox entry addressed to the requester into the
  existing `GET /v1/user/state` response; delete the row once served.
- A periodic sweep (mirroring the shape of other periodic server tasks
  already in `server/src/lib.rs`) deletes mailbox rows past the TTL.
- Tests (extend `server/src/api/user.rs`'s `#[cfg(test)]` module using the
  existing `test::Server` harness):
  - round-trip a peer's `pq_kem_public_key` through `PeerContents` then
    `/v1/user/state`;
  - old-shaped JSON (no PQ fields) still deserializes (back-compat);
  - a peer outside the requester's authorized CIDR set never has PQ fields
    or mailbox entries leaked;
  - malformed/wrong-length ciphertext upload is rejected with 4xx, not a
    panic;
  - a delivered mailbox entry is deleted and not served twice;
  - a TTL-expired, undelivered entry is swept.

**Acceptance**: `cargo test --workspace --locked` green; a client on an old
binary can still talk to a migrated server and vice versa (verified by the
back-compat test above); no CLI/keypair/PSK-application behavior changed
yet.

## M2 — Client keypair generation & registration

- Generate an ML-KEM-768 keypair and a dedicated X25519 keypair on
  `install`/`redeem-invite`, store both secret keys `0o600` under
  `<data_dir>/interfaces/<interface>/pq-kem/` (mirrors
  `interface_config.rs`'s handling of the WireGuard private key).
- Add a `RestClient` method to push both public keys
  (`client-core/src/rest_client.rs`, alongside `create_peer`), called once
  at install and idempotently re-checked on every `up`.
- `innernet show`: display whether the local interface and each visible
  peer has advertised a PQ public key (best-effort, no exchange running
  yet — this milestone is data-plumbing only).

**Acceptance**: `innernet install`/`redeem-invite` on a PQ-flagged network
generates and registers both keypairs; `innernet show` reflects it; no
WireGuard PSK is touched yet (that's M4).

## M3 — Peer-to-peer exchange loop

- Implement the dial/listen (initiator/responder) tie-break from design.md
  §5.4: the coordinating server (peer id 1) is always responder; otherwise
  lower peer ID initiates.
- On each `up --daemon` cycle (client) / periodic sync task (server):
  - as initiator for a given pair, if due for rotation, fetch the
    responder's public keys, encapsulate, upload the ciphertext;
  - as responder, decapsulate any pending mailbox entries delivered in the
    state fetch.
- Wire the derived shared secret through the §5.7 hybrid combiner into a
  32-byte value, but **do not yet apply it to WireGuard** — that's M4, kept
  separate so this milestone's tests can assert on the derived bytes
  directly without needing a real WireGuard interface.
- Tests: two simulated peers (initiator + responder) converge on an
  identical derived PSK end-to-end through the mailbox mechanism (using a
  fake/in-memory server for the mailbox, not a real network round trip);
  a stale/wrong-length ciphertext delivered to the responder is rejected
  without panicking and without disturbing the previous derived value.

**Acceptance**: two real client processes (or client+server) against a real
test server converge on identical derived secret bytes for a pair, verified
by a shared test assertion point (e.g. writing the derived value to a file
each side can compare, similar in spirit to the two-real-process test
pattern already used elsewhere in this codebase for other cross-process
convergence checks).

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

## M5 — Permissive mode & mixed-fleet interop

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

## M6 — Server as a mesh peer

- The coordination server generates and registers its own PQ keypairs for
  its own coordination-API WireGuard link, and runs the same periodic
  exchange logic as any client interface (design.md §5.10) — no special
  casing beyond the responder role already assigned to it by §5.4.
- Tests: the server's own coordination-API link gets a real derived PSK
  applied and rotated, using the same test harness pattern as M3/M4.

**Acceptance**: `innernet-server serve --enable-pq-psk` results in the
server's own link to at least one enabled client carrying a real derived
PSK, verified the same way M4 verifies a client-side link.

## M7 — Security review & hardening

- Fuzz/property-test the mailbox endpoint's input validation (malformed
  length, non-ciphertext-shaped bytes, oversized payloads) for panics.
- Confirm mailbox rows are properly scoped by the existing CIDR
  authorization checks — a peer must never be able to enumerate or read a
  ciphertext addressed to a peer it isn't authorized to see.
- Load-test the mailbox table's TTL sweep under a large, mostly-online
  fleet with a short rotation interval to validate the growth-bound
  reasoning in design.md §5.9/§8.
- Confirm a compromised/malicious server's practical capability is bounded
  exactly as design.md §5.8 claims (relay-level substitution, not secret
  key or plaintext-shared-secret exposure) — write this up as a concrete
  test/documented finding, not just an assumption.
- Revisit whether the §5.8 signed-ciphertext hardening should ship now or
  stay deferred, based on what the above review actually finds.

**Acceptance**: findings and resolutions recorded back into design.md §6/§8;
no known panic/crash path from untrusted mailbox input; CIDR scoping
verified by test, not just code review.

## M8 — Docs & release

- README.md section documenting `--enable-pq-psk`/`--pq-psk-permissive`,
  modeled on how any other optional feature is documented there.
- man page updates, if this project ships them for other flags.
- Migration note for existing deployments: this is purely additive/opt-in
  (new nullable columns, new table, no behavior change until a flag is
  passed) — confirm and document that an old server can run against a
  migrated database with the new columns simply unused.
