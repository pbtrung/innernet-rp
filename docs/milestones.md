# Milestones: post-quantum PSK exchange

Companion to [design.md](design.md) — read that first for the full
rationale. Each milestone should land as its own deliverable with tests, and
should keep the system shippable throughout: the feature stays fully inert
(no schema reads matter, no new keypairs generated, no mailbox traffic)
until a network operator opts in, all the way through M6.

## M0 — Spike: integrate the KEM/hybrid-ECDH library and the signing library

Not user-facing; de-risks every later milestone's assumptions in design.md
§2.1/§5.1–§5.8.

- Integrate the chosen KEM/hybrid-ECDH library (ML-KEM-1024, X448,
  SHA3/HKDF) and pin a specific version. Its integration maturity is not
  yet established upstream — decide here whether to track a moving upstream
  target or vendor a pinned copy, and record the decision (design doc §10
  flags this as an open risk to close out in this milestone).
- Separately integrate the chosen P-521 ECDSA signing library (§5.8) — a
  second, independent crypto dependency from the KEM/hybrid-ECDH library,
  since that library doesn't implement NIST prime-field curves; confirm it
  interoperates cleanly with the other library's own randomness/byte
  conventions.
- Confirm both libraries link correctly against their system-provided
  installations (§2.1), not a vendored/bundled copy.
- Confirm actual key/ciphertext/signature byte sizes for ML-KEM-1024, X448,
  and P-521 against both libraries' own output (design.md §2/§8 state
  expected sizes; verify against the real implementations rather than the
  specs alone).
- Prototype the encapsulate/decapsulate round trip end-to-end in a
  throwaway test, confirming both sides converge on the identical shared
  secret.
- Prototype the §5.7 hybrid combiner (X448 ECDH + ML-KEM shared secret →
  HKDF-SHA3-256 → 32 bytes) and write down the exact derivation label so
  it's fixed before any real keys depend on it.
- Prototype P-521 ECDSA sign/verify over a `ciphertext || to_peer_id ||
  from_peer_id` message (§5.8) using a fixed-width raw `r || s` signature
  encoding (not DER), confirming the exact 132-byte signature length holds.
- Decide both libraries' minimum-version and cross-compilation impact on
  this project's own build tooling (relevant to M8's aarch64 target).

**Acceptance**: a throwaway integration test demonstrates two independent
encapsulate/decapsulate calls converging on the same derived PSK bytes, and
a sign/verify round trip over a sample message; library/version choices and
exact sizes recorded back into design.md §2/§8 if they differ from the
estimates there.

## M1 — Schema & API plumbing

- Add two new nullable fields to the peer record and its backing storage —
  a KEM public key and a signature public key.
- Both fields default to absent so old and new client/server combinations
  round-trip peer records without them.
- Add one boolean feature flag advertising this capability, alongside the
  server's other existing feature flags.
- New handshake-mailbox table (`to_peer_id`, `from_peer_id`, `ciphertext`,
  `signature`, `created_at`), primary-keyed on `(to_peer_id, from_peer_id)`.
- Add `PUT /v1/user/pq-handshake/{to_peer_id}` to the server's API, with
  input validation (exact expected ML-KEM-1024 ciphertext length, exact
  expected P-521 signature length, authorization check that the caller may
  see `to_peer_id` per existing CIDR rules).
- Embed any pending mailbox entry addressed to the requester into the
  existing bulk peer-state fetch response; delete the row once served.
- A periodic sweep (mirroring the shape of other periodic server tasks)
  deletes mailbox rows past the TTL.
- Tests, using the server's existing test harness:
  - round-trip a peer's KEM/signature public keys through a peer record and
    the bulk state fetch;
  - old-shaped peer records (no PQ fields) still deserialize (back-compat);
  - a peer outside the requester's authorized CIDR set never has PQ fields
    or mailbox entries leaked;
  - malformed/wrong-length ciphertext or signature upload is rejected with
    a 4xx response, not a crash;
  - a delivered mailbox entry is deleted and not served twice;
  - a TTL-expired, undelivered entry is swept.

**Acceptance**: the full automated test suite passes; a client on an old
build can still talk to a migrated server and vice versa (verified by the
back-compat test above); no keypair-generation/PSK-application behavior
changed yet.

## M2 — Client keypair generation & registration

- Generate an ML-KEM-1024 keypair, a dedicated X448 keypair, and a
  dedicated P-521 signing keypair once per interface, at the same point the
  interface's WireGuard keypair is first established. Store all three
  secret keys with the same permission discipline (owner-only) as the
  existing WireGuard private key.
- Register all three public keys with the server through the same
  mechanism already used for other per-peer fields, called once at setup
  and idempotently re-checked on every regular sync.
- The client's status display: show whether the local interface and each
  visible peer has advertised PQ public keys (best-effort, no exchange
  running yet — this milestone is data-plumbing only).

**Acceptance**: setting up a network with this feature enabled generates
and registers all three keypairs; the status display reflects it; no
WireGuard PSK is touched yet (that's M4).

## M3 — Peer-to-peer exchange loop

- Implement the dial/listen (initiator/responder) tie-break from design.md
  §5.4: the coordinating server (peer id 1) is always responder; otherwise
  lower peer ID initiates.
- Add a `--pq-psk-rotation-interval <seconds>` option (client and server),
  default **5 minutes** (design.md §5.6) — independent of the general
  peer-list fetch interval.
- On each rotation-interval tick:
  - as initiator for a given pair, fetch the responder's public keys,
    encapsulate, sign `ciphertext || to_peer_id || from_peer_id` with the
    local P-521 key, upload `{ciphertext, signature}`;
  - as responder, for any pending mailbox entry delivered in the state
    fetch: verify the signature against the sender's cached signature
    public key first — on failure, log and discard without decapsulating;
    on success, decapsulate and derive the shared secret.
- Wire the derived shared secret through the §5.7 hybrid combiner into a
  32-byte value, but **do not yet apply it to WireGuard** — that's M4, kept
  separate so this milestone's tests can assert on the derived bytes
  directly without needing a real WireGuard interface.
- Tests: two simulated peers (initiator + responder) converge on an
  identical derived PSK end-to-end through the mailbox mechanism (using a
  fake/in-memory server for the mailbox, not a real network round trip); a
  tampered signature is rejected without crashing and without disturbing
  the previous derived value; a stale/wrong-length ciphertext delivered to
  the responder is rejected the same way.

**Acceptance**: two real client processes (or client+server) against a real
test server converge on identical derived secret bytes for a pair, verified
by a shared test assertion point (e.g. writing the derived value to a file
each side can compare, similar in spirit to other cross-process convergence
checks in this project's test suite); a forged/tampered signature is
provably rejected in the same test run.

## M4 — PSK application

- Apply the M3-derived PSK to the relevant WireGuard peer configuration, on
  both initial exchange and each subsequent rotation.
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

**Acceptance**: a real two-peer test run shows the applied WireGuard
preshared-key value change from the interim value to the real derived value
once the first exchange completes, and again on subsequent rotations.

## M5 — Idle-detection pause/resume

- Add a `--pq-psk-idle-timeout <seconds>` option, default **15 minutes**
  (design.md §5.12).
- Before each rotation tick for a given peer, check that peer's WireGuard
  transfer byte-count delta since the last check; if unchanged for longer
  than the idle timeout, skip rotation for that pair only.
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

- Add `--enable-pq-psk` and `--pq-psk-permissive` options, following the
  existing option pattern already used for other optional per-peer
  features in this project.
- A peer with `--enable-pq-psk` but not `--pq-psk-permissive` treats a peer
  with no advertised KEM public key as unreachable (fail-closed, matching
  the existing default for other optional protections in this project).
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

**Acceptance**: running the server with this feature enabled results in its
own link to at least one enabled client carrying a real derived PSK,
verified the same way M4 verifies a client-side link.

## M8 — Build targets & platform support

- Confirm both crypto libraries (§2.1) cross-compile and link cleanly for
  both architectures this project already ships prebuilt binaries for:
  x86_64 (amd64) and aarch64 (design.md §5.13).
- Extend the existing release/build tooling to build this feature's
  binaries for both targets; confirm no non-Linux build path is silently
  affected (this feature stays Linux-only per design.md §4).
- Tests: a build matrix (CI) covering both architectures, not just the
  developer's native one.

**Acceptance**: both architectures' binaries build in CI and successfully
run the M3/M4 convergence test under emulation or real hardware for the
non-native target.

## M9 — Security review & hardening

Implements design.md §7's full Docker-based test plan against real
processes, not just unit tests with fakes:

- Stand up the four-container topology from design.md §7.1
  (`peer-a`/`peer-b` cooperating, `peer-m` adversarial/cross-CIDR, `peer-x`
  flood-only) in a new Docker-based test harness.
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
- Revisit whether carrying two independent crypto dependencies (design.md
  §2.1/§10) is worth it versus a single-library alternative, based on what
  this review finds about the practical audit/maintenance cost.

**Acceptance**: all eleven design.md §7.2 cases automated and green in CI,
including the security-negative ones (cross-CIDR isolation, malformed
payload, invalid signature, flood resilience) — a suite that only covers
the happy path does not close this milestone; findings and any resulting
default changes recorded back into design.md §6/§10.

## M10 — Docs & release

- Documentation section covering `--enable-pq-psk`, `--pq-psk-permissive`,
  `--pq-psk-rotation-interval`, and `--pq-psk-idle-timeout`, modeled on how
  any other optional feature is documented in this project.
- Manual-page updates, if this project ships them for other options.
- Migration note for existing deployments: this is purely additive/opt-in
  (new nullable fields, new table, no behavior change until an option is
  passed) — confirm and document that an old server can run against a
  migrated database with the new fields simply unused.
