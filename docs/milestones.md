# Milestones: post-quantum PSK exchange

Companion to [design.md](design.md). Each milestone is a separately testable
deliverable. M0 restores the baseline and establishes the harness for later
milestones; [implementation.md](implementation.md) records actual evidence.
Criteria below are not a claim that all milestones or tests are complete.
Follow [testing.md](testing.md) for unit fixtures, Docker peer simulation,
fault injection, coverage mapping, and CI execution requirements.

Introduce the enablement/policy gate in M1, before key generation, API
traffic, or WireGuard changes. A never-enabled installation remains inert
unless explicitly enabled. Once enabled, omission of a flag cannot silently
discard persisted security policy. Signatures are mandatory in protocol v1.
Before M4, enablement is confined to development/test paths; production
activation must refuse to claim strict protection without its traffic gate.

Management-link provisioning moves into M2 so that recovery is available
before M4 applies any data PSK. M7 completes management rotation/recovery
coverage. Data-peer rotation never changes the PSK carrying the coordination
API. No milestone claims uninterrupted two-party PSK installation.

## M0 — Baseline, crypto integration, and protocol fixtures

- Record the innernet baseline commit this project was derived from, as a
  historical/derivation record, along with implementation toolchain and
  test/build entry points. Establish the harness rather than assuming
  pre-reset files exist in this checkout. This is a new, independent
  design/app/binary with no old/new binary compatibility requirement
  against upstream innernet releases.
- Establish the unit framework, virtual clocks, scripted transport/storage/
  kernel adapters, canonical fixtures, and design-case coverage manifest
  from testing sections 1–2. Define the suite runner contracts before later
  milestones depend on them.
- Select the P-521/SHA-512 signing library and integrate it alongside
  leancrypto's combined ML-KEM-1024/X448 API plus SHA3, HMAC, and HKDF.
  Confirm API availability and failure behavior, including deterministic
  ECDSA, canonical signatures, and all required public-key checks.
- Link both crypto libraries and SQLite against system-provided shared
  installations. Record exact tested package versions in reproducible build
  environments, minimum runtime versions, ABI requirements, and x86_64/
  aarch64 cross-compilation constraints. Do not vendor/bundle copies or
  silently use a differently encoded library hybrid.
- Freeze the canonical B/T/E encodings, SHA-512 signature digest, RFC 6979
  nonce behavior, raw low-S signature representation, HKDF labels/salt,
  operator-PSK input, and directional confirmation tags in design section
  5.14/5.7. Publish fixed cross-implementation vectors for every message type.
- Verify ML-KEM modulus/length checks, X448 all-zero rejection, P-521 point
  and scalar validation, encoding boundaries, randomness failure, and
  correctly sized ciphertexts that produce implicit rejection. No API may
  expose ML-KEM's internal implicit-reject flag.
- Measure raw/base64/JSON fixtures, including all three public-key fields.
  Confirm 2092 bytes for a base64 ML-KEM key/component ciphertext, 2168 bytes
  for the full hybrid ciphertext including ephemeral X448, and all
  submitted message/registration fixtures fitting the 8 KiB request cap.
- Model proposed/ready/committed/complete/aborted transitions, durable
  receipts, and replay high-water marks before writing production PSKs.

**Acceptance:** independent encapsulate/decapsulate endpoints agree within
one exchange; separate randomized exchanges produce different PSKs. Both
implementations reproduce canonical vectors, including negative cases.
Library versions, build prerequisites, actual sizes, and protocol fixtures
are recorded. Neither production interfaces nor their PSKs are modified.

## M1 — Early policy gate, schema, and reliable API

- Introduce `--enable-pq-psk` and `--pq-psk-permissive`, validating their
  dependency from the start. Advertise `pq_psk_versions: [1]` only when the
  server's required enrollment/recovery prerequisites are ready; installing
  schema support alone is not operational readiness.
- Add the persistent network ID, explicit server role, stable non-reused
  peer IDs, and all three nullable public keys: KEM, X448, and signing.
  Add atomic bundle ID/revision, WireGuard identity binding, and lifecycle
  metadata. Distinguish absent, partial, malformed, and retired bundles.
- Implement atomic `PUT /v1/user/pq-keys` registration/retirement with revision
  compare-and-swap and the signed phase-message handshake endpoint.
- Implement one active durable exchange per unordered data pair and compact
  terminal sequence/outcome records. Enforce role-specific monotonic phase
  transitions and per-endpoint installation/confirmation receipts.
- Add opt-in, versioned paginated state responses. Keep legacy response
  shapes for legacy requests. Deliver non-destructively; duplicate retries
  return the recorded outcome. Old receipts cannot delete newer exchanges.
- Enforce current session identity, enabled/redeemed status, CIDR visibility,
  complete bundles, signatures, phase rules, and self/server-target rejection
  on writes and deliveries, including every continuation page.
- Enforce the design section 5.2 body/read-time/concurrency/rate/record caps
  before costly decoding or crypto. Reserve resources for admitted recovery,
  retirement, and ordinary coordination. Return bounded 4xx/429/503 errors.
- Enforce the 600-second prepare TTL on reads/writes and in a sweep; retries
  do not extend it, and expiry serializes with commitment. Committed work
  survives TTL. Retain freshness tombstones until bundle retirement.
- Use atomic versioned migrations that reject unknown newer schemas without
  writes and never lower version markers. Establish backup/rollback fixtures.
- Add real SQLite/API integration tests from testing section 3, including
  concurrent transition/expiry races, authenticated requests, page loss,
  and schema reopening; in-memory fakes alone do not verify durability.

**Acceptance:** API/schema tests cover all three keys, partial registration,
non-consuming fetches, duplicate/lost responses, phase conflicts, stale
receipts, authorization changes between pages, expiry races, tombstones,
and resource admission. Old-shaped records still deserialize. With
enablement absent on a never-enabled interface, no keys or PQ traffic are
generated and no WireGuard behavior changes.

## M2 — Durable identity and management-link provisioning

- Generate and register complete bundles on first enablement, including
  existing interfaces. Persist before registration using 0700 directories,
  0600 files, atomic durable writes, safe file creation, and an interface
  ownership lock. Handle failed randomness/writes without partial identity.
- Persist confirmed/pending exchange secrets, replay marks, retry messages,
  and gate/installation intent. Load them before touching a restarted
  interface; never rely on kernel configuration as the only PSK copy.
- Implement atomic bundle replacement after draining work, cache revision
  invalidation, and explicit emergency retirement/re-enrollment for lost
  keys, lost replay state, or stale backups. Never restart counters under
  an old bundle ID or silently overwrite another process's state.
- Provision an independent random per-client management PSK through the
  invitation's authenticated confidential out-of-band transfer. Preserve it
  across invitation redemption and persist it at server and client before
  link activation. Existing-network migration uses independent admin access
  and preserves any suitable existing operator-provisioned secret.
- Restore management PSKs before serving/reaching the API after reboot and
  enforce the management-only access policy. Missing/mismatched secrets block
  readiness rather than falling back to zero or a public placeholder.
- Display advertised, legacy, preparing, recovering, confirmed, and blocked
  states separately. A public key on file is not proof of protected traffic.

**Acceptance:** fresh/existing-interface enablement, registration crashes,
permissions/symlinks, simultaneous processes, identity retirement, invitation
redemption, and server/client reboot tests pass. A provisioned management
link remains usable independently of any client-to-client data key. No
mailbox-derived data PSK is applied yet. M4 is blocked until this independent
recovery channel and its restoration are implemented and tested.

## M3 — Durable exchange and confirmation loop

- Implement lower-ID initiator/higher-ID responder for data peers only;
  reject management-server pairs. Persist increasing per-bundle-pair
  sequences and random exchange IDs, permitting one outstanding exchange.
- Introduce `--pq-psk-rotation-interval`, default 300 seconds, on data clients.
  Reject nonpositive/overflowing values. Schedule from prior completion;
  short intervals cannot overwrite unfinished work.
- Implement propose, ready, commit, installed, confirmed, and abort messages
  with design section 5.14's exact signed envelopes and directional tags.
  Before commitment both sides must have verified agreement on the candidate.
- Derive the hybrid candidate using an explicitly adopted operator PSK, or
  the specified absent-key input. A mismatch fails before installation;
  a previous feature-derived PSK must not be misclassified as an operator key.
- Process all delivered phases on each state fetch, independently of rotation
  ticks and idleness. Retry identical persisted messages with bounded jittered
  backoff/`Retry-After`; use fair bounded workers across peers.
- Model a successful PSK installer/handshake observer in this milestone,
  without changing real WireGuard state. Exercise every durable-write,
  message-loss, reorder, and crash boundary, including commit-versus-abort.
- Add seeded unit event schedules and a Docker server/client skeleton with
  separate identities/volumes and peer-preserving fault controls. Keep
  simulated installer results distinct from M4's real WireGuard evidence.
- Never independently roll back committed work. On restart reconcile its
  durable decision and recover forward; unresolved commitment blocks new
  work for that pair, not all other pairs.

**Acceptance:** independent processes converge on one candidate and terminal
outcome through a real test API, with fake kernel application. Lost responses,
replays after newer completion, stale generations, wrong confirmation tags,
TTL races, and restarts cannot change the decision or reinstall an obsolete
key. Test-only comparisons use owner-only temporary storage excluded from
logs and uploaded artifacts. Production WireGuard PSKs remain untouched.

## M4 — Fail-closed data activation and kernel recovery

- Implement the persistent Linux application-traffic gate from design
  section 5.6, covering local/forwarded IPv4/IPv6 traffic and route fallback.
  Restore the gate before interfaces/peers on boot; existing sessions cannot
  bypass initial strict enablement. Transport handshake/keepalive probes may
  run while application traffic remains gated.
- After durable commitment, install on the responder first and wait for its
  authenticated installed receipt before installing on the initiator.
  Persist intent before kernel writes. Remove/recreate only the affected
  peer with the full authorized configuration and candidate PSK, discarding
  old sessions/in-flight handshakes. Accept and measure the interruption.
- Require a fresh authenticated handshake on that new peer instance; persist
  confirmation before opening its application gate and send the signed
  receipt. Old handshake timestamps or configured-key readback alone cannot
  prove the exchange completed.
- Before commitment leave the working PSK unchanged; afterward reapply/retry
  the candidate following crashes or kernel/API errors. No timeout-based
  unilateral rollback, PSK clearing, or public-key-derived interim PSK.
- Verify operator-PSK adoption/preservation and explicit unrecoverable-state
  retirement. Configuration ownership conflicts must fail visibly rather
  than silently overwriting another PSK manager.
- Run Docker smoke and loss/install-crash/replay scenarios from testing
  section 4.4 with real kernel peers. Use cooperating peer C as the A–C
  traffic/progress control while A–B fails or rotates; verify both blocked
  traffic and positive probe reachability.

**Acceptance:** real WireGuard tests pass design cases 2–7: first activation,
repeated rotations, interruption measurement, lost acknowledgments, crashes
around every gate/kernel/write boundary, and replay rollback. Strict traffic
never escapes through an old unprotected session or route fallback; unrelated
peers and the management API remain usable throughout data-key mismatch.

## M5 — Tunnel-inactivity pause and fair scheduling

- Introduce `--pq-psk-idle-timeout`, default 900 seconds; zero disables
  pausing. Document that it measures tunnel traffic including keepalives,
  not application idleness.
- Sample WireGuard counters on every state-fetch cycle. First observations,
  counter resets, and peer recreation establish a fresh baseline and count
  as activity; use monotonic elapsed time and checked arithmetic.
- Pause only new rotations. Resume an overdue rotation on the first poll
  observing traffic, without waiting another rotation interval. Initial
  exchanges, receipt processing, reconciliation, and recovery never pause.
- Exercise healthy persistent keepalive, keepalive-disabled inactivity,
  counter reset, distinct poll/rotation periods, resource backoff, and
  concurrent active/idle peers under fair scheduling.

**Acceptance:** design case 13 passes: a truly inactive tunnel pauses and
resumes promptly, a keepalive-only tunnel does not pause, pending work
progresses without application traffic, and other peers remain independent
within shared resource budgets.

## M6 — Mixed-fleet policy and explicit lifecycle transitions

- Complete strict/permissive behavior using the options introduced in M1.
  Strict blocks until confirmed PQ data activation. Permissive permits
  legacy only for entirely absent bundles with no prior successful local
  PQ relationship, preserving an existing operator PSK.
- Persist prior-PQ status. Partial/invalid/retired bundles, failed signatures,
  failed rotations, and disappearing capabilities never silently downgrade.
- Make disabling/re-enabling explicit and durable. Drain work or retire it
  while gated, publish retirement atomically, and retain recovery state until
  retirement is confirmed. Missing startup flags cannot bypass this process.
- Legacy transition requires explicit authorization on both endpoints and
  matching restoration of the operator PSK, or explicitly authorized zero
  PSK. Remote strict peers remain blocked; local opt-out cannot force them.

This project has no old/new client-server binary compatibility requirement:
it is a new, independent design/app/binary, not a fork retaining wire
compatibility with upstream innernet releases. "Legacy" in this milestone
means a peer that has never advertised a PQ bundle, not an old binary.

**Acceptance:** design case 15 passes. Reports distinguish permissive
legacy exemption from expected strict refusal, and configured/advertised/
confirmed protection states are accurate.

## M7 — Management PSK rotation and operational recovery

- Extend M2's working management provisioning with design section 5.10's
  administrative rotation procedure: independent admin access, durable
  staging at both ends, coordinated peer replacement, fresh-handshake/API
  verification, and removal of superseded secrets only after confirmation.
- Exercise failed installation at either end and coordinated repair to the
  same old or new secret using independent access. Never depend on a broken
  management tunnel to transport its own repair or fall back to no PSK.
- Test simultaneous server reboot/client restart, invitation-to-final-peer
  identity changes, management-only ACLs, lost management secrets, and
  restoration of many per-client management PSKs before API startup.
- Verify mailbox targets exclude the server link, and client data-key
  disagreement cannot itself disrupt the management key/configuration.
  Automatic management-PSK rotation is not part of version 1.

**Acceptance:** design case 16 passes, including successful and failed
administrative rotations, out-of-band repair, and general server/transit
traffic denial. Operational docs distinguish stable independent recovery
from a claim that the management secret can never be changed.

## M8 — Build targets and runtime dependencies

- Build and execute on Linux x86_64 and aarch64 using the system shared
  libraries/version constraints established in M0. Check actual target
  runtime loading as well as cross-compilation.
- Establish release/build automation for both architectures and record the
  exact test environments. Run the crypto, durability, gate, and WireGuard
  convergence checks under supported emulation or real hardware.
- Keep legacy non-Linux paths usable with PQ disabled; reject unsupported
  feature options clearly without pulling mandatory Linux-only runtime
  requirements into those paths.

**Acceptance:** design case 18 passes on both architectures, and runtime
package/ABI requirements and non-Linux feature boundaries are recorded.

## M9 — Security, fault, and load review

- Complete all 18 numbered cases in design section 7.2 against the specified
  container topology, fault injector, persistent state, and real processes.
  Earlier milestone results may be reused for the same tested revision;
  happy-path convergence alone does not close this milestone.
- Close every unit/integration/Docker entry in the testing section 5
  coverage manifest. Require the documented pull-request/nightly/release
  suites and preserve reproducible seeds, schedules, and sanitized results.
- Review canonical authentication and the hybrid combiner, static-key
  compromise limits, operator-PSK retention, replay/rollback safety, secret
  persistence, strict traffic gating, and forward recovery after commitment.
- Demonstrate the trusted-directory limitation: initial key substitution by
  a malicious directory is possible despite mandatory signatures. Ordinary
  peers must still fail forgery/substitution checks. Do not report the
  directory-compromise demonstration as a prevented attack.
- Exercise the quantitative flood target in design case 14, recording
  hardware, offered load, admission responses, peak RSS, response percentiles,
  and progress of already-admitted exchanges. Test body caps, TTL/read races,
  database budgets, and recovery-capacity reservation independently.
- Validate the 300/900/600-second rotation/inactivity/prepare defaults and
  per-peer/global budgets. Any adjustments update design, implementation,
  tests, and release docs together. Signature policy and system linking are
  already decided and are not optional downgrade mechanisms.
- Finish process/database downgrade/re-upgrade testing from design section
  10, including legacy binaries that rewrite newer schema markers. Prevent
  unsupported rollback and test the coordinated backup recovery procedure.

**Acceptance:** all design cases have recorded passing enforcement checks
and documented expected limitations. Review findings are resolved or the
relevant release claim is narrowed explicitly. Secret material is absent
from production outputs, test logs, and uploaded artifacts. Do not claim an
external cryptographic audit unless one has actually been performed.

## M10 — Documentation and release

- Document the enable/permissive/rotation/inactivity options and their exact
  defaults, validation, persistence, and client/server applicability.
- Document management invitation provisioning, independent administrative
  PSK rotation, data-link interruption, forward recovery, key loss/retirement,
  explicit disable/downgrade, and operator-PSK ownership.
- State the passive-quantum threat model, trusted directory, classical
  signatures, absent PSK-layer forward secrecy, management-link exception,
  and the distinction between tunnel inactivity and application idleness.
- Publish exact supported client/server/runtime/schema combinations and
  their real test results. Nullable fields and old-shaped deserialization
  are not evidence of arbitrary backward compatibility.
- Allow direct old-server database rollback only for proven-compatible
  binaries. Otherwise require a matching pre-upgrade backup and coordinated
  endpoint/policy/management restoration, retiring bundle IDs if replay
  state would go backward. Never lower newer schema version markers.
- Update manual pages if the selected baseline ships them. Explain that
  upgrading a never-enabled network is opt-in, while strict enablement and
  management-link provisioning intentionally change behavior.

**Acceptance:** release documentation matches the implemented/tested
protocol and compatibility matrix; required management provisioning and
recovery instructions are available before users can enable strict PQ.
