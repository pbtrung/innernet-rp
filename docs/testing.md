# Test plan: unit tests and simulated Docker peers

Status: implementation in progress; see [implementation.md](implementation.md)
Related: [design.md](design.md), [milestones.md](milestones.md)

The numbered requirements in design section 7.2 remain the acceptance
checklist. This plan defines how to test them, which dependencies to replace
in unit tests, and which behaviors require real processes and WireGuard.
It does not change the protocol, its defaults, or its threat model.

## 1. Test layers and harness layout

| Layer | Executes | Replaces | Purpose |
| --- | --- | --- | --- |
| Unit | Production codecs, crypto adapters, policy and transition logic | Clock, storage/transport failures, kernel effects | Deterministic boundary and invariant checks |
| Integration | Real SQLite/files, API handlers and independent processes | WireGuard installer until M4 | Transactions, persistence, authentication and retry semantics |
| Docker | Built server/client binaries, system crypto libraries and WireGuard | Network conditions and selected crash points | Peer convergence, traffic enforcement and operational recovery |

Use the implementation language's normal unit-test framework once M0 selects
the baseline. The planned repository layout is `tests/unit/`,
`tests/integration/`, `tests/fixtures/`, and `tests/docker/`, with a shared
scenario manifest relating test names to design case numbers. Existing
baseline tests may keep their native locations; the manifest indexes them.

`tests/docker/` will contain the Compose definition, pinned image/build
recipes, enrollment fixtures, fault controls, and scenario driver. Provide
a documented runner with selectable `unit`, `integration`, `docker-smoke`,
`docker-faults`, `compatibility`, and `load` suites. M0 provides
`bash tests/run.sh SUITE`; unimplemented suites fail explicitly until their
milestone supplies the required assertions.

Each test has explicit preconditions, an action/fault schedule, expected
state and traffic assertions, a bounded deadline, and cleanup. Reuse protocol
fixtures across layers, but derive expected results from the specification
and independent vectors rather than asking the implementation under test
to generate its own expected answer.

## 2. Unit tests

Unit tests run without Docker, root, external services, network access, or
real-time sleeps. Use a virtual monotonic clock and a separately controlled
server expiry clock, scripted delivery queues, a fake WireGuard adapter,
and a persistence adapter that can fail before/after each durability boundary.
Keep real crypto primitives in cryptographic tests. Deterministic randomness
and fault adapters are test-only and unavailable to production configuration.

### 2.1 Encoding and cryptography

- Reproduce fixed B/T/E transcript, HKDF, signature, and confirmation-tag
  vectors from design sections 5.7/5.14. Compare the independently produced
  expected bytes; round-tripping one encoder/decoder alone is insufficient.
- Cover all three public keys and each message type. Exercise IDs around
  `2^53`, the `2^63 - 1` limit, zero/overflow, leading zeros, duplicate JSON
  fields, missing/extra fields, and noncanonical base64. Verify exact raw,
  encoded, and complete-request size boundaries, including 8 KiB plus one.
- Reject malformed ML-KEM keys, invalid P-521 points/scalars, high-S/DER
  signatures, wrong X448 length, and all-zero X448 results. A valid-size
  wrong-key ciphertext must fail confirmation without exposing an internal
  decapsulation-rejection flag.
- Verify both directions derive the same candidate for one exchange and
  different candidates for fixed, distinct encapsulation fixtures. Bind
  both bundles, identities, network, sequence, message type, and operator
  PSK ID. Changing one bound field or either secret must invalidate the
  relevant signature/tag or produce a different derived key as applicable.
- Inject failed randomness and crypto-library errors. Assert no candidate
  installation or partial registration follows. Wrong operator PSKs fail
  confirmation while the previously configured PSK stays untouched.

### 2.2 Exchange state machine and durable decisions

Use table-driven tests for every phase/message/sender combination, including
out-of-order and duplicate installed/confirmed receipts. Verify these
invariants after every event in both fixed and seeded generated schedules:

- At most one active exchange exists per data pair, including across bundle
  replacement; sequence/high-water marks never decrease within a bundle
  pair and new work cannot replace nonterminal work.
- Before commitment, failure or abort does not change the installed PSK.
  A durable commit requires valid readiness; after commitment timeout cannot
  select abort, clear the PSK, or independently restore the previous key.
- The responder installs first; the initiator needs its authenticated
  receipt. No side opens its application gate on an old handshake timestamp
  or merely on reading back a configured candidate.
- Failed persistence cannot produce a success receipt for an undurable
  transition. Restart reconstructs a legal state from durable data only.
- Duplicate messages preserve the recorded outcome. Conflicting content,
  old bundle IDs, and replay after a newer completed exchange never reinstall
  an obsolete PSK. Fresh server timestamps do not make old sequences valid.
- Expiry and commitment have a single winner. Prepare retries do not extend
  TTL; committed work survives it. Old receipts cannot erase a newer record.

Generate bounded sequences of delivery, loss, duplication, clock advance,
expiry, revocation, and restart. Record the schedule/seed on failure and
reduce failing schedules to a regression fixture. Assert safety throughout;
assert eventual completion only after faults stop, resources are available,
and both endpoints/relay receive fair execution. Permanent partitions have
no convergence deadline.

### 2.3 Policy, scheduling, and resource boundaries

- Strict/permissive behavior distinguishes absent, partial, malformed,
  retired, and previously established PQ identities. Test explicit enable,
  disable, re-enrollment, bilateral downgrade, and operator-PSK ownership.
- Check stable pair roles, server/self-target rejection, revocation, and
  network/bundle isolation independently of transport authentication.
- Advance the virtual clock around rotation, inactivity, and prepare-TTL
  boundaries. Include zero/negative/overflowing durations, wall-clock jumps,
  unrelated poll/rotation intervals, and jitter/`Retry-After` limits.
- Test counter resets and first observations. Keepalive traffic counts as
  activity, including handshakes caused by rotation itself; idleness pauses
  only new rotations. Initial exchanges and committed recovery proceed
  without application traffic.
- Exercise token-bucket refill/burst boundaries, concurrency slots, active
  record caps, paginated response budgets, and reserved recovery capacity.
  A rejected proposal must not consume a permanent slot or starve admitted
  work. Test fair progress for another peer while one pair retries forever.

## 3. Persistence and API integration tests

Use temporary real SQLite databases and the selected filesystem storage
implementation. In-memory fakes do not establish crash durability, locking,
atomic replacement, or schema compatibility.

- Open concurrent database connections to race ready/commit/abort/expiry,
  registration revisions, revocation, and stale acknowledgments. Assert
  one durable decision, correct foreign-key cleanup, and intact tombstones.
- Restart independent processes after controlled commit/write boundaries;
  reopen files/databases and check state, permissions, and gate intent.
  Cover failed writes/fsync/rename, quota exhaustion, corrupted files,
  ownership locks, symlink substitution, and restored stale snapshots.
- Run actual API handlers with the real authentication/session path. Test
  caller-derived identity, disabled/unredeemed peers, cross-CIDR requests,
  oversized/slow bodies, decoding failures, and visibility changes between
  continuation pages. Authorized malformed senders exercise parsing rather
  than stopping at an unrelated authorization rejection.
- Drop a response after the server commits a write, then retry the exact
  message. Lose a GET page and fetch it again. Assert idempotent outcomes,
  non-consuming delivery, and no reinstallation on terminal retries.
- Verify supported schema upgrades and backup restoration against recorded
  legacy databases/binaries. Unsupported newer schemas fail before writes;
  new-to-old-to-new runs must never lower or corrupt a schema marker.

A killed process/container is not a host power-loss test: the host can retain
filesystem caches. Use storage-fault injection for durability assumptions
and document any stronger VM/power-loss coverage separately.

## 4. Docker peer simulation

### 4.1 Services and network layout

Use separate containers and network namespaces for the server and every peer.
Normal scenarios run the real implementation and real crypto, not a fake
mailbox shared directly between client processes.

| Service | Identity/visibility | Role |
| --- | --- | --- |
| `server` | Coordination identity | Real API, directory and durable exchange database |
| `peer-a` | Cooperating data peer; lower ID than B/C | Initiates A–B and A–C exchanges |
| `peer-b` | Cooperating data peer | Rotation, restart and replay target |
| `peer-c` | Cooperating data peer | Unaffected A–C traffic/progress control |
| `peer-m` | Valid identity, no visibility of B | Cross-CIDR and authorization adversary |
| `peer-x` | Authorized synthetic sender | Malformed signed input and flood source |
| `legacy-peer` | Optional pinned old binary | Mixed-fleet profile |

An isolated Docker bridge supplies the outer IP/UDP transport for WireGuard.
The coordination API must be reached through each client's real server-link
WireGuard session; applications bind/connect to overlay addresses. Do not
substitute Compose service-name TCP access for the protected API or permit
application probes to succeed over the Docker underlay.

Use Compose `internal: true` and no published host ports for scenario
networks. Build/pull pinned images before starting the isolated test run.
Keep credentials and persistent state separate per participant; the server
must not mount data peers' private state. For independent admin recovery,
the host driver uses targeted container execution, modeling console access
without creating an application-accessible bypass. Docker's network controls
are described in its [Compose network reference](https://docs.docker.com/reference/compose-file/networks/).

The host must have the required Linux WireGuard and traffic-gate facilities.
Grant `NET_ADMIN` to participants that configure their own network namespace
and `NET_RAW` only to probes/capture tools that need it. Avoid privileged
mode, host networking, module-loading privileges in containers, and Docker
socket mounts in simulated peers. A preflight must fail clearly when the
required kernel/capabilities are unavailable, not silently replace kernel
WireGuard with a mock. See [Docker runtime capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities).

### 4.2 Provisioning and persistent fixtures

The driver generates unique network/peer/bundle identities per run and
creates invitations with separately provisioned management PSKs. Inject
those through owner-only fixture files, not environment variables or command
lines. This models the design's trusted out-of-band enrollment; it is not
evidence that a particular real-world invitation channel is secure.

Give the server and each peer their own run-scoped named volume. Reuse a
participant's volume for restart/recreation cases; use a new one only when
the scenario explicitly tests state loss and re-enrollment. Preserve the
server database and its migration fixtures independently of peer state.
Named volumes retain data beyond container removal, as described in the
[Docker volume documentation](https://docs.docker.com/engine/storage/volumes/).

Start the server and wait for local storage/listener health. Start invited
clients, establish their management tunnels, assert authenticated API
readiness, and redeem/register them before checking bundle preconditions.
Compose startup ordering alone is insufficient; use health checks plus
bounded authenticated API/peer-state readiness assertions. The driver must
not wait for an established A–B data link before starting the test intended
to exercise its initial failure. See [Compose readiness handling](https://docs.docker.com/compose/how-tos/startup-order/).

### 4.3 Fault controls and observations

Expose test-only barriers at durable-write, phase-acceptance, gate-change,
kernel-installation, and receipt boundaries. Control them through a local
test socket and host driver; they must not become production API endpoints.
Container process controls distinguish graceful shutdown, forced kill,
pause/resume, and recreation with preserved versus missing state.

For precise HTTP faults, use a client-local test proxy in that peer's network
namespace. It forwards through the real management tunnel with that peer's
source identity intact. Select faults by exchange ID and phase: reject the
request before forwarding, forward and drop the committed response, hold a
state page, or duplicate a message. A proxy on a shared underlay must not
replace authenticated peer identity with its own. Reordering TCP packets
alone does not simulate delivery of reordered application messages.

For network faults, apply loss/delay/partition rules only inside the chosen
participant's namespace, separately targeting its server link or data pair.
Clear injected faults before asserting recovery. Do not alter the host's
network rules or global clock. Virtual time drives unit tests; Docker tests
use real monotonic time and supported shorter test settings. Cases that
depend on WireGuard session expiry must wait for actual kernel timers.

Observe both control and data behavior: durable phase/high-water marks,
fresh peer-instance handshake evidence, traffic-gate state, successful and
blocked overlay requests, unrelated A–C progress, API responsiveness, and
resource usage. Run a positive reachability control for each negative traffic
test so a broken probe cannot masquerade as a working security gate.
Pair-specific faults must leave A–C connected. Whole-node/container restarts
can interrupt every link on that node; measure those expected interruptions
and recovery separately instead of demanding impossible A–C availability.

PSK comparison runs in a test-only helper that reports equality/inequality,
not raw keys or persistent key fingerprints. Do not log full WireGuard
configuration dumps, secrets, or private state. Keep optional packet captures
and snapshots local to the protected run unless explicitly sanitized.

### 4.4 Required Docker scenarios

1. **Smoke/convergence:** provision A/B/C and verify protected API access.
   Attempt application traffic before initial confirmation, establish A–B
   and A–C, then observe two rotations and fresh handshakes. Confirm matching
   endpoint PSKs and distinct successive values without exporting them.
2. **Lost commit response:** hold B at ready, accept A's commit at the
   server but drop its HTTP response, then restart A with preserved state.
   Release delivery and assert one committed exchange, forward recovery to
   the same candidate, and restoration of management/A–C after the expected
   restart interruption. A separate response-loss-only run keeps A–C live.
3. **Install crash matrix:** kill B before and after kernel installation
   and before its installed receipt; repeat for A. Recreate each container
   with its volume and assert safe gate restoration and no old-session
   bypass. Separately remove state and require blocked re-enrollment.
4. **Offline and expiry:** pause B before ready until prepare expiry, then
   resume it and reject the stale exchange. Repeat after commit: recovery
   survives TTL and must finish once B returns. Include a management outage
   longer than a real WireGuard session lifetime.
5. **Replay and tampering:** complete K0 then K1, replay K0 phases, and alter
   each authenticated field/tag/signature. Assert K1 stays installed and
   old receipts cannot affect later work. Repeat after server/peer restart.
6. **Isolation and policy:** attempt M-to-B access, revoke visibility between
   state pages, and test malformed payloads from authorized X. Exercise
   strict/permissive legacy combinations and explicit retirement/downgrade,
   including operator-PSK mismatch and preservation.
7. **Inactivity and fairness:** stop A–B application traffic with keepalives
   still active and assert no idle pause. Disable keepalives and allow
   handshake activity to settle, using a test idle timeout below the rotation
   interval so a traffic-free window can reach pause. Resume traffic and
   verify the next activity poll starts due work; A–C continues throughout.
   Separately test production timer ordering: rotation-generated handshakes
   count as activity and can prevent pause even with keepalives disabled.
8. **Management rotation:** use host-controlled independent admin access
   to stage/apply a new server-link PSK on both endpoints. Test successful
   handshake/API verification and mismatched installation repaired out of
   band. No mailbox request rotates or repairs this same management key.
9. **Adversarial/full profiles:** execute directory substitution as an
   expected threat-model limitation, the quantitative design case 14 flood
   target, real legacy/schema transitions, and both architecture profiles.

For deterministic Docker scenarios, use 1-second polls and a documented
shortened rotation interval, separate from production defaults. Pause
automatic new rotations when isolating a single-exchange fault. Readiness
and post-fault recovery get a 30-second deadline once preconditions hold;
expected offline/expiry waits get a scenario-specific bound. These ordinary
deadlines do not substitute for the load-case targets in design section 7.2
or shorten kernel timers. Never change production constants just for tests.

## 5. Coverage and CI acceptance

Map every design case to concrete test names in the shared manifest.
Assertions about real kernel/network behavior require Docker evidence even
when unit tests cover the corresponding decisions.

| Design cases | Unit evidence | Integration/Docker evidence |
| --- | --- | --- |
| 1, 8, 9 | Canonical vectors, malformed inputs, context binding | Real libraries and authenticated serialization paths |
| 2, 3 | Gate/installation decisions, stale-observation rejection | Kernel peers, fresh handshakes and actual traffic enforcement |
| 4, 5, 6, 7 | Generated loss/replay/crash/expiry schedules | Durable DB races and independent process/container recovery |
| 10 | Documented trust-model assumptions | Malicious-directory substitution is demonstrated |
| 11, 12 | ACL/phase/quota/pagination boundary decisions | Real sessions, page revocation, storage limits and TTL races |
| 13 | Virtual-time cadence, counters and fairness | Real keepalive-only and inactive tunnels with A–C control |
| 14 | Admission-budget and capacity-reservation boundaries | Measured offered load, RSS, p99 and admitted-peer progress |
| 15, 16 | Lifecycle/policy and secret-selection decisions | Enrollment, restart, operator keys and admin recovery |
| 17 | Version/policy dispatch | Exact old/new binaries and schema round trips |
| 18 | Architecture-independent vectors | Target runtime packages and real target-kernel execution |

Every pull request runs unit and persistence/API suites plus Docker smoke
on a supported Linux runner. Changes to crypto, state transitions, gating,
management provisioning, or persistence also run the associated Docker fault
matrix before merge. Nightly jobs run larger seeded schedules, all Docker
faults, compatibility, and measured load. Release validation requires all
18 design cases on the release revision; scheduled coverage is not a waiver.

Run x86_64 and aarch64 userspace checks with recorded library/image versions.
Kernel WireGuard/gate evidence on aarch64 needs a native runner or VM with
an aarch64 guest kernel; userspace emulation on an x86_64 host alone does not
test an aarch64 kernel. Missing facilities or legacy fixtures fail required
jobs clearly, rather than being silently counted as passing/skipped coverage.

Each result records case/test IDs, commit and image digests, library versions,
kernel/architecture, seed and fault schedule, effective timing/resource
settings, expected outcomes, and sanitized failure diagnostics. Retrying a
flaky scenario may aid diagnosis but cannot erase its first failure or replace
a deterministic regression test. Collect results before teardown, including
on timeout. Clean up only that run's labeled containers/networks/volumes and
temporary secrets; do not run global Docker prune operations.

M0 establishes unit fixtures, the manifest, and runner contracts; M1–M3 add
real persistence/API tests and a container skeleton; M4 enables real-kernel
smoke/fault tests; M5–M8 add scheduling, lifecycle, management, compatibility,
and platform profiles; M9 closes full coverage. Release testing is complete only
when its required assertions have recorded results, not when containers
merely start or a happy-path ping succeeds.
