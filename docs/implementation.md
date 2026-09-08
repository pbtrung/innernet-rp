# Implementation and validation record

## Baseline and supported environment

The implementation restores innernet 2.0.0 at
`e922387122874c8182abab5b1c1e3eed2da1ba7f` (pre-Rosenpass). Its database schema
is `PRAGMA user_version = 2`. Netlink API adaptations are taken from the later
`7ca1b57` changes to the two kernel integration files only; no Rosenpass daemon
or crypto is included. Hyper 1 and ureq 3 replace obsolete HTTP interfaces.
Unknown newer database schemas are rejected before writes.

This records the legacy baseline, not completed old/new compatibility.
Actual legacy process interoperability belongs to M6; no old binary is
authorized to open a migrated live database. Retain a stopped-server backup
with matching endpoint configuration before migration. Stale replay-state
restores require retirement/re-enrollment, not reused bundle counters.

Tested on Linux x86_64, Arch Linux, 2026-09-07:

| Component | Exact package version | Minimum supported runtime/ABI |
| --- | --- | --- |
| Rust/Cargo | `1:1.98.1-1` (rustc 1.98.1) | Development toolchain 1.98.1 |
| leancrypto | `1.8.0-1` | 1.8.0, `libleancrypto.so.1` |
| OpenSSL | `3.6.4-1` | 3.6.4, `libcrypto.so.3` |
| SQLite | `3.53.4-1` | Tested/supported 3.53.4, `libsqlite3.so.0` |
| C compiler | `16.2.1+r23+gd564253eb6c8-1` | C11 plus platform headers |
| pkgconf | `3.0.7-1` | pkg-config-compatible tool |

Install matching system runtime and development packages before building.
`pkg-config --modversion leancrypto openssl sqlite3` must resolve the shared
installations. No vendored/bundled crypto or SQLite feature is enabled.
`pq/native/crypto.c` is a narrow ABI adapter, not a copy of either library.
The build probes minimum crypto versions and checks ML-KEM struct sizes.
Package changes require vector/native interoperability tests, not just relinking.

The reproducible x86_64 container uses Arch base digest
`sha256:82b1b08faae9d61e3e7e13d562f4d09114d939105b0d59ff34140f3bd418593a`
and the frozen Arch repository snapshot `2026/09/07`. Build and run the
userspace checks with:

```sh
docker build -f tests/docker/Dockerfile.build -t innernet-pq-build:m0 .
docker build -f tests/docker/Dockerfile.test -t innernet-pq-tests:m0 .
```

The test context excludes local settings, Git metadata, database/config/key
files, and build output. Containers do not mount host credentials or configure
host networking. These userspace checks are not the M4 kernel-peer scenarios.

All direct registry Rust dependencies were checked against current stable
crates.io releases on 2026-09-07. Cargo.lock fixes the complete resolution;
older transitive major versions may remain where an upstream crate requires
them. Dependency updates include API migrations and repeat locked tests.

There is no installed rustup/nightly in the recorded environment. The commit
workflow uses `cargo fmt --all` as its documented fallback; nightly-only
format settings warn and are not applied. Clippy warnings remain errors.

For aarch64 cross-builds, supply a target C compiler, target sysroot, target
shared libraries/headers and target pkg-config search directories. Never
point target pkg-config at x86_64 libraries or enable static/bundled fallback.
The native interop executable must run on the target (native/VM, or explicitly
configured userspace emulation); it is not a host-side proof. aarch64 execution
and non-Linux packaging remain M8 acceptance work.

## Crypto and fixture evidence

M0 (`c2fe868`) originally tested standalone primitives. The requested follow-up
adopts `lc_kyber_x448_keypair/enc/dec` with `LC_KYBER_1024` and checked
load/pointer/public-key recovery APIs. Initialize with `LC_INIT_NON_PQC_ENABLED`
for classical X448. Key generation seeds a local library Hash-DRBG from 64
bytes of fallible OS entropy; encapsulation uses leancrypto's seeded RNG and
fresh ephemeral X448 key. No process-global test RNG override is installed.

The combined API returns raw ML-KEM/X448 shared-secret components, which retain
the protocol's HKDF-SHA3-256 combiner, operator input, and confirmation labels.
The optional KMAC `*_kdf` APIs are not selected. See the
[leancrypto 1.8.0 hybrid implementation](https://github.com/smuellerDD/leancrypto/blob/v1.8.0/ml-kem/src/kyber_x448_kem.c).
This explicit pre-release wire revision appends ephemeral X448 to ciphertext
and updates all transcript/signature vectors; old 1568-byte proposals fail
length validation. The historical M0 result record remains scoped to M0.

OpenSSL provides P-521/SHA-512 with explicit RFC 6979 nonce mode, compressed
point validation, checked scalars, raw 66-byte r/s, and low-S normalization/
rejection. Errors never expose an ML-KEM implicit-rejection flag. Rust secret
arrays zeroize on drop; native temporary secret buffers are cleansed.

`tests/fixtures/reference.py` independently encodes B/T/E and calculates
SHA3/HMAC/HKDF and RFC 6979 P-521 signatures using Python standard-library
hashes and public fixed scalar arithmetic. It is test-only, not constant-time.
`protocol-v1.json` is public test material, not production credentials. Rust
tests compare every message type and both receipt directions with this oracle.

`tests/fixtures/interop.c` tests both OpenSSL-to-leancrypto and leancrypto-to-
OpenSSL ML-KEM encapsulation/decapsulation, compares seeded public/private
encodings, and compares X448 public/shared outputs. It also constructs hybrid
encapsulation/decapsulation independently in OpenSSL and compares both raw
secret components with leancrypto's combined API in both directions. It is compiled only by a
test, never into either production binary.

Measured compact JSON fixtures (not HTTP framing):

| Fixture | Bytes |
| --- | ---: |
| B, raw | 1747 |
| T, raw | 5220 |
| E, raw | 156 |
| Bundle JSON, three keys and metadata | 2455 |
| Propose JSON | 2816 |
| Each ready/commit/installed/confirmed/abort JSON | 587 |
| ML-KEM public key or ciphertext, base64 | 2092 |
| Full hybrid ciphertext, base64 | 2168 |
| Three public keys, separately base64 encoded | 2260 |

M1 registration wrappers must also fit the 8192-byte cap. Tests cover cap/cap+1,
canonical decimal/base64/JSON, malformed keys, high-S signatures, all-zero X448,
implicit-reject confirmation, failed RNG, context/operator-secret substitution,
and distinct random exchanges. Virtual clocks and scripted storage/transport/
kernel effects live only in `tests/unit/support.rs`; they model durability and
fresh-handshake boundaries, not actual power loss or traffic enforcement.

## Runner contract and evidence boundaries

Use `bash tests/run.sh SUITE`. `unit` checks independent fixtures and native
Cargo tests; `integration` runs independent native-library endpoints and gains
real storage/API tests in M1–M3. Both need build prerequisites but no external
services, root, real-time sleeps, or production interfaces. The upstream
public-IP external-service test remains explicitly ignored. The baseline
userspace interface test previously silently returned for non-root but changed
interfaces as root; it is now explicitly isolated/ignored, with a real pure
builder test in the default suite. WireGuard examples are compile-only.
Neither excluded integration test counts as feature evidence. IPv6 tests use
the separate `v6-test` feature run. Baseline address enumeration is read-only
but needs netlink socket permission in a restrictive sandbox.

Reserved `docker-smoke`, `docker-faults`, `compatibility`, and `load` suites fail
with exit 2 until implemented; missing evidence is never reported as a pass.
`tests/coverage.json` maps all 18 design cases, distinguishing implemented
tests from future real-kernel/load assertions. Later milestones update it.

M0 does not touch production interfaces. Its tests do not establish protected
data traffic, management enrollment, kernel recovery, broad compatibility, or
an external audit.

## M1 — Policy, schema, and public mailbox

The CLI now validates opt-in/dependent permissive options before side effects.
Production activation still refuses until M4's management recovery and traffic
gate are present. Tests explicitly construct a ready service; schema v3 alone
does not advertise `pq_psk_versions: [1]`. Public server capabilities omit the
new field when not ready, and legacy state requests retain their old shape.

Schema v3 atomically migrates versions 0/1/2, persists the network ID, records
the server role by its configured key/address, and makes peer IDs immutable
and non-reusable. Complete public bundles register by revision CAS with a
permanent bundle-ID registry. Partial/invalid keys fail before registration;
retirement is explicit, with emergency retirement invalidating affected work.
The public API stores no endpoint secrets or candidate PSKs.

Signed phase writes use immediate SQLite transactions, durable duplicate
receipts, one active exchange per pair, and compact terminal high-water rows.
Expired preparation is committed even when the triggering late write fails.
Committed exchanges do not expire. Peer disabling/association removal
invalidates work transactionally; re-enabling does not resurrect that work.
The sweep snapshots small primary keys, not all transcript bodies, and indexes
prepare expiry separately from committed recovery.

Requests are limited to 8192 streamed bytes and a five-second body deadline,
with bounded blocking workers, caller/global token buckets, and reserved
recovery slots/tokens. Database growth admission keeps a recovery reserve.
`?phase=N` and `?retire=1` select admission classes before decoding and must
match the body. Limit errors include `Retry-After`. PQ reads use a separate
eight-worker pool. Opt-in pages contain at most 32 objects (a stricter cap than
32 PQ records), 128 KiB of PQ content, and 1 MiB total. HMAC keyset cursors bind
requester and visibility revision; changing authorization invalidates them.
They expire on server restart because the signing key is process-local.

`bash tests/run.sh integration` now runs native hybrid interoperability and
15 real SQLite/API tests. They cover schema backups/reopening, rollback on
failed migration, byte-for-byte newer-schema refusal, ID/revision overflow,
registration CAS, phase/expiry races over separate database connections,
lost/duplicate pages and replies, replay tombstones, invalidated sessions,
streamed body limits/deadlines, retirement, and recovery under exhausted
record/worker budgets. The policy unit test separately checks inert defaults.
The coverage manifest labels this API/storage evidence, not kernel protection,
independent client-process convergence, or old/new binary compatibility.

## M2 — Durable identity and management-link provisioning

`pq/src/store.rs` implements owner-only private state: 0700 directories,
0600 files, `O_NOFOLLOW`-traversed paths, an exclusive `flock` interface
lock held only by the process actually using it, atomic `renameat` commits,
and a generation/digest check that turns a concurrent writer into a durable
`Conflict` rather than a silent overwrite. `pq/src/state.rs`'s `EndpointState`
models identity generation, revision-CAS bundle replacement, management-link
storage, and per-relationship exchange secrets on top of it; `observe_remote`
refreshes a cached remote bundle on a strictly newer revision (invalidating
any pending exchange pinned to the superseded bundle ID) and rejects a
replayed/older one, and `emergency_retire` blocks every relationship and
discards their secrets without rewinding sequence counters, for the lost-key/
lost-replay-state recovery path.

Management-link provisioning (design 5.10) now rides ordinary peer
invitations instead of a separate enrollment step: `server::management::
Manager::open_or_create` is the short-lived handle `add-peer`/`enable-peer`
use to provision a new peer's link and durably latch `pq_network.
management_ready` once every enabled peer has one; `Manager::load` is the
strict handle `serve()` uses, failing closed if the persisted state doesn't
match this network or any enabled peer's link is missing/corrupt. A separate
`innernet-server require-management` command and `management::prepare` cover
retrofitting an existing network (out-of-band `peer-N.management.json`
artifacts for peers that redeemed before management was required).
Client-side, `client-core::management` persists a redeemed enrollment before
the interface ever comes up with its PSK, and restores it across a client
restart before the interface is reconfigured.

A new server-link traffic policy (`server/src/gate.rs`) is narrower than
M4's future data-peer gate: once a network requires management, an
idempotent nftables table scoped entirely to the server's own interface
allows established/related traffic, PMTUD-relevant ICMP/ICMPv6, and the
coordination API's TCP port, and drops everything else in/forwarded through
that interface.

Two real defects surfaced only once end-to-end Docker evidence existed,
both silently dropping a peer's management PSK back to an unprotected
link on a kernel peer-config rebuild that predates this feature:
`serve()`'s startup peer-config loop called the per-link PSK lookup for
every database peer, including the server's own row (which by construction
never has a link), turning ordinary startup into a hard failure; and
`api::user::redeem`'s delayed post-redemption `DeviceUpdate` (see the
`REDEEM_TRANSITION_WAIT` comment there) rebuilt the redeeming peer's kernel
entry from a plain, PSK-less builder, silently reverting a freshly
protected link to a mismatched one that could never complete a handshake
again. Both are fixed; `Context.management` now carries a lightweight
`Arc<HashMap<peer_id, psk>>` snapshot, taken once at `serve()` startup
after the private-state lock is released, specifically so handlers like
`redeem` can preserve a PSK on a rebuild without holding that lock.

`tests/docker/` gained a real scenario for this milestone: `Dockerfile.
runtime` builds the actual workspace binaries on the pinned M0 base image;
`docker-compose.m2.yml` runs one server and two data peers (`peer-a`,
`peer-b`) on an isolated internal bridge with real kernel WireGuard
interfaces (verified this host can create them under `--cap-add NET_ADMIN`)
and static addresses (container-name DNS is not reliable on an `internal:
true` network); `scenarios/m2_management.sh` drives it with the real
`innernet-server`/`innernet` binaries exactly as an operator would — no
test-only entrypoint exists, because management-link provisioning never
depended on `--enable-pq-psk`, which stays gated. It asserts: fresh
invitation-carried enrollment yields independent, non-empty PSKs on both
peers; the coordination API stays reachable while an unrelated service
bound on the server's overlay address is unreachable through the same link
(a real positive/negative reachability pair, not a closed-port stand-in);
a server restart preserves the durable link and API access; and deleting
an enabled peer's link from the private store makes the next `serve()`
refuse to start rather than silently reporting readiness. `bash tests/run.sh
docker-smoke` now runs this scenario; `docker-faults`/`compatibility`/`load`
remain unimplemented as before.

Tested on Linux x86_64, Arch Linux, 2026-09-07, Docker 29.7.2, kernel
WireGuard module 7.2.2-1-cachyos:

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked` | all suites pass (pq: 4+7+1+12+2; server: 53 + 1 explicitly ignored; client-core: 6; shared: 5; wireguard-control: 12 + 1 explicitly ignored) |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` | passed |
| `bash tests/run.sh unit` / `integration` | passed |
| `bash tests/run.sh docker-smoke` (`scenarios/m2_management.sh`) | passed: enrollment/PSK independence, ACL positive+negative control, server-restart durability, lost-link fail-closed startup |
| `server::gate::tests::apply_installs_a_real_ruleset_and_clear_removes_it` (`#[ignore]`, run in a `--cap-add NET_ADMIN` container; this sandbox has neither root nor that capability) | passed |

Explicitly out of scope for M2: the admin HTTP peer-creation endpoint
(`api::admin::peer::handlers::create`) does not yet provision a management
link or preserve a PSK on its own kernel rebuild — only the CLI `add-peer`
path does; data-peer identity/bundle generation and the exchange/rotation
loop remain gated behind `--enable-pq-psk`'s existing production refusal,
unchanged from M1; and the full 5-peer/9-scenario Docker fault apparatus
from `docs/testing.md` section 4 is M4+ work, not attempted here.

## M3 — Durable exchange and confirmation loop

The server side needed no new work: M1's mailbox API already implements
registration, the signed phase-message handshake, and versioned paginated
state in full. M3 adds the client-side decision engine and driver loop that
actually walk that API, plus a real `--pq-psk-rotation-interval` (default
300 seconds) client-only flag added to `PqOptions` (validated non-zero and
non-overflowing; the server flattens it too but never reads it).

`pq/src/engine.rs`'s `EndpointState::reconcile` is a pure function — no
network or kernel I/O beyond a new `Installer` trait — deciding, for one
data-peer relationship, what to do this cycle: initiate a rotation once due
(lower peer ID only, never superseding pending work), respond to a fresh
proposal, build/send the next phase message, install then send `Installed`
once committed (responder first, reusing `Decision.installed[]`'s already-
encoded ordering), confirm a handshake and send `Confirmed`, or finalize
into `Relationship.confirmed` once complete. Per M3's own mandate ("model a
successful PSK installer/handshake observer... without changing real
WireGuard state"), `FakeInstaller` records calls instead of touching
WireGuard; M4 supplies a real implementation without changing the engine.
A single uniform `durably_sent` retry check (checked against the *server's*
reported record, never this side's own possibly-ahead local mirror of it)
replaces per-phase retry logic, including for the final `Confirmed`
message and for a record already compacted by `Exchange::compact()`.

`client-core/src/pq_sync.rs` walks `GET /user/state?pq_version=1` pages
(looping on `next_cursor`, restarting on a `409` revision change) and drives
the engine for every visible data peer, PUTing the resulting signed message
and persisting state via the existing `Store` before acting. Network access
sits behind a `Transport` trait so tests substitute an in-process server
(spoofing per-peer source addresses the way real WireGuard tunnels would)
without real sockets, root, or a kernel interface; `RestClient` is the
production implementation. `server::test::Server`, the crate's existing
in-process API test harness, is now reachable from other crates via a new
`test-harness` Cargo feature (never enabled in a normal build), so
`client-core/tests/pq_exchange.rs` can run two independent `EndpointState` +
driver-loop instances against the real session/API/db path and show they
converge on one candidate, with a simulated restart (drop the store's
interface lock, reopen) leaving the durable outcome untouched.

That real-API test, and separately `pq/tests/schedule.rs`'s 300 seeded
reproducible randomized fault schedules (lost responses, restarts, time
advances, run over a fast in-crate simulated mailbox), each caught a real
durability bug that pure single-path unit tests had missed — both
stemming from `Exchange::compact()` clearing `messages`/`transcript` once
a record goes terminal, or from a side's own local decision mirror racing
ahead of what the server actually durably recorded:

- The per-message absorb loop couldn't find the counterparty's final
  message once compacted, so a side that fell one poll behind would never
  observe completion. Fixed by adopting the exchange's own still-present
  terminal `Decision` wholesale instead of replaying individual messages
  once terminal.
- The retry check itself had a symmetric gap: it trusted a *locally*-
  optimistic terminal decision as proof of durability, but a side's own
  final message (e.g. its `Confirmed` receipt) can be exactly the one
  that got lost, letting that side falsely declare victory. Fixed by
  keying "is this terminal record trustworthy" off the server's own
  reported `Exchange.decision`, which can only reach a terminal phase
  once every required message was truly processed.

M3's Docker evidence needed a bypass M2 never did (real identity
generation and a real exchange both require `--enable-pq-psk`, which stays
gated in the shipped CLI). Both `client`/`server` gained a `pq-dev-harness`
Cargo feature (off by default, never in a normal build): under it, `serve()`
actually populates `Context.pq` (which the real `serve()` otherwise always
leaves `None`, regardless of any flag) and skips the production refusal
entirely; the client gains one hidden, non-interactive subcommand
(`pq-dev-rotate <interface> <other-peer-id>`) that generates an identity,
registers it, and drives the same real `pq_sync` loop with a
`FakeInstaller` until convergence, printing the resulting PSK — bypassing
the refusal only for that specific subcommand. `tests/docker/
scenarios/m3_exchange.sh` runs two real containers through the real
mailbox API (with a fake installer; M3 never touches real WireGuard state)
and asserts they converge on the same candidate; wired into
`bash tests/run.sh docker-smoke` alongside M2's scenario.

Tested on Linux x86_64, Arch Linux, 2026-09-07, Docker 29.7.2:

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked` | all suites pass (pq: 4+11+1+12+2, including the 300-schedule property test; server: 53 + 1 explicitly ignored; client-core: 6 + 1 real-API integration test; shared: 6; wireguard-control: 12 + 1 explicitly ignored) |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` (default, and again with `--features pq-dev-harness,test-harness`) | passed both ways |
| `bash tests/run.sh unit` / `integration` | passed |
| `bash tests/run.sh docker-smoke` (`scenarios/m2_management.sh` + `scenarios/m3_exchange.sh`) | passed: M2's scenario unaffected; M3's two independent containers converge on one candidate through the real API |

Explicitly out of scope for M3: real WireGuard installation/handshake
observation (M4's job — `FakeInstaller` only); a second real rotation for
the *same* established identity through Docker (the `pq-dev-rotate`
harness always generates a fresh identity per invocation; re-rotation of
an established relationship is already rigorously covered by
`pq/src/engine.rs`'s own unit tests, just not through real containers);
proactive client-initiated `Abort` (the engine only observes one, whether
peer-signed or TTL-expired — sending one is policy/M6 territory); the idle-
timeout/inactivity pause scheduling that reuses this driver loop (M5); and
`--pq-psk-rotation-interval` is validated and consumed by the engine, but
no CLI path yet threads a live client's flag value all the way into a
running `up --daemon` loop, since that loop's own PQ wiring stays behind
`--enable-pq-psk`'s production refusal until M4.
