# Implementation and validation record

## Baseline and supported environment

The implementation restores innernet 2.0.0 at
`e922387122874c8182abab5b1c1e3eed2da1ba7f` (pre-Rosenpass). Its database schema
is `PRAGMA user_version = 2`. Netlink API adaptations are taken from the later
`7ca1b57` changes to the two kernel integration files only; no Rosenpass daemon
or crypto is included. Hyper 1 and ureq 3 replace obsolete HTTP interfaces.
Unknown newer database schemas are rejected before writes.

This records the historical baseline this project was derived from, not a
compatibility commitment; this is a new, independent design/app/binary
with no old/new binary compatibility requirement against upstream innernet
releases. No old binary of this project's own prior releases is authorized
to open a migrated live database. Retain a stopped-server backup with
matching endpoint configuration before migration. Stale replay-state
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
The coverage manifest labels this API/storage evidence, not kernel protection
or independent client-process convergence.

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

## M4 — Fail-closed data activation and kernel recovery

M4 is where the feature starts touching real kernel state and becomes a
real, usable production feature for the first time: a real per-peer Linux
traffic gate, a real `Installer` that recreates WireGuard peers with the
candidate PSK and observes genuine kernel handshakes, and — because M2
(management recovery) and this milestone (the gate) are exactly the two
preconditions M1-M3's refusal comment named — production `--enable-pq-psk`
activation itself.

`client-core/src/gate.rs` is a new client-side nftables mechanism, distinct
from `server/src/gate.rs`'s whole-interface, permanent management-only
gate: it is per-peer and transient, and matches by *address* (named
`blocked_v4`/`blocked_v6` sets), not by which kernel peer entry currently
routes it — so a less-specific route (e.g. a hub peer's `0.0.0.0/0`) cannot
carry blocked application traffic to a gated peer's address through a
*different* peer entry while that peer's own `/32`/`/128` route is briefly
absent for recreation. Two lifecycle tiers match the two real needs:
`apply_all` is an idempotent destructive recreate, used exactly once per
cold boot (nftables state does not survive a reboot, so this restores every
known relationship's gate before any peer gets a kernel entry again);
`block`/`release` are idempotent additive/element operations for a single
peer's rotation, never disturbing any other peer's concurrent gate state.

`client-core/src/pq_install.rs`'s `RealInstaller` implements `pq::engine`'s
`Installer` trait for real kernel state. It is deliberately stateless:
`engine.rs` already tracks `pending.installed`/`pending.confirmed` durably,
so `install` is never called twice per rotation and `handshake_fresh` can
safely read straight from the kernel every call. Freshness is structural,
not timestamp-compared: `install` always removes then recreates the kernel
peer entry (as two sequential `DeviceUpdate::apply` calls, since a single
batched remove+add for the same key cannot be relied on to discard the old
session), which resets the kernel's `last_handshake_time` to `None`, so any
`Some(_)` observed afterward is necessarily a handshake under the new
instance — exactly what milestones.md's "old handshake timestamps... alone
cannot prove the exchange completed" requires, without storing or comparing
a timestamp at all. `install` gates the peer before touching the kernel;
`handshake_fresh` releases that gate as a side effect of returning `true`.
`reconcile_gate` reuses that same kernel-read-and-release logic to
re-verify the gate for every already-confirmed, no-pending relationship —
needed because a merely steady-state relationship never otherwise passes
back through `engine::reconcile`'s `Committed` arm to trigger a release, so
a cold boot's gate would otherwise stay closed for it forever.

`client-core/src/pq_sync.rs` splits `sync` into `fetch_state` + `apply` so
the real production path can fetch the peer directory once, build
`RealInstaller` from it, then reconcile, without a second network round
trip; `sync` itself stays a thin wrapper so M3's tests/dev harness keep
compiling unchanged. `register` extracts the "discover self/server/network
ids, generate an identity, `PUT /user/pq-keys`" logic that was inline in
the M3 dev harness, so the real activation path can reuse it.

`client-core::interface::fetch()` now threads a `PqOptions` through and,
when `--enable-pq-psk` is set, opens (or, on first activation, registers)
this interface's PQ state *before* the ordinary peer-diff/`DeviceUpdate`
step and proactively gates every visible, not-yet-confirmed peer at that
point — closing a real window where a newly-visible peer would otherwise
get ordinary WireGuard connectivity before the PQ engine had even
discovered it. Once the interface and ordinary peers are live, it fetches
PQ exchange state and runs `pq_sync::apply` with a `RealInstaller`, then
`pq_install::reconcile_gate`. On a cold boot it restores the gate from the
locally *cached* peer directory (`DataStore`), never a live fetch: the
coordination API is reachable only through the very tunnel being restored,
so it cannot be queried yet at that point.

`shared::pq::PqOptions::production_ready()` is now exactly `validate()` —
the M1-M3 unconditional refusal is lifted. This alone was not sufficient,
though: the server never had any way to flip `pq_network.enabled`, and
`Context.pq` was only ever constructed under the `pq-dev-harness` feature,
so `db::pq::ready()` could never be true outside a dev/test build
regardless of what a client asked for. `server/src/db/pq.rs` gained
`enable()` (refusing until `management_ready` is already set — an
independent recovery channel must exist before any data PSK is exchanged),
exposed as a new `innernet-server enable-pq <interface>` command;
`Context.pq` is now always constructed in production too, with the real
`Limits::default()` M1 already defined (the `pq-dev-harness` feature's
relaxed test limits are untouched). `pq_network.enabled`, not whether the
service object exists, remains the actual gate `db::pq::ready()` checks.

Building the M4 Docker scenarios against real Docker/kernel state surfaced
two further real bugs, both fixed:

- The proactive-gating step described above initially iterated the
  *ordinary* peer list without excluding the coordination server's own
  entry. Since the server never has a PQ relationship, it was classified
  "unconfirmed" and added to the blocked set — self-blocking the very link
  the PQ handshake needs to complete, hanging every subsequent request to
  the server on that interface. Fixed by excluding `state.server_id`/
  `state.peer_id`, the same way `pq_sync::apply`'s own loop already does.
- The CLI's top-level error log used `{}` (anyhow's `Display`), which shows
  only a wrapped error's outermost context and hid the actual root cause
  while diagnosing the bug above. Changed to `{:#}` so the full chain is
  visible — a real improvement independent of the bug hunt, and itself in
  the spirit of M4's "fail visibly, not silently" tenet.

`tests/docker/docker-compose.m4.yml` adds a third peer, C, per testing.md's
A-C traffic/progress control, and uses the plain production runtime image
(no `pq-dev-harness` feature — `--enable-pq-psk` now works for real).
`m4_smoke.sh` covers testing.md section 4.4 scenario 1 (smoke/convergence):
application traffic gated at first activation, checked atomically against
a live gate-set snapshot rather than raced against a timer (in this
low-latency Docker network a full propose/ready/commit/install/confirm
sequence can complete in single-digit seconds, so a naive two-round-trip
race would sometimes lose the window before ever observing it — when that
happens the scenario notes it and moves on rather than failing a race it
did not win); a positive A-C reachability control; two rotations with
matching/distinct successive PSKs; and A-C staying reachable throughout,
including through its own independent rotation on the same interval.
`m4_crash.sh` is a coarser, container-level variant of scenario 3 (install
crash matrix): it kills peer-b outright mid-rotation, recreates its
container with its volume preserved, and asserts recovery converges to one
matching candidate, the recreated peer starts gated again (no stale-session
bypass), and A-C stays live throughout — it does not target the exact
kernel-install/pre-receipt boundaries the full matrix describes, which
needs test-only fault hooks testing.md section 4.3 describes but this
codebase does not yet implement.

Tested on Linux x86_64, Arch Linux, 2026-09-08, Docker 29.7.2:

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked` | all suites pass (pq: 4+11+1+12+2, including the 300-schedule property test; server: 54 + 1 explicitly ignored; client-core: 6 + 1 real-API integration test; shared: 7; wireguard-control: 12 + 1 explicitly ignored) |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` (default, and again with `--features pq-dev-harness,test-harness`) | passed both ways |
| `bash tests/run.sh unit` / `integration` | passed |
| `bash tests/run.sh docker-smoke` (`m2_management.sh` + `m3_exchange.sh` + `m4_smoke.sh` + `m4_crash.sh`) | passed: M2/M3 scenarios unaffected; M4's smoke and crash-restart scenarios both pass with real kernel peers |

Explicitly out of scope for M4: testing.md section 4.4 scenarios 2 and 5
(precise lost-response and replay/tampering fault injection — both need
test-only HTTP-level fault hooks section 4.3 describes but this codebase
does not yet implement; the pure-protocol side of loss/replay is already
covered by `pq/src/engine.rs` and `pq/tests/schedule.rs`'s seeded fault
schedules from M3); scenario 6 (isolation/mixed strict-permissive-legacy
policy — explicitly M6 territory per milestones.md's own scoping); the
idle-timeout/inactivity pause scheduling that reuses this driver loop (M5);
and management PSK rotation's own full failure/recovery testing (M7 — M4
only needs the already-provisioned M2 management link to remain usable).

## M5 — Tunnel-inactivity pause and fair scheduling

M5 is a scheduling-layer refinement, not a protocol change: don't start a
*new* PSK rotation for a data peer whose tunnel has seen no traffic (not
even a keepalive) for a while, resume promptly the moment traffic
reappears, and make one peer's failure or backoff never block or crash
progress on any other peer. Nothing about the exchange protocol, the gate,
or the installer changes.

`--pq-psk-idle-timeout` (default 900s) joins `PqOptions` following the
exact existing pattern, with one different convention: `0` means "pausing
disabled" (a valid value), not an error — unlike the rotation interval,
which rejects `0`.

`pq/src/state.rs`'s `Relationship` gains a durable `activity:
Option<Activity>` field (`rx_bytes`, `tx_bytes`, `last_active_at`),
`#[serde(default)]` so a pre-M5 persisted relationship — which under
`deny_unknown_fields` would otherwise fail to deserialize — loads fine
with `activity: None`, correctly meaning "never observed yet" and matching
design 5.12's "first observation... counts as activity". A new
`EndpointState::observe_activity` updates it: activity is "new" whenever
the sampled counters differ *at all* from the stored baseline, covering
both a genuine increase and a reset-to-a-different-value from peer
recreation, without ever subtracting — sidestepping design 5.12's "never
unsigned subtraction across a reset" concern entirely by never computing a
delta magnitude, only equality.

The engine stays pure. `EndpointState::reconcile` gains one new parameter,
`idle_timeout: u64`, used only inside the existing initiator `due`
computation: a repeat rotation is due only if the rotation interval
elapsed *and* (idle_timeout is 0, or the relationship has no activity
baseline yet, or activity was observed within idle_timeout). The engine
never reads kernel counters itself — the caller samples them and calls
`observe_activity` *before* `reconcile`, in the same cycle, which is what
makes "resume promptly on the first poll observing traffic" (design 5.12)
fall out for free: the just-updated `last_active_at` is what the `due`
check sees. An unconfirmed (never-yet-completed) relationship is still
always due, unconditionally — initial exchanges never pause.

Also finally read for the first time: `Pending`'s `attempts`/
`next_retry_at` fields, carried unused since M2. A new
`EndpointState::note_send_failure` applies a bounded jittered backoff
(1-60s, doubling per consecutive attempt) after a transport-send failure;
the existing retry check gains `pending.next_retry_at <= now` as an
additional condition. Every outbox push that represents real progress
(Commit, Installed, Confirmed) resets `attempts`/`next_retry_at`, so a
stale backoff from an earlier phase never delays a brand new message.

`client-core/src/pq_sync.rs`'s `apply` no longer propagates a single
relationship's failure (an `observe_remote` conflict, an engine error, a
storage error, or a transport error) with `?`, aborting the entire cycle —
each is now logged (`log::warn!`, never silently swallowed) and the loop
moves on to the next peer. This was a real, previously-existing fragility,
not a hypothetical one: a single bad request could kill the whole
`up --daemon` process (observed firsthand while diagnosing M4's Docker
bugs), directly violating design 5.12's "other peers remain independent"
and "must not restart a daemon or block others". A transport send failure
now also calls `note_send_failure` instead of hammering immediately next
cycle. `apply`/`sync` gain `idle_timeout: u64` and `device:
Option<&wireguard_control::Device>` parameters; when `device` is `Some`,
each peer's real WireGuard byte counters are sampled via `observe_activity`
before `reconcile`. `None` (M3's dev harness, the real-API integration
test) skips sampling entirely, preserving their existing behavior
unchanged. `client-core::interface::fetch()` passes the real kernel
`Device` it already fetches for the ordinary peer diff — no second kernel
read needed — and `pq.pq_psk_idle_timeout`.

"Bounded shared workers" (design 5.12) needed no new concurrency
primitives: it is already satisfied structurally by the server's existing
semaphore-based admission control (M1, `server/src/pq.rs`'s
`Limits`/`Permit`); the client side only needed to stop letting one peer's
failure block reaching the others in the same sequential loop, which the
fault-tolerant restructure above provides.

Building the M5 Docker scenario surfaced a real constraint worth recording:
this codebase's server applies one hardcoded persistent-keepalive interval
(`shared::PERSISTENT_KEEPALIVE_INTERVAL_SECS`, 25s) to *every* peer, with no
per-peer override anywhere in the schema or CLI. A genuinely
keepalive-disabled, truly-idle tunnel therefore cannot be produced with
real containers today. `tests/docker/scenarios/m5_inactivity.sh` instead
proves the achievable real-kernel half of testing.md section 4.4 scenario
7: with a short test-only rotation interval (15s) and an idle timeout set
comfortably above the 25s keepalive (40s), both A-B and A-C complete two
full rotation cycles on schedule through real kernel peers — the
idle-pause mechanism, once wired into real activation, never throttles a
healthy keepalive-carrying link, and A-C's independent progress throughout
is the fair-scheduling control. The genuinely-idle-pauses/resumes-promptly
half is instead covered at the engine unit-test level (a fixed simulated
baseline, not a real kernel counter), which is where it must stay until a
per-peer keepalive control exists.

Tested on Linux x86_64, Arch Linux, 2026-09-08, Docker 29.7.2:

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked` | all suites pass (pq: 4+17+1+12+2, including the 300-schedule property test; server: 54 + 1 explicitly ignored; client-core: 12 + 1 real-API integration test; shared: 8; wireguard-control: 12 + 1 explicitly ignored) |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` (default, and again with `--features pq-dev-harness,test-harness`) | passed both ways |
| `bash tests/run.sh unit` / `integration` | passed |
| `bash tests/run.sh docker-smoke` (`m2_management.sh` + `m3_exchange.sh` + `m4_smoke.sh` + `m4_crash.sh` + `m5_inactivity.sh`) | passed: M2/M3/M4 scenarios unaffected; M5's inactivity scenario passes with real kernel peers |

Explicitly out of scope for M5: a real-kernel demonstration of a genuinely
idle tunnel pausing and resuming (needs a per-peer persistent-keepalive
control this codebase does not yet have — covered at the engine
unit-test level instead, as described above); the numeric 300s/900s
rotation/idle defaults are not re-validated here (M9's job); and mixed
strict/permissive/legacy scheduling interactions stay M6 territory.

## M6 — Mixed-fleet policy and explicit lifecycle transitions

M6 finishes the strict/permissive policy semantics M1 introduced as inert
CLI flags, adds durable explicit disable/re-enable lifecycle transitions,
and closes the milestone with real Docker evidence. Before this milestone,
`pq::state::Policy` was written (always hardcoded to `Strict`) but never
read, `Relationship.prior_pq` was written but never read, and a peer with
no PQ bundle never got a `Relationship` at all — meaning permissive mode's
entire reason to exist (legacy pass-through for a peer that never had PQ)
was unimplemented, not just untested.

`pq_sync::open_or_register` now sets `state.policy` from the live
`--pq-psk-permissive` flag on every call. Legacy eligibility is computed,
not stored: a new `pq_install::legacy_eligible` returns true exactly when
policy is `Permissive`, no bundle is currently advertised, and the peer's
relationship (if any) never reached `prior_pq`. `prior_pq`, not
`confirmed.is_some()`, is the right signal because `confirmed` can be
transiently cleared (e.g. by `emergency_retire`) while `prior_pq` never
is. `client-core::interface`'s proactive-gating loop now iterates
`pq_peers` (not the ordinary peer list) so `entry.pq.is_some()` is
available, and explicitly releases (never gates) a legacy-eligible peer
instead of blocking it — the fix that makes permissive mode's legacy
exemption real rather than a flag with no effect. Toggling the flag can
never retroactively legalize legacy treatment for a relationship that
ever confirmed PQ, since eligibility is gated on `prior_pq` history, not
current policy.

Explicit disable reuses `Enrollment::Retiring`, already declared and
already unused for this purpose. A new `EndpointState::disable()` — an
ordinary administrative action, distinct from `emergency_retire`'s
lost/corrupt-local-state handling — sets `registration.lifecycle =
Retired`, `enrollment = Retiring`, and clears every relationship's
`pending`, while retaining `confirmed`/sequence/`prior_pq` state rather
than clearing it, matching "retain recovery/replay state until
retirement is durable". `EndpointState::reconcile` gains one
short-circuit: while `enrollment == Retiring`, never start a new
exchange. `interface::fetch()`'s gating step becomes retirement-aware:
while retiring/retired, every relationship is gated immediately,
including ones already confirmed — closing the application-traffic gate
is exactly "drain... while gated". A new `pq_sync::submit_pending_
registration` runs on every cycle while `enrollment` is `Registering` or
`Retiring`, posting to `/user/pq-keys` (or `/user/pq-keys?retire=1` for
retirement) and calling the already-implemented, previously-unused
`accept_registration` to verify the response and advance `enrollment`.
Explicit re-enable reuses the already-implemented, already-tested
`replace()` (a fresh identity, `Enrollment::Registering`, every
relationship blocked pending re-confirmation) — `prior_pq`/sequence
counters on existing relationships survive `replace()` untouched. Both
are wired to new CLI commands, `innernet pq-disable <interface>` and
`innernet pq-enable <interface>`.

Bilateral downgrade (a coordinated, both-sides-authorized restoration of
a matching legacy/zero operator PSK) is explicitly out of scope for this
pass: it requires a new wire-protocol message, a genuine protocol
addition rather than a wiring gap like everything else in this
milestone. Local explicit disable (this interface's own PQ posture, with
its own operator PSK preserved untouched) is implemented and tested; the
coordinated two-sided handshake is documented as deferred.

Building the M6 Docker scenarios, the plan originally called for
executing a genuinely separate old binary (built via `git worktree` from
this repository's pinned pre-Rosenpass baseline commit,
`e922387122874c8182abab5b1c1e3eed2da1ba7f`) against the current server, to
demonstrate real old/new wire compatibility. That investigation
succeeded technically — the old binary redeemed its invitation and
brought up a real WireGuard tunnel against the new server on a plain
(no-management) network — but also surfaced a genuine, unrelated
constraint: on a `require-management` network, M2's server-side
management-link PSK provisioning is unconditional for every enabled
peer, and the pre-Rosenpass binary has no code to read or adopt the
invite's `management` field, so the resulting PSK mismatch made
WireGuard silently drop the handshake. Given that finding, the user
decided this project has no old/new binary compatibility requirement — it
is a new, independent design/app/binary, not a fork retaining wire
compatibility with upstream innernet releases — so that scenario and its
supporting Dockerfile/compose/entrypoint files were removed rather than
carried forward. `tests/docker/scenarios/m6_policy.sh` (design case 15)
was kept: `peer-legacy` is a fully-capable current binary that simply
never passes `--enable-pq-psk`, which exercises the exact same
legacy-eligibility code path a truly incapable peer would (bundle
presence is the only thing the engine ever checks, never why a bundle is
absent), with real kernel peers on a `require-management`,
PQ-enabled network. It confirms: a permissive peer stays reachable with
the bundle-less legacy peer; a strict peer stays blocked with the same
peer (not a crash or a hang); the ordinary (non-PQ) sync loop keeps
progressing for the legacy peer throughout; and permissive/strict (both
PQ-capable) still fully confirm real PQ with each other, converging on
matching PSKs.

Tested on Linux x86_64, Arch Linux, 2026-09-08, Docker 29.7.2:

| Check | Result |
| --- | --- |
| `cargo test --workspace --locked` | all suites pass |
| `cargo clippy --workspace --locked --all-targets -- -D warnings` (default, and again with `--features pq-dev-harness,test-harness`) | passed both ways |
| `bash tests/run.sh unit` / `integration` | passed |
| `bash tests/run.sh docker-smoke` (`m2_management.sh` + `m3_exchange.sh` + `m4_smoke.sh` + `m4_crash.sh` + `m5_inactivity.sh` + `m6_policy.sh`) | passed: M2-M5 scenarios unaffected; M6's mixed-fleet policy scenario passes with real kernel peers |

Explicitly out of scope for M6: bilateral downgrade's coordinated
two-sided handshake (needs a new wire-protocol message — a genuine
protocol addition, not a wiring gap); and old/new binary compatibility,
which is not a project goal (this is a new, independent design/app/
binary, not a fork of upstream innernet). This completes the milestones
requested in "implement M3-M6"; M7-M9 (management PSK rotation,
cross-platform build profiles, and the full security/fault/load review)
are not part of this pass.
