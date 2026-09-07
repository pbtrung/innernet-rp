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

## M0 crypto and fixture evidence

leancrypto provides standalone ML-KEM-1024, X448, SHA3-256, HMAC and HKDF.
Initialize with `LC_INIT_NON_PQC_ENABLED` to permit classical X448; without
it the library returns unsupported. The installed library does not export
the header-declared X448 public-key convenience function, so public keys
are derived using X448 and RFC 7748's base point 5.

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
encodings, and compares X448 public/shared outputs. It is compiled only by a
test, never into either production binary.

Measured compact JSON fixtures (not HTTP framing):

| Fixture | Bytes |
| --- | ---: |
| B, raw | 1747 |
| T, raw | 5164 |
| E, raw | 156 |
| Bundle JSON, three keys and metadata | 2455 |
| Propose JSON | 2740 |
| Each ready/commit/installed/confirmed/abort JSON | 587 |
| ML-KEM public key or ciphertext, base64 | 2092 |
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
