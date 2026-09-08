#!/usr/bin/env bash
# M8: real aarch64 evidence via `docker buildx build --platform linux/arm64`
# (QEMU user-mode emulation, registered separately via
# `docker run --privileged --rm tonistiigi/binfmt --install arm64`) --
# an emulated-native build/test, not host-to-target cross-compilation.
# Runs the crypto vectors, durability/store tests, and the real
# openssl/leancrypto native_interop check (all of pq/tests/*.rs) against
# binaries genuinely compiled and executed for aarch64, exercising real
# architecture-specific code paths a code review alone cannot verify.
#
# Explicitly does NOT attempt gate/nftables/WireGuard kernel checks:
# QEMU user-mode emulation translates instructions only -- syscalls still
# reach the host's x86_64 kernel, so no aarch64 kernel module behavior is
# reachable this way. No ARM hardware or full-system aarch64 VM is
# available in this environment; that evidence stays a documented gap
# (see docs/implementation.md's M8 section), not something faked here.
#
# Requires Docker buildx with the linux/arm64 platform registered. Not
# run as part of `unit`/`integration`/`docker-smoke`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."

if ! docker buildx inspect --bootstrap 2>/dev/null | grep -q 'linux/arm64'; then
    echo "FAIL: linux/arm64 is not a registered buildx platform." >&2
    echo "      Register QEMU emulation first: docker run --privileged --rm tonistiigi/binfmt --install arm64" >&2
    exit 1
fi

echo "[*] building the aarch64 toolchain image (emulated-native, real leancrypto/openssl for aarch64)..."
docker buildx build --platform linux/arm64 --load \
    -f tests/docker/Dockerfile.build.aarch64 -t innernet-pq-build:aarch64 . \
    >/tmp/m8-aarch64-build.log 2>&1 \
    || { echo "toolchain image build failed, see /tmp/m8-aarch64-build.log" >&2; tail -n 100 /tmp/m8-aarch64-build.log >&2; exit 1; }

echo "[*] building the workspace for aarch64..."
docker buildx build --platform linux/arm64 --load \
    -f tests/docker/Dockerfile.runtime.aarch64 -t innernet-pq-runtime:aarch64 . \
    >/tmp/m8-aarch64-runtime.log 2>&1 \
    || { echo "workspace build failed, see /tmp/m8-aarch64-runtime.log" >&2; tail -n 100 /tmp/m8-aarch64-runtime.log >&2; exit 1; }
echo "[ok] real aarch64 build succeeded (cargo build --workspace --locked)"

echo "[*] running crypto/durability/native-interop checks under real aarch64 emulation..."
docker run --rm --platform linux/arm64 innernet-pq-runtime:aarch64 \
    sh -c "cd /work && cargo test -p innernet-pq --locked" \
    2>&1 | tee /tmp/m8-aarch64-test.log
if ! grep -q "^test result: ok" /tmp/m8-aarch64-test.log; then
    echo "FAIL: aarch64 pq test suite did not report ok" >&2
    exit 1
fi
if grep -qE "^test result: FAILED|^error" /tmp/m8-aarch64-test.log; then
    echo "FAIL: aarch64 pq test suite reported a failure" >&2
    exit 1
fi
echo "[ok] real crypto vectors, durability/store tests, and native_interop passed under real aarch64 emulation"

echo "[PASS] M8 aarch64 build/test checks"
