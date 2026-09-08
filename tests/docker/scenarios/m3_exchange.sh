#!/usr/bin/env bash
# M3 Docker scenario: real containers, real crypto and binaries, the real
# server mailbox API -- with a fake kernel installer (M3 explicitly does not
# touch real WireGuard state; that is M4's job). Asserts two independent
# processes converge on one candidate PSK through the real API. Rotation
# producing a genuinely different candidate for the *same* established
# identity is already covered rigorously by pq/src/engine.rs's own unit
# tests; this skeleton's job is cross-container/real-API convergence.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m3.yml -p innernet_pq_m3)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building the pq-dev-harness runtime image..."
docker build -f tests/docker/Dockerfile.runtime.m3 -t innernet-pq-runtime:m3 . >/tmp/m3-build.log 2>&1 \
    || { echo "build failed, see /tmp/m3-build.log" >&2; tail -n 100 /tmp/m3-build.log >&2; exit 1; }

cleanup
echo "[*] starting server, peer-a, peer-b..."
"${COMPOSE[@]}" up -d

wait_for_file() {
    local desc="$1" service="$2" path="$3" tries=0
    until "${COMPOSE[@]}" exec -T "$service" test -s "$path" >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -gt 90 ]; then
            echo "timed out waiting for: $desc" >&2
            "${COMPOSE[@]}" logs
            exit 1
        fi
        sleep 1
    done
}

read_psk() {
    "${COMPOSE[@]}" exec -T "$1" sh -c "sed -n 's/^PQ_PSK=//p' /invites/psk-$1.txt"
}

echo "[*] waiting for both peers to converge on a rotation..."
wait_for_file "peer-a PSK" peer-a /invites/psk-peer-a.txt
wait_for_file "peer-b PSK" peer-b /invites/psk-peer-b.txt

psk_a="$(read_psk peer-a)"
psk_b="$(read_psk peer-b)"
[ -n "$psk_a" ] || { echo "FAIL: peer-a produced no PSK" >&2; exit 1; }
[ "$psk_a" = "$psk_b" ] || { echo "FAIL: peer-a and peer-b converged on different candidates" >&2; exit 1; }
echo "[ok] independent processes converged on one candidate through the real API"

echo "[PASS] M3 Docker exchange scenario"
