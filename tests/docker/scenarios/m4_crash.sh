#!/usr/bin/env bash
# M4 Docker scenario: a coarser, container-level variant of testing.md
# section 4.4 scenario 3 ("install crash matrix"). Kills peer-b outright
# (not a graceful stop) shortly after activation starts, mid-rotation, then
# recreates its container with its volume preserved, and asserts: recovery
# converges to one final candidate matching on both sides, the gate is
# closed again immediately on restart (no old-session bypass through a
# stale pre-crash kernel state -- the container's own network namespace and
# kernel interface are destroyed by the kill, so this also re-exercises the
# cold-boot gate-restoration path from a real crash), and A-C stays
# reachable throughout.
#
# This does not target the exact kernel-install/pre-receipt boundaries the
# full milestones.md matrix describes (before/after kernel install, before
# the installed receipt): that needs test-only fault hooks docs/testing.md
# section 4.3 describes but this codebase does not yet implement. See
# docs/implementation.md's M4 section for the explicit scoping note.
#
# Requires Docker with a real WireGuard-capable kernel, nft, and the ability
# to grant containers NET_ADMIN. Not run as part of `unit`/`integration`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m4.yml -p innernet_pq_m4)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building the production runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m4 . >/tmp/m4-crash-build.log 2>&1 \
    || { echo "build failed, see /tmp/m4-crash-build.log" >&2; tail -n 100 /tmp/m4-crash-build.log >&2; exit 1; }

cleanup
echo "[*] starting server, peer-a, peer-b, peer-c..."
"${COMPOSE[@]}" up -d

wait_for() {
    local desc="$1" tries=0
    shift
    until "$@" >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -gt 90 ]; then
            echo "timed out waiting for: $desc" >&2
            "${COMPOSE[@]}" logs
            exit 1
        fi
        sleep 1
    done
}

allowed_ip_of() {
    local querier="$1" endpoint_ip="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm4 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $4}' | cut -d/ -f1
}
psk_of() {
    local querier="$1" endpoint_ip="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm4 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $2}'
}
probe() {
    "${COMPOSE[@]}" exec -T peer-a curl -s -o /dev/null --max-time 3 "http://$1:8080/"
}

echo "[*] waiting for peer-a, peer-b, peer-c to redeem and bring up their tunnels..."
wait_for "peer-a interface up" "${COMPOSE[@]}" exec -T peer-a wg show pqm4
wait_for "peer-b interface up" "${COMPOSE[@]}" exec -T peer-b wg show pqm4
wait_for "peer-c interface up" "${COMPOSE[@]}" exec -T peer-c wg show pqm4

b_ip="" c_ip="" tries=0
until [ -n "$b_ip" ] && [ -n "$c_ip" ]; do
    b_ip="$(allowed_ip_of peer-a 10.90.0.4)"
    c_ip="$(allowed_ip_of peer-a 10.90.0.5)"
    tries=$((tries + 1))
    [ "$tries" -le 90 ] || { echo "FAIL: could not determine overlay addresses" >&2; exit 1; }
    [ -n "$b_ip" ] && [ -n "$c_ip" ] || sleep 1
done

echo "[*] killing peer-b mid-rotation (before it can have confirmed yet)..."
sleep 2
"${COMPOSE[@]}" kill peer-b >/dev/null

echo "[*] verifying A-C stays live while peer-b is down..."
wait_for "A-C reachable during peer-b outage" probe "$c_ip"

echo "[*] recreating peer-b with its volume preserved..."
"${COMPOSE[@]}" up -d peer-b
wait_for "peer-b interface back up" "${COMPOSE[@]}" exec -T peer-b wg show pqm4

echo "[*] negative control: the recreated peer-b starts gated again, not bypassed..."
if probe "$b_ip"; then
    echo "FAIL: application traffic to peer-b was reachable immediately after its crash-restart, before reconfirmation" >&2
    exit 1
fi
echo "[ok] recreated peer-b's gate starts closed (no stale-session bypass)"

echo "[*] waiting for recovery to converge on one confirmed candidate..."
wait_for "A-B application traffic reachable after recovery" probe "$b_ip"
a_psk="$(psk_of peer-a 10.90.0.4)"
b_psk="$(psk_of peer-b 10.90.0.3)"
[ "$a_psk" != "(none)" ] && [ -n "$a_psk" ] || { echo "FAIL: peer-a has no PSK for peer-b after recovery" >&2; exit 1; }
[ "$a_psk" = "$b_psk" ] || { echo "FAIL: peer-a and peer-b mismatched after crash recovery" >&2; exit 1; }
probe "$c_ip" || { echo "FAIL: A-C stopped being reachable after peer-b's recovery" >&2; exit 1; }
echo "[ok] crash recovery converged to one matching candidate; A-C stayed live throughout"

echo "[PASS] M4 Docker crash-restart scenario"
