#!/usr/bin/env bash
# M5 Docker scenario: real containers, real kernel WireGuard interfaces --
# the achievable real-kernel subset of testing.md section 4.4 scenario 7
# ("inactivity and fairness"). This codebase's server currently applies one
# hardcoded persistent-keepalive interval to every peer (shared::
# PERSISTENT_KEEPALIVE_INTERVAL_SECS, 25s) with no per-peer override, so a
# genuinely keepalive-disabled tunnel cannot be produced with real
# containers today -- that half of scenario 7 (a truly inactive tunnel
# pausing and resuming) is instead covered by pq/src/engine.rs's own unit
# tests (idle_timeout_pauses_a_repeat_rotation_and_resumes_promptly_on_
# activity, idle_timeout_zero_never_pauses,
# a_relationship_with_no_activity_baseline_yet_is_never_paused), which
# simulate the sampled counters directly. See docs/implementation.md's M5
# section for this scoping note.
#
# What real kernel peers *do* prove here: with --pq-psk-idle-timeout set
# (comfortably above the 25s keepalive interval, so keepalive traffic alone
# always keeps the relationship "active"), both A-B and A-C keep rotating
# normally across two full rotation cycles -- the idle-pause mechanism
# being present and active never throttles a healthy, keepalive-carrying
# link. A-C's independent progress throughout is the fairness/independence
# control.
#
# Requires Docker with a real WireGuard-capable kernel, nft, and the ability
# to grant containers NET_ADMIN. Not run as part of `unit`/`integration`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m5.yml -p innernet_pq_m5)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building the production runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m5 . >/tmp/m5-build.log 2>&1 \
    || { echo "build failed, see /tmp/m5-build.log" >&2; tail -n 100 /tmp/m5-build.log >&2; exit 1; }

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
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm5 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $4}' | cut -d/ -f1
}
psk_of() {
    local querier="$1" endpoint_ip="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm5 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $2}'
}
keepalive_of() {
    local querier="$1" endpoint_ip="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm5 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $8}'
}
probe() {
    "${COMPOSE[@]}" exec -T peer-a curl -s -o /dev/null --max-time 3 "http://$1:8080/"
}

echo "[*] waiting for peer-a, peer-b, peer-c to redeem and bring up their tunnels..."
wait_for "peer-a interface up" "${COMPOSE[@]}" exec -T peer-a wg show pqm5
wait_for "peer-b interface up" "${COMPOSE[@]}" exec -T peer-b wg show pqm5
wait_for "peer-c interface up" "${COMPOSE[@]}" exec -T peer-c wg show pqm5

b_ip="" c_ip="" tries=0
until [ -n "$b_ip" ] && [ -n "$c_ip" ]; do
    b_ip="$(allowed_ip_of peer-a 10.92.0.4)"
    c_ip="$(allowed_ip_of peer-a 10.92.0.5)"
    tries=$((tries + 1))
    [ "$tries" -le 90 ] || { echo "FAIL: could not determine overlay addresses" >&2; exit 1; }
    [ -n "$b_ip" ] && [ -n "$c_ip" ] || sleep 1
done
echo "[ok] peer-b=$b_ip peer-c=$c_ip"

keepalive_b="$(keepalive_of peer-a 10.92.0.4)"
[ "$keepalive_b" != off ] && [ -n "$keepalive_b" ] || { echo "FAIL: peer-b has no persistent keepalive configured" >&2; exit 1; }
echo "[ok] peer-b carries a persistent keepalive of ${keepalive_b}s"

echo "[*] waiting for A-B and A-C to converge on a confirmed candidate..."
wait_for "A-B reachable" probe "$b_ip"
wait_for "A-C reachable" probe "$c_ip"
psk_b_1="$(psk_of peer-a 10.92.0.4)"
psk_c_1="$(psk_of peer-a 10.92.0.5)"
[ "$psk_b_1" != "(none)" ] && [ -n "$psk_b_1" ] || { echo "FAIL: peer-a has no PSK for peer-b" >&2; exit 1; }
[ "$psk_c_1" != "(none)" ] && [ -n "$psk_c_1" ] || { echo "FAIL: peer-a has no PSK for peer-c" >&2; exit 1; }
echo "[ok] first rotation confirmed for both A-B and A-C"

echo "[*] waiting for a second rotation on A-B, with the idle timeout active but never triggered by keepalive traffic..."
tries=0
while :; do
    psk_b_2="$(psk_of peer-a 10.92.0.4)"
    if [ "$psk_b_2" != "$psk_b_1" ] && [ -n "$psk_b_2" ] && [ "$psk_b_2" != "(none)" ]; then
        break
    fi
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
        echo "FAIL: A-B's second rotation did not complete -- a healthy keepalive-carrying tunnel should never be paused by the idle timeout" >&2
        exit 1
    fi
    sleep 2
done
echo "[ok] A-B rotated again on schedule; the idle-pause mechanism did not throttle a healthy keepalive-carrying link"

echo "[*] confirming A-C rotated independently too (fair scheduling)..."
tries=0
while :; do
    psk_c_2="$(psk_of peer-a 10.92.0.5)"
    if [ "$psk_c_2" != "$psk_c_1" ] && [ -n "$psk_c_2" ] && [ "$psk_c_2" != "(none)" ]; then
        break
    fi
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
        echo "FAIL: A-C's second rotation did not complete independently of A-B" >&2
        exit 1
    fi
    sleep 2
done
echo "[ok] A-C rotated independently of A-B"

probe "$b_ip" || { echo "FAIL: A-B unreachable after its second rotation" >&2; exit 1; }
probe "$c_ip" || { echo "FAIL: A-C unreachable after its second rotation" >&2; exit 1; }
echo "[ok] A-B and A-C both remain reachable"

echo "[PASS] M5 Docker inactivity scenario"
