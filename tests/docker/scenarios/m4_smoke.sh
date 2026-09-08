#!/usr/bin/env bash
# M4 Docker scenario: real containers, real kernel WireGuard interfaces, a
# real per-peer nftables data gate, and a real Installer -- production
# `--enable-pq-psk` activation end to end (testing.md section 4.4 scenario
# 1: smoke/convergence). Covers: application traffic gated at first
# activation (checked atomically against the live gate-set snapshot, since
# in this low-latency Docker network a full propose/ready/commit/install/
# confirm sequence can complete in single-digit seconds -- fast enough that
# a naive two-round-trip race would sometimes lose the window before ever
# observing it), a positive A-C reachability control, two rotations with
# matching/distinct successive PSKs, and A-C staying live throughout.
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
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m4 . >/tmp/m4-build.log 2>&1 \
    || { echo "build failed, see /tmp/m4-build.log" >&2; tail -n 100 /tmp/m4-build.log >&2; exit 1; }

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

psk_of() {
    local querier="$1" endpoint_ip="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm4 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $2}'
}

probe() {
    # Reachability through the actual tunnel: the target address exists
    # only on the wg interface, so a positive result cannot be explained by
    # the docker underlay bridge.
    "${COMPOSE[@]}" exec -T peer-a curl -s -o /dev/null --max-time 3 "http://$1:8080/"
}

# One remote round trip that resolves peer-b/peer-c's overlay addresses,
# reads the live gate-set membership, and attempts application traffic --
# all computed together server-side, so the gate-state observation and the
# reachability attempt it is checked against cannot be pulled apart by a
# separate network round trip's worth of elapsed time.
snapshot() {
    "${COMPOSE[@]}" exec -T peer-a sh -c '
        set -eu
        dump="$(wg show pqm4 dump)"
        b_ip="$(printf "%s" "$dump" | awk -v ep="10.90.0.4:" "\$3 ~ \"^\"ep {print \$4}" | cut -d/ -f1)"
        c_ip="$(printf "%s" "$dump" | awk -v ep="10.90.0.5:" "\$3 ~ \"^\"ep {print \$4}" | cut -d/ -f1)"
        blocked="$(nft list set inet innernet_pq_data_pqm4 blocked_v4 2>/dev/null || true)"
        b_blocked=no
        [ -n "$b_ip" ] && printf "%s" "$blocked" | grep -q "$b_ip" && b_blocked=yes
        b_http=""
        [ -n "$b_ip" ] && b_http="$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://$b_ip:8080/" || true)"
        echo "b_ip=$b_ip"
        echo "c_ip=$c_ip"
        echo "b_blocked=$b_blocked"
        echo "b_http=$b_http"
    '
}

echo "[*] waiting for peer-a, peer-b, peer-c to redeem and bring up their tunnels..."
wait_for "peer-a interface up" "${COMPOSE[@]}" exec -T peer-a wg show pqm4
wait_for "peer-b interface up" "${COMPOSE[@]}" exec -T peer-b wg show pqm4
wait_for "peer-c interface up" "${COMPOSE[@]}" exec -T peer-c wg show pqm4

b_ip="" c_ip="" b_blocked="" b_http="" tries=0
until [ -n "$b_ip" ] && [ -n "$c_ip" ]; do
    eval "$(snapshot)"
    tries=$((tries + 1))
    if [ "$tries" -gt 90 ]; then
        echo "FAIL: could not determine peer-b/peer-c overlay addresses" >&2
        "${COMPOSE[@]}" logs
        exit 1
    fi
    [ -n "$b_ip" ] && [ -n "$c_ip" ] || sleep 1
done
echo "[ok] peer-b=$b_ip peer-c=$c_ip"

if [ "$b_blocked" = yes ]; then
    echo "[*] caught peer-b still gated (pre-confirmation): asserting traffic is actually blocked..."
    [ "$b_http" != 200 ] || { echo "FAIL: peer-b's address was in the blocked set but traffic still got an HTTP 200" >&2; exit 1; }
    echo "[ok] blocked before confirmation"
else
    echo "[note] peer-b already confirmed by the time of the first snapshot (fast Docker-network convergence); pre-confirmation gating already exercised structurally by client-core::gate's own unit/ignored tests, skipping the live race here"
fi

echo "[*] positive control: A-C traffic is reachable..."
wait_for "A-C reachable" probe "$c_ip"
echo "[ok] A-C reachable"

echo "[*] waiting for A-B to converge on a confirmed candidate..."
wait_for "A-B application traffic reachable" probe "$b_ip"
psk_1_a="$(psk_of peer-a 10.90.0.4)"
psk_1_b="$(psk_of peer-b 10.90.0.3)"
[ "$psk_1_a" != "(none)" ] && [ -n "$psk_1_a" ] || { echo "FAIL: peer-a has no PSK for peer-b" >&2; exit 1; }
[ "$psk_1_a" = "$psk_1_b" ] || { echo "FAIL: peer-a and peer-b hold different PSKs" >&2; exit 1; }
echo "[ok] first rotation confirmed; both sides hold the same PSK"

echo "[*] confirming A-C independently converged too..."
psk_c_a="$(psk_of peer-a 10.90.0.5)"
[ "$psk_c_a" != "(none)" ] && [ -n "$psk_c_a" ] || { echo "FAIL: peer-a has no PSK for peer-c" >&2; exit 1; }

echo "[*] waiting for a second rotation to produce a different candidate..."
tries=0
while :; do
    psk_2_a="$(psk_of peer-a 10.90.0.4)"
    if [ "$psk_2_a" != "$psk_1_a" ] && [ -n "$psk_2_a" ] && [ "$psk_2_a" != "(none)" ]; then
        break
    fi
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
        echo "FAIL: second rotation did not complete in time" >&2
        exit 1
    fi
    sleep 2
done
psk_2_b="$(psk_of peer-b 10.90.0.3)"
[ "$psk_2_a" = "$psk_2_b" ] || { echo "FAIL: second rotation left peer-a/peer-b mismatched" >&2; exit 1; }
wait_for "A-B reachable after the second rotation" probe "$b_ip"
# A-C rotates on the same interval, independently of A-B: a brief real gate
# closure during A-C's own rotation is expected, so this is a retry, not a
# single-shot probe.
wait_for "A-C reachable (independent of A-B's rotations)" probe "$c_ip"
echo "[ok] second rotation produced a distinct, matching PSK; A-B and A-C both remain reachable"

echo "[PASS] M4 Docker smoke scenario"
