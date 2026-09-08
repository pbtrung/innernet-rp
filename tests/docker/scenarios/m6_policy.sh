#!/usr/bin/env bash
# M6 Docker scenario: real mixed-fleet policy (design case 15) with real
# kernel peers. peer-legacy is a fully-capable binary that simply never
# passes --enable-pq-psk -- see docker-compose.m6.yml's header for why
# this is the right way to exercise the strict/permissive legacy-
# eligibility code path with real kernel peers.
#
# Covers: a permissive peer stays reachable with a peer that advertises no
# PQ bundle (legacy exemption); a strict peer stays blocked with the same
# peer (strict enforcement, not a crash or a hang); and the permissive/
# strict peers still fully confirm real PQ with each other (policy never
# breaks normal PQ operation between two capable peers).
#
# Requires Docker with a real WireGuard-capable kernel, nft, and the
# ability to grant containers NET_ADMIN. Not run as part of
# `unit`/`integration`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m6.yml -p innernet_pq_m6)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building the current production runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m6 . >/tmp/m6-policy-build.log 2>&1 \
    || { echo "build failed, see /tmp/m6-policy-build.log" >&2; tail -n 100 /tmp/m6-policy-build.log >&2; exit 1; }

cleanup
echo "[*] starting server, peer-legacy, peer-permissive, peer-strict..."
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
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm6 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $4}' | cut -d/ -f1
}
psk_of() {
    local querier="$1" endpoint_ip="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm6 dump \
        | awk -v ep="${endpoint_ip}:" '$3 ~ "^"ep {print $2}'
}
probe_from() {
    "${COMPOSE[@]}" exec -T "$1" curl -s -o /dev/null --max-time 3 "http://$2:8080/"
}

echo "[*] waiting for all three peers to redeem and bring up their tunnels..."
wait_for "server up" "${COMPOSE[@]}" exec -T server wg show pqm6
wait_for "peer-legacy interface up" "${COMPOSE[@]}" exec -T peer-legacy wg show pqm6
wait_for "peer-permissive interface up" "${COMPOSE[@]}" exec -T peer-permissive wg show pqm6
wait_for "peer-strict interface up" "${COMPOSE[@]}" exec -T peer-strict wg show pqm6

legacy_ip="" permissive_ip="" strict_ip="" tries=0
until [ -n "$legacy_ip" ] && [ -n "$permissive_ip" ] && [ -n "$strict_ip" ]; do
    legacy_ip="$(allowed_ip_of peer-permissive 10.93.0.3)"
    permissive_ip="$(allowed_ip_of peer-legacy 10.93.0.4)"
    strict_ip="$(allowed_ip_of peer-legacy 10.93.0.5)"
    tries=$((tries + 1))
    [ "$tries" -le 90 ] || { echo "FAIL: could not determine overlay addresses" >&2; exit 1; }
    [ -n "$legacy_ip" ] && [ -n "$permissive_ip" ] && [ -n "$strict_ip" ] || sleep 1
done
echo "[ok] legacy=$legacy_ip permissive=$permissive_ip strict=$strict_ip"

echo "[*] positive control: permissive peer stays reachable with the bundle-less legacy peer..."
wait_for "permissive <-> legacy reachable" probe_from peer-permissive "$legacy_ip"
echo "[ok] permissive mode's legacy exception let a bundle-less peer through"

echo "[*] negative control: strict peer stays blocked with the same legacy peer..."
sleep 5 # give strict peer a few real poll cycles to (wrongly) confirm, if it were going to.
if probe_from peer-strict "$legacy_ip"; then
    echo "FAIL: strict mode allowed application traffic to a peer with no PQ bundle" >&2
    exit 1
fi
echo "[ok] strict mode correctly refused a bundle-less peer, not a crash or a hang"

echo "[*] confirming the ordinary (non-PQ) sync loop kept progressing throughout for the legacy peer..."
"${COMPOSE[@]}" exec -T peer-legacy wg show pqm6 dump | grep -q "$permissive_ip" \
    || { echo "FAIL: legacy peer never saw peer-permissive in its own peer list" >&2; exit 1; }

echo "[*] waiting for permissive and strict (both PQ-capable) to fully confirm PQ with each other..."
wait_for "permissive <-> strict reachable" probe_from peer-permissive "$strict_ip"
psk_permissive="$(psk_of peer-permissive 10.93.0.5)"
psk_strict="$(psk_of peer-strict 10.93.0.4)"
[ "$psk_permissive" != "(none)" ] && [ -n "$psk_permissive" ] || { echo "FAIL: permissive peer has no PSK for strict peer" >&2; exit 1; }
[ "$psk_permissive" = "$psk_strict" ] || { echo "FAIL: permissive and strict peers converged on different candidates" >&2; exit 1; }
echo "[ok] policy never broke real PQ confirmation between two capable peers"

echo "[PASS] M6 Docker mixed-fleet policy scenario"
