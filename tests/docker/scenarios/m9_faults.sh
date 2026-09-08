#!/usr/bin/env bash
# M9 Docker scenario: closes design cases 4/5/7's real-kernel half --
# response-level fault injection (lost response, duplicate delivery via
# the client's own real retry, and stale-message replay) with real kernel
# peers, real binaries, real containers. Matches testing.md section 4.4
# scenarios 2 (lost commit response) and 5 (replay/tampering), the two
# scenarios M4's own implementation notes flagged as blocked on missing
# fault-injection hooks.
#
# peer-b's own traffic is relayed through tests/docker/scenarios/
# fault_proxy.py (see its header and peer-entrypoint-m9-fault.sh for how);
# peer-a is peer-b's exchange partner, peer-c is testing.md's cooperating
# "A-C traffic/progress control" -- its independent progress throughout
# proves one peer's fault never blocks or crashes another.
#
# Requires Docker with a real WireGuard-capable kernel, nft, and the
# ability to grant containers NET_ADMIN. Not run as part of
# `unit`/`integration`/`docker-smoke`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m9.yml -p innernet_pq_m9)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m9 . >/tmp/m9-faults-build.log 2>&1 \
    || { echo "build failed, see /tmp/m9-faults-build.log" >&2; tail -n 100 /tmp/m9-faults-build.log >&2; exit 1; }

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
    local querier="$1" pubkey="$2"
    "${COMPOSE[@]}" exec -T "$querier" wg show pqm9 dump | awk -v pk="$pubkey" '$1 == pk {print $2}'
}

run_scenario() {
    local mode="$1" match="$2" count="$3" label="$4"
    cleanup
    echo "[*] starting server, peer-a, peer-b (faulted: $label), peer-c..."
    FAULT_MODE="$mode" FAULT_MATCH="$match" FAULT_COUNT="$count" "${COMPOSE[@]}" up -d

    wait_for "peer-a interface up" "${COMPOSE[@]}" exec -T peer-a wg show pqm9
    wait_for "peer-b interface up" "${COMPOSE[@]}" exec -T peer-b wg show pqm9
    wait_for "peer-c interface up" "${COMPOSE[@]}" exec -T peer-c wg show pqm9

    a_pubkey="$("${COMPOSE[@]}" exec -T peer-a wg show pqm9 public-key | tr -d '\r\n')"
    b_pubkey="$("${COMPOSE[@]}" exec -T peer-b wg show pqm9 public-key | tr -d '\r\n')"
    c_pubkey="$("${COMPOSE[@]}" exec -T peer-c wg show pqm9 public-key | tr -d '\r\n')"

    echo "[*] waiting for A-B to converge on a matching real candidate despite the injected fault ($label)..."
    tries=0
    a_psk="" b_psk=""
    until [ -n "$a_psk" ] && [ "$a_psk" != "(none)" ] && [ "$a_psk" = "$b_psk" ]; do
        a_psk="$(psk_of peer-a "$b_pubkey")"
        b_psk="$(psk_of peer-b "$a_pubkey")"
        tries=$((tries + 1))
        if [ "$tries" -gt 90 ]; then
            echo "FAIL: A-B never converged on a matching candidate under fault mode '$label'" >&2
            "${COMPOSE[@]}" logs peer-b
            exit 1
        fi
        sleep 2
    done
    echo "[ok] A-B converged on a matching real candidate despite the injected fault ($label)"

    echo "[*] confirming A-C's independent progress was never blocked by peer-b's fault..."
    tries=0
    a_c_psk="" c_a_psk=""
    until [ -n "$a_c_psk" ] && [ "$a_c_psk" != "(none)" ] && [ "$a_c_psk" = "$c_a_psk" ]; do
        a_c_psk="$(psk_of peer-a "$c_pubkey")"
        c_a_psk="$(psk_of peer-c "$a_pubkey")"
        tries=$((tries + 1))
        if [ "$tries" -gt 90 ]; then
            echo "FAIL: A-C never converged; peer-b's fault must not block an unrelated relationship" >&2
            exit 1
        fi
        sleep 2
    done
    echo "[ok] A-C progressed independently throughout"

    "${COMPOSE[@]}" logs peer-b 2>&1 | grep -i "fault-proxy" || true
}

# peer-a is created first (id 2), peer-b second (id 3): matches design's
# lower-ID-initiates rule, so peer-b is A-B's *responder*, never A-B's
# own phase=1 sender. Match specifically on peer-b's traffic addressed to
# peer 2 (peer-a) so the fault lands on the intended A-B relationship,
# not on peer-b's own initiator role in its separate B-C relationship
# (peer-b -> peer 4/peer-c), which uses the same "pq-handshake" substring.
run_scenario "drop-response" "pq-handshake/2?phase=" "1" "lost commit response, real client retry"
echo "[PASS] M9 lost-response/real-retry fault scenario"

run_scenario "replay" "pq-handshake/2?phase=" "1" "stale handshake message replay"
echo "[PASS] M9 replay fault scenario"

echo "[PASS] M9 Docker fault-injection scenario"
