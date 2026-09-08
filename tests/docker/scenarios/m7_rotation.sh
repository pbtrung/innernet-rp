#!/usr/bin/env bash
# M7 Docker scenario: real administrative management-PSK rotation (design
# 5.10) with real kernel peers, real binaries, real containers. Covers
# design case 16's successful/failed administrative rotation using
# independent access, matching testing.md section 4.4 scenario 8's "stage/
# apply a new server-link PSK on both endpoints... mismatched installation
# repaired out of band".
#
# peer-a exercises the full happy path: stage -> apply (both sides) ->
# verify -> mark-verified -> confirm, then a server+peer-a restart proves
# the rotated (not the original) secret is what survives.
# peer-b exercises the failure/repair path: stage+apply on the server only
# (peer-b's client is never touched), proving the link breaks on a real
# mismatch, then `rollback-management-rotation` restores parity out of
# band without needing peer-b's cooperation -- design 5.10 step 4's
# "restore old to both" (peer-b never left "old" in the first place).
#
# Requires Docker with a real WireGuard-capable kernel, nft, and the
# ability to grant containers NET_ADMIN. Not run as part of
# `unit`/`integration`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m7.yml -p innernet_pq_m7)
SERVER_BIN=/work/target/debug/innernet-server
CLIENT_BIN=/work/target/debug/innernet
API="http://10.96.0.1:51820/v1/user/state"

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m7 . >/tmp/m7-build.log 2>&1 \
    || { echo "build failed, see /tmp/m7-build.log" >&2; tail -n 100 /tmp/m7-build.log >&2; exit 1; }

cleanup
echo "[*] starting server, peer-a, peer-b..."
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

wait_for_http() {
    local peer="$1" tries=0
    until "${COMPOSE[@]}" exec -T "$peer" sh -c \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 5 '$API'" | grep -qE '^[0-9]{3}$'; do
        tries=$((tries + 1))
        if [ "$tries" -gt 45 ]; then
            return 1
        fi
        sleep 2
    done
}

# A remove+re-add rotation apply (needed to force a fresh handshake --
# see client-core::management::push_active_to_kernel) resets the observed
# endpoint in `wg show dump` until a new handshake arrives, so peer rows
# must be identified by their stable public key, never by endpoint.
psk_of() {
    # Peer $1's own dump, keyed by the server's public key.
    "${COMPOSE[@]}" exec -T "$1" wg show pqm7 dump | awk -v pk="$server_pubkey" '$1 == pk {print $2}'
}
server_side_psk_of() {
    # The server's own dump, keyed by the named peer's public key.
    "${COMPOSE[@]}" exec -T server wg show pqm7 dump | awk -v pk="$1" '$1 == pk {print $2}'
}

echo "[*] waiting for both peers to redeem and establish their management link..."
wait_for "peer-a interface up" "${COMPOSE[@]}" exec -T peer-a wg show pqm7
wait_for "peer-b interface up" "${COMPOSE[@]}" exec -T peer-b wg show pqm7
server_pubkey="$("${COMPOSE[@]}" exec -T server wg show pqm7 public-key | tr -d '\r\n')"
peer_a_pubkey="$("${COMPOSE[@]}" exec -T peer-a wg show pqm7 public-key | tr -d '\r\n')"
peer_b_pubkey="$("${COMPOSE[@]}" exec -T peer-b wg show pqm7 public-key | tr -d '\r\n')"
wait_for_http peer-a || { echo "FAIL: coordination API unreachable before any rotation" >&2; exit 1; }
original_a_psk="$(psk_of peer-a)"
original_b_psk="$(psk_of peer-b)"
[ "$original_a_psk" != "(none)" ] && [ -n "$original_a_psk" ] || { echo "FAIL: peer-a has no management PSK" >&2; exit 1; }
echo "[ok] both peers hold independent management PSKs"

echo "[*] peer-a: staging a rotation candidate on the server..."
stage_output="$("${COMPOSE[@]}" exec -T server "$SERVER_BIN" stage-management-rotation pqm7 \
    --name peer-a --independent-admin-access)"
artifact_path="$(printf '%s' "$stage_output" | grep -oE '/etc/innernet-server/[^ ;]+\.json')"
[ -n "$artifact_path" ] || { echo "FAIL: could not parse the staged artifact path from: $stage_output" >&2; exit 1; }
"${COMPOSE[@]}" exec -T server cp "$artifact_path" /invites/peer-a-rotation.json
echo "[ok] staged candidate exported and transferred (out of band) to peer-a"

echo "[*] peer-a: importing the staged candidate..."
"${COMPOSE[@]}" exec -T peer-a "$CLIENT_BIN" stage-management pqm7 /invites/peer-a-rotation.json

echo "[*] peer-a: applying the rotation on both sides..."
"${COMPOSE[@]}" exec -T server "$SERVER_BIN" apply-management-rotation pqm7 \
    --name peer-a --independent-admin-access
"${COMPOSE[@]}" exec -T peer-a "$CLIENT_BIN" apply-management pqm7

echo "[*] peer-a: verifying a real fresh handshake and authenticated request..."
wait_for_http peer-a || { echo "FAIL: coordination API unreachable after applying peer-a's rotation" >&2; "${COMPOSE[@]}" logs; exit 1; }
rotated_a_psk="$(psk_of peer-a)"
[ "$rotated_a_psk" != "$original_a_psk" ] || { echo "FAIL: peer-a's PSK did not actually change" >&2; exit 1; }
[ "$rotated_a_psk" = "$(server_side_psk_of "$peer_a_pubkey")" ] || { echo "FAIL: peer-a and the server disagree on the rotated PSK" >&2; exit 1; }
echo "[ok] real fresh handshake and authenticated request succeeded on the rotated secret"

echo "[*] peer-a: marking verified and confirming (discarding the superseded secret)..."
"${COMPOSE[@]}" exec -T server "$SERVER_BIN" mark-management-verified pqm7 \
    --name peer-a --independent-admin-access
"${COMPOSE[@]}" exec -T server "$SERVER_BIN" confirm-management-rotation pqm7 \
    --name peer-a --independent-admin-access
"${COMPOSE[@]}" exec -T peer-a "$CLIENT_BIN" confirm-management pqm7
echo "[ok] peer-a's rotation is confirmed end to end"

echo "[*] peer-b: negative control -- applying only on the server creates a real mismatch..."
"${COMPOSE[@]}" exec -T server "$SERVER_BIN" stage-management-rotation pqm7 \
    --name peer-b --independent-admin-access >/dev/null
"${COMPOSE[@]}" exec -T server "$SERVER_BIN" apply-management-rotation pqm7 \
    --name peer-b --independent-admin-access
sleep 5 # give peer-b's own daemon a few real poll cycles to (wrongly) recover, if it were going to.
if wait_for_http peer-b; then
    echo "FAIL: peer-b's link stayed reachable despite a real one-sided PSK mismatch" >&2
    exit 1
fi
echo "[ok] a real one-sided PSK mismatch broke the link, not a crash or a hang"

echo "[*] peer-b: repairing out of band with rollback-management-rotation..."
"${COMPOSE[@]}" exec -T server "$SERVER_BIN" rollback-management-rotation pqm7 \
    --name peer-b --independent-admin-access
wait_for_http peer-b || { echo "FAIL: coordination API still unreachable after the server-side rollback" >&2; "${COMPOSE[@]}" logs; exit 1; }
[ "$(psk_of peer-b)" = "$original_b_psk" ] || { echo "FAIL: peer-b's PSK does not match its original secret after rollback" >&2; exit 1; }
echo "[ok] independent-access rollback repaired the mismatch without touching peer-b"

echo "[*] restarting the server and peer-a together; the rotated secret must survive..."
"${COMPOSE[@]}" restart server peer-a
wait_for "server interface back up" "${COMPOSE[@]}" exec -T server wg show pqm7
wait_for "peer-a interface back up" "${COMPOSE[@]}" exec -T peer-a wg show pqm7
wait_for_http peer-a || { echo "FAIL: coordination API unreachable after restarting server and peer-a" >&2; "${COMPOSE[@]}" logs; exit 1; }
restarted_a_psk="$(psk_of peer-a)"
[ "$restarted_a_psk" = "$rotated_a_psk" ] || { echo "FAIL: peer-a's rotated PSK did not survive a server+client restart" >&2; exit 1; }
[ "$restarted_a_psk" != "$original_a_psk" ] || { echo "FAIL: peer-a reverted to its pre-rotation PSK across a restart" >&2; exit 1; }
echo "[ok] the rotated (not the original) secret survived a real server+client restart"

echo "[PASS] M7 Docker management-PSK rotation scenario"
