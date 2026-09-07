#!/usr/bin/env bash
# M2 Docker scenario: real containers, real WireGuard kernel interfaces, real
# crypto and binaries. Covers the M2 acceptance line from docs/milestones.md:
# fresh invitation-carried management enrollment, the server-link ACL's
# positive/negative reachability pair, server-restart durability, and a
# fail-closed refusal when an enabled peer's management link is lost.
#
# Requires Docker with a real WireGuard-capable kernel and the ability to
# grant containers NET_ADMIN. Not run as part of `unit`/`integration`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m2.yml -p innernet_pq_m2)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m2 . >/tmp/m2-build.log 2>&1 \
    || { echo "build failed, see /tmp/m2-build.log" >&2; tail -n 100 /tmp/m2-build.log >&2; exit 1; }

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

psk_of() {
    # A peer's own interface may also carry a data-peer entry once CIDR
    # visibility exposes one (its PSK is unrelated and expected to be
    # "(none)" pre-M3/M4). Identify the *server* line specifically by its
    # stable docker-network endpoint rather than assuming line order/count.
    "${COMPOSE[@]}" exec -T "$1" wg show pqm2 dump | awk '$3 ~ /^10\.88\.0\.2:/ {print $2}'
}

# Redemption's key rotation (a deliberate ~5s client + ~5s server delayed
# kernel update, see api::user::redeem) means the API isn't reachable the
# instant the interface first comes up; retry within a bounded deadline
# rather than racing it with a single attempt.
wait_for_http() {
    local peer="$1" url="$2" tries=0
    until "${COMPOSE[@]}" exec -T "$peer" sh -c \
        "curl -s -o /dev/null -w '%{http_code}' --max-time 5 '$url'" | grep -qE '^[0-9]{3}$'; do
        tries=$((tries + 1))
        if [ "$tries" -gt 30 ]; then
            return 1
        fi
        sleep 2
    done
}

echo "[*] waiting for both peers to redeem and establish their management link..."
wait_for "peer-a interface up" "${COMPOSE[@]}" exec -T peer-a wg show pqm2
wait_for "peer-b interface up" "${COMPOSE[@]}" exec -T peer-b wg show pqm2

a_psk="$(psk_of peer-a)"
b_psk="$(psk_of peer-b)"
[ "$a_psk" != "(none)" ] && [ -n "$a_psk" ] || { echo "FAIL: peer-a has no management PSK" >&2; exit 1; }
[ "$b_psk" != "(none)" ] && [ -n "$b_psk" ] || { echo "FAIL: peer-b has no management PSK" >&2; exit 1; }
[ "$a_psk" != "$b_psk" ] || { echo "FAIL: peer-a and peer-b share a PSK" >&2; exit 1; }
echo "[ok] both peers hold independent, non-empty management PSKs"

echo "[*] positive control: coordination API stays reachable through the ACL..."
wait_for_http peer-a http://10.99.0.1:51820/v1/user/state \
    || { echo "FAIL: coordination API unreachable" >&2; "${COMPOSE[@]}" logs; exit 1; }
echo "[ok] coordination API reachable"

echo "[*] negative control: an unrelated service through the server is blocked..."
if "${COMPOSE[@]}" exec -T peer-a curl -s -o /dev/null --max-time 5 http://10.99.0.1:8080/; then
    echo "FAIL: unrelated port was reachable through the management-only link" >&2
    exit 1
fi
echo "[ok] unrelated traffic through the server is dropped"

echo "[*] restarting the server; the link and API access must survive..."
"${COMPOSE[@]}" restart server
wait_for "server interface back up" "${COMPOSE[@]}" exec -T server wg show pqm2
wait_for_http peer-a http://10.99.0.1:51820/v1/user/state \
    || { echo "FAIL: coordination API unreachable after server restart" >&2; "${COMPOSE[@]}" logs; exit 1; }
restarted_psk="$(psk_of peer-a)"
[ "$restarted_psk" = "$a_psk" ] || { echo "FAIL: peer-a's PSK changed across a server restart" >&2; exit 1; }
echo "[ok] server restart preserved the durable management link"

echo "[*] simulating lost management state for peer-b: serve must fail closed..."
"${COMPOSE[@]}" stop server >/dev/null
docker run --rm -v innernet_pq_m2_server_config:/etc/innernet-server innernet-pq-runtime:m2 \
    python3 -c "
import json, glob
path = glob.glob('/etc/innernet-server/pqm2.server-pq/state.json')[0]
with open(path) as f:
    state = json.load(f)
value = state['value']
removed = value['links'].pop('3', None)  # peer-b is the second added peer (id 3)
assert removed is not None, 'peer-b link was not present to remove'
state['generation'] += 1
with open(path, 'w') as f:
    json.dump(state, f)
"
if "${COMPOSE[@]}" up -d server && "${COMPOSE[@]}" exec -T server sh -c 'sleep 3; wg show pqm2' >/dev/null 2>&1; then
    echo "FAIL: server started with an incomplete management link, should have failed closed" >&2
    exit 1
fi
echo "[ok] server refused to start with a missing enabled-peer management link"

echo "[PASS] M2 Docker management scenario"
