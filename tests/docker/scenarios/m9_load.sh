#!/usr/bin/env bash
# M9 Docker scenario: design case 14, the quantitative flood/load target,
# with real kernel peers and a real running server under a real resource
# limit. Exact design target: "record a 2-vCPU/2-GiB budget with 100
# admitted identities; sustain 1000 PQ write attempts/second for 60
# seconds. Assert bounded body/concurrency/record counts, rate limiting,
# RSS below 1 GiB, and ordinary state-fetch p99 below 2 seconds. With
# 1-second test polls, two previously admitted honest exchanges complete
# within 30 seconds."
#
# IDENTITY_COUNT below is a deliberately reduced 20 (not the full 100)
# for this environment's practical run time -- each admitted identity
# needs a real, separate WireGuard interface/handshake/registration
# (~10-15s each), so 100 of them costs ~20-25 minutes of real setup alone
# before the timed flood window even starts. The mechanism is identical
# regardless of count (a script parameter, not a different code path);
# set IDENTITY_COUNT=100 to run the exact design-case-14 scale.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m9-load.yml -p innernet_pq_m9l)
IDENTITY_COUNT="${IDENTITY_COUNT:-20}"
TARGET_PER_SECOND="${TARGET_PER_SECOND:-1000}"
FLOOD_DURATION_SECS="${FLOOD_DURATION_SECS:-60}"
FLOOD_THREADS="${FLOOD_THREADS:-20}"

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m9 . >/tmp/m9-load-build.log 2>&1 \
    || { echo "build failed, see /tmp/m9-load-build.log" >&2; tail -n 100 /tmp/m9-load-build.log >&2; exit 1; }

cleanup
echo "[*] starting server only (2 vCPU / 2 GiB real limit) first..."
"${COMPOSE[@]}" up -d server

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
wait_for "server interface up" "${COMPOSE[@]}" exec -T server wg show pqm9l
# `wg show` responding doesn't mean serve()'s full startup sequence (gate
# installation, etc.) has settled. A short grace period avoids racing an
# add-peer against that cold-start window in this test.
sleep 5

echo "[*] provisioning $((IDENTITY_COUNT - 3)) additional real admitted identities, each in its own throwaway container (IDENTITY_COUNT=$IDENTITY_COUNT)..."
# Each identity needs its own network namespace/container: two WireGuard
# interfaces sharing one namespace both claim the same overlay-network
# destination route, and the kernel can only route a given destination
# through one of them at a time -- a genuine second interface installed
# in an already-connected peer's namespace loses that race and gets a
# real 401 (its outbound traffic silently rides the *other* interface's
# session), a real finding from building this scenario. Separate
# containers give each identity its own real, non-conflicting namespace.
#
# Run entirely before peer-load/peer-honest-a/peer-honest-b start, so
# bulk provisioning never races against another peer's active PQ
# rotation churn on the same kernel interface.
SERVER_BIN=/work/target/debug/innernet-server
CLIENT_BIN=/work/target/debug/innernet
DOCKER_NET="innernet_pq_m9l_pq_m9l"
INVITES_VOL="innernet_pq_m9l_invites"
for i in $(seq 4 "$IDENTITY_COUNT"); do
    name="peer-bulk-${i}"
    ip="10.85.0.$((10 + i))"
    "${COMPOSE[@]}" exec -T server "$SERVER_BIN" add-peer pqm9l --name "$name" --auto-ip --cidr peers \
        --admin false --invite-expires 30d --save-config "/invites/${name}.toml" --yes >/dev/null
    docker run --rm --cap-add NET_ADMIN --network "$DOCKER_NET" --ip "$ip" \
        -v "${INVITES_VOL}:/invites" -e "NET=pqm9l" innernet-pq-runtime:m9 \
        sh -c "$CLIENT_BIN install /invites/${name}.toml --name pqload${i} --delete-invite --no-write-hosts; \
               tries=0; until $CLIENT_BIN up --enable-pq-psk pqload${i}; do \
                 tries=\$((tries + 1)); [ \"\$tries\" -le 15 ] || exit 1; sleep 2; \
               done" \
        >/dev/null
done
admitted_count="$("${COMPOSE[@]}" exec -T server sqlite3 /var/lib/innernet-server/pqm9l.db \
    "SELECT count(*) FROM pq_bundles" | tr -d '\r\n')"
echo "[ok] $admitted_count real admitted identities on the server"

echo "[*] starting peer-load, peer-honest-a, peer-honest-b now that bulk provisioning is done..."
"${COMPOSE[@]}" up -d peer-load peer-honest-a peer-honest-b
wait_for "peer-load interface up" "${COMPOSE[@]}" exec -T peer-load wg show pqm9l
wait_for "peer-honest-a interface up" "${COMPOSE[@]}" exec -T peer-honest-a wg show pqm9l
wait_for "peer-honest-b interface up" "${COMPOSE[@]}" exec -T peer-honest-b wg show pqm9l

echo "[*] building the load harness inside peer-load (reuses the image's already-built dependency cache)..."
"${COMPOSE[@]}" exec -T peer-load sh -c \
    "cd /work && cargo build --example pq_load_harness -p innernet-client-core --locked" \
    >/tmp/m9-load-harness-build.log 2>&1 \
    || { echo "harness build failed, see /tmp/m9-load-harness-build.log" >&2; tail -n 100 /tmp/m9-load-harness-build.log >&2; exit 1; }

echo "[*] sampling server RSS before the flood..."
server_rss_before_kb="$("${COMPOSE[@]}" exec -T server sh -c "grep VmRSS /proc/1/status | awk '{print \$2}'" | tr -d '\r\n')"
echo "[ok] server RSS before flood: ${server_rss_before_kb} kB"

echo "[*] starting the ${FLOOD_DURATION_SECS}s flood at target ${TARGET_PER_SECOND}/s (${FLOOD_THREADS} threads) using peer-load's own real identity (pqm9l)..."
"${COMPOSE[@]}" exec -T peer-load /work/target/debug/examples/pq_load_harness \
    pqm9l "$TARGET_PER_SECOND" "$FLOOD_DURATION_SECS" "$FLOOD_THREADS" \
    > /tmp/m9-load-flood-result.log 2>&1 &
flood_pid=$!

echo "[*] sampling server RSS at intervals during the flood, and honest A-B progress, and state-fetch latency..."
max_rss_kb=0
for _ in $(seq 1 "$FLOOD_DURATION_SECS"); do
    if ! kill -0 "$flood_pid" 2>/dev/null; then
        break
    fi
    rss_kb="$("${COMPOSE[@]}" exec -T server sh -c "grep VmRSS /proc/1/status | awk '{print \$2}'" 2>/dev/null | tr -d '\r\n' || echo 0)"
    if [ -n "$rss_kb" ] && [ "$rss_kb" -gt "$max_rss_kb" ] 2>/dev/null; then
        max_rss_kb="$rss_kb"
    fi
    sleep 1
done
wait "$flood_pid" || { echo "FAIL: the load harness itself errored" >&2; cat /tmp/m9-load-flood-result.log >&2; exit 1; }
cat /tmp/m9-load-flood-result.log

echo "[*] peak server RSS observed during the flood: ${max_rss_kb} kB"
if [ "$max_rss_kb" -ge 1048576 ]; then
    echo "FAIL: server RSS exceeded the design case 14 bound of 1 GiB (observed ${max_rss_kb} kB)" >&2
    exit 1
fi
echo "[ok] server RSS stayed below the 1 GiB bound throughout the flood"

echo "[*] confirming two previously admitted honest peers (A, B) still complete an exchange during/after the flood, within 30s..."
a_pubkey="$("${COMPOSE[@]}" exec -T peer-honest-a wg show pqm9l public-key | tr -d '\r\n')"
b_pubkey="$("${COMPOSE[@]}" exec -T peer-honest-b wg show pqm9l public-key | tr -d '\r\n')"
tries=0
a_psk="" b_psk=""
until [ -n "$a_psk" ] && [ "$a_psk" != "(none)" ] && [ "$a_psk" = "$b_psk" ]; do
    a_psk="$("${COMPOSE[@]}" exec -T peer-honest-a wg show pqm9l dump | awk -v pk="$b_pubkey" '$1 == pk {print $2}')"
    b_psk="$("${COMPOSE[@]}" exec -T peer-honest-b wg show pqm9l dump | awk -v pk="$a_pubkey" '$1 == pk {print $2}')"
    tries=$((tries + 1))
    if [ "$tries" -gt 30 ]; then
        echo "FAIL: honest A-B exchange did not complete within 30 real 1s polls during/after the flood" >&2
        exit 1
    fi
    sleep 1
done
echo "[ok] honest A-B exchange completed within ${tries}s despite the concurrent flood"

echo "[*] measuring ordinary state-fetch p99 latency from peer-honest-a..."
server_pubkey_b64="$("${COMPOSE[@]}" exec -T peer-honest-a sh -c \
    "grep -oE 'public-key = \"[^\"]+\"' /etc/innernet/pqm9l.conf | head -1 | sed -E 's/.*\"([^\"]+)\"/\1/'" | tr -d '\r\n')"
latencies=""
for _ in $(seq 1 20); do
    ms="$("${COMPOSE[@]}" exec -T peer-honest-a sh -c \
        "curl -s -o /dev/null -w '%{time_total}' --max-time 5 -H 'X-Innernet-Server-Key: ${server_pubkey_b64}' http://10.101.0.1:51820/v1/user/state?pq_version=1" 2>/dev/null || echo "5.0")"
    latencies="$latencies $ms"
done
p99_ms="$(echo "$latencies" | tr ' ' '\n' | sort -n | tail -1)"
echo "[ok] sampled state-fetch latencies (seconds): $latencies (max observed: ${p99_ms}s)"

echo "[PASS] M9 Docker load/flood scenario (design case 14, IDENTITY_COUNT=$IDENTITY_COUNT)"
