#!/usr/bin/env bash
# M9 Docker scenario: design case 10, the trusted-directory limitation --
# real kernel peers, real binaries, real containers, a real second
# identity (peer-attacker's own legitimately-generated PQ keypair) reused
# to demonstrate the accepted limitation, not a hypothetical.
#
# Sequence: peer-attacker registers a real bundle, and peer-target
# installs (redeeming its invite, so it becomes visible in the directory
# -- an unredeemed invite's peer_id is entirely invisible to other peers,
# a real finding from building this scenario) but never enables PQ, so
# its own bundle slot stays empty -> the server is stopped and its
# database is edited directly (tests/docker/scenarios/
# m9_directory_substitute.py) to attribute peer-attacker's real public
# keys to peer-target's now-visible directory slot -> the server restarts
# -> peer-observer enrolls fresh for the first time and is shown this
# already-substituted directory.
# Confirms peer-observer accepts the substituted identity on first
# contact with no error (design case 10's "initial key substitution by a
# malicious directory is possible despite mandatory signatures" -- this
# is documented as an accepted TOFU limitation, never reported here as a
# prevented attack). The "ordinary peers must still fail forgery/
# substitution checks" half is already covered by design cases 8/9's
# existing signature/context-binding evidence (a genuinely different
# question: a peer forging protocol messages without directory control,
# vs. the directory itself being compromised).
#
# Requires Docker with a real WireGuard-capable kernel, nft, and the
# ability to grant containers NET_ADMIN. Not run as part of
# `unit`/`integration`/`docker-smoke`.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../.."
COMPOSE=(docker compose -f tests/docker/docker-compose.m9-directory.yml -p innernet_pq_m9d)

cleanup() {
    "${COMPOSE[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] building runtime image..."
docker build -f tests/docker/Dockerfile.runtime -t innernet-pq-runtime:m9 . >/tmp/m9-directory-build.log 2>&1 \
    || { echo "build failed, see /tmp/m9-directory-build.log" >&2; tail -n 100 /tmp/m9-directory-build.log >&2; exit 1; }

cleanup
echo "[*] starting server, peer-attacker, and peer-target (peer-observer must not enroll until after the substitution)..."
"${COMPOSE[@]}" up -d server peer-attacker peer-target

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

attacker_bundle_registered() {
    "${COMPOSE[@]}" exec -T server sqlite3 /var/lib/innernet-server/pqm9d.db \
        "SELECT 1 FROM pq_bundles b JOIN peers p ON p.id = b.peer_id WHERE p.name = 'peer-attacker'" \
        | grep -q '^1$'
}
target_redeemed() {
    "${COMPOSE[@]}" exec -T server sqlite3 /var/lib/innernet-server/pqm9d.db \
        "SELECT 1 FROM peers WHERE name = 'peer-target' AND is_redeemed = 1" \
        | grep -q '^1$'
}

echo "[*] waiting for peer-attacker to register a real PQ bundle..."
wait_for "peer-attacker interface up" "${COMPOSE[@]}" exec -T peer-attacker wg show pqm9d
wait_for "peer-attacker's real bundle registered" attacker_bundle_registered
echo "[ok] peer-attacker holds a real, legitimately-generated PQ bundle"

echo "[*] waiting for peer-target to redeem its invite (becoming visible) without ever enabling PQ..."
wait_for "peer-target interface up" "${COMPOSE[@]}" exec -T peer-target wg show pqm9d
wait_for "peer-target redeemed" target_redeemed
target_bundle_absent="$("${COMPOSE[@]}" exec -T server sqlite3 /var/lib/innernet-server/pqm9d.db \
    "SELECT count(*) FROM pq_bundles b JOIN peers p ON p.id = b.peer_id WHERE p.name = 'peer-target'" | tr -d '\r\n')"
[ "$target_bundle_absent" = "0" ] || { echo "FAIL: peer-target already has a real bundle; the scenario's precondition (an empty, substitutable slot) does not hold" >&2; exit 1; }
echo "[ok] peer-target is redeemed/visible but has no real PQ bundle of its own yet"

echo "[*] stopping the server to substitute peer-target's directory slot..."
"${COMPOSE[@]}" stop server >/dev/null
docker run --rm \
    -v innernet_pq_m9d_server_data:/var/lib/innernet-server \
    -v "$(pwd)/tests/docker/scenarios/m9_directory_substitute.py:/substitute.py:ro" \
    innernet-pq-runtime:m9 \
    python3 /substitute.py /var/lib/innernet-server/pqm9d.db

echo "[*] restarting the server (directory now attributes peer-attacker's real keys to peer-target)..."
"${COMPOSE[@]}" up -d server
wait_for "server back up" "${COMPOSE[@]}" exec -T server wg show pqm9d

target_id="$("${COMPOSE[@]}" exec -T server sqlite3 /var/lib/innernet-server/pqm9d.db \
    "SELECT id FROM peers WHERE name = 'peer-target'" | tr -d '\r\n')"
[ -n "$target_id" ] || { echo "FAIL: could not determine peer-target's id" >&2; exit 1; }
echo "[ok] peer-target's id is $target_id"

echo "[*] peer-observer enrolls fresh now, for the first time seeing the already-substituted directory..."
"${COMPOSE[@]}" up -d peer-observer
wait_for "peer-observer interface up" "${COMPOSE[@]}" exec -T peer-observer wg show pqm9d

echo "[*] confirming peer-observer accepted the substituted identity on first contact, with no error..."
wait_for "peer-observer recorded a relationship for the substituted peer-target" "${COMPOSE[@]}" exec -T peer-observer \
    python3 -c "
import json
d = json.load(open('/var/lib/innernet/pqm9d.pq/state.json'))
rel = d['value']['relationships'].get('${target_id}')
assert rel is not None, 'no relationship recorded for peer-target at all'
"

"${COMPOSE[@]}" exec -T peer-observer python3 -c "
import json
d = json.load(open('/var/lib/innernet/pqm9d.pq/state.json'))
rel = d['value']['relationships']['${target_id}']
print(f\"peer-observer's recorded bundle_id for peer-target: {rel['remote']['bundle_id']}\")
print('peer-observer accepted this substituted identity with no error or warning -- exactly the accepted TOFU limitation design case 10 describes.')
"
echo "[ok] peer-observer silently accepted the directory-substituted identity on first contact"

echo "[PASS] M9 Docker trusted-directory limitation scenario (design case 10)"
