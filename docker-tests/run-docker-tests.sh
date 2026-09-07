#!/usr/bin/env bash
set -e
shopt -s nocasematch

SELF_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SELF_DIR/.."

help() {
    cat >&2 <<-_EOF
Usage: "${0##*/}" [options...] (<test>)
 --interactive  Enter interactive mode, providing a chance to attach to innernet docker containers
 --userspace    Use userspace wireguard instead of kernel one
 --verbose      Print verbose innernet logs
_EOF
}

TEST_FILTER=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --interactive)
        INTERACTIVE=true
        shift
        ;;
    --userspace)
        INNERNET_ARGS="$INNERNET_ARGS --backend userspace"
        shift
        ;;
    --verbose)
        INNERNET_ARGS="$INNERNET_ARGS -vvv"
        CLIENT_ARGS="$CLIENT_ARGS --verbose"
        SERVER_RUST_LOG="debug"
        CLIENT_RUST_LOG="trace"
        shift
        ;;
    --help)
        help
        exit
        ;;
    -*)
        echo "Invalid option."
        help
        exit 1
        ;;
    *)
        TEST_FILTER+=("$1")
        shift
        ;;
  esac
done

cmd() {
    echo "[#] $*" >&2
    "$@"
}

info() {
    echo -e "\033[0;34m- $@\033[0m" 1>&2
}

tmp_dir=$(mktemp -d -t innernet-tests-XXXXXXXXXX)
info "temp dir: $tmp_dir"
cleanup() {
    info "Cleaning up."
    rm -rf "$tmp_dir"
    cmd docker stop $(docker ps -q) || true
    cmd docker network remove innernet
}
trap cleanup EXIT

info "Creating network."
NETWORK=$(cmd docker network create -d bridge --subnet=172.18.0.0/16 innernet)

info "Starting server."
# Enabled unconditionally: per doc/milestones.md M6, the server's own Rosenpass sync only ever
# adds PSK protection to server<->peer links and never gates peer visibility/reachability, so
# turning it on here is safe for every other test in this file, not just the rosenpass-specific
# ones below.
SERVER_ROSENPASS_ARGS="${SERVER_ROSENPASS_ARGS:---enable-rosenpass}"
SERVER_CONTAINER=$(cmd docker create -it --rm \
    --network "$NETWORK" \
    --ip 172.18.1.1 \
    --volume /dev/net/tun:/dev/net/tun \
    --env RUST_LOG="$SERVER_RUST_LOG" \
    --env INNERNET_ARGS="$INNERNET_ARGS" \
    --env SERVER_ROSENPASS_ARGS="$SERVER_ROSENPASS_ARGS" \
    --cap-add NET_ADMIN \
    innernet)
cmd docker start -a "$SERVER_CONTAINER" | sed -e 's/^/\x1B[0;95mserver\x1B[0m: /' &

info "server started as $SERVER_CONTAINER"
info "Waiting for server to initialize."
cmd sleep 5

create_peer_docker() {
    local IP=$1
    local LISTEN_PORT="${2:-}"
    local ROSENPASS_ARGS="${3:-}"
    cmd docker create --rm -it \
        --network "$NETWORK" \
        --ip $IP \
        --volume /dev/net/tun:/dev/net/tun \
        --cap-add NET_ADMIN \
        --env RUST_LOG="$CLIENT_RUST_LOG" \
        --env INTERFACE=evilcorp \
        --env LISTEN_PORT="$LISTEN_PORT" \
        --env INNERNET_ARGS="$INNERNET_ARGS" \
        --env CLIENT_ARGS="$CLIENT_ARGS" \
        --env ROSENPASS_ARGS="$ROSENPASS_ARGS" \
        innernet /app/start-client.sh
}

# Retries "$@" (a command and its arguments) every 2s until it succeeds or $1 seconds have
# elapsed. Returns 1 without aborting the script (unlike a bare failing `cmd`, which does abort
# under this script's `set -e`) so callers can decide how to report a timeout.
wait_until() {
    local timeout=$1
    shift
    local waited=0
    while ! "$@" >/dev/null 2>&1; do
        if (( waited >= timeout )); then
            return 1
        fi
        sleep 2
        waited=$((waited + 2))
    done
    return 0
}

# Prints the preshared key `wg show` reports for the peer at $2 (a docker-network IP, matched
# against `wg show ... endpoints`) on $1's WireGuard interface, or "(none)" if that peer isn't a
# known WireGuard peer yet (no handshake exchanged, so no endpoint recorded).
peer_psk() {
    local container=$1
    local peer_ip=$2
    local pubkey
    pubkey=$(docker exec "$container" wg show evilcorp endpoints | awk -v ip="$peer_ip:" '$0 ~ ip {print $1; exit}')
    if [[ -z "$pubkey" ]]; then
        echo "(none)"
        return 0
    fi
    docker exec "$container" wg show evilcorp preshared-keys | awk -v pk="$pubkey" '$1 == pk {print $2; exit}'
}

_psk_is_set() {
    local psk
    psk=$(peer_psk "$1" "$2")
    [[ -n "$psk" && "$psk" != "(none)" ]]
}

_psk_changed_from() {
    local psk
    psk=$(peer_psk "$1" "$2")
    [[ -n "$psk" && "$psk" != "(none)" && "$psk" != "$3" ]]
}

info "Starting first peer."
cmd docker cp "$SERVER_CONTAINER:/app/peer1.toml" "$tmp_dir"
PEER1_CONTAINER=$(create_peer_docker 172.18.1.2 51821)
info "peer1 started as $PEER1_CONTAINER"
cmd docker cp "$tmp_dir/peer1.toml" "$PEER1_CONTAINER:/app/invite.toml"
cmd docker start -a "$PEER1_CONTAINER" | sed -e 's/^/\x1B[0;96mpeer 1\x1B[0m: /' &
sleep 10

info "Creating a new CIDR from first peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-cidr evilcorp \
    --name "robots" \
    --cidr "10.66.2.0/24" \
    --parent "evilcorp" \
    --yes

info "Creating association between CIDRs."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-association evilcorp \
        humans \
        robots

info "Creating invitation for second peer from first peer."
cmd docker exec "$PEER1_CONTAINER" innernet \
    add-peer evilcorp \
    --name "peer2" \
    --cidr "robots" \
    --admin false \
    --auto-ip \
    --save-config "/app/peer2.toml" \
    --invite-expires "30s" \
    --yes
cmd docker cp "$PEER1_CONTAINER:/app/peer2.toml" "$tmp_dir"

info "Starting second peer."
PEER2_CONTAINER=$(create_peer_docker 172.18.1.3)
info "peer2 started as $PEER2_CONTAINER"
cmd docker cp "$tmp_dir/peer2.toml" "$PEER2_CONTAINER:/app/invite.toml"
cmd docker start -a "$PEER2_CONTAINER" | sed -e 's/^/\x1B[0;93mpeer 2\x1B[0m: /' &
sleep 10

if [[ $INTERACTIVE == true ]]; then
    info "Open a new terminal and connect to one of the docker containers to test innernet commands."
    info ""
    info "Server:"
    info "  docker exec -it ${SERVER_CONTAINER:0:12} bash"
    info "Admin client:"
    info "  docker exec -it ${PEER1_CONTAINER:0:12} bash"
    info "Non-admin client:"
    info "  docker exec -it ${PEER2_CONTAINER:0:12} bash"
    wait
fi

test_short_lived_invitation() {
    info "Creating short-lived invitation for third peer."
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "peer3" \
        --cidr "robots" \
        --admin false \
        --ip "10.66.2.100" \
        --save-config "/app/peer3.toml" \
        --invite-expires "1s" \
        --yes

    info "waiting 15 seconds to see if the server clears out the IP address."
    sleep 11

    info "Re-requesting invite after expiration with the same parameters."
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "peer3" \
        --cidr "robots" \
        --admin false \
        --ip "10.66.2.100" \
        --save-config "/app/peer3_2.toml" \
        --invite-expires "30m" \
        --yes
}

test_install_listen_port() {
    info "Confirming install applies the requested listen port."
    cmd docker exec "$PEER1_CONTAINER" bash -c \
        'innernet $INNERNET_ARGS show "$INTERFACE" | grep -Fq "listening port: 51821"'
}

test_simultaneous_redemption() {
    info "Creating invitation for fourth and fifth peer from first peer."
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "peer4" \
        --cidr "robots" \
        --admin false \
        --auto-ip \
        --save-config "/app/peer4.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/peer4.toml" "$tmp_dir"
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "peer5" \
        --cidr "robots" \
        --admin false \
        --auto-ip \
        --save-config "/app/peer5.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/peer5.toml" "$tmp_dir"

    info "Starting fourth and fifth peer and redeeming simultaneously."
    PEER4_CONTAINER=$(create_peer_docker 172.18.1.4)
    cmd docker cp "$tmp_dir/peer4.toml" "$PEER4_CONTAINER:/app/invite.toml"
    PEER5_CONTAINER=$(create_peer_docker 172.18.1.5)
    cmd docker cp "$tmp_dir/peer5.toml" "$PEER5_CONTAINER:/app/invite.toml"

    cmd docker start -a "$PEER4_CONTAINER" | sed -e 's/^/\x1B[0;92mpeer 4\x1B[0m: /' &
    info "peer4 started as $PEER4_CONTAINER"
    cmd docker start -a "$PEER5_CONTAINER" | sed -e 's/^/\x1B[0;94mpeer 5\x1B[0m: /' &
    info "peer5 started as $PEER5_CONTAINER"

    info "Checking connectivity betweeen peers."
    cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.0.1
    cmd docker exec "$PEER2_CONTAINER" ping -c3 10.66.1.1
}

test_rename_cidr() {
    info "Renaming CIDR from peer1"
    cmd docker exec "$PEER1_CONTAINER" innernet \
        rename-cidr evilcorp \
            --name "robots" \
            --new-name "coolbeans" \
            --yes
    sleep 5

    info "Confirming the CIDR rename from peer1"
    cmd docker exec "$PEER1_CONTAINER" innernet list-cidrs evilcorp | grep coolbeans

    info "Renaming CIDR from server"
    cmd docker exec "$SERVER_CONTAINER" innernet-server \
        rename-cidr evilcorp \
            --name "coolbeans" \
            --new-name "robots" \
            --yes
    sleep 5

    info "Confirming the CIDR rename from peer1"
    cmd docker exec "$PEER1_CONTAINER" innernet list-cidrs evilcorp | grep robots
}

test_rosenpass_handshake() {
    info "Creating invitations for two Rosenpass-enabled peers."
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "rosenpass-a" \
        --cidr "humans" \
        --admin false \
        --ip "10.66.1.200" \
        --save-config "/app/rp_a.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/rp_a.toml" "$tmp_dir"
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "rosenpass-b" \
        --cidr "humans" \
        --admin false \
        --ip "10.66.1.201" \
        --save-config "/app/rp_b.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/rp_b.toml" "$tmp_dir"

    info "Starting both Rosenpass-enabled peers."
    RP_A_CONTAINER=$(create_peer_docker 172.18.1.6 "" "--enable-rosenpass")
    info "rosenpass peer A started as $RP_A_CONTAINER"
    cmd docker cp "$tmp_dir/rp_a.toml" "$RP_A_CONTAINER:/app/invite.toml"
    cmd docker start -a "$RP_A_CONTAINER" | sed -e 's/^/\x1B[0;35mrp-a\x1B[0m: /' &

    RP_B_CONTAINER=$(create_peer_docker 172.18.1.7 "" "--enable-rosenpass")
    info "rosenpass peer B started as $RP_B_CONTAINER"
    cmd docker cp "$tmp_dir/rp_b.toml" "$RP_B_CONTAINER:/app/invite.toml"
    cmd docker start -a "$RP_B_CONTAINER" | sed -e 's/^/\x1B[0;36mrp-b\x1B[0m: /' &

    info "Waiting for plain WireGuard connectivity between the two peers."
    wait_until 60 docker exec "$RP_A_CONTAINER" ping -c1 10.66.1.201 \
        || { info "peer A never reached peer B."; exit 1; }

    info "Confirming traffic flows immediately via the interim preshared key."
    local psk_a
    psk_a=$(peer_psk "$RP_A_CONTAINER" 172.18.1.7)
    if [[ -z "$psk_a" || "$psk_a" == "(none)" ]]; then
        info "expected a non-empty interim preshared key on peer A, got: '$psk_a'"
        exit 1
    fi
    cmd docker exec "$RP_A_CONTAINER" ping -c3 10.66.1.201

    info "Waiting for the real Rosenpass exchange to complete and rotate the PSK (this can take a while)."
    wait_until 150 _psk_changed_from "$RP_A_CONTAINER" 172.18.1.7 "$psk_a" \
        || { info "preshared key never rotated away from its interim value - real exchange did not complete."; exit 1; }
    info "Preshared key rotated after a real Rosenpass exchange, as expected."

    info "Confirming traffic still flows after the PSK rotation."
    cmd docker exec "$RP_A_CONTAINER" ping -c3 10.66.1.201
    cmd docker exec "$RP_B_CONTAINER" ping -c3 10.66.1.200

    info "Confirming Rosenpass secret-key and PSK handoff file permissions are 0600."
    cmd docker exec "$RP_A_CONTAINER" bash -c '
        set -e
        mode=$(stat -c %a /var/lib/innernet/rosenpass/evilcorp/secret-key)
        [[ "$mode" == "600" ]] || { echo "secret-key mode is $mode, not 600" >&2; exit 1; }
        for f in /var/lib/innernet/rosenpass/evilcorp/peers/*.psk; do
            mode=$(stat -c %a "$f")
            [[ "$mode" == "600" ]] || { echo "$f mode is $mode, not 600" >&2; exit 1; }
        done
    '

    info "Confirming the server also applied its own Rosenpass-derived preshared key to peer A."
    wait_until 60 _psk_is_set "$SERVER_CONTAINER" 172.18.1.6 \
        || { info "server never applied a preshared key to rosenpass peer A."; exit 1; }
}

test_rosenpass_permissive_fallback() {
    info "Creating invitations for a three-peer mixed fleet: strict, permissive, and legacy (no Rosenpass)."
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "rosenpass-strict" \
        --cidr "humans" \
        --admin false \
        --ip "10.66.1.202" \
        --save-config "/app/rp_e.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/rp_e.toml" "$tmp_dir"
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "rosenpass-permissive" \
        --cidr "humans" \
        --admin false \
        --ip "10.66.1.203" \
        --save-config "/app/rp_f.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/rp_f.toml" "$tmp_dir"
    cmd docker exec "$PEER1_CONTAINER" innernet \
        add-peer evilcorp \
        --name "legacy-peer" \
        --cidr "humans" \
        --admin false \
        --ip "10.66.1.204" \
        --save-config "/app/legacy_g.toml" \
        --invite-expires "30s" \
        --yes
    cmd docker cp "$PEER1_CONTAINER:/app/legacy_g.toml" "$tmp_dir"

    info "Starting the three peers."
    RP_E_CONTAINER=$(create_peer_docker 172.18.1.8 "" "--enable-rosenpass")
    info "strict Rosenpass peer started as $RP_E_CONTAINER"
    cmd docker cp "$tmp_dir/rp_e.toml" "$RP_E_CONTAINER:/app/invite.toml"
    cmd docker start -a "$RP_E_CONTAINER" | sed -e 's/^/\x1B[0;35mrp-e\x1B[0m: /' &

    RP_F_CONTAINER=$(create_peer_docker 172.18.1.9 "" "--enable-rosenpass --rosenpass-permissive")
    info "permissive Rosenpass peer started as $RP_F_CONTAINER"
    cmd docker cp "$tmp_dir/rp_f.toml" "$RP_F_CONTAINER:/app/invite.toml"
    cmd docker start -a "$RP_F_CONTAINER" | sed -e 's/^/\x1B[0;36mrp-f\x1B[0m: /' &

    LEGACY_G_CONTAINER=$(create_peer_docker 172.18.1.10 "")
    info "legacy (no Rosenpass) peer started as $LEGACY_G_CONTAINER"
    cmd docker cp "$tmp_dir/legacy_g.toml" "$LEGACY_G_CONTAINER:/app/invite.toml"
    cmd docker start -a "$LEGACY_G_CONTAINER" | sed -e 's/^/\x1B[0;33mlegacy\x1B[0m: /' &

    info "Waiting for the permissive peer to reach both the strict peer and the legacy peer."
    wait_until 60 docker exec "$RP_F_CONTAINER" ping -c1 10.66.1.202 \
        || { info "permissive peer never reached the strict Rosenpass peer."; exit 1; }
    wait_until 60 docker exec "$RP_F_CONTAINER" ping -c1 10.66.1.204 \
        || { info "permissive peer never reached the legacy (keyless) peer - fail-open fallback did not work."; exit 1; }

    info "Confirming connectivity is real, not just a single probe packet."
    cmd docker exec "$RP_F_CONTAINER" ping -c3 10.66.1.202
    cmd docker exec "$RP_F_CONTAINER" ping -c3 10.66.1.204

    info "Confirming the strict peer got a real preshared key for its Rosenpass-enabled neighbor."
    local psk_e
    psk_e=$(peer_psk "$RP_E_CONTAINER" 172.18.1.9)
    if [[ -z "$psk_e" || "$psk_e" == "(none)" ]]; then
        info "expected a non-empty preshared key between the two Rosenpass-enabled peers, got: '$psk_e'"
        exit 1
    fi

    info "Confirming strict mode excludes the keyless legacy peer from its own WireGuard interface."
    local legacy_pubkey
    legacy_pubkey=$(docker exec "$LEGACY_G_CONTAINER" wg show evilcorp public-key)
    if docker exec "$RP_E_CONTAINER" wg show evilcorp peers | grep -qF "$legacy_pubkey"; then
        info "expected strict-mode peer to exclude the keyless legacy peer, but found it in its peer list"
        exit 1
    fi
}

# Run tests (functions prefixed with test_) in alphabetical order.
# Optional filter provided by positional arguments is applied.
for func in $(declare -F | awk '{print $3}'); do
    if [[ "$func" =~ ^test_ ]]; then
        if [ ${#TEST_FILTER[@]} -eq 0 ] || [[ "${TEST_FILTER[*]}" =~ "$func" ]]; then
            $func
        fi
    fi
done

echo
info "Test succeeded."
