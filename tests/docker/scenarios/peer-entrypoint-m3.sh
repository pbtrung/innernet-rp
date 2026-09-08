#!/bin/sh
# M3 Docker scenario: peer side. Installs (same as M2), then drives one real
# data-peer PQ rotation against $2 via the hidden pq-dev-harness subcommand
# (a fake installer only -- no real WireGuard state is touched), writing the
# resulting PSK to a shared file the host driver compares between peers.
set -eu
BIN=/work/target/debug/innernet
NET=pqm3
NAME=$1
OTHER_PEER_ID=$2

if [ ! -f "/etc/innernet/${NET}.conf" ]; then
    tries=0
    while [ ! -f "/invites/${NAME}.toml" ]; do
        tries=$((tries + 1))
        if [ "$tries" -gt 60 ]; then
            echo "invitation for ${NAME} never appeared" >&2
            exit 1
        fi
        sleep 1
    done

    tries=0
    until "$BIN" install "/invites/${NAME}.toml" --default-name --delete-invite --no-write-hosts; do
        tries=$((tries + 1))
        if [ "$tries" -gt 30 ]; then
            echo "install for ${NAME} never succeeded" >&2
            exit 1
        fi
        sleep 2
    done
fi

"$BIN" pq-dev-rotate "$NET" "$OTHER_PEER_ID" --timeout-secs 60 --rotation-interval 5 \
    > "/invites/psk-${NAME}.txt"
cat "/invites/psk-${NAME}.txt"

exec "$BIN" up --daemon --interval 5 --no-write-hosts "$NET"
