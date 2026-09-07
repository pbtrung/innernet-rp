#!/bin/sh
# M2 Docker scenario: peer side. Waits for its invitation (written by the
# server to a shared volume, modeling the confidential out-of-band transfer;
# not evidence that any particular real-world channel is secure), installs
# non-interactively via the real `innernet` binary, then stays up polling.
set -eu
BIN=/work/target/debug/innernet
NET=pqm2
NAME=$1

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

exec "$BIN" up --daemon --interval 5 --no-write-hosts "$NET"
