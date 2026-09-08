#!/bin/sh
# M7 Docker scenario: peer side. Identical to M2's peer-entrypoint.sh --
# installs from its invitation, then stays up polling. M7's host driver runs
# the new client-side rotation subcommands against this same running
# `up --daemon` process's private state via `docker compose exec`.
set -eu
BIN=/work/target/debug/innernet
NET=pqm7
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
