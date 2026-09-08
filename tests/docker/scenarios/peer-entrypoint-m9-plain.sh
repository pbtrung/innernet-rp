#!/bin/sh
# M9 Docker scenario (design case 10): peer-target's entrypoint. Installs
# (redeeming its invite, becoming visible to other peers -- an unredeemed
# invite's peer_id is entirely invisible in the directory, confirmed while
# building this scenario) but never passes --enable-pq-psk, so it never
# registers a real PQ bundle of its own. This is exactly the "no real
# bundle exists yet for this now-visible peer_id" precondition
# m9_directory.sh needs before substituting one via direct database edit.
set -eu
BIN=/work/target/debug/innernet
NET="${NET:-pqm9}"
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

exec "$BIN" up --daemon --interval 2 --no-write-hosts "$NET"
