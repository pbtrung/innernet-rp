#!/bin/sh
# M6 Docker scenario: real new-binary peer, real production --enable-pq-psk
# activation, with an optional extra policy flag ($2, e.g.
# --pq-psk-permissive; empty for strict).
set -eu
BIN=/work/target/debug/innernet
NET=pqm6
NAME=$1
EXTRA_FLAG=${2:-}

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

(
    until ip -4 addr show "$NET" 2>/dev/null | grep -q 'inet '; do sleep 1; done
    exec python3 -m http.server 8080 >/dev/null 2>&1
) &

if [ -n "$EXTRA_FLAG" ]; then
    exec "$BIN" up --enable-pq-psk "$EXTRA_FLAG" --pq-psk-rotation-interval 15 \
        --daemon --interval 2 --no-write-hosts "$NET"
else
    exec "$BIN" up --enable-pq-psk --pq-psk-rotation-interval 15 \
        --daemon --interval 2 --no-write-hosts "$NET"
fi
