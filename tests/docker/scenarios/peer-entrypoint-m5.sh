#!/bin/sh
# M5 Docker scenario: peer side. Installs (same as M4), then runs real
# production `up --enable-pq-psk` with a short, documented test-only
# rotation interval and an idle timeout comfortably above the server's
# hardcoded 25s persistent-keepalive interval (shared::
# PERSISTENT_KEEPALIVE_INTERVAL_SECS -- no per-peer override exists yet),
# so keepalive traffic alone reliably keeps every relationship "active"
# and two full rotation cycles can be observed within a bounded test
# deadline. See m5_inactivity.sh's header for the scoping note on why a
# genuinely idle real-kernel tunnel isn't produced here.
set -eu
BIN=/work/target/debug/innernet
NET=pqm5
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

# A minimal listener on this peer's own overlay address, so the application-
# traffic gate has something real to block/allow.
(
    until ip -4 addr show "$NET" 2>/dev/null | grep -q 'inet '; do sleep 1; done
    exec python3 -m http.server 8080 >/dev/null 2>&1
) &

exec "$BIN" up --enable-pq-psk --pq-psk-rotation-interval 15 --pq-psk-idle-timeout 40 \
    --daemon --interval 2 --no-write-hosts "$NET"
