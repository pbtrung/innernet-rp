#!/bin/sh
# M4 Docker scenario: peer side. Installs (same as M2/M3), then runs real
# production `up --enable-pq-psk`: no dev-harness feature, no hidden
# subcommand -- this is the exact command flow M4 unlocks. A short
# --pq-psk-rotation-interval is passed explicitly (never a hardcoded
# production-constant change) so a Docker-scale test can observe more than
# one rotation without an unreasonable wait, per docs/testing.md's
# deterministic-test-parameters guidance.
set -eu
BIN=/work/target/debug/innernet
NET=pqm4
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
# traffic gate has something real to block/allow (a closed port would be
# indistinguishable from a gated one).
(
    until ip -4 addr show "$NET" 2>/dev/null | grep -q 'inet '; do sleep 1; done
    exec python3 -m http.server 8080 >/dev/null 2>&1
) &

exec "$BIN" up --enable-pq-psk --pq-psk-rotation-interval 10 --daemon --interval 2 \
    --no-write-hosts "$NET"
