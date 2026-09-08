#!/bin/sh
# M6 Docker scenario: a fully-capable binary that simply never passes
# --enable-pq-psk. It correctly adopts the management-link PSK like any
# other peer (management is required on this network), which isolates the
# strict/permissive legacy-eligibility question from anything else. From
# the PQ engine's perspective this is indistinguishable from a peer that
# has never advertised a PQ bundle: legacy eligibility only ever checks
# whether a bundle is currently advertised, never why it is absent.
set -eu
BIN=/work/target/debug/innernet
NET=pqm6
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

(
    until ip -4 addr show "$NET" 2>/dev/null | grep -q 'inet '; do sleep 1; done
    exec python3 -m http.server 8080 >/dev/null 2>&1
) &

exec "$BIN" up --daemon --interval 2 --no-write-hosts "$NET"
