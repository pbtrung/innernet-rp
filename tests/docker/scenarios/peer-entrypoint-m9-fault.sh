#!/bin/sh
# M9 Docker scenario: the fault-injected peer. Installs normally, then
# starts fault_proxy.py and rewrites this interface's own
# InterfaceConfig.server.internal-endpoint to point at it (127.0.0.1) --
# every subsequent real HTTP request from this peer's real client process
# still crosses this peer's real, already-up WireGuard tunnel, only the
# last hop is relayed. Never touches production code paths.
set -eu
BIN=/work/target/debug/innernet
NET=pqm9
NAME=$1
CONF="/etc/innernet/${NET}.conf"
PROXY_PORT=17171

if [ ! -f "$CONF" ]; then
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

    real_endpoint="$(grep -oE 'internal-endpoint = "[^"]+"' "$CONF" | sed -E 's/.*"([^"]+)"/\1/')"
    [ -n "$real_endpoint" ] || { echo "could not find internal-endpoint in $CONF" >&2; exit 1; }

    REAL_SERVER="$real_endpoint" LISTEN_PORT="$PROXY_PORT" \
        FAULT_MODE="${FAULT_MODE:-}" FAULT_MATCH="${FAULT_MATCH:-}" FAULT_COUNT="${FAULT_COUNT:-1}" \
        python3 /fault_proxy.py &

    tries=0
    until python3 -c "import socket; socket.create_connection(('127.0.0.1', $PROXY_PORT), timeout=1).close()" 2>/dev/null; do
        tries=$((tries + 1))
        if [ "$tries" -gt 30 ]; then
            echo "fault proxy never came up" >&2
            exit 1
        fi
        sleep 1
    done

    sed -i "s#internal-endpoint = \"${real_endpoint}\"#internal-endpoint = \"127.0.0.1:${PROXY_PORT}\"#" "$CONF"
else
    # A container restart: the proxy must be running again before `up`
    # tries to use it, but we no longer know the real endpoint (the conf
    # file now points at the proxy). Fault scenarios in this milestone
    # never restart peer-b mid-run, so this path is not exercised.
    echo "unexpected: ${CONF} already exists on a fresh fault-peer container" >&2
    exit 1
fi

(
    until ip -4 addr show "$NET" 2>/dev/null | grep -q 'inet '; do sleep 1; done
    exec python3 -m http.server 8080 >/dev/null 2>&1
) &

exec "$BIN" up --enable-pq-psk --pq-psk-rotation-interval 10 --daemon --interval 2 \
    --no-write-hosts "$NET"
