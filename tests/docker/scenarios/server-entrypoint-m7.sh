#!/bin/sh
# M7 Docker scenario: server side. Provisions a management-required network
# and two peer invitations, exactly like M2's server-entrypoint.sh -- M7's
# host driver runs the new rotation subcommands against this same live
# `serve` process via `docker compose exec`, the same way `add-peer`/
# `enable-peer` already operate against a running server.
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm7

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    "$BIN" new --network-name "$NET" --network-cidr 10.96.0.0/23 \
        --external-endpoint 10.95.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.96.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-a --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-a.toml --yes
    "$BIN" add-peer "$NET" --name peer-b --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-b.toml --yes
fi

exec "$BIN" serve "$NET"
