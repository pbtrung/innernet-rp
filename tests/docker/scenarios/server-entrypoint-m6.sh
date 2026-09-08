#!/bin/sh
# M6 Docker scenario 2/2: server side. Provisions a management-required
# network and three peer invitations (a fully-capable new binary that
# never opts into PQ, a permissive new-binary peer, a strict new-binary
# peer), then enables the real PQ mailbox. Same real provisioning shape as
# M4/M5.
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm6

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    "$BIN" new --network-name "$NET" --network-cidr 10.97.0.0/23 \
        --external-endpoint 10.93.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.97.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-legacy --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-legacy.toml --yes
    "$BIN" add-peer "$NET" --name peer-permissive --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-permissive.toml --yes
    "$BIN" add-peer "$NET" --name peer-strict --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-strict.toml --yes
    "$BIN" enable-pq "$NET"
fi

exec "$BIN" serve "$NET"
