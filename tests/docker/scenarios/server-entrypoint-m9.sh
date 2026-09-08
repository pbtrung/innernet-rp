#!/bin/sh
# M9 Docker scenario: server side. Provisions a management-required network
# and three peer invitations (A and B under real PQ activation, cooperating
# control peer C), then enables the real PQ mailbox.
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm9

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    "$BIN" new --network-name "$NET" --network-cidr 10.98.0.0/23 \
        --external-endpoint 10.91.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.98.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-a --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-a.toml --yes
    "$BIN" add-peer "$NET" --name peer-b --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-b.toml --yes
    "$BIN" add-peer "$NET" --name peer-c --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-c.toml --yes
    "$BIN" enable-pq "$NET"
fi

exec "$BIN" serve "$NET"
