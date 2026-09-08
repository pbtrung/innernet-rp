#!/bin/sh
# M9 Docker scenario (design case 14): server side. Provisions
# peer-honest-a/peer-honest-b (the "two previously admitted honest
# exchanges complete within 30 seconds" control, exercised concurrently
# with the flood) and peer-load (the flood driver's own first interface).
# The load driver itself provisions its remaining bulk identities directly
# via m9_load.sh, since the exact count is a script parameter.
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm9l

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    "$BIN" new --network-name "$NET" --network-cidr 10.101.0.0/22 \
        --external-endpoint 10.85.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.101.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-load --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-load.toml --yes
    "$BIN" add-peer "$NET" --name peer-honest-a --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-honest-a.toml --yes
    "$BIN" add-peer "$NET" --name peer-honest-b --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-honest-b.toml --yes
    "$BIN" enable-pq "$NET"
fi

exec "$BIN" serve "$NET"
