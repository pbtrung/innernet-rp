#!/bin/sh
# M9 Docker scenario (design case 10): server side. Provisions
# peer-attacker (registers a real PQ bundle), peer-target (installs, so
# its directory slot becomes visible, but never enables PQ -- see
# peer-entrypoint-m9-plain.sh -- so its own bundle slot stays empty until
# m9_directory.sh's substitution), and peer-observer (installs last, after
# the substitution).
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm9d

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    "$BIN" new --network-name "$NET" --network-cidr 10.100.0.0/23 \
        --external-endpoint 10.94.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.100.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-attacker --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-attacker.toml --yes
    "$BIN" add-peer "$NET" --name peer-target --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-target.toml --yes
    "$BIN" add-peer "$NET" --name peer-observer --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-observer.toml --yes
    "$BIN" enable-pq "$NET"
fi

exec "$BIN" serve "$NET"
