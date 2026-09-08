#!/bin/sh
# M3 Docker scenario: server side. Provisions a management-required network
# and two peer invitations non-interactively (same shape as M2's setup),
# then serves with the pq-dev-harness feature's PQ mailbox service enabled.
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm3

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    # A hostname here would need working container DNS resolution, which
    # `internal: true` bridge networks do not reliably provide; the static
    # address is already fixed by the compose file.
    "$BIN" new --network-name "$NET" --network-cidr 10.98.0.0/23 \
        --external-endpoint 10.89.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.98.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-a --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-a.toml --yes
    "$BIN" add-peer "$NET" --name peer-b --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-b.toml --yes
    # No CLI path sets this yet (that's the real --enable-pq-psk activation,
    # still gated pre-M4); this dev-only scenario flips it directly, exactly
    # like the crate's own pq_api_* test fixtures do.
    sqlite3 "/var/lib/innernet-server/${NET}.db" "UPDATE pq_network SET enabled = 1"
fi

exec "$BIN" serve "$NET"
