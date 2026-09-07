#!/bin/sh
# M2 Docker scenario: server side. Provisions a management-required network
# and two peer invitations non-interactively, exactly as an operator would
# via the real `innernet-server` binary (no test-only entrypoint exists;
# management-link provisioning never depended on --enable-pq-psk).
set -eu
BIN=/work/target/debug/innernet-server
NET=pqm2

if [ ! -f "/etc/innernet-server/${NET}.conf" ]; then
    # A hostname here would need working container DNS resolution, which
    # `internal: true` bridge networks do not reliably provide; the static
    # address is already fixed by the compose file.
    "$BIN" new --network-name "$NET" --network-cidr 10.99.0.0/23 \
        --external-endpoint 10.88.0.2:51820 --listen-port 51820
    "$BIN" require-management "$NET" --independent-admin-access
    "$BIN" add-cidr "$NET" --name peers --cidr 10.99.1.0/24 --parent "$NET" --yes
    "$BIN" add-peer "$NET" --name peer-a --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-a.toml --yes
    "$BIN" add-peer "$NET" --name peer-b --auto-ip --cidr peers --admin false \
        --invite-expires 30d --save-config /invites/peer-b.toml --yes
fi

# A minimal listener on an unrelated port, bound only to the overlay address,
# so the ACL negative test has something real to fail against (a closed port
# would be indistinguishable from a dropped one).
(
    until ip -4 addr show "$NET" 2>/dev/null | grep -q 'inet '; do sleep 1; done
    exec python3 -m http.server 8080 --bind 10.99.0.1 >/dev/null 2>&1
) &

exec "$BIN" serve "$NET"
