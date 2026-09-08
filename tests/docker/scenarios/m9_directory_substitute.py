#!/usr/bin/env python3
"""M9 Docker scenario (design case 10): the "malicious directory" step.

Run directly against the server's SQLite database file (server stopped
first, matching the established pattern for this kind of live-state
edit) to attribute peer-attacker's real, legitimately-generated PQ bundle
to peer-target's directory slot -- simulating a compromised/malicious
directory backend, never a client submitting a fraudulent registration
through the real API (a different, already-covered case). No production
code path is touched or bypassed at request time; this edits durable
state directly, the same technique used elsewhere in this test suite
(e.g. tests/docker/scenarios/m2_management.sh's lost-management-state
simulation).
"""
import os
import secrets
import sqlite3
import sys

db_path = sys.argv[1]
conn = sqlite3.connect(db_path)
conn.execute("PRAGMA foreign_keys = ON")

attacker = conn.execute(
    "SELECT pq_kem_public_key, pq_x448_public_key, pq_sig_public_key, bundle_id "
    "FROM pq_bundles b JOIN peers p ON p.id = b.peer_id WHERE p.name = 'peer-attacker'"
).fetchone()
if attacker is None:
    print("peer-attacker has not registered a real bundle yet", file=sys.stderr)
    sys.exit(1)
kem, x448, sig, attacker_bundle_id = attacker

target_row = conn.execute("SELECT id, public_key FROM peers WHERE name = 'peer-target'").fetchone()
if target_row is None:
    print("peer-target does not exist", file=sys.stderr)
    sys.exit(1)
target_id, target_wg_key_b64 = target_row

import base64
target_wg_key = base64.b64decode(target_wg_key_b64)

# A fresh bundle_id: the directory can attribute any public key material
# to any peer_id, but bundle_id itself is globally unique/foreign-keyed
# to pq_bundle_history, so the substitution needs its own history entry.
substituted_bundle_id = secrets.token_bytes(16)
conn.execute(
    "INSERT INTO pq_bundle_history(bundle_id, peer_id) VALUES (?, ?)",
    (substituted_bundle_id, target_id),
)
conn.execute(
    """
    INSERT INTO pq_bundles(peer_id, pq_version, bundle_id, bundle_revision, wg_public_key,
                            pq_kem_public_key, pq_x448_public_key, pq_sig_public_key, lifecycle)
    VALUES (?, 1, ?, 1, ?, ?, ?, ?, 'enabled')
    """,
    (target_id, substituted_bundle_id, target_wg_key, kem, x448, sig),
)
conn.commit()
conn.close()

print(
    f"substituted peer-target (id={target_id}) with peer-attacker's real PQ public keys "
    f"(attacker's own bundle_id={attacker_bundle_id.hex()}, substituted bundle_id={substituted_bundle_id.hex()})"
)
