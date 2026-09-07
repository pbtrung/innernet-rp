CREATE TABLE pq_network (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    network_id BLOB NOT NULL CHECK(length(network_id) = 16),
    visibility_revision INTEGER NOT NULL DEFAULT 1 CHECK(typeof(visibility_revision) = 'integer' AND visibility_revision > 0),
    swept_visibility_revision INTEGER NOT NULL DEFAULT 0,
    max_peer_id INTEGER NOT NULL DEFAULT 0 CHECK(max_peer_id >= 0),
    enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
    management_ready INTEGER NOT NULL DEFAULT 0 CHECK(management_ready IN (0,1))
);
ALTER TABLE peers ADD COLUMN is_server INTEGER NOT NULL DEFAULT 0 CHECK(is_server IN (0,1));
CREATE UNIQUE INDEX one_server_role ON peers(is_server) WHERE is_server = 1;
CREATE TABLE pq_bundle_history (
    bundle_id BLOB PRIMARY KEY CHECK(length(bundle_id) = 16),
    peer_id INTEGER NOT NULL CHECK(peer_id > 0)
) WITHOUT ROWID;
CREATE TABLE pq_bundles (
    peer_id INTEGER PRIMARY KEY REFERENCES peers(id) ON DELETE CASCADE,
    pq_version INTEGER NOT NULL CHECK(pq_version = 1),
    bundle_id BLOB NOT NULL UNIQUE REFERENCES pq_bundle_history(bundle_id),
    bundle_revision INTEGER NOT NULL CHECK(bundle_revision > 0),
    wg_public_key BLOB NOT NULL CHECK(length(wg_public_key) = 32),
    pq_kem_public_key BLOB NOT NULL CHECK(length(pq_kem_public_key) = 1568),
    pq_x448_public_key BLOB NOT NULL CHECK(length(pq_x448_public_key) = 56),
    pq_sig_public_key BLOB NOT NULL CHECK(length(pq_sig_public_key) = 67),
    lifecycle TEXT NOT NULL CHECK(lifecycle IN ('enabled', 'retired'))
);
CREATE TABLE pq_exchanges (
    initiator_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    responder_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    initiator_bundle_id BLOB NOT NULL CHECK(length(initiator_bundle_id) = 16),
    responder_bundle_id BLOB NOT NULL CHECK(length(responder_bundle_id) = 16),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    prepare_expires_at INTEGER NOT NULL,
    record TEXT NOT NULL CHECK(length(record) <= 32768 AND json_valid(record)),
    PRIMARY KEY(initiator_id, responder_id, initiator_bundle_id, responder_bundle_id),
    CHECK(initiator_id > 0 AND initiator_id < responder_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX one_active_exchange_per_pair
    ON pq_exchanges(initiator_id, responder_id) WHERE active = 1;
CREATE INDEX pq_responder_delivery ON pq_exchanges(responder_id, initiator_id);
CREATE INDEX pq_active_expiry ON pq_exchanges(active, prepare_expires_at);
CREATE INDEX pq_prepare_expiry ON pq_exchanges(prepare_expires_at)
    WHERE active = 1 AND json_extract(record, '$.decision.phase') IN ('proposed', 'ready');
CREATE TRIGGER pq_no_reused_peer_id BEFORE INSERT ON peers
WHEN NEW.id <= (SELECT max_peer_id FROM pq_network WHERE singleton = 1)
BEGIN SELECT RAISE(ABORT, 'peer IDs cannot be reused'); END;
CREATE TRIGGER pq_track_peer_id AFTER INSERT ON peers
BEGIN UPDATE pq_network SET max_peer_id = NEW.id WHERE singleton = 1; END;
CREATE TRIGGER pq_immutable_peer_id BEFORE UPDATE OF id ON peers WHEN NEW.id != OLD.id
BEGIN SELECT RAISE(ABORT, 'peer IDs are immutable'); END;
