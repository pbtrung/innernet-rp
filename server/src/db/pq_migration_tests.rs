use super::*;
use rusqlite::Connection;

fn legacy(path: &std::path::Path, version: i32) -> Connection {
    let conn = Connection::open(path).unwrap();
    for sql in [
        peer::CREATE_TABLE_SQL,
        association::CREATE_TABLE_SQL,
        cidr::CREATE_TABLE_SQL,
    ] {
        conn.execute(sql, []).unwrap();
    }
    if version < 2 {
        conn.execute("ALTER TABLE peers DROP COLUMN candidates", [])
            .unwrap();
    }
    if version < 1 {
        conn.execute("ALTER TABLE peers DROP COLUMN invite_expires", [])
            .unwrap();
    }
    conn.pragma_update(None, "user_version", version).unwrap();
    conn
}

#[test]
fn pq_migrations_are_atomic_reopenable_and_reject_newer_without_writes() {
    for version in 0..=2 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let backup = dir.path().join("backup.db");
        let conn = legacy(&path, version);
        drop(conn);
        std::fs::copy(&path, &backup).unwrap();
        let conn = Connection::open(&path).unwrap();
        auto_migrate(&conn).unwrap();
        let id = pq::network(&conn).unwrap().0;
        assert!(!pq::ready(&conn).unwrap());
        assert_eq!(
            conn.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))
                .unwrap(),
            CURRENT_VERSION
        );
        drop(conn);
        let conn = Connection::open(&path).unwrap();
        auto_migrate(&conn).unwrap();
        assert_eq!(pq::network(&conn).unwrap().0, id);
        let backup = Connection::open(backup).unwrap();
        assert_eq!(
            backup
                .pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))
                .unwrap(),
            version
        );
        conn.pragma_update(None, "user_version", CURRENT_VERSION + 1)
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert!(auto_migrate(&conn).is_err());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }
}

#[test]
fn pq_migration_failure_rolls_back_columns_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let conn = legacy(&dir.path().join("failed.db"), 0);
    conn.execute("CREATE TABLE pq_network(sentinel INTEGER)", [])
        .unwrap();
    assert!(auto_migrate(&conn).is_err());
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))
            .unwrap(),
        0
    );
    let names: Vec<String> = conn
        .prepare("SELECT name FROM pragma_table_info('peers')")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for name in ["invite_expires", "candidates", "is_server"] {
        assert!(!names.iter().any(|n| n == name));
    }
}

#[test]
fn pq_stable_peer_ids_server_role_and_revision_overflow_fail_closed() {
    let server = crate::test::Server::new().unwrap();
    let conn = server.db.lock();
    let last = DatabasePeer::get(&conn, crate::test::USER2_PEER_ID).unwrap();
    conn.execute("DELETE FROM peers WHERE id = ?1", [last.id])
        .unwrap();
    let next = DatabasePeer::create(&conn, last.contents.clone()).unwrap();
    assert!(next.id > last.id);
    let key = crate::ConfigFile::from_file(server.wg_conf_path()).unwrap();
    let public = wireguard_control::Key::from_base64(&key.private_key)
        .unwrap()
        .get_public();
    assert!(conn
        .execute("UPDATE peers SET id = 99 WHERE is_server = 1", [])
        .is_err());
    assert_eq!(
        pq::identify_server(&conn, &public.to_base64(), key.address).unwrap(),
        1
    );
    assert!(pq::pair_allowed(&conn, 1, crate::test::DEVELOPER1_PEER_ID).is_err());
    conn.execute("UPDATE pq_network SET visibility_revision = ?1", [i64::MAX])
        .unwrap();
    assert!(conn
        .execute(
            "UPDATE peers SET name = 'overflow' WHERE id = ?1",
            [next.id]
        )
        .is_err());
    assert_eq!(DatabasePeer::get(&conn, next.id).unwrap().name, next.name);
    conn.execute(
        "UPDATE pq_network SET visibility_revision = 1, max_peer_id = ?1",
        [i64::MAX],
    )
    .unwrap();
    conn.execute("DELETE FROM peers WHERE id = ?1", [next.id])
        .unwrap();
    assert!(DatabasePeer::create(&conn, next.contents.clone()).is_err());
}

#[test]
fn pq_migrated_server_role_uses_identity_not_peer_number() {
    let dir = tempfile::tempdir().unwrap();
    let conn = legacy(&dir.path().join("server-99.db"), 2);
    let key = wireguard_control::Key::generate_private().get_public();
    conn.execute("INSERT INTO peers(id, name, ip, public_key, cidr_id, is_redeemed) VALUES(99, 'server', '10.42.0.1', ?1, 1, 1)", [key.to_base64()]).unwrap();
    auto_migrate(&conn).unwrap();
    assert_eq!(
        pq::identify_server(&conn, &key.to_base64(), "10.42.0.1".parse().unwrap()).unwrap(),
        99
    );
    assert!(pq::is_server(&conn, 99).unwrap());
}
