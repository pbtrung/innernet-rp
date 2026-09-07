use rusqlite::{params, Transaction, TransactionBehavior};

pub mod association;
pub mod cidr;
pub mod peer;
pub mod pq;

pub use association::DatabaseAssociation;
pub use cidr::DatabaseCidr;
pub use peer::DatabasePeer;

const INVITE_EXPIRATION_VERSION: i32 = 1;
const ENDPOINT_CANDIDATES_VERSION: i32 = 2;

pub const CURRENT_VERSION: i32 = 3;

pub fn auto_migrate(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    // Check before taking a write lock, then recheck inside the transaction to
    // serialize concurrent openers. Failure never lowers a version marker.
    let old_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if !(0..=CURRENT_VERSION).contains(&old_version) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let transaction = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let old_version: i32 = transaction.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if !(0..=CURRENT_VERSION).contains(&old_version) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    migrate(&transaction, old_version)?;
    transaction.commit()
}

pub fn create(conn: &rusqlite::Connection) -> Result<(), rusqlite::Error> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    for sql in [
        peer::CREATE_TABLE_SQL,
        association::CREATE_TABLE_SQL,
        cidr::CREATE_TABLE_SQL,
    ] {
        tx.execute(sql, [])?;
    }
    migrate(&tx, 2)?;
    tx.commit()
}

fn migrate(conn: &rusqlite::Connection, old_version: i32) -> Result<(), rusqlite::Error> {
    if old_version < INVITE_EXPIRATION_VERSION {
        conn.execute(
            "ALTER TABLE peers ADD COLUMN invite_expires INTEGER",
            params![],
        )?;
    }

    if old_version < ENDPOINT_CANDIDATES_VERSION {
        conn.execute("ALTER TABLE peers ADD COLUMN candidates TEXT", params![])?;
    }

    if old_version < 3 {
        let invalid: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM peers WHERE id <= 0)",
            [],
            |r| r.get(0),
        )?;
        if invalid {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let network_id = innernet_pq::crypto::random::<16>(&mut innernet_pq::crypto::SystemRandom)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        conn.execute_batch(include_str!("pq_schema.sql"))?;
        conn.execute("INSERT INTO pq_network(singleton, network_id, max_peer_id) VALUES(1, ?1, (SELECT coalesce(max(id),0) FROM peers))", [network_id.0.as_slice()])?;
        for table in ["peers", "cidrs", "associations", "pq_bundles"] {
            for operation in ["INSERT", "UPDATE", "DELETE"] {
                conn.execute_batch(&format!("CREATE TRIGGER pq_visibility_{table}_{operation} AFTER {operation} ON {table}
                    BEGIN UPDATE pq_network SET visibility_revision = visibility_revision + 1 WHERE singleton = 1; END;"))?;
            }
        }
    }

    if old_version != CURRENT_VERSION {
        conn.pragma_update(None, "user_version", CURRENT_VERSION)?;
        log::info!(
            "migrated db version from {} to {}",
            old_version,
            CURRENT_VERSION
        );
    }

    Ok(())
}

#[cfg(test)]
#[path = "pq_migration_tests.rs"]
mod pq_migration_tests;
