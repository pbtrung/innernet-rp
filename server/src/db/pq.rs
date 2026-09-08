//! Transactional mailbox: public material only, non-consuming delivery.
use crate::{db::DatabasePeer, pq::Limits, ServerError};
use innernet_pq::{
    api::{AdvertisedBundle, Exchange, Lifecycle, MessageDigest, Registration},
    crypto,
    protocol::{Binary, Bundle, Decision, Kind, Message, Number, Phase, Transcript, PREPARE_TTL},
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

pub fn network(conn: &Connection) -> Result<(Binary<16>, i64), ServerError> {
    let (bytes, revision): (Vec<u8>, i64) = conn.query_row(
        "SELECT network_id, visibility_revision FROM pq_network WHERE singleton = 1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok((
        Binary(bytes.try_into().map_err(|_| ServerError::Unavailable)?),
        revision,
    ))
}

pub fn ready(conn: &Connection) -> Result<bool, ServerError> {
    Ok(conn.query_row(
        "SELECT enabled = 1 AND management_ready = 1 AND
        (SELECT count(*) FROM peers WHERE is_server = 1 AND is_disabled = 0 AND is_redeemed = 1) = 1
        FROM pq_network WHERE singleton = 1",
        [],
        |r| r.get(0),
    )?)
}

/// Durably records that every currently enabled peer has a provisioned
/// management link. Never cleared automatically: a subsequently added peer
/// without a link fails closed through `management::Manager::load` instead
/// of silently reporting stale readiness.
pub fn set_management_ready(conn: &Connection, ready: bool) -> Result<(), ServerError> {
    conn.execute(
        "UPDATE pq_network SET management_ready = ?1 WHERE singleton = 1",
        [ready],
    )?;
    Ok(())
}

/// Enables the post-quantum data-peer PSK mailbox for this network. Refuses
/// before the management-only link is already required and ready: real
/// production activation must never claim strict data-peer protection
/// without an already-independent recovery channel in place first (design
/// 5.3/5.10; the milestones.md preamble's "management-link provisioning
/// moves into M2 so that recovery is available before M4 applies any data
/// PSK"). `enabled` alone does not make `db::pq::ready()` true: that also
/// requires a registered, non-disabled server peer.
pub fn enable(conn: &Connection) -> Result<(), ServerError> {
    let management_ready: bool = conn.query_row(
        "SELECT management_ready FROM pq_network WHERE singleton = 1",
        [],
        |r| r.get(0),
    )?;
    if !management_ready {
        return Err(ServerError::InvalidQuery);
    }
    conn.execute("UPDATE pq_network SET enabled = 1 WHERE singleton = 1", [])?;
    Ok(())
}

/// Infer a migrated server role only from both the persisted private-key public
/// identity and address, never from the numeric peer ID.
pub fn identify_server(
    conn: &Connection,
    public_key: &str,
    address: std::net::IpAddr,
) -> Result<i64, ServerError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    let id: i64 = tx.query_row("SELECT id FROM peers WHERE public_key = ?1 AND ip = ?2 AND is_disabled = 0 AND is_redeemed = 1",
        params![public_key, address.to_string()], |r| r.get(0))?;
    let prior: Option<i64> = tx
        .query_row("SELECT id FROM peers WHERE is_server = 1", [], |r| r.get(0))
        .optional()?;
    if prior.is_some_and(|prior| prior != id) {
        return Err(ServerError::Conflict);
    }
    tx.execute(
        "UPDATE peers SET is_server = 1 WHERE id = ?1 AND is_server = 0",
        [id],
    )?;
    tx.commit()?;
    Ok(id)
}

pub fn is_server(conn: &Connection, id: i64) -> Result<bool, ServerError> {
    Ok(
        conn.query_row("SELECT is_server FROM peers WHERE id = ?1", [id], |r| {
            r.get(0)
        })?,
    )
}

pub fn caller(conn: &Connection, id: i64, key: &str) -> Result<DatabasePeer, ServerError> {
    let peer = DatabasePeer::get(conn, id)?;
    if peer.is_disabled || !peer.is_redeemed || peer.public_key != key {
        return Err(ServerError::Unauthorized);
    }
    Ok(peer)
}

pub fn pair_allowed(conn: &Connection, first: i64, second: i64) -> Result<(), ServerError> {
    if first <= 0
        || second <= 0
        || first == second
        || is_server(conn, first)?
        || is_server(conn, second)?
    {
        return Err(ServerError::Unauthorized);
    }
    let a = DatabasePeer::get(conn, first)?;
    let b = DatabasePeer::get(conn, second)?;
    if a.is_disabled
        || b.is_disabled
        || !a.is_redeemed
        || !b.is_redeemed
        || !a
            .get_all_allowed_peers(conn)?
            .iter()
            .any(|p| p.id == second)
        || !b.get_all_allowed_peers(conn)?.iter().any(|p| p.id == first)
    {
        return Err(ServerError::Unauthorized);
    }
    Ok(())
}

pub fn bundle(conn: &Connection, peer: i64) -> Result<Option<AdvertisedBundle>, ServerError> {
    // An absent row represents all nullable fields being absent. SQL NOT NULL /
    // length constraints prevent partially registered rows.
    type Row = (u8, Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String);
    let row: Option<Row> = conn.query_row("SELECT pq_version, bundle_id, bundle_revision, wg_public_key,
        pq_kem_public_key, pq_x448_public_key, pq_sig_public_key, lifecycle FROM pq_bundles WHERE peer_id = ?1",
        [peer], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?))).optional()?;
    row.map(|(version, id, revision, wg, kem, x448, sig, lifecycle)| {
        fn bytes<const N: usize>(value: Vec<u8>) -> Result<Binary<N>, ServerError> {
            Ok(Binary(
                value.try_into().map_err(|_| ServerError::Unavailable)?,
            ))
        }
        let bundle = Bundle {
            bundle_id: bytes(id)?,
            bundle_revision: Number::new(revision as u64)?,
            wg_public_key: bytes(wg)?,
            pq_kem_public_key: bytes(kem)?,
            pq_x448_public_key: bytes(x448)?,
            pq_sig_public_key: bytes(sig)?,
        };
        bundle.validate()?;
        let lifecycle = match lifecycle.as_str() {
            "enabled" => Lifecycle::Enabled,
            "retired" => Lifecycle::Retired,
            _ => return Err(ServerError::Unavailable),
        };
        if version != 1 {
            return Err(ServerError::Unavailable);
        }
        Ok(AdvertisedBundle {
            pq_version: version,
            lifecycle,
            bundle,
        })
    })
    .transpose()
}

fn active_bundle(conn: &Connection, peer: i64) -> Result<Bundle, ServerError> {
    let advertised = bundle(conn, peer)?.ok_or(ServerError::Conflict)?;
    if advertised.lifecycle != Lifecycle::Enabled {
        return Err(ServerError::Conflict);
    }
    let current = DatabasePeer::get(conn, peer)?;
    let wg = wireguard_control::Key::from_base64(&current.public_key)
        .map_err(|_| ServerError::Conflict)?;
    if wg.as_bytes() != advertised.bundle.wg_public_key.0 {
        return Err(ServerError::Conflict);
    }
    Ok(advertised.bundle)
}

fn budget(conn: &Connection, limits: &Limits, new_bundle: bool) -> Result<(), ServerError> {
    let pages: u64 =
        conn.pragma_query_value(None, "page_count", |r| r.get::<_, i64>(0).map(|v| v as u64))?;
    let page_size: u64 =
        conn.pragma_query_value(None, "page_size", |r| r.get::<_, i64>(0).map(|v| v as u64))?;
    let peers: u32 = conn.query_row("SELECT count(*) FROM peers", [], |r| r.get(0))?;
    let bundles: u32 =
        conn.query_row("SELECT count(*) FROM pq_bundle_history", [], |r| r.get(0))?;
    if pages.saturating_mul(page_size).saturating_add(32768)
        > limits.database_bytes - limits.recovery_reserve_bytes
        || peers > limits.peer_ids
        || bundles > limits.bundle_ids
        || (new_bundle && bundles == limits.bundle_ids)
    {
        return Err(ServerError::RateLimited);
    }
    Ok(())
}

pub fn register(
    conn: &Connection,
    id: i64,
    key: &str,
    request: &Registration,
    limits: &Limits,
    now: u64,
) -> Result<AdvertisedBundle, ServerError> {
    write(conn, now, |tx| register_inner(tx, id, key, request, limits))
}

/// Expiry/revocation and the write serialize under one lock, but rejecting the
/// write rolls back only its savepoint, never the already due terminal outcome.
fn write<T>(
    conn: &Connection,
    now: u64,
    operation: impl FnOnce(&Connection) -> Result<T, ServerError>,
) -> Result<T, ServerError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    sweep_inner(&tx, now)?;
    tx.execute_batch("SAVEPOINT pq_write")?;
    let result = operation(&tx);
    if result.is_err() {
        tx.execute_batch("ROLLBACK TO pq_write")?;
    }
    tx.execute_batch("RELEASE pq_write")?;
    tx.commit()?;
    result
}

fn register_inner(
    tx: &Connection,
    id: i64,
    key: &str,
    request: &Registration,
    limits: &Limits,
) -> Result<AdvertisedBundle, ServerError> {
    if !ready(tx)? {
        return Err(ServerError::Unavailable);
    }
    caller(tx, id, key)?;
    if is_server(tx, id)? {
        return Err(ServerError::Unauthorized);
    }
    let current = bundle(tx, id)?;
    let desired = AdvertisedBundle {
        pq_version: request.pq_version,
        lifecycle: request.lifecycle.clone(),
        bundle: request.bundle.clone(),
    };
    request.bundle.validate()?;
    if request.pq_version != 1
        || (request.emergency && request.lifecycle != Lifecycle::Retired)
        || wireguard_control::Key::from_base64(key)
            .map_err(|_| ServerError::InvalidQuery)?
            .as_bytes()
            != request.bundle.wg_public_key.0
    {
        return Err(ServerError::InvalidQuery);
    }
    // A lost successful reply is an identical CAS retry, not a fresh revision.
    let next = request
        .expected_revision
        .map(Number::next)
        .transpose()?
        .unwrap_or(Number::new(1)?);
    if request.bundle.bundle_revision != next {
        return Err(ServerError::Conflict);
    }
    if current.as_ref() == Some(&desired) {
        return Ok(desired);
    }
    if current.as_ref().map(|b| b.bundle.bundle_revision) != request.expected_revision {
        return Err(ServerError::Conflict);
    }
    let active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM pq_exchanges WHERE active = 1 AND (initiator_id = ?1 OR responder_id = ?1))", [id], |r| r.get(0))?;
    if active && !(request.emergency && request.lifecycle == Lifecycle::Retired) {
        return Err(ServerError::Conflict);
    }
    match request.lifecycle {
        Lifecycle::Enabled => {
            budget(tx, limits, true)?;
            if current
                .as_ref()
                .is_some_and(|b| b.bundle.bundle_id == request.bundle.bundle_id)
            {
                return Err(ServerError::Conflict);
            }
            let reused: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM pq_bundle_history WHERE bundle_id = ?1)",
                [request.bundle.bundle_id.0.as_slice()],
                |r| r.get(0),
            )?;
            if reused {
                return Err(ServerError::Conflict);
            }
            tx.execute(
                "INSERT INTO pq_bundle_history(bundle_id, peer_id) VALUES(?1, ?2)",
                params![request.bundle.bundle_id.0.as_slice(), id],
            )?;
        },
        Lifecycle::Retired => {
            let current = current.as_ref().ok_or(ServerError::Conflict)?;
            let mut prior = current.bundle.clone();
            prior.bundle_revision = next;
            if prior != request.bundle {
                return Err(ServerError::Conflict);
            }
            terminate_peer(tx, id, "retired")?;
        },
    }
    let b = &request.bundle;
    tx.execute("INSERT INTO pq_bundles(peer_id, pq_version, bundle_id, bundle_revision, wg_public_key, pq_kem_public_key,
        pq_x448_public_key, pq_sig_public_key, lifecycle) VALUES(?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(peer_id) DO UPDATE SET bundle_id=excluded.bundle_id, bundle_revision=excluded.bundle_revision,
        wg_public_key=excluded.wg_public_key, pq_kem_public_key=excluded.pq_kem_public_key,
        pq_x448_public_key=excluded.pq_x448_public_key, pq_sig_public_key=excluded.pq_sig_public_key, lifecycle=excluded.lifecycle",
        params![id, b.bundle_id.0.as_slice(), b.bundle_revision.get() as i64, b.wg_public_key.0.as_slice(),
            b.pq_kem_public_key.0.as_slice(), b.pq_x448_public_key.0.as_slice(), b.pq_sig_public_key.0.as_slice(),
            if request.lifecycle == Lifecycle::Enabled { "enabled" } else { "retired" }])?;
    // Old generations are irrevocably retired, so their large/history rows may
    // be removed; the non-reusable bundle-ID registry remains.
    tx.execute(
        "DELETE FROM pq_exchanges WHERE active = 0 AND (initiator_id = ?1 OR responder_id = ?1)",
        [id],
    )?;
    Ok(desired)
}

pub fn load_pair(conn: &Connection, first: i64, second: i64) -> Result<Vec<Exchange>, ServerError> {
    let mut statement = conn.prepare("SELECT record FROM pq_exchanges WHERE initiator_id = ?1 AND responder_id = ?2 ORDER BY initiator_bundle_id, responder_bundle_id")?;
    let records = statement
        .query_map(params![first.min(second), first.max(second)], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    records
        .iter()
        .map(|r| serde_json::from_str(r).map_err(Into::into))
        .collect()
}

pub fn save(conn: &Connection, record: &Exchange) -> Result<(), ServerError> {
    conn.execute("INSERT INTO pq_exchanges(initiator_id, responder_id, initiator_bundle_id, responder_bundle_id, sequence, active, prepare_expires_at, record)
        VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(initiator_id,responder_id,initiator_bundle_id,responder_bundle_id)
        DO UPDATE SET sequence=excluded.sequence, active=excluded.active, prepare_expires_at=excluded.prepare_expires_at, record=excluded.record",
        params![record.initiator_id.get() as i64, record.responder_id.get() as i64, record.initiator_bundle_id.0.as_slice(), record.responder_bundle_id.0.as_slice(),
            record.sequence.get() as i64, !record.decision.terminal(), i64::try_from(record.prepare_expires_at).map_err(|_| ServerError::InvalidQuery)?, serde_json::to_string(record)?])?;
    Ok(())
}

pub fn submit(
    conn: &Connection,
    id: i64,
    key: &str,
    other: i64,
    message: &Message,
    limits: &Limits,
    now: u64,
) -> Result<Exchange, ServerError> {
    write(conn, now, |tx| {
        submit_inner(tx, id, key, other, message, limits, now)
    })
}

fn submit_inner(
    tx: &Connection,
    id: i64,
    key: &str,
    other: i64,
    message: &Message,
    limits: &Limits,
    now: u64,
) -> Result<Exchange, ServerError> {
    if !ready(tx)? {
        return Err(ServerError::Unavailable);
    }
    caller(tx, id, key)?;
    pair_allowed(tx, id, other)?;
    let kind = message.validate_shape()?;
    if message.sender_id.get() != id as u64
        || message.initiator_id.get() != id.min(other) as u64
        || message.responder_id.get() != id.max(other) as u64
    {
        return Err(ServerError::Unauthorized);
    }
    let (network_id, _) = network(tx)?;
    let first = active_bundle(tx, id.min(other))?;
    let second = active_bundle(tx, id.max(other))?;
    if message.network_id != network_id
        || message.initiator_bundle_id != first.bundle_id
        || message.responder_bundle_id != second.bundle_id
    {
        return Err(ServerError::Conflict);
    }
    let mut records = load_pair(tx, id, other)?;
    let digest = MessageDigest::of(message)?;
    if let Some(record) = records.iter_mut().find(|r| {
        r.initiator_bundle_id == first.bundle_id && r.responder_bundle_id == second.bundle_id
    }) {
        if message.sequence < record.sequence {
            return Err(ServerError::Conflict);
        }
        if message.sequence == record.sequence {
            if message.exchange_id != record.exchange_id
                || message.transcript_hash != record.transcript_hash
            {
                return Err(ServerError::Conflict);
            }
            if record.receipts.contains(&digest) {
                return Ok(record.clone());
            }
            if record.decision.terminal()
                || record.receipts.iter().any(|r| {
                    r.sender_id == message.sender_id && r.message_type == message.message_type
                })
            {
                return Err(ServerError::Conflict);
            }
            let transcript = record.transcript.as_ref().ok_or(ServerError::Unavailable)?;
            message.authenticate(transcript)?;
            record.decision.advance(kind, id < other)?;
            record.messages.push(message.clone());
            record.receipts.push(digest);
            record.compact();
            save(tx, record)?;
            return Ok(record.clone());
        }
    }
    if kind != Kind::Propose || records.iter().any(|r| !r.decision.terminal()) {
        return Err(ServerError::Conflict);
    }
    budget(tx, limits, false)?;
    let global: u32 = tx.query_row(
        "SELECT count(*) FROM pq_exchanges WHERE active = 1",
        [],
        |r| r.get(0),
    )?;
    for peer in [id, other] {
        let count: u32 = tx.query_row("SELECT count(*) FROM pq_exchanges WHERE active = 1 AND (initiator_id = ?1 OR responder_id = ?1)", [peer], |r| r.get(0))?;
        if count >= limits.peer_active || global >= limits.global_active {
            return Err(ServerError::RateLimited);
        }
    }
    let transcript = Transcript {
        network_id,
        initiator_id: message.initiator_id,
        responder_id: message.responder_id,
        initiator: first,
        responder: second,
        sequence: message.sequence,
        exchange_id: message.exchange_id.clone(),
        operator_psk_id: message
            .operator_psk_id
            .clone()
            .ok_or(ServerError::InvalidQuery)?,
        ciphertext: message
            .ciphertext
            .clone()
            .ok_or(ServerError::InvalidQuery)?,
    };
    transcript.validate()?;
    message.authenticate(&transcript)?;
    let record = Exchange {
        network_id: transcript.network_id.clone(),
        initiator_id: transcript.initiator_id,
        responder_id: transcript.responder_id,
        initiator_bundle_id: transcript.initiator.bundle_id.clone(),
        responder_bundle_id: transcript.responder.bundle_id.clone(),
        sequence: transcript.sequence,
        exchange_id: transcript.exchange_id.clone(),
        transcript_hash: Binary(crypto::hash(&transcript.encode())?),
        decision: Decision::default(),
        created_at: now,
        prepare_expires_at: now
            .checked_add(PREPARE_TTL)
            .ok_or(ServerError::InvalidQuery)?,
        transcript: Some(transcript),
        messages: vec![message.clone()],
        receipts: vec![digest],
        termination: None,
    };
    save(tx, &record)?;
    Ok(record)
}

pub fn terminate_peer(conn: &Connection, id: i64, reason: &str) -> Result<(), ServerError> {
    visit(
        conn,
        "active = 1 AND (initiator_id = ?1 OR responder_id = ?1)",
        [id],
        |mut record| {
            record.decision.phase = Phase::Aborted;
            record.termination = Some(reason.into());
            record.compact();
            save(conn, &record)
        },
    )
}

fn visit(
    conn: &Connection,
    predicate: &str,
    params: impl rusqlite::Params,
    mut operation: impl FnMut(Exchange) -> Result<(), ServerError>,
) -> Result<(), ServerError> {
    // Snapshot only bounded primary keys before changing the table. Keeping a
    // live SELECT cursor across writes has undefined row-visibility semantics;
    // materializing full transcripts here would amplify memory use.
    type Key = (i64, i64, Vec<u8>, Vec<u8>);
    let keys: Vec<Key> = conn.prepare(&format!("SELECT initiator_id, responder_id, initiator_bundle_id, responder_bundle_id FROM pq_exchanges WHERE {predicate}"))?
        .query_map(params, |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect::<Result<_, _>>()?;
    for (first, second, first_bundle, second_bundle) in keys {
        let record: String = conn.query_row("SELECT record FROM pq_exchanges WHERE initiator_id = ?1 AND responder_id = ?2 AND initiator_bundle_id = ?3 AND responder_bundle_id = ?4",
            params![first, second, first_bundle, second_bundle], |r| r.get(0))?;
        operation(serde_json::from_str(&record)?)?;
    }
    Ok(())
}

pub fn sweep_inner(conn: &Connection, now: u64) -> Result<(), ServerError> {
    let changed: bool = conn.query_row("SELECT visibility_revision != swept_visibility_revision FROM pq_network WHERE singleton = 1", [], |r| r.get(0))?;
    let predicate = if changed {
        "active = 1 AND ?1 >= 0"
    } else {
        "active = 1 AND json_extract(record, '$.decision.phase') IN ('proposed', 'ready') AND prepare_expires_at <= ?1"
    };
    visit(
        conn,
        predicate,
        [i64::try_from(now).map_err(|_| ServerError::Unavailable)?],
        |mut record| {
            let first = record.initiator_id.get() as i64;
            let second = record.responder_id.get() as i64;
            if changed {
                match pair_allowed(conn, first, second) {
                    Ok(()) => {},
                    Err(
                        ServerError::Unauthorized
                        | ServerError::NotFound
                        | ServerError::Database(rusqlite::Error::QueryReturnedNoRows),
                    ) => {
                        record.decision.phase = Phase::Aborted;
                        record.termination = Some("revoked".into());
                    },
                    Err(error) => return Err(error),
                }
            }
            if now >= record.prepare_expires_at {
                record.decision.expire();
            }
            if record.decision.terminal() {
                record.compact();
                save(conn, &record)?;
            }
            Ok(())
        },
    )?;
    if changed {
        conn.execute("UPDATE pq_network SET swept_visibility_revision = visibility_revision WHERE singleton = 1", [])?;
    }
    Ok(())
}
pub fn sweep(conn: &Connection, now: u64) -> Result<(), ServerError> {
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    sweep_inner(&tx, now)?;
    tx.commit()?;
    Ok(())
}
