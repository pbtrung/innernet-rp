//! Opt-in public mailbox API. Admission precedes body collection and decoding.
use crate::{
    body::Body,
    db::{self, DatabaseCidr},
    pq::Service,
    util::json_response,
    ServerError, Session,
};
use http_body_util::{BodyExt, Limited};
use hyper::{header, Request, Response};
use innernet_pq::{
    api::{Lifecycle, PeerState, Registration, StatePage},
    crypto,
    protocol::{parse_message, Binary, Kind, Number, REQUEST_LIMIT},
};
use innernet_shared::{Cidr, Peer};
use rusqlite::{params, Transaction, TransactionBehavior};
use std::{sync::Arc, time::Duration};
use subtle::ConstantTimeEq;

type Page = StatePage<Peer, Cidr>;

fn service(session: &Session) -> Result<Arc<Service>, ServerError> {
    if !session.user_capable() {
        return Err(ServerError::Unauthorized);
    }
    session.context.pq.clone().ok_or(ServerError::Unavailable)
}

async fn body(req: Request<Body>) -> Result<bytes::Bytes, ServerError> {
    if req.headers().get_all(header::CONTENT_TYPE).iter().count() != 1
        || req
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
        || req.headers().contains_key(header::CONTENT_ENCODING)
    {
        return Err(ServerError::UnsupportedMedia);
    }
    if req.headers().get_all(header::CONTENT_LENGTH).iter().count() > 1 {
        return Err(ServerError::InvalidQuery);
    }
    if let Some(value) = req.headers().get(header::CONTENT_LENGTH) {
        let length: u64 = value
            .to_str()
            .map_err(|_| ServerError::InvalidQuery)?
            .parse()
            .map_err(|_| ServerError::InvalidQuery)?;
        if length > REQUEST_LIMIT as u64 {
            return Err(ServerError::PayloadTooLarge);
        }
    }
    Ok(tokio::time::timeout(
        Duration::from_secs(5),
        Limited::new(req.into_body(), REQUEST_LIMIT).collect(),
    )
    .await
    .map_err(|_| ServerError::InvalidQuery)?
    .map_err(|_| ServerError::PayloadTooLarge)?
    .to_bytes())
}

pub async fn register(req: Request<Body>, session: Session) -> Result<Response<Body>, ServerError> {
    let service = service(&session)?;
    // This untrusted hint only reserves admission. The decoded operation must
    // match it; it cannot authorize enrollment through recovery capacity.
    let retirement = match req.uri().query() {
        None => false,
        Some("retire=1") => true,
        _ => return Err(ServerError::InvalidQuery),
    };
    let permit = service.admit(session.peer.id, !retirement)?;
    let bytes = body(req).await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let request = Registration::parse(&bytes)?;
        if retirement != (request.lifecycle == Lifecycle::Retired) {
            return Err(ServerError::InvalidQuery);
        }
        let conn = session.context.db.lock();
        json_response(db::pq::register(
            &conn,
            session.peer.id,
            &session.peer.public_key,
            &request,
            &service.limits,
            service.clock.epoch_seconds(),
        )?)
    })
    .await
    .map_err(|_| ServerError::Unavailable)?
}

pub async fn handshake(
    req: Request<Body>,
    session: Session,
    other: &str,
) -> Result<Response<Body>, ServerError> {
    let other: Number = serde_json::from_value(serde_json::Value::String(other.into()))
        .map_err(|_| ServerError::InvalidQuery)?;
    let service = service(&session)?;
    let phase = match req.uri().query() {
        None | Some("phase=1") => 1,
        Some("phase=2") => 2,
        Some("phase=3") => 3,
        Some("phase=4") => 4,
        Some("phase=5") => 5,
        Some("phase=6") => 6,
        _ => return Err(ServerError::InvalidQuery),
    };
    let permit = service.admit(session.peer.id, phase == Kind::Propose as u8)?;
    let bytes = body(req).await?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let message = parse_message(&bytes)?;
        if message.message_type != phase {
            return Err(ServerError::InvalidQuery);
        }
        let conn = session.context.db.lock();
        json_response(db::pq::submit(
            &conn,
            session.peer.id,
            &session.peer.public_key,
            other.get() as i64,
            &message,
            &service.limits,
            service.clock.epoch_seconds(),
        )?)
    })
    .await
    .map_err(|_| ServerError::Unavailable)?
}

// HMAC-authenticated keyset cursor: requester, visibility, stage, last ID.
// No offsets into a mutable mailbox, no secret material, no server-side sessions.
fn encode_cursor(service: &Service, fields: [u64; 4]) -> Result<String, ServerError> {
    let mut bytes = [0; 64];
    for (chunk, value) in bytes[..32].as_chunks_mut::<8>().0.iter_mut().zip(fields) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    let tag = crypto::tag(&service.cursor_key, &bytes[..32])?;
    bytes[32..].copy_from_slice(&tag);
    Ok(serde_json::to_value(Binary(bytes))?
        .as_str()
        .ok_or(ServerError::Unavailable)?
        .into())
}
fn decode_cursor(
    service: &Service,
    value: &str,
    requester: u64,
    revision: u64,
) -> Result<(u64, i64), ServerError> {
    let bytes: Binary<64> = serde_json::from_value(serde_json::Value::String(value.into()))
        .map_err(|_| ServerError::InvalidQuery)?;
    if !bool::from(crypto::tag(&service.cursor_key, &bytes.0[..32])?.ct_eq(&bytes.0[32..])) {
        return Err(ServerError::InvalidQuery);
    }
    let fields: Vec<_> = bytes.0[..32]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|v| u64::from_be_bytes(*v))
        .collect();
    if fields[0] != requester || fields[1] != revision {
        return Err(ServerError::Conflict);
    }
    if fields[2] > 2 || fields[3] > i64::MAX as u64 {
        return Err(ServerError::InvalidQuery);
    }
    Ok((fields[2], fields[3] as i64))
}

pub async fn state(req: Request<Body>, session: Session) -> Result<Response<Body>, ServerError> {
    let service = service(&session)?;
    let query = req.uri().query().ok_or(ServerError::InvalidQuery)?;
    if query.len() > 256 {
        return Err(ServerError::InvalidQuery);
    }
    let mut version = false;
    let mut cursor = None;
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "pq_version" if !version && value == "1" => version = true,
            "cursor" if cursor.is_none() && !value.is_empty() => cursor = Some(value.into_owned()),
            _ => return Err(ServerError::InvalidQuery),
        }
    }
    if !version {
        return Err(ServerError::InvalidQuery);
    }
    let permit = service.admit_read()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        page(&session, &service, cursor.as_deref()).and_then(json_response)
    })
    .await
    .map_err(|_| ServerError::Unavailable)?
}

fn page(session: &Session, service: &Service, cursor: Option<&str>) -> Result<Page, ServerError> {
    let conn = session.context.db.lock();
    let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate)?;
    if !db::pq::ready(&tx)? {
        return Err(ServerError::Unavailable);
    }
    let caller = db::pq::caller(&tx, session.peer.id, &session.peer.public_key)?;
    db::pq::sweep_inner(&tx, service.clock.epoch_seconds())?;
    let (network_id, revision) = db::pq::network(&tx)?;
    let (mut stage, mut after) = cursor
        .map(|c| decode_cursor(service, c, caller.id as u64, revision as u64))
        .transpose()?
        .unwrap_or((0, 0));
    let mut page = Page {
        pq_version: 1,
        network_id,
        visibility_revision: Number::new(revision as u64)?,
        peers: vec![],
        cidrs: vec![],
        exchanges: vec![],
        next_cursor: None,
    };
    let mut pq_bytes = 512; // Version/network/cursor envelope and separators.
    let mut total_bytes = 512; // Includes JSON punctuation and the signed cursor.
    let mut count = 0;
    // Bound even wholly legacy pages to 32 objects. Fetch only one public bundle
    // at a time; never materialize the entire PQ directory/mailbox in memory.
    let mut peers = caller.get_all_allowed_peers(&tx)?;
    peers.sort_by_key(|p| p.id);
    while stage < 3 && count < 32 {
        let (id, value, pq_size) = match stage {
            0 => {
                let Some(peer) = peers.iter().find(|p| p.id > after) else {
                    stage = 1;
                    after = 0;
                    continue;
                };
                let mut values = vec![peer.inner.clone()];
                super::inject_endpoints(session, &mut values);
                let advertised = db::pq::bundle(&tx, peer.id)?;
                if let Some(bundle) = &advertised {
                    if wireguard_control::Key::from_base64(&peer.public_key)
                        .map_err(|_| ServerError::Conflict)?
                        .as_bytes()
                        != bundle.bundle.wg_public_key.0
                    {
                        return Err(ServerError::Conflict);
                    }
                }
                let size = advertised
                    .as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?
                    .map_or(64, |v| v.len() + 64); // Includes per-peer PQ metadata.
                let value = PeerState {
                    peer: values.remove(0),
                    is_server: db::pq::is_server(&tx, peer.id)?,
                    pq: advertised,
                };
                (peer.id, serde_json::to_value(value)?, size)
            },
            1 => {
                use rusqlite::OptionalExtension;
                let id: Option<i64> = tx
                    .query_row(
                        "SELECT id FROM cidrs WHERE id > ?1 ORDER BY id LIMIT 1",
                        [after],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(id) = id else {
                    stage = 2;
                    after = 0;
                    continue;
                };
                (id, serde_json::to_value(DatabaseCidr::get(&tx, id)?)?, 0)
            },
            _ => {
                use rusqlite::OptionalExtension;
                let row: Option<(i64, String)> = tx.query_row("SELECT CASE WHEN initiator_id = ?1 THEN responder_id ELSE initiator_id END AS other, record FROM pq_exchanges
                    WHERE (initiator_id = ?1 OR responder_id = ?1) AND other > ?2 ORDER BY other LIMIT 1", params![caller.id, after], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
                let Some((other, record)) = row else {
                    stage = 3;
                    continue;
                };
                match db::pq::pair_allowed(&tx, caller.id, other) {
                    Ok(()) => {},
                    Err(ServerError::Unauthorized | ServerError::NotFound) => {
                        after = other;
                        continue;
                    },
                    Err(error) => return Err(error),
                }
                let value: innernet_pq::api::Exchange = serde_json::from_str(&record)?;
                (other, serde_json::to_value(value)?, record.len())
            },
        };
        let size = serde_json::to_vec(&value)?.len() + 1;
        if pq_bytes + pq_size > 128 * 1024 || total_bytes + size > 1024 * 1024 {
            if count == 0 {
                return Err(ServerError::Unavailable);
            }
            break;
        }
        match stage {
            0 => page.peers.push(serde_json::from_value(value)?),
            1 => page.cidrs.push(serde_json::from_value(value)?),
            _ => page.exchanges.push(serde_json::from_value(value)?),
        }
        pq_bytes += pq_size;
        total_bytes += size;
        count += 1;
        after = id;
    }
    if stage < 3 {
        page.next_cursor = Some(encode_cursor(
            service,
            [caller.id as u64, revision as u64, stage, after as u64],
        )?);
    }
    tx.commit()?;
    Ok(page)
}

#[cfg(test)]
#[path = "pq_tests.rs"]
mod tests;
