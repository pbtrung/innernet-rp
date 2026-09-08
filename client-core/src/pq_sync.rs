//! Drives one client's data-peer PQ exchanges: walks the versioned paginated
//! state (design 5.2), then advances every visible relationship's engine by
//! one step (design 5.4-5.6). Never touches production WireGuard state
//! itself; that is the `Installer` the caller supplies.
//!
//! Network access is behind the `Transport` trait so tests can substitute an
//! in-process server (spoofing per-peer source addresses the way real
//! WireGuard tunnels would) without needing real sockets, root, or a kernel
//! WireGuard interface; `RestClient` is the real, production implementation.
use crate::rest_client::{RestClient, RestError};
use anyhow::Context as _;
use innernet_pq::{
    api::{AdvertisedBundle, Exchange, Lifecycle, PeerState, Registration, StatePage},
    crypto::Random,
    engine::{Action, Installer},
    protocol::{Binary, Message, Number},
    state::{EndpointState, Enrollment, Identity, ManagementLink, Policy},
    store::Store,
};
use innernet_shared::{Cidr, Peer};
use std::collections::BTreeMap;
use wireguard_control::Key;

pub type Page = StatePage<Peer, Cidr>;

pub enum TransportError {
    /// The visibility revision changed mid-walk; restart pagination.
    Conflict,
    Other(anyhow::Error),
}
impl From<anyhow::Error> for TransportError {
    fn from(error: anyhow::Error) -> Self {
        TransportError::Other(error)
    }
}

pub trait Transport {
    fn get_state(&self, cursor: Option<&str>) -> Result<Page, TransportError>;
    fn put_handshake(
        &self,
        other: Number,
        phase: u8,
        message: &Message,
    ) -> Result<Exchange, TransportError>;
}

fn cursor_query(cursor: &str) -> String {
    let encoded: String = url::form_urlencoded::byte_serialize(cursor.as_bytes()).collect();
    format!("/user/state?pq_version=1&cursor={encoded}")
}

impl Transport for RestClient<'_> {
    fn get_state(&self, cursor: Option<&str>) -> Result<Page, TransportError> {
        let path = match cursor {
            Some(c) => cursor_query(c),
            None => "/user/state?pq_version=1".to_string(),
        };
        self.http("GET", &path).map_err(rest_error)
    }
    fn put_handshake(
        &self,
        other: Number,
        phase: u8,
        message: &Message,
    ) -> Result<Exchange, TransportError> {
        let path = format!("/user/pq-handshake/{}?phase={}", other.get(), phase);
        self.http_form("PUT", &path, message).map_err(rest_error)
    }
}
fn rest_error(error: RestError) -> TransportError {
    if error.has_status_of(409) {
        TransportError::Conflict
    } else {
        TransportError::Other(anyhow::Error::new(error))
    }
}

/// Discovers this peer's own id, the server's id, and the network id from
/// the opt-in PQ state response, before this side has ever registered a
/// bundle; generates a fresh identity and registers it with the server.
/// Shared by the M3 dev harness and real first activation (M4).
pub fn register(
    rest_client: &RestClient,
    own_public_key: Binary<32>,
    rng: &mut impl Random,
) -> anyhow::Result<EndpointState> {
    let page: StatePage<Peer, Cidr> = rest_client.http("GET", "/user/state?pq_version=1")?;
    let own_base64 = Key(own_public_key.0).to_base64();
    let me = page
        .peers
        .iter()
        .find(|p| p.peer.public_key == own_base64)
        .ok_or_else(|| {
            anyhow::anyhow!("could not find this peer's own entry in the visible state")
        })?;
    let server_entry =
        page.peers.iter().find(|p| p.is_server).ok_or_else(|| {
            anyhow::anyhow!("could not find the server's entry in the visible state")
        })?;
    let self_id =
        Number::new(me.peer.id as u64).map_err(|_| anyhow::anyhow!("invalid self peer id"))?;
    let server_id = Number::new(server_entry.peer.id as u64)
        .map_err(|_| anyhow::anyhow!("invalid server peer id"))?;

    let identity = Identity::generate(
        own_public_key,
        Number::new(1).map_err(|_| anyhow::anyhow!("invalid revision"))?,
        rng,
    )?;
    let state = EndpointState {
        network_id: page.network_id,
        peer_id: self_id,
        server_id,
        server_public_key: Binary([0; 32]),
        policy: Policy::Strict,
        registration: Registration {
            expected_revision: None,
            pq_version: 1,
            lifecycle: Lifecycle::Enabled,
            bundle: identity.bundle.clone(),
            emergency: false,
        },
        identity,
        enrollment: Enrollment::Advertised,
        management: ManagementLink::generate(rng)?,
        relationships: BTreeMap::new(),
    };
    let _: AdvertisedBundle = rest_client.http_form("PUT", "/user/pq-keys", &state.registration)?;
    Ok(state)
}

/// Walks every page, restarting from the top if the visibility revision
/// changes mid-walk.
pub fn fetch_state(
    transport: &impl Transport,
) -> anyhow::Result<(Vec<PeerState<Peer>>, Vec<Exchange>)> {
    let mut peers = Vec::new();
    let mut exchanges = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        match transport.get_state(cursor.as_deref()) {
            Ok(page) => {
                peers.extend(page.peers);
                exchanges.extend(page.exchanges);
                match page.next_cursor {
                    Some(next) => cursor = Some(next),
                    None => return Ok((peers, exchanges)),
                }
            },
            Err(TransportError::Conflict) => {
                peers.clear();
                exchanges.clear();
                cursor = None;
            },
            Err(TransportError::Other(error)) => return Err(error).context("fetching PQ state"),
        }
    }
}

fn exchange_for(exchanges: &[Exchange], self_id: Number, other: Number) -> Option<&Exchange> {
    exchanges.iter().find(|e| {
        (e.initiator_id == self_id && e.responder_id == other)
            || (e.initiator_id == other && e.responder_id == self_id)
    })
}

/// Advances every visible data-peer relationship by one step against
/// already-fetched `peers`/`exchanges`, persisting `state` via `store` after
/// every durable mutation and before performing the corresponding
/// network/kernel action. Split out from `sync` so a real production caller
/// can fetch the peer directory once, build a real `Installer` from it
/// (which needs each peer's endpoint/keepalive/allowed IP), then reconcile
/// -- without a second network round trip of its own.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    peers: &[PeerState<Peer>],
    exchanges: &[Exchange],
    transport: &impl Transport,
    store: &mut Store,
    state: &mut EndpointState,
    installer: &mut impl Installer,
    rng: &mut impl Random,
    now: u64,
    rotation_interval: u64,
) -> anyhow::Result<()> {
    let self_id = state.peer_id;
    let server_id = state.server_id;

    for entry in peers {
        if entry.is_server {
            continue;
        }
        let Ok(other) = Number::new(entry.peer.id as u64) else {
            continue;
        };
        if other == self_id || other == server_id {
            continue;
        }
        let Some(advertised) = &entry.pq else {
            continue;
        };
        state.observe_remote(other, &advertised.bundle, advertised.lifecycle.clone())?;

        let exchange = exchange_for(exchanges, self_id, other);
        let action = state.reconcile(other, exchange, now, rotation_interval, installer, rng)?;
        store
            .save(state)
            .context("persisting PQ state before acting")?;

        if let Action::Send(message) = action {
            transport
                .put_handshake(other, message.message_type, &message)
                .map_err(|e| match e {
                    TransportError::Conflict => anyhow::anyhow!(
                        "stale visibility revision while submitting a phase message"
                    ),
                    TransportError::Other(error) => error,
                })
                .context("submitting a signed phase message")?;
        }
    }
    Ok(())
}

/// Fetches then reconciles in one call. Kept for callers that don't need
/// the fetched peer directory for anything else (M3's tests and dev
/// harness); the real production path calls `fetch_state`/`apply`
/// separately instead.
pub fn sync(
    transport: &impl Transport,
    store: &mut Store,
    state: &mut EndpointState,
    installer: &mut impl Installer,
    rng: &mut impl Random,
    now: u64,
    rotation_interval: u64,
) -> anyhow::Result<()> {
    let (peers, exchanges) = fetch_state(transport)?;
    apply(
        &peers,
        &exchanges,
        transport,
        store,
        state,
        installer,
        rng,
        now,
        rotation_interval,
    )
}
