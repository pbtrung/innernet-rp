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
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use wireguard_control::{Device, InterfaceName, Key};

pub type Page = StatePage<Peer, Cidr>;

/// Where this interface's PQ activation state (identity, management link,
/// data-peer relationships) is persisted. Distinct from both the client's
/// management-link store (`crate::management`, `.client-pq`) and M3's dev
/// harness store (`.pq-dev-harness`), which never runs alongside real
/// activation.
pub fn path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
    data_dir.join(format!("{interface}.pq"))
}

/// Opens this interface's PQ activation state, registering a fresh identity
/// with the server on first-ever activation. Requires the coordination API
/// to be reachable, so this must run only after the interface is confirmed
/// up (never called for gate restoration at cold boot, which relies solely
/// on already-persisted/cached state instead).
///
/// `permissive` sets `state.policy` from the live `--pq-psk-permissive`
/// flag on every call, not just at registration -- safe because legacy
/// eligibility (see `client_core::interface`) is gated on a relationship's
/// `prior_pq`, never on policy history, so toggling this flag can never
/// retroactively legalize legacy treatment for a relationship that ever
/// confirmed PQ.
pub fn open_or_register(
    data_dir: &Path,
    interface: &InterfaceName,
    rest_client: &RestClient,
    own_public_key: Binary<32>,
    permissive: bool,
    rng: &mut impl Random,
) -> anyhow::Result<(Store, EndpointState)> {
    let mut store =
        Store::open(&path(data_dir, interface), true).context("opening PQ activation state")?;
    let mut state = if store.is_fresh() {
        let state = register(rest_client, own_public_key, rng)?;
        store
            .save(&state)
            .context("persisting freshly registered PQ state")?;
        state
    } else {
        store.load().context("loading PQ activation state")?
    };
    state.policy = if permissive {
        Policy::Permissive
    } else {
        Policy::Strict
    };
    Ok((store, state))
}

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

/// Submits `state.registration` while a change (explicit disable via
/// `EndpointState::disable`, or re-enable via `EndpointState::replace`) is
/// still pending confirmation, advancing `enrollment` once the server's
/// response confirms it via `accept_registration`. A no-op once `enrollment`
/// has already settled to `Advertised`/`Retired`. A retirement (`lifecycle
/// == Retired`) must hit `?retire=1`; any other pending registration hits
/// the plain path -- the server rejects a mismatch between the two
/// (`server/src/api/pq.rs`'s `register` handler).
pub fn submit_pending_registration(
    rest_client: &RestClient,
    state: &mut EndpointState,
) -> anyhow::Result<()> {
    if !matches!(
        state.enrollment,
        Enrollment::Registering | Enrollment::Retiring
    ) {
        return Ok(());
    }
    let path = if state.registration.lifecycle == Lifecycle::Retired {
        "/user/pq-keys?retire=1"
    } else {
        "/user/pq-keys"
    };
    let response: AdvertisedBundle = rest_client
        .http_form("PUT", path, &state.registration)
        .context("submitting a changed PQ registration")?;
    state
        .accept_registration(&response)
        .context("the server's response did not match the submitted registration")?;
    Ok(())
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
///
/// One relationship's failure (an observation conflict, an engine error, a
/// storage error, or a transport error sending the outbox message) is
/// logged and this loop moves on to the next peer instead of aborting the
/// whole cycle: other peers must remain independent, and idle peers must
/// not restart a daemon or block others (design 5.12). A transport send
/// failure also records a bounded jittered backoff via
/// `EndpointState::note_send_failure` so the retry does not hammer
/// immediately next cycle.
///
/// `device`, when `Some`, is used to sample each peer's current WireGuard
/// byte counters (via `EndpointState::observe_activity`) before
/// reconciling, so `idle_timeout` can pause a repeat rotation for a
/// genuinely inactive tunnel. `None` skips activity sampling entirely
/// (matching pre-M5 behavior) -- used by callers with no real kernel
/// `Device` to sample (M3's dev harness and tests).
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
    idle_timeout: u64,
    device: Option<&Device>,
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
        if let Err(error) =
            state.observe_remote(other, &advertised.bundle, advertised.lifecycle.clone())
        {
            log::warn!(
                "observing peer {}'s advertised PQ bundle: {error}",
                other.get()
            );
            continue;
        }

        if let Some(device) = device {
            let counters = device
                .peers
                .iter()
                .find(|p| p.config.public_key.to_base64() == entry.peer.public_key)
                .map(|p| (p.stats.rx_bytes, p.stats.tx_bytes));
            if let Some((rx_bytes, tx_bytes)) = counters {
                if let Err(error) = state.observe_activity(other, now, rx_bytes, tx_bytes) {
                    log::warn!("sampling tunnel activity for peer {}: {error}", other.get());
                }
            }
        }

        let exchange = exchange_for(exchanges, self_id, other);
        let action = match state.reconcile(
            other,
            exchange,
            now,
            rotation_interval,
            idle_timeout,
            installer,
            rng,
        ) {
            Ok(action) => action,
            Err(error) => {
                log::warn!(
                    "advancing the PQ exchange with peer {}: {error}",
                    other.get()
                );
                continue;
            },
        };
        if let Err(error) = store.save(state) {
            log::warn!(
                "persisting PQ state before acting on peer {}: {error}",
                other.get()
            );
            continue;
        }

        if let Action::Send(message) = action {
            if let Err(error) = transport.put_handshake(other, message.message_type, &message) {
                let error = match error {
                    TransportError::Conflict => anyhow::anyhow!(
                        "stale visibility revision while submitting a phase message"
                    ),
                    TransportError::Other(error) => error,
                };
                log::warn!(
                    "submitting a signed phase message to peer {}: {error}",
                    other.get()
                );
                if let Err(error) = state.note_send_failure(other, now, rng) {
                    log::warn!("recording a send failure for peer {}: {error}", other.get());
                } else if let Err(error) = store.save(state) {
                    log::warn!(
                        "persisting the retry backoff for peer {}: {error}",
                        other.get()
                    );
                }
            }
        }
    }
    Ok(())
}

/// Fetches then reconciles in one call. Kept for callers that don't need
/// the fetched peer directory for anything else (M3's tests and dev
/// harness); the real production path calls `fetch_state`/`apply`
/// separately instead.
#[allow(clippy::too_many_arguments)]
pub fn sync(
    transport: &impl Transport,
    store: &mut Store,
    state: &mut EndpointState,
    installer: &mut impl Installer,
    rng: &mut impl Random,
    now: u64,
    rotation_interval: u64,
    idle_timeout: u64,
    device: Option<&Device>,
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
        idle_timeout,
        device,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_pq::{
        api::{AdvertisedBundle, Lifecycle},
        crypto::SystemRandom,
        engine::FakeInstaller,
        protocol::{Bundle, Number},
        state::{Enrollment, Identity, ManagementLink, Policy},
    };
    use innernet_shared::PeerContents;
    use std::cell::RefCell;
    use wireguard_control::KeyPair;

    fn peer_state(id: u64, server_id: u64) -> (EndpointState, Bundle) {
        let identity = Identity::generate(
            Binary([id as u8; 32]),
            Number::new(1).unwrap(),
            &mut SystemRandom,
        )
        .unwrap();
        let bundle = identity.bundle.clone();
        let state = EndpointState {
            network_id: Binary([9; 16]),
            peer_id: Number::new(id).unwrap(),
            server_id: Number::new(server_id).unwrap(),
            server_public_key: Binary([1; 32]),
            policy: Policy::Strict,
            registration: Registration {
                expected_revision: None,
                pq_version: 1,
                lifecycle: Lifecycle::Enabled,
                bundle: bundle.clone(),
                emergency: false,
            },
            identity,
            enrollment: Enrollment::Advertised,
            management: ManagementLink::generate(&mut SystemRandom).unwrap(),
            relationships: BTreeMap::new(),
        };
        (state, bundle)
    }

    fn peer_entry(id: i64, ip: &str, bundle: Bundle) -> PeerState<Peer> {
        PeerState {
            peer: Peer {
                id,
                contents: PeerContents {
                    name: "peer".parse().unwrap(),
                    ip: ip.parse().unwrap(),
                    cidr_id: 1,
                    public_key: Key(bundle.wg_public_key.0).to_base64(),
                    endpoint: None,
                    persistent_keepalive_interval: None,
                    is_admin: false,
                    is_disabled: false,
                    is_redeemed: true,
                    invite_expires: None,
                    candidates: vec![],
                },
            },
            is_server: false,
            pq: Some(AdvertisedBundle {
                pq_version: 1,
                lifecycle: Lifecycle::Enabled,
                bundle,
            }),
        }
    }

    fn legacy_peer_entry(id: i64, ip: &str, public_key: &Key) -> PeerState<Peer> {
        PeerState {
            peer: Peer {
                id,
                contents: PeerContents {
                    name: "legacy-peer".parse().unwrap(),
                    ip: ip.parse().unwrap(),
                    cidr_id: 1,
                    public_key: public_key.to_base64(),
                    endpoint: None,
                    persistent_keepalive_interval: None,
                    is_admin: false,
                    is_disabled: false,
                    is_redeemed: true,
                    invite_expires: None,
                    candidates: vec![],
                },
            },
            is_server: false,
            pq: None,
        }
    }

    #[derive(Default)]
    struct RecordingTransport {
        sent: RefCell<Vec<Number>>,
    }
    impl Transport for RecordingTransport {
        fn get_state(&self, _cursor: Option<&str>) -> Result<Page, TransportError> {
            unreachable!("this test calls apply() directly with pre-fetched pages")
        }
        fn put_handshake(
            &self,
            other: Number,
            _phase: u8,
            _message: &Message,
        ) -> Result<Exchange, TransportError> {
            self.sent.borrow_mut().push(other);
            Err(TransportError::Other(anyhow::anyhow!(
                "test transport never actually delivers"
            )))
        }
    }

    #[test]
    fn one_relationships_failure_does_not_block_another_in_the_same_cycle() {
        let (mut state, _own_bundle) = peer_state(2, 1);
        let (_, bundle_b) = peer_state(3, 1);
        let (_, bundle_c) = peer_state(4, 1);
        let b_id = Number::new(3).unwrap();
        let c_id = Number::new(4).unwrap();

        state
            .observe_remote(b_id, &bundle_b, Lifecycle::Enabled)
            .unwrap();
        state
            .observe_remote(c_id, &bundle_c, Lifecycle::Enabled)
            .unwrap();

        // Corrupt B's cached revision so this cycle's advertised bundle (an
        // older revision) triggers a real observe_remote Conflict for B
        // specifically, while C stays healthy.
        state
            .relationships
            .get_mut(&b_id)
            .unwrap()
            .remote
            .bundle_revision = Number::new(5).unwrap();

        let peers = vec![
            peer_entry(3, "10.0.0.3", bundle_b),
            peer_entry(4, "10.0.0.4", bundle_c),
        ];
        let exchanges = vec![];
        let transport = RecordingTransport::default();
        let mut installer = FakeInstaller::default();
        let mut rng = SystemRandom;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("state"), true).unwrap();

        apply(
            &peers,
            &exchanges,
            &transport,
            &mut store,
            &mut state,
            &mut installer,
            &mut rng,
            0,
            300,
            0,
            None,
        )
        .unwrap();

        assert!(
            state.relationships[&b_id].pending.is_none(),
            "B's observe_remote conflict must not create a pending exchange"
        );
        assert_eq!(
            *transport.sent.borrow(),
            vec![c_id],
            "only C's healthy relationship should have attempted to send"
        );
    }

    #[test]
    fn a_bundle_less_peer_is_never_touched_by_the_engine_or_installer() {
        // Whatever policy decides about *gating* a legacy peer is
        // client_core::interface's job (pq_install::legacy_eligible); this
        // proves the durable/kernel-facing half of "preserve any operator
        // PSK" independently: apply()'s loop must never create a
        // Relationship, send a message, or invoke the installer for a peer
        // that advertises no PQ bundle at all, regardless of policy.
        let (mut state, _own_bundle) = peer_state(2, 1);
        let legacy_key = KeyPair::generate().public;
        let legacy_id = Number::new(3).unwrap();

        let peers = vec![legacy_peer_entry(3, "10.0.0.3", &legacy_key)];
        let exchanges = vec![];
        let transport = RecordingTransport::default();
        let mut installer = FakeInstaller::default();
        let mut rng = SystemRandom;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("state"), true).unwrap();

        apply(
            &peers,
            &exchanges,
            &transport,
            &mut store,
            &mut state,
            &mut installer,
            &mut rng,
            0,
            300,
            0,
            None,
        )
        .unwrap();

        assert!(
            !state.relationships.contains_key(&legacy_id),
            "a bundle-less peer must never get a Relationship"
        );
        assert!(transport.sent.borrow().is_empty());
        assert!(installer.installed_psks.is_empty());
    }
}
