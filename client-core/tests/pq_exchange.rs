//! M3 Step 4: two independent EndpointState + driver-loop instances converge
//! through the real server API (server::test::Server, gated behind its
//! `test-harness` feature), with a fake kernel installer. No real socket,
//! root, or kernel WireGuard interface is used; production WireGuard state
//! is never touched.
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt};
use hyper::Response;
use innernet_client_core::pq_sync::{self, Page, Transport, TransportError};
use innernet_pq::{
    api::{Lifecycle, Registration},
    crypto::SystemRandom,
    engine::FakeInstaller,
    protocol::{Message, Number},
    state::{EndpointState, Enrollment, Identity, ManagementLink, Policy},
    store::Store,
};
use innernet_server::test::{
    Server, DEVELOPER1_PEER_ID, DEVELOPER1_PEER_IP, DEVELOPER2_PEER_ID, DEVELOPER2_PEER_IP,
};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use tokio::runtime::Runtime;

type Body = BoxBody<Bytes, hyper::Error>;

async fn read_json<T: DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

struct TestTransport<'a> {
    server: &'a Server,
    ip: &'static str,
    runtime: Runtime,
}
impl Transport for TestTransport<'_> {
    fn get_state(&self, cursor: Option<&str>) -> Result<Page, TransportError> {
        let path = match cursor {
            Some(c) => format!("/v1/user/state?pq_version=1&cursor={c}"),
            None => "/v1/user/state?pq_version=1".to_string(),
        };
        let response = self
            .runtime
            .block_on(self.server.request(self.ip, "GET", &path));
        if response.status().as_u16() == 409 {
            return Err(TransportError::Conflict);
        }
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("GET {path} returned {}", response.status()).into());
        }
        Ok(self.runtime.block_on(read_json(response)))
    }
    fn put_handshake(
        &self,
        other: Number,
        phase: u8,
        message: &Message,
    ) -> Result<innernet_pq::api::Exchange, TransportError> {
        let path = format!("/v1/user/pq-handshake/{}?phase={phase}", other.get());
        let response = self
            .runtime
            .block_on(self.server.form_request(self.ip, "PUT", &path, message));
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("PUT {path} returned {}", response.status()).into());
        }
        Ok(self.runtime.block_on(read_json(response)))
    }
}

fn peer_state(
    peer_id: i64,
    server_id: i64,
    network_id: [u8; 16],
    identity: Identity,
) -> EndpointState {
    EndpointState {
        network_id: innernet_pq::protocol::Binary(network_id),
        peer_id: Number::new(peer_id as u64).unwrap(),
        server_id: Number::new(server_id as u64).unwrap(),
        server_public_key: innernet_pq::protocol::Binary([0; 32]),
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
        management: ManagementLink::generate(&mut SystemRandom).unwrap(),
        relationships: BTreeMap::new(),
    }
}

/// Drives one side to convergence (or a bounded number of cycles), returning
/// whether it reached `Action::Complete` this call.
fn drive(
    transport: &impl Transport,
    store: &mut Store,
    state: &mut EndpointState,
    installer: &mut FakeInstaller,
    other: Number,
) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut rng = SystemRandom;
    let mut completed = false;
    // pq_sync::sync drives every visible relationship; watch this pair's
    // outcome via the state it leaves behind rather than its own return
    // value, since a completed relationship simply stops needing action.
    pq_sync::sync(transport, store, state, installer, &mut rng, now, 300).unwrap();
    if state.relationships[&other].confirmed.is_some()
        && state.relationships[&other].pending.is_none()
    {
        completed = true;
    }
    completed
}

#[test]
fn independent_processes_converge_through_the_real_api() {
    let mut server = Server::new().unwrap();
    // A tight local test loop issues far more requests per second than a
    // real client's 5-60s poll interval; raise the token buckets so the
    // test exercises protocol convergence rather than M1's own,
    // separately-tested rate limiter.
    let limits = innernet_server::pq::Limits {
        peer_rate: 1000,
        peer_burst: 1000,
        global_rate: 2000,
        global_burst: 2000,
        ..Default::default()
    };
    server.pq = Some(std::sync::Arc::new(
        innernet_server::pq::Service::new(limits).unwrap(),
    ));

    let (network_id, key_a, key_b): ([u8; 16], String, String) = {
        let conn = server.db.lock();
        conn.execute(
            "UPDATE pq_network SET enabled = 1, management_ready = 1",
            [],
        )
        .unwrap();
        let network_id: Vec<u8> = conn
            .query_row(
                "SELECT network_id FROM pq_network WHERE singleton = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let key = |id: i64| -> String {
            conn.query_row("SELECT public_key FROM peers WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .unwrap()
        };
        (
            network_id.try_into().unwrap(),
            key(DEVELOPER1_PEER_ID),
            key(DEVELOPER2_PEER_ID),
        )
    };

    let wg_a = innernet_pq::protocol::Binary(
        wireguard_control::Key::from_base64(&key_a)
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap(),
    );
    let wg_b = innernet_pq::protocol::Binary(
        wireguard_control::Key::from_base64(&key_b)
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap(),
    );
    let identity_a = Identity::generate(wg_a, Number::new(1).unwrap(), &mut SystemRandom).unwrap();
    let identity_b = Identity::generate(wg_b, Number::new(1).unwrap(), &mut SystemRandom).unwrap();

    let server_id = 1;
    let mut a = peer_state(DEVELOPER1_PEER_ID, server_id, network_id, identity_a);
    let mut b = peer_state(DEVELOPER2_PEER_ID, server_id, network_id, identity_b);
    let a_id = a.peer_id;
    let b_id = b.peer_id;

    let transport_a = TestTransport {
        server: &server,
        ip: DEVELOPER1_PEER_IP,
        runtime: Runtime::new().unwrap(),
    };
    let transport_b = TestTransport {
        server: &server,
        ip: DEVELOPER2_PEER_IP,
        runtime: Runtime::new().unwrap(),
    };

    for (transport, state) in [(&transport_a, &mut a), (&transport_b, &mut b)] {
        let registration = Registration {
            expected_revision: None,
            pq_version: 1,
            lifecycle: Lifecycle::Enabled,
            bundle: state.identity.bundle.clone(),
            emergency: false,
        };
        transport.runtime.block_on(transport.server.form_request(
            transport.ip,
            "PUT",
            "/v1/user/pq-keys",
            registration,
        ));
    }
    a.observe_remote(b_id, &b.identity.bundle.clone(), Lifecycle::Enabled)
        .unwrap();
    b.observe_remote(a_id, &a.identity.bundle.clone(), Lifecycle::Enabled)
        .unwrap();

    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let mut store_a = Store::open(&a_dir.path().join("state"), true).unwrap();
    let mut store_b = Store::open(&b_dir.path().join("state"), true).unwrap();
    let mut installer_a = FakeInstaller::default();
    let mut installer_b = FakeInstaller::default();

    let (mut a_done, mut b_done) = (false, false);
    for _ in 0..40 {
        if !a_done && drive(&transport_a, &mut store_a, &mut a, &mut installer_a, b_id) {
            a_done = true;
        }
        if !b_done && drive(&transport_b, &mut store_b, &mut b, &mut installer_b, a_id) {
            b_done = true;
        }
        if a_done && b_done {
            break;
        }
    }
    assert!(
        a_done && b_done,
        "exchange did not converge through the real API"
    );

    let psk_a: [u8; 32] = *a.relationships[&b_id].confirmed.as_ref().unwrap().psk.0 .0;
    let psk_b: [u8; 32] = *b.relationships[&a_id].confirmed.as_ref().unwrap().psk.0 .0;
    assert_eq!(psk_a, psk_b);
    assert_eq!(installer_a.installed_psks.len(), 1);
    assert_eq!(installer_b.installed_psks.len(), 1);

    // A restart must not change or reinstall the decision: release the
    // exclusive interface lock (as a process exit would), reopen, and
    // confirm the durable outcome survived untouched.
    drop(store_a);
    let reloaded_a: EndpointState = Store::open(&a_dir.path().join("state"), false)
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(
        *reloaded_a.relationships[&b_id]
            .confirmed
            .as_ref()
            .unwrap()
            .psk
            .0
             .0,
        psk_a
    );
}
