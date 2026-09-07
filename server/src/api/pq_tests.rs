use super::*;
use crate::{
    db::DatabasePeer,
    pq::{Clock, Limits},
    test,
};
use hyper::StatusCode;
use innernet_pq::{
    api::Exchange,
    crypto::{Candidate, Secret},
    protocol::{Message, Phase, Transcript},
};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
struct Time(AtomicU64);
impl Clock for Time {
    fn monotonic_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst) * 1000
    }
    fn epoch_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Fixture {
    server: test::Server,
    time: Arc<Time>,
    transcript: Transcript,
    candidate: Candidate,
}
impl Fixture {
    async fn new() -> Self {
        let mut server = test::Server::new().unwrap();
        let time = Arc::new(Time::default());
        server.pq = Some(Arc::new(
            Service::with_clock(Limits::default(), time.clone()).unwrap(),
        ));
        let mut transcript: Transcript = serde_json::from_value(
            serde_json::from_str::<serde_json::Value>(include_str!(
                "../../../tests/fixtures/protocol-v1.json"
            ))
            .unwrap()["transcript"]
                .clone(),
        )
        .unwrap();
        transcript.initiator_id = Number::new(test::DEVELOPER1_PEER_ID as u64).unwrap();
        transcript.responder_id = Number::new(test::DEVELOPER2_PEER_ID as u64).unwrap();
        {
            let conn = server.db.lock();
            conn.execute(
                "UPDATE pq_network SET enabled = 1, management_ready = 1",
                [],
            )
            .unwrap();
            transcript.network_id = db::pq::network(&conn).unwrap().0;
            for (id, bundle) in [
                (test::DEVELOPER1_PEER_ID, &mut transcript.initiator),
                (test::DEVELOPER2_PEER_ID, &mut transcript.responder),
            ] {
                bundle.bundle_revision = Number::new(1).unwrap();
                let peer = DatabasePeer::get(&conn, id).unwrap();
                bundle.wg_public_key = Binary(
                    wireguard_control::Key::from_base64(&peer.public_key)
                        .unwrap()
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                );
            }
        }
        for (ip, bundle) in [
            (test::DEVELOPER1_PEER_IP, &transcript.initiator),
            (test::DEVELOPER2_PEER_IP, &transcript.responder),
        ] {
            let request = Registration {
                expected_revision: None,
                pq_version: 1,
                lifecycle: Lifecycle::Enabled,
                bundle: bundle.clone(),
                emergency: false,
            };
            assert_eq!(
                server
                    .form_request(ip, "PUT", "/v1/user/pq-keys", request)
                    .await
                    .status(),
                StatusCode::OK
            );
        }
        let candidate = crypto::derive(
            &Secret::from_bytes([1; 32]),
            &Secret::from_bytes([2; 56]),
            &Secret::from_bytes([0; 32]),
            &transcript.encode(),
        )
        .unwrap();
        Self {
            server,
            time,
            transcript,
            candidate,
        }
    }
    fn message(&self, kind: Kind, initiator: bool) -> Message {
        let mut scalar = [0; 66];
        scalar[65] = if initiator { 1 } else { 2 };
        Message::signed(
            &self.transcript,
            kind,
            if initiator {
                self.transcript.initiator_id
            } else {
                self.transcript.responder_id
            },
            &self.candidate,
            &Secret::from_bytes(scalar),
        )
        .unwrap()
    }
    async fn send(&self, message: &Message) -> Response<Body> {
        let first = message.sender_id == self.transcript.initiator_id;
        let other = if first {
            self.transcript.responder_id
        } else {
            self.transcript.initiator_id
        };
        self.server
            .form_request(
                if first {
                    test::DEVELOPER1_PEER_IP
                } else {
                    test::DEVELOPER2_PEER_IP
                },
                "PUT",
                &format!(
                    "/v1/user/pq-handshake/{}?phase={}",
                    other.get(),
                    message.message_type
                ),
                message,
            )
            .await
    }
    async fn step(&self, kind: Kind, initiator: bool) -> Exchange {
        let response = self.send(&self.message(kind, initiator)).await;
        assert_eq!(response.status(), StatusCode::OK, "{kind:?}");
        decode(response).await
    }
    async fn page(&self) -> Page {
        let response = self
            .server
            .request(
                test::DEVELOPER1_PEER_IP,
                "GET",
                "/v1/user/state?pq_version=1",
            )
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        decode(response).await
    }
}
async fn decode<T: serde::de::DeserializeOwned>(response: Response<Body>) -> T {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn pq_api_capability_readiness_and_atomic_registration() {
    let mut server = test::Server::new().unwrap();
    let legacy: serde_json::Value = decode(
        server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/user/state")
            .await,
    )
    .await;
    assert_eq!(legacy.as_object().unwrap().len(), 2);
    assert_eq!(
        server
            .request(
                test::DEVELOPER1_PEER_IP,
                "GET",
                "/v1/user/state?pq_version=1"
            )
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    server.pq = Some(Arc::new(Service::new(Limits::default()).unwrap()));
    let caps: serde_json::Value = decode(
        server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/user/capabilities")
            .await,
    )
    .await;
    assert!(caps.get("pq_psk_versions").is_none());
    let f = Fixture::new().await;
    let caps: serde_json::Value = decode(
        f.server
            .request(test::DEVELOPER1_PEER_IP, "GET", "/v1/user/capabilities")
            .await,
    )
    .await;
    assert_eq!(caps["pq_psk_versions"], serde_json::json!([1]));
    let mut request = Registration {
        expected_revision: None,
        pq_version: 1,
        lifecycle: Lifecycle::Enabled,
        bundle: f.transcript.initiator.clone(),
        emergency: false,
    };
    // Identical registration response loss is harmless; revision is not bumped.
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys",
                &request
            )
            .await
            .status(),
        StatusCode::OK
    );
    request.expected_revision = Some(Number::new(1).unwrap());
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys",
                &request
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    request.bundle.bundle_revision = Number::new(2).unwrap();
    request.bundle.bundle_id = Binary([77; 16]);
    let mut incomplete = serde_json::to_value(&request).unwrap();
    incomplete["bundle"]
        .as_object_mut()
        .unwrap()
        .remove("pq_x448_public_key");
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys",
                incomplete
            )
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    f.time.0.store(1, Ordering::SeqCst);
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys",
                &request
            )
            .await
            .status(),
        StatusCode::OK
    );
    request.expected_revision = Some(Number::new(2).unwrap());
    request.bundle.bundle_revision = Number::new(3).unwrap();
    request.bundle.bundle_id = f.transcript.initiator.bundle_id.clone();
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys",
                &request
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    let conn = f.server.db.lock();
    assert_eq!(
        db::pq::bundle(&conn, test::DEVELOPER1_PEER_ID)
            .unwrap()
            .unwrap()
            .bundle
            .bundle_revision
            .get(),
        2
    );
}

#[tokio::test]
async fn pq_api_durable_duplicate_delivery_tombstones_and_stale_receipts() {
    let mut f = Fixture::new().await;
    let proposed = f.step(Kind::Propose, true).await;
    assert_eq!(proposed, f.step(Kind::Propose, true).await);
    assert_eq!(f.page().await.exchanges, f.page().await.exchanges);
    assert_eq!(f.page().await.exchanges[0], proposed);
    assert_eq!(
        f.send(&f.message(Kind::Commit, true)).await.status(),
        StatusCode::CONFLICT
    );
    f.step(Kind::Ready, false).await;
    f.step(Kind::Commit, true).await;
    assert_eq!(
        f.send(&f.message(Kind::Abort, true)).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        f.send(&f.message(Kind::Installed, true)).await.status(),
        StatusCode::CONFLICT
    );
    f.step(Kind::Installed, false).await;
    f.step(Kind::Installed, true).await;
    f.step(Kind::Confirmed, true).await;
    let completed = f.step(Kind::Confirmed, false).await;
    assert_eq!(completed.decision.phase, Phase::Complete);
    assert!(completed.transcript.is_none() && completed.messages.is_empty());
    assert_eq!(completed.receipts.len(), 7);
    let old_receipt = f.message(Kind::Confirmed, true);
    f.time.0.store(2, Ordering::SeqCst);
    f.transcript.sequence = Number::new(2).unwrap();
    f.transcript.exchange_id = Binary([33; 16]);
    f.step(Kind::Propose, true).await;
    assert_eq!(f.send(&old_receipt).await.status(), StatusCode::CONFLICT);
    let path = f.server.db.lock().path().unwrap().to_owned();
    let reopened = rusqlite::Connection::open(path).unwrap();
    db::auto_migrate(&reopened).unwrap();
    let records = db::pq::load_pair(
        &reopened,
        test::DEVELOPER1_PEER_ID,
        test::DEVELOPER2_PEER_ID,
    )
    .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].sequence.get(), 2);
    assert_eq!(records[0].decision.phase, Phase::Proposed);
}

#[tokio::test]
async fn pq_api_expiry_persists_on_reads_failed_writes_and_sweeps() {
    for mode in 0..3 {
        let f = Fixture::new().await;
        f.step(Kind::Propose, true).await;
        f.step(Kind::Ready, false).await;
        f.time.0.store(600, Ordering::SeqCst);
        match mode {
            0 => {
                assert_eq!(f.page().await.exchanges[0].decision.phase, Phase::Aborted);
            },
            1 => {
                assert_eq!(
                    f.send(&f.message(Kind::Commit, true)).await.status(),
                    StatusCode::CONFLICT
                );
            },
            _ => db::pq::sweep(&f.server.db.lock(), 600).unwrap(),
        }
        let result = f.step(Kind::Propose, true).await;
        assert_eq!(result.decision.phase, Phase::Aborted);
        assert_eq!(result.prepare_expires_at, 600);
    }
    let f = Fixture::new().await;
    f.step(Kind::Propose, true).await;
    f.step(Kind::Ready, false).await;
    f.step(Kind::Commit, true).await;
    f.time.0.store(100_000, Ordering::SeqCst);
    assert_eq!(f.page().await.exchanges[0].decision.phase, Phase::Committed);
}

#[tokio::test]
async fn pq_api_current_identity_roles_signatures_and_retirement() {
    let f = Fixture::new().await;
    let message = f.message(Kind::Propose, true);
    for other in ["0", "01", "-1", "9223372036854775808"] {
        assert_eq!(
            f.server
                .form_request(
                    test::DEVELOPER1_PEER_IP,
                    "PUT",
                    &format!("/v1/user/pq-handshake/{other}"),
                    &message
                )
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for other in [1, test::DEVELOPER1_PEER_ID, test::USER1_PEER_ID] {
        assert_eq!(
            f.server
                .form_request(
                    test::DEVELOPER1_PEER_IP,
                    "PUT",
                    &format!("/v1/user/pq-handshake/{other}"),
                    &message
                )
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    f.time.0.store(2, Ordering::SeqCst);
    let mut changed = message.clone();
    changed.signature.0[9] ^= 1;
    assert_eq!(f.send(&changed).await.status(), StatusCode::BAD_REQUEST);
    f.step(Kind::Propose, true).await;
    let mut retire = Registration {
        expected_revision: Some(Number::new(1).unwrap()),
        pq_version: 1,
        lifecycle: Lifecycle::Retired,
        bundle: f.transcript.initiator.clone(),
        emergency: false,
    };
    retire.bundle.bundle_revision = Number::new(2).unwrap();
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys?retire=1",
                &retire
            )
            .await
            .status(),
        StatusCode::CONFLICT
    );
    retire.emergency = true;
    assert_eq!(
        f.server
            .form_request(
                test::DEVELOPER1_PEER_IP,
                "PUT",
                "/v1/user/pq-keys?retire=1",
                &retire
            )
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(f.send(&message).await.status(), StatusCode::CONFLICT);
    let ctx = f.server.context();
    let peer = DatabasePeer::get(&ctx.db.lock(), test::DEVELOPER1_PEER_ID).unwrap();
    let session = Session { context: ctx, peer };
    f.server
        .db
        .lock()
        .execute(
            "UPDATE peers SET public_key = ?1 WHERE id = ?2",
            params![
                wireguard_control::Key::generate_private()
                    .get_public()
                    .to_base64(),
                test::DEVELOPER1_PEER_ID
            ],
        )
        .unwrap();
    assert!(matches!(
        page(&session, f.server.pq.as_ref().unwrap(), None),
        Err(ServerError::Unauthorized)
    ));
}

#[tokio::test]
async fn pq_api_pages_are_bounded_non_consuming_and_authorization_bound() {
    let f = Fixture::new().await;
    {
        let conn = f.server.db.lock();
        let template = DatabasePeer::get(&conn, test::DEVELOPER1_PEER_ID).unwrap();
        for n in 10..55 {
            let mut contents = template.contents.clone();
            contents.name = format!("page-{n}").parse().unwrap();
            contents.ip = match template.ip {
                std::net::IpAddr::V4(ip) => std::net::Ipv4Addr::from(u32::from(ip) + n).into(),
                std::net::IpAddr::V6(ip) => {
                    std::net::Ipv6Addr::from(u128::from(ip) + u128::from(n)).into()
                },
            };
            contents.public_key = wireguard_control::Key::generate_private()
                .get_public()
                .to_base64();
            DatabasePeer::create(&conn, contents).unwrap();
        }
    }
    let first = f.page().await;
    assert_eq!(first.peers.len(), 32);
    let cursor = first.next_cursor.unwrap();
    let query = url::form_urlencoded::Serializer::new(String::from("/v1/user/state?"))
        .append_pair("pq_version", "1")
        .append_pair("cursor", &cursor)
        .finish();
    let mut ids: Vec<_> = first.peers.iter().map(|p| p.peer.id).collect();
    let second: Page = decode(
        f.server
            .request(test::DEVELOPER1_PEER_IP, "GET", &query)
            .await,
    )
    .await;
    let retry: Page = decode(
        f.server
            .request(test::DEVELOPER1_PEER_IP, "GET", &query)
            .await,
    )
    .await;
    assert_eq!(
        serde_json::to_value(&second).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    ids.extend(second.peers.iter().map(|p| p.peer.id));
    let count = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), count);
    assert_eq!(count, 48);
    assert!(serde_json::to_vec(&second).unwrap().len() < 1024 * 1024);
    assert_eq!(
        f.server
            .request(test::DEVELOPER2_PEER_IP, "GET", &query)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    DatabasePeer::disable(&f.server.db.lock(), test::DEVELOPER2_PEER_ID).unwrap();
    assert_eq!(
        f.server
            .request(test::DEVELOPER1_PEER_IP, "GET", &query)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    for query in [
        "pq_version=1&pq_version=1",
        "pq_version=2",
        "pq_version=1&cursor=bad",
        "pq_version=1&extra=x",
    ] {
        assert_eq!(
            f.server
                .request(
                    test::DEVELOPER1_PEER_IP,
                    "GET",
                    &format!("/v1/user/state?{query}")
                )
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
}

#[tokio::test]
async fn pq_api_raw_body_limits_and_recovery_admission() {
    let f = Fixture::new().await;
    let original = serde_json::to_string(&f.message(Kind::Propose, true)).unwrap();
    for (extra, expected) in [(0, StatusCode::OK), (1, StatusCode::PAYLOAD_TOO_LARGE)] {
        let mut bytes = original.clone().into_bytes();
        bytes.resize(REQUEST_LIMIT + extra, b' ');
        let request = f
            .server
            .base_request_builder("PUT", "/v1/user/pq-handshake/4")
            .header("Content-Type", "application/json")
            .body(crate::body::full(bytes))
            .unwrap();
        assert_eq!(
            f.server
                .raw_request(test::DEVELOPER1_PEER_IP, request)
                .await
                .status(),
            expected
        );
    }
    for header in ["Content-Encoding", "Content-Type"] {
        let request = f
            .server
            .base_request_builder("PUT", "/v1/user/pq-handshake/4")
            .header(header, "gzip")
            .body(crate::body::full(original.clone()))
            .unwrap();
        assert_eq!(
            f.server
                .raw_request(test::DEVELOPER1_PEER_IP, request)
                .await
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }
    let duplicate = original.replacen('{', "{\"version\":1,", 1);
    let request = f
        .server
        .base_request_builder("PUT", "/v1/user/pq-handshake/4")
        .header("Content-Type", "application/json")
        .body(crate::body::full(duplicate))
        .unwrap();
    assert_eq!(
        f.server
            .raw_request(test::DEVELOPER1_PEER_IP, request)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let service = f.server.pq.as_ref().unwrap();
    let hold = service.admit(test::DEVELOPER1_PEER_ID, true).unwrap();
    for _ in 0..1000 {
        assert!(matches!(
            service.admit(test::DEVELOPER1_PEER_ID, true),
            Err(ServerError::RateLimited)
        ));
    }
    let recovery = service.admit(test::DEVELOPER1_PEER_ID, false).unwrap();
    assert!(service.admit(test::DEVELOPER1_PEER_ID, false).is_err());
    drop((hold, recovery));
    f.step(Kind::Ready, false).await;
    f.step(Kind::Commit, true).await;
}

#[tokio::test]
async fn pq_api_sqlite_concurrent_commit_abort_and_expiry_serialize() {
    for expire in [false, true] {
        let f = Fixture::new().await;
        f.step(Kind::Propose, true).await;
        f.step(Kind::Ready, false).await;
        let path = f.server.db.lock().path().unwrap().to_owned();
        let commit = f.message(Kind::Commit, true);
        let abort = f.message(Kind::Abort, true);
        let key = DatabasePeer::get(&f.server.db.lock(), test::DEVELOPER1_PEER_ID)
            .unwrap()
            .public_key
            .clone();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = [true, false]
            .into_iter()
            .map(|committer| {
                let conn = rusqlite::Connection::open(&path).unwrap();
                conn.busy_timeout(Duration::from_secs(5)).unwrap();
                conn.pragma_update(None, "foreign_keys", 1).unwrap();
                let barrier = barrier.clone();
                let key = key.clone();
                let message = if committer {
                    commit.clone()
                } else {
                    abort.clone()
                };
                std::thread::spawn(move || {
                    barrier.wait();
                    if !committer && expire {
                        db::pq::sweep(&conn, 600).map(|_| None)
                    } else {
                        db::pq::submit(
                            &conn,
                            test::DEVELOPER1_PEER_ID,
                            &key,
                            test::DEVELOPER2_PEER_ID,
                            &message,
                            &Limits::default(),
                            599,
                        )
                        .map(Some)
                    }
                })
            })
            .collect();
        let results: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
        let records = db::pq::load_pair(
            &f.server.db.lock(),
            test::DEVELOPER1_PEER_ID,
            test::DEVELOPER2_PEER_ID,
        )
        .unwrap();
        assert!(matches!(
            records[0].decision.phase,
            Phase::Aborted | Phase::Committed
        ));
        if !expire {
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        }
        assert!(results.iter().all(|r| r.is_ok()
            || matches!(
                r,
                Err(ServerError::Conflict | ServerError::Pq(innernet_pq::Error::Conflict))
            )));
    }
}

#[tokio::test]
async fn pq_api_revocation_is_irrevocable_and_recovery_survives_record_budget() {
    let mut f = Fixture::new().await;
    f.step(Kind::Propose, true).await;
    let limits = Limits {
        global_active: 1,
        peer_active: 1,
        ..Limits::default()
    };
    f.server.pq = Some(Arc::new(
        Service::with_clock(limits, f.time.clone()).unwrap(),
    ));
    f.step(Kind::Ready, false).await;
    f.step(Kind::Commit, true).await;
    let conn = f.server.db.lock();
    let mut peer = DatabasePeer::get(&conn, test::DEVELOPER2_PEER_ID).unwrap();
    DatabasePeer::disable(&conn, peer.id).unwrap();
    peer.update(&conn, peer.contents.clone()).unwrap();
    let record = db::pq::load_pair(&conn, test::DEVELOPER1_PEER_ID, test::DEVELOPER2_PEER_ID)
        .unwrap()
        .remove(0);
    assert_eq!(record.decision.phase, Phase::Aborted);
    assert_eq!(record.termination.as_deref(), Some("disabled"));
}

// An actual streaming body controlled by the test, not a Content-Length mock.
struct DelayedBody(Option<tokio::sync::oneshot::Receiver<bytes::Bytes>>);
impl hyper::body::Body for DelayedBody {
    type Data = bytes::Bytes;
    type Error = hyper::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::{future::Future, task::Poll};
        let Some(receiver) = self.0.as_mut() else {
            return Poll::Ready(None);
        };
        match std::pin::Pin::new(receiver).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.0 = None;
                Poll::Ready(result.ok().map(|bytes| Ok(hyper::body::Frame::data(bytes))))
            },
        }
    }
}

#[tokio::test(start_paused = true)]
async fn pq_api_body_deadline_releases_permits_and_rechecks_delayed_session() {
    let f = Fixture::new().await;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let req = f
        .server
        .base_request_builder("PUT", "/v1/user/pq-handshake/4")
        .header("Content-Type", "application/json")
        .body(DelayedBody(Some(receiver)).boxed())
        .unwrap();
    let context = f.server.context();
    let task = tokio::spawn(crate::hyper_service(
        req,
        context,
        std::net::SocketAddr::new(test::DEVELOPER1_PEER_IP.parse().unwrap(), 54321),
    ));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        task.await.unwrap().unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    drop(sender);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let req = f
        .server
        .base_request_builder("PUT", "/v1/user/pq-handshake/4")
        .header("Content-Type", "application/json")
        .body(DelayedBody(Some(receiver)).boxed())
        .unwrap();
    let task = tokio::spawn(crate::hyper_service(
        req,
        f.server.context(),
        std::net::SocketAddr::new(test::DEVELOPER1_PEER_IP.parse().unwrap(), 54321),
    ));
    tokio::task::yield_now().await;
    DatabasePeer::disable(&f.server.db.lock(), test::DEVELOPER1_PEER_ID).unwrap();
    sender
        .send(
            serde_json::to_vec(&f.message(Kind::Propose, true))
                .unwrap()
                .into(),
        )
        .unwrap();
    assert_eq!(
        task.await.unwrap().unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn pq_api_new_pair_quota_does_not_block_committed_recovery() {
    let mut f = Fixture::new().await;
    let mut other = f.transcript.responder.clone();
    other.bundle_id = Binary([87; 16]);
    {
        let conn = f.server.db.lock();
        let peer = DatabasePeer::get(&conn, test::USER1_PEER_ID).unwrap();
        other.wg_public_key = Binary(
            wireguard_control::Key::from_base64(&peer.public_key)
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
        );
        db::DatabaseAssociation::create(
            &conn,
            innernet_shared::AssociationContents {
                cidr_id_1: test::DEVELOPER_CIDR_ID,
                cidr_id_2: test::USER_CIDR_ID,
            },
        )
        .unwrap();
    }
    let request = Registration {
        expected_revision: None,
        pq_version: 1,
        lifecycle: Lifecycle::Enabled,
        bundle: other.clone(),
        emergency: false,
    };
    assert_eq!(
        f.server
            .form_request(test::USER1_PEER_IP, "PUT", "/v1/user/pq-keys", request)
            .await
            .status(),
        StatusCode::OK
    );
    f.server.pq = Some(Arc::new(
        Service::with_clock(
            Limits {
                global_active: 1,
                peer_active: 1,
                ..Limits::default()
            },
            f.time.clone(),
        )
        .unwrap(),
    ));
    f.step(Kind::Propose, true).await;
    let mut t = f.transcript.clone();
    t.responder = other;
    t.responder_id = Number::new(test::USER1_PEER_ID as u64).unwrap();
    let mut scalar = [0; 66];
    scalar[65] = 1;
    let message = Message::signed(
        &t,
        Kind::Propose,
        t.initiator_id,
        &f.candidate,
        &Secret::from_bytes(scalar),
    )
    .unwrap();
    let rejected = f
        .server
        .form_request(
            test::DEVELOPER1_PEER_IP,
            "PUT",
            &format!("/v1/user/pq-handshake/{}", test::USER1_PEER_ID),
            message,
        )
        .await;
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers()["Retry-After"], "1");
    f.step(Kind::Ready, false).await;
    f.step(Kind::Commit, true).await;
    f.step(Kind::Installed, false).await;
    f.step(Kind::Installed, true).await;
    f.step(Kind::Confirmed, true).await;
    f.step(Kind::Confirmed, false).await;
    assert_eq!(f.page().await.exchanges[0].decision.phase, Phase::Complete);
}

#[test]
fn pq_api_global_worker_reservation_and_invalid_configuration() {
    let service = Service::with_clock(
        Limits {
            global_writes: 4,
            ..Limits::default()
        },
        Arc::new(Time::default()),
    )
    .unwrap();
    let holds: Vec<_> = (1..=3).map(|p| service.admit(p, true).unwrap()).collect();
    assert!(service.admit(4, true).is_err());
    let recovery = service.admit(4, false).unwrap();
    assert!(service.admit_read().is_ok());
    drop((holds, recovery));
    assert!(Service::new(Limits {
        global_writes: usize::MAX,
        ..Limits::default()
    })
    .is_err());
    assert!(Service::new(Limits {
        recovery_reserve_bytes: 0,
        ..Limits::default()
    })
    .is_err());
}
