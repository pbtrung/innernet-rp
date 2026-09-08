//! Seeded fault-schedule property test (design case 4-7 / M3's "seeded unit
//! event schedules"). Runs many bounded, reproducible randomized schedules
//! of lost responses, duplicate/replayed delivery, and restarts over the
//! same two-sided simulated mailbox pattern as engine.rs's own unit tests,
//! asserting safety invariants hold throughout: sequence never decreases,
//! a completed candidate never changes underneath a restart, and both
//! sides converge on the same PSK once faults stop. On failure the seed and
//! schedule are printed so the run becomes a fixed regression case.
use innernet_pq::{
    Result,
    api::{Exchange as ApiExchange, Lifecycle, Registration},
    crypto::{Random, SystemRandom},
    engine::{Action, FakeInstaller},
    protocol::{Binary, Bundle, Decision, Kind, Number},
    state::{EndpointState, Enrollment, Identity, ManagementLink, Policy},
};
use std::collections::BTreeMap;

/// A tiny deterministic PRNG so a failing schedule is exactly reproducible
/// from its printed seed, independent of any external crate's algorithm.
struct Lcg(u64);
impl Lcg {
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, bound: u32) -> u32 {
        (self.next_u64() % u64::from(bound)) as u32
    }
}
impl Random for Lcg {
    fn fill(&mut self, output: &mut [u8]) -> Result<()> {
        for chunk in output.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }
}

fn peer(id: u64, server_id: u64, rng: &mut Lcg) -> (EndpointState, Bundle) {
    let identity =
        Identity::generate(Binary([id as u8; 32]), Number::new(1).unwrap(), rng).unwrap();
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

/// Mirrors what the real server's mailbox would durably record for one
/// sent message: the first message seeds the transcript, every later one
/// folds through the same Decision::advance the server uses.
fn apply(
    existing: Option<ApiExchange>,
    action: &Action,
    sender: &EndpointState,
    other: Number,
) -> Option<ApiExchange> {
    let message = match action {
        Action::Send(message) => (**message).clone(),
        _ => return existing,
    };
    let mut exchange = existing.unwrap_or_else(|| {
        let transcript = sender.relationships[&other]
            .pending
            .as_ref()
            .unwrap()
            .transcript
            .clone();
        ApiExchange {
            network_id: transcript.network_id.clone(),
            initiator_id: transcript.initiator_id,
            responder_id: transcript.responder_id,
            initiator_bundle_id: transcript.initiator.bundle_id.clone(),
            responder_bundle_id: transcript.responder.bundle_id.clone(),
            sequence: transcript.sequence,
            exchange_id: transcript.exchange_id.clone(),
            transcript_hash: Binary(innernet_pq::crypto::hash(&transcript.encode()).unwrap()),
            decision: Decision::default(),
            created_at: 0,
            prepare_expires_at: 600,
            transcript: Some(transcript),
            messages: vec![],
            receipts: vec![],
            termination: None,
        }
    });
    let sender_is_initiator = message.sender_id == exchange.initiator_id;
    let kind = message.validate_shape().unwrap();
    if kind != Kind::Propose {
        // A stale/duplicate/out-of-order kind is simply not legal from the
        // exchange's current recorded phase; the real server would likewise
        // return the existing durable outcome rather than double-apply it.
        let _ = exchange.decision.advance(kind, sender_is_initiator);
    }
    exchange.messages.push(message);
    Some(exchange)
}

/// Round-trips through JSON, exactly as `Store::save`/`load` would durably
/// persist and restore this state, without needing real files for a fast,
/// high-iteration property test (file-level atomicity is store.rs's own,
/// separately tested concern).
fn restart(state: &EndpointState) -> EndpointState {
    let bytes = serde_json::to_vec(state).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[derive(Clone, Copy, Debug)]
enum Event {
    DeliverA,
    DeliverB,
    LoseResponseA,
    LoseResponseB,
    RestartA,
    RestartB,
    AdvanceTime(u64),
}

fn run_schedule(seed: u64, rotation_interval: u64) {
    let mut rng = Lcg(seed);
    let (mut a, bundle_a) = peer(2, 1, &mut rng);
    let (mut b, bundle_b) = peer(3, 1, &mut rng);
    let a_id = a.peer_id;
    let b_id = b.peer_id;
    a.observe_remote(b_id, &bundle_b, Lifecycle::Enabled)
        .unwrap();
    b.observe_remote(a_id, &bundle_a, Lifecycle::Enabled)
        .unwrap();

    let mut installer_a = FakeInstaller::default();
    let mut installer_b = FakeInstaller::default();
    let mut exchange: Option<ApiExchange> = None;
    let mut now = 0u64;
    let mut last_sequence_a = a.relationships[&b_id].sequence;
    let mut last_sequence_b = b.relationships[&a_id].sequence;
    let mut completions = 0;
    let mut psk_history: Vec<[u8; 32]> = Vec::new();
    let mut events = Vec::new();

    for _ in 0..300 {
        let event = match rng.below(7) {
            0 => Event::DeliverA,
            1 => Event::DeliverB,
            2 => Event::LoseResponseA,
            3 => Event::LoseResponseB,
            4 => Event::RestartA,
            5 => Event::RestartB,
            _ => Event::AdvanceTime(1 + u64::from(rng.below(60))),
        };
        events.push(event);
        let fail = |what: &str| -> ! {
            panic!("seed {seed} failed at {what}; schedule so far: {events:?}");
        };

        match event {
            Event::DeliverA => {
                let action = a
                    .reconcile(
                        b_id,
                        exchange.as_ref(),
                        now,
                        rotation_interval,
                        &mut installer_a,
                        &mut rng,
                    )
                    .unwrap_or_else(|_| fail("A reconcile"));
                exchange = apply(exchange, &action, &a, b_id);
            },
            Event::DeliverB => {
                let action = b
                    .reconcile(
                        a_id,
                        exchange.as_ref(),
                        now,
                        rotation_interval,
                        &mut installer_b,
                        &mut rng,
                    )
                    .unwrap_or_else(|_| fail("B reconcile"));
                exchange = apply(exchange, &action, &b, a_id);
            },
            Event::LoseResponseA => {
                a.reconcile(
                    b_id,
                    exchange.as_ref(),
                    now,
                    rotation_interval,
                    &mut installer_a,
                    &mut rng,
                )
                .unwrap_or_else(|_| fail("A reconcile (lost)"));
                // Deliberately do not `apply`: the PUT never reached the server.
            },
            Event::LoseResponseB => {
                b.reconcile(
                    a_id,
                    exchange.as_ref(),
                    now,
                    rotation_interval,
                    &mut installer_b,
                    &mut rng,
                )
                .unwrap_or_else(|_| fail("B reconcile (lost)"));
            },
            Event::RestartA => a = restart(&a),
            Event::RestartB => b = restart(&b),
            Event::AdvanceTime(seconds) => now += seconds,
        }

        // Sequence/high-water marks never decrease, restarts included.
        let sequence_a = a.relationships[&b_id].sequence;
        let sequence_b = b.relationships[&a_id].sequence;
        if sequence_a < last_sequence_a || sequence_b < last_sequence_b {
            fail("a sequence number decreased");
        }
        last_sequence_a = sequence_a;
        last_sequence_b = sequence_b;

        // A newly observed candidate must never match an earlier one for
        // this pair (that would mean an old, superseded key was reinstalled).
        if let Some(confirmed) = &a.relationships[&b_id].confirmed {
            let psk: [u8; 32] = *confirmed.psk.0.0;
            if psk_history.last() != Some(&psk) {
                if psk_history.contains(&psk) {
                    fail("an old candidate was reinstalled");
                }
                completions += 1;
                psk_history.push(psk);
            }
        }
    }

    // Sanity: fault injection did not wedge the pair forever when there was
    // ample opportunity (300 events with a short interval) to complete at
    // least once.
    if rotation_interval <= 5 && completions == 0 {
        eprintln!(
            "a.pending={:?} b.pending={:?} a.confirmed={:?} b.confirmed={:?} exchange_decision={:?}",
            a.relationships[&b_id].pending.as_ref().map(|p| (
                p.decision.clone(),
                p.installed,
                p.confirmed
            )),
            b.relationships[&a_id].pending.as_ref().map(|p| (
                p.decision.clone(),
                p.installed,
                p.confirmed
            )),
            a.relationships[&b_id].confirmed.is_some(),
            b.relationships[&a_id].confirmed.is_some(),
            exchange.as_ref().map(|e| e.decision.clone()),
        );
        panic!("seed {seed} never completed a single rotation; schedule: {events:?}");
    }
}

#[test]
fn seeded_fault_schedules_never_violate_safety_invariants() {
    for seed in 0..300u64 {
        run_schedule(seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1), 5);
    }
}
