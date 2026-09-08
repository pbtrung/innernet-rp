//! Client-side exchange-driving decisions (design 5.4-5.6). Pure: no network
//! or kernel I/O beyond the `Installer` trait, which M3 only fakes; the
//! caller performs the actual HTTP round trip and kernel action and must
//! persist the mutated `EndpointState` before acting on the returned
//! `Action` (never send/install before the corresponding intent is durable).
use crate::{
    Error, Result,
    api::Exchange,
    crypto::{self, Candidate, HybridPublic, Random},
    protocol::{Binary, Bundle, Decision, Kind, Message, Number, Phase, Transcript},
    state::{CandidateSecrets, Confirmed, EndpointState, Pending, Status, StoredSecret},
};

/// Installs a candidate PSK and observes a fresh authenticated handshake.
/// M3 models this; M4 replaces `FakeInstaller` with a real WireGuard-backed
/// implementation (`client_core::pq_install::RealInstaller`) without
/// changing the engine that calls it. A real implementation is expected to
/// gate that peer's application traffic before `install` touches the
/// kernel, and to release that gate as a side effect of `handshake_fresh`
/// returning `true` -- the engine itself has no separate "release the
/// gate" action, so this is the one point in the trait contract where a
/// real installer's gate-release happens.
pub trait Installer {
    fn install(&mut self, bundle: &Bundle, candidate: &Candidate) -> Result<()>;
    fn handshake_fresh(&mut self, bundle: &Bundle) -> Result<bool>;
}

/// Records calls instead of touching real WireGuard state, per M3's mandate
/// to "model a successful PSK installer/handshake observer... without
/// changing real WireGuard state." `handshake_fresh` reports true exactly
/// once per install, modeling a single fresh handshake being observed.
#[derive(Default)]
pub struct FakeInstaller {
    pub installed_psks: std::collections::BTreeMap<[u8; 16], [u8; 32]>,
    handshake_seen: std::collections::BTreeSet<[u8; 16]>,
}
impl Installer for FakeInstaller {
    fn install(&mut self, bundle: &Bundle, candidate: &Candidate) -> Result<()> {
        self.installed_psks
            .insert(bundle.bundle_id.0, *candidate.psk.0);
        self.handshake_seen.remove(&bundle.bundle_id.0);
        Ok(())
    }
    fn handshake_fresh(&mut self, bundle: &Bundle) -> Result<bool> {
        Ok(self.handshake_seen.insert(bundle.bundle_id.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Sign and PUT this message to `/user/pq-handshake/{other}?phase=N`.
    Send(Box<Message>),
    /// The exchange completed; `relationship.confirmed` now holds the PSK.
    Complete,
    /// Nothing to do this cycle.
    None,
}

fn durably_sent(remote: Option<&Exchange>, pending: &Pending, self_id: Number) -> bool {
    let Some(exchange) = remote else { return false };
    if exchange.exchange_id != pending.transcript.exchange_id
        || exchange.sequence != pending.transcript.sequence
    {
        return false;
    }
    // The server's own terminal record (not our possibly-optimistic local
    // mirror of it) subsumes any specific message check: reaching a
    // terminal state server-side already required every necessary message,
    // even one this side can no longer see post-compaction.
    if exchange.decision.terminal() {
        return true;
    }
    match pending.outbox.last() {
        None => true,
        Some(last) => exchange
            .messages
            .iter()
            .any(|m| m.sender_id == self_id && m.message_type == last.message_type),
    }
}

impl EndpointState {
    /// Advances one data-peer relationship by exactly the durable steps that
    /// are ready this cycle. The caller must persist this state before
    /// acting on the returned `Action`.
    pub fn reconcile(
        &mut self,
        other: Number,
        remote: Option<&Exchange>,
        now: u64,
        rotation_interval: u64,
        installer: &mut impl Installer,
        rng: &mut impl Random,
    ) -> Result<Action> {
        if other == self.peer_id || other == self.server_id {
            return Err(Error::Invalid);
        }
        let initiator = self.peer_id < other;
        let self_id = self.peer_id;
        let network_id = self.network_id.clone();
        let local_bundle = self.identity.bundle.clone();
        let signing = self.identity.signing.clone();
        let hybrid_secret = self.identity.hybrid_secret();

        let relationship = self.relationships.get_mut(&other).ok_or(Error::Invalid)?;
        if relationship.gated || relationship.status == Status::Blocked {
            return Ok(Action::None);
        }
        let remote_bundle = relationship.remote.clone();

        if relationship.pending.is_none() {
            if initiator {
                let due = match &relationship.confirmed {
                    None => true,
                    Some(confirmed) => {
                        now.saturating_sub(confirmed.completed_at) >= rotation_interval
                    },
                };
                if !due {
                    return Ok(Action::None);
                }
                let sequence = relationship.sequence;
                relationship.sequence = sequence.next()?;
                let exchange_id = Binary(*crypto::random::<16>(rng)?.0);
                let hybrid_public = HybridPublic {
                    kem: remote_bundle.pq_kem_public_key.0,
                    x448: remote_bundle.pq_x448_public_key.0,
                };
                let (raw_ciphertext, shared) = crypto::encapsulate(&hybrid_public)?;
                let transcript = Transcript {
                    network_id,
                    initiator_id: self_id,
                    responder_id: other,
                    initiator: local_bundle,
                    responder: remote_bundle,
                    sequence,
                    exchange_id,
                    operator_psk_id: relationship.operator_psk_id.clone(),
                    ciphertext: Binary(raw_ciphertext),
                };
                let candidate = crypto::derive(
                    &shared.kem,
                    &shared.x448,
                    &relationship.operator_psk.clone().0,
                    &transcript.encode(),
                )?;
                let message =
                    Message::signed(&transcript, Kind::Propose, self_id, &candidate, &signing.0)?;
                relationship.pending = Some(Pending {
                    transcript,
                    candidate: CandidateSecrets::from(candidate),
                    decision: Decision::default(),
                    outbox: vec![message.clone()],
                    installation_intent: false,
                    installed: false,
                    confirmed: false,
                    attempts: 0,
                    next_retry_at: 0,
                });
                return Ok(Action::Send(Box::new(message)));
            }

            let Some(exchange) = remote else {
                return Ok(Action::None);
            };
            if exchange.decision.phase != Phase::Proposed {
                return Ok(Action::None);
            }
            let Some(transcript) = &exchange.transcript else {
                return Ok(Action::None);
            };
            if transcript.network_id != self.network_id
                || transcript.initiator_id != other
                || transcript.responder_id != self_id
                || transcript.initiator != remote_bundle
                || transcript.responder != local_bundle
            {
                // A stale/mismatched proposal under a superseded bundle; ignore.
                return Ok(Action::None);
            }
            let transcript = transcript.clone();
            let shared = crypto::decapsulate(&transcript.ciphertext.0, &hybrid_secret)?;
            let candidate = crypto::derive(
                &shared.kem,
                &shared.x448,
                &relationship.operator_psk.clone().0,
                &transcript.encode(),
            )?;
            // The propose message carries the initiator's confirmation tag;
            // find and verify it before trusting this candidate.
            let propose = exchange
                .messages
                .iter()
                .find(|m| m.sender_id == other && m.message_type == Kind::Propose as u8)
                .ok_or(Error::Invalid)?;
            propose.authenticate(&transcript)?;
            propose.confirm(&candidate)?;
            let mut decision = Decision::default();
            decision.advance(Kind::Ready, false)?;
            let message =
                Message::signed(&transcript, Kind::Ready, self_id, &candidate, &signing.0)?;
            relationship.pending = Some(Pending {
                transcript,
                candidate: CandidateSecrets::from(candidate),
                decision,
                outbox: vec![message.clone()],
                installation_intent: false,
                installed: false,
                confirmed: false,
                attempts: 0,
                next_retry_at: 0,
            });
            return Ok(Action::Send(Box::new(message)));
        }

        let pending = relationship
            .pending
            .as_mut()
            .expect("checked non-empty above");

        if let Some(exchange) = remote
            && exchange.exchange_id == pending.transcript.exchange_id
            && exchange.sequence == pending.transcript.sequence
        {
            if exchange.decision.terminal() && !pending.decision.terminal() {
                // A terminal record may already be compacted (transcript and
                // messages cleared, per Exchange::compact) if this side is
                // catching up after missing a poll; every prior transition
                // was independently signature-verified before the server
                // (itself running the same Decision::advance) could ever
                // reach a terminal state, so the compact Decision itself is
                // the authoritative, trusted outcome here.
                pending.decision = exchange.decision.clone();
            } else {
                for message in exchange.messages.iter().filter(|m| m.sender_id == other) {
                    let kind = message.validate_shape()?;
                    let sender_is_initiator = message.sender_id == pending.transcript.initiator_id;
                    let mut trial = pending.decision.clone();
                    if trial.advance(kind, sender_is_initiator).is_ok() {
                        message.authenticate(&pending.transcript)?;
                        message.confirm(&pending.candidate.candidate())?;
                        pending.decision = trial;
                    }
                }
            }
        }

        // Always re-check durability here, even if our own local decision
        // already optimistically shows terminal: that local view can be
        // ahead of what the server actually durably recorded (our own final
        // message may have been lost), and only the server's own record
        // (which durably_sent consults) is trustworthy proof of receipt.
        if pending.decision.phase != Phase::Aborted
            && !durably_sent(remote, pending, self_id)
            && let Some(last) = pending.outbox.last()
        {
            return Ok(Action::Send(Box::new(last.clone())));
        }

        match pending.decision.phase {
            Phase::Aborted => {
                relationship.pending = None;
                Ok(Action::None)
            },
            Phase::Proposed => Ok(Action::None), // retry above covers the wait; nothing new to build yet.
            Phase::Ready => {
                if initiator {
                    let candidate = pending.candidate.candidate();
                    let message = Message::signed(
                        &pending.transcript,
                        Kind::Commit,
                        self_id,
                        &candidate,
                        &signing.0,
                    )?;
                    pending.decision.advance(Kind::Commit, true)?;
                    pending.outbox.push(message.clone());
                    Ok(Action::Send(Box::new(message)))
                } else {
                    Ok(Action::None) // responder already replied; waiting for commit.
                }
            },
            Phase::Committed => {
                if !pending.installed {
                    if !initiator || pending.decision.installed[1] {
                        installer
                            .install(&remote_bundle, &pending.candidate.candidate())
                            .map_err(|_| Error::Installer)?;
                        pending.installed = true;
                        let candidate = pending.candidate.candidate();
                        let message = Message::signed(
                            &pending.transcript,
                            Kind::Installed,
                            self_id,
                            &candidate,
                            &signing.0,
                        )?;
                        let sender_is_initiator = self_id == pending.transcript.initiator_id;
                        pending
                            .decision
                            .advance(Kind::Installed, sender_is_initiator)?;
                        pending.outbox.push(message.clone());
                        return Ok(Action::Send(Box::new(message)));
                    }
                    return Ok(Action::None); // initiator waits for the responder's install receipt.
                }
                if !pending.confirmed {
                    if installer
                        .handshake_fresh(&remote_bundle)
                        .map_err(|_| Error::Installer)?
                    {
                        pending.confirmed = true;
                        let candidate = pending.candidate.candidate();
                        let message = Message::signed(
                            &pending.transcript,
                            Kind::Confirmed,
                            self_id,
                            &candidate,
                            &signing.0,
                        )?;
                        let sender_is_initiator = self_id == pending.transcript.initiator_id;
                        pending
                            .decision
                            .advance(Kind::Confirmed, sender_is_initiator)?;
                        pending.outbox.push(message.clone());
                        return Ok(Action::Send(Box::new(message)));
                    }
                    return Ok(Action::None);
                }
                Ok(Action::None) // both locally done; waiting for the peer/server to complete.
            },
            Phase::Complete => {
                relationship.confirmed = Some(Confirmed {
                    local_bundle_id: Binary(local_bundle.bundle_id.0),
                    remote_bundle_id: Binary(remote_bundle.bundle_id.0),
                    sequence: pending.transcript.sequence,
                    exchange_id: pending.transcript.exchange_id.clone(),
                    transcript_hash: Binary(crypto::hash(&pending.transcript.encode())?),
                    psk: StoredSecret(pending.candidate.psk.clone().0),
                    completed_at: now,
                });
                relationship.prior_pq = true;
                relationship.status = Status::Confirmed;
                relationship.pending = None;
                Ok(Action::Complete)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        api::{Exchange as ApiExchange, Lifecycle, Registration},
        crypto::SystemRandom,
        state::{EndpointState, Enrollment, Identity, ManagementLink, Policy},
    };
    use std::collections::BTreeMap;

    fn peer(id: u64, server_id: u64) -> (EndpointState, Bundle) {
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

    /// Mimics just enough of the server's mailbox to test the engine in
    /// isolation: seeds the exchange record's transcript from whichever side
    /// sends first, then folds each subsequent signed message into the same
    /// `Decision::advance` the real server uses. Step 4 replaces this with
    /// the real API.
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
                transcript_hash: Binary(crypto::hash(&transcript.encode()).unwrap()),
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
            exchange
                .decision
                .advance(kind, sender_is_initiator)
                .unwrap();
        }
        exchange.messages.push(message);
        Some(exchange)
    }

    struct Peers<'a> {
        a: &'a mut EndpointState,
        b: &'a mut EndpointState,
        a_id: Number,
        b_id: Number,
        installer_a: &'a mut FakeInstaller,
        installer_b: &'a mut FakeInstaller,
    }

    #[allow(clippy::too_many_arguments)]
    fn converge(peers: Peers, start: u64, rotation_interval: u64, rng: &mut impl Random) -> u64 {
        let Peers {
            a,
            b,
            a_id,
            b_id,
            installer_a,
            installer_b,
        } = peers;
        let mut exchange: Option<ApiExchange> = None;
        let (mut a_done, mut b_done) = (false, false);
        for now in start..start + 40 {
            if !a_done {
                let action = a
                    .reconcile(
                        b_id,
                        exchange.as_ref(),
                        now,
                        rotation_interval,
                        installer_a,
                        rng,
                    )
                    .unwrap();
                if action == Action::Complete {
                    a_done = true;
                }
                exchange = apply(exchange, &action, a, b_id);
            }
            if !b_done {
                let action = b
                    .reconcile(
                        a_id,
                        exchange.as_ref(),
                        now,
                        rotation_interval,
                        installer_b,
                        rng,
                    )
                    .unwrap();
                if action == Action::Complete {
                    b_done = true;
                }
                exchange = apply(exchange, &action, b, a_id);
            }
            if a_done && b_done {
                return now;
            }
        }
        panic!("exchange did not converge within the bounded iteration count");
    }

    #[test]
    fn independent_processes_converge_on_one_candidate_through_the_full_phase_sequence() {
        let (mut a, bundle_a) = peer(2, 1);
        let (mut b, bundle_b) = peer(3, 1);
        let a_id = Number::new(2).unwrap();
        let b_id = Number::new(3).unwrap();
        a.observe_remote(b_id, &bundle_b, Lifecycle::Enabled)
            .unwrap();
        b.observe_remote(a_id, &bundle_a, Lifecycle::Enabled)
            .unwrap();

        let mut rng = SystemRandom;
        let mut installer_a = FakeInstaller::default();
        let mut installer_b = FakeInstaller::default();
        let completed_at = converge(
            Peers {
                a: &mut a,
                b: &mut b,
                a_id,
                b_id,
                installer_a: &mut installer_a,
                installer_b: &mut installer_b,
            },
            0,
            300,
            &mut rng,
        );

        let psk_a: [u8; 32] = *a.relationships[&b_id].confirmed.as_ref().unwrap().psk.0.0;
        let psk_b: [u8; 32] = *b.relationships[&a_id].confirmed.as_ref().unwrap().psk.0.0;
        assert_eq!(psk_a, psk_b);
        assert_eq!(installer_a.installed_psks.len(), 1);
        assert_eq!(installer_b.installed_psks.len(), 1);
        assert!(a.relationships[&b_id].pending.is_none());
        assert!(b.relationships[&a_id].pending.is_none());

        // A second rotation, once due, converges on a genuinely different candidate.
        let second_completed_at = converge(
            Peers {
                a: &mut a,
                b: &mut b,
                a_id,
                b_id,
                installer_a: &mut installer_a,
                installer_b: &mut installer_b,
            },
            completed_at + 300,
            300,
            &mut rng,
        );
        assert!(second_completed_at > completed_at);
        let psk_a_2: [u8; 32] = *a.relationships[&b_id].confirmed.as_ref().unwrap().psk.0.0;
        assert_ne!(psk_a, psk_a_2);
        assert_eq!(installer_a.installed_psks.len(), 1); // same bundle ID, latest PSK overwrote the entry.
    }

    #[test]
    fn rotation_does_not_start_before_the_interval_elapses() {
        let (mut a, bundle_a) = peer(2, 1);
        let (mut b, bundle_b) = peer(3, 1);
        let a_id = Number::new(2).unwrap();
        let b_id = Number::new(3).unwrap();
        a.observe_remote(b_id, &bundle_b, Lifecycle::Enabled)
            .unwrap();
        b.observe_remote(a_id, &bundle_a, Lifecycle::Enabled)
            .unwrap();
        let mut rng = SystemRandom;
        let mut installer_a = FakeInstaller::default();
        let mut installer_b = FakeInstaller::default();
        let completed_at = converge(
            Peers {
                a: &mut a,
                b: &mut b,
                a_id,
                b_id,
                installer_a: &mut installer_a,
                installer_b: &mut installer_b,
            },
            0,
            300,
            &mut rng,
        );

        let action = a
            .reconcile(b_id, None, completed_at, 300, &mut installer_a, &mut rng)
            .unwrap();
        assert_eq!(action, Action::None);
        let action = a
            .reconcile(
                b_id,
                None,
                completed_at + 299,
                300,
                &mut installer_a,
                &mut rng,
            )
            .unwrap();
        assert_eq!(action, Action::None);
        let action = a
            .reconcile(
                b_id,
                None,
                completed_at + 300,
                300,
                &mut installer_a,
                &mut rng,
            )
            .unwrap();
        assert!(matches!(action, Action::Send(_)));
    }

    #[test]
    fn replaying_the_same_snapshot_is_a_safe_no_op() {
        let (mut a, bundle_a) = peer(2, 1);
        let (mut b, bundle_b) = peer(3, 1);
        let a_id = Number::new(2).unwrap();
        let b_id = Number::new(3).unwrap();
        a.observe_remote(b_id, &bundle_b, Lifecycle::Enabled)
            .unwrap();
        b.observe_remote(a_id, &bundle_a, Lifecycle::Enabled)
            .unwrap();
        let mut rng = SystemRandom;
        let mut installer_a = FakeInstaller::default();
        let mut installer_b = FakeInstaller::default();

        // A proposes; B has not replied yet.
        let propose = a
            .reconcile(b_id, None, 0, 300, &mut installer_a, &mut rng)
            .unwrap();
        let exchange = apply(None, &propose, &a, b_id);
        let ready = b
            .reconcile(a_id, exchange.as_ref(), 0, 300, &mut installer_b, &mut rng)
            .unwrap();
        let exchange = apply(exchange, &ready, &b, a_id);

        // Feed the exact same snapshot (B's ready already recorded) to A twice.
        let first = a
            .reconcile(b_id, exchange.as_ref(), 0, 300, &mut installer_a, &mut rng)
            .unwrap();
        let second = a
            .reconcile(b_id, exchange.as_ref(), 0, 300, &mut installer_a, &mut rng)
            .unwrap();
        assert_eq!(first, second);
        assert!(matches!(first, Action::Send(_)));
        assert_eq!(
            a.relationships[&b_id]
                .pending
                .as_ref()
                .unwrap()
                .decision
                .phase,
            Phase::Committed
        );
    }

    #[test]
    fn prepare_ttl_expiry_before_commitment_is_adopted_as_abort() {
        let (mut a, _) = peer(2, 1);
        let (_, bundle_b) = peer(3, 1);
        let b_id = Number::new(3).unwrap();
        a.observe_remote(b_id, &bundle_b, Lifecycle::Enabled)
            .unwrap();
        let mut rng = SystemRandom;
        let mut installer_a = FakeInstaller::default();

        let propose = a
            .reconcile(b_id, None, 0, 300, &mut installer_a, &mut rng)
            .unwrap();
        let mut exchange = apply(None, &propose, &a, b_id).unwrap();
        // The server's sweep expired this before B replied; no signed abort exists.
        exchange.decision.expire();
        assert_eq!(exchange.decision.phase, Phase::Aborted);

        let action = a
            .reconcile(b_id, Some(&exchange), 700, 300, &mut installer_a, &mut rng)
            .unwrap();
        assert_eq!(action, Action::None);
        assert!(a.relationships[&b_id].pending.is_none());
    }
}
