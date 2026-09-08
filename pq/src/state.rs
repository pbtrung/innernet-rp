//! Private endpoint snapshots. These types must never be used as API bodies.
use crate::{
    Error, Result,
    api::{AdvertisedBundle, Lifecycle, Registration},
    crypto::{self, Candidate, HybridSecret, Random, Secret},
    protocol::{Binary, Bundle, Decision, Message, Number, Transcript},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Secret serialization exists only for the owner-only snapshot, not public
/// protocol objects. Deliberately no Debug or Display implementation.
pub struct StoredSecret<const N: usize>(pub Secret<N>);
impl<const N: usize> Clone for StoredSecret<N> {
    fn clone(&self) -> Self {
        Self(Secret::from_bytes(*self.0.0))
    }
}
impl<const N: usize> Serialize for StoredSecret<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(STANDARD.encode(self.0.0.as_slice()));
        serializer.serialize_str(&encoded)
    }
}
impl<'de, const N: usize> Deserialize<'de> for StoredSecret<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        if text.len() != N.div_ceil(3) * 4 {
            return Err(D::Error::custom("invalid private field"));
        }
        let mut value = Secret::from_bytes([0; N]);
        if STANDARD
            .decode_slice(text.as_bytes(), value.0.as_mut_slice())
            .map_err(|_| D::Error::custom("invalid private field"))?
            != N
        {
            return Err(D::Error::custom("invalid private field"));
        }
        if Zeroizing::new(STANDARD.encode(value.0.as_slice())).as_str() != text.as_str() {
            return Err(D::Error::custom("invalid private field"));
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    Strict,
    Permissive,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enrollment {
    Registering,
    Advertised,
    Retiring,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Advertised,
    Legacy,
    Preparing,
    Recovering,
    Confirmed,
    Blocked,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub bundle: Bundle,
    pub kem: StoredSecret<3168>,
    pub x448: StoredSecret<56>,
    pub signing: StoredSecret<66>,
}
impl Identity {
    pub fn generate(wg: Binary<32>, revision: Number, rng: &mut impl Random) -> Result<Self> {
        let id = crypto::random::<16>(rng)?;
        let (hybrid, private) = crypto::hybrid_keypair(rng)?;
        let (signing, signing_private) = crypto::signing_keypair(rng)?;
        Ok(Self {
            bundle: Bundle {
                bundle_id: Binary(*id.0),
                bundle_revision: revision,
                wg_public_key: wg,
                pq_kem_public_key: Binary(hybrid.kem),
                pq_x448_public_key: Binary(hybrid.x448),
                pq_sig_public_key: Binary(signing),
            },
            kem: StoredSecret(private.kem),
            x448: StoredSecret(private.x448),
            signing: StoredSecret(signing_private),
        })
    }
    pub fn hybrid_secret(&self) -> HybridSecret {
        HybridSecret {
            kem: self.kem.clone().0,
            x448: self.x448.clone().0,
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.bundle.validate()?;
        let public = crypto::hybrid_public(&self.hybrid_secret())?;
        if public.kem != self.bundle.pq_kem_public_key.0
            || public.x448 != self.bundle.pq_x448_public_key.0
            || crypto::signing_public(&self.signing.0)? != self.bundle.pq_sig_public_key.0
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedLink {
    pub provision_id: Binary<16>,
    pub psk: StoredSecret<32>,
}
impl StagedLink {
    pub fn generate(rng: &mut impl Random) -> Result<Self> {
        let link = Self {
            provision_id: Binary(*crypto::random::<16>(rng)?.0),
            psk: StoredSecret(crypto::random(rng)?),
        };
        link.validate()?;
        Ok(link)
    }
    pub fn validate(&self) -> Result<()> {
        if self.psk.0.same(&Secret::from_bytes([0; 32])) {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
}

/// A per-peer management-link secret, plus (design 5.10's administrative
/// rotation) an optional durably staged candidate and, once applied, the
/// superseded secret retained until an operator confirms the new one really
/// works. Rotation is entirely operator/script-driven -- nothing in the pq
/// mailbox or the ordinary sync loop ever touches these fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementLink {
    pub provision_id: Binary<16>,
    pub psk: StoredSecret<32>,
    pub verified: bool,
    #[serde(default)]
    pub staged: Option<StagedLink>,
    #[serde(default)]
    pub previous: Option<StagedLink>,
}
impl ManagementLink {
    pub fn generate(rng: &mut impl Random) -> Result<Self> {
        let link = Self {
            provision_id: Binary(*crypto::random::<16>(rng)?.0),
            psk: StoredSecret(crypto::random(rng)?),
            verified: false,
            staged: None,
            previous: None,
        };
        link.validate()?;
        Ok(link)
    }
    pub fn validate(&self) -> Result<()> {
        if self.psk.0.same(&Secret::from_bytes([0; 32])) {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }

    /// Stages a rotation candidate without touching the currently active
    /// secret. Idempotent like `ServerState::provision`: re-staging the same
    /// adopted secret is a no-op; a conflicting adopted secret is refused.
    pub fn stage_rotation(
        &mut self,
        adopted: Option<Secret<32>>,
        rng: &mut impl Random,
    ) -> Result<()> {
        if let Some(existing) = &self.staged {
            if adopted
                .as_ref()
                .is_some_and(|key| !key.same(&existing.psk.0))
            {
                return Err(Error::Conflict);
            }
            return Ok(());
        }
        let mut staged = StagedLink::generate(rng)?;
        if let Some(secret) = adopted {
            staged.psk = StoredSecret(secret);
            staged.validate()?;
        }
        self.staged = Some(staged);
        Ok(())
    }

    /// Promotes the staged candidate into the active secret, retaining the
    /// superseded one until `confirm_rotation` or `rollback_rotation`.
    /// Marks the link unverified: a newly applied secret needs a fresh real
    /// handshake/authenticated request before superseded state is dropped.
    pub fn apply_rotation(&mut self) -> Result<()> {
        let staged = self.staged.take().ok_or(Error::Conflict)?;
        self.previous = Some(StagedLink {
            provision_id: self.provision_id.clone(),
            psk: self.psk.clone(),
        });
        self.provision_id = staged.provision_id;
        self.psk = staged.psk;
        self.verified = false;
        Ok(())
    }

    /// Discards the superseded secret once an operator has verified the
    /// newly applied one actually works. Requires `verified` -- this is
    /// what finally gives `verified`/`mark_verified` a real purpose.
    pub fn confirm_rotation(&mut self) -> Result<()> {
        if self.previous.is_none() {
            return Err(Error::Conflict);
        }
        if !self.verified {
            return Err(Error::Conflict);
        }
        self.previous = None;
        Ok(())
    }

    /// Design 5.10 step 4's "restore old to both": discards any staged/
    /// newly-applied candidate and restores the secret that was active
    /// before the rotation attempt began, which was necessarily already
    /// verified working.
    pub fn rollback_rotation(&mut self) -> Result<()> {
        let previous = self.previous.take().ok_or(Error::Conflict)?;
        self.staged = None;
        self.provision_id = previous.provision_id;
        self.psk = previous.psk;
        self.verified = true;
        Ok(())
    }

    /// Unconditional out-of-band repair for a mismatched installation:
    /// forces the active secret to an explicitly chosen value, independent
    /// of any in-progress staged/previous rotation state.
    pub fn force_active(&mut self, secret: Secret<32>, rng: &mut impl Random) -> Result<()> {
        let mut forced = StagedLink::generate(rng)?;
        forced.psk = StoredSecret(secret);
        forced.validate()?;
        self.provision_id = forced.provision_id;
        self.psk = forced.psk;
        self.verified = false;
        self.staged = None;
        self.previous = None;
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateSecrets {
    pub psk: StoredSecret<32>,
    pub initiator_confirmation: StoredSecret<32>,
    pub responder_confirmation: StoredSecret<32>,
}
impl From<Candidate> for CandidateSecrets {
    fn from(value: Candidate) -> Self {
        Self {
            psk: StoredSecret(value.psk),
            initiator_confirmation: StoredSecret(value.initiator_confirmation),
            responder_confirmation: StoredSecret(value.responder_confirmation),
        }
    }
}
impl CandidateSecrets {
    pub fn candidate(&self) -> Candidate {
        Candidate {
            psk: self.psk.clone().0,
            initiator_confirmation: self.initiator_confirmation.clone().0,
            responder_confirmation: self.responder_confirmation.clone().0,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub transcript: Transcript,
    pub candidate: CandidateSecrets,
    pub decision: Decision,
    pub outbox: Vec<Message>,
    pub installation_intent: bool,
    pub installed: bool,
    pub confirmed: bool,
    pub attempts: u32,
    pub next_retry_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmed {
    pub local_bundle_id: Binary<16>,
    pub remote_bundle_id: Binary<16>,
    pub sequence: Number,
    pub exchange_id: Binary<16>,
    pub transcript_hash: Binary<32>,
    pub psk: StoredSecret<32>,
    pub completed_at: u64,
}

/// A tunnel-activity baseline (design 5.12): sampled WireGuard byte counters
/// and when they last showed a change. Absent (`None` on `Relationship`)
/// means "never sampled yet" -- itself treated as activity, matching
/// "first observation... counts as activity", so a pre-M5 persisted
/// relationship (or one whose kernel peer never existed yet) is never
/// wrongly judged idle.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub last_active_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationship {
    pub remote: Bundle,
    pub sequence: Number,
    pub prior_pq: bool,
    pub operator_psk_id: Binary<16>,
    pub operator_psk: StoredSecret<32>,
    pub confirmed: Option<Confirmed>,
    pub pending: Option<Pending>,
    pub gated: bool,
    pub status: Status,
    #[serde(default)]
    pub activity: Option<Activity>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointState {
    pub network_id: Binary<16>,
    pub peer_id: Number,
    pub server_id: Number,
    pub server_public_key: Binary<32>,
    pub policy: Policy,
    pub identity: Identity,
    pub enrollment: Enrollment,
    pub registration: Registration,
    pub management: ManagementLink,
    pub relationships: BTreeMap<Number, Relationship>,
}
impl EndpointState {
    pub fn validate(&self) -> Result<()> {
        if self.peer_id == self.server_id || self.relationships.len() > 10_000 {
            return Err(Error::Invalid);
        }
        self.identity.validate()?;
        self.management.validate()?;
        if self.registration.bundle != self.identity.bundle {
            return Err(Error::Invalid);
        }
        for (other, relationship) in &self.relationships {
            if *other == self.peer_id || *other == self.server_id {
                return Err(Error::Invalid);
            }
            relationship.remote.validate()?;
            if let Some(pending) = &relationship.pending {
                pending.transcript.validate()?;
                let t = &pending.transcript;
                if t.network_id != self.network_id
                    || t.initiator_id != self.peer_id.min(*other)
                    || t.responder_id != self.peer_id.max(*other)
                    || t.sequence > relationship.sequence
                    || pending.outbox.len() > 8
                {
                    return Err(Error::Invalid);
                }
                let local = if self.peer_id < *other {
                    &t.initiator
                } else {
                    &t.responder
                };
                let remote = if self.peer_id < *other {
                    &t.responder
                } else {
                    &t.initiator
                };
                if local != &self.identity.bundle || remote != &relationship.remote {
                    return Err(Error::Invalid);
                }
                for message in &pending.outbox {
                    if message.sender_id != self.peer_id {
                        return Err(Error::Invalid);
                    }
                    message.authenticate(t)?;
                    message.confirm(&pending.candidate.candidate())?;
                }
            }
        }
        Ok(())
    }

    /// The caller must save this transition before sending its public request.
    pub fn replace(&mut self, identity: Identity) -> Result<()> {
        if self.relationships.values().any(|r| r.pending.is_some()) {
            return Err(Error::Conflict);
        }
        if identity.bundle.wg_public_key != self.identity.bundle.wg_public_key
            || identity.bundle.bundle_id == self.identity.bundle.bundle_id
            || identity.bundle.bundle_revision != self.identity.bundle.bundle_revision.next()?
        {
            return Err(Error::Invalid);
        }
        identity.validate()?;
        self.registration = Registration {
            expected_revision: Some(self.identity.bundle.bundle_revision),
            pq_version: 1,
            lifecycle: Lifecycle::Enabled,
            bundle: identity.bundle.clone(),
            emergency: false,
        };
        self.identity = identity;
        self.enrollment = Enrollment::Registering;
        // Prior protection and operator/confirmed keys survive replacement. Old
        // generation counters are not reused under the new bundle identity.
        for r in self.relationships.values_mut() {
            r.gated = true;
            r.status = Status::Blocked;
        }
        Ok(())
    }

    pub fn accept_registration(&mut self, advertised: &AdvertisedBundle) -> Result<()> {
        if advertised.bundle != self.registration.bundle
            || advertised.lifecycle != self.registration.lifecycle
            || advertised.pq_version != 1
        {
            return Err(Error::Conflict);
        }
        self.enrollment = if advertised.lifecycle == Lifecycle::Enabled {
            Enrollment::Advertised
        } else {
            Enrollment::Retired
        };
        Ok(())
    }

    /// Reconcile a freshly fetched remote bundle (a directory fetch, not an
    /// exchange message). Refreshes the cached copy on a strictly newer
    /// revision, invalidating any pending exchange pinned to the stale
    /// bundle ID; rejects a replayed/older revision; blocks a retired remote.
    pub fn observe_remote(
        &mut self,
        other: Number,
        bundle: &Bundle,
        lifecycle: Lifecycle,
    ) -> Result<()> {
        if other == self.peer_id || other == self.server_id {
            return Err(Error::Invalid);
        }
        bundle.validate()?;
        let is_new = !self.relationships.contains_key(&other);
        if is_new && lifecycle == Lifecycle::Retired {
            return Err(Error::Invalid);
        }
        let relationship = self
            .relationships
            .entry(other)
            .or_insert_with(|| Relationship {
                remote: bundle.clone(),
                sequence: Number::new(1).expect("1 is nonzero"),
                prior_pq: false,
                operator_psk_id: Binary([0; 16]),
                operator_psk: StoredSecret(Secret::from_bytes([0; 32])),
                confirmed: None,
                pending: None,
                gated: false,
                status: Status::Advertised,
                activity: None,
            });
        if !is_new {
            if bundle.bundle_revision < relationship.remote.bundle_revision
                || (bundle.bundle_revision == relationship.remote.bundle_revision
                    && bundle != &relationship.remote)
            {
                return Err(Error::Conflict);
            }
            let previous = relationship.remote.clone();
            relationship.remote = bundle.clone();
            if bundle.bundle_id != previous.bundle_id
                && let Some(pending) = &relationship.pending
            {
                let remote_slot = if self.peer_id < other {
                    &pending.transcript.responder
                } else {
                    &pending.transcript.initiator
                };
                if remote_slot.bundle_id == previous.bundle_id {
                    relationship.pending = None;
                }
            }
        }
        if lifecycle == Lifecycle::Retired {
            relationship.status = Status::Blocked;
            relationship.pending = None;
        } else if relationship.status == Status::Blocked && !relationship.gated {
            relationship.status = Status::Advertised;
        }
        Ok(())
    }

    /// Samples this relationship's current WireGuard byte counters (design
    /// 5.12). Activity is "new" whenever the sampled counters differ at all
    /// from the stored baseline -- covering both a genuine increase and a
    /// reset-to-a-different-value from peer recreation/interface reset,
    /// without ever subtracting (sidesteps the underflow concern by never
    /// computing a delta magnitude, only equality). A first observation
    /// (no baseline yet) always counts as activity. An unchanged sample
    /// leaves `last_active_at` untouched.
    pub fn observe_activity(
        &mut self,
        other: Number,
        now: u64,
        rx_bytes: u64,
        tx_bytes: u64,
    ) -> Result<()> {
        let relationship = self.relationships.get_mut(&other).ok_or(Error::Invalid)?;
        let changed = match &relationship.activity {
            None => true,
            Some(a) => a.rx_bytes != rx_bytes || a.tx_bytes != tx_bytes,
        };
        if changed {
            relationship.activity = Some(Activity {
                rx_bytes,
                tx_bytes,
                last_active_at: now,
            });
        }
        Ok(())
    }

    /// Explicit administrative disable (design 5.11): unlike
    /// `emergency_retire`, this is an ordinary action over locally-trusted
    /// state, not a response to lost/corrupt keys, so it must *retain*
    /// `confirmed`/sequence/`prior_pq` state rather than discard it --
    /// "retain recovery/replay state until retirement is durable". Each
    /// relationship's in-flight `pending` exchange is explicitly retired
    /// (design 5.11's "drain... or explicitly retire it", the latter
    /// alternative), not drained to completion. The caller submits this
    /// retirement (`pq_sync::submit_pending_registration`); once the
    /// server confirms it, `enrollment` advances past `Retiring` via
    /// `accept_registration`. A later `replace` with a fresh identity is
    /// how this interface re-enables.
    pub fn disable(&mut self) -> Result<()> {
        if self.enrollment == Enrollment::Retiring
            || self.registration.lifecycle == Lifecycle::Retired
        {
            return Err(Error::Conflict);
        }
        self.registration = Registration {
            expected_revision: Some(self.identity.bundle.bundle_revision),
            pq_version: 1,
            lifecycle: Lifecycle::Retired,
            bundle: self.identity.bundle.clone(),
            emergency: false,
        };
        self.enrollment = Enrollment::Retiring;
        for r in self.relationships.values_mut() {
            r.pending = None;
        }
        Ok(())
    }

    /// Local escape hatch for lost private keys/replay state or a stale
    /// restored backup: block every relationship and discard its recovery
    /// secrets, never resuming them under a later identity. The caller
    /// submits this retirement, then calls `replace` with a freshly
    /// generated identity once it is durably confirmed.
    pub fn emergency_retire(&mut self) -> Result<()> {
        self.registration = Registration {
            expected_revision: Some(self.identity.bundle.bundle_revision),
            pq_version: 1,
            lifecycle: Lifecycle::Retired,
            bundle: self.identity.bundle.clone(),
            emergency: true,
        };
        self.enrollment = Enrollment::Retiring;
        for r in self.relationships.values_mut() {
            r.pending = None;
            r.confirmed = None;
            r.gated = true;
            r.status = Status::Blocked;
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerState {
    pub network_id: Binary<16>,
    pub server_id: Number,
    pub server_public_key: Binary<32>,
    pub links: BTreeMap<Number, ManagementLink>,
}

impl ServerState {
    pub fn validate(&self) -> Result<()> {
        if self.links.len() > 10_000 || self.links.contains_key(&self.server_id) {
            return Err(Error::Invalid);
        }
        for link in self.links.values() {
            link.validate()?;
        }
        Ok(())
    }
    pub fn provision(
        &mut self,
        peer: Number,
        adopted: Option<Secret<32>>,
        rng: &mut impl Random,
    ) -> Result<&ManagementLink> {
        if peer == self.server_id {
            return Err(Error::Invalid);
        }
        if let Some(existing) = self.links.get(&peer) {
            if adopted
                .as_ref()
                .is_some_and(|key| !key.same(&existing.psk.0))
            {
                return Err(Error::Conflict);
            }
        } else {
            if self.links.len() >= 10_000 {
                return Err(Error::Conflict);
            }
            let mut link = ManagementLink::generate(rng)?;
            if let Some(secret) = adopted {
                link.psk = StoredSecret(secret);
                link.validate()?;
            }
            self.links.insert(peer, link);
        }
        self.links.get(&peer).ok_or(Error::Invalid)
    }

    fn link_mut(&mut self, peer: Number) -> Result<&mut ManagementLink> {
        if peer == self.server_id {
            return Err(Error::Invalid);
        }
        self.links.get_mut(&peer).ok_or(Error::Invalid)
    }

    /// Design 5.10 step 1: stage a rotation candidate at both ends without
    /// touching the currently active, live secret.
    pub fn stage_rotation(
        &mut self,
        peer: Number,
        adopted: Option<Secret<32>>,
        rng: &mut impl Random,
    ) -> Result<&ManagementLink> {
        self.link_mut(peer)?.stage_rotation(adopted, rng)?;
        self.links.get(&peer).ok_or(Error::Invalid)
    }

    /// Design 5.10 step 2: replace the live secret with the staged one,
    /// retaining the superseded secret until confirmed or rolled back.
    pub fn apply_rotation(&mut self, peer: Number) -> Result<&ManagementLink> {
        self.link_mut(peer)?.apply_rotation()?;
        self.links.get(&peer).ok_or(Error::Invalid)
    }

    /// Design 5.10 step 3: discard the superseded secret once verified.
    pub fn confirm_rotation(&mut self, peer: Number) -> Result<&ManagementLink> {
        self.link_mut(peer)?.confirm_rotation()?;
        self.links.get(&peer).ok_or(Error::Invalid)
    }

    /// Design 5.10 step 4: restore the secret that was active before the
    /// rotation attempt began.
    pub fn rollback_rotation(&mut self, peer: Number) -> Result<&ManagementLink> {
        self.link_mut(peer)?.rollback_rotation()?;
        self.links.get(&peer).ok_or(Error::Invalid)
    }

    /// Out-of-band repair for a mismatched installation: force this side's
    /// active secret to an explicitly chosen value.
    pub fn force_active(
        &mut self,
        peer: Number,
        secret: Secret<32>,
        rng: &mut impl Random,
    ) -> Result<&ManagementLink> {
        self.link_mut(peer)?.force_active(secret, rng)?;
        self.links.get(&peer).ok_or(Error::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto::SystemRandom, store::Store};

    #[test]
    fn complete_identity_and_management_secrets_survive_private_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private");
        let identity =
            Identity::generate(Binary([7; 32]), Number::new(1).unwrap(), &mut SystemRandom)
                .unwrap();
        let mut state = EndpointState {
            network_id: Binary([1; 16]),
            peer_id: Number::new(2).unwrap(),
            server_id: Number::new(1).unwrap(),
            server_public_key: Binary([9; 32]),
            policy: Policy::Strict,
            registration: Registration {
                expected_revision: None,
                pq_version: 1,
                lifecycle: Lifecycle::Enabled,
                bundle: identity.bundle.clone(),
                emergency: false,
            },
            identity,
            enrollment: Enrollment::Registering,
            management: ManagementLink::generate(&mut SystemRandom).unwrap(),
            relationships: BTreeMap::new(),
        };
        state.validate().unwrap();
        let mut store = Store::open(&path, true).unwrap();
        store.save(&state).unwrap();
        drop(store);
        let mut store = Store::open(&path, false).unwrap();
        let restored: EndpointState = store.load().unwrap();
        restored.validate().unwrap();
        assert!(restored.identity.kem.0.same(&state.identity.kem.0));
        assert!(restored.management.psk.0.same(&state.management.psk.0));
        let next = Identity::generate(Binary([7; 32]), Number::new(2).unwrap(), &mut SystemRandom)
            .unwrap();
        state.replace(next).unwrap();
        state.validate().unwrap();
        store.save(&state).unwrap();
        assert!(state.registration.expected_revision.is_some());
        let response = AdvertisedBundle {
            pq_version: 1,
            lifecycle: Lifecycle::Enabled,
            bundle: state.identity.bundle.clone(),
        };
        state.accept_registration(&response).unwrap();
        assert_eq!(state.enrollment, Enrollment::Advertised);
    }

    fn base_state(peer_id: u64, server_id: u64) -> EndpointState {
        let identity =
            Identity::generate(Binary([7; 32]), Number::new(1).unwrap(), &mut SystemRandom)
                .unwrap();
        EndpointState {
            network_id: Binary([1; 16]),
            peer_id: Number::new(peer_id).unwrap(),
            server_id: Number::new(server_id).unwrap(),
            server_public_key: Binary([9; 32]),
            policy: Policy::Strict,
            registration: Registration {
                expected_revision: None,
                pq_version: 1,
                lifecycle: Lifecycle::Enabled,
                bundle: identity.bundle.clone(),
                emergency: false,
            },
            identity,
            enrollment: Enrollment::Registering,
            management: ManagementLink::generate(&mut SystemRandom).unwrap(),
            relationships: BTreeMap::new(),
        }
    }

    fn dummy_pending(local: &Bundle, remote: &Bundle, initiator_is_local: bool) -> Pending {
        let (initiator, responder) = if initiator_is_local {
            (local.clone(), remote.clone())
        } else {
            (remote.clone(), local.clone())
        };
        Pending {
            transcript: Transcript {
                network_id: Binary([1; 16]),
                initiator_id: Number::new(1).unwrap(),
                responder_id: Number::new(2).unwrap(),
                initiator,
                responder,
                sequence: Number::new(1).unwrap(),
                exchange_id: Binary([3; 16]),
                operator_psk_id: Binary([0; 16]),
                ciphertext: Binary([0; 1624]),
            },
            candidate: CandidateSecrets {
                psk: StoredSecret(Secret::from_bytes([0; 32])),
                initiator_confirmation: StoredSecret(Secret::from_bytes([1; 32])),
                responder_confirmation: StoredSecret(Secret::from_bytes([2; 32])),
            },
            decision: Decision::default(),
            outbox: vec![],
            installation_intent: false,
            installed: false,
            confirmed: false,
            attempts: 0,
            next_retry_at: 0,
        }
    }

    #[test]
    fn observe_remote_refreshes_cache_and_invalidates_pinned_pending_work() {
        let mut state = base_state(2, 1);
        let other = Number::new(3).unwrap();
        let old_remote =
            Identity::generate(Binary([8; 32]), Number::new(5).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state.relationships.insert(
            other,
            Relationship {
                remote: old_remote.clone(),
                sequence: Number::new(1).unwrap(),
                prior_pq: true,
                operator_psk_id: Binary([0; 16]),
                operator_psk: StoredSecret(Secret::from_bytes([0; 32])),
                confirmed: None,
                pending: Some(dummy_pending(&state.identity.bundle, &old_remote, true)),
                gated: false,
                status: Status::Advertised,
                activity: None,
            },
        );

        // Observing the already-cached bundle again is an idempotent no-op.
        state
            .observe_remote(other, &old_remote, Lifecycle::Enabled)
            .unwrap();
        assert!(state.relationships[&other].pending.is_some());

        // A newer bundle refreshes the cache and invalidates the pinned exchange.
        let new_remote =
            Identity::generate(Binary([8; 32]), Number::new(6).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state
            .observe_remote(other, &new_remote, Lifecycle::Enabled)
            .unwrap();
        assert_eq!(state.relationships[&other].remote, new_remote);
        assert!(state.relationships[&other].pending.is_none());

        // Replaying the now-stale revision is rejected; the refreshed cache stands.
        assert!(
            state
                .observe_remote(other, &old_remote, Lifecycle::Enabled)
                .is_err()
        );
        assert_eq!(state.relationships[&other].remote, new_remote);

        // Retirement blocks the relationship without resurrecting on its own.
        state
            .observe_remote(other, &new_remote, Lifecycle::Retired)
            .unwrap();
        assert_eq!(state.relationships[&other].status, Status::Blocked);

        // A further bundle un-blocks an ungated relationship.
        let newer_remote =
            Identity::generate(Binary([8; 32]), Number::new(7).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state
            .observe_remote(other, &newer_remote, Lifecycle::Enabled)
            .unwrap();
        assert_eq!(state.relationships[&other].status, Status::Advertised);

        // Self/server targets are always rejected.
        assert!(
            state
                .observe_remote(state.peer_id, &newer_remote, Lifecycle::Enabled)
                .is_err()
        );
        assert!(
            state
                .observe_remote(state.server_id, &newer_remote, Lifecycle::Enabled)
                .is_err()
        );
    }

    #[test]
    fn emergency_retirement_blocks_relationships_and_permits_a_fresh_identity() {
        let mut state = base_state(2, 1);
        let other = Number::new(3).unwrap();
        let old_revision = state.identity.bundle.bundle_revision;
        let remote =
            Identity::generate(Binary([8; 32]), Number::new(5).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state.relationships.insert(
            other,
            Relationship {
                remote: remote.clone(),
                sequence: Number::new(4).unwrap(),
                prior_pq: true,
                operator_psk_id: Binary([0; 16]),
                operator_psk: StoredSecret(Secret::from_bytes([0; 32])),
                confirmed: None,
                pending: Some(dummy_pending(&state.identity.bundle, &remote, true)),
                gated: false,
                status: Status::Confirmed,
                activity: None,
            },
        );

        state.emergency_retire().unwrap();
        assert_eq!(state.enrollment, Enrollment::Retiring);
        assert_eq!(state.registration.lifecycle, Lifecycle::Retired);
        assert!(state.registration.emergency);
        assert_eq!(state.registration.expected_revision, Some(old_revision));
        let relationship = &state.relationships[&other];
        assert!(relationship.pending.is_none());
        assert!(relationship.gated);
        assert_eq!(relationship.status, Status::Blocked);
        // The sequence counter is never rewound under a later identity.
        assert_eq!(relationship.sequence, Number::new(4).unwrap());

        let retired = AdvertisedBundle {
            pq_version: 1,
            lifecycle: Lifecycle::Retired,
            bundle: state.registration.bundle.clone(),
        };
        state.accept_registration(&retired).unwrap();
        assert_eq!(state.enrollment, Enrollment::Retired);

        let fresh = Identity::generate(
            Binary([7; 32]),
            old_revision.next().unwrap(),
            &mut SystemRandom,
        )
        .unwrap();
        state.replace(fresh).unwrap();
        assert_eq!(state.enrollment, Enrollment::Registering);
    }

    #[test]
    fn explicit_disable_retains_recovery_state_and_re_enable_never_resets_it() {
        let mut state = base_state(2, 1);
        let other = Number::new(3).unwrap();
        let old_revision = state.identity.bundle.bundle_revision;
        let remote =
            Identity::generate(Binary([8; 32]), Number::new(5).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        let confirmed = Confirmed {
            local_bundle_id: Binary([0; 16]),
            remote_bundle_id: Binary([0; 16]),
            sequence: Number::new(4).unwrap(),
            exchange_id: Binary([0; 16]),
            transcript_hash: Binary([0; 32]),
            psk: StoredSecret(Secret::from_bytes([9; 32])),
            completed_at: 100,
        };
        state.relationships.insert(
            other,
            Relationship {
                remote: remote.clone(),
                sequence: Number::new(4).unwrap(),
                prior_pq: true,
                operator_psk_id: Binary([0; 16]),
                operator_psk: StoredSecret(Secret::from_bytes([0; 32])),
                confirmed: Some(confirmed),
                pending: Some(dummy_pending(&state.identity.bundle, &remote, true)),
                gated: false,
                status: Status::Confirmed,
                activity: None,
            },
        );

        state.disable().unwrap();
        assert_eq!(state.enrollment, Enrollment::Retiring);
        assert_eq!(state.registration.lifecycle, Lifecycle::Retired);
        assert!(!state.registration.emergency); // ordinary disable, not lost-key emergency.
        let relationship = &state.relationships[&other];
        assert!(relationship.pending.is_none()); // explicitly retired, not drained.
        // Unlike emergency_retire, disable retains recovery/replay state
        // until retirement is durable: confirmed/prior_pq/sequence/gated/
        // status are all untouched.
        assert!(relationship.confirmed.is_some());
        assert!(relationship.prior_pq);
        assert!(!relationship.gated);
        assert_eq!(relationship.status, Status::Confirmed);
        assert_eq!(relationship.sequence, Number::new(4).unwrap());

        // Disabling again (or an already-retired lifecycle) is rejected,
        // not silently repeated.
        assert!(state.disable().is_err());

        let retired = AdvertisedBundle {
            pq_version: 1,
            lifecycle: Lifecycle::Retired,
            bundle: state.registration.bundle.clone(),
        };
        state.accept_registration(&retired).unwrap();
        assert_eq!(state.enrollment, Enrollment::Retired);

        // Re-enable: a fresh identity via the existing `replace`, which
        // never resets this relationship's sequence/prior_pq.
        let fresh = Identity::generate(
            Binary([7; 32]),
            old_revision.next().unwrap(),
            &mut SystemRandom,
        )
        .unwrap();
        state.replace(fresh).unwrap();
        assert_eq!(state.enrollment, Enrollment::Registering);
        let relationship = &state.relationships[&other];
        assert_eq!(relationship.sequence, Number::new(4).unwrap());
        assert!(relationship.prior_pq);
        assert!(relationship.gated); // replace blocks pending re-confirmation.
    }

    #[test]
    fn management_provisioning_is_per_peer_idempotent_and_preserves_adopted_keys() {
        let mut server = ServerState {
            network_id: Binary([1; 16]),
            server_id: Number::new(9).unwrap(),
            server_public_key: Binary([1; 32]),
            links: BTreeMap::new(),
        };
        let a = Number::new(1).unwrap();
        let b = Number::new(2).unwrap();
        server
            .provision(a, Some(Secret::from_bytes([7; 32])), &mut SystemRandom)
            .unwrap();
        let first = server.links[&a].clone();
        server.provision(a, None, &mut SystemRandom).unwrap();
        assert_eq!(server.links[&a].provision_id, first.provision_id);
        assert!(server.links[&a].psk.0.same(&first.psk.0));
        server.provision(b, None, &mut SystemRandom).unwrap();
        assert!(!server.links[&b].psk.0.same(&first.psk.0));
        assert!(
            server
                .provision(a, Some(Secret::from_bytes([8; 32])), &mut SystemRandom)
                .is_err()
        );
        assert!(
            server
                .provision(server.server_id, None, &mut SystemRandom)
                .is_err()
        );
        server.validate().unwrap();
    }

    fn server_with_one_link() -> (ServerState, Number) {
        let mut server = ServerState {
            network_id: Binary([1; 16]),
            server_id: Number::new(9).unwrap(),
            server_public_key: Binary([1; 32]),
            links: BTreeMap::new(),
        };
        let a = Number::new(1).unwrap();
        server
            .provision(a, Some(Secret::from_bytes([7; 32])), &mut SystemRandom)
            .unwrap();
        (server, a)
    }

    #[test]
    fn rotation_requires_staging_first_and_apply_retains_the_superseded_secret() {
        let (mut server, a) = server_with_one_link();
        let original_psk = server.links[&a].psk.clone();
        let original_provision_id = server.links[&a].provision_id.clone();

        // Apply/confirm/rollback before any staging is a conflict, not a panic.
        assert!(matches!(server.apply_rotation(a), Err(Error::Conflict)));
        assert!(matches!(server.confirm_rotation(a), Err(Error::Conflict)));
        assert!(matches!(server.rollback_rotation(a), Err(Error::Conflict)));

        server
            .stage_rotation(a, Some(Secret::from_bytes([8; 32])), &mut SystemRandom)
            .unwrap();
        // Staging never touches the currently active, live secret.
        assert!(server.links[&a].psk.0.same(&original_psk.0));
        // Re-staging the same adopted secret is idempotent.
        server
            .stage_rotation(a, Some(Secret::from_bytes([8; 32])), &mut SystemRandom)
            .unwrap();
        // A conflicting adopted secret while already staged is refused.
        assert!(matches!(
            server.stage_rotation(a, Some(Secret::from_bytes([9; 32])), &mut SystemRandom),
            Err(Error::Conflict)
        ));

        server.apply_rotation(a).unwrap();
        assert!(server.links[&a].psk.0.same(&Secret::from_bytes([8; 32])));
        assert_ne!(server.links[&a].provision_id, original_provision_id);
        assert!(!server.links[&a].verified); // a newly applied secret is unconfirmed.
        let previous = server.links[&a].previous.as_ref().unwrap();
        assert!(previous.psk.0.same(&original_psk.0));
        assert_eq!(previous.provision_id, original_provision_id);
        server.validate().unwrap();
    }

    #[test]
    fn confirm_rotation_requires_verified_and_then_drops_the_superseded_secret() {
        let (mut server, a) = server_with_one_link();
        server.stage_rotation(a, None, &mut SystemRandom).unwrap();
        server.apply_rotation(a).unwrap();

        // Cannot confirm an unverified rotation: the old secret stays available.
        assert!(matches!(server.confirm_rotation(a), Err(Error::Conflict)));
        assert!(server.links[&a].previous.is_some());

        server.links.get_mut(&a).unwrap().verified = true;
        server.confirm_rotation(a).unwrap();
        assert!(server.links[&a].previous.is_none());
        // Nothing left to confirm a second time.
        assert!(matches!(server.confirm_rotation(a), Err(Error::Conflict)));
        server.validate().unwrap();
    }

    #[test]
    fn rollback_rotation_restores_the_prior_secret_as_already_verified() {
        let (mut server, a) = server_with_one_link();
        let original_psk = server.links[&a].psk.clone();
        let original_provision_id = server.links[&a].provision_id.clone();
        server.stage_rotation(a, None, &mut SystemRandom).unwrap();
        server.apply_rotation(a).unwrap();
        assert!(!server.links[&a].psk.0.same(&original_psk.0));

        server.rollback_rotation(a).unwrap();
        assert!(server.links[&a].psk.0.same(&original_psk.0));
        assert_eq!(server.links[&a].provision_id, original_provision_id);
        assert!(server.links[&a].verified); // the restored secret was already working.
        assert!(server.links[&a].staged.is_none());
        assert!(server.links[&a].previous.is_none());
        server.validate().unwrap();
    }

    #[test]
    fn force_active_repairs_a_mismatched_installation_unconditionally() {
        let (mut server, a) = server_with_one_link();
        // Even mid-rotation, force wins and clears all rotation bookkeeping.
        server.stage_rotation(a, None, &mut SystemRandom).unwrap();
        server
            .force_active(a, Secret::from_bytes([42; 32]), &mut SystemRandom)
            .unwrap();
        assert!(server.links[&a].psk.0.same(&Secret::from_bytes([42; 32])));
        assert!(!server.links[&a].verified);
        assert!(server.links[&a].staged.is_none());
        assert!(server.links[&a].previous.is_none());
        server.validate().unwrap();
    }

    #[test]
    fn rotation_on_an_unprovisioned_or_server_peer_is_rejected() {
        let (mut server, _a) = server_with_one_link();
        let never_provisioned = Number::new(2).unwrap();
        assert!(matches!(
            server.stage_rotation(never_provisioned, None, &mut SystemRandom),
            Err(Error::Invalid)
        ));
        assert!(matches!(
            server.stage_rotation(server.server_id, None, &mut SystemRandom),
            Err(Error::Invalid)
        ));
    }

    #[test]
    fn observe_activity_records_first_observation_and_only_changed_samples() {
        let mut state = base_state(2, 1);
        let other = Number::new(3).unwrap();
        let remote =
            Identity::generate(Binary([8; 32]), Number::new(5).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state
            .observe_remote(other, &remote, Lifecycle::Enabled)
            .unwrap();
        assert!(state.relationships[&other].activity.is_none());

        // First observation always counts as activity, even a (0, 0) sample.
        state.observe_activity(other, 100, 0, 0).unwrap();
        let activity = state.relationships[&other].activity.as_ref().unwrap();
        assert_eq!((activity.rx_bytes, activity.tx_bytes), (0, 0));
        assert_eq!(activity.last_active_at, 100);

        // An unchanged sample later leaves the baseline (and its timestamp) alone.
        state.observe_activity(other, 200, 0, 0).unwrap();
        assert_eq!(
            state.relationships[&other]
                .activity
                .as_ref()
                .unwrap()
                .last_active_at,
            100
        );

        // A genuine increase updates both the baseline and the timestamp.
        state.observe_activity(other, 300, 10, 5).unwrap();
        let activity = state.relationships[&other].activity.as_ref().unwrap();
        assert_eq!((activity.rx_bytes, activity.tx_bytes), (10, 5));
        assert_eq!(activity.last_active_at, 300);

        // A reset to a lower (but different) value also counts as activity,
        // without ever subtracting.
        state.observe_activity(other, 400, 2, 1).unwrap();
        let activity = state.relationships[&other].activity.as_ref().unwrap();
        assert_eq!((activity.rx_bytes, activity.tx_bytes), (2, 1));
        assert_eq!(activity.last_active_at, 400);

        assert!(
            state
                .observe_activity(Number::new(99).unwrap(), 0, 0, 0)
                .is_err()
        );
    }

    #[test]
    fn a_pre_m5_relationship_without_activity_deserializes_to_none() {
        let mut state = base_state(2, 1);
        let other = Number::new(3).unwrap();
        let remote =
            Identity::generate(Binary([8; 32]), Number::new(5).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state
            .observe_remote(other, &remote, Lifecycle::Enabled)
            .unwrap();

        // Simulate a pre-M5 persisted relationship by serializing to a JSON
        // value and dropping the `activity` field entirely (as a pre-M5
        // Store's state.json would never have had it), then deserializing.
        let mut value = serde_json::to_value(&state).unwrap();
        value["relationships"][&other.get().to_string()]
            .as_object_mut()
            .unwrap()
            .remove("activity");
        let restored: EndpointState = serde_json::from_value(value).unwrap();
        assert!(restored.relationships[&other].activity.is_none());
    }
}
