//! The real `innernet_pq::engine::Installer` (M4): recreates a WireGuard
//! peer with the candidate PSK and observes genuine kernel handshakes,
//! gating that peer's application traffic around the transition.
//!
//! Stateless by design: `pq::engine::EndpointState::reconcile` already
//! tracks `pending.installed`/`pending.confirmed` durably, so `install` is
//! never called twice for one rotation and `handshake_fresh` can safely
//! read straight from the kernel every call. Freshness proof is structural,
//! not timestamp-comparison: `install` always removes-then-recreates the
//! kernel peer entry, which resets its `last_handshake_time` to `None`, so
//! any `Some(_)` observed afterward is necessarily a handshake under the new
//! instance -- never a stale one carried over from before the rotation.
use crate::gate;
use innernet_pq::{
    api::Lifecycle,
    crypto::Candidate,
    engine::Installer,
    protocol::{Bundle, Number},
    state::{EndpointState, Policy},
    Error as PqError, Result as PqResult,
};
use innernet_shared::{peer_allowed_ip, Peer};
use wireguard_control::{
    AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder,
};

/// Finds the `Peer` directory entry matching a PQ bundle's own WireGuard
/// public key. Shared by `RealInstaller` and the standalone gate helpers
/// below, so every kernel/gate action agrees on the same lookup.
fn find_peer<'a>(peers: &'a [Peer], bundle: &Bundle) -> Option<&'a Peer> {
    let key = Key(bundle.wg_public_key.0).to_base64();
    peers.iter().find(|p| p.public_key == key)
}

/// The allowed IP for every relationship this state knows about, resolved
/// against `peers` (a cached or freshly fetched directory). Used to seed
/// the data gate before any peer gets a kernel entry again -- at cold boot
/// this must rely on a locally cached directory, since the coordination API
/// is reachable only through the very tunnel being restored.
pub fn blocked_allowed_ips(state: &EndpointState, peers: &[Peer]) -> Vec<AllowedIp> {
    state
        .relationships
        .values()
        .filter_map(|relationship| find_peer(peers, &relationship.remote))
        .map(peer_allowed_ip)
        .collect()
}

/// Whether `other` (which currently advertises a PQ bundle iff `has_bundle`)
/// qualifies for permissive mode's legacy exception (design 5.11): a peer
/// with no PQ bundle that has never confirmed PQ with this interface.
/// `prior_pq`, not `confirmed.is_some()`, is the signal that disqualifies a
/// peer -- it is never cleared by `emergency_retire` the way `confirmed`
/// is, so a relationship that ever completed PQ can never slide back into
/// legacy eligibility just because its confirmed state was later reset.
/// Pure and total: `other` need not have a `Relationship` yet (a peer never
/// before seen with a bundle has `prior_pq` vacuously false).
pub fn legacy_eligible(state: &EndpointState, other: Number, has_bundle: bool) -> bool {
    if state.policy != Policy::Permissive || has_bundle {
        return false;
    }
    !state.relationships.get(&other).is_some_and(|r| r.prior_pq)
}

/// Re-verifies the gate for every already-confirmed, no-pending
/// relationship: a cold boot closes every gate regardless of prior
/// confirmation (nftables state does not survive a reboot), and a merely
/// steady-state relationship never otherwise passes back through
/// `engine::reconcile`'s `Committed` arm to trigger a release. Reuses
/// `RealInstaller::handshake_fresh`'s exact kernel-read-and-release logic
/// rather than duplicating it; safe to call every tick; errors for one
/// relationship (an unknown peer, an unreachable device) are logged and do
/// not block reconciling the others, since a closed gate is the fail-closed
/// default.
pub fn reconcile_gate(
    interface: InterfaceName,
    backend: Backend,
    state: &EndpointState,
    peers: &[Peer],
) {
    if state.registration.lifecycle == Lifecycle::Retired {
        // Disabling/disabled: interface::fetch()'s proactive pass just
        // gated every relationship unconditionally; never reopen one here.
        return;
    }
    let mut installer = RealInstaller::new(interface, backend, peers);
    for relationship in state.relationships.values() {
        if relationship.pending.is_some() || relationship.confirmed.is_none() {
            continue;
        }
        if let Err(error) = installer.handshake_fresh(&relationship.remote) {
            log::warn!("checking gate release for a confirmed PQ relationship: {error}");
        }
    }
}

/// Borrows the just-fetched peer directory so it never needs a second
/// network round trip to find a peer's endpoint/keepalive/allowed IP.
pub struct RealInstaller<'a> {
    interface: InterfaceName,
    backend: Backend,
    peers: &'a [Peer],
}

impl<'a> RealInstaller<'a> {
    pub fn new(interface: InterfaceName, backend: Backend, peers: &'a [Peer]) -> Self {
        Self {
            interface,
            backend,
            peers,
        }
    }

    fn find_peer(&self, bundle: &Bundle) -> PqResult<&Peer> {
        find_peer(self.peers, bundle).ok_or(PqError::Installer)
    }
}

impl Installer for RealInstaller<'_> {
    fn install(&mut self, bundle: &Bundle, candidate: &Candidate) -> PqResult<()> {
        let peer = self.find_peer(bundle)?;
        let allowed_ip = peer_allowed_ip(peer);
        let public_key = Key::from_base64(&peer.public_key).map_err(|_| PqError::Installer)?;

        // Gate before touching the kernel peer at all (design 5.6's ordering).
        gate::block(&self.interface, std::slice::from_ref(&allowed_ip))
            .map_err(|_| PqError::Installer)?;

        // Remove, then recreate with the full authorized config and the
        // candidate PSK, in two separate applies: a single DeviceUpdate
        // batching both for the same key must not be relied on to discard
        // the old session, since backends key peer updates by public key
        // and could collapse a remove+add pair into a no-op merge.
        DeviceUpdate::new()
            .add_peer(PeerConfigBuilder::new(&public_key).remove())
            .apply(&self.interface, self.backend)
            .map_err(|_| PqError::Installer)?;

        let mut builder = PeerConfigBuilder::new(&public_key)
            .replace_allowed_ips()
            .add_allowed_ip(allowed_ip.address, allowed_ip.cidr)
            .set_preshared_key(Key(*candidate.psk.0));
        if let Some(interval) = peer.persistent_keepalive_interval {
            builder = builder.set_persistent_keepalive_interval(interval);
        }
        if let Some(endpoint) = peer.endpoint.as_ref().and_then(|e| e.resolve().ok()) {
            builder = builder.set_endpoint(endpoint);
        }
        DeviceUpdate::new()
            .add_peer(builder)
            .apply(&self.interface, self.backend)
            .map_err(|_| PqError::Installer)?;
        Ok(())
    }

    fn handshake_fresh(&mut self, bundle: &Bundle) -> PqResult<bool> {
        let peer = self.find_peer(bundle)?;
        let public_key = Key::from_base64(&peer.public_key).map_err(|_| PqError::Installer)?;
        let device = Device::get(&self.interface, self.backend).map_err(|_| PqError::Installer)?;
        let fresh = device
            .peers
            .iter()
            .find(|p| p.config.public_key == public_key)
            .is_some_and(|p| p.stats.last_handshake_time.is_some());
        if fresh {
            let allowed_ip = peer_allowed_ip(peer);
            gate::release(&self.interface, std::slice::from_ref(&allowed_ip))
                .map_err(|_| PqError::Installer)?;
        }
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use innernet_pq::protocol::Binary;
    use innernet_shared::{NetworkOpts, PeerContents};
    use std::{net::IpAddr, process::Command, time::SystemTime};
    use wireguard_control::{Key, KeyPair};

    fn candidate(byte: u8) -> Candidate {
        Candidate {
            psk: innernet_pq::crypto::Secret::from_bytes([byte; 32]),
            initiator_confirmation: innernet_pq::crypto::Secret::from_bytes([0; 32]),
            responder_confirmation: innernet_pq::crypto::Secret::from_bytes([0; 32]),
        }
    }

    fn fake_peer(id: i64, name: &str, ip: IpAddr, public_key: &Key) -> Peer {
        Peer {
            id,
            contents: PeerContents {
                name: name.parse().unwrap(),
                ip,
                cidr_id: 1,
                public_key: public_key.to_base64(),
                endpoint: None,
                persistent_keepalive_interval: Some(25),
                is_admin: false,
                is_disabled: false,
                is_redeemed: true,
                invite_expires: None,
                candidates: vec![],
            },
        }
    }

    fn endpoint_state(policy: Policy) -> EndpointState {
        use innernet_pq::{
            api::{Lifecycle, Registration},
            crypto::SystemRandom,
            state::{Enrollment, Identity, ManagementLink},
        };
        let identity =
            Identity::generate(Binary([9; 32]), Number::new(1).unwrap(), &mut SystemRandom)
                .unwrap();
        EndpointState {
            network_id: Binary([1; 16]),
            peer_id: Number::new(2).unwrap(),
            server_id: Number::new(1).unwrap(),
            server_public_key: Binary([1; 32]),
            policy,
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
            relationships: std::collections::BTreeMap::new(),
        }
    }

    fn fake_bundle(public_key: &Key) -> Bundle {
        Bundle {
            bundle_id: Binary([1; 16]),
            bundle_revision: innernet_pq::protocol::Number::new(1).unwrap(),
            wg_public_key: Binary(public_key.0),
            pq_kem_public_key: Binary([2; 1568]),
            pq_x448_public_key: Binary([3; 56]),
            pq_sig_public_key: Binary([4; 67]),
        }
    }

    fn with_relationship(mut state: EndpointState, other: Number, prior_pq: bool) -> EndpointState {
        use innernet_pq::{
            crypto::{Secret, SystemRandom},
            state::{Identity, Relationship, Status, StoredSecret},
        };
        let remote =
            Identity::generate(Binary([8; 32]), Number::new(1).unwrap(), &mut SystemRandom)
                .unwrap()
                .bundle;
        state.relationships.insert(
            other,
            Relationship {
                remote,
                sequence: Number::new(1).unwrap(),
                prior_pq,
                operator_psk_id: Binary([0; 16]),
                operator_psk: StoredSecret(Secret::from_bytes([0; 32])),
                confirmed: None,
                pending: None,
                gated: false,
                status: Status::Advertised,
                activity: None,
            },
        );
        state
    }

    #[test]
    fn legacy_eligible_only_for_permissive_bundle_less_never_confirmed_peers() {
        let other = Number::new(3).unwrap();

        // Strict: never eligible, regardless of bundle presence.
        assert!(!legacy_eligible(
            &endpoint_state(Policy::Strict),
            other,
            false
        ));
        assert!(!legacy_eligible(
            &endpoint_state(Policy::Strict),
            other,
            true
        ));

        // Permissive, no relationship yet, no bundle: eligible.
        assert!(legacy_eligible(
            &endpoint_state(Policy::Permissive),
            other,
            false
        ));

        // Permissive, but the peer currently has a bundle: never eligible --
        // the exception is only for a peer with no bundle at all.
        assert!(!legacy_eligible(
            &endpoint_state(Policy::Permissive),
            other,
            true
        ));

        // Permissive, no bundle now, but this relationship previously
        // confirmed PQ (prior_pq): never eligible -- must never silently
        // downgrade a relationship that once succeeded.
        let state = with_relationship(endpoint_state(Policy::Permissive), other, true);
        assert!(!legacy_eligible(&state, other, false));

        // Permissive, no bundle now, relationship exists but never
        // confirmed (e.g. seen a bundle once, then it disappeared before
        // confirming): still eligible.
        let state = with_relationship(endpoint_state(Policy::Permissive), other, false);
        assert!(legacy_eligible(&state, other, false));
    }

    /// Exercises real kernel WireGuard peer installation and nft gating.
    /// Requires root/NET_ADMIN, the `nft` binary, and a Linux kernel
    /// WireGuard module -- a container with `--cap-add NET_ADMIN`, not this
    /// sandbox; never run on a production host.
    #[test]
    #[ignore = "requires root/NET_ADMIN, nft, and a Linux kernel WireGuard module"]
    fn install_recreates_the_peer_with_the_candidate_psk_and_gates_it() {
        let interface: InterfaceName = "wg-pq-instl0".parse().unwrap();
        let own = KeyPair::generate();
        let remote = KeyPair::generate();
        innernet_shared::wg::up(
            &interface,
            &own.private.to_base64(),
            "10.77.0.1/24".parse().unwrap(),
            None,
            None,
            &NetworkOpts {
                no_routing: true,
                backend: Backend::Kernel,
                mtu: None,
            },
        )
        .unwrap();

        let peer = fake_peer(2, "peer-b", "10.77.0.2".parse().unwrap(), &remote.public);
        let bundle = fake_bundle(&remote.public);
        let peers = vec![peer];
        let mut installer = RealInstaller::new(interface, Backend::Kernel, &peers);

        installer.install(&bundle, &candidate(7)).unwrap();
        let device = Device::get(&interface, Backend::Kernel).unwrap();
        let installed = device
            .peers
            .iter()
            .find(|p| p.config.public_key == remote.public)
            .expect("peer installed");
        assert_eq!(installed.config.preshared_key, Some(Key([7; 32])));
        assert_eq!(installed.stats.last_handshake_time, None::<SystemTime>);
        let listed = Command::new("nft")
            .args([
                "list",
                "table",
                "inet",
                &format!("innernet_pq_data_{}", interface.as_str_lossy()),
            ])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&listed.stdout).contains("10.77.0.2"));

        // No real handshake occurred yet: freshness must not be claimed.
        assert!(!installer.handshake_fresh(&bundle).unwrap());

        gate::clear(&interface).unwrap();
        Device::get(&interface, Backend::Kernel)
            .unwrap()
            .delete()
            .unwrap();
    }
}
