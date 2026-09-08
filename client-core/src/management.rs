//! Client-side management-link persistence: the PSK protecting this client's
//! own link to the coordination server, distinct from any data-peer PSK.
//! Also drives design 5.10's administrative rotation from the client side:
//! staging an out-of-band artifact, applying it to the live kernel peer
//! entry, confirming it, or rolling back -- entirely operator/script-driven,
//! never touched by the ordinary sync loop.
use anyhow::{anyhow, bail, Context, Result};
use innernet_pq::store::Store;
use innernet_shared::{management::Enrollment, NetworkOpts};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use wireguard_control::{Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

pub fn path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
    data_dir.join(format!("{interface}.client-pq"))
}

/// Local, non-wire persisted state: the active management enrollment plus
/// (once a rotation is under way) a staged candidate and, once applied, the
/// superseded enrollment retained until `confirm` or `rollback`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct ManagementState {
    active: Enrollment,
    #[serde(default)]
    staged: Option<Enrollment>,
    #[serde(default)]
    previous: Option<Enrollment>,
}

fn validate_state(state: &ManagementState) -> Result<()> {
    state.active.validate().map_err(anyhow::Error::msg)?;
    for candidate in state.staged.iter().chain(state.previous.iter()) {
        candidate.validate().map_err(anyhow::Error::msg)?;
    }
    Ok(())
}

/// Read-only peek at the persisted state, for callers (`load`, tests) that
/// never write. Never shares a `Store` handle with a write: the store's
/// generation/digest CAS guard is per-instance, populated only by a `load`
/// on that same instance, so a read-then-separately-opened-write would
/// always look like a conflicting external change.
fn read_state(data_dir: &Path, interface: &InterfaceName) -> Result<Option<ManagementState>> {
    let candidate = path(data_dir, interface);
    if std::fs::symlink_metadata(&candidate).is_err() {
        return Ok(None);
    }
    let mut store = Store::open(&candidate, false).context("opening private management state")?;
    let state: ManagementState = store.load().context("loading private management state")?;
    validate_state(&state)?;
    Ok(Some(state))
}

/// Loads the current state and, if present, hands it to `f` for an in-place
/// update, saving the result back through the *same* `Store` instance --
/// required for the CAS guard above to see a matching generation/digest.
fn update_state(
    data_dir: &Path,
    interface: &InterfaceName,
    f: impl FnOnce(ManagementState) -> Result<ManagementState>,
) -> Result<ManagementState> {
    let candidate = path(data_dir, interface);
    if std::fs::symlink_metadata(&candidate).is_err() {
        bail!("no active management enrollment");
    }
    let mut store = Store::open(&candidate, false).context("opening private management state")?;
    let state: ManagementState = store.load().context("loading private management state")?;
    validate_state(&state)?;
    let updated = f(state)?;
    validate_state(&updated)?;
    store
        .save(&updated)
        .context("persisting private management state")?;
    Ok(updated)
}

/// Persists a freshly redeemed enrollment before the interface is brought up
/// with its PSK, matching design 5.10's "persist at both endpoints before
/// enabling the link". A stale store from an abandoned earlier attempt under
/// the same interface name is overwritten: no established relationship
/// exists without a saved `InterfaceConfig`, which `redeem_invite` gates on.
pub fn adopt(data_dir: &Path, interface: &InterfaceName, enrollment: &Enrollment) -> Result<()> {
    enrollment.validate().map_err(anyhow::Error::msg)?;
    let mut store = Store::open(&path(data_dir, interface), true)
        .context("opening private management state")?;
    if !store.is_fresh() {
        let _existing: ManagementState =
            store.load().context("reopening private management state")?;
    }
    store
        .save(&ManagementState {
            active: enrollment.clone(),
            staged: None,
            previous: None,
        })
        .context("persisting private management state")?;
    Ok(())
}

/// Restores the active management PSK across a client restart, before the
/// interface is (re)configured. Returns `None` for networks that never had
/// one.
pub fn load(data_dir: &Path, interface: &InterfaceName) -> Result<Option<Enrollment>> {
    Ok(read_state(data_dir, interface)?.map(|state| state.active))
}

/// Pushes a new PSK into the live kernel peer entry and removes any
/// existing session -- design 5.10 step 2's "replace peer config both
/// sides with new PSK, remove old sessions". A `wg set` PSK change alone
/// never tears down an already-established session (WireGuard only mixes
/// the PSK into the *next* handshake), so without this a rotation would
/// silently keep encrypting traffic under the superseded secret for up to
/// REJECT_AFTER_TIME (~180s) after "apply" claims to have taken effect.
/// Removing a peer drops every attribute the kernel held for it, so the
/// existing endpoint/allowed-ips/keepalive are read back first and carried
/// forward into the re-added entry -- otherwise the server link would come
/// back reachable-nowhere.
fn push_active_to_kernel(
    interface: &InterfaceName,
    network_opts: &NetworkOpts,
    server_public_key: &str,
    enrollment: &Enrollment,
) -> Result<()> {
    let key =
        Key::from_base64(server_public_key).map_err(|_| anyhow!("invalid server public key"))?;
    let device = Device::get(interface, network_opts.backend)
        .context("reading the current kernel interface state")?;
    let existing = device.peers.iter().find(|p| p.config.public_key == key);

    let mut peer_config =
        PeerConfigBuilder::new(&key).set_preshared_key(Key(*enrollment.psk.bytes()));
    if let Some(existing) = existing {
        if let Some(endpoint) = existing.config.endpoint {
            peer_config = peer_config.set_endpoint(endpoint);
        }
        if let Some(keepalive) = existing.config.persistent_keepalive_interval {
            peer_config = peer_config.set_persistent_keepalive_interval(keepalive);
        }
        if !existing.config.allowed_ips.is_empty() {
            peer_config = peer_config.replace_allowed_ips();
            for ip in &existing.config.allowed_ips {
                peer_config = peer_config.add_allowed_ip(ip.address, ip.cidr);
            }
        }
        DeviceUpdate::new()
            .remove_peer_by_key(&key)
            .apply(interface, network_opts.backend)
            .context("removing the superseded session from the kernel")?;
    }
    DeviceUpdate::new()
        .add_peer(peer_config)
        .apply(interface, network_opts.backend)
        .context("applying the management PSK to the kernel")?;
    Ok(())
}

/// Design 5.10 step 1 (client side): stages a rotation candidate imported
/// from the server's out-of-band transfer artifact, without touching the
/// currently active, live secret.
pub fn stage(data_dir: &Path, interface: &InterfaceName, enrollment: &Enrollment) -> Result<()> {
    enrollment.validate().map_err(anyhow::Error::msg)?;
    update_state(data_dir, interface, |mut state| {
        state.staged = Some(enrollment.clone());
        Ok(state)
    })?;
    Ok(())
}

/// Design 5.10 step 2: promotes the staged candidate into the active
/// secret, retaining the superseded one until `confirm` or `rollback`, and
/// pushes it into the live kernel peer entry immediately -- `fetch()`'s
/// passive peer-diff loop cannot be relied on to notice a changed PSK with
/// nothing else to trigger it.
pub fn apply_active(
    data_dir: &Path,
    interface: &InterfaceName,
    network_opts: &NetworkOpts,
    server_public_key: &str,
) -> Result<()> {
    let state = update_state(data_dir, interface, |mut state| {
        let staged = state
            .staged
            .take()
            .ok_or_else(|| anyhow!("no rotation is staged"))?;
        state.previous = Some(state.active.clone());
        state.active = staged;
        Ok(state)
    })?;
    push_active_to_kernel(interface, network_opts, server_public_key, &state.active)
}

/// Design 5.10 step 3: discards the superseded secret once an operator has
/// verified the newly applied one actually works.
pub fn confirm(data_dir: &Path, interface: &InterfaceName) -> Result<()> {
    update_state(data_dir, interface, |mut state| {
        if state.previous.is_none() {
            bail!("no rotation to confirm");
        }
        state.previous = None;
        Ok(state)
    })?;
    Ok(())
}

/// Design 5.10 step 4's "restore old to both": discards any staged/newly-
/// applied candidate, restores the secret that was active before the
/// rotation attempt began, and pushes it back into the live kernel peer
/// entry immediately.
pub fn rollback(
    data_dir: &Path,
    interface: &InterfaceName,
    network_opts: &NetworkOpts,
    server_public_key: &str,
) -> Result<()> {
    let state = update_state(data_dir, interface, |mut state| {
        let previous = state
            .previous
            .take()
            .ok_or_else(|| anyhow!("no rotation to roll back"))?;
        state.staged = None;
        state.active = previous;
        Ok(state)
    })?;
    push_active_to_kernel(interface, network_opts, server_public_key, &state.active)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment(psk: u8) -> Enrollment {
        Enrollment {
            network_id: [1; 16],
            provision_id: [2; 16],
            peer_id: 3,
            server_id: 1,
            psk: innernet_shared::management::SecretKey::from_bytes([psk; 32]).unwrap(),
        }
    }

    #[test]
    fn adopt_persists_and_load_restores_across_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        assert!(load(dir.path(), &interface).unwrap().is_none());

        let original = enrollment(7);
        adopt(dir.path(), &interface, &original).unwrap();
        let restored = load(dir.path(), &interface).unwrap().unwrap();
        assert_eq!(restored.psk.bytes(), original.psk.bytes());

        // A fresh redemption attempt under the same interface name overwrites
        // an abandoned prior attempt's state.
        let replacement = enrollment(9);
        adopt(dir.path(), &interface, &replacement).unwrap();
        let restored = load(dir.path(), &interface).unwrap().unwrap();
        assert_eq!(restored.psk.bytes(), replacement.psk.bytes());
    }

    #[test]
    fn adopt_rejects_an_invalid_enrollment_before_persisting_anything() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        let mut invalid = enrollment(7);
        invalid.server_id = invalid.peer_id; // self-targeting is never valid.
        assert!(adopt(dir.path(), &interface, &invalid).is_err());
        assert!(!path(dir.path(), &interface).exists());
    }

    #[test]
    fn load_refuses_a_tampered_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        adopt(dir.path(), &interface, &enrollment(7)).unwrap();
        std::fs::write(path(dir.path(), &interface).join("state.json"), b"not json").unwrap();
        assert!(load(dir.path(), &interface).is_err());
    }

    #[test]
    fn stage_requires_an_existing_active_enrollment_and_never_touches_it() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        // No active enrollment yet: nothing to rotate.
        assert!(stage(dir.path(), &interface, &enrollment(9)).is_err());

        adopt(dir.path(), &interface, &enrollment(7)).unwrap();
        stage(dir.path(), &interface, &enrollment(9)).unwrap();
        let state = read_state(dir.path(), &interface).unwrap().unwrap();
        assert_eq!(state.active.psk.bytes(), enrollment(7).psk.bytes());
        assert_eq!(
            state.staged.as_ref().unwrap().psk.bytes(),
            enrollment(9).psk.bytes()
        );
        assert!(state.previous.is_none());
    }

    #[test]
    fn apply_active_requires_a_staged_candidate_and_retains_the_superseded_one() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        adopt(dir.path(), &interface, &enrollment(7)).unwrap();
        let network_opts = NetworkOpts {
            no_routing: false,
            backend: Default::default(),
            mtu: None,
        };

        // No staged candidate yet: the durable state is untouched by the attempt.
        assert!(apply_active(dir.path(), &interface, &network_opts, "").is_err());
        let state = read_state(dir.path(), &interface).unwrap().unwrap();
        assert!(state.staged.is_none() && state.previous.is_none());

        stage(dir.path(), &interface, &enrollment(9)).unwrap();
        // No real "test" WireGuard interface exists in this unit test, so
        // the kernel push fails -- but durable state still advances first,
        // matching redeem_invite's existing persist-then-apply ordering.
        let _ = apply_active(dir.path(), &interface, &network_opts, "");
        let state = read_state(dir.path(), &interface).unwrap().unwrap();
        assert_eq!(state.active.psk.bytes(), enrollment(9).psk.bytes());
        assert!(state.staged.is_none());
        assert_eq!(
            state.previous.as_ref().unwrap().psk.bytes(),
            enrollment(7).psk.bytes()
        );
    }

    #[test]
    fn confirm_requires_an_applied_rotation_and_then_drops_the_superseded_secret() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        adopt(dir.path(), &interface, &enrollment(7)).unwrap();
        assert!(confirm(dir.path(), &interface).is_err());

        stage(dir.path(), &interface, &enrollment(9)).unwrap();
        let _ = apply_active(
            dir.path(),
            &interface,
            &NetworkOpts {
                no_routing: false,
                backend: Default::default(),
                mtu: None,
            },
            "",
        );
        confirm(dir.path(), &interface).unwrap();
        let state = read_state(dir.path(), &interface).unwrap().unwrap();
        assert!(state.previous.is_none());
        assert!(confirm(dir.path(), &interface).is_err());
    }

    #[test]
    fn rollback_restores_the_prior_active_secret_and_discards_the_staged_one() {
        let dir = tempfile::tempdir().unwrap();
        let interface: InterfaceName = "test".parse().unwrap();
        adopt(dir.path(), &interface, &enrollment(7)).unwrap();
        let network_opts = NetworkOpts {
            no_routing: false,
            backend: Default::default(),
            mtu: None,
        };
        assert!(rollback(dir.path(), &interface, &network_opts, "").is_err());

        stage(dir.path(), &interface, &enrollment(9)).unwrap();
        let _ = apply_active(dir.path(), &interface, &network_opts, "");
        let _ = rollback(dir.path(), &interface, &network_opts, "");
        let state = read_state(dir.path(), &interface).unwrap().unwrap();
        assert_eq!(state.active.psk.bytes(), enrollment(7).psk.bytes());
        assert!(state.staged.is_none());
        assert!(state.previous.is_none());
    }
}
