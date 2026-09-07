//! Client-side management-link persistence: the PSK protecting this client's
//! own link to the coordination server, distinct from any data-peer PSK.
use anyhow::{Context, Result};
use innernet_pq::store::Store;
use innernet_shared::management::Enrollment;
use std::path::{Path, PathBuf};
use wireguard_control::InterfaceName;

pub fn path(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
    data_dir.join(format!("{interface}.client-pq"))
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
        let _existing: Enrollment = store.load().context("reopening private management state")?;
    }
    store
        .save(enrollment)
        .context("persisting private management state")?;
    Ok(())
}

/// Restores the management PSK across a client restart, before the interface
/// is (re)configured. Returns `None` for networks that never had one.
pub fn load(data_dir: &Path, interface: &InterfaceName) -> Result<Option<Enrollment>> {
    let candidate = path(data_dir, interface);
    if std::fs::symlink_metadata(&candidate).is_err() {
        return Ok(None);
    }
    let mut store = Store::open(&candidate, false).context("opening private management state")?;
    let enrollment: Enrollment = store.load().context("loading private management state")?;
    enrollment.validate().map_err(anyhow::Error::msg)?;
    Ok(Some(enrollment))
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
}
