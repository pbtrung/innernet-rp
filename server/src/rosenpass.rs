//! Runs the server's own Rosenpass keypair lifecycle, exchange daemon, and PSK application, so
//! the coordination API's own WireGuard link can carry Rosenpass PSKs too (design.md 5.9).
//!
//! This mirrors `client_core::rosenpass::sync` closely, but differs in how it sources data:
//! the server already has every peer's row (including its own) directly in its database, so
//! there's no HTTP round trip needed to "fetch" a peer's key or "register" its own - both are
//! direct reads/writes against the same `Connection` the rest of the server already uses.
//!
//! Deliberately does **not** exclude peers lacking a Rosenpass key from the server's own device,
//! even when the server is started with `--rosenpass-permissive` unset (strict mode only
//! applies client-side, see `client_core::interface::apply_rosenpass_visibility_policy`): the
//! server must remain reachable to every enrolled peer for redemption/coordination to keep
//! working regardless of that peer's Rosenpass status. Only the PSK on that specific link is
//! conditional - never the peer's ability to reach the server at all.

use crate::{db::DatabasePeer, Db};
use innernet_shared::{
    rosenpass::{self, DaemonPaths, RosenpassKeyPaths, RosenpassPeerConfig},
    Endpoint, PeerContents, RosenpassOpts,
};
use std::{path::PathBuf, time::Duration};
use wireguard_control::{Backend, InterfaceName};

/// Spawns a periodic task running the server's Rosenpass sync, if enabled. A no-op if
/// `rosenpass_opts.enable_rosenpass` is false.
pub fn spawn(
    db: Db,
    interface: InterfaceName,
    backend: Backend,
    data_dir: PathBuf,
    our_wg_public_key: String,
    wg_listen_port: u16,
    rosenpass_opts: RosenpassOpts,
) {
    if !rosenpass_opts.enable_rosenpass {
        return;
    }
    tokio::task::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            if let Err(e) = sync(
                &db,
                &interface,
                backend,
                &data_dir,
                &our_wg_public_key,
                wg_listen_port,
                rosenpass_opts.rosenpass_group.as_deref(),
            ) {
                log::error!("failed to sync server-side rosenpass state: {e}");
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn sync(
    db: &Db,
    interface: &InterfaceName,
    backend: Backend,
    data_dir: &std::path::Path,
    our_wg_public_key: &str,
    wg_listen_port: u16,
    drop_privileges_group: Option<&str>,
) -> anyhow::Result<()> {
    let rosenpass_dir = rosenpass::interface_rosenpass_dir(data_dir, interface);
    let key_paths = RosenpassKeyPaths::new(&rosenpass_dir);
    if !key_paths.exist() {
        log::info!("generating rosenpass keypair for server interface {interface}");
        rosenpass::generate_keypair(&key_paths)?;
    }
    let our_rosenpass_key = rosenpass::read_public_key_base64(&key_paths)?;

    let rosenpass_port = wg_listen_port.checked_add(1).unwrap_or_else(|| {
        log::warn!(
            "WireGuard listen port {wg_listen_port} has no room for the conventional \
             rosenpass_port+1 rosenpass port; falling back to 51821"
        );
        51821
    });

    // Collect everything we need from the database up front and release the lock before the
    // (potentially slower) subprocess/filesystem work below - other request handlers need this
    // same lock and shouldn't be blocked on it.
    let (peers, our_peer_id) = {
        let conn = db.lock();
        let mut peers = DatabasePeer::list_enabled(&conn)?;

        let self_idx = peers.iter().position(|p| p.public_key == our_wg_public_key);
        let our_rosenpass_addr = self_idx
            .and_then(|i| peers[i].endpoint.as_ref())
            .map(|wg_endpoint| wg_endpoint.with_port(rosenpass_port));

        if let Some(i) = self_idx {
            sync_registration(
                &conn,
                &mut peers[i],
                &our_rosenpass_key,
                our_rosenpass_addr.as_ref(),
            )?;
        }

        let our_peer_id = self_idx.map(|i| peers[i].id);
        let peers = peers.into_iter().map(|p| p.inner).collect::<Vec<_>>();
        (peers, our_peer_id)
    };

    // Same dial/listen tie-break as the client (see client_core::rosenpass::sync and
    // rosenpass::we_dial) - exactly one side of each pair must dial, or the two sides derive
    // different, silently mismatched PSKs. As the server (always peer id 1), `we_dial` always
    // evaluates to false here: the server never dials, only ever listens.
    let peer_configs: Vec<RosenpassPeerConfig> = peers
        .iter()
        .filter(|p| !p.is_disabled && p.public_key != our_wg_public_key)
        .filter_map(|p| {
            let raw_key = p.rosenpass_public_key.as_deref()?;
            match cache_peer_key(&rosenpass_dir, p.id, raw_key) {
                Ok(public_key_path) => {
                    let we_dial =
                        our_peer_id.is_some_and(|our_id| rosenpass::we_dial(our_id, p.id));
                    let endpoint = we_dial
                        .then(|| p.rosenpass_addr.as_ref())
                        .flatten()
                        .and_then(|e| e.resolve().ok());
                    Some(RosenpassPeerConfig {
                        peer_id: p.id,
                        public_key_path,
                        endpoint,
                    })
                },
                Err(e) => {
                    log::warn!("failed to cache rosenpass key for peer {}: {e}", p.id);
                    None
                },
            }
        })
        .collect();

    rosenpass::ensure_daemon_running(
        &rosenpass_dir,
        &key_paths,
        rosenpass_port,
        &peer_configs,
        drop_privileges_group,
    )?;

    rosenpass::apply_psks(
        interface,
        backend,
        &rosenpass_dir,
        &our_rosenpass_key,
        &peer_configs,
        &peers,
    )?;

    Ok(())
}

/// Registers the server's own Rosenpass public key/address directly in its own database row,
/// but only if it doesn't already match (see `client_core::rosenpass`'s equivalent for why this
/// is idempotent rather than unconditional).
fn sync_registration(
    conn: &rusqlite::Connection,
    self_peer: &mut DatabasePeer,
    our_rosenpass_key: &str,
    our_rosenpass_addr: Option<&Endpoint>,
) -> anyhow::Result<()> {
    let already_registered = self_peer.rosenpass_public_key.as_deref() == Some(our_rosenpass_key)
        && self_peer.rosenpass_addr.as_ref() == our_rosenpass_addr;
    if already_registered {
        return Ok(());
    }

    log::info!("registering server's own rosenpass public key/address");
    self_peer.update(
        conn,
        PeerContents {
            rosenpass_public_key: Some(our_rosenpass_key.to_string()),
            rosenpass_addr: our_rosenpass_addr.cloned(),
            ..self_peer.contents.clone()
        },
    )?;

    Ok(())
}

/// Ensures a peer's raw public key is cached locally, writing it if missing or outdated. Unlike
/// the client's equivalent, no network fetch is ever needed: the server already has every
/// peer's raw key directly in its own database row.
fn cache_peer_key(
    rosenpass_dir: &std::path::Path,
    peer_id: i64,
    raw_key_base64: &str,
) -> anyhow::Result<PathBuf> {
    use base64::Engine;

    let path = DaemonPaths::peer_public_key_path(rosenpass_dir, peer_id);

    let up_to_date =
        rosenpass::read_public_key_base64_at(&path).ok().as_deref() == Some(raw_key_base64);
    if up_to_date {
        return Ok(path);
    }

    let raw = base64::engine::general_purpose::STANDARD
        .decode(raw_key_base64)
        .map_err(|e| {
            anyhow::anyhow!("peer {peer_id}'s stored rosenpass key isn't valid base64: {e}")
        })?;

    if let Some(dir) = path.parent() {
        innernet_shared::ensure_dirs_exist(&[dir])?;
    }
    std::fs::write(&path, &raw)
        .map_err(|e| anyhow::anyhow!("failed to cache rosenpass key for peer {peer_id}: {e}"))?;

    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use innernet_shared::ROSENPASS_PUBLIC_KEY_BASE64_LEN;

    fn dummy_key_base64() -> String {
        "A".repeat(ROSENPASS_PUBLIC_KEY_BASE64_LEN)
    }

    #[test]
    fn test_cache_peer_key_writes_and_skips_when_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let key = dummy_key_base64();

        let path = cache_peer_key(dir.path(), 42, &key).unwrap();
        assert!(path.is_file());
        let cached = rosenpass::read_public_key_base64_at(&path).unwrap();
        assert_eq!(cached, key);

        // Re-caching the same key should be a no-op that doesn't error, not rewrite garbage.
        let path_again = cache_peer_key(dir.path(), 42, &key).unwrap();
        assert_eq!(path, path_again);
    }

    #[test]
    fn test_cache_peer_key_rejects_invalid_base64() {
        let dir = tempfile::tempdir().unwrap();
        // Right length, but not valid base64 (all invalid characters).
        let bad_key = "!".repeat(ROSENPASS_PUBLIC_KEY_BASE64_LEN);
        assert!(cache_peer_key(dir.path(), 1, &bad_key).is_err());
    }

    #[test]
    fn test_cache_peer_key_updates_when_key_changes() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = dummy_key_base64();
        let raw_b = vec![0x42u8; innernet_shared::rosenpass::ROSENPASS_PUBLIC_KEY_LEN];
        let key_b = base64::engine::general_purpose::STANDARD.encode(&raw_b);

        let path = cache_peer_key(dir.path(), 7, &key_a).unwrap();
        assert_eq!(rosenpass::read_public_key_base64_at(&path).unwrap(), key_a);

        cache_peer_key(dir.path(), 7, &key_b).unwrap();
        assert_eq!(rosenpass::read_public_key_base64_at(&path).unwrap(), key_b);
    }
}
