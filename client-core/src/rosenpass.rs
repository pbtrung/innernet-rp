//! Client-side Rosenpass orchestration: keypair lifecycle, keeping the server's record of our
//! own key/address in sync, caching peers' keys fetched on demand, and running the exchange
//! daemon with an up-to-date peer list.
//!
//! Registration/caching are intentionally idempotent and cheap rather than "always fetch/send on
//! every fetch cycle": a Rosenpass public key is ~683 KiB base64-encoded, so re-sending or
//! re-fetching it on every periodic `innernet up --daemon` cycle would be wasteful. We compare
//! hashes already present in the `State` we just fetched (no extra round trips) and only
//! act when they differ.

use crate::rest_client::RestClient;
use anyhow::{Context as _, Error};
use base64::Engine;
use innernet_shared::{
    interface_config::ServerInfo,
    rosenpass::{self, DaemonPaths, RosenpassKeyPaths, RosenpassPeerConfig},
    rosenpass_public_key_hash, Peer, RosenpassContents, RosenpassOpts,
};
use std::path::Path;
use wireguard_control::{Backend, InterfaceName};

/// Ensures a Rosenpass keypair exists for this interface (generating one on first use), keeps
/// the server's record of our own public key/address in sync, caches any peers' keys we don't
/// already have, (re)starts the exchange daemon if the resulting peer set/config changed, and
/// applies any newly-derived preshared keys (real or interim) to the WireGuard interface.
///
/// `our_wg_public_key` identifies "ourselves" in `peers` (the just-fetched peer list) — matching
/// the same way the rest of the fetch loop identifies the local interface's own peer entry.
/// `wg_listen_port` is used to derive our own Rosenpass listen port (`wg_listen_port + 1` by
/// convention — see doc/design.md 5.5/8 — not a protocol requirement, just this project's choice
/// of default so operators can predict/firewall it).
#[allow(clippy::too_many_arguments)]
pub fn sync(
    data_dir: &Path,
    interface: &InterfaceName,
    backend: Backend,
    rosenpass_opts: &RosenpassOpts,
    server: &ServerInfo,
    our_wg_public_key: &str,
    wg_listen_port: u16,
    peers: &[Peer],
) -> Result<(), Error> {
    if !rosenpass_opts.enable_rosenpass {
        return Ok(());
    }

    let rosenpass_dir = rosenpass::interface_rosenpass_dir(data_dir, interface);
    let key_paths = RosenpassKeyPaths::new(&rosenpass_dir);
    if !key_paths.exist() {
        log::info!("generating rosenpass keypair for {interface}");
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

    let self_peer = peers.iter().find(|p| p.public_key == our_wg_public_key);
    let our_rosenpass_addr = self_peer
        .and_then(|p| p.endpoint.as_ref())
        .map(|wg_endpoint| wg_endpoint.with_port(rosenpass_port));

    sync_registration(
        server,
        &our_rosenpass_key,
        self_peer,
        our_rosenpass_addr.as_ref(),
    )?;

    // Exactly one side of each peer pair must dial (set `endpoint`); the other must leave it
    // unset and rely solely on its own `listen` socket. Configuring *both* sides to dial each
    // other is not merely redundant - verified against the real `rosenpass` binary, it makes
    // each side independently complete its own handshake, and the two sides derive *different*
    // (silently mismatched) preshared keys, breaking that WireGuard tunnel with no visible
    // error. Both peers must independently reach the same dial/listen assignment without
    // coordinating, so it's derived from something both already know: peer ID. The lower ID
    // always dials the higher one - an arbitrary but deterministic, symmetric tie-break, in the
    // same spirit as sorting both sides' keys for the interim PSK below.
    let our_peer_id = self_peer.map(|p| p.id);

    let rest_client = RestClient::new(server);
    let peer_configs: Vec<RosenpassPeerConfig> = peers
        .iter()
        .filter(|p| !p.is_disabled && p.public_key != our_wg_public_key)
        .filter_map(|p| {
            let hash = p.rosenpass_public_key_hash.as_deref()?;
            match ensure_cached_peer_key(&rest_client, &rosenpass_dir, p.id, hash) {
                Ok(public_key_path) => {
                    let we_dial = our_peer_id.is_some_and(|our_id| our_id < p.id);
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

    rosenpass::ensure_daemon_running(&rosenpass_dir, &key_paths, rosenpass_port, &peer_configs)?;

    rosenpass::apply_psks(
        interface,
        backend,
        &rosenpass_dir,
        &our_rosenpass_key,
        &peer_configs,
        peers,
    )?;

    Ok(())
}

/// Registers our public key/address with the server, but only if it doesn't already match what
/// the server has on record (see module docs on why this is idempotent rather than unconditional).
fn sync_registration(
    server: &ServerInfo,
    our_rosenpass_key: &str,
    self_peer: Option<&Peer>,
    our_rosenpass_addr: Option<&innernet_shared::Endpoint>,
) -> Result<(), Error> {
    let local_hash = rosenpass_public_key_hash(our_rosenpass_key);

    let already_registered = self_peer.is_some_and(|p| {
        p.rosenpass_public_key_hash.as_deref() == Some(local_hash.as_str())
            && p.rosenpass_addr.as_ref() == our_rosenpass_addr
    });

    if already_registered {
        log::debug!("rosenpass key/address already registered and unchanged");
        return Ok(());
    }

    log::info!("registering rosenpass public key/address with server");
    RestClient::new(server).register_rosenpass_key(&RosenpassContents {
        public_key: Some(our_rosenpass_key.to_string()),
        addr: our_rosenpass_addr.cloned(),
    })?;

    Ok(())
}

/// Ensures a peer's raw public key is cached locally at
/// [`DaemonPaths::peer_public_key_path`], fetching it from the server if missing or if its hash
/// no longer matches `expected_hash` (i.e. the peer rotated/changed its key).
fn ensure_cached_peer_key(
    rest_client: &RestClient,
    rosenpass_dir: &Path,
    peer_id: i64,
    expected_hash: &str,
) -> Result<std::path::PathBuf, Error> {
    let path = DaemonPaths::peer_public_key_path(rosenpass_dir, peer_id);

    let up_to_date = rosenpass::read_public_key_base64_at(&path)
        .ok()
        .map(|b64| rosenpass_public_key_hash(&b64))
        .as_deref()
        == Some(expected_hash);
    if up_to_date {
        return Ok(path);
    }

    log::info!("fetching rosenpass public key for peer {peer_id}");
    let fetched = rest_client.get_rosenpass_key(peer_id)?;
    let b64 = fetched.public_key.with_context(|| {
        format!("peer {peer_id} advertised a rosenpass key but the server returned none for it")
    })?;

    if rosenpass_public_key_hash(&b64) != expected_hash {
        anyhow::bail!(
            "peer {peer_id}'s fetched rosenpass key doesn't match its currently-advertised hash \
             (it may have changed keys mid-request; will retry next fetch)"
        );
    }

    let raw = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("server returned a rosenpass key that isn't valid base64")?;

    if let Some(dir) = path.parent() {
        innernet_shared::ensure_dirs_exist(&[dir])?;
    }
    std::fs::write(&path, &raw)
        .with_context(|| format!("failed to cache rosenpass key for peer {peer_id}"))?;

    Ok(path)
}
