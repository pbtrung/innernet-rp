//! Client-side Rosenpass keypair lifecycle: generate a keypair on demand, and keep the server's
//! record of our public key/address in sync with our local one.
//!
//! Registration is intentionally idempotent and cheap rather than "always PUT on every fetch":
//! a Rosenpass public key is ~683 KiB base64-encoded, so re-sending it on every periodic
//! `innernet up --daemon` fetch cycle would be wasteful. Instead, we compare our own peer
//! entry's `rosenpass_public_key_hash` (already present in the `State` we just fetched — no
//! extra round trip) against a local hash of our on-disk key, and only register when they
//! differ (first registration, or the key changed).

use crate::rest_client::RestClient;
use anyhow::Error;
use innernet_shared::{
    interface_config::ServerInfo,
    rosenpass::{self, RosenpassKeyPaths},
    rosenpass_public_key_hash, Peer, RosenpassContents, RosenpassOpts,
};
use std::path::Path;
use wireguard_control::InterfaceName;

/// Ensures a Rosenpass keypair exists for this interface (generating one if this is the first
/// time Rosenpass has been enabled for it), and ensures the server's record of our public
/// key/address matches our local key, registering it if not.
///
/// `our_wg_public_key` identifies "ourselves" in `peers` (the just-fetched peer list) — matching
/// the same way the rest of the fetch loop identifies the local interface's own peer entry.
pub fn sync(
    data_dir: &Path,
    interface: &InterfaceName,
    rosenpass_opts: &RosenpassOpts,
    server: &ServerInfo,
    our_wg_public_key: &str,
    peers: &[Peer],
) -> Result<(), Error> {
    if !rosenpass_opts.enable_rosenpass {
        return Ok(());
    }

    let paths = RosenpassKeyPaths::new(&rosenpass::interface_rosenpass_dir(data_dir, interface));
    if !paths.exist() {
        log::info!("generating Rosenpass keypair for {}", interface);
        rosenpass::generate_keypair(&paths)?;
    }

    let local_key = rosenpass::read_public_key_base64(&paths)?;
    let local_hash = rosenpass_public_key_hash(&local_key);

    let already_registered = peers
        .iter()
        .find(|p| p.public_key == our_wg_public_key)
        .is_some_and(|p| p.rosenpass_public_key_hash.as_deref() == Some(local_hash.as_str()));

    if already_registered {
        log::debug!("rosenpass key already registered and unchanged, skipping re-registration");
        return Ok(());
    }

    log::info!("registering rosenpass public key with server");
    RestClient::new(server).register_rosenpass_key(&RosenpassContents {
        public_key: Some(local_key),
        addr: None,
    })?;

    Ok(())
}
