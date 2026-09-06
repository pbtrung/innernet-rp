//! Support for running [Rosenpass](https://rosenpass.eu) as a managed subprocess alongside
//! WireGuard. Per doc/design.md 5.7, innernet shells out to the upstream `rosenpass` binary
//! rather than reimplementing or embedding its post-quantum crypto.

use crate::{chmod, ensure_dirs_exist};
use anyhow::{bail, Context as _, Error};
use base64::Engine;
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};
use wireguard_control::InterfaceName;

/// Where a given interface's Rosenpass keypair (and, later, its exchange-daemon config/state)
/// lives on disk: `<data_dir>/rosenpass/<interface>/`, alongside (not inside) the plain
/// `<data_dir>/<interface>.json` `DataStore` file.
pub fn interface_rosenpass_dir(data_dir: &Path, interface: &InterfaceName) -> PathBuf {
    data_dir.join("rosenpass").join(interface.to_string())
}

/// Raw byte length of a Rosenpass static public key (Classic McEliece 460896). See
/// [`crate::ROSENPASS_PUBLIC_KEY_BASE64_LEN`] for the corresponding base64-encoded length.
pub const ROSENPASS_PUBLIC_KEY_LEN: usize = 524_160;

/// The name of the Rosenpass binary looked up on `$PATH`, same convention as `wg`/`ip` elsewhere
/// in this codebase (see `wg::cmd`).
const ROSENPASS_BIN: &str = "rosenpass";

/// Paths to a Rosenpass keypair on disk, rooted at a per-interface directory (e.g.
/// `<data_dir>/interfaces/<interface>/rosenpass/`).
#[derive(Debug, Clone)]
pub struct RosenpassKeyPaths {
    pub public_key: PathBuf,
    pub secret_key: PathBuf,
}

impl RosenpassKeyPaths {
    pub fn new(rosenpass_dir: &Path) -> Self {
        Self {
            public_key: rosenpass_dir.join("public-key"),
            secret_key: rosenpass_dir.join("secret-key"),
        }
    }

    pub fn exist(&self) -> bool {
        self.public_key.is_file() && self.secret_key.is_file()
    }
}

/// Generates a new Rosenpass keypair by shelling out to `rosenpass gen-keys` (see
/// doc/design.md 5.7 for why innernet doesn't reimplement or embed Rosenpass's PQ crypto).
///
/// Fails loudly, rather than silently skipping Rosenpass, if the `rosenpass` binary isn't
/// installed, since a keypair is required for a peer to participate at all.
pub fn generate_keypair(paths: &RosenpassKeyPaths) -> Result<(), Error> {
    if let Some(dir) = paths.public_key.parent() {
        ensure_dirs_exist(&[dir])?;
    }

    let status = Command::new(ROSENPASS_BIN)
        .arg("gen-keys")
        .arg("--public-key")
        .arg(&paths.public_key)
        .arg("--secret-key")
        .arg(&paths.secret_key)
        .status()
        .with_context(|| {
            format!(
                "failed to run `{ROSENPASS_BIN} gen-keys` - is rosenpass (>= 0.2.1) installed \
                 and on PATH? see doc/design.md for why innernet requires the upstream binary \
                 rather than embedding it"
            )
        })?;

    if !status.success() {
        bail!("`{ROSENPASS_BIN} gen-keys` exited with {status}");
    }

    let secret_key_file = File::open(&paths.secret_key).with_context(|| {
        format!(
            "rosenpass gen-keys did not produce a secret key at {:?}",
            paths.secret_key
        )
    })?;
    chmod(&secret_key_file, 0o600)?;

    Ok(())
}

/// Reads the raw public key file and base64-encodes it for registration with the server (the
/// server-side field is base64, matching the WireGuard key convention — see
/// `PeerContents::rosenpass_public_key`), validating it's exactly the expected length for a
/// Classic McEliece 460896 key.
pub fn read_public_key_base64(paths: &RosenpassKeyPaths) -> Result<String, Error> {
    let raw = std::fs::read(&paths.public_key).with_context(|| {
        format!(
            "failed to read rosenpass public key at {:?}",
            paths.public_key
        )
    })?;

    if raw.len() != ROSENPASS_PUBLIC_KEY_LEN {
        bail!(
            "rosenpass public key at {:?} has unexpected length {} (expected {})",
            paths.public_key,
            raw.len(),
            ROSENPASS_PUBLIC_KEY_LEN
        );
    }

    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_paths() {
        let dir = Path::new("/tmp/example/rosenpass");
        let paths = RosenpassKeyPaths::new(dir);
        assert_eq!(paths.public_key, dir.join("public-key"));
        assert_eq!(paths.secret_key, dir.join("secret-key"));
    }

    #[test]
    fn test_read_public_key_base64_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RosenpassKeyPaths::new(dir.path());
        std::fs::write(&paths.public_key, b"too short").unwrap();

        assert!(read_public_key_base64(&paths).is_err());
    }

    #[test]
    fn test_read_public_key_base64_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RosenpassKeyPaths::new(dir.path());
        let raw = vec![0x42u8; ROSENPASS_PUBLIC_KEY_LEN];
        std::fs::write(&paths.public_key, &raw).unwrap();

        let encoded = read_public_key_base64(&paths).unwrap();
        assert_eq!(encoded.len(), crate::ROSENPASS_PUBLIC_KEY_BASE64_LEN);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .unwrap(),
            raw
        );
    }
}
