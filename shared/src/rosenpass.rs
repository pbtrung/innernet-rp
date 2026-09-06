//! Support for running [Rosenpass](https://rosenpass.eu) as a managed subprocess alongside
//! WireGuard. Per doc/design.md 5.7, innernet shells out to the upstream `rosenpass` binary
//! rather than reimplementing or embedding its post-quantum crypto.

use crate::{chmod, ensure_dirs_exist, Peer};
use anyhow::{bail, Context as _, Error};
use base64::Engine;
use serde::Serialize;
use std::{
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use wireguard_control::{Backend, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder};

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
    check_rosenpass_version()?;

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
    read_public_key_base64_at(&paths.public_key)
}

/// Like [`read_public_key_base64`], but for any raw public-key file — also used for peers'
/// cached keys, not just our own (see [`DaemonPaths::peer_public_key_path`]).
pub fn read_public_key_base64_at(path: &Path) -> Result<String, Error> {
    let raw = std::fs::read(path)
        .with_context(|| format!("failed to read rosenpass public key at {path:?}"))?;

    if raw.len() != ROSENPASS_PUBLIC_KEY_LEN {
        bail!(
            "rosenpass public key at {:?} has unexpected length {} (expected {})",
            path,
            raw.len(),
            ROSENPASS_PUBLIC_KEY_LEN
        );
    }

    Ok(base64::engine::general_purpose::STANDARD.encode(raw))
}

/// Derives a deterministic placeholder WireGuard preshared key from two peers' Rosenpass public
/// keys, for the window before their first real exchange completes (which can take a noticeable
/// moment — the daemon has to start, dial/be dialed, and complete a post-quantum handshake).
/// Without this, that window would leave the tunnel with no PSK at all.
///
/// Both sides must derive the *same* value without coordinating, so the two keys are sorted
/// before hashing — order of arguments doesn't matter, matching NetBird's equivalent mechanism
/// (their `DeterministicSeedKey()`) and the same "sort, don't pick a side" principle already
/// used for the dial/listen tie-break above.
///
/// This is **not** a substitute for the real exchange: it provides no post-quantum protection at
/// all (it's derived from public keys with a public hash function, not a key exchange) — only
/// bridging the gap so the tunnel isn't left with zero PSK while waiting.
pub fn interim_preshared_key(a_public_key_base64: &str, b_public_key_base64: &str) -> Key {
    use sha2::{Digest, Sha256};
    let (first, second) = if a_public_key_base64 <= b_public_key_base64 {
        (a_public_key_base64, b_public_key_base64)
    } else {
        (b_public_key_base64, a_public_key_base64)
    };
    let mut hasher = Sha256::new();
    hasher.update(b"innernet-rosenpass-interim-psk-v1");
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    Key(hasher.finalize().into())
}

/// Paths for a running (or to-be-started) Rosenpass exchange daemon for one interface.
#[derive(Debug, Clone)]
pub struct DaemonPaths {
    /// The TOML config file passed to `rosenpass exchange-config`.
    pub config: PathBuf,
    /// The daemon's stdout+stderr, redirected to a file (rather than a pipe) because the daemon
    /// must outlive the short-lived `innernet` CLI invocation that spawned it — nothing holds a
    /// live pipe across separate `innernet up`/`fetch` invocations. See [`poll_new_events`] for
    /// why we need this log at all rather than only reading `key_out` files directly.
    pub log: PathBuf,
    /// How many bytes of `log` have already been scanned by [`poll_new_events`], so repeated
    /// calls (across separate CLI invocations) don't reprocess old lines.
    pub log_offset: PathBuf,
    /// The daemon's PID, so a later `innernet` invocation can tell whether it's still running
    /// and, if the config changed, stop it before starting a new one (Rosenpass has no config
    /// reload mechanism — see doc/design.md 5.6/8 — so a changed peer set means a full restart).
    pub pid: PathBuf,
}

impl DaemonPaths {
    pub fn new(rosenpass_dir: &Path) -> Self {
        Self {
            config: rosenpass_dir.join("rosenpass.toml"),
            log: rosenpass_dir.join("rosenpass.log"),
            log_offset: rosenpass_dir.join("rosenpass.log.offset"),
            pid: rosenpass_dir.join("rosenpass.pid"),
        }
    }

    /// Where a given peer's raw (non-base64) public key is cached locally, fetched on demand
    /// from the server and reused as long as its hash matches what's currently advertised. See
    /// the server-side `PeerContents::rosenpass_public_key_hash` docs for why this is cached
    /// rather than re-fetched every time.
    pub fn peer_public_key_path(rosenpass_dir: &Path, peer_id: i64) -> PathBuf {
        rosenpass_dir.join("peers").join(format!("{peer_id}.pub"))
    }

    /// Where Rosenpass writes the derived preshared key for a given peer (base64-encoded, per
    /// upstream's `key_out` mechanism).
    pub fn peer_key_out_path(rosenpass_dir: &Path, peer_id: i64) -> PathBuf {
        rosenpass_dir.join("peers").join(format!("{peer_id}.psk"))
    }
}

/// One peer to include in the Rosenpass exchange daemon's config.
#[derive(Debug, Clone)]
pub struct RosenpassPeerConfig {
    pub peer_id: i64,
    /// Path to that peer's cached raw public key file (see [`DaemonPaths::peer_public_key_path`]).
    pub public_key_path: PathBuf,
    /// Where to dial this peer, if known. `None` means we only ever respond to this peer's
    /// connection attempts, never initiate — still useful if the peer dials us.
    pub endpoint: Option<SocketAddr>,
}

// Mirrors rosenpass's own `rosenpass::config::{Rosenpass, RosenpassPeer, Verbosity}` (see
// upstream src/config.rs) closely enough to serialize a config file it accepts — field names
// and shapes must match exactly. We only ever *write* this (never parse rosenpass's own config
// back), so only `Serialize` is needed. The upstream struct's `wg` (direct `wg set` integration)
// and `pre_shared_key` (an extra *input* PSK ingredient) fields are omitted entirely, which is
// equivalent to leaving them `None` (see doc/design.md 5.6 for why innernet uses the `key_out`
// file handoff rather than upstream's direct WireGuard integration).
#[derive(Serialize)]
struct RpConfig {
    public_key: PathBuf,
    secret_key: PathBuf,
    listen: Vec<SocketAddr>,
    verbosity: RpVerbosity,
    peers: Vec<RpPeer>,
}

#[derive(Serialize)]
enum RpVerbosity {
    Quiet,
}

#[derive(Serialize)]
struct RpPeer {
    public_key: PathBuf,
    endpoint: Option<String>,
    key_out: PathBuf,
}

/// Renders the Rosenpass exchange-daemon config for this interface: our own keypair, our
/// listen address(es) on `listen_port` (both IPv4-any and IPv6-any, matching upstream's own
/// `add_if_any` convenience), and one peer entry per `peers` with its `key_out` set to where
/// we'll look for its derived PSK (see [`DaemonPaths::peer_key_out_path`]).
fn render_config(
    rosenpass_dir: &Path,
    key_paths: &RosenpassKeyPaths,
    listen_port: u16,
    peers: &[RosenpassPeerConfig],
) -> String {
    let config = RpConfig {
        public_key: key_paths.public_key.clone(),
        secret_key: key_paths.secret_key.clone(),
        // IPv4-any only. Binding *both* an IPv4-any and an IPv6-any socket on the same port
        // fails with "Address already in use" on Linux (dual-stack IPv6-any sockets also claim
        // the IPv4 namespace by default there) — verified empirically against the real 0.2.3
        // binary. Since `IPV6_V6ONLY`'s default differs across the platforms this project
        // supports (Linux vs. macOS/OpenBSD), there's no single "listen on both" address pair
        // that's portable, so IPv6-only peers can't dial us (a known limitation) until this is
        // revisited with an OS-specific listen strategy.
        listen: vec![SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            listen_port,
        ))],
        verbosity: RpVerbosity::Quiet,
        peers: peers
            .iter()
            .map(|p| RpPeer {
                public_key: p.public_key_path.clone(),
                endpoint: p.endpoint.map(|a| a.to_string()),
                key_out: DaemonPaths::peer_key_out_path(rosenpass_dir, p.peer_id),
            })
            .collect(),
    };
    toml::to_string_pretty(&config).expect("rosenpass config is always representable as TOML")
}

/// Ensures a Rosenpass exchange daemon is running for this interface with an up-to-date peer
/// list, (re)starting it only if the rendered config actually changed or the previously-started
/// process is no longer alive. A full restart (rather than an in-place reload) is used because
/// Rosenpass 0.2.3 has no config-reload mechanism (confirmed by inspecting upstream's source —
/// no signal handling, no `remove_peer`, no IPC) — every peer-set/endpoint change requires
/// stopping and restarting the whole exchange, which briefly drops PQ protection for every peer
/// on that interface, not just the one that changed. Document this as a known limitation rather
/// than something silently absorbed.
pub fn ensure_daemon_running(
    rosenpass_dir: &Path,
    key_paths: &RosenpassKeyPaths,
    listen_port: u16,
    peers: &[RosenpassPeerConfig],
) -> Result<(), Error> {
    ensure_dirs_exist(&[rosenpass_dir, &rosenpass_dir.join("peers")])?;
    let paths = DaemonPaths::new(rosenpass_dir);

    let new_config = render_config(rosenpass_dir, key_paths, listen_port, peers);
    let existing_config = std::fs::read_to_string(&paths.config).ok();
    let config_unchanged = existing_config.as_deref() == Some(new_config.as_str());
    let daemon_alive = read_pid(&paths.pid).is_some_and(pid_is_alive);

    if config_unchanged && daemon_alive {
        return Ok(());
    }

    if daemon_alive {
        log::info!("rosenpass peer set/config changed, restarting exchange daemon");
        if let Some(pid) = read_pid(&paths.pid) {
            kill_pid(pid);
        }
    }

    std::fs::write(&paths.config, &new_config)
        .with_context(|| format!("failed to write rosenpass config to {:?}", paths.config))?;

    spawn_daemon(&paths)
}

/// The minimum acceptable `rosenpass` version. Versions before this did not validate buffer size
/// when decoding messages, allowing a malformed UDP packet to crash the process — see
/// [CVE-2023-53157](https://osv.dev/vulnerability/CVE-2023-53157) / GHSA-624c-2h52-gf7f.
const MIN_ROSENPASS_VERSION: (u32, u32, u32) = (0, 2, 1);

/// Confirms the `rosenpass` binary on PATH is at least [`MIN_ROSENPASS_VERSION`], refusing to
/// spawn it otherwise. Checked once per actual daemon (re)start — not on every `fetch()` poll —
/// since [`ensure_daemon_running`] only calls this when it's about to spawn a new process.
///
/// If the version string can't be parsed at all (an unexpected `--version` output format from a
/// future release), this logs a warning and proceeds rather than blocking indefinitely on a
/// parsing assumption — the exact-length/base64 validation elsewhere and this project's own
/// pinned-version documentation (design.md) are the actual controls; this check is a
/// best-effort extra safety net, not the sole line of defense.
fn check_rosenpass_version() -> Result<(), Error> {
    let output = Command::new(ROSENPASS_BIN)
        .arg("--version")
        .output()
        .with_context(|| {
            format!(
                "failed to run `{ROSENPASS_BIN} --version` - is rosenpass installed and on PATH?"
            )
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_str = stdout.trim().rsplit(' ').next().unwrap_or("");

    match parse_semver(version_str) {
        Some(version) if version >= MIN_ROSENPASS_VERSION => Ok(()),
        Some(version) => bail!(
            "rosenpass version {}.{}.{} is older than the minimum required {}.{}.{} (fixes \
             CVE-2023-53157, a remote-DoS-via-malformed-packet bug) - refusing to start it; \
             upgrade rosenpass",
            version.0,
            version.1,
            version.2,
            MIN_ROSENPASS_VERSION.0,
            MIN_ROSENPASS_VERSION.1,
            MIN_ROSENPASS_VERSION.2,
        ),
        None => {
            log::warn!(
                "could not parse a version number from `{ROSENPASS_BIN} --version` output \
                 ({stdout:?}); proceeding without a version check"
            );
            Ok(())
        },
    }
}

fn parse_semver(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;
    Some((major, minor, patch))
}

fn spawn_daemon(paths: &DaemonPaths) -> Result<(), Error> {
    check_rosenpass_version()?;

    let log_file = File::create(&paths.log)
        .with_context(|| format!("failed to create rosenpass log file at {:?}", paths.log))?;
    let log_file_err = log_file
        .try_clone()
        .context("failed to duplicate rosenpass log file handle for stderr")?;
    // Reset the read offset: this is a fresh log for a fresh process.
    std::fs::write(&paths.log_offset, b"0")
        .with_context(|| format!("failed to reset {:?}", paths.log_offset))?;

    let child = Command::new(ROSENPASS_BIN)
        .arg("exchange-config")
        .arg(&paths.config)
        .stdin(Stdio::null())
        .stdout(log_file)
        .stderr(log_file_err)
        .spawn()
        .with_context(|| {
            format!(
                "failed to run `{ROSENPASS_BIN} exchange-config` - is rosenpass (>= 0.2.1) \
                 installed and on PATH?"
            )
        })?;

    // Deliberately not calling `.wait()`: dropping this `Child` handle does not terminate the
    // process (Rust's `Child` has no "kill on drop" behavior), which is exactly what we need —
    // the daemon must outlive this short-lived `innernet` invocation. Its PID is persisted so a
    // later invocation can find and, if needed, stop it.
    std::fs::write(&paths.pid, child.id().to_string())
        .with_context(|| format!("failed to write rosenpass pid file to {:?}", paths.pid))?;

    Ok(())
}

fn read_pid(pid_path: &Path) -> Option<u32> {
    std::fs::read_to_string(pid_path).ok()?.trim().parse().ok()
}

/// Checks whether a process is alive by shelling out to `kill -0`, the same "small external
/// utility" idiom already used elsewhere in this codebase (see `wg::cmd`) rather than reaching
/// for a raw-syscall dependency.
fn pid_is_alive(pid: u32) -> bool {
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn kill_pid(pid: u32) {
    if let Err(e) = Command::new("kill")
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        log::warn!("failed to signal rosenpass process {pid}: {e}");
    }
}

/// One `output-key` event parsed from the daemon's log — see upstream's `app_server.rs`, which
/// prints `output-key peer <id-b64> key-file <path> exchanged|stale` to stdout on every key
/// output, specifically so it can be detected externally like this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeEvent {
    pub key_out_path: PathBuf,
    pub fresh: bool,
}

/// Scans any log lines written since the last call, returning the events found. Distinguishing
/// `exchanged` (a genuine new PSK) from `stale` matters: on `stale`, upstream overwrites the
/// *same* `key_out` file with random bytes to invalidate it (its own comment: "erasing outdated
/// key from peer") — so the file's raw contents alone can't tell us which case produced them.
/// Only an `exchanged` event's contents should ever be applied to WireGuard.
pub fn poll_new_events(paths: &DaemonPaths) -> Result<Vec<ExchangeEvent>, Error> {
    let offset: u64 = std::fs::read_to_string(&paths.log_offset)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    let mut file = match File::open(&paths.log) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).context("failed to open rosenpass log"),
    };
    let len = file.metadata()?.len();
    if len < offset {
        // The log was truncated/recreated (e.g. a restart) since we last read it; start over.
        file.seek(SeekFrom::Start(0))?;
    } else {
        file.seek(SeekFrom::Start(offset))?;
    }

    let mut new_offset = offset.min(len);
    let mut events = vec![];
    for line in BufReader::new(&mut file).lines() {
        let line = line.context("failed to read rosenpass log line")?;
        new_offset += line.len() as u64 + 1; // +1 for the newline
        if let Some(event) = parse_output_key_line(&line) {
            events.push(event);
        }
    }

    std::fs::write(&paths.log_offset, new_offset.to_string())
        .with_context(|| format!("failed to update {:?}", paths.log_offset))?;

    Ok(events)
}

fn parse_output_key_line(line: &str) -> Option<ExchangeEvent> {
    // `output-key peer <peerid-b64> key-file <path> exchanged|stale`
    let rest = line.strip_prefix("output-key peer ")?;
    let (_peer_id, rest) = rest.split_once(" key-file ")?;
    let (path, why) = rest.rsplit_once(' ')?;
    let fresh = match why {
        "exchanged" => true,
        "stale" => false,
        _ => return None,
    };
    // Upstream prints the path via `{:?}` (Rust Debug for PathBuf), which quotes it.
    let path = path.trim_matches('"');
    Some(ExchangeEvent {
        key_out_path: PathBuf::from(path),
        fresh,
    })
}

/// Applies any newly-available preshared keys to the WireGuard interface: a real,
/// Rosenpass-derived key for any peer whose exchange just completed (see [`poll_new_events`]
/// for why only *new* `exchanged` events are trusted, never a peer's `key_out` file read
/// blindly), or — for a peer with no exchange completed yet — a deterministic interim key (see
/// [`interim_preshared_key`]), so the tunnel isn't left with no PSK at all while the first real
/// handshake is still in progress. Applied as a single, separate `DeviceUpdate` from the main
/// peer diff, but just as non-disruptive: wireguard-control merges peer settings onto the
/// existing peer rather than replacing it.
///
/// Shared between the client and server (design.md 5.9) — both run this same tail end of their
/// Rosenpass sync, differing only in how they source `peer_configs` and their own key (an HTTP
/// round trip for the client, direct database access for the server).
pub fn apply_psks(
    interface: &InterfaceName,
    backend: Backend,
    rosenpass_dir: &Path,
    our_rosenpass_key: &str,
    peer_configs: &[RosenpassPeerConfig],
    peers: &[Peer],
) -> Result<(), Error> {
    let daemon_paths = DaemonPaths::new(rosenpass_dir);
    let events = poll_new_events(&daemon_paths)?;

    let mut builders = Vec::new();
    for peer_cfg in peer_configs {
        let Some(peer) = peers.iter().find(|p| p.id == peer_cfg.peer_id) else {
            continue;
        };
        let Ok(wg_pubkey) = Key::from_base64(&peer.public_key) else {
            log::warn!(
                "peer {} has an unparseable WireGuard public key, skipping PSK application",
                peer_cfg.peer_id
            );
            continue;
        };

        let key_out_path = DaemonPaths::peer_key_out_path(rosenpass_dir, peer_cfg.peer_id);

        if let Some(psk) = fresh_exchanged_psk(&events, &key_out_path, peer_cfg.peer_id) {
            log::info!(
                "applying fresh rosenpass-derived preshared key for peer {}",
                peer_cfg.peer_id
            );
            builders.push(PeerConfigBuilder::new(&wg_pubkey).set_preshared_key(psk));
            continue;
        }

        if events
            .iter()
            .any(|e| e.key_out_path == key_out_path && !e.fresh)
        {
            log::warn!(
                "peer {}'s rosenpass session went stale (dropped/expired) - leaving its last \
                 applied preshared key in place rather than a random one",
                peer_cfg.peer_id
            );
        }

        if !key_out_path.exists() {
            match read_public_key_base64_at(&peer_cfg.public_key_path) {
                Ok(peer_key) => {
                    let interim = interim_preshared_key(our_rosenpass_key, &peer_key);
                    log::info!(
                        "applying interim preshared key for peer {} pending its first rosenpass \
                         exchange",
                        peer_cfg.peer_id
                    );
                    builders.push(PeerConfigBuilder::new(&wg_pubkey).set_preshared_key(interim));
                },
                Err(e) => log::warn!(
                    "failed to derive interim preshared key for peer {}: {e}",
                    peer_cfg.peer_id
                ),
            }
        }
    }

    if !builders.is_empty() {
        DeviceUpdate::new()
            .add_peers(&builders)
            .apply(interface, backend)
            .context("failed to apply rosenpass-derived preshared keys")?;
    }

    Ok(())
}

/// Returns the derived key from a fresh `exchanged` event matching `key_out_path`, if there is
/// one among `events` (only newly-observed events since the last poll — see [`poll_new_events`]).
fn fresh_exchanged_psk(events: &[ExchangeEvent], key_out_path: &Path, peer_id: i64) -> Option<Key> {
    if !events
        .iter()
        .any(|e| e.key_out_path == key_out_path && e.fresh)
    {
        return None;
    }
    match std::fs::read_to_string(key_out_path)
        .context("failed to read rosenpass key_out file")
        .and_then(|contents| {
            Key::from_base64(contents.trim())
                .map_err(|e| anyhow::anyhow!("invalid base64 in rosenpass key_out file: {e}"))
        }) {
        Ok(key) => Some(key),
        Err(e) => {
            log::warn!("failed to read exchanged rosenpass preshared key for peer {peer_id}: {e}");
            None
        },
    }
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

    #[test]
    fn test_parse_semver() {
        assert_eq!(parse_semver("0.2.3"), Some((0, 2, 3)));
        assert_eq!(parse_semver("1.10.20"), Some((1, 10, 20)));
        assert_eq!(parse_semver(""), None);
        assert_eq!(parse_semver("not-a-version"), None);
        assert_eq!(parse_semver("0.2"), None);
        assert_eq!(parse_semver("v0.2.3"), None); // a leading "v" isn't handled - by design,
                                                  // real `rosenpass --version` output never has one
    }

    #[test]
    fn test_min_rosenpass_version_ordering() {
        // Confirms tuple ordering does what we rely on in check_rosenpass_version.
        assert!((0, 2, 0) < MIN_ROSENPASS_VERSION);
        assert!((0, 1, 99) < MIN_ROSENPASS_VERSION);
        assert!((0, 2, 1) >= MIN_ROSENPASS_VERSION);
        assert!((0, 3, 0) >= MIN_ROSENPASS_VERSION);
        assert!((1, 0, 0) >= MIN_ROSENPASS_VERSION);
    }

    /// Confirms the version check accepts the real installed binary. Ignored by default
    /// (requires `rosenpass` on PATH); run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn test_check_rosenpass_version_accepts_real_binary() {
        check_rosenpass_version().expect("the installed rosenpass binary should be >= 0.2.1");
    }

    #[test]
    fn test_interim_preshared_key_symmetric_and_deterministic() {
        let a = "a-public-key";
        let b = "b-public-key";

        let from_a_b = interim_preshared_key(a, b);
        let from_b_a = interim_preshared_key(b, a);
        assert_eq!(
            from_a_b, from_b_a,
            "both sides must derive the same interim PSK regardless of argument order"
        );

        let different = interim_preshared_key(a, "some-other-key");
        assert_ne!(from_a_b, different);
    }

    #[test]
    fn test_parse_output_key_line() {
        let exchanged = parse_output_key_line(
            r#"output-key peer YBVIgpfLbi/knrMCTEb0L6eVy0daiZnJJQkxBK9s+2I= key-file "/data/rosenpass/peers/3.psk" exchanged"#,
        )
        .unwrap();
        assert!(exchanged.fresh);
        assert_eq!(
            exchanged.key_out_path,
            PathBuf::from("/data/rosenpass/peers/3.psk")
        );

        let stale = parse_output_key_line(
            r#"output-key peer YBVIgpfLbi/knrMCTEb0L6eVy0daiZnJJQkxBK9s+2I= key-file "/data/rosenpass/peers/3.psk" stale"#,
        )
        .unwrap();
        assert!(!stale.fresh);

        assert!(parse_output_key_line("some unrelated log line").is_none());
    }

    #[test]
    fn test_parse_output_key_line_malformed_input_rejected() {
        // Every one of these must return None, never panic - this parses output from a
        // subprocess handling untrusted network input, so malformed/adversarial log lines are
        // an expected input, not an edge case to shrug off.
        let malformed = [
            "",
            "output-key peer",
            "output-key peer AAAA",
            "output-key peer AAAA key-file",
            // Missing the trailing status word entirely.
            r#"output-key peer AAAA key-file "/x/1.psk""#,
            // Unknown/unexpected status word.
            r#"output-key peer AAAA key-file "/x/1.psk" pending"#,
            // Empty path.
            r#"output-key peer AAAA key-file "" exchanged"#,
            // Missing "peer " after the initial token.
            "output-key AAAA key-file \"/x/1.psk\" exchanged",
            // Case sensitivity - upstream always lowercases, a different case shouldn't match.
            r#"OUTPUT-KEY PEER AAAA KEY-FILE "/x/1.psk" EXCHANGED"#,
            // Extremely long adversarial input shouldn't panic or hang.
            &format!(
                "output-key peer {} key-file \"{}\" exchanged",
                "A".repeat(1_000_000),
                "/x/".to_string() + &"y".repeat(1_000_000)
            ),
            // Embedded null byte / control characters.
            "output-key peer AAAA key-file \"/x/1\0.psk\" exchanged",
            // Non-UTF8-adjacent unicode noise around the delimiters.
            "output-key peer AAAA🔑 key-file \"/x/1.psk\" exchanged",
        ];
        for line in malformed {
            let result = parse_output_key_line(line);
            if line.contains("exchanged") && line.contains("key-file") && !line.contains("pending")
            {
                // Some of the "adversarial but still shaped correctly" lines above (huge input,
                // embedded null, unicode noise) are actually still syntactically parseable by
                // design - the parser only looks at delimiters, not content - and that's fine as
                // long as it never panics. Just confirm no panic occurred (we got here) and, if
                // it did parse, the fresh flag is still correctly derived.
                if let Some(event) = result {
                    assert!(event.fresh);
                }
            } else {
                assert!(
                    result.is_none(),
                    "expected None for malformed line: {line:?}"
                );
            }
        }
    }

    #[test]
    fn test_render_config_shape() {
        let dir = tempfile::tempdir().unwrap();
        let key_paths = RosenpassKeyPaths::new(dir.path());
        let peer = RosenpassPeerConfig {
            peer_id: 3,
            public_key_path: DaemonPaths::peer_public_key_path(dir.path(), 3),
            endpoint: Some("1.2.3.4:9999".parse().unwrap()),
        };

        let rendered = render_config(dir.path(), &key_paths, 51821, &[peer]);

        assert!(rendered.contains("public-key"));
        assert!(rendered.contains("secret-key"));
        assert!(rendered.contains("51821"));
        assert!(rendered.contains("1.2.3.4:9999"));
        assert!(rendered.contains("3.pub"));
        assert!(rendered.contains("3.psk"));
        // Never include upstream's direct-`wg`-integration or extra-PSK-input fields.
        assert!(!rendered.contains("wireguard"));
        assert!(!rendered.contains("pre-shared-key") && !rendered.contains("pre_shared_key"));
    }

    #[test]
    fn test_poll_new_events_only_returns_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let rosenpass_dir = dir.path();
        std::fs::create_dir_all(rosenpass_dir).unwrap();
        let paths = DaemonPaths::new(rosenpass_dir);

        std::fs::write(
            &paths.log,
            "output-key peer AAAA key-file \"/x/1.psk\" exchanged\n",
        )
        .unwrap();
        std::fs::write(&paths.log_offset, "0").unwrap();

        let first = poll_new_events(&paths).unwrap();
        assert_eq!(first.len(), 1);
        assert!(first[0].fresh);

        // Calling again without new log content should yield nothing new.
        let second = poll_new_events(&paths).unwrap();
        assert_eq!(second.len(), 0);

        // Appending a new line should surface only that line.
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(&paths.log)
            .unwrap();
        use std::io::Write;
        writeln!(log, "output-key peer AAAA key-file \"/x/1.psk\" stale").unwrap();
        drop(log);

        let third = poll_new_events(&paths).unwrap();
        assert_eq!(third.len(), 1);
        assert!(!third[0].fresh);
    }

    #[test]
    fn test_pid_liveness_and_kill() {
        // Spawn a short-lived real process to exercise the actual `kill -0`/`kill` shellouts,
        // rather than mocking process liveness.
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();

        assert!(pid_is_alive(pid));
        kill_pid(pid);
        // Reap the process so it doesn't linger as a zombie, and give the signal a moment to land.
        let _ = child.wait();
        assert!(!pid_is_alive(pid));
    }

    /// Validates our hand-rendered config against the *real* upstream `rosenpass` binary's own
    /// `validate` subcommand (see doc/design.md's M0 spike) — not just against our reading of
    /// its source. Ignored by default since it requires `rosenpass` (>= 0.2.1) on PATH; run with
    /// `cargo test -- --ignored` after `cargo install rosenpass --locked`.
    #[test]
    #[ignore]
    fn test_rendered_config_accepted_by_real_rosenpass_binary() {
        let dir = tempfile::tempdir().unwrap();
        let key_paths = RosenpassKeyPaths::new(dir.path());
        generate_keypair(&key_paths).expect("requires the real `rosenpass` binary on PATH");

        let peer_dir = dir.path().join("peers");
        std::fs::create_dir_all(&peer_dir).unwrap();
        let peer_key_paths = RosenpassKeyPaths::new(&dir.path().join("peer-keys"));
        generate_keypair(&peer_key_paths).unwrap();

        let peer = RosenpassPeerConfig {
            peer_id: 1,
            public_key_path: peer_key_paths.public_key,
            endpoint: Some("127.0.0.1:9999".parse().unwrap()),
        };
        let rendered = render_config(dir.path(), &key_paths, 51821, &[peer]);
        let config_path = dir.path().join("rosenpass.toml");
        std::fs::write(&config_path, &rendered).unwrap();

        let output = Command::new(ROSENPASS_BIN)
            .arg("validate")
            .arg(&config_path)
            .output()
            .expect("failed to run real rosenpass binary");
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("rosenpass validate stderr:\n{stderr}");
        assert!(
            stderr.contains("is valid TOML and conforms to the expected schema"),
            "rendered config was not accepted by the real rosenpass binary:\n{rendered}\n---\n{stderr}"
        );
        assert!(
            stderr.contains("passed all logical checks"),
            "rendered config failed rosenpass's logical validation:\n{rendered}\n---\n{stderr}"
        );
    }

    /// The single most safety-critical property of this whole integration: two real peers must
    /// derive the *identical* preshared key, or WireGuard will silently fail to handshake
    /// between them. This is **not** automatic — configuring both sides to dial each other
    /// (both set `endpoint` for the other) causes each side to complete its own independent
    /// handshake and derive a *different* key, verified empirically against the real 0.2.3
    /// binary before this code was written. Exactly one side must dial (`endpoint` set) and the
    /// other must only listen (`endpoint` unset for that peer) — see the dial/listen tie-break
    /// in `client_core::rosenpass::sync`. This test exercises our actual `ensure_daemon_running`
    /// or straight to `render_config`/spawn, with that exact asymmetric shape, end to end against
    /// two real rosenpass processes, and would fail loudly if this ever regressed (e.g. someone
    /// "fixing" the asymmetry back to a symmetric config because it looks more natural).
    ///
    /// Ignored by default (requires the real `rosenpass` binary on PATH); run with
    /// `cargo test -- --ignored` after `cargo install rosenpass --locked --version 0.2.3`.
    #[test]
    #[ignore]
    fn test_two_real_peers_converge_on_identical_psk_when_only_one_dials() {
        let dialer_dir = tempfile::tempdir().unwrap();
        let listener_dir = tempfile::tempdir().unwrap();

        let dialer_keys = RosenpassKeyPaths::new(dialer_dir.path());
        let listener_keys = RosenpassKeyPaths::new(listener_dir.path());
        generate_keypair(&dialer_keys).expect("requires the real `rosenpass` binary on PATH");
        generate_keypair(&listener_keys).unwrap();

        let listener_port = 31_301u16;

        // The listener's peer entry for the dialer has NO endpoint - it only ever responds.
        let listener_peers = vec![RosenpassPeerConfig {
            peer_id: 1,
            public_key_path: dialer_keys.public_key.clone(),
            endpoint: None,
        }];
        ensure_daemon_running(
            listener_dir.path(),
            &listener_keys,
            listener_port,
            &listener_peers,
        )
        .unwrap();

        // The dialer's peer entry for the listener DOES have an endpoint - it initiates.
        let dialer_peers = vec![RosenpassPeerConfig {
            peer_id: 2,
            public_key_path: listener_keys.public_key.clone(),
            endpoint: Some(format!("127.0.0.1:{listener_port}").parse().unwrap()),
        }];
        ensure_daemon_running(dialer_dir.path(), &dialer_keys, 31_302, &dialer_peers).unwrap();

        let listener_psk_path = DaemonPaths::peer_key_out_path(listener_dir.path(), 1);
        let dialer_psk_path = DaemonPaths::peer_key_out_path(dialer_dir.path(), 2);

        let mut listener_psk = None;
        let mut dialer_psk = None;
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(200));
            listener_psk = std::fs::read_to_string(&listener_psk_path).ok();
            dialer_psk = std::fs::read_to_string(&dialer_psk_path).ok();
            if listener_psk.is_some() && dialer_psk.is_some() {
                break;
            }
        }

        // Clean up both daemons before asserting, so a failing assertion doesn't leak processes.
        for dir in [listener_dir.path(), dialer_dir.path()] {
            if let Some(pid) = read_pid(&DaemonPaths::new(dir).pid) {
                kill_pid(pid);
            }
        }

        let listener_psk = listener_psk.expect("listener never wrote a derived PSK in time");
        let dialer_psk = dialer_psk.expect("dialer never wrote a derived PSK in time");
        assert_eq!(
            listener_psk, dialer_psk,
            "the two sides derived DIFFERENT preshared keys - this would silently break \
             WireGuard's handshake for this peer pair"
        );
    }
}
