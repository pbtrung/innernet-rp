//! Support for running [Rosenpass](https://rosenpass.eu) as a managed subprocess alongside
//! WireGuard. Per doc/design.md 5.7, innernet shells out to the upstream `rosenpass` binary
//! rather than reimplementing or embedding its post-quantum crypto.

use crate::{chmod, ensure_dirs_exist};
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

fn spawn_daemon(paths: &DaemonPaths) -> Result<(), Error> {
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
