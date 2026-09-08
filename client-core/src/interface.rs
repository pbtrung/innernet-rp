pub use innernet_shared::interface_config::InterfaceConfig;
pub use wireguard_control::InterfaceName;

use crate::{
    data_store::DataStore,
    gate,
    nat::{self, NatTraverse},
    pq_install::{self, RealInstaller},
    pq_sync,
    rest_client::{RestClient, RestError},
    HostsOpts, NatOpts, NetworkOpts, WrappedIoError,
};
use anyhow::{anyhow, bail, Context as _, Error};
use colored::{ColoredString, Colorize};
use innernet_pq::{
    crypto::SystemRandom,
    protocol::{Binary, Number},
    store::Store,
};
use innernet_shared::{
    get_local_addrs, peer_allowed_ip,
    pq::PqOptions,
    update_hosts_file,
    wg::{self, DeviceExt as _},
    Endpoint, PeerChange, PeerDiff, RedeemContents, State, REDEEM_TRANSITION_WAIT,
};
use std::{
    io,
    net::SocketAddr,
    path::Path,
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use wireguard_control::{Backend, Device, DeviceUpdate, PeerConfigBuilder};

#[derive(Debug, Error)]
pub enum RedeemInviteError {
    #[error("Error accessing innernet interface config file: {0}")]
    InterfaceConfigAccess(WrappedIoError),
    #[error("Config file for innernet interface {0} already exists.")]
    InterfaceConfigExists(InterfaceName),
    #[error("Error making a REST request: {0}")]
    RestRequest(#[from] RestError),
    #[error("Could not persist the management enrollment: {0}")]
    ManagementPersist(String),
    #[error("Could not resolve server address for endpoint {endpoint}: {error}")]
    ServerAddressResolve {
        endpoint: Endpoint,
        error: io::Error,
    },
    #[error("WireGuard interface {0} already exists.")]
    WireguardInterfaceExists(InterfaceName),
    #[error("Error managing the Wireguard interface {interface}: {error}")]
    WireguardOperation {
        interface: InterfaceName,
        error: io::Error,
    },
}

/// Redeem an invitation to join an innernet network.
///
/// - Brings the WireGuard interface up.
/// - Generates a fresh key pair and uses the public part to redeem the invite and the private part
///   to update the WireGuard interface.
/// - Bails if either a WireGuard or an innernet `interface` of the same name already exists and
///   brings the interface down if it was already up.
pub fn redeem_invite(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    let config_path = InterfaceConfig::build_config_file_path(config_dir, interface)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;

    if config_path.exists() {
        return Err(RedeemInviteError::InterfaceConfigExists(*interface));
    }

    if Device::list(network_opts.backend)
        .iter()
        .flatten()
        .any(|name| name == interface)
    {
        return Err(RedeemInviteError::WireguardInterfaceExists(*interface));
    }

    // Persist a provisioned management PSK before the interface protects
    // anything with it, matching design 5.10's "persist at both endpoints
    // before enabling the link". A network that never requires management
    // has no enrollment to adopt here.
    let preshared_key = if let Some(enrollment) = &config.server.management {
        crate::management::adopt(data_dir, interface, enrollment)
            .map_err(|e| RedeemInviteError::ManagementPersist(e.to_string()))?;
        Some(*enrollment.psk.bytes())
    } else {
        None
    };

    log::info!(
        "bringing up interface {}.",
        interface.as_str_lossy().yellow()
    );

    let endpoint = &config.server.external_endpoint;
    let resolved_endpoint =
        endpoint
            .resolve()
            .map_err(|e| RedeemInviteError::ServerAddressResolve {
                endpoint: endpoint.clone(),
                error: e,
            })?;

    wg::up(
        interface,
        &config.interface.private_key,
        config.interface.address,
        config.interface.listen_port,
        Some(wg::ServerPeer {
            public_key: &config.server.public_key,
            address: config.server.internal_endpoint.ip(),
            endpoint: resolved_endpoint,
            preshared_key,
        }),
        network_opts,
    )
    .map_err(|e| RedeemInviteError::WireguardOperation {
        interface: *interface,
        error: e,
    })?;

    update_keypair(network_opts, interface, &config_path, config).inspect_err(|e| {
        log::error!("failed to update keypair (is the innernet server reachable?): {e}.",);
        log::info!("bringing down the interface.");
        if let Err(e) = wg::down(interface, network_opts.backend) {
            log::warn!("failed to bring down interface: {}.", e);
        };
    })?;

    Ok(())
}

fn update_keypair(
    network_opts: &NetworkOpts,
    interface: &InterfaceName,
    config_path: &Path,
    mut config: InterfaceConfig,
) -> Result<(), RedeemInviteError> {
    log::info!("Generating new keypair.");
    let keypair = wireguard_control::KeyPair::generate();

    log::info!(
        "Registering keypair with server (at {}).",
        config.server.internal_endpoint
    );
    RestClient::new(&config.server).http_form::<_, ()>(
        "POST",
        "/user/redeem",
        RedeemContents {
            public_key: keypair.public.to_base64(),
        },
    )?;

    config.interface.private_key = keypair.private.to_base64();
    config
        .save_new(config_path, 0o600)
        .map_err(RedeemInviteError::InterfaceConfigAccess)?;
    log::info!(
        "New keypair registered. Copied config to {}.\n",
        config_path.to_string_lossy().yellow()
    );

    log::info!("Changing keys and waiting 5s for server's WireGuard interface to transition.",);
    DeviceUpdate::new()
        .set_private_key(keypair.private)
        .apply(interface, network_opts.backend)
        .map_err(|e| RedeemInviteError::WireguardOperation {
            interface: *interface,
            error: e,
        })?;
    thread::sleep(REDEEM_TRANSITION_WAIT);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn fetch(
    config_dir: &Path,
    data_dir: &Path,
    network_opts: &NetworkOpts,
    hosts_opts: &HostsOpts,
    nat: &NatOpts,
    interface: &InterfaceName,
    bring_up_interface: bool,
    pq: &PqOptions,
) -> Result<(), Error> {
    let config = InterfaceConfig::from_interface(config_dir, interface)?;
    let interface_up = interface_is_up(network_opts.backend, interface);

    // Restores the management PSK across a restart, before the interface is
    // (re)configured. Never a data-peer PSK: those are unrelated to this link.
    let management_psk = crate::management::load(data_dir, interface)?.map(|e| *e.psk.bytes());
    // Cached peer directory, needed even before the interface exists: the
    // coordination API is reachable only through this very tunnel, so a
    // cold-boot gate restoration cannot fetch a fresh directory and must
    // rely on what was already cached from the last successful fetch.
    let mut store = DataStore::open_or_create(data_dir, interface)?;
    let pq_path = pq_sync::path(data_dir, interface);

    if !interface_up {
        if !bring_up_interface {
            bail!(
                "Interface is not up. Use 'innernet up {}' instead",
                interface
            );
        }

        // Restore the data-traffic gate before any peer (confirmed or not)
        // gets a kernel entry again: nftables state does not survive a
        // reboot, so "existing sessions cannot bypass it" requires this to
        // run before wg::up(), not after. A never-yet-activated interface
        // (no PQ store on disk) has no relationship to protect yet.
        if pq.enable_pq_psk && std::fs::symlink_metadata(&pq_path).is_ok() {
            let mut pq_store =
                Store::open(&pq_path, false).context("opening PQ activation state")?;
            let state: innernet_pq::state::EndpointState =
                pq_store.load().context("loading PQ activation state")?;
            let blocked = pq_install::blocked_allowed_ips(&state, store.peers());
            gate::apply_all(interface, &blocked)
                .map_err(|e| anyhow!("restoring the PQ data-traffic gate on boot: {e}"))?;
        }

        log::info!(
            "bringing up interface {}.",
            interface.as_str_lossy().yellow()
        );
        let resolved_endpoint = config
            .server
            .external_endpoint
            .resolve()
            .context(config.server.external_endpoint.to_string())?;
        wg::up(
            interface,
            &config.interface.private_key,
            config.interface.address,
            config.interface.listen_port,
            Some(wg::ServerPeer {
                public_key: &config.server.public_key,
                address: config.server.internal_endpoint.ip(),
                endpoint: resolved_endpoint,
                preshared_key: management_psk,
            }),
            network_opts,
        )
        .context(interface.to_string())?;
    }

    log::info!(
        "fetching state for {} from server...",
        interface.as_str_lossy().yellow()
    );
    let rest_client = RestClient::new(&config.server);
    let (State { mut peers, cidrs }, server_is_reachable) = match rest_client
        .http("GET", "/user/state")
    {
        Ok(state) => (state, true),
        Err(e) => {
            if e.is_transport_error() {
                if store.peers().is_empty() {
                    bail!(
                        "Could not connect to the innernet server and there are no cached peers, \
                     exiting."
                    )
                }

                log::warn!(
                    "Could not connect to the innernet server, proceeding with cached state instead."
                );

                let state = State {
                    peers: store.peers().to_vec(),
                    cidrs: store.cidrs().to_vec(),
                };
                (state, false)
            } else {
                bail!(e)
            }
        },
    };

    // Apply the local peer endpoint overrides.
    for (peer_ip, endpoint_override) in config.peer_endpoint_overrides() {
        log::debug!(
            "overriding peer IP {} with endpoint {}",
            peer_ip,
            endpoint_override
        );

        if let Some(peer) = peers.iter_mut().find(|p| p.ip == *peer_ip) {
            peer.endpoint = Some(endpoint_override.clone());
        }
    }

    // Opened before the ordinary peer diff/apply below (not after): a peer
    // that just became newly visible through the ordinary directory must
    // never carry application traffic on an unconfirmed PQ link, even for
    // the single tick before the PQ engine itself discovers/creates its
    // Relationship. Gating here, before that peer gets its ordinary
    // WireGuard connectivity, closes that window.
    let mut pq_activation = if pq.enable_pq_psk && server_is_reachable {
        let public_key = wireguard_control::Key::from_base64(&config.interface.private_key)
            .map_err(|e| anyhow!("parsing this interface's own public key: {e}"))?
            .get_public();
        let mut rng = SystemRandom;
        let (pq_store, state) = pq_sync::open_or_register(
            data_dir,
            interface,
            &rest_client,
            Binary(public_key.0),
            pq.pq_psk_permissive,
            &mut rng,
        )
        .context("opening or registering PQ activation state")?;

        // Fetched here (not later, alongside `apply`) so this gating pass
        // can see each peer's current bundle presence -- required to tell
        // a not-yet-confirmed PQ peer (always gated) apart from a
        // permissive-eligible legacy peer (never gated), which the
        // ordinary (non-PQ) peer directory alone cannot distinguish.
        // Reused below for `apply`, so this is still exactly one PQ state
        // fetch per cycle.
        let (pq_peers, exchanges) =
            pq_sync::fetch_state(&rest_client).context("fetching PQ exchange state")?;

        let mut to_gate = Vec::new();
        let mut to_release = Vec::new();
        for entry in &pq_peers {
            if entry.is_server {
                continue;
            }
            // The coordination server itself is never a PQ data-peer
            // relationship (pq_sync::apply's own loop excludes it the same
            // way); including it here would gate the very link this
            // activation needs to complete over.
            let Ok(id) = Number::new(entry.peer.id as u64) else {
                continue;
            };
            if id == state.server_id || id == state.peer_id {
                continue;
            }
            let relationship = state.relationships.get(&id);
            if relationship.and_then(|r| r.confirmed.as_ref()).is_some() {
                // Already confirmed; reconcile_gate (below, after peers are
                // live) re-verifies it, never this proactive pass.
                continue;
            }
            let allowed_ip = peer_allowed_ip(&entry.peer);
            if pq_install::legacy_eligible(&state, id, entry.pq.is_some()) {
                to_release.push(allowed_ip);
            } else {
                to_gate.push(allowed_ip);
            }
        }
        if !to_gate.is_empty() {
            gate::block(interface, &to_gate)
                .map_err(|e| anyhow!("gating newly visible PQ peers: {e}"))?;
        }
        if !to_release.is_empty() {
            gate::release(interface, &to_release)
                .map_err(|e| anyhow!("releasing legacy-eligible PQ peers: {e}"))?;
        }
        Some((pq_store, state, rng, pq_peers, exchanges))
    } else {
        None
    };

    let device = Device::get(interface, network_opts.backend)?;
    let modifications = device.diff(&peers);

    let server_key = wireguard_control::Key::from_base64(&config.server.public_key).ok();
    let mut updates = modifications
        .iter()
        .inspect(|diff| print_peer_diff(&store, diff))
        .cloned()
        .map(PeerConfigBuilder::from)
        .collect::<Vec<_>>();
    // A rebuilt server peer entry (from an ordinary allowed-IP/endpoint diff)
    // must never silently drop its management PSK back to an unprotected link.
    if let Some(psk) = management_psk {
        for update in &mut updates {
            if server_key
                .as_ref()
                .is_some_and(|key| update.public_key() == key)
            {
                *update = update
                    .clone()
                    .set_preshared_key(wireguard_control::Key(psk));
            }
        }
    }

    if !updates.is_empty() || !interface_up {
        DeviceUpdate::new()
            .add_peers(&updates)
            .apply(interface, network_opts.backend)
            .context(interface.to_string())?;

        if !hosts_opts.no_write_hosts {
            update_hosts_file(interface, hosts_opts, &peers)?;
        }

        println!();
        log::info!("updated interface {}\n", interface.as_str_lossy().yellow());
    } else {
        log::info!("{}", "peers are already up to date".green());
    }
    let interface_updated_time = Instant::now();

    // Peers (including any already-Confirmed PQ relationship's PSK) are now
    // live; advance every visible PQ relationship by one step against the
    // real kernel, then re-verify the gate for any already-confirmed,
    // no-pending relationship (needed even outside an active rotation: a
    // cold boot closes every gate above, and a merely-confirmed
    // relationship still needs one fresh post-boot handshake before its
    // gate reopens, since the gate itself did not survive the reboot).
    if let Some((mut pq_store, mut state, mut rng, pq_peers, exchanges)) = pq_activation.take() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut installer = RealInstaller::new(*interface, network_opts.backend, &peers);
        pq_sync::apply(
            &pq_peers,
            &exchanges,
            &rest_client,
            &mut pq_store,
            &mut state,
            &mut installer,
            &mut rng,
            now,
            pq.pq_psk_rotation_interval,
            pq.pq_psk_idle_timeout,
            Some(&device),
        )
        .context("advancing PQ data-peer exchanges")?;
        pq_install::reconcile_gate(*interface, network_opts.backend, &state, &peers);
    }

    store
        .update_peers_and_set_cidrs(&peers, cidrs)
        .context(interface.to_string())?;

    let listen_port = device.listen_port.unwrap_or(51820);
    if server_is_reachable {
        report_candidates(&rest_client, nat, listen_port)?;
    }

    if nat.no_nat_traversal {
        log::debug!("NAT traversal explicitly disabled, not attempting.");
    } else {
        let mut nat_traverse =
            NatTraverse::new(interface, &config, network_opts.backend, &modifications)?;

        // Give time for handshakes with recently changed endpoints to complete before attempting traversal.
        if !nat_traverse.is_finished() {
            thread::sleep(nat::STEP_INTERVAL - interface_updated_time.elapsed());
        }
        loop {
            if nat_traverse.is_finished() {
                break;
            }
            log::info!(
                "Attempting to establish connection with {} remaining unconnected peers...",
                nat_traverse.remaining()
            );
            nat_traverse.step()?;
        }
    }

    Ok(())
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum ChangeAction {
    Added,
    Modified,
    Removed,
}

impl ChangeAction {
    fn colored_output(&self) -> ColoredString {
        match self {
            Self::Added => "added".green(),
            Self::Modified => "modified".yellow(),
            Self::Removed => "removed".red(),
        }
    }
}

fn print_peer_diff(store: &DataStore, diff: &PeerDiff) {
    let public_key = diff.public_key().to_base64();

    let change_action = match (diff.old, diff.new) {
        (None, Some(_)) => ChangeAction::Added,
        (Some(_), Some(_)) => ChangeAction::Modified,
        (Some(_), None) => ChangeAction::Removed,
        _ => unreachable!("PeerDiff can't be None -> None"),
    };

    // Grab the peer name from either the new data, or the historical data (if the peer is removed).
    let peer_hostname = match diff.new {
        Some(peer) => Some(peer.name.clone()),
        None => store
            .peers()
            .iter()
            .find(|p| p.public_key == public_key)
            .map(|p| p.name.clone()),
    };
    let peer_name = peer_hostname.as_deref().unwrap_or("[unknown]");

    if change_action == ChangeAction::Modified
        && diff
            .changes()
            .iter()
            .all(|c| *c == PeerChange::NatTraverseReattempt)
    {
        // If this peer was "modified" but the only change is a NAT Traversal Reattempt,
        // don't bother printing this peer.
        return;
    }

    log::info!(
        "  peer {} ({}...) was {}.",
        peer_name.yellow(),
        public_key[..10].dimmed(),
        change_action.colored_output(),
    );

    for change in diff.changes() {
        if let PeerChange::Endpoint { .. } = change {
            log::info!("    {}", change);
        } else {
            log::debug!("    {}", change);
        }
    }
}

fn report_candidates(
    rest_client: &RestClient,
    nat: &NatOpts,
    listen_port: u16,
) -> Result<(), Error> {
    let candidates: Vec<Endpoint> = get_local_addrs()?
        .filter(|ip| !nat.is_excluded(*ip))
        .map(|addr| SocketAddr::from((addr, listen_port)).into())
        .collect::<Vec<Endpoint>>();
    log::info!(
        "reporting {} interface address{} as NAT traversal candidates",
        candidates.len(),
        if candidates.len() == 1 { "" } else { "es" },
    );
    for candidate in &candidates {
        log::debug!("  candidate: {}", candidate);
    }
    if let Err(e) = rest_client.http_form::<_, ()>("PUT", "/user/candidates", &candidates) {
        if e.has_status_of(404) {
            log::warn!("your network is using an old version of innernet-server that doesn't support NAT traversal candidate reporting.")
        } else {
            return Err(e.into());
        }
    }

    log::debug!("candidates successfully reported");
    Ok(())
}

pub fn interface_is_up(backend: Backend, interface_name: &InterfaceName) -> bool {
    match Device::list(backend) {
        Ok(interfaces) => interfaces.contains(interface_name),
        _ => false,
    }
}
