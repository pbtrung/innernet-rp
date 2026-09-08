use crate::{Error, IoErrorContext, NetworkOpts, Peer, PeerDiff};
use ipnet::IpNet;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use wireguard_control::{
    Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder, PeerInfo,
};

pub use super::netlink::set_addr;

pub use super::netlink::set_up;

/// The server peer to configure alongside bringing up an interface.
pub struct ServerPeer<'a> {
    pub public_key: &'a str,
    pub address: IpAddr,
    pub endpoint: SocketAddr,
    /// The management-link PSK, when this network requires one. Never a
    /// data-peer PSK: those are rotated independently through the mailbox.
    pub preshared_key: Option<[u8; 32]>,
}

pub fn up(
    interface: &InterfaceName,
    private_key: &str,
    address: IpNet,
    listen_port: Option<u16>,
    peer: Option<ServerPeer<'_>>,
    network: &NetworkOpts,
) -> Result<(), io::Error> {
    let mut device = DeviceUpdate::new();
    if let Some(server) = peer {
        let prefix = if server.address.is_ipv4() { 32 } else { 128 };
        let mut peer_config = PeerConfigBuilder::new(
            &wireguard_control::Key::from_base64(server.public_key).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "failed to parse base64 public key",
                )
            })?,
        )
        .add_allowed_ip(server.address, prefix)
        .set_persistent_keepalive_interval(25)
        .set_endpoint(server.endpoint);
        if let Some(psk) = server.preshared_key {
            peer_config = peer_config.set_preshared_key(Key(psk));
        }
        device = device.add_peer(peer_config);
    }
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    }
    device
        .set_private_key(wireguard_control::Key::from_base64(private_key).unwrap())
        .apply(interface, network.backend)?;
    set_addr(interface, address)?;
    set_up(interface, network.mtu.unwrap_or(1280))?;
    if !network.no_routing {
        add_route(interface, address)?;
    }
    Ok(())
}

pub fn set_listen_port(
    interface: &InterfaceName,
    listen_port: Option<u16>,
    backend: Backend,
) -> Result<(), Error> {
    let mut device = DeviceUpdate::new();
    if let Some(listen_port) = listen_port {
        device = device.set_listen_port(listen_port);
    } else {
        device = device.randomize_listen_port();
    }
    device.apply(interface, backend)?;

    Ok(())
}

pub fn down(interface: &InterfaceName, backend: Backend) -> Result<(), Error> {
    Ok(Device::get(interface, backend)
        .with_str(interface.as_str_lossy())?
        .delete()
        .with_str(interface.as_str_lossy())?)
}

pub use super::netlink::add_route;

pub trait DeviceExt {
    /// Diff the output of a wgctrl device with a list of server-reported peers.
    fn diff<'a>(&'a self, peers: &'a [Peer]) -> Vec<PeerDiff<'a>>;

    // /// Get a peer by their public key, a helper function.
    fn get_peer(&self, public_key: &str) -> Option<&PeerInfo>;
}

impl DeviceExt for Device {
    fn diff<'a>(&'a self, peers: &'a [Peer]) -> Vec<PeerDiff<'a>> {
        let interface_public_key = self
            .public_key
            .as_ref()
            .map(|k| k.to_base64())
            .unwrap_or_default();
        let existing_peers = &self.peers;

        // Match existing peers (by pubkey) to new peer information from the server.
        let modifications = peers.iter().filter_map(|peer| {
            if peer.is_disabled || peer.public_key == interface_public_key {
                None
            } else {
                let existing_peer = existing_peers
                    .iter()
                    .find(|p| p.config.public_key.to_base64() == peer.public_key);
                PeerDiff::new(existing_peer, Some(peer)).unwrap()
            }
        });

        // Remove any peers on the interface that aren't in the server's peer list any more.
        let removals = existing_peers.iter().filter_map(|existing| {
            let public_key = existing.config.public_key.to_base64();
            if peers.iter().any(|p| p.public_key == public_key) {
                None
            } else {
                PeerDiff::new(Some(existing), None).unwrap()
            }
        });

        modifications.chain(removals).collect::<Vec<_>>()
    }

    fn get_peer(&self, public_key: &str) -> Option<&PeerInfo> {
        Key::from_base64(public_key)
            .ok()
            .and_then(|key| self.peers.iter().find(|peer| peer.config.public_key == key))
    }
}

pub trait PeerInfoExt {
    /// WireGuard rejects any communication after REJECT_AFTER_TIME, so we can use this
    /// as a heuristic for "currentness" without relying on heavier things like ICMP.
    fn is_recently_connected(&self) -> bool;
}
impl PeerInfoExt for PeerInfo {
    fn is_recently_connected(&self) -> bool {
        const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

        let last_handshake = self
            .stats
            .last_handshake_time
            .and_then(|t| t.elapsed().ok())
            .unwrap_or(Duration::MAX);

        last_handshake <= REJECT_AFTER_TIME
    }
}
