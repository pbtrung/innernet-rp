use crate::{chmod, ensure_dirs_exist, Endpoint, Error, IoErrorContext, Peer, WrappedIoError};
use indoc::writedoc;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, KeyPair};

/// This struct contains everything necessary to establish an innernet connection: information about
/// a local innernet interface and a remote innernet server.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceConfig {
    /// The information to bring up the interface.
    pub interface: InterfaceInfo,

    /// The necessary contact information for the server.
    pub server: ServerInfo,

    /// A configurable map of peer IP addresses to Endpoints which should
    /// be used as the WireGuard endpoint for that peer.
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    peer_endpoint_overrides: BTreeMap<IpAddr, Endpoint>,

    /// A static WireGuard preshared key protecting this peer's link back to whichever admin
    /// peer created its invitation (reusing `wg_export`'s local exported-peer PSK mechanism,
    /// not just a non-innernet-peer feature despite the module name - see `add_peer` in
    /// `client/src/main.rs`) - baseline PSK protection for that one link, immediately, whether
    /// or not Rosenpass ever gets enabled on either side. `None` for invitations created before
    /// this existed. Only meaningful on first read at `install` time, which consumes it (via
    /// `Option::take`) to seed this peer's own local PSK store before it's ever persisted here -
    /// nothing re-reads or re-writes this field afterward, so it never lingers in a peer's own
    /// saved config; rotating it would need a fresh invitation, like the private key itself.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_link_psk: Option<AdminLinkPsk>,
}

/// See `InterfaceConfig::admin_link_psk`.
#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct AdminLinkPsk {
    /// The admin peer's stable database id - *not* its WireGuard public key, which changes when
    /// this new peer redeems its own invitation (a freshly-generated keypair gets registered
    /// with the server, replacing the invitation's temporary one), so anything keyed by public
    /// key set at invitation-creation time would silently stop matching. The admin's own id
    /// never changes, so this is what `shared::wg_export`'s local PSK store is keyed by on both
    /// ends of the link (see that module for the same reasoning from the admin's side).
    pub admin_peer_id: i64,
    /// The preshared key itself (base64), matching what the admin peer already applied locally
    /// to its own link to this new peer.
    pub psk: String,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct InterfaceInfo {
    /// The interface name (i.e. "tonari")
    pub network_name: String,

    /// The invited peer's internal IP address that's been allocated to it, inside
    /// the entire network's CIDR prefix.
    pub address: IpNet,

    /// WireGuard private key (base64)
    pub private_key: String,

    /// The local listen port. A random port will be used if `None`.
    pub listen_port: Option<u16>,
}

impl InterfaceInfo {
    pub fn new(network_name: &InterfaceName, keypair: &KeyPair, address: IpNet) -> Self {
        Self {
            network_name: network_name.to_string(),
            private_key: keypair.private.to_base64(),
            address,
            listen_port: None,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct ServerInfo {
    /// The server's WireGuard public key
    pub public_key: String,

    /// The external internet endpoint to reach the server.
    pub external_endpoint: Endpoint,

    /// An internal endpoint in the WireGuard network that hosts the coordination API.
    pub internal_endpoint: SocketAddr,
}

impl ServerInfo {
    pub fn new(server_peer: &Peer, internal_endpoint: SocketAddr) -> Self {
        Self {
            external_endpoint: server_peer
                .endpoint
                .clone()
                .expect("The innernet server should have a WireGuard endpoint"),
            internal_endpoint,
            public_key: server_peer.public_key.clone(),
        }
    }
}

impl InterfaceConfig {
    fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        InterfaceConfig {
            interface,
            server,
            peer_endpoint_overrides: BTreeMap::new(),
            admin_link_psk: None,
        }
    }

    /// Save a new config file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>, mode: u32) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .with_path(path)?;

        chmod(&file, mode).with_path(path)?;

        file.write_all(self.as_toml().as_bytes()).with_path(path)?;

        Ok(())
    }

    /// Overwrites the config file if it already exists.
    pub fn save(&self, config_dir: &Path, interface: &InterfaceName) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        File::create(&path)
            .with_path(&path)?
            .write_all(self.as_toml().as_bytes())?;

        Ok(path)
    }

    fn as_toml(&self) -> String {
        toml::to_string(self).unwrap()
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(toml::from_str(
            &std::fs::read_to_string(&path).with_path(path)?,
        )?)
    }

    pub fn from_interface(config_dir: &Path, interface: &InterfaceName) -> Result<Self, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        crate::warn_on_dangerous_mode(&path).with_path(&path)?;
        Self::from_file(path)
    }

    pub fn get_path(config_dir: &Path, interface: &InterfaceName) -> PathBuf {
        config_dir
            .join(interface.to_string())
            .with_extension("conf")
    }

    pub fn build_config_file_path(
        config_dir: &Path,
        interface: &InterfaceName,
    ) -> Result<PathBuf, WrappedIoError> {
        ensure_dirs_exist(&[config_dir])?;
        Ok(Self::get_path(config_dir, interface))
    }

    pub fn peer_endpoint_overrides(&self) -> &BTreeMap<IpAddr, Endpoint> {
        &self.peer_endpoint_overrides
    }

    pub fn set_endpoint_override_for_peer(&mut self, peer_ip: IpAddr, endpoint: Endpoint) {
        self.peer_endpoint_overrides.insert(peer_ip, endpoint);
    }

    pub fn unset_endpoint_override_for_peer(&mut self, peer_ip: IpAddr) {
        self.peer_endpoint_overrides.remove(&peer_ip);
    }
}

impl InterfaceInfo {
    pub fn public_key(&self) -> Result<String, Error> {
        Ok(wireguard_control::Key::from_base64(&self.private_key)?
            .get_public()
            .to_base64())
    }
}

#[must_use]
pub struct PeerInvitation {
    interface_config: InterfaceConfig,
}

impl PeerInvitation {
    pub fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        Self {
            interface_config: InterfaceConfig::new(interface, server),
        }
    }

    /// The generated keypair/address this invitation carries, e.g. for rendering a static
    /// `wg-quick` config instead of an innernet-native invitation (see `wg_export`).
    pub fn interface_config(&self) -> &InterfaceConfig {
        &self.interface_config
    }

    /// Attaches a static preshared key protecting this invited peer's link back to the admin
    /// peer creating the invitation (see `InterfaceConfig::admin_link_psk`). The admin's own
    /// side of that link is the caller's responsibility to seed locally (see `wg_export`) -
    /// this only conveys what the new peer needs to seed its own side once installed.
    pub fn set_admin_link_psk(&mut self, admin_peer_id: i64, psk: String) {
        self.interface_config.admin_link_psk = Some(AdminLinkPsk { admin_peer_id, psk });
    }

    /// Save a new invitation file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;

        writedoc!(
            file,
            r"
                    # This is an invitation file to an innernet network.
                    #
                    # To join, you must install innernet.
                    # See https://github.com/tonarino/innernet for instructions.
                    #
                    # If you have innernet, just run:
                    #
                    #   innernet install <this file>
                    #
                    # Don't edit the contents below unless you love chaos and dysfunction.
                "
        )?;

        file.write_all(self.interface_config.as_toml().as_bytes())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wireguard_control::KeyPair;

    fn test_interface_info() -> InterfaceInfo {
        InterfaceInfo::new(
            &"evilcorp".parse().unwrap(),
            &KeyPair::generate(),
            "10.80.0.5/32".parse().unwrap(),
        )
    }

    fn test_server_info() -> ServerInfo {
        ServerInfo {
            public_key: "serverkey".to_string(),
            external_endpoint: "1.2.3.4:51820".parse().unwrap(),
            internal_endpoint: "10.80.0.1:51820".parse().unwrap(),
        }
    }

    #[test]
    fn test_admin_link_psk_roundtrip() {
        let mut config = InterfaceConfig::new(test_interface_info(), test_server_info());
        assert!(config.admin_link_psk.is_none());

        config.admin_link_psk = Some(AdminLinkPsk {
            admin_peer_id: 1,
            psk: "psk-base64".to_string(),
        });

        let toml = toml::to_string(&config).unwrap();
        assert!(toml.contains("admin-link-psk"));

        let parsed: InterfaceConfig = toml::from_str(&toml).unwrap();
        let link = parsed.admin_link_psk.unwrap();
        assert_eq!(link.admin_peer_id, 1);
        assert_eq!(link.psk, "psk-base64");
    }

    #[test]
    fn test_old_shaped_config_without_admin_link_psk_still_parses() {
        // Simulates an invitation/config saved before this field existed - must still
        // deserialize successfully, defaulting to None, not fail or panic.
        let old = format!(
            r#"
            [interface]
            network-name = "evilcorp"
            address = "10.80.0.5/32"
            private-key = "{}"
            listen-port = 51820

            [server]
            public-key = "serverkey"
            external-endpoint = "1.2.3.4:51820"
            internal-endpoint = "10.80.0.1:51820"
            "#,
            KeyPair::generate().private.to_base64()
        );

        let parsed: InterfaceConfig =
            toml::from_str(&old).expect("old-shaped config without admin-link-psk must parse");
        assert!(parsed.admin_link_psk.is_none());
    }

    #[test]
    fn test_peer_invitation_set_admin_link_psk() {
        let mut invitation = PeerInvitation::new(test_interface_info(), test_server_info());
        assert!(invitation.interface_config().admin_link_psk.is_none());

        invitation.set_admin_link_psk(1, "psk-base64".to_string());

        let link = invitation
            .interface_config()
            .admin_link_psk
            .as_ref()
            .unwrap();
        assert_eq!(link.admin_peer_id, 1);
        assert_eq!(link.psk, "psk-base64");
    }
}
