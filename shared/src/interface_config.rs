use crate::{ensure_dirs_exist, Endpoint, Error, IoErrorContext, Peer, WrappedIoError};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io,
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
}

#[derive(Clone, Deserialize, Serialize)]
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

impl std::fmt::Debug for InterfaceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceInfo")
            .field("network_name", &self.network_name)
            .field("address", &self.address)
            .field("private_key", &"[redacted]")
            .field("listen_port", &self.listen_port)
            .finish()
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management: Option<crate::management::Enrollment>,
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
            management: None,
        }
    }

    pub fn with_management(mut self, management: Option<crate::management::Enrollment>) -> Self {
        self.management = management;
        self
    }
}

impl InterfaceConfig {
    fn new(interface: InterfaceInfo, server: ServerInfo) -> Self {
        InterfaceConfig {
            interface,
            server,
            peer_endpoint_overrides: BTreeMap::new(),
        }
    }

    /// Save a new config file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>, mode: u32) -> Result<(), WrappedIoError> {
        let path = path.as_ref();
        if mode != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "confidential configurations require mode 0600",
            ))
            .with_path(path);
        }
        crate::private_file::write_toml(path, self, true).with_path(path)
    }

    /// Overwrites the config file if it already exists.
    pub fn save(&self, config_dir: &Path, interface: &InterfaceName) -> Result<PathBuf, Error> {
        let path = Self::build_config_file_path(config_dir, interface)?;
        crate::private_file::write_toml(&path, self, false).with_path(&path)?;

        Ok(path)
    }

    fn as_toml(&self) -> zeroize::Zeroizing<String> {
        zeroize::Zeroizing::new(
            toml::to_string(self).expect("serializable interface configuration"),
        )
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let text = crate::private_file::read(path, true).with_path(path)?;
        let value: Self = toml::from_str(&text).map_err(|_| {
            anyhow::anyhow!("invalid interface configuration; private contents omitted")
        })?;
        if let Some(management) = &value.server.management {
            management.validate().map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(value)
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

    /// Save a new invitation file, failing if it already exists.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<(), io::Error> {
        let mut text = zeroize::Zeroizing::new(indoc::formatdoc!(
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
        ));
        text.push_str(&self.interface_config.as_toml());
        crate::private_file::write(path.as_ref(), text.as_bytes(), true)
    }
}
