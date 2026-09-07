//! Server-local management enrollment. Private artifacts never enter the API.
use crate::{
    db::{self, DatabasePeer},
    open_database_connection, ConfigFile, ServerConfig, ServerError,
};
use anyhow::{bail, Result};
use innernet_pq::{
    crypto::{Secret, SystemRandom},
    protocol::{Binary, Number},
    state::ServerState,
    store::Store,
};
use innernet_shared::management::{Enrollment, Provisioning, SecretKey};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use wireguard_control::{InterfaceName, Key, PeerConfigBuilder};

pub struct Manager {
    store: Store,
    pub(crate) state: ServerState,
}
impl Manager {
    pub fn path(conf: &ServerConfig, interface: &InterfaceName) -> PathBuf {
        conf.config_dir().join(format!("{interface}.server-pq"))
    }
    pub fn load(
        conf: &ServerConfig,
        interface: &InterfaceName,
        config: &ConfigFile,
        conn: &rusqlite::Connection,
    ) -> Result<Option<Self>> {
        let path = Self::path(conf, interface);
        if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && !config.management_required
        {
            return Ok(None);
        }
        let mut store = Store::open(&path, false)?;
        let state: ServerState = store.load()?;
        state.validate()?;
        let public = Key::from_base64(&config.private_key)?.get_public();
        if state.network_id != db::pq::network(conn)?.0
            || state.server_public_key.0.as_slice() != public.as_bytes()
            || !db::pq::is_server(conn, state.server_id.get() as i64)?
        {
            bail!("management state does not match this network; explicit recovery is required");
        }
        for peer in DatabasePeer::list(conn)? {
            if !peer.is_disabled
                && peer.id != state.server_id.get() as i64
                && !state.links.contains_key(&Number::new(peer.id as u64)?)
            {
                bail!(
                    "management PSK is missing for peer {}; independent enrollment is required",
                    peer.id
                );
            }
        }
        Ok(Some(Self { store, state }))
    }
    pub fn peer_config(
        &self,
        peer: &innernet_shared::Peer,
    ) -> Result<PeerConfigBuilder, ServerError> {
        let id = Number::new(peer.id as u64)?;
        let link = self.state.links.get(&id).ok_or(ServerError::Unavailable)?;
        Ok(PeerConfigBuilder::from(peer).set_preshared_key(Key(*link.psk.0 .0)))
    }
    pub fn enrollment(&self, peer: i64) -> Result<Enrollment> {
        let link = self
            .state
            .links
            .get(&Number::new(peer as u64)?)
            .ok_or_else(|| anyhow::anyhow!("peer has no provisioned management link"))?;
        Ok(Enrollment {
            network_id: self.state.network_id.0,
            provision_id: link.provision_id.0,
            peer_id: peer,
            server_id: self.state.server_id.get() as i64,
            psk: SecretKey::from_bytes(*link.psk.0 .0).map_err(anyhow::Error::msg)?,
        })
    }
    pub fn mark_verified(&mut self, id: i64) -> Result<(), ServerError> {
        let link = self
            .state
            .links
            .get_mut(&Number::new(id as u64)?)
            .ok_or(ServerError::Unavailable)?;
        if !link.verified {
            link.verified = true;
            if self.store.save(&self.state).is_err() {
                self.state
                    .links
                    .get_mut(&Number::new(id as u64)?)
                    .ok_or(ServerError::Unavailable)?
                    .verified = false;
                return Err(ServerError::Unavailable);
            }
        }
        Ok(())
    }

    /// Short-lived handle for administrative commands (`add-peer`,
    /// `enable-peer`) that run independently of a long-lived `serve` process.
    /// Returns `None` when this network has never required management, so
    /// callers can skip management wiring entirely for ordinary networks.
    pub fn open_or_create(
        conf: &ServerConfig,
        interface: &InterfaceName,
        config: &ConfigFile,
        conn: &rusqlite::Connection,
    ) -> Result<Option<Self>> {
        if !config.management_required {
            return Ok(None);
        }
        let path = Self::path(conf, interface);
        let public = Key::from_base64(&config.private_key)?.get_public();
        let server_id = db::pq::identify_server(conn, &public.to_base64(), config.address)?;
        let mut store = Store::open(&path, true)?;
        let state = if store.is_fresh() {
            let state = ServerState {
                network_id: db::pq::network(conn)?.0,
                server_id: Number::new(server_id as u64)?,
                server_public_key: Binary(public.as_bytes().try_into()?),
                links: BTreeMap::new(),
            };
            state.validate()?;
            store.save(&state)?;
            state
        } else {
            let state: ServerState = store.load()?;
            state.validate()?;
            if state.network_id != db::pq::network(conn)?.0
                || state.server_public_key.0.as_slice() != public.as_bytes()
                || state.server_id.get() as i64 != server_id
            {
                bail!(
                    "management state does not match this network; explicit recovery is required"
                );
            }
            state
        };
        Ok(Some(Self { store, state }))
    }

    /// Provisions a link for a newly created peer and, once every enabled
    /// peer has one, durably latches network-wide management readiness.
    pub fn provision_new_peer(
        &mut self,
        peer: i64,
        conn: &rusqlite::Connection,
    ) -> Result<Enrollment> {
        let id = Number::new(peer as u64)?;
        self.state.provision(id, None, &mut SystemRandom)?;
        self.store.save(&self.state)?;
        let complete = DatabasePeer::list(conn)?.into_iter().all(|p| {
            p.is_disabled
                || p.id == self.state.server_id.get() as i64
                || self
                    .state
                    .links
                    .contains_key(&Number::new(p.id as u64).unwrap_or(self.state.server_id))
        });
        if complete {
            db::pq::set_management_ready(conn, true)?;
        }
        self.enrollment(peer)
    }
}

/// Prepares durable secrets and migration artifacts without touching interfaces.
/// The operator must transfer each artifact confidentially through independent
/// admin access before restarting either end with management protection.
pub fn prepare(
    conf: &ServerConfig,
    interface: &InterfaceName,
    independent_admin_access: bool,
    adopted: Option<&Path>,
) -> Result<PathBuf> {
    if !independent_admin_access {
        bail!("independent authenticated administrative access is required");
    }
    let mut config = ConfigFile::from_file(conf.config_path(interface))?;
    let conn = open_database_connection(interface, conf)?;
    let public = Key::from_base64(&config.private_key)?.get_public();
    let server = db::pq::identify_server(&conn, &public.to_base64(), config.address)?;
    let adopted: BTreeMap<Number, SecretKey> = if let Some(path) = adopted {
        serde_json::from_str(&innernet_shared::private_file::read(path, true)?)
            .map_err(|_| anyhow::anyhow!("invalid private PSK adoption file; contents omitted"))?
    } else {
        BTreeMap::new()
    };
    let path = Manager::path(conf, interface);
    let mut state = ServerState {
        network_id: db::pq::network(&conn)?.0,
        server_id: Number::new(server as u64)?,
        server_public_key: Binary(public.as_bytes().try_into()?),
        links: BTreeMap::new(),
    };
    let peers = DatabasePeer::list(&conn)?;
    for id in adopted.keys() {
        if !peers
            .iter()
            .any(|p| p.id as u64 == id.get() && !p.is_disabled && p.id != server)
        {
            bail!("adoption file contains an unavailable peer identity");
        }
    }
    // Finish fallible entropy work before creating the private directory.
    for peer in &peers {
        if peer.id == server || peer.is_disabled {
            continue;
        }
        let id = Number::new(peer.id as u64)?;
        state.provision(
            id,
            adopted.get(&id).map(|s| Secret::from_bytes(*s.bytes())),
            &mut SystemRandom,
        )?;
    }
    let mut store = Store::open(&path, true)?;
    if store.is_fresh() {
        state.validate()?;
        store.save(&state)?;
    } else {
        let prior: ServerState = store.load()?;
        prior.validate()?;
        if prior.network_id != state.network_id
            || prior.server_id != state.server_id
            || prior.server_public_key != state.server_public_key
        {
            bail!("private management state belongs to a different identity");
        }
        state = prior;
        for peer in &peers {
            if peer.id == server || peer.is_disabled {
                continue;
            }
            let id = Number::new(peer.id as u64)?;
            state.provision(
                id,
                adopted.get(&id).map(|s| Secret::from_bytes(*s.bytes())),
                &mut SystemRandom,
            )?;
        }
        store.save(&state)?;
    }
    let manager = Manager { store, state };
    // This durable marker prevents missing startup flags from bypassing recovery.
    config.management_required = true;
    config.write_to_path(conf.config_path(interface))?;
    for peer in &peers {
        if peer.id == server || peer.is_disabled {
            continue;
        }
        let artifact = Provisioning {
            server_public_key: public.to_base64(),
            peer_address: peer.ip,
            enrollment: manager.enrollment(peer.id)?,
        };
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&artifact)?);
        manager
            .store
            .export(&format!("peer-{}.management.json", peer.id), &bytes)?;
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::Server;

    fn require_management(server: &Server) -> ConfigFile {
        let mut config =
            ConfigFile::from_file(server.conf().config_path(&server.interface())).unwrap();
        config.management_required = true;
        config
    }

    fn management_ready(conn: &rusqlite::Connection) -> bool {
        conn.query_row(
            "SELECT management_ready FROM pq_network WHERE singleton = 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn open_or_create_is_a_noop_when_management_was_never_required() {
        let server = Server::new().unwrap();
        let conn = server.db();
        let conn = conn.lock();
        let config = ConfigFile::from_file(server.conf().config_path(&server.interface())).unwrap();
        assert!(!config.management_required);
        assert!(
            Manager::open_or_create(server.conf(), &server.interface(), &config, &conn)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn provisioning_every_enabled_peer_latches_readiness_and_yields_independent_psks() {
        let server = Server::new().unwrap();
        let conn = server.db();
        let conn = conn.lock();
        let config = require_management(&server);
        let peers = DatabasePeer::list(&conn).unwrap();
        let enabled_ids: Vec<i64> = peers
            .iter()
            .filter(|p| !p.is_disabled && !db::pq::is_server(&conn, p.id).unwrap())
            .map(|p| p.id)
            .collect();
        assert!(enabled_ids.len() > 1);

        let mut manager =
            Manager::open_or_create(server.conf(), &server.interface(), &config, &conn)
                .unwrap()
                .unwrap();
        for (index, id) in enabled_ids.iter().enumerate() {
            manager.provision_new_peer(*id, &conn).unwrap();
            assert_eq!(management_ready(&conn), index + 1 == enabled_ids.len());
        }

        // Every peer's provisioned link is independent, and re-provisioning is idempotent.
        let first = manager.state.links[&Number::new(enabled_ids[0] as u64).unwrap()]
            .psk
            .clone();
        let second = manager.state.links[&Number::new(enabled_ids[1] as u64).unwrap()]
            .psk
            .clone();
        assert!(!first.0.same(&second.0));
        let enrollment_again = manager.provision_new_peer(enabled_ids[0], &conn).unwrap();
        assert!(enrollment_again.psk.bytes() == first.0 .0.as_slice());
        drop(manager); // releases the exclusive interface lock, like `add_peer` exiting.

        // Reopening independently (as `serve` would) sees the same durable links.
        let reopened = Manager::load(server.conf(), &server.interface(), &config, &conn)
            .unwrap()
            .unwrap();
        for id in &enabled_ids {
            let peer = DatabasePeer::get(&conn, *id).unwrap();
            let built = reopened.peer_config(&peer).unwrap();
            assert_eq!(
                *built.public_key(),
                wireguard_control::Key::from_base64(&peer.public_key).unwrap()
            );
        }
    }

    #[test]
    fn load_fails_closed_when_an_enabled_peer_has_no_provisioned_link() {
        let server = Server::new().unwrap();
        let conn = server.db();
        let conn = conn.lock();
        let config = require_management(&server);
        let peers = DatabasePeer::list(&conn).unwrap();
        let enabled_ids: Vec<i64> = peers
            .iter()
            .filter(|p| !p.is_disabled && !db::pq::is_server(&conn, p.id).unwrap())
            .map(|p| p.id)
            .collect();

        let mut manager =
            Manager::open_or_create(server.conf(), &server.interface(), &config, &conn)
                .unwrap()
                .unwrap();
        // Provision every peer except the last: `load` must refuse readiness.
        for id in &enabled_ids[..enabled_ids.len() - 1] {
            manager.provision_new_peer(*id, &conn).unwrap();
        }
        assert!(!management_ready(&conn));
        assert!(Manager::load(server.conf(), &server.interface(), &config, &conn).is_err());
    }
}
