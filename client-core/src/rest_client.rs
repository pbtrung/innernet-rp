use innernet_shared::{
    interface_config::ServerInfo, Cidr, CidrContents, Peer, PeerContents, INNERNET_PUBKEY_HEADER,
};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;
use thiserror::Error;
use ureq::Agent;

/// A REST client that can be used to communicate with an innernet REST server.
///
/// We recommend to use the high level API (like [`Self::create_peer()`]) when possible and fall
/// back on the low level [`Self::http()`] and [`Self::http_form()`] otherwise.
pub struct RestClient<'a> {
    agent: Agent,
    server: &'a ServerInfo,
}

impl<'a> RestClient<'a> {
    /// Create a [`Self`] to communicate with an innernet server described by [`ServerInfo`].
    pub fn new(server: &'a ServerInfo) -> Self {
        let agent = Agent::config_builder()
            // Some platforms (e.g. OpenBSD) can take longer to complete the first WireGuard
            // handshake, hence a lower timeout value could result in an unwarranted failure
            .timeout_global(Some(Duration::from_secs(10)))
            .max_redirects(0)
            .build().into();
        Self { agent, server }
    }

    pub fn create_cidr(&self, cidr_contents: &CidrContents) -> Result<Cidr, RestError> {
        let cidr = self.http_form("POST", "/admin/cidrs", cidr_contents)?;
        Ok(cidr)
    }

    pub fn get_cidrs(&self) -> Result<Vec<Cidr>, RestError> {
        let cidrs = self.http("GET", "/admin/cidrs")?;
        Ok(cidrs)
    }

    pub fn create_peer(&self, peer_contents: &PeerContents) -> Result<Peer, RestError> {
        let peer = self.http_form("POST", "/admin/peers", peer_contents)?;
        Ok(peer)
    }

    pub fn get_peers(&self) -> Result<Vec<Peer>, RestError> {
        let peers = self.http("GET", "/admin/peers")?;
        Ok(peers)
    }

    #[allow(clippy::result_large_err)]
    /// Perform a `verb` HTTP request at the given `endpoint`.
    ///
    /// Example: `rest_client.http("GET", "/admin/peers")?;`.
    pub fn http<T: DeserializeOwned>(&self, verb: &str, endpoint: &str) -> Result<T, RestError> {
        self.request::<(), _>(verb, endpoint, None)
    }

    /// Send serializable data using a `verb` HTTP request at the given `endpoint`
    ///
    /// Example: `rest_client.http_form("POST", "/admin/peers", PeerContents { .. })?;`.
    #[allow(clippy::result_large_err)]
    pub fn http_form<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: S,
    ) -> Result<T, RestError> {
        self.request(verb, endpoint, Some(form))
    }

    #[allow(clippy::result_large_err)]
    fn request<S: Serialize, T: DeserializeOwned>(
        &self,
        verb: &str,
        endpoint: &str,
        form: Option<S>,
    ) -> Result<T, RestError> {
        let payload = form
            .map(|form| serde_json::to_vec(&form))
            .transpose()
            .map_err(RestError::RequestSerialize)?
            .unwrap_or_default();
        let request = ureq::http::Request::builder()
            .method(verb)
            .uri(format!(
                "http://{}/v1{}",
                self.server.internal_endpoint, endpoint
            ))
            .header(INNERNET_PUBKEY_HEADER, &self.server.public_key)
            .header("content-type", "application/json")
            .body(payload)
            .map_err(RestError::RequestBuild)?;
        let mut response = self
            .agent
            .run(request)
            .map_err(|e| RestError::RequestSend(Box::new(e)))?;
        let mut response = response
            .body_mut()
            .read_to_string()
            .map_err(RestError::ResponseRead)?;
        // A little trick for serde to parse an empty response as `()`.
        if response.is_empty() {
            response = "null".into();
        }
        serde_json::from_str(&response).map_err(RestError::ResponseDeserialize)
    }
}

#[derive(Debug, Error)]
pub enum RestError {
    #[error("Error building request: {0}")]
    RequestBuild(ureq::http::Error),
    #[error("Error sending request: {0}")]
    RequestSend(Box<ureq::Error>),
    #[error("Error serializing request: {0}")]
    RequestSerialize(serde_json::Error),
    #[error("Error deserializing response: {0}")]
    ResponseDeserialize(serde_json::Error),
    #[error("Error reading response: {0}")]
    ResponseRead(ureq::Error),
}

impl RestError {
    pub fn has_status_of(&self, status: u16) -> bool {
        if let RestError::RequestSend(error) = self {
            matches!(**error, ureq::Error::StatusCode(s) if s == status)
        } else {
            false
        }
    }

    pub fn is_transport_error(&self) -> bool {
        if let RestError::RequestSend(error) = self {
            matches!(
                **error,
                ureq::Error::Io(_)
                    | ureq::Error::Timeout(_)
                    | ureq::Error::HostNotFound
                    | ureq::Error::ConnectionFailed
                    | ureq::Error::Protocol(_)
            )
        } else {
            false
        }
    }
}
