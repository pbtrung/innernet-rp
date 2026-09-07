//! Confidential invitation metadata. Never part of public peer/state responses.
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct SecretKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey([redacted])")
    }
}
impl SecretKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, &'static str> {
        if bytes == [0; 32] {
            Err("a management PSK must not be zero")
        } else {
            Ok(Self(Zeroizing::new(bytes)))
        }
    }
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn wireguard_key(&self) -> wireguard_control::Key {
        wireguard_control::Key(*self.0)
    }
}
impl Serialize for SecretKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = Zeroizing::new(STANDARD.encode(self.0.as_slice()));
        serializer.serialize_str(&text)
    }
}
impl<'de> Deserialize<'de> for SecretKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = Zeroizing::new(String::deserialize(deserializer)?);
        let mut bytes = Zeroizing::new([0; 32]);
        if text.len() != 44
            || STANDARD
                .decode_slice(text.as_bytes(), bytes.as_mut_slice())
                .map_err(|_| D::Error::custom("invalid management PSK"))?
                != 32
            || Zeroizing::new(STANDARD.encode(bytes.as_slice())).as_str() != text.as_str()
        {
            return Err(D::Error::custom("invalid management PSK"));
        }
        Self::from_bytes(*bytes).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Enrollment {
    pub network_id: [u8; 16],
    pub provision_id: [u8; 16],
    pub peer_id: i64,
    pub server_id: i64,
    pub psk: SecretKey,
}
impl Enrollment {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.peer_id <= 0 || self.server_id <= 0 || self.peer_id == self.server_id {
            return Err("invalid management enrollment identities");
        }
        Ok(())
    }
}

/// Existing-interface migration artifact, delivered through an independent
/// authenticated confidential channel, never through public directory records.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Provisioning {
    pub server_public_key: String,
    pub peer_address: std::net::IpAddr,
    pub enrollment: Enrollment,
}
