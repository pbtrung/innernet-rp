//! Public, versioned API objects. They never contain endpoint secrets.
use crate::{
    Error, Result, crypto,
    protocol::{Binary, Bundle, Decision, Message, Number, REQUEST_LIMIT, Transcript},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Enabled,
    Retired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertisedBundle {
    pub pq_version: u8,
    pub lifecycle: Lifecycle,
    pub bundle: Bundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub expected_revision: Option<Number>,
    pub pq_version: u8,
    pub lifecycle: Lifecycle,
    pub bundle: Bundle,
    /// Explicit emergency retirement may terminate committed work while gated.
    pub emergency: bool,
}
impl Registration {
    pub fn parse(body: &[u8]) -> Result<Self> {
        if body.len() > REQUEST_LIMIT {
            return Err(Error::Invalid);
        }
        let value: Self = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        if value.pq_version != 1 || (value.emergency && value.lifecycle != Lifecycle::Retired) {
            return Err(Error::Invalid);
        }
        value.bundle.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageDigest {
    pub sender_id: Number,
    pub message_type: u8,
    pub digest: Binary<32>,
}
impl MessageDigest {
    pub fn of(message: &Message) -> Result<Self> {
        Ok(Self {
            sender_id: message.sender_id,
            message_type: message.message_type,
            digest: Binary(crypto::hash(
                &serde_json::to_vec(message).map_err(|_| Error::Invalid)?,
            )?),
        })
    }
}

/// Active records carry the exact transcript/messages. Terminal records compact
/// those bodies, preserving the high-water decision and identical-retry digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    pub network_id: Binary<16>,
    pub initiator_id: Number,
    pub responder_id: Number,
    pub initiator_bundle_id: Binary<16>,
    pub responder_bundle_id: Binary<16>,
    pub sequence: Number,
    pub exchange_id: Binary<16>,
    pub transcript_hash: Binary<32>,
    pub decision: Decision,
    pub created_at: u64,
    pub prepare_expires_at: u64,
    pub transcript: Option<Transcript>,
    pub messages: Vec<Message>,
    pub receipts: Vec<MessageDigest>,
    /// Explicit administrative invalidation is not an ordinary pre-commit abort.
    pub termination: Option<String>,
}
impl Exchange {
    pub fn compact(&mut self) {
        if self.decision.terminal() {
            self.transcript = None;
            self.messages.clear();
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerState<P> {
    pub peer: P,
    pub is_server: bool,
    pub pq: Option<AdvertisedBundle>,
}

/// Explicit opt-in shape. Legacy state responses remain unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePage<P, C> {
    pub pq_version: u8,
    pub network_id: Binary<16>,
    pub visibility_revision: Number,
    pub peers: Vec<PeerState<P>>,
    pub cidrs: Vec<C>,
    pub exchanges: Vec<Exchange>,
    pub next_cursor: Option<String>,
}
