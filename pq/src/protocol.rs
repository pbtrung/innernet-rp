//! Canonical protocol v1 encodings. Wire values are deliberately not permissive.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use subtle::ConstantTimeEq;

use crate::{
    Error, Result,
    crypto::{self, Candidate, Secret},
};

pub const REQUEST_LIMIT: usize = 8192;
pub const PREPARE_TTL: u64 = 600;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Binary<const N: usize>(pub [u8; N]);
impl<const N: usize> Serialize for Binary<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(self.0))
    }
}
impl<'de, const N: usize> Deserialize<'de> for Binary<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() != N.div_ceil(3) * 4 {
            return Err(D::Error::custom("invalid binary length"));
        }
        let bytes = STANDARD
            .decode(&value)
            .map_err(|_| D::Error::custom("invalid base64"))?;
        if STANDARD.encode(&bytes) != value {
            return Err(D::Error::custom("noncanonical base64"));
        }
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| D::Error::custom("invalid binary length"))?,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Number(u64);
impl Number {
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 || value > i64::MAX as u64 {
            Err(Error::Invalid)
        } else {
            Ok(Self(value))
        }
    }
    pub fn get(self) -> u64 {
        self.0
    }
    pub fn next(self) -> Result<Self> {
        Self::new(self.0.checked_add(1).ok_or(Error::Invalid)?)
    }
}
impl Serialize for Number {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}
impl<'de> Deserialize<'de> for Number {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || value.starts_with('0') || !value.bytes().all(|c| c.is_ascii_digit())
        {
            return Err(D::Error::custom("noncanonical decimal identifier"));
        }
        Self::new(value.parse().map_err(D::Error::custom)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub bundle_id: Binary<16>,
    pub bundle_revision: Number,
    pub wg_public_key: Binary<32>,
    pub pq_kem_public_key: Binary<1568>,
    pub pq_x448_public_key: Binary<56>,
    pub pq_sig_public_key: Binary<67>,
}
impl Bundle {
    pub fn validate(&self) -> Result<()> {
        crypto::validate_kem(&self.pq_kem_public_key.0)?;
        crypto::validate_x448(&self.pq_x448_public_key.0)?;
        crypto::validate_signing(&self.pq_sig_public_key.0)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1747);
        out.extend_from_slice(&self.bundle_id.0);
        out.extend_from_slice(&self.bundle_revision.get().to_be_bytes());
        out.extend_from_slice(&self.wg_public_key.0);
        out.extend_from_slice(&self.pq_kem_public_key.0);
        out.extend_from_slice(&self.pq_x448_public_key.0);
        out.extend_from_slice(&self.pq_sig_public_key.0);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    pub network_id: Binary<16>,
    pub initiator_id: Number,
    pub responder_id: Number,
    pub initiator: Bundle,
    pub responder: Bundle,
    pub sequence: Number,
    pub exchange_id: Binary<16>,
    pub operator_psk_id: Binary<16>,
    /// ML-KEM ciphertext followed by leancrypto's ephemeral X448 public key.
    pub ciphertext: Binary<1624>,
}
impl Transcript {
    pub fn validate(&self) -> Result<()> {
        if self.initiator_id >= self.responder_id {
            return Err(Error::Invalid);
        }
        self.initiator.validate()?;
        self.responder.validate()?;
        crypto::validate_x448(
            self.ciphertext.0[1568..]
                .try_into()
                .map_err(|_| Error::Invalid)?,
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = b"innernet pq-psk v1 transcript".to_vec();
        out.push(1);
        out.extend_from_slice(&self.network_id.0);
        out.extend_from_slice(&self.initiator_id.get().to_be_bytes());
        out.extend_from_slice(&self.responder_id.get().to_be_bytes());
        out.extend(self.initiator.encode());
        out.extend(self.responder.encode());
        out.extend_from_slice(&self.sequence.get().to_be_bytes());
        out.extend_from_slice(&self.exchange_id.0);
        out.extend_from_slice(&self.operator_psk_id.0);
        out.extend_from_slice(&self.ciphertext.0);
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Propose = 1,
    Ready = 2,
    Commit = 3,
    Installed = 4,
    Confirmed = 5,
    Abort = 6,
}
impl TryFrom<u8> for Kind {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Propose),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Commit),
            4 => Ok(Self::Installed),
            5 => Ok(Self::Confirmed),
            6 => Ok(Self::Abort),
            _ => Err(Error::Invalid),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub version: u8,
    pub network_id: Binary<16>,
    pub initiator_id: Number,
    pub responder_id: Number,
    pub initiator_bundle_id: Binary<16>,
    pub responder_bundle_id: Binary<16>,
    pub sequence: Number,
    pub exchange_id: Binary<16>,
    pub transcript_hash: Binary<32>,
    pub sender_id: Number,
    pub message_type: u8,
    pub tag: Binary<32>,
    pub signature: Binary<132>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<Binary<1624>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_psk_id: Option<Binary<16>>,
}
impl Message {
    pub fn validate_shape(&self) -> Result<Kind> {
        let kind = Kind::try_from(self.message_type)?;
        if self.version != 1 || self.initiator_id >= self.responder_id {
            return Err(Error::Invalid);
        }
        let initiator = self.sender_id == self.initiator_id;
        let responder = self.sender_id == self.responder_id;
        if !(initiator || responder)
            || (kind == Kind::Ready && !responder)
            || (matches!(kind, Kind::Propose | Kind::Commit | Kind::Abort) && !initiator)
        {
            return Err(Error::Invalid);
        }
        let proposal = kind == Kind::Propose;
        if self.ciphertext.is_some() != proposal || self.operator_psk_id.is_some() != proposal {
            return Err(Error::Invalid);
        }
        Ok(kind)
    }
    pub fn envelope(&self) -> Vec<u8> {
        let mut out = b"innernet pq-psk v1 message".to_vec();
        out.push(self.version);
        out.extend_from_slice(&self.network_id.0);
        out.extend_from_slice(&self.initiator_id.get().to_be_bytes());
        out.extend_from_slice(&self.responder_id.get().to_be_bytes());
        out.extend_from_slice(&self.initiator_bundle_id.0);
        out.extend_from_slice(&self.responder_bundle_id.0);
        out.extend_from_slice(&self.sequence.get().to_be_bytes());
        out.extend_from_slice(&self.exchange_id.0);
        out.extend_from_slice(&self.transcript_hash.0);
        out.extend_from_slice(&self.sender_id.get().to_be_bytes());
        out.push(self.message_type);
        out
    }
    pub fn authenticate(&self, transcript: &Transcript) -> Result<()> {
        self.validate_shape()?;
        if self.network_id != transcript.network_id
            || self.initiator_id != transcript.initiator_id
            || self.responder_id != transcript.responder_id
            || self.initiator_bundle_id != transcript.initiator.bundle_id
            || self.responder_bundle_id != transcript.responder.bundle_id
            || self.sequence != transcript.sequence
            || self.exchange_id != transcript.exchange_id
            || self.transcript_hash.0 != crypto::hash(&transcript.encode())?
            || self
                .ciphertext
                .as_ref()
                .is_some_and(|c| c != &transcript.ciphertext)
            || self
                .operator_psk_id
                .as_ref()
                .is_some_and(|id| id != &transcript.operator_psk_id)
        {
            return Err(Error::Invalid);
        }
        let bundle = if self.sender_id == self.initiator_id {
            &transcript.initiator
        } else {
            &transcript.responder
        };
        let mut signed = self.envelope();
        signed.extend_from_slice(&self.tag.0);
        crypto::verify(&bundle.pq_sig_public_key.0, &self.signature.0, &signed)
    }
    pub fn confirm(&self, candidate: &Candidate) -> Result<()> {
        self.validate_shape()?;
        let key = if self.sender_id == self.initiator_id {
            &candidate.initiator_confirmation
        } else {
            &candidate.responder_confirmation
        };
        if bool::from(crypto::tag(key, &self.envelope())?.ct_eq(&self.tag.0)) {
            Ok(())
        } else {
            Err(Error::Crypto)
        }
    }
    pub fn signed(
        transcript: &Transcript,
        kind: Kind,
        sender: Number,
        candidate: &Candidate,
        signing_key: &Secret<66>,
    ) -> Result<Self> {
        let mut message = Self {
            version: 1,
            network_id: transcript.network_id.clone(),
            initiator_id: transcript.initiator_id,
            responder_id: transcript.responder_id,
            initiator_bundle_id: transcript.initiator.bundle_id.clone(),
            responder_bundle_id: transcript.responder.bundle_id.clone(),
            sequence: transcript.sequence,
            exchange_id: transcript.exchange_id.clone(),
            transcript_hash: Binary(crypto::hash(&transcript.encode())?),
            sender_id: sender,
            message_type: kind as u8,
            tag: Binary([0; 32]),
            signature: Binary([0; 132]),
            ciphertext: (kind == Kind::Propose).then(|| transcript.ciphertext.clone()),
            operator_psk_id: (kind == Kind::Propose).then(|| transcript.operator_psk_id.clone()),
        };
        message.validate_shape()?;
        let key = if sender == transcript.initiator_id {
            &candidate.initiator_confirmation
        } else {
            &candidate.responder_confirmation
        };
        message.tag = Binary(crypto::tag(key, &message.envelope())?);
        let mut signed = message.envelope();
        signed.extend_from_slice(&message.tag.0);
        message.signature = Binary(crypto::sign(signing_key, &signed)?);
        Ok(message)
    }
}

pub fn parse_message(body: &[u8]) -> Result<Message> {
    if body.len() > REQUEST_LIMIT {
        return Err(Error::Invalid);
    }
    let message: Message = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
    // Option fields must be absent, not explicit null. Derived struct decoding
    // already rejects duplicate/unknown fields and trailing JSON values.
    let object: serde_json::Value = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
    if ["ciphertext", "operator_psk_id"]
        .iter()
        .any(|key| object.get(key).is_some_and(|v| v.is_null()))
    {
        return Err(Error::Invalid);
    }
    message.validate_shape()?;
    Ok(message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Proposed,
    Ready,
    Committed,
    Complete,
    Aborted,
}

/// Pure transition model; persistence and replay admission wrap it in M1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub phase: Phase,
    pub installed: [bool; 2],
    pub confirmed: [bool; 2],
}
impl Default for Decision {
    fn default() -> Self {
        Self {
            phase: Phase::Proposed,
            installed: [false; 2],
            confirmed: [false; 2],
        }
    }
}
impl Decision {
    pub fn advance(&mut self, kind: Kind, initiator: bool) -> Result<()> {
        let side = usize::from(!initiator);
        match (self.phase, kind) {
            (Phase::Proposed, Kind::Ready) if !initiator => self.phase = Phase::Ready,
            (Phase::Ready, Kind::Commit) if initiator => self.phase = Phase::Committed,
            (Phase::Proposed | Phase::Ready, Kind::Abort) if initiator => {
                self.phase = Phase::Aborted
            },
            (Phase::Committed, Kind::Installed) if !initiator || self.installed[1] => {
                self.installed[side] = true
            },
            (Phase::Committed, Kind::Confirmed) if self.installed[side] => {
                self.confirmed[side] = true;
                if self.confirmed == [true; 2] {
                    self.phase = Phase::Complete;
                }
            },
            _ => return Err(Error::Conflict),
        }
        Ok(())
    }
    pub fn expire(&mut self) {
        if matches!(self.phase, Phase::Proposed | Phase::Ready) {
            self.phase = Phase::Aborted;
        }
    }
    pub fn terminal(&self) -> bool {
        matches!(self.phase, Phase::Complete | Phase::Aborted)
    }
}
