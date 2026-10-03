//! QuMail Core Domain Models & Types
//!
//! Provides fundamental security levels, crypto context, identifiers,
//! and canonical domain errors for the QuMail architecture.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Protocol version identifier for QuMail envelopes.
pub const QUMAIL_PROTOCOL_VERSION: u16 = 1;

/// Cryptographic security level selected for a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    /// Level 1: Standard email encryption using conventional TLS/MIME infrastructure.
    Baseline = 1,
    /// Level 2: Quantum-aided AES-256-GCM using symmetric quantum keys as seed.
    Qaes = 2,
    /// Level 2.5: Hybrid Post-Quantum Cryptography + symmetric encryption.
    HybridPqc = 3,
    /// Level 3: Information-Theoretically Secure One-Time Pad with Carter-Wegman MAC.
    QuantumOtp = 4,
}

impl SecurityLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Baseline => "baseline",
            SecurityLevel::Qaes => "qaes",
            SecurityLevel::HybridPqc => "hybrid_pqc",
            SecurityLevel::QuantumOtp => "quantum_otp",
        }
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SecurityLevel {
    type Err = QuMailError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "1" | "baseline" | "none" => Ok(SecurityLevel::Baseline),
            "2" | "qaes" | "aes" | "q-aes" => Ok(SecurityLevel::Qaes),
            "2.5" | "hybrid" | "hybrid_pqc" | "pqc" => Ok(SecurityLevel::HybridPqc),
            "3" | "otp" | "quantum_otp" | "quantum-otp" => Ok(SecurityLevel::QuantumOtp),
            _ => Err(QuMailError::InvalidSecurityLevel(s.to_string())),
        }
    }
}

/// Strongly typed Message Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub String);

impl MessageId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Strongly typed Key Identifier (UUID string from ETSI QKD 014 or local key bank).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

impl KeyId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }

    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

impl Default for KeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Secure Application Entity (SAE) numerical or string ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SaeId(pub u64);

impl fmt::Display for SaeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Cryptographic Context accompanying an encryption or decryption operation.
///
/// Ensures domain separation and prevents cross-protocol or cross-session replay attacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoContext {
    pub protocol_version: u16,
    pub message_id: MessageId,
    pub sender_sae: SaeId,
    pub recipient_sae: SaeId,
    pub key_id: KeyId,
    pub timestamp_epoch_secs: u64,
}

impl CryptoContext {
    pub fn new(sender_sae: SaeId, recipient_sae: SaeId, key_id: KeyId) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            protocol_version: QUMAIL_PROTOCOL_VERSION,
            message_id: MessageId::new(),
            sender_sae,
            recipient_sae,
            key_id,
            timestamp_epoch_secs: now,
        }
    }

    /// Generates canonical bytes to bind as Authenticated Associated Data (AAD).
    ///
    /// The serialization uses fixed-length encoding and length prefixes to prevent
    /// canonicalization ambiguities.
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(64);
        aad.extend_from_slice(&self.protocol_version.to_be_bytes());
        aad.extend_from_slice(&self.sender_sae.0.to_be_bytes());
        aad.extend_from_slice(&self.recipient_sae.0.to_be_bytes());
        aad.extend_from_slice(&self.timestamp_epoch_secs.to_be_bytes());
        
        let msg_id_bytes = self.message_id.0.as_bytes();
        aad.extend_from_slice(&(msg_id_bytes.len() as u16).to_be_bytes());
        aad.extend_from_slice(msg_id_bytes);

        let key_id_bytes = self.key_id.0.as_bytes();
        aad.extend_from_slice(&(key_id_bytes.len() as u16).to_be_bytes());
        aad.extend_from_slice(key_id_bytes);

        aad
    }
}

/// Comprehensive, typed domain errors for the QuMail architecture.
#[derive(Debug, Error)]
pub enum QuMailError {
    #[error("invalid security level specified: '{0}'")]
    InvalidSecurityLevel(String),

    #[error("key manager error: {0}")]
    KeyManager(String),

    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    #[error("network or mail transport failure: {0}")]
    Network(String),

    #[error("invalid or malformed QuMail MIME envelope: {0}")]
    InvalidEnvelope(String),

    #[error("message authentication failed: tag mismatch or tampered payload")]
    AuthenticationFailed,

    #[error("key bank exhausted: requested {requested_bytes} bytes, only {available_bytes} bytes available")]
    KeyBankExhausted {
        requested_bytes: usize,
        available_bytes: usize,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_parsing() {
        assert_eq!("baseline".parse::<SecurityLevel>().unwrap(), SecurityLevel::Baseline);
        assert_eq!("qaes".parse::<SecurityLevel>().unwrap(), SecurityLevel::Qaes);
        assert_eq!("hybrid".parse::<SecurityLevel>().unwrap(), SecurityLevel::HybridPqc);
        assert_eq!("otp".parse::<SecurityLevel>().unwrap(), SecurityLevel::QuantumOtp);
        assert!("invalid".parse::<SecurityLevel>().is_err());
    }

    #[test]
    fn test_crypto_context_canonical_aad() {
        let ctx1 = CryptoContext {
            protocol_version: 1,
            message_id: MessageId("msg-1".into()),
            sender_sae: SaeId(10),
            recipient_sae: SaeId(20),
            key_id: KeyId("key-xyz".into()),
            timestamp_epoch_secs: 1700000000,
        };
        let ctx2 = ctx1.clone();
        assert_eq!(ctx1.to_aad_bytes(), ctx2.to_aad_bytes());

        let mut ctx3 = ctx1.clone();
        ctx3.recipient_sae = SaeId(21);
        assert_ne!(ctx1.to_aad_bytes(), ctx3.to_aad_bytes());
    }
}
