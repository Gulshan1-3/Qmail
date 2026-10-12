//! QuMail Multi-Tier Cryptographic Engine
//!
//! Implements:
//! - Level 1: Baseline (Standard email transport, passthrough payload)
//! - Level 2: Quantum-aided AES-256-GCM (Seed derived from QKD key via HKDF)
//! - Level 2.5: Hybrid Post-Quantum (NIST FIPS 203 ML-KEM-768 + QKD Dual-PRF Combiner)
//! - Level 3: Information-Theoretically Secure Vernam OTP with Carter-Wegman Poly1305 MAC

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate, KeyExport, TryKeyInit};
pub use ml_kem::{DecapsulationKey, EncapsulationKey, Kem, MlKem768};
pub use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::KeyInit as DsaKeyInit;
pub use ml_dsa::{MlDsa65, Signature, SigningKey, VerifyingKey};
use rand_core::{TryCryptoRng, TryRng};
use poly1305::universal_hash::UniversalHash;
use poly1305::Poly1305;
use qumail_core::{CryptoContext, KeyId, SecurityLevel};
use qumail_kme::KeyMaterial;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use rand::RngCore;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Adapter bridging rand::RngCore to rand_core 0.10 used by ml-kem
pub struct CryptoRngAdapter;

impl TryRng for CryptoRngAdapter {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        use rand::RngCore;
        Ok(rand::thread_rng().next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        use rand::RngCore;
        Ok(rand::thread_rng().next_u64())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(dst);
        Ok(())
    }
}

impl TryCryptoRng for CryptoRngAdapter {}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("insufficient key material: needed {needed} bytes, provided {provided} bytes")]
    InsufficientKeyMaterial { needed: usize, provided: usize },

    #[error("encryption failure: {0}")]
    EncryptionFailed(String),

    #[error("decryption failure: {0}")]
    DecryptionFailed(String),

    #[error("authentication tag verification failed: payload tampered or key mismatch")]
    AuthenticationFailed,

    #[error("post-quantum cryptography failure: {0}")]
    Pqc(String),

    #[error("digital signature failure: {0}")]
    Signature(String),

    #[error("unsupported or unexpected security level for operation: {0}")]
    UnsupportedSecurityLevel(String),
}

/// Encapsulated encrypted payload with associated cryptographic metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub level: SecurityLevel,
    pub ciphertext: Vec<u8>,
    pub tag: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub allocated_key_ids: Vec<KeyId>,
    /// Encapsulated post-quantum ciphertext (ML-KEM-768 ciphertext) for Level 2.5
    pub pqc_ciphertext: Option<Vec<u8>>,
}

/// Primary interface for multi-tier cryptographic operations.
pub trait CryptoProvider: Send + Sync {
    fn encrypt(
        &self,
        level: SecurityLevel,
        plaintext: &[u8],
        context: &CryptoContext,
        keys: &[KeyMaterial],
    ) -> Result<EncryptedMessage, CryptoError>;

    fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
        context: &CryptoContext,
        keys: &[KeyMaterial],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError>;
}

/// Bundle containing Base64-encoded ML-KEM-768 public and secret keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqcKeyPairBundle {
    pub public_key_b64: String,
    pub secret_key_b64: String,
}

/// Bundle containing Base64-encoded NIST FIPS 204 ML-DSA-65 public and secret keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DsaKeyPairBundle {
    pub public_key_b64: String,
    pub secret_key_b64: String,
}

impl DsaKeyPairBundle {
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(json.as_bytes())?;
            file.flush()?;
            Ok(())
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, json)
        }
    }

    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Production implementation of the QuMail Cryptographic Dispatcher.
#[derive(Default, Clone)]
pub struct QuMailCryptoEngine {
    /// Optional local ML-KEM private key for receiving Level 2.5 messages
    local_pqc_key: Option<Arc<DecapsulationKey<MlKem768>>>,
    /// Optional recipient ML-KEM public key for sending Level 2.5 messages
    recipient_pqc_key: Option<Arc<EncapsulationKey<MlKem768>>>,
    /// Optional local ML-DSA-65 signing key for signing outgoing messages
    local_dsa_key: Option<Arc<SigningKey<MlDsa65>>>,
    /// Optional peer ML-DSA-65 public key for verifying incoming messages
    peer_dsa_key: Option<Arc<VerifyingKey<MlDsa65>>>,
}

use std::sync::Arc;

impl QuMailCryptoEngine {
    pub fn new() -> Self {
        Self {
            local_pqc_key: None,
            recipient_pqc_key: None,
            local_dsa_key: None,
            peer_dsa_key: None,
        }
    }

    pub fn with_pqc_decapsulation_key(dk: DecapsulationKey<MlKem768>) -> Self {
        Self {
            local_pqc_key: Some(Arc::new(dk)),
            recipient_pqc_key: None,
            local_dsa_key: None,
            peer_dsa_key: None,
        }
    }

    pub fn with_recipient_pqc_key(ek: EncapsulationKey<MlKem768>) -> Self {
        Self {
            local_pqc_key: None,
            recipient_pqc_key: Some(Arc::new(ek)),
            local_dsa_key: None,
            peer_dsa_key: None,
        }
    }

    pub fn with_pqc_keys(
        dk: Option<DecapsulationKey<MlKem768>>,
        ek: Option<EncapsulationKey<MlKem768>>,
    ) -> Self {
        Self {
            local_pqc_key: dk.map(Arc::new),
            recipient_pqc_key: ek.map(Arc::new),
            local_dsa_key: None,
            peer_dsa_key: None,
        }
    }

    pub fn with_dsa_signing_key(sk: SigningKey<MlDsa65>) -> Self {
        Self {
            local_pqc_key: None,
            recipient_pqc_key: None,
            local_dsa_key: Some(Arc::new(sk)),
            peer_dsa_key: None,
        }
    }

    pub fn with_peer_dsa_key(vk: VerifyingKey<MlDsa65>) -> Self {
        Self {
            local_pqc_key: None,
            recipient_pqc_key: None,
            local_dsa_key: None,
            peer_dsa_key: Some(Arc::new(vk)),
        }
    }

    pub fn with_all_keys(
        dk: Option<DecapsulationKey<MlKem768>>,
        ek: Option<EncapsulationKey<MlKem768>>,
        sk: Option<SigningKey<MlDsa65>>,
        vk: Option<VerifyingKey<MlDsa65>>,
    ) -> Self {
        Self {
            local_pqc_key: dk.map(Arc::new),
            recipient_pqc_key: ek.map(Arc::new),
            local_dsa_key: sk.map(Arc::new),
            peer_dsa_key: vk.map(Arc::new),
        }
    }

    pub fn local_dsa_signing_key(&self) -> Option<&SigningKey<MlDsa65>> {
        self.local_dsa_key.as_deref()
    }

    pub fn peer_dsa_verifying_key(&self) -> Option<&VerifyingKey<MlDsa65>> {
        self.peer_dsa_key.as_deref()
    }

    /// Generates a fresh NIST FIPS 203 ML-KEM-768 keypair.
    pub fn generate_pqc_keypair() -> (DecapsulationKey<MlKem768>, EncapsulationKey<MlKem768>) {
        let mut adapter = CryptoRngAdapter;
        MlKem768::generate_keypair_from_rng(&mut adapter)
    }

    /// Exports an ML-KEM-768 keypair as Base64-encoded strings.
    pub fn export_pqc_keypair(
        dk: &DecapsulationKey<MlKem768>,
        ek: &EncapsulationKey<MlKem768>,
    ) -> PqcKeyPairBundle {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        PqcKeyPairBundle {
            public_key_b64: STANDARD.encode(ek.to_bytes()),
            secret_key_b64: STANDARD.encode(dk.to_bytes()),
        }
    }

    /// Parses an ML-KEM-768 encapsulation (public) key from bytes.
    pub fn parse_encapsulation_key(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, CryptoError> {
        TryKeyInit::new_from_slice(bytes)
            .map_err(|e| CryptoError::Pqc(format!("invalid encapsulation key: {e:?}")))
    }

    /// Parses an ML-KEM-768 decapsulation (secret) key from bytes.
    pub fn parse_decapsulation_key(bytes: &[u8]) -> Result<DecapsulationKey<MlKem768>, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::Pqc(format!(
                "invalid decapsulation key length: expected 64, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 64];
        seed.copy_from_slice(bytes);
        Ok(DecapsulationKey::<MlKem768>::from_seed(seed.into()))
    }

    /// Generates a fresh NIST FIPS 204 ML-DSA-65 keypair.
    pub fn generate_dsa_keypair() -> (SigningKey<MlDsa65>, VerifyingKey<MlDsa65>) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        let vk = sk.verifying_key().clone();
        seed.zeroize();
        (sk, vk)
    }

    /// Exports an ML-DSA-65 keypair as Base64-encoded strings.
    pub fn export_dsa_keypair(
        sk: &SigningKey<MlDsa65>,
        vk: &VerifyingKey<MlDsa65>,
    ) -> DsaKeyPairBundle {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        DsaKeyPairBundle {
            public_key_b64: STANDARD.encode(vk.encode()),
            secret_key_b64: STANDARD.encode(sk.as_seed().as_slice()),
        }
    }

    /// Parses an ML-DSA-65 verifying (public) key from bytes.
    pub fn parse_dsa_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<MlDsa65>, CryptoError> {
        DsaKeyInit::new_from_slice(bytes)
            .map_err(|e| CryptoError::Signature(format!("invalid ML-DSA verifying key: {e:?}")))
    }

    /// Parses an ML-DSA-65 signing (secret) key from 32-byte seed.
    pub fn parse_dsa_signing_key(bytes: &[u8]) -> Result<SigningKey<MlDsa65>, CryptoError> {
        if bytes.len() != 32 {
            return Err(CryptoError::Signature(format!(
                "invalid ML-DSA signing key seed length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let sk = SigningKey::<MlDsa65>::from_seed(&seed.into());
        seed.zeroize();
        Ok(sk)
    }

    /// Computes a detached ML-DSA-65 signature over arbitrary data.
    pub fn sign_detached(
        sk: &SigningKey<MlDsa65>,
        data: &[u8],
    ) -> Vec<u8> {
        let sig: Signature<MlDsa65> = sk.sign(data);
        sig.encode().to_vec()
    }

    /// Verifies a detached ML-DSA-65 signature over data against the verifying key.
    pub fn verify_detached(
        vk: &VerifyingKey<MlDsa65>,
        data: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CryptoError> {
        let sig = Signature::<MlDsa65>::try_from(sig_bytes)
            .map_err(|e| CryptoError::Signature(format!("invalid ML-DSA signature bytes: {e:?}")))?;
        vk.verify(data, &sig)
            .map_err(|e| CryptoError::Signature(format!("signature verification failed: {e:?}")))
    }

    /// Derives a 256-bit AES key and a 96-bit nonce from a QKD key and context using HKDF-SHA256.
    fn derive_aes_key_and_nonce(
        qkd_key: &[u8],
        context: &CryptoContext,
    ) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
        let salt = context.message_id.0.as_bytes();
        let hk = Hkdf::<Sha256>::new(Some(salt), qkd_key);
        let mut okm = [0u8; 44]; // 32 bytes for AES-256 key + 12 bytes for GCM nonce
        let info = b"QuMail-AES256GCM-v1";
        hk.expand(info, &mut okm)
            .expect("44 bytes is valid expansion length for SHA-256");

        let mut aes_key = [0u8; 32];
        let mut nonce = [0u8; 12];
        aes_key.copy_from_slice(&okm[..32]);
        nonce.copy_from_slice(&okm[32..44]);
        okm.zeroize();

        (Zeroizing::new(aes_key), nonce)
    }

    /// Dual-PRF Hybrid Combiner (NIST / BSI compliant):
    /// Combines QKD key material and Post-Quantum ML-KEM shared secret via HKDF.
    fn derive_hybrid_key_and_nonce(
        qkd_key: &[u8],
        pqc_shared_secret: &[u8],
        context: &CryptoContext,
    ) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
        let mut combined_ikm = Zeroizing::new(Vec::with_capacity(qkd_key.len() + pqc_shared_secret.len()));
        combined_ikm.extend_from_slice(qkd_key);
        combined_ikm.extend_from_slice(pqc_shared_secret);

        let salt = context.message_id.0.as_bytes();
        let hk = Hkdf::<Sha256>::new(Some(salt), &combined_ikm);
        let mut okm = [0u8; 44];
        let info = b"QuMail-Hybrid-PQC-QKD-v1";
        hk.expand(info, &mut okm)
            .expect("44 bytes is valid expansion length for SHA-256");

        let mut aes_key = [0u8; 32];
        let mut nonce = [0u8; 12];
        aes_key.copy_from_slice(&okm[..32]);
        nonce.copy_from_slice(&okm[32..44]);
        okm.zeroize();

        (Zeroizing::new(aes_key), nonce)
    }

    /// Concatenates key material bytes into a continuous zeroizing stream.
    fn flatten_keys(keys: &[KeyMaterial]) -> Zeroizing<Vec<u8>> {
        let total_len: usize = keys.iter().map(|k| k.bytes.len()).sum();
        let mut buf = Zeroizing::new(Vec::with_capacity(total_len));
        for k in keys {
            buf.extend_from_slice(&k.bytes);
        }
        buf
    }

    /// Computes a Carter-Wegman Poly1305 MAC over ciphertext and context AAD.
    fn compute_poly1305_mac(mac_key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> [u8; 16] {
        let mut mac = Poly1305::new(mac_key.into());
        // Domain separation & collision resistance
        mac.update_padded(b"QuMail-QuantumOTP-Poly1305-v1");
        mac.update_padded(&(aad.len() as u64).to_be_bytes());
        mac.update_padded(aad);
        mac.update_padded(&(ciphertext.len() as u64).to_be_bytes());
        mac.update_padded(ciphertext);
        mac.finalize().into()
    }
}

impl CryptoProvider for QuMailCryptoEngine {
    fn encrypt(
        &self,
        level: SecurityLevel,
        plaintext: &[u8],
        context: &CryptoContext,
        keys: &[KeyMaterial],
    ) -> Result<EncryptedMessage, CryptoError> {
        let key_ids: Vec<KeyId> = keys.iter().map(|k| k.key_id.clone()).collect();

        match level {
            // Level 1: Baseline (TLS/MIME transport level, plaintext payload)
            SecurityLevel::Baseline => Ok(EncryptedMessage {
                level: SecurityLevel::Baseline,
                ciphertext: plaintext.to_vec(),
                tag: None,
                nonce: None,
                allocated_key_ids: Vec::new(),
                pqc_ciphertext: None,
            }),

            // Level 2: Quantum-aided AES-256-GCM
            SecurityLevel::Qaes => {
                if keys.is_empty() || keys[0].bytes.len() < 32 {
                    return Err(CryptoError::InsufficientKeyMaterial {
                        needed: 32,
                        provided: keys.first().map(|k| k.bytes.len()).unwrap_or(0),
                    });
                }

                let (aes_key, _derived_nonce) =
                    Self::derive_aes_key_and_nonce(&keys[0].bytes, context);
                // Cryptographically secure random 96-bit nonce (prevents catastrophic nonce-reuse)
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);

                let cipher = Aes256Gcm::new_from_slice(&*aes_key)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let aad = context.to_aad_bytes();
                let payload = Payload {
                    msg: plaintext,
                    aad: &aad,
                };

                let ciphertext = cipher
                    .encrypt(nonce, payload)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

                Ok(EncryptedMessage {
                    level,
                    ciphertext,
                    tag: None, // AES-GCM appends 16-byte tag to the ciphertext
                    nonce: Some(nonce_bytes.to_vec()),
                    allocated_key_ids: vec![keys[0].key_id.clone()],
                    pqc_ciphertext: None,
                })
            }

            // Level 2.5: Hybrid Post-Quantum (ML-KEM-768 + QKD Dual Combiner)
            SecurityLevel::HybridPqc => {
                if keys.is_empty() || keys[0].bytes.len() < 32 {
                    return Err(CryptoError::InsufficientKeyMaterial {
                        needed: 32,
                        provided: keys.first().map(|k| k.bytes.len()).unwrap_or(0),
                    });
                }

                let mut adapter = CryptoRngAdapter;
                let (pqc_ct, pqc_ss) = if let Some(ek) = &self.recipient_pqc_key {
                    ek.encapsulate_with_rng(&mut adapter)
                } else if let Some(dk) = &self.local_pqc_key {
                    dk.encapsulation_key().encapsulate_with_rng(&mut adapter)
                } else {
                    let (_dk, ek) = MlKem768::generate_keypair_from_rng(&mut adapter);
                    ek.encapsulate_with_rng(&mut adapter)
                };

                let (combined_key, _derived_nonce) = Self::derive_hybrid_key_and_nonce(
                    &keys[0].bytes,
                    pqc_ss.as_slice(),
                    context,
                );

                // Cryptographically secure random 96-bit nonce (prevents catastrophic nonce-reuse)
                let mut nonce_bytes = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);

                let cipher = Aes256Gcm::new_from_slice(&*combined_key)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let mut aad = context.to_aad_bytes();
                aad.extend_from_slice(pqc_ct.as_slice());

                let payload = Payload {
                    msg: plaintext,
                    aad: &aad,
                };

                let ciphertext = cipher
                    .encrypt(nonce, payload)
                    .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

                Ok(EncryptedMessage {
                    level: SecurityLevel::HybridPqc,
                    ciphertext,
                    tag: None,
                    nonce: Some(nonce_bytes.to_vec()),
                    allocated_key_ids: vec![keys[0].key_id.clone()],
                    pqc_ciphertext: Some(pqc_ct.as_slice().to_vec()),
                })
            }

            // Level 3: Quantum Secure Vernam OTP + Carter-Wegman Poly1305 MAC
            SecurityLevel::QuantumOtp => {
                let stream = Self::flatten_keys(keys);
                let needed = plaintext.len() + 32; // Plaintext length + 32-byte MAC key
                if stream.len() < needed {
                    return Err(CryptoError::InsufficientKeyMaterial {
                        needed,
                        provided: stream.len(),
                    });
                }

                let otp_stream = &stream[..plaintext.len()];
                let mut mac_key = [0u8; 32];
                mac_key.copy_from_slice(&stream[plaintext.len()..plaintext.len() + 32]);

                // OTP Vernam XOR
                let mut ct = Vec::with_capacity(plaintext.len());
                for (p, k) in plaintext.iter().zip(otp_stream.iter()) {
                    ct.push(p ^ k);
                }

                // Carter-Wegman Poly1305 Authentication Tag
                let aad = context.to_aad_bytes();
                let tag = Self::compute_poly1305_mac(&mac_key, &ct, &aad);
                mac_key.zeroize();

                Ok(EncryptedMessage {
                    level: SecurityLevel::QuantumOtp,
                    ciphertext: ct,
                    tag: Some(tag.to_vec()),
                    nonce: None,
                    allocated_key_ids: key_ids,
                    pqc_ciphertext: None,
                })
            }
        }
    }

    fn decrypt(
        &self,
        encrypted: &EncryptedMessage,
        context: &CryptoContext,
        keys: &[KeyMaterial],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        match encrypted.level {
            SecurityLevel::Baseline => Ok(Zeroizing::new(encrypted.ciphertext.clone())),

            SecurityLevel::Qaes => {
                if keys.is_empty() || keys[0].bytes.len() < 32 {
                    return Err(CryptoError::InsufficientKeyMaterial {
                        needed: 32,
                        provided: keys.first().map(|k| k.bytes.len()).unwrap_or(0),
                    });
                }

                let (aes_key, derived_nonce) =
                    Self::derive_aes_key_and_nonce(&keys[0].bytes, context);
                let nonce_bytes = if let Some(ref n) = encrypted.nonce {
                    if n.len() != 12 {
                        return Err(CryptoError::DecryptionFailed("Invalid nonce length: expected 12 bytes".into()));
                    }
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(n);
                    arr
                } else {
                    derived_nonce
                };
                let cipher = Aes256Gcm::new_from_slice(&*aes_key)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let aad = context.to_aad_bytes();
                let payload = Payload {
                    msg: &encrypted.ciphertext,
                    aad: &aad,
                };

                let decrypted = cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;

                Ok(Zeroizing::new(decrypted))
            }

            SecurityLevel::HybridPqc => {
                if keys.is_empty() || keys[0].bytes.len() < 32 {
                    return Err(CryptoError::InsufficientKeyMaterial {
                        needed: 32,
                        provided: keys.first().map(|k| k.bytes.len()).unwrap_or(0),
                    });
                }

                let pqc_ct_bytes = encrypted
                    .pqc_ciphertext
                    .as_ref()
                    .ok_or_else(|| CryptoError::DecryptionFailed("Missing ML-KEM ciphertext".into()))?;

                let dk = self.local_pqc_key.as_ref().ok_or_else(|| {
                    CryptoError::DecryptionFailed("No local ML-KEM decapsulation key configured".into())
                })?;

                let pqc_ss = dk
                    .decapsulate_slice(pqc_ct_bytes)
                    .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid ML-KEM ciphertext: {e}")))?;

                let (combined_key, derived_nonce) = Self::derive_hybrid_key_and_nonce(
                    &keys[0].bytes,
                    pqc_ss.as_slice(),
                    context,
                );

                let nonce_bytes = if let Some(ref n) = encrypted.nonce {
                    if n.len() != 12 {
                        return Err(CryptoError::DecryptionFailed("Invalid nonce length: expected 12 bytes".into()));
                    }
                    let mut arr = [0u8; 12];
                    arr.copy_from_slice(n);
                    arr
                } else {
                    derived_nonce
                };

                let cipher = Aes256Gcm::new_from_slice(&*combined_key)
                    .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
                let nonce = Nonce::from_slice(&nonce_bytes);

                let mut aad = context.to_aad_bytes();
                aad.extend_from_slice(pqc_ct_bytes);

                let payload = Payload {
                    msg: &encrypted.ciphertext,
                    aad: &aad,
                };

                let decrypted = cipher
                    .decrypt(nonce, payload)
                    .map_err(|_| CryptoError::AuthenticationFailed)?;

                Ok(Zeroizing::new(decrypted))
            }

            SecurityLevel::QuantumOtp => {
                let tag_bytes = encrypted
                    .tag
                    .as_ref()
                    .ok_or(CryptoError::AuthenticationFailed)?;
                if tag_bytes.len() != 16 {
                    return Err(CryptoError::AuthenticationFailed);
                }

                let stream = Self::flatten_keys(keys);
                let needed = encrypted.ciphertext.len() + 32;
                if stream.len() < needed {
                    return Err(CryptoError::InsufficientKeyMaterial {
                        needed,
                        provided: stream.len(),
                    });
                }

                let otp_stream = &stream[..encrypted.ciphertext.len()];
                let mut mac_key = [0u8; 32];
                mac_key.copy_from_slice(
                    &stream[encrypted.ciphertext.len()..encrypted.ciphertext.len() + 32],
                );

                // Constant-time MAC verification
                let aad = context.to_aad_bytes();
                let expected_tag = Self::compute_poly1305_mac(&mac_key, &encrypted.ciphertext, &aad);
                mac_key.zeroize();

                if expected_tag.ct_eq(tag_bytes.as_slice()).unwrap_u8() != 1 {
                    return Err(CryptoError::AuthenticationFailed);
                }

                // Decrypt via XOR
                let mut pt = Vec::with_capacity(encrypted.ciphertext.len());
                for (c, k) in encrypted.ciphertext.iter().zip(otp_stream.iter()) {
                    pt.push(c ^ k);
                }

                Ok(Zeroizing::new(pt))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use qumail_core::{KeyId, MessageId, SaeId};
    use rand::RngCore;

    fn make_test_context() -> CryptoContext {
        CryptoContext {
            protocol_version: 1,
            message_id: MessageId("test-msg-1".into()),
            sender_sae: SaeId(1),
            recipient_sae: SaeId(2),
            key_id: KeyId("key-1".into()),
            timestamp_epoch_secs: 1700000000,
        }
    }

    #[test]
    fn test_level1_baseline_roundtrip() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let payload = b"Hello unencrypted standard email";
        let enc = engine
            .encrypt(SecurityLevel::Baseline, payload, &ctx, &[])
            .unwrap();
        let dec = engine.decrypt(&enc, &ctx, &[]).unwrap();
        assert_eq!(&dec[..], payload);
    }

    #[test]
    fn test_level2_qaes_roundtrip() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let mut key_bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = KeyMaterial::new(KeyId::new(), key_bytes);

        let payload = b"Classified ISRO Telemetry Data with Attachment Payload 1234567890";
        let enc = engine
            .encrypt(SecurityLevel::Qaes, payload, &ctx, &[key.clone()])
            .unwrap();
        let dec = engine.decrypt(&enc, &ctx, &[key]).unwrap();
        assert_eq!(&dec[..], payload);
    }

    #[test]
    fn test_level2_tamper_detection() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let mut key_bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = KeyMaterial::new(KeyId::new(), key_bytes);

        let payload = b"Confidential financial statement";
        let mut enc = engine
            .encrypt(SecurityLevel::Qaes, payload, &ctx, &[key.clone()])
            .unwrap();

        // Mutate single bit in ciphertext
        enc.ciphertext[0] ^= 0x01;
        assert!(matches!(
            engine.decrypt(&enc, &ctx, &[key]),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_level2_5_hybrid_pqc_roundtrip() {
        let (dk, ek) = QuMailCryptoEngine::generate_pqc_keypair();
        let engine = QuMailCryptoEngine::with_pqc_keys(Some(dk), Some(ek));

        let ctx = make_test_context();
        let mut qkd_key_bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut qkd_key_bytes);
        let qkd_key = KeyMaterial::new(KeyId::new(), qkd_key_bytes);

        let payload = b"Post-Quantum Encrypted Space Launch Trajectory";

        let enc_msg = engine
            .encrypt(SecurityLevel::HybridPqc, payload, &ctx, &[qkd_key.clone()])
            .unwrap();

        assert_eq!(enc_msg.level, SecurityLevel::HybridPqc);
        assert!(enc_msg.pqc_ciphertext.is_some());

        // Decrypt using QuMailCryptoEngine with configured decapsulation key
        let decrypted = engine.decrypt(&enc_msg, &ctx, &[qkd_key]).unwrap();
        assert_eq!(&decrypted[..], payload);
    }

    #[test]
    fn test_level3_otp_roundtrip() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let payload = b"Quantum Secure OTP Payload";
        let needed = payload.len() + 32;

        let mut key_bytes = vec![0u8; needed];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = KeyMaterial::new(KeyId::new(), key_bytes);

        let enc = engine
            .encrypt(SecurityLevel::QuantumOtp, payload, &ctx, &[key.clone()])
            .unwrap();
        let dec = engine.decrypt(&enc, &ctx, &[key]).unwrap();
        assert_eq!(&dec[..], payload);
    }

    #[test]
    fn test_level3_otp_tamper_rejected() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let payload = b"Transfer 1000 BTC to Alice";
        let needed = payload.len() + 32;

        let mut key_bytes = vec![0u8; needed];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = KeyMaterial::new(KeyId::new(), key_bytes);

        let mut enc = engine
            .encrypt(SecurityLevel::QuantumOtp, payload, &ctx, &[key.clone()])
            .unwrap();

        // Tamper with ciphertext (attempted bit flip attack)
        enc.ciphertext[2] ^= 0x01;
        assert!(matches!(
            engine.decrypt(&enc, &ctx, &[key]),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_pqc_keypair_export_and_parse() {
        let (dk, ek) = QuMailCryptoEngine::generate_pqc_keypair();
        let bundle = QuMailCryptoEngine::export_pqc_keypair(&dk, &ek);

        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let pk_bytes = STANDARD.decode(&bundle.public_key_b64).unwrap();
        let sk_bytes = STANDARD.decode(&bundle.secret_key_b64).unwrap();

        let parsed_ek = QuMailCryptoEngine::parse_encapsulation_key(&pk_bytes).unwrap();
        let parsed_dk = QuMailCryptoEngine::parse_decapsulation_key(&sk_bytes).unwrap();

        let mut adapter = CryptoRngAdapter;
        let (ct, ss_enc) = parsed_ek.encapsulate_with_rng(&mut adapter);
        let ss_dec = parsed_dk.decapsulate(&ct);

        assert_eq!(ss_enc.as_slice(), ss_dec.as_slice());
    }

    #[test]
    fn test_unique_random_nonces_per_encryption() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let mut key_bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = KeyMaterial::new(KeyId::new(), key_bytes);

        let enc1 = engine
            .encrypt(SecurityLevel::Qaes, b"msg1", &ctx, &[key.clone()])
            .unwrap();
        let enc2 = engine
            .encrypt(SecurityLevel::Qaes, b"msg2", &ctx, &[key.clone()])
            .unwrap();

        // Nonces must be unique (randomized) even with the exact same context & key
        assert_ne!(enc1.nonce, enc2.nonce);

        // Both must decrypt correctly using their respective transmitted nonces
        let dec1 = engine.decrypt(&enc1, &ctx, &[key.clone()]).unwrap();
        let dec2 = engine.decrypt(&enc2, &ctx, &[key]).unwrap();
        assert_eq!(&dec1[..], b"msg1");
        assert_eq!(&dec2[..], b"msg2");
    }

    #[test]
    fn test_tampered_nonce_rejected() {
        let engine = QuMailCryptoEngine::new();
        let ctx = make_test_context();
        let mut key_bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key_bytes);
        let key = KeyMaterial::new(KeyId::new(), key_bytes);

        let mut enc = engine
            .encrypt(SecurityLevel::Qaes, b"sensitive payload", &ctx, &[key.clone()])
            .unwrap();

        // Tamper with transmitted nonce
        if let Some(ref mut n) = enc.nonce {
            n[0] ^= 0x01;
        }

        // Must fail authentication
        assert!(matches!(
            engine.decrypt(&enc, &ctx, &[key]),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn test_dsa_keypair_export_and_parse() {
        let (sk, vk) = QuMailCryptoEngine::generate_dsa_keypair();
        let bundle = QuMailCryptoEngine::export_dsa_keypair(&sk, &vk);

        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;

        let pk_bytes = STANDARD.decode(&bundle.public_key_b64).unwrap();
        let sk_bytes = STANDARD.decode(&bundle.secret_key_b64).unwrap();

        let parsed_vk = QuMailCryptoEngine::parse_dsa_verifying_key(&pk_bytes).unwrap();
        let parsed_sk = QuMailCryptoEngine::parse_dsa_signing_key(&sk_bytes).unwrap();

        let data = b"ISRO Space Commission Mission Directive";
        let sig = QuMailCryptoEngine::sign_detached(&parsed_sk, data);
        assert!(QuMailCryptoEngine::verify_detached(&parsed_vk, data, &sig).is_ok());
    }

    #[test]
    fn test_dsa_tampered_signature_rejected() {
        let (sk, vk) = QuMailCryptoEngine::generate_dsa_keypair();
        let data = b"Orbital Burn Telemetry Parameters";
        let mut sig = QuMailCryptoEngine::sign_detached(&sk, data);

        // Tamper with signature bytes
        sig[10] ^= 0x55;
        assert!(QuMailCryptoEngine::verify_detached(&vk, data, &sig).is_err());
    }

    #[test]
    fn test_dsa_tampered_message_rejected() {
        let (sk, vk) = QuMailCryptoEngine::generate_dsa_keypair();
        let data = b"Transfer 10 QKD Keys to Node 2";
        let sig = QuMailCryptoEngine::sign_detached(&sk, data);

        let tampered_data = b"Transfer 10 QKD Keys to Node 9";
        assert!(QuMailCryptoEngine::verify_detached(&vk, tampered_data, &sig).is_err());
    }

    #[test]
    fn test_dsa_wrong_public_key_rejected() {
        let (sk1, _vk1) = QuMailCryptoEngine::generate_dsa_keypair();
        let (_sk2, vk2) = QuMailCryptoEngine::generate_dsa_keypair();

        let data = b"Authentic Message from Alice";
        let sig = QuMailCryptoEngine::sign_detached(&sk1, data);

        // Verification against Bob's public key must fail
        assert!(QuMailCryptoEngine::verify_detached(&vk2, data, &sig).is_err());
    }
}

