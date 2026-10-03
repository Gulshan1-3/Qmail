//! QuMail Key Management Entity (KME) & Key Bank Subsystem
//!
//! Conforms to ETSI GS QKD 014 REST specifications and provides an ISRO-compliant
//! 100 x 1 Kb symmetrical pre-distributed key bank as well as a synchronized simulator.

use async_trait::async_trait;
use base64::Engine;
use qumail_core::{KeyId, SaeId};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("KME network or HTTP failure: {0}")]
    Network(String),

    #[error("insufficient keys: requested {requested} keys, available {available}")]
    KeyExhaustion { requested: usize, available: usize },

    #[error("key slot '{0}' not found or already consumed")]
    KeyNotFound(String),

    #[error("reservation '{0}' expired or invalid")]
    InvalidReservation(String),

    #[error("IO error in key bank storage: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("mTLS client authentication error: {0}")]
    Tls(String),
}

/// Representation of a single raw key with automatic zeroization on drop.
#[derive(Clone, Debug)]
pub struct KeyMaterial {
    pub key_id: KeyId,
    pub bytes: Zeroizing<Vec<u8>>,
}

impl KeyMaterial {
    pub fn new(key_id: KeyId, bytes: Vec<u8>) -> Self {
        Self {
            key_id,
            bytes: Zeroizing::new(bytes),
        }
    }
}

/// Key inventory and availability status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInventoryStatus {
    pub source_kme_id: String,
    pub target_kme_id: String,
    pub master_sae_id: u64,
    pub slave_sae_id: u64,
    pub key_size_bits: usize,
    pub stored_key_count: usize,
    pub max_key_count: usize,
}

/// Request for reserving key material from a KeyManager.
#[derive(Clone, Debug)]
pub struct KeyRequest {
    pub peer_sae: SaeId,
    pub requested_bytes: usize,
    pub count: usize,
}

/// Handle representing an active reservation of key material.
#[derive(Clone, Debug)]
pub struct KeyReservation {
    pub reservation_id: String,
    pub keys: Vec<KeyMaterial>,
}

/// Primary abstraction for acquiring, committing, and recovering quantum keys.
#[async_trait]
pub trait KeyManager: Send + Sync {
    /// Reserves key material for an outbound encrypted message.
    async fn reserve(&self, req: KeyRequest) -> Result<KeyReservation, KeyError>;

    /// Commits a reservation, marking the keys permanently consumed and unavailable.
    async fn commit(&self, res: KeyReservation) -> Result<(), KeyError>;

    /// Releases a reservation back to the available pool if an operation aborted.
    async fn release(&self, res: KeyReservation) -> Result<(), KeyError>;

    /// Recovers previously exchanged symmetrical keys on the receiving end.
    async fn get_decryption_keys(
        &self,
        peer_sae: SaeId,
        key_ids: &[KeyId],
    ) -> Result<Vec<KeyMaterial>, KeyError>;

    /// Queries key inventory and health.
    async fn status(&self, peer_sae: SaeId) -> Result<KeyInventoryStatus, KeyError>;
}

// ============================================================================
// 1. ISRO Symmetrical 100 x 1 Kb Local Key Bank
// ============================================================================

pub const KEY_BANK_TOTAL_SLOTS: usize = 100;
pub const KEY_BANK_SLOT_SIZE_BYTES: usize = 1024; // 1 Kb (1024 bytes)

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyState {
    Available,
    Reserved,
    Consumed,
    Zeroized,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeyBankSlot {
    pub slot_id: u32,
    pub key_id: String,
    pub state: KeyState,
    pub reserved_at: Option<u64>,
    pub consumed_at: Option<u64>,
    pub key_b64: String,
}

#[derive(Serialize, Deserialize)]
struct KeyBankFile {
    pub owner_sae: u64,
    pub peer_sae: u64,
    pub slots: Vec<KeyBankSlot>,
}

/// Symmetrical persistent local Key Bank implementing the ISRO 100 x 1 Kb key bank specification.
pub struct KeyBankStore {
    path: PathBuf,
    owner_sae: SaeId,
    peer_sae: SaeId,
    state: Mutex<KeyBankFile>,
}

impl KeyBankStore {
    pub fn open_or_create(
        path: impl AsRef<Path>,
        owner_sae: SaeId,
        peer_sae: SaeId,
    ) -> Result<Self, KeyError> {
        Self::open_or_create_with_ttl(path, owner_sae, peer_sae, 60)
    }

    /// Creates or opens an existing key bank file with a specific reservation expiration TTL.
    pub fn open_or_create_with_ttl(
        path: impl AsRef<Path>,
        owner_sae: SaeId,
        peer_sae: SaeId,
        ttl_secs: u64,
    ) -> Result<Self, KeyError> {
        let p = path.as_ref().to_path_buf();
        if p.exists() && fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false) {
            let data = fs::read_to_string(&p)?;
            let mut kbf: KeyBankFile =
                serde_json::from_str(&data).map_err(|e| KeyError::Serialization(e.to_string()))?;

            // Crash consistency reconciliation:
            // Check if any slot was left in 'Reserved' state due to an unexpected process termination.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let mut reconciled = false;
            for slot in &mut kbf.slots {
                if slot.state == KeyState::Reserved {
                    if let Some(res_at) = slot.reserved_at {
                        if now.saturating_sub(res_at) >= ttl_secs {
                            // Abandoned reservation expired; safely return to available pool
                            slot.state = KeyState::Available;
                            slot.reserved_at = None;
                            reconciled = true;
                        }
                    } else {
                        slot.state = KeyState::Available;
                        reconciled = true;
                    }
                }
            }
            if reconciled {
                let serialized = serde_json::to_string_pretty(&kbf)
                    .map_err(|e| KeyError::Serialization(e.to_string()))?;
                fs::write(&p, serialized)?;
            }

            Ok(Self {
                path: p,
                owner_sae,
                peer_sae,
                state: Mutex::new(kbf),
            })
        } else {
            // Initialize 100 slots with cryptographically secure random bytes
            let mut slots = Vec::with_capacity(KEY_BANK_TOTAL_SLOTS);
            let mut rng = rand::thread_rng();
            for i in 0..KEY_BANK_TOTAL_SLOTS {
                let mut raw = vec![0u8; KEY_BANK_SLOT_SIZE_BYTES];
                rng.fill_bytes(&mut raw);
                let key_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
                slots.push(KeyBankSlot {
                    slot_id: i as u32,
                    key_id: uuid::Uuid::new_v4().to_string(),
                    state: KeyState::Available,
                    reserved_at: None,
                    consumed_at: None,
                    key_b64,
                });
            }
            let kbf = KeyBankFile {
                owner_sae: owner_sae.0,
                peer_sae: peer_sae.0,
                slots,
            };
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)?;
            }
            let serialized = serde_json::to_string_pretty(&kbf)
                .map_err(|e| KeyError::Serialization(e.to_string()))?;
            fs::write(&p, serialized)?;
            Ok(Self {
                path: p,
                owner_sae,
                peer_sae,
                state: Mutex::new(kbf),
            })
        }
    }

    /// Helper to generate a symmetrical pair of synchronized key banks for Alice and Bob.
    pub fn create_synchronized_pair(
        alice_path: impl AsRef<Path>,
        bob_path: impl AsRef<Path>,
        alice_sae: SaeId,
        bob_sae: SaeId,
    ) -> Result<(), KeyError> {
        let mut alice_slots = Vec::with_capacity(KEY_BANK_TOTAL_SLOTS);
        let mut bob_slots = Vec::with_capacity(KEY_BANK_TOTAL_SLOTS);
        let mut rng = rand::thread_rng();

        for i in 0..KEY_BANK_TOTAL_SLOTS {
            let mut raw = vec![0u8; KEY_BANK_SLOT_SIZE_BYTES];
            rng.fill_bytes(&mut raw);
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
            let key_id = uuid::Uuid::new_v4().to_string();

            alice_slots.push(KeyBankSlot {
                slot_id: i as u32,
                key_id: key_id.clone(),
                state: KeyState::Available,
                reserved_at: None,
                consumed_at: None,
                key_b64: key_b64.clone(),
            });

            bob_slots.push(KeyBankSlot {
                slot_id: i as u32,
                key_id,
                state: KeyState::Available,
                reserved_at: None,
                consumed_at: None,
                key_b64,
            });
        }

        let alice_file = KeyBankFile {
            owner_sae: alice_sae.0,
            peer_sae: bob_sae.0,
            slots: alice_slots,
        };
        let bob_file = KeyBankFile {
            owner_sae: bob_sae.0,
            peer_sae: alice_sae.0,
            slots: bob_slots,
        };

        if let Some(parent) = alice_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = bob_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(
            &alice_path,
            serde_json::to_string_pretty(&alice_file)
                .map_err(|e| KeyError::Serialization(e.to_string()))?,
        )?;
        fs::write(
            &bob_path,
            serde_json::to_string_pretty(&bob_file)
                .map_err(|e| KeyError::Serialization(e.to_string()))?,
        )?;

        Ok(())
    }

    fn persist(&self, kbf: &KeyBankFile) -> Result<(), KeyError> {
        let serialized = serde_json::to_string_pretty(kbf)
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        fs::write(&self.path, serialized)?;
        Ok(())
    }
}

#[async_trait]
impl KeyManager for KeyBankStore {
    async fn reserve(&self, req: KeyRequest) -> Result<KeyReservation, KeyError> {
        let mut guard = self.state.lock().unwrap();
        let needed = req.count.max(1);
        let mut reserved_slots = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for slot in guard.slots.iter_mut() {
            if slot.state == KeyState::Available {
                slot.state = KeyState::Reserved;
                slot.reserved_at = Some(now);
                reserved_slots.push(slot.clone());
                if reserved_slots.len() == needed {
                    break;
                }
            }
        }

        if reserved_slots.len() < needed {
            // Revert changes on exhaustion
            for r in &reserved_slots {
                if let Some(s) = guard.slots.get_mut(r.slot_id as usize) {
                    s.state = KeyState::Available;
                    s.reserved_at = None;
                }
            }
            return Err(KeyError::KeyExhaustion {
                requested: needed,
                available: reserved_slots.len(),
            });
        }

        self.persist(&guard)?;

        let mut keys = Vec::with_capacity(reserved_slots.len());
        for slot in reserved_slots {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&slot.key_b64)
                .map_err(|e| KeyError::Serialization(e.to_string()))?;
            keys.push(KeyMaterial::new(KeyId::from_string(slot.key_id), decoded));
        }

        Ok(KeyReservation {
            reservation_id: uuid::Uuid::new_v4().to_string(),
            keys,
        })
    }

    async fn commit(&self, res: KeyReservation) -> Result<(), KeyError> {
        let mut guard = self.state.lock().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for key in res.keys {
            if let Some(slot) = guard.slots.iter_mut().find(|s| s.key_id == key.key_id.0) {
                slot.state = KeyState::Consumed;
                slot.consumed_at = Some(now);
                // Zeroize sensitive slot bytes in storage
                let mut zero_vec = vec![0u8; KEY_BANK_SLOT_SIZE_BYTES];
                slot.key_b64 = base64::engine::general_purpose::STANDARD.encode(&zero_vec);
                zero_vec.zeroize();
                slot.state = KeyState::Zeroized;
            }
        }
        self.persist(&guard)
    }

    async fn release(&self, res: KeyReservation) -> Result<(), KeyError> {
        let mut guard = self.state.lock().unwrap();
        for key in res.keys {
            if let Some(slot) = guard.slots.iter_mut().find(|s| s.key_id == key.key_id.0) {
                if slot.state == KeyState::Reserved {
                    slot.state = KeyState::Available;
                    slot.reserved_at = None;
                }
            }
        }
        self.persist(&guard)
    }

    async fn get_decryption_keys(
        &self,
        _peer_sae: SaeId,
        key_ids: &[KeyId],
    ) -> Result<Vec<KeyMaterial>, KeyError> {
        let mut guard = self.state.lock().unwrap();
        let mut results = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for target_id in key_ids {
            let slot = guard
                .slots
                .iter_mut()
                .find(|s| s.key_id == target_id.0 && s.state == KeyState::Available)
                .ok_or_else(|| KeyError::KeyNotFound(target_id.0.clone()))?;

            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&slot.key_b64)
                .map_err(|e| KeyError::Serialization(e.to_string()))?;

            // Mark slot consumed & zeroized upon recovery
            slot.state = KeyState::Consumed;
            slot.consumed_at = Some(now);
            let mut zero_vec = vec![0u8; KEY_BANK_SLOT_SIZE_BYTES];
            slot.key_b64 = base64::engine::general_purpose::STANDARD.encode(&zero_vec);
            zero_vec.zeroize();
            slot.state = KeyState::Zeroized;

            results.push(KeyMaterial::new(target_id.clone(), decoded));
        }

        self.persist(&guard)?;
        Ok(results)
    }

    async fn status(&self, _peer_sae: SaeId) -> Result<KeyInventoryStatus, KeyError> {
        let guard = self.state.lock().unwrap();
        let available = guard
            .slots
            .iter()
            .filter(|s| s.state == KeyState::Available)
            .count();
        Ok(KeyInventoryStatus {
            source_kme_id: format!("local-sae-{}", self.owner_sae.0),
            target_kme_id: format!("local-sae-{}", self.peer_sae.0),
            master_sae_id: self.owner_sae.0,
            slave_sae_id: self.peer_sae.0,
            key_size_bits: KEY_BANK_SLOT_SIZE_BYTES * 8,
            stored_key_count: available,
            max_key_count: KEY_BANK_TOTAL_SLOTS,
        })
    }
}

// ============================================================================
// 2. ETSI GS QKD 014 REST Client
// ============================================================================

#[derive(Deserialize)]
struct EtsiStatusResponse {
    #[serde(default)]
    pub source_kme_id: Option<String>,
    #[serde(default)]
    pub target_kme_id: Option<String>,
    #[serde(default)]
    pub master_sae_id: Option<u64>,
    #[serde(default)]
    pub slave_sae_id: Option<u64>,
    #[serde(default)]
    pub key_size: Option<usize>,
    #[serde(default)]
    pub stored_key_count: Option<usize>,
    #[serde(default)]
    pub max_key_count: Option<usize>,
}

#[derive(Serialize)]
struct EtsiEncRequest {
    pub number: u32,
}

#[derive(Deserialize)]
struct EtsiKeyItem {
    #[serde(rename = "key_ID")]
    pub key_id: String,
    #[serde(rename = "key")]
    pub key_b64: String,
}

#[derive(Deserialize)]
struct EtsiKeysResponse {
    pub keys: Vec<EtsiKeyItem>,
}

#[derive(Serialize)]
struct EtsiDecKeyId {
    #[serde(rename = "key_ID")]
    pub key_id: String,
}

#[derive(Serialize)]
struct EtsiDecRequest {
    #[serde(rename = "key_IDs")]
    pub key_ids: Vec<EtsiDecKeyId>,
}

pub struct Etsi014Client {
    base_url: String,
    client: reqwest::Client,
    my_sae_id: SaeId,
}

impl Etsi014Client {
    pub fn new(
        base_url: impl Into<String>,
        my_sae_id: SaeId,
        identity_p12: Option<(&Path, &str)>,
        ca_pem: Option<&Path>,
    ) -> Result<Self, KeyError> {
        let mut builder = reqwest::Client::builder();

        if let Some(ca_path) = ca_pem {
            let ca_bytes = fs::read(ca_path)?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_bytes)
                .map_err(|e| KeyError::Tls(e.to_string()))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        if let Some((p12_path, pwd)) = identity_p12 {
            let p12_bytes = fs::read(p12_path)?;
            let identity = reqwest::Identity::from_pkcs12_der(&p12_bytes, pwd)
                .map_err(|e| KeyError::Tls(e.to_string()))?;
            builder = builder.identity(identity);
        }

        let client = builder.build().map_err(|e| KeyError::Tls(e.to_string()))?;

        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client,
            my_sae_id,
        })
    }

    /// Queries the total Shannon entropy of all stored QKD keys on the KME.
    pub async fn get_total_entropy(&self) -> Result<f64, KeyError> {
        let url = format!("{}/api/v1/keys/entropy/total", self.base_url);
        #[derive(Deserialize)]
        struct EntropyResp {
            total_entropy: f64,
        }
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KeyError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| KeyError::Network(e.to_string()))?;
        let parsed: EntropyResp = resp
            .json()
            .await
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        Ok(parsed.total_entropy)
    }

    /// Queries the registered SAE ID of the calling client certificate.
    pub async fn get_my_sae_info(&self) -> Result<u64, KeyError> {
        let url = format!("{}/api/v1/sae/info/me", self.base_url);
        #[derive(Deserialize)]
        struct SaeInfoResp {
            #[serde(rename = "SAE_ID")]
            sae_id: u64,
        }
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KeyError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| KeyError::Network(e.to_string()))?;
        let parsed: SaeInfoResp = resp
            .json()
            .await
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        Ok(parsed.sae_id)
    }
}

#[async_trait]
impl KeyManager for Etsi014Client {
    async fn reserve(&self, req: KeyRequest) -> Result<KeyReservation, KeyError> {
        let url = format!("{}/api/v1/keys/{}/enc_keys", self.base_url, req.peer_sae.0);
        let count = req.count.clamp(1, 10) as u32;
        let response = self
            .client
            .post(&url)
            .json(&EtsiEncRequest { number: count })
            .send()
            .await
            .map_err(|e| KeyError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| KeyError::Network(e.to_string()))?;

        let parsed: EtsiKeysResponse = response
            .json()
            .await
            .map_err(|e| KeyError::Serialization(e.to_string()))?;

        let mut keys = Vec::with_capacity(parsed.keys.len());
        for k in parsed.keys {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(k.key_b64)
                .map_err(|e| KeyError::Serialization(e.to_string()))?;
            keys.push(KeyMaterial::new(KeyId::from_string(k.key_id), decoded));
        }

        Ok(KeyReservation {
            reservation_id: uuid::Uuid::new_v4().to_string(),
            keys,
        })
    }

    async fn commit(&self, _res: KeyReservation) -> Result<(), KeyError> {
        // ETSI GS QKD 014 consumes keys on the server immediately when enc_keys is requested.
        Ok(())
    }

    async fn release(&self, _res: KeyReservation) -> Result<(), KeyError> {
        // ETSI GS QKD 014 is atomic on enc_keys call; no rollback endpoint exists in the standard.
        Ok(())
    }

    async fn get_decryption_keys(
        &self,
        peer_sae: SaeId,
        key_ids: &[KeyId],
    ) -> Result<Vec<KeyMaterial>, KeyError> {
        let url = format!("{}/api/v1/keys/{}/dec_keys", self.base_url, peer_sae.0);
        let req_body = EtsiDecRequest {
            key_ids: key_ids
                .iter()
                .map(|k| EtsiDecKeyId {
                    key_id: k.0.clone(),
                })
                .collect(),
        };

        let response = self
            .client
            .post(&url)
            .json(&req_body)
            .send()
            .await
            .map_err(|e| KeyError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| KeyError::Network(e.to_string()))?;

        let parsed: EtsiKeysResponse = response
            .json()
            .await
            .map_err(|e| KeyError::Serialization(e.to_string()))?;

        let mut keys = Vec::with_capacity(parsed.keys.len());
        for k in parsed.keys {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(k.key_b64)
                .map_err(|e| KeyError::Serialization(e.to_string()))?;
            keys.push(KeyMaterial::new(KeyId::from_string(k.key_id), decoded));
        }

        Ok(keys)
    }

    async fn status(&self, peer_sae: SaeId) -> Result<KeyInventoryStatus, KeyError> {
        let url = format!("{}/api/v1/keys/{}/status", self.base_url, peer_sae.0);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| KeyError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| KeyError::Network(e.to_string()))?;

        let parsed: EtsiStatusResponse = resp
            .json()
            .await
            .map_err(|e| KeyError::Serialization(e.to_string()))?;

        Ok(KeyInventoryStatus {
            source_kme_id: parsed.source_kme_id.unwrap_or_else(|| "kme-1".into()),
            target_kme_id: parsed.target_kme_id.unwrap_or_else(|| "kme-2".into()),
            master_sae_id: parsed.master_sae_id.unwrap_or(self.my_sae_id.0),
            slave_sae_id: parsed.slave_sae_id.unwrap_or(peer_sae.0),
            key_size_bits: parsed.key_size.unwrap_or(256),
            stored_key_count: parsed.stored_key_count.unwrap_or(0),
            max_key_count: parsed.max_key_count.unwrap_or(100),
        })
    }
}

// ============================================================================
// 3. Synchronized QKD Simulator
// ============================================================================

/// In-memory synchronized QKD Simulator for unit and integration testing.
///
/// Guaranteed to store keys generated during `reserve` and return matching bytes
/// when `get_decryption_keys` is queried with the corresponding key UUIDs.
#[derive(Clone, Default)]
pub struct QkdSimulator {
    storage: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl QkdSimulator {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeyManager for QkdSimulator {
    async fn reserve(&self, req: KeyRequest) -> Result<KeyReservation, KeyError> {
        let mut guard = self.storage.lock().unwrap();
        let count = req.count.max(1);
        let key_len = if req.requested_bytes > 0 {
            (req.requested_bytes / count).max(32)
        } else {
            32
        };

        let mut keys = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            let key_id = KeyId::new();
            let mut bytes = vec![0u8; key_len];
            rng.fill_bytes(&mut bytes);
            guard.insert(key_id.0.clone(), bytes.clone());
            keys.push(KeyMaterial::new(key_id, bytes));
        }

        Ok(KeyReservation {
            reservation_id: uuid::Uuid::new_v4().to_string(),
            keys,
        })
    }

    async fn commit(&self, _res: KeyReservation) -> Result<(), KeyError> {
        Ok(())
    }

    async fn release(&self, res: KeyReservation) -> Result<(), KeyError> {
        let mut guard = self.storage.lock().unwrap();
        for k in res.keys {
            guard.remove(&k.key_id.0);
        }
        Ok(())
    }

    async fn get_decryption_keys(
        &self,
        _peer_sae: SaeId,
        key_ids: &[KeyId],
    ) -> Result<Vec<KeyMaterial>, KeyError> {
        let guard = self.storage.lock().unwrap();
        let mut results = Vec::new();

        for kid in key_ids {
            let bytes = guard
                .get(&kid.0)
                .cloned()
                .ok_or_else(|| KeyError::KeyNotFound(kid.0.clone()))?;
            results.push(KeyMaterial::new(kid.clone(), bytes));
        }

        Ok(results)
    }

    async fn status(&self, peer_sae: SaeId) -> Result<KeyInventoryStatus, KeyError> {
        let guard = self.storage.lock().unwrap();
        Ok(KeyInventoryStatus {
            source_kme_id: "sim-kme-1".into(),
            target_kme_id: "sim-kme-2".into(),
            master_sae_id: 1,
            slave_sae_id: peer_sae.0,
            key_size_bits: 256,
            stored_key_count: guard.len() + 100,
            max_key_count: 1000,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_qkd_simulator_encryption_decryption_match() {
        let sim = QkdSimulator::new();
        let res = sim
            .reserve(KeyRequest {
                peer_sae: SaeId(2),
                requested_bytes: 64,
                count: 2,
            })
            .await
            .unwrap();

        assert_eq!(res.keys.len(), 2);
        let key_ids: Vec<KeyId> = res.keys.iter().map(|k| k.key_id.clone()).collect();

        let recovered = sim.get_decryption_keys(SaeId(2), &key_ids).await.unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(res.keys[0].bytes[..], recovered[0].bytes[..]);
        assert_eq!(res.keys[1].bytes[..], recovered[1].bytes[..]);
    }

    #[tokio::test]
    async fn test_synchronized_keybank_store() {
        let alice_file = NamedTempFile::new().unwrap();
        let bob_file = NamedTempFile::new().unwrap();

        KeyBankStore::create_synchronized_pair(
            alice_file.path(),
            bob_file.path(),
            SaeId(1),
            SaeId(2),
        )
        .unwrap();

        let alice_km =
            KeyBankStore::open_or_create(alice_file.path(), SaeId(1), SaeId(2)).unwrap();
        let bob_km = KeyBankStore::open_or_create(bob_file.path(), SaeId(2), SaeId(1)).unwrap();

        let res = alice_km
            .reserve(KeyRequest {
                peer_sae: SaeId(2),
                requested_bytes: 1024,
                count: 1,
            })
            .await
            .unwrap();

        assert_eq!(res.keys.len(), 1);
        let key_id = res.keys[0].key_id.clone();
        alice_km.commit(res).await.unwrap();

        let recovered = bob_km
            .get_decryption_keys(SaeId(1), &[key_id])
            .await
            .unwrap();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].bytes.len(), KEY_BANK_SLOT_SIZE_BYTES);

        // Key should now be consumed on Bob's end as well
        assert!(bob_km
            .get_decryption_keys(SaeId(1), &[recovered[0].key_id.clone()])
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_concurrent_key_bank_reservations() {
        let temp_file = NamedTempFile::new().unwrap();
        let km = Arc::new(
            KeyBankStore::open_or_create(temp_file.path(), SaeId(1), SaeId(2)).unwrap(),
        );

        // Spawn 20 concurrent tasks, each reserving 5 keys (20 * 5 = 100 slots total)
        let mut handles = Vec::new();
        for _ in 0..20 {
            let km_clone = Arc::clone(&km);
            handles.push(tokio::spawn(async move {
                km_clone
                    .reserve(KeyRequest {
                        peer_sae: SaeId(2),
                        requested_bytes: 5 * KEY_BANK_SLOT_SIZE_BYTES,
                        count: 5,
                    })
                    .await
            }));
        }

        let mut all_key_ids = std::collections::HashSet::new();
        for h in handles {
            let res = h.await.unwrap().expect("Reservation must succeed");
            assert_eq!(res.keys.len(), 5);
            for k in res.keys {
                assert!(
                    all_key_ids.insert(k.key_id.0),
                    "Duplicate key allocation detected in concurrent reservation!"
                );
            }
        }

        assert_eq!(all_key_ids.len(), 100);

        // Now key bank should be completely exhausted
        let fail_res = km
            .reserve(KeyRequest {
                peer_sae: SaeId(2),
                requested_bytes: 1024,
                count: 1,
            })
            .await;
        assert!(matches!(fail_res, Err(KeyError::KeyExhaustion { .. })));
    }

    #[tokio::test]
    async fn test_crash_recovery_reconciliation() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        // 1. Process 1 opens key bank, reserves keys, but crashes (drops without commit or release)
        {
            let km = KeyBankStore::open_or_create(&path, SaeId(1), SaeId(2)).unwrap();
            let res = km
                .reserve(KeyRequest {
                    peer_sae: SaeId(2),
                    requested_bytes: 1024,
                    count: 10,
                })
                .await
                .unwrap();
            assert_eq!(res.keys.len(), 10);
            let status = km.status(SaeId(2)).await.unwrap();
            assert_eq!(status.stored_key_count, 90);
            // Simulated crash: res is dropped without km.commit(res)
        }

        // 2. Re-open key bank after crash: reconciliation recovers the orphaned reservation
        let km_recovered =
            KeyBankStore::open_or_create_with_ttl(&path, SaeId(1), SaeId(2), 0).unwrap();
        let status = km_recovered.status(SaeId(2)).await.unwrap();
        assert_eq!(status.stored_key_count, 100);
    }

    #[tokio::test]
    async fn test_mock_etsi_server_integration() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok((mut socket, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 4096];
                        let n = socket.read(&mut buf).await.unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);

                        let (status, body) = if req.contains("GET /api/v1/keys/2/status") {
                            (
                                "200 OK",
                                r#"{"source_kme_id":"1","target_kme_id":"2","master_sae_id":1,"slave_sae_id":2,"key_size":256,"stored_key_count":50,"max_key_count":100}"#,
                            )
                        } else if req.contains("POST /api/v1/keys/2/enc_keys") {
                            (
                                "200 OK",
                                r#"{"keys":[{"key_ID":"test-uuid-1","key":"dGhpc19pc19zZWNyZXRfa2V5XzFfb2ZfMzJfYnl0ZXM="}]}"#,
                            )
                        } else if req.contains("POST /api/v1/keys/1/dec_keys") {
                            (
                                "200 OK",
                                r#"{"keys":[{"key_ID":"test-uuid-1","key":"dGhpc19pc19zZWNyZXRfa2V5XzFfb2ZfMzJfYnl0ZXM="}]}"#,
                            )
                        } else if req.contains("GET /api/v1/keys/entropy/total") {
                            (
                                "200 OK",
                                r#"{"total_entropy":7.985}"#,
                            )
                        } else if req.contains("GET /api/v1/sae/info/me") {
                            (
                                "200 OK",
                                r#"{"SAE_ID":1}"#,
                            )
                        } else {
                            ("404 Not Found", r#"{"error":"not found"}"#)
                        };

                        let response = format!(
                            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            status,
                            body.len(),
                            body
                        );
                        let _ = socket.write_all(response.as_bytes()).await;
                    });
                }
            }
        });

        let client = Etsi014Client::new(format!("http://{}", addr), SaeId(1), None, None).unwrap();

        // 1. Status query
        let st = client.status(SaeId(2)).await.unwrap();
        assert_eq!(st.stored_key_count, 50);
        assert_eq!(st.key_size_bits, 256);

        // 2. Encrypt keys
        let res = client
            .reserve(KeyRequest {
                peer_sae: SaeId(2),
                requested_bytes: 32,
                count: 1,
            })
            .await
            .unwrap();
        assert_eq!(res.keys.len(), 1);
        assert_eq!(res.keys[0].key_id.0, "test-uuid-1");

        // 3. Decrypt keys
        let dec_keys = client
            .get_decryption_keys(SaeId(1), &[KeyId::from_string("test-uuid-1")])
            .await
            .unwrap();
        assert_eq!(dec_keys.len(), 1);
        assert_eq!(dec_keys[0].bytes.len(), 32);

        // 4. Entropy telemetry
        let entropy = client.get_total_entropy().await.unwrap();
        assert!((entropy - 7.985).abs() < 0.001);

        // 5. SAE info
        let my_sae = client.get_my_sae_info().await.unwrap();
        assert_eq!(my_sae, 1);
    }
}
