//! One-shot decrypt demo for the received QuMail hybrid-PQC email.
//! Run: cargo run --bin decrypt_demo

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use qumail_core::{CryptoContext, KeyId, MessageId, SaeId, SecurityLevel};
use qumail_crypto::{CryptoProvider, EncryptedMessage, PqcKeyPairBundle, QuMailCryptoEngine};
use qumail_kme::{KeyBankStore, KeyManager};
use qumail_net::QuMailEnvelopeHeader;
use std::fs;

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n🔐 QuMail Hybrid-PQC Decryption Demo");
    println!("══════════════════════════════════════\n");

    // ── 1. Load receiver key bank (Bob = SAE 2) ────────────────────────────
    println!("📂 Loading receiver ISRO key bank (SAE 2)...");
    let km = KeyBankStore::open_or_create(
        "/tmp/keybank_receiver.json",
        SaeId(2),
        SaeId(1),
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    // ── 2. Load ML-KEM-768 private key ────────────────────────────────────
    println!("🔑 Loading NIST FIPS 203 ML-KEM-768 private key...");
    let pqc_json = fs::read_to_string("/tmp/gulshan_pqc_keypair.json")?;
    let bundle: PqcKeyPairBundle = serde_json::from_str(&pqc_json)?;
    let dk_bytes = B64.decode(&bundle.secret_key_b64)?;
    let dk = QuMailCryptoEngine::parse_decapsulation_key(&dk_bytes)?;
    let crypto = QuMailCryptoEngine::with_pqc_decapsulation_key(dk);

    // ── 3. Parse the envelope header ──────────────────────────────────────
    println!("📋 Parsing QuMail envelope header...");
    let header_json = fs::read_to_string("/tmp/qumail_header.json")?;
    let header: QuMailEnvelopeHeader = serde_json::from_str(&header_json)?;

    println!("   Message ID  : {}", header.message_id);
    println!("   Security    : {:?}", header.security_level);
    println!("   SAE Link    : {} → {}", header.sender_sae, header.recipient_sae);
    println!("   Key ID      : {}", header.key_ids[0]);
    println!("   Nonce (b64) : {}", header.nonce_b64.as_deref().unwrap_or("none"));

    // ── 4. Recover QKD key from receiver's key bank ───────────────────────
    println!("\n🗝️  Recovering QKD key from receiver bank...");
    let key_id = KeyId(header.key_ids[0].clone());
    let keys = km.get_decryption_keys(SaeId(1), &[key_id.clone()])
        .await
        .map_err(|e| anyhow::anyhow!("Key bank error: {e}"))?;
    let qkd_key = keys.into_iter().next()
        .ok_or_else(|| anyhow::anyhow!("Key {} not found in receiver bank", key_id.0))?;
    println!("   ✓ QKD key recovered ({} bytes)", qkd_key.bytes.len());

    // ── 5. Assemble EncryptedMessage struct ───────────────────────────────
    println!("📦 Loading ciphertext payload...");
    let ct_b64 = fs::read_to_string("/tmp/qumail_payload.b64")?;
    let ciphertext = B64.decode(ct_b64.trim())?;
    println!("   ✓ Ciphertext: {} bytes", ciphertext.len());

    let nonce = header.nonce_b64.as_deref()
        .map(|s| B64.decode(s))
        .transpose()?;
    let pqc_ct = header.pqc_ciphertext_b64.as_deref()
        .map(|s| B64.decode(s))
        .transpose()?;

    let encrypted = EncryptedMessage {
        level: SecurityLevel::HybridPqc,
        ciphertext,
        tag: None,
        nonce,
        allocated_key_ids: vec![key_id.clone()],
        pqc_ciphertext: pqc_ct,
    };

    // ── 6. Crypto context (must match what sender used) ───────────────────
    let ctx = CryptoContext {
        protocol_version: 1,
        message_id: MessageId(header.message_id.clone()),
        sender_sae: SaeId(header.sender_sae),
        recipient_sae: SaeId(header.recipient_sae),
        key_id: key_id,
        timestamp_epoch_secs: header.timestamp_epoch_secs,
    };

    // ── 7. DECRYPT ────────────────────────────────────────────────────────
    println!("⚛️  Running Dual-PRF (K_QKD ‖ K_PQC) decombiner + AES-256-GCM decrypt...");
    let plaintext = crypto.decrypt(&encrypted, &ctx, &[qkd_key])
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    println!("\n╔══════════════════════════════════════════════════════════╗");
    println!("║  ✅  DECRYPTION SUCCESSFUL — QuMail Hybrid PQC (L2.5)  ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");
    println!("{}", String::from_utf8_lossy(&plaintext));
    println!("\n──────────────────────────────────────────────────────────");
    println!("🛡️  Decrypted using:");
    println!("    • ISRO QKD Key Bank (SAE 2, receiver side)");
    println!("    • NIST FIPS 203 ML-KEM-768 private decapsulation key");
    println!("    • Dual-PRF combiner: K = HKDF(K_QKD ‖ K_PQC)");
    println!("    • AES-256-GCM authenticated decryption");
    println!("──────────────────────────────────────────────────────────\n");

    Ok(())
}
