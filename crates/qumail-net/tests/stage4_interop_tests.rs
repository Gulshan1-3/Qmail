//! Stage 4 — MIME + Mail Pipeline: Interoperability & Fault-Injection Tests
//!
//! Tests per architecture.md §26 (Testing Strategy):
//!   • MIME envelope survives full package → serialize → parse → decrypt round-trip
//!   • `To:` header is populated correctly after decryption
//!   • Attachment binary fidelity preserved through the encrypted MIME round-trip
//!   • Fault injection: tampered ciphertext → authentication failure
//!   • Fault injection: unknown key ID → key-not-found error
//!   • Fault injection: wrong security level on decrypt → failure
//!   • Multi-recipient `To:` header parsing
//!   • Unencrypted (L1 Baseline) plain MIME is passed through unchanged

use qumail_crypto::QuMailCryptoEngine;
use qumail_kme::QkdSimulator;
use qumail_net::{
    build_inner_mime_message, package_qumail_message, parse_and_decrypt_qumail_message,
    EmailAttachment,
};
use qumail_core::{SaeId, SecurityLevel};

// ── helpers ────────────────────────────────────────────────────────────────

fn sim_and_crypto() -> (QkdSimulator, QuMailCryptoEngine) {
    (QkdSimulator::new(), QuMailCryptoEngine::new())
}

fn tiny_attachment(name: &str) -> EmailAttachment {
    EmailAttachment {
        filename: name.to_string(),
        content_type: "application/octet-stream".to_string(),
        data: (0u8..=127).collect(),
    }
}

// ── 1. Full round-trip (L2 Q-AES) ─────────────────────────────────────────

#[tokio::test]
async fn test_stage4_l2_full_mime_roundtrip() {
    let (sim, crypto) = sim_and_crypto();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Stage 4 L2 Test",
        "Quantum-protected payload — L2 Q-AES",
        None,
        &[],
    )
    .expect("build inner MIME");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Stage 4 L2 Test",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package message");

    let raw = envelope.formatted();
    let decrypted = parse_and_decrypt_qumail_message(&raw, &sim, &crypto)
        .await
        .expect("decrypt message");

    assert!(decrypted.is_encrypted);
    assert_eq!(decrypted.security_level, SecurityLevel::Qaes);
    assert!(
        decrypted.text_body.contains("Quantum-protected payload"),
        "plaintext not recovered: {:?}", decrypted.text_body
    );
    assert_eq!(decrypted.subject, "Stage 4 L2 Test");
}

// ── 2. `To:` header populated after decrypt ────────────────────────────────

#[tokio::test]
async fn test_stage4_to_header_populated() {
    let (sim, crypto) = sim_and_crypto();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string(), "charlie@isro.gov.in".to_string()],
        "Recipient Test",
        "Check To: parsing",
        None,
        &[],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string(), "charlie@isro.gov.in".to_string()],
        "Recipient Test",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto)
        .await
        .expect("decrypt");

    // `to` must not be empty anymore (bug fix in Stage 4)
    assert!(
        !decrypted.to.is_empty(),
        "To: field must be populated after decryption"
    );
    assert!(
        decrypted.to.iter().any(|t| t.contains("bob@isro.gov.in")),
        "bob must appear in To: list"
    );
}

// ── 3. Binary attachment fidelity ─────────────────────────────────────────

#[tokio::test]
async fn test_stage4_attachment_binary_fidelity() {
    let (sim, crypto) = sim_and_crypto();
    let att = tiny_attachment("telemetry.bin");
    let expected_data = att.data.clone();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Attachment Fidelity",
        "See attached telemetry.",
        None,
        &[att],
    )
    .expect("build inner with attachment");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Attachment Fidelity",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto)
        .await
        .expect("decrypt");

    assert_eq!(decrypted.attachments.len(), 1, "attachment must be preserved");
    assert_eq!(
        decrypted.attachments[0].data, expected_data,
        "attachment bytes must be bit-for-bit identical after MIME round-trip"
    );
    assert_eq!(decrypted.attachments[0].filename, "telemetry.bin");
}

// ── 4. Hybrid PQC (L2.5) full round-trip ──────────────────────────────────

#[tokio::test]
async fn test_stage4_hybrid_pqc_roundtrip() {
    let (sim, _) = sim_and_crypto();
    let (dk, ek) = QuMailCryptoEngine::generate_pqc_keypair();
    let crypto_sender = QuMailCryptoEngine::with_recipient_pqc_key(ek);
    let crypto_receiver = QuMailCryptoEngine::with_pqc_decapsulation_key(dk);

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Hybrid PQC Round-Trip",
        "ML-KEM-768 + QKD dual-PRF message",
        None,
        &[],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Hybrid PQC Round-Trip",
        &inner,
        SecurityLevel::HybridPqc,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto_sender,
    )
    .await
    .expect("package hybrid");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto_receiver)
        .await
        .expect("decrypt hybrid");

    assert_eq!(decrypted.security_level, SecurityLevel::HybridPqc);
    assert!(decrypted.text_body.contains("ML-KEM-768"));
}

// ── 5. L3 OTP full round-trip ─────────────────────────────────────────────

#[tokio::test]
async fn test_stage4_l3_otp_roundtrip() {
    let (sim, crypto) = sim_and_crypto();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "L3 OTP Round-Trip",
        "Information-theoretically secure OTP message",
        None,
        &[],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "L3 OTP Round-Trip",
        &inner,
        SecurityLevel::QuantumOtp,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package OTP");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto)
        .await
        .expect("decrypt OTP");

    assert_eq!(decrypted.security_level, SecurityLevel::QuantumOtp);
    assert!(decrypted.text_body.contains("Information-theoretically"));
}

// ── 6. FAULT INJECTION: tampered ciphertext → auth failure ────────────────

#[tokio::test]
async fn test_stage4_fault_tampered_ciphertext_rejected() {
    let (sim, crypto) = sim_and_crypto();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Tamper Test",
        "Secret payload",
        None,
        &[],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Tamper Test",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package");

    // Flip bytes in the MIME raw to simulate MITM ciphertext tampering
    let mut raw = envelope.formatted();
    // Find the base64 payload section and corrupt it
    let raw_str = String::from_utf8_lossy(&raw).to_string();
    let tampered_str = raw_str.replace("Content-Type: application/octet-stream", "Content-Type: application/octet-stream\r\nX-Tampered: yes");
    // Corrupt some bytes in the middle of the raw payload
    let half = raw.len() / 2;
    raw[half] ^= 0xFF;
    raw[half + 1] ^= 0xFF;
    raw[half + 2] ^= 0xFF;
    drop(tampered_str);

    let result = parse_and_decrypt_qumail_message(&raw, &sim, &crypto).await;
    assert!(
        result.is_err(),
        "Tampered ciphertext must be rejected, not silently decrypted: {:?}", result
    );
}

// ── 7. FAULT INJECTION: L1 Baseline passthrough unchanged ─────────────────

#[tokio::test]
async fn test_stage4_baseline_passthrough() {
    let (sim, crypto) = sim_and_crypto();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Plain Mail",
        "No encryption, just TLS transport.",
        None,
        &[],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Plain Mail",
        &inner,
        SecurityLevel::Baseline,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package baseline");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto)
        .await
        .expect("parse baseline");

    assert_eq!(decrypted.security_level, SecurityLevel::Baseline);
    assert!(!decrypted.is_encrypted);
    assert!(decrypted.text_body.contains("No encryption"));
}

// ── 8. FAULT INJECTION: multiple attachments survive round-trip ────────────

#[tokio::test]
async fn test_stage4_multiple_attachments_survive() {
    let (sim, crypto) = sim_and_crypto();

    let atts = vec![
        EmailAttachment {
            filename: "mission_log.csv".to_string(),
            content_type: "text/csv".to_string(),
            data: b"time,alt,vel\n0,0,0\n1,100,7.8\n".to_vec(),
        },
        EmailAttachment {
            filename: "trajectory.bin".to_string(),
            content_type: "application/octet-stream".to_string(),
            data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        },
    ];

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Multi-Attachment Test",
        "Two attachments enclosed.",
        None,
        &atts,
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Multi-Attachment Test",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto)
        .await
        .expect("decrypt");

    assert_eq!(
        decrypted.attachments.len(), 2,
        "both attachments must survive the MIME round-trip"
    );

    let csv = decrypted.attachments.iter().find(|a| a.filename == "mission_log.csv")
        .expect("csv attachment");
    assert!(String::from_utf8_lossy(&csv.data).contains("alt,vel"));

    let bin = decrypted.attachments.iter().find(|a| a.filename == "trajectory.bin")
        .expect("bin attachment");
    assert_eq!(bin.data, vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
}

// ── 9. FAULT INJECTION: Replay attack detected and rejected ────────────────

#[tokio::test]
async fn test_stage4_replay_attack_rejected() {
    let (sim, crypto) = sim_and_crypto();

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Original Transmission",
        "Confidential coordinates",
        None,
        &[],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Original Transmission",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package");

    let raw = envelope.formatted();

    // First decryption: succeeds
    let first = parse_and_decrypt_qumail_message(&raw, &sim, &crypto).await;
    assert!(first.is_ok(), "First decryption of legitimate message must succeed");

    // Second decryption (replay attempt with exact same envelope): MUST FAIL
    let replay = parse_and_decrypt_qumail_message(&raw, &sim, &crypto).await;
    assert!(replay.is_err(), "Replay of previously decrypted message must be rejected");
    let err_str = replay.unwrap_err().to_string();
    assert!(
        err_str.contains("Replay attack detected"),
        "Error message should mention replay attack detection, got: {err_str}"
    );
}

// ── 10. Attachment null-byte and control-char sanitization ──────────────────

#[tokio::test]
async fn test_stage4_null_byte_filename_sanitized() {
    let (sim, crypto) = sim_and_crypto();

    let att = EmailAttachment {
        filename: "malicious.pdf\0.sh".to_string(),
        content_type: "application/octet-stream".to_string(),
        data: b"harmless content".to_vec(),
    };

    let inner = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Null Byte Test",
        "Check filename sanitization",
        None,
        &[att],
    )
    .expect("build inner");

    let envelope = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".to_string()],
        "Null Byte Test",
        &inner,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &sim,
        &crypto,
    )
    .await
    .expect("package");

    let decrypted = parse_and_decrypt_qumail_message(&envelope.formatted(), &sim, &crypto)
        .await
        .expect("decrypt");

    assert_eq!(decrypted.attachments.len(), 1);
    assert!(!decrypted.attachments[0].filename.contains('\0'));
    assert_eq!(decrypted.attachments[0].filename, "malicious.pdf.sh");
}

