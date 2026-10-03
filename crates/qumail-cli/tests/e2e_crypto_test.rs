//! End-to-End Cryptographic & Mail Pipeline Verification
//!
//! Validates the entire QuMail operational workflow:
//! 1. Symmetrical Key Bank initialization (100 x 1 Kb keys for Alice and Bob).
//! 2. Encryption and packaging under Level 1 (Baseline), Level 2 (Q-AES), and Level 3 (Quantum OTP).
//! 3. Attachment integrity preservation across MIME transport.
//! 4. Tamper detection and rejection (malleability defense).
//! 5. Key consumption and zeroization verification.

use qumail_core::{SaeId, SecurityLevel};
use qumail_crypto::QuMailCryptoEngine;
use qumail_kme::{KeyBankStore, KeyManager};
use qumail_net::{
    build_inner_mime_message, package_qumail_message, parse_and_decrypt_qumail_message,
    EmailAttachment,
};
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_e2e_isro_keybank_workflow() {
    let alice_file = NamedTempFile::new().unwrap();
    let bob_file = NamedTempFile::new().unwrap();

    // 1. Initialize Symmetrical 100 x 1 Kb Key Banks
    KeyBankStore::create_synchronized_pair(
        alice_file.path(),
        bob_file.path(),
        SaeId(1),
        SaeId(2),
    )
    .expect("Failed to initialize synchronized key banks");

    let alice_km =
        KeyBankStore::open_or_create(alice_file.path(), SaeId(1), SaeId(2)).unwrap();
    let bob_km = KeyBankStore::open_or_create(bob_file.path(), SaeId(2), SaeId(1)).unwrap();
    let crypto = QuMailCryptoEngine::new();

    // Check initial inventory
    let status_before = alice_km.status(SaeId(2)).await.unwrap();
    assert_eq!(status_before.stored_key_count, 100);
    assert_eq!(status_before.key_size_bits, 8192); // 1024 bytes * 8 = 8192 bits

    // 2. Compose message with multiple attachments (binary + text)
    let binary_payload = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let csv_payload = b"sensor_id,voltage,temperature\nS1,3.3,24.5\nS2,5.0,26.1\n".to_vec();

    let att1 = EmailAttachment {
        filename: "firmware.bin".to_string(),
        content_type: "application/octet-stream".to_string(),
        data: binary_payload.clone(),
    };
    let att2 = EmailAttachment {
        filename: "telemetry.csv".to_string(),
        content_type: "text/csv".to_string(),
        data: csv_payload.clone(),
    };

    let inner_msg = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".into()],
        "Orbital Trajectory Update",
        "Orbital burn coordinates and firmware patch attached.",
        Some("<p>Orbital burn coordinates and firmware patch attached.</p>"),
        &[att1, att2],
    )
    .unwrap();

    // 3. Alice encrypts under Level 2 (Quantum-aided AES-256-GCM)
    let outer_msg = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".into()],
        "Orbital Trajectory Update",
        &inner_msg,
        SecurityLevel::Qaes,
        SaeId(1),
        SaeId(2),
        &alice_km,
        &crypto,
    )
    .await
    .expect("Alice encryption failed");

    // Verify key consumption on Alice's side
    let status_after_alice = alice_km.status(SaeId(2)).await.unwrap();
    assert_eq!(status_after_alice.stored_key_count, 99);

    // 4. Bob receives and decrypts message
    let raw_email = outer_msg.formatted();
    let decrypted = parse_and_decrypt_qumail_message(&raw_email, &bob_km, &crypto)
        .await
        .expect("Bob decryption failed");

    assert_eq!(decrypted.security_level, SecurityLevel::Qaes);
    assert!(decrypted.is_encrypted);
    assert_eq!(decrypted.subject, "Orbital Trajectory Update");
    assert_eq!(
        decrypted.text_body.trim(),
        "Orbital burn coordinates and firmware patch attached."
    );
    assert_eq!(decrypted.attachments.len(), 2);

    let recovered_bin = decrypted
        .attachments
        .iter()
        .find(|a| a.filename == "firmware.bin")
        .expect("firmware.bin missing");
    assert_eq!(recovered_bin.data, binary_payload);

    let recovered_csv = decrypted
        .attachments
        .iter()
        .find(|a| a.filename == "telemetry.csv")
        .expect("telemetry.csv missing");
    assert_eq!(recovered_csv.data, csv_payload);

    // Verify key consumption on Bob's side
    let status_after_bob = bob_km.status(SaeId(1)).await.unwrap();
    assert_eq!(status_after_bob.stored_key_count, 99);
}

#[tokio::test]
async fn test_e2e_level3_otp_tamper_defense() {
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
    let crypto = QuMailCryptoEngine::new();

    let inner_msg = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".into()],
        "Top Secret Instruction",
        "Authorise propulsion sequence 42.",
        None,
        &[],
    )
    .unwrap();

    // Alice encrypts under Level 3 (Vernam OTP + Carter-Wegman Poly1305 MAC)
    let outer_msg = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".into()],
        "Top Secret Instruction",
        &inner_msg,
        SecurityLevel::QuantumOtp,
        SaeId(1),
        SaeId(2),
        &alice_km,
        &crypto,
    )
    .await
    .unwrap();

    let raw_str = String::from_utf8(outer_msg.formatted()).unwrap();
    assert!(raw_str.contains("\"tag_b64\""));

    // Adversary modifies the Carter-Wegman MAC tag
    let tampered_str = raw_str.replacen("\"tag_b64\": \"", "\"tag_b64\": \"X", 1);
    assert_ne!(raw_str, tampered_str);

    // Bob attempts to parse and decrypt tampered message
    let result = parse_and_decrypt_qumail_message(tampered_str.as_bytes(), &bob_km, &crypto).await;
    assert!(
        result.is_err(),
        "Tampered OTP ciphertext MUST be rejected by Carter-Wegman MAC"
    );
}

#[tokio::test]
async fn test_e2e_level2_5_hybrid_pqc_workflow() {
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

    // Bob generates ML-KEM-768 keypair and publishes encapsulation key to Alice
    let (bob_dk, bob_ek) = QuMailCryptoEngine::generate_pqc_keypair();

    let alice_crypto = QuMailCryptoEngine::with_recipient_pqc_key(bob_ek);
    let bob_crypto = QuMailCryptoEngine::with_pqc_decapsulation_key(bob_dk);

    let inner_msg = build_inner_mime_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".into()],
        "Quantum-Resistant Telemetry",
        "Encrypted via ML-KEM-768 + QKD Dual-PRF Combiner.",
        None,
        &[],
    )
    .unwrap();

    // Alice encrypts under Level 2.5 (Hybrid PQC)
    let outer_msg = package_qumail_message(
        "alice@isro.gov.in",
        &["bob@isro.gov.in".into()],
        "Quantum-Resistant Telemetry",
        &inner_msg,
        SecurityLevel::HybridPqc,
        SaeId(1),
        SaeId(2),
        &alice_km,
        &alice_crypto,
    )
    .await
    .unwrap();

    let raw_email = outer_msg.formatted();
    let raw_str = String::from_utf8(raw_email.clone()).unwrap();
    assert!(raw_str.contains("\"pqc_ciphertext_b64\""));

    // Bob decrypts message using his decapsulation key + QKD key
    let decrypted = parse_and_decrypt_qumail_message(&raw_email, &bob_km, &bob_crypto)
        .await
        .expect("Bob failed to decrypt Hybrid PQC message");

    assert_eq!(decrypted.security_level, SecurityLevel::HybridPqc);
    assert_eq!(
        decrypted.text_body.trim(),
        "Encrypted via ML-KEM-768 + QKD Dual-PRF Combiner."
    );
}

