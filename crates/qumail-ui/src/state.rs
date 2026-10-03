//! QuMail UI Application State
//!
//! Manages active folders, selected emails, compose drafts, search queries,
//! security level filters, and key manager connections.

#![allow(dead_code)]

use crate::model::{KeyBankStatus, MailFolder, UiAttachment, UiEmail, UiVerificationInfo};
use qumail_core::SecurityLevel;
use qumail_net::QuMailEnvelopeHeader;
use std::path::PathBuf;
use std::sync::mpsc;

/// Result message sent from the background IMAP-sync thread back to the UI frame loop.
#[derive(Debug)]
pub enum SyncResult {
    /// IMAP sync succeeded; carries a human-readable summary.
    Success(String),
    /// IMAP sync failed; carries the error description.
    Failure(String),
    /// SMTP send succeeded; carries the subject line.
    SmtpSuccess(String),
    /// SMTP send failed.
    SmtpFailure(String),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ActiveModal {
    None,
    Compose,
    Settings,
    EnvelopeInspector,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SecurityFilter {
    All,
    Baseline,
    Qaes,
    HybridPqc,
    QuantumOtp,
}

impl SecurityFilter {
    pub fn matches(&self, level: SecurityLevel) -> bool {
        match self {
            Self::All => true,
            Self::Baseline => level == SecurityLevel::Baseline,
            Self::Qaes => level == SecurityLevel::Qaes,
            Self::HybridPqc => level == SecurityLevel::HybridPqc,
            Self::QuantumOtp => level == SecurityLevel::QuantumOtp,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::All => "All Levels",
            Self::Baseline => "L1 Baseline",
            Self::Qaes => "L2 Q-AES",
            Self::HybridPqc => "L2.5 Hybrid",
            Self::QuantumOtp => "L3 OTP",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ComposeDraft {
    pub to: String,
    pub subject: String,
    pub body: String,
    pub security_level: SecurityLevel,
    pub attachments: Vec<UiAttachment>,
    pub status_message: Option<(String, bool)>, // (text, is_error)
    pub is_sending: bool,
}

impl Default for ComposeDraft {
    fn default() -> Self {
        Self {
            to: "director.sac@isro.gov.in".to_string(),
            subject: "".to_string(),
            body: "".to_string(),
            security_level: SecurityLevel::Qaes,
            attachments: Vec::new(),
            status_message: None,
            is_sending: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SettingsConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_user: String,
    pub imap_pass: String,
    pub key_bank_path: PathBuf,
    pub km_url: String,
    pub sender_sae: u64,
    pub recipient_sae: u64,
    pub pqc_public_key_b64: String,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            smtp_host: "smtp.gmail.com".to_string(),
            smtp_port: 587,
            smtp_user: "officer.sac@isro.gov.in".to_string(),
            smtp_pass: "••••••••••••".to_string(),
            imap_host: "imap.gmail.com".to_string(),
            imap_port: 993,
            imap_user: "officer.sac@isro.gov.in".to_string(),
            imap_pass: "••••••••••••".to_string(),
            key_bank_path: PathBuf::from("keybank_alice.json"),
            km_url: "https://kme.sac.isro.gov.in:8443".to_string(),
            sender_sae: 1,
            recipient_sae: 2,
            pqc_public_key_b64: "5nMALNJ4udJ6KXlcBqnI7jsSUFRuEkZLBEJGdnFby4ic...".to_string(),
        }
    }
}

pub struct AppState {
    pub active_folder: MailFolder,
    pub active_modal: ActiveModal,
    pub selected_email_id: Option<String>,
    pub search_query: String,
    pub security_filter: SecurityFilter,
    pub emails: Vec<UiEmail>,
    pub key_bank_status: KeyBankStatus,
    pub compose_draft: ComposeDraft,
    pub settings: SettingsConfig,
    pub notification_toast: Option<(String, bool)>, // (message, is_error)

    /// Receiver end of the background-thread → UI channel.
    /// Background IMAP sync and SMTP tasks post `SyncResult` here.
    pub sync_rx: mpsc::Receiver<SyncResult>,
    /// Sender clone kept so navigation / compose can spawn new background tasks.
    pub sync_tx: mpsc::Sender<SyncResult>,
    /// True while an IMAP sync is in-flight.
    pub is_syncing: bool,
    /// True while an SMTP send is in-flight.
    pub is_sending_smtp: bool,
}

impl AppState {
    pub fn new() -> Self {
        let emails = Self::seed_initial_emails();
        let selected_email_id = emails.first().map(|e| e.id.clone());
        let (sync_tx, sync_rx) = mpsc::channel::<SyncResult>();

        Self {
            active_folder: MailFolder::Inbox,
            active_modal: ActiveModal::None,
            selected_email_id,
            search_query: String::new(),
            security_filter: SecurityFilter::All,
            emails,
            key_bank_status: KeyBankStatus::default(),
            compose_draft: ComposeDraft::default(),
            settings: SettingsConfig::default(),
            notification_toast: None,
            sync_rx,
            sync_tx,
            is_syncing: false,
            is_sending_smtp: false,
        }
    }

    /// Drain pending background results and update UI state.
    /// Call once per egui frame in `app.rs::update()`.
    pub fn poll_sync_results(&mut self) {
        while let Ok(result) = self.sync_rx.try_recv() {
            match result {
                SyncResult::Success(msg) => {
                    self.is_syncing = false;
                    self.notification_toast = Some((msg, false));
                }
                SyncResult::Failure(msg) => {
                    self.is_syncing = false;
                    self.notification_toast = Some((
                        format!("IMAP sync failed: {}", msg),
                        true,
                    ));
                }
                SyncResult::SmtpSuccess(subject) => {
                    self.is_sending_smtp = false;
                    self.notification_toast = Some((
                        format!("✓ Email \"{}\" dispatched via SMTP.", subject),
                        false,
                    ));
                }
                SyncResult::SmtpFailure(msg) => {
                    self.is_sending_smtp = false;
                    self.notification_toast =
                        Some((format!("SMTP error: {}", msg), true));
                }
            }
        }
    }

    /// Returns emails filtered by current folder, search query, and security level
    pub fn filtered_emails(&self) -> Vec<&UiEmail> {
        self.emails
            .iter()
            .filter(|e| e.folder == self.active_folder)
            .filter(|e| self.security_filter.matches(e.security_level))
            .filter(|e| {
                if self.search_query.trim().is_empty() {
                    true
                } else {
                    let q = self.search_query.to_lowercase();
                    e.subject.to_lowercase().contains(&q)
                        || e.from.to_lowercase().contains(&q)
                        || e.snippet.to_lowercase().contains(&q)
                }
            })
            .collect()
    }

    pub fn selected_email(&self) -> Option<&UiEmail> {
        self.selected_email_id
            .as_ref()
            .and_then(|id| self.emails.iter().find(|e| &e.id == id))
    }

    pub fn unread_count(&self, folder: MailFolder) -> usize {
        self.emails
            .iter()
            .filter(|e| e.folder == folder && e.is_unread)
            .count()
    }

    /// Calculate required key slots for a message size in bytes under a given level
    pub fn calculate_key_requirement(level: SecurityLevel, payload_bytes: usize) -> (usize, &'static str) {
        match level {
            SecurityLevel::Baseline => (0, "0 keys (Standard TLS)"),
            SecurityLevel::Qaes => (1, "1 slot (32-byte seed derived via HKDF-SHA256)"),
            SecurityLevel::HybridPqc => (1, "1 slot (ML-KEM-768 ciphertext + 32-byte QKD Dual-PRF)"),
            SecurityLevel::QuantumOtp => {
                let needed_bytes = payload_bytes + 32; // OTP XOR + Carter-Wegman MAC key
                let slots = (needed_bytes + 1023) / 1024;
                (slots, "Information-Theoretic Vernam OTP + Carter-Wegman Poly1305 MAC")
            }
        }
    }

    /// Realistic initial ISRO aerospace email dataset showcasing all 4 security levels
    fn seed_initial_emails() -> Vec<UiEmail> {
        vec![
            UiEmail {
                id: "msg-101".to_string(),
                folder: MailFolder::Inbox,
                from: "dr.somnath@isro.gov.in".to_string(),
                to: vec!["officer.sac@isro.gov.in".to_string()],
                date: "Today, 14:42 IST".to_string(),
                subject: "[URGENT] GSLV-MkIII Trajectory Vector Correction".to_string(),
                snippet: "Attached orbital vector matrices verified via QKD station at Mount Abu...".to_string(),
                body_text: "Mission Directors,\n\nPlease find attached the revised third-stage cryogenic injection vector matrices for the upcoming launch.\n\nAll azimuth values have been calculated against real-time ionospheric telemetry. Verification was performed across the dedicated SAC Ahmedabad to Mount Abu QKD optical ground link.\n\nExecute payload verification immediately prior to final LOX pressurization.\n\nRegards,\nDr. S. Somnath\nChairman, ISRO".to_string(),
                attachments: vec![
                    UiAttachment {
                        filename: "cryo_stage3_vectors.bin".to_string(),
                        content_type: "application/octet-stream".to_string(),
                        size_bytes: 4096,
                        data: vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04],
                    },
                    UiAttachment {
                        filename: "sensor_telemetry.csv".to_string(),
                        content_type: "text/csv".to_string(),
                        size_bytes: 1420,
                        data: b"timestamp,stage,pressure_bar,temp_kelvin\n0.00,C25,34.2,289.1\n".to_vec(),
                    },
                ],
                security_level: SecurityLevel::QuantumOtp,
                is_unread: true,
                verification: Some(UiVerificationInfo {
                    verified: true,
                    level: SecurityLevel::QuantumOtp,
                    method_title: "Information-Theoretic Vernam OTP + Poly1305 MAC".to_string(),
                    method_detail: "Key stream derived from 5 contiguous 1024-byte symmetric QKD blocks with Carter-Wegman MAC. Provably tamper-evident.".to_string(),
                    key_ids: vec![
                        "isro-qkd-key-0042".to_string(),
                        "isro-qkd-key-0043".to_string(),
                        "isro-qkd-key-0044".to_string(),
                        "isro-qkd-key-0045".to_string(),
                        "isro-qkd-key-0046".to_string(),
                    ],
                    aad_authenticated: true,
                    timestamp_epoch_secs: 1727602920,
                }),
                envelope_header: Some(QuMailEnvelopeHeader {
                    version: 1,
                    security_level: SecurityLevel::QuantumOtp,
                    message_id: "urn:uuid:gslv-traj-42".to_string(),
                    sender_sae: 1,
                    recipient_sae: 2,
                    key_ids: vec!["isro-qkd-key-0042".into(), "isro-qkd-key-0043".into()],
                    timestamp_epoch_secs: 1727602920,
                    tag_b64: Some("N8J9Xz4vL1q7Y0w2==".to_string()),
                    nonce_b64: None,
                    pqc_ciphertext_b64: None,
                }),
                raw_mime_size: 7820,
            },
            UiEmail {
                id: "msg-102".to_string(),
                folder: MailFolder::Inbox,
                from: "quantum.telecom@ursc.isro.gov.in".to_string(),
                to: vec!["officer.sac@isro.gov.in".to_string()],
                date: "Today, 11:15 IST".to_string(),
                subject: "NIST FIPS 203 ML-KEM-768 Hybrid Rekeying Notice".to_string(),
                snippet: "Rotated satellite optical ground station key material using Dual-PRF combiner...".to_string(),
                body_text: "QuMail Node Administrators,\n\nWe have successfully rotated the post-quantum identity encapsulation keypair for ground station URSC Bangalore.\n\nThe new ML-KEM-768 public parameter set has been published. All communications dispatched under Level 2.5 are combined with current ETSI GS QKD 014 entropy pool material.\n\nPlease verify your local decapsulation store.\n\nURSC Quantum Communications Division".to_string(),
                attachments: vec![
                    UiAttachment {
                        filename: "ursc_fips203_cert.pem".to_string(),
                        content_type: "application/x-pem-file".to_string(),
                        size_bytes: 1842,
                        data: b"-----BEGIN PQC PUBLIC KEY-----\nMIICXzCCAkegAwIBAg...\n-----END PQC PUBLIC KEY-----\n".to_vec(),
                    },
                ],
                security_level: SecurityLevel::HybridPqc,
                is_unread: true,
                verification: Some(UiVerificationInfo {
                    verified: true,
                    level: SecurityLevel::HybridPqc,
                    method_title: "NIST FIPS 203 ML-KEM-768 + QKD Dual-PRF Combiner".to_string(),
                    method_detail: "Shared secret encapsulated with recipient lattice public key and combined with 256-bit QKD symmetric key via HKDF-SHA256.".to_string(),
                    key_ids: vec!["isro-qkd-key-0078".to_string()],
                    aad_authenticated: true,
                    timestamp_epoch_secs: 1727591700,
                }),
                envelope_header: Some(QuMailEnvelopeHeader {
                    version: 1,
                    security_level: SecurityLevel::HybridPqc,
                    message_id: "urn:uuid:pqc-rekey-78".to_string(),
                    sender_sae: 2,
                    recipient_sae: 1,
                    key_ids: vec!["isro-qkd-key-0078".into()],
                    timestamp_epoch_secs: 1727591700,
                    tag_b64: None,
                    nonce_b64: Some("dGVzdG5vbmNlMTI=".to_string()),
                    pqc_ciphertext_b64: Some("5nMALNJ4udJ6KXlcBqnI7jsSUFRuEk...".to_string()),
                }),
                raw_mime_size: 4210,
            },
            UiEmail {
                id: "msg-103".to_string(),
                folder: MailFolder::Inbox,
                from: "security.audit@isro.gov.in".to_string(),
                to: vec!["officer.sac@isro.gov.in".to_string()],
                date: "Yesterday, 16:30 IST".to_string(),
                subject: "ETSI GS QKD 014 Key Bank Audit: 100 x 1 Kb Certified".to_string(),
                snippet: "Audit completed for symmetrical key bank. 100 keys validated, 0 collisions...".to_string(),
                body_text: "Security Operations,\n\nAnnual cryptographic audit report for the QuMail ISRO Symmetrical Key Bank has concluded.\n\nAll 100 symmetric keys (each 1024 bytes / 8192 bits) satisfy FIPS 140-3 entropy standards. Crash recovery reconciliation and atomic reservation primitives passed all stress runs.\n\nKey depletion alert threshold is maintained at 20 remaining slots.\n\nISRO Information Security Cell".to_string(),
                attachments: vec![],
                security_level: SecurityLevel::Qaes,
                is_unread: false,
                verification: Some(UiVerificationInfo {
                    verified: true,
                    level: SecurityLevel::Qaes,
                    method_title: "Quantum-Aided AES-256-GCM".to_string(),
                    method_detail: "256-bit symmetric session key and 96-bit nonce derived from 1024-byte QKD slot via HKDF-SHA256 with AAD context binding.".to_string(),
                    key_ids: vec!["isro-qkd-key-0091".to_string()],
                    aad_authenticated: true,
                    timestamp_epoch_secs: 1727523000,
                }),
                envelope_header: Some(QuMailEnvelopeHeader {
                    version: 1,
                    security_level: SecurityLevel::Qaes,
                    message_id: "urn:uuid:audit-report-91".to_string(),
                    sender_sae: 1,
                    recipient_sae: 2,
                    key_ids: vec!["isro-qkd-key-0091".into()],
                    timestamp_epoch_secs: 1727523000,
                    tag_b64: None,
                    nonce_b64: Some("a2V5bm9uY2UxMjM0".to_string()),
                    pqc_ciphertext_b64: None,
                }),
                raw_mime_size: 2150,
            },
            UiEmail {
                id: "msg-104".to_string(),
                folder: MailFolder::Inbox,
                from: "newsletter@esa.int".to_string(),
                to: vec!["officer.sac@isro.gov.in".to_string()],
                date: "28 Sep, 09:00 IST".to_string(),
                subject: "European Space Agency: Earth Observation Monthly Digest".to_string(),
                snippet: "Discover latest Sentinel satellite radar imagery and global climate updates...".to_string(),
                body_text: "Dear Colleague,\n\nWelcome to this month's issue of the ESA Earth Observation Digest. In this issue: Sentinel-2C data calibration, Copernicus marine monitoring updates, and upcoming international symposia.\n\nBest regards,\nESA Communications Team".to_string(),
                attachments: vec![],
                security_level: SecurityLevel::Baseline,
                is_unread: false,
                verification: None,
                envelope_header: None,
                raw_mime_size: 1540,
            },
            UiEmail {
                id: "msg-201".to_string(),
                folder: MailFolder::Sent,
                from: "officer.sac@isro.gov.in".to_string(),
                to: vec!["director.sac@isro.gov.in".to_string()],
                date: "Yesterday, 18:05 IST".to_string(),
                subject: "Payload Calibration Telemetry Report #14".to_string(),
                snippet: "Transmitted encrypted calibration logs over Level 2 Q-AES pipeline...".to_string(),
                body_text: "Sir,\n\nCalibration telemetry for sensor array 7 has been successfully compiled and sent under Level 2 security.\n\nAll sensor drift values remain within acceptable thresholds (+/- 0.02%).\n\nRespectfully,\nSAC Payload Engineering".to_string(),
                attachments: vec![
                    UiAttachment {
                        filename: "sensor7_calibration.log".to_string(),
                        content_type: "text/plain".to_string(),
                        size_bytes: 840,
                        data: b"SENSOR 7: CALIBRATION STABLE. BIAS: 0.0012\n".to_vec(),
                    },
                ],
                security_level: SecurityLevel::Qaes,
                is_unread: false,
                verification: Some(UiVerificationInfo {
                    verified: true,
                    level: SecurityLevel::Qaes,
                    method_title: "Quantum-Aided AES-256-GCM".to_string(),
                    method_detail: "Sender copy: Key slot isro-qkd-key-0099 consumed and zeroized upon commit.".to_string(),
                    key_ids: vec!["isro-qkd-key-0099".to_string()],
                    aad_authenticated: true,
                    timestamp_epoch_secs: 1727527500,
                }),
                envelope_header: None,
                raw_mime_size: 2600,
            },
        ]
    }
}
