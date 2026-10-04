//! QuMail Network & Mail Protocol Subsystem
//!
//! Handles MIME composition, RFC 822 serialization, standard `multipart/encrypted`
//! container wrapping, attachment preservation, SMTP transmission, and IMAP retrieval.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use lettre::message::{header, Attachment, Body, Mailbox, Message, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParametersBuilder};
use lettre::{SmtpTransport, Transport};
use mailparse::{parse_mail, MailHeaderMap, ParsedMail};
use mime_guess::MimeGuess;
use native_tls::TlsConnector;
use qumail_core::{CryptoContext, KeyId, MessageId, SaeId, SecurityLevel};
use qumail_crypto::{CryptoProvider, EncryptedMessage};
use qumail_kme::{KeyManager, KeyRequest};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use thiserror::Error;
use tracing::info;

pub const QUMAIL_MIME_PROTOCOL: &str = "application/vnd.qumail.v1";
pub const QUMAIL_HEADER_MIME: &str = "application/vnd.qumail.header+json";
pub const MAX_MIME_RECURSION_DEPTH: usize = 32;

static REPLAY_CACHE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();

fn get_replay_cache() -> &'static Mutex<HashSet<String>> {
    REPLAY_CACHE.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Enforces anti-replay protection. Returns an error if the message_id has already been processed.
pub fn record_and_check_replay(message_id: &str) -> Result<()> {
    let mut cache = get_replay_cache().lock().unwrap_or_else(|e| e.into_inner());
    if !cache.insert(message_id.to_string()) {
        return Err(anyhow!(
            "Replay attack detected: message ID '{}' has already been decrypted and processed",
            message_id
        ));
    }
    Ok(())
}

/// Resets the in-memory anti-replay cache (for testing isolation).
#[doc(hidden)]
pub fn reset_replay_cache_for_testing() {
    let mut cache = get_replay_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache.clear();
}

#[derive(Debug, Error)]
pub enum MailNetError {
    #[error("SMTP delivery failure: {0}")]
    Smtp(String),

    #[error("IMAP connection or synchronization failure: {0}")]
    Imap(String),

    #[error("MIME construction error: {0}")]
    Mime(String),

    #[error("envelope parse error: {0}")]
    Parse(String),

    #[error("cryptographic error during mail processing: {0}")]
    Crypto(String),

    #[error("key manager failure during mail processing: {0}")]
    KeyManager(String),
}

/// In-memory representation of an attachment.
#[derive(Clone, Debug)]
pub struct EmailAttachment {
    pub filename: String,
    pub content_type: String,
    pub data: Vec<u8>,
}

impl EmailAttachment {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        let filename = p
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("invalid attachment filename"))?
            .to_string();
        let data = fs::read(p).with_context(|| format!("reading file {}", p.display()))?;
        let mime = MimeGuess::from_path(p)
            .first_or_octet_stream()
            .to_string();
        Ok(Self {
            filename,
            content_type: mime,
            data,
        })
    }
}

/// Metadata header stored inside QuMail `multipart/encrypted` messages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuMailEnvelopeHeader {
    pub version: u16,
    pub security_level: SecurityLevel,
    pub message_id: String,
    pub sender_sae: u64,
    pub recipient_sae: u64,
    pub key_ids: Vec<String>,
    pub timestamp_epoch_secs: u64,
    pub tag_b64: Option<String>,
    pub nonce_b64: Option<String>,
    #[serde(default)]
    pub pqc_ciphertext_b64: Option<String>,
}

/// Decrypted and parsed high-level email message ready for display.
#[derive(Clone, Debug)]
pub struct DecryptedEmail {
    pub date: String,
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub text_body: String,
    pub html_body: Option<String>,
    pub attachments: Vec<EmailAttachment>,
    pub security_level: SecurityLevel,
    pub is_encrypted: bool,
    pub key_ids: Vec<KeyId>,
}

// ============================================================================
// 1. MIME Inner Builder & Envelope Packaging
// ============================================================================

/// Builds the inner RFC 822 MIME message containing plaintext, HTML, and all attachments.
pub fn build_inner_mime_message(
    from: &str,
    to: &[String],
    subject: &str,
    text: &str,
    html: Option<&str>,
    attachments: &[EmailAttachment],
) -> Result<Message> {
    let from_mb: Mailbox = from.parse().context("invalid from address")?;
    let mut builder = Message::builder().from(from_mb);

    for recipient in to {
        let mb: Mailbox = recipient.parse().context("invalid recipient address")?;
        builder = builder.to(mb);
    }
    builder = builder.subject(subject);

    // Body parts
    let text_part = SinglePart::plain(text.to_string());
    let body_part = if let Some(html_content) = html {
        MultiPart::alternative()
            .singlepart(text_part)
            .singlepart(SinglePart::html(html_content.to_string()))
    } else {
        MultiPart::mixed().singlepart(text_part)
    };

    if !attachments.is_empty() {
        let mut mixed = MultiPart::mixed().multipart(body_part);
        for att in attachments {
            let ct = header::ContentType::parse(&att.content_type)
                .unwrap_or_else(|_| header::ContentType::parse("application/octet-stream").unwrap());
            let part = Attachment::new(att.filename.clone()).body(Body::new(att.data.clone()), ct);
            mixed = mixed.singlepart(part);
        }
        builder.multipart(mixed).context("building multipart message")
    } else {
        builder.multipart(body_part).context("building single body message")
    }
}

/// Encapsulates an inner RFC 822 email into a standard QuMail `multipart/encrypted` envelope.
pub async fn package_qumail_message(
    from: &str,
    to: &[String],
    subject: &str,
    inner_msg: &Message,
    security_level: SecurityLevel,
    sender_sae: SaeId,
    recipient_sae: SaeId,
    key_manager: &dyn KeyManager,
    crypto: &dyn CryptoProvider,
) -> Result<Message> {
    if security_level == SecurityLevel::Baseline {
        // Level 1: Return raw email without envelope transformation
        return Ok(inner_msg.clone());
    }

    let inner_rfc822_bytes = inner_msg.formatted();

    // Allocate required key material based on security level
    let (needed_bytes, needed_count) = match security_level {
        SecurityLevel::Qaes | SecurityLevel::HybridPqc => (32, 1),
        SecurityLevel::QuantumOtp => (inner_rfc822_bytes.len() + 32, 1),
        SecurityLevel::Baseline => (0, 0),
    };

    let reservation = key_manager
        .reserve(KeyRequest {
            peer_sae: recipient_sae,
            requested_bytes: needed_bytes,
            count: needed_count,
        })
        .await
        .map_err(|e| anyhow!("KME key reservation failed: {e}"))?;

    let primary_key_id = reservation
        .keys
        .first()
        .map(|k| k.key_id.clone())
        .unwrap_or_else(KeyId::new);

    let context = CryptoContext::new(sender_sae, recipient_sae, primary_key_id);

    // Encrypt inner message
    let encrypted = crypto
        .encrypt(
            security_level,
            &inner_rfc822_bytes,
            &context,
            &reservation.keys,
        )
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    // Commit key consumption
    key_manager
        .commit(reservation.clone())
        .await
        .map_err(|e| anyhow!("KME commit failed: {e}"))?;

    // Build JSON metadata header part
    let header_meta = QuMailEnvelopeHeader {
        version: 1,
        security_level,
        message_id: context.message_id.0.clone(),
        sender_sae: sender_sae.0,
        recipient_sae: recipient_sae.0,
        key_ids: encrypted.allocated_key_ids.iter().map(|k| k.0.clone()).collect(),
        timestamp_epoch_secs: context.timestamp_epoch_secs,
        tag_b64: encrypted
            .tag
            .map(|t| base64::engine::general_purpose::STANDARD.encode(t)),
        nonce_b64: encrypted
            .nonce
            .map(|n| base64::engine::general_purpose::STANDARD.encode(n)),
        pqc_ciphertext_b64: encrypted
            .pqc_ciphertext
            .map(|c| base64::engine::general_purpose::STANDARD.encode(c)),
    };

    let header_json = serde_json::to_string_pretty(&header_meta)?;
    let header_part = SinglePart::builder()
        .header(header::ContentType::parse(QUMAIL_HEADER_MIME).unwrap())
        .body(header_json);

    // Encrypted payload part (Base64-encoded)
    let ct_b64 = base64::engine::general_purpose::STANDARD.encode(encrypted.ciphertext);
    let payload_part = SinglePart::builder()
        .header(header::ContentType::parse("application/octet-stream").unwrap())
        .header(header::ContentTransferEncoding::Base64)
        .body(ct_b64);

    let multipart_body = MultiPart::encrypted(QUMAIL_MIME_PROTOCOL.to_string())
        .singlepart(header_part)
        .singlepart(payload_part);

    let from_mb: Mailbox = from.parse().context("invalid from address")?;
    let mut builder = Message::builder().from(from_mb);
    for r in to {
        builder = builder.to(r.parse().context("invalid recipient address")?);
    }

    let outer_subject = format!("[QuMail-{}] {}", security_level.as_str().to_uppercase(), subject);
    builder
        .subject(outer_subject)
        .multipart(multipart_body)
        .context("building outer encrypted envelope")
}

// ============================================================================
// 2. MIME Envelope Parsing & Decryption
// ============================================================================

/// Detects and decrypts a received RFC 822 email, extracting body and attachments.
pub async fn parse_and_decrypt_qumail_message(
    raw_rfc822: &[u8],
    key_manager: &dyn KeyManager,
    crypto: &dyn CryptoProvider,
) -> Result<DecryptedEmail> {
    let parsed = parse_mail(raw_rfc822).context("parsing outer RFC822 mail")?;

    let outer_subject = parsed
        .headers
        .get_first_value("Subject")
        .unwrap_or_default();
    let outer_from = parsed.headers.get_first_value("From").unwrap_or_default();
    let outer_date = parsed.headers.get_first_value("Date").unwrap_or_default();

    // Check if message is a QuMail encrypted envelope
    let mut envelope_meta: Option<QuMailEnvelopeHeader> = None;
    let mut ciphertext_b64: Option<String> = None;

    extract_qumail_parts(&parsed, &mut envelope_meta, &mut ciphertext_b64);

    if let (Some(meta), Some(ct_b64)) = (envelope_meta, ciphertext_b64) {
        // Enforce anti-replay check: prevent replay attacks using previously decrypted envelopes
        record_and_check_replay(&meta.message_id)?;

        // Message is encrypted! Recover keys from KeyManager
        let ct = base64::engine::general_purpose::STANDARD
            .decode(&ct_b64)
            .context("base64 decode ciphertext")?;

        let key_ids: Vec<KeyId> = meta
            .key_ids
            .iter()
            .map(|id| KeyId::from_string(id.clone()))
            .collect();

        let keys = key_manager
            .get_decryption_keys(SaeId(meta.sender_sae), &key_ids)
            .await
            .map_err(|e| anyhow!("Failed to recover decryption keys: {e}"))?;

        let context = CryptoContext {
            protocol_version: meta.version,
            message_id: MessageId(meta.message_id),
            sender_sae: SaeId(meta.sender_sae),
            recipient_sae: SaeId(meta.recipient_sae),
            key_id: key_ids.first().cloned().unwrap_or_default(),
            timestamp_epoch_secs: meta.timestamp_epoch_secs,
        };

        let tag = meta
            .tag_b64
            .map(|t| base64::engine::general_purpose::STANDARD.decode(t))
            .transpose()?;
        let nonce = meta
            .nonce_b64
            .map(|n| base64::engine::general_purpose::STANDARD.decode(n))
            .transpose()?;
        let pqc_ciphertext = meta
            .pqc_ciphertext_b64
            .map(|c| base64::engine::general_purpose::STANDARD.decode(c))
            .transpose()?;

        let encrypted = EncryptedMessage {
            level: meta.security_level,
            ciphertext: ct,
            tag,
            nonce,
            allocated_key_ids: key_ids.clone(),
            pqc_ciphertext,
        };

        let decrypted_bytes = crypto
            .decrypt(&encrypted, &context, &keys)
            .map_err(|e| anyhow!("Decryption failed: {e}"))?;

        // Parse inner decrypted MIME tree
        let inner_parsed =
            parse_mail(&decrypted_bytes).context("parsing decrypted inner MIME message")?;

        let inner_subject = inner_parsed
            .headers
            .get_first_value("Subject")
            .unwrap_or(outer_subject);
        let inner_from = inner_parsed
            .headers
            .get_first_value("From")
            .unwrap_or(outer_from);
        let inner_date = inner_parsed
            .headers
            .get_first_value("Date")
            .unwrap_or(outer_date);

        let (text, html, attachments) = extract_content_and_attachments(&inner_parsed)?;

        Ok(DecryptedEmail {
            date: inner_date,
            from: inner_from,
            to: inner_parsed
                .headers
                .get_all_values("To")
                .into_iter()
                .flat_map(|v| v.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
                .filter(|s| !s.is_empty())
                .collect(),
            subject: inner_subject,
            text_body: text,
            html_body: html,
            attachments,
            security_level: meta.security_level,
            is_encrypted: true,
            key_ids,
        })
    } else {
        // Standard unencrypted email (Level 1 Baseline)
        let (text, html, attachments) = extract_content_and_attachments(&parsed)?;
        Ok(DecryptedEmail {
            date: outer_date,
            from: outer_from,
            to: parsed
                .headers
                .get_all_values("To")
                .into_iter()
                .flat_map(|v| v.split(',').map(|s| s.trim().to_string()).collect::<Vec<_>>())
                .filter(|s| !s.is_empty())
                .collect(),
            subject: outer_subject,
            text_body: text,
            html_body: html,
            attachments,
            security_level: SecurityLevel::Baseline,

            is_encrypted: false,
            key_ids: vec![],
        })
    }
}

fn extract_qumail_parts(
    part: &ParsedMail,
    meta: &mut Option<QuMailEnvelopeHeader>,
    ct: &mut Option<String>,
) {
    extract_qumail_parts_inner(part, meta, ct, 0);
}

fn extract_qumail_parts_inner(
    part: &ParsedMail,
    meta: &mut Option<QuMailEnvelopeHeader>,
    ct: &mut Option<String>,
    depth: usize,
) {
    if depth > MAX_MIME_RECURSION_DEPTH {
        tracing::warn!("MIME recursion depth limit ({MAX_MIME_RECURSION_DEPTH}) reached; halting traversal");
        return;
    }

    let ctype = &part.ctype.mimetype;
    if ctype == QUMAIL_HEADER_MIME || ctype == "application/json" {
        if let Ok(body) = part.get_body() {
            if let Ok(h) = serde_json::from_str::<QuMailEnvelopeHeader>(&body) {
                *meta = Some(h);
            }
        }
    } else if ctype == "application/octet-stream" || ctype == "application/qumail-otp" {
        if let Ok(body) = part.get_body() {
            // Clean whitespace / line breaks from base64
            let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            if !clean.is_empty() {
                *ct = Some(clean);
            }
        }
    }

    for sub in &part.subparts {
        extract_qumail_parts_inner(sub, meta, ct, depth + 1);
    }
}

fn extract_content_and_attachments(
    mail: &ParsedMail,
) -> Result<(String, Option<String>, Vec<EmailAttachment>)> {
    let mut text_body = String::new();
    let mut html_body = None;
    let mut attachments = Vec::new();

    collect_mail_parts(mail, &mut text_body, &mut html_body, &mut attachments)?;

    Ok((text_body, html_body, attachments))
}

fn collect_mail_parts(
    part: &ParsedMail,
    text: &mut String,
    html: &mut Option<String>,
    attachments: &mut Vec<EmailAttachment>,
) -> Result<()> {
    collect_mail_parts_inner(part, text, html, attachments, 0)
}

fn collect_mail_parts_inner(
    part: &ParsedMail,
    text: &mut String,
    html: &mut Option<String>,
    attachments: &mut Vec<EmailAttachment>,
    depth: usize,
) -> Result<()> {
    if depth > MAX_MIME_RECURSION_DEPTH {
        return Err(anyhow!("MIME recursion depth limit exceeded ({MAX_MIME_RECURSION_DEPTH})"));
    }

    let cdisp = part.get_content_disposition();
    let is_attachment_disp = cdisp.disposition == mailparse::DispositionType::Attachment;
    let filename_opt = cdisp
        .params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned());

    if is_attachment_disp || (filename_opt.is_some() && part.ctype.mimetype != "text/plain") {
        let raw_filename = filename_opt.unwrap_or_else(|| "attachment.bin".into());
        // Path traversal and null-byte/control-character sanitization
        let clean_filename = Path::new(&raw_filename)
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.chars().filter(|c| *c != '\0' && !c.is_control()).collect::<String>())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "attachment.bin".to_string());

        let raw_data = part.get_body_raw().unwrap_or_default();
        let data = if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(
            std::str::from_utf8(&raw_data).unwrap_or("").trim(),
        ) {
            if !decoded.is_empty() {
                decoded
            } else {
                raw_data
            }
        } else if raw_data.ends_with(b"\r\n") {
            raw_data[..raw_data.len() - 2].to_vec()
        } else {
            raw_data
        };

        attachments.push(EmailAttachment {
            filename: clean_filename,
            content_type: part.ctype.mimetype.clone(),
            data,
        });
    } else if part.subparts.is_empty() {
        if part.ctype.mimetype == "text/plain" && text.is_empty() {
            if let Ok(t) = part.get_body() {
                *text = t;
            }
        } else if part.ctype.mimetype == "text/html" && html.is_none() {
            if let Ok(h) = part.get_body() {
                *html = Some(h);
            }
        }
    } else {
        for sub in &part.subparts {
            collect_mail_parts_inner(sub, text, html, attachments, depth + 1)?;
        }
    }

    Ok(())
}

// ============================================================================
// 3. SMTP & IMAP Transport Services
// ============================================================================

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub implicit_tls: bool,
}

pub fn send_smtp_message(config: &SmtpConfig, message: &Message) -> Result<()> {
    let creds = Credentials::new(config.username.clone(), config.password.clone());
    let tls_params = TlsParametersBuilder::new(config.host.clone()).build()?;
    let builder = if config.implicit_tls {
        SmtpTransport::relay(&config.host)?
            .port(config.port)
            .tls(Tls::Required(tls_params))
    } else {
        SmtpTransport::relay(&config.host)?
            .port(config.port)
            .tls(Tls::Opportunistic(tls_params))
    };

    let transport = builder
        .credentials(creds)
        .pool_config(Default::default())
        .build();

    info!(
        "Transmitting message via SMTP {}:{}...",
        config.host, config.port
    );
    transport.send(message).context("SMTP send failed")?;
    info!("Message successfully sent via SMTP");
    Ok(())
}

pub struct ImapConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub mailbox: String,
}

pub async fn fetch_imap_messages(
    config: &ImapConfig,
    limit: u32,
    key_manager: &dyn KeyManager,
    crypto: &dyn CryptoProvider,
) -> Result<Vec<DecryptedEmail>> {
    let tls = TlsConnector::builder().build().context("TLS connector build")?;
    let client = imap::connect((config.host.as_str(), config.port), &config.host, &tls)
        .with_context(|| format!("connecting to IMAP {}:{}", config.host, config.port))?;

    let mut session = client
        .login(&config.username, &config.password)
        .map_err(|e| anyhow!("IMAP login failed: {}", e.0))?;

    session
        .select(&config.mailbox)
        .with_context(|| format!("selecting mailbox {}", config.mailbox))?;

    let mb = session.status(&config.mailbox, "MESSAGES").context("status")?;
    let last = mb.exists;
    if last == 0 {
        session.logout()?;
        return Ok(Vec::new());
    }

    let from_seq = if last > limit { last - limit + 1 } else { 1 };
    let range = format!("{}:{}", from_seq, last);
    let msgs = session.fetch(range, "RFC822").context("fetch messages")?;

    let mut results = Vec::new();
    for msg in msgs.iter() {
        if let Some(body) = msg.body() {
            match parse_and_decrypt_qumail_message(body, key_manager, crypto).await {
                Ok(email) => results.push(email),
                Err(e) => {
                    tracing::warn!("Failed to parse or decrypt message: {e}");
                }
            }
        }
    }

    session.logout()?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qumail_crypto::QuMailCryptoEngine;
    use qumail_kme::QkdSimulator;

    #[tokio::test]
    async fn test_full_qumail_email_package_and_decrypt_with_attachments() {
        let sim = QkdSimulator::new();
        let crypto = QuMailCryptoEngine::new();

        let attachment = EmailAttachment {
            filename: "satellite_telemetry.csv".to_string(),
            content_type: "text/csv".to_string(),
            data: b"timestamp,altitude,velocity\n100,500,7.8\n".to_vec(),
        };

        let inner_msg = build_inner_mime_message(
            "alice@isro.gov.in",
            &["bob@isro.gov.in".into()],
            "Trajectory Update",
            "Please find attached orbital parameters.",
            Some("<p>Please find attached orbital parameters.</p>"),
            &[attachment.clone()],
        )
        .unwrap();

        // 1. Test Level 2 Q-AES
        let outer_msg_l2 = package_qumail_message(
            "alice@isro.gov.in",
            &["bob@isro.gov.in".into()],
            "Trajectory Update",
            &inner_msg,
            SecurityLevel::Qaes,
            SaeId(1),
            SaeId(2),
            &sim,
            &crypto,
        )
        .await
        .unwrap();

        let outer_bytes_l2 = outer_msg_l2.formatted();
        let decrypted_l2 = parse_and_decrypt_qumail_message(&outer_bytes_l2, &sim, &crypto)
            .await
            .unwrap();

        assert_eq!(decrypted_l2.security_level, SecurityLevel::Qaes);
        assert!(decrypted_l2.is_encrypted);
        assert_eq!(decrypted_l2.subject, "Trajectory Update");
        assert_eq!(
            decrypted_l2.text_body.trim(),
            "Please find attached orbital parameters."
        );
        assert_eq!(decrypted_l2.attachments.len(), 1);
        assert_eq!(
            decrypted_l2.attachments[0].filename,
            "satellite_telemetry.csv"
        );
        assert_eq!(decrypted_l2.attachments[0].data, attachment.data);

        // 2. Test Level 3 Quantum OTP
        let outer_msg_l3 = package_qumail_message(
            "alice@isro.gov.in",
            &["bob@isro.gov.in".into()],
            "Top Secret Code",
            &inner_msg,
            SecurityLevel::QuantumOtp,
            SaeId(1),
            SaeId(2),
            &sim,
            &crypto,
        )
        .await
        .unwrap();

        let outer_bytes_l3 = outer_msg_l3.formatted();
        let decrypted_l3 = parse_and_decrypt_qumail_message(&outer_bytes_l3, &sim, &crypto)
            .await
            .unwrap();

        assert_eq!(decrypted_l3.security_level, SecurityLevel::QuantumOtp);
        assert!(decrypted_l3.is_encrypted);
        assert_eq!(decrypted_l3.attachments.len(), 1);
        assert_eq!(decrypted_l3.attachments[0].data, attachment.data);
    }
}
