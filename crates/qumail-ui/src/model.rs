//! QuMail UI Data Models
//!
//! Internal data representations for Outlook folders, messages, attachments,
//! cryptographic verification banners, and KME/Key Bank health gauges.

#![allow(dead_code)]

use qumail_core::SecurityLevel;
use qumail_net::QuMailEnvelopeHeader;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MailFolder {
    Inbox,
    Sent,
    Drafts,
    Trash,
}

impl MailFolder {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Inbox => "Inbox",
            Self::Sent => "Sent Items",
            Self::Drafts => "Drafts",
            Self::Trash => "Deleted Items",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Inbox => "📥",
            Self::Sent => "📤",
            Self::Drafts => "📝",
            Self::Trash => "🗑",
        }
    }
}

#[derive(Clone, Debug)]
pub struct UiAttachment {
    pub filename: String,
    pub content_type: String,
    pub size_bytes: usize,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct UiVerificationInfo {
    pub verified: bool,
    pub level: SecurityLevel,
    pub method_title: String,
    pub method_detail: String,
    pub key_ids: Vec<String>,
    pub aad_authenticated: bool,
    pub timestamp_epoch_secs: u64,
}

#[derive(Clone, Debug)]
pub struct UiEmail {
    pub id: String,
    pub folder: MailFolder,
    pub from: String,
    pub to: Vec<String>,
    pub date: String,
    pub subject: String,
    pub snippet: String,
    pub body_text: String,
    pub attachments: Vec<UiAttachment>,
    pub security_level: SecurityLevel,
    pub is_unread: bool,
    pub verification: Option<UiVerificationInfo>,
    pub envelope_header: Option<QuMailEnvelopeHeader>,
    pub raw_mime_size: usize,
}

#[derive(Clone, Debug)]
pub struct KeyBankStatus {
    pub stored_keys: usize,
    pub max_keys: usize,
    pub key_size_bits: usize,
    pub master_sae: u64,
    pub slave_sae: u64,
    pub mode: String,
    pub is_healthy: bool,
}

impl Default for KeyBankStatus {
    fn default() -> Self {
        Self {
            stored_keys: 100,
            max_keys: 100,
            key_size_bits: 8192,
            master_sae: 1,
            slave_sae: 2,
            mode: "ISRO 100 x 1 Kb Symmetrical Key Bank".to_string(),
            is_healthy: true,
        }
    }
}
