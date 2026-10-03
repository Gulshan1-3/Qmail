//! QuMail Command-Line Interface
//!
//! Provides operational commands to send quantum-safe emails (Levels 1, 2, 3),
//! fetch and decrypt messages with attachment recovery, inspect KME inventory,
//! and generate ISRO-compliant 100 x 1 Kb symmetrical key banks.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use qumail_core::{SaeId, SecurityLevel};
use qumail_crypto::{
    DecapsulationKey, EncapsulationKey, MlKem768, PqcKeyPairBundle, QuMailCryptoEngine,
};
use qumail_kme::{Etsi014Client, KeyBankStore, KeyManager, QkdSimulator};
use qumail_net::{
    build_inner_mime_message, fetch_imap_messages, package_qumail_message, send_smtp_message,
    EmailAttachment, ImapConfig, SmtpConfig,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Copy, Clone, Eq, PartialEq, Debug, ValueEnum)]
pub enum CliSecurityLevel {
    #[value(name = "baseline", alias = "1", alias = "none")]
    Baseline,
    #[value(name = "qaes", alias = "2", alias = "aes")]
    Qaes,
    #[value(name = "hybrid", alias = "2.5", alias = "hybrid_pqc")]
    Hybrid,
    #[value(name = "quantum-otp", alias = "3", alias = "otp")]
    QuantumOtp,
}

impl From<CliSecurityLevel> for SecurityLevel {
    fn from(c: CliSecurityLevel) -> Self {
        match c {
            CliSecurityLevel::Baseline => SecurityLevel::Baseline,
            CliSecurityLevel::Qaes => SecurityLevel::Qaes,
            CliSecurityLevel::Hybrid => SecurityLevel::HybridPqc,
            CliSecurityLevel::QuantumOtp => SecurityLevel::QuantumOtp,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "qumail",
    version,
    about = "QuMail: Quantum-Safe Email Client (ISRO SIH1523 / ETSI GS QKD 014)"
)]
struct Cli {
    #[arg(long, env = "QMAIL_LOG", default_value = "info")]
    log: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Send an email with selectable quantum security level
    Send {
        #[arg(long, env = "QMAIL_SMTP_HOST", default_value = "smtp.gmail.com")]
        smtp_host: String,

        #[arg(long, env = "QMAIL_SMTP_PORT", default_value_t = 587)]
        smtp_port: u16,

        #[arg(long, default_value_t = false)]
        implicit_tls: bool,

        #[arg(long, env = "QMAIL_SMTP_USER")]
        username: String,

        #[arg(long, env = "QMAIL_SMTP_PASS")]
        password: String,

        #[arg(long)]
        from: String,

        #[arg(long, value_delimiter = ',')]
        to: Vec<String>,

        #[arg(long)]
        subject: String,

        #[arg(long, default_value = "")]
        text: String,

        #[arg(long)]
        html: Option<String>,

        #[arg(long, value_delimiter = ',')]
        attachments: Vec<String>,

        #[arg(long, value_enum, default_value_t = CliSecurityLevel::Baseline)]
        security: CliSecurityLevel,

        /// Path to local ISRO 100 x 1 Kb key bank file
        #[arg(long, env = "QMAIL_KEY_BANK")]
        key_bank: Option<PathBuf>,

        /// Remote ETSI GS QKD 014 KME URL
        #[arg(long, env = "QMAIL_KM_URL")]
        km_url: Option<String>,

        #[arg(long, env = "QMAIL_KM_IDENTITY_P12")]
        km_identity_p12: Option<PathBuf>,

        #[arg(long, env = "QMAIL_KM_IDENTITY_PASSWORD")]
        km_identity_password: Option<String>,

        #[arg(long, env = "QMAIL_KM_CA_PEM")]
        km_ca_pem: Option<PathBuf>,

        #[arg(long, env = "QMAIL_SENDER_SAE", default_value_t = 1)]
        sender_sae: u64,

        #[arg(long, env = "QMAIL_RECIPIENT_SAE", default_value_t = 2)]
        recipient_sae: u64,

        /// Path to recipient's ML-KEM-768 public key file, JSON bundle, or base64 string
        #[arg(long, env = "QMAIL_RECIPIENT_PQC_KEY")]
        recipient_pqc_key: Option<String>,

        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Fetch and automatically decrypt incoming QuMail messages
    Fetch {
        #[arg(long, env = "QMAIL_IMAP_HOST", default_value = "imap.gmail.com")]
        imap_host: String,

        #[arg(long, env = "QMAIL_IMAP_PORT", default_value_t = 993)]
        imap_port: u16,

        #[arg(long, env = "QMAIL_IMAP_USER")]
        username: String,

        #[arg(long, env = "QMAIL_IMAP_PASS")]
        password: String,

        #[arg(long, default_value = "INBOX")]
        mailbox: String,

        #[arg(long, default_value_t = 10)]
        limit: u32,

        #[arg(long)]
        attachments_dir: Option<PathBuf>,

        /// Path to local ISRO 100 x 1 Kb key bank file
        #[arg(long, env = "QMAIL_KEY_BANK")]
        key_bank: Option<PathBuf>,

        /// Remote ETSI GS QKD 014 KME URL
        #[arg(long, env = "QMAIL_KM_URL")]
        km_url: Option<String>,

        #[arg(long, env = "QMAIL_KM_IDENTITY_P12")]
        km_identity_p12: Option<PathBuf>,

        #[arg(long, env = "QMAIL_KM_IDENTITY_PASSWORD")]
        km_identity_password: Option<String>,

        #[arg(long, env = "QMAIL_KM_CA_PEM")]
        km_ca_pem: Option<PathBuf>,

        #[arg(long, env = "QMAIL_MY_SAE", default_value_t = 2)]
        my_sae: u64,

        /// Path to local ML-KEM-768 private key file, JSON bundle, or base64 string
        #[arg(long, env = "QMAIL_PQC_KEY")]
        pqc_key: Option<String>,
    },

    /// Check key inventory and health of KME or Key Bank
    KmeStatus {
        #[arg(long, env = "QMAIL_KEY_BANK")]
        key_bank: Option<PathBuf>,

        #[arg(long, env = "QMAIL_KM_URL")]
        km_url: Option<String>,

        #[arg(long, env = "QMAIL_KM_IDENTITY_P12")]
        km_identity_p12: Option<PathBuf>,

        #[arg(long, env = "QMAIL_KM_IDENTITY_PASSWORD")]
        km_identity_password: Option<String>,

        #[arg(long, env = "QMAIL_KM_CA_PEM")]
        km_ca_pem: Option<PathBuf>,

        #[arg(long, default_value_t = 1)]
        my_sae: u64,

        #[arg(long, default_value_t = 2)]
        peer_sae: u64,
    },

    /// Initialize a pair of synchronized 100 x 1 Kb symmetrical key banks for Alice and Bob
    InitKeybank {
        #[arg(long, default_value = "keybank_alice.json")]
        alice_file: PathBuf,

        #[arg(long, default_value = "keybank_bob.json")]
        bob_file: PathBuf,

        #[arg(long, default_value_t = 1)]
        alice_sae: u64,

        #[arg(long, default_value_t = 2)]
        bob_sae: u64,
    },

    /// Generate a fresh NIST FIPS 203 ML-KEM-768 keypair for Level 2.5 Hybrid PQC
    GeneratePqcKey {
        /// File path to save the JSON keypair bundle
        #[arg(long, short, default_value = "pqc_keypair.json")]
        out: PathBuf,
    },
}

fn init_tracing(level: &str) -> Result<()> {
    let filter = EnvFilter::try_new(level)
        .or_else(|_| EnvFilter::try_new("info"))
        .context("invalid log level")?;
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
    Ok(())
}

fn resolve_pqc_encapsulation_key(
    key_arg: Option<&str>,
) -> Result<Option<EncapsulationKey<MlKem768>>> {
    let Some(arg) = key_arg else {
        return Ok(None);
    };
    let bytes = if Path::new(arg).exists() {
        let content = fs::read_to_string(arg)?;
        if let Ok(bundle) = serde_json::from_str::<PqcKeyPairBundle>(&content) {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(bundle.public_key_b64)?
        } else {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(content.trim())?
        }
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(arg.trim())?
    };
    let ek = QuMailCryptoEngine::parse_encapsulation_key(&bytes)
        .map_err(|e| anyhow!("Failed to parse encapsulation key: {e}"))?;
    Ok(Some(ek))
}

fn resolve_pqc_decapsulation_key(
    key_arg: Option<&str>,
) -> Result<Option<DecapsulationKey<MlKem768>>> {
    let Some(arg) = key_arg else {
        return Ok(None);
    };
    let bytes = if Path::new(arg).exists() {
        let content = fs::read_to_string(arg)?;
        if let Ok(bundle) = serde_json::from_str::<PqcKeyPairBundle>(&content) {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(bundle.secret_key_b64)?
        } else {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(content.trim())?
        }
    } else {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(arg.trim())?
    };
    let dk = QuMailCryptoEngine::parse_decapsulation_key(&bytes)
        .map_err(|e| anyhow!("Failed to parse decapsulation key: {e}"))?;
    Ok(Some(dk))
}

fn resolve_key_manager(
    key_bank: Option<&Path>,
    km_url: Option<&str>,
    km_p12: Option<(&Path, &str)>,
    km_ca: Option<&Path>,
    my_sae: SaeId,
    peer_sae: SaeId,
) -> Result<Arc<dyn KeyManager>> {
    if let Some(bank_path) = key_bank {
        let store = KeyBankStore::open_or_create(bank_path, my_sae, peer_sae)
            .map_err(|e| anyhow!("Failed to open Key Bank at {}: {e}", bank_path.display()))?;
        Ok(Arc::new(store))
    } else if let Some(url) = km_url {
        let client = Etsi014Client::new(url, my_sae, km_p12, km_ca)
            .map_err(|e| anyhow!("Failed to initialize ETSI GS QKD 014 client: {e}"))?;
        Ok(Arc::new(client))
    } else {
        info!("No KME URL or Key Bank provided: using synchronized in-memory QKD simulator");
        Ok(Arc::new(QkdSimulator::new()))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(&cli.log)?;

    match cli.command {
        Commands::Send {
            smtp_host,
            smtp_port,
            implicit_tls,
            username,
            password,
            from,
            to,
            subject,
            text,
            html,
            attachments,
            security,
            key_bank,
            km_url,
            km_identity_p12,
            km_identity_password,
            km_ca_pem,
            sender_sae,
            recipient_sae,
            recipient_pqc_key,
            dry_run,
        } => {
            let mut att_data = Vec::new();
            for p in &attachments {
                att_data.push(EmailAttachment::from_file(p)?);
            }

            let inner_msg = build_inner_mime_message(
                &from,
                &to,
                &subject,
                &text,
                html.as_deref(),
                &att_data,
            )?;

            let p12_tuple = match (&km_identity_p12, &km_identity_password) {
                (Some(p), Some(pwd)) => Some((p.as_path(), pwd.as_str())),
                _ => None,
            };

            let km = resolve_key_manager(
                key_bank.as_deref(),
                km_url.as_deref(),
                p12_tuple,
                km_ca_pem.as_deref(),
                SaeId(sender_sae),
                SaeId(recipient_sae),
            )?;

            let recipient_pqc = resolve_pqc_encapsulation_key(recipient_pqc_key.as_deref())?;
            let crypto = QuMailCryptoEngine::with_pqc_keys(None, recipient_pqc);
            let sec_level: SecurityLevel = security.into();

            let packaged = package_qumail_message(
                &from,
                &to,
                &subject,
                &inner_msg,
                sec_level,
                SaeId(sender_sae),
                SaeId(recipient_sae),
                km.as_ref(),
                &crypto,
            )
            .await?;

            if dry_run {
                println!("\n=== [Dry Run] Built Envelope ===");
                println!("Security Level: {sec_level}");
                println!("Recipients: {}", to.join(", "));
                println!("Message Size: {} bytes", packaged.formatted().len());
                return Ok(());
            }

            let smtp_conf = SmtpConfig {
                host: smtp_host,
                port: smtp_port,
                username,
                password,
                implicit_tls,
            };

            send_smtp_message(&smtp_conf, &packaged)?;
            println!("Email successfully sent with security level [{sec_level}]!");
            Ok(())
        }

        Commands::Fetch {
            imap_host,
            imap_port,
            username,
            password,
            mailbox,
            limit,
            attachments_dir,
            key_bank,
            km_url,
            km_identity_p12,
            km_identity_password,
            km_ca_pem,
            my_sae,
            pqc_key,
        } => {
            let p12_tuple = match (&km_identity_p12, &km_identity_password) {
                (Some(p), Some(pwd)) => Some((p.as_path(), pwd.as_str())),
                _ => None,
            };

            let km = resolve_key_manager(
                key_bank.as_deref(),
                km_url.as_deref(),
                p12_tuple,
                km_ca_pem.as_deref(),
                SaeId(my_sae),
                SaeId(1), // Peer SAE fallback
            )?;

            let local_pqc = resolve_pqc_decapsulation_key(pqc_key.as_deref())?;
            let crypto = QuMailCryptoEngine::with_pqc_keys(local_pqc, None);
            let imap_conf = ImapConfig {
                host: imap_host,
                port: imap_port,
                username,
                password,
                mailbox,
            };

            let emails = fetch_imap_messages(&imap_conf, limit, km.as_ref(), &crypto).await?;
            println!("\n=== Fetched {} Messages ===", emails.len());

            for (idx, em) in emails.iter().enumerate() {
                println!(
                    "\n[{}] {} | {} | Security: [{}]",
                    idx + 1,
                    em.date,
                    em.from,
                    em.security_level
                );
                println!("Subject: {}", em.subject);
                if !em.text_body.is_empty() {
                    println!("Body:\n{}", em.text_body.trim());
                }

                if !em.attachments.is_empty() {
                    println!("Attachments ({}):", em.attachments.len());
                    for att in &em.attachments {
                        println!(" - {} ({} bytes)", att.filename, att.data.len());
                        if let Some(dir) = &attachments_dir {
                            fs::create_dir_all(dir)?;
                            let target = dir.join(&att.filename);
                            fs::write(&target, &att.data)?;
                            println!("   -> saved to {}", target.display());
                        }
                    }
                }
            }

            Ok(())
        }

        Commands::KmeStatus {
            key_bank,
            km_url,
            km_identity_p12,
            km_identity_password,
            km_ca_pem,
            my_sae,
            peer_sae,
        } => {
            let p12_tuple = match (&km_identity_p12, &km_identity_password) {
                (Some(p), Some(pwd)) => Some((p.as_path(), pwd.as_str())),
                _ => None,
            };

            let km = resolve_key_manager(
                key_bank.as_deref(),
                km_url.as_deref(),
                p12_tuple,
                km_ca_pem.as_deref(),
                SaeId(my_sae),
                SaeId(peer_sae),
            )?;

            let st = km.status(SaeId(peer_sae)).await?;
            println!("\n=== QuMail Key Management Status ===");
            println!("Source KME:      {}", st.source_kme_id);
            println!("Target KME:      {}", st.target_kme_id);
            println!("Master SAE ID:   {}", st.master_sae_id);
            println!("Slave SAE ID:    {}", st.slave_sae_id);
            println!("Key Slot Size:   {} bits ({} bytes)", st.key_size_bits, st.key_size_bits / 8);
            println!("Stored Keys:     {}/{}", st.stored_key_count, st.max_key_count);
            println!("Health State:    ONLINE & OPERATIONAL");
            Ok(())
        }

        Commands::InitKeybank {
            alice_file,
            bob_file,
            alice_sae,
            bob_sae,
        } => {
            KeyBankStore::create_synchronized_pair(
                &alice_file,
                &bob_file,
                SaeId(alice_sae),
                SaeId(bob_sae),
            )?;
            println!("\nSuccessfully initialized ISRO 100 x 1 Kb Symmetrical Key Banks:");
            println!("Alice Key Bank: {} (SAE {})", alice_file.display(), alice_sae);
            println!("Bob Key Bank:   {} (SAE {})", bob_file.display(), bob_sae);
            println!("Total Capacity: 100 keys (102.4 KB symmetric quantum key material)");
            Ok(())
        }

        Commands::GeneratePqcKey { out } => {
            let (dk, ek) = QuMailCryptoEngine::generate_pqc_keypair();
            let bundle = QuMailCryptoEngine::export_pqc_keypair(&dk, &ek);
            let json = serde_json::to_string_pretty(&bundle)?;
            fs::write(&out, json)?;
            println!("\n=== Generated NIST FIPS 203 ML-KEM-768 Keypair ===");
            println!("Saved keypair bundle to: {}", out.display());
            println!("Public Encapsulation Key (Base64):\n{}", bundle.public_key_b64);
            Ok(())
        }
    }
}
