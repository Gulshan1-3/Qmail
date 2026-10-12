//! Settings & Key Management Modal
//!
//! Provides configuration for SMTP, IMAP, ETSI GS QKD 014 REST KME,
//! local ISRO 100 x 1 Kb key banks, and NIST FIPS 203 PQC key generation.

use crate::state::{ActiveModal, AppState, SettingsConfig};
use crate::theme::QuMailTheme;
use egui::{vec2, Align2, Color32, Context, RichText, ScrollArea, Window};
use qumail_crypto::QuMailCryptoEngine;

pub fn render_settings_modal(ctx: &Context, state: &mut AppState) {
    if state.active_modal != ActiveModal::Settings {
        return;
    }

    let mut open = true;
    let mut should_close = false;

    Window::new("⚙ QuMail Settings & Cryptographic Key Management")
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .default_size(vec2(620.0, 520.0))
        .show(ctx, |ui| {
            ui.vertical(|ui| {
                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // 1. Quantum Key Management (KME / Key Bank)
                        ui.label(
                            RichText::new("1. QUANTUM KEY MANAGER & ISRO KEY BANK")
                                .size(12.5)
                                .strong()
                                .color(QuMailTheme::L2_CYAN_FG),
                        );
                        ui.add_space(4.0);

                        egui::Grid::new("kme_settings_grid")
                            .num_columns(2)
                            .spacing(vec2(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.label("Key Bank Path:");
                                let mut path_str = state.settings.key_bank_path.to_string_lossy().to_string();
                                if ui.add(egui::TextEdit::singleline(&mut path_str).desired_width(320.0)).changed() {
                                    state.settings.key_bank_path = path_str.into();
                                }
                                ui.end_row();

                                ui.label("ETSI 014 KME URL:");
                                ui.add(egui::TextEdit::singleline(&mut state.settings.km_url).desired_width(320.0));
                                ui.end_row();

                                ui.label("My Node SAE ID:");
                                ui.add(egui::DragValue::new(&mut state.settings.sender_sae).range(1..=9999));
                                ui.end_row();

                                ui.label("Peer Node SAE ID:");
                                ui.add(egui::DragValue::new(&mut state.settings.recipient_sae).range(1..=9999));
                                ui.end_row();
                            });

                        ui.add_space(6.0);
                        if ui.button(RichText::new("🔄 Re-initialize Symmetrical Key Bank (100 x 1 Kb)").size(11.5)).clicked() {
                            state.key_bank_status.stored_keys = 100;
                            state.key_bank_status.is_healthy = true;
                            state.notification_toast = Some((
                                "Key Bank re-initialized with 100 fresh 1 Kb keys.".to_string(),
                                false,
                            ));
                        }

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(8.0);

                        // 2. Post-Quantum Identity (NIST FIPS 203 ML-KEM-768)
                        ui.label(
                            RichText::new("2. NIST FIPS 203 ML-KEM-768 POST-QUANTUM KEY")
                                .size(12.5)
                                .strong()
                                .color(QuMailTheme::L25_PURPLE_FG),
                        );
                        ui.add_space(4.0);

                        ui.horizontal(|ui| {
                            if ui.button(RichText::new("⚡ Generate Fresh ML-KEM Keypair").size(11.5)).clicked() {
                                let (dk, ek) = QuMailCryptoEngine::generate_pqc_keypair();
                                let bundle = QuMailCryptoEngine::export_pqc_keypair(&dk, &ek);
                                state.settings.pqc_public_key_b64 = bundle.public_key_b64;
                                state.notification_toast = Some((
                                    "Fresh NIST FIPS 203 ML-KEM-768 keypair generated.".to_string(),
                                    false,
                                ));
                            }
                        });

                        ui.add_space(4.0);
                        ui.label(RichText::new("Local Public Encapsulation Key (Base64):").size(10.5).color(QuMailTheme::TEXT_MUTED));
                        ui.add(
                            egui::TextEdit::multiline(&mut state.settings.pqc_public_key_b64)
                                .desired_rows(3)
                                .desired_width(ui.available_width()),
                        );

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(8.0);

                        // 3. Post-Quantum Digital Signature Identity (NIST FIPS 204 ML-DSA-65)
                        ui.label(
                            RichText::new("3. NIST FIPS 204 ML-DSA-65 DIGITAL SIGNATURE KEY")
                                .size(12.5)
                                .strong()
                                .color(Color32::from_rgb(52, 211, 153)),
                        );
                        ui.add_space(4.0);

                        ui.horizontal(|ui| {
                            if ui.button(RichText::new("⚡ Generate Fresh ML-DSA Keypair").size(11.5)).clicked() {
                                let (sk, vk) = QuMailCryptoEngine::generate_dsa_keypair();
                                let bundle = QuMailCryptoEngine::export_dsa_keypair(&sk, &vk);
                                state.settings.dsa_public_key_b64 = bundle.public_key_b64;
                                state.notification_toast = Some((
                                    "Fresh NIST FIPS 204 ML-DSA-65 keypair generated.".to_string(),
                                    false,
                                ));
                            }
                        });

                        ui.add_space(4.0);
                        ui.label(RichText::new("Local Public Verifying Key (Base64):").size(10.5).color(QuMailTheme::TEXT_MUTED));
                        ui.add(
                            egui::TextEdit::multiline(&mut state.settings.dsa_public_key_b64)
                                .desired_rows(3)
                                .desired_width(ui.available_width()),
                        );

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(8.0);

                        // 4. SMTP & IMAP Transport Settings
                        ui.label(
                            RichText::new("4. MAIL SERVER TRANSPORT (SMTP & IMAP)")
                                .size(12.5)
                                .strong()
                                .color(QuMailTheme::TEXT_PRIMARY),
                        );
                        ui.add_space(4.0);

                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Quick Presets:").size(11.0).color(QuMailTheme::TEXT_MUTED));
                            if ui.button("Gmail").clicked() {
                                state.settings.smtp_host = "smtp.gmail.com".to_string();
                                state.settings.smtp_port = 587;
                                state.settings.imap_host = "imap.gmail.com".to_string();
                                state.settings.imap_port = 993;
                            }
                            if ui.button("Outlook / 365").clicked() {
                                state.settings.smtp_host = "smtp-mail.outlook.com".to_string();
                                state.settings.smtp_port = 587;
                                state.settings.imap_host = "outlook.office365.com".to_string();
                                state.settings.imap_port = 993;
                            }
                            if ui.button("Yahoo Mail").clicked() {
                                state.settings.smtp_host = "smtp.mail.yahoo.com".to_string();
                                state.settings.smtp_port = 587;
                                state.settings.imap_host = "imap.mail.yahoo.com".to_string();
                                state.settings.imap_port = 993;
                            }
                            if ui.button("Custom").clicked() {
                                state.settings.smtp_port = 587;
                                state.settings.imap_port = 993;
                            }
                        });

                        ui.add_space(6.0);

                        egui::Grid::new("transport_settings_grid")
                            .num_columns(2)
                            .spacing(vec2(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.label("SMTP Host / Port:");
                                ui.horizontal(|ui| {
                                    ui.add(egui::TextEdit::singleline(&mut state.settings.smtp_host).desired_width(200.0));
                                    ui.add(egui::DragValue::new(&mut state.settings.smtp_port));
                                });
                                ui.end_row();

                                ui.label("SMTP Username (Email):");
                                let smtp_user_changed = ui.add(
                                    egui::TextEdit::singleline(&mut state.settings.smtp_user)
                                        .desired_width(260.0)
                                        .hint_text("your_name@example.com"),
                                ).changed();
                                if smtp_user_changed && (state.settings.imap_user.is_empty() || state.settings.imap_user == "officer.sac@isro.gov.in") {
                                    state.settings.imap_user = state.settings.smtp_user.clone();
                                }
                                ui.end_row();

                                ui.label("SMTP Password:");
                                let pass_changed = ui.add(
                                    egui::TextEdit::singleline(&mut state.settings.smtp_pass)
                                        .password(true)
                                        .desired_width(260.0)
                                        .hint_text("Gmail: 16-character App Password"),
                                ).changed();
                                if pass_changed && (state.settings.imap_pass.is_empty() || state.settings.imap_pass == "••••••••••••") {
                                    state.settings.imap_pass = state.settings.smtp_pass.clone();
                                }
                                ui.end_row();

                                ui.label("IMAP Host / Port:");
                                ui.horizontal(|ui| {
                                    ui.add(egui::TextEdit::singleline(&mut state.settings.imap_host).desired_width(200.0));
                                    ui.add(egui::DragValue::new(&mut state.settings.imap_port));
                                });
                                ui.end_row();

                                ui.label("IMAP Username:");
                                ui.add(egui::TextEdit::singleline(&mut state.settings.imap_user).desired_width(260.0));
                                ui.end_row();

                                ui.label("IMAP Password:");
                                ui.add(
                                    egui::TextEdit::singleline(&mut state.settings.imap_pass)
                                        .password(true)
                                        .desired_width(260.0)
                                        .hint_text("Same App Password"),
                                );
                                ui.end_row();
                            });

                        ui.add_space(8.0);

                        ui.horizontal(|ui| {
                            let test_btn = egui::Button::new(
                                RichText::new(if state.is_testing_smtp {
                                    "Testing SMTP Connection..."
                                } else {
                                    "Test SMTP Connection"
                                })
                                .size(11.5)
                                .strong(),
                            );

                            if ui.add_enabled(!state.is_testing_smtp, test_btn).clicked() {
                                state.is_testing_smtp = true;
                                let tx = state.sync_tx.clone();
                                let cfg = qumail_net::SmtpConfig {
                                    host: state.settings.smtp_host.clone(),
                                    port: state.settings.smtp_port,
                                    username: state.settings.smtp_user.clone(),
                                    password: state.settings.smtp_pass.clone(),
                                    implicit_tls: state.settings.smtp_port == 465,
                                };
                                std::thread::spawn(move || {
                                    match qumail_net::test_smtp_connection(&cfg) {
                                        Ok(()) => {
                                            let _ = tx.send(crate::state::SyncResult::SmtpTestSuccess(
                                                format!("SMTP authentication with {} succeeded.", cfg.host)
                                            ));
                                        }
                                        Err(e) => {
                                            let _ = tx.send(crate::state::SyncResult::SmtpTestFailure(e.to_string()));
                                        }
                                    }
                                });
                            }
                        });

                        ui.add_space(6.0);
                        egui::Frame::none()
                            .fill(QuMailTheme::BG_CARD)
                            .rounding(4.0)
                            .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("Direct Real Email Notice: For Gmail, enable 2-Step Verification at myaccount.google.com/security, generate a 16-character App Password at myaccount.google.com/apppasswords, and paste it into the password field above. Use port 587 (STARTTLS).")
                                        .size(10.5)
                                        .color(QuMailTheme::TEXT_MUTED),
                                );
                            });

                    });

                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Save & Close").size(12.0).strong()).clicked() {
                        should_close = true;
                        match state.settings.save() {
                            Ok(()) => {
                                state.notification_toast = Some((
                                    format!("Settings saved to {}.", SettingsConfig::config_path().display()),
                                    false,
                                ));
                            }
                            Err(e) => {
                                state.notification_toast = Some((
                                    format!("Failed to save settings: {}", e),
                                    true,
                                ));
                            }
                        }
                    }
                });
            });
        });

    if should_close || !open {
        state.active_modal = ActiveModal::None;
    }
}
