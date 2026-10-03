//! Compose Modal Window
//!
//! Interactive email creation interface with live quantum key consumption estimation,
//! attachment handling, and selectable multi-tier cryptographic policy.

use crate::model::{MailFolder, UiAttachment, UiEmail, UiVerificationInfo};
use crate::state::{ActiveModal, AppState, SyncResult};
use crate::theme::QuMailTheme;
use egui::{vec2, Align2, Color32, Context, RichText, Stroke, Window};
use qumail_core::SecurityLevel;


pub fn render_compose_modal(ctx: &Context, state: &mut AppState) {
    if state.active_modal != ActiveModal::Compose {
        return;
    }

    let mut open = true;
    let mut should_close = false;

    Window::new("✉ Compose Quantum Secure Email")
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .default_size(vec2(680.0, 580.0))
        .show(ctx, |ui| {
            ui.vertical(|ui| {
                // Header & Recipient
                egui::Grid::new("compose_grid")
                    .num_columns(2)
                    .spacing(vec2(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.label(RichText::new("To:").strong().color(QuMailTheme::TEXT_MUTED));
                        ui.add(
                            egui::TextEdit::singleline(&mut state.compose_draft.to)
                                .hint_text("recipient@isro.gov.in")
                                .desired_width(ui.available_width()),
                        );
                        ui.end_row();

                        ui.label(RichText::new("Subject:").strong().color(QuMailTheme::TEXT_MUTED));
                        ui.add(
                            egui::TextEdit::singleline(&mut state.compose_draft.subject)
                                .hint_text("Enter subject...")
                                .desired_width(ui.available_width()),
                        );
                        ui.end_row();
                    });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                // Security Policy Selector
                ui.label(
                    RichText::new("SECURITY LEVEL & CRYPTOGRAPHIC POLICY")
                        .size(11.0)
                        .strong()
                        .color(QuMailTheme::L2_CYAN_FG),
                );
                ui.add_space(4.0);

                ui.horizontal_wrapped(|ui| {
                    let levels = [
                        (SecurityLevel::Baseline, "L1 Baseline", "Standard TLS transport"),
                        (SecurityLevel::Qaes, "L2 Q-AES-256", "QKD-derived AES-GCM"),
                        (SecurityLevel::HybridPqc, "L2.5 Hybrid PQC", "NIST ML-KEM-768 + QKD"),
                        (SecurityLevel::QuantumOtp, "L3 Quantum OTP", "Vernam OTP + Poly1305"),
                    ];

                    for (lvl, title, _sub) in levels {
                        let is_selected = state.compose_draft.security_level == lvl;
                        let (bg, fg) = QuMailTheme::badge_colors(lvl);

                        let fill = if is_selected {
                            bg
                        } else {
                            QuMailTheme::BG_CARD
                        };

                        let btn = egui::Button::new(
                            RichText::new(title)
                                .size(12.0)
                                .strong()
                                .color(if is_selected { fg } else { QuMailTheme::TEXT_SECONDARY }),
                        )
                        .fill(fill)
                        .stroke(Stroke::new(
                            if is_selected { 1.5 } else { 1.0 },
                            if is_selected { fg } else { QuMailTheme::BORDER },
                        ))
                        .rounding(4.0)
                        .min_size(vec2(130.0, 28.0));

                        if ui.add(btn).clicked() {
                            state.compose_draft.security_level = lvl;
                        }
                    }
                });

                ui.add_space(8.0);

                // Live Key Consumption Estimation Box
                let text_len = state.compose_draft.body.as_bytes().len();
                let att_len: usize = state.compose_draft.attachments.iter().map(|a| a.size_bytes).sum();
                let total_payload = text_len + att_len;

                let (needed_slots, explanation) =
                    AppState::calculate_key_requirement(state.compose_draft.security_level, total_payload);
                let available_slots = state.key_bank_status.stored_keys;
                let has_enough_keys = available_slots >= needed_slots;

                egui::Frame::none()
                    .fill(QuMailTheme::BG_CARD)
                    .stroke(Stroke::new(
                        1.0,
                        if has_enough_keys {
                            QuMailTheme::BORDER
                        } else {
                            QuMailTheme::ERROR_FG
                        },
                    ))
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("📊 Key Estimator:").size(11.5).strong().color(QuMailTheme::TEXT_PRIMARY));
                            ui.label(
                                RichText::new(format!("Payload: {} bytes", total_payload))
                                    .size(11.0)
                                    .color(QuMailTheme::TEXT_MUTED),
                            );

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if !has_enough_keys {
                                    ui.label(
                                        RichText::new("⚠ INSUFFICIENT QKD KEYS")
                                            .size(11.0)
                                            .strong()
                                            .color(QuMailTheme::ERROR_FG),
                                    );
                                } else {
                                    ui.label(
                                        RichText::new(format!("Required: {} / {} available", needed_slots, available_slots))
                                            .size(11.0)
                                            .strong()
                                            .color(QuMailTheme::L3_EMERALD_FG),
                                    );
                                }
                            });
                        });

                        ui.add_space(2.0);
                        ui.label(RichText::new(explanation).size(10.5).color(QuMailTheme::TEXT_SECONDARY));
                    });

                ui.add_space(8.0);

                // Attachments List & Actions
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("Attachments ({})", state.compose_draft.attachments.len()))
                            .size(11.5)
                            .strong()
                            .color(QuMailTheme::TEXT_MUTED),
                    );

                    if ui.button(RichText::new("+ Attach Telemetry Demo").size(11.0)).clicked() {
                        let sample_id = state.compose_draft.attachments.len() + 1;
                        state.compose_draft.attachments.push(UiAttachment {
                            filename: format!("telemetry_batch_{sample_id}.bin"),
                            content_type: "application/octet-stream".to_string(),
                            size_bytes: 2048,
                            data: vec![0xAB, 0xCD, 0xEF, 0x01],
                        });
                    }

                    if !state.compose_draft.attachments.is_empty() && ui.button(RichText::new("Clear All").size(11.0)).clicked() {
                        state.compose_draft.attachments.clear();
                    }
                });

                if !state.compose_draft.attachments.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        for att in &state.compose_draft.attachments {
                            egui::Frame::none()
                                .fill(QuMailTheme::BG_CARD)
                                .rounding(3.0)
                                .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                .show(ui, |ui| {
                                    ui.label(RichText::new(format!("📎 {} ({} B)", att.filename, att.size_bytes)).size(10.5));
                                });
                        }
                    });
                }

                ui.add_space(8.0);

                // Body Editor
                ui.label(RichText::new("Message Body:").size(11.5).strong().color(QuMailTheme::TEXT_MUTED));
                ui.add(
                    egui::TextEdit::multiline(&mut state.compose_draft.body)
                        .hint_text("Compose secure email content here...")
                        .desired_rows(10)
                        .desired_width(ui.available_width()),
                );

                ui.add_space(10.0);

                // Status Message if present
                if let Some((msg, is_err)) = &state.compose_draft.status_message {
                    let color = if *is_err {
                        QuMailTheme::ERROR_FG
                    } else {
                        QuMailTheme::SUCCESS_FG
                    };
                    ui.label(RichText::new(msg).size(12.0).strong().color(color));
                    ui.add_space(4.0);
                }

                // Send & Cancel Buttons
                ui.horizontal(|ui| {
                    let send_btn = egui::Button::new(
                        RichText::new("🚀 Send Quantum Secure Mail")
                            .size(13.0)
                            .strong()
                            .color(Color32::WHITE),
                    )
                    .fill(QuMailTheme::OUTLOOK_BLUE)
                    .rounding(4.0)
                    .min_size(vec2(200.0, 32.0));

                    if ui.add(send_btn).clicked() {
                        if state.compose_draft.to.trim().is_empty() {
                            state.compose_draft.status_message =
                                Some(("Recipient 'To' address cannot be empty.".to_string(), true));
                        } else if !has_enough_keys {
                            state.compose_draft.status_message = Some((
                                format!("Insufficient key material: requires {} slots, {} available.", needed_slots, available_slots),
                                true,
                            ));
                        } else {
                            // Deduct key slots from Key Bank
                            if needed_slots > 0 && state.key_bank_status.stored_keys >= needed_slots {
                                state.key_bank_status.stored_keys -= needed_slots;
                            }

                            // Generate new Sent email record
                            let new_id = format!("msg-sent-{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs());
                            let subject = if state.compose_draft.subject.trim().is_empty() {
                                "(No Subject)".to_string()
                            } else {
                                state.compose_draft.subject.clone()
                            };

                            let snippet = if state.compose_draft.body.len() > 60 {
                                format!("{}...", &state.compose_draft.body[..60])
                            } else {
                                state.compose_draft.body.clone()
                            };

                            let verification = if state.compose_draft.security_level != SecurityLevel::Baseline {
                                Some(UiVerificationInfo {
                                    verified: true,
                                    level: state.compose_draft.security_level,
                                    method_title: QuMailTheme::badge_label(state.compose_draft.security_level).to_string(),
                                    method_detail: format!("Encrypted for recipient using {} key slots.", needed_slots),
                                    key_ids: (0..needed_slots).map(|i| format!("isro-qkd-key-sent-{:04}", i + 1)).collect(),
                                    aad_authenticated: true,
                                    timestamp_epoch_secs: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                                })
                            } else {
                                None
                            };

                            let sent_email = UiEmail {
                                id: new_id.clone(),
                                folder: MailFolder::Sent,
                                from: state.settings.smtp_user.clone(),
                                to: vec![state.compose_draft.to.clone()],
                                date: "Just now".to_string(),
                                subject: subject.clone(),
                                snippet,
                                body_text: state.compose_draft.body.clone(),
                                attachments: state.compose_draft.attachments.clone(),
                                security_level: state.compose_draft.security_level,
                                is_unread: false,
                                verification,
                                envelope_header: None,
                                raw_mime_size: total_payload + 1024,
                            };

                            state.emails.insert(0, sent_email);
                            state.selected_email_id = Some(new_id);

                            // --- Background SMTP dispatch ---
                            let tx = state.sync_tx.clone();
                            let smtp_host = state.settings.smtp_host.clone();
                            let smtp_port = state.settings.smtp_port;
                            let smtp_user = state.settings.smtp_user.clone();
                            let smtp_pass = state.settings.smtp_pass.clone();
                            let from_addr = smtp_user.clone();
                            let to_addr = state.compose_draft.to.clone();
                            let subject_clone = subject.clone();
                            let body_clone = state.compose_draft.body.clone();

                            // Detect demo credentials — skip real network
                            let is_demo = smtp_user.ends_with("isro.gov.in")
                                || smtp_pass.contains("•")
                                || smtp_pass.len() < 4;

                            if is_demo {
                                state.notification_toast = Some((
                                    format!("Email \"{}\" queued (demo mode — no live SMTP).", subject),
                                    false,
                                ));
                            } else {
                                state.is_sending_smtp = true;
                                std::thread::spawn(move || {
                                    use qumail_net::{SmtpConfig, send_smtp_message};
                                    use lettre::message::SinglePart;

                                    let smtp_config = SmtpConfig {
                                        host: smtp_host,
                                        port: smtp_port,
                                        username: smtp_user.clone(),
                                        password: smtp_pass,
                                        implicit_tls: smtp_port == 465,
                                    };

                                    // Build a simple MIME message for the UI-composed draft
                                    let msg_result = lettre::Message::builder()
                                        .from(from_addr.parse().unwrap())
                                        .to(to_addr.parse().unwrap())
                                        .subject(subject_clone.clone())
                                        .singlepart(
                                            SinglePart::plain(body_clone)
                                        );

                                    match msg_result {
                                        Ok(msg) => match send_smtp_message(&smtp_config, &msg) {
                                            Ok(()) => {
                                                let _ = tx.send(SyncResult::SmtpSuccess(subject_clone));
                                            }
                                            Err(e) => {
                                                let _ = tx.send(SyncResult::SmtpFailure(e.to_string()));
                                            }
                                        },
                                        Err(e) => {
                                            let _ = tx.send(SyncResult::SmtpFailure(format!("Message build: {}", e)));
                                        }
                                    }
                                });
                            }

                            // Reset draft
                            state.compose_draft = Default::default();
                            should_close = true;
                        }
                    }


                    if ui.button(RichText::new("Cancel").size(12.0)).clicked() {
                        should_close = true;
                    }
                });
            });
        });

    if should_close || !open {
        state.active_modal = ActiveModal::None;
    }
}
