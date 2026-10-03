//! Message Reading & Cryptographic Verification Pane
//!
//! Right column rendering decrypted email content, attachments, and the
//! prominent Quantum Security Verification Banner with Key ID audit trail.

use crate::state::{ActiveModal, AppState};
use crate::theme::QuMailTheme;
use egui::{Color32, RichText, ScrollArea, Stroke, Ui};
use std::fs;

pub fn render_message_reading_pane(ui: &mut Ui, state: &mut AppState) {
    let Some(email) = state.selected_email().cloned() else {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(RichText::new("✉").size(48.0).color(QuMailTheme::TEXT_MUTED));
            ui.add_space(12.0);
            ui.label(
                RichText::new("Select a message to view content and cryptographic verification")
                    .size(14.0)
                    .color(QuMailTheme::TEXT_MUTED),
            );
        });
        return;
    };

    ui.vertical(|ui| {
        ui.add_space(8.0);

        // Action Toolbar
        ui.horizontal(|ui| {
            if ui
                .button(RichText::new("↩ Reply").size(12.0).color(QuMailTheme::TEXT_PRIMARY))
                .clicked()
            {
                state.compose_draft.to = email.from.clone();
                state.compose_draft.subject = format!("Re: {}", email.subject);
                state.compose_draft.security_level = email.security_level;
                state.compose_draft.body = format!("\n\n--- Original Message ---\n{}", email.body_text);
                state.active_modal = ActiveModal::Compose;
            }

            if ui
                .button(RichText::new("↪ Forward").size(12.0).color(QuMailTheme::TEXT_PRIMARY))
                .clicked()
            {
                state.compose_draft.to.clear();
                state.compose_draft.subject = format!("Fwd: {}", email.subject);
                state.compose_draft.security_level = email.security_level;
                state.compose_draft.body = format!("\n\n--- Forwarded Message ---\n{}", email.body_text);
                state.active_modal = ActiveModal::Compose;
            }

            ui.separator();

            if ui
                .button(RichText::new("🗑 Delete").size(12.0).color(QuMailTheme::ERROR_FG))
                .clicked()
            {
                let id_to_remove = email.id.clone();
                state.emails.retain(|e| e.id != id_to_remove);
                state.selected_email_id = state.emails.first().map(|e| e.id.clone());
                return;
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if email.envelope_header.is_some() {
                    let inspect_btn = egui::Button::new(
                        RichText::new("🛡 Inspect Crypto Envelope")
                            .size(11.5)
                            .strong()
                            .color(QuMailTheme::L2_CYAN_FG),
                    )
                    .stroke(Stroke::new(1.0, QuMailTheme::L2_CYAN_FG))
                    .fill(QuMailTheme::BG_CARD);

                    if ui.add(inspect_btn).clicked() {
                        state.active_modal = ActiveModal::EnvelopeInspector;
                    }
                }
            });
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(8.0);

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // Subject Line
                ui.label(
                    RichText::new(&email.subject)
                        .size(20.0)
                        .strong()
                        .color(QuMailTheme::TEXT_PRIMARY),
                );

                ui.add_space(8.0);

                // Metadata Box (From, To, Date)
                egui::Frame::none()
                    .fill(QuMailTheme::BG_CARD)
                    .rounding(4.0)
                    .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("From:").size(12.0).color(QuMailTheme::TEXT_MUTED));
                            ui.label(RichText::new(&email.from).size(12.5).strong().color(Color32::WHITE));

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new(&email.date).size(11.5).color(QuMailTheme::TEXT_MUTED));
                            });
                        });

                        ui.add_space(2.0);

                        ui.horizontal(|ui| {
                            ui.label(RichText::new("To:").size(12.0).color(QuMailTheme::TEXT_MUTED));
                            ui.label(RichText::new(email.to.join(", ")).size(12.0).color(QuMailTheme::TEXT_SECONDARY));

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(
                                    RichText::new(format!("Payload Size: {} bytes", email.raw_mime_size))
                                        .size(10.5)
                                        .color(QuMailTheme::TEXT_MUTED),
                                );
                            });
                        });
                    });

                ui.add_space(10.0);

                // Quantum Security Verification Banner
                if let Some(v) = &email.verification {
                    let (bg, fg) = QuMailTheme::badge_colors(v.level);

                    egui::Frame::none()
                        .fill(bg)
                        .stroke(Stroke::new(1.0, fg.linear_multiply(0.5)))
                        .rounding(6.0)
                        .inner_margin(egui::Margin::same(12.0))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("🛡").size(20.0));
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(format!("✓ Quantum Cryptographic Guarantee: {}", v.method_title))
                                            .size(13.0)
                                            .strong()
                                            .color(Color32::WHITE),
                                    );
                                    ui.label(
                                        RichText::new(&v.method_detail)
                                            .size(11.5)
                                            .color(fg),
                                    );

                                    if !v.key_ids.is_empty() {
                                        ui.add_space(4.0);
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                RichText::new("Consumed QKD Key IDs:")
                                                    .size(10.5)
                                                    .strong()
                                                    .color(Color32::WHITE),
                                            );
                                            for kid in &v.key_ids {
                                                egui::Frame::none()
                                                    .fill(QuMailTheme::BG_APP)
                                                    .rounding(3.0)
                                                    .inner_margin(egui::Margin::symmetric(4.0, 1.0))
                                                    .show(ui, |ui| {
                                                        ui.label(
                                                            RichText::new(kid)
                                                                .size(9.5)
                                                                .monospace()
                                                                .color(fg),
                                                        );
                                                    });
                                            }
                                        });
                                    }
                                });
                            });
                        });

                    ui.add_space(10.0);
                }

                // Attachments Strip
                if !email.attachments.is_empty() {
                    ui.label(
                        RichText::new(format!("ATTACHMENTS ({})", email.attachments.len()))
                            .size(11.0)
                            .strong()
                            .color(QuMailTheme::TEXT_MUTED),
                    );
                    ui.add_space(4.0);

                    ui.horizontal_wrapped(|ui| {
                        for att in &email.attachments {
                            egui::Frame::none()
                                .fill(QuMailTheme::BG_CARD)
                                .stroke(Stroke::new(1.0, QuMailTheme::BORDER))
                                .rounding(4.0)
                                .inner_margin(egui::Margin::symmetric(8.0, 6.0))
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new("📎").size(13.0));
                                        ui.vertical(|ui| {
                                            ui.label(
                                                RichText::new(&att.filename)
                                                    .size(12.0)
                                                    .strong()
                                                    .color(QuMailTheme::TEXT_PRIMARY),
                                            );
                                            ui.label(
                                                RichText::new(format!("{:.1} KB", att.size_bytes as f32 / 1024.0))
                                                    .size(10.0)
                                                    .color(QuMailTheme::TEXT_MUTED),
                                            );
                                        });

                                        ui.add_space(4.0);
                                        if ui.button(RichText::new("Save").size(10.5)).clicked() {
                                            let save_path = std::env::temp_dir().join(&att.filename);
                                            if let Err(e) = fs::write(&save_path, &att.data) {
                                                state.notification_toast = Some((format!("Failed to save: {e}"), true));
                                            } else {
                                                state.notification_toast = Some((
                                                    format!("Saved to {}", save_path.display()),
                                                    false,
                                                ));
                                            }
                                        }
                                    });
                                });
                        }
                    });

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(8.0);
                }

                // Message Body
                ui.label(
                    RichText::new(&email.body_text)
                        .size(13.5)
                        .color(QuMailTheme::TEXT_PRIMARY)
                        .line_height(Some(20.0)),
                );
            });
    });
}
