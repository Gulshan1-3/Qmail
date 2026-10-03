//! Cryptographic Envelope Inspector Modal
//!
//! Provides verifiable audit inspection of the underlying `multipart/encrypted`
//! MIME envelope header, Base64 nonces, tags, and ML-KEM-768 lattice ciphertexts.

use crate::state::{ActiveModal, AppState};
use crate::theme::QuMailTheme;
use egui::{vec2, Align2, Context, RichText, ScrollArea, Window};

pub fn render_inspector_modal(ctx: &Context, state: &mut AppState) {
    if state.active_modal != ActiveModal::EnvelopeInspector {
        return;
    }

    let Some(email) = state.selected_email().cloned() else {
        state.active_modal = ActiveModal::None;
        return;
    };

    let Some(header) = email.envelope_header else {
        state.active_modal = ActiveModal::None;
        return;
    };

    let mut open = true;
    let mut should_close = false;

    Window::new("🛡 Cryptographic Envelope Audit Inspector")
        .open(&mut open)
        .collapsible(false)
        .resizable(true)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, 0.0))
        .default_size(vec2(640.0, 480.0))
        .show(ctx, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Subject:").strong().color(QuMailTheme::TEXT_MUTED));
                    ui.label(RichText::new(&email.subject).strong().color(QuMailTheme::TEXT_PRIMARY));
                });

                ui.horizontal(|ui| {
                    ui.label(RichText::new("Protocol:").strong().color(QuMailTheme::TEXT_MUTED));
                    ui.label(
                        RichText::new("multipart/encrypted; protocol=\"application/vnd.qumail.v1\"")
                            .monospace()
                            .size(11.0)
                            .color(QuMailTheme::L2_CYAN_FG),
                    );
                });

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        // Metadata Fields
                        egui::Grid::new("inspector_grid")
                            .num_columns(2)
                            .spacing(vec2(12.0, 6.0))
                            .show(ui, |ui| {
                                ui.label(RichText::new("Envelope Version:").strong());
                                ui.label(format!("v{}", header.version));
                                ui.end_row();

                                ui.label(RichText::new("Security Level:").strong());
                                ui.horizontal(|ui| {
                                    QuMailTheme::render_badge(ui, header.security_level);
                                });
                                ui.end_row();

                                ui.label(RichText::new("Message ID:").strong());
                                ui.label(RichText::new(&header.message_id).monospace());
                                ui.end_row();

                                ui.label(RichText::new("Sender SAE ID:").strong());
                                ui.label(format!("#{} (Master)", header.sender_sae));
                                ui.end_row();

                                ui.label(RichText::new("Recipient SAE ID:").strong());
                                ui.label(format!("#{} (Slave)", header.recipient_sae));
                                ui.end_row();

                                ui.label(RichText::new("Timestamp:").strong());
                                ui.label(format!("Epoch {} secs", header.timestamp_epoch_secs));
                                ui.end_row();

                                ui.label(RichText::new("Allocated Key IDs:").strong());
                                ui.vertical(|ui| {
                                    for kid in &header.key_ids {
                                        ui.label(RichText::new(kid).monospace().color(QuMailTheme::L3_EMERALD_FG));
                                    }
                                });
                                ui.end_row();

                                if let Some(nonce) = &header.nonce_b64 {
                                    ui.label(RichText::new("GCM Nonce (Base64):").strong());
                                    ui.label(RichText::new(nonce).monospace().color(QuMailTheme::L2_CYAN_FG));
                                    ui.end_row();
                                }

                                if let Some(tag) = &header.tag_b64 {
                                    ui.label(RichText::new("Carter-Wegman MAC Tag:").strong());
                                    ui.label(RichText::new(tag).monospace().color(QuMailTheme::L3_EMERALD_FG));
                                    ui.end_row();
                                }

                                if let Some(pqc_ct) = &header.pqc_ciphertext_b64 {
                                    ui.label(RichText::new("ML-KEM-768 Ciphertext:").strong());
                                    ui.label(
                                        RichText::new(if pqc_ct.len() > 60 {
                                            format!("{}... ({} bytes)", &pqc_ct[..60], pqc_ct.len())
                                        } else {
                                            pqc_ct.clone()
                                        })
                                        .monospace()
                                        .color(QuMailTheme::L25_PURPLE_FG),
                                    );
                                    ui.end_row();
                                }
                            });

                        ui.add_space(12.0);
                        ui.separator();
                        ui.add_space(8.0);

                        // Raw JSON Header View
                        ui.label(
                            RichText::new("RAW ENVELOPE JSON HEADER (Part 1 of Multipart):")
                                .size(11.0)
                                .strong()
                                .color(QuMailTheme::TEXT_MUTED),
                        );
                        ui.add_space(4.0);

                        let raw_json = serde_json::to_string_pretty(&header).unwrap_or_default();
                        egui::Frame::none()
                            .fill(QuMailTheme::BG_APP)
                            .rounding(4.0)
                            .inner_margin(egui::Margin::same(8.0))
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new(&raw_json)
                                        .monospace()
                                        .size(11.0)
                                        .color(QuMailTheme::TEXT_SECONDARY),
                                );
                            });
                    });

                ui.add_space(8.0);
                if ui.button(RichText::new("Close Inspector").size(12.0)).clicked() {
                    should_close = true;
                }
            });
        });

    if should_close || !open {
        state.active_modal = ActiveModal::None;
    }
}
