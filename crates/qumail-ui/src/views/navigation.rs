//! Navigation & Quantum Key Bank Health Panel
//!
//! Classic Outlook left sidebar containing folder tree, quick compose action,
//! and live telemetry gauge for the ETSI GS QKD 014 / ISRO Symmetrical Key Bank.

use crate::model::MailFolder;
use crate::state::{ActiveModal, AppState, SyncResult};
use crate::theme::QuMailTheme;
use egui::{vec2, Color32, ProgressBar, RichText, Stroke, Ui};


pub fn render_navigation_pane(ui: &mut Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        // App Header / Brand
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            ui.label(
                RichText::new("⚡ QuMail")
                    .size(20.0)
                    .strong()
                    .color(QuMailTheme::OUTLOOK_BLUE),
            );
            ui.label(
                RichText::new("SECURE")
                    .size(10.0)
                    .strong()
                    .color(QuMailTheme::L3_EMERALD_FG),
            );
        });

        ui.horizontal(|ui| {
            ui.add_space(8.0);
            ui.label(
                RichText::new("ISRO QKD-Assisted Email Client")
                    .size(10.5)
                    .color(QuMailTheme::TEXT_MUTED),
            );
        });

        ui.add_space(14.0);

        // Compose Button (Prominent Outlook style)
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            let compose_btn = egui::Button::new(
                RichText::new("✏  New Quantum Mail")
                    .size(13.5)
                    .strong()
                    .color(Color32::WHITE),
            )
            .fill(QuMailTheme::OUTLOOK_BLUE)
            .rounding(4.0)
            .min_size(vec2(ui.available_width() - 16.0, 34.0));

            if ui.add(compose_btn).clicked() {
                state.active_modal = ActiveModal::Compose;
            }
        });

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);

        // Folders Section
        ui.label(
            RichText::new("  FOLDERS")
                .size(10.5)
                .strong()
                .color(QuMailTheme::TEXT_MUTED),
        );
        ui.add_space(4.0);

        let folders = [
            MailFolder::Inbox,
            MailFolder::Sent,
            MailFolder::Drafts,
            MailFolder::Trash,
        ];

        for folder in folders {
            let is_selected = state.active_folder == folder;
            let unread = state.unread_count(folder);

            let bg_color = if is_selected {
                QuMailTheme::BG_CARD_SELECTED
            } else {
                Color32::TRANSPARENT
            };

            egui::Frame::none()
                .fill(bg_color)
                .rounding(4.0)
                .inner_margin(egui::Margin::symmetric(10.0, 6.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(folder.icon()).size(14.0));
                        ui.add_space(4.0);

                        let text_color = if is_selected {
                            Color32::WHITE
                        } else {
                            QuMailTheme::TEXT_PRIMARY
                        };

                        let folder_label = ui.add(
                            egui::Label::new(
                                RichText::new(folder.name())
                                    .size(13.0)
                                    .color(text_color)
                                    .strong(),
                            )
                            .sense(egui::Sense::click()),
                        );

                        if folder_label.clicked() {
                            state.active_folder = folder;
                        }

                        if unread > 0 {
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                egui::Frame::none()
                                    .fill(QuMailTheme::OUTLOOK_BLUE)
                                    .rounding(10.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 1.0))
                                    .show(ui, |ui| {
                                        ui.label(
                                            RichText::new(format!("{unread}"))
                                                .size(10.5)
                                                .strong()
                                                .color(Color32::WHITE),
                                        );
                                    });
                            });
                        }
                    });
                });
        }

        ui.add_space(16.0);
        ui.separator();
        ui.add_space(8.0);

        // Quantum Key Bank Telemetry Gauge
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            ui.label(
                RichText::new("QUANTUM KEY GAUGE")
                    .size(10.5)
                    .strong()
                    .color(QuMailTheme::L2_CYAN_FG),
            );
        });

        ui.add_space(4.0);

        egui::Frame::none()
            .fill(QuMailTheme::BG_CARD)
            .stroke(Stroke::new(1.0, QuMailTheme::BORDER))
            .rounding(6.0)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                ui.set_width(ui.available_width() - 8.0);

                let stored = state.key_bank_status.stored_keys;
                let max = state.key_bank_status.max_keys;
                let ratio = if max > 0 {
                    stored as f32 / max as f32
                } else {
                    0.0
                };

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Symmetric Key Bank:")
                            .size(11.0)
                            .color(QuMailTheme::TEXT_MUTED),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{stored}/{max}"))
                                .size(11.5)
                                .strong()
                                .color(if stored > 20 {
                                    QuMailTheme::L3_EMERALD_FG
                                } else {
                                    QuMailTheme::WARNING_FG
                                }),
                        );
                    });
                });

                ui.add_space(4.0);
                ui.add(
                    ProgressBar::new(ratio)
                        .show_percentage()
                        .animate(false)
                        .fill(if stored > 20 {
                            QuMailTheme::OUTLOOK_BLUE
                        } else {
                            QuMailTheme::WARNING_FG
                        }),
                );

                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Slot Size:")
                            .size(10.5)
                            .color(QuMailTheme::TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{} bits (1024 B)", state.key_bank_status.key_size_bits))
                            .size(10.5)
                            .color(QuMailTheme::TEXT_PRIMARY),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Capacity:")
                            .size(10.5)
                            .color(QuMailTheme::TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{:.1} KB available", (stored * 1024) as f32 / 1024.0))
                            .size(10.5)
                            .color(QuMailTheme::TEXT_PRIMARY),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Link SAE:")
                            .size(10.5)
                            .color(QuMailTheme::TEXT_MUTED),
                    );
                    ui.label(
                        RichText::new(format!("{} ⇄ {}", state.key_bank_status.master_sae, state.key_bank_status.slave_sae))
                            .size(10.5)
                            .strong()
                            .color(QuMailTheme::L2_CYAN_FG),
                    );
                });

                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let dot_color = if state.key_bank_status.is_healthy {
                        QuMailTheme::SUCCESS_FG
                    } else {
                        QuMailTheme::ERROR_FG
                    };
                    ui.label(RichText::new("●").color(dot_color).size(11.0));
                    ui.label(
                        RichText::new(if state.key_bank_status.is_healthy {
                            "KME SYNCHRONIZED"
                        } else {
                            "OFFLINE / DEPLETED"
                        })
                        .size(10.0)
                        .strong()
                        .color(dot_color),
                    );
                });
            });

        ui.add_space(12.0);

        // Sync Inbox Button — dispatches a background IMAP poll
        ui.horizontal(|ui| {
            ui.add_space(8.0);

            let sync_label = if state.is_syncing {
                "⏳ Syncing…"
            } else {
                "🔄 Sync Inbox"
            };

            let sync_btn = egui::Button::new(
                RichText::new(sync_label)
                    .size(12.0)
                    .color(if state.is_syncing {
                        QuMailTheme::TEXT_MUTED
                    } else {
                        Color32::WHITE
                    }),
            )
            .fill(if state.is_syncing {
                QuMailTheme::BG_CARD
            } else {
                QuMailTheme::OUTLOOK_BLUE
            })
            .rounding(4.0)
            .min_size(vec2(ui.available_width() - 16.0, 28.0));

            if ui.add_enabled(!state.is_syncing, sync_btn).clicked() {
                // Clone everything the background thread needs
                let tx = state.sync_tx.clone();
                let imap_host = state.settings.imap_host.clone();
                let imap_port = state.settings.imap_port;
                let imap_user = state.settings.imap_user.clone();
                let imap_pass = state.settings.imap_pass.clone();

                // Detect demo/placeholder credentials — don't hit real servers
                let is_demo = imap_user.ends_with("isro.gov.in")
                    || imap_pass.contains("•")
                    || imap_pass.len() < 4;

                state.is_syncing = true;

                if is_demo {
                    // Simulate a sync so the UI flow is exercisable
                    std::thread::spawn(move || {
                        std::thread::sleep(std::time::Duration::from_millis(800));
                        let _ = tx.send(SyncResult::Success(
                            "Inbox sync complete (demo mode — 0 new messages).".to_string(),
                        ));
                    });
                } else {
                    // Dispatch real IMAP fetch in a background thread with its own tokio runtime
                    std::thread::spawn(move || {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .expect("tokio rt");

                        let result = rt.block_on(async move {
                            use qumail_kme::QkdSimulator;
                            use qumail_crypto::QuMailCryptoEngine;
                            use qumail_net::{ImapConfig, fetch_imap_messages};

                            let sim = QkdSimulator::new();
                            let crypto = QuMailCryptoEngine::new();
                            let cfg = ImapConfig {
                                host: imap_host,
                                port: imap_port,
                                username: imap_user,
                                password: imap_pass,
                                mailbox: "INBOX".to_string(),
                            };
                            fetch_imap_messages(&cfg, 20, &sim, &crypto).await
                        });

                        match result {
                            Ok(msgs) => {
                                let _ = tx.send(SyncResult::Success(format!(
                                    "Inbox synced — {} message(s) fetched.",
                                    msgs.len()
                                )));
                            }
                            Err(e) => {
                                let _ = tx.send(SyncResult::Failure(e.to_string()));
                            }
                        }
                    });
                }
            }
        });

        ui.add_space(12.0);

        // Push settings and account footer to bottom

        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            ui.add_space(10.0);
            ui.separator();
            ui.add_space(6.0);

            // Settings Action
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                if ui
                    .button(RichText::new("⚙ Settings & Keys").size(12.0).color(QuMailTheme::TEXT_SECONDARY))
                    .clicked()
                {
                    state.active_modal = ActiveModal::Settings;
                }
            });

            ui.add_space(4.0);

            // User Identity
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("👤").size(14.0));
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(&state.settings.smtp_user)
                            .size(11.5)
                            .strong()
                            .color(QuMailTheme::TEXT_PRIMARY),
                    );
                    ui.label(
                        RichText::new(format!("SAE Node: #{}", state.settings.sender_sae))
                            .size(10.0)
                            .color(QuMailTheme::TEXT_MUTED),
                    );
                });
            });
        });
    });
}
