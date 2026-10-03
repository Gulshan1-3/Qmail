//! Message List Panel
//!
//! Middle column showing searchable, filtered email cards with unread indicators,
//! attachment flags, and color-coded security badges.

use crate::state::{AppState, SecurityFilter};
use crate::theme::QuMailTheme;
use egui::{vec2, Color32, RichText, ScrollArea, Stroke, Ui};

pub fn render_message_list_pane(ui: &mut Ui, state: &mut AppState) {
    ui.vertical(|ui| {
        ui.add_space(8.0);

        // Header: Folder Title & Sync Action
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(state.active_folder.name())
                    .size(18.0)
                    .strong()
                    .color(QuMailTheme::TEXT_PRIMARY),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(RichText::new("🔄 Sync IMAP").size(11.5).color(QuMailTheme::OUTLOOK_BLUE))
                    .clicked()
                {
                    state.notification_toast = Some(("IMAP mailbox synchronized".to_string(), false));
                }
            });
        });

        ui.add_space(6.0);

        // Search Bar
        ui.horizontal(|ui| {
            ui.label(RichText::new("🔍").size(12.0));
            ui.add(
                egui::TextEdit::singleline(&mut state.search_query)
                    .hint_text("Search messages, senders, subjects...")
                    .desired_width(ui.available_width() - 8.0),
            );
        });

        ui.add_space(8.0);

        // Security Filter Tabs
        ui.horizontal_wrapped(|ui| {
            let filters = [
                SecurityFilter::All,
                SecurityFilter::Baseline,
                SecurityFilter::Qaes,
                SecurityFilter::HybridPqc,
                SecurityFilter::QuantumOtp,
            ];

            for f in filters {
                let is_active = state.security_filter == f;
                let text_color = if is_active {
                    Color32::WHITE
                } else {
                    QuMailTheme::TEXT_SECONDARY
                };
                let bg = if is_active {
                    QuMailTheme::OUTLOOK_BLUE
                } else {
                    QuMailTheme::BG_CARD
                };

                let btn = egui::Button::new(
                    RichText::new(f.label())
                        .size(11.0)
                        .color(text_color)
                        .strong(),
                )
                .fill(bg)
                .rounding(12.0)
                .min_size(vec2(0.0, 22.0));

                if ui.add(btn).clicked() {
                    state.security_filter = f;
                }
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);

        // Scrollable List of Emails
        let filtered_ids: Vec<String> = state
            .filtered_emails()
            .iter()
            .map(|e| e.id.clone())
            .collect();

        if filtered_ids.is_empty() {
            ui.vertical_centered(|ui| {
                ui.add_space(40.0);
                ui.label(RichText::new("📭").size(32.0));
                ui.add_space(8.0);
                ui.label(
                    RichText::new("No messages match current filter")
                        .size(13.0)
                        .color(QuMailTheme::TEXT_MUTED),
                );
            });
            return;
        }

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for id in filtered_ids {
                    let is_selected = state.selected_email_id.as_deref() == Some(&id);

                    // Find email data
                    if let Some(em) = state.emails.iter().find(|e| e.id == id).cloned() {
                        let bg = if is_selected {
                            QuMailTheme::BG_CARD_SELECTED
                        } else {
                            QuMailTheme::BG_CARD
                        };

                        let frame = egui::Frame::none()
                            .fill(bg)
                            .stroke(Stroke::new(
                                if is_selected { 1.5 } else { 1.0 },
                                if is_selected {
                                    QuMailTheme::OUTLOOK_BLUE
                                } else {
                                    QuMailTheme::BORDER
                                },
                            ))
                            .rounding(6.0)
                            .inner_margin(egui::Margin::symmetric(10.0, 8.0));

                        let card_response = frame
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.vertical(|ui| {
                                    // Row 1: Sender & Date + Unread dot
                                    ui.horizontal(|ui| {
                                        if em.is_unread {
                                            ui.label(
                                                RichText::new("●")
                                                    .color(QuMailTheme::OUTLOOK_BLUE)
                                                    .size(10.0),
                                            );
                                        }

                                        ui.label(
                                            RichText::new(&em.from)
                                                .size(12.5)
                                                .strong()
                                                .color(if em.is_unread {
                                                    Color32::WHITE
                                                } else {
                                                    QuMailTheme::TEXT_PRIMARY
                                                }),
                                        );

                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.label(
                                                    RichText::new(&em.date)
                                                        .size(10.5)
                                                        .color(QuMailTheme::TEXT_MUTED),
                                                );
                                            },
                                        );
                                    });

                                    ui.add_space(2.0);

                                    // Row 2: Subject
                                    ui.label(
                                        RichText::new(&em.subject)
                                            .size(12.5)
                                            .strong()
                                            .color(QuMailTheme::TEXT_PRIMARY),
                                    );

                                    ui.add_space(2.0);

                                    // Row 3: Snippet
                                    ui.label(
                                        RichText::new(&em.snippet)
                                            .size(11.0)
                                            .color(QuMailTheme::TEXT_SECONDARY),
                                    );

                                    ui.add_space(4.0);

                                    // Row 4: Security Badge + Attachment Icon
                                    ui.horizontal(|ui| {
                                        QuMailTheme::render_badge(ui, em.security_level);

                                        if !em.attachments.is_empty() {
                                            ui.add_space(6.0);
                                            ui.label(
                                                RichText::new(format!("📎 {}", em.attachments.len()))
                                                    .size(10.5)
                                                    .color(QuMailTheme::TEXT_MUTED),
                                            );
                                        }
                                    });
                                });
                            })
                            .response;

                        let clicked = card_response.interact(egui::Sense::click()).clicked();
                        if clicked {
                            state.selected_email_id = Some(id.clone());
                            // Mark as read when clicked
                            if let Some(mut_em) = state.emails.iter_mut().find(|e| e.id == id) {
                                mut_em.is_unread = false;
                            }
                        }

                        ui.add_space(4.0);
                    }
                }
            });
    });
}
