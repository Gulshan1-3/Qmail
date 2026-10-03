//! QuMail Root GUI Application
//!
//! Three-pane desktop client coordinating navigation, message listing,
//! cryptographic verification reading pane, and modal dialogs.

use crate::state::AppState;
use crate::theme::QuMailTheme;
use crate::views::compose_modal::render_compose_modal;
use crate::views::inspector_modal::render_inspector_modal;
use crate::views::message_list::render_message_list_pane;
use crate::views::message_reading::render_message_reading_pane;
use crate::views::navigation::render_navigation_pane;
use crate::views::settings_modal::render_settings_modal;
use eframe::App;
use egui::{CentralPanel, Context, RichText, SidePanel, TopBottomPanel};

pub struct QuMailApp {
    state: AppState,
}

impl QuMailApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Configure custom Outlook dark theme palette
        let mut visuals = egui::Visuals::dark();
        visuals.window_fill = QuMailTheme::BG_CARD;
        visuals.panel_fill = QuMailTheme::BG_APP;
        visuals.faint_bg_color = QuMailTheme::BG_CARD;
        visuals.extreme_bg_color = QuMailTheme::BG_APP;
        visuals.window_stroke = egui::Stroke::new(1.0, QuMailTheme::BORDER);
        cc.egui_ctx.set_visuals(visuals);

        Self {
            state: AppState::new(),
        }
    }
}

impl App for QuMailApp {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        // Drain any background IMAP-sync / SMTP results from worker threads.
        self.state.poll_sync_results();
        // Request a repaint shortly after to pick up any newly posted results.
        ctx.request_repaint_after(std::time::Duration::from_millis(250));

        // Optional top notification toast

        if let Some((msg, is_error)) = &self.state.notification_toast.clone() {
            let bg = if *is_error {
                QuMailTheme::ERROR_BG
            } else {
                QuMailTheme::SUCCESS_BG
            };
            let fg = if *is_error {
                QuMailTheme::ERROR_FG
            } else {
                QuMailTheme::SUCCESS_FG
            };

            TopBottomPanel::top("notification_toast").show(ctx, |ui| {
                egui::Frame::none()
                    .fill(bg)
                    .inner_margin(egui::Margin::symmetric(12.0, 6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(if *is_error { "⚠" } else { "✓" }).size(13.0).color(fg));
                            ui.label(RichText::new(msg).size(12.0).strong().color(fg));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.button(RichText::new("✕").size(11.0).color(fg)).clicked() {
                                    self.state.notification_toast = None;
                                }
                            });
                        });
                    });
            });
        }

        // 1. Left Navigation & Key Bank Telemetry Pane
        SidePanel::left("nav_panel")
            .resizable(true)
            .min_width(200.0)
            .default_width(240.0)
            .max_width(320.0)
            .show(ctx, |ui| {
                render_navigation_pane(ui, &mut self.state);
            });

        // 2. Middle Message List Pane
        SidePanel::left("list_panel")
            .resizable(true)
            .min_width(280.0)
            .default_width(340.0)
            .max_width(480.0)
            .show(ctx, |ui| {
                render_message_list_pane(ui, &mut self.state);
            });

        // 3. Right Message Reading & Verification Pane
        CentralPanel::default().show(ctx, |ui| {
            render_message_reading_pane(ui, &mut self.state);
        });

        // Modals
        render_compose_modal(ctx, &mut self.state);
        render_settings_modal(ctx, &mut self.state);
        render_inspector_modal(ctx, &mut self.state);
    }
}
