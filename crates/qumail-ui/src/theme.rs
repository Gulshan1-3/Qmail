//! QuMail Visual Theme & Styling
//!
//! Enterprise Outlook-grade aesthetic with quantum security visual cues.

#![allow(dead_code)]

use egui::{Color32, Stroke};
use qumail_core::SecurityLevel;

pub struct QuMailTheme;

impl QuMailTheme {
    // Brand & Base Colors
    pub const OUTLOOK_BLUE: Color32 = Color32::from_rgb(0, 120, 212);
    pub const OUTLOOK_HOVER: Color32 = Color32::from_rgb(16, 110, 190);
    pub const OUTLOOK_NAVY: Color32 = Color32::from_rgb(0, 69, 120);

    // Dark Surface Colors
    pub const BG_APP: Color32 = Color32::from_rgb(26, 28, 30);
    pub const BG_NAV: Color32 = Color32::from_rgb(32, 34, 38);
    pub const BG_CARD: Color32 = Color32::from_rgb(38, 41, 46);
    pub const BG_CARD_HOVER: Color32 = Color32::from_rgb(48, 52, 58);
    pub const BG_CARD_SELECTED: Color32 = Color32::from_rgb(45, 55, 72);
    pub const BORDER: Color32 = Color32::from_rgb(52, 56, 64);

    // Text Colors
    pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(240, 243, 246);
    pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(160, 166, 178);
    pub const TEXT_MUTED: Color32 = Color32::from_rgb(115, 120, 132);

    // Security Level Colors
    pub const L1_GRAY_BG: Color32 = Color32::from_rgb(50, 54, 60);
    pub const L1_GRAY_FG: Color32 = Color32::from_rgb(180, 185, 195);

    pub const L2_CYAN_BG: Color32 = Color32::from_rgb(12, 60, 96);
    pub const L2_CYAN_FG: Color32 = Color32::from_rgb(100, 181, 246);

    pub const L25_PURPLE_BG: Color32 = Color32::from_rgb(68, 28, 88);
    pub const L25_PURPLE_FG: Color32 = Color32::from_rgb(206, 147, 216);

    pub const L3_EMERALD_BG: Color32 = Color32::from_rgb(18, 68, 48);
    pub const L3_EMERALD_FG: Color32 = Color32::from_rgb(129, 199, 132);

    // Alerts
    pub const SUCCESS_BG: Color32 = Color32::from_rgb(20, 60, 36);
    pub const SUCCESS_FG: Color32 = Color32::from_rgb(102, 187, 106);

    pub const ERROR_BG: Color32 = Color32::from_rgb(80, 24, 24);
    pub const ERROR_FG: Color32 = Color32::from_rgb(239, 83, 80);

    pub const WARNING_BG: Color32 = Color32::from_rgb(74, 52, 14);
    pub const WARNING_FG: Color32 = Color32::from_rgb(255, 183, 77);

    /// Returns the badge background and foreground colors for a given security level.
    pub fn badge_colors(level: SecurityLevel) -> (Color32, Color32) {
        match level {
            SecurityLevel::Baseline => (Self::L1_GRAY_BG, Self::L1_GRAY_FG),
            SecurityLevel::Qaes => (Self::L2_CYAN_BG, Self::L2_CYAN_FG),
            SecurityLevel::HybridPqc => (Self::L25_PURPLE_BG, Self::L25_PURPLE_FG),
            SecurityLevel::QuantumOtp => (Self::L3_EMERALD_BG, Self::L3_EMERALD_FG),
        }
    }

    /// Returns human-readable label with badge tag
    pub fn badge_label(level: SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Baseline => "L1 Baseline",
            SecurityLevel::Qaes => "L2 Q-AES-256",
            SecurityLevel::HybridPqc => "L2.5 Hybrid PQC",
            SecurityLevel::QuantumOtp => "L3 Quantum OTP",
        }
    }

    /// Renders a security level pill badge in the current egui UI
    pub fn render_badge(ui: &mut egui::Ui, level: SecurityLevel) {
        let (bg, fg) = Self::badge_colors(level);
        let label = Self::badge_label(level);

        egui::Frame::none()
            .fill(bg)
            .stroke(Stroke::new(1.0, fg.linear_multiply(0.4)))
            .rounding(4.0)
            .inner_margin(egui::Margin::symmetric(6.0, 2.0))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(label)
                        .color(fg)
                        .size(10.5)
                        .strong(),
                );
            });
    }
}
