//! QuMail Desktop Graphical Client Entry Point
//!
//! Launches the Outlook-grade Quantum-Safe Email Client (ISRO SIH1523 / ETSI GS QKD 014).

mod app;
mod model;
mod state;
mod theme;
mod views;

use app::QuMailApp;
use eframe::NativeOptions;
use egui::vec2;
use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let native_options = NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("QuMail — Quantum-Safe Email Client (ISRO SIH1523)")
            .with_inner_size(vec2(1280.0, 800.0))
            .with_min_inner_size(vec2(960.0, 600.0)),
        ..Default::default()
    };

    eframe::run_native(
        "QuMail",
        native_options,
        Box::new(|cc| Ok(Box::new(QuMailApp::new(cc)))),
    )
}
