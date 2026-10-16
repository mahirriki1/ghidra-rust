#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui;
use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let argument = std::env::args_os().nth(1);
    if argument.as_deref() == Some(std::ffi::OsStr::new("--analysis-worker")) {
        if let Err(error) = ghidra_rust::worker::run_worker() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let initial_path = argument.map(PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 920.0])
            .with_min_inner_size([1000.0, 640.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Ghidra Rust — Native reverse engineering",
        options,
        Box::new(move |cc| {
            Ok(Box::new(ghidra_rust::app::DesktopApp::new(
                cc,
                initial_path,
            )))
        }),
    )
}
