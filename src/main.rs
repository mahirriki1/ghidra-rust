#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui;
use std::path::PathBuf;

fn main() -> std::process::ExitCode {
    let argument = std::env::args_os().nth(1);
    if argument.as_deref() == Some(std::ffi::OsStr::new("--analysis-worker")) {
        if let Err(error) = ghidra_rust::worker::run_worker() {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return std::process::ExitCode::SUCCESS;
    }
    let initial_path = argument.map(PathBuf::from);
    if let Err(error) = run_desktop(initial_path) {
        report_startup_error(&error.to_string());
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

fn run_desktop(initial_path: Option<PathBuf>) -> eframe::Result<()> {
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

fn report_startup_error(error: &str) {
    eprintln!("Cannot start Ghidra Rust: {error}");
    // Release builds have no console. Surface renderer/window startup failures
    // in a native dialog, including when the EXE is launched from Explorer.
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let message: Vec<u16> = format!(
            "Cannot start Ghidra Rust.\n\n{error}\n\nThe desktop requires an OpenGL-capable graphics driver. If graphics initialization failed, update the GPU driver and try a local desktop session."
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let title: Vec<u16> = "Ghidra Rust — startup error\0".encode_utf16().collect();
        // SAFETY: both strings are live NUL-terminated UTF-16 buffers. The
        // ownerless modal dialog is shown only after the event loop has failed.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            )
        };
    }
}
