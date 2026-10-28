#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use eframe::egui;
use std::path::PathBuf;

fn main() -> std::process::ExitCode {
    let argument = std::env::args_os().nth(1);
    #[cfg(windows)]
    if argument.as_deref() == Some(std::ffi::OsStr::new("--update-helper")) {
        return ghidra_rust::updater::run_helper().map_or_else(
            |error| {
                use std::io::Write;
                if let Ok(message) = serde_json::to_string(&error) {
                    let _ = writeln!(std::io::stdout(), "{message}");
                    let _ = std::io::stdout().flush();
                }
                report_update_error(&error);
                std::process::ExitCode::FAILURE
            },
            |_| std::process::ExitCode::SUCCESS,
        );
    }
    #[cfg(windows)]
    let initial_path = if argument.as_deref() == Some(std::ffi::OsStr::new("--update-cleanup")) {
        match ghidra_rust::updater::run_cleanup() {
            Ok(project) => project,
            Err(error) => {
                eprintln!("Update cleanup skipped: {error}");
                None
            }
        }
    } else {
        argument.clone().map(PathBuf::from)
    };
    #[cfg(not(windows))]
    let initial_path = argument.clone().map(PathBuf::from);
    let worker = argument.as_deref() == Some(std::ffi::OsStr::new("--analysis-worker"));
    if let Err(error) = ghidra_rust::performance::init() {
        if worker {
            eprintln!("{error}");
        } else {
            report_startup_error(&error);
        }
        return std::process::ExitCode::FAILURE;
    }
    let lifetime = ghidra_rust::performance::span("process_lifetime");
    let mut success = if worker {
        ghidra_rust::worker::run_worker().map_err(|error| eprintln!("{error}"))
    } else {
        run_desktop(initial_path).map_err(|error| report_startup_error(&error.to_string()))
    }
    .is_ok();
    lifetime.finish(0);
    if let Err(error) = ghidra_rust::performance::flush() {
        eprintln!("{error}");
        success = false;
    }
    if success {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}

fn run_desktop(initial_path: Option<PathBuf>) -> eframe::Result<()> {
    let size = egui::vec2(1440.0, 920.0);
    let minimum = egui::vec2(1000.0, 640.0);
    let placement = ghidra_rust::window_chrome::initial_placement(size, minimum);
    let mut viewport = egui::ViewportBuilder::default()
        .with_icon(ghidra_rust::brand::icon())
        .with_inner_size(size)
        .with_min_inner_size(minimum);
    if let Some(rect) = placement {
        viewport = viewport
            .with_inner_size(rect.size())
            .with_position(rect.min);
    }
    let options = eframe::NativeOptions {
        viewport: ghidra_rust::window_chrome::configure_viewport(viewport),
        renderer: eframe::Renderer::Glow,
        // eframe centers on the full primary monitor where no work area is known.
        centered: placement.is_none(),
        ..Default::default()
    };
    let restart = ghidra_rust::updater::RestartSlot::default();
    let app_restart = restart.clone();
    eframe::run_native(
        "Ghidra Rust — Native reverse engineering",
        options,
        Box::new(move |cc| {
            Ok(Box::new(
                ghidra_rust::app::DesktopApp::new(cc, initial_path).with_restart(app_restart),
            ))
        }),
    )?;
    if let Some(restart) = restart.take() {
        restart
            .installed
            .restart(restart.project)
            .map_err(|error| eframe::Error::AppCreation(Box::new(std::io::Error::other(error))))?;
    }
    Ok(())
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

#[cfg(windows)]
fn report_update_error(error: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let message: Vec<u16> = error.encode_utf16().chain(Some(0)).collect();
    let title: Vec<u16> = "Ghidra Rust — update\0".encode_utf16().collect();
    // SAFETY: both strings are live NUL-terminated UTF-16 buffers for this call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            message.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}
