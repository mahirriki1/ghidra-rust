//! Disposable process fixture: exercise production updater entry points without
//! a renderer or error dialog, so failures can be asserted by integration tests.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::io::Read;
    let result = match std::env::args().nth(1).as_deref() {
        Some("--parent") => std::io::stdin()
            .read_to_end(&mut Vec::new())
            .map(|_| ())
            .map_err(|error| error.to_string()),
        Some("--update-helper") => ghidra_rust::updater::run_helper(),
        Some("--update-cleanup") => ghidra_rust::updater::run_cleanup().and_then(|project| {
            let path = std::env::var_os("GHIDRA_RUST_TEST_UPDATER_RESULT")
                .ok_or("Missing test result path")?;
            std::fs::write(
                path,
                serde_json::to_vec(&project).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())
        }),
        _ => Err("Unknown updater fixture mode".into()),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The updater process fixture requires native Windows.");
}
