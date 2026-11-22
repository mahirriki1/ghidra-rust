//! Console-subsystem entry point on every platform, including release Windows.
use ghidra_rust::headless::{self, Analyzer, Error, ErrorCode, Input, Options};
use std::path::PathBuf;

const HELP: &str = "ghidra-rust-headless --binary PATH [--output-project PATH]\n\
  ghidra-rust-headless --project PATH [--binary EXTERNAL_BINARY] [--output-project PATH]\n\n\
Options: --no-debug-info, --use-debug-info, --debug-info PATH\n\
--use-debug-info re-enables debug info for a saved project and clears its per-function skips.\n\
Reads API v1 JSON lines from stdin and writes JSON replies to stdout.\n\
Example: {\"api_version\":1,\"id\":1,\"command\":{\"kind\":\"info\"}}\n\
Project source hints are display-only. External projects need --binary.\n\
See docs/headless.md for commands, worker limits, and host containment.\n";

fn main() -> std::process::ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    if args.peek().is_some_and(|v| v == "--analysis-worker") {
        args.next();
        return ghidra_rust::worker::run_worker_with(args).map_or_else(
            |e| {
                eprintln!("{e}");
                std::process::ExitCode::FAILURE
            },
            |_| std::process::ExitCode::SUCCESS,
        );
    }
    if args.peek().is_some_and(|v| v == "--help" || v == "-h") {
        print!("{HELP}");
        return std::process::ExitCode::SUCCESS;
    }
    if args.peek().is_some_and(|v| v == "--version") {
        println!(
            "ghidra-rust-headless {} (API {})",
            env!("CARGO_PKG_VERSION"),
            headless::API_VERSION
        );
        return std::process::ExitCode::SUCCESS;
    }
    let result = (|| {
        let mut binary = None;
        let mut project = None;
        let mut output = None;
        let mut debug_info = None;
        let mut use_debug_info = None;
        while let Some(arg) = args.next() {
            if arg == "--no-debug-info" || arg == "--use-debug-info" {
                if use_debug_info.is_some() {
                    return Err(invalid("Options may be specified only once"));
                }
                use_debug_info = Some(arg == "--use-debug-info");
                continue;
            }
            let slot = match arg.to_str() {
                Some("--binary") => &mut binary,
                Some("--project") => &mut project,
                Some("--output-project") => &mut output,
                Some("--debug-info") => &mut debug_info,
                _ => return Err(invalid("Unknown option; use --help")),
            };
            if slot.is_some() {
                return Err(invalid("Options may be specified only once"));
            }
            *slot = Some(PathBuf::from(
                args.next()
                    .ok_or_else(|| invalid("Option requires a path"))?,
            ));
        }
        let input = match (project, binary) {
            (Some(path), external_binary) => Input::Project {
                path,
                external_binary,
            },
            (None, Some(path)) => Input::Binary(path),
            (None, None) => return Err(invalid("Select --binary or --project; use --help")),
        };
        let executable = std::env::current_exe().map_err(|e| invalid(&e.to_string()))?;
        Analyzer::open(
            input,
            &executable,
            Options {
                output_project: output,
                use_debug_info,
                debug_info,
                ..Default::default()
            },
        )
    })();
    match result {
        Ok(mut analyzer) => match headless::protocol::serve(
            std::io::stdin().lock(),
            std::io::stdout().lock(),
            &mut analyzer,
        ) {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("{error}");
                std::process::ExitCode::FAILURE
            }
        },
        Err(error) => {
            let _ = headless::protocol::write_error(&mut std::io::stdout().lock(), error);
            std::process::ExitCode::FAILURE
        }
    }
}
fn invalid(message: &str) -> Error {
    Error {
        code: ErrorCode::InvalidRequest,
        message: message.into(),
    }
}
