#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use ghidra_rust::debugger::{Debugger, Error, State, Stop};
use ghidra_rust::headless::{Analyzer, Command as AnalysisCommand, Input, Options, Output};

const GDB: &str = "/usr/bin/gdb";

fn stopped(debugger: &mut Debugger) -> Stop {
    match debugger.wait(Duration::from_secs(5)).unwrap() {
        State::Stopped(stop) => stop.clone(),
        state => panic!("expected a stop, got {state:?}"),
    }
}

fn fixture(flags: &[&str]) -> Option<(tempfile::TempDir, std::path::PathBuf, Analyzer)> {
    if !Path::new(GDB).is_file() {
        eprintln!("Skipping native debugger test: {GDB} is unavailable");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fixture with spaces");
    let compilation = Command::new("gcc")
        .args(["-O0", "-g", "-fPIE", "-pie"])
        .args(flags)
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debugger.c"
        ))
        .arg("-o")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        compilation.status.success(),
        "{}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    let analysis = Analyzer::open(
        Input::Binary(path.clone()),
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless")),
        Options::default(),
    )
    .unwrap();
    Some((dir, path, analysis))
}

#[test]
fn debugger_controls_a_real_pie_and_maps_its_stops_to_the_matching_binary() {
    let Some((_dir, path, mut analysis)) = fixture(&[]) else {
        return;
    };
    let Output::Info { info, .. } = analysis.execute(AnalysisCommand::Info {}).unwrap() else {
        panic!()
    };
    let function = info
        .functions
        .iter()
        .find(|f| f.name == "debug_point")
        .unwrap()
        .address;
    let Output::Function { analysis: code } = analysis
        .execute(AnalysisCommand::Function {
            address: function,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    let first_instruction = code
        .view
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .find(|instruction| instruction.address == function)
        .unwrap();
    let mut wrong_info = info.clone();
    wrong_info.sha256 = "0".repeat(64);
    assert!(matches!(
        Debugger::launch(&path, &wrong_info, Path::new(GDB)),
        Err(Error::Invalid(_))
    ));

    let mut debugger = Debugger::launch(&path, &info, Path::new(GDB)).unwrap();
    assert!(
        stopped(&mut debugger).location.static_address.is_none(),
        "dynamic loader belongs to another image"
    );
    assert!(debugger.insert_breakpoint(u64::MAX).is_err());
    let id = debugger.insert_breakpoint(function).unwrap();
    debugger.resume().unwrap();
    let hit = stopped(&mut debugger);
    assert_eq!(hit.reason, "breakpoint-hit");
    assert_eq!(hit.location.static_address, Some(function));
    assert_ne!(
        hit.location.runtime, function,
        "PIE must have a runtime load bias"
    );
    let registers = debugger.registers().unwrap();
    assert_eq!(
        registers
            .iter()
            .find(|register| register.name == "rip")
            .unwrap()
            .value,
        hit.location.runtime
    );
    let stack = debugger.stack().unwrap();
    assert_eq!(stack[0].location, hit.location);
    assert!(
        stack
            .iter()
            .any(|frame| frame.function.as_deref() == Some("main"))
    );
    assert_eq!(
        debugger
            .read_memory(hit.location.runtime, first_instruction.bytes.len())
            .unwrap(),
        first_instruction.bytes
    );
    assert!(debugger.read_memory(0, 8).is_err());
    debugger.remove_breakpoint(id).unwrap();
    debugger.step_instruction().unwrap();
    let step = stopped(&mut debugger);
    assert_eq!(
        step.location.static_address,
        Some(function + first_instruction.bytes.len() as u64)
    );
    debugger.resume().unwrap();
    debugger.pause().unwrap();
    assert_eq!(stopped(&mut debugger).reason, "signal-received");
    debugger.resume().unwrap();
    assert!(matches!(
        debugger.wait(Duration::from_secs(5)).unwrap(),
        State::Exited { code: Some(19), .. }
    ));
    drop(debugger);

    let mut debugger = Debugger::launch(&path, &info, Path::new(GDB)).unwrap();
    debugger.insert_breakpoint(function).unwrap();
    debugger.resume().unwrap();
    let next = stopped(&mut debugger);
    assert_eq!(next.location.static_address, Some(function));
    assert_ne!(
        hit.location.runtime, next.location.runtime,
        "two PIE launches should have different ASLR addresses"
    );
    // The fixture passes getpid() as the first argument, so rdi identifies
    // the actual stopped process without exposing a public process handle.
    let pid = debugger
        .registers()
        .unwrap()
        .into_iter()
        .find(|r| r.name == "rdi")
        .unwrap()
        .value;
    let process = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    assert_eq!(std::fs::read_link(&process).unwrap(), path);
    drop(debugger);
    assert!(
        !process.exists(),
        "dropping the session must end the stopped target"
    );
}

#[test]
fn debugger_ends_the_session_when_the_target_replaces_its_image() {
    let Some((_dir, path, mut analysis)) = fixture(&["-DDEBUGGER_REEXEC"]) else {
        return;
    };
    let Output::Info { info, .. } = analysis.execute(AnalysisCommand::Info {}).unwrap() else {
        panic!()
    };
    let mut debugger = Debugger::launch(&path, &info, Path::new(GDB)).unwrap();
    debugger.resume().unwrap();
    let error = debugger.wait(Duration::from_secs(5)).unwrap_err();
    assert!(
        error.to_string().contains("replaced its executable"),
        "{error}"
    );
    assert_eq!(debugger.state(), &State::Closed);
}
