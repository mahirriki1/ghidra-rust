#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ghidra_rust::debugger::controller::{
    BreakpointStatus, Command as DebugCommand, Controller, Event, Launch, Snapshot, StepKind,
};
use ghidra_rust::debugger::{Debugger, Error, State, Stop};
use ghidra_rust::headless::{Analyzer, Command as AnalysisCommand, Input, Options, Output};
use ghidra_rust::model::BinaryInfo;

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
    assert!(
        matches!(debugger.insert_breakpoint(function), Err(Error::Invalid(message)) if message == "Breakpoint already set")
    );
    assert_eq!(
        debugger.breakpoint_ids().collect::<Vec<_>>(),
        [(function, id)],
        "a duplicate static address must not add a second GDB breakpoint"
    );
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
    let paused = stopped(&mut debugger);
    assert_eq!(paused.reason, "signal-received");
    assert_eq!(paused.signal.as_deref(), Some("SIGINT"));
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

fn analysed(flags: &[&str]) -> Option<(tempfile::TempDir, PathBuf, BinaryInfo, u64)> {
    let (dir, path, mut analysis) = fixture(flags)?;
    let Output::Info { info, .. } = analysis.execute(AnalysisCommand::Info {}).unwrap() else {
        panic!()
    };
    let debug_point = info
        .functions
        .iter()
        .find(|f| f.name == "debug_point")
        .unwrap()
        .address;
    Some((dir, path, *info, debug_point))
}

fn start(path: &Path, info: &BinaryInfo, breakpoints: &[u64], run: bool) -> Controller {
    let mut launch = Launch::new(path.to_owned(), info.clone(), Arc::new(|| ()));
    launch.breakpoints = (1, breakpoints.iter().copied().collect());
    launch.run = run;
    Controller::launch(launch).unwrap()
}

fn next(controller: &Controller) -> Event {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(event) = controller.try_recv() {
            return event;
        }
        assert!(Instant::now() < deadline, "no debugger event arrived");
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn next_stop(controller: &Controller) -> Snapshot {
    loop {
        match next(controller) {
            Event::Stopped(snapshot) => return *snapshot,
            Event::Running | Event::Breakpoints { .. } => (),
            event => panic!("expected a stop, got {event:?}"),
        }
    }
}

fn register(snapshot: &Snapshot, name: &str) -> u64 {
    snapshot
        .registers
        .as_ref()
        .unwrap()
        .iter()
        .find(|register| register.name == name)
        .unwrap()
        .value
}

fn assert_ended(controller: &Controller, error: Option<&str>) {
    loop {
        match next(controller) {
            Event::Ended { error: ended } => {
                match (ended.as_deref(), error) {
                    (None, None) => (),
                    (Some(message), Some(expected)) if message.contains(expected) => (),
                    (ended, _) => panic!("unexpected end {ended:?}, expected {error:?}"),
                }
                return;
            }
            Event::Running | Event::Breakpoints { .. } | Event::Stopped(_) => (),
            event => panic!("expected the session to end, got {event:?}"),
        }
    }
}

#[test]
fn controller_runs_to_a_breakpoint_and_reports_one_consistent_snapshot() {
    let Some((_dir, path, info, debug_point)) = analysed(&[]) else {
        return;
    };
    let controller = start(&path, &info, &[debug_point], true);
    let Event::Breakpoints { revision, status } = next(&controller) else {
        panic!("the initial breakpoints apply before the loader stop")
    };
    assert_eq!(revision, 1);
    assert_eq!(
        status.into_iter().collect::<Vec<_>>(),
        [(debug_point, BreakpointStatus::Set)]
    );
    let loader = next_stop(&controller);
    assert_eq!(loader.stop_seq, 1);
    assert_eq!(
        next(&controller),
        Event::Running,
        "run resumes the loader stop"
    );
    let hit = next_stop(&controller);
    assert_eq!(hit.stop_seq, 2);
    assert_eq!(hit.stop.reason, "breakpoint-hit");
    assert_eq!(hit.stop.location.static_address, Some(debug_point));
    assert_eq!(register(&hit, "rip"), hit.stop.location.runtime);
    let registers = hit.registers.as_ref().unwrap();
    assert_eq!(registers.len(), hit.register_locations.len());
    let rip = registers.iter().position(|r| r.name == "rip").unwrap();
    assert_eq!(hit.register_locations[rip], hit.stop.location);
    let frames = hit.frames.as_ref().unwrap();
    assert_eq!(frames[0].location, hit.stop.location);
    assert!(
        frames
            .iter()
            .any(|frame| frame.function.as_deref() == Some("main"))
    );
    assert!(controller.shutdown(Duration::from_secs(5)));
}

#[test]
fn controller_pauses_a_sleeping_target_and_stop_kills_it() {
    let Some((_dir, path, info, debug_point)) = analysed(&[]) else {
        return;
    };
    let controller = start(&path, &info, &[debug_point], true);
    let hit = next_stop(&controller);
    let hit = if hit.stop_seq == 1 {
        next_stop(&controller)
    } else {
        hit
    };
    assert_eq!(hit.stop.location.static_address, Some(debug_point));
    // The fixture passes getpid() as the first argument.
    let process = PathBuf::from(format!("/proc/{}/exe", register(&hit, "rdi")));
    assert_eq!(std::fs::read_link(&process).unwrap(), path);
    assert!(controller.send(DebugCommand::Pause));
    assert!(
        matches!(next(&controller), Event::Refused { .. }),
        "a stopped target cannot pause"
    );
    controller.send(DebugCommand::Breakpoints {
        revision: 2,
        addresses: BTreeSet::new(),
    });
    assert!(matches!(
        next(&controller),
        Event::Breakpoints { revision: 2, status } if status.is_empty()
    ));
    controller.send(DebugCommand::Resume);
    assert_eq!(next(&controller), Event::Running);
    controller.send(DebugCommand::Pause);
    let paused = next_stop(&controller);
    assert_eq!(paused.stop.reason, "signal-received");
    assert_eq!(paused.stop.signal.as_deref(), Some("SIGINT"));
    assert_eq!(paused.stop_seq, hit.stop_seq + 1);
    controller.send(DebugCommand::Stop);
    assert_ended(&controller, None);
    assert!(!process.exists(), "Ended follows the end of the target");
}

#[test]
fn controller_applies_breakpoints_changed_while_running_at_the_next_stop() {
    let Some((_dir, path, info, debug_point)) = analysed(&[]) else {
        return;
    };
    let controller = start(&path, &info, &[debug_point], true);
    while next_stop(&controller).stop.location.static_address != Some(debug_point) {}
    controller.send(DebugCommand::Resume);
    assert_eq!(next(&controller), Event::Running);
    // The target is now inside sleep(1), before the second debug_point call.
    controller.send(DebugCommand::Breakpoints {
        revision: 7,
        addresses: BTreeSet::new(),
    });
    controller.send(DebugCommand::Pause);
    assert!(
        matches!(next(&controller), Event::Breakpoints { revision: 7, status } if status.is_empty()),
        "pending breakpoints apply before the next stop's snapshot"
    );
    let paused = next_stop(&controller);
    assert_eq!(paused.stop.signal.as_deref(), Some("SIGINT"));
    controller.send(DebugCommand::Resume);
    assert_eq!(next(&controller), Event::Running);
    assert_eq!(
        next(&controller),
        Event::Exited {
            code: Some(19),
            signal: None
        },
        "the removed breakpoint must not stop the second call"
    );
    assert_ended(&controller, None);
}

#[test]
fn controller_reports_exit_code_and_ends() {
    let Some((_dir, path, info, _)) = analysed(&[]) else {
        return;
    };
    let controller = start(&path, &info, &[], true);
    assert_eq!(next_stop(&controller).stop_seq, 1);
    assert_eq!(next(&controller), Event::Running);
    assert_eq!(
        next(&controller),
        Event::Exited {
            code: Some(19),
            signal: None
        }
    );
    assert_eq!(next(&controller), Event::Ended { error: None });
    assert!(
        !controller.send(DebugCommand::Resume),
        "the thread has ended"
    );
}

#[test]
fn controller_rejects_stale_memory_reads() {
    let Some((_dir, path, info, debug_point)) = analysed(&[]) else {
        return;
    };
    let controller = start(&path, &info, &[], false);
    let loader = next_stop(&controller);
    controller.send(DebugCommand::Breakpoints {
        revision: 2,
        addresses: [debug_point].into(),
    });
    assert!(matches!(
        next(&controller),
        Event::Breakpoints { revision: 2, .. }
    ));
    controller.send(DebugCommand::Step(StepKind::Instruction));
    assert_eq!(next(&controller), Event::Running);
    let step = next_stop(&controller);
    assert_eq!(step.stop_seq, loader.stop_seq + 1);
    let rip = step.stop.location.runtime;
    controller.send(DebugCommand::ReadMemory {
        token: 1,
        stop: loader.stop_seq,
        runtime: rip,
        length: 1,
    });
    let Event::Memory {
        token: 1, result, ..
    } = next(&controller)
    else {
        panic!("expected a memory reply")
    };
    assert_eq!(result, Err("stale".into()));
    controller.send(DebugCommand::ReadMemory {
        token: 2,
        stop: step.stop_seq,
        runtime: rip,
        length: 16,
    });
    let Event::Memory {
        token: 2,
        stop_seq,
        runtime,
        result,
    } = next(&controller)
    else {
        panic!("expected a memory reply")
    };
    assert_eq!((stop_seq, runtime), (step.stop_seq, rip));
    assert_eq!(result.unwrap().len(), 16);
    controller.send(DebugCommand::Resume);
    assert_eq!(next(&controller), Event::Running);
    let hit = next_stop(&controller);
    assert_eq!(hit.stop.location.static_address, Some(debug_point));
    assert!(controller.shutdown(Duration::from_secs(5)));
}

#[test]
fn controller_reports_missing_gdb() {
    let Some((_dir, path, info, _)) = analysed(&[]) else {
        return;
    };
    let missing = Path::new("/nonexistent/ghidra-rust-test/gdb");
    let Err(error) = Debugger::launch(&path, &info, missing) else {
        panic!("a missing GDB cannot launch")
    };
    assert!(matches!(error, Error::Unavailable(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "GDB is required at /nonexistent/ghidra-rust-test/gdb"
    );
    let mut launch = Launch::new(path, info, Arc::new(|| ()));
    launch.gdb = missing.to_owned();
    let controller = Controller::launch(launch).unwrap();
    assert_ended(&controller, Some("GDB is required"));
}

#[test]
fn controller_ends_with_an_error_when_the_target_execs() {
    let Some((_dir, path, info, _)) = analysed(&["-DDEBUGGER_REEXEC"]) else {
        return;
    };
    let controller = start(&path, &info, &[], true);
    assert_ended(&controller, Some("replaced its executable"));
}
