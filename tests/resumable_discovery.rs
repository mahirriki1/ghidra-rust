//! Continuation through real contained worker restarts; original generated code.
#[allow(dead_code)]
mod common;
use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::discovery::{Discovery, Status};
use ghidra_rust::model::*;
use std::path::Path;
use std::time::{Duration, Instant};

fn worker(path: &Path) -> WorkerClient {
    WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        path,
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    )
    .unwrap()
}
fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).unwrap();
    let started = Instant::now();
    let mut previous = None;
    loop {
        assert!(started.elapsed() < Duration::from_secs(30));
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                if let Response::Progress { progress } = reply.response {
                    progress.validate_after(previous.as_ref()).unwrap();
                    previous = Some(progress);
                } else {
                    return reply.response;
                }
            }
            Some(WorkerEvent::Failed(error)) => panic!("{error}"),
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}
fn open(worker: &mut WorkerClient, path: &Path) -> BinaryInfo {
    let Response::Opened { info } = request(
        worker,
        Request::Open {
            path: path.to_string_lossy().into_owned(),
        },
    ) else {
        panic!()
    };
    info
}

// Compiles its many-function fixture with GCC.
#[cfg(target_os = "linux")]
#[test]
fn all_known_seeds_survive_cancel_restart_and_interactive_requests() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("many-functions");
    let source = dir.path().join("many-functions.c");
    let mut code = String::from("int f299(void);\nint f000(void) { return f299() + 1; }\n");
    for n in 1..300 {
        code.push_str(&format!("int f{n:03}(void) {{ return {n}; }}\n"));
    }
    code.push_str("int main(void) { return f000(); }\n");
    std::fs::write(&source, code).unwrap();
    assert!(
        std::process::Command::new("gcc")
            .args(["-g", "-O0", "-fno-inline", "-fno-pie", "-no-pie"])
            .arg(&source)
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut worker = worker(&path);
    let info = open(&mut worker, &path);
    assert!(info.functions.len() > 300);
    let mut state = Discovery::new(
        Some(info.entry),
        info.functions.iter().map(|f| f.address),
        false,
    );
    let first = state.begin(1, 1, 0).unwrap();
    assert!(
        serde_json::to_vec(&WorkerRequest {
            id: 2,
            request: first.clone()
        })
        .unwrap()
        .len()
            < 60 * 1024
    );
    let Response::DiscoveryBatch { batch: first } = request(&mut worker, first) else {
        panic!()
    };
    state.commit(&info, &first).unwrap();
    assert!(!state.report.references.is_empty());
    let committed = state.report.references.clone();
    let abandoned = state.begin(1, 1, 0).unwrap();
    worker.send(abandoned).unwrap();
    drop(worker); // Actual cancellation of an in-flight contained worker.
    state.interrupt();
    let mut worker = self::worker(&path);
    let reopened = open(&mut worker, &path);
    assert_eq!(info.sha256, reopened.sha256);
    for functions in first.functions.chunks(MAX_DISCOVERY_SYNC_FUNCTIONS) {
        assert!(matches!(
            request(
                &mut worker,
                Request::SyncFunctions {
                    functions: functions.to_vec()
                }
            ),
            Response::FunctionsSynced
        ));
    }
    assert!(matches!(
        request(
            &mut worker,
            Request::Bytes {
                address: info.entry,
                length: 1
            }
        ),
        Response::Bytes { .. }
    ));
    while let Some(batch) = state.begin(1, 2, 0) {
        let Response::DiscoveryBatch { batch } = request(&mut worker, batch) else {
            panic!()
        };
        state.commit(&info, &batch).unwrap();
    }
    for function in &info.functions {
        assert!(matches!(
            state.status(function.address),
            Some(Status::Done | Status::PartialByOwnLimit | Status::Failed)
        ));
    }
    assert!(state.batches > 2);
    assert_eq!(state.remaining(), 0);
    assert_eq!(state.report.functions_examined, first.functions.len());
    assert!(
        committed
            .iter()
            .all(|reference| state.report.references.contains(reference))
    );
    // Real worker evidence passes the checks applied to saved projects.
    let saved = state.save();
    saved.validate(&info).unwrap();
    assert!(saved.pending.is_empty() && saved.report.references.len() >= committed.len());
}

#[test]
fn confirmed_callees_are_scheduled_in_later_batches_on_stripped_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stripped-arm64");
    let (bytes, base) = common::elf(false);
    std::fs::write(&path, bytes).unwrap();
    let mut worker = worker(&path);
    let info = open(&mut worker, &path);
    let mut state = Discovery::new(
        Some(info.entry),
        info.functions.iter().map(|f| f.address),
        false,
    );
    let Response::DiscoveryBatch { batch: first } =
        request(&mut worker, state.begin(1, 1, 0).unwrap())
    else {
        panic!()
    };
    assert_eq!(first.analysis.functions_examined, 1);
    state.commit(&info, &first).unwrap();
    assert_eq!(state.status(base + 48), Some(Status::Pending));
    let Response::DiscoveryBatch { batch } = request(&mut worker, state.begin(1, 1, 0).unwrap())
    else {
        panic!()
    };
    state.commit(&info, &batch).unwrap();
    assert!(matches!(
        state.status(base + 48),
        Some(Status::Done | Status::PartialByOwnLimit)
    ));
    assert!(
        state
            .report
            .references
            .iter()
            .any(|r| r.target == base + 48)
    );
    state.save().validate(&info).unwrap();
}
