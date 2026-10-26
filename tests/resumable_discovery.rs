//! Continuation through real contained worker restarts; original generated code.
#[allow(dead_code)]
mod common;
mod inventory;
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
    let Response::Opened { info, .. } = request(
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
    // Each returns a string literal's address: address-taking evidence.
    for n in 0..30 {
        code.push_str(&format!(
            "const char *s{n:02}(void) {{ return \"label {n:02}\"; }}\n"
        ));
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
    let mut inventory = inventory::Inventory::default();
    let first = inventory.bind(first);
    let Response::DiscoveryBatch { batch: mut reply } = request(&mut worker, first.clone()) else {
        panic!()
    };
    inventory
        .commit(&mut state, &info, &first, &mut reply)
        .unwrap();
    let first_functions = inventory.functions().to_vec();
    assert!(!state.report.references.is_empty());
    let committed = state.report.references.clone();
    let committed_addresses = state.report.addresses.clone().unwrap();
    let abandoned = state.begin(1, 1, 0).unwrap();
    worker.send(abandoned).unwrap();
    drop(worker); // Actual cancellation of an in-flight contained worker.
    state.interrupt();
    let mut worker = self::worker(&path);
    let reopened = open(&mut worker, &path);
    assert_eq!(info.sha256, reopened.sha256);
    for functions in ghidra_rust::model::sync_chunks(&first_functions) {
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
    let mut unchanged = 0;
    while let Some(batch) = state.begin(1, 2, 0) {
        let batch = inventory.bind(batch);
        let Response::DiscoveryBatch { batch: mut reply } = request(&mut worker, batch.clone())
        else {
            panic!()
        };
        unchanged += usize::from(
            !inventory
                .commit(&mut state, &info, &batch, &mut reply)
                .unwrap(),
        );
    }
    for function in &info.functions {
        assert!(matches!(
            state.status(function.address),
            Some(Status::Done | Status::PartialByOwnLimit | Status::Failed)
        ));
    }
    assert!(state.batches > 2);
    assert_eq!(state.remaining(), 0);
    assert_eq!(state.report.functions_examined, first_functions.len());
    // The replacement worker's first reply carries its inventory; replays
    // that leave it unchanged then send no rows.
    assert!(unchanged > 0 && unchanged < state.batches);
    assert!(
        committed
            .iter()
            .all(|reference| state.report.references.contains(reference))
    );
    // Address evidence accumulates across batches and the worker restart,
    // once for each string-returning function, and never admits functions.
    let addresses = state.report.addresses.as_ref().unwrap();
    assert!(
        committed_addresses
            .references
            .iter()
            .all(|reference| addresses.references.contains(reference))
    );
    assert!(addresses.candidates_examined >= committed_addresses.candidates_examined);
    let owners: std::collections::BTreeSet<_> = info
        .functions
        .iter()
        .filter(|function| function.name.starts_with('s') && function.name.len() == 3)
        .map(|function| function.address)
        .collect();
    assert_eq!(owners.len(), 30);
    let taken: std::collections::BTreeSet<_> = addresses
        .references
        .iter()
        .filter(|reference| owners.contains(&reference.function))
        .map(|reference| (reference.function, reference.target))
        .collect();
    assert_eq!(taken.len(), 30);
    assert!(
        taken
            .iter()
            .all(|&(_, target)| state.status(target).is_none())
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
    let mut inventory = inventory::Inventory::default();
    let first = inventory.bind(state.begin(1, 1, 0).unwrap());
    let Response::DiscoveryBatch { batch: mut reply } = request(&mut worker, first.clone()) else {
        panic!()
    };
    assert_eq!(reply.analysis.functions_examined, 1);
    inventory
        .commit(&mut state, &info, &first, &mut reply)
        .unwrap();
    assert_eq!(state.status(base + 48), Some(Status::Pending));
    let second = inventory.bind(state.begin(1, 1, 0).unwrap());
    let Response::DiscoveryBatch { batch: mut reply } = request(&mut worker, second.clone()) else {
        panic!()
    };
    inventory
        .commit(&mut state, &info, &second, &mut reply)
        .unwrap();
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
