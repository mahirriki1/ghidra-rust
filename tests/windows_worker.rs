//! Real Windows worker through the production suspended-spawn and job path.
#![cfg(windows)]

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{FileIdentity, Request, Response};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).expect("send worker request");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                return reply.response;
            }
            Some(WorkerEvent::Failed(error)) => panic!("Windows worker failed: {error}"),
            None if Instant::now() >= deadline => panic!("Windows worker response timed out"),
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[test]
fn real_windows_worker_opens_graphs_decompiles_and_protects_the_input() {
    let binary = match std::env::var_os("GHIDRA_RUST_TEST_PE") {
        Some(path) => PathBuf::from(path),
        None => {
            assert!(
                std::env::var_os("CI").is_none(),
                "Windows CI must compile and set GHIDRA_RUST_TEST_PE"
            );
            eprintln!(
                "Set GHIDRA_RUST_TEST_PE to a compiled tests/fixtures/sample.c PE to run this test"
            );
            return;
        }
    };
    assert!(
        binary.is_file(),
        "Windows PE fixture is missing: {}",
        binary.display()
    );
    let context = eframe::egui::Context::default();
    let executable = Path::new(env!("CARGO_BIN_EXE_ghidra-rust"));
    let mut worker = WorkerClient::start_using_executable(context, &binary, executable)
        .expect("start production Windows worker in a resource-limited job");
    let Response::Opened { info } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Windows worker did not open PE fixture");
    };
    assert_eq!(info.format, "PE");
    assert_eq!(
        info.sha256,
        ghidra_rust::session::fingerprint(&binary).unwrap()
    );
    assert_eq!(
        info.source_identity,
        FileIdentity::from_file(&std::fs::File::open(&binary).unwrap())
    );
    let protection = worker.protection().bind_snapshot(&info).unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&binary)
            .is_err(),
        "Retained input handle must deny concurrent writers"
    );
    let address = info
        .functions
        .iter()
        .find(|function| function.name == "branch_loop")
        .or_else(|| {
            info.functions
                .iter()
                .find(|function| function.name == "main")
        })
        .map_or(info.entry, |function| function.address);
    let Response::Graph { view } = request(&mut worker, Request::Graph { address }) else {
        panic!("Windows worker did not return a CFG");
    };
    assert_eq!(view.address, address);
    assert!(!view.blocks.is_empty());
    let Response::Decompiled {
        address: decompiled_address,
        text,
        mappings,
    } = request(&mut worker, Request::Decompile { address })
    else {
        panic!("Windows worker did not return decompiled code");
    };
    assert_eq!(decompiled_address, address);
    assert!(!text.trim().is_empty());
    assert!(
        !mappings.is_empty(),
        "PE decompilation must return semantic instruction locations"
    );
    let Response::Strings { strings, .. } = request(&mut worker, Request::Strings) else {
        panic!("Windows worker did not return strings");
    };
    assert!(
        strings
            .iter()
            .any(|entry| entry.text.contains("aGVsbG8gcmV2ZXJzZXI="))
    );
    drop(worker);
    drop(protection);
}
