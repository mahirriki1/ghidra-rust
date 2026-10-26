//! Optional validation of a trusted large PE through the real desktop worker.
//! Inputs are read only; projects are created under the checkout's ignored target.
#![cfg(any(windows, target_os = "linux"))]

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{MAX_FUNCTIONS, Request, Response};
use ghidra_rust::project::ProjectData;
use ghidra_rust::session::Session;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).expect("send real worker request");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                if let Response::Progress { progress } = &reply.response {
                    progress.validate_after(None).unwrap();
                    continue;
                }
                return reply.response;
            }
            Some(WorkerEvent::Failed(error)) => panic!("Large PE worker failed: {error}"),
            None if Instant::now() >= deadline => panic!("Large PE request exceeded GUI deadline"),
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[test]
#[ignore = "requires a user-selected trusted local PE via GHIDRA_RUST_TEST_LARGE_PE"]
fn large_pe_metadata_analysis_and_project_round_trip() {
    let binary = PathBuf::from(
        std::env::var_os("GHIDRA_RUST_TEST_LARGE_PE").expect("select a trusted local PE"),
    );
    let hash = ghidra_rust::session::fingerprint(&binary).unwrap();
    let started = Instant::now();
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &binary,
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    )
    .expect("start production contained worker");
    let Response::Opened { info, .. } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Cannot open the large PE");
    };
    assert_eq!(info.format, "PE");
    assert_eq!(info.sha256, hash);
    assert!(info.functions.len() > 1 && info.functions.len() <= MAX_FUNCTIONS);
    eprintln!(
        "Opened large PE in {:?}: {} functions, partial={}",
        started.elapsed(),
        info.functions.len(),
        info.functions_truncated
    );
    for note in &info.warnings {
        eprintln!("{note}");
    }
    let address = std::env::var("GHIDRA_RUST_TEST_FUNCTION")
        .ok()
        .map(|text| u64::from_str_radix(text.trim_start_matches("0x"), 16).unwrap())
        .unwrap_or(info.entry);
    let Response::Graph { view } = request(&mut worker, Request::Graph { address }) else {
        panic!("Cannot recover large PE graph");
    };
    assert_eq!(view.address, address);
    assert!(!view.blocks.is_empty());
    let Response::Decompiled { text, mappings, .. } =
        request(&mut worker, Request::Decompile { address })
    else {
        panic!("Cannot decompile large PE function");
    };
    assert!(!text.trim().is_empty());
    assert!(!mappings.is_empty());
    if let Ok(import) = std::env::var("GHIDRA_RUST_TEST_IMPORT") {
        assert!(
            text.contains(&import),
            "Expected imported name {import} in function {address:#x}: {}",
            text.chars().take(2048).collect::<String>()
        );
    }
    eprintln!(
        "Function {address:#x}: {} blocks, {} code bytes, {} mappings",
        view.blocks.len(),
        text.len(),
        mappings.len()
    );
    let Response::Strings { strings, truncated } = request(&mut worker, Request::Strings) else {
        panic!("Cannot scan large PE strings");
    };
    assert!(!strings.is_empty());
    eprintln!("Strings: {}, partial={truncated}", strings.len());
    let protection = worker.protection().bind_snapshot(&info).unwrap();
    let project = ProjectData {
        semantics: Default::default(),
        session: Session::new(hash.clone()),
        info,
        view: Some(view),
        decompiled: Some(text),
        mappings,
        strings,
        strings_truncated: truncated,
        crypto: vec![],
        crypto_truncated: false,
        selected_address: Some(address),
        discovery: None,
    };
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/large-pe-test");
    std::fs::create_dir_all(&output).unwrap();
    let directory = tempfile::tempdir_in(output).unwrap();
    let saved = directory.path().join("analysis.grproj");
    project.save(&saved, &protection, true).unwrap();
    project.save(&saved, &protection, true).unwrap();
    let reopened = ProjectData::load(&saved).unwrap();
    assert!(reopened.cache_compatible);
    assert_eq!(
        reopened.data.info.functions_truncated,
        project.info.functions_truncated
    );
    assert_eq!(reopened.data.decompiled, project.decompiled);
    assert_eq!(ghidra_rust::session::fingerprint(&binary).unwrap(), hash);
}
