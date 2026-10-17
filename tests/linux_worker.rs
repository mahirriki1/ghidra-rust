//! Exercise the production bubblewrap path, including the host loader layout.
#![cfg(target_os = "linux")]

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{Request, Response};
use ghidra_rust::project::ProjectData;
use ghidra_rust::session::{Annotation, Session};
use object::{Object, ObjectSymbol};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).expect("send sandboxed worker request");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                return reply.response;
            }
            Some(WorkerEvent::Failed(error)) => panic!("Sandboxed Linux worker failed: {error}"),
            None if Instant::now() >= deadline => {
                panic!("Sandboxed Linux worker response timed out")
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

#[test]
fn sandboxed_linux_worker_and_embedded_project_round_trip() {
    let directory = tempfile::Builder::new()
        .prefix("ghidra rust 日本語 ")
        .tempdir()
        .unwrap();
    let binary = directory.path().join("sample input café");
    let compiled = Command::new("gcc")
        .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("Linux integration tests require GCC");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let original = std::fs::read(&binary).unwrap();
    let image = object::File::parse(original.as_slice()).unwrap();
    let address = image
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("branch_loop"))
        .unwrap()
        .address();
    let context = eframe::egui::Context::default();
    let executable = Path::new(env!("CARGO_BIN_EXE_ghidra-rust"));
    // Never skip or replace this with an unrestricted worker. In particular,
    // the Ubuntu release runner must execute its own ELF loader in bubblewrap.
    let mut worker =
        WorkerClient::start_using_executable(context.clone(), &binary, executable).unwrap();
    let Response::Opened { info } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Sandboxed worker did not open ELF fixture");
    };
    assert_eq!(info.format, "ELF");
    assert_eq!(Path::new(&info.path), binary.canonicalize().unwrap());
    assert_eq!(
        info.sha256,
        ghidra_rust::session::fingerprint(&binary).unwrap()
    );
    let protection = worker.protection().bind_snapshot(&info).unwrap();
    let Response::Graph { view } = request(&mut worker, Request::Graph { address }) else {
        panic!("Sandboxed worker did not return CFG");
    };
    assert!(view.blocks.len() >= 3);
    let Response::Decompiled { text, mappings, .. } =
        request(&mut worker, Request::Decompile { address })
    else {
        panic!("Sandboxed worker did not decompile the fixture");
    };
    assert!(text.contains("branch_loop"));
    assert!(!mappings.is_empty());
    assert!(mappings.iter().all(|mapping| {
        mapping.start < mapping.end
            && text.is_char_boundary(mapping.start)
            && text.is_char_boundary(mapping.end)
            && mapping.addresses.iter().all(|address| {
                view.blocks.iter().any(|block| {
                    block
                        .instructions
                        .iter()
                        .any(|instruction| instruction.address == *address)
                })
            })
    }));
    let mut session = Session::new(info.sha256.clone());
    session.annotations.insert(
        address,
        Annotation {
            label: "saved_function".into(),
            comment: "Linux sandbox project 日本語".into(),
            decoded: vec![],
        },
    );
    let mut project = ProjectData {
        info,
        session,
        view: Some(view),
        decompiled: Some(text),
        mappings,
        strings: vec![],
        strings_truncated: false,
        crypto: vec![],
        crypto_truncated: false,
        selected_address: Some(address),
    };
    assert!(project.save(&binary, &protection, true).is_err());
    let project_path = directory.path().join("analysis 日本語.grproj");
    project.save(&project_path, &protection, true).unwrap();
    project
        .session
        .annotations
        .get_mut(&address)
        .unwrap()
        .comment = "Updated Linux project 日本語".into();
    project.save(&project_path, &protection, true).unwrap();
    let loaded = ProjectData::load(&project_path).unwrap();
    assert!(loaded.cache_compatible);
    assert_eq!(loaded.data.decompiled, project.decompiled);
    assert_eq!(
        serde_json::to_value(&loaded.data.mappings).unwrap(),
        serde_json::to_value(&project.mappings).unwrap()
    );
    assert_eq!(
        loaded.data.session.annotations[&address].comment,
        "Updated Linux project 日本語"
    );
    let embedded = loaded.binary.as_ref().unwrap().clone();
    let extracted = embedded.path().to_owned();
    let mut reopened =
        WorkerClient::start_using_executable(context, &extracted, executable).unwrap();
    reopened.retain_source(Arc::new(embedded));
    let Response::Opened { info: fresh } = request(
        &mut reopened,
        Request::Open {
            path: extracted.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Sandboxed worker did not reopen the embedded input");
    };
    loaded.data.validate_against(&fresh).unwrap();
    assert_ne!(fresh.source_identity, project.info.source_identity);
    drop(loaded);
    assert!(
        extracted.is_file(),
        "Worker must retain the extracted input"
    );
    assert!(matches!(
        request(&mut reopened, Request::Graph { address }),
        Response::Graph { .. }
    ));
    drop(reopened);
    let deadline = Instant::now() + Duration::from_secs(10);
    while extracted.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !extracted.exists(),
        "Extracted input leaked after sandboxed worker shutdown"
    );
    assert_eq!(std::fs::read(&binary).unwrap(), original);
}
