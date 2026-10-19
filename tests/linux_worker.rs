//! Exercise the production bubblewrap path, including the host loader layout.
#![cfg(target_os = "linux")]

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{CallAnalysis, Request, Response};
use ghidra_rust::project::ProjectData;
use ghidra_rust::session::{Annotation, Session};
use object::{Object, ObjectSymbol};
use std::collections::BTreeSet;
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
                if let Response::Progress { progress } = &reply.response {
                    progress.validate_after(None).unwrap();
                    continue;
                }
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

// Differential check on our original linked C fixture only. GNU objdump is an
// independent decoder; compare real call instruction PCs and destinations,
// without treating disassembly text as semantic GUI mappings.
fn compare_fixture_calls(binary: &Path, image: &object::File<'_>, analysis: &CallAnalysis) {
    for name in ["main", "branch_loop", "decode_xor"] {
        let caller = image
            .symbols()
            .find(|symbol| symbol.name().ok() == Some(name))
            .unwrap()
            .address();
        let output = Command::new("objdump")
            .arg("--no-show-raw-insn")
            .arg(format!("--disassemble={name}"))
            .arg(binary)
            .output()
            .expect("Linux differential tests require GNU objdump (binutils)");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(
            text.contains(&format!("<{name}>:")),
            "Missing objdump function {name}"
        );
        let expected: BTreeSet<_> = text
            .lines()
            .filter_map(|line| {
                let (pc, instruction) = line.trim().split_once(':')?;
                let pc = u64::from_str_radix(pc, 16).ok()?;
                let mut fields = instruction.split_whitespace();
                if !matches!(fields.next()?, "call" | "callq" | "bl") {
                    return None;
                }
                let destination = fields.next()?;
                if destination.starts_with('*') {
                    return None;
                }
                Some((
                    pc,
                    u64::from_str_radix(destination, 16).expect("Direct objdump call target"),
                ))
            })
            .collect();
        let actual: BTreeSet<_> = analysis
            .references
            .iter()
            .filter(|reference| reference.caller == caller)
            .map(|reference| (reference.address, reference.target))
            .collect();
        assert_eq!(
            actual, expected,
            "Confirmed calls differ from GNU objdump in {name}"
        );
        if name == "main" {
            assert!(!expected.is_empty());
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
    let Response::Functions {
        functions,
        analysis,
        ..
    } = request(&mut worker, Request::Discover)
    else {
        panic!("Sandboxed worker did not analyze calls");
    };
    analysis.validate(&info, &functions).unwrap();
    compare_fixture_calls(&binary, &image, &analysis);
    assert!(
        analysis
            .references
            .iter()
            .any(|reference| reference.target == address)
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
