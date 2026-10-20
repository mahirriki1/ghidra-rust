//! Native workers analyze original AArch64 bytes; they never execute the input.
#![cfg(any(target_os = "linux", windows))]
mod common;

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{
    BinaryInfo, CodeMapping, DataProvenance, EdgeKind, FunctionView, Request, Response,
};
use ghidra_rust::project::ProjectData;
use ghidra_rust::session::{Annotation, Session};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).unwrap();
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
            Some(WorkerEvent::Failed(error)) => panic!("Contained worker failed: {error}"),
            None if Instant::now() >= deadline => panic!("Contained worker timed out"),
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn graph(worker: &mut WorkerClient, address: u64) -> FunctionView {
    match request(worker, Request::Graph { address }) {
        Response::Graph { view } => view,
        other => panic!("Expected CFG at {address:#x}, got {other:?}"),
    }
}

#[test]
fn contained_data_accesses_use_literal_reads_and_block_local_propagation() {
    let source = include_str!("fixtures/aarch64-data.S");
    let words: Vec<_> = source
        .lines()
        .filter_map(|line| line.trim().strip_prefix(".inst 0x"))
        .flat_map(|value| {
            u32::from_str_radix(value.split_whitespace().next().unwrap(), 16)
                .unwrap()
                .to_le_bytes()
        })
        .collect();
    let literal = source
        .lines()
        .find_map(|line| line.trim().strip_prefix(".quad 0x"))
        .map(|value| {
            u64::from_str_radix(value.split_whitespace().next().unwrap(), 16)
                .unwrap()
                .to_le_bytes()
        })
        .unwrap();
    for (format, (mut bytes, base), code_offset) in [
        ("ELF", common::elf(true), 0x100),
        ("PE", common::pe(), 0x200),
        ("Mach-O", common::macho(), 0x1000),
    ] {
        bytes[code_offset..code_offset + words.len()].copy_from_slice(&words);
        bytes[code_offset + 32..code_offset + 40].copy_from_slice(&literal);
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("original literal fixture");
        std::fs::write(&binary, &bytes).unwrap();
        let mut worker = WorkerClient::start_using_executable(
            eframe::egui::Context::default(),
            &binary,
            Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
        )
        .unwrap();
        let Response::Opened { info } = request(
            &mut worker,
            Request::Open {
                path: binary.to_string_lossy().into_owned(),
            },
        ) else {
            panic!("Open {format}");
        };
        let (functions, analysis) = match request(&mut worker, Request::Discover) {
            Response::Functions {
                functions,
                analysis,
                ..
            } => (functions, analysis),
            other => panic!("Discover {format}: {other:?}"),
        };
        analysis.validate(&info, &functions).unwrap();
        let data = analysis.data.unwrap();
        let read = |address, provenance| ghidra_rust::model::DataReference {
            function: base,
            address,
            target: base + 32,
            size: 8,
            access: ghidra_rust::model::DataAccess::Read,
            provenance,
        };
        let fixture: Vec<_> = data
            .references
            .iter()
            .filter(|reference| reference.function == base)
            .cloned()
            .collect();
        assert_eq!(
            fixture,
            [
                read(base, DataProvenance::InstructionLocal),
                read(base + 16, DataProvenance::Propagated),
            ],
            "{format}"
        );
        // The load after the call stays unresolved.
        assert!(data.unresolved_accesses >= 1);
        assert!(
            !functions
                .iter()
                .any(|function| function.address == base + 32)
        );
        let Response::Bytes {
            address,
            bytes: read,
        } = request(
            &mut worker,
            Request::Bytes {
                address: base + 32,
                length: 8,
            },
        )
        else {
            panic!("Read {format} literal bytes");
        };
        assert_eq!(address, base + 32);
        assert_eq!(read, literal);
        assert_eq!(std::fs::read(&binary).unwrap(), bytes);
    }
}

fn decompile(
    worker: &mut WorkerClient,
    address: u64,
    info: &BinaryInfo,
    view: &FunctionView,
) -> (String, Vec<CodeMapping>) {
    let Response::Decompiled {
        address: returned,
        text,
        mappings,
    } = request(worker, Request::Decompile { address })
    else {
        panic!("Expected real decompilation at {address:#x}");
    };
    assert_eq!(returned, address);
    assert!(text.contains("return"), "{text}");
    assert!(
        !mappings.is_empty(),
        "Missing semantic engine locations: {text}"
    );
    ghidra_rust::selection::validate_mappings(&text, &mappings, &info.sections).unwrap();
    let pcs: BTreeSet<_> = view
        .blocks
        .iter()
        .flat_map(|b| &b.instructions)
        .map(|i| i.address)
        .collect();
    assert!(
        mappings
            .iter()
            .flat_map(|m| &m.addresses)
            .all(|pc| pcs.contains(pc))
    );
    (text, mappings)
}

#[test]
fn contained_aarch64_workers_analyze_elf_pe_macho_and_reopen_projects() {
    for (format, (bytes, base)) in [
        ("ELF", common::elf(true)),
        ("PE", common::pe()),
        ("Mach-O", common::macho()),
    ] {
        let directory = tempfile::Builder::new()
            .prefix("aarch64 fixture 日本語 ")
            .tempdir()
            .unwrap();
        let binary = directory.path().join("original input");
        std::fs::write(&binary, &bytes).unwrap();
        let context = eframe::egui::Context::default();
        let executable = Path::new(env!("CARGO_BIN_EXE_ghidra-rust"));
        let mut worker =
            WorkerClient::start_using_executable(context.clone(), &binary, executable).unwrap();
        let response = request(
            &mut worker,
            Request::Open {
                path: binary.to_string_lossy().into_owned(),
            },
        );
        let Response::Opened { info } = response else {
            panic!("Open {format}: {response:?}");
        };
        assert_eq!(info.architecture, "AArch64");
        assert_eq!(info.format, format);
        assert_eq!(info.entry, base);
        assert_eq!(
            info.sha256,
            ghidra_rust::session::fingerprint(&binary).unwrap()
        );
        for (symbol, offset) in common::SYMBOLS {
            assert!(
                info.functions
                    .iter()
                    .any(|f| f.address == base + offset && f.name.ends_with(symbol)),
                "{format}: missing {symbol}: {:?}",
                info.functions
            );
        }
        let Response::Functions {
            functions,
            analysis,
            ..
        } = request(&mut worker, Request::Discover)
        else {
            panic!("Expected symbol-bearing discovery");
        };
        analysis.validate(&info, &functions).unwrap();
        assert!(
            analysis
                .references
                .iter()
                .any(|reference| reference.address == base + 8 && reference.target == base + 48)
        );
        assert_eq!(analysis.unresolved_calls, 1);
        assert!(analysis.partial);
        let protection = worker.protection().bind_snapshot(&info).unwrap();
        let entry = graph(&mut worker, base);
        let pcs: BTreeSet<_> = entry
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .map(|i| {
                assert_eq!(i.bytes.len(), 4);
                assert_eq!(i.address % 4, 0);
                assert!(!i.mnemonic.is_empty());
                i.address
            })
            .collect();
        assert_eq!(
            pcs,
            [0, 4, 8, 12, 16, 20, 24, 32, 36].map(|o| base + o).into()
        );
        assert_eq!(entry.calls.len(), 1);
        assert_eq!(entry.calls[0].address, base + 8);
        assert_eq!(entry.calls[0].target, Some(base + 48));
        assert!(
            entry
                .edges
                .iter()
                .any(|e| e.kind == EdgeKind::True && e.target == Some(base + 32))
        );
        assert!(
            entry
                .edges
                .iter()
                .any(|e| e.kind == EdgeKind::False && e.target == Some(base + 20))
        );
        let (entry_text, _) = decompile(&mut worker, base, &info, &entry);
        assert!(entry_text.contains("fixture_sum"), "{format}: {entry_text}");
        let sum = graph(&mut worker, base + 48);
        assert!(
            sum.edges
                .iter()
                .any(|e| e.target == Some(base + 56) && e.source == base + 56),
            "Loop backedge: {:?}",
            sum.edges
        );
        let (text, mappings) = decompile(&mut worker, base + 48, &info, &sum);
        let indirect = graph(&mut worker, base + 76);
        assert_eq!(indirect.blocks[0].instructions.len(), 1);
        assert!(
            indirect
                .edges
                .iter()
                .any(|e| e.kind == EdgeKind::Unknown && e.target.is_none())
        );
        let indirect_call = graph(&mut worker, base + 80);
        assert_eq!(indirect_call.calls.len(), 1);
        assert_eq!(indirect_call.calls[0].target, None);
        assert_eq!(indirect_call.blocks[0].instructions.len(), 2);
        for address in [base + 1, base + 2, base + 3, base - 4] {
            for req in [Request::Graph { address }, Request::Decompile { address }] {
                assert!(matches!(request(&mut worker, req), Response::Error { .. }));
            }
        }
        assert!(matches!(
            request(
                &mut worker,
                Request::Rename {
                    address: base + 48,
                    name: "renamed_sum".into()
                }
            ),
            Response::Renamed { .. }
        ));
        let (renamed, _) = decompile(&mut worker, base + 48, &info, &sum);
        assert!(renamed.contains("renamed_sum"));
        // Keep the original result and annotations, then verify portable project
        // identity, exact mappings, and extracted input ownership through reaping.
        let mut session = Session::new(info.sha256.clone());
        session.annotations.insert(
            base + 48,
            Annotation {
                label: "renamed_sum".into(),
                comment: "AArch64 project round trip".into(),
                decoded: vec![],
            },
        );
        let project = ProjectData {
            info,
            session,
            view: Some(sum),
            decompiled: Some(text),
            mappings,
            strings: vec![],
            strings_truncated: false,
            crypto: vec![],
            crypto_truncated: false,
            selected_address: Some(base + 48),
            discovery: None,
        };
        assert!(project.save(&binary, &protection, true).is_err());
        let path = directory.path().join("analysis.grproj");
        project.save(&path, &protection, true).unwrap();
        let loaded = ProjectData::load(&path).unwrap();
        assert!(loaded.cache_compatible);
        assert_eq!(loaded.data.decompiled, project.decompiled);
        assert_eq!(
            serde_json::to_value(&loaded.data.mappings).unwrap(),
            serde_json::to_value(&project.mappings).unwrap()
        );
        assert_eq!(
            loaded.data.session.annotations[&(base + 48)].comment,
            "AArch64 project round trip"
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
            panic!("Reopen {format}");
        };
        loaded.data.validate_against(&fresh).unwrap();
        drop(loaded);
        assert!(extracted.is_file());
        let reopened_sum = graph(&mut reopened, base + 48);
        decompile(&mut reopened, base + 48, &fresh, &reopened_sum);
        drop(reopened);
        let deadline = Instant::now() + Duration::from_secs(10);
        while extracted.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !extracted.exists(),
            "Worker must release extraction after reaping"
        );
        assert_eq!(std::fs::read(&binary).unwrap(), bytes);
    }
}

#[test]
fn stripped_aarch64_discovery_follows_real_calls_in_all_containers() {
    let (mut pe, pe_base) = common::pe();
    pe[0x108..0x110].fill(0); // No export directory.
    let (mut macho, macho_base) = common::macho();
    macho[196..200].fill(0); // LC_SYMTAB nsyms = 0.
    for (bytes, base) in [common::elf(false), (pe, pe_base), (macho, macho_base)] {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("stripped");
        std::fs::write(&binary, bytes).unwrap();
        let mut worker = WorkerClient::start_using_executable(
            eframe::egui::Context::default(),
            &binary,
            Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
        )
        .unwrap();
        let response = request(
            &mut worker,
            Request::Open {
                path: binary.to_string_lossy().into_owned(),
            },
        );
        let Response::Opened { info } = response else {
            panic!("Open stripped image: {response:?}");
        };
        assert_eq!(info.entry, base);
        assert_eq!(info.functions.len(), 1);
        assert_eq!(graph(&mut worker, base).calls[0].target, Some(base + 48));
        let response = request(&mut worker, Request::Discover);
        let Response::Functions {
            functions,
            analysis,
            ..
        } = response
        else {
            panic!("Discover functions: {response:?}");
        };
        analysis.validate(&info, &functions).unwrap();
        assert_eq!(
            analysis.references,
            vec![ghidra_rust::model::CallReference {
                caller: base,
                address: base + 8,
                target: base + 48,
            }]
        );
        assert_eq!(analysis.functions_examined, 2);
        assert!(functions.iter().any(|f| f.address == base + 48));
        let sum = graph(&mut worker, base + 48);
        decompile(&mut worker, base + 48, &info, &sum);
    }
}

#[test]
fn aarch64_rejects_unaligned_entries_and_truncated_instructions() {
    let (mut bytes, base) = common::elf(true);
    // Misaligned entry and first function; last symbol points at an incomplete
    // four-byte instruction in a shortened executable section.
    bytes[24..32].copy_from_slice(&(base + 1).to_le_bytes());
    bytes[0x220..0x228].copy_from_slice(&(base + 1).to_le_bytes());
    bytes[0x268..0x270].copy_from_slice(&(base + 84).to_le_bytes());
    bytes[0x460..0x468].copy_from_slice(&86u64.to_le_bytes());
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("malformed entries");
    std::fs::write(&binary, bytes).unwrap();
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &binary,
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    )
    .unwrap();
    let response = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    );
    let Response::Opened { info } = response else {
        panic!("Open bounded malformed fixture: {response:?}");
    };
    assert!(
        info.functions
            .iter()
            .all(|f| f.address % 4 == 0 && f.address != base + 84)
    );
    assert!(info.warnings.iter().any(|w| w.contains("entry point")));
    for address in [base + 1, base + 84] {
        assert!(matches!(
            request(&mut worker, Request::Graph { address }),
            Response::Error { .. }
        ));
        assert!(matches!(
            request(&mut worker, Request::Decompile { address }),
            Response::Error { .. }
        ));
    }
    let partial = graph(&mut worker, base + 80);
    assert_eq!(
        partial.blocks.iter().flat_map(|b| &b.instructions).count(),
        1
    );
    assert!(
        partial
            .warnings
            .iter()
            .any(|w| w.contains("executable regions"))
    );
    assert!(
        !graph(&mut worker, base + 48).blocks.is_empty(),
        "Bad requests must not poison the worker"
    );
}

#[test]
fn stripped_arm64_pe_recovers_unwind_entries_and_names_confirmed_import_veneers() {
    let (bytes, base) = common::arm64_pe_metadata();
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("original stripped ARM64 PE");
    std::fs::write(&binary, &bytes).unwrap();
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &binary,
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    )
    .unwrap();
    let Response::Opened { info } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Expected stripped ARM64 PE");
    };
    assert_eq!(
        info.functions
            .iter()
            .map(|function| function.address)
            .collect::<Vec<_>>(),
        [base, base + 0x80, base + 0xa0]
    );
    assert!(info.functions_truncated); // Fragment ownership remains incomplete.
    assert!(
        info.warnings
            .iter()
            .any(|warning| warning.contains("fragment records"))
    );
    let isolated = graph(&mut worker, base + 0x80);
    let (text, _) = decompile(&mut worker, base + 0x80, &info, &isolated);
    assert!(text.contains('7'), "{text}");
    let caller = graph(&mut worker, base + 0xa0);
    let (text, _) = decompile(&mut worker, base + 0xa0, &info, &caller);
    assert!(text.contains("fixture_import"), "{text}");
    let Response::Functions {
        functions,
        analysis,
        ..
    } = request(&mut worker, Request::Discover)
    else {
        panic!("Expected discovery report");
    };
    analysis.validate(&info, &functions).unwrap();
    // 26 CFG instruction attempts plus three veneer-confirmation attempts.
    assert_eq!(analysis.decode_attempts, 29);
    assert!(
        functions
            .iter()
            .any(|function| function.address == base + 0xc0 && function.name == "fixture_import")
    );
    assert!(
        functions
            .iter()
            .any(|function| function.address == base + 48)
    );
    assert!(
        !functions
            .iter()
            .any(|function| function.address == base + 0x90)
    );
    assert!(
        analysis
            .references
            .iter()
            .any(|reference| reference.caller == base + 0xa0
                && reference.address == base + 0xa8
                && reference.target == base + 0xc0)
    );
    let veneer = graph(&mut worker, base + 0xc0);
    assert_eq!(
        veneer
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .count(),
        3
    );
    assert!(
        veneer
            .edges
            .iter()
            .any(|edge| edge.kind == EdgeKind::Unknown && edge.target.is_none())
    );
    assert!(veneer.calls.is_empty());
    assert_eq!(
        info.sha256,
        ghidra_rust::session::fingerprint(&binary).unwrap()
    );
    assert_eq!(std::fs::read(&binary).unwrap(), bytes);
}
