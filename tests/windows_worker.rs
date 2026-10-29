//! Real Windows worker through the production suspended-spawn and job path.
#![cfg(windows)]

mod linkage;

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::discovery::Discovery;
use ghidra_rust::model::{FileIdentity, Request, Response};
use ghidra_rust::project::ProjectData;
use ghidra_rust::semantic::{LocalRename, TokenKind};
use ghidra_rust::session::{Annotation, BinaryProtection, Session};
use object::Object;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).expect("send worker request");
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
            Some(WorkerEvent::Failed(error)) => panic!("Windows worker failed: {error}"),
            None if Instant::now() >= deadline => panic!("Windows worker response timed out"),
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn fixture() -> Option<(tempfile::TempDir, PathBuf, PathBuf)> {
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
            return None;
        }
    };
    assert!(
        binary.is_file(),
        "Windows PE fixture is missing: {}",
        binary.display()
    );
    // Exercise UTF-16 process creation and UTF-8 IPC paths independently of the
    // checkout, CI runner, and Windows user's temporary-directory spelling.
    let directory = tempfile::Builder::new()
        .prefix("ghidra rust 日本語 ")
        .tempdir()
        .expect("create Windows test directory");
    let input = directory.path().join("sample input café.exe");
    let executable = directory.path().join("ghidra rust 日本語.exe");
    std::fs::copy(&binary, &input).expect("copy PE fixture to Unicode path");
    std::fs::copy(Path::new(env!("CARGO_BIN_EXE_ghidra-rust")), &executable)
        .expect("copy application to Unicode path");
    Some((directory, input, executable))
}

#[test]
fn stripped_pe_runtime_functions_load_without_explicit_discovery() {
    let Some((_directory, binary, executable)) = fixture() else {
        return;
    };
    let mut bytes = std::fs::read(&binary).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    let branch = image
        .exports()
        .unwrap()
        .into_iter()
        .find(|export| export.name() == b"branch_loop")
        .unwrap()
        .address();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let directory = pe + 24 + 112; // PE32+ export data directory.
    // Modify only this test's private copy of our original source fixture.
    bytes[directory..directory + 8].fill(0);
    std::fs::write(&binary, bytes).unwrap();
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &binary,
        &executable,
    )
    .unwrap();
    let Response::Opened { info, .. } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Cannot open the stripped PE fixture");
    };
    assert!(info.functions.len() > 1);
    assert!(
        info.functions
            .iter()
            .any(|function| function.address == branch),
        "The exception table must recover the original non-exported branch function"
    );
    let Response::Graph { view } = request(&mut worker, Request::Graph { address: branch }) else {
        panic!("Cannot browse the recovered stripped function");
    };
    assert!(view.blocks.len() >= 3);
}

#[test]
fn real_windows_worker_and_embedded_project_round_trip() {
    let Some((directory, binary, executable)) = fixture() else {
        return;
    };
    // Resolve the original fixture's export independently of our loader so this
    // cannot silently exercise CRT startup instead of the branch/loop function.
    let image_bytes = std::fs::read(&binary).unwrap();
    let image = object::File::parse(image_bytes.as_slice()).unwrap();
    let exports = image.exports().unwrap();
    let exported = |name: &[u8]| {
        exports
            .iter()
            .find(|symbol| symbol.name() == name)
            .expect("MSVC fixture must export its test symbols")
            .address()
    };
    let address = exported(b"branch_loop");
    let aes = exported(b"aes_sbox_prefix");
    let alias = directory.path().join("hard link input.exe");
    std::fs::hard_link(&binary, &alias).expect("create same-volume input alias");
    let context = eframe::egui::Context::default();
    let mut worker = WorkerClient::start_using_executable(context.clone(), &binary, &executable)
        .expect("start production Windows worker in a resource-limited job");
    let Response::Opened { info, .. } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Windows worker did not open PE fixture");
    };
    let declarations = linkage::read(|query| request(&mut worker, query), &info);
    assert!(
        declarations
            .exports
            .iter()
            .any(|export| export.raw.as_deref() == Some("branch_loop")
                && export.target.address() == Some(address))
    );
    assert!(
        declarations
            .imports
            .iter()
            .any(|import| import.library.is_some() && import.slot.is_some())
    );
    assert_eq!(info.format, "PE");
    assert!(
        info.functions
            .iter()
            .any(|function| function.address == address && function.name == "branch_loop"),
        "PE export names must load before explicit function discovery"
    );
    assert_eq!(
        Path::new(&info.path),
        binary.canonicalize().unwrap(),
        "WorkerClient must retain the actual Unicode input path"
    );
    assert_eq!(
        info.sha256,
        ghidra_rust::session::fingerprint(&binary).unwrap()
    );
    let identity = FileIdentity::from_file(&std::fs::File::open(&binary).unwrap())
        .expect("Windows fixture must provide a nonzero full file identity");
    assert_eq!(info.source_identity, Some(identity));
    assert_eq!(
        FileIdentity::from_file(&std::fs::File::open(&alias).unwrap()),
        Some(identity),
        "Hard links must identify the same opened Windows file"
    );
    let protection = worker.protection().bind_snapshot(&info).unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&binary)
            .is_err(),
        "Retained input handle must deny concurrent writers"
    );
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&alias)
            .is_err(),
        "A hard link must not bypass the retained input's write exclusion"
    );
    let Response::Graph { view } = request(&mut worker, Request::Graph { address }) else {
        panic!("Windows worker did not return a CFG");
    };
    assert_eq!(view.address, address);
    assert!(view.blocks.len() >= 3);
    assert!(
        view.edges
            .iter()
            .any(|edge| { edge.target.is_some_and(|target| target <= edge.source) }),
        "PE fixture's loop must retain a backedge"
    );
    let Response::Decompiled {
        semantics,
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
        text.contains("branch_loop"),
        "Loaded PE names must reach the real decompiler: {text}"
    );
    assert!(
        !mappings.is_empty(),
        "PE decompilation must return semantic instruction locations"
    );
    let (local_index, local) = semantics.locals.iter().enumerate().find(|(index, _)| {
        semantics.tokens.iter().filter(|token| matches!(token.kind, TokenKind::Local { local: Some(i) } if i == *index)).count() > 2
    }).expect("MSVC /Od branch fixture must recover a storage-backed local and its declaration/uses");
    let local_rename = LocalRename {
        identity: local.identity.clone(),
        name: "windows_local_value".into(),
    };
    let mut expected = text;
    for token in semantics.tokens.iter().rev().filter(
        |token| matches!(token.kind, TokenKind::Local { local: Some(i) } if i == local_index),
    ) {
        expected.replace_range(token.start..token.end, &local_rename.name);
    }
    let Response::Decompiled {
        text,
        mappings,
        semantics,
        ..
    } = request(
        &mut worker,
        Request::DecompileWithLocals {
            address,
            renames: vec![local_rename.clone()],
        },
    )
    else {
        panic!("Windows worker did not rename the recovered local");
    };
    assert_eq!(text, expected);
    assert!(semantics.warnings.is_empty());
    let Response::Strings { strings, truncated } = request(&mut worker, Request::Strings) else {
        panic!("Windows worker did not return strings");
    };
    assert!(
        strings
            .iter()
            .any(|entry| entry.text.contains("aGVsbG8gcmV2ZXJzZXI="))
    );
    let Response::Crypto {
        matches: crypto,
        truncated: crypto_truncated,
    } = request(&mut worker, Request::Crypto)
    else {
        panic!("Windows worker did not return cryptographic constants");
    };
    assert!(
        crypto
            .iter()
            .any(|hit| hit.address == aes && hit.algorithm.contains("AES"))
    );
    let mut discovery = Discovery::new(
        Some(info.entry),
        info.functions.iter().map(|function| function.address),
        info.functions_truncated,
    );
    let Response::DiscoveryBatch { mut batch } =
        request(&mut worker, discovery.begin(1, 1, 0).unwrap())
    else {
        panic!("Windows worker did not return a discovery batch");
    };
    discovery
        .commit_reply(&info, None, None, &mut batch)
        .unwrap();
    let saved = discovery.save();
    saved.validate(&info).unwrap();
    assert!(!saved.report.references.is_empty());
    assert!(!saved.report.data.as_ref().unwrap().references.is_empty());
    // Address-taking evidence is examined even when this batch finds none.
    assert!(saved.report.addresses.is_some());
    let mut session = Session::new(info.sha256.clone());
    session.version = 2;
    session.local_renames.push(local_rename.clone());
    let sidecar = directory.path().join("local names 日本語.json");
    session.save(&sidecar, &protection).unwrap();
    let mut session = Session::load(&sidecar, &info.sha256).unwrap();
    assert_eq!(session.local_renames, vec![local_rename.clone()]);
    session.annotations.insert(
        address,
        Annotation {
            label: "saved_function".into(),
            comment: "Windows project 日本語 round-trip".into(),
            decoded: vec![],
        },
    );
    let mut project = ProjectData {
        semantics,
        info,
        session,
        view: Some(view),
        decompiled: Some(text),
        mappings,
        strings,
        strings_truncated: truncated,
        crypto,
        crypto_truncated,
        selected_address: Some(address),
        discovery: Some(Arc::new(saved)),
    };
    assert!(
        project.save(&binary, &protection, true).is_err(),
        "Project saves must reject the original input pathname"
    );
    assert!(
        project.save(&alias, &protection, true).is_err(),
        "Project saves must reject an input alias by opened file identity"
    );

    let project_path = directory.path().join("analysis 日本語 #1%.grproj");
    project.save(&project_path, &protection, true).unwrap();
    // Replacing an existing SQLite project exercises MoveFileExW rather than
    // only the easier first-save path. No open SQLite handles may block it.
    project
        .session
        .annotations
        .get_mut(&address)
        .unwrap()
        .comment = "Updated Windows project 日本語".into();
    project.save(&project_path, &protection, true).unwrap();
    let loaded = ProjectData::load(&project_path).expect("reload embedded SQLite project");
    assert!(loaded.cache_compatible);
    assert!(loaded.data.info.source_identity.is_none());
    assert_eq!(loaded.source_hint, project.info.path);
    assert_eq!(loaded.data.decompiled, project.decompiled);
    assert_eq!(
        serde_json::to_value(&loaded.data.mappings).unwrap(),
        serde_json::to_value(&project.mappings).unwrap()
    );
    assert_eq!(loaded.data.selected_address, Some(address));
    let restored = loaded.data.discovery.as_ref().unwrap();
    let original = project.discovery.as_ref().unwrap();
    assert_eq!(restored.report.references, original.report.references);
    assert_eq!(
        restored.report.data.as_ref().unwrap().references,
        original.report.data.as_ref().unwrap().references
    );
    assert_eq!(
        restored.report.addresses.as_ref().unwrap().references,
        original.report.addresses.as_ref().unwrap().references
    );
    assert_eq!(restored.pending, original.pending);
    assert_eq!(
        loaded.data.session.annotations[&address].comment,
        "Updated Windows project 日本語"
    );
    let embedded = loaded
        .binary
        .as_ref()
        .expect("default embedded image")
        .clone();
    let extracted = embedded.path().to_owned();
    assert_eq!(
        ghidra_rust::session::fingerprint(&extracted).unwrap(),
        project.info.sha256
    );
    let mut reopened = WorkerClient::start_using_executable(context, &extracted, &executable)
        .expect("start worker for extracted Windows project input");
    reopened.retain_source(Arc::new(embedded));
    let Response::Opened { info: fresh, .. } = request(
        &mut reopened,
        Request::Open {
            path: extracted.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("Windows worker did not reopen embedded project input");
    };
    assert_eq!(
        declarations.digest,
        linkage::read(|query| request(&mut reopened, query), &fresh).digest
    );
    loaded.data.validate_against(&fresh).unwrap();
    let Response::Decompiled {
        text: replayed,
        semantics: replayed_semantics,
        ..
    } = request(
        &mut reopened,
        Request::DecompileWithLocals {
            address,
            renames: loaded.data.session.local_renames.clone(),
        },
    )
    else {
        panic!("Windows worker did not replay saved local names");
    };
    assert_eq!(Some(&replayed), loaded.data.decompiled.as_ref());
    assert!(replayed_semantics.warnings.is_empty());
    assert!(fresh.source_identity.is_some());
    assert_ne!(fresh.source_identity, project.info.source_identity);
    let fresh_protection = reopened.protection().bind_snapshot(&fresh).unwrap();
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&extracted)
            .is_err(),
        "Extracted project input must receive the same deny-write protection"
    );
    assert!(!protection.same_source(&fresh_protection));
    drop(fresh_protection);
    drop(loaded);
    assert!(
        extracted.is_file(),
        "Worker must retain the extracted input lease"
    );
    let Response::Graph { view: fresh_view } = request(&mut reopened, Request::Graph { address })
    else {
        panic!("Windows worker lost its extracted input after project data was dropped");
    };
    assert_eq!(fresh_view.address, address);
    assert!(!fresh_view.blocks.is_empty());
    drop(reopened);
    // Worker cleanup runs off the GUI thread; its lease must outlive the child
    // and then remove the private extracted file without a Windows sharing leak.
    let deadline = Instant::now() + Duration::from_secs(10);
    while extracted.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        !extracted.exists(),
        "Extracted input leaked after worker shutdown"
    );

    // FILE_SHARE_DELETE allows renaming while the worker/GUI retain their
    // deny-write handles. File identity and snapshot reads must survive it.
    let renamed = directory.path().join("renamed input 日本語.exe");
    std::fs::rename(&binary, &renamed).expect("rename input with retained guards");
    let renamed_protection = BinaryProtection::open(&renamed).unwrap();
    assert!(protection.same_source(&renamed_protection));
    assert_eq!(
        protection.verified_snapshot().unwrap().len() as u64,
        project.info.file_len
    );
    assert!(project.save(&renamed, &protection, true).is_err());
    drop(renamed_protection);
    drop(worker);
    drop(protection);
    // The app copy is still an executable image until the original worker has
    // exited. Wait for its release instead of leaking the temporary directory
    // when TempDir's drop races asynchronous reaping on Windows.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::remove_file(&executable) {
            Ok(()) => break,
            Err(error) if Instant::now() >= deadline => {
                panic!("Worker executable remained locked after shutdown: {error}");
            }
            Err(_) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

/// Opens `binary` and reads every validated page of its symbol-name table.
fn open_names(
    binary: &Path,
) -> (
    WorkerClient,
    ghidra_rust::model::BinaryInfo,
    ghidra_rust::symbol_names::SymbolNames,
) {
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        binary,
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    )
    .unwrap();
    let response = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    );
    let Response::Opened {
        info,
        symbols: Some(summary),
    } = response
    else {
        panic!(
            "Windows worker did not open {}: {response:?}",
            binary.display()
        );
    };
    let mut pages = ghidra_rust::symbol_names::SymbolNameFetch::new(summary).unwrap();
    while let Some(cursor) = pages.cursor() {
        let Response::SymbolNames { page } = request(&mut worker, Request::SymbolNames { cursor })
        else {
            panic!("Windows worker did not return symbol names");
        };
        pages.accept(page).unwrap();
    }
    (worker, info, pages.finish().unwrap())
}

fn exports(binary: &Path) -> Vec<(String, u64)> {
    let bytes = std::fs::read(binary).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    image
        .exports()
        .unwrap()
        .into_iter()
        .map(|export| {
            (
                String::from_utf8(export.name().to_vec()).unwrap(),
                export.address(),
            )
        })
        .collect()
}

#[test]
fn msvc_decorated_exports_are_demangled_with_raw_identities() {
    let Some(binary) = std::env::var_os("GHIDRA_RUST_TEST_PE_CPP").map(PathBuf::from) else {
        assert!(
            std::env::var_os("CI").is_none(),
            "Windows CI must compile and set GHIDRA_RUST_TEST_PE_CPP"
        );
        eprintln!("Set GHIDRA_RUST_TEST_PE_CPP to an MSVC build of demangle_program.cpp");
        return;
    };
    let decorated: Vec<_> = exports(&binary)
        .into_iter()
        .filter(|(name, _)| name.starts_with('?'))
        .collect();
    assert!(decorated.len() >= 4, "{decorated:?}");
    let (_worker, info, names) = open_names(&binary);
    for (raw, address) in &decorated {
        let record = names
            .get(*address)
            .unwrap_or_else(|| panic!("{raw} has no display name"));
        assert_eq!(
            &record.raw, raw,
            "the raw identity must be the exact export"
        );
        assert!(record.display.is_some(), "{raw} has no display name");
        assert!(
            info.functions
                .iter()
                .any(|function| function.address == *address && function.name == *raw),
            "{raw} must keep its exact export name as the inventory identity"
        );
    }
    for display in [
        "demangle_fixture::overloaded",
        "demangle_fixture::identity<int>",
        "demangle_fixture::exit",
    ] {
        let address = names.find(display).expect(display);
        assert!(
            decorated.iter().any(|(_, export)| *export == address),
            "{display} must belong to a decorated export"
        );
    }
}

#[test]
fn rust_v0_dylib_exports_are_demangled_with_raw_identities() {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("demangle_program.dll");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = std::process::Command::new(rustc)
        .args([
            "--edition=2024",
            "--crate-name=demangle_program",
            "--crate-type=dylib",
            "-Csymbol-mangling-version=v0",
            "-Copt-level=0",
            "-Cpanic=abort",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/demangle_program.rs"))
        .arg("-o")
        .arg(&binary)
        .current_dir(directory.path())
        .output()
        .expect("The pinned Rust toolchain is required for the original fixture");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let exported = exports(&binary);
    let (mut worker, _info, names) = open_names(&binary);
    let main = exported
        .iter()
        .find(|(name, _)| name == "main")
        .expect("exported fixture main")
        .1;
    let Response::Decompiled {
        text, semantics, ..
    } = request(&mut worker, Request::Decompile { address: main })
    else {
        panic!("Windows worker did not decompile the Rust fixture");
    };
    for display in ["demangle_program::demangle_probe", "demangle_program::café"] {
        let address = names.find(display).expect(display);
        let raw = &names.get(address).unwrap().raw;
        assert!(raw.starts_with("_R"), "{raw}");
        assert!(
            exported.contains(&(raw.clone(), address)),
            "{raw} is not exported"
        );
        assert!(
            semantics.tokens.iter().any(|token| {
                matches!(token.kind, TokenKind::Call { target } if target == address)
                    && &text[token.start..token.end] == display
            }),
            "{display} call token\n{text}"
        );
    }
}

// Exact original arrays and independently specified offsets; the production
// matcher/domain are never used to calculate the expected answers.
fn verify_search_fixture(
    info: &ghidra_rust::model::BinaryInfo,
    original: &[u8],
    mut invoke: impl FnMut(Request) -> Response,
) {
    use ghidra_rust::search::{MemoryPattern, MemorySearchSession, MemorySearchSpec, SearchState};
    use object::{Object, ObjectSection};
    let image = object::File::parse(original).unwrap();
    let marker_address = |marker: &[u8]| {
        let mut addresses = Vec::new();
        for section in image.sections() {
            if let Ok(bytes) = section.data() {
                for (offset, _) in bytes
                    .windows(marker.len())
                    .enumerate()
                    .filter(|(_, bytes)| *bytes == marker)
                {
                    addresses.push(section.address() + offset as u64);
                }
            }
        }
        assert_eq!(addresses.len(), 1, "original marker must occur once");
        addresses[0]
    };
    let ascii = marker_address(&[
        0xd3, 0x71, 0x53, 0x72, 0x63, 0x48, 0x34, 0x41, 0x42, 0x41, 0x42, 0x41, 0xf2,
    ]);
    let utf16 = marker_address(&[
        0xf1, 0x51, 0, 0x34, 0, 0x3e, 0xd8, 0x80, 0xdd, 0, 0x51, 0, 0x34, 0, 0x3e, 0xd8, 0x80,
        0xdd, 0xfe,
    ]);
    let wildcard = marker_address(&[
        0xe3, 0xd9, 0x6e, 0xa5, 0x16, 0xb7, 0xc8, 0x71, 0xd9, 0x6e, 0xa5, 0x80, 0xb7, 0xc8, 0xae,
    ]);
    let dense = marker_address(&[0xa6; 600]);
    for (spec, expected) in [
        (
            MemorySearchSpec {
                pattern: MemoryPattern::Ascii {
                    text: "srch4aba".into(),
                },
                match_case: false,
            },
            vec![ascii + 2],
        ),
        (
            MemorySearchSpec {
                pattern: MemoryPattern::Utf16Le {
                    text: "Q4🦀".into(),
                },
                match_case: true,
            },
            vec![utf16 + 1, utf16 + 10],
        ),
        (
            MemorySearchSpec::hex("D9 6E A5 ?? B7 C8").unwrap(),
            vec![wildcard + 1, wildcard + 8],
        ),
        (
            MemorySearchSpec::hex("A6 A6 A6 A6 A6 A6 A6 A6").unwrap(),
            (0..593).map(|offset| dense + offset).collect(),
        ),
    ] {
        let mut results = ghidra_rust::function_results::FunctionResults::default();
        let reservation = results
            .reserve_transient(ghidra_rust::search::MEMORY_SEARCH_RESERVATION_BYTES, &[])
            .unwrap();
        let mut search = MemorySearchSession::new(info, 7, 9, spec, reservation).unwrap();
        while let Some(query) = search.next_request(1).unwrap() {
            let Response::MemorySearch(page) = invoke(query) else {
                panic!("memory search page");
            };
            search.accept(page).unwrap();
        }
        assert_eq!(search.state(), SearchState::Complete);
        assert_eq!(
            search
                .hits()
                .iter()
                .map(|hit| hit.address)
                .collect::<Vec<_>>(),
            expected
        );
    }
}

#[test]
fn windows_memory_search_uses_the_contained_worker_and_original_markers() {
    let Some((_directory, binary, executable)) = fixture() else {
        return;
    };
    let original = std::fs::read(&binary).unwrap();
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &binary,
        &executable,
    )
    .unwrap();
    let Response::Opened { info, .. } = request(
        &mut worker,
        Request::Open {
            path: binary.to_string_lossy().into_owned(),
        },
    ) else {
        panic!("open");
    };
    verify_search_fixture(&info, &original, |query| request(&mut worker, query));
}
