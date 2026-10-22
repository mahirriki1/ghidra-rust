//! Exercise the production bubblewrap path, including the host loader layout.
#![cfg(target_os = "linux")]

mod inventory;

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{CallAnalysis, DataAccess, Request, Response};
use ghidra_rust::project::ProjectData;
use ghidra_rust::session::{Annotation, Session};
use object::{Object, ObjectSymbol};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
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

// Limited differential on the original x86-64 fixture: objdump annotates each
// RIP-relative access with its resolved target. The fixture deliberately uses
// 32-bit MOVs, so operand position determines read/write without a general
// disassembly-text reference heuristic in the application.
fn compare_fixture_data(binary: &Path, owner: u64, target: u64, analysis: &CallAnalysis) {
    let output = Command::new("objdump")
        .args(["--no-show-raw-insn", "--disassemble=read_write_word"])
        .arg(binary)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let mut expected = BTreeSet::new();
    for line in text
        .lines()
        .filter(|line| line.contains("<reference_word>"))
    {
        let (pc, instruction) = line.trim().split_once(':').unwrap();
        let (operation, comment) = instruction.split_once('#').unwrap();
        let (mnemonic, operands) = operation.trim().split_once(char::is_whitespace).unwrap();
        assert_eq!(mnemonic, "mov");
        assert_eq!(
            u64::from_str_radix(comment.split_whitespace().next().unwrap(), 16).unwrap(),
            target
        );
        let (source, destination) = operands.split_once(',').unwrap();
        let access = if source.contains("(%rip)") {
            assert_eq!(destination.trim(), "%eax");
            DataAccess::Read
        } else {
            assert_eq!(source.trim(), "%eax");
            assert!(destination.contains("(%rip)"));
            DataAccess::Write
        };
        expected.insert((u64::from_str_radix(pc, 16).unwrap(), 4, access));
    }
    assert!(
        expected
            .iter()
            .any(|(_, _, access)| *access == DataAccess::Read)
    );
    assert!(
        expected
            .iter()
            .any(|(_, _, access)| *access == DataAccess::Write)
    );
    let actual = analysis
        .data
        .as_ref()
        .unwrap()
        .references
        .iter()
        .filter(|reference| reference.function == owner && reference.target == target)
        .map(|reference| (reference.address, reference.size, reference.access))
        .collect();
    assert_eq!(
        expected, actual,
        "Data-access PCs, widths or kinds differ from GNU objdump"
    );
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
    let owner = image
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("read_write_word"))
        .unwrap()
        .address();
    let target = image
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("reference_word"))
        .unwrap()
        .address();
    let data = analysis.data.as_ref().expect("Fresh data-access analysis");
    if info.architecture == "x86-64" {
        compare_fixture_data(&binary, owner, target, &analysis);
    }
    for access in [DataAccess::Read, DataAccess::Write]
        .into_iter()
        .filter(|_| matches!(info.architecture.as_str(), "x86" | "x86-64"))
    {
        assert!(
            data.references
                .iter()
                .any(|reference| reference.function == owner
                    && reference.target == target
                    && reference.size == 4
                    && reference.access == access)
        );
    }
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
        semantics: Default::default(),
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
        discovery: None,
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

#[test]
fn semantic_local_rename_survives_sandboxed_worker_restart() {
    use ghidra_rust::semantic::{LocalRename, TokenKind};
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("locals");
    let compiled = Command::new("gcc")
        .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(compiled.status.success(), "{:?}", compiled);
    let bytes = std::fs::read(&binary).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    let address = image
        .symbols()
        .find(|s| s.name().ok() == Some("branch_loop"))
        .unwrap()
        .address();
    let context = eframe::egui::Context::default();
    let executable = Path::new(env!("CARGO_BIN_EXE_ghidra-rust"));
    let mut worker =
        WorkerClient::start_using_executable(context.clone(), &binary, executable).unwrap();
    assert!(matches!(
        request(
            &mut worker,
            Request::Open {
                path: binary.to_string_lossy().into_owned()
            }
        ),
        Response::Opened { .. }
    ));
    let Response::Decompiled {
        semantics,
        text: original,
        ..
    } = request(&mut worker, Request::Decompile { address })
    else {
        panic!()
    };
    let (index, local) = semantics
        .locals
        .iter()
        .enumerate()
        .find(|(i, _)| {
            semantics
                .tokens
                .iter()
                .filter(|t| matches!(t.kind, TokenKind::Local { local: Some(j) } if j == *i))
                .count()
                > 2
        })
        .unwrap();
    let rename = LocalRename {
        identity: local.identity.clone(),
        name: "sandbox_local".into(),
    };
    let mut expected = original;
    for token in semantics
        .tokens
        .iter()
        .rev()
        .filter(|t| matches!(t.kind, TokenKind::Local { local: Some(i) } if i == index))
    {
        expected.replace_range(token.start..token.end, &rename.name);
    }
    let Response::Decompiled {
        text, semantics, ..
    } = request(
        &mut worker,
        Request::DecompileWithLocals {
            address,
            renames: vec![rename.clone()],
        },
    )
    else {
        panic!()
    };
    assert_eq!(text, expected);
    assert!(semantics.warnings.is_empty());
    drop(worker);
    let mut worker = WorkerClient::start_using_executable(context, &binary, executable).unwrap();
    assert!(matches!(
        request(
            &mut worker,
            Request::Open {
                path: binary.to_string_lossy().into_owned()
            }
        ),
        Response::Opened { .. }
    ));
    let Response::Decompiled {
        text, semantics, ..
    } = request(
        &mut worker,
        Request::DecompileWithLocals {
            address,
            renames: vec![rename],
        },
    )
    else {
        panic!()
    };
    assert_eq!(text, expected);
    assert!(semantics.warnings.is_empty());
    assert_eq!(std::fs::read(&binary).unwrap(), bytes);
}

/// Compiles original C with GCC; `strip` additionally removes every symbol.
fn compile(directory: &Path, name: &str, source: &Path, args: &[&str], strip: bool) -> PathBuf {
    let output = directory.join(name);
    let compiled = Command::new("gcc")
        .args(args)
        .arg(source)
        .arg("-o")
        .arg(&output)
        .output()
        .expect("Linux integration tests require GCC");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    if strip {
        let stripped = Command::new("strip")
            .arg("--strip-all")
            .arg(&output)
            .status()
            .expect("Linux integration tests require binutils strip");
        assert!(stripped.success());
    }
    output
}

fn symbol(binary: &Path, name: &str) -> u64 {
    let bytes = std::fs::read(binary).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    image
        .symbols()
        .find(|symbol| symbol.name().ok() == Some(name))
        .unwrap_or_else(|| panic!("{name} symbol"))
        .address()
}

fn open(binary: &Path) -> (WorkerClient, ghidra_rust::model::BinaryInfo) {
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
    let Response::Opened { info } = response else {
        panic!(
            "Sandboxed worker did not open {}: {response:?}",
            binary.display()
        );
    };
    (worker, info)
}

fn recovered_main(info: &ghidra_rust::model::BinaryInfo) -> Option<u64> {
    let main = info
        .functions
        .iter()
        .find(|function| function.name == "main")?;
    let note = format!("Recovered main at {:#x}", main.address);
    info.warnings
        .iter()
        .any(|warning| warning.starts_with(&note))
        .then_some(main.address)
}

// Stripped glibc executables keep no symbol for main: the C runtime's entry
// passes it to the imported __libc_start_main. Truth comes from the unstripped
// twin, whose allocated sections stripping leaves unchanged.
#[test]
fn stripped_elf_recovers_main_from_its_startup_call() {
    let directory = tempfile::tempdir().unwrap();
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample.c"
    ));
    for flags in [
        ["-O0", "-fno-pie", "-no-pie"],
        ["-O0", "-fPIE", "-pie"],
        ["-O2", "-fno-pie", "-no-pie"],
        ["-O2", "-fPIE", "-pie"],
    ] {
        let name = flags.join("");
        let args = [&flags[..], &["-fno-inline"]].concat();
        let reference = compile(
            directory.path(),
            &format!("{name}-symbols"),
            source,
            &args,
            false,
        );
        let binary = compile(directory.path(), &name, source, &args, true);
        let (main, callee) = (
            symbol(&reference, "main"),
            symbol(&reference, "branch_loop"),
        );
        let (mut worker, info) = open(&binary);
        assert_eq!(recovered_main(&info), Some(main), "{name}");
        assert!(
            !info.functions.iter().any(|f| f.address == callee),
            "{name}"
        );
        let Response::Functions {
            functions,
            analysis,
            ..
        } = request(&mut worker, Request::Discover)
        else {
            panic!("Sandboxed worker did not discover calls");
        };
        analysis.validate(&info, &functions).unwrap();
        // Discovery follows main's genuine direct calls; the startup handoff is
        // an indirect call and is never reported as a direct reference.
        assert!(functions.iter().any(|f| f.address == callee), "{name}");
        assert!(
            analysis
                .references
                .iter()
                .any(|r| r.caller == main && r.target == callee)
        );
        assert!(!analysis.references.iter().any(|r| r.target == main));
        // Optimized main once failed semantic capture: a member printed under
        // another variable's name must stay unverified, not reject the result.
        let response = request(&mut worker, Request::Decompile { address: main });
        let Response::Decompiled { text, mappings, .. } = response else {
            panic!("{name}: recovered main did not decompile: {response:?}");
        };
        ghidra_rust::selection::validate_mappings(&text, &mappings, &info.sections).unwrap();
        assert!(text.contains("main("), "{name}: {text}");
    }
}

#[test]
fn elf_startup_recovery_requires_complete_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let sample = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/sample.c"
    ));
    // Symbols win: the unstripped build names main itself, without a note.
    let symbols = compile(directory.path(), "symbols", sample, &["-O0"], false);
    let (_, info) = open(&symbols);
    assert!(info.functions.iter().any(|f| f.name == "main"));
    assert_eq!(recovered_main(&info), None);
    // Original startup code: a direct PLT call with a constant callback is
    // recognized through the verified import stub. When an unknown call can
    // clobber the argument first, nothing is recovered rather than guessed.
    let startup = directory.path().join("startup.c");
    std::fs::write(
        &startup,
        "extern int __libc_start_main(void *, int, char **, void *, void *, void *, void *);\n\
         extern int puts(const char *);\n\
         __attribute__((noinline)) int callback(void) { return puts(\"callback\"); }\n\
         __attribute__((noinline)) void *pick(void) { puts(\"pick\"); return (void *)callback; }\n\
         #ifdef UNKNOWN\n\
         void _start(void) { __libc_start_main(pick(), 0, 0, 0, 0, 0, 0); }\n\
         #else\n\
         void _start(void) { __libc_start_main((void *)callback, 0, 0, 0, 0, 0, 0); }\n\
         #endif\n",
    )
    .unwrap();
    let args = ["-O1", "-fno-pie", "-no-pie", "-nostartfiles"];
    let reference = compile(directory.path(), "direct-symbols", &startup, &args, false);
    let direct = compile(directory.path(), "direct", &startup, &args, true);
    let (_, info) = open(&direct);
    assert_eq!(recovered_main(&info), Some(symbol(&reference, "callback")));
    let unknown_args = [&args[..], &["-DUNKNOWN"]].concat();
    let unknown = compile(directory.path(), "unknown", &startup, &unknown_args, true);
    let (_, info) = open(&unknown);
    assert!(!info.functions.iter().any(|f| f.name == "main"));
}

// Jump-table destinations come from engine flow analysis of the switch. The
// case-only callee is reachable through them alone, so its call reference and
// stripped-build discovery both depend on that recovery.
#[test]
fn switch_tables_extend_graphs_and_discovery() {
    use ghidra_rust::model::{EdgeEvidence, EdgeKind};
    let directory = tempfile::tempdir().unwrap();
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/switch.c"
    ));
    for flags in [["-O2", "-fno-pie", "-no-pie"], ["-O2", "-fPIE", "-pie"]] {
        let name = flags.join("");
        let reference = compile(
            directory.path(),
            &format!("{name}-symbols"),
            source,
            &flags,
            false,
        );
        let [dense, case_only, computed] =
            ["dense", "case_only", "computed"].map(|name| symbol(&reference, name));
        let (mut worker, _) = open(&reference);
        let Response::Graph { view } = request(&mut worker, Request::Graph { address: dense })
        else {
            panic!("{name}: no switch graph");
        };
        let switched: Vec<_> = view
            .edges
            .iter()
            .filter(|edge| edge.evidence == Some(EdgeEvidence::EngineJumpTable))
            .collect();
        // Seven cases; the default is the bounds check's ordinary branch.
        assert!(switched.len() >= 6, "{name}: {:?}", view.edges);
        assert!(switched.iter().all(|edge| edge.kind == EdgeKind::Branch));
        let branch = switched[0].source;
        assert!(switched.iter().all(|edge| edge.source == branch));
        assert!(
            !view
                .edges
                .iter()
                .any(|edge| edge.source == branch && edge.target.is_none()),
            "{name}: complete table keeps an unresolved successor"
        );
        let case = view
            .blocks
            .iter()
            .find(|block| {
                switched
                    .iter()
                    .any(|edge| edge.target == Some(block.address))
                    && block
                        .instructions
                        .iter()
                        .any(|i| view.calls.iter().any(|c| c.address == i.address))
            })
            .map(|block| block.address);
        assert!(case.is_some(), "{name}: no case block with a call");
        assert!(
            view.calls.iter().any(|call| call.target == Some(case_only)),
            "{name}: {:?}",
            view.calls
        );
        // Flow-only recovery leaves the function ready for decompilation.
        let response = request(&mut worker, Request::Decompile { address: dense });
        let Response::Decompiled { text, .. } = response else {
            panic!("{name}: switch function did not decompile: {response:?}");
        };
        assert!(text.contains("case_only("), "{name}: {text}");
        // A computed tail jump through an unknown pointer stays unresolved.
        let Response::Graph { view } = request(&mut worker, Request::Graph { address: computed })
        else {
            panic!("{name}: no computed-jump graph");
        };
        assert!(view.edges.iter().all(|edge| edge.evidence.is_none()));
        assert!(
            view.edges
                .iter()
                .any(|edge| edge.kind == EdgeKind::Unknown && edge.target.is_none())
        );
        assert!(
            view.warnings
                .iter()
                .any(|w| w.contains("has unresolved targets")),
            "{name}: {:?}",
            view.warnings
        );
        let Response::Functions { analysis, .. } = request(&mut worker, Request::Discover) else {
            panic!("{name}: discovery failed");
        };
        assert!(
            analysis
                .references
                .iter()
                .any(|r| r.caller == dense && r.target == case_only),
            "{name}"
        );

        // Stripped: main is recovered, dense is discovered from it, and
        // case_only only through the switch.
        let binary = compile(directory.path(), &name, source, &flags, true);
        let (mut worker, info) = open(&binary);
        assert!(!info.functions.iter().any(|f| f.address == case_only));
        let Response::Functions {
            functions,
            analysis,
            ..
        } = request(&mut worker, Request::Discover)
        else {
            panic!("{name}: stripped discovery failed");
        };
        analysis.validate(&info, &functions).unwrap();
        for address in [dense, case_only, computed] {
            assert!(
                functions.iter().any(|f| f.address == address),
                "{name}: {address:#x} not discovered"
            );
        }
        assert!(
            analysis
                .references
                .iter()
                .any(|r| r.caller == dense && r.target == case_only)
        );
        assert!(!analysis.references.iter().any(|r| r.caller == computed));
    }
}

/// Runs resumable discovery to completion, as the desktop does, optionally
/// with the function-start pattern phase. Returns the final inventory.
fn discover_batches(
    worker: &mut WorkerClient,
    info: &ghidra_rust::model::BinaryInfo,
    patterns: bool,
) -> (
    Vec<ghidra_rust::model::FunctionInfo>,
    ghidra_rust::discovery::Discovery,
) {
    let mut state = ghidra_rust::discovery::Discovery::new(
        ghidra_rust::call_analysis::code_address(info, info.entry).then_some(info.entry),
        info.functions.iter().map(|function| function.address),
        info.functions_truncated,
    );
    if patterns {
        state.enable_patterns(info);
    }
    let mut inventory = inventory::Inventory::default();
    let mut functions = info.functions.clone();
    while let Some(next) = state.begin(1, 1, 0) {
        let next = inventory.bind(next);
        let Response::DiscoveryBatch { mut batch } = request(worker, next.clone()) else {
            panic!("Expected a discovery batch");
        };
        inventory
            .commit(&mut state, info, &next, &mut batch)
            .unwrap();
        functions = inventory.functions().to_vec();
    }
    assert_eq!(state.remaining(), 0);
    (functions, state)
}

// Function-start patterns recover code that no direct call reaches. Every
// pattern-derived start, and every callee found through one, must be a real
// function of the unstripped twin; symbols never seed the stripped run.
#[test]
fn function_start_patterns_recover_callbacks_without_false_starts() {
    let directory = tempfile::tempdir().unwrap();
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/callbacks.c"
    ));
    for flags in [
        ["-O0", "-fno-pie", "-no-pie"],
        ["-O0", "-fPIE", "-pie"],
        ["-O2", "-fno-pie", "-no-pie"],
        ["-O2", "-fPIE", "-pie"],
    ] {
        let name = flags.join("");
        let reference = compile(
            directory.path(),
            &format!("{name}-symbols"),
            source,
            &flags,
            false,
        );
        let truth: BTreeSet<u64> = {
            let bytes = std::fs::read(&reference).unwrap();
            let image = object::File::parse(bytes.as_slice()).unwrap();
            image
                .symbols()
                .filter(|symbol| symbol.kind() == object::SymbolKind::Text && symbol.address() != 0)
                .map(|symbol| symbol.address())
                .collect()
        };
        let binary = compile(directory.path(), &name, source, &flags, true);
        let (mut worker, info) = open(&binary);
        let (without, _) = discover_batches(&mut worker, &info, false);
        let (mut worker, info) = open(&binary);
        let (with, state) = discover_batches(&mut worker, &info, true);
        let phase = state.patterns.as_ref().expect("x86-64 ELF uses patterns");
        assert!(
            phase.cursor.is_none() && !phase.partial,
            "{name}: {phase:?}"
        );
        let before: BTreeSet<_> = without.iter().map(|f| f.address).collect();
        let gained: BTreeSet<_> = with
            .iter()
            .map(|f| f.address)
            .filter(|address| !before.contains(address))
            .collect();
        let false_starts: Vec<_> = gained.difference(&truth).collect();
        assert!(
            false_starts.is_empty(),
            "{name}: false starts {false_starts:x?}"
        );
        let callbacks = [
            "keep_across_call",
            "with_locals",
            "two_calls",
            "leaf",
            "scaled",
        ]
        .map(|function| symbol(&reference, function));
        // None of these is reached by a direct call from main.
        assert!(
            callbacks.iter().all(|address| !before.contains(address)),
            "{name}"
        );
        let found: Vec<_> = callbacks.iter().filter(|a| gained.contains(a)).collect();
        eprintln!("{name}: {} of {} callbacks", found.len(), callbacks.len());
        if flags[0] == "-O0" {
            // Unoptimized code keeps the frame-pointer prologue everywhere;
            // `scaled` follows from the recovered callbacks' direct calls.
            assert_eq!(found.len(), callbacks.len(), "{name}: {gained:x?}");
        }
    }
}

// Calls to functions that never return end their block: the bytes after
// them, often the next function, are not their successor. Truth comes from
// the unstripped twin's symbol extents; stripped discovery never sees it.
#[test]
fn no_return_calls_end_blocks_and_keep_neighbours_separate() {
    use ghidra_rust::model::NoReturnEvidence;
    let directory = tempfile::tempdir().unwrap();
    let source = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/noreturn.c"
    ));
    for flags in [
        ["-O0", "-fno-pie", "-no-pie"],
        ["-O0", "-fPIE", "-pie"],
        ["-O2", "-fno-pie", "-no-pie"],
        ["-O2", "-fPIE", "-pie"],
    ] {
        let name = flags.join("");
        let args = [&flags[..], &["-fstack-protector-all"]].concat();
        let reference = compile(
            directory.path(),
            &format!("{name}-symbols"),
            source,
            &args,
            false,
        );
        let extent = |function: &str| {
            let bytes = std::fs::read(&reference).unwrap();
            let image = object::File::parse(bytes.as_slice()).unwrap();
            let symbol = image
                .symbols()
                .find(|symbol| symbol.name().ok() == Some(function))
                .unwrap_or_else(|| panic!("{function} symbol"));
            symbol.address()..symbol.address() + symbol.size()
        };
        let [die_exit, die_abort, after_abort, guarded] =
            ["die_exit", "die_abort", "after_abort", "guarded"].map(extent);

        let (mut worker, _) = open(&reference);
        for function in [&die_exit, &die_abort, &guarded] {
            let Response::Graph { view } = request(
                &mut worker,
                Request::Graph {
                    address: function.start,
                },
            ) else {
                panic!("{name}: no graph");
            };
            // Every decoded instruction stays inside the function itself.
            for block in &view.blocks {
                for instruction in &block.instructions {
                    assert!(
                        function.contains(&instruction.address),
                        "{name}: {:#x} outside {function:x?}",
                        instruction.address
                    );
                }
            }
            let ended: Vec<_> = view
                .calls
                .iter()
                .filter(|c| c.no_return.is_some())
                .collect();
            assert!(!ended.is_empty(), "{name}: {:?}", view.calls);
            for call in ended {
                assert_eq!(call.no_return, Some(NoReturnEvidence::NamedTarget));
                let block = view
                    .blocks
                    .iter()
                    .find(|b| b.instructions.iter().any(|i| i.address == call.address))
                    .unwrap();
                assert_eq!(block.instructions.last().unwrap().address, call.address);
                assert!(!view.edges.iter().any(|edge| edge.source == block.address));
            }
            assert!(
                !view
                    .warnings
                    .iter()
                    .any(|w| w.contains("another known function")),
                "{name}: {:?}",
                view.warnings
            );
        }
        let response = request(
            &mut worker,
            Request::Decompile {
                address: die_exit.start,
            },
        );
        let Response::Decompiled { text, .. } = response else {
            panic!("{name}: {response:?}");
        };
        assert!(!text.contains("puts"), "{name}: {text}");

        // Stripped: a neighbour after a no-return call is its own function,
        // recovered from its prologue, and owns its own calls.
        let binary = compile(directory.path(), &name, source, &args, true);
        let (mut worker, info) = open(&binary);
        let (functions, state) = discover_batches(&mut worker, &info, true);
        let report = state.snapshot();
        for owner in [&die_exit, &die_abort] {
            assert!(
                report
                    .references
                    .iter()
                    .filter(|r| r.caller == owner.start)
                    .all(|r| owner.contains(&r.address)),
                "{name}: {:?}",
                report.references
            );
        }
        if flags[0] == "-O0" {
            assert!(
                functions.iter().any(|f| f.address == after_abort.start),
                "{name}: after_abort not recovered"
            );
        }
    }
}
