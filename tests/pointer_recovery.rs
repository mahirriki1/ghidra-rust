//! Original corpus, analyzed stripped; truth is used only after discovery.
#![cfg(target_os = "linux")]
mod differential;
mod inventory;

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::discovery::Discovery;
use ghidra_rust::model::*;

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
    loop {
        assert!(started.elapsed() < Duration::from_secs(60));
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                if !matches!(reply.response, Response::Progress { .. }) {
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
            path: path.to_string_lossy().into(),
        },
    ) else {
        panic!()
    };
    info
}
fn discover(path: &Path, restart: bool) -> (BinaryInfo, Discovery, Vec<FunctionInfo>) {
    let mut worker = worker(path);
    let info = open(&mut worker, path);
    let mut state = Discovery::new(
        Some(info.entry),
        info.functions.iter().map(|f| f.address),
        false,
    );
    state.enable_patterns(&info);
    let mut inventory = inventory::Inventory::default();
    let mut epoch = 1;
    let mut restarted = false;
    for _ in
        0..MAX_POINTER_STEPS + MAX_PATTERN_CURSOR_STEPS + MAX_FUNCTIONS / MAX_ANALYSIS_FUNCTIONS
    {
        let Some(batch_request) = state.begin(1, epoch, 0) else {
            break;
        };
        // Replace the real contained worker after a table prefix has committed.
        if restart
            && !restarted
            && matches!(&batch_request, Request::DiscoverBatch { patterns: Some(DiscoveryCursor::Pointers(PointerCursor { phase: PointerPhase::Tables, position, .. })), .. } if *position > 0)
        {
            let first = batch_request.clone();
            worker.send(first).unwrap();
            drop(worker);
            state.interrupt();
            worker = self::worker(path);
            open(&mut worker, path);
            for functions in sync_chunks(inventory.functions()) {
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
            epoch += 1;
            restarted = true;
            continue;
        }
        let batch_request = inventory.bind(batch_request);
        let Response::DiscoveryBatch { mut batch } = request(&mut worker, batch_request.clone())
        else {
            panic!()
        };
        inventory
            .commit(&mut state, &info, &batch_request, &mut batch)
            .unwrap();
    }
    assert_eq!(state.remaining(), 0);
    assert!(!state.scanning());
    if restart {
        assert!(restarted);
    }
    state.save().validate(&info).unwrap();
    (info, state, inventory.functions().to_vec())
}

#[test]
fn stripped_o2_bank_tail_boundaries_and_replacement() {
    let directory = tempfile::tempdir().unwrap();
    for (id, restart) in [("O2-nopie-stripped", false), ("O2-pie-stripped", true)] {
        let (cases, _) = differential::corpus(directory.path(), Some(id)).unwrap();
        let case = &cases[0];
        let (_, state, functions) = discover(&case.path, restart);
        let recovered: BTreeSet<_> = functions
            .iter()
            .map(|f| f.address - case.load_base)
            .collect();
        let truth = case.truth.as_ref().unwrap()["functions"]
            .as_array()
            .unwrap();
        let primary: Vec<_> = truth.iter().filter(|f| f["scope"] == "primary").collect();
        let address =
            |f: &serde_json::Value| differential::parse_hex(f["rva"].as_str().unwrap()).unwrap();
        let hits = primary
            .iter()
            .filter(|f| recovered.contains(&address(f)))
            .count();
        let misses: Vec<_> = primary
            .iter()
            .filter(|f| !recovered.contains(&address(f)))
            .map(|f| &f["names"])
            .collect();
        eprintln!(
            "{id}: {hits}/{} primary; {} total; missing {misses:?}",
            primary.len(),
            functions.len()
        );
        assert!(hits >= 321);
        let register = truth
            .iter()
            .find(|f| {
                f["names"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n == "register_tm_clones")
            })
            .unwrap();
        assert!(recovered.contains(&address(register)));
        assert_eq!(
            state
                .admission(address(register) + case.load_base)
                .unwrap()
                .reason,
            AdmissionReason::CrtForwarder
        );

        let bank: Vec<_> = primary
            .iter()
            .filter(|f| {
                f["names"].as_array().unwrap().iter().any(|n| {
                    n.as_str()
                        .unwrap()
                        .strip_prefix("bench_many_")
                        .is_some_and(|n| n.len() == 3 && n.bytes().all(|b| b.is_ascii_digit()))
                })
            })
            .collect();
        assert_eq!(bank.len(), 300);
        for function in bank {
            let entry = address(function) + case.load_base;
            assert!(recovered.contains(&address(function)));
            assert_eq!(
                state.admission(entry).unwrap().reason,
                AdmissionReason::PointerTable
            );
        }
        for &entry in &recovered {
            for function in &primary {
                let low = address(function);
                let size = function["size"].as_u64().unwrap();
                assert!(
                    !(low < entry && entry < low + size),
                    "false interior entry {entry:#x}"
                );
            }
        }
    }
}

#[test]
fn small_tables_offcuts_labels_singletons_and_unwind_free_precision() {
    use object::{Object, ObjectSymbol};
    let dir = tempfile::tempdir().unwrap();
    for pie in [false, true] {
        for unwind in [false, true] {
            let original = dir.path().join("pointers");
            let stripped = dir.path().join("pointers-stripped");
            let mut gcc = std::process::Command::new("gcc");
            gcc.args(["-nostdlib", "-Wl,-e,_start", "-Wl,--no-as-needed", "-lc"]);
            gcc.arg(if pie { "-pie" } else { "-no-pie" });
            if !unwind {
                gcc.arg("-DNO_UNWIND");
            }
            assert!(
                gcc.arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/pointer-tables.S"
                ))
                .arg("-o")
                .arg(&original)
                .status()
                .unwrap()
                .success()
            );
            let bytes = std::fs::read(&original).unwrap();
            let file = object::File::parse(bytes.as_slice()).unwrap();
            let address = |name: &str| {
                file.symbols()
                    .find(|s| s.name() == Ok(name))
                    .unwrap()
                    .address()
            };
            let expected: BTreeSet<_> = file
                .symbols()
                .filter(|s| s.kind() == object::SymbolKind::Text && s.size() != 0)
                .map(|s| s.address())
                .collect();
            assert!(
                std::process::Command::new("strip")
                    .args(["--strip-all", "-o"])
                    .arg(&stripped)
                    .arg(&original)
                    .status()
                    .unwrap()
                    .success()
            );
            let (_, state, functions) = discover(&stripped, false);
            for function in &functions {
                assert!(
                    expected.contains(&function.address),
                    "unexpected {function:?}"
                );
            }
            for name in ["init_callback", "fini_callback", "_init", "_fini"] {
                let entry = address(name);
                assert!(
                    functions.iter().any(|f| f.address == entry),
                    "missing {name} (pie {pie}, unwind {unwind})"
                );
                assert_eq!(
                    state.admission(entry).unwrap().reason,
                    AdmissionReason::InitMetadata
                );
            }
            let forward = address("crt_forward_target");
            assert!(functions.iter().any(|f| f.address == forward));
            let witness = state.admission(forward).unwrap();
            assert_eq!(witness.reason, AdmissionReason::CrtForwarder);
            assert_eq!(witness.owner, Some(address("init_callback")));
            for name in ["singleton", "computed_label_a", "computed_label_b"] {
                assert!(
                    functions.iter().all(|f| f.address != address(name)),
                    "admitted {name}"
                );
            }
            for name in ["pointer_a", "pointer_b"] {
                let admitted = functions.iter().any(|f| f.address == address(name));
                assert_eq!(admitted, unwind, "{name} (pie {pie})");
            }
            assert!(state.recovery_accounting().cursor_steps >= 4);
        }
    }
}
