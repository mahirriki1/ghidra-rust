//! The production coordinator's behavioral contract, independent of GUI state.
use ghidra_rust::function_presentation::{PreparedDecompilation, PreparedGraph};
use ghidra_rust::function_results::{FunctionResults, Invalidation};
use ghidra_rust::model::*;
use ghidra_rust::result_store::ResultOrigin;
use ghidra_rust::semantic::{LocalIdentity, LocalRename, LocalStorage, SemanticInfo};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn functions() -> Vec<FunctionInfo> {
    [0x1000, 0x1040]
        .into_iter()
        .map(|address| FunctionInfo {
            address,
            name: format!("f{address:x}"),
        })
        .collect()
}
fn ready(results: &mut FunctionResults) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while results.preparing() {
        assert!(Instant::now() < deadline);
        results.poll_inputs();
        std::thread::yield_now();
    }
}
fn opened() -> FunctionResults {
    let mut results = FunctionResults::default();
    results.open(&"a".repeat(64), &[]);
    results.update_inputs(functions(), vec![]);
    ready(&mut results);
    results
}
fn graph(address: u64) -> PreparedGraph {
    PreparedGraph::new(FunctionView {
        address,
        blocks: vec![BasicBlock {
            address,
            instructions: vec![Instruction {
                address,
                bytes: vec![0xc3],
                mnemonic: "ret".into(),
                operands: String::new(),
            }],
        }],
        edges: vec![],
        calls: vec![],
        warnings: vec![],
    })
}
fn code(address: u64, text: &str) -> PreparedDecompilation {
    PreparedDecompilation::validate(
        address,
        text.into(),
        vec![],
        SemanticInfo::default(),
        &[SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: 256,
            file_offset: 0,
            file_size: 256,
            executable: true,
        }],
    )
    .unwrap()
}
fn populate(results: &mut FunctionResults, address: u64, text: &str) {
    let binding = results
        .binding(address, results.local_state(address))
        .unwrap();
    results.admit_graph(
        Some(&binding),
        graph(address),
        ResultOrigin::Computed,
        Some(address),
    );
    results.admit_decompilation(
        Some(&binding),
        code(address, text),
        ResultOrigin::Computed,
        Some(address),
    );
}

#[test]
fn stored_aba_preserves_original_output_and_refresh_requires_recomputation() {
    let mut results = opened();
    populate(&mut results, 0x1000, "A before shared type inference");
    let first = results.lookup(0x1000, "").decompiled.unwrap().0;
    populate(
        &mut results,
        0x1040,
        "B teaches the warm worker a global type",
    );
    for address in [0x1000, 0x1040, 0x1000] {
        let hit = results.lookup(address, "");
        assert!(FunctionResults::miss_requests(&hit, address, true).is_empty());
    }
    assert!(Arc::ptr_eq(
        &first,
        &results.lookup(0x1000, "").decompiled.unwrap().0
    ));
    let superseded = results.binding(0x1000, String::new()).unwrap();
    results.refresh(0x1000);
    assert!(!results.current(Some(&superseded)));
    let miss = results.lookup(0x1000, "");
    assert!(matches!(
        FunctionResults::miss_requests(&miss, 0x1000, true).as_slice(),
        [Request::Graph { address: 0x1000 }]
    ));
    populate(
        &mut results,
        0x1000,
        "A recomputed with current shared global types",
    );
    assert_ne!(
        results.lookup(0x1000, "").decompiled.unwrap().0.text(),
        first.text()
    );
    assert!(results.lookup(0x1040, "").complete(true));
}

#[test]
fn successful_empty_decompilation_is_a_hit_and_partial_graph_requests_only_code() {
    let mut results = opened();
    let binding = results.binding(0x1000, String::new()).unwrap();
    results.admit_graph(Some(&binding), graph(0x1000), ResultOrigin::Saved, None);
    let hit = results.lookup(0x1000, "");
    assert!(FunctionResults::miss_requests(&hit, 0x1000, false).is_empty());
    assert!(matches!(
        FunctionResults::miss_requests(&hit, 0x1000, true).as_slice(),
        [Request::Decompile { address: 0x1000 }]
    ));
    results.admit_decompilation(
        Some(&binding),
        code(0x1000, ""),
        ResultOrigin::Computed,
        None,
    );
    assert!(results.lookup(0x1000, "").complete(true));
}

#[test]
fn local_edits_keep_other_functions_and_hash_unapplied_identity_records() {
    let mut results = opened();
    populate(&mut results, 0x1000, "A");
    populate(&mut results, 0x1040, "B");
    let old = results.lookup(0x1040, "").decompiled.unwrap().0;
    let rename = LocalRename {
        identity: LocalIdentity {
            function: 0x1000,
            engine: "incompatible unapplied record".into(),
            storage: LocalStorage::Stack,
            offset: 8,
            size: 4,
            verification: "a".repeat(64),
        },
        name: "unapplied".into(),
    };
    let old_binding = results.binding(0x1000, String::new()).unwrap();
    results.inputs_changed(Invalidation::LocalNames);
    results.refresh_decompilation(0x1000, Invalidation::LocalNames);
    results.update_inputs(functions(), vec![rename.clone()]);
    ready(&mut results);
    assert!(!results.current(Some(&old_binding)));
    let state = results.local_state(0x1000);
    assert!(!state.is_empty());
    let hit = results.lookup(0x1000, &state);
    assert!(hit.graph.is_some() && hit.decompiled.is_none());
    assert!(Arc::ptr_eq(
        &old,
        &results.lookup(0x1040, "").decompiled.unwrap().0
    ));
    let mut changed = rename;
    changed.identity.offset += 4;
    results.update_inputs(functions(), vec![changed]);
    ready(&mut results);
    assert_ne!(state, results.local_state(0x1000));
}

#[test]
fn identical_content_at_a_later_revision_is_compatible_but_name_and_inventory_changes_are_not() {
    let mut results = opened();
    populate(&mut results, 0x1000, "A");
    let original = results.lookup(0x1000, "").decompiled.unwrap().0;
    results.inputs_changed(Invalidation::FunctionNames);
    results.update_inputs(functions(), vec![]);
    ready(&mut results);
    assert!(Arc::ptr_eq(
        &original,
        &results.lookup(0x1000, "").decompiled.unwrap().0
    ));
    let mut renamed = functions();
    renamed[1].name = "callee_renamed".into();
    results.update_inputs(renamed, vec![]);
    ready(&mut results);
    assert!(!results.lookup(0x1000, "").complete(false));
    populate(&mut results, 0x1000, "A with callee_renamed");
    let mut inventory = functions();
    inventory.push(FunctionInfo {
        address: 0x1080,
        name: "new".into(),
    });
    results.update_inputs(inventory, vec![]);
    ready(&mut results);
    assert!(!results.lookup(0x1000, "").complete(false));
}
#[cfg(any(target_os = "linux", windows))]
#[allow(dead_code)]
mod common;

#[cfg(any(target_os = "linux", windows))]
fn worker_cache_case(path: &std::path::Path, a: u64, b: u64) {
    use ghidra_rust::client::{WorkerClient, WorkerEvent};
    fn request(worker: &mut WorkerClient, request: Request, count: &mut usize) -> Response {
        *count += 1;
        let id = worker.send(request).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match worker.poll() {
                Some(WorkerEvent::Reply(reply)) => {
                    assert_eq!(reply.id, id);
                    if matches!(reply.response, Response::Progress { .. }) {
                        continue;
                    }
                    return reply.response;
                }
                Some(WorkerEvent::Failed(error)) => panic!("Worker failed: {error}"),
                None => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        path,
        std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    )
    .unwrap();
    let mut count = 0;
    let Response::Opened { info, .. } = request(
        &mut worker,
        Request::Open {
            path: path.to_string_lossy().into_owned(),
        },
        &mut count,
    ) else {
        panic!("Open");
    };
    let mut results = FunctionResults::default();
    results.open(&info.sha256, &[]);
    results.update_inputs(info.functions.clone(), vec![]);
    ready(&mut results);
    let mut original = None;
    for address in [a, b, a] {
        let hit = results.lookup(address, "");
        let misses = FunctionResults::miss_requests(&hit, address, true);
        if hit.complete(true) {
            assert!(misses.is_empty());
            assert_eq!(
                count, 5,
                "A/B use two graph/code pairs plus Open; revisit uses none"
            );
            assert!(Arc::ptr_eq(
                &hit.decompiled.unwrap().0,
                original.as_ref().unwrap()
            ));
            continue;
        }
        let binding = results.binding(address, String::new()).unwrap();
        let Response::Graph { view } = request(&mut worker, Request::Graph { address }, &mut count)
        else {
            panic!("Graph");
        };
        results.admit_graph(
            Some(&binding),
            PreparedGraph::validate(view, &info).unwrap(),
            ResultOrigin::Computed,
            Some(address),
        );
        let Response::Decompiled {
            text,
            mappings,
            semantics,
            ..
        } = request(&mut worker, Request::Decompile { address }, &mut count)
        else {
            panic!("Code");
        };
        let code = results.admit_decompilation(
            Some(&binding),
            PreparedDecompilation::validate(address, text, mappings, semantics, &info.sections)
                .unwrap(),
            ResultOrigin::Computed,
            Some(address),
        );
        if address == a {
            original = Some(code);
        }
    }
    results.refresh(a);
    assert!(!results.lookup(a, "").complete(false));
    let Response::Graph { view } = request(&mut worker, Request::Graph { address: a }, &mut count)
    else {
        panic!();
    };
    let binding = results.binding(a, String::new()).unwrap();
    results.admit_graph(
        Some(&binding),
        PreparedGraph::validate(view, &info).unwrap(),
        ResultOrigin::Computed,
        Some(a),
    );
    let Response::Decompiled {
        text,
        mappings,
        semantics,
        ..
    } = request(&mut worker, Request::Decompile { address: a }, &mut count)
    else {
        panic!();
    };
    let fresh = results.admit_decompilation(
        Some(&binding),
        PreparedDecompilation::validate(a, text, mappings, semantics, &info.sections).unwrap(),
        ResultOrigin::Computed,
        Some(a),
    );
    assert!(!Arc::ptr_eq(&fresh, original.as_ref().unwrap()));
    assert_eq!(count, 7);
}

#[cfg(any(target_os = "linux", windows))]
#[test]
fn contained_arm64_elf_pe_and_macho_revisits_use_the_stored_indivisible_result() {
    for (name, (bytes, base)) in [
        ("ELF", common::elf(true)),
        ("PE", common::pe()),
        ("MachO", common::macho()),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        worker_cache_case(&path, base, base + 48);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn contained_x86_fixture_revisits_use_zero_worker_requests() {
    use object::{Object, ObjectSymbol};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sample");
    assert!(
        std::process::Command::new("gcc")
            .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sample.c"
            ))
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let bytes = std::fs::read(&path).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    let address = |name| {
        image
            .symbols()
            .find(|s| s.name().ok() == Some(name))
            .unwrap()
            .address()
    };
    worker_cache_case(&path, address("branch_loop"), address("read_write_word"));
}

#[test]
fn production_payload_churn_is_bounded_and_save_pins_cannot_force_admission() {
    let budget = 48 * 1024;
    let mut results = FunctionResults::new(budget);
    results.open(&"a".repeat(64), &[]);
    results.update_inputs(functions(), vec![]);
    ready(&mut results);
    let text = format!("/*{}*/", "x".repeat(28 * 1024));
    let mut peak = 0;
    for step in 0..256 {
        populate(&mut results, 0x1000 + 4 * (step % 32), &text);
        let usage = results.usage();
        peak = peak.max(usage.charged);
        assert!(usage.charged <= budget);
    }
    assert!(results.counters().evicted > 0);
    let pin = results.lookup(0x107c, "").decompiled.unwrap().0;
    for step in 0..128 {
        populate(&mut results, 0x1000 + 4 * (step % 16), &text);
        let usage = results.usage();
        peak = peak.max(usage.charged);
        assert!(usage.charged <= budget);
        assert!(usage.pinned >= pin.bytes());
    }
    assert!(results.counters().uncached > 0);
    assert_eq!(
        results.usage().uncached,
        0,
        "temporary uncached results were released"
    );
    results.refresh(0x107c);
    let held = results.usage().charged;
    drop(pin);
    assert!(results.usage().charged < held);
    println!(
        "Production payload churn: 384 visits, budget={budget}, peak_charged={peak}, evicted_bytes={}, uncached_admissions={}",
        results.counters().evicted_bytes,
        results.counters().uncached
    );
}

#[test]
fn address_evidence_is_charged_once_per_publication_until_save_pins_drop() {
    use ghidra_rust::call_analysis::CallIndex;
    let publication = |count: u64| {
        Arc::new(CallIndex::new(CallAnalysis {
            addresses: Some(Box::new(AddressAnalysis {
                references: (0..count)
                    .map(|n| AddressReference {
                        function: 0x1000,
                        address: 0x1000 + n,
                        target: 0x10_0000 + n,
                        provenance: DataProvenance::InstructionLocal,
                    })
                    .collect(),
                candidates_examined: count as usize,
                ..Default::default()
            })),
            ..Default::default()
        }))
    };
    let mut results = opened();
    let baseline = results.usage().charged;
    let empty = publication(0);
    assert!(results.retain_discovery(&empty, &[]));
    let empty_charge = results.usage().charged - baseline;
    let count = MAX_ADDRESS_REFERENCES as u64;
    let large = publication(count);
    assert!(results.retain_discovery(&large, &[]));
    let large_charge = results.usage().charged - baseline - empty_charge;
    // Evidence rows plus both target and owner index allocations.
    let rows = count as usize * std::mem::size_of::<AddressReference>();
    let index = 2 * count as usize * std::mem::size_of::<usize>();
    assert!(large_charge >= empty_charge + rows + index);
    // Retaining the same publication again charges nothing more.
    assert!(results.retain_discovery(&large, &[]));
    assert_eq!(
        results.usage().charged - baseline - empty_charge,
        large_charge
    );
    // A project save keeps the evidence snapshot charged after the index
    // and publication are replaced, until the save itself drops.
    let saved = Arc::clone(large.snapshot());
    drop(large);
    let held = results.usage().charged;
    assert!(held > baseline + empty_charge);
    assert!(held - baseline - empty_charge >= rows);
    drop(saved);
    assert_eq!(results.usage().charged, baseline + empty_charge);
}
