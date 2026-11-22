//! The opt-in host trace of Sibling phases through the real Analyzer, in a
//! dedicated host process: this binary has exactly one test, which owns
//! trace initialization and the single flush. Built only with the
//! `performance` feature: `cargo test --features performance --test
//! sibling_trace`.
#![cfg(all(feature = "performance", any(target_os = "linux", windows)))]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, serde::Deserialize)]
struct Record {
    request: u64,
    phase: String,
    start_us: u64,
    elapsed_us: u64,
    value: u64,
    dropped: u64,
}

/// A DWARF build of `sample.c`: GCC on Linux, the configured VS-clang PE
/// on Windows.
fn fixture(directory: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let path = directory.join("sample");
        let built = std::process::Command::new("gcc")
            .args(["-O0", "-fno-pie", "-no-pie", "-fno-inline", "-g"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sample.c"
            ))
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap();
        assert!(built.success());
        Some(path)
    }
    #[cfg(windows)]
    {
        let _ = directory;
        let Some(path) = std::env::var_os("GHIDRA_RUST_TEST_PE_DWARF") else {
            eprintln!("Set GHIDRA_RUST_TEST_PE_DWARF using scripts/build-windows.ps1");
            return None;
        };
        Some(PathBuf::from(path))
    }
}

fn function(api: &mut ghidra_rust::headless::Analyzer, address: u64) {
    use ghidra_rust::headless::{Command, Output};
    let Output::Function { .. } = api
        .execute(Command::Function {
            address,
            refresh: true,
        })
        .unwrap()
    else {
        panic!("not a function result")
    };
}

fn address(api: &mut ghidra_rust::headless::Analyzer, name: &str) -> u64 {
    use ghidra_rust::headless::{Command, Output};
    let Output::Info { info, .. } = api.execute(Command::Info {}).unwrap() else {
        panic!("not info")
    };
    info.functions
        .iter()
        .find(|function| function.name == name)
        .unwrap()
        .address
}

#[test]
fn sibling_phases_are_traced_per_logical_request() {
    let traces = tempfile::tempdir().unwrap();
    let inputs = tempfile::tempdir().unwrap();
    let Some(path) = fixture(inputs.path()) else {
        return;
    };
    // SAFETY: this binary runs this one test; no other thread reads or
    // writes the environment while it is set, before any worker starts.
    unsafe { std::env::set_var("GHIDRA_RUST_PERF_DIR", traces.path()) };
    ghidra_rust::performance::init().unwrap();
    let mut api = ghidra_rust::headless::Analyzer::open(
        ghidra_rust::headless::Input::Binary(path),
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless")),
        ghidra_rust::headless::Options {
            use_debug_info: Some(true),
            worker_arguments: vec![ghidra_rust::worker::NO_FORK_ARGUMENT.into()],
            optional_floor: Some(Duration::from_secs(10)),
            ..Default::default()
        },
    )
    .unwrap();
    let main = address(&mut api, "main");
    // One completed attempt, then one forced setup cutoff.
    function(&mut api, main);
    api.set_optional_windows(None, Some(Duration::from_millis(5)));
    function(&mut api, main);
    drop(api);
    ghidra_rust::performance::flush().unwrap();

    let files = std::fs::read_dir(traces.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    let [file] = &files[..] else {
        panic!("expected one trace file: {files:?}");
    };
    let records: Vec<Record> = std::fs::read_to_string(file)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let health = records
        .iter()
        .find(|record| record.phase == "trace_health")
        .expect("trace health");
    assert_eq!(health.dropped, 0);
    // Every sibling record belongs to a nonzero logical request.
    let mut attempts: BTreeMap<u64, Vec<&Record>> = BTreeMap::new();
    for record in records
        .iter()
        .filter(|record| record.phase.starts_with("sibling_"))
    {
        assert_ne!(record.request, 0, "{record:?}");
        attempts.entry(record.request).or_default().push(record);
    }
    assert_eq!(attempts.len(), 2, "{attempts:#?}");
    let phase = |attempt: &[&Record], name: &str| -> Vec<(u64, u64, u64)> {
        attempt
            .iter()
            .filter(|record| record.phase == name)
            .map(|record| (record.start_us, record.elapsed_us, record.value))
            .collect()
    };
    let cutoffs = |attempt: &[&Record]| {
        attempt
            .iter()
            .filter(|record| record.phase.starts_with("sibling_cutoff_"))
            .count()
    };
    let (&completed, &cut) = (
        attempts.keys().next().unwrap(),
        attempts.keys().nth(1).unwrap(),
    );
    // The completed attempt: publication, then startup, Open, replay and
    // the render in order, one settlement, no cutoff.
    let attempt = &attempts[&completed];
    let [(published, _, _)] = phase(attempt, "sibling_published")[..] else {
        panic!("{attempt:#?}");
    };
    let mut previous = published;
    for name in [
        "sibling_startup",
        "sibling_open",
        "sibling_replay",
        "sibling_render",
    ] {
        let [(start, elapsed, _)] = phase(attempt, name)[..] else {
            panic!("{name}: {attempt:#?}");
        };
        assert!(start >= previous, "{name} starts before the previous phase");
        previous = start + elapsed;
    }
    assert_eq!(phase(attempt, "sibling_settlement").len(), 1);
    assert_eq!(phase(attempt, "sibling_settlement")[0].2, 1, "finished");
    assert_eq!(cutoffs(attempt), 0);
    assert_eq!(phase(attempt, "sibling_setup_observed_us").len(), 1);
    // The forced cutoff: one typed setup cutoff after publication, one
    // settlement with that outcome, and no render sent.
    let attempt = &attempts[&cut];
    let [(published, _, budget)] = phase(attempt, "sibling_published")[..] else {
        panic!("{attempt:#?}");
    };
    assert!(budget <= 5, "{attempt:#?}");
    assert_eq!(cutoffs(attempt), 1, "{attempt:#?}");
    let cutoff = attempt
        .iter()
        .find(|record| record.phase.starts_with("sibling_cutoff_"))
        .unwrap();
    assert_ne!(cutoff.phase, "sibling_cutoff_render");
    assert!(cutoff.start_us >= published);
    assert_eq!(cutoff.value, 1, "limited by the setup allowance");
    let settlement = phase(attempt, "sibling_settlement");
    assert_eq!(settlement.len(), 1);
    assert!((40..44).contains(&settlement[0].2), "{settlement:?}");
    assert!(phase(attempt, "sibling_render").is_empty());
    assert!(phase(attempt, "sibling_settlement")[0].0 >= published);
}
