//! Run each logger in its own process without mutating shared environment.
#![cfg(feature = "performance")]

#[test]
#[ignore = "subprocess entry point"]
fn trace_child() {
    ghidra_rust::performance::init().unwrap();
    let _context = ghidra_rust::performance::context(42);
    ghidra_rust::performance::span("known_span").finish(7);
    ghidra_rust::performance::navigation_begin(77);
    ghidra_rust::performance::navigation_frame(77, false, true);
    ghidra_rust::performance::navigation_frame(77, true, false);
    for value in 0..120_000 {
        ghidra_rust::performance::event("bounded_event", value);
    }
    ghidra_rust::performance::flush().unwrap();
    ghidra_rust::performance::event("after_shutdown", 0);
}

#[test]
fn trace_is_exclusive_bounded_and_reports_saturation() {
    let directory = tempfile::tempdir().unwrap();
    let sentinel = directory.path().join("existing.jsonl");
    std::fs::write(&sentinel, b"preserve this file").unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "trace_child"])
        .env("GHIDRA_RUST_PERF_DIR", directory.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve this file");
    let traces: Vec<_> = std::fs::read_dir(directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path != &sentinel)
        .collect();
    assert_eq!(traces.len(), 1);
    let text = std::fs::read_to_string(&traces[0]).unwrap();
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(records.len() <= 100_000);
    let code = records
        .iter()
        .position(|record| {
            record["phase"] == "navigation_frame_submission"
                && record["request"] == 77
                && record["value"] == 1
        })
        .unwrap();
    let listing = records
        .iter()
        .position(|record| record["phase"] == "listing_frame_submission" && record["request"] == 77)
        .unwrap();
    assert!(
        listing > code,
        "Later listing submission was discarded after pseudocode"
    );
    assert!(
        !records
            .iter()
            .any(|record| record["phase"] == "after_shutdown")
    );
    assert_eq!(records.last().unwrap()["phase"], "trace_health");
    assert!(records.last().unwrap()["dropped"].as_u64().unwrap() > 0);
    assert!(records.iter().any(|record| record["phase"] == "known_span"
        && record["request"] == 42
        && record["value"] == 7));
    assert!(
        records
            .iter()
            .any(|record| record["phase"] == "trace_limit_reached"
                || record["dropped"].as_u64().unwrap() > 0)
    );
}

#[test]
fn unusable_trace_directory_fails_explicitly() {
    let directory = tempfile::tempdir().unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "trace_child"])
        .env("GHIDRA_RUST_PERF_DIR", directory.path().join("missing"))
        .output()
        .unwrap();
    assert!(!child.status.success());
}
