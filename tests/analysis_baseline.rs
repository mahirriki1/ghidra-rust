//! Opt-in Linux analysis-client baseline, not a GUI or cross-tool benchmark.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod common;
mod inventory;

use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{Request, Response};
use ghidra_rust::{project, selection, session};
use object::{Object, ObjectSymbol};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);
const REPEATS: usize = 3;
const MAX_PROCESSES: usize = 16;
const MAX_THREADS: usize = 256;

#[derive(Clone, Copy, Debug, Serialize)]
struct Memory {
    processes: usize,
    rss_kib: u64,
    pss_kib: u64,
}

struct Sampler {
    last: Instant,
    samples: usize,
    peak_rss_kib: u64,
    peak_pss_kib: u64,
    max_processes: usize,
    // Birth ticks distinguish our descendants from later PID reuse. We never
    // signal a sampled PID; WorkerClient owns termination and reaping.
    children: BTreeMap<u32, u64>,
}

fn birth(pid: u32) -> Option<u64> {
    process_state(pid).map(|state| state.0)
}

fn process_state(pid: u32) -> Option<(u64, char)> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.raw_os_error() == Some(libc::ESRCH) =>
        {
            return None;
        }
        Err(error) => panic!("Cannot inspect process {pid}: {error}"),
    };
    // comm can contain spaces and ')'; fields after the final ')' start at3.
    let mut fields = stat
        .rsplit_once(')')
        .expect("Kernel process comm")
        .1
        .split_whitespace();
    let state = fields.next().unwrap().chars().next().unwrap();
    let ticks = fields
        .nth(18)
        .unwrap()
        .parse()
        .expect("Kernel process birth ticks");
    Some((ticks, state))
}

fn process_tree() -> Vec<u32> {
    let mut pending = VecDeque::from([std::process::id()]);
    let mut processes = BTreeSet::new();
    while let Some(pid) = pending.pop_front() {
        if !processes.insert(pid) {
            continue;
        }
        assert!(
            processes.len() <= MAX_PROCESSES,
            "Unexpected process count in baseline"
        );
        let tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("Cannot enumerate baseline process threads: {error}"),
        };
        // The worker is spawned from a test thread, not necessarily the thread
        // group leader. Reading only /task/<pid>/children misses that worker.
        for (index, task) in tasks.enumerate() {
            assert!(index < MAX_THREADS, "Unexpected thread count in baseline");
            let path = task.unwrap().path().join("children");
            let children = match fs::read_to_string(path) {
                Ok(children) => children,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("Cannot enumerate baseline children: {error}"),
            };
            for child in children.split_whitespace() {
                pending.push_back(child.parse().expect("Kernel child PID"));
            }
        }
    }
    processes.into_iter().collect()
}

fn kib(text: &str, key: &str) -> u64 {
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("Missing {key} memory metric"));
    let mut fields = value.split_whitespace();
    let amount = fields.next().unwrap().parse().expect("Kernel memory count");
    assert_eq!(fields.next(), Some("kB"));
    amount
}

impl Sampler {
    fn new() -> Self {
        Self {
            last: Instant::now(),
            samples: 0,
            peak_rss_kib: 0,
            peak_pss_kib: 0,
            max_processes: 0,
            children: BTreeMap::new(),
        }
    }

    fn sample(&mut self) -> Memory {
        let mut memory = Memory {
            processes: 0,
            rss_kib: 0,
            pss_kib: 0,
        };
        for pid in process_tree() {
            let Some((start, state)) = process_state(pid) else {
                continue;
            };
            if pid != std::process::id() {
                self.children.insert(pid, start);
            }
            if matches!(state, 'Z' | 'X') {
                continue;
            }
            let maps = match fs::read_to_string(format!("/proc/{pid}/smaps_rollup")) {
                Ok(maps) => maps,
                // A process which exited during enumeration has no resident
                // pages to attribute. Permission failures must not become zero.
                Err(_)
                    if process_state(pid).is_none_or(|(_, state)| matches!(state, 'Z' | 'X')) =>
                {
                    continue;
                }
                Err(error) => panic!("Cannot measure process {pid}: {error}"),
            };
            if birth(pid) != Some(start) {
                continue;
            }
            memory.processes += 1;
            memory.rss_kib = memory.rss_kib.checked_add(kib(&maps, "Rss:")).unwrap();
            memory.pss_kib = memory.pss_kib.checked_add(kib(&maps, "Pss:")).unwrap();
        }
        assert!(memory.processes > 0);
        self.last = Instant::now();
        self.samples += 1;
        self.peak_rss_kib = self.peak_rss_kib.max(memory.rss_kib);
        self.peak_pss_kib = self.peak_pss_kib.max(memory.pss_kib);
        self.max_processes = self.max_processes.max(memory.processes);
        memory
    }

    fn request(&mut self, worker: &mut WorkerClient, request: Request) -> (Response, f64, Memory) {
        let start = Instant::now();
        let id = worker.send(request).unwrap();
        let mut previous = None;
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "Baseline request timed out"
            );
            if self.last.elapsed() >= SAMPLE_INTERVAL {
                self.sample();
            }
            match worker.poll() {
                Some(WorkerEvent::Reply(reply)) => {
                    assert_eq!(reply.id, id);
                    if let Response::Progress { progress } = reply.response {
                        progress.validate_after(previous.as_ref()).unwrap();
                        previous = Some(progress);
                        continue;
                    }
                    assert!(
                        !matches!(reply.response, Response::Error { .. }),
                        "{:?}",
                        reply.response
                    );
                    let elapsed_ms = start.elapsed().as_secs_f64() * 1000.;
                    return (reply.response, elapsed_ms, self.sample());
                }
                Some(WorkerEvent::Failed(error)) => {
                    panic!("Contained baseline worker failed: {error}")
                }
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

struct Fixture {
    name: &'static str,
    path: PathBuf,
    function: u64,
}

fn command_text(command: &mut Command) -> String {
    let output = command.output().expect("Baseline metadata command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn fixtures(directory: &Path) -> Vec<Fixture> {
    let c = directory.join("original-x86-64-ELF");
    let compiled = Command::new("gcc")
        .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.c"
        ))
        .arg("-o")
        .arg(&c)
        .output()
        .expect("Baseline requires GCC");
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let bytes = fs::read(&c).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    let function = image
        .symbols()
        .find(|symbol| symbol.name().ok() == Some("branch_loop"))
        .unwrap()
        .address();
    let mut fixtures = vec![Fixture {
        name: "x86-64-ELF",
        path: c,
        function,
    }];
    for (name, (bytes, base), offset) in [
        ("ARM64-ELF", common::elf(true), 48),
        ("ARM64-PE", common::pe(), 48),
        ("ARM64-MachO", common::macho(), 48),
        ("ARM64-PE-metadata", common::arm64_pe_metadata(), 0xa0),
        ("ARM64-PE-metadata-8MiB", common::arm64_pe_metadata(), 0xa0),
    ] {
        let path = directory.join(name);
        fs::write(&path, bytes).unwrap();
        if name.ends_with("8MiB") {
            // File-backed padding exercises full-image retention without
            // allocating a second large fixture buffer in the client process.
            fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(8 * 1024 * 1024)
                .unwrap();
        }
        fixtures.push(Fixture {
            name,
            path,
            function: base + offset,
        });
    }
    let source = directory.join("many-seeds.c");
    let mut text = String::from("int f299(void);\nint f000(void) { return f299() + 1; }\n");
    for n in 1..300 {
        text.push_str(&format!("int f{n:03}(void) {{ return {n}; }}\n"));
    }
    text.push_str("int main(void) { return f000(); }\n");
    fs::write(&source, text).unwrap();
    let path = directory.join("many-seeds");
    assert!(
        Command::new("gcc")
            .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
            .arg(&source)
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let bytes = fs::read(&path).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    let function = image
        .symbols()
        .find(|s| s.name().ok() == Some("f000"))
        .unwrap()
        .address();
    fixtures.push(Fixture {
        name: "x86-64-ELF-300-seeds",
        path,
        function,
    });
    fixtures
}

#[test]
#[ignore = "Opt-in instrumented Linux baseline; run --release --test analysis_baseline -- --ignored --nocapture"]
fn profile_contained_analysis_client() {
    if cfg!(debug_assertions) {
        panic!("Run the baseline with --release");
    }
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/analysis-baseline");
    fs::create_dir_all(&output).unwrap();
    let directory = tempfile::Builder::new()
        .prefix("fixtures-")
        .tempdir_in(&output)
        .unwrap();
    let fixtures = fixtures(directory.path());
    let executable = Path::new(env!("CARGO_BIN_EXE_ghidra-rust"));
    let executable_sha256 = session::fingerprint(executable).unwrap();
    let sampler_executable_sha256 =
        session::fingerprint(&std::env::current_exe().unwrap()).unwrap();
    let git_commit = command_text(Command::new("git").args(["rev-parse", "HEAD"]));
    let worktree_dirty =
        !command_text(Command::new("git").args(["status", "--porcelain"])).is_empty();
    let compiler = command_text(Command::new("rustc").arg("-vV"));
    let gcc = command_text(Command::new("gcc").arg("--version"));
    let mut rows = Vec::new();
    for fixture in fixtures {
        let input_sha256 = session::fingerprint(&fixture.path).unwrap();
        let input_bytes = fs::metadata(&fixture.path).unwrap().len();
        for repeat in 1..=REPEATS {
            let mut sampler = Sampler::new();
            let before_start = sampler.sample();
            let start = Instant::now();
            let mut worker = WorkerClient::start_using_executable(
                eframe::egui::Context::default(),
                &fixture.path,
                executable,
            )
            .unwrap();
            let spawn_ms = start.elapsed().as_secs_f64() * 1000.;
            let (Response::Opened { info }, open_ms, loaded_memory) = sampler.request(
                &mut worker,
                Request::Open {
                    path: fixture.path.to_string_lossy().into_owned(),
                },
            ) else {
                panic!("Expected Opened");
            };
            assert_eq!(info.sha256, input_sha256);
            let mut state = ghidra_rust::discovery::Discovery::new(
                ghidra_rust::call_analysis::code_address(&info, info.entry).then_some(info.entry),
                info.functions.iter().map(|f| f.address),
                info.functions_truncated,
            );
            let mut functions = info.functions.clone();
            let mut inventory = inventory::Inventory::default();
            let mut discover_ms = 0.;
            let mut reply_bytes = 0;
            let mut batch_metrics = Vec::new();
            while let Some(request) = state.begin(1, 1, 0) {
                let request = inventory.bind(request);
                let (Response::DiscoveryBatch { mut batch }, elapsed, _) =
                    sampler.request(&mut worker, request.clone())
                else {
                    panic!("Expected discovery batch");
                };
                reply_bytes += serde_json::to_vec(&Response::DiscoveryBatch {
                    batch: batch.clone(),
                })
                .unwrap()
                .len();
                discover_ms += elapsed;
                batch_metrics.push(
                    serde_json::json!({ "functions": batch.analysis.functions_examined,
                    "decode_attempts": batch.analysis.decode_attempts, "request_ms": elapsed,
                    "reply_bytes": serde_json::to_vec(&batch).unwrap().len() }),
                );
                inventory
                    .commit(&mut state, &info, &request, &mut batch)
                    .unwrap();
                functions = inventory.functions().to_vec();
            }
            let analysis = state.snapshot();
            let second_start = Instant::now();
            assert!(
                state.begin(1, 1, 0).is_none(),
                "Completed seeds must not repeat"
            );
            let second_ms = second_start.elapsed().as_secs_f64() * 1000.;
            let second = ghidra_rust::model::CallAnalysis::default();
            let second_functions = &functions;
            let (Response::Graph { view }, graph_ms, _) = sampler.request(
                &mut worker,
                Request::Graph {
                    address: fixture.function,
                },
            ) else {
                panic!("Expected Graph");
            };
            let (Response::Decompiled { text, mappings, .. }, decompile_ms, retained_memory) =
                sampler.request(
                    &mut worker,
                    Request::Decompile {
                        address: fixture.function,
                    },
                )
            else {
                panic!("Expected Decompiled");
            };
            selection::validate_mappings(&text, &mappings, &info.sections).unwrap();
            assert!(!mappings.is_empty());
            let through_decompile_ms = start.elapsed().as_secs_f64() * 1000.;
            assert!(sampler.max_processes >= 2, "Worker memory was not sampled");
            let stop = Instant::now();
            drop(worker);
            while sampler
                .children
                .iter()
                .any(|(&pid, &ticks)| birth(pid) == Some(ticks))
            {
                assert!(
                    stop.elapsed() < Duration::from_secs(10),
                    "Worker was not reaped"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
            let shutdown_ms = stop.elapsed().as_secs_f64() * 1000.;
            assert_eq!(session::fingerprint(&fixture.path).unwrap(), input_sha256);
            rows.push(serde_json::json!({
                "fixture": fixture.name, "repeat": repeat, "input_sha256": input_sha256,
                "input_bytes": input_bytes, "function_address": format!("{:#x}", fixture.function),
                "spawn_ms": spawn_ms, "open_ms": open_ms, "discover_ms": discover_ms,
                "graph_ms": graph_ms, "decompile_ms": decompile_ms,
                "through_decompile_ms": through_decompile_ms, "shutdown_ms": shutdown_ms,
                "client_before_start": before_start, "loaded_memory": loaded_memory,
                "retained_results_memory": retained_memory,
                "observed_peak_sum_rss_kib": sampler.peak_rss_kib,
                "observed_peak_sum_pss_kib": sampler.peak_pss_kib,
                "memory_samples": sampler.samples, "max_processes": sampler.max_processes,
                "new_functions": functions.iter().filter(|f| ghidra_rust::model::function_at(&info.functions, f.address).is_none()).count(),
                "second_functions_examined": second.functions_examined, "second_decode_attempts": second.decode_attempts,
                "second_discover_ms": second_ms, "discovery_reply_bytes": reply_bytes, "batches": batch_metrics,
                "second_new_functions": second_functions.iter().filter(|f| ghidra_rust::model::function_at(&functions, f.address).is_none()).count(),
                "known_functions": functions.len(), "functions_examined": analysis.functions_examined,
                "decode_attempts": analysis.decode_attempts, "confirmed_calls": analysis.references.len(),
                "data_accesses": analysis.data.as_ref().map(|data| data.references.len()),
                "data_operations_charged": analysis.data.as_ref().map(|data| data.operations_charged),
                "data_candidates": analysis.data.as_ref().map(|data| data.accesses_examined),
                "data_unresolved": analysis.data.as_ref().map(|data| data.unresolved_accesses),
                "data_omitted": analysis.data.as_ref().map(|data| data.omitted_accesses),
                "data_unsupported_instructions": analysis.data.as_ref().map(|data| data.unsupported_instructions),
                "data_partial": analysis.data.as_ref().map(|data| data.partial),
                "analysis_partial": analysis.partial, "graph_blocks": view.blocks.len(),
                "pseudocode_bytes": text.len(), "semantic_ranges": mappings.len(),
            }));
        }
    }
    let report = serde_json::json!({
        "scope": "instrumented analysis client plus all observed descendants; no native GUI",
        "platform": std::env::consts::ARCH,
        "kernel": fs::read_to_string("/proc/sys/kernel/osrelease").unwrap().trim(),
        "logical_cpus_available": std::thread::available_parallelism().unwrap().get(),
        "git_commit": git_commit, "worktree_dirty": worktree_dirty,
        "rustc": compiler, "gcc": gcc,
        "engine_fingerprint": project::ENGINE_FINGERPRINT,
        "worker_executable_sha256": executable_sha256,
        "sampler_executable_sha256": sampler_executable_sha256,
        "sample_interval_ms": SAMPLE_INTERVAL.as_millis(), "runs": rows,
        "limitations": ["Samples are non-atomic estimates; they can miss short peaks and skew aggregate totals",
            "RSS sums can count shared pages more than once; PSS apportions shared pages",
            "Sampling perturbs timings; the client allocator persists between fresh-worker runs",
            "Fixture preparation, builds, rendering and project I/O are outside the timed scope",
            "Fixture creation and identity hashing warm filesystem caches; these are not cold-cache timings",
            "No Ghidra timing or memory comparison is implied"],
    });
    let mut file = tempfile::Builder::new()
        .prefix("baseline-")
        .suffix(".json")
        .tempfile_in(&output)
        .unwrap();
    serde_json::to_writer_pretty(&mut file, &report).unwrap();
    file.write_all(b"\n").unwrap();
    let (_, path) = file.keep().unwrap();
    println!("Analysis baseline: {}", path.display());
}
