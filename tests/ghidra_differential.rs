//! Opt-in differential benchmark comparing the contained ghidra-rust worker
//! with a separately installed Ghidra on identical inputs. It measures; it
//! does not assert that either tool is better. See docs/analysis-performance.md.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod differential;
mod inventory;
mod measurement;

use differential::{Case, Limits, RunRequest, SCHEMA_VERSION, hex, parse_hex};
use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::model::{BinaryInfo, Request, Response, function_at};
use ghidra_rust::{project, session};
use measurement::{SAMPLE_INTERVAL, Sampler};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const REQUEST_ENV: &str = "GHIDRA_RUST_DIFF_REQUEST";
const RUN_TIMEOUT: Duration = Duration::from_secs(1200);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REAP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_REPEATS: usize = 20;
/// The exact trailer `analysis.rs` appends when it truncates decompiler text.
const RUST_TRUNCATION_TRAILER: &str =
    "\n/* Decompiler output truncated at the 2 MiB prototype limit. */\n";
/// Inherited variables that would silently change the JVM configuration.
const JAVA_OVERRIDES: [&str; 6] = [
    "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "GHIDRA_JAVA_OPTIONS",
    "GHIDRA_MAXMEM",
    "GHIDRA_HEADLESS_MAXMEM",
];

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.
}

fn bounded(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

fn command_text(command: &mut Command) -> String {
    match command.output() {
        Ok(output) if output.status.success() => {
            let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&output.stderr));
            text.trim().to_owned()
        }
        Ok(output) => format!("failed: {}", output.status),
        Err(error) => format!("unavailable: {error}"),
    }
}

/// Writes a complete JSON document that must not replace an existing file.
fn publish(path: &Path, value: &Value) {
    let directory = path.parent().unwrap();
    let mut file = tempfile::NamedTempFile::new_in(directory).unwrap();
    serde_json::to_writer_pretty(&mut file, value).unwrap();
    file.write_all(b"\n").unwrap();
    file.as_file().sync_all().unwrap();
    file.persist_noclobber(path).unwrap();
}

// ---------------------------------------------------------------------------
// ghidra-rust arm: one fresh client process per repetition.

/// A terminal reply and its latency, or a failure kind and message. `error`
/// is an engine error reply from a still-usable worker; `timeout` and `worker`
/// mean the worker must not receive further requests.
type Waited = Result<(Response, f64), (&'static str, String)>;

fn request(worker: &mut WorkerClient, request: Request) -> Waited {
    let start = Instant::now();
    let id = match worker.send(request) {
        Ok(id) => id,
        Err(error) => return Err(("worker", error)),
    };
    let mut previous = None;
    loop {
        if start.elapsed() >= REQUEST_TIMEOUT {
            return Err(("timeout", "Request exceeded the 30-second deadline".into()));
        }
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                if reply.id != id {
                    return Err(("worker", "Reply answered another request".into()));
                }
                match reply.response {
                    Response::Progress { progress } => {
                        if let Err(error) = progress.validate_after(previous.as_ref()) {
                            return Err(("worker", error));
                        }
                        previous = Some(progress);
                    }
                    Response::Error { message } => return Err(("error", message)),
                    response => return Ok((response, ms(start.elapsed()))),
                }
            }
            Some(WorkerEvent::Failed(error)) => return Err(("worker", error)),
            None => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

struct RustRun {
    stage: &'static str,
    failure_stage: Option<&'static str>,
    status: &'static str,
    error: Option<String>,
    info: Option<BinaryInfo>,
    functions: Vec<ghidra_rust::model::FunctionInfo>,
    analysis: ghidra_rust::model::CallAnalysis,
    queue_exhausted: bool,
    analysis_timed_out: bool,
    remaining: usize,
    batches: usize,
    decompilations: Vec<Value>,
    timings: serde_json::Map<String, Value>,
}

fn rust_arm(request_doc: &RunRequest) -> RustRun {
    let mut run = RustRun {
        stage: "open",
        failure_stage: None,
        status: "ok",
        error: None,
        info: None,
        functions: Vec::new(),
        analysis: Default::default(),
        queue_exhausted: false,
        analysis_timed_out: false,
        remaining: 0,
        batches: 0,
        decompilations: Vec::new(),
        timings: Default::default(),
    };
    let fail = |run: &mut RustRun, error: String| {
        run.status = "failed";
        run.failure_stage.get_or_insert(run.stage);
        run.error = Some(bounded(&error, request_doc.limits.max_error_bytes));
    };
    let start = Instant::now();
    let mut worker = match WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &request_doc.input_path,
        Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
    ) {
        Ok(worker) => worker,
        Err(error) => {
            run.stage = "worker_start";
            fail(&mut run, error);
            return run;
        }
    };
    run.timings
        .insert("worker_start_ms".into(), ms(start.elapsed()).into());
    let info = match request(
        &mut worker,
        Request::Open {
            path: request_doc.input_path.to_string_lossy().into_owned(),
        },
    ) {
        Ok((Response::Opened { info }, elapsed)) => {
            run.timings.insert("open_ms".into(), elapsed.into());
            info
        }
        Ok(_) => {
            fail(&mut run, "Expected Opened".into());
            return run;
        }
        Err((_, error)) => {
            fail(&mut run, error);
            return run;
        }
    };
    if info.sha256 != request_doc.input_sha256 {
        fail(&mut run, "Worker opened a different input".into());
        return run;
    }
    // Discovery runs to queue exhaustion from the production inventory and
    // entry point only; truth symbols and requested addresses are not seeds.
    run.stage = "discovery";
    let discovery_start = Instant::now();
    let mut state = ghidra_rust::discovery::Discovery::new(
        ghidra_rust::call_analysis::code_address(&info, info.entry).then_some(info.entry),
        info.functions.iter().map(|function| function.address),
        info.functions_truncated,
    );
    let mut inventory = inventory::Inventory::default();
    run.functions = info.functions.clone();
    let mut request_ms = 0.;
    let deadline = Duration::from_secs(request_doc.limits.analysis_timeout_seconds);
    loop {
        if discovery_start.elapsed() >= deadline {
            run.analysis_timed_out = true;
            run.status = "partial";
            break;
        }
        let Some(batch_request) = state.begin(1, 1, 0) else {
            run.queue_exhausted = true;
            break;
        };
        let batch_request = inventory.bind(batch_request);
        match request(&mut worker, batch_request.clone()) {
            Ok((Response::DiscoveryBatch { mut batch }, elapsed)) => {
                request_ms += elapsed;
                run.batches += 1;
                if let Err(error) = inventory.commit(&mut state, &info, &batch_request, &mut batch)
                {
                    fail(&mut run, error);
                    break;
                }
                run.functions = inventory.functions().to_vec();
            }
            Ok(_) => {
                fail(&mut run, "Expected a discovery batch".into());
                break;
            }
            Err((_, error)) => {
                fail(&mut run, error);
                break;
            }
        }
    }
    // Freeze evidence before decompilation, which can name or create functions.
    run.analysis = state.snapshot();
    run.remaining = state.remaining();
    run.timings
        .insert("discovery_ms".into(), ms(discovery_start.elapsed()).into());
    run.timings
        .insert("discovery_request_ms".into(), request_ms.into());
    run.info = Some(info);
    run.stage = "decompile";
    let decompile_start = Instant::now();
    let mut retained = 0usize;
    let mut worker_failed = run.status == "failed";
    for requested in &request_doc.requested {
        let va = parse_hex(&requested.va).unwrap();
        let mut record = json!({"rva": requested.rva, "raw": requested.va, "c": null,
            "elapsed_ms": null, "error": null, "engine_truncation": false,
            "export_truncation": false, "c_bytes": null});
        let status = if worker_failed {
            "not_attempted_after_failure"
        } else if function_at(&run.functions, va).is_none() {
            "not_discovered"
        } else {
            match request(&mut worker, Request::Decompile { address: va }) {
                Ok((Response::Decompiled { text, .. }, elapsed)) => {
                    record["elapsed_ms"] = elapsed.into();
                    record["c_bytes"] = text.len().into();
                    let truncated = text.ends_with(RUST_TRUNCATION_TRAILER);
                    record["engine_truncation"] = truncated.into();
                    let limit = request_doc
                        .limits
                        .max_c_bytes_per_function
                        .min(request_doc.limits.max_c_bytes_total - retained);
                    let kept = bounded(&text, limit);
                    retained += kept.len();
                    record["export_truncation"] = (kept.len() < text.len()).into();
                    record["c"] = kept.into();
                    if truncated {
                        "output_truncated"
                    } else {
                        "success"
                    }
                }
                Ok(_) => "error",
                Err((kind, error)) => {
                    record["error"] = bounded(&error, request_doc.limits.max_error_bytes).into();
                    // A timed-out or failed worker is not reused for later requests.
                    worker_failed = kind != "error";
                    if kind == "worker" { "error" } else { kind }
                }
            }
        };
        record["status"] = status.into();
        run.decompilations.push(record);
    }
    run.timings.insert(
        "decompile_set_ms".into(),
        ms(decompile_start.elapsed()).into(),
    );
    let shutdown = Instant::now();
    drop(worker);
    run.timings
        .insert("shutdown_ms".into(), ms(shutdown.elapsed()).into());
    run.stage = "complete";
    run
}

fn rust_export(request_doc: &RunRequest, run: RustRun, process_ms: f64) -> Value {
    let base = parse_hex(&request_doc.load_base).unwrap();
    let rva = |address: u64| address.checked_sub(base).map(hex);
    let limits = &request_doc.limits;
    let functions_capped = run.functions.len() > limits.max_functions;
    let functions: Vec<_> = run
        .functions
        .iter()
        .take(limits.max_functions)
        .filter_map(|function| {
            Some(
                json!({"rva": rva(function.address)?, "raw": hex(function.address),
                "name": bounded(&function.name, limits.max_function_name_bytes),
                "body_bytes": null, "thunk": null, "noreturn": null}),
            )
        })
        .collect();
    let calls_capped = run.analysis.references.len() > limits.max_calls;
    let calls: Vec<_> = run
        .analysis
        .references
        .iter()
        .take(limits.max_calls)
        .filter_map(|call| {
            Some(json!({"kind": "call", "from_rva": rva(call.address)?, "target_rva": rva(call.target)?,
                "caller_rva": rva(call.caller), "raw_from": hex(call.address),
                "raw_target": hex(call.target)}))
        })
        .collect();
    let blocks: Vec<_> = run
        .info
        .iter()
        .flat_map(|info| &info.sections)
        .filter(|section| section.executable)
        .filter_map(|section| {
            Some(json!({"name": section.name, "rva": rva(section.address)?,
                "size": section.size, "file_offset": section.file_offset}))
        })
        .collect();
    let mut timings = run.timings;
    timings.insert("process_ms".into(), process_ms.into());
    json!({
        "schema_version": SCHEMA_VERSION, "document_type": "tool_export",
        "run_id": request_doc.run_id, "case_id": request_doc.case_id,
        "repetition": request_doc.repetition, "tool": "ghidra-rust",
        "status": run.status, "failure_stage": run.failure_stage,
        "error": run.error,
        "input": {"sha256": request_doc.input_sha256},
        "tool_info": {"version": env!("CARGO_PKG_VERSION"),
            "engine_fingerprint": project::ENGINE_FINGERPRINT,
            "architecture": run.info.as_ref().map(|info| &info.architecture),
            "format": run.info.as_ref().map(|info| &info.format)},
        "settings": {"profile": "ghidra-rust-contained-discovery",
            "analyzer_options": null, "limits": limits},
        "addressing": {"load_base": request_doc.load_base, "tool_base": request_doc.load_base,
            "original_base": request_doc.load_base, "normalization": "identity"},
        "executable_blocks": blocks,
        "coverage": {"queue_exhausted": run.queue_exhausted,
            "analysis_timed_out": run.analysis_timed_out,
            "analysis_partial": run.analysis.partial, "pending": run.remaining,
            "functions_examined": run.analysis.functions_examined,
            "decode_attempts": run.analysis.decode_attempts,
            "failed_functions": run.analysis.failed_functions,
            "unresolved_calls": run.analysis.unresolved_calls,
            "batches": run.batches,
            "functions_capped": functions_capped, "calls_capped": calls_capped},
        "functions": functions, "calls": calls,
        "decompilations": run.decompilations, "timings": timings,
    })
}

#[test]
#[ignore = "Internal child of benchmark_against_ghidra; requires its run request"]
fn export_contained_worker() {
    let Some(path) = std::env::var_os(REQUEST_ENV) else {
        eprintln!("{REQUEST_ENV} is unset; this entry point only serves the differential suite");
        return;
    };
    let start = Instant::now();
    let request_doc = RunRequest::read(Path::new(&path)).unwrap();
    assert_eq!(request_doc.tool, "ghidra-rust");
    assert_eq!(
        session::fingerprint(&request_doc.input_path).unwrap(),
        request_doc.input_sha256
    );
    let run = rust_arm(&request_doc);
    let after = session::fingerprint(&request_doc.input_path).unwrap();
    assert_eq!(
        after, request_doc.input_sha256,
        "Input changed during analysis"
    );
    let export = rust_export(&request_doc, run, ms(start.elapsed()));
    publish(&request_doc.output, &export);
}

// ---------------------------------------------------------------------------
// Controller: corpus, scheduling, sampling and the suite manifest.

struct Measured {
    exit: Option<i32>,
    timed_out: bool,
    wall_ms: f64,
    descendant_wait_ms: f64,
    leaked_descendants: bool,
    sampler: Sampler,
}

/// Runs `command` in its own process group, sampling its whole tree. Only the
/// owned group is ever signalled, and only after the run deadline.
fn measure(command: &mut Command, log: &Path) -> Result<Measured, String> {
    let output = fs::File::create_new(log).map_err(|e| e.to_string())?;
    let errors = output.try_clone().map_err(|e| e.to_string())?;
    command
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(errors);
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("Cannot start {command:?}: {error}"))?;
    let group = child.id() as libc::pid_t;
    let mut sampler = Sampler::new(child.id());
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        if start.elapsed() >= RUN_TIMEOUT {
            timed_out = true;
            // SAFETY: `group` is the process group created for this child by
            // `process_group(0)`; the child is unreaped, so its ID is not reused.
            unsafe { libc::kill(-group, libc::SIGKILL) };
            break child.wait().map_err(|e| e.to_string())?;
        }
        if sampler.last.elapsed() >= SAMPLE_INTERVAL {
            sampler.sample();
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let wall_ms = ms(start.elapsed());
    let stop = Instant::now();
    let mut leaked_descendants = false;
    while sampler.descendants_alive() {
        if stop.elapsed() >= REAP_TIMEOUT {
            leaked_descendants = true;
            // SAFETY: as above; descendants that stayed in the owned group are
            // the only processes this can reach.
            unsafe { libc::kill(-group, libc::SIGKILL) };
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(Measured {
        exit: status.code(),
        timed_out,
        wall_ms,
        descendant_wait_ms: ms(stop.elapsed()),
        leaked_descendants,
        sampler,
    })
}

struct Ghidra {
    home: PathBuf,
    version: String,
    java: String,
}

fn ghidra() -> Ghidra {
    let home = std::env::var_os("GHIDRA_RUST_BENCH_GHIDRA_HOME")
        .expect("Set GHIDRA_RUST_BENCH_GHIDRA_HOME to a built Ghidra installation");
    let home = Path::new(&home)
        .canonicalize()
        .expect("GHIDRA_RUST_BENCH_GHIDRA_HOME must exist");
    assert!(
        home.join("support/analyzeHeadless").is_file(),
        "No support/analyzeHeadless in the selected Ghidra installation"
    );
    let properties = fs::read_to_string(home.join("Ghidra/application.properties"))
        .expect("Ghidra application.properties");
    let version = properties
        .lines()
        .find_map(|line| line.strip_prefix("application.version="))
        .expect("Ghidra application.version")
        .to_owned();
    let java = match std::env::var_os("JAVA_HOME") {
        Some(java_home) => {
            command_text(Command::new(Path::new(&java_home).join("bin/java")).arg("-version"))
        }
        None => command_text(Command::new("java").arg("-version")),
    };
    Ghidra {
        home,
        version,
        java,
    }
}

/// Fresh per-run Ghidra directories, removed once the run has been measured.
const GHIDRA_SCRATCH: [&str; 6] = [
    "project",
    "settings",
    "cache",
    "tmp",
    "xdg-config",
    "xdg-cache",
];

fn ghidra_command(ghidra: &Ghidra, run: &Path, request: &Path, input: &Path) -> Command {
    for path in [run, request, input] {
        // The launcher word-splits its JVM option string.
        assert!(
            !path.to_string_lossy().contains(char::is_whitespace),
            "Benchmark paths must not contain whitespace: {}",
            path.display()
        );
    }
    let script_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ghidra");
    let mut command = Command::new(ghidra.home.join("support/analyzeHeadless"));
    for variable in JAVA_OVERRIDES {
        command.env_remove(variable);
    }
    let directory = |name: &str| {
        let path = run.join(name);
        fs::create_dir(&path).unwrap();
        path
    };
    let [project, settings, cache, tmp, config, xdg_cache] = GHIDRA_SCRATCH.map(directory);
    command
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_CACHE_HOME", xdg_cache)
        .env("GHIDRA_HEADLESS_MAXMEM", "2G")
        .env(
            "GHIDRA_HEADLESS_JAVA_OPTIONS",
            format!(
                "-Dapplication.settingsdir={} -Dapplication.cachedir={} -Dapplication.tempdir={} -Djava.io.tmpdir={}",
                settings.display(),
                cache.display(),
                tmp.display(),
                tmp.display()
            ),
        )
        .arg(&project)
        .arg("benchmark")
        .arg("-import")
        .arg(input)
        .args(["-loader", "ElfLoader", "-loader-loadLibraries", "false"])
        .arg("-scriptPath")
        .arg(&script_dir)
        .args(["-preScript", "DifferentialExport.java", "before"])
        .arg(request)
        .args(["-postScript", "DifferentialExport.java", "after"])
        .arg(request)
        .arg("-analysisTimeoutPerFile")
        .arg(differential::ANALYSIS_TIMEOUT_SECONDS.to_string())
        .args(["-max-cpu", "1"])
        .arg("-log")
        .arg(run.join("headless.log"))
        .arg("-scriptlog")
        .arg(run.join("script.log"))
        .arg("-deleteProject");
    command
}

fn repeats() -> usize {
    match std::env::var("GHIDRA_RUST_BENCH_REPEATS") {
        Err(_) => 3,
        Ok(value) => value
            .parse()
            .ok()
            .filter(|repeats| (1..=MAX_REPEATS).contains(repeats))
            .expect("GHIDRA_RUST_BENCH_REPEATS must be 1–20"),
    }
}

fn run_arm(
    tool: &str,
    case: &Case,
    repetition: usize,
    order: usize,
    suite: &Path,
    ghidra: &Ghidra,
) -> Value {
    let run_id = format!("{}-r{repetition}-{tool}", case.id);
    let run = suite.join(&run_id);
    fs::create_dir(&run).unwrap();
    let request_path = run.join("request.json");
    let output = run.join("export.json");
    let request = RunRequest {
        schema_version: SCHEMA_VERSION,
        document_type: "run_request".into(),
        run_id: run_id.clone(),
        case_id: case.id.clone(),
        repetition,
        tool: tool.into(),
        input_path: case.path.clone(),
        input_sha256: case.sha256.clone(),
        input_bytes: case.bytes,
        load_base: hex(case.load_base),
        requested: case.requested.clone(),
        output: output.clone(),
        limits: Limits::current(),
    };
    publish(&request_path, &serde_json::to_value(&request).unwrap());
    let mut command = if tool == "ghidra" {
        ghidra_command(ghidra, &run, &request_path, &case.path)
    } else {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["export_contained_worker", "--exact", "--ignored"])
            .args(["--nocapture", "--test-threads=1"])
            .env(REQUEST_ENV, &request_path);
        command
    };
    let measured = measure(&mut command, &run.join("process.log"));
    if tool == "ghidra" {
        // Keep the request, export and logs; drop Ghidra's per-run caches.
        for name in GHIDRA_SCRATCH {
            let _ = fs::remove_dir_all(run.join(name));
        }
    }
    let (status, error, memory) = match measured {
        Ok(measured) => {
            let exported = output.is_file();
            let status = if measured.timed_out {
                "timeout"
            } else if measured.exit != Some(0) || !exported || measured.leaked_descendants {
                "failed"
            } else {
                "ok"
            };
            let sampler = &measured.sampler;
            (
                status,
                None,
                json!({"exit_code": measured.exit, "wall_ms": measured.wall_ms,
                    "descendant_wait_ms": measured.descendant_wait_ms,
                    "leaked_descendants": measured.leaked_descendants,
                    "export_present": exported,
                    "memory": {"scope": "launched process and all observed descendants",
                        "sample_interval_ms": SAMPLE_INTERVAL.as_millis(),
                        "samples": sampler.samples, "max_gap_ms": ms(sampler.max_gap),
                        "collection_ms": ms(sampler.collection),
                        "observed_peak_sum_rss_kib": sampler.peak_rss_kib,
                        "observed_peak_sum_pss_kib": sampler.peak_pss_kib,
                        "max_processes": sampler.max_processes}}),
            )
        }
        Err(error) => ("failed", Some(error), json!({})),
    };
    let relative = |path: &Path| {
        path.strip_prefix(suite)
            .unwrap()
            .to_string_lossy()
            .into_owned()
    };
    let mut record = json!({"run_id": run_id, "case_id": case.id, "repetition": repetition,
        "tool": tool, "order": order, "status": status, "error": error,
        "export": relative(&output), "log": relative(&run.join("process.log"))});
    record
        .as_object_mut()
        .unwrap()
        .extend(memory.as_object().cloned().unwrap_or_default());
    println!(
        "{run_id}: {status} in {:.0} ms",
        record["wall_ms"].as_f64().unwrap_or(f64::NAN)
    );
    record
}

#[test]
#[ignore = "Opt-in differential benchmark; requires GHIDRA_RUST_BENCH_GHIDRA_HOME and --release"]
fn benchmark_against_ghidra() {
    if cfg!(debug_assertions) {
        panic!("Run the differential benchmark with --release");
    }
    let ghidra = ghidra();
    let repeats = repeats();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/ghidra-differential");
    fs::create_dir_all(&root).unwrap();
    let suite = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(&root)
        .unwrap()
        .keep();
    let inputs = suite.join("inputs");
    fs::create_dir(&inputs).unwrap();
    let selected = std::env::var("GHIDRA_RUST_BENCH_CASE").ok();
    let (cases, build) = match std::env::var_os("GHIDRA_RUST_BENCH_INPUT") {
        Some(_) if selected.is_some() => panic!("Select either an external input or a case"),
        Some(path) => (
            vec![
                differential::external(
                    Path::new(&path),
                    std::env::var("GHIDRA_RUST_BENCH_ADDRESSES").ok().as_deref(),
                )
                .unwrap(),
            ],
            json!({"external": true}),
        ),
        None => differential::corpus(&inputs, selected.as_deref()).unwrap(),
    };
    assert!(!cases.is_empty(), "No benchmark case matched");
    let mut truths = serde_json::Map::new();
    for case in &cases {
        if let Some(truth) = &case.truth {
            let config = case.build["config"].as_str().unwrap();
            let name = format!("truth-{config}.json");
            if !suite.join(&name).exists() {
                publish(&suite.join(&name), truth);
            }
            truths.insert(case.id.clone(), name.into());
        }
    }
    let mut runs = Vec::new();
    for (index, case) in cases.iter().enumerate() {
        // Alternate the starting arm between cases; arms interleave per case.
        let arms = if index % 2 == 0 {
            ["ghidra-rust", "ghidra"]
        } else {
            ["ghidra", "ghidra-rust"]
        };
        let mut order = 0;
        for repetition in 1..=repeats {
            for tool in arms {
                order += 1;
                runs.push(run_arm(tool, case, repetition, order, &suite, &ghidra));
            }
        }
    }
    for case in &cases {
        assert_eq!(
            session::fingerprint(&case.path).unwrap(),
            case.sha256,
            "Benchmark input {} changed",
            case.id
        );
    }
    let git = |args: &[&str]| command_text(Command::new("git").args(args));
    let manifest = json!({
        "schema_version": SCHEMA_VERSION, "document_type": "suite",
        "scope": "fresh tool processes on identical inputs; no native GUI",
        "cache_policy": "fresh-process, fresh-application-cache, OS-cache-uncontrolled",
        "repetitions": repeats, "git_commit": git(&["rev-parse", "HEAD"]),
        "worktree_dirty": !git(&["status", "--porcelain"]).is_empty(),
        "rustc": command_text(Command::new("rustc").arg("-vV")),
        "engine_fingerprint": project::ENGINE_FINGERPRINT,
        "worker_executable_sha256": session::fingerprint(Path::new(env!("CARGO_BIN_EXE_ghidra-rust"))).unwrap(),
        "controller_executable_sha256": session::fingerprint(&std::env::current_exe().unwrap()).unwrap(),
        "ghidra": {"home": ghidra.home, "version": ghidra.version, "java": ghidra.java,
            "profile": "ghidra-default-analyzers-cpu1", "max_heap": "2G",
            "script_sha256": session::fingerprint(&Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/ghidra/DifferentialExport.java")).unwrap()},
        "kernel": fs::read_to_string("/proc/sys/kernel/osrelease").unwrap().trim(),
        "logical_cpus_available": std::thread::available_parallelism().unwrap().get(),
        "build": build,
        "cases": cases.iter().map(|case| json!({"case_id": case.id, "sha256": case.sha256,
            "bytes": case.bytes, "load_base": hex(case.load_base), "build": case.build,
            "truth": truths.get(&case.id), "requested": case.requested})).collect::<Vec<_>>(),
        "runs": runs,
        "limitations": [
            "Ghidra runs its default analyzers; ghidra-rust runs contained direct-call discovery. Scopes differ",
            "Ghidra runs without the production worker's sandbox; use trusted inputs only",
            "Ghidra's 2 GiB heap limit is not equivalent to the worker's 2 GiB address-space limit",
            "Samples are non-atomic estimates; RSS sums can double-count shared pages",
            "Filesystem caches are warmed by builds and hashing; these are not cold-cache timings",
            "Ghidra 12.1.x and the pinned engine's upstream decompiler baseline differ",
        ],
    });
    let manifest_path = suite.join("suite.json");
    publish(&manifest_path, &manifest);
    let compare = |format: &str| {
        Command::new("python3")
            .arg("-I")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/compare-ghidra-benchmark.py"))
            .args(["--suite"])
            .arg(&manifest_path)
            .args(["--format", format])
            .output()
    };
    for (format, name) in [("json", "report.json"), ("table", "report.txt")] {
        match compare(format) {
            Ok(output) if output.status.success() => {
                fs::write(suite.join(name), &output.stdout).unwrap();
                if format == "table" {
                    print!("{}", String::from_utf8_lossy(&output.stdout));
                }
            }
            Ok(output) => eprintln!(
                "Comparator failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => eprintln!("Cannot run the comparator: {error}"),
        }
    }
    println!("Differential suite: {}", suite.display());
    let failures: Vec<_> = runs
        .iter()
        .filter(|run| run["status"] != "ok")
        .map(|run| run["run_id"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        failures.is_empty(),
        "Failed runs (reports retained): {failures:?}"
    );
}
