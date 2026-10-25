//! Opt-in native Windows release measurements through the production client.
//! Inputs are only read/analyzed, never launched. Raw records stay under target/.
//! Run with GHIDRA_RUST_TEST_PE set to the original compiled sample.c fixture:
//! cargo test --release --locked --target x86_64-pc-windows-msvc \
//!   --test windows_analysis_baseline -- --ignored --nocapture --test-threads=1
//! Optional GHIDRA_RUST_BENCH_INPUT adds an arbitrary supported trusted image;
//! GHIDRA_RUST_BENCH_A/B select hexadecimal function addresses in that image.
//! GHIDRA_RUST_BENCH_REPEATS defaults to three (accepted range: 1..=20).
//! GHIDRA_RUST_BENCH_EXTERNAL_BATCHES defaults to eight; zero opts into exhaustion.
//! GHIDRA_RUST_BENCH_MODE is latency (default) or memory (in-request sampling).
//! GHIDRA_RUST_BENCH_SOURCE_METADATA may name JSON containing the original git
//! revision/status and source archive hash, for exported Windows checkouts.
#![cfg(windows)]
#![recursion_limit = "256"]
mod common;
mod inventory;
mod result_measurement;

use ghidra_rust::call_analysis::{CallIndex, code_address};
use ghidra_rust::client::{WorkerClient, WorkerEvent};
use ghidra_rust::discovery::Discovery;
use ghidra_rust::model::{
    AnalysisStage, BinaryInfo, CallAnalysis, DataAccess, DataProvenance, EdgeKind, FunctionInfo,
    FunctionView, MAX_FUNCTIONS, Request, Response,
};
use ghidra_rust::{project, selection, session};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_FILES, FILETIME, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_VM_READ,
    QueryFullProcessImageNameW, WaitForSingleObject,
};

const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);
// Match the existing contained-worker integration tests. Progress never resets it.
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
const REAP_DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MeasurementMode {
    Latency,
    Memory,
}
impl MeasurementMode {
    fn from_env() -> Self {
        match std::env::var("GHIDRA_RUST_BENCH_MODE") {
            Err(std::env::VarError::NotPresent) => Self::Latency,
            Ok(value) if value == "latency" => Self::Latency,
            Ok(value) if value == "memory" => Self::Memory,
            _ => panic!("GHIDRA_RUST_BENCH_MODE must be latency or memory"),
        }
    }
}

// PROCESS_MEMORY_COUNTERS_EX from psapi.h. SIZE_T fields use the native pointer
// width; the first two DWORD fields and repr(C) preserve both Win32/Win64 ABI.
// K32GetProcessMemoryInfo is exported by Kernel32 on supported modern Windows;
// declaring this small API avoids adding another windows-sys feature/dependency.
#[repr(C)]
#[derive(Default)]
struct ProcessMemoryCountersEx {
    cb: u32,
    page_fault_count: u32,
    peak_working_set_size: usize,
    working_set_size: usize,
    quota_peak_paged_pool_usage: usize,
    quota_paged_pool_usage: usize,
    quota_peak_non_paged_pool_usage: usize,
    quota_non_paged_pool_usage: usize,
    pagefile_usage: usize,
    peak_pagefile_usage: usize,
    private_usage: usize,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn K32GetProcessMemoryInfo(
        process: HANDLE,
        counters: *mut ProcessMemoryCountersEx,
        size: u32,
    ) -> i32;
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: each instance exclusively owns a non-null, non-pseudo Win32
        // handle obtained from OpenProcess or CreateToolhelp32Snapshot.
        assert_ne!(unsafe { CloseHandle(self.0) }, 0, "CloseHandle failed");
    }
}

#[derive(Clone, Serialize)]
struct ProcessIdentity {
    pid: u32,
    creation_filetime_100ns: u64,
    executable: PathBuf,
}
struct TrackedProcess {
    handle: OwnedHandle,
    identity: ProcessIdentity,
}
impl TrackedProcess {
    fn open(pid: u32) -> Self {
        // SAFETY: pid is a ToolHelp/current-process ID; no pointer arguments or
        // inherited handles. Failure is fatal, never a zero memory substitute.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        assert!(
            !handle.is_null(),
            "OpenProcess({pid}): {}",
            std::io::Error::last_os_error()
        );
        let handle = OwnedHandle(handle);
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: handle is live; outputs are four distinct writable FILETIMEs.
        assert_ne!(
            unsafe { GetProcessTimes(handle.0, &mut creation, &mut exit, &mut kernel, &mut user) },
            0,
            "GetProcessTimes({pid}): {}",
            std::io::Error::last_os_error()
        );
        let mut path = vec![0u16; 32_768];
        let mut length = path.len() as u32;
        // SAFETY: length describes the live writable UTF-16 buffer; the process
        // handle remains owned for the full call and all subsequent samples.
        assert_ne!(
            unsafe { QueryFullProcessImageNameW(handle.0, 0, path.as_mut_ptr(), &mut length) },
            0,
            "QueryFullProcessImageNameW({pid}): {}",
            std::io::Error::last_os_error()
        );
        let executable = PathBuf::from(String::from_utf16(&path[..length as usize]).unwrap())
            .canonicalize()
            .unwrap();
        Self {
            handle,
            identity: ProcessIdentity {
                pid,
                creation_filetime_100ns: (u64::from(creation.dwHighDateTime) << 32)
                    | u64::from(creation.dwLowDateTime),
                executable,
            },
        }
    }

    fn alive(&self) -> bool {
        // SAFETY: the retained process handle has SYNCHRONIZE access. Keeping it
        // open pins process identity even if Windows later reuses its PID.
        match unsafe { WaitForSingleObject(self.handle.0, 0) } {
            WAIT_TIMEOUT => true,
            WAIT_OBJECT_0 => false,
            other => panic!(
                "Process wait failed ({other}): {}",
                std::io::Error::last_os_error()
            ),
        }
    }

    fn memory(&self, role: &'static str) -> ProcessMemory {
        assert!(self.alive(), "{role} exited before memory sampling");
        let mut counters = ProcessMemoryCountersEx {
            cb: std::mem::size_of::<ProcessMemoryCountersEx>() as u32,
            ..Default::default()
        };
        // SAFETY: repr(C) matches PROCESS_MEMORY_COUNTERS_EX; counters is writable
        // for cb bytes, and this retained process handle has query/VM-read access.
        assert_ne!(
            unsafe {
                K32GetProcessMemoryInfo(
                    self.handle.0,
                    &mut counters,
                    std::mem::size_of::<ProcessMemoryCountersEx>() as u32,
                )
            },
            0,
            "Missing {role} memory: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            counters.working_set_size > 0 && counters.private_usage > 0,
            "Missing/zero {role} working set or private bytes"
        );
        ProcessMemory {
            role,
            identity: self.identity.clone(),
            working_set_bytes: counters.working_set_size as u64,
            private_bytes: counters.private_usage as u64,
            page_fault_count: counters.page_fault_count,
        }
    }
}

fn direct_children() -> Vec<u32> {
    // SAFETY: this flag requests a read-only system process snapshot; PID is
    // ignored for TH32CS_SNAPPROCESS. INVALID_HANDLE_VALUE is checked before use.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert!(
        snapshot != INVALID_HANDLE_VALUE && !snapshot.is_null(),
        "ToolHelp snapshot: {}",
        std::io::Error::last_os_error()
    );
    let snapshot = OwnedHandle(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut children = Vec::new();
    // SAFETY: snapshot is live and entry is initialized, correctly sized output.
    let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while found != 0 {
        if entry.th32ParentProcessID == std::process::id() {
            children.push(entry.th32ProcessID);
        }
        // SAFETY: the same snapshot and writable correctly sized entry remain live.
        found = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    // SAFETY: called immediately after the terminating ToolHelp enumeration call.
    assert_eq!(
        unsafe { GetLastError() },
        ERROR_NO_MORE_FILES,
        "ToolHelp enumeration failed"
    );
    children.sort_unstable();
    children
}

#[derive(Clone, Serialize)]
struct ProcessMemory {
    role: &'static str,
    identity: ProcessIdentity,
    working_set_bytes: u64,
    private_bytes: u64,
    page_fault_count: u32,
}
#[derive(Clone, Serialize)]
struct MemorySample {
    measurement_mode: MeasurementMode,
    sample_index: usize,
    since_start_ms: f64,
    collection_ms: f64,
    processes: Vec<ProcessMemory>,
    process_count: usize,
    worker_count: usize,
    sum_working_set_bytes: u64,
    sum_private_bytes: u64,
}

fn json_line(file: &mut impl Write, value: &impl Serialize) {
    serde_json::to_writer(&mut *file, value).unwrap();
    file.write_all(b"\n").unwrap();
    // Preserve completed records even when a later assertion fails.
    file.flush().unwrap();
}
fn milliseconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
struct JsonHash {
    hash: Sha256,
    bytes: usize,
}
impl Write for JsonHash {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.hash.update(bytes);
        self.bytes = self.bytes.checked_add(bytes.len()).unwrap();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn value_identity(value: &impl Serialize) -> (usize, String) {
    let mut writer = JsonHash {
        hash: Sha256::new(),
        bytes: 0,
    };
    serde_json::to_writer(&mut writer, value).unwrap();
    (writer.bytes, format!("{:x}", writer.hash.finalize()))
}
fn value_digest(value: &impl Serialize) -> String {
    value_identity(value).1
}
#[derive(Serialize)]
struct RequestRecord<'a> {
    measurement_mode: MeasurementMode,
    phase: &'a str,
    id: u64,
    request: &'a Request,
    request_ms: f64,
    in_request_sample_count: usize,
    in_request_sampling_ms: f64,
    memory: &'a MemorySample,
    progress_count: usize,
    response_bytes: usize,
    response_sha256: String,
    response: &'a Response,
}

struct Sampler {
    mode: MeasurementMode,
    client: TrackedProcess,
    worker: Option<TrackedProcess>,
    origin: Instant,
    last: Instant,
    samples: usize,
    sampling_ms: f64,
    peak_sum_working_set_bytes: u64,
    peak_sum_private_bytes: u64,
    records: BufWriter<File>,
    memory: BufWriter<File>,
}
impl Sampler {
    fn new(directory: &Path, name: &str, mode: MeasurementMode) -> Self {
        Self {
            mode,
            client: TrackedProcess::open(std::process::id()),
            worker: None,
            origin: Instant::now(),
            last: Instant::now(),
            samples: 0,
            sampling_ms: 0.,
            peak_sum_working_set_bytes: 0,
            peak_sum_private_bytes: 0,
            records: BufWriter::new(
                File::create_new(directory.join(format!("{name}-requests.jsonl"))).unwrap(),
            ),
            memory: BufWriter::new(
                File::create_new(directory.join(format!("{name}-memory.jsonl"))).unwrap(),
            ),
        }
    }

    fn attach(&mut self, executable: &Path) {
        let children = direct_children();
        assert_eq!(
            children.len(),
            1,
            "Run this integration test alone; expected exactly one production worker child"
        );
        let worker = TrackedProcess::open(children[0]);
        assert_eq!(
            worker.identity.executable,
            executable.canonicalize().unwrap()
        );
        assert!(
            worker.identity.creation_filetime_100ns >= self.client.identity.creation_filetime_100ns
        );
        self.worker = Some(worker);
        self.sample();
    }

    fn sample(&mut self) -> MemorySample {
        let start = Instant::now();
        let since_start_ms = milliseconds(self.origin);
        let mut processes = vec![self.client.memory("client")];
        if let Some(worker) = &self.worker {
            // Count the active worker on every sample, and reject unexpected
            // descendants rather than silently omitting their memory.
            assert_eq!(
                direct_children(),
                vec![worker.identity.pid],
                "Unexpected worker process tree"
            );
            processes.push(worker.memory("worker"));
        } else {
            assert!(
                direct_children().is_empty(),
                "Previous worker has not exited"
            );
        }
        let sample = MemorySample {
            measurement_mode: self.mode,
            sample_index: self.samples + 1,
            since_start_ms,
            collection_ms: milliseconds(start),
            process_count: processes.len(),
            worker_count: usize::from(self.worker.is_some()),
            sum_working_set_bytes: processes.iter().map(|p| p.working_set_bytes).sum(),
            sum_private_bytes: processes.iter().map(|p| p.private_bytes).sum(),
            processes,
        };
        self.samples += 1;
        self.peak_sum_working_set_bytes = self
            .peak_sum_working_set_bytes
            .max(sample.sum_working_set_bytes);
        self.peak_sum_private_bytes = self.peak_sum_private_bytes.max(sample.sum_private_bytes);
        json_line(&mut self.memory, &sample);
        // This duration includes the snapshot, process reads and memory JSON
        // flush. Its own timing-record write cannot be included in this value;
        // sampling_ms below includes that write in request/run overhead totals.
        json_line(
            &mut self.records,
            &json!({ "phase": "memory_sample_timing", "measurement_mode": self.mode,
                "sample_index": sample.sample_index, "collection_ms": sample.collection_ms,
                "sample_and_memory_write_ms": milliseconds(start),
                "cumulative_sampling_ms_before": self.sampling_ms,
            }),
        );
        self.sampling_ms += milliseconds(start);
        self.last = Instant::now();
        sample
    }

    fn request(&mut self, worker: &mut WorkerClient, request: Request, phase: &str) -> Response {
        let start = Instant::now();
        let samples_before = self.samples;
        let sampling_ms_before = self.sampling_ms;
        let id = worker.send(request.clone()).unwrap();
        let mut previous = None;
        let mut progress_count = 0usize;
        loop {
            if start.elapsed() >= REQUEST_DEADLINE {
                json_line(
                    &mut self.records,
                    &json!({ "phase": phase, "id": id,
                    "measurement_mode": self.mode,
                    "request": request, "failure": "request_deadline_exceeded",
                    "in_request_sample_count": self.samples - samples_before,
                    "in_request_sampling_ms": self.sampling_ms - sampling_ms_before,
                    "elapsed_ms": milliseconds(start) }),
                );
                panic!("{phase} request {id} exceeded 30 seconds");
            }
            match worker.poll() {
                Some(WorkerEvent::Reply(reply)) => {
                    let elapsed_ms = milliseconds(start);
                    assert_eq!(reply.id, id);
                    if let Response::Progress { progress: update } = reply.response {
                        update.validate_after(previous.as_ref()).unwrap();
                        progress_count += 1;
                        assert!(
                            matches!(request, Request::Discover | Request::DiscoverBatch { .. }),
                            "Unexpected analysis progress"
                        );
                        assert!(
                            progress_count != 1 || update.stage == AnalysisStage::Seeds,
                            "First progress must be Seeds"
                        );
                        assert!(
                            progress_count <= ghidra_rust::model::MAX_ANALYSIS_FUNCTIONS + 3,
                            "Excessive progress replies"
                        );
                        json_line(
                            &mut self.records,
                            &json!({ "phase": phase,
                            "measurement_mode": self.mode,
                            "id": id, "progress": update, "since_request_ms": milliseconds(start) }),
                        );
                        previous = Some(update);
                        continue;
                    }
                    let final_analysis = match &reply.response {
                        Response::Functions { analysis, .. } => Some(analysis),
                        Response::DiscoveryBatch { batch } => Some(&batch.analysis),
                        _ => None,
                    };
                    if let Some(analysis) = final_analysis {
                        let last = previous.as_ref().expect("Missing final discovery progress");
                        assert_eq!(last.stage, AnalysisStage::Publish);
                        assert_eq!(last.functions_examined, analysis.functions_examined);
                        assert_eq!(last.decode_attempts, analysis.decode_attempts);
                    }
                    let in_request_sample_count = self.samples - samples_before;
                    let in_request_sampling_ms = self.sampling_ms - sampling_ms_before;
                    let memory = self.sample();
                    let (response_bytes, response_sha256) = value_identity(&reply.response);
                    json_line(
                        &mut self.records,
                        &RequestRecord {
                            measurement_mode: self.mode,
                            phase,
                            id,
                            request: &request,
                            request_ms: elapsed_ms,
                            in_request_sample_count,
                            in_request_sampling_ms,
                            memory: &memory,
                            progress_count,
                            response_bytes,
                            response_sha256,
                            response: &reply.response,
                        },
                    );
                    assert!(
                        !matches!(reply.response, Response::Error { .. }),
                        "{phase}: {:?}",
                        reply.response
                    );
                    return reply.response;
                }
                Some(WorkerEvent::Failed(error)) => {
                    json_line(
                        &mut self.records,
                        &json!({ "phase": phase, "id": id,
                        "measurement_mode": self.mode,
                        "in_request_sample_count": self.samples - samples_before,
                        "in_request_sampling_ms": self.sampling_ms - sampling_ms_before,
                        "request": request, "failure": error, "elapsed_ms": milliseconds(start) }),
                    );
                    panic!("Production worker failed during {phase}: {error}")
                }
                None => {
                    // Latency mode never enumerates processes or writes memory
                    // records while any request is pending, including Open and
                    // inventory replay. Memory mode retains active-work samples.
                    if self.mode == MeasurementMode::Memory
                        && self.last.elapsed() >= SAMPLE_INTERVAL
                    {
                        self.sample();
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn stop(&mut self, worker: WorkerClient) -> (f64, MemorySample) {
        let start = Instant::now();
        drop(worker);
        let tracked = self.worker.take().expect("Sampled worker identity");
        while tracked.alive() {
            assert!(start.elapsed() < REAP_DEADLINE, "Worker did not terminate");
            std::thread::sleep(Duration::from_millis(1));
        }
        drop(tracked);
        while !direct_children().is_empty() {
            assert!(start.elapsed() < REAP_DEADLINE, "Worker was not reaped");
            std::thread::sleep(Duration::from_millis(1));
        }
        (milliseconds(start), self.sample())
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Expected {
    SamplePe,
    Common {
        base: u64,
    },
    Metadata {
        base: u64,
    },
    Simple {
        base: u64,
    },
    Branch {
        base: u64,
    },
    Many {
        base: u64,
        hidden: u64,
        seeds: usize,
    },
    Data {
        base: u64,
    },
    External,
}
#[derive(Serialize)]
struct Fixture {
    name: String,
    path: PathBuf,
    pair: Option<[u64; 2]>,
    expected: Expected,
}
fn p16(bytes: &mut [u8], at: usize, n: u16) {
    bytes[at..at + 2].copy_from_slice(&n.to_le_bytes());
}
fn p32(bytes: &mut [u8], at: usize, n: u32) {
    bytes[at..at + 4].copy_from_slice(&n.to_le_bytes());
}
fn p64(bytes: &mut [u8], at: usize, n: u64) {
    bytes[at..at + 8].copy_from_slice(&n.to_le_bytes());
}
fn align16(n: usize) -> usize {
    (n + 15) & !15
}

// Independent, original AArch64 instruction sequences in a minimal linked ELF.
// Symbols intentionally omit the many-functions fixture's final direct callee.
// This is generated data only: no cross compiler, emulator, or execution.
fn generated_arm64(words: &[u32], offsets: &[usize]) -> (Vec<u8>, u64) {
    let base = 0x601000u64;
    let text_at = 0x100;
    let text_len = words.len() * 4;
    let symbols_at = align16(text_at + text_len);
    let symbols_len = (offsets.len() + 1) * 24;
    let strings_at = symbols_at + symbols_len;
    let mut strings = vec![0u8];
    let mut names = Vec::new();
    for index in 0..offsets.len() {
        names.push(strings.len());
        strings.extend_from_slice(format!("unseen_f{index:03}\0").as_bytes());
    }
    let section_names = b"\0.text\0.symtab\0.strtab\0.shstrtab\0";
    let section_names_at = strings_at + strings.len();
    let sections_at = align16(section_names_at + section_names.len());
    let mut b = vec![0u8; sections_at + 5 * 64];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    p16(&mut b, 16, 2); // ET_EXEC
    p16(&mut b, 18, 183); // EM_AARCH64
    p32(&mut b, 20, 1);
    p64(&mut b, 24, base);
    p64(&mut b, 32, 64);
    p64(&mut b, 40, sections_at as u64);
    p16(&mut b, 52, 64);
    p16(&mut b, 54, 56);
    p16(&mut b, 56, 1);
    p16(&mut b, 58, 64);
    p16(&mut b, 60, 5);
    p16(&mut b, 62, 4);
    p32(&mut b, 64, 1); // PT_LOAD
    p32(&mut b, 68, 5); // PF_R | PF_X
    p64(&mut b, 72, text_at as u64);
    p64(&mut b, 80, base);
    p64(&mut b, 88, base);
    p64(&mut b, 96, text_len as u64);
    p64(&mut b, 104, text_len as u64);
    p64(&mut b, 112, 0x100);
    for (index, &word) in words.iter().enumerate() {
        p32(&mut b, text_at + index * 4, word);
    }
    for (index, &offset) in offsets.iter().enumerate() {
        let at = symbols_at + (index + 1) * 24;
        p32(&mut b, at, names[index] as u32);
        b[at + 4] = 0x12; // STB_GLOBAL | STT_FUNC
        p16(&mut b, at + 6, 1);
        p64(&mut b, at + 8, base + offset as u64);
    }
    b[strings_at..strings_at + strings.len()].copy_from_slice(&strings);
    b[section_names_at..section_names_at + section_names.len()].copy_from_slice(section_names);
    for (slot, name, kind, flags, addr, offset, len, link, align, entry_size) in [
        (1, 1, 1, 6, base, text_at, text_len, 0, 4, 0),
        (2, 7, 2, 0, 0, symbols_at, symbols_len, 3, 8, 24),
        (3, 15, 3, 0, 0, strings_at, strings.len(), 0, 1, 0),
        (
            4,
            23,
            3,
            0,
            0,
            section_names_at,
            section_names.len(),
            0,
            1,
            0,
        ),
    ] {
        let at = sections_at + slot * 64;
        p32(&mut b, at, name);
        p32(&mut b, at + 4, kind);
        p64(&mut b, at + 8, flags);
        p64(&mut b, at + 16, addr);
        p64(&mut b, at + 24, offset as u64);
        p64(&mut b, at + 32, len as u64);
        p32(&mut b, at + 40, link);
        if kind == 2 {
            p32(&mut b, at + 44, 1); // First non-local symbol.
        }
        p64(&mut b, at + 48, align);
        p64(&mut b, at + 56, entry_size);
    }
    (b, base)
}

fn write_fixture(
    fixtures: &mut Vec<Fixture>,
    directory: &Path,
    name: &str,
    bytes: &[u8],
    pair: [u64; 2],
    expected: Expected,
) {
    let path = directory.join(name);
    let mut file = File::create_new(&path).unwrap();
    file.write_all(bytes).unwrap();
    fixtures.push(Fixture {
        name: name.into(),
        path,
        pair: Some(pair),
        expected,
    });
}
fn env_address(name: &str) -> Option<u64> {
    std::env::var(name).ok().map(|value| {
        u64::from_str_radix(value.trim().trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| panic!("{name} must be a hexadecimal address"))
    })
}
fn fixtures(directory: &Path) -> Vec<Fixture> {
    // Require this fixture rather than silently skipping the x64 Windows case.
    // Supply exact MSVC command/compiler identity in optional build metadata.
    let sample = std::env::var_os("GHIDRA_RUST_TEST_PE")
        .expect("Set GHIDRA_RUST_TEST_PE to the original tests/fixtures/sample.c PE");
    let mut fixtures = vec![Fixture {
        name: "original-sample-PE".into(),
        path: PathBuf::from(sample).canonicalize().unwrap(),
        pair: None,
        expected: Expected::SamplePe,
    }];
    for (name, (bytes, base), expected, pair) in [
        ("common-arm64-ELF", common::elf(true), 0, [0, 48]),
        ("common-arm64-PE", common::pe(), 0, [0, 48]),
        ("common-arm64-MachO", common::macho(), 0, [0, 48]),
        (
            "common-arm64-PE-metadata",
            common::arm64_pe_metadata(),
            1,
            [0xa0, 0x80],
        ),
    ] {
        write_fixture(
            &mut fixtures,
            directory,
            name,
            &bytes,
            pair.map(|offset| base + offset),
            if expected == 1 {
                Expected::Metadata { base }
            } else {
                Expected::Common { base }
            },
        );
    }
    let (bytes, base) = generated_arm64(
        &[
            0x11003400, 0xd65f03c0, // add w0,w0,#13; ret
            0x51001c00, 0xd65f03c0, // sub w0,w0,#7; ret
        ],
        &[0, 8],
    );
    write_fixture(
        &mut fixtures,
        directory,
        "unseen-arm64-simple-ELF",
        &bytes,
        [base, base + 8],
        Expected::Simple { base },
    );
    let (bytes, base) = generated_arm64(
        &[
            0x34000080, // cbz w0, +16
            0x11002c00, 0xd65f03c0, 0xd503201f, // add #11; ret; nop
            0x52800260, 0xd65f03c0, // mov w0,#19; ret
            0x11005400, 0xd65f03c0, // second function: add #21; ret
        ],
        &[0, 24],
    );
    write_fixture(
        &mut fixtures,
        directory,
        "unseen-arm64-branch-ELF",
        &bytes,
        [base, base + 24],
        Expected::Branch { base },
    );
    let mut words = vec![0xa9bf7bfd, 0x910003fd, 0, 0xa8c17bfd, 0xd65f03c0];
    let mut offsets = vec![0];
    for n in 1..300u32 {
        offsets.push(words.len() * 4);
        words.extend([0x11000000 | ((n + 1) << 10), 0xd65f03c0]);
    }
    let hidden_offset = words.len() * 4;
    // The call at +8 reaches an unseeded leaf after all 300 symbol seeds.
    words[2] = 0x94000000 | ((hidden_offset as u32 - 8) / 4);
    words.extend([0x11056800, 0xd65f03c0]); // add #346; ret
    let (bytes, base) = generated_arm64(&words, &offsets);
    write_fixture(
        &mut fixtures,
        directory,
        "unseen-arm64-301-functions-ELF",
        &bytes,
        [base, base + offsets[299] as u64],
        Expected::Many {
            base,
            hidden: base + hidden_offset as u64,
            seeds: offsets.len(),
        },
    );
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
    let (mut bytes, base) = common::pe();
    bytes[0x200..0x200 + words.len()].copy_from_slice(&words);
    bytes[0x220..0x228].copy_from_slice(&0x2166657261746164u64.to_le_bytes());
    write_fixture(
        &mut fixtures,
        directory,
        "common-arm64-data-PE",
        &bytes,
        [base, base + 48],
        Expected::Data { base },
    );
    if let Some(input) = std::env::var_os("GHIDRA_RUST_BENCH_INPUT") {
        let pair = match (
            env_address("GHIDRA_RUST_BENCH_A"),
            env_address("GHIDRA_RUST_BENCH_B"),
        ) {
            (None, None) => None,
            (Some(a), Some(b)) => Some([a, b]),
            _ => panic!("Set both GHIDRA_RUST_BENCH_A and GHIDRA_RUST_BENCH_B, or neither"),
        };
        fixtures.push(Fixture {
            name: "optional-input".into(),
            path: PathBuf::from(input).canonicalize().unwrap(),
            pair,
            expected: Expected::External,
        });
    }
    fixtures
}

fn choose_pair(fixture: &Fixture, info: &BinaryInfo, functions: &[FunctionInfo]) -> [u64; 2] {
    let pair = fixture.pair.unwrap_or_else(|| {
        let a = if matches!(fixture.expected, Expected::SamplePe) {
            assert!(
                info.format.contains("PE"),
                "GHIDRA_RUST_TEST_PE must be a PE fixture"
            );
            functions
                .iter()
                .find(|f| f.name == "branch_loop")
                .expect("Original sample PE must export branch_loop")
                .address
        } else {
            functions
                .iter()
                .find(|f| f.address == info.entry)
                .or_else(|| functions.first())
                .expect("Input has no supported function")
                .address
        };
        let b = functions
            .iter()
            .find(|f| f.address != a)
            .map_or(a, |f| f.address);
        [a, b]
    });
    for address in pair {
        assert!(
            code_address(info, address),
            "Selected function {address:#x} is not file-backed executable code"
        );
    }
    pair
}

fn check_evidence(
    fixture: &Fixture,
    info: &BinaryInfo,
    report: &CallAnalysis,
    functions: &[FunctionInfo],
) {
    let call = |caller, address, target| {
        report
            .references
            .iter()
            .any(|r| r.caller == caller && r.address == address && r.target == target)
    };
    match fixture.expected {
        Expected::Common { base } | Expected::Metadata { base } => {
            assert!(
                call(base, base + 8, base + 48),
                "Missing original direct-call evidence"
            );
            if matches!(fixture.expected, Expected::Common { .. }) {
                assert!(
                    report.unresolved_calls >= 1,
                    "Unknown register call must remain unresolved"
                );
            }
            if matches!(fixture.expected, Expected::Metadata { .. }) {
                assert!(call(base + 0xa0, base + 0xa8, base + 0xc0));
                assert!(
                    functions
                        .iter()
                        .any(|f| f.address == base + 0xc0 && f.name == "fixture_import")
                );
                assert!(
                    !functions.iter().any(|f| f.address == base + 0x90),
                    "Fragment is not independent function evidence"
                );
            }
        }
        Expected::Many {
            base,
            hidden,
            seeds,
        } => {
            assert_eq!(info.functions.len(), seeds);
            assert!(!info.functions.iter().any(|f| f.address == hidden));
            assert_eq!(functions.len(), seeds + 1);
            assert_eq!(report.functions_examined, seeds + 1);
            assert!(
                call(base, base + 8, hidden),
                "Unseeded direct callee must be discovered"
            );
        }
        Expected::Data { base } => {
            let data = report.data.as_ref().expect("Missing bounded data evidence");
            let refs: Vec<_> = data
                .references
                .iter()
                .filter(|r| r.function == base)
                .collect();
            assert_eq!(refs.len(), 2);
            for (address, provenance) in [
                (base, DataProvenance::InstructionLocal),
                (base + 16, DataProvenance::Propagated),
            ] {
                assert!(refs.iter().any(|r| r.address == address
                    && r.target == base + 32
                    && r.size == 8
                    && r.access == DataAccess::Read
                    && r.provenance == provenance));
            }
            assert!(
                data.unresolved_accesses >= 1,
                "Post-call register load must remain unresolved"
            );
            assert!(!functions.iter().any(|f| f.address == base + 32));
        }
        Expected::Simple { .. } | Expected::Branch { .. } => {
            assert_eq!(report.functions_examined, 2);
            assert!(report.references.is_empty());
        }
        Expected::SamplePe | Expected::External => (),
    }
}

struct Discovered {
    state: Discovery,
    index: CallIndex,
    functions: Vec<FunctionInfo>,
    parent_timings: Vec<Value>,
    exhausted: bool,
    external_batch_cap: Option<usize>,
}
fn discover(
    sampler: &mut Sampler,
    worker: &mut WorkerClient,
    info: &BinaryInfo,
    epoch: u64,
    external_batch_cap: Option<usize>,
) -> Discovered {
    let start = Instant::now();
    let mut state = Discovery::new(
        code_address(info, info.entry).then_some(info.entry),
        info.functions.iter().map(|f| f.address),
        info.functions_truncated,
    );
    let new_ms = milliseconds(start);
    let mut functions = info.functions.clone();
    let mut adopted = inventory::Inventory::default();
    let mut index = CallIndex::new(CallAnalysis::default());
    let mut timings = Vec::new();
    loop {
        if external_batch_cap.is_some_and(|cap| state.batches >= cap) && state.remaining() > 0 {
            timings.push(json!({ "external_batch_cap": external_batch_cap,
                "cap_reached": true, "remaining": state.remaining() }));
            break;
        }
        let start = Instant::now();
        let request = state.begin(1, epoch, 0);
        let begin_ms = milliseconds(start);
        let Some(request) = request else {
            assert_eq!(state.remaining(), 0, "Discovery stopped before exhaustion");
            timings.push(json!({ "exhausted_begin_ms": begin_ms, "new_ms": new_ms }));
            break;
        };
        assert!(
            state.batches < MAX_FUNCTIONS,
            "Discovery failed to make bounded seed progress"
        );
        let request = adopted.bind(request);
        let Response::DiscoveryBatch { mut batch } =
            sampler.request(worker, request.clone(), "discover")
        else {
            panic!("Expected bounded discovery reply");
        };
        let start = Instant::now();
        // The desktop's adoption: reconstruct the inventory, then commit.
        let changed = adopted
            .commit(&mut state, info, &request, &mut batch)
            .unwrap();
        let commit_ms = milliseconds(start);
        let start = Instant::now();
        let snapshot = state.snapshot();
        let snapshot_ms = milliseconds(start);
        let start = Instant::now();
        let replacement = CallIndex::new(snapshot);
        let index_ms = milliseconds(start);
        // Dropping the previous index is outside the constructor timing.
        index = replacement;
        let start = Instant::now();
        let saved = state.save();
        let save_ms = milliseconds(start);
        saved.validate(info).unwrap();
        functions = adopted.functions().to_vec();
        let row = json!({ "batch": state.batches, "begin_ms": begin_ms, "inventory_changed": changed,
            "commit_ms": commit_ms, "snapshot_ms": snapshot_ms,
            "index_ms": index_ms, "save_ms": save_ms,
            "remaining": state.remaining(), "examined": batch.analysis.functions_examined,
            "decode_attempts": batch.analysis.decode_attempts,
            "indexed_calls": index.report.references.len(),
            "indexed_data": index.report.data.as_ref().map(|d| d.references.len()),
        });
        json_line(
            &mut sampler.records,
            &json!({ "phase": "parent_discovery_adoption", "timings": row }),
        );
        timings.push(row);
        sampler.sample();
    }
    let exhausted = state.remaining() == 0;
    let exhausted_begin_ms = if exhausted {
        let start = Instant::now();
        assert!(
            state.begin(1, epoch, 0).is_none(),
            "Completed discovery must not send another request"
        );
        Some(milliseconds(start))
    } else {
        None
    };
    let saved = state.save();
    saved.validate(info).unwrap();
    assert!(exhausted || (external_batch_cap.is_some() && saved.report.partial));
    json_line(
        &mut sampler.records,
        &json!({ "phase": "discovery_stopped",
            "exhausted": exhausted, "external_batch_cap": external_batch_cap,
            "cap_reached": !exhausted, "pending_functions": state.remaining(),
            "second_discover_is_parent_noop": exhausted, "exhausted_begin_ms": exhausted_begin_ms,
            "snapshot": saved,
        }),
    );
    Discovered {
        state,
        index,
        functions,
        parent_timings: timings,
        exhausted,
        external_batch_cap,
    }
}

fn checked_graph(
    sampler: &mut Sampler,
    worker: &mut WorkerClient,
    info: &BinaryInfo,
    address: u64,
    phase: &str,
) -> FunctionView {
    let Response::Graph { view } = sampler.request(worker, Request::Graph { address }, phase)
    else {
        panic!("Expected real graph");
    };
    assert_eq!(view.address, address);
    assert!(!view.blocks.is_empty(), "Missing CFG at {address:#x}");
    let mut pcs = BTreeSet::new();
    for instruction in view.blocks.iter().flat_map(|b| &b.instructions) {
        assert!(code_address(info, instruction.address));
        assert!(!instruction.bytes.is_empty() && !instruction.mnemonic.is_empty());
        assert!(pcs.insert(instruction.address), "Duplicate graph PC");
        if info.architecture == "AArch64" {
            assert_eq!(instruction.bytes.len(), 4);
        }
    }
    assert!(pcs.contains(&address));
    for call in &view.calls {
        assert!(pcs.contains(&call.address));
        // Raw CFG calls may leave mapped code; only confirmed discovery
        // evidence and semantic navigation tokens require executable targets.
    }
    view
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ResultDigests {
    graph_sha256: String,
    decompiled_sha256: String,
}
#[derive(Serialize)]
struct FunctionStep {
    step: &'static str,
    address: u64,
    digests: ResultDigests,
    equal_to_previous_same_address: Option<bool>,
}
#[derive(Serialize)]
struct WarmResults {
    steps: Vec<FunctionStep>,
    last_by_address: BTreeMap<u64, ResultDigests>,
    repeated_address_digests_equal: bool,
}
fn coverage_context(info: &BinaryInfo, discovered: &Discovered) -> Value {
    let saved = discovered.state.save();
    json!({
        "open_inventory_functions": info.functions.len(),
        "open_inventory_sha256": value_digest(&info.functions),
        "last_discovery_inventory_functions": discovered.functions.len(),
        "last_discovery_inventory_sha256": value_digest(&discovered.functions),
        "initial_entry_seed": code_address(info, info.entry).then_some(info.entry),
        "terminal_statuses_sha256": value_digest(&(&saved.done, &saved.limited, &saved.failed)),
        "pending_sha256": value_digest(&saved.pending),
        "pending_functions": saved.pending.len(), "done_functions": saved.done.len(),
        "limited_functions": saved.limited.len(), "failed_functions": saved.failed.len(),
        "batches": saved.batches, "exhausted": discovered.exhausted,
        "external_batch_cap": discovered.external_batch_cap, "partial": saved.report.partial,
    })
}
fn warm_aba(
    sampler: &mut Sampler,
    worker: &mut WorkerClient,
    info: &BinaryInfo,
    fixture: &Fixture,
    discovered: &Discovered,
    pair: [u64; 2],
) -> WarmResults {
    let mut results = BTreeMap::new();
    let mut cached = result_measurement::CachedResults::new(info, &discovered.functions);
    cached.publish(std::sync::Arc::new(discovered.state.save()));
    let mut steps = Vec::new();
    let controlled = !matches!(fixture.expected, Expected::External);
    let context = coverage_context(info, discovered);
    for (step, address) in [pair[0], pair[1], pair[0]].into_iter().enumerate() {
        let phase = ["A-first", "B", "A-warm"][step];
        let view = checked_graph(sampler, worker, info, address, phase);
        let decompiled = sampler.request(worker, Request::Decompile { address }, phase);
        let Response::Decompiled {
            address: returned,
            text,
            mappings,
            semantics,
        } = &decompiled
        else {
            panic!("Expected real decompilation at {address:#x}");
        };
        assert_eq!(*returned, address);
        assert!(!text.is_empty(), "Missing decompiler text at {address:#x}");
        if controlled {
            assert!(
                !mappings.is_empty(),
                "Controlled fixture has no genuine semantic locations at {address:#x}"
            );
        }
        selection::validate_mappings(text, mappings, &info.sections).unwrap();
        semantics.validate(text, address, &info.sections).unwrap();
        let pcs: BTreeSet<_> = view
            .blocks
            .iter()
            .flat_map(|b| &b.instructions)
            .map(|i| i.address)
            .collect();
        // Engine analysis can follow code beyond the application's bounded CFG,
        // including in the original data-reference fixture. Keep genuine PCs;
        // executable/UTF-8 validation above applies universally.
        let mapping_pcs_outside_graph = mappings
            .iter()
            .flat_map(|m| &m.addresses)
            .filter(|pc| !pcs.contains(pc))
            .count();
        // Cross-check confirmed discovery calls against independently requested
        // CFGs. Bounded graph truncation may omit evidence from later blocks.
        for reference in discovered
            .index
            .report
            .references
            .iter()
            .filter(|r| r.caller == address && pcs.contains(&r.address))
        {
            assert!(
                view.calls
                    .iter()
                    .any(|c| c.address == reference.address && c.target == Some(reference.target)),
                "Confirmed call evidence differs from the graph"
            );
        }
        if let Expected::Branch { base } = fixture.expected
            && address == base
        {
            assert!(
                view.edges
                    .iter()
                    .any(|e| e.kind == EdgeKind::True && e.target == Some(base + 16))
            );
            assert!(
                view.edges
                    .iter()
                    .any(|e| e.kind == EdgeKind::False && e.target == Some(base + 4))
            );
        }
        if let Expected::Simple { base } = fixture.expected {
            let expected = if address == base {
                0x11003400u32
            } else {
                0x51001c00u32
            };
            assert_eq!(view.blocks[0].instructions[0].bytes, expected.to_le_bytes());
            assert!(text.contains("return"));
        }
        if let Expected::Metadata { base } = fixture.expected
            && address == base + 0xa0
        {
            assert!(text.contains("fixture_import"));
            assert!(
                semantics.tokens.iter().any(|token| matches!(token.kind,
                ghidra_rust::semantic::TokenKind::Call { target } if target == base + 0xc0)),
                "Import navigation must use a genuine engine call target"
            );
        }
        let hashes = ResultDigests {
            graph_sha256: value_digest(&view),
            decompiled_sha256: value_digest(&decompiled),
        };
        let equality = results
            .insert(address, hashes.clone())
            .map(|previous| previous == hashes);
        // Include live graph/text/mappings plus retained discovery state and
        // index in this observation. Results from previous functions are dropped.
        let memory = sampler.sample();
        json_line(
            &mut sampler.records,
            &json!({ "phase": "validated_function", "step": phase,
                "address": address, "digests": hashes, "memory_with_current_results": memory,
                "equal_to_previous_same_address": equality,
                "digest_equality_enforced": false, "parent_coverage_context": context,
                "worker_context": "May acquire/promote callee/import knowledge during requests; parent inventory is the last discovery response, not a query of current engine state",
                "graph_pcs": pcs.len(), "mapping_pcs_outside_graph": mapping_pcs_outside_graph,
                "mapping_ranges": mappings.len(),
                "semantic_tokens": semantics.tokens.len(), "pseudocode_bytes": text.len(),
            }),
        );
        steps.push(FunctionStep {
            step: phase,
            address,
            digests: hashes,
            equal_to_previous_same_address: equality,
        });
        cached.admit(info, view, decompiled);
        // A/B/A can acquire shared global types even with an unchanged function
        // inventory. Preserve every difference; each result was validated above.
    }
    let cached_visits = cached.measure(pair);
    let memory = sampler.sample();
    json_line(
        &mut sampler.records,
        &json!({ "phase": "cached_function_visits", "cached_visits": cached_visits, "memory_with_store": memory }),
    );
    let repeated_address_digests_equal = steps
        .iter()
        .all(|step| step.equal_to_previous_same_address != Some(false));
    WarmResults {
        steps,
        last_by_address: results,
        repeated_address_digests_equal,
    }
}

fn evidence_digest(discovered: &Discovered) -> String {
    let report = &discovered.index.report;
    // Compare evidence separately from work counters. Only controlled fixtures
    // assert equality; external capped/replayed engine contexts may differ.
    value_digest(&(
        &discovered.functions,
        &report.references,
        report.data.as_ref().map(|d| &d.references),
        report.unresolved_calls,
        report.skipped_fallthrough_calls,
        report.failed_functions,
        report.partial,
    ))
}

fn start_open(
    sampler: &mut Sampler,
    fixture: &Fixture,
    executable: &Path,
    input_hash: &str,
) -> (WorkerClient, BinaryInfo, f64) {
    let start = Instant::now();
    let mut worker = WorkerClient::start_using_executable(
        eframe::egui::Context::default(),
        &fixture.path,
        executable,
    )
    .unwrap();
    let spawn_ms = milliseconds(start);
    sampler.attach(executable);
    let Response::Opened { info } = sampler.request(
        &mut worker,
        Request::Open {
            path: fixture
                .path
                .to_str()
                .expect("Input path must be representable as UTF-8")
                .into(),
        },
        "open",
    ) else {
        panic!("Expected Opened");
    };
    assert_eq!(info.sha256, input_hash);
    assert_eq!(info.file_len, fs::metadata(&fixture.path).unwrap().len());
    (worker, info, spawn_ms)
}

fn replay_inventory(
    sampler: &mut Sampler,
    worker: &mut WorkerClient,
    functions: &[FunctionInfo],
    opened: &BinaryInfo,
) {
    // Open has already installed the original inventory, including large PE
    // runtime tables. Replay only genuinely new/changed function context.
    let updates: Vec<_> = functions
        .iter()
        .filter(|function| {
            ghidra_rust::model::function_at(&opened.functions, function.address)
                .is_none_or(|existing| existing.name != function.name)
        })
        .cloned()
        .collect();
    json_line(
        &mut sampler.records,
        &json!({ "phase": "restart_replay_inventory",
            "original_inventory_functions": opened.functions.len(),
            "retained_inventory_functions": functions.len(),
            "functions_requiring_sync": updates.len(),
            "sync_chunk_limit": ghidra_rust::model::MAX_DISCOVERY_SYNC_FUNCTIONS,
        }),
    );
    for chunk in ghidra_rust::model::sync_chunks(&updates) {
        assert!(matches!(
            sampler.request(
                worker,
                Request::SyncFunctions {
                    functions: chunk.to_vec(),
                },
                "restart-replay-functions"
            ),
            Response::FunctionsSynced
        ));
    }
}

fn command_text(program: &str, args: &[&str]) -> String {
    let output = Command::new(program)
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|e| panic!("Metadata command {program}: {e}"));
    assert!(
        output.status.success(),
        "Metadata {program}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
fn hash_file(path: &Path) -> Value {
    json!({ "path": path, "sha256": session::fingerprint(path).unwrap(),
        "bytes": fs::metadata(path).unwrap().len() })
}

struct TraceFlushOnFailure(bool);
impl Drop for TraceFlushOnFailure {
    fn drop(&mut self) {
        if self.0 {
            // Preserve terminal trace health after failed assertions too. Avoid
            // a second panic while unwinding; surface any flush error in output.
            if let Err(error) = ghidra_rust::performance::flush() {
                eprintln!("Performance trace flush after failed baseline: {error}");
            }
        }
    }
}

#[test]
#[ignore = "Opt-in native Windows baseline: --release --test windows_analysis_baseline -- --ignored --nocapture --test-threads=1"]
fn profile_windows_production_workers() {
    if cfg!(debug_assertions) {
        panic!("Run this baseline with --release");
    }
    ghidra_rust::performance::init().unwrap();
    let mut trace_guard = TraceFlushOnFailure(true);
    let measurement_mode = MeasurementMode::from_env();
    let repeats: usize = std::env::var("GHIDRA_RUST_BENCH_REPEATS").map_or(3, |value| {
        value
            .parse()
            .expect("GHIDRA_RUST_BENCH_REPEATS must be an integer")
    });
    assert!(
        (1..=20).contains(&repeats),
        "Use between 1 and 20 repetitions"
    );
    let external_batches: usize =
        std::env::var("GHIDRA_RUST_BENCH_EXTERNAL_BATCHES").map_or(8, |value| {
            value
                .parse()
                .expect("GHIDRA_RUST_BENCH_EXTERNAL_BATCHES must be an integer")
        });
    assert!(
        external_batches <= MAX_FUNCTIONS,
        "External batch cap exceeds maximum function count"
    );
    let output = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/analysis-baseline");
    fs::create_dir_all(&output).unwrap();
    // Keep the entire report directory and generated original fixtures even if
    // a later measurement panics. No existing output or input is overwritten.
    let directory = tempfile::Builder::new()
        .prefix("windows-")
        .tempdir_in(&output)
        .unwrap()
        .keep();
    let fixtures_dir = directory.join("fixtures");
    fs::create_dir(&fixtures_dir).unwrap();
    let fixtures = fixtures(&fixtures_dir);
    let executable = Path::new(env!("CARGO_BIN_EXE_ghidra-rust"));
    let current_executable = std::env::current_exe().unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_build = std::env::var_os("GHIDRA_RUST_BENCH_BUILD_METADATA").map(|path| {
        let path = PathBuf::from(path);
        json!({ "identity": hash_file(&path), "record": fs::read_to_string(path).unwrap() })
    });
    let source_metadata = if let Some(path) = std::env::var_os("GHIDRA_RUST_BENCH_SOURCE_METADATA")
    {
        let path = PathBuf::from(path);
        let supplied: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(
            supplied.is_object(),
            "Source metadata must be a JSON object"
        );
        json!({ "mode": "supplied_export_metadata", "identity": hash_file(&path), "record": supplied })
    } else {
        json!({ "mode": "live_git_checkout",
            "git_commit": command_text("git", &["rev-parse", "HEAD"]),
            "git_branch": command_text("git", &["branch", "--show-current"]),
            "git_worktree": command_text("git", &["rev-parse", "--show-toplevel"]),
            "git_worktrees": command_text("git", &["worktree", "list", "--porcelain"]),
            "git_status": command_text("git", &["status", "--porcelain=v1", "--untracked-files=normal"]),
            "git_diff_sha256": digest(command_text("git", &["diff", "HEAD", "--", "."]).as_bytes()),
        })
    };
    let metadata = json!({
        "schema": 2, "started_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
        "scope": "native Windows instrumented analysis test client plus production worker; no native GUI",
        "platform": std::env::consts::OS, "architecture": std::env::consts::ARCH,
        "windows_version": command_text("cmd.exe", &["/d", "/c", "ver"]),
        "rustc": command_text("rustc", &["-vV"]), "cargo": command_text("cargo", &["-V"]),
        "source_metadata": source_metadata,
        "engine_fingerprint": project::ENGINE_FINGERPRINT,
        "worker_build": hash_file(executable), "harness_build": hash_file(&current_executable),
        "cargo_lock": hash_file(&root.join("Cargo.lock")), "manifest": hash_file(&root.join("Cargo.toml")),
        "harness_source": hash_file(&root.join("tests/windows_analysis_baseline.rs")),
        "sample_source": hash_file(&root.join("tests/fixtures/sample.c")),
        "common_fixture_source": hash_file(&root.join("tests/common/mod.rs")),
        "assembly_sources": [hash_file(&root.join("tests/fixtures/aarch64.S")),
            hash_file(&root.join("tests/fixtures/arm64-pe.S")), hash_file(&root.join("tests/fixtures/aarch64-data.S"))],
        "fixture_build": fixture_build,
        "config": { "repeats": repeats, "measurement_mode": measurement_mode,
            "sample_interval_ms": SAMPLE_INTERVAL.as_millis(), "poll_sleep_ms": 1,
            "in_request_sampling": measurement_mode == MeasurementMode::Memory,
            "sample_interval_scope": "Minimum gap after a completed sample in memory mode while polling an unanswered request; boundary samples occur in both modes.",
            "request_timing_scope": "Caller send through terminal WorkerClient::poll, including reader parsing/validation, scheduling and progress handling; excludes terminal boundary sample and report serialization.",
            "sampling_timing_scope": "Sample collection plus memory JSON serialization/flush; request/run sampling totals also include the sample timing-record write. Other report/progress writes are excluded from sampling totals.",
            "request_deadline_ms": REQUEST_DEADLINE.as_millis(), "profile": "release",
            "external_batch_cap": if external_batches == 0 { None } else { Some(external_batches) },
            "external_zero_means_exhaustion": true, "fixture_discovery_exhausts": true,
            "performance_feature": cfg!(feature = "performance"),
            "rustflags": std::env::var_os("RUSTFLAGS"), "cargo_target_dir": std::env::var_os("CARGO_TARGET_DIR"),
            "cargo_build_target": std::env::var_os("CARGO_BUILD_TARGET"),
            "performance_directory": std::env::var_os("GHIDRA_RUST_PERF_DIR"),
            "logical_cpus_available": std::thread::available_parallelism().unwrap().get(),
        },
        "fixtures": fixtures,
        "limitations": [
            "Windows jobs/watchdogs are resource controls, without filesystem or network isolation. Use trusted inputs.",
            "Working set and private committed bytes are Windows metrics, not PSS. Working set sums can double-count shared pages.",
            "Samples are non-atomic, can miss short peaks, and include observer/test-harness memory. Only observed peaks are reported.",
            "Restart comparisons retain original discovery state/index alongside recomputed state/index; client totals include both.",
            "Sampling, polling, JSON recording, validation, and the persistent client allocator perturb the workload.",
            "Request latency ends when the caller polls the terminal reply; no reader-thread receipt timestamp is measured. The nominal 1 ms sleep can overshoot with Windows timer/scheduling granularity.",
            "Latency mode samples only between requests and can miss all transient active-worker peaks. Memory mode samples during unanswered requests and its latency includes blocking snapshots/JSON flushes; compare only matching modes.",
            "Sample collection spans sequential process reads; sample_and_memory_write_ms excludes its own timing-record write. Cumulative sampling overhead is observer wall time, not a subtractable correction to latency.",
            "Per-process page_fault_count is a cumulative Windows counter (including soft faults), can wrap, and is not hard-fault or I/O latency attribution.",
            "Parent begin/commit/snapshot/index/save timings are measured separately outside worker requests; destructor time is excluded from index construction.",
            "Each repetition starts a fresh worker and also restarts/replays the function inventory; the client process and OS file cache persist.",
            "Builds, fixture generation, input hashing, rendering, project I/O, and Ghidra comparisons are outside measured request scope.",
            "Input hashes and fixture preparation warm filesystem caches. These are not cold-cache measurements.",
            "Optional single-function inputs necessarily use A == B; the selected addresses are recorded.",
            "MSVC fixture compiler provenance is recorded when GHIDRA_RUST_BENCH_BUILD_METADATA is supplied; otherwise it is unknown.",
            "External discovery defaults to eight batches per fresh worker; pending coverage and exact measured work are recorded. Fixtures always exhaust.",
            "External A/B/A and restart digests/evidence may differ as worker context grows or capped seed coverage changes; all differences are recorded without equality assertions.",
        ],
    });
    let mut file = File::create_new(directory.join("metadata.json")).unwrap();
    serde_json::to_writer_pretty(&mut file, &metadata).unwrap();
    file.write_all(b"\n").unwrap();
    println!("Windows raw analysis baseline: {}", directory.display());
    let mut summaries = BufWriter::new(File::create_new(directory.join("runs.jsonl")).unwrap());
    for fixture in &fixtures {
        let input_hash = session::fingerprint(&fixture.path).unwrap();
        let input_bytes = fs::metadata(&fixture.path).unwrap().len();
        json_line(
            &mut summaries,
            &json!({ "phase": "input_before", "measurement_mode": measurement_mode, "fixture": fixture,
            "input_sha256": input_hash, "input_bytes": input_bytes }),
        );
        for repeat in 1..=repeats {
            let name = format!("{}-{repeat}", fixture.name);
            println!("Measuring {name}");
            let mut sampler = Sampler::new(&directory, &name, measurement_mode);
            // Retain the selected mode even if this repetition fails before a
            // completed summary or request record can be written.
            json_line(
                &mut summaries,
                &json!({ "phase": "run_started", "fixture": fixture.name,
                    "repeat": repeat, "measurement_mode": measurement_mode }),
            );
            let before = sampler.sample();
            let (mut worker, info, spawn_ms) =
                start_open(&mut sampler, fixture, executable, &input_hash);
            let external_cap =
                if matches!(fixture.expected, Expected::External) && external_batches != 0 {
                    Some(external_batches)
                } else {
                    None
                };
            let discovery = discover(&mut sampler, &mut worker, &info, 1, external_cap);
            check_evidence(
                fixture,
                &info,
                &discovery.index.report,
                &discovery.functions,
            );
            let pair = choose_pair(fixture, &info, &discovery.functions);
            let expected_results =
                warm_aba(&mut sampler, &mut worker, &info, fixture, &discovery, pair);
            let evidence = evidence_digest(&discovery);
            let (shutdown_ms, after_first_shutdown) = sampler.stop(worker);
            assert_eq!(
                session::fingerprint(&fixture.path).unwrap(),
                input_hash,
                "Input changed during analysis"
            );
            let (mut restarted, reopened, restart_spawn_ms) =
                start_open(&mut sampler, fixture, executable, &input_hash);
            replay_inventory(
                &mut sampler,
                &mut restarted,
                &discovery.functions,
                &reopened,
            );
            // Genuine discovery is rerun, not restored from a claimed cache.
            let replayed = discover(&mut sampler, &mut restarted, &reopened, 2, external_cap);
            check_evidence(
                fixture,
                &reopened,
                &replayed.index.report,
                &replayed.functions,
            );
            let replayed_evidence = evidence_digest(&replayed);
            let evidence_equal = evidence == replayed_evidence;
            let replayed_results = warm_aba(
                &mut sampler,
                &mut restarted,
                &reopened,
                fixture,
                &replayed,
                pair,
            );
            let results_equal =
                expected_results.last_by_address == replayed_results.last_by_address;
            let restart_step_equality: Vec<_> = expected_results
                .steps
                .iter()
                .zip(&replayed_results.steps)
                .map(|(before, after)| {
                    json!({
                        "step": before.step, "address": before.address,
                        "addresses_equal": before.address == after.address,
                        "digests_equal": before.digests == after.digests,
                    })
                })
                .collect();
            let controlled = !matches!(fixture.expected, Expected::External);
            let initial_context = coverage_context(&info, &discovery);
            let replay_context = coverage_context(&reopened, &replayed);
            let coverage_equal = initial_context == replay_context;
            let replay_expands_context = !discovery
                .functions
                .iter()
                .map(|f| (f.address, &f.name))
                .eq(info.functions.iter().map(|f| (f.address, &f.name)));
            let coverage_equality_enforced = controlled && !replay_expands_context;
            json_line(
                &mut sampler.records,
                &json!({ "phase": "restart_comparison",
                    "evidence_equal": evidence_equal, "last_result_digests_equal": results_equal,
                    "step_digest_equality": restart_step_equality,
                    "parent_coverage_equal": coverage_equal, "equality_enforced": controlled,
                    "replay_expands_initial_inventory_context": replay_expands_context,
                    "coverage_equality_enforced": coverage_equality_enforced,
                    "initial_context": initial_context, "replay_context": replay_context,
                    "initial_steps": expected_results.steps, "replay_steps": replayed_results.steps,
                    "context_caveat": "Worker knowledge may grow during function requests or inventory replay; capped discovery can examine different seeds. Expanded replay context can change graph boundaries/statuses. Differences are recorded; coverage equality is required only for equivalent initial inventories.",
                }),
            );
            if coverage_equality_enforced {
                assert!(
                    coverage_equal,
                    "Equivalent-context controlled fixture restart changed reconstructed discovery coverage"
                );
            }
            if controlled {
                assert!(
                    evidence_equal,
                    "Controlled fixture restart changed discovery evidence"
                );
                assert!(
                    results_equal,
                    "Controlled fixture restart changed CFG, text, mappings, or semantics"
                );
            }
            let (restart_shutdown_ms, after_restart_shutdown) = sampler.stop(restarted);
            let after_hash = session::fingerprint(&fixture.path).unwrap();
            assert_eq!(
                after_hash, input_hash,
                "Input changed during restart/replay"
            );
            json_line(
                &mut summaries,
                &json!({
                    "fixture": fixture, "repeat": repeat, "measurement_mode": measurement_mode,
                    "input_sha256_before": input_hash,
                    "input_sha256_after": after_hash, "input_bytes": input_bytes,
                    "addresses": pair, "aba_has_distinct_functions": pair[0] != pair[1],
                    "spawn_ms": spawn_ms, "shutdown_ms": shutdown_ms,
                    "restart_spawn_ms": restart_spawn_ms, "restart_shutdown_ms": restart_shutdown_ms,
                    "client_before_start": before, "after_first_shutdown": after_first_shutdown,
                    "after_restart_shutdown": after_restart_shutdown,
                    "observed_peak_sum_working_set_bytes": sampler.peak_sum_working_set_bytes,
                    "observed_peak_sum_private_bytes": sampler.peak_sum_private_bytes,
                    "memory_sample_count": sampler.samples, "cumulative_sampling_ms": sampler.sampling_ms,
                    "evidence_sha256": evidence,
                    "restart_evidence_sha256": replayed_evidence,
                    "restart_evidence_equal": evidence_equal, "restart_last_result_digests_equal": results_equal,
                    "restart_step_digest_equality": restart_step_equality,
                    "parent_coverage_equal": coverage_equal, "equality_enforced": controlled,
                    "parent_coverage_context": initial_context, "restart_parent_coverage_context": replay_context,
                    "results": expected_results, "restart_results": replayed_results, "parent_discovery_timings": discovery.parent_timings,
                    "parent_restart_discovery_timings": replayed.parent_timings,
                    "discovery": discovery.state.save(), "restarted_discovery": replayed.state.save(),
                "discovery_exhausted": discovery.exhausted, "restart_discovery_exhausted": replayed.exhausted,
                "external_batch_cap": discovery.external_batch_cap,
                "discovery_cap_reached": !discovery.exhausted, "restart_discovery_cap_reached": !replayed.exhausted,
                "measured_work": { "batches": discovery.state.batches,
                    "functions_examined": discovery.index.report.functions_examined,
                    "decode_attempts": discovery.index.report.decode_attempts,
                    "pending_functions": discovery.state.remaining(),
                    "partial": discovery.index.report.partial },
                "restart_measured_work": { "batches": replayed.state.batches,
                    "functions_examined": replayed.index.report.functions_examined,
                    "decode_attempts": replayed.index.report.decode_attempts,
                    "pending_functions": replayed.state.remaining(),
                    "partial": replayed.index.report.partial },
                    "requests_file": format!("{name}-requests.jsonl"), "memory_file": format!("{name}-memory.jsonl"),
                }),
            );
        }
    }
    // Verify that the actual production worker and harness executables also
    // stayed fixed throughout the run, rather than accidentally mixing builds.
    assert_eq!(hash_file(executable), metadata["worker_build"]);
    assert_eq!(hash_file(&current_executable), metadata["harness_build"]);
    ghidra_rust::performance::flush().unwrap();
    trace_guard.0 = false;
    println!(
        "Completed Windows raw analysis baseline: {}",
        directory.display()
    );
}
