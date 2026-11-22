//! Bounded, synchronous analysis. This module runs in the disposable worker process.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(test)]
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use ghidra_decompiler::address::Address;
use ghidra_decompiler::program::Program;
use object::{Object, ObjectSection, ObjectSegment, SectionFlags, SectionKind, SegmentFlags};
use sha2::{Digest, Sha256};

use crate::model::*;

mod cfg;
mod function_candidates;
pub(crate) mod linkage;
#[doc(hidden)]
pub mod managed;
mod patterns;
mod pointers;
mod search;
mod strings;

use cfg::*;
use managed::Report;
use strings::*;

const MAX_INSTRUCTIONS: usize = 2048;
const MAX_BLOCKS: usize = 128;
const MAX_BYTES: usize = MAX_BYTE_READ;
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CRYPTO_RESULTS: usize = 10_000;
const SCAN_CHUNK: usize = 256 * 1024;
const MAX_STRING_PREVIEW: usize = 512;
/// Largest executable the worker opens.
pub const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

/// Shared limits of one Program-listing request; tests narrow them.
#[derive(Clone, Copy)]
struct ListingLimits {
    decode_attempts: usize,
    reply_bytes: usize,
    elapsed: std::time::Duration,
    /// Engine switch-recovery time after which no recovery starts.
    switches: std::time::Duration,
}

impl Default for ListingLimits {
    fn default() -> Self {
        Self {
            decode_attempts: MAX_ANALYSIS_INSTRUCTIONS,
            reply_bytes: crate::model::MAX_LISTING_REPLY_BYTES,
            elapsed: crate::model::LISTING_ALLOWANCE,
            switches: crate::model::LISTING_ALLOWANCE,
        }
    }
}

/// Counts encoded bytes without retaining them.
struct EncodedLength(usize);

impl std::io::Write for EncodedLength {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub struct LoadedProgram {
    program: Program,
    target: crate::architecture::Target,
    // The engine currently takes ownership of a Vec, so the immutable scan snapshot
    // duplicates at most 128 MiB. Both copies originate from exactly the hashed bytes.
    // This favors consistent analysis over live file reads; engine snapshot sharing is future work.
    snapshot: Arc<[u8]>,
    pe_ranges: Vec<(u64, u64)>,
    pe_imports: BTreeMap<u64, String>,
    upx_packed: bool,
    pub info: BinaryInfo,
    pub(crate) macho_legacy: Option<MachoLegacySections>,
    inventory: crate::inventory::Inventory,
    /// Instructions decoded from established functions in this worker.
    coverage: Coverage,
    pointers: Option<pointers::PointerRecovery>,
    /// Calls that never return, from the image's own symbols and imports.
    no_return: Arc<crate::no_return::NoReturnIndex>,
    /// Original symbols and display names derived at open, before any replay.
    symbol_names: Arc<crate::symbol_names::SymbolTable>,
    linkage: Option<crate::linkage::LinkageTable>,
    search: Option<search::CachedSearch>,
    signatures: Vec<crate::signatures::FunctionSignature>,
    applied_signatures: BTreeSet<u64>,
    signature_state: Option<String>,
    analysis_started: bool,
    debug: crate::debug_info::DebugIndex,
    /// Recent graphs' call hints.
    debug_calls: VecDeque<(u64, CallHints)>,
    /// Callees too large (or too irregular) to probe for another render.
    debug_large: BTreeSet<u64>,
    /// Client-chosen functions rendered without any debug prototype.
    debug_skip: BTreeSet<u64>,
    /// Functions whose render failed with debug prototypes installed.
    debug_failed: BTreeSet<u64>,
    /// While a debug render runs: callees it found too large to probe.
    debug_large_journal: Option<Vec<u64>>,
    /// Verified final renders; see [`ResultCache`].
    results: ResultCache,
    /// Changes whenever names, signatures, inventory or discovery may have
    /// changed what a render prints.
    result_epoch: u64,
    /// The last managed request's unconsumed offer; see [`managed`].
    pending_debug: Option<managed::Pending>,
    /// Nonces of managed offers, never reused within this worker.
    debug_nonce: u64,
    debug_inventory_digest: Option<String>,
    debug_program_digest: Option<String>,
    debug_long_names: BTreeMap<u64, String>,
    debug_long_names_complete: bool,
}

/// Callees above this many instructions are never probed for another
/// function's render; their own render decides them.
const PROBE_CALLEE_INSTRUCTIONS: usize = 1024;
/// Probe allowance relative to the rendered function, so evidence for its
/// callees costs a fraction of the render itself. The floor lets small
/// callers cover their typical direct callees; at 64 instructions about a
/// fifth of libfprint renders left a callee unverified.
const PROBE_MIN_INSTRUCTIONS: usize = 512;
const PROBE_MAX_INSTRUCTIONS: usize = 4096;
const PROBE_MAX_COUNT: usize = 32;
/// Debug-prototype work for one Decompile is optional. The worker first
/// renders the function exactly as without debug info (the reference),
/// with nothing else running. Only then, on a single-threaded Linux worker,
/// does one disposable child try callee and target debug prototypes; the
/// request publishes the child's result if it arrives and is valid by the
/// optional cutoff, and the reference with a warning otherwise. The cutoff
/// is the earlier of this point after dispatch and the reference's end plus
/// `OPTIONAL_RATIO` times its duration (at least `OPTIONAL_FLOOR`).
const DEBUG_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(crate::model::WORKER_REQUEST_TIMEOUT.as_secs() - 3);
const OPTIONAL_RATIO: u32 = 3;
const OPTIONAL_FLOOR: std::time::Duration = std::time::Duration::from_secs(3);
/// CPU the worker keeps for decoding, validating and publishing a reply
/// after optional work; the optional child never starts with less left.
const PUBLICATION_RESERVE: std::time::Duration = std::time::Duration::from_secs(1);
/// Published when a candidate with callee debug prototypes lost a
/// corroborated input or call argument of the reference render.
pub const CALLER_EVIDENCE_WARNING: &str =
    "Callee debug prototypes omitted because this render lost argument evidence";
/// Published when the function's own debug prototype lost such evidence.
pub const OWN_EVIDENCE_WARNING: &str =
    "Debug prototype omitted because this render lost argument evidence";
/// Published when debug prototypes could apply but this worker has no
/// isolated executor for them (Windows and multithreaded workers until the
/// managed executor is available).
pub const UNVERIFIED_WARNING: &str = "Debug prototype is unverified";
pub const CALLEE_UNVERIFIED_WARNING: &str = "Some callee debug prototypes are unverified";
pub const OPTIONAL_UNAVAILABLE_WARNING: &str =
    "Debug prototypes not applied: no isolated debug render in this worker";
/// Published when a sibling's setup used up its allowance before any
/// optional render; the inferred baseline stands.
pub const SETUP_CUTOFF_WARNING: &str = "Debug setup timed out";
/// Wall-clock stop for pathological inputs, far below the worker CPU limit.
const PROBE_MAX_TIME: std::time::Duration = std::time::Duration::from_secs(2);

struct ProbeBudget {
    target: u64,
    instructions: usize,
    probes: usize,
    deadline: std::time::Instant,
}
impl ProbeBudget {
    fn for_target(target: u64, instructions: usize) -> Self {
        Self {
            target,
            instructions: (instructions / 2).clamp(PROBE_MIN_INSTRUCTIONS, PROBE_MAX_INSTRUCTIONS),
            probes: PROBE_MAX_COUNT,
            deadline: std::time::Instant::now() + PROBE_MAX_TIME,
        }
    }
    fn take_probe(&mut self) -> bool {
        if self.probes == 0 || self.instructions == 0 || std::time::Instant::now() >= self.deadline
        {
            return false;
        }
        self.probes -= 1;
        true
    }
}

fn instruction_count(view: &FunctionView) -> usize {
    view.blocks.iter().map(|b| b.instructions.len()).sum()
}

/// A function's estimated instruction count and direct call targets.
type CallHints = (usize, Vec<u64>);

/// Hints from a recovered graph whose walk decoded `decoded` instructions;
/// the view can omit some of them at its block limit.
fn call_hints(recovered: &cfg::GraphRecovery, decoded: usize) -> CallHints {
    (
        instruction_count(&recovered.view).max(decoded),
        recovered
            .view
            .calls
            .iter()
            .filter_map(|c| c.target)
            .collect(),
    )
}

/// One Decompile's debug-prototype work; see [`DEBUG_DEADLINE`].
struct DebugJob<'a> {
    address: u64,
    renames: &'a [crate::semantic::LocalRename],
    context: &'a str,
    owned: bool,
    /// Whether the target's own prototype may be installed or probed.
    target_work: bool,
    /// Eligible direct callees the reference render called, sorted.
    callees: Vec<u64>,
    /// Facts of the reference render, captured before any lock.
    reference: Option<&'a crate::debug_info::caller::Facts>,
}

/// A render's text, mappings, semantics and direct call targets.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Published {
    pub(crate) text: String,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_CODE_MAPPINGS }>")]
    pub(crate) mappings: Vec<CodeMapping>,
    pub(crate) semantics: crate::semantic::SemanticInfo,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_GRAPH_CALLS }>")]
    pub(crate) calls: Vec<u64>,
    pub(crate) calls_complete: bool,
}

/// The owned state of one request between its reference render and its
/// optional debug render; a managed offer retains it until consumed.
pub(crate) struct PreparedJob {
    address: u64,
    renames: Vec<crate::semantic::LocalRename>,
    context: String,
    owned: bool,
    active: bool,
    client_skip: bool,
    engine_failure: bool,
    cacheable: bool,
    /// Direct calls of the last displayed graph, when known.
    cached_hints: Option<Vec<u64>>,
    target_work: bool,
    /// Eligible direct callees the reference render called, sorted.
    callees: Vec<u64>,
    /// Facts of the reference render, captured before any lock.
    caller: Option<crate::debug_info::caller::Facts>,
    /// Whether any optional debug work may change the render.
    work: bool,
    started: std::time::Instant,
    reference_end: std::time::Instant,
    reference_time: std::time::Duration,
    /// Trace label when no optional work runs.
    label: &'static str,
}

impl PreparedJob {
    fn job(&self) -> DebugJob<'_> {
        DebugJob {
            address: self.address,
            renames: &self.renames,
            context: &self.context,
            owned: self.owned,
            target_work: self.target_work,
            callees: self.callees.clone(),
            reference: self.caller.as_ref(),
        }
    }
}

/// What the final render of one request shows after optional work.
#[derive(Default)]
struct Settled {
    /// A validated candidate replaces the reference.
    candidate: bool,
    debug_owned: bool,
    /// Whether the final render carries the eligible callee prototypes.
    callees_shown: bool,
    vetoed: bool,
    own_vetoed: bool,
    unavailable: bool,
    engine_failure: bool,
}

fn optional_window_available(wall: std::time::Duration, cpu: Option<std::time::Duration>) -> bool {
    !wall.is_zero() && cpu.is_some_and(|left| left > PUBLICATION_RESERVE)
}

fn duration_us(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Clips an oversized render at a character boundary, dropping mappings and
/// tokens past the cut. Idempotent.
fn clip(
    text: &mut String,
    mappings: &mut Vec<CodeMapping>,
    semantics: &mut crate::semantic::SemanticInfo,
) {
    if text.len() > MAX_DECOMPILED_BYTES {
        let mut end = MAX_DECOMPILED_BYTES - 100;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        mappings.retain(|mapping| mapping.end <= end);
        semantics.tokens.retain(|token| token.end <= end);
        text.push_str(crate::decompile::TRUNCATION_TRAILER);
    }
}

/// A final render: debug warnings appended after the engine's and local
/// warnings (which keep their order), the
/// prototype's provenance, and clipping.
pub(crate) fn compose(
    published: Published,
    warnings: &[impl AsRef<str>],
    debug_owned: bool,
) -> (String, Vec<CodeMapping>, crate::semantic::SemanticInfo) {
    let Published {
        mut text,
        mut mappings,
        mut semantics,
        ..
    } = published;
    let slots = crate::semantic::MAX_FUNCTION_RENAMES.saturating_sub(semantics.warnings.len());
    semantics.warnings.extend(
        warnings
            .iter()
            .take(slots)
            .map(|warning| warning.as_ref().to_owned()),
    );
    if debug_owned {
        semantics.prototype_source = crate::semantic::PrototypeSource::DebugInfo;
    }
    clip(&mut text, &mut mappings, &mut semantics);
    (text, mappings, semantics)
}

/// Why a debug render left the reference as the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Unchanged {
    /// No debug prototype could be installed.
    NothingInstalled,
    /// Callee prototypes lost evidence of the reference render.
    EvidenceLost,
    /// The function's own prototype lost evidence of the reference render.
    OwnEvidenceLost,
}

/// A debug render's result for the worker that started it. Every variant
/// carries the decision changes it made (target and eligible callees only)
/// and callees found too large to probe.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DebugOutcome {
    Candidate {
        render: Box<Published>,
        /// The target's own debug prototype owns this render.
        target_owns: bool,
        #[serde(
            deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_GRAPH_CALLS }>"
        )]
        installed_callees: Vec<u64>,
        /// A callee lock was installed and the caller comparison passed.
        compared: bool,
        /// A veto removed callee prototypes from this render.
        vetoed: bool,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { managed::MAX_JOB_ENTRIES }>")]
        changes: Vec<crate::debug_info::Change>,
        #[serde(
            deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_GRAPH_CALLS }>"
        )]
        large: Vec<u64>,
    },
    UseReference {
        reason: Unchanged,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { managed::MAX_JOB_ENTRIES }>")]
        changes: Vec<crate::debug_info::Change>,
        #[serde(
            deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_GRAPH_CALLS }>"
        )]
        large: Vec<u64>,
    },
    /// The engine failed with debug prototypes installed.
    Failed {
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { managed::MAX_JOB_ENTRIES }>")]
        changes: Vec<crate::debug_info::Change>,
        #[serde(
            deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_GRAPH_CALLS }>"
        )]
        large: Vec<u64>,
    },
}

/// Test hook: a disposable debug render never finishes, so each request
/// takes the expiry path deterministically. A hexadecimal address limits
/// the stall to that target.
fn debug_render_stalled(address: u64) -> bool {
    static STALLED: std::sync::OnceLock<Option<Option<u64>>> = std::sync::OnceLock::new();
    match STALLED.get_or_init(|| {
        let value = std::env::var("GHIDRA_RUST_TEST_STALL_DEBUG_RENDER").ok()?;
        Some(
            value
                .strip_prefix("0x")
                .and_then(|hex| u64::from_str_radix(hex, 16).ok()),
        )
    }) {
        None => false,
        Some(None) => true,
        Some(Some(only)) => *only == address,
    }
}

/// A host-test-only fault in one function's optional debug render, or in
/// its managed preparation, set by the worker argument
/// [`crate::worker::FAULT_ARGUMENT`]. Compiled only with `test-hooks`.
#[cfg(feature = "test-hooks")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    Stall,
    Spin,
    Abort,
    /// A normal `PrepareDecompile` exits as at the CPU limit after its
    /// ordinary render and before its baseline is written.
    PrepareExit,
    /// [`Self::PrepareExit`] that also stops an inference-only recovery.
    PrepareExitAlways,
}

#[cfg(feature = "test-hooks")]
static DEBUG_FAULT: std::sync::OnceLock<(Fault, u64)> = std::sync::OnceLock::new();

/// Parses `KIND@ADDRESS` for [`crate::worker::FAULT_ARGUMENT`].
#[cfg(feature = "test-hooks")]
pub fn set_debug_fault(spec: &str) -> Result<(), String> {
    let invalid = || "Invalid debug fault argument".to_string();
    let (kind, address) = spec.split_once('@').ok_or_else(invalid)?;
    let kind = match kind {
        "stall" => Fault::Stall,
        "spin" => Fault::Spin,
        "abort" => Fault::Abort,
        "prepare-exit" => Fault::PrepareExit,
        "prepare-exit-always" => Fault::PrepareExitAlways,
        _ => return Err(invalid()),
    };
    let address = address
        .strip_prefix("0x")
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .ok_or_else(invalid)?;
    DEBUG_FAULT
        .set((kind, address))
        .map_err(|_| "Repeated debug fault argument".to_string())
}

/// Runs the configured fault for `address` in an optional render that has
/// started, if any. Stall and spin never return; the host's deadline (or
/// the CPU limit) stops the process.
#[cfg(feature = "test-hooks")]
fn debug_fault(address: u64) {
    let Some(&(fault, only)) = DEBUG_FAULT.get() else {
        return;
    };
    if only != address || matches!(fault, Fault::PrepareExit | Fault::PrepareExitAlways) {
        return;
    }
    {
        use std::io::Write;
        let _ = std::io::stderr().write_all(b"debug-order: optional started\n");
    }
    match fault {
        Fault::Stall => loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        },
        Fault::Spin => loop {
            std::hint::spin_loop();
        },
        Fault::Abort => std::process::abort(),
        Fault::PrepareExit | Fault::PrepareExitAlways => unreachable!(),
    }
}

/// Without `test-hooks` no fault can be configured.
#[cfg(not(feature = "test-hooks"))]
fn debug_fault(_address: u64) {}

/// Runs a configured preparation fault for `address`: the worker stops
/// exactly as at its CPU limit, with this platform's CPU-limit exit status
/// ([`crate::limits::cpu_limit_stop`]), before any baseline frame is written.
#[cfg(feature = "test-hooks")]
fn prepare_fault(address: u64, inference_only: bool) {
    let Some(&(fault, only)) = DEBUG_FAULT.get() else {
        return;
    };
    let fires = match fault {
        Fault::PrepareExit => !inference_only,
        Fault::PrepareExitAlways => true,
        _ => false,
    };
    if !fires || only != address {
        return;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: _exit ends the process at once, as the SIGXCPU handler does;
    // no Rust or engine state is used afterwards.
    unsafe {
        libc::_exit(crate::limits::CPU_LIMIT_EXIT)
    }
    #[cfg(windows)]
    std::process::exit(crate::limits::WATCHDOG_EXIT as i32);
    #[cfg(not(any(target_os = "linux", windows)))]
    std::process::exit(crate::limits::CPU_LIMIT_EXIT)
}

#[cfg(not(feature = "test-hooks"))]
fn prepare_fault(_address: u64, _inference_only: bool) {}

/// Opt-in diagnostics on stderr (`GHIDRA_RUST_DEBUG_TRACE`): optional
/// renders started, caller vetoes with their reason, and result reuse. Used
/// by tests and corpus audits; never written to the protocol stream.
fn debug_trace(event: std::fmt::Arguments<'_>) {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *ENABLED.get_or_init(|| std::env::var_os("GHIDRA_RUST_DEBUG_TRACE").is_some()) {
        // One write per line: the optional child traces to the same pipe
        // concurrently, and a short write to a pipe is never interleaved.
        use std::io::Write;
        let line = format!("debug-trace: {event}\n");
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }
}

/// Complete final renders of verified debug work, keyed by everything they
/// depend on. Repeated ordinary requests reuse them; Refresh renders anew.
#[derive(Default)]
struct ResultCache {
    entries: VecDeque<CachedResult>,
    bytes: usize,
}

struct CachedResult {
    address: u64,
    renames: Vec<crate::semantic::LocalRename>,
    context: String,
    epoch: u64,
    /// The decision state of the target and every callee considered, and
    /// whether each was too large to probe, when the result was committed.
    dependencies: Vec<(u64, crate::debug_info::EntryState, bool)>,
    text: String,
    mappings: Vec<CodeMapping>,
    semantics: crate::semantic::SemanticInfo,
    bytes: usize,
}

/// How the optional debug render of one request ended.
enum Optional {
    /// No isolated executor here (Windows or a multithreaded worker).
    Unavailable,
    /// No optional window or CPU reserve was left, or no child started.
    NoWindow,
    /// No valid reply by the cutoff (late, crashed or malformed).
    Expired,
    /// Malformed isolated reply.
    Invalid,
    /// Newer host input arrived first; nothing is charged.
    Superseded,
    Replied(DebugOutcome),
}

/// What the worker publishes after adopting a debug render.
enum Adopted {
    Candidate { target_owns: bool, vetoed: bool },
    Reference { vetoed: bool, own: bool },
    Failed,
    Invalid,
}

/// [`DebugOutcome`] before its decision changes are attached.
enum Inner {
    Candidate {
        render: Box<Published>,
        target_owns: bool,
        installed_callees: Vec<u64>,
        compared: bool,
        vetoed: bool,
    },
    Reference(Unchanged),
    Failed,
}

pub(crate) const RESULT_CACHE_ENTRIES: usize = 64;
pub(crate) const RESULT_CACHE_BYTES: usize = 8 * 1024 * 1024;
/// Larger results are not retained at all.
pub(crate) const RESULT_CACHE_MAX_ENTRY: usize = 2 * 1024 * 1024;

impl ResultCache {
    fn clear(&mut self) {
        self.entries.clear();
        self.bytes = 0;
    }
    fn insert(&mut self, entry: CachedResult) {
        if entry.bytes > RESULT_CACHE_MAX_ENTRY {
            return;
        }
        if let Some(index) = self.entries.iter().position(|e| {
            e.address == entry.address && e.renames == entry.renames && e.context == entry.context
        }) && let Some(old) = self.entries.remove(index)
        {
            self.bytes -= old.bytes;
        }
        while self.entries.len() >= RESULT_CACHE_ENTRIES
            || self.bytes.saturating_add(entry.bytes) > RESULT_CACHE_BYTES
        {
            let Some(old) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= old.bytes;
        }
        self.bytes += entry.bytes;
        self.entries.push_back(entry);
    }
}

/// Engine functions a discovery pass named, and whether it changed the engine
/// in ways it cannot enumerate.
struct Discovered {
    added: Vec<FunctionInfo>,
    opaque: bool,
}

fn engine_error(error: ghidra_decompiler::error::Error) -> String {
    error.explain().to_string()
}

fn warning(warnings: &mut Vec<String>, message: impl Into<String>) {
    let message = message.into();
    if warnings.len() < 64 && !warnings.contains(&message) {
        warnings.push(message);
    }
}

/// Whether `address` is in the section's virtual extent, including any
/// zero-filled tail beyond its file-backed bytes.
fn mapped(section: &SectionInfo, address: u64) -> bool {
    address >= section.address && address - section.address < section.size
}

/// Whether `length` bytes (at least one) at `address` are file-backed code.
fn executable(sections: &[SectionInfo], address: u64, length: usize) -> bool {
    let length = (length as u64).max(1);
    sections
        .iter()
        .any(|section| section.executable && section.backs(address, length))
}

#[cfg(test)]
fn metadata(path: &Path, bytes: &[u8]) -> Result<BinaryInfo, String> {
    metadata_with_target(path, bytes).map(|(info, _)| info)
}

#[cfg(test)]
fn metadata_with_target(
    path: &Path,
    bytes: &[u8],
) -> Result<(BinaryInfo, crate::architecture::Target), String> {
    metadata_with_migration(path, bytes).map(|(info, target, _)| (info, target))
}

/// Built once per Mach-O parse. Prefix maxima answer containment without
/// merging adjacent segments into a fictitious larger containing segment.
#[derive(Default)]
struct MachoExecutableSegments(BTreeMap<Vec<u8>, Vec<(u64, u64)>>);

impl MachoExecutableSegments {
    fn new(object: &object::File<'_>) -> Result<Self, String> {
        let mut result = Self::default();
        for (count, segment) in object.segments().enumerate() {
            if count >= MAX_SECTIONS {
                return Err("Mach-O exceeds the 4096-segment budget".into());
            }
            if !matches!(segment.flags(), SegmentFlags::MachO { initprot, .. }
                if initprot & object::macho::VM_PROT_EXECUTE != 0)
            {
                continue;
            }
            let Some(name) = segment.name_bytes().map_err(|e| e.to_string())? else {
                continue;
            };
            let end = segment
                .address()
                .checked_add(segment.size())
                .ok_or("Mach-O segment address overflows")?;
            result
                .0
                .entry(name.to_vec())
                .or_default()
                .push((segment.address(), end));
        }
        for ranges in result.0.values_mut() {
            ranges.sort_unstable();
            let mut maximum = 0;
            for (_, end) in ranges {
                maximum = maximum.max(*end);
                *end = maximum;
            }
        }
        Ok(result)
    }

    fn contains(&self, name: &[u8], address: u64, size: u64) -> bool {
        let Some(ranges) = self.0.get(name) else {
            return false;
        };
        let index = ranges.partition_point(|(start, _)| *start <= address);
        index > 0
            && address
                .checked_add(size)
                .is_some_and(|end| end <= ranges[index - 1].1)
    }
}

fn metadata_with_migration(
    path: &Path,
    bytes: &[u8],
) -> Result<
    (
        BinaryInfo,
        crate::architecture::Target,
        Option<MachoLegacySections>,
    ),
    String,
> {
    let object = object::File::parse(bytes).map_err(|e| format!("Cannot parse executable: {e}"))?;
    let format = match object.format() {
        object::BinaryFormat::Elf => "ELF",
        object::BinaryFormat::Pe => "PE",
        object::BinaryFormat::MachO => "Mach-O",
        other => {
            return Err(format!(
                "Unsupported executable format {other:?}; use ELF, PE, or Mach-O."
            ));
        }
    };
    if !matches!(
        object.kind(),
        object::ObjectKind::Executable | object::ObjectKind::Dynamic
    ) {
        return Err("Only linked executables and shared libraries are supported; relocatable object files are not supported yet.".into());
    }
    let target = crate::architecture::Target::for_image(&object)?;
    let macho = object.format() == object::BinaryFormat::MachO;
    let executable_segments = if macho {
        MachoExecutableSegments::new(&object)?
    } else {
        Default::default()
    };
    let mut legacy_sections = Vec::new();
    let mut legacy_possible = true;
    let mut sections = Vec::new();
    let mut candidates = 0;
    for section in object.sections() {
        let kind = section.kind();
        let (allocated, executable) = match section.flags() {
            SectionFlags::Elf { sh_flags } => (
                sh_flags & u64::from(object::elf::SHF_ALLOC) != 0,
                sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0,
            ),
            SectionFlags::Coff { characteristics } => (
                characteristics & object::pe::IMAGE_SCN_MEM_DISCARDABLE == 0,
                characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0,
            ),
            SectionFlags::MachO { flags } => {
                let code = kind == SectionKind::Text
                    || flags
                        & (object::macho::S_ATTR_PURE_INSTRUCTIONS
                            | object::macho::S_ATTR_SOME_INSTRUCTIONS)
                        != 0
                    || flags & object::macho::SECTION_TYPE == object::macho::S_SYMBOL_STUBS;
                (code || legacy_allocated(kind), code)
            }
            _ => (
                matches!(
                    kind,
                    SectionKind::Text
                        | SectionKind::Data
                        | SectionKind::ReadOnlyData
                        | SectionKind::ReadOnlyDataWithRel
                        | SectionKind::ReadOnlyString
                        | SectionKind::UninitializedData
                        | SectionKind::Tls
                        | SectionKind::UninitializedTls
                ),
                kind == SectionKind::Text,
            ),
        };
        if !allocated || section.size() == 0 {
            continue;
        }
        if candidates >= MAX_SECTIONS {
            return Err(
                "Executables with more than 4096 mapped sections are not supported yet.".into(),
            );
        }
        candidates += 1;
        // Only non-empty allocated candidates within the cap need a lookup.
        let executable = executable
            && (!macho
                || section
                    .segment_name_bytes()
                    .ok()
                    .flatten()
                    .is_some_and(|name| {
                        executable_segments.contains(name, section.address(), section.size())
                    }));
        if macho && !executable && !legacy_allocated(kind) {
            continue;
        }
        section
            .address()
            .checked_add(section.size())
            .ok_or("Section address overflow")?;
        let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
        if file_offset
            .checked_add(file_size)
            .is_none_or(|end| end > bytes.len() as u64)
        {
            return Err(format!(
                "Section {} extends past the file",
                section.name().unwrap_or("?")
            ));
        }
        let published = SectionInfo {
            name: section
                .name()
                .unwrap_or("<unnamed>")
                .chars()
                .take(256)
                .collect(),
            address: section.address(),
            size: section.size(),
            file_offset,
            file_size: file_size.min(section.size()),
            executable,
        };
        if macho && legacy_allocated(kind) {
            let mut legacy = published.clone();
            legacy.executable = kind == SectionKind::Text;
            legacy_possible &= legacy.executable == published.executable;
            legacy_sections.push(legacy);
        }
        sections.push(published);
    }
    legacy_sections.sort_by_key(|section| section.address);
    sections.sort_by_key(|section| section.address);
    if !sections.iter().any(|s| s.executable && s.file_size > 0) {
        return Err("No supported executable sections found; sectionless executables are not supported yet.".into());
    }
    for pair in sections.windows(2) {
        if pair[0].address + pair[0].size > pair[1].address {
            return Err("Overlapping mapped sections are not supported by this prototype.".into());
        }
    }
    // object 0.37 exposes LC_MAIN's file offset, not a virtual address.
    // Translate only through validated file-backed executable sections. A Mach-O
    // without a supported LC_MAIN entry remains navigable by symbols/address.
    let entry = if object.format() == object::BinaryFormat::MachO {
        macho_entry(object.entry(), &sections)?
    } else {
        object.entry()
    };
    let mut info = BinaryInfo {
        path: path.to_string_lossy().into_owned(),
        architecture: target.name.into(),
        format: format.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        source_identity: None,
        entry,
        file_len: bytes.len() as u64,
        sections,
        functions: Vec::new(),
        functions_truncated: false,
        warnings: Vec::new(),
    };
    if crate::packing::detect_upx_pe(&info.format, info.entry, &info.sections, bytes) {
        warning(&mut info.warnings, crate::packing::UPX_PACKED_WARNING);
    }
    let macho_legacy = if macho && legacy_possible {
        Some(MachoLegacySections {
            entry: macho_entry(object.entry(), &legacy_sections)?,
            indices: legacy_sections
                .iter()
                .map(|section| {
                    info.sections
                        .binary_search_by_key(&section.address, |fresh| fresh.address)
                        .map_err(|_| "Missing worker legacy section".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    } else {
        None
    };
    Ok((info, target, macho_legacy))
}

fn legacy_allocated(kind: SectionKind) -> bool {
    matches!(
        kind,
        SectionKind::Text
            | SectionKind::Data
            | SectionKind::ReadOnlyData
            | SectionKind::ReadOnlyDataWithRel
            | SectionKind::ReadOnlyString
            | SectionKind::UninitializedData
            | SectionKind::Tls
            | SectionKind::UninitializedTls
    )
}

fn macho_entry(offset: u64, sections: &[SectionInfo]) -> Result<u64, String> {
    let mut entry = None;
    if offset != 0 {
        for section in sections {
            if let Some(relative) = offset.checked_sub(section.file_offset)
                && section.executable
                && relative < section.file_size
            {
                if entry.is_some() {
                    return Err(
                        "Mach-O entry file offset has ambiguous executable mappings.".into(),
                    );
                }
                entry = section.address.checked_add(relative);
            }
        }
    }
    Ok(entry.unwrap_or(0))
}

/// Positive x86 cdecl check independent of DWARF locations and inferred locks.
pub(crate) fn debug_return_pop(
    program: &Program,
    entry: u64,
    sections: &[SectionInfo],
) -> Result<i32, String> {
    let mut remaining = MAX_INSTRUCTIONS;
    let recovered = recover_graph_budgeted(
        program,
        &Bounds {
            tail_entry: None,
            sections,
            is_function: &|_| false,
            pe_ranges: &[],
        },
        entry,
        &mut remaining,
        &Arc::default(),
        None,
    )?;
    if recovered.partial {
        return Err("Incomplete return-stack evidence".into());
    }
    let mut pop = None;
    for instruction in recovered.view.blocks.iter().flat_map(|b| &b.instructions) {
        if !instruction.mnemonic.eq_ignore_ascii_case("RET")
            && !instruction.mnemonic.eq_ignore_ascii_case("RETF")
        {
            continue;
        }
        let bytes = &instruction.bytes;
        let amount = if bytes.last().is_some_and(|&b| b == 0xc3 || b == 0xcb) {
            4
        } else if bytes.len() >= 3 && matches!(bytes[bytes.len() - 3], 0xc2 | 0xca) {
            4 + i32::from(u16::from_le_bytes([
                bytes[bytes.len() - 2],
                bytes[bytes.len() - 1],
            ]))
        } else {
            return Err("Unsupported return opcode".into());
        };
        if pop.is_some_and(|old| old != amount) {
            return Err("Inconsistent return-stack adjustment".into());
        }
        pop = Some(amount);
    }
    pop.ok_or_else(|| "No proven return-stack adjustment".into())
}

#[cfg(test)]
std::thread_local! {static DEBUG_HINT_FAILURE: std::cell::Cell<bool> = const {std::cell::Cell::new(false)};}

impl LoadedProgram {
    pub fn open(path: &str) -> Result<Self, String> {
        Self::open_debug(path, &Default::default())
    }

    pub fn open_debug(
        path: &str,
        debug_options: &crate::debug_info::DebugOptions,
    ) -> Result<Self, String> {
        Self::open_with_companion_policy(path, debug_options, true)
    }

    pub(crate) fn open_with_companion_policy(
        path: &str,
        debug_options: &crate::debug_info::DebugOptions,
        automatic_companion: bool,
    ) -> Result<Self, String> {
        let path = Path::new(path);
        #[cfg(windows)]
        crate::windows::validate_local_path(path)
            .map_err(|e| format!("Unsupported input binary path: {e}"))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        crate::windows::configure_read(&mut options);
        let mut file = options
            .open(path)
            .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
        #[cfg(windows)]
        crate::windows::verify_regular_file(&file)
            .map_err(|e| format!("Cannot inspect input binary: {e}"))?;
        let file_metadata = file.metadata().map_err(|e| e.to_string())?;
        if !file_metadata.is_file() {
            return Err("Choose a regular executable file.".into());
        }
        if file_metadata.len() > MAX_IMAGE_BYTES {
            return Err("This prototype limits executable files to 128 MiB.".into());
        }
        // Bounded reading also handles a file growing after the metadata check.
        let reading = crate::performance::span("open_read");
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_IMAGE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Cannot read executable: {e}"))?;
        if bytes.len() as u64 > MAX_IMAGE_BYTES {
            return Err("Executable grew beyond the 128 MiB prototype limit while reading.".into());
        }
        reading.finish(bytes.len() as u64);
        let metadata_time = crate::performance::span("open_metadata_hash");
        let (mut info, target, macho_legacy) = metadata_with_migration(path, &bytes)?;
        metadata_time.finish(0);
        // This flag comes only from the freshly parsed immutable image, never a
        // saved project's warnings or cached analysis.
        let upx_packed = crate::packing::has_upx_warning(&info);
        if target.name == "AArch64" {
            warning(
                &mut info.warnings,
                "AArch64 analysis is experimental: indirect branches, jump tables, exception flow, and newer ISA extensions may be incomplete.",
            );
        }
        info.source_identity = FileIdentity::from_file(&file);
        let snapshot_time = crate::performance::span("open_snapshot_copy");
        let snapshot = Arc::from(bytes.as_slice());
        snapshot_time.finish(bytes.len() as u64);
        let pe_time = crate::performance::span("open_pe_parse");
        let pe = crate::pe::parse(&bytes, &info.sections)?;
        pe_time.finish(0);
        let engine_load = crate::performance::span("open_engine_image");
        let mut program =
            Program::from_image(&path.to_string_lossy(), bytes, Some(target.language))
                .map_err(engine_error)?;
        engine_load.finish(0);
        if program.language_id() != target.language {
            return Err(
                "Engine language does not match the validated binary architecture and ABI.".into(),
            );
        }
        let mut pe_ranges = Vec::new();
        let mut pe_imports = BTreeMap::new();
        let mut pe_names = BTreeMap::new();
        if let Some(pe) = pe {
            let _registration = crate::performance::span("open_pe_register");
            crate::pe_symbols::register(&mut program, &pe, target.pointer_bytes)?;
            info.functions_truncated = pe.functions_truncated;
            for note in pe.warnings {
                warning(&mut info.warnings, note);
            }
            pe_ranges = pe.function_ranges;
            pe_imports = pe.imports;
            pe_names = pe.functions;
        }
        let (functions, mut rejected) = select_functions(&program, &info, &BTreeSet::new())?;
        info.functions_truncated |= rejected;
        info.functions = functions;
        if !upx_packed && target.name == "AArch64" && !pe_imports.is_empty() {
            let targets = info
                .functions
                .iter()
                .map(|function| function.address)
                .take(crate::pe_symbols::MAX_THUNK_TARGETS)
                .collect();
            crate::pe_symbols::register_aarch64_import_thunks(
                &mut program,
                &pe_imports,
                &snapshot,
                &info.sections,
                &targets,
            )?;
            if info.functions.len() > crate::pe_symbols::MAX_THUNK_TARGETS {
                warning(
                    &mut info.warnings,
                    "ARM64 PE import-veneer naming on open is limited to the first 2,048 established function entries; discovery and selected-function analysis can name additional confirmed targets.",
                );
            }
            let functions;
            (functions, rejected) = select_functions(&program, &info, &BTreeSet::new())?;
            info.functions_truncated |= rejected;
            info.functions = functions;
        }
        if info.format == "ELF" && !info.functions_truncated {
            rejected |= recover_elf_main(&mut program, &mut info, &target, &snapshot)?;
        }
        let symbol_names = Arc::new(symbol_table(&program, &info, &pe_names)?);
        drop(pe_names);
        let mut no_return = crate::no_return::NoReturnIndex::build(
            &program,
            &info.format,
            target.pointer_bytes as u32,
            &pe_imports,
            |address| crate::call_analysis::code_address(&info, address),
        );
        if info.format == "ELF" {
            no_return.add_startup_slots(
                crate::elf_startup::libc_start_slots(&snapshot, &info.architecture)
                    .into_iter()
                    .filter(|&slot| {
                        info.sections
                            .iter()
                            .any(|section| section.backs(slot, target.pointer_bytes as u64))
                    }),
            );
        }
        if no_return.incomplete || !crate::no_return::mark_engine(&mut program, &no_return) {
            warning(
                &mut info.warnings,
                "No-return recognition is incomplete; some calls that never return keep a fallthrough.",
            );
        }
        let mut inventory = crate::inventory::Inventory::default();
        inventory.certify(&info.functions, !rejected);
        if !info.entry.is_multiple_of(target.instruction_alignment)
            || !executable(
                &info.sections,
                info.entry,
                target.instruction_alignment as usize,
            )
        {
            info.warnings.push("The binary entry point is not a supported aligned file-backed instruction address; select a function from the list.".into());
        }
        let debug = if debug_options.enabled {
            {
                let companion = debug_options
                    .companion_path
                    .as_ref()
                    .map(std::path::PathBuf::from)
                    .or_else(|| {
                        automatic_companion
                            .then(|| crate::debug_info::companion::automatic(path))
                            .flatten()
                    });
                if let Some(path) = companion {
                    crate::debug_info::DebugIndex::with_companion(&snapshot, &info, &path)
                } else {
                    crate::debug_info::DebugIndex::build(&snapshot, &info)
                }
            }
        } else {
            Default::default()
        };
        if debug_options.enabled
            && debug_options.companion_path.is_some()
            && debug
                .summary
                .as_ref()
                .and_then(|s| s.source.as_ref())
                .is_none()
        {
            warning(
                &mut info.warnings,
                "Debug companion rejected: UUID, architecture, file format, or file validation did not match.",
            );
        }
        if let Some(summary) = &debug.summary {
            match summary.status {
                crate::debug_info::DebugStatus::Partial => warning(
                    &mut info.warnings,
                    "DWARF indexing is partial; unsupported functions retain inference.",
                ),
                crate::debug_info::DebugStatus::Unsupported => warning(
                    &mut info.warnings,
                    "Compressed DWARF is unsupported; functions retain inference.",
                ),
                _ => (),
            }
        }
        Ok(Self {
            macho_legacy,
            program,
            target,
            snapshot,
            pe_ranges,
            pe_imports,
            upx_packed,
            info,
            inventory,
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::new(no_return),
            symbol_names,
            linkage: None,
            search: None,
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
            debug,
            debug_calls: VecDeque::new(),
            debug_large: BTreeSet::new(),
            debug_skip: debug_options.skip.iter().copied().collect(),
            debug_failed: BTreeSet::new(),
            debug_large_journal: None,
            results: ResultCache::default(),
            result_epoch: 0,
            pending_debug: None,
            debug_nonce: 0,
            debug_inventory_digest: None,
            debug_program_digest: None,
            debug_long_names: BTreeMap::new(),
            debug_long_names_complete: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn debug_index_mut(&mut self) -> &mut crate::debug_info::DebugIndex {
        &mut self.debug
    }

    pub(crate) fn bind_open(&mut self, request_id: u64) {
        // The physical Open follows every earlier offer on this transport.
        self.debug_nonce = request_id;
    }

    pub fn debug_summary(&self) -> Option<&crate::debug_info::DebugSummary> {
        self.debug.summary.as_ref()
    }

    pub fn symbol_names(&self) -> &crate::model::SymbolNameSummary {
        self.symbol_names.summary()
    }

    pub fn handle(&mut self, request: Request) -> Result<Response, String> {
        self.handle_with_progress(request, &mut |_| Ok(()))
    }

    /// The ordinary single-terminal request: the reference render, then on
    /// a single-threaded Linux worker the optional debug render in a
    /// disposable child, both before one reply. Managed hosts use
    /// [`Self::prepare_decompile`] instead.
    fn decompile(
        &mut self,
        address: u64,
        renames: &[crate::semantic::LocalRename],
        refresh: bool,
    ) -> Result<Response, String> {
        self.pending_debug = None;
        let (job, mut published) =
            match self.reference(address, renames, Some(refresh), false, false)? {
                Ok(prepared) => prepared,
                Err(hit) => return Ok(hit),
            };
        let mut settled = Settled::default();
        let mut label = job.label;
        if job.work {
            let optional = self.run_optional(&job, None, None, None, None);
            let (adopted, candidate) = self.adopt_optional(&job, optional, &mut settled);
            label = adopted;
            if let Some(candidate) = candidate {
                published = *candidate;
            }
        }
        self.trace_request(&job, label);
        Ok(self.finish(&job, &settled, published))
    }

    /// Everything before optional debug work: validation, import resolution,
    /// cheap decisions, a verified cached result and the reference render,
    /// which is exactly the render without debug information. Nothing
    /// optional runs before the reference is complete. `capture` records
    /// caller evidence whatever the decisions (a sibling's recapture) and
    /// never uses or fills the result cache. A cache hit is the final reply.
    /// `inference_only` renders exactly as with no optional debug work: no
    /// cache, candidate or hint search, and no caller-evidence capture.
    fn reference(
        &mut self,
        address: u64,
        renames: &[crate::semantic::LocalRename],
        raw_refresh: Option<bool>,
        capture: bool,
        inference_only: bool,
    ) -> Result<Result<(PreparedJob, Published), Response>, String> {
        let started = std::time::Instant::now();
        crate::semantic::validate_renames(renames, Some(address))?;
        self.check_unpacked()?;
        self.check_code(address)?;
        // Import resolution and the engine can name or create functions.
        self.inventory.take_certificate(&self.info.functions);
        let imports = crate::performance::span("decompile_import_resolution");
        self.resolve_import_thunks(address)?;
        imports.finish(0);
        let _rendering = crate::performance::span("decompile_render");
        let context = if self.signatures.is_empty() {
            String::new()
        } else {
            crate::signatures::state_digest(&self.signatures)
        };
        let owned = self.applied_signatures.contains(&address);
        let active = self.debug.active();
        let client_skip = active && self.debug_skip.contains(&address);
        let engine_failure =
            active && raw_refresh.is_some() && self.debug_failed.contains(&address);
        let optional = active && !client_skip && !engine_failure && !inference_only;
        // Import registration can change engine symbols in ways a cached
        // render cannot see, so PE images are never cached.
        let cacheable = optional && !capture && self.pe_imports.is_empty();
        if cacheable && raw_refresh == Some(false) {
            if let Some(hit) = self.cached_result(address, renames, &context) {
                crate::performance::event("debug_result_cache_hit", address);
                debug_trace(format_args!("cache-hit {address:#x}"));
                return Ok(Err(hit));
            }
        } else if raw_refresh == Some(true) {
            crate::performance::event("debug_result_cache_bypass", address);
        }
        // Cheap decisions first: known graph hints with no eligible target
        // or callee mean no debug work, and no evidence to collect. A
        // recovery does no debug work, so it never looks them up.
        let cached_hints = if inference_only {
            None
        } else {
            self.debug_calls
                .iter()
                .find(|(entry, _)| *entry == address)
                .map(|(_, hints)| hints.1.clone())
        };
        let callee_eligible = |program: &Self, callee| {
            callee != address
                && !program.applied_signatures.contains(&callee)
                && if raw_refresh.is_some() {
                    program.callee_eligible(address, callee)
                } else {
                    program.debug.indexed(callee)
                }
        };
        let target_work = optional
            && !owned
            && if raw_refresh.is_some() {
                self.target_eligible(address)
            } else {
                self.debug.indexed(address)
            };
        let maybe_work = optional
            && (target_work
                || cached_hints
                    .as_ref()
                    .is_none_or(|hints| hints.iter().any(|&callee| callee_eligible(self, callee))));
        // The reference render is exactly the render without debug info, and
        // nothing else runs until it is complete.
        let reference_started = std::time::Instant::now();
        let reference = crate::decompile::render_full(
            &mut self.program,
            address,
            &self.info.sections,
            renames,
            &context,
            owned,
            Some(Arc::clone(&self.symbol_names)),
            maybe_work || capture,
        )
        .map_err(engine_error)?;
        let reference_end = std::time::Instant::now();
        let reference_time = reference_end - reference_started;
        let crate::decompile::Render {
            text,
            mappings,
            semantics,
            calls,
            caller,
            calls_complete,
            ..
        } = reference;
        let published = Published {
            text,
            mappings,
            semantics,
            calls,
            calls_complete,
        };
        let callees = if maybe_work {
            published
                .calls
                .iter()
                .copied()
                .filter(|&callee| {
                    callee_eligible(self, callee)
                        && cached_hints
                            .as_ref()
                            .is_none_or(|hints| hints.contains(&callee))
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let work = calls_complete && maybe_work && (target_work || !callees.is_empty());
        let label = if !active {
            "inactive"
        } else if inference_only && !client_skip {
            "recovery"
        } else if !optional {
            "skipped"
        } else if !maybe_work {
            "no-work-hints"
        } else {
            "no-work"
        };
        Ok(Ok((
            PreparedJob {
                address,
                renames: renames.to_vec(),
                context,
                owned,
                active,
                client_skip,
                engine_failure,
                cacheable: cacheable && calls_complete && raw_refresh.is_some(),
                cached_hints,
                target_work,
                callees,
                caller,
                work,
                started,
                reference_end,
                reference_time,
                label,
            },
            published,
        )))
    }

    fn trace_request(&self, job: &PreparedJob, label: &str) {
        debug_trace(format_args!(
            "request {:#x} reference_us={} optional_us={} outcome={label}",
            job.address,
            job.reference_time.as_micros(),
            if job.work {
                job.reference_end.elapsed().as_micros()
            } else {
                0
            }
        ));
    }

    /// Adopts how the optional render of `job` ended: decisions are
    /// committed only from a reply valid as a whole. Returns the outcome
    /// label and an accepted candidate's render.
    fn adopt_optional(
        &mut self,
        job: &PreparedJob,
        optional: Optional,
        settled: &mut Settled,
    ) -> (&'static str, Option<Box<Published>>) {
        let address = job.address;
        match optional {
            Optional::Unavailable => {
                debug_trace(format_args!("unavailable {address:#x}"));
                settled.unavailable = true;
                ("unavailable", None)
            }
            // No time or CPU left, or no child: nothing was attempted.
            Optional::NoWindow => ("no-window", None),
            Optional::Invalid => ("invalid", None),
            // Newer host input arrived: abandoned without any charge.
            Optional::Superseded => {
                debug_trace(format_args!("superseded {address:#x}"));
                ("superseded", None)
            }
            Optional::Expired => {
                // Expired, crashed or malformed: one direct attempt.
                crate::performance::event("debug_optional_expired", address);
                debug_trace(format_args!("expired {address:#x}"));
                if job.target_work {
                    self.debug.defer_target(address);
                }
                ("expired", None)
            }
            Optional::Replied(outcome) => {
                let (report, render) = outcome.split();
                let label = self.adopt_report(job, &report, render.as_deref(), settled);
                (label, render.filter(|_| settled.candidate))
            }
        }
    }

    /// Commits a checked debug report and records what the final render
    /// shows. `render` is the candidate's body when this worker has it.
    fn adopt_report(
        &mut self,
        job: &PreparedJob,
        report: &Report,
        render: Option<&Published>,
        settled: &mut Settled,
    ) -> &'static str {
        Self::describe_adoption(job.address, self.adopt_debug(job, report, render), settled)
    }

    fn describe_adoption(address: u64, adopted: Adopted, settled: &mut Settled) -> &'static str {
        match adopted {
            Adopted::Candidate {
                target_owns,
                vetoed,
            } => {
                crate::performance::event("debug_candidate_published", address);
                settled.candidate = true;
                settled.debug_owned = target_owns;
                settled.callees_shown = !vetoed;
                settled.vetoed = vetoed;
                if vetoed {
                    "veto-target-only"
                } else {
                    "candidate"
                }
            }
            Adopted::Reference { vetoed, own } => {
                crate::performance::event("debug_reference_published", address);
                settled.callees_shown = true;
                settled.vetoed = vetoed;
                settled.own_vetoed = own;
                if own {
                    "veto-own"
                } else if vetoed {
                    "veto"
                } else {
                    "reference"
                }
            }
            Adopted::Failed => {
                settled.engine_failure = true;
                "failed"
            }
            Adopted::Invalid => {
                crate::performance::event("debug_reply_invalid", address);
                "invalid"
            }
        }
    }

    /// Debug warnings of a final render whose direct calls are `calls`,
    /// from the committed decisions.
    fn debug_warnings(
        &self,
        job: &PreparedJob,
        settled: &Settled,
        calls: &[u64],
        changes: &[crate::debug_info::Change],
    ) -> Vec<&'static str> {
        use crate::debug_info::Decision;
        let address = job.address;
        let decision = |entry| match changes.binary_search_by_key(&entry, |change| change.entry) {
            Ok(index) => changes[index].new.decision(),
            Err(_) => self.debug.decision(entry),
        };
        let mut warnings = Vec::new();
        if job.client_skip {
            warnings.push(crate::debug_info::SKIPPED_FUNCTION_WARNING);
        } else if job.engine_failure || settled.engine_failure {
            warnings.push(crate::debug_info::ENGINE_FAILURE_WARNING);
        } else if job.active {
            if settled.unavailable {
                warnings.push(OPTIONAL_UNAVAILABLE_WARNING);
            }
            if settled.vetoed {
                warnings.push(CALLER_EVIDENCE_WARNING);
            }
            if settled.own_vetoed {
                warnings.push(OWN_EVIDENCE_WARNING);
            } else if !job.owned
                && !settled.debug_owned
                && matches!(decision(address), Decision::Undecided | Decision::Accepted)
            {
                warnings.push(UNVERIFIED_WARNING);
            }
            if !settled.vetoed
                && calls.iter().any(|&callee| {
                    callee != address
                        && job
                            .cached_hints
                            .as_ref()
                            .is_none_or(|hints| hints.contains(&callee))
                        && !self.applied_signatures.contains(&callee)
                        && match decision(callee) {
                            Decision::Undecided => true,
                            Decision::Accepted => !settled.callees_shown,
                            _ => false,
                        }
                })
            {
                warnings.push(CALLEE_UNVERIFIED_WARNING);
            }
        }
        warnings
    }

    /// The final reply of an ordinary request, cached when it is clean.
    fn finish(&mut self, job: &PreparedJob, settled: &Settled, published: Published) -> Response {
        let warnings = self.debug_warnings(job, settled, &published.calls, &[]);
        let clean = warnings.is_empty();
        let cacheable = published.calls_complete;
        let calls = published.calls.clone();
        let (text, mappings, semantics) = compose(published, &warnings, settled.debug_owned);
        if job.cacheable && clean && cacheable {
            self.cache_final(job, &calls, &text, &mappings, &semantics);
        }
        Response::Decompiled {
            address: job.address,
            text,
            mappings,
            semantics,
        }
    }

    /// Only a final result is reused: no pending or provisional decision
    /// and no warning about unverified or unavailable debug work.
    fn cache_final(
        &mut self,
        job: &PreparedJob,
        calls: &[u64],
        text: &str,
        mappings: &[CodeMapping],
        semantics: &crate::semantic::SemanticInfo,
    ) {
        let mut dependencies = std::iter::once(job.address)
            .chain(calls.iter().copied())
            .chain(job.callees.iter().copied())
            .collect::<Vec<_>>();
        dependencies.sort_unstable();
        dependencies.dedup();
        if dependencies
            .iter()
            .all(|&entry| !self.debug.provisional(entry))
        {
            self.cache_result(
                job.address,
                &job.renames,
                &job.context,
                &dependencies,
                text,
                mappings,
                semantics,
            );
        }
    }

    /// Renders ordinary inference and offers immutable indexed membership.
    /// Managed preparation never reads or writes the raw decisions or LRU.
    /// An `inference_only` recovery is the same ordinary render with no
    /// evidence, digest, offer or pending optional job, and always final.
    fn prepare_decompile(
        &mut self,
        logical_id: u64,
        address: u64,
        renames: &[crate::semantic::LocalRename],
        inference_only: bool,
    ) -> Result<Response, String> {
        if logical_id == 0 {
            return Err("Invalid logical decompile ID".into());
        }
        self.pending_debug = None;
        let (job, mut published) =
            match self.reference(address, renames, None, false, inference_only)? {
                Ok(prepared) => prepared,
                Err(_) => unreachable!("Managed reference never reads the raw cache"),
            };
        prepare_fault(address, inference_only);
        if inference_only || !job.work || !self.debug_long_names_complete {
            self.trace_request(&job, job.label);
            let warnings = if job.client_skip {
                vec![crate::debug_info::SKIPPED_FUNCTION_WARNING]
            } else if inference_only {
                // Debug data of the target itself stays unverified.
                if job.active && !job.owned && self.debug.indexed(address) {
                    vec![UNVERIFIED_WARNING]
                } else {
                    Vec::new()
                }
            } else if job.active && (!published.calls_complete || !self.debug_long_names_complete) {
                vec![UNVERIFIED_WARNING]
            } else {
                Vec::new()
            };
            let (text, mappings, semantics) = compose(published, &warnings, false);
            return Ok(Response::Decompiled {
                address,
                text,
                mappings,
                semantics,
            });
        }
        let executor = if crate::decompile::callee_probes_available() {
            managed::Executor::ForkHere
        } else {
            managed::Executor::Sibling
        };
        clip(
            &mut published.text,
            &mut published.mappings,
            &mut published.semantics,
        );
        let binding = self.managed_binding(&job, &published);
        self.debug_nonce = self
            .debug_nonce
            .checked_add(1)
            .ok_or("Debug offer counter overflow")?;
        let offer = managed::DebugOffer {
            logical_id,
            nonce: self.debug_nonce,
            executor,
            reference_us: duration_us(job.reference_time),
            elapsed_us: duration_us(job.reference_end - job.started),
            binding,
            calls: published.calls,
            target_work: job.target_work,
            graph_prepared: job.cached_hints.is_some(),
            callees: job.callees.clone(),
            cacheable: self.info.format != "PE"
                && self.pe_imports.is_empty()
                && !published
                    .text
                    .ends_with(crate::decompile::TRUNCATION_TRAILER),
        };
        debug_trace(format_args!(
            "prepared {address:#x} executor={executor:?} reference_us={}",
            job.reference_time.as_micros()
        ));
        if executor == managed::Executor::ForkHere {
            self.pending_debug = Some(managed::Pending {
                offer: offer.clone(),
                job,
            });
        }
        Ok(Response::PreparedDecompile {
            address,
            text: published.text,
            mappings: published.mappings,
            semantics: published.semantics,
            offer,
        })
    }

    pub(crate) fn try_prepared(
        &mut self,
        submitted: managed::PeerJob,
        preempt: &mut dyn FnMut() -> bool,
        started: &mut dyn FnMut(bool) -> Result<(), String>,
    ) -> Response {
        let ticket = submitted.ticket;
        let unavailable = |reason| managed::unavailable(ticket, reason);
        let Some(managed::Pending { offer, mut job }) = self.pending_debug.take_if(|pending| {
            pending.offer.nonce == ticket.nonce && pending.offer.logical_id == ticket.logical_id
        }) else {
            return unavailable("stale");
        };
        if submitted.check().is_err()
            || submitted.address != job.address
            || submitted.renames != job.renames
            || submitted.binding != offer.binding
            || submitted.graph_prepared != offer.graph_prepared
            || !self.check_seed(&submitted, offer.target_work, &offer.callees, true)
        {
            return unavailable("manifest");
        }
        job.target_work = submitted.target_work;
        job.callees = submitted.callees;
        let limit =
            std::time::Instant::now() + std::time::Duration::from_millis(submitted.remaining_ms);
        let optional = self.run_optional(
            &job,
            Some(limit),
            Some(preempt),
            Some(started),
            Some(&submitted.seed),
        );
        match optional {
            Optional::Replied(outcome) => managed::finished(ticket, offer.binding, outcome),
            Optional::Expired => unavailable("expired"),
            Optional::Invalid => unavailable("invalid"),
            Optional::Unavailable => unavailable("unavailable"),
            Optional::NoWindow => unavailable("deadline"),
            Optional::Superseded => unavailable("superseded"),
        }
    }

    /// Recaptures a fresh peer's ordinary output before accepting its job.
    pub(crate) fn render_debug_once(
        &mut self,
        job: managed::PeerJob,
        started: &mut dyn FnMut(managed::Ticket, bool) -> Result<(), String>,
    ) -> Result<Response, String> {
        let ticket = job.ticket;
        let unavailable = |reason| Ok(managed::unavailable(ticket, reason));
        job.check()?;
        let cutoff = std::time::Instant::now() + std::time::Duration::from_millis(job.remaining_ms);
        if !self.debug.active() {
            return unavailable("inactive");
        }
        let (prepared, mut published) =
            match self.reference(job.address, &job.renames, None, true, false)? {
                Ok(prepared) => prepared,
                Err(_) => unreachable!("Peer reference never reads the raw cache"),
            };
        clip(
            &mut published.text,
            &mut published.mappings,
            &mut published.semantics,
        );
        let measured = self.managed_binding(&prepared, &published);
        if measured != job.binding {
            let reason = if measured.program != job.binding.program
                || measured.context != job.binding.context
            {
                "digest-context"
            } else if measured.baseline != job.binding.baseline {
                "digest-baseline"
            } else {
                "digest-facts"
            };
            debug_trace(format_args!("peer-mismatch {:#x} {reason}", job.address));
            return unavailable(reason);
        }
        if !published.calls_complete
            || !self.check_seed(&job, prepared.target_work, &prepared.callees, false)
            || !self.seed_job(&job.seed)
        {
            return unavailable("eligibility");
        }
        if std::time::Instant::now() >= cutoff {
            return unavailable("deadline");
        }
        started(ticket, job.target_work)?;
        debug_fault(job.address);
        let debug_job = DebugJob {
            address: job.address,
            renames: &job.renames,
            context: &prepared.context,
            owned: prepared.owned,
            target_work: job.target_work,
            callees: job.callees,
            reference: prepared.caller.as_ref(),
        };
        let mut outcome = self.debug_render(&debug_job);
        Self::clip_outcome(&mut outcome);
        Ok(managed::finished(ticket, measured, outcome))
    }

    fn check_seed(
        &self,
        job: &managed::PeerJob,
        indexed_target: bool,
        indexed_callees: &[u64],
        exact: bool,
    ) -> bool {
        let eligible = |entry: u64| {
            if entry == job.address {
                indexed_target
            } else {
                indexed_callees.binary_search(&entry).is_ok()
            }
        };
        job.seed
            .states
            .iter()
            .all(|&(entry, _)| eligible(entry) && self.debug.indexed(entry))
            && job.seed.large.iter().all(|&entry| eligible(entry))
            && job.target_work == (indexed_target && job.seed.target_eligible(job.address))
            && job.callees.iter().all(|&entry| eligible(entry))
            && (!exact
                || indexed_callees
                    .iter()
                    .copied()
                    .filter(|&entry| job.seed.callee_eligible(entry))
                    .eq(job.callees.iter().copied()))
    }

    fn seed_job(&mut self, seed: &managed::Seed) -> bool {
        // Called only inside a disposable executor. The fork may inherit a
        // primary that previously served raw requests on the same transport.
        self.debug.reset_decisions();
        self.debug_large = seed.large.iter().copied().collect();
        seed.states
            .iter()
            .all(|&(entry, state)| self.debug.seed(entry, state))
    }

    fn clip_outcome(outcome: &mut DebugOutcome) {
        if let DebugOutcome::Candidate { render, .. } = outcome {
            clip(
                &mut render.text,
                &mut render.mappings,
                &mut render.semantics,
            );
        }
    }

    fn managed_binding(&mut self, job: &PreparedJob, published: &Published) -> managed::Binding {
        let inventory = self
            .debug_inventory_digest
            .get_or_insert_with(|| managed::inventory_digest(&self.info.functions));
        let program = self
            .debug_program_digest
            .get_or_insert_with(|| {
                managed::program_digest(
                    &self.info,
                    self.target.language,
                    inventory,
                    self.debug.summary.as_ref(),
                    &self.debug_skip,
                    &job.context,
                    &self.applied_signatures,
                    &self.debug_long_names,
                )
            })
            .clone();
        managed::Binding {
            context: managed::context_digest(&program, job.address, &job.renames),
            program,
            baseline: managed::baseline_digest(
                job.address,
                &published.text,
                &published.mappings,
                &published.semantics,
                &published.calls,
            ),
            facts: managed::facts_digest(job.caller.as_ref()),
        }
    }

    /// Whether the target's own debug prototype may still apply.
    fn target_eligible(&self, address: u64) -> bool {
        use crate::debug_info::Decision;
        match self.debug.decision(address) {
            Decision::Accepted => true,
            Decision::Undecided => self.debug.target_attempts_left(address),
            _ => false,
        }
    }

    /// Whether a debug prototype of `callee` may change `address`'s render:
    /// accepted, or undecided and still probeable.
    fn callee_eligible(&self, address: u64, callee: u64) -> bool {
        use crate::debug_info::Decision;
        callee != address
            && !self.applied_signatures.contains(&callee)
            && match self.debug.decision(callee) {
                Decision::Accepted => true,
                Decision::Undecided => {
                    !self.debug_large.contains(&callee) && self.debug.callee_attempts_left(callee)
                }
                _ => false,
            }
    }

    /// Runs [`Self::debug_render`] in a disposable child after the reference
    /// render, until the request's optional cutoff (and `limit`). A managed
    /// request also stops at once, charging nothing, when `preempt` reports
    /// newer host input.
    fn run_optional(
        &mut self,
        job: &PreparedJob,
        limit: Option<std::time::Instant>,
        mut preempt: Option<&mut dyn FnMut() -> bool>,
        started: Option<&mut dyn FnMut(bool) -> Result<(), String>>,
        seed: Option<&managed::Seed>,
    ) -> Optional {
        if !crate::decompile::callee_probes_available() {
            return Optional::Unavailable;
        }
        let now = std::time::Instant::now();
        let mut cutoff = (job.started + DEBUG_DEADLINE).min(
            job.reference_end
                + OPTIONAL_FLOOR.max(job.reference_time.saturating_mul(OPTIONAL_RATIO)),
        );
        if let Some(limit) = limit {
            cutoff = cutoff.min(limit);
        }
        let window = cutoff.saturating_duration_since(now);
        // The worker's own CPU allowance must still cover publishing; the
        // child's CPU is limited separately.
        if !optional_window_available(window, crate::limits::cpu_headroom()) {
            return Optional::NoWindow;
        }
        if preempt.as_mut().is_some_and(|check| check()) {
            return Optional::Superseded;
        }
        let stalled = debug_render_stalled(job.address);
        if stalled {
            use std::io::Write;
            let _ = std::io::stderr().write_all(b"debug-order: reference complete\n");
        }
        let debug_job = job.job();
        let Some(child) = crate::decompile::isolate(window, || {
            if stalled {
                use std::io::Write;
                let _ = std::io::stderr().write_all(b"debug-order: optional started\n");
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
            if let Some(seed) = seed
                && !self.seed_job(seed)
            {
                return None;
            }
            debug_fault(debug_job.address);
            let mut outcome = self.debug_render(&debug_job);
            if seed.is_some() {
                Self::clip_outcome(&mut outcome);
            }
            Some(outcome)
        }) else {
            return Optional::NoWindow;
        };
        if let Some(started) = started
            && started(job.target_work).is_err()
        {
            return Optional::Superseded;
        }
        crate::performance::event("debug_optional_forked", job.address);
        debug_trace(format_args!("fork {:#x}", job.address));
        let mut never = || false;
        match child.reply::<DebugOutcome>(cutoff, preempt.unwrap_or(&mut never)) {
            Ok(outcome) => Optional::Replied(outcome),
            Err(crate::decompile::Ended::Preempted) => Optional::Superseded,
            Err(crate::decompile::Ended::Expired) => Optional::Expired,
            Err(crate::decompile::Ended::Invalid) if seed.is_none() => Optional::Expired,
            Err(crate::decompile::Ended::Invalid) => Optional::Invalid,
        }
    }

    /// Checks a debug report as a whole before committing anything, then
    /// commits its decision changes. A candidate's `render`, when this
    /// worker has it, is checked too; a sibling's is checked by the host.
    /// A malformed report commits nothing.
    fn adopt_debug(
        &mut self,
        job: &PreparedJob,
        report: &Report,
        render: Option<&Published>,
    ) -> Adopted {
        let adopted = self.check_debug(job, report, render);
        if !matches!(adopted, Adopted::Invalid) {
            let (changes, large) = report.decisions();
            self.apply_debug_changes(
                changes,
                large,
                matches!(adopted, Adopted::Failed).then_some(job.address),
            );
        }
        adopted
    }

    fn check_debug(
        &self,
        job: &PreparedJob,
        report: &Report,
        render: Option<&Published>,
    ) -> Adopted {
        let mut allowed = job.callees.clone();
        allowed.push(job.address);
        let (changes, large) = report.decisions();
        if changes.len() > allowed.len()
            || !self.debug.check_changes(changes, &allowed)
            || (!job.target_work && changes.iter().any(|change| change.entry == job.address))
            || large.len() > job.callees.len()
            || !large.windows(2).all(|pair| pair[0] < pair[1])
            || large.iter().any(|entry| !job.callees.contains(entry))
        {
            return Adopted::Invalid;
        }
        // The target's state after this render, for its provenance.
        let state_after = |entry| match changes.binary_search_by_key(&entry, |change| change.entry)
        {
            Ok(index) => changes[index].new,
            Err(_) => self.debug.state(entry),
        };
        let target_after = state_after(job.address);
        if let Report::Candidate {
            calls,
            target_owns,
            installed_callees,
            compared,
            vetoed,
            ..
        } = report
        {
            let body = render.is_none_or(|render| {
                render.text.len()
                    <= MAX_DECOMPILED_BYTES + crate::decompile::TRUNCATION_TRAILER.len()
                    && crate::selection::validate_mappings(
                        &render.text,
                        &render.mappings,
                        &self.info.sections,
                    )
                    .is_ok()
                    && render
                        .semantics
                        .validate(&render.text, job.address, &self.info.sections)
                        .is_ok()
                    && render.semantics.locals.iter().all(|local| {
                        local.identity.engine == crate::semantic::local_fingerprint(&job.context)
                    })
                    && render.calls == *calls
                    && render.semantics.prototype_source
                        == crate::semantic::PrototypeSource::Inferred
            });
            let valid = body
                && calls.len() <= crate::model::MAX_GRAPH_CALLS
                && calls.windows(2).all(|pair| pair[0] < pair[1])
                && calls
                    .iter()
                    .all(|&entry| crate::call_analysis::code_address(&self.info, entry))
                && installed_callees.len() <= job.callees.len()
                && installed_callees.windows(2).all(|pair| pair[0] < pair[1])
                && installed_callees.iter().all(|entry| {
                    job.callees.contains(entry)
                        && state_after(*entry).decision() == crate::debug_info::Decision::Accepted
                })
                && *compared
                && (*target_owns || !installed_callees.is_empty())
                && (!*vetoed || (*target_owns && installed_callees.is_empty()))
                && (!*target_owns
                    || (job.target_work
                        && target_after.status == crate::debug_info::Status::Verified));
            if !valid {
                return Adopted::Invalid;
            }
        }
        match report {
            Report::Candidate {
                target_owns,
                vetoed,
                ..
            } => Adopted::Candidate {
                target_owns: *target_owns,
                vetoed: *vetoed,
            },
            Report::UseReference { reason, .. } => Adopted::Reference {
                vetoed: *reason == Unchanged::EvidenceLost,
                own: *reason == Unchanged::OwnEvidenceLost,
            },
            Report::Failed { .. } => Adopted::Failed,
        }
    }

    fn apply_debug_changes(
        &mut self,
        changes: &[crate::debug_info::Change],
        large: &[u64],
        failed: Option<u64>,
    ) {
        self.debug.apply_changes(changes);
        for &entry in large {
            if self.debug_large.len() < crate::model::MAX_FUNCTIONS {
                self.debug_large.insert(entry);
            }
        }
        if let Some(address) = failed
            && self.debug_failed.len() < crate::model::MAX_FUNCTIONS
        {
            self.debug_failed.insert(address);
        }
    }

    /// The debug render of `job`, in a disposable child: the target's
    /// unlocked probe, then accepted and newly proven callee prototypes, the
    /// target's prototype, one locked render, the caller comparison against
    /// the reference and the target's verification. Returns the decision
    /// changes it made, which the worker adopts.
    fn debug_render(&mut self, job: &DebugJob<'_>) -> DebugOutcome {
        self.debug.begin_journal();
        self.debug_large_journal = Some(Vec::new());
        let outcome = self.debug_render_inner(job);
        let changes = self.debug.take_journal();
        let large = self.debug_large_journal.take().unwrap_or_default();
        match outcome {
            Inner::Candidate {
                render,
                target_owns,
                installed_callees,
                compared,
                vetoed,
            } => DebugOutcome::Candidate {
                render,
                target_owns,
                installed_callees,
                compared,
                vetoed,
                changes,
                large,
            },
            Inner::Reference(reason) => DebugOutcome::UseReference {
                reason,
                changes,
                large,
            },
            Inner::Failed => DebugOutcome::Failed { changes, large },
        }
    }

    fn debug_render_inner(&mut self, job: &DebugJob<'_>) -> Inner {
        use crate::debug_info::Decision;
        let address = job.address;
        let started = std::time::Instant::now();
        // Obligations come from the reference and the machine code alone,
        // before any lock is installed.
        let obligations = job.reference.map(|facts| {
            let _timing = crate::performance::span("caller_evidence_corroborate");
            let program = &self.program;
            let executable = crate::selection::ExecutableRanges::new(&self.info.sections).ok();
            crate::debug_info::caller::obligations(facts, &mut |pc| {
                let executable = executable.as_ref()?;
                let lifted = program.pcode(pc, 1).ok()?.into_iter().next()?;
                let length = u64::try_from(lifted.length).ok()?;
                (lifted.address == pc && executable.contains_span(pc, length)).then(|| {
                    crate::debug_info::caller::RawInstruction {
                        address: pc,
                        length,
                        ops: lifted
                            .operations
                            .iter()
                            .map(|op| crate::debug_info::caller::RawOp {
                                opcode: op.opcode,
                                output: op
                                    .output
                                    .as_ref()
                                    .map(crate::debug_info::caller::RawVarnode::from_engine),
                                inputs: op
                                    .inputs
                                    .iter()
                                    .map(crate::debug_info::caller::RawVarnode::from_engine)
                                    .collect(),
                            })
                            .collect(),
                    }
                })
            })
        });
        // The CFG's direct calls drop targets only the engine reports
        // (flow past calls that never return, resolved indirect jumps).
        let (target_size, callees) = match self.debug_call_hints(address) {
            Ok((size, hints)) => (
                size,
                job.callees
                    .iter()
                    .copied()
                    .filter(|callee| hints.contains(callee))
                    .collect::<Vec<_>>(),
            ),
            Err(_) => (0, job.callees.clone()),
        };
        let mut budget = ProbeBudget::for_target(address, target_size);
        let prepared = started.elapsed();
        // The target's unlocked probe runs before any callee lock exists.
        let mut probed = None;
        if job.target_work && self.debug.decision(address) == Decision::Undecided {
            probed = self.debug.probe_pending(&mut self.program, address);
        }
        let probed_at = started.elapsed();
        self.debug_callees(&callees, &mut budget);
        let callees_at = started.elapsed();
        debug_trace(format_args!(
            "child {address:#x} evidence_hints_us={} target_probe_us={} callees_us={}",
            prepared.as_micros(),
            (probed_at - prepared).as_micros(),
            (callees_at - probed_at).as_micros()
        ));
        let mut target_owned = false;
        let mut pending = false;
        if job.target_work {
            match self.debug.decision(address) {
                Decision::Accepted => {
                    target_owned = self.debug.install_accepted(&mut self.program, address);
                    // A callee-only acceptance must pass its own locked render.
                    pending = target_owned && self.debug.provisional(address);
                }
                Decision::Undecided => {
                    if let Some(probed) = probed {
                        target_owned =
                            self.debug
                                .install_probed(&mut self.program, address, probed);
                        pending = target_owned;
                    }
                }
                _ => {}
            }
        }
        let mut vetoed = false;
        for attempt in 0..2 {
            let installed_callees = self
                .debug
                .installed_entries()
                .into_iter()
                .filter(|&entry| entry != address && !self.applied_signatures.contains(&entry))
                .collect::<Vec<_>>();
            if installed_callees.is_empty() && !target_owned {
                return Inner::Reference(if vetoed {
                    Unchanged::EvidenceLost
                } else {
                    Unchanged::NothingInstalled
                });
            }
            // Any lock, the function's own included, changes how the engine
            // recovers every call's arguments: compare each candidate.
            let compare = true;
            let rendered = crate::decompile::render_full(
                &mut self.program,
                address,
                &self.info.sections,
                job.renames,
                job.context,
                job.owned,
                Some(Arc::clone(&self.symbol_names)),
                compare,
            );
            let Ok(render) = rendered else {
                // A definitive engine failure: a provisional target is
                // withdrawn for its callers.
                if pending {
                    self.debug.fail_direct(address);
                }
                self.withdraw_debug(address, false);
                return Inner::Failed;
            };
            if compare {
                // Callee locks need complete evidence. The function's own
                // lock alone was previously never compared; it is vetoed
                // only by a confirmed loss among the facts that exist.
                let complete = !installed_callees.is_empty();
                let verdict = match (&obligations, &render.caller) {
                    (Some(obligations), Some(candidate)) => {
                        crate::debug_info::caller::compare(obligations, candidate, complete)
                    }
                    _ if !complete => Ok(()),
                    _ => Err(crate::debug_info::caller::Veto::IncompleteReference),
                };
                if let Err(veto) = verdict {
                    crate::performance::event("debug_caller_veto", address);
                    debug_trace(format_args!(
                        "veto {address:#x} ({} callees{}): {veto}",
                        installed_callees.len(),
                        if target_owned { ", own" } else { "" }
                    ));
                    if attempt == 0 && !installed_callees.is_empty() {
                        // Remove every callee prototype; the function's own
                        // (if installed) renders once more alone.
                        vetoed = true;
                        for entry in installed_callees {
                            self.debug.rollback(&mut self.program, entry, false);
                        }
                        continue;
                    }
                    if !installed_callees.is_empty() || !target_owned {
                        return Inner::Reference(Unchanged::EvidenceLost);
                    }
                    // The function's own prototype lost evidence. It is not
                    // verified by this render; a pending verification is
                    // charged one attempt, and callers may still use it.
                    if pending {
                        self.debug.defer_target(address);
                    }
                    self.debug.rollback(&mut self.program, address, false);
                    return Inner::Reference(Unchanged::OwnEvidenceLost);
                }
            }
            if pending
                && !self
                    .debug
                    .verify(&mut self.program, address, &render.evidence)
            {
                // Rejected (or unverifiable): the callees alone may still
                // apply, verified afresh by one more render.
                target_owned = false;
                pending = false;
                if attempt == 0 {
                    continue;
                }
                break;
            }
            let target_owns = target_owned
                && self.debug.state(address).status == crate::debug_info::Status::Verified;
            return Inner::Candidate {
                render: Box::new(Published {
                    text: render.text,
                    mappings: render.mappings,
                    semantics: render.semantics,
                    calls: render.calls,
                    calls_complete: render.calls_complete,
                }),
                target_owns,
                installed_callees: installed_callees.clone(),
                compared: compare,
                vetoed,
            };
        }
        Inner::Reference(if vetoed {
            Unchanged::EvidenceLost
        } else {
            Unchanged::NothingInstalled
        })
    }

    /// A cached final render for exactly this request and current decisions.
    fn cached_result(
        &mut self,
        address: u64,
        renames: &[crate::semantic::LocalRename],
        context: &str,
    ) -> Option<Response> {
        let index = self.results.entries.iter().position(|entry| {
            entry.address == address
                && entry.epoch == self.result_epoch
                && entry.context == context
                && entry.renames == renames
        })?;
        let current = |entry: u64| (self.debug.state(entry), self.debug_large.contains(&entry));
        if self.results.entries[index]
            .dependencies
            .iter()
            .any(|&(entry, state, large)| current(entry) != (state, large))
        {
            if let Some(stale) = self.results.entries.remove(index) {
                self.results.bytes -= stale.bytes;
            }
            return None;
        }
        // Most recently used last.
        let entry = self.results.entries.remove(index)?;
        let response = Response::Decompiled {
            address,
            text: entry.text.clone(),
            mappings: entry.mappings.clone(),
            semantics: entry.semantics.clone(),
        };
        self.results.entries.push_back(entry);
        Some(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn cache_result(
        &mut self,
        address: u64,
        renames: &[crate::semantic::LocalRename],
        context: &str,
        dependencies: &[u64],
        text: &str,
        mappings: &[CodeMapping],
        semantics: &crate::semantic::SemanticInfo,
    ) {
        let mut counter = EncodedLength(0);
        if serde_json::to_writer(&mut counter, semantics).is_err() {
            return;
        }
        let bytes = counter
            .0
            .saturating_add(text.len())
            .saturating_add(
                mappings
                    .len()
                    .saturating_mul(std::mem::size_of::<CodeMapping>()),
            )
            .saturating_add(dependencies.len().saturating_mul(std::mem::size_of::<(
                u64,
                crate::debug_info::EntryState,
                bool,
            )>()))
            .saturating_add(context.len() + 256);
        self.results.insert(CachedResult {
            address,
            renames: renames.to_vec(),
            context: context.into(),
            epoch: self.result_epoch,
            dependencies: dependencies
                .iter()
                .map(|&entry| {
                    (
                        entry,
                        self.debug.state(entry),
                        self.debug_large.contains(&entry),
                    )
                })
                .collect(),
            text: text.into(),
            mappings: mappings.to_vec(),
            semantics: semantics.clone(),
            bytes,
        });
    }

    /// The instruction count and direct call targets of `address`, from the
    /// last displayed graph or a bounded CFG walk.
    fn debug_call_hints(&mut self, address: u64) -> Result<CallHints, String> {
        #[cfg(test)]
        if DEBUG_HINT_FAILURE.get() {
            return Err("Injected CFG hint error".into());
        }
        if let Some((_, hints)) = self.debug_calls.iter().find(|(entry, _)| *entry == address) {
            return Ok(hints.clone());
        }
        let mut remaining = MAX_INSTRUCTIONS;
        let recovered = recover_graph_budgeted(
            &self.program,
            &Bounds {
                tail_entry: None,
                sections: &self.info.sections,
                is_function: &|entry| function_at(&self.info.functions, entry).is_some(),
                pe_ranges: &self.pe_ranges,
            },
            address,
            &mut remaining,
            &self.no_return,
            None,
        )?;
        Ok(call_hints(&recovered, MAX_INSTRUCTIONS - remaining))
    }

    /// Reinstalls accepted callees and probes bounded undecided candidates
    /// in one child. The child starts with only previously accepted locks.
    fn debug_callees(&mut self, callees: &[u64], budget: &mut ProbeBudget) -> bool {
        use crate::debug_info::Decision;

        let mut changed = false;
        let mut addresses = Vec::new();
        let mut candidates = Vec::new();
        let mut can_probe = None;
        for &callee in callees {
            if callee == budget.target || self.applied_signatures.contains(&callee) {
                continue;
            }
            match self.debug.decision(callee) {
                Decision::Accepted if !self.debug.is_installed(callee) => {
                    changed |= self.debug.install_accepted(&mut self.program, callee);
                }
                Decision::Undecided
                    if !addresses.contains(&callee)
                        && !self.debug_large.contains(&callee)
                        && *can_probe
                            .get_or_insert_with(crate::decompile::callee_probes_available)
                        && budget.take_probe() =>
                {
                    if let Some(prototype) = self.debug.prepare_callee(callee)
                        && self.probe_shape(callee, budget)
                    {
                        addresses.push(callee);
                        candidates.push(prototype);
                    }
                }
                _ => {}
            }
        }
        if addresses.is_empty() || std::time::Instant::now() >= budget.deadline {
            return changed;
        }
        let replies = crate::decompile::probe_callees(
            &mut self.program,
            &addresses,
            &self.info.sections,
            budget.deadline,
        );
        // Only charge an unavailable attempt for explicit failed results
        // and the first missing result. Later candidates may not have run.
        let evidence = replies.into_iter().chain(std::iter::once(None));
        for ((entry, prototype), evidence) in addresses.into_iter().zip(candidates).zip(evidence) {
            changed |=
                self.debug
                    .finish_callee(&mut self.program, entry, prototype, evidence.as_ref());
        }
        changed
    }

    /// Charge the shape walk even if the remaining allowance is too small.
    /// The walk only estimates cost (the probe child's CPU limits bound it,
    /// and evidence comes from the engine), so unresolved indirect jumps and
    /// tail exits do not prevent a probe; a walk that needs the whole
    /// allowance does. Cache a large shape only if this request gave it the
    /// full per-callee allowance.
    fn probe_shape(&mut self, entry: u64, budget: &mut ProbeBudget) -> bool {
        let allowance = budget.instructions.min(PROBE_CALLEE_INSTRUCTIONS) + 1;
        let mut remaining = allowance;
        let shape = recover_graph_budgeted(
            &self.program,
            &Bounds {
                tail_entry: None,
                sections: &self.info.sections,
                is_function: &|e| function_at(&self.info.functions, e).is_some(),
                pe_ranges: &self.pe_ranges,
            },
            entry,
            &mut remaining,
            &self.no_return,
            None,
        )
        .is_ok()
            && remaining > 0;
        budget.instructions = budget.instructions.saturating_sub(allowance - remaining);
        if !shape
            && allowance > PROBE_CALLEE_INSTRUCTIONS
            && self.debug_large.len() < crate::model::MAX_FUNCTIONS
            && self.debug_large.insert(entry)
            && let Some(journal) = self.debug_large_journal.as_mut()
        {
            journal.push(entry);
        }
        shape
    }

    /// Removes every installed debug prototype, so the next render of
    /// `address` uses none, its own or any callee's (including call targets
    /// only the engine resolves). Other functions reinstall accepted
    /// prototypes on demand without new evidence. `reject` also stops any
    /// later install for `address` itself.
    fn withdraw_debug(&mut self, address: u64, reject: bool) {
        if reject && !self.applied_signatures.contains(&address) {
            self.debug.rollback(&mut self.program, address, true);
        }
        for entry in self.debug.installed_entries() {
            if !self.applied_signatures.contains(&entry) {
                self.debug.rollback(&mut self.program, entry, false);
            }
        }
    }

    /// The displayed CFG. Known functions of unpacked images also resolve
    /// switch tables; other addresses keep raw instruction flow.
    fn graph(&mut self, address: u64) -> Result<FunctionView, String> {
        let mut remaining = MAX_INSTRUCTIONS;
        let recovered =
            self.graph_recovery_budgeted(address, &mut remaining, &mut SwitchBudget::new())?;
        if self.debug.active() {
            self.debug_calls.retain(|(entry, _)| *entry != address);
            if self.debug_calls.len() == 64 {
                self.debug_calls.pop_front();
            }
            self.debug_calls.push_back((
                address,
                call_hints(&recovered, MAX_INSTRUCTIONS - remaining),
            ));
        }
        Ok(recovered.view)
    }

    /// [`Self::graph`] charging decode attempts and engine switch recoveries
    /// to budgets a caller may share between functions.
    fn graph_budgeted(
        &mut self,
        address: u64,
        remaining: &mut usize,
        switches: &mut SwitchBudget,
    ) -> Result<FunctionView, String> {
        self.graph_recovery_budgeted(address, remaining, switches)
            .map(|recovered| recovered.view)
    }

    fn graph_recovery_budgeted(
        &mut self,
        address: u64,
        remaining: &mut usize,
        switches: &mut SwitchBudget,
    ) -> Result<cfg::GraphRecovery, String> {
        let functions = &self.info.functions;
        if !functions.is_sorted_by_key(|function| function.address) {
            return Err("Function inventory is not ordered by address".into());
        }
        let is_function = |candidate| function_at(functions, candidate).is_some();
        let recovered = if self.upx_packed || !is_function(address) {
            recover_graph_budgeted(
                &self.program,
                &Bounds {
                    tail_entry: None,
                    sections: &self.info.sections,
                    is_function: &is_function,
                    pe_ranges: &self.pe_ranges,
                },
                address,
                remaining,
                &self.no_return,
                None,
            )?
        } else {
            recover_graph_switched(
                &mut self.program,
                &Bounds {
                    tail_entry: None,
                    sections: &self.info.sections,
                    is_function: &is_function,
                    pe_ranges: &self.pe_ranges,
                },
                address,
                remaining,
                switches,
                &self.no_return,
                None,
            )?
        };
        Ok(recovered)
    }

    /// Graph-path views of `entries` for the Program listing, an examined
    /// prefix within shared limits: decode attempts, one switch budget capped
    /// at the listing allowance, an elapsed allowance and an encoded-size
    /// estimate. Every function receives the full per-graph walk limit; the
    /// first entry is always examined. No function starts after the
    /// allowance, and none starts a switch recovery once recoveries have
    /// spent it, so a batch takes at most the allowance plus one function's
    /// walk and one engine recovery.
    ///
    /// A view whose switch recovery the allowance skipped would differ from
    /// its Graph reply. Such a function ends the prefix unexamined, so a
    /// later batch retries it first; as the first entry it has no view.
    fn listing(
        &mut self,
        entries: &[u64],
        limits: ListingLimits,
    ) -> Result<Vec<crate::model::ListingOutcome>, String> {
        crate::model::validate_listing_entries(entries)?;
        let started = std::time::Instant::now();
        let mut switches = SwitchBudget::within(limits.switches);
        let mut decoded = 0usize;
        let mut encoded = 0usize;
        let mut outcomes = Vec::with_capacity(entries.len());
        for &entry in entries {
            if !outcomes.is_empty()
                && (limits.decode_attempts.saturating_sub(decoded) < MAX_INSTRUCTIONS
                    || encoded >= limits.reply_bytes
                    || started.elapsed() >= limits.elapsed)
            {
                break;
            }
            let mut remaining = MAX_INSTRUCTIONS;
            let mut view = self
                .graph_budgeted(entry, &mut remaining, &mut switches)
                .ok();
            decoded = decoded.saturating_add(MAX_INSTRUCTIONS - remaining);
            if view
                .as_ref()
                .is_some_and(|view| view.warnings.iter().any(|w| w == SWITCH_SKIPPED))
            {
                if !outcomes.is_empty() {
                    break;
                }
                view = None;
            }
            if let Some(view) = &view {
                let mut counter = EncodedLength(0);
                serde_json::to_writer(&mut counter, view)
                    .map_err(|error| format!("Listing view encoding failed: {error}"))?;
                encoded = encoded.saturating_add(counter.0);
            }
            outcomes.push(crate::model::ListingOutcome { entry, view });
        }
        Ok(outcomes)
    }

    pub(crate) fn handle_with_progress(
        &mut self,
        request: Request,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<Response, String> {
        if matches!(
            request,
            Request::Graph { .. }
                | Request::Listing { .. }
                | Request::Decompile { .. }
                | Request::DecompileWithLocals { .. }
                | Request::RefreshDecompile { .. }
                | Request::PrepareDecompile { .. }
                | Request::RenderDebugOnce { .. }
                | Request::Discover
                | Request::DiscoverBatch { .. }
        ) {
            self.analysis_started = true;
        }
        // Requests that can change names, signatures, the inventory or the
        // engine's functions retire every cached render.
        if !matches!(
            request,
            Request::Graph { .. }
                | Request::Listing { .. }
                | Request::Decompile { .. }
                | Request::DecompileWithLocals { .. }
                | Request::RefreshDecompile { .. }
                | Request::PrepareDecompile { .. }
                | Request::TryPreparedDebug { .. }
                | Request::RenderDebugOnce { .. }
                | Request::SearchMemory { .. }
                | Request::Bytes { .. }
                | Request::Strings
                | Request::StringsWithOptions { .. }
                | Request::Crypto
                | Request::SymbolNames { .. }
                | Request::Linkage { .. }
        ) {
            self.result_epoch = self.result_epoch.wrapping_add(1);
            self.results.clear();
            // An offer is bound to the names and signatures it was made under.
            self.pending_debug = None;
        }
        if request.changes_managed_program() {
            self.debug_program_digest = None;
        }
        match request {
            request @ Request::SearchMemory { .. } => self.search_memory(request),
            Request::Listing { binding, entries } => Ok(Response::Listing {
                binding,
                outcomes: self.listing(&entries, ListingLimits::default())?,
            }),
            Request::Graph { address } => Ok(Response::Graph {
                view: self.graph(address)?,
            }),
            Request::Decompile { address } => self.decompile(address, &[], false),
            Request::DecompileWithLocals { address, renames } => {
                self.decompile(address, &renames, false)
            }
            Request::RefreshDecompile { address, renames } => {
                self.decompile(address, &renames, true)
            }
            Request::PrepareDecompile {
                logical_id,
                address,
                renames,
                inference_only,
                ..
            } => self.prepare_decompile(logical_id, address, &renames, inference_only),
            Request::TryPreparedDebug { job } => {
                Ok(self.try_prepared(job, &mut || false, &mut |_| Ok(())))
            }
            Request::RenderDebugOnce { job } => self.render_debug_once(job, &mut |_, _| Ok(())),
            Request::Discover => {
                self.check_unpacked()?;
                // Selected-function analysis can materialize and name a callee
                // since the last published inventory. Preserve those names.
                self.rebuild_inventory(&BTreeSet::new())?;
                self.inventory.take_certificate(&self.info.functions);
                let (analysis, _, _) = self.discover_calls(None, progress)?;
                // Evidence owners must survive inventory admission so every
                // published reference has its caller in the same reply.
                let owners = analysis
                    .references
                    .iter()
                    .map(|reference| reference.caller)
                    .chain(
                        analysis
                            .data
                            .iter()
                            .flat_map(|data| data.references.iter().map(|r| r.function)),
                    )
                    .chain(
                        analysis
                            .addresses
                            .iter()
                            .flat_map(|addresses| addresses.references.iter().map(|r| r.function)),
                    )
                    .collect();
                self.rebuild_inventory(&owners)?;
                Ok(Response::Functions {
                    functions: self.info.functions.clone(),
                    truncated: self.info.functions_truncated || analysis.partial,
                    analysis,
                })
            }
            Request::DiscoverBatch {
                binding,
                inventory_base,
                seeds,
                patterns: Some(DiscoveryCursor::Pointers(cursor)),
            } => {
                self.check_unpacked()?;
                if !seeds.is_empty() {
                    return Err("A pointer scan has no seeds".into());
                }
                let empty = AnalysisProgress {
                    stage: AnalysisStage::Seeds,
                    functions_examined: 0,
                    decode_attempts: 0,
                };
                progress(empty.clone())?;
                let certificate = self.inventory.take_certificate(&self.info.functions);
                let (scan, discovered, admissions) = self.scan_pointers(cursor)?;
                self.update_batch_inventory(certificate, &BTreeSet::new(), discovered)?;
                let inventory = self
                    .inventory
                    .publish(inventory_base, &self.info.functions)?;
                progress(AnalysisProgress {
                    stage: AnalysisStage::Publish,
                    ..empty
                })?;
                Ok(Response::DiscoveryBatch {
                    batch: DiscoveryBatch {
                        binding,
                        inventory,
                        truncated: self.info.functions_truncated,
                        analysis: CallAnalysis::default(),
                        outcomes: Vec::new(),
                        patterns: None,
                        pointers: Some(Box::new(scan)),
                        admissions,
                        recovery_records: 0,
                    },
                })
            }
            Request::DiscoverBatch {
                binding,
                inventory_base,
                seeds,
                patterns: Some(crate::model::DiscoveryCursor::Patterns(cursor)),
            } => {
                self.check_unpacked()?;
                if !seeds.is_empty() {
                    return Err("A pattern-scan batch has no seeds".into());
                }
                // Same progress protocol as seed batches: the scan reports no
                // examined functions or call-analysis decode work.
                let empty = AnalysisProgress {
                    stage: AnalysisStage::Seeds,
                    functions_examined: 0,
                    decode_attempts: 0,
                };
                progress(empty.clone())?;
                let certificate = self.inventory.take_certificate(&self.info.functions);
                let (scan, discovered) = self.scan_patterns(cursor)?;
                self.update_batch_inventory(certificate, &BTreeSet::new(), discovered)?;
                let inventory = self
                    .inventory
                    .publish(inventory_base, &self.info.functions)?;
                progress(AnalysisProgress {
                    stage: AnalysisStage::Publish,
                    ..empty
                })?;
                Ok(Response::DiscoveryBatch {
                    batch: DiscoveryBatch {
                        binding,
                        inventory,
                        truncated: self.info.functions_truncated,
                        analysis: CallAnalysis {
                            partial: self.info.functions_truncated,
                            ..Default::default()
                        },
                        outcomes: Vec::new(),
                        admissions: scan
                            .admitted
                            .iter()
                            .map(|&entry| FunctionAdmission {
                                entry,
                                reason: AdmissionReason::Pattern,
                                source: entry,
                                owner: None,
                                encoding: PointerEncoding::Direct,
                                boundary: BoundaryEvidence::Pattern,
                                table: None,
                            })
                            .collect(),
                        patterns: Some(scan),
                        pointers: None,
                        recovery_records: 0,
                    },
                })
            }
            Request::DiscoverBatch {
                binding,
                inventory_base,
                seeds,
                patterns: None,
            } => {
                self.check_unpacked()?;
                if seeds.is_empty()
                    || seeds.len() > MAX_ANALYSIS_FUNCTIONS
                    || seeds.iter().copied().collect::<BTreeSet<_>>().len() != seeds.len()
                {
                    return Err("Invalid discovery seed batch".into());
                }
                for &address in &seeds {
                    self.check_code(address)?;
                }
                #[cfg(debug_assertions)]
                let truncated_before = self.info.functions_truncated;
                let certificate = self.inventory.take_certificate(&self.info.functions);
                let (analysis, outcomes, discovered) =
                    self.discover_calls(Some(&seeds), progress)?;
                let recovery_records = self.take_pointer_preparation();
                let owners = outcomes.iter().map(|outcome| outcome.address).collect();
                self.update_batch_inventory(certificate, &owners, discovered)?;
                #[cfg(debug_assertions)]
                {
                    // The full selection remains the oracle for every shortcut.
                    let (expected, rejected) =
                        select_functions(&self.program, &self.info, &owners)?;
                    assert_eq!(self.info.functions, expected, "inventory shortcut diverged");
                    assert_eq!(self.info.functions_truncated, truncated_before || rejected);
                }
                let publishing = crate::performance::span("inventory_publish");
                let inventory = self
                    .inventory
                    .publish(inventory_base, &self.info.functions)?;
                publishing.finish(match &inventory {
                    InventoryChange::Unchanged { .. } => 0,
                    InventoryChange::Delta {
                        upserts, removals, ..
                    } => (upserts.len() + removals.len()) as u64,
                    InventoryChange::Replace { functions, .. } => functions.len() as u64,
                });
                Ok(Response::DiscoveryBatch {
                    batch: DiscoveryBatch {
                        binding,
                        inventory,
                        truncated: self.info.functions_truncated,
                        analysis,
                        outcomes,
                        patterns: None,
                        pointers: None,
                        admissions: Vec::new(),
                        recovery_records,
                    },
                })
            }
            Request::SyncSignatures {
                binary_sha256,
                context,
                signatures,
            } => {
                crate::signatures::validate_signatures(&signatures)?;
                if binary_sha256 != self.info.sha256
                    || context != crate::signatures::state_digest(&signatures)
                {
                    return Err("Signature state does not match this binary or its digest".into());
                }
                if self.analysis_started || self.signature_state.is_some() {
                    return Err(
                        "Signature replacement requires a fresh worker before analysis".into(),
                    );
                }
                let abi = crate::signatures::current_abi(&self.info)?;
                let mut unapplied = Vec::new();
                let mut compatible = Vec::new();
                for signature in &signatures {
                    self.check_code(signature.function)?;
                    if signature.engine != crate::signatures::SIGNATURE_FINGERPRINT
                        || signature.abi != abi
                    {
                        unapplied.push(SignatureStatus { function: signature.function,
                            reason: "Saved signature has an incompatible engine or ABI; edit it to apply to this image".into() });
                    } else if function_at(&self.info.functions, signature.function).is_none() {
                        unapplied.push(SignatureStatus { function: signature.function,
                            reason: "Saved signature entry is absent from the current function inventory; recompute discovery before editing it".into() });
                    } else {
                        compatible.push(signature.clone());
                    }
                }
                crate::signatures::apply(&mut self.program, &compatible, &abi)?;
                self.applied_signatures = compatible
                    .iter()
                    .map(|signature| signature.function)
                    .collect();
                self.signatures = signatures;
                self.signature_state = Some(context.clone());
                Ok(Response::SignaturesSynced {
                    binary_sha256,
                    context,
                    unapplied,
                })
            }
            Request::SyncFunctions { functions } => {
                validate_functions(&functions, MAX_FUNCTION_NAME_BYTES, true)?;
                if functions.len() > MAX_DISCOVERY_SYNC_FUNCTIONS {
                    return Err("Oversized function synchronization".into());
                }
                // Validate the entire request before touching the engine. The
                // inventory admission routine retains its shared name/count caps.
                for function in &functions {
                    self.check_code(function.address)?;
                }
                if functions.iter().all(|function| {
                    function_at(&self.info.functions, function.address)
                        .is_some_and(|current| current.name == function.name)
                }) {
                    return Ok(Response::FunctionsSynced);
                }
                self.inventory.take_certificate(&self.info.functions);
                for function in functions {
                    if function_at(&self.info.functions, function.address)
                        .is_some_and(|current| current.name == function.name)
                    {
                        continue;
                    }
                    self.program
                        .set_function_name(function.address, &function.name)
                        .map_err(engine_error)?;
                    self.debug_long_names.remove(&function.address);
                }
                self.rebuild_inventory(&BTreeSet::new())?;
                Ok(Response::FunctionsSynced)
            }
            Request::Rename { address, name } => {
                self.check_code(address)?;
                if name.trim().is_empty() || name.len() > 1024 || name.chars().any(char::is_control)
                {
                    return Err(
                        "Function names must contain 1–1024 bytes and no control characters."
                            .into(),
                    );
                }
                self.inventory.take_certificate(&self.info.functions);
                self.program
                    .set_function_name(address, &name)
                    .map_err(engine_error)?;
                self.synchronize_function_name(address, &name)?;
                self.rebuild_inventory(&BTreeSet::new())?;
                if name.len() > MAX_FUNCTION_NAME_BYTES {
                    if self.debug_long_names.len() < crate::session::MAX_ANNOTATIONS
                        || self.debug_long_names.contains_key(&address)
                    {
                        self.debug_long_names.insert(address, name.clone());
                    } else {
                        // An incomplete name projection cannot authorize a managed job.
                        self.debug_long_names_complete = false;
                    }
                } else {
                    self.debug_long_names.remove(&address);
                }
                Ok(Response::Renamed { address, name })
            }
            Request::Bytes { address, length } => {
                let bytes = read_virtual(&self.snapshot, &self.info.sections, address, length)?;
                Ok(Response::Bytes { address, bytes })
            }
            Request::Strings => self.strings(MIN_STRING_LENGTH),
            Request::StringsWithOptions { minimum_length } => self.strings(minimum_length),
            Request::Crypto => self.crypto(),
            Request::SymbolNames { cursor } => Ok(Response::SymbolNames {
                page: self.symbol_names.page(cursor)?,
            }),
            Request::Linkage { cursor, digest } => {
                if self.linkage.is_none() {
                    let pe = crate::pe::linkage(&self.snapshot, &self.info.sections)?;
                    let entries = self.program.functions().map_err(engine_error)?;
                    let stubs: Vec<_> = entries
                        .iter()
                        .filter(|entry| {
                            entry.source == ghidra_decompiler::program::FunctionSource::ImportStub
                        })
                        .take(crate::linkage::MAX_LINKAGE_LOCATIONS)
                        // The engine records `symbol` only when it differs
                        // from the loaded name, so plain C stubs carry their
                        // raw name in `name`. A name only selects a candidate;
                        // the stub's encoded slot must still match it.
                        .map(|entry| linkage::EngineStub {
                            address: entry.address,
                            raw: entry.symbol.as_deref().unwrap_or(&entry.name),
                        })
                        .collect();
                    self.linkage = Some(linkage::table(&self.snapshot, &self.info, pe, &stubs));
                }
                let table = self.linkage.as_ref().expect("table prepared");
                if (cursor != 0 && digest.is_none())
                    || digest
                        .as_ref()
                        .is_some_and(|digest| digest != &table.summary().digest)
                {
                    return Err("Linkage request does not match the current table".into());
                }
                Ok(Response::Linkage {
                    summary: table.summary().clone(),
                    page: table.page(cursor)?,
                })
            }
            Request::Open { .. } => Err("Open is handled by the worker.".into()),
        }
    }

    /// Replaces the inventory, journaling the change for the next publication.
    fn set_inventory(&mut self, functions: Vec<FunctionInfo>) {
        self.inventory.record(&self.info.functions, &functions);
        self.info.functions = functions;
        self.debug_inventory_digest = None;
        self.debug_program_digest = None;
    }

    /// [`function_list`] for `required` owners, certifying ordinary selections.
    fn rebuild_inventory(&mut self, required: &BTreeSet<u64>) -> Result<(), String> {
        let (functions, rejected) = select_functions(&self.program, &self.info, required)?;
        self.info.functions_truncated |= rejected;
        self.set_inventory(functions);
        // When every candidate fits, owner priority cannot change the selection.
        if required.is_empty() || !rejected {
            self.inventory.certify(&self.info.functions, !rejected);
        }
        Ok(())
    }

    /// Brings the inventory to `function_list(required)` after a batch. A
    /// certificate taken before the batch proves when no rebuild is needed:
    /// promoting already admitted owners leaves a greedy selection unchanged,
    /// and functions the batch named join a selection that admitted everything
    /// because discovery only names them within the same budgets.
    fn update_batch_inventory(
        &mut self,
        certificate: Option<bool>,
        required: &BTreeSet<u64>,
        discovered: Discovered,
    ) -> Result<(), String> {
        let owned = |functions: &[FunctionInfo]| {
            required
                .iter()
                .all(|&address| function_at(functions, address).is_some())
        };
        match certificate {
            Some(complete) if !discovered.opaque && discovered.added.is_empty() => {
                if complete || owned(&self.info.functions) {
                    crate::performance::event("inventory_reused", 0);
                    self.inventory.certify(&self.info.functions, complete);
                    Ok(())
                } else {
                    self.rebuild_inventory(required)
                }
            }
            Some(true) if !discovered.opaque => {
                crate::performance::event("inventory_extended", discovered.added.len() as u64);
                let mut added = discovered.added;
                added.sort_unstable_by_key(|function| function.address);
                for function in &added {
                    self.inventory.insert(function);
                }
                let current = std::mem::take(&mut self.info.functions);
                let mut merged = Vec::with_capacity(current.len() + added.len());
                let mut added = added.into_iter().peekable();
                for function in current {
                    while let Some(new) = added.next_if(|new| new.address < function.address) {
                        merged.push(new);
                    }
                    merged.push(function);
                }
                merged.extend(added);
                self.info.functions = merged;
                self.inventory.certify(&self.info.functions, true);
                Ok(())
            }
            _ => {
                // Establish the ordinary selection, which serves any owners it admits.
                let (functions, rejected) =
                    select_functions(&self.program, &self.info, &BTreeSet::new())?;
                if !rejected || owned(&functions) {
                    self.info.functions_truncated |= rejected;
                    self.set_inventory(functions);
                    self.inventory.certify(&self.info.functions, !rejected);
                    Ok(())
                } else {
                    self.rebuild_inventory(required)
                }
            }
        }
    }

    fn check_unpacked(&self) -> Result<(), String> {
        if self.upx_packed {
            return Err(crate::packing::UPX_ANALYSIS_ERROR.into());
        }
        Ok(())
    }

    fn discover_calls(
        &mut self,
        seeds: Option<&[u64]>,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<(CallAnalysis, Vec<DiscoveryOutcome>, Discovered), String> {
        let _discovery = crate::performance::span("discovery_decode_cfg_data_admission");
        self.prepare_pointers();
        // Adapted from Ghidra FunctionAnalyzer's established-call rule and its
        // fallthrough-call exclusion. See NOTICE and docs/analysis.md. Decode
        // through public pinned-engine APIs; never promote arbitrary constants.
        let mut report = CallAnalysis {
            partial: self.info.functions_truncated,
            ..Default::default()
        };
        let emit =
            |stage,
             report: &CallAnalysis,
             progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>| {
                progress(AnalysisProgress {
                    stage,
                    functions_examined: report.functions_examined,
                    decode_attempts: report.decode_attempts,
                })
            };
        emit(AnalysisStage::Seeds, &report, progress)?;
        let space = self
            .program
            .architecture()
            .manager
            .get_default_data_space()
            .ok_or("Missing default data space during reference analysis")?;
        if space.get_word_size() != 1 {
            return Err("Data references require a byte-addressed memory space".into());
        }
        let space_name = space.get_name().to_owned();
        let sinks = crate::data_analysis::address_sinks(
            &mut self.program,
            self.target.name,
            self.target.pointer_bytes as u32,
        )?;
        let mut data = crate::data_analysis::DataCollector::new(
            &self.info.sections,
            &space_name,
            self.target.pointer_bytes as u32,
        )
        .with_addresses(sinks);
        if self.target.name == "AArch64" {
            data = data.with_propagation();
        }
        // The published inventory plus functions this pass names. Borrowed, so a
        // batch does not copy every name of a large inventory.
        let published = &self.info.functions;
        let mut added = BTreeMap::new();
        let mut opaque = false;
        let known = |added: &BTreeMap<u64, String>, address| {
            added.contains_key(&address) || function_at(published, address).is_some()
        };
        report.partial |= seeds.is_none() && published.len() > MAX_ANALYSIS_FUNCTIONS;
        let mut name_bytes = published
            .iter()
            .map(|function| json_escaped_len(&function.name))
            .fold(0usize, usize::saturating_add)
            .min(MAX_FUNCTION_NAME_JSON_BYTES);
        let mut pending = VecDeque::new();
        let mut scheduled = BTreeSet::new();
        if let Some(seeds) = seeds {
            pending.extend(seeds.iter().copied());
            scheduled.extend(seeds.iter().copied());
        } else {
            if self.check_code(self.info.entry).is_ok() {
                scheduled.insert(self.info.entry);
                pending.push_back(self.info.entry);
            }
            for address in published
                .iter()
                .map(|function| function.address)
                .take(MAX_ANALYSIS_FUNCTIONS)
            {
                if scheduled.insert(address) {
                    pending.push_back(address);
                }
            }
        }
        let mut decoding = crate::performance::Accumulator::new("discovery_recovery_accumulated");
        let mut switches = SwitchBudget::new();
        let mut outcomes = Vec::new();
        let mut references = BTreeSet::new();
        emit(AnalysisStage::Calls, &report, progress)?;
        while let Some(address) = pending.pop_front() {
            if report.functions_examined == MAX_ANALYSIS_FUNCTIONS
                || report.decode_attempts == MAX_ANALYSIS_INSTRUCTIONS
                || seeds.is_some()
                    && MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts < MAX_INSTRUCTIONS
            {
                // Leave unstarted seeds pending. A batch limit is not a limit
                // on this function's own walk or cumulative session coverage.
                report.partial |= seeds.is_none();
                break;
            }
            report.functions_examined += 1;
            let available =
                (MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts).min(MAX_INSTRUCTIONS);
            let mut remaining = available;
            let sections = &self.info.sections;
            let pe_ranges = &self.pe_ranges;
            let mut walk = decoding.measure(|| {
                let mut walk = Walk::new(
                    &self.program,
                    sections,
                    address,
                    &self.no_return,
                    Some(&mut data),
                )?;
                walk.run(
                    &self.program,
                    &Bounds {
                        tail_entry: Some(&|a| {
                            self.pointers
                                .as_ref()
                                .is_some_and(|p| p.metadata.fdes.contains_key(&a))
                        }),
                        sections,
                        is_function: &|candidate| known(&added, candidate),
                        pe_ranges,
                    },
                    &mut remaining,
                    Some(&mut data),
                );
                Ok::<_, String>(walk)
            });
            // Switch recovery needs an engine function, so a walk that decoded
            // anything names its entry first. Failed decoding never does.
            let mut admitted = true;
            if let Ok(pending) = &walk
                && !pending.nodes.is_empty()
                && !known(&added, address)
            {
                admitted = admit_discovered(
                    &mut self.program,
                    published.len(),
                    &mut added,
                    &mut name_bytes,
                    address,
                )?;
            }
            if admitted
                && !self.upx_packed
                && let Ok(pending) = &mut walk
                && pending.switches(&mut self.program, sections, &mut switches)
            {
                decoding.measure(|| {
                    pending.run(
                        &self.program,
                        &Bounds {
                            tail_entry: Some(&|a| {
                                self.pointers
                                    .as_ref()
                                    .is_some_and(|p| p.metadata.fdes.contains_key(&a))
                            }),
                            sections,
                            is_function: &|candidate| known(&added, candidate),
                            pe_ranges,
                        },
                        &mut remaining,
                        Some(&mut data),
                    )
                });
            }
            let recovered = walk.and_then(|walk| walk.finish(Some(&mut data)));
            report.decode_attempts += available - remaining;
            match recovered {
                Ok(recovered) => {
                    if admitted {
                        self.coverage.add(address, &recovered.intervals);
                    }
                    report.partial |= recovered.partial;
                    outcomes.push(DiscoveryOutcome {
                        address,
                        status: if recovered.partial {
                            DiscoveryStatus::PartialByOwnLimit
                        } else {
                            DiscoveryStatus::Done
                        },
                    });
                    if !admitted {
                        report.partial = true;
                        continue;
                    }
                    for (call, fallthrough) in recovered.calls {
                        if references.len()
                            + report.unresolved_calls
                            + report.skipped_fallthrough_calls
                            >= MAX_CALL_REFERENCES
                        {
                            report.partial = true;
                            break;
                        }
                        let Some(target) = call
                            .target
                            .filter(|target| self.check_code(*target).is_ok())
                        else {
                            report.unresolved_calls += 1;
                            report.partial = true;
                            continue;
                        };
                        if target == fallthrough {
                            report.skipped_fallthrough_calls += 1;
                            continue;
                        }
                        let reference = CallReference {
                            caller: address,
                            address: call.address,
                            target,
                        };
                        if references.len() == MAX_CALL_REFERENCES
                            && !references.contains(&reference)
                        {
                            report.partial = true;
                            continue;
                        }
                        references.insert(reference);
                        if seeds.is_some() {
                            // Confirmed targets are queued by the parent for a later batch.
                        } else if scheduled.len() < MAX_FUNCTIONS && scheduled.insert(target) {
                            pending.push_back(target);
                        } else if !scheduled.contains(&target) {
                            report.partial = true;
                        }
                    }
                }
                Err(_) => {
                    report.failed_functions += 1;
                    outcomes.push(DiscoveryOutcome {
                        address,
                        status: DiscoveryStatus::Failed,
                    });
                    report.partial = true;
                }
            }
            emit(AnalysisStage::Calls, &report, progress)?;
        }
        report.references = references.into_iter().collect();
        let (data, addresses) = data.finish_all();
        report.data = Some(data);
        report.addresses = addresses.map(Box::new);
        if self.target.name == "AArch64" && !self.pe_imports.is_empty() {
            let targets: BTreeSet<_> = report
                .references
                .iter()
                .map(|reference| reference.target)
                .chain(if seeds.is_some() {
                    outcomes.iter().map(|o| o.address).collect::<Vec<_>>()
                } else {
                    published
                        .iter()
                        .map(|function| function.address)
                        .chain(added.keys().copied())
                        .collect()
                })
                .collect();
            report.partial |= targets.len() > crate::pe_symbols::MAX_THUNK_TARGETS;
            let targets = targets
                .into_iter()
                .take(crate::pe_symbols::MAX_THUNK_TARGETS)
                .collect();
            let mut remaining = MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts;
            // Import promotion renames engine functions without enumerating them.
            opaque = true;
            report.partial |= !crate::pe_symbols::register_aarch64_import_thunks_budgeted(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
                &mut remaining,
            )?;
            report.decode_attempts = MAX_ANALYSIS_INSTRUCTIONS - remaining;
        }
        emit(AnalysisStage::Publish, &report, progress)?;
        let added = added
            .into_iter()
            .map(|(address, name)| FunctionInfo { address, name })
            .collect();
        Ok((report, outcomes, Discovered { added, opaque }))
    }

    fn check_code(&self, address: u64) -> Result<(), String> {
        if !address.is_multiple_of(self.target.instruction_alignment) {
            return Err(format!(
                "{} instructions require {}-byte aligned addresses.",
                self.target.name, self.target.instruction_alignment
            ));
        }
        if executable(
            &self.info.sections,
            address,
            self.target.instruction_alignment as usize,
        ) {
            Ok(())
        } else {
            Err(format!(
                "{address:#x} is outside file-backed executable sections."
            ))
        }
    }

    fn resolve_import_thunks(&mut self, entry: u64) -> Result<(), String> {
        if self.pe_imports.is_empty() {
            return Ok(());
        }
        let mut pending = VecDeque::from([entry]);
        let mut visited = BTreeSet::new();
        let mut targets = BTreeSet::from([entry]);
        let mut no_return_targets = BTreeSet::new();
        // The decompiler can follow a tail branch into another known function.
        // Resolve imports from those exact CFG call targets as well, with a
        // fixed work budget. Never treat arbitrary byte matches as code entries.
        while visited.len() < 8 {
            let Some(address) = pending.pop_front() else {
                break;
            };
            if !visited.insert(address) {
                continue;
            }
            let mut remaining = MAX_INSTRUCTIONS;
            let Ok(recovered) = recover_graph_budgeted(
                &self.program,
                &Bounds {
                    tail_entry: None,
                    sections: &self.info.sections,
                    is_function: &|pc| function_at(&self.info.functions, pc).is_some(),
                    pe_ranges: &self.pe_ranges,
                },
                address,
                &mut remaining,
                &self.no_return,
                None,
            ) else {
                continue;
            };
            // Naming uses every bounded decoded call, including those omitted
            // from the displayed graph by its separate block limit.
            no_return_targets.extend(
                recovered
                    .calls
                    .iter()
                    .map(|(call, _)| call)
                    .filter(|call| call.no_return.is_some())
                    .filter_map(|call| call.target),
            );
            for target in recovered.calls.iter().filter_map(|(call, _)| call.target) {
                if targets.len() < crate::pe_symbols::MAX_THUNK_TARGETS {
                    targets.insert(target);
                }
            }
            let view = recovered.view;
            let blocks: BTreeSet<_> = view.blocks.iter().map(|block| block.address).collect();
            for target in view.edges.iter().filter_map(|edge| edge.target) {
                if !blocks.contains(&target)
                    && self
                        .pe_ranges
                        .binary_search_by_key(&target, |range| range.0)
                        .is_ok()
                    && !visited.contains(&target)
                {
                    pending.push_back(target);
                }
            }
        }
        if self.target.name == "AArch64" {
            crate::pe_symbols::register_aarch64_import_thunks(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
            )?;
        } else {
            crate::pe_symbols::register_import_thunks(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
                self.target.pointer_bytes,
            )?;
        }
        // An unmarked thunk only keeps the decompiler's ordinary call flow.
        crate::no_return::mark_targets(&mut self.program, no_return_targets);
        Ok(())
    }

    fn synchronize_function_name(&mut self, address: u64, name: &str) -> Result<(), String> {
        // In the pinned engine, Program::set_function_name updates the symbol but
        // leaves an already materialized Funcdata and its local scope unchanged.
        // Update those public engine objects too, so definitions and call sites
        // use the same name. This is a model/cache update, never a text rewrite.
        let architecture = self.program.architecture();
        let space = architecture
            .manager
            .get_default_code_space()
            .ok_or("Missing default code space while renaming function")?;
        let symbol = {
            let table = architecture
                .symboltab
                .as_deref()
                .ok_or("Missing symbol table while renaming function")?;
            let global = table
                .get_global_scope()
                .ok_or("Missing global scope while renaming function")?;
            let symbol = table
                .scope_query_function(global, &Address::new(space, address))
                .ok_or("Renamed function symbol was not found")?;
            let entry = table
                .symbol_get_first_whole_map(symbol)
                .map_err(engine_error)?;
            if table.entry(entry).get_addr().get_offset() != address {
                return Err("Renaming requires the start address of a function.".into());
            }
            symbol
        };
        architecture
            .with_function(symbol, |function, architecture| {
                architecture.clear_analysis(function);
                function.name = name.to_string();
                function.display_name = name.to_string();
                if let Some(scope) = function.get_scope_local() {
                    let local = architecture.symboltab_mut()?.scope_mut(scope);
                    local.name = name.to_string();
                    local.display_name = name.to_string();
                }
                Ok(())
            })
            .map_err(engine_error)
    }

    fn strings(&mut self, minimum_length: usize) -> Result<Response, String> {
        scan_strings(&self.snapshot, &self.info.sections, minimum_length)
    }

    fn crypto(&mut self) -> Result<Response, String> {
        let mut matches = Vec::new();
        let mut scanned = 0u64;
        let mut truncated = false;
        // Overlap preserves signatures that straddle chunk boundaries.
        const OVERLAP: usize = crate::crypto::MAX_SIGNATURE_LEN - 1;
        for section in &self.info.sections {
            let size = section.file_size.min(MAX_SCAN_BYTES - scanned);
            if size < section.file_size {
                truncated = true;
            }
            if size == 0 {
                continue;
            }
            let mut offset = 0u64;
            while offset < size {
                let count = (size - offset).min(SCAN_CHUNK as u64) as usize;
                let overlap_start = offset.saturating_sub(OVERLAP as u64);
                let base = section.address + overlap_start;
                let file_start = (section.file_offset + overlap_start) as usize;
                let file_end = (section.file_offset + offset + count as u64) as usize;
                let chunk = self
                    .snapshot
                    .get(file_start..file_end)
                    .ok_or("Section extends past immutable image snapshot")?;
                let chunk_limit = MAX_CRYPTO_RESULTS.min(crate::crypto::MAX_MATCHES);
                let found = crate::crypto::scan_region(chunk, base, chunk_limit);
                let chunk_limited = found.len() >= chunk_limit;
                // Matches fully contained in the preceding overlap were already reported.
                for hit in found {
                    if offset == 0
                        || hit.address.saturating_add(hit.length as u64) > section.address + offset
                    {
                        matches.push(hit);
                    }
                }
                if matches.len() >= MAX_CRYPTO_RESULTS || chunk_limited {
                    matches.truncate(MAX_CRYPTO_RESULTS);
                    return Ok(Response::Crypto {
                        matches,
                        truncated: true,
                    });
                }
                offset += count as u64;
            }
            scanned += size;
        }
        matches.sort_by_key(|m| m.address);
        Ok(Response::Crypto { matches, truncated })
    }
}

/// Names a function discovered at `address` within the shared inventory
/// count and escaped-name budgets. Returns whether it was admitted.
fn admit_discovered(
    program: &mut Program,
    published: usize,
    added: &mut BTreeMap<u64, String>,
    name_bytes: &mut usize,
    address: u64,
) -> Result<bool, String> {
    let name = format!("FUN_{address:08x}");
    let bytes = json_escaped_len(&name);
    if published + added.len() >= MAX_FUNCTIONS
        || bytes > MAX_FUNCTION_NAME_JSON_BYTES - *name_bytes
    {
        return Ok(false);
    }
    program
        .set_function_name(address, &name)
        .map_err(engine_error)?;
    *name_bytes += bytes;
    added.insert(address, name);
    Ok(true)
}

/// Names `main` when a stripped ELF executable's startup code passes it to
/// the imported `__libc_start_main`, then republishes the inventory. Existing
/// functions and names always win; a failed recognition leaves the inventory
/// unchanged. Returns whether republishing rejected any inventory candidate,
/// which is also recorded as truncation.
fn recover_elf_main(
    program: &mut Program,
    info: &mut BinaryInfo,
    target: &crate::architecture::Target,
    bytes: &[u8],
) -> Result<bool, String> {
    let _span = crate::performance::span("open_elf_startup");
    let known = |address| function_at(&info.functions, address).is_some();
    if info
        .functions
        .iter()
        .any(|function| function.name == "main")
        || info.functions.len() >= MAX_FUNCTIONS
    {
        return Ok(false);
    }
    let recovery = match crate::elf_startup::recognize(
        program,
        bytes,
        target.name,
        info.entry,
        target.pointer_bytes as u32,
        |address| crate::call_analysis::code_address(info, address) && !known(address),
    ) {
        Ok(recovery) => recovery,
        Err(crate::elf_startup::Miss::Exhausted) => {
            warning(
                &mut info.warnings,
                "ELF startup recognition stopped at its work limit; main was not recovered.",
            );
            return Ok(false);
        }
        Err(_) => return Ok(false),
    };
    // A global symbol already named main (for example a data label) keeps
    // its name; the callback stays an unnamed discovery candidate instead.
    let occupied = program
        .data_symbols()
        .map_err(engine_error)?
        .iter()
        .any(|symbol| symbol.name == "main");
    if occupied || program.set_function_name(recovery.main, "main").is_err() {
        return Ok(false);
    }
    // The engine cannot forget the new function, so a publication that omits
    // it is merely incomplete rather than an open failure.
    let (functions, rejected) = select_functions(program, info, &BTreeSet::from([recovery.main]))?;
    info.functions_truncated |= rejected;
    if function_at(&functions, recovery.main).is_none_or(|function| function.name != "main") {
        warning(
            &mut info.warnings,
            "A recovered ELF startup callback did not fit the function list; main was not published.",
        );
        info.functions_truncated = true;
        return Ok(true);
    }
    info.functions = functions;
    warning(
        &mut info.warnings,
        format!(
            "Recovered main at {:#x} from the first argument passed to the imported __libc_start_main at {:#x}. This name is analysis-derived, not an ELF symbol.",
            recovery.main, recovery.call
        ),
    );
    Ok(rejected)
}

/// Publishes the engine inventory within the shared count and escaped-name
/// budgets. The entry and `required` addresses (owners of evidence in the same
/// reply) are admitted first; remaining entries follow engine address order.
#[cfg(test)]
fn function_list(
    program: &Program,
    info: &mut BinaryInfo,
    required: &BTreeSet<u64>,
) -> Result<Vec<FunctionInfo>, String> {
    let (functions, rejected) = select_functions(program, info, required)?;
    info.functions_truncated |= rejected;
    Ok(functions)
}

/// The published inventory for the engine's functions: the entry first, then
/// `required` owners, then the rest, each admitted while the count and name
/// budgets allow. Also reports whether any candidate was rejected.
fn select_functions(
    program: &Program,
    info: &BinaryInfo,
    required: &BTreeSet<u64>,
) -> Result<(Vec<FunctionInfo>, bool), String> {
    let _inventory = crate::performance::span("inventory_rebuild");
    let alignment = crate::architecture::instruction_alignment(program.language_id());
    let code_entry = |address: u64| {
        address.is_multiple_of(alignment) && executable(&info.sections, address, alignment as usize)
    };
    let entries: Vec<_> = program
        .functions()
        .map_err(engine_error)?
        .into_iter()
        .filter(|f| code_entry(f.address))
        .map(|f| FunctionInfo {
            address: f.address,
            name: bounded_name(&f.name),
        })
        .collect();
    let mut admitted = BTreeMap::new();
    let mut name_bytes = 0usize;
    let mut truncated = false;
    let mut admit = |function: FunctionInfo, admitted: &mut BTreeMap<u64, String>| {
        if admitted.contains_key(&function.address) {
            return;
        }
        let bytes = json_escaped_len(&function.name);
        if admitted.len() < MAX_FUNCTIONS && bytes <= MAX_FUNCTION_NAME_JSON_BYTES - name_bytes {
            name_bytes += bytes;
            admitted.insert(function.address, function.name);
        } else {
            truncated = true;
        }
    };
    if code_entry(info.entry) {
        let name = entries
            .iter()
            .find(|f| f.address == info.entry)
            .map_or_else(|| "entry".into(), |f| f.name.clone());
        admit(
            FunctionInfo {
                address: info.entry,
                name,
            },
            &mut admitted,
        );
    }
    let (first, rest): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|f| required.contains(&f.address));
    for function in first.into_iter().chain(rest) {
        admit(function, &mut admitted);
    }
    Ok((
        admitted
            .into_iter()
            .map(|(address, name)| FunctionInfo { address, name })
            .collect(),
        truncated,
    ))
}

/// The demangler's view of a validated container. Only PE selects the
/// bounded MSVC backend for `?`-decorated names.
fn symbol_format(container: &str) -> crate::symbol_names::SymbolFormat {
    match container {
        "Mach-O" => crate::symbol_names::SymbolFormat::MachO,
        "PE" => crate::symbol_names::SymbolFormat::Pe,
        _ => crate::symbol_names::SymbolFormat::Other,
    }
}

/// The open-time symbol-name table for the engine's code entries. Raw names
/// are the loader symbols the engine recorded or exact PE metadata names; the
/// engine's own (possibly demangled, shortened or suffixed) names never are.
fn symbol_table(
    program: &Program,
    info: &BinaryInfo,
    pe_names: &BTreeMap<u64, String>,
) -> Result<crate::symbol_names::SymbolTable, String> {
    let _building = crate::performance::span("open_symbol_names");
    let alignment = crate::architecture::instruction_alignment(program.language_id());
    let format = symbol_format(&info.format);
    let entries = program.functions().map_err(engine_error)?;
    Ok(crate::symbol_names::SymbolTable::build(
        entries
            .iter()
            .filter(|f| {
                f.address.is_multiple_of(alignment)
                    && executable(&info.sections, f.address, alignment as usize)
            })
            .map(|f| crate::symbol_names::SymbolSource {
                address: f.address,
                raw: pe_names
                    .get(&f.address)
                    .or(f.symbol.as_ref())
                    .unwrap_or(&f.name),
                engine: &f.name,
            }),
        format,
    ))
}

fn bounded_name(name: &str) -> String {
    let mut end = name.len().min(MAX_FUNCTION_NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

fn read_virtual(
    snapshot: &[u8],
    sections: &[SectionInfo],
    address: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    if length > MAX_BYTES {
        return Err("Byte selections are limited to 64 KiB.".into());
    }
    address
        .checked_add(length as u64)
        .ok_or("Byte range overflows address space")?;
    let mut output = vec![0; length];
    let mut written = 0;
    while written < length {
        let current = address + written as u64;
        let section = sections
            .iter()
            .find(|s| mapped(s, current))
            .ok_or_else(|| format!("Unmapped address {current:#x}; selection crosses a gap."))?;
        let offset = current - section.address;
        let count = (section.size - offset).min((length - written) as u64) as usize;
        let backed = section.file_size.saturating_sub(offset).min(count as u64) as usize;
        if backed > 0 {
            let start = (section.file_offset + offset) as usize;
            let source = snapshot
                .get(start..start + backed)
                .ok_or("Section extends past immutable image snapshot")?;
            output[written..written + backed].copy_from_slice(source);
        }
        // Mapped uninitialized tails are zero-filled, unlike unmapped gaps.
        written += count;
    }
    Ok(output)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::strings::StringRun;
    use super::*;
    use crate::semantic::TokenKind;
    use ghidra_decompiler::opcodes::OpCode;
    use ghidra_decompiler::program::InstructionPcode;

    #[test]
    fn many_macho_segments_and_sections_use_bounded_indexed_containment() {
        fn image(count: usize) -> Vec<u8> {
            let offset = 32 + count * 152;
            let mut bytes = vec![0; offset + count * 4];
            let p32 =
                |b: &mut [u8], at, value: u32| b[at..at + 4].copy_from_slice(&value.to_le_bytes());
            let p64 =
                |b: &mut [u8], at, value: u64| b[at..at + 8].copy_from_slice(&value.to_le_bytes());
            p32(&mut bytes, 0, 0xfeedfacf);
            p32(&mut bytes, 4, 0x100000c);
            p32(&mut bytes, 12, 2);
            p32(&mut bytes, 16, count as u32);
            p32(&mut bytes, 20, (count * 152) as u32);
            for index in 0..count {
                let at = 32 + index * 152;
                let address = 0x100001000 + index as u64 * 4;
                p32(&mut bytes, at, 0x19);
                p32(&mut bytes, at + 4, 152);
                bytes[at + 8..at + 14].copy_from_slice(b"__TEXT");
                p64(&mut bytes, at + 24, address);
                p64(&mut bytes, at + 32, 4);
                p64(&mut bytes, at + 40, (offset + index * 4) as u64);
                p64(&mut bytes, at + 48, 4);
                p32(&mut bytes, at + 56, 5);
                p32(&mut bytes, at + 60, 5);
                p32(&mut bytes, at + 64, 1);
                bytes[at + 72..at + 79].copy_from_slice(b"__stubs");
                bytes[at + 88..at + 94].copy_from_slice(b"__TEXT");
                p64(&mut bytes, at + 104, address);
                p64(&mut bytes, at + 112, 4);
                p32(&mut bytes, at + 120, (offset + index * 4) as u32);
                p32(&mut bytes, at + 136, 0x80000408);
                p32(&mut bytes, at + 144, 4);
            }
            bytes
        }
        let bytes = image(MAX_SECTIONS);
        let started = std::time::Instant::now();
        let info = metadata(Path::new("many-macho"), &bytes).unwrap();
        assert_eq!(info.sections.len(), MAX_SECTIONS);
        assert!(info.sections.iter().all(|section| section.executable));
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert!(
            metadata(Path::new("over-budget-macho"), &image(MAX_SECTIONS + 1))
                .unwrap_err()
                .contains("4096-segment budget")
        );
        // Adjacent segments are not a single containing segment.
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let segments = MachoExecutableSegments::new(&object).unwrap();
        assert!(!segments.contains(b"__TEXT", 0x100001000, 8));
    }

    fn raw_aarch64(bytes: Vec<u8>) -> LoadedProgram {
        let mut image = elf_fixture();
        image[18..20].copy_from_slice(&183u16.to_le_bytes());
        let (mut info, target) = metadata_with_target(Path::new("synthetic"), &image).unwrap();
        info.entry = 0x1000;
        info.sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        LoadedProgram {
            macho_legacy: None,
            program: Program::from_raw_bytes(bytes.clone(), target.language, 0x1000).unwrap(),
            target,
            snapshot: Arc::from(bytes),
            info,
            pe_ranges: vec![],
            pe_imports: BTreeMap::new(),
            upx_packed: false,
            inventory: Default::default(),
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::default(),
            symbol_names: Arc::default(),
            linkage: None,
            search: None,
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
            debug: Default::default(),
            debug_calls: VecDeque::new(),
            debug_large: BTreeSet::new(),
            debug_skip: BTreeSet::new(),
            debug_failed: BTreeSet::new(),
            debug_large_journal: None,
            results: ResultCache::default(),
            result_epoch: 0,
            pending_debug: None,
            debug_nonce: 0,
            debug_inventory_digest: None,
            debug_program_digest: None,
            debug_long_names: BTreeMap::new(),
            debug_long_names_complete: true,
        }
    }

    fn raw_x86(bytes: Vec<u8>) -> LoadedProgram {
        let mut loaded = raw_aarch64(bytes.clone());
        loaded.target = crate::architecture::Target {
            name: "x86-64",
            language: "x86:LE:64:default:gcc",
            pointer_bytes: 8,
            instruction_alignment: 1,
        };
        loaded.info.architecture = "x86-64".into();
        loaded.program = Program::from_raw_bytes(bytes, loaded.target.language, 0x1000).unwrap();
        loaded
    }

    fn bulk_functions(loaded: &mut LoadedProgram, names: impl Iterator<Item = (u64, String)>) {
        let metadata = crate::pe::PeMetadata {
            functions: names.collect(),
            ..Default::default()
        };
        crate::pe_symbols::register(&mut loaded.program, &metadata, 8).unwrap();
    }

    #[test]
    fn cleanup_after_action_error_or_panic_restores_rendering_and_function_scope() {
        use ghidra_decompiler::{
            action::{Action, ActionBase, ActionGroupList},
            architecture::Architecture,
            error::{Error, Result},
            funcdata::Funcdata,
        };
        struct Failure {
            base: ActionBase,
            panic: bool,
        }
        impl Action for Failure {
            fn base(&self) -> &ActionBase {
                &self.base
            }
            fn base_mut(&mut self) -> &mut ActionBase {
                &mut self.base
            }
            fn clone_action(&self, _: &ActionGroupList) -> Option<Box<dyn Action>> {
                None
            }
            fn apply(&mut self, _: &mut Funcdata, _: &mut Architecture) -> Result<i32> {
                if self.panic {
                    panic!("injected action panic");
                }
                Err(Error::Lowlevel("injected action error".into()))
            }
        }
        let mut loaded = raw_x86(vec![0x89, 0xf8, 0xc3]);
        loaded
            .program
            .set_function_name(0x1000, "identity")
            .unwrap();
        let baseline =
            crate::decompile::render(&mut loaded.program, 0x1000, &loaded.info.sections).unwrap();
        for panic in [false, true] {
            let architecture = loaded.program.architecture();
            let name = architecture.allacts.currentact.clone().unwrap();
            let original = architecture
                .allacts
                .actionmap
                .insert(
                    name.clone(),
                    Box::new(Failure {
                        base: ActionBase::new(0, "injected", "base"),
                        panic,
                    }),
                )
                .unwrap();
            assert!(
                crate::decompile::render(&mut loaded.program, 0x1000, &loaded.info.sections)
                    .is_err()
            );
            let architecture = loaded.program.architecture();
            let returned = architecture
                .allacts
                .actionmap
                .insert(name, original)
                .unwrap();
            assert_eq!(returned.base().name, "injected");
            let rendered =
                crate::decompile::render(&mut loaded.program, 0x1000, &loaded.info.sections)
                    .unwrap();
            assert_eq!(rendered.0, baseline.0);
            assert_eq!(
                serde_json::to_value(rendered.1).unwrap(),
                serde_json::to_value(&baseline.1).unwrap()
            );
            assert_eq!(
                serde_json::to_value(rendered.2).unwrap(),
                serde_json::to_value(&baseline.2).unwrap()
            );
        }
    }

    #[test]
    fn printing_failure_clears_expression_ids_before_reusing_banks() {
        let mut loaded = raw_x86(vec![0x89, 0xf8, 0x83, 0xc0, 0x01, 0xc3, 0x89, 0xf8, 0xc3]);
        loaded
            .program
            .set_function_name(0x1000, "increment")
            .unwrap();
        loaded
            .program
            .set_function_name(0x1006, "identity")
            .unwrap();
        let baseline: Vec<_> = [0x1000, 0x1006]
            .into_iter()
            .map(|address| {
                serde_json::to_value(
                    crate::decompile::render(&mut loaded.program, address, &loaded.info.sections)
                        .unwrap(),
                )
                .unwrap()
            })
            .collect();
        for mode in [1, 2] {
            crate::decompile::PRINT_FAILURE.set(mode);
            assert!(
                crate::decompile::render(&mut loaded.program, 0x1000, &loaded.info.sections)
                    .is_err()
            );
            assert_eq!(crate::decompile::PRINT_FAILURE.get(), 0);
            let architecture = loaded.program.architecture();
            let printer = architecture.printlist[architecture.print].as_ref().unwrap();
            assert!(printer.base().revpol.is_empty());
            assert!(printer.base().nodepend.is_empty());
            for (index, address) in [0x1000, 0x1006].into_iter().enumerate() {
                let output =
                    crate::decompile::render(&mut loaded.program, address, &loaded.info.sections)
                        .unwrap();
                assert_eq!(serde_json::to_value(output).unwrap(), baseline[index]);
            }
        }
    }

    #[test]
    fn repeated_engine_analysis_releases_tombstones_and_preserves_output() {
        use ghidra_decompiler::address::Address;
        let mut loaded = raw_x86(vec![0x89, 0xf8, 0x83, 0xc0, 0x01, 0xc3]);
        loaded
            .program
            .set_function_name(0x1000, "increment")
            .unwrap();
        let mut expected = None;
        let mut first_id = None;
        for _ in 0..32 {
            let output = loaded
                .handle(Request::Decompile { address: 0x1000 })
                .unwrap();
            let value = serde_json::to_value(output).unwrap();
            if let Some(expected) = &expected {
                assert_eq!(&value, expected);
            } else {
                expected = Some(value);
            }
            let architecture = loaded.program.architecture();
            let space = architecture.manager.get_default_code_space().unwrap();
            let address = Address::new(space.clone(), 0x1000);
            let table = architecture.symboltab_ref().unwrap();
            let symbol = table
                .scope_query_function(table.get_global_scope().unwrap(), &address)
                .unwrap();
            architecture
                .with_function(symbol, |function, architecture| {
                    let scope = function.localmap;
                    function.follow_flow(
                        &Address::new(space.clone(), 0),
                        &Address::new(space.clone(), space.get_highest()),
                        architecture,
                    )?;
                    let id = function.obank.begin_alive().unwrap();
                    if let Some(first) = first_id {
                        assert_eq!(id, first, "arena tombstones accumulated");
                    } else {
                        first_id = Some(id);
                    }
                    crate::engine_cleanup::clear(function, architecture);
                    assert_eq!(function.localmap, scope);
                    assert_eq!(function.name, "increment");
                    Ok(())
                })
                .unwrap();
        }
    }

    #[test]
    fn override_cleanup_keeps_bank_identity_and_override_targets() {
        use ghidra_decompiler::{address::Address, jumptable::JumpTable};
        let mut loaded = raw_x86(vec![0xc3]);
        loaded.program.set_function_name(0x1000, "guarded").unwrap();
        let architecture = loaded.program.architecture();
        let address = Address::new(
            architecture.manager.get_default_code_space().unwrap(),
            0x1000,
        );
        let table = architecture.symboltab_ref().unwrap();
        let symbol = table
            .scope_query_function(table.get_global_scope().unwrap(), &address)
            .unwrap();
        architecture
            .with_function(symbol, |function, architecture| {
                function.follow_flow(
                    &Address::new(address.get_space().unwrap().clone(), 0),
                    &Address::new(address.get_space().unwrap().clone(), u64::MAX),
                    architecture,
                )?;
                let old = function.obank.begin_alive().expect("flow produced p-code");
                let mut table = JumpTable::new(address.clone());
                table.set_indirect_op(function, old);
                table.set_override(std::slice::from_ref(&address), &address, 0, 0)?;
                let id = function.jumptables.alloc(table);
                function.jumpvec.push(id);
                crate::engine_cleanup::clear(function, architecture);
                assert_eq!(function.jumpvec, vec![id]);
                assert!(function.jump_table(id).is_override());
                let new = function.new_op(0, &address);
                assert_ne!(old, new, "override bank IDs must not be reissued");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn demangled_leaf_names_are_display_only_never_no_return_evidence() {
        let mut loaded = raw_x86(vec![0xc3; 0x40]);
        bulk_functions(
            &mut loaded,
            [
                (0x1000, "_Z4exitv".into()),
                (0x1010, "_RNvC4demo4exit".into()),
                (0x1020, "exit".into()),
            ]
            .into_iter(),
        );
        let index = crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        );
        assert_eq!(
            index.targets().iter().copied().collect::<Vec<_>>(),
            [0x1020]
        );
        let table = symbol_table(&loaded.program, &loaded.info, &BTreeMap::new()).unwrap();
        let display = |address| {
            table
                .display_for(
                    address,
                    &loaded
                        .program
                        .functions()
                        .unwrap()
                        .into_iter()
                        .find(|f| f.address == address)
                        .unwrap()
                        .name,
                )
                .map(str::to_owned)
        };
        assert_eq!(display(0x1000).as_deref(), Some("exit"));
        assert_eq!(display(0x1010).as_deref(), Some("demo::exit"));
        assert_eq!(display(0x1020), None);
    }

    #[test]
    fn pseudocode_prints_display_names_only_for_verified_tokens_and_labels_win() {
        // CALL 0x1020; RET at the caller, RET at the callee.
        let mut bytes = vec![0xe8, 0x1b, 0, 0, 0, 0xc3];
        bytes.resize(0x21, 0xc3);
        let mut loaded = raw_x86(bytes);
        bulk_functions(
            &mut loaded,
            [
                (0x1000, "caller".into()),
                (0x1020, "_ZN4demo6calleeEv".into()),
            ]
            .into_iter(),
        );
        loaded.symbol_names =
            Arc::new(symbol_table(&loaded.program, &loaded.info, &BTreeMap::new()).unwrap());
        let decompile = |loaded: &mut LoadedProgram, address| {
            let Response::Decompiled {
                text, semantics, ..
            } = loaded.handle(Request::Decompile { address }).unwrap()
            else {
                panic!("decompilation");
            };
            (text, semantics)
        };
        let (text, semantics) = decompile(&mut loaded, 0x1000);
        assert!(!text.contains("_ZN4demo6calleeEv"), "{text}");
        let calls: Vec<_> = semantics
            .tokens
            .iter()
            .filter(|token| matches!(token.kind, TokenKind::Call { target: 0x1020 }))
            .map(|token| &text[token.start..token.end])
            .collect();
        assert_eq!(calls, ["demo::callee"], "{text}");
        let (text, _) = decompile(&mut loaded, 0x1020);
        assert!(text.contains("demo::callee("), "{text}");
        // An analyst rename replaces the engine name, so it is never substituted.
        loaded
            .handle(Request::Rename {
                address: 0x1020,
                name: "label_name".into(),
            })
            .unwrap();
        let (text, semantics) = decompile(&mut loaded, 0x1000);
        assert!(!text.contains("demo::callee"), "{text}");
        assert!(semantics.tokens.iter().any(|token| {
            matches!(token.kind, TokenKind::Call { target: 0x1020 })
                && &text[token.start..token.end] == "label_name"
        }));
    }

    #[test]
    fn no_return_calls_preserve_other_paths_and_ignore_later_renames() {
        // JNE 0x1007; CALL 0x1020; RET. The RET is reachable by the branch,
        // even though the call itself cannot fall through to it.
        let mut bytes = vec![0x75, 5, 0xe8, 0x19, 0, 0, 0, 0xc3];
        bytes.resize(0x21, 0xc3);
        let mut loaded = raw_x86(bytes);
        bulk_functions(&mut loaded, [(0x1020, "exit".into())].into_iter());
        loaded.no_return = Arc::new(crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        ));
        loaded
            .synchronize_function_name(0x1020, "renamed_exit")
            .unwrap();
        let view = loaded.graph(0x1000).unwrap();
        assert_eq!(view.calls[0].no_return, Some(NoReturnEvidence::NamedTarget));
        let call_block = view
            .blocks
            .iter()
            .find(|b| b.instructions.last().unwrap().address == 0x1002)
            .unwrap();
        assert!(
            !view
                .edges
                .iter()
                .any(|edge| edge.source == call_block.address)
        );
        assert!(view.blocks.iter().any(|b| b.address == 0x1007));

        // Renaming a returning function to a listed name does not create evidence.
        let mut loaded = raw_x86(vec![0xe8, 1, 0, 0, 0, 0xc3, 0xc3]);
        bulk_functions(&mut loaded, [(0x1006, "helper".into())].into_iter());
        loaded.no_return = Arc::new(crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        ));
        loaded.synchronize_function_name(0x1006, "abort").unwrap();
        let view = loaded.graph(0x1000).unwrap();
        assert_eq!(view.calls[0].no_return, None);
        assert!(
            view.blocks
                .iter()
                .flat_map(|b| &b.instructions)
                .any(|i| i.address == 0x1005)
        );
    }

    #[test]
    fn no_return_does_not_override_call_to_own_fallthrough_or_internal_flow() {
        // The engine lowers a literal CALL-next to a branch. Use the normal
        // CALL p-code form with an explicit next-instruction target to cover
        // the flow guard independently of that SLEIGH optimization.
        let loaded = raw_x86(vec![0xe8, 0x1b, 0, 0, 0, 0xc3]);
        let mut code = loaded.program.pcode(0x1000, 1).unwrap().pop().unwrap();
        code.operations
            .iter_mut()
            .find(|op| op.opcode == OpCode::Call)
            .unwrap()
            .inputs[0]
            .offset = 0x1005;
        let mut calls = Vec::new();
        let mut warnings = Vec::new();
        let (edges, terminal, _) = flow(&code, 0x1005, &mut calls, &mut warnings, &mut |_, _| {
            Some(NoReturnEvidence::NamedTarget)
        });
        assert!(!terminal);
        assert_eq!(edges, [(Some(0x1005), EdgeKind::Branch)]);
        assert_eq!(calls[0].no_return, None);
        // Force a non-fallthrough target and internal p-code flow. Neither
        // an address match nor a prototype may override ambiguous machine flow.
        let call = code
            .operations
            .iter_mut()
            .find(|op| op.opcode == OpCode::Call)
            .unwrap();
        call.inputs[0].offset = 0x1020;
        code.operations
            .push(ghidra_decompiler::program::PcodeOperation {
                opcode: OpCode::Cbranch,
                output: None,
                inputs: vec![ghidra_decompiler::program::PcodeVarnode {
                    space: "const".into(),
                    offset: 1,
                    size: 8,
                }],
                space: None,
            });
        calls.clear();
        let (edges, terminal, _) = flow(&code, 0x1005, &mut calls, &mut warnings, &mut |_, _| {
            Some(NoReturnEvidence::NamedTarget)
        });
        assert!(terminal && calls.is_empty());
        assert_eq!(edges, [(None, EdgeKind::Unknown)]);
    }

    #[test]
    fn no_return_terminal_can_establish_a_pattern_candidate() {
        let mut bytes = vec![0xe8, 0x1b, 0, 0, 0];
        bytes.resize(0x21, 0xc3);
        let mut loaded = raw_x86(bytes);
        bulk_functions(&mut loaded, [(0x1020, "abort".into())].into_iter());
        let index = Arc::new(crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        ));
        let mut walk =
            Walk::new(&loaded.program, &loaded.info.sections, 0x1000, &index, None).unwrap();
        walk.run(
            &loaded.program,
            &Bounds {
                tail_entry: None,
                sections: &loaded.info.sections,
                is_function: &|pc| pc == 0x1020,
                pe_ranges: &[],
            },
            &mut 16,
            None,
        );
        assert_eq!(walk.nodes.len(), 1);
        assert!(walk.complete_function(&Coverage::default(), &|pc| pc == 0x1020, &|_| true, 1));
    }

    #[test]
    fn full_inventory_reserves_entry_and_evidence_owners() {
        let mut loaded = raw_x86(vec![0xc3; MAX_FUNCTIONS + 8]);
        bulk_functions(
            &mut loaded,
            (0..MAX_FUNCTIONS as u64).map(|i| (0x1008 + i, format!("FUN_{:x}", 0x1008 + i))),
        );
        loaded.program.set_function_name(0x1001, "owner").unwrap();
        let owners = BTreeSet::from([0x1001]);
        let functions = function_list(&loaded.program, &mut loaded.info, &owners).unwrap();
        assert_eq!(functions.len(), MAX_FUNCTIONS);
        assert_eq!(functions[0].address, 0x1000);
        assert_eq!(functions[0].name, "entry");
        assert_eq!(functions[1].name, "owner");
        assert!(loaded.info.functions_truncated);
        // Address order admits the lowest remaining entries; two are omitted.
        assert_eq!(
            functions.last().unwrap().address,
            0x1008 + MAX_FUNCTIONS as u64 - 3
        );
        validate_functions(&functions, MAX_FUNCTION_NAME_BYTES, true).unwrap();
    }

    #[test]
    fn inventory_names_respect_the_escaped_byte_budget() {
        let count = MAX_FUNCTION_NAME_JSON_BYTES / 250 + 16;
        let mut loaded = raw_x86(vec![0xc3; count + 8]);
        // Quotes double when escaped: 125 of them cost 250 bytes.
        bulk_functions(
            &mut loaded,
            (0..count as u64).map(|i| (0x1008 + i, format!("{}{i:x}", "\"".repeat(125)))),
        );
        let functions = function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
        assert!(loaded.info.functions_truncated);
        assert!(functions.len() < count);
        let escaped: usize = functions.iter().map(|f| json_escaped_len(&f.name)).sum();
        assert!(escaped <= MAX_FUNCTION_NAME_JSON_BYTES);
        assert!(escaped > MAX_FUNCTION_NAME_JSON_BYTES - 512);
        validate_functions(&functions, MAX_FUNCTION_NAME_BYTES, true).unwrap();
    }

    fn discover(loaded: &mut LoadedProgram) -> (Vec<FunctionInfo>, CallAnalysis) {
        let Response::Functions {
            functions,
            analysis,
            ..
        } = loaded.handle(Request::Discover).unwrap()
        else {
            panic!("Expected discovery")
        };
        analysis.validate(&loaded.info, &functions).unwrap();
        (functions, analysis)
    }

    #[test]
    fn confirmed_calls_discover_with_symbols_preserve_names_and_stop_cycles() {
        let mut bytes = vec![0xcc; 0x50];
        bytes[..16].copy_from_slice(&[
            0xe8, 0x1b, 0, 0, 0, // call 1020
            0xe8, 0x16, 0, 0, 0, // call 1020 from another site
            0xb8, 0x40, 0x10, 0, 0, // numeric value 1040 is not a function seed
            0xc3,
        ]);
        bytes[0x20..0x26].copy_from_slice(&[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3]); // call root; ret
        bytes[0x40] = 0xc3;
        let mut loaded = raw_x86(bytes);
        loaded
            .program
            .set_function_name(0x1000, "root_name")
            .unwrap();
        loaded.info.functions =
            function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "root_name");
        assert_eq!(functions[1].address, 0x1020);
        assert_eq!(report.functions_examined, 2);
        assert_eq!(
            report.references,
            vec![
                CallReference {
                    caller: 0x1000,
                    address: 0x1000,
                    target: 0x1020
                },
                CallReference {
                    caller: 0x1000,
                    address: 0x1005,
                    target: 0x1020
                },
                CallReference {
                    caller: 0x1020,
                    address: 0x1020,
                    target: 0x1000
                },
            ]
        );
        let (_, repeated) = discover(&mut loaded);
        assert_eq!(repeated.references, report.references);
    }

    #[test]
    fn calls_to_fallthrough_do_not_split_functions_and_indirect_calls_stay_unknown() {
        let mut loaded = raw_x86(vec![0xe8, 0, 0, 0, 0, 0x58, 0xff, 0xd0, 0xc3]);
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].address, 0x1000);
        assert!(report.references.is_empty());
        // The x86 SLEIGH language emits a branch for call-to-next-PC already.
        assert_eq!(report.skipped_fallthrough_calls, 0);
        assert_eq!(report.unresolved_calls, 1);
        assert!(report.partial);
    }

    #[test]
    fn failed_decode_is_charged_and_does_not_create_a_function() {
        let mut bytes = vec![0xcc; 0x21];
        bytes[..6].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 1020; ret
        bytes[0x20] = 0xe8; // Truncated call at the actual target.
        let mut loaded = raw_x86(bytes);
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 1);
        assert!(
            loaded
                .program
                .functions()
                .unwrap()
                .iter()
                .all(|f| f.address != 0x1020)
        );
        assert_eq!(report.decode_attempts, 3);
        assert_eq!(report.failed_functions, 1);
        assert!(report.partial);
    }

    #[test]
    fn aarch64_call_to_fallthrough_is_not_a_function_candidate() {
        let mut bytes = 0x94000001u32.to_le_bytes().to_vec(); // BL next PC
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
        let mut loaded = raw_aarch64(bytes);
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 1);
        assert!(report.references.is_empty());
        assert_eq!(report.skipped_fallthrough_calls, 1);
    }

    #[test]
    fn discovery_has_an_exact_shared_decode_budget_and_monotonic_progress() {
        let stride = MAX_INSTRUCTIONS + 1;
        let mut bytes = vec![0x90; stride * 9];
        for function in 0..9 {
            bytes[(function + 1) * stride - 1] = 0xc3;
        }
        let mut loaded = raw_x86(bytes);
        for function in 0..9 {
            loaded
                .program
                .set_function_name(
                    0x1000 + (function * stride) as u64,
                    &format!("seed_{function}"),
                )
                .unwrap();
        }
        loaded.info.functions =
            function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
        let mut events: Vec<AnalysisProgress> = Vec::new();
        let Response::Functions { analysis, .. } = loaded
            .handle_with_progress(Request::Discover, &mut |event| {
                event.validate_after(events.last()).unwrap();
                events.push(event);
                Ok(())
            })
            .unwrap()
        else {
            panic!("Expected discovery")
        };
        assert_eq!(analysis.decode_attempts, MAX_ANALYSIS_INSTRUCTIONS);
        assert_eq!(analysis.functions_examined, 8);
        assert!(analysis.partial);
        assert_eq!(events.first().unwrap().stage, AnalysisStage::Seeds);
        assert_eq!(events.last().unwrap().stage, AnalysisStage::Publish);
        assert!(events.len() <= MAX_ANALYSIS_FUNCTIONS + 3);
    }

    #[test]
    fn packed_image_rejects_expensive_analysis_without_poisoning_other_requests() {
        let mut loaded = raw_aarch64(0xd65f03c0u32.to_le_bytes().to_vec());
        // Simulate the already validated packed-image flag with a tiny safe
        // engine fixture; no real packed application or decompression is run.
        loaded.upx_packed = true;
        assert!(
            loaded
                .handle_with_progress(Request::Discover, &mut |_| panic!(
                    "Packed input must be rejected before progress/work"
                ))
                .is_err()
        );
        for request in [Request::Decompile { address: 0x1000 }, Request::Discover] {
            assert_eq!(
                loaded.handle(request).unwrap_err(),
                crate::packing::UPX_ANALYSIS_ERROR
            );
        }
        assert!(matches!(
            loaded.handle(Request::Graph { address: 0x1000 }),
            Ok(Response::Graph { .. })
        ));
        assert!(matches!(
            loaded.handle(Request::Strings),
            Ok(Response::Strings { .. })
        ));
        let Response::Bytes { bytes, .. } = loaded
            .handle(Request::Bytes {
                address: 0x1000,
                length: 4,
            })
            .unwrap()
        else {
            panic!("Packed-image guard must leave byte inspection usable");
        };
        assert_eq!(bytes, 0xd65f03c0u32.to_le_bytes());
    }

    #[test]
    fn aarch64_discovery_counts_decoded_instructions_omitted_by_block_limit() {
        // Each unconditional B starts a block. Decode 256 instructions but retain
        // only 128 blocks; discovery must charge all decoded instructions.
        let mut bytes = 0x14000001u32.to_le_bytes().repeat(255);
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
        let mut loaded = raw_aarch64(bytes);
        let (view, count) =
            recover_graph_counted(&loaded.program, &loaded.info.sections, &[], 0x1000, &[])
                .unwrap();
        assert_eq!(count, 256);
        assert_eq!(view.blocks.len(), MAX_BLOCKS);
        assert_eq!(
            view.blocks
                .iter()
                .map(|block| block.instructions.len())
                .sum::<usize>(),
            128
        );
        let Response::Functions { truncated, .. } = loaded.handle(Request::Discover).unwrap()
        else {
            panic!("Expected function list");
        };
        assert!(
            truncated,
            "Graph truncation must be visible during discovery"
        );
    }

    #[test]
    fn call_evidence_survives_display_block_limits() {
        let mut bytes = 0x14000001u32.to_le_bytes().repeat(140);
        bytes.extend_from_slice(&0x94000002u32.to_le_bytes()); // BL helper, after the display cutoff
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes()); // helper
        let mut loaded = raw_aarch64(bytes);
        let (_, report) = discover(&mut loaded);
        assert_eq!(
            report.references,
            vec![CallReference {
                caller: 0x1000,
                address: 0x1000 + 140 * 4,
                target: 0x1000 + 142 * 4
            }]
        );
        assert!(report.partial);
        assert!(report.decode_attempts > 128);
    }

    #[test]
    fn aarch64_discovery_reports_unvisited_seeds_without_losing_known_names() {
        let mut loaded = raw_aarch64(0xd65f03c0u32.to_le_bytes().repeat(130));
        for index in 0..130 {
            loaded
                .program
                .set_function_name(0x1000 + index * 4, &format!("original_{index}"))
                .unwrap();
        }
        loaded.info.functions =
            function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
        let Response::Functions {
            functions,
            truncated,
            ..
        } = loaded.handle(Request::Discover).unwrap()
        else {
            panic!("Expected function list");
        };
        assert!(
            truncated,
            "Omitted seeds must not report complete discovery"
        );
        assert_eq!(functions.len(), 130);
        assert!(functions.iter().any(|f| f.name == "original_129"));
    }

    #[test]
    fn discovery_batches_publish_reconstructable_inventory_changes() {
        let mut bytes = vec![0xcc; 0x50];
        bytes[..6].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 1020; ret
        bytes[0x20] = 0xc3;
        bytes[0x40] = 0xc3;
        let mut loaded = raw_x86(bytes);
        for (address, name) in [(0x1000, "root"), (0x1040, "leaf")] {
            loaded.program.set_function_name(address, name).unwrap();
        }
        loaded.rebuild_inventory(&BTreeSet::new()).unwrap();
        let mut adopted: Option<(u64, Vec<FunctionInfo>)> = None;
        let mut batch = |loaded: &mut LoadedProgram, base: Option<u64>, seed: u64| {
            let binding = DiscoveryBinding {
                generation: 1,
                epoch: 1,
                revision: 0,
                batch: seed,
            };
            let Response::DiscoveryBatch { batch } = loaded
                .handle(Request::DiscoverBatch {
                    binding,
                    inventory_base: base,
                    seeds: vec![seed],
                    patterns: None,
                })
                .unwrap()
            else {
                panic!("Expected a discovery batch");
            };
            let change = batch.inventory;
            let revision = change.revision();
            let previous = adopted
                .as_ref()
                .filter(|(adopted, _)| Some(*adopted) == base)
                .map(|(revision, functions)| (*revision, functions.as_slice()));
            if let Some(functions) = change.clone().apply(previous).unwrap() {
                adopted = Some((revision, functions));
            }
            assert_eq!(adopted.as_ref().unwrap().1, loaded.info.functions);
            change
        };
        assert!(matches!(
            batch(&mut loaded, None, 0x1000),
            InventoryChange::Replace { revision: 1, .. }
        ));
        // The confirmed callee is named by discovery and sent as one new row.
        let InventoryChange::Delta {
            upserts, removals, ..
        } = batch(&mut loaded, Some(1), 0x1020)
        else {
            panic!("Expected the named callee as a delta");
        };
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].name, "FUN_00001020");
        assert!(removals.is_empty());
        assert!(matches!(
            batch(&mut loaded, Some(2), 0x1040),
            InventoryChange::Unchanged { revision: 2 }
        ));
        loaded
            .handle(Request::Rename {
                address: 0x1040,
                name: "renamed_leaf".into(),
            })
            .unwrap();
        let InventoryChange::Delta { upserts, .. } = batch(&mut loaded, Some(2), 0x1000) else {
            panic!("Expected the rename as a delta");
        };
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].name, "renamed_leaf");
        // Engine work outside discovery invalidates the shortcut, not correctness.
        loaded
            .handle(Request::Decompile { address: 0x1000 })
            .unwrap();
        let current = batch(&mut loaded, Some(3), 0x1040).revision();
        assert!(matches!(
            batch(&mut loaded, Some(current - 1), 0x1040),
            InventoryChange::Replace { .. }
        ));
    }

    pub(crate) fn elf_fixture() -> Vec<u8> {
        fn put16(bytes: &mut [u8], offset: usize, value: u16) {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn put32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut bytes = vec![0; 0x380];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 24, 0x401000);
        put64(&mut bytes, 32, 64);
        put64(&mut bytes, 40, 0x280);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 2);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, 4);
        put16(&mut bytes, 62, 3);
        let text = [
            0x85, 0xc0, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ];
        let data = b"fixture ASCII\0\0W\0i\0d\0e\0\0\0expand 32-byte k\0";
        let names = b"\0.text\0.rodata\0.shstrtab\0";
        bytes[0x100..0x100 + text.len()].copy_from_slice(&text);
        bytes[0x200..0x200 + data.len()].copy_from_slice(data);
        bytes[0x240..0x240 + names.len()].copy_from_slice(names);
        for (slot, offset, address, size, flags) in [
            (0, 0x100, 0x401000, text.len(), 5),
            (1, 0x200, 0x402000, data.len(), 4),
        ] {
            let header = 64 + slot * 56;
            put32(&mut bytes, header, 1);
            put32(&mut bytes, header + 4, flags);
            put64(&mut bytes, header + 8, offset);
            put64(&mut bytes, header + 16, address);
            put64(&mut bytes, header + 24, address);
            put64(&mut bytes, header + 32, size as u64);
            put64(&mut bytes, header + 40, size as u64);
            put64(&mut bytes, header + 48, 0x100);
        }
        for (slot, name, address, offset, size, flags) in [
            (1, 1, 0x401000, 0x100, text.len(), 6),
            (2, 7, 0x402000, 0x200, data.len(), 2),
            (3, 15, 0, 0x240, names.len(), 0),
        ] {
            let header = 0x280 + slot * 64;
            put32(&mut bytes, header, name);
            put32(&mut bytes, header + 4, if slot == 3 { 3 } else { 1 });
            put64(&mut bytes, header + 8, flags);
            put64(&mut bytes, header + 16, address);
            put64(&mut bytes, header + 24, offset);
            put64(&mut bytes, header + 32, size as u64);
            put64(&mut bytes, header + 48, 1);
        }
        bytes
    }

    fn graph(bytes: &[u8]) -> FunctionView {
        let program =
            Program::from_raw_bytes(bytes.to_vec(), "x86:LE:64:default:gcc", 0x1000).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        recover_graph_counted(&program, &sections, &[], 0x1000, &[])
            .unwrap()
            .0
    }

    #[test]
    fn conditional_branch_forms_three_blocks() {
        // test eax,eax; je taken; mov eax,1; ret; taken: xor eax,eax; ret
        let view = graph(&[
            0x85, 0xc0, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ]);
        assert_eq!(view.blocks.len(), 3);
        assert!(
            view.edges.iter().any(|e| e.source == 0x1000
                && e.target == Some(0x100a)
                && e.kind == EdgeKind::True)
        );
        assert!(
            view.edges.iter().any(|e| e.source == 0x1000
                && e.target == Some(0x1004)
                && e.kind == EdgeKind::False)
        );
    }

    #[test]
    fn graph_honors_function_entries_outside_the_displayed_inventory() {
        // jmp 0x1005; mov eax,1; ret. The jump is a known function's tail entry,
        // retained in PE ranges even when that function is outside the UI page.
        let bytes = vec![0xe9, 0, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3];
        let program =
            Program::from_raw_bytes(bytes.clone(), "x86:LE:64:default:windows", 0x1000).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        let (view, _) =
            recover_graph_counted(&program, &sections, &[], 0x1000, &[(0x1005, 0x100b)]).unwrap();
        assert_eq!(
            view.blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .count(),
            1
        );
        assert!(
            view.warnings
                .iter()
                .any(|warning| warning.contains("another known function entry"))
        );
    }

    #[test]
    fn imports_resolve_through_confirmed_calls_in_a_tail_function() {
        let mut bytes = vec![0xcc; 0x100];
        bytes[..5].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]); // tail to 0x1010
        bytes[0x10..0x16].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0, 0xc3]);
        bytes[0x20..0x26].copy_from_slice(&[0xff, 0x25, 0x5a, 0, 0, 0]);
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "x86:LE:64:default:windows", 0x1000).unwrap();
        let mut symbols = crate::pe::PeMetadata::default();
        symbols.functions.insert(0x1000, "entry".into());
        symbols.functions.insert(0x1010, "tail".into());
        symbols.imports.insert(0x1080, "ExitProcess".into());
        crate::pe_symbols::register(&mut program, &symbols, 8).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: 0x100,
            file_offset: 0,
            file_size: 0x100,
            executable: true,
        }];
        let mut info = BinaryInfo {
            path: "synthetic".into(),
            architecture: "x86-64".into(),
            format: "PE".into(),
            entry: 0x1000,
            file_len: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            source_identity: None,
            sections,
            functions: vec![],
            functions_truncated: false,
            warnings: vec![],
        };
        info.functions = function_list(&program, &mut info, &BTreeSet::new()).unwrap();
        let mut loaded = LoadedProgram {
            macho_legacy: None,
            target: crate::architecture::Target::for_image(
                &object::File::parse(elf_fixture().as_slice()).unwrap(),
            )
            .unwrap(),
            program,
            snapshot: Arc::from(bytes),
            info,
            pe_ranges: vec![(0x1000, 0x1005), (0x1010, 0x1016)],
            pe_imports: symbols.imports,
            upx_packed: false,
            inventory: Default::default(),
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::default(),
            symbol_names: Arc::default(),
            linkage: None,
            search: None,
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
            debug: Default::default(),
            debug_calls: VecDeque::new(),
            debug_large: BTreeSet::new(),
            debug_skip: BTreeSet::new(),
            debug_failed: BTreeSet::new(),
            debug_large_journal: None,
            results: ResultCache::default(),
            result_epoch: 0,
            pending_debug: None,
            debug_nonce: 0,
            debug_inventory_digest: None,
            debug_program_digest: None,
            debug_long_names: BTreeMap::new(),
            debug_long_names_complete: true,
        };
        loaded.resolve_import_thunks(0x1000).unwrap();
        assert!(
            loaded
                .program
                .functions()
                .unwrap()
                .iter()
                .any(|function| function.address == 0x1020 && function.name == "ExitProcess")
        );
        let Response::Decompiled { text, .. } = loaded
            .handle(Request::Decompile { address: 0x1010 })
            .unwrap()
        else {
            panic!("Expected decompiler result")
        };
        assert!(text.contains("ExitProcess"), "{text}");
    }

    #[test]
    fn backward_branch_splits_a_loop_without_redecoding() {
        // xor ecx,ecx; loop: inc ecx; cmp ecx,3; jne loop; ret
        let view = graph(&[0x31, 0xc9, 0xff, 0xc1, 0x83, 0xf9, 3, 0x75, 0xf9, 0xc3]);
        assert_eq!(view.blocks.len(), 3);
        assert!(
            view.edges.iter().any(|e| e.source == 0x1002
                && e.target == Some(0x1002)
                && e.kind == EdgeKind::True)
        );
        assert_eq!(
            view.blocks
                .iter()
                .map(|b| b.instructions.len())
                .sum::<usize>(),
            5
        );
    }

    #[test]
    fn call_is_a_call_site_and_indirect_jump_is_unknown() {
        // call 0x100a; jmp rax; padding; ret
        let view = graph(&[0xe8, 5, 0, 0, 0, 0xff, 0xe0, 0x90, 0x90, 0x90, 0xc3]);
        assert_eq!(view.calls.len(), 1);
        assert_eq!(view.calls[0].target, Some(0x100a));
        assert_eq!(view.blocks.len(), 1);
        assert!(
            view.edges
                .iter()
                .any(|e| e.target.is_none() && e.kind == EdgeKind::Unknown)
        );
        assert!(!view.edges.iter().any(|e| e.target == Some(0x100a)));
    }

    #[test]
    fn coverage_merges_ranges_and_reports_instruction_ends() {
        let mut coverage = Coverage::default();
        coverage.add(
            0x1000,
            &[(0x1000, 0x1004), (0x1004, 0x1006), (0x1010, 0x1012)],
        );
        assert_eq!(coverage.ranges.len(), 2);
        assert!(coverage.contains(0x1005) && !coverage.contains(0x1006));
        assert!(coverage.overlaps(0x0fff, 0x1001) && !coverage.overlaps(0x1006, 0x1010));
        assert!(coverage.ends_at(0x1006) && coverage.ends_at(0x1012));
        assert!(!coverage.ends_at(0x1004) && !coverage.ends_at(0x1010));
        // A bridging range joins its neighbours.
        coverage.add(0x1006, &[(0x1006, 0x1010)]);
        assert_eq!(
            coverage.ranges.into_iter().collect::<Vec<_>>(),
            [(0x1000, 0x1012)]
        );
    }

    #[test]
    fn pattern_candidates_need_complete_independent_code() {
        let check = |bytes: &[u8], coverage: &Coverage, known: &[u64]| {
            let program =
                Program::from_raw_bytes(bytes.to_vec(), "x86:LE:64:default:gcc", 0x1000).unwrap();
            let sections = vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                executable: true,
            }];
            let is_function = |address| known.contains(&address);
            let mut remaining = MAX_INSTRUCTIONS;
            let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
            walk.run(
                &program,
                &Bounds {
                    tail_entry: None,
                    sections: &sections,
                    is_function: &is_function,
                    pe_ranges: &[],
                },
                &mut remaining,
                None,
            );
            let is_code = |address| (0x1000..0x1000 + bytes.len() as u64).contains(&address);
            walk.complete_function(coverage, &is_function, &is_code, 0)
        };
        let empty = Coverage::default();
        // push rbp; mov rbp,rsp; pop rbp; ret
        let frame = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        assert!(check(&frame, &empty, &[]));
        // Its bytes already belong to decoded code.
        let mut covered = Coverage::default();
        covered.add(0x2000, &[(0x1004, 0x1005)]);
        assert!(!check(&frame, &covered, &[]));
        // push rbp; jmp rax: an unresolved indirect jump.
        assert!(!check(&[0x55, 0xff, 0xe0], &empty, &[]));
        // push rbp; nop; then a known function: running into it is no exit.
        assert!(!check(&[0x55, 0x90, 0xc3], &empty, &[0x1002]));
        // push rbp; je +1; ret; ret: both paths return.
        assert!(check(&[0x55, 0x74, 0x01, 0xc3, 0xc3], &empty, &[]));
        // A path ending in an explicit jump to a known function is accepted
        // beside a return, but a call into the middle of decoded code is not.
        assert!(check(
            &[0x74, 0x01, 0xc3, 0xeb, 0x00, 0xc3],
            &empty,
            &[0x1005]
        ));
        let mut interior = Coverage::default();
        interior.add(0x1000, &[(0x1006, 0x100a)]);
        // call 0x1007; ret; padding.
        let call = [0xe8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x90, 0x90];
        assert!(!check(&call, &interior, &[]));
        assert!(check(&call, &empty, &[]));
    }

    #[test]
    fn switch_destinations_are_validated_before_they_become_edges() {
        use crate::switch_analysis::{Recovered, Table};
        // jmp rax; ret; ret
        let bytes = [0xff, 0xe0, 0xc3, 0xc3];
        let program =
            Program::from_raw_bytes(bytes.to_vec(), "x86:LE:64:default:gcc", 0x1000).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        let mut remaining = MAX_INSTRUCTIONS;
        let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
        walk.run(
            &program,
            &Bounds {
                tail_entry: None,
                sections: &sections,
                is_function: &|_| false,
                pe_ranges: &[],
            },
            &mut remaining,
            None,
        );
        let table = |branch, targets: &[u64], partial| Table {
            branch,
            targets: targets.to_vec(),
            partial,
        };
        // A table must belong to the exact decoded jump; the second one has a
        // repeated entry and an address outside executable sections.
        let queued = walk.apply(
            Recovered {
                tables: vec![
                    table(0x1001, &[0x1003], false),
                    table(0x1000, &[0x1002, 0x1003, 0x1002, 0x9000], false),
                ],
                truncated: false,
            },
            &sections,
        );
        assert!(queued);
        walk.run(
            &program,
            &Bounds {
                tail_entry: None,
                sections: &sections,
                is_function: &|_| false,
                pe_ranges: &[],
            },
            &mut remaining,
            None,
        );
        let view = walk.finish(None).unwrap().view;
        let mut switched: Vec<_> = view
            .edges
            .iter()
            .filter(|edge| edge.evidence == Some(EdgeEvidence::EngineJumpTable))
            .map(|edge| (edge.source, edge.target))
            .collect();
        switched.sort();
        assert_eq!(switched, [(0x1000, Some(0x1002)), (0x1000, Some(0x1003))]);
        // The rejected entry leaves an unresolved successor, never an edge.
        assert!(
            view.edges
                .iter()
                .any(|e| e.source == 0x1000 && e.target.is_none() && e.evidence.is_none())
        );
        assert!(!view.edges.iter().any(|e| e.target == Some(0x9000)));
        assert!(
            view.warnings
                .iter()
                .any(|w| w.contains("only partly recovered"))
        );
        assert!(
            !view
                .warnings
                .iter()
                .any(|w| w.contains("unresolved targets"))
        );
    }

    #[test]
    fn a_table_without_valid_destinations_leaves_the_jump_unresolved() {
        use crate::switch_analysis::{Recovered, Table};
        let bytes = [0xff, 0xe0, 0xc3];
        let program =
            Program::from_raw_bytes(bytes.to_vec(), "x86:LE:64:default:gcc", 0x1000).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        let mut remaining = MAX_INSTRUCTIONS;
        let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
        walk.run(
            &program,
            &Bounds {
                tail_entry: None,
                sections: &sections,
                is_function: &|_| false,
                pe_ranges: &[],
            },
            &mut remaining,
            None,
        );
        let recovered = Recovered {
            tables: vec![Table {
                branch: 0x1000,
                targets: vec![0x9000],
                partial: false,
            }],
            truncated: false,
        };
        assert!(!walk.apply(recovered, &sections));
        let view = walk.finish(None).unwrap().view;
        assert!(view.edges.iter().all(|e| e.evidence.is_none()));
        assert!(
            view.warnings
                .iter()
                .any(|w| w.contains("0x1000 has unresolved targets"))
        );
    }

    #[test]
    fn internal_pcode_branches_do_not_become_machine_addresses() {
        use ghidra_decompiler::program::{PcodeOperation, PcodeVarnode};
        let code = InstructionPcode {
            address: 0x1000,
            length: 2,
            operations: vec![PcodeOperation {
                opcode: OpCode::Cbranch,
                output: None,
                inputs: vec![PcodeVarnode {
                    space: "const".into(),
                    offset: 3,
                    size: 8,
                }],
                space: None,
            }],
        };
        let mut calls = Vec::new();
        let mut warnings = Vec::new();
        let (edges, terminal, _) = flow(&code, 0x1002, &mut calls, &mut warnings, &mut |_, _| None);
        assert!(terminal);
        assert_eq!(edges, vec![(None, EdgeKind::Unknown)]);
        assert!(warnings[0].contains("internal p-code branches"));
    }

    #[test]
    fn mapped_reads_zero_fill_tails_and_refuse_gaps() {
        let snapshot = [1, 2, 3, 4];
        let sections = [SectionInfo {
            name: "data".into(),
            address: 0x4000,
            size: 6,
            file_offset: 0,
            file_size: 4,
            executable: false,
        }];
        assert_eq!(
            read_virtual(&snapshot, &sections, 0x4002, 4).unwrap(),
            [3, 4, 0, 0]
        );
        assert!(
            read_virtual(&snapshot, &sections, 0x4002, 5)
                .unwrap_err()
                .contains("gap")
        );
        assert!(read_virtual(&snapshot, &sections, 0x4000, MAX_BYTES + 1).is_err());
    }

    #[test]
    fn rejects_non_executable_input() {
        assert!(metadata(Path::new("bad"), b"not an executable").is_err());
    }

    #[test]
    fn elf_metadata_uses_virtual_addresses_and_rejects_other_architectures() {
        let mut bytes = elf_fixture();
        let info = metadata(Path::new("fixture.elf"), &bytes).unwrap();
        assert_eq!(info.entry, 0x401000);
        assert_eq!(info.sections.len(), 2);
        assert_eq!(info.sections[0].file_offset, 0x100);
        assert_eq!(info.sections[1].address, 0x402000);
        assert_eq!(info.sha256.len(), 64);
        assert!(info.warnings.is_empty());
        bytes[18..20].copy_from_slice(&243u16.to_le_bytes());
        assert!(
            metadata(Path::new("fixture.elf"), &bytes)
                .unwrap_err()
                .contains("Unsupported architecture")
        );
    }

    #[test]
    fn real_elf_snapshot_survives_original_mutation_for_all_analysis() {
        let path = std::env::temp_dir().join(format!("ghidra-rust-elf-{}", std::process::id()));
        std::fs::write(&path, elf_fixture()).unwrap();
        let mut loaded = LoadedProgram::open(path.to_str().unwrap()).unwrap();
        let expected_hash = format!("{:x}", Sha256::digest(elf_fixture()));
        assert_eq!(loaded.info.sha256, expected_hash);
        // Engine instructions, auxiliary bytes, strings, and crypto must all use
        // the originally hashed image even if the original file is overwritten.
        std::fs::write(&path, b"The original file no longer contains an ELF image.").unwrap();
        assert_eq!(loaded.info.functions[0].address, 0x401000);
        let Response::Graph { view } = loaded.handle(Request::Graph { address: 0x401000 }).unwrap()
        else {
            panic!("Expected graph");
        };
        assert_eq!(view.blocks.len(), 3);
        let Response::Strings { strings, truncated } = loaded.handle(Request::Strings).unwrap()
        else {
            panic!("Expected strings");
        };
        assert!(!truncated);
        assert!(
            strings.iter().any(|s| s.address == 0x402000
                && s.text == "fixture ASCII"
                && s.encoding == "ASCII")
        );
        assert!(
            strings
                .iter()
                .any(|s| s.address == 0x40200f && s.text == "Wide" && s.encoding == "UTF-16LE")
        );
        let Response::Bytes { bytes, .. } = loaded
            .handle(Request::Bytes {
                address: 0x402000,
                length: 7,
            })
            .unwrap()
        else {
            panic!("Expected bytes");
        };
        assert_eq!(&bytes, b"fixture");
        let Response::Crypto { matches, truncated } = loaded.handle(Request::Crypto).unwrap()
        else {
            panic!("Expected crypto matches");
        };
        assert!(!truncated);
        assert!(
            matches
                .iter()
                .any(|hit| hit.algorithm.starts_with("ChaCha / Salsa"))
        );
        let expected_text = loaded.program.decompile(0x401000).unwrap();
        let Response::Decompiled { text, mappings, .. } = loaded
            .handle(Request::Decompile { address: 0x401000 })
            .unwrap()
        else {
            panic!("Expected decompilation");
        };
        assert!(!text.is_empty());
        assert_eq!(
            text, expected_text,
            "Semantic collection must preserve the engine's C output"
        );
        assert!(
            !mappings.is_empty(),
            "Real engine p-code must produce machine locations"
        );
        assert!(mappings.windows(2).all(|pair| pair[0].end <= pair[1].start));
        let machine_addresses: BTreeSet<_> = view
            .blocks
            .iter()
            .flat_map(|block| {
                block
                    .instructions
                    .iter()
                    .map(|instruction| instruction.address)
            })
            .collect();
        for mapping in &mappings {
            assert!(mapping.start < mapping.end && mapping.end <= text.len());
            assert!(text.is_char_boundary(mapping.start) && text.is_char_boundary(mapping.end));
            assert!(
                mapping
                    .addresses
                    .iter()
                    .all(|address| machine_addresses.contains(address))
            );
        }
        loaded
            .handle(Request::Rename {
                address: 0x401000,
                name: "fixture_entry".into(),
            })
            .unwrap();
        assert!(
            loaded
                .info
                .functions
                .iter()
                .any(|f| f.name == "fixture_entry")
        );
        let Response::Decompiled { text, .. } = loaded
            .handle(Request::Decompile { address: 0x401000 })
            .unwrap()
        else {
            panic!("Expected decompilation after rename");
        };
        assert!(
            text.contains("fixture_entry"),
            "Materialized function name must follow symbol rename: {text}"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn function_names_are_capped_at_utf8_boundaries() {
        let name = "界".repeat(200);
        let bounded = bounded_name(&name);
        assert!(bounded.len() <= 256);
        assert_eq!(bounded.chars().count(), 85);
    }

    #[test]
    fn refuses_oversized_image_before_reading() {
        let path = std::env::temp_dir().join(format!("ghidra-rust-large-{}", std::process::id()));
        File::create(&path)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES + 1)
            .unwrap();
        let error = LoadedProgram::open(path.to_str().unwrap()).err().unwrap();
        assert!(error.contains("128 MiB"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn string_minimum_filters_noise_before_the_result_budget() {
        let mut bytes = b"abcd\0".repeat(MAX_STRING_RESULTS + 100);
        let target_offset = bytes.len();
        bytes.extend_from_slice(b"meaningful string\0");
        let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap() else {
            panic!("Expected string results");
        };
        assert!(!truncated);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].address, 0x1000 + target_offset as u64);
        assert_eq!(strings[0].text, "meaningful string");

        let Response::Strings { strings, truncated } =
            scan_test_strings(&bytes, MIN_STRING_LENGTH).unwrap()
        else {
            panic!("Expected legacy string results");
        };
        assert!(truncated);
        assert_eq!(strings.len(), MAX_STRING_RESULTS);
    }

    #[test]
    fn string_limit_requires_an_additional_matching_result() {
        let mut bytes = b"token6\0".repeat(MAX_STRING_RESULTS);
        bytes.extend_from_slice(b"abcd\0");
        let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap() else {
            panic!("Expected string results");
        };
        assert_eq!(strings.len(), MAX_STRING_RESULTS);
        assert!(!truncated, "Exactly the result limit is still complete");

        bytes.extend_from_slice(b"one more match");
        let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap() else {
            panic!("Expected string results after section-final flush");
        };
        assert_eq!(strings.len(), MAX_STRING_RESULTS);
        assert!(truncated);
    }

    #[test]
    fn string_minimum_preserves_ascii_and_unaligned_wide_chunk_boundaries() {
        for wide in [false, true] {
            let start = SCAN_CHUNK - 3;
            let mut bytes = vec![0; start];
            for &byte in b"boundary string" {
                bytes.push(byte);
                if wide {
                    bytes.push(0);
                }
            }
            // Flush on the section boundary, including the odd UTF-16 parity.
            let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap()
            else {
                panic!("Expected string results");
            };
            assert!(!truncated);
            assert_eq!(strings.len(), 1);
            assert_eq!(strings[0].address, 0x1000 + start as u64);
            assert_eq!(strings[0].text, "boundary string");
            assert_eq!(strings[0].length, Some(15 * if wide { 2 } else { 1 }));
            assert_eq!(strings[0].encoding, if wide { "UTF-16LE" } else { "ASCII" });
        }
    }

    #[test]
    fn string_minimum_is_bounded_and_legacy_protocol_remains_accepted() {
        for invalid in [0, MIN_STRING_LENGTH - 1, MAX_STRING_MINIMUM + 1, usize::MAX] {
            assert!(scan_test_strings(b"valid string", invalid).is_err());
        }
        assert!(scan_test_strings(b"valid string", MIN_STRING_LENGTH).is_ok());
        assert!(scan_test_strings(b"valid string", MAX_STRING_MINIMUM).is_ok());
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"kind":"strings"}"#).unwrap(),
            Request::Strings
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(
                r#"{"kind":"strings_with_options","minimum_length":6}"#
            )
            .unwrap(),
            Request::StringsWithOptions { minimum_length: 6 }
        ));
    }

    fn scan_test_strings(bytes: &[u8], minimum_length: usize) -> Result<Response, String> {
        scan_strings(
            bytes,
            &[SectionInfo {
                name: "test strings".into(),
                address: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                executable: false,
            }],
            minimum_length,
        )
    }

    #[test]
    fn long_string_preview_is_bounded() {
        let mut run = StringRun::default();
        let mut strings = Vec::new();
        for offset in 0..5000 {
            run.feed(Some('a'), 0x1000 + offset, "ASCII", &mut strings);
        }
        run.flush("ASCII", &mut strings);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].address, 0x1000);
        assert!(strings[0].text.len() <= MAX_STRING_PREVIEW + 3);
        assert!(strings[0].text.ends_with('…'));
    }

    #[test]
    fn listing_views_equal_graph_replies_within_budget_prefixes() {
        let path = std::env::temp_dir().join(format!("ghidra-rust-listing-{}", std::process::id()));
        std::fs::write(&path, elf_fixture()).unwrap();
        let mut loaded = LoadedProgram::open(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(&path).unwrap();
        // A known function, a raw entry, and bytes outside executable code.
        let entries = [0x401000, 0x40100a, 0x402000];
        let Response::Listing { binding, outcomes } = loaded
            .handle(Request::Listing {
                binding: crate::model::ListingBinding {
                    generation: 7,
                    token: 9,
                },
                entries: entries.to_vec(),
            })
            .unwrap()
        else {
            panic!("Expected a listing reply");
        };
        assert_eq!((binding.generation, binding.token), (7, 9));
        assert_eq!(
            outcomes.iter().map(|o| o.entry).collect::<Vec<_>>(),
            entries
        );
        for outcome in &outcomes[..2] {
            let Response::Graph { view } = loaded
                .handle(Request::Graph {
                    address: outcome.entry,
                })
                .unwrap()
            else {
                panic!("Expected a graph");
            };
            assert_eq!(
                serde_json::to_string(outcome.view.as_ref().unwrap()).unwrap(),
                serde_json::to_string(&view).unwrap(),
                "Listing runs the Graph path"
            );
        }
        assert!(outcomes[2].view.is_none(), "non-code is a failed outcome");
        // Each shared limit stops later functions from starting, never the first.
        let narrowed = [
            ListingLimits {
                decode_attempts: MAX_INSTRUCTIONS,
                ..Default::default()
            },
            ListingLimits {
                reply_bytes: 1,
                ..Default::default()
            },
            ListingLimits {
                elapsed: std::time::Duration::ZERO,
                ..Default::default()
            },
        ];
        for limits in narrowed {
            let outcomes = loaded.listing(&entries, limits).unwrap();
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].entry, 0x401000);
            assert!(outcomes[0].view.is_some());
        }
        // A view the switch allowance would degrade is never returned.
        // Two functions, each `jmp rax`, need an engine switch recovery.
        let mut raw = raw_x86(vec![0xff, 0xe0, 0xc3, 0xc3, 0xff, 0xe0, 0xc3, 0xc3]);
        raw.info.functions = [0x1000, 0x1004]
            .map(|address| crate::model::FunctionInfo {
                address,
                name: format!("f{address:x}"),
            })
            .to_vec();
        let cut = ListingLimits {
            switches: std::time::Duration::ZERO,
            ..Default::default()
        };
        let outcomes = raw.listing(&[0x1000, 0x1004], cut).unwrap();
        assert_eq!(outcomes.len(), 1, "a skipped recovery ends the prefix");
        assert!(outcomes[0].view.is_none());
        let outcomes = raw
            .listing(&[0x1000, 0x1004], ListingLimits::default())
            .unwrap();
        assert_eq!(outcomes.len(), 2);
        for outcome in &outcomes {
            let view = outcome.view.as_ref().unwrap();
            assert!(!view.warnings.iter().any(|w| w == SWITCH_SKIPPED));
            let Response::Graph { view: graph } = raw
                .handle(Request::Graph {
                    address: outcome.entry,
                })
                .unwrap()
            else {
                panic!("Expected a graph");
            };
            assert_eq!(
                serde_json::to_string(view).unwrap(),
                serde_json::to_string(&graph).unwrap()
            );
        }
        for invalid in [vec![], vec![0x40100a, 0x401000], vec![0x401000, 0x401000]] {
            assert!(loaded.listing(&invalid, ListingLimits::default()).is_err());
        }
        let oversized = format!(
            "{{\"kind\":\"listing\",\"binding\":{{\"generation\":1,\"token\":1}},\"entries\":[{}]}}",
            (0..=crate::model::MAX_LISTING_FUNCTIONS)
                .map(|i| (0x401000 + i).to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(serde_json::from_str::<Request>(&oversized).is_err());
    }
    #[test]
    fn failed_cfg_hint_does_not_fail_decompile() {
        let (bytes, entry) = crate::architecture::fixtures::dwarf_prototype(false, 0);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture");
        std::fs::write(&path, bytes).unwrap();
        let mut loaded = LoadedProgram::open(path.to_str().unwrap()).unwrap();
        DEBUG_HINT_FAILURE.set(true);
        let response = loaded.handle(Request::Decompile { address: entry });
        DEBUG_HINT_FAILURE.set(false);
        assert!(
            matches!(response, Ok(Response::Decompiled { .. })),
            "{response:?}"
        );
    }

    /// Compiles original C with GCC into a temporary directory.
    #[cfg(target_os = "linux")]
    fn gcc(source: &str, arguments: &[&str]) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("image");
        let result = std::process::Command::new("gcc")
            .args(arguments)
            .arg(source)
            .arg("-o")
            .arg(&output)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        (directory, output)
    }
    #[cfg(target_os = "linux")]
    fn decompiled(
        loaded: &mut LoadedProgram,
        name: &str,
    ) -> (u64, String, crate::semantic::SemanticInfo) {
        let address = loaded
            .info
            .functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .address;
        match loaded.handle(Request::Decompile { address }) {
            Ok(Response::Decompiled {
                text, semantics, ..
            }) => (address, text, semantics),
            other => panic!("{name}: {other:?}"),
        }
    }
    #[test]
    fn managed_debug_fork_requires_known_cpu_and_nonempty_wall_headroom() {
        use std::time::Duration;
        let positive = Duration::from_millis(1);
        let one = Duration::from_secs(1);
        assert!(!optional_window_available(
            Duration::ZERO,
            Some(one + positive)
        ));
        assert!(!optional_window_available(positive, None));
        assert!(!optional_window_available(positive, Some(one)));
        assert!(optional_window_available(positive, Some(one + positive)));
    }

    /// An inference-only recovery renders exactly the debug-off result
    /// under the same user signature and local names (apart from the
    /// ordinary unverified warning for an indexed target), computes no
    /// binding digest and leaves no offer or pending optional job; a normal
    /// preparation on the same worker still offers its upgrade.
    #[cfg(target_os = "linux")]
    #[test]
    fn managed_scheduler_inference_only_matches_debug_off_without_offer() {
        use crate::client::managed_decompile::prepare_request;
        use crate::signatures::*;
        let (_directory, path) = gcc(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.c"),
            &["-O0", "-g", "-fno-pie", "-no-pie", "-fno-inline"],
        );
        let open = |enabled: bool| {
            let mut loaded = LoadedProgram::open_debug(
                path.to_str().unwrap(),
                &crate::debug_info::DebugOptions {
                    enabled,
                    ..Default::default()
                },
            )
            .unwrap();
            let address = |name: &str| {
                loaded
                    .info
                    .functions
                    .iter()
                    .find(|entry| entry.name == name)
                    .unwrap()
                    .address
            };
            let (main, branch) = (address("main"), address("branch_loop"));
            let ty = SignatureType {
                base: SignatureBase::U32,
                pointer_depth: 0,
            };
            let signatures = vec![FunctionSignature {
                function: branch,
                engine: SIGNATURE_FINGERPRINT.into(),
                abi: "x86:LE:64:default:gcc".into(),
                return_type: ty,
                parameters: vec![SignatureParameter {
                    name: "limit".into(),
                    ty,
                }],
            }];
            let synced = loaded
                .handle(Request::SyncSignatures {
                    binary_sha256: loaded.info.sha256.clone(),
                    context: state_digest(&signatures),
                    signatures,
                })
                .unwrap();
            assert!(matches!(synced, Response::SignaturesSynced { .. }));
            (loaded, main)
        };
        let (mut off, main) = open(false);
        let Response::Decompiled { semantics, .. } =
            off.handle(Request::Decompile { address: main }).unwrap()
        else {
            panic!("ordinary inference")
        };
        let renames = vec![crate::semantic::LocalRename {
            identity: semantics.locals.first().unwrap().identity.clone(),
            name: "renamed_local".into(),
        }];
        let Response::Decompiled {
            text,
            mappings,
            semantics,
            ..
        } = off
            .handle(Request::DecompileWithLocals {
                address: main,
                renames: renames.clone(),
            })
            .unwrap()
        else {
            panic!("ordinary inference")
        };
        assert!(text.contains("renamed_local"), "{text}");
        assert!(text.contains("branch_loop("), "{text}");
        let (mut on, _) = open(true);
        assert!(matches!(
            on.handle(Request::Graph { address: main }).unwrap(),
            Response::Graph { .. }
        ));
        // The Graph recorded main's call hints; a recovery never reads them.
        let hints = |on: &mut LoadedProgram, inference_only| {
            let Ok(Ok((job, _))) = on.reference(main, &renames, None, false, inference_only) else {
                panic!("a reference render")
            };
            job.cached_hints
        };
        assert!(hints(&mut on, false).is_some());
        assert!(hints(&mut on, true).is_none());
        let reply = on
            .handle(prepare_request(main, renames.clone(), false, true).unwrap())
            .unwrap();
        let Response::Decompiled {
            text: recovered,
            mappings: recovered_mappings,
            semantics: mut recovered_semantics,
            ..
        } = reply
        else {
            panic!("an inference-only recovery is always final: {reply:?}")
        };
        assert_eq!(recovered, text);
        assert_eq!(recovered_mappings, mappings);
        assert_eq!(
            recovered_semantics.warnings.pop().as_deref(),
            Some(UNVERIFIED_WARNING)
        );
        assert_eq!(recovered_semantics, semantics);
        assert_eq!(
            recovered_semantics.prototype_source,
            crate::semantic::PrototypeSource::Inferred
        );
        assert!(on.pending_debug.is_none());
        assert!(on.debug_program_digest.is_none());
        assert!(on.debug_inventory_digest.is_none());
        assert!(on.results.entries.is_empty());
        // The same worker still offers a normal upgrade.
        let reply = on
            .handle(prepare_request(main, renames, false, false).unwrap())
            .unwrap();
        let Response::PreparedDecompile { text: baseline, .. } = reply else {
            panic!("{reply:?}")
        };
        assert_eq!(baseline, text);
        assert!(on.debug_program_digest.is_some());
    }

    /// The managed baseline equals the debug-off render on the same image
    /// (text, mappings, tokens, locals, prototype and warnings) and installs
    /// nothing in the long-lived engine. A sibling's recapture reproduces
    /// its binding; the primary commits its checked report exactly once.
    /// Forged reports, flipped digests, executor mismatches and offers
    /// retired by a mutating request change no decision.
    #[cfg(target_os = "linux")]
    #[test]
    fn managed_debug_sibling_binds_exact_baseline_and_leaves_primary_raw_state_alone() {
        use crate::client::managed_decompile::{DecisionBook, admit_prepared, prepare_request};
        let (_directory, path) = gcc(
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.c"),
            &["-O0", "-g", "-fno-pie", "-no-pie", "-fno-inline"],
        );
        let open = |enabled: bool| {
            LoadedProgram::open_debug(
                path.to_str().unwrap(),
                &crate::debug_info::DebugOptions {
                    enabled,
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let mut primary = open(true);
        let address = primary
            .info
            .functions
            .iter()
            .find(|entry| entry.name == "branch_loop")
            .unwrap()
            .address;
        let Response::Decompiled {
            text,
            mappings,
            semantics,
            ..
        } = open(false).handle(Request::Decompile { address }).unwrap()
        else {
            panic!("ordinary inference")
        };
        let prepare = |loaded: &mut LoadedProgram| {
            let reply = loaded
                .handle(prepare_request(address, Vec::new(), false, false).unwrap())
                .unwrap();
            admit_prepared(address, reply, &loaded.info, "").unwrap()
        };
        let prepared = prepare(&mut primary);
        assert_eq!(prepared.text, text);
        assert_eq!(prepared.mappings, mappings);
        assert_eq!(prepared.semantics, semantics);
        assert_eq!(
            prepared.offer.as_ref().unwrap().executor,
            managed::Executor::Sibling
        );
        let cutoff = || std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut book = DecisionBook::default();
        let tx = book.begin(&prepared, Vec::new(), cutoff()).unwrap();
        let peer = |job| {
            let mut sibling = open(true);
            let mut started = 0;
            let response = sibling
                .render_debug_once(job, &mut |_, _| {
                    started += 1;
                    Ok(())
                })
                .unwrap();
            (response, started)
        };
        for (field, expected) in [
            (0, "digest-baseline"),
            (1, "digest-facts"),
            (2, "digest-context"),
        ] {
            let mut forged = tx.job.clone();
            let digest = match field {
                0 => &mut forged.binding.baseline,
                1 => &mut forged.binding.facts,
                _ => &mut forged.binding.context,
            };
            digest.replace_range(0..1, if digest.starts_with('0') { "1" } else { "0" });
            let (response, started) = peer(forged);
            assert!(
                matches!(response, Response::DebugUnavailable { ref reason, .. } if reason == expected),
                "{response:?}"
            );
            assert_eq!(started, 0);
        }
        let (reply, started) = peer(tx.job.clone());
        assert_eq!(started, 1);
        let mut bad = reply.clone();
        if let Response::DebugFinished { outcome, .. } = &mut bad
            && let DebugOutcome::Candidate { changes, .. } = &mut outcome.0
        {
            changes[0].entry = address + 1;
        } else {
            panic!("expected a candidate");
        }
        let mut bad = tx.stage_reply(&prepared, bad, true, &primary.info, "");
        assert!(book.accept(&tx, &mut bad));
        assert_eq!(bad.result.render(&prepared).0, prepared.text);
        assert!(
            book.cached(Some(&tx.job.binding.program), address, &[], false)
                .is_none()
        );
        let prepared = prepare(&mut primary);
        let tx = book.begin(&prepared, Vec::new(), cutoff()).unwrap();
        let (reply, started) = peer(tx.job.clone());
        assert_eq!(started, 1);
        let mut staged = tx.stage_reply(&prepared, reply, true, &primary.info, "");
        assert!(book.accept(&tx, &mut staged));
        let (text, _, semantics) = staged.result.render(&prepared);
        assert!(text.contains("uint4 branch_loop(uint4 count)"), "{text}");
        assert_eq!(
            semantics.prototype_source,
            crate::semantic::PrototypeSource::DebugInfo
        );
        assert_eq!(
            primary.debug.state(address),
            crate::debug_info::EntryState::default()
        );
        assert!(primary.debug.installed_entries().is_empty());
        assert!(primary.results.entries.is_empty());
        for _ in 0..30 {
            let Some(Response::Decompiled { text: cached, .. }) =
                book.cached(Some(&tx.job.binding.program), address, &[], false)
            else {
                panic!("verified host hit")
            };
            assert_eq!(cached, text);
        }
        assert!(
            book.cached(Some(&tx.job.binding.program), address, &[], true)
                .is_none()
        );
        let mut replacement = open(true);
        let next = prepare(&mut replacement);
        let tx = book.begin(&next, Vec::new(), cutoff()).unwrap();
        assert_eq!(
            tx.job.seed.state(address).status,
            crate::debug_info::Status::Verified
        );
        let (rendered, started) = peer(tx.job.clone());
        assert_eq!(started, 1);
        let mut staged = tx.stage_reply(&next, rendered, true, &replacement.info, "");
        assert!(book.accept(&tx, &mut staged));
        assert_eq!(staged.result.render(&next).0, text);
        let different = replacement
            .handle(Request::Rename {
                address,
                name: "changed_name".into(),
            })
            .unwrap();
        assert!(matches!(different, Response::Renamed { .. }));
        let next = prepare(&mut replacement);
        let changed = book.begin(&next, Vec::new(), cutoff()).unwrap();
        assert_ne!(changed.job.binding.program, tx.job.binding.program);
        assert_eq!(
            changed.job.seed.state(address),
            crate::debug_info::EntryState::default()
        );
    }

    /// A libtest process is multithreaded, so it can never fork the isolated
    /// debug render. Its unmanaged fallback publishes exactly the inferred
    /// render with a warning, runs no optional engine work (the injected
    /// engine failure never happens) and changes no decision. The isolated
    /// successful and failing renders are covered by real workers in
    /// `tests/debug_info.rs`.
    #[cfg(target_os = "linux")]
    #[test]
    fn unmanaged_fallback_never_runs_debug_work_in_process() {
        let (_directory, path) = gcc(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/debug_opaque_session.c"
            ),
            &["-O2", "-g", "-fPIC", "-shared"],
        );
        let mut plain = LoadedProgram::open_debug(
            path.to_str().unwrap(),
            &crate::debug_info::DebugOptions {
                enabled: false,
                ..Default::default()
            },
        )
        .unwrap();
        let (_, inferred, _) = decompiled(&mut plain, "decode_session");
        let mut loaded = LoadedProgram::open(path.to_str().unwrap()).unwrap();
        crate::debug_info::ZERO_SIZE_OPAQUE.set(true);
        let (address, text, semantics) = decompiled(&mut loaded, "decode_session");
        crate::debug_info::ZERO_SIZE_OPAQUE.set(false);
        assert_eq!(text, inferred);
        assert_eq!(
            semantics.prototype_source,
            crate::semantic::PrototypeSource::Inferred
        );
        assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == OPTIONAL_UNAVAILABLE_WARNING),
            "{:?}",
            semantics.warnings
        );
        assert!(
            !semantics
                .warnings
                .iter()
                .any(|w| w == crate::debug_info::ENGINE_FAILURE_WARNING)
        );
        assert!(!loaded.debug.is_installed(address));
        assert!(loaded.debug.undecided(address));
        assert_eq!(
            loaded.debug.state(address),
            crate::debug_info::EntryState::default()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn unmanaged_fallback_leaves_callee_decisions_for_an_isolated_render() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("callees.c");
        let mut text = String::from(
            "__attribute__((noinline)) int small_callee(char *name, int count) { return name[0] + count; }\n\
             __attribute__((noinline)) int large_callee(char *name, int count) {\n volatile int total = count;\n",
        );
        for n in 0..400 {
            text.push_str(&format!(
                " total = total * {} + name[{}];\n",
                n % 7 + 2,
                n % 5
            ));
        }
        text.push_str(
            " return total;\n}\n\
             int caller(char *name) { return small_callee(name, 1) + large_callee(name, 2); }\n\
             int main(int argc, char **argv) { return caller(argv[argc - 1]); }\n",
        );
        std::fs::write(&source, text).unwrap();
        let (_image, path) = gcc(
            source.to_str().unwrap(),
            &["-O0", "-g", "-fno-pie", "-no-pie"],
        );
        let mut loaded = LoadedProgram::open(path.to_str().unwrap()).unwrap();
        let address = |name: &str| {
            loaded
                .info
                .functions
                .iter()
                .find(|f| f.name == name)
                .unwrap()
                .address
        };
        let (small, large) = (address("small_callee"), address("large_callee"));
        let (_, first, semantics) = decompiled(&mut loaded, "caller");
        assert_eq!(
            semantics.prototype_source,
            crate::semantic::PrototypeSource::Inferred
        );
        assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == OPTIONAL_UNAVAILABLE_WARNING)
        );
        // A libtest process is multithreaded, even with one test running.
        // The worker never forks and keeps both callees undecided.
        assert_eq!(
            loaded.debug.decision(small),
            crate::debug_info::Decision::Undecided
        );
        assert_eq!(
            loaded.debug.decision(large),
            crate::debug_info::Decision::Undecided
        );
        assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == "Some callee debug prototypes are unverified")
        );
        // Unavailable callee evidence can be retried twice and is never a
        // rejection, even once the separate callee attempt limit is reached.
        for _ in 0..2 {
            let prototype = loaded.debug.prepare_callee(small).unwrap();
            assert!(
                !loaded
                    .debug
                    .finish_callee(&mut loaded.program, small, prototype, None)
            );
            assert!(loaded.debug.undecided(small));
        }
        assert!(loaded.debug.prepare_callee(small).is_none());
        // Direct renders fall back the same way and decide nothing.
        let (_, _, own_small) = decompiled(&mut loaded, "small_callee");
        assert_eq!(
            own_small.prototype_source,
            crate::semantic::PrototypeSource::Inferred
        );
        assert!(loaded.debug.undecided(large));
        let (_, second, _) = decompiled(&mut loaded, "caller");
        assert!(first.contains("large_callee"), "{first}");
        assert!(second.contains("large_callee"), "{second}");
    }

    fn cached(address: u64, bytes: usize) -> CachedResult {
        CachedResult {
            address,
            renames: Vec::new(),
            context: String::new(),
            epoch: 0,
            dependencies: Vec::new(),
            text: String::new(),
            mappings: Vec::new(),
            semantics: Default::default(),
            bytes,
        }
    }

    #[test]
    fn result_cache_bounds_entries_and_bytes() {
        let mut cache = ResultCache::default();
        for address in 0..100 {
            cache.insert(cached(address, 1024));
        }
        assert_eq!(cache.entries.len(), RESULT_CACHE_ENTRIES);
        assert_eq!(cache.bytes, RESULT_CACHE_ENTRIES * 1024);
        // The oldest entries were evicted first.
        assert_eq!(cache.entries.front().unwrap().address, 36);
        // Large entries evict by bytes; an oversized one is not retained.
        for address in 200..210 {
            cache.insert(cached(address, RESULT_CACHE_MAX_ENTRY));
        }
        assert!(cache.bytes <= RESULT_CACHE_BYTES);
        assert_eq!(
            cache.bytes,
            cache.entries.iter().map(|entry| entry.bytes).sum::<usize>()
        );
        let before = cache.entries.len();
        cache.insert(cached(300, RESULT_CACHE_MAX_ENTRY + 1));
        assert_eq!(cache.entries.len(), before);
        assert!(cache.entries.iter().all(|entry| entry.address != 300));
        // A replacement for the same request keeps one entry.
        cache.insert(cached(209, 10));
        assert_eq!(
            cache
                .entries
                .iter()
                .filter(|entry| entry.address == 209)
                .count(),
            1
        );
        cache.clear();
        assert_eq!((cache.entries.len(), cache.bytes), (0, 0));
    }
}
