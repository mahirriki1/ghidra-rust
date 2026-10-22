use serde::{Deserialize, Serialize};

/// Enforced by both the worker and the desktop before syntax-cache construction.
pub const MAX_DECOMPILED_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CODE_MAPPINGS: usize = 32_768;
pub const MAX_MAPPING_ADDRESSES: usize = 64;
pub const MAX_CODE_ADDRESS_REFS: usize = 131_072;
pub const MAX_STRING_RESULTS: usize = 10_000;
/// Function inventory ceiling shared by loaders, worker replies, projects, and
/// reference validation. Large x64 PEs near the 128 MiB input limit can carry
/// over 260,000 runtime functions. Discovery has its own smaller work budgets.
pub const MAX_FUNCTIONS: usize = 262_144;
pub const MAX_FUNCTION_NAME_BYTES: usize = 256;
/// Total JSON-escaped bytes of all inventory names, excluding quotation marks.
/// With 43 bytes per entry for structure and 20-digit addresses, a full
/// inventory serializes to at most 43 * 262_144 + 8 MiB + 1 bytes (19.7 MB).
pub const MAX_FUNCTION_NAME_JSON_BYTES: usize = 8 * 1024 * 1024;
/// Largest encoded worker reply, excluding its newline. Fits the largest
/// function inventory (19.7 MB) with either both reference classes (about
/// 4.1 MB) or worst-case section metadata (6.8 MB).
pub const MAX_REPLY_BYTES: usize = 32 * 1024 * 1024;
/// Largest byte range one `Bytes` request may read.
pub const MAX_BYTE_READ: usize = 64 * 1024;
/// Deserialization caps for collections shared by worker replies and projects.
/// Tighter semantic limits are validated after decoding.
pub const MAX_SECTIONS: usize = 4096;
pub const MAX_WARNINGS: usize = 128;
pub const MAX_GRAPH_BLOCKS: usize = 128;
pub const MAX_GRAPH_EDGES: usize = 4096;
pub const MAX_GRAPH_CALLS: usize = 2048;
pub const MAX_GRAPH_INSTRUCTIONS: usize = 2048;
pub const MAX_INSTRUCTION_BYTES: usize = 32;
pub const MAX_PROJECT_STRINGS: usize = 20_000;
pub const MAX_CRYPTO_MATCHES: usize = 10_000;
pub const MIN_STRING_LENGTH: usize = 4;
pub const MAX_STRING_MINIMUM: usize = 64;
/// Per request, never a cumulative session ceiling.
pub const MAX_ANALYSIS_FUNCTIONS: usize = 128;
/// Interrupted batches retry each affected seed individually at most once.
pub const MAX_DISCOVERY_INTERRUPTION_ATTEMPTS: usize = 2;
/// Sixteen worst-case JSON-escaped 256-byte names fit below 60 KiB requests.
pub const MAX_DISCOVERY_SYNC_FUNCTIONS: usize = 16;
pub const MAX_ANALYSIS_INSTRUCTIONS: usize = 16_384;
/// Executable bytes inspected by one function-start pattern request.
pub const MAX_PATTERN_SCAN_BYTES: u64 = 1024 * 1024;
/// Pattern matching is chunked so a match flood has a local bound.
pub const PATTERN_SCAN_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_PATTERN_MATCHES_PER_CHUNK: usize = 4_096;
pub const MAX_PATTERN_MATCHES: usize =
    MAX_PATTERN_MATCHES_PER_CHUNK * (MAX_PATTERN_SCAN_BYTES as usize / PATTERN_SCAN_CHUNK_BYTES);
pub const MAX_PATTERN_VALIDATIONS: usize = 128;
/// Parent-accepted replies that perform pattern cursor work. Coverage-only
/// preparation is accounted separately by its distinct function identities.
/// A maximum-size image needs at most 128 ordinary 1 MiB scan replies.
pub const MAX_PATTERN_CURSOR_STEPS: usize = 256;
/// Cursor replies that claim an uncharged match-point resume. Keeping this
/// separate prevents coverage preparation from replenishing the smaller bound.
pub const MAX_PATTERN_RESUME_STEPS: usize = 64;
/// Complete inventory rows the parent will reconstruct and validate while the
/// pattern phase is active. Unchanged inventories cost no rows. This admits an
/// initial full inventory and several replacement-worker epochs while bounding
/// repeated full replacements or tiny deltas that force complete validation.
pub const MAX_PATTERN_INVENTORY_VALIDATION_ROWS: usize = MAX_FUNCTIONS * 8;
/// Every prepared function consumes at least one decode attempt. The identities
/// let the parent reject repeated coverage claims from one worker epoch.
pub const MAX_PATTERN_COVERAGE: usize = MAX_ANALYSIS_INSTRUCTIONS;
/// Shared per-batch and session aggregate evidence caps. Reaching an aggregate
/// cap marks coverage partial; seed processing can still continue.
pub const MAX_CALL_REFERENCES: usize = 16_384;
pub const MAX_DATA_REFERENCES: usize = 16_384;
pub const MAX_DATA_OPERATIONS: usize = 131_072;
pub const MAX_DATA_OPERATIONS_PER_INSTRUCTION: usize = 256;
pub const MAX_DATA_OPERATION_INPUTS: usize = 16;
pub const MAX_DATA_ACCESS_BYTES: u32 = 64;
/// Compact p-code operations retained per function for block-local propagation.
pub const MAX_DATA_RETAINED_OPERATIONS: usize = 16_384;
/// Register/unique byte ranges with known constant values at any point.
pub const MAX_DATA_TRACKED_VALUES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataAccess {
    Read,
    Write,
}

/// How a data reference's pointer was established.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataProvenance {
    /// The accessing instruction's own p-code yields a constant pointer.
    #[default]
    InstructionLocal,
    /// The pointer depends on register constants established by earlier
    /// instructions of the same basic block (AArch64 only).
    Propagated,
}

/// A direct memory access established from engine p-code.
/// This does not classify the target as a data object or runtime pointer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DataReference {
    pub function: u64,
    pub address: u64,
    pub target: u64,
    pub size: u32,
    pub access: DataAccess,
    /// Absent in replies from earlier workers, which were instruction-local only.
    #[serde(default)]
    pub provenance: DataProvenance,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DataAnalysis {
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_DATA_REFERENCES }>")]
    pub references: Vec<DataReference>,
    pub operations_charged: usize,
    pub accesses_examined: usize,
    pub unresolved_accesses: usize,
    pub omitted_accesses: usize,
    pub unsupported_instructions: usize,
    pub partial: bool,
}

/// An established direct call decoded from `address` while walking `caller`.
/// This records machine-code evidence, not a recovered source-language call.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CallReference {
    pub caller: u64,
    pub address: u64,
    pub target: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AnalysisStage {
    Seeds,
    Calls,
    Publish,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisProgress {
    pub stage: AnalysisStage,
    pub functions_examined: usize,
    pub decode_attempts: usize,
}

/// A fresh worker computation, or a discovery session's cumulative aggregate.
/// Projects store aggregates only through `discovery::DiscoverySnapshot`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallAnalysis {
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_CALL_REFERENCES }>")]
    pub references: Vec<CallReference>,
    /// Optional for legacy protocol replies; absent evidence is not a fresh
    /// empty computation.
    #[serde(default)]
    pub data: Option<DataAnalysis>,
    pub functions_examined: usize,
    /// Charged decode attempts, including failures and instructions omitted by
    /// display limits. This is a work count, not the size of a displayed graph.
    pub decode_attempts: usize,
    pub unresolved_calls: usize,
    pub skipped_fallthrough_calls: usize,
    pub failed_functions: usize,
    pub partial: bool,
}

/// Parent session identity, echoed by a disposable worker. Request IDs are
/// additionally checked by the transport and the desktop's pending request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryBinding {
    pub generation: u64,
    pub epoch: u64,
    pub revision: u64,
    pub batch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryStatus {
    Done,
    PartialByOwnLimit,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryOutcome {
    pub address: u64,
    pub status: DiscoveryStatus,
}

/// A worker's function inventory relative to the revision the parent last
/// adopted from it. Revisions are scoped to one worker process.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum InventoryChange {
    /// Identical to the requested base.
    Unchanged { revision: u64 },
    /// The requested base with strictly ordered, disjoint upserts and removals.
    Delta {
        base: u64,
        revision: u64,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
        upserts: Vec<FunctionInfo>,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
        removals: Vec<u64>,
    },
    /// The complete inventory, sent when the parent holds no matching base.
    Replace {
        revision: u64,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
        functions: Vec<FunctionInfo>,
    },
}

impl InventoryChange {
    pub fn revision(&self) -> u64 {
        match self {
            Self::Unchanged { revision }
            | Self::Delta { revision, .. }
            | Self::Replace { revision, .. } => *revision,
        }
    }

    /// The complete inventory this change produces from `base`, which must be
    /// the inventory adopted at the revision the request named. Unchanged rows
    /// are moved or shared, never revalidated here; callers validate the result.
    pub fn apply(
        self,
        base: Option<(u64, &[FunctionInfo])>,
    ) -> Result<Option<Vec<FunctionInfo>>, String> {
        match self {
            Self::Replace { functions, .. } => Ok(Some(functions)),
            Self::Unchanged { revision } => match base {
                Some((current, _)) if current == revision => Ok(None),
                _ => Err("Unchanged inventory does not match the adopted revision".into()),
            },
            Self::Delta {
                base: from,
                revision,
                upserts,
                removals,
            } => {
                let Some((current, functions)) = base.filter(|(current, _)| *current == from)
                else {
                    return Err("Inventory delta does not match the adopted revision".into());
                };
                if revision
                    != current
                        .checked_add(1)
                        .ok_or("Inventory revision overflow")?
                    || upserts.len().saturating_add(removals.len()) > MAX_FUNCTIONS
                    || upserts.is_empty() && removals.is_empty()
                    || upserts
                        .windows(2)
                        .any(|pair| pair[0].address >= pair[1].address)
                    || removals.windows(2).any(|pair| pair[0] >= pair[1])
                    || upserts
                        .iter()
                        .any(|function| function.name.len() > MAX_FUNCTION_NAME_BYTES)
                {
                    return Err("Invalid inventory delta bounds or ordering".into());
                }
                let mut merged = Vec::with_capacity(
                    (functions.len() + upserts.len()).min(MAX_FUNCTIONS.saturating_add(1)),
                );
                let mut upserts = upserts.into_iter().peekable();
                let mut removals = removals.into_iter().peekable();
                let mut rows = functions.iter().peekable();
                loop {
                    let next = [
                        rows.peek().map(|row| row.address),
                        upserts.peek().map(|row| row.address),
                        removals.peek().copied(),
                    ]
                    .into_iter()
                    .flatten()
                    .min();
                    let Some(address) = next else { break };
                    let existing = rows.next_if(|row| row.address == address);
                    let upsert = upserts.next_if(|row| row.address == address);
                    let removed = removals.next_if_eq(&address).is_some();
                    match (existing, upsert, removed) {
                        (Some(_), None, true) => {}
                        (Some(row), None, false) => merged.push(row.clone()),
                        (_, Some(row), false) => merged.push(row),
                        _ => return Err("Inventory delta removes an absent or upserted row".into()),
                    }
                    if merged.len() > MAX_FUNCTIONS {
                        return Err("Inventory delta exceeds the function limit".into());
                    }
                }
                Ok(Some(merged))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveryBatch {
    pub binding: DiscoveryBinding,
    pub inventory: InventoryChange,
    pub truncated: bool,
    pub analysis: CallAnalysis,
    /// The examined prefix of the request's seeds; the suffix remains pending.
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_ANALYSIS_FUNCTIONS }>")]
    pub outcomes: Vec<DiscoveryOutcome>,
    /// Present exactly for a pattern-scan request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patterns: Option<PatternScan>,
}

/// Function starts admitted by one pattern-scan request.
pub const MAX_PATTERN_ADMISSIONS: usize = 128;

/// One bounded step of the function-start pattern scan. Admitted starts are
/// in the reply's inventory and become ordinary discovery seeds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternScan {
    /// Where the next request continues; `None` when the scan is complete.
    pub next: Option<u64>,
    pub scanned_bytes: u64,
    pub matches: usize,
    /// Candidates whose code was decoded and checked.
    pub validated: usize,
    /// Strictly increasing new function starts.
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_PATTERN_ADMISSIONS }>")]
    pub admitted: Vec<u64>,
    /// Strictly increasing established function entries decoded to learn which
    /// bytes are already code. Each identity may appear once per worker epoch.
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_PATTERN_COVERAGE }>")]
    pub covered: Vec<u64>,
    /// Limits or failures left part of the scan unexamined.
    pub partial: bool,
}

/// UTF-8 byte span in rendered C and its originating machine instructions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeMapping {
    pub start: usize,
    pub end: usize,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_MAPPING_ADDRESSES }>")]
    pub addresses: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionInfo {
    pub address: u64,
    pub name: String,
}

/// Bytes `serde_json` emits for `text` inside a string literal, excluding quotes.
pub fn json_escaped_len(text: &str) -> usize {
    text.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
            c if (c as u32) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum()
}

/// Exact lookup in an inventory validated by [`validate_functions`].
pub fn function_at(functions: &[FunctionInfo], address: u64) -> Option<&FunctionInfo> {
    functions
        .binary_search_by_key(&address, |function| function.address)
        .ok()
        .map(|index| &functions[index])
}

/// Count, ordering, and name bounds that make [`function_at`] valid. Worker
/// inventories also respect the aggregate escaped-name budget; legacy projects
/// pass `max_name_bytes` matching their original, larger per-name bound.
pub fn validate_functions(
    functions: &[FunctionInfo],
    max_name_bytes: usize,
    name_budget: bool,
) -> Result<(), String> {
    if functions.len() > MAX_FUNCTIONS {
        return Err(format!(
            "Function inventory exceeds the {MAX_FUNCTIONS}-entry limit"
        ));
    }
    let mut escaped = 0usize;
    for (index, function) in functions.iter().enumerate() {
        if index > 0 && functions[index - 1].address >= function.address {
            return Err("Function inventory is not strictly ordered by address".into());
        }
        if function.name.len() > max_name_bytes {
            return Err("Function name exceeds its length limit".into());
        }
        escaped = escaped.saturating_add(json_escaped_len(&function.name));
    }
    if name_budget && escaped > MAX_FUNCTION_NAME_JSON_BYTES {
        return Err("Function names exceed the inventory byte budget".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub executable: bool,
}

impl SectionInfo {
    /// Whether `[address, address + length)` lies in this section's
    /// file-backed bytes.
    pub fn backs(&self, address: u64, length: u64) -> bool {
        address
            .checked_sub(self.address)
            .and_then(|offset| offset.checked_add(length))
            .is_some_and(|end| end <= self.size.min(self.file_size))
    }
}

/// Identity of an opened file, independent of its current pathname.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    /// Upper half of Windows' 128-bit file ID; zero for Unix inode numbers.
    #[serde(default)]
    pub inode_high: u64,
}

impl FileIdentity {
    pub fn from_file(file: &std::fs::File) -> Option<Self> {
        #[cfg(windows)]
        {
            crate::windows::file_identity(file).ok()
        }
        #[cfg(not(windows))]
        {
            Self::from_metadata(&file.metadata().ok()?)
        }
    }

    pub fn from_metadata(metadata: &std::fs::Metadata) -> Option<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(Self {
                device: metadata.dev(),
                inode: metadata.ino(),
                inode_high: 0,
            })
        }
        #[cfg(not(unix))]
        {
            let _ = metadata;
            None
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    pub architecture: String,
    pub format: String,
    pub entry: u64,
    pub file_len: u64,
    pub sha256: String,
    pub source_identity: Option<FileIdentity>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_SECTIONS }>")]
    pub sections: Vec<SectionInfo>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub functions_truncated: bool,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_WARNINGS }>")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_INSTRUCTION_BYTES }>")]
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub address: u64,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_GRAPH_INSTRUCTIONS }>")]
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Branch,
    True,
    False,
    Unknown,
}

/// Analysis evidence beyond the instruction's own encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeEvidence {
    /// A destination of a switch table recovered by engine flow analysis.
    EngineJumpTable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub source: u64,
    pub target: Option<u64>,
    pub kind: EdgeKind,
    /// Absent in projects saved before switch recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EdgeEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallSite {
    pub address: u64,
    pub target: Option<u64>,
    /// Why the call never returns; its block then has no successor. Absent
    /// in projects saved before no-return analysis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_return: Option<NoReturnEvidence>,
}

/// The identity that establishes a call never returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NoReturnEvidence {
    /// The target is a named no-return function or import stub.
    NamedTarget,
    /// The call reads, directly or through an exact thunk, the import address
    /// table slot of a named no-return import (or a verified ELF startup slot).
    ImportSlot { slot: u64 },
}

impl NoReturnEvidence {
    pub fn description(self) -> String {
        match self {
            Self::NamedTarget => {
                "Does not return: original function/import identity matches the no-return list"
                    .into()
            }
            Self::ImportSlot { slot } => {
                format!("Does not return: named import through slot {slot:#x}")
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionView {
    pub address: u64,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_GRAPH_BLOCKS }>")]
    pub blocks: Vec<BasicBlock>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_GRAPH_EDGES }>")]
    pub edges: Vec<Edge>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_GRAPH_CALLS }>")]
    pub calls: Vec<CallSite>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_WARNINGS }>")]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringEntry {
    pub address: u64,
    pub text: String,
    pub encoding: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CryptoMatch {
    pub address: u64,
    pub algorithm: String,
    pub signature: String,
    pub length: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    Open {
        path: String,
    },
    Graph {
        address: u64,
    },
    Decompile {
        address: u64,
    },
    DecompileWithLocals {
        address: u64,
        #[serde(
            deserialize_with = "crate::bounded::vec::<_, _, { crate::semantic::MAX_FUNCTION_RENAMES }>"
        )]
        renames: Vec<crate::semantic::LocalRename>,
    },
    Discover,
    DiscoverBatch {
        binding: DiscoveryBinding,
        /// Inventory revision the parent adopted from this worker, if any.
        #[serde(default)]
        inventory_base: Option<u64>,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_ANALYSIS_FUNCTIONS }>")]
        seeds: Vec<u64>,
        /// With no seeds: continue the function-start pattern scan from this
        /// address instead of walking functions.
        #[serde(default)]
        patterns: Option<u64>,
    },
    SyncFunctions {
        #[serde(
            deserialize_with = "crate::bounded::vec::<_, _, { MAX_DISCOVERY_SYNC_FUNCTIONS }>"
        )]
        functions: Vec<FunctionInfo>,
    },
    Rename {
        address: u64,
        name: String,
    },
    Bytes {
        address: u64,
        length: usize,
    },
    Strings,
    StringsWithOptions {
        minimum_length: usize,
    },
    Crypto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Opened {
        info: BinaryInfo,
    },
    Graph {
        view: FunctionView,
    },
    Decompiled {
        address: u64,
        text: String,
        #[serde(default)]
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_CODE_MAPPINGS }>")]
        mappings: Vec<CodeMapping>,
        #[serde(default)]
        semantics: crate::semantic::SemanticInfo,
    },
    Functions {
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
        functions: Vec<FunctionInfo>,
        truncated: bool,
        analysis: CallAnalysis,
    },
    DiscoveryBatch {
        batch: DiscoveryBatch,
    },
    FunctionsSynced,
    Progress {
        progress: AnalysisProgress,
    },
    Renamed {
        address: u64,
        name: String,
    },
    Bytes {
        address: u64,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_BYTE_READ }>")]
        bytes: Vec<u8>,
    },
    Strings {
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_PROJECT_STRINGS }>")]
        strings: Vec<StringEntry>,
        truncated: bool,
    },
    Crypto {
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_CRYPTO_MATCHES }>")]
        matches: Vec<CryptoMatch>,
        truncated: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub id: u64,
    pub request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub id: u64,
    pub response: Response,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_length_matches_serde_json() {
        for text in [
            "",
            "plain",
            "q\"b\\",
            "\n\r\t\u{8}\u{c}",
            "\u{0}\u{1f}\u{7f}",
            "é漢🦀",
        ] {
            assert_eq!(
                json_escaped_len(text) + 2,
                serde_json::to_string(text).unwrap().len(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn inventory_validation_requires_order_count_and_budget() {
        let function = |address, name: &str| FunctionInfo {
            address,
            name: name.into(),
        };
        let ordered = vec![function(1, "a"), function(2, "b")];
        validate_functions(&ordered, 1, true).unwrap();
        assert_eq!(function_at(&ordered, 2).unwrap().name, "b");
        assert!(function_at(&ordered, 3).is_none());
        assert!(validate_functions(&[function(2, "b"), function(1, "a")], 1, true).is_err());
        assert!(validate_functions(&[function(1, "a"), function(1, "b")], 1, true).is_err());
        assert!(validate_functions(&[function(1, "ab")], 1, true).is_err());
        let long = "\u{1}".repeat(MAX_FUNCTION_NAME_BYTES);
        let count = MAX_FUNCTION_NAME_JSON_BYTES / json_escaped_len(&long) + 1;
        let heavy: Vec<_> = (0..count as u64).map(|a| function(a, &long)).collect();
        assert!(validate_functions(&heavy, MAX_FUNCTION_NAME_BYTES, true).is_err());
        validate_functions(&heavy, MAX_FUNCTION_NAME_BYTES, false).unwrap();
        let many: Vec<_> = (0..=MAX_FUNCTIONS as u64)
            .map(|a| function(a, ""))
            .collect();
        assert!(validate_functions(&many, 1, false).is_err());
    }

    #[test]
    fn pattern_coverage_reply_is_bounded_while_decoding() {
        let scan = PatternScan {
            covered: vec![0; MAX_PATTERN_COVERAGE + 1],
            ..Default::default()
        };
        let encoded = serde_json::to_value(scan).unwrap();
        assert!(serde_json::from_value::<PatternScan>(encoded).is_err());
    }
}
