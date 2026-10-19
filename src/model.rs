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
pub const MIN_STRING_LENGTH: usize = 4;
pub const MAX_STRING_MINIMUM: usize = 64;
pub const MAX_ANALYSIS_FUNCTIONS: usize = 128;
pub const MAX_ANALYSIS_INSTRUCTIONS: usize = 16_384;
pub const MAX_CALL_REFERENCES: usize = 16_384;
pub const MAX_DATA_REFERENCES: usize = 16_384;
pub const MAX_DATA_OPERATIONS: usize = 131_072;
pub const MAX_DATA_OPERATIONS_PER_INSTRUCTION: usize = 256;
pub const MAX_DATA_OPERATION_INPUTS: usize = 16;
pub const MAX_DATA_ACCESS_BYTES: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataAccess {
    Read,
    Write,
}

/// A direct memory access established by instruction-local engine p-code.
/// This does not classify the target as a data object or runtime pointer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DataReference {
    pub function: u64,
    pub address: u64,
    pub target: u64,
    pub size: u32,
    pub access: DataAccess,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DataAnalysis {
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

/// A fresh worker computation. References are deliberately session-only; project
/// snapshots retain the existing function inventory with saved-result provenance.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallAnalysis {
    pub references: Vec<CallReference>,
    /// Optional for legacy protocol replies; absent evidence is not a fresh
    /// empty computation. Neither reference class is stored in projects.
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

/// UTF-8 byte span in rendered C and its originating machine instructions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CodeMapping {
    pub start: usize,
    pub end: usize,
    pub addresses: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub sections: Vec<SectionInfo>,
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub functions_truncated: bool,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub address: u64,
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    Branch,
    True,
    False,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub source: u64,
    pub target: Option<u64>,
    pub kind: EdgeKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallSite {
    pub address: u64,
    pub target: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionView {
    pub address: u64,
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<Edge>,
    pub calls: Vec<CallSite>,
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
    Open { path: String },
    Graph { address: u64 },
    Decompile { address: u64 },
    Discover,
    Rename { address: u64, name: String },
    Bytes { address: u64, length: usize },
    Strings,
    StringsWithOptions { minimum_length: usize },
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
        mappings: Vec<CodeMapping>,
    },
    Functions {
        functions: Vec<FunctionInfo>,
        truncated: bool,
        analysis: CallAnalysis,
    },
    Progress {
        progress: AnalysisProgress,
    },
    Renamed {
        address: u64,
        name: String,
    },
    Bytes {
        address: u64,
        bytes: Vec<u8>,
    },
    Strings {
        strings: Vec<StringEntry>,
        truncated: bool,
    },
    Crypto {
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
}
