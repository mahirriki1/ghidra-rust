use serde::{Deserialize, Serialize};

/// Enforced by both the worker and the desktop before syntax-cache construction.
pub const MAX_DECOMPILED_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CODE_MAPPINGS: usize = 32_768;
pub const MAX_MAPPING_ADDRESSES: usize = 64;
pub const MAX_CODE_ADDRESS_REFS: usize = 131_072;
pub const MAX_STRING_RESULTS: usize = 10_000;
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
