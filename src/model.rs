use serde::{Deserialize, Serialize};

/// Enforced by both the worker and the desktop before syntax-cache construction.
pub const MAX_DECOMPILED_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CODE_MAPPINGS: usize = 32_768;
pub const MAX_MAPPING_ADDRESSES: usize = 64;
pub const MAX_CODE_ADDRESS_REFS: usize = 131_072;

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
