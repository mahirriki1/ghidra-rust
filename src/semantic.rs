//! Bounded semantic tokens. Persistent identities contain no engine arena IDs.
use crate::model::SectionInfo;
use crate::selection::ExecutableRanges;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const LOCAL_FINGERPRINT: &str = "local-storage-use-v1:268c3a406d8d964bc00ae2ead4d3e1e1373aaa27";
pub const MAX_TOKENS: usize = 32_768;
pub const MAX_LOCALS: usize = 4096;
pub const MAX_LOCAL_RENAMES: usize = 4096;
pub const MAX_FUNCTION_RENAMES: usize = 64;
pub const MAX_LOCAL_NAME: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalStorage {
    Stack,
    Register,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalIdentity {
    pub function: u64,
    pub engine: String,
    pub storage: LocalStorage,
    pub offset: u64,
    pub size: u32,
    /// Hash of storage/use limits, type, and every recovered SSA definition/use.
    pub verification: String,
}
impl LocalIdentity {
    pub fn validate(&self) -> Result<(), String> {
        if self.storage == LocalStorage::Register
            && self.offset.checked_add(u64::from(self.size)).is_none()
        {
            return Err("Local register storage range overflows".into());
        }
        if self.engine.len() > 96
            || self.engine.is_empty()
            || !self
                .engine
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || self.size == 0
            || self.size > 256
            || self.verification.len() != 64
            || !self
                .verification
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("Invalid local-variable identity".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRename {
    pub identity: LocalIdentity,
    pub name: String,
}

pub fn validate_name(name: &str) -> Result<(), String> {
    let mut bytes = name.bytes();
    if name.len() > MAX_LOCAL_NAME
        || !bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err("Local names must be C identifiers of 1–64 ASCII bytes".into());
    }
    // Reject names the C printer cannot distinguish from syntax.
    if [
        "auto",
        "break",
        "case",
        "char",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "float",
        "for",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "struct",
        "switch",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
        "_Bool",
        "_Complex",
        "_Imaginary",
    ]
    .contains(&name)
    {
        return Err("Local name is a reserved C keyword".into());
    }
    Ok(())
}

pub fn validate_renames(renames: &[LocalRename], function: Option<u64>) -> Result<(), String> {
    if renames.len()
        > if function.is_some() {
            MAX_FUNCTION_RENAMES
        } else {
            MAX_LOCAL_RENAMES
        }
    {
        return Err("Local rename count exceeds its limit".into());
    }
    let mut identities = BTreeSet::new();
    let mut counts = std::collections::BTreeMap::new();
    for rename in renames {
        rename.identity.validate()?;
        validate_name(&rename.name)?;
        if function.is_some_and(|f| f != rename.identity.function)
            || !identities.insert(&rename.identity)
        {
            return Err("Duplicate or cross-function local rename identity".into());
        }
        let count = counts.entry(rename.identity.function).or_insert(0);
        *count += 1;
        if *count > MAX_FUNCTION_RENAMES {
            return Err("Too many local renames in one function".into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalVariable {
    pub identity: LocalIdentity,
    pub name: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TokenKind {
    Call {
        target: u64,
    },
    /// None means the engine printed a local but cannot provide a supported identity.
    Local {
        local: Option<usize>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SemanticToken {
    pub start: usize,
    pub end: usize,
    #[serde(flatten)]
    pub kind: TokenKind,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SemanticInfo {
    #[serde(
        default,
        deserialize_with = "crate::bounded::vec::<_, _, { MAX_TOKENS }>"
    )]
    pub tokens: Vec<SemanticToken>,
    #[serde(
        default,
        deserialize_with = "crate::bounded::vec::<_, _, { MAX_LOCALS }>"
    )]
    pub locals: Vec<LocalVariable>,
    #[serde(
        default,
        deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTION_RENAMES }>"
    )]
    pub warnings: Vec<String>,
}
impl SemanticInfo {
    pub fn token_at(&self, byte: usize) -> Option<&SemanticToken> {
        self.tokens
            .get(self.tokens.partition_point(|t| t.end <= byte))
            .filter(|t| t.start <= byte && byte < t.end)
    }
    pub fn validate(
        &self,
        text: &str,
        function: u64,
        sections: &[SectionInfo],
    ) -> Result<(), String> {
        if self.tokens.len() > MAX_TOKENS
            || self.locals.len() > MAX_LOCALS
            || self.warnings.len() > MAX_FUNCTION_RENAMES
            || self.warnings.iter().any(|w| w.len() > 256)
        {
            return Err("Semantic metadata exceeds its limits".into());
        }
        let executable = ExecutableRanges::new(sections)?;
        if !executable.contains(function) {
            return Err("Invalid semantic function address".into());
        }
        let mut identities = BTreeSet::new();
        for local in &self.locals {
            local.identity.validate()?;
            if local.identity.function != function
                || local.name.len() > 256
                || local.name.is_empty()
                || !identities.insert(&local.identity)
            {
                return Err("Invalid, incompatible, or duplicate semantic local identity".into());
            }
        }
        let mut previous = 0;
        for token in &self.tokens {
            if token.start < previous
                || token.start >= token.end
                || token.end > text.len()
                || !text.is_char_boundary(token.start)
                || !text.is_char_boundary(token.end)
            {
                return Err("Invalid or overlapping semantic token byte range".into());
            }
            match token.kind {
                TokenKind::Call { target } if !executable.contains(target) => {
                    return Err("Unmapped semantic call target".into());
                }
                TokenKind::Local { local: Some(index) } => {
                    let local = self
                        .locals
                        .get(index)
                        .ok_or("Invalid semantic local reference")?;
                    if text[token.start..token.end] != local.name {
                        return Err("Semantic local token differs from its symbol name".into());
                    }
                }
                _ => (),
            }
            previous = token.end;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> LocalIdentity {
        LocalIdentity {
            function: 0x1000,
            engine: LOCAL_FINGERPRINT.into(),
            storage: LocalStorage::Stack,
            offset: u64::MAX - 7,
            size: 4,
            verification: "a".repeat(64),
        }
    }
    #[test]
    fn tokens_reject_overlap_utf8_misbound_variables_and_unmapped_targets() {
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: 16,
            file_size: 16,
            file_offset: 0,
            executable: true,
        }];
        let mut info = SemanticInfo {
            tokens: vec![SemanticToken {
                start: 0,
                end: 2,
                kind: TokenKind::Local { local: Some(0) },
            }],
            locals: vec![LocalVariable {
                identity: identity(),
                name: "é".into(),
            }],
            warnings: vec![],
        };
        info.validate("é call", 0x1000, &sections).unwrap();
        info.tokens[0].end = 1;
        assert!(info.validate("é call", 0x1000, &sections).is_err());
        info.tokens[0].end = 2;
        info.locals[0].name = "other".into();
        assert!(info.validate("é call", 0x1000, &sections).is_err());
        info.locals[0].name = "é".into();
        info.locals[0].identity.function = 0x1001;
        assert!(info.validate("é call", 0x1000, &sections).is_err());
        info.locals[0].identity.function = 0x1000;
        info.locals.push(info.locals[0].clone());
        assert!(info.validate("é call", 0x1000, &sections).is_err());
        info.locals.pop();
        info.tokens.push(info.tokens[0].clone());
        assert!(info.validate("é call", 0x1000, &sections).is_err());
        info.tokens = vec![SemanticToken {
            start: 3,
            end: 7,
            kind: TokenKind::Call { target: 0x2000 },
        }];
        assert!(info.validate("é call", 0x1000, &sections).is_err());
        info.tokens[0].kind = TokenKind::Local { local: Some(99) };
        assert!(info.validate("é call", 0x1000, &sections).is_err());
    }
    #[test]
    fn maximum_per_function_replay_fits_the_worker_request_budget() {
        let renames: Vec<_> = (0..MAX_FUNCTION_RENAMES)
            .map(|offset| {
                let mut id = identity();
                id.offset = offset as u64;
                LocalRename {
                    identity: id,
                    name: "a".repeat(MAX_LOCAL_NAME),
                }
            })
            .collect();
        validate_renames(&renames, Some(0x1000)).unwrap();
        let bytes = serde_json::to_vec(&crate::model::WorkerRequest {
            id: u64::MAX,
            request: crate::model::Request::DecompileWithLocals {
                address: 0x1000,
                renames,
            },
        })
        .unwrap();
        assert!(bytes.len() < 60 * 1024);
    }
}
