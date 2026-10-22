//! Bounded, address-owned function prototypes applied through public engine APIs.
use crate::model::BinaryInfo;
pub use crate::semantic::{SIGNATURE_LOCAL_FINGERPRINT, local_fingerprint};
use ghidra_decompiler::{
    address::Address,
    architecture::Architecture,
    error::Error,
    fspec::{ParameterPieces, PrototypePieces, assign_storage_glb},
    funcdata::Funcdata,
    program::Program,
    types::{TypeFactory, TypeId, TypeMetatype},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_SIGNATURES: usize = 64;
pub const MAX_PARAMETERS: usize = 32;
pub const MAX_TOTAL_PARAMETERS: usize = 256;
pub const MAX_SIGNATURE_BYTES: usize = 48 * 1024;
pub const MAX_POINTER_DEPTH: u8 = 4;
pub const MAX_INFERRED_NOTES: usize = MAX_PARAMETERS + 8;
pub const SIGNATURE_FINGERPRINT: &str = "signature-v1:268c3a406d8d964bc00ae2ead4d3e1e1373aaa27";
const MAX_CONTEXT: usize = 96;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureBase {
    Void,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureType {
    pub base: SignatureBase,
    pub pointer_depth: u8,
}
impl SignatureType {
    pub fn validate(&self) -> Result<(), String> {
        if self.pointer_depth > MAX_POINTER_DEPTH {
            return Err("Signature pointer depth exceeds four".into());
        }
        Ok(())
    }
    pub fn is_void(&self) -> bool {
        self.base == SignatureBase::Void && self.pointer_depth == 0
    }
}
impl std::fmt::Display for SignatureType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.base {
            SignatureBase::Void => "void",
            SignatureBase::I8 => "int8_t",
            SignatureBase::U8 => "uint8_t",
            SignatureBase::I16 => "int16_t",
            SignatureBase::U16 => "uint16_t",
            SignatureBase::I32 => "int32_t",
            SignatureBase::U32 => "uint32_t",
            SignatureBase::I64 => "int64_t",
            SignatureBase::U64 => "uint64_t",
        })?;
        for _ in 0..self.pointer_depth {
            f.write_str(" *")?;
        }
        Ok(())
    }
}

fn short_string<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    struct Short;
    impl serde::de::Visitor<'_> for Short {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a string of at most 256 bytes")
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<String, E> {
            if s.len() > 256 {
                return Err(E::custom("Signature string exceeds 256 bytes"));
            }
            Ok(s.to_owned())
        }
    }
    d.deserialize_str(Short)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureParameter {
    #[serde(deserialize_with = "short_string")]
    pub name: String,
    pub ty: SignatureType,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionSignature {
    pub function: u64,
    #[serde(deserialize_with = "short_string")]
    pub engine: String,
    #[serde(deserialize_with = "short_string")]
    pub abi: String,
    pub return_type: SignatureType,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_PARAMETERS }>")]
    pub parameters: Vec<SignatureParameter>,
}
fn validate_context(s: &str) -> Result<(), String> {
    if s.is_empty()
        || s.len() > MAX_CONTEXT
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        return Err("Invalid signature engine or ABI identifier".into());
    }
    Ok(())
}
impl FunctionSignature {
    /// Structural validation deliberately permits saved incompatible engine/ABI IDs.
    pub fn validate(&self) -> Result<(), String> {
        validate_context(&self.engine)?;
        validate_context(&self.abi)?;
        self.return_type.validate()?;
        if self.parameters.len() > MAX_PARAMETERS {
            return Err("Signature has too many parameters".into());
        }
        let mut names = BTreeSet::new();
        for parameter in &self.parameters {
            crate::semantic::validate_name(&parameter.name)?;
            parameter.ty.validate()?;
            if parameter.ty.is_void() || !names.insert(&parameter.name) {
                return Err("Signature parameters need distinct names and non-void types".into());
            }
        }
        Ok(())
    }
}
pub fn validate_signatures(signatures: &[FunctionSignature]) -> Result<(), String> {
    if signatures.len() > MAX_SIGNATURES {
        return Err("Too many function signatures".into());
    }
    let mut entries = BTreeSet::new();
    let mut parameters = 0;
    for signature in signatures {
        signature.validate()?;
        parameters += signature.parameters.len();
        if parameters > MAX_TOTAL_PARAMETERS || !entries.insert(signature.function) {
            return Err("Duplicate signature entry or too many total parameters".into());
        }
    }
    if serde_json::to_vec(signatures)
        .map_err(|e| e.to_string())?
        .len()
        > MAX_SIGNATURE_BYTES
    {
        return Err("Function signatures exceed the 48 KiB limit".into());
    }
    Ok(())
}

/// Order independent digest of the complete signature state (including empty state).
pub fn state_digest(signatures: &[FunctionSignature]) -> String {
    let mut sorted: Vec<_> = signatures.iter().collect();
    sorted.sort_by_key(|s| s.function);
    let bytes = serde_json::to_vec(&sorted).expect("Signature serialization cannot fail");
    format!("{:x}", Sha256::digest(bytes))
}

pub fn current_abi(info: &BinaryInfo) -> Result<String, String> {
    let pe = match info.format.as_str() {
        "PE" => true,
        "ELF" | "Mach-O" => false,
        _ => return Err("Unsupported signature binary format".into()),
    };
    let language = match info.architecture.as_str() {
        "x86" if pe => "x86:LE:32:default:windows",
        "x86" => "x86:LE:32:default:gcc",
        "x86-64" if pe => "x86:LE:64:default:windows",
        "x86-64" => "x86:LE:64:default:gcc",
        "AArch64" if pe => "AARCH64:LE:64:v8A:windows",
        "AArch64" if info.format == "Mach-O" => "AARCH64:LE:64:AppleSilicon:default",
        "AArch64" => "AARCH64:LE:64:v8A:default",
        _ => return Err("Unsupported signature architecture".into()),
    };
    Ok(language.into())
}

fn engine_type(
    types: &mut TypeFactory,
    ty: SignatureType,
) -> ghidra_decompiler::error::Result<TypeId> {
    use SignatureBase::*;
    let (size, meta) = match ty.base {
        Void => (0, TypeMetatype::Void),
        I8 => (1, TypeMetatype::Int),
        U8 => (1, TypeMetatype::Uint),
        I16 => (2, TypeMetatype::Int),
        U16 => (2, TypeMetatype::Uint),
        I32 => (4, TypeMetatype::Int),
        U32 => (4, TypeMetatype::Uint),
        I64 => (8, TypeMetatype::Int),
        U64 => (8, TypeMetatype::Uint),
    };
    let mut id = if size == 0 {
        types.get_type_void()?
    } else {
        types.get_base_no_char(size, meta)?
    };
    for _ in 0..ty.pointer_depth {
        id = types.get_type_pointer(types.get_size_of_pointer(), id, 1)?;
    }
    Ok(id)
}

/// All addresses and storage are preflighted before changing any prototype.
/// The worker must discard this Program if applying a preflighted batch fails.
pub fn apply(
    program: &mut Program,
    signatures: &[FunctionSignature],
    abi: &str,
) -> Result<(), String> {
    validate_signatures(signatures)?;
    if program.language_id() != abi {
        return Err("Signature ABI does not match the loaded engine language".into());
    }
    let architecture = program.architecture();
    let code = architecture
        .manager
        .get_default_code_space()
        .ok_or("Missing code address space")?;
    if code.get_word_size() != 1 {
        return Err("Signature application requires byte-addressed code".into());
    }
    let mut prepared = Vec::with_capacity(signatures.len());
    for signature in signatures {
        if signature.engine != SIGNATURE_FINGERPRINT || signature.abi != abi {
            return Err("Saved signature engine or ABI is incompatible".into());
        }
        let db = architecture.symboltab_ref().map_err(|e| e.to_string())?;
        let scope = db.get_global_scope().ok_or("Missing global scope")?;
        let address = Address::new(code.clone(), signature.function);
        let symbol = db
            .scope_query_function(scope, &address)
            .ok_or("Signature address is not an established function entry")?;
        architecture
            .with_function(symbol, |data, _| {
                if data.get_address() != &address {
                    return Err(Error::Lowlevel(
                        "Signature address is not an exact function entry".into(),
                    ));
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        let types = architecture.types.as_mut().ok_or("Missing type factory")?;
        let outtype = engine_type(types, signature.return_type).map_err(|e| e.to_string())?;
        let intypes = signature
            .parameters
            .iter()
            .map(|p| engine_type(types, p.ty))
            .collect::<ghidra_decompiler::error::Result<Vec<_>>>()
            .map_err(|e| e.to_string())?;
        let pieces = PrototypePieces {
            model: architecture.defaultfp,
            name: String::new(),
            outtype: Some(outtype),
            intypes,
            innames: signature
                .parameters
                .iter()
                .map(|p| p.name.clone())
                .collect(),
            first_var_arg_slot: -1,
        };
        let model = pieces.model.ok_or("Missing default calling convention")?;
        let mut storage = Vec::new();
        assign_storage_glb(model, &pieces, &mut storage, false, architecture)
            .map_err(|e| e.to_string())?;
        let expected = std::iter::once(outtype).chain(pieces.intypes.iter().copied());
        if storage.len() != signature.parameters.len() + 1
            || storage.iter().zip(expected).any(|(p, tp)| {
                p.tp != Some(tp)
                    || p.flags & (ParameterPieces::HIDDENRETPARM | ParameterPieces::INDIRECTSTORAGE)
                        != 0
                    || (architecture.types.as_ref().unwrap().get(tp).get_metatype()
                        != TypeMetatype::Void
                        && p.addr.is_invalid())
            })
        {
            return Err(
                "Signature requires unsupported hidden, indirect, or unassigned storage".into(),
            );
        }
        prepared.push((symbol, pieces, storage));
    }
    for (symbol, pieces, storage) in prepared {
        architecture
            .with_function(symbol, |data, architecture| {
                if data.is_proc_started() {
                    architecture.clear_analysis(data);
                }
                let proto = data.get_func_proto_mut();
                // Previous inference errors must not survive a complete replacement.
                proto.set_input_errors(false);
                proto.set_output_errors(false);
                proto.set_pieces(&pieces, architecture)?;
                if proto.has_input_errors()
                    || proto.has_output_errors()
                    || proto.num_params(architecture) as usize != pieces.intypes.len()
                    || proto.get_output_type(architecture) != pieces.outtype.unwrap()
                    || proto.is_dotdotdot()
                    || proto.get_model() != pieces.model
                {
                    return Err(Error::Lowlevel(
                        "Engine did not accept the complete signature".into(),
                    ));
                }
                if proto.get_output_ref().is_none_or(|p| {
                    p.is_hidden_return(architecture)
                        || p.is_indirect_storage(architecture)
                        || p.get_address(architecture) != storage[0].addr
                }) {
                    return Err(Error::Lowlevel(
                        "Engine returned unsupported return storage".into(),
                    ));
                }
                for (i, &ty) in pieces.intypes.iter().enumerate() {
                    let param = proto
                        .get_param(i as i32, architecture)
                        .ok_or_else(|| Error::Lowlevel("Missing applied parameter".into()))?;
                    if param.get_type(architecture) != ty
                        || param.get_name(architecture) != pieces.innames[i]
                        || param.is_hidden_return(architecture)
                        || param.is_indirect_storage(architecture)
                        || param.get_address(architecture) != storage[i + 1].addr
                    {
                        return Err(Error::Lowlevel(
                            "Engine changed signature parameter type, name, or storage".into(),
                        ));
                    }
                    param.set_type_lock(true, architecture);
                    param.set_name_lock(true, architecture);
                }
                proto.set_input_lock(true, architecture);
                proto.set_output_lock(true, architecture);
                proto.set_model_lock(true);
                Ok(())
            })
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferredParameter {
    #[serde(deserialize_with = "short_string")]
    pub name: String,
    pub ty: Option<SignatureType>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferredSignature {
    pub return_type: Option<SignatureType>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_PARAMETERS }>")]
    pub parameters: Vec<InferredParameter>,
    #[serde(deserialize_with = "short_string")]
    pub abi: String,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_INFERRED_NOTES }>")]
    pub unsupported: Vec<String>,
}
impl InferredSignature {
    pub fn validate(&self) -> Result<(), String> {
        validate_context(&self.abi)?;
        if self.parameters.len() > MAX_PARAMETERS
            || self.unsupported.len() > MAX_INFERRED_NOTES
            || self.unsupported.iter().any(|s| s.len() > 256)
        {
            return Err("Inferred signature exceeds limits".into());
        }
        if let Some(ty) = self.return_type {
            ty.validate()?;
        }
        for p in &self.parameters {
            if p.name.len() > 256 {
                return Err("Inferred parameter name exceeds limit".into());
            }
            if let Some(ty) = p.ty {
                ty.validate()?;
                if ty.is_void() {
                    return Err("Invalid inferred void parameter".into());
                }
            }
        }
        Ok(())
    }
}

fn inferred_type(types: &TypeFactory, mut id: TypeId) -> Option<SignatureType> {
    let mut pointer_depth = 0;
    while types.get(id).get_metatype() == TypeMetatype::Ptr {
        if pointer_depth == MAX_POINTER_DEPTH {
            return None;
        }
        let tp = types.get(id);
        if tp.get_size() != types.get_size_of_pointer()
            || tp.get_word_size() != 1
            || tp.get_space().is_some()
        {
            return None;
        }
        pointer_depth += 1;
        id = tp.get_ptr_to();
    }
    let tp = types.get(id);
    let base = match (tp.get_metatype(), tp.get_size()) {
        (TypeMetatype::Void, _) => SignatureBase::Void,
        (TypeMetatype::Int, 1) => SignatureBase::I8,
        (TypeMetatype::Uint, 1) => SignatureBase::U8,
        (TypeMetatype::Int, 2) => SignatureBase::I16,
        (TypeMetatype::Uint, 2) => SignatureBase::U16,
        (TypeMetatype::Int, 4) => SignatureBase::I32,
        (TypeMetatype::Uint, 4) => SignatureBase::U32,
        (TypeMetatype::Int, 8) => SignatureBase::I64,
        (TypeMetatype::Uint, 8) => SignatureBase::U64,
        _ => return None,
    };
    Some(SignatureType {
        base,
        pointer_depth,
    })
}

fn type_description(types: &TypeFactory, id: TypeId) -> String {
    let tp = types.get(id);
    let name: String = tp.get_name().chars().take(96).collect();
    // Bound bytes, not just Unicode scalar count.
    let name: String = name
        .char_indices()
        .take_while(|(i, c)| i + c.len_utf8() <= 96)
        .map(|(_, c)| c)
        .collect();
    format!(
        "{:?} ({} bytes, '{}')",
        tp.get_metatype(),
        tp.get_size(),
        name
    )
}

/// Called after the complete analysis action and before Program clears analysis.
pub(crate) fn capture(
    data: &mut Funcdata,
    architecture: &Architecture,
    abi: &str,
) -> InferredSignature {
    let proto = data.get_func_proto_mut();
    let mut result = InferredSignature {
        return_type: None,
        parameters: Vec::new(),
        abi: abi.into(),
        unsupported: Vec::new(),
    };
    if proto.is_dotdotdot() {
        result
            .unsupported
            .push("Variadic prototypes are unsupported".into());
    }
    if proto.has_input_errors() || proto.has_output_errors() {
        result
            .unsupported
            .push("Engine reported prototype storage errors".into());
    }
    if proto.get_model() != architecture.defaultfp {
        result
            .unsupported
            .push("Nondefault calling convention is unsupported".into());
    }
    let Some(types) = architecture.types.as_ref() else {
        result
            .unsupported
            .push("Missing engine type factory".into());
        return result;
    };
    let output = proto.get_output_ref();
    result.return_type = output.and_then(|p| inferred_type(types, p.get_type(architecture)));
    if output
        .is_some_and(|p| p.is_hidden_return(architecture) || p.is_indirect_storage(architecture))
    {
        result.return_type = None;
    }
    if result.return_type.is_none() {
        let description = output
            .map(|p| type_description(types, p.get_type(architecture)))
            .unwrap_or_else(|| "missing type".into());
        result
            .unsupported
            .push(format!("Unsupported return type/storage: {description}"));
    }
    let count = proto.num_params(architecture);
    if count > MAX_PARAMETERS as i32 {
        result
            .unsupported
            .push("Inferred prototype exceeds 32 parameters".into());
    }
    // Do not copy an unbounded engine prototype just to truncate it afterward.
    for i in 0..count.min(MAX_PARAMETERS as i32) {
        let Some(parameter) = proto.get_param(i, architecture) else {
            result
                .unsupported
                .push(format!("Missing engine parameter {}", i + 1));
            result.parameters.push(InferredParameter {
                name: String::new(),
                ty: None,
            });
            continue;
        };
        let id = parameter.get_type(architecture);
        let mut ty = inferred_type(types, id).filter(|t| !t.is_void());
        if parameter.is_hidden_return(architecture) || parameter.is_indirect_storage(architecture) {
            ty = None;
        }
        if ty.is_none() {
            result.unsupported.push(format!(
                "Unsupported parameter {} type/storage: {}",
                i + 1,
                type_description(types, id)
            ));
        }
        let name = parameter.get_name(architecture);
        let name = if name.len() <= 256 {
            name.to_owned()
        } else {
            String::new()
        };
        result.parameters.push(InferredParameter { name, ty });
    }
    result
}
