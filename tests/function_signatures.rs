//! Public-engine prototype edits on original, locally compiled C source.
#![cfg(target_os = "linux")]
use ghidra_decompiler::program::Program;
use ghidra_rust::{
    decompile::{render, render_with_context},
    model::SectionInfo,
    semantic::{LocalRename, TokenKind, local_fingerprint},
    signatures::{
        self, FunctionSignature, SIGNATURE_FINGERPRINT, SignatureBase::*, SignatureParameter,
        SignatureType,
    },
};
use object::{Object, ObjectSection, ObjectSymbol};
use std::{collections::BTreeMap, process::Command};

const ABI: &str = "x86:LE:64:default:gcc";
fn ty(base: signatures::SignatureBase, pointer_depth: u8) -> SignatureType {
    SignatureType {
        base,
        pointer_depth,
    }
}
fn signature(function: u64, parameters: &[(&str, SignatureType)]) -> FunctionSignature {
    FunctionSignature {
        function,
        engine: SIGNATURE_FINGERPRINT.into(),
        abi: ABI.into(),
        return_type: ty(I64, 0),
        parameters: parameters
            .iter()
            .map(|(name, ty)| SignatureParameter {
                name: (*name).into(),
                ty: *ty,
            })
            .collect(),
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    bytes: Vec<u8>,
    addresses: BTreeMap<String, u64>,
    sections: Vec<SectionInfo>,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("signature.c");
        std::fs::write(&source, r#"
#include <stdint.h>
__attribute__((noinline)) int64_t callee(int64_t *values, uint32_t count) {
    return values[count] + count;
}
__attribute__((noinline)) int64_t caller(int64_t *values, uint32_t count) {
    return callee(values, count) + 3;
}
__attribute__((noinline)) int64_t stack_callee(int64_t a,int64_t b,int64_t c,int64_t d,int64_t e,int64_t f,int64_t g,int64_t h) {
    return a+b+c+d+e+f+g+h;
}
__attribute__((noinline)) int64_t zero(void) { return 7; }
__attribute__((noinline)) double unsupported(double value) { return value + 1.5; }
int main(void) { int64_t values[2]={4,8}; return (int)caller(values,1)+(int)stack_callee(1,2,3,4,5,6,7,8)+(int)zero()+(int)unsupported(2.0); }
"#).unwrap();
        let binary = directory.path().join("fixture");
        let output = Command::new("gcc")
            .args(["-O0", "-fno-pie", "-no-pie", "-fno-inline"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let bytes = std::fs::read(binary).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let addresses = file
            .symbols()
            .filter_map(|s| Some((s.name().ok()?.to_string(), s.address())))
            .collect();
        let sections = file
            .sections()
            .filter_map(|s| {
                let (file_offset, file_size) = s.file_range()?;
                Some(SectionInfo {
                    name: s.name().ok()?.into(),
                    address: s.address(),
                    size: s.size(),
                    file_size,
                    file_offset,
                    executable: s.kind() == object::SectionKind::Text,
                })
            })
            .collect();
        Self {
            _directory: directory,
            bytes,
            addresses,
            sections,
        }
    }
    fn engine(&self) -> Program {
        Program::from_image("signature-fixture", self.bytes.clone(), Some(ABI)).unwrap()
    }
    fn address(&self, name: &str) -> u64 {
        self.addresses[name]
    }
}

#[test]
fn callee_signature_before_caller_analysis_preserves_arguments_names_and_printmarks() {
    let f = Fixture::new();
    let mut engine = f.engine();
    let callee = f.address("callee");
    let caller = f.address("caller");
    let edit = signature(
        callee,
        &[("values_owned", ty(I64, 1)), ("count_owned", ty(U32, 0))],
    );
    signatures::apply(&mut engine, std::slice::from_ref(&edit), ABI).unwrap();
    let context = signatures::state_digest(std::slice::from_ref(&edit));
    // Caller has never been analyzed: the engine must obtain its call inputs
    // from the callee's locked, address-bound prototype.
    let (caller_text, caller_marks, caller_semantics) =
        render_with_context(&mut engine, caller, &f.sections, &[], &context, false).unwrap();
    println!("Caller after applying callee signature before analysis:\n{caller_text}");
    let call = caller_semantics
        .tokens
        .iter()
        .find(|t| matches!(t.kind, TokenKind::Call { target } if target == callee))
        .expect("Genuine engine call target");
    assert_eq!(&caller_text[call.start..call.end], "callee");
    let expression = &caller_text[call.end..];
    assert!(
        expression.starts_with('(') && expression.split(')').next().unwrap().contains(','),
        "{caller_text}"
    );
    assert!(
        caller_text.contains('*'),
        "Caller pointer type was not propagated: {caller_text}"
    );
    assert!(!caller_marks.is_empty());
    let (text, marks, semantics) =
        render_with_context(&mut engine, callee, &f.sections, &[], &context, true).unwrap();
    let prototype = semantics.prototype.as_ref().unwrap();
    assert_eq!(prototype.return_type, Some(edit.return_type));
    assert_eq!(
        prototype
            .parameters
            .iter()
            .map(|p| (&p.name, p.ty))
            .collect::<Vec<_>>(),
        edit.parameters
            .iter()
            .map(|p| (&p.name, Some(p.ty)))
            .collect::<Vec<_>>()
    );
    assert!(prototype.unsupported.is_empty(), "{prototype:?}");
    assert!(
        text.contains("values_owned") && text.contains("count_owned") && !marks.is_empty(),
        "{text}"
    );
    let owned = semantics
        .locals
        .iter()
        .find(|v| v.signature_parameter == Some(0))
        .expect("Ordered parameter ownership");
    assert_eq!(owned.identity.engine, local_fingerprint(&context));
    let rename = LocalRename {
        identity: owned.identity.clone(),
        name: "must_not_replace_signature".into(),
    };
    let (again, _, replay) =
        render_with_context(&mut engine, callee, &f.sections, &[rename], &context, true).unwrap();
    assert_eq!(again, text);
    assert!(replay.warnings.iter().any(|w| w.contains("owned")));
    assert_eq!(
        render_with_context(&mut engine, caller, &f.sections, &[], &context, false)
            .unwrap()
            .0,
        caller_text
    );

    // The same current function must get a new identity when a callee's pointee
    // type, names, or ABI context changes, even if its own storage stays equal.
    let (_, _, changed) =
        render_with_context(&mut engine, callee, &f.sections, &[], &"b".repeat(64), true).unwrap();
    assert_ne!(
        changed
            .locals
            .iter()
            .find(|v| v.signature_parameter == Some(0))
            .unwrap()
            .identity,
        owned.identity
    );
}

#[test]
fn zero_add_remove_stack_parameters_and_repeated_application_are_exact() {
    let f = Fixture::new();
    let mut engine = f.engine();
    for (name, counts) in [("zero", vec![0, 1, 0]), ("stack_callee", vec![8, 6, 8, 0])] {
        for count in counts {
            let parameters: Vec<_> = (0..count)
                .map(|i| SignatureParameter {
                    name: format!("ordered_{i}"),
                    ty: ty(I64, 0),
                })
                .collect();
            let mut edit = signature(f.address(name), &[]);
            edit.parameters = parameters;
            signatures::apply(&mut engine, std::slice::from_ref(&edit), ABI).unwrap();
            signatures::apply(&mut engine, std::slice::from_ref(&edit), ABI).unwrap();
            let context = signatures::state_digest(std::slice::from_ref(&edit));
            for _ in 0..2 {
                let (text, _, semantics) = render_with_context(
                    &mut engine,
                    edit.function,
                    &f.sections,
                    &[],
                    &context,
                    true,
                )
                .unwrap();
                let prototype = semantics.prototype.unwrap();
                assert_eq!(prototype.parameters.len(), count, "{text}\n{prototype:?}");
                for (actual, expected) in prototype.parameters.iter().zip(&edit.parameters) {
                    assert_eq!(actual.name, expected.name, "{text}");
                    assert_eq!(actual.ty, Some(expected.ty));
                }
            }
        }
    }
}

#[test]
fn preflight_rejects_incompatible_or_nonentry_batch_before_any_prototype_changes() {
    let f = Fixture::new();
    let mut engine = f.engine();
    let entry = f.address("callee");
    let original = render(&mut engine, entry, &f.sections).unwrap().0;
    let valid = signature(entry, &[("changed", ty(I64, 0))]);
    let mut invalid = signature(f.address("zero") + 1, &[]);
    for fault in 0..3 {
        if fault == 1 {
            invalid.function = f.address("zero");
            invalid.engine = "saved-older-engine".into();
        }
        if fault == 2 {
            invalid.engine = SIGNATURE_FINGERPRINT.into();
            invalid.abi = "different-abi".into();
        }
        assert!(signatures::apply(&mut engine, &[valid.clone(), invalid.clone()], ABI).is_err());
        assert_eq!(render(&mut engine, entry, &f.sections).unwrap().0, original);
    }
    assert!(signatures::apply(&mut engine, &[valid], "wrong-abi").is_err());
}

#[test]
fn inferred_unsupported_types_remain_visible_without_integer_fallback() {
    let f = Fixture::new();
    let mut engine = f.engine();
    let (text, _, semantics) = render(&mut engine, f.address("unsupported"), &f.sections).unwrap();
    let prototype = semantics.prototype.unwrap();
    assert!(prototype.return_type.is_none(), "{text}\n{prototype:?}");
    assert!(
        prototype.parameters.iter().any(|p| p.ty.is_none()),
        "{text}\n{prototype:?}"
    );
    assert!(!prototype.unsupported.is_empty());
}

#[test]
fn shared_state_is_bounded_strict_and_canonical() {
    let first = signature(0x1000, &[("pointer", ty(U8, 2))]);
    let second = signature(0x2000, &[]);
    assert_eq!(
        signatures::state_digest(&[first.clone(), second.clone()]),
        signatures::state_digest(&[second, first.clone()])
    );
    assert_eq!(signatures::state_digest(&[]), signatures::state_digest(&[]));
    assert_ne!(
        signatures::state_digest(&[]),
        signatures::state_digest(std::slice::from_ref(&first))
    );
    let original_digest = signatures::state_digest(std::slice::from_ref(&first));
    for change in 0..4 {
        let mut modified = first.clone();
        match change {
            0 => modified.parameters[0].ty.pointer_depth += 1,
            1 => modified.parameters[0].name = "changed".into(),
            2 => modified.abi = "older-abi".into(),
            _ => modified.engine = "older-engine".into(),
        }
        modified.validate().unwrap();
        assert_ne!(original_digest, signatures::state_digest(&[modified]));
    }
    assert!(signatures::validate_signatures(&[first.clone(), first.clone()]).is_err());
    let mut json = serde_json::to_value(&first).unwrap();
    json["unknown"] = true.into();
    assert!(serde_json::from_value::<FunctionSignature>(json).is_err());
    let mut bad = first.clone();
    bad.parameters[0].ty = ty(Void, 0);
    assert!(bad.validate().is_err());
    bad.parameters[0].ty = ty(U64, 5);
    assert!(bad.validate().is_err());
    bad.parameters = vec![first.parameters[0].clone(); signatures::MAX_PARAMETERS + 1];
    assert!(
        serde_json::from_slice::<FunctionSignature>(&serde_json::to_vec(&bad).unwrap()).is_err()
    );
    let mut total: Vec<_> = (0..signatures::MAX_SIGNATURES)
        .map(|i| signature(i as u64, &[]))
        .collect();
    total.push(signature(u64::MAX, &[]));
    assert!(signatures::validate_signatures(&total).is_err());
    assert!(local_fingerprint("").len() <= 96 && local_fingerprint("nonempty").len() <= 96);
    assert_ne!(local_fingerprint(""), local_fingerprint("nonempty"));
}

#[test]
fn supported_scalar_and_pointer_types_round_trip_through_engine() {
    let f = Fixture::new();
    let mut engine = f.engine();
    let function = f.address("zero");
    for base in [Void, I8, U8, I16, U16, I32, U32, I64, U64] {
        for pointer_depth in [0, signatures::MAX_POINTER_DEPTH] {
            let mut edit = signature(function, &[]);
            edit.return_type = ty(base, pointer_depth);
            if !edit.return_type.is_void() {
                edit.parameters.push(SignatureParameter {
                    name: "typed_parameter".into(),
                    ty: edit.return_type,
                });
            }
            signatures::apply(&mut engine, std::slice::from_ref(&edit), ABI).unwrap();
            let context = signatures::state_digest(std::slice::from_ref(&edit));
            let (text, _, semantics) =
                render_with_context(&mut engine, function, &f.sections, &[], &context, true)
                    .unwrap();
            let inferred = semantics.prototype.unwrap();
            assert_eq!(
                inferred.return_type,
                Some(edit.return_type),
                "{text}\n{inferred:?}"
            );
            assert_eq!(inferred.parameters.len(), edit.parameters.len());
            if let Some(parameter) = edit.parameters.first() {
                assert_eq!(inferred.parameters[0].ty, Some(parameter.ty));
                assert_eq!(inferred.parameters[0].name, parameter.name);
            }
            assert!(inferred.unsupported.is_empty(), "{inferred:?}");
        }
    }
}

#[test]
fn current_abi_signatures_use_native_width_storage_on_other_supported_targets() {
    for (abi, bytes) in [
        ("x86:LE:32:default:gcc", vec![0x8b, 0x44, 0x24, 0x04, 0xc3]),
        (
            "x86:LE:32:default:windows",
            vec![0x8b, 0x44, 0x24, 0x04, 0xc3],
        ),
        ("x86:LE:64:default:windows", vec![0xb8, 1, 0, 0, 0, 0xc3]),
        (
            "AARCH64:LE:64:v8A:default",
            vec![0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
        ),
        (
            "AARCH64:LE:64:v8A:windows",
            vec![0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
        ),
        (
            "AARCH64:LE:64:AppleSilicon:default",
            vec![0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6],
        ),
    ] {
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        let mut program = Program::from_raw_bytes(bytes, abi, 0x1000).unwrap();
        program.set_function_name(0x1000, "typed_entry").unwrap();
        let mut signature = signature(0x1000, &[("buffer", ty(U8, 1)), ("count", ty(U32, 0))]);
        signature.abi = abi.into();
        signature.return_type = ty(U32, 0);
        signatures::apply(&mut program, std::slice::from_ref(&signature), abi)
            .unwrap_or_else(|error| panic!("{abi}: {error}"));
        let context = signatures::state_digest(std::slice::from_ref(&signature));
        let (text, _, semantics) =
            render_with_context(&mut program, 0x1000, &sections, &[], &context, true).unwrap();
        let prototype = semantics.prototype.unwrap();
        assert_eq!(
            prototype.return_type,
            Some(signature.return_type),
            "{abi}: {text}"
        );
        assert_eq!(prototype.parameters.len(), 2, "{abi}: {text}");
        for (actual, expected) in prototype.parameters.iter().zip(&signature.parameters) {
            assert_eq!(
                (&actual.name, actual.ty),
                (&expected.name, Some(expected.ty)),
                "{abi}: {text}"
            );
        }
        assert!(
            prototype.unsupported.is_empty(),
            "{abi}: {:?}",
            prototype.unsupported
        );
    }
}
