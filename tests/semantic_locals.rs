//! Recovered symbol identity and semantic target regressions on original source.
#![cfg(target_os = "linux")]
use ghidra_rust::{
    analysis::LoadedProgram,
    model::{Request, Response},
    semantic::{LocalRename, SemanticInfo, TokenKind},
};
use object::{Object, ObjectSymbol};
use std::process::Command;

fn fixture() -> (tempfile::TempDir, String, u64, u64) {
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("fixture");
    let output = Command::new("gcc")
        .args(["-g", "-O0", "-fno-pie", "-no-pie", "-fno-inline"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/sample.c"
        ))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let bytes = std::fs::read(&binary).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let address = |name| {
        file.symbols()
            .find(|s| s.name().ok() == Some(name))
            .unwrap()
            .address()
    };
    (
        directory,
        binary.to_string_lossy().into_owned(),
        address("branch_loop"),
        address("main"),
    )
}
fn decompile(
    program: &mut LoadedProgram,
    address: u64,
    renames: Vec<LocalRename>,
) -> (String, SemanticInfo) {
    let Response::Decompiled {
        text,
        mappings,
        semantics,
        ..
    } = program
        .handle(Request::DecompileWithLocals { address, renames })
        .unwrap()
    else {
        panic!()
    };
    ghidra_rust::selection::validate_mappings(&text, &mappings, &program.info.sections).unwrap();
    semantics
        .validate(&text, address, &program.info.sections)
        .unwrap();
    (text, semantics)
}

#[test]
fn local_storage_identity_renames_all_and_only_its_tokens_across_reanalysis() {
    let (_directory, path, branch, main) = fixture();
    let mut program = LoadedProgram::open(&path).unwrap();
    let (original, first) = decompile(&mut program, branch, vec![]);
    assert!(
        !first.locals.is_empty(),
        "No supported recovered locals: {original}\n{first:?}"
    );
    let (index, local) = first
        .locals
        .iter()
        .enumerate()
        .find(|(i, _)| {
            first
                .tokens
                .iter()
                .filter(|t| matches!(t.kind, TokenKind::Local { local: Some(j) } if j == *i))
                .count()
                > 2
        })
        .expect("Recovered local with declaration and uses");
    let rename = LocalRename {
        identity: local.identity.clone(),
        name: "verified_local_value".into(),
    };
    let (renamed, second) = decompile(&mut program, branch, vec![rename.clone()]);
    assert!(second.warnings.is_empty(), "{:?}", second.warnings);
    // Compare the entire printed output after replacing precisely the captured
    // variable spans. No identifier matching or edits to strings/comments.
    let mut expected = original.clone();
    for token in first
        .tokens
        .iter()
        .rev()
        .filter(|t| matches!(t.kind, TokenKind::Local { local: Some(i) } if i == index))
    {
        expected.replace_range(token.start..token.end, &rename.name);
    }
    assert_eq!(renamed, expected);
    decompile(&mut program, main, vec![]);
    assert_eq!(
        decompile(&mut program, branch, vec![rename.clone()]).0,
        renamed
    );
    // Rebuild every arena, not just the selected function.
    drop(program);
    let mut program = LoadedProgram::open(&path).unwrap();
    assert_eq!(
        decompile(&mut program, branch, vec![rename.clone()]).0,
        renamed
    );
    let other = first
        .locals
        .iter()
        .find(|v| v.identity != rename.identity)
        .expect("Distinct local for collision rejection");
    let mut collision = rename.clone();
    collision.name.clone_from(&other.name);
    let (unmodified, collision_info) = decompile(&mut program, branch, vec![collision]);
    assert_eq!(unmodified, original);
    assert!(
        collision_info
            .warnings
            .iter()
            .any(|w| w.contains("collides"))
    );
    let mut absent = rename.clone();
    absent.identity.offset ^= 0x80;
    assert_eq!(decompile(&mut program, branch, vec![absent]).0, original);
    let mut wrong_function = rename.clone();
    wrong_function.identity.function = main;
    assert!(
        program
            .handle(Request::DecompileWithLocals {
                address: branch,
                renames: vec![wrong_function]
            })
            .is_err()
    );
    let mut stale = rename.clone();
    stale.identity.verification = "f".repeat(64);
    let (text, info) = decompile(&mut program, branch, vec![stale]);
    assert_eq!(text, original);
    assert!(info.warnings.iter().any(|w| w.contains("not applied")));
    let mut incompatible = rename.clone();
    incompatible.identity.engine = "older-engine".into();
    assert_eq!(
        decompile(&mut program, branch, vec![incompatible]).0,
        original
    );
    assert!(
        program
            .handle(Request::DecompileWithLocals {
                address: branch,
                renames: vec![rename.clone(), rename]
            })
            .is_err()
    );
}

#[test]
fn actual_call_tokens_keep_targets_after_callee_rename_and_name_collision() {
    let (_directory, path, branch, main) = fixture();
    let mut program = LoadedProgram::open(&path).unwrap();
    let (_, before) = decompile(&mut program, main, vec![]);
    assert!(
        before
            .tokens
            .iter()
            .any(|t| matches!(t.kind, TokenKind::Call { target } if target == branch))
    );
    program
        .handle(Request::Rename {
            address: branch,
            name: "collision".into(),
        })
        .unwrap();
    let other = program
        .info
        .functions
        .iter()
        .find(|f| f.name == "decode_xor")
        .unwrap()
        .address;
    let (renamed, renamed_info) = decompile(&mut program, main, vec![]);
    assert!(renamed_info.tokens.iter().any(
        |t| matches!(t.kind, TokenKind::Call { target } if target == branch)
            && &renamed[t.start..t.end] == "collision"
    ));

    // The application deliberately forbids duplicate explicit function names.
    // Public engine display names can still collide (e.g. demangled names).
    // Create that condition on the real analyzed fixture, without changing code
    // or substituting metadata/text in the result being tested.
    let mut engine = ghidra_decompiler::program::Program::from_image(
        "fixture",
        std::fs::read(&path).unwrap(),
        None,
    )
    .unwrap();
    let architecture = engine.architecture();
    let symbols = architecture.function_symbols_address_order().unwrap();
    let mut changed = 0;
    for symbol in symbols {
        let db = architecture.symboltab_mut().unwrap();
        if ["branch_loop", "decode_xor"].contains(&db.symbol(symbol).name.as_str()) {
            db.symbol_mut(symbol).display_name = "collision".into();
            changed += 1;
        }
    }
    assert_eq!(changed, 2);
    let (text, _, after) =
        ghidra_rust::decompile::render(&mut engine, main, &program.info.sections).unwrap();
    for target in [branch, other] {
        assert!(
            after.tokens.iter().any(
                |t| matches!(t.kind, TokenKind::Call { target: a } if a == target)
                    && text[t.start..t.end].contains("collision")
            ),
            "{text}\n{after:?}"
        );
    }
    assert!(after.token_at(0).is_none());
}

#[test]
fn project_and_annotation_roundtrip_retain_verified_local_names() {
    use ghidra_rust::{
        project::ProjectData,
        session::{BinaryProtection, Session},
    };
    let (directory, path, branch, _) = fixture();
    let mut program = LoadedProgram::open(&path).unwrap();
    let (_, first) = decompile(&mut program, branch, vec![]);
    let rename = LocalRename {
        identity: first.locals.first().unwrap().identity.clone(),
        name: "saved_local".into(),
    };
    let protection = BinaryProtection::open(std::path::Path::new(&path))
        .unwrap()
        .bind_snapshot(&program.info)
        .unwrap();
    let mut session = Session::new(program.info.sha256.clone());
    session.version = 2;
    session.local_renames.push(rename.clone());
    let json = directory.path().join("names.json");
    session.save(&json, &protection).unwrap();
    let restored = Session::load(&json, &program.info.sha256).unwrap();
    assert_eq!(restored.local_renames, session.local_renames);
    let Response::Graph { view } = program.handle(Request::Graph { address: branch }).unwrap()
    else {
        panic!()
    };
    let Response::Decompiled {
        text,
        mappings,
        semantics,
        ..
    } = program
        .handle(Request::DecompileWithLocals {
            address: branch,
            renames: restored.local_renames.clone(),
        })
        .unwrap()
    else {
        panic!()
    };
    let project = ProjectData {
        info: program.info.clone(),
        session: restored,
        view: Some(view),
        decompiled: Some(text.clone()),
        mappings,
        semantics,
        strings: vec![],
        strings_truncated: false,
        crypto: vec![],
        crypto_truncated: false,
        selected_address: Some(branch),
        discovery: None,
    };
    let destination = directory.path().join("names.grproj");
    project.save(&destination, &protection, true).unwrap();
    let loaded = ProjectData::load(&destination).unwrap();
    assert!(loaded.cache_compatible);
    assert_eq!(loaded.data.session.local_renames, vec![rename]);
    assert!(!loaded.data.semantics.tokens.is_empty());
    let extracted = loaded.binary.as_ref().unwrap().path();
    let mut fresh = LoadedProgram::open(extracted.to_str().unwrap()).unwrap();
    assert_eq!(
        decompile(
            &mut fresh,
            branch,
            loaded.data.session.local_renames.clone()
        )
        .0,
        text
    );
    // A new engine can retain old overrides without adopting incompatible tokens.
    let db = rusqlite::Connection::open(&destination).unwrap();
    let body: Vec<u8> = db
        .query_row(
            "SELECT value FROM project_data WHERE key='body'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    body["engine"] = "incompatible-cache".into();
    body["semantics"]["locals"][0]["identity"]["engine"] = "incompatible-local-engine".into();
    db.execute(
        "UPDATE project_data SET value=?1 WHERE key='body'",
        [serde_json::to_vec(&body).unwrap()],
    )
    .unwrap();
    let mut incompatible_session = session.clone();
    incompatible_session.local_renames[0].identity.engine = "incompatible-local-engine".into();
    db.execute(
        "UPDATE project_data SET value=?1 WHERE key='annotations'",
        [serde_json::to_vec(&incompatible_session).unwrap()],
    )
    .unwrap();
    drop(db);
    let incompatible = ProjectData::load(&destination).unwrap();
    assert!(!incompatible.cache_compatible);
    assert!(
        incompatible.data.decompiled.is_none() && incompatible.data.semantics.tokens.is_empty()
    );
    assert_eq!(
        incompatible.data.session.local_renames,
        incompatible_session.local_renames
    );
    let (unchanged, warnings) = decompile(
        &mut fresh,
        branch,
        incompatible.data.session.local_renames.clone(),
    );
    assert!(!unchanged.contains("saved_local"));
    assert!(!warnings.warnings.is_empty());
    // Version 1 JSON remains readable; v1 cannot carry silently ignored names.
    let mut legacy = serde_json::to_value(&session).unwrap();
    legacy["version"] = 1.into();
    std::fs::write(&json, serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert!(Session::load(&json, &program.info.sha256).is_err());
    legacy.as_object_mut().unwrap().remove("local_renames");
    std::fs::write(&json, serde_json::to_vec(&legacy).unwrap()).unwrap();
    assert!(
        Session::load(&json, &program.info.sha256)
            .unwrap()
            .local_renames
            .is_empty()
    );
}
