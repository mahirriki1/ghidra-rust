//! Public headless API exercised against real contained child processes.
#![cfg(any(target_os = "linux", windows))]
use ghidra_rust::headless::{
    Analyzer, CancellationToken, Command as ApiCommand, ErrorCode, Input, Options, Origin, Output,
};
use ghidra_rust::project::ProjectData;
use object::{Object, ObjectSymbol};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn executable() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"))
}
struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
    a: u64,
    b: u64,
}
fn fixture() -> Option<Fixture> {
    let directory = tempfile::tempdir().unwrap();
    let path;
    #[cfg(target_os = "linux")]
    {
        path = directory.path().join("fixture");
        let output = Command::new("gcc")
            .args(["-O0", "-g", "-fno-pie", "-no-pie"])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sample.c"
            ))
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[cfg(windows)]
    {
        let Some(source) = std::env::var_os("GHIDRA_RUST_TEST_PE") else {
            eprintln!("Set GHIDRA_RUST_TEST_PE using scripts/build-windows.ps1");
            return None;
        };
        path = directory.path().join("fixture.exe");
        std::fs::copy(source, &path).unwrap();
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        return None;
    }
    let bytes = std::fs::read(&path).unwrap();
    let image = object::File::parse(bytes.as_slice()).unwrap();
    let find = |name: &[u8]| {
        image
            .symbols()
            .find(|s| s.name_bytes().ok() == Some(name))
            .map(|s| s.address())
            .or_else(|| {
                image
                    .exports()
                    .unwrap()
                    .iter()
                    .find(|s| s.name() == name)
                    .map(|s| s.address())
            })
            .unwrap()
    };
    let a = find(b"branch_loop");
    #[cfg(target_os = "linux")]
    let b = find(b"main");
    #[cfg(not(target_os = "linux"))]
    let b = image.entry();
    Some(Fixture {
        _directory: directory,
        path,
        a,
        b,
    })
}
fn analyze(
    api: &mut Analyzer,
    address: u64,
    refresh: bool,
) -> Box<ghidra_rust::headless::FunctionAnalysis> {
    let Output::Function { analysis } = api
        .execute(ApiCommand::Function { address, refresh })
        .unwrap()
    else {
        panic!("Expected function output");
    };
    assert_eq!(analysis.view.address, address);
    assert!(!analysis.text.is_empty());
    analysis
}

#[test]
fn headless_projects_reuse_saved_functions_and_refresh_independently() {
    let Some(f) = fixture() else {
        return;
    };
    let destination = f._directory.path().join("checkpoint.grproj");
    let mut api = Analyzer::open(
        Input::Binary(f.path.clone()),
        executable(),
        Options {
            output_project: Some(destination.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let Output::Info { info, .. } = api.execute(ApiCommand::Info {}).unwrap() else {
        panic!()
    };
    assert!(info.source_identity.is_none());
    assert_eq!(Path::new(&info.path).components().count(), 1);
    assert_eq!(
        api.execute(ApiCommand::Function {
            address: u64::MAX,
            refresh: false
        })
        .unwrap_err()
        .code,
        ErrorCode::InvalidAddress
    );
    let first = analyze(&mut api, f.a, false);
    assert!(!first.cache_hit && first.graph_origin == Origin::Computed);
    let hit = analyze(&mut api, f.a, false);
    assert!(hit.cache_hit && hit.decompiled_origin == Origin::Computed);
    analyze(&mut api, f.b, false);
    assert!(
        matches!(api.execute(ApiCommand::SaveProject { embed_binary: true }).unwrap(),Output::ProjectSaved { functions } if functions>=2)
    );
    drop(api);
    let loaded = ProjectData::load(&destination).unwrap();
    let extracted = loaded.binary.as_ref().unwrap().path().to_owned();
    assert_eq!(loaded.data.function_results.len(), 1);
    drop(loaded);
    assert!(!extracted.exists());
    let mut api = Analyzer::open(
        Input::Project {
            path: destination,
            external_binary: None,
        },
        executable(),
        Options::default(),
    )
    .unwrap();
    let restored = analyze(&mut api, f.a, false);
    assert!(restored.cache_hit);
    assert_eq!(restored.graph_origin, Origin::Saved);
    assert_eq!(restored.decompiled_origin, Origin::Saved);
    assert_eq!(restored.text, first.text);
    assert_eq!(
        serde_json::to_value(&restored.mappings).unwrap(),
        serde_json::to_value(&first.mappings).unwrap()
    );
    let refreshed = analyze(&mut api, f.a, true);
    assert!(
        !refreshed.cache_hit
            && refreshed.graph_origin == Origin::Computed
            && refreshed.decompiled_origin == Origin::Computed
    );
    assert_eq!(
        analyze(&mut api, f.b, false).decompiled_origin,
        Origin::Saved
    );
}

#[test]
fn headless_external_projects_require_explicit_input_and_protect_aliases() {
    let Some(f) = fixture() else {
        return;
    };
    let alias = f._directory.path().join("alias");
    std::fs::hard_link(&f.path, &alias).unwrap();
    let original = std::fs::read(&f.path).unwrap();
    for destination in [&f.path, &alias] {
        let mut api = Analyzer::open(
            Input::Binary(f.path.clone()),
            executable(),
            Options {
                output_project: Some(destination.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        analyze(&mut api, f.a, false);
        assert_eq!(
            api.execute(ApiCommand::SaveProject { embed_binary: true })
                .unwrap_err()
                .code,
            ErrorCode::Project
        );
        assert_eq!(std::fs::read(&f.path).unwrap(), original);
    }
    let destination = f._directory.path().join("external.grproj");
    let mut api = Analyzer::open(
        Input::Binary(f.path.clone()),
        executable(),
        Options {
            output_project: Some(destination.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    analyze(&mut api, f.a, false);
    api.execute(ApiCommand::SaveProject {
        embed_binary: false,
    })
    .unwrap();
    drop(api);
    assert_eq!(
        Analyzer::open(
            Input::Project {
                path: destination.clone(),
                external_binary: None
            },
            executable(),
            Options::default()
        )
        .err()
        .unwrap()
        .code,
        ErrorCode::InvalidRequest
    );
    let mut api = Analyzer::open(
        Input::Project {
            path: destination,
            external_binary: Some(f.path.clone()),
        },
        executable(),
        Options::default(),
    )
    .unwrap();
    assert_eq!(
        analyze(&mut api, f.a, false).decompiled_origin,
        Origin::Saved
    );
}

#[test]
fn headless_scans_bytes_linkage_and_discovery_are_bounded_and_validated() {
    let Some(f) = fixture() else {
        return;
    };
    let mut api = Analyzer::open(
        Input::Binary(f.path.clone()),
        executable(),
        Options::default(),
    )
    .unwrap();
    let Output::Bytes { address, bytes } = api
        .execute(ApiCommand::Bytes {
            address: f.a,
            length: 1,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(address, f.a);
    assert_eq!(bytes.len(), 1);
    assert_eq!(
        api.execute(ApiCommand::Bytes {
            address: u64::MAX,
            length: 2
        })
        .unwrap_err()
        .code,
        ErrorCode::InvalidAddress
    );
    assert!(
        matches!(api.execute(ApiCommand::Strings {minimum_length:4}).unwrap(),Output::Strings {strings,..} if strings.iter().any(|v|v.text.contains("aGVsbG8gcmV2ZXJzZXI=")))
    );
    assert!(
        matches!(api.execute(ApiCommand::Crypto {}).unwrap(),Output::Crypto {matches,..} if matches.iter().any(|v|v.algorithm.contains("AES")))
    );
    let (mut cursor, mut digest) = (0, None);
    loop {
        let Output::Linkage { summary, page } =
            api.execute(ApiCommand::Linkage { cursor, digest }).unwrap()
        else {
            panic!()
        };
        assert_eq!(summary.digest, page.digest);
        assert_eq!(page.cursor, cursor);
        let Some(next) = page.next else {
            break;
        };
        cursor = next;
        digest = Some(page.digest);
    }
    assert_eq!(
        api.execute(ApiCommand::Linkage {
            cursor: 999,
            digest: Some("0".repeat(64))
        })
        .unwrap_err()
        .code,
        ErrorCode::InvalidRequest
    );
    let mut batches = 0;
    for _ in 0..2 {
        let Output::Discovery { snapshot, complete } =
            api.execute(ApiCommand::Discover {}).unwrap()
        else {
            panic!()
        };
        let Output::Info { info, .. } = api.execute(ApiCommand::Info {}).unwrap() else {
            panic!()
        };
        snapshot.validate(&info).unwrap();
        assert!(snapshot.batches >= batches);
        if snapshot.batches == 0 {
            assert!(!complete && !snapshot.pending.is_empty());
        }
        batches = snapshot.batches;
    }
    assert!(
        batches > 0,
        "two fixture steps must reach instruction analysis"
    );
}

fn console(f: &Fixture, args: &[&std::ffi::OsStr], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(executable())
        .arg("--binary")
        .arg(&f.path)
        .args(args)
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let _ = stdin.write_all(input);
    drop(stdin);
    child.wait_with_output().unwrap()
}
#[test]
fn console_recovers_from_bad_frames_and_never_accepts_path_commands() {
    let Some(f) = fixture() else {
        return;
    };
    let input=b"{\"api_version\":1,\"id\":1,\"command\":{\"kind\":\"open\",\"path\":\"/etc/passwd\"}}\n{\"api_version\":2,\"id\":2,\"command\":{\"kind\":\"info\"}}\n{\"api_version\":1,\"id\":3,\"command\":{\"kind\":\"info\"}}\n{\"api_version\":1,\"id\":3,\"command\":{\"kind\":\"info\"}}\n";
    let out = console(&f, &[], input);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0]["error"]["code"], "invalid_request");
    assert_eq!(lines[1]["error"]["code"], "unsupported_version");
    assert_eq!(lines[2]["result"]["kind"], "info");
    assert_eq!(lines[3]["error"]["code"], "invalid_request");
    let out = console(
        &f,
        &[],
        &vec![b'x'; ghidra_rust::headless::protocol::MAX_REQUEST_BYTES + 1],
    );
    assert!(!out.status.success());
    let lines: Vec<_> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
        .collect();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["error"]["code"], "invalid_request");
}

#[test]
fn console_checkpoints_without_a_display() {
    let Some(f) = fixture() else {
        return;
    };
    let path = f._directory.path().join("console.grproj");
    let input = format!(
        "{{\"api_version\":1,\"id\":1,\"command\":{{\"kind\":\"function\",\"address\":{}}}}}\n{{\"api_version\":1,\"id\":2,\"command\":{{\"kind\":\"save_project\"}}}}\n",
        f.a
    );
    let out = console(
        &f,
        &[std::ffi::OsStr::new("--output-project"), path.as_os_str()],
        input.as_bytes(),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let frames: Vec<serde_json::Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["result"]["analysis"]["view"]["address"], f.a);
    assert_eq!(frames[1]["result"]["kind"], "project_saved");
    assert!(ProjectData::load(&path).unwrap().data.decompiled.is_some());
}

#[test]
fn cancellation_and_deadlines_stop_a_stalled_real_child() {
    let Some(f) = fixture() else {
        return;
    };
    let worker = f
        ._directory
        .path()
        .join(if cfg!(windows) { "stall.exe" } else { "stall" });
    let output = Command::new("rustc")
        .args(["--edition=2024", "-C", "target-feature=+crt-static"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/headless_stall.rs"
        ))
        .arg("-o")
        .arg(&worker)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let started = Instant::now();
    let error = Analyzer::open(
        Input::Binary(f.path.clone()),
        &worker,
        Options {
            worker_timeout: Duration::from_millis(100),
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(5));
    let token = CancellationToken::default();
    let cancel = token.clone();
    let handle = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cancel.cancel();
    });
    let started = Instant::now();
    let error = Analyzer::open(
        Input::Binary(f.path.clone()),
        &worker,
        Options {
            cancellation: token,
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    handle.join().unwrap();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert!(started.elapsed() < Duration::from_secs(5));
}

fn editable_project(f: &Fixture, path: &Path) -> ProjectData {
    use ghidra_rust::model::FileIdentity;
    let mut data = ProjectData::load(path).unwrap().data;
    data.info.source_identity = FileIdentity::from_file(&std::fs::File::open(&f.path).unwrap());
    data.decompiled = None;
    data.mappings.clear();
    data.semantics = Default::default();
    data.function_results.clear();
    data
}
fn write_project(f: &Fixture, path: &Path, data: &ProjectData) {
    let guard = ghidra_rust::session::BinaryProtection::open(&f.path)
        .unwrap()
        .bind_snapshot(&data.info)
        .unwrap();
    data.save(path, &guard, true).unwrap();
}

#[test]
fn headless_replays_saved_local_names_and_preserves_comments() {
    let Some(f) = fixture() else {
        return;
    };
    let path = f._directory.path().join("locals.grproj");
    let output = f._directory.path().join("locals-updated.grproj");
    let mut api = Analyzer::open(
        Input::Binary(f.path.clone()),
        executable(),
        Options {
            output_project: Some(path.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let original = analyze(&mut api, f.a, false);
    let local = original
        .semantics
        .locals
        .first()
        .expect("original unoptimized branch fixture has a recovered local")
        .identity
        .clone();
    api.execute(ApiCommand::SaveProject { embed_binary: true })
        .unwrap();
    drop(api);
    let mut data = editable_project(&f, &path);
    data.session.annotations.insert(
        f.a,
        ghidra_rust::session::Annotation {
            comment: "review on the phone".into(),
            ..Default::default()
        },
    );
    data.session
        .local_renames
        .push(ghidra_rust::semantic::LocalRename {
            identity: local,
            name: "review_counter".into(),
        });
    data.session.upgrade_version();
    write_project(&f, &path, &data);
    let mut api = Analyzer::open(
        Input::Project {
            path,
            external_binary: None,
        },
        executable(),
        Options {
            output_project: Some(output.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    let renamed = analyze(&mut api, f.a, false);
    assert!(renamed.text.contains("review_counter"));
    let Output::Annotations { session } = api.execute(ApiCommand::Annotations {}).unwrap() else {
        panic!()
    };
    assert_eq!(session.annotations[&f.a].comment, "review on the phone");
    api.execute(ApiCommand::SaveProject { embed_binary: true })
        .unwrap();
    drop(api);
    let saved = ProjectData::load(&output).unwrap();
    assert_eq!(saved.data.session.local_renames[0].name, "review_counter");
    assert_eq!(
        saved.data.session.annotations[&f.a].comment,
        "review on the phone"
    );
}

#[test]
fn headless_replays_saved_function_names_and_signatures_before_analysis() {
    use ghidra_rust::signatures::{
        FunctionSignature, SIGNATURE_FINGERPRINT, SignatureBase, SignatureParameter, SignatureType,
    };
    let Some(f) = fixture() else {
        return;
    };
    let path = f._directory.path().join("signature.grproj");
    let mut api = Analyzer::open(
        Input::Binary(f.path.clone()),
        executable(),
        Options {
            output_project: Some(path.clone()),
            ..Default::default()
        },
    )
    .unwrap();
    analyze(&mut api, f.a, false);
    api.execute(ApiCommand::SaveProject { embed_binary: true })
        .unwrap();
    drop(api);
    let mut data = editable_project(&f, &path);
    data.view = None;
    data.session.annotations.insert(
        f.a,
        ghidra_rust::session::Annotation {
            label: "mobile_branch".into(),
            ..Default::default()
        },
    );
    let ty = SignatureType {
        base: SignatureBase::U32,
        pointer_depth: 0,
    };
    data.session.signatures.push(FunctionSignature {
        function: f.a,
        engine: SIGNATURE_FINGERPRINT.into(),
        abi: ghidra_rust::signatures::current_abi(&data.info).unwrap(),
        return_type: ty,
        parameters: vec![SignatureParameter {
            name: "mobile_count".into(),
            ty,
        }],
    });
    data.session.upgrade_version();
    write_project(&f, &path, &data);
    let mut api = Analyzer::open(
        Input::Project {
            path,
            external_binary: None,
        },
        executable(),
        Options::default(),
    )
    .unwrap();
    let Output::Info {
        unapplied_signatures,
        ..
    } = api.execute(ApiCommand::Info {}).unwrap()
    else {
        panic!()
    };
    assert!(unapplied_signatures.is_empty());
    let analysis = analyze(&mut api, f.a, false);
    assert!(analysis.text.contains("mobile_branch"));
    assert!(analysis.text.contains("mobile_count"));
}
