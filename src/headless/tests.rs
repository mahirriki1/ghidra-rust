//! Lifecycle regressions against real contained workers. Failures are injected
//! only through private controller state: a shortened deadline, a seed the
//! worker rejects, or a trusted test executable that never replies.
use super::*;
use object::{Object, ObjectSymbol};

struct Fixture {
    directory: tempfile::TempDir,
    path: PathBuf,
    a: u64,
    b: u64,
}

fn executable() -> PathBuf {
    std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(if cfg!(windows) {
            "ghidra-rust-headless.exe"
        } else {
            "ghidra-rust-headless"
        })
}

fn fixture() -> Option<Fixture> {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(target_os = "linux")]
    let path = {
        let path = directory.path().join("fixture");
        let output = std::process::Command::new("gcc")
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
        path
    };
    #[cfg(windows)]
    let path = {
        let Some(source) = std::env::var_os("GHIDRA_RUST_TEST_PE") else {
            eprintln!("Set GHIDRA_RUST_TEST_PE using scripts/build-windows.ps1");
            return None;
        };
        let path = directory.path().join("fixture.exe");
        std::fs::copy(source, &path).unwrap();
        path
    };
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
    #[cfg(windows)]
    let b = image.entry();
    Some(Fixture {
        directory,
        path,
        a,
        b,
    })
}

fn open(f: &Fixture, output_project: Option<PathBuf>) -> Analyzer {
    Analyzer::open(
        Input::Binary(f.path.clone()),
        &executable(),
        Options {
            output_project,
            ..Default::default()
        },
    )
    .unwrap()
}

fn analyze(api: &mut Analyzer, address: u64, refresh: bool) -> Box<FunctionAnalysis> {
    let Output::Function { analysis } =
        api.execute(Command::Function { address, refresh }).unwrap()
    else {
        panic!("Expected function output");
    };
    analysis
}

fn discover(api: &mut Analyzer) -> Result<(DiscoverySnapshot, bool), Error> {
    api.execute(Command::Discover {}).map(|output| {
        let Output::Discovery { snapshot, complete } = output else {
            panic!("Expected discovery output");
        };
        (*snapshot, complete)
    })
}

/// A mapped, file-backed address the worker refuses as a discovery seed.
fn data_address(api: &Analyzer) -> u64 {
    api.data
        .info
        .sections
        .iter()
        .find(|s| !s.executable && s.file_size > 0 && s.size > 0)
        .expect("fixture has a file-backed data section")
        .address
}

#[test]
fn failed_and_cancelled_sessions_still_checkpoint_completed_work() {
    let Some(f) = fixture() else {
        return;
    };
    let path = f.directory.path().join("after-failure.grproj");
    let mut api = open(&f, Some(path.clone()));
    // Discovery first: inventory changes invalidate earlier function results.
    let mut committed = None;
    for _ in 0..4 {
        let (snapshot, _) = discover(&mut api).unwrap();
        if snapshot.batches > 0 {
            committed = Some(snapshot);
            break;
        }
    }
    let committed = committed.expect("fixture discovery commits a batch");
    let computed = analyze(&mut api, f.a, false);
    let Output::Strings { strings, .. } =
        api.execute(Command::Strings { minimum_length: 4 }).unwrap()
    else {
        panic!()
    };
    assert!(!strings.is_empty());
    let Output::Crypto { matches, .. } = api.execute(Command::Crypto {}).unwrap() else {
        panic!()
    };
    assert!(!matches.is_empty());

    // An ordinary deadline failure stops the worker but not the session.
    api.options.worker_timeout = Duration::from_nanos(1);
    assert_eq!(
        api.execute(Command::Function {
            address: f.b,
            refresh: false
        })
        .unwrap_err()
        .code,
        ErrorCode::Timeout
    );
    assert!(api.worker.is_none());
    api.options.worker_timeout = WORKER_REQUEST_TIMEOUT;
    assert!(matches!(
        api.execute(Command::Info {}).unwrap(),
        Output::Info { .. }
    ));
    assert!(matches!(
        api.execute(Command::Annotations {}).unwrap(),
        Output::Annotations { .. }
    ));
    assert_eq!(
        api.execute(Command::Function {
            address: f.a,
            refresh: false
        })
        .unwrap_err()
        .code,
        ErrorCode::SessionClosed
    );
    assert!(matches!(
        api.execute(Command::SaveProject { embed_binary: true }).unwrap(),
        Output::ProjectSaved { functions } if functions >= 1
    ));

    // Permanent cancellation still allows reading and checkpointing.
    api.cancellation().cancel();
    for command in [
        Command::Discover {},
        Command::Function {
            address: f.a,
            refresh: false,
        },
    ] {
        assert_eq!(api.execute(command).unwrap_err().code, ErrorCode::Cancelled);
    }
    assert!(matches!(
        api.execute(Command::Info {}).unwrap(),
        Output::Info { .. }
    ));
    api.execute(Command::SaveProject { embed_binary: true })
        .unwrap();
    drop(api);

    let loaded = crate::project::ProjectData::load(&path).unwrap();
    assert_eq!(loaded.data.strings.len(), strings.len());
    assert_eq!(loaded.data.crypto.len(), matches.len());
    let saved = loaded.data.discovery.as_ref().unwrap();
    assert_eq!(saved.batches, committed.batches);
    assert_eq!(saved.done, committed.done);
    drop(loaded);
    let mut api = Analyzer::open(
        Input::Project {
            path,
            external_binary: None,
        },
        &executable(),
        Options::default(),
    )
    .unwrap();
    let restored = analyze(&mut api, f.a, false);
    assert_eq!(restored.decompiled_origin, Origin::Saved);
    assert_eq!(restored.text, computed.text);
}

#[test]
fn discovery_resumes_on_verified_workers_and_bounds_failures_and_restarts() {
    let Some(f) = fixture() else {
        return;
    };
    let mut api = open(&f, None);
    let bad = data_address(&api);
    // An effective name the first worker never saw: a restart must replay it.
    api.data
        .info
        .functions
        .iter_mut()
        .find(|v| v.address == f.a)
        .unwrap()
        .name = "resumed_branch".into();
    api.update_context();
    api.discovery = Some(Discovery::new(None, [f.a, bad, f.b], false));

    // The whole batch fails; every seed is re-queued for a single retry.
    assert_eq!(
        discover(&mut api).unwrap_err().code,
        ErrorCode::WorkerFailed
    );
    assert!(api.worker.is_none());
    let state = api.discovery.as_ref().unwrap();
    assert_eq!(state.remaining(), 3);
    assert_eq!(state.batches, 0);
    assert_eq!(api.data.discovery.as_ref().unwrap().pending.len(), 3);

    // The next explicit call resumes on a fresh worker epoch.
    let (snapshot, _) = discover(&mut api).unwrap();
    assert_eq!((api.discovery_resumes, api.worker_epoch), (1, 2));
    assert!(snapshot.done.contains(&f.a));
    assert!(analyze(&mut api, f.a, true).text.contains("resumed_branch"));

    // The rejected seed fails again on its own and becomes terminal.
    assert_eq!(
        discover(&mut api).unwrap_err().code,
        ErrorCode::WorkerFailed
    );
    let state = api.discovery.as_ref().unwrap();
    assert_eq!(state.status(bad), Some(crate::discovery::Status::Failed));
    assert_eq!(state.report.failed_functions, 1);
    assert_eq!(state.status(f.a), Some(crate::discovery::Status::Done));
    let saved = api.data.discovery.as_ref().unwrap();
    assert_eq!(saved.failed, vec![bad]);
    assert!(saved.done.contains(&f.a));

    let mut complete = false;
    for _ in 0..64 {
        let (snapshot, done) = discover(&mut api).unwrap();
        assert!(snapshot.done.contains(&f.a));
        if done {
            // The PE entry includes CRT startup and can hit its own walk
            // limit; either analyzed terminal state proves the retry ran.
            assert!(matches!(
                snapshot.status(f.b),
                Some(crate::discovery::Status::Done | crate::discovery::Status::PartialByOwnLimit)
            ));
            assert_eq!(snapshot.report.failed_functions, 1);
            complete = true;
            break;
        }
    }
    assert!(complete);
    assert_eq!((api.discovery_resumes, api.worker_epoch), (2, 3));

    // Replacement workers that never answer spend the remaining budget.
    let stall = f
        .directory
        .path()
        .join(if cfg!(windows) { "stall.exe" } else { "stall" });
    let output = std::process::Command::new("rustc")
        .args(["--edition=2024", "-C", "target-feature=+crt-static"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/headless_stall.rs"
        ))
        .arg("-o")
        .arg(&stall)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    api.stop();
    api.executable = stall;
    api.options.worker_timeout = Duration::from_millis(200);
    api.discovery = Some(Discovery::new(None, [f.a], false));
    assert_eq!(discover(&mut api).unwrap_err().code, ErrorCode::Timeout);
    assert_eq!((api.discovery_resumes, api.worker_epoch), (3, 4));
    let started = Instant::now();
    assert_eq!(
        discover(&mut api).unwrap_err().code,
        ErrorCode::SessionClosed
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!((api.discovery_resumes, api.worker_epoch), (3, 4));
    assert!(api.worker.is_none());
    // A failed restart has no batch in flight, so the seed is not charged.
    assert_eq!(api.discovery.as_ref().unwrap().remaining(), 1);
}

#[test]
fn replacement_workers_must_match_the_retained_image() {
    let Some(f) = fixture() else {
        return;
    };
    let mut api = open(&f, None);
    // A mismatched retained mapping must reject the replacement worker.
    api.data.info.entry = f.a;
    api.stop();
    assert_eq!(
        discover(&mut api).unwrap_err().code,
        ErrorCode::WorkerFailed
    );
    assert!(api.worker.is_none());
    assert_eq!(api.discovery_resumes, 1);
}
