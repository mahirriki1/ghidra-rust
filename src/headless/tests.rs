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
    // Test builds may name an explicit headless worker.
    if let Some(explicit) = std::env::var_os("GHIDRA_RUST_TEST_WORKER") {
        let explicit = PathBuf::from(explicit);
        assert!(
            explicit.is_file(),
            "GHIDRA_RUST_TEST_WORKER does not name a built worker executable"
        );
        return explicit;
    }
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

#[cfg(target_os = "linux")]
#[test]
fn debug_disabled_is_persisted_and_preserved_on_verified_restart() {
    let f = fixture().unwrap();
    let checkpoint = f.directory.path().join("debug-off.grproj");
    let mut api = Analyzer::open(
        Input::Binary(f.path.clone()),
        &executable(),
        Options {
            use_debug_info: Some(false),
            output_project: Some(checkpoint.clone()),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(!api.data.use_debug_info && api.data.debug_state.is_empty());
    let first = analyze(&mut api, f.a, false);
    api.restart().unwrap();
    let refreshed = analyze(&mut api, f.a, true);
    assert_eq!(first.text, refreshed.text);
    assert_eq!(
        refreshed.semantics.prototype_source,
        crate::semantic::PrototypeSource::Inferred
    );
    // Checkpoint the setting itself, alongside the retained pseudocode.
    api.execute(Command::SaveProject { embed_binary: true })
        .unwrap();
    let loaded = ProjectData::load(&checkpoint).unwrap();
    assert!(!loaded.data.use_debug_info);
}

#[cfg(target_os = "linux")]
#[test]
fn worker_exit_during_debug_open_retries_without_debug() {
    use std::os::unix::fs::PermissionsExt;
    let f = fixture().unwrap();
    let info = crate::analysis::LoadedProgram::open(f.path.to_str().unwrap())
        .unwrap()
        .info;
    let executable = f.directory.path().join("retry-worker.py");
    let info = serde_json::to_string(&info).unwrap();
    let script = format!(
        r#"#!/usr/bin/python3
import sys,json,os
info=json.loads({info:?})
for line in sys.stdin:
    msg=json.loads(line); req=msg['request']; kind=req['kind']
    if kind=='open':
        if req.get('debug',{{}}).get('enabled',True): os._exit(9)
        st=os.stat('/input/binary')
        info['source_identity']={{'device':st.st_dev,'inode':st.st_ino,'inode_high':0}}
        reply={{'kind':'opened','info':info}}
    elif kind=='sync_functions': reply={{'kind':'functions_synced'}}
    elif kind=='sync_signatures': reply={{'kind':'signatures_synced','binary_sha256':req['binary_sha256'],'context':req['context'],'unapplied':[]}}
    else: reply={{'kind':'error','message':'unsupported test request'}}
    print(json.dumps({{'id':msg['id'],'response':reply}}),flush=True)
"#
    );
    std::fs::write(&executable, script).unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let checkpoint = f.directory.path().join("fallback.grproj");
    let mut api = Analyzer::open(
        Input::Binary(f.path),
        &executable,
        Options {
            output_project: Some(checkpoint.clone()),
            ..Options::default()
        },
    )
    .unwrap();
    assert!(!api.data.use_debug_info && api.data.debug_state.is_empty());
    let Output::Info {
        info,
        use_debug_info,
        debug_status,
        ..
    } = api.execute(Command::Info {}).unwrap()
    else {
        panic!()
    };
    assert!(!use_debug_info);
    assert_eq!(
        debug_status,
        crate::debug_info::DebugUseStatus::DisabledAfterOpenFailure
    );
    assert!(crate::debug_info::has_open_fallback(&info));
    api.execute(Command::SaveProject { embed_binary: true })
        .unwrap();
    let saved = ProjectData::load(&checkpoint).unwrap();
    assert!(!saved.data.use_debug_info);
    assert!(crate::debug_info::has_open_fallback(&saved.data.info));
    drop(api);
    let mut reopened = Analyzer::open(
        Input::Project {
            path: checkpoint.clone(),
            external_binary: None,
        },
        &executable,
        Options::default(),
    )
    .unwrap();
    let Output::Info {
        info,
        use_debug_info,
        debug_status,
        ..
    } = reopened.execute(Command::Info {}).unwrap()
    else {
        panic!()
    };
    assert!(!use_debug_info);
    assert_eq!(
        debug_status,
        crate::debug_info::DebugUseStatus::DisabledAfterOpenFailure
    );
    assert!(crate::debug_info::has_open_fallback(&info));
    drop(reopened);
    let mut enabled = Analyzer::open(
        Input::Project {
            path: checkpoint,
            external_binary: None,
        },
        &super::tests::executable(),
        Options {
            use_debug_info: Some(true),
            ..Options::default()
        },
    )
    .unwrap();
    let Output::Info {
        info,
        use_debug_info,
        debug_status,
        ..
    } = enabled.execute(Command::Info {}).unwrap()
    else {
        panic!()
    };
    assert!(use_debug_info);
    assert_eq!(debug_status, crate::debug_info::DebugUseStatus::Enabled);
    assert!(!crate::debug_info::has_open_fallback(&info));
}

/// A worker double for managed preparation, driven only by each physical
/// request's mode (never by Open's skip list): a normal `prepare_decompile`
/// of `f.a` exits, stalls, answers with a mismatched reply, or exits in
/// the middle of its reply (`cut`); an inference-only recovery answers with
/// the ordinary render unless `always` stops it too. With `cancel:TAG` the
/// recovery names its process TAG (visible in the host's `/proc`) when it
/// arrives and answers only a second later. The sandboxed double cannot
/// write host files, so it refuses any Open that carries a skip, and only a
/// recovery succeeds.
#[cfg(target_os = "linux")]
fn prepare_double(f: &Fixture, failure: &str, always: bool) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let mut loaded = crate::analysis::LoadedProgram::open_debug(
        f.path.to_str().unwrap(),
        &crate::debug_info::DebugOptions {
            enabled: false,
            ..Default::default()
        },
    )
    .unwrap();
    let info = serde_json::to_string(&loaded.info).unwrap();
    let graph =
        serde_json::to_string(&loaded.handle(Request::Graph { address: f.a }).unwrap()).unwrap();
    let code = serde_json::to_string(&loaded.handle(Request::Decompile { address: f.a }).unwrap())
        .unwrap();
    let path = f
        .directory
        .path()
        .join(format!("prepare-{}-{always}.py", failure.replace(':', "-")));
    let script = format!(
        r#"#!/usr/bin/python3
import sys,json,os,time
info=json.loads({info:?})
graph=json.loads({graph:?})
code=json.loads({code:?})
for line in sys.stdin:
    msg=json.loads(line); req=msg['request']; kind=req['kind']
    if kind=='open':
        enabled=req.get('debug',{{}}).get('enabled',True)
        if req.get('debug',{{}}).get('skip',[]): os._exit(3)
        st=os.stat('/input/binary')
        info['source_identity']={{'device':st.st_dev,'inode':st.st_ino,'inode_high':0}}
        reply={{'kind':'opened','info':info}}
        if enabled: reply['debug']={{'state':'test-debug','functions':1,'format':'dwarf','status':'applied'}}
    elif kind=='sync_functions': reply={{'kind':'functions_synced'}}
    elif kind=='sync_signatures': reply={{'kind':'signatures_synced','binary_sha256':req['binary_sha256'],'context':req['context'],'unapplied':[]}}
    elif kind=='graph': reply=graph
    elif kind=='prepare_decompile':
        recovery=req.get('inference_only',False)
        failure={failure:?}
        if req['address']=={a} and (not recovery or {always}):
            if failure=='timeout': time.sleep(30)
            if failure=='reject': reply=graph
            elif failure=='cut':
                sys.stdout.write(json.dumps({{'id':msg['id'],'response':code}})[:40]); sys.stdout.flush(); os._exit(152)
            else: os._exit(152)
        else:
            if recovery and failure.startswith('cancel:'):
                with open('/proc/self/comm','w') as comm: comm.write(failure[7:])
                time.sleep(1)
            reply=code
    else: reply={{'kind':'error','message':'unsupported test request'}}
    print(json.dumps({{'id':msg['id'],'response':reply}}),flush=True)
"#,
        a = f.a,
        always = if always { "True" } else { "False" },
    );
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

/// A stop before the managed baseline (an exit, including the CPU-limit
/// status, or the wall deadline) is recovered once with an inference-only
/// request on a fresh worker, and never records a per-function skip. A
/// recovery that stops too is the command's ordinary error after exactly
/// one restart; a mismatched reply is never recovered.
#[cfg(target_os = "linux")]
#[test]
fn managed_scheduler_prepare_stop_recovers_once_without_a_skip() {
    // The deadline case uses the one bounded real stall.
    for (failure, always) in [
        ("exit", false),
        ("timeout", false),
        // A reply cut off by the exit is process loss, not a rejection.
        ("cut", false),
        ("exit", true),
        ("reject", false),
    ] {
        let order = format!("{failure} always={always}");
        let f = fixture().unwrap();
        let double = prepare_double(&f, failure, always);
        let checkpoint = f.directory.path().join("recovery.grproj");
        let mut api = Analyzer::open(
            Input::Binary(f.path.clone()),
            &double,
            Options {
                output_project: Some(checkpoint.clone()),
                worker_timeout: Duration::from_secs(2),
                ..Default::default()
            },
        )
        .unwrap();
        let initial_epoch = api.worker_epoch;
        let result = api.execute(Command::Function {
            address: f.a,
            refresh: false,
        });
        let expected_epoch = initial_epoch + u64::from(failure != "reject");
        assert_eq!(api.worker_epoch, expected_epoch, "{order}: one restart");
        assert_eq!(api.discovery_resumes, 0, "{order}: its own bound");
        let Output::Info {
            info,
            use_debug_info,
            debug_status,
            debug_skipped_functions,
            ..
        } = api.execute(Command::Info {}).unwrap()
        else {
            panic!();
        };
        // The binary-wide setting and the skip list never change.
        assert!(use_debug_info, "{order}");
        assert_eq!(debug_status, crate::debug_info::DebugUseStatus::Enabled);
        assert!(!crate::debug_info::has_fallback(&info));
        assert!(debug_skipped_functions.is_empty(), "{order}");
        if failure == "reject" {
            let error = result.unwrap_err();
            assert_eq!(error.code, ErrorCode::WorkerFailed);
            assert!(error.message.contains("reply"), "{}", error.message);
            assert!(api.worker.is_none());
            continue;
        }
        if always {
            let error = result.unwrap_err();
            assert_eq!(error.code, ErrorCode::WorkerFailed, "{order}");
            assert!(
                error.message.contains("CPU time limit reached"),
                "{order}: {}",
                error.message
            );
            assert!(api.worker.is_none());
            continue;
        }
        let Output::Function { analysis } = result.unwrap() else {
            panic!();
        };
        assert_eq!(
            analysis.semantics.prototype_source,
            crate::semantic::PrototypeSource::Inferred
        );
        assert!(
            analysis.text.contains("branch_loop(uint4 param_1)"),
            "{}",
            analysis.text
        );
        api.execute(Command::SaveProject { embed_binary: true })
            .unwrap();
        drop(api);
        let saved = ProjectData::load(&checkpoint).unwrap();
        assert!(saved.data.use_debug_info);
        assert!(saved.data.debug_skip.is_empty(), "{order}");
        drop(saved);
        // A recovered function stays eligible: a real worker on the saved
        // project upgrades it without re-enabling debug info.
        let mut reopened = Analyzer::open(
            Input::Project {
                path: checkpoint,
                external_binary: None,
            },
            &executable(),
            Default::default(),
        )
        .unwrap();
        assert_eq!(
            analyze(&mut reopened, f.a, true).semantics.prototype_source,
            crate::semantic::PrototypeSource::DebugInfo,
            "{order}"
        );
    }
}

/// A cancellation while the recovery runs ends the command as cancelled:
/// the recovered render is never adopted, nothing is saved as a skip, and
/// the worker is stopped. The double names its process when the recovery
/// request arrives, and the test cancels only then.
#[cfg(target_os = "linux")]
#[test]
fn managed_scheduler_cancellation_during_recovery_is_terminal() {
    let tag = format!("grcancel{}", std::process::id() % 1_000_000);
    let f = fixture().unwrap();
    let double = prepare_double(&f, &format!("cancel:{tag}"), false);
    let options = Options {
        worker_timeout: Duration::from_secs(10),
        ..Default::default()
    };
    let cancellation = options.cancellation.clone();
    let mut api = Analyzer::open(Input::Binary(f.path.clone()), &double, options).unwrap();
    let initial_epoch = api.worker_epoch;
    let watcher = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(60);
        while Instant::now() < deadline {
            let arrived = std::fs::read_dir("/proc").unwrap().flatten().any(|entry| {
                std::fs::read_to_string(entry.path().join("comm"))
                    .is_ok_and(|comm| comm.trim_end() == tag)
            });
            if arrived {
                cancellation.cancel();
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    });
    let result = api.execute(Command::Function {
        address: f.a,
        refresh: false,
    });
    assert!(
        watcher.join().unwrap(),
        "the recovery request never arrived"
    );
    let Err(error) = result else {
        panic!("a cancelled recovery is never adopted")
    };
    assert_eq!(error.code, ErrorCode::Cancelled, "{}", error.message);
    assert_eq!(api.worker_epoch, initial_epoch + 1, "one replacement");
    assert!(api.worker.is_none());
    assert!(api.data.debug_skip.is_empty());
}

/// A reply the client already refused, or one for another request, is a
/// rejection even when it is read after the deadline; only an otherwise
/// acceptable late reply is the deadline.
#[cfg(target_os = "linux")]
#[test]
fn managed_scheduler_late_rejection_is_not_a_deadline() {
    use crate::client::{WorkerClient, WorkerEvent};
    use crate::model::WorkerResponse;
    let options = Options::default();
    let late = || Instant::now() + Duration::from_secs(600);
    let reply = |id| {
        WorkerEvent::Reply(Box::new(WorkerResponse {
            id,
            response: Response::Error {
                message: "late".into(),
            },
        }))
    };
    let exchange = |event| {
        let mut worker = WorkerClient::with_events(vec![event]);
        let error = exchange_until(
            &mut worker,
            Request::Graph { address: 0x1000 },
            Instant::now() + Duration::from_secs(60),
            &options,
        )
        .unwrap_err();
        (error.code, worker.failure())
    };
    let refused = WorkerEvent::Failed("Worker reply does not match its sent request".into());
    assert_eq!(
        exchange((late(), refused)),
        (
            ErrorCode::WorkerFailed,
            Some(crate::client::FailureKind::Rejected)
        )
    );
    assert_eq!(exchange((late(), reply(7))).0, ErrorCode::WorkerFailed);
    assert_eq!(exchange((late(), reply(1))).0, ErrorCode::Timeout);
    assert_eq!(
        exchange((Instant::now(), reply(1))).0,
        ErrorCode::CommandFailed
    );
}

#[cfg(target_os = "linux")]
#[test]
fn managed_debug_verified_cache_serves_both_real_executors() {
    use crate::semantic::PrototypeSource;
    for sibling in [false, true] {
        let fixture = fixture().unwrap();
        let mut api = Analyzer::open(
            Input::Binary(fixture.path.clone()),
            &executable(),
            Options {
                use_debug_info: Some(true),
                worker_arguments: sibling
                    .then(|| crate::worker::NO_FORK_ARGUMENT.into())
                    .into_iter()
                    .collect(),
                // Sibling startup is inside the window; host load must not
                // decide these positive checks.
                optional_floor: sibling.then_some(Duration::from_secs(10)),
                ..Options::default()
            },
        )
        .unwrap();
        let cold = analyze(&mut api, fixture.a, false);
        assert_eq!(cold.semantics.prototype_source, PrototypeSource::DebugInfo);
        assert!(
            cold.text.contains("branch_loop(uint4 count)"),
            "{}",
            cold.text
        );
        let hits = crate::client::managed_stats().cache_hits;
        for _ in 0..30 {
            // Remove only the presentation entry to exercise the lower
            // verified result cache through the ordinary command route.
            api.results
                .refresh_decompilation(fixture.a, crate::function_results::Invalidation::Refresh);
            let warm = analyze(&mut api, fixture.a, false);
            assert_eq!(warm.text, cold.text);
            assert_eq!(warm.mappings, cold.mappings);
            assert_eq!(warm.semantics, cold.semantics);
        }
        assert!(crate::client::managed_stats().cache_hits >= hits + 30);
        let refreshed = analyze(&mut api, fixture.a, true);
        assert_eq!(refreshed.text, cold.text);
        assert_eq!(refreshed.mappings, cold.mappings);
        assert_eq!(refreshed.semantics, cold.semantics);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn managed_debug_sibling_replays_an_acknowledged_long_name() {
    use crate::client::managed_decompile::PeerContext;
    use crate::semantic::PrototypeSource;
    let fixture = fixture().unwrap();
    let name = format!("renamed_{}_suffix", "n".repeat(MAX_FUNCTION_NAME_BYTES));
    let mut api = Analyzer::open(
        Input::Binary(fixture.path.clone()),
        &executable(),
        Options {
            use_debug_info: Some(true),
            worker_arguments: vec![crate::worker::NO_FORK_ARGUMENT.into()],
            optional_floor: Some(Duration::from_secs(10)),
            ..Options::default()
        },
    )
    .unwrap();

    // The public console has no rename command and project labels are
    // bounded to the inventory width. Exercise a real acknowledged Rename
    // through the shared private client, then replay the desktop's exact
    // acknowledged spelling in its ordinary sibling path.
    let Response::Renamed {
        address,
        name: acknowledged,
    } = api
        .request(Request::Rename {
            address: fixture.a,
            name: name.clone(),
        })
        .unwrap()
    else {
        panic!("missing long name acknowledgement")
    };
    assert_eq!((address, &acknowledged), (fixture.a, &name));
    let entry = api
        .data
        .info
        .functions
        .iter_mut()
        .find(|entry| entry.address == address)
        .unwrap();
    entry.name.clone_from(&acknowledged);
    api.peer_context = Some(Arc::new(PeerContext {
        launch: api.worker.as_ref().unwrap().peer_launch(),
        enabled: true,
        skip: Vec::new(),
        info: Arc::new(api.data.info.clone()),
        debug_state: api.data.debug_state.clone(),
        functions: Arc::new(effective_functions(&api.data)),
        long_names: vec![FunctionInfo {
            address,
            name: acknowledged,
        }],
        signatures: Arc::new(Vec::new()),
        unapplied: Vec::new(),
        signature_context: String::new(),
    }));
    let settled = analyze(&mut api, fixture.a, true);
    assert!(settled.text.contains(&name), "{}", settled.text);
    assert_eq!(
        settled.semantics.prototype_source,
        PrototypeSource::DebugInfo
    );
    assert!(api.data.debug_skip.is_empty());
}
