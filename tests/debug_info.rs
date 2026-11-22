//! Exercise the real disposable process, not just an in-process protocol mock.

#[cfg(target_os = "linux")]
use ghidra_rust::model::{Request, Response, WorkerRequest, WorkerResponse};
#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(target_os = "linux")]
use std::process::{Child, ChildStdin, Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
struct Process {
    child: Child,
    input: ChildStdin,
    output: Receiver<WorkerResponse>,
    /// The last 16 KiB of the worker's diagnostics.
    errors: Arc<Mutex<Vec<u8>>>,
    id: u64,
}

/// Why a worker gave no reply: it exhausted its per-request CPU budget,
/// the client's wall-clock deadline passed, or the reply stream ended
/// (including transport and engine crashes), with its exit status and
/// diagnostics.
#[cfg(target_os = "linux")]
#[derive(Debug)]
#[allow(dead_code, reason = "the fields are reported through Debug")]
enum Failure {
    CpuLimit { stderr: String },
    Timeout { stderr: String },
    Disconnected { status: String, stderr: String },
}

#[cfg(target_os = "linux")]
impl Failure {
    /// A request deadline or CPU budget stop, which debug-off can hit too.
    fn resource(&self) -> bool {
        matches!(self, Self::CpuLimit { .. } | Self::Timeout { .. })
    }
}

#[cfg(target_os = "linux")]
impl Process {
    fn start() -> Self {
        Self::start_with(&[])
    }
    fn start_with(environment: &[(&str, &str)]) -> Self {
        Self::start_configured(environment, &|_| {})
    }
    /// [`Self::start_with`], letting `configure` adjust the command first
    /// (for example to start the worker at a given priority and affinity).
    fn start_configured(environment: &[(&str, &str)], configure: &dyn Fn(&mut Command)) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"));
        configure(&mut command);
        let mut child = command
            .arg("--analysis-worker")
            .envs(environment.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let errors = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&errors);
        std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            while let Ok(n @ 1..) = stderr.read(&mut buffer) {
                let mut errors = sink.lock().unwrap();
                errors.extend_from_slice(&buffer[..n]);
                let excess = errors.len().saturating_sub(16 * 1024);
                errors.drain(..excess);
            }
        });
        let (tx, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let Ok(response) = serde_json::from_str(&line) else {
                    break;
                };
                if tx.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output,
            errors,
            id: 0,
        }
    }
    fn request(&mut self, request: Request) -> Response {
        self.request_with_timeout(request, Duration::from_secs(30))
    }
    fn request_with_timeout(&mut self, request: Request, timeout: Duration) -> Response {
        let operation = match &request {
            Request::Open { .. } => "Open",
            Request::Decompile { .. } | Request::DecompileWithLocals { .. } => "Decompile",
            _ => "request",
        };
        self.try_request(request, timeout)
            .unwrap_or_else(|failure| panic!("worker must reply to {operation}: {failure:?}"))
    }
    /// One exchange within `timeout`, as the desktop and headless clients
    /// bound it. A failure stops the worker and reports how it ended.
    fn try_request(&mut self, request: Request, timeout: Duration) -> Result<Response, Failure> {
        self.id += 1;
        let written = serde_json::to_writer(
            &mut self.input,
            &WorkerRequest {
                id: self.id,
                request,
            },
        )
        .is_ok()
            && self.input.write_all(b"\n").is_ok()
            && self.input.flush().is_ok();
        let received = if written {
            self.output.recv_timeout(timeout)
        } else {
            Err(RecvTimeoutError::Disconnected)
        };
        match received {
            Ok(response) => {
                assert_eq!(response.id, self.id);
                Ok(response.response)
            }
            Err(RecvTimeoutError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                Err(Failure::Timeout {
                    stderr: self.stderr(),
                })
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The reply stream ended; collect the exit, bounded.
                let deadline = Instant::now() + Duration::from_secs(5);
                let status = loop {
                    match self.child.try_wait() {
                        Ok(Some(status)) => break Some(status),
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        _ => {
                            let _ = self.child.kill();
                            break self.child.wait().ok();
                        }
                    }
                };
                // Let the diagnostics reader drain the closed pipe.
                std::thread::sleep(Duration::from_millis(50));
                let stderr = self.stderr();
                if status.and_then(|status| status.code())
                    == Some(ghidra_rust::limits::CPU_LIMIT_EXIT)
                {
                    Err(Failure::CpuLimit { stderr })
                } else {
                    Err(Failure::Disconnected {
                        status: format!("{status:?}"),
                        stderr,
                    })
                }
            }
        }
    }
    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.errors.lock().unwrap()).into_owned()
    }
}

#[cfg(target_os = "linux")]
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(target_os = "linux")]
fn fixture(debug: bool) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("sample");
    let mut command = Command::new("gcc");
    command.args(["-O0", "-fno-pie", "-no-pie", "-fno-inline"]);
    if debug {
        command.arg("-g");
    }
    assert!(
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/sample.c"
            ))
            .arg("-o")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    (directory, path)
}
#[cfg(target_os = "linux")]
fn open(
    worker: &mut Process,
    path: &std::path::Path,
    enabled: bool,
) -> ghidra_rust::model::BinaryInfo {
    let response = worker.request(Request::Open {
        path: path.to_string_lossy().into(),
        debug: ghidra_rust::debug_info::DebugOptions {
            enabled,
            ..Default::default()
        },
    });
    let Response::Opened { info, .. } = response else {
        panic!("{response:?}")
    };
    info
}
#[cfg(target_os = "linux")]
fn decompile(worker: &mut Process, address: u64) -> (String, ghidra_rust::semantic::SemanticInfo) {
    let response = worker.request(Request::Decompile { address });
    let Response::Decompiled {
        text, semantics, ..
    } = response
    else {
        panic!("{response:?}")
    };
    (text, semantics)
}
#[cfg(target_os = "linux")]
#[test]
fn source_prototypes_and_toggle_in_real_workers() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, path) = fixture(true);
    let mut worker = Process::start();
    let info = open(&mut worker, &path, true);
    let mut main_text = String::new();
    for (name, declaration) in [
        ("main", "int4 main(int4 argc,char **argv)"),
        ("decode_xor", "void decode_xor(char *output)"),
        ("branch_loop", "uint4 branch_loop(uint4 count)"),
    ] {
        let address = info
            .functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .address;
        let (text, semantics) = decompile(&mut worker, address);
        assert!(text.contains(declaration), "{text}");
        assert!(!text.contains("param_1"), "{text}");
        assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
        if name == "main" {
            main_text = text;
        }
    }
    let main = info
        .functions
        .iter()
        .find(|f| f.name == "main")
        .unwrap()
        .address;
    assert_eq!(main_text, decompile(&mut worker, main).0);
    let mut disabled = Process::start();
    open(&mut disabled, &path, false);
    let (text, semantics) = decompile(&mut disabled, main);
    assert!(text.contains("xunknown8 main(int4 param_1)"), "{text}");
    assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    let mut restored = Process::start();
    open(&mut restored, &path, true);
    assert_eq!(main_text, decompile(&mut restored, main).0);
}
#[cfg(target_os = "linux")]
#[test]
fn stripped_fixture_keeps_inference() {
    let (_directory, path) = fixture(false);
    let mut worker = Process::start();
    let info = open(&mut worker, &path, true);
    let address = info
        .functions
        .iter()
        .find(|f| f.name == "main")
        .unwrap()
        .address;
    let (text, semantics) = decompile(&mut worker, address);
    assert!(text.contains("xunknown8 main(int4 param_1)"), "{text}");
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::Inferred
    );
}

/// The mandatory native Windows check: the VS-clang PE with DWARF through
/// the production managed client (contained job workers, the sibling
/// executor), from both the console worker and the GUI-subsystem desktop
/// executable in worker mode. Debug-off gives inference first; the managed
/// result upgrades all three declarations to their debug prototypes.
#[cfg(windows)]
#[test]
fn mandatory_vs_clang_dwarf_pe_prototypes() {
    use ghidra_rust::semantic::PrototypeSource;
    let Some(path) = std::env::var_os("GHIDRA_RUST_TEST_PE_DWARF") else {
        eprintln!("Set GHIDRA_RUST_TEST_PE_DWARF using scripts/build-windows.ps1");
        return;
    };
    let path = std::path::PathBuf::from(path);
    let declarations = [
        ("main", "int4 main(int4 argc,char **argv)"),
        ("decode_xor", "void decode_xor(char *output)"),
        ("branch_loop", "uint4 branch_loop(uint4 count)"),
    ];
    let mut off = managed_session(&path, false, Executor::Fork, &[]);
    for exe in [
        env!("CARGO_BIN_EXE_ghidra-rust-headless"),
        env!("CARGO_BIN_EXE_ghidra-rust"),
    ] {
        for executor in [Executor::Fork, Executor::Sibling] {
            let mut api =
                managed_session_with(&path, true, executor, std::path::Path::new(exe), &[]);
            for (name, declaration) in declarations {
                let address = managed_address(&mut api, name);
                let (off_text, _, off_semantics) = managed_function(&mut off, address, false);
                assert!(!off_text.contains(declaration), "{off_text}");
                assert_eq!(off_semantics.prototype_source, PrototypeSource::Inferred);
                for refresh in [false, true] {
                    let (text, _, semantics) = managed_function(&mut api, address, refresh);
                    assert!(
                        text.contains(declaration),
                        "{exe} {executor:?} refresh={refresh} {name}: {text}
{:?}",
                        semantics.warnings
                    );
                    assert_eq!(
                        semantics.prototype_source,
                        PrototypeSource::DebugInfo,
                        "{exe} {executor:?} {name}"
                    );
                }
            }
            assert!(managed_skips(&mut api).is_empty());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn clang_x86_32_and_64_linked_dwarf_use_the_engine_abi() {
    for target in ["i386-unknown-linux-gnu", "x86_64-unknown-linux-gnu"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("abi");
        let output = Command::new("/usr/bin/clang")
            .args([
                "-target",
                target,
                "-g",
                "-gdwarf-4",
                "-O0",
                "-fno-pie",
                "-no-pie",
                "-nostdlib",
                "-Wl,-e,fixture_entry",
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/debug_abi.c"
            ))
            .arg("-o")
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut worker = Process::start();
        let info = open(&mut worker, &path, true);
        let address = info
            .functions
            .iter()
            .find(|f| f.name == "fixture_entry")
            .unwrap()
            .address;
        let (text, semantics) = decompile(&mut worker, address);
        assert!(
            text.contains("int4 fixture_entry(int4 count)"),
            "{target}: {text}"
        );
        assert_eq!(
            semantics.prototype_source,
            ghidra_rust::semantic::PrototypeSource::DebugInfo
        );
    }
}
#[cfg(target_os = "linux")]
#[test]
fn applied_user_signature_and_local_rename_override_debug_names() {
    use ghidra_rust::{semantic::*, signatures::*};
    let (_directory, path) = fixture(true);
    let mut worker = Process::start();
    let info = open(&mut worker, &path, true);
    let branch = info
        .functions
        .iter()
        .find(|f| f.name == "branch_loop")
        .unwrap()
        .address;
    let ty = SignatureType {
        base: SignatureBase::U32,
        pointer_depth: 0,
    };
    let signatures = vec![FunctionSignature {
        function: branch,
        engine: SIGNATURE_FINGERPRINT.into(),
        abi: "x86:LE:64:default:gcc".into(),
        return_type: ty,
        parameters: vec![SignatureParameter {
            name: "limit".into(),
            ty,
        }],
    }];
    let response = worker.request(Request::SyncSignatures {
        binary_sha256: info.sha256,
        context: state_digest(&signatures),
        signatures,
    });
    assert!(
        matches!(response, Response::SignaturesSynced { .. }),
        "{response:?}"
    );
    let (text, semantics) = decompile(&mut worker, branch);
    assert!(text.contains("uint4 branch_loop(uint4 limit)"), "{text}");
    assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    let mut names = Process::start();
    let info = open(&mut names, &path, true);
    let main = info
        .functions
        .iter()
        .find(|f| f.name == "main")
        .unwrap()
        .address;
    let (_, semantics) = decompile(&mut names, main);
    let argc = semantics.locals.iter().find(|v| v.name == "argc").unwrap();
    assert!(argc.signature_parameter.is_none());
    let response = names.request(Request::DecompileWithLocals {
        address: main,
        renames: vec![LocalRename {
            identity: argc.identity.clone(),
            name: "arg_count".into(),
        }],
    });
    let Response::Decompiled { text, .. } = response else {
        panic!("{response:?}")
    };
    assert!(
        text.contains("int4 main(int4 arg_count,char **argv)"),
        "{text}"
    );
    assert!(
        decompile(&mut names, main)
            .0
            .contains("int4 main(int4 argc,char **argv)")
    );
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod common;
#[cfg(target_os = "linux")]
#[test]
fn arm64_elf_and_macho_synthetic_prototypes_veto_wrong_entry_registers() {
    for macho in [false, true] {
        for (register, expected) in [(0, true), (1, false)] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("arm64");
            let (bytes, address) = common::dwarf_prototype(macho, register);
            std::fs::write(&path, bytes).unwrap();
            let mut worker = Process::start();
            open(&mut worker, &path, true);
            let (text, semantics) = decompile(&mut worker, address);
            assert_eq!(
                semantics.prototype_source == ghidra_rust::semantic::PrototypeSource::DebugInfo,
                expected,
                "{macho}: {text}"
            );
            if expected {
                assert!(
                    text.contains(if macho {
                        "int4 _fixture_entry(int4 count)"
                    } else {
                        "int4 fixture_entry(int4 count)"
                    }),
                    "{text}"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn sandboxed_macho_companions_are_bound_verified_and_protected() {
    use ghidra_rust::client::{WorkerClient, WorkerEvent};
    use std::time::{Duration, Instant};
    fn uuid(mut image: Vec<u8>, value: u8) -> Vec<u8> {
        let count = u32::from_le_bytes(image[16..20].try_into().unwrap());
        let size = u32::from_le_bytes(image[20..24].try_into().unwrap());
        let at = 32 + size as usize;
        image[at..at + 4].copy_from_slice(&0x1bu32.to_le_bytes());
        image[at + 4..at + 8].copy_from_slice(&24u32.to_le_bytes());
        image[at + 8..at + 24].fill(value);
        image[16..20].copy_from_slice(&(count + 1).to_le_bytes());
        image[20..24].copy_from_slice(&(size + 24).to_le_bytes());
        image
    }
    fn request(worker: &mut WorkerClient, request: Request) -> Response {
        let id = worker.send(request).unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match worker.poll() {
                Some(WorkerEvent::Reply(reply)) => {
                    assert_eq!(reply.id, id);
                    return reply.response;
                }
                Some(WorkerEvent::Failed(error)) => panic!("{error}"),
                None => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let binary = directory.path().join("original");
    std::fs::write(&binary, uuid(common::macho().0, 7)).unwrap();
    let companion = ghidra_rust::debug_info::companion::automatic(&binary).unwrap();
    std::fs::create_dir_all(companion.parent().unwrap()).unwrap();
    let (debug, address) = common::dwarf_prototype(true, 0);
    let debug = uuid(debug, 7);
    std::fs::write(&companion, &debug).unwrap();
    for explicit in [false, true] {
        let mut worker = WorkerClient::start_using_executable_and_debug(
            eframe::egui::Context::default(),
            &binary,
            std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless")),
            explicit.then_some(companion.as_path()),
        )
        .unwrap();
        let response = request(
            &mut worker,
            Request::Open {
                path: binary.to_string_lossy().into_owned(),
                debug: Default::default(),
            },
        );
        let Response::Opened {
            info,
            debug: Some(summary),
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert_eq!(summary.source.as_ref().unwrap().uuid, "07".repeat(16));
        assert_eq!(
            summary.source.as_ref().unwrap().path,
            companion.to_string_lossy()
        );
        let response = request(&mut worker, Request::Decompile { address });
        let Response::Decompiled {
            text, semantics, ..
        } = response
        else {
            panic!("{response:?}")
        };
        assert!(text.contains("int4 _fixture_entry(int4 count)"), "{text}");
        assert_eq!(
            semantics.prototype_source,
            ghidra_rust::semantic::PrototypeSource::DebugInfo
        );
        let alias = directory.path().join(format!("alias-{explicit}"));
        std::fs::hard_link(&companion, &alias).unwrap();
        let protection = worker.protection().bind_snapshot(&info).unwrap();
        let result = ghidra_rust::session::Session::new(info.sha256).save(&alias, &protection);
        assert!(result.is_err(), "companion aliases must be protected");
        assert_eq!(std::fs::read(&companion).unwrap(), debug);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gcc_nondefault_calling_conventions_never_receive_locked_debug_prototypes() {
    use ghidra_rust::semantic::PrototypeSource;
    for width in ["-m32", "-m64"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abi");
        let output = Command::new("gcc")
            .args([
                width,
                "-g",
                "-O0",
                "-fno-pie",
                "-no-pie",
                "-fno-stack-protector",
                "-nostdlib",
                "-Wl,-e,fixture_entry",
            ])
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/debug_calling_conventions.c"
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
        let mut worker = Process::start();
        let info = open(&mut worker, &path, true);
        let expected: &[&str] = if width == "-m32" {
            &["std_callee", "fast_callee", "reg_callee"]
        } else {
            &["ms_callee"]
        };
        for name in expected {
            let address = info
                .functions
                .iter()
                .find(|f| f.name == *name)
                .unwrap()
                .address;
            let (text, semantics) = decompile(&mut worker, address);
            assert_eq!(
                semantics.prototype_source,
                PrototypeSource::Inferred,
                "{width} {name}: {text}"
            );
        }
        let address = info
            .functions
            .iter()
            .find(|f| f.name == "default_callee")
            .unwrap()
            .address;
        let (text, semantics) = decompile(&mut worker, address);
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::DebugInfo,
            "{width}: {text}"
        );
        assert!(text.contains("default_callee(int4 a,int4 b)"), "{text}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn hostile_abbreviation_tables_return_partial_before_open_deadline() {
    for count in [20_000usize, 400_000] {
        let mut abbrev = vec![1, 0x11, 1];
        for _ in 0..count {
            abbrev.extend_from_slice(&[3, 0x19]);
        }
        abbrev.extend_from_slice(&[0, 0, 0]);
        let mut info = vec![0; 11];
        info[4..6].copy_from_slice(&4u16.to_le_bytes());
        info[10] = 8;
        info.resize(info.len() + count, 1);
        let len = (info.len() - 4) as u32;
        info[..4].copy_from_slice(&len.to_le_bytes());
        let bytes = common::replace_elf_dwarf(common::dwarf_prototype(false, 0).0, &info, &abbrev);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hostile");
        std::fs::write(&path, bytes).unwrap();
        let mut worker = Process::start();
        worker.id += 1;
        serde_json::to_writer(
            &mut worker.input,
            &WorkerRequest {
                id: worker.id,
                request: Request::Open {
                    path: path.to_string_lossy().into_owned(),
                    debug: Default::default(),
                },
            },
        )
        .unwrap();
        worker.input.write_all(b"\n").unwrap();
        worker.input.flush().unwrap();
        let reply = worker
            .output
            .recv_timeout(Duration::from_secs(3))
            .expect("hostile DWARF must not make Open slow or kill the worker");
        let Response::Opened {
            debug: Some(summary),
            ..
        } = reply.response
        else {
            panic!("{:?}", reply.response)
        };
        assert_eq!(
            summary.status,
            ghidra_rust::debug_info::DebugStatus::Partial
        );
        assert_eq!(summary.functions, 0);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn original_coff_fixtures_cover_i386_prefix_and_codeview_negative() {
    for (target, emulation, entry) in [
        ("i686-pc-windows-msvc", "i386pe", "_fixture_entry@4"),
        ("x86_64-pc-windows-msvc", "i386pep", "fixture_entry"),
    ] {
        for dwarf in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let object = dir.path().join("fixture.obj");
            let image = dir.path().join("fixture.exe");
            let mut command = Command::new("/usr/bin/clang");
            if target.starts_with("i686") {
                command.arg("-DFIXTURE_STDCALL");
            }
            let output = command
                .args([
                    "-target",
                    target,
                    "-g",
                    if dwarf { "-gdwarf-4" } else { "-gcodeview" },
                    "-O0",
                    "-fno-stack-protector",
                    "-c",
                ])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/debug_abi.c"
                ))
                .arg("-o")
                .arg(&object)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = Command::new("ld")
                .args(["-m", emulation, "--entry", entry, "--subsystem", "console"])
                .arg(&object)
                .arg("-o")
                .arg(&image)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            // A companion PDB is irrelevant to this worker and must never be read.
            std::fs::write(dir.path().join("fixture.pdb"), b"original non-PDB marker").unwrap();
            let mut worker = Process::start();
            let info = open(&mut worker, &image, true);
            let address = info
                .functions
                .iter()
                .find(|f| f.name == entry)
                .unwrap()
                .address;
            let (text, semantics) = decompile(&mut worker, address);
            assert_eq!(
                semantics.prototype_source == ghidra_rust::semantic::PrototypeSource::DebugInfo,
                dwarf,
                "{target}: {text}"
            );
            if dwarf {
                assert!(text.contains("int4 count"), "{text}");
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn gate_image(case: &str) -> (Vec<u8>, u64) {
    let (image, base) = common::dwarf_prototype(false, 0);
    let mut abbrev = vec![
        1, 0x11, 1, 0, 0, 2, 0x2e, 1, 0x11, 1, 3, 8, 0x49, 0x13, 0x36, 0x0b, 0, 0, 3, 5, 0, 3, 8,
        0x49, 0x13, 2, 0x18, 0, 0, 4, 5, 0, 3, 8, 0x49, 0x13, 2, 0x18, 0x1c, 0x19, 0, 0, 5, 0x18,
        0, 0, 0, 6, 0x24, 0, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, 7, 0x13, 0, 0, 0, 8, 0x2e, 1, 0x11, 1,
        0x31, 0x13, 0, 0, 9, 0x2e, 1, 3, 8, 0x49, 0x13, 0, 0, 10, 0x2e, 1, 0x11, 1, 3, 8, 0x49,
        0x10, 0x36, 0x0b, 0, 0, 11, 5, 0, 3, 8, 0x49, 0x10, 2, 0x18, 0, 0, 12, 0x2e, 1, 0x11, 1, 3,
        8, 0x31, 0x13, 0x36, 0x0b, 0, 0, 0,
    ];
    if case == "locations" {
        let at = abbrev
            .windows(4)
            .position(|w| w == [0x49, 0x13, 2, 0x18])
            .unwrap();
        abbrev[at + 3] = 0x17;
    }
    let mut info = vec![0; 11];
    info[4..6].copy_from_slice(&4u16.to_le_bytes());
    info[10] = 8;
    info.push(1);
    if case == "line" {
        abbrev.splice(3..5, [0x10, 0x17, 0, 0]);
        info.extend_from_slice(&0u32.to_le_bytes());
    }
    let mut types = vec![];
    let mut origins = vec![];
    for _ in 0..if case == "duplicate" { 2 } else { 1 } {
        info.push(if case == "origin" {
            8
        } else if matches!(case, "bad_origin_type" | "origin_name_mismatch") {
            12
        } else if case == "cross_unit" {
            10
        } else {
            2
        });
        info.extend_from_slice(&if case == "tombstone" { 0 } else { base }.to_le_bytes());
        if case != "origin" {
            info.extend_from_slice(if case == "clone" {
                b"fixture_entry.constprop.0\0"
            } else {
                b"fixture_entry\0"
            });
        }
        if case == "origin" {
            origins.push(info.len());
            info.extend_from_slice(&[0; 4]);
        } else if matches!(case, "bad_origin_type" | "origin_name_mismatch") {
            if case == "origin_name_mismatch" {
                origins.push(info.len());
            }
            info.extend_from_slice(&u32::MAX.to_le_bytes());
            info.push(1);
        } else {
            types.push((info.len(), false));
            info.extend_from_slice(&[0; 4]);
            info.push(if case == "nocall" { 3 } else { 1 });
        }
        info.push(if case == "constant" {
            4
        } else if case == "cross_unit" {
            11
        } else {
            3
        });
        info.extend_from_slice(b"count\0");
        types.push((info.len(), case == "aggregate"));
        info.extend_from_slice(&[0; 4]);
        if case == "locations" {
            info.extend_from_slice(&0u32.to_le_bytes());
        } else {
            info.extend_from_slice(&[1, 0x50]);
        }
        if case == "variadic" {
            info.push(5);
        }
        info.push(0);
    }
    if matches!(case, "origin" | "origin_name_mismatch") {
        let at = info.len() as u32;
        for slot in origins {
            info[slot..slot + 4].copy_from_slice(&at.to_le_bytes());
        }
        info.push(9);
        info.extend_from_slice(if case == "origin_name_mismatch" {
            b"different_source\0"
        } else {
            b"fixture_entry\0"
        });
        types.push((info.len(), false));
        info.extend_from_slice(&[0; 4]);
        info.push(0);
    }
    let base_type = info.len() as u32;
    info.extend_from_slice(&[6, 4, 5]);
    let aggregate = info.len() as u32;
    info.extend_from_slice(&[7, 0]);
    let length = (info.len() - 4) as u32;
    info[..4].copy_from_slice(&length.to_le_bytes());
    if case == "cross_unit" {
        let offset = info.len() as u32;
        let mut second = vec![0; 11];
        second[4..6].copy_from_slice(&4u16.to_le_bytes());
        second[10] = 8;
        second.extend_from_slice(&[1, 6, 4, 5, 0]);
        let length = (second.len() - 4) as u32;
        second[..4].copy_from_slice(&length.to_le_bytes());
        for (slot, _) in types {
            info[slot..slot + 4].copy_from_slice(&(offset + 12).to_le_bytes());
        }
        info.extend_from_slice(&second);
    } else {
        for (slot, agg) in types {
            info[slot..slot + 4]
                .copy_from_slice(&if agg { aggregate } else { base_type }.to_le_bytes());
        }
    }
    (common::replace_elf_dwarf(image, &info, &abbrev), base)
}
#[cfg(target_os = "linux")]
#[test]
fn synthetic_gates_origins_and_cross_unit_references_have_independent_oracles() {
    for (case, expected) in [
        ("normal", true),
        ("origin", true),
        ("origin_name_mismatch", false),
        ("cross_unit", true),
        ("clone", false),
        ("constant", false),
        ("nocall", false),
        ("variadic", false),
        ("aggregate", false),
        ("duplicate", false),
        ("tombstone", false),
        ("bad_origin_type", false),
    ] {
        let (bytes, address) = gate_image(case);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(case);
        std::fs::write(&path, bytes).unwrap();
        let mut worker = Process::start();
        open(&mut worker, &path, true);
        let (text, semantics) = decompile(&mut worker, address);
        assert_eq!(
            semantics.prototype_source == ghidra_rust::semantic::PrototypeSource::DebugInfo,
            expected,
            "{case}: {text}"
        );
        if expected {
            assert!(text.contains("fixture_entry(int4 count)"), "{case}: {text}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn repeated_scalar_types_do_not_exhaust_a_visit_order_budget() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("types.c");
    let image = dir.path().join("types");
    let parameters = (0..32)
        .map(|n| format!("int p{n}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut text = String::new();
    for n in 0..2000 {
        text.push_str(&format!(
            "__attribute__((noinline)) int repeat_{n}({parameters}) {{return p0+{n};}}\n"
        ));
    }
    std::fs::write(&source, text).unwrap();
    let output = Command::new("gcc")
        .args([
            "-g",
            "-O0",
            "-fno-stack-protector",
            "-fno-pie",
            "-no-pie",
            "-nostdlib",
            "-Wl,-e,repeat_0",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut visited = Process::start();
    let info = open(&mut visited, &image, true);
    for function in info
        .functions
        .iter()
        .filter(|f| f.name.starts_with("repeat_"))
    {
        let (_, semantics) = decompile(&mut visited, function.address);
        assert_eq!(
            semantics.prototype_source,
            ghidra_rust::semantic::PrototypeSource::DebugInfo,
            "{}",
            function.name
        );
    }
    let last = info
        .functions
        .iter()
        .find(|f| f.name == "repeat_1999")
        .unwrap()
        .address;
    let after = decompile(&mut visited, last).0;
    let mut fresh = Process::start();
    open(&mut fresh, &image, true);
    assert_eq!(after, decompile(&mut fresh, last).0);
}

#[cfg(target_os = "linux")]
#[test]
fn projects_reverify_changed_removed_and_explicit_companions_without_trusting_hints() {
    use ghidra_rust::{
        headless::{Analyzer, Command as ApiCommand, Input, Options, Origin, Output},
        semantic::PrototypeSource,
    };
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("original");
    let project = dir.path().join("project.grproj");
    std::fs::write(&binary, common::with_macho_uuid(common::macho().0, 7)).unwrap();
    let companion = ghidra_rust::debug_info::companion::automatic(&binary).unwrap();
    std::fs::create_dir_all(companion.parent().unwrap()).unwrap();
    let (debug, address) = common::dwarf_prototype(true, 0);
    let mut debug = common::with_macho_uuid(debug, 7);
    std::fs::write(&companion, &debug).unwrap();
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"));
    let mut api = Analyzer::open(
        Input::Binary(binary.clone()),
        exe,
        Options {
            output_project: Some(project.clone()),
            ..Options::default()
        },
    )
    .unwrap();
    let Output::Function { analysis } = api
        .execute(ApiCommand::Function {
            address,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        analysis.semantics.prototype_source,
        PrototypeSource::DebugInfo
    );
    api.execute(ApiCommand::SaveProject {
        embed_binary: false,
    })
    .unwrap();
    drop(api);
    debug.push(0);
    std::fs::write(&companion, &debug).unwrap();
    let mut reopened = Analyzer::open(
        Input::Project {
            path: project.clone(),
            external_binary: Some(binary.clone()),
        },
        exe,
        Options::default(),
    )
    .unwrap();
    let Output::Function { analysis } = reopened
        .execute(ApiCommand::Function {
            address,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(analysis.decompiled_origin, Origin::Computed);
    assert_eq!(analysis.graph_origin, Origin::Saved);
    assert_eq!(
        analysis.semantics.prototype_source,
        PrototypeSource::DebugInfo
    );
    drop(reopened);
    let explicit = dir.path().join("picked.dwarf");
    std::fs::rename(&companion, &explicit).unwrap();
    // Forge a project path hint pointing to a valid matching file. Without an
    // explicit host selection this path must not cause even a successful load.
    let db = rusqlite::Connection::open(&project).unwrap();
    let body: Vec<u8> = db
        .query_row("SELECT value FROM project_data WHERE key='body'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    body["debug_source"]["path"] = explicit.to_string_lossy().into_owned().into();
    db.execute(
        "UPDATE project_data SET value=?1 WHERE key='body'",
        [serde_json::to_vec(&body).unwrap()],
    )
    .unwrap();
    drop(db);
    let mut missing = Analyzer::open(
        Input::Project {
            path: project.clone(),
            external_binary: Some(binary.clone()),
        },
        exe,
        Options::default(),
    )
    .unwrap();
    let Output::Function { analysis } = missing
        .execute(ApiCommand::Function {
            address,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        analysis.semantics.prototype_source,
        PrototypeSource::Inferred
    );
    assert_eq!(analysis.decompiled_origin, Origin::Computed);
    drop(missing);
    let mut picked = Analyzer::open(
        Input::Project {
            path: project,
            external_binary: Some(binary.clone()),
        },
        exe,
        Options {
            debug_info: Some(explicit.clone()),
            ..Options::default()
        },
    )
    .unwrap();
    let Output::Function { analysis } = picked
        .execute(ApiCommand::Function {
            address,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        analysis.semantics.prototype_source,
        PrototypeSource::DebugInfo
    );
    drop(picked);
    // Disabled means no candidate resolution or file open at all, even when an
    // explicit path is a FIFO. A touched FIFO would block a plain File::open.
    let fifo = dir.path().join("off-fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut off = Analyzer::open(
        Input::Binary(binary.clone()),
        exe,
        Options {
            use_debug_info: Some(false),
            debug_info: Some(fifo),
            ..Options::default()
        },
    )
    .unwrap();
    let Output::Function { analysis } = off
        .execute(ApiCommand::Function {
            address,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        analysis.semantics.prototype_source,
        PrototypeSource::Inferred
    );
    let mut rogue = debug.clone();
    let mut at = 0;
    while at + 13 <= rogue.len() {
        if &rogue[at..at + 13] == b"fixture_entry" {
            rogue[at..at + 13].copy_from_slice(b"foreign_entry");
            at += 13;
        } else {
            at += 1;
        }
    }
    let rogue_path = dir.path().join("rogue.dwarf");
    std::fs::write(&rogue_path, rogue).unwrap();
    let mut rogue = Analyzer::open(
        Input::Binary(binary),
        exe,
        Options {
            debug_info: Some(rogue_path),
            ..Options::default()
        },
    )
    .unwrap();
    let Output::Function { analysis } = rogue
        .execute(ApiCommand::Function {
            address,
            refresh: false,
        })
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        analysis.semantics.prototype_source,
        PrototypeSource::Inferred
    );
}

#[cfg(target_os = "linux")]
#[test]
fn coff_sysv_register_inputs_veto_the_default_windows_model() {
    let dir = tempfile::tempdir().unwrap();
    let object = dir.path().join("abi.obj");
    let image = dir.path().join("abi.exe");
    let output = Command::new("/usr/bin/clang")
        .args([
            "-target",
            "x86_64-pc-windows-msvc",
            "-g",
            "-gdwarf-4",
            "-O0",
            "-fno-stack-protector",
            "-c",
        ])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_calling_conventions.c"
        ))
        .arg("-o")
        .arg(&object)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("ld")
        .args([
            "-m",
            "i386pep",
            "--entry",
            "fixture_entry",
            "--subsystem",
            "console",
        ])
        .arg(&object)
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut worker = Process::start();
    let info = open(&mut worker, &image, true);
    for (name, expected) in [("ms_callee", true), ("sysv_callee", false)] {
        let address = info
            .functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .address;
        let (text, semantics) = decompile(&mut worker, address);
        assert_eq!(
            semantics.prototype_source == ghidra_rust::semantic::PrototypeSource::DebugInfo,
            expected,
            "{name}: {text}"
        );
    }
}

#[cfg(windows)]
#[test]
fn msvc_pe_and_its_pdb_keep_inferred_prototypes() {
    let Some(path) = std::env::var_os("GHIDRA_RUST_TEST_PE") else {
        eprintln!("Set GHIDRA_RUST_TEST_PE using scripts/build-windows.ps1");
        return;
    };
    use ghidra_rust::client::{WorkerClient, WorkerEvent};
    use ghidra_rust::model::{Request, Response};
    use ghidra_rust::semantic::PrototypeSource;
    let path = std::path::PathBuf::from(path);
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"));
    let mut worker = WorkerClient::start_using_executable_and_debug(
        eframe::egui::Context::default(),
        &path,
        exe,
        None,
    )
    .unwrap();
    let id = worker
        .send(Request::Open {
            path: path.to_string_lossy().into_owned(),
            debug: Default::default(),
        })
        .unwrap();
    let start = std::time::Instant::now();
    let info = loop {
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                let Response::Opened { info, debug, .. } = reply.response else {
                    panic!("{reply:?}")
                };
                assert!(debug.is_none());
                break info;
            }
            Some(WorkerEvent::Failed(error)) => panic!("{error}"),
            None if start.elapsed() < ghidra_rust::model::WORKER_REQUEST_TIMEOUT => {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            None => panic!("Timed out opening native MSVC fixture"),
        }
    };
    worker.stop_and_wait().unwrap();
    let address = info
        .functions
        .iter()
        .find(|f| f.name == "branch_loop")
        .unwrap()
        .address;
    let mut off = managed_session(&path, false, Executor::Sibling, &[]);
    let (text, mappings, semantics) = managed_function(&mut off, address, false);
    assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    assert!(text.contains("param_1"), "{text}");
    let mut on = managed_session(&path, true, Executor::Sibling, &[]);
    assert_eq!(
        managed_function(&mut on, address, false),
        (text, mappings, semantics)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn shared_line_headers_cannot_make_open_slow() {
    let abbrev = [1, 0x11, 0, 0x10, 0x17, 0, 0, 0];
    let mut unit = vec![0; 11];
    unit[4..6].copy_from_slice(&4u16.to_le_bytes());
    unit[10] = 8;
    unit.extend_from_slice(&[1, 0, 0, 0, 0]);
    let length = (unit.len() - 4) as u32;
    unit[..4].copy_from_slice(&length.to_le_bytes());
    let info = unit.repeat(65_536);
    let mut prologue = vec![
        1,
        1,
        1,
        (-5i8) as u8,
        14,
        13,
        0,
        1,
        1,
        1,
        1,
        0,
        0,
        0,
        1,
        0,
        0,
        1,
    ];
    for _ in 0..100_000 {
        prologue.extend_from_slice(b"d\0");
    }
    prologue.extend_from_slice(&[0, 0]);
    let mut line = vec![0; 4];
    line.extend_from_slice(&4u16.to_le_bytes());
    line.extend_from_slice(&(prologue.len() as u32).to_le_bytes());
    line.extend_from_slice(&prologue);
    let length = (line.len() - 4) as u32;
    line[..4].copy_from_slice(&length.to_le_bytes());
    // Verify that this really is a parseable, large line header; no timings or
    // acceptance oracle is derived from the implementation under test.
    let program = gimli::DebugLine::new(&line, gimli::LittleEndian)
        .program(gimli::DebugLineOffset(0), 8, None, None)
        .unwrap();
    assert_eq!(program.header().include_directories().len(), 100_000);
    let image = common::replace_elf_dwarf(common::dwarf_prototype(false, 0).0, &info, &abbrev);
    let image = common::elf_debug_section(image, ".debug_line", &line);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shared-line");
    std::fs::write(&path, image).unwrap();
    let mut worker = Process::start();
    worker.id += 1;
    serde_json::to_writer(
        &mut worker.input,
        &WorkerRequest {
            id: worker.id,
            request: Request::Open {
                path: path.to_string_lossy().into_owned(),
                debug: Default::default(),
            },
        },
    )
    .unwrap();
    worker.input.write_all(b"\n").unwrap();
    worker.input.flush().unwrap();
    let reply = worker
        .output
        .recv_timeout(Duration::from_secs(3))
        .expect("unused shared line headers must not kill or delay Open");
    let Response::Opened {
        debug: Some(summary),
        ..
    } = reply.response
    else {
        panic!("{:?}", reply.response)
    };
    assert_eq!(summary.functions, 0);
    assert_eq!(
        summary.status,
        ghidra_rust::debug_info::DebugStatus::Applied
    );
}

#[cfg(target_os = "linux")]
#[test]
fn lazy_prototypes_never_parse_unused_line_headers() {
    let (image, address) = gate_image("line");
    let image = common::elf_debug_section(image, ".debug_line", b"invalid unused line header");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unused-line");
    std::fs::write(&path, image).unwrap();
    let mut worker = Process::start();
    open(&mut worker, &path, true);
    let (text, semantics) = decompile(&mut worker, address);
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::DebugInfo,
        "{text}"
    );
    assert!(text.contains("fixture_entry(int4 count)"), "{text}");
}

#[cfg(target_os = "linux")]
#[test]
fn base_address_only_location_lists_veto_prototypes_instead_of_hiding_work() {
    let (image, address) = gate_image("locations");
    let mut locations = Vec::new();
    for _ in 0..100_000 {
        locations.extend_from_slice(&u64::MAX.to_le_bytes());
        locations.extend_from_slice(&address.to_le_bytes());
    }
    locations.extend_from_slice(&[0; 16]);
    let image = common::elf_debug_section(image, ".debug_loc", &locations);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base-only");
    std::fs::write(&path, image).unwrap();
    let mut worker = Process::start();
    open(&mut worker, &path, true);
    let (text, semantics) = decompile(&mut worker, address);
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::Inferred,
        "{text}"
    );
}

#[cfg(target_os = "linux")]
fn hostile_attribute_image(form: u8, payload: &[u8]) -> (Vec<u8>, u64) {
    let (image, address) = common::dwarf_prototype(false, 0);
    // Original linked test image, with a CU and one named void subprogram.
    // DW_AT_decl_file is unused by prototypes, and still must be validated.
    let abbrev = [
        1, 0x11, 1, 0, 0, 2, 0x2e, 0, 0x11, 1, 3, 8, 0x3a, form, 0, 0, 0,
    ];
    let mut info = vec![0; 11];
    info[4..6].copy_from_slice(&4u16.to_le_bytes());
    info[10] = 8;
    info.extend_from_slice(&[1, 2]);
    info.extend_from_slice(&address.to_le_bytes());
    info.extend_from_slice(b"fixture_entry\0");
    info.extend_from_slice(payload);
    info.push(0);
    let length = (info.len() - 4) as u32;
    info[..4].copy_from_slice(&length.to_le_bytes());
    (common::replace_elf_dwarf(image, &info, &abbrev), address)
}
#[cfg(target_os = "linux")]
fn hostile_attribute_stays_fast(form: u8, payload: &[u8]) {
    let (image, address) = hostile_attribute_image(form, payload);
    hostile_image_stays_fast(image, address, 0);
}
#[cfg(target_os = "linux")]
fn hostile_image_stays_fast(image: Vec<u8>, address: u64, indexed_functions: usize) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("hostile-form");
    std::fs::write(&path, image).unwrap();
    let mut worker = Process::start();
    let reply = worker.request_with_timeout(
        Request::Open {
            path: path.to_string_lossy().into_owned(),
            debug: Default::default(),
        },
        Duration::from_secs(3),
    );
    let Response::Opened {
        debug: Some(summary),
        ..
    } = reply
    else {
        panic!("{reply:?}");
    };
    assert_eq!(
        summary.status,
        ghidra_rust::debug_info::DebugStatus::Partial
    );
    assert_eq!(summary.functions, indexed_functions);
    let reply = worker.request_with_timeout(Request::Decompile { address }, Duration::from_secs(3));
    let Response::Decompiled {
        text, semantics, ..
    } = reply
    else {
        panic!("{reply:?}");
    };
    assert!(text.contains("fixture_entry("), "{text}");
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::Inferred
    );
    assert!(matches!(
        worker.request_with_timeout(Request::Graph { address }, Duration::from_secs(3)),
        Response::Graph { .. }
    ));
    assert!(worker.child.try_wait().unwrap().is_none());
}
#[cfg(target_os = "linux")]
#[test]
fn indirect_chain_cannot_escape_open_or_lazy_decompile_budgets() {
    let mut payload = vec![gimli::DW_FORM_indirect.0 as u8; 64 * 1024 * 1024];
    payload.push(gimli::DW_FORM_flag_present.0 as u8);
    hostile_attribute_stays_fast(gimli::DW_FORM_indirect.0 as u8, &payload);
}
#[cfg(target_os = "linux")]
#[test]
fn long_unused_inline_strings_are_rejected_before_gimli_scans() {
    let mut payload = vec![b'x'; 8 * 1024 * 1024];
    payload.push(0);
    hostile_attribute_stays_fast(gimli::DW_FORM_string.0 as u8, &payload);
}
#[cfg(target_os = "linux")]
#[test]
fn huge_unused_exprloc_and_block_are_rejected_before_gimli_decodes() {
    let length = 8 * 1024 * 1024u32;
    for form in [gimli::DW_FORM_exprloc, gimli::DW_FORM_block4] {
        let mut payload = if form == gimli::DW_FORM_exprloc {
            vec![0x80, 0x80, 0x80, 4] // ULEB128(8 MiB)
        } else {
            length.to_le_bytes().to_vec()
        };
        payload.resize(payload.len() + length as usize, 0x50);
        hostile_attribute_stays_fast(form.0 as u8, &payload);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn lazy_cross_unit_reference_rejects_an_unvalidated_indirect_type() {
    let (image, address) = common::dwarf_prototype(false, 0);
    let abbrev = [
        1, 0x11, 1, 0, 0, 2, 0x2e, 0, 0x11, 1, 3, 8, 0x49, 0x10, 0, 0, 3, 0x24, 0, 0x0b, 0x0b,
        0x3e, 0x0b, 0x3a, 0x16, 0, 0, 0,
    ];
    let header = || {
        let mut bytes = vec![0; 11];
        bytes[4..6].copy_from_slice(&4u16.to_le_bytes());
        bytes[10] = 8;
        bytes.push(1);
        bytes
    };
    let mut first = header();
    first.push(2);
    first.extend_from_slice(&address.to_le_bytes());
    first.extend_from_slice(b"fixture_entry\0");
    let reference = first.len();
    first.extend_from_slice(&[0; 4]);
    first.push(0);
    let target = first.len() as u32 + 12; // next CU's base-type DIE
    first[reference..reference + 4].copy_from_slice(&target.to_le_bytes());
    let length = (first.len() - 4) as u32;
    first[..4].copy_from_slice(&length.to_le_bytes());
    let mut second = header();
    second.extend_from_slice(&[3, 4, 5]);
    second.resize(
        second.len() + 64 * 1024 * 1024,
        gimli::DW_FORM_indirect.0 as u8,
    );
    second.extend_from_slice(&[gimli::DW_FORM_flag_present.0 as u8, 0]);
    let length = (second.len() - 4) as u32;
    second[..4].copy_from_slice(&length.to_le_bytes());
    first.extend_from_slice(&second);
    let image = common::replace_elf_dwarf(image, &first, &abbrev);
    // The function's CU passed indexing. Its referenced type's CU did not,
    // so only lazy extraction encounters the missing validation certificate.
    hostile_image_stays_fast(image, address, 1);
}

#[cfg(target_os = "linux")]
fn gcc_image(
    source: &std::path::Path,
    arguments: &[&str],
) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("image");
    let output = Command::new("gcc")
        .args(arguments)
        .arg(source)
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (directory, image)
}

#[cfg(target_os = "linux")]
fn decompile_named(
    worker: &mut Process,
    info: &ghidra_rust::model::BinaryInfo,
    name: &str,
) -> (String, ghidra_rust::semantic::SemanticInfo) {
    let address = info
        .functions
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name}"))
        .address;
    decompile(worker, address)
}

/// GCC output from original source whose engine render divided by zero when
/// a named structure became a zero-size incomplete pointee.
#[cfg(target_os = "linux")]
#[test]
fn named_structure_pointers_keep_their_prototype_without_engine_failure() {
    let (_directory, image) = gcc_image(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_opaque_session.c"
        )),
        &["-O2", "-g", "-fPIC", "-shared"],
    );
    let mut worker = Process::start();
    let info = open(&mut worker, &image, true);
    let (text, semantics) = decompile_named(&mut worker, &info, "decode_session");
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::DebugInfo
    );
    assert!(
        text.contains("SESSION * decode_session(SESSION **existing,char **cursor,int8 length)"),
        "{text}"
    );
}

/// Linkage and function names up to the symbol limit match; long parameter
/// names fall back to generated names without losing the prototype.
#[cfg(target_os = "linux")]
#[test]
fn long_function_names_match_and_long_parameter_names_fall_back() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("names.c");
    let function = format!("function_{}", "n".repeat(150));
    let parameter = format!("parameter_{}", "p".repeat(80));
    std::fs::write(
        &source,
        format!(
            "__attribute__((noinline)) int {function}(int {parameter}, char *label) \
             {{ return {parameter} + label[0]; }}\n\
             int main(int argc, char **argv) {{ return {function}(argc, argv[0]); }}\n"
        ),
    )
    .unwrap();
    let (_image_directory, image) = gcc_image(&source, &["-O0", "-g", "-fno-pie", "-no-pie"]);
    let mut worker = Process::start();
    let info = open(&mut worker, &image, true);
    let (text, semantics) = decompile_named(&mut worker, &info, &function);
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::DebugInfo,
        "{text}"
    );
    assert!(text.contains("(int4 param_1,char *label)"), "{text}");
}

/// Assembler units carry subprograms without types or parameters; they must
/// not become a confident `void f(void)`.
#[cfg(target_os = "linux")]
#[test]
fn assembler_units_keep_inferred_prototypes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("seven.s");
    std::fs::write(
        &source,
        "\t.text\n\t.globl asm_seven\n\t.type asm_seven, @function\nasm_seven:\n\
         \tmovl $7, %eax\n\tret\n\t.size asm_seven, .-asm_seven\n\
         \t.globl main\n\t.type main, @function\nmain:\n\tcall asm_seven\n\tret\n\
         \t.size main, .-main\n\t.section .note.GNU-stack,\"\",@progbits\n",
    )
    .unwrap();
    let (_image_directory, image) = gcc_image(&source, &["-g", "-fno-pie", "-no-pie"]);
    let mut worker = Process::start();
    let info = open(&mut worker, &image, true);
    let (text, semantics) = decompile_named(&mut worker, &info, "asm_seven");
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::Inferred,
        "{text}"
    );
    assert!(!text.contains("void asm_seven(void)"), "{text}");
}

/// Deeply nested scopes and very large bodies do not reject a unit or a
/// prototype; parameters precede the body.
#[cfg(target_os = "linux")]
#[test]
fn deep_and_wide_bodies_keep_their_prototypes() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("shapes.c");
    let mut text =
        String::from("__attribute__((noinline)) int deep(int depth) {\n int total = depth;\n");
    for n in 0..80 {
        text.push_str(&format!(
            " {{ volatile int level_{n} = total + {n}; total += level_{n};\n"
        ));
    }
    text.push_str(&" }".repeat(80));
    text.push_str("\n return total;\n}\n__attribute__((noinline)) int wide(int width) {\n int total = width;\n");
    for n in 0..1100 {
        text.push_str(&format!(
            " {{ volatile int a{n} = total, b{n} = a{n}, c{n} = b{n}, d{n} = c{n}, e{n} = d{n}, f{n} = e{n}, g{n} = f{n}, h{n} = g{n}, i{n} = h{n}, j{n} = i{n}, k{n} = j{n}, l{n} = k{n}, m{n} = l{n}, o{n} = m{n}; total += o{n}; }}\n"
        ));
    }
    text.push_str(
        " return total;\n}\nint main(int argc, char **argv) { (void)argv; return deep(argc) + wide(argc); }\n",
    );
    std::fs::write(&source, text).unwrap();
    let (_image_directory, image) = gcc_image(&source, &["-O0", "-g", "-fno-pie", "-no-pie"]);
    let mut worker = Process::start();
    let info = open(&mut worker, &image, true);
    for (name, declaration) in [
        ("deep", "int4 deep(int4 depth)"),
        ("main", "int4 main(int4 argc,char **argv)"),
    ] {
        let (text, semantics) = decompile_named(&mut worker, &info, name);
        assert_eq!(
            semantics.prototype_source,
            ghidra_rust::semantic::PrototypeSource::DebugInfo,
            "{name}"
        );
        assert!(text.contains(declaration), "{text}");
    }
    // `wide`'s 1,100 scopes must not reject its unit or prototype. Whether
    // its long body's debug render finishes in time is runtime policy: the
    // unverified warning appears only for a prototype that parsed (one that
    // cannot be extracted is rejected without a warning).
    let (text, semantics) = decompile_named(&mut worker, &info, "wide");
    match semantics.prototype_source {
        ghidra_rust::semantic::PrototypeSource::DebugInfo => {
            assert!(text.contains("int4 wide(int4 width)"), "{text}")
        }
        ghidra_rust::semantic::PrototypeSource::Inferred => assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == "Debug prototype is unverified"),
            "{:?}",
            semantics.warnings
        ),
    }
}

/// One generated branchy body per name: `blocks` conditional updates of an
/// accumulator and an output array, about 16 instructions each at -O2. With
/// `table`, a dense switch (a jump table) comes first, so a raw CFG walk
/// stops at its indirect jump and sees almost none of the body.
#[cfg(target_os = "linux")]
fn branchy_function(name: &str, blocks: u32, table: bool) -> String {
    let mut text = format!(
        "__attribute__((noinline)) int {name}(int a, int b, int *out)\n{{\n int acc = a ^ b;\n"
    );
    if table {
        text.push_str(" switch (a & 15) {\n");
        for case in 0..16 {
            text.push_str(&format!(
                "  case {case}: acc = acc * {scale} + out[{case}]; out[{write}] ^= b + {case}; break;\n",
                scale = case + 3,
                write = (case * 7) % 16,
            ));
        }
        text.push_str(" }\n");
    }
    for i in 0..blocks {
        let key = i.wrapping_mul(2_654_435_761) & 0xffff;
        text.push_str(&format!(
            " if ((acc ^ {key}) & {bit}) {{ acc = acc * {scale} + out[{read}]; out[{write}] = acc - b; }}\n \
             else {{ b += acc >> {shift}; if (b & {odd}) out[{other}] ^= a + {i}; }}\n",
            bit = 1 << (i % 13),
            scale = 3 + i % 7,
            read = i % 16,
            write = (i * 5) % 16,
            shift = 1 + i % 5,
            odd = key | 1,
            other = (i * 3) % 16,
        ));
    }
    text.push_str(" return acc + b;\n}\n");
    text
}

/// A -O2 image of generated branchy functions `(name, blocks, table)`,
/// each called from `main`.
#[cfg(target_os = "linux")]
fn branchy_image(functions: &[(&str, u32, bool)]) -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("large.c");
    let mut text = String::new();
    let mut calls = String::new();
    for &(name, blocks, table) in functions {
        text.push_str(&branchy_function(name, blocks, table));
        calls.push_str(&format!(" + {name}(argc, 1, v)"));
    }
    text.push_str(&format!(
        "int main(int argc, char **argv) {{ int v[16] = {{0}}; (void)argv;\n return v[3]{calls}; }}\n"
    ));
    std::fs::write(&source, text).unwrap();
    let (image_directory, image) = gcc_image(&source, &["-O2", "-g", "-fno-pie", "-no-pie"]);
    drop(directory);
    (image_directory, image)
}

/// One Decompile of `name` in a fresh worker, with debug info on or off,
/// bounded by the clients' request deadline.
#[cfg(target_os = "linux")]
fn fresh_decompile(
    image: &std::path::Path,
    name: &str,
    enabled: bool,
    environment: &[(&str, &str)],
) -> (
    Duration,
    Result<(String, ghidra_rust::semantic::SemanticInfo), Failure>,
) {
    fresh_decompile_configured(image, name, enabled, environment, &|_| {}, &|_| {})
}

/// [`fresh_decompile`] with a worker command hook and a check of the
/// started worker's process id.
#[cfg(target_os = "linux")]
fn fresh_decompile_configured(
    image: &std::path::Path,
    name: &str,
    enabled: bool,
    environment: &[(&str, &str)],
    configure: &dyn Fn(&mut Command),
    check: &dyn Fn(u32),
) -> (
    Duration,
    Result<(String, ghidra_rust::semantic::SemanticInfo), Failure>,
) {
    let mode = if enabled { Mode::On } else { Mode::Off };
    let attempt = fresh_attempt(image, name, mode, environment, configure, check);
    (attempt.wall, attempt.result)
}

/// One paired off/on comparison. Only an actual debug-off CPU or wall stop
/// is a baseline limit. A debug-on crash or wrong render after a successful
/// debug-off render is a feature failure; a debug-on CPU or wall stop that
/// debug-off escaped is unresolved until repeated with controls, because
/// the two fresh processes did not see the same scheduler service.
#[cfg(target_os = "linux")]
#[derive(Debug, PartialEq, Eq)]
enum Comparison {
    Compared(ghidra_rust::semantic::PrototypeSource),
    OffResourceLimit,
    Unresolved,
}

/// Classifies a paired run: `Err` describes a feature failure.
#[cfg(target_os = "linux")]
fn classify(
    off: Result<(), &Failure>,
    on: Result<ghidra_rust::semantic::PrototypeSource, &Failure>,
) -> Result<Comparison, String> {
    match (off, on) {
        (Err(failure), _) if failure.resource() => Ok(Comparison::OffResourceLimit),
        (Err(failure), _) => Err(format!("debug-off failed: {failure:?}")),
        (Ok(()), Ok(source)) => Ok(Comparison::Compared(source)),
        (Ok(()), Err(failure)) if failure.resource() => Ok(Comparison::Unresolved),
        (Ok(()), Err(failure)) => Err(format!(
            "debug-on failed where debug-off succeeded: {failure:?}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn load_average() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|load| load.split_whitespace().next().map(str::to_owned))
        .unwrap_or_else(|| "?".into())
}

/// User plus system CPU seconds of a live process.
#[cfg(target_os = "linux")]
fn process_cpu_seconds(pid: u32) -> Option<f64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields after the parenthesized command name start at field 3.
    let fields = stat[stat.rfind(')')? + 2..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let ticks = fields.get(11)?.parse::<f64>().ok()? + fields.get(12)?.parse::<f64>().ok()?;
    // SAFETY: sysconf only reads a configuration value.
    let hertz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (hertz > 0).then(|| ticks / hertz as f64)
}

/// How one fresh raw worker renders: debug info off, on, or on with the
/// managed inference-only recovery request (the within-mode control: the
/// same indexed Open, no evidence, offer or optional work).
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Off,
    On,
    OnInferenceOnly,
}

/// One fresh-process render and what it cost.
#[cfg(target_os = "linux")]
struct Attempt {
    mode: Mode,
    wall: Duration,
    /// Request CPU seconds, when the worker survived to be measured.
    cpu: Option<f64>,
    load: (String, String),
    result: Result<(String, ghidra_rust::semantic::SemanticInfo), Failure>,
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for Attempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let outcome = match &self.result {
            Ok((_, semantics)) => format!("{:?}", semantics.prototype_source),
            Err(Failure::CpuLimit { .. }) => "CPU limit (exit 152)".into(),
            Err(Failure::Timeout { .. }) => "wall deadline".into(),
            Err(Failure::Disconnected { status, .. }) => format!("disconnected {status}"),
        };
        write!(
            f,
            "{:?}: {outcome} in {:?}, request CPU {}, load {} -> {}",
            self.mode,
            self.wall,
            self.cpu
                .map_or_else(|| "unmeasured".into(), |cpu| format!("{cpu:.3}s")),
            self.load.0,
            self.load.1
        )
    }
}

/// One single-terminal render of `name` in a fresh raw worker (Open, then
/// one request), with a worker command hook and a check of its process.
#[cfg(target_os = "linux")]
fn fresh_attempt(
    image: &std::path::Path,
    name: &str,
    mode: Mode,
    environment: &[(&str, &str)],
    configure: &dyn Fn(&mut Command),
    check: &dyn Fn(u32),
) -> Attempt {
    let start_load = load_average();
    let mut worker = Process::start_configured(environment, configure);
    let pid = worker.child.id();
    check(pid);
    let info = open(&mut worker, image, mode != Mode::Off);
    let address = info
        .functions
        .iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name}"))
        .address;
    let request = match mode {
        Mode::Off | Mode::On => Request::Decompile { address },
        Mode::OnInferenceOnly => Request::PrepareDecompile {
            logical_id: 1,
            address,
            renames: Vec::new(),
            refresh: false,
            inference_only: true,
        },
    };
    let before = process_cpu_seconds(pid);
    let started = Instant::now();
    let reply = worker.try_request(request, ghidra_rust::model::WORKER_REQUEST_TIMEOUT);
    let wall = started.elapsed();
    let cpu = process_cpu_seconds(pid)
        .zip(before)
        .map(|(after, before)| after - before)
        .filter(|_| reply.is_ok());
    let result = reply.map(|response| match response {
        Response::Decompiled {
            text, semantics, ..
        } => (text, semantics),
        other => panic!("{name}: {other:?}"),
    });
    Attempt {
        mode,
        wall,
        cpu,
        load: (start_load, load_average()),
        result,
    }
}

/// Checks a debug-off and a debug-on attempt of `name` as a pair: the
/// debug-on render carries the debug prototype, or exactly the inferred
/// render with the unverified warning. `Err` is a feature failure.
#[cfg(target_os = "linux")]
fn check_pair(off: &Attempt, on: &Attempt, declaration: &str) -> Result<Comparison, String> {
    use ghidra_rust::semantic::PrototypeSource;
    let verdict = classify(
        off.result.as_ref().map(|_| ()),
        on.result
            .as_ref()
            .map(|(_, semantics)| semantics.prototype_source),
    )?;
    if let (Ok((off_text, _)), Ok((text, semantics))) = (&off.result, &on.result) {
        match semantics.prototype_source {
            PrototypeSource::DebugInfo => {
                let header = text.split('{').next().unwrap();
                if !header.contains(declaration) {
                    return Err(format!("debug-on header {header:?}"));
                }
            }
            PrototypeSource::Inferred => {
                if !semantics
                    .warnings
                    .iter()
                    .any(|w| w == "Debug prototype is unverified")
                {
                    return Err(format!(
                        "inferred without warning: {:?}",
                        semantics.warnings
                    ));
                }
                if text != off_text {
                    return Err("the published inferred render differs from debug-off".into());
                }
            }
        }
    }
    Ok(verdict)
}

/// Debug-off then debug-on for `name`, each in a fresh worker and in
/// sequence. A debug-off success near the deadline is logged as near-limit
/// evidence, never excused; a feature failure panics with both attempts.
#[cfg(target_os = "linux")]
fn compare_debug_off_and_on(image: &std::path::Path, name: &str, declaration: &str) -> Comparison {
    compare_configured(image, name, declaration, &|_| {}, &|_| {})
}

#[cfg(target_os = "linux")]
fn compare_configured(
    image: &std::path::Path,
    name: &str,
    declaration: &str,
    configure: &dyn Fn(&mut Command),
    check: &dyn Fn(u32),
) -> Comparison {
    let deadline = ghidra_rust::model::WORKER_REQUEST_TIMEOUT;
    let off = fresh_attempt(image, name, Mode::Off, &[], configure, check);
    if off.result.is_ok() && off.wall + Duration::from_secs(3) > deadline {
        eprintln!("{name}: near-limit evidence: {off}");
    }
    if off.result.as_ref().is_err_and(Failure::resource) {
        eprintln!("{name}: baseline limit without debug info: {off}");
        return Comparison::OffResourceLimit;
    }
    let on = fresh_attempt(image, name, Mode::On, &[], configure, check);
    let verdict = check_pair(&off, &on, declaration)
        .unwrap_or_else(|error| panic!("{name}: {error}; {off}; {on}; cutoff {deadline:?}"));
    eprintln!("{name}: {verdict:?}; {off}; {on}");
    verdict
}

/// Counts of an opt-in paired run, reported separately.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct Tally {
    paired_successes: usize,
    baseline_limited: usize,
    unresolved: usize,
    feature_failures: Vec<String>,
    controls_completed: usize,
    controls_limited: usize,
}

#[cfg(target_os = "linux")]
impl Tally {
    fn record(&mut self, verdict: Result<Comparison, String>) {
        match verdict {
            Ok(Comparison::Compared(_)) => self.paired_successes += 1,
            Ok(Comparison::OffResourceLimit) => self.baseline_limited += 1,
            Ok(Comparison::Unresolved) => self.unresolved += 1,
            Err(error) => self.feature_failures.push(error),
        }
    }

    fn report(&self, label: &str) {
        eprintln!("{label}: {self:?}");
        if self.paired_successes == 0 {
            eprintln!("{label}: no paired successes; this run is not evidence of parity");
        }
    }
}

/// Fresh-process blocks in the order OFF/ON/ON/OFF, then ON/OFF/OFF/ON,
/// each followed by the debug-on inference-only control. Adjacent off/on
/// attempts are paired; every attempt is reported.
#[cfg(target_os = "linux")]
fn paired_blocks(
    image: &std::path::Path,
    name: &str,
    declaration: &str,
    configure: &dyn Fn(&mut Command),
    check: &dyn Fn(u32),
    tally: &mut Tally,
) {
    use Mode::*;
    for (block, order) in [[Off, On, On, Off], [On, Off, Off, On]].iter().enumerate() {
        let attempts = order
            .iter()
            .map(|&mode| fresh_attempt(image, name, mode, &[], configure, check))
            .collect::<Vec<_>>();
        for attempt in &attempts {
            eprintln!("{name} block {block}: {attempt}");
        }
        for pair in attempts.chunks(2) {
            let (off, on) = if pair[0].mode == Off {
                (&pair[0], &pair[1])
            } else {
                (&pair[1], &pair[0])
            };
            tally.record(check_pair(off, on, declaration));
        }
        let control = fresh_attempt(image, name, OnInferenceOnly, &[], configure, check);
        eprintln!("{name} block {block} control: {control}");
        match &control.result {
            Ok(_) => tally.controls_completed += 1,
            Err(failure) if failure.resource() => tally.controls_limited += 1,
            Err(failure) => tally
                .feature_failures
                .push(format!("inference-only control failed: {failure:?}")),
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn comparison_classification_never_excuses_a_debug_on_failure() {
    use ghidra_rust::semantic::PrototypeSource;
    let timeout = || Failure::Timeout {
        stderr: String::new(),
    };
    // A debug-on CPU or wall stop after a debug-off success is unresolved
    // (reported, never counted as a success); a crash is a feature failure.
    assert_eq!(
        classify(Ok(()), Err(&timeout())),
        Ok(Comparison::Unresolved)
    );
    let disconnected = |status: &str| Failure::Disconnected {
        status: status.into(),
        stderr: String::new(),
    };
    assert!(classify(Ok(()), Err(&disconnected("exit 1"))).is_err());
    let cpu = Failure::CpuLimit {
        stderr: String::new(),
    };
    assert_eq!(
        classify(Err(&cpu), Err(&timeout())),
        Ok(Comparison::OffResourceLimit)
    );
    assert!(
        classify(
            Err(&disconnected("signal 11")),
            Ok(PrototypeSource::Inferred)
        )
        .is_err()
    );
    assert_eq!(
        classify(Ok(()), Ok(PrototypeSource::DebugInfo)),
        Ok(Comparison::Compared(PrototypeSource::DebugInfo))
    );
    // A run whose every baseline was limited compared nothing.
    let all_limited = [Comparison::OffResourceLimit, Comparison::OffResourceLimit];
    assert!(
        !all_limited
            .iter()
            .any(|c| matches!(c, Comparison::Compared(_)))
    );
}

/// A large body whose locked render costs more than its inferred render
/// (about 1.7 times here) and several times its unlocked probe.
#[cfg(target_os = "linux")]
#[test]
fn large_bodies_never_fail_where_inference_succeeds() {
    // About 1,650 instructions: roughly 5 CPU seconds of inferred rendering
    // in a release worker.
    let (_directory, image) = branchy_image(&[("medium", 100, false)]);
    // Feature failures panic inside the comparison. Scheduler-dependent
    // limits are reported, not a verdict of the default gate.
    let comparison =
        compare_debug_off_and_on(&image, "medium", "int4 medium(int4 a,int4 b,int4 *out)");
    if !matches!(comparison, Comparison::Compared(_)) {
        eprintln!("medium: no paired success on this host: {comparison:?}");
    }
}

/// Near the request limits: bodies whose inferred render alone takes most of
/// the CPU allowance, one behind a jump table. Debug-off failures here are
/// reported as baseline limits, separately from feature failures. Opt-in:
/// release builds only, about four minutes.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "native stress: cargo test --release -- --ignored near_cap"]
fn near_cap_bodies_never_fail_where_inference_succeeds() {
    let functions = [
        ("blocks155", 155, false),
        ("blocks160", 160, false),
        ("table170", 170, true),
        ("blocks200", 200, false),
    ];
    let (_directory, image) = branchy_image(&functions);
    let mut baseline = Vec::new();
    let mut unresolved = Vec::new();
    let mut compared = 0;
    for (name, _, _) in functions {
        let declaration = format!("int4 {name}(int4 a,int4 b,int4 *out)");
        match compare_debug_off_and_on(&image, name, &declaration) {
            Comparison::OffResourceLimit => baseline.push(name),
            Comparison::Unresolved => unresolved.push(name),
            Comparison::Compared(_) => compared += 1,
        }
    }
    eprintln!("baseline limits: {baseline:?}; unresolved: {unresolved:?}");
    assert!(compared > 0, "no paired comparison completed");
}

/// One CPU this process may run on: CPU 1 when allowed.
#[cfg(target_os = "linux")]
fn one_allowed_cpu() -> usize {
    // SAFETY: set is zero-initialized storage for one cpu_set_t, written by
    // sched_getaffinity for this process.
    let set = unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        assert_eq!(
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set),
            0
        );
        set
    };
    // SAFETY: CPU_ISSET reads the initialized set within its fixed size.
    let allowed = |cpu: usize| unsafe { libc::CPU_ISSET(cpu, &set) };
    if allowed(1) {
        return 1;
    }
    (0..libc::CPU_SETSIZE as usize)
        .find(|&cpu| allowed(cpu))
        .unwrap()
}

/// Starts each worker on `cpu` at nice 19 before it executes.
#[cfg(target_os = "linux")]
fn pin_and_nice(cpu: usize) -> impl Fn(&mut Command) {
    move |command: &mut Command| {
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs in the forked child before exec and only
        // makes two raw syscalls on its own stack-allocated set.
        unsafe {
            command.pre_exec(move || {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(cpu, &mut set);
                if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0
                    || libc::setpriority(libc::PRIO_PROCESS, 0, 19) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// The started process really runs at nice 19 on `cpu` only.
#[cfg(target_os = "linux")]
fn assert_pinned_and_nice(pid: u32, cpu: usize) {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    // Fields after the parenthesized command name: nice is the 19th field.
    let fields = stat[stat.rfind(')').unwrap() + 2..]
        .split_whitespace()
        .collect::<Vec<_>>();
    assert_eq!(fields[16], "19", "{stat}");
    // SAFETY: set is zero-initialized storage for one cpu_set_t.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        assert_eq!(
            libc::sched_getaffinity(
                pid as libc::pid_t,
                std::mem::size_of::<libc::cpu_set_t>(),
                &mut set
            ),
            0
        );
        assert!(libc::CPU_ISSET(cpu, &set));
        assert_eq!(libc::CPU_COUNT(&set), 1);
    }
}

/// Inherited nice 19 on one CPU, with no busy peer: the reference render
/// gets the CPU alone, so debug-on succeeds wherever debug-off does, through
/// raw workers and the public console including a saved and reopened
/// project, and never records a skip.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "native stress: cargo test --release --test debug_info -- --ignored inherited_nice_preserves_inference"]
fn inherited_nice_preserves_inference() {
    let (directory, image) = branchy_image(&[("big", 175, false)]);
    let cpu = one_allowed_cpu();
    let configure = pin_and_nice(cpu);
    let check = |pid: u32| assert_pinned_and_nice(pid, cpu);
    inherited_policy_run("nice 19", &directory, &image, &configure, &check);
}

/// The opt-in scheduler run: raw single-terminal pairs and controls are
/// diagnostic (paired successes, baseline limits and unresolved pairs are
/// reported separately); the managed console gate fails on any held
/// baseline lost to a feature failure and on any newly saved skip.
#[cfg(target_os = "linux")]
fn inherited_policy_run(
    label: &str,
    directory: &tempfile::TempDir,
    image: &std::path::Path,
    configure: &dyn Fn(&mut Command),
    check: &dyn Fn(u32),
) {
    let mut tally = Tally::default();
    paired_blocks(
        image,
        "big",
        "int4 big(int4 a,int4 b,int4 *out)",
        configure,
        check,
        &mut tally,
    );
    tally.report(&format!("{label} raw pairs"));
    let console = console_preserves_near_limit_project(directory, image, configure, check);
    eprintln!("{label} managed console: {console:?}");
    assert!(
        tally.feature_failures.is_empty(),
        "{label}: {:?}",
        tally.feature_failures
    );
}

/// Observe the actual inherited policy and affinity on the raw worker,
/// then repeat through the managed console and its project checkpoint.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "native stress: inherited SCHED_IDLE on one CPU"]
fn inherited_idle_preserves_inference() {
    use std::os::unix::process::CommandExt;
    let (directory, image) = branchy_image(&[("big", 175, false)]);
    let cpu = one_allowed_cpu();
    let configure = |command: &mut Command| {
        // SAFETY: the child hook only uses scheduler syscalls with initialized
        // stack storage. It never alters the test process's priority.
        unsafe {
            command.pre_exec(move || {
                let mut set: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(cpu, &mut set);
                let parameter = libc::sched_param { sched_priority: 0 };
                if libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) != 0
                    || libc::sched_setscheduler(0, libc::SCHED_IDLE, &parameter) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    };
    let check = |pid: u32| {
        // SAFETY: these queries only read policy and fill an initialized mask.
        unsafe {
            let pid = pid as libc::pid_t;
            assert_eq!(libc::sched_getscheduler(pid), libc::SCHED_IDLE);
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            assert_eq!(
                libc::sched_getaffinity(pid, std::mem::size_of_val(&set), &mut set),
                0
            );
            assert_eq!(libc::CPU_COUNT(&set), 1);
            assert!(libc::CPU_ISSET(cpu, &set));
        }
        eprintln!("Observed SCHED_IDLE on CPU {cpu} for PID {pid}");
    };
    inherited_policy_run("SCHED_IDLE", &directory, &image, &configure, &check);
}

/// How the managed console gate ended on a loaded host.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct ConsoleOutcome {
    /// Function commands that returned their render.
    rendered: usize,
    /// Function commands whose normal attempt and one inference-only
    /// recovery both hit a CPU or wall limit: an ordinary baseline limit.
    baseline_limited: usize,
}

/// The public console, then a saved project reopened without
/// `--use-debug-info` (which would clear skips), then Refresh. A limited
/// render is reported as a baseline limit; any other command failure and
/// any newly saved skip (in Info before and after Save, the SQLite
/// snapshot, after reopen and after Refresh) is a feature failure.
#[cfg(target_os = "linux")]
fn console_preserves_near_limit_project(
    directory: &tempfile::TempDir,
    image: &std::path::Path,
    configure: &dyn Fn(&mut Command),
    check: &dyn Fn(u32),
) -> ConsoleOutcome {
    let mut worker = Process::start();
    let big = open(&mut worker, image, true)
        .functions
        .iter()
        .find(|f| f.name == "big")
        .unwrap()
        .address;
    drop(worker);
    let project = directory.path().join("big.grproj");
    let console = |arguments: &[&std::ffi::OsStr], input: String| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"));
        configure(&mut command);
        let mut child = command
            .args(arguments)
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        check(child.id());
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>()
    };
    let command = |id: u32, command: serde_json::Value| {
        format!(
            "{}\n",
            serde_json::json!({"api_version": 1, "id": id, "command": command})
        )
    };
    let mut outcome = ConsoleOutcome::default();
    let mut function = |reply: &serde_json::Value, order: &str| {
        let Some(error) = reply.get("error") else {
            assert!(
                reply["result"]["analysis"]["text"]
                    .as_str()
                    .unwrap()
                    .contains("big("),
                "{order}: {reply}"
            );
            outcome.rendered += 1;
            return;
        };
        let limited = error["code"] == "timeout"
            || (error["code"] == "worker_failed"
                && error["message"]
                    .as_str()
                    .is_some_and(|m| m.contains("CPU time limit reached")));
        assert!(limited, "{order}: feature failure: {reply}");
        eprintln!("{order}: baseline limit after one recovery: {error}");
        outcome.baseline_limited += 1;
    };
    let no_skips = |reply: &serde_json::Value, order: &str| {
        assert!(reply.get("error").is_none(), "{order}: {reply}");
        assert_eq!(
            reply["result"]["debug_skipped_functions"],
            serde_json::json!([]),
            "{order}: a newly saved skip is a feature failure"
        );
    };
    let replies = console(
        &[
            "--binary".as_ref(),
            image.as_os_str(),
            "--use-debug-info".as_ref(),
            "--output-project".as_ref(),
            project.as_os_str(),
        ],
        command(1, serde_json::json!({"kind": "function", "address": big}))
            + &command(2, serde_json::json!({"kind": "info"}))
            + &command(
                3,
                serde_json::json!({"kind": "save_project", "embed_binary": true}),
            ),
    );
    assert_eq!(replies.len(), 3, "{replies:?}");
    function(&replies[0], "first function");
    no_skips(&replies[1], "first Info");
    assert!(replies[2].get("error").is_none(), "{}", replies[2]);
    let saved = ghidra_rust::project::ProjectData::load(&project).unwrap();
    assert!(saved.data.debug_skip.is_empty(), "saved snapshot");
    drop(saved);
    let reopened = console(
        &["--project".as_ref(), project.as_os_str()],
        command(1, serde_json::json!({"kind": "info"}))
            + &command(
                2,
                serde_json::json!({"kind": "function", "address": big, "refresh": true}),
            )
            + &command(3, serde_json::json!({"kind": "info"})),
    );
    assert_eq!(reopened.len(), 3, "{reopened:?}");
    no_skips(&reopened[0], "reopened Info");
    function(&reopened[1], "reopened Refresh");
    no_skips(&reopened[2], "Info after Refresh");
    outcome
}

/// The expiry path, driven deterministically: a debug render that never
/// finishes leaves the request its own inferred render, exactly as without
/// debug info, with the unverified warning, after at most its wait.
#[cfg(target_os = "linux")]
#[test]
fn expired_debug_renders_publish_the_inferred_render_with_a_warning() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, path) = fixture(true);
    let (_, off) = fresh_decompile(&path, "main", false, &[]);
    let (off_text, _) = off.unwrap();
    let mut worker = Process::start_with(&[("GHIDRA_RUST_TEST_STALL_DEBUG_RENDER", "1")]);
    let info = open(&mut worker, &path, true);
    let main = info.functions.iter().find(|f| f.name == "main").unwrap();
    for view in 0..2 {
        let started = Instant::now();
        let (text, semantics) = decompile(&mut worker, main.address);
        let elapsed = started.elapsed();
        assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
        assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == "Debug prototype is unverified"),
            "view {view}: {:?}",
            semantics.warnings
        );
        assert_eq!(text, off_text, "view {view}");
        // Bounded by the optional cutoff, inside the request deadline.
        assert!(
            elapsed < Duration::from_secs(27),
            "view {view}: {elapsed:?}"
        );
    }
    // The stalled optional render started only after the reference render
    // was complete, on both views.
    let order = || {
        worker
            .stderr()
            .lines()
            .filter_map(|line| line.strip_prefix("debug-order: "))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while order().len() < 4 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let order = order();
    assert_eq!(
        order,
        [
            "reference complete",
            "optional started",
            "reference complete",
            "optional started"
        ],
        "{order:?}"
    );
    let (_, on) = fresh_decompile(&path, "main", true, &[]);
    let (text, semantics) = on.unwrap();
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
    assert!(text.contains("int4 main(int4 argc,char **argv)"), "{text}");
}

/// A callee accepted from a caller's unlocked probe is provisional: its own
/// first render must pass the locked-output check before it reports debug
/// provenance. Here the locked render passes register upper halves to an
/// external call as invented arguments, so both navigation orders end with
/// the same inferred callee, and the caller then renders the same way.
#[cfg(target_os = "linux")]
#[test]
fn provisional_callee_prototypes_need_their_own_locked_render() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, image) = gcc_image(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_provisional_callee.c"
        )),
        &["-O2", "-g", "-fPIC", "-shared", "-fvisibility=hidden"],
    );
    let assert_inferred = |text: &str, semantics: &ghidra_rust::semantic::SemanticInfo| {
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::Inferred,
            "{text}"
        );
        assert!(!text.contains("in_register_"), "{text}");
        assert!(
            !semantics
                .warnings
                .iter()
                .any(|w| w == "Debug prototype is unverified"),
            "rejected, not pending: {:?}",
            semantics.warnings
        );
    };
    // Caller first: the callee becomes provisional for its callers.
    let mut caller_first = Process::start();
    let info = open(&mut caller_first, &image, true);
    let (first_caller, semantics) = decompile_named(&mut caller_first, &info, "energy_maps");
    assert!(
        !semantics
            .warnings
            .iter()
            .any(|w| w == "Some callee debug prototypes are unverified"),
        "the caller's probe decides the callee: {:?}",
        semantics.warnings
    );
    let (callee, semantics) = decompile_named(&mut caller_first, &info, "grid_energy");
    assert_inferred(&callee, &semantics);
    let (caller, _) = decompile_named(&mut caller_first, &info, "energy_maps");
    // Direct first: the target's own verification rejects it.
    let mut direct_first = Process::start();
    let info = open(&mut direct_first, &image, true);
    let (direct, semantics) = decompile_named(&mut direct_first, &info, "grid_energy");
    assert_inferred(&direct, &semantics);
    assert_eq!(callee, direct);
    let (direct_caller, _) = decompile_named(&mut direct_first, &info, "energy_maps");
    assert_eq!(
        caller, direct_caller,
        "callers no longer use the rejected prototype"
    );
    assert_ne!(
        first_caller, caller,
        "the provisional prototype was used by its caller"
    );
}

/// The caller TU without debug info, the callee TU with it, linked as one
/// shared object, and each function's entry by its exact symbol.
#[cfg(target_os = "linux")]
fn caller_fixture() -> (tempfile::TempDir, std::path::PathBuf, [u64; 3]) {
    use object::{Object, ObjectSymbol};
    let directory = tempfile::tempdir().unwrap();
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    let run = |arguments: &[&std::ffi::OsStr]| {
        let output = Command::new("gcc").args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let submit = directory.path().join("submit.o");
    let schedule = directory.path().join("schedule.o");
    let image = directory.path().join("fixture.so");
    let source = |name: &str| std::path::PathBuf::from(format!("{fixtures}{name}"));
    let flags = ["-O2", "-fPIC", "-fno-plt", "-fno-omit-frame-pointer", "-c"];
    let mut arguments = flags.map(std::ffi::OsStr::new).to_vec();
    let submit_source = source("debug_caller_submit.c");
    arguments.extend([submit_source.as_os_str(), "-o".as_ref(), submit.as_os_str()]);
    run(&arguments);
    let mut arguments = std::iter::once(std::ffi::OsStr::new("-g"))
        .chain(flags.map(std::ffi::OsStr::new))
        .collect::<Vec<_>>();
    let schedule_source = source("debug_caller_schedule.c");
    arguments.extend([
        schedule_source.as_os_str(),
        "-o".as_ref(),
        schedule.as_os_str(),
    ]);
    run(&arguments);
    run(&[
        "-nostdlib".as_ref(),
        "-shared".as_ref(),
        submit.as_os_str(),
        schedule.as_os_str(),
        "-o".as_ref(),
        image.as_os_str(),
    ]);
    let bytes = std::fs::read(&image).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let entry = |name: &str| {
        object
            .symbols()
            .find(|symbol| symbol.name().ok() == Some(name))
            .unwrap_or_else(|| panic!("{name}"))
            .address()
    };
    let entries = [
        entry("sample_entry"),
        entry("sample_entry_positive"),
        entry("sample_schedule"),
    ];
    (directory, image, entries)
}

/// Structural equality through the wire encoding, for reply types without
/// `PartialEq`.
#[cfg(target_os = "linux")]
mod erased {
    pub trait Json {
        fn json(&self) -> serde_json::Value;
    }
    impl<T: serde::Serialize> Json for T {
        fn json(&self) -> serde_json::Value {
            serde_json::to_value(self).unwrap()
        }
    }
}

/// The arguments of every call to `callee` in `text`, whitespace-normalized,
/// split at top-level commas across line wraps and nested calls.
#[cfg(target_os = "linux")]
fn call_arguments(text: &str, callee: &str) -> Vec<Vec<String>> {
    let mut calls = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find(callee) {
        let after = &rest[at + callee.len()..];
        rest = after;
        let Some(after) = after.strip_prefix('(') else {
            continue;
        };
        let (mut depth, mut current, mut arguments) = (0usize, String::new(), Vec::new());
        for character in after.chars() {
            match character {
                '(' => {
                    depth += 1;
                    current.push(character);
                }
                ')' if depth == 0 => break,
                ')' => {
                    depth -= 1;
                    current.push(character);
                }
                ',' if depth == 0 => arguments.push(std::mem::take(&mut current)),
                c if c.is_whitespace() => {}
                c => current.push(c),
            }
        }
        if !current.is_empty() || !arguments.is_empty() {
            arguments.push(current);
        }
        calls.push(arguments);
    }
    calls
}

/// A callee's debug prototype must not drop a caller's live argument at an
/// unrelated indirect call: here the fifth incoming register is copied into
/// the fourth argument of `collect_task` well before the direct call to the
/// DWARF-described `sample_schedule`. The positive wrapper shows a callee
/// prototype still improving a caller.
#[cfg(target_os = "linux")]
#[test]
fn callee_lock_preserves_forwarded_input_at_an_unrelated_indirect_call() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, image, [entry, positive, schedule]) = caller_fixture();
    let refresh = |worker: &mut Process, address: u64| {
        let response = worker.request(Request::RefreshDecompile {
            address,
            renames: Vec::new(),
        });
        let Response::Decompiled {
            text,
            mappings,
            semantics,
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        (text, mappings, semantics)
    };
    let full = |worker: &mut Process, address: u64| {
        let response = worker.request(Request::Decompile { address });
        let Response::Decompiled {
            text,
            mappings,
            semantics,
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        (text, mappings, semantics)
    };
    let mut off_worker = Process::start();
    open(&mut off_worker, &image, false);
    let (off_text, off_mappings, off_semantics) = full(&mut off_worker, entry);
    let formals = off_semantics
        .prototype
        .as_ref()
        .expect("inferred prototype")
        .parameters
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(formals.len(), 5, "{off_text}");
    let forwarded = |text: &str| {
        let calls = call_arguments(text, "(*collect_task@got)");
        assert_eq!(calls.len(), 1, "{text}");
        calls[0].clone()
    };
    assert_eq!(forwarded(&off_text).get(3), Some(&formals[4]), "{off_text}");
    let (off_positive, _, _) = full(&mut off_worker, positive);
    let off_header = off_positive.split('{').next().unwrap().to_owned();

    let assert_vetoed = |(text, mappings, semantics): &(
        String,
        Vec<ghidra_rust::model::CodeMapping>,
        ghidra_rust::semantic::SemanticInfo,
    ),
                         order: &str| {
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::Inferred,
            "{order}"
        );
        assert_eq!(forwarded(text).get(3), Some(&formals[4]), "{order}: {text}");
        assert_eq!(text, &off_text, "{order}");
        let json = |value: &dyn erased::Json| value.json();
        assert_eq!(json(mappings), json(&off_mappings), "{order}");
        assert_eq!(
            json(&semantics.tokens),
            json(&off_semantics.tokens),
            "{order}"
        );
        assert_eq!(
            json(&semantics.locals),
            json(&off_semantics.locals),
            "{order}"
        );
        assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == ghidra_rust::analysis::CALLER_EVIDENCE_WARNING),
            "{order}: {:?}",
            semantics.warnings
        );
    };
    let assert_callee = |worker: &mut Process| {
        let (text, semantics) = decompile(worker, schedule);
        assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
        assert!(
            text.contains(
                "void * sample_schedule(void *queue,uint4 delay,code *callback,void *context,void *cleanup)"
            ),
            "{text}"
        );
    };
    let assert_positive = |worker: &mut Process, order: &str| {
        let (text, semantics) = decompile(worker, positive);
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::Inferred,
            "{order}"
        );
        let header = text.split('{').next().unwrap();
        assert!(header.contains("void *param_1"), "{order}: {header}");
        assert_ne!(header, off_header, "{order}: the callee prototype applies");
        let calls = call_arguments(&text, "sample_schedule");
        assert_eq!(calls.len(), 1, "{order}: {text}");
        assert_eq!(calls[0].len(), 5, "{order}: {text}");
        assert_eq!(calls[0][0], "param_1", "{order}: {text}");
        assert!(
            !semantics
                .warnings
                .iter()
                .any(|w| w == ghidra_rust::analysis::CALLER_EVIDENCE_WARNING),
            "{order}: {:?}",
            semantics.warnings
        );
    };

    // Fresh caller first, then the positive caller after that veto.
    let mut fresh = Process::start();
    open(&mut fresh, &image, true);
    assert_vetoed(&full(&mut fresh, entry), "fresh");
    assert_positive(&mut fresh, "after the veto");
    assert_callee(&mut fresh);
    assert_vetoed(&refresh(&mut fresh, entry), "refresh");
    assert_vetoed(&full(&mut fresh, entry), "revisit");

    // Callee first: its own verified prototype still cannot drop the
    // caller's argument.
    let mut callee_first = Process::start();
    open(&mut callee_first, &image, true);
    assert_callee(&mut callee_first);
    assert_vetoed(&full(&mut callee_first, entry), "callee first");
    assert_positive(&mut callee_first, "callee first");
    assert_vetoed(&refresh(&mut callee_first, entry), "callee-first refresh");
}

/// The worker's opt-in diagnostics so far, after its reader drained them.
#[cfg(target_os = "linux")]
fn traces(worker: &Process, event: &str, expected: usize) -> usize {
    let count = || {
        worker
            .stderr()
            .lines()
            .filter(|line| line.starts_with(&format!("debug-trace: {event}")))
            .count()
    };
    // The worker writes each trace before its reply; the diagnostics reader
    // may still be draining it under load. Wait for the expected count, then
    // briefly for any extra line.
    let deadline = Instant::now() + Duration::from_secs(10);
    while count() < expected && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));
    count()
}

/// The engine failure is injected inside the isolated debug render of a
/// real worker: the function keeps exactly its inferred render, remembers
/// the failure, and a worker without the injection keeps the prototype.
#[cfg(target_os = "linux")]
#[test]
fn engine_failure_in_the_isolated_render_keeps_inference() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, image) = gcc_image(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_opaque_session.c"
        )),
        &["-O2", "-g", "-fPIC", "-shared"],
    );
    let (_, off) = fresh_decompile(&image, "decode_session", false, &[]);
    let (off_text, _) = off.unwrap();
    let mut failing = Process::start_with(&[
        ("GHIDRA_RUST_TEST_ZERO_SIZE_OPAQUE", "1"),
        ("GHIDRA_RUST_DEBUG_TRACE", "1"),
    ]);
    let info = open(&mut failing, &image, true);
    for view in 0..2 {
        let (text, semantics) = decompile_named(&mut failing, &info, "decode_session");
        assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
        assert_eq!(text, off_text, "view {view}");
        assert!(
            semantics
                .warnings
                .iter()
                .any(|w| w == ghidra_rust::debug_info::ENGINE_FAILURE_WARNING),
            "view {view}: {:?}",
            semantics.warnings
        );
    }
    assert_eq!(traces(&failing, "fork", 1), 1, "the failure is remembered");
    let mut fixed = Process::start();
    let info = open(&mut fixed, &image, true);
    let (text, semantics) = decompile_named(&mut fixed, &info, "decode_session");
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
    assert!(
        text.contains("SESSION * decode_session(SESSION **existing,char **cursor,int8 length)"),
        "{text}"
    );
}

/// A provisional callee whose own direct verification expires twice is
/// withdrawn: its callers no longer use it, and it stays rejected.
#[cfg(target_os = "linux")]
#[test]
fn provisional_callee_expiring_twice_is_withdrawn_from_callers() {
    use ghidra_rust::semantic::PrototypeSource;
    use object::{Object, ObjectSymbol};
    let (_directory, image) = gcc_image(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_provisional_callee.c"
        )),
        &["-O2", "-g", "-fPIC", "-shared", "-fvisibility=hidden"],
    );
    let bytes = std::fs::read(&image).unwrap();
    let callee = object::File::parse(bytes.as_slice())
        .unwrap()
        .symbols()
        .find(|s| s.name().ok() == Some("grid_energy"))
        .unwrap()
        .address();
    // Reference: the caller without the callee's prototype.
    let mut direct = Process::start();
    let info = open(&mut direct, &image, true);
    decompile_named(&mut direct, &info, "grid_energy");
    let (unlocked_caller, _) = decompile_named(&mut direct, &info, "energy_maps");

    let stall = format!("{callee:#x}");
    let mut worker = Process::start_with(&[
        ("GHIDRA_RUST_TEST_STALL_DEBUG_RENDER", stall.as_str()),
        ("GHIDRA_RUST_DEBUG_TRACE", "1"),
    ]);
    let info = open(&mut worker, &image, true);
    let (first_caller, _) = decompile_named(&mut worker, &info, "energy_maps");
    assert_ne!(
        first_caller, unlocked_caller,
        "the provisional prototype applied"
    );
    let unverified = |semantics: &ghidra_rust::semantic::SemanticInfo| {
        semantics
            .warnings
            .iter()
            .any(|w| w == "Debug prototype is unverified")
    };
    for attempt in 0..2 {
        let (_, semantics) = decompile(&mut worker, callee);
        assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
        // The first expiry leaves it provisional; the second rejects it.
        assert_eq!(unverified(&semantics), attempt == 0, "attempt {attempt}");
        assert!(
            !semantics
                .warnings
                .iter()
                .any(|w| w == ghidra_rust::debug_info::SKIPPED_FUNCTION_WARNING)
        );
    }
    assert_eq!(traces(&worker, "expired", 2), 2);
    let response = worker.request(Request::RefreshDecompile {
        address: info
            .functions
            .iter()
            .find(|f| f.name == "energy_maps")
            .unwrap()
            .address,
        renames: Vec::new(),
    });
    let Response::Decompiled { text, .. } = response else {
        panic!("{response:?}")
    };
    assert_eq!(text, unlocked_caller, "the withdrawn prototype is gone");
    // Rejected for good: its own later renders no longer try it.
    let (_, semantics) = decompile(&mut worker, callee);
    assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    assert!(!unverified(&semantics), "{:?}", semantics.warnings);
}

/// Repeated ordinary requests reuse a verified render; Refresh, a local
/// rename and a name change each render anew.
#[cfg(target_os = "linux")]
#[test]
fn verified_results_are_reused_until_their_context_changes() {
    use ghidra_rust::semantic::{LocalRename, PrototypeSource};
    let (_directory, path) = fixture(true);
    let mut worker = Process::start_with(&[("GHIDRA_RUST_DEBUG_TRACE", "1")]);
    let info = open(&mut worker, &path, true);
    let address = |name: &str| {
        info.functions
            .iter()
            .find(|f| f.name == name)
            .unwrap()
            .address
    };
    let branch_loop = address("branch_loop");
    let full = |worker: &mut Process, request: Request| {
        let response = worker.request(request);
        let Response::Decompiled {
            text,
            mappings,
            semantics,
            ..
        } = response
        else {
            panic!("{response:?}")
        };
        serde_json::to_string(&(text, mappings, semantics)).unwrap()
    };
    let first = full(
        &mut worker,
        Request::Decompile {
            address: branch_loop,
        },
    );
    assert!(first.contains("uint4 branch_loop(uint4 count)"), "{first}");
    for _ in 1..30 {
        let again = full(
            &mut worker,
            Request::Decompile {
                address: branch_loop,
            },
        );
        assert_eq!(again, first);
    }
    assert_eq!(traces(&worker, "fork", 1), 1);
    assert_eq!(traces(&worker, "cache-hit", 29), 29);
    // Refresh renders anew and publishes the same verified render.
    let refreshed = full(
        &mut worker,
        Request::RefreshDecompile {
            address: branch_loop,
            renames: Vec::new(),
        },
    );
    assert_eq!(refreshed, first);
    assert_eq!(traces(&worker, "fork", 2), 2);
    // A local rename is a different request context.
    let (_, semantics) = decompile(&mut worker, branch_loop);
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
    let local = semantics.locals.first().expect("a recovered local");
    let renamed = full(
        &mut worker,
        Request::DecompileWithLocals {
            address: branch_loop,
            renames: vec![LocalRename {
                identity: local.identity.clone(),
                name: "renamed_local".into(),
            }],
        },
    );
    assert!(renamed.contains("renamed_local"), "{renamed}");
    assert_eq!(traces(&worker, "fork", 3), 3);
    // A function rename can change what any render prints.
    let response = worker.request(Request::Rename {
        address: address("decode_xor"),
        name: "renamed_function".into(),
    });
    assert!(!matches!(response, Response::Error { .. }), "{response:?}");
    full(
        &mut worker,
        Request::Decompile {
            address: branch_loop,
        },
    );
    assert_eq!(traces(&worker, "fork", 4), 4);
}

#[cfg(target_os = "linux")]
#[test]
fn independent_inputs_survive_return_locks_and_missing_switch_arms() {
    use object::{Object, ObjectSection, ObjectSymbol};
    for case in ["VOID_CASE", "RETURN_WIDTH_CASE", "SWITCH_CASE"] {
        let source = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_counter_evidence.c"
        ));
        let (_real_dir, real) = gcc_image(
            source,
            &[
                "-O2",
                "-fno-reorder-blocks-and-partition",
                "-g",
                "-shared",
                "-nostdlib",
                "-fPIC",
                &format!("-D{case}"),
            ],
        );
        let (fake_dir, fake) = gcc_image(
            source,
            &[
                "-O2",
                "-fno-reorder-blocks-and-partition",
                "-g",
                "-shared",
                "-nostdlib",
                "-fPIC",
                "-DFAKE",
                &format!("-D{case}"),
            ],
        );
        let bytes = std::fs::read(fake).unwrap();
        let object = object::File::parse(bytes.as_slice()).unwrap();
        let real_bytes = std::fs::read(&real).unwrap();
        let real_object = object::File::parse(real_bytes.as_slice()).unwrap();
        let entry = |image: &object::File<'_>| {
            image
                .symbols()
                .find(|s| s.name().ok() == Some("suspect"))
                .unwrap()
                .address()
        };
        assert_eq!(
            entry(&real_object),
            entry(&object),
            "forged DWARF must target the actual function"
        );
        let mut command = Command::new("objcopy");
        for (i, section) in object.sections().enumerate() {
            let name = section.name().unwrap();
            if name.starts_with(".debug_") {
                let path = fake_dir.path().join(format!("section-{i}"));
                std::fs::write(&path, section.data().unwrap()).unwrap();
                command
                    .arg("--update-section")
                    .arg(format!("{name}={}", path.display()));
            }
        }
        assert!(command.arg(&real).status().unwrap().success());
        let mut worker = Process::start();
        let info = open(&mut worker, &real, true);
        let (text, semantics) = decompile_named(&mut worker, &info, "suspect");
        assert_eq!(
            semantics.prototype_source,
            ghidra_rust::semantic::PrototypeSource::Inferred,
            "{case}: {text}"
        );
        assert!(text.contains("return"), "{text}");
    }
}
#[cfg(target_os = "linux")]
#[test]
fn opaque_collision_uses_void_without_rejecting_debug_prototype() {
    let (_directory, image) = gcc_image(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_counter_evidence.c"
        )),
        &["-O2", "-g", "-shared", "-nostdlib", "-fPIC", "-DCOLLISION"],
    );
    let mut worker = Process::start();
    let info = open(&mut worker, &image, true);
    let (text, semantics) = decompile_named(&mut worker, &info, "suspect");
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::DebugInfo,
        "{text}"
    );
    assert!(text.contains("void *"), "{text}");
}

#[cfg(target_os = "linux")]
fn assert_limited_functions_stay_inferred(path: &std::path::Path, names: &[&str]) {
    use ghidra_rust::semantic::PrototypeSource;

    let mut enabled = Process::start();
    let info = open(&mut enabled, path, true);
    let mut disabled = Process::start();
    open(&mut disabled, path, false);
    for name in names {
        let (text, semantics) = decompile_named(&mut enabled, &info, name);
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::Inferred,
            "{text}"
        );
        assert_eq!(text, decompile_named(&mut disabled, &info, name).0);
        let declaration = text.trim_start();
        // Inference can miss the return type of pick's external tail call.
        if *name != "pick" {
            assert!(!declaration.starts_with("void "), "{text}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gcc_g1_has_no_function_prototypes() {
    let (_directory, path) = gcc_image(
        std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_limited.c"
        )),
        &["-O2", "-g1", "-shared", "-fPIC"],
    );
    assert_limited_functions_stay_inferred(&path, &["get_counter", "pick", "ignore_args"]);
}

#[cfg(target_os = "linux")]
#[test]
fn rustc_limited_debuginfo_has_no_function_prototypes() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("limited");
    let status = Command::new("rustc")
        .args(["--edition=2024", "-C", "opt-level=2", "-C", "debuginfo=1"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_limited.rs"
        ))
        .arg("-o")
        .arg(&image)
        .status();
    match status {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("Skipping limited Rust DWARF fixture (rustc unavailable)");
            return;
        }
        result => assert!(result.unwrap().success()),
    }
    // The ELF loader currently treats this TLS section header as overlapping.
    assert!(
        Command::new("objcopy")
            .args(["--remove-section", ".tbss"])
            .arg(&image)
            .status()
            .unwrap()
            .success()
    );
    assert_limited_functions_stay_inferred(&image, &["scaled_counter"]);
}

#[cfg(target_os = "linux")]
#[test]
fn gcc_cross_partition_ipa_clone_does_not_inherit_source_prototype() {
    use ghidra_rust::semantic::PrototypeSource;

    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("lto");
    let output = Command::new("gcc")
        .args(["-O2", "-g", "-flto", "-flto-partition=max"])
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_lto_clone_a.c"
        ))
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/debug_lto_clone_b.c"
        ))
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut enabled = Process::start();
    let info = open(&mut enabled, &image, true);
    let clone = info
        .functions
        .iter()
        .find(|f| f.name.starts_with("record_reading.isra."))
        .expect("GCC must emit an IPA-SRA clone for the fixture");
    // Render the caller first, so a callee probe cannot admit the clone either.
    decompile_named(&mut enabled, &info, "main");
    let (text, semantics) = decompile(&mut enabled, clone.address);
    assert_eq!(
        semantics.prototype_source,
        PrototypeSource::Inferred,
        "{text}"
    );
    let mut disabled = Process::start();
    open(&mut disabled, &image, false);
    assert_eq!(text, decompile(&mut disabled, clone.address).0);
    assert!(text.contains(&format!("void {}(", clone.name)), "{text}");
}

// ---------------------------------------------------------------------------
// Managed two-phase path: the production Analyzer client, its primary worker
// and (for the sibling executor) single-use debug peers.

/// Which process runs a managed request's optional debug render.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Executor {
    /// The primary's own disposable fork (single-threaded Linux workers).
    Fork,
    /// A fresh sibling worker, as on Windows: the primary and its peers run
    /// with `--no-fork`, so no fork is used for optional or callee work.
    Sibling,
}

/// The least optional window for sibling sessions in these tests. A sibling
/// starts, opens and replays a peer process inside the window, which a
/// loaded host (a parallel test run) can stretch past the production three
/// seconds; the checks here are about results, not that latency. Shared by
/// the Linux and Windows tests, so the type is spelled out rather than
/// relying on the Linux-only import.
const SIBLING_TEST_FLOOR: std::time::Duration = std::time::Duration::from_secs(10);

/// A managed session on `path` with the given executor, worker executable
/// and extra host-test-only worker arguments.
fn managed_session_with(
    path: &std::path::Path,
    debug: bool,
    executor: Executor,
    exe: &std::path::Path,
    extra: &[String],
) -> ghidra_rust::headless::Analyzer {
    use ghidra_rust::headless::{Analyzer, Input, Options};
    let mut worker_arguments = Vec::new();
    if executor == Executor::Sibling {
        worker_arguments.push(ghidra_rust::worker::NO_FORK_ARGUMENT.into());
    }
    worker_arguments.extend(extra.iter().map(Into::into));
    Analyzer::open(
        Input::Binary(path.to_owned()),
        exe,
        Options {
            use_debug_info: Some(debug),
            worker_arguments,
            optional_floor: (executor == Executor::Sibling).then_some(SIBLING_TEST_FLOOR),
            ..Options::default()
        },
    )
    .unwrap()
}

fn managed_session(
    path: &std::path::Path,
    debug: bool,
    executor: Executor,
    extra: &[String],
) -> ghidra_rust::headless::Analyzer {
    managed_session_with(
        path,
        debug,
        executor,
        std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless")),
        extra,
    )
}

/// One public `function` command: text, mappings and semantics.
fn managed_function(
    api: &mut ghidra_rust::headless::Analyzer,
    address: u64,
    refresh: bool,
) -> (
    String,
    Vec<ghidra_rust::model::CodeMapping>,
    ghidra_rust::semantic::SemanticInfo,
) {
    use ghidra_rust::headless::{Command as ApiCommand, Output};
    let Output::Function { analysis } = api
        .execute(ApiCommand::Function { address, refresh })
        .unwrap()
    else {
        panic!("not a function result")
    };
    (analysis.text, analysis.mappings, analysis.semantics)
}

/// The verified Open inventory's entry named `name`.
fn managed_address(api: &mut ghidra_rust::headless::Analyzer, name: &str) -> u64 {
    use ghidra_rust::headless::{Command as ApiCommand, Output};
    let Output::Info { info, .. } = api.execute(ApiCommand::Info {}).unwrap() else {
        panic!("not info")
    };
    info.functions
        .iter()
        .find(|function| function.name == name)
        .unwrap_or_else(|| panic!("{name}"))
        .address
}

fn managed_skips(api: &mut ghidra_rust::headless::Analyzer) -> Vec<u64> {
    use ghidra_rust::headless::{Command as ApiCommand, Output};
    let Output::Info {
        debug_skipped_functions,
        ..
    } = api.execute(ApiCommand::Info {}).unwrap()
    else {
        panic!("not info")
    };
    debug_skipped_functions
}

/// A DWARF build of `sample.c` for the sibling tests: GCC on Linux, the
/// VS-clang PE from `scripts/build-windows.ps1` on Windows (`None` when that
/// fixture is not configured).
#[cfg(any(target_os = "linux", windows))]
fn sibling_fixture() -> Option<(Option<tempfile::TempDir>, std::path::PathBuf)> {
    #[cfg(target_os = "linux")]
    {
        let (directory, path) = fixture(true);
        Some((Some(directory), path))
    }
    #[cfg(windows)]
    {
        let Some(path) = std::env::var_os("GHIDRA_RUST_TEST_PE_DWARF") else {
            eprintln!("Set GHIDRA_RUST_TEST_PE_DWARF using scripts/build-windows.ps1");
            return None;
        };
        Some((None, std::path::PathBuf::from(path)))
    }
}

/// A sibling whose setup (startup, Open and replay) cannot finish within
/// its allowance settles at once with the inferred baseline and one setup
/// reason, records no skip or decision, leaves the primary usable, and a
/// later eligible Refresh with the production allowance upgrades.
#[cfg(any(target_os = "linux", windows))]
#[test]
fn managed_scheduler_sibling_setup_cutoff_keeps_the_inferred_baseline() {
    use ghidra_rust::semantic::PrototypeSource;
    let Some((_directory, path)) = sibling_fixture() else {
        return;
    };
    let mut api = managed_session(&path, true, Executor::Sibling, &[]);
    let main = managed_address(&mut api, "main");
    let other = managed_address(&mut api, "branch_loop");
    let (inferred, _, _) = {
        let mut off = managed_session(&path, false, Executor::Fork, &[]);
        managed_function(&mut off, main, false)
    };
    // A setup allowance far below what starting and opening a peer takes.
    api.set_optional_windows(None, Some(std::time::Duration::from_millis(5)));
    let started = std::time::Instant::now();
    let (text, _, semantics) = managed_function(&mut api, main, true);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(text, inferred);
    assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    assert_eq!(
        semantics
            .warnings
            .iter()
            .filter(|warning| *warning == ghidra_rust::analysis::SETUP_CUTOFF_WARNING)
            .count(),
        1,
        "{:?}",
        semantics.warnings
    );
    assert!(
        !semantics
            .warnings
            .iter()
            .any(|warning| warning == ghidra_rust::analysis::UNVERIFIED_WARNING),
        "{:?}",
        semantics.warnings
    );
    assert!(managed_skips(&mut api).is_empty());
    // The primary stays usable.
    let (other_text, _, _) = managed_function(&mut api, other, false);
    assert!(other_text.contains("branch_loop"), "{other_text}");
    // A fresh eligible Refresh with an allowance a loaded test host can
    // meet upgrades the same function.
    api.set_optional_windows(Some(SIBLING_TEST_FLOOR), None);
    let (text, _, semantics) = managed_function(&mut api, main, true);
    assert!(text.contains("int4 main(int4 argc,char **argv)"), "{text}");
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
    assert!(managed_skips(&mut api).is_empty());
}

/// The source declarations of `sample.c` in both executors, the inferred
/// forms with debug info off, and Refresh of each.
#[cfg(target_os = "linux")]
#[test]
fn managed_debug_sample_prototypes_in_both_executors() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, path) = fixture(true);
    let declarations = [
        (
            "main",
            "int4 main(int4 argc,char **argv)",
            "xunknown8 main(int4 param_1)",
        ),
        (
            "decode_xor",
            "void decode_xor(char *output)",
            "void decode_xor(int8 param_1)",
        ),
        (
            "branch_loop",
            "uint4 branch_loop(uint4 count)",
            "uint4 branch_loop(uint4 param_1)",
        ),
    ];
    let mut off = managed_session(&path, false, Executor::Fork, &[]);
    for (name, _, inferred) in declarations {
        let address = managed_address(&mut off, name);
        let (text, _, semantics) = managed_function(&mut off, address, false);
        assert!(text.contains(inferred), "{text}");
        assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    }
    for executor in [Executor::Fork, Executor::Sibling] {
        let mut api = managed_session(&path, true, executor, &[]);
        for (name, declaration, _) in declarations {
            let address = managed_address(&mut api, name);
            for refresh in [false, true] {
                let (text, _, semantics) = managed_function(&mut api, address, refresh);
                assert!(text.contains(declaration), "{executor:?} {refresh}: {text}");
                assert_eq!(
                    semantics.prototype_source,
                    PrototypeSource::DebugInfo,
                    "{executor:?}"
                );
                assert!(
                    !semantics
                        .warnings
                        .iter()
                        .any(|w| w == ghidra_rust::analysis::OPTIONAL_UNAVAILABLE_WARNING),
                    "{:?}",
                    semantics.warnings
                );
            }
        }
        assert!(managed_skips(&mut api).is_empty());
    }
}

/// A stalled, CPU-spinning or aborting optional render (after its launch)
/// costs the request nothing but the window: the held baseline is the
/// answer, identical to debug-off apart from the warning, no skip is
/// recorded, and the next request on the same session works.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(not(feature = "test-hooks"), ignore = "needs the test-hooks worker")]
fn managed_debug_faults_return_the_held_baseline() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, path) = fixture(true);
    let mut off = managed_session(&path, false, Executor::Fork, &[]);
    let main = managed_address(&mut off, "main");
    let branch = managed_address(&mut off, "branch_loop");
    let (off_text, off_mappings, off_semantics) = managed_function(&mut off, main, false);
    let json = |value: &dyn erased::Json| value.json();
    for executor in [Executor::Fork, Executor::Sibling] {
        for fault in ["stall", "spin", "abort"] {
            let argument = format!("{}{fault}@{main:#x}", ghidra_rust::worker::FAULT_ARGUMENT);
            let mut api = managed_session(&path, true, executor, &[argument]);
            let started = Instant::now();
            let (text, mappings, semantics) = managed_function(&mut api, main, false);
            let elapsed = started.elapsed();
            let order = format!("{executor:?} {fault}");
            assert!(elapsed < Duration::from_secs(20), "{order}: {elapsed:?}");
            assert_eq!(text, off_text, "{order}");
            assert_eq!(json(&mappings), json(&off_mappings), "{order}");
            assert_eq!(
                json(&semantics.tokens),
                json(&off_semantics.tokens),
                "{order}"
            );
            assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
            assert_eq!(
                semantics.warnings.first().map(String::as_str),
                Some(ghidra_rust::analysis::UNVERIFIED_WARNING),
                "{order}: {:?}",
                semantics.warnings
            );
            assert!(managed_skips(&mut api).is_empty(), "{order}");
            // The session is healthy: another function upgrades.
            let (text, _, semantics) = managed_function(&mut api, branch, false);
            assert!(
                text.contains("uint4 branch_loop(uint4 count)"),
                "{order}: {text}"
            );
            assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
            // A second visit of the faulted function stays usable.
            let (text, _, _) = managed_function(&mut api, main, true);
            assert_eq!(text, off_text, "{order}");
            assert!(managed_skips(&mut api).is_empty(), "{order}");
        }
    }
}

/// Drives the public console protocol over `commands` on `api`, one reply
/// line per command, parsed.
#[cfg(target_os = "linux")]
fn serve_commands(
    api: &mut ghidra_rust::headless::Analyzer,
    commands: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    let input = commands
        .iter()
        .enumerate()
        .map(|(index, command)| {
            format!(
                "{}\n",
                serde_json::json!({"api_version": 1, "id": index + 1, "command": command})
            )
        })
        .collect::<String>();
    let mut output = Vec::new();
    ghidra_rust::headless::protocol::serve(input.as_bytes(), &mut output, api).unwrap();
    let replies = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    // Exactly one terminal reply per command, in order.
    assert_eq!(replies.len(), commands.len(), "{replies:?}");
    for (index, reply) in replies.iter().enumerate() {
        assert_eq!(reply["id"], serde_json::json!(index + 1), "{reply}");
    }
    replies
}

/// A worker stop before the managed baseline (the deterministic CPU-limit
/// exit after the ordinary render, before the baseline frame) is recovered
/// once with inference only and records no skip, through Info, an embedded
/// Save, a reopen without re-enabling debug info, and Refresh. The saved
/// snapshot keeps the original empty list, the inferred render equals
/// debug-off, and an unfaulted worker on the reopened project still
/// upgrades. A recovery that stops too is the command's ordinary error.
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(not(feature = "test-hooks"), ignore = "needs the test-hooks worker")]
fn managed_scheduler_prepare_stop_recovers_without_a_saved_skip() {
    use ghidra_rust::headless::{Analyzer, Input, Options};
    use ghidra_rust::semantic::PrototypeSource;
    let (directory, path) = fixture(true);
    let mut off = managed_session(&path, false, Executor::Fork, &[]);
    let main = managed_address(&mut off, "main");
    let branch = managed_address(&mut off, "branch_loop");
    let (off_text, off_mappings, off_semantics) = managed_function(&mut off, main, false);
    assert!(off_text.contains("main(int4 param_1)"), "{off_text}");
    drop(off);
    let json = |value: &dyn erased::Json| value.json();
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"));
    let fault = |kind: &str| {
        vec![std::ffi::OsString::from(format!(
            "{}{kind}@{main:#x}",
            ghidra_rust::worker::FAULT_ARGUMENT
        ))]
    };
    let function =
        |refresh| serde_json::json!({"kind": "function", "address": main, "refresh": refresh});
    let info = serde_json::json!({"kind": "info"});
    let check_inferred = |reply: &serde_json::Value, order: &str| {
        assert!(reply.get("error").is_none(), "{order}: {reply}");
        let analysis = &reply["result"]["analysis"];
        assert_eq!(analysis["text"], serde_json::json!(off_text), "{order}");
        assert_eq!(analysis["mappings"], json(&off_mappings), "{order}");
        assert_eq!(
            analysis["semantics"]["tokens"],
            json(&off_semantics.tokens),
            "{order}"
        );
        assert_eq!(
            analysis["semantics"]["locals"],
            json(&off_semantics.locals),
            "{order}"
        );
        assert_eq!(
            analysis["semantics"]["prototype"],
            json(&off_semantics.prototype),
            "{order}"
        );
        assert_eq!(
            analysis["semantics"]["prototype_source"],
            json(&PrototypeSource::Inferred),
            "{order}"
        );
        // The ordinary unverified warning, never the legacy skip warning.
        let warnings = analysis["semantics"]["warnings"].to_string();
        assert!(
            warnings.contains(ghidra_rust::analysis::UNVERIFIED_WARNING),
            "{order}: {warnings}"
        );
        assert!(
            !warnings.contains(ghidra_rust::debug_info::SKIPPED_FUNCTION_WARNING),
            "{order}: {warnings}"
        );
    };
    let no_skips = |reply: &serde_json::Value, order: &str| {
        assert_eq!(
            reply["result"]["debug_skipped_functions"],
            serde_json::json!([]),
            "{order}: {reply}"
        );
        assert_eq!(reply["result"]["use_debug_info"], serde_json::json!(true));
        assert_eq!(
            reply["result"]["debug_status"],
            serde_json::json!("enabled")
        );
    };
    let project = directory.path().join("scheduler.grproj");
    let mut api = Analyzer::open(
        Input::Binary(path.clone()),
        exe,
        Options {
            use_debug_info: Some(true),
            output_project: Some(project.clone()),
            worker_arguments: fault("prepare-exit"),
            ..Options::default()
        },
    )
    .unwrap();
    let replies = serve_commands(
        &mut api,
        &[
            function(false),
            info.clone(),
            serde_json::json!({"kind": "save_project", "embed_binary": true}),
        ],
    );
    check_inferred(&replies[0], "first console");
    no_skips(&replies[1], "first console");
    assert!(replies[2].get("error").is_none(), "{}", replies[2]);
    drop(api);
    let saved = ghidra_rust::project::ProjectData::load(&project).unwrap();
    assert!(saved.data.use_debug_info);
    assert!(
        saved.data.debug_skip.is_empty(),
        "{:?}",
        saved.data.debug_skip
    );
    drop(saved);
    // Reopened without --use-debug-info (which would clear skips).
    let reopen = |worker_arguments| {
        Analyzer::open(
            Input::Project {
                path: project.clone(),
                external_binary: None,
            },
            exe,
            Options {
                worker_arguments,
                ..Options::default()
            },
        )
        .unwrap()
    };
    let mut api = reopen(fault("prepare-exit"));
    let replies = serve_commands(&mut api, &[info.clone(), function(true), info.clone()]);
    no_skips(&replies[0], "reopened");
    check_inferred(&replies[1], "reopened Refresh");
    no_skips(&replies[2], "after Refresh");
    drop(api);
    // Without the fault, the same project still upgrades.
    let mut api = reopen(Vec::new());
    let (text, _, semantics) = managed_function(&mut api, main, true);
    assert!(text.contains("int4 main(int4 argc,char **argv)"), "{text}");
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
    assert!(managed_skips(&mut api).is_empty());
    drop(api);
    // Both attempts stop: the ordinary error, and still no skip.
    let mut api = managed_session_with(
        &path,
        true,
        Executor::Fork,
        exe,
        &[format!(
            "{}prepare-exit-always@{main:#x}",
            ghidra_rust::worker::FAULT_ARGUMENT
        )],
    );
    let replies = serve_commands(&mut api, &[function(false), info.clone()]);
    assert_eq!(
        replies[0]["error"]["code"],
        serde_json::json!("worker_failed"),
        "{}",
        replies[0]
    );
    assert!(
        replies[0]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("CPU time limit reached"),
        "{}",
        replies[0]
    );
    no_skips(&replies[1], "double failure");
    drop(api);
    // The hook is per function: another function on a faulted worker
    // upgrades normally.
    let mut api = managed_session(
        &path,
        true,
        Executor::Fork,
        &[format!(
            "{}prepare-exit@{main:#x}",
            ghidra_rust::worker::FAULT_ARGUMENT
        )],
    );
    let (text, _, semantics) = managed_function(&mut api, branch, false);
    assert!(text.contains("uint4 branch_loop(uint4 count)"), "{text}");
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
}

/// The caller-evidence regression through the managed path in both
/// executors. With a fork, the fresh caller is vetoed at once (the nested
/// callee batch proves the callee). A nonfork sibling may defer an
/// undecided callee; after the callee's own render, Refresh must still
/// preserve the caller's fifth formal at `collect_task`'s fourth argument,
/// and the positive wrapper shows the verified callee.
#[cfg(target_os = "linux")]
#[test]
fn managed_debug_caller_evidence_in_both_executors() {
    use ghidra_rust::semantic::PrototypeSource;
    let (_directory, image, [entry, positive, schedule]) = caller_fixture();
    let mut off = managed_session(&image, false, Executor::Fork, &[]);
    let (off_text, off_mappings, off_semantics) = managed_function(&mut off, entry, false);
    let formals = off_semantics
        .prototype
        .as_ref()
        .expect("inferred prototype")
        .parameters
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>();
    assert_eq!(formals.len(), 5, "{off_text}");
    let forwarded = |text: &str| {
        let calls = call_arguments(text, "(*collect_task@got)");
        assert_eq!(calls.len(), 1, "{text}");
        calls[0].clone()
    };
    assert_eq!(forwarded(&off_text).get(3), Some(&formals[4]));
    let (off_positive, _, _) = managed_function(&mut off, positive, false);
    let off_header = off_positive.split('{').next().unwrap().to_owned();
    let json = |value: &dyn erased::Json| value.json();
    let same_as_off = |(text, mappings, semantics): &(
        String,
        Vec<ghidra_rust::model::CodeMapping>,
        ghidra_rust::semantic::SemanticInfo,
    ),
                       order: &str| {
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::Inferred,
            "{order}"
        );
        assert_eq!(forwarded(text).get(3), Some(&formals[4]), "{order}: {text}");
        assert_eq!(text, &off_text, "{order}");
        assert_eq!(json(mappings), json(&off_mappings), "{order}");
        assert_eq!(
            json(&semantics.tokens),
            json(&off_semantics.tokens),
            "{order}"
        );
        assert_eq!(
            json(&semantics.locals),
            json(&off_semantics.locals),
            "{order}"
        );
    };
    let vetoed = |result: &(
        String,
        Vec<ghidra_rust::model::CodeMapping>,
        ghidra_rust::semantic::SemanticInfo,
    ),
                  order: &str| {
        same_as_off(result, order);
        assert!(
            result
                .2
                .warnings
                .iter()
                .any(|w| w == ghidra_rust::analysis::CALLER_EVIDENCE_WARNING),
            "{order}: {:?}",
            result.2.warnings
        );
    };
    for executor in [Executor::Fork, Executor::Sibling] {
        let mut api = managed_session(&image, true, executor, &[]);
        let fresh = managed_function(&mut api, entry, false);
        match executor {
            Executor::Fork => vetoed(&fresh, "fork fresh"),
            Executor::Sibling => same_as_off(&fresh, "sibling fresh"),
        }
        let (text, _, semantics) = managed_function(&mut api, schedule, false);
        assert_eq!(
            semantics.prototype_source,
            PrototypeSource::DebugInfo,
            "{executor:?}"
        );
        assert!(
            text.contains(
                "void * sample_schedule(void *queue,uint4 delay,code *callback,void *context,void *cleanup)"
            ),
            "{text}"
        );
        vetoed(
            &managed_function(&mut api, entry, true),
            &format!("{executor:?} refresh"),
        );
        let (text, _, semantics) = managed_function(&mut api, positive, false);
        let header = text.split('{').next().unwrap();
        assert!(header.contains("void *param_1"), "{executor:?}: {header}");
        assert_ne!(
            header, off_header,
            "{executor:?}: the callee prototype applies"
        );
        let calls = call_arguments(&text, "sample_schedule");
        assert_eq!(calls.len(), 1, "{text}");
        assert_eq!(calls[0].len(), 5, "{text}");
        assert!(
            !semantics
                .warnings
                .iter()
                .any(|w| w == ghidra_rust::analysis::CALLER_EVIDENCE_WARNING),
            "{:?}",
            semantics.warnings
        );
        assert!(managed_skips(&mut api).is_empty());
    }
}

/// Two units name `ReviewType` differently (a scalar typedef and a
/// structure). Every optional render builds its types in a fresh factory,
/// so neither order nor Refresh lets one unit's type leak into the other.
#[cfg(target_os = "linux")]
#[test]
fn managed_debug_fresh_type_factories_keep_colliding_names_apart() {
    use ghidra_rust::semantic::PrototypeSource;
    let directory = tempfile::tempdir().unwrap();
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");
    let mut objects = Vec::new();
    for unit in ["debug_review_scalar", "debug_review_pointer"] {
        let object = directory.path().join(format!("{unit}.o"));
        let status = Command::new("gcc")
            .args(["-g", "-O1", "-fPIC", "-c"])
            .arg(format!("{fixtures}{unit}.c"))
            .arg("-o")
            .arg(&object)
            .status()
            .unwrap();
        assert!(status.success());
        objects.push(object);
    }
    let image = directory.path().join("review.so");
    let status = Command::new("gcc")
        .args(["-nostdlib", "-shared"])
        .args(&objects)
        .arg("-o")
        .arg(&image)
        .status()
        .unwrap();
    assert!(status.success());
    let mut expected = None;
    for executor in [Executor::Fork, Executor::Sibling] {
        for order in [
            ["review_scalar", "review_pointer"],
            ["review_pointer", "review_scalar"],
        ] {
            let mut api = managed_session(&image, true, executor, &[]);
            let mut headers = std::collections::BTreeMap::new();
            for refresh in [false, true] {
                for name in order {
                    let address = managed_address(&mut api, name);
                    let (text, _, semantics) = managed_function(&mut api, address, refresh);
                    assert_eq!(
                        semantics.prototype_source,
                        PrototypeSource::DebugInfo,
                        "{name}"
                    );
                    let header = text.split('{').next().unwrap().trim().to_owned();
                    if let Some(previous) = headers.insert(name, header.clone()) {
                        assert_eq!(previous, header, "{executor:?} {order:?} refresh");
                    }
                }
            }
            assert!(
                headers["review_scalar"].contains("ReviewType value"),
                "{headers:?}"
            );
            assert!(
                headers["review_pointer"].contains("ReviewType *value"),
                "{headers:?}"
            );
            match &expected {
                None => expected = Some(headers),
                Some(expected) => assert_eq!(expected, &headers, "{executor:?} {order:?}"),
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(not(feature = "test-hooks"), ignore = "needs the test-hooks worker")]
fn managed_debug_empty_optional_window_does_not_start_a_peer() {
    use ghidra_rust::headless::{Analyzer, Input, Options};
    let (_directory, path) = fixture(true);
    let mut off = managed_session(&path, false, Executor::Fork, &[]);
    let main = managed_address(&mut off, "main");
    let branch = managed_address(&mut off, "branch_loop");
    let baseline = managed_function(&mut off, main, false);
    let mut on = Analyzer::open(
        Input::Binary(path),
        std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless")),
        Options {
            use_debug_info: Some(true),
            worker_timeout: Duration::from_secs(3),
            worker_arguments: vec![
                ghidra_rust::worker::NO_FORK_ARGUMENT.into(),
                format!("{}stall@{main:#x}", ghidra_rust::worker::FAULT_ARGUMENT).into(),
            ],
            ..Options::default()
        },
    )
    .unwrap();
    let (text, mappings, mut semantics) = managed_function(&mut on, main, false);
    assert_eq!(text, baseline.0);
    assert_eq!(
        serde_json::to_value(mappings).unwrap(),
        serde_json::to_value(baseline.1).unwrap()
    );
    assert_eq!(
        semantics.warnings.pop().as_deref(),
        Some(ghidra_rust::analysis::UNVERIFIED_WARNING)
    );
    assert_eq!(
        serde_json::to_value(semantics).unwrap(),
        serde_json::to_value(baseline.2).unwrap()
    );
    assert!(
        managed_function(&mut on, branch, false)
            .0
            .contains("branch_loop")
    );
    assert!(managed_skips(&mut on).is_empty());
}

#[cfg(windows)]
#[test]
fn managed_debug_native_caller_keeps_forwarded_stack_input_after_priming() {
    use ghidra_rust::semantic::{PrototypeSource, TokenKind};
    let Some(path) = std::env::var_os("GHIDRA_RUST_TEST_PE_DWARF_CALLER") else {
        eprintln!("Set GHIDRA_RUST_TEST_PE_DWARF_CALLER using scripts/build-windows.ps1");
        return;
    };
    let mut off = managed_session(std::path::Path::new(&path), false, Executor::Sibling, &[]);
    let entry = managed_address(&mut off, "sample_entry");
    let positive = managed_address(&mut off, "sample_entry_positive");
    let schedule = managed_address(&mut off, "sample_schedule");
    use ghidra_rust::headless::{Analyzer, Command as ApiCommand, Output};
    let render_caller = |api: &mut Analyzer, refresh| {
        let Output::Function { analysis } = api
            .execute(ApiCommand::Function {
                address: entry,
                refresh,
            })
            .unwrap()
        else {
            panic!("expected the caller function");
        };
        analysis
    };
    let forwarded = |analysis: &ghidra_rust::headless::FunctionAnalysis| {
        let text = &analysis.text;
        let prototype = analysis.semantics.prototype.as_ref().unwrap();
        assert!(prototype.parameters.len() >= 5, "{text}");
        let forwarded = &prototype.parameters[4].name;
        let mut indirect = analysis
            .view
            .calls
            .iter()
            .filter(|call| call.target.is_none());
        let site = indirect.next().expect("indirect collecting call").address;
        assert!(indirect.next().is_none(), "ambiguous collecting call");
        assert!(
            analysis
                .mappings
                .iter()
                .filter(|mapping| mapping.addresses.contains(&site))
                .any(|mapping| {
                    let start = text[..mapping.start]
                        .rfind('\n')
                        .map_or(0, |start| start + 1);
                    let end = text[mapping.start..]
                        .find(';')
                        .map_or(mapping.end, |end| mapping.start + end);
                    let statement = &text[start..end];
                    let Some((_, arguments)) = statement.split_once(")(") else {
                        return false;
                    };
                    arguments
                        .trim_end_matches(')')
                        .split(',')
                        .nth(3)
                        .map(str::trim)
                        == Some(forwarded.as_str())
                }),
            "Missing fifth Win64 input in the fourth slot of call {site:#x}: {text}"
        );
        site
    };
    let off_caller = render_caller(&mut off, false);
    let collect_site = forwarded(&off_caller);
    let (off_positive, _, _) = managed_function(&mut off, positive, false);
    let mut on = managed_session(std::path::Path::new(&path), true, Executor::Sibling, &[]);
    let (text, _, semantics) = managed_function(&mut on, schedule, false);
    assert_eq!(
        semantics.prototype_source,
        PrototypeSource::DebugInfo,
        "{text}"
    );
    assert!(
        text.contains("sample_schedule(") && text.contains("*queue"),
        "{text}"
    );
    assert_eq!(forwarded(&render_caller(&mut on, true)), collect_site);
    let (text, _, semantics) = managed_function(&mut on, positive, true);
    assert_ne!(
        text, off_positive,
        "The verified callee must improve the wrapper: {:?}",
        semantics.warnings
    );
    assert!(
        semantics.tokens.iter().any(|token| matches!(
            token.kind, TokenKind::Call { target } if target == schedule
        )),
        "{text}"
    );
    assert!(managed_skips(&mut on).is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn managed_debug_fork_refusal_does_not_launch_and_old_open_nonce_cannot_be_reused() {
    let (_directory, image) = fixture(true);
    let mut worker = Process::start_with(&[("GHIDRA_RUST_DEBUG_TRACE", "1")]);
    let info = open(&mut worker, &image, true);
    let address = info
        .functions
        .iter()
        .find(|function| function.name == "branch_loop")
        .unwrap()
        .address;
    let request = |logical_id| Request::PrepareDecompile {
        logical_id,
        address,
        renames: Vec::new(),
        refresh: false,
        inference_only: false,
    };
    let offer = match worker.request(request(1)) {
        Response::PreparedDecompile { offer, .. } => serde_json::to_value(offer).unwrap(),
        reply => panic!("{reply:?}"),
    };
    let job = |remaining_ms| {
        let job = serde_json::json!({
            "ticket": { "logical_id": 1, "nonce": offer["nonce"], "book_version": 1 },
            "address": address, "remaining_ms": remaining_ms, "renames": [],
            "binding": offer["binding"], "target_work": offer["target_work"],
            "graph_prepared": offer["graph_prepared"], "callees": offer["callees"],
            "seed": { "states": [], "large": [] },
        });
        serde_json::from_value(job).unwrap()
    };
    assert!(matches!(
        worker.request(Request::TryPreparedDebug { job: job(0) }),
        Response::DebugUnavailable { .. }
    ));
    assert!(!worker.stderr().contains(&format!("fork {address:#x}")));
    open(&mut worker, &image, true);
    let Response::PreparedDecompile { .. } = worker.request(request(2)) else {
        panic!("A new Open must admit the same address");
    };
    assert!(matches!(
        worker.request(Request::TryPreparedDebug { job: job(1000) }),
        Response::DebugUnavailable { ref reason, .. } if reason == "stale"
    ));
    let (text, semantics) = decompile(&mut worker, address);
    assert!(text.contains("uint4 branch_loop(uint4 count)"), "{text}");
    assert_eq!(
        semantics.prototype_source,
        ghidra_rust::semantic::PrototypeSource::DebugInfo
    );
}

/// Native Windows status transport and recovery for the injected watchdog
/// exit: the test-only `prepare-exit` hook ends a real Prepare with the
/// Windows CPU-limit code before any baseline frame. A raw worker reports
/// exit code 124; the production client calls it the CPU limit; the
/// Analyzer recovers once with inference only and no skip; a stop of the
/// recovery too is the ordinary CPU-limit error with no third worker; a
/// clean session still upgrades.
#[cfg(windows)]
#[test]
#[cfg_attr(not(feature = "test-hooks"), ignore = "needs the test-hooks worker")]
fn managed_scheduler_windows_prepare_exit_is_the_cpu_limit_and_recovers() {
    use ghidra_rust::model::{Request, Response, WorkerRequest, WorkerResponse};
    use ghidra_rust::semantic::PrototypeSource;
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let Some((_directory, path)) = sibling_fixture() else {
        return;
    };
    let exe = std::path::Path::new(env!("CARGO_BIN_EXE_ghidra-rust-headless"));
    let mut off = managed_session(&path, false, Executor::Fork, &[]);
    let main = managed_address(&mut off, "main");
    let (off_text, off_mappings, off_semantics) = managed_function(&mut off, main, false);
    drop(off);
    let fault = |kind: &str| format!("{}{kind}@{main:#x}", ghidra_rust::worker::FAULT_ARGUMENT);
    let open = |path: &std::path::Path| Request::Open {
        path: path.to_str().unwrap().into(),
        debug: ghidra_rust::debug_info::DebugOptions {
            enabled: true,
            companion_path: None,
            skip: Vec::new(),
        },
    };
    let prepare = || Request::PrepareDecompile {
        logical_id: 1,
        address: main,
        renames: Vec::new(),
        refresh: false,
        inference_only: false,
    };

    // A raw worker with owned redirected pipes: the Open is answered, the
    // Prepare ends the process with 124 and no baseline frame.
    let mut child = Command::new(exe)
        .arg("--analysis-worker")
        .arg(fault("prepare-exit"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut exchange = |id, request| {
        serde_json::to_writer(&mut input, &WorkerRequest { id, request }).unwrap();
        input.write_all(b"\n").unwrap();
        input.flush().unwrap();
    };
    exchange(1, open(&path));
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let opened: WorkerResponse = serde_json::from_str(&line).unwrap();
    assert!(matches!(opened.response, Response::Opened { .. }), "{line}");
    exchange(2, prepare());
    let mut frames = Vec::new();
    loop {
        line.clear();
        if output.read_line(&mut line).unwrap() == 0 {
            break;
        }
        frames.push(serde_json::from_str::<WorkerResponse>(&line).unwrap());
    }
    assert!(
        !frames.iter().any(|frame| matches!(
            frame.response,
            Response::PreparedDecompile { .. } | Response::Decompiled { .. }
        )),
        "{frames:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "the faulted worker did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(status.code(), Some(124));

    // The production client classifies that exit as the CPU limit.
    let mut client = ghidra_rust::client::WorkerClient::start_with_worker_arguments(
        eframe::egui::Context::default(),
        &path,
        exe,
        None,
        true,
        vec![fault("prepare-exit").into()],
    )
    .unwrap();
    let poll = |client: &mut ghidra_rust::client::WorkerClient| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(event) = client.poll() {
                return event;
            }
            assert!(Instant::now() < deadline, "no worker event");
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    // The bound worker opens the client's protected image.
    let protected = client.protection().path().to_owned();
    client.send(open(&protected)).unwrap();
    assert!(matches!(
        poll(&mut client),
        ghidra_rust::client::WorkerEvent::Reply(reply)
            if matches!(reply.response, Response::Opened { .. })
    ));
    client.send(prepare()).unwrap();
    match poll(&mut client) {
        ghidra_rust::client::WorkerEvent::Failed(message) => {
            assert!(message.contains("CPU time limit reached"), "{message}");
        }
        ghidra_rust::client::WorkerEvent::Reply(reply) => panic!("{reply:?}"),
    }
    drop(client);

    // The Analyzer recovers once with inference only and records no skip.
    let mut api = managed_session_with(
        &path,
        true,
        Executor::Sibling,
        exe,
        &[fault("prepare-exit")],
    );
    let (text, mappings, semantics) = managed_function(&mut api, main, false);
    assert_eq!(text, off_text);
    assert_eq!(mappings, off_mappings);
    assert_eq!(semantics.tokens, off_semantics.tokens);
    assert_eq!(semantics.prototype, off_semantics.prototype);
    assert_eq!(semantics.prototype_source, PrototypeSource::Inferred);
    assert!(
        semantics
            .warnings
            .iter()
            .any(|warning| warning == ghidra_rust::analysis::UNVERIFIED_WARNING),
        "{:?}",
        semantics.warnings
    );
    assert!(managed_skips(&mut api).is_empty());
    drop(api);

    // Both Prepares stop: the second stop's CPU-limit error, still no skip.
    let mut api = managed_session_with(
        &path,
        true,
        Executor::Sibling,
        exe,
        &[fault("prepare-exit-always")],
    );
    let error = api
        .execute(ghidra_rust::headless::Command::Function {
            address: main,
            refresh: false,
        })
        .expect_err("the recovery stopped too");
    assert_eq!(error.code, ghidra_rust::headless::ErrorCode::WorkerFailed);
    assert!(
        error.message.contains("CPU time limit reached"),
        "{}",
        error.message
    );
    assert!(managed_skips(&mut api).is_empty());
    drop(api);

    // An unfaulted session still upgrades.
    let mut api = managed_session(&path, true, Executor::Sibling, &[]);
    let (text, _, semantics) = managed_function(&mut api, main, true);
    assert!(text.contains("int4 main(int4 argc,char **argv)"), "{text}");
    assert_eq!(semantics.prototype_source, PrototypeSource::DebugInfo);
}
