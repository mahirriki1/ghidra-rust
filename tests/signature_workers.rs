//! Complete signature-state replay through real disposable worker processes.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use ghidra_rust::{
    client::{WorkerClient, WorkerEvent},
    model::{
        BinaryInfo, CodeMapping, FunctionView, Request, Response, WorkerRequest, WorkerResponse,
    },
    semantic::{
        LOCAL_FINGERPRINT, LocalIdentity, LocalRename, SIGNATURE_LOCAL_FINGERPRINT, SemanticInfo,
        TokenKind,
    },
    signatures::{
        self, FunctionSignature, SIGNATURE_FINGERPRINT, SignatureBase, SignatureParameter,
        SignatureType,
    },
};
use object::{Object, ObjectSymbol};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

struct Fixture {
    _directory: tempfile::TempDir,
    binary: PathBuf,
    addresses: BTreeMap<String, u64>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("signatures.c");
        std::fs::write(
            &source,
            r#"
#include <stdint.h>
__attribute__((noinline)) int64_t callee(int64_t *values, uint32_t count) {
    return values[count] + count;
}
__attribute__((noinline)) int64_t caller(int64_t *values, uint32_t count) {
    int64_t result = callee(values, count);
    return result + 3;
}
__attribute__((noinline)) int64_t zero(void) { return 7; }
int main(void) {
    int64_t values[2] = {4, 8};
    return (int)caller(values, 1) + (int)zero();
}
"#,
        )
        .unwrap();
        let binary = directory.path().join("fixture");
        let output = Command::new("gcc")
            .args(["-O0", "-fno-pie", "-no-pie", "-fno-inline"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .output()
            .expect("worker signature tests require GCC");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = std::fs::read(&binary).unwrap();
        let image = object::File::parse(bytes.as_slice()).unwrap();
        let addresses = image
            .symbols()
            .filter_map(|s| Some((s.name().ok()?.to_owned(), s.address())))
            .collect();
        Self {
            _directory: directory,
            binary,
            addresses,
        }
    }

    fn address(&self, name: &str) -> u64 {
        self.addresses[name]
    }

    fn open(&self) -> (WorkerClient, BinaryInfo) {
        let mut worker = WorkerClient::start_using_executable(
            eframe::egui::Context::default(),
            &self.binary,
            Path::new(env!("CARGO_BIN_EXE_ghidra-rust")),
        )
        .expect("start contained worker");
        let info = open(&mut worker, self);
        (worker, info)
    }

    fn signature(&self, info: &BinaryInfo, name: &str) -> FunctionSignature {
        FunctionSignature {
            function: self.address(name),
            engine: SIGNATURE_FINGERPRINT.into(),
            abi: signatures::current_abi(info).unwrap(),
            return_type: ty(SignatureBase::I64, 0),
            parameters: if name == "callee" {
                vec![
                    SignatureParameter {
                        name: "values_owned".into(),
                        ty: ty(SignatureBase::I64, 1),
                    },
                    SignatureParameter {
                        name: "count_owned".into(),
                        ty: ty(SignatureBase::U32, 0),
                    },
                ]
            } else {
                vec![]
            },
        }
    }
}

fn ty(base: SignatureBase, pointer_depth: u8) -> SignatureType {
    SignatureType {
        base,
        pointer_depth,
    }
}

fn request(worker: &mut WorkerClient, request: Request) -> Response {
    let id = worker.send(request).expect("send contained worker request");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match worker.poll() {
            Some(WorkerEvent::Reply(reply)) => {
                assert_eq!(reply.id, id);
                if let Response::Progress { progress } = &reply.response {
                    progress.validate_after(None).unwrap();
                    continue;
                }
                return reply.response;
            }
            Some(WorkerEvent::Failed(error)) => panic!("Contained worker failed: {error}"),
            None if Instant::now() >= deadline => panic!("Contained worker timed out"),
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn open(worker: &mut WorkerClient, fixture: &Fixture) -> BinaryInfo {
    match request(
        worker,
        Request::Open {
            path: fixture.binary.to_string_lossy().into_owned(),
        },
    ) {
        Response::Opened { info } => info,
        other => panic!("Expected opened fixture, got {other:?}"),
    }
}

// Reproduce the frontend startup order: inventory and names, then complete
// signature state, then the first Graph/Discover/Decompile request.
fn inventory(worker: &mut WorkerClient, info: &BinaryInfo) {
    assert!(matches!(
        request(
            worker,
            Request::SyncFunctions {
                functions: info.functions.clone(),
            }
        ),
        Response::FunctionsSynced
    ));
}

fn sync_request(info: &BinaryInfo, signatures: &[FunctionSignature]) -> Request {
    Request::SyncSignatures {
        binary_sha256: info.sha256.clone(),
        context: signatures::state_digest(signatures),
        signatures: signatures.to_vec(),
    }
}

fn sync(worker: &mut WorkerClient, info: &BinaryInfo, signatures: &[FunctionSignature]) {
    assert_ack(
        request(worker, sync_request(info, signatures)),
        info,
        signatures,
        &[],
    );
}

fn assert_ack(
    response: Response,
    info: &BinaryInfo,
    signatures: &[FunctionSignature],
    unapplied_entries: &[u64],
) {
    let Response::SignaturesSynced {
        binary_sha256,
        context,
        unapplied,
    } = response
    else {
        panic!("Expected complete signature-state acknowledgement, got {response:?}");
    };
    assert_eq!(binary_sha256, info.sha256);
    // Includes incompatible and missing-entry records, and hashes [] as well.
    assert_eq!(context, signatures::state_digest(signatures));
    assert!(!context.is_empty());
    assert_eq!(
        unapplied
            .iter()
            .map(|s| s.function)
            .collect::<BTreeSet<_>>(),
        unapplied_entries.iter().copied().collect()
    );
    assert_eq!(unapplied.len(), unapplied_entries.len());
    assert!(unapplied.iter().all(|s| !s.reason.trim().is_empty()));
}

struct Decompiled {
    text: String,
    mappings: Vec<CodeMapping>,
    semantics: SemanticInfo,
}

fn decompile(
    worker: &mut WorkerClient,
    info: &BinaryInfo,
    address: u64,
    renames: Vec<LocalRename>,
) -> Decompiled {
    let response = request(worker, Request::DecompileWithLocals { address, renames });
    let Response::Decompiled {
        address: actual,
        text,
        mappings,
        semantics,
    } = response
    else {
        panic!("Expected decompilation at {address:#x}, got {response:?}");
    };
    assert_eq!(actual, address);
    ghidra_rust::selection::validate_mappings(&text, &mappings, &info.sections).unwrap();
    semantics.validate(&text, address, &info.sections).unwrap();
    assert!(!mappings.is_empty(), "Missing engine printmarks: {text}");
    assert!(
        !semantics.locals.is_empty(),
        "Missing real local identities: {text}"
    );
    Decompiled {
        text,
        mappings,
        semantics,
    }
}

fn graph(worker: &mut WorkerClient, address: u64) -> FunctionView {
    match request(worker, Request::Graph { address }) {
        Response::Graph { view } => {
            assert_eq!(view.address, address);
            view
        }
        other => panic!("Expected graph, got {other:?}"),
    }
}

fn identities(result: &Decompiled) -> BTreeSet<LocalIdentity> {
    result
        .semantics
        .locals
        .iter()
        .map(|v| v.identity.clone())
        .collect()
}

fn assert_fingerprint(result: &Decompiled, fingerprint: &str) {
    assert!(!result.semantics.locals.is_empty());
    assert!(
        result
            .semantics
            .locals
            .iter()
            .all(|v| v.identity.engine == fingerprint)
    );
}

fn assert_prototype(result: &Decompiled, signature: &FunctionSignature) {
    let prototype = result
        .semantics
        .prototype
        .as_ref()
        .expect("Engine prototype");
    assert_eq!(
        prototype.return_type,
        Some(signature.return_type),
        "{}",
        result.text
    );
    assert_eq!(prototype.abi, signature.abi);
    assert!(prototype.unsupported.is_empty(), "{prototype:?}");
    assert_eq!(
        prototype
            .parameters
            .iter()
            .map(|p| (&p.name, p.ty))
            .collect::<Vec<_>>(),
        signature
            .parameters
            .iter()
            .map(|p| (&p.name, Some(p.ty)))
            .collect::<Vec<_>>()
    );
}

fn assert_discarded(worker: &mut WorkerClient, address: u64) {
    for next in [
        Request::Bytes { address, length: 1 },
        Request::Graph { address },
        Request::Decompile { address },
    ] {
        assert!(
            matches!(request(worker, next), Response::Error { message } if message == "Open a binary first.")
        );
    }
}

#[test]
fn complete_state_is_installed_before_caller_analysis_and_keeps_real_call_mappings() {
    let fixture = Fixture::new();
    let (mut worker, mut info) = fixture.open();
    let callee = fixture.address("callee");
    let caller = fixture.address("caller");
    // Saved inventory names must be installed before signature application too.
    info.functions
        .iter_mut()
        .find(|f| f.address == callee)
        .unwrap()
        .name = "renamed_callee".into();
    inventory(&mut worker, &info);
    let mut zero = fixture.signature(&info, "zero");
    zero.return_type = ty(SignatureBase::U32, 0);
    let callee_signature = fixture.signature(&info, "callee");
    let saved = vec![zero.clone(), callee_signature.clone()];
    sync(&mut worker, &info, &saved);

    // No callee Graph or Decompile has run: only complete replay can provide
    // its locked parameter types to the first caller analysis.
    let result = decompile(&mut worker, &info, caller, vec![]);
    assert_fingerprint(&result, SIGNATURE_LOCAL_FINGERPRINT);
    assert!(
        result
            .semantics
            .locals
            .iter()
            .all(|v| v.signature_parameter.is_none())
    );
    let token = result
        .semantics
        .tokens
        .iter()
        .find(|t| matches!(t.kind, TokenKind::Call { target } if target == callee))
        .expect("Engine direct-call target");
    assert_eq!(&result.text[token.start..token.end], "renamed_callee");
    let arguments = result.text[token.end..].split(')').next().unwrap();
    assert!(
        arguments.starts_with('(') && arguments.contains(','),
        "{}",
        result.text
    );
    assert!(
        result.text.contains('*'),
        "Callee pointer type must propagate: {}",
        result.text
    );
    let view = graph(&mut worker, caller);
    let call = view
        .calls
        .iter()
        .find(|c| c.target == Some(callee))
        .expect("Real direct call in CFG");
    assert!(
        result.mappings.iter().any(|m| m.start < token.end
            && token.start < m.end
            && m.addresses.contains(&call.address)),
        "Call token must map to its real call instruction: {}",
        result.text
    );
    let instructions: BTreeSet<_> = view
        .blocks
        .iter()
        .flat_map(|b| b.instructions.iter().map(|i| i.address))
        .collect();
    assert!(
        result
            .mappings
            .iter()
            .flat_map(|m| &m.addresses)
            .all(|a| instructions.contains(a))
    );

    let callee_result = decompile(&mut worker, &info, callee, vec![]);
    assert_prototype(&callee_result, &callee_signature);
    for (index, parameter) in callee_signature.parameters.iter().enumerate() {
        assert!(
            callee_result
                .semantics
                .locals
                .iter()
                .any(|v| v.signature_parameter == Some(index) && v.name == parameter.name)
        );
    }
    // The second signature in the complete state must also reach the engine.
    let Response::Decompiled { semantics, .. } = request(
        &mut worker,
        Request::Decompile {
            address: zero.function,
        },
    ) else {
        panic!("Expected zero-parameter decompilation");
    };
    let prototype = semantics.prototype.unwrap();
    assert_eq!(prototype.return_type, Some(zero.return_type));
    assert!(prototype.parameters.is_empty());
}

#[test]
fn removing_and_restoring_state_across_workers_restores_caller_local_identities() {
    let fixture = Fixture::new();
    let caller = fixture.address("caller");
    let (mut worker, info) = fixture.open();
    inventory(&mut worker, &info);
    sync(&mut worker, &info, &[]);
    let baseline = decompile(&mut worker, &info, caller, vec![]);
    assert_fingerprint(&baseline, LOCAL_FINGERPRINT);
    drop(worker);

    let saved = vec![fixture.signature(&info, "callee")];
    let (mut worker, info) = fixture.open();
    inventory(&mut worker, &info);
    sync(&mut worker, &info, &saved);
    let active = decompile(&mut worker, &info, caller, vec![]);
    assert_fingerprint(&active, SIGNATURE_LOCAL_FINGERPRINT);
    assert!(
        active
            .semantics
            .locals
            .iter()
            .all(|v| v.signature_parameter.is_none())
    );
    let (index, local) = active
        .semantics
        .locals
        .iter()
        .enumerate()
        .find(|(index, _)| {
            active
                .semantics
                .tokens
                .iter()
                .filter(|t| matches!(t.kind, TokenKind::Local { local: Some(i) } if i == *index))
                .count()
                >= 2
        })
        .expect("Caller local with declaration and uses");
    let rename = LocalRename {
        identity: local.identity.clone(),
        name: "replayed_caller_local".into(),
    };
    let mut expected = active.text.clone();
    for token in active
        .semantics
        .tokens
        .iter()
        .rev()
        .filter(|t| matches!(t.kind, TokenKind::Local { local: Some(i) } if i == index))
    {
        expected.replace_range(token.start..token.end, &rename.name);
    }
    let renamed = decompile(&mut worker, &info, caller, vec![rename.clone()]);
    assert_eq!(renamed.text, expected);
    assert!(
        renamed.semantics.warnings.is_empty(),
        "{:?}",
        renamed.semantics.warnings
    );
    drop(worker);

    let (mut worker, info) = fixture.open();
    inventory(&mut worker, &info);
    sync(&mut worker, &info, &[]);
    let removed = decompile(&mut worker, &info, caller, vec![rename.clone()]);
    assert_eq!(removed.text, baseline.text);
    assert_eq!(identities(&removed), identities(&baseline));
    assert!(
        removed
            .semantics
            .warnings
            .iter()
            .any(|w| w.contains("not applied"))
    );
    assert_fingerprint(&removed, LOCAL_FINGERPRINT);
    drop(worker);

    let (mut worker, info) = fixture.open();
    inventory(&mut worker, &info);
    sync(&mut worker, &info, &saved);
    let restored = decompile(&mut worker, &info, caller, vec![rename]);
    assert_eq!(restored.text, expected);
    assert_eq!(identities(&restored), identities(&active));
    assert!(
        restored.semantics.warnings.is_empty(),
        "{:?}",
        restored.semantics.warnings
    );
}

#[test]
fn reapplying_or_replacing_state_discards_the_worker_until_fresh_open() {
    let fixture = Fixture::new();
    let caller = fixture.address("caller");
    // Reapplying identical state is forbidden even before analysis. The first
    // sync is also forbidden after any analysis entry point, and an already
    // installed state cannot be removed from an analyzed engine.
    for (initially_synced, analysis) in [
        (true, None),
        (false, Some(Request::Graph { address: caller })),
        (false, Some(Request::Discover)),
        (false, Some(Request::Decompile { address: caller })),
        (true, Some(Request::Decompile { address: caller })),
    ] {
        let (mut worker, info) = fixture.open();
        inventory(&mut worker, &info);
        let saved = vec![fixture.signature(&info, "callee")];
        if initially_synced {
            sync(&mut worker, &info, &saved);
        }
        let removal = initially_synced && analysis.is_some();
        if let Some(analysis) = analysis {
            assert!(!matches!(
                request(&mut worker, analysis),
                Response::Error { .. }
            ));
        }
        let replacement = if removal { &[] } else { saved.as_slice() };
        assert!(
            matches!(request(&mut worker, sync_request(&info, replacement)), Response::Error { message } if message.contains("fresh worker"))
        );
        assert_discarded(&mut worker, caller);
        let reopened = open(&mut worker, &fixture);
        assert_eq!(reopened.sha256, info.sha256);
        inventory(&mut worker, &reopened);
        sync(&mut worker, &reopened, &[]);
        let recovered = decompile(&mut worker, &reopened, fixture.address("callee"), vec![]);
        assert_fingerprint(&recovered, LOCAL_FINGERPRINT);
        assert!(!recovered.text.contains("values_owned"));
        assert!(
            recovered
                .semantics
                .locals
                .iter()
                .all(|v| v.signature_parameter.is_none())
        );
    }
}

#[test]
fn incompatible_saved_fingerprints_are_acknowledged_without_engine_effect() {
    let fixture = Fixture::new();
    let callee = fixture.address("callee");
    let caller = fixture.address("caller");
    let (mut worker, info) = fixture.open();
    inventory(&mut worker, &info);
    sync(&mut worker, &info, &[]);
    let baseline_caller = decompile(&mut worker, &info, caller, vec![]);
    let baseline_callee = decompile(&mut worker, &info, callee, vec![]);
    drop(worker);
    let mut previous_context = None;
    for incompatible_abi in [false, true] {
        let mut saved = fixture.signature(&info, "callee");
        if incompatible_abi {
            saved.abi = "saved-older-abi".into();
        } else {
            saved.engine = "saved-older-engine".into();
        }
        saved.validate().unwrap();
        let saved = vec![saved];
        let mut previous = None;
        // A second fresh worker must recover the same full-state identities,
        // even though this state made no prototype change in either engine.
        for _ in 0..2 {
            let (mut worker, info) = fixture.open();
            inventory(&mut worker, &info);
            assert_ack(
                request(&mut worker, sync_request(&info, &saved)),
                &info,
                &saved,
                &[callee],
            );
            let result = decompile(&mut worker, &info, caller, vec![]);
            assert_eq!(result.text, baseline_caller.text);
            assert_fingerprint(&result, SIGNATURE_LOCAL_FINGERPRINT);
            assert_ne!(identities(&result), identities(&baseline_caller));
            if let Some(previous) = &previous {
                assert_eq!(&identities(&result), previous);
            }
            previous = Some(identities(&result));
            let result = decompile(&mut worker, &info, callee, vec![]);
            assert_eq!(result.text, baseline_callee.text);
            assert_eq!(
                result.semantics.prototype,
                baseline_callee.semantics.prototype
            );
            assert!(
                result
                    .semantics
                    .locals
                    .iter()
                    .all(|v| v.signature_parameter.is_none())
            );
        }
        if let Some(previous_context) = &previous_context {
            assert_ne!(previous.as_ref().unwrap(), previous_context);
        }
        previous_context = previous;
    }
}

#[test]
fn executable_missing_entries_remain_saved_and_unapplied_in_a_mixed_batch() {
    let fixture = Fixture::new();
    let (mut worker, info) = fixture.open();
    inventory(&mut worker, &info);
    let mut missing = fixture.signature(&info, "callee");
    missing.function += 1;
    let mut incompatible = missing.clone();
    incompatible.function += 1;
    incompatible.engine = "saved-older-engine".into();
    for saved in [&missing, &incompatible] {
        assert!(ghidra_rust::call_analysis::code_address(
            &info,
            saved.function
        ));
        assert!(!info.functions.iter().any(|f| f.address == saved.function));
        saved.validate().unwrap();
    }
    let mut valid = fixture.signature(&info, "zero");
    valid.return_type = ty(SignatureBase::U32, 0);
    let saved = vec![missing.clone(), valid.clone(), incompatible.clone()];
    assert_ne!(
        signatures::state_digest(&saved),
        signatures::state_digest(std::slice::from_ref(&valid))
    );
    let response = request(&mut worker, sync_request(&info, &saved));
    let Response::SignaturesSynced { unapplied, .. } = &response else {
        panic!("Missing saved entries must remain replayable: {response:?}");
    };
    assert!(
        unapplied
            .iter()
            .any(|s| s.function == missing.function && s.reason.contains("inventory"))
    );
    assert!(
        unapplied
            .iter()
            .any(|s| s.function == incompatible.function && s.reason.contains("incompatible"))
    );
    assert_ack(
        response,
        &info,
        &saved,
        &[missing.function, incompatible.function],
    );
    let result = decompile(&mut worker, &info, fixture.address("callee"), vec![]);
    assert_fingerprint(&result, SIGNATURE_LOCAL_FINGERPRINT);
    assert!(!result.text.contains("values_owned"));
    assert!(
        result
            .semantics
            .locals
            .iter()
            .all(|v| v.signature_parameter.is_none())
    );
    let Response::Decompiled { semantics, .. } = request(
        &mut worker,
        Request::Decompile {
            address: valid.function,
        },
    ) else {
        panic!("Valid signature in mixed batch must still decompile");
    };
    assert_eq!(
        semantics.prototype.unwrap().return_type,
        Some(valid.return_type)
    );
    let Response::Functions { functions, .. } = request(&mut worker, Request::Discover) else {
        panic!("Mixed saved state must leave worker usable");
    };
    assert!(
        functions
            .iter()
            .all(|f| f.address != missing.function && f.address != incompatible.function),
        "Replay must never invent function entries"
    );
}

// WorkerClient intentionally preflights state digests. This raw protocol peer
// exercises server rejection itself on the original source fixture, like the
// existing worker_process tests. Production client/containment stays unchanged.
struct ProtocolWorker {
    child: Child,
    input: ChildStdin,
    output: Receiver<WorkerResponse>,
    id: u64,
}
impl ProtocolWorker {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_ghidra-rust"))
            .arg("--analysis-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let line = line.unwrap();
                let response = serde_json::from_str(&line).expect("Worker JSON reply");
                if sender.send(response).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output: receiver,
            id: 0,
        }
    }
    fn request(&mut self, request: Request) -> Response {
        self.id += 1;
        serde_json::to_writer(
            &mut self.input,
            &WorkerRequest {
                id: self.id,
                request,
            },
        )
        .unwrap();
        self.input.write_all(b"\n").unwrap();
        self.input.flush().unwrap();
        let response = self
            .output
            .recv_timeout(Duration::from_secs(30))
            .expect("Real protocol worker reply");
        assert_eq!(response.id, self.id);
        response.response
    }
}
impl Drop for ProtocolWorker {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn wrong_binary_digest_or_nonexecutable_entry_fails_closed_at_worker_boundary() {
    let fixture = Fixture::new();
    let mut worker = ProtocolWorker::start();
    for fault in 0..3 {
        let Response::Opened { info } = worker.request(Request::Open {
            path: fixture.binary.to_string_lossy().into_owned(),
        }) else {
            panic!("Open original protocol fixture");
        };
        assert!(matches!(
            worker.request(Request::SyncFunctions {
                functions: info.functions.clone()
            }),
            Response::FunctionsSynced
        ));
        let mut saved = vec![fixture.signature(&info, "callee")];
        if fault == 2 {
            saved[0].function = 0;
        }
        let mut request = sync_request(&info, &saved);
        let Request::SyncSignatures {
            binary_sha256,
            context,
            ..
        } = &mut request
        else {
            unreachable!()
        };
        if fault == 0 {
            *binary_sha256 = if info.sha256 == "0".repeat(64) {
                "1".repeat(64)
            } else {
                "0".repeat(64)
            };
        }
        if fault == 1 {
            *context = signatures::state_digest(&[]);
        }
        assert!(matches!(worker.request(request), Response::Error { .. }));
        for request in [
            Request::Bytes {
                address: fixture.address("callee"),
                length: 1,
            },
            Request::Decompile {
                address: fixture.address("callee"),
            },
        ] {
            assert!(
                matches!(worker.request(request), Response::Error { message } if message == "Open a binary first.")
            );
        }
        // A subsequent Open recovers this same process, but carries no partial
        // prototype state from the rejected batch.
        let Response::Opened { info } = worker.request(Request::Open {
            path: fixture.binary.to_string_lossy().into_owned(),
        }) else {
            panic!("Fresh Open after rejection");
        };
        assert!(matches!(
            worker.request(Request::SyncFunctions {
                functions: info.functions.clone()
            }),
            Response::FunctionsSynced
        ));
        assert_ack(worker.request(sync_request(&info, &[])), &info, &[], &[]);
        let Response::Decompiled {
            text, semantics, ..
        } = worker.request(Request::Decompile {
            address: fixture.address("callee"),
        })
        else {
            panic!("Reopened program must decompile");
        };
        assert!(!text.contains("values_owned"));
        assert!(!semantics.locals.is_empty());
        assert!(
            semantics
                .locals
                .iter()
                .all(|v| v.identity.engine == LOCAL_FINGERPRINT && v.signature_parameter.is_none())
        );
    }
}
