//! Newline-delimited JSON protocol. Never write diagnostic text to stdout.
use crate::analysis::LoadedProgram;
use crate::model::{Request, Response, WorkerRequest, WorkerResponse};
use std::io::{self, BufRead, BufReader, Read, Write};

/// The worker's role, chosen by its host on the command line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// The long-lived analysis worker.
    Primary,
    /// A disposable sibling for one optional debug render: one Open, then
    /// name and signature replay, then one `RenderDebugOnce`, then exit.
    Peer,
}

/// Exact internal arguments after `--analysis-worker`.
pub const PEER_ARGUMENT: &str = "--debug-peer-once";
pub(crate) const BOUND_ARGUMENT: &str = "--bound-worker-inputs";
/// Treats this worker like one without process isolation (Windows or a
/// threaded worker): no fork for optional or callee work. Hosts pass it
/// only to test the sibling executor on Linux.
pub const NO_FORK_ARGUMENT: &str = "--no-fork";
/// Test hook `--test-debug-fault=KIND@ADDRESS`: the optional debug render
/// of the function at the hexadecimal ADDRESS stalls (`stall`), spins on
/// the CPU (`spin`) or aborts (`abort`) after it has started. With
/// `prepare-exit`, every normal managed preparation of that function exits
/// as at the CPU limit after its ordinary render, before its baseline frame;
/// an inference-only recovery is unaffected. `prepare-exit-always` stops
/// the recovery too. Hosts pass it only from tests, never from project data.
/// Only workers built with the `test-hooks` feature accept it; distributed
/// builds refuse it like any unknown worker argument.
pub const FAULT_ARGUMENT: &str = "--test-debug-fault=";

/// Whether `argument` is one of the internal worker arguments above.
pub fn internal_argument(argument: &std::ffi::OsStr) -> bool {
    argument.to_str().is_some_and(|argument| {
        argument == PEER_ARGUMENT
            || argument == BOUND_ARGUMENT
            || argument == NO_FORK_ARGUMENT
            || argument.starts_with(FAULT_ARGUMENT)
    })
}

pub fn run_worker() -> Result<(), String> {
    run_worker_with(std::iter::empty())
}

/// Runs a worker with the internal arguments that followed
/// `--analysis-worker`; any other argument is refused before startup.
pub fn run_worker_with(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<(), String> {
    let mut role = Role::Primary;
    let mut bound_inputs = false;
    for argument in arguments {
        match argument.to_str() {
            Some(PEER_ARGUMENT) if role == Role::Primary => role = Role::Peer,
            Some(BOUND_ARGUMENT) if !bound_inputs => bound_inputs = true,
            Some(NO_FORK_ARGUMENT) => crate::decompile::disable_isolation(),
            #[cfg(feature = "test-hooks")]
            Some(fault) if fault.starts_with(FAULT_ARGUMENT) => {
                crate::analysis::set_debug_fault(&fault[FAULT_ARGUMENT.len()..])?;
            }
            _ => return Err("Unexpected analysis worker argument".into()),
        }
    }
    if role == Role::Peer {
        // The nonfork executor uses the same deferred-callee policy on
        // Windows and Linux, even when this particular process has one thread.
        crate::decompile::disable_isolation();
    }
    crate::limits::configure_worker()?;
    // A buffer larger than stdin's own makes every read bypass it, so the
    // bytes of a pipelined request are visible to `input_pending`.
    let input = BufReader::with_capacity(256 * 1024, io::stdin().lock());
    protocol(input, io::stdout().lock(), true, role, bound_inputs)
}

/// Whether host input is waiting: a buffered or readable request (or the
/// host closed the pipe). A managed optional render yields to it.
fn input_pending<R>(input: &BufReader<R>, poll_stdin: bool) -> bool {
    if !input.buffer().is_empty() {
        return true;
    }
    #[cfg(unix)]
    if poll_stdin {
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd for the lifetime of the call; a zero
        // timeout never blocks. Errors read as "nothing pending".
        let ready = unsafe { libc::poll(&mut descriptor, 1, 0) };
        return ready > 0 && descriptor.revents != 0;
    }
    #[cfg(not(unix))]
    let _ = poll_stdin;
    false
}

/// Whether `request` is legal for a worker in `role` after `state`.
fn admit(role: Role, request: &Request, peer: &mut PeerState) -> Result<(), String> {
    match (role, request) {
        (Role::Primary, Request::RenderDebugOnce { .. }) => {
            Err("Only a debug peer renders a single debug job".into())
        }
        (Role::Primary, _) => Ok(()),
        (Role::Peer, Request::Open { .. }) if !peer.opened => {
            peer.opened = true;
            Ok(())
        }
        (Role::Peer, Request::SyncFunctions { .. } | Request::Rename { .. })
            if peer.opened && !peer.signatures =>
        {
            Ok(())
        }
        (Role::Peer, Request::SyncSignatures { .. }) if peer.opened && !peer.signatures => {
            peer.signatures = true;
            Ok(())
        }
        (Role::Peer, Request::RenderDebugOnce { .. }) if peer.opened => Ok(()),
        (Role::Peer, _) => Err("Request is not part of a debug peer's replay".into()),
    }
}

#[derive(Default)]
struct PeerState {
    opened: bool,
    signatures: bool,
}

fn protocol<R: Read>(
    mut input: BufReader<R>,
    mut output: impl Write,
    enforce_limits: bool,
    role: Role,
    bound_inputs: bool,
) -> Result<(), String> {
    let mut loaded: Option<LoadedProgram> = None;
    let mut peer = PeerState::default();
    let mut last_id = 0;
    const MAX_REQUEST_BYTES: u64 = 64 * 1024;
    loop {
        let mut line = Vec::new();
        let length = (&mut input)
            .take(MAX_REQUEST_BYTES + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("Worker input failed: {e}"))?;
        if length == 0 {
            break;
        }
        if length as u64 > MAX_REQUEST_BYTES {
            // Stop rather than interpreting the remaining oversized line as another command.
            send(
                &mut output,
                WorkerResponse {
                    id: 0,
                    response: Response::Error {
                        message: "Worker requests are limited to 64 KiB.".into(),
                    },
                },
            )?;
            return Err("Oversized worker request; process stopped.".into());
        }
        if line.last() != Some(&b'\n') {
            return Err("Truncated worker request.".into());
        }
        let request: WorkerRequest = match serde_json::from_slice(&line) {
            Ok(request) => request,
            Err(error) => {
                // Preserve an available id, even when the request body is invalid.
                let id = serde_json::from_slice::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|value| value.get("id").and_then(|id| id.as_u64()))
                    .unwrap_or(0);
                send(
                    &mut output,
                    WorkerResponse {
                        id,
                        response: Response::Error {
                            message: format!("Invalid worker request: {error}"),
                        },
                    },
                )?;
                if role == Role::Peer {
                    return Err("Invalid debug peer request; process stopped.".into());
                }
                continue;
            }
        };
        if request.id <= last_id {
            return Err("Worker request IDs must be nonzero and increasing.".into());
        }
        last_id = request.id;
        if let Err(message) = admit(role, &request.request, &mut peer) {
            send(
                &mut output,
                WorkerResponse {
                    id: request.id,
                    response: Response::Error { message },
                },
            )?;
            if role == Role::Peer {
                return Err("Unexpected debug peer request; process stopped.".into());
            }
            continue;
        }
        // An optional render never replenishes the CPU allowance its
        // prepared request started with, and a peer's replay never
        // replenishes the allowance of its one transaction.
        let replenish = match (&request.request, role) {
            (Request::TryPreparedDebug { .. }, _) => false,
            (Request::Open { .. }, Role::Peer) => true,
            (_, Role::Peer) => false,
            _ => true,
        };
        if enforce_limits && replenish {
            crate::limits::begin_request()?;
        }
        let request_id = request.id;
        let signature_sync = matches!(request.request, Request::SyncSignatures { .. });
        let render_once = matches!(request.request, Request::RenderDebugOnce { .. });
        let _trace_context = crate::performance::context(request_id);
        let execution = crate::performance::span(crate::performance::operation(&request.request));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request.request {
                Request::Open { path, debug } => {
                    // An unsuccessful replacement must never leave a previous image active.
                    loaded = None;
                    let mut program = LoadedProgram::open_with_companion_policy(
                        &path,
                        &debug,
                        role == Role::Primary && !bound_inputs,
                    )?;
                    program.bind_open(request_id);
                    let debug = program.debug_summary().cloned();
                    let info = program.info.clone();
                    let symbols = Some(program.symbol_names().clone());
                    let macho_legacy = program.macho_legacy.clone();
                    loaded = Some(program);
                    Ok(Response::Opened {
                        debug,
                        info,
                        symbols,
                        macho_legacy,
                    })
                }
                Request::TryPreparedDebug { job } => {
                    let ticket = job.ticket;
                    Ok(loaded
                        .as_mut()
                        .ok_or_else(|| "Open a binary first.".to_string())?
                        .try_prepared(
                            job,
                            &mut || input_pending(&input, enforce_limits),
                            &mut |direct| {
                                send(
                                    &mut output,
                                    WorkerResponse {
                                        id: request_id,
                                        response: Response::DebugStarted { ticket, direct },
                                    },
                                )
                            },
                        ))
                }
                Request::RenderDebugOnce { job } => loaded
                    .as_mut()
                    .ok_or_else(|| "Open a binary first.".to_string())?
                    .render_debug_once(job, &mut |ticket, direct| {
                        send(
                            &mut output,
                            WorkerResponse {
                                id: request_id,
                                response: Response::DebugStarted { ticket, direct },
                            },
                        )
                    }),
                request => loaded
                    .as_mut()
                    .ok_or_else(|| "Open a binary first.".to_string())?
                    .handle_with_progress(request, &mut |progress| {
                        send(
                            &mut output,
                            WorkerResponse {
                                id: request_id,
                                response: Response::Progress { progress },
                            },
                        )
                    }),
            }));
        let response = match result {
            Ok(Ok(response)) => response,
            Ok(Err(message)) => Response::Error { message },
            Err(payload) => {
                // A panic can leave the embedded engine inconsistent. Require a fresh Open.
                loaded = None;
                let message = payload
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "unknown engine panic".into());
                Response::Error {
                    message: format!("Analysis panicked; reopen the binary: {message}"),
                }
            }
        };
        // A rejected prototype installation may have mutated engine type locks.
        // No request may observe that worker's partial state.
        if signature_sync && matches!(response, Response::Error { .. }) {
            loaded = None;
        }
        let failed = matches!(response, Response::Error { .. });
        execution.finish(0);
        crate::performance::event("request_result_error", u64::from(failed));
        send(
            &mut output,
            WorkerResponse {
                id: request.id,
                response,
            },
        )?;
        crate::performance::event("request_published", request.id);
        // A peer exits after its one transaction, or after any failure.
        if role == Role::Peer && (render_once || failed) {
            return if failed {
                Err("Debug peer request failed; process stopped.".into())
            } else {
                Ok(())
            };
        }
    }
    Ok(())
}

fn send(output: &mut impl Write, response: WorkerResponse) -> Result<(), String> {
    // Encode atomically into a bounded buffer: an oversized response must not
    // publish a partial JSON line and desynchronize the parent protocol.
    let encoding = crate::performance::span("reply_encode");
    let limit = if matches!(response.response, Response::MemorySearch(..)) {
        crate::model::MAX_MEMORY_SEARCH_REPLY_BYTES - 1
    } else {
        MAX_RESPONSE_BYTES
    };
    let mut encoded = ResponseBuffer {
        limit: Some(limit),
        ..Default::default()
    };
    let response_id = response.id;
    if serde_json::to_writer(&mut encoded, &response).is_err() {
        encoded.bytes.clear();
        let response = if let Response::PreparedDecompile {
            address,
            text,
            mappings,
            semantics,
            ..
        } = response.response
        {
            Response::Decompiled {
                address,
                text,
                mappings,
                semantics,
            }
        } else {
            Response::Error {
                message: format!(
                    "Analysis response exceeds its {limit}-byte protocol limit; narrow the requested analysis."
                ),
            }
        };
        let fallback = WorkerResponse {
            id: response_id,
            response,
        };
        if serde_json::to_writer(&mut encoded, &fallback).is_err() {
            encoded.bytes.clear();
            let fallback = WorkerResponse {
                id: response_id,
                response: Response::Error {
                    message: "Analysis response exceeds its protocol limit.".into(),
                },
            };
            serde_json::to_writer(&mut encoded, &fallback)
                .map_err(|e| format!("Worker error response encoding failed: {e}"))?;
        }
    }
    encoding.finish(encoded.bytes.len() as u64);
    let _writing = crate::performance::span("reply_write_flush");
    output
        .write_all(&encoded.bytes)
        .map_err(|e| format!("Worker output failed: {e}"))?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|e| format!("Worker output failed: {e}"))
}

use crate::model::MAX_REPLY_BYTES as MAX_RESPONSE_BYTES;

#[derive(Default)]
struct ResponseBuffer {
    bytes: Vec<u8>,
    limit: Option<usize>,
}

impl Write for ResponseBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len()
            > self
                .limit
                .unwrap_or(MAX_RESPONSE_BYTES)
                .saturating_sub(self.bytes.len())
        {
            return Err(io::Error::other("Response size limit exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn largest_inventory_and_evidence_fit_the_response_limit() {
        // 32 escaped bytes per name spends the full aggregate name budget.
        let name = format!("{}ab", "\u{1}".repeat(5));
        assert_eq!(json_escaped_len(&name), 32);
        const { assert!(32 * MAX_FUNCTIONS == MAX_FUNCTION_NAME_JSON_BYTES) };
        let functions: Vec<_> = (0..MAX_FUNCTIONS as u64)
            .map(|i| FunctionInfo {
                address: u64::MAX - i,
                name: name.clone(),
            })
            .collect();
        let call = CallReference {
            caller: u64::MAX,
            address: u64::MAX,
            target: u64::MAX,
        };
        let data = DataReference {
            function: u64::MAX,
            address: u64::MAX,
            target: u64::MAX,
            size: u32::MAX,
            access: DataAccess::Write,
            provenance: DataProvenance::InstructionLocal,
        };
        let address = AddressReference {
            function: u64::MAX,
            address: u64::MAX,
            target: u64::MAX,
            provenance: DataProvenance::InstructionLocal,
        };
        let full = |n| usize::MAX - n;
        let analysis = CallAnalysis {
            references: vec![call; MAX_CALL_REFERENCES],
            data: Some(DataAnalysis {
                references: vec![data; MAX_DATA_REFERENCES],
                operations_charged: full(0),
                accesses_examined: full(1),
                unresolved_accesses: full(2),
                omitted_accesses: full(3),
                unsupported_instructions: full(4),
                partial: true,
            }),
            addresses: Some(Box::new(AddressAnalysis {
                references: vec![address; MAX_ADDRESS_REFERENCES],
                candidates_examined: full(10),
                omitted_candidates: full(11),
                unsupported_instructions: full(12),
                partial: true,
            })),
            functions_examined: full(5),
            decode_attempts: full(6),
            unresolved_calls: full(7),
            skipped_fallthrough_calls: full(8),
            failed_functions: full(9),
            partial: true,
        };
        let reply = |response| {
            let mut buffer = ResponseBuffer::default();
            // The client's preflight must admit every maximal valid reply.
            serde_json::to_writer(
                &mut buffer,
                &WorkerResponse {
                    id: u64::MAX,
                    response,
                },
            )
            .is_ok()
                && crate::bounded::check_reply(&buffer.bytes).is_ok()
        };
        assert!(reply(Response::Functions {
            functions: functions.clone(),
            truncated: true,
            analysis,
        }));
        let section = SectionInfo {
            name: "\u{1}".repeat(256),
            address: u64::MAX,
            size: u64::MAX,
            file_offset: u64::MAX,
            file_size: u64::MAX,
            executable: true,
        };
        assert!(reply(Response::Opened {
            debug: Some(crate::debug_info::DebugSummary {
                state: "a".repeat(96),
                functions: crate::model::MAX_FUNCTIONS,
                format: crate::debug_info::DebugFormat::Dwarf,
                status: crate::debug_info::DebugStatus::Partial,
                source: Some(crate::debug_info::companion::DebugSource {
                    path: "x".repeat(4096),
                    uuid: "f".repeat(32),
                    sha256: "f".repeat(64),
                    identity: Some(FileIdentity {
                        device: u64::MAX,
                        inode: u64::MAX,
                        inode_high: u64::MAX
                    }),
                })
            }),
            macho_legacy: Some(crate::model::MachoLegacySections {
                indices: (0..crate::model::MAX_SECTIONS).collect(),
                entry: u64::MAX,
            }),
            info: BinaryInfo {
                path: "\u{1}".repeat(32 * 1024),
                architecture: "AArch64".into(),
                format: "Mach-O".into(),
                entry: u64::MAX,
                file_len: u64::MAX,
                sha256: "f".repeat(64),
                source_identity: Some(FileIdentity {
                    device: u64::MAX,
                    inode: u64::MAX,
                    inode_high: u64::MAX,
                }),
                sections: vec![section; 4096],
                functions,
                functions_truncated: true,
                warnings: vec!["\u{1}".repeat(512); 64],
            },
            symbols: Some(SymbolNameSummary {
                digest: "f".repeat(64),
                records: usize::MAX,
                truncated: true,
            }),
        }));
    }

    #[test]
    fn discovery_progress_keeps_the_request_id_and_one_terminal_reply() {
        let mut binary = tempfile::NamedTempFile::new().unwrap();
        binary
            .write_all(&crate::analysis::tests::elf_fixture())
            .unwrap();
        // Windows analysis intentionally denies concurrent writable handles.
        // Retain automatic path cleanup while closing the fixture's writer.
        let binary = binary.into_temp_path();
        let requests = [
            WorkerRequest {
                id: 1,
                request: Request::Open {
                    debug: Default::default(),
                    path: binary.to_string_lossy().into_owned(),
                },
            },
            WorkerRequest {
                id: 2,
                request: Request::Discover,
            },
            WorkerRequest {
                id: 3,
                request: Request::Bytes {
                    address: 0x402000,
                    length: 1,
                },
            },
        ];
        let input = requests
            .iter()
            .map(|request| format!("{}\n", serde_json::to_string(request).unwrap()))
            .collect::<String>();
        let mut output = Vec::new();
        protocol(
            BufReader::new(io::Cursor::new(input)),
            &mut output,
            false,
            Role::Primary,
            false,
        )
        .unwrap();
        let replies: Vec<WorkerResponse> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert_eq!(replies[0].id, 1);
        assert!(
            matches!(replies[0].response, Response::Opened { .. }),
            "Fixture failed to open: {:?}",
            replies[0].response
        );
        let mut previous = None;
        let mut events = 0;
        let mut terminal = 0;
        for reply in replies.iter().filter(|reply| reply.id == 2) {
            match &reply.response {
                Response::Progress { progress } => {
                    assert_eq!(terminal, 0);
                    progress.validate_after(previous.as_ref()).unwrap();
                    previous = Some(progress.clone());
                    events += 1;
                }
                Response::Functions { analysis, .. } => {
                    terminal += 1;
                    let progress = previous.as_ref().unwrap();
                    assert_eq!(progress.stage, crate::model::AnalysisStage::Publish);
                    assert_eq!(progress.decode_attempts, analysis.decode_attempts);
                    assert_eq!(progress.functions_examined, analysis.functions_examined);
                }
                other => panic!("Unexpected discovery reply: {other:?}"),
            }
        }
        assert_eq!(terminal, 1);
        assert!((3..=crate::model::MAX_ANALYSIS_FUNCTIONS + 3).contains(&events));
        assert_eq!(replies.last().unwrap().id, 3);
        assert!(matches!(
            replies.last().unwrap().response,
            Response::Bytes { .. }
        ));
    }

    #[test]
    fn oversized_response_becomes_one_error_line_with_original_id() {
        let response = WorkerResponse {
            id: 42,
            response: Response::Decompiled {
                address: 0x1000,
                mappings: Vec::new(),
                semantics: Default::default(),
                text: "x".repeat(MAX_RESPONSE_BYTES),
            },
        };
        let mut output = Vec::new();
        send(&mut output, response).unwrap();
        assert!(output.len() < 1024);
        let decoded: WorkerResponse = serde_json::from_slice(&output).unwrap();
        assert_eq!(decoded.id, 42);
        assert!(matches!(decoded.response, Response::Error { .. }));
        assert_eq!(output.iter().filter(|byte| **byte == b'\n').count(), 1);
    }

    #[test]
    fn failed_open_clears_previously_loaded_program() {
        let path =
            std::env::temp_dir().join(format!("ghidra-rust-worker-state-{}", std::process::id()));
        std::fs::write(&path, crate::analysis::tests::elf_fixture()).unwrap();
        let requests = [
            WorkerRequest {
                id: 1,
                request: Request::Open {
                    debug: Default::default(),
                    path: path.to_string_lossy().into_owned(),
                },
            },
            WorkerRequest {
                id: 2,
                request: Request::Open {
                    debug: Default::default(),
                    path: "/nonexistent/ghidra-rust-state-test".into(),
                },
            },
            WorkerRequest {
                id: 3,
                request: Request::Bytes {
                    address: 0x402000,
                    length: 4,
                },
            },
        ];
        let input = requests
            .iter()
            .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
            .collect::<String>();
        let mut output = Vec::new();
        protocol(
            BufReader::new(io::Cursor::new(input)),
            &mut output,
            false,
            Role::Primary,
            false,
        )
        .unwrap();
        let responses: Vec<WorkerResponse> = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert!(matches!(responses[0].response, Response::Opened { .. }));
        assert!(matches!(responses[1].response, Response::Error { .. }));
        assert!(
            matches!(&responses[2].response, Response::Error { message } if message == "Open a binary first.")
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_request_stops_without_unbounded_allocation() {
        let mut output = Vec::new();
        let input = vec![b'x'; 70 * 1024];
        assert!(
            protocol(
                BufReader::new(io::Cursor::new(input)),
                &mut output,
                false,
                Role::Primary,
                false,
            )
            .unwrap_err()
            .contains("Oversized")
        );
        let response: WorkerResponse = serde_json::from_slice(&output).unwrap();
        assert!(matches!(response.response, Response::Error { .. }));
    }

    fn run(role: Role, input: &str) -> (Result<(), String>, Vec<WorkerResponse>) {
        let mut output = Vec::new();
        let result = protocol(
            BufReader::new(io::Cursor::new(input.as_bytes().to_vec())),
            &mut output,
            false,
            role,
            false,
        );
        let replies = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        (result, replies)
    }

    /// A debug peer accepts only Open, then replay, then one render; any
    /// other request ends the process after one error reply. A primary
    /// refuses the peer-only render and continues.
    #[test]
    fn worker_roles_enforce_the_debug_peer_state_machine() {
        let render = r#"{"id":2,"request":{"kind":"render_debug_once","job":{"ticket":{"nonce":1,"logical_id":1,"book_version":1},"address":4096,"remaining_ms":1000,"renames":[],"binding":{"program":"","context":"","baseline":"","facts":""},"target_work":true,"graph_prepared":false,"callees":[],"seed":{"states":[],"large":[]}}}}"#;
        let (result, replies) = run(Role::Primary, &format!("{render}\n"));
        assert!(result.is_ok());
        assert!(
            matches!(&replies[0].response, Response::Error { message } if message.contains("Only a debug peer"))
        );
        // Before Open, analysis and render requests stop a peer.
        for line in [
            render,
            r#"{"id":2,"request":{"kind":"graph","address":4096}}"#,
        ] {
            let (result, replies) = run(Role::Peer, &format!("{line}\n{line}\n"));
            assert!(result.is_err(), "{line}");
            assert_eq!(replies.len(), 1, "the process stops after one error");
            assert!(matches!(replies[0].response, Response::Error { .. }));
        }
        // A malformed line stops a peer instead of being skipped.
        let (result, replies) = run(Role::Peer, "{\n");
        assert!(result.is_err());
        assert_eq!(replies.len(), 1);
    }

    #[test]
    fn pending_input_counts_buffered_requests() {
        let mut input = BufReader::new(io::Cursor::new(b"one\ntwo\n".to_vec()));
        assert!(!input_pending(&input, false));
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        // The second, pipelined request is already buffered.
        assert!(input_pending(&input, false));
        line.clear();
        input.read_line(&mut line).unwrap();
        assert!(!input_pending(&input, false));
    }

    #[test]
    fn protocol_reports_errors_and_continues_with_matching_ids() {
        let input = concat!(
            "{\"id\":7,\"request\":{\"kind\":\"graph\",\"address\":4096}}\n",
            "{\"id\":8,\"request\":{\"kind\":\"does_not_exist\"}}\n",
            "{\"id\":9,\"request\":{\"kind\":\"open\",\"path\":\"/nonexistent/ghidra-rust-binary\"}}\n",
        );
        let mut output = Vec::new();
        protocol(
            BufReader::new(io::Cursor::new(input)),
            &mut output,
            false,
            Role::Primary,
            false,
        )
        .unwrap();
        let responses: Vec<WorkerResponse> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(
            responses.iter().map(|r| r.id).collect::<Vec<_>>(),
            [7, 8, 9]
        );
        assert!(
            responses
                .iter()
                .all(|r| matches!(r.response, Response::Error { .. }))
        );
    }

    /// A distributed worker refuses every fault hook before it starts.
    #[cfg(not(feature = "test-hooks"))]
    #[test]
    fn distributed_worker_rejects_the_fault_hook() {
        for kind in ["stall", "abort", "prepare-exit", "prepare-exit-always"] {
            let argument = format!("{FAULT_ARGUMENT}{kind}@0x1000");
            assert_eq!(
                run_worker_with([std::ffi::OsString::from(argument)]),
                Err("Unexpected analysis worker argument".into())
            );
        }
    }
}
