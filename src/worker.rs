//! Newline-delimited JSON protocol. Never write diagnostic text to stdout.
use crate::analysis::LoadedProgram;
use crate::model::{Request, Response, WorkerRequest, WorkerResponse};
use std::io::{self, BufRead, Read, Write};

pub fn run_worker() -> Result<(), String> {
    crate::limits::configure_worker()?;
    protocol(io::stdin().lock(), io::stdout().lock(), true)
}

fn protocol(
    mut input: impl BufRead,
    mut output: impl Write,
    enforce_limits: bool,
) -> Result<(), String> {
    let mut loaded: Option<LoadedProgram> = None;
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
                continue;
            }
        };
        if enforce_limits {
            crate::limits::begin_request()?;
        }
        let request_id = request.id;
        let signature_sync = matches!(request.request, Request::SyncSignatures { .. });
        let _trace_context = crate::performance::context(request_id);
        let execution = crate::performance::span(crate::performance::operation(&request.request));
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request.request {
                Request::Open { path } => {
                    // An unsuccessful replacement must never leave a previous image active.
                    loaded = None;
                    let program = LoadedProgram::open(&path)?;
                    let info = program.info.clone();
                    let symbols = Some(program.symbol_names().clone());
                    loaded = Some(program);
                    Ok(Response::Opened { info, symbols })
                }
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
        execution.finish(0);
        crate::performance::event(
            "request_result_error",
            u64::from(matches!(response, Response::Error { .. })),
        );
        send(
            &mut output,
            WorkerResponse {
                id: request.id,
                response,
            },
        )?;
        crate::performance::event("request_published", request.id);
    }
    Ok(())
}

fn send(output: &mut impl Write, response: WorkerResponse) -> Result<(), String> {
    // Encode atomically into a bounded buffer: an oversized response must not
    // publish a partial JSON line and desynchronize the parent protocol.
    let encoding = crate::performance::span("reply_encode");
    let mut encoded = ResponseBuffer::default();
    if serde_json::to_writer(&mut encoded, &response).is_err() {
        encoded.bytes.clear();
        let fallback = WorkerResponse {
            id: response.id,
            response: Response::Error { message: "Analysis response exceeds the 32 MiB protocol limit; narrow the requested analysis.".into() },
        };
        serde_json::to_writer(&mut encoded, &fallback)
            .map_err(|e| format!("Worker error response encoding failed: {e}"))?;
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
}

impl Write for ResponseBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_RESPONSE_BYTES.saturating_sub(self.bytes.len()) {
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
        protocol(io::Cursor::new(input), &mut output, false).unwrap();
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
                    path: path.to_string_lossy().into_owned(),
                },
            },
            WorkerRequest {
                id: 2,
                request: Request::Open {
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
        protocol(io::Cursor::new(input), &mut output, false).unwrap();
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
            protocol(io::Cursor::new(input), &mut output, false)
                .unwrap_err()
                .contains("Oversized")
        );
        let response: WorkerResponse = serde_json::from_slice(&output).unwrap();
        assert!(matches!(response.response, Response::Error { .. }));
    }

    #[test]
    fn protocol_reports_errors_and_continues_with_matching_ids() {
        let input = concat!(
            "{\"id\":7,\"request\":{\"kind\":\"graph\",\"address\":4096}}\n",
            "{\"id\":8,\"request\":{\"kind\":\"does_not_exist\"}}\n",
            "{\"id\":9,\"request\":{\"kind\":\"open\",\"path\":\"/nonexistent/ghidra-rust-binary\"}}\n",
        );
        let mut output = Vec::new();
        protocol(io::Cursor::new(input), &mut output, false).unwrap();
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
}
