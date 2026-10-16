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
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match request.request {
                Request::Open { path } => {
                    // An unsuccessful replacement must never leave a previous image active.
                    loaded = None;
                    let program = LoadedProgram::open(&path)?;
                    let info = program.info.clone();
                    loaded = Some(program);
                    Ok(Response::Opened { info })
                }
                request => loaded
                    .as_mut()
                    .ok_or_else(|| "Open a binary first.".to_string())?
                    .handle(request),
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
        send(
            &mut output,
            WorkerResponse {
                id: request.id,
                response,
            },
        )?;
    }
    Ok(())
}

fn send(output: &mut impl Write, response: WorkerResponse) -> Result<(), String> {
    // Encode atomically into a bounded buffer: an oversized response must not
    // publish a partial JSON line and desynchronize the parent protocol.
    let mut encoded = ResponseBuffer::default();
    if serde_json::to_writer(&mut encoded, &response).is_err() {
        encoded.bytes.clear();
        let fallback = WorkerResponse {
            id: response.id,
            response: Response::Error { message: "Analysis response exceeds the 12 MiB protocol limit; narrow the requested analysis.".into() },
        };
        serde_json::to_writer(&mut encoded, &fallback)
            .map_err(|e| format!("Worker error response encoding failed: {e}"))?;
    }
    output
        .write_all(&encoded.bytes)
        .map_err(|e| format!("Worker output failed: {e}"))?;
    output
        .write_all(b"\n")
        .and_then(|_| output.flush())
        .map_err(|e| format!("Worker output failed: {e}"))
}

const MAX_RESPONSE_BYTES: usize = 12 * 1024 * 1024;

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

    #[test]
    fn oversized_response_becomes_one_error_line_with_original_id() {
        let response = WorkerResponse {
            id: 42,
            response: Response::Decompiled {
                address: 0x1000,
                mappings: Vec::new(),
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
