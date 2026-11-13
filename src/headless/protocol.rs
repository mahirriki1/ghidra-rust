//! Versioned public JSON-lines framing. The internal worker protocol is never
//! exposed directly, and every reply is encoded completely before publication.
use super::{API_VERSION, Analyzer, Command, Error, ErrorCode, Output};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Read, Write};

pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub api_version: u16,
    pub id: u64,
    pub command: Command,
}

#[derive(Serialize)]
struct Reply {
    api_version: u16,
    id: Option<u64>,
    #[serde(flatten)]
    outcome: Outcome,
}
#[derive(Serialize)]
#[serde(untagged)]
enum Outcome {
    Success { result: Output },
    Failure { error: Error },
}

/// One terminal response per frame. IDs must be nonzero and strictly increasing.
/// A malformed bounded frame does not touch analysis. Oversized frames close
/// the stream so their remainder can never be mistaken for a second command.
pub fn serve(
    mut input: impl BufRead,
    mut output: impl Write,
    analyzer: &mut Analyzer,
) -> Result<(), Error> {
    let mut last_id = 0;
    loop {
        let mut line = Vec::new();
        let length = (&mut input)
            .take(MAX_REQUEST_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|e| {
                Error::new(
                    ErrorCode::InvalidRequest,
                    format!("Cannot read API request: {e}"),
                )
            })?;
        if length == 0 {
            return Ok(());
        }
        if length > MAX_REQUEST_BYTES {
            let error = Error::new(
                ErrorCode::InvalidRequest,
                "API request exceeds 64 KiB; stream closed",
            );
            write_reply(&mut output, None, Err(error))?;
            return Err(Error::new(ErrorCode::InvalidRequest, "Oversized API frame"));
        }
        let id = available_id(&line);
        let parsed = parse(&line, last_id);
        let response = match parsed {
            Ok(request) => {
                last_id = request.id;
                analyzer.execute(request.command)
            }
            Err(error) => Err(error),
        };
        write_reply(&mut output, id, response)?;
    }
}

fn parse(line: &[u8], last_id: u64) -> Result<Request, Error> {
    crate::bounded::check_json(line, 4096, 4096)
        .map_err(|e| Error::new(ErrorCode::InvalidRequest, e))?;
    let request: Request = serde_json::from_slice(line)
        .map_err(|e| Error::new(ErrorCode::InvalidRequest, e.to_string()))?;
    if request.api_version != API_VERSION {
        return Err(Error::new(
            ErrorCode::UnsupportedVersion,
            "Unsupported API version; expected 1",
        ));
    }
    if request.id == 0 || request.id <= last_id {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "Request IDs must be nonzero and strictly increasing",
        ));
    }
    Ok(request)
}

fn available_id(line: &[u8]) -> Option<u64> {
    crate::bounded::check_json(line, 4096, 4096).ok()?;
    serde_json::from_slice::<serde_json::Value>(line)
        .ok()?
        .get("id")?
        .as_u64()
}

pub fn write_error(output: &mut impl Write, error: Error) -> Result<(), Error> {
    write_reply(output, None, Err(error))
}

fn write_reply(
    output: &mut impl Write,
    id: Option<u64>,
    result: Result<Output, Error>,
) -> Result<(), Error> {
    let outcome = match result {
        Ok(result) => Outcome::Success { result },
        Err(error) => Outcome::Failure { error },
    };
    let reply = Reply {
        api_version: API_VERSION,
        id,
        outcome,
    };
    let mut buffer = Capped(Vec::new());
    if serde_json::to_writer(&mut buffer, &reply).is_err() {
        buffer.0.clear();
        let reply = Reply {
            api_version: API_VERSION,
            id,
            outcome: Outcome::Failure {
                error: Error::new(
                    ErrorCode::ResponseTooLarge,
                    "API response exceeds the 32 MiB limit",
                ),
            },
        };
        serde_json::to_writer(&mut buffer, &reply)
            .map_err(|e| Error::new(ErrorCode::ResponseTooLarge, e.to_string()))?;
    }
    output
        .write_all(&buffer.0)
        .and_then(|()| output.write_all(b"\n"))
        .and_then(|()| output.flush())
        .map_err(|e| {
            Error::new(
                ErrorCode::InvalidRequest,
                format!("Cannot write API response: {e}"),
            )
        })
}
struct Capped(Vec<u8>);
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > crate::model::MAX_REPLY_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("Response size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_reject_version_replay_unknown_fields_and_path_operations() {
        let frame = |version, id, command| {
            serde_json::to_vec(
                &serde_json::json!({"api_version":version,"id":id,"command":command}),
            )
            .unwrap()
        };
        assert_eq!(
            parse(&frame(2, 1, serde_json::json!({"kind":"info"})), 0)
                .unwrap_err()
                .code,
            ErrorCode::UnsupportedVersion
        );
        for (id, last) in [(0, 0), (1, 1), (1, 2)] {
            assert!(parse(&frame(1, id, serde_json::json!({"kind":"info"})), last).is_err());
        }
        for command in [
            serde_json::json!({"kind":"open","path":"/etc/passwd"}),
            serde_json::json!({"kind":"save_project","path":"/etc/passwd"}),
            serde_json::json!({"kind":"info","unknown":true}),
            serde_json::json!({"kind":"annotations","path":"/etc/passwd"}),
            serde_json::json!({"kind":"discover","path":"/etc/passwd"}),
            serde_json::json!({"kind":"crypto","path":"/etc/passwd"}),
        ] {
            assert!(parse(&frame(1, 3, command), 2).is_err());
        }
        assert_eq!(
            parse(&frame(1, 3, serde_json::json!({"kind":"info"})), 2)
                .unwrap()
                .id,
            3
        );
    }
    #[test]
    fn oversized_outputs_publish_only_one_small_error_frame() {
        let output = Output::Bytes {
            address: 0,
            bytes: vec![255; crate::model::MAX_REPLY_BYTES / 3],
        };
        let mut bytes = Vec::new();
        write_reply(&mut bytes, Some(7), Ok(output)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["id"], 7);
        assert_eq!(value["error"]["code"], "response_too_large");
        assert!(bytes.len() < 1024);
        assert_eq!(bytes.iter().filter(|&&v| v == b'\n').count(), 1);
    }
}
