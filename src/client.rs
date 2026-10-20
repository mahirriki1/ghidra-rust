//! Disposable worker client. Parsing and blocking reads never run on the GUI thread.
use crate::model::{Request, WorkerRequest, WorkerResponse};
use crate::session::BinaryProtection;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// The worker's largest encoded reply plus its newline.
const MAX_RESPONSE: usize = crate::model::MAX_REPLY_BYTES + 1;

pub enum WorkerEvent {
    Reply(Box<WorkerResponse>),
    Failed(String),
}

pub struct WorkerClient {
    child: Option<Child>,
    #[cfg(windows)]
    _job: crate::windows::WorkerJob,
    input: ChildStdin,
    events: Receiver<WorkerEvent>,
    next_id: u64,
    /// Highest request id written; replies may only answer sent requests.
    sent: Arc<AtomicU64>,
    binary_path: PathBuf,
    protection: BinaryProtection,
    source_lease: Option<Arc<dyn Send + Sync>>,
}

impl WorkerClient {
    pub fn start(ctx: eframe::egui::Context, binary_path: &Path) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        Self::start_using_executable(ctx, binary_path, &exe)
    }

    /// Start with an explicitly trusted copy of this application's executable.
    /// Exposed for integration tests that otherwise run inside Cargo's harness.
    #[doc(hidden)]
    pub fn start_using_executable(
        ctx: eframe::egui::Context,
        binary_path: &Path,
        exe: &Path,
    ) -> Result<Self, String> {
        let protection = BinaryProtection::open(binary_path)?;
        let binary_path = protection.path().to_owned();
        let mut command = worker_command(exe, &binary_path)?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Engine diagnostics may contain untrusted symbol names or terminal
            // control sequences. Structured errors use the bounded JSON channel.
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Cannot start analysis worker: {e}"))?;
        #[cfg(windows)]
        let job = match crate::windows::WorkerJob::assign_and_resume(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Cannot contain Windows analysis worker: {error}"));
            }
        };
        let input = child.stdin.take().ok_or("Worker has no input pipe")?;
        let output = child.stdout.take().ok_or("Worker has no output pipe")?;
        let (sender, events) = mpsc::sync_channel(8);
        let display_path = binary_path.to_string_lossy().into_owned();
        let reader_protection = protection.clone();
        let sent = Arc::new(AtomicU64::new(0));
        let reader_sent = sent.clone();
        std::thread::Builder::new()
            .name("analysis-responses".into())
            .spawn(move || {
                let mut reader = BufReader::new(output);
                let mut answered = 0;
                let mut sections = Vec::new();
                loop {
                    let event = match bounded_line(&mut reader, MAX_RESPONSE).and_then(|line| {
                        match line {
                            Some(line) => {
                                check_reply_order(&line, &reader_sent, &mut answered)?;
                                Ok(Some(line))
                            }
                            None => Ok(None),
                        }
                    }) {
                        Ok(Some(line)) => match serde_json::from_slice::<WorkerResponse>(&line) {
                            Ok(mut reply) => {
                                // The sandbox sees only /input/binary. Keep the
                                // actual user-selected path in the desktop model.
                                if let crate::model::Response::Opened { info } = &mut reply.response
                                {
                                    if let Err(error) = reader_protection.verify_identity(info) {
                                        if sender.send(WorkerEvent::Failed(error)).is_ok() {
                                            ctx.request_repaint();
                                        }
                                        return;
                                    }
                                    info.path.clone_from(&display_path);
                                    sections.clone_from(&info.sections);
                                }
                                if let crate::model::Response::Decompiled {
                                    address,
                                    text,
                                    mappings,
                                    semantics,
                                } = &reply.response
                                {
                                    let checked = if text.len() > crate::model::MAX_DECOMPILED_BYTES
                                    {
                                        Err("Decompiler text exceeds limit".into())
                                    } else {
                                        crate::selection::validate_mappings(
                                            text, mappings, &sections,
                                        )
                                        .and_then(|()| {
                                            semantics.validate(text, *address, &sections)
                                        })
                                        .and_then(|()| {
                                            if semantics.locals.iter().any(|v| {
                                                v.identity.engine
                                                    != crate::semantic::LOCAL_FINGERPRINT
                                            }) {
                                                Err("Incompatible semantic local identity".into())
                                            } else {
                                                Ok(())
                                            }
                                        })
                                    };
                                    if let Err(error) = checked {
                                        if sender
                                            .send(WorkerEvent::Failed(format!(
                                                "Invalid decompiler reply: {error}"
                                            )))
                                            .is_ok()
                                        {
                                            ctx.request_repaint();
                                        }
                                        return;
                                    }
                                }
                                WorkerEvent::Reply(Box::new(reply))
                            }
                            Err(e) => WorkerEvent::Failed(format!("Invalid worker response: {e}")),
                        },
                        Ok(None) => WorkerEvent::Failed(
                            "Analysis worker exited. Reopen the binary to restart it.".into(),
                        ),
                        Err(e) => WorkerEvent::Failed(e),
                    };
                    let failed = matches!(event, WorkerEvent::Failed(_));
                    if sender.send(event).is_err() {
                        return;
                    }
                    ctx.request_repaint();
                    if failed {
                        return;
                    }
                }
            })
            .map_err(|e| {
                let _ = child.kill();
                let _ = child.wait();
                format!("Cannot start response reader: {e}")
            })?;
        Ok(Self {
            child: Some(child),
            #[cfg(windows)]
            _job: job,
            input,
            events,
            next_id: 0,
            sent,
            binary_path,
            protection,
            source_lease: None,
        })
    }

    /// Keep an extracted project image alive until the worker has exited and its
    /// file handles are closed, including during asynchronous process reaping.
    pub fn retain_source(&mut self, source: Arc<dyn Send + Sync>) {
        self.source_lease = Some(source);
    }

    pub fn protection(&self) -> BinaryProtection {
        self.protection.clone()
    }

    pub fn send(&mut self, mut request: Request) -> Result<u64, String> {
        if let Request::Open { path } = &mut request {
            let requested = Path::new(path)
                .canonicalize()
                .map_err(|e| format!("Cannot resolve binary: {e}"))?;
            if requested != self.binary_path {
                return Err("Restart the worker before opening a different binary".into());
            }
            #[cfg(target_os = "linux")]
            {
                *path = "/input/binary".into();
            }
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or("Request counter overflow")?;
        let mut bytes = serde_json::to_vec(&WorkerRequest {
            id: self.next_id,
            request,
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() > 60 * 1024 {
            return Err("Request is too large".into());
        }
        bytes.push(b'\n');
        // Publish before writing so the reader never sees an unsent reply id.
        self.sent.store(self.next_id, Ordering::Release);
        self.input
            .write_all(&bytes)
            .map_err(|e| format!("Worker input failed: {e}"))?;
        self.input.flush().map_err(|e| e.to_string())?;
        Ok(self.next_id)
    }

    pub fn poll(&self) -> Option<WorkerEvent> {
        self.events.try_recv().ok()
    }
}

#[cfg(target_os = "linux")]
fn worker_command(exe: &Path, binary_path: &Path) -> Result<Command, String> {
    let bwrap = ["/usr/bin/bwrap", "/usr/sbin/bwrap"].into_iter()
        .map(Path::new).find(|path| path.is_file())
        .ok_or("Linux analysis requires bubblewrap (bwrap). Install it with your distribution's package manager.")?;
    let mut command = Command::new(bwrap);
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--clearenv",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    // Preserve the host's loader layout: Arch's /lib64 resolves to /usr/lib,
    // whereas Ubuntu's resolves to /usr/lib64. Pointing both at /usr/lib makes
    // an Ubuntu-built worker fail before its first instruction executes.
    for library in ["/lib", "/lib64"] {
        let path = Path::new(library);
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if library == "/lib64" && error.kind() == std::io::ErrorKind::NotFound => {
                continue;
            }
            Err(error) => return Err(format!("Cannot inspect system library directory: {error}")),
        };
        if metadata.file_type().is_symlink() {
            let resolved = path
                .canonicalize()
                .map_err(|error| format!("Cannot resolve {library}: {error}"))?;
            if !resolved.starts_with("/usr") || !resolved.is_dir() {
                return Err(format!(
                    "Linux analysis requires {library} to resolve to a library directory under /usr"
                ));
            }
            // Canonical targets avoid depending on other host symlinks that
            // are deliberately absent from the sandbox's private root.
            command.arg("--symlink").arg(resolved).arg(path);
        } else if metadata.is_dir() {
            command.arg("--ro-bind").arg(path).arg(path);
        } else {
            return Err(format!("System library path is not a directory: {library}"));
        }
    }
    command
        .args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--dir",
            "/app",
            "--dir",
            "/input",
            "--ro-bind",
        ])
        .arg(exe)
        .arg("/app/worker")
        .arg("--ro-bind")
        .arg(binary_path)
        .arg("/input/binary")
        .args(["--chdir", "/", "--", "/app/worker", "--analysis-worker"]);
    Ok(command)
}

#[cfg(not(target_os = "linux"))]
fn worker_command(exe: &Path, _binary_path: &Path) -> Result<Command, String> {
    let mut command = Command::new(exe);
    command.arg("--analysis-worker");
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    }
    Ok(command)
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Reap without making the UI wait for a worker to finish analysis.
            // Keep ownership recoverable if the OS refuses to create a thread.
            let cleanup = Arc::new(Mutex::new(Some((child, self.source_lease.take()))));
            let thread_cleanup = Arc::clone(&cleanup);
            if std::thread::Builder::new()
                .name("worker-cleanup".into())
                .spawn(move || {
                    if let Some((mut child, lease)) = thread_cleanup
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .take()
                    {
                        let _ = child.wait();
                        drop(lease);
                    }
                })
                .is_err()
                && let Some((mut child, lease)) = cleanup
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .take()
            {
                // The child has already been killed. Waiting here is the rare
                // fallback that preserves temporary-image cleanup correctness.
                let _ = child.wait();
                drop(lease);
            }
        }
    }
}

/// Shape-checks a reply before serde buffers it, and admits at most one
/// terminal reply per sent request, in order. Progress replies are small and
/// must belong to an unanswered request. This bounds how many large replies a
/// misbehaving worker can queue.
fn check_reply_order(line: &[u8], sent: &AtomicU64, answered: &mut u64) -> Result<(), String> {
    let shape = crate::bounded::check_reply(line)?;
    if shape.id <= *answered || shape.id > sent.load(Ordering::Acquire) {
        return Err("Worker reply does not answer a pending request".into());
    }
    if shape.kind != "progress" {
        *answered = shape.id;
    }
    Ok(())
}

fn bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    loop {
        let buffer = reader
            .fill_buf()
            .map_err(|e| format!("Worker output failed: {e}"))?;
        if buffer.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err("Truncated worker response".into())
            };
        }
        let end = buffer.iter().position(|&byte| byte == b'\n');
        let count = end.map_or(buffer.len(), |end| end + 1);
        if count > limit.saturating_sub(line.len()) {
            return Err("Worker response exceeded the 32 MiB limit".into());
        }
        line.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_must_answer_sent_requests_once_and_in_order() {
        let sent = AtomicU64::new(2);
        let mut answered = 0;
        let reply = |id: u64, kind: &str| {
            format!(r#"{{"id":{id},"response":{{"kind":"{kind}","message":"x"}}}}"#)
        };
        let progress = |id: u64| {
            format!(
                r#"{{"id":{id},"response":{{"kind":"progress","progress":{{"stage":"Calls","functions_examined":0,"decode_attempts":0}}}}}}"#
            )
        };
        let mut check = |line: String| check_reply_order(line.as_bytes(), &sent, &mut answered);
        assert!(check(progress(1)).is_ok());
        assert!(check(reply(1, "error")).is_ok());
        assert!(check(reply(1, "error")).is_err(), "second terminal reply");
        assert!(check(progress(1)).is_err(), "progress after completion");
        assert!(check(reply(3, "error")).is_err(), "unsent request");
        assert!(check(reply(2, "error")).is_ok());
    }
    #[test]
    fn response_framing_preserves_messages_and_rejects_unbounded_or_partial_output() {
        let mut input = std::io::Cursor::new(b"one\ntwo\n".as_slice());
        assert_eq!(bounded_line(&mut input, 4).unwrap().unwrap(), b"one\n");
        assert_eq!(bounded_line(&mut input, 4).unwrap().unwrap(), b"two\n");
        assert!(bounded_line(&mut input, 4).unwrap().is_none());
        assert!(bounded_line(&mut std::io::Cursor::new(b"12345\n"), 4).is_err());
        assert!(bounded_line(&mut std::io::Cursor::new(b"partial"), 20).is_err());
    }
}
