//! Disposable worker client. Parsing and blocking reads never run on the GUI thread.
use crate::model::{Request, WorkerRequest, WorkerResponse};
use crate::session::BinaryProtection;
use std::io::{BufRead, BufReader, Read, Write};
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

struct EventSender(mpsc::SyncSender<Option<WorkerEvent>>);
impl EventSender {
    fn send(&self, event: WorkerEvent) -> Result<(), mpsc::SendError<Option<WorkerEvent>>> {
        self.0.send(Some(event))
    }
}

struct SentSearch {
    id: u64,
    request: Request,
}

impl SentSearch {
    fn validate(
        &self,
        page: &crate::search::MemorySearchPage,
        sections: &[crate::model::SectionInfo],
        image_len: u64,
        image_hash: &str,
    ) -> Result<(), String> {
        let Request::SearchMemory { binding, .. } = &self.request else {
            return Err("Invalid search context".into());
        };
        if binding.binary_sha256 != image_hash {
            return Err("Search image binding mismatch".into());
        }
        let domain = crate::search::SearchDomain::new(sections, image_len)?;
        let context = domain.request_context(&self.request)?;
        domain.validate_page(&context, page)
    }
}

pub struct WorkerClient {
    child: Option<Child>,
    diagnostics: Arc<Mutex<Diagnostics>>,
    eof: Option<std::time::Instant>,
    eof_reported: bool,
    context: eframe::egui::Context,
    #[cfg(windows)]
    _job: Arc<crate::windows::WorkerJob>,
    input: ChildStdin,
    events: Receiver<Option<WorkerEvent>>,
    next_id: u64,
    /// Highest request id written; replies may only answer sent requests.
    sent: Arc<AtomicU64>,
    binary_path: PathBuf,
    protection: BinaryProtection,
    source_lease: Option<Arc<dyn Send + Sync>>,
    signature_context: Arc<Mutex<String>>,
    sent_search: Arc<Mutex<Option<SentSearch>>>,
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
        let startup = crate::performance::span("worker_start");
        let protection_time = crate::performance::span("binary_protection");
        let protection = BinaryProtection::open(binary_path)?;
        protection_time.finish(0);
        let binary_path = protection.path().to_owned();
        let mut command = worker_command(exe, &binary_path)?;
        let spawning = crate::performance::span("worker_spawn");
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Engine diagnostics may contain untrusted symbol names or terminal
            // control sequences. Structured errors use the bounded JSON channel.
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Cannot start analysis worker: {e}"))?;
        spawning.finish(child.id() as u64);
        #[cfg(windows)]
        let _assigning = crate::performance::span("worker_job_assignment");
        #[cfg(windows)]
        let job = match crate::windows::WorkerJob::assign_and_resume(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Cannot contain Windows analysis worker: {error}"));
            }
        };
        #[cfg(windows)]
        _assigning.finish(0);
        let input = child.stdin.take().ok_or("Worker has no input pipe")?;
        let output = child.stdout.take().ok_or("Worker has no output pipe")?;
        let stderr = child.stderr.take().ok_or("Worker has no diagnostic pipe")?;
        let diagnostics = Arc::new(Mutex::new(Diagnostics::default()));
        let draining = Arc::clone(&diagnostics);
        std::thread::Builder::new()
            .name("analysis-diagnostics".into())
            .spawn(move || {
                drain_diagnostics(stderr, &draining);
            })
            .map_err(|error| {
                let _ = child.kill();
                let _ = child.wait();
                format!("Cannot start diagnostic reader: {error}")
            })?;
        let (sender, events) = mpsc::sync_channel(8);
        let sender = EventSender(sender);
        let display_path = binary_path.to_string_lossy().into_owned();
        let reader_protection = protection.clone();
        let sent = Arc::new(AtomicU64::new(0));
        let reader_sent = sent.clone();
        let signature_context = Arc::new(Mutex::new(String::new()));
        let reader_signature_context = Arc::clone(&signature_context);
        let sent_search: Arc<Mutex<Option<SentSearch>>> = Arc::new(Mutex::new(None));
        let reader_sent_search = Arc::clone(&sent_search);
        let worker_pid = child.id();
        let context = ctx.clone();
        std::thread::Builder::new()
            .name("analysis-responses".into())
            .spawn(move || {
                let _peer = crate::performance::peer(worker_pid as u64);
                let mut reader = BufReader::new(output);
                let mut answered = 0;
                let mut sections = Vec::new();
                let mut binary_sha256 = String::new();
                let mut image_len = 0;
                loop {
                    let event = match bounded_line(&mut reader, MAX_RESPONSE).and_then(|line| {
                        match line {
                            Some(line) => {
                                let _preflight = crate::performance::span("reply_preflight");
                                let request_id =
                                    check_reply_order(&line, &reader_sent, &mut answered)?;
                                Ok(Some((line, request_id)))
                            }
                            None => Ok(None),
                        }
                    }) {
                        Ok(Some((line, request_id))) => {
                            let _trace_context = crate::performance::context(request_id);
                            let parsing = crate::performance::span("reply_parse");
                            let decoded = serde_json::from_slice::<WorkerResponse>(&line);
                            parsing.finish(line.len() as u64);
                            match decoded {
                                Ok(mut reply) => {
                                    let _trace_context = crate::performance::context(reply.id);
                                    let _validation =
                                        crate::performance::span("reply_reader_validation");
                                    // The sandbox sees only /input/binary. Keep the
                                    // actual user-selected path in the desktop model.
                                    if let crate::model::Response::Opened { info, .. } =
                                        &mut reply.response
                                    {
                                        if let Err(error) = reader_protection.verify_identity(info)
                                        {
                                            if sender.send(WorkerEvent::Failed(error)).is_ok() {
                                                ctx.request_repaint();
                                            }
                                            return;
                                        }
                                        info.path.clone_from(&display_path);
                                        sections.clone_from(&info.sections);
                                        binary_sha256.clone_from(&info.sha256);
                                        image_len = info.file_len;
                                    }
                                    if let crate::model::Response::Decompiled {
                                        address,
                                        text,
                                        mappings,
                                        semantics,
                                    } = &reply.response
                                    {
                                        let checked =
                                            if text.len() > crate::model::MAX_DECOMPILED_BYTES {
                                                Err("Decompiler text exceeds limit".into())
                                            } else {
                                                crate::selection::validate_mappings(
                                                    text, mappings, &sections,
                                                )
                                                .and_then(|()| {
                                                    semantics.validate(text, *address, &sections)
                                                })
                                                .and_then(|()| {
                                                    let expected =
                                                        crate::semantic::local_fingerprint(
                                                            &reader_signature_context
                                                                .lock()
                                                                .unwrap_or_else(|e| e.into_inner()),
                                                        );
                                                    if semantics
                                                        .locals
                                                        .iter()
                                                        .any(|v| v.identity.engine != expected)
                                                    {
                                                        Err("Incompatible semantic local identity"
                                                            .into())
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
                                    let search_check = {
                                        let mut sent = reader_sent_search
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner());
                                        if sent.as_ref().is_some_and(|sent| sent.id == reply.id) {
                                            let sent =
                                                sent.take().expect("matched search transport");
                                            match &reply.response {
                                                crate::model::Response::MemorySearch(page) => sent
                                                    .validate(
                                                        page,
                                                        &sections,
                                                        image_len,
                                                        &binary_sha256,
                                                    ),
                                                crate::model::Response::Error { .. } => Ok(()),
                                                _ => {
                                                    Err("Unexpected reply to memory search".into())
                                                }
                                            }
                                        } else if matches!(
                                            reply.response,
                                            crate::model::Response::MemorySearch(..)
                                        ) {
                                            Err("Unsolicited memory search reply".into())
                                        } else {
                                            Ok(())
                                        }
                                    };
                                    if let Err(error) = search_check {
                                        let _ = sender.send(WorkerEvent::Failed(error));
                                        ctx.request_repaint();
                                        return;
                                    }
                                    WorkerEvent::Reply(Box::new(reply))
                                }
                                Err(e) => {
                                    WorkerEvent::Failed(format!("Invalid worker response: {e}"))
                                }
                            }
                        }
                        Ok(None) => {
                            let _ = sender.0.send(None);
                            ctx.request_repaint();
                            return;
                        }
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
        startup.finish(child.id() as u64);
        Ok(Self {
            child: Some(child),
            diagnostics,
            eof: None,
            eof_reported: false,
            context,
            #[cfg(windows)]
            _job: Arc::new(job),
            input,
            events,
            next_id: 0,
            sent,
            binary_path,
            protection,
            source_lease: None,
            signature_context,
            sent_search,
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
        if self.eof.is_some() {
            return Err("Analysis worker output has closed".into());
        }
        let _trace_context = crate::performance::context(self.next_id.saturating_add(1));
        let _sending = crate::performance::span("request_send");
        crate::performance::event(crate::performance::operation(&request), 0);
        let mut next_signature_context = None;
        if let Request::SyncSignatures {
            binary_sha256,
            context,
            signatures,
        } = &request
        {
            crate::signatures::validate_signatures(signatures)?;
            if context != &crate::signatures::state_digest(signatures) || binary_sha256.len() != 64
            {
                return Err("Invalid signature synchronization binding".into());
            }
            next_signature_context = Some(if signatures.is_empty() {
                String::new()
            } else {
                context.clone()
            });
        }
        if let Request::Open { path } = &mut request {
            let requested = Path::new(path)
                .canonicalize()
                .map_err(|e| format!("Cannot resolve binary: {e}"))?;
            if requested != self.binary_path {
                return Err("Restart the worker before opening a different binary".into());
            }
            next_signature_context = Some(String::new());
            #[cfg(target_os = "linux")]
            {
                *path = "/input/binary".into();
            }
        }
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or("Request counter overflow")?;
        let next_search = if let Request::SearchMemory { binding, spec, .. } = &request {
            if !crate::search::valid_digest(&binding.binary_sha256) {
                return Err("Invalid search image digest".into());
            }
            spec.compile()?;
            Some(SentSearch {
                id: self.next_id,
                request: request.clone(),
            })
        } else {
            None
        };
        let mut bytes = serde_json::to_vec(&WorkerRequest {
            id: self.next_id,
            request,
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() > 60 * 1024 {
            return Err("Request is too large".into());
        }
        if let Some(context) = next_signature_context {
            *self
                .signature_context
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = context;
        }
        if let Some(context) = next_search {
            let mut sent = self.sent_search.lock().unwrap_or_else(|e| e.into_inner());
            if sent.is_some() {
                return Err("Memory search page already in flight".into());
            }
            *sent = Some(context);
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

    pub fn poll(&mut self) -> Option<WorkerEvent> {
        if self.eof_reported {
            return None;
        }
        if self.eof.is_none() {
            match self.events.try_recv().ok()? {
                None => self.eof = Some(std::time::Instant::now()),
                Some(event) => return Some(event),
            }
        }
        // Never block the GUI on exit/reaping or stderr drain. A bounded grace
        // admits late status/diagnostics; an unobserved exit remains unknown.
        let status = self
            .child
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten());
        let diagnostics = self.diagnostics.lock().unwrap_or_else(|e| e.into_inner());
        if (status.is_none() || !diagnostics.done)
            && self
                .eof
                .is_some_and(|start| start.elapsed() < std::time::Duration::from_millis(250))
        {
            self.context
                .request_repaint_after(std::time::Duration::from_millis(20));
            return None;
        }
        self.eof_reported = true;
        let message = exit_diagnostic(status, diagnostics.allocation_failed);
        Some(WorkerEvent::Failed(message))
    }

    /// Update jobs call this off the GUI thread before replacing the executable.
    /// Keep the extracted-image lease until the child has actually been reaped.
    pub fn stop_and_wait(mut self) -> Result<(), String> {
        if let Some(mut child) = self.child.take() {
            let killed = child.kill();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if killed.is_ok() && std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    result => {
                        self.child = Some(child);
                        return Err(format!(
                            "Cannot stop and reap the analysis worker for update: {result:?}"
                        ));
                    }
                }
            }
        }
        self.source_lease = None;
        Ok(())
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
            let source_lease = self.source_lease.take();
            #[cfg(windows)]
            let source_lease =
                Some(Arc::new((source_lease, Arc::clone(&self._job))) as Arc<dyn Send + Sync>);
            let cleanup = Arc::new(Mutex::new(Some((child, source_lease))));
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

// Retain classification only, never untrusted engine text or symbol names.
#[derive(Default)]
struct Diagnostics {
    allocation_failed: bool,
    done: bool,
}

fn drain_diagnostics(mut input: impl Read, diagnostics: &Mutex<Diagnostics>) {
    let mut buffer = [0u8; 4096];
    let mut line = Vec::with_capacity(256);
    let mut overflow = false;
    loop {
        let count = match input.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        for &byte in &buffer[..count] {
            if byte == b'\n' {
                if !overflow && allocator_message(&line) {
                    diagnostics
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .allocation_failed = true;
                }
                line.clear();
                overflow = false;
            } else if line.len() < 256 {
                line.push(byte);
            } else {
                overflow = true;
            }
        }
    }
    let mut diagnostics = diagnostics.lock().unwrap_or_else(|e| e.into_inner());
    diagnostics.allocation_failed |= !overflow && allocator_message(&line);
    diagnostics.done = true;
}

fn allocator_message(line: &[u8]) -> bool {
    line.strip_prefix(b"memory allocation of ")
        .and_then(|rest| rest.strip_suffix(b" bytes failed"))
        .is_some_and(|digits| !digits.is_empty() && digits.iter().all(u8::is_ascii_digit))
}

fn exit_diagnostic(status: Option<std::process::ExitStatus>, allocation: bool) -> String {
    let status = status.map_or_else(|| "exit status unknown".into(), |status| status.to_string());
    let hint = if allocation {
        "; allocator failure reported (memory limit may have been reached)"
    } else {
        ""
    };
    format!("Analysis worker exited: {status}{hint}. Reopen the binary to restart it.")
}

/// Shape-checks a reply before serde buffers it, and admits at most one
/// terminal reply per sent request, in order. Progress replies are small and
/// must belong to an unanswered request. This bounds how many large replies a
/// misbehaving worker can queue.
fn check_reply_order(line: &[u8], sent: &AtomicU64, answered: &mut u64) -> Result<u64, String> {
    let preflight = crate::performance::span("reply_preflight_scan");
    let shape = crate::bounded::check_reply(line)?;
    if shape.id <= *answered || shape.id > sent.load(Ordering::Acquire) {
        return Err("Worker reply does not answer a pending request".into());
    }
    preflight.finish(shape.id);
    if shape.kind != "progress" {
        *answered = shape.id;
    }
    Ok(shape.id)
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

    #[cfg(unix)]
    #[test]
    fn idle_eof_schedules_grace_poll_and_delivers_failure_once() {
        let context = eframe::egui::Context::default();
        let delays = Arc::new(Mutex::new(Vec::new()));
        let observed = delays.clone();
        context.set_repaint_observer(move |info| observed.lock().unwrap().push(info.delay));
        let mut child = Command::new("sh")
            .args(["-c", "exec 1>&-; exec sleep 2"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, events) = mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            assert!(
                bounded_line(&mut BufReader::new(output), 1)
                    .unwrap()
                    .is_none()
            );
            sender.send(None).unwrap();
        });
        reader.join().unwrap();
        let path = std::env::current_exe().unwrap();
        let mut client = WorkerClient {
            child: Some(child),
            diagnostics: Arc::new(Mutex::new(Diagnostics::default())),
            eof: None,
            eof_reported: false,
            context,
            input,
            events,
            next_id: 0,
            sent: Arc::new(AtomicU64::new(0)),
            binary_path: path.clone(),
            protection: BinaryProtection::open(&path).unwrap(),
            source_lease: None,
            signature_context: Arc::new(Mutex::new(String::new())),
            sent_search: Arc::new(Mutex::new(None)),
        };
        assert!(client.poll().is_none());
        assert!(
            delays
                .lock()
                .unwrap()
                .contains(&std::time::Duration::from_millis(20))
        );
        // Simulate the scheduled wakeup after the grace, without depending on
        // wall-clock sleeps or unrelated input to drive the client.
        client.eof = Some(std::time::Instant::now() - std::time::Duration::from_millis(300));
        assert!(matches!(client.poll(), Some(WorkerEvent::Failed(_))));
        assert!(client.poll().is_none());
    }

    #[test]
    fn diagnostic_stream_is_bounded_and_never_renders_engine_text() {
        let diagnostic = Mutex::new(Diagnostics::default());
        let mut input = vec![b'x'; 1_000_000];
        input.extend_from_slice(
            b"\n\x1b[31mhostile symbol\nmemory allocation of 2097152 bytes failed\n",
        );
        drain_diagnostics(std::io::Cursor::new(input), &diagnostic);
        let state = diagnostic.lock().unwrap();
        assert!(state.done && state.allocation_failed);
        let text = exit_diagnostic(None, state.allocation_failed);
        assert!(text.contains("unknown") && text.contains("allocator"));
        assert!(!text.contains("hostile") && !text.contains('\x1b'));
        assert!(!allocator_message(
            b"symbol memory allocation of 2 bytes failed"
        ));
        assert!(!allocator_message(b"memory allocation of NaN bytes failed"));
    }

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
