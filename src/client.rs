//! Disposable worker client. Parsing and blocking reads never run on the GUI thread.
pub(crate) mod managed_decompile;
#[doc(hidden)]
pub use managed_decompile::{ManagedStats, stats as managed_stats};

use crate::model::{Request, WorkerRequest, WorkerResponse};
use crate::session::BinaryProtection;
#[cfg(windows)]
use crate::windows::WorkerProcess as Child;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(not(windows))]
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};

/// The worker's largest encoded reply plus its newline.
const MAX_RESPONSE: usize = crate::model::MAX_REPLY_BYTES + 1;
/// The largest encoded request, below the worker's 64 KiB line limit.
const MAX_REQUEST_BYTES: usize = 60 * 1024;

pub enum WorkerEvent {
    Reply(Box<WorkerResponse>),
    Failed(String),
}

type TimedEvent = (std::time::Instant, WorkerEvent);

/// How the last reported [`WorkerEvent::Failed`] arose. Hosts use it to tell
/// a lost process from a rejected reply before both are reported with one
/// public error code; only process loss can justify a recovery attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    /// The worker exited at its CPU limit.
    CpuLimit,
    /// The worker crashed on a fatal signal (Linux; see
    /// [`crate::limits::crash_signal`]).
    Crashed,
    /// The worker exited or closed its output for another reason.
    Exited,
    /// A reply was malformed, unsolicited or failed validation.
    Rejected,
}

/// Why worker output ended inside a frame rather than at a boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Interruption {
    /// End of output after part of a frame.
    Truncated,
    /// Reading the output pipe failed.
    ReadFailed(String),
}

/// One read of worker output by [`bounded_line`].
#[derive(Debug, PartialEq, Eq)]
enum Frame {
    /// A complete, newline-terminated frame.
    Line(Vec<u8>),
    /// Output ended at a frame boundary.
    End,
    /// Output ended inside a frame. Unlike a complete invalid frame this is
    /// a transport loss, classified with the process status at end of output.
    Interrupted(Interruption),
}
struct EventSender(mpsc::SyncSender<Option<TimedEvent>>);
impl EventSender {
    fn send(&self, event: WorkerEvent) -> Result<(), mpsc::SendError<Option<TimedEvent>>> {
        self.0.send(Some((std::time::Instant::now(), event)))
    }
}

/// Which debug companion a worker opens.
enum Companion<'a> {
    /// An explicit companion, or (when enabled) the automatic dSYM lookup.
    Lookup {
        explicit: Option<&'a Path>,
        enabled: bool,
    },
    /// Exactly this companion, or explicitly none: a debug peer reuses its
    /// primary's accepted choice and never looks up a new one.
    Exactly(Option<&'a Path>),
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

#[derive(Clone, Copy)]
enum ReplyPurpose {
    Ordinary,
    Discovery,
    Prepare {
        logical_id: u64,
        address: u64,
        inference_only: bool,
    },
    Debug(crate::analysis::managed::Ticket, bool, u64),
}

impl ReplyPurpose {
    fn for_request(request: &Request) -> Self {
        match request {
            Request::Discover | Request::DiscoverBatch { .. } => Self::Discovery,
            Request::PrepareDecompile {
                logical_id,
                address,
                inference_only,
                ..
            } => Self::Prepare {
                logical_id: *logical_id,
                address: *address,
                inference_only: *inference_only,
            },
            Request::TryPreparedDebug { job } | Request::RenderDebugOnce { job } => {
                Self::Debug(job.ticket, job.target_work, job.address)
            }
            _ => Self::Ordinary,
        }
    }

    fn admits(self, response: &crate::model::Response, started: bool) -> bool {
        use crate::model::Response;
        match response {
            Response::Progress { .. } => matches!(self, Self::Discovery),
            Response::PreparedDecompile { address, offer, .. } => {
                matches!(self, Self::Prepare { logical_id, address: sent, inference_only: false }
                    if sent == *address && logical_id == offer.logical_id)
            }
            Response::DebugStarted { ticket, direct } => {
                !started
                    && matches!(self, Self::Debug(sent, expected, _) if sent == *ticket && expected == *direct)
            }
            Response::DebugFinished { ticket, .. } => {
                started && matches!(self, Self::Debug(sent, _, _) if sent == *ticket)
            }
            Response::DebugUnavailable { ticket, .. } => {
                matches!(self, Self::Debug(sent, _, _) if sent == *ticket)
            }
            Response::Error { .. } => true,
            Response::Decompiled {
                address, semantics, ..
            } if let Self::Prepare {
                address: sent,
                inference_only,
                ..
            } = self =>
            {
                // A recovery renders ordinary inference only; a debug
                // prototype there was never checked by the managed client.
                sent == *address
                    && (!inference_only
                        || semantics.prototype_source == crate::semantic::PrototypeSource::Inferred)
            }
            _ => !matches!(self, Self::Debug(..) | Self::Prepare { .. }),
        }
    }
}

struct SentReply {
    id: u64,
    purpose: ReplyPurpose,
    signature_context: String,
    started: bool,
}

type SentReplies = Arc<Mutex<std::collections::VecDeque<SentReply>>>;

fn admit_reply(
    queue: &SentReplies,
    reply: &WorkerResponse,
) -> Result<(String, ReplyPurpose), String> {
    use crate::model::Response;
    let mut queue = queue.lock().unwrap_or_else(|e| e.into_inner());
    let pending = queue.front_mut().ok_or("Unsolicited worker reply")?;
    if pending.id != reply.id || !pending.purpose.admits(&reply.response, pending.started) {
        return Err("Worker reply does not match its sent request".into());
    }
    let purpose = pending.purpose;
    match reply.response {
        Response::DebugStarted { .. } => {
            pending.started = true;
            Ok((String::new(), purpose))
        }
        Response::Progress { .. } => Ok((String::new(), purpose)),
        _ => Ok((
            queue.pop_front().expect("matched reply").signature_context,
            purpose,
        )),
    }
}

enum WorkerInput {
    #[cfg(all(test, unix))]
    Direct(std::process::ChildStdin),
    Queued(mpsc::SyncSender<Vec<u8>>),
}

impl WorkerInput {
    fn write(&mut self, bytes: Vec<u8>) -> Result<(), String> {
        match self {
            #[cfg(all(test, unix))]
            Self::Direct(input) => input
                .write_all(&bytes)
                .and_then(|()| input.flush())
                .map_err(|error| format!("Worker input failed: {error}")),
            Self::Queued(writer) => writer
                .try_send(bytes)
                .map_err(|error| format!("Worker input failed: {error}")),
        }
    }
}

pub struct WorkerClient {
    child: Option<Child>,
    diagnostics: Arc<Mutex<Diagnostics>>,
    eof: Option<std::time::Instant>,
    eof_reported: bool,
    failure: Option<FailureKind>,
    /// Set by the reader when output ended inside a frame.
    interrupted: Arc<Mutex<Option<Interruption>>>,
    context: eframe::egui::Context,
    input: WorkerInput,
    events: Receiver<Option<TimedEvent>>,
    next_id: u64,
    /// Highest request id written; replies may only answer sent requests.
    sent: Arc<AtomicU64>,
    sent_replies: SentReplies,
    peer_slot: managed_decompile::PeerSlot,
    pub(crate) managed_program: Option<String>,
    pub(crate) managed_revision: u64,
    cached_reply: Option<TimedEvent>,
    binary_path: PathBuf,
    companion_path: Option<PathBuf>,
    accepted_companion: Arc<Mutex<Option<crate::debug_info::companion::DebugSource>>>,
    /// The trusted executable and internal arguments this worker runs; a
    /// debug peer starts from the same.
    exe: PathBuf,
    worker_args: Vec<std::ffi::OsString>,
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
        Self::start_using_executable_and_debug(ctx, binary_path, exe, None)
    }

    pub fn start_with_debug_info(
        ctx: eframe::egui::Context,
        binary_path: &Path,
        debug_path: Option<&Path>,
    ) -> Result<Self, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        Self::start_using_executable_and_debug(ctx, binary_path, &exe, debug_path)
    }

    pub fn start_using_executable_and_debug(
        ctx: eframe::egui::Context,
        binary_path: &Path,
        exe: &Path,
        debug_path: Option<&Path>,
    ) -> Result<Self, String> {
        Self::start_using_executable_options(ctx, binary_path, exe, debug_path, true)
    }

    pub(crate) fn start_using_executable_options(
        ctx: eframe::egui::Context,
        binary_path: &Path,
        exe: &Path,
        debug_path: Option<&Path>,
        enabled: bool,
    ) -> Result<Self, String> {
        Self::start_configured(
            ctx,
            binary_path,
            exe,
            Companion::Lookup {
                explicit: debug_path,
                enabled,
            },
            Vec::new(),
        )
    }

    /// [`Self::start_using_executable_options`] with internal worker
    /// arguments (host-test-only executor controls; see
    /// [`crate::worker::NO_FORK_ARGUMENT`]). Their debug peers inherit them.
    #[doc(hidden)]
    pub fn start_with_worker_arguments(
        ctx: eframe::egui::Context,
        binary_path: &Path,
        exe: &Path,
        debug_path: Option<&Path>,
        enabled: bool,
        arguments: Vec<std::ffi::OsString>,
    ) -> Result<Self, String> {
        Self::start_configured(
            ctx,
            binary_path,
            exe,
            Companion::Lookup {
                explicit: debug_path,
                enabled,
            },
            arguments,
        )
    }

    /// A single-use debug peer of the worker described by `launch`: the same
    /// executable, image path and exact companion (or none), never a new
    /// automatic lookup.
    pub(crate) fn start_peer(launch: &managed_decompile::PeerLaunch) -> Result<Self, String> {
        let mut arguments = vec![std::ffi::OsString::from(crate::worker::PEER_ARGUMENT)];
        arguments.extend(launch.worker_args.iter().cloned());
        let mut client = Self::start_configured(
            eframe::egui::Context::default(),
            &launch.binary,
            &launch.exe,
            Companion::Exactly(
                launch
                    .companion
                    .as_ref()
                    .map(|source| Path::new(&source.path)),
            ),
            arguments,
        )?;
        client.worker_args = launch.worker_args.clone();
        if let Some(lease) = &launch.lease {
            client.retain_source(Arc::clone(lease));
        }
        Ok(client)
    }

    /// What a debug peer of this worker starts from.
    pub(crate) fn peer_launch(&self) -> managed_decompile::PeerLaunch {
        managed_decompile::PeerLaunch {
            exe: self.exe.clone(),
            binary: self.binary_path.clone(),
            companion: self
                .accepted_companion
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            protection: self.protection.clone(),
            lease: self.source_lease.clone(),
            worker_args: self.worker_args.clone(),
            slot: self.peer_slot.clone(),
        }
    }

    fn start_configured(
        ctx: eframe::egui::Context,
        binary_path: &Path,
        exe: &Path,
        choice: Companion<'_>,
        worker_args: Vec<std::ffi::OsString>,
    ) -> Result<Self, String> {
        let startup = crate::performance::span("worker_start");
        let protection_time = crate::performance::span("binary_protection");
        let protection = BinaryProtection::open(binary_path)?;
        protection_time.finish(0);
        let binary_path = protection.path().to_owned();
        let (candidate, required) = match choice {
            Companion::Lookup { explicit, enabled } => (
                if enabled {
                    explicit
                        .map(Path::to_path_buf)
                        .or_else(|| crate::debug_info::companion::automatic(&binary_path))
                } else {
                    None
                },
                explicit.is_some(),
            ),
            Companion::Exactly(path) => (path.map(Path::to_path_buf), true),
        };
        let companion = match candidate
            .as_ref()
            .map(|path| crate::debug_info::companion_path::prepare(path))
        {
            Some(Ok(prepared)) => Some(prepared),
            Some(Err(error)) if required => return Err(error),
            _ => None,
        };
        let mut launch_args = worker_args.clone();
        launch_args.push(crate::worker::BOUND_ARGUMENT.into());
        let command = worker_command(exe, &binary_path, companion.as_ref(), &launch_args)?;
        let spawning = crate::performance::span("worker_spawn");
        let mut child =
            spawn_worker(command).map_err(|e| format!("Cannot start analysis worker: {e}"))?;
        spawning.finish(child.id() as u64);
        let (Some(mut input), Some(output), Some(stderr)) =
            (child.stdin.take(), child.stdout.take(), child.stderr.take())
        else {
            let _ = kill_worker(&mut child);
            let _ = child.wait();
            return Err("Worker is missing a protocol or diagnostic pipe".into());
        };
        // A blocked input pipe cannot stop navigation or delay a deadline.
        // The sent-order queue bounds both physical exchanges and queued writes.
        let (writer, requests) = mpsc::sync_channel::<Vec<u8>>(32);
        std::thread::Builder::new()
            .name("analysis-requests".into())
            .spawn(move || {
                for bytes in requests {
                    if input
                        .write_all(&bytes)
                        .and_then(|()| input.flush())
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .map_err(|error| {
                let _ = kill_worker(&mut child);
                let _ = child.wait();
                format!("Cannot start analysis request writer: {error}")
            })?;
        let input = WorkerInput::Queued(writer);
        let diagnostics = Arc::new(Mutex::new(Diagnostics::default()));
        let draining = Arc::clone(&diagnostics);
        std::thread::Builder::new()
            .name("analysis-diagnostics".into())
            .spawn(move || {
                drain_diagnostics(stderr, &draining);
            })
            .map_err(|error| {
                let _ = kill_worker(&mut child);
                let _ = child.wait();
                format!("Cannot start diagnostic reader: {error}")
            })?;
        let (sender, events) = mpsc::sync_channel(8);
        let sender = EventSender(sender);
        let display_path = binary_path.to_string_lossy().into_owned();
        let companion_path = companion.as_ref().map(|p| p.path.clone());
        let display_debug_path = companion_path.clone();
        let companion_file = companion.map(|p| p.file);
        let reader_protection = protection.clone();
        let accepted_companion = Arc::new(Mutex::new(None));
        let reader_companion = Arc::clone(&accepted_companion);
        let sent = Arc::new(AtomicU64::new(0));
        let reader_sent = sent.clone();
        let signature_context = Arc::new(Mutex::new(String::new()));
        let sent_replies = SentReplies::default();
        let reader_sent_replies = Arc::clone(&sent_replies);
        let sent_search: Arc<Mutex<Option<SentSearch>>> = Arc::new(Mutex::new(None));
        let reader_sent_search = Arc::clone(&sent_search);
        let interrupted = Arc::new(Mutex::new(None));
        let reader_interrupted = Arc::clone(&interrupted);
        let worker_pid = child.id();
        let exe = exe.to_owned();
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
                            Frame::Line(line) => {
                                let _preflight = crate::performance::span("reply_preflight");
                                let request_id =
                                    check_reply_order(&line, &reader_sent, &mut answered)?;
                                Ok(Some((line, request_id)))
                            }
                            Frame::End => Ok(None),
                            Frame::Interrupted(interruption) => {
                                *reader_interrupted.lock().unwrap_or_else(|e| e.into_inner()) =
                                    Some(interruption);
                                Ok(None)
                            }
                        }
                    }) {
                        Ok(Some((line, request_id))) => {
                            let _trace_context = crate::performance::context(request_id);
                            let parsing = crate::performance::span("reply_parse");
                            let decoded = serde_json::from_slice::<WorkerResponse>(&line);
                            parsing.finish(line.len() as u64);
                            match decoded {
                                Ok(mut reply) => {
                                    let (signature_context, purpose) =
                                        match admit_reply(&reader_sent_replies, &reply) {
                                            Ok(context) => context,
                                            Err(error) => {
                                                let _ = sender.send(WorkerEvent::Failed(error));
                                                ctx.request_repaint();
                                                return;
                                            }
                                        };
                                    let _trace_context = crate::performance::context(reply.id);
                                    let _validation =
                                        crate::performance::span("reply_reader_validation");
                                    // The sandbox sees only /input/binary. Keep the
                                    // actual user-selected path in the desktop model.
                                    if let crate::model::Response::Opened { info, debug, .. } =
                                        &mut reply.response
                                    {
                                        if let Some(debug) = debug
                                            && let Err(error) = debug.validate()
                                        {
                                            let _ = sender.send(WorkerEvent::Failed(error));
                                            ctx.request_repaint();
                                            return;
                                        }
                                        if let Err(error) = reader_protection.verify_identity(info)
                                        {
                                            if sender.send(WorkerEvent::Failed(error)).is_ok() {
                                                ctx.request_repaint();
                                            }
                                            return;
                                        }
                                        let mut accepted =
                                            debug.as_mut().and_then(|d| d.source.as_mut());
                                        if let Some(source) = accepted.as_deref_mut() {
                                            let checked = display_debug_path
                                                .as_ref()
                                                .zip(companion_file.as_deref())
                                                .ok_or_else(|| {
                                                    "Companion descriptor is missing".to_string()
                                                })
                                                .and_then(|(path, file)| {
                                                    source.path =
                                                        path.to_string_lossy().into_owned();
                                                    reader_protection
                                                        .retain_debug_file(source, file)
                                                });
                                            if let Err(error) = checked {
                                                let _ = sender.send(WorkerEvent::Failed(error));
                                                ctx.request_repaint();
                                                return;
                                            }
                                        }
                                        *reader_companion
                                            .lock()
                                            .unwrap_or_else(|e| e.into_inner()) = accepted.cloned();
                                        info.path.clone_from(&display_path);
                                        sections.clone_from(&info.sections);
                                        binary_sha256.clone_from(&info.sha256);
                                        image_len = info.file_len;
                                    }
                                    let code = match &reply.response {
                                        crate::model::Response::Decompiled {
                                            address,
                                            text,
                                            mappings,
                                            semantics,
                                        } => Some((*address, text, mappings, semantics)),
                                        crate::model::Response::PreparedDecompile {
                                            address,
                                            text,
                                            mappings,
                                            semantics,
                                            ..
                                        } => Some((*address, text, mappings, semantics)),
                                        crate::model::Response::DebugFinished {
                                            outcome, ..
                                        } => match (&outcome.0, purpose) {
                                            (
                                                crate::analysis::DebugOutcome::Candidate {
                                                    render,
                                                    ..
                                                },
                                                ReplyPurpose::Debug(_, _, address),
                                            ) => Some((
                                                address,
                                                &render.text,
                                                &render.mappings,
                                                &render.semantics,
                                            )),
                                            _ => None,
                                        },
                                        _ => None,
                                    };
                                    if let Some((address, text, mappings, semantics)) = code {
                                        let checked = managed_decompile::check_code(
                                            address,
                                            text,
                                            mappings,
                                            semantics,
                                            &sections,
                                            &signature_context,
                                        );
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
                let _ = kill_worker(&mut child);
                let _ = child.wait();
                format!("Cannot start response reader: {e}")
            })?;
        startup.finish(child.id() as u64);
        Ok(Self {
            child: Some(child),
            diagnostics,
            eof: None,
            eof_reported: false,
            failure: None,
            interrupted,
            context,
            input,
            events,
            next_id: 0,
            sent,
            sent_replies,
            peer_slot: managed_decompile::PeerSlot::default(),
            managed_program: None,
            managed_revision: 0,
            cached_reply: None,
            binary_path,
            companion_path,
            accepted_companion,
            exe,
            worker_args,
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
        if let Request::Open { path, debug } = &mut request {
            debug.companion_path = self
                .companion_path
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned());
            if Path::new(path) != self.binary_path
                && Path::new(path)
                    .canonicalize()
                    .map_err(|e| format!("Cannot resolve binary: {e}"))?
                    != self.binary_path
            {
                return Err("Restart the worker before opening a different binary".into());
            }
            next_signature_context = Some(String::new());
            #[cfg(target_os = "linux")]
            {
                *path = "/input/binary".into();
                debug.companion_path = (debug.enabled && self.companion_path.is_some())
                    .then(|| "/input/debug.dwarf".into());
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
        let purpose = ReplyPurpose::for_request(&request);
        let changes_program = request.changes_managed_program();
        let mut bytes = serde_json::to_vec(&WorkerRequest {
            id: self.next_id,
            request,
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_REQUEST_BYTES {
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
        {
            let mut replies = self.sent_replies.lock().unwrap_or_else(|e| e.into_inner());
            if replies.len() >= 32 {
                return Err("Too many worker requests in flight".into());
            }
            replies.push_back(SentReply {
                id: self.next_id,
                purpose,
                signature_context: self
                    .signature_context
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
                started: false,
            });
        }
        bytes.push(b'\n');
        // Publish before writing so the reader never sees an unsent reply id.
        self.sent.store(self.next_id, Ordering::Release);
        self.input.write(bytes)?;
        if changes_program {
            self.managed_program = None;
            self.managed_revision = self.next_id;
        }
        Ok(self.next_id)
    }

    pub(crate) fn can_queue_verified_result(&self) -> bool {
        self.eof.is_none()
            && self.cached_reply.is_none()
            && self
                .sent_replies
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
    }

    /// Sends a verified host-cache hit through the normal presentation path.
    pub(crate) fn queue_verified_result(
        &mut self,
        response: crate::model::Response,
    ) -> Result<u64, String> {
        self.next_id = self
            .next_id
            .checked_add(1)
            .ok_or("Request counter overflow")?;
        self.cached_reply = Some((
            std::time::Instant::now(),
            WorkerEvent::Reply(Box::new(WorkerResponse {
                id: self.next_id,
                response,
            })),
        ));
        self.context.request_repaint();
        Ok(self.next_id)
    }

    /// How the last reported failure arose, once one has been polled.
    pub(crate) fn failure(&self) -> Option<FailureKind> {
        self.failure
    }

    pub fn poll(&mut self) -> Option<WorkerEvent> {
        self.poll_timed().map(|(_, event)| event)
    }

    pub(crate) fn poll_timed(&mut self) -> Option<TimedEvent> {
        if let Some(reply) = self.cached_reply.take() {
            return Some(reply);
        }
        if self.eof_reported {
            return None;
        }
        if self.eof.is_none() {
            match self.events.try_recv().ok()? {
                None => self.eof = Some(std::time::Instant::now()),
                Some(event) => {
                    if matches!(event.1, WorkerEvent::Failed(_)) {
                        self.failure = Some(FailureKind::Rejected);
                    }
                    return Some(event);
                }
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
        let interrupted = self
            .interrupted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let (kind, message) = end_failure(status, interrupted, diagnostics.allocation_failed);
        self.failure = Some(kind);
        Some((std::time::Instant::now(), WorkerEvent::Failed(message)))
    }

    /// Update jobs call this off the GUI thread before replacing the executable.
    /// Keep the extracted-image lease until the child has actually been reaped.
    pub fn stop_and_wait(mut self) -> Result<(), String> {
        self.peer_slot.stop_and_wait()?;
        if let Some(mut child) = self.child.take() {
            let killed = kill_worker(&mut child);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if killed.is_ok() && std::time::Instant::now() < deadline => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
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

/// Spawns bwrap from one thread that lives as long as the process. Its
/// `--die-with-parent` is `PR_SET_PDEATHSIG`, which fires when the spawning
/// *thread* exits; desktop file jobs start workers from short-lived threads,
/// whose exit would orphan the sandbox. Fails closed if that thread cannot
/// run, rather than spawning without the guarantee.
#[cfg(target_os = "linux")]
fn spawn_worker(command: Command) -> std::io::Result<Child> {
    type Job = (Command, mpsc::SyncSender<std::io::Result<Child>>);
    static SPAWNER: std::sync::OnceLock<Option<mpsc::Sender<Job>>> = std::sync::OnceLock::new();
    let stopped = || std::io::Error::other("worker spawner thread is unavailable");
    let spawner = SPAWNER
        .get_or_init(|| {
            let (sender, jobs) = mpsc::channel::<Job>();
            std::thread::Builder::new()
                .name("worker-spawner".into())
                .spawn(move || {
                    for (command, reply) in jobs {
                        let _ = reply.send(spawn_with_pipes(command));
                    }
                })
                .ok()
                .map(|_| sender)
        })
        .as_ref()
        .ok_or_else(stopped)?;
    let (reply, result) = mpsc::sync_channel(1);
    spawner.send((command, reply)).map_err(|_| stopped())?;
    result.recv().map_err(|_| stopped())?
}

#[cfg(all(not(target_os = "linux"), not(windows)))]
fn spawn_worker(command: Command) -> std::io::Result<Child> {
    spawn_with_pipes(command)
}

#[cfg(windows)]
fn spawn_worker(command: Command) -> std::io::Result<Child> {
    Child::spawn(Path::new(command.get_program()), command.get_args())
}

#[cfg(not(windows))]
fn spawn_with_pipes(mut command: Command) -> std::io::Result<Child> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Treat engine diagnostics like other untrusted input.
        .stderr(Stdio::piped())
        .spawn()
}

/// Kills a worker. On Linux bwrap leads its own process group, which its
/// namespace init shares until the sandbox is set up; killing only bwrap
/// during that setup would leave the init waiting forever for bwrap's
/// release, outside `--die-with-parent`. Kill the whole group while bwrap is
/// unreaped, so its pid (and so the group id) cannot have been reused.
fn kill_worker(child: &mut Child) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    if matches!(child.try_wait(), Ok(None))
        && let Ok(group) = libc::pid_t::try_from(child.id())
    {
        // SAFETY: kill only sends a signal. `group` is the id of the group
        // this unreaped child created at spawn (`process_group(0)`).
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
    child.kill()
}

#[cfg(target_os = "linux")]
fn worker_command(
    exe: &Path,
    binary_path: &Path,
    companion: Option<&crate::debug_info::companion_path::Prepared>,
    worker_args: &[std::ffi::OsString],
) -> Result<Command, String> {
    let bwrap = ["/usr/bin/bwrap", "/usr/sbin/bwrap"].into_iter()
        .map(Path::new).find(|path| path.is_file())
        .ok_or("Linux analysis requires bubblewrap (bwrap). Install it with your distribution's package manager.")?;
    let mut command = Command::new(bwrap);
    {
        use std::os::unix::process::CommandExt;
        // A group of its own, so `kill_worker` reaches a sandbox in setup.
        command.process_group(0);
    }
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
        .arg("/input/binary");
    if let Some(companion) = companion {
        use std::os::{fd::AsRawFd, unix::process::CommandExt};
        let fd = companion.file.as_raw_fd();
        command
            .arg("--ro-bind")
            .arg(format!("/proc/self/fd/{fd}"))
            .arg("/input/debug.dwarf");
        // SAFETY: only the async-signal-safe fcntl syscall runs after fork.
        // The live Prepared file remains owned through spawn; inheriting this
        // one read-only descriptor lets bwrap bind the already-opened inode.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    command.args(["--chdir", "/", "--", "/app/worker", "--analysis-worker"]);
    command.args(worker_args);
    Ok(command)
}

#[cfg(not(target_os = "linux"))]
fn worker_command(
    exe: &Path,
    _binary_path: &Path,
    _companion: Option<&crate::debug_info::companion_path::Prepared>,
    worker_args: &[std::ffi::OsString],
) -> Result<Command, String> {
    let mut command = Command::new(exe);
    command.arg("--analysis-worker").args(worker_args);
    Ok(command)
}

impl Drop for WorkerClient {
    fn drop(&mut self) {
        self.peer_slot.cancel();
        if let Some(mut child) = self.child.take() {
            let _ = kill_worker(&mut child);
            // Reap without making the UI wait for a worker to finish analysis.
            // Keep ownership recoverable if the OS refuses to create a thread.
            let source_lease = self.source_lease.take();
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

/// Classifies the end of worker output after the exit grace. Output that
/// ended at a frame boundary, or whose read failed, is process loss. Output
/// that ended inside a frame is process loss once the exit is confirmed;
/// otherwise the worker closed its output mid-reply and the reply is rejected.
fn end_failure(
    status: Option<std::process::ExitStatus>,
    interrupted: Option<Interruption>,
    allocation: bool,
) -> (FailureKind, String) {
    if interrupted == Some(Interruption::Truncated) && status.is_none() {
        return (FailureKind::Rejected, "Truncated worker response".into());
    }
    let kind = match status.as_ref() {
        Some(status) if crate::limits::cpu_limit_stop(status) => FailureKind::CpuLimit,
        Some(status) if crate::limits::crash_signal(status).is_some() => FailureKind::Crashed,
        _ => FailureKind::Exited,
    };
    (
        kind,
        exit_diagnostic(status, allocation, interrupted.as_ref()),
    )
}

fn exit_diagnostic(
    status: Option<std::process::ExitStatus>,
    allocation: bool,
    interrupted: Option<&Interruption>,
) -> String {
    let cpu = status.as_ref().is_some_and(crate::limits::cpu_limit_stop);
    let crash = status.as_ref().and_then(crate::limits::crash_signal);
    let status = status.map_or_else(|| "exit status unknown".into(), |status| status.to_string());
    let crashed;
    let hint = if cpu {
        "; CPU time limit reached"
    } else if let Some(signal) = crash {
        crashed = format!("; crashed ({signal})");
        &crashed
    } else if allocation {
        "; allocator failure reported (memory limit may have been reached)"
    } else {
        ""
    };
    let cut = match interrupted {
        None => String::new(),
        Some(Interruption::Truncated) => "; a reply was cut off".into(),
        Some(Interruption::ReadFailed(error)) => format!("; worker output failed: {error}"),
    };
    format!("Analysis worker exited: {status}{hint}{cut}. Reopen the binary to restart it.")
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
    // Progress and a debug peer's start notice never complete a request.
    if shape.kind != "progress" && shape.kind != "debug_started" {
        *answered = shape.id;
    }
    Ok(shape.id)
}

/// Reads one frame of at most `limit` bytes. An oversized frame is an
/// error (a rejected reply); output that ends early is [`Frame::Interrupted`].
fn bounded_line(reader: &mut impl BufRead, limit: usize) -> Result<Frame, String> {
    let mut line = Vec::new();
    loop {
        let buffer = match reader.fill_buf() {
            Ok(buffer) => buffer,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Ok(Frame::Interrupted(Interruption::ReadFailed(
                    error.to_string(),
                )));
            }
        };
        if buffer.is_empty() {
            return Ok(if line.is_empty() {
                Frame::End
            } else {
                Frame::Interrupted(Interruption::Truncated)
            });
        }
        let end = buffer.iter().position(|&byte| byte == b'\n');
        let count = end.map_or(buffer.len(), |end| end + 1);
        if count > limit.saturating_sub(line.len()) {
            return Err("Worker response exceeded the 32 MiB limit".into());
        }
        line.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Frame::Line(line));
        }
    }
}

/// A client for host tests over an idle `sh` child that accepts every
/// request: `events` are the only output events, in order.
#[cfg(all(test, target_os = "linux"))]
impl WorkerClient {
    pub(crate) fn with_events(events: Vec<TimedEvent>) -> Self {
        use std::os::unix::process::CommandExt;
        // Its own group, as `kill_worker` signals the worker's group.
        let mut child = Command::new("sh")
            .process_group(0)
            .args(["-c", "exec cat >/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let (sender, receiver) = mpsc::sync_channel(events.len() + 1);
        for event in events {
            sender.send(Some(event)).unwrap();
        }
        // Queued events stay readable; later polls find none.
        drop(sender);
        let path = std::env::current_exe().unwrap();
        Self {
            child: Some(child),
            diagnostics: Arc::new(Mutex::new(Diagnostics::default())),
            eof: None,
            eof_reported: false,
            failure: None,
            interrupted: Arc::new(Mutex::new(None)),
            context: eframe::egui::Context::default(),
            input: WorkerInput::Direct(input),
            events: receiver,
            next_id: 0,
            sent: Arc::new(AtomicU64::new(0)),
            sent_replies: SentReplies::default(),
            peer_slot: managed_decompile::PeerSlot::default(),
            managed_program: None,
            managed_revision: 0,
            cached_reply: None,
            binary_path: path.clone(),
            companion_path: None,
            accepted_companion: Arc::new(Mutex::new(None)),
            exe: path.clone(),
            worker_args: Vec::new(),
            protection: BinaryProtection::open(&path).unwrap(),
            source_lease: None,
            signature_context: Arc::new(Mutex::new(String::new())),
            sent_search: Arc::new(Mutex::new(None)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    fn open_pidfd(pid: i32) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        // SAFETY: pidfd_open takes a PID and flags and returns a new
        // descriptor or -1; no memory is passed.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let fd = libc::c_int::try_from(fd).unwrap_or(-1);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh descriptor that only this value owns.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }

    #[cfg(target_os = "linux")]
    fn pidfd_signal(pidfd: &std::os::fd::OwnedFd, signal: libc::c_int) -> std::io::Result<()> {
        // SAFETY: the pidfd names one process for its whole lifetime, never
        // a later process reusing its PID; a null info pointer is permitted.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                std::os::fd::AsRawFd::as_raw_fd(pidfd),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// The leak scan identifies processes only through pidfds. Where they
    /// are denied or unsupported, the scan would find nothing and pass, so
    /// the test must fail with the reason instead.
    #[cfg(target_os = "linux")]
    fn pidfd_preflight(
        open: impl Fn(i32) -> std::io::Result<std::os::fd::OwnedFd>,
        signal: impl Fn(&std::os::fd::OwnedFd, libc::c_int) -> std::io::Result<()>,
    ) -> Result<(), String> {
        let own = i32::try_from(std::process::id()).map_err(|e| e.to_string())?;
        let pidfd = open(own).map_err(|e| format!("pidfd_open on this test process: {e}"))?;
        signal(&pidfd, 0).map_err(|e| format!("pidfd signal 0 on this test process: {e}"))
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn denied_pidfds_fail_the_leak_scan_preflight() {
        let denied = |_| -> std::io::Result<std::os::fd::OwnedFd> {
            Err(std::io::Error::from_raw_os_error(libc::EPERM))
        };
        let error = pidfd_preflight(denied, pidfd_signal).unwrap_err();
        assert!(error.contains("pidfd_open"), "{error}");
        let unsupported = |_: &std::os::fd::OwnedFd, _| -> std::io::Result<()> {
            Err(std::io::Error::from_raw_os_error(libc::ENOSYS))
        };
        assert!(pidfd_preflight(open_pidfd, unsupported).is_err());
        pidfd_preflight(open_pidfd, pidfd_signal).unwrap();
    }

    /// Workers stopped while bubblewrap is still building their sandbox
    /// leave no process behind. Killing only bwrap used to leave its
    /// namespace init waiting forever for bwrap to release it.
    #[cfg(target_os = "linux")]
    #[test]
    fn workers_stopped_during_sandbox_setup_leave_no_process() {
        use std::os::unix::ffi::OsStrExt;
        pidfd_preflight(open_pidfd, pidfd_signal)
            .unwrap_or_else(|error| panic!("this test needs working pidfds: {error}"));
        let worker = crate::app::test_worker().unwrap_or_else(|error| panic!("{error}"));
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("input");
        std::fs::write(&binary, b"not analysed").unwrap();
        for _ in 0..40 {
            let context = eframe::egui::Context::default();
            drop(WorkerClient::start_using_executable(context, &binary, &worker).unwrap());
        }
        // Only sandboxes binding this test's private file are inspected. Each
        // match holds a pidfd opened before its command line was read and
        // confirmed live afterwards, so the line and any signal concern the
        // same process even if its numeric PID is later reused. Processes
        // that disappear during the scan are ignored; any other pidfd error
        // on a matching process is reported.
        let marker = binary.as_os_str().as_bytes().to_vec();
        let sandboxes = || {
            let mut errors = Vec::new();
            let matches = std::fs::read_dir("/proc")
                .unwrap()
                .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<i32>().ok())
                .filter_map(|pid| {
                    let matching = || {
                        std::fs::read(format!("/proc/{pid}/cmdline"))
                            .is_ok_and(|line| line.windows(marker.len()).any(|w| w == marker))
                    };
                    let pidfd = match open_pidfd(pid) {
                        Ok(pidfd) => pidfd,
                        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return None,
                        Err(error) => {
                            if matching() {
                                errors.push(format!("{pid}: {error}"));
                            }
                            return None;
                        }
                    };
                    (matching() && pidfd_signal(&pidfd, 0).is_ok()).then_some((pid, pidfd))
                })
                .collect::<Vec<_>>();
            assert!(errors.is_empty(), "pidfd errors on sandboxes: {errors:?}");
            matches
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < deadline && !sandboxes().is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let left = sandboxes();
        for (_, pidfd) in &left {
            let _ = pidfd_signal(pidfd, libc::SIGKILL);
        }
        let left = left.into_iter().map(|(pid, _)| pid).collect::<Vec<_>>();
        assert!(left.is_empty(), "sandboxes left behind: {left:?}");
    }

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
            assert_eq!(
                bounded_line(&mut BufReader::new(output), 1).unwrap(),
                Frame::End
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
            failure: None,
            interrupted: Arc::new(Mutex::new(None)),
            context,
            input: WorkerInput::Direct(input),
            events,
            next_id: 0,
            sent: Arc::new(AtomicU64::new(0)),
            sent_replies: SentReplies::default(),
            peer_slot: managed_decompile::PeerSlot::default(),
            managed_program: None,
            managed_revision: 0,
            cached_reply: None,
            binary_path: path.clone(),
            companion_path: None,
            accepted_companion: Arc::new(Mutex::new(None)),
            exe: path.clone(),
            worker_args: Vec::new(),
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
        let text = exit_diagnostic(None, state.allocation_failed, None);
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
        // A debug peer's start notice never completes its exchange, and is
        // refused once the exchange is answered.
        let sent = AtomicU64::new(1);
        let mut answered = 0;
        let started = r#"{"id":1,"response":{"kind":"debug_started","nonce":4}}"#;
        let unavailable =
            r#"{"id":1,"response":{"kind":"debug_unavailable","nonce":4,"reason":"stale"}}"#;
        let mut check = |line: &str| check_reply_order(line.as_bytes(), &sent, &mut answered);
        assert!(check(started).is_ok());
        assert!(check(unavailable).is_ok());
        assert!(check(started).is_err(), "notice after completion");
        assert!(check(unavailable).is_err(), "second terminal reply");
    }
    #[test]
    fn managed_debug_notice_must_match_the_sent_role_nonce_and_order() {
        use crate::model::Response;
        let queue = SentReplies::default();
        let ticket = |nonce| crate::analysis::managed::Ticket {
            nonce,
            logical_id: 2,
            book_version: 1,
        };
        for (id, purpose) in [
            (1, ReplyPurpose::Debug(ticket(19), true, 0x1000)),
            (2, ReplyPurpose::Ordinary),
        ] {
            queue.lock().unwrap().push_back(SentReply {
                id,
                purpose,
                signature_context: "the sent context".into(),
                started: false,
            });
        }
        let started = |id, nonce, direct| WorkerResponse {
            id,
            response: Response::DebugStarted {
                ticket: ticket(nonce),
                direct,
            },
        };
        assert!(admit_reply(&queue, &started(2, 19, true)).is_err());
        assert!(admit_reply(&queue, &started(1, 18, true)).is_err());
        assert!(admit_reply(&queue, &started(1, 19, false)).is_err());
        assert!(admit_reply(&queue, &started(1, 19, true)).is_ok());
        assert!(admit_reply(&queue, &started(1, 19, true)).is_err());
        assert_eq!(
            admit_reply(
                &queue,
                &WorkerResponse {
                    id: 1,
                    response: Response::Error {
                        message: "test".into()
                    },
                }
            )
            .unwrap()
            .0,
            "the sent context"
        );
        assert!(admit_reply(&queue, &started(2, 19, true)).is_err());
    }

    #[test]
    fn inference_only_prepare_admits_only_an_inferred_final_render() {
        use crate::model::Response;
        use crate::semantic::PrototypeSource;
        let decompiled = |source| Response::Decompiled {
            address: 0x1000,
            text: "void f(void) {}".into(),
            mappings: Vec::new(),
            semantics: crate::semantic::SemanticInfo {
                prototype_source: source,
                ..Default::default()
            },
        };
        let prepare = |inference_only| ReplyPurpose::Prepare {
            logical_id: 1,
            address: 0x1000,
            inference_only,
        };
        assert!(prepare(true).admits(&decompiled(PrototypeSource::Inferred), false));
        // Otherwise valid, but with forged debug provenance.
        assert!(!prepare(true).admits(&decompiled(PrototypeSource::DebugInfo), false));
        // A normal preparation may finish with a verified debug render.
        assert!(prepare(false).admits(&decompiled(PrototypeSource::DebugInfo), false));
        let queue = SentReplies::default();
        queue.lock().unwrap().push_back(SentReply {
            id: 1,
            purpose: prepare(true),
            signature_context: String::new(),
            started: false,
        });
        let forged = WorkerResponse {
            id: 1,
            response: decompiled(PrototypeSource::DebugInfo),
        };
        assert!(admit_reply(&queue, &forged).is_err());
    }

    #[test]
    fn response_framing_preserves_messages_and_rejects_unbounded_or_partial_output() {
        let mut input = std::io::Cursor::new(b"one\ntwo\n".as_slice());
        assert_eq!(
            bounded_line(&mut input, 4).unwrap(),
            Frame::Line(b"one\n".to_vec())
        );
        assert_eq!(
            bounded_line(&mut input, 4).unwrap(),
            Frame::Line(b"two\n".to_vec())
        );
        assert_eq!(bounded_line(&mut input, 4).unwrap(), Frame::End);
        // An oversized frame was received in full: a rejected reply.
        assert!(bounded_line(&mut std::io::Cursor::new(b"12345\n"), 4).is_err());
        // Output that stops inside a frame is a transport interruption.
        assert_eq!(
            bounded_line(&mut std::io::Cursor::new(b"partial"), 20).unwrap(),
            Frame::Interrupted(Interruption::Truncated)
        );
        struct Broken;
        impl std::io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
        }
        assert!(matches!(
            bounded_line(&mut BufReader::new(Broken), 20).unwrap(),
            Frame::Interrupted(Interruption::ReadFailed(_))
        ));
    }

    /// The exit status a CPU-limit stop reports on this platform, and an
    /// ordinary one.
    #[cfg(any(target_os = "linux", windows))]
    fn exit_statuses() -> (std::process::ExitStatus, std::process::ExitStatus) {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::process::ExitStatusExt;
            let code = |code: i32| std::process::ExitStatus::from_raw(code << 8);
            (code(crate::limits::CPU_LIMIT_EXIT), code(1))
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::ExitStatusExt;
            let code = std::process::ExitStatus::from_raw;
            (code(crate::limits::WATCHDOG_EXIT), code(1))
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn end_of_output_tells_process_loss_from_a_rejected_reply() {
        let (cpu, other) = exit_statuses();
        // Clean end of output: process loss, classified by the status.
        let (kind, message) = end_failure(Some(cpu), None, false);
        assert_eq!(kind, FailureKind::CpuLimit);
        assert!(message.contains("CPU time limit reached"), "{message}");
        assert_eq!(end_failure(Some(other), None, false).0, FailureKind::Exited);
        assert_eq!(end_failure(None, None, false).0, FailureKind::Exited);
        // A reply cut off by a confirmed exit is process loss too, and keeps
        // the exit diagnostic other hosts match on.
        let (kind, message) = end_failure(Some(cpu), Some(Interruption::Truncated), false);
        assert_eq!(kind, FailureKind::CpuLimit);
        assert!(message.starts_with("Analysis worker exited:"), "{message}");
        assert!(message.contains("cut off"), "{message}");
        assert_eq!(
            end_failure(Some(other), Some(Interruption::Truncated), false).0,
            FailureKind::Exited
        );
        // A pipe failure is process loss even before the exit is observed.
        let failed = Interruption::ReadFailed("broken pipe".into());
        let (kind, message) = end_failure(None, Some(failed), false);
        assert_eq!(kind, FailureKind::Exited);
        assert!(message.contains("broken pipe"), "{message}");
        // A worker that is still running closed its output mid-reply.
        assert_eq!(
            end_failure(None, Some(Interruption::Truncated), false),
            (FailureKind::Rejected, "Truncated worker response".into())
        );
    }

    /// The Windows watchdog's TerminateProcess code is the CPU limit, for
    /// both the failure kind and its diagnostic; Linux's 152 is not.
    #[cfg(windows)]
    #[test]
    fn windows_watchdog_exit_is_classified_as_the_cpu_limit() {
        use std::os::windows::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw;
        assert!(crate::limits::cpu_limit_stop(&status(
            crate::limits::WATCHDOG_EXIT
        )));
        assert!(!crate::limits::cpu_limit_stop(&status(152)));
        // The abort fallback is an ordinary exit.
        assert!(!crate::limits::cpu_limit_stop(&status(0xC000_0409)));
        let (kind, message) = end_failure(Some(status(crate::limits::WATCHDOG_EXIT)), None, false);
        assert_eq!(kind, FailureKind::CpuLimit);
        assert!(message.contains("CPU time limit reached"), "{message}");
        assert_eq!(
            end_failure(Some(status(152)), None, false).0,
            FailureKind::Exited
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cpu_limit_is_the_handler_exit_or_the_signal() {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw;
        assert!(crate::limits::cpu_limit_stop(&status(
            crate::limits::CPU_LIMIT_EXIT << 8
        )));
        assert!(crate::limits::cpu_limit_stop(&status(libc::SIGXCPU)));
        assert!(!crate::limits::cpu_limit_stop(&status(124 << 8)));
        assert!(!crate::limits::cpu_limit_stop(&status(libc::SIGKILL)));
        assert!(!crate::limits::cpu_limit_stop(&status(134 << 8)));
    }

    /// The crash handlers' `128 + signal` exits (and death by the signal)
    /// are crashes, apart from the CPU limit's 152 and ordinary exits, and
    /// keep the exit diagnostic prefix other hosts match on.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_crash_exits_are_classified_as_crashes() {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::ExitStatus::from_raw;
        for raw in [134 << 8, 139 << 8, libc::SIGSEGV] {
            let (kind, message) = end_failure(Some(status(raw)), None, false);
            assert_eq!(kind, FailureKind::Crashed, "{message}");
            assert!(message.starts_with("Analysis worker exited:"), "{message}");
            assert!(message.contains("crashed (SIG"), "{message}");
            assert!(!message.contains("CPU time limit"), "{message}");
        }
        let (kind, message) = end_failure(Some(status(134 << 8)), None, false);
        assert_eq!(kind, FailureKind::Crashed);
        assert!(message.contains("crashed (SIGABRT)"), "{message}");
        let (kind, message) = end_failure(Some(status(152 << 8)), None, false);
        assert_eq!(kind, FailureKind::CpuLimit);
        assert!(!message.contains("crashed"), "{message}");
        for raw in [1 << 8, libc::SIGKILL] {
            assert_eq!(
                end_failure(Some(status(raw)), None, true).0,
                FailureKind::Exited
            );
        }
    }
}
