//! Headless controller over the production contained worker. The caller owns
//! the input/output paths and trusted worker executable; commands cannot open
//! arbitrary server paths. This module never starts a window or event loop.
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use crate::client::{WorkerClient, WorkerEvent};
use crate::discovery::{Discovery, DiscoverySnapshot, WorkerInventory};
use crate::function_presentation::{PreparedDecompilation, PreparedGraph};
use crate::function_results::FunctionResults;
use crate::model::*;
use crate::project::{EmbeddedBinary, ProjectData, SavedFunction};
use crate::result_store::{ResultOrigin, Shared};
use crate::session::{BinaryProtection, Session};
use serde::{Deserialize, Serialize};

pub mod protocol;
#[cfg(all(test, any(target_os = "linux", windows)))]
mod tests;

/// Version of the public console protocol, independent of worker/project formats.
pub const API_VERSION: u16 = 1;

#[derive(Clone, Default)]
pub struct CancellationToken(Arc<AtomicBool>);
impl CancellationToken {
    /// Cancellation is permanent for this token. Create a new token/session to resume.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub enum Input {
    Binary(PathBuf),
    Project {
        path: PathBuf,
        external_binary: Option<PathBuf>,
    },
}

pub struct Options {
    /// A host-selected destination. API commands carry no filesystem paths.
    pub output_project: Option<PathBuf>,
    pub use_debug_info: Option<bool>,
    pub debug_info: Option<PathBuf>,
    /// May shorten, but never extend, the production worker deadline.
    pub worker_timeout: Duration,
    pub cancellation: CancellationToken,
    /// Host-test-only internal worker arguments (see
    /// [`crate::worker::NO_FORK_ARGUMENT`]); empty in production.
    #[doc(hidden)]
    pub worker_arguments: Vec<std::ffi::OsString>,
    /// Host-test-only least optional window after a baseline: it replaces
    /// the production three-second render minimum and raises a sibling's
    /// setup minimum. Both still end by the request deadline less the
    /// settlement reserve. `None` in production.
    #[doc(hidden)]
    pub optional_floor: Option<Duration>,
    /// Host-test-only exact sibling setup allowance in place of the
    /// adaptive one, for forcing a setup cutoff. `None` in production.
    #[doc(hidden)]
    pub optional_setup: Option<Duration>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            output_project: None,
            use_debug_info: None,
            debug_info: None,
            worker_timeout: WORKER_REQUEST_TIMEOUT,
            cancellation: CancellationToken::default(),
            worker_arguments: Vec::new(),
            optional_floor: None,
            optional_setup: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    InvalidAddress,
    CommandFailed,
    WorkerFailed,
    Timeout,
    Cancelled,
    SessionClosed,
    Project,
    ResponseTooLarge,
}

#[derive(Debug, Serialize)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}
impl Error {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        if message.len() > 4096 {
            let mut end = 4096;
            while !message.is_char_boundary(end) {
                end -= 1;
            }
            message.truncate(end);
        }
        Self { code, message }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    Info {},
    Annotations {},
    Function {
        address: u64,
        #[serde(default)]
        refresh: bool,
    },
    Discover {},
    Strings {
        minimum_length: usize,
    },
    Crypto {},
    Bytes {
        address: u64,
        length: usize,
    },
    Linkage {
        cursor: usize,
        #[serde(default)]
        digest: Option<String>,
    },
    SaveProject {
        #[serde(default = "embed_by_default")]
        embed_binary: bool,
    },
}
fn embed_by_default() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Computed,
    Saved,
}
impl From<ResultOrigin> for Origin {
    fn from(value: ResultOrigin) -> Self {
        match value {
            ResultOrigin::Computed => Self::Computed,
            ResultOrigin::Saved => Self::Saved,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct FunctionAnalysis {
    pub view: FunctionView,
    pub text: String,
    pub mappings: Vec<CodeMapping>,
    pub semantics: crate::semantic::SemanticInfo,
    pub graph_origin: Origin,
    pub decompiled_origin: Origin,
    pub cache_hit: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Output {
    Info {
        info: Box<BinaryInfo>,
        use_debug_info: bool,
        debug_status: crate::debug_info::DebugUseStatus,
        /// Functions rendered without debug prototypes after a worker failure
        /// (saved by earlier versions; a worker stop no longer adds one).
        debug_skipped_functions: Vec<u64>,
        unapplied_signatures: Vec<SignatureStatus>,
    },
    Annotations {
        session: Box<Session>,
    },
    Function {
        analysis: Box<FunctionAnalysis>,
    },
    Discovery {
        snapshot: Box<DiscoverySnapshot>,
        complete: bool,
    },
    Strings {
        strings: Vec<StringEntry>,
        truncated: bool,
    },
    Crypto {
        matches: Vec<CryptoMatch>,
        truncated: bool,
    },
    Bytes {
        address: u64,
        bytes: Vec<u8>,
    },
    Linkage {
        summary: crate::linkage::LinkageSummary,
        page: crate::linkage::LinkagePage,
    },
    ProjectSaved {
        functions: usize,
    },
}

/// A single verified binary, its annotations and bounded reusable results.
/// Worker transport failures, malformed replies, timeouts, cancellation and
/// non-recoverable engine errors stop the worker. Completed results, scans,
/// committed discovery and annotations stay owned by this controller, so
/// `info`, `annotations` and `save_project` keep working without a worker.
/// `discover` starts a replacement worker for the same verified image, at most
/// [`MAX_DISCOVERY_RESUMES`] times per session. A debug-enabled Open failure
/// retries once with debug info disabled and retains that setting; a worker
/// stop before a debug-enabled function's baseline retries that function once
/// with ordinary inference only and records no skip.
pub struct Analyzer {
    worker: Option<ReapingWorker>,
    data: ProjectData,
    /// The protection bound when the session opened. Replacement workers must
    /// verify the same source identity; checkpoints keep using this guard.
    protection: BinaryProtection,
    /// The controller's own lease on an extracted project image, independent
    /// of any worker, so a checkpoint can still embed it after a stop.
    source: Option<EmbeddedBinary>,
    /// Canonical input path the first worker verified; replacement workers
    /// reopen exactly this path and are then checked against `protection`.
    binary_path: PathBuf,
    executable: PathBuf,
    options: Options,
    results: FunctionResults,
    graph: Option<Shared<PreparedGraph>>,
    code: Option<Shared<PreparedDecompilation>>,
    discovery: Option<Discovery>,
    /// Inventory adopted from the current worker; reset with every worker.
    inventory: Option<WorkerInventory>,
    /// Distinct per worker so discovery bindings never cross a restart.
    worker_epoch: u64,
    discovery_resumes: u8,
    unapplied_signatures: Vec<SignatureStatus>,
    peer_context: Option<Arc<crate::client::managed_decompile::PeerContext>>,
    decision_book: crate::client::managed_decompile::DecisionBook,
    recover_optional_primary: bool,
    linkage: Option<crate::linkage::LinkageFetch>,
}

/// Synchronously stops and reaps its worker on drop, releasing any retained
/// extracted-image lease before the owner returns. The desktop's asynchronous
/// [`WorkerClient`] drop could otherwise let a short-lived console exit first.
struct ReapingWorker(Option<WorkerClient>);
impl ReapingWorker {
    fn start(
        path: &Path,
        executable: &Path,
        debug_path: Option<&Path>,
        enabled: bool,
        arguments: &[std::ffi::OsString],
    ) -> Result<Self, Error> {
        WorkerClient::start_with_worker_arguments(
            eframe::egui::Context::default(),
            path,
            executable,
            debug_path,
            enabled,
            arguments.to_vec(),
        )
        .map(|worker| Self(Some(worker)))
        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))
    }
}
impl std::ops::Deref for ReapingWorker {
    type Target = WorkerClient;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned worker")
    }
}
impl std::ops::DerefMut for ReapingWorker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.as_mut().expect("owned worker")
    }
}
impl Drop for ReapingWorker {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            // On a reaping failure the client falls back to its own
            // asynchronous drop, which still keeps the lease until exit.
            let _ = worker.stop_and_wait();
        }
    }
}

/// Startup and replay failures discard the worker, so an engine error there
/// is never reported as a recoverable `CommandFailed`.
fn fatal(mut error: Error) -> Error {
    if error.code == ErrorCode::CommandFailed {
        error.code = ErrorCode::WorkerFailed;
    }
    error
}

/// A failed managed preparation: `Stopped` before any reply, or `Failed`.
enum Prepared {
    Stopped(Error),
    Failed(Error),
}

/// A verified worker `Open` reply and the protection bound to its snapshot.
struct Opened {
    info: BinaryInfo,
    macho_legacy: Option<MachoLegacySections>,
    protection: BinaryProtection,
    debug_state: String,
    debug_source: Option<crate::debug_info::companion::DebugSource>,
}

fn open_worker(
    worker: &mut WorkerClient,
    options: &Options,
    use_debug_info: bool,
    skip: &[u64],
) -> Result<Opened, Error> {
    let actual_path = worker
        .protection()
        .path()
        .to_str()
        .ok_or_else(|| Error::new(ErrorCode::InvalidRequest, "The binary path must be UTF-8"))?
        .to_owned();
    let Response::Opened {
        info,
        macho_legacy,
        debug,
        ..
    } = exchange(
        worker,
        Request::Open {
            debug: crate::debug_info::DebugOptions {
                companion_path: None,
                enabled: use_debug_info,
                skip: skip.to_vec(),
            },
            path: actual_path,
        },
        options,
    )
    .map_err(fatal)?
    else {
        return Err(Error::new(
            ErrorCode::WorkerFailed,
            "Unexpected worker open reply",
        ));
    };
    crate::project::validate_info(&info, MAX_FUNCTION_NAME_BYTES, true)
        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
    let protection = worker
        .protection()
        .bind_snapshot(&info)
        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
    Ok(Opened {
        debug_source: debug.as_ref().and_then(|d| d.source.clone()),
        debug_state: debug.map_or_else(String::new, |d| d.state),
        info,
        macho_legacy,
        protection,
    })
}

/// One fallback for a worker that dies or times out while reading debug info.
fn start_open_worker(
    path: &Path,
    executable: &Path,
    source: Option<&crate::project::EmbeddedBinary>,
    options: &Options,
    enabled: bool,
    skip: &[u64],
) -> Result<(ReapingWorker, Opened, bool), Error> {
    let mut worker = ReapingWorker::start(
        path,
        executable,
        options.debug_info.as_deref(),
        enabled,
        &options.worker_arguments,
    )?;
    if let Some(source) = source {
        worker.retain_source(Arc::new(source.clone()));
    }
    match open_worker(&mut worker, options, enabled, skip) {
        Ok(opened) => Ok((worker, opened, enabled)),
        Err(error)
            if enabled && matches!(error.code, ErrorCode::WorkerFailed | ErrorCode::Timeout) =>
        {
            drop(worker);
            // A failed retry returns its error; the caller's setting and
            // warnings are unchanged.
            let (worker, mut opened, enabled) =
                start_open_worker(path, executable, source, options, false, skip)?;
            crate::debug_info::record_open_fallback(&mut opened.info);
            Ok((worker, opened, enabled))
        }
        Err(error) => Err(error),
    }
}

/// Replays complete effective names before prototypes, and both before any
/// analysis. Returns the worker's unapplied saved signatures.
/// The engine spelling of every controller function name, as replayed.
fn effective_functions(data: &ProjectData) -> Vec<FunctionInfo> {
    data.info
        .functions
        .iter()
        .map(|function| FunctionInfo {
            address: function.address,
            name: crate::model::inventory_spelling(&function.name).to_owned(),
        })
        .collect()
}

fn replay(
    worker: &mut WorkerClient,
    data: &ProjectData,
    options: &Options,
) -> Result<Vec<SignatureStatus>, Error> {
    let effective = effective_functions(data);
    for chunk in sync_chunks(&effective) {
        if !matches!(
            exchange(
                worker,
                Request::SyncFunctions {
                    functions: chunk.to_vec()
                },
                options
            )
            .map_err(fatal)?,
            Response::FunctionsSynced
        ) {
            return Err(Error::new(
                ErrorCode::WorkerFailed,
                "Unexpected function synchronization reply",
            ));
        }
    }
    if data.session.signatures.is_empty() {
        return Ok(Vec::new());
    }
    let context = crate::signatures::state_digest(&data.session.signatures);
    match exchange(
        worker,
        Request::SyncSignatures {
            binary_sha256: data.info.sha256.clone(),
            context: context.clone(),
            signatures: data.session.signatures.clone(),
        },
        options,
    )
    .map_err(fatal)?
    {
        Response::SignaturesSynced {
            binary_sha256,
            context: actual,
            unapplied,
        } if binary_sha256 == data.info.sha256 && actual == context => Ok(unapplied),
        _ => Err(Error::new(
            ErrorCode::WorkerFailed,
            "Unexpected signature synchronization reply",
        )),
    }
}

impl Analyzer {
    /// `executable` is selected by the host, supports `--analysis-worker`, and
    /// must be trusted. Project source hints are never opened automatically.
    /// A startup error stops and reaps any worker before returning, so an
    /// extracted project image never outlives this call.
    pub fn open(input: Input, executable: &Path, options: Options) -> Result<Self, Error> {
        if options.worker_timeout.is_zero() || options.worker_timeout > WORKER_REQUEST_TIMEOUT {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "Worker timeout must be greater than zero and at most 30 seconds",
            ));
        }
        if options.cancellation.is_cancelled() {
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        let (project, path) = match input {
            Input::Binary(path) => (None, path),
            Input::Project {
                path,
                external_binary,
            } => {
                let project =
                    ProjectData::load(&path).map_err(|e| Error::new(ErrorCode::Project, e))?;
                let binary = match (&project.binary, external_binary) {
                    (Some(binary), None) => binary.path().to_owned(),
                    (None, Some(path)) => path,
                    (Some(_), Some(_)) => {
                        return Err(Error::new(
                            ErrorCode::InvalidRequest,
                            "An embedded project does not require an external binary",
                        ));
                    }
                    (None, None) => {
                        return Err(Error::new(
                            ErrorCode::InvalidRequest,
                            "Select the external binary explicitly; source hints are display-only",
                        ));
                    }
                };
                (Some(project), binary)
            }
        };
        // Declared after `project` so every early return reaps the worker
        // (dropping its lease) before the project's own image lease drops.
        let source = project.as_ref().and_then(|p| p.binary.clone());
        let enabled = options
            .use_debug_info
            .unwrap_or_else(|| project.as_ref().is_none_or(|p| p.data.use_debug_info));
        // Explicitly enabling debug info also clears per-function skips.
        let skip = match &project {
            Some(project) if options.use_debug_info != Some(true) => {
                project.data.debug_skip.clone()
            }
            _ => Vec::new(),
        };
        let (mut worker, opened, enabled) =
            start_open_worker(&path, executable, source.as_ref(), &options, enabled, &skip)?;
        let binary_path = worker.protection().path().to_owned();
        let Opened {
            mut info,
            macho_legacy,
            protection,
            debug_state,
            debug_source,
        } = opened;
        if !enabled && let Some(project) = &project {
            crate::debug_info::inherit_fallback(&mut info, &project.data.info);
        }
        let mut data = if let Some(mut project) = project {
            project.data.use_debug_info = enabled;
            project.data.debug_skip = skip;
            project.accept_debug(&debug_state);
            project.data.debug_source = debug_source;
            project
                .accept_opened(&info, macho_legacy.as_ref())
                .map_err(|e| Error::new(ErrorCode::Project, e))?;
            if project.cache_compatible {
                info.functions.clone_from(&project.data.info.functions);
                info.functions_truncated = project.data.info.functions_truncated;
            }
            // Preserve the original protected pathname as a hint, just as the GUI does.
            info.path.clone_from(&project.source_hint);
            let mut data = project.data;
            data.info = info;
            data
        } else {
            ProjectData {
                debug_source,
                debug_state,
                use_debug_info: enabled,
                debug_skip: Vec::new(),
                session: Session::new(info.sha256.clone()),
                info,
                view: None,
                decompiled: None,
                mappings: Vec::new(),
                semantics: Default::default(),
                strings: Vec::new(),
                strings_truncated: false,
                crypto: Vec::new(),
                crypto_truncated: false,
                selected_address: None,
                discovery: None,
                function_results: Vec::new(),
            }
        };
        data.session
            .validate_ranges(&data.info.sections, &data.info.architecture)
            .map_err(|e| Error::new(ErrorCode::Project, e))?;
        for function in &mut data.info.functions {
            if let Some(annotation) = data
                .session
                .annotations
                .get(&function.address)
                .filter(|v| !v.label.is_empty())
            {
                function.name.clone_from(&annotation.label);
            }
        }
        let unapplied_signatures = replay(&mut worker, &data, &options)?;
        let mut analyzer = Self {
            worker: Some(worker),
            data,
            protection,
            source,
            binary_path,
            executable: executable.to_owned(),
            options,
            results: FunctionResults::default(),
            graph: None,
            code: None,
            discovery: None,
            inventory: None,
            peer_context: None,
            decision_book: Default::default(),
            recover_optional_primary: false,
            worker_epoch: 1,
            discovery_resumes: 0,
            unapplied_signatures,
            linkage: None,
        };
        analyzer.results.open(
            &analyzer.data.info.sha256,
            &analyzer.data.session.signatures,
        );
        analyzer.results.set_debug_state(&analyzer.data.debug_state);
        analyzer.update_context();
        analyzer.wait_context()?;
        for saved in crate::project::prepare_functions(&mut analyzer.data)
            .into_iter()
            .rev()
        {
            let address = saved.graph.address();
            let binding = analyzer
                .results
                .binding(address, analyzer.results.local_state(address));
            analyzer
                .results
                .admit_graph(binding.as_ref(), saved.graph, ResultOrigin::Saved, None);
            if let Some(code) = saved.code {
                analyzer.results.admit_decompilation(
                    binding.as_ref(),
                    code,
                    ResultOrigin::Saved,
                    None,
                );
            }
        }
        if let Some(view) = analyzer.data.view.take() {
            let address = view.address;
            let binding = analyzer
                .results
                .binding(address, analyzer.results.local_state(address));
            analyzer.graph = Some(analyzer.results.admit_graph(
                binding.as_ref(),
                PreparedGraph::new(view),
                ResultOrigin::Saved,
                Some(address),
            ));
            if let Some(text) = analyzer.data.decompiled.take() {
                let code = PreparedDecompilation::validate(
                    address,
                    text,
                    std::mem::take(&mut analyzer.data.mappings),
                    std::mem::take(&mut analyzer.data.semantics),
                    &analyzer.data.info.sections,
                )
                .map_err(|e| {
                    Error::new(
                        ErrorCode::Project,
                        format!("Invalid saved pseudocode: {e:?}"),
                    )
                })?;
                analyzer.code = Some(analyzer.results.admit_decompilation(
                    binding.as_ref(),
                    code,
                    ResultOrigin::Saved,
                    Some(address),
                ));
            }
        }
        Ok(analyzer)
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.options.cancellation.clone()
    }

    fn active(&self) -> Result<(), Error> {
        if self.options.cancellation.is_cancelled() {
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        if self.worker.is_none() {
            return Err(Error::new(
                ErrorCode::SessionClosed,
                "The worker stopped; run discover to resume it or open a new analysis session",
            ));
        }
        Ok(())
    }

    /// In-protocol byte and linkage errors leave the worker usable, as on the
    /// desktop, and are reported as `CommandFailed`. Every other failure stops
    /// the worker; an engine error is then reported as `WorkerFailed`.
    fn request(&mut self, request: Request) -> Result<Response, Error> {
        self.active()?;
        let recoverable = matches!(request, Request::Bytes { .. } | Request::Linkage { .. });
        let response = exchange(
            self.worker.as_mut().expect("active worker"),
            request,
            &self.options,
        );
        match response {
            Err(error) if recoverable && error.code == ErrorCode::CommandFailed => Err(error),
            Err(error) => {
                self.stop();
                Err(fatal(error))
            }
            Ok(response) => Ok(response),
        }
    }

    /// [`Self::request`] for a managed preparation, telling a stop before
    /// any reply (process exit or wall deadline) from every other failure:
    /// rejected or mismatched replies, engine errors and cancellation.
    fn prepare(&mut self, request: Request) -> Result<Response, Prepared> {
        self.active().map_err(Prepared::Failed)?;
        let worker = self.worker.as_mut().expect("active worker");
        let response = exchange(worker, request, &self.options);
        let error = match response {
            Ok(response) => return Ok(response),
            Err(error) => error,
        };
        let stopped = match error.code {
            ErrorCode::Timeout => true,
            ErrorCode::WorkerFailed => self
                .worker
                .as_ref()
                .and_then(|w| w.failure())
                .is_some_and(|kind| kind != crate::client::FailureKind::Rejected),
            _ => false,
        };
        self.stop();
        let error = fatal(error);
        Err(if stopped {
            Prepared::Stopped(error)
        } else {
            Prepared::Failed(error)
        })
    }

    /// Stops and reaps the worker. Retained results, scans, annotations and
    /// committed discovery survive; per-worker state does not.
    fn stop(&mut self) {
        drop(self.worker.take());
        self.peer_context = None;
        self.inventory = None;
        self.reset_linkage();
        if let Some(state) = &mut self.discovery {
            state.interrupt();
        }
    }

    fn reset_linkage(&mut self) {
        self.linkage = None;
        self.results.set_linkage_bytes(0);
    }

    /// Starts preparing the function-result context for the current names.
    fn update_context(&mut self) {
        self.peer_context = None;
        self.results.update_inputs(
            self.data.info.functions.clone(),
            self.data.session.local_renames.clone(),
        );
    }

    /// Parent-side preparation shares the request deadline and, for analysis,
    /// cancellation. Checkpoints still finish preparing after cancellation.
    fn wait_context(&mut self) -> Result<(), Error> {
        self.wait_context_for(true)
    }

    fn wait_context_for(&mut self, cancellable: bool) -> Result<(), Error> {
        let deadline = Instant::now() + self.options.worker_timeout;
        while self.results.preparing() {
            if cancellable && self.options.cancellation.is_cancelled() {
                return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
            }
            if Instant::now() >= deadline {
                return Err(Error::new(
                    ErrorCode::Timeout,
                    "Function context preparation timed out",
                ));
            }
            self.results.poll_inputs();
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }

    /// Host-test-only: replaces [`Options::optional_floor`] and
    /// [`Options::optional_setup`] for later commands of this session.
    #[doc(hidden)]
    pub fn set_optional_windows(&mut self, floor: Option<Duration>, setup: Option<Duration>) {
        self.options.optional_floor = floor;
        self.options.optional_setup = setup;
    }

    pub fn execute(&mut self, command: Command) -> Result<Output, Error> {
        let result = self.execute_inner(command);
        if result.as_ref().is_err_and(|e| {
            matches!(
                e.code,
                ErrorCode::WorkerFailed | ErrorCode::Cancelled | ErrorCode::Timeout
            )
        }) {
            self.stop();
        }
        result
    }

    fn execute_inner(&mut self, command: Command) -> Result<Output, Error> {
        if self.options.cancellation.is_cancelled() {
            self.stop();
        }
        // Retained data stays readable and checkpointable without a worker,
        // including after permanent cancellation. Discovery checks its own.
        if !matches!(
            command,
            Command::Info {}
                | Command::Annotations {}
                | Command::SaveProject { .. }
                | Command::Discover {}
        ) {
            if self.worker.is_none()
                && !self.options.cancellation.is_cancelled()
                && std::mem::take(&mut self.recover_optional_primary)
            {
                self.restart_worker(false)?;
            }
            self.active()?;
        }
        match command {
            Command::Info {} => {
                let mut info = self.data.info.clone();
                info.source_identity = None;
                info.path = Path::new(&info.path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                Ok(Output::Info {
                    debug_status: crate::debug_info::DebugUseStatus::of(
                        self.data.use_debug_info,
                        &info,
                    ),
                    use_debug_info: self.data.use_debug_info,
                    debug_skipped_functions: self.data.debug_skip.clone(),
                    info: Box::new(info),
                    unapplied_signatures: self.unapplied_signatures.clone(),
                })
            }
            Command::Annotations {} => Ok(Output::Annotations {
                session: Box::new(self.data.session.clone()),
            }),
            Command::Function { address, refresh } => self.function(address, refresh),
            Command::Discover {} => self.discover(),
            Command::Strings { minimum_length } => {
                if !(MIN_STRING_LENGTH..=MAX_STRING_MINIMUM).contains(&minimum_length) {
                    return Err(Error::new(
                        ErrorCode::InvalidRequest,
                        "String minimum length is outside the supported range",
                    ));
                }
                let Response::Strings { strings, truncated } =
                    self.request(Request::StringsWithOptions { minimum_length })?
                else {
                    return self.unexpected();
                };
                let ranges = crate::selection::MappedRanges::new(&self.data.info.sections)
                    .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
                crate::project::validate_strings(&strings, MAX_STRING_RESULTS, &ranges)
                    .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
                self.data.strings.clone_from(&strings);
                self.data.strings_truncated = truncated;
                Ok(Output::Strings { strings, truncated })
            }
            Command::Crypto {} => {
                let Response::Crypto { matches, truncated } = self.request(Request::Crypto)? else {
                    return self.unexpected();
                };
                let ranges = crate::selection::MappedRanges::new(&self.data.info.sections)
                    .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
                crate::project::validate_crypto(&matches, &ranges)
                    .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
                self.data.crypto.clone_from(&matches);
                self.data.crypto_truncated = truncated;
                Ok(Output::Crypto { matches, truncated })
            }
            Command::Bytes { address, length } => {
                let ranges = crate::selection::MappedRanges::new(&self.data.info.sections)
                    .map_err(|e| Error::new(ErrorCode::InvalidAddress, e))?;
                if length == 0
                    || length > MAX_BYTE_READ
                    || !ranges.contains_span(address, length as u64)
                {
                    return Err(Error::new(
                        ErrorCode::InvalidAddress,
                        "Byte range is empty, oversized, or unmapped",
                    ));
                }
                let Response::Bytes {
                    address: actual,
                    bytes,
                } = self.request(Request::Bytes { address, length })?
                else {
                    return self.unexpected();
                };
                if actual != address || bytes.len() != length {
                    return self.unexpected();
                }
                Ok(Output::Bytes { address, bytes })
            }
            Command::Linkage { cursor, digest } => self.linkage(cursor, digest),
            Command::SaveProject { embed_binary } => {
                if self.options.output_project.is_none() {
                    return Err(Error::new(
                        ErrorCode::InvalidRequest,
                        "Configure --output-project before requesting a checkpoint",
                    ));
                }
                // Results are captured only under a committed context.
                self.wait_context_for(false)?;
                let path = self.options.output_project.as_ref().expect("checked");
                let mut data = self.data.clone();
                data.view = self
                    .graph
                    .as_ref()
                    .map(|v| crate::project::persistable_view(v.view(), &data.info.sections));
                if let Some(code) = &self.code {
                    data.decompiled = Some(code.text().into());
                    data.mappings = code.mappings().to_vec();
                    data.semantics = code.semantics().clone();
                }
                data.function_results = SavedFunction::capture(
                    self.results.snapshot(),
                    data.view.as_ref().map(|v| v.address),
                    &data.info.sections,
                );
                let functions = data.function_results.len() + usize::from(data.view.is_some());
                data.save(path, &self.protection, embed_binary)
                    .map_err(|e| Error::new(ErrorCode::Project, e))?;
                Ok(Output::ProjectSaved { functions })
            }
        }
    }

    fn function(&mut self, address: u64, refresh: bool) -> Result<Output, Error> {
        if !crate::call_analysis::code_address(&self.data.info, address) {
            return Err(Error::new(
                ErrorCode::InvalidAddress,
                "Function entry is not executable file-backed code",
            ));
        }
        // A context left preparing by an earlier timeout is never bound against.
        self.wait_context()?;
        if refresh {
            self.results.refresh(address);
        }
        let local = self.results.local_state(address);
        let binding = self.results.binding(address, local.clone());
        let hit = self.results.lookup(address, &local);
        let cache_hit = hit.complete(true);
        let (graph, graph_origin) = if let Some(graph) = hit.graph {
            graph
        } else {
            let Response::Graph { view } = self.request(Request::Graph { address })? else {
                return self.unexpected();
            };
            if view.address != address {
                return self.unexpected();
            }
            let graph = PreparedGraph::validate(view, &self.data.info)
                .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
            (
                self.results.admit_graph(
                    binding.as_ref(),
                    graph,
                    ResultOrigin::Computed,
                    Some(address),
                ),
                ResultOrigin::Computed,
            )
        };
        let (code, code_origin) = if let Some(code) = hit.decompiled {
            code
        } else {
            let renames = self
                .data
                .session
                .local_renames
                .iter()
                .filter(|r| r.identity.function == address)
                .cloned()
                .collect::<Vec<_>>();
            let cached = self.decision_book.cached(
                self.worker
                    .as_ref()
                    .and_then(|worker| worker.managed_program.as_deref()),
                address,
                &renames,
                refresh,
            );
            let request = |inference_only| {
                crate::client::managed_decompile::prepare_request(
                    address,
                    renames.clone(),
                    refresh,
                    inference_only,
                )
                .map_err(|e| Error::new(ErrorCode::CommandFailed, e))
            };
            let mut dispatched = Instant::now();
            let first = match cached {
                Some(reply) => Ok(reply),
                None => self.prepare(request(false)?),
            };
            let (reply, recovered) = match first {
                Ok(reply) => (reply, false),
                Err(Prepared::Stopped(_))
                    if self.data.use_debug_info && !self.data.debug_state.is_empty() =>
                {
                    // The worker stopped before any baseline (an exit, such
                    // as the CPU limit, or the wall deadline). That says
                    // nothing about debug work, so no skip is recorded: one
                    // fresh worker renders only ordinary inference. A
                    // second failure is the command's error. A
                    // cancellation never launches the replacement.
                    if self.options.cancellation.is_cancelled() {
                        return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
                    }
                    self.restart_worker(false)?;
                    dispatched = Instant::now();
                    (self.request(request(true)?)?, true)
                }
                Err(Prepared::Stopped(error) | Prepared::Failed(error)) => return Err(error),
            };
            let (actual, text, mappings, semantics) = match reply {
                Response::Decompiled {
                    address,
                    text,
                    mappings,
                    semantics,
                } => (address, text, mappings, semantics),
                prepared @ Response::PreparedDecompile { .. } if !recovered => {
                    let (text, mappings, semantics) =
                        self.settle_prepared(address, renames, prepared, dispatched)?;
                    (address, text, mappings, semantics)
                }
                _ => return self.unexpected(),
            };
            if actual != address {
                return self.unexpected();
            }
            let code = PreparedDecompilation::validate(
                address,
                text,
                mappings,
                semantics,
                &self.data.info.sections,
            )
            .map_err(|e| {
                Error::new(
                    ErrorCode::WorkerFailed,
                    format!("Invalid pseudocode: {e:?}"),
                )
            })?;
            // A cancellation that arrived while the recovery's reply was
            // read or validated ends the command instead of adopting it.
            if recovered && self.options.cancellation.is_cancelled() {
                self.stop();
                return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
            }
            (
                self.results.admit_decompilation(
                    binding.as_ref(),
                    code,
                    ResultOrigin::Computed,
                    Some(address),
                ),
                ResultOrigin::Computed,
            )
        };
        let analysis = FunctionAnalysis {
            view: graph.view().clone(),
            text: code.text().into(),
            mappings: code.mappings().to_vec(),
            semantics: code.semantics().clone(),
            graph_origin: graph_origin.into(),
            decompiled_origin: code_origin.into(),
            cache_hit,
        };
        self.graph = Some(graph);
        self.code = Some(code);
        self.data.selected_address = Some(address);
        Ok(Output::Function {
            analysis: Box::new(analysis),
        })
    }

    /// Settles a managed baseline for `address` with at most one optional
    /// debug render, and returns the one final render. After a validated
    /// baseline, an optional failure or timeout is not a command failure:
    /// the baseline stands (a stopped primary is replaced by the next
    /// command), and no per-function skip is recorded.
    fn settle_prepared(
        &mut self,
        address: u64,
        renames: Vec<crate::semantic::LocalRename>,
        reply: Response,
        dispatched: Instant,
    ) -> Result<
        (
            String,
            Vec<crate::model::CodeMapping>,
            crate::semantic::SemanticInfo,
        ),
        Error,
    > {
        use crate::client::managed_decompile as managed;
        let context = self.signature_context();
        let prepared = match managed::admit_prepared(address, reply, &self.data.info, &context) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.stop();
                return Err(Error::new(ErrorCode::WorkerFailed, error));
            }
        };
        // The validated baseline is published here; a sibling's setup
        // allowance (including any wait for an earlier peer) starts now.
        let published = Instant::now();
        let Some(offer) = prepared.offer.as_ref() else {
            return Ok(managed::Staged::unverified().result.render(&prepared));
        };
        let hard = managed::hard_cap(dispatched, self.options.worker_timeout);
        let cutoff = match offer.executor {
            crate::analysis::managed::Executor::ForkHere => managed::cutoff(
                dispatched,
                self.options.worker_timeout,
                offer,
                self.options.optional_floor,
            ),
            // A sibling's phases are bounded separately within this cap.
            crate::analysis::managed::Executor::Sibling => hard,
        };
        let Some(transaction) = self.decision_book.begin(&prepared, renames, cutoff) else {
            return Ok(managed::Staged::unverified().result.render(&prepared));
        };
        if let Some(worker) = self.worker.as_mut() {
            worker.managed_program = Some(transaction.job.binding.program.clone());
        }
        let mut primary_failed = false;
        let mut acceptance = transaction.cutoff();
        let mut staged = if !transaction.has_work() {
            transaction.stage_no_work(&prepared)
        } else if managed::remaining_ms(cutoff) == 0 {
            managed::Staged::unverified()
        } else {
            match offer.executor {
                crate::analysis::managed::Executor::ForkHere => {
                    let mut direct = false;
                    let mut job = transaction.job.clone();
                    job.remaining_ms = managed::remaining_ms(cutoff);
                    let reply = self.worker.as_mut().map(|worker| {
                        exchange_observing(
                            worker,
                            managed::optional_request(job, offer.executor),
                            dispatched + self.options.worker_timeout,
                            &self.options,
                            |launched| direct = launched,
                        )
                    });
                    match reply {
                        Some(Ok(response)) => transaction.stage_reply(
                            &prepared,
                            response,
                            direct,
                            &self.data.info,
                            &context,
                        ),
                        Some(Err(error)) if error.code == ErrorCode::Cancelled => {
                            self.decision_book.cancel(&transaction);
                            self.stop();
                            return Err(error);
                        }
                        Some(Err(error)) => {
                            primary_failed = error.code != ErrorCode::CommandFailed
                                && error.message != "Request is too large";
                            let expired = error.code == ErrorCode::Timeout
                                || error.message.starts_with("Analysis worker exited:");
                            transaction.stage_fallback(direct && expired, false)
                        }
                        None => managed::Staged::unverified(),
                    }
                }
                crate::analysis::managed::Executor::Sibling => {
                    let _trace = crate::performance::context(transaction.job.ticket.logical_id);
                    match self.run_peer(transaction.job.clone(), offer, hard, published) {
                        Ok(Some((end, timing))) => {
                            acceptance = timing.acceptance();
                            let settled = Instant::now();
                            let code = end.code();
                            let staged = match end {
                                managed::PeerEnd::Finished(outcome) => transaction.stage_outcome(
                                    &prepared,
                                    *outcome,
                                    &self.data.info,
                                    &context,
                                ),
                                // Only an acknowledged direct attempt
                                // defers the target.
                                managed::PeerEnd::Expired => {
                                    transaction.stage_fallback(true, false)
                                }
                                managed::PeerEnd::NotLaunched(_)
                                | managed::PeerEnd::RenderCutoff => {
                                    transaction.stage_fallback(false, false)
                                }
                                managed::PeerEnd::SetupCutoff(_) => {
                                    transaction.stage_setup_cutoff()
                                }
                                managed::PeerEnd::Invalid | managed::PeerEnd::Cancelled => {
                                    managed::Staged::unverified()
                                }
                            };
                            crate::performance::interval(
                                "sibling_settlement",
                                settled,
                                Instant::now(),
                                code,
                            );
                            staged
                        }
                        Ok(None) => managed::Staged::unverified(),
                        Err(error) => {
                            self.decision_book.cancel(&transaction);
                            return Err(error);
                        }
                    }
                }
            }
        };
        if self.options.cancellation.is_cancelled() {
            self.decision_book.cancel(&transaction);
            self.stop();
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        if !self
            .decision_book
            .accept_until(&transaction, &mut staged, acceptance)
        {
            staged = managed::Staged::unverified();
        }
        if primary_failed {
            self.stop();
            self.recover_optional_primary = true;
        }
        Ok(staged.result.render(&prepared))
    }

    /// The committed signature context the worker renders under.
    fn signature_context(&self) -> String {
        if self.data.session.signatures.is_empty() {
            String::new()
        } else {
            crate::signatures::state_digest(&self.data.session.signatures)
        }
    }

    /// Runs one sibling attempt to its end, with its timing, or `None`
    /// without a primary worker. A setup allowance already spent before the
    /// peer starts ends as a setup cutoff.
    fn run_peer(
        &mut self,
        job: crate::analysis::managed::PeerJob,
        offer: &crate::analysis::managed::DebugOffer,
        hard: Instant,
        published: Instant,
    ) -> Result<
        Option<(
            crate::client::managed_decompile::PeerEnd,
            Arc<crate::client::managed_decompile::PeerTiming>,
        )>,
        Error,
    > {
        use crate::client::managed_decompile as managed;
        let Some(worker) = self.worker.as_ref() else {
            return Ok(None);
        };
        let context = if let Some(context) = &self.peer_context {
            Arc::clone(context)
        } else {
            let context = Arc::new(managed::PeerContext {
                launch: worker.peer_launch(),
                enabled: self.data.use_debug_info,
                skip: self.data.debug_skip.clone(),
                info: Arc::new(self.data.info.clone()),
                debug_state: self.data.debug_state.clone(),
                functions: Arc::new(effective_functions(&self.data)),
                long_names: Vec::new(),
                signatures: Arc::new(self.data.session.signatures.clone()),
                unapplied: self.unapplied_signatures.clone(),
                signature_context: self.signature_context(),
            });
            self.peer_context = Some(Arc::clone(&context));
            context
        };
        let floor = self.options.optional_floor;
        let slot = context.launch.slot.clone();
        let grace = self
            .options
            .optional_setup
            .unwrap_or_else(|| managed::setup_grace(slot.setup_sample(), floor));
        let timing = Arc::new(managed::PeerTiming::new(
            published,
            grace,
            managed::render_allowance(offer.reference_us, floor),
            hard,
        ));
        managed::trace_budget(&timing, published, hard, grace, slot.setup_sample());
        // Host work since publication may already have spent the setup
        // allowance (a slow host or a tiny test allowance): that is a setup
        // cutoff before any peer, not an unverified settlement.
        if let Some(end) = timing.spent_setup(Instant::now()) {
            crate::performance::event("sibling_no_budget", 0);
            return Ok(Some((end, timing)));
        }
        // A peer cancelled at an earlier cutoff may still be reaping; this
        // synchronous host waits for it within the setup allowance, and a
        // cancellation ends the wait without reserving.
        let token = self.options.cancellation.clone();
        let waiting = Instant::now();
        let reservation = match slot.wait_reserve(timing.setup_until(), &|| token.is_cancelled()) {
            managed::Reserve::Reserved(reservation) => reservation,
            managed::Reserve::Cancelled => {
                return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
            }
            managed::Reserve::Deadline => {
                return Ok(timing.expire(Instant::now()).map(|_| {
                    (
                        managed::PeerEnd::SetupCutoff(managed::SetupStage::Retirement),
                        Arc::clone(&timing),
                    )
                }));
            }
        };
        crate::performance::interval("sibling_retirement", waiting, Instant::now(), 0);
        let cancelled: Arc<dyn Fn() -> bool + Send + Sync> = {
            let token = token.clone();
            Arc::new(move || token.is_cancelled())
        };
        let run = match managed::start_peer(
            context,
            job,
            reservation,
            Arc::clone(&timing),
            Some(cancelled),
            || {},
        ) {
            Ok(run) => run,
            Err(error) => return Ok(Some((managed::PeerEnd::NotLaunched(error), timing))),
        };
        loop {
            if token.is_cancelled() {
                run.cancel();
                // The attempt thread reports before it reaps the peer.
                let _ = run.wait(Instant::now() + Duration::from_secs(10));
                return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
            }
            // Always the current phase's deadline: readiness moves it.
            let now = Instant::now();
            let deadline = run.deadline();
            if now >= deadline
                && let Some(end) = run.expire(now)
            {
                return Ok(Some((end, timing)));
            }
            // Before the deadline, or after an attempt that finished on its
            // own (its end is on the way): wait in short steps.
            let step = now + Duration::from_millis(20);
            if let Some(end) = run.wait(if deadline > now {
                deadline.min(step)
            } else {
                step
            }) {
                return Ok(Some((end, timing)));
            }
        }
    }

    /// One bounded discovery step. A failed step returns its error after
    /// [`Discovery::interrupt`] has re-queued or failed the in-flight seeds,
    /// keeping all committed evidence. With unfinished work and no worker, the
    /// next call first starts a verified replacement under the shared cap.
    fn discover(&mut self) -> Result<Output, Error> {
        if self.options.cancellation.is_cancelled() {
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        // Saved discovery is display data: a run always starts fresh.
        let mut state = self.discovery.take().unwrap_or_else(|| {
            let info = &self.data.info;
            let mut state = Discovery::new(
                crate::call_analysis::code_address(info, info.entry).then_some(info.entry),
                info.functions.iter().map(|v| v.address),
                info.functions_truncated,
            );
            if Discovery::patterns_apply(info) {
                state.start_sources(info.architecture == "x86-64" && info.format == "ELF");
            }
            state
        });
        let unfinished = state.remaining() != 0 || state.scanning();
        let result = if unfinished && self.worker.is_none() {
            self.restart()
        } else {
            Ok(())
        }
        .and_then(|()| self.discovery_step(&mut state));
        if result.is_err() {
            state.interrupt();
        }
        let complete = state.remaining() == 0 && !state.scanning();
        let snapshot = state.save();
        // Checkpoints keep committed evidence, including after a failed step.
        self.data.discovery = Some(Arc::new(snapshot.clone()));
        self.discovery = Some(state);
        result.map(|()| Output::Discovery {
            snapshot: Box::new(snapshot),
            complete,
        })
    }

    fn discovery_step(&mut self, state: &mut Discovery) -> Result<(), Error> {
        let Some(mut request) = state.begin(1, self.worker_epoch, 0) else {
            return Ok(());
        };
        let requested = self
            .inventory
            .as_ref()
            .filter(|inventory| inventory.epoch() == self.worker_epoch)
            .map(WorkerInventory::revision);
        if let Request::DiscoverBatch { inventory_base, .. } = &mut request {
            *inventory_base = requested;
        }
        let Response::DiscoveryBatch { mut batch } = self.request(request)? else {
            return self.unexpected();
        };
        let commit = state.commit_reply(
            &self.data.info,
            self.inventory.as_ref(),
            requested,
            &mut batch,
        );
        match commit.map_err(|e| Error::new(ErrorCode::WorkerFailed, e))? {
            crate::discovery::ReplyCommit::Adopted(inventory, changed) => {
                if changed {
                    self.data.info.functions = inventory.functions().to_vec();
                }
                self.data.info.functions_truncated = batch.truncated;
                self.inventory = Some(inventory);
                if changed {
                    self.graph = None;
                    self.code = None;
                    self.update_context();
                    self.wait_context()?;
                }
            }
            crate::discovery::ReplyCommit::PatternBudgetExhausted => {
                self.inventory = None;
                state.interrupt();
            }
        }
        Ok(())
    }

    /// Starts a replacement worker for the same verified image. Its identity,
    /// hash and mapping must match the session; the controller's names and
    /// signatures are replayed before any analysis. Each attempt, successful
    /// or not, spends one of the session's [`MAX_DISCOVERY_RESUMES`].
    fn restart(&mut self) -> Result<(), Error> {
        self.restart_worker(true)
    }
    fn restart_worker(&mut self, discovery: bool) -> Result<(), Error> {
        if discovery && self.discovery_resumes >= MAX_DISCOVERY_RESUMES {
            return Err(Error::new(
                ErrorCode::SessionClosed,
                "Discovery worker restarts are exhausted; open a new analysis session",
            ));
        }
        if discovery {
            self.discovery_resumes += 1;
        }
        self.worker_epoch = self.worker_epoch.wrapping_add(1);
        let (mut worker, opened, enabled) = start_open_worker(
            &self.binary_path,
            &self.executable,
            self.source.as_ref(),
            &self.options,
            self.data.use_debug_info,
            &self.data.debug_skip,
        )?;
        self.data.use_debug_info = enabled;
        if crate::debug_info::has_open_fallback(&opened.info) {
            crate::debug_info::record_open_fallback(&mut self.data.info);
        }
        if !opened.protection.same_source(&self.protection)
            || !crate::project::same_image(&self.data.info, &opened.info)
        {
            return Err(Error::new(
                ErrorCode::WorkerFailed,
                "Binary changed on disk; open a new analysis session",
            ));
        }
        self.protection
            .inherit_debug_sources(&opened.protection)
            .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
        if self.data.debug_state != opened.debug_state {
            self.data.debug_state = opened.debug_state;
            self.data.debug_source = opened.debug_source;
            self.data.decompiled = None;
            self.data.mappings.clear();
            self.data.semantics = Default::default();
            self.results.set_debug_state(&self.data.debug_state);
        }
        self.unapplied_signatures = replay(&mut worker, &self.data, &self.options)?;
        self.inventory = None;
        self.worker = Some(worker);
        self.recover_optional_primary = false;
        Ok(())
    }

    fn linkage(&mut self, cursor: usize, digest: Option<String>) -> Result<Output, Error> {
        if cursor == 0 {
            if digest.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "Start linkage at cursor 0 without a digest",
                ));
            }
            self.reset_linkage();
        } else if self.linkage.as_ref().is_none_or(|fetch| {
            fetch.cursor() != Some(cursor)
                || digest.as_deref() != Some(fetch.summary().digest.as_str())
        }) {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "Continue linkage with its exact cursor and digest",
            ));
        }
        let response = self.request(Request::Linkage { cursor, digest });
        // A failed page ends this fetch; restart it at cursor 0.
        let Response::Linkage { summary, page } = response.inspect_err(|_| self.reset_linkage())?
        else {
            return self.unexpected();
        };
        if self.linkage.is_none() {
            self.linkage = Some(
                crate::linkage::LinkageFetch::new(summary.clone(), &self.data.info.sha256)
                    .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?,
            );
        }
        let fetch = self.linkage.as_mut().expect("initialized fetch");
        if fetch.summary() != &summary || page.cursor != cursor || page.digest != summary.digest {
            return self.unexpected();
        }
        if summary.records() != 0 {
            fetch
                .accept(page.clone(), &self.data.info)
                .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
        } else if !page.entries.is_empty() || page.next.is_some() {
            return self.unexpected();
        }
        let bytes = fetch.estimated_bytes().unwrap_or(usize::MAX);
        if !self.results.set_linkage_bytes(bytes) {
            self.reset_linkage();
            return Err(Error::new(
                ErrorCode::ResponseTooLarge,
                "Linkage accumulation exceeds the shared memory budget",
            ));
        }
        if page.next.is_none() {
            self.reset_linkage();
        }
        Ok(Output::Linkage { summary, page })
    }

    fn unexpected<T>(&mut self) -> Result<T, Error> {
        self.stop();
        Err(Error::new(
            ErrorCode::WorkerFailed,
            "Worker reply does not match the requested operation",
        ))
    }
}

impl Drop for Analyzer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn exchange(
    worker: &mut WorkerClient,
    request: Request,
    options: &Options,
) -> Result<Response, Error> {
    let deadline = Instant::now() + options.worker_timeout;
    exchange_until(worker, request, deadline, options)
}

/// [`exchange`] bounded by an absolute deadline (never later than the
/// worker timeout after sending).
fn exchange_until(
    worker: &mut WorkerClient,
    request: Request,
    deadline: Instant,
    options: &Options,
) -> Result<Response, Error> {
    exchange_observing(worker, request, deadline, options, |_| {})
}

fn exchange_observing(
    worker: &mut WorkerClient,
    request: Request,
    deadline: Instant,
    options: &Options,
    mut debug_started: impl FnMut(bool),
) -> Result<Response, Error> {
    let id = worker
        .send(request)
        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
    let started = Instant::now();
    let deadline = deadline.min(started + options.worker_timeout);
    let mut progress = None;
    let mut events = 0;
    loop {
        if options.cancellation.is_cancelled() {
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        let expired = || {
            Error::new(
                ErrorCode::Timeout,
                "Worker request exceeded its wall-time deadline",
            )
        };
        // A known rejection (a reply the client refused, or one for another
        // request) is reported as such even when it arrives late; only an
        // otherwise acceptable late event, or process loss, is the deadline.
        match worker.poll_timed() {
            Some((ready, WorkerEvent::Failed(message))) => {
                if ready > deadline
                    && worker.failure() != Some(crate::client::FailureKind::Rejected)
                {
                    return Err(expired());
                }
                return Err(Error::new(ErrorCode::WorkerFailed, message));
            }
            Some((ready, WorkerEvent::Reply(reply))) => {
                if reply.id != id {
                    return Err(Error::new(
                        ErrorCode::WorkerFailed,
                        "Worker replied to a different request",
                    ));
                }
                if ready > deadline {
                    return Err(expired());
                }
                if let Response::DebugStarted { direct, .. } = reply.response {
                    debug_started(direct);
                    continue;
                }
                if let Response::Progress { progress: next } = reply.response {
                    events += 1;
                    next.validate_event(events, progress.as_ref())
                        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
                    progress = Some(next);
                    continue;
                }
                match reply.response {
                    Response::Error { message } => {
                        return Err(Error::new(ErrorCode::CommandFailed, message));
                    }
                    Response::DiscoveryBatch { ref batch } => batch
                        .analysis
                        .validate_final(progress.as_ref())
                        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?,
                    _ if progress.is_some() => {
                        return Err(Error::new(
                            ErrorCode::WorkerFailed,
                            "Unexpected analysis progress",
                        ));
                    }
                    _ => {}
                }
                return Ok(reply.response);
            }
            None => {
                if Instant::now() >= deadline {
                    return Err(expired());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}
