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
use crate::project::{ProjectData, SavedFunction};
use crate::result_store::{ResultOrigin, Shared};
use crate::session::{BinaryProtection, Session};
use serde::{Deserialize, Serialize};

pub mod protocol;

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
    /// May shorten, but never extend, the production worker deadline.
    pub worker_timeout: Duration,
    pub cancellation: CancellationToken,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            output_project: None,
            worker_timeout: WORKER_REQUEST_TIMEOUT,
            cancellation: CancellationToken::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    UnsupportedVersion,
    InvalidAddress,
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
/// Errors in the worker transport, cancellation, and timeouts close the worker;
/// completed results remain owned until this controller is dropped.
pub struct Analyzer {
    worker: Option<WorkerClient>,
    data: ProjectData,
    protection: BinaryProtection,
    options: Options,
    results: FunctionResults,
    graph: Option<Shared<PreparedGraph>>,
    code: Option<Shared<PreparedDecompilation>>,
    discovery: Option<Discovery>,
    inventory: Option<WorkerInventory>,
    unapplied_signatures: Vec<SignatureStatus>,
    linkage: Option<crate::linkage::LinkageFetch>,
}

impl Analyzer {
    /// `executable` is selected by the host, supports `--analysis-worker`, and
    /// must be trusted. Project source hints are never opened automatically.
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
        let mut worker = WorkerClient::start_using_executable(
            eframe::egui::Context::default(),
            &path,
            executable,
        )
        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
        if let Some(binary) = project.as_ref().and_then(|p| p.binary.as_ref()) {
            worker.retain_source(Arc::new(binary.clone()));
        }
        let actual_path = worker
            .protection()
            .path()
            .to_str()
            .ok_or_else(|| Error::new(ErrorCode::InvalidRequest, "The binary path must be UTF-8"))?
            .to_owned();
        let response = exchange(&mut worker, Request::Open { path: actual_path }, &options)?;
        let Response::Opened {
            mut info,
            macho_legacy,
            ..
        } = response
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
        let mut data = if let Some(mut project) = project {
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
        // Replay complete effective names before prototypes, and prototypes before analysis.
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
        let effective: Vec<_> = data
            .info
            .functions
            .iter()
            .map(|function| {
                let mut end = function.name.len().min(MAX_FUNCTION_NAME_BYTES);
                while !function.name.is_char_boundary(end) {
                    end -= 1;
                }
                FunctionInfo {
                    address: function.address,
                    name: function.name[..end].into(),
                }
            })
            .collect();
        for chunk in sync_chunks(&effective) {
            if !matches!(
                exchange(
                    &mut worker,
                    Request::SyncFunctions {
                        functions: chunk.to_vec()
                    },
                    &options
                )?,
                Response::FunctionsSynced
            ) {
                return Err(Error::new(
                    ErrorCode::WorkerFailed,
                    "Unexpected function synchronization reply",
                ));
            }
        }
        let mut unapplied_signatures = Vec::new();
        if !data.session.signatures.is_empty() {
            let context = crate::signatures::state_digest(&data.session.signatures);
            match exchange(
                &mut worker,
                Request::SyncSignatures {
                    binary_sha256: data.info.sha256.clone(),
                    context: context.clone(),
                    signatures: data.session.signatures.clone(),
                },
                &options,
            )? {
                Response::SignaturesSynced {
                    binary_sha256,
                    context: actual,
                    unapplied,
                } if binary_sha256 == data.info.sha256 && actual == context => {
                    unapplied_signatures = unapplied
                }
                _ => {
                    return Err(Error::new(
                        ErrorCode::WorkerFailed,
                        "Unexpected signature synchronization reply",
                    ));
                }
            }
        }
        let mut analyzer = Self {
            worker: Some(worker),
            data,
            protection,
            options,
            results: FunctionResults::default(),
            graph: None,
            code: None,
            discovery: None,
            inventory: None,
            unapplied_signatures,
            linkage: None,
        };
        analyzer.results.open(
            &analyzer.data.info.sha256,
            &analyzer.data.session.signatures,
        );
        analyzer.update_context()?;
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
                "The worker stopped; open a new analysis session",
            ));
        }
        Ok(())
    }

    fn request(&mut self, request: Request) -> Result<Response, Error> {
        self.active()?;
        let response = exchange(
            self.worker.as_mut().expect("active worker"),
            request,
            &self.options,
        );
        if response.is_err() {
            self.stop();
        }
        response
    }

    fn stop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.stop_and_wait();
        }
    }

    fn update_context(&mut self) -> Result<(), Error> {
        self.results.update_inputs(
            self.data.info.functions.clone(),
            self.data.session.local_renames.clone(),
        );
        let deadline = Instant::now() + self.options.worker_timeout;
        while self.results.preparing() {
            self.active()?;
            if Instant::now() >= deadline {
                self.stop();
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
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        self.active()?;
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
                let path = self.options.output_project.as_ref().ok_or_else(|| {
                    Error::new(
                        ErrorCode::InvalidRequest,
                        "Configure --output-project before requesting a checkpoint",
                    )
                })?;
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
                .collect();
            let Response::Decompiled {
                address: actual,
                text,
                mappings,
                semantics,
            } = self.request(Request::DecompileWithLocals { address, renames })?
            else {
                return self.unexpected();
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

    fn discover(&mut self) -> Result<Output, Error> {
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
        if let Some(mut request) = state.begin(1, 1, 0) {
            let requested = self.inventory.as_ref().map(WorkerInventory::revision);
            if let Request::DiscoverBatch { inventory_base, .. } = &mut request {
                *inventory_base = requested;
            }
            let Response::DiscoveryBatch { mut batch } = self.request(request)? else {
                return self.unexpected();
            };
            match state
                .commit_reply(
                    &self.data.info,
                    self.inventory.as_ref(),
                    requested,
                    &mut batch,
                )
                .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?
            {
                crate::discovery::ReplyCommit::Adopted(inventory, changed) => {
                    if changed {
                        self.data.info.functions = inventory.functions().to_vec();
                    }
                    self.data.info.functions_truncated = batch.truncated;
                    self.inventory = Some(inventory);
                    if changed {
                        self.graph = None;
                        self.code = None;
                        self.update_context()?;
                    }
                }
                crate::discovery::ReplyCommit::PatternBudgetExhausted => {
                    self.inventory = None;
                    state.interrupt();
                }
            }
        }
        let complete = state.remaining() == 0 && !state.scanning();
        let snapshot = state.save();
        self.data.discovery = Some(Arc::new(snapshot.clone()));
        self.discovery = Some(state);
        Ok(Output::Discovery {
            snapshot: Box::new(snapshot),
            complete,
        })
    }

    fn linkage(&mut self, cursor: usize, digest: Option<String>) -> Result<Output, Error> {
        if cursor == 0 {
            if digest.is_some() {
                return Err(Error::new(
                    ErrorCode::InvalidRequest,
                    "Start linkage at cursor 0 without a digest",
                ));
            }
            self.linkage = None;
            self.results.set_linkage_bytes(0);
        } else if self.linkage.as_ref().is_none_or(|fetch| {
            fetch.cursor() != Some(cursor)
                || digest.as_deref() != Some(fetch.summary().digest.as_str())
        }) {
            return Err(Error::new(
                ErrorCode::InvalidRequest,
                "Continue linkage with its exact cursor and digest",
            ));
        }
        let Response::Linkage { summary, page } =
            self.request(Request::Linkage { cursor, digest })?
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
            self.linkage = None;
            self.results.set_linkage_bytes(0);
            return Err(Error::new(
                ErrorCode::ResponseTooLarge,
                "Linkage accumulation exceeds the shared memory budget",
            ));
        }
        if page.next.is_none() {
            self.linkage = None;
            self.results.set_linkage_bytes(0);
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
    let id = worker
        .send(request)
        .map_err(|e| Error::new(ErrorCode::WorkerFailed, e))?;
    let started = Instant::now();
    let mut progress = None;
    let mut events = 0;
    loop {
        if options.cancellation.is_cancelled() {
            return Err(Error::new(ErrorCode::Cancelled, "Analysis cancelled"));
        }
        if started.elapsed() >= options.worker_timeout {
            return Err(Error::new(
                ErrorCode::Timeout,
                "Worker request exceeded its wall-time deadline",
            ));
        }
        match worker.poll() {
            Some(WorkerEvent::Failed(message)) => {
                return Err(Error::new(ErrorCode::WorkerFailed, message));
            }
            Some(WorkerEvent::Reply(reply)) => {
                if reply.id != id {
                    return Err(Error::new(
                        ErrorCode::WorkerFailed,
                        "Worker replied to a different request",
                    ));
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
                        return Err(Error::new(ErrorCode::WorkerFailed, message));
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
            None => std::thread::sleep(Duration::from_millis(2)),
        }
    }
}
