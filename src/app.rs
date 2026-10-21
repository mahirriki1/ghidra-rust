//! Native desktop shell. Blocking analysis is disposable process work; dialogs
//! and sidecar I/O run on bounded background jobs, with generation-bound results.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, ScrollArea, TextEdit};

use crate::annotation_display::{AnnotationBrowser, CodeRow, CommentRows};
use crate::client::{WorkerClient, WorkerEvent};
use crate::decoder_ui::{DecoderAction, DecoderPanel};
use crate::discovery::DiscoverySnapshot;
use crate::file_dialog::{FileDialogKind, FileDialogs, request_file};
use crate::graph::{GraphAction, GraphCanvas};
use crate::highlight::HighlightedCode;
use crate::model::*;
use crate::project::{EmbeddedBinary, LoadedProject, ProjectData};
use crate::selection::{SemanticSelection, validate_mappings};
use crate::semantic::{LocalIdentity, LocalRename, SemanticInfo, TokenKind};
use crate::session::{Annotation, BinaryProtection, Session};
use crate::theme;

const DEADLINE: Duration = Duration::from_secs(30);
const HISTORY_LIMIT: usize = 32;
const UNDO_BYTES: usize = 4 * 1024 * 1024;
/// Per-frame work for the function filter, keeping typing responsive.
const FILTER_FRAME_BUDGET: Duration = Duration::from_millis(4);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Tab {
    Graph,
    #[default]
    Listing,
    Strings,
    Crypto,
    Decode,
    References,
}

#[derive(Clone)]
enum BrowserDialogKind {
    Rename { address: u64, function: bool },
    GoTo,
    RenameLocal { identity: LocalIdentity },
}

struct BrowserDialog {
    kind: BrowserDialogKind,
    text: String,
    error: Option<String>,
    focus: bool,
    generation: u64,
}

#[derive(Clone, Copy)]
enum Shortcut {
    Rename,
    GoTo,
    Comment,
    ToggleGraph,
    Back,
    Forward,
    Save,
    Undo,
}

fn shortcut(event: &egui::Event) -> Option<Shortcut> {
    let egui::Event::Key {
        key,
        pressed: true,
        repeat: false,
        modifiers,
        ..
    } = event
    else {
        return None;
    };
    let plain = !modifiers.alt
        && !modifiers.ctrl
        && !modifiers.shift
        && !modifiers.mac_cmd
        && !modifiers.command;
    if plain {
        return match key {
            egui::Key::L => Some(Shortcut::Rename),
            egui::Key::G => Some(Shortcut::GoTo),
            egui::Key::Semicolon => Some(Shortcut::Comment),
            egui::Key::Space => Some(Shortcut::ToggleGraph),
            _ => None,
        };
    }
    if modifiers.alt
        && !modifiers.ctrl
        && !modifiers.shift
        && !modifiers.mac_cmd
        && !modifiers.command
    {
        return match key {
            egui::Key::ArrowLeft => Some(Shortcut::Back),
            egui::Key::ArrowRight => Some(Shortcut::Forward),
            _ => None,
        };
    }
    if (modifiers.command || modifiers.ctrl) && !modifiers.alt && !modifiers.shift {
        return match key {
            egui::Key::S => Some(Shortcut::Save),
            egui::Key::Z => Some(Shortcut::Undo),
            _ => None,
        };
    }
    None
}

fn info_without_functions(info: &BinaryInfo) -> BinaryInfo {
    BinaryInfo {
        path: String::new(),
        architecture: info.architecture.clone(),
        format: info.format.clone(),
        entry: info.entry,
        file_len: info.file_len,
        sha256: info.sha256.clone(),
        source_identity: info.source_identity,
        sections: info.sections.clone(),
        functions: vec![],
        functions_truncated: info.functions_truncated,
        warnings: vec![],
    }
}

/// UI annotation labels can be longer than worker inventory names.
fn inventory_name(name: &str) -> &str {
    let mut end = name.len().min(MAX_FUNCTION_NAME_BYTES);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    &name[..end]
}

/// Addresses whose displayed inventory entry a freshly opened worker lacks.
fn replay_addresses(worker: &[FunctionInfo], desired: &[FunctionInfo]) -> VecDeque<u64> {
    desired
        .iter()
        .filter(|function| {
            function_at(worker, function.address)
                .is_none_or(|current| current.name != inventory_name(&function.name))
        })
        .map(|function| function.address)
        .collect()
}

struct DiscoveryPublication {
    /// Display inventory when the batch changed it.
    functions: Option<Vec<FunctionInfo>>,
    inventory: crate::discovery::WorkerInventory,
    truncated: bool,
    index: crate::call_analysis::CallIndex,
}

struct DiscoveryUpdate {
    generation: u64,
    state: crate::discovery::Discovery,
    /// Committed results for project saves, built off the GUI thread.
    saved: Arc<DiscoverySnapshot>,
    publication: Result<Option<DiscoveryPublication>, String>,
}

struct Pending {
    id: u64,
    request: Request,
    started: Instant,
    selection: u64,
    revision: u64,
    byte_origin: (Option<u64>, Tab),
}

struct Opening {
    path: PathBuf,
    preserve: bool,
    follow: Option<Request>,
    revision: u64,
    follow_origin: RequestOrigin,
}

#[derive(Clone, Copy)]
struct RequestOrigin {
    selection: u64,
    revision: u64,
    byte_origin: (Option<u64>, Tab),
}

/// Analyses offered by the auto-analysis dialog; kept for the session.
#[derive(Clone, Copy)]
struct AnalysisOptions {
    functions: bool,
    strings: bool,
    crypto: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            functions: true,
            strings: true,
            crypto: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnalysisStep {
    Strings,
    Crypto,
    Functions,
}

impl AnalysisStep {
    fn label(self) -> &'static str {
        match self {
            Self::Strings => "defined strings",
            Self::Crypto => "FindCrypt constants",
            Self::Functions => "function discovery",
        }
    }

    fn owns(self, request: &Request) -> bool {
        matches!(
            (self, request),
            (
                Self::Strings,
                Request::Strings | Request::StringsWithOptions { .. }
            ) | (Self::Crypto, Request::Crypto)
        )
    }
}

struct AnalyzePrompt {
    generation: u64,
    first_open: bool,
}

/// Selected analyses run one at a time whenever the worker is otherwise idle,
/// so they never preempt navigation or each other.
struct AnalysisPlan {
    generation: u64,
    steps: VecDeque<AnalysisStep>,
    current: Option<AnalysisStep>,
    total: usize,
}

#[derive(Clone)]
enum Intent {
    OpenDialog,
    OpenProjectDialog,
    OpenProjectPath(PathBuf),
    OpenPath(PathBuf),
    Close,
    Quit,
    LoadAnnotations,
}

enum FileEvent {
    Chosen(Option<PathBuf>),
    ProjectChosen(Option<PathBuf>),
    Saved {
        generation: u64,
        revision: u64,
        result: Result<Option<PathBuf>, String>,
    },
    ProjectSaved {
        generation: u64,
        revision: u64,
        embedded: bool,
        result: Result<Option<PathBuf>, String>,
    },
    ProjectLoaded {
        generation: u64,
        revision: u64,
        result: Result<Option<Box<ProjectOpen>>, String>,
    },
    Loaded {
        generation: u64,
        revision: u64,
        hash: String,
        result: Result<Option<(Session, PathBuf)>, String>,
    },
}

struct ProjectOpen {
    project: LoadedProject,
    project_path: PathBuf,
    binary_path: PathBuf,
    /// Prepared by the file job, so restoring a large reference index never
    /// sorts or allocates its lookup tables on the GUI thread.
    discovery_index: Option<crate::call_analysis::CallIndex>,
}

struct Edit {
    address: u64,
    before: Option<Annotation>,
    function_name: Option<String>,
    local: Option<(LocalIdentity, Option<LocalRename>)>,
}

pub struct DesktopApp {
    client: Option<WorkerClient>,
    pending: Option<Pending>,
    opening: Option<Opening>,
    queue: VecDeque<Request>,
    applied_names: BTreeMap<u64, String>,
    info: Option<BinaryInfo>,
    binary_path: Option<PathBuf>,
    binary_protection: Option<BinaryProtection>,
    session: Option<Session>,
    session_path: Option<PathBuf>,
    project_path: Option<PathBuf>,
    project_binary: Option<EmbeddedBinary>,
    opening_project: Option<Box<ProjectOpen>>,
    embed_binary: bool,
    generation: u64,
    selection_generation: u64,
    revision: u64,
    saved_revision: u64,
    undo: VecDeque<Edit>,
    view: Option<FunctionView>,
    call_index: Option<crate::call_analysis::CallIndex>,
    discovery: Option<crate::discovery::Discovery>,
    discovery_job: Option<Receiver<DiscoveryUpdate>>,
    discovery_running: bool,
    discovery_summary: Option<String>,
    worker_epoch: u64,
    /// The inventory last adopted from the current worker. Batch requests name
    /// its revision while `inventory_synced` records that `info.functions` is
    /// still that inventory; every other inventory write clears it.
    worker_inventory: Option<crate::discovery::WorkerInventory>,
    inventory_synced: bool,
    discovery_sync: Option<VecDeque<u64>>,
    discovery_bytes: Option<(Request, RequestOrigin)>,
    /// What a project save stores: the latest committed session results, or
    /// the restored project's snapshot until discovery runs again.
    discovery_saved: Option<Arc<DiscoverySnapshot>>,
    /// References and summary came from a project rather than this session.
    saved_references: bool,
    analysis_options: AnalysisOptions,
    analyze_prompt: Option<AnalyzePrompt>,
    analysis_plan: Option<AnalysisPlan>,
    reference_data: bool,
    reference_target: Option<u64>,
    reference_query: String,
    analysis_progress: Option<AnalysisProgress>,
    progress_events: usize,
    reference_focus: Option<(u64, u64)>,
    undisplayed_call: Option<u64>,
    canvas: Option<GraphCanvas>,
    listing: Vec<Instruction>,
    decompiled: String,
    decompiled_lines: Vec<(usize, usize)>,
    highlighted: Option<HighlightedCode>,
    saved_analysis: bool,
    cached_graph: bool,
    cached_functions: bool,
    cached_strings: bool,
    cached_crypto: bool,
    semantic: SemanticSelection,
    semantic_info: SemanticInfo,
    selected_local: Option<usize>,
    decompiler_rename_context: bool,
    pending_code_scroll: Option<usize>,
    pending_comment_scroll: Option<u64>,
    pending_listing_scroll: Option<usize>,
    auto_decompile: bool,
    selected: Option<u64>,
    history: Vec<u64>,
    history_index: usize,
    function_filter: String,
    filtered_functions: Vec<usize>,
    /// Lowercased effective labels, aligned with `info.functions` and valid for
    /// `filter_keys_revision`.
    filter_keys: Vec<String>,
    filter_keys_revision: u64,
    filter_query: String,
    /// Next inventory index to examine while a filter is in progress.
    filter_cursor: Option<usize>,
    string_filter: String,
    string_minimum: usize,
    strings_minimum_used: Option<usize>,
    strings: Vec<StringEntry>,
    strings_truncated: bool,
    strings_scanned: bool,
    filtered_strings: Vec<usize>,
    crypto: Vec<CryptoMatch>,
    crypto_truncated: bool,
    tab: Tab,
    address: String,
    name_edit: String,
    comment_edit: String,
    annotation_browser: AnnotationBrowser,
    comment_rows: CommentRows,
    comment_rows_key: Option<(u64, u64, u64)>,
    /// Only exact PCs observed in a recovered CFG or genuine print mapping.
    comment_owners: BTreeMap<u64, u64>,
    editor_address: Option<u64>,
    decoder: DecoderPanel,
    status: String,
    file_job: Option<Receiver<FileEvent>>,
    file_dialogs: FileDialogs,
    intent: Option<Intent>,
    after_save: Option<Intent>,
    initial_path: Option<PathBuf>,
    quit_confirmed: bool,
    annotations_open: bool,
    program_tree: bool,
    browser_dialog: Option<BrowserDialog>,
    focus_comment: bool,
}

impl DesktopApp {
    pub fn new(cc: &eframe::CreationContext<'_>, initial_path: Option<PathBuf>) -> Self {
        let _startup = crate::performance::span("gui_state_creation");
        theme::install(&cc.egui_ctx);
        Self::empty(initial_path)
    }

    fn empty(initial_path: Option<PathBuf>) -> Self {
        Self {
            client: None,
            pending: None,
            opening: None,
            queue: VecDeque::new(),
            applied_names: BTreeMap::new(),
            info: None,
            binary_path: None,
            binary_protection: None,
            session: None,
            session_path: None,
            project_path: None,
            project_binary: None,
            opening_project: None,
            embed_binary: true,
            generation: 0,
            selection_generation: 0,
            revision: 0,
            saved_revision: 0,
            undo: VecDeque::new(),
            view: None,
            call_index: None,
            discovery: None,
            discovery_job: None,
            discovery_running: false,
            discovery_summary: None,
            worker_epoch: 0,
            worker_inventory: None,
            inventory_synced: false,
            discovery_sync: None,
            discovery_bytes: None,
            discovery_saved: None,
            saved_references: false,
            analysis_options: AnalysisOptions::default(),
            analyze_prompt: None,
            analysis_plan: None,
            reference_data: false,
            reference_target: None,
            reference_query: String::new(),
            analysis_progress: None,
            progress_events: 0,
            reference_focus: None,
            undisplayed_call: None,
            canvas: None,
            listing: Vec::new(),
            decompiled: String::new(),
            decompiled_lines: Vec::new(),
            highlighted: None,
            saved_analysis: false,
            cached_graph: false,
            cached_functions: false,
            cached_strings: false,
            cached_crypto: false,
            semantic: SemanticSelection::default(),
            semantic_info: SemanticInfo::default(),
            selected_local: None,
            decompiler_rename_context: false,
            pending_code_scroll: None,
            pending_comment_scroll: None,
            pending_listing_scroll: None,
            auto_decompile: true,
            selected: None,
            history: Vec::new(),
            history_index: 0,
            function_filter: String::new(),
            filtered_functions: Vec::new(),
            filter_keys: Vec::new(),
            filter_keys_revision: 0,
            filter_query: String::new(),
            filter_cursor: None,
            string_filter: String::new(),
            string_minimum: 6,
            strings_minimum_used: None,
            strings: Vec::new(),
            strings_truncated: false,
            strings_scanned: false,
            filtered_strings: Vec::new(),
            crypto: Vec::new(),
            crypto_truncated: false,
            tab: Tab::Listing,
            address: String::new(),
            name_edit: String::new(),
            comment_edit: String::new(),
            annotation_browser: AnnotationBrowser::default(),
            comment_rows: CommentRows::default(),
            comment_rows_key: None,
            comment_owners: BTreeMap::new(),
            editor_address: None,
            decoder: DecoderPanel::default(),
            status: "Open a binary to begin".into(),
            file_job: None,
            file_dialogs: FileDialogs::default(),
            intent: None,
            after_save: None,
            initial_path,
            quit_confirmed: false,
            annotations_open: false,
            program_tree: false,
            browser_dialog: None,
            focus_comment: false,
        }
    }

    fn dirty(&self) -> bool {
        self.revision != self.saved_revision
    }

    fn request_intent(&mut self, intent: Intent, context: &egui::Context) {
        if self.file_job.is_some() {
            self.status = "Wait for the current file dialog or annotation operation".into();
        } else if self.dirty() && !matches!(intent, Intent::OpenDialog | Intent::OpenProjectDialog)
        {
            self.intent = Some(intent);
        } else {
            self.execute_intent(intent, context);
        }
    }

    fn execute_intent(&mut self, intent: Intent, context: &egui::Context) {
        match intent {
            Intent::OpenDialog => {
                let sender = self.file_dialogs.sender();
                let initial_dir = self.dialog_directory();
                self.file_task(context, move || {
                    FileEvent::Chosen(request_file(
                        &sender,
                        FileDialogKind::OpenBinary,
                        initial_dir,
                    ))
                });
            }
            Intent::OpenProjectDialog => {
                let sender = self.file_dialogs.sender();
                let initial_dir = self.dialog_directory();
                self.file_task(context, move || {
                    FileEvent::ProjectChosen(request_file(
                        &sender,
                        FileDialogKind::OpenProject,
                        initial_dir,
                    ))
                });
            }
            Intent::OpenProjectPath(path) => self.open_project(path, context),
            Intent::OpenPath(path) => {
                if is_project_path(&path) {
                    self.open_project(path, context);
                } else {
                    self.start_open(path, false, None, context);
                }
            }
            Intent::Close => self.clear_binary(),
            Intent::Quit => {
                self.quit_confirmed = true;
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Intent::LoadAnnotations => self.load_annotations(context),
        }
    }

    fn clear_binary(&mut self) {
        self.stop_worker();
        self.generation = self.generation.wrapping_add(1);
        self.info = None;
        self.binary_path = None;
        self.binary_protection = None;
        self.session = None;
        self.session_path = None;
        self.project_path = None;
        self.project_binary = None;
        self.opening_project = None;
        self.revision = 0;
        self.saved_revision = 0;
        self.undo.clear();
        self.clear_views();
        self.status = "Binary closed".into();
    }

    fn clear_views(&mut self) {
        self.worker_inventory = None;
        self.inventory_synced = false;
        self.discovery = None;
        self.discovery_job = None;
        self.discovery_running = false;
        self.discovery_summary = None;
        self.discovery_sync = None;
        self.discovery_bytes = None;
        self.discovery_saved = None;
        self.saved_references = false;
        self.analyze_prompt = None;
        self.analysis_plan = None;
        self.call_index = None;
        self.reference_data = false;
        self.reference_target = None;
        self.reference_query.clear();
        self.reference_focus = None;
        self.undisplayed_call = None;
        self.browser_dialog = None;
        self.focus_comment = false;
        self.view = None;
        self.canvas = None;
        self.listing.clear();
        self.decompiled.clear();
        self.semantic.clear();
        self.comment_rows_key = None;
        self.semantic_info = SemanticInfo::default();
        self.selected_local = None;
        self.decompiler_rename_context = false;
        self.pending_code_scroll = None;
        self.pending_comment_scroll = None;
        self.pending_listing_scroll = None;
        self.highlighted = None;
        self.saved_analysis = false;
        self.decompiled_lines.clear();
        self.cached_graph = false;
        self.cached_functions = false;
        self.cached_strings = false;
        self.cached_crypto = false;
        self.strings.clear();
        self.strings_minimum_used = None;
        self.strings_truncated = false;
        self.strings_scanned = false;
        self.filtered_strings.clear();
        self.crypto.clear();
        self.crypto_truncated = false;
        self.selected = None;
        self.editor_address = None;
        self.name_edit.clear();
        self.comment_edit.clear();
        self.history.clear();
        self.comment_owners.clear();
        self.annotation_browser = AnnotationBrowser::default();
        self.history_index = 0;
        self.filtered_functions.clear();
        self.filter_keys.clear();
        self.filter_cursor = None;
        self.decoder = DecoderPanel::default();
    }

    fn stop_worker(&mut self) {
        crate::performance::event("worker_stop_epoch", self.worker_epoch);
        if self.discovery_running {
            crate::performance::event("discovery_action_interrupted", self.generation);
        }
        self.discovery_running = false;
        self.discovery_sync = None;
        self.discovery_bytes = None;
        self.worker_inventory = None;
        self.inventory_synced = false;
        if let Some(state) = &mut self.discovery {
            state.interrupt();
        }
        self.update_discovery_summary();
        self.analysis_progress = None;
        self.progress_events = 0;
        self.client = None;
        self.pending = None;
        self.opening = None;
        self.queue.clear();
        self.applied_names.clear();
        self.opening_project = None;
    }

    fn start_open(
        &mut self,
        path: PathBuf,
        preserve: bool,
        follow: Option<Request>,
        context: &egui::Context,
    ) {
        let follow_origin = self.request_origin();
        self.stop_worker();
        match WorkerClient::start(context.clone(), &path) {
            Ok(mut client) => {
                if preserve && let Some(binary) = &self.project_binary {
                    client.retain_source(std::sync::Arc::new(binary.clone()));
                }
                self.worker_epoch = self.worker_epoch.wrapping_add(1);
                self.client = Some(client);
                self.opening = Some(Opening {
                    path: path.clone(),
                    preserve,
                    follow,
                    revision: self.revision,
                    follow_origin,
                });
                self.status = format!("Opening {}…", path.display());
                self.send_direct(Request::Open {
                    path: path.to_string_lossy().into_owned(),
                });
            }
            Err(error) => self.status = error,
        }
    }

    fn send_direct(&mut self, request: Request) {
        self.analysis_progress = None;
        self.progress_events = 0;
        let Some(client) = &mut self.client else {
            return;
        };
        let wire_request = match &request {
            Request::Decompile { address } => Request::DecompileWithLocals {
                address: *address,
                renames: self
                    .session
                    .as_ref()
                    .map(|session| {
                        session
                            .local_renames
                            .iter()
                            .filter(|r| r.identity.function == *address)
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
            },
            _ => request.clone(),
        };
        match client.send(wire_request) {
            Ok(id) => {
                let _context = crate::performance::context(id);
                crate::performance::event("generation", self.generation);
                crate::performance::event("epoch", self.worker_epoch);
                crate::performance::event("selection", self.selection_generation);
                crate::performance::event("annotation_revision", self.revision);
                self.pending = Some(Pending {
                    id,
                    request,
                    started: Instant::now(),
                    selection: self.selection_generation,
                    revision: self.revision,
                    byte_origin: (self.selected, self.tab),
                });
            }
            Err(error) => {
                self.stop_worker();
                self.status = error;
            }
        }
    }

    fn request(&mut self, request: Request, context: &egui::Context) {
        if self.opening.is_some() {
            // The new client must first prove it opened the intended binary.
            let origin = self.request_origin();
            if let Some(opening) = &mut self.opening {
                opening.follow = Some(request);
                opening.follow_origin = origin;
            }
            return;
        }
        if matches!(request, Request::Discover) {
            if self
                .info
                .as_ref()
                .is_some_and(crate::packing::has_upx_warning)
            {
                self.status = crate::packing::UPX_ANALYSIS_ERROR.into();
                return;
            }
            self.start_discovery(context);
            return;
        }
        if matches!(request, Request::Decompile { .. } | Request::Discover)
            && self
                .info
                .as_ref()
                .is_some_and(crate::packing::has_upx_warning)
        {
            self.status = crate::packing::UPX_ANALYSIS_ERROR.into();
            return;
        }
        if self.discovery_job.is_some()
            || self.pending.as_ref().is_some_and(|pending| {
                matches!(
                    pending.request,
                    Request::DiscoverBatch { .. } | Request::SyncFunctions { .. }
                )
            })
        {
            // Interactive work runs between bounded batches. Keep only the
            // newest navigation requests, and bound queued user actions.
            if matches!(request, Request::Bytes { .. }) {
                self.discovery_bytes = Some((request, self.request_origin()));
                return;
            }
            if matches!(request, Request::Graph { .. }) {
                self.queue.retain(|queued| {
                    !matches!(queued, Request::Graph { .. } | Request::Decompile { .. })
                });
            }
            if self.queue.len() < HISTORY_LIMIT {
                self.queue.push_back(request);
            }
            return;
        }
        if self.client.is_none() || self.pending.is_some() {
            // A user action preempts an automatic scan; run that scan again later.
            if let (Some(pending), Some(plan)) = (&self.pending, &mut self.analysis_plan)
                && let Some(step) = plan.current.filter(|step| step.owns(&pending.request))
            {
                plan.steps.push_front(step);
                plan.current = None;
            }
            if let Some(path) = self.binary_path.clone() {
                let continue_discovery = self.discovery_running;
                self.start_open(path, true, Some(request), context);
                self.discovery_running = continue_discovery && self.client.is_some();
            }
        } else {
            self.schedule_request(request);
        }
    }

    fn schedule_request(&mut self, request: Request) {
        if matches!(request, Request::Discover) {
            self.discovery_running = true;
            return;
        }
        let address = match &request {
            Request::Graph { address } | Request::Decompile { address } => Some(*address),
            _ => None,
        };
        if let Some(address) = address {
            let name = self
                .session
                .as_ref()
                .and_then(|session| session.annotations.get(&address))
                .map(|annotation| annotation.label.clone())
                .filter(|label| !label.is_empty());
            if let Some(name) = name
                && self.applied_names.get(&address) != Some(&name)
            {
                self.queue.push_front(request);
                self.send_direct(Request::Rename { address, name });
                return;
            }
        }
        self.send_direct(request);
    }

    fn request_origin(&self) -> RequestOrigin {
        RequestOrigin {
            selection: self.selection_generation,
            revision: self.revision,
            byte_origin: (self.selected, self.tab),
        }
    }

    fn schedule_open_follow(&mut self, request: Request, origin: RequestOrigin) {
        if matches!(request, Request::Bytes { .. }) {
            // Reopening a busy worker must not bind an older byte-read action
            // to the selection or tab active when Open eventually completes.
            if origin.selection != self.selection_generation
                || origin.revision != self.revision
                || origin.byte_origin.0 != self.selected
            {
                return;
            }
            self.schedule_request(request);
            if let Some(pending) = &mut self.pending {
                pending.byte_origin = origin.byte_origin;
            }
        } else {
            self.schedule_request(request);
        }
    }

    fn navigate(&mut self, address: u64, record: bool, context: &egui::Context) {
        self.reference_focus = None;
        self.undisplayed_call = None;
        self.selection_generation = self.selection_generation.wrapping_add(1);
        crate::performance::navigation_begin(self.selection_generation);
        self.selected = Some(address);
        self.address = format!("{address:x}");
        self.editor_address = None;
        self.decompiled.clear();
        self.semantic.clear();
        self.comment_rows_key = None;
        self.semantic_info = SemanticInfo::default();
        self.selected_local = None;
        self.decompiler_rename_context = false;
        self.pending_code_scroll = None;
        self.pending_comment_scroll = None;
        self.pending_listing_scroll = None;
        self.highlighted = None;
        self.saved_analysis = false;
        self.decompiled_lines.clear();
        if record {
            if !self.history.is_empty() {
                self.history.truncate(self.history_index + 1);
            }
            if self.history.last() != Some(&address) {
                self.history.push(address);
            }
            if self.history.len() > 256 {
                self.history.remove(0);
            }
            self.history_index = self.history.len().saturating_sub(1);
        }
        self.view = None;
        self.cached_graph = false;
        self.canvas = None;
        self.listing.clear();
        self.status = format!("Loading function {address:#x}…");
        self.request(Request::Graph { address }, context);
    }

    fn select_instruction(&mut self, address: u64) {
        self.pending_comment_scroll = Some(address);
        self.selected_local = None;
        self.decompiler_rename_context = false;
        self.selected = Some(address);
        self.address = format!("{address:x}");
        self.editor_address = None;
        self.semantic.select_instruction(address);
        self.pending_code_scroll = self.semantic.ranges.first().map(|range| {
            self.decompiled_lines
                .partition_point(|(_, end)| *end <= range.start)
        });
    }

    fn select_decompiled_byte(&mut self, byte: usize) {
        self.pending_comment_scroll = None;
        self.decompiler_rename_context = true;
        self.selected_local = match self.semantic_info.token_at(byte).map(|t| &t.kind) {
            Some(TokenKind::Local { local }) => *local,
            _ => None,
        };
        let Some(primary) = self.semantic.select_code(byte) else {
            self.semantic.addresses.clear();
            self.semantic.ranges.clear();
            self.pending_code_scroll = None;
            self.pending_comment_scroll = None;
            self.pending_listing_scroll = None;
            self.status = "This source location has no machine instruction mapping".into();
            return;
        };
        self.selected = Some(primary);
        self.address = format!("{primary:x}");
        self.editor_address = None;
        self.pending_listing_scroll = self.listing.iter().position(|i| i.address == primary);
        if self.pending_listing_scroll.is_none() {
            self.status =
                format!("Selected instruction {primary:#x} is outside the current bounded CFG");
        }
        if let Some(canvas) = &mut self.canvas {
            canvas.reveal_instruction(primary);
        }
    }

    fn update_discovery_summary(&mut self) {
        if let Some(state) = &self.discovery {
            let patterns = state.patterns.as_ref().map_or(String::new(), |phase| {
                format!(
                    " · {} pattern starts from {} KiB{}",
                    phase.admitted,
                    phase.scanned_bytes / 1024,
                    if phase.cursor.is_some() {
                        " (scanning)"
                    } else if phase.partial {
                        " (partial)"
                    } else {
                        ""
                    }
                )
            });
            self.discovery_summary = Some(
                discovery_summary(
                    "Discovery",
                    state.report.functions_examined,
                    state.remaining(),
                    state.batches,
                    state.report.failed_functions,
                    state.partial(),
                    if self.discovery_running {
                        " · running"
                    } else if state.remaining() != 0 || state.scanning() {
                        " · paused"
                    } else {
                        ""
                    },
                ) + &patterns,
            );
        }
    }

    /// Discard all discovery results, including saved ones, and start again
    /// from the current function inventory.
    fn rediscover(&mut self, context: &egui::Context) {
        if self.pending.as_ref().is_some_and(|pending| {
            matches!(
                pending.request,
                Request::DiscoverBatch { .. } | Request::SyncFunctions { .. }
            )
        }) {
            self.stop_worker();
        }
        // Dropping the receiver discards any background adoption in progress.
        self.discovery = None;
        self.discovery_job = None;
        self.discovery_running = false;
        self.discovery_summary = None;
        self.discovery_saved = None;
        self.saved_references = false;
        self.call_index = None;
        self.request(Request::Discover, context);
    }

    fn start_discovery(&mut self, context: &egui::Context) {
        let Some(info) = &self.info else { return };
        if !self.discovery_running {
            crate::performance::event("discovery_action_begin", self.generation);
        }
        if self.discovery.is_none() && self.discovery_job.is_none() {
            // Saved results are display-only; a fresh run replaces them.
            if self.saved_references {
                self.saved_references = false;
                self.call_index = None;
                self.discovery_summary = None;
                self.discovery_saved = None;
            }
            // Only copy addresses here; queue construction, validation and all
            // reference sorting/indexing happen in parent background jobs.
            let seeds: Vec<_> = info.functions.iter().map(|f| f.address).collect();
            let entry = crate::call_analysis::code_address(info, info.entry).then_some(info.entry);
            let partial = info.functions_truncated;
            let patterns = crate::discovery::Discovery::patterns_apply(info);
            let generation = self.generation;
            let (sender, receiver) = mpsc::sync_channel(1);
            self.discovery_job = Some(receiver);
            let context = context.clone();
            std::thread::spawn(move || {
                let mut state = crate::discovery::Discovery::new(entry, seeds, partial);
                if patterns {
                    state.start_patterns();
                }
                let _ = sender.send(DiscoveryUpdate {
                    generation,
                    saved: Arc::new(state.save()),
                    state,
                    publication: Ok(None),
                });
                context.request_repaint();
            });
        }
        if self.client.is_none()
            && self.opening.is_none()
            && let Some(path) = self.binary_path.clone()
        {
            self.start_open(path, true, Some(Request::Discover), context);
        }
        self.discovery_running = self.client.is_some();
        self.update_discovery_summary();
    }

    fn poll_discovery(&mut self, _context: &egui::Context) {
        let Some(job) = &self.discovery_job else {
            return;
        };
        let update = match job.try_recv() {
            Ok(update) => update,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.discovery_job = None;
                self.discovery_running = false;
                self.status = "Discovery adoption job failed".into();
                return;
            }
        };
        let _install = crate::performance::span("gui_discovery_install_filter");
        self.discovery_job = None;
        if update.generation != self.generation {
            return;
        }
        self.discovery = Some(update.state);
        self.discovery_saved = Some(update.saved);
        match update.publication {
            Ok(Some(publication)) => {
                self.call_index = Some(publication.index);
                let changed = publication.functions.is_some();
                if let Some(info) = &mut self.info {
                    if let Some(functions) = publication.functions {
                        info.functions = functions;
                    }
                    info.functions_truncated = publication.truncated;
                }
                // A batch committed after its worker stopped is not a base for
                // the replacement worker.
                if publication.inventory.epoch() == self.worker_epoch {
                    self.worker_inventory = Some(publication.inventory);
                    self.inventory_synced = true;
                } else {
                    self.inventory_synced = false;
                }
                self.cached_functions &= self
                    .discovery
                    .as_ref()
                    .is_some_and(|state| state.remaining() != 0);
                if changed {
                    self.rebuild_filter();
                }
                self.status = "Discovery batch committed".into();
            }
            Ok(None) => {}
            Err(error) => {
                self.stop_worker();
                self.status = format!("Invalid discovery batch: {error}");
            }
        }
        self.update_discovery_summary();
    }

    fn pump_discovery(&mut self, _context: &egui::Context) {
        if !self.discovery_running
            || self.discovery_job.is_some()
            || self.pending.is_some()
            || self.opening.is_some()
            || !self.queue.is_empty()
            || self.discovery_bytes.is_some()
            || self.client.is_none()
        {
            return;
        }
        if let Some(addresses) = &mut self.discovery_sync {
            let Some(info) = &self.info else { return };
            while !addresses.is_empty() {
                // Read current names at send time so a later rename is not replaced.
                let functions: Vec<_> = addresses
                    .drain(..addresses.len().min(MAX_DISCOVERY_SYNC_FUNCTIONS))
                    .filter_map(|address| function_at(&info.functions, address))
                    .map(|function| FunctionInfo {
                        address: function.address,
                        name: inventory_name(&function.name).to_owned(),
                    })
                    .collect();
                if !functions.is_empty() {
                    self.send_direct(Request::SyncFunctions { functions });
                    return;
                }
            }
            self.discovery_sync = None;
        }
        let base = self.inventory_base();
        let Some(state) = &mut self.discovery else {
            return;
        };
        if let Some(mut request) = state.begin(self.generation, self.worker_epoch, self.revision) {
            if let Request::DiscoverBatch { inventory_base, .. } = &mut request {
                *inventory_base = base;
            }
            self.send_direct(request);
        } else if state.remaining() == 0 && !state.scanning() {
            crate::performance::event("discovery_action_adopted", self.generation);
            self.discovery_running = false;
            self.worker_inventory = None;
            self.inventory_synced = false;
            self.status = "Discovery seed queue exhausted".into();
        }
        self.update_discovery_summary();
    }

    /// The adopted worker inventory revision `info.functions` still matches.
    fn inventory_base(&self) -> Option<u64> {
        let inventory = self
            .worker_inventory
            .as_ref()
            .filter(|inventory| self.inventory_synced && inventory.epoch() == self.worker_epoch)?;
        debug_assert!(
            self.info
                .as_ref()
                .is_some_and(|info| info.functions == inventory.functions()),
            "display inventory changed without clearing its worker base"
        );
        Some(inventory.revision())
    }

    fn start_auto_analysis(&mut self) {
        let options = self.analysis_options;
        let packed = self
            .info
            .as_ref()
            .is_some_and(crate::packing::has_upx_warning);
        // Short whole-image scans first; discovery may continue for many batches.
        let steps: VecDeque<_> = [
            (options.strings, AnalysisStep::Strings),
            (options.crypto, AnalysisStep::Crypto),
            (options.functions && !packed, AnalysisStep::Functions),
        ]
        .into_iter()
        .filter_map(|(enabled, step)| enabled.then_some(step))
        .collect();
        self.analysis_plan = (!steps.is_empty()).then_some(AnalysisPlan {
            generation: self.generation,
            total: steps.len(),
            steps,
            current: None,
        });
    }

    fn pump_analysis(&mut self, context: &egui::Context) {
        let Some(plan) = &mut self.analysis_plan else {
            return;
        };
        if plan.generation != self.generation {
            self.analysis_plan = None;
            return;
        }
        if self.pending.is_some()
            || self.opening.is_some()
            || !self.queue.is_empty()
            || self.discovery_running
            || self.discovery_job.is_some()
            || self.discovery_bytes.is_some()
        {
            return;
        }
        // The previous step finished, failed, or was cancelled; each runs once
        // unless a user action preempted it.
        plan.current = plan.steps.pop_front();
        let Some(step) = plan.current else {
            self.analysis_plan = None;
            self.status = "Auto analysis finished".into();
            return;
        };
        let request = match step {
            AnalysisStep::Strings => self.string_request(),
            AnalysisStep::Crypto => Request::Crypto,
            AnalysisStep::Functions => Request::Discover,
        };
        self.request(request, context);
    }

    fn automatic(&self, step: AnalysisStep) -> bool {
        self.analysis_plan
            .as_ref()
            .is_some_and(|plan| plan.current == Some(step))
    }

    fn poll_worker(&mut self, context: &egui::Context) {
        self.poll_discovery(context);
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.started.elapsed() > DEADLINE)
        {
            self.stop_worker();
            self.status =
                "Analysis exceeded 30 seconds and was stopped. Choose an action to restart.".into();
        }
        // Each WorkerClient owns a fresh event channel; dropped clients cannot
        // deliver replies into this generation's queue.
        for _ in 0..8 {
            let Some(event) = self.client.as_ref().and_then(WorkerClient::poll) else {
                break;
            };
            match event {
                WorkerEvent::Failed(error) => {
                    self.stop_worker();
                    self.status = error;
                    break;
                }
                WorkerEvent::Reply(reply) => self.receive_worker_reply(*reply, context),
            }
        }
        self.dispatch_queued();
        self.pump_discovery(context);
        self.pump_analysis(context);
        if self.pending.is_some() || self.discovery_job.is_some() {
            context.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn receive_worker_reply(&mut self, reply: WorkerResponse, context: &egui::Context) {
        let Some(pending) = &self.pending else { return };
        if pending.id != reply.id {
            self.stop_worker();
            self.status = "Worker replied with an unexpected request ID".into();
            return;
        }
        if let Response::Progress { progress } = reply.response {
            // Progress never completes a request or extends its wall-time deadline.
            self.progress_events += 1;
            if !matches!(
                pending.request,
                Request::Discover | Request::DiscoverBatch { .. }
            ) || (self.progress_events == 1 && progress.stage != AnalysisStage::Seeds)
                || self.progress_events > MAX_ANALYSIS_FUNCTIONS + 3
                || progress
                    .validate_after(self.analysis_progress.as_ref())
                    .is_err()
            {
                self.stop_worker();
                self.status = "Invalid worker analysis progress; worker stopped".into();
                return;
            }
            if matches!(pending.request, Request::DiscoverBatch { .. })
                || pending.selection == self.selection_generation
                    && pending.revision == self.revision
            {
                self.analysis_progress = Some(progress);
            }
            return;
        }
        let final_analysis = match &reply.response {
            Response::Functions { analysis, .. } => Some(analysis),
            Response::DiscoveryBatch { batch } => Some(&batch.analysis),
            _ => None,
        };
        if let Some(analysis) = final_analysis
            && self.analysis_progress.as_ref().is_none_or(|last| {
                last.stage != AnalysisStage::Publish
                    || last.functions_examined != analysis.functions_examined
                    || last.decode_attempts != analysis.decode_attempts
            })
        {
            self.stop_worker();
            self.status = "Call analysis did not match its final progress; worker stopped".into();
            return;
        }
        let pending = self.pending.take().expect("Checked pending request");
        self.analysis_progress = None;
        self.progress_events = 0;
        self.receive(pending, reply.response, context);
    }

    fn receive(&mut self, pending: Pending, response: Response, context: &egui::Context) {
        let _trace_context = crate::performance::context(pending.id);
        let _adoption = crate::performance::span("gui_reply_adoption");
        if let Response::Error { message } = response {
            self.stop_worker();
            self.status = crop(&message, 4096);
            return;
        }
        if let Err(error) = self.validate_reply(&response) {
            self.stop_worker();
            self.status = format!("Invalid worker response: {error}; worker stopped");
            return;
        }
        match (pending.request, response) {
            (Request::Open { .. }, Response::Opened { mut info }) => {
                let Some(opening) = self.opening.take() else {
                    return;
                };
                let protection = match self
                    .client
                    .as_ref()
                    .ok_or_else(|| "Analysis worker disappeared while opening".to_string())
                    .and_then(|client| client.protection().bind_snapshot(&info))
                {
                    Ok(protection) => protection,
                    Err(error) => {
                        self.stop_worker();
                        self.status = error;
                        return;
                    }
                };
                if opening.preserve
                    && self
                        .binary_protection
                        .as_ref()
                        .is_none_or(|old| !old.same_source(&protection))
                {
                    self.stop_worker();
                    self.status = "Input binary identity changed. Existing notes were retained; save them, then reopen explicitly.".into();
                    return;
                }
                if !opening.preserve && opening.revision != self.revision {
                    self.stop_worker();
                    self.status = "Annotations changed while opening the binary. Notes were retained; save them and reopen.".into();
                    return;
                }
                if opening.preserve
                    && self
                        .info
                        .as_ref()
                        .is_some_and(|old| old.sha256 != info.sha256)
                {
                    self.stop_worker();
                    self.status = "Binary changed on disk. Existing notes were retained; save them, then reopen explicitly.".into();
                    return;
                }
                let project = self.opening_project.take();
                if let Some(project) = &project
                    && let Err(error) = project.project.data.validate_against(&info)
                {
                    self.stop_worker();
                    self.status = error;
                    return;
                }
                if !opening.preserve {
                    self.generation = self.generation.wrapping_add(1);
                    self.clear_views();
                    self.undo.clear();
                    self.revision = 0;
                    self.saved_revision = 0;
                    self.session = Some(Session::new(info.sha256.clone()));
                    self.session_path = None;
                    self.project_path = None;
                    self.project_binary = None;
                }
                // Replay only names the fresh worker inventory lacks or differs on.
                let replay = project.is_some() || opening.preserve && self.info.is_some();
                let worker_functions = if replay {
                    info.functions.clone()
                } else {
                    Vec::new()
                };
                if let Some(project) = &project {
                    self.session = Some(project.project.data.session.clone());
                    if project.project.cache_compatible {
                        info.functions = project.project.data.info.functions.clone();
                        info.functions_truncated = project.project.data.info.functions_truncated;
                    }
                    info.path = project.project.source_hint.clone();
                } else if opening.preserve
                    && self.project_path.is_some()
                    && let Some(previous) = &self.info
                {
                    info.path = previous.path.clone();
                }
                if opening.preserve
                    && let Some(previous) = &mut self.info
                {
                    info.functions = std::mem::take(&mut previous.functions);
                    info.functions_truncated = previous.functions_truncated;
                }
                if let Some(session) = &self.session {
                    for function in &mut info.functions {
                        if let Some(annotation) = session.annotations.get(&function.address)
                            && !annotation.label.is_empty()
                        {
                            function.name = annotation.label.clone();
                        }
                    }
                }
                self.discovery_sync =
                    replay.then(|| replay_addresses(&worker_functions, &info.functions));
                let first = info
                    .functions
                    .iter()
                    .find(|function| function.name == "main")
                    .map(|function| function.address)
                    .unwrap_or(info.entry);
                self.binary_path = Some(opening.path);
                if !opening.preserve {
                    self.binary_protection = Some(protection);
                }
                self.cached_functions =
                    project.as_ref().is_some_and(|p| p.project.cache_compatible);
                // Replayed names and display labels differ from the raw Opened
                // inventory; the first batch from this worker replaces it.
                self.worker_inventory = None;
                self.inventory_synced = false;
                self.info = Some(info);
                self.rebuild_filter();
                self.status = "Binary loaded".into();
                if let Some(project) = project {
                    self.restore_project(*project, context);
                } else if let Some(request) = opening.follow {
                    if matches!(request, Request::Discover) {
                        self.start_discovery(context);
                    } else {
                        self.schedule_open_follow(request, opening.follow_origin);
                    }
                } else {
                    if !opening.preserve {
                        // Like Ghidra, offer analysis when a binary is first opened.
                        self.analyze_prompt = Some(AnalyzePrompt {
                            generation: self.generation,
                            first_open: true,
                        });
                    }
                    self.navigate(first, true, context);
                }
            }
            (Request::Graph { address }, Response::Graph { view }) if view.address == address => {
                if pending.selection != self.selection_generation
                    || pending.revision != self.revision
                {
                    return;
                }
                self.listing = view
                    .blocks
                    .iter()
                    .flat_map(|block| block.instructions.iter().cloned())
                    .collect();
                self.listing.sort_by_key(|instruction| instruction.address);
                self.listing.dedup_by_key(|instruction| instruction.address);
                let geometry = crate::performance::span("gui_graph_geometry");
                self.canvas = Some(GraphCanvas::new(&view));
                geometry.finish(view.blocks.len() as u64);
                self.cached_graph = false;
                self.saved_analysis = false;
                self.view = Some(view);
                self.comment_rows_key = None;
                self.status = format!("Function {address:#x} ready");
                if let Some((caller, pc)) = self.reference_focus.take()
                    && caller == address
                {
                    self.select_instruction(pc);
                    if let Some(row) = self
                        .listing
                        .iter()
                        .position(|instruction| instruction.address == pc)
                    {
                        self.pending_listing_scroll = Some(row);
                        if let Some(canvas) = &mut self.canvas {
                            canvas.reveal_instruction(pc);
                        }
                    } else {
                        self.undisplayed_call = Some(pc);
                    }
                }
                if self.should_auto_decompile() {
                    self.schedule_request(Request::Decompile { address });
                }
            }
            (
                Request::Decompile { address: expected },
                Response::Decompiled {
                    address,
                    text,
                    mappings,
                    semantics,
                },
            ) if address == expected => {
                if pending.selection == self.selection_generation
                    && pending.revision == self.revision
                    && self
                        .view
                        .as_ref()
                        .is_some_and(|view| view.address == address)
                {
                    if text.len() > MAX_DECOMPILED_BYTES {
                        self.stop_worker();
                        self.decompiled.clear();
                        self.semantic.clear();
                        self.comment_rows_key = None;
                        self.semantic_info = SemanticInfo::default();
                        self.selected_local = None;
                        self.decompiler_rename_context = false;
                        self.pending_code_scroll = None;
                        self.pending_comment_scroll = None;
                        self.pending_listing_scroll = None;
                        self.decompiled_lines.clear();
                        self.highlighted = None;
                        self.status =
                            "Decompiler response exceeded the 2 MiB limit; analysis worker stopped"
                                .into();
                        return;
                    }
                    let sections = self
                        .info
                        .as_ref()
                        .map(|i| i.sections.as_slice())
                        .unwrap_or(&[]);
                    if let Err(error) = validate_mappings(&text, &mappings, sections) {
                        self.stop_worker();
                        self.decompiled.clear();
                        self.highlighted = None;
                        self.semantic.clear();
                        self.comment_rows_key = None;
                        self.decompiled_lines.clear();
                        self.semantic_info = SemanticInfo::default();
                        self.selected_local = None;
                        self.decompiler_rename_context = false;
                        self.status = format!("Invalid decompiler source mappings: {error}");
                        return;
                    }
                    self.semantic_info = semantics;
                    self.selected_local = None;
                    self.decompiler_rename_context = false;
                    self.semantic.mappings = mappings;
                    self.comment_rows_key = None;
                    if let Some(address) = self.selected {
                        self.semantic.select_instruction(address);
                    }
                    let highlighting = crate::performance::span("gui_highlighting");
                    self.highlighted = Some(HighlightedCode::new(&text));
                    highlighting.finish(text.len() as u64);
                    self.saved_analysis = false;
                    self.decompiled = text;
                    let mut offset = 0;
                    self.decompiled_lines = self
                        .decompiled
                        .split_inclusive('\n')
                        .take(20_000)
                        .map(|line| {
                            let range = (offset, offset + line.len());
                            offset += line.len();
                            range
                        })
                        .collect();
                    self.pending_code_scroll = self.semantic.ranges.first().map(|range| {
                        self.decompiled_lines
                            .partition_point(|(_, end)| *end <= range.start)
                    });
                    self.pending_comment_scroll = self.selected;
                    self.status = self
                        .semantic_info
                        .warnings
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "Ready".into());
                }
            }
            (Request::SyncFunctions { .. }, Response::FunctionsSynced) => {}
            (
                Request::DiscoverBatch {
                    binding,
                    inventory_base,
                    ..
                },
                Response::DiscoveryBatch { batch },
            ) => {
                if batch.binding != binding
                    || binding.generation != self.generation
                    || binding.epoch != self.worker_epoch
                {
                    self.stop_worker();
                    self.status = "Stale discovery reply rejected".into();
                    return;
                }
                let Some(state) = self.discovery.take() else {
                    self.stop_worker();
                    self.status = "Unexpected discovery batch".into();
                    return;
                };
                let Some(info) = &self.info else { return };
                // Evidence depends on immutable bytes, not selection or renamed
                // display labels. The batch must echo the revision it was sent
                // with; current annotations are applied after atomic adoption.
                let validation = info_without_functions(info);
                let generation = self.generation;
                let base = self.worker_inventory.clone();
                let (sender, receiver) = mpsc::sync_channel(1);
                self.discovery_job = Some(receiver);
                let context = context.clone();
                let scheduled = crate::performance::span("parent_adoption_schedule");
                let trace_id = pending.id;
                std::thread::spawn(move || {
                    scheduled.finish(0);
                    let _trace_context = crate::performance::context(trace_id);
                    let mut state = state;
                    let mut batch = batch;
                    let commit = crate::performance::span("parent_discovery_commit");
                    let committed =
                        state.commit_reply(&validation, base.as_ref(), inventory_base, &mut batch);
                    commit.finish(0);
                    let publication = committed.map(|(inventory, changed)| {
                        let _index = crate::performance::span("parent_reference_index");
                        Some(DiscoveryPublication {
                            functions: changed.then(|| inventory.functions().to_vec()),
                            inventory,
                            truncated: batch.truncated,
                            index: crate::call_analysis::CallIndex::new(state.snapshot()),
                        })
                    });
                    let saving = crate::performance::span("parent_discovery_snapshot");
                    let saved = Arc::new(state.save());
                    saving.finish(0);
                    let _ = sender.send(DiscoveryUpdate {
                        generation,
                        saved,
                        state,
                        publication,
                    });
                    context.request_repaint();
                });
            }
            (
                Request::Discover,
                Response::Functions {
                    functions,
                    truncated,
                    analysis,
                },
            ) => {
                if pending.selection != self.selection_generation
                    || pending.revision != self.revision
                {
                    return;
                }
                let Some(info) = &self.info else { return };
                if let Err(error) = analysis.validate(info, &functions) {
                    self.stop_worker();
                    self.status = format!("Invalid worker reference analysis: {error}");
                    return;
                }
                self.status = format!(
                    "{} calls · {} · {} function walks · {} decode attempts{}",
                    analysis.references.len(),
                    analysis.data.as_ref().map_or_else(
                        || "data not analyzed".into(),
                        |data| format!("{} data accesses", data.references.len())
                    ),
                    analysis.functions_examined,
                    analysis.decode_attempts,
                    if truncated
                        || analysis.partial
                        || analysis.data.as_ref().is_some_and(|data| data.partial)
                    {
                        " · partial coverage"
                    } else {
                        " · direct references analyzed"
                    }
                );
                self.call_index = Some(crate::call_analysis::CallIndex::new(analysis));
                self.cached_functions = false;
                self.inventory_synced = false;
                if let Some(info) = &mut self.info {
                    info.functions = functions;
                    info.functions_truncated = truncated;
                }
                self.rebuild_filter();
            }
            (
                Request::Rename {
                    address: expected,
                    name: requested,
                },
                Response::Renamed { address, name },
            ) if address == expected && name == requested => {
                self.applied_names.insert(address, name.clone());
                // The worker may also have re-admitted entries; resend in full.
                self.inventory_synced = false;
                if let Some(info) = &mut self.info
                    && let Ok(index) = info
                        .functions
                        .binary_search_by_key(&address, |function| function.address)
                {
                    let function = &mut info.functions[index];
                    function.name = name;
                }
                self.rebuild_filter();
                self.status = "Function renamed".into();
                if self.queue.is_empty()
                    && self.should_auto_decompile()
                    && self
                        .view
                        .as_ref()
                        .is_some_and(|view| view.address == address)
                {
                    self.send_direct(Request::Decompile { address });
                }
            }
            (
                Request::Bytes {
                    address: expected,
                    length,
                },
                Response::Bytes { address, bytes },
            ) if address == expected && bytes.len() <= length => {
                if pending.selection != self.selection_generation
                    || pending.revision != self.revision
                    || pending.byte_origin.0 != self.selected
                {
                    return;
                }
                self.decoder.set_source(address, bytes);
                if self.tab == pending.byte_origin.1 {
                    self.tab = Tab::Decode;
                }
                self.status = "Bytes loaded into decoder".into();
            }
            (
                request @ (Request::Strings | Request::StringsWithOptions { .. }),
                Response::Strings { strings, truncated },
            ) => {
                self.strings_minimum_used = Some(match request {
                    Request::StringsWithOptions { minimum_length } => minimum_length,
                    _ => MIN_STRING_LENGTH,
                });
                self.cached_strings = false;
                self.strings = strings;
                self.strings_truncated = truncated;
                self.strings_scanned = true;
                self.rebuild_string_filter();
                if !self.automatic(AnalysisStep::Strings) {
                    self.tab = Tab::Strings;
                }
                self.status = if truncated {
                    format!(
                        "Showing {} string previews; raise the minimum length and rescan for fewer matches",
                        self.strings.len()
                    )
                } else {
                    format!("String scan complete: {} results", self.strings.len())
                };
            }
            (Request::Crypto, Response::Crypto { matches, truncated }) => {
                self.cached_crypto = false;
                self.crypto = matches;
                self.crypto_truncated = truncated;
                if !self.automatic(AnalysisStep::Crypto) {
                    self.tab = Tab::Crypto;
                }
                self.status = if truncated {
                    "FindCrypt result limit reached"
                } else {
                    "Constant scan complete; matches are heuristic evidence"
                }
                .into();
            }
            _ => {
                self.stop_worker();
                self.status = "Unexpected worker response; worker stopped".into();
            }
        }
        self.dispatch_queued();
    }

    fn dispatch_queued(&mut self) {
        // Publish the batch inventory before processing renames/navigation, so
        // an older batch cannot overwrite a newer acknowledged function name.
        if self.discovery_job.is_some() {
            return;
        }
        if self.pending.is_none()
            && let Some(request) = self.queue.pop_front()
        {
            self.schedule_request(request);
        }
        if self.pending.is_none()
            && let Some((request, origin)) = self.discovery_bytes.take()
        {
            self.schedule_open_follow(request, origin);
        }
    }

    /// Structural bounds for every reply before adoption clones, sorts, or
    /// indexes it. Request-specific checks remain at each adoption site.
    fn validate_reply(&self, response: &Response) -> Result<(), String> {
        use crate::project::{validate_crypto, validate_info, validate_strings, validate_view};
        let ranges = || {
            let info = self.info.as_ref().ok_or("No binary is open")?;
            crate::selection::MappedRanges::new(&info.sections)
        };
        match response {
            Response::Opened { info } => {
                validate_info(info, MAX_FUNCTION_NAME_BYTES, true).map(|_| ())
            }
            Response::Graph { view } => validate_view(
                view,
                &ranges()?,
                self.info.as_ref().ok_or("No binary is open")?,
            ),
            Response::Strings { strings, .. } => {
                validate_strings(strings, MAX_STRING_RESULTS, &ranges()?)
            }
            Response::Crypto { matches, .. } => validate_crypto(matches, &ranges()?),
            _ => Ok(()),
        }
    }

    /// Names or labels changed: drop cached search keys and refilter.
    fn rebuild_filter(&mut self) {
        self.filter_keys.clear();
        self.restart_filter();
    }

    /// The query changed; cached keys remain valid.
    fn restart_filter(&mut self) {
        self.filter_query = self.function_filter.to_lowercase();
        self.filtered_functions.clear();
        self.filter_cursor = Some(0);
        self.step_filter(FILTER_FRAME_BUDGET);
    }

    /// Advances the function filter within `budget`; returns whether it is done.
    /// Inventories can hold 262,144 entries, so large filters span frames
    /// instead of blocking input. Keys are lowercased once per name revision.
    fn step_filter(&mut self, budget: Duration) -> bool {
        // Annotation edits and undo change effective labels.
        if self.filter_keys_revision != self.revision {
            self.filter_keys_revision = self.revision;
            self.filter_keys.clear();
            self.filtered_functions.clear();
            self.filter_cursor = Some(0);
        }
        let Some(mut index) = self.filter_cursor else {
            return true;
        };
        let Some(info) = &self.info else {
            self.filter_cursor = None;
            return true;
        };
        let functions = &info.functions;
        if self.filter_query.is_empty() {
            self.filtered_functions.extend(index..functions.len());
            self.filter_cursor = None;
            return true;
        }
        // Format addresses only for queries that could match one.
        let hex = self
            .filter_query
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
        let started = Instant::now();
        let mut address = String::with_capacity(16);
        while index < functions.len() {
            let function = &functions[index];
            if index == self.filter_keys.len() {
                let label = self
                    .session
                    .as_ref()
                    .and_then(|session| session.annotations.get(&function.address))
                    .map(|annotation| annotation.label.as_str())
                    .filter(|label| !label.is_empty())
                    .unwrap_or(&function.name);
                self.filter_keys.push(label.to_lowercase());
            }
            let matched = self.filter_keys[index].contains(&self.filter_query)
                || hex && {
                    use std::fmt::Write;
                    address.clear();
                    let _ = write!(address, "{:x}", function.address);
                    address.contains(&self.filter_query)
                };
            if matched {
                self.filtered_functions.push(index);
            }
            index += 1;
            if index.is_multiple_of(1024) && started.elapsed() >= budget {
                self.filter_cursor = Some(index);
                return false;
            }
        }
        self.filter_cursor = None;
        true
    }

    fn should_auto_decompile(&self) -> bool {
        self.auto_decompile
            && !self
                .info
                .as_ref()
                .is_some_and(crate::packing::has_upx_warning)
    }

    fn string_request(&self) -> Request {
        Request::StringsWithOptions {
            minimum_length: self
                .string_minimum
                .clamp(MIN_STRING_LENGTH, MAX_STRING_MINIMUM),
        }
    }

    fn rebuild_string_filter(&mut self) {
        let filter = self.string_filter.to_lowercase();
        self.filtered_strings = self
            .strings
            .iter()
            .enumerate()
            .filter(|(_, string)| filter.is_empty() || string.text.to_lowercase().contains(&filter))
            .map(|(index, _)| index)
            .collect();
    }

    fn edit_annotation(&mut self, address: u64, annotation: Annotation) {
        let Some(session) = &mut self.session else {
            return;
        };
        let before = session.annotations.insert(address, annotation);
        let function_name = self
            .info
            .as_ref()
            .and_then(|info| {
                info.functions
                    .iter()
                    .find(|function| function.address == address)
            })
            .map(|function| function.name.clone());
        self.undo.push_back(Edit {
            address,
            before,
            function_name,
            local: None,
        });
        while self.undo.len() > HISTORY_LIMIT
            || self.undo.iter().map(edit_size).sum::<usize>() > UNDO_BYTES
        {
            self.undo.pop_front();
        }
        self.revision = self.revision.wrapping_add(1);
    }

    fn undo(&mut self, context: &egui::Context) {
        let Some(mut edit) = self.undo.pop_back() else {
            return;
        };
        if let Some((identity, before)) = edit.local.take() {
            if let Some(session) = &mut self.session {
                session.local_renames.retain(|r| r.identity != identity);
                if let Some(before) = before {
                    session.local_renames.push(before);
                }
                self.revision = self.revision.wrapping_add(1);
                self.refresh_local_function(identity.function, context);
            }
            return;
        }
        if let Some(session) = &mut self.session {
            match edit.before {
                Some(annotation) => {
                    session.annotations.insert(edit.address, annotation);
                }
                None => {
                    session.annotations.remove(&edit.address);
                }
            }
            self.revision = self.revision.wrapping_add(1);
            self.editor_address = None;
            let name = session
                .annotations
                .get(&edit.address)
                .map(|annotation| annotation.label.clone())
                .filter(|label| !label.is_empty())
                .or(edit.function_name)
                .unwrap_or_else(|| format!("FUN_{:x}", edit.address));
            if self.info.as_ref().is_some_and(|info| {
                info.functions
                    .iter()
                    .any(|function| function.address == edit.address)
            }) {
                self.request(
                    Request::Rename {
                        address: edit.address,
                        name,
                    },
                    context,
                );
            }
        }
    }

    fn dialog_directory(&self) -> Option<PathBuf> {
        self.project_path
            .as_ref()
            .or(self.session_path.as_ref())
            .and_then(|path| path.parent())
            .or_else(|| self.binary_path.as_ref().and_then(|path| path.parent()))
            .map(std::path::Path::to_path_buf)
            .or_else(|| std::env::current_dir().ok())
    }

    fn save_project(&mut self, save_as: bool, context: &egui::Context) {
        let (Some(info), Some(session), Some(protection)) = (
            self.info.clone(),
            self.session.clone(),
            self.binary_protection.clone(),
        ) else {
            return;
        };
        let view = self
            .view
            .as_ref()
            .map(|view| crate::project::persistable_view(view, &info.sections));
        let data = ProjectData {
            info,
            session,
            view,
            decompiled: (!self.decompiled.is_empty()).then(|| self.decompiled.clone()),
            mappings: self.semantic.mappings.clone(),
            semantics: self.semantic_info.clone(),
            strings: self.strings.clone(),
            strings_truncated: self.strings_truncated,
            crypto: self.crypto.clone(),
            crypto_truncated: self.crypto_truncated,
            selected_address: self.selected,
            discovery: self.discovery_saved.clone(),
        };
        let generation = self.generation;
        let revision = self.revision;
        let previous = (!save_as).then(|| self.project_path.clone()).flatten();
        let embedded = self.embed_binary;
        let sender = self.file_dialogs.sender();
        let initial_dir = self.dialog_directory();
        self.file_task(context, move || {
            let path = previous
                .or_else(|| request_file(&sender, FileDialogKind::SaveProject, initial_dir));
            let result = path
                .map(|path| data.save(&path, &protection, embedded).map(|_| path))
                .transpose();
            FileEvent::ProjectSaved {
                generation,
                revision,
                embedded,
                result,
            }
        });
    }

    fn restore_project(&mut self, project: ProjectOpen, context: &egui::Context) {
        let ProjectOpen {
            project,
            project_path,
            discovery_index,
            ..
        } = project;
        let LoadedProject {
            data,
            binary,
            cache_compatible,
            ..
        } = project;
        self.embed_binary = binary.is_some();
        self.project_binary = binary;
        self.project_path = Some(project_path);
        self.cached_strings = cache_compatible && !data.strings.is_empty();
        self.cached_crypto = cache_compatible && !data.crypto.is_empty();
        self.strings = data.strings;
        self.strings_truncated = data.strings_truncated;
        self.strings_scanned = self.cached_strings || data.strings_truncated;
        self.crypto = data.crypto;
        self.crypto_truncated = data.crypto_truncated;
        self.rebuild_string_filter();
        if let Some(saved) = data.discovery {
            self.call_index = discovery_index;
            self.discovery_summary = Some(discovery_summary(
                "Saved discovery",
                saved.report.functions_examined,
                saved.remaining(),
                saved.batches,
                saved.report.failed_functions,
                saved.report.partial,
                "",
            ));
            self.saved_references = true;
            self.discovery_saved = Some(saved);
        }
        let selected = data
            .selected_address
            .or_else(|| data.view.as_ref().map(|v| v.address))
            .or_else(|| self.info.as_ref().map(|info| info.entry));
        if let Some(view) = data.view.filter(|view| {
            selected.is_some_and(|address| {
                address == view.address
                    || data
                        .mappings
                        .iter()
                        .any(|mapping| mapping.addresses.contains(&address))
                    || view
                        .blocks
                        .iter()
                        .any(|b| b.instructions.iter().any(|i| i.address == address))
            })
        }) {
            let address = view.address;
            self.listing = view
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter().cloned())
                .collect();
            self.listing.sort_by_key(|i| i.address);
            self.listing.dedup_by_key(|i| i.address);
            self.canvas = Some(GraphCanvas::new(&view));
            self.view = Some(view);
            self.comment_rows_key = None;
            self.saved_analysis = true;
            self.cached_graph = true;
            self.history.push(address);
            self.history_index = 0;
            self.selected = selected;
            self.address = format!("{:x}", selected.unwrap_or(address));
            if let Some(text) = data.decompiled {
                self.semantic_info = data.semantics;
                self.semantic.mappings = data.mappings;
                self.comment_rows_key = None;
                if let Some(address) = selected {
                    self.semantic.select_instruction(address);
                }
                self.highlighted = Some(HighlightedCode::new(&text));
                let mut offset = 0;
                self.decompiled_lines = text
                    .split_inclusive('\n')
                    .take(20_000)
                    .map(|line| {
                        let range = (offset, offset + line.len());
                        offset += line.len();
                        range
                    })
                    .collect();
                self.decompiled = text;
            } else if self.should_auto_decompile() {
                self.schedule_request(Request::Decompile { address });
            }
            self.status = "Project opened — showing saved analysis; use Analysis → Refresh function to recompute".into();
        } else if let Some(address) = selected {
            self.navigate(address, true, context);
            self.status = if cache_compatible {
                "Project opened; loading function"
            } else {
                "Project opened; engine version changed, regenerating analysis"
            }
            .into();
        }
    }

    fn open_project(&mut self, project_path: PathBuf, context: &egui::Context) {
        let generation = self.generation;
        let revision = self.revision;
        let sender = self.file_dialogs.sender();
        // Only the user-selected project's directory is used. A source hint in
        // an untrusted project must never cause implicit network/file access.
        let initial_dir = project_path.parent().map(std::path::Path::to_path_buf);
        self.file_task(context, move || {
            let result = (|| {
                let project = ProjectData::load(&project_path)?;
                let discovery_index = project
                    .data
                    .discovery
                    .as_ref()
                    .map(|saved| crate::call_analysis::CallIndex::new(saved.report.clone()));
                let binary_path = if let Some(binary) = &project.binary {
                    binary.path().to_owned()
                } else {
                    let Some(path) =
                        request_file(&sender, FileDialogKind::LocateProjectBinary, initial_dir)
                    else {
                        return Ok(None);
                    };
                    BinaryProtection::open(&path)?.verify_sha256(&project.data.info.sha256)?;
                    path
                };
                Ok(Some(Box::new(ProjectOpen {
                    project,
                    project_path,
                    binary_path,
                    discovery_index,
                })))
            })();
            FileEvent::ProjectLoaded {
                generation,
                revision,
                result,
            }
        });
    }

    fn file_task(
        &mut self,
        context: &egui::Context,
        task: impl FnOnce() -> FileEvent + Send + 'static,
    ) {
        if self.file_job.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = context.clone();
        match std::thread::Builder::new()
            .name("desktop-files".into())
            .spawn(move || {
                let _ = sender.send(task());
                context.request_repaint();
            }) {
            Ok(_) => self.file_job = Some(receiver),
            Err(error) => self.status = format!("Cannot start file operation: {error}"),
        }
    }

    fn save_annotations(&mut self, context: &egui::Context) {
        let (Some(session), Some(protection)) =
            (self.session.clone(), self.binary_protection.clone())
        else {
            return;
        };
        let generation = self.generation;
        let revision = self.revision;
        let previous = self.session_path.clone();
        let project_path = self.project_path.clone();
        let info = self.info.clone();
        let sender = self.file_dialogs.sender();
        let initial_dir = self.dialog_directory();
        self.file_task(context, move || {
            let path = previous
                .or_else(|| request_file(&sender, FileDialogKind::SaveAnnotations, initial_dir));
            let result = path
                .map(|path| {
                    let project_guard = project_path
                        .as_ref()
                        .map(|p| BinaryProtection::open(p))
                        .transpose()?;
                    if let Some(info) = &info {
                        crate::project::protect_binary_destination(&path, info)?;
                    }
                    session
                        .save_with_guards(&path, &protection, project_guard.as_slice())
                        .map(|_| path)
                })
                .transpose();
            FileEvent::Saved {
                generation,
                revision,
                result,
            }
        });
    }

    fn load_annotations(&mut self, context: &egui::Context) {
        let Some(session) = &self.session else {
            return;
        };
        let generation = self.generation;
        let revision = self.revision;
        let hash = session.binary_sha256.clone();
        let sections = self
            .info
            .as_ref()
            .map(|info| info.sections.clone())
            .unwrap_or_default();
        let sender = self.file_dialogs.sender();
        let initial_dir = self.dialog_directory();
        self.file_task(context, move || {
            let path = request_file(&sender, FileDialogKind::OpenAnnotations, initial_dir);
            let result = path
                .map(|path| {
                    let session = Session::load(&path, &hash)?;
                    session.validate_ranges(&sections)?;
                    Ok((session, path))
                })
                .transpose();
            FileEvent::Loaded {
                generation,
                revision,
                hash,
                result,
            }
        });
    }

    fn poll_files(&mut self, context: &egui::Context) {
        let Some(receiver) = &self.file_job else {
            return;
        };
        let event = match receiver.try_recv() {
            Ok(event) => event,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.file_job = None;
                self.after_save = None;
                self.status = "File operation stopped unexpectedly".into();
                return;
            }
        };
        self.file_job = None;
        match event {
            FileEvent::Chosen(Some(path)) => self.request_intent(Intent::OpenPath(path), context),
            FileEvent::ProjectChosen(Some(path)) => {
                self.request_intent(Intent::OpenProjectPath(path), context)
            }
            FileEvent::Chosen(None) | FileEvent::ProjectChosen(None) => {}
            FileEvent::ProjectLoaded {
                generation,
                revision,
                result,
            } if generation == self.generation && revision == self.revision => match result {
                Ok(Some(project)) => {
                    let path = project.binary_path.clone();
                    self.start_open(path, false, None, context);
                    if self.opening.is_some() {
                        if let Some(binary) = &project.project.binary
                            && let Some(client) = &mut self.client
                        {
                            client.retain_source(std::sync::Arc::new(binary.clone()));
                        }
                        self.opening_project = Some(project);
                    }
                }
                Ok(None) => self.status = "Open project cancelled".into(),
                Err(error) => self.status = error,
            },
            FileEvent::ProjectSaved {
                generation,
                revision,
                embedded,
                result,
            } if generation == self.generation => match result {
                Ok(Some(path)) => {
                    self.project_path = Some(path);
                    self.embed_binary = embedded;
                    self.saved_revision = revision;
                    self.status = "Project saved (.grproj)".into();
                    self.finish_save(context);
                }
                Ok(None) => {
                    self.intent = self.after_save.take();
                    self.status = "Save cancelled".into();
                }
                Err(error) => {
                    self.intent = self.after_save.take();
                    self.status = error;
                }
            },
            FileEvent::Saved {
                generation,
                revision,
                result,
            } if generation == self.generation => match result {
                Ok(Some(path)) => {
                    self.session_path = Some(path);
                    if self.project_path.is_none() {
                        self.saved_revision = revision;
                    }
                    self.status = "Annotations exported (JSON)".into();
                }
                Ok(None) => {
                    self.intent = self.after_save.take();
                    self.status = "Save cancelled".into();
                }
                Err(error) => {
                    self.intent = self.after_save.take();
                    self.status = error;
                }
            },
            FileEvent::Loaded {
                generation,
                revision,
                hash,
                result,
            } if generation == self.generation
                && self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.binary_sha256 == hash) =>
            {
                if revision != self.revision {
                    self.status = "Annotations changed while the sidecar was loading; loaded notes were not applied".into();
                    return;
                }
                match result {
                    Ok(Some((session, path))) => {
                        self.session = Some(session);
                        self.session_path = Some(path);
                        self.undo.clear();
                        self.revision = self.revision.wrapping_add(1);
                        if self.project_path.is_none() {
                            self.saved_revision = self.revision;
                        }
                        self.editor_address = None;
                        self.applied_names.clear();
                        self.decompiled.clear();
                        self.semantic.clear();
                        self.comment_rows_key = None;
                        self.semantic_info = SemanticInfo::default();
                        self.selected_local = None;
                        self.decompiler_rename_context = false;
                        self.pending_code_scroll = None;
                        self.pending_comment_scroll = None;
                        self.pending_listing_scroll = None;
                        self.highlighted = None;
                        self.decompiled_lines.clear();
                        self.status = "Annotations loaded".into();
                        self.rebuild_filter();
                        // A fresh engine also removes names absent from the newly
                        // loaded sidecar; current-function labels are replayed.
                        if let Some(address) = self.view.as_ref().map(|view| view.address)
                            && let Some(path) = self.binary_path.clone()
                        {
                            self.start_open(path, true, Some(Request::Graph { address }), context);
                        }
                    }
                    Ok(None) => {}
                    Err(error) => self.status = error,
                }
            }
            _ => {
                self.status = "Discarded a file result from a previously opened binary".into();
                self.after_save = None;
            }
        }
    }

    fn finish_save(&mut self, context: &egui::Context) {
        if !self.dirty()
            && let Some(intent) = self.after_save.take()
        {
            self.execute_intent(intent, context);
        } else if let Some(intent) = self.after_save.take() {
            self.intent = Some(intent);
        }
    }

    fn unsaved_window(&mut self, context: &egui::Context) {
        if self.intent.is_none() {
            return;
        }
        let mut choice = None;
        egui::Modal::new(egui::Id::unique("unsaved-annotations")).show(context, |ui| {
            ui.heading("Unsaved annotations");
            ui.label("Save your annotation changes before continuing?");
            ui.horizontal(|ui| {
                if ui.button("Save and continue").clicked() {
                    choice = Some(0);
                }
                if ui.button("Discard changes").clicked() {
                    choice = Some(1);
                }
                if ui.button("Cancel").clicked() {
                    choice = Some(2);
                }
            });
        });
        match choice {
            Some(0) => {
                self.after_save = self.intent.take();
                self.save_project(false, context);
            }
            Some(1) => {
                if let Some(intent) = self.intent.take() {
                    self.execute_intent(intent, context);
                }
            }
            Some(2) => self.intent = None,
            _ => {}
        }
    }

    fn analyze_window(&mut self, context: &egui::Context) {
        let Some(prompt) = &self.analyze_prompt else {
            return;
        };
        let Some(info) = self
            .info
            .as_ref()
            .filter(|_| prompt.generation == self.generation)
        else {
            self.analyze_prompt = None;
            return;
        };
        let first_open = prompt.first_open;
        let packed = crate::packing::has_upx_warning(info);
        let name = crop(
            &std::path::Path::new(&info.path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            60,
        );
        let options = &mut self.analysis_options;
        let mut analyze = false;
        let mut dismiss = false;
        let modal = egui::Modal::new(egui::Id::unique("auto-analysis")).show(context, |ui| {
            ui.set_width(440.0);
            ui.heading(if first_open { "Analyze binary?" } else { "Auto Analysis" });
            ui.label(if first_open {
                format!("{name} has not been analyzed. Analyze it now?")
            } else {
                format!("Choose the analyses to run on {name}.")
            });
            ui.add_space(8.0);
            ui.add_enabled(
                !packed,
                egui::Checkbox::new(&mut options.functions, "Function discovery and references"),
            );
            ui.weak(if packed {
                crate::packing::UPX_ANALYSIS_ERROR
            } else {
                "Follows confirmed direct calls and indexes call and data references."
            });
            ui.checkbox(&mut options.strings, "Defined strings");
            ui.add_enabled_ui(options.strings, |ui| {
                ui.horizontal(|ui| {
                    ui.weak("Minimum characters");
                    ui.add(
                        egui::DragValue::new(&mut self.string_minimum)
                            .range(MIN_STRING_LENGTH..=MAX_STRING_MINIMUM)
                            .speed(1),
                    );
                });
            });
            ui.checkbox(&mut options.crypto, "FindCrypt constants");
            ui.weak("Heuristic matches for standardized cryptographic constants.");
            ui.add_space(8.0);
            ui.weak("Analysis runs in the background while you browse. Cancel it from the Analysis menu.");
            ui.separator();
            ui.horizontal(|ui| {
                let selected = options.functions && !packed || options.strings || options.crypto;
                analyze = ui.add_enabled(selected, egui::Button::new("Analyze")).clicked();
                dismiss = ui
                    .button(if first_open { "Not now" } else { "Cancel" })
                    .clicked();
            });
        });
        if analyze {
            self.analyze_prompt = None;
            self.start_auto_analysis();
            self.pump_analysis(context);
        } else if dismiss
            // A stray click beside the one-time prompt should not dismiss it.
            || modal.should_close() && context.input(|input| input.key_pressed(egui::Key::Escape))
        {
            self.analyze_prompt = None;
        }
    }

    fn begin_rename(&mut self) {
        if self.decompiler_rename_context && self.selected_local.is_none() {
            self.status =
                "Local rename unsupported: select a verified local-variable token; refresh legacy pseudocode if needed".into();
            return;
        }
        if let Some(local) = self
            .selected_local
            .and_then(|i| self.semantic_info.locals.get(i))
        {
            self.browser_dialog = Some(BrowserDialog {
                kind: BrowserDialogKind::RenameLocal {
                    identity: local.identity.clone(),
                },
                text: local.name.clone(),
                error: None,
                focus: true,
                generation: self.generation,
            });
            return;
        }
        let (Some(address), Some(info), Some(session)) = (self.selected, &self.info, &self.session)
        else {
            return;
        };
        let function = function_at(&info.functions, address);
        let text = session
            .annotations
            .get(&address)
            .map(|note| note.label.clone())
            .filter(|name| !name.is_empty())
            .or_else(|| function.map(|function| function.name.clone()))
            .unwrap_or_default();
        self.browser_dialog = Some(BrowserDialog {
            kind: BrowserDialogKind::Rename {
                address,
                function: function.is_some(),
            },
            text,
            error: None,
            focus: true,
            generation: self.generation,
        });
    }

    fn rename_local(
        &mut self,
        identity: &LocalIdentity,
        name: &str,
        context: &egui::Context,
    ) -> Result<(), String> {
        crate::semantic::validate_name(name)?;
        if identity.engine != crate::semantic::LOCAL_FINGERPRINT
            || !self
                .semantic_info
                .locals
                .iter()
                .any(|v| &v.identity == identity)
            || self
                .view
                .as_ref()
                .is_none_or(|v| v.address != identity.function)
        {
            return Err(
                "Local identity is no longer present; refresh and select the variable again".into(),
            );
        }
        if self
            .semantic_info
            .locals
            .iter()
            .any(|v| v.identity != *identity && v.name == name)
        {
            return Err("Name is already used by another local variable".into());
        }
        let session = self.session.as_mut().ok_or("Open a binary first")?;
        let before = session
            .local_renames
            .iter()
            .find(|r| r.identity == *identity)
            .cloned();
        if before.as_ref().is_some_and(|r| r.name == name) {
            return Ok(());
        }
        let mut updated = session.local_renames.clone();
        updated.retain(|r| r.identity != *identity);
        updated.push(LocalRename {
            identity: identity.clone(),
            name: name.into(),
        });
        crate::semantic::validate_renames(&updated, None)?;
        session.local_renames = updated;
        session.version = 2;
        self.undo.push_back(Edit {
            address: identity.function,
            before: None,
            function_name: None,
            local: Some((identity.clone(), before)),
        });
        while self.undo.len() > HISTORY_LIMIT
            || self.undo.iter().map(edit_size).sum::<usize>() > UNDO_BYTES
        {
            self.undo.pop_front();
        }
        self.revision = self.revision.wrapping_add(1);
        self.refresh_local_function(identity.function, context);
        Ok(())
    }

    fn refresh_local_function(&mut self, function: u64, context: &egui::Context) {
        if self.view.as_ref().is_some_and(|v| v.address == function) {
            self.decompiled.clear();
            self.decompiled_lines.clear();
            self.highlighted = None;
            self.semantic.clear();
            self.semantic_info = SemanticInfo::default();
            self.selected_local = None;
            self.decompiler_rename_context = false;
            self.pending_code_scroll = None;
            self.pending_comment_scroll = None;
            self.comment_rows_key = None;
            self.request(Request::Decompile { address: function }, context);
        }
    }

    fn begin_go_to(&mut self) {
        if self.info.is_some() {
            self.browser_dialog = Some(BrowserDialog {
                kind: BrowserDialogKind::GoTo,
                text: self.address.clone(),
                error: None,
                focus: true,
                generation: self.generation,
            });
        }
    }

    fn resolve_location(&self, query: &str) -> Result<u64, String> {
        let info = self.info.as_ref().ok_or("Open a binary first")?;
        let query = query.trim();
        let address = parse_address(query)
            .ok()
            .or_else(|| {
                self.session
                    .as_ref()?
                    .annotations
                    .iter()
                    .find(|(_, note)| !note.label.is_empty() && note.label == query)
                    .map(|(&address, _)| address)
            })
            .or_else(|| {
                info.functions
                    .iter()
                    .find(|function| function.name == query)
                    .map(|function| function.address)
            })
            .ok_or("Enter a hexadecimal address or an exact function/label name")?;
        if !info
            .sections
            .iter()
            .any(|section| address >= section.address && address - section.address < section.size)
        {
            return Err("Address is outside mapped program memory".into());
        }
        Ok(address)
    }

    fn rename_at(
        &mut self,
        address: u64,
        name: &str,
        context: &egui::Context,
    ) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
            return Err("Names must contain 1–256 bytes and no control characters".into());
        }
        let mut note = self
            .session
            .as_ref()
            .ok_or("Open a binary first")?
            .annotations
            .get(&address)
            .cloned()
            .unwrap_or_default();
        if note.label == name {
            return Ok(());
        }
        let function = self.info.as_ref().is_some_and(|info| {
            info.functions
                .iter()
                .any(|function| function.address == address)
        });
        note.label = name.into();
        self.edit_annotation(address, note);
        self.editor_address = None;
        self.rebuild_filter();
        if function {
            self.decompiled.clear();
            self.semantic.clear();
            self.comment_rows_key = None;
            self.semantic_info = SemanticInfo::default();
            self.selected_local = None;
            self.decompiler_rename_context = false;
            self.pending_code_scroll = None;
            self.pending_comment_scroll = None;
            self.pending_listing_scroll = None;
            self.decompiled_lines.clear();
            self.highlighted = None;
            self.request(
                Request::Rename {
                    address,
                    name: name.into(),
                },
                context,
            );
        } else {
            self.status = format!("Label set at {address:#x}");
        }
        Ok(())
    }

    fn history_step(&mut self, forward: bool, context: &egui::Context) {
        if forward && self.history_index + 1 < self.history.len() {
            self.history_index += 1;
        } else if !forward && self.history_index > 0 {
            self.history_index -= 1;
        } else {
            return;
        }
        self.navigate_annotation(self.history[self.history_index], false, context);
    }

    fn handle_shortcuts(&mut self, context: &egui::Context) {
        if self.info.is_none()
            || self.opening.is_some()
            || self.file_job.is_some()
            || self.intent.is_some()
            || self.browser_dialog.is_some()
            || context.egui_wants_keyboard_input()
            || egui::Popup::is_any_open(context)
            || context.memory(|memory| memory.top_modal_layer().is_some())
        {
            return;
        }
        let action = context.input_mut(|input| {
            let (index, action) = input
                .events
                .iter()
                .enumerate()
                .find_map(|(index, event)| shortcut(event).map(|action| (index, action)))?;
            input.events.remove(index);
            Some(action)
        });
        match action {
            Some(Shortcut::Rename) => self.begin_rename(),
            Some(Shortcut::GoTo) => self.begin_go_to(),
            Some(Shortcut::Comment) if self.selected.is_some() => {
                self.annotations_open = true;
                self.focus_comment = true;
            }
            Some(Shortcut::ToggleGraph) => {
                self.tab = match self.tab {
                    Tab::Listing => Tab::Graph,
                    Tab::Graph => Tab::Listing,
                    other => other,
                }
            }
            Some(Shortcut::Back) => self.history_step(false, context),
            Some(Shortcut::Forward) => self.history_step(true, context),
            Some(Shortcut::Save) => self.save_project(false, context),
            Some(Shortcut::Undo) => self.undo(context),
            _ => {}
        }
        if action.is_some() {
            context.request_repaint();
        }
    }

    fn browser_dialog(&mut self, context: &egui::Context) {
        let Some(mut dialog) = self.browser_dialog.take() else {
            return;
        };
        if dialog.generation != self.generation {
            return;
        }
        let mut apply = false;
        let mut cancel = false;
        let modal = egui::Modal::new(egui::Id::unique("browser-command")).show(context, |ui| {
            ui.set_width(420.0);
            let title = match &dialog.kind {
                BrowserDialogKind::Rename { function: true, .. } => "Rename Function",
                BrowserDialogKind::Rename { .. } => "Set Label",
                BrowserDialogKind::GoTo => "Go To",
                BrowserDialogKind::RenameLocal { .. } => "Rename Local Variable",
            };
            ui.heading(title);
            match &dialog.kind {
                BrowserDialogKind::Rename { address, .. } => {
                    ui.label(format!("Address {address:#x}"));
                }
                BrowserDialogKind::GoTo => {
                    ui.label("Hexadecimal address or function/label name");
                }
                BrowserDialogKind::RenameLocal { identity } => {
                    ui.label(format!("Local in function {:#x}", identity.function));
                }
            }
            let mut output = TextEdit::singleline(&mut dialog.text)
                .char_limit(512)
                .desired_width(f32::INFINITY)
                .show(ui);
            if dialog.focus {
                output.response.request_focus();
                output
                    .state
                    .cursor
                    .set_char_range(Some(egui::text::CCursorRange::select_all(&output.galley)));
                output.state.store(context, output.response.id);
                dialog.focus = false;
            }
            apply |= context.input(|input| input.key_pressed(egui::Key::Enter));
            if let Some(error) = &dialog.error {
                ui.colored_label(theme::ERROR, error);
            }
            ui.horizontal(|ui| {
                apply |= ui.button("OK").clicked();
                cancel |= ui.button("Cancel").clicked();
            });
        });
        if cancel || modal.should_close() {
            return;
        }
        if apply {
            let result = match &dialog.kind {
                BrowserDialogKind::Rename { address, .. } => {
                    self.rename_at(*address, &dialog.text, context)
                }
                BrowserDialogKind::RenameLocal { identity } => {
                    self.rename_local(identity, &dialog.text, context)
                }
                BrowserDialogKind::GoTo => self
                    .resolve_location(&dialog.text)
                    .map(|address| self.navigate(address, true, context)),
            };
            match result {
                Ok(()) => return,
                Err(error) => dialog.error = Some(error),
            }
        }
        self.browser_dialog = Some(dialog);
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        let loaded = self.info.is_some();
        egui::MenuBar::new().ui(ui, |ui| {
            theme::brand_mark(ui);
            ui.menu_button("File", |ui| {
                if ui.button("Open binary…").clicked() {
                    self.request_intent(Intent::OpenDialog, &context);
                    ui.close();
                }
                if ui.button("Open project…").clicked() {
                    self.request_intent(Intent::OpenProjectDialog, &context);
                    ui.close();
                }
                ui.add_enabled_ui(loaded && self.file_job.is_none(), |ui| {
                    if ui.add(egui::Button::new("Save project…").shortcut_text("Ctrl+S")).clicked() {
                        self.save_project(false, &context);
                        ui.close();
                    }
                    if ui.button("Save project as…").clicked() {
                        self.save_project(true, &context);
                        ui.close();
                    }
                    ui.checkbox(&mut self.embed_binary, "Include binary in project")
                        .on_hover_text("A portable .grproj includes the analyzed binary. Otherwise you must locate the matching binary when reopening.");
                    ui.separator();
                    if ui.button("Export annotations (JSON)…").clicked() {
                        self.save_annotations(&context);
                        ui.close();
                    }
                    if ui.button("Open annotations…").clicked() {
                        self.request_intent(Intent::LoadAnnotations, &context);
                        ui.close();
                    }
                });
                if ui
                    .add_enabled(loaded, egui::Button::new("Close binary"))
                    .clicked()
                {
                    self.request_intent(Intent::Close, &context);
                    ui.close();
                }
            });
            ui.menu_button("Edit", |ui| {
                if ui
                    .add_enabled(!self.undo.is_empty(), egui::Button::new("Undo annotation").shortcut_text("Ctrl+Z"))
                    .clicked()
                {
                    self.undo(&context);
                    ui.close();
                }
                if ui
                    .add_enabled(self.selected.is_some(), egui::Button::new("Rename function / label…").shortcut_text("L"))
                    .clicked()
                {
                    self.begin_rename();
                    ui.close();
                }
                if ui.add_enabled(self.selected.is_some(), egui::Button::new("Edit comment…").shortcut_text(";")).clicked() {
                    self.annotations_open = true;
                    self.focus_comment = true;
                    ui.close();
                }
            });
            ui.menu_button("Navigation", |ui| {
                if ui.add_enabled(loaded, egui::Button::new("Go to…").shortcut_text("G")).clicked() {
                    self.begin_go_to();
                    ui.close();
                }
                if ui.add_enabled(self.history_index > 0, egui::Button::new("Back").shortcut_text("Alt+Left")).clicked() {
                    self.history_step(false, &context);
                    ui.close();
                }
                if ui.add_enabled(self.history_index + 1 < self.history.len(), egui::Button::new("Forward").shortcut_text("Alt+Right")).clicked() {
                    self.history_step(true, &context);
                    ui.close();
                }
            });
            ui.menu_button("View", |ui| {
                for (tab, label) in [
                    (Tab::Listing, "Listing"),
                    (Tab::Graph, "Function Graph"),
                    (Tab::Strings, "Defined Strings"),
                    (Tab::Crypto, "FindCrypt"),
                    (Tab::Decode, "String Decoder"),
                    (Tab::References, "References"),
                ] {
                    if ui.selectable_value(&mut self.tab, tab, label).clicked() {
                        ui.close();
                    }
                }
                ui.separator();
                ui.checkbox(&mut self.annotations_open, "Annotations");
                ui.checkbox(&mut self.auto_decompile, "Automatic decompilation");
            });
            ui.menu_button("Analysis", |ui| {
                ui.add_enabled_ui(loaded, |ui| {
                    if ui.button("Auto analyze…").clicked() {
                        self.analyze_prompt = Some(AnalyzePrompt {
                            generation: self.generation,
                            first_open: false,
                        });
                        ui.close();
                    }
                    ui.separator();
                    if ui.add_enabled(self.view.is_some(), egui::Button::new("Refresh function")).clicked() {
                        if let Some(address) = self.view.as_ref().map(|view| view.address) {
                            self.navigate(address, false, &context);
                        }
                        ui.close();
                    }
                    for (label, request) in [
                        ("Discover functions", Request::Discover),
                        ("Find strings", self.string_request()),
                        ("Find cryptographic constants", Request::Crypto),
                    ] {
                        if ui.button(label).clicked() {
                            self.request(request, &context);
                            ui.close();
                        }
                    }
                    if ui
                        .add_enabled(
                            self.discovery.is_some() || self.call_index.is_some(),
                            egui::Button::new("Rediscover from scratch"),
                        )
                        .on_hover_text("Discard discovery results, including saved ones, and examine every known function again.")
                        .clicked()
                    {
                        self.rediscover(&context);
                        ui.close();
                    }
                });
                if ui
                    .add_enabled(
                        self.pending.is_some()
                            || self.discovery_running
                            || self.discovery_job.is_some()
                            || self.analysis_plan.is_some(),
                        egui::Button::new("Cancel analysis"),
                    )
                    .clicked()
                {
                    self.stop_worker();
                    self.analysis_plan = None;
                    self.status = "Analysis cancelled".into();
                    ui.close();
                }
            });
            ui.menu_button("Help", |ui| {
                ui.label("Ghidra / Rust — native prototype");
                ui.weak("x86 / x86-64 / AArch64 · limited analysis and signature coverage");
                ui.weak("Save .grproj projects or export JSON annotations. Java plugins are not supported.");
                ui.label("L: rename function / label · G: go to · ;: comment");
                ui.label("Space: Listing / Graph · Alt+Left/Right: history");
                ui.label("Ctrl+S: save project · Ctrl+Z: undo annotation");
                ui.weak("Shortcuts pause while typing or using a dialog. Local-variable renaming is not yet supported.");
            });
            crate::window_chrome::menu_bar_controls(ui);
        });
        ui.separator();
        ui.horizontal(|ui| {
            if ui.button("Open…").clicked() {
                self.request_intent(Intent::OpenDialog, &context);
            }
            if ui
                .add_enabled(loaded && self.file_job.is_none(), egui::Button::new("Save"))
                .clicked()
            {
                self.save_project(false, &context);
            }
            ui.separator();
            if theme::history_button(ui, false, self.history_index > 0).clicked() {
                self.history_step(false, &context);
            }
            if theme::history_button(ui, true, self.history_index + 1 < self.history.len())
                .clicked()
            {
                self.history_step(true, &context);
            }
            let entry = ui.add(
                TextEdit::singleline(&mut self.address)
                    .desired_width(130.0)
                    .hint_text("Go to address")
                    .char_limit(18),
            );
            if ui.button("Go").clicked()
                || (entry.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
            {
                match parse_address(&self.address) {
                    Ok(address) => self.navigate(address, true, &context),
                    Err(error) => self.status = error,
                }
            }
            ui.separator();
            if ui
                .add_enabled(loaded, egui::Button::new("Annotate"))
                .clicked()
            {
                self.annotations_open = true;
            }
            if self.dirty() {
                ui.colored_label(theme::WARNING, "Unsaved");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(info) = &self.info {
                    let name = std::path::Path::new(&info.path)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    ui.label(RichText::new(crop(&name, 45)).strong());
                }
            });
        });
    }

    fn navigation_panel(&mut self, ui: &mut egui::Ui) {
        let tree_height = (ui.available_height() * 0.36).clamp(160.0, 450.0);
        egui::Panel::top("symbol-tree-dock")
            .default_size(tree_height)
            .min_size(100.0)
            .resizable(true)
            .frame(theme::inner_frame())
            .show(ui, |ui| {
                ui.set_min_height(ui.available_height());
                theme::dock_header(ui, "Program", false, |ui| {if self.cached_functions || self.cached_strings || self.cached_crypto {ui.weak("Saved analysis").on_hover_text("Some tree results were loaded from the project. Recompute the corresponding analysis to verify them.");}});
                ui.horizontal(|ui| {
                    theme::tab(ui, &mut self.program_tree, false, "Symbol Tree");
                    theme::tab(ui, &mut self.program_tree, true, "Program Trees");
                });
                ui.separator();
                self.symbol_tree(ui);
            });
        self.function_panel(ui);
    }

    fn symbol_tree(&mut self, ui: &mut egui::Ui) {
        let mut function = None;
        let mut read = None;
        let mut scan_strings = false;
        ScrollArea::both()
            .id_salt("symbol-tree-scroll")
            // Fill the resized dock rather than anchoring nested scrollbars to
            // the width of whichever tree label was painted last.
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let Some(info) = &self.info else {
                    ui.weak("No program loaded");
                    return;
                };
                let name = std::path::Path::new(&info.path)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy();
                egui::CollapsingHeader::new(crop(&name, 100))
                    .default_open(true)
                    .show(ui, |ui| {
                        if !self.program_tree {
                            egui::CollapsingHeader::new(format!(
                                "Functions ({})",
                                info.functions.len()
                            ))
                            .show(ui, |ui| {
                                ScrollArea::vertical()
                                    .id_salt("tree-function-scroll")
                                    .auto_shrink([false, true])
                                    .max_height(180.0)
                                    .show_rows(ui, 20.0, info.functions.len(), |ui, rows| {
                                        for index in rows {
                                            let item = &info.functions[index];
                                            if ui
                                                .add(
                                                    egui::Button::selectable(
                                                        self.view.as_ref().is_some_and(|v| {
                                                            v.address == item.address
                                                        }),
                                                        crop(&item.name, 100),
                                                    )
                                                    .truncate(),
                                                )
                                                .on_hover_text(&item.name)
                                                .clicked()
                                            {
                                                function = Some(item.address);
                                            }
                                        }
                                    });
                            });
                            egui::CollapsingHeader::new("Labels").show(ui, |ui| {
                                let mut found = false;
                                if let Some(session) = &self.session {
                                    for (address, annotation) in session
                                        .annotations
                                        .iter()
                                        .filter(|(_, a)| !a.label.is_empty())
                                        .take(512)
                                    {
                                        found = true;
                                        if ui
                                            .selectable_label(false, crop(&annotation.label, 100))
                                            .clicked()
                                        {
                                            if function_at(&info.functions, *address).is_some() {
                                                function = Some(*address);
                                            } else {
                                                read = Some((*address, 128));
                                            }
                                        }
                                    }
                                }
                                if !found {
                                    ui.weak("No user labels");
                                }
                            });
                            egui::CollapsingHeader::new(if self.strings_scanned {
                                format!("Strings ({})", self.strings.len())
                            } else {
                                "Strings (not scanned)".into()
                            })
                            .show(ui, |ui| {
                                if self.strings.is_empty() {
                                    if ui.small_button("Find strings").clicked() {
                                        scan_strings = true;
                                    }
                                } else {
                                    ScrollArea::vertical()
                                        .id_salt("tree-string-scroll")
                                        .auto_shrink([false, true])
                                        .max_height(160.0)
                                        .show_rows(ui, 20.0, self.strings.len(), |ui, rows| {
                                            for index in rows {
                                                let string = &self.strings[index];
                                                if ui
                                                    .add(
                                                        egui::Button::selectable(
                                                            false,
                                                            crop(&string.text, 100),
                                                        )
                                                        .truncate(),
                                                    )
                                                    .on_hover_text(&string.text)
                                                    .clicked()
                                                {
                                                    let length = if string.encoding.contains("16") {
                                                        string
                                                            .text
                                                            .encode_utf16()
                                                            .count()
                                                            .saturating_mul(2)
                                                    } else {
                                                        string.text.len()
                                                    };
                                                    read = Some((
                                                        string.address,
                                                        length.clamp(1, crate::decode::MAX_INPUT),
                                                    ));
                                                }
                                            }
                                        });
                                }
                            });
                        }
                        egui::CollapsingHeader::new(format!("Sections ({})", info.sections.len()))
                            .default_open(self.program_tree)
                            .show(ui, |ui| {
                                for section in info.sections.iter().take(512) {
                                    if ui
                                        .selectable_label(
                                            false,
                                            format!(
                                                "{}  {:x}",
                                                crop(&section.name, 60),
                                                section.address
                                            ),
                                        )
                                        .on_hover_text(format!(
                                            "{} bytes{}",
                                            section.size,
                                            if section.executable {
                                                " · executable"
                                            } else {
                                                ""
                                            }
                                        ))
                                        .clicked()
                                    {
                                        read = Some((
                                            section.address,
                                            (section.size.min(128)) as usize,
                                        ));
                                    }
                                }
                            });
                    });
            });
        let context = ui.ctx().clone();
        if let Some(address) = function {
            self.navigate(address, true, &context);
        }
        if let Some((address, length)) = read {
            self.select_instruction(address);
            self.tab = Tab::Decode;
            self.request(Request::Bytes { address, length }, &context);
        }
        if scan_strings {
            self.request(self.string_request(), &context);
        }
    }

    fn function_panel(&mut self, ui: &mut egui::Ui) {
        theme::dock_header(ui, "Functions", false, |ui| {
            if self.cached_functions {
                ui.weak("Saved analysis").on_hover_text("Function names and addresses loaded from the project. Discover functions to recompute.");
            }
        });
        if ui
            .add(
                TextEdit::singleline(&mut self.function_filter)
                    .id(egui::Id::unique("function-filter"))
                    .hint_text("Filter name or address")
                    .char_limit(256),
            )
            .changed()
        {
            self.restart_filter();
        }
        if self.step_filter(FILTER_FRAME_BUDGET) {
            ui.weak(format!("{} functions", self.filtered_functions.len()));
        } else {
            ui.weak(format!(
                "Filtering… {} matches",
                self.filtered_functions.len()
            ));
            ui.ctx().request_repaint();
        }
        if self
            .info
            .as_ref()
            .is_some_and(|info| info.functions_truncated)
        {
            ui.colored_label(theme::WARNING, "Partial function list")
                .on_hover_text("Loading or discovery reached a budget or encountered incomplete flow. Known entries are retained; see References and Analysis notes for coverage.");
        }
        ui.label(RichText::new("Address       Name").monospace().weak());
        let mut navigate = None;
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        ScrollArea::vertical()
            .id_salt("function-list")
            .auto_shrink([false, false])
            .show_rows(ui, row_height, self.filtered_functions.len(), |ui, rows| {
                if let Some(info) = &self.info {
                    for row in rows {
                        let function = &info.functions[self.filtered_functions[row]];
                        let label = self
                            .session
                            .as_ref()
                            .and_then(|session| session.annotations.get(&function.address))
                            .map(|annotation| annotation.label.as_str())
                            .filter(|label| !label.is_empty())
                            .unwrap_or(&function.name);
                        let response = ui
                            .add(
                                egui::Button::selectable(
                                    self.view
                                        .as_ref()
                                        .is_some_and(|view| view.address == function.address),
                                    RichText::new(format!("{:08x}  {}", function.address, label))
                                        .monospace(),
                                )
                                .truncate(),
                            )
                            .on_hover_text(format!("{:x}  {}", function.address, label));
                        if response.clicked() {
                            navigate = Some(function.address);
                        }
                        response.context_menu(|ui| {
                            if ui.button("Rename / comment…").clicked() {
                                navigate = Some(function.address);
                                self.annotations_open = true;
                                ui.close();
                            }
                        });
                    }
                }
            });
        if let Some(address) = navigate {
            self.navigate(address, true, ui.ctx());
        }
    }

    fn update_comment_rows(&mut self) {
        let key = (self.generation, self.selection_generation, self.revision);
        if self.comment_rows_key == Some(key) {
            return;
        }
        self.comment_rows = if let Some(session) = &self.session {
            self.annotation_browser
                .update(self.generation, self.revision, &session.annotations);
            CommentRows::new(
                self.view.as_ref().map(|view| view.address),
                &self.decompiled_lines,
                &self.semantic.mappings,
                &self.listing,
                &session.annotations,
            )
        } else {
            CommentRows::new(
                None,
                &self.decompiled_lines,
                &self.semantic.mappings,
                &self.listing,
                &BTreeMap::new(),
            )
        };
        if let Some(view) = &self.view {
            for &address in &self.comment_rows.addresses {
                self.comment_owners.insert(address, view.address);
            }
            if let Some(session) = &self.session {
                for instruction in &self.listing {
                    if session.annotations.contains_key(&instruction.address) {
                        self.comment_owners
                            .insert(instruction.address, view.address);
                    }
                }
            }
        }
        self.comment_owners.retain(|pc, _| {
            self.history.contains(pc)
                || self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.annotations.contains_key(pc))
        });
        self.comment_rows_key = Some(key);
    }

    fn navigate_annotation(&mut self, address: u64, record: bool, context: &egui::Context) {
        self.update_comment_rows();
        let current_owner = self
            .view
            .as_ref()
            .filter(|view| {
                address == view.address
                    || self
                        .listing
                        .binary_search_by_key(&address, |i| i.address)
                        .is_ok()
                    || self
                        .semantic
                        .mappings
                        .iter()
                        .any(|m| m.addresses.contains(&address))
            })
            .map(|view| view.address);
        let owner = current_owner
            .or_else(|| self.comment_owners.get(&address).copied())
            .unwrap_or(address);
        if record {
            // Capture the exact departure selection, including an instruction
            // reached by a single click, for predictable Back/Forward behavior.
            if let Some(selected) = self.selected {
                if let Some(view) = &self.view
                    && (selected == view.address
                        || self
                            .listing
                            .binary_search_by_key(&selected, |i| i.address)
                            .is_ok()
                        || self
                            .semantic
                            .mappings
                            .iter()
                            .any(|m| m.addresses.contains(&selected)))
                {
                    self.comment_owners.insert(selected, view.address);
                }
                if let Some(previous) = self.history.get_mut(self.history_index) {
                    *previous = selected;
                }
            }
            self.history.truncate(self.history_index + 1);
            if self.history.last() != Some(&address) {
                self.history.push(address);
            }
            if self.history.len() > 256 {
                self.history.remove(0);
            }
            self.history_index = self.history.len().saturating_sub(1);
            self.comment_owners.retain(|pc, _| {
                self.history.contains(pc)
                    || self
                        .session
                        .as_ref()
                        .is_some_and(|s| s.annotations.contains_key(pc))
            });
        }
        if self
            .info
            .as_ref()
            .is_some_and(|info| !crate::call_analysis::code_address(info, address))
        {
            // Comments can belong to data as well as instructions. Never turn
            // an annotated string/global into a guessed function entry.
            self.reference_focus = None;
            self.select_instruction(address);
            self.tab = Tab::Decode;
            self.request(
                Request::Bytes {
                    address,
                    length: 128,
                },
                context,
            );
            return;
        }
        if record || !matches!(self.tab, Tab::Listing | Tab::Graph) {
            self.tab = Tab::Listing;
        }
        if self.view.as_ref().is_some_and(|view| view.address == owner) {
            self.select_instruction(address);
            self.pending_listing_scroll = self.listing.iter().position(|i| i.address == address);
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
        } else {
            self.navigate(owner, false, context);
            self.selected = Some(address);
            self.address = format!("{address:x}");
            self.reference_focus = Some((owner, address));
        }
    }

    fn open_comment(&mut self, address: u64) {
        self.select_instruction(address);
        self.annotations_open = true;
        self.focus_comment = true;
    }

    fn annotation_browser(&mut self, ui: &mut egui::Ui) {
        self.update_comment_rows();
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.annotation_browser.query)
                    .hint_text("Filter address, label or comment")
                    .char_limit(256),
            );
            ui.checkbox(&mut self.annotation_browser.comments_only, "Comments only");
        });
        if let Some(session) = &self.session {
            self.annotation_browser
                .update(self.generation, self.revision, &session.annotations);
        }
        ui.weak(format!(
            "{} annotations · click an address to go there",
            self.annotation_browser.filtered.len()
        ));
        let mut jump = None;
        let row = ui.text_style_height(&egui::TextStyle::Monospace) + 5.0;
        ScrollArea::both()
            .id_salt("annotation-browser")
            .max_height(200.0)
            .auto_shrink([false, false])
            .show_rows(
                ui,
                row,
                self.annotation_browser.filtered.len(),
                |ui, rows| {
                    for row in rows {
                        let entry =
                            &self.annotation_browser.entries[self.annotation_browser.filtered[row]];
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    self.selected == Some(entry.address),
                                    RichText::new(format!("{:08x}", entry.address)).monospace(),
                                )
                                .clicked()
                            {
                                jump = Some((entry.address, false));
                            }
                            if ui.small_button("Edit").clicked() {
                                jump = Some((entry.address, true));
                            }
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!("{}  {}", entry.label, entry.comment))
                                        .color(theme::SYNTAX_COMMENT),
                                )
                                .wrap_mode(egui::TextWrapMode::Extend),
                            );
                        });
                    }
                },
            );
        if let Some((address, edit)) = jump {
            self.navigate_annotation(address, true, ui.ctx());
            if edit {
                self.open_comment(address);
            }
        }
    }

    fn decompiler_call_target(&self, byte: usize) -> Option<u64> {
        match self.semantic_info.token_at(byte)?.kind {
            TokenKind::Call { target } => Some(target),
            _ => None,
        }
    }

    fn side_panel(&mut self, ui: &mut egui::Ui) {
        self.update_comment_rows();
        let context = ui.ctx().clone();
        theme::dock_header(ui, "Decompiler", false, |ui| {
            if ui
                .small_button("Copy")
                .on_hover_text("Copy full pseudocode")
                .clicked()
            {
                context.copy_text(self.decompiled.clone());
            }
            if ui.small_button("Refresh").clicked()
                && let Some(view) = &self.view
            {
                self.request(
                    Request::Decompile {
                        address: view.address,
                    },
                    &context,
                );
            }
            ui.checkbox(&mut self.auto_decompile, "Auto");
            if !self.semantic_info.warnings.is_empty() {
                ui.colored_label(
                    theme::WARNING,
                    format!(
                        "{} local name(s) not applied",
                        self.semantic_info.warnings.len()
                    ),
                )
                .on_hover_text(self.semantic_info.warnings.join("\n"));
            }
            if self.saved_analysis {
                ui.weak("Saved analysis").on_hover_text("Cached results from this project. Refresh to recompute with the analysis engine.");
            }
        });
        if let Some(view) = &self.view {
            let entry = view.address;
            let function = self
                .info
                .as_ref()
                .and_then(|info| function_at(&info.functions, view.address));
            let name = function.map(|f| f.name.as_str()).unwrap_or("function");
            let response = ui.label(
                RichText::new(format!("{}  ·  {:x}", crop(name, 100), view.address))
                    .monospace()
                    .color(theme::BLUE),
            );
            response.context_menu(|ui| {
                if ui.button("Rename / comment…").clicked() {
                    self.open_comment(entry);
                    ui.close();
                }
            });
            ui.separator();
        }
        if self.decompiled.is_empty() {
            ui.add_space(8.0);
            if self
                .info
                .as_ref()
                .is_some_and(crate::packing::has_upx_warning)
            {
                ui.colored_label(theme::WARNING, crate::packing::UPX_PACKED_WARNING);
            } else {
                ui.weak(if self.pending.is_some() {
                    "Decompilation pending…"
                } else {
                    "Select a function to view its decompiled code."
                });
            }
        }
        let row = ui.text_style_height(&egui::TextStyle::Monospace);
        let mut navigate = None;
        let mut select_code = None;
        let mut edit_comment = None;
        let mut select_comment = None;
        let mut rename_local_byte = None;
        let mut scroll = ScrollArea::both()
            .id_salt("decompiler-text")
            .auto_shrink([false, false]);
        let code_target = self.pending_code_scroll.take().map(|target| {
            self.comment_rows
                .source_rows
                .get(target)
                .copied()
                .unwrap_or(target)
        });
        let comment_target = self
            .pending_comment_scroll
            .take()
            .and_then(|address| self.comment_rows.comment_rows.get(&address).copied());
        if let Some(target) = comment_target.or(code_target) {
            scroll =
                scroll.vertical_scroll_offset(target as f32 * (row + ui.spacing().item_spacing.y));
        }
        scroll.show_rows(ui, row, self.comment_rows.rows.len(), |ui, rows| {
            for display_row in rows {
                let index = match self.comment_rows.rows[display_row] {
                    CodeRow::Source(index) => index,
                    CodeRow::UnmappedHeading => {
                        ui.colored_label(theme::WARNING, "Comments without visible code");
                        continue;
                    }
                    CodeRow::Comment(address) => {
                        if let Some(preview) = self.annotation_browser.comments.get(&address) {
                            let response = ui
                                .add(
                                    egui::Label::new(
                                        RichText::new(format!("// {address:08x}: {preview}"))
                                            .monospace()
                                            .color(theme::SYNTAX_COMMENT),
                                    )
                                    .sense(egui::Sense::click())
                                    .wrap_mode(egui::TextWrapMode::Extend),
                                )
                                .on_hover_text("Double-click to view or edit the full comment");
                            if response.clicked() {
                                select_comment = Some(address);
                            }
                            if response.double_clicked() {
                                edit_comment = Some(address);
                            }
                            response.context_menu(|ui| {
                                if ui.button("Edit comment…").clicked() {
                                    edit_comment = Some(address);
                                    ui.close();
                                }
                            });
                        }
                        continue;
                    }
                };
                let (start, end) = self.decompiled_lines[index];
                let line = self.decompiled[start..end].trim_end_matches(['\n', '\r']);
                let visible = line
                    .char_indices()
                    .nth(2000)
                    .map_or(line.len(), |(at, _)| at);
                let Some(highlighted) = &self.highlighted else {
                    continue;
                };
                let mut job = highlighted.selected_line_job(
                    &self.decompiled,
                    start..start + visible,
                    13.0,
                    &self.semantic.ranges,
                );
                if visible < line.len() {
                    job.append(
                        "…",
                        0.0,
                        egui::TextFormat {
                            font_id: egui::FontId::monospace(13.0),
                            color: theme::TEXT,
                            ..Default::default()
                        },
                    );
                }
                let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
                let response = ui.add(
                    egui::Label::new(galley.clone())
                        .selectable(true)
                        .wrap_mode(egui::TextWrapMode::Extend),
                );
                let mut pointer_byte = None;
                if response.hovered()
                    && let Some(pointer) = context.pointer_hover_pos()
                {
                    let cursor = galley.cursor_from_pos(pointer - response.rect.min);
                    let byte = line[..visible]
                        .char_indices()
                        .nth(cursor.index.0)
                        .map_or(visible, |(at, _)| at);
                    pointer_byte = (byte < visible).then_some(start + byte);
                    if byte < visible && (response.clicked() || response.secondary_clicked()) {
                        select_code = Some(start + byte);
                    }
                    if byte < visible
                        && let Some(target) = self.decompiler_call_target(start + byte)
                    {
                        let clicked = response.double_clicked();
                        response
                            .clone()
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(format!("Double-click to go to {target:#x}"));
                        if clicked {
                            navigate = Some(target);
                        }
                    }
                }
                let local_token = pointer_byte
                    .and_then(|byte| self.semantic_info.token_at(byte))
                    .filter(|t| matches!(t.kind, TokenKind::Local { .. }))
                    .cloned();
                // Egui retains context menus after the pointer leaves the row.
                let menu_id = response.id.with("local-token");
                if response.secondary_clicked() {
                    context.data_mut(|d| {
                        d.insert_temp(
                            menu_id,
                            (self.selection_generation, self.revision, local_token),
                        )
                    });
                }
                let local_token = context
                    .data(|d| {
                        d.get_temp::<(u64, u64, Option<crate::semantic::SemanticToken>)>(menu_id)
                    })
                    .filter(|(selection, revision, _)| {
                        *selection == self.selection_generation && *revision == self.revision
                    })
                    .and_then(|(_, _, token)| token);
                if let Some(token) = local_token {
                    response.context_menu(|ui| {
                        if matches!(token.kind, TokenKind::Local { local: Some(_) }) {
                            if ui.button("Rename local variable…  L").clicked() {
                                rename_local_byte = Some(token.start);
                                ui.close();
                            }
                        } else {
                            ui.label("Renaming unsupported: no verified storage identity");
                        }
                    });
                }
            }
        });
        if let Some(target) = navigate {
            self.navigate(target, true, &context);
        } else if let Some(address) = edit_comment {
            self.open_comment(address);
        } else if let Some(address) = select_comment {
            self.select_instruction(address);
            self.pending_listing_scroll = self.listing.iter().position(|i| i.address == address);
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
        } else if let Some(byte) = rename_local_byte {
            self.select_decompiled_byte(byte);
            self.begin_rename();
        } else if let Some(byte) = select_code {
            self.select_decompiled_byte(byte);
            if matches!(
                self.semantic_info.token_at(byte).map(|t| &t.kind),
                Some(TokenKind::Local { local: None })
            ) {
                self.status =
                    "Local rename unsupported: select a verified local-variable token; refresh legacy pseudocode if needed".into();
            }
        }
    }

    fn annotation_editor(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        let Some(address) = self.selected else {
            return;
        };
        if self.editor_address != Some(address) {
            self.editor_address = Some(address);
            self.comment_edit = self
                .session
                .as_ref()
                .and_then(|session| session.annotations.get(&address))
                .map(|annotation| annotation.comment.clone())
                .unwrap_or_default();
            self.name_edit = self
                .view
                .as_ref()
                .and_then(|view| function_at(&self.info.as_ref()?.functions, view.address))
                .map(|function| function.name.clone())
                .unwrap_or_default();
        }
        ui.label(format!("Selected address {address:#x}"));
        if let Some(function) = self.view.as_ref().map(|view| view.address) {
            ui.label(format!("Function {function:#x}"));
            ui.add(
                TextEdit::singleline(&mut self.name_edit)
                    .hint_text("Function name")
                    .char_limit(256),
            );
            if ui.button("Rename function").clicked() {
                let name = self.name_edit.clone();
                if let Err(error) = self.rename_at(function, &name, &context) {
                    self.status = error;
                }
            }
        }
        let comment = ScrollArea::vertical()
            .id_salt("comment-editor")
            .max_height(180.0)
            .show(ui, |ui| {
                ui.add(
                    TextEdit::multiline(&mut self.comment_edit)
                        .hint_text("Comment at selected address")
                        .desired_rows(4)
                        .char_limit(crate::session::MAX_COMMENT_BYTES),
                )
            })
            .inner;
        if self.focus_comment {
            comment.request_focus();
            self.focus_comment = false;
        }

        if ui.button("Apply comment").clicked() {
            let mut annotation = self
                .session
                .as_ref()
                .and_then(|session| session.annotations.get(&address))
                .cloned()
                .unwrap_or_default();
            annotation.comment = self.comment_edit.clone();
            if annotation.comment.len() > crate::session::MAX_COMMENT_BYTES {
                self.status = "Comment exceeds the 64 KiB limit".into();
            } else if self.session.as_ref().is_some_and(|s| {
                !s.annotations.contains_key(&address)
                    && s.annotations.len() >= crate::session::MAX_ANNOTATIONS
            }) {
                self.status = "Annotation limit reached (10000)".into();
            } else {
                self.edit_annotation(address, annotation);
            }
        }
        if ui.button("Decode 128 bytes here").clicked() {
            self.request(
                Request::Bytes {
                    address,
                    length: 128,
                },
                &context,
            );
        }
        if let Some(annotation) = self
            .session
            .as_ref()
            .and_then(|session| session.annotations.get(&address))
        {
            ScrollArea::vertical()
                .id_salt("decoded-annotations")
                .max_height(120.0)
                .show(ui, |ui| {
                    for decoded in &annotation.decoded {
                        ui.label(format!(
                            "{}: {}",
                            decoded.operation,
                            crop(&decoded.text, 400)
                        ));
                    }
                });
        }
    }

    fn navigate_reference(&mut self, caller: u64, pc: u64, context: &egui::Context) {
        self.tab = Tab::Listing;
        self.navigate(caller, true, context);
        self.reference_focus = Some((caller, pc));
    }

    fn read_data_reference(&mut self, target: u64, size: u32, context: &egui::Context) {
        // This action requests bytes; a memory target never becomes a function
        // or a guessed instruction/pseudocode link. Retain code selection and
        // project context; Decode carries the byte source's own exact address.
        self.reference_target = Some(target);
        self.reference_query = format!("{target:x}");
        self.request(
            Request::Bytes {
                address: target,
                length: size as usize,
            },
            context,
        );
    }

    fn data_references_panel(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        let Some(index) = &self.call_index else {
            ui.weak("Data accesses have not been analyzed in this session. Run discovery to compute them.");
            return;
        };
        let Some(data) = &index.report.data else {
            ui.weak("This result has no data-access analysis. Run discovery again.");
            return;
        };
        ui.weak(format!(
            "{}{} direct accesses · {} p-code operations charged · {} access candidates",
            if self.saved_references {
                "Saved analysis · "
            } else {
                ""
            },
            data.references.len(),
            data.operations_charged,
            data.accesses_examined
        ));
        ui.weak("Direct memory reads/writes in examined functions. AArch64 register constants are propagated only within a basic block; address-only values and loaded pointers are outside this pass.");
        if data.partial || index.report.partial {
            ui.colored_label(theme::WARNING, "Partial access coverage: work limits, unsupported instructions or incomplete function walks.");
        }
        ui.weak(format!(
            "{} unresolved addresses · {} omitted accesses · {} unsupported instructions",
            data.unresolved_accesses, data.omitted_accesses, data.unsupported_instructions
        ));
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.reference_query)
                    .hint_text("Hex target address")
                    .desired_width(130.0)
                    .char_limit(18),
            );
            if ui.small_button("Find accesses").clicked() {
                match parse_address(&self.reference_query) {
                    Ok(address) => self.reference_target = Some(address),
                    Err(error) => self.status = error,
                }
            }
            if ui.small_button("Current function").clicked() {
                self.reference_target = None;
            }
        });
        let rows = if let Some(target) = self.reference_target {
            ui.label(format!("Accesses starting at {target:#x}"));
            index.data_incoming.get(&target)
        } else if let Some(function) = self.view.as_ref().map(|view| view.address) {
            ui.label(format!("Accesses from function {function:#x}"));
            index.data_outgoing.get(&function)
        } else {
            ui.weak("Select a function or enter an exact target address.");
            None
        }
        .map(Vec::as_slice)
        .unwrap_or(&[]);
        ui.weak(format!(
            "{} matching accesses · an empty result does not establish absence of references",
            rows.len()
        ));
        let mut source = None;
        let mut read = None;
        let mut target = None;
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        ScrollArea::both().id_salt("data-references").show_rows(ui, row_height, rows.len(), |ui, visible| {
            for row in visible {
                let reference = &data.references[rows[row]];
                ui.horizontal(|ui| {
                    ui.weak(match reference.access { DataAccess::Read => "Read", DataAccess::Write => "Write" });
                    if reference.provenance == DataProvenance::Propagated {
                        ui.weak("propagated").on_hover_text("Pointer built from register constants set earlier in the same basic block");
                    }
                    ui.monospace(format!("{}B", reference.size));
                    if ui.button(format!("{:x}", reference.target))
                        .on_hover_text("Load exactly the accessed bytes into Decode").clicked() {
                        read = Some((reference.target, reference.size));
                    }
                    if ui.small_button("Refs").on_hover_text("Show accesses beginning at this exact address").clicked() {
                        target = Some(reference.target);
                    }
                    if ui.button(format!("{:x} @ {:x}", reference.function, reference.address))
                        .on_hover_text("Open the source function and select this decoded memory-access instruction").clicked() {
                        source = Some((reference.function, reference.address));
                    }
                });
            }
        });
        if let Some((function, pc)) = source {
            self.navigate_reference(function, pc, &context);
        } else if let Some((address, size)) = read {
            self.read_data_reference(address, size, &context);
        } else if let Some(address) = target {
            self.reference_target = Some(address);
            self.reference_query = format!("{address:x}");
        }
    }

    fn references_panel(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        if ui
            .add_enabled(
                self.info.is_some() && self.file_job.is_none(),
                egui::Button::new("Discover functions and references"),
            )
            .clicked()
        {
            self.request(Request::Discover, &context);
        }
        if let Some(summary) = &self.discovery_summary {
            ui.weak(summary);
        }
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.reference_data, false, "Calls");
            ui.selectable_value(&mut self.reference_data, true, "Data accesses");
        });
        if self.reference_data {
            self.data_references_panel(ui);
            return;
        }
        let Some(index) = &self.call_index else {
            ui.weak("Call references have not been analyzed in this session. Run discovery to compute them.");
            return;
        };
        let report = &index.report;
        ui.weak(format!(
            "{} · {} functions examined · {} decode attempts",
            if self.saved_references {
                "Saved analysis"
            } else {
                "Computed this session"
            },
            report.functions_examined,
            report.decode_attempts
        ));
        ui.weak("Confirmed direct calls in examined functions. Unknown indirect targets remain unresolved.");
        if report.partial {
            ui.colored_label(
                theme::WARNING,
                "Partial call coverage: limits, unresolved flow, or recovery failures.",
            );
        }
        ui.weak(format!(
            "{} unresolved calls · {} failed function walks · {} fallthrough calls excluded",
            report.unresolved_calls, report.failed_functions, report.skipped_fallthrough_calls
        ));
        let Some(function) = self.view.as_ref().map(|view| view.address) else {
            ui.label("Select a function to inspect its incoming and outgoing calls.");
            return;
        };
        ui.label(RichText::new(format!("Function {function:#x}")).monospace());
        let incoming = index
            .incoming
            .get(&function)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let outgoing = index
            .outgoing
            .get(&function)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let count = incoming.len() + outgoing.len();
        ui.label(format!(
            "{} incoming · {} outgoing",
            incoming.len(),
            outgoing.len()
        ));
        let name = |address| {
            self.info
                .as_ref()
                .and_then(|info| {
                    info.functions
                        .binary_search_by_key(&address, |f| f.address)
                        .ok()
                        .map(|i| &info.functions[i])
                })
                .map(|function| {
                    self.session
                        .as_ref()
                        .and_then(|s| s.annotations.get(&address))
                        .map(|a| a.label.as_str())
                        .filter(|n| !n.is_empty())
                        .unwrap_or(&function.name)
                })
                .unwrap_or("function")
        };
        let mut source = None;
        let mut target = None;
        let row_height = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
        ScrollArea::both().id_salt("call-references").show_rows(
            ui,
            row_height,
            count,
            |ui, rows| {
                for row in rows {
                    let is_incoming = row < incoming.len();
                    let reference = &report.references[if is_incoming {
                        incoming[row]
                    } else {
                        outgoing[row - incoming.len()]
                    }];
                    ui.horizontal(|ui| {
                        ui.weak(if is_incoming { "From" } else { "To" });
                        if ui
                            .button(format!(
                                "{:x} {}",
                                if is_incoming {
                                    reference.caller
                                } else {
                                    reference.target
                                },
                                crop(
                                    name(if is_incoming {
                                        reference.caller
                                    } else {
                                        reference.target
                                    }),
                                    60
                                )
                            ))
                            .clicked()
                        {
                            target = Some(if is_incoming {
                                reference.caller
                            } else {
                                reference.target
                            });
                        }
                        if ui
                            .button(format!("at {:x}", reference.address))
                            .on_hover_text(
                                "Open the caller and select this decoded call instruction",
                            )
                            .clicked()
                        {
                            source = Some((reference.caller, reference.address));
                        }
                    });
                }
            },
        );
        if let Some((caller, pc)) = source {
            self.navigate_reference(caller, pc, &context);
        } else if let Some(address) = target {
            self.navigate(address, true, &context);
        }
    }

    fn main_panel(&mut self, ui: &mut egui::Ui) {
        self.update_comment_rows();
        let title = match self.tab {
            Tab::Listing => "Listing",
            Tab::Graph => "Function Graph",
            Tab::Strings => "Defined Strings",
            Tab::Crypto => "FindCrypt",
            Tab::Decode => "String Decoder",
            Tab::References => "References",
        };
        let filename = self
            .info
            .as_ref()
            .and_then(|info| std::path::Path::new(&info.path).file_name())
            .map(|name| name.to_string_lossy());
        let title = filename.map_or_else(
            || title.to_owned(),
            |name| format!("{title}: {}", crop(&name, 90)),
        );
        theme::dock_header(ui, &title, true, |ui| {
            if (matches!(self.tab, Tab::Graph | Tab::Listing) && self.cached_graph)
                || (self.tab == Tab::Strings && self.cached_strings)
                || (self.tab == Tab::Crypto && self.cached_crypto)
            {
                ui.weak("Saved analysis")
                    .on_hover_text("Persisted project results. Scan again to recompute.");
            }
        });
        ui.horizontal_wrapped(|ui| {
            for (tab, name) in [
                (Tab::Listing, "Listing"),
                (Tab::Graph, "Function Graph"),
                (Tab::Strings, "Strings"),
                (Tab::Crypto, "FindCrypt"),
                (Tab::Decode, "Decode"),
                (Tab::References, "References"),
            ] {
                theme::tab(ui, &mut self.tab, tab, name);
            }
        });
        ui.separator();
        let context = ui.ctx().clone();
        match self.tab {
            Tab::References => self.references_panel(ui),
            Tab::Graph => {
                let mut navigate = None;
                if let Some(view) = &self.view {
                    for warning in view.warnings.iter().take(3) {
                        ui.colored_label(theme::WARNING, warning);
                    }
                    if !view.calls.is_empty() {
                        egui::CollapsingHeader::new(format!(
                            "{} direct / unresolved calls",
                            view.calls.len()
                        ))
                        .show(ui, |ui| {
                            ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                                for call in view.calls.iter().take(256) {
                                    if let Some(target) = call.target {
                                        if ui
                                            .button(format!(
                                                "{:x} → {:x}{}",
                                                call.address,
                                                target,
                                                if call.no_return.is_some() {
                                                    " [no return]"
                                                } else {
                                                    ""
                                                }
                                            ))
                                            .on_hover_text(call.no_return.map_or_else(
                                                || "Direct call".into(),
                                                |e| e.description(),
                                            ))
                                            .clicked()
                                        {
                                            navigate = Some(target);
                                        }
                                    } else {
                                        ui.weak(format!(
                                            "{:x} → unresolved{}",
                                            call.address,
                                            if call.no_return.is_some() {
                                                " [no return]"
                                            } else {
                                                ""
                                            }
                                        ))
                                        .on_hover_text(
                                            call.no_return.map_or_else(
                                                || "Unresolved indirect call".into(),
                                                |e| e.description(),
                                            ),
                                        );
                                    }
                                }
                            });
                        });
                    }
                    if let Some(canvas) = &mut self.canvas {
                        canvas.set_comments(
                            view,
                            (self.generation, self.revision),
                            &self.annotation_browser.comments,
                        );
                        if let Some(action) =
                            canvas.show_selected(ui, view, self.selected, &self.semantic.addresses)
                        {
                            match action {
                                GraphAction::Select(address) => self.select_instruction(address),
                                GraphAction::Navigate(target) => navigate = Some(target),
                            }
                        }
                    }
                } else {
                    ui.add_space(40.0);
                    ui.label("Function Graph");
                    ui.weak("Select a function from the left to display its control flow.");
                }
                if let Some(address) = navigate {
                    self.navigate(address, true, &context);
                }
            }
            Tab::Listing => {
                if let Some(pc) = self.undisplayed_call {
                    ui.colored_label(theme::WARNING, format!("Referenced instruction {pc:#x} is outside this bounded source graph. Use Go to inspect its address."));
                }
                if self.info.is_none() {
                    ui.add_space(32.0);
                    ui.heading("Code Browser");
                    ui.weak("Open a binary to begin analysis.");
                    if ui.button("Open binary…").clicked() {
                        self.request_intent(Intent::OpenDialog, &context);
                    }
                } else if let Some(view) = &self.view {
                    let name = self
                        .info
                        .as_ref()
                        .and_then(|info| function_at(&info.functions, view.address))
                        .map(|f| f.name.as_str())
                        .unwrap_or("function");
                    ui.label(
                        RichText::new(format!("{}  ·  {:x}", crop(name, 120), view.address))
                            .monospace()
                            .color(theme::BLUE),
                    );
                    ui.separator();
                }
                ui.label(
                    RichText::new(format!(
                        "{:<8}  {:<25} {:<10} {}",
                        "Address", "Bytes", "Mnemonic", "Operands"
                    ))
                    .monospace()
                    .weak(),
                );
                ui.separator();
                let mut selected = None;
                let mut decode = None;
                let mut navigate = None;
                let mut annotate = None;
                let row = ui.text_style_height(&egui::TextStyle::Monospace) + 5.0;
                let mut scroll = ScrollArea::both().id_salt("instruction-list");
                if let Some(target) = self.pending_listing_scroll.take() {
                    scroll = scroll.vertical_scroll_offset(
                        target as f32 * (row + ui.spacing().item_spacing.y),
                    );
                }
                scroll.show_rows(ui, row, self.listing.len(), |ui, rows| {
                    for index in rows {
                        let instruction = &self.listing[index];
                        let mut job = theme::listing_row(
                            instruction.address,
                            &hex(&instruction.bytes),
                            &instruction.mnemonic,
                            &instruction.operands,
                        );
                        if let Some(comment) =
                            self.annotation_browser.comments.get(&instruction.address)
                        {
                            job.append(
                                &format!("  ; {comment}"),
                                0.0,
                                egui::TextFormat {
                                    font_id: egui::FontId::monospace(13.0),
                                    color: theme::SYNTAX_COMMENT,
                                    ..Default::default()
                                },
                            );
                        }
                        let response = ui.add(
                            egui::Button::selectable(
                                self.selected == Some(instruction.address)
                                    || self.semantic.addresses.contains(&instruction.address),
                                job,
                            )
                            .wrap_mode(egui::TextWrapMode::Extend),
                        );
                        let response = if let Some(note) = self
                            .session
                            .as_ref()
                            .and_then(|session| session.annotations.get(&instruction.address))
                        {
                            response.on_hover_text(format!(
                                "{}\n{}\nUse ; or Rename / comment… to view the full comment.",
                                crate::annotation_display::preview(&note.label, 80),
                                crate::annotation_display::preview(&note.comment, 400)
                            ))
                        } else {
                            response
                        };
                        let response = if let Some(evidence) = self
                            .view
                            .as_ref()
                            .and_then(|view| {
                                view.calls
                                    .iter()
                                    .find(|call| call.address == instruction.address)
                            })
                            .and_then(|call| call.no_return)
                        {
                            response.on_hover_text(evidence.description())
                        } else {
                            response
                        };
                        if response.clicked() {
                            selected = Some(instruction.address);
                        }
                        let target = self
                            .view
                            .as_ref()
                            .and_then(|view| {
                                view.calls
                                    .iter()
                                    .find(|call| call.address == instruction.address)
                            })
                            .and_then(|call| call.target);
                        if response.double_clicked()
                            && let Some(target) = target
                        {
                            navigate = Some(target);
                        }
                        response.context_menu(|ui| {
                            if let Some(target) = target
                                && ui.button(format!("Go to {target:x}")).clicked()
                            {
                                navigate = Some(target);
                                ui.close();
                            }
                            if ui.button("Rename / comment…").clicked() {
                                annotate = Some(instruction.address);
                                ui.close();
                            }
                            if ui.button("Decode selected bytes").clicked() {
                                decode = Some((instruction.address, instruction.bytes.clone()));
                                ui.close();
                            }
                        });
                    }
                });
                if let Some(address) = selected {
                    self.select_instruction(address);
                }
                if let Some(address) = navigate {
                    self.navigate(address, true, &context);
                }
                if let Some(address) = annotate {
                    self.open_comment(address);
                }
                if let Some((address, bytes)) = decode {
                    self.decoder.set_source(address, bytes);
                    self.tab = Tab::Decode;
                }
            }
            Tab::Strings => {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.info.is_some(), egui::Button::new("Find strings"))
                        .clicked()
                    {
                        self.request(self.string_request(), &context);
                    }
                    ui.label("Minimum characters");
                    ui.add(
                        egui::DragValue::new(&mut self.string_minimum)
                            .range(MIN_STRING_LENGTH..=MAX_STRING_MINIMUM)
                            .speed(1),
                    );
                });
                if self.strings_scanned {
                    ui.weak(format!(
                        "{} loaded · {} visible{}",
                        self.strings.len(),
                        self.filtered_strings.len(),
                        self.strings_minimum_used
                            .map_or(String::new(), |minimum| format!(
                                " · minimum {minimum} characters"
                            ))
                    ));
                }
                if self.strings_truncated {
                    ui.label("Partial scan: up to 10,000 previews and 64 MiB of data. Increase the minimum length and rescan to reduce short-string noise.");
                }
                if ui
                    .add(
                        TextEdit::singleline(&mut self.string_filter)
                            .hint_text("Filter loaded strings")
                            .char_limit(256),
                    )
                    .changed()
                {
                    self.rebuild_string_filter();
                }
                ui.weak("Click a string to load its source bytes into the decoder");
                let mut read = None;
                let row = ui.text_style_height(&egui::TextStyle::Monospace) + 6.0;
                ScrollArea::vertical().id_salt("strings-list").show_rows(
                    ui,
                    row,
                    self.filtered_strings.len(),
                    |ui, rows| {
                        for index in rows {
                            let string = &self.strings[self.filtered_strings[index]];
                            if ui
                                .button(
                                    RichText::new(format!(
                                        "{:08x}  {}  {}",
                                        string.address,
                                        string.encoding,
                                        crop(&string.text, 240)
                                    ))
                                    .monospace(),
                                )
                                .clicked()
                            {
                                let length = if string.encoding.contains("16") {
                                    string.text.encode_utf16().count().saturating_mul(2)
                                } else {
                                    string.text.len()
                                };
                                read = Some((
                                    string.address,
                                    length.clamp(1, crate::decode::MAX_INPUT),
                                ));
                            }
                        }
                    },
                );
                if let Some((address, length)) = read {
                    self.select_instruction(address);
                    self.request(Request::Bytes { address, length }, &context);
                }
            }
            Tab::Crypto => {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Cryptographic constants").strong());
                    if ui
                        .add_enabled(self.info.is_some(), egui::Button::new("Scan"))
                        .clicked()
                    {
                        self.request(Request::Crypto, &context);
                    }
                });
                ui.weak("Constant matches are clues; they do not establish algorithm use.");
                let mut read = None;
                let row = ui.text_style_height(&egui::TextStyle::Body) + 6.0;
                ScrollArea::vertical().id_salt("crypto-list").show_rows(
                    ui,
                    row,
                    self.crypto.len(),
                    |ui, rows| {
                        for index in rows {
                            let hit = &self.crypto[index];
                            if ui
                                .button(format!(
                                    "{:08x}  {} · {} ({} bytes)",
                                    hit.address, hit.algorithm, hit.signature, hit.length
                                ))
                                .clicked()
                            {
                                read = Some((hit.address, hit.length));
                            }
                        }
                    },
                );
                if let Some((address, length)) = read {
                    self.select_instruction(address);
                    self.request(Request::Bytes { address, length }, &context);
                }
            }
            Tab::Decode => {
                let action = ScrollArea::vertical()
                    .id_salt("decoder-workspace-scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| self.decoder.show(ui))
                    .inner;
                if let Some(action) = action {
                    match action {
                        DecoderAction::Read { address, length } => {
                            self.request(Request::Bytes { address, length }, &context)
                        }
                        DecoderAction::Annotate { annotation } => {
                            let count = self
                                .session
                                .as_ref()
                                .map(|session| {
                                    session
                                        .annotations
                                        .values()
                                        .map(|annotation| annotation.decoded.len())
                                        .sum::<usize>()
                                })
                                .unwrap_or(0);
                            if count >= 128 {
                                self.status =
                                    "Decoded annotation limit reached (128 per session)".into();
                            } else {
                                let address = annotation.source_address;
                                let mut existing = self
                                    .session
                                    .as_ref()
                                    .and_then(|session| session.annotations.get(&address))
                                    .cloned()
                                    .unwrap_or_default();
                                existing.decoded.push(annotation);
                                self.edit_annotation(address, existing);
                                self.status =
                                    "Decoded annotation added; save annotations to persist".into();
                            }
                        }
                    }
                }
            }
        }
    }
}

impl DesktopApp {
    fn draw(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        if let Some(path) = self.initial_path.take() {
            self.request_intent(Intent::OpenPath(path), &context);
        }
        if let Some(path) = context.input(|input| {
            input
                .raw
                .dropped_files
                .first()
                .map(|file| file.path().to_owned())
        }) {
            self.request_intent(Intent::OpenPath(path), &context);
        }
        self.poll_files(&context);
        self.poll_worker(&context);
        if context.input(|input| input.viewport().close_requested())
            && self.dirty()
            && !self.quit_confirmed
        {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if self.intent.is_none() {
                self.request_intent(Intent::Quit, &context);
            }
        }
        egui::Panel::top("toolbar")
            .frame(theme::toolbar_frame(ui.style()))
            .show(ui, |ui| self.toolbar(ui));
        egui::Panel::bottom("status")
            .frame(theme::status_frame(ui.style()))
            .show(ui, |ui| {
            egui::Sides::new().shrink_left().wrap().show(
                ui,
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        if self.file_job.is_some() {
                            ui.spinner();
                        }
                        ui.label(&self.status);
                        if let Some(plan) = &self.analysis_plan {
                            let step = plan.current.or(plan.steps.front().copied());
                            ui.weak(format!(
                                "Auto analysis {}/{}{}",
                                plan.total - plan.steps.len(),
                                plan.total,
                                step.map_or(String::new(), |step| format!(" · {}", step.label())),
                            ));
                        }
                        if let Some(summary) = &self.discovery_summary {
                            ui.weak(summary);
                        }
                        if let Some(info) = &self.info {
                            ui.weak(format!(
                                "{} · {} · {} bytes",
                                info.format, info.architecture, info.file_len
                            ));
                            if !info.warnings.is_empty() {
                                ui.menu_button("Analysis notes", |ui| {
                                    ui.set_max_width(520.0);
                                    for warning in info.warnings.iter().take(64) {
                                        ui.label(crop(warning, 1024));
                                    }
                                });
                            }
                        }
                    });
                },
                |ui| {
                    if let Some(pending) = &self.pending {
                        let elapsed = pending.started.elapsed();
                        // Avoid flashing the bar for jobs which finish immediately.
                        if elapsed >= Duration::from_millis(200) {
                            let task = match pending.request {
                                Request::Open { .. } => "Opening binary",
                                Request::Graph { .. } => "Building graph",
                                Request::Decompile { .. } | Request::DecompileWithLocals { .. } => "Decompiling",
                                Request::Discover | Request::DiscoverBatch { .. } => {
                                    "Discovering functions"
                                }
                                Request::SyncFunctions { .. } => "Restoring function context",
                                Request::Rename { .. } => "Renaming function",
                                Request::Bytes { .. } => "Reading bytes",
                                Request::Strings | Request::StringsWithOptions { .. } => {
                                    "Finding strings"
                                }
                                Request::Crypto => "Scanning constants",
                            };
                            let stage = self.analysis_progress.as_ref().map(|progress| match progress.stage {
                                AnalysisStage::Seeds => "Seeding analysis", AnalysisStage::Calls => "Analyzing references", AnalysisStage::Publish => "Publishing results",
                            }).unwrap_or(task);
                            let activity = ui.scope(|ui| theme::analysis_activity(ui, stage, elapsed));
                            if let Some(progress) = &self.analysis_progress {
                                activity.response.on_hover_text(format!("{} functions examined · {} decode attempts. Total work is unknown.", progress.functions_examined, progress.decode_attempts));
                            }
                        }
                    }
                },
            );
        });
        egui::Panel::left("navigation-dock-v2")
            .default_size(260.0)
            .min_size(180.0)
            .resizable(true)
            .frame(theme::view_frame())
            .show(ui, |ui| self.navigation_panel(ui));
        let right_width = (ui.available_width() * 0.48).max(280.0);
        egui::Panel::right("decompiler-dock-v2")
            .default_size(right_width)
            .min_size(240.0)
            .resizable(true)
            .frame(theme::view_frame())
            .show(ui, |ui| self.side_panel(ui));
        egui::CentralPanel::default()
            .frame(theme::view_frame())
            .show(ui, |ui| self.main_panel(ui));
        let mut annotations_open = self.annotations_open;
        egui::Window::new("Annotations")
            .open(&mut annotations_open)
            .default_width(420.0)
            .resizable(true)
            .show(&context, |ui| {
                self.annotation_browser(ui);
                ui.separator();
                if self.selected.is_none() {
                    ui.weak("Select an address to add a name or comment.");
                } else {
                    self.annotation_editor(ui);
                }
            });
        self.annotations_open = annotations_open;
        self.unsaved_window(&context);
        self.analyze_window(&context);
        self.file_dialogs.show(&context);
        self.browser_dialog(&context);
        self.handle_shortcuts(&context);
        crate::window_chrome::resize_borders(ui);
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let frame = crate::performance::span("gui_frame_cpu");
        self.draw(ui);
        crate::performance::navigation_frame(
            self.selection_generation,
            self.view.is_some() && matches!(self.tab, Tab::Graph | Tab::Listing),
            !self.decompiled.is_empty(),
        );
        frame.finish(0);
        #[cfg(feature = "capture")]
        self.capture_tick(ui.ctx());
    }
}

#[cfg(feature = "capture")]
impl DesktopApp {
    fn capture_tick(&mut self, context: &egui::Context) {
        use std::sync::{Mutex, OnceLock};
        static CAPTURE: OnceLock<Mutex<Option<crate::capture::Capture>>> = OnceLock::new();
        let mut guard = CAPTURE
            .get_or_init(|| Mutex::new(crate::capture::Capture::from_env()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(capture) = guard.as_mut() else {
            return;
        };
        // Screenshots show the browser, not the first-open analysis prompt.
        self.analyze_prompt = None;
        let busy = self.pending.is_some()
            || self.opening.is_some()
            || !self.queue.is_empty()
            || self.file_job.is_some()
            || self.info.is_none();
        if !busy && let Some(address) = capture.goto.take() {
            if capture.graph {
                self.tab = Tab::Graph;
            }
            self.navigate(address, true, context);
            return;
        }
        if !busy
            && self.view.is_some()
            && let Some(address) = capture.select.take()
        {
            self.select_instruction(address);
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
            return;
        }
        capture.tick(context, !busy);
    }
}

fn discovery_summary(
    label: &str,
    examined: usize,
    remaining: usize,
    batches: usize,
    failed: usize,
    partial: bool,
    activity: &str,
) -> String {
    format!(
        "{label}: {examined} examined · {remaining} remaining · {batches} batches · {failed} failed · {}{activity}",
        if partial {
            "partial coverage"
        } else {
            "complete seed coverage"
        },
    )
}

fn is_project_path(path: &std::path::Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("grproj"))
}

fn edit_size(edit: &Edit) -> usize {
    edit.local.as_ref().map_or(0, |(id, before)| {
        id.engine.len()
            + id.verification.len()
            + 64
            + before.as_ref().map_or(0, |r| {
                r.name.len() + r.identity.engine.len() + r.identity.verification.len() + 64
            })
    }) + edit.function_name.as_ref().map_or(0, String::len)
        + edit.before.as_ref().map_or(0, |annotation| {
            annotation.label.len()
                + annotation.comment.len()
                + annotation
                    .decoded
                    .iter()
                    .map(|decoded| {
                        decoded.text.len() + decoded.parameters.len() + decoded.operation.len()
                    })
                    .sum::<usize>()
        })
}

fn parse_address(text: &str) -> Result<u64, String> {
    let text = text.trim();
    u64::from_str_radix(
        text.strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text),
        16,
    )
    .map_err(|_| "Enter a hexadecimal address".into())
}

fn crop(text: &str, maximum: usize) -> String {
    let mut chars = text.chars();
    let mut result: String = chars.by_ref().take(maximum).collect();
    if chars.next().is_some() {
        result.push('…');
    }
    result
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packed_image_skips_automatic_and_manual_expensive_analysis() {
        let mut app = keyboard_app();
        assert!(app.should_auto_decompile());
        app.info
            .as_mut()
            .unwrap()
            .warnings
            .push(crate::packing::UPX_PACKED_WARNING.into());
        assert!(!app.should_auto_decompile());
        for request in [Request::Decompile { address: 0x1000 }, Request::Discover] {
            app.request(request, &egui::Context::default());
            assert_eq!(app.status, crate::packing::UPX_ANALYSIS_ERROR);
            assert!(app.opening.is_none());
            assert!(app.pending.is_none());
        }
    }

    #[test]
    fn string_options_are_applied_before_scanning_and_result_provenance_is_retained() {
        let mut app = keyboard_app();
        app.string_minimum = 8;
        let request = app.string_request();
        assert!(matches!(
            request,
            Request::StringsWithOptions { minimum_length: 8 }
        ));
        let pending = Pending {
            id: 1,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
        };
        app.string_minimum = 12;
        app.receive(
            pending,
            Response::Strings {
                strings: vec![],
                truncated: true,
            },
            &egui::Context::default(),
        );
        assert_eq!(app.strings_minimum_used, Some(8));
        assert!(app.strings_truncated);
        assert!(app.status.contains("raise the minimum"));
        app.clear_views();
        assert_eq!(app.strings_minimum_used, None);
    }

    #[test]
    fn scan_results_distinguish_partial_functions_and_unscanned_strings() {
        let mut app = keyboard_app();
        assert!(!app.strings_scanned);
        let pending = |request| Pending {
            id: 1,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
        };
        let functions = app.info.as_ref().unwrap().functions.clone();
        let function_request = pending(Request::Discover);
        let string_request = pending(Request::Strings);
        app.receive(
            function_request,
            Response::Functions {
                functions,
                truncated: true,
                analysis: CallAnalysis::default(),
            },
            &egui::Context::default(),
        );
        assert!(app.info.as_ref().unwrap().functions_truncated);
        assert!(app.status.contains("data not analyzed"));
        assert!(app.status.contains("partial"));
        app.receive(
            string_request,
            Response::Strings {
                strings: vec![],
                truncated: false,
            },
            &egui::Context::default(),
        );
        assert!(app.strings_scanned);
        assert!(app.strings.is_empty());
        app.clear_views();
        assert!(!app.strings_scanned);
    }

    #[test]
    fn unbounded_graphs_and_mismatched_renames_stop_the_worker() {
        fn pending(app: &DesktopApp, request: Request) -> Pending {
            Pending {
                id: 1,
                request,
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            }
        }
        let mut app = keyboard_app();
        let block = |address| BasicBlock {
            address,
            instructions: Vec::new(),
        };
        app.receive(
            pending(&app, Request::Graph { address: 0x1000 }),
            Response::Graph {
                view: FunctionView {
                    address: 0x1000,
                    blocks: (0..=MAX_GRAPH_BLOCKS as u64)
                        .map(|i| block(0x1000 + i))
                        .collect(),
                    edges: Vec::new(),
                    calls: Vec::new(),
                    warnings: Vec::new(),
                },
            },
            &egui::Context::default(),
        );
        assert!(app.status.contains("Basic block count"), "{}", app.status);
        assert!(app.view.is_none() && app.listing.is_empty());

        let mut app = keyboard_app();
        app.receive(
            pending(
                &app,
                Request::Rename {
                    address: 0x1000,
                    name: "requested".into(),
                },
            ),
            Response::Renamed {
                address: 0x1000,
                name: "other".into(),
            },
            &egui::Context::default(),
        );
        assert!(app.status.contains("Unexpected worker response"));
        assert_eq!(app.info.as_ref().unwrap().functions[0].name, "entry");
    }

    #[test]
    fn discovery_requests_name_a_worker_inventory_only_while_it_is_displayed() {
        let mut app = keyboard_app();
        app.worker_epoch = 2;
        let info = app.info.clone().unwrap();
        let adopt = || {
            crate::discovery::WorkerInventory::adopt(
                &info,
                None,
                None,
                2,
                InventoryChange::Replace {
                    revision: 5,
                    functions: info.functions.clone(),
                },
                false,
            )
            .unwrap()
            .0
        };
        app.worker_inventory = Some(adopt());
        app.inventory_synced = true;
        assert_eq!(app.inventory_base(), Some(5));
        app.worker_epoch = 3;
        assert_eq!(app.inventory_base(), None, "another worker's revision");
        app.worker_epoch = 2;
        // The worker may re-admit entries after a rename, so resend in full.
        app.receive(
            Pending {
                id: 1,
                request: Request::Rename {
                    address: 0x1000,
                    name: "renamed".into(),
                },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            },
            Response::Renamed {
                address: 0x1000,
                name: "renamed".into(),
            },
            &egui::Context::default(),
        );
        assert_eq!(app.info.as_ref().unwrap().functions[0].name, "renamed");
        assert_eq!(app.inventory_base(), None);
        app.worker_inventory = Some(adopt());
        app.inventory_synced = true;
        app.stop_worker();
        assert!(app.worker_inventory.is_none());
        assert_eq!(app.inventory_base(), None);
    }

    #[test]
    fn large_function_filters_progress_across_frames_and_follow_label_edits() {
        let mut app = keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.sections[0].size = 0x10_0000;
        info.functions = (0..20_000u64)
            .map(|i| FunctionInfo {
                address: 0x1000 + i,
                name: format!("Fn_{i}"),
            })
            .collect();
        app.rebuild_filter();
        assert_eq!(app.filtered_functions.len(), 20_000);
        app.function_filter = "FN_19".into();
        app.filter_query = app.function_filter.to_lowercase();
        app.filtered_functions.clear();
        app.filter_cursor = Some(0);
        let mut steps = 0;
        while !app.step_filter(Duration::ZERO) {
            steps += 1;
        }
        assert!(steps >= 19, "{steps}");
        let expected: Vec<_> = (0..20_000)
            .filter(|i| format!("fn_{i}").contains("fn_19"))
            .collect();
        assert_eq!(app.filtered_functions, expected);
        // A label edit bumps the revision; stale keys are rebuilt.
        app.session.as_mut().unwrap().annotations.insert(
            0x1000 + 5,
            Annotation {
                label: "fn_19_label".into(),
                ..Default::default()
            },
        );
        app.revision += 1;
        while !app.step_filter(Duration::from_secs(1)) {}
        assert_eq!(app.filtered_functions[0], 5);
        // Hexadecimal queries also match addresses.
        app.function_filter = "1fff".into();
        app.restart_filter();
        while !app.step_filter(Duration::from_secs(1)) {}
        assert!(app.filtered_functions.contains(&(0x1fff - 0x1000)));
    }

    fn keyboard_app() -> DesktopApp {
        let mut app = DesktopApp::empty(None);
        app.info = Some(BinaryInfo {
            path: "fixture".into(),
            architecture: "x86:LE:64:default".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 256,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 256,
                file_offset: 0,
                file_size: 256,
                executable: true,
            }],
            functions: vec![
                FunctionInfo {
                    address: 0x1000,
                    name: "entry".into(),
                },
                FunctionInfo {
                    address: 0x1040,
                    name: "next".into(),
                },
            ],
            warnings: Vec::new(),
            functions_truncated: false,
        });
        app.session = Some(Session::new("a".repeat(64)));
        app.selected = Some(0x1000);
        app.address = "1000".into();
        app.rebuild_filter();
        app
    }

    #[test]
    fn data_targets_request_bytes_without_function_navigation_or_stale_selection() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        app.tab = Tab::References;
        app.semantic.select_instruction(0x1004);
        let function = app.view.as_ref().unwrap().address;
        let history = app.history.clone();
        let generation = app.selection_generation;
        let selected = app.selected;
        let semantic_addresses = app.semantic.addresses.clone();
        app.read_data_reference(0x1080, 4, &context);
        assert_eq!(app.selected, selected);
        assert_eq!(app.reference_target, Some(0x1080));
        assert_eq!(app.view.as_ref().unwrap().address, function);
        assert_eq!(app.history, history);
        assert_eq!(app.selection_generation, generation);
        assert_eq!(app.semantic.addresses, semantic_addresses);
        assert!(app.tab == Tab::References);

        // The same reply can complete a read without stealing a newer tab.
        for changed in 0..5 {
            app.tab = Tab::References;
            app.status = "waiting".into();
            let pending = Pending {
                id: 1,
                request: Request::Bytes {
                    address: 0x1080,
                    length: 4,
                },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            };
            match changed {
                1 => app.tab = Tab::Strings,
                2 => app.selection_generation = app.selection_generation.wrapping_add(1),
                3 => app.revision += 1,
                4 => app.selected = Some(0x1008),
                _ => {}
            }
            app.receive(
                pending,
                Response::Bytes {
                    address: 0x1080,
                    bytes: vec![1, 2, 3, 4],
                },
                &context,
            );
            match changed {
                0 => assert!(app.tab == Tab::Decode),
                1 => {
                    assert!(app.tab == Tab::Strings);
                    assert_eq!(app.status, "Bytes loaded into decoder");
                }
                _ => assert_eq!(app.status, "waiting"),
            }
        }
    }

    #[test]
    fn data_reference_adoption_is_validated_and_cleared_on_reopen() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.info.as_mut().unwrap().architecture = "x86-64".into();
        let report = CallAnalysis {
            decode_attempts: 1,
            functions_examined: 1,
            data: Some(DataAnalysis {
                references: vec![DataReference {
                    function: 0x1000,
                    address: 0x1004,
                    target: 0x1080,
                    size: 4,
                    access: DataAccess::Read,
                    provenance: DataProvenance::InstructionLocal,
                }],
                operations_charged: 1,
                accesses_examined: 1,
                ..Default::default()
            }),
            ..Default::default()
        };
        for valid in [true, false] {
            let pending = Pending {
                id: 1,
                request: Request::Discover,
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            };
            let mut analysis = report.clone();
            if !valid {
                analysis.data.as_mut().unwrap().references[0].target = 0x2000;
            }
            app.receive(
                pending,
                Response::Functions {
                    functions: app.info.as_ref().unwrap().functions.clone(),
                    truncated: false,
                    analysis,
                },
                &context,
            );
            // A malformed worker reply must not replace previously validated evidence.
            assert_eq!(
                app.call_index
                    .as_ref()
                    .unwrap()
                    .report
                    .data
                    .as_ref()
                    .unwrap()
                    .references[0]
                    .target,
                0x1080
            );
            if !valid {
                assert!(app.status.contains("Invalid worker reference analysis"));
            }
        }
        app.reference_data = true;
        app.reference_target = Some(0x1080);
        app.reference_query = "1080".into();
        app.clear_views();
        assert!(app.call_index.is_none());
        assert!(!app.reference_data);
        assert!(app.reference_target.is_none());
        assert!(app.reference_query.is_empty());
    }

    fn key_event(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat: false,
            modifiers,
        }
    }

    fn keyboard_frame(context: &egui::Context, app: &mut DesktopApp, events: Vec<egui::Event>) {
        let mut output = context.run_ui(
            egui::RawInput {
                events,
                ..Default::default()
            },
            |ui| app.draw(ui),
        );
        output.textures_delta.clear();
    }

    #[test]
    fn symbol_tree_scrollbars_and_rows_follow_dock_width_in_both_directions() {
        fn frame(
            context: &egui::Context,
            app: &mut DesktopApp,
            width: f32,
            events: Vec<egui::Event>,
        ) -> egui::FullOutput {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 720.0),
                    )),
                    events,
                    ..Default::default()
                },
                |root| {
                    egui::Panel::left("tree-resize-test")
                        .exact_size(width)
                        .frame(egui::Frame::NONE)
                        .show(root, |ui| app.symbol_tree(ui));
                },
            );
            output.textures_delta.clear();
            output
        }

        let context = egui::Context::default();
        theme::install(&context);
        context.all_styles_mut(|style| {
            style.animation_time = 0.0;
            // Solid tracks make actual scrollbar geometry observable, including
            // when the pointer is elsewhere in this headless rendering test.
            style.spacing.scroll = egui::style::ScrollStyle::solid();
        });
        let mut app = keyboard_app();
        app.info.as_mut().unwrap().functions = (0..512)
            .map(|index| FunctionInfo {
                address: 0x1000 + index * 16,
                name: format!("resize_function_{index:04}_{}", "long_name_".repeat(15)),
            })
            .collect();
        app.strings_scanned = true;
        app.strings = (0..512)
            .map(|index| StringEntry {
                address: 0x9000 + index * 256,
                text: format!("resize_string_{index:04}_{}", "long_text_".repeat(15)),
                encoding: "ASCII".into(),
            })
            .collect();
        frame(&context, &mut app, 260.0, vec![]);
        let output = frame(&context, &mut app, 260.0, vec![]);
        let functions = text_position(&output, "Functions (512)", 0);
        frame(&context, &mut app, 260.0, pointer_events(functions));
        let output = frame(&context, &mut app, 260.0, vec![]);
        let strings = text_position(&output, "Strings (512)", 0);
        frame(&context, &mut app, 260.0, pointer_events(strings));

        let mut widths = Vec::new();
        let mut scrollbar_rights = Vec::new();
        for width in [260.0, 430.0, 260.0] {
            frame(&context, &mut app, width, vec![]);
            let output = frame(&context, &mut app, width, vec![]);
            let bars: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| {
                    if let egui::epaint::Shape::Rect(rect) = &shape.shape {
                        (rect.rect.height() > 100.0 && rect.rect.width() < 20.0)
                            .then_some(rect.rect)
                    } else {
                        None
                    }
                })
                .collect();
            assert_eq!(
                bars.len(),
                2,
                "each expanded list has its own bounded scrollbar"
            );
            assert!((bars[0].right() - bars[1].right()).abs() < 2.0);
            assert!(
                bars[0].right() > width - 35.0,
                "scrollbars follow the dock edge"
            );
            scrollbar_rights.push(bars[0].right());

            let mut row_widths = Vec::new();
            for prefix in ["resize_function_", "resize_string_"] {
                let rows: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| {
                        if let egui::epaint::Shape::Text(text) = &shape.shape {
                            text.galley
                                .text()
                                .starts_with(prefix)
                                .then_some((shape.clip_rect, &text.galley))
                        } else {
                            None
                        }
                    })
                    .collect();
                assert!(!rows.is_empty(), "expanded rows are rendered");
                assert!(rows.len() < 20, "lists remain virtualized");
                assert!(rows.iter().all(|(_, galley)| galley.rows.len() == 1));
                assert!(
                    rows[0].0.right() > width - 40.0,
                    "row clipping follows the resized viewport"
                );
                row_widths.push(rows[0].0.width());
            }
            widths.push(row_widths);
        }
        assert!(scrollbar_rights[1] - scrollbar_rights[0] > 150.0);
        assert!((scrollbar_rights[2] - scrollbar_rights[0]).abs() < 2.0);
        for ((narrow, wide), restored) in widths[0].iter().zip(&widths[1]).zip(&widths[2]) {
            assert!(wide - narrow > 150.0);
            assert!((restored - narrow).abs() < 2.0);
        }
    }

    #[test]
    fn rename_shortcut_selects_the_old_name_and_enter_commits_the_replacement() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::L, egui::Modifiers::NONE)],
        );
        assert!(matches!(
            app.browser_dialog.as_ref().unwrap().kind,
            BrowserDialogKind::Rename {
                address: 0x1000,
                function: true
            }
        ));
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![egui::Event::Text("new_entry".into())],
        );
        assert_eq!(app.browser_dialog.as_ref().unwrap().text, "new_entry");
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::Enter, egui::Modifiers::NONE)],
        );
        assert!(app.browser_dialog.is_none());
        assert_eq!(
            app.session.as_ref().unwrap().annotations[&0x1000].label,
            "new_entry"
        );
        assert!(app.dirty());
    }

    #[test]
    fn typing_shortcut_characters_in_a_filter_does_not_execute_commands() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        keyboard_frame(&context, &mut app, vec![]);
        context.memory_mut(|memory| memory.request_focus(egui::Id::unique("function-filter")));
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![
                key_event(egui::Key::L, egui::Modifiers::NONE),
                key_event(egui::Key::G, egui::Modifiers::NONE),
                key_event(egui::Key::Semicolon, egui::Modifiers::NONE),
                key_event(egui::Key::Space, egui::Modifiers::NONE),
                egui::Event::Text("lg; ".into()),
            ],
        );
        assert_eq!(app.function_filter, "lg; ");
        assert!(app.browser_dialog.is_none());
        assert!(!app.annotations_open);
        assert!(app.tab == Tab::Listing);
        assert!(!app.dirty());
    }

    #[test]
    fn rename_escape_cancels_and_file_jobs_block_shortcuts() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.begin_rename();
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![egui::Event::Text("cancelled".into())],
        );
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::Escape, egui::Modifiers::NONE)],
        );
        assert!(app.browser_dialog.is_none());
        assert!(!app.dirty());
        let (_sender, receiver) = mpsc::sync_channel(1);
        app.file_job = Some(receiver);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::L, egui::Modifiers::NONE)],
        );
        assert!(app.browser_dialog.is_none());
    }

    #[test]
    fn labels_target_the_selected_address_and_names_remain_saveable() {
        let mut app = keyboard_app();
        let context = egui::Context::default();
        app.selected = Some(0x1004);
        app.begin_rename();
        assert!(matches!(
            app.browser_dialog.as_ref().unwrap().kind,
            BrowserDialogKind::Rename {
                address: 0x1004,
                function: false
            }
        ));
        for name in ["".to_owned(), "line\nbreak".into(), "🦀".repeat(65)] {
            assert!(app.rename_at(0x1004, &name, &context).is_err());
            assert!(!app.dirty());
        }
        app.rename_at(0x1004, "loop_body", &context).unwrap();
        assert_eq!(
            app.session.as_ref().unwrap().annotations[&0x1004].label,
            "loop_body"
        );
        assert!(
            !app.session
                .as_ref()
                .unwrap()
                .annotations
                .contains_key(&0x1000)
        );
        assert_eq!(app.info.as_ref().unwrap().functions[0].name, "entry");
        assert_eq!(app.resolve_location("loop_body").unwrap(), 0x1004);
        assert_eq!(app.resolve_location("next").unwrap(), 0x1040);
        assert_eq!(app.resolve_location("0x1040").unwrap(), 0x1040);
        assert!(app.resolve_location("0x2000").is_err());
        assert!(app.resolve_location("missing").is_err());
        app.undo(&context);
        assert!(
            !app.session
                .as_ref()
                .unwrap()
                .annotations
                .contains_key(&0x1004)
        );
    }

    #[test]
    fn modified_and_repeating_letter_keys_do_not_open_rename() {
        for modifiers in [
            egui::Modifiers::CTRL,
            egui::Modifiers::SHIFT,
            egui::Modifiers::ALT,
        ] {
            assert!(shortcut(&key_event(egui::Key::L, modifiers)).is_none());
        }
        let mut repeat = key_event(egui::Key::L, egui::Modifiers::NONE);
        if let egui::Event::Key { repeat, .. } = &mut repeat {
            *repeat = true;
        }
        assert!(shortcut(&repeat).is_none());
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.begin_rename();
        app.generation += 1;
        keyboard_frame(&context, &mut app, vec![]);
        assert!(app.browser_dialog.is_none());
        assert!(!app.dirty());
    }

    #[test]
    fn goto_shortcut_resolves_a_function_and_comment_shortcut_focuses_the_editor() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::G, egui::Modifiers::NONE)],
        );
        assert!(matches!(
            app.browser_dialog.as_ref().unwrap().kind,
            BrowserDialogKind::GoTo
        ));
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, vec![egui::Event::Text("next".into())]);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::Enter, egui::Modifiers::NONE)],
        );
        assert_eq!(app.selected, Some(0x1040));
        assert!(app.browser_dialog.is_none());
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::Semicolon, egui::Modifiers::NONE)],
        );
        assert!(app.annotations_open);
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![egui::Event::Text("label lg; comment".into())],
        );
        assert_eq!(app.comment_edit, "label lg; comment");
        assert!(app.browser_dialog.is_none());
    }

    #[test]
    fn history_shortcuts_revisit_functions_without_adding_history_entries() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.history = vec![0x1000, 0x1040];
        app.history_index = 1;
        app.selected = Some(0x1040);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::ArrowLeft, egui::Modifiers::ALT)],
        );
        assert_eq!(app.selected, Some(0x1000));
        assert_eq!(app.history_index, 0);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::ArrowRight, egui::Modifiers::ALT)],
        );
        assert_eq!(app.selected, Some(0x1040));
        assert_eq!(app.history_index, 1);
        assert_eq!(app.history, [0x1000, 0x1040]);
        app.navigate(0x1080, true, &context);
        app.history_step(false, &context);
        app.navigate(0x10c0, true, &context);
        assert_eq!(app.history, [0x1000, 0x1040, 0x10c0]);
    }

    fn call_navigation_app(text: &str) -> DesktopApp {
        let mut app = keyboard_app();
        app.view = Some(FunctionView {
            address: 0x1000,
            blocks: vec![],
            edges: vec![],
            calls: vec![CallSite {
                address: 0x1004,
                target: Some(0x1040),
                no_return: None,
            }],
            warnings: vec![],
        });
        app.decompiled = text.into();
        app.highlighted = Some(HighlightedCode::new(text));
        app.decompiled_lines = vec![(0, text.len())];
        app.history = vec![0x1000];
        app
    }

    fn semantic_app() -> DesktopApp {
        let source = "int entry() { return café + 1; }";
        let mut app = call_navigation_app(source);
        let instructions: Vec<_> = [0x1000, 0x1004, 0x1008]
            .into_iter()
            .map(|address| Instruction {
                address,
                bytes: vec![0x90],
                mnemonic: "mov".into(),
                operands: "eax, 1".into(),
            })
            .collect();
        let view = app.view.as_mut().unwrap();
        view.calls.clear();
        view.blocks = vec![BasicBlock {
            address: 0x1000,
            instructions: instructions.clone(),
        }];
        app.canvas = Some(GraphCanvas::new(view));
        app.listing = instructions;
        app.semantic.mappings = vec![CodeMapping {
            start: source.find("return").unwrap(),
            end: source.find(';').unwrap() + 1,
            addresses: vec![0x1004, 0x1008],
        }];
        app.semantic.select_instruction(0x1000);
        app
    }

    fn pointer_events(point: egui::Pos2) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(point),
            egui::Event::PointerButton {
                pos: point,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            },
            egui::Event::PointerButton {
                pos: point,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }

    fn rendered_text(output: &egui::FullOutput) -> Vec<String> {
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) => Some(text.galley.text().to_owned()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn comments_render_at_exact_listing_and_code_locations_and_refresh_after_edit_delete_undo() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        let instruction = Instruction {
            address: 0x100c,
            bytes: vec![0x90],
            mnemonic: "nop".into(),
            operands: String::new(),
        };
        app.listing.push(instruction.clone());
        app.view.as_mut().unwrap().blocks[0]
            .instructions
            .push(instruction);
        for (address, comment) in [
            (0x1000, "entry note"),
            (0x1004, "first */ literal"),
            (0x1008, "second note"),
            (0x100c, "unmapped note"),
        ] {
            app.edit_annotation(
                address,
                Annotation {
                    comment: comment.into(),
                    ..Default::default()
                },
            );
        }
        let original_source = app.decompiled.clone();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
        let listing = rendered_text(&output);
        assert!(
            listing
                .iter()
                .any(|row| row.starts_with("00001004") && row.contains("; first */ literal"))
        );
        assert!(
            !listing
                .iter()
                .any(|row| row.starts_with("00001008") && row.contains("first */ literal"))
        );
        output.textures_delta.clear();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let code = rendered_text(&output);
        for comment in [
            "entry note",
            "first */ literal",
            "second note",
            "unmapped note",
        ] {
            assert_eq!(code.iter().filter(|row| row.contains(comment)).count(), 1);
        }
        let position = |needle: &str| code.iter().position(|row| row.contains(needle)).unwrap();
        assert!(position("first */ literal") < position("return café"));
        assert!(position("second note") < position("return café"));
        assert!(position("unmapped note") > position("Comments without visible code"));
        assert_eq!(app.decompiled, original_source);
        let mapping = &app.semantic.mappings[0];
        assert_eq!(
            &app.decompiled[mapping.start..mapping.end],
            "return café + 1;"
        );
        output.textures_delta.clear();

        app.edit_annotation(
            0x1004,
            Annotation {
                comment: "edited note".into(),
                ..Default::default()
            },
        );
        app.edit_annotation(0x1008, Annotation::default());
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let code = rendered_text(&output);
        assert!(code.iter().any(|row| row.contains("edited note")));
        assert!(
            !code
                .iter()
                .any(|row| row.contains("first */ literal") || row.contains("second note"))
        );
        output.textures_delta.clear();
        app.undo(&context);
        app.update_comment_rows();
        assert!(app.comment_rows.rows.contains(&CodeRow::Comment(0x1008)));
        assert_eq!(app.decompiled, original_source);
    }

    #[test]
    fn comment_browser_filters_jumps_and_edits_exact_addresses_with_history() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        app.edit_annotation(
            0x1008,
            Annotation {
                label: "answer".into(),
                comment: "unique needle".into(),
                ..Default::default()
            },
        );
        app.edit_annotation(
            0x1004,
            Annotation {
                comment: "another comment".into(),
                ..Default::default()
            },
        );
        app.select_instruction(0x1004);
        app.annotation_browser.query = "NEEDLE".into();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.annotation_browser(ui));
        assert_eq!(app.annotation_browser.filtered.len(), 1);
        let point = text_position(&output, "00001008", 4);
        output.textures_delta.clear();
        let mut output = context.run_ui(
            egui::RawInput {
                events: pointer_events(point),
                time: Some(1.0),
                ..Default::default()
            },
            |ui| app.annotation_browser(ui),
        );
        output.textures_delta.clear();
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.pending_listing_scroll, Some(2));
        assert_eq!(app.history, [0x1004, 0x1008]);
        app.history_step(false, &context);
        assert_eq!(app.selected, Some(0x1004));
        assert_eq!(app.pending_listing_scroll, Some(1));
        app.history_step(true, &context);
        assert_eq!(app.selected, Some(0x1008));
        assert!(
            app.client.is_none(),
            "same-function navigation retains displayed analysis"
        );
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.annotation_browser(ui));
        let point = text_position(&output, "Edit", 1);
        output.textures_delta.clear();
        let mut output = context.run_ui(
            egui::RawInput {
                events: pointer_events(point),
                time: Some(2.0),
                ..Default::default()
            },
            |ui| app.annotation_browser(ui),
        );
        output.textures_delta.clear();
        assert!(app.annotations_open && app.focus_comment);
        assert_eq!(app.selected, Some(0x1008));
    }

    #[test]
    fn counterpart_scroll_includes_comments_and_reaches_unmapped_notes_once() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        app.decompiled = (0..200).map(|n| format!("statement_{n}();\n")).collect();
        app.highlighted = Some(HighlightedCode::new(&app.decompiled));
        let mut offset = 0;
        app.decompiled_lines = app
            .decompiled
            .split_inclusive('\n')
            .map(|line| {
                let range = (offset, offset + line.len());
                offset += line.len();
                range
            })
            .collect();
        app.semantic.mappings = vec![CodeMapping {
            start: app.decompiled_lines[150].0,
            end: app.decompiled_lines[150].1 - 1,
            addresses: vec![0x1004],
        }];
        for (address, comment) in [
            (0x1004, "mapped scroll target"),
            (0x1008, "unmapped scroll target"),
        ] {
            app.edit_annotation(
                address,
                Annotation {
                    comment: comment.into(),
                    ..Default::default()
                },
            );
        }
        for (address, comment) in [
            (0x1004, "mapped scroll target"),
            (0x1008, "unmapped scroll target"),
        ] {
            app.select_instruction(address);
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(600.0, 300.0),
                    )),
                    ..Default::default()
                },
                |ui| app.side_panel(ui),
            );
            let text = rendered_text(&output);
            assert!(
                text.iter().any(|row| row.contains(comment)),
                "{comment} visible after one-shot scroll"
            );
            assert!(
                text.len() < 40,
                "source and comment rows remain virtualized"
            );
            assert!(app.pending_code_scroll.is_none() && app.pending_comment_scroll.is_none());
            output.textures_delta.clear();
        }
        assert!(
            app.semantic.ranges.is_empty(),
            "unmapped comment never acquires a code selection"
        );
    }

    #[test]
    fn annotation_history_retains_graph_and_data_comments_open_bytes() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        app.tab = Tab::Graph;
        app.history = vec![0x1000, 0x1004];
        app.history_index = 1;
        app.history_step(false, &context);
        assert_eq!(app.selected, Some(0x1000));
        assert!(app.tab == Tab::Graph);
        app.history_step(true, &context);
        assert_eq!(app.selected, Some(0x1004));
        assert!(app.tab == Tab::Graph);

        let info = app.info.as_mut().unwrap();
        info.file_len = 512;
        info.sections.push(SectionInfo {
            name: ".data".into(),
            address: 0x2000,
            size: 256,
            file_offset: 256,
            file_size: 256,
            executable: false,
        });
        app.discovery_job = Some(mpsc::sync_channel(1).1);
        app.navigate_annotation(0x2000, true, &context);
        assert_eq!(app.selected, Some(0x2000));
        assert!(app.tab == Tab::Decode);
        assert!(app.reference_focus.is_none());
        assert!(matches!(
            app.discovery_bytes,
            Some((
                Request::Bytes {
                    address: 0x2000,
                    ..
                },
                _
            ))
        ));
        assert!(app.queue.is_empty());
        assert_eq!(app.view.as_ref().unwrap().address, 0x1000);
    }

    #[test]
    fn annotation_navigation_reuses_observed_owner_without_guessing_symbol_extents() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        let original_view = app.view.clone().unwrap();
        app.edit_annotation(
            0x1008,
            Annotation {
                comment: "inside entry".into(),
                ..Default::default()
            },
        );
        app.update_comment_rows();
        app.navigate(0x1040, true, &context);
        app.navigate_annotation(0x1008, true, &context);
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.reference_focus, Some((0x1000, 0x1008)));
        assert_eq!(app.status, "Loading function 0x1000…");
        app.receive(
            Pending {
                id: 1,
                request: Request::Graph { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            },
            Response::Graph {
                view: original_view,
            },
            &context,
        );
        assert_eq!(app.view.as_ref().unwrap().address, 0x1000);
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.pending_listing_scroll, Some(2));
        app.update_comment_rows();
        assert!(app.comment_rows.rows.contains(&CodeRow::Comment(0x1008)));
        // An address numerically between symbols has no known owner.
        app.navigate_annotation(0x1020, true, &context);
        assert_eq!(app.reference_focus, Some((0x1020, 0x1020)));
        assert_eq!(app.selected, Some(0x1020));
    }

    fn text_position(output: &egui::FullOutput, needle: &str, byte: usize) -> egui::Pos2 {
        output
            .shapes
            .iter()
            .find_map(|shape| {
                if let egui::epaint::Shape::Text(text) = &shape.shape {
                    if text.galley.text().contains(needle) {
                        let index = text.galley.text()[..byte].chars().count();
                        Some(
                            text.pos
                                + text
                                    .galley
                                    .pos_from_cursor(egui::text::CCursor::new(index))
                                    .center()
                                    .to_vec2(),
                        )
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .expect("rendered target text")
    }

    #[test]
    fn clicking_c_statement_selects_its_machine_instructions_without_navigation_or_focus_change() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        let generation = app.selection_generation;
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let point = text_position(
            &output,
            "return café",
            app.decompiled.find("café").unwrap() + 3,
        );
        output.textures_delta.clear();
        let mut output = context.run_ui(
            egui::RawInput {
                events: pointer_events(point),
                time: Some(1.0),
                ..Default::default()
            },
            |ui| app.side_panel(ui),
        );
        output.textures_delta.clear();
        assert_eq!(app.selected, Some(0x1004));
        assert_eq!(
            app.semantic.addresses,
            std::collections::BTreeSet::from([0x1004, 0x1008])
        );
        assert_eq!(app.pending_listing_scroll, Some(1));
        assert_eq!(app.selection_generation, generation);
        assert_eq!(app.history, vec![0x1000]);
        assert!(app.client.is_none());
        assert!(context.memory(|memory| memory.focused()).is_none());
        // Unmapped punctuation does not fabricate a nearby machine address.
        app.select_decompiled_byte(0);
        assert_eq!(app.selected, Some(0x1004));
        assert!(app.semantic.addresses.is_empty());
        assert!(app.semantic.ranges.is_empty());
        assert!(app.pending_listing_scroll.is_none());
        assert!(app.status.contains("no machine instruction mapping"));
    }

    #[test]
    fn narrow_listing_keeps_long_instructions_on_single_scrollable_rows() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        let operands = "rax, qword ptr [rip + a_long_symbol_name_that_exceeds_the_pane_width]";
        for instruction in &mut app.listing {
            instruction.operands = operands.into();
        }
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(360.0, 500.0),
                )),
                ..Default::default()
            },
            |ui| app.main_panel(ui),
        );
        output.textures_delta.clear();
        let rows: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| {
                if let egui::epaint::Shape::Text(text) = &shape.shape {
                    text.galley
                        .text()
                        .contains(operands)
                        .then_some(&text.galley)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(rows.len(), app.listing.len());
        for row in rows {
            assert_eq!(
                row.rows.len(),
                1,
                "long instructions must not consume adjacent rows"
            );
            assert!(
                row.rect.width() > 360.0,
                "retain the full horizontally scrollable instruction"
            );
        }
    }

    #[test]
    fn clicking_listing_or_graph_instruction_highlights_the_related_c_statement() {
        for tab in [Tab::Listing, Tab::Graph] {
            let context = egui::Context::default();
            theme::install(&context);
            let mut app = semantic_app();
            app.tab = tab;
            let generation = app.selection_generation;
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 700.0),
                    )),
                    ..Default::default()
                },
                |ui| app.main_panel(ui),
            );
            let point = text_position(&output, "00001008", 3);
            output.textures_delta.clear();
            let mut output = context.run_ui(
                egui::RawInput {
                    events: pointer_events(point),
                    time: Some(1.0),
                    ..Default::default()
                },
                |ui| app.main_panel(ui),
            );
            output.textures_delta.clear();
            assert_eq!(app.selected, Some(0x1008));
            assert_eq!(
                app.semantic.addresses,
                std::collections::BTreeSet::from([0x1008])
            );
            assert_eq!(
                app.semantic.ranges,
                vec![app.semantic.mappings[0].start..app.semantic.mappings[0].end]
            );
            assert_eq!(app.pending_code_scroll, Some(0));
            assert_eq!(app.selection_generation, generation);
            let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
            assert!(output.shapes.iter().any(|shape|matches!(&shape.shape,egui::epaint::Shape::Text(text) if text.galley.job.sections.iter().any(|s|s.format.background==theme::CURRENT_LINE))));
            output.textures_delta.clear();
            assert!(app.pending_code_scroll.is_none());
        }
    }

    #[test]
    fn navigation_clears_old_semantic_links_and_cross_function_views() {
        let mut app = semantic_app();
        app.select_decompiled_byte(app.decompiled.find("return").unwrap());
        app.navigate(0x1040, true, &egui::Context::default());
        assert!(app.semantic.mappings.is_empty());
        assert!(app.semantic.addresses.is_empty());
        assert!(app.semantic.ranges.is_empty());
        assert!(app.view.is_none());
        assert!(app.canvas.is_none());
        assert!(app.listing.is_empty());
        app.select_decompiled_byte(0);
        assert_eq!(app.selected, Some(0x1040));
    }

    #[test]
    fn decompiler_navigation_uses_only_semantic_targets_even_with_duplicate_names() {
        let mut app = call_navigation_app("next()");
        assert_eq!(app.decompiler_call_target(1), None); // Legacy text cache fails closed.
        app.semantic_info
            .tokens
            .push(crate::semantic::SemanticToken {
                start: 0,
                end: 4,
                kind: TokenKind::Call { target: 0x1040 },
            });
        assert_eq!(app.decompiler_call_target(1), Some(0x1040));
        assert_eq!(app.decompiler_call_target(4), None);
        app.info.as_mut().unwrap().functions.push(FunctionInfo {
            address: 0x1080,
            name: "next".into(),
        });
        app.view.as_mut().unwrap().calls.clear();
        assert_eq!(app.decompiler_call_target(1), Some(0x1040));
        app.semantic_info.tokens.clear();
        assert_eq!(app.decompiler_call_target(1), None);
    }

    #[test]
    fn double_clicking_decompiler_call_text_navigates_and_records_history() {
        let context = egui::Context::default();
        theme::install(&context);
        let source = "void entry() { next(); }";
        let mut app = call_navigation_app(source);
        let start = source.find("next").unwrap();
        app.semantic_info
            .tokens
            .push(crate::semantic::SemanticToken {
                start,
                end: start + 4,
                kind: TokenKind::Call { target: 0x1040 },
            });
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let point = output
            .shapes
            .iter()
            .find_map(|shape| {
                if let egui::epaint::Shape::Text(text) = &shape.shape
                    && text.galley.text() == source
                {
                    let cursor = egui::text::CCursor::new(source.find("next").unwrap() + 2);
                    Some(text.pos + text.galley.pos_from_cursor(cursor).center().to_vec2())
                } else {
                    None
                }
            })
            .expect("rendered decompiler call");
        output.textures_delta.clear();
        for (index, time) in [1.0, 1.15].into_iter().enumerate() {
            let events = vec![
                egui::Event::PointerMoved(point),
                egui::Event::PointerButton {
                    pos: point,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::PointerButton {
                    pos: point,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ];
            let mut output = context.run_ui(
                egui::RawInput {
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |ui| app.side_panel(ui),
            );
            output.textures_delta.clear();
            if index == 0 {
                assert_eq!(app.selected, Some(0x1000));
            }
        }
        assert_eq!(app.selected, Some(0x1040));
        assert_eq!(app.history, [0x1000, 0x1040]);
    }

    #[test]
    fn selected_local_rename_and_undo_share_the_annotation_history() {
        let mut app = semantic_app();
        let context = egui::Context::default();
        let identity = LocalIdentity {
            function: 0x1000,
            engine: crate::semantic::LOCAL_FINGERPRINT.into(),
            storage: crate::semantic::LocalStorage::Register,
            offset: 0,
            size: 4,
            verification: "a".repeat(64),
        };
        let byte = app.decompiled.find("café").unwrap();
        app.semantic_info
            .locals
            .push(crate::semantic::LocalVariable {
                identity: identity.clone(),
                name: "café".into(),
            });
        app.semantic_info
            .tokens
            .push(crate::semantic::SemanticToken {
                start: byte,
                end: byte + "café".len(),
                kind: TokenKind::Local { local: Some(0) },
            });
        app.edit_annotation(
            0x1004,
            Annotation {
                comment: "keep me".into(),
                ..Default::default()
            },
        );
        let original = app.decompiled.clone();
        let original_semantics = app.semantic_info.clone();
        // Exercise native egui pointer selection, keyboard dispatch, modal text
        // selection/replacement, Enter application, and Ctrl+Z outside editors.
        theme::install(&context);
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let point = text_position(&output, "return café", byte + 1);
        output.textures_delta.clear();
        let mut output = context.run_ui(
            egui::RawInput {
                events: pointer_events(point),
                time: Some(1.0),
                ..Default::default()
            },
            |ui| app.side_panel(ui),
        );
        output.textures_delta.clear();
        assert_eq!(app.selected_local, Some(0));
        assert_eq!(app.selected, Some(0x1004));
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::L, egui::Modifiers::NONE)],
        );
        assert!(
            matches!(&app.browser_dialog.as_ref().unwrap().kind, BrowserDialogKind::RenameLocal { identity: selected } if selected == &identity)
        );
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![egui::Event::Text("local_value".into())],
        );
        assert_eq!(app.browser_dialog.as_ref().unwrap().text, "local_value");
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::Enter, egui::Modifiers::NONE)],
        );
        assert!(app.browser_dialog.is_none());
        assert_eq!(
            app.session.as_ref().unwrap().local_renames[0].name,
            "local_value"
        );
        assert_eq!(app.session.as_ref().unwrap().version, 2);
        // Rendering while the replacement is pending must not reuse source rows
        // from the old text. The returned offsets then place the same comment
        // above the renamed statement without modifying the engine's source.
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        output.textures_delta.clear();
        let renamed = original.replace("café", "local_value");
        let mut semantics = original_semantics;
        semantics.locals[0].name = "local_value".into();
        semantics.tokens[0].end = byte + "local_value".len();
        app.receive(
            Pending {
                id: 1,
                request: Request::Decompile { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            },
            Response::Decompiled {
                address: 0x1000,
                mappings: vec![CodeMapping {
                    start: renamed.find("return").unwrap(),
                    end: renamed.find(';').unwrap() + 1,
                    addresses: vec![0x1004, 0x1008],
                }],
                text: renamed.clone(),
                semantics,
            },
            &context,
        );
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let rows = rendered_text(&output);
        let comment = rows.iter().position(|row| row.contains("keep me")).unwrap();
        let statement = rows
            .iter()
            .position(|row| row.contains("return local_value"))
            .unwrap();
        assert!(comment < statement);
        assert_eq!(rows.iter().filter(|row| row.contains("keep me")).count(), 1);
        assert_eq!(app.decompiled, renamed);
        output.textures_delta.clear();
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(
                egui::Key::Z,
                egui::Modifiers {
                    ctrl: true,
                    command: true,
                    ..Default::default()
                },
            )],
        );
        assert!(app.session.as_ref().unwrap().local_renames.is_empty());
        assert_eq!(
            app.session.as_ref().unwrap().annotations[&0x1004].comment,
            "keep me"
        );
        keyboard_frame(
            &context,
            &mut app,
            vec![egui::Event::Key {
                key: egui::Key::Z,
                physical_key: Some(egui::Key::Z),
                pressed: false,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(
                egui::Key::Z,
                egui::Modifiers {
                    ctrl: true,
                    command: true,
                    ..Default::default()
                },
            )],
        );
        assert!(
            !app.session
                .as_ref()
                .unwrap()
                .annotations
                .contains_key(&0x1004)
        );
        app.decompiler_rename_context = true;
        app.selected_local = None;
        app.begin_rename();
        assert!(app.browser_dialog.is_none());
        assert!(app.status.contains("unsupported"));
    }

    #[test]
    fn edits_store_bounded_deltas_and_do_not_mark_later_revisions_saved() {
        let mut app = DesktopApp::empty(None);
        app.session = Some(Session::new("a".repeat(64)));
        for index in 0..40 {
            app.edit_annotation(
                index,
                Annotation {
                    comment: format!("note {index}"),
                    ..Default::default()
                },
            );
        }
        assert_eq!(app.undo.len(), HISTORY_LIMIT);
        let saved_snapshot = app.revision;
        app.edit_annotation(41, Annotation::default());
        app.saved_revision = saved_snapshot;
        assert!(app.dirty());
    }

    #[test]
    fn restored_project_shows_saved_highlighted_analysis_and_keeps_its_binary_until_close() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("fixture.bin");
        std::fs::write(&binary, [0_u8; 256]).unwrap();
        let mut app = keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.path = binary.to_string_lossy().into_owned();
        info.sha256 = crate::session::fingerprint(&binary).unwrap();
        info.source_identity = FileIdentity::from_file(&std::fs::File::open(&binary).unwrap());
        let protection = BinaryProtection::open(&binary)
            .unwrap()
            .bind_snapshot(info)
            .unwrap();
        let mut session = Session::new(info.sha256.clone());
        session.annotations.insert(
            0x1000,
            Annotation {
                label: "restored_entry".into(),
                comment: "restored header comment".into(),
                ..Default::default()
            },
        );
        session.annotations.insert(
            0x1004,
            Annotation {
                comment: "restored statement comment".into(),
                ..Default::default()
            },
        );
        let source = "int restored_entry() { return 7; }\n";
        let data = ProjectData {
            info: info.clone(),
            session: session.clone(),
            view: Some(FunctionView {
                address: 0x1000,
                blocks: vec![],
                edges: vec![],
                calls: vec![],
                warnings: vec![],
            }),
            decompiled: Some(source.into()),
            mappings: vec![CodeMapping {
                start: source.find("return").unwrap(),
                end: source.find(';').unwrap() + 1,
                addresses: vec![0x1004],
            }],
            semantics: Default::default(),
            strings: vec![StringEntry {
                address: 0x1040,
                text: "saved string".into(),
                encoding: "ASCII".into(),
            }],
            strings_truncated: true,
            crypto: vec![],
            crypto_truncated: false,
            selected_address: Some(0x1000),
            discovery: None,
        };
        let project_path = directory.path().join("analysis.grproj");
        data.save(&project_path, &protection, true).unwrap();
        let project = ProjectData::load(&project_path).unwrap();
        let extracted = project.binary.as_ref().unwrap().path().to_owned();
        app.session = Some(project.data.session.clone());
        app.restore_project(
            ProjectOpen {
                project,
                project_path: project_path.clone(),
                binary_path: extracted.clone(),
                discovery_index: None,
            },
            &egui::Context::default(),
        );
        assert_eq!(app.project_path, Some(project_path));
        assert!(app.saved_analysis);
        assert!(app.highlighted.is_some());
        assert!(app.decompiled.contains("restored_entry"));
        let context = egui::Context::default();
        theme::install(&context);
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        let text = rendered_text(&output);
        assert!(
            text.iter()
                .any(|row| row.contains("restored header comment"))
        );
        assert!(
            text.iter()
                .any(|row| row.contains("restored statement comment"))
        );
        output.textures_delta.clear();
        assert_eq!(app.decompiled, source);
        assert_eq!(app.history, [0x1000]);
        assert_eq!(app.strings[0].text, "saved string");
        assert!(app.strings_truncated);
        assert!(extracted.exists());
        keyboard_frame(&egui::Context::default(), &mut app, vec![]);
        app.stop_worker();
        assert!(
            extracted.exists(),
            "Cancelling analysis retains the project image for restarts"
        );
        app.clear_binary();
        assert!(!extracted.exists());
        assert!(app.project_path.is_none());
        assert!(!app.saved_analysis);
    }

    #[test]
    fn project_save_results_preserve_edits_made_during_background_save_and_cancelled_intents() {
        let mut app = keyboard_app();
        app.edit_annotation(0x1000, Annotation::default());
        let saved = app.revision;
        app.edit_annotation(0x1040, Annotation::default());
        let (tx, rx) = mpsc::channel();
        app.file_job = Some(rx);
        app.after_save = Some(Intent::Close);
        tx.send(FileEvent::ProjectSaved {
            generation: app.generation,
            revision: saved,
            embedded: true,
            result: Ok(Some("analysis.grproj".into())),
        })
        .unwrap();
        app.poll_files(&egui::Context::default());
        assert!(app.dirty());
        assert!(app.info.is_some());
        assert!(matches!(app.intent, Some(Intent::Close)));
        assert_eq!(app.saved_revision, saved);
        let (tx, rx) = mpsc::channel();
        app.file_job = Some(rx);
        app.after_save = app.intent.take();
        tx.send(FileEvent::ProjectSaved {
            generation: app.generation,
            revision: app.revision,
            embedded: true,
            result: Ok(None),
        })
        .unwrap();
        app.poll_files(&egui::Context::default());
        assert!(app.dirty());
        assert!(matches!(app.intent, Some(Intent::Close)));
    }

    #[test]
    fn saved_references_restore_with_provenance_until_discovery_runs_again() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = keyboard_app();
        let info = app.info.clone().unwrap();
        let mut state = crate::discovery::Discovery::new(Some(0x1000), [0x1000, 0x1040], false);
        let Some(Request::DiscoverBatch { binding, .. }) = state.begin(1, 1, 0) else {
            panic!()
        };
        let batch = DiscoveryBatch {
            binding,
            inventory: InventoryChange::Replace {
                revision: 1,
                functions: info.functions.clone(),
            },
            truncated: false,
            patterns: None,
            outcomes: vec![DiscoveryOutcome {
                address: 0x1000,
                status: DiscoveryStatus::Done,
            }],
            analysis: CallAnalysis {
                references: vec![CallReference {
                    caller: 0x1000,
                    address: 0x1004,
                    target: 0x1040,
                }],
                functions_examined: 1,
                decode_attempts: 2,
                ..Default::default()
            },
        };
        crate::discovery::commit_replacement(&mut state, &info, &batch).unwrap();
        let saved = Arc::new(state.save());
        let data = ProjectData {
            info: info.clone(),
            session: app.session.clone().unwrap(),
            view: None,
            decompiled: None,
            mappings: Vec::new(),
            semantics: Default::default(),
            strings: Vec::new(),
            strings_truncated: false,
            crypto: Vec::new(),
            crypto_truncated: false,
            selected_address: None,
            discovery: Some(saved.clone()),
        };
        app.restore_project(
            ProjectOpen {
                discovery_index: Some(crate::call_analysis::CallIndex::new(saved.report.clone())),
                project: LoadedProject {
                    data,
                    binary: None,
                    source_hint: "fixture".into(),
                    cache_compatible: true,
                },
                project_path: "analysis.grproj".into(),
                binary_path: "fixture".into(),
            },
            &context,
        );
        assert!(app.saved_references);
        assert!(Arc::ptr_eq(app.discovery_saved.as_ref().unwrap(), &saved));
        assert_eq!(app.call_index.as_ref().unwrap().incoming[&0x1040], [0]);
        assert!(
            app.discovery_summary
                .as_ref()
                .unwrap()
                .starts_with("Saved discovery: 1 examined · 1 remaining")
        );
        app.tab = Tab::References;
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
        output.textures_delta.clear();
        assert!(
            output.shapes.iter().any(|shape| matches!(&shape.shape,
            egui::epaint::Shape::Text(text) if text.galley.text().starts_with("Saved analysis ·")))
        );

        // Discover never resumes or trusts saved statuses; it starts fresh.
        app.request(Request::Discover, &context);
        assert!(!app.saved_references && app.call_index.is_none());
        assert!(app.discovery_saved.is_none());
        while app.discovery_job.is_some() {
            app.poll_discovery(&context);
        }
        let fresh = app.discovery_saved.as_ref().unwrap();
        assert_eq!((fresh.batches, fresh.pending.len()), (0, 2));

        // Rediscover discards session results too.
        app.discovery.as_mut().unwrap().batches = 3;
        app.rediscover(&context);
        while app.discovery_job.is_some() {
            app.poll_discovery(&context);
        }
        assert_eq!(app.discovery.as_ref().unwrap().batches, 0);
    }

    #[test]
    fn json_export_does_not_mark_an_existing_project_saved() {
        let mut app = keyboard_app();
        app.project_path = Some("analysis.grproj".into());
        app.edit_annotation(0x1000, Annotation::default());
        let (tx, rx) = mpsc::channel();
        app.file_job = Some(rx);
        tx.send(FileEvent::Saved {
            generation: app.generation,
            revision: app.revision,
            result: Ok(Some("annotations.json".into())),
        })
        .unwrap();
        app.poll_files(&egui::Context::default());
        assert!(app.dirty());
        assert_eq!(
            app.project_path.as_deref(),
            Some(std::path::Path::new("analysis.grproj"))
        );
    }

    #[test]
    fn opening_a_project_path_preserves_unsaved_work_before_loading() {
        let mut app = keyboard_app();
        app.edit_annotation(0x1000, Annotation::default());
        app.request_intent(
            Intent::OpenPath("other.GRPROJ".into()),
            &egui::Context::default(),
        );
        assert!(is_project_path(std::path::Path::new("other.GRPROJ")));
        assert!(!is_project_path(std::path::Path::new("program.exe")));
        assert!(matches!(app.intent, Some(Intent::OpenPath(_))));
        assert!(app.file_job.is_none());
        assert!(app.dirty());
    }

    #[test]
    fn navigation_addresses_and_display_cropping_are_unicode_safe() {
        assert_eq!(parse_address(" 0x401000 ").unwrap(), 0x401000);
        assert_eq!(parse_address("FFFFFFFFFFFFFFFF").unwrap(), u64::MAX);
        assert!(parse_address("10000000000000000").is_err());
        assert_eq!(crop("🦀hello", 1), "🦀…");
    }

    #[test]
    fn stopping_workers_retains_source_protection_until_the_binary_is_closed() {
        let source = std::env::current_exe().unwrap();
        let protection = BinaryProtection::open(&source).unwrap();
        let mut app = DesktopApp::empty(None);
        app.binary_protection = Some(protection.clone());
        app.binary_path = Some(source);
        app.stop_worker();
        assert!(
            app.binary_protection
                .as_ref()
                .unwrap()
                .same_source(&protection)
        );
        app.clear_binary();
        assert!(app.binary_protection.is_none());
    }

    #[test]
    fn closed_binary_drops_all_binary_scoped_views_and_notes() {
        let mut app = DesktopApp::empty(None);
        app.session = Some(Session::new("a".repeat(64)));
        app.crypto.push(CryptoMatch {
            address: 1,
            algorithm: "test".into(),
            signature: "test".into(),
            length: 1,
        });
        app.edit_annotation(1, Annotation::default());
        app.clear_binary();
        assert!(app.session.is_none());
        assert!(app.crypto.is_empty());
        assert!(!app.dirty());
        assert!(app.undo.is_empty());
    }

    #[test]
    fn stale_decompiler_and_graph_results_are_not_displayed() {
        let mut app = DesktopApp::empty(None);
        app.auto_decompile = false;
        app.selection_generation = 2;
        let pending = Pending {
            id: 1,
            request: Request::Graph { address: 0x1000 },
            started: Instant::now(),
            selection: 1,
            revision: 0,
            byte_origin: (None, Tab::Listing),
        };
        app.receive(
            pending,
            Response::Graph {
                view: FunctionView {
                    address: 0x1000,
                    blocks: Vec::new(),
                    edges: Vec::new(),
                    calls: Vec::new(),
                    warnings: Vec::new(),
                },
            },
            &egui::Context::default(),
        );
        assert!(app.view.is_none());
        let pending = Pending {
            id: 2,
            request: Request::Decompile { address: 0x1000 },
            started: Instant::now(),
            selection: 2,
            revision: 0,
            byte_origin: (None, Tab::Listing),
        };
        app.revision = 1;
        app.receive(
            pending,
            Response::Decompiled {
                address: 0x1000,
                mappings: Vec::new(),
                semantics: Default::default(),
                text: "stale output".into(),
            },
            &egui::Context::default(),
        );
        assert!(app.decompiled.is_empty());
    }

    #[test]
    fn analysis_activity_stays_bottom_right_and_disappears_on_cancel() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = DesktopApp::empty(None);
        app.pending = Some(Pending {
            id: 1,
            request: Request::Decompile { address: 0x1000 },
            started: Instant::now() - Duration::from_secs(2),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
        });
        let frame = |app: &mut DesktopApp| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 640.0),
                    )),
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
            output.textures_delta.clear();
            output
        };
        // Settle panel sizing before checking placement at the minimum window size.
        frame(&mut app);
        let output = frame(&mut app);
        let position = text_position(&output, "Decompiling ·", 0);
        assert!(position.x > 650.0 && position.x < 1000.0, "{position:?}");
        assert!(position.y > 600.0 && position.y < 640.0, "{position:?}");
        app.stop_worker();
        let output = frame(&mut app);
        assert!(!output.shapes.iter().any(|shape| matches!(&shape.shape,
            egui::epaint::Shape::Text(text) if text.galley.text().contains("Decompiling ·"))));
    }

    #[test]
    fn analyze_prompt_queues_the_checked_analyses_and_skips_discovery_for_packed_images() {
        let context = egui::Context::default();
        theme::install(&context);
        let frame = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    events,
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 800.0),
                    )),
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
            output.textures_delta.clear();
            output
        };
        let click = |output: &egui::FullOutput, label: &str| {
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text) if text.galley.text() == label => {
                        Some(text.pos + text.galley.rect.center().to_vec2())
                    }
                    _ => None,
                })
                .map(pointer_events)
                .expect("rendered dialog control")
        };
        for packed in [false, true] {
            let mut app = keyboard_app();
            if packed {
                app.info
                    .as_mut()
                    .unwrap()
                    .warnings
                    .push(crate::packing::UPX_PACKED_WARNING.into());
            }
            app.analyze_prompt = Some(AnalyzePrompt {
                generation: app.generation,
                first_open: true,
            });
            frame(&mut app, Vec::new());
            let output = frame(&mut app, Vec::new());
            let events = click(&output, "FindCrypt constants");
            frame(&mut app, events);
            let output = frame(&mut app, Vec::new());
            let events = click(&output, "Analyze");
            frame(&mut app, events);
            assert!(app.analyze_prompt.is_none());
            // Without a worker the first scan is marked current but sends nothing.
            let plan = app.analysis_plan.as_ref().expect("analysis plan");
            assert_eq!(plan.current, Some(AnalysisStep::Strings));
            let expected = if packed {
                vec![AnalysisStep::Crypto]
            } else {
                vec![AnalysisStep::Crypto, AnalysisStep::Functions]
            };
            assert_eq!(Vec::from(plan.steps.clone()), expected);
        }
        let mut app = keyboard_app();
        app.analyze_prompt = Some(AnalyzePrompt {
            generation: app.generation,
            first_open: true,
        });
        frame(&mut app, Vec::new());
        frame(&mut app, pointer_events(egui::pos2(1100.0, 700.0)));
        let output = frame(&mut app, Vec::new());
        assert!(
            app.analyze_prompt.is_some(),
            "backdrop clicks keep the prompt"
        );
        let events = click(&output, "Not now");
        frame(&mut app, events);
        assert!(app.analyze_prompt.is_none() && app.analysis_plan.is_none());
    }

    #[test]
    fn auto_analysis_waits_for_idle_requeues_preempted_scans_and_keeps_the_tab() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        let pending = |app: &DesktopApp, request| Pending {
            id: 1,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
        };
        app.start_auto_analysis();
        app.pending = Some(pending(&app, Request::Graph { address: 0x1000 }));
        app.pump_analysis(&context);
        assert_eq!(app.analysis_plan.as_ref().unwrap().current, None);
        app.pending = None;
        app.pump_analysis(&context);
        assert_eq!(
            app.analysis_plan.as_ref().unwrap().current,
            Some(AnalysisStep::Strings)
        );
        // Navigating restarts the busy worker; the interrupted scan runs again later.
        app.pending = Some(pending(&app, app.string_request()));
        app.navigate(0x1040, true, &context);
        let plan = app.analysis_plan.as_ref().unwrap();
        assert_eq!(plan.current, None);
        assert_eq!(
            Vec::from(plan.steps.clone()),
            [AnalysisStep::Strings, AnalysisStep::Functions]
        );
        app.pending = None;
        app.pump_analysis(&context);
        app.receive(
            pending(&app, app.string_request()),
            Response::Strings {
                strings: Vec::new(),
                truncated: false,
            },
            &context,
        );
        assert!(app.strings_scanned);
        assert!(app.tab == Tab::Listing);
        app.pump_analysis(&context);
        assert_eq!(
            app.analysis_plan.as_ref().unwrap().current,
            Some(AnalysisStep::Functions)
        );
        while app.discovery_job.is_some() {
            app.poll_discovery(&context);
        }
        app.pump_analysis(&context);
        assert!(app.analysis_plan.is_none());
        assert_eq!(app.status, "Auto analysis finished");
    }

    #[test]
    fn worker_restart_replays_only_missing_or_renamed_inventory_entries() {
        let function = |address, name: &str| FunctionInfo {
            address,
            name: name.into(),
        };
        let long = format!("{}é", "x".repeat(MAX_FUNCTION_NAME_BYTES - 1));
        let worker = [
            function(0x1000, "entry"),
            function(0x1040, "next"),
            function(0x1060, inventory_name(&long)),
        ];
        let desired = [
            function(0x1000, "entry"),
            function(0x1040, "renamed"),
            function(0x1060, &long),
            function(0x1080, "FUN_00001080"),
        ];
        assert_eq!(
            replay_addresses(&worker, &desired),
            [0x1040, 0x1080],
            "Unchanged and already-truncated labels need no replay request"
        );
    }

    #[test]
    fn byte_reads_queued_during_discovery_keep_the_original_selection_binding() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        let binding = DiscoveryBinding {
            generation: app.generation,
            epoch: 1,
            revision: app.revision,
            batch: 1,
        };
        app.pending = Some(Pending {
            id: 7,
            request: Request::DiscoverBatch {
                binding,
                inventory_base: None,
                seeds: vec![0x1000],
                patterns: None,
            },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
        });
        app.request(
            Request::Bytes {
                address: 0x1000,
                length: 4,
            },
            &context,
        );
        let (request, origin) = app.discovery_bytes.take().unwrap();
        app.selection_generation += 1;
        app.pending = None;
        app.schedule_open_follow(request, origin);
        assert!(
            app.pending.is_none(),
            "A stale queued read must not be rebound to the new selection"
        );
        assert!(app.queue.is_empty());
    }

    #[test]
    fn navigation_between_batches_keeps_and_adopts_program_wide_results() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.worker_epoch = 3;
        app.discovery_running = true;
        let info = app.info.as_ref().unwrap();
        let mut state = crate::discovery::Discovery::new(
            Some(info.entry),
            info.functions.iter().map(|f| f.address),
            false,
        );
        let request = state
            .begin(app.generation, app.worker_epoch, app.revision)
            .unwrap();
        let Request::DiscoverBatch { binding, seeds, .. } = &request else {
            panic!()
        };
        let batch = DiscoveryBatch {
            binding: *binding,
            inventory: InventoryChange::Replace {
                revision: 1,
                functions: info.functions.clone(),
            },
            truncated: false,
            patterns: None,
            outcomes: seeds
                .iter()
                .map(|&address| DiscoveryOutcome {
                    address,
                    status: DiscoveryStatus::Done,
                })
                .collect(),
            analysis: CallAnalysis {
                functions_examined: seeds.len(),
                decode_attempts: seeds.len(),
                references: vec![CallReference {
                    caller: 0x1000,
                    address: 0x1000,
                    target: 0x1040,
                }],
                ..Default::default()
            },
        };
        app.discovery = Some(state);
        app.call_index = Some(crate::call_analysis::CallIndex::new(CallAnalysis::default()));
        app.pending = Some(Pending {
            id: 7,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
        });
        app.navigate(0x1040, true, &context);
        assert!(matches!(
            app.queue.front(),
            Some(Request::Graph { address: 0x1040 })
        ));
        assert!(app.discovery_running);
        assert!(app.call_index.is_some());
        let pending = app.pending.take().unwrap();
        app.receive(pending, Response::DiscoveryBatch { batch }, &context);
        // Cancellation after a terminal reply keeps this completed batch even
        // if its background validation has not yet been adopted by the UI.
        app.stop_worker();
        let started = Instant::now();
        while app.discovery_job.is_some() {
            assert!(started.elapsed() < Duration::from_secs(5));
            app.poll_discovery(&context);
            std::thread::yield_now();
        }
        assert_eq!(app.discovery.as_ref().unwrap().batches, 1);
        assert_eq!(app.call_index.as_ref().unwrap().report.references.len(), 1);
        assert!(!app.discovery_running);
        assert!(
            app.discovery_summary
                .as_ref()
                .unwrap()
                .contains("2 examined")
        );
    }

    #[test]
    fn progress_is_request_bound_nonterminal_and_does_not_extend_deadlines() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        let started = Instant::now() - Duration::from_secs(3);
        app.pending = Some(Pending {
            id: 7,
            request: Request::Discover,
            started,
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
        });
        for stage in [
            AnalysisStage::Seeds,
            AnalysisStage::Calls,
            AnalysisStage::Publish,
        ] {
            app.receive_worker_reply(
                WorkerResponse {
                    id: 7,
                    response: Response::Progress {
                        progress: AnalysisProgress {
                            stage,
                            functions_examined: 0,
                            decode_attempts: 0,
                        },
                    },
                },
                &context,
            );
            assert_eq!(app.pending.as_ref().unwrap().started, started);
            assert!(app.call_index.is_none());
        }
        app.receive_worker_reply(
            WorkerResponse {
                id: 7,
                response: Response::Functions {
                    functions: app.info.as_ref().unwrap().functions.clone(),
                    truncated: false,
                    analysis: CallAnalysis::default(),
                },
            },
            &context,
        );
        assert!(app.pending.is_none());
        assert!(app.call_index.is_some());
        assert!(app.analysis_progress.is_none());
        app.clear_binary();
        assert!(app.call_index.is_none());
    }

    #[test]
    fn invalid_progress_and_stale_analysis_cannot_replace_reference_evidence() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.pending = Some(Pending {
            id: 7,
            request: Request::Discover,
            started: Instant::now(),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
        });
        app.receive_worker_reply(
            WorkerResponse {
                id: 99,
                response: Response::Progress {
                    progress: AnalysisProgress {
                        stage: AnalysisStage::Seeds,
                        functions_examined: 0,
                        decode_attempts: 0,
                    },
                },
            },
            &context,
        );
        assert!(app.pending.is_none());
        assert!(app.status.contains("unexpected request ID"));
        app.pending = Some(Pending {
            id: 7,
            request: Request::Discover,
            started: Instant::now(),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
        });
        app.receive_worker_reply(
            WorkerResponse {
                id: 7,
                response: Response::Progress {
                    progress: AnalysisProgress {
                        stage: AnalysisStage::Seeds,
                        functions_examined: MAX_ANALYSIS_FUNCTIONS + 1,
                        decode_attempts: 0,
                    },
                },
            },
            &context,
        );
        assert!(app.pending.is_none());
        assert!(app.status.contains("Invalid worker analysis progress"));
        let pending = Pending {
            id: 7,
            request: Request::Discover,
            started: Instant::now(),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
        };
        app.revision += 1;
        app.receive(
            pending,
            Response::Functions {
                functions: vec![],
                truncated: false,
                analysis: CallAnalysis::default(),
            },
            &context,
        );
        assert!(app.call_index.is_none());
        assert_eq!(app.info.as_ref().unwrap().functions.len(), 2);
    }

    #[test]
    fn reference_source_navigation_selects_once_and_explains_display_omissions() {
        let context = egui::Context::default();
        for pc in [0x1004, 0x104c] {
            let mut app = semantic_app();
            let view = app.view.clone().unwrap();
            app.auto_decompile = false;
            app.navigate_reference(0x1000, pc, &context);
            assert!(app.semantic.mappings.is_empty());
            assert!(app.view.is_none());
            let pending = Pending {
                id: 1,
                request: Request::Graph { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
            };
            app.receive(pending, Response::Graph { view }, &context);
            assert_eq!(app.selected, Some(pc));
            assert!(app.semantic.addresses.contains(&pc));
            assert_eq!(app.pending_listing_scroll, (pc == 0x1004).then_some(1));
            assert_eq!(app.undisplayed_call, (pc == 0x104c).then_some(pc));
            assert!(app.reference_focus.is_none());
            assert!(app.tab == Tab::Listing);
        }
    }

    #[test]
    fn empty_desktop_and_all_tabs_render_without_a_worker() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = DesktopApp::empty(None);
        assert!(app.tab == Tab::Listing);
        for tab in [
            Tab::Graph,
            Tab::Listing,
            Tab::Strings,
            Tab::Crypto,
            Tab::Decode,
            Tab::References,
        ] {
            app.tab = tab;
            let mut output = context.run_ui(egui::RawInput::default(), |ui| app.draw(ui));
            assert!(!output.shapes.is_empty());
            output.textures_delta.clear();
        }
        assert!(app.client.is_none());
    }

    #[test]
    fn accepted_decompiler_output_renders_highlighted_utf8_and_clears_on_close() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = DesktopApp::empty(None);
        app.view = Some(FunctionView {
            address: 0x1000,
            blocks: Vec::new(),
            edges: Vec::new(),
            calls: Vec::new(),
            warnings: Vec::new(),
        });
        let text =
            "uint4 café(int param_1) {\n /* multiline\n    🦀 */\n return param_1 + 0x10;\n}\n";
        app.receive(
            Pending {
                id: 1,
                request: Request::Decompile { address: 0x1000 },
                started: Instant::now(),
                selection: 0,
                revision: 0,
                byte_origin: (None, Tab::Listing),
            },
            Response::Decompiled {
                address: 0x1000,
                mappings: Vec::new(),
                semantics: Default::default(),
                text: text.into(),
            },
            &context,
        );
        assert_eq!(app.decompiled, text);
        assert!(app.highlighted.is_some());
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        app.clear_binary();
        assert!(app.highlighted.is_none());
        assert!(app.decompiled.is_empty());
    }

    #[test]
    fn desktop_rejects_oversized_decompiler_text_before_highlighting() {
        let context = egui::Context::default();
        let mut app = DesktopApp::empty(None);
        app.view = Some(FunctionView {
            address: 0x1000,
            blocks: Vec::new(),
            edges: Vec::new(),
            calls: Vec::new(),
            warnings: Vec::new(),
        });
        for extra in [0, 1] {
            let text = format!("//{}", "x".repeat(MAX_DECOMPILED_BYTES - 2 + extra));
            app.receive(
                Pending {
                    id: 1,
                    request: Request::Decompile { address: 0x1000 },
                    started: Instant::now(),
                    selection: 0,
                    revision: 0,
                    byte_origin: (None, Tab::Listing),
                },
                Response::Decompiled {
                    address: 0x1000,
                    mappings: Vec::new(),
                    semantics: Default::default(),
                    text,
                },
                &context,
            );
            if extra == 0 {
                assert_eq!(app.decompiled.len(), MAX_DECOMPILED_BYTES);
                assert!(app.highlighted.is_some());
            } else {
                assert!(app.decompiled.is_empty());
                assert!(app.highlighted.is_none());
                assert!(app.decompiled_lines.is_empty());
                assert!(app.status.contains("exceeded the 2 MiB limit"));
                assert!(app.client.is_none());
            }
        }
    }
}
