//! Native desktop shell. Blocking analysis is disposable process work; dialogs
//! and sidecar I/O run on bounded background jobs, with generation-bound results.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, ScrollArea, TextEdit};

use crate::client::{WorkerClient, WorkerEvent};
use crate::decoder_ui::{DecoderAction, DecoderPanel};
use crate::file_dialog::{FileDialogKind, FileDialogs, request_file};
use crate::graph::{GraphAction, GraphCanvas};
use crate::highlight::HighlightedCode;
use crate::model::*;
use crate::project::{EmbeddedBinary, LoadedProject, ProjectData};
use crate::selection::{SemanticSelection, validate_mappings};
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

#[derive(Clone, Copy)]
enum BrowserDialogKind {
    Rename { address: u64, function: bool },
    GoTo,
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
}

struct Edit {
    address: u64,
    before: Option<Annotation>,
    function_name: Option<String>,
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
    pending_code_scroll: Option<usize>,
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
            pending_code_scroll: None,
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
        self.pending_code_scroll = None;
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
        self.history_index = 0;
        self.filtered_functions.clear();
        self.filter_keys.clear();
        self.filter_cursor = None;
        self.decoder = DecoderPanel::default();
    }

    fn stop_worker(&mut self) {
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
        match client.send(request.clone()) {
            Ok(id) => {
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
        if matches!(request, Request::Decompile { .. } | Request::Discover)
            && self
                .info
                .as_ref()
                .is_some_and(crate::packing::has_upx_warning)
        {
            self.status = crate::packing::UPX_ANALYSIS_ERROR.into();
            return;
        }
        if self.client.is_none() || self.pending.is_some() {
            if let Some(path) = self.binary_path.clone() {
                self.start_open(path, true, Some(request), context);
            }
        } else {
            self.schedule_request(request);
        }
    }

    fn schedule_request(&mut self, request: Request) {
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
        self.selected = Some(address);
        self.address = format!("{address:x}");
        self.editor_address = None;
        self.decompiled.clear();
        self.semantic.clear();
        self.pending_code_scroll = None;
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
        let Some(primary) = self.semantic.select_code(byte) else {
            self.semantic.addresses.clear();
            self.semantic.ranges.clear();
            self.pending_code_scroll = None;
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

    fn poll_worker(&mut self, context: &egui::Context) {
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
        if self.pending.is_some() {
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
            if !matches!(pending.request, Request::Discover)
                || (self.progress_events == 1 && progress.stage != AnalysisStage::Seeds)
                || self.progress_events > MAX_ANALYSIS_FUNCTIONS + 3
                || progress
                    .validate_after(self.analysis_progress.as_ref())
                    .is_err()
            {
                self.stop_worker();
                self.status = "Invalid worker analysis progress; worker stopped".into();
                return;
            }
            if pending.selection == self.selection_generation && pending.revision == self.revision {
                self.analysis_progress = Some(progress);
            }
            return;
        }
        if let Response::Functions { analysis, .. } = &reply.response
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
                if let Some(session) = &self.session {
                    for function in &mut info.functions {
                        if let Some(annotation) = session.annotations.get(&function.address)
                            && !annotation.label.is_empty()
                        {
                            function.name = annotation.label.clone();
                        }
                    }
                }
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
                self.info = Some(info);
                self.rebuild_filter();
                self.status = "Binary loaded".into();
                if let Some(project) = project {
                    self.restore_project(*project, context);
                } else if let Some(request) = opening.follow {
                    self.schedule_open_follow(request, opening.follow_origin);
                } else {
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
                self.canvas = Some(GraphCanvas::new(&view));
                self.cached_graph = false;
                self.saved_analysis = false;
                self.view = Some(view);
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
                        self.pending_code_scroll = None;
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
                        self.status = format!("Invalid decompiler source mappings: {error}");
                        return;
                    }
                    self.semantic.mappings = mappings;
                    if let Some(address) = self.selected {
                        self.semantic.select_instruction(address);
                    }
                    self.highlighted = Some(HighlightedCode::new(&text));
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
                    self.status = "Ready".into();
                }
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
                self.tab = Tab::Strings;
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
                self.tab = Tab::Crypto;
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
        if self.pending.is_none()
            && let Some(request) = self.queue.pop_front()
        {
            self.send_direct(request);
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
            Response::Graph { view } => validate_view(view, &ranges()?),
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
        });
        while self.undo.len() > HISTORY_LIMIT
            || self.undo.iter().map(edit_size).sum::<usize>() > UNDO_BYTES
        {
            self.undo.pop_front();
        }
        self.revision = self.revision.wrapping_add(1);
    }

    fn undo(&mut self, context: &egui::Context) {
        let Some(edit) = self.undo.pop_back() else {
            return;
        };
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
            strings: self.strings.clone(),
            strings_truncated: self.strings_truncated,
            crypto: self.crypto.clone(),
            crypto_truncated: self.crypto_truncated,
            selected_address: self.selected,
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
            self.saved_analysis = true;
            self.cached_graph = true;
            self.history.push(address);
            self.history_index = 0;
            self.selected = selected;
            self.address = format!("{:x}", selected.unwrap_or(address));
            if let Some(text) = data.decompiled {
                self.semantic.mappings = data.mappings;
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
                        self.pending_code_scroll = None;
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

    fn begin_rename(&mut self) {
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
            self.pending_code_scroll = None;
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
        self.navigate(self.history[self.history_index], false, context);
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
            let title = match dialog.kind {
                BrowserDialogKind::Rename { function: true, .. } => "Rename Function",
                BrowserDialogKind::Rename { .. } => "Set Label",
                BrowserDialogKind::GoTo => "Go To",
            };
            ui.heading(title);
            match dialog.kind {
                BrowserDialogKind::Rename { address, .. } => {
                    ui.label(format!("Address {address:#x}"));
                }
                BrowserDialogKind::GoTo => {
                    ui.label("Hexadecimal address or function/label name");
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
            let result = match dialog.kind {
                BrowserDialogKind::Rename { address, .. } => {
                    self.rename_at(address, &dialog.text, context)
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
                });
                if ui
                    .add_enabled(self.pending.is_some(), egui::Button::new("Cancel analysis"))
                    .clicked()
                {
                    self.stop_worker();
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

    fn decompiler_call_target(&self, name: &str) -> Option<u64> {
        let view = self.view.as_ref()?;
        let info = self.info.as_ref()?;
        let mut targets = view
            .calls
            .iter()
            .filter_map(|call| function_at(&info.functions, call.target?))
            .filter(|function| function.name == name)
            .map(|function| function.address);
        let first = targets.next()?;
        // A text-only decompiler response cannot disambiguate same-name callees.
        if targets.any(|address| address != first) {
            return None;
        }
        Some(first)
    }

    fn side_panel(&mut self, ui: &mut egui::Ui) {
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
            if self.saved_analysis {
                ui.weak("Saved analysis").on_hover_text("Cached results from this project. Refresh to recompute with the analysis engine.");
            }
        });
        if let Some(view) = &self.view {
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
                    self.annotations_open = true;
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
        let mut scroll = ScrollArea::both()
            .id_salt("decompiler-text")
            .auto_shrink([false, false]);
        if let Some(target) = self.pending_code_scroll.take() {
            scroll = scroll.vertical_scroll_offset(target as f32 * row);
        }
        scroll.show_rows(ui, row, self.decompiled_lines.len(), |ui, rows| {
            for index in rows {
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
                if response.hovered()
                    && let Some(pointer) = context.pointer_hover_pos()
                {
                    let cursor = galley.cursor_from_pos(pointer - response.rect.min);
                    let byte = line[..visible]
                        .char_indices()
                        .nth(cursor.index.0)
                        .map_or(visible, |(at, _)| at);
                    if byte < visible && response.clicked() {
                        select_code = Some(start + byte);
                    }
                    if byte < visible
                        && let Some(name) =
                            highlighted.function_name_at(&self.decompiled, start + byte)
                        && let Some(target) = self.decompiler_call_target(name)
                    {
                        let clicked = response.double_clicked();
                        response
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .on_hover_text(format!("Double-click to go to {name} ({target:#x})"));
                        if clicked {
                            navigate = Some(target);
                        }
                    }
                }
            }
        });
        if let Some(target) = navigate {
            self.navigate(target, true, &context);
        } else if let Some(byte) = select_code {
            self.select_decompiled_byte(byte);
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
        let comment = ui.add(
            TextEdit::multiline(&mut self.comment_edit)
                .hint_text("Comment at selected address")
                .desired_rows(3)
                .char_limit(16 * 1024),
        );
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
            self.edit_annotation(address, annotation);
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
            "{} direct accesses · {} p-code operations charged · {} access candidates",
            data.references.len(),
            data.operations_charged,
            data.accesses_examined
        ));
        ui.weak("Direct memory reads/writes in examined functions. AArch64 register constants are propagated only within a basic block; address-only values and loaded pointers are outside this pass. Recomputed after project reopen.");
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
            "Computed this session · {} functions examined · {} decode attempts",
            report.functions_examined, report.decode_attempts
        ));
        ui.weak("Confirmed direct calls in examined functions. Unknown indirect targets remain unresolved. References are recomputed after reopening a project.");
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
                                            .button(format!("{:x} → {:x}", call.address, target))
                                            .clicked()
                                        {
                                            navigate = Some(target);
                                        }
                                    } else {
                                        ui.weak(format!("{:x} → unresolved", call.address));
                                    }
                                }
                            });
                        });
                    }
                    if let Some(canvas) = &mut self.canvas
                        && let Some(action) =
                            canvas.show_selected(ui, view, self.selected, &self.semantic.addresses)
                    {
                        match action {
                            GraphAction::Select(address) => self.select_instruction(address),
                            GraphAction::Navigate(target) => navigate = Some(target),
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
                    scroll = scroll.vertical_scroll_offset(target as f32 * row);
                }
                scroll.show_rows(ui, row, self.listing.len(), |ui, rows| {
                    for index in rows {
                        let instruction = &self.listing[index];
                        let response = ui.add(
                            egui::Button::selectable(
                                self.selected == Some(instruction.address)
                                    || self.semantic.addresses.contains(&instruction.address),
                                theme::listing_row(
                                    instruction.address,
                                    &hex(&instruction.bytes),
                                    &instruction.mnemonic,
                                    &instruction.operands,
                                ),
                            )
                            .wrap_mode(egui::TextWrapMode::Extend),
                        );
                        let response = if let Some(note) = self
                            .session
                            .as_ref()
                            .and_then(|session| session.annotations.get(&instruction.address))
                        {
                            response.on_hover_text(format!("{}\n{}", note.label, note.comment))
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
                    self.select_instruction(address);
                    self.annotations_open = true;
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
                                Request::Decompile { .. } => "Decompiling",
                                Request::Discover => "Discovering functions",
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
                if self.selected.is_none() {
                    ui.weak("Select an address to add a name or comment.");
                } else {
                    self.annotation_editor(ui);
                }
            });
        self.annotations_open = annotations_open;
        self.unsaved_window(&context);
        self.file_dialogs.show(&context);
        self.browser_dialog(&context);
        self.handle_shortcuts(&context);
        crate::window_chrome::resize_borders(ui);
    }
}

impl eframe::App for DesktopApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.draw(ui);
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

fn is_project_path(path: &std::path::Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("grproj"))
}

fn edit_size(edit: &Edit) -> usize {
    edit.function_name.as_ref().map_or(0, String::len)
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
    fn decompiler_navigation_requires_a_known_unambiguous_called_function() {
        let mut app = call_navigation_app("next()");
        assert_eq!(app.decompiler_call_target("next"), Some(0x1040));
        assert_eq!(app.decompiler_call_target("entry"), None);
        assert_eq!(app.decompiler_call_target("missing"), None);
        app.info.as_mut().unwrap().functions.push(FunctionInfo {
            address: 0x1080,
            name: "next".into(),
        });
        app.view.as_mut().unwrap().calls.push(CallSite {
            address: 0x1008,
            target: Some(0x1080),
        });
        assert_eq!(app.decompiler_call_target("next"), None);
        app.view.as_mut().unwrap().calls.clear();
        assert_eq!(app.decompiler_call_target("next"), None);
    }

    #[test]
    fn double_clicking_decompiler_call_text_navigates_and_records_history() {
        let context = egui::Context::default();
        theme::install(&context);
        let source = "void entry() { next(); }";
        let mut app = call_navigation_app(source);
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
                ..Default::default()
            },
        );
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
            decompiled: Some("int restored_entry() { return 7; }\n".into()),
            mappings: Vec::new(),
            strings: vec![StringEntry {
                address: 0x1040,
                text: "saved string".into(),
                encoding: "ASCII".into(),
            }],
            strings_truncated: true,
            crypto: vec![],
            crypto_truncated: false,
            selected_address: Some(0x1000),
        };
        let project_path = directory.path().join("analysis.grproj");
        data.save(&project_path, &protection, true).unwrap();
        let project = ProjectData::load(&project_path).unwrap();
        let extracted = project.binary.as_ref().unwrap().path().to_owned();
        app.session = Some(session);
        app.restore_project(
            ProjectOpen {
                project,
                project_path: project_path.clone(),
                binary_path: extracted.clone(),
            },
            &egui::Context::default(),
        );
        assert_eq!(app.project_path, Some(project_path));
        assert!(app.saved_analysis);
        assert!(app.highlighted.is_some());
        assert!(app.decompiled.contains("restored_entry"));
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
