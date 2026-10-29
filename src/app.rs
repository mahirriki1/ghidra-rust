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
use crate::function_presentation::{
    DecompilationError, Listing, PreparedDecompilation, PreparedGraph,
};
use crate::function_results::{FunctionResults, ResultBinding};
use crate::graph::{GraphAction, GraphCanvas};
use crate::hex_ui::{HexAction, HexPanel};
use crate::model::*;
use crate::project::{EmbeddedBinary, LoadedProject, ProjectData};
use crate::result_store::{ResultOrigin, Shared};
use crate::search::SearchState;
use crate::search_jobs::{
    Capture, CaptureInput, Destination, MemoryMode, MemorySearch, SearchKind, SearchView, Searches,
    SourceEpochs, TextPhase, TextSearch,
};
use crate::search_ui::{DialogKind, DialogResult, ResultAction, SearchDialog, SearchForm, Submit};
use crate::selection::SemanticSelection;
use crate::semantic::{LocalIdentity, LocalRename, SemanticInfo, TokenKind};
use crate::session::{Annotation, BinaryProtection, Session};
use crate::signature_ui::{DraftParameter, SignatureAction, SignatureEditor};
use crate::signatures::{self, FunctionSignature};
use crate::theme;
use crate::xrefs::{
    AccessFilter, CallDirection, CallRow, DataRow, TargetKind, TargetSet, XrefTarget,
};

const DEADLINE: Duration = Duration::from_secs(30);
/// Consecutive automatic discovery resumes after unrelated worker failures.
const MAX_DISCOVERY_RESUMES: u8 = 3;
/// Decompiler line pitch: denser than table rows, like a code editor.
const CODE_ROW_HEIGHT: f32 = 18.0;
const HISTORY_LIMIT: usize = 32;
const UNDO_BYTES: usize = 4 * 1024 * 1024;
/// Per-frame work for the function filter, keeping typing responsive.
const FILTER_FRAME_BUDGET: Duration = Duration::from_millis(4);

mod listing_cursor;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Tab {
    Graph,
    #[default]
    Listing,
    Strings,
    Crypto,
    Decode,
    Hex,
    References,
    /// Results of the current memory or program-text search.
    Search,
}

/// The list shown in the left Functions dock; session-only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum FunctionDock {
    #[default]
    Functions,
    Imports,
    Exports,
}

const FUNCTION_DOCK_TABS: [(FunctionDock, &str); 3] = [
    (FunctionDock::Functions, "Functions"),
    (FunctionDock::Imports, "Imports"),
    (FunctionDock::Exports, "Exports"),
];

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
    Help,
    Rename,
    GoTo,
    Comment,
    ToggleGraph,
    Back,
    Forward,
    Save,
    Undo,
    Xrefs,
    SearchMemory,
    SearchText,
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
            egui::Key::F1 => Some(Shortcut::Help),
            egui::Key::L => Some(Shortcut::Rename),
            egui::Key::G => Some(Shortcut::GoTo),
            egui::Key::Semicolon => Some(Shortcut::Comment),
            egui::Key::Space => Some(Shortcut::ToggleGraph),
            egui::Key::X => Some(Shortcut::Xrefs),
            egui::Key::S => Some(Shortcut::SearchMemory),
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
            egui::Key::F => Some(Shortcut::SearchText),
            _ => None,
        };
    }
    None
}

/// Where a binary opens: `main`, else its entry point, else its lowest known
/// function, each only when it is file-backed executable code. A shared
/// library's zero entry is not a location, so it may have none.
fn start_address(info: &BinaryInfo) -> Option<u64> {
    let code = |address: &u64| crate::call_analysis::code_address(info, *address);
    info.functions
        .iter()
        .find(|function| function.name == "main")
        .map(|function| function.address)
        .filter(code)
        .or(Some(info.entry).filter(code))
        .or_else(|| {
            info.functions
                .iter()
                .map(|function| function.address)
                .filter(code)
                .min()
        })
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
/// The next function-name synchronization from `addresses`, packed by encoded
/// size so typical names need few worker round trips. Addresses no longer in
/// the inventory are skipped.
fn next_sync_batch(addresses: &mut VecDeque<u64>, functions: &[FunctionInfo]) -> Vec<FunctionInfo> {
    let mut batch = Vec::new();
    let mut bytes = 0;
    while let Some(&address) = addresses.front() {
        if let Some(function) = function_at(functions, address) {
            let name = inventory_name(&function.name);
            let size = crate::model::sync_entry_bytes(name);
            if batch.len() == MAX_DISCOVERY_SYNC_FUNCTIONS
                || (!batch.is_empty() && bytes + size > crate::model::MAX_SYNC_FUNCTION_BYTES)
            {
                break;
            }
            bytes += size;
            batch.push(FunctionInfo {
                address,
                name: name.to_owned(),
            });
        }
        addresses.pop_front();
    }
    batch
}

/// Whether discovery may continue after `request` failed. Reopening, its own
/// name synchronization and signature replay are not retried, and legacy full
/// discovery has no batches.
fn resumes_discovery(request: &Request) -> bool {
    !matches!(
        request,
        Request::Open { .. }
            | Request::SyncFunctions { .. }
            | Request::SyncSignatures { .. }
            | Request::Discover
    )
}

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

static NO_SEMANTICS: SemanticInfo = SemanticInfo {
    prototype: None,
    tokens: Vec::new(),
    locals: Vec::new(),
    warnings: Vec::new(),
};

// Field-level accessors keep the displayed results borrowable alongside
// mutable access to other desktop fields.
fn graph_view(graph: &Option<Shared<PreparedGraph>>) -> Option<&FunctionView> {
    graph.as_deref().map(|graph| graph.view())
}

fn listing_of(graph: &Option<Shared<PreparedGraph>>) -> Listing<'_> {
    graph
        .as_deref()
        .map_or(Listing::empty(), |graph| graph.listing())
}

fn code_text(code: &Option<Shared<PreparedDecompilation>>) -> &str {
    code.as_deref().map_or("", |code| code.text())
}

fn code_lines(code: &Option<Shared<PreparedDecompilation>>) -> &[(usize, usize)] {
    code.as_deref().map_or(&[], |code| code.lines())
}

fn semantics_of(code: &Option<Shared<PreparedDecompilation>>) -> &SemanticInfo {
    code.as_deref()
        .map_or(&NO_SEMANTICS, |code| code.semantics())
}

/// Bytes Decode reads at a taken address, which has no access width.
const ADDRESS_DECODE_BYTES: u32 = 64;

/// Explicit target choices for one selection, bound to the state they came from.
struct XrefChoices {
    key: XrefKey,
    set: TargetSet,
}

/// Generation, selection, annotation revision and reference-evidence revision.
type XrefKey = (u64, u64, u64, u64);

/// Filtered References rows, recomputed only when an input changes.
#[derive(Clone, PartialEq)]
struct ReferenceRowsKey {
    generation: u64,
    references: u64,
    revision: u64,
    names: u64,
    data: bool,
    scope: Option<u64>,
    explicit: bool,
    direction: CallDirection,
    access: AccessFilter,
    filter: String,
}

struct ReferenceRows {
    key: ReferenceRowsKey,
    calls: Vec<CallRow>,
    data: Vec<DataRow>,
}

/// Decompiler context captured by the opening secondary click.
#[derive(Clone)]
struct DecompilerMenu {
    key: XrefKey,
    local: Option<crate::semantic::SemanticToken>,
    targets: TargetSet,
}

struct DiscoveryPublication {
    /// Display inventory when the batch changed it.
    functions: Option<Vec<FunctionInfo>>,
    inventory: crate::discovery::WorkerInventory,
    truncated: bool,
    index: Arc<crate::call_analysis::CallIndex>,
}

struct DiscoveryUpdate {
    generation: u64,
    state: crate::discovery::Discovery,
    /// Committed results for project saves, built off the GUI thread.
    saved: Arc<DiscoverySnapshot>,
    publication: Result<Option<DiscoveryPublication>, String>,
}

/// Byte reads have an explicit consumer; the active tab is only an optional
/// Decode focus hint, never a destination selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ByteDestination {
    Decode,
    HexPage { token: u64 },
}

#[derive(Clone, Copy)]
struct ByteBinding {
    generation: u64,
    intent: u64,
    destination: ByteDestination,
}

struct Pending {
    id: u64,
    request: Request,
    started: Instant,
    selection: u64,
    revision: u64,
    byte_origin: (Option<u64>, Tab),
    bytes: Option<ByteBinding>,
    /// Store identity captured when a function request was sent.
    result: Option<ResultBinding>,
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
    bytes: Option<ByteBinding>,
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
    started: Instant,
    steps: VecDeque<AnalysisStep>,
    current: Option<AnalysisStep>,
    total: usize,
}

/// Transient presentation survives while background adoption owns `Discovery`.
/// It is never loaded from projects or recreated by a late reply after Cancel.
#[derive(Clone, Copy)]
struct DiscoveryActivity {
    generation: u64,
    started: Instant,
    known: Option<crate::discovery::FunctionProgress>,
    scanning: bool,
}

#[derive(Debug)]
struct RunPresentation {
    phase: &'static str,
    elapsed: Duration,
    step: Option<(usize, usize)>,
    progress: theme::BarProgress,
    known: Option<crate::discovery::FunctionProgress>,
    foreground: Option<&'static str>,
}

impl RunPresentation {
    fn label(&self) -> String {
        let mut label = self.phase.to_owned();
        if let theme::BarProgress::KnownFunctions { processed, total } = self.progress {
            label.push_str(&format!(" {processed}/{total}"));
        }
        if let Some((current, total)) = self.step {
            label.push_str(&format!(" · step {current}/{total}"));
        }
        label.push_str(&format!(" · {:.1}s", self.elapsed.as_secs_f32()));
        label
    }
}

/// Pages of one worker's symbol-name table, bound to the binary generation and
/// worker epoch that announced it.
struct SymbolFetch {
    generation: u64,
    epoch: u64,
    pages: crate::symbol_names::SymbolNameFetch,
}

/// Shown name for an exact inventory entry, and its original symbol when that
/// differs. A non-empty analyst label wins, then the worker's display name,
/// then the effective inventory name. Text never becomes an identity.
fn function_display<'a>(
    session: Option<&'a Session>,
    symbols: Option<&'a crate::symbol_names::SymbolNames>,
    function: &'a FunctionInfo,
) -> (&'a str, Option<&'a str>) {
    let record = symbols.and_then(|symbols| symbols.get(function.address));
    let shown = session
        .and_then(|session| session.annotations.get(&function.address))
        .map(|annotation| annotation.label.as_str())
        .filter(|label| !label.is_empty())
        .or_else(|| record.and_then(|record| record.display.as_deref()))
        .unwrap_or(&function.name);
    (
        shown,
        record
            .map(|record| record.raw.as_str())
            .filter(|raw| *raw != shown),
    )
}

fn request_task(request: &Request) -> &'static str {
    match request {
        Request::Open { .. } => "Opening binary",
        Request::Graph { .. } => "Building graph",
        Request::Decompile { .. } | Request::DecompileWithLocals { .. } => "Decompiling",
        Request::Discover | Request::DiscoverBatch { .. } => "Discovering functions",
        Request::SyncFunctions { .. } => "Restoring function context",
        Request::SyncSignatures { .. } => "Applying function signatures",
        Request::Rename { .. } => "Renaming function",
        Request::Bytes { .. } => "Reading bytes",
        Request::Strings | Request::StringsWithOptions { .. } => "Finding strings",
        Request::Crypto => "Scanning constants",
        Request::SymbolNames { .. } => "Reading symbol names",
        Request::Linkage { .. } => "Reading imports and exports",
        Request::SearchMemory { .. } => "Searching memory",
    }
}

#[derive(Clone)]
enum Intent {
    OpenDialog,
    OpenProjectDialog,
    OpenProjectPath(PathBuf),
    OpenPath(PathBuf),
    Close,
    Quit,
    InstallUpdate,
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
        result_revision: u64,
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
    discovery_index: Option<Arc<crate::call_analysis::CallIndex>>,
}

#[derive(Clone)]
struct Edit {
    address: u64,
    before: Option<Annotation>,
    function_name: Option<String>,
    local: Option<(LocalIdentity, Option<LocalRename>)>,
    signature: Option<(u64, Option<FunctionSignature>)>,
}

struct SignatureReplay {
    signatures: Vec<FunctionSignature>,
    context: String,
    generation: u64,
    revision: u64,
    epoch: u64,
    sent: bool,
}

struct SignatureChange {
    function: u64,
    before: Option<FunctionSignature>,
    signatures: Vec<FunctionSignature>,
    generation: u64,
    revision: u64,
    selection: u64,
    epoch: u64,
    undone: Option<Edit>,
}

pub struct DesktopApp {
    client: Option<WorkerClient>,
    pending: Option<Pending>,
    opening: Option<Opening>,
    queue: VecDeque<Request>,
    applied_names: BTreeMap<u64, String>,
    reset_names: std::collections::BTreeSet<u64>,
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
    result_revision: u64,
    saved_result_revision: u64,
    result_scope: Option<u64>,
    undo: VecDeque<Edit>,
    /// Retained per-function results; the displayed ones are shared, not copied.
    results: FunctionResults,
    graph: Option<Shared<PreparedGraph>>,
    code: Option<Shared<PreparedDecompilation>>,
    call_index: Option<Arc<crate::call_analysis::CallIndex>>,
    deferred_discovery: Option<DiscoveryUpdate>,
    deferred_restore: Option<Box<ProjectOpen>>,
    discovery: Option<crate::discovery::Discovery>,
    discovery_job: Option<Receiver<DiscoveryUpdate>>,
    discovery_running: bool,
    discovery_activity: Option<DiscoveryActivity>,
    discovery_summary: Option<String>,
    worker_epoch: u64,
    /// Validated symbol names for the binary generation they belong to.
    symbol_names: Option<(u64, Arc<crate::symbol_names::SymbolNames>)>,
    symbol_fetch: Option<SymbolFetch>,
    /// A table digest that failed validation for a generation is not retried.
    symbol_failed: Option<(u64, String)>,
    /// Advances when displayed function names change without an annotation edit.
    symbol_revision: u64,
    /// Imports and exports of the displayed binary generation.
    linkage: crate::linkage_ui::LinkageTree,
    /// The selected linkage row is the X target until the selection moves.
    linkage_focus: bool,
    /// The inventory last adopted from the current worker. Batch requests name
    /// its revision while `inventory_synced` records that `info.functions` is
    /// still that inventory; every other inventory write clears it.
    worker_inventory: Option<crate::discovery::WorkerInventory>,
    inventory_synced: bool,
    discovery_sync: Option<VecDeque<u64>>,
    /// One replaceable byte action, independent of the bounded function queue.
    discovery_bytes: Option<(Request, RequestOrigin)>,
    byte_intent: u64,
    /// What a project save stores: the latest committed session results, or
    /// the restored project's snapshot until discovery runs again.
    discovery_saved: Option<Arc<DiscoverySnapshot>>,
    /// References and summary came from a project rather than this session.
    saved_references: bool,
    analysis_options: AnalysisOptions,
    analyze_prompt: Option<AnalyzePrompt>,
    analysis_plan: Option<AnalysisPlan>,
    reference_data: bool,
    /// Explicitly inspected address; `None` follows the displayed function.
    xref_target: Option<XrefTarget>,
    reference_query: String,
    reference_filter: String,
    reference_direction: CallDirection,
    reference_access: AccessFilter,
    reference_rows: Option<ReferenceRows>,
    /// Advances whenever `call_index` changes, invalidating captured targets.
    reference_revision: u64,
    xref_choices: Option<XrefChoices>,
    /// Direct target of a decompiler call token chosen by the user.
    selected_call: Option<u64>,
    /// Generation and exact start of the string row chosen for X.
    string_focus: Option<(u64, u64)>,
    analysis_progress: Option<AnalysisProgress>,
    progress_events: usize,
    reference_focus: Option<(u64, u64)>,
    undisplayed_call: Option<u64>,
    canvas: Option<GraphCanvas>,
    saved_analysis: bool,
    cached_graph: bool,
    cached_functions: bool,
    cached_strings: bool,
    cached_crypto: bool,
    semantic: SemanticSelection,
    selected_local: Option<usize>,
    decompiler_rename_context: bool,
    pending_code_scroll: Option<usize>,
    pending_comment_scroll: Option<u64>,
    pending_listing_scroll: Option<usize>,
    listing_cursor: listing_cursor::ListingCursor,
    /// Automatic discovery resumes since the last committed batch.
    discovery_resumes: u8,
    /// Widest decompiler display row, in monospace characters.
    code_chars: usize,
    auto_decompile: bool,
    selected: Option<u64>,
    history: Vec<crate::linkage_ui::Place>,
    data_location: Option<(u64, u64)>,
    code_selection: Option<u64>,
    history_index: usize,
    function_filter: String,
    function_dock: FunctionDock,
    /// Flat Imports and Exports filters, indexed by `linkage_ui::Table`.
    linkage_filters: [String; 2],
    filtered_functions: Vec<usize>,
    /// Lowercased effective labels, aligned with `info.functions` and valid for
    /// `filter_keys_revision`.
    filter_keys: Vec<String>,
    filter_keys_revision: (u64, u64),
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
    comment_rows_key: Option<(u64, u64, u64, u64)>,
    /// Only exact PCs observed in a recovered CFG or genuine print mapping.
    comment_owners: BTreeMap<u64, u64>,
    editor_address: Option<u64>,
    decoder: DecoderPanel,
    hex: HexPanel,
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
    help_dialog: Option<crate::help::HelpDialog>,
    updater: crate::update_ui::UpdatePanel,
    restart: crate::updater::RestartSlot,
    focus_comment: bool,
    signature_editor: Option<SignatureEditor>,
    signature_replay: Option<SignatureReplay>,
    signature_change: Option<SignatureChange>,
    signature_unapplied: Vec<SignatureStatus>,
    signature_error: Option<String>,
    signature_restore_pc: Option<(u64, u64)>,
    signature_recovery: Option<u64>,
    /// Transient memory/program-text search; never saved in projects.
    searches: Searches,
    search_form: SearchForm,
    search_dialog: Option<SearchDialog>,
    /// Revisions of the mutable text sources a program-text search captures.
    source_epochs: SourceEpochs,
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
            reset_names: std::collections::BTreeSet::new(),
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
            result_revision: 0,
            saved_result_revision: 0,
            result_scope: None,
            undo: VecDeque::new(),
            results: FunctionResults::default(),
            graph: None,
            code: None,
            call_index: None,
            deferred_discovery: None,
            deferred_restore: None,
            discovery: None,
            discovery_job: None,
            discovery_running: false,
            discovery_activity: None,
            discovery_summary: None,
            worker_epoch: 0,
            symbol_names: None,
            symbol_fetch: None,
            symbol_failed: None,
            symbol_revision: 0,
            linkage: crate::linkage_ui::LinkageTree::default(),
            linkage_focus: false,
            worker_inventory: None,
            inventory_synced: false,
            discovery_sync: None,
            discovery_bytes: None,
            byte_intent: 0,
            discovery_saved: None,
            saved_references: false,
            analysis_options: AnalysisOptions::default(),
            analyze_prompt: None,
            analysis_plan: None,
            reference_data: false,
            xref_target: None,
            reference_query: String::new(),
            reference_filter: String::new(),
            reference_direction: CallDirection::All,
            reference_access: AccessFilter::All,
            reference_rows: None,
            reference_revision: 0,
            xref_choices: None,
            selected_call: None,
            string_focus: None,
            analysis_progress: None,
            progress_events: 0,
            reference_focus: None,
            undisplayed_call: None,
            canvas: None,
            saved_analysis: false,
            cached_graph: false,
            cached_functions: false,
            cached_strings: false,
            cached_crypto: false,
            semantic: SemanticSelection::default(),
            selected_local: None,
            decompiler_rename_context: false,
            pending_code_scroll: None,
            pending_comment_scroll: None,
            pending_listing_scroll: None,
            listing_cursor: Default::default(),
            discovery_resumes: 0,
            code_chars: 0,
            auto_decompile: true,
            selected: None,
            history: Vec::new(),
            data_location: None,
            code_selection: None,
            history_index: 0,
            function_filter: String::new(),
            function_dock: FunctionDock::Functions,
            linkage_filters: [String::new(), String::new()],
            filtered_functions: Vec::new(),
            filter_keys: Vec::new(),
            filter_keys_revision: (0, 0),
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
            hex: HexPanel::default(),
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
            help_dialog: None,
            updater: crate::update_ui::UpdatePanel::default(),
            restart: crate::updater::RestartSlot::default(),
            focus_comment: false,
            signature_editor: None,
            signature_replay: None,
            signature_change: None,
            signature_unapplied: Vec::new(),
            signature_error: None,
            signature_restore_pc: None,
            signature_recovery: None,
            searches: Searches::default(),
            search_form: SearchForm::default(),
            search_dialog: None,
            source_epochs: SourceEpochs::default(),
        }
    }

    fn dirty(&self) -> bool {
        self.revision != self.saved_revision
            || (self.project_path.is_some() && self.result_revision != self.saved_result_revision)
    }

    pub fn with_restart(mut self, restart: crate::updater::RestartSlot) -> Self {
        self.restart = restart;
        self
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
            Intent::InstallUpdate => self.install_update(context),
            Intent::LoadAnnotations => self.load_annotations(context),
        }
    }

    fn install_update(&mut self, context: &egui::Context) {
        let Some(prepared) = self.updater.ready() else {
            return;
        };
        if self.file_job.is_some()
            || self.opening.is_some()
            || self.signature_change.is_some()
            || self.signature_replay.is_some()
        {
            self.status =
                "Wait for the current file or signature operation before installing the update"
                    .into();
            self.updater.open = true;
            return;
        }
        let protections = self.binary_protection.iter().cloned().collect();
        let worker = self.client.take();
        self.stop_worker();
        self.updater.install(crate::updater::install_job(
            context,
            prepared,
            protections,
            worker,
        ));
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
        self.result_revision = 0;
        self.saved_result_revision = 0;
        self.undo.clear();
        self.clear_views();
        self.status = "Binary closed".into();
    }

    fn clear_views(&mut self) {
        self.signature_editor = None;
        self.signature_error = None;
        self.signature_unapplied.clear();
        self.signature_restore_pc = None;
        self.signature_recovery = None;
        self.worker_inventory = None;
        self.inventory_synced = false;
        self.discovery_activity = None;
        self.discovery = None;
        self.discovery_job = None;
        self.deferred_discovery = None;
        self.deferred_restore = None;
        self.discovery_running = false;
        self.discovery_summary = None;
        self.discovery_sync = None;
        self.discovery_bytes = None;
        self.discovery_saved = None;
        self.saved_references = false;
        self.analyze_prompt = None;
        self.analysis_plan = None;
        self.set_call_index(None);
        self.reference_data = false;
        self.xref_target = None;
        self.reference_query.clear();
        self.reference_filter.clear();
        self.reference_direction = CallDirection::All;
        self.reference_access = AccessFilter::All;
        self.xref_choices = None;
        self.selected_call = None;
        self.string_focus = None;
        self.reference_focus = None;
        self.undisplayed_call = None;
        self.linkage.reset();
        self.linkage_focus = false;
        self.results.set_linkage_bytes(0);
        self.browser_dialog = None;
        self.focus_comment = false;
        self.reset_names.clear();
        self.result_scope = None;
        self.results.close();
        self.graph = None;
        self.canvas = None;
        self.code = None;
        self.semantic.clear();
        self.comment_rows_key = None;
        self.selected_local = None;
        self.decompiler_rename_context = false;
        self.pending_code_scroll = None;
        self.pending_comment_scroll = None;
        self.pending_listing_scroll = None;
        self.listing_cursor = Default::default();
        self.saved_analysis = false;
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
        self.data_location = None;
        self.code_selection = None;
        self.comment_owners.clear();
        self.annotation_browser = AnnotationBrowser::default();
        self.history_index = 0;
        self.filtered_functions.clear();
        self.filter_keys.clear();
        self.filter_cursor = None;
        self.decoder = DecoderPanel::default();
        self.hex = HexPanel::default();
        self.searches.clear();
        self.search_form = SearchForm::default();
        self.search_dialog = None;
        self.source_epochs.bump_inventory();
        self.source_epochs.bump_linkage();
        self.source_epochs.bump_strings();
        if self.tab == Tab::Search {
            self.tab = Tab::Listing;
        }
        self.advance_byte_intent();
    }

    /// Stop the worker after its current request failed. Discovery that the
    /// failure did not belong to continues on a fresh worker; interrupted
    /// batches retry within their own limits, and consecutive automatic resumes
    /// without a committed batch are bounded.
    fn stop_after_failure(&mut self, resumable: bool, context: &egui::Context) {
        let resume = resumable
            && self.discovery_running
            && self.signature_change.is_none()
            && self.discovery_resumes < MAX_DISCOVERY_RESUMES;
        if resume && let Some(path) = self.binary_path.clone() {
            self.stop_worker_transport();
            self.discovery_resumes += 1;
            self.start_open(path, true, None, context);
            self.discovery_running = self.client.is_some();
            self.update_discovery_summary();
        } else {
            self.stop_worker();
        }
    }

    fn stop_worker(&mut self) {
        self.discovery_activity = None;
        self.analysis_plan = None;
        self.stop_worker_transport();
        // Without a worker, an unfinished memory search cannot continue. Its
        // committed hits remain; an explicit Cancel marks it Canceled first.
        self.end_memory_search(SearchState::Unavailable);
    }

    /// Recovery preserves the logical run, but keeps the existing byte-intent
    /// cancellation and worker interruption accounting.
    fn stop_worker_transport(&mut self) {
        if self.hex.is_loading() {
            self.hex
                .cancel("Analysis stopped. Retry to read this page.");
        }
        self.advance_byte_intent();
        self.stop_worker_inner();
    }

    /// Restarting to verify a retained snapshot may carry a deferred byte origin over
    /// the disposable worker boundary. Explicit stops use `stop_worker` above.
    fn stop_worker_inner(&mut self) {
        self.signature_replay = None;
        if let Some(change) = self.signature_change.take() {
            self.signature_recovery = Some(
                self.signature_restore_pc
                    .map_or(change.function, |(function, _)| function),
            );
            if let Some(edit) = change.undone {
                self.undo.push_back(edit);
            }
            self.signature_error = Some("Signature change was not committed; the worker stopped. The saved signature state is unchanged.".into());
        }
        crate::performance::event("worker_stop_epoch", self.worker_epoch);
        if self.discovery_running {
            crate::performance::event("discovery_action_interrupted", self.generation);
        }
        self.discovery_running = false;
        self.discovery_sync = None;
        self.discovery_bytes = None;
        self.worker_inventory = None;
        self.inventory_synced = false;
        // A memory page lost with this worker resumes from the committed
        // cursor only after a replacement verifies the same image.
        if let Some(Pending {
            request: Request::SearchMemory { binding, .. },
            ..
        }) = &self.pending
            && let Some(memory) = self.searches.memory(binding.search_id)
        {
            memory.interrupted = true;
        }
        // Pages of an unfinished table never outlive the worker they came from.
        self.linkage.interrupt();
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
        self.start_open_at(path, preserve, follow, follow_origin, context);
    }

    fn start_open_at(
        &mut self,
        path: PathBuf,
        preserve: bool,
        follow: Option<Request>,
        follow_origin: RequestOrigin,
        context: &egui::Context,
    ) {
        let bytes = preserve.then(|| self.discovery_bytes.take()).flatten();
        // Only carry remaining queued work when dispatch itself needs to
        // recreate an absent worker. Navigation that preempts a live request
        // retains its existing behavior of discarding the old function queue.
        let queued = (preserve && self.client.is_none() && self.pending.is_none())
            .then(|| std::mem::take(&mut self.queue));
        if preserve {
            // A pending page interrupted by function navigation needs an
            // explicit Retry; a newer deferred page survives the restart.
            if bytes.is_none()
                && !matches!(follow, Some(Request::Bytes { .. }))
                && self.hex.is_loading()
            {
                self.hex
                    .cancel("Read interrupted. Retry to read this page.");
            }
            self.stop_worker_inner();
        } else {
            self.stop_worker();
        }
        self.discovery_bytes = bytes;
        if let Some(queued) = queued {
            self.queue = queued;
        }
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
            Err(error) => {
                self.stop_worker();
                self.status = error;
            }
        }
    }

    fn send_direct(&mut self, request: Request) {
        let origin = self.request_origin();
        self.send_direct_at(request, origin);
    }

    fn send_direct_at(&mut self, request: Request, origin: RequestOrigin) {
        self.analysis_progress = None;
        self.progress_events = 0;
        // Results computed while a signature state is staged or awaiting
        // acknowledgement are never stored under the committed context.
        let result = match &request {
            Request::Graph { address } | Request::Decompile { address }
                if self.signature_change.is_none() && self.signature_replay.is_none() =>
            {
                self.results
                    .binding(*address, self.local_override_state(*address))
            }
            _ => None,
        };
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
                    selection: origin.selection,
                    revision: origin.revision,
                    byte_origin: origin.byte_origin,
                    bytes: origin.bytes,
                    result,
                });
            }
            Err(error) => {
                self.stop_worker();
                self.status = error;
            }
        }
    }

    /// The exact local-name override records the engine receives for `function`.
    fn local_override_state(&self, function: u64) -> String {
        self.results.local_state(function)
    }

    fn update_result_inputs(&mut self, reason: crate::function_results::Invalidation) {
        self.results.inputs_changed(reason);
        let Some(info) = &self.info else {
            return;
        };
        let mut functions = info.functions.clone();
        let locals = self
            .session
            .as_ref()
            .map_or_else(Vec::new, |s| s.local_renames.clone());
        if let Some(session) = &self.session {
            for function in &mut functions {
                if let Some(annotation) = session.annotations.get(&function.address)
                    && !annotation.label.is_empty()
                {
                    function.name.clone_from(&annotation.label);
                }
            }
        }
        self.results.update_inputs(functions, locals);
    }

    fn request(&mut self, request: Request, context: &egui::Context) {
        if matches!(request, Request::Discover)
            && self
                .info
                .as_ref()
                .is_some_and(|info| !crate::packing::has_upx_warning(info))
            && !self
                .opening
                .as_ref()
                .is_some_and(|opening| !opening.preserve)
        {
            self.begin_discovery_activity(Instant::now());
        }
        if let Request::Bytes { address, length } = request {
            self.request_bytes(address, length, ByteDestination::Decode, context);
            return;
        }
        if self.opening.is_some() {
            // The new client must first prove it opened the intended binary.
            let origin = self.request_origin();
            if let Some(opening) = &mut self.opening {
                if matches!(opening.follow, Some(Request::Bytes { .. }))
                    && self.discovery_bytes.is_none()
                {
                    self.discovery_bytes = opening
                        .follow
                        .take()
                        .map(|read| (read, opening.follow_origin));
                }
                opening.follow = Some(request);
                opening.follow_origin = origin;
            }
            return;
        }
        if self.signature_replay.is_some() || self.results.preparing() {
            if self.queue.len() < HISTORY_LIMIT {
                self.queue.push_back(request);
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
                    Request::DiscoverBatch { .. }
                        | Request::SyncFunctions { .. }
                        | Request::SymbolNames { .. }
                        | Request::Linkage { .. }
                        | Request::SearchMemory { .. }
                )
            })
        {
            // Interactive work runs between bounded batches. Keep only the
            // newest navigation requests, and bound queued user actions.
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
                self.update_discovery_summary();
            }
        } else {
            self.schedule_request(request);
        }
    }

    fn schedule_request(&mut self, request: Request) {
        if self.signature_replay.is_some() || self.results.preparing() {
            if self.queue.len() < HISTORY_LIMIT {
                self.queue.push_back(request);
            }
            return;
        }
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
            bytes: None,
        }
    }

    fn advance_byte_intent(&mut self) {
        self.byte_intent = self
            .byte_intent
            .checked_add(1)
            .expect("byte intent exhausted");
        self.discovery_bytes = None;
    }

    fn request_bytes(
        &mut self,
        address: u64,
        length: usize,
        destination: ByteDestination,
        context: &egui::Context,
    ) {
        self.advance_byte_intent();
        if destination == ByteDestination::Decode && self.hex.is_loading() {
            self.hex
                .cancel("Another byte action replaced this read. Retry to load this page.");
        }
        let mut origin = self.request_origin();
        origin.bytes = Some(ByteBinding {
            generation: self.generation,
            intent: self.byte_intent,
            destination,
        });
        let request = Request::Bytes { address, length };
        if length == 0 || length > MAX_BYTE_READ || address.checked_add(length as u64).is_none() {
            self.fail_byte_request(
                &request,
                origin,
                "Invalid byte read range; choose a bounded range.",
            );
            return;
        }
        if !self.byte_request_current(&request, origin) {
            self.retire_byte_request(&request, origin);
            return;
        }
        // Never preempt an in-flight worker or snapshot adoption for a page.
        // Replacing this slot drops the previous action without re-binding it.
        self.discovery_bytes = Some((request, origin));
        self.dispatch_queued(context);
    }

    fn byte_request_current(&self, request: &Request, origin: RequestOrigin) -> bool {
        let (Request::Bytes { address, length }, Some(binding)) = (request, origin.bytes) else {
            return false;
        };
        binding.generation == self.generation
            && binding.intent == self.byte_intent
            && origin.selection == self.selection_generation
            && origin.revision == self.revision
            && origin.byte_origin.0 == self.selected
            && match binding.destination {
                ByteDestination::Decode => true,
                ByteDestination::HexPage { token } => self.hex.expects(token, *address, *length),
            }
    }

    /// A context change invalidates even the latest action. Release its loading
    /// state, but never fail a replacement page or automatically request again.
    fn retire_byte_request(&mut self, request: &Request, origin: RequestOrigin) {
        if let (Request::Bytes { address, length }, Some(binding)) = (request, origin.bytes)
            && binding.generation == self.generation
            && binding.intent == self.byte_intent
            && let ByteDestination::HexPage { token } = binding.destination
            && self.hex.expects(token, *address, *length)
        {
            self.hex.cancel("Context changed. Retry to read this page.");
        }
    }

    fn fail_byte_request(&mut self, request: &Request, origin: RequestOrigin, message: &str) {
        if !self.byte_request_current(request, origin) {
            self.retire_byte_request(request, origin);
            return;
        }
        let message = crop(message, 4096);
        if let Some(ByteBinding {
            destination: ByteDestination::HexPage { token },
            ..
        }) = origin.bytes
        {
            self.hex.fail(token, message.clone());
        }
        self.status = message;
    }

    /// Both already-loaded instruction bytes and Hex selections supersede every
    /// outstanding byte intent without altering the function/annotation context.
    fn decode_loaded_bytes(&mut self, address: u64, bytes: Vec<u8>) {
        self.advance_byte_intent();
        if self.hex.is_loading() {
            self.hex
                .cancel("Bytes copied to Decode. Retry to load this page.");
        }
        self.decoder.set_source(address, bytes);
        self.tab = Tab::Decode;
    }

    fn handle_hex_action(&mut self, action: HexAction, context: &egui::Context) {
        match action {
            HexAction::Read {
                token,
                address,
                length,
            } => {
                self.request_bytes(address, length, ByteDestination::HexPage { token }, context);
            }
            HexAction::Decode { address, bytes } => self.decode_loaded_bytes(address, bytes),
        }
    }

    fn open_hex_section(&mut self, index: usize, context: &egui::Context) {
        let action = {
            let Some(info) = &self.info else { return };
            self.hex.open_section(index, &info.sections)
        };
        self.tab = Tab::Hex;
        if let Some(action) = action {
            self.handle_hex_action(action, context);
        }
    }

    fn schedule_open_follow(&mut self, request: Request, origin: RequestOrigin) {
        if matches!(request, Request::Bytes { .. }) {
            if !self.byte_request_current(&request, origin) {
                self.retire_byte_request(&request, origin);
                return;
            }
            self.send_direct_at(request, origin);
        } else if let Request::Graph { address } = request {
            if origin.selection != self.selection_generation {
                return;
            }
            if self.signature_change.is_none() {
                let _lookup_adoption = crate::performance::span("function_result_lookup_adoption");
                let state = self.local_override_state(address);
                let hit = self.results.lookup(address, &state);
                let requests =
                    FunctionResults::miss_requests(&hit, address, self.should_auto_decompile());
                if let Some((graph, origin)) = hit.graph {
                    self.adopt_graph(graph, origin);
                }
                if let Some((code, origin)) = hit.decompiled {
                    self.adopt_decompilation(code, origin);
                }
                for request in requests {
                    self.schedule_request(request);
                }
            } else {
                self.schedule_request(Request::Graph { address });
            }
        } else {
            self.schedule_request(request);
        }
    }

    fn set_call_index(&mut self, index: Option<Arc<crate::call_analysis::CallIndex>>) {
        self.call_index = index;
        self.result_revision = self.result_revision.wrapping_add(1);
        self.reference_revision = self.reference_revision.wrapping_add(1);
        self.reference_rows = None;
    }

    fn navigate(&mut self, address: u64, record: bool, context: &egui::Context) {
        self.navigate_to(address, None, record, context);
    }

    /// Opens the function at `address`. `focus` is an exact instruction to
    /// select once its graph is displayed, now or when a reply arrives.
    fn navigate_to(
        &mut self,
        address: u64,
        focus: Option<u64>,
        record: bool,
        context: &egui::Context,
    ) {
        if self.result_scope != Some(address) {
            self.result_revision = self.result_revision.wrapping_add(1);
        }
        self.result_scope = Some(address);
        self.reference_focus = None;
        self.string_focus = None;
        self.linkage_focus = false;
        self.selected_call = None;
        self.undisplayed_call = None;
        self.selection_generation = self.selection_generation.wrapping_add(1);
        crate::performance::navigation_begin(self.selection_generation);
        if record {
            self.record_location(address, address);
        }
        self.data_location = None;
        self.selected = Some(address);
        self.address = format!("{address:x}");
        self.editor_address = None;
        self.clear_decompilation();
        self.pending_listing_scroll = None;
        self.saved_analysis = false;
        self.graph = None;
        self.cached_graph = false;
        self.canvas = None;
        if let Some(pc) = focus {
            self.selected = Some(pc);
            self.address = format!("{pc:x}");
            self.reference_focus = Some((address, pc));
        }
        let _lookup_adoption = crate::performance::span("function_result_lookup_adoption");
        let state = self.local_override_state(address);
        let hit = if self.signature_change.is_none() {
            self.results.lookup(address, &state)
        } else {
            crate::function_results::FunctionHit {
                graph: None,
                decompiled: None,
            }
        };
        let requests = FunctionResults::miss_requests(&hit, address, self.should_auto_decompile());
        if let Some((graph, origin)) = hit.graph {
            self.adopt_graph(graph, origin);
        }
        if let Some((code, origin)) = hit.decompiled {
            self.adopt_decompilation(code, origin);
        }
        // Retire queued work for superseded selections. A full hit never sends
        // or restarts a worker, even while another request is finishing.
        self.queue.retain(|request| {
            !matches!(request, Request::Graph { .. } | Request::Decompile { .. })
        });
        if let Some(opening) = &mut self.opening
            && matches!(
                opening.follow,
                Some(Request::Graph { .. } | Request::Decompile { .. })
            )
        {
            opening.follow = None;
        }
        for request in requests {
            self.status = format!("Loading function {address:#x}…");
            self.request(request, context);
        }
    }

    /// Analysis → Refresh function: recompute both components, bypassing the store.
    fn refresh_function(&mut self, context: &egui::Context) {
        let Some(address) = self.view().map(|view| view.address) else {
            return;
        };
        self.results.refresh(address);
        self.result_revision = self.result_revision.wrapping_add(1);
        self.navigate(address, false, context);
    }

    /// Decompiler Refresh: recompute only the pseudocode, bypassing the store.
    fn refresh_decompilation(&mut self, context: &egui::Context) {
        let Some(address) = self.view().map(|view| view.address) else {
            return;
        };
        self.results
            .refresh_decompilation(address, crate::function_results::Invalidation::Refresh);
        self.result_revision = self.result_revision.wrapping_add(1);
        self.clear_decompilation();
        self.request(Request::Decompile { address }, context);
    }

    /// Shows the stored decompilation of the displayed graph, or requests it.
    fn load_decompilation(&mut self, address: u64) {
        let state = self.local_override_state(address);
        if let Some((code, origin)) = self.results.lookup(address, &state).decompiled {
            self.adopt_decompilation(code, origin);
        } else if self.should_auto_decompile() {
            crate::performance::event("function_result_miss_decompile", address);
            self.schedule_request(Request::Decompile { address });
        }
    }

    /// Drops the displayed decompilation and every selection derived from it.
    fn clear_decompilation(&mut self) {
        self.code = None;
        self.saved_analysis = false;
        self.semantic.clear();
        self.comment_rows_key = None;
        self.selected_local = None;
        self.selected_call = None;
        self.decompiler_rename_context = false;
        self.pending_code_scroll = None;
        self.pending_comment_scroll = None;
    }

    /// Shows a function graph and listing. Live replies, stored results and
    /// project restores all adopt through here.
    fn adopt_graph(&mut self, graph: Shared<PreparedGraph>, origin: ResultOrigin) {
        let _adoption = crate::performance::span("function_result_adopt_graph");
        let address = graph.address();
        self.canvas = Some(GraphCanvas::with_geometry(graph.view(), graph.geometry()));
        self.cached_graph = origin == ResultOrigin::Saved;
        self.graph = Some(graph);
        self.result_scope = Some(address);
        if let Some((function, pc)) = self.signature_restore_pc.take()
            && function == address
        {
            let pc = if self.listing().contains(pc) {
                pc
            } else {
                address
            };
            self.selected = Some(pc);
            self.address = format!("{pc:x}");
            self.select_instruction(pc);
            self.pending_listing_scroll = self.listing().position(pc);
        }
        self.comment_rows_key = None;
        self.status = format!("Function {address:#x} ready");
        if let Some((caller, pc)) = self.reference_focus.take()
            && caller == address
        {
            self.select_instruction(pc);
            if let Some(row) = self.listing().position(pc) {
                self.pending_listing_scroll = Some(row);
                if let Some(canvas) = &mut self.canvas {
                    canvas.reveal_instruction(pc);
                }
            } else {
                self.undisplayed_call = Some(pc);
            }
        }
    }

    /// Shows one indivisible decompilation for the displayed graph.
    fn adopt_decompilation(&mut self, code: Shared<PreparedDecompilation>, origin: ResultOrigin) {
        let _adoption = crate::performance::span("function_result_adopt_decompilation");
        self.selected_local = None;
        self.selected_call = None;
        self.decompiler_rename_context = false;
        self.semantic.mappings = code.mappings().clone();
        self.comment_rows_key = None;
        if let Some(address) = self.selected {
            self.semantic.select_instruction(address);
        }
        self.saved_analysis = origin == ResultOrigin::Saved;
        self.pending_code_scroll = self
            .semantic
            .ranges
            .first()
            .map(|range| code.lines().partition_point(|(_, end)| *end <= range.start));
        self.pending_comment_scroll = self.selected;
        self.status = code
            .semantics()
            .warnings
            .first()
            .cloned()
            .unwrap_or_else(|| "Ready".into());
        self.code = Some(code);
    }

    fn view(&self) -> Option<&FunctionView> {
        graph_view(&self.graph)
    }

    fn listing(&self) -> Listing<'_> {
        listing_of(&self.graph)
    }

    fn decompiled(&self) -> &str {
        code_text(&self.code)
    }

    fn semantics(&self) -> &SemanticInfo {
        semantics_of(&self.code)
    }

    fn select_instruction(&mut self, address: u64) {
        self.data_location = None;
        self.set_selected_address(address);
        self.pending_comment_scroll = Some(address);
        self.semantic.select_instruction(address);
        self.pending_code_scroll =
            self.semantic.ranges.first().map(|range| {
                code_lines(&self.code).partition_point(|(_, end)| *end <= range.start)
            });
    }

    fn set_selected_address(&mut self, address: u64) {
        self.string_focus = None;
        self.linkage_focus = false;
        self.selected_call = None;
        self.xref_choices = None;
        self.pending_comment_scroll = None;
        self.pending_code_scroll = None;
        self.selected_local = None;
        self.decompiler_rename_context = false;
        self.selected = Some(address);
        self.address = format!("{address:x}");
        self.editor_address = None;
    }

    fn select_decompiled_byte(&mut self, byte: usize) {
        self.data_location = None;
        self.string_focus = None;
        self.linkage_focus = false;
        self.xref_choices = None;
        self.pending_comment_scroll = None;
        self.decompiler_rename_context = true;
        self.selected_local = match self.semantics().token_at(byte).map(|t| &t.kind) {
            Some(TokenKind::Local { local }) => *local,
            _ => None,
        };
        self.selected_call = match self.semantics().token_at(byte).map(|t| &t.kind) {
            Some(TokenKind::Call { target }) => Some(*target),
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
        self.pending_listing_scroll = self.listing().position(primary);
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
            if let Some(activity) = &mut self.discovery_activity
                && activity.generation == self.generation
            {
                activity.known = Some(state.progress());
                activity.scanning = state.scanning();
            }
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
        self.analysis_plan = None;
        // Dropping the receiver discards any background adoption in progress.
        self.discovery_activity = None;
        self.discovery = None;
        self.discovery_job = None;
        self.deferred_discovery = None;
        self.discovery_running = false;
        self.discovery_summary = None;
        self.discovery_saved = None;
        self.saved_references = false;
        self.set_call_index(None);
        self.request(Request::Discover, context);
    }

    fn begin_discovery_activity(&mut self, now: Instant) {
        if self
            .discovery_activity
            .as_ref()
            .is_none_or(|activity| activity.generation != self.generation)
        {
            let started = self
                .analysis_plan
                .as_ref()
                .filter(|plan| plan.generation == self.generation)
                .map_or(now, |plan| plan.started);
            self.discovery_activity = Some(DiscoveryActivity {
                generation: self.generation,
                started,
                known: self.discovery.as_ref().map(|state| state.progress()),
                scanning: self
                    .discovery
                    .as_ref()
                    .is_some_and(|state| state.scanning()),
            });
        }
    }

    fn finish_discovery(&mut self) {
        if self.discovery_running {
            crate::performance::event("discovery_action_adopted", self.generation);
        }
        self.discovery_running = false;
        self.discovery_activity = None;
        self.update_discovery_summary();
        self.worker_inventory = None;
        self.inventory_synced = false;
        self.finish_auto_run(AnalysisStep::Functions);
    }

    fn start_discovery(&mut self, context: &egui::Context) {
        if self.info.is_none() {
            return;
        }
        self.begin_discovery_activity(Instant::now());
        if !self.discovery_running {
            crate::performance::event("discovery_action_begin", self.generation);
        }
        self.discovery_resumes = 0;
        if self.discovery.is_none() && self.discovery_job.is_none() {
            // Saved results are display-only; a fresh run replaces them.
            if self.saved_references {
                self.saved_references = false;
                self.set_call_index(None);
                self.discovery_summary = None;
                self.discovery_saved = None;
            }
            let Some(info) = &self.info else { return };
            // Only copy addresses here; queue construction, validation and all
            // reference sorting/indexing happen in parent background jobs.
            let seeds: Vec<_> = info.functions.iter().map(|f| f.address).collect();
            let entry = crate::call_analysis::code_address(info, info.entry).then_some(info.entry);
            let partial = info.functions_truncated;
            let patterns = crate::discovery::Discovery::patterns_apply(info);
            let elf_pointers = info.architecture == "x86-64" && info.format == "ELF";
            let generation = self.generation;
            let (sender, receiver) = mpsc::sync_channel(1);
            self.discovery_job = Some(receiver);
            let context = context.clone();
            std::thread::spawn(move || {
                let mut state = crate::discovery::Discovery::new(entry, seeds, partial);
                if patterns {
                    state.start_sources(elf_pointers);
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
        let update = if let Some(update) = self.deferred_discovery.take() {
            update
        } else {
            let Some(job) = &self.discovery_job else {
                return;
            };
            match job.try_recv() {
                Ok(update) => update,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    self.discovery_job = None;
                    self.stop_worker();
                    self.status = "Discovery adoption job failed".into();
                    return;
                }
            }
        };
        let _install = crate::performance::span("gui_discovery_install_filter");
        self.discovery_job = None;
        if update.generation != self.generation {
            return;
        }
        if let Ok(Some(publication)) = &update.publication {
            let preparation = crate::result_store::Retained::retained_bytes(update.saved.as_ref())
                .and_then(|snapshot| {
                    crate::result_store::Retained::retained_bytes(publication.index.as_ref())
                        .and_then(|index| snapshot.checked_add(index))
                })
                .unwrap_or(usize::MAX);
            crate::performance::event(
                "result_store_discovery_preparation_bytes",
                preparation as u64,
            );
            let protect = self
                .view()
                .map(|view| view.address)
                .into_iter()
                .collect::<Vec<_>>();
            if let Some(old) = &self.call_index {
                let saved_owner = self
                    .discovery_saved
                    .as_ref()
                    .is_some_and(|saved| Arc::ptr_eq(saved, old.snapshot()));
                if !self.results.can_replace_discovery(
                    &publication.index,
                    old,
                    saved_owner,
                    &protect,
                ) {
                    self.deferred_discovery = Some(update);
                    _context.request_repaint_after(Duration::from_millis(20));
                    return;
                }
            }
            // The old evidence stays displayed through pressure. After the
            // swap preflight succeeds, release UI owners before reservation;
            // an in-flight save continues to pin and charge its old snapshot.
            self.call_index = None;
            self.discovery_saved = None;
            if !self.results.retain_discovery(&publication.index, &protect) {
                self.deferred_discovery = Some(update);
                _context.request_repaint_after(Duration::from_millis(20));
                return;
            }
        }
        crate::performance::event("result_store_discovery_preparation_bytes", 0);
        self.discovery = Some(update.state);
        self.discovery_saved = Some(update.saved);
        match update.publication {
            Ok(Some(publication)) => {
                self.set_call_index(Some(publication.index));
                let changed = publication.functions.is_some();
                if let Some(info) = &mut self.info {
                    if let Some(functions) = publication.functions {
                        info.functions = functions;
                    }
                    if info.functions_truncated != publication.truncated {
                        self.source_epochs.bump_inventory();
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
                    self.update_result_inputs(crate::function_results::Invalidation::Inventory);
                    self.result_revision = self.result_revision.wrapping_add(1);
                    self.rebuild_filter();
                }
                self.discovery_resumes = 0;
                self.status = "Discovery batch committed".into();
            }
            Ok(None) => {}
            Err(error) => {
                self.stop_worker();
                self.status = format!("Invalid discovery batch: {error}");
            }
        }
        self.update_discovery_summary();
        if self
            .discovery
            .as_ref()
            .is_some_and(|state| state.remaining() == 0 && !state.scanning())
        {
            self.finish_discovery();
        }
    }

    fn pump_discovery(&mut self, _context: &egui::Context) {
        if !self.discovery_running
            || self.signature_replay.is_some()
            || self.discovery_job.is_some()
            || self.deferred_discovery.is_some()
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
            // Read current names at send time so a later rename is not replaced.
            let functions = next_sync_batch(addresses, &info.functions);
            if !functions.is_empty() {
                self.send_direct(Request::SyncFunctions { functions });
                return;
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
            self.finish_discovery();
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
        self.start_auto_analysis_at(Instant::now());
    }

    fn start_auto_analysis_at(&mut self, now: Instant) {
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
            started: now,
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

    fn finish_auto_run(&mut self, step: AnalysisStep) {
        if self.analysis_plan.as_ref().is_some_and(|plan| {
            plan.generation == self.generation
                && plan.current == Some(step)
                && plan.steps.is_empty()
        }) {
            self.analysis_plan = None;
        }
    }

    fn automatic(&self, step: AnalysisStep) -> bool {
        self.analysis_plan
            .as_ref()
            .is_some_and(|plan| plan.current == Some(step))
    }

    fn poll_worker(&mut self, context: &egui::Context) {
        if self.results.poll_inputs()
            && self.data_location.is_none()
            && let Some(address) = self.view().map(|view| view.address)
        {
            // Re-resolving the displayed function keeps a selected tree row.
            let linkage_focus = self.linkage_focus;
            self.navigate_to(address, self.selected, false, context);
            self.linkage_focus = linkage_focus;
        }
        if !self.results.preparing()
            && let Some(project) = self.deferred_restore.take()
        {
            self.restore_project(*project, context);
        }
        self.poll_discovery(context);
        self.poll_linkage();
        if self.results.preparing() {
            context.request_repaint_after(Duration::from_millis(10));
        }
        // A failed/canceled edit restores the committed state once. Recovery
        // has no staged edit, so another failure cannot start a retry loop.
        if let Some(function) = self.signature_recovery.take()
            && self.client.is_none()
            && let Some(path) = self.binary_path.clone()
        {
            self.start_open(
                path,
                true,
                Some(Request::Graph { address: function }),
                context,
            );
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.started.elapsed() > DEADLINE)
        {
            let resumable = self
                .pending
                .as_ref()
                .is_some_and(|pending| resumes_discovery(&pending.request));
            self.fail_pending_linkage();
            self.fail_pending_search();
            self.stop_after_failure(resumable, context);
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
                    let signature_failure = self.signature_change.is_some();
                    let resumable = self
                        .pending
                        .as_ref()
                        .is_some_and(|pending| resumes_discovery(&pending.request));
                    self.fail_pending_linkage();
                    self.fail_pending_search();
                    self.stop_after_failure(resumable, context);
                    if signature_failure {
                        self.signature_error = Some(format!("Signature change failed: {error}"));
                    }
                    self.status = error;
                    break;
                }
                WorkerEvent::Reply(reply) => self.receive_worker_reply(*reply, context),
            }
        }
        self.dispatch_queued(context);
        self.pump_worker_turns(context);
        // Whole-image automatic scans wait until a memory search ends.
        if !self.searches.memory_searching() {
            self.pump_analysis(context);
        }
        if self.pending.is_some()
            || self.discovery_job.is_some()
            || self.discovery_activity.is_some()
            || self.analysis_plan.is_some()
            || self.searches.memory_searching()
        {
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
            ) || progress
                .validate_event(self.progress_events, self.analysis_progress.as_ref())
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
            && analysis
                .validate_final(self.analysis_progress.as_ref())
                .is_err()
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
            if matches!(pending.request, Request::Bytes { .. }) {
                let origin = RequestOrigin {
                    selection: pending.selection,
                    revision: pending.revision,
                    byte_origin: pending.byte_origin,
                    bytes: pending.bytes,
                };
                self.fail_byte_request(&pending.request, origin, &message);
                self.dispatch_queued(context);
                return;
            }
            if let Request::SearchMemory { binding, .. } = &pending.request {
                // The worker answered in protocol; only this search stops.
                // Failed pages are never retried automatically.
                if let Some(memory) = self.searches.memory(binding.search_id)
                    && let Some(session) = &mut memory.session
                    && session.state() == SearchState::Searching
                {
                    session.unavailable();
                }
                self.status = crop(&message, 4096);
                self.dispatch_queued(context);
                return;
            }
            if matches!(pending.request, Request::Linkage { .. }) {
                // The worker answered in protocol; only this table is lost.
                self.fail_linkage();
                self.status = crop(&message, 4096);
                self.dispatch_queued(context);
                return;
            }
            if matches!(pending.request, Request::SymbolNames { .. })
                && let Some(fetch) = self.symbol_fetch.take()
            {
                // Raw/effective names stay usable; this table is not retried.
                self.symbol_failed = Some((fetch.generation, fetch.pages.summary().digest.clone()));
            }
            let signature_failure = self.signature_change.is_some();
            self.stop_after_failure(resumes_discovery(&pending.request), context);
            if signature_failure {
                self.signature_error =
                    Some(format!("Signature not applied: {}", crop(&message, 4096)));
            }
            self.status = crop(&message, 4096);
            return;
        }
        if let Err(error) = self.validate_reply(&response) {
            self.stop_worker();
            self.status = format!("Invalid worker response: {error}; worker stopped");
            return;
        }
        if let Request::Bytes {
            address: expected,
            length,
        } = &pending.request
        {
            let Response::Bytes { address, bytes } = response else {
                self.stop_worker();
                self.status = "Unexpected worker response; worker stopped".into();
                return;
            };
            if address != *expected
                || bytes.len() > *length
                || *length > MAX_BYTE_READ
                || address.checked_add(*length as u64).is_none()
            {
                self.stop_worker();
                self.status = "Unexpected worker byte response; worker stopped".into();
                return;
            }
            let origin = RequestOrigin {
                selection: pending.selection,
                revision: pending.revision,
                byte_origin: pending.byte_origin,
                bytes: pending.bytes,
            };
            if !self.byte_request_current(&pending.request, origin) {
                self.retire_byte_request(&pending.request, origin);
                self.dispatch_queued(context);
                return;
            }
            match pending.bytes.expect("checked byte binding").destination {
                ByteDestination::Decode => {
                    self.decoder.set_source(address, bytes);
                    if self.tab == pending.byte_origin.1 {
                        self.tab = Tab::Decode;
                    }
                    self.status = "Bytes loaded into decoder".into();
                }
                ByteDestination::HexPage { token } => {
                    if bytes.len() != *length {
                        self.fail_byte_request(
                            &pending.request,
                            origin,
                            "Short Hex page reply. Retry to read this page.",
                        );
                    } else if let Err(error) = self.hex.accept(token, address, bytes) {
                        let message = crop(&error, 4096);
                        self.hex.fail(token, message.clone());
                        self.status = message;
                    } else {
                        self.status = "Hex page loaded".into();
                    }
                }
            }
            self.dispatch_queued(context);
            return;
        }
        match (pending.request, response) {
            (Request::Open { .. }, Response::Opened { mut info, symbols }) => {
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
                    self.result_revision = 0;
                    self.saved_result_revision = 0;
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
                let reset = !self.reset_names.is_empty();
                for address in std::mem::take(&mut self.reset_names) {
                    if let Some(function) = info.functions.iter_mut().find(|f| f.address == address)
                    {
                        function.name = function_at(&worker_functions, address)
                            .map(|f| f.name.clone())
                            .unwrap_or_else(|| format!("FUN_{address:x}"));
                    }
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
                let first = start_address(&info);
                self.binary_path = Some(opening.path);
                if !opening.preserve {
                    self.binary_protection = Some(protection);
                }
                self.cached_functions = (opening.preserve && self.cached_functions)
                    || project.as_ref().is_some_and(|p| p.project.cache_compatible);
                // Replayed names and display labels differ from the raw Opened
                // inventory; the first batch from this worker replaces it.
                self.worker_inventory = None;
                self.inventory_synced = false;
                self.info = Some(info);
                // A replacement worker for the same verified image keeps the
                // stored results; a newly opened binary starts empty.
                if !opening.preserve
                    && let Some(info) = &self.info
                {
                    let committed = self
                        .session
                        .as_ref()
                        .map_or(&[][..], |session| session.signatures.as_slice());
                    self.results.open(&info.sha256, committed);
                    self.update_result_inputs(crate::function_results::Invalidation::Inventory);
                } else if reset {
                    self.update_result_inputs(crate::function_results::Invalidation::FunctionNames);
                }
                let signatures = self
                    .signature_change
                    .as_ref()
                    .map(|change| change.signatures.clone())
                    .or_else(|| {
                        self.session
                            .as_ref()
                            .map(|session| session.signatures.clone())
                    })
                    .unwrap_or_default();
                if !signatures.is_empty() || self.signature_change.is_some() {
                    self.signature_replay = Some(SignatureReplay {
                        context: signatures::state_digest(&signatures),
                        signatures,
                        generation: self.generation,
                        revision: self.revision,
                        epoch: self.worker_epoch,
                        sent: false,
                    });
                }
                self.begin_symbol_names(symbols);
                self.linkage.begin(self.generation, self.worker_epoch);
                // Same source and SHA are verified above: an interrupted page
                // restarts at the committed cursor on this worker's epoch.
                if let Some(SearchView {
                    kind: SearchKind::Memory(memory),
                    ..
                }) = &mut self.searches.current
                    && memory.interrupted
                {
                    if let Some(session) = &mut memory.session {
                        session.abandon_page();
                    }
                    memory.interrupted = false;
                }
                self.rebuild_filter();
                self.status = "Binary loaded".into();
                if let Some(project) = project {
                    if self.results.preparing() {
                        self.deferred_restore = Some(project);
                    } else {
                        self.restore_project(*project, context);
                    }
                } else if let Some(request) = opening.follow {
                    if matches!(request, Request::Discover) {
                        self.start_discovery(context);
                    } else {
                        self.schedule_open_follow(request, opening.follow_origin);
                    }
                } else if !opening.preserve {
                    // Like Ghidra, offer analysis when a binary is first opened.
                    self.analyze_prompt = Some(AnalyzePrompt {
                        generation: self.generation,
                        first_open: true,
                    });
                    if let Some(first) = first {
                        self.navigate(first, true, context);
                    }
                }
            }
            (Request::Graph { address }, Response::Graph { view }) if view.address == address => {
                // Superseded replies are discarded, never stored opportunistically.
                if pending.selection != self.selection_generation
                    || pending.revision != self.revision
                    || pending
                        .result
                        .as_ref()
                        .is_some_and(|_| !self.results.current(pending.result.as_ref()))
                {
                    return;
                }
                self.result_revision = self.result_revision.wrapping_add(1);
                let graph = self.results.admit_graph(
                    pending.result.as_ref(),
                    PreparedGraph::new(view),
                    ResultOrigin::Computed,
                    Some(address),
                );
                self.adopt_graph(graph, ResultOrigin::Computed);
                self.load_decompilation(address);
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
                    && self.view().is_some_and(|view| view.address == address)
                    && (pending.result.is_none() || self.results.current(pending.result.as_ref()))
                {
                    let sections = self
                        .info
                        .as_ref()
                        .map(|i| i.sections.as_slice())
                        .unwrap_or(&[]);
                    // Errors and malformed output fail closed and are never stored.
                    let code = match PreparedDecompilation::validate(
                        address, text, mappings, semantics, sections,
                    ) {
                        Ok(code) => code,
                        Err(DecompilationError::Oversized) => {
                            self.stop_worker();
                            self.clear_decompilation();
                            self.pending_listing_scroll = None;
                            self.status =
                                "Decompiler response exceeded the 2 MiB limit; analysis worker stopped"
                                    .into();
                            return;
                        }
                        Err(DecompilationError::Mappings(error)) => {
                            self.stop_worker();
                            self.clear_decompilation();
                            self.status = format!("Invalid decompiler source mappings: {error}");
                            return;
                        }
                    };
                    self.result_revision = self.result_revision.wrapping_add(1);
                    let code = self.results.admit_decompilation(
                        pending.result.as_ref(),
                        code,
                        ResultOrigin::Computed,
                        Some(address),
                    );
                    self.adopt_decompilation(code, ResultOrigin::Computed);
                }
            }
            (Request::SyncFunctions { .. }, Response::FunctionsSynced) => {}
            (
                Request::SyncSignatures {
                    binary_sha256: expected_binary,
                    context: expected_context,
                    signatures,
                },
                Response::SignaturesSynced {
                    binary_sha256,
                    context: actual_context,
                    unapplied,
                },
            ) => {
                let valid = expected_binary == binary_sha256
                    && expected_context == actual_context
                    && actual_context == signatures::state_digest(&signatures)
                    && self
                        .info
                        .as_ref()
                        .is_some_and(|info| info.sha256 == binary_sha256)
                    && self.signature_replay.as_ref().is_some_and(|replay| {
                        replay.sent
                            && replay.context == actual_context
                            && replay.generation == self.generation
                            && replay.revision == self.revision
                            && replay.epoch == self.worker_epoch
                    })
                    && unapplied.len() <= signatures.len()
                    && unapplied.iter().all(|status| {
                        status.reason.len() <= 1024
                            && signatures
                                .iter()
                                .any(|signature| signature.function == status.function)
                    });
                if !valid {
                    self.stop_worker();
                    self.status = "Signature acknowledgement was stale or incompatible; saved signatures were retained".into();
                    return;
                }
                let committed_edit = self.signature_change.is_some();
                if let Some(change) = self.signature_change.take() {
                    // Undo restores the exact saved record even when the current
                    // engine cannot apply it. New edits still require application.
                    let restores_saved_signature = change
                        .undone
                        .as_ref()
                        .and_then(|edit| edit.signature.as_ref())
                        .is_some_and(|(function, before)| {
                            *function == change.function
                                && before.as_ref()
                                    == signatures.iter().find(|s| s.function == *function)
                        });
                    if change.generation != self.generation
                        || change.revision != self.revision
                        || change.selection != self.selection_generation
                        || change.epoch != self.worker_epoch
                        || change.signatures != signatures
                        || !restores_saved_signature
                            && unapplied.iter().any(|s| s.function == change.function)
                    {
                        if let Some(edit) = change.undone {
                            self.undo.push_back(edit);
                        }
                        self.stop_worker();
                        self.signature_recovery = Some(change.function);
                        self.signature_error = Some("Signature change was not committed: the replay could not confirm the edited function".into());
                        self.status = self.signature_error.clone().unwrap_or_default();
                        return;
                    }
                    self.invalidate_signature_analysis();
                    self.result_revision = self.result_revision.wrapping_add(1);
                    if let Some(session) = &mut self.session {
                        session.signatures = change.signatures;
                        session.upgrade_version();
                        // Only an acknowledged state becomes the result context.
                        self.results.signatures_committed(&session.signatures);
                    }
                    if change.undone.is_none() {
                        self.undo.push_back(Edit {
                            address: change.function,
                            before: None,
                            function_name: None,
                            local: None,
                            signature: Some((change.function, change.before)),
                        });
                        self.trim_undo();
                    }
                    self.revision = self.revision.wrapping_add(1);
                }
                self.signature_unapplied = unapplied;
                self.signature_replay = None;
                if committed_edit {
                    self.signature_error = None;
                }
                self.status = if self.signature_unapplied.is_empty() {
                    "Function signature state applied".into()
                } else {
                    "Saved signatures retained; incompatible signatures are not applied".into()
                };
            }
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
                    let saved = Arc::new(state.save());
                    let publication = committed.map(|adopted| {
                        adopted.map(|(inventory, changed)| {
                            let _index = crate::performance::span("parent_reference_index");
                            DiscoveryPublication {
                                functions: changed.then(|| inventory.functions().to_vec()),
                                inventory,
                                truncated: batch.truncated,
                                index: Arc::new(crate::call_analysis::CallIndex::from_snapshot(
                                    saved.clone(),
                                )),
                            }
                        })
                    });
                    let saving = crate::performance::span("parent_discovery_snapshot");
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
                        |data| format!(
                            "{} data accesses · {} addresses",
                            data.references.len(),
                            analysis
                                .addresses
                                .as_ref()
                                .map_or(0, |addresses| addresses.references.len())
                        )
                    ),
                    analysis.functions_examined,
                    analysis.decode_attempts,
                    if truncated
                        || analysis.partial
                        || analysis.data.as_ref().is_some_and(|data| data.partial)
                        || analysis
                            .addresses
                            .as_ref()
                            .is_some_and(|addresses| addresses.partial)
                    {
                        " · partial coverage"
                    } else {
                        " · direct references analyzed"
                    }
                );
                self.set_call_index(Some(Arc::new(crate::call_analysis::CallIndex::new(
                    analysis,
                ))));
                self.result_revision = self.result_revision.wrapping_add(1);
                self.cached_functions = false;
                self.inventory_synced = false;
                if let Some(info) = &mut self.info {
                    info.functions = functions;
                    info.functions_truncated = truncated;
                }
                self.update_result_inputs(crate::function_results::Invalidation::Inventory);
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
                self.update_result_inputs(crate::function_results::Invalidation::FunctionNames);
                self.rebuild_filter();
                self.status = "Function renamed".into();
                if self.queue.is_empty()
                    && let Some(current) = self.view().map(|view| view.address)
                {
                    self.navigate(current, false, context);
                }
            }
            (
                request @ (Request::Strings | Request::StringsWithOptions { .. }),
                Response::Strings { strings, truncated },
            ) => {
                self.strings_minimum_used = Some(match request {
                    Request::StringsWithOptions { minimum_length } => minimum_length,
                    _ => MIN_STRING_LENGTH,
                });
                self.result_revision = self.result_revision.wrapping_add(1);
                self.cached_strings = false;
                self.source_epochs.bump_strings();
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
                self.finish_auto_run(AnalysisStep::Strings);
            }
            (Request::SymbolNames { cursor }, Response::SymbolNames { page }) => {
                self.receive_symbol_names(cursor, page, context);
            }
            (Request::Linkage { cursor, digest }, Response::Linkage { summary, page }) => {
                self.receive_linkage(cursor, digest, summary, page, context);
            }
            (Request::SearchMemory { binding, .. }, Response::MemorySearch(page)) => {
                self.receive_memory_page(binding, page);
            }
            (Request::Crypto, Response::Crypto { matches, truncated }) => {
                self.result_revision = self.result_revision.wrapping_add(1);
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
                self.finish_auto_run(AnalysisStep::Crypto);
            }
            _ => {
                self.stop_worker();
                self.status = "Unexpected worker response; worker stopped".into();
            }
        }
        self.dispatch_queued(context);
    }

    fn dispatch_queued(&mut self, context: &egui::Context) {
        if self.signature_replay.is_some() {
            self.pump_signature_replay();
            return;
        }
        // Adopt inventory before renames/navigation, then dispatch the newest
        // byte intent before starting another automatic batch or scan.
        if self.discovery_job.is_some()
            || self.deferred_discovery.is_some()
            || self.results.preparing()
            || self.pending.is_some()
            || self.opening.is_some()
        {
            return;
        }
        if let Some(request) = self.queue.pop_front() {
            if self.client.is_none() || matches!(request, Request::Discover) {
                self.request(request, context);
            } else {
                self.schedule_request(request);
            }
        }
        if self.pending.is_some() || self.opening.is_some() || !self.queue.is_empty() {
            return;
        }
        if let Some((request, origin)) = self.discovery_bytes.take() {
            if !self.byte_request_current(&request, origin) {
                self.retire_byte_request(&request, origin);
            } else if self.client.is_some() {
                self.schedule_open_follow(request, origin);
            } else if let Some(path) = self.binary_path.clone() {
                // Open still proves retained identity and hash before this
                // original consumer/context is allowed to receive anything.
                let continue_discovery = self.discovery_running;
                self.start_open_at(path, true, Some(request), origin, context);
                self.discovery_running = continue_discovery && self.client.is_some();
                self.update_discovery_summary();
            } else {
                self.fail_byte_request(
                    &request,
                    origin,
                    "No binary is available. Reopen it, then Retry.",
                );
            }
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
            Response::Opened { info, .. } => {
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
        self.source_epochs.bump_inventory();
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
        // Annotation edits, undo and adopted symbol names change effective labels.
        let revision = (self.revision, self.symbol_revision);
        if self.filter_keys_revision != revision {
            self.filter_keys_revision = revision;
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
                let symbols = self
                    .symbol_names
                    .as_ref()
                    .filter(|(generation, _)| *generation == self.generation)
                    .map(|(_, names)| names.as_ref());
                let (label, raw) = function_display(self.session.as_ref(), symbols, function);
                // A query cannot contain NUL, so it never spans both names.
                let mut key = label.to_lowercase();
                if let Some(raw) = raw {
                    key.push('\0');
                    key.push_str(&raw.to_lowercase());
                }
                self.filter_keys.push(key);
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
        let old_label = session
            .annotations
            .get(&address)
            .map(|a| a.label.as_str())
            .unwrap_or("");
        let name_changed = old_label != annotation.label
            && self
                .info
                .as_ref()
                .is_some_and(|info| function_at(&info.functions, address).is_some());
        let before = session.annotations.insert(address, annotation);
        if name_changed {
            self.update_result_inputs(crate::function_results::Invalidation::FunctionNames);
            self.result_revision = self.result_revision.wrapping_add(1);
        }
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
            signature: None,
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
        if let Some((function, before)) = edit.signature.clone() {
            if let Err(error) = self.stage_signature(function, before, Some(edit.clone()), context)
            {
                self.undo.push_back(edit);
                self.status = error;
            }
            return;
        }
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
            let old_label = session
                .annotations
                .get(&edit.address)
                .map(|a| a.label.clone())
                .unwrap_or_default();
            let new_label = edit.before.as_ref().map(|a| a.label.as_str()).unwrap_or("");
            let name_changed = old_label != new_label;
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
            if name_changed
                && self.info.as_ref().is_some_and(|info| {
                    info.functions
                        .iter()
                        .any(|function| function.address == edit.address)
                })
            {
                self.update_result_inputs(crate::function_results::Invalidation::FunctionNames);
                self.result_revision = self.result_revision.wrapping_add(1);
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

    /// The existing project field describes a code selection, never a Hex span.
    fn project_selection(&self) -> Option<u64> {
        let info = self.info.as_ref()?;
        self.selected
            .filter(|_| self.data_location.is_none())
            .or(self.code_selection)
            .filter(|&address| crate::call_analysis::code_address(info, address))
            .or_else(|| self.view().map(|view| view.address))
            .or_else(|| start_address(info))
    }

    fn save_project(&mut self, save_as: bool, context: &egui::Context) {
        let (Some(info), Some(session), Some(protection)) = (
            self.info.clone(),
            self.session.clone(),
            self.binary_protection.clone(),
        ) else {
            return;
        };
        // Project format v4 stores the displayed function's results.
        let view = self
            .view()
            .map(|view| crate::project::persistable_view(view, &info.sections));
        let data = ProjectData {
            info,
            session,
            view,
            decompiled: (!self.decompiled().is_empty()).then(|| self.decompiled().to_owned()),
            mappings: self.semantic.mappings.to_vec(),
            semantics: self.semantics().clone(),
            strings: self.strings.clone(),
            strings_truncated: self.strings_truncated,
            crypto: self.crypto.clone(),
            crypto_truncated: self.crypto_truncated,
            selected_address: self.project_selection(),
            discovery: self.discovery_saved.clone(),
        };
        let generation = self.generation;
        let revision = self.revision;
        let result_revision = self.result_revision;
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
                result_revision,
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
        // Projects persist a code location, so reveal it even if the previous
        // binary was closed while Hex or another analysis tab was active.
        self.tab = Tab::Listing;
        self.embed_binary = binary.is_some();
        self.project_binary = binary;
        self.project_path = Some(project_path);
        self.cached_strings = cache_compatible && !data.strings.is_empty();
        self.cached_crypto = cache_compatible && !data.crypto.is_empty();
        self.source_epochs.bump_strings();
        self.strings = data.strings;
        self.strings_truncated = data.strings_truncated;
        self.strings_scanned = self.cached_strings || data.strings_truncated;
        self.crypto = data.crypto;
        self.crypto_truncated = data.crypto_truncated;
        self.rebuild_string_filter();
        if let Some(saved) = data.discovery {
            if let Some(index) = discovery_index
                && self.results.retain_discovery(&index, &[])
            {
                self.set_call_index(Some(index));
            }
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
            .filter(|&address| {
                self.info
                    .as_ref()
                    .is_some_and(|info| crate::call_analysis::code_address(info, address))
            })
            .or_else(|| data.view.as_ref().map(|v| v.address))
            .or_else(|| self.info.as_ref().and_then(start_address));
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
            // Saved results enter the store with their provenance, so the
            // marker stays visible on revisits until each is recomputed.
            let binding = self
                .results
                .binding(address, self.local_override_state(address));
            let graph = self.results.admit_graph(
                binding.as_ref(),
                PreparedGraph::new(view),
                ResultOrigin::Saved,
                Some(address),
            );
            self.adopt_graph(graph, ResultOrigin::Saved);
            self.history.push(crate::linkage_ui::Place::Code(address));
            self.history_index = 0;
            self.selected = selected;
            self.address = format!("{:x}", selected.unwrap_or(address));
            let sections = self
                .info
                .as_ref()
                .map(|info| info.sections.as_slice())
                .unwrap_or(&[]);
            let code = data.decompiled.and_then(|text| {
                PreparedDecompilation::validate(
                    address,
                    text,
                    data.mappings,
                    data.semantics,
                    sections,
                )
                .ok()
            });
            if let Some(code) = code {
                let code = self.results.admit_decompilation(
                    binding.as_ref(),
                    code,
                    ResultOrigin::Saved,
                    Some(address),
                );
                self.adopt_decompilation(code, ResultOrigin::Saved);
            } else if self.should_auto_decompile() {
                self.schedule_request(Request::Decompile { address });
            }
            self.saved_result_revision = self.result_revision;
            self.status = "Project opened · saved analysis".into();
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
                let discovery_index = project.data.discovery.as_ref().map(|saved| {
                    Arc::new(crate::call_analysis::CallIndex::from_snapshot(
                        saved.clone(),
                    ))
                });
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
                result_revision,
                embedded,
                result,
            } if generation == self.generation => match result {
                Ok(Some(path)) => {
                    self.project_path = Some(path);
                    self.embed_binary = embedded;
                    self.saved_revision = revision;
                    self.saved_result_revision = result_revision;
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
                        let function = self.view().map(|view| view.address);
                        let selected_pc = self.selected;
                        let signature_changed = self.session.as_ref().is_none_or(|old| {
                            signatures::state_digest(&old.signatures)
                                != signatures::state_digest(&session.signatures)
                        });
                        let label_projection = |notes: &Session| {
                            notes
                                .annotations
                                .iter()
                                .filter(|(address, a)| {
                                    !a.label.is_empty()
                                        && self.info.as_ref().is_some_and(|info| {
                                            function_at(&info.functions, **address).is_some()
                                        })
                                })
                                .map(|(&address, a)| (address, a.label.clone()))
                                .collect::<BTreeMap<_, _>>()
                        };
                        let old_names = self
                            .session
                            .as_ref()
                            .map(&label_projection)
                            .unwrap_or_default();
                        let new_names = label_projection(&session);
                        let names_changed = old_names != new_names;
                        self.reset_names.extend(
                            old_names
                                .keys()
                                .filter(|address| !new_names.contains_key(address))
                                .copied(),
                        );
                        let selected_locals_changed = function.is_some_and(|function| {
                            let projection = |session: &Session| {
                                session
                                    .local_renames
                                    .iter()
                                    .filter(|r| r.identity.function == function)
                                    .cloned()
                                    .collect::<Vec<_>>()
                            };
                            self.session
                                .as_ref()
                                .is_none_or(|old| projection(old) != projection(&session))
                        });
                        let locals_changed = self
                            .session
                            .as_ref()
                            .is_none_or(|old| old.local_renames != session.local_renames);
                        self.session = Some(session);
                        self.session_path = Some(path);
                        self.undo.clear();
                        self.revision = self.revision.wrapping_add(1);
                        if self.project_path.is_none() {
                            self.saved_revision = self.revision;
                        }
                        self.editor_address = None;
                        if names_changed || locals_changed {
                            self.update_result_inputs(if names_changed {
                                crate::function_results::Invalidation::FunctionNames
                            } else {
                                crate::function_results::Invalidation::LocalNames
                            });
                        }
                        if signature_changed {
                            if let Some(session) = &self.session {
                                self.results.signatures_committed(&session.signatures);
                            }
                            self.invalidate_signature_analysis();
                            self.signature_restore_pc = function.zip(selected_pc);
                        }
                        self.status = "Annotations loaded".into();
                        self.rebuild_filter();
                        // A fresh engine also removes names absent from the newly
                        // loaded sidecar; current-function labels are replayed.
                        if (signature_changed || names_changed)
                            && let Some(path) = self.binary_path.clone()
                        {
                            self.clear_decompilation();
                            self.start_open(
                                path,
                                true,
                                function.map(|address| Request::Graph { address }),
                                context,
                            );
                        } else if selected_locals_changed && let Some(function) = function {
                            self.results.refresh_decompilation(
                                function,
                                crate::function_results::Invalidation::LocalNames,
                            );
                            self.clear_decompilation();
                            self.request(Request::Decompile { address: function }, context);
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
            ui.heading(if first_open {
                "Analyze binary?"
            } else {
                "Auto Analysis"
            });
            ui.label(name);
            ui.add_space(8.0);
            ui.add_enabled(
                !packed,
                egui::Checkbox::new(&mut options.functions, "Function discovery and references"),
            )
            .on_hover_text(
                "Recovers functions from calls, patterns and ELF pointers; indexes references.",
            );
            if packed {
                ui.colored_label(theme::WARNING, "Discovery unavailable · UPX")
                    .on_hover_text("Unpack a separate copy; see status warnings.");
            }
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
            ui.checkbox(&mut options.crypto, "FindCrypt constants")
                .on_hover_text("Heuristic matches for standardized cryptographic constants.");
            ui.add_space(4.0);
            ui.separator();
            ui.horizontal(|ui| {
                let selected = options.functions && !packed || options.strings || options.crypto;
                analyze = ui
                    .add_enabled(selected, egui::Button::new("Analyze"))
                    .on_hover_text("Run in background; cancel from Analysis.")
                    .clicked();
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
            .and_then(|i| semantics_of(&self.code).locals.get(i))
        {
            if local.signature_parameter.is_some() {
                self.status = "Parameter names are edited in the function signature".into();
                self.begin_signature_editor();
                return;
            }
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
            .or_else(|| {
                function.map(|function| {
                    let shown = function_display(Some(session), self.symbols(), function).0;
                    // A display name too long to commit as a label is not offered.
                    if shown.len() <= 256 {
                        shown
                    } else {
                        &function.name
                    }
                    .to_owned()
                })
            })
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

    fn signature_context(&self) -> String {
        self.session
            .as_ref()
            .filter(|session| !session.signatures.is_empty())
            .map(|session| signatures::state_digest(&session.signatures))
            .unwrap_or_default()
    }

    fn trim_undo(&mut self) {
        while self.undo.len() > HISTORY_LIMIT
            || self.undo.iter().map(edit_size).sum::<usize>() > UNDO_BYTES
        {
            self.undo.pop_front();
        }
    }

    fn pump_signature_replay(&mut self) {
        if self.pending.is_some() || self.opening.is_some() || self.client.is_none() {
            return;
        }
        let Some(replay) = &self.signature_replay else {
            return;
        };
        if replay.sent {
            return;
        }
        if replay.generation != self.generation
            || replay.revision != self.revision
            || replay.epoch != self.worker_epoch
        {
            self.stop_worker();
            self.status = "Signature replay canceled because the annotation context changed".into();
            return;
        }
        if let Some(addresses) = &mut self.discovery_sync {
            let Some(info) = &self.info else {
                return;
            };
            let functions = next_sync_batch(addresses, &info.functions);
            if !functions.is_empty() {
                self.send_direct(Request::SyncFunctions { functions });
                return;
            }
            self.discovery_sync = None;
        }
        let Some(replay) = &mut self.signature_replay else {
            return;
        };
        let Some(info) = &self.info else {
            return;
        };
        let request = Request::SyncSignatures {
            binary_sha256: info.sha256.clone(),
            context: replay.context.clone(),
            signatures: replay.signatures.clone(),
        };
        replay.sent = true;
        self.send_direct(request);
    }

    /// Prototypes can change caller types and CFG recovery. Retain only the
    /// immutable byte scans and exact inventory; every engine result is rebuilt.
    fn invalidate_signature_analysis(&mut self) {
        self.selection_generation = self.selection_generation.wrapping_add(1);
        self.graph = None;
        self.canvas = None;
        self.clear_decompilation();
        self.pending_listing_scroll = None;
        self.comment_rows = CommentRows::default();
        self.comment_owners.clear();
        self.cached_graph = false;
        self.saved_analysis = false;
        self.discovery_activity = None;
        self.discovery = None;
        self.discovery_job = None;
        self.deferred_discovery = None;
        self.discovery_saved = None;
        self.discovery_running = false;
        self.discovery_summary = None;
        self.saved_references = false;
        self.set_call_index(None);
        self.reference_focus = None;
        self.undisplayed_call = None;
        self.analysis_plan = None;
        self.signature_editor = None;
        self.signature_unapplied.clear();
    }

    fn stage_signature(
        &mut self,
        function: u64,
        replacement: Option<FunctionSignature>,
        undone: Option<Edit>,
        context: &egui::Context,
    ) -> Result<(), String> {
        if self.signature_change.is_some() || self.file_job.is_some() || self.opening.is_some() {
            return Err("Wait for the current file or signature operation to finish".into());
        }
        let info = self.info.as_ref().ok_or("Open a binary first")?;
        if function_at(&info.functions, function).is_none() {
            return Err("Choose an exact known function entry".into());
        }
        let session = self.session.as_ref().ok_or("Open a binary first")?;
        let before = session
            .signatures
            .iter()
            .find(|s| s.function == function)
            .cloned();
        if before == replacement {
            return Ok(());
        }
        if replacement.as_ref().is_some_and(|s| s.function != function) {
            return Err("Signature function does not match the editor".into());
        }
        let mut signatures = session.signatures.clone();
        signatures.retain(|s| s.function != function);
        signatures.extend(replacement);
        signatures.sort_by_key(|s| s.function);
        signatures::validate_signatures(&signatures)?;
        let path = self.binary_path.clone().ok_or("No binary is available")?;
        let restore_function = self.view().map_or(function, |view| view.address);
        let restore_pc = self.selected.map(|pc| (restore_function, pc));
        self.stop_worker();
        self.signature_recovery = None;
        // Pending signature edits cannot destroy committed discovery evidence.
        // Clear the displayed function while keeping committed store/publication
        // state until the worker acknowledges the complete new signature state.
        self.selection_generation = self.selection_generation.wrapping_add(1);
        self.graph = None;
        self.canvas = None;
        self.clear_decompilation();
        self.pending_listing_scroll = None;
        self.signature_restore_pc = restore_pc;
        self.start_open(
            path,
            true,
            Some(Request::Graph {
                address: restore_function,
            }),
            context,
        );
        if self.client.is_none() {
            return Err(self.status.clone());
        }
        self.signature_error = None;
        self.signature_change = Some(SignatureChange {
            function,
            before,
            signatures,
            generation: self.generation,
            revision: self.revision,
            selection: self.selection_generation,
            epoch: self.worker_epoch,
            undone,
        });
        self.status = "Applying complete signature state in a fresh worker…".into();
        Ok(())
    }

    fn begin_signature_editor(&mut self) {
        if self.file_job.is_some() || self.opening.is_some() || self.signature_replay.is_some() {
            return;
        }
        let Some(info) = &self.info else {
            return;
        };
        let Some(function) = self.view().map(|view| view.address) else {
            return;
        };
        let Some(entry) = function_at(&info.functions, function) else {
            self.status = "Signature editing requires an exact known function entry".into();
            return;
        };
        let abi = match signatures::current_abi(info) {
            Ok(abi) => abi,
            Err(error) => {
                self.status = error;
                return;
            }
        };
        let saved = self
            .session
            .as_ref()
            .and_then(|s| s.signatures.iter().find(|s| s.function == function));
        let (return_type, parameters, mut notes) = if let Some(saved) = saved {
            (
                Some(saved.return_type),
                saved
                    .parameters
                    .iter()
                    .map(|p| DraftParameter {
                        name: p.name.clone(),
                        ty: Some(p.ty),
                    })
                    .collect(),
                Vec::new(),
            )
        } else if let Some(inferred) = &semantics_of(&self.code).prototype {
            (
                inferred.return_type,
                inferred
                    .parameters
                    .iter()
                    .map(|p| DraftParameter {
                        name: p.name.clone(),
                        ty: p.ty,
                    })
                    .collect(),
                inferred.unsupported.clone(),
            )
        } else {
            (
                None,
                Vec::new(),
                vec!["No inferred prototype. Choose types or refresh decompilation.".into()],
            )
        };
        if let Some(status) = self
            .signature_unapplied
            .iter()
            .find(|s| s.function == function)
        {
            notes.push(status.reason.clone());
        }
        self.signature_editor = Some(SignatureEditor {
            function,
            generation: self.generation,
            revision: self.revision,
            selection: self.selection_generation,
            name: entry.name.clone(),
            abi,
            return_type,
            parameters,
            notes,
            error: None,
            has_override: saved.is_some(),
        });
    }

    fn signature_window(&mut self, context: &egui::Context) {
        if self.signature_change.is_some() {
            let modal =
                egui::Modal::new(egui::Id::unique("signature-applying")).show(context, |ui| {
                    ui.heading("Applying function signature");
                    ui.label("Verifying signatures…");
                    ui.spinner()
                        .on_hover_text("Verifying binary and replaying signatures.");
                    ui.button("Cancel").clicked()
                });
            if modal.inner || modal.should_close() {
                self.stop_worker();
                self.signature_error = Some(
                    "Signature change canceled; restoring the committed signature state.".into(),
                );
                self.status = self.signature_error.clone().unwrap_or_default();
            }
            return;
        }
        let Some(mut editor) = self.signature_editor.take() else {
            return;
        };
        if editor.generation != self.generation
            || editor.revision != self.revision
            || editor.selection != self.selection_generation
            || self.view().is_none_or(|v| v.address != editor.function)
        {
            return;
        }
        match editor.show(context) {
            Some(SignatureAction::Cancel) => {}
            Some(SignatureAction::Apply(signature)) => {
                if let Err(error) =
                    self.stage_signature(editor.function, Some(signature), None, context)
                {
                    editor.error = Some(error);
                    self.signature_editor = Some(editor);
                }
            }
            Some(SignatureAction::Remove) => {
                if let Err(error) = self.stage_signature(editor.function, None, None, context) {
                    editor.error = Some(error);
                    self.signature_editor = Some(editor);
                }
            }
            None => self.signature_editor = Some(editor),
        }
    }

    fn rename_local(
        &mut self,
        identity: &LocalIdentity,
        name: &str,
        context: &egui::Context,
    ) -> Result<(), String> {
        crate::semantic::validate_name(name)?;
        if identity.engine != crate::semantic::local_fingerprint(&self.signature_context())
            || !self
                .semantics()
                .locals
                .iter()
                .any(|v| &v.identity == identity)
            || self.view().is_none_or(|v| v.address != identity.function)
        {
            return Err(
                "Local identity is no longer present; refresh and select the variable again".into(),
            );
        }
        if self
            .semantics()
            .locals
            .iter()
            .any(|v| &v.identity == identity && v.signature_parameter.is_some())
        {
            return Err("This parameter name belongs to the function signature. Use Edit signature to rename it.".into());
        }
        if self
            .semantics()
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
        session.upgrade_version();
        self.undo.push_back(Edit {
            address: identity.function,
            before: None,
            function_name: None,
            local: Some((identity.clone(), before)),
            signature: None,
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

    /// A local-name edit or its undo changes only this function's pseudocode.
    fn refresh_local_function(&mut self, function: u64, context: &egui::Context) {
        self.update_result_inputs(crate::function_results::Invalidation::LocalNames);
        self.results
            .refresh_decompilation(function, crate::function_results::Invalidation::LocalNames);
        if self.view().is_some_and(|v| v.address == function) {
            self.clear_decompilation();
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
            // Exact original symbol, then exact demangled display name.
            .or_else(|| self.symbols()?.find(query))
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
            self.clear_decompilation();
            self.pending_listing_scroll = None;
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
        match self.history[self.history_index] {
            crate::linkage_ui::Place::Code(address) => {
                self.navigate_annotation(address, false, context)
            }
            crate::linkage_ui::Place::Data { address, length } => {
                self.open_data(address, length, context)
            }
        }
    }

    fn handle_shortcuts(&mut self, context: &egui::Context) {
        if self.navigation_shortcuts_blocked(context) {
            return;
        }
        let action = context.input_mut(|input| {
            let (index, action) = input.events.iter().enumerate().find_map(|(index, event)| {
                let action = shortcut(event)?;
                (self.info.is_some() || matches!(action, Shortcut::Help)).then_some((index, action))
            })?;
            input.events.remove(index);
            Some(action)
        });
        match action {
            Some(Shortcut::Help) => self.help_dialog = Some(crate::help::HelpDialog::Shortcuts),
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
            Some(Shortcut::Xrefs) => self.show_selection_xrefs(),
            Some(Shortcut::SearchMemory) => self.open_search_dialog(DialogKind::Memory),
            Some(Shortcut::SearchText) => self.open_search_dialog(DialogKind::Text),
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
                    ui.label("Address or name");
                }
                BrowserDialogKind::RenameLocal { identity } => {
                    ui.label(format!("Local in function {:#x}", identity.function));
                }
            }
            let mut output = TextEdit::singleline(&mut dialog.text)
                .char_limit(512)
                .desired_width(f32::INFINITY)
                .show(ui);
            if matches!(dialog.kind, BrowserDialogKind::GoTo) {
                egui::Response::clone(&output.response)
                    .on_hover_text("Hex address or exact function/label name.");
            }
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
                    if ui
                        .add(egui::Button::new("Save project…").shortcut_text("Ctrl+S"))
                        .clicked()
                    {
                        self.save_project(false, &context);
                        ui.close();
                    }
                    if ui.button("Save project as…").clicked() {
                        self.save_project(true, &context);
                        ui.close();
                    }
                    ui.checkbox(&mut self.embed_binary, "Include binary in project")
                        .on_hover_text(
                            "Embed binary for portability; otherwise locate it on reopen.",
                        );
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
                    .add_enabled(
                        !self.undo.is_empty(),
                        egui::Button::new("Undo annotation").shortcut_text("Ctrl+Z"),
                    )
                    .clicked()
                {
                    self.undo(&context);
                    ui.close();
                }
                if ui
                    .add_enabled(
                        self.selected.is_some(),
                        egui::Button::new("Rename function / label…").shortcut_text("L"),
                    )
                    .clicked()
                {
                    self.begin_rename();
                    ui.close();
                }
                if ui
                    .add_enabled(
                        self.selected.is_some(),
                        egui::Button::new("Edit comment…").shortcut_text(";"),
                    )
                    .clicked()
                {
                    self.annotations_open = true;
                    self.focus_comment = true;
                    ui.close();
                }
            });
            ui.menu_button("Navigation", |ui| {
                if ui
                    .add_enabled(loaded, egui::Button::new("Go to…").shortcut_text("G"))
                    .clicked()
                {
                    self.begin_go_to();
                    ui.close();
                }
                if ui
                    .add_enabled(
                        self.history_index > 0,
                        egui::Button::new("Back").shortcut_text("Alt+Left"),
                    )
                    .clicked()
                {
                    self.history_step(false, &context);
                    ui.close();
                }
                if ui
                    .add_enabled(
                        self.history_index + 1 < self.history.len(),
                        egui::Button::new("Forward").shortcut_text("Alt+Right"),
                    )
                    .clicked()
                {
                    self.history_step(true, &context);
                    ui.close();
                }
            });
            ui.menu_button("Search", |ui| {
                let enabled = self.search_available();
                if ui
                    .add_enabled(enabled, egui::Button::new("Memory…").shortcut_text("S"))
                    .clicked()
                {
                    self.open_search_dialog(DialogKind::Memory);
                    ui.close();
                }
                if ui
                    .add_enabled(
                        enabled,
                        egui::Button::new("Program text…").shortcut_text(crate::help::FIND_KEYS),
                    )
                    .clicked()
                {
                    self.open_search_dialog(DialogKind::Text);
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
                    (Tab::Hex, "Hex / Memory Map"),
                    (Tab::References, "References"),
                    (Tab::Search, "Search"),
                ] {
                    if tab == Tab::Search && self.searches.current.is_none() {
                        continue;
                    }
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
                    if ui
                        .add_enabled(self.graph.is_some(), egui::Button::new("Refresh function"))
                        .clicked()
                    {
                        self.refresh_function(&context);
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
                        .on_hover_text("Discard discovery results and reanalyze known functions.")
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
                    // Stopping the worker also cancels a memory search.
                    self.end_memory_search(SearchState::Canceled);
                    self.stop_worker();
                    self.analysis_plan = None;
                    self.status = "Analysis cancelled".into();
                    ui.close();
                }
            });
            ui.menu_button("Help", |ui| {
                if ui.button("Check for updates…").clicked() {
                    self.help_dialog = None;
                    self.updater.open = true;
                    ui.close();
                }
                if ui
                    .add(egui::Button::new("Keyboard shortcuts").shortcut_text("F1"))
                    .clicked()
                {
                    self.help_dialog = Some(crate::help::HelpDialog::Shortcuts);
                    ui.close();
                }
                if ui.button("About Ghidra Rust").clicked() {
                    self.help_dialog = Some(crate::help::HelpDialog::About);
                    ui.close();
                }
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
                let cached = self.cached_functions || self.cached_strings || self.cached_crypto;
                theme::dock_tabs(
                    ui,
                    &mut self.program_tree,
                    &[(false, "Symbol Tree"), (true, "Program Trees")],
                    cached.then_some((
                        "Saved",
                        "Saved tree results; recompute each analysis to verify.",
                    )),
                    |_| {},
                );
                self.symbol_tree(ui);
            });
        self.function_panel(ui);
    }

    fn symbol_tree(&mut self, ui: &mut egui::Ui) {
        let mut function = None;
        let mut read = None;
        let mut string_read = false;
        let mut string_xrefs = None;
        let mut section_index = None;
        let mut scan_strings = false;
        let mut linkage_action = None;
        // Rendered beside borrowed program state, then returned unchanged.
        let mut linkage = std::mem::take(&mut self.linkage);
        let pointer = self.pointer_width();
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
                                            let (label, raw) = function_display(
                                                self.session.as_ref(),
                                                self.symbols(),
                                                item,
                                            );
                                            if ui
                                                .add(
                                                    egui::Button::selectable(
                                                        self.view().is_some_and(|v| {
                                                            v.address == item.address
                                                        }),
                                                        crop(label, 100),
                                                    )
                                                    .truncate(),
                                                )
                                                .on_hover_text(name_hover(label, raw))
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
                                                let response = ui
                                                    .add(
                                                        egui::Button::selectable(
                                                            self.string_focus
                                                                == Some((
                                                                    self.generation,
                                                                    string.address,
                                                                )),
                                                            crop(&string.text, 100),
                                                        )
                                                        .truncate(),
                                                    )
                                                    .on_hover_text(&string.text);
                                                response.context_menu(|ui| {
                                                    if ui.button("Xrefs to…").clicked() {
                                                        string_xrefs = Some(string.address);
                                                        ui.close();
                                                    }
                                                });
                                                if response.clicked() {
                                                    string_read = true;
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
                            linkage_action = linkage.show(
                                ui,
                                self.session.as_ref(),
                                self.revision,
                                &self.filter_query,
                                self.client.is_some(),
                                pointer,
                            );
                        }
                        egui::CollapsingHeader::new(format!("Sections ({})", info.sections.len()))
                            .default_open(self.program_tree)
                            .show(ui, |ui| {
                                for (index, section) in info.sections.iter().enumerate().take(512) {
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
                                        section_index = Some(index);
                                    }
                                }
                            });
                    });
            });
        self.linkage = linkage;
        let context = ui.ctx().clone();
        if let Some(address) = function {
            self.navigate(address, true, &context);
        }
        self.linkage_action(linkage_action, &context);
        if let Some((address, length)) = read {
            if string_read {
                self.select_string(address);
            } else {
                self.select_instruction(address);
            }
            self.tab = Tab::Decode;
            self.request(Request::Bytes { address, length }, &context);
        }
        if let Some(address) = string_xrefs {
            self.select_string(address);
            self.open_xrefs(XrefTarget {
                address,
                kind: TargetKind::StringStart,
            });
        }
        if let Some(index) = section_index {
            self.open_hex_section(index, &context);
        }
        if scan_strings {
            self.request(self.string_request(), &context);
        }
    }

    /// Applies a Symbol Tree or flat Imports/Exports interaction.
    fn linkage_action(
        &mut self,
        action: Option<crate::linkage_ui::TreeAction>,
        context: &egui::Context,
    ) {
        match action {
            Some(crate::linkage_ui::TreeAction::Select(item)) => self.select_linkage(item),
            Some(crate::linkage_ui::TreeAction::Open(item)) => self.open_linkage(item, context),
            Some(crate::linkage_ui::TreeAction::OpenPlace(item, place)) => {
                self.open_linkage_place(item, place, context);
            }
            Some(crate::linkage_ui::TreeAction::Xrefs(item)) => {
                self.select_linkage(item);
                self.show_selection_xrefs();
            }
            None => {}
        }
    }

    /// The Functions dock: Functions, Imports and Exports tabs.
    fn function_panel(&mut self, ui: &mut egui::Ui) {
        let filtered = self.step_filter(FILTER_FRAME_BUDGET);
        if !filtered {
            ui.ctx().request_repaint();
        }
        let table = match self.function_dock {
            FunctionDock::Functions => None,
            FunctionDock::Imports => Some(crate::linkage_ui::Table::Imports),
            FunctionDock::Exports => Some(crate::linkage_ui::Table::Exports),
        };
        if let Some(table) = table {
            self.linkage.refresh_flat(
                table,
                self.session.as_ref(),
                self.revision,
                &self.linkage_filters[table as usize],
            );
        }
        let mut dock = self.function_dock;
        let worker = self.client.is_some();
        let changed = theme::dock_tabs(
            ui,
            &mut dock,
            &FUNCTION_DOCK_TABS,
            (table.is_none() && self.cached_functions).then_some((
                "Saved analysis",
                "Saved functions; run Discover to recompute.",
            )),
            |ui| match table {
                Some(table) => self.linkage.flat_header(ui, table, worker),
                None => {
                    ui.weak(if filtered {
                        self.filtered_functions.len().to_string()
                    } else {
                        format!("Filtering… {}", self.filtered_functions.len())
                    });
                    if self
                        .info
                        .as_ref()
                        .is_some_and(|info| info.functions_truncated)
                    {
                        ui.colored_label(theme::WARNING, "Partial").on_hover_text(
                            "Incomplete function inventory; see References and status warnings.",
                        );
                    }
                }
            },
        );
        if changed {
            // This frame keeps the header it counted; the new tab follows.
            self.function_dock = dock;
            ui.ctx().request_repaint();
        }
        match table {
            None => self.function_list(ui),
            Some(table) => {
                let pointer = self.pointer_width();
                let action = self.linkage.show_flat(
                    ui,
                    table,
                    self.session.as_ref(),
                    self.revision,
                    &mut self.linkage_filters[table as usize],
                    pointer,
                );
                self.linkage_action(action, ui.ctx());
            }
        }
    }

    fn function_list(&mut self, ui: &mut egui::Ui) {
        if ui
            .add(
                TextEdit::singleline(&mut self.function_filter)
                    .id(egui::Id::unique("function-filter"))
                    .hint_text("Filter name or address")
                    .desired_width(f32::INFINITY)
                    .char_limit(256),
            )
            .changed()
        {
            self.restart_filter();
        }
        let Some(info) = &self.info else {
            return;
        };
        let glyph = theme::glyph_width(ui);
        let digits = theme::address_digits(info.functions.last().map_or(0, |f| f.address));
        let name_x = (digits + 2) as f32 * glyph;
        theme::column_header(ui, &[("Address", 0.0), ("Name", name_x)], 0.0);
        let mut navigate = None;
        let mut xrefs = None;
        let mut annotate = None;
        let displayed = self.view().map(|view| view.address);
        theme::rows::<()>(
            ui,
            "function-list",
            self.filtered_functions.len(),
            theme::ROW_HEIGHT,
            0.0,
            None,
            |ui, row, rect| {
                let function = &info.functions[self.filtered_functions[row]];
                let (label, raw) =
                    function_display(self.session.as_ref(), self.symbols(), function);
                let response = theme::row_response(
                    ui,
                    ui.scope_id().with(("function-row", function.address)),
                    rect,
                    displayed == Some(function.address),
                    false,
                );
                theme::cell_text(
                    ui,
                    rect,
                    RichText::new(format!("{:0digits$x}", function.address)).monospace(),
                    theme::MUTED,
                );
                let witness = self
                    .discovery
                    .as_ref()
                    .and_then(|state| state.admission(function.address));
                let marker_width = if witness.is_some() { 12.0 } else { 0.0 };
                if witness.is_some() {
                    theme::cell_text(
                        ui,
                        rect.with_min_x(rect.left() + name_x),
                        RichText::new("◆"),
                        theme::MUTED,
                    );
                }
                theme::cell_text(
                    ui,
                    rect.with_min_x(rect.left() + name_x + marker_width),
                    RichText::new(label).monospace(),
                    theme::TEXT,
                );
                let detail = witness
                    .map(|w| format!("\n{}", w.hover_text()))
                    .unwrap_or_default();
                let response = response.on_hover_text(format!(
                    "{:x}  {}{}",
                    function.address,
                    name_hover(label, raw),
                    detail
                ));
                if response.clicked() {
                    navigate = Some(function.address);
                }
                response.context_menu(|ui| {
                    if ui.button("Rename / comment…").clicked() {
                        annotate = Some(function.address);
                        ui.close();
                    }
                    if ui.button("Xrefs to this function").clicked() {
                        xrefs = Some(function.address);
                        ui.close();
                    }
                });
                None
            },
        );
        if let Some(address) = annotate {
            navigate = Some(address);
            self.annotations_open = true;
        }
        if let Some(address) = navigate {
            self.navigate(address, true, ui.ctx());
        }
        if let Some(address) = xrefs {
            self.open_xrefs(XrefTarget {
                address,
                kind: TargetKind::Function,
            });
        }
    }

    fn update_comment_rows(&mut self) {
        let key = (
            self.generation,
            self.selection_generation,
            self.revision,
            self.symbol_revision,
        );
        if self.comment_rows_key == Some(key) {
            return;
        }
        let listing = listing_of(&self.graph);
        let lines = code_lines(&self.code);
        self.comment_rows = if let Some(session) = &self.session {
            self.annotation_browser
                .update(self.generation, self.revision, &session.annotations);
            CommentRows::new(
                graph_view(&self.graph).map(|view| view.address),
                lines,
                &self.semantic.mappings,
                listing.iter(),
                &session.annotations,
            )
        } else {
            CommentRows::new(
                None,
                lines,
                &self.semantic.mappings,
                listing.iter(),
                &BTreeMap::new(),
            )
        };
        if let Some(view) = graph_view(&self.graph) {
            for &address in &self.comment_rows.addresses {
                self.comment_owners.insert(address, view.address);
            }
            if let Some(session) = &self.session {
                for instruction in listing.iter() {
                    if session.annotations.contains_key(&instruction.address) {
                        self.comment_owners
                            .insert(instruction.address, view.address);
                    }
                }
            }
        }
        self.code_chars = self
            .comment_rows
            .rows
            .iter()
            .map(|row| match *row {
                CodeRow::Source(index) => lines.get(index).map_or(0, |&(start, end)| {
                    code_text(&self.code)
                        .get(start..end)
                        .map_or(0, |line| line.chars().take(2001).count())
                }),
                CodeRow::Comment(address) => self
                    .annotation_browser
                    .comments
                    .get(&address)
                    .map_or(0, |comment| comment.chars().count() + 14),
                CodeRow::UnmappedHeading => 0,
            })
            .max()
            .unwrap_or(0);
        self.comment_owners.retain(|pc, _| {
            self.history.iter().any(|place| place.address() == *pc)
                || self
                    .session
                    .as_ref()
                    .is_some_and(|session| session.annotations.contains_key(pc))
        });
        self.comment_rows_key = Some(key);
    }

    fn navigate_annotation(&mut self, address: u64, record: bool, context: &egui::Context) {
        self.navigate_location(address, None, record, context);
    }

    /// Opens `address`, inside `owner` when that is known from evidence.
    /// Recorded history keeps the exact departure and destination
    /// instructions and their observed owners for Back/Forward.
    fn navigate_location(
        &mut self,
        address: u64,
        owner: Option<u64>,
        record: bool,
        context: &egui::Context,
    ) {
        self.update_comment_rows();
        let explicit = owner.is_some();
        let current_owner = self
            .view()
            .filter(|view| {
                address == view.address
                    || self.listing().contains(address)
                    || self
                        .semantic
                        .mappings
                        .iter()
                        .any(|m| m.addresses.contains(&address))
            })
            .map(|view| view.address);
        let owner = owner
            .or(current_owner)
            .or_else(|| self.comment_owners.get(&address).copied())
            .unwrap_or(address);
        if record {
            self.record_location(address, owner);
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
        if self.view().is_some_and(|view| view.address == owner) {
            self.select_instruction(address);
            self.pending_listing_scroll = self.listing().position(address);
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
            if explicit {
                self.reference_focus = None;
                self.undisplayed_call = self.pending_listing_scroll.is_none().then_some(address);
            }
        } else {
            // The exact destination is bound before lookup, so a stored
            // result selects it as precisely as a delayed reply would.
            self.navigate_to(owner, Some(address), false, context);
        }
    }

    /// Records a Back/Forward step to `address` within `owner`, capturing the
    /// exact departure selection, including an instruction reached by a single
    /// click, for predictable Back/Forward behavior.
    fn record_location(&mut self, address: u64, owner: u64) {
        self.record_destination(crate::linkage_ui::Place::Code(address), owner);
    }

    fn record_destination(&mut self, destination: crate::linkage_ui::Place, owner: u64) {
        let address = destination.address();
        if let Some(selected) = self.selected {
            if let Some(view) = graph_view(&self.graph)
                && (selected == view.address
                    || listing_of(&self.graph).contains(selected)
                    || self
                        .semantic
                        .mappings
                        .iter()
                        .any(|m| m.addresses.contains(&selected)))
            {
                self.comment_owners.insert(selected, view.address);
            }
            if let Some(previous) = self.history.get_mut(self.history_index) {
                *previous = self.data_location.map_or(
                    crate::linkage_ui::Place::Code(selected),
                    |(address, length)| crate::linkage_ui::Place::Data { address, length },
                );
            }
        }
        self.history.truncate(self.history_index + 1);
        if self.history.last() != Some(&destination) {
            self.history.push(destination);
        }
        if self.history.len() > 256 {
            self.history.remove(0);
        }
        self.history_index = self.history.len().saturating_sub(1);
        if owner != address {
            self.comment_owners.insert(address, owner);
        }
        self.comment_owners.retain(|pc, _| {
            self.history.iter().any(|place| place.address() == *pc)
                || self
                    .session
                    .as_ref()
                    .is_some_and(|s| s.annotations.contains_key(pc))
        });
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
            "{} annotations",
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
                                .on_hover_text("Go to address.")
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
        match self.semantics().token_at(byte)?.kind {
            TokenKind::Call { target } => Some(target),
            _ => None,
        }
    }

    fn side_panel(&mut self, ui: &mut egui::Ui) {
        self.update_comment_rows();
        let context = ui.ctx().clone();
        #[derive(Clone, Copy)]
        enum Action {
            Copy,
            Refresh,
            Auto,
            Signature,
            Warnings,
        }
        let warnings = &semantics_of(&self.code).warnings;
        let mut actions = vec![
            theme::DockAction {
                id: Action::Copy,
                label: "Copy",
                tooltip: "Copy full pseudocode",
                enabled: true,
                priority: 0,
                kind: theme::DockActionKind::Button,
            },
            theme::DockAction {
                id: Action::Refresh,
                label: "Refresh",
                tooltip: "Refresh pseudocode",
                enabled: true,
                priority: 1,
                kind: theme::DockActionKind::Button,
            },
            theme::DockAction {
                id: Action::Signature,
                label: "Signature…",
                tooltip: "Edit return type, ordered parameters and current image ABI",
                enabled: self.graph.is_some() && self.signature_replay.is_none(),
                priority: 4,
                kind: theme::DockActionKind::Button,
            },
            theme::DockAction {
                id: Action::Auto,
                label: "Auto",
                tooltip: "Automatically decompile selected functions",
                enabled: true,
                priority: 3,
                kind: theme::DockActionKind::Toggle(self.auto_decompile),
            },
        ];
        if !warnings.is_empty() {
            actions.push(theme::DockAction {
                id: Action::Warnings,
                label: "Warnings",
                tooltip: "Names not applied",
                enabled: true,
                priority: 2,
                kind: theme::DockActionKind::Warnings(warnings),
            });
        }
        let action = theme::dock_header_actions(
            ui,
            "Decompiler",
            self.saved_analysis
                .then_some(("Saved analysis", "Saved pseudocode; Refresh to recompute.")),
            &actions,
        );
        match action {
            Some(Action::Copy) => context.copy_text(self.decompiled().to_owned()),
            Some(Action::Refresh) => self.refresh_decompilation(&context),
            Some(Action::Auto) => self.auto_decompile = !self.auto_decompile,
            Some(Action::Signature) => self.begin_signature_editor(),
            Some(Action::Warnings) | None => {}
        }
        if let Some(error) = &self.signature_error {
            ui.colored_label(theme::WARNING, error);
        }
        if self.signature_replay.is_some() {
            ui.weak("Verifying signatures…");
        }
        if let Some(view) = graph_view(&self.graph) {
            let entry = view.address;
            let (name, raw) = self.function_names(entry).unwrap_or(("function", None));
            let response = ui
                .horizontal(|ui| function_title(ui, name, raw, entry))
                .inner;
            response.context_menu(|ui| {
                if ui.button("Edit signature…").clicked() {
                    self.begin_signature_editor();
                    ui.close();
                }
                if ui.button("Rename / comment…").clicked() {
                    self.open_comment(entry);
                    ui.close();
                }
                if ui.button("Xrefs to this function").clicked() {
                    self.open_xrefs(XrefTarget {
                        address: entry,
                        kind: TargetKind::Function,
                    });
                    ui.close();
                }
            });
            if let Some(status) = self
                .signature_unapplied
                .iter()
                .find(|s| s.function == entry)
            {
                ui.colored_label(theme::WARNING, "Signature not applied")
                    .on_hover_text(&status.reason);
            } else if self
                .session
                .as_ref()
                .is_some_and(|s| s.signatures.iter().any(|s| s.function == entry))
            {
                ui.weak(if self.signature_replay.is_some() {
                    "Signature pending"
                } else if self.client.is_none() {
                    "Saved signature · worker inactive"
                } else {
                    "Applied signature override"
                });
            } else if self.semantics().prototype.is_some() {
                ui.weak("Inferred signature");
            }
        }
        if self.code.is_none() {
            if self
                .info
                .as_ref()
                .is_some_and(crate::packing::has_upx_warning)
            {
                ui.colored_label(theme::WARNING, "Decompilation unavailable · UPX")
                    .on_hover_text("Unpack a separate copy; see status warnings.");
            } else {
                ui.weak(if self.pending.is_some() {
                    "Decompilation pending…"
                } else {
                    "Select a function."
                });
            }
        }
        let mut navigate = None;
        let mut select_code = None;
        let mut edit_comment = None;
        let mut select_comment = None;
        let mut rename_local_byte = None;
        let mut xrefs = None;
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
        let glyph = theme::glyph_width(ui);
        theme::rows::<()>(
            ui,
            ("decompiler-text", self.view().map(|view| view.address)),
            self.comment_rows.rows.len(),
            CODE_ROW_HEIGHT,
            self.code_chars as f32 * glyph + 12.0,
            comment_target.or(code_target),
            |ui, display_row, rect| {
                let builder = egui::UiBuilder::new()
                    .id_salt(("code-row", display_row))
                    .max_rect(rect.with_min_x(rect.left() + 6.0))
                    .layout(egui::Layout::left_to_right(egui::Align::Center));
                ui.scope_builder(builder, |ui| {
                    let index = match self.comment_rows.rows[display_row] {
                        CodeRow::Source(index) => index,
                        CodeRow::UnmappedHeading => {
                            ui.colored_label(theme::WARNING, "Comments without visible code");
                            return;
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
                            return;
                        }
                    };
                    let Some(code) = self.code.as_deref() else {
                        return;
                    };
                    let (start, end) = code.lines()[index];
                    let line = code.text()[start..end].trim_end_matches(['\n', '\r']);
                    let visible = line
                        .char_indices()
                        .nth(2000)
                        .map_or(line.len(), |(at, _)| at);
                    let mut job = code.highlighted().selected_line_job(
                        code.text(),
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
                            let go = format!("Double-click to go to {target:#x}");
                            let hover = match self.function_names(target) {
                                Some((_, Some(raw))) => {
                                    format!("{}\n{go}", crop(raw, MAX_HOVER_NAME))
                                }
                                _ => go,
                            };
                            response
                                .clone()
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .on_hover_text(hover);
                            if clicked {
                                navigate = Some(target);
                            }
                        }
                    }
                    // Egui retains context menus after the pointer leaves the row,
                    // so capture the clicked token and its exact targets once.
                    let menu_id = response.id.with("decompiler-menu");
                    if response.secondary_clicked() {
                        let token = pointer_byte.and_then(|byte| self.semantics().token_at(byte));
                        let local = token
                            .filter(|t| matches!(t.kind, TokenKind::Local { .. }))
                            .cloned();
                        let view = self.info.as_ref().zip(self.view());
                        let targets = match (token.map(|t| &t.kind), pointer_byte, view) {
                            (Some(TokenKind::Call { target }), _, _) => {
                                TargetSet::single(XrefTarget {
                                    address: *target,
                                    kind: TargetKind::CallTarget,
                                })
                            }
                            (_, Some(byte), Some(view)) => crate::xrefs::instruction_targets(
                                Some(view),
                                self.call_index.as_deref(),
                                view.1.address,
                                self.semantic.addresses_at(byte).iter().copied(),
                            ),
                            _ => TargetSet::default(),
                        };
                        let menu = DecompilerMenu {
                            key: self.xref_key(),
                            local,
                            targets,
                        };
                        context.data_mut(|d| d.insert_temp(menu_id, menu));
                    }
                    let menu = context
                        .data(|d| d.get_temp::<DecompilerMenu>(menu_id))
                        .filter(|menu| menu.key == self.xref_key());
                    if let Some(menu) = menu {
                        let function = self.view().map(|view| view.address);
                        response.context_menu(|ui| {
                            if let Some(token) = &menu.local {
                                if matches!(token.kind, TokenKind::Local { local: Some(_) }) {
                                    if ui.button("Rename local variable…  L").clicked() {
                                        rename_local_byte = Some(token.start);
                                        ui.close();
                                    }
                                } else {
                                    ui.add_enabled(false, egui::Label::new("Rename unavailable"))
                                        .on_disabled_hover_text("No verified storage identity.");
                                }
                                ui.separator();
                            }
                            xref_menu_items(ui, &menu.targets, function, &mut xrefs);
                        });
                    }
                });
                None
            },
        );
        if let Some(target) = xrefs {
            self.open_xrefs(target);
        } else if let Some(target) = navigate {
            self.navigate(target, true, &context);
        } else if let Some(address) = edit_comment {
            self.open_comment(address);
        } else if let Some(address) = select_comment {
            self.select_instruction(address);
            self.pending_listing_scroll = self.listing().position(address);
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
        } else if let Some(byte) = rename_local_byte {
            self.select_decompiled_byte(byte);
            self.begin_rename();
        } else if let Some(byte) = select_code {
            self.select_decompiled_byte(byte);
            if matches!(
                self.semantics().token_at(byte).map(|t| &t.kind),
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
                .view()
                .and_then(|view| function_at(&self.info.as_ref()?.functions, view.address))
                .map(|function| function.name.clone())
                .unwrap_or_default();
        }
        ui.label(format!("Selected address {address:#x}"));
        if let Some(function) = self.view().map(|view| view.address) {
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
            if ui.button("Edit function signature…").clicked() {
                self.begin_signature_editor();
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

    /// Opens the exact source instruction of reference evidence in its owner,
    /// recording that instruction rather than the owner's entry in history.
    fn navigate_reference(&mut self, caller: u64, pc: u64, context: &egui::Context) {
        self.navigate_location(pc, Some(caller), true, context);
        self.tab = Tab::Listing;
    }

    fn xref_key(&self) -> XrefKey {
        (
            self.generation,
            self.selection_generation,
            self.revision,
            self.reference_revision,
        )
    }

    /// Inspects references to exactly `target`, independent of the displayed
    /// function, until Current function is chosen.
    fn open_xrefs(&mut self, target: XrefTarget) {
        self.xref_choices = None;
        self.xref_target = Some(target);
        self.reference_query = format!("{:x}", target.address);
        self.reference_filter.clear();
        let data_address = self
            .info
            .as_ref()
            .is_some_and(|info| !crate::call_analysis::code_address(info, target.address));
        self.reference_data = match self.call_index.as_deref() {
            _ if target.kind.prefers_data() || data_address => true,
            Some(index) => {
                let counts = crate::xrefs::counts(index, target.address);
                counts.calls == 0 && counts.data() > 0
            }
            None => false,
        };
        self.tab = Tab::References;
    }

    /// Exact targets of the current selection: a chosen call token, else the
    /// call and data evidence of every selected instruction in the displayed
    /// function, else the selected address itself.
    fn selection_xref_targets(&self) -> TargetSet {
        if let Some(item) = self.linkage_target() {
            return self.linkage_xref_targets(item);
        }
        if let Some(address) = self.string_target() {
            return TargetSet::single(XrefTarget {
                address,
                kind: TargetKind::StringStart,
            });
        }
        if let Some(target) = self.selected_call {
            return TargetSet::single(XrefTarget {
                address: target,
                kind: TargetKind::CallTarget,
            });
        }
        let mut set = TargetSet::default();
        let pcs: Vec<u64> = if self.semantic.addresses.is_empty() {
            self.selected.into_iter().collect()
        } else {
            self.semantic.addresses.iter().copied().collect()
        };
        if let Some(view) = self.view() {
            set = crate::xrefs::instruction_targets(
                self.info.as_ref().map(|info| (info, view)),
                self.call_index.as_deref(),
                view.address,
                pcs.iter().copied().filter(|pc| {
                    *pc == view.address
                        || self.listing().contains(*pc)
                        || self
                            .semantic
                            .mappings
                            .iter()
                            .any(|m| m.addresses.contains(pc))
                }),
            );
        }
        if set.targets.is_empty() {
            let function = self.view().map(|view| view.address);
            if let Some(address) = self.selected.or(function) {
                let entry = Some(address) == function
                    || self
                        .info
                        .as_ref()
                        .is_some_and(|info| function_at(&info.functions, address).is_some());
                set = TargetSet::single(XrefTarget {
                    address,
                    kind: if entry {
                        TargetKind::Function
                    } else {
                        TargetKind::Address
                    },
                });
            }
        }
        set
    }

    /// The exact start of the string row last chosen in Strings or the
    /// program tree, while it is still the selection and no code view has
    /// taken focus. Listing and Graph keep their code-selection scope.
    fn string_target(&self) -> Option<u64> {
        self.string_focus
            .filter(|&(generation, address)| {
                generation == self.generation
                    && self.selected == Some(address)
                    && !matches!(self.tab, Tab::Listing | Tab::Graph)
            })
            .map(|(_, address)| address)
    }

    /// Selects a string row's start and makes it the X target.
    fn select_string(&mut self, address: u64) {
        self.select_instruction(address);
        self.string_focus = Some((self.generation, address));
    }

    /// The linkage row last selected in the Symbol Tree, while it is still
    /// the selection.
    fn linkage_target(&self) -> Option<crate::linkage_ui::LinkageItem> {
        self.linkage.selected().filter(|_| self.linkage_focus)
    }

    fn show_selection_xrefs(&mut self) {
        let set = self.selection_xref_targets();
        if set.targets.is_empty() && self.linkage_target().is_some() {
            // Forwarders and unresolved entries have no address to query.
            return;
        }
        match set.targets.as_slice() {
            [] => self.status = "Select an instruction, function or address first".into(),
            [target] if set.omitted() == 0 => self.open_xrefs(*target),
            _ => {
                self.xref_choices = Some(XrefChoices {
                    key: self.xref_key(),
                    set,
                });
                self.tab = Tab::References;
            }
        }
    }

    /// Display label for an exact function entry; never reference evidence.
    fn reference_name(&self, address: u64) -> Option<&str> {
        self.function_names(address).map(|(shown, _)| shown)
    }

    /// [`function_display`] for an exact inventory entry.
    fn function_names(&self, address: u64) -> Option<(&str, Option<&str>)> {
        let function = function_at(&self.info.as_ref()?.functions, address)?;
        Some(function_display(
            self.session.as_ref(),
            self.symbols(),
            function,
        ))
    }

    /// The adopted symbol-name table of the displayed binary.
    fn symbols(&self) -> Option<&crate::symbol_names::SymbolNames> {
        self.symbol_names
            .as_ref()
            .filter(|(generation, _)| *generation == self.generation)
            .map(|(_, names)| names.as_ref())
    }

    /// A worker announced its open-time table. A replacement worker for the
    /// same image keeps an adopted table or continues an unfinished one.
    fn begin_symbol_names(&mut self, summary: Option<crate::model::SymbolNameSummary>) {
        let Some(summary) = summary else {
            self.symbol_fetch = None;
            return;
        };
        let generation = self.generation;
        if self
            .symbols()
            .is_some_and(|names| names.digest() == summary.digest)
            || self
                .symbol_failed
                .as_ref()
                .is_some_and(|failed| *failed == (generation, summary.digest.clone()))
        {
            self.symbol_fetch = None;
            return;
        }
        if let Some(fetch) = &mut self.symbol_fetch
            && fetch.generation == generation
            && *fetch.pages.summary() == summary
        {
            fetch.epoch = self.worker_epoch;
            return;
        }
        self.symbol_fetch = match crate::symbol_names::SymbolNameFetch::new(summary) {
            Ok(pages) => Some(SymbolFetch {
                generation,
                epoch: self.worker_epoch,
                pages,
            }),
            Err(error) => {
                self.status = error;
                None
            }
        };
        self.adopt_symbol_names();
    }

    /// Adopts a completely received table; partial pages are never displayed.
    fn adopt_symbol_names(&mut self) {
        if self
            .symbol_fetch
            .as_ref()
            .is_none_or(|fetch| fetch.pages.cursor().is_some())
        {
            return;
        }
        let fetch = self.symbol_fetch.take().expect("checked symbol fetch");
        if let Some(names) = fetch.pages.finish() {
            crate::performance::event("symbol_names_retained_bytes", names.retained_bytes() as u64);
            self.symbol_names = Some((fetch.generation, Arc::new(names)));
            self.symbol_revision = self.symbol_revision.wrapping_add(1);
            self.rebuild_filter();
        }
    }

    /// Requests the next page while the worker is otherwise idle; user
    /// actions and replays go first, discovery and scans afterwards.
    fn pump_symbol_names(&mut self) {
        if self.client.is_none()
            || self.pending.is_some()
            || self.opening.is_some()
            || !self.queue.is_empty()
            || self.signature_replay.is_some()
            || self.discovery_job.is_some()
            || self.deferred_discovery.is_some()
            || self.discovery_bytes.is_some()
            || self.results.preparing()
        {
            return;
        }
        let Some(cursor) = self
            .symbol_fetch
            .as_ref()
            .filter(|fetch| fetch.generation == self.generation && fetch.epoch == self.worker_epoch)
            .and_then(|fetch| fetch.pages.cursor())
        else {
            return;
        };
        self.send_direct(Request::SymbolNames { cursor });
    }

    fn receive_symbol_names(
        &mut self,
        cursor: usize,
        page: crate::model::SymbolNamePage,
        context: &egui::Context,
    ) {
        let Some(fetch) = self.symbol_fetch.as_mut().filter(|fetch| {
            fetch.generation == self.generation
                && fetch.epoch == self.worker_epoch
                && fetch.pages.cursor() == Some(cursor)
        }) else {
            // Another binary or table replaced this request; drop the page.
            return;
        };
        let accepted = if page.cursor == cursor {
            fetch.pages.accept(page)
        } else {
            Err("Symbol-name page answers another cursor".into())
        };
        if let Err(error) = accepted {
            let digest = fetch.pages.summary().digest.clone();
            self.symbol_failed = Some((fetch.generation, digest));
            self.symbol_fetch = None;
            self.stop_worker();
            self.status = format!("Invalid worker response: symbol names: {error}; worker stopped");
            return;
        }
        self.adopt_symbol_names();
        context.request_repaint();
    }

    /// Requests the next import/export page while the worker is otherwise
    /// idle, after symbol names; user actions, replays and adoption go first.
    fn pump_linkage(&mut self) {
        if self.client.is_none()
            || self.pending.is_some()
            || self.opening.is_some()
            || !self.queue.is_empty()
            || self.signature_replay.is_some()
            || self.discovery_job.is_some()
            || self.deferred_discovery.is_some()
            || self.discovery_bytes.is_some()
            || self.results.preparing()
        {
            return;
        }
        if let Some(request) = self.linkage.request(self.generation, self.worker_epoch) {
            self.send_direct(request);
        }
    }

    fn receive_linkage(
        &mut self,
        cursor: usize,
        digest: Option<String>,
        summary: crate::linkage::LinkageSummary,
        page: crate::linkage::LinkagePage,
        context: &egui::Context,
    ) {
        let Some(info) = &self.info else {
            return;
        };
        let received = self.linkage.receive(
            self.generation,
            self.worker_epoch,
            cursor,
            digest.as_deref(),
            summary,
            page,
            info,
        );
        match received {
            Ok(crate::linkage_ui::Received::Stale | crate::linkage_ui::Received::Pending) => {}
            Ok(crate::linkage_ui::Received::Complete(linkage)) => {
                // Charged while the presentation is prepared from it.
                if self.results.set_linkage_bytes(linkage.retained_bytes()) {
                    self.linkage.build(linkage, context);
                } else {
                    self.fail_linkage();
                }
            }
            Err(error) => {
                self.fail_linkage();
                self.stop_worker();
                self.status = format!("Invalid worker response: linkage: {error}; worker stopped");
                return;
            }
        }
        context.request_repaint();
    }

    /// Adopts a finished background presentation within the session budget.
    fn poll_linkage(&mut self) {
        match self.linkage.poll() {
            crate::linkage_ui::Polled::Idle => {}
            crate::linkage_ui::Polled::Ready(bytes) => {
                self.source_epochs.bump_linkage();
                crate::performance::event("linkage_retained_bytes", bytes as u64);
                if !self.results.set_linkage_bytes(bytes) {
                    self.fail_linkage();
                }
            }
            crate::linkage_ui::Polled::Failed => self.fail_linkage(),
        }
    }

    /// A worker that timed out or died serving the table is not asked again
    /// for this binary, so the table cannot keep restarting workers.
    fn fail_pending_linkage(&mut self) {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| matches!(pending.request, Request::Linkage { .. }))
        {
            self.fail_linkage();
        }
    }

    fn fail_linkage(&mut self) {
        self.source_epochs.bump_linkage();
        self.linkage.fail();
        self.linkage_focus = false;
        self.results.set_linkage_bytes(0);
    }

    fn pointer_width(&self) -> u64 {
        self.info
            .as_ref()
            .and_then(|info| crate::architecture::properties(&info.architecture))
            .map_or(1, |(pointer, _)| pointer)
    }

    /// Single click on a linkage row: it becomes the X target. The code
    /// selection, and so the Back/Forward departure point, stays where it was;
    /// tokens chosen in code views no longer apply.
    fn select_linkage(&mut self, item: crate::linkage_ui::LinkageItem) {
        self.string_focus = None;
        self.selected_call = None;
        self.xref_choices = None;
        self.selected_local = None;
        self.decompiler_rename_context = false;
        self.linkage.select(item);
        self.linkage_focus = true;
    }

    /// Double click: code through function navigation, slots and data in Hex.
    /// Entries without an address only become selected.
    fn open_linkage(&mut self, item: crate::linkage_ui::LinkageItem, context: &egui::Context) {
        let place = self.linkage.prepared().and_then(|prepared| {
            crate::linkage_ui::destination(prepared.linkage(), item, self.pointer_width())
        });
        match place {
            Some(place) => self.open_linkage_place(item, place, context),
            None => self.select_linkage(item),
        }
    }

    fn open_linkage_place(
        &mut self,
        item: crate::linkage_ui::LinkageItem,
        place: crate::linkage_ui::Place,
        context: &egui::Context,
    ) {
        self.linkage.select(item);
        match place {
            crate::linkage_ui::Place::Code(address) => {
                self.navigate_location(address, None, true, context);
            }
            crate::linkage_ui::Place::Data { address, length } => {
                self.navigate_data(address, length, context);
            }
        }
        // X now follows the destination's selection.
        self.linkage_focus = false;
    }

    /// Opens a slot or data object in Hex at exactly `address`, selecting up
    /// to `length` file-backed bytes. It is recorded for Back/Forward and is
    /// never treated as a function entry.
    fn navigate_data(&mut self, address: u64, length: u64, context: &egui::Context) {
        if address == 0 {
            return;
        }
        self.record_destination(crate::linkage_ui::Place::Data { address, length }, address);
        self.open_data(address, length, context);
    }

    fn open_data(&mut self, address: u64, length: u64, context: &egui::Context) {
        if self.data_location.is_none() {
            self.code_selection = self.selected;
        }
        self.selection_generation = self.selection_generation.wrapping_add(1);
        self.queue.retain(|request| {
            !matches!(request, Request::Graph { .. } | Request::Decompile { .. })
        });
        self.reference_focus = None;
        self.set_selected_address(address);
        self.semantic.addresses.clear();
        self.semantic.ranges.clear();
        self.data_location = Some((address, length));
        let action = {
            let Some(info) = &self.info else { return };
            self.hex.go_to_span(address, length, &info.sections)
        };
        self.tab = Tab::Hex;
        if let Some(action) = action {
            self.handle_hex_action(action, context);
        }
    }

    /// Exact X targets of the selected linkage row: one address opens
    /// References directly, several use the bounded chooser.
    fn linkage_xref_targets(&self, item: crate::linkage_ui::LinkageItem) -> TargetSet {
        let Some(prepared) = self.linkage.prepared() else {
            return TargetSet::default();
        };
        let functions = self.info.as_ref().map(|info| info.functions.as_slice());
        TargetSet::from_targets(
            crate::linkage_ui::places(prepared.linkage(), item, self.pointer_width())
                .into_iter()
                .map(|place| match place {
                    crate::linkage_ui::Place::Code(address) => XrefTarget {
                        address,
                        kind: if functions.is_some_and(|f| function_at(f, address).is_some()) {
                            TargetKind::Function
                        } else {
                            TargetKind::Address
                        },
                    },
                    crate::linkage_ui::Place::Data { address, .. } => XrefTarget {
                        address,
                        kind: TargetKind::DataAccess,
                    },
                }),
        )
    }

    fn read_data_reference(&mut self, target: u64, size: u32, context: &egui::Context) {
        // This action requests bytes; a memory target never becomes a function
        // or a guessed instruction/pseudocode link. Retain code selection and
        // project context; Decode carries the byte source's own exact address.
        self.xref_target = Some(XrefTarget {
            address: target,
            kind: TargetKind::DataAccess,
        });
        self.reference_query = format!("{target:x}");
        self.request(
            Request::Bytes {
                address: target,
                length: size as usize,
            },
            context,
        );
    }

    /// Target controls, explicit choices and the inspected scope shared by
    /// the call and data views. Returns the scope address and whether it was
    /// chosen explicitly rather than followed from the displayed function.
    fn reference_scope(&mut self, ui: &mut egui::Ui) -> Option<(u64, bool)> {
        if self
            .xref_choices
            .as_ref()
            .is_some_and(|choices| choices.key != self.xref_key())
        {
            self.xref_choices = None;
        }
        if let Some(choices) = &self.xref_choices {
            let mut chosen = None;
            let mut dismiss = false;
            ui.horizontal_wrapped(|ui| {
                ui.label("Targets");
                for target in &choices.set.targets {
                    let name = self
                        .reference_name(target.address)
                        .map_or(String::new(), |name| format!("  {}", crop(name, 60)));
                    if ui
                        .button(format!(
                            "{} {:x}{name}",
                            target.kind.label(),
                            target.address
                        ))
                        .clicked()
                    {
                        chosen = Some(*target);
                    }
                }
                if choices.set.omitted() > 0 {
                    ui.weak(format!("+{} omitted", choices.set.omitted()))
                        .on_hover_text("Select fewer instructions to list every target.");
                }
                if ui.small_button("Dismiss").clicked() {
                    dismiss = true;
                }
            });
            if let Some(target) = chosen {
                self.open_xrefs(target);
            } else if dismiss {
                self.xref_choices = None;
            }
        }
        if let Some(target) = self.xref_target {
            let name = self
                .reference_name(target.address)
                .map_or(String::new(), |name| format!("  {}", crop(name, 80)));
            ui.label(
                RichText::new(format!(
                    "References to {} {:#x}{name}",
                    target.kind.label(),
                    target.address
                ))
                .monospace()
                .color(theme::BLUE),
            );
            if target.kind == TargetKind::StringStart {
                ui.weak("Exact start").on_hover_text(
                    "First-byte references only; excludes interior bytes and loaded pointers.",
                );
            }
            Some((target.address, true))
        } else if let Some(function) = self.view().map(|view| view.address) {
            let name = self
                .reference_name(function)
                .map_or(String::new(), |name| format!("  {}", crop(name, 80)));
            ui.label(
                RichText::new(format!("Function {function:#x}{name}"))
                    .monospace()
                    .color(theme::BLUE),
            );
            Some((function, false))
        } else {
            theme::empty_state(ui, "Select a function or enter an address");
            None
        }
    }

    /// Rows for the current inputs, recomputed only when one changes.
    fn refresh_reference_rows(&mut self, scope: u64, explicit: bool) {
        let key = ReferenceRowsKey {
            generation: self.generation,
            references: self.reference_revision,
            revision: self.revision,
            names: self.symbol_revision,
            data: self.reference_data,
            scope: Some(scope),
            explicit,
            direction: self.reference_direction,
            access: self.reference_access,
            filter: self.reference_filter.clone(),
        };
        if self
            .reference_rows
            .as_ref()
            .is_some_and(|rows| rows.key == key)
        {
            return;
        }
        let Some(index) = &self.call_index else {
            self.reference_rows = None;
            return;
        };
        let filter = crate::xrefs::TextFilter::new(&self.reference_filter);
        let name = |address| self.reference_name(address);
        let (calls, data) = if self.reference_data {
            let scope = if explicit {
                crate::xrefs::DataScope::StartingAt(scope)
            } else {
                crate::xrefs::DataScope::From(scope)
            };
            (
                Vec::new(),
                crate::xrefs::data_rows(index, scope, self.reference_access, &filter, name),
            )
        } else {
            (
                crate::xrefs::call_rows(index, scope, self.reference_direction, &filter, name),
                Vec::new(),
            )
        };
        self.reference_rows = Some(ReferenceRows { key, calls, data });
    }

    fn reference_filter_field(&mut self, ui: &mut egui::Ui) {
        ui.add(
            TextEdit::singleline(&mut self.reference_filter)
                .hint_text("Filter name or address")
                .desired_width(200.0)
                .char_limit(256),
        )
        .on_hover_text("Names are display labels only; they never create references");
    }

    fn data_references_panel(&mut self, ui: &mut egui::Ui, scope: Option<(u64, bool)>) {
        let context = ui.ctx().clone();
        let Some(index) = &self.call_index else {
            theme::empty_state(ui, "Data references not analyzed");
            return;
        };
        if index.report.data.is_none() && index.report.addresses.is_none() {
            theme::empty_state(ui, "Data references unavailable");
            return;
        }
        let report = &index.report;
        ui.horizontal_wrapped(|ui| {
            // Long coverage summaries wrap within the panel.
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            if self.saved_references {
                ui.colored_label(theme::WARNING, "Saved analysis")
                    .on_hover_text("Saved references; run Discover to recompute.");
            }
            if let Some(data) = &report.data {
                ui.weak(format!(
                    "{} direct accesses · {} unresolved · {} omitted · {} unsupported",
                    data.references.len(),
                    data.unresolved_accesses,
                    data.omitted_accesses,
                    data.unsupported_instructions
                ))
                .on_hover_text(format!(
                    "Examined functions · {} p-code operations · {} candidates. Excludes loaded pointers.",
                    data.operations_charged, data.accesses_examined
                ));
            }
            match &report.addresses {
                Some(addresses) => {
                    ui.weak(format!(
                        "· {} addresses taken",
                        addresses.references.len()
                    ))
                    .on_hover_text(format!(
                        "Concrete addresses formed in registers or stored values · {} candidates · {} omitted. Not proof of pointer use.",
                        addresses.candidates_examined, addresses.omitted_candidates
                    ));
                }
                None => {
                    ui.weak("· Addresses not analyzed")
                        .on_hover_text("Run Discover to recompute.");
                }
            }
            if report.partial
                || report.data.as_ref().is_some_and(|data| data.partial)
                || report.addresses.as_ref().is_some_and(|addresses| addresses.partial)
            {
                ui.colored_label(theme::WARNING, "Partial")
                    .on_hover_text("Work limits, unsupported instructions or incomplete function walks.");
            }
        });
        let Some((address, explicit)) = scope else {
            return;
        };
        ui.horizontal(|ui| {
            theme::tab(ui, &mut self.reference_access, AccessFilter::All, "All");
            theme::tab(ui, &mut self.reference_access, AccessFilter::Read, "Read");
            theme::tab(ui, &mut self.reference_access, AccessFilter::Write, "Write");
            theme::tab(
                ui,
                &mut self.reference_access,
                AccessFilter::Address,
                "Address",
            );
            ui.separator();
            self.reference_filter_field(ui);
        });
        self.refresh_reference_rows(address, explicit);
        let (Some(index), Some(rows)) = (&self.call_index, &self.reference_rows) else {
            return;
        };
        let report = &index.report;
        let rows = rows.data.as_slice();
        ui.horizontal(|ui| {
            ui.label(if explicit {
                format!("{} references starting at {address:#x}", rows.len())
            } else {
                format!("{} references from this function", rows.len())
            })
            .on_hover_text("Examined functions only; empty does not mean no references.");
        });
        let mut source = None;
        let mut read = None;
        let mut target = None;
        let mut open = None;
        let glyph = theme::glyph_width(ui);
        let size_x = 11.0 * glyph;
        let target_x = size_x + 6.0 * glyph;
        let source_x = target_x + 18.0 * glyph;
        theme::column_header(
            ui,
            &[
                ("Kind", 0.0),
                ("Size", size_x),
                ("Target", target_x),
                ("Source", source_x),
            ],
            0.0,
        );
        let functions = self.info.as_ref().map(|info| info.functions.as_slice());
        theme::rows::<()>(
            ui,
            "data-references",
            rows.len(),
            theme::ROW_HEIGHT,
            source_x + 60.0 * glyph,
            None,
            |ui, row, rect| {
                // Rows are validated indices into the same immutable report.
                let (function, pc, destination, size, provenance, kind, color) = match rows[row] {
                    DataRow::Access(i) => {
                        let reference = &report.data.as_ref()?.references[i];
                        let (kind, color) = match reference.access {
                            DataAccess::Read => ("Read", theme::EDGE_TRUE),
                            DataAccess::Write => ("Write", theme::SYNTAX_VARIABLE),
                        };
                        (
                            reference.function,
                            reference.address,
                            reference.target,
                            Some(reference.size),
                            reference.provenance,
                            kind,
                            color,
                        )
                    }
                    DataRow::Address(i) => {
                        let reference = &report.addresses.as_ref()?.references[i];
                        (
                            reference.function,
                            reference.address,
                            reference.target,
                            None,
                            reference.provenance,
                            "Address",
                            theme::SYNTAX_KEYWORD,
                        )
                    }
                };
                let propagated = provenance == DataProvenance::Propagated;
                let over_kind = ui
                    .input(|input| input.pointer.hover_pos())
                    .is_some_and(|pos| pos.x < rect.left() + size_x);
                let response = theme::row_response(
                    ui,
                    ui.scope_id().with(("data-reference", row)),
                    rect,
                    false,
                    false,
                )
                .on_hover_text(match (over_kind, propagated, size) {
                    (true, true, _) => "* Address from register constants in this block.",
                    (true, false, None) => "Address taken",
                    _ => "Click to open the source instruction",
                });
                let cell = |x: f32, width: f32| {
                    egui::Rect::from_x_y_ranges(
                        rect.left() + x..=rect.left() + x + width,
                        rect.y_range(),
                    )
                };
                let kind = if propagated {
                    format!("{kind}*")
                } else {
                    kind.to_owned()
                };
                theme::cell_text(
                    ui,
                    cell(0.0, size_x),
                    RichText::new(kind).monospace(),
                    color,
                );
                theme::cell_text(
                    ui,
                    cell(size_x, target_x - size_x),
                    RichText::new(size.map_or_else(|| "—".to_owned(), |size| format!("{size}B")))
                        .monospace(),
                    theme::MUTED,
                );
                theme::cell_text(
                    ui,
                    cell(target_x, source_x - target_x),
                    RichText::new(format!("{destination:x}")).monospace(),
                    theme::SYNTAX_CONSTANT,
                );
                let name = self
                    .reference_name(function)
                    .map_or(String::new(), |name| format!(" {}", crop(name, 40)));
                theme::cell_text(
                    ui,
                    rect.with_min_x(rect.left() + source_x),
                    RichText::new(format!("{pc:x} @ {function:x}{name}")).monospace(),
                    theme::TEXT,
                );
                if response.clicked() {
                    source = Some((function, pc));
                }
                response.context_menu(|ui| {
                    if ui.button("Go to source instruction").clicked() {
                        source = Some((function, pc));
                        ui.close();
                    }
                    // A taken code address opens only an established entry;
                    // other bytes are inspected, never made a function.
                    if functions
                        .is_some_and(|functions| function_at(functions, destination).is_some())
                        && ui
                            .button(format!("Open function {destination:x}"))
                            .clicked()
                    {
                        open = Some(destination);
                        ui.close();
                    }
                    let length = size.unwrap_or(ADDRESS_DECODE_BYTES);
                    if ui
                        .button(format!("Decode {length} bytes at {destination:x}"))
                        .clicked()
                    {
                        read = Some((destination, length));
                        ui.close();
                    }
                    if ui
                        .button(format!("References starting at {destination:x}"))
                        .clicked()
                    {
                        target = Some((destination, size.is_none()));
                        ui.close();
                    }
                });
                None
            },
        );
        if let Some((function, pc)) = source {
            self.navigate_reference(function, pc, &context);
        } else if let Some(address) = open {
            self.navigate(address, true, &context);
        } else if let Some((address, size)) = read {
            self.read_data_reference(address, size, &context);
        } else if let Some((address, taken)) = target {
            self.open_xrefs(XrefTarget {
                address,
                kind: if taken {
                    TargetKind::TakenAddress
                } else {
                    TargetKind::DataAccess
                },
            });
        }
    }

    fn references_panel(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        let mut open = None;
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.info.is_some() && self.file_job.is_none(),
                    egui::Button::new("Discover"),
                )
                .on_hover_text("Run Discover to populate references.")
                .clicked()
            {
                self.request(Request::Discover, &context);
            }
            ui.separator();
            theme::tab(ui, &mut self.reference_data, false, "Calls");
            theme::tab(ui, &mut self.reference_data, true, "Data references");
            ui.separator();
            let response = ui.add(
                TextEdit::singleline(&mut self.reference_query)
                    .hint_text("Exact hex address")
                    .desired_width(130.0)
                    .char_limit(18),
            );
            let entered =
                response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if ui
                .small_button("Show xrefs")
                .on_hover_text("References to exactly this address")
                .clicked()
                || entered
            {
                match parse_address(&self.reference_query) {
                    Ok(address) => open = Some(address),
                    Err(error) => self.status = error,
                }
            }
            if ui
                .add_enabled(
                    self.xref_target.is_some(),
                    egui::Button::new("Current function").small(),
                )
                .on_hover_text("Follow the displayed function again")
                .clicked()
            {
                self.xref_target = None;
                self.reference_query.clear();
            }
            if let (Some(index), Some(target)) = (&self.call_index, self.xref_target) {
                let counts = crate::xrefs::counts(index, target.address);
                ui.weak(format!(
                    "{} calls · {} data refs",
                    counts.calls,
                    counts.data()
                ))
                .on_hover_text(format!(
                    "{} accesses · {} address taken",
                    counts.accesses, counts.addresses
                ));
            }
        });
        if let Some(address) = open {
            let function = self
                .info
                .as_ref()
                .is_some_and(|info| function_at(&info.functions, address).is_some());
            self.open_xrefs(XrefTarget {
                address,
                kind: if function {
                    TargetKind::Function
                } else {
                    TargetKind::Address
                },
            });
        }
        let scope = self.reference_scope(ui);
        if self.reference_data {
            self.data_references_panel(ui, scope);
            return;
        }
        let Some(index) = &self.call_index else {
            theme::empty_state(ui, "Calls not analyzed");
            return;
        };
        let report = &index.report;
        ui.horizontal_wrapped(|ui| {
            // Long coverage summaries wrap within the panel.
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
            if self.saved_references {
                ui.colored_label(theme::WARNING, "Saved analysis")
                    .on_hover_text("Saved references; run Discover to recompute.");
            }
            ui.weak(format!(
                "{} functions examined · {} unresolved calls · {} failed walks",
                report.functions_examined, report.unresolved_calls, report.failed_functions,
            ))
            .on_hover_text(format!(
                "Confirmed direct calls · {} decode attempts · {} fallthrough calls excluded. Indirect targets may remain unresolved.",
                report.decode_attempts, report.skipped_fallthrough_calls
            ));
            if report.partial {
                ui.colored_label(theme::WARNING, "Partial call coverage")
                    .on_hover_text("Limits, unresolved flow, or recovery failures.");
            }
        });
        let Some((address, explicit)) = scope else {
            return;
        };
        let (incoming, outgoing) = (
            index.incoming.get(&address).map_or(0, Vec::len),
            index.outgoing.get(&address).map_or(0, Vec::len),
        );
        ui.horizontal(|ui| {
            theme::tab(ui, &mut self.reference_direction, CallDirection::All, "All");
            theme::tab(
                ui,
                &mut self.reference_direction,
                CallDirection::Incoming,
                &format!("Incoming {incoming}"),
            );
            theme::tab(
                ui,
                &mut self.reference_direction,
                CallDirection::Outgoing,
                &format!("Outgoing {outgoing}"),
            );
            ui.separator();
            self.reference_filter_field(ui);
        });
        self.refresh_reference_rows(address, explicit);
        let (Some(index), Some(rows)) = (&self.call_index, &self.reference_rows) else {
            return;
        };
        let report = &index.report;
        let rows = rows.calls.as_slice();
        ui.horizontal(|ui| {
            ui.label(format!("{} matching calls", rows.len()))
                .on_hover_text("Examined functions only; empty does not mean no references.");
        });
        let mut source = None;
        let mut target = None;
        let mut inspect = None;
        let glyph = theme::glyph_width(ui);
        let function_x = 6.0 * glyph;
        let site_x = function_x + 44.0 * glyph;
        theme::column_header(
            ui,
            &[("", 0.0), ("Function", function_x), ("Call site", site_x)],
            0.0,
        );
        theme::rows::<()>(
            ui,
            "call-references",
            rows.len(),
            theme::ROW_HEIGHT,
            site_x + 20.0 * glyph,
            None,
            |ui, row, rect| {
                let CallRow {
                    reference,
                    incoming,
                } = rows[row];
                let reference = &report.references[reference];
                let counterpart = if incoming {
                    reference.caller
                } else {
                    reference.target
                };
                let (shown, raw) = self
                    .function_names(counterpart)
                    .unwrap_or(("function", None));
                let action =
                    "Click to open the call instruction · double-click to open the function";
                let response = theme::row_response(
                    ui,
                    ui.scope_id().with(("call-reference", row)),
                    rect,
                    false,
                    false,
                )
                .on_hover_text(match raw {
                    Some(raw) => format!("{}\n{action}", crop(raw, MAX_HOVER_NAME)),
                    None => action.to_owned(),
                });
                let cell = |x: f32, width: f32| {
                    egui::Rect::from_x_y_ranges(
                        rect.left() + x..=rect.left() + x + width,
                        rect.y_range(),
                    )
                };
                theme::cell_text(
                    ui,
                    cell(0.0, function_x),
                    if incoming { "From" } else { "To" },
                    theme::MUTED,
                );
                theme::cell_text(
                    ui,
                    cell(function_x, site_x - function_x),
                    RichText::new(format!("{counterpart:x} {}", crop(shown, 60))).monospace(),
                    theme::SYNTAX_FUNCTION,
                );
                theme::cell_text(
                    ui,
                    rect.with_min_x(rect.left() + site_x),
                    RichText::new(format!("{:x}", reference.address)).monospace(),
                    theme::TEXT,
                );
                if response.double_clicked() {
                    target = Some(counterpart);
                } else if response.clicked() {
                    source = Some((reference.caller, reference.address));
                }
                response.context_menu(|ui| {
                    if ui.button("Go to call instruction").clicked() {
                        source = Some((reference.caller, reference.address));
                        ui.close();
                    }
                    if ui.button(format!("Open {counterpart:x}")).clicked() {
                        target = Some(counterpart);
                        ui.close();
                    }
                    if ui.button("Xrefs to this function").clicked() {
                        inspect = Some(counterpart);
                        ui.close();
                    }
                });
                None
            },
        );
        if let Some(address) = target {
            self.navigate(address, true, &context);
        } else if let Some((caller, pc)) = source {
            self.navigate_reference(caller, pc, &context);
        } else if let Some(address) = inspect {
            self.open_xrefs(XrefTarget {
                address,
                kind: TargetKind::Function,
            });
        }
    }

    fn main_panel(&mut self, ui: &mut egui::Ui) {
        self.update_comment_rows();
        let saved_search = self.tab == Tab::Search
            && matches!(
                &self.searches.current,
                Some(SearchView { kind: SearchKind::Text(text), .. }) if text.saved()
            );
        let saved = (matches!(self.tab, Tab::Graph | Tab::Listing) && self.cached_graph)
            || (self.tab == Tab::Strings && self.cached_strings)
            || (self.tab == Tab::Crypto && self.cached_crypto)
            || saved_search;
        let saved_tooltip = if matches!(self.tab, Tab::Graph | Tab::Listing) {
            "Saved graph/listing; Refresh to recompute."
        } else if saved_search {
            "Includes saved names or strings."
        } else {
            "Saved scan results; rescan to recompute."
        };
        let mut tabs = vec![
            (Tab::Listing, "Listing"),
            (Tab::Graph, "Function Graph"),
            (Tab::Strings, "Strings"),
            (Tab::Crypto, "FindCrypt"),
            (Tab::Decode, "Decode"),
            (Tab::Hex, "Hex / Memory Map"),
            (Tab::References, "References"),
        ];
        if self.searches.current.is_some() {
            tabs.push((Tab::Search, "Search"));
        }
        theme::dock_tabs(
            ui,
            &mut self.tab,
            &tabs,
            saved.then_some(("Saved analysis", saved_tooltip)),
            |_| {},
        );
        let context = ui.ctx().clone();
        match self.tab {
            Tab::References => self.references_panel(ui),
            Tab::Search => self.search_panel(ui),
            Tab::Graph => {
                let mut navigate = None;
                let mut xrefs = None;
                if let Some(view) = graph_view(&self.graph) {
                    if !view.calls.is_empty() {
                        egui::CollapsingHeader::new(format!(
                            "{} direct / unresolved calls",
                            view.calls.len()
                        ))
                        .show(ui, |ui| {
                            ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                                for call in view.calls.iter().take(256) {
                                    if let Some(target) = call.target {
                                        let (name, raw) = self
                                            .function_names(target)
                                            .map_or((None, None), |(name, raw)| (Some(name), raw));
                                        let evidence = call.no_return.map_or_else(
                                            || "Direct call".into(),
                                            |e| e.description(),
                                        );
                                        let label = format!(
                                            "{:x} → {:x}{}{}",
                                            call.address,
                                            target,
                                            name.map_or(String::new(), |name| format!(
                                                "  {}",
                                                crop(name, 80)
                                            )),
                                            if call.no_return.is_some() {
                                                " [no return]"
                                            } else {
                                                ""
                                            }
                                        );
                                        if ui
                                            .add(egui::Button::new(label).truncate())
                                            .on_hover_text(match name {
                                                Some(name) => {
                                                    format!("{}\n{evidence}", name_hover(name, raw))
                                                }
                                                None => evidence,
                                            })
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
                        let names = |target| {
                            let function = function_at(&self.info.as_ref()?.functions, target)?;
                            let symbols = self
                                .symbol_names
                                .as_ref()
                                .filter(|(generation, _)| *generation == self.generation)
                                .map(|(_, names)| names.as_ref());
                            Some(function_display(self.session.as_ref(), symbols, function).0)
                        };
                        canvas.set_comments(
                            view,
                            (self.generation, self.revision, self.symbol_revision),
                            &self.annotation_browser.comments,
                            || {
                                view.calls
                                    .iter()
                                    .filter_map(|call| {
                                        Some((call.address, names(call.target?)?.to_owned()))
                                    })
                                    .collect()
                            },
                        );
                        let call_index = self.call_index.as_deref();
                        let info = self.info.as_ref();
                        let menu = |ui: &mut egui::Ui, pc: Option<u64>| {
                            let call = pc.and_then(|pc| {
                                view.calls
                                    .iter()
                                    .find(|call| call.address == pc)
                                    .and_then(|call| call.target)
                            });
                            if let Some(target) = call
                                && ui.button(format!("Go to {target:x}")).clicked()
                            {
                                navigate = Some(target);
                                ui.close();
                            }
                            let targets = pc.map_or_else(TargetSet::default, |pc| {
                                crate::xrefs::instruction_targets(
                                    info.map(|info| (info, view)),
                                    call_index,
                                    view.address,
                                    [pc],
                                )
                            });
                            xref_menu_items(ui, &targets, Some(view.address), &mut xrefs);
                        };
                        if let Some(action) = canvas.show_selected(
                            ui,
                            view,
                            self.selected,
                            &self.semantic.addresses,
                            menu,
                        ) {
                            match action {
                                GraphAction::Select(address) => self.select_instruction(address),
                                GraphAction::Navigate(target) => navigate = Some(target),
                            }
                        }
                    }
                } else {
                    theme::empty_state(ui, "Select a function");
                }
                if let Some(target) = xrefs {
                    self.open_xrefs(target);
                } else if let Some(address) = navigate {
                    self.navigate(address, true, &context);
                }
            }
            Tab::Listing => {
                self.listing_cursor_input(ui);
                let mut listing_xrefs = None;
                if let Some(pc) = self.undisplayed_call {
                    ui.colored_label(theme::WARNING, format!("Outside graph: {pc:#x}"))
                        .on_hover_text("Use Go to inspect the referenced instruction's address.");
                }
                if self.info.is_none() {
                    theme::empty_state(ui, "No binary loaded");
                    ui.vertical_centered(|ui| {
                        if ui.button("Open binary…").clicked() {
                            self.request_intent(Intent::OpenDialog, &context);
                        }
                    });
                    return;
                }
                let Some(view) = graph_view(&self.graph) else {
                    theme::empty_state(ui, "Select a function");
                    return;
                };
                let listing = listing_of(&self.graph);
                let entry = view.address;
                let (name, raw) = self.function_names(entry).unwrap_or(("function", None));
                function_title(ui, name, raw, entry).context_menu(|ui| {
                    if ui.button("Xrefs to this function").clicked() {
                        listing_xrefs = Some(XrefTarget {
                            address: entry,
                            kind: TargetKind::Function,
                        });
                        ui.close();
                    }
                });
                let digits = theme::address_digits(listing.last().map_or(0, |i| i.address));
                let glyph = theme::glyph_width(ui);
                let (header, _) = ui.allocate_exact_size(
                    egui::vec2(ui.available_width(), theme::ROW_HEIGHT),
                    egui::Sense::hover(),
                );
                let mut selected = None;
                let mut decode = None;
                let mut navigate = None;
                let mut annotate = None;
                let mut follow = None;
                let reveal = self.pending_listing_scroll.take();
                let (_, output) = theme::rows::<()>(
                    ui,
                    ("instruction-list", entry),
                    listing.len(),
                    theme::ROW_HEIGHT,
                    0.0,
                    reveal,
                    |ui, index, rect| {
                        let instruction = listing.get(index)?;
                        let response = theme::row_response(
                            ui,
                            ui.scope_id().with(("listing-row", instruction.address)),
                            rect,
                            self.selected == Some(instruction.address),
                            self.semantic.addresses.contains(&instruction.address),
                        );
                        let call = view
                            .calls
                            .iter()
                            .find(|call| call.address == instruction.address);
                        let callee = call
                            .and_then(|call| call.target)
                            .and_then(|target| self.function_names(target));
                        let columns = theme::listing_columns(
                            rect.width(),
                            glyph,
                            digits,
                            ui.pixels_per_point(),
                        );
                        let elided = theme::listing_cells(
                            ui,
                            rect,
                            &columns,
                            &theme::ListingRow {
                                address: instruction.address,
                                address_digits: digits,
                                bytes: &instruction.bytes,
                                mnemonic: &instruction.mnemonic,
                                operands: &instruction.operands,
                                callee: callee.map(|(name, _)| name),
                                comment: self
                                    .annotation_browser
                                    .comments
                                    .get(&instruction.address)
                                    .map(String::as_str),
                            },
                        );
                        let mut hover = Vec::new();
                        if let Some((_, Some(raw))) = callee {
                            hover.push(crop(raw, MAX_HOVER_NAME));
                        }
                        if elided.address || elided.bytes || elided.code {
                            hover.push(format!(
                                "{:0digits$x}  {}  {} {}",
                                instruction.address,
                                hex(&instruction.bytes),
                                instruction.mnemonic,
                                instruction.operands
                            ));
                            if let Some((name, _)) = callee {
                                hover.push(crop(name, MAX_HOVER_NAME));
                            }
                        }
                        if let Some(note) = self
                            .session
                            .as_ref()
                            .and_then(|session| session.annotations.get(&instruction.address))
                        {
                            hover.push(format!(
                                "{}\n{}",
                                crate::annotation_display::preview(&note.label, 80),
                                crate::annotation_display::preview(&note.comment, 400)
                            ));
                        }
                        if let Some(evidence) = call.and_then(|call| call.no_return) {
                            hover.push(evidence.description());
                        }
                        let response = if hover.is_empty() {
                            response
                        } else {
                            response.on_hover_text(hover.join("\n\n"))
                        };
                        if response.clicked() {
                            selected = Some(instruction.address);
                        }
                        let target = call.and_then(|call| call.target);
                        if response.double_clicked() {
                            follow = self.listing_follow_target(instruction.address);
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
                            ui.separator();
                            let targets = crate::xrefs::instruction_targets(
                                self.info.as_ref().map(|info| (info, view)),
                                self.call_index.as_deref(),
                                view.address,
                                [instruction.address],
                            );
                            xref_menu_items(ui, &targets, Some(view.address), &mut listing_xrefs);
                        });
                        None
                    },
                );
                let columns = theme::listing_columns(
                    output.inner_rect.width(),
                    glyph,
                    digits,
                    ui.pixels_per_point(),
                );
                theme::paint_listing_header(ui, header, &columns);
                if let Some(address) = selected {
                    self.select_instruction(address);
                }
                self.listing_cursor_drawn(ui, output.inner_rect);
                if let Some(target) = follow {
                    self.follow_listing_target(target, &context);
                }
                if let Some(address) = navigate {
                    self.navigate(address, true, &context);
                }
                if let Some(address) = annotate {
                    self.open_comment(address);
                }
                if let Some((address, bytes)) = decode {
                    self.decode_loaded_bytes(address, bytes);
                }
                if let Some(target) = listing_xrefs {
                    self.open_xrefs(target);
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
                    ui.label("Min. length");
                    ui.add(
                        egui::DragValue::new(&mut self.string_minimum)
                            .range(MIN_STRING_LENGTH..=MAX_STRING_MINIMUM)
                            .speed(1),
                    );
                    ui.separator();
                    if ui
                        .add(
                            TextEdit::singleline(&mut self.string_filter)
                                .hint_text("Filter strings")
                                .desired_width(200.0)
                                .char_limit(256),
                        )
                        .changed()
                    {
                        self.rebuild_string_filter();
                    }
                    if self.strings_scanned {
                        ui.weak(format!(
                            "{} of {}{}",
                            self.filtered_strings.len(),
                            self.strings.len(),
                            self.strings_minimum_used
                                .map_or(String::new(), |minimum| format!(" · min. {minimum}"))
                        ));
                    }
                    if self.strings_truncated {
                        ui.colored_label(theme::WARNING, "Partial scan")
                        .on_hover_text(
                            "10,000 previews / 64 MiB limit. Increase minimum length and rescan.",
                        );
                    }
                });
                let mut read = None;
                let mut xrefs = None;
                let glyph = theme::glyph_width(ui);
                let digits = self.info.as_ref().map_or(8, |info| {
                    theme::address_digits(
                        info.sections
                            .iter()
                            .map(|s| s.address.saturating_add(s.size))
                            .max()
                            .unwrap_or(0),
                    )
                });
                let type_x = (digits + 2) as f32 * glyph;
                let text_x = type_x + 10.0 * glyph;
                theme::column_header(
                    ui,
                    &[("Address", 0.0), ("Type", type_x), ("String", text_x)],
                    0.0,
                );
                let selected = self.selected;
                theme::rows::<()>(
                    ui,
                    "strings-list",
                    self.filtered_strings.len(),
                    theme::ROW_HEIGHT,
                    0.0,
                    None,
                    |ui, index, rect| {
                        let string = &self.strings[self.filtered_strings[index]];
                        let response = theme::row_response(
                            ui,
                            ui.scope_id().with(("string-row", string.address)),
                            rect,
                            selected == Some(string.address),
                            false,
                        )
                        .on_hover_text("Click to load into Decode · X for xrefs");
                        theme::cell_text(
                            ui,
                            rect,
                            RichText::new(format!("{:0digits$x}", string.address)).monospace(),
                            theme::MUTED,
                        );
                        theme::cell_text(
                            ui,
                            rect.with_min_x(rect.left() + type_x),
                            RichText::new(&string.encoding).monospace(),
                            theme::SYNTAX_TYPE,
                        );
                        theme::cell_text(
                            ui,
                            rect.with_min_x(rect.left() + text_x),
                            RichText::new(crop(&string.text, 240)).monospace(),
                            theme::SYNTAX_CONSTANT,
                        );
                        response.context_menu(|ui| {
                            if ui.button("Xrefs to…").clicked() {
                                xrefs = Some(string.address);
                                ui.close();
                            }
                        });
                        if response.clicked() {
                            let length = if string.encoding.contains("16") {
                                string.text.encode_utf16().count().saturating_mul(2)
                            } else {
                                string.text.len()
                            };
                            read =
                                Some((string.address, length.clamp(1, crate::decode::MAX_INPUT)));
                        }
                        None
                    },
                );
                if let Some((address, length)) = read {
                    self.select_string(address);
                    self.request(Request::Bytes { address, length }, &context);
                } else if let Some(address) = xrefs {
                    self.select_string(address);
                    self.open_xrefs(XrefTarget {
                        address,
                        kind: TargetKind::StringStart,
                    });
                }
            }
            Tab::Crypto => {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.info.is_some(), egui::Button::new("Scan constants"))
                        .clicked()
                    {
                        self.request(Request::Crypto, &context);
                    }
                    ui.weak(format!("{} candidates", self.crypto.len()))
                        .on_hover_text("Constant matches do not prove algorithm use.");
                });
                let mut read = None;
                let glyph = theme::glyph_width(ui);
                let digits = theme::address_digits(
                    self.crypto.iter().map(|hit| hit.address).max().unwrap_or(0),
                );
                let widest = |text: fn(&CryptoMatch) -> &str, cap: usize| {
                    self.crypto
                        .iter()
                        .map(|hit| text(hit).chars().count().min(cap))
                        .max()
                        .unwrap_or(0)
                        .max(10) as f32
                        + 2.0
                };
                let algorithm_x = (digits + 2) as f32 * glyph;
                let signature_x = algorithm_x + widest(|hit| &hit.algorithm, 32) * glyph;
                let size_x = signature_x + widest(|hit| &hit.signature, 64) * glyph;
                theme::column_header(
                    ui,
                    &[
                        ("Address", 0.0),
                        ("Algorithm", algorithm_x),
                        ("Signature", signature_x),
                        ("Bytes", size_x),
                    ],
                    0.0,
                );
                let selected = self.selected;
                theme::rows::<()>(
                    ui,
                    "crypto-list",
                    self.crypto.len(),
                    theme::ROW_HEIGHT,
                    size_x + 10.0 * glyph,
                    None,
                    |ui, index, rect| {
                        let hit = &self.crypto[index];
                        let response = theme::row_response(
                            ui,
                            ui.scope_id().with(("crypto-row", index)),
                            rect,
                            selected == Some(hit.address),
                            false,
                        )
                        .on_hover_text("Click to load the matched bytes into Decode");
                        let cell = |x: f32, width: f32| {
                            egui::Rect::from_x_y_ranges(
                                rect.left() + x..=rect.left() + x + width,
                                rect.y_range(),
                            )
                        };
                        theme::cell_text(
                            ui,
                            cell(0.0, algorithm_x),
                            RichText::new(format!("{:0digits$x}", hit.address)).monospace(),
                            theme::MUTED,
                        );
                        theme::cell_text(
                            ui,
                            cell(algorithm_x, signature_x - algorithm_x),
                            RichText::new(&hit.algorithm).monospace(),
                            theme::SYNTAX_TYPE,
                        );
                        theme::cell_text(
                            ui,
                            cell(signature_x, size_x - signature_x),
                            RichText::new(&hit.signature).monospace(),
                            theme::TEXT,
                        );
                        theme::cell_text(
                            ui,
                            cell(size_x, 10.0 * glyph),
                            RichText::new(hit.length.to_string()).monospace(),
                            theme::SYNTAX_CONSTANT,
                        );
                        if response.clicked() {
                            read = Some((hit.address, hit.length));
                        }
                        None
                    },
                );
                if let Some((address, length)) = read {
                    self.select_instruction(address);
                    self.request(Request::Bytes { address, length }, &context);
                }
            }
            Tab::Hex => {
                let action = {
                    let sections = self
                        .info
                        .as_ref()
                        .map(|info| info.sections.as_slice())
                        .unwrap_or(&[]);
                    self.hex.show(ui, sections)
                };
                if let Some(action) = action {
                    self.handle_hex_action(action, &context);
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
    /// Display-only filtering keeps old project warning data intact.
    fn status_notes(&self) -> impl Iterator<Item = &str> {
        self.info
            .iter()
            .flat_map(|info| info.warnings.iter().map(String::as_str))
            .filter(|note| !is_legacy_load_note(note))
            .chain(self.discovery_summary.as_deref().filter(|_| {
                self.discovery.as_ref().is_some_and(|state| state.partial())
                    || self.discovery_saved.as_ref().is_some_and(|saved| {
                        saved.report.partial
                            || saved.remaining() != 0
                            || saved.report.data.as_ref().is_some_and(|data| data.partial)
                            || saved
                                .report
                                .addresses
                                .as_ref()
                                .is_some_and(|addresses| addresses.partial)
                    })
            }))
    }

    /// Live run state takes precedence over the disposable worker's current job.
    fn analysis_presentation(&self, now: Instant) -> Option<RunPresentation> {
        let plan = self
            .analysis_plan
            .as_ref()
            .filter(|plan| plan.generation == self.generation);
        let discovery = self
            .discovery_activity
            .as_ref()
            .filter(|run| run.generation == self.generation);
        let pending = self.pending.as_ref();
        let started = plan
            .map(|plan| plan.started)
            .or_else(|| discovery.map(|run| run.started))
            .or_else(|| pending.map(|pending| pending.started))?;
        let elapsed = now.saturating_duration_since(started);
        if elapsed < Duration::from_millis(200) {
            return None;
        }
        let selected = plan.and_then(|plan| plan.current.or(plan.steps.front().copied()));
        let step = plan.map(|plan| {
            let ordinal = plan.total - plan.steps.len() + usize::from(plan.current.is_none());
            (ordinal.min(plan.total), plan.total)
        });
        let known = discovery.and_then(|run| run.known);
        let mut display = RunPresentation {
            phase: "Analysis",
            elapsed,
            step,
            progress: theme::BarProgress::Activity,
            known,
            foreground: None,
        };
        if plan.is_none() && discovery.is_none() {
            let pending = pending?;
            display.phase = self
                .analysis_progress
                .as_ref()
                .map(|progress| match progress.stage {
                    AnalysisStage::Seeds => "Seeding analysis",
                    AnalysisStage::Calls => "Analyzing references",
                    AnalysisStage::Publish => "Publishing results",
                })
                .unwrap_or_else(|| request_task(&pending.request));
            return Some(display);
        }
        if let Some(pending) = pending
            && matches!(
                pending.request,
                Request::Graph { .. }
                    | Request::Decompile { .. }
                    | Request::DecompileWithLocals { .. }
                    | Request::Bytes { .. }
                    | Request::Rename { .. }
            )
        {
            display.phase = if discovery.is_some() {
                "Discovery waiting"
            } else {
                "Analysis waiting"
            };
            display.foreground = Some(request_task(&pending.request));
        } else if self.opening.is_some()
            || self.signature_replay.is_some()
            || self
                .discovery_sync
                .as_ref()
                .is_some_and(|addresses| !addresses.is_empty())
            || pending.is_some_and(|pending| {
                matches!(
                    pending.request,
                    Request::Open { .. }
                        | Request::SyncFunctions { .. }
                        | Request::SyncSignatures { .. }
                )
            })
        {
            display.phase = "Restoring";
        } else if let Some(task) = pending.and_then(|pending| match pending.request {
            Request::Strings | Request::StringsWithOptions { .. } => Some("Strings"),
            Request::Crypto => Some("Constants"),
            _ => None,
        }) {
            display.phase = task;
        } else if discovery.is_some()
            && self
                .analysis_progress
                .as_ref()
                .is_some_and(|progress| matches!(progress.stage, AnalysisStage::Publish))
        {
            display.phase = "Publishing";
        } else if let Some(discovery) = discovery {
            if self.discovery_job.is_some() {
                display.phase = if known.is_some() {
                    "Adopting"
                } else {
                    "Preparing discovery"
                };
            } else if pending.is_some_and(|pending| {
                matches!(
                    pending.request,
                    Request::DiscoverBatch {
                        patterns: Some(_),
                        ..
                    }
                )
            }) || discovery.scanning
                && known.is_some_and(|work| work.processed == work.total)
            {
                display.phase = "Patterns";
            } else if let Some(work) =
                known.filter(|work| work.total != 0 && work.processed < work.total)
            {
                display.phase = "Functions";
                display.progress = theme::BarProgress::KnownFunctions {
                    processed: work.processed,
                    total: work.total,
                };
            } else {
                display.phase = "Preparing discovery";
            }
        } else {
            display.phase = match selected {
                Some(AnalysisStep::Strings) => "Strings",
                Some(AnalysisStep::Crypto) => "Constants",
                Some(AnalysisStep::Functions) => "Preparing discovery",
                None => "Analysis",
            };
        }
        Some(display)
    }

    fn status_bar(&self, ui: &mut egui::Ui) {
        self.status_bar_at(ui, Instant::now());
    }

    fn status_bar_at(&self, ui: &mut egui::Ui, now: Instant) {
        let (row, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), theme::ROW_HEIGHT),
            egui::Sense::hover(),
        );
        ui.scope_builder(
            egui::UiBuilder::new()
                .max_rect(row)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
            |ui| {
                ui.set_clip_rect(row.intersect(ui.clip_rect()));
                ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                if let Some(display) = self.analysis_presentation(now) {
                    let label = display.label();
                    let activity = ui.allocate_ui_with_layout(
                        egui::vec2((row.width() * 0.45).min(420.0), row.height()),
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| theme::analysis_activity(ui, &label, display.elapsed, display.progress),
                    );
                    activity.response.on_hover_ui(|ui| {
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                        ui.label(&label);
                        if let Some(step) = self.analysis_plan.as_ref().and_then(|plan| plan.current.or(plan.steps.front().copied())) {
                            ui.label(step.label());
                        }
                        ui.label("Cancel: Analysis → Cancel analysis.");
                        ui.label("Elapsed includes waits · step count is not time progress.");
                        if let Some(work) = display.known {
                            ui.label(format!("{}/{} known functions processed", work.processed, work.total));
                            ui.label("Includes failed/limited attempts; excludes in-flight work. Total may grow; not whole-program coverage.");
                        }
                        if let Some(task) = display.foreground {
                            ui.label(task);
                        }
                        if let Some(progress) = &self.analysis_progress {
                            ui.label(format!("Current batch: {} functions examined · {} decode attempts.", progress.functions_examined, progress.decode_attempts));
                        }
                        if let Some(summary) = &self.discovery_summary {
                            ui.label(summary);
                        }
                    });
                }
                let count = self.status_notes().count();
                if count != 0 {
                    theme::warning_menu(ui, count, |ui| {
                        ui.set_max_width(520.0);
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                        for note in self.status_notes().take(64) {
                            ui.label(crop(note, 1024));
                        }
                    });
                }
                let identity = self.info.as_ref().map(|info| format!(
                    "{} · {} · {} bytes", info.format, info.architecture, info.file_len,
                ));
                if ui.available_width() >= 600.0
                    && let Some(identity) = &identity
                {
                    ui.add(egui::Label::new(RichText::new(identity).weak()).truncate())
                        .on_hover_text(identity);
                }
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width().max(0.0), row.height()),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        if self.file_job.is_some() {
                            ui.spinner();
                        }
                        let status = ui.add(egui::Label::new(&self.status).truncate());
                        status.on_hover_ui(|ui| {
                            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Wrap);
                            ui.label(&self.status);
                            if let Some(identity) = &identity {
                                ui.weak(identity);
                            }
                            if let Some(summary) = &self.discovery_summary {
                                ui.label(summary);
                            }
                        });
                    },
                );
            },
        );
    }

    fn draw(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        if let Some(path) = self.initial_path.take() {
            self.request_intent(Intent::OpenPath(path), &context);
        }
        if let Some(path) = context
            .input(|input| {
                input
                    .raw
                    .dropped_files
                    .first()
                    .map(|file| file.path().to_owned())
            })
            .filter(|_| !self.updater.installing())
        {
            self.request_intent(Intent::OpenPath(path), &context);
        }
        self.poll_files(&context);
        if !self.updater.installing() {
            self.poll_worker(&context);
        }
        self.pump_text_search(&context);
        if let Some(installed) = self.updater.poll(&context) {
            self.status = "Update ready. Restarting…".into();
            self.restart.set(crate::updater::Restart {
                installed,
                project: self.project_path.clone(),
            });
            self.quit_confirmed = true;
            context.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.updater.installing() && context.input(|input| input.viewport().close_requested()) {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
        if context.input(|input| input.viewport().close_requested())
            && !self.updater.installing()
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
            .show(ui, |ui| self.status_bar(ui));
        // Side docks shrink with the window so the central views keep room.
        let (left, right) = dock_ranges(ui.available_width());
        egui::Panel::left("navigation-dock-v2")
            .default_size(260.0)
            .size_range(left)
            .resizable(true)
            .frame(theme::view_frame())
            .show(ui, |ui| self.navigation_panel(ui));
        egui::Panel::right("decompiler-dock-v2")
            .default_size(ui.available_width() * 0.48)
            .size_range(right(ui.available_width()))
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
                    ui.weak("Select an address.");
                } else {
                    self.annotation_editor(ui);
                }
            });
        self.annotations_open = annotations_open;
        if let Some(dialog) = self.help_dialog
            && !dialog.show(&context)
        {
            self.help_dialog = None;
        }
        self.unsaved_window(&context);
        self.analyze_window(&context);
        self.file_dialogs.show(&context);
        self.browser_dialog(&context);
        self.search_dialog_window(&context);
        self.signature_window(&context);
        if self.intent.is_none()
            && self.after_save.is_none()
            && self.file_job.is_none()
            && self.updater.show(&context)
        {
            self.request_intent(Intent::InstallUpdate, &context);
        }
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
            self.view().is_some() && matches!(self.tab, Tab::Graph | Tab::Listing),
            !self.decompiled().is_empty(),
        );
        frame.finish(0);
        #[cfg(feature = "capture")]
        self.capture_tick(ui.ctx());
    }
}

#[cfg(feature = "capture")]
impl DesktopApp {
    fn capture_cache_check(
        &mut self,
        check: &mut crate::capture::CacheCheck,
        context: &egui::Context,
    ) -> bool {
        let a = check.a;
        let b = check.b;
        eprintln!("native cache check step {}", check.step);
        match check.step {
            0 => self.navigate(a, true, context),
            1 => {
                assert_eq!(self.view().unwrap().address, a);
                assert!(!self.decompiled().is_empty());
                check.epoch = self.worker_epoch;
                check.graph = self.graph.clone();
                check.code = self.code.clone();
                let (byte, pc) = self
                    .semantic
                    .mappings
                    .iter()
                    .find_map(|m| {
                        m.addresses
                            .iter()
                            .find(|&&pc| pc != a && self.listing().contains(pc))
                            .map(|&pc| (m.start, pc))
                    })
                    .expect("genuine mapped instruction");
                self.select_decompiled_byte(byte);
                assert!(self.semantic.addresses.contains(&pc));
                self.select_instruction(pc);
                assert!(!self.semantic.ranges.is_empty());
                check.pc = pc;
                self.navigate_location(pc, Some(a), true, context);
                self.navigate(b, true, context);
            }
            2 => {
                assert_eq!(self.view().unwrap().address, b);
                self.navigate_location(check.pc, Some(a), true, context);
                assert!(Arc::ptr_eq(
                    self.code.as_ref().unwrap(),
                    check.code.as_ref().unwrap()
                ));
                assert!(Arc::ptr_eq(
                    self.graph.as_ref().unwrap(),
                    check.graph.as_ref().unwrap()
                ));
                assert!(self.pending.is_none() && self.queue.is_empty());
                assert_eq!(self.selected, Some(check.pc));
                assert_eq!(self.worker_epoch, check.epoch);
            }
            3 => {
                self.history_step(false, context);
                assert_eq!(self.view().unwrap().address, b);
                assert!(self.pending.is_none() && self.queue.is_empty());
            }
            4 => {
                self.history_step(true, context);
                assert_eq!(self.view().unwrap().address, a);
                assert_eq!(self.selected, Some(check.pc));
                assert!(self.pending.is_none() && self.queue.is_empty());
                self.tab = Tab::Graph;
            }
            5 => self.refresh_function(context),
            6 => {
                assert_eq!(self.view().unwrap().address, a);
                assert!(!Arc::ptr_eq(
                    self.code.as_ref().unwrap(),
                    check.code.as_ref().unwrap()
                ));
                assert!(!Arc::ptr_eq(
                    self.graph.as_ref().unwrap(),
                    check.graph.as_ref().unwrap()
                ));
                self.select_instruction(check.pc);
                assert!(!self.semantic.ranges.is_empty());
                check.graph = None;
                check.code = None;
                if let Some(path) = &check.project {
                    self.project_path = Some(path.clone());
                    self.save_project(false, context);
                }
            }
            7 => {
                if let Some(path) = &check.project {
                    assert!(!self.dirty());
                    assert!(path.exists());
                    self.open_project(path.clone(), context);
                }
            }
            8 => {
                if check.project.is_some() {
                    assert!(self.cached_graph && self.saved_analysis);
                    assert_eq!(self.view().unwrap().address, a);
                    assert_eq!(self.selected, Some(check.pc));
                }
                check.code = self.code.clone();
                let path = self.binary_path.clone().unwrap();
                self.start_open(path, true, Some(Request::Graph { address: b }), context);
                self.navigate_to(a, Some(check.pc), false, context);
                assert!(self.opening.as_ref().unwrap().follow.is_none());
                assert!(Arc::ptr_eq(
                    self.code.as_ref().unwrap(),
                    check.code.as_ref().unwrap()
                ));
            }
            9 => {
                assert_eq!(self.view().unwrap().address, a);
                assert_eq!(self.selected, Some(check.pc));
                assert!(Arc::ptr_eq(
                    self.code.as_ref().unwrap(),
                    check.code.as_ref().unwrap()
                ));
                if check.project.is_some() {
                    assert!(self.saved_analysis && self.cached_graph && self.cached_functions);
                    assert!(!self.dirty());
                }
                check.code = None;
                self.tab = Tab::Listing;
                crate::performance::event("native_cache_check_complete", check.step as u64);
                eprintln!(
                    "native cache check passed: A/B/A, exact history, selection, Refresh, project save/reopen, worker restart with superseded navigation"
                );
                return true;
            }
            _ => unreachable!(),
        }
        check.step += 1;
        false
    }

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
        if let Some(size) = capture.size.take() {
            context.send_viewport_cmd(egui::ViewportCommand::InnerSize(size));
        }
        // Screenshots show the browser, not the first-open analysis prompt.
        if self.analyze_prompt.take().is_some() && capture.analyze {
            self.analysis_options = AnalysisOptions {
                functions: true,
                strings: true,
                crypto: true,
            };
            self.start_auto_analysis();
        }
        let busy = self.pending.is_some()
            || self.opening.is_some()
            || !self.queue.is_empty()
            || self.file_job.is_some()
            || self.analysis_plan.is_some()
            || self.discovery_running
            || self.results.preparing()
            || self.deferred_restore.is_some()
            || self.info.is_none();
        if !busy && let Some(check) = &mut capture.cache_check {
            if self.capture_cache_check(check, context) {
                capture.cache_check = None;
            }
            context.request_repaint_after(Duration::from_millis(50));
            return;
        }
        if !busy && let Some(address) = capture.goto.take() {
            self.tab = match capture.tab.as_deref() {
                Some("graph") => Tab::Graph,
                Some("strings") => Tab::Strings,
                Some("crypto") => Tab::Crypto,
                Some("decode") => Tab::Decode,
                Some("hex") => Tab::Hex,
                Some("references") => Tab::References,
                _ => Tab::Listing,
            };
            self.navigate(address, true, context);
            return;
        }
        if !busy
            && self.view().is_some()
            && let Some(address) = capture.select.take()
        {
            self.select_instruction(address);
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
            return;
        }
        if !busy && std::mem::take(&mut capture.updates) {
            self.updater.open = true;
            context.request_repaint();
            return;
        }
        capture.tick(context, !busy);
    }
}

// Freeze the exact historical messages: similarly worded real warnings stay visible.
/// Search orchestration: dialogs, memory pages between maintenance turns,
/// paced text capture, staleness, cancellation and exact activation.
impl DesktopApp {
    /// Search needs a verified binary and the same guards as keyboard actions.
    fn search_available(&self) -> bool {
        self.info.is_some()
            && self.opening.is_none()
            && self.file_job.is_none()
            && self.signature_change.is_none()
    }

    fn open_search_dialog(&mut self, kind: DialogKind) {
        if self.search_available() {
            self.search_dialog = Some(SearchDialog::new(kind, self.generation));
        }
    }

    fn search_dialog_window(&mut self, context: &egui::Context) {
        let Some(mut dialog) = self.search_dialog.take() else {
            return;
        };
        if dialog.generation != self.generation || self.info.is_none() {
            return;
        }
        match crate::search_ui::show_dialog(context, &mut dialog, &mut self.search_form) {
            DialogResult::Open => self.search_dialog = Some(dialog),
            DialogResult::Close => {}
            DialogResult::Submit(Submit::Memory(spec, mode)) => {
                self.start_memory_search(spec, mode, context);
            }
            DialogResult::Submit(Submit::Text(spec)) => self.start_text_search(spec),
        }
    }

    /// Results already displayed stay in the store; search never evicts them.
    fn search_protect(&self) -> Vec<u64> {
        self.view().map(|view| view.address).into_iter().collect()
    }

    fn start_memory_search(
        &mut self,
        spec: crate::search::MemorySearchSpec,
        mode: MemoryMode,
        context: &egui::Context,
    ) {
        let protect = self.search_protect();
        let Some(info) = &self.info else {
            return;
        };
        let id = self.searches.next_id();
        let pattern = spec.canonical().unwrap_or_default();
        let session = self
            .results
            .reserve_transient(crate::search::MEMORY_SEARCH_RESERVATION_BYTES, &protect)
            .and_then(|reservation| {
                crate::search::MemorySearchSession::new(
                    info,
                    self.generation,
                    id,
                    spec,
                    reservation,
                )
                .ok()
            });
        self.searches.replace(Some(SearchView {
            id,
            kind: SearchKind::Memory(MemorySearch {
                session,
                mode,
                pattern,
                interrupted: false,
            }),
        }));
        self.tab = Tab::Search;
        // A stopped worker is replaced for an explicit search; the new one
        // must verify the same source and image before any page is sent.
        if self.client.is_none()
            && self.opening.is_none()
            && self.searches.memory_searching()
            && let Some(path) = self.binary_path.clone()
        {
            let continue_discovery = self.discovery_running;
            self.start_open(path, true, None, context);
            self.discovery_running = continue_discovery && self.client.is_some();
            self.update_discovery_summary();
        }
    }

    fn text_binding(&self, search_id: u64) -> Option<crate::search_text::TextBinding> {
        let info = self.info.as_ref()?;
        Some(crate::search_text::TextBinding {
            binary_sha256: info.sha256.clone(),
            generation: self.generation,
            search_id,
            annotation_revision: self.revision,
            inventory_revision: self.source_epochs.inventory,
            symbol_revision: self.symbol_revision,
            linkage_revision: self.source_epochs.linkage,
            strings_revision: self.source_epochs.strings,
            symbol_digest: None,
            linkage_digest: None,
        })
    }

    /// Whether every source revision a text search captured is unchanged.
    /// Selection is deliberately absent.
    fn text_sources_current(&self, binding: &crate::search_text::TextBinding) -> bool {
        self.info
            .as_ref()
            .is_some_and(|info| info.sha256 == binding.binary_sha256)
            && binding.generation == self.generation
            && binding.annotation_revision == self.revision
            && binding.inventory_revision == self.source_epochs.inventory
            && binding.symbol_revision == self.symbol_revision
            && binding.linkage_revision == self.source_epochs.linkage
            && binding.strings_revision == self.source_epochs.strings
    }

    fn start_text_search(&mut self, spec: crate::search_text::TextSearchSpec) {
        let id = self.searches.next_id();
        let Some(binding) = self.text_binding(id) else {
            return;
        };
        self.searches.replace(Some(SearchView {
            id,
            kind: SearchKind::Text(TextSearch::new(spec, binding)),
        }));
        self.tab = Tab::Search;
    }

    fn text_search_mut(&mut self) -> Option<&mut TextSearch> {
        match &mut self.searches.current {
            Some(SearchView {
                kind: SearchKind::Text(text),
                ..
            }) => Some(text),
            _ => None,
        }
    }

    /// One frame of program-text work: reap a retired job, notice source
    /// changes, then capture a bounded slice or poll the background matcher.
    fn pump_text_search(&mut self, context: &egui::Context) {
        let idle = self.searches.reap();
        let Some(SearchView {
            kind: SearchKind::Text(text),
            ..
        }) = &self.searches.current
        else {
            return;
        };
        let current = self.text_sources_current(&text.binding);
        if !current {
            self.searches.stale_text();
            return;
        }
        if text.state != SearchState::Searching {
            return;
        }
        let (spec, mut binding) = (text.spec.clone(), text.binding.clone());
        let phase = self
            .text_search_mut()
            .map(|text| std::mem::replace(&mut text.phase, TextPhase::Done))
            .expect("checked text search");
        enum Step {
            Phase(TextPhase),
            Finished(crate::search_text::TextSearchResult),
            Failed(SearchState),
        }
        let protect = self.search_protect();
        let step = match phase {
            TextPhase::Queued if !idle => Step::Phase(TextPhase::Queued),
            TextPhase::Queued => match self
                .results
                .reserve_transient(crate::search_text::TEXT_CORPUS_BASE_BYTES, &protect)
                .map(|lease| Capture::new(lease, spec.sources))
            {
                Some(Ok(capture)) => {
                    context.request_repaint();
                    Step::Phase(TextPhase::Capturing(Box::new(capture)))
                }
                _ => Step::Failed(SearchState::Unavailable),
            },
            TextPhase::Capturing(mut capture) => {
                let input = CaptureInput {
                    functions: self.info.as_ref().map_or(&[], |info| &info.functions),
                    names: if self.cached_functions {
                        crate::search_text::TextProvenance::Saved
                    } else {
                        crate::search_text::TextProvenance::Live
                    },
                    annotations: self.session.as_ref().map(|session| &session.annotations),
                    strings: &self.strings,
                    strings_provenance: if self.cached_strings {
                        crate::search_text::TextProvenance::Saved
                    } else {
                        crate::search_text::TextProvenance::Live
                    },
                };
                let results = &mut self.results;
                let mut admit = |reservation: &crate::result_store::TransientReservation, bytes| {
                    results.grow_transient(reservation, bytes, &protect)
                };
                if capture.step(&input, FILTER_FRAME_BUDGET, &mut admit) {
                    self.start_text_job(*capture, &spec, &mut binding, &protect)
                        .map_or_else(Step::Failed, |job| Step::Phase(TextPhase::Running(job)))
                } else {
                    context.request_repaint();
                    Step::Phase(TextPhase::Capturing(capture))
                }
            }
            TextPhase::Running(mut job) => match job.try_finish() {
                Ok(Some(result)) if result.binding == binding && result.spec == spec => {
                    Step::Finished(result)
                }
                Ok(Some(_)) => Step::Failed(SearchState::Stale),
                Ok(None) => {
                    context.request_repaint_after(Duration::from_millis(16));
                    Step::Phase(TextPhase::Running(job))
                }
                Err(_) => Step::Failed(SearchState::Unavailable),
            },
            TextPhase::Done => Step::Phase(TextPhase::Done),
        };
        let Some(text) = self.text_search_mut() else {
            return;
        };
        text.binding = binding;
        match step {
            Step::Phase(phase) => text.phase = phase,
            Step::Finished(result) => {
                text.state = result.state;
                text.result = Some(result);
            }
            Step::Failed(state) => text.state = state,
        }
    }

    /// Finishes a capture with the adopted immutable tables shared by Arc
    /// (never copied) and starts the background matcher.
    fn start_text_job(
        &mut self,
        capture: Capture,
        spec: &crate::search_text::TextSearchSpec,
        binding: &mut crate::search_text::TextBinding,
        protect: &[u64],
    ) -> Result<crate::search_text::TextJob, SearchState> {
        use crate::search_text::{SourceStatus, TextSources};
        let symbols = self
            .symbol_names
            .as_ref()
            .filter(|(generation, _)| *generation == self.generation)
            .map(|(_, names)| Arc::clone(names))
            .filter(|_| spec.sources.contains(TextSources::NAMES));
        let wants_linkage = spec.sources.contains(TextSources::IMPORTS)
            || spec.sources.contains(TextSources::EXPORTS);
        let linkage = self
            .linkage
            .prepared()
            .filter(|_| wants_linkage)
            .map(|prepared| prepared.shared_linkage())
            .filter(|linkage| self.results.share_linkage_charge(linkage));
        let names_missing = self.symbol_fetch.is_some()
            || self
                .symbol_failed
                .as_ref()
                .is_some_and(|(generation, _)| *generation == self.generation);
        let names = if names_missing
            || self
                .info
                .as_ref()
                .is_some_and(|info| info.functions_truncated)
        {
            SourceStatus::Partial
        } else {
            SourceStatus::Available
        };
        let declared = if linkage.is_some() {
            SourceStatus::Available
        } else {
            SourceStatus::Unavailable
        };
        let notes = if self.session.is_some() {
            SourceStatus::Available
        } else {
            SourceStatus::Unavailable
        };
        let strings = if !self.strings_scanned {
            SourceStatus::Unavailable
        } else if self.strings_truncated {
            SourceStatus::Partial
        } else {
            SourceStatus::Available
        };
        binding.symbol_digest = symbols.as_ref().map(|names| names.digest().to_owned());
        binding.linkage_digest = linkage.as_ref().map(|linkage| linkage.digest.clone());
        let corpus = capture.into_builder().finish(
            symbols,
            linkage,
            [names, declared, declared, notes, notes, strings],
        );
        let reservation = self
            .results
            .reserve_transient(crate::search_text::TEXT_JOB_RESERVATION_BYTES, protect)
            .ok_or(SearchState::Unavailable)?;
        crate::search_text::TextJob::start(corpus, spec.clone(), binding.clone(), reservation)
            .map_err(|_| SearchState::Unavailable)
    }

    /// The worker can take a memory page: no foreground work, replay,
    /// adoption or byte intent is waiting.
    fn worker_idle(&self) -> bool {
        self.client.is_some()
            && self.pending.is_none()
            && self.opening.is_none()
            && self.queue.is_empty()
            && self.signature_replay.is_none()
            && self.discovery_job.is_none()
            && self.deferred_discovery.is_none()
            && self.discovery_bytes.is_none()
            && !self.results.preparing()
    }

    /// Dispatches the next bounded memory page; attempts are charged here.
    fn pump_search(&mut self) -> bool {
        if !self.worker_idle() {
            return false;
        }
        let epoch = self.worker_epoch;
        let Some((_, memory)) = self.searches.memory_page() else {
            return false;
        };
        let Some(session) = &mut memory.session else {
            return false;
        };
        match session.next_request(epoch) {
            Ok(Some(request)) => {
                self.send_direct(request);
                self.pending.is_some()
            }
            Ok(None) => false,
            Err(error) => {
                session.unavailable();
                self.status = error;
                false
            }
        }
    }

    /// After foreground work, memory pages alternate with maintenance
    /// (symbol names, linkage, discovery) so neither starves the other. The
    /// first turn after a search starts is the search's; with no
    /// maintenance waiting, pages run back to back. Without a memory
    /// search the maintenance order is unchanged.
    fn pump_worker_turns(&mut self, context: &egui::Context) {
        if self.pending.is_some() || self.opening.is_some() {
            return;
        }
        let searching = self.searches.memory_page().is_some();
        if searching && self.searches.search_turn && self.pump_search() {
            self.searches.search_turn = false;
            return;
        }
        let start = if searching {
            self.searches.maintenance_turn
        } else {
            0
        };
        for offset in 0..3 {
            let which = (start + offset) % 3;
            match which {
                0 => self.pump_symbol_names(),
                1 => self.pump_linkage(),
                _ => self.pump_discovery(context),
            }
            if self.pending.is_some() || self.opening.is_some() {
                if searching {
                    self.searches.search_turn = true;
                    self.searches.maintenance_turn = (which + 1) % 3;
                }
                return;
            }
        }
        if searching && self.pump_search() {
            self.searches.search_turn = false;
        }
    }

    /// Adopts a page only for the displayed search, binary and worker epoch;
    /// a known stale page is dropped, a malformed current one stops the worker.
    fn receive_memory_page(
        &mut self,
        binding: crate::search::SearchBinding,
        page: crate::search::MemorySearchPage,
    ) {
        if binding.generation != self.generation || binding.worker_epoch != self.worker_epoch {
            return;
        }
        let Some(memory) = self.searches.memory(binding.search_id) else {
            return;
        };
        let Some(session) = &mut memory.session else {
            return;
        };
        if session.state() != SearchState::Searching {
            return;
        }
        if let Err(error) = session.accept(page) {
            session.unavailable();
            self.stop_worker();
            self.status =
                format!("Invalid worker response: memory search: {error}; worker stopped");
        }
    }

    /// The pending page timed out or its worker died: no automatic retry.
    fn fail_pending_search(&mut self) {
        if let Some(Pending {
            request: Request::SearchMemory { binding, .. },
            ..
        }) = &self.pending
        {
            let id = binding.search_id;
            if let Some(memory) = self.searches.memory(id)
                && let Some(session) = &mut memory.session
                && session.state() == SearchState::Searching
            {
                session.unavailable();
            }
        }
    }

    /// Ends an unfinished memory search, keeping its committed hits.
    fn end_memory_search(&mut self, state: SearchState) {
        if let Some(SearchView {
            kind: SearchKind::Memory(memory),
            ..
        }) = &mut self.searches.current
            && let Some(session) = &mut memory.session
            && session.state() == SearchState::Searching
        {
            match state {
                SearchState::Canceled => session.cancel(),
                _ => session.unavailable(),
            }
        }
    }

    /// Cancel invalidates the search at once. An active memory page is one
    /// bounded step, so it finishes and its late reply is dropped; replacing
    /// the worker would cost a full reopen. A queued page is never sent.
    fn cancel_search(&mut self) {
        let Some(view) = &self.searches.current else {
            return;
        };
        match view.kind {
            SearchKind::Memory(_) => self.end_memory_search(SearchState::Canceled),
            SearchKind::Text(_) => self.searches.cancel_text(),
        }
    }

    /// The function whose recovered CFG, genuine semantic mapping or recorded
    /// history observed exactly `pc` as an instruction.
    fn observed_owner(&self, pc: u64) -> Option<u64> {
        self.view()
            .filter(|view| {
                pc == view.address
                    || self.listing().contains(pc)
                    || self
                        .semantic
                        .mappings
                        .iter()
                        .any(|mapping| mapping.addresses.contains(&pc))
            })
            .map(|view| view.address)
            .or_else(|| self.comment_owners.get(&pc).copied())
    }

    /// The adopted linkage table when it is still the one `text` searched.
    fn search_linkage(&self, text: &TextSearch) -> Option<&crate::linkage::Linkage> {
        let linkage = self.linkage.prepared()?.linkage();
        (text.binding.linkage_digest.as_deref() == Some(linkage.digest.as_str())).then_some(linkage)
    }

    /// Where activating row `index` of `view` goes, decided from current
    /// evidence and the captured record's own facts, never snippet text.
    /// Without `observe`, owner evidence is skipped: a mapped address opens
    /// either way, so rows can ask per frame without scanning mappings.
    fn search_target(
        &self,
        view: &SearchView,
        index: usize,
        observe: bool,
    ) -> Option<SearchTarget> {
        let info = self.info.as_ref()?;
        let observed = |pc| observe.then(|| self.observed_owner(pc)).flatten();
        match &view.kind {
            SearchKind::Memory(memory) => {
                let hit = memory.hits().get(index)?;
                crate::search_jobs::resolve(info, hit.address, u64::from(hit.length), observed)
                    .map(SearchTarget::Address)
            }
            SearchKind::Text(text) => {
                use crate::search_text::TextSourceKey;
                let hit = text.hits().get(index)?;
                let item = match hit.key {
                    TextSourceKey::Import(id) => crate::linkage_ui::LinkageItem::Import(id),
                    TextSourceKey::Export(id) => crate::linkage_ui::LinkageItem::Export(id),
                    TextSourceKey::String(_) => {
                        // A preview start is data, opened exactly in Hex.
                        let address = hit.address?;
                        return crate::search_jobs::resolve(info, address, 1, |_| None).map(|_| {
                            SearchTarget::Address(Destination::Data { address, length: 1 })
                        });
                    }
                    TextSourceKey::Name(_)
                    | TextSourceKey::Label(_)
                    | TextSourceKey::Comment(_) => {
                        return crate::search_jobs::resolve(info, hit.address?, 1, observed)
                            .map(SearchTarget::Address);
                    }
                };
                let linkage = self.search_linkage(text)?;
                crate::linkage_ui::destination(linkage, item, self.pointer_width())
                    .map(|place| SearchTarget::Linkage(item, place))
            }
        }
    }

    fn open_search_result(&mut self, index: usize, context: &egui::Context) {
        let Some(view) = &self.searches.current else {
            return;
        };
        match self.search_target(view, index, true) {
            Some(SearchTarget::Address(Destination::Code { address, owner })) => {
                self.navigate_location(address, Some(owner), true, context);
            }
            Some(SearchTarget::Address(Destination::Data { address, length })) => {
                self.open_search_data(address, length, context);
            }
            Some(SearchTarget::Linkage(item, place)) => {
                self.open_linkage_place(item, place, context);
            }
            None => {}
        }
    }

    /// Exact bytes in Hex, recorded for Back/Forward. Unlike linkage places,
    /// a validated mapping at address zero is a real destination here.
    fn open_search_data(&mut self, address: u64, length: u64, context: &egui::Context) {
        self.string_focus = None;
        self.linkage_focus = false;
        self.record_destination(crate::linkage_ui::Place::Data { address, length }, address);
        self.open_data(address, length, context);
    }

    fn search_panel(&mut self, ui: &mut egui::Ui) {
        let context = ui.ctx().clone();
        let Some(view) = &self.searches.current else {
            theme::empty_state(ui, "No search");
            return;
        };
        let mut table = self.searches.table;
        let linkage = match &view.kind {
            SearchKind::Text(text) => self.search_linkage(text),
            SearchKind::Memory(_) => None,
        };
        let openable = |index| self.search_target(view, index, false).is_some();
        let action = crate::search_ui::show_results(
            ui,
            view,
            &mut table,
            &crate::search_ui::ResultContext {
                sections: self
                    .info
                    .as_ref()
                    .map_or(&[], |info| info.sections.as_slice()),
                linkage,
                pointer: self.pointer_width(),
                openable: &openable,
            },
        );
        self.searches.table = table;
        match action {
            Some(ResultAction::Open(index)) => self.open_search_result(index, &context),
            Some(ResultAction::OpenPlace(index, item, place)) => {
                let still = self.searches.current.as_ref().is_some_and(|view| {
                    matches!(&view.kind, SearchKind::Text(text)
                        if self.search_linkage(text).is_some()
                            && text.hits().get(index).is_some())
                });
                if still {
                    self.open_linkage_place(item, place, &context);
                }
            }
            Some(ResultAction::Cancel) => self.cancel_search(),
            Some(ResultAction::Edit(kind)) => self.open_search_dialog(kind),
            None => {}
        }
    }
}

/// A search row's resolved activation.
enum SearchTarget {
    Address(Destination),
    Linkage(crate::linkage_ui::LinkageItem, crate::linkage_ui::Place),
}

fn is_legacy_load_note(note: &str) -> bool {
    matches!(
        note,
        "Prototype analysis: symbols and supported PE function metadata load immediately; deeper function discovery is explicit. Optimized C++/Rust types and source reconstruction are incomplete."
            | "Function lists are capped at 262144 entries, 8 MiB of names, and 256 bytes per name in this prototype."
    )
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

/// Width ranges for the navigation dock, given the window width, and for the
/// decompiler dock, given the width left beside the navigation dock. Both
/// docks keep a usable minimum but never take the central views' minimum.
fn dock_ranges(width: f32) -> (egui::Rangef, impl Fn(f32) -> egui::Rangef) {
    let width = width.max(0.0);
    // Reserve frame margins and both resize gutters before sharing width.
    let usable = (width - 32.0).max(0.0);
    let scale = (usable / (180.0 + 240.0 + 260.0)).min(1.0);
    let central = 260.0 * scale;
    let right_min = 240.0 * scale;
    let left_max = (width * 0.35).min((usable - central - right_min).max(0.0));
    let left = egui::Rangef::new((180.0 * scale).min(left_max), left_max);
    let right = move |remaining: f32| {
        let max = (remaining - central - 32.0).max(0.0);
        egui::Rangef::new(right_min.min(max), max)
    };
    (left, right)
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
    }) + edit.signature.as_ref().map_or(0, |(_, before)| {
        16 + before.as_ref().map_or(0, |s| {
            s.engine.len()
                + s.abi.len()
                + 64
                + s.parameters
                    .iter()
                    .map(|p| p.name.len() + 32)
                    .sum::<usize>()
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

/// Context entries for exact reference targets; each is its own explicit
/// choice, so a multi-target selection never silently picks one.
fn xref_menu_items(
    ui: &mut egui::Ui,
    targets: &TargetSet,
    function: Option<u64>,
    chosen: &mut Option<XrefTarget>,
) {
    for target in &targets.targets {
        if ui
            .button(format!(
                "Xrefs to {} {:x}",
                target.kind.label(),
                target.address
            ))
            .clicked()
        {
            *chosen = Some(*target);
            ui.close();
        }
    }
    if targets.omitted() > 0 {
        ui.weak(format!("{} more targets omitted", targets.omitted()));
    }
    if let Some(function) = function
        && targets.targets.iter().all(|t| t.address != function)
        && ui.button("Xrefs to this function").clicked()
    {
        *chosen = Some(XrefTarget {
            address: function,
            kind: TargetKind::Function,
        });
        ui.close();
    }
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

/// Characters of a raw or displayed name shown in one tooltip.
const MAX_HOVER_NAME: usize = 512;

/// The shown name, and the raw symbol beneath it when that differs.
fn name_hover(shown: &str, raw: Option<&str>) -> String {
    match raw {
        Some(raw) => format!(
            "{}\n{}",
            crop(shown, MAX_HOVER_NAME),
            crop(raw, MAX_HOVER_NAME)
        ),
        None => crop(shown, MAX_HOVER_NAME),
    }
}

/// A function header that truncates long names rather than widening its dock.
fn function_title(
    ui: &mut egui::Ui,
    name: &str,
    raw: Option<&str>,
    address: u64,
) -> egui::Response {
    let title = format!("{}  {address:x}", crop(name, 120));
    let response = ui.add(
        egui::Label::new(RichText::new(&title).monospace().color(theme::BLUE))
            .truncate()
            .show_tooltip_when_elided(raw.is_none()),
    );
    match raw {
        Some(raw) => response.on_hover_text(name_hover(name, Some(raw))),
        None => response,
    }
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

    fn test_signature() -> FunctionSignature {
        FunctionSignature {
            function: 0x1000,
            engine: signatures::SIGNATURE_FINGERPRINT.into(),
            abi: "x86:LE:64:default:gcc".into(),
            return_type: signatures::SignatureType {
                base: signatures::SignatureBase::I64,
                pointer_depth: 0,
            },
            parameters: vec![signatures::SignatureParameter {
                name: "values".into(),
                ty: signatures::SignatureType {
                    base: signatures::SignatureBase::I32,
                    pointer_depth: 1,
                },
            }],
        }
    }

    fn signature_ack(
        app: &mut DesktopApp,
        signatures: Vec<FunctionSignature>,
        undone: Option<Edit>,
    ) -> (Pending, Response) {
        let function = 0x1000;
        let context = signatures::state_digest(&signatures);
        let binary_sha256 = app.info.as_ref().unwrap().sha256.clone();
        app.signature_change = Some(SignatureChange {
            function,
            before: app
                .session
                .as_ref()
                .unwrap()
                .signatures
                .iter()
                .find(|s| s.function == function)
                .cloned(),
            signatures: signatures.clone(),
            generation: app.generation,
            revision: app.revision,
            selection: app.selection_generation,
            epoch: app.worker_epoch,
            undone,
        });
        app.signature_replay = Some(SignatureReplay {
            signatures: signatures.clone(),
            context: context.clone(),
            generation: app.generation,
            revision: app.revision,
            epoch: app.worker_epoch,
            sent: true,
        });
        (
            Pending {
                id: 1,
                request: Request::SyncSignatures {
                    binary_sha256: binary_sha256.clone(),
                    context: context.clone(),
                    signatures,
                },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: None,
            },
            Response::SignaturesSynced {
                binary_sha256,
                context,
                unapplied: Vec::new(),
            },
        )
    }

    #[test]
    fn signature_edits_commit_only_after_ack_and_apply_remove_undo_are_single_edits() {
        let mut app = keyboard_app();
        let context = egui::Context::default();
        let signature = test_signature();
        let (pending, reply) = signature_ack(&mut app, vec![signature.clone()], None);
        assert!(
            app.session.as_ref().unwrap().signatures.is_empty(),
            "staged state is not saved"
        );
        assert!(app.undo.is_empty());
        app.receive(pending, reply, &context);
        assert_eq!(
            app.session.as_ref().unwrap().signatures.as_slice(),
            std::slice::from_ref(&signature)
        );
        assert_eq!(app.session.as_ref().unwrap().version, 3);
        assert_eq!((app.revision, app.undo.len()), (1, 1));
        let (pending, reply) = signature_ack(&mut app, vec![], None);
        app.receive(pending, reply, &context);
        assert!(app.session.as_ref().unwrap().signatures.is_empty());
        assert_eq!((app.revision, app.undo.len()), (2, 2));
        let edit = app.undo.pop_back().unwrap();
        assert_eq!(
            edit.signature.as_ref().unwrap().1.as_ref(),
            Some(&signature)
        );
        let (pending, reply) = signature_ack(&mut app, vec![signature.clone()], Some(edit));
        app.receive(pending, reply, &context);
        assert_eq!(app.session.as_ref().unwrap().signatures, [signature]);
        assert_eq!((app.revision, app.undo.len()), (3, 1));
        assert!(app.signature_recovery.is_none());
    }

    #[test]
    fn undo_restores_incompatible_saved_signatures_and_keeps_earlier_history_accessible() {
        for incompatible_abi in [false, true] {
            for replace in [false, true] {
                let mut app = keyboard_app();
                let context = egui::Context::default();
                let mut saved = test_signature();
                if incompatible_abi {
                    saved.abi = "x86:LE:64:default:windows".into();
                } else {
                    saved.engine = "older-signature-engine".into();
                }
                app.session.as_mut().unwrap().signatures = vec![saved.clone()];
                app.session.as_mut().unwrap().upgrade_version();
                app.edit_annotation(
                    0x1001,
                    Annotation {
                        comment: "earlier note".into(),
                        ..Annotation::default()
                    },
                );
                let replacement = if replace {
                    vec![test_signature()]
                } else {
                    vec![]
                };
                let (pending, reply) = signature_ack(&mut app, replacement, None);
                app.receive(pending, reply, &context);
                assert_eq!((app.revision, app.undo.len()), (2, 2));
                let edit = app.undo.pop_back().unwrap();
                let (pending, mut reply) = signature_ack(&mut app, vec![saved.clone()], Some(edit));
                let status = SignatureStatus {
                    function: saved.function,
                    reason: "Saved signature has an incompatible engine or ABI".into(),
                };
                if let Response::SignaturesSynced { unapplied, .. } = &mut reply {
                    unapplied.push(status);
                }
                app.receive(pending, reply, &context);
                assert_eq!(app.session.as_ref().unwrap().signatures, [saved.clone()]);
                assert_eq!((app.revision, app.undo.len()), (3, 1));
                assert_eq!(app.signature_unapplied.len(), 1);
                assert_eq!(app.signature_unapplied[0].function, saved.function);
                assert!(app.signature_change.is_none() && app.signature_replay.is_none());
                assert!(app.signature_recovery.is_none());
                app.undo(&context);
                assert_eq!((app.revision, app.undo.len()), (4, 0));
                assert!(app.session.as_ref().unwrap().annotations.is_empty());
                assert_eq!(app.session.as_ref().unwrap().signatures, [saved]);
            }
        }
    }

    #[test]
    fn failed_canceled_and_stale_signature_replays_retain_committed_state_and_recover_once() {
        for failure in 0..4 {
            let mut app = keyboard_app();
            let context = egui::Context::default();
            let committed = test_signature();
            app.session.as_mut().unwrap().signatures = vec![committed.clone()];
            app.session.as_mut().unwrap().upgrade_version();
            let mut replacement = committed.clone();
            replacement.parameters[0].ty.pointer_depth = 2;
            let undo = Edit {
                address: 0x1000,
                before: None,
                function_name: None,
                local: None,
                signature: Some((0x1000, Some(committed.clone()))),
            };
            let (pending, mut reply) = signature_ack(&mut app, vec![replacement], Some(undo));
            match failure {
                0 => app.stop_worker(),
                1 => app.receive(
                    pending,
                    Response::Error {
                        message: "storage rejected".into(),
                    },
                    &context,
                ),
                2 => {
                    app.selection_generation += 1;
                    app.receive(pending, reply, &context);
                }
                _ => {
                    if let Response::SignaturesSynced { unapplied, .. } = &mut reply {
                        unapplied.push(SignatureStatus {
                            function: 0x1000,
                            reason: "entry missing".into(),
                        });
                    }
                    app.receive(pending, reply, &context);
                }
            }
            assert_eq!(app.session.as_ref().unwrap().signatures, [committed]);
            assert_eq!((app.revision, app.undo.len()), (0, 1));
            assert!(app.signature_change.is_none() && app.signature_replay.is_none());
            assert_eq!(app.signature_recovery, Some(0x1000), "failure {failure}");
            // With no retained source, recovery consumes its one opportunity.
            // A failed baseline reopen has no staged edit to schedule more work.
            app.poll_worker(&context);
            assert!(app.signature_recovery.is_none());
            app.poll_worker(&context);
            assert!(app.client.is_none());
        }
    }

    #[test]
    fn signature_invalidation_clears_engine_results_and_preserves_byte_scans_and_navigation() {
        let mut app = semantic_app();
        app.strings_scanned = true;
        app.strings.push(StringEntry {
            address: 0x1010,
            text: "bytes".into(),
            encoding: "ASCII".into(),
        });
        app.crypto.push(CryptoMatch {
            address: 0x1010,
            algorithm: "constant".into(),
            signature: "bytes".into(),
            length: 4,
        });
        app.history = vec![0x1000, 0x1040]
            .into_iter()
            .map(crate::linkage_ui::Place::Code)
            .collect();
        app.history_index = 1;
        let selected = app.selected;
        app.comment_owners.insert(0x1001, 0x1000);
        let deferred_state = crate::discovery::Discovery::new(Some(0x1000), [0x1000], false);
        app.deferred_discovery = Some(DiscoveryUpdate {
            generation: app.generation,
            saved: Arc::new(deferred_state.save()),
            state: deferred_state,
            publication: Ok(None),
        });
        app.invalidate_signature_analysis();
        assert!(app.deferred_discovery.is_none());
        assert!(app.graph.is_none() && app.canvas.is_none() && app.listing().is_empty());
        assert!(
            app.code.is_none()
                && app.semantic.mappings.is_empty()
                && app.semantics().tokens.is_empty()
        );
        assert!(
            app.comment_owners.is_empty()
                && app.call_index.is_none()
                && app.discovery_saved.is_none()
        );
        assert!(app.strings_scanned && app.strings.len() == 1 && app.crypto.len() == 1);
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1000, 0x1040]
        );
        assert_eq!((app.history_index, app.selected), (1, selected));
    }

    #[test]
    fn signature_parameter_renames_route_to_editor_and_other_locals_keep_version_three() {
        let mut app = semantic_app();
        let context = egui::Context::default();
        app.session.as_mut().unwrap().signatures = vec![test_signature()];
        app.session.as_mut().unwrap().upgrade_version();
        let identity = LocalIdentity {
            function: 0x1000,
            engine: crate::semantic::SIGNATURE_LOCAL_FINGERPRINT.into(),
            storage: crate::semantic::LocalStorage::Register,
            offset: 0,
            size: 8,
            verification: "a".repeat(64),
        };
        edit_semantics(&mut app, |semantics| {
            semantics.locals.push(crate::semantic::LocalVariable {
                identity: identity.clone(),
                name: "values".into(),
                signature_parameter: Some(0),
            })
        });
        app.selected_local = Some(0);
        app.begin_rename();
        assert!(app.signature_editor.is_some() && app.browser_dialog.is_none());
        assert!(
            app.rename_local(&identity, "ignored", &context)
                .unwrap_err()
                .contains("function signature")
        );
        let mut other = identity.clone();
        other.offset = 8;
        other.verification = "b".repeat(64);
        edit_semantics(&mut app, |semantics| {
            semantics.locals.push(crate::semantic::LocalVariable {
                identity: other.clone(),
                name: "local_1".into(),
                signature_parameter: None,
            })
        });
        app.signature_editor = None;
        app.rename_local(&other, "renamed_local", &context).unwrap();
        assert_eq!(app.session.as_ref().unwrap().version, 3);
        assert_eq!(
            app.session.as_ref().unwrap().local_renames[0].name,
            "renamed_local"
        );
        assert_eq!(app.session.as_ref().unwrap().signatures, [test_signature()]);
    }

    #[test]
    fn refreshed_signature_selection_requires_an_instruction_in_the_fresh_graph() {
        for (old, expected) in [(0x1004, 0x1004), (0x1010, 0x1000)] {
            let mut app = semantic_app();
            app.auto_decompile = false;
            let view = app.view().unwrap().clone();
            app.selected = Some(old);
            app.signature_restore_pc = Some((0x1000, old));
            let pending = Pending {
                id: 1,
                request: Request::Graph { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: None,
            };
            app.receive(pending, Response::Graph { view }, &egui::Context::default());
            assert_eq!(app.selected, Some(expected));
            assert!(app.signature_restore_pc.is_none());
        }
    }

    #[test]
    fn signature_editor_uses_structured_inference_and_discards_stale_drafts() {
        let mut app = semantic_app();
        edit_semantics(&mut app, |semantics| {
            semantics.prototype = Some(signatures::InferredSignature {
                return_type: None,
                abi: "x86:LE:64:default:gcc".into(),
                parameters: vec![signatures::InferredParameter {
                    name: "value".into(),
                    ty: None,
                }],
                unsupported: vec!["Floating point type is unsupported".into()],
            })
        });
        app.begin_signature_editor();
        let editor = app.signature_editor.as_ref().unwrap();
        assert!(editor.return_type.is_none() && editor.parameters[0].ty.is_none());
        assert!(editor.notes[0].contains("unsupported"));
        app.revision += 1;
        app.signature_window(&egui::Context::default());
        assert!(
            app.signature_editor.is_none() && app.session.as_ref().unwrap().signatures.is_empty()
        );
    }

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
            bytes: None,
            result: None,
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
            bytes: None,
            result: None,
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
                bytes: None,
                result: None,
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
        assert!(app.graph.is_none() && app.listing().is_empty());

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
                bytes: None,
                result: None,
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

    pub(super) fn keyboard_app() -> DesktopApp {
        let mut app = DesktopApp::empty(None);
        app.info = Some(BinaryInfo {
            path: "fixture".into(),
            architecture: "x86-64".into(),
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

    fn symbol_reply(
        app: &DesktopApp,
        cursor: usize,
        page: crate::model::SymbolNamePage,
    ) -> (Pending, Response) {
        (
            Pending {
                id: 1,
                request: Request::SymbolNames { cursor },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: None,
            },
            Response::SymbolNames { page },
        )
    }

    fn demangled_app() -> (DesktopApp, crate::symbol_names::SymbolTable) {
        let mut app = keyboard_app();
        // A PE export keeps its raw engine name; only the table demangles it.
        app.info.as_mut().unwrap().functions[0].name = "_ZN4demo3fooEv".into();
        let table = crate::symbol_names::SymbolTable::build(
            [crate::symbol_names::SymbolSource {
                address: 0x1000,
                raw: "_ZN4demo3fooEv",
                engine: "_ZN4demo3fooEv",
            }],
            crate::symbol_names::SymbolFormat::Other,
        );
        app.begin_symbol_names(Some(table.summary().clone()));
        (app, table)
    }

    #[test]
    fn demangled_names_display_filter_and_go_to_by_either_form_while_labels_win() {
        let context = egui::Context::default();
        let (mut app, table) = demangled_app();
        assert_eq!(app.function_names(0x1000), Some(("_ZN4demo3fooEv", None)));
        let (pending, reply) = symbol_reply(&app, 0, table.page(0).unwrap());
        app.receive(pending, reply, &context);
        assert!(app.symbol_fetch.is_none());
        assert_eq!(
            app.function_names(0x1000),
            Some(("demo::foo", Some("_ZN4demo3fooEv")))
        );
        assert_eq!(app.function_names(0x1040), Some(("next", None)));
        // Names alone never become annotations, history or unsaved changes.
        assert!(app.session.as_ref().unwrap().annotations.is_empty());
        assert_eq!((app.revision, app.undo.len()), (0, 0));
        assert_eq!(
            app.info.as_ref().unwrap().functions[0].name,
            "_ZN4demo3fooEv"
        );
        assert_eq!(app.resolve_location("_ZN4demo3fooEv"), Ok(0x1000));
        assert_eq!(app.resolve_location("demo::foo"), Ok(0x1000));
        assert!(app.resolve_location("demo::fo").is_err());
        for query in ["DEMO::F", "3fooev"] {
            app.function_filter = query.into();
            app.restart_filter();
            assert_eq!(app.filtered_functions, [0], "{query}");
        }
        app.edit_annotation(
            0x1000,
            Annotation {
                label: "analyst_name".into(),
                ..Annotation::default()
            },
        );
        assert_eq!(
            app.function_names(0x1000),
            Some(("analyst_name", Some("_ZN4demo3fooEv")))
        );
        assert_eq!(app.reference_name(0x1000), Some("analyst_name"));
        app.function_filter = "analyst".into();
        app.restart_filter();
        assert_eq!(app.filtered_functions, [0]);
        // The label stays bound to the address, never to either name.
        let session = app.session.as_ref().unwrap();
        assert_eq!(session.annotations.len(), 1);
        assert_eq!(session.annotations[&0x1000].label, "analyst_name");
        assert_eq!(app.resolve_location("analyst_name"), Ok(0x1000));
        assert_eq!(app.resolve_location("_ZN4demo3fooEv"), Ok(0x1000));
    }

    #[test]
    fn stale_and_invalid_symbol_pages_never_adopt_names_or_retry() {
        let context = egui::Context::default();
        let (mut app, table) = demangled_app();
        let page = table.page(0).unwrap();
        // Another worker epoch or binary generation cannot complete this table.
        app.worker_epoch += 1;
        let (pending, reply) = symbol_reply(&app, 0, page.clone());
        app.receive(pending, reply, &context);
        assert!(app.symbols().is_none() && app.symbol_fetch.is_some());
        app.worker_epoch -= 1;
        app.generation += 1;
        let (pending, reply) = symbol_reply(&app, 0, page.clone());
        app.receive(pending, reply, &context);
        assert!(app.symbols().is_none());
        app.generation -= 1;
        let mut tampered = page.clone();
        tampered.entries[0].display = Some("demo::bar".into());
        let (pending, reply) = symbol_reply(&app, 0, tampered);
        app.receive(pending, reply, &context);
        assert!(app.status.contains("symbol names"), "{}", app.status);
        assert!(app.symbols().is_none() && app.symbol_fetch.is_none());
        assert_eq!(app.function_names(0x1000), Some(("_ZN4demo3fooEv", None)));
        // A replacement worker announcing the same table does not refetch it.
        app.begin_symbol_names(Some(table.summary().clone()));
        assert!(app.symbol_fetch.is_none());
        // An adopted table also survives a replacement worker for the same image.
        app.symbol_failed = None;
        app.begin_symbol_names(Some(table.summary().clone()));
        let (pending, reply) = symbol_reply(&app, 0, page);
        app.receive(pending, reply, &context);
        assert!(app.symbols().is_some());
        app.worker_epoch += 1;
        app.begin_symbol_names(Some(table.summary().clone()));
        assert!(app.symbol_fetch.is_none() && app.symbols().is_some());
    }

    #[test]
    fn data_targets_request_bytes_without_function_navigation_or_stale_selection() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        app.tab = Tab::References;
        app.semantic.select_instruction(0x1004);
        let function = app.view().unwrap().address;
        let history = app.history.clone();
        let generation = app.selection_generation;
        let selected = app.selected;
        let semantic_addresses = app.semantic.addresses.clone();
        app.read_data_reference(0x1080, 4, &context);
        assert_eq!(app.selected, selected);
        assert_eq!(app.xref_target.map(|t| t.address), Some(0x1080));
        assert_eq!(app.view().unwrap().address, function);
        assert_eq!(app.history, history);
        assert_eq!(app.selection_generation, generation);
        assert_eq!(app.semantic.addresses, semantic_addresses);
        assert!(app.tab == Tab::References);

        // The same reply can complete a read without stealing a newer tab.
        for changed in 0..5 {
            app.tab = Tab::References;
            app.status = "waiting".into();
            let pending = Pending {
                result: None,
                id: 1,
                request: Request::Bytes {
                    address: 0x1080,
                    length: 4,
                },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: Some(ByteBinding {
                    generation: app.generation,
                    intent: app.byte_intent,
                    destination: ByteDestination::Decode,
                }),
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
    fn propagated_access_hover_preserves_row_navigation() {
        let context = egui::Context::default();
        theme::install(&context);
        context.style_mut_of(egui::Theme::Dark, |style| {
            style.interaction.tooltip_delay = 0.0
        });
        let mut app = semantic_app();
        app.info.as_mut().unwrap().architecture = "AArch64".into();
        app.reference_data = true;
        let report = CallAnalysis {
            data: Some(DataAnalysis {
                references: vec![DataReference {
                    function: 0x1000,
                    address: 0x1004,
                    target: 0x1080,
                    size: 4,
                    access: DataAccess::Read,
                    provenance: DataProvenance::Propagated,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        let index = crate::call_analysis::CallIndex::new(report);
        app.set_call_index(Some(Arc::new(index)));
        let frame = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    time: Some(context.input(|input| input.time) + 0.25),
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 400.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| {
                    app.data_references_panel(ui, Some((0x1000, false)));
                },
            );
            output.textures_delta.clear();
            output
        };
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        let pos = text_position(&output, "Read*", 0) + egui::vec2(6.0, 5.0);
        frame(&mut app, vec![egui::Event::PointerMoved(pos)]);
        let output = frame(&mut app, vec![]);
        assert!(
            rendered_text(&output)
                .iter()
                .any(|text| text.contains("* Address from register constants in this block."))
        );
        frame(&mut app, pointer_events(pos));
        assert_eq!(app.selected, Some(0x1004));
        assert!(app.tab == Tab::Listing);
    }

    #[test]
    fn missing_inferred_signature_is_discoverable_in_warning_menu() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        edit_semantics(&mut app, |semantics| semantics.prototype = None);
        app.begin_signature_editor();
        let frame = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(900.0, 600.0),
                    )),
                    events,
                    ..Default::default()
                },
                |_| app.signature_window(&context),
            );
            output.textures_delta.clear();
            output
        };
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        let pos = text_position(&output, "    1", 0) + egui::vec2(8.0, 5.0);
        frame(&mut app, pointer_events(pos));
        let output = frame(&mut app, vec![]);
        assert!(rendered_text(&output).iter().any(|text| {
            text.contains("No inferred prototype. Choose types or refresh decompilation.")
        }));
        assert!(app.signature_editor.as_ref().unwrap().return_type.is_none());
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
                bytes: None,
                result: None,
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
        app.xref_target = Some(XrefTarget {
            address: 0x1080,
            kind: TargetKind::DataAccess,
        });
        app.reference_query = "1080".into();
        app.clear_views();
        assert!(app.call_index.is_none());
        assert!(!app.reference_data);
        assert!(app.xref_target.is_none());
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
    fn help_shortcut_respects_focus_dialogs_repeats_and_file_jobs() {
        let f1 = || {
            let press = key_event(egui::Key::F1, egui::Modifiers::NONE);
            let mut release = press.clone();
            if let egui::Event::Key { pressed, .. } = &mut release {
                *pressed = false;
            }
            vec![press, release]
        };
        // Exercise the first frame of a non-editing modal independently of
        // any previous dialog's keyboard focus or modal layer.
        {
            let context = egui::Context::default();
            let mut app = keyboard_app();
            app.analyze_prompt = Some(AnalyzePrompt {
                generation: app.generation,
                first_open: true,
            });
            keyboard_frame(&context, &mut app, f1());
            assert!(app.help_dialog.is_none());
        }
        let context = egui::Context::default();
        let mut app = keyboard_app();
        keyboard_frame(&context, &mut app, vec![]);
        let filter = egui::Id::unique("function-filter");
        context.memory_mut(|memory| memory.request_focus(filter));
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, f1());
        assert!(app.help_dialog.is_none());
        context.memory_mut(|memory| memory.surrender_focus(filter));

        let (_sender, receiver) = mpsc::sync_channel(1);
        app.file_job = Some(receiver);
        keyboard_frame(&context, &mut app, f1());
        assert!(app.help_dialog.is_none());
        app.file_job = None;

        app.begin_go_to();
        keyboard_frame(&context, &mut app, f1());
        assert!(app.help_dialog.is_none());
        app.browser_dialog = None;

        // A modal without a text editor must block Help too.
        app.analyze_prompt = Some(AnalyzePrompt {
            generation: app.generation,
            first_open: true,
        });
        keyboard_frame(&context, &mut app, f1());
        assert!(app.help_dialog.is_none());
        app.analyze_prompt = None;
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, vec![]);

        // Hold F1 across the end of a file job. egui derives repeat from
        // whether the key was already down, rather than trusting the flag.
        let (_sender, receiver) = mpsc::sync_channel(1);
        app.file_job = Some(receiver);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::F1, egui::Modifiers::NONE)],
        );
        app.file_job = None;
        let mut repeat = key_event(egui::Key::F1, egui::Modifiers::NONE);
        if let egui::Event::Key { repeat, .. } = &mut repeat {
            *repeat = true;
        }
        keyboard_frame(&context, &mut app, vec![repeat]);
        assert!(app.help_dialog.is_none());
        let mut release = key_event(egui::Key::F1, egui::Modifiers::NONE);
        if let egui::Event::Key { pressed, .. } = &mut release {
            *pressed = false;
        }
        keyboard_frame(&context, &mut app, vec![release.clone()]);
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::F1, egui::Modifiers::SHIFT)],
        );
        assert!(app.help_dialog.is_none());
        keyboard_frame(&context, &mut app, vec![release]);
        keyboard_frame(&context, &mut app, f1());
        assert_eq!(app.help_dialog, Some(crate::help::HelpDialog::Shortcuts));
    }

    #[test]
    fn help_menu_dialogs_close_and_f1_works_without_a_binary() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = DesktopApp::empty(None);
        let frame = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 800.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
            output.textures_delta.clear();
            output
        };
        let click = |output: &egui::FullOutput, label: &str| {
            let position = output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text) if text.galley.text() == label => {
                        Some(text.pos + text.galley.rect.center().to_vec2())
                    }
                    _ => None,
                })
                .expect("visible Help control");
            pointer_events(position)
        };
        frame(
            &mut app,
            vec![key_event(egui::Key::F1, egui::Modifiers::NONE)],
        );
        assert_eq!(app.help_dialog, Some(crate::help::HelpDialog::Shortcuts));
        frame(&mut app, vec![]);
        frame(&mut app, vec![]);
        frame(
            &mut app,
            vec![key_event(egui::Key::Escape, egui::Modifiers::NONE)],
        );
        assert!(app.help_dialog.is_none());
        app = keyboard_app();
        for (label, expected) in [
            ("Keyboard shortcuts", crate::help::HelpDialog::Shortcuts),
            ("About Ghidra Rust", crate::help::HelpDialog::About),
        ] {
            let output = frame(&mut app, vec![]);
            frame(&mut app, click(&output, "Help"));
            frame(&mut app, vec![]);
            let output = frame(&mut app, vec![]);
            frame(&mut app, click(&output, label));
            assert_eq!(app.help_dialog, Some(expected));
            assert!(!egui::Popup::is_any_open(&context));
            frame(&mut app, vec![]);
            let output = frame(&mut app, vec![]);
            // Help owns keyboard focus; background navigation cannot run.
            frame(
                &mut app,
                vec![key_event(egui::Key::Space, egui::Modifiers::NONE)],
            );
            assert!(app.tab == Tab::Listing);
            frame(&mut app, click(&output, "×"));
            assert!(app.help_dialog.is_none());
        }
        let output = frame(&mut app, vec![]);
        frame(&mut app, click(&output, "Help"));
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        frame(&mut app, click(&output, "Check for updates…"));
        assert!(app.updater.open);
        frame(&mut app, vec![]);
        frame(
            &mut app,
            vec![key_event(egui::Key::Space, egui::Modifiers::NONE)],
        );
        assert!(app.tab == Tab::Listing);
        frame(
            &mut app,
            vec![key_event(egui::Key::F1, egui::Modifiers::NONE)],
        );
        assert!(app.help_dialog.is_none());
        frame(&mut app, vec![]);
        frame(
            &mut app,
            vec![key_event(egui::Key::Escape, egui::Modifiers::NONE)],
        );
        assert!(!app.updater.open);
    }

    #[test]
    fn update_restart_intent_uses_save_prompt_and_cancel_keeps_the_session() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = keyboard_app();
        app.revision = app.saved_revision + 1;
        let selection = app.selected;
        app.request_intent(Intent::InstallUpdate, &context);
        assert!(matches!(app.intent, Some(Intent::InstallUpdate)));
        assert!(app.dirty());
        assert!(!app.quit_confirmed);
        assert!(app.restart.take().is_none());
        // Cancelling the save prompt neither installs nor discards anything.
        let draw = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 800.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| app.draw(ui),
            );
            output.textures_delta.clear();
            output
        };
        draw(&mut app, vec![]);
        let output = draw(&mut app, vec![]);
        let position = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if text.galley.text() == "Cancel" => {
                    Some(text.pos + text.galley.rect.center().to_vec2())
                }
                _ => None,
            })
            .expect("save prompt Cancel control");
        draw(&mut app, pointer_events(position));
        assert!(app.intent.is_none());
        assert_eq!(app.selected, selection);
        assert!(app.dirty());
        // A save that still has newer edits must present the prompt again.
        app.after_save = Some(Intent::InstallUpdate);
        app.finish_save(&context);
        assert!(matches!(app.intent, Some(Intent::InstallUpdate)));
        assert!(!app.quit_confirmed);
    }

    #[test]
    fn closing_during_install_cannot_reopen_a_discard_prompt_or_exit_early() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = keyboard_app();
        // Discarding unsaved work before installation leaves the revision dirty.
        app.revision = app.saved_revision + 1;
        let (job, _completion) = crate::updater::Job::pending_for_test();
        app.updater.install(job);
        let mut input = egui::RawInput::default();
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .events
            .push(egui::ViewportEvent::Close);
        let mut output = context.run_ui(input, |ui| app.draw(ui));
        output.textures_delta.clear();
        assert!(app.updater.installing());
        assert!(app.intent.is_none());
        assert!(!app.quit_confirmed);
        assert!(app.restart.take().is_none());
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
        for tab in [Tab::Listing, Tab::Hex] {
            let context = egui::Context::default();
            let mut app = keyboard_app();
            app.tab = tab;
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
            assert!(app.tab == tab);
            assert!(!app.dirty());
        }
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
        app.history = vec![0x1000, 0x1040]
            .into_iter()
            .map(crate::linkage_ui::Place::Code)
            .collect();
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
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1000, 0x1040]
        );
        app.navigate(0x1080, true, &context);
        app.history_step(false, &context);
        app.navigate(0x10c0, true, &context);
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1000, 0x1040, 0x10c0]
        );
    }

    fn edit_view(app: &mut DesktopApp, edit: impl FnOnce(&mut FunctionView)) {
        let mut view = app.view().unwrap().clone();
        edit(&mut view);
        show_view(app, view);
    }

    pub(super) fn set_listing(app: &mut DesktopApp, instructions: Vec<Instruction>) {
        let address = instructions.first().map_or(0, |i| i.address);
        edit_view(app, |view| {
            view.address = address;
            view.blocks = vec![BasicBlock {
                address,
                instructions,
            }];
        });
    }

    /// Displays `view` as an unstored live result.
    pub(super) fn show_view(app: &mut DesktopApp, view: FunctionView) {
        let graph =
            app.results
                .admit_graph(None, PreparedGraph::new(view), ResultOrigin::Computed, None);
        app.canvas = Some(GraphCanvas::with_geometry(graph.view(), graph.geometry()));
        app.graph = Some(graph);
    }

    /// Displays one unstored decompilation, keeping the current selection.
    fn show_code(
        app: &mut DesktopApp,
        text: &str,
        mappings: Vec<CodeMapping>,
        semantics: SemanticInfo,
    ) {
        let address = app.view().map_or(0, |view| view.address);
        let code = app.results.admit_decompilation(
            None,
            PreparedDecompilation::prepare(address, text.into(), mappings, semantics),
            ResultOrigin::Computed,
            None,
        );
        app.semantic.mappings = code.mappings().clone();
        app.code = Some(code);
    }

    /// Replaces the displayed decompilation's semantics, as a new reply would.
    fn edit_semantics(app: &mut DesktopApp, edit: impl FnOnce(&mut SemanticInfo)) {
        let mut semantics = app.semantics().clone();
        edit(&mut semantics);
        let text = app.decompiled().to_owned();
        let mappings = app.semantic.mappings.to_vec();
        show_code(app, &text, mappings, semantics);
    }

    /// Appends an instruction to the first block of the displayed graph.
    fn push_instruction(app: &mut DesktopApp, instruction: Instruction) {
        let mut view = app.view().unwrap().clone();
        view.blocks[0].instructions.push(instruction);
        show_view(app, view);
    }

    fn call_navigation_app(text: &str) -> DesktopApp {
        let mut app = keyboard_app();
        show_view(
            &mut app,
            FunctionView {
                address: 0x1000,
                blocks: vec![],
                edges: vec![],
                calls: vec![CallSite {
                    address: 0x1004,
                    target: Some(0x1040),
                    no_return: None,
                }],
                warnings: vec![],
            },
        );
        show_code(&mut app, text, vec![], SemanticInfo::default());
        app.history = vec![0x1000]
            .into_iter()
            .map(crate::linkage_ui::Place::Code)
            .collect();
        app
    }

    pub(super) fn semantic_app() -> DesktopApp {
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
        let mut view = app.view().unwrap().clone();
        view.calls.clear();
        view.blocks = vec![BasicBlock {
            address: 0x1000,
            instructions,
        }];
        show_view(&mut app, view);
        show_code(
            &mut app,
            source,
            vec![CodeMapping {
                start: source.find("return").unwrap(),
                end: source.find(';').unwrap() + 1,
                addresses: vec![0x1004, 0x1008],
            }],
            SemanticInfo::default(),
        );
        app.semantic.select_instruction(0x1000);
        app
    }

    pub(super) fn pointer_events(point: egui::Pos2) -> Vec<egui::Event> {
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
    fn narrow_decompiler_header_keeps_actions_reachable_and_copies_full_source() {
        for scale in [1.0, 1.25] {
            for width in [180.0, 240.0, 260.0, 700.0] {
                let context = egui::Context::default();
                theme::install(&context);
                context.set_pixels_per_point(scale);
                context.all_styles_mut(|style| style.animation_time = 0.0);
                let mut app = semantic_app();
                app.saved_analysis = true;
                let source = app.decompiled().to_owned();
                let mut draw = |events| {
                    let time = context.input(|input| input.time) + 0.1;
                    let mut output = context.run_ui(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                egui::vec2(width, 500.0),
                            )),
                            time: Some(time),
                            events,
                            ..Default::default()
                        },
                        |ui| app.side_panel(ui),
                    );
                    output.textures_delta.clear();
                    output
                };
                draw(vec![]);
                if width == 240.0 {
                    let output = draw(vec![]);
                    for label in ["Decompiler", "Copy", "Refresh", "Saved"] {
                        assert!(
                            !exact_text(&output, label).is_empty(),
                            "inline {label} at {scale}"
                        );
                    }
                    for shape in &output.shapes {
                        if let egui::Shape::Text(text) = &shape.shape
                            && ["Decompiler", "Saved"].contains(&text.galley.text())
                        {
                            assert!(!text.galley.elided);
                            assert!(
                                shape
                                    .clip_rect
                                    .contains_rect(text.galley.rect.translate(text.pos.to_vec2()))
                            );
                        }
                    }
                }
                for label in ["Copy", "Auto"] {
                    let output = draw(vec![]);
                    if exact_text(&output, label).is_empty() {
                        let more = exact_text(&output, "⋯")[0];
                        draw(pointer_events(more));
                        draw(vec![]);
                    }
                    let output = draw(vec![]);
                    let target = exact_text(&output, label)[0];
                    let output = draw(pointer_events(target));
                    if label == "Copy" {
                        assert!(output.platform_output.commands.iter().any(|command| matches!(command, egui::OutputCommand::CopyText(text) if text == &source)), "full source copied at {width}/{scale}");
                    }
                }
                assert!(
                    !app.auto_decompile,
                    "Auto toggles through its actual control"
                );
            }
        }
    }

    fn rendered_listing_rows(output: &egui::FullOutput) -> Vec<String> {
        let anchors: Vec<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text)
                    if text.galley.text().len() == 8
                        && text.galley.text().bytes().all(|c| c.is_ascii_hexdigit()) =>
                {
                    Some(text.pos.y)
                }
                _ => None,
            })
            .collect();
        anchors
            .into_iter()
            .map(|y| {
                let mut cells: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) if (text.pos.y - y).abs() < 1.0 => {
                            Some((text.pos.x, text.galley.text()))
                        }
                        _ => None,
                    })
                    .collect();
                cells.sort_by(|a, b| a.0.total_cmp(&b.0));
                cells
                    .into_iter()
                    .map(|(_, text)| text)
                    .collect::<Vec<_>>()
                    .join(" ")
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
        push_instruction(&mut app, instruction);
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
        let original_source = app.decompiled().to_owned();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
        output.textures_delta.clear();
        let listing = rendered_listing_rows(&output);
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
        assert_eq!(app.decompiled(), original_source);
        let mapping = &app.semantic.mappings[0];
        assert_eq!(
            &app.decompiled()[mapping.start..mapping.end],
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
        assert_eq!(app.decompiled(), original_source);
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
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1004, 0x1008]
        );
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
        let text: String = (0..200).map(|n| format!("statement_{n}();\n")).collect();
        show_code(&mut app, &text, vec![], SemanticInfo::default());
        app.semantic.mappings = vec![CodeMapping {
            start: code_lines(&app.code)[150].0,
            end: code_lines(&app.code)[150].1 - 1,
            addresses: vec![0x1004],
        }]
        .into();
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
        app.history = vec![0x1000, 0x1004]
            .into_iter()
            .map(crate::linkage_ui::Place::Code)
            .collect();
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
        assert_eq!(app.view().unwrap().address, 0x1000);
    }

    #[test]
    fn annotation_navigation_reuses_observed_owner_without_guessing_symbol_extents() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        let original_view = app.view().unwrap().clone();
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
                bytes: None,
                result: None,
            },
            Response::Graph {
                view: original_view,
            },
            &context,
        );
        assert_eq!(app.view().unwrap().address, 0x1000);
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.pending_listing_scroll, Some(2));
        app.update_comment_rows();
        assert!(app.comment_rows.rows.contains(&CodeRow::Comment(0x1008)));
        // An address numerically between symbols has no known owner.
        app.navigate_annotation(0x1020, true, &context);
        assert_eq!(app.reference_focus, Some((0x1020, 0x1020)));
        assert_eq!(app.selected, Some(0x1020));
    }

    pub(super) fn text_position(
        output: &egui::FullOutput,
        needle: &str,
        byte: usize,
    ) -> egui::Pos2 {
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
            app.decompiled().find("café").unwrap() + 3,
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
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1000]
        );
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
    fn each_function_listing_keeps_its_own_scroll_position() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        let function = |entry: u64| -> Vec<Instruction> {
            (0..2000u64)
                .map(|row| Instruction {
                    address: entry + row * 4,
                    bytes: vec![0x90],
                    mnemonic: "nop".into(),
                    operands: String::new(),
                })
                .collect()
        };
        let frame = |app: &mut DesktopApp| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(700.0, 500.0),
                    )),
                    ..Default::default()
                },
                |ui| app.main_panel(ui),
            );
            output.textures_delta.clear();
            rendered_text(&output).join("\n")
        };
        set_listing(&mut app, function(0x1000));
        app.comment_rows_key = None;
        app.pending_listing_scroll = Some(1500);
        frame(&mut app);
        let text = frame(&mut app);
        assert!(text.contains(&format!("{:08x}", 0x1000 + 1500 * 4)));
        assert!(!text.contains("00001000"));
        // Another function starts at its first instruction, not at row 1500.
        edit_view(&mut app, |view| view.address = 0x9000);
        set_listing(&mut app, function(0x9000));
        app.comment_rows_key = None;
        let text = frame(&mut app);
        assert!(text.contains("00009000"), "{text}");
        // Returning restores the earlier function's position.
        edit_view(&mut app, |view| view.address = 0x1000);
        set_listing(&mut app, function(0x1000));
        app.comment_rows_key = None;
        assert!(frame(&mut app).contains(&format!("{:08x}", 0x1000 + 1500 * 4)));
    }

    #[test]
    fn side_docks_leave_the_central_views_room_as_the_window_shrinks() {
        for width in [
            0.0_f32, 20.0, 200.0, 400.0, 680.0, 700.0, 760.0, 1024.0, 1440.0, 2560.0,
        ] {
            let (left, right_range) = dock_ranges(width);
            for left_width in [left.min, left.max] {
                let right = right_range(width - left_width);
                for range in [left, right] {
                    assert!(range.min.is_finite() && range.max.is_finite());
                    assert!(
                        0.0 <= range.min && range.min <= range.max,
                        "{width}: {range:?}"
                    );
                }
                let usable = (width - 32.0).max(0.0);
                let central = 260.0 * (usable / 680.0).min(1.0);
                assert!(width - left_width - right.max + 0.001 >= central, "{width}");
            }
        }
    }

    #[test]
    fn narrow_listing_clips_long_instructions_without_horizontal_scrolling() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        let operands = "rax, qword ptr [rip + a_long_symbol_name_that_exceeds_the_pane_width]";
        edit_view(&mut app, |view| {
            for instruction in view.blocks.iter_mut().flat_map(|b| &mut b.instructions) {
                instruction.operands = operands.into();
            }
        });
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
        assert_eq!(rows.len(), app.listing().len());
        for row in rows {
            assert_eq!(
                row.rows.len(),
                1,
                "long instructions must not consume adjacent rows"
            );
            assert!(row.rect.width() < 360.0, "fit the operand cell");
            assert!(row.elided, "long operands are visibly ellipsized");
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

    /// `semantic_app` with a call at 0x1004 and two accesses at 0x1008.
    fn xref_app() -> DesktopApp {
        let mut app = semantic_app();
        edit_view(&mut app, |view| {
            view.calls = vec![CallSite {
                address: 0x1004,
                target: Some(0x1040),
                no_return: None,
            }]
        });
        let data = |target, access| DataReference {
            function: 0x1000,
            address: 0x1008,
            target,
            size: 4,
            access,
            provenance: DataProvenance::InstructionLocal,
        };
        app.set_call_index(Some(Arc::new(crate::call_analysis::CallIndex::new(
            CallAnalysis {
                references: vec![
                    CallReference {
                        caller: 0x1000,
                        address: 0x1004,
                        target: 0x1040,
                    },
                    CallReference {
                        caller: 0x1040,
                        address: 0x1044,
                        target: 0x1040,
                    },
                ],
                data: Some(DataAnalysis {
                    references: vec![
                        data(0x2000, DataAccess::Read),
                        data(0x2010, DataAccess::Write),
                    ],
                    ..Default::default()
                }),
                functions_examined: 2,
                decode_attempts: 8,
                ..Default::default()
            },
        ))));
        app
    }

    fn secondary_events(point: egui::Pos2) -> Vec<egui::Event> {
        let button = |pressed| egui::Event::PointerButton {
            pos: point,
            button: egui::PointerButton::Secondary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        vec![
            egui::Event::PointerMoved(point),
            button(true),
            button(false),
        ]
    }

    #[test]
    fn selection_xrefs_use_exact_evidence_and_require_explicit_choices() {
        let mut app = xref_app();
        // A call instruction resolves to its decoded target only.
        app.select_instruction(0x1004);
        app.show_selection_xrefs();
        assert_eq!(
            app.xref_target,
            Some(XrefTarget {
                address: 0x1040,
                kind: TargetKind::CallTarget
            })
        );
        assert!(app.tab == Tab::References && !app.reference_data);
        // Two accesses from one instruction offer both and pick neither.
        app.xref_target = None;
        app.select_instruction(0x1008);
        app.show_selection_xrefs();
        assert!(app.xref_target.is_none());
        let choices = app.xref_choices.as_ref().unwrap();
        assert_eq!(
            choices
                .set
                .targets
                .iter()
                .map(|t| t.address)
                .collect::<Vec<_>>(),
            [0x2000, 0x2010]
        );
        // A decompiler expression mapped to several PCs merges their targets.
        app.select_decompiled_byte(app.decompiled().find("return").unwrap());
        app.show_selection_xrefs();
        let choices = app.xref_choices.as_ref().unwrap();
        assert_eq!(
            choices
                .set
                .targets
                .iter()
                .map(|t| t.address)
                .collect::<Vec<_>>(),
            [0x1040, 0x2000, 0x2010]
        );
        app.open_xrefs(choices.set.targets[2]);
        assert!(app.xref_choices.is_none() && app.reference_data);
        assert_eq!(app.xref_target.unwrap().address, 0x2010);
        // Without operand evidence the exact selected address is inspected.
        app.select_instruction(0x1000);
        app.show_selection_xrefs();
        assert_eq!(app.xref_target.unwrap().kind, TargetKind::Function);
        app.selected = Some(0x10f0);
        app.semantic.addresses.clear();
        app.show_selection_xrefs();
        assert_eq!(
            app.xref_target,
            Some(XrefTarget {
                address: 0x10f0,
                kind: TargetKind::Address
            })
        );
        // Text never establishes a target: duplicate labels keep exact calls.
        for address in [0x1000, 0x1040] {
            app.edit_annotation(
                address,
                Annotation {
                    label: "dup".into(),
                    ..Default::default()
                },
            );
        }
        app.select_instruction(0x1004);
        app.show_selection_xrefs();
        assert_eq!(app.xref_target.unwrap().address, 0x1040);
    }

    #[test]
    fn graph_call_targets_outside_file_backed_code_are_not_xref_targets() {
        let mut app = xref_app();
        // A crafted saved view can claim a call into data or unmapped memory.
        for target in [0x2000, 0x1101, 0x9000] {
            edit_view(&mut app, |view| view.calls[0].target = Some(target));
            app.set_call_index(None);
            app.select_instruction(0x1004);
            assert_eq!(
                app.selection_xref_targets().targets,
                [XrefTarget {
                    address: 0x1004,
                    kind: TargetKind::Address
                }],
                "{target:#x}"
            );
        }
    }

    #[test]
    fn decompiler_call_tokens_resolve_directly_and_legacy_text_does_not() {
        let source = "void f() { helper(); }";
        let mut app = call_navigation_app(source);
        let call = source.find("helper").unwrap();
        edit_semantics(&mut app, |semantics| {
            semantics.tokens = vec![crate::semantic::SemanticToken {
                start: call,
                end: call + "helper".len(),
                kind: TokenKind::Call { target: 0x1040 },
            }]
        });
        app.select_decompiled_byte(call + 1);
        app.show_selection_xrefs();
        assert_eq!(
            app.xref_target,
            Some(XrefTarget {
                address: 0x1040,
                kind: TargetKind::CallTarget
            })
        );
        // Legacy text without tokens or mappings has no call evidence; the
        // name "helper" is never looked up.
        let mut legacy = call_navigation_app(source);
        legacy.select_decompiled_byte(call + 1);
        assert!(legacy.selected_call.is_none());
        legacy.show_selection_xrefs();
        assert_eq!(legacy.xref_target.unwrap().address, 0x1000);
    }

    #[test]
    fn xref_shortcut_respects_focus_dialogs_repeats_and_file_jobs() {
        // Each press is released so egui does not report the next as a repeat.
        let tap = |modifiers| {
            let press = key_event(egui::Key::X, modifiers);
            let egui::Event::Key {
                key,
                physical_key,
                modifiers,
                ..
            } = press
            else {
                unreachable!()
            };
            vec![
                press,
                egui::Event::Key {
                    key,
                    physical_key,
                    pressed: false,
                    repeat: false,
                    modifiers,
                },
            ]
        };
        let x = || tap(egui::Modifiers::NONE);
        let context = egui::Context::default();
        let mut app = xref_app();
        app.select_instruction(0x1004);
        keyboard_frame(&context, &mut app, vec![]);
        context.memory_mut(|memory| memory.request_focus(egui::Id::unique("function-filter")));
        keyboard_frame(&context, &mut app, vec![]);
        let mut typed = x();
        typed.insert(1, egui::Event::Text("x".into()));
        keyboard_frame(&context, &mut app, typed);
        assert_eq!(app.function_filter, "x");
        assert!(app.xref_target.is_none() && app.tab == Tab::Listing);
        context.memory_mut(|memory| memory.surrender_focus(egui::Id::unique("function-filter")));
        let (_sender, receiver) = mpsc::sync_channel(1);
        app.file_job = Some(receiver);
        keyboard_frame(&context, &mut app, x());
        assert!(app.xref_target.is_none());
        app.file_job = None;
        app.begin_go_to();
        keyboard_frame(&context, &mut app, x());
        assert!(app.xref_target.is_none());
        app.browser_dialog = None;
        let repeat = egui::Event::Key {
            key: egui::Key::X,
            physical_key: Some(egui::Key::X),
            pressed: true,
            repeat: true,
            modifiers: egui::Modifiers::NONE,
        };
        keyboard_frame(&context, &mut app, vec![repeat]);
        assert!(app.xref_target.is_none());
        keyboard_frame(&context, &mut app, tap(egui::Modifiers::SHIFT));
        assert!(app.xref_target.is_none());
        keyboard_frame(&context, &mut app, x());
        assert_eq!(app.xref_target.unwrap().address, 0x1040);
        assert!(app.tab == Tab::References);
    }

    #[test]
    fn listing_and_graph_context_menus_offer_each_exact_target() {
        for (tab, name) in [(Tab::Listing, "listing"), (Tab::Graph, "graph")] {
            let context = egui::Context::default();
            theme::install(&context);
            let mut app = xref_app();
            app.tab = tab;
            let screen = Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1000.0, 700.0),
            ));
            let frame = |app: &mut DesktopApp, events| {
                let mut output = context.run_ui(
                    egui::RawInput {
                        screen_rect: screen,
                        events,
                        time: Some(1.0),
                        ..Default::default()
                    },
                    |ui| app.main_panel(ui),
                );
                output.textures_delta.clear();
                output
            };
            let output = frame(&mut app, vec![]);
            let point = text_position(&output, "00001008", 3);
            frame(&mut app, secondary_events(point));
            // The captured instruction survives pointer movement over the menu.
            let output = frame(
                &mut app,
                vec![egui::Event::PointerMoved(egui::pos2(990.0, 690.0))],
            );
            let text = rendered_text(&output);
            for item in [
                "Xrefs to data access target 2000",
                "Xrefs to data access target 2010",
                "Xrefs to this function",
            ] {
                assert!(text.iter().any(|t| t == item), "{name} {item}");
            }
            assert!(!text.iter().any(|t| t.contains("call target 1040")));
            let point = text_position(&output, "Xrefs to data access target 2010", 0);
            frame(&mut app, pointer_events(point));
            assert_eq!(
                app.xref_target,
                Some(XrefTarget {
                    address: 0x2010,
                    kind: TargetKind::DataAccess
                }),
                "{name}"
            );
            assert!(app.tab == Tab::References && app.reference_data);
            assert_eq!(app.view().unwrap().address, 0x1000);
        }
    }

    #[test]
    fn explicit_xrefs_filter_rows_and_keep_saved_provenance_visible() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = xref_app();
        app.saved_references = true;
        app.open_xrefs(XrefTarget {
            address: 0x1040,
            kind: TargetKind::Function,
        });
        // Independent of the displayed function.
        assert_eq!(app.view().unwrap().address, 0x1000);
        let frame = |app: &mut DesktopApp| {
            let mut output =
                context.run_ui(egui::RawInput::default(), |ui| app.references_panel(ui));
            output.textures_delta.clear();
            rendered_text(&output)
        };
        let text = frame(&mut app);
        assert!(text.iter().any(|t| t.starts_with("Saved analysis")));
        assert!(
            text.iter()
                .any(|t| t == "References to function 0x1040  next")
        );
        // Two calls to it (one recursive) and its own outgoing call.
        assert!(text.iter().any(|t| t == "3 matching calls"));
        assert!(
            !text
                .iter()
                .any(|t| t.contains("does not establish absence"))
        );
        app.reference_direction = CallDirection::Outgoing;
        assert!(frame(&mut app).iter().any(|t| t == "1 matching calls"));
        app.reference_direction = CallDirection::All;
        app.reference_filter = "entry".into();
        assert!(frame(&mut app).iter().any(|t| t == "1 matching calls"));
        app.reference_filter = "0x1044".into();
        assert!(frame(&mut app).iter().any(|t| t == "2 matching calls"));
        app.reference_filter = "missing".into();
        assert!(frame(&mut app).iter().any(|t| t == "0 matching calls"));
        // Rows recompute when names change, not only when the query does.
        app.reference_filter = "renamed".into();
        frame(&mut app);
        app.edit_annotation(
            0x1000,
            Annotation {
                label: "renamed".into(),
                ..Default::default()
            },
        );
        assert!(frame(&mut app).iter().any(|t| t == "1 matching calls"));
        // Data view: exact-start string accesses with access filtering.
        app.reference_filter.clear();
        app.open_xrefs(XrefTarget {
            address: 0x2010,
            kind: TargetKind::StringStart,
        });
        assert!(app.reference_data);
        let text = frame(&mut app);
        assert!(text.iter().any(|t| t == "Exact start"));
        assert!(text.iter().any(|t| t == "1 references starting at 0x2010"));
        app.reference_access = AccessFilter::Read;
        assert!(
            frame(&mut app)
                .iter()
                .any(|t| t == "0 references starting at 0x2010")
        );
        // Current function resets to the displayed function's own accesses.
        app.reference_access = AccessFilter::All;
        app.xref_target = None;
        assert!(
            frame(&mut app)
                .iter()
                .any(|t| t == "2 references from this function")
        );
    }

    #[test]
    fn string_rows_own_x_and_list_taken_addresses_with_their_own_filter() {
        let mut app = xref_app();
        let mut report = app.call_index.as_ref().unwrap().report.clone();
        report.addresses = Some(Box::new(AddressAnalysis {
            references: vec![AddressReference {
                function: 0x1000,
                address: 0x1000,
                target: 0x2010,
                provenance: DataProvenance::InstructionLocal,
            }],
            candidates_examined: 1,
            ..Default::default()
        }));
        app.set_call_index(Some(Arc::new(crate::call_analysis::CallIndex::new(report))));
        // A Strings row is the X target ahead of any residual code selection.
        app.tab = Tab::Strings;
        app.select_string(0x2010);
        app.show_selection_xrefs();
        assert_eq!(
            app.xref_target,
            Some(XrefTarget {
                address: 0x2010,
                kind: TargetKind::StringStart
            })
        );
        assert!(app.tab == Tab::References && app.reference_data);
        for scale in [1.0, 1.25] {
            let context = egui::Context::default();
            theme::install(&context);
            context.set_pixels_per_point(scale);
            let frame = |app: &mut DesktopApp| {
                let mut output =
                    context.run_ui(egui::RawInput::default(), |ui| app.references_panel(ui));
                output.textures_delta.clear();
                rendered_text(&output)
            };
            app.reference_access = AccessFilter::All;
            let text = frame(&mut app);
            // The write access and the address-taking, each in its own row.
            assert!(text.iter().any(|t| t == "2 references starting at 0x2010"));
            assert!(text.iter().any(|t| t == "Address"));
            assert!(text.iter().any(|t| t == "\u{2014}"));
            assert!(text.iter().any(|t| t == "0 calls \u{b7} 2 data refs"));
            app.reference_access = AccessFilter::Address;
            assert!(
                frame(&mut app)
                    .iter()
                    .any(|t| t == "1 references starting at 0x2010")
            );
            app.reference_access = AccessFilter::Read;
            assert!(
                frame(&mut app)
                    .iter()
                    .any(|t| t == "0 references starting at 0x2010")
            );
        }
        // Listing and Graph restore code-selection scope.
        app.tab = Tab::Listing;
        assert_ne!(
            app.selection_xref_targets().targets[0].kind,
            TargetKind::StringStart
        );
        // Selecting code, or another binary generation, drops the string.
        app.tab = Tab::Strings;
        app.select_string(0x2010);
        app.generation = app.generation.wrapping_add(1);
        assert!(app.string_target().is_none());
        app.generation = app.generation.wrapping_sub(1);
        assert_eq!(app.string_target(), Some(0x2010));
        app.select_instruction(0x1008);
        assert!(app.string_target().is_none());
        // The source column navigates to the exact taking instruction.
        app.tab = Tab::Strings;
        app.select_string(0x2010);
        app.show_selection_xrefs();
        let context = egui::Context::default();
        app.navigate_reference(0x1000, 0x1000, &context);
        assert_eq!(app.selected, Some(0x1000));
        assert!(app.tab == Tab::Listing && app.string_target().is_none());
    }

    #[test]
    fn reference_headers_wrap_within_narrow_panels_at_fractional_scale() {
        let mut app = xref_app();
        app.saved_references = true;
        app.open_xrefs(XrefTarget {
            address: 0x2010,
            kind: TargetKind::StringStart,
        });
        for (scale, data) in [(1.0, true), (1.25, true), (1.25, false)] {
            app.reference_data = data;
            for width in [760.0, 560.0, 420.0] {
                let context = egui::Context::default();
                theme::install(&context);
                context.set_pixels_per_point(scale);
                let mut output = context.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 500.0),
                        )),
                        ..Default::default()
                    },
                    |ui| app.references_panel(ui),
                );
                output.textures_delta.clear();
                // The panel width in points after egui applies the scale.
                let visible = context.content_rect().width();
                // Table columns scroll horizontally; header text must not clip.
                let rows = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::epaint::Shape::Text(text)
                            if matches!(text.galley.text(), "Kind" | "Function") =>
                        {
                            Some(text.pos.y)
                        }
                        _ => None,
                    })
                    .reduce(f32::min);
                for shape in &output.shapes {
                    if let egui::epaint::Shape::Text(text) = &shape.shape {
                        let bounds = text.galley.rect.translate(text.pos.to_vec2());
                        assert!(
                            bounds.right() <= visible + 0.5
                                || rows.is_some_and(|row| bounds.top() >= row),
                            "{scale} {width}: {:?} ends at {}",
                            text.galley.text(),
                            bounds.right()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn selection_changes_and_invalidation_drop_captured_xref_targets() {
        // Choices belong to the selection that produced them.
        let mut app = xref_app();
        app.select_instruction(0x1008);
        app.show_selection_xrefs();
        assert!(app.xref_choices.is_some());
        app.select_instruction(0x1004);
        assert!(app.xref_choices.is_none());
        app.select_instruction(0x1008);
        app.show_selection_xrefs();
        app.select_decompiled_byte(0);
        assert!(app.xref_choices.is_none());
        // A chosen call token does not outlive its pseudocode.
        let source = "void f() { helper(); }";
        let call = source.find("helper").unwrap();
        let mut app = call_navigation_app(source);
        edit_semantics(&mut app, |semantics| {
            semantics.tokens = vec![crate::semantic::SemanticToken {
                start: call,
                end: call + "helper".len(),
                kind: TokenKind::Call { target: 0x1040 },
            }]
        });
        app.select_decompiled_byte(call);
        assert_eq!(app.selected_call, Some(0x1040));
        app.invalidate_signature_analysis();
        assert!(app.selected_call.is_none());
        assert!(
            app.selection_xref_targets()
                .targets
                .iter()
                .all(|t| t.kind != TargetKind::CallTarget)
        );
    }

    #[test]
    fn decompiler_menu_offers_every_mapped_target_until_state_changes() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = xref_app();
        let frame = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 600.0),
                    )),
                    events,
                    time: Some(1.0),
                    ..Default::default()
                },
                |ui| app.side_panel(ui),
            );
            output.textures_delta.clear();
            output
        };
        let output = frame(&mut app, vec![]);
        let byte = app.decompiled().find("return").unwrap() + 2;
        let point = text_position(&output, "return", byte);
        frame(&mut app, secondary_events(point));
        let text = rendered_text(&frame(&mut app, vec![]));
        for item in [
            "Xrefs to call target 1040",
            "Xrefs to data access target 2000",
            "Xrefs to data access target 2010",
        ] {
            assert!(text.iter().any(|t| t == item), "{item}");
        }
        // An annotation edit expires the captured targets.
        app.edit_annotation(
            0x1004,
            Annotation {
                comment: "changed".into(),
                ..Default::default()
            },
        );
        let text = rendered_text(&frame(&mut app, vec![]));
        assert!(!text.iter().any(|t| t.starts_with("Xrefs to")));
    }

    #[test]
    fn xref_choices_and_targets_expire_with_their_state() {
        let context = egui::Context::default();
        let mut app = xref_app();
        app.select_instruction(0x1008);
        app.show_selection_xrefs();
        assert!(app.xref_choices.is_some());
        // New evidence (discovery, restore, signature invalidation) expires choices.
        app.invalidate_signature_analysis();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.references_panel(ui));
        output.textures_delta.clear();
        assert!(app.xref_choices.is_none());
        let mut app = xref_app();
        app.select_instruction(0x1008);
        app.show_selection_xrefs();
        app.navigate(0x1040, true, &context);
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.references_panel(ui));
        output.textures_delta.clear();
        assert!(app.xref_choices.is_none());
        // Closing the binary clears every contextual reference state.
        app.open_xrefs(XrefTarget {
            address: 0x2000,
            kind: TargetKind::DataAccess,
        });
        app.reference_filter = "x".into();
        app.reference_access = AccessFilter::Write;
        app.clear_binary();
        assert!(app.xref_target.is_none() && app.xref_choices.is_none());
        assert!(app.reference_filter.is_empty() && app.reference_access == AccessFilter::All);
        assert!(app.reference_rows.is_none() && app.call_index.is_none());
    }

    #[test]
    fn navigation_clears_old_semantic_links_and_cross_function_views() {
        let mut app = semantic_app();
        app.select_decompiled_byte(app.decompiled().find("return").unwrap());
        app.navigate(0x1040, true, &egui::Context::default());
        assert!(app.semantic.mappings.is_empty());
        assert!(app.semantic.addresses.is_empty());
        assert!(app.semantic.ranges.is_empty());
        assert!(app.view().is_none());
        assert!(app.canvas.is_none());
        assert!(app.listing().is_empty());
        app.select_decompiled_byte(0);
        assert_eq!(app.selected, Some(0x1040));
    }

    #[test]
    fn decompiler_navigation_uses_only_semantic_targets_even_with_duplicate_names() {
        let mut app = call_navigation_app("next()");
        assert_eq!(app.decompiler_call_target(1), None); // Legacy text cache fails closed.
        edit_semantics(&mut app, |semantics| {
            semantics.tokens.push(crate::semantic::SemanticToken {
                start: 0,
                end: 4,
                kind: TokenKind::Call { target: 0x1040 },
            })
        });
        assert_eq!(app.decompiler_call_target(1), Some(0x1040));
        assert_eq!(app.decompiler_call_target(4), None);
        app.info.as_mut().unwrap().functions.push(FunctionInfo {
            address: 0x1080,
            name: "next".into(),
        });
        edit_view(&mut app, |view| view.calls.clear());
        assert_eq!(app.decompiler_call_target(1), Some(0x1040));
        edit_semantics(&mut app, |semantics| semantics.tokens.clear());
        assert_eq!(app.decompiler_call_target(1), None);
    }

    #[test]
    fn double_clicking_decompiler_call_text_navigates_and_records_history() {
        let context = egui::Context::default();
        theme::install(&context);
        let source = "void entry() { next(); }";
        let mut app = call_navigation_app(source);
        let start = source.find("next").unwrap();
        edit_semantics(&mut app, |semantics| {
            semantics.tokens.push(crate::semantic::SemanticToken {
                start,
                end: start + 4,
                kind: TokenKind::Call { target: 0x1040 },
            })
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
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1000, 0x1040]
        );
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
        let byte = app.decompiled().find("café").unwrap();
        edit_semantics(&mut app, |semantics| {
            semantics.locals.push(crate::semantic::LocalVariable {
                identity: identity.clone(),
                name: "café".into(),
                signature_parameter: None,
            })
        });
        edit_semantics(&mut app, |semantics| {
            semantics.tokens.push(crate::semantic::SemanticToken {
                start: byte,
                end: byte + "café".len(),
                kind: TokenKind::Local { local: Some(0) },
            })
        });
        app.edit_annotation(
            0x1004,
            Annotation {
                comment: "keep me".into(),
                ..Default::default()
            },
        );
        let original = app.decompiled().to_owned();
        let original_semantics = app.semantics().clone();
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
                bytes: None,
                result: None,
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
        assert_eq!(app.decompiled(), renamed);
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
        assert_eq!(app.status, "Project opened · saved analysis");
        assert!(app.saved_analysis);
        assert!(app.code.is_some());
        assert!(app.decompiled().contains("restored_entry"));
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
        assert_eq!(app.decompiled(), source);
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1000]
        );
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
            result_revision: app.result_revision,
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
            result_revision: app.result_revision,
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
            pointers: None,
            admissions: Vec::new(),
            recovery_records: 0,
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
                discovery_index: Some(Arc::new(crate::call_analysis::CallIndex::from_snapshot(
                    saved.clone(),
                ))),
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
        assert!(output.shapes.iter().any(|shape| matches!(&shape.shape,
            egui::epaint::Shape::Text(text) if text.galley.text() == "Saved analysis")));

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
            bytes: None,
            result: None,
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
        assert!(app.view().is_none());
        let pending = Pending {
            id: 2,
            request: Request::Decompile { address: 0x1000 },
            started: Instant::now(),
            selection: 2,
            revision: 0,
            byte_origin: (None, Tab::Listing),
            bytes: None,
            result: None,
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
        assert!(app.decompiled().is_empty());
    }

    fn status_frame(
        context: &egui::Context,
        app: &DesktopApp,
        now: Instant,
        width: f32,
        events: Vec<egui::Event>,
    ) -> (egui::FullOutput, egui::Rect) {
        let mut rect = egui::Rect::NOTHING;
        let mut output = context.run_ui(
            egui::RawInput {
                time: Some(context.input(|input| input.time) + 0.25),
                events,
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 160.0),
                )),
                ..Default::default()
            },
            |ui| {
                rect = egui::Panel::bottom("status")
                    .frame(theme::status_frame(ui.style()))
                    .show(ui, |ui| app.status_bar_at(ui, now))
                    .response
                    .rect;
            },
        );
        output.textures_delta.clear();
        (output, rect)
    }

    fn run_progress_app(now: Instant) -> DesktopApp {
        let mut app = keyboard_app();
        app.discovery = Some(crate::discovery::Discovery::new(
            None,
            [0x1000, 0x1040],
            false,
        ));
        app.discovery_running = true;
        app.begin_discovery_activity(now);
        app.update_discovery_summary();
        app
    }

    fn run_pending(app: &DesktopApp, request: Request, started: Instant) -> Pending {
        Pending {
            id: 1,
            request,
            started,
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: None,
        }
    }

    fn run_commit(app: &DesktopApp, state: &mut crate::discovery::Discovery, count: usize) {
        let request = state
            .begin(app.generation, app.worker_epoch, app.revision)
            .unwrap();
        let Request::DiscoverBatch { binding, seeds, .. } = request else {
            panic!()
        };
        let batch = DiscoveryBatch {
            binding,
            inventory: InventoryChange::Replace {
                revision: binding.batch,
                functions: app.info.as_ref().unwrap().functions.clone(),
            },
            truncated: false,
            patterns: None,
            outcomes: seeds
                .iter()
                .take(count)
                .map(|&address| DiscoveryOutcome {
                    address,
                    status: DiscoveryStatus::Done,
                })
                .collect(),
            analysis: CallAnalysis {
                functions_examined: count,
                decode_attempts: count,
                ..Default::default()
            },
            pointers: None,
            admissions: Vec::new(),
            recovery_records: 0,
        };
        crate::discovery::commit_replacement(state, app.info.as_ref().unwrap(), &batch).unwrap();
    }

    fn run_update(app: &mut DesktopApp, state: crate::discovery::Discovery) {
        let (sender, receiver) = mpsc::sync_channel(1);
        app.discovery_job = Some(receiver);
        sender
            .send(DiscoveryUpdate {
                generation: app.generation,
                saved: Arc::new(state.save()),
                state,
                publication: Ok(None),
            })
            .unwrap();
    }

    #[test]
    fn run_progress_persists_through_gaps_setup_replay_and_adoption() {
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let context = egui::Context::default();
        let mut app = run_progress_app(start);
        assert!(
            app.analysis_presentation(start + Duration::from_millis(199))
                .is_none()
        );
        assert!(
            app.analysis_presentation(start + Duration::from_millis(200))
                .is_some()
        );
        let work = theme::BarProgress::KnownFunctions {
            processed: 0,
            total: 2,
        };
        assert_eq!(app.analysis_presentation(now).unwrap().progress, work);

        // Initial preparation has no counts; the clock starts before the job.
        let activity = app.discovery_activity.take().unwrap();
        app.discovery = None;
        app.begin_discovery_activity(start);
        let (sender, receiver) = mpsc::sync_channel(1);
        app.discovery_job = Some(receiver);
        assert_eq!(
            app.analysis_presentation(now).unwrap().phase,
            "Preparing discovery"
        );
        drop(sender);
        app.discovery_job = None;
        app.discovery_activity = Some(activity);
        app.discovery = Some(crate::discovery::Discovery::new(
            None,
            [0x1000, 0x1040],
            false,
        ));

        for request in [
            Request::Graph { address: 0x1000 },
            Request::Bytes {
                address: 0x1000,
                length: 4,
            },
        ] {
            app.pending = Some(run_pending(&app, request, now));
            let display = app.analysis_presentation(now).unwrap();
            assert_eq!(display.phase, "Discovery waiting");
            assert!(display.foreground.is_some());
            assert_eq!(display.elapsed, Duration::from_secs(3));
            assert_eq!(display.known.unwrap().total, 2);
            assert_eq!(display.progress, theme::BarProgress::Activity);
            assert_eq!(
                app.pending.as_ref().unwrap().started,
                now,
                "run clocks do not change deadlines"
            );
        }
        app.pending = Some(run_pending(
            &app,
            Request::SyncFunctions { functions: vec![] },
            now,
        ));
        assert_eq!(app.analysis_presentation(now).unwrap().phase, "Restoring");
        app.pending = None;
        app.signature_replay = Some(SignatureReplay {
            signatures: vec![],
            context: String::new(),
            generation: app.generation,
            revision: app.revision,
            epoch: app.worker_epoch,
            sent: false,
        });
        assert_eq!(app.analysis_presentation(now).unwrap().phase, "Restoring");
        app.signature_replay = None;
        app.analysis_progress = Some(AnalysisProgress {
            stage: AnalysisStage::Calls,
            functions_examined: 99,
            decode_attempts: 999,
        });
        assert_eq!(
            app.analysis_presentation(now).unwrap().progress,
            work,
            "batch-local counts are not added"
        );
        app.analysis_progress = None;
        let mut state = app.discovery.take().unwrap();
        run_commit(&app, &mut state, 1);
        run_update(&mut app, state);
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(display.phase, "Adopting");
        assert_eq!(display.progress, theme::BarProgress::Activity);
        assert_eq!(
            display.known.unwrap().processed,
            0,
            "unaccepted results do not advance progress"
        );
        app.poll_discovery(&context);
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(
            display.progress,
            theme::BarProgress::KnownFunctions {
                processed: 1,
                total: 2
            }
        );
        assert_eq!(display.elapsed, Duration::from_secs(3));
        app.stop_worker_transport();
        assert_eq!(
            app.analysis_presentation(now).unwrap().elapsed,
            Duration::from_secs(3)
        );
    }

    #[test]
    fn run_progress_cancel_late_adoption_fresh_resume_and_invalidation() {
        let context = egui::Context::default();
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let mut app = run_progress_app(start);
        let mut state = app.discovery.take().unwrap();
        run_commit(&app, &mut state, 1);
        run_update(&mut app, state);
        app.stop_worker();
        assert!(app.analysis_presentation(now).is_none());
        app.poll_discovery(&context);
        assert_eq!(app.discovery.as_ref().unwrap().progress().processed, 1);
        assert!(
            app.analysis_presentation(now).is_none(),
            "late adoption retains results without restarting a canceled bar"
        );
        app.begin_discovery_activity(now);
        assert!(
            app.analysis_presentation(now + Duration::from_millis(199))
                .is_none()
        );
        let display = app
            .analysis_presentation(now + Duration::from_millis(200))
            .unwrap();
        assert_eq!(display.elapsed, Duration::from_millis(200));
        assert_eq!(display.known.unwrap().processed, 1);
        app.invalidate_signature_analysis();
        assert!(
            app.analysis_presentation(now + Duration::from_secs(1))
                .is_none()
        );
        app.begin_discovery_activity(start);
        app.generation += 1;
        assert!(app.analysis_presentation(now).is_none());
        app.begin_discovery_activity(start);
        app.clear_binary();
        assert!(app.analysis_presentation(now).is_none());
    }

    #[test]
    fn run_progress_patterns_are_activity_and_final_adoption_settles_auto_run() {
        let context = egui::Context::default();
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let mut app = run_progress_app(start);
        app.analysis_options = AnalysisOptions {
            strings: false,
            crypto: false,
            functions: true,
        };
        app.start_auto_analysis_at(start);
        let plan = app.analysis_plan.as_mut().unwrap();
        plan.current = plan.steps.pop_front();
        let mut state = app.discovery.take().unwrap();
        state.start_patterns();
        run_commit(&app, &mut state, 2);
        run_update(&mut app, state);
        assert_eq!(app.analysis_presentation(now).unwrap().phase, "Adopting");
        app.poll_discovery(&context);
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(display.phase, "Patterns");
        assert_eq!(display.known.unwrap().processed, 2);
        assert_eq!(
            display.progress,
            theme::BarProgress::Activity,
            "N/N does not imply discovery completion"
        );
        assert!(app.discovery_running);
        assert!(
            app.discovery_summary
                .as_ref()
                .unwrap()
                .contains("· running")
        );
        let mut state = app.discovery.take().unwrap();
        let phase = state.patterns.as_mut().unwrap();
        phase.cursor = None;
        phase.admitted = 7;
        phase.scanned_bytes = 8192;
        run_update(&mut app, state);
        app.poll_discovery(&context);
        assert!(app.discovery_activity.is_none());
        assert!(!app.discovery_running);
        let summary = app.discovery_summary.as_ref().unwrap();
        assert!(!summary.contains("· running") && !summary.contains("· paused"));
        assert!(summary.contains("7 pattern starts from 8 KiB"));
        app.pump_analysis(&context);
        assert!(app.analysis_plan.is_none());
        assert!(app.analysis_presentation(now).is_none());
    }

    #[test]
    fn final_seed_adoption_keeps_partial_warning_without_live_status() {
        let context = egui::Context::default();
        theme::install(&context);
        let start = Instant::now();
        let mut app = run_progress_app(start);
        let mut state = crate::discovery::Discovery::new(None, [0x1000, 0x1040], true);
        run_commit(&app, &mut state, 2);
        run_update(&mut app, state);
        app.poll_discovery(&context);
        assert!(!app.discovery_running);
        assert!(app.discovery_activity.is_none());
        assert!(
            app.analysis_presentation(start + Duration::from_secs(3))
                .is_none()
        );
        let summary = app.discovery_summary.as_ref().unwrap();
        assert!(summary.contains("partial coverage"));
        assert!(!summary.contains("· running") && !summary.contains("· paused"));
        assert!(app.status_notes().any(|note| note == summary));
        status_frame(&context, &app, start, 1000.0, vec![]);
        let (output, _) = status_frame(&context, &app, start, 1000.0, vec![]);
        let position = text_position(&output, "    1", 0) + egui::vec2(8.0, 5.0);
        status_frame(&context, &app, start, 1000.0, pointer_events(position));
        let (output, _) = status_frame(&context, &app, start, 1000.0, vec![]);
        assert!(rendered_text(&output).iter().any(|text| text == summary));
    }

    #[test]
    fn run_progress_auto_ordinals_and_origin_survive_scan_preemption() {
        let context = egui::Context::default();
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let mut app = keyboard_app();
        app.analysis_options.crypto = true;
        app.start_auto_analysis_at(start);
        app.pump_analysis(&context);
        assert_eq!(app.analysis_presentation(now).unwrap().step, Some((1, 3)));
        app.pending = Some(run_pending(&app, app.string_request(), now));
        app.request(Request::Graph { address: 0x1040 }, &context);
        assert_eq!(app.analysis_plan.as_ref().unwrap().current, None);
        app.pending = Some(run_pending(&app, Request::Graph { address: 0x1040 }, now));
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(display.phase, "Analysis waiting");
        assert_eq!(display.step, Some((1, 3)));
        app.pending = None;
        app.pump_analysis(&context);
        assert_eq!(app.analysis_presentation(now).unwrap().step, Some((1, 3)));
        app.receive(
            run_pending(&app, app.string_request(), now),
            Response::Strings {
                strings: vec![],
                truncated: false,
            },
            &context,
        );
        app.pump_analysis(&context);
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(display.phase, "Constants");
        assert_eq!(display.step, Some((2, 3)));
        assert_eq!(display.elapsed, Duration::from_secs(3));
        app.pending = Some(run_pending(&app, Request::Crypto, now));
        app.request(Request::Graph { address: 0x1000 }, &context);
        assert_eq!(app.analysis_presentation(now).unwrap().step, Some((2, 3)));
        app.pending = None;
        app.pump_analysis(&context);
        assert_eq!(app.analysis_presentation(now).unwrap().step, Some((2, 3)));
        app.receive(
            run_pending(&app, Request::Crypto, now),
            Response::Crypto {
                matches: vec![],
                truncated: false,
            },
            &context,
        );
        app.pump_analysis(&context);
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(display.step, Some((3, 3)));
        assert_eq!(display.elapsed, Duration::from_secs(3));
        app.stop_worker();
        assert!(app.analysis_presentation(now).is_none());
    }

    #[test]
    fn run_progress_survives_recovery_open_but_terminal_failure_ends_it() {
        let context = egui::Context::default();
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let mut app = run_progress_app(start);
        app.binary_path = Some(std::env::current_exe().unwrap());
        app.analysis_options = AnalysisOptions {
            strings: false,
            crypto: false,
            functions: true,
        };
        app.start_auto_analysis_at(start);
        app.stop_after_failure(true, &context);
        assert!(app.client.is_some(), "recovery must start successfully");
        let display = app.analysis_presentation(now).unwrap();
        assert_eq!(display.phase, "Restoring");
        assert_eq!(display.elapsed, Duration::from_secs(3));
        assert_eq!(display.step, Some((1, 1)));
        assert_eq!(display.known.unwrap().total, 2);
        assert_eq!(app.discovery_activity.as_ref().unwrap().started, start);
        app.stop_after_failure(false, &context);
        assert!(app.analysis_presentation(now).is_none());
        assert!(app.analysis_plan.is_none());
    }

    #[test]
    fn run_progress_saved_results_stay_idle_and_last_scan_settles_before_navigation() {
        let context = egui::Context::default();
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let mut app = keyboard_app();
        let state = crate::discovery::Discovery::new(None, [0x1000], false);
        app.discovery_saved = Some(Arc::new(state.save()));
        app.saved_references = true;
        app.cached_functions = true;
        app.discovery_summary = Some("Saved discovery: partial coverage".into());
        assert!(app.analysis_presentation(now).is_none());
        for (strings, step) in [(true, AnalysisStep::Strings), (false, AnalysisStep::Crypto)] {
            app.analysis_options = AnalysisOptions {
                strings,
                crypto: !strings,
                functions: false,
            };
            app.start_auto_analysis_at(start);
            app.pump_analysis(&context);
            assert_eq!(app.analysis_plan.as_ref().unwrap().current, Some(step));
            app.pending = Some(run_pending(&app, Request::Graph { address: 0x1000 }, now));
            // Final analysis adoption may settle while foreground work is present.
            let (request, response) = if strings {
                (
                    app.string_request(),
                    Response::Strings {
                        strings: vec![],
                        truncated: false,
                    },
                )
            } else {
                (
                    Request::Crypto,
                    Response::Crypto {
                        matches: vec![],
                        truncated: false,
                    },
                )
            };
            app.receive(run_pending(&app, request, start), response, &context);
            assert!(app.analysis_plan.is_none());
            assert!(
                app.analysis_presentation(now).is_none(),
                "fresh standalone work retains its own 200 ms delay"
            );
            app.pending = None;
        }
    }

    #[test]
    fn run_progress_both_modes_keep_narrow_rows_and_warning_popup() {
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        for width in [1440.0, 1000.0, 520.0, 260.0] {
            let context = egui::Context::default();
            theme::install(&context);
            let mut app = run_progress_app(start);
            app.status = "Very long status ".repeat(100);
            status_frame(&context, &app, now, width, vec![]);
            let (_, known_rect) = status_frame(&context, &app, now, width, vec![]);
            let (sender, receiver) = mpsc::sync_channel(1);
            app.discovery_job = Some(receiver);
            let (output, activity_rect) = status_frame(&context, &app, now, width, vec![]);
            assert_eq!(known_rect, activity_rect);
            assert!(activity_rect.height() <= theme::ROW_HEIGHT + 8.0);
            for shape in &output.shapes {
                if let egui::epaint::Shape::Text(text) = &shape.shape {
                    assert_eq!(text.galley.rows.len(), 1);
                }
            }
            let position = text_position(&output, "    1", 0) + egui::vec2(8.0, 5.0);
            status_frame(&context, &app, now, width, pointer_events(position));
            let (output, _) = status_frame(&context, &app, now, width, vec![]);
            assert!(
                rendered_text(&output)
                    .iter()
                    .any(|text| text.contains("partial coverage"))
            );
            drop(sender);
        }
    }

    #[test]
    fn run_progress_hover_explains_counts_in_both_modes() {
        let start = Instant::now();
        let now = start + Duration::from_secs(3);
        let context = egui::Context::default();
        theme::install(&context);
        context.style_mut_of(egui::Theme::Dark, |style| {
            style.interaction.tooltip_delay = 0.0
        });
        let mut app = run_progress_app(start);
        status_frame(&context, &app, now, 1000.0, vec![]);
        for adopting in [false, true] {
            let (_sender, receiver) = mpsc::sync_channel(1);
            app.discovery_job = adopting.then_some(receiver);
            let (_, rect) = status_frame(&context, &app, now, 1000.0, vec![]);
            status_frame(
                &context,
                &app,
                now,
                1000.0,
                vec![egui::Event::PointerMoved(egui::pos2(
                    rect.right() - 40.0,
                    rect.center().y,
                ))],
            );
            let (output, _) = status_frame(&context, &app, now, 1000.0, vec![]);
            assert!(
                rendered_text(&output)
                    .iter()
                    .any(|text| text.contains("excludes in-flight work")
                        && text.contains("Total may grow"))
            );
        }
    }

    #[test]
    fn status_notes_filter_only_exact_legacy_text_without_changing_project_data() {
        let context = egui::Context::default();
        theme::install(&context);
        let now = Instant::now();
        let mut app = keyboard_app();
        let legacy = vec![
            "Prototype analysis: symbols and supported PE function metadata load immediately; deeper function discovery is explicit. Optimized C++/Rust types and source reconstruction are incomplete.".into(),
            "Function lists are capped at 262144 entries, 8 MiB of names, and 256 bytes per name in this prototype.".into(),
        ];
        app.info.as_mut().unwrap().warnings = legacy.clone();
        status_frame(&context, &app, now, 1000.0, vec![]);
        let (output, _) = status_frame(&context, &app, now, 1000.0, vec![]);
        assert!(
            !rendered_text(&output)
                .iter()
                .any(|text| text.starts_with("    "))
        );
        assert_eq!(app.info.as_ref().unwrap().warnings, legacy);

        let near_legacy = format!("{} Additional coverage warning.", legacy[1]);
        app.info.as_mut().unwrap().warnings.extend([
            crate::packing::UPX_PACKED_WARNING.into(),
            near_legacy.clone(),
        ]);
        let stored = app.info.as_ref().unwrap().warnings.clone();
        assert_eq!(
            app.status_notes().collect::<Vec<_>>(),
            [crate::packing::UPX_PACKED_WARNING, &near_legacy]
        );
        let (output, _) = status_frame(&context, &app, now, 1000.0, vec![]);
        let position = text_position(&output, "    2", 0) + egui::vec2(8.0, 5.0);
        status_frame(&context, &app, now, 1000.0, pointer_events(position));
        let (output, _) = status_frame(&context, &app, now, 1000.0, vec![]);
        let texts = rendered_text(&output);
        assert!(
            texts
                .iter()
                .any(|text| text == crate::packing::UPX_PACKED_WARNING)
        );
        assert!(texts.contains(&near_legacy));
        assert!(!texts.contains(&legacy[0]));
        assert!(!texts.contains(&legacy[1]));
        assert_eq!(app.info.as_ref().unwrap().warnings, stored);
    }

    #[test]
    fn status_bar_stays_one_row_with_long_multiline_text_and_partial_discovery() {
        for width in [1440.0, 1000.0, 520.0, 260.0] {
            let context = egui::Context::default();
            theme::install(&context);
            let now = Instant::now();
            let mut app = keyboard_app();
            app.status = format!("{}\nmore details", "Discovery batch committed ".repeat(100));
            app.discovery = Some(crate::discovery::Discovery::new(
                Some(0x1000),
                [0x1000],
                false,
            ));
            app.discovery_running = true;
            app.update_discovery_summary();
            app.pending = Some(Pending {
                id: 1,
                request: Request::SyncSignatures {
                    signatures: Vec::new(),
                    binary_sha256: String::new(),
                    context: String::new(),
                },
                started: now,
                selection: 0,
                revision: 0,
                byte_origin: (None, Tab::Listing),
                bytes: None,
                result: None,
            });
            status_frame(&context, &app, now, width, vec![]);
            let (output, idle_rect) = status_frame(
                &context,
                &app,
                now + Duration::from_millis(199),
                width,
                vec![],
            );
            assert!(
                !rendered_text(&output)
                    .iter()
                    .any(|text| text.contains("Applying function signatures"))
            );
            let (output, busy_rect) = status_frame(
                &context,
                &app,
                now + Duration::from_millis(200),
                width,
                vec![],
            );
            assert!(
                rendered_text(&output)
                    .iter()
                    .any(|text| text.contains("Applying function signatures"))
            );
            assert_eq!(idle_rect, busy_rect);
            assert!(
                busy_rect.height() <= theme::ROW_HEIGHT + 8.0,
                "{busy_rect:?}"
            );
            assert!(rendered_text(&output).iter().any(|text| text == "    1"));
            for shape in &output.shapes {
                if let egui::epaint::Shape::Text(text) = &shape.shape {
                    assert_eq!(text.galley.rows.len(), 1, "{:?}", text.galley.text());
                    assert!(
                        text.pos.y >= busy_rect.top()
                            && text.pos.y + text.galley.size().y <= busy_rect.bottom()
                    );
                    assert!(shape.clip_rect.left() >= 0.0 && shape.clip_rect.right() <= width);
                }
            }
            // Saved partial coverage continues to show an indicator after reopen.
            app.discovery_saved = app.discovery.take().map(|state| Arc::new(state.save()));
            assert_eq!(app.status_notes().count(), 1);
        }
    }

    #[test]
    fn analysis_activity_stays_bottom_right_and_disappears_on_cancel() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = DesktopApp::empty(None);
        app.pending = Some(Pending {
            result: None,
            id: 1,
            request: Request::Decompile { address: 0x1000 },
            started: Instant::now() - Duration::from_secs(2),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
            bytes: None,
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
            bytes: None,
            result: None,
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
            result: None,
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
            bytes: None,
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
            pointers: None,
            admissions: Vec::new(),
            recovery_records: 0,
        };
        app.discovery = Some(state);
        app.call_index = Some(Arc::new(crate::call_analysis::CallIndex::new(
            CallAnalysis::default(),
        )));
        app.pending = Some(Pending {
            result: None,
            id: 7,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
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
            result: None,
            id: 7,
            request: Request::Discover,
            started,
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
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
            result: None,
            id: 7,
            request: Request::Discover,
            started: Instant::now(),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
            bytes: None,
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
            result: None,
            id: 7,
            request: Request::Discover,
            started: Instant::now(),
            selection: 0,
            revision: 0,
            byte_origin: (None, Tab::Listing),
            bytes: None,
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
            bytes: None,
            result: None,
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
            let view = app.view().unwrap().clone();
            app.auto_decompile = false;
            // From another function, the caller is loaded before selecting.
            app.navigate(0x1040, true, &context);
            app.navigate_reference(0x1000, pc, &context);
            assert!(app.semantic.mappings.is_empty());
            assert!(app.view().is_none());
            let pending = Pending {
                id: 1,
                request: Request::Graph { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: None,
            };
            app.receive(pending, Response::Graph { view }, &context);
            assert_eq!(app.selected, Some(pc));
            assert!(app.semantic.addresses.contains(&pc));
            assert_eq!(app.pending_listing_scroll, (pc == 0x1004).then_some(1));
            assert_eq!(app.undisplayed_call, (pc == 0x104c).then_some(pc));
            assert!(app.reference_focus.is_none());
            assert!(app.tab == Tab::Listing);

            // Within the displayed caller, selection is immediate.
            let mut app = semantic_app();
            app.navigate_reference(0x1000, pc, &context);
            assert_eq!(app.view().unwrap().address, 0x1000);
            assert_eq!(app.selected, Some(pc));
            assert_eq!(app.pending_listing_scroll, (pc == 0x1004).then_some(1));
            assert_eq!(app.undisplayed_call, (pc == 0x104c).then_some(pc));
            assert!(app.reference_focus.is_none() && app.queue.is_empty());
        }
    }

    #[test]
    fn reference_history_records_exact_source_instructions_and_owners() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        let caller = app.view().unwrap().clone();
        app.auto_decompile = false;
        app.select_instruction(0x1008);
        // A callsite in another function is recorded as its exact instruction.
        app.navigate_reference(0x1040, 0x1044, &context);
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1008, 0x1044]
        );
        assert_eq!(app.reference_focus, Some((0x1040, 0x1044)));
        assert_eq!(app.comment_owners.get(&0x1044), Some(&0x1040));
        assert_eq!(app.comment_owners.get(&0x1008), Some(&0x1000));
        // Back returns to the departure instruction inside its own owner.
        app.history_step(false, &context);
        assert_eq!(app.history_index, 0);
        assert_eq!(app.reference_focus, Some((0x1000, 0x1008)));
        app.receive(
            Pending {
                id: 1,
                request: Request::Graph { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: None,
            },
            Response::Graph { view: caller },
            &context,
        );
        assert_eq!(app.selected, Some(0x1008));
        // Forward reopens the recorded owner, not a guessed function at the PC.
        app.history_step(true, &context);
        assert_eq!(app.reference_focus, Some((0x1040, 0x1044)));
        assert_eq!(
            app.history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1008, 0x1044]
        );
    }

    /// No worker process is needed to exercise delivery order. A pending
    /// function request holds the real GUI queue while tests deliver byte replies.
    fn hex_app() -> DesktopApp {
        let mut app = semantic_app();
        app.info.as_mut().unwrap().sections = vec![
            SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x2200,
                file_offset: 0,
                file_size: 0x2200,
                executable: true,
            },
            SectionInfo {
                name: ".data".into(),
                address: 0x8000,
                size: 0x100,
                file_offset: 0x2200,
                file_size: 32,
                executable: false,
            },
        ];
        app.info.as_mut().unwrap().file_len = 0x2220;
        app.pending = Some(Pending {
            result: None,
            id: 99,
            request: Request::Graph { address: 0x1000 },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
        });
        app
    }

    fn deferred_bytes(app: &mut DesktopApp) -> Pending {
        let (request, origin) = app.discovery_bytes.take().expect("deferred byte action");
        Pending {
            result: None,
            id: 100,
            request,
            started: Instant::now(),
            selection: origin.selection,
            revision: origin.revision,
            byte_origin: origin.byte_origin,
            bytes: origin.bytes,
        }
    }

    fn data_page(value: u8) -> Vec<u8> {
        let mut bytes = vec![0; 0x100];
        bytes[..32].fill(value);
        bytes
    }

    fn byte_payload(pending: &Pending, value: u8) -> Response {
        let Request::Bytes { address, length } = pending.request else {
            panic!("byte request")
        };
        Response::Bytes {
            address,
            bytes: if address == 0x8000 && length == 0x100 {
                data_page(value)
            } else {
                vec![value; length]
            },
        }
    }

    fn assert_decoder_source(app: &mut DesktopApp, address: u64, bytes: &[u8]) {
        let context = egui::Context::default();
        theme::install(&context);
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            let _ = app.decoder.show(ui);
        });
        output.textures_delta.clear();
        let text = rendered_text(&output);
        assert!(
            text.iter()
                .any(|text| text == &format!("Source: {address:#x}, {} bytes", bytes.len())),
            "{text:?}"
        );
        assert!(text.iter().any(|text| text == &hex(bytes)), "{text:?}");
    }

    #[test]
    fn hex_section_and_decode_actions_preserve_function_context_and_project_state() {
        let context = egui::Context::default();
        let mut app = hex_app();
        app.semantic.select_instruction(0x1004);
        app.history = vec![0x1040, 0x1000]
            .into_iter()
            .map(crate::linkage_ui::Place::Code)
            .collect();
        app.history_index = 1;
        let selected = app.selected;
        let address_field = app.address.clone();
        let selection = app.selection_generation;
        let revision = app.revision;
        let history = app.history.clone();
        let code = app.decompiled().to_owned();
        let mappings = serde_json::to_string(app.semantic.mappings.as_ref()).unwrap();
        let semantic_addresses = app.semantic.addresses.clone();
        let view = serde_json::to_string(&app.view()).unwrap();
        let listing = serde_json::to_string(&app.listing().iter().collect::<Vec<_>>()).unwrap();
        let dirty = app.dirty();
        app.open_hex_section(1, &context);
        assert!(app.tab == Tab::Hex);
        let pending = deferred_bytes(&mut app);
        assert!(matches!(
            pending.request,
            Request::Bytes {
                address: 0x8000,
                length: 0x100
            }
        ));
        let response = byte_payload(&pending, 0x41);
        app.receive(pending, response, &context);
        assert_eq!(
            app.hex.loaded_page(),
            Some((0x8000, data_page(0x41).as_slice()))
        );
        assert!(app.tab == Tab::Hex);
        app.handle_hex_action(
            HexAction::Decode {
                address: 0x8002,
                bytes: vec![0x41; 3],
            },
            &context,
        );
        assert!(app.tab == Tab::Decode);
        assert_decoder_source(&mut app, 0x8002, &[0x41; 3]);
        assert_eq!(app.selected, selected);
        assert_eq!(app.address, address_field);
        assert_eq!(app.selection_generation, selection);
        assert_eq!(app.revision, revision);
        assert_eq!(app.history, history);
        assert_eq!(app.history_index, 1);
        assert_eq!(app.decompiled(), code);
        assert_eq!(
            serde_json::to_string(app.semantic.mappings.as_ref()).unwrap(),
            mappings
        );
        assert_eq!(app.semantic.addresses, semantic_addresses);
        assert_eq!(serde_json::to_string(&app.view()).unwrap(), view);
        assert_eq!(
            serde_json::to_string(&app.listing().iter().collect::<Vec<_>>()).unwrap(),
            listing
        );
        assert_eq!(app.dirty(), dirty);
        assert!(app.canvas.is_some());
        assert!(app.code.is_some());
    }

    #[test]
    fn hex_destination_never_depends_on_the_tab_active_when_bytes_arrive() {
        let context = egui::Context::default();
        let mut app = hex_app();
        app.decode_loaded_bytes(0x1010, vec![0xde, 0xad]);
        app.open_hex_section(1, &context);
        let pending = deferred_bytes(&mut app);
        app.tab = Tab::Strings;
        let response = byte_payload(&pending, 0x42);
        app.receive(pending, response, &context);
        assert!(app.tab == Tab::Strings);
        assert_eq!(
            app.hex.loaded_page(),
            Some((0x8000, data_page(0x42).as_slice()))
        );
        assert_decoder_source(&mut app, 0x1010, &[0xde, 0xad]);

        // A normal Request::Bytes still means Decode, even while Hex is visible.
        app.tab = Tab::Hex;
        app.request(
            Request::Bytes {
                address: 0x1000,
                length: 2,
            },
            &context,
        );
        let pending = deferred_bytes(&mut app);
        let response = byte_payload(&pending, 0x43);
        app.receive(pending, response, &context);
        assert!(app.tab == Tab::Decode);
        assert_decoder_source(&mut app, 0x1000, &[0x43; 2]);
        assert_eq!(
            app.hex.loaded_page(),
            Some((0x8000, data_page(0x42).as_slice()))
        );
    }

    #[test]
    fn stale_hex_page_and_its_late_error_cannot_replace_a_newer_page() {
        let context = egui::Context::default();
        for error in [false, true] {
            for completed in [false, true] {
                let mut app = hex_app();
                app.open_hex_section(0, &context);
                let old = deferred_bytes(&mut app);
                app.open_hex_section(1, &context);
                let mut new = Some(deferred_bytes(&mut app));
                if completed {
                    let pending = new.take().unwrap();
                    let response = byte_payload(&pending, 0x42);
                    app.receive(pending, response, &context);
                } else {
                    app.status = "new page pending".into();
                }
                app.tab = Tab::References;
                let response = if error {
                    Response::Error {
                        message: "old page failed".into(),
                    }
                } else {
                    byte_payload(&old, 0x41)
                };
                app.receive(old, response, &context);
                assert!(app.tab == Tab::References);
                assert_eq!(
                    app.pending.as_ref().unwrap().id,
                    99,
                    "late errors must not stop the worker"
                );
                if let Some(pending) = new {
                    assert!(
                        app.hex.is_loading(),
                        "an old error must not cancel the new pending page"
                    );
                    assert_eq!(app.status, "new page pending");
                    let response = byte_payload(&pending, 0x42);
                    app.receive(pending, response, &context);
                }
                assert_eq!(
                    app.hex.loaded_page(),
                    Some((0x8000, data_page(0x42).as_slice()))
                );
                assert_eq!(app.status, "Hex page loaded");
                assert!(app.tab == Tab::References);
            }
        }
    }

    #[test]
    fn a_hex_copy_and_an_instruction_copy_both_supersede_old_decoder_reads() {
        let context = egui::Context::default();
        for from_hex in [false, true] {
            let mut app = hex_app();
            app.request(
                Request::Bytes {
                    address: 0x1000,
                    length: 4,
                },
                &context,
            );
            let old = deferred_bytes(&mut app);
            if from_hex {
                app.open_hex_section(1, &context);
                let page = deferred_bytes(&mut app);
                let response = byte_payload(&page, 0x55);
                app.receive(page, response, &context);
                app.handle_hex_action(
                    HexAction::Decode {
                        address: 0x8000,
                        bytes: vec![0x55; 2],
                    },
                    &context,
                );
            } else {
                app.decode_loaded_bytes(0x1004, vec![0x55; 2]);
            }
            let copied = if from_hex { 0x8000 } else { 0x1004 };
            let intent = app.byte_intent;
            let response = byte_payload(&old, 0x11);
            app.receive(old, response, &context);
            assert_decoder_source(&mut app, copied, &[0x55; 2]);
            assert!(app.tab == Tab::Decode);
            assert_eq!(app.byte_intent, intent);
            assert_eq!(app.pending.as_ref().unwrap().id, 99);
        }
    }

    #[test]
    fn byte_context_changes_reject_pages_decoder_payloads_and_late_errors() {
        let context = egui::Context::default();
        for page in [false, true] {
            for changed in 0..4 {
                for error in [false, true] {
                    let mut app = hex_app();
                    app.decode_loaded_bytes(0x1010, vec![0xaa, 0xbb]);
                    if page {
                        app.open_hex_section(1, &context);
                    } else {
                        app.request(
                            Request::Bytes {
                                address: 0x1000,
                                length: 2,
                            },
                            &context,
                        );
                    }
                    let pending = deferred_bytes(&mut app);
                    match changed {
                        0 => {
                            app.generation += 1;
                            app.clear_views();
                        }
                        1 => app.selection_generation += 1,
                        2 => app.revision += 1,
                        3 => app.selected = Some(0x1008),
                        _ => unreachable!(),
                    }
                    app.tab = Tab::References;
                    app.status = "new context".into();
                    let response = if error {
                        Response::Error {
                            message: "old context failed".into(),
                        }
                    } else {
                        byte_payload(&pending, 0x11)
                    };
                    app.receive(pending, response, &context);
                    assert!(app.hex.loaded_page().is_none());
                    assert!(!app.hex.is_loading(), "a stale current page needs Retry");
                    assert!(app.tab == Tab::References);
                    assert_eq!(app.status, "new context");
                    assert_eq!(app.pending.as_ref().unwrap().id, 99);
                    if changed != 0 {
                        assert_decoder_source(&mut app, 0x1010, &[0xaa, 0xbb]);
                    }
                }
            }
        }
    }

    fn retry_hex_page(app: &mut DesktopApp, context: &egui::Context) {
        let frame = |app: &mut DesktopApp, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 720.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| app.main_panel(ui),
            );
            output.textures_delta.clear();
            output
        };
        let _ = frame(app, vec![]);
        let output = frame(app, vec![]);
        let point = output
            .shapes
            .iter()
            .find_map(|shape| {
                if let egui::epaint::Shape::Text(text) = &shape.shape
                    && text.galley.text() == "Retry"
                {
                    Some(text.pos + text.galley.size() * 0.5)
                } else {
                    None
                }
            })
            .expect("failed pages expose an explicit Retry button");
        let _ = frame(app, pointer_events(point));
    }

    #[test]
    fn short_page_and_byte_errors_require_an_explicit_retry_without_stopping_analysis() {
        let context = egui::Context::default();
        theme::install(&context);
        for error in [false, true] {
            let mut app = hex_app();
            app.open_hex_section(1, &context);
            let pending = deferred_bytes(&mut app);
            let response = if error {
                Response::Error {
                    message: "page unavailable".into(),
                }
            } else {
                Response::Bytes {
                    address: 0x8000,
                    bytes: vec![1; 0xff],
                }
            };
            app.receive(pending, response, &context);
            assert!(
                app.hex.loaded_page().is_none(),
                "a short page must never be padded or adopted"
            );
            assert!(!app.hex.is_loading());
            assert_eq!(app.pending.as_ref().unwrap().id, 99);
            let intent = app.byte_intent;
            for _ in 0..3 {
                let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
                output.textures_delta.clear();
                assert!(
                    app.discovery_bytes.is_none(),
                    "painting a failed page must not retry"
                );
            }
            assert_eq!(app.byte_intent, intent);
            retry_hex_page(&mut app, &context);
            let retry = deferred_bytes(&mut app);
            let response = byte_payload(&retry, 0x33);
            app.receive(retry, response, &context);
            assert_eq!(
                app.hex.loaded_page(),
                Some((0x8000, data_page(0x33).as_slice()))
            );
        }
    }

    #[test]
    fn cancelling_a_page_drops_queued_bytes_and_retry_gets_a_fresh_intent() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = hex_app();
        app.open_hex_section(1, &context);
        let old = deferred_bytes(&mut app);
        let old_intent = app.byte_intent;
        app.stop_worker();
        assert!(!app.hex.is_loading());
        assert!(app.discovery_bytes.is_none());
        for _ in 0..3 {
            let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
            output.textures_delta.clear();
        }
        assert!(app.discovery_bytes.is_none());
        // Hold a replacement worker operation while the explicit retry queues.
        app.pending = hex_app().pending;
        retry_hex_page(&mut app, &context);
        assert!(app.byte_intent > old_intent);
        let retry = deferred_bytes(&mut app);
        let response = byte_payload(&old, 0x11);
        app.receive(old, response, &context);
        assert!(
            app.hex.is_loading(),
            "cancelled delivery cannot finish the retry"
        );
        let response = byte_payload(&retry, 0x66);
        app.receive(retry, response, &context);
        assert_eq!(
            app.hex.loaded_page(),
            Some((0x8000, data_page(0x66).as_slice()))
        );
    }

    #[test]
    fn busy_worker_page_clicks_coalesce_without_reopening_and_keep_the_original_origin() {
        let context = egui::Context::default();
        for request in [
            Request::Graph { address: 0x1000 },
            Request::Decompile { address: 0x1000 },
            Request::Strings,
            Request::Crypto,
            Request::Rename {
                address: 0x1000,
                name: "entry".into(),
            },
            Request::Bytes {
                address: 0x1000,
                length: 2,
            },
        ] {
            let mut app = hex_app();
            app.pending.as_mut().unwrap().request = request;
            app.worker_epoch = 17;
            app.queue.push_back(Request::Decompile { address: 0x1000 });
            let selection = app.selection_generation;
            let revision = app.revision;
            let selected = app.selected;
            app.open_hex_section(0, &context);
            let old_intent = app.byte_intent;
            app.open_hex_section(1, &context);
            let (request, origin) = app.discovery_bytes.as_ref().unwrap();
            assert!(matches!(
                request,
                Request::Bytes {
                    address: 0x8000,
                    length: 0x100
                }
            ));
            assert!(origin.bytes.unwrap().intent > old_intent);
            assert!(matches!(
                origin.bytes.unwrap().destination,
                ByteDestination::HexPage { .. }
            ));
            assert_eq!(origin.selection, selection);
            assert_eq!(origin.revision, revision);
            assert_eq!(origin.byte_origin.0, selected);
            assert!(origin.byte_origin.1 == Tab::Hex);
            assert_eq!(app.pending.as_ref().unwrap().id, 99);
            assert_eq!(app.worker_epoch, 17);
            assert!(app.opening.is_none());
            assert_eq!(app.queue.len(), 1);
            app.tab = Tab::Crypto;
            let (request, origin) = app.discovery_bytes.take().unwrap();
            app.selection_generation += 1;
            app.pending = None;
            app.schedule_open_follow(request, origin);
            assert!(app.pending.is_none());
            assert!(!app.hex.is_loading());
            assert!(app.tab == Tab::Crypto);
        }
    }

    #[test]
    fn opening_and_adoption_defer_bytes_without_replacing_function_followups() {
        let context = egui::Context::default();
        for opening in [false, true] {
            let mut app = hex_app();
            if opening {
                app.opening = Some(Opening {
                    path: PathBuf::from("retained-image"),
                    preserve: true,
                    follow: Some(Request::Decompile { address: 0x1000 }),
                    revision: app.revision,
                    follow_origin: app.request_origin(),
                });
            } else {
                app.pending = None;
                app.discovery_job = Some(mpsc::sync_channel(1).1);
            }
            app.open_hex_section(0, &context);
            app.open_hex_section(1, &context);
            assert!(matches!(
                app.discovery_bytes,
                Some((
                    Request::Bytes {
                        address: 0x8000,
                        length: 0x100
                    },
                    _
                ))
            ));
            if opening {
                assert!(matches!(
                    app.opening.as_ref().unwrap().follow,
                    Some(Request::Decompile { address: 0x1000 })
                ));
            } else {
                assert!(app.discovery_job.is_some());
                assert!(app.opening.is_none());
            }
        }

        // A navigation action arriving during a byte-triggered reopen moves the
        // original byte consumer into the same deferred slot rather than losing it.
        let mut app = hex_app();
        app.open_hex_section(1, &context);
        let (read, origin) = app.discovery_bytes.take().unwrap();
        app.opening = Some(Opening {
            path: PathBuf::from("retained-image"),
            preserve: true,
            follow: Some(read),
            revision: app.revision,
            follow_origin: origin,
        });
        app.request(Request::Decompile { address: 0x1000 }, &context);
        let (read, deferred) = app.discovery_bytes.as_ref().unwrap();
        assert!(matches!(
            read,
            Request::Bytes {
                address: 0x8000,
                length: 0x100
            }
        ));
        assert_eq!(deferred.bytes.unwrap().intent, origin.bytes.unwrap().intent);
        assert_eq!(deferred.selection, origin.selection);
        assert_eq!(deferred.revision, origin.revision);
        assert!(deferred.byte_origin.1 == origin.byte_origin.1);
    }

    #[test]
    fn invalid_byte_ranges_do_not_interrupt_a_busy_worker_or_enter_the_queue() {
        let context = egui::Context::default();
        let mut app = hex_app();
        for (address, length) in [(0x1000, 0), (0x1000, MAX_BYTE_READ + 1), (u64::MAX, 2)] {
            app.request(Request::Bytes { address, length }, &context);
            assert!(app.discovery_bytes.is_none());
            assert!(app.opening.is_none());
            assert_eq!(app.pending.as_ref().unwrap().id, 99);
            assert!(app.status.contains("Invalid byte read range"));
        }
    }

    #[test]
    fn malformed_stale_bytes_and_wrong_request_ids_still_stop_the_worker() {
        let context = egui::Context::default();
        for malformed in 0..3 {
            let mut app = hex_app();
            app.open_hex_section(1, &context);
            let old = deferred_bytes(&mut app);
            app.decode_loaded_bytes(0x1000, vec![0x90]);
            let response = match malformed {
                0 => Response::Bytes {
                    address: 0x8001,
                    bytes: vec![0; 0x100],
                },
                1 => Response::Bytes {
                    address: 0x8000,
                    bytes: vec![0; 0x101],
                },
                _ => Response::Crypto {
                    matches: vec![],
                    truncated: false,
                },
            };
            app.receive(old, response, &context);
            assert!(
                app.pending.is_none(),
                "protocol violations remain fatal even for stale reads"
            );
            assert!(app.status.contains("worker stopped"));
            assert_decoder_source(&mut app, 0x1000, &[0x90]);
        }
        let mut app = hex_app();
        app.receive_worker_reply(
            WorkerResponse {
                id: 98,
                response: Response::Bytes {
                    address: 0x1000,
                    bytes: vec![0],
                },
            },
            &context,
        );
        assert!(app.pending.is_none());
        assert!(app.status.contains("unexpected request ID"));
    }

    #[test]
    fn hex_pages_survive_ordinary_tab_paints_and_never_request_on_idle_frames() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = hex_app();
        app.open_hex_section(1, &context);
        let pending = deferred_bytes(&mut app);
        let response = byte_payload(&pending, 0x77);
        app.receive(pending, response, &context);
        app.pending = None;
        let intent = app.byte_intent;
        for tab in [
            Tab::Decode,
            Tab::Listing,
            Tab::Hex,
            Tab::References,
            Tab::Hex,
        ] {
            app.tab = tab;
            for _ in 0..3 {
                let mut output = context.run_ui(egui::RawInput::default(), |ui| app.main_panel(ui));
                output.textures_delta.clear();
                assert!(app.discovery_bytes.is_none());
                assert!(app.pending.is_none());
                assert!(app.opening.is_none());
            }
            assert_eq!(
                app.hex.loaded_page(),
                Some((0x8000, data_page(0x77).as_slice()))
            );
        }
        assert_eq!(app.byte_intent, intent);
        app.clear_views();
        assert!(app.hex.loaded_page().is_none());
        assert!(!app.hex.is_loading());
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
            Tab::Hex,
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
        let mut app = keyboard_app();
        show_view(
            &mut app,
            FunctionView {
                address: 0x1000,
                blocks: Vec::new(),
                edges: Vec::new(),
                calls: Vec::new(),
                warnings: Vec::new(),
            },
        );
        let text =
            "uint4 café(int param_1) {\n /* multiline\n    🦀 */\n return param_1 + 0x10;\n}\n";
        app.receive(
            Pending {
                result: None,
                id: 1,
                request: Request::Decompile { address: 0x1000 },
                started: Instant::now(),
                selection: 0,
                revision: 0,
                byte_origin: (None, Tab::Listing),
                bytes: None,
            },
            Response::Decompiled {
                address: 0x1000,
                mappings: Vec::new(),
                semantics: Default::default(),
                text: text.into(),
            },
            &context,
        );
        assert_eq!(app.decompiled(), text);
        assert!(app.code.is_some());
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        app.clear_binary();
        assert!(app.code.is_none());
        assert!(app.decompiled().is_empty());
    }

    #[test]
    fn desktop_rejects_oversized_decompiler_text_before_highlighting() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        show_view(
            &mut app,
            FunctionView {
                address: 0x1000,
                blocks: Vec::new(),
                edges: Vec::new(),
                calls: Vec::new(),
                warnings: Vec::new(),
            },
        );
        for extra in [0, 1] {
            let text = format!("//{}", "x".repeat(MAX_DECOMPILED_BYTES - 2 + extra));
            app.receive(
                Pending {
                    result: None,
                    id: 1,
                    request: Request::Decompile { address: 0x1000 },
                    started: Instant::now(),
                    selection: 0,
                    revision: 0,
                    byte_origin: (None, Tab::Listing),
                    bytes: None,
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
                assert_eq!(app.decompiled().len(), MAX_DECOMPILED_BYTES);
                assert!(app.code.is_some());
            } else {
                assert!(app.decompiled().is_empty());
                assert!(app.code.is_none());
                assert!(code_lines(&app.code).is_empty());
                assert!(app.status.contains("exceeded the 2 MiB limit"));
                assert!(app.client.is_none());
            }
        }
    }
    fn retained_app() -> DesktopApp {
        let mut app = semantic_app();
        let view = app.view().unwrap().clone();
        let text = app.decompiled().to_owned();
        let mappings = app.semantic.mappings.to_vec();
        let semantics = app.semantics().clone();
        app.results.open(&"a".repeat(64), &[]);
        app.results
            .update_inputs(app.info.as_ref().unwrap().functions.clone(), vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        let binding = app.results.binding(0x1000, String::new()).unwrap();
        let graph = app.results.admit_graph(
            Some(&binding),
            PreparedGraph::new(view),
            ResultOrigin::Saved,
            None,
        );
        let code = app.results.admit_decompilation(
            Some(&binding),
            PreparedDecompilation::prepare(0x1000, text, mappings, semantics),
            ResultOrigin::Saved,
            None,
        );
        app.adopt_graph(graph, ResultOrigin::Saved);
        app.adopt_decompilation(code, ResultOrigin::Saved);
        let binding = app.results.binding(0x1040, String::new()).unwrap();
        app.results.admit_graph(
            Some(&binding),
            PreparedGraph::new(FunctionView {
                address: 0x1040,
                blocks: vec![BasicBlock {
                    address: 0x1040,
                    instructions: vec![Instruction {
                        address: 0x1040,
                        bytes: vec![0xc3],
                        mnemonic: "ret".into(),
                        operands: String::new(),
                    }],
                }],
                edges: vec![],
                calls: vec![],
                warnings: vec![],
            }),
            ResultOrigin::Computed,
            None,
        );
        app.results.admit_decompilation(
            Some(&binding),
            PreparedDecompilation::prepare(
                0x1040,
                "return;".into(),
                vec![],
                SemanticInfo::default(),
            ),
            ResultOrigin::Computed,
            None,
        );
        app
    }

    #[test]
    fn full_hits_restore_exact_instruction_history_and_saved_provenance_synchronously() {
        let context = egui::Context::default();
        let mut app = retained_app();
        let graph = app.graph.clone().unwrap();
        let code = app.code.clone().unwrap();
        app.navigate_location(0x1008, Some(0x1000), true, &context);
        app.navigate(0x1040, true, &context);
        assert_eq!(app.view().unwrap().address, 0x1040);
        assert!(!app.saved_analysis);
        app.history_step(false, &context);
        assert_eq!(app.selected, Some(0x1008));
        assert!(Arc::ptr_eq(app.graph.as_ref().unwrap(), &graph));
        assert!(Arc::ptr_eq(app.code.as_ref().unwrap(), &code));
        assert!(app.cached_graph && app.saved_analysis);
        assert!(app.reference_focus.is_none());
        assert!(app.pending_listing_scroll.is_some());
        app.history_step(true, &context);
        assert_eq!(app.view().unwrap().address, 0x1040);
        app.navigate_location(0x1004, Some(0x1000), true, &context);
        assert_eq!(app.selected, Some(0x1004));
        assert!(!app.semantic.ranges.is_empty());
        assert!(app.client.is_none() && app.pending.is_none() && app.queue.is_empty());
    }

    #[test]
    fn old_function_reply_after_refresh_cannot_display_or_enter_the_store() {
        let context = egui::Context::default();
        let mut app = retained_app();
        let old = app.results.binding(0x1000, String::new()).unwrap();
        app.results
            .refresh_decompilation(0x1000, crate::function_results::Invalidation::Refresh);
        app.clear_decompilation();
        app.receive(
            Pending {
                id: 1,
                request: Request::Decompile { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: Some(old),
            },
            Response::Decompiled {
                address: 0x1000,
                text: "late stale result".into(),
                mappings: vec![],
                semantics: SemanticInfo::default(),
            },
            &context,
        );
        assert!(app.code.is_none());
        let hit = app.results.lookup(0x1000, "");
        assert!(hit.graph.is_some() && hit.decompiled.is_none());
    }

    #[test]
    fn result_adoption_during_save_stays_dirty_and_failed_signature_ack_keeps_committed_references()
    {
        let context = egui::Context::default();
        let mut app = retained_app();
        app.project_path = Some("snapshot.grproj".into());
        let revision = app.result_revision;
        app.navigate(0x1040, true, &context);
        let (sender, receiver) = mpsc::channel();
        app.file_job = Some(receiver);
        sender
            .send(FileEvent::ProjectSaved {
                generation: app.generation,
                revision: app.revision,
                result_revision: revision,
                embedded: true,
                result: Ok(Some("snapshot.grproj".into())),
            })
            .unwrap();
        app.poll_files(&context);
        assert!(app.dirty());
        let publication = Arc::new(crate::call_analysis::CallIndex::new(CallAnalysis::default()));
        app.set_call_index(Some(publication.clone()));
        let (pending, mut response) = signature_ack(&mut app, vec![test_signature()], None);
        if let Response::SignaturesSynced { unapplied, .. } = &mut response {
            unapplied.push(SignatureStatus {
                function: 0x1000,
                reason: "not applied".into(),
            });
        }
        app.receive(pending, response, &context);
        assert!(Arc::ptr_eq(app.call_index.as_ref().unwrap(), &publication));
        assert!(app.results.lookup(0x1000, "").complete(true));
    }
    #[test]
    fn comment_and_presentation_label_import_keeps_current_results_and_sends_no_work() {
        let mut app = retained_app();
        let graph = app.graph.clone().unwrap();
        let code = app.code.clone().unwrap();
        let mut imported = app.session.as_ref().unwrap().clone();
        imported.annotations.insert(
            0x1004,
            Annotation {
                label: "display_only".into(),
                comment: "imported comment".into(),
                ..Default::default()
            },
        );
        let (sender, receiver) = mpsc::channel();
        app.file_job = Some(receiver);
        sender
            .send(FileEvent::Loaded {
                generation: app.generation,
                revision: app.revision,
                hash: imported.binary_sha256.clone(),
                result: Ok(Some((imported, "notes.json".into()))),
            })
            .unwrap();
        app.poll_files(&egui::Context::default());
        assert!(Arc::ptr_eq(app.graph.as_ref().unwrap(), &graph));
        assert!(Arc::ptr_eq(app.code.as_ref().unwrap(), &code));
        assert!(!app.results.preparing());
        assert!(app.results.lookup(0x1000, "").complete(true));
        assert!(app.pending.is_none() && app.opening.is_none() && app.queue.is_empty());
    }

    #[test]
    fn import_of_another_functions_local_override_keeps_current_graph_and_code() {
        let mut app = retained_app();
        let graph = app.graph.clone().unwrap();
        let code = app.code.clone().unwrap();
        let mut imported = app.session.as_ref().unwrap().clone();
        imported.local_renames.push(LocalRename {
            identity: LocalIdentity {
                function: 0x1040,
                engine: crate::semantic::LOCAL_FINGERPRINT.into(),
                storage: crate::semantic::LocalStorage::Stack,
                offset: 8,
                size: 4,
                verification: "a".repeat(64),
            },
            name: "other_local".into(),
        });
        let (sender, receiver) = mpsc::channel();
        app.file_job = Some(receiver);
        sender
            .send(FileEvent::Loaded {
                generation: app.generation,
                revision: app.revision,
                hash: imported.binary_sha256.clone(),
                result: Ok(Some((imported, "notes.json".into()))),
            })
            .unwrap();
        app.poll_files(&egui::Context::default());
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        assert!(Arc::ptr_eq(app.graph.as_ref().unwrap(), &graph));
        assert!(Arc::ptr_eq(app.code.as_ref().unwrap(), &code));
        assert!(app.results.lookup(0x1000, "").complete(true));
        assert!(
            app.results
                .lookup(0x1040, &app.results.local_state(0x1040))
                .decompiled
                .is_none()
        );
        assert!(app.pending.is_none() && app.opening.is_none() && app.queue.is_empty());
    }
    #[test]
    fn a_cache_hit_during_reopen_retires_the_old_queued_destination() {
        let context = egui::Context::default();
        let mut app = retained_app();
        let origin = app.request_origin();
        app.opening = Some(Opening {
            path: "fixture".into(),
            preserve: true,
            follow: Some(Request::Graph { address: 0x1000 }),
            revision: app.revision,
            follow_origin: origin,
        });
        app.navigate(0x1040, true, &context);
        assert!(app.opening.as_ref().unwrap().follow.is_none());
        app.schedule_open_follow(Request::Graph { address: 0x1000 }, origin);
        assert_eq!(app.view().unwrap().address, 0x1040);
        assert_eq!(app.decompiled(), "return;");
        assert!(app.pending.is_none() && app.queue.is_empty());
    }

    #[test]
    fn committed_worker_recovery_reuses_results_without_laundering_saved_provenance() {
        let mut app = retained_app();
        let code = app.code.clone().unwrap();
        app.graph = None;
        app.clear_decompilation();
        let origin = app.request_origin();
        app.schedule_open_follow(Request::Graph { address: 0x1000 }, origin);
        assert!(Arc::ptr_eq(app.code.as_ref().unwrap(), &code));
        assert!(app.saved_analysis && app.cached_graph);
        assert!(app.pending.is_none() && app.queue.is_empty());
    }
    #[test]
    fn identical_cache_adoption_stays_saved_and_fresh_code_adoption_becomes_dirty() {
        let context = egui::Context::default();
        let mut app = retained_app();
        app.project_path = Some("snapshot.grproj".into());
        app.saved_revision = app.revision;
        app.saved_result_revision = app.result_revision;
        app.navigate_to(0x1000, app.selected, false, &context);
        assert!(!app.dirty());
        let binding = app.results.binding(0x1000, String::new()).unwrap();
        app.receive(
            Pending {
                id: 1,
                request: Request::Decompile { address: 0x1000 },
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: Some(binding),
            },
            Response::Decompiled {
                address: 0x1000,
                text: "new analysis".into(),
                mappings: vec![],
                semantics: SemanticInfo::default(),
            },
            &context,
        );
        assert!(app.dirty());
        assert_eq!(app.revision, app.saved_revision);
    }

    fn linkage_app(sha256: &str) -> (DesktopApp, crate::linkage::LinkageTable) {
        let mut app = DesktopApp::empty(None);
        app.info = Some(crate::linkage_ui::fixture::info(sha256));
        app.session = Some(Session::new(sha256.into()));
        app.selected = Some(0x1000);
        app.address = "1000".into();
        app.rebuild_filter();
        app.linkage.begin(app.generation, app.worker_epoch);
        let table = crate::linkage_ui::fixture::table(
            sha256,
            vec![crate::linkage::LinkageGap::DelayVariant],
        );
        (app, table)
    }

    fn linkage_reply(
        app: &DesktopApp,
        request: Request,
        table: &crate::linkage::LinkageTable,
    ) -> (Pending, Response) {
        let Request::Linkage { cursor, .. } = &request else {
            panic!("expected a linkage request");
        };
        let page = table.page(*cursor).unwrap();
        (
            Pending {
                id: 1,
                request,
                started: Instant::now(),
                selection: app.selection_generation,
                revision: app.revision,
                byte_origin: (app.selected, app.tab),
                bytes: None,
                result: None,
            },
            Response::Linkage {
                summary: table.summary().clone(),
                page,
            },
        )
    }

    fn adopt_linkage(app: &mut DesktopApp, table: &crate::linkage::LinkageTable) {
        let context = egui::Context::default();
        while let Some(request) = app.linkage.request(app.generation, app.worker_epoch) {
            let (pending, reply) = linkage_reply(app, request, table);
            app.receive(pending, reply, &context);
        }
        for _ in 0..5000 {
            app.poll_linkage();
            if app.linkage.status() != crate::linkage_ui::Status::Loading {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(app.linkage.status(), crate::linkage_ui::Status::Ready);
    }

    #[test]
    fn linkage_rows_navigate_exactly_and_never_create_functions() {
        use crate::linkage_ui::{LinkageItem, fixture};
        let context = egui::Context::default();
        let (mut app, table) = linkage_app(&"a".repeat(64));
        adopt_linkage(&mut app, &table);
        assert!(app.results.usage().charged > 0, "linkage is charged");
        let functions = app.info.as_ref().unwrap().functions.clone();
        let unchanged = |app: &DesktopApp| {
            assert_eq!(app.info.as_ref().unwrap().functions, functions);
            assert!(app.pending.is_none() && app.opening.is_none());
            assert!(
                !app.queue
                    .iter()
                    .any(|request| matches!(request, Request::Graph { .. }))
            );
        };
        // A data export opens Hex at its exact address.
        app.open_linkage(LinkageItem::Export(1), &context);
        assert_eq!(app.tab, Tab::Hex);
        assert_eq!(app.selected, Some(fixture::DATA_EXPORT));
        assert_eq!(
            app.history.last().map(|place| place.address()),
            Some(fixture::DATA_EXPORT)
        );
        assert_eq!(app.linkage.selected(), Some(LinkageItem::Export(1)));
        unchanged(&app);
        // Forwarders and unresolved entries only become selected.
        let history = app.history.clone();
        for id in [2, 3] {
            app.open_linkage(LinkageItem::Export(id), &context);
            assert_eq!(app.linkage.selected(), Some(LinkageItem::Export(id)));
            assert_eq!(
                (app.tab, &app.history, app.selected),
                (Tab::Hex, &history, Some(fixture::DATA_EXPORT))
            );
        }
        // An import goes to its verified stub through code navigation.
        let generation = app.selection_generation;
        app.open_linkage(LinkageItem::Import(0), &context);
        assert_eq!(app.selected, Some(fixture::STUB));
        assert_eq!(app.tab, Tab::Listing);
        assert_ne!(app.selection_generation, generation);
        assert_eq!(
            app.history.last().map(|place| place.address()),
            Some(fixture::STUB)
        );
        // Its slot-only namesake in another library opens its slot instead.
        app.open_linkage(LinkageItem::Import(1), &context);
        assert_eq!(
            (app.tab, app.selected),
            (Tab::Hex, Some(fixture::SLOT_ONLY))
        );
        unchanged(&app);
        // Back/Forward revisit the exact addresses.
        app.history_step(false, &context);
        assert_eq!(app.selected, Some(fixture::STUB));
        app.history_step(false, &context);
        assert_eq!(app.selected, Some(fixture::DATA_EXPORT));
        app.history_step(true, &context);
        assert_eq!(app.selected, Some(fixture::STUB));
        app.history_step(true, &context);
        assert_eq!(
            (app.tab, app.selected),
            (Tab::Hex, Some(fixture::SLOT_ONLY))
        );
        assert_eq!(app.hex.focused_span(), Some((fixture::SLOT_ONLY, 8)));
        assert!(app.semantic.addresses.is_empty());
        // Returning to the same VA with a different span retains both steps.
        app.navigate_data(fixture::SLOT_ONLY, 1, &context);
        app.history_step(false, &context);
        assert_eq!(app.hex.focused_span(), Some((fixture::SLOT_ONLY, 8)));
        app.history_step(true, &context);
        assert_eq!(app.hex.focused_span(), Some((fixture::SLOT_ONLY, 1)));
        for offset in 0..300 {
            app.navigate_data(fixture::SLOT_ONLY, 1 + offset % 8, &context);
        }
        assert_eq!(app.history.len(), 256);
        assert_eq!(app.history_index, 255);
        app.history_step(false, &context);
        app.navigate_data(fixture::DATA_EXPORT, 1, &context);
        assert_eq!(app.history_index + 1, app.history.len());
        assert_eq!(app.info.as_ref().unwrap().functions, functions);
    }

    #[test]
    fn linkage_x_uses_exact_addresses_or_the_bounded_chooser() {
        use crate::linkage_ui::{LinkageItem, fixture};
        let context = egui::Context::default();
        theme::install(&context);
        let (mut app, table) = linkage_app(&"a".repeat(64));
        adopt_linkage(&mut app, &table);
        // Several verified locations become explicit choices.
        app.selected_call = Some(0x1000);
        app.select_linkage(LinkageItem::Import(0));
        assert!(app.selected_call.is_none(), "stale call token cleared");
        app.show_selection_xrefs();
        let choices = app.xref_choices.as_ref().expect("target chooser");
        assert_eq!(
            choices
                .set
                .targets
                .iter()
                .map(|target| (target.address, target.kind))
                .collect::<Vec<_>>(),
            [
                (fixture::STUB, TargetKind::Function),
                (0x1030, TargetKind::Address),
                (fixture::SLOT, TargetKind::DataAccess),
                (0x2020, TargetKind::DataAccess),
            ]
        );
        assert_eq!(app.tab, Tab::References);
        // One exact address opens References directly, through the X key.
        app.select_linkage(LinkageItem::Import(1));
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::X, egui::Modifiers::NONE)],
        );
        assert!(app.xref_choices.is_none());
        assert_eq!(
            app.xref_target,
            Some(XrefTarget {
                address: fixture::SLOT_ONLY,
                kind: TargetKind::DataAccess
            })
        );
        // A forwarder has no address, so X does nothing.
        let status = app.status.clone();
        app.select_linkage(LinkageItem::Export(2));
        app.show_selection_xrefs();
        assert_eq!(app.xref_target.unwrap().address, fixture::SLOT_ONLY);
        assert!(app.xref_choices.is_none());
        assert_eq!(app.status, status);
        // Once the selection moves, X follows it rather than the row.
        app.select_linkage(LinkageItem::Export(1));
        app.select_instruction(0x1000);
        assert_eq!(
            app.selection_xref_targets().targets,
            [XrefTarget {
                address: 0x1000,
                kind: TargetKind::Function
            }]
        );
    }

    fn paged_linkage_table(sha256: &str) -> crate::linkage::LinkageTable {
        let records = std::iter::once(crate::linkage::LinkageRecord::Library(
            crate::linkage::Library {
                id: 0,
                name: "paged.dll".into(),
            },
        ))
        .chain((0..1500).map(|id| {
            crate::linkage::LinkageRecord::Import(crate::linkage_ui::fixture::import(
                id,
                Some(&format!("paged_{id}")),
                Some(0),
            ))
        }))
        .collect();
        crate::linkage::LinkageTable::new(records, Vec::new()).with_image(sha256)
    }

    #[test]
    fn late_linkage_pages_after_a_new_binary_or_cancel_are_dropped() {
        let context = egui::Context::default();
        let (mut app, _) = linkage_app(&"a".repeat(64));
        let table = paged_linkage_table(&"a".repeat(64));
        let first = app
            .linkage
            .request(app.generation, app.worker_epoch)
            .unwrap();
        let (pending, reply) = linkage_reply(&app, first, &table);
        app.receive(pending, reply, &context);
        let second = app
            .linkage
            .request(app.generation, app.worker_epoch)
            .unwrap();
        assert!(matches!(second, Request::Linkage { cursor, digest: Some(_) } if cursor > 0));
        // Cancel discards received pages; the late reply changes nothing.
        let (pending, reply) = linkage_reply(&app, second.clone(), &table);
        app.stop_worker();
        app.receive(pending, reply, &context);
        assert_eq!(app.linkage.status(), crate::linkage_ui::Status::Loading);
        assert!(matches!(
            app.linkage.request(app.generation, app.worker_epoch),
            Some(Request::Linkage {
                cursor: 0,
                digest: None
            })
        ));
        // A replacement worker for the same image starts from the first page.
        app.worker_epoch += 1;
        app.linkage.begin(app.generation, app.worker_epoch);
        assert!(matches!(
            app.linkage.request(app.generation, app.worker_epoch),
            Some(Request::Linkage {
                cursor: 0,
                digest: None
            })
        ));
        // A page answering the previous binary is dropped after a new open.
        let first = app
            .linkage
            .request(app.generation, app.worker_epoch)
            .unwrap();
        let (pending, reply) = linkage_reply(&app, first, &table);
        app.receive(pending, reply, &context);
        let (pending, reply) = linkage_reply(&app, second, &table);
        app.clear_views();
        app.generation += 1;
        app.linkage.begin(app.generation, app.worker_epoch);
        app.receive(pending, reply, &context);
        assert_eq!(app.linkage.status(), crate::linkage_ui::Status::Loading);
        assert!(app.status.is_empty() || !app.status.contains("linkage"));
        adopt_linkage(&mut app, &table);
        assert_eq!(
            app.linkage.prepared().unwrap().linkage().imports.len(),
            1500
        );
        // A tampered current page fails closed; a worker error only loses the table.
        app.clear_views();
        app.generation += 1;
        app.linkage.begin(app.generation, app.worker_epoch);
        let request = app
            .linkage
            .request(app.generation, app.worker_epoch)
            .unwrap();
        let (pending, mut reply) = linkage_reply(&app, request.clone(), &table);
        if let Response::Linkage { page, .. } = &mut reply {
            page.entries.swap(0, 1);
        }
        app.receive(pending, reply, &context);
        assert_eq!(app.linkage.status(), crate::linkage_ui::Status::Unavailable);
        assert!(app.status.contains("linkage"), "{}", app.status);
        assert!(
            app.linkage
                .request(app.generation, app.worker_epoch)
                .is_none()
        );
        app.clear_views();
        app.generation += 1;
        app.linkage.begin(app.generation, app.worker_epoch);
        let (pending, _) = linkage_reply(&app, request, &table);
        app.receive(
            pending,
            Response::Error {
                message: "linkage failed".into(),
            },
            &context,
        );
        assert_eq!(app.linkage.status(), crate::linkage_ui::Status::Unavailable);
        assert_eq!(app.status, "linkage failed");
    }

    #[test]
    fn linkage_tree_fits_narrow_and_wide_docks_at_fractional_scale() {
        fn frame(
            context: &egui::Context,
            app: &mut DesktopApp,
            width: f32,
            events: Vec<egui::Event>,
        ) -> egui::FullOutput {
            let time = context.input(|input| input.time) + 0.05;
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 800.0),
                    )),
                    time: Some(time),
                    events,
                    ..Default::default()
                },
                |root| {
                    egui::Panel::left("linkage-tree-test")
                        .exact_size(width)
                        .frame(egui::Frame::NONE)
                        .show(root, |ui| app.symbol_tree(ui));
                },
            );
            output.textures_delta.clear();
            output
        }
        fn bars(output: &egui::FullOutput) -> Vec<egui::Rect> {
            output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Rect(rect)
                        if rect.rect.width().min(rect.rect.height()) < 20.0
                            && rect.rect.width().max(rect.rect.height()) > 60.0 =>
                    {
                        Some(rect.rect)
                    }
                    _ => None,
                })
                .collect()
        }

        let context = egui::Context::default();
        theme::install(&context);
        context.set_pixels_per_point(1.25);
        context.all_styles_mut(|style| {
            style.animation_time = 0.0;
            style.spacing.scroll = egui::style::ScrollStyle::solid();
        });
        let (mut app, table) = linkage_app(&"a".repeat(64));
        app.client = None;
        frame(&context, &mut app, 260.0, vec![]);
        let output = frame(&context, &mut app, 260.0, vec![]);
        assert!(!rendered_text(&output).iter().any(|t| t.contains("Loading")));
        adopt_linkage(&mut app, &table);
        frame(&context, &mut app, 260.0, vec![]);
        let output = frame(&context, &mut app, 260.0, vec![]);
        let text = rendered_text(&output);
        assert!(
            text.iter()
                .any(|t| t.starts_with("Imports (4)") && t.ends_with("Partial"))
        );
        let imports = text_position(&output, "Imports (4)", 0);
        frame(&context, &mut app, 260.0, pointer_events(imports));
        let output = frame(&context, &mut app, 260.0, vec![]);
        let group = text_position(&output, "KERNEL32.dll (2)", 0);
        frame(&context, &mut app, 260.0, pointer_events(group));
        let output = frame(&context, &mut app, 260.0, vec![]);
        let exports = text_position(&output, "Exports (5)", 0);
        frame(&context, &mut app, 260.0, pointer_events(exports));
        for width in [150.0, 260.0, 431.0, 260.0] {
            frame(&context, &mut app, width, vec![]);
            let output = frame(&context, &mut app, width, vec![]);
            let again = frame(&context, &mut app, width, vec![]);
            assert_eq!(
                bars(&output),
                bars(&again),
                "no scrollbar flicker at {width}"
            );
            let rows: Vec<_> = output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text)
                        if ["fn", "Shared", "code_export", "data_export", "ordinal 9"]
                            .contains(&text.galley.text()) =>
                    {
                        Some((shape.clip_rect, text.galley.rows.len()))
                    }
                    _ => None,
                })
                .collect();
            assert!(rows.len() >= 5, "{width}: {rows:?}");
            for (clip, lines) in rows {
                assert_eq!(lines, 1);
                assert!(clip.right() <= width + 0.5, "{width}: {clip:?}");
            }
            // Expanded lists stay within their content height: no scrollbars.
            assert!(
                bars(&output)
                    .iter()
                    .all(|bar| bar.height() < bar.width() || bar.height() > 300.0),
                "{width}: {:?}",
                bars(&output)
            );
        }
        // Clicking selects; double-clicking a data row opens Hex.
        let output = frame(&context, &mut app, 260.0, vec![]);
        let data = text_position(&output, "data_export", 0);
        frame(&context, &mut app, 260.0, pointer_events(data));
        assert_eq!(
            app.linkage.selected(),
            Some(crate::linkage_ui::LinkageItem::Export(1))
        );
        assert_ne!(app.tab, Tab::Hex);
        frame(&context, &mut app, 260.0, pointer_events(data));
        assert_eq!(app.tab, Tab::Hex);
        assert_eq!(app.selected, Some(crate::linkage_ui::fixture::DATA_EXPORT));
    }

    fn function_dock_frame(
        context: &egui::Context,
        app: &mut DesktopApp,
        width: f32,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let time = context.input(|input| input.time) + 0.05;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 800.0),
                )),
                time: Some(time),
                events,
                ..Default::default()
            },
            |root| {
                egui::Panel::left("function-dock-test")
                    .exact_size(width)
                    .frame(egui::Frame::NONE)
                    .show(root, |ui| app.navigation_panel(ui));
            },
        );
        output.textures_delta.clear();
        output
    }

    /// Centers of every galley whose whole text is `text`, top to bottom.
    fn exact_text(output: &egui::FullOutput, text: &str) -> Vec<egui::Pos2> {
        let mut found: Vec<egui::Pos2> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(shown) if shown.galley.text() == text => {
                    Some(shown.galley.rect.translate(shown.pos.to_vec2()).center())
                }
                _ => None,
            })
            .collect();
        found.sort_by(|a, b| a.y.total_cmp(&b.y));
        found
    }

    fn selection_fill_at(output: &egui::FullOutput, point: egui::Pos2) -> bool {
        output.shapes.iter().any(|shape| {
            matches!(&shape.shape, egui::epaint::Shape::Rect(rect)
                if rect.fill == theme::SELECTION && rect.rect.contains(point))
        })
    }

    #[test]
    fn function_dock_tabs_share_linkage_selection_navigation_and_filters() {
        use crate::linkage_ui::{LinkageItem, Table, TreeAction, fixture};
        let context = egui::Context::default();
        theme::install(&context);
        context.set_pixels_per_point(1.25);
        context.all_styles_mut(|style| style.animation_time = 0.0);
        let (mut app, table) = linkage_app(&"a".repeat(64));
        app.client = None;
        adopt_linkage(&mut app, &table);
        let width = 340.0;
        let frame =
            |app: &mut DesktopApp, events| function_dock_frame(&context, app, width, events);
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        let [tab] = exact_text(&output, "Imports")[..] else {
            panic!("one Imports tab")
        };
        frame(&mut app, pointer_events(tab));
        assert_eq!(app.function_dock, FunctionDock::Imports);
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        // Flat: declared names across libraries; ordinal-only last.
        assert_eq!(
            app.linkage.flat_items(Table::Imports).unwrap(),
            [2, 0, 1, 3].map(LinkageItem::Import)
        );
        let text = rendered_text(&output);
        for shown in ["Library", "KERNEL32.dll", "USER32.dll", "Unknown library"] {
            assert!(text.iter().any(|t| t == shown), "{shown}: {text:?}");
        }
        assert!(
            text.iter()
                .any(|t| t.ends_with("1010") && t.starts_with('0'))
        );
        let row =
            |output: &egui::FullOutput, name: &str, index: usize| exact_text(output, name)[index];
        // A click selects the same item the Symbol Tree highlights.
        let history = app.history.clone();
        frame(&mut app, pointer_events(row(&output, "fn", 0)));
        assert_eq!(app.linkage.selected(), Some(LinkageItem::Import(2)));
        assert_eq!(app.linkage_target(), Some(LinkageItem::Import(2)));
        assert_eq!(app.history, history);
        let output = frame(&mut app, vec![]);
        assert!(selection_fill_at(&output, row(&output, "fn", 0)));
        let tree_imports = text_position(&output, "Imports (4)", 0);
        frame(&mut app, pointer_events(tree_imports));
        let output = frame(&mut app, vec![]);
        let group = text_position(&output, "KERNEL32.dll (2)", 0);
        frame(&mut app, pointer_events(group));
        let output = frame(&mut app, vec![]);
        let names = exact_text(&output, "fn");
        assert_eq!(names.len(), 2, "tree and flat rows");
        assert!(names.iter().all(|&name| selection_fill_at(&output, name)));
        // A tree selection is highlighted in the flat Exports.
        app.linkage_action(Some(TreeAction::Select(LinkageItem::Export(1))), &context);
        app.function_dock = FunctionDock::Exports;
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        assert!(selection_fill_at(&output, row(&output, "data_export", 0)));
        assert!(rendered_text(&output).iter().any(|t| t == "Ordinal"));
        // Double-click opens code through navigation and data in Hex.
        app.function_dock = FunctionDock::Imports;
        frame(&mut app, vec![]);
        let output = frame(&mut app, vec![]);
        let flat =
            |output: &egui::FullOutput, name: &str| *exact_text(output, name).last().unwrap();
        let shared = flat(&output, "Shared");
        let kernel = exact_text(&output, "Shared")
            .into_iter()
            .rev()
            .nth(1)
            .unwrap();
        assert!(kernel.y < shared.y);
        frame(&mut app, pointer_events(kernel));
        frame(&mut app, pointer_events(kernel));
        assert_eq!((app.tab, app.selected), (Tab::Listing, Some(fixture::STUB)));
        assert_eq!(
            app.history.last().map(|place| place.address()),
            Some(fixture::STUB)
        );
        assert_eq!(app.linkage.selected(), Some(LinkageItem::Import(0)));
        // Past the multi-click window, so the next pair is a new double-click.
        for _ in 0..10 {
            frame(&mut app, vec![]);
        }
        let output = frame(&mut app, vec![]);
        let shared = flat(&output, "Shared");
        frame(&mut app, pointer_events(shared));
        frame(&mut app, pointer_events(shared));
        assert_eq!(
            (app.tab, app.selected),
            (Tab::Hex, Some(fixture::SLOT_ONLY))
        );
        // The row menu offers the tree's explicit places.
        let output = frame(&mut app, vec![]);
        frame(&mut app, secondary_events(flat(&output, "fn")));
        let output = frame(&mut app, vec![]);
        let go = text_position(&output, "Go to slot 2010", 0);
        assert!(rendered_text(&output).iter().any(|t| t == "Xrefs to…"));
        frame(&mut app, pointer_events(go));
        assert_eq!((app.tab, app.selected), (Tab::Hex, Some(0x2010)));
        // Typing filters by library, raw name, ordinal, address and label.
        let output = frame(&mut app, vec![]);
        let hint = text_position(&output, "Filter name or address", 0);
        frame(&mut app, pointer_events(hint));
        frame(&mut app, vec![egui::Event::Text("kernel32".into())]);
        frame(&mut app, vec![]);
        assert_eq!(app.linkage_filters[Table::Imports as usize], "kernel32");
        assert_eq!(
            app.linkage.flat_items(Table::Imports).unwrap(),
            [2, 0].map(LinkageItem::Import)
        );
        context.memory_mut(|memory| memory.stop_text_input());
        app.edit_annotation(
            fixture::STUB,
            Annotation {
                label: "analyst_shared".into(),
                ..Annotation::default()
            },
        );
        for (query, expected) in [
            ("YAXXZ", vec![2]),
            ("ordinal 42", vec![3]),
            ("2018", vec![3]),
            ("analyst", vec![0]),
        ] {
            app.linkage_filters[Table::Imports as usize] = query.into();
            frame(&mut app, vec![]);
            assert_eq!(
                app.linkage.flat_items(Table::Imports).unwrap(),
                expected
                    .into_iter()
                    .map(LinkageItem::Import)
                    .collect::<Vec<_>>(),
                "{query}"
            );
        }
        app.function_dock = FunctionDock::Exports;
        for (query, expected) in [("ordinal 9", 3), ("2040", 1)] {
            app.linkage_filters[Table::Exports as usize] = query.into();
            frame(&mut app, vec![]);
            assert_eq!(
                app.linkage.flat_items(Table::Exports).unwrap(),
                [LinkageItem::Export(expected)],
                "{query}"
            );
        }
        // Functions keeps its own filter across tab switches.
        let click_tab = |app: &mut DesktopApp, label: &str| {
            let output = frame(app, vec![]);
            let [tab] = exact_text(&output, label)[..] else {
                panic!("one {label} tab")
            };
            frame(app, pointer_events(tab));
            frame(app, vec![]);
            frame(app, vec![])
        };
        click_tab(&mut app, "Functions");
        app.function_filter = "entry".into();
        app.restart_filter();
        let functions = app.filtered_functions.clone();
        assert_eq!(functions, [0]);
        click_tab(&mut app, "Imports");
        assert_eq!(app.function_dock, FunctionDock::Imports);
        assert_eq!(app.linkage_filters[Table::Imports as usize], "analyst");
        let output = click_tab(&mut app, "Functions");
        assert_eq!(app.function_dock, FunctionDock::Functions);
        assert_eq!(
            (app.function_filter.as_str(), &app.filtered_functions),
            ("entry", &functions)
        );
        assert!(rendered_text(&output).iter().any(|t| t == "entry"));
        // Another binary generation drops the flat list with the table.
        app.function_dock = FunctionDock::Imports;
        app.linkage_filters[Table::Imports as usize].clear();
        frame(&mut app, vec![]);
        assert!(app.linkage.flat_items(Table::Imports).is_some());
        app.generation += 1;
        app.linkage.begin(app.generation, app.worker_epoch);
        let output = frame(&mut app, vec![]);
        assert!(app.linkage.flat_items(Table::Imports).is_none());
        assert!(exact_text(&output, "Shared").is_empty());
    }

    #[test]
    fn function_dock_tabs_stay_reachable_and_fit_narrow_docks_at_fractional_scale() {
        use crate::linkage_ui::{LinkageItem, Table};
        fn bars(output: &egui::FullOutput) -> Vec<egui::Rect> {
            output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Rect(rect)
                        if rect.rect.width().min(rect.rect.height()) < 20.0
                            && rect.rect.width().max(rect.rect.height()) > 60.0 =>
                    {
                        Some(rect.rect)
                    }
                    _ => None,
                })
                .collect()
        }
        let labels = ["Functions", "Imports", "Exports"];
        for width in [150.0, 200.0, 260.0, 431.0] {
            let context = egui::Context::default();
            theme::install(&context);
            context.set_pixels_per_point(1.25);
            context.all_styles_mut(|style| style.animation_time = 0.0);
            let (mut app, table) = linkage_app(&"a".repeat(64));
            app.client = None;
            adopt_linkage(&mut app, &table);
            let frame =
                |app: &mut DesktopApp, events| function_dock_frame(&context, app, width, events);
            frame(&mut app, vec![]);
            let output = frame(&mut app, vec![]);
            let shown: Vec<_> = labels
                .iter()
                .map(|label| exact_text(&output, label).first().copied())
                .collect();
            let exports = if shown.iter().all(Option::is_some) {
                shown[2].unwrap()
            } else {
                // Collapsed to a view menu: every tab is one of its entries.
                assert!(shown[0].is_some(), "selected tab remains visible");
                let more = *exact_text(&output, "»")
                    .last()
                    .expect("Functions overflow chevron");
                frame(&mut app, pointer_events(more));
                let output = frame(&mut app, vec![]);
                for label in labels {
                    assert!(!exact_text(&output, label).is_empty(), "{width}: {label}");
                }
                *exact_text(&output, "Exports").last().unwrap()
            };
            frame(&mut app, pointer_events(exports));
            assert_eq!(app.function_dock, FunctionDock::Exports, "{width}");
            for dock in [FunctionDock::Exports, FunctionDock::Imports] {
                app.function_dock = dock;
                frame(&mut app, vec![]);
                let output = frame(&mut app, vec![]);
                let again = frame(&mut app, vec![]);
                assert_eq!(bars(&output), bars(&again), "{width}: no scrollbar flicker");
                let mut headings: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::epaint::Shape::Text(text)
                            if ["Address", "Name", "Library", "Ordinal"]
                                .contains(&text.galley.text()) =>
                        {
                            Some(text.galley.rect.translate(text.pos.to_vec2()))
                        }
                        _ => None,
                    })
                    .collect();
                headings.sort_by(|a, b| a.left().total_cmp(&b.left()));
                for pair in headings.windows(2) {
                    assert!(
                        pair[0].right() + 2.0 < pair[1].left(),
                        "{width}: headings overlap: {pair:?}"
                    );
                }
                let rows: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::epaint::Shape::Text(text)
                            if ["fn", "Shared", "code_export", "data_export", "KERNEL32.dll"]
                                .contains(&text.galley.text()) =>
                        {
                            Some((shape.clip_rect, text.galley.rows.len()))
                        }
                        _ => None,
                    })
                    .collect();
                assert!(rows.len() >= 2, "{width}: {rows:?}");
                for (clip, lines) in rows {
                    assert_eq!(lines, 1);
                    assert!(clip.right() <= width + 0.5, "{width}: {clip:?}");
                }
            }
            assert_eq!(
                app.linkage.flat_items(Table::Exports).unwrap().len(),
                5,
                "{width}"
            );
            assert!(
                app.linkage
                    .flat_items(Table::Imports)
                    .unwrap()
                    .contains(&LinkageItem::Import(0))
            );
        }
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn project_saved_at_linkage_data_reopens_and_fetches_tree_without_navigation() {
        use crate::linkage_ui::{LinkageItem, Status};
        let directory = tempfile::tempdir().unwrap();
        #[cfg(target_os = "linux")]
        let binary = {
            let binary = directory.path().join("sample");
            assert!(
                std::process::Command::new("gcc")
                    .args(["-O0", "-g", "-rdynamic", "tests/fixtures/sample.c", "-o"])
                    .arg(&binary)
                    .status()
                    .unwrap()
                    .success()
            );
            binary
        };
        #[cfg(windows)]
        let binary = match std::env::var_os("GHIDRA_RUST_TEST_PE") {
            Some(path) => PathBuf::from(path),
            None => return, // scripts/build-windows.ps1 supplies the native fixture.
        };
        let executable = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join(if cfg!(windows) {
                "ghidra-rust.exe"
            } else {
                "ghidra-rust"
            });
        assert!(
            executable.is_file(),
            "full cargo test builds the worker executable: {}",
            executable.display()
        );
        let context = egui::Context::default();
        let mut app = DesktopApp::empty(None);
        // Use the application's executable rather than Cargo's test harness.
        let start = |app: &mut DesktopApp, path: PathBuf| {
            let mut client =
                WorkerClient::start_using_executable(context.clone(), &path, &executable).unwrap();
            if let Some(project) = &app.opening_project
                && let Some(binary) = &project.project.binary
            {
                client.retain_source(Arc::new(binary.clone()));
            }
            app.client = Some(client);
            app.worker_epoch += 1;
            app.opening = Some(Opening {
                path: path.clone(),
                preserve: false,
                follow: None,
                revision: app.revision,
                follow_origin: app.request_origin(),
            });
            app.send_direct(Request::Open {
                path: path.to_string_lossy().into_owned(),
            });
        };
        let settle = |app: &mut DesktopApp| {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                app.poll_worker(&context);
                if app.linkage.status() == Status::Ready
                    && app.pending.is_none()
                    && app.queue.is_empty()
                    && !app.results.preparing()
                    && app.deferred_restore.is_none()
                {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "reopen did not settle: {}, tree {:?}",
                    app.status,
                    app.linkage.status()
                );
                assert!(app.client.is_some(), "worker stopped: {}", app.status);
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        start(&mut app, binary);
        settle(&mut app);
        app.analyze_prompt = None;
        let code_pc = app.selected.unwrap();
        #[cfg(target_os = "linux")]
        let item = {
            let linkage = app.linkage.prepared().unwrap().linkage();
            let import = linkage
                .imports
                .iter()
                .find(|import| import.raw.as_deref() == Some("__libc_start_main"))
                .unwrap();
            assert!(import.stub.is_none());
            LinkageItem::Import(import.id)
        };
        #[cfg(windows)]
        let item = {
            let linkage = app.linkage.prepared().unwrap().linkage();
            LinkageItem::Export(
                linkage
                    .exports
                    .iter()
                    .find(|export| export.raw.as_deref() == Some("base64_message"))
                    .unwrap()
                    .id,
            )
        };
        app.open_linkage(item, &context);
        let data_address = app.selected.unwrap();
        assert_eq!(app.tab, Tab::Hex);
        assert_eq!(app.project_selection(), Some(code_pc));
        let project_path = directory.path().join("data-location.grproj");
        app.project_path = Some(project_path.clone());
        app.save_project(false, &context);
        while app.file_job.is_some() {
            app.poll_files(&context);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            ProjectData::load(&project_path)
                .unwrap()
                .data
                .selected_address,
            Some(code_pc)
        );
        // Also exercise projects saved by the original feature: they persisted
        // a data selection alongside the previous displayed code results.
        let mut old = ProjectData::load(&project_path).unwrap().data;
        old.selected_address = Some(data_address);
        old.info.source_identity = app.info.as_ref().unwrap().source_identity;
        let legacy_path = directory.path().join("legacy-data-location.grproj");
        old.save(&legacy_path, app.binary_protection.as_ref().unwrap(), true)
            .unwrap();
        old.view = None;
        old.decompiled = None;
        old.mappings.clear();
        old.semantics = Default::default();
        let entry_path = directory.path().join("legacy-no-code-view.grproj");
        old.save(&entry_path, app.binary_protection.as_ref().unwrap(), true)
            .unwrap();
        // Without a saved view, reopening lands where a fresh open would.
        let opening_pc = start_address(app.info.as_ref().unwrap()).unwrap();
        for (path, expected_pc) in [
            (project_path, code_pc),
            (legacy_path, code_pc),
            (entry_path, opening_pc),
        ] {
            app.clear_binary();
            app.open_project(path, &context);
            while app.file_job.is_some() {
                app.poll_files(&context);
                std::thread::sleep(Duration::from_millis(2));
            }
            let opening = app
                .opening
                .as_ref()
                .expect("project starts worker verification")
                .path
                .clone();
            // Replace only Cargo's harness process; keep the real file-load,
            // Opened verification, deferred restore and page-adoption paths.
            start(&mut app, opening);
            settle(&mut app);
            assert_eq!(app.selected, Some(expected_pc));
            assert_eq!(app.tab, Tab::Listing);
            assert!(app.view().is_some());
            assert!(!app.status.contains("outside file-backed"));
            assert_eq!(app.linkage.status(), Status::Ready);
            assert!(!app.linkage.prepared().unwrap().linkage().imports.is_empty());
        }
        app.clear_binary();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn shared_library_without_main_or_entry_opens_at_a_known_function() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("liblinkage.so");
        assert!(
            std::process::Command::new("gcc")
                .args(["-O0", "-fPIC", "-shared", "tests/fixtures/linkage.c", "-o"])
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let executable = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ghidra-rust");
        assert!(
            executable.is_file(),
            "full cargo test builds the worker executable: {}",
            executable.display()
        );
        let context = egui::Context::default();
        let mut app = DesktopApp::empty(None);
        app.client = Some(
            WorkerClient::start_using_executable(context.clone(), &binary, &executable).unwrap(),
        );
        app.worker_epoch += 1;
        app.opening = Some(Opening {
            path: binary.clone(),
            preserve: false,
            follow: None,
            revision: app.revision,
            follow_origin: app.request_origin(),
        });
        app.send_direct(Request::Open {
            path: binary.to_string_lossy().into_owned(),
        });
        let deadline = Instant::now() + Duration::from_secs(30);
        while app.info.is_none() || app.pending.is_some() || !app.queue.is_empty() {
            app.poll_worker(&context);
            assert!(
                Instant::now() < deadline,
                "open did not settle: {}",
                app.status
            );
            assert!(app.client.is_some(), "worker stopped: {}", app.status);
            std::thread::sleep(Duration::from_millis(2));
        }
        let info = app.info.as_ref().unwrap();
        // A shared library declares no entry point and has no `main`.
        assert_eq!(info.entry, 0);
        assert!(
            info.functions
                .iter()
                .all(|function| function.name != "main")
        );
        assert!(
            !app.status.contains("outside file-backed"),
            "{}",
            app.status
        );
        let selected = app.selected.expect("opens at a known function");
        assert!(
            info.functions
                .iter()
                .any(|function| function.address == selected)
        );
        assert!(crate::call_analysis::code_address(info, selected));
        assert!(app.view().is_some());
        app.clear_binary();
    }

    #[test]
    fn saved_projects_omit_linkage_and_reopen_rebuilds_it_from_the_image() {
        use crate::linkage_ui::{LinkageItem, Status, fixture};
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("fixture.bin");
        std::fs::write(&binary, [0_u8; 0x400]).unwrap();
        let sha256 = crate::session::fingerprint(&binary).unwrap();
        let (mut app, table) = linkage_app(&sha256);
        let info = app.info.as_mut().unwrap();
        info.path = binary.to_string_lossy().into_owned();
        info.source_identity = FileIdentity::from_file(&std::fs::File::open(&binary).unwrap());
        let protection = BinaryProtection::open(&binary)
            .unwrap()
            .bind_snapshot(info)
            .unwrap();
        adopt_linkage(&mut app, &table);
        app.edit_annotation(
            fixture::STUB,
            Annotation {
                label: "analyst_shared".into(),
                ..Annotation::default()
            },
        );
        app.select_linkage(LinkageItem::Import(2));
        app.function_filter = "shared".into();
        app.restart_filter();
        let data = ProjectData {
            info: app.info.clone().unwrap(),
            session: app.session.clone().unwrap(),
            view: None,
            decompiled: None,
            mappings: Vec::new(),
            semantics: Default::default(),
            strings: Vec::new(),
            strings_truncated: false,
            crypto: Vec::new(),
            crypto_truncated: false,
            selected_address: app.selected,
            discovery: None,
        };
        let project_path = directory.path().join("linkage.grproj");
        data.save(&project_path, &protection, true).unwrap();
        let bytes = std::fs::read(&project_path).unwrap();
        for declared in ["USER32.dll", "data_export", "OTHER.Func", "?fn@@YAXXZ"] {
            assert!(
                !bytes
                    .windows(declared.len())
                    .any(|window| window == declared.as_bytes()),
                "{declared} is not persisted"
            );
        }
        // Reopen: a new generation starts empty and fetches from the image.
        let project = ProjectData::load(&project_path).unwrap();
        let extracted = project.binary.as_ref().unwrap().path().to_owned();
        app.clear_views();
        app.generation += 1;
        app.function_filter.clear();
        app.restart_filter();
        app.session = Some(project.data.session.clone());
        app.restore_project(
            ProjectOpen {
                project,
                project_path,
                binary_path: extracted,
                discovery_index: None,
            },
            &egui::Context::default(),
        );
        app.linkage.begin(app.generation, app.worker_epoch);
        assert_eq!(app.linkage.status(), Status::Loading);
        assert!(app.linkage.selected().is_none() && app.linkage.prepared().is_none());
        adopt_linkage(&mut app, &fixture::table(&sha256, Vec::new()));
        let linkage = app.linkage.prepared().unwrap().linkage();
        assert_eq!(linkage.digest, table.summary().digest);
        // The saved label still names the import at its exact stub.
        let import = &linkage.imports[0];
        assert_eq!(
            crate::linkage_ui::shown_name(
                Some(
                    app.session.as_ref().unwrap().annotations[&fixture::STUB]
                        .label
                        .as_str()
                ),
                &import.raw,
                &import.display,
                import.ordinal
            ),
            "analyst_shared"
        );
    }

    fn tap(key: egui::Key, modifiers: egui::Modifiers) -> Vec<egui::Event> {
        let press = key_event(key, modifiers);
        let mut release = press.clone();
        if let egui::Event::Key { pressed, .. } = &mut release {
            *pressed = false;
        }
        vec![press, release]
    }

    fn find_modifiers() -> egui::Modifiers {
        egui::Modifiers {
            ctrl: !cfg!(target_os = "macos"),
            mac_cmd: cfg!(target_os = "macos"),
            command: true,
            ..Default::default()
        }
    }

    fn dialog_kind(app: &DesktopApp) -> Option<DialogKind> {
        app.search_dialog.as_ref().map(|dialog| dialog.kind)
    }

    #[test]
    fn search_shortcuts_respect_guards_escape_and_leave_other_bindings_intact() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, tap(egui::Key::S, egui::Modifiers::NONE));
        assert_eq!(dialog_kind(&app), Some(DialogKind::Memory));
        // The open search modal blocks every other shortcut.
        keyboard_frame(&context, &mut app, vec![]);
        for key in [egui::Key::F1, egui::Key::G, egui::Key::L, egui::Key::X] {
            keyboard_frame(&context, &mut app, tap(key, egui::Modifiers::NONE));
        }
        assert!(app.help_dialog.is_none() && app.browser_dialog.is_none());
        assert_eq!(app.tab, Tab::Listing);
        // Escape closes only the search modal.
        keyboard_frame(
            &context,
            &mut app,
            tap(egui::Key::Escape, egui::Modifiers::NONE),
        );
        assert_eq!(dialog_kind(&app), None);
        assert_eq!((app.tab, app.selected), (Tab::Listing, Some(0x1000)));
        assert!(app.searches.current.is_none());
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, vec![]);

        keyboard_frame(&context, &mut app, tap(egui::Key::F, find_modifiers()));
        assert_eq!(dialog_kind(&app), Some(DialogKind::Text));
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(
            &context,
            &mut app,
            tap(egui::Key::Escape, egui::Modifiers::NONE),
        );
        assert_eq!(dialog_kind(&app), None);
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, vec![]);

        // Text focus, file jobs, repeats and extra modifiers never open search.
        let filter = egui::Id::unique("function-filter");
        context.memory_mut(|memory| memory.request_focus(filter));
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, tap(egui::Key::S, egui::Modifiers::NONE));
        context.memory_mut(|memory| memory.surrender_focus(filter));
        let (_sender, receiver) = mpsc::sync_channel(1);
        app.file_job = Some(receiver);
        keyboard_frame(&context, &mut app, tap(egui::Key::F, find_modifiers()));
        // Hold S across the end of the file job: its repeat must not open.
        keyboard_frame(
            &context,
            &mut app,
            vec![key_event(egui::Key::S, egui::Modifiers::NONE)],
        );
        app.file_job = None;
        let mut repeat = key_event(egui::Key::S, egui::Modifiers::NONE);
        if let egui::Event::Key { repeat, .. } = &mut repeat {
            *repeat = true;
        }
        keyboard_frame(&context, &mut app, vec![repeat]);
        let release = tap(egui::Key::S, egui::Modifiers::NONE).pop().unwrap();
        keyboard_frame(&context, &mut app, vec![release]);
        keyboard_frame(
            &context,
            &mut app,
            tap(egui::Key::S, egui::Modifiers::SHIFT),
        );
        keyboard_frame(&context, &mut app, tap(egui::Key::F, egui::Modifiers::NONE));
        assert_eq!(dialog_kind(&app), None);

        // X still belongs to the selection, and Help lists both search keys.
        keyboard_frame(&context, &mut app, tap(egui::Key::X, egui::Modifiers::NONE));
        assert_eq!(app.tab, Tab::References);
        assert!(crate::help::SHORTCUTS.contains(&("S", "Search memory")));
        assert!(crate::help::SHORTCUTS.contains(&(crate::help::FIND_KEYS, "Search program text")));
    }

    #[test]
    fn search_dialog_submits_only_valid_queries_and_opens_the_search_tab() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        keyboard_frame(&context, &mut app, vec![]);
        keyboard_frame(&context, &mut app, tap(egui::Key::S, egui::Modifiers::NONE));
        keyboard_frame(&context, &mut app, vec![]);
        // A nibble wildcard is invalid hex: Enter keeps the dialog open.
        keyboard_frame(&context, &mut app, vec![egui::Event::Text("4?".into())]);
        keyboard_frame(
            &context,
            &mut app,
            tap(egui::Key::Enter, egui::Modifiers::NONE),
        );
        assert_eq!(dialog_kind(&app), Some(DialogKind::Memory));
        assert!(app.searches.current.is_none());
        app.search_form.memory_query = "D9 6E A5 ?? B7 C8".into();
        keyboard_frame(
            &context,
            &mut app,
            tap(egui::Key::Enter, egui::Modifiers::NONE),
        );
        assert_eq!(dialog_kind(&app), None);
        assert_eq!(app.tab, Tab::Search);
        let Some(SearchView {
            kind: SearchKind::Memory(memory),
            ..
        }) = &app.searches.current
        else {
            panic!("memory search");
        };
        assert_eq!(memory.pattern, "D9 6E A5 ?? B7 C8");
        assert_eq!(memory.state(), SearchState::Searching);
    }

    /// Answers each page the displayed memory search asks for by scanning
    /// `image` with the production scanner, as the worker would.
    fn deliver_memory_pages(app: &mut DesktopApp, image: &[u8], context: &egui::Context) {
        let info = app.info.clone().unwrap();
        let domain = crate::search::SearchDomain::new(&info.sections, info.file_len).unwrap();
        loop {
            let epoch = app.worker_epoch;
            let Some((_, memory)) = app.searches.memory_page() else {
                break;
            };
            let Some(request) = memory
                .session
                .as_mut()
                .unwrap()
                .next_request(epoch)
                .unwrap()
            else {
                break;
            };
            let page = memory_page(&domain, &request, image);
            let pending = search_pending(app, request);
            app.receive(pending, Response::MemorySearch(page), context);
        }
    }

    fn memory_page(
        domain: &crate::search::SearchDomain,
        request: &Request,
        image: &[u8],
    ) -> crate::search::MemorySearchPage {
        let Request::SearchMemory { spec, .. } = request else {
            panic!("memory search request");
        };
        domain
            .scan(
                image,
                &spec.compile().unwrap(),
                &domain.request_context(request).unwrap(),
            )
            .unwrap()
    }

    fn search_pending(app: &DesktopApp, request: Request) -> Pending {
        Pending {
            id: 7,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: None,
        }
    }

    fn ascii(text: &str) -> crate::search::MemorySearchSpec {
        crate::search::MemorySearchSpec {
            pattern: crate::search::MemoryPattern::Ascii { text: text.into() },
            match_case: false,
        }
    }

    fn memory_addresses(app: &DesktopApp) -> Vec<u64> {
        match &app.searches.current {
            Some(SearchView {
                kind: SearchKind::Memory(memory),
                ..
            }) => memory.hits().iter().map(|hit| hit.address).collect(),
            _ => Vec::new(),
        }
    }

    fn search_state(app: &DesktopApp) -> Option<SearchState> {
        app.searches.current.as_ref().map(SearchView::state)
    }

    /// hex_app's image: `.text` file bytes 0..0x2200, `.data` 0x2200..0x2220.
    fn marked_image() -> Vec<u8> {
        let mut image = vec![0; 0x2220];
        for (va, text) in [
            (0x1004u64, b"SRCH"),
            (0x1011, b"srch"),
            (0x1ffe, b"sRcH"),
            (0x8004, b"SRCH"),
        ] {
            let offset = if va >= 0x8000 {
                va - 0x8000 + 0x2200
            } else {
                va - 0x1000
            } as usize;
            image[offset..offset + 4].copy_from_slice(text);
        }
        image
    }

    #[test]
    fn memory_hits_open_code_only_with_an_owner_and_exact_hex_spans_across_pages() {
        let context = egui::Context::default();
        let mut app = hex_app();
        let (selected, history) = (app.selected, app.history.clone());
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        assert_eq!(app.tab, Tab::Search);
        // The analyst moves on; completion never switches tabs or selection,
        // and annotation edits do not stale raw byte matches.
        app.tab = Tab::Strings;
        app.edit_annotation(
            0x1040,
            Annotation {
                label: "renamed".into(),
                ..Default::default()
            },
        );
        deliver_memory_pages(&mut app, &marked_image(), &context);
        assert_eq!(search_state(&app), Some(SearchState::Complete));
        assert_eq!(memory_addresses(&app), [0x1004, 0x1011, 0x1ffe, 0x8004]);
        assert_eq!((app.tab, app.selected), (Tab::Strings, selected));
        assert_eq!(app.history, history);

        // An exact PC of the displayed CFG opens through code navigation.
        app.open_search_result(0, &context);
        assert_eq!((app.tab, app.selected), (Tab::Listing, Some(0x1004)));
        assert_eq!(app.view().map(|view| view.address), Some(0x1000));
        assert_eq!(
            app.history.last(),
            Some(&crate::linkage_ui::Place::Code(0x1004))
        );
        // Inside the function's bytes but not an observed instruction: Hex.
        app.open_search_result(1, &context);
        assert_eq!(app.tab, Tab::Hex);
        assert_eq!(app.data_location, Some((0x1011, 4)));
        assert_eq!(app.view().map(|view| view.address), Some(0x1000));
        let pending = deferred_bytes(&mut app);
        let response = byte_payload(&pending, 0x11);
        app.receive(pending, response, &context);
        assert_eq!(app.hex.focused_span(), Some((0x1011, 4)));

        // A span crossing the 0x2000 page keeps its whole exact selection.
        app.open_search_result(2, &context);
        let pending = deferred_bytes(&mut app);
        assert!(matches!(
            pending.request,
            Request::Bytes {
                address: 0x1ffe,
                ..
            }
        ));
        let response = byte_payload(&pending, 0x22);
        app.receive(pending, response, &context);
        assert_eq!(app.hex.selected_bytes(), Some((0x1ffe, vec![0x22; 4])));

        // Back and Forward revisit exact data places.
        app.history_step(false, &context);
        assert_eq!(app.data_location, Some((0x1011, 4)));
        let pending = deferred_bytes(&mut app);
        let response = byte_payload(&pending, 0x11);
        app.receive(pending, response, &context);
        app.history_step(true, &context);
        assert_eq!(app.data_location, Some((0x1ffe, 4)));
        let pending = deferred_bytes(&mut app);
        assert!(matches!(
            pending.request,
            Request::Bytes {
                address: 0x1ffe,
                ..
            }
        ));
        let response = byte_payload(&pending, 0x33);
        app.receive(pending, response, &context);
        assert_eq!(app.hex.selected_bytes(), Some((0x1ffe, vec![0x33; 4])));
        app.history_step(false, &context);
        app.history_step(false, &context);
        assert_eq!(
            app.history[app.history_index],
            crate::linkage_ui::Place::Code(0x1004)
        );
        assert_eq!(app.selected, Some(0x1004));

        // Data outside code also opens in Hex; it never becomes a function.
        let functions = app.info.as_ref().unwrap().functions.clone();
        app.open_search_result(3, &context);
        assert_eq!(app.data_location, Some((0x8004, 4)));
        assert_eq!(app.info.as_ref().unwrap().functions, functions);
    }

    #[test]
    fn memory_pages_bind_to_search_epoch_and_cancel_requery_or_close_clear_them() {
        let context = egui::Context::default();
        let mut app = hex_app();
        app.pending = None;
        let image = marked_image();
        let info = app.info.clone().unwrap();
        let domain = crate::search::SearchDomain::new(&info.sections, info.file_len).unwrap();
        let next = |app: &mut DesktopApp| {
            let epoch = app.worker_epoch;
            let (_, memory) = app.searches.memory_page().unwrap();
            memory
                .session
                .as_mut()
                .unwrap()
                .next_request(epoch)
                .unwrap()
                .unwrap()
        };

        // Cancel invalidates at once; its late page is dropped.
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        let request = next(&mut app);
        app.pending = Some(search_pending(&app, request.clone()));
        app.cancel_search();
        assert_eq!(search_state(&app), Some(SearchState::Canceled));
        // The bounded page finishes on the same worker instead of a reopen.
        let pending = app.pending.take().expect("in-flight page kept");
        assert!(app.opening.is_none(), "cancel must not reopen the binary");
        let late = memory_page(&domain, &request, &image);
        app.receive(pending, Response::MemorySearch(late), &context);
        assert_eq!(search_state(&app), Some(SearchState::Canceled));
        assert!(memory_addresses(&app).is_empty());

        // A requery's identity differs: the previous query's page is dropped,
        // as is a page from an earlier worker epoch.
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        let old = next(&mut app);
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        let page = memory_page(&domain, &old, &image);
        app.receive(
            search_pending(&app, old),
            Response::MemorySearch(page),
            &context,
        );
        assert_eq!(search_state(&app), Some(SearchState::Searching));
        assert!(memory_addresses(&app).is_empty());
        let request = next(&mut app);
        let page = memory_page(&domain, &request, &image);
        app.worker_epoch += 1;
        app.receive(
            search_pending(&app, request),
            Response::MemorySearch(page),
            &context,
        );
        assert!(memory_addresses(&app).is_empty());

        // A worker replaced with a page in flight resumes from the committed
        // cursor only after the replacement verified the same image.
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        let lost = next(&mut app);
        app.pending = Some(search_pending(&app, lost));
        app.stop_worker_inner();
        assert!(
            app.searches.memory_page().is_none(),
            "waits for verification"
        );
        let Some(SearchView {
            kind: SearchKind::Memory(memory),
            ..
        }) = &mut app.searches.current
        else {
            panic!("memory search");
        };
        assert!(memory.interrupted);
        memory.session.as_mut().unwrap().abandon_page();
        memory.interrupted = false;
        app.worker_epoch += 1;
        deliver_memory_pages(&mut app, &image, &context);
        assert_eq!(memory_addresses(&app), [0x1004, 0x1011, 0x1ffe, 0x8004]);

        // A malformed current page stops the worker and keeps committed hits.
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        let request = next(&mut app);
        let mut page = memory_page(&domain, &request, &image);
        page.hits[0].length += 1;
        app.receive(
            search_pending(&app, request),
            Response::MemorySearch(page),
            &context,
        );
        assert_eq!(search_state(&app), Some(SearchState::Unavailable));
        assert!(app.status.contains("memory search"), "{}", app.status);

        // A protocol error ends only this search, without retrying.
        app.start_memory_search(ascii("srch"), MemoryMode::Ascii, &context);
        let request = next(&mut app);
        app.receive(
            search_pending(&app, request),
            Response::Error {
                message: "no".into(),
            },
            &context,
        );
        assert_eq!(search_state(&app), Some(SearchState::Unavailable));
        assert!(app.searches.memory_page().is_none());

        // Close/new binary/project reopen drop results, dialog and the tab.
        app.tab = Tab::Search;
        app.search_dialog = Some(SearchDialog::new(DialogKind::Text, app.generation));
        app.search_form.text_query = "srch".into();
        app.clear_binary();
        assert!(app.searches.current.is_none() && app.search_dialog.is_none());
        assert!(app.search_form.text_query.is_empty());
        assert_ne!(app.tab, Tab::Search);
    }

    fn wait_for_text(app: &mut DesktopApp, context: &egui::Context) {
        for _ in 0..5000 {
            app.pump_text_search(context);
            if search_state(app) != Some(SearchState::Searching) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("text search did not finish");
    }

    fn text_hits(app: &DesktopApp) -> Vec<(crate::search_text::TextSourceKey, Option<u64>)> {
        match &app.searches.current {
            Some(SearchView {
                kind: SearchKind::Text(text),
                ..
            }) => text
                .hits()
                .iter()
                .map(|hit| (hit.key, hit.address))
                .collect(),
            _ => Vec::new(),
        }
    }

    fn text_app() -> DesktopApp {
        let mut app = keyboard_app();
        app.info.as_mut().unwrap().functions[1].name = "srch_fn".into();
        let session = app.session.as_mut().unwrap();
        session.annotations.insert(
            0x1000,
            Annotation {
                label: String::new(),
                comment: "see SRCH4ABA".into(),
                ..Default::default()
            },
        );
        session.annotations.insert(
            0x1010,
            Annotation {
                label: "srch_label".into(),
                ..Default::default()
            },
        );
        app.strings = vec![StringEntry {
            address: 0x1080,
            text: "a srch string".into(),
            encoding: "ascii".into(),
        }];
        app.strings_scanned = true;
        app.rebuild_filter();
        app
    }

    #[test]
    fn text_search_finds_loaded_sources_and_goes_stale_only_when_they_change() {
        use crate::search_text::{TextSearchSpec, TextSourceKey, TextSources};
        let context = egui::Context::default();
        let mut app = text_app();
        let spec = |sources| TextSearchSpec {
            query: "SRCH".into(),
            match_case: false,
            sources,
        };
        app.start_text_search(spec(TextSources::ALL));
        app.tab = Tab::Listing;
        wait_for_text(&mut app, &context);
        assert_eq!(
            text_hits(&app),
            [
                (TextSourceKey::Comment(0x1000), Some(0x1000)),
                (TextSourceKey::Label(0x1010), Some(0x1010)),
                (TextSourceKey::Name(0x1040), Some(0x1040)),
                (TextSourceKey::String(0), Some(0x1080)),
            ]
        );
        // The import/export table was never adopted: Partial, not Complete.
        assert_eq!(search_state(&app), Some(SearchState::Partial));
        assert_eq!((app.tab, app.selected), (Tab::Listing, Some(0x1000)));

        // Selection alone never stales text results.
        app.select_instruction(0x1040);
        app.pump_text_search(&context);
        assert_eq!(search_state(&app), Some(SearchState::Partial));

        // Labels and comments alone are complete loaded sources.
        app.start_text_search(spec(TextSources(
            TextSources::LABELS.0 | TextSources::COMMENTS.0,
        )));
        wait_for_text(&mut app, &context);
        assert_eq!(search_state(&app), Some(SearchState::Complete));
        assert_eq!(text_hits(&app).len(), 2);

        // Exact destinations: a label at a non-entry code byte opens Hex, a
        // known entry opens code, a string preview start opens Hex.
        app.start_text_search(spec(TextSources::ALL));
        wait_for_text(&mut app, &context);
        app.open_search_result(1, &context);
        assert_eq!((app.tab, app.data_location), (Tab::Hex, Some((0x1010, 1))));
        app.open_search_result(2, &context);
        assert_eq!(app.selected, Some(0x1040));
        assert_eq!(app.data_location, None);
        app.open_search_result(3, &context);
        assert_eq!(app.data_location, Some((0x1080, 1)));
        app.pump_text_search(&context);
        assert_eq!(search_state(&app), Some(SearchState::Partial));

        // Source edits make results stale; they are never silently refreshed.
        app.edit_annotation(
            0x1020,
            Annotation {
                comment: "srch".into(),
                ..Default::default()
            },
        );
        app.pump_text_search(&context);
        assert_eq!(search_state(&app), Some(SearchState::Stale));
        assert_eq!(text_hits(&app).len(), 4);
        app.undo(&context);
        app.pump_text_search(&context);
        assert_eq!(search_state(&app), Some(SearchState::Stale));
        for change in 0..3 {
            app.start_text_search(spec(TextSources::ALL));
            wait_for_text(&mut app, &context);
            match change {
                0 => app.rebuild_filter(),
                1 => {
                    app.source_epochs.bump_strings();
                }
                _ => app.fail_linkage(),
            }
            app.pump_text_search(&context);
            assert_eq!(search_state(&app), Some(SearchState::Stale), "{change}");
        }

        // A change during capture or matching stops it as Stale; Cancel keeps
        // whatever was committed and a newer query replaces an older job.
        app.start_text_search(spec(TextSources::ALL));
        app.pump_text_search(&context);
        app.symbol_revision += 1;
        app.pump_text_search(&context);
        assert_eq!(search_state(&app), Some(SearchState::Stale));
        app.start_text_search(spec(TextSources::ALL));
        app.pump_text_search(&context);
        app.cancel_search();
        assert_eq!(search_state(&app), Some(SearchState::Canceled));
        app.start_text_search(spec(TextSources::STRINGS));
        wait_for_text(&mut app, &context);
        assert_eq!(text_hits(&app), [(TextSourceKey::String(0), Some(0x1080))]);
    }

    #[test]
    fn text_search_shares_adopted_linkage_and_opens_declared_places() {
        use crate::search_text::{TextSearchSpec, TextSourceKey, TextSources};
        let context = egui::Context::default();
        let (mut app, table) = linkage_app(&"a".repeat(64));
        app.client = None;
        adopt_linkage(&mut app, &table);
        let linkage = app.linkage.prepared().unwrap().shared_linkage();
        let export = linkage
            .exports
            .iter()
            .find(|export| export.target.code() && export.raw.is_some())
            .expect("fixture code export");
        let (id, name) = (export.id, export.raw.clone().unwrap());
        app.start_text_search(TextSearchSpec {
            query: name.clone(),
            match_case: true,
            sources: TextSources::EXPORTS,
        });
        wait_for_text(&mut app, &context);
        // The fixture table records a gap, so its names are a partial source.
        assert_eq!(search_state(&app), Some(SearchState::Partial));
        let index = text_hits(&app)
            .iter()
            .position(|(key, _)| *key == TextSourceKey::Export(id))
            .expect("export hit");
        let place =
            crate::linkage_ui::destination(&linkage, crate::linkage_ui::LinkageItem::Export(id), 8)
                .unwrap();
        app.open_search_result(index, &context);
        assert_eq!(app.history.last(), Some(&place));
        // A replaced table no longer resolves captured linkage identities.
        app.fail_linkage();
        app.pump_text_search(&context);
        assert_eq!(search_state(&app), Some(SearchState::Stale));
        let view = app.searches.current.as_ref().unwrap();
        assert!(app.search_target(view, index, true).is_none());
    }

    fn desktop_frame(
        context: &egui::Context,
        app: &mut DesktopApp,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let time = context.input(|input| input.time) + 0.05;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1280.0, 800.0),
                )),
                time: Some(time),
                focused: true,
                events,
                ..Default::default()
            },
            |ui| app.draw(ui),
        );
        output.textures_delta.clear();
        output
    }

    /// Each pointer or key event in its own frame, as a desktop delivers them.
    fn desktop_events(
        context: &egui::Context,
        app: &mut DesktopApp,
        events: impl IntoIterator<Item = egui::Event>,
    ) {
        for event in events {
            desktop_frame(context, app, vec![event]);
        }
        desktop_frame(context, app, vec![]);
    }

    #[test]
    fn opened_search_hits_leave_listing_clicks_keys_and_shortcuts_working_after_back() {
        let context = egui::Context::default();
        theme::install(&context);
        context.set_pixels_per_point(1.25);
        context.all_styles_mut(|style| style.animation_time = 0.0);
        let mut app = hex_app();
        app.pending = None;
        app.client = None;
        app.tab = Tab::Listing;
        app.select_instruction(0x1000);
        desktop_frame(&context, &mut app, vec![]);

        // S, choose ASCII, type into the field, then Return.
        desktop_events(&context, &mut app, tap(egui::Key::S, egui::Modifiers::NONE));
        assert!(app.search_dialog.is_some());
        let output = desktop_frame(&context, &mut app, vec![]);
        let ascii = text_position(&output, "ASCII", 1);
        let hex = text_position(&output, "Hex", 1);
        let click = |app: &mut DesktopApp, point| {
            desktop_events(&context, app, pointer_events(point));
        };
        click(&mut app, ascii);
        assert_eq!(app.search_form.memory_mode, MemoryMode::Ascii);
        click(&mut app, egui::pos2(hex.x + 40.0, hex.y + 28.0));
        for ch in "srch".chars() {
            let key = egui::Key::from_name(&ch.to_string()).unwrap();
            let mut events = tap(key, egui::Modifiers::NONE);
            events.insert(1, egui::Event::Text(ch.into()));
            desktop_events(&context, &mut app, events);
        }
        assert_eq!(app.search_form.memory_query, "srch");
        desktop_events(
            &context,
            &mut app,
            tap(egui::Key::Enter, egui::Modifiers::NONE),
        );
        assert!(app.search_dialog.is_none());
        deliver_memory_pages(&mut app, &marked_image(), &context);
        assert_eq!(app.tab, Tab::Search);

        let no_focus = |context: &egui::Context| context.memory(|memory| memory.focused());
        let listing_click_and_keys = |app: &mut DesktopApp| {
            assert_eq!((app.tab, app.selected), (Tab::Listing, Some(0x1000)));
            assert_eq!(no_focus(&context), None);
            assert!(!app.navigation_shortcuts_blocked(&context));
            desktop_events(&context, app, tap(egui::Key::Space, egui::Modifiers::NONE));
            assert_eq!(app.tab, Tab::Graph);
            desktop_events(&context, app, tap(egui::Key::Space, egui::Modifiers::NONE));
            assert_eq!(app.tab, Tab::Listing);
            let output = desktop_frame(&context, app, vec![]);
            let row = text_position(&output, "00001004", 3);
            click(app, row);
            assert_eq!(app.selected, Some(0x1004));
            desktop_events(
                &context,
                app,
                tap(egui::Key::ArrowDown, egui::Modifiers::NONE),
            );
            assert_eq!(app.selected, Some(0x1008));
            app.select_instruction(0x1000);
        };

        // Double-click, then Enter on the selected row, then the context menu.
        let output = desktop_frame(&context, &mut app, vec![]);
        let row = text_position(&output, "00001011", 3);
        let [moved, press, release] = <[egui::Event; 3]>::try_from(pointer_events(row)).unwrap();
        for open in 0..3 {
            app.tab = Tab::Search;
            desktop_frame(&context, &mut app, vec![]);
            match open {
                0 => desktop_events(
                    &context,
                    &mut app,
                    [
                        moved.clone(),
                        press.clone(),
                        release.clone(),
                        press.clone(),
                        release.clone(),
                    ],
                ),
                1 => {
                    assert_eq!(app.searches.table.selected, Some(1));
                    desktop_events(
                        &context,
                        &mut app,
                        tap(egui::Key::Enter, egui::Modifiers::NONE),
                    );
                }
                _ => {
                    desktop_events(&context, &mut app, secondary_events(row));
                    let output = desktop_frame(&context, &mut app, vec![]);
                    // The menu item, not the toolbar's "Open…".
                    let open = output
                        .shapes
                        .iter()
                        .rev()
                        .find_map(|shape| match &shape.shape {
                            egui::epaint::Shape::Text(text) if text.galley.text() == "Open" => {
                                Some(text.pos + text.galley.rect.center().to_vec2())
                            }
                            _ => None,
                        })
                        .expect("context menu Open");
                    click(&mut app, open);
                }
            }
            assert_eq!(
                (app.tab, app.data_location),
                (Tab::Hex, Some((0x1011, 4))),
                "open {open}"
            );
            desktop_events(
                &context,
                &mut app,
                tap(egui::Key::ArrowLeft, egui::Modifiers::ALT),
            );
            listing_click_and_keys(&mut app);
            // Forward returns to the exact span, and Back again restores input.
            desktop_events(
                &context,
                &mut app,
                tap(egui::Key::ArrowRight, egui::Modifiers::ALT),
            );
            assert_eq!((app.tab, app.data_location), (Tab::Hex, Some((0x1011, 4))));
            desktop_events(
                &context,
                &mut app,
                tap(egui::Key::ArrowLeft, egui::Modifiers::ALT),
            );
            listing_click_and_keys(&mut app);
        }
        // Search shortcuts still open their dialogs.
        desktop_events(
            &context,
            &mut app,
            tap(egui::Key::F, egui::Modifiers::COMMAND),
        );
        assert!(app.search_dialog.is_some());
    }

    fn search_frame(
        context: &egui::Context,
        app: &mut DesktopApp,
        width: f32,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let time = context.input(|input| input.time) + 0.05;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 600.0),
                )),
                time: Some(time),
                events,
                ..Default::default()
            },
            |root| {
                egui::Panel::left("search-test")
                    .exact_size(width)
                    .frame(egui::Frame::NONE)
                    .show(root, |ui| app.search_panel(ui));
            },
        );
        output.textures_delta.clear();
        output
    }

    fn texts(output: &egui::FullOutput) -> Vec<(&egui::epaint::TextShape, egui::Rect)> {
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) => Some((text, shape.clip_rect)),
                _ => None,
            })
            .collect()
    }

    fn scrollbars(output: &egui::FullOutput) -> Vec<egui::Rect> {
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Rect(rect)
                    if rect.rect.width().min(rect.rect.height()) < 20.0
                        && rect.rect.width().max(rect.rect.height()) > 60.0 =>
                {
                    Some(rect.rect)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn search_results_fit_narrow_and_wide_panes_at_fractional_scale() {
        use crate::search_text::{TextSearchSpec, TextSources};
        for (memory, rows) in [(true, 3usize), (true, 4000), (false, 4)] {
            for width in [150.0, 230.0, 431.0, 760.0] {
                let context = egui::Context::default();
                theme::install(&context);
                context.set_pixels_per_point(1.25);
                context.all_styles_mut(|style| style.animation_time = 0.0);
                let mut app = if memory { hex_app() } else { text_app() };
                if memory {
                    app.pending = None;
                    let mut image = marked_image();
                    if rows > 4 {
                        image[..rows].fill(b'A');
                    } else {
                        image[4..8].fill(0);
                    }
                    let query = if rows > 4 { "A" } else { "srch" };
                    app.start_memory_search(ascii(query), MemoryMode::Ascii, &context);
                    deliver_memory_pages(&mut app, &image, &context);
                } else {
                    app.start_text_search(TextSearchSpec {
                        query: "srch".into(),
                        match_case: false,
                        sources: TextSources::ALL,
                    });
                    wait_for_text(&mut app, &context);
                }
                assert_eq!(app.searches.current.as_ref().unwrap().count(), rows);
                search_frame(&context, &mut app, width, vec![]);
                let output = search_frame(&context, &mut app, width, vec![]);
                let again = search_frame(&context, &mut app, width, vec![]);
                assert_eq!(
                    scrollbars(&output),
                    scrollbars(&again),
                    "{width}: no scrollbar flicker"
                );
                let shapes = texts(&output);
                let mut headings: Vec<_> = shapes
                    .iter()
                    .filter(|(text, _)| {
                        ["Address", "Section", "Match", "Kind", "Text"]
                            .contains(&text.galley.text())
                    })
                    .map(|(text, _)| text.galley.rect.translate(text.pos.to_vec2()))
                    // The column strip lies below the query/state header.
                    .filter(|rect| rect.top() > theme::ROW_HEIGHT + 4.0)
                    .collect();
                headings.sort_by(|a, b| a.left().total_cmp(&b.left()));
                assert!(headings.len() >= 2, "{width}: {headings:?}");
                for pair in headings.windows(2) {
                    assert!(pair[0].right() + 2.0 < pair[1].left(), "{width}: {pair:?}");
                }
                // Every cell is one clipped line; addresses are monospace and
                // names, kinds, sections and text use the body font.
                let mut proportional = 0;
                for (text, clip) in &shapes {
                    let galley_text = text.galley.text();
                    if galley_text.is_empty() {
                        continue;
                    }
                    assert_eq!(text.galley.rows.len(), 1, "{width}: {galley_text}");
                    assert!(
                        clip.right() <= width + 0.5,
                        "{width}: {galley_text} {clip:?}"
                    );
                    let family = &text.galley.job.sections[0].format.font_id.family;
                    if galley_text.chars().all(|c| c.is_ascii_hexdigit()) && galley_text.len() == 8
                    {
                        assert_eq!(*family, egui::FontFamily::Monospace, "{galley_text}");
                    }
                    if ["String", "Label", ".text", "Name", "Comment"].contains(&galley_text)
                        || galley_text.to_lowercase().contains("srch")
                        || (rows > 4 && galley_text == "A")
                    {
                        assert_eq!(*family, egui::FontFamily::Proportional, "{galley_text}");
                        proportional += 1;
                    }
                }
                assert!(proportional > 0, "{width}");
                // Rows keep the shared fixed pitch and stable hit targets.
                let rows_y: Vec<f32> = shapes
                    .iter()
                    .filter(|(text, _)| {
                        text.galley.text().chars().all(|c| c.is_ascii_hexdigit())
                            && text.galley.text().len() == 8
                    })
                    .map(|(text, _)| text.galley.rect.translate(text.pos.to_vec2()).center().y)
                    .collect();
                assert!(!rows_y.is_empty(), "{width}");
                for pair in rows_y.windows(2) {
                    assert!(
                        ((pair[1] - pair[0]) - theme::ROW_HEIGHT).abs() < 0.5,
                        "{width}: {rows_y:?}"
                    );
                }
                // A single click selects locally; it never navigates.
                if let Some(first) = rows_y.first() {
                    let (tab, selected) = (app.tab, app.selected);
                    let point = egui::pos2(width * 0.5, *first);
                    search_frame(&context, &mut app, width, pointer_events(point));
                    search_frame(&context, &mut app, width, vec![]);
                    assert_eq!(app.searches.table.selected, Some(0), "{width}");
                    assert_eq!((app.tab, app.selected), (tab, selected));
                    let output = search_frame(&context, &mut app, width, vec![]);
                    assert!(selection_fill_at(&output, point), "{width}");
                }
            }
        }
    }
}
