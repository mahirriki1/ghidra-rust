//! In-app file chooser. Listing, metadata, Places and overwrite checks run on
//! one bounded background reader shared by every chooser, so the dialog needs
//! no desktop portal, additional GUI toolkit, or GUI-thread filesystem access.
mod io;
mod places;
mod table;

use self::io::{
    Candidate, EntryKind, Listing, MAX_EDIT_CHARS, MAX_PATH_UNITS, Outcome, Partial, Reply,
    Scheduler, Verdict, Work, display, native_units,
};
use self::places::{Place, Places, Recents};
use self::table::{SortState, TableEvent, TableView, TypeFilter};
use crate::theme;
use eframe::egui::{self, RichText, Stroke, TextEdit};
use std::collections::VecDeque;
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileDialogKind {
    OpenBinary,
    OpenProject,
    LocateProjectBinary,
    SaveProject,
    OpenAnnotations,
    SaveAnnotations,
}

impl FileDialogKind {
    fn is_save(self) -> bool {
        matches!(self, Self::SaveAnnotations | Self::SaveProject)
    }

    fn title(self) -> &'static str {
        match self {
            Self::OpenBinary => "Open binary",
            Self::OpenProject => "Open project (.grproj)",
            Self::LocateProjectBinary => "Locate project binary",
            Self::SaveProject => "Save project (.grproj)",
            Self::OpenAnnotations => "Open annotations",
            Self::SaveAnnotations => "Save annotations",
        }
    }

    fn default_name(self) -> &'static str {
        match self {
            Self::SaveAnnotations => "annotations.json",
            Self::SaveProject => "analysis.grproj",
            _ => "",
        }
    }

    fn default_extension(self) -> Option<&'static str> {
        (self == Self::SaveProject).then_some("grproj")
    }
}

pub struct FileDialogRequest {
    kind: FileDialogKind,
    initial_dir: Option<PathBuf>,
    result: SyncSender<Option<PathBuf>>,
}

/// Call only from a file-task thread: the modal sends back an explicit choice.
/// The working-directory fallback is resolved here, off the GUI thread.
pub fn request_file(
    sender: &Sender<FileDialogRequest>,
    kind: FileDialogKind,
    initial_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    let initial_dir = initial_dir
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| std::env::current_dir().ok());
    let (result, receiver) = mpsc::sync_channel(1);
    sender
        .send(FileDialogRequest {
            kind,
            initial_dir,
            result,
        })
        .ok()?;
    receiver.recv().ok().flatten()
}

/// Owns the modal, the single filesystem reader, Places and the session's
/// recent directories, so a canceled chooser cannot reset any of them.
pub struct FileDialogs {
    requests: Sender<FileDialogRequest>,
    receiver: Receiver<FileDialogRequest>,
    active: Option<(Picker, SyncSender<Option<PathBuf>>)>,
    scheduler: Scheduler,
    places: Places,
    recents: Recents,
    next_dialog: u64,
}

impl Default for FileDialogs {
    fn default() -> Self {
        Self::with_scheduler(Scheduler::native())
    }
}

struct Io<'a> {
    scheduler: &'a mut Scheduler,
    recents: &'a mut Recents,
    places: &'a Places,
}

impl FileDialogs {
    fn with_scheduler(scheduler: Scheduler) -> Self {
        let (requests, receiver) = mpsc::channel();
        Self {
            requests,
            receiver,
            active: None,
            scheduler,
            places: Places::default(),
            recents: Recents::default(),
            next_dialog: 0,
        }
    }

    pub fn sender(&self) -> Sender<FileDialogRequest> {
        self.requests.clone()
    }

    #[cfg(test)]
    pub(crate) fn is_open(&self) -> bool {
        self.active.is_some()
    }

    pub fn show(&mut self, context: &egui::Context) {
        self.open_next();
        let mut choice = self.pump();
        if choice.is_none()
            && let Some((picker, _)) = &mut self.active
        {
            let mut io = Io {
                scheduler: &mut self.scheduler,
                recents: &mut self.recents,
                places: &self.places,
            };
            choice = picker.show(context, &mut io);
        }
        if let Some(choice) = choice {
            self.finish(choice);
            context.request_repaint();
        }
        self.start();
        if self.active.is_some() && !self.scheduler.idle() {
            context.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn open_next(&mut self) {
        if self.active.is_some() {
            return;
        }
        let Ok(request) = self.receiver.try_recv() else {
            return;
        };
        self.next_dialog += 1;
        self.places.restart(self.next_dialog);
        let mut picker = Picker::new(request.kind, self.next_dialog);
        if let Some(directory) = request.initial_dir {
            let mut io = Io {
                scheduler: &mut self.scheduler,
                recents: &mut self.recents,
                places: &self.places,
            };
            picker.navigate(&mut io, directory, Intent::Initial, None);
        }
        self.active = Some((picker, request.result));
        self.start();
    }

    /// Adopt finished work and start the next job. Stale replies only free
    /// the slot.
    fn pump(&mut self) -> Option<Option<PathBuf>> {
        let mut choice = None;
        // Each round frees the slot; a failed spawn yields one reply.
        for _ in 0..4 {
            let Some(reply) = self.scheduler.poll() else {
                break;
            };
            if let Some(path) = self.route(reply) {
                choice = Some(Some(path));
                break;
            }
            self.start();
        }
        choice
    }

    fn route(&mut self, reply: Reply) -> Option<PathBuf> {
        if reply.optional {
            match reply.outcome {
                Outcome::Candidates(places) => self.places.candidates(reply.dialog, places),
                Outcome::Probed(place, directory) => {
                    self.places.probed(reply.dialog, place, directory);
                }
                _ => self.places.lost(reply.dialog),
            }
            return None;
        }
        let (picker, _) = self.active.as_mut()?;
        if picker.dialog != reply.dialog {
            return None;
        }
        let mut io = Io {
            scheduler: &mut self.scheduler,
            recents: &mut self.recents,
            places: &self.places,
        };
        picker.adopt(&mut io, reply)
    }

    fn start(&mut self) {
        let active = self.active.is_some();
        let places = &mut self.places;
        self.scheduler
            .start(|| if active { places.next() } else { None });
    }

    fn finish(&mut self, choice: Option<PathBuf>) {
        let Some((picker, result)) = self.active.take() else {
            return;
        };
        if let Some(path) = &choice
            && let Some(directory) = &picker.committed
            && path.parent() == Some(directory.as_path())
        {
            self.recents.record(directory);
        }
        self.scheduler.cancel();
        let _ = result.send(choice);
    }
}

const MAX_HISTORY: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Intent {
    Initial,
    New,
    Back,
    Forward,
}

/// Directories committed by successful loads only.
#[derive(Default)]
struct History {
    paths: VecDeque<PathBuf>,
    cursor: usize,
}

impl History {
    fn back(&self) -> Option<&PathBuf> {
        self.cursor
            .checked_sub(1)
            .and_then(|index| self.paths.get(index))
    }

    fn forward(&self) -> Option<&PathBuf> {
        self.paths.get(self.cursor + 1)
    }

    fn commit(&mut self, path: &Path, intent: Intent) {
        match intent {
            Intent::Back if self.back().is_some_and(|back| back == path) => self.cursor -= 1,
            Intent::Forward if self.forward().is_some_and(|forward| forward == path) => {
                self.cursor += 1;
            }
            _ => {
                if self
                    .paths
                    .get(self.cursor)
                    .is_some_and(|current| current == path)
                {
                    return;
                }
                self.paths.truncate(self.cursor + 1);
                self.paths.push_back(path.to_owned());
                if self.paths.len() > MAX_HISTORY {
                    self.paths.pop_front();
                }
                self.cursor = self.paths.len() - 1;
            }
        }
    }
}

struct Navigation {
    token: u64,
    target: PathBuf,
    intent: Intent,
    recent: bool,
    /// Text from the path editor, restored for correction on failure.
    typed: Option<String>,
}

#[derive(Default)]
struct Location {
    editing: bool,
    text: String,
    /// The lossy text shown on entry; unchanged text keeps the native path.
    original: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilenameSource {
    Typed,
    /// A listed entry by index within the listing generation.
    Entry(usize, u64),
}

enum Confirmation {
    Idle,
    Inspecting(u64),
    /// The exact path to replace after an explicit decision.
    Replace(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Focus {
    Location,
    Table,
    Filename,
}

/// One breadcrumb: its sanitized label and exact target.
struct Crumb {
    label: String,
    target: PathBuf,
    /// A root segment already ends in a separator.
    root: bool,
}

fn crumbs(path: &Path) -> Vec<Crumb> {
    let mut crumbs = Vec::new();
    let mut target = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(component) = components.next() {
        target.push(component);
        let (label, root) = match component {
            // A Windows prefix and its root form one atomic segment.
            Component::Prefix(_) if components.peek() == Some(&Component::RootDir) => continue,
            Component::Prefix(_) => (display(target.as_os_str()), false),
            Component::RootDir => (display(target.as_os_str()), true),
            other => (display(other.as_os_str()), false),
        };
        crumbs.push(Crumb {
            label,
            target: target.clone(),
            root,
        });
    }
    crumbs
}

/// The lexical parent, ascending through a trailing `.` or `..` instead of
/// stripping it. Links are resolved by the reader, not here.
fn parent_of(path: &Path) -> Option<PathBuf> {
    match path.components().next_back()? {
        Component::CurDir | Component::ParentDir => Some(path.join("..")),
        Component::Normal(_) => path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf),
        Component::RootDir | Component::Prefix(_) => None,
    }
}

/// Reject Windows namespaces other than local drives before any lookup.
#[cfg(windows)]
fn path_policy_error(path: &Path) -> Option<&'static str> {
    use std::path::Prefix;
    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) if path.has_root() => None,
            Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {
                Some("Drive-relative paths are unsupported")
            }
            _ => Some("Only local drive paths are supported"),
        },
        _ => None,
    }
}

#[cfg(not(windows))]
fn path_policy_error(_: &Path) -> Option<&'static str> {
    None
}

struct Picker {
    kind: FileDialogKind,
    dialog: u64,
    committed: Option<PathBuf>,
    crumbs: Vec<Crumb>,
    listing: Option<Listing>,
    generation: u64,
    history: History,
    navigation: Option<Navigation>,
    location: Location,
    filename: String,
    source: FilenameSource,
    filter: String,
    type_filter: TypeFilter,
    sort: SortState,
    visible: Vec<usize>,
    selected: Option<usize>,
    reveal: Option<usize>,
    page: usize,
    focus: Option<Focus>,
    error: Option<String>,
    revision: u64,
    confirmation: Confirmation,
}

const TABLE_ID: &str = "file-chooser-table";
const NAME_ID: &str = "file-chooser-name";
const LOCATION_ID: &str = "file-chooser-location";
const FILTER_ID: &str = "file-chooser-filter";

impl Picker {
    fn new(kind: FileDialogKind, dialog: u64) -> Self {
        Self {
            kind,
            dialog,
            committed: None,
            crumbs: Vec::new(),
            listing: None,
            generation: 0,
            history: History::default(),
            navigation: None,
            location: Location::default(),
            filename: kind.default_name().into(),
            source: FilenameSource::Typed,
            filter: String::new(),
            type_filter: TypeFilter::choices(kind)[0],
            sort: SortState::default(),
            visible: Vec::new(),
            selected: None,
            reveal: None,
            page: 1,
            focus: None,
            error: None,
            revision: 0,
            confirmation: Confirmation::Idle,
        }
    }

    fn awaits(&self, token: u64) -> bool {
        self.navigation
            .as_ref()
            .is_some_and(|navigation| navigation.token == token)
            || matches!(self.confirmation, Confirmation::Inspecting(awaited) if awaited == token)
    }

    fn busy(&self) -> bool {
        self.navigation.is_some() || matches!(self.confirmation, Confirmation::Inspecting(_))
    }

    fn entry(&self, index: usize) -> Option<&io::Entry> {
        self.listing.as_ref()?.entries.get(index)
    }

    /// Any change to the name, folder, type or selection invalidates a
    /// pending inspection or replacement prompt.
    fn touch(&mut self) {
        self.revision += 1;
        self.confirmation = Confirmation::Idle;
    }

    /// Drop the row selection. An open name taken from a row is cleared; a
    /// save name survives only when its label is the exact native name.
    fn clear_selection(&mut self) {
        self.selected = None;
        self.reveal = None;
        if let FilenameSource::Entry(index, generation) = self.source {
            self.touch();
            let exact = generation == self.generation
                && self
                    .entry(index)
                    .is_some_and(|entry| entry.name.to_str() == Some(entry.label.as_str()));
            if !(self.kind.is_save() && exact) {
                self.filename.clear();
            }
            self.source = FilenameSource::Typed;
        }
    }

    fn navigate(&mut self, io: &mut Io, target: PathBuf, intent: Intent, typed: Option<String>) {
        self.navigate_from(io, target, intent, false, typed);
    }

    fn navigate_from(
        &mut self,
        io: &mut Io,
        target: PathBuf,
        intent: Intent,
        recent: bool,
        typed: Option<String>,
    ) {
        if let Some(error) = path_policy_error(&target) {
            self.error = Some(error.into());
            return;
        }
        if native_units(target.as_os_str()) > MAX_PATH_UNITS {
            self.error = Some("Path too long".into());
            return;
        }
        self.touch();
        self.clear_selection();
        self.error = None;
        let token = io.scheduler.demand(self.dialog, Work::Read(target.clone()));
        self.navigation = Some(Navigation {
            token,
            target,
            intent,
            recent,
            typed,
        });
    }

    fn go_back(&mut self, io: &mut Io) {
        if let Some(target) = self.history.back().cloned() {
            self.navigate(io, target, Intent::Back, None);
        }
    }

    fn go_forward(&mut self, io: &mut Io) {
        if let Some(target) = self.history.forward().cloned() {
            self.navigate(io, target, Intent::Forward, None);
        }
    }

    fn go_up(&mut self, io: &mut Io) {
        if let Some(target) = self.committed.as_deref().and_then(parent_of) {
            self.navigate(io, target, Intent::New, None);
        }
    }

    fn edit_location(&mut self) {
        let text = self
            .committed
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.location = Location {
            editing: true,
            original: text.clone(),
            text,
        };
        self.focus = Some(Focus::Location);
    }

    /// Unchanged editor text keeps the committed native path even when its
    /// lossy rendering differs. Relative text resolves against the folder.
    fn submit_location(&mut self, io: &mut Io) {
        let text = self.location.text.clone();
        if text.is_empty() {
            return;
        }
        let target = match &self.committed {
            Some(committed) if text == self.location.original => committed.clone(),
            Some(committed) => committed.join(&text),
            None => PathBuf::from(&text),
        };
        self.navigate(io, target, Intent::New, Some(text));
    }

    fn adopt(&mut self, io: &mut Io, reply: Reply) -> Option<PathBuf> {
        match reply.outcome {
            Outcome::Listing(result) => {
                let navigation = self
                    .navigation
                    .take_if(|navigation| navigation.token == reply.token)?;
                match result {
                    Ok(listing) if listing.directory == navigation.target => {
                        self.commit(io, navigation, listing);
                    }
                    Ok(_) => self.fail(io, navigation, "Unexpected listing".into()),
                    Err(error) => self.fail(io, navigation, error),
                }
                None
            }
            Outcome::Inspected(verdict) => {
                if !matches!(self.confirmation, Confirmation::Inspecting(token) if token == reply.token)
                {
                    return None;
                }
                self.confirmation = Confirmation::Idle;
                match verdict {
                    Verdict::Directory(path) => {
                        if self.source == FilenameSource::Typed {
                            self.filename = self.kind.default_name().into();
                        }
                        self.navigate(io, path, Intent::New, None);
                        None
                    }
                    Verdict::Existing(path) if self.kind.is_save() => {
                        self.confirmation = Confirmation::Replace(path);
                        None
                    }
                    Verdict::Existing(path) => Some(path),
                    Verdict::Missing(path) if self.kind.is_save() => Some(path),
                    Verdict::Missing(_) => {
                        self.error = Some("Not found".into());
                        None
                    }
                    Verdict::Failed(error) => {
                        self.error = Some(error);
                        None
                    }
                }
            }
            Outcome::Lost(error) => {
                if let Some(navigation) = self
                    .navigation
                    .take_if(|navigation| navigation.token == reply.token)
                {
                    self.fail(io, navigation, error);
                } else if self.awaits(reply.token) {
                    self.confirmation = Confirmation::Idle;
                    self.error = Some(error);
                }
                None
            }
            Outcome::Canceled | Outcome::Candidates(_) | Outcome::Probed(..) => None,
        }
    }

    fn commit(&mut self, io: &mut Io, navigation: Navigation, listing: Listing) {
        self.history.commit(&navigation.target, navigation.intent);
        if navigation.intent != Intent::Initial {
            io.recents.record(&navigation.target);
        }
        self.crumbs = crumbs(&navigation.target);
        self.committed = Some(navigation.target);
        self.listing = Some(listing);
        self.generation += 1;
        self.selected = None;
        self.reveal = None;
        self.location.editing = false;
        self.rebuild_visible();
    }

    /// The committed folder, listing and history stay usable.
    fn fail(&mut self, io: &mut Io, navigation: Navigation, error: String) {
        self.error = Some(error);
        if navigation.recent {
            io.recents.remove(&navigation.target);
        }
        if let Some(text) = navigation.typed {
            self.location.editing = true;
            self.location.text = text;
            self.focus = Some(Focus::Location);
        }
    }

    /// Re-sort and filter. The selection survives only while still visible;
    /// no other row is chosen in its place.
    fn rebuild_visible(&mut self) {
        self.visible = match &self.listing {
            Some(listing) => {
                table::visible(&listing.entries, &self.filter, self.type_filter, self.sort)
            }
            None => Vec::new(),
        };
        match self.selected {
            Some(selected) => match self.visible.iter().position(|&index| index == selected) {
                Some(row) => self.reveal = Some(row),
                None => self.clear_selection(),
            },
            None => self.reveal = None,
        }
    }

    fn select(&mut self, index: usize) {
        let Some(entry) = self.entry(index) else {
            return;
        };
        let directory = entry.kind == EntryKind::Directory;
        let label = entry.label.clone();
        if directory {
            self.touch();
            self.clear_selection();
        } else {
            self.filename = label;
            self.source = FilenameSource::Entry(index, self.generation);
            self.touch();
        }
        self.selected = Some(index);
    }

    fn select_row(&mut self, row: usize) {
        if let Some(&index) = self.visible.get(row) {
            self.select(index);
            self.reveal = Some(row);
        }
    }

    fn activate(&mut self, io: &mut Io, index: usize) -> Option<PathBuf> {
        let entry = self.entry(index)?;
        match entry.kind {
            EntryKind::Directory => {
                let path = entry.path.clone();
                self.navigate(io, path, Intent::New, None);
                None
            }
            EntryKind::File if !self.kind.is_save() => Some(entry.path.clone()),
            _ => {
                self.select(index);
                self.submit(io)
            }
        }
    }

    fn can_submit(&self) -> bool {
        match self.source {
            FilenameSource::Entry(_, generation) => generation == self.generation,
            FilenameSource::Typed => !self.filename.trim().is_empty(),
        }
    }

    /// Resolve the exact candidate and inspect it off-thread. A listed file
    /// opens directly; a save always classifies the target first.
    fn submit(&mut self, io: &mut Io) -> Option<PathBuf> {
        if matches!(self.confirmation, Confirmation::Replace(_)) || !self.can_submit() {
            return None;
        }
        let (path, kind) = match self.source {
            FilenameSource::Entry(index, _) => {
                let entry = self.entry(index)?;
                (entry.path.clone(), Some(entry.kind))
            }
            FilenameSource::Typed => {
                let typed = PathBuf::from(&self.filename);
                let path = match &self.committed {
                    Some(directory) => directory.join(typed),
                    None if typed.is_absolute() => typed,
                    None => {
                        self.error = Some("No folder".into());
                        return None;
                    }
                };
                (path, None)
            }
        };
        if let Some(error) = path_policy_error(&path) {
            self.error = Some(error.into());
            return None;
        }
        if native_units(path.as_os_str()) > MAX_PATH_UNITS {
            self.error = Some("Path too long".into());
            return None;
        }
        if !self.kind.is_save() {
            // A listed file, or a repeated Open while the reader is stalled,
            // goes to the caller's own validation.
            let stalled =
                matches!(self.confirmation, Confirmation::Inspecting(_)) && io.scheduler.running();
            if kind == Some(EntryKind::File) || stalled {
                return Some(path);
            }
        } else if matches!(self.confirmation, Confirmation::Inspecting(_)) {
            return None;
        }
        // An inspection supersedes a pending navigation; the current folder
        // stays committed.
        self.navigation = None;
        self.error = None;
        let token = io.scheduler.demand(
            self.dialog,
            Work::Inspect(Candidate {
                path,
                extension: self.kind.default_extension(),
            }),
        );
        self.confirmation = Confirmation::Inspecting(token);
        None
    }

    /// Chooser keys run before the widgets draw. Table keys need the table's
    /// focus from the previous frame; text editors keep their own keys.
    fn handle_keys(&mut self, context: &egui::Context, io: &mut Io) -> Option<PathBuf> {
        if matches!(self.confirmation, Confirmation::Replace(_)) {
            return None;
        }
        let table = egui::Id::unique(TABLE_ID);
        if self.location.editing
            && context
                .input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.location.editing = false;
        }
        if context.input_mut(|input| input.consume_key(egui::Modifiers::COMMAND, egui::Key::L)) {
            self.edit_location();
        }
        // Text editors keep Alt+arrow word movement.
        let editing = context.memory(|memory| {
            [LOCATION_ID, NAME_ID, FILTER_ID]
                .iter()
                .any(|id| memory.has_focus(egui::Id::unique(id)))
        });
        if !editing {
            if context
                .input_mut(|input| input.consume_key(egui::Modifiers::ALT, egui::Key::ArrowLeft))
            {
                self.go_back(io);
            }
            if context
                .input_mut(|input| input.consume_key(egui::Modifiers::ALT, egui::Key::ArrowRight))
            {
                self.go_forward(io);
            }
        }
        if !context.memory(|memory| memory.has_focus(table)) {
            return None;
        }
        context.memory_mut(|memory| {
            memory.set_focus_lock_filter(
                table,
                egui::EventFilter {
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    ..Default::default()
                },
            );
        });
        let keys = context.input_mut(|input| {
            let mut keys = Vec::new();
            input.events.retain(|event| match event {
                egui::Event::Key {
                    key,
                    pressed: true,
                    repeat,
                    modifiers,
                    ..
                } if modifiers.is_none()
                    && matches!(
                        key,
                        egui::Key::ArrowUp
                            | egui::Key::ArrowDown
                            | egui::Key::Home
                            | egui::Key::End
                            | egui::Key::PageUp
                            | egui::Key::PageDown
                            | egui::Key::Enter
                            | egui::Key::Backspace
                    ) =>
                {
                    keys.push((*key, *repeat));
                    false
                }
                _ => true,
            });
            keys
        });
        for (key, repeat) in keys {
            // Going up must also work in an empty directory or with no matches.
            if key == egui::Key::Backspace && !repeat {
                self.go_up(io);
                continue;
            }
            let Some(last) = self.visible.len().checked_sub(1) else {
                continue;
            };
            let row = self
                .selected
                .and_then(|selected| self.visible.iter().position(|&index| index == selected));
            match key {
                egui::Key::ArrowUp => self.select_row(row.map_or(0, |row| row.saturating_sub(1))),
                egui::Key::ArrowDown => self.select_row(row.map_or(0, |row| (row + 1).min(last))),
                egui::Key::Home => self.select_row(0),
                egui::Key::End => self.select_row(last),
                egui::Key::PageUp => {
                    self.select_row(row.map_or(0, |row| row.saturating_sub(self.page)));
                }
                egui::Key::PageDown => {
                    self.select_row(row.map_or(0, |row| (row + self.page).min(last)));
                }
                egui::Key::Enter if !repeat => {
                    if let Some(selected) = self.selected {
                        return self.activate(io, selected);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn show(&mut self, context: &egui::Context, io: &mut Io) -> Option<Option<PathBuf>> {
        if let Some(path) = self.handle_keys(context, io) {
            return Some(Some(path));
        }
        let mut choice = None;
        let size = modal_size(context);
        let frame = egui::Frame::popup(&context.global_style()).inner_margin(12.0);
        let modal = egui::Modal::new(egui::Id::unique("file-chooser"))
            .frame(frame)
            .show(context, |ui| {
                let layout = Layout::new(size.x);
                if size.y < layout.min_height() {
                    ui.set_width(size.x);
                    egui::ScrollArea::vertical()
                        .id_salt("file-chooser-compact")
                        .max_height(size.y)
                        .show(ui, |ui| {
                            let size = egui::vec2(ui.available_width(), layout.min_height());
                            choice = self.draw(ui, io, size, &layout);
                        });
                } else {
                    choice = self.draw(ui, io, size, &layout);
                }
                resize_grip(ui, size);
            });
        if matches!(self.confirmation, Confirmation::Replace(_)) {
            choice = choice.or(self.draw_replace(context));
        } else if modal.should_close() {
            choice = Some(None);
        }
        choice
    }

    fn draw(
        &mut self,
        ui: &mut egui::Ui,
        io: &mut Io,
        size: egui::Vec2,
        layout: &Layout,
    ) -> Option<Option<PathBuf>> {
        let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
        let mut rows = Rows::new(rect);
        let title = rows.take(TITLE);
        let mut title_ui = ui.new_child(egui::UiBuilder::new().max_rect(title));
        let heading = title_ui.label(RichText::new(self.kind.title()).strong());
        if self.kind == FileDialogKind::LocateProjectBinary {
            heading.on_hover_text("SHA-256 must match the project.");
        }
        let header = rows.take(CONTROL);
        self.draw_header(ui, io, header, layout);
        if layout.filter.is_none() {
            let filter = rows.take(CONTROL);
            self.draw_filter(ui, filter);
        }
        let footer_rows = if layout.tiny { 3 } else { 2 };
        let footer = rows.take_bottom(footer_rows);
        let body = rows.rest();
        let mut table_rect = body;
        if let Some(width) = layout.sidebar {
            let (sidebar, rest) = split_left(body, width, GAP);
            self.draw_places(ui, io, sidebar);
            table_rect = rest;
        }
        let output = self.draw_table(ui, io, table_rect, layout);
        let choice = self.draw_footer(ui, io, footer, layout);
        output.map(Some).or(choice)
    }

    fn draw_header(&mut self, ui: &mut egui::Ui, io: &mut Io, rect: egui::Rect, layout: &Layout) {
        let mut child = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(rect)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let ui = &mut child;
        ui.spacing_mut().item_spacing.x = 3.0;
        if theme::history_button(ui, false, self.history.back().is_some()).clicked() {
            self.go_back(io);
        }
        if theme::history_button(ui, true, self.history.forward().is_some()).clicked() {
            self.go_forward(io);
        }
        let up_target = self.committed.as_deref().and_then(parent_of);
        if up_button(ui, up_target.is_some()).clicked() {
            self.go_up(io);
        }
        ui.add_space(8.0 - 3.0);
        if layout.sidebar.is_none() {
            self.places_menu(ui, io);
        }
        let partial = self
            .listing
            .as_ref()
            .and_then(|listing| listing.partial)
            .filter(|_| self.navigation.is_none());
        // Fixed geometry right of the buttons, so the chip and filter never
        // depend on the breadcrumb width.
        let start = ui.cursor().min.x;
        let filter = layout.filter.map(|width| {
            egui::Rect::from_min_max(
                egui::pos2(rect.right() - width, rect.top()),
                rect.right_bottom(),
            )
        });
        let end = filter.map_or(rect.right(), |filter| filter.left() - 8.0);
        let chip = partial.map(|_| {
            egui::Rect::from_min_max(
                egui::pos2((end - 52.0).max(start), rect.top()),
                egui::pos2(end, rect.bottom()),
            )
        });
        let path_end = chip.map_or(end, |chip| chip.left() - 4.0).max(start);
        let path = egui::Rect::from_min_max(
            egui::pos2(start, rect.top()),
            egui::pos2(path_end, rect.bottom()),
        );
        self.draw_path(ui, io, path);
        if let (Some(partial), Some(chip)) = (partial, chip) {
            let tip = match partial {
                Partial::Truncated => "4,096-entry limit; enter a path directly.",
                Partial::Budget => "Listing size limit; enter a path directly.",
                Partial::Failed => "Some entries could not be read.",
            };
            ui.put(
                chip,
                egui::Label::new(RichText::new("Partial").color(theme::WARNING)).truncate(),
            )
            .on_hover_text(tip);
        }
        if let Some(filter) = filter {
            self.draw_filter(ui, filter);
        }
    }

    fn draw_filter(&mut self, ui: &mut egui::Ui, rect: egui::Rect) {
        let response = ui.put(
            rect,
            TextEdit::singleline(&mut self.filter)
                .id(egui::Id::unique(FILTER_ID))
                .desired_width(f32::INFINITY)
                .hint_text("Filter")
                .char_limit(256),
        );
        if response.changed() {
            self.rebuild_visible();
        }
        let response = if !self.filter.is_empty() && self.visible.is_empty() {
            response.on_hover_text("No matches")
        } else {
            response
        };
        if response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
            self.focus = Some(Focus::Table);
            if self.selected.is_none() {
                self.select_row(0);
            }
        }
    }

    fn draw_path(&mut self, ui: &mut egui::Ui, io: &mut Io, rect: egui::Rect) {
        let status = egui::Rect::from_min_max(
            egui::pos2(rect.right() - CONTROL, rect.top()),
            rect.right_bottom(),
        );
        if self.location.editing {
            let response = ui.put(
                rect,
                TextEdit::singleline(&mut self.location.text)
                    .id(egui::Id::unique(LOCATION_ID))
                    .desired_width(f32::INFINITY)
                    .char_limit(MAX_EDIT_CHARS)
                    .margin(egui::Margin {
                        right: CONTROL as i8,
                        ..egui::Margin::symmetric(4, 2)
                    }),
            );
            if self.focus == Some(Focus::Location) {
                response.request_focus();
                let mut state =
                    egui::text_edit::TextEditState::load(ui.ctx(), response.id).unwrap_or_default();
                state
                    .cursor
                    .set_char_range(Some(egui::text::CCursorRange::select_all_str(
                        &self.location.text,
                    )));
                state.store(ui.ctx(), response.id);
                self.focus = None;
            }
            if response.lost_focus() {
                if ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                    self.submit_location(io);
                } else if self.navigation.is_none() {
                    self.location.editing = false;
                }
            }
        } else {
            self.draw_crumbs(ui, io, rect.with_max_x(status.left()), rect);
        }
        if let Some(error) = &self.error {
            ui.painter().rect_stroke(
                rect,
                3,
                Stroke::new(1.0, theme::ERROR),
                egui::StrokeKind::Inside,
            );
            error_icon(ui, status, error);
        } else if self.busy() {
            ui.put(status.shrink(3.0), egui::Spinner::new());
        }
    }

    fn draw_crumbs(&mut self, ui: &mut egui::Ui, io: &mut Io, rect: egui::Rect, frame: egui::Rect) {
        const SEPARATOR: f32 = 10.0;
        const ELLIPSIS: f32 = 20.0;
        let id = ui.scope_id().with("file-chooser-path");
        let background = ui.interact(frame, id, egui::Sense::click());
        background.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, "Edit path"));
        ui.painter()
            .rect_filled(frame, 3, ui.visuals().extreme_bg_color);
        if background.has_focus() {
            ui.painter().rect_stroke(
                frame,
                3,
                Stroke::new(1.0, theme::ACCENT),
                egui::StrokeKind::Inside,
            );
        }
        let background = background.on_hover_text("Edit path (Ctrl+L)");
        let font = egui::TextStyle::Body.resolve(ui.style());
        let width = |ui: &egui::Ui, label: &str| {
            ui.fonts_mut(|fonts| {
                fonts
                    .layout_no_wrap(label.to_owned(), font.clone(), theme::TEXT)
                    .size()
                    .x
            }) + 8.0
        };
        let count = self.crumbs.len();
        let rooted = self.crumbs.first().is_some_and(|crumb| crumb.root);
        let separator = |index: usize| {
            if index == 1 && rooted { 0.0 } else { SEPARATOR }
        };
        // Keep the first segment and as many trailing segments as fit,
        // measuring only those; collapse the middle behind an ellipsis.
        let available = rect.width() - 4.0;
        let mut shown = Vec::new();
        let mut used = self
            .crumbs
            .first()
            .map_or(0.0, |crumb| width(ui, &crumb.label));
        for index in (1..count).rev() {
            let next = width(ui, &self.crumbs[index].label) + separator(index);
            let reserve = if index > 1 {
                ELLIPSIS + separator(1)
            } else {
                0.0
            };
            if !shown.is_empty() && used + next + reserve > available {
                break;
            }
            used += next;
            shown.push((index, next - separator(index)));
        }
        shown.reverse();
        let hidden = 1..shown.first().map_or(count, |(index, _)| *index).max(1);
        let clip = rect.intersect(ui.clip_rect());
        let painter = ui.painter().with_clip_rect(clip);
        let hover_fill = ui.visuals().widgets.hovered.weak_bg_fill;
        let chevron = |x: &mut f32, gap: f32| {
            if gap > 0.0 {
                let center = egui::pos2(*x + gap / 2.0, rect.center().y);
                let stroke = Stroke::new(1.0, theme::MUTED);
                painter.line_segment(
                    [
                        center + egui::vec2(-1.5, -3.5),
                        center + egui::vec2(1.5, 0.0),
                    ],
                    stroke,
                );
                painter.line_segment(
                    [
                        center + egui::vec2(1.5, 0.0),
                        center + egui::vec2(-1.5, 3.5),
                    ],
                    stroke,
                );
            }
            *x += gap;
        };
        let cell_at = |x: f32, w: f32| {
            egui::Rect::from_min_size(
                egui::pos2(x, rect.top() + 2.0),
                egui::vec2(w.min(rect.right() - x).max(0.0), rect.height() - 4.0),
            )
        };
        let mut target = None;
        let mut crumb = |ui: &mut egui::Ui, x: &mut f32, index: usize, w: f32| {
            let label = &self.crumbs[index].label;
            let cell = cell_at(*x, w);
            let response = ui.interact(cell.intersect(clip), id.with(index), egui::Sense::click());
            response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, label));
            if response.hovered() || response.has_focus() {
                painter.rect_filled(cell, 2, hover_fill);
            }
            painter.with_clip_rect(cell.intersect(clip)).text(
                egui::pos2(cell.left() + 4.0, cell.center().y),
                egui::Align2::LEFT_CENTER,
                label,
                font.clone(),
                if index + 1 == count {
                    theme::TEXT
                } else {
                    theme::MUTED
                },
            );
            *x += w;
            if response.clicked() {
                target = Some(index);
            }
        };
        let mut x = rect.left() + 2.0;
        if count > 0 {
            let w = width(ui, &self.crumbs[0].label);
            crumb(ui, &mut x, 0, w);
        }
        let mut hidden_choice = None;
        if !hidden.is_empty() {
            chevron(&mut x, separator(1));
            let cell = cell_at(x, ELLIPSIS);
            let response = ui.interact(cell, id.with("hidden"), egui::Sense::click());
            response.widget_info(|| {
                egui::WidgetInfo::labeled(egui::Role::Button, true, "Parent folders")
            });
            if response.hovered() || response.has_focus() {
                painter.rect_filled(cell, 2, hover_fill);
            }
            for offset in [-4.0, 0.0, 4.0] {
                painter.circle_filled(cell.center() + egui::vec2(offset, 0.0), 1.2, theme::MUTED);
            }
            x += ELLIPSIS;
            let crumbs = &self.crumbs;
            egui::Popup::menu(&response).show(|ui| {
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for index in hidden.clone().rev() {
                            if ui.button(&crumbs[index].label).clicked() {
                                hidden_choice = Some(index);
                            }
                        }
                    });
            });
        }
        for (index, w) in shown {
            chevron(
                &mut x,
                if hidden.is_empty() {
                    separator(index)
                } else {
                    SEPARATOR
                },
            );
            crumb(ui, &mut x, index, w);
        }
        if let Some(index) = target.or(hidden_choice) {
            let path = self.crumbs[index].target.clone();
            self.navigate(io, path, Intent::New, None);
        } else if background.clicked() {
            self.edit_location();
        }
    }

    fn place_items<'a>(&self, places: &'a Places, recents: &'a Recents) -> Vec<SideItem<'a>> {
        let mut items = vec![SideItem::Heading("Places")];
        items.extend(places.shown().iter().map(SideItem::Place));
        #[cfg(not(windows))]
        items.push(SideItem::Root);
        if recents.paths().len() > 0 {
            items.push(SideItem::Heading("Recent"));
            items.extend(recents.paths().map(SideItem::Recent));
        }
        items
    }

    fn draw_places(&mut self, ui: &mut egui::Ui, io: &mut Io, rect: egui::Rect) {
        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
        child.painter().rect_filled(rect, 0, theme::CHROME);
        let items = self.place_items(io.places, io.recents);
        let committed = self.committed.as_deref();
        let (target, _) = theme::rows(
            &mut child,
            "file-chooser-places",
            items.len(),
            theme::ROW_HEIGHT,
            0.0,
            None,
            |ui, row, rect| {
                let item = &items[row];
                let Some((label, path)) = item.target() else {
                    if let SideItem::Heading(title) = item {
                        ui.painter().text(
                            egui::pos2(rect.left() + 6.0, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            *title,
                            egui::FontId::proportional(11.0),
                            theme::MUTED,
                        );
                    }
                    return None;
                };
                let selected = committed == Some(path);
                let response = theme::row_response(
                    ui,
                    egui::Id::unique(("file-chooser-place", row)),
                    rect,
                    selected,
                    false,
                );
                response
                    .widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, &label));
                theme::cell_text(
                    ui,
                    rect,
                    RichText::new(&label).text_style(egui::TextStyle::Body),
                    theme::TEXT,
                );
                let clicked = response.clicked();
                if matches!(item, SideItem::Recent(_)) {
                    response.on_hover_ui(|ui| {
                        ui.label(display(path.as_os_str()));
                    });
                }
                clicked.then(|| (path.to_path_buf(), matches!(item, SideItem::Recent(_))))
            },
        );
        if let Some((path, recent)) = target {
            self.navigate_from(io, path.to_path_buf(), Intent::New, recent, None);
        }
    }

    fn places_menu(&mut self, ui: &mut egui::Ui, io: &mut Io) {
        let response = ui
            .add(
                egui::Button::new("")
                    .min_size(egui::vec2(26.0, 22.0))
                    .frame_when_inactive(false),
            )
            .on_hover_text("Places");
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, "Places"));
        let center = response.rect.center();
        for offset in [-4.0, 0.0, 4.0] {
            ui.painter().line_segment(
                [
                    center + egui::vec2(-6.0, offset),
                    center + egui::vec2(6.0, offset),
                ],
                Stroke::new(1.5, theme::MUTED),
            );
        }
        let mut target = None;
        egui::Popup::menu(&response).show(|ui| {
            egui::ScrollArea::vertical()
                .max_height(320.0)
                .show(ui, |ui| {
                    for item in self.place_items(io.places, io.recents) {
                        match item.target() {
                            Some((label, path)) => {
                                if ui.button(label).clicked() {
                                    target = Some((
                                        path.to_path_buf(),
                                        matches!(item, SideItem::Recent(_)),
                                    ));
                                }
                            }
                            None => {
                                if let SideItem::Heading(title) = item {
                                    ui.weak(title);
                                }
                            }
                        }
                    }
                });
        });
        if let Some((path, recent)) = target {
            self.navigate_from(io, path.to_path_buf(), Intent::New, recent, None);
        }
    }

    fn draw_table(
        &mut self,
        ui: &mut egui::Ui,
        io: &mut Io,
        rect: egui::Rect,
        layout: &Layout,
    ) -> Option<PathBuf> {
        let mut child = ui.new_child(egui::UiBuilder::new().max_rect(rect));
        let ui = &mut child;
        ui.painter().rect_filled(rect, 0, theme::VIEW);
        let gutter = ui.spacing().scroll.allocated_width();
        let columns = table::columns(rect.width(), gutter, layout.outer);
        let table_id = egui::Id::unique(TABLE_ID);
        if self.focus == Some(Focus::Table) {
            ui.memory_mut(|memory| memory.request_focus(table_id));
            self.focus = None;
        }
        let empty = Vec::new();
        let output = table::draw(
            ui,
            TableView {
                entries: self
                    .listing
                    .as_ref()
                    .map_or(&empty, |listing| &listing.entries),
                visible: &self.visible,
                selected: self.selected,
                reveal: self.reveal.take(),
                sort: self.sort,
                generation: self.generation,
                columns,
                focus: table_id,
                next_focus: egui::Id::unique(NAME_ID),
            },
        );
        self.page = output.page;
        if let Some(column) = output.sort {
            self.sort.click(column);
            self.rebuild_visible();
        }
        match output.event {
            Some(TableEvent::Select(index)) => {
                self.select(index);
                None
            }
            Some(TableEvent::Activate(index)) => self.activate(io, index),
            None => None,
        }
    }

    fn draw_footer(
        &mut self,
        ui: &mut egui::Ui,
        io: &mut Io,
        rect: egui::Rect,
        layout: &Layout,
    ) -> Option<Option<PathBuf>> {
        let mut rows = Rows::new(rect);
        let name_row = rows.take(CONTROL);
        let mut name_ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(name_row)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let label = name_ui.label("Name");
        let name = name_ui.add_sized(
            egui::vec2(name_ui.available_width(), CONTROL),
            TextEdit::singleline(&mut self.filename)
                .id(egui::Id::unique(NAME_ID))
                .char_limit(MAX_EDIT_CHARS),
        );
        let name = name.labelled_by(label.id);
        if name.changed() {
            self.source = FilenameSource::Typed;
            self.touch();
        }
        if self.focus == Some(Focus::Filename) {
            name.request_focus();
            self.focus = None;
        }
        let mut choice = None;
        if name.lost_focus() && name_ui.input(|input| input.key_pressed(egui::Key::Enter)) {
            choice = self.submit(io).map(Some);
        }
        let (type_row, actions_row) = if layout.tiny {
            (rows.take(CONTROL), rows.take(CONTROL))
        } else {
            let row = rows.take(CONTROL);
            (row, row)
        };
        let mut type_ui = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(type_row)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        let choices = TypeFilter::choices(self.kind);
        let type_width = if layout.tiny {
            type_row.width()
        } else {
            (type_row.width() - ACTIONS).clamp(0.0, 200.0)
        };
        let mut type_filter = self.type_filter;
        egui::ComboBox::from_id_salt("file-chooser-type")
            .selected_text(type_filter.label())
            .width(type_width)
            .truncate()
            .show_ui(&mut type_ui, |ui| {
                for choice in choices {
                    ui.selectable_value(&mut type_filter, *choice, choice.label());
                }
            })
            .response
            .on_hover_text("File type");
        if type_filter != self.type_filter {
            self.type_filter = type_filter;
            self.touch();
            self.rebuild_visible();
        }
        let mut actions = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(actions_row)
                .layout(egui::Layout::right_to_left(egui::Align::Center)),
        );
        if actions
            .add_sized(egui::vec2(64.0, CONTROL), egui::Button::new("Cancel"))
            .clicked()
        {
            choice = Some(None);
        }
        let verb = if self.kind.is_save() { "Save" } else { "Open" };
        let waiting = matches!(self.confirmation, Confirmation::Inspecting(_));
        let enabled = self.can_submit() && !(waiting && self.kind.is_save());
        let action = actions.add_enabled_ui(enabled, |ui| {
            ui.add_sized(egui::vec2(64.0, CONTROL), egui::Button::new(verb))
        });
        if waiting {
            actions.add(egui::Spinner::new());
        }
        if action.inner.clicked() && choice.is_none() {
            choice = self.submit(io).map(Some);
        }
        choice
    }

    fn draw_replace(&mut self, context: &egui::Context) -> Option<Option<PathBuf>> {
        let Confirmation::Replace(path) = &self.confirmation else {
            return None;
        };
        let path = path.clone();
        let mut replace = None;
        let modal =
            egui::Modal::new(egui::Id::unique("file-chooser-replace")).show(context, |ui| {
                ui.set_max_width(
                    360.0_f32
                        .min(context.content_rect().width() - 48.0)
                        .max(0.0),
                );
                ui.label(RichText::new("Replace existing file?").strong());
                let name = path
                    .file_name()
                    .map_or_else(|| display(path.as_os_str()), display);
                ui.add(egui::Label::new(name).truncate())
                    .on_hover_text(display(path.as_os_str()));
                ui.horizontal(|ui| {
                    if ui.button("Replace").clicked() {
                        replace = Some(true);
                    }
                    if ui.button("Keep existing").clicked() {
                        replace = Some(false);
                    }
                });
            });
        if replace.is_none() && modal.should_close() {
            replace = Some(false);
        }
        match replace {
            Some(true) => Some(Some(path)),
            Some(false) => {
                self.confirmation = Confirmation::Idle;
                None
            }
            None => None,
        }
    }
}

enum SideItem<'a> {
    Heading(&'static str),
    Place(&'a Place),
    #[cfg_attr(windows, allow(dead_code))]
    Root,
    Recent(&'a PathBuf),
}

impl SideItem<'_> {
    fn target(&self) -> Option<(String, &Path)> {
        match self {
            Self::Heading(_) => None,
            Self::Place(place) => Some((place.label.clone(), &place.path)),
            Self::Root => Some(("/".into(), Path::new("/"))),
            Self::Recent(path) => Some((
                path.file_name()
                    .map_or_else(|| display(path.as_os_str()), display),
                path.as_path(),
            )),
        }
    }
}

const TITLE: f32 = 20.0;
const CONTROL: f32 = 22.0;
const GAP: f32 = 6.0;
const ACTIONS: f32 = 64.0 * 2.0 + 30.0;

/// Width-dependent chooser layout in logical points.
struct Layout {
    outer: f32,
    sidebar: Option<f32>,
    filter: Option<f32>,
    tiny: bool,
}

impl Layout {
    /// `inner` excludes the 12-point frame margins.
    fn new(inner: f32) -> Self {
        let outer = inner + 24.0;
        let (sidebar, filter) = if outer >= 760.0 {
            (Some(152.0), Some(176.0))
        } else if outer >= 600.0 {
            (Some(120.0), Some(120.0))
        } else {
            (None, None)
        };
        Self {
            outer,
            sidebar,
            filter,
            tiny: outer < 420.0,
        }
    }

    fn min_height(&self) -> f32 {
        let controls =
            3.0 + f32::from(u8::from(self.filter.is_none())) + f32::from(u8::from(self.tiny));
        TITLE + controls * (CONTROL + GAP) + GAP + theme::ROW_HEIGHT * 3.0
    }
}

/// Top-down rows of a fixed rectangle.
struct Rows {
    rect: egui::Rect,
}

impl Rows {
    fn new(rect: egui::Rect) -> Self {
        Self { rect }
    }

    fn take(&mut self, height: f32) -> egui::Rect {
        let height = height.min(self.rect.height());
        let row = egui::Rect::from_min_size(self.rect.min, egui::vec2(self.rect.width(), height));
        self.rect.min.y = (self.rect.min.y + height + GAP).min(self.rect.max.y);
        row
    }

    fn take_bottom(&mut self, count: usize) -> egui::Rect {
        let height = (count as f32 * (CONTROL + GAP) - GAP).min(self.rect.height());
        let rect = egui::Rect::from_min_max(
            egui::pos2(self.rect.left(), self.rect.bottom() - height),
            self.rect.max,
        );
        self.rect.max.y = (rect.top() - GAP).max(self.rect.min.y);
        rect
    }

    fn rest(&self) -> egui::Rect {
        self.rect
    }
}

fn split_left(rect: egui::Rect, width: f32, gap: f32) -> (egui::Rect, egui::Rect) {
    let width = width.min(rect.width());
    let left = rect.with_max_x(rect.left() + width);
    let right = rect.with_min_x((rect.left() + width + gap).min(rect.right()));
    (left, right)
}

/// The inner size: 880 × 560 points outside by default, user-resizable and
/// clamped to the window every frame, with no minimum forced past it.
fn modal_size(context: &egui::Context) -> egui::Vec2 {
    let margins = egui::vec2(24.0, 24.0);
    let cap =
        (context.content_rect().size() - egui::vec2(32.0, 32.0) - margins).max(egui::Vec2::ZERO);
    let wanted = context
        .data(|data| data.get_temp::<egui::Vec2>(size_id()))
        .unwrap_or(egui::vec2(880.0, 560.0) - margins);
    let minimum = (egui::vec2(480.0, 320.0) - margins).min(cap);
    wanted.clamp(minimum, cap).floor()
}

fn size_id() -> egui::Id {
    egui::Id::unique("file-chooser-size")
}

/// A bottom-right drag handle. The modal is centered, so the size changes by
/// twice the pointer movement to keep the corner under the pointer.
fn resize_grip(ui: &mut egui::Ui, size: egui::Vec2) {
    let corner = ui.min_rect().right_bottom();
    let rect = egui::Rect::from_min_max(corner - egui::vec2(12.0, 12.0), corner);
    let response = ui
        .interact(
            rect,
            egui::Id::unique("file-chooser-grip"),
            egui::Sense::drag(),
        )
        .on_hover_cursor(egui::CursorIcon::ResizeNwSe);
    if response.dragged() {
        let size = size + response.drag_delta() * 2.0;
        ui.data_mut(|data| data.insert_temp(size_id(), size));
    }
    let stroke = Stroke::new(1.0, theme::MUTED);
    for step in [4.0, 8.0] {
        ui.painter().line_segment(
            [
                corner - egui::vec2(step, 1.0),
                corner - egui::vec2(1.0, step),
            ],
            stroke,
        );
    }
}

fn up_button(ui: &mut egui::Ui, enabled: bool) -> egui::Response {
    let response = ui.add_enabled(
        enabled,
        egui::Button::new("")
            .min_size(egui::vec2(26.0, 22.0))
            .frame_when_inactive(false),
    );
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, response.enabled(), "Up"));
    if ui.is_rect_visible(response.rect) {
        let center = response.rect.center();
        let color = if response.enabled() {
            ui.style().interact(&response).fg_stroke.color
        } else {
            theme::MUTED.gamma_multiply(0.45)
        };
        let stroke = Stroke::new(1.8, color);
        let tip = center - egui::vec2(0.0, 5.0);
        ui.painter()
            .line_segment([center + egui::vec2(0.0, 5.0), tip], stroke);
        ui.painter()
            .line_segment([tip + egui::vec2(-4.0, 4.0), tip], stroke);
        ui.painter()
            .line_segment([tip + egui::vec2(4.0, 4.0), tip], stroke);
    }
    response
        .on_hover_text("Up (Backspace)")
        .on_disabled_hover_text("Up (Backspace)")
}

fn error_icon(ui: &mut egui::Ui, rect: egui::Rect, error: &str) {
    let response = ui.interact(
        rect,
        ui.scope_id().with("file-chooser-error"),
        egui::Sense::click(),
    );
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Label, true, error));
    let center = rect.center();
    ui.painter().circle_filled(center, 6.5, theme::ERROR);
    ui.painter().line_segment(
        [center - egui::vec2(0.0, 3.5), center + egui::vec2(0.0, 1.0)],
        Stroke::new(1.6, theme::VIEW),
    );
    ui.painter()
        .circle_filled(center + egui::vec2(0.0, 3.5), 0.9, theme::VIEW);
    response.on_hover_text(error);
}

#[cfg(test)]
mod tests {
    use super::io::fake::Fake;
    use super::io::{DirectoryPermit, Filesystem, spawn_thread};
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const WAIT: Duration = Duration::from_secs(10);

    fn dialogs_on(fs: Arc<dyn Filesystem>) -> FileDialogs {
        FileDialogs::with_scheduler(Scheduler::new(
            fs,
            Arc::new(AtomicBool::new(false)),
            spawn_thread,
        ))
    }

    fn open(
        dialogs: &mut FileDialogs,
        kind: FileDialogKind,
        directory: Option<&Path>,
    ) -> Receiver<Option<PathBuf>> {
        let (result, receiver) = mpsc::sync_channel(1);
        dialogs
            .requests
            .send(FileDialogRequest {
                kind,
                initial_dir: directory.map(Path::to_path_buf),
                result,
            })
            .unwrap();
        dialogs.open_next();
        assert!(dialogs.active.is_some());
        receiver
    }

    fn act<R>(dialogs: &mut FileDialogs, action: impl FnOnce(&mut Picker, &mut Io) -> R) -> R {
        let (picker, _) = dialogs.active.as_mut().expect("open chooser");
        let mut io = Io {
            scheduler: &mut dialogs.scheduler,
            recents: &mut dialogs.recents,
            places: &dialogs.places,
        };
        action(picker, &mut io)
    }

    fn picker(dialogs: &FileDialogs) -> &Picker {
        &dialogs.active.as_ref().expect("open chooser").0
    }

    /// Run queued work to completion; an accepted path closes the chooser.
    fn settle(dialogs: &mut FileDialogs) -> Option<PathBuf> {
        for _ in 0..256 {
            dialogs.start();
            if !dialogs.scheduler.running() && dialogs.scheduler.idle() {
                return None;
            }
            let reply = dialogs.scheduler.wait(WAIT).expect("reader replied");
            if let Some(path) = dialogs.route(reply) {
                dialogs.finish(Some(path.clone()));
                return Some(path);
            }
        }
        panic!("chooser work did not settle");
    }

    fn submit(dialogs: &mut FileDialogs, name: &str) -> Option<PathBuf> {
        act(dialogs, |picker, io| {
            picker.filename = name.into();
            picker.source = FilenameSource::Typed;
            picker.touch();
            picker.submit(io)
        })
        .or_else(|| settle(dialogs))
    }

    fn labels(picker: &Picker) -> Vec<String> {
        let entries = &picker.listing.as_ref().unwrap().entries;
        picker
            .visible
            .iter()
            .map(|&index| entries[index].label.clone())
            .collect()
    }

    fn index_of(picker: &Picker, label: &str) -> usize {
        picker
            .listing
            .as_ref()
            .unwrap()
            .entries
            .iter()
            .position(|entry| entry.label == label)
            .unwrap()
    }

    static SPAWNS: AtomicUsize = AtomicUsize::new(0);

    fn counting_spawn(task: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
        SPAWNS.fetch_add(1, Ordering::SeqCst);
        spawn_thread(task)
    }

    #[test]
    fn pending_directory_read_cannot_accumulate_threads_across_cancelled_choosers() {
        let fs = Arc::new(Fake::default());
        fs.dir("/tmp", &[]);
        let busy = Arc::new(AtomicBool::new(true));
        let mut dialogs =
            FileDialogs::with_scheduler(Scheduler::new(fs.clone(), busy.clone(), counting_spawn));
        for _ in 0..8 {
            let result = open(
                &mut dialogs,
                FileDialogKind::OpenBinary,
                Some(Path::new("/tmp")),
            );
            dialogs.start();
            assert!(!dialogs.scheduler.running());
            dialogs.finish(None);
            assert_eq!(result.try_recv(), Ok(None));
        }
        assert_eq!(SPAWNS.load(Ordering::SeqCst), 0);
        drop(DirectoryPermit(busy.clone()));
        assert!(!busy.load(Ordering::Acquire));
        let _result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(Path::new("/tmp")),
        );
        assert!(dialogs.scheduler.running());
        assert_eq!(SPAWNS.load(Ordering::SeqCst), 1);
        settle(&mut dialogs);
        assert_eq!(fs.reads.load(Ordering::SeqCst), 1);
        assert_eq!(
            picker(&dialogs).committed.as_deref(),
            Some(Path::new("/tmp"))
        );
    }

    #[test]
    fn chooser_returns_only_the_explicit_selection() {
        let dialogs = FileDialogs::default();
        let sender = dialogs.sender();
        let task =
            std::thread::spawn(move || request_file(&sender, FileDialogKind::OpenBinary, None));
        let request = dialogs.receiver.recv_timeout(WAIT).unwrap();
        assert_eq!(request.kind, FileDialogKind::OpenBinary);
        // The working-directory fallback is resolved on the file-task thread.
        assert_eq!(request.initial_dir, std::env::current_dir().ok());
        request.result.send(Some(PathBuf::from("fixture"))).unwrap();
        assert_eq!(task.join().unwrap(), Some(PathBuf::from("fixture")));
        assert!(dialogs.active.is_none());
    }

    #[test]
    fn cancelled_dialog_releases_the_waiting_file_job() {
        let dialogs = FileDialogs::default();
        let sender = dialogs.sender();
        let task = std::thread::spawn(move || {
            request_file(&sender, FileDialogKind::SaveAnnotations, None)
        });
        let request = dialogs.receiver.recv_timeout(WAIT).unwrap();
        request.result.send(None).unwrap();
        assert!(task.join().unwrap().is_none());
    }

    #[test]
    fn chooser_renders_without_a_desktop_portal() {
        let directory = tempfile::tempdir().unwrap();
        let mut dialogs = FileDialogs::default();
        let result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(directory.path()),
        );
        let context = egui::Context::default();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            dialogs.show(ui.ctx());
        });
        assert!(dialogs.active.is_some());
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        dialogs.finish(None);
        assert_eq!(result.try_recv(), Ok(None));
    }

    #[test]
    fn newer_navigation_discards_old_listing_even_for_same_path() {
        let fs = Arc::new(Fake::default());
        fs.dir("/a", &[("first", io::EntryKind::File)]);
        fs.dir("/b", &[("second", io::EntryKind::File)]);
        let (gate, _) = fs.gate("/a");
        let mut dialogs = dialogs_on(fs.clone());
        let _result = open(&mut dialogs, FileDialogKind::OpenBinary, None);
        let navigate = |dialogs: &mut FileDialogs, path: &str| {
            act(dialogs, |picker, io| {
                picker.navigate(io, path.into(), Intent::New, None);
            });
            dialogs.start();
        };
        navigate(&mut dialogs, "/a");
        let stale = picker(&dialogs).navigation.as_ref().unwrap().token;
        navigate(&mut dialogs, "/b");
        navigate(&mut dialogs, "/a");
        // A forged late result for the same path, listing or error, is
        // ignored because its token is stale.
        for outcome in [
            Outcome::Listing(Ok(Listing {
                directory: "/a".into(),
                entries: Vec::new(),
                partial: None,
            })),
            Outcome::Listing(Err("Permission denied".into())),
        ] {
            let dialog = picker(&dialogs).dialog;
            assert!(
                dialogs
                    .route(Reply {
                        dialog,
                        token: stale,
                        optional: false,
                        outcome,
                    })
                    .is_none()
            );
            let picker = picker(&dialogs);
            assert!(picker.listing.is_none() && picker.error.is_none());
            assert!(picker.history.paths.is_empty());
        }
        drop(gate);
        settle(&mut dialogs);
        let picker = picker(&dialogs);
        assert_eq!(picker.committed.as_deref(), Some(Path::new("/a")));
        assert_eq!(labels(picker), ["first"]);
        assert_eq!(picker.history.paths, [PathBuf::from("/a")]);
        // The superseded /b request never reached the filesystem.
        assert!(!fs.read_paths().contains(&PathBuf::from("/b")));
    }

    #[test]
    fn cancel_and_reopen_share_one_filesystem_permit() {
        let fs = Arc::new(Fake::default());
        fs.dir("/slow", &[]);
        fs.dir("/fast", &[("file", io::EntryKind::File)]);
        let (gate, started) = fs.gate("/slow");
        let mut dialogs = dialogs_on(fs.clone());
        let first = open(
            &mut dialogs,
            FileDialogKind::SaveProject,
            Some(Path::new("/slow")),
        );
        // The reader is blocked inside the filesystem call; cancel is not.
        started.recv_timeout(WAIT).unwrap();
        dialogs.finish(None);
        assert_eq!(first.try_recv(), Ok(None));
        // Reopened choosers stay usable but cannot start another reader.
        for _ in 0..5 {
            let result = open(
                &mut dialogs,
                FileDialogKind::SaveProject,
                Some(Path::new("/fast")),
            );
            act(&mut dialogs, |picker, io| {
                picker.navigate(io, "/fast".into(), Intent::New, None);
                picker.filename = "/fast/new".into();
                picker.submit(io);
            });
            dialogs.start();
            assert!(matches!(
                picker(&dialogs).confirmation,
                Confirmation::Inspecting(_)
            ));
            dialogs.finish(None);
            assert_eq!(result.try_recv(), Ok(None));
        }
        let _result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(Path::new("/fast")),
        );
        drop(gate);
        settle(&mut dialogs);
        assert_eq!(
            picker(&dialogs).committed.as_deref(),
            Some(Path::new("/fast"))
        );
        assert_eq!(fs.peak.load(Ordering::SeqCst), 1);
        assert_eq!(fs.reads.load(Ordering::SeqCst), 2);
    }

    fn failing_spawn(_: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
        Err(std::io::Error::other("no threads"))
    }

    fn vanishing_spawn(task: Box<dyn FnOnce() + Send>) -> std::io::Result<()> {
        drop(task);
        Ok(())
    }

    #[test]
    fn reader_disconnect_and_spawn_failure_leave_chooser_usable() {
        for spawn in [failing_spawn as io::Spawner, vanishing_spawn] {
            let fs = Arc::new(Fake::default());
            fs.dir("/d", &[]);
            let busy = Arc::new(AtomicBool::new(false));
            let mut dialogs =
                FileDialogs::with_scheduler(Scheduler::new(fs.clone(), busy.clone(), spawn));
            let result = open(
                &mut dialogs,
                FileDialogKind::OpenProject,
                Some(Path::new("/d")),
            );
            settle(&mut dialogs);
            let picker = picker(&dialogs);
            assert!(picker.error.is_some() && picker.navigation.is_none());
            assert!(!busy.load(Ordering::Acquire));
            dialogs.finish(None);
            assert_eq!(result.try_recv(), Ok(None));
        }
    }

    #[test]
    fn failed_navigation_preserves_committed_history() {
        let fs = Arc::new(Fake::default());
        fs.dir("/home", &[("x", io::EntryKind::Directory)]);
        fs.dir("/home/x", &[]);
        fs.set("/denied", Err(std::io::ErrorKind::PermissionDenied));
        let mut dialogs = dialogs_on(fs);
        let _result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(Path::new("/home")),
        );
        settle(&mut dialogs);
        act(&mut dialogs, |picker, io| {
            picker.navigate(io, "/home/x".into(), Intent::New, None);
        });
        settle(&mut dialogs);
        act(&mut dialogs, |picker, io| {
            picker.edit_location();
            picker.location.text = "/denied".into();
            picker.submit_location(io);
        });
        settle(&mut dialogs);
        let state = picker(&dialogs);
        assert!(state.error.is_some());
        assert_eq!(state.committed.as_deref(), Some(Path::new("/home/x")));
        assert_eq!(
            state.history.paths,
            [PathBuf::from("/home"), "/home/x".into()]
        );
        assert!(state.location.editing);
        assert_eq!(state.location.text, "/denied");
        // A failed Recent entry is removed; the other recents stay.
        dialogs.recents.record(Path::new("/gone"));
        act(&mut dialogs, |picker, io| {
            picker.navigate_from(io, "/gone".into(), Intent::New, true, None);
        });
        settle(&mut dialogs);
        let recents: Vec<_> = dialogs.recents.paths().cloned().collect();
        assert_eq!(recents, [PathBuf::from("/home/x")]);
        act(&mut dialogs, |picker, io| picker.go_back(io));
        settle(&mut dialogs);
        let state = picker(&dialogs);
        assert_eq!(state.committed.as_deref(), Some(Path::new("/home")));
        assert!(state.error.is_none());
        assert_eq!(state.history.forward(), Some(&PathBuf::from("/home/x")));
        act(&mut dialogs, |picker, io| picker.go_up(io));
        settle(&mut dialogs);
        // Up to a missing root fails without losing Forward history.
        assert_eq!(
            picker(&dialogs).committed.as_deref(),
            Some(Path::new("/home"))
        );
        assert_eq!(picker(&dialogs).history.paths.len(), 2);
    }

    #[test]
    fn sort_filters_preserve_native_selection() {
        let fs = Arc::new(Fake::default());
        fs.dir(
            "/d",
            &[
                ("zeta", io::EntryKind::File),
                ("alpha", io::EntryKind::File),
                ("folder", io::EntryKind::Directory),
            ],
        );
        let mut dialogs = dialogs_on(fs);
        let result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(Path::new("/d")),
        );
        settle(&mut dialogs);
        let zeta = index_of(picker(&dialogs), "zeta");
        act(&mut dialogs, |picker, _| {
            picker.select(zeta);
            picker.sort.click(table::SortColumn::Name);
            picker.rebuild_visible();
        });
        let state = picker(&dialogs);
        assert_eq!(labels(state), ["folder", "zeta", "alpha"]);
        assert_eq!((state.selected, state.reveal), (Some(zeta), Some(1)));
        // Filtering the selection out clears it without choosing another.
        act(&mut dialogs, |picker, _| {
            picker.filter = "alp".into();
            picker.rebuild_visible();
        });
        let state = picker(&dialogs);
        assert_eq!(labels(state), ["alpha"]);
        assert_eq!(state.selected, None);
        assert!(state.filename.is_empty() && !state.can_submit());
        act(&mut dialogs, |picker, _| {
            picker.filter.clear();
            picker.rebuild_visible();
            picker.select(zeta);
        });
        assert_eq!(
            act(&mut dialogs, |picker, io| picker.submit(io)),
            Some(PathBuf::from("/d/zeta"))
        );
        drop(result);
    }

    #[test]
    fn changing_native_selection_discards_pending_save_inspection() {
        for select_folder in [false, true] {
            let fs = Arc::new(Fake::default());
            fs.dir(
                "/d",
                &[
                    ("target.json", EntryKind::File),
                    ("folder", EntryKind::Directory),
                ],
            );
            let mut dialogs = dialogs_on(fs);
            let result = open(
                &mut dialogs,
                FileDialogKind::SaveAnnotations,
                Some(Path::new("/d")),
            );
            settle(&mut dialogs);
            let file = index_of(picker(&dialogs), "target.json");
            let folder = index_of(picker(&dialogs), "folder");
            act(&mut dialogs, |picker, io| {
                picker.select(file);
                assert!(picker.submit(io).is_none());
            });
            dialogs.start();
            act(&mut dialogs, |picker, _| {
                if select_folder {
                    picker.select(folder);
                } else {
                    picker.filter = "folder".into();
                    picker.rebuild_visible();
                }
            });
            // Neither an existing target nor a target removed during the
            // inspection may prompt or finish after its selection is abandoned.
            let mut reply = dialogs.scheduler.wait(WAIT).expect("inspection replied");
            reply.outcome = Outcome::Inspected(Verdict::Missing("/d/target.json".into()));
            assert!(dialogs.route(reply).is_none());
            assert!(matches!(picker(&dialogs).confirmation, Confirmation::Idle));
            assert!(result.try_recv().is_err());
            assert_eq!(
                selected_label(&dialogs).as_deref(),
                if select_folder { Some("folder") } else { None }
            );
        }
    }

    #[test]
    fn backspace_goes_up_from_an_empty_directory() {
        let root = tempfile::tempdir().unwrap();
        let empty = root.path().join("empty");
        std::fs::create_dir(&empty).unwrap();
        let mut dialogs = FileDialogs::default();
        let _result = open(&mut dialogs, FileDialogKind::OpenBinary, Some(&empty));
        settle(&mut dialogs);
        let context = egui::Context::default();
        theme::install(&context);
        let screen = egui::vec2(1000.0, 700.0);
        frame(&context, &mut dialogs, screen, vec![]);
        context.memory_mut(|memory| memory.request_focus(egui::Id::unique(TABLE_ID)));
        frame(&context, &mut dialogs, screen, press(egui::Key::Backspace));
        settle(&mut dialogs);
        assert_eq!(picker(&dialogs).committed.as_deref(), Some(root.path()));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_and_control_names_return_exact_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let names = [
            OsStr::from_bytes(b"same\xff"),
            OsStr::from_bytes(b"same\xfe"),
            OsStr::new("line\nbreak\u{202e}"),
            OsStr::new(" spaced "),
        ];
        for name in names {
            std::fs::write(directory.path().join(name), b"x").unwrap();
        }
        let mut dialogs = FileDialogs::default();
        let _result = open(
            &mut dialogs,
            FileDialogKind::SaveAnnotations,
            Some(directory.path()),
        );
        settle(&mut dialogs);
        let state = picker(&dialogs);
        let entries = &state.listing.as_ref().unwrap().entries;
        let find = |name: &OsStr| entries.iter().position(|entry| entry.name == name).unwrap();
        let (first, second) = (find(names[0]), find(names[1]));
        assert_eq!(entries[first].label, entries[second].label);
        assert_eq!(entries[find(names[2])].label, "line\\u{a}break\\u{202e}");
        // Lossy labels collide, but each row keeps its own native path.
        act(&mut dialogs, |picker, _| picker.select(second));
        let state = picker(&dialogs);
        assert_eq!(
            state.source,
            FilenameSource::Entry(second, state.generation)
        );
        let chosen = act(&mut dialogs, |picker, io| picker.submit(io));
        assert!(chosen.is_none());
        let replace = settle(&mut dialogs);
        assert!(replace.is_none());
        let Confirmation::Replace(path) = &picker(&dialogs).confirmation else {
            panic!("an existing save target needs confirmation");
        };
        assert_eq!(path, &directory.path().join(names[1]));
        // Leaving the folder drops a lossy saved name but keeps an exact one.
        let here = directory.path().to_path_buf();
        act(&mut dialogs, |picker, io| {
            picker.select(second);
            picker.navigate(io, here.clone(), Intent::New, None);
        });
        assert!(picker(&dialogs).filename.is_empty());
        settle(&mut dialogs);
        let spaced = {
            let entries = &picker(&dialogs).listing.as_ref().unwrap().entries;
            entries
                .iter()
                .position(|entry| entry.name == names[3])
                .unwrap()
        };
        act(&mut dialogs, |picker, io| {
            picker.select(spaced);
            picker.navigate(io, here.clone(), Intent::New, None);
        });
        let state = picker(&dialogs);
        assert_eq!(state.filename, " spaced ");
        assert_eq!(state.source, FilenameSource::Typed);
    }

    #[cfg(unix)]
    #[test]
    fn directory_links_do_not_trigger_recursive_reads() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub").join("inside"), b"x").unwrap();
        symlink("loop", root.join("loop")).unwrap();
        symlink("missing", root.join("dangling")).unwrap();
        symlink("sub", root.join("folder-link")).unwrap();
        let mut dialogs = FileDialogs::default();
        let _result = open(&mut dialogs, FileDialogKind::OpenBinary, Some(root));
        settle(&mut dialogs);
        let state = picker(&dialogs);
        let kind = |label| state.listing.as_ref().unwrap().entries[index_of(state, label)].kind;
        // Listing reports links without resolving their targets.
        for link in ["loop", "dangling", "folder-link"] {
            assert_eq!(kind(link), EntryKind::Link);
        }
        assert_eq!(kind("sub"), EntryKind::Directory);
        // A link loop fails once with an error; the folder stays put.
        let looped = index_of(state, "loop");
        assert!(act(&mut dialogs, |picker, io| picker.activate(io, looped)).is_none());
        assert!(settle(&mut dialogs).is_none());
        let state = picker(&dialogs);
        assert!(state.error.is_some());
        assert_eq!(state.committed.as_deref(), Some(root));
        // An explicitly activated folder link is followed once.
        let linked = index_of(state, "folder-link");
        act(&mut dialogs, |picker, io| picker.activate(io, linked));
        assert!(settle(&mut dialogs).is_none());
        let state = picker(&dialogs);
        assert_eq!(
            state.committed.as_deref(),
            Some(root.join("folder-link").as_path())
        );
        assert_eq!(labels(state), ["inside"]);
    }

    #[test]
    fn save_directory_is_navigation_before_default_extension() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::create_dir(root.join("report")).unwrap();
        std::fs::create_dir(root.join("other.grproj")).unwrap();
        let mut dialogs = FileDialogs::default();
        let result = open(&mut dialogs, FileDialogKind::SaveProject, Some(root));
        settle(&mut dialogs);
        assert_eq!(submit(&mut dialogs, "report"), None);
        let state = picker(&dialogs);
        assert_eq!(
            state.committed.as_deref(),
            Some(root.join("report").as_path())
        );
        assert_eq!(state.filename, "analysis.grproj");
        act(&mut dialogs, |picker, io| picker.go_back(io));
        settle(&mut dialogs);
        assert_eq!(submit(&mut dialogs, "other"), None);
        assert_eq!(
            picker(&dialogs).committed.as_deref(),
            Some(root.join("other.grproj").as_path())
        );
        assert!(result.try_recv().is_err());
        // A missing target gets the extension exactly once.
        assert_eq!(
            submit(&mut dialogs, "fresh"),
            Some(root.join("other.grproj").join("fresh.grproj"))
        );
        assert_eq!(
            result.try_recv(),
            Ok(Some(root.join("other.grproj").join("fresh.grproj")))
        );
    }

    #[test]
    fn save_confirmation_is_explicit_and_revision_bound() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        std::fs::write(root.join("existing.grproj"), b"x").unwrap();
        let mut dialogs = FileDialogs::default();
        let result = open(&mut dialogs, FileDialogKind::SaveProject, Some(root));
        settle(&mut dialogs);
        assert_eq!(submit(&mut dialogs, "existing"), None);
        let Confirmation::Replace(path) = &picker(&dialogs).confirmation else {
            panic!("an existing file needs an explicit decision");
        };
        assert_eq!(path, &root.join("existing.grproj"));
        // Another Save cannot bypass the prompt; editing withdraws it.
        assert!(act(&mut dialogs, |picker, io| picker.submit(io)).is_none());
        act(&mut dialogs, |picker, _| {
            picker.filename.push('2');
            picker.touch();
        });
        assert!(matches!(picker(&dialogs).confirmation, Confirmation::Idle));
        // A late inspection after an edit cannot confirm the old name.
        act(&mut dialogs, |picker, io| {
            picker.filename = "existing".into();
            picker.submit(io);
            picker.filename = "fresh".into();
            picker.touch();
        });
        assert_eq!(settle(&mut dialogs), None);
        assert!(matches!(picker(&dialogs).confirmation, Confirmation::Idle));
        assert!(result.try_recv().is_err());
        // Cancel during an inspection returns no path.
        act(&mut dialogs, |picker, io| {
            picker.filename = "existing".into();
            picker.submit(io)
        });
        dialogs.start();
        dialogs.finish(None);
        assert_eq!(result.try_recv(), Ok(None));
        assert!(settle(&mut dialogs).is_none());

        // Permission errors are not treated as an absent target.
        let fs = Arc::new(Fake::default());
        fs.dir("/d", &[]);
        fs.set(
            "/d/locked.grproj",
            Err(std::io::ErrorKind::PermissionDenied),
        );
        let mut dialogs = dialogs_on(fs);
        let result = open(
            &mut dialogs,
            FileDialogKind::SaveProject,
            Some(Path::new("/d")),
        );
        settle(&mut dialogs);
        assert_eq!(submit(&mut dialogs, "locked"), None);
        assert!(picker(&dialogs).error.is_some());
        assert!(result.try_recv().is_err());
    }

    #[test]
    fn recents_are_session_bounded_and_no_io() {
        let fs = Arc::new(Fake::default());
        fs.dir("/a", &[("file", io::EntryKind::File)]);
        fs.dir("/b", &[("file", io::EntryKind::File)]);
        let mut dialogs = dialogs_on(fs.clone());
        let result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(Path::new("/a")),
        );
        settle(&mut dialogs);
        // The automatic first listing is not an explicit visit.
        assert_eq!(dialogs.recents.paths().len(), 0);
        act(&mut dialogs, |picker, io| {
            picker.navigate(io, "/b".into(), Intent::New, None);
        });
        settle(&mut dialogs);
        dialogs.finish(None);
        assert_eq!(result.try_recv(), Ok(None));
        let recents: Vec<_> = dialogs.recents.paths().cloned().collect();
        assert_eq!(recents, [PathBuf::from("/b")]);
        // A canceled chooser adds nothing; an accepted file adds its folder.
        let result = open(
            &mut dialogs,
            FileDialogKind::OpenBinary,
            Some(Path::new("/a")),
        );
        settle(&mut dialogs);
        let file = index_of(picker(&dialogs), "file");
        let chosen = act(&mut dialogs, |picker, io| picker.activate(io, file));
        assert_eq!(chosen.as_deref(), Some(Path::new("/a/file")));
        dialogs.finish(chosen);
        assert!(result.try_recv().unwrap().is_some());
        let recents: Vec<_> = dialogs.recents.paths().cloned().collect();
        assert_eq!(recents, [PathBuf::from("/a"), "/b".into()]);
        // Rendering Recent performs no filesystem access.
        let _result = open(&mut dialogs, FileDialogKind::OpenBinary, None);
        settle(&mut dialogs);
        let calls = fs.calls.load(Ordering::SeqCst);
        let context = egui::Context::default();
        for _ in 0..3 {
            let mut output = context.run_ui(egui::RawInput::default(), |ui| {
                let (picker, _) = dialogs.active.as_mut().unwrap();
                let mut io = Io {
                    scheduler: &mut dialogs.scheduler,
                    recents: &mut dialogs.recents,
                    places: &dialogs.places,
                };
                assert!(picker.show(ui.ctx(), &mut io).is_none());
            });
            output.textures_delta.clear();
        }
        assert_eq!(fs.calls.load(Ordering::SeqCst), calls);
        assert_eq!(FileDialogs::default().recents.paths().len(), 0);
    }

    fn key(key: egui::Key, modifiers: egui::Modifiers, repeat: bool) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat,
            modifiers,
        }
    }

    fn release(code: egui::Key) -> egui::Event {
        let mut event = key(code, egui::Modifiers::NONE, false);
        if let egui::Event::Key { pressed, .. } = &mut event {
            *pressed = false;
        }
        event
    }

    /// A complete key press, so the next press is not a repeat.
    fn press(code: egui::Key) -> Vec<egui::Event> {
        vec![key(code, egui::Modifiers::NONE, false), release(code)]
    }

    fn frame(
        context: &egui::Context,
        dialogs: &mut FileDialogs,
        screen: egui::Vec2,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, screen)),
                events,
                ..Default::default()
            },
            |ui| dialogs.show(ui.ctx()),
        );
        output.textures_delta.clear();
        output
    }

    fn selected_label(dialogs: &FileDialogs) -> Option<String> {
        let state = picker(dialogs);
        state
            .selected
            .and_then(|index| state.entry(index))
            .map(|entry| entry.label.clone())
    }

    #[test]
    fn chooser_keyboard_focus_routes_navigation_and_submit_once() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        for name in ["a.bin", "b.bin", "c.bin"] {
            std::fs::write(root.join(name), b"x").unwrap();
        }
        let screen = egui::vec2(1000.0, 700.0);
        let context = egui::Context::default();
        theme::install(&context);
        let mut dialogs = FileDialogs::default();
        let result = open(&mut dialogs, FileDialogKind::OpenBinary, Some(&root));
        settle(&mut dialogs);
        let step = |dialogs: &mut FileDialogs, events| {
            frame(&context, dialogs, screen, events);
            settle(dialogs)
        };
        step(&mut dialogs, vec![]);
        act(&mut dialogs, |picker, _| picker.focus = Some(Focus::Table));
        step(&mut dialogs, vec![]);
        step(&mut dialogs, vec![]);
        let expect = |dialogs: &mut FileDialogs, events, label: &str| {
            assert!(
                frame(&context, dialogs, screen, events)
                    .platform_output
                    .events
                    .len()
                    < 64
            );
            assert_eq!(selected_label(dialogs).as_deref(), Some(label));
        };
        expect(&mut dialogs, press(egui::Key::ArrowDown), "sub");
        expect(&mut dialogs, press(egui::Key::ArrowDown), "a.bin");
        assert_eq!(picker(&dialogs).filename, "a.bin");
        expect(&mut dialogs, press(egui::Key::End), "c.bin");
        expect(&mut dialogs, press(egui::Key::Home), "sub");
        expect(&mut dialogs, press(egui::Key::PageDown), "c.bin");
        expect(
            &mut dialogs,
            vec![key(egui::Key::ArrowUp, egui::Modifiers::NONE, true)],
            "b.bin",
        );
        // A held Enter never submits; one fresh press does, exactly once.
        let chosen = picker(&dialogs).selected;
        let hold = || vec![key(egui::Key::Enter, egui::Modifiers::NONE, false)];
        act(&mut dialogs, |picker, _| picker.selected = None);
        step(&mut dialogs, hold());
        act(&mut dialogs, |picker, _| picker.selected = chosen);
        step(&mut dialogs, hold());
        assert!(result.try_recv().is_err());
        step(&mut dialogs, vec![release(egui::Key::Enter)]);
        step(&mut dialogs, press(egui::Key::Enter));
        assert_eq!(result.try_recv(), Ok(Some(root.join("b.bin"))));
        assert!(dialogs.active.is_none());
        step(&mut dialogs, press(egui::Key::Enter));
        assert!(result.try_recv().is_err());

        // Backspace edits the name field, but goes up from the table.
        let result = open(&mut dialogs, FileDialogKind::OpenBinary, Some(&root));
        settle(&mut dialogs);
        act(&mut dialogs, |picker, _| {
            picker.focus = Some(Focus::Filename)
        });
        step(&mut dialogs, vec![]);
        step(&mut dialogs, vec![egui::Event::Text("zz".into())]);
        step(&mut dialogs, press(egui::Key::Backspace));
        assert_eq!(picker(&dialogs).filename, "z");
        assert_eq!(picker(&dialogs).committed.as_deref(), Some(root.as_path()));
        act(&mut dialogs, |picker, _| picker.focus = Some(Focus::Table));
        step(&mut dialogs, vec![]);
        step(&mut dialogs, vec![]);
        step(&mut dialogs, press(egui::Key::Backspace));
        assert_eq!(
            picker(&dialogs).committed.as_deref(),
            Some(directory.path())
        );
        // Alt+Left returns through chooser history.
        step(
            &mut dialogs,
            vec![key(egui::Key::ArrowLeft, egui::Modifiers::ALT, false)],
        );
        assert_eq!(picker(&dialogs).committed.as_deref(), Some(root.as_path()));
        // Ctrl+L edits the path; Escape leaves editing before it cancels.
        step(
            &mut dialogs,
            vec![key(egui::Key::L, egui::Modifiers::COMMAND, false)],
        );
        assert!(picker(&dialogs).location.editing);
        step(&mut dialogs, vec![]);
        step(&mut dialogs, press(egui::Key::Escape));
        assert!(dialogs.active.is_some());
        assert!(!picker(&dialogs).location.editing);
        step(&mut dialogs, vec![]);
        step(&mut dialogs, press(egui::Key::Escape));
        assert!(dialogs.active.is_none());
        assert_eq!(result.try_recv(), Ok(None));
    }

    #[test]
    fn chooser_fractional_layout_stays_bounded() {
        let fs = Arc::new(Fake::default());
        let names: Vec<String> = (0..4096)
            .map(|index| format!("{index:04} {}", "long file name ".repeat(index % 7 + 1)))
            .collect();
        let mut entries: Vec<(&str, io::EntryKind)> = names
            .iter()
            .map(|name| (name.as_str(), io::EntryKind::File))
            .collect();
        entries.push(("folder", io::EntryKind::Directory));
        fs.dir("/big", &entries);
        for scale in [1.0, 1.25] {
            for (width, height) in [
                (1280.0, 800.0),
                (700.0, 520.0),
                (440.0, 400.0),
                (300.0, 200.0),
            ] {
                let screen = egui::vec2(width, height);
                let bounds = egui::Rect::from_min_size(egui::Pos2::ZERO, screen).expand(1.0);
                let context = egui::Context::default();
                theme::install(&context);
                context.set_pixels_per_point(scale);
                context.global_style_mut(|style| style.animation_time = 0.0);
                let mut dialogs = dialogs_on(fs.clone());
                let _result = open(
                    &mut dialogs,
                    FileDialogKind::SaveProject,
                    Some(Path::new("/big")),
                );
                settle(&mut dialogs);
                let mut previous = None;
                for index in 0..8 {
                    let output = frame(&context, &mut dialogs, screen, vec![]);
                    settle(&mut dialogs);
                    let area = context
                        .memory(|memory| memory.area_rect(egui::Id::unique("file-chooser")))
                        .expect("chooser area");
                    assert!(
                        index < 2 || bounds.contains_rect(area),
                        "scale={scale} screen={screen:?} area={area:?}"
                    );
                    // Only the visible rows of 4,096 are painted.
                    assert!(output.shapes.len() < 1500, "{}", output.shapes.len());
                    let cancel = output
                        .shapes
                        .iter()
                        .find_map(|clipped| match &clipped.shape {
                            egui::Shape::Text(text) if text.galley.text() == "Cancel" => {
                                Some(text.visual_bounding_rect().intersect(clipped.clip_rect))
                            }
                            _ => None,
                        });
                    // A new area is laid out invisibly on its first pass.
                    if height >= 400.0 && index > 1 {
                        let cancel = cancel.unwrap_or_else(|| {
                            panic!("Cancel is painted: scale={scale} screen={screen:?}")
                        });
                        assert!(cancel.is_positive() && bounds.contains_rect(cancel));
                    }
                    if index >= 4 {
                        if let Some(previous) = previous {
                            assert_eq!(previous, (area, output.shapes.len()));
                        }
                        previous = Some((area, output.shapes.len()));
                    }
                }
            }
        }
    }
}
