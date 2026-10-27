//! Symbol Tree presentation of the adopted import/export table.
//!
//! [`LinkageTree`] owns one binary generation's page fetch, the background
//! grouping job and the flattened rows of expanded groups. A page is adopted
//! only for the generation and worker epoch that requested it, at the expected
//! cursor and table digest; anything else is dropped unseen, and a defective
//! current page discards the whole table. Partial tables are never shown.
//!
//! Shown names are display text only: an analyst label at the row's exact
//! address, then the worker's demangled name, then the raw declaration, then
//! its ordinal. Order stays on declared text (see [`LinkageView`]). Nothing
//! here demangles, resolves a library or creates a function.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui::{self, RichText};

use crate::linkage::{
    Export, ExportTarget, GroupKey, Import, ImportKind, Linkage, LinkageFetch, LinkagePage,
    LinkageSummary, LinkageView, LocationKind, import_locations,
};
use crate::model::{BinaryInfo, Request};
use crate::session::Session;
use crate::theme;

/// Height of one expanded category's virtualized list.
const LIST_HEIGHT: f32 = 180.0;
/// Row indentation per tree level inside a category list.
const INDENT: f32 = 14.0;

/// Stable identity of a selectable row: dense per-kind record indices of the
/// adopted table, never names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum LinkageItem {
    Import(u32),
    Export(u32),
    /// An additional verified location, by index into `Linkage::locations`.
    Location(u32),
}

/// One exact address an entry declares, with how it may be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    /// Verified file-backed code: opened through function/code navigation.
    Code(u64),
    /// A slot or data object: opened in Hex, selecting at most `length`
    /// file-backed bytes. Never becomes a function.
    Data { address: u64, length: u64 },
}

/// What a tree interaction asks the desktop to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TreeAction {
    Select(LinkageItem),
    Open(LinkageItem),
    /// An explicit location chosen from a row's menu.
    OpenPlace(LinkageItem, Place),
    Xrefs(LinkageItem),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Row {
    Group(u32),
    Import(u32),
    Location(u32),
}

/// Background-built presentation: the grouped view plus lowercased declared
/// names for filtering, indexed by record identity.
pub(crate) struct PreparedLinkage {
    view: LinkageView,
    import_keys: Box<[Box<str>]>,
    export_keys: Box<[Box<str>]>,
    group_keys: Box<[Box<str>]>,
}

fn declared_key(raw: &Option<String>, display: &Option<String>, ordinal: Option<u32>) -> Box<str> {
    let mut key = String::new();
    if let Some(display) = display {
        key.push_str(&display.to_lowercase());
        // A query cannot contain NUL, so it never spans both names.
        key.push('\0');
    }
    match (raw, ordinal) {
        (Some(raw), _) => key.push_str(&raw.to_lowercase()),
        (None, Some(ordinal)) => {
            let _ = write!(key, "ordinal {ordinal}");
        }
        (None, None) => {}
    }
    key.into_boxed_str()
}

impl PreparedLinkage {
    pub(crate) fn build(linkage: Arc<Linkage>) -> Self {
        let view = LinkageView::build(linkage);
        let linkage = &view.linkage;
        let import_keys = linkage
            .imports
            .iter()
            .map(|i| declared_key(&i.raw, &i.display, i.ordinal))
            .collect();
        let export_keys = linkage
            .exports
            .iter()
            .map(|e| declared_key(&e.raw, &e.display, e.ordinal))
            .collect();
        let group_keys = view
            .groups
            .iter()
            .map(|group| group.label.to_lowercase().into_boxed_str())
            .collect();
        Self {
            view,
            import_keys,
            export_keys,
            group_keys,
        }
    }

    pub(crate) fn linkage(&self) -> &Linkage {
        &self.view.linkage
    }

    /// Allocation capacity retained by the table, its view and filter keys.
    pub(crate) fn retained_bytes(&self) -> usize {
        let keys =
            |keys: &[Box<str>]| size_of_val(keys) + keys.iter().map(|k| k.len()).sum::<usize>();
        self.view.retained_bytes()
            + keys(&self.import_keys)
            + keys(&self.export_keys)
            + keys(&self.group_keys)
    }
}

/// The analyst label at `address`, when one is set.
fn label_at(session: Option<&Session>, address: Option<u64>) -> Option<&str> {
    let address = address?;
    session?
        .annotations
        .get(&address)
        .map(|annotation| annotation.label.as_str())
        .filter(|label| !label.is_empty())
}

/// Rename, then worker display name, then raw name, then ordinal.
pub(crate) fn shown_name<'a>(
    label: Option<&'a str>,
    raw: &'a Option<String>,
    display: &'a Option<String>,
    ordinal: Option<u32>,
) -> Cow<'a, str> {
    if let Some(name) = label.or(display.as_deref()).or(raw.as_deref()) {
        return Cow::Borrowed(name);
    }
    ordinal.map_or(Cow::Borrowed("?"), |ordinal| {
        Cow::Owned(format!("ordinal {ordinal}"))
    })
}

/// The exact address a row's name and analyst label belong to.
fn import_address(import: &Import) -> Option<u64> {
    import.stub.or(import.slot)
}

fn place_of(kind: LocationKind, address: u64, pointer: u64) -> Option<Place> {
    (address != 0).then_some(match kind {
        LocationKind::Stub => Place::Code(address),
        LocationKind::Slot => Place::Data {
            address,
            length: pointer,
        },
    })
}

/// Every exact address `item` declares: the primary stub, then the primary
/// slot, then further verified locations. Forwarders and unresolved entries
/// have none; address zero is never a place.
pub(crate) fn places(linkage: &Linkage, item: LinkageItem, pointer: u64) -> Vec<Place> {
    match item {
        LinkageItem::Import(id) => {
            let Some(import) = linkage.imports.get(id as usize) else {
                return Vec::new();
            };
            let primary = [
                import.stub.map(|a| (LocationKind::Stub, a)),
                import.slot.map(|a| (LocationKind::Slot, a)),
            ];
            let mut found: Vec<Place> = primary
                .into_iter()
                .flatten()
                .filter_map(|(kind, address)| place_of(kind, address, pointer))
                .collect();
            for (kind, address) in import_locations(linkage, import) {
                if let Some(place) = place_of(kind, address, pointer)
                    && !found.contains(&place)
                {
                    found.push(place);
                }
            }
            found
        }
        LinkageItem::Location(index) => linkage
            .locations
            .get(index as usize)
            .and_then(|location| place_of(location.kind, location.address, pointer))
            .into_iter()
            .collect(),
        LinkageItem::Export(id) => linkage
            .exports
            .get(id as usize)
            .and_then(|export| match export.target {
                ExportTarget::Code { address } | ExportTarget::Resolver { address } => {
                    (address != 0).then_some(Place::Code(address))
                }
                ExportTarget::Data { address } => {
                    (address != 0).then_some(Place::Data { address, length: 1 })
                }
                ExportTarget::Forwarder { .. } | ExportTarget::Unresolved => None,
            })
            .into_iter()
            .collect(),
    }
}

/// Where opening `item` goes: its stub, else its slot, else nowhere.
pub(crate) fn destination(linkage: &Linkage, item: LinkageItem, pointer: u64) -> Option<Place> {
    places(linkage, item, pointer).into_iter().next()
}

/// Outcome of a linkage reply for the current fetch.
pub(crate) enum Received {
    /// Another binary, worker, cursor or table: dropped without effect.
    Stale,
    /// Accepted; more pages follow.
    Pending,
    Complete(Linkage),
}

pub(crate) enum Polled {
    Idle,
    /// The presentation was adopted and retains this many bytes.
    Ready(usize),
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Idle,
    Loading,
    Ready,
    Unavailable,
}

enum State {
    Idle,
    Fetching {
        epoch: u64,
        /// Created by the first page's summary; uncommitted until complete.
        fetch: Option<Box<LinkageFetch>>,
    },
    Building(Receiver<PreparedLinkage>),
    Ready(Box<PreparedLinkage>),
    Unavailable,
}

struct RowsKey {
    query: String,
    revision: u64,
    expansion: u64,
}

struct Rows {
    key: RowsKey,
    imports: Vec<Row>,
    exports: Vec<u32>,
    /// Shown members per group, aligned with `LinkageView::groups`.
    group_counts: Vec<u32>,
    import_matches: usize,
}

/// One binary generation's imports and exports in the Symbol Tree.
pub(crate) struct LinkageTree {
    generation: u64,
    state: State,
    selected: Option<LinkageItem>,
    /// Groups the analyst expanded while no filter is active.
    expanded: BTreeSet<GroupKey>,
    /// Groups the analyst collapsed while filtering; matches start expanded.
    collapsed: BTreeSet<GroupKey>,
    collapsed_query: String,
    expansion: u64,
    rows: Option<Rows>,
}

impl Default for LinkageTree {
    fn default() -> Self {
        Self {
            generation: 0,
            state: State::Idle,
            selected: None,
            expanded: BTreeSet::new(),
            collapsed: BTreeSet::new(),
            collapsed_query: String::new(),
            expansion: 0,
            rows: None,
        }
    }
}

impl LinkageTree {
    /// Drops every table, page, job and transient tree state.
    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }

    /// A worker for `generation` opened. The same verified image keeps an
    /// adopted, building or failed table; an unfinished fetch restarts from
    /// its first page on the new worker.
    pub(crate) fn begin(&mut self, generation: u64, epoch: u64) {
        if self.generation != generation {
            self.reset();
            self.generation = generation;
        }
        if matches!(self.state, State::Idle | State::Fetching { .. }) {
            self.state = State::Fetching { epoch, fetch: None };
        }
    }

    /// The worker stopped: pages received so far are discarded.
    pub(crate) fn interrupt(&mut self) {
        if let State::Fetching { fetch, .. } = &mut self.state {
            *fetch = None;
        }
    }

    pub(crate) fn fail(&mut self) {
        self.state = State::Unavailable;
        self.rows = None;
    }

    pub(crate) fn status(&self) -> Status {
        match self.state {
            State::Idle => Status::Idle,
            State::Fetching { .. } | State::Building(_) => Status::Loading,
            State::Ready(_) => Status::Ready,
            State::Unavailable => Status::Unavailable,
        }
    }

    pub(crate) fn prepared(&self) -> Option<&PreparedLinkage> {
        match &self.state {
            State::Ready(prepared) => Some(prepared),
            _ => None,
        }
    }

    pub(crate) fn selected(&self) -> Option<LinkageItem> {
        self.selected.filter(|_| self.prepared().is_some())
    }

    pub(crate) fn select(&mut self, item: LinkageItem) {
        self.selected = Some(item);
    }

    /// The next page to request from worker `epoch`, if one is owed.
    pub(crate) fn request(&self, generation: u64, epoch: u64) -> Option<Request> {
        let State::Fetching {
            epoch: expected,
            fetch,
        } = &self.state
        else {
            return None;
        };
        if self.generation != generation || *expected != epoch {
            return None;
        }
        match fetch {
            None => Some(Request::Linkage {
                cursor: 0,
                digest: None,
            }),
            Some(fetch) => fetch.cursor().map(|cursor| Request::Linkage {
                cursor,
                digest: Some(fetch.summary().digest.clone()),
            }),
        }
    }

    /// Validates one reply to `Request::Linkage { cursor, digest }`. Replies
    /// for another generation, epoch, cursor or digest are stale. An error
    /// means the current reply was defective; nothing was adopted.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn receive(
        &mut self,
        generation: u64,
        epoch: u64,
        cursor: usize,
        digest: Option<&str>,
        summary: LinkageSummary,
        page: LinkagePage,
        info: &BinaryInfo,
    ) -> Result<Received, String> {
        let State::Fetching {
            epoch: expected,
            fetch,
        } = &mut self.state
        else {
            return Ok(Received::Stale);
        };
        if self.generation != generation || *expected != epoch {
            return Ok(Received::Stale);
        }
        let current = match fetch {
            None => cursor == 0 && digest.is_none(),
            Some(fetch) => {
                fetch.cursor() == Some(cursor) && digest == Some(fetch.summary().digest.as_str())
            }
        };
        if !current {
            return Ok(Received::Stale);
        }
        if page.cursor != cursor {
            return Err("Linkage page answers another cursor".into());
        }
        let pages = match fetch {
            Some(pages) if *pages.summary() != summary => {
                return Err("Linkage summary changed between pages".into());
            }
            Some(pages) => pages,
            None => fetch.insert(Box::new(LinkageFetch::new(summary, &info.sha256)?)),
        };
        if pages.cursor().is_some() {
            pages.accept(page, info)?;
        } else if !page.entries.is_empty()
            || page.next.is_some()
            || page.digest != pages.summary().digest
        {
            return Err("Linkage page does not match its empty table".into());
        }
        if pages.cursor().is_some() {
            return Ok(Received::Pending);
        }
        let complete = fetch.take().and_then(|pages| pages.finish());
        complete
            .map(Received::Complete)
            .ok_or_else(|| "Incomplete linkage table".into())
    }

    /// Groups and indexes a complete table on a background thread.
    pub(crate) fn build(&mut self, linkage: Linkage, context: &egui::Context) {
        let linkage = Arc::new(linkage);
        let (sender, receiver) = mpsc::sync_channel(1);
        let context = context.clone();
        let spawned = std::thread::Builder::new()
            .name("linkage-view".into())
            .spawn(move || {
                let prepared = PreparedLinkage::build(linkage);
                if sender.send(prepared).is_ok() {
                    context.request_repaint();
                }
            });
        self.state = match spawned {
            Ok(_) => State::Building(receiver),
            Err(_) => State::Unavailable,
        };
    }

    /// Adopts a finished background build.
    pub(crate) fn poll(&mut self) -> Polled {
        let State::Building(job) = &self.state else {
            return Polled::Idle;
        };
        match job.try_recv() {
            Ok(prepared) => {
                let bytes = prepared.retained_bytes();
                self.state = State::Ready(Box::new(prepared));
                self.rows = None;
                Polled::Ready(bytes)
            }
            Err(TryRecvError::Empty) => Polled::Idle,
            Err(TryRecvError::Disconnected) => {
                self.fail();
                Polled::Failed
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn wait(&mut self) -> Polled {
        loop {
            match self.poll() {
                Polled::Idle if matches!(self.state, State::Building(_)) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                polled => return polled,
            }
        }
    }

    fn toggle(&mut self, key: GroupKey, filtering: bool) {
        let set = if filtering {
            &mut self.collapsed
        } else {
            &mut self.expanded
        };
        if !set.remove(&key) {
            set.insert(key);
        }
        self.expansion = self.expansion.wrapping_add(1);
    }

    /// Flattened rows for the current filter, labels and expansion; rebuilt
    /// only when one of them changes, never per frame.
    fn refresh_rows(&mut self, session: Option<&Session>, revision: u64, query: &str) {
        if self.collapsed_query != query {
            self.collapsed_query = query.to_owned();
            self.collapsed.clear();
            self.expansion = self.expansion.wrapping_add(1);
        }
        if self.rows.as_ref().is_some_and(|rows| {
            rows.key.query == query
                && rows.key.revision == revision
                && rows.key.expansion == self.expansion
        }) {
            return;
        }
        let key = RowsKey {
            query: query.to_owned(),
            revision,
            expansion: self.expansion,
        };
        let State::Ready(prepared) = &self.state else {
            self.rows = None;
            return;
        };
        self.rows = Some(flatten(
            prepared,
            session,
            key,
            &self.expanded,
            &self.collapsed,
        ));
    }

    #[cfg(test)]
    fn visible_rows(&mut self, session: Option<&Session>, query: &str) -> (Vec<Row>, Vec<u32>) {
        self.refresh_rows(session, 0, query);
        self.rows
            .as_ref()
            .map(|rows| (rows.imports.clone(), rows.exports.clone()))
            .unwrap_or_default()
    }
}

/// Lowercase query matching over cached keys, labels and exact addresses.
struct Matcher<'a> {
    query: &'a str,
    hex: bool,
    buffer: String,
}

impl Matcher<'_> {
    fn matches(&mut self, key: &str, label: Option<&str>, address: Option<u64>) -> bool {
        self.query.is_empty()
            || key.contains(self.query)
            || label.is_some_and(|label| label.to_lowercase().contains(self.query))
            || self.hex
                && address.is_some_and(|address| {
                    self.buffer.clear();
                    let _ = write!(self.buffer, "{address:x}");
                    self.buffer.contains(self.query)
                })
    }
}

fn flatten(
    prepared: &PreparedLinkage,
    session: Option<&Session>,
    key: RowsKey,
    expanded: &BTreeSet<GroupKey>,
    collapsed: &BTreeSet<GroupKey>,
) -> Rows {
    let linkage = prepared.linkage();
    let query = key.query.as_str();
    let filtering = !query.is_empty();
    let mut matcher = Matcher {
        query,
        hex: filtering && query.bytes().all(|b| b.is_ascii_hexdigit()),
        buffer: String::with_capacity(16),
    };
    let mut imports = Vec::new();
    let mut group_counts = Vec::with_capacity(prepared.view.groups.len());
    let mut import_matches = 0usize;
    for (index, group) in prepared.view.groups.iter().enumerate() {
        let whole = filtering && prepared.group_keys[index].contains(query);
        let open = if filtering {
            !collapsed.contains(&group.key)
        } else {
            expanded.contains(&group.key)
        };
        let start = imports.len();
        imports.push(Row::Group(index as u32));
        let mut shown = 0u32;
        for &id in &group.members {
            let import = &linkage.imports[id as usize];
            let address = import_address(import);
            if !whole
                && !matcher.matches(
                    &prepared.import_keys[id as usize],
                    label_at(session, address),
                    address,
                )
            {
                continue;
            }
            shown += 1;
            if open {
                imports.push(Row::Import(id));
                let first = linkage
                    .locations
                    .partition_point(|location| location.import < id);
                imports.extend(
                    linkage.locations[first..]
                        .iter()
                        .take_while(|location| location.import == id)
                        .enumerate()
                        .map(|(offset, _)| Row::Location((first + offset) as u32)),
                );
            }
        }
        if filtering && shown == 0 {
            imports.truncate(start);
        }
        group_counts.push(shown);
        import_matches += shown as usize;
    }
    let exports = prepared
        .view
        .exports
        .iter()
        .copied()
        .filter(|&id| {
            let export = &linkage.exports[id as usize];
            let address = export.target.address();
            matcher.matches(
                &prepared.export_keys[id as usize],
                label_at(session, address),
                address,
            )
        })
        .collect();
    Rows {
        key,
        imports,
        exports,
        group_counts,
        import_matches,
    }
}

fn import_hover(ui: &mut egui::Ui, linkage: &Linkage, import: &Import) {
    let library = match (import.library, import.scope) {
        (Some(library), _) => linkage.libraries[library as usize].name.as_str(),
        (None, Some(scope)) => scope.label(),
        (None, None) => "Unknown library",
    };
    ui.label(RichText::new(raw_text(&import.raw, import.ordinal)).monospace());
    let mut facts = vec![Cow::Borrowed(library)];
    if let Some(version) = &import.version {
        facts.push(Cow::Borrowed(version));
    }
    if let (Some(ordinal), Some(_)) = (import.ordinal, &import.raw) {
        facts.push(Cow::Owned(format!("ordinal {ordinal}")));
    }
    if import.kind == ImportKind::Delay {
        facts.push(Cow::Borrowed("delay"));
    }
    if import.weak {
        facts.push(Cow::Borrowed("weak"));
    }
    ui.weak(facts.join(" · "));
    let mut addresses = Vec::new();
    if let Some(stub) = import.stub {
        addresses.push(format!("stub {stub:x}"));
    }
    if let Some(slot) = import.slot {
        addresses.push(format!("slot {slot:x}"));
    }
    if !addresses.is_empty() {
        ui.weak(addresses.join(" · "));
    }
}

fn export_hover(ui: &mut egui::Ui, export: &Export) {
    ui.label(RichText::new(raw_text(&export.raw, export.ordinal)).monospace());
    let mut facts = Vec::new();
    if let (Some(ordinal), Some(_)) = (export.ordinal, &export.raw) {
        facts.push(format!("ordinal {ordinal}"));
    }
    if let Some(version) = &export.version {
        facts.push(version.clone());
    }
    facts.push(match &export.target {
        ExportTarget::Code { address } => format!("code {address:x}"),
        ExportTarget::Resolver { address } => format!("resolver {address:x}"),
        ExportTarget::Data { address } => format!("data {address:x}"),
        ExportTarget::Forwarder { target } => format!("→ {target}"),
        ExportTarget::Unresolved => "unresolved".into(),
    });
    ui.weak(facts.join(" · "));
}

fn raw_text(raw: &Option<String>, ordinal: Option<u32>) -> Cow<'_, str> {
    match (raw, ordinal) {
        (Some(raw), _) => Cow::Borrowed(raw),
        (None, Some(ordinal)) => Cow::Owned(format!("ordinal {ordinal}")),
        (None, None) => Cow::Borrowed("?"),
    }
}

fn place_label(place: Place, stub: bool) -> String {
    match place {
        Place::Code(address) if stub => format!("Go to stub {address:x}"),
        Place::Code(address) => format!("Go to {address:x}"),
        Place::Data { address, length } if length > 1 => format!("Go to slot {address:x}"),
        Place::Data { address, .. } => format!("Go to {address:x}"),
    }
}

/// A row's secondary-click menu: every exact location, then Xrefs.
fn row_menu(
    response: &egui::Response,
    item: LinkageItem,
    places: impl FnOnce() -> Vec<Place>,
    action: &mut Option<TreeAction>,
) {
    response.context_menu(|ui| {
        let places = places();
        let stub = matches!(item, LinkageItem::Import(_) | LinkageItem::Location(_));
        for place in &places {
            if ui.button(place_label(*place, stub)).clicked() {
                *action = Some(TreeAction::OpenPlace(item, *place));
                ui.close();
            }
        }
        if ui
            .add_enabled(!places.is_empty(), egui::Button::new("Xrefs to…"))
            .clicked()
        {
            *action = Some(TreeAction::Xrefs(item));
            ui.close();
        }
    });
}

fn click_action(response: &egui::Response, item: LinkageItem) -> Option<TreeAction> {
    if response.double_clicked() {
        Some(TreeAction::Open(item))
    } else if response.clicked() {
        Some(TreeAction::Select(item))
    } else {
        None
    }
}

/// A category header with its count and a terse state.
fn header_text(
    ui: &egui::Ui,
    title: &str,
    count: Option<(usize, usize)>,
    state: Option<(&str, egui::Color32)>,
) -> egui::text::LayoutJob {
    let font = egui::TextStyle::Button.resolve(ui.style());
    let mut job = egui::text::LayoutJob::default();
    let mut text = title.to_owned();
    match count {
        Some((shown, total)) if shown != total => {
            let _ = write!(text, " ({shown}/{total})");
        }
        Some((_, total)) => {
            let _ = write!(text, " ({total})");
        }
        None => {}
    }
    job.append(
        &text,
        0.0,
        egui::TextFormat::simple(font.clone(), egui::Color32::PLACEHOLDER),
    );
    if let Some((state, color)) = state {
        job.append(state, 8.0, egui::TextFormat::simple(font, color));
    }
    job
}

impl LinkageTree {
    /// Imports and Exports categories. `query` is the lowercased function
    /// filter; `revision` changes whenever analyst labels may have changed.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        session: Option<&Session>,
        revision: u64,
        query: &str,
        worker: bool,
        pointer: u64,
    ) -> Option<TreeAction> {
        self.refresh_rows(session, revision, query);
        let loading = match &self.state {
            State::Fetching { .. } => worker,
            State::Building(_) => true,
            _ => false,
        };
        let state = match self.status() {
            Status::Loading if loading => Some(("Loading", theme::MUTED)),
            Status::Unavailable => Some(("Unavailable", theme::MUTED)),
            Status::Ready if self.prepared().is_some_and(|p| p.linkage().partial()) => {
                Some(("Partial", theme::WARNING))
            }
            _ => None,
        };
        let partial = state.is_some_and(|(text, _)| text == "Partial");
        let (import_count, export_count) = match (self.prepared(), &self.rows) {
            (Some(prepared), Some(rows)) => (
                Some((rows.import_matches, prepared.linkage().imports.len())),
                Some((rows.exports.len(), prepared.linkage().exports.len())),
            ),
            _ => (None, None),
        };
        let mut action = None;
        let mut toggle = None;
        let filtering = !query.is_empty();
        let header = egui::CollapsingHeader::new(header_text(ui, "Imports", import_count, state))
            .id_salt("tree-imports")
            .show(ui, |ui| {
                self.import_list(ui, session, pointer, &mut action, &mut toggle)
            });
        if partial && let Some(prepared) = self.prepared() {
            header.header_response.on_hover_ui(|ui| {
                for gap in &prepared.linkage().gaps {
                    ui.label(gap.label());
                }
            });
        }
        let header = egui::CollapsingHeader::new(header_text(ui, "Exports", export_count, state))
            .id_salt("tree-exports")
            .show(ui, |ui| self.export_list(ui, session, pointer, &mut action));
        if partial && let Some(prepared) = self.prepared() {
            header.header_response.on_hover_ui(|ui| {
                for gap in &prepared.linkage().gaps {
                    ui.label(gap.label());
                }
            });
        }
        if let Some(key) = toggle {
            self.toggle(key, filtering);
        }
        action
    }

    fn import_list(
        &self,
        ui: &mut egui::Ui,
        session: Option<&Session>,
        pointer: u64,
        action: &mut Option<TreeAction>,
        toggle: &mut Option<GroupKey>,
    ) {
        let (Some(prepared), Some(rows)) = (self.prepared(), &self.rows) else {
            return;
        };
        if rows.imports.is_empty() {
            ui.weak("None");
            return;
        }
        let linkage = prepared.linkage();
        let filtering = !rows.key.query.is_empty();
        let count = rows.imports.len();
        let height = (count as f32 * theme::ROW_HEIGHT).min(LIST_HEIGHT);
        ui.allocate_ui(egui::vec2(ui.available_width(), height), |ui| {
            theme::rows::<()>(
                ui,
                "tree-import-rows",
                count,
                theme::ROW_HEIGHT,
                0.0,
                None,
                |ui, row, rect| {
                    match rows.imports[row] {
                        Row::Group(index) => {
                            let group = &prepared.view.groups[index as usize];
                            let open = if filtering {
                                !self.collapsed.contains(&group.key)
                            } else {
                                self.expanded.contains(&group.key)
                            };
                            let response = theme::row_response(
                                ui,
                                ui.scope_id().with(("linkage-group", index)),
                                rect,
                                false,
                                false,
                            );
                            paint_disclosure(ui, rect, open);
                            theme::cell_text(
                                ui,
                                rect.with_min_x(rect.left() + INDENT),
                                body(format!(
                                    "{} ({})",
                                    group.label, rows.group_counts[index as usize]
                                )),
                                theme::TEXT,
                            );
                            if response.clicked() {
                                *toggle = Some(group.key);
                            }
                        }
                        Row::Import(id) => {
                            let import = &linkage.imports[id as usize];
                            let item = LinkageItem::Import(id);
                            let response = theme::row_response(
                                ui,
                                ui.scope_id().with(("linkage-import", id)),
                                rect,
                                self.selected == Some(item),
                                false,
                            );
                            let name = shown_name(
                                label_at(session, import_address(import)),
                                &import.raw,
                                &import.display,
                                import.ordinal,
                            );
                            theme::cell_text(
                                ui,
                                rect.with_min_x(rect.left() + INDENT),
                                body(name),
                                theme::TEXT,
                            );
                            if let Some(chosen) = click_action(&response, item) {
                                *action = Some(chosen);
                            }
                            row_menu(&response, item, || places(linkage, item, pointer), action);
                            response.on_hover_ui(|ui| import_hover(ui, linkage, import));
                        }
                        Row::Location(index) => {
                            let location = &linkage.locations[index as usize];
                            let item = LinkageItem::Location(index);
                            let response = theme::row_response(
                                ui,
                                ui.scope_id().with(("linkage-location", index)),
                                rect,
                                self.selected == Some(item),
                                false,
                            );
                            let kind = match location.kind {
                                LocationKind::Stub => "stub",
                                LocationKind::Slot => "slot",
                            };
                            theme::cell_text(
                                ui,
                                rect.with_min_x(rect.left() + 2.0 * INDENT),
                                format!("{kind} {:x}", location.address),
                                theme::MUTED,
                            );
                            if let Some(chosen) = click_action(&response, item) {
                                *action = Some(chosen);
                            }
                            row_menu(&response, item, || places(linkage, item, pointer), action);
                        }
                    }
                    None
                },
            );
        });
    }

    fn export_list(
        &self,
        ui: &mut egui::Ui,
        session: Option<&Session>,
        pointer: u64,
        action: &mut Option<TreeAction>,
    ) {
        let (Some(prepared), Some(rows)) = (self.prepared(), &self.rows) else {
            return;
        };
        if rows.exports.is_empty() {
            ui.weak("None");
            return;
        }
        let linkage = prepared.linkage();
        let count = rows.exports.len();
        let height = (count as f32 * theme::ROW_HEIGHT).min(LIST_HEIGHT);
        ui.allocate_ui(egui::vec2(ui.available_width(), height), |ui| {
            theme::rows::<()>(
                ui,
                "tree-export-rows",
                count,
                theme::ROW_HEIGHT,
                0.0,
                None,
                |ui, row, rect| {
                    let id = rows.exports[row];
                    let export = &linkage.exports[id as usize];
                    let item = LinkageItem::Export(id);
                    let response = theme::row_response(
                        ui,
                        ui.scope_id().with(("linkage-export", id)),
                        rect,
                        self.selected == Some(item),
                        false,
                    );
                    let name = shown_name(
                        label_at(session, export.target.address()),
                        &export.raw,
                        &export.display,
                        export.ordinal,
                    );
                    let color = if export.target.address().is_some() {
                        theme::TEXT
                    } else {
                        theme::MUTED
                    };
                    theme::cell_text(ui, rect, body(name), color);
                    if let Some(chosen) = click_action(&response, item) {
                        *action = Some(chosen);
                    }
                    row_menu(&response, item, || places(linkage, item, pointer), action);
                    response.on_hover_ui(|ui| export_hover(ui, export));
                    None
                },
            );
        });
    }
}

/// The collapsing-header triangle, painted font-independently.
/// Names use the body font of the neighbouring tree rows; addresses stay
/// monospace.
fn body(text: impl Into<String>) -> RichText {
    RichText::new(text).text_style(egui::TextStyle::Body)
}

fn paint_disclosure(ui: &egui::Ui, rect: egui::Rect, open: bool) {
    if !ui.is_rect_visible(rect) {
        return;
    }
    let center = egui::pos2(rect.left() + INDENT / 2.0 + 2.0, rect.center().y);
    let size = 3.5;
    let points = if open {
        vec![
            center + egui::vec2(-size, -size / 2.0),
            center + egui::vec2(size, -size / 2.0),
            center + egui::vec2(0.0, size),
        ]
    } else {
        vec![
            center + egui::vec2(-size / 2.0, -size),
            center + egui::vec2(size, 0.0),
            center + egui::vec2(-size / 2.0, size),
        ]
    };
    ui.painter().add(egui::Shape::convex_polygon(
        points,
        theme::MUTED,
        egui::Stroke::NONE,
    ));
}

/// Small original tables shared by these tests and the desktop's.
#[cfg(test)]
pub(crate) mod fixture {
    use crate::linkage::{
        Export, ExportTarget, Import, ImportKind, Library, LinkageGap, LinkageRecord, LinkageTable,
        Location, LocationKind,
    };
    use crate::model::{BinaryInfo, FunctionInfo, SectionInfo};

    pub(crate) const STUB: u64 = 0x1010;
    pub(crate) const SLOT: u64 = 0x2000;
    pub(crate) const SLOT_ONLY: u64 = 0x2008;
    pub(crate) const CODE_EXPORT: u64 = 0x1020;
    pub(crate) const DATA_EXPORT: u64 = 0x2040;
    pub(crate) const ZERO_FILL: u64 = 0x20f0;

    pub(crate) fn info(sha256: &str) -> BinaryInfo {
        BinaryInfo {
            path: "fixture".into(),
            architecture: "x86-64".into(),
            format: "PE".into(),
            entry: 0x1000,
            file_len: 0x400,
            sha256: sha256.into(),
            source_identity: None,
            sections: vec![
                SectionInfo {
                    name: ".text".into(),
                    address: 0x1000,
                    size: 0x100,
                    file_offset: 0,
                    file_size: 0x100,
                    executable: true,
                },
                SectionInfo {
                    name: ".data".into(),
                    address: 0x2000,
                    size: 0x100,
                    file_offset: 0x100,
                    file_size: 0x80,
                    executable: false,
                },
            ],
            functions: vec![
                FunctionInfo {
                    address: 0x1000,
                    name: "entry".into(),
                },
                FunctionInfo {
                    address: STUB,
                    name: "thunk_Shared".into(),
                },
                FunctionInfo {
                    address: CODE_EXPORT,
                    name: "code_export".into(),
                },
            ],
            functions_truncated: false,
            warnings: Vec::new(),
        }
    }

    pub(crate) fn import(id: u32, raw: Option<&str>, library: Option<u32>) -> Import {
        Import {
            id,
            raw: raw.map(Into::into),
            display: None,
            ordinal: None,
            library,
            scope: None,
            version: None,
            kind: ImportKind::Normal,
            weak: false,
            slot: None,
            stub: None,
        }
    }

    fn export(id: u32, raw: Option<&str>, target: ExportTarget) -> Export {
        Export {
            id,
            raw: raw.map(Into::into),
            display: None,
            ordinal: None,
            version: None,
            target,
        }
    }

    /// Equal names in two DLLs, a demangled delay import, an ordinal-only
    /// import of no known library, every export target kind and further
    /// locations of one import.
    pub(crate) fn table(sha256: &str, gaps: Vec<LinkageGap>) -> LinkageTable {
        let mut records = vec![
            LinkageRecord::Library(Library {
                id: 0,
                name: "USER32.dll".into(),
            }),
            LinkageRecord::Library(Library {
                id: 1,
                name: "KERNEL32.dll".into(),
            }),
        ];
        let mut shared = import(0, Some("Shared"), Some(1));
        shared.slot = Some(SLOT);
        shared.stub = Some(STUB);
        let mut slot_only = import(1, Some("Shared"), Some(0));
        slot_only.slot = Some(SLOT_ONLY);
        let mut delay = import(2, Some("?fn@@YAXXZ"), Some(1));
        delay.display = Some("fn".into());
        delay.ordinal = Some(7);
        delay.kind = ImportKind::Delay;
        delay.slot = Some(0x2010);
        let mut ordinal = import(3, None, None);
        ordinal.ordinal = Some(42);
        ordinal.weak = true;
        ordinal.slot = Some(0x2018);
        records.extend([shared, slot_only, delay, ordinal].map(LinkageRecord::Import));
        let mut unresolved = export(3, None, ExportTarget::Unresolved);
        unresolved.ordinal = Some(9);
        records.extend(
            [
                export(
                    0,
                    Some("code_export"),
                    ExportTarget::Code {
                        address: CODE_EXPORT,
                    },
                ),
                export(
                    1,
                    Some("data_export"),
                    ExportTarget::Data {
                        address: DATA_EXPORT,
                    },
                ),
                export(
                    2,
                    Some("forwarded"),
                    ExportTarget::Forwarder {
                        target: "OTHER.Func".into(),
                    },
                ),
                unresolved,
                export(
                    4,
                    Some("zero_fill"),
                    ExportTarget::Data { address: ZERO_FILL },
                ),
            ]
            .map(LinkageRecord::Export),
        );
        records.extend(
            [(LocationKind::Stub, 0x1030), (LocationKind::Slot, 0x2020)].map(|(kind, address)| {
                LinkageRecord::Location(Location {
                    import: 0,
                    kind,
                    address,
                })
            }),
        );
        LinkageTable::new(records, gaps).with_image(sha256)
    }

    /// Serves `table` to `tree` like a worker, page by page.
    pub(crate) fn fetch(
        tree: &mut super::LinkageTree,
        table: &LinkageTable,
        info: &BinaryInfo,
        generation: u64,
        epoch: u64,
    ) -> Option<crate::linkage::Linkage> {
        while let Some(crate::model::Request::Linkage { cursor, digest }) =
            tree.request(generation, epoch)
        {
            let page = table.page(cursor).unwrap();
            match tree
                .receive(
                    generation,
                    epoch,
                    cursor,
                    digest.as_deref(),
                    table.summary().clone(),
                    page,
                    info,
                )
                .unwrap()
            {
                super::Received::Complete(linkage) => return Some(linkage),
                super::Received::Pending => {}
                super::Received::Stale => return None,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{self, *};
    use super::*;
    use crate::linkage::{LinkageGap, LinkageRecord, LinkageTable};
    use crate::session::Annotation;

    const SHA: &str = "ab";

    fn sha() -> String {
        SHA.repeat(32)
    }

    fn ready(gaps: Vec<LinkageGap>) -> LinkageTree {
        let info = fixture::info(&sha());
        let mut tree = LinkageTree::default();
        tree.begin(1, 1);
        let linkage = fixture::fetch(&mut tree, &fixture::table(&sha(), gaps), &info, 1, 1)
            .expect("complete table");
        tree.build(linkage, &egui::Context::default());
        assert!(matches!(tree.wait(), Polled::Ready(bytes) if bytes > 0));
        tree
    }

    fn group_labels(tree: &LinkageTree, rows: &[Row]) -> Vec<String> {
        let prepared = tree.prepared().unwrap();
        rows.iter()
            .map(|row| match *row {
                Row::Group(index) => format!("[{}]", prepared.view.groups[index as usize].label),
                Row::Import(id) => format!("import {id}"),
                Row::Location(index) => format!("location {index}"),
            })
            .collect()
    }

    #[test]
    fn equal_names_in_different_libraries_are_distinct_rows_under_their_own_groups() {
        let mut tree = ready(Vec::new());
        let (rows, exports) = tree.visible_rows(None, "");
        // Collapsed by default: libraries alphabetically, then unknown.
        assert_eq!(
            group_labels(&tree, &rows),
            ["[KERNEL32.dll]", "[USER32.dll]", "[Unknown library]"]
        );
        assert_eq!(exports.len(), 5);
        for group in tree.prepared().unwrap().view.groups.clone_keys() {
            tree.toggle(group, false);
        }
        let (rows, _) = tree.visible_rows(None, "");
        assert_eq!(
            group_labels(&tree, &rows),
            [
                "[KERNEL32.dll]",
                "import 2",
                "import 0",
                "location 0",
                "location 1",
                "[USER32.dll]",
                "import 1",
                "[Unknown library]",
                "import 3",
            ]
        );
        // Same declared text, different identities and destinations.
        let linkage = tree.prepared().unwrap().linkage();
        assert_eq!(
            destination(linkage, LinkageItem::Import(0), 8),
            Some(Place::Code(STUB))
        );
        assert_eq!(
            destination(linkage, LinkageItem::Import(1), 8),
            Some(Place::Data {
                address: SLOT_ONLY,
                length: 8
            })
        );
        // The same name filter finds both, each in its own library.
        let (rows, _) = tree.visible_rows(None, "shared");
        assert_eq!(
            group_labels(&tree, &rows),
            [
                "[KERNEL32.dll]",
                "import 0",
                "location 0",
                "location 1",
                "[USER32.dll]",
                "import 1"
            ]
        );
    }

    trait GroupKeys {
        fn clone_keys(&self) -> Vec<GroupKey>;
    }

    impl GroupKeys for Box<[crate::linkage::ImportGroup]> {
        fn clone_keys(&self) -> Vec<GroupKey> {
            self.iter().map(|group| group.key).collect()
        }
    }

    #[test]
    fn names_prefer_analyst_labels_then_display_raw_and_ordinal() {
        let tree = ready(Vec::new());
        let linkage = tree.prepared().unwrap().linkage();
        let shown = |session: Option<&Session>, id: usize| {
            let import = &linkage.imports[id];
            shown_name(
                label_at(session, import_address(import)),
                &import.raw,
                &import.display,
                import.ordinal,
            )
            .into_owned()
        };
        assert_eq!(shown(None, 2), "fn");
        assert_eq!(shown(None, 0), "Shared");
        assert_eq!(shown(None, 3), "ordinal 42");
        let mut session = Session::new(sha());
        // A label at the stub names the import; an empty label does not.
        session.annotations.insert(
            STUB,
            Annotation {
                label: "analyst_shared".into(),
                ..Annotation::default()
            },
        );
        session.annotations.insert(0x2010, Annotation::default());
        assert_eq!(shown(Some(&session), 0), "analyst_shared");
        assert_eq!(shown(Some(&session), 2), "fn");
        // Order stays on declared text, and filters see the label too.
        let mut tree = tree;
        let (rows, _) = tree.visible_rows(Some(&session), "analyst");
        assert_eq!(
            group_labels(&tree, &rows),
            ["[KERNEL32.dll]", "import 0", "location 0", "location 1"]
        );
        let (rows, _) = tree.visible_rows(Some(&session), "yaxxz");
        assert_eq!(group_labels(&tree, &rows), ["[KERNEL32.dll]", "import 2"]);
        let (_, exports) = tree.visible_rows(None, "ordinal 9");
        assert_eq!(exports, [3]);
    }

    #[test]
    fn forwarders_unresolved_and_zero_never_navigate_and_data_opens_bytes() {
        let tree = ready(Vec::new());
        let linkage = tree.prepared().unwrap().linkage();
        for id in [2, 3] {
            assert_eq!(destination(linkage, LinkageItem::Export(id), 8), None);
            assert!(places(linkage, LinkageItem::Export(id), 8).is_empty());
        }
        assert_eq!(
            destination(linkage, LinkageItem::Export(0), 8),
            Some(Place::Code(CODE_EXPORT))
        );
        // Data is inspected as bytes, including zero-fill; never as code.
        for (id, address) in [(1, DATA_EXPORT), (4, ZERO_FILL)] {
            assert_eq!(
                destination(linkage, LinkageItem::Export(id), 8),
                Some(Place::Data { address, length: 1 })
            );
        }
        let mut zero = Linkage::default();
        let mut import = fixture::import(0, Some("zero"), None);
        import.slot = Some(0);
        zero.imports = vec![import].into_boxed_slice();
        zero.exports = vec![Export {
            id: 0,
            raw: Some("zero".into()),
            display: None,
            ordinal: None,
            version: None,
            target: ExportTarget::Code { address: 0 },
        }]
        .into_boxed_slice();
        for item in [LinkageItem::Import(0), LinkageItem::Export(0)] {
            assert_eq!(destination(&zero, item, 8), None);
        }
    }

    #[test]
    fn every_verified_location_is_an_explicit_choice() {
        let tree = ready(Vec::new());
        let linkage = tree.prepared().unwrap().linkage();
        assert_eq!(
            places(linkage, LinkageItem::Import(0), 8),
            [
                Place::Code(STUB),
                Place::Data {
                    address: SLOT,
                    length: 8
                },
                Place::Code(0x1030),
                Place::Data {
                    address: 0x2020,
                    length: 8
                },
            ]
        );
        assert_eq!(
            places(linkage, LinkageItem::Location(1), 8),
            [Place::Data {
                address: 0x2020,
                length: 8
            }]
        );
    }

    #[test]
    fn late_stale_and_defective_pages_never_adopt_and_restart_cleanly() {
        let info = fixture::info(&sha());
        let table = fixture::table(&sha(), Vec::new());
        let page = || table.page(0).unwrap();
        let summary = || table.summary().clone();
        let mut tree = LinkageTree::default();
        tree.begin(1, 1);
        // Another epoch, generation, cursor or digest is dropped.
        for (generation, epoch, cursor, digest) in [
            (1, 2, 0, None),
            (2, 1, 0, None),
            (1, 1, 1, None),
            (1, 1, 0, Some("f")),
        ] {
            let received = tree
                .receive(generation, epoch, cursor, digest, summary(), page(), &info)
                .unwrap();
            assert!(matches!(received, Received::Stale));
        }
        assert_eq!(tree.status(), Status::Loading);
        // A defective current page fails closed with nothing adopted.
        let mut tampered = page();
        if let LinkageRecord::Library(library) = &mut tampered.entries[0] {
            library.name = "EVIL.dll".into();
        }
        assert!(
            tree.receive(1, 1, 0, None, summary(), tampered, &info)
                .is_err()
        );
        // A worker restart discards nothing adopted but restarts the fetch.
        tree.interrupt();
        tree.begin(1, 2);
        assert!(matches!(
            tree.request(1, 2),
            Some(Request::Linkage {
                cursor: 0,
                digest: None
            })
        ));
        assert!(tree.request(1, 1).is_none());
        let linkage = fixture::fetch(&mut tree, &table, &info, 1, 2).unwrap();
        // A late page after completion or after a new binary is stale.
        tree.build(linkage, &egui::Context::default());
        let received = tree
            .receive(1, 2, 0, None, summary(), page(), &info)
            .unwrap();
        assert!(matches!(received, Received::Stale));
        tree.reset();
        tree.begin(2, 2);
        let received = tree
            .receive(1, 2, 0, None, summary(), page(), &info)
            .unwrap();
        assert!(matches!(received, Received::Stale));
        // The summary is bound to the displayed image.
        let other = fixture::table(&"cd".repeat(32), Vec::new());
        assert!(
            tree.receive(
                2,
                2,
                0,
                None,
                other.summary().clone(),
                other.page(0).unwrap(),
                &info
            )
            .is_err()
        );
        // An empty table completes from its only, empty page.
        let empty = LinkageTable::new(Vec::new(), Vec::new()).with_image(&sha());
        tree.reset();
        tree.begin(3, 1);
        let complete = fixture::fetch(&mut tree, &empty, &info, 3, 1).unwrap();
        assert!(complete.imports.is_empty() && complete.exports.is_empty());
    }

    #[test]
    fn filters_large_tables_by_name_library_and_address_without_rows_for_misses() {
        let info = fixture::info(&sha());
        let mut records = vec![LinkageRecord::Library(crate::linkage::Library {
            id: 0,
            name: "big.dll".into(),
        })];
        let imports = crate::linkage::MAX_IMPORTS as u32;
        records.extend((0..imports).map(|id| {
            LinkageRecord::Import(fixture::import(
                id,
                Some(&format!("import_{id:05}")),
                Some(0),
            ))
        }));
        let exports = crate::linkage::MAX_EXPORTS as u32;
        records.extend((0..exports).map(|id| {
            LinkageRecord::Export(Export {
                id,
                raw: Some(format!("export_{id:05}")),
                display: None,
                ordinal: Some(id),
                version: None,
                target: ExportTarget::Unresolved,
            })
        }));
        let table = LinkageTable::new(records, vec![LinkageGap::ImportLimit]).with_image(&sha());
        let mut tree = LinkageTree::default();
        tree.begin(1, 1);
        let linkage = fixture::fetch(&mut tree, &table, &info, 1, 1).unwrap();
        tree.build(linkage, &egui::Context::default());
        assert!(matches!(tree.wait(), Polled::Ready(_)));
        let (rows, exported) = tree.visible_rows(None, "");
        assert_eq!((rows.len(), exported.len()), (1, exports as usize));
        let expected = |prefix: &str, count: u32| {
            (0..count)
                .filter(|id| format!("{prefix}_{id:05}").contains("_0999"))
                .count()
        };
        let (matched_imports, matched_exports) =
            (expected("import", imports), expected("export", exports));
        assert!(matched_imports > 1 && matched_exports > 1);
        let (rows, exported) = tree.visible_rows(None, "_0999");
        assert_eq!(rows.len(), 1 + matched_imports);
        assert_eq!(exported.len(), matched_exports);
        assert_eq!(
            tree.rows.as_ref().unwrap().group_counts,
            [matched_imports as u32]
        );
        // A collapsed filtered group keeps its count and hides members.
        tree.toggle(GroupKey::Library(0), true);
        let (rows, _) = tree.visible_rows(None, "_0999");
        assert_eq!(rows, [Row::Group(0)]);
        assert_eq!(tree.rows.as_ref().unwrap().import_matches, matched_imports);
        // A new query expands matches again; the library name matches all.
        let (rows, exported) = tree.visible_rows(None, "big.dll");
        assert_eq!((rows.len(), exported.len()), (1 + imports as usize, 0));
        let (rows, exported) = tree.visible_rows(None, "no such name");
        assert!(rows.is_empty() && exported.is_empty());
        assert!(tree.prepared().unwrap().linkage().partial());
    }
}
