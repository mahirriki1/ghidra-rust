//! The Listing tab's opt-in Program scope: every section and known function
//! in address order, positioned by address rather than row index. Function
//! bodies come only from genuine views: the displayed graph, else views a
//! bounded `Request::Listing` returned. Everything else stays undefined.
//! Scope, scroll position and cached views are session-only.
//!
//! Undefined gaps also show the session's listing evidence: import slots,
//! absolute pointer-table witnesses and string candidates as `??` data rows,
//! and split marks at reference targets, data exports and annotations. The
//! index is built once per input change (binary, linkage, strings, reference
//! report, wholesale annotation replacement) and whenever the Program scope is
//! shown again, and updated in place as discovery commits witnesses and as
//! labels or comments change. Witnesses are session-only:
//! after a project reopen they return only once discovery runs again.

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use eframe::egui;

use super::{DesktopApp, MAX_HOVER_NAME, Pending, Tab, crop, hex, name_hover};
use crate::function_presentation::{Listing, PreparedGraph};
use crate::function_results::ResultBinding;
use crate::listing_evidence::{EvidenceKind, ListingEvidence};
use crate::model::{
    FunctionView, ListingBinding, ListingOutcome, MAX_LISTING_FUNCTIONS, Request, function_at,
};
use crate::program_listing::{
    AddressScale, BodySource, ByteCache, CachedBody, Expansions, ListingCache, Position,
    ProgramRows, Rank, Row,
};
use crate::result_store::{ProgramContext, Stored};
use crate::theme;

/// Rows materialized before the anchor, and the most in one window.
const WINDOW_BEFORE: usize = 128;
const WINDOW_ROWS: usize = 512;
const WINDOW_MARGIN: usize = 32;
/// Functions prefetched beyond the viewport in the scroll direction.
const PREFETCH: usize = 8;
const ADDRESS_BAR_WIDTH: f32 = 12.0;
/// How long a granted Listing turn may hold discovery while it waits for the
/// batch's context, the displayed function or user requests.
const LISTING_TURN_WAIT: Duration = Duration::from_secs(1);
/// A turn never holds discovery longer than this after its batch committed.
const LISTING_TURN_CAP: Duration = Duration::from_secs(3);
/// Failed Listing requests one binary generation tolerates.
const MAX_LISTING_FAILURES: u8 = 8;

/// A granted discovery turn; its wait starts once a request could go.
#[derive(Clone, Copy, Debug)]
struct Turn {
    granted: Instant,
    ready: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum ListingScope {
    #[default]
    Function,
    Program,
}

/// A one-shot request to bring an address into view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reveal {
    /// A function entry: its header row.
    Entry(u64),
    /// The body row covering an exact address.
    Address(u64),
    /// Exactly this row, else the row covering its address.
    Row(Position),
}

/// Inputs of the derived rows; any change rebuilds them.
#[derive(Clone, Debug)]
struct RowsKey {
    generation: u64,
    cache: u64,
    graph: Option<Weak<Stored<PreparedGraph>>>,
}

impl PartialEq for RowsKey {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.cache == other.cache
            && match (&self.graph, &other.graph) {
                (Some(a), Some(b)) => Weak::ptr_eq(a, b),
                (None, None) => true,
                _ => false,
            }
    }
}

/// Inputs of one materialized window of rows. The anchor may move within a
/// window while it stays [`WINDOW_MARGIN`] rows from either materialized edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowKey {
    rows: u64,
    inventory: (u64, usize, usize, u64, u64),
    expansions: u64,
    evidence: u64,
    anchor: Option<u64>,
    after: usize,
}

/// Inputs the evidence index was built from; any change rebuilds it.
/// Discovery witnesses and the same run's extended references update it in
/// place and move the key along; single label or comment edits update it in
/// place without touching the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EvidenceKey {
    generation: u64,
    linkage: u64,
    strings: u64,
    references: u64,
    annotations: u64,
}

/// The session's listing evidence, empty until the Program scope shows it.
#[derive(Default)]
pub(super) struct Evidence {
    key: Option<EvidenceKey>,
    pub(super) index: ListingEvidence,
    /// Data exports by address, for the names their split marks show.
    exports: std::collections::BTreeMap<u64, u32>,
    /// Advances when the session's annotations are replaced wholesale.
    annotations: u64,
    /// Advances on every change, invalidating materialized rows.
    pub(super) epoch: u64,
    /// Full builds this session, for tests of the incremental paths.
    #[cfg(test)]
    pub(super) builds: u64,
}

struct Window {
    key: WindowKey,
    rows: Vec<Row>,
    top: usize,
    /// The first and last rows are also the model's.
    at_start: bool,
    at_end: bool,
}

#[derive(Default)]
pub(super) struct ProgramPane {
    pub(super) scope: ListingScope,
    pub(super) cache: ListingCache,
    pub(super) reveal: Option<Reveal>,
    /// Context the displayed graph was computed under, when known.
    pub(super) graph_context: Option<Arc<ProgramContext>>,
    rows: Option<(RowsKey, ProgramRows, AddressScale)>,
    pub(super) rows_serial: u64,
    window: Option<Window>,
    pub(super) top: Option<Position>,
    offset: f32,
    /// The last reveal's target and its distance in points below the view's
    /// top. While set, `top` is derived from it every frame, so rows loading
    /// or appearing above it never move it; the user scrolling clears it.
    pub(super) pin: Option<(Position, f32)>,
    /// First and last rows fully shown last frame.
    pub(super) shown: Option<(Position, Position)>,
    page: usize,
    /// Visible entries lacking a current view, then prefetch candidates.
    wanted: Vec<u64>,
    prefetch: Vec<u64>,
    /// The last scroll moved toward lower addresses; prefetch follows it.
    backward: bool,
    /// Advances for every request sent; never reset within a session.
    pub(super) token: u64,
    /// The selection generation of a re-resolution that keeps the viewport:
    /// its focus adoption must not reveal.
    pub(super) quiet: Option<u64>,
    /// A `pending_listing_scroll` from such an adoption, for that generation.
    pub(super) quiet_scroll: Option<u64>,
    /// The next signature restore of the selection keeps the viewport.
    quiet_restore: bool,
    /// The one Listing turn a committed discovery batch granted.
    discovery_turn: Option<Turn>,
    /// The last pane frame ended before it could compute `wanted`.
    drawn_empty: bool,
    /// Entries of a failed multi-entry request, retried one per request in
    /// order so only an entry whose own request fails is blocked.
    isolating: std::collections::VecDeque<u64>,
    /// Failed Listing requests this binary generation; after
    /// [`MAX_LISTING_FAILURES`] the Program listing loads nothing more.
    failures: u8,
    /// Set by a failing Listing so discovery resumes without spending one
    /// of its own resumes.
    pub(super) free_resume: bool,
    /// The context `wanted` was computed under.
    wanted_context: Option<Arc<ProgramContext>>,
    /// The row the cursor stands on while `selected` is its address; it
    /// tells rows sharing that address apart.
    pub(super) cursor: Option<Position>,
    /// A follow of the cursor's function, armed by a cursor move.
    pub(super) follow: Option<super::program_cursor::Follow>,
    /// Expanded byte intervals; session-only, cleared with the binary.
    pub(super) expanded: Expansions,
    /// Bytes shown by byte rows.
    pub(super) bytes: ByteCache,
    /// Pages of byte rows in view lacking bytes (top first), and the pages
    /// of every byte row in view, as of the last pane frame.
    byte_wanted: Vec<(u64, usize)>,
    byte_visible: Vec<u64>,
    /// Data rows and split marks; session-only, cleared with the binary.
    pub(super) evidence: Evidence,
    /// The one session-only split mark a destination inside a zero-filled
    /// tail placed; it gives that address a row without reading bytes.
    pub(super) anchor: Option<u64>,
    /// A destination inside a pending body, landed once rows change.
    pub(super) landing: Option<super::listing_destinations::Landing>,
    /// Tests without a worker process let follows send as if one ran.
    #[cfg(test)]
    pub(super) assume_worker: bool,
}

impl Evidence {
    /// The session's annotations were replaced as a whole: rebuild.
    pub(super) fn replace_annotations(&mut self) {
        self.annotations = self.annotations.wrapping_add(1);
    }
}

impl ProgramPane {
    /// The derived rows, when built for binary `generation`.
    pub(super) fn current_rows(&self, generation: u64) -> Option<&ProgramRows> {
        self.rows
            .as_ref()
            .filter(|(key, ..)| key.generation == generation)
            .map(|(_, rows, _)| rows)
    }

    /// The first and last rows fully shown last frame, else the top row.
    pub(super) fn edges(&self) -> Option<(Position, Position)> {
        self.shown.or_else(|| self.top.map(|top| (top, top)))
    }

    /// A new binary or closed one: everything but the scope and token.
    pub(super) fn reset(&mut self) {
        let (scope, token) = (self.scope, self.token);
        *self = Self {
            scope,
            token: token.wrapping_add(1),
            ..Default::default()
        };
    }

    /// Where `position` was drawn last frame, in points below the view's
    /// top, when it was in the materialized window.
    fn drawn_distance(&self, position: Position) -> Option<f32> {
        let rows = &self.window.as_ref()?.rows;
        let find = |at: Position| rows.binary_search_by_key(&at, Row::position).ok();
        let below = find(position)?.checked_sub(find(self.top?)?)?;
        Some(below as f32 * theme::ROW_HEIGHT - self.offset)
    }
}

impl DesktopApp {
    pub(super) fn program_scope(&self) -> bool {
        self.program.scope == ListingScope::Program
    }

    pub(super) fn set_listing_scope(&mut self, scope: ListingScope) {
        if scope == self.program.scope {
            return;
        }
        self.program.scope = scope;
        self.listing_cursor.deactivate();
        self.program.quiet_scroll = None;
        self.program.follow = None;
        self.program.cursor = None;
        self.program.landing = None;
        if scope == ListingScope::Function {
            // Function scope never reads the cache; release its charge, and
            // drop any reply in flight.
            self.program.token = self.program.token.wrapping_add(1);
            self.program.pin = None;
            self.program.cache.clear();
            self.results.set_listing_bytes(0);
            self.program.rows = None;
            self.program.window = None;
            self.program.wanted.clear();
            self.program.prefetch.clear();
            self.program.bytes.release();
            self.program.byte_wanted.clear();
            self.program.byte_visible.clear();
            self.release_evidence();
        }
        if scope == ListingScope::Program {
            self.program.window = None;
            self.program.shown = None;
            self.program.reveal = self.selected.map(|address| {
                if self.view().is_some_and(|view| view.address == address) {
                    Reveal::Entry(address)
                } else {
                    Reveal::Address(address)
                }
            });
        }
    }

    /// The view an instruction row of `entry` comes from: the displayed
    /// graph, else (in Program scope) the cached view.
    pub(super) fn row_view(&self, entry: u64) -> Option<(&FunctionView, Listing<'_>)> {
        if let Some(graph) = self.graph.as_ref().filter(|g| g.address() == entry) {
            return Some((graph.view(), graph.listing()));
        }
        if !self.program_scope() {
            return None;
        }
        let body = self.program.cache.get(entry)?;
        Some((body.view(), body.listing()))
    }

    /// Enter / double-click destination of the row at `pc` in `entry`'s view.
    pub(super) fn row_follow_target(&self, entry: u64, pc: u64) -> Option<u64> {
        let (view, listing) = self.row_view(entry)?;
        super::listing_cursor::follow_target(view, listing, self.info.as_ref()?, pc)
    }

    /// Follows `target` from a row of `entry`; one inside that function's
    /// view opens in it.
    pub(super) fn follow_row_target(&mut self, entry: u64, target: u64, context: &egui::Context) {
        if self.view().is_some_and(|view| view.address == entry) {
            self.follow_listing_target(target, context);
            return;
        }
        let owner = self
            .row_view(entry)
            .filter(|(_, listing)| listing.contains(target))
            .map(|_| entry);
        self.navigate_location(target, owner, true, context);
    }

    /// Before the displayed graph is replaced, keep its view for the
    /// Program listing so its rows do not fall back to pending.
    pub(super) fn remember_displayed(&mut self) {
        if !self.program_scope() {
            return;
        }
        let Some(graph) = self.graph.as_ref() else {
            return;
        };
        let entry = graph.address();
        if self
            .info
            .as_ref()
            .is_none_or(|info| function_at(&info.functions, entry).is_none())
        {
            return;
        }
        // A view of known context is authoritative and replaces any cached
        // one; one of unknown context (a saved project) only fills a gap.
        let context = self.program.graph_context.clone();
        if context.is_none() && self.program.cache.get(entry).is_some() {
            return;
        }
        if let Some(body) = CachedBody::new(graph.view().clone(), context.clone()) {
            let results = &mut self.results;
            let kept = self
                .program
                .cache
                .insert(entry, body, entry, |bytes| results.set_listing_bytes(bytes));
            if !kept && let Some(context) = context {
                self.program.cache.fail(entry, context);
            }
        }
    }

    /// Rebuilds the derived rows when the cache or displayed graph changed.
    pub(super) fn program_rows_sync(&mut self) {
        let key = RowsKey {
            generation: self.generation,
            cache: self.program.cache.epoch(),
            graph: self.graph.as_ref().map(Arc::downgrade),
        };
        if self
            .program
            .rows
            .as_ref()
            .is_some_and(|(old, ..)| *old == key)
        {
            return;
        }
        let Some(info) = self.info.as_ref() else {
            self.program.rows = None;
            return;
        };
        let displayed = self.graph.as_deref();
        let bodies = displayed
            .map(|graph| BodySource {
                owner: graph.address(),
                listing: graph.listing(),
            })
            .into_iter()
            .chain(
                self.program
                    .cache
                    .bodies()
                    .filter(|(entry, _)| displayed.is_none_or(|g| g.address() != *entry))
                    .map(|(entry, body)| BodySource {
                        owner: entry,
                        listing: body.listing(),
                    }),
            );
        let rows = ProgramRows::new(&info.sections, bodies, self.program.cache.failed());
        let scale = AddressScale::new(&rows);
        self.program.rows = Some((key, rows, scale));
        self.program.rows_serial = self.program.rows_serial.wrapping_add(1);
    }

    fn evidence_key(&self) -> EvidenceKey {
        EvidenceKey {
            generation: self.generation,
            linkage: self.source_epochs.linkage,
            strings: self.source_epochs.strings,
            references: self.reference_revision,
            annotations: self.program.evidence.annotations,
        }
    }

    /// Frees the index; the Program scope rebuilds it when shown again.
    fn release_evidence(&mut self) {
        let evidence = &mut self.program.evidence;
        evidence.key = None;
        evidence.index = ListingEvidence::default();
        evidence.exports.clear();
        evidence.epoch = evidence.epoch.wrapping_add(1);
    }

    /// Builds the evidence index when an input it came from changed: the
    /// binary, the adopted linkage table, the strings, the reference report
    /// or the session (beyond the edits applied in place). Invalid section
    /// metadata leaves no evidence at all.
    pub(super) fn program_evidence_sync(&mut self) {
        let key = self.evidence_key();
        if self.program.evidence.key == Some(key) {
            return;
        }
        let _build = crate::performance::span("gui_listing_evidence_build");
        let index = self.info.as_ref().and_then(|info| {
            let admissions = self
                .discovery
                .iter()
                .flat_map(|state| state.pointer_recovery.admissions.values().copied());
            ListingEvidence::build(
                info,
                self.linkage.prepared().map(|prepared| prepared.linkage()),
                admissions,
                &self.strings,
                self.call_index.as_deref(),
                self.session.as_ref(),
            )
            .ok()
        });
        let exports = self
            .linkage
            .prepared()
            .into_iter()
            .flat_map(|prepared| {
                prepared
                    .linkage()
                    .exports
                    .iter()
                    .take(crate::linkage::MAX_EXPORTS)
            })
            .filter_map(|export| match export.target {
                crate::linkage::ExportTarget::Data { address } => Some((address, export.id)),
                _ => None,
            })
            .collect();
        let evidence = &mut self.program.evidence;
        evidence.index = index.unwrap_or_default();
        evidence.exports = exports;
        evidence.key = Some(key);
        evidence.epoch = evidence.epoch.wrapping_add(1);
        #[cfg(test)]
        {
            evidence.builds += 1;
        }
    }

    /// Whether the evidence index is built from exactly the current inputs.
    pub(super) fn program_evidence_current(&self) -> bool {
        self.program.evidence.key == Some(self.evidence_key())
    }

    /// A discovery commit extended this run: adds every committed witness
    /// and the extended reference index's targets in place. All of them, not
    /// only this batch's: a rebuild while the discovery state was away in its
    /// background commit saw none, and repeated witnesses are no-ops.
    /// `current` is whether the index matched every input before the commit;
    /// otherwise it stays stale and is rebuilt from all committed witnesses.
    pub(super) fn program_evidence_commit(&mut self, current: bool) {
        if !current {
            return;
        }
        let admissions = self
            .discovery
            .iter()
            .flat_map(|state| state.pointer_recovery.admissions.values().copied());
        let references = self.reference_revision;
        let evidence = &mut self.program.evidence;
        let Some(key) = &mut evidence.key else {
            return;
        };
        if key.references != references {
            if let Some(calls) = self.call_index.as_deref() {
                evidence.index.add_reference_marks(calls);
            }
            key.references = references;
        }
        evidence.index.add_witnesses(admissions);
        evidence.epoch = evidence.epoch.wrapping_add(1);
    }

    /// The label or comment at `address` changed. A current index updates
    /// the address's mark in place; a stale one is rebuilt anyway.
    pub(super) fn program_evidence_annotation(&mut self, address: u64) {
        if !self.program_evidence_current() {
            return;
        }
        let marked = self
            .session
            .as_ref()
            .and_then(|session| session.annotations.get(&address))
            .is_some_and(|note| !note.label.is_empty() || !note.comment.is_empty());
        let evidence = &mut self.program.evidence;
        if marked {
            evidence.index.add_mark(address);
        } else {
            evidence.index.remove_mark(address);
        }
        evidence.epoch = evidence.epoch.wrapping_add(1);
    }

    /// Data and address references to exactly `address` in the current
    /// report: the references that make it a split mark.
    fn xref_count(&self, address: u64) -> usize {
        self.call_index.as_deref().map_or(0, |calls| {
            calls.data_incoming.get(&address).map_or(0, Vec::len)
                + calls.address_incoming.get(&address).map_or(0, Vec::len)
        })
    }

    /// What a split mark at `address` shows on the row starting there: the
    /// analyst's label, else a data export's name.
    fn listing_note(&self, address: u64) -> theme::ListingNote<'_> {
        let annotation = self
            .session
            .as_ref()
            .and_then(|session| session.annotations.get(&address));
        let export = || {
            let id = *self.program.evidence.exports.get(&address)?;
            let export = self
                .linkage
                .prepared()?
                .linkage()
                .exports
                .get(id as usize)?;
            export.display.as_deref().or(export.raw.as_deref())
        };
        theme::ListingNote {
            label: annotation
                .map(|note| note.label.as_str())
                .filter(|label| !label.is_empty())
                .or_else(export),
            xrefs: self.xref_count(address),
            comment: self
                .annotation_browser
                .comments
                .get(&address)
                .map(String::as_str),
        }
    }

    /// One hover line for the split mark at `address`.
    fn mark_hover(&self, address: u64) -> String {
        let note = self.listing_note(address);
        let mut line = format!("{address:#x}");
        if let Some(label) = note.label {
            line.push_str("  ");
            line.push_str(&crop(label, MAX_HOVER_NAME));
        }
        if note.xrefs > 0 {
            line.push_str(&format!("  XREF[{}]", note.xrefs));
        }
        if let Some(comment) = note.comment {
            line.push_str("  ; ");
            line.push_str(&crop(comment, 120));
        }
        line
    }

    /// The operands evidence and hover provenance of a data row.
    fn data_row_text(&self, start: u64, end: u64, kind: EvidenceKind) -> (Option<String>, String) {
        let length = end - start;
        match kind {
            EvidenceKind::ImportSlot(id) => {
                let linkage = self.linkage.prepared().map(|prepared| prepared.linkage());
                let import = linkage.and_then(|linkage| linkage.imports.get(id as usize));
                let Some((linkage, import)) = linkage.zip(import) else {
                    return (None, format!("Import slot · {length:#x}"));
                };
                let name = crate::linkage_ui::shown_name(
                    None,
                    &import.raw,
                    &import.display,
                    import.ordinal,
                );
                let library = match (import.library, import.scope) {
                    (Some(library), _) => linkage
                        .libraries
                        .get(library as usize)
                        .map_or("Unknown library", |library| library.name.as_str()),
                    (None, Some(scope)) => scope.label(),
                    (None, None) => "Unknown library",
                };
                let mut facts = vec![crop(library, MAX_HOVER_NAME)];
                facts.push(match import.kind {
                    crate::linkage::ImportKind::Normal => "import slot".into(),
                    crate::linkage::ImportKind::Delay => "delay-load slot".into(),
                });
                if import.weak {
                    facts.push("weak".into());
                }
                let name = crop(&name, MAX_HOVER_NAME);
                (Some(name.clone()), format!("{name}\n{}", facts.join(" · ")))
            }
            EvidenceKind::Pointer { entry, .. } => {
                let names = self.function_names(entry);
                let mut hover = names.map_or_else(
                    || format!("{entry:#x}"),
                    |(name, raw)| name_hover(name, raw),
                );
                if let Some(admission) = self
                    .discovery
                    .as_ref()
                    .and_then(|state| state.admission(entry))
                {
                    hover.push_str("\n\n");
                    hover.push_str(&admission.hover_text());
                }
                (names.map(|(name, _)| crop(name, 120)), hover)
            }
            EvidenceKind::String(index) => {
                let string = self
                    .strings
                    .get(index as usize)
                    .filter(|string| string.address == start);
                let Some(string) = string else {
                    return (None, format!("String · {length:#x}"));
                };
                let origin = if self.cached_strings {
                    "saved"
                } else {
                    "scanned"
                };
                (
                    Some(crop(&string.text, 120)),
                    format!(
                        "{}\n{} · {length:#x} · {origin}",
                        crop(&string.text, 400),
                        crop(&string.encoding, 64)
                    ),
                )
            }
        }
    }

    /// Whether `entry` needs a Listing request now. A view computed under
    /// an older context is recomputed only while visible (`stale`).
    fn listing_needs(&self, entry: u64, context: &Arc<ProgramContext>, stale: bool) -> bool {
        self.result_scope != Some(entry)
            && self.view().is_none_or(|view| view.address != entry)
            && self
                .info
                .as_ref()
                .is_some_and(|info| function_at(&info.functions, entry).is_some())
            && self.program.cache.needs(entry, context)
            && (stale || self.program.cache.get(entry).is_none())
    }

    pub(super) fn program_listing_pane(&mut self, ui: &mut egui::Ui, context: &egui::Context) {
        self.program_rows_sync();
        self.program_evidence_sync();
        self.resume_landing(context);
        // Until this frame reaches its rows, nothing is in view.
        self.program.drawn_empty = true;
        self.program.wanted.clear();
        self.program.prefetch.clear();
        self.program.wanted_context = None;
        let quiet = self.program.quiet_scroll.take() == Some(self.selection_generation);
        if let Some(address) = self
            .pending_listing_scroll
            .take()
            .and_then(|row| self.listing().get(row))
            .map(|instruction| instruction.address)
            .filter(|_| !quiet)
        {
            self.program.reveal = Some(Reveal::Address(address));
        }
        let full = ui.available_rect_before_wrap();
        let ppp = ui.pixels_per_point();
        let snap = |x: f32| (x * ppp).round() / ppp;
        let header =
            egui::Rect::from_min_size(full.min, egui::vec2(full.width(), theme::ROW_HEIGHT));
        let bar_left = snap(full.right() - ADDRESS_BAR_WIDTH);
        let body = egui::Rect::from_min_max(
            egui::pos2(full.left(), snap(header.bottom())),
            egui::pos2(bar_left, full.bottom()),
        );
        let bar = egui::Rect::from_min_max(egui::pos2(bar_left, body.top()), full.max);
        ui.allocate_rect(header, egui::Sense::hover());
        let page = ((body.height() / theme::ROW_HEIGHT).floor() as usize).max(1);
        self.program.page = page;
        let Some(info) = self.info.as_ref() else {
            return;
        };
        let Some((_, rows, scale)) = self.program.rows.as_ref() else {
            return;
        };
        if rows.is_empty() {
            theme::empty_state(ui, "No sections");
            return;
        }
        let layout = rows
            .layout(&info.functions, &self.program.expanded)
            .with_evidence(&self.program.evidence.index)
            .with_anchor(self.program.anchor);
        // One-shot reveal: center only a row that is not fully shown, then
        // pin it where it is on screen.
        if let Some(reveal) = self.program.reveal.take() {
            let (target, wanted) = match reveal {
                Reveal::Entry(address) => (
                    layout.reveal(address),
                    layout
                        .reveal(address)
                        .map(|row| row.position())
                        .unwrap_or(Position::new(address, Rank::Function)),
                ),
                Reveal::Address(address) => (
                    layout.resolve(Position::new(address, Rank::Body)),
                    Position::new(address, Rank::Body),
                ),
                Reveal::Row(position) => (layout.resolve(position), position),
            };
            if let Some(target) = target {
                let position = target.position();
                let shown = self
                    .program
                    .shown
                    .is_some_and(|(first, last)| first <= position && position <= last);
                // Measured in last frame's rows from its top.
                let distance = shown
                    .then(|| self.program.drawn_distance(position))
                    .flatten();
                let distance = distance.unwrap_or_else(|| {
                    let mut row = target;
                    let mut walked = 0;
                    while walked < page / 2 {
                        match layout.previous(&row) {
                            Some(previous) => {
                                row = previous;
                                walked += 1;
                            }
                            None => break,
                        }
                    }
                    self.program.top = Some(row.position());
                    self.program.offset = 0.0;
                    walked as f32 * theme::ROW_HEIGHT
                });
                self.program.pin = Some((wanted, distance.max(0.0)));
            }
        }
        // A pinned reveal keeps its screen row while rows above it change.
        if let Some((position, distance)) = self.program.pin {
            match pinned_top(&layout, position, distance) {
                Some((top, offset)) => {
                    self.program.top = Some(top);
                    self.program.offset = snap(offset);
                }
                None => self.program.pin = None,
            }
        }
        let top = self
            .program
            .top
            .and_then(|top| layout.resolve(top))
            .or_else(|| layout.at_or_after(Position::new(0, Rank::Section)));
        let Some(top) = top else {
            return;
        };
        let functions = &info.functions;
        let key = WindowKey {
            rows: self.program.rows_serial,
            inventory: (
                self.generation,
                functions.as_ptr() as usize,
                functions.len(),
                self.source_epochs.inventory,
                functions.last().map_or(0, |f| f.address),
            ),
            expansions: self.program.expanded.epoch(),
            evidence: self.program.evidence.epoch,
            anchor: self.program.anchor,
            after: (page + WINDOW_BEFORE).min(WINDOW_ROWS - WINDOW_BEFORE - 1),
        };
        let reused = self.program.window.as_mut().is_some_and(|window| {
            let Ok(index) = window
                .rows
                .binary_search_by_key(&top.position(), Row::position)
            else {
                return false;
            };
            let room_before = index >= WINDOW_MARGIN || window.at_start;
            let room_after = window.at_end || window.rows.len() - index > page + WINDOW_MARGIN;
            let fits = window.key == key && window.rows[index] == top && room_before && room_after;
            if fits {
                window.top = index;
            }
            fits
        });
        if !reused {
            let mut before = Vec::new();
            let mut row = top;
            while before.len() < WINDOW_BEFORE {
                match layout.previous(&row) {
                    Some(previous) => {
                        before.push(previous);
                        row = previous;
                    }
                    None => break,
                }
            }
            let at_start = before.len() < WINDOW_BEFORE;
            before.reverse();
            let index = before.len();
            let mut window = before;
            window.push(top);
            let mut row = top;
            let mut at_end = false;
            while window.len() - index <= key.after {
                match layout.next(&row) {
                    Some(next) => {
                        window.push(next);
                        row = next;
                    }
                    None => {
                        at_end = true;
                        break;
                    }
                }
            }
            self.program.window = Some(Window {
                key,
                rows: window,
                top: index,
                at_start,
                at_end,
            });
        }
        let window = self.program.window.as_ref().expect("materialized above");
        let digits = theme::address_digits(
            info.sections
                .iter()
                .map(|s| s.address.saturating_add(s.size))
                .max()
                .unwrap_or(0),
        );
        let glyph = theme::glyph_width(ui);
        let columns = theme::listing_columns(body.width(), glyph, digits, ppp);
        theme::paint_listing_header(ui, header, &columns);
        let displayed = self.view().map(|view| view.address);
        let cursor = self.program_cursor(&layout).map(|row| row.position());
        let mut clicked = None;
        let mut follow = None;
        let mut menu_opened = None;
        let mut menu_chosen = None;
        let mut header_xrefs = None;
        let mut stop = None;
        let mut toggled = None;
        let mut witness = None;
        let bytes = &self.program.bytes;
        let evidence = &self.program.evidence.index;
        let anchored = theme::anchored_rows(
            ui,
            body,
            &window.rows,
            window.top,
            self.program.offset,
            window.at_end,
            |ui, _, row, rect| match *row {
                Row::Section { section, start } => {
                    let Some(section) = info.sections.get(section) else {
                        return;
                    };
                    let end = start.saturating_add(section.size);
                    theme::listing_mark(
                        ui,
                        rect,
                        &columns,
                        start,
                        digits,
                        theme::ListingMark::Section {
                            name: &crop(&section.name, 120),
                            end,
                        },
                        cursor == Some(row.position()),
                    );
                    ui.interact(
                        rect,
                        ui.scope_id().with(("program-section", start)),
                        egui::Sense::hover(),
                    )
                    .on_hover_text(format!(
                        "{}\n{start:#x}–{end:#x}\nfile {:#x} · zero-filled {:#x}",
                        crop(&section.name, MAX_HOVER_NAME),
                        section.file_size.min(section.size),
                        section.size - section.file_size.min(section.size)
                    ));
                }
                Row::Function { entry } => {
                    let (name, raw) = self.function_names(entry).unwrap_or(("function", None));
                    let warnings = self
                        .row_view(entry)
                        .map_or(&[][..], |(view, _)| view.warnings.as_slice());
                    let response = theme::row_response(
                        ui,
                        ui.scope_id().with(("program-function", entry)),
                        rect,
                        false,
                        false,
                    );
                    theme::listing_mark(
                        ui,
                        rect,
                        &columns,
                        entry,
                        digits,
                        theme::ListingMark::Function {
                            name: &crop(name, 120),
                            partial: !warnings.is_empty(),
                        },
                        cursor == Some(row.position()),
                    );
                    let mut hover = vec![name_hover(name, raw)];
                    hover.extend(warnings.iter().take(8).map(|w| crop(w, 400)));
                    let response = response.on_hover_text(hover.join("\n\n"));
                    if response.clicked() {
                        clicked = Some((entry, row.position()));
                    }
                    response.context_menu(|ui| {
                        if ui.button("Xrefs to this function").clicked() {
                            header_xrefs = Some(entry);
                            ui.close();
                        }
                    });
                }
                Row::Instruction { owner, start, .. } => {
                    let Some((view, instruction)) =
                        self.row_view(owner).and_then(|(view, listing)| {
                            listing
                                .position(start)
                                .and_then(|index| listing.get(index))
                                .map(|instruction| (view, instruction))
                        })
                    else {
                        return;
                    };
                    let response = theme::row_response(
                        ui,
                        ui.scope_id().with(("program-row", start)),
                        rect,
                        cursor == Some(row.position()),
                        displayed == Some(owner) && self.semantic.addresses.contains(&start),
                    );
                    let call = view.calls.iter().find(|call| call.address == start);
                    let callee = call
                        .and_then(|call| call.target)
                        .and_then(|target| self.function_names(target));
                    let elided = theme::listing_cells(
                        ui,
                        rect,
                        &columns,
                        &theme::ListingRow {
                            address: start,
                            address_digits: digits,
                            bytes: &instruction.bytes,
                            mnemonic: &instruction.mnemonic,
                            operands: &instruction.operands,
                            callee: callee.map(|(name, _)| name),
                            comment: self
                                .annotation_browser
                                .comments
                                .get(&start)
                                .map(String::as_str),
                        },
                    );
                    let mut hover = Vec::new();
                    if let Some((_, Some(raw))) = callee {
                        hover.push(crop(raw, MAX_HOVER_NAME));
                    }
                    if elided.address || elided.bytes || elided.code {
                        hover.push(format!(
                            "{start:0digits$x}  {}  {} {}",
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
                        .and_then(|session| session.annotations.get(&start))
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
                        clicked = Some((owner, row.position()));
                    }
                    if response.double_clicked() {
                        follow = self.row_follow_target(owner, start).map(|t| (owner, t));
                    }
                    let source = super::MenuSource::Instruction {
                        entry: owner,
                        pc: start,
                    };
                    if let Some(source) = self.menu_shown(&response, source, &mut menu_opened) {
                        response.context_menu(|ui| self.menu_body(ui, source, &mut menu_chosen));
                    }
                }
                Row::Undefined { start, end } | Row::ZeroFill { start, end } => {
                    let length = end - start;
                    let zero = matches!(row, Row::ZeroFill { .. });
                    let marked = evidence
                        .split_marks(start, start.saturating_add(1))
                        .next()
                        .is_some();
                    let note = if marked {
                        self.listing_note(start)
                    } else {
                        theme::ListingNote::default()
                    };
                    let mark = if zero {
                        theme::ListingMark::ZeroFill { length, note }
                    } else {
                        theme::ListingMark::Undefined { length, note }
                    };
                    let response = theme::row_response(
                        ui,
                        ui.scope_id().with(("program-gap", start)),
                        rect,
                        false,
                        false,
                    );
                    let selected = cursor == Some(row.position());
                    theme::listing_mark(ui, rect, &columns, start, digits, mark, selected);
                    let mut hover = format!("{start:#x}–{end:#x}  ({length:#x})");
                    if marked {
                        hover.push_str("\n\n");
                        hover.push_str(&self.mark_hover(start));
                    }
                    let response = response.on_hover_text(hover);
                    if !zero
                        && theme::listing_disclosure(
                            ui,
                            ui.scope_id().with(("program-disclosure", start)),
                            rect,
                            &columns,
                            false,
                        )
                    {
                        toggled = Some(*row);
                    }
                    if response.clicked() {
                        stop = Some(*row);
                    }
                    if response.double_clicked() && !zero {
                        toggled = Some(*row);
                    }
                    let source = super::MenuSource::Span {
                        address: start,
                        length,
                    };
                    if let Some(source) = self.menu_shown(&response, source, &mut menu_opened) {
                        response.context_menu(|ui| self.menu_body(ui, source, &mut menu_chosen));
                    }
                }
                Row::Byte { address } => {
                    let response = theme::row_response(
                        ui,
                        ui.scope_id().with(("program-byte", address)),
                        rect,
                        false,
                        false,
                    );
                    theme::listing_mark(
                        ui,
                        rect,
                        &columns,
                        address,
                        digits,
                        theme::ListingMark::Byte {
                            value: bytes.byte(address),
                            failed: layout
                                .byte_page(address)
                                .is_some_and(|(page, _)| bytes.is_failed(page)),
                        },
                        cursor == Some(row.position()),
                    );
                    let first = layout
                        .byte_run(address)
                        .is_some_and(|(start, _)| start == address);
                    if first
                        && theme::listing_disclosure(
                            ui,
                            ui.scope_id().with(("program-disclosure", address)),
                            rect,
                            &columns,
                            true,
                        )
                    {
                        toggled = Some(*row);
                    }
                    if response.clicked() {
                        stop = Some(*row);
                    }
                    if response.double_clicked() {
                        toggled = Some(*row);
                    }
                    let source = super::MenuSource::Span { address, length: 1 };
                    if let Some(source) = self.menu_shown(&response, source, &mut menu_opened) {
                        response.context_menu(|ui| self.menu_body(ui, source, &mut menu_chosen));
                    }
                }
                Row::Data { start, end, kind } => {
                    let response = theme::row_response(
                        ui,
                        ui.scope_id().with(("program-data", start)),
                        rect,
                        false,
                        false,
                    );
                    let (shown, provenance) = self.data_row_text(start, end, kind);
                    let data = match kind {
                        EvidenceKind::ImportSlot(_) => theme::DataEvidence::Slot {
                            name: shown.as_deref().unwrap_or("?"),
                        },
                        EvidenceKind::Pointer { entry, .. } => theme::DataEvidence::Pointer {
                            target: entry,
                            name: shown.as_deref(),
                        },
                        EvidenceKind::String(_) => theme::DataEvidence::String {
                            preview: shown.as_deref().unwrap_or(""),
                        },
                    };
                    let item = crate::listing_evidence::Evidence { start, end, kind };
                    let marks: Vec<u64> = evidence.marks_within(&item).take(9).collect();
                    let note = if marks.first() == Some(&start) {
                        self.listing_note(start)
                    } else {
                        theme::ListingNote::default()
                    };
                    theme::listing_mark(
                        ui,
                        rect,
                        &columns,
                        start,
                        digits,
                        theme::ListingMark::Data {
                            evidence: data,
                            note,
                        },
                        cursor == Some(row.position()),
                    );
                    let mut hover = format!("{start:#x}–{end:#x}\n{provenance}");
                    if !marks.is_empty() {
                        hover.push('\n');
                        for &mark in marks.iter().take(8) {
                            hover.push('\n');
                            hover.push_str(&self.mark_hover(mark));
                        }
                        if marks.len() > 8 {
                            hover.push_str("\n…");
                        }
                    }
                    let response = response.on_hover_text(hover);
                    if response.clicked() {
                        stop = Some(*row);
                    }
                    if response.double_clicked()
                        && let EvidenceKind::Pointer { entry, .. } = kind
                    {
                        witness = Some(entry);
                    }
                    let source = super::MenuSource::Span {
                        address: start,
                        length: end - start,
                    };
                    if let Some(source) = self.menu_shown(&response, source, &mut menu_opened) {
                        response.context_menu(|ui| self.menu_body(ui, source, &mut menu_chosen));
                    }
                }
                Row::Pending { start, end, .. } => {
                    theme::listing_mark(
                        ui,
                        rect,
                        &columns,
                        start,
                        digits,
                        theme::ListingMark::Pending,
                        cursor == Some(row.position()),
                    );
                    ui.interact(
                        rect,
                        ui.scope_id().with(("program-gap", start)),
                        egui::Sense::hover(),
                    )
                    .on_hover_text(format!("{start:#x}–{end:#x}"));
                }
            },
        );
        // Re-anchor at the row the wheel reached, and record what is shown.
        // Scrolling ends a pinned reveal; the view then anchors by address.
        if anchored.scrolled {
            self.program.pin = None;
        }
        let rows = &window.rows;
        // Keep the pin at the row it was actually drawn at: near the end of
        // the program the view is clamped above the requested distance, and
        // a stale distance would jump the target once rows below it load.
        if let Some((position, distance)) = &mut self.program.pin {
            let index = match rows.binary_search_by_key(position, Row::position) {
                Ok(index) => Some(index),
                Err(index) => index.checked_sub(1),
            };
            if let Some(below) = index
                .and_then(|index| index.checked_sub(anchored.top))
                .filter(|&below| below <= page)
            {
                *distance = (below as f32 * theme::ROW_HEIGHT - anchored.offset).max(0.0);
            }
        }
        let new_top = rows[anchored.top].position();
        if new_top != top.position() {
            self.program.backward = new_top < top.position();
        }
        self.program.top = Some(new_top);
        self.program.offset = anchored.offset;
        self.program.shown = (!anchored.full.is_empty()).then(|| {
            (
                rows[anchored.full.start].position(),
                rows[anchored.full.end - 1].position(),
            )
        });
        let shown = &rows[anchored.top..(anchored.top + page + 1).min(rows.len())];
        let bottom = shown.last().map_or(new_top.address, |row| {
            row.span().map_or(row.position().address, |(_, end)| end)
        });
        let thumb = (
            scale.fraction(new_top.address) as f32,
            scale.fraction(bottom) as f32,
        );
        ui.allocate_rect(bar, egui::Sense::hover());
        let jump = theme::address_bar(ui, bar, ui.scope_id().with("program-address-bar"), thumb)
            .and_then(|fraction| scale.address(f64::from(fraction)))
            .and_then(|address| layout.reveal(address));
        // Entries the viewport shows without a current view, then the next
        // ones in the scroll direction.
        let mut wanted = Vec::new();
        let mut prefetch = Vec::new();
        if let Some(current) = self.results.current_context() {
            for entry in shown.iter().filter_map(Row::function) {
                if !wanted.contains(&entry) && self.listing_needs(entry, current, true) {
                    wanted.push(entry);
                }
            }
            let bounds = (shown.first(), shown.last());
            if let (Some(first), Some(last)) = bounds {
                let candidates: Box<dyn Iterator<Item = u64>> = if !self.program.backward {
                    let after = last.position().address;
                    let index = functions.partition_point(|f| f.address <= after);
                    Box::new(functions[index..].iter().map(|f| f.address))
                } else {
                    let before = first.position().address;
                    let index = functions.partition_point(|f| f.address < before);
                    Box::new(functions[..index].iter().rev().map(|f| f.address))
                };
                prefetch.extend(
                    candidates
                        .take(PREFETCH)
                        .filter(|&entry| self.listing_needs(entry, current, false)),
                );
            }
        }
        // Pages of the byte rows in view, top first; those lacking bytes
        // are wanted.
        let mut byte_wanted: Vec<(u64, usize)> = Vec::new();
        let mut byte_visible: Vec<u64> = Vec::new();
        for row in shown {
            let Row::Byte { address } = *row else {
                continue;
            };
            let Some(page) = layout.byte_page(address) else {
                continue;
            };
            if !byte_visible.contains(&page.0) {
                byte_visible.push(page.0);
            }
            if bytes.byte(address).is_none() && !byte_wanted.contains(&page) {
                byte_wanted.push(page);
            }
        }
        self.program.byte_wanted = byte_wanted;
        self.program.byte_visible = byte_visible;
        self.program.wanted = wanted;
        self.program.wanted_context = self.results.current_context().cloned();
        self.program.drawn_empty = false;
        self.program.prefetch = prefetch;
        if let Some(row) = jump {
            self.program.pin = None;
            self.program.top = Some(row.position());
            self.program.offset = 0.0;
            context.request_repaint();
        }
        if self.listing_page_wanted().is_some() {
            // The next frame's worker poll sends it.
            context.request_repaint();
        }
        self.listing_cursor_drawn(ui, body);
        if let Some((owner, position)) = clicked {
            self.navigate_location(position.address, Some(owner), false, context);
            self.program.cursor = Some(position);
        }
        if let Some(row) = stop {
            self.move_program_cursor(row, context);
        }
        if let Some(row) = toggled {
            self.toggle_bytes(row);
            context.request_repaint();
        }
        if let Some(entry) = witness {
            self.follow_witness(entry, context);
        }
        if let Some((owner, target)) = follow {
            self.follow_row_target(owner, target, context);
        }
        self.finish_menu(menu_opened, menu_chosen, context);
        if let Some(entry) = header_xrefs {
            self.open_xrefs(crate::xrefs::XrefTarget {
                address: entry,
                kind: crate::xrefs::TargetKind::Function,
            });
        }
    }

    /// Whether a Listing request may start once a worker is available:
    /// nothing else is sent, queued, prepared or awaited. In particular the
    /// displayed function's graph presentation and its decompilation go
    /// first, and so does every maintenance request; `poll_worker` offers the
    /// worker to Listing only after the maintenance pumps.
    pub(super) fn listing_may_dispatch(&self) -> bool {
        use super::graph_preparation::Continuation;
        let awaiting_code = self.graph.as_ref().is_some_and(|graph| {
            let address = graph.address();
            let decompile = |request: &Request| {
                matches!(request, Request::Decompile { address: a } if *a == address)
            };
            self.queue.iter().any(decompile)
                || self.pending.as_ref().is_some_and(|p| decompile(&p.request))
        });
        self.program_scope()
            && self.tab == Tab::Listing
            && self.pending.is_none()
            && self.opening.is_none()
            && self.queue.is_empty()
            && self.discovery_bytes.is_none()
            && self.discovery_job.is_none()
            && self.deferred_discovery.is_none()
            && self.signature_replay.is_none()
            && self.signature_change.is_none()
            && !self.results.preparing()
            && !awaiting_code
            && !self.graph_preparation.awaits(|continuation| {
                matches!(
                    continuation,
                    Continuation::Live { .. } | Continuation::Saved(_)
                )
            })
    }

    /// Re-resolves the displayed function after a result-input change
    /// (discovery, renames, signatures), or opens the function the Program
    /// cursor rests in, without moving the Program view. A Program cursor
    /// outside `address` (on another function's row or a gap) stays where
    /// it is, is not reported as outside the graph, and keeps its follow.
    pub(super) fn reresolve_displayed(
        &mut self,
        address: u64,
        focus: Option<u64>,
        context: &egui::Context,
    ) {
        let outside = self.program_scope()
            && focus.is_some_and(|pc| {
                pc != address
                    && !self
                        .row_view(address)
                        .is_some_and(|(_, listing)| listing.contains(pc))
            });
        let (reveal, follow, cursor) = (
            self.program.reveal,
            self.program.follow,
            self.program.cursor,
        );
        let undisplayed = self.undisplayed_call;
        self.program.quiet = Some(self.selection_generation.wrapping_add(1));
        self.navigate_to(address, focus, false, context);
        self.program.reveal = reveal;
        self.program.follow = follow;
        self.program.cursor = cursor;
        if outside {
            self.reference_focus = None;
            self.undisplayed_call = undisplayed;
        }
    }

    /// After a rename of the displayed function. Function scope reopens it
    /// at its entry as before; the Program scope keeps the view, the cursor
    /// (also on another function's row) and any follow it armed.
    pub(super) fn reopen_after_rename(&mut self, address: u64, context: &egui::Context) {
        if !self.program_scope() {
            self.navigate(address, false, context);
            return;
        }
        self.reresolve_displayed(address, self.selected, context);
    }

    /// A signature edit is about to drop the displayed graph: keep its
    /// rows, and restore its selection without a reveal.
    pub(super) fn keep_for_signature_restore(&mut self) {
        self.remember_displayed();
        if self.program_scope() {
            self.program.quiet_restore = true;
        }
    }

    /// Where the signature restore sets `pending_listing_scroll`.
    pub(super) fn note_restore_scroll(&mut self) {
        if std::mem::take(&mut self.program.quiet_restore) {
            self.program.quiet_scroll = Some(self.selection_generation);
        }
    }

    /// Called where a focus adoption sets `pending_listing_scroll`.
    pub(super) fn note_focus_scroll(&mut self) {
        if self.program.quiet.take() == Some(self.selection_generation) {
            self.program.quiet_scroll = Some(self.selection_generation);
        }
    }

    /// Sends at most one bounded Listing request, only when nothing else
    /// wants the worker ([`Self::listing_may_dispatch`]); it never preempts,
    /// queues behind or reopens anything.
    pub(super) fn dispatch_listing(&mut self) {
        if self.client.is_none() {
            self.program.discovery_turn = None;
            return;
        }
        if let Some((address, length)) = self.next_listing_page() {
            let origin = self.listing_page_origin();
            self.send_direct_at(Request::Bytes { address, length }, origin);
            return;
        }
        let Some(entries) = self.next_listing_entries() else {
            return;
        };
        self.program.token = self.program.token.wrapping_add(1);
        let binding = ListingBinding {
            generation: self.generation,
            token: self.program.token,
        };
        self.send_direct(Request::Listing { binding, entries });
    }

    /// Whether a worker is running; tests may assume one.
    fn listing_worker(&self) -> bool {
        #[cfg(test)]
        if self.program.assume_worker {
            return true;
        }
        self.client.is_some()
    }

    /// The byte page of rows in view that may be read now, at the Program
    /// listing's priority: only when [`Self::listing_may_dispatch`], with a
    /// worker, below the failure cap and, during discovery, within a
    /// granted turn.
    fn listing_page_wanted(&self) -> Option<(u64, usize)> {
        if !self.listing_worker()
            || self.program.failures >= MAX_LISTING_FAILURES
            || !self.listing_may_dispatch()
        {
            return None;
        }
        if self.discovery_running {
            let turn = self.program.discovery_turn?;
            if self.program.drawn_empty
                || turn.granted.elapsed() > LISTING_TURN_CAP
                || turn
                    .ready
                    .is_some_and(|ready| ready.elapsed() > LISTING_TURN_WAIT)
            {
                return None;
            }
        }
        self.program
            .bytes
            .next(&self.program.byte_wanted, &self.program.byte_visible)
    }

    /// The byte page the next Listing request reads, if one may go now.
    /// Pages go before function bodies; during discovery a page uses the
    /// batch's whole turn.
    pub(super) fn next_listing_page(&mut self) -> Option<(u64, usize)> {
        let page = self.listing_page_wanted()?;
        if self.discovery_running {
            self.program.discovery_turn = None;
        }
        Some(page)
    }

    /// The origin of a new Listing byte read, under a new token. It is
    /// bound to the binary and that token only, never to a byte intent, so
    /// it neither cancels nor is cancelled by a user's Hex or Decode read.
    fn listing_page_origin(&mut self) -> super::RequestOrigin {
        self.program.token = self.program.token.wrapping_add(1);
        let mut origin = self.request_origin();
        origin.bytes = Some(super::ByteBinding {
            generation: self.generation,
            intent: self.byte_intent,
            destination: super::ByteDestination::Listing {
                token: self.program.token,
            },
        });
        origin
    }

    /// Adopts a current Listing byte read: a complete page is cached, a
    /// short one is not requested again. Nothing else changes.
    pub(super) fn receive_listing_page(&mut self, address: u64, length: usize, bytes: Vec<u8>) {
        if bytes.len() != length {
            self.program.bytes.fail(address);
            return;
        }
        let top = self.program.top.map_or(address, |top| top.address);
        self.program
            .bytes
            .accept(address, bytes, top, &self.program.byte_visible);
    }

    /// Opens the function a pointer-table witness row points at, recording
    /// history as any explicit navigation does.
    pub(super) fn follow_witness(&mut self, entry: u64, context: &egui::Context) {
        self.program.follow = None;
        self.navigate_location(entry, Some(entry), true, context);
    }

    /// Expands a collapsed `??` row by up to 64 KiB, or collapses the run
    /// holding a byte row, keeping the toggled row where it was drawn. A
    /// cursor inside a collapsed run moves to the run's start. Nothing is
    /// navigated, selected anew or recorded in history.
    pub(super) fn toggle_bytes(&mut self, row: Row) {
        let Some(layout) = self.program_layout() else {
            return;
        };
        let (start, end, expand) = match row {
            Row::Undefined { .. } => {
                let Some((start, end)) = crate::program_listing::expand_interval(&row) else {
                    return;
                };
                (start, end, true)
            }
            Row::Byte { address } => {
                let Some((start, end)) = layout.byte_run(address) else {
                    return;
                };
                (start, end, false)
            }
            _ => return,
        };
        let mut pinned = Position::new(start, Rank::Body);
        let distance = self.program.drawn_distance(row.position());
        if expand {
            self.program.expanded.expand(start, end, self.selected);
        } else {
            self.program.expanded.collapse(start, end);
            // The collapsed run may join a collapsed part before it: the
            // row now covering its start may begin earlier.
            if let Some(collapsed) = self
                .program_layout()
                .and_then(|layout| layout.resolve(pinned))
            {
                pinned = collapsed.position();
            }
            if self
                .selected
                .is_some_and(|selected| start <= selected && selected < end)
            {
                self.data_location = None;
                self.set_selected_address(pinned.address);
                self.program.cursor = Some(pinned);
            }
        }
        self.program.reveal = None;
        match distance {
            Some(distance) => self.program.pin = Some((pinned, distance.max(0.0))),
            None => self.program.reveal = Some(Reveal::Row(pinned)),
        }
    }

    /// A committed discovery batch grants the Program listing one turn before
    /// the next batch. Discovery holds while the turn is outstanding, at most
    /// [`LISTING_TURN_WAIT`].
    pub(super) fn grant_listing_turn(&mut self) {
        if self.discovery_running && self.program_scope() && self.tab == Tab::Listing {
            self.program.discovery_turn = Some(Turn {
                granted: Instant::now(),
                ready: None,
            });
        }
    }

    /// Whether discovery must wait for an outstanding Listing turn.
    pub(super) fn listing_turn_outstanding(&self) -> bool {
        self.program.discovery_turn.is_some()
    }

    /// The entries the next Listing request names, if one may go now.
    /// While discovery runs, only a granted turn sends, and only visible
    /// entries; the turn is used or dropped before the next batch. Otherwise
    /// visible entries go first, then prefetch.
    pub(super) fn next_listing_entries(&mut self) -> Option<Vec<u64>> {
        if self.program.failures >= MAX_LISTING_FAILURES {
            self.program.discovery_turn = None;
            return None;
        }
        if !self.discovery_running {
            self.program.discovery_turn = None;
            if !self.listing_may_dispatch() {
                return None;
            }
            let current = self.results.current_context()?.clone();
            if let Some(entry) = self.next_isolated(&current, None) {
                return Some(vec![entry]);
            }
            let visible = self.listing_entries(&self.program.wanted, &current, true);
            return if visible.is_empty() {
                let prefetch = self.listing_entries(&self.program.prefetch, &current, false);
                (!prefetch.is_empty()).then_some(prefetch)
            } else {
                Some(visible)
            };
        }
        let turn = self.program.discovery_turn?;
        if !self.program_scope()
            || self.tab != Tab::Listing
            || self.program.drawn_empty
            || turn.granted.elapsed() > LISTING_TURN_CAP
            || turn
                .ready
                .is_some_and(|ready| ready.elapsed() > LISTING_TURN_WAIT)
        {
            self.program.discovery_turn = None;
            return None;
        }
        // User work, the displayed function and maintenance go first; the
        // turn's own wait starts only once a request could go.
        if !self.listing_may_dispatch() {
            return None;
        }
        if let Some(turn) = &mut self.program.discovery_turn {
            turn.ready.get_or_insert_with(Instant::now);
        }
        // Then wait for the batch's context and for rows drawn under it.
        let current = self.results.current_context()?.clone();
        let drawn = self
            .program
            .wanted_context
            .as_ref()
            .is_some_and(|wanted| Arc::ptr_eq(wanted, &current));
        if !drawn {
            return None;
        }
        self.program.discovery_turn = None;
        let visible = self.listing_entries(&self.program.wanted, &current, true);
        if visible.is_empty() {
            // Nothing in view needs a body: discovery continues at once.
            return None;
        }
        if let Some(entry) = self.next_isolated(&current, Some(&visible)) {
            return Some(vec![entry]);
        }
        let isolating = &self.program.isolating;
        let visible: Vec<u64> = visible
            .into_iter()
            .filter(|entry| !isolating.contains(entry))
            .collect();
        (!visible.is_empty()).then_some(visible)
    }

    /// The next entry of an isolation still worth requesting alone, among
    /// `within` when given. Entries no longer needed leave the queue.
    fn next_isolated(
        &mut self,
        current: &Arc<ProgramContext>,
        within: Option<&[u64]>,
    ) -> Option<u64> {
        let mut index = 0;
        while let Some(&entry) = self.program.isolating.get(index) {
            if !self.listing_needs(entry, current, true) {
                self.program.isolating.remove(index);
                continue;
            }
            if within.is_none_or(|within| within.contains(&entry)) {
                self.program.isolating.remove(index);
                return Some(entry);
            }
            index += 1;
        }
        None
    }

    fn listing_entries(
        &self,
        candidates: &[u64],
        current: &Arc<ProgramContext>,
        stale: bool,
    ) -> Vec<u64> {
        let mut entries: Vec<u64> = candidates
            .iter()
            .copied()
            .filter(|&entry| self.listing_needs(entry, current, stale))
            .collect();
        entries.sort_unstable();
        entries.dedup();
        entries.truncate(MAX_LISTING_FUNCTIONS);
        entries
    }

    /// Adopts a Listing reply. A reply that does not answer its request is
    /// malformed and stops the worker; a superseded one is dropped. Only
    /// views still bound to the current result context are cached.
    pub(super) fn receive_listing(
        &mut self,
        request: &Request,
        result: Option<&ResultBinding>,
        binding: ListingBinding,
        outcomes: Vec<ListingOutcome>,
    ) {
        let Request::Listing {
            binding: sent,
            entries,
        } = request
        else {
            return;
        };
        let answers = binding == *sent
            && !outcomes.is_empty()
            && outcomes.len() <= entries.len()
            && outcomes.iter().zip(entries).all(|(outcome, entry)| {
                outcome.entry == *entry
                    && outcome
                        .view
                        .as_ref()
                        .is_none_or(|view| view.address == *entry)
            });
        if !answers {
            self.stop_worker();
            self.status = "Invalid worker response: listing; worker stopped".into();
            return;
        }
        let Some(result) = result else {
            return;
        };
        if sent.generation != self.generation
            || sent.token != self.program.token
            || !self.results.current(Some(result))
        {
            return;
        }
        let context = result.key.function.context.clone();
        let center = self.program.top.map_or(entries[0], |top| top.address);
        for outcome in outcomes {
            match outcome
                .view
                .and_then(|view| CachedBody::new(view, Some(context.clone())))
            {
                Some(body) => {
                    let results = &mut self.results;
                    let kept = self
                        .program
                        .cache
                        .insert(outcome.entry, body, center, |bytes| {
                            results.set_listing_bytes(bytes)
                        });
                    // A view that does not fit is not requested again
                    // under this context.
                    if !kept {
                        self.program.cache.fail(outcome.entry, context.clone());
                    }
                }
                None => self.program.cache.fail(outcome.entry, context.clone()),
            }
        }
    }

    /// The pending request timed out or its worker failed.
    pub(super) fn fail_pending_listing(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.fail_listing(&pending);
            self.pending = Some(pending);
        }
    }

    /// The request failed without a reply: it timed out, crashed the
    /// worker or answered with an error. A multi-entry request is retried
    /// one entry per request, in order, so only an entry whose own request
    /// fails is blocked for this binary; the others load normally. Each
    /// failure counts toward [`MAX_LISTING_FAILURES`], so failing views can
    /// never cycle the worker indefinitely, and a failure during discovery
    /// resumes it without spending one of its own resumes.
    pub(super) fn fail_listing(&mut self, pending: &Pending) {
        if let (Request::Bytes { address, .. }, Some(binding)) = (&pending.request, pending.bytes)
            && matches!(binding.destination, super::ByteDestination::Listing { .. })
        {
            if binding.generation == self.generation {
                self.program.failures = self.program.failures.saturating_add(1);
                self.program.free_resume = self.program.failures <= MAX_LISTING_FAILURES;
                self.program.bytes.fail(*address);
            }
            return;
        }
        let Request::Listing { binding, entries } = &pending.request else {
            return;
        };
        if binding.generation != self.generation {
            return;
        }
        self.program.failures = self.program.failures.saturating_add(1);
        self.program.free_resume = self.program.failures <= MAX_LISTING_FAILURES;
        match entries.as_slice() {
            [entry] => self.program.cache.block(*entry),
            entries => {
                for &entry in entries.iter().rev() {
                    if !self.program.isolating.contains(&entry) {
                        self.program.isolating.push_front(entry);
                    }
                }
            }
        }
    }
}

/// The top row and offset that put the row at `position` exactly
/// `distance` points below the view's top, walking back from it; fewer
/// rows above it keep it as low as the program allows.
fn pinned_top(
    layout: &crate::program_listing::Layout<'_>,
    position: Position,
    distance: f32,
) -> Option<(Position, f32)> {
    let target = layout.resolve(position)?;
    let above = (distance / theme::ROW_HEIGHT).ceil() as usize;
    let mut row = target;
    let mut walked = 0;
    while walked < above {
        match layout.previous(&row) {
            Some(previous) => {
                row = previous;
                walked += 1;
            }
            None => break,
        }
    }
    Some((
        row.position(),
        (walked as f32 * theme::ROW_HEIGHT - distance).max(0.0),
    ))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::super::tests as fixture;
    use super::*;
    use crate::model::{BasicBlock, FunctionInfo, Instruction, Response, SectionInfo};

    fn view(entry: u64, count: u64) -> FunctionView {
        FunctionView {
            address: entry,
            blocks: vec![BasicBlock {
                address: entry,
                instructions: (0..count)
                    .map(|i| Instruction {
                        address: entry + i * 4,
                        bytes: vec![0x90; 4],
                        mnemonic: "nop".into(),
                        operands: String::new(),
                    })
                    .collect(),
            }],
            edges: vec![],
            calls: vec![],
            warnings: vec![],
        }
    }

    /// Program scope over `.text` (three functions) and a data section, with
    /// a published result context; `entry` is displayed.
    fn program_app() -> DesktopApp {
        let mut app = fixture::keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.sections.push(SectionInfo {
            name: ".data".into(),
            address: 0x2000,
            size: 0x40,
            file_offset: 0x100,
            file_size: 0x40,
            executable: false,
        });
        info.file_len = 0x140;
        info.functions.push(FunctionInfo {
            address: 0x1080,
            name: "third".into(),
        });
        let functions = info.functions.clone();
        app.results.open(&"a".repeat(64), &[]);
        app.results.update_inputs(functions, vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        fixture::show_view(&mut app, view(0x1000, 4));
        app.result_scope = Some(0x1000);
        app.tab = Tab::Listing;
        app.set_listing_scope(ListingScope::Program);
        app
    }

    fn listing_pending(app: &mut DesktopApp, entries: Vec<u64>) -> Pending {
        app.program.token += 1;
        let request = Request::Listing {
            binding: ListingBinding {
                generation: app.generation,
                token: app.program.token,
            },
            entries: entries.clone(),
        };
        Pending {
            id: 1,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: app.results.binding(entries[0], String::new()),
        }
    }

    fn reply(pending: &Pending, outcomes: Vec<ListingOutcome>) -> Response {
        let Request::Listing { binding, .. } = &pending.request else {
            unreachable!()
        };
        Response::Listing {
            binding: *binding,
            outcomes,
        }
    }

    fn outcome(entry: u64, count: u64) -> ListingOutcome {
        ListingOutcome {
            entry,
            view: Some(view(entry, count)),
        }
    }

    #[test]
    fn listing_replies_are_cached_only_when_they_answer_the_current_request() {
        let context = egui::Context::default();
        let unchanged = |change: &dyn Fn(&mut DesktopApp, &mut Pending, &mut Response)| {
            let mut app = program_app();
            let mut pending = listing_pending(&mut app, vec![0x1040, 0x1080]);
            let mut response = reply(&pending, vec![outcome(0x1040, 2), outcome(0x1080, 2)]);
            change(&mut app, &mut pending, &mut response);
            let epoch = app.program.cache.epoch();
            app.receive(pending, response, &context);
            assert!(app.program.cache.is_empty());
            assert_eq!(app.program.cache.epoch(), epoch);
            app
        };
        // A reply for another token is malformed: the worker stops.
        let app = unchanged(&|_, _, response| {
            if let Response::Listing { binding, .. } = response {
                binding.token += 1;
            }
        });
        assert!(app.status.contains("Invalid worker response"));
        // Outcomes must be an ordered prefix of the requested entries.
        for outcomes in [
            vec![outcome(0x1080, 2)],
            vec![],
            vec![outcome(0x1040, 2), outcome(0x1080, 2), outcome(0x10c0, 1)],
            vec![ListingOutcome {
                entry: 0x1040,
                view: Some(view(0x1080, 1)),
            }],
        ] {
            let app =
                unchanged(&|_, pending, response| *response = reply(pending, outcomes.clone()));
            assert!(
                app.status.contains("Invalid worker response"),
                "{}",
                app.status
            );
        }
        // An instruction outside executable file-backed bytes is rejected.
        let app = unchanged(&|_, pending, response| {
            let mut data = view(0x1040, 1);
            data.blocks.push(BasicBlock {
                address: 0x2000,
                instructions: vec![Instruction {
                    address: 0x2000,
                    bytes: vec![0x90],
                    mnemonic: "nop".into(),
                    operands: String::new(),
                }],
            });
            *response = reply(
                pending,
                vec![ListingOutcome {
                    entry: 0x1040,
                    view: Some(data),
                }],
            );
        });
        assert!(app.status.contains("Invalid worker response"));
        // Superseded binary, request token or result context: dropped quietly.
        for stale in [
            &(|app: &mut DesktopApp| app.generation += 1) as &dyn Fn(&mut DesktopApp),
            &|app: &mut DesktopApp| app.program.token += 1,
            &|app: &mut DesktopApp| app.results.refresh(0x1040),
        ] {
            let app = unchanged(&|app, _, _| stale(app));
            assert!(!app.status.contains("Invalid"));
        }
        // The current answer: one view and one failure are both retained.
        let mut app = program_app();
        let pending = listing_pending(&mut app, vec![0x1040, 0x1080]);
        let response = reply(
            &pending,
            vec![
                outcome(0x1040, 3),
                ListingOutcome {
                    entry: 0x1080,
                    view: None,
                },
            ],
        );
        app.receive(pending, response, &context);
        assert!(app.program.cache.get(0x1040).is_some());
        let current = app.results.current_context().unwrap().clone();
        assert!(!app.program.cache.needs(0x1040, &current));
        assert!(
            !app.program.cache.needs(0x1080, &current),
            "failures are not retried"
        );
        assert_eq!(app.observed_owner(0x1044), Some(0x1040));
        assert!(app.results.usage().charged >= app.program.cache.bytes());
    }

    /// Frames through the real Listing pane.
    struct Harness {
        context: egui::Context,
        app: DesktopApp,
        time: f64,
        height: f32,
    }

    impl Harness {
        fn new(app: DesktopApp) -> Self {
            let context = egui::Context::default();
            theme::install(&context);
            context.set_pixels_per_point(1.25);
            context.all_styles_mut(|style| {
                style.animation_time = 0.0;
                style.scroll_animation = egui::style::ScrollAnimation::none();
            });
            let mut harness = Self {
                context,
                app,
                time: 0.0,
                height: 400.0,
            };
            harness.frame(vec![]);
            harness
        }

        fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
            self.time += 0.5;
            let Self { context, app, .. } = self;
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(700.0, self.height),
                    )),
                    time: Some(self.time),
                    events,
                    ..Default::default()
                },
                |ui| app.main_panel(ui),
            );
            output.textures_delta.clear();
            output
        }

        fn wheel(&mut self, delta: f32) {
            self.frame(vec![
                egui::Event::PointerMoved(egui::pos2(300.0, 200.0)),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    phase: egui::TouchPhase::Move,
                    source: egui::MouseWheelSource::Unknown,
                    delta: egui::vec2(0.0, delta),
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }

        fn top(&self) -> Position {
            self.app.program.top.unwrap()
        }
    }

    fn long_app() -> DesktopApp {
        let mut app = program_app();
        // 0x1000 covers all of .text: 64 four-byte rows.
        fixture::show_view(&mut app, view(0x1000, 64));
        app
    }

    #[test]
    fn reveal_is_consumed_once_and_later_wheel_scrolling_is_kept() {
        let mut h = Harness::new(long_app());
        let text = fixture::rendered_text(&h.frame(vec![]));
        assert!(
            text.iter().any(|t| t == ".text  00001000–00001100"),
            "{text:?}"
        );
        h.app.program.reveal = Some(Reveal::Address(0x10f0));
        h.frame(vec![]);
        assert!(h.app.program.reveal.is_none());
        let revealed = h.top();
        assert!(revealed.address > 0x1000 && revealed.address < 0x10f0);
        let (first, last) = h.app.program.shown.unwrap();
        assert!(first.address <= 0x10f0 && 0x10f0 <= last.address);
        // A second reveal of a shown row does not move the view.
        h.app.program.reveal = Some(Reveal::Address(0x10f0));
        h.frame(vec![]);
        assert_eq!(h.top(), revealed);
        h.wheel(3.0 * theme::ROW_HEIGHT);
        // egui spreads one wheel step over a few frames; let it settle.
        let mut scrolled = h.top();
        for _ in 0..30 {
            h.frame(vec![]);
            scrolled = h.top();
        }
        assert!(scrolled < revealed, "{scrolled:?} {revealed:?}");
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.top(), scrolled, "the wheel position is not reset");
        }
        // Offsets stay on device pixels at 1.25x.
        h.wheel(7.3);
        let offset = h.app.program.offset * 1.25;
        assert!((offset - offset.round()).abs() < 1e-3, "{offset}");
        // Scrolling far past the end stops with the last row in view.
        for _ in 0..20 {
            h.wheel(-2000.0);
        }
        let (_, last) = h.app.program.shown.unwrap();
        assert_eq!(last.address, 0x2000, "the data section's single row");
    }

    #[test]
    fn rows_show_cached_views_and_clicks_open_their_function() {
        let context = egui::Context::default();
        let mut app = program_app();
        let pending = listing_pending(&mut app, vec![0x1040]);
        let response = reply(&pending, vec![outcome(0x1040, 2)]);
        app.receive(pending, response, &context);
        let mut h = Harness::new(app);
        let output = h.frame(vec![]);
        let text = fixture::rendered_text(&output);
        // Undefined bytes between bodies are one collapsed row.
        for expected in [
            "00001040",
            "00001044",
            "00001048",
            "next  00001040",
            "??",
            "38h",
        ] {
            assert!(text.iter().any(|t| t == expected), "{expected} in {text:?}");
        }
        assert!(text.iter().any(|t| t == "…"), "third is pending: {text:?}");
        // The pending body of `third` is wanted; the displayed one is not.
        assert_eq!(h.app.program.wanted, vec![0x1080]);
        let point = fixture::text_position(&output, "00001044", 1);
        let epoch = h.app.selection_generation;
        h.frame(fixture::pointer_events(point));
        assert_eq!(h.app.selected, Some(0x1044));
        assert_eq!(h.app.result_scope, Some(0x1040), "opens the row's owner");
        assert_ne!(h.app.selection_generation, epoch);
        // Leaving `entry` keeps its rows from the remembered view.
        assert!(h.app.program.cache.get(0x1000).is_some());
        let text = fixture::rendered_text(&h.frame(vec![]));
        assert!(text.iter().any(|t| t == "0000100c"), "{text:?}");
    }

    #[test]
    fn navigation_during_a_pending_listing_queues_instead_of_restarting() {
        let context = egui::Context::default();
        let mut app = program_app();
        app.binary_path = Some("/nonexistent/ghidra-rust-listing".into());
        app.worker_epoch = 17;
        let pending = listing_pending(&mut app, vec![0x1040]);
        app.pending = Some(pending);
        app.navigate(0x1040, true, &context);
        assert_eq!(app.worker_epoch, 17);
        assert!(app.opening.is_none());
        assert!(matches!(
            app.pending.as_ref().map(|p| &p.request),
            Some(Request::Listing { .. })
        ));
        assert!(
            app.queue
                .iter()
                .any(|request| matches!(request, Request::Graph { address: 0x1040 }))
        );
        assert_eq!(app.program.reveal, Some(Reveal::Entry(0x1040)));
    }

    #[test]
    fn menus_on_rows_of_other_functions_use_their_cached_view() {
        let context = egui::Context::default();
        let mut app = program_app();
        let pending = listing_pending(&mut app, vec![0x1040]);
        let response = reply(&pending, vec![outcome(0x1040, 2)]);
        app.receive(pending, response, &context);
        let mut h = Harness::new(app);
        let output = h.frame(vec![]);
        let point = fixture::text_position(&output, "00001044", 1);
        let selected = h.app.selected;
        h.frame(fixture::secondary_events(point));
        let output = h.frame(vec![]);
        let text = fixture::rendered_text(&output);
        for item in [
            "Show in Graph",
            "Show in Hex",
            "Copy instruction",
            "Xrefs to this function",
        ] {
            assert!(text.iter().any(|t| t == item), "{item} in {text:?}");
        }
        assert_eq!(h.app.selected, selected, "a menu does not select");
        let point = fixture::text_position(&output, "Show in Graph", 1);
        h.frame(fixture::pointer_events(point));
        assert_eq!(h.app.tab, Tab::Graph);
        assert_eq!(h.app.selected, Some(0x1044));
        assert_eq!(h.app.result_scope, Some(0x1040));
    }

    /// The live request `app` would send for `request` now.
    fn function_pending(app: &DesktopApp, request: Request, address: u64) -> Pending {
        Pending {
            id: 1,
            request,
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: app
                .results
                .binding(address, app.local_override_state(address)),
        }
    }

    #[test]
    fn result_input_changes_re_resolve_without_moving_the_program_view() {
        let mut h = Harness::new(long_app());
        // As a user scroll would: it ends the initial reveal's pin.
        h.app.program.pin = None;
        h.app.program.top = Some(Position::new(0x2000, Rank::Section));
        h.frame(vec![]);
        // Scrolled to the end: the selected entry is far out of view.
        let away = h.top();
        assert!(away.address > 0x1040, "{away:?}");
        assert!(h.app.program.shown.unwrap().0.address > 0x1000);
        // Discovery adopts another function: the context changes and the
        // displayed function re-resolves with its selection.
        let info = h.app.info.as_mut().unwrap();
        info.functions.push(FunctionInfo {
            address: 0x10c0,
            name: "fourth".into(),
        });
        h.app.rebuild_filter();
        h.app
            .update_result_inputs(crate::function_results::Invalidation::Inventory);
        let selection = h.app.selection_generation;
        let context = h.context.clone();
        let deadline = Instant::now() + Duration::from_secs(2);
        while h.app.selection_generation == selection {
            assert!(
                Instant::now() < deadline,
                "the displayed function re-resolves"
            );
            h.app.poll_worker(&context);
            std::thread::yield_now();
        }
        h.frame(vec![]);
        assert_eq!(h.top(), away);
        // Its graph reply selects the kept instruction without a reveal.
        let pending = function_pending(&h.app, Request::Graph { address: 0x1000 }, 0x1000);
        h.app.receive(
            pending,
            Response::Graph {
                view: view(0x1000, 64),
            },
            &context,
        );
        h.app.settle_graph();
        assert!(h.app.view().is_some());
        assert_eq!(h.app.selected, Some(0x1000));
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.top(), away, "the Program view stays where it was");
        }
        // A user navigation still reveals its destination.
        h.app.navigate(0x1000, true, &context);
        h.frame(vec![]);
        assert!(h.top().address < away.address, "{:?}", h.top());
    }

    #[test]
    fn listing_waits_for_the_users_graph_presentation_and_decompilation() {
        let context = egui::Context::default();
        let mut app = program_app();
        let pending = listing_pending(&mut app, vec![0x1040]);
        let response = reply(&pending, vec![outcome(0x1040, 2)]);
        app.receive(pending, response, &context);
        assert!(app.listing_may_dispatch());
        // A click on `next` sends its Graph request.
        app.navigate_location(0x1044, Some(0x1040), false, &context);
        app.pending = Some(function_pending(
            &app,
            Request::Graph { address: 0x1040 },
            0x1040,
        ));
        assert!(!app.listing_may_dispatch());
        let pending = app.pending.take().unwrap();
        app.graph_preparation.pause(true, &context);
        app.receive(
            pending,
            Response::Graph {
                view: view(0x1040, 2),
            },
            &context,
        );
        // Nothing is sent or queued while the reply is prepared off-thread.
        assert!(app.pending.is_none() && app.queue.is_empty());
        assert!(!app.listing_may_dispatch(), "graph presentation goes first");
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert_eq!(app.view().map(|view| view.address), Some(0x1040));
        assert!(matches!(
            app.queue.front(),
            Some(Request::Decompile { address: 0x1040 })
        ));
        assert!(!app.listing_may_dispatch(), "decompilation goes next");
        let request = app.queue.pop_front().unwrap();
        app.pending = Some(function_pending(&app, request, 0x1040));
        assert!(!app.listing_may_dispatch());
        let pending = app.pending.take().unwrap();
        app.receive(
            pending,
            Response::Decompiled {
                address: 0x1040,
                text: "void next(void) {}".into(),
                mappings: vec![],
                semantics: Default::default(),
            },
            &context,
        );
        assert!(app.code.is_some());
        assert!(app.listing_may_dispatch(), "then the Program listing");
    }

    #[test]
    fn failures_block_only_the_culprit_and_function_scope_frees_the_cache() {
        let context = egui::Context::default();
        let mut app = program_app();
        let pending = listing_pending(&mut app, vec![0x1040]);
        app.receive(
            pending,
            Response::Error {
                message: "Analysis panicked; reopen the binary: x".into(),
            },
            &context,
        );
        let current = app.results.current_context().unwrap().clone();
        assert!(!app.program.cache.needs(0x1040, &current), "the culprit");
        assert!(app.program.cache.needs(0x1080, &current), "the rest retry");
        let pending = listing_pending(&mut app, vec![0x1080]);
        let response = reply(&pending, vec![outcome(0x1080, 1)]);
        app.receive(pending, response, &context);
        assert_eq!(app.observed_owner(0x1080), Some(0x1080));
        assert!(app.results.usage().charged >= app.program.cache.bytes());
        app.set_listing_scope(ListingScope::Function);
        assert!(app.program.cache.is_empty());
        assert_eq!(
            app.observed_owner(0x1080),
            None,
            "Function scope reads no cache"
        );
        assert!(!app.program.cache.needs(0x1040, &current), "still blocked");
    }

    #[test]
    fn discovery_allows_one_visible_only_listing_per_committed_batch() {
        let context = egui::Context::default();
        let mut app = program_app();
        // A longer `.text` puts two more entries below a short viewport.
        let info = app.info.as_mut().unwrap();
        info.sections[0].size = 0x1000;
        info.sections[0].file_size = 0x1000;
        info.sections[1].address = 0x2000;
        for address in [0x1800, 0x1c00] {
            info.functions.push(FunctionInfo {
                address,
                name: format!("f{address:x}"),
            });
        }
        let functions = info.functions.clone();
        app.results.update_inputs(functions, vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        let mut h = Harness::new(app);
        h.height = 240.0;
        h.frame(vec![]);
        let (wanted, prefetch) = (h.app.program.wanted.clone(), h.app.program.prefetch.clone());
        assert!(
            !wanted.is_empty() && !prefetch.is_empty(),
            "{wanted:?} {prefetch:?}"
        );
        assert!(prefetch.iter().all(|entry| !wanted.contains(entry)));
        let mut visible = wanted.clone();
        visible.sort_unstable();
        h.app.discovery_running = true;
        // Idle frames during discovery send nothing, not even prefetch.
        assert_eq!(h.app.next_listing_entries(), None);
        // A committed batch grants one turn; discovery holds until it goes.
        h.app.grant_listing_turn();
        assert!(h.app.listing_turn_outstanding());
        // User work goes first; the turn waits for it without expiring.
        h.app.pending = Some(function_pending(
            &h.app,
            Request::Graph { address: 0x1040 },
            0x1040,
        ));
        assert_eq!(h.app.next_listing_entries(), None);
        assert!(h.app.listing_turn_outstanding());
        h.app.pending = None;
        assert_eq!(h.app.next_listing_entries(), Some(visible.clone()));
        assert!(!h.app.listing_turn_outstanding(), "discovery continues");
        assert_eq!(h.app.next_listing_entries(), None, "one per batch");
        // The visible bodies load; the next batch's turn finds nothing
        // visible pending and sends nothing, so prefetch still waits.
        let pending = listing_pending(&mut h.app, visible.clone());
        let outcomes = visible.iter().map(|&entry| outcome(entry, 1)).collect();
        let response = reply(&pending, outcomes);
        h.app.receive(pending, response, &context);
        h.frame(vec![]);
        assert!(h.app.program.wanted.is_empty());
        assert!(!h.app.program.prefetch.is_empty());
        h.app.grant_listing_turn();
        assert_eq!(h.app.next_listing_entries(), None);
        assert!(!h.app.listing_turn_outstanding());
        assert_eq!(h.app.next_listing_entries(), None);
        // Once discovery ends, prefetch may go on idle frames again.
        h.app.discovery_running = false;
        assert!(h.app.next_listing_entries().is_some());
    }

    /// Waits until result inputs are published and the displayed function
    /// re-resolved, then delivers its graph reply as the worker would.
    fn settle_reresolution(h: &mut Harness, view: FunctionView) {
        let context = h.context.clone();
        let deadline = Instant::now() + Duration::from_secs(2);
        while h.app.results.preparing() {
            assert!(Instant::now() < deadline, "result inputs publish");
            h.app.poll_worker(&context);
            std::thread::yield_now();
        }
        h.app.poll_worker(&context);
        let address = view.address;
        let pending = function_pending(&h.app, Request::Graph { address }, address);
        h.app.receive(pending, Response::Graph { view }, &context);
        h.app.settle_graph();
        assert!(h.app.view().is_some());
    }

    #[test]
    fn renaming_the_displayed_function_keeps_the_program_view_and_selection() {
        let mut h = Harness::new(long_app());
        h.app.select_instruction(0x10a4);
        // As a user scroll would: it ends the initial reveal's pin.
        h.app.program.pin = None;
        h.app.program.top = Some(Position::new(0x10a0, Rank::Body));
        h.frame(vec![]);
        let (top, selected) = (h.top(), h.app.selected);
        assert_eq!(top.address, 0x10a0);
        let pending = Pending {
            id: 1,
            request: Request::Rename {
                address: 0x1000,
                name: "renamed".into(),
            },
            started: Instant::now(),
            selection: h.app.selection_generation,
            revision: h.app.revision,
            byte_origin: (h.app.selected, h.app.tab),
            bytes: None,
            result: None,
        };
        let context = h.context.clone();
        h.app.receive(
            pending,
            Response::Renamed {
                address: 0x1000,
                name: "renamed".into(),
            },
            &context,
        );
        assert_eq!(h.app.function_names(0x1000).map(|n| n.0), Some("renamed"));
        settle_reresolution(&mut h, view(0x1000, 64));
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.top(), top, "the Program view stays put");
            assert_eq!(h.app.selected, selected, "and so does the selection");
        }
    }

    #[test]
    fn a_failed_batch_is_isolated_so_only_its_culprit_is_blocked() {
        let context = egui::Context::default();
        let mut app = program_app();
        let info = app.info.as_mut().unwrap();
        info.functions.push(FunctionInfo {
            address: 0x10c0,
            name: "bad".into(),
        });
        let functions = info.functions.clone();
        app.results.update_inputs(functions, vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        // During discovery, the failure resumes it without spending a resume.
        app.discovery_running = true;
        app.binary_path = Some("/nonexistent/ghidra-rust-listing".into());
        let crash = |app: &mut DesktopApp, entries: Vec<u64>| {
            let pending = listing_pending(app, entries);
            app.receive(
                pending,
                Response::Error {
                    message: "Analysis panicked; reopen the binary: bad".into(),
                },
                &context,
            );
        };
        crash(&mut app, vec![0x1040, 0x1080, 0x10c0]);
        assert_eq!(app.discovery_resumes, 0);
        let current = app.results.current_context().unwrap().clone();
        for entry in [0x1040, 0x1080, 0x10c0] {
            assert!(
                app.program.cache.needs(entry, &current),
                "{entry:x} not blamed yet"
            );
        }
        // One entry per request, in order; successes are cached normally.
        app.discovery_running = false;
        for entry in [0x1040, 0x1080] {
            assert_eq!(app.next_listing_entries(), Some(vec![entry]));
            let pending = listing_pending(&mut app, vec![entry]);
            let response = reply(&pending, vec![outcome(entry, 1)]);
            app.receive(pending, response, &context);
            assert!(app.program.cache.get(entry).is_some());
        }
        assert_eq!(app.next_listing_entries(), Some(vec![0x10c0]));
        crash(&mut app, vec![0x10c0]);
        assert!(
            !app.program.cache.needs(0x10c0, &current),
            "the culprit is blocked"
        );
        for entry in [0x1040, 0x1080] {
            assert!(app.program.cache.get(entry).is_some(), "{entry:x} kept");
        }
        assert!(app.program.isolating.is_empty());
        // A scope switch drops any reply still in flight.
        let token = app.program.token;
        app.set_listing_scope(ListingScope::Function);
        assert_ne!(app.program.token, token);
    }

    #[test]
    fn a_reveal_stays_pinned_while_bodies_above_it_load_until_the_user_scrolls() {
        let context = egui::Context::default();
        let mut app = program_app();
        let info = app.info.as_mut().unwrap();
        info.sections[0].size = 0x1000;
        info.sections[0].file_size = 0x1000;
        for address in [0x1400, 0x1800] {
            info.functions.push(FunctionInfo {
                address,
                name: format!("f{address:x}"),
            });
        }
        let functions = info.functions.clone();
        app.results.update_inputs(functions, vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        let mut h = Harness::new(app);
        h.height = 300.0;
        h.frame(vec![]);
        // The screen row of the `f1800` header, if shown.
        let row_of = |h: &Harness| {
            let window = h.app.program.window.as_ref()?;
            let top = window
                .rows
                .binary_search_by_key(&h.top(), Row::position)
                .ok()?;
            let target = window
                .rows
                .binary_search_by_key(&Position::new(0x1800, Rank::Function), Row::position)
                .ok()?;
            let (first, last) = h.app.program.shown?;
            (first <= window.rows[target].position() && window.rows[target].position() <= last)
                .then(|| target.checked_sub(top))
                .flatten()
        };
        h.app.program.reveal = Some(Reveal::Entry(0x1800));
        h.frame(vec![]);
        let pinned = row_of(&h).expect("revealed");
        assert!(pinned > 0, "rows above the target are in view");
        // Bodies between the view's top and the target load and grow.
        let fill = |h: &mut Harness, entry: u64, count: u64| {
            let pending = listing_pending(&mut h.app, vec![entry]);
            let response = reply(&pending, vec![outcome(entry, count)]);
            h.app.receive(pending, response, &context);
            h.frame(vec![]);
        };
        fill(&mut h, 0x1080, 16);
        fill(&mut h, 0x1400, 32);
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(row_of(&h), Some(pinned), "the revealed row stays put");
        }
        // After the user scrolls, the view anchors by address again.
        h.wheel(-2.0 * theme::ROW_HEIGHT);
        for _ in 0..30 {
            h.frame(vec![]);
        }
        assert!(h.app.program.pin.is_none());
        let top = h.top();
        fill(&mut h, 0x1040, 16);
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.top(), top, "a later fill does not snap back");
        }
    }

    #[test]
    fn a_pin_near_the_program_end_keeps_the_row_it_was_drawn_at() {
        let context = egui::Context::default();
        let mut app = program_app();
        let info = app.info.as_mut().unwrap();
        info.sections[0].size = 0x1000;
        info.sections[0].file_size = 0x1000;
        for address in [0x1400, 0x1800] {
            info.functions.push(FunctionInfo {
                address,
                name: format!("f{address:x}"),
            });
        }
        let functions = info.functions.clone();
        app.results.update_inputs(functions, vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        let mut h = Harness::new(app);
        h.height = 300.0;
        h.frame(vec![]);
        let screen_row = |h: &Harness| {
            let window = h.app.program.window.as_ref()?;
            let top = window
                .rows
                .binary_search_by_key(&h.top(), Row::position)
                .ok()?;
            let target = window
                .rows
                .binary_search_by_key(&Position::new(0x1800, Rank::Function), Row::position)
                .ok()?;
            let (first, last) = h.app.program.shown?;
            let at = window.rows[target].position();
            (first <= at && at <= last)
                .then(|| target.checked_sub(top))
                .flatten()
        };
        // The last function: the view is clamped at the program end, so the
        // header is drawn lower than a centred reveal would place it.
        h.app.program.reveal = Some(Reveal::Entry(0x1800));
        h.frame(vec![]);
        h.frame(vec![]);
        let drawn = screen_row(&h).expect("revealed");
        // Its body loads below the header and the end clamp loosens.
        let pending = listing_pending(&mut h.app, vec![0x1800]);
        let response = reply(&pending, vec![outcome(0x1800, 32)]);
        h.app.receive(pending, response, &context);
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(screen_row(&h), Some(drawn), "the header does not jump");
        }
    }

    /// Program scope with the end of the `??` gap after `entry` expanded
    /// and drawn: its byte rows want `.text`'s one 0x100-byte page.
    fn bytes_harness() -> Harness {
        let mut app = program_app();
        app.program.expanded.expand(0x1030, 0x1040, None);
        let mut h = Harness::new(app);
        h.height = 600.0;
        h.frame(vec![]);
        assert_eq!(h.app.program.byte_wanted, vec![PAGE]);
        h
    }

    const PAGE: (u64, usize) = (0x1000, 0x100);

    /// A Listing byte read of `PAGE` as `dispatch_listing` binds it.
    fn page_pending(app: &mut DesktopApp) -> Pending {
        let origin = app.listing_page_origin();
        Pending {
            id: 1,
            request: Request::Bytes {
                address: PAGE.0,
                length: PAGE.1,
            },
            started: Instant::now(),
            selection: origin.selection,
            revision: origin.revision,
            byte_origin: origin.byte_origin,
            bytes: origin.bytes,
            result: None,
        }
    }

    #[test]
    fn byte_pages_go_last_only_to_a_running_worker() {
        let mut h = bytes_harness();
        assert_eq!(h.app.next_listing_page(), None, "no worker");
        h.app.dispatch_listing();
        assert!(h.app.pending.is_none() && h.app.opening.is_none());
        h.app.program.assume_worker = true;
        assert_eq!(h.app.next_listing_page(), Some(PAGE));
        // A graph the user awaits, the displayed function's decompilation
        // and a user's byte read all go first.
        h.app.pending = Some(function_pending(
            &h.app,
            Request::Graph { address: 0x1040 },
            0x1040,
        ));
        assert_eq!(h.app.next_listing_page(), None);
        h.app.pending = None;
        h.app
            .queue
            .push_back(Request::Decompile { address: 0x1000 });
        assert_eq!(h.app.next_listing_page(), None);
        h.app.queue.clear();
        h.app.discovery_bytes = Some((
            Request::Bytes {
                address: 0x2000,
                length: 16,
            },
            h.app.request_origin(),
        ));
        assert_eq!(h.app.next_listing_page(), None);
        h.app.discovery_bytes = None;
        // Other tabs and the Function scope read nothing.
        h.app.tab = Tab::Graph;
        assert_eq!(h.app.next_listing_page(), None);
        h.app.tab = Tab::Listing;
        assert_eq!(h.app.next_listing_page(), Some(PAGE));
        // During discovery, only a granted turn sends, and a page spends it.
        h.app.discovery_running = true;
        assert_eq!(h.app.next_listing_page(), None);
        h.app.grant_listing_turn();
        assert_eq!(h.app.next_listing_page(), Some(PAGE));
        assert!(!h.app.listing_turn_outstanding(), "discovery continues");
        assert_eq!(h.app.next_listing_page(), None, "one read per turn");
        assert_eq!(h.app.next_listing_entries(), None, "the turn is spent");
        h.app.discovery_running = false;
        // After the failure cap, nothing more is read.
        h.app.program.failures = MAX_LISTING_FAILURES;
        assert_eq!(h.app.next_listing_page(), None);
        h.app.program.failures = 0;
        h.app.set_listing_scope(ListingScope::Function);
        assert_eq!(h.app.next_listing_page(), None);
    }

    #[test]
    fn a_click_during_a_byte_read_queues_and_user_reads_are_not_cancelled() {
        let context = egui::Context::default();
        let mut h = bytes_harness();
        h.app.binary_path = Some("/nonexistent/ghidra-rust-listing".into());
        h.app.worker_epoch = 17;
        let pending = page_pending(&mut h.app);
        h.app.pending = Some(pending);
        let output = h.frame(vec![]);
        let point = fixture::text_position(&output, "next  00001040", 1);
        h.frame(fixture::pointer_events(point));
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.app.worker_epoch, 17, "the worker is not restarted");
        assert!(h.app.opening.is_none());
        assert!(matches!(
            h.app.pending.as_ref().map(|p| &p.request),
            Some(Request::Bytes { .. })
        ));
        assert!(
            h.app
                .queue
                .iter()
                .any(|request| matches!(request, Request::Graph { address: 0x1040 }))
        );
        // A Hex read the user starts meanwhile waits for the page and is
        // dispatched still current once the page arrives.
        h.app.queue.clear();
        h.app.binary_path = None;
        h.app.open_data(0x1020, 4, &context);
        assert!(h.app.hex.is_loading());
        let (request, origin) = h.app.discovery_bytes.clone().expect("waiting");
        assert!(h.app.byte_request_current(&request, origin));
        let pending = h.app.pending.take().unwrap();
        h.app.receive(
            pending,
            Response::Bytes {
                address: PAGE.0,
                bytes: vec![0x41; PAGE.1],
            },
            &context,
        );
        assert_eq!(h.app.program.bytes.byte(0x1020), Some(0x41));
        assert!(h.app.discovery_bytes.is_none(), "sent next");
        // Without a worker or binary in this test it then fails for that
        // reason; a replaced read would have been retired silently.
        assert_eq!(
            h.app.status,
            "No binary is available. Reopen it, then Retry."
        );
    }

    #[test]
    fn page_replies_are_kept_only_when_current_and_complete() {
        let context = egui::Context::default();
        let deliver = |change: &dyn Fn(&mut DesktopApp, &mut Vec<u8>)| {
            let mut h = bytes_harness();
            h.app.program.assume_worker = true;
            let pending = page_pending(&mut h.app);
            let mut bytes = vec![0x41; PAGE.1];
            change(&mut h.app, &mut bytes);
            h.app.status = "before".into();
            h.app.receive(
                pending,
                Response::Bytes {
                    address: PAGE.0,
                    bytes,
                },
                &context,
            );
            h
        };
        // Superseded by another token (a scope switch, another read) or
        // binary: dropped, and requested again later.
        for stale in [
            &(|app: &mut DesktopApp| app.program.token += 1) as &dyn Fn(&mut DesktopApp),
            &|app: &mut DesktopApp| app.generation += 1,
        ] {
            let h = deliver(&|app, _| stale(app));
            assert!(h.app.program.bytes.is_empty());
            assert!(!h.app.program.bytes.is_failed(PAGE.0));
            assert_eq!(h.app.status, "before");
        }
        // A short reply is not shown and not requested again; its bytes
        // keep `??` in the failed tone rather than the pending one.
        let unknown = |output: &egui::FullOutput| -> Vec<egui::Color32> {
            output
                .shapes
                .iter()
                .filter_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text) if text.galley.text() == "??" => {
                        Some(text.galley.job.sections[0].format.color)
                    }
                    _ => None,
                })
                .collect()
        };
        let pending = unknown(&bytes_harness().frame(vec![]));
        assert!(!pending.contains(&theme::BYTES_FAILED));
        let mut h = deliver(&|_, bytes| bytes.truncate(0x80));
        assert!(h.app.program.bytes.is_empty());
        assert!(h.app.program.bytes.is_failed(PAGE.0));
        assert_eq!(h.app.next_listing_page(), None);
        assert_eq!(h.app.status, "before");
        let failed = unknown(&h.frame(vec![]));
        assert_eq!(
            failed.iter().filter(|c| **c == theme::BYTES_FAILED).count(),
            0x10,
            "the expanded bytes"
        );
        // An over-long one is malformed: the worker stops.
        let h = deliver(&|_, bytes| bytes.push(0));
        assert!(h.app.program.bytes.is_empty());
        assert!(h.app.status.contains("worker stopped"), "{}", h.app.status);
        // The current, complete answer is shown without a tab or status
        // change.
        let mut h = deliver(&|_, _| {});
        assert_eq!(h.app.program.bytes.byte(0x10ff), Some(0x41));
        assert_eq!((h.app.tab, h.app.status.as_str()), (Tab::Listing, "before"));
        let text = fixture::rendered_text(&h.frame(vec![]));
        for expected in ["00001030", "41", "41h  'A'"] {
            assert!(text.iter().any(|t| t == expected), "{expected} in {text:?}");
        }
        assert!(h.app.program.byte_wanted.is_empty());
        // An error answer, a deadline or a crash marks the page failed.
        let mut h = bytes_harness();
        let pending = page_pending(&mut h.app);
        h.app.receive(
            pending,
            Response::Error {
                message: "unreadable".into(),
            },
            &context,
        );
        assert!(h.app.program.bytes.is_failed(PAGE.0));
        assert_eq!(h.app.program.failures, 0, "the worker answered");
        let mut h = bytes_harness();
        let pending = page_pending(&mut h.app);
        h.app.pending = Some(pending);
        h.app.fail_pending_listing();
        assert!(h.app.program.bytes.is_failed(PAGE.0));
        assert_eq!(h.app.program.failures, 1);
    }
}
