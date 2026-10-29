//! GUI-side search orchestration: one logical search at a time, bounded
//! per-frame capture of mutable text sources, source epochs that make text
//! results stale, and the exact destination resolver. Matching and page
//! validation live in `search`/`search_text`; this module only drives them.
use std::collections::BTreeMap;
use std::ops::Bound;
use std::time::{Duration, Instant};

use crate::model::{BinaryInfo, FunctionInfo, StringEntry, function_at};
use crate::result_store::TransientReservation;
use crate::search::{MemoryHit, MemorySearchSession, SearchState};
use crate::search_text::{
    MAX_SEARCH_CAPTURE_FIELD_BYTES, MAX_SEARCH_CAPTURE_RECORDS, SourceStatus, TextBinding,
    TextCorpusBuilder, TextHit, TextJob, TextProvenance, TextSearchResult, TextSearchSpec,
    TextSourceKey, TextSources,
};
use crate::session::Annotation;

/// Explicit revisions of the GUI's mutable text sources. Selection is not a
/// source: moving it never makes a text search stale.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceEpochs {
    /// Inventory names, labels applied to them, or the name table changed.
    pub inventory: u64,
    /// The adopted import/export table was replaced, failed or cleared.
    pub linkage: u64,
    /// Loaded string previews were replaced.
    pub strings: u64,
}

impl SourceEpochs {
    pub fn bump_inventory(&mut self) {
        self.inventory = self.inventory.wrapping_add(1);
    }
    pub fn bump_linkage(&mut self) {
        self.linkage = self.linkage.wrapping_add(1);
    }
    pub fn bump_strings(&mut self) {
        self.strings = self.strings.wrapping_add(1);
    }
}

/// How the memory dialog encodes its literal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum MemoryMode {
    #[default]
    Hex,
    Ascii,
    Utf16Le,
}

impl MemoryMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Ascii => "ASCII",
            Self::Utf16Le => "UTF-16LE",
        }
    }
}

/// One memory query. `session` is absent when its fixed reservation or
/// domain could not be admitted: the search is Unavailable before any work.
pub(crate) struct MemorySearch {
    pub session: Option<MemorySearchSession>,
    pub mode: MemoryMode,
    /// The submitted pattern's canonical spelling, cached for every row.
    pub pattern: String,
    /// The in-flight page was lost with a worker replacement that has not yet
    /// verified the same source; nothing is dispatched until it has.
    pub interrupted: bool,
}

impl MemorySearch {
    pub fn state(&self) -> SearchState {
        self.session
            .as_ref()
            .map_or(SearchState::Unavailable, MemorySearchSession::state)
    }

    pub fn hits(&self) -> &[MemoryHit] {
        self.session.as_ref().map_or(&[], MemorySearchSession::hits)
    }
}

pub(crate) enum TextPhase {
    /// Waiting for an earlier query's canceled job to exit before capture.
    Queued,
    Capturing(Box<Capture>),
    Running(TextJob),
    Done,
}

/// One program-text query over loaded sources.
pub(crate) struct TextSearch {
    pub spec: TextSearchSpec,
    /// Source revisions at submission; table digests are set at job start.
    pub binding: TextBinding,
    pub phase: TextPhase,
    /// The adopted result keeps its reservation for as long as it is shown.
    pub result: Option<TextSearchResult>,
    pub state: SearchState,
}

impl TextSearch {
    pub fn new(spec: TextSearchSpec, binding: TextBinding) -> Self {
        Self {
            spec,
            binding,
            phase: TextPhase::Queued,
            result: None,
            state: SearchState::Searching,
        }
    }

    pub fn hits(&self) -> &[TextHit] {
        self.result.as_ref().map_or(&[], |result| &result.hits)
    }

    /// Names/Imports/Exports/Labels/Comments/Strings readiness and omissions.
    pub fn sources(&self) -> Option<[SourceStatus; 6]> {
        self.result.as_ref().map(|result| result.sources)
    }

    pub fn saved(&self) -> bool {
        self.hits()
            .iter()
            .any(|hit| hit.provenance == TextProvenance::Saved)
    }
}

pub(crate) enum SearchKind {
    Memory(MemorySearch),
    Text(TextSearch),
}

/// The displayed logical search.
pub(crate) struct SearchView {
    pub id: u64,
    pub kind: SearchKind,
}

/// Local result-table state; single clicks never navigate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResultTable {
    pub selected: Option<usize>,
    /// The table was clicked last; Enter then opens the selection.
    pub focus: bool,
}

impl SearchView {
    pub fn state(&self) -> SearchState {
        match &self.kind {
            SearchKind::Memory(memory) => memory.state(),
            SearchKind::Text(text) => text.state,
        }
    }

    pub fn count(&self) -> usize {
        match &self.kind {
            SearchKind::Memory(memory) => memory.hits().len(),
            SearchKind::Text(text) => text.hits().len(),
        }
    }

    /// Searching: pages, capture or matching may still change the results.
    pub fn active(&self) -> bool {
        self.state() == SearchState::Searching
    }
}

/// Search state owned by the desktop; every field is transient and binary-scoped.
#[derive(Default)]
pub(crate) struct Searches {
    pub current: Option<SearchView>,
    pub table: ResultTable,
    /// A canceled text job that still owns its corpus and reservation. At most
    /// one exists; the next text capture waits for it.
    pub retiring: Option<TextJob>,
    next_id: u64,
    /// Whether the next idle worker turn belongs to a memory page rather than
    /// maintenance (symbol names, linkage, discovery).
    pub search_turn: bool,
    /// Round-robin position among maintenance candidates while searching.
    pub maintenance_turn: usize,
}

impl Searches {
    /// Every new search gets a fresh identity; old replies can never match it.
    pub fn next_id(&mut self) -> u64 {
        self.next_id = self.next_id.checked_add(1).expect("search id exhausted");
        self.next_id
    }

    /// Replaces the displayed search. A running text job is canceled and kept
    /// until it exits so its corpus is never duplicated by the next capture.
    pub fn replace(&mut self, view: Option<SearchView>) {
        if let Some(SearchView {
            kind: SearchKind::Text(text),
            ..
        }) = &mut self.current
        {
            Self::retire(&mut self.retiring, text);
        }
        self.current = view;
        self.table = ResultTable::default();
        self.search_turn = true;
    }

    /// Close/new binary/project: drop every result and binding. A retiring
    /// job keeps its corpus and reservation until its thread exits.
    pub fn clear(&mut self) {
        self.replace(None);
        self.maintenance_turn = 0;
    }

    fn retire(retiring: &mut Option<TextJob>, text: &mut TextSearch) {
        if let TextPhase::Running(job) = std::mem::replace(&mut text.phase, TextPhase::Done) {
            job.cancel();
            // Dropping a second retiring job moves its join to a reaper thread.
            *retiring = Some(job);
        }
    }

    /// Cancel the displayed text query's capture or job, keeping its hits.
    pub fn cancel_text(&mut self) {
        if let Some(SearchView {
            kind: SearchKind::Text(text),
            ..
        }) = &mut self.current
            && text.state == SearchState::Searching
        {
            Self::retire(&mut self.retiring, text);
            text.phase = TextPhase::Done;
            text.state = SearchState::Canceled;
        }
    }

    /// Source revisions changed under the displayed text query.
    pub fn stale_text(&mut self) {
        if let Some(SearchView {
            kind: SearchKind::Text(text),
            ..
        }) = &mut self.current
            && matches!(
                text.state,
                SearchState::Searching | SearchState::Complete | SearchState::Partial
            )
        {
            Self::retire(&mut self.retiring, text);
            text.phase = TextPhase::Done;
            text.state = SearchState::Stale;
        }
    }

    /// Joins a finished retiring job without waiting; returns whether none remains.
    pub fn reap(&mut self) -> bool {
        if let Some(job) = &mut self.retiring
            && job.is_finished()
        {
            let _ = job.try_finish();
            self.retiring = None;
        }
        self.retiring.is_none()
    }

    /// The memory query that wants another page dispatched.
    pub fn memory_page(&mut self) -> Option<(u64, &mut MemorySearch)> {
        match &mut self.current {
            Some(SearchView {
                id,
                kind: SearchKind::Memory(memory),
                ..
            }) if memory.state() == SearchState::Searching && !memory.interrupted => {
                Some((*id, memory))
            }
            _ => None,
        }
    }

    /// The displayed memory query, if it is the one with identity `id`.
    pub fn memory(&mut self, id: u64) -> Option<&mut MemorySearch> {
        match &mut self.current {
            Some(SearchView {
                id: current,
                kind: SearchKind::Memory(memory),
                ..
            }) if *current == id => Some(memory),
            _ => None,
        }
    }

    pub fn memory_searching(&self) -> bool {
        matches!(
            &self.current,
            Some(SearchView { kind: SearchKind::Memory(memory), .. })
                if memory.state() == SearchState::Searching
        )
    }
}

/// Where a capture resumes. Vectors use indices; annotations resume after the
/// last captured address through `BTreeMap::range`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cursor {
    Names(usize),
    Labels(Option<u64>),
    Comments(Option<u64>),
    Strings(usize),
    Done,
}

/// Borrowed mutable sources for one capture slice.
pub(crate) struct CaptureInput<'a> {
    pub functions: &'a [FunctionInfo],
    pub names: TextProvenance,
    pub annotations: Option<&'a BTreeMap<u64, Annotation>>,
    pub strings: &'a [StringEntry],
    pub strings_provenance: TextProvenance,
}

/// Bounded copying of the enabled mutable sources into a charged corpus.
/// No matching, folding or sorting happens here.
pub(crate) struct Capture {
    builder: TextCorpusBuilder,
    cursor: Cursor,
    sources: TextSources,
}

impl Capture {
    pub fn new(lease: TransientReservation, sources: TextSources) -> Result<Self, String> {
        let mut capture = Self {
            builder: TextCorpusBuilder::new(lease)?,
            cursor: Cursor::Names(0),
            sources,
        };
        capture.skip_disabled();
        Ok(capture)
    }

    fn skip_disabled(&mut self) {
        loop {
            let source = match self.cursor {
                Cursor::Names(_) => TextSources::NAMES,
                Cursor::Labels(_) => TextSources::LABELS,
                Cursor::Comments(_) => TextSources::COMMENTS,
                Cursor::Strings(_) => TextSources::STRINGS,
                Cursor::Done => return,
            };
            if self.sources.contains(source) {
                return;
            }
            self.advance();
        }
    }

    fn advance(&mut self) {
        self.cursor = match self.cursor {
            Cursor::Names(_) => Cursor::Labels(None),
            Cursor::Labels(_) => Cursor::Comments(None),
            Cursor::Comments(_) => Cursor::Strings(0),
            Cursor::Strings(_) | Cursor::Done => Cursor::Done,
        };
        self.skip_disabled();
    }

    pub fn finished(&self) -> bool {
        self.cursor == Cursor::Done
    }

    /// Copies whole records until the first of `budget`, the per-frame record
    /// count or the per-frame copied-field bytes. A field that does not fit
    /// the rest of this slice waits for the next one. `admit` must grow the
    /// given reservation before the builder allocates. Returns `finished()`.
    pub fn step(
        &mut self,
        input: &CaptureInput<'_>,
        budget: Duration,
        admit: &mut dyn FnMut(&TransientReservation, usize) -> bool,
    ) -> bool {
        let started = Instant::now();
        let token = self.builder.reservation().clone();
        let (mut records, mut bytes) = (0usize, 0usize);
        while self.cursor != Cursor::Done {
            if records == MAX_SEARCH_CAPTURE_RECORDS
                || (records % 64 == 63 && started.elapsed() >= budget)
            {
                break;
            }
            let Some((key, address, text, provenance)) = self.peek(input) else {
                self.advance();
                continue;
            };
            if records != 0 && bytes + text.len() > MAX_SEARCH_CAPTURE_FIELD_BYTES {
                break;
            }
            match self
                .builder
                .push(key, address, text, provenance, |n| admit(&token, n))
            {
                Ok(true) => {}
                Ok(false) => {
                    // Corpus or store admission refused a whole record.
                    self.cursor = Cursor::Done;
                    break;
                }
                // An out-of-order or over-limit record is omitted, never reordered.
                Err(_) => self.builder.mark_partial(),
            }
            records += 1;
            bytes += text.len();
            self.next_record(key);
        }
        self.finished()
    }

    /// The record at the cursor, or `None` when its source is exhausted.
    fn peek<'a>(
        &self,
        input: &CaptureInput<'a>,
    ) -> Option<(TextSourceKey, u64, &'a str, TextProvenance)> {
        let annotation = |after: Option<u64>, comment: bool| {
            let range = (
                after.map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            );
            input
                .annotations?
                .range(range)
                .map(|(&address, note)| {
                    let text = if comment { &note.comment } else { &note.label };
                    (address, text.as_str())
                })
                .find(|(_, text)| !text.is_empty())
        };
        match self.cursor {
            Cursor::Names(index) => input.functions.get(index).map(|function| {
                (
                    TextSourceKey::Name(function.address),
                    function.address,
                    function.name.as_str(),
                    input.names,
                )
            }),
            Cursor::Labels(after) => annotation(after, false).map(|(address, text)| {
                (
                    TextSourceKey::Label(address),
                    address,
                    text,
                    TextProvenance::Live,
                )
            }),
            Cursor::Comments(after) => annotation(after, true).map(|(address, text)| {
                (
                    TextSourceKey::Comment(address),
                    address,
                    text,
                    TextProvenance::Live,
                )
            }),
            Cursor::Strings(index) => input.strings.get(index).map(|string| {
                (
                    TextSourceKey::String(index),
                    string.address,
                    string.text.as_str(),
                    input.strings_provenance,
                )
            }),
            Cursor::Done => None,
        }
    }

    fn next_record(&mut self, key: TextSourceKey) {
        self.cursor = match (self.cursor, key) {
            (Cursor::Names(index), _) => Cursor::Names(index + 1),
            (Cursor::Labels(_), TextSourceKey::Label(address)) => Cursor::Labels(Some(address)),
            (Cursor::Comments(_), TextSourceKey::Comment(address)) => {
                Cursor::Comments(Some(address))
            }
            (Cursor::Strings(index), _) => Cursor::Strings(index + 1),
            (cursor, _) => cursor,
        };
    }

    pub fn into_builder(self) -> TextCorpusBuilder {
        self.builder
    }
}

/// Where activating a result goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    /// An instruction whose owner is proved by an inventory entry or an
    /// observed CFG/semantic/history owner.
    Code { address: u64, owner: u64 },
    /// Mapped bytes opened in Hex at exactly `address`.
    Data { address: u64, length: u64 },
}

/// Exact destination for a byte match or address-bearing text record. Code
/// requires file-backed executable membership AND an exact known entry or an
/// observed owner of exactly this PC; nothing else becomes code. Any other
/// mapped address opens Hex, even inside an executable section. No nearest
/// function or symbol extent is ever consulted.
pub(crate) fn resolve(
    info: &BinaryInfo,
    address: u64,
    length: u64,
    observed_owner: impl FnOnce(u64) -> Option<u64>,
) -> Option<Destination> {
    if crate::call_analysis::code_address(info, address) {
        let owner = function_at(&info.functions, address)
            .map(|function| function.address)
            .or_else(|| observed_owner(address));
        if let Some(owner) = owner {
            return Some(Destination::Code { address, owner });
        }
    }
    info.sections
        .iter()
        .any(|section| address >= section.address && address - section.address < section.size)
        .then_some(Destination::Data {
            address,
            length: length.max(1),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_results::FunctionResults;
    use crate::model::SectionInfo;

    fn info() -> BinaryInfo {
        BinaryInfo {
            path: "fixture".into(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 0x3000,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![
                SectionInfo {
                    name: ".text".into(),
                    address: 0x1000,
                    size: 0x1000,
                    file_offset: 0,
                    file_size: 0x1000,
                    executable: true,
                },
                SectionInfo {
                    name: ".bss".into(),
                    address: 0x4000,
                    size: 0x100,
                    file_offset: 0x1000,
                    file_size: 0,
                    executable: false,
                },
            ],
            functions: vec![FunctionInfo {
                address: 0x1000,
                name: "entry".into(),
            }],
            warnings: Vec::new(),
            functions_truncated: false,
        }
    }

    #[test]
    fn byte_matches_become_code_only_with_an_exact_owner() {
        let info = info();
        // An exact inventory entry owns itself.
        assert_eq!(
            resolve(&info, 0x1000, 4, |_| None),
            Some(Destination::Code {
                address: 0x1000,
                owner: 0x1000
            })
        );
        // Inside an instruction or function body without observed ownership:
        // the exact bytes in Hex, never the nearest function.
        assert_eq!(
            resolve(&info, 0x1003, 6, |_| None),
            Some(Destination::Data {
                address: 0x1003,
                length: 6
            })
        );
        // An observed owner of exactly this PC.
        assert_eq!(
            resolve(&info, 0x1010, 6, |pc| (pc == 0x1010).then_some(0x1000)),
            Some(Destination::Code {
                address: 0x1010,
                owner: 0x1000
            })
        );
        // Zero-fill data stays data; unmapped addresses have no destination.
        assert_eq!(
            resolve(&info, 0x4010, 1, |_| Some(0x1000)),
            Some(Destination::Data {
                address: 0x4010,
                length: 1
            })
        );
        assert_eq!(resolve(&info, 0x9000, 1, |_| Some(0x1000)), None);
    }

    fn reservation(store: &mut FunctionResults, bytes: usize) -> TransientReservation {
        store.reserve_transient(bytes, &[]).unwrap()
    }

    #[test]
    fn capture_copies_enabled_sources_in_key_order_within_frame_limits() {
        let mut store = FunctionResults::default();
        let functions: Vec<_> = (0..20_000u64)
            .map(|i| FunctionInfo {
                address: 0x1000 + i,
                name: format!("f{i}"),
            })
            .collect();
        let mut annotations = BTreeMap::new();
        annotations.insert(
            0x10,
            Annotation {
                label: "lbl".into(),
                comment: String::new(),
                decoded: Vec::new(),
            },
        );
        annotations.insert(
            0x20,
            Annotation {
                label: String::new(),
                comment: "note".into(),
                decoded: Vec::new(),
            },
        );
        let strings = vec![StringEntry {
            address: 0x30,
            text: "hello".into(),
            encoding: "ascii".into(),
        }];
        let input = CaptureInput {
            functions: &functions,
            names: TextProvenance::Live,
            annotations: Some(&annotations),
            strings: &strings,
            strings_provenance: TextProvenance::Saved,
        };
        let lease = reservation(&mut store, crate::search_text::TEXT_CORPUS_BASE_BYTES);
        let mut capture = Capture::new(lease, TextSources::ALL).unwrap();
        let mut admit = |token: &TransientReservation, n| store.grow_transient(token, n, &[]);
        // 20,000 names exceed one frame's 8,192-record slice.
        assert!(!capture.step(&input, Duration::from_secs(60), &mut admit));
        assert_eq!(capture.builder.records(), MAX_SEARCH_CAPTURE_RECORDS);
        let mut frames = 1;
        loop {
            frames += 1;
            if capture.step(&input, Duration::from_secs(60), &mut admit) {
                break;
            }
        }
        assert_eq!(frames, 3);
        // Names, the one nonempty label, the one nonempty comment, one string.
        assert_eq!(capture.builder.records(), 20_003);

        // Disabled sources are skipped without copying.
        let lease = reservation(&mut store, crate::search_text::TEXT_CORPUS_BASE_BYTES);
        let mut capture = Capture::new(
            lease,
            TextSources(TextSources::COMMENTS.0 | TextSources::STRINGS.0),
        )
        .unwrap();
        let mut admit = |token: &TransientReservation, n| store.grow_transient(token, n, &[]);
        assert!(capture.step(&input, Duration::from_secs(60), &mut admit));
        assert_eq!(capture.builder.records(), 2);
    }

    #[test]
    fn oversized_fields_wait_for_a_fresh_slice_and_refused_admission_stops() {
        let mut store = FunctionResults::default();
        let big = "c".repeat(60 * 1024);
        let annotations: BTreeMap<u64, Annotation> = (0..40u64)
            .map(|address| {
                (
                    address,
                    Annotation {
                        label: String::new(),
                        comment: big.clone(),
                        decoded: Vec::new(),
                    },
                )
            })
            .collect();
        let input = CaptureInput {
            functions: &[],
            names: TextProvenance::Live,
            annotations: Some(&annotations),
            strings: &[],
            strings_provenance: TextProvenance::Live,
        };
        let lease = reservation(&mut store, crate::search_text::TEXT_CORPUS_BASE_BYTES);
        let mut capture = Capture::new(lease, TextSources::COMMENTS).unwrap();
        let mut admit = |token: &TransientReservation, n| store.grow_transient(token, n, &[]);
        assert!(!capture.step(&input, Duration::from_secs(60), &mut admit));
        // 1 MiB per frame holds 17 whole 60 KiB comments; the 18th waits.
        assert_eq!(capture.builder.records(), 17);
        assert!(!capture.step(&input, Duration::from_secs(60), &mut admit));
        assert_eq!(capture.builder.records(), 34);

        // A refused growth stops capture without copying part of a record.
        let lease = reservation(&mut store, crate::search_text::TEXT_CORPUS_BASE_BYTES);
        let mut capture = Capture::new(lease, TextSources::COMMENTS).unwrap();
        let mut granted = 0;
        let mut admit = |_: &TransientReservation, _| {
            granted += 1;
            granted <= 3
        };
        assert!(capture.step(&input, Duration::from_secs(60), &mut admit));
        assert_eq!(capture.builder.records(), 3);
    }
}
