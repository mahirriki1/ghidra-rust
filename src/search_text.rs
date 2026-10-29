//! Loaded-text matching. GUI capture, scheduling, revision adoption and navigation
//! belong to the caller; this module never obtains more metadata or demangles.
use std::collections::LinkedList;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use crate::linkage::Linkage;
use crate::model::*;
use crate::result_store::TransientReservation;
use crate::search::{CompiledPattern, SearchState};
use crate::symbol_names::SymbolNames;

pub const MAX_SEARCH_CORPUS_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_SEARCH_RESULT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SEARCH_SNIPPET_BYTES: usize = 160;
pub const MAX_SEARCH_CAPTURE_RECORDS: usize = 8192;
pub const MAX_SEARCH_CAPTURE_FIELD_BYTES: usize = 1024 * 1024;
const CORPUS_CHUNK_RECORDS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TextSources(pub u8);
impl TextSources {
    pub const NAMES: Self = Self(1);
    pub const IMPORTS: Self = Self(2);
    pub const EXPORTS: Self = Self(4);
    pub const LABELS: Self = Self(8);
    pub const COMMENTS: Self = Self(16);
    pub const STRINGS: Self = Self(32);
    pub const ALL: Self = Self(63);
    pub fn contains(self, source: Self) -> bool {
        self.0 & source.0 != 0
    }
}
impl Default for TextSources {
    fn default() -> Self {
        Self::ALL
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextSearchSpec {
    pub query: String,
    pub match_case: bool,
    pub sources: TextSources,
}
impl TextSearchSpec {
    pub fn validate(&self) -> Result<(), String> {
        if self.query.is_empty() || self.query.len() > MAX_SEARCH_PATTERN_BYTES {
            return Err("Use a literal of 1–256 UTF-8 bytes".into());
        }
        if self.sources.0 == 0 || self.sources.0 & !TextSources::ALL.0 != 0 {
            return Err("Select at least one valid source".into());
        }
        Ok(())
    }
    fn compile(&self) -> Result<CompiledPattern, String> {
        self.validate()?;
        // Byte-oriented literals fold ASCII only, including inside UTF-8 text.
        let bytes = self.query.as_bytes().to_vec();
        let mask = vec![255; bytes.len()];
        crate::search::compile_text_literal(bytes, mask, self.match_case)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextSourceKey {
    Name(u64),
    Import(u32),
    Export(u32),
    Label(u64),
    Comment(u64),
    String(usize),
}
impl TextSourceKey {
    pub fn source(self) -> TextSources {
        match self {
            Self::Name(_) => TextSources::NAMES,
            Self::Import(_) => TextSources::IMPORTS,
            Self::Export(_) => TextSources::EXPORTS,
            Self::Label(_) => TextSources::LABELS,
            Self::Comment(_) => TextSources::COMMENTS,
            Self::String(_) => TextSources::STRINGS,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextProvenance {
    Live,
    Saved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceStatus {
    Available,
    Partial,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextBinding {
    pub binary_sha256: String,
    pub generation: u64,
    pub search_id: u64,
    pub annotation_revision: u64,
    pub inventory_revision: u64,
    pub symbol_revision: u64,
    pub linkage_revision: u64,
    pub strings_revision: u64,
    pub symbol_digest: Option<String>,
    pub linkage_digest: Option<String>,
}

pub const VARIANT_INVENTORY: u8 = 1;
pub const VARIANT_RAW: u8 = 2;
pub const VARIANT_DISPLAY: u8 = 4;
pub const VARIANT_TEXT: u8 = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextHit {
    pub key: TextSourceKey,
    pub address: Option<u64>,
    pub matched_variants: u8,
    /// UTF-8 range in the chosen original field, never a binary byte extent.
    pub text_range: Range<usize>,
    pub snippet: String,
    pub provenance: TextProvenance,
}

struct TextRecord {
    key: TextSourceKey,
    address: u64,
    text: Box<str>,
    provenance: TextProvenance,
}

/// Initial charge before constructing a corpus. Chunk and field charges grow
/// before allocation; the linked chunks never copy the accumulated corpus.
pub const TEXT_CORPUS_BASE_BYTES: usize = size_of::<TextCorpus>() + size_of::<TextCorpusBuilder>();
/// Pre-reserve result slots, snippets, matcher and thread/sort bookkeeping.
/// Sorting is in-place and requires no separate result index.
pub const TEXT_JOB_RESERVATION_BYTES: usize = MAX_SEARCH_RESULT_BYTES + 16 * 1024;

pub struct TextCorpusBuilder {
    corpus: TextCorpus,
    last: Option<TextSourceKey>,
    stopped: bool,
    counts: [usize; 6],
}
pub struct TextCorpus {
    chunks: LinkedList<Vec<TextRecord>>,
    copied_bytes: usize,
    field_bytes: usize,
    records: usize,
    partial: bool,
    lease: TransientReservation,
    symbols: Option<Arc<SymbolNames>>,
    linkage: Option<Arc<Linkage>>,
    status: [SourceStatus; 6],
}
impl TextCorpusBuilder {
    pub fn new(lease: TransientReservation) -> Result<Self, String> {
        if lease.capacity() < TEXT_CORPUS_BASE_BYTES {
            return Err("Corpus reservation is too small".into());
        }
        Ok(Self {
            corpus: TextCorpus {
                chunks: LinkedList::new(),
                copied_bytes: TEXT_CORPUS_BASE_BYTES,
                records: 0,
                field_bytes: 0,
                partial: false,
                lease,
                symbols: None,
                linkage: None,
                status: [SourceStatus::Available; 6],
            },
            last: None,
            stopped: false,
            counts: [0; 6],
        })
    }
    pub fn reservation(&self) -> &TransientReservation {
        &self.corpus.lease
    }
    pub fn bytes(&self) -> usize {
        self.corpus.copied_bytes
    }
    pub fn records(&self) -> usize {
        self.corpus.records
    }
    pub fn mark_partial(&mut self) {
        self.corpus.partial = true;
    }

    /// Capture mutable fields only, in key order (Names, Labels, Comments,
    /// Strings). The admission callback must grow this builder's reservation.
    /// False means stop capture: no part of that record was copied.
    pub fn push(
        &mut self,
        key: TextSourceKey,
        address: u64,
        text: &str,
        provenance: TextProvenance,
        admit: impl FnOnce(usize) -> bool,
    ) -> Result<bool, String> {
        if self.stopped {
            return Ok(false);
        }
        if matches!(key, TextSourceKey::Import(_) | TextSourceKey::Export(_))
            || self.last.is_some_and(|last| last >= key)
            || matches!(key, TextSourceKey::Name(a) | TextSourceKey::Label(a) | TextSourceKey::Comment(a) if a != address)
        {
            return Err("Invalid mutable text record identity/order".into());
        }
        let count_limit = match key {
            TextSourceKey::Name(_) => MAX_FUNCTIONS,
            TextSourceKey::Label(_) | TextSourceKey::Comment(_) => crate::session::MAX_ANNOTATIONS,
            TextSourceKey::String(index) if index < MAX_PROJECT_STRINGS => MAX_PROJECT_STRINGS,
            _ => return Err("Invalid captured text source".into()),
        };
        let source = key.source().0.trailing_zeros() as usize;
        if self.counts[source] >= count_limit {
            return Err("Too many captured text records".into());
        }
        let new_chunk = self
            .corpus
            .chunks
            .back()
            .is_none_or(|chunk| chunk.len() == CORPUS_CHUNK_RECORDS);
        // LinkedList node: two links plus the Vec descriptor; capacity is exact.
        let container = if new_chunk {
            2 * size_of::<usize>()
                + size_of::<Vec<TextRecord>>()
                + CORPUS_CHUNK_RECORDS * size_of::<TextRecord>()
        } else {
            0
        };
        let extra = text
            .len()
            .checked_add(container)
            .ok_or("Corpus size overflow")?;
        let next = self
            .corpus
            .copied_bytes
            .checked_add(extra)
            .ok_or("Corpus size overflow")?;
        if next > MAX_SEARCH_CORPUS_BYTES || !admit(extra) {
            self.corpus.partial = true;
            self.stopped = true;
            return Ok(false);
        }
        if new_chunk {
            self.corpus
                .chunks
                .push_back(Vec::with_capacity(CORPUS_CHUNK_RECORDS));
        }
        self.corpus
            .chunks
            .back_mut()
            .expect("chunk allocated")
            .push(TextRecord {
                key,
                address,
                text: text.into(),
                provenance,
            });
        self.corpus.copied_bytes = next;
        self.corpus.records += 1;
        self.corpus.field_bytes += text.len();
        self.counts[source] += 1;
        self.last = Some(key);
        Ok(true)
    }
    /// Adopted immutable owners are borrowed through Arcs, never recopied or
    /// charged as source copies. Their text still consumes the scan allowance.
    pub fn finish(
        mut self,
        symbols: Option<Arc<SymbolNames>>,
        linkage: Option<Arc<Linkage>>,
        status: [SourceStatus; 6],
    ) -> TextCorpus {
        self.corpus.symbols = symbols;
        self.corpus.linkage = linkage;
        self.corpus.status = status;
        if self.corpus.symbols.as_ref().is_some_and(|s| s.truncated()) {
            self.corpus.status[0] = SourceStatus::Partial;
        }
        if self.corpus.linkage.as_ref().is_some_and(|l| l.partial()) {
            self.corpus.status[1] = SourceStatus::Partial;
            self.corpus.status[2] = SourceStatus::Partial;
        }
        crate::performance::event("search_text_corpus_bytes", self.corpus.copied_bytes as u64);
        self.corpus
    }
}

#[derive(Clone, Default)]
pub struct TextCancellation(Arc<AtomicBool>);
impl TextCancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn canceled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub struct TextSearchResult {
    pub binding: TextBinding,
    pub spec: TextSearchSpec,
    pub hits: Vec<TextHit>,
    pub state: SearchState,
    /// Source omissions/readiness, in Names/Imports/Exports/Labels/Comments/Strings order.
    pub sources: [SourceStatus; 6],
    pub scanned: usize,
    _reservation: TransientReservation,
}

/// One running job. The caller keeps at most one and one pending *spec*.
/// A finished handle can be joined without waiting; cancellation never detaches it.
pub struct TextJob {
    cancellation: TextCancellation,
    handle: Option<JoinHandle<TextSearchResult>>,
}
impl TextJob {
    pub fn start(
        corpus: TextCorpus,
        spec: TextSearchSpec,
        binding: TextBinding,
        reservation: TransientReservation,
    ) -> Result<Self, String> {
        spec.validate()?;
        if reservation.capacity() < TEXT_JOB_RESERVATION_BYTES {
            return Err("Text job reservation is too small".into());
        }
        if !crate::search::valid_digest(&binding.binary_sha256)
            || binding.symbol_digest.as_deref() != corpus.symbols.as_ref().map(|s| s.digest())
            || binding.linkage_digest.as_deref()
                != corpus.linkage.as_ref().map(|s| s.digest.as_str())
        {
            return Err("Text corpus binding mismatch".into());
        }
        // Inputs can originate in reusable GUI buffers with large capacities.
        let spec = TextSearchSpec {
            query: spec.query.clone(),
            ..spec
        };
        let binding = binding.clone();
        let cancellation = TextCancellation::default();
        let cancel = cancellation.clone();
        let handle = std::thread::Builder::new()
            .name("program-text-search".into())
            .spawn(move || run(corpus, spec, binding, reservation, &cancel))
            .map_err(|e| format!("Cannot start text search: {e}"))?;
        Ok(Self {
            cancellation,
            handle: Some(handle),
        })
    }
    pub fn cancel(&self) {
        self.cancellation.cancel();
    }
    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(|h| h.is_finished())
    }
    pub fn try_finish(&mut self) -> Result<Option<TextSearchResult>, String> {
        if !self.is_finished() {
            return Ok(None);
        }
        self.handle
            .take()
            .map(|h| h.join().map_err(|_| "Text search failed".into()))
            .transpose()
    }
    /// Move an old job to an off-frame reaper before launching a pending spec.
    pub fn cancel_and_join(mut self) -> Result<(), String> {
        self.cancel();
        if let Some(handle) = self.handle.take() {
            handle.join().map_err(|_| "Text search failed")?;
        }
        Ok(())
    }
}
impl Drop for TextJob {
    fn drop(&mut self) {
        self.cancel();
        if let Some(handle) = self.handle.take() {
            // Normal controllers keep the handle until try_finish. This final
            // reaper also keeps dropping a controller off the frame's wait path.
            let _ = std::thread::Builder::new()
                .name("text-search-reaper".into())
                .spawn(move || {
                    let _ = handle.join();
                });
        }
    }
}

struct Matching<'a> {
    pattern: CompiledPattern,
    spec: &'a TextSearchSpec,
    cancellation: &'a TextCancellation,
    hits: Vec<TextHit>,
    scanned: usize,
    remaining: usize,
    result_bytes: usize,
    partial: bool,
}
impl Matching<'_> {
    fn stopped(&self) -> bool {
        self.partial || self.cancellation.canceled()
    }
    fn record(
        &mut self,
        key: TextSourceKey,
        address: Option<u64>,
        variants: &[(u8, &str, TextProvenance)],
    ) {
        if self.stopped() || !self.spec.sources.contains(key.source()) {
            return;
        }
        // Charge all variants before examining any; never match a partial record.
        let Some(bytes) = variants
            .iter()
            .try_fold(0usize, |n, (_, s, _)| n.checked_add(s.len()))
        else {
            self.partial = true;
            return;
        };
        if bytes > self.remaining {
            self.partial = true;
            return;
        }
        self.remaining -= bytes;
        self.scanned += bytes;
        let (mut matched, mut chosen) = (0, None);
        for &(variant, text, provenance) in variants {
            if self.cancellation.canceled() {
                return;
            }
            let mut state = [0; 4];
            let mut offset = 0;
            let mut found = None;
            'chunks: for chunk in text.as_bytes().chunks(MAX_BYTE_READ) {
                if self.cancellation.canceled() {
                    return;
                }
                for &byte in chunk {
                    offset += 1;
                    if self.pattern.feed(&mut state, byte) {
                        let start = offset - self.pattern.len();
                        if text.is_char_boundary(start) && text.is_char_boundary(offset) {
                            found = Some(start..offset);
                            break 'chunks;
                        }
                    }
                }
            }
            if let Some(range) = found {
                matched |= variant;
                // Variants arrive in inventory/raw/display preference order.
                chosen = Some((text, range, provenance));
            }
        }
        let Some((text, range, provenance)) = chosen else {
            return;
        };
        if self.cancellation.canceled() {
            return;
        }
        if self.hits.len() == MAX_SEARCH_RESULTS {
            self.partial = true;
            return;
        }
        let snippet = snippet(text, range.clone());
        let extra = snippet.capacity();
        if self
            .result_bytes
            .checked_add(extra)
            .is_none_or(|n| n > MAX_SEARCH_RESULT_BYTES)
        {
            self.partial = true;
            return;
        }
        self.result_bytes += extra;
        self.hits.push(TextHit {
            key,
            address,
            matched_variants: matched,
            text_range: range,
            snippet,
            provenance,
        });
    }
}

fn run(
    corpus: TextCorpus,
    spec: TextSearchSpec,
    binding: TextBinding,
    reservation: TransientReservation,
    cancel: &TextCancellation,
) -> TextSearchResult {
    let _timing = crate::performance::span("search_text_matching");
    let hits = Vec::with_capacity(MAX_SEARCH_RESULTS);
    let result_bytes = hits.capacity() * size_of::<TextHit>()
        + size_of::<TextSearchResult>()
        + spec.query.capacity()
        + binding.binary_sha256.capacity()
        + binding.symbol_digest.as_ref().map_or(0, String::capacity)
        + binding.linkage_digest.as_ref().map_or(0, String::capacity);
    let mut matching = Matching {
        pattern: spec.compile().expect("validated literal"),
        spec: &spec,
        cancellation: cancel,
        hits,
        scanned: 0,
        remaining: MAX_SEARCH_CORPUS_BYTES.saturating_sub(corpus.copied_bytes - corpus.field_bytes),
        result_bytes,
        partial: false,
    };
    let records = || corpus.chunks.iter().flat_map(|c| c.iter());
    let mut inventory = records()
        .take_while(|r| matches!(r.key, TextSourceKey::Name(_)))
        .peekable();
    let mut symbols = corpus
        .symbols
        .as_ref()
        .map_or(&[][..], |s| s.records())
        .iter()
        .peekable();
    while inventory.peek().is_some() || symbols.peek().is_some() {
        if matching.stopped() {
            break;
        }
        let ia = inventory.peek().map(|r| r.address);
        let sa = symbols.peek().map(|r| r.address);
        let address = match (ia, sa) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) | (None, Some(a)) => a,
            _ => unreachable!(),
        };
        let inv = if ia == Some(address) {
            inventory.next()
        } else {
            None
        };
        let sym = if sa == Some(address) {
            symbols.next()
        } else {
            None
        };
        let mut fields = [(0, "", TextProvenance::Live); 3];
        let mut count = 0;
        if let Some(r) = inv {
            fields[count] = (VARIANT_INVENTORY, &r.text, r.provenance);
            count += 1;
        }
        if let Some(r) = sym {
            fields[count] = (VARIANT_RAW, &r.raw, TextProvenance::Live);
            count += 1;
            if let Some(display) = &r.display {
                fields[count] = (VARIANT_DISPLAY, display, TextProvenance::Live);
                count += 1;
            }
        }
        matching.record(
            TextSourceKey::Name(address),
            Some(address),
            &fields[..count],
        );
    }
    if let Some(linkage) = &corpus.linkage {
        for import in &linkage.imports {
            if matching.stopped() {
                break;
            }
            declared(
                &mut matching,
                TextSourceKey::Import(import.id),
                import.stub.or(import.slot),
                &import.raw,
                &import.display,
                import.ordinal,
            );
        }
        for export in &linkage.exports {
            if matching.stopped() {
                break;
            }
            declared(
                &mut matching,
                TextSourceKey::Export(export.id),
                export.target.address(),
                &export.raw,
                &export.display,
                export.ordinal,
            );
        }
    }
    for record in records().filter(|r| !matches!(r.key, TextSourceKey::Name(_))) {
        if matching.stopped() {
            break;
        }
        matching.record(
            record.key,
            Some(record.address),
            &[(VARIANT_TEXT, &record.text, record.provenance)],
        );
    }
    let unavailable = (0..6)
        .any(|i| spec.sources.0 & (1 << i) != 0 && corpus.status[i] != SourceStatus::Available);
    let state = if cancel.canceled() {
        SearchState::Canceled
    } else if matching.partial || corpus.partial || unavailable {
        SearchState::Partial
    } else {
        SearchState::Complete
    };
    // Unstable sort is in-place: no result-size temporary index or duplicate set.
    matching
        .hits
        .sort_unstable_by_key(|h| (h.address.is_none(), h.address, h.key));
    crate::performance::event("search_text_results", matching.hits.len() as u64);
    crate::performance::event("search_text_scanned_bytes", matching.scanned as u64);
    TextSearchResult {
        binding,
        spec: spec.clone(),
        hits: matching.hits,
        state,
        sources: corpus.status,
        scanned: matching.scanned,
        _reservation: reservation,
    }
}

fn declared(
    matching: &mut Matching<'_>,
    key: TextSourceKey,
    address: Option<u64>,
    raw: &Option<String>,
    display: &Option<String>,
    ordinal: Option<u32>,
) {
    let fallback = if raw.is_none() {
        ordinal.map(|n| format!("ordinal {n}"))
    } else {
        None
    };
    let mut fields = [(0, "", TextProvenance::Live); 2];
    let mut count = 0;
    if let Some(raw) = raw.as_ref().or(fallback.as_ref()) {
        fields[count] = (VARIANT_RAW, raw, TextProvenance::Live);
        count += 1;
    }
    if let Some(display) = display {
        fields[count] = (VARIANT_DISPLAY, display, TextProvenance::Live);
        count += 1;
    }
    matching.record(key, address, &fields[..count]);
}

/// Escape a bounded window beginning at the match (with a little leading
/// context). Each scalar is appended whole, including its escaped spelling.
fn snippet(text: &str, range: Range<usize>) -> String {
    let mut start = range.start.saturating_sub(24);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    // Keep the first matched scalar visible even when preceding controls expand.
    if text[start..range.start]
        .chars()
        .map(escaped_len)
        .sum::<usize>()
        > 48
    {
        start = range.start;
    }
    let mut snippet = String::with_capacity(MAX_SEARCH_SNIPPET_BYTES);
    if start != 0 {
        snippet.push('…');
    }
    let mut end = start;
    for ch in text[start..].chars() {
        let size = escaped_len(ch);
        if snippet.len() + size + 3 > MAX_SEARCH_SNIPPET_BYTES {
            break;
        }
        if ch.is_control() {
            for c in ch.escape_default() {
                snippet.push(c);
            }
        } else {
            snippet.push(ch);
        }
        end += ch.len_utf8();
    }
    if end < text.len() {
        snippet.push('…');
    }
    snippet
}
fn escaped_len(ch: char) -> usize {
    if ch.is_control() {
        ch.escape_default().count()
    } else {
        ch.len_utf8()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::function_results::FunctionResults;
    use crate::symbol_names::{SymbolNameFetch, digest};

    fn names(records: Vec<SymbolName>) -> Arc<SymbolNames> {
        let digest = digest(&records);
        let mut fetch = SymbolNameFetch::new(SymbolNameSummary {
            digest: digest.clone(),
            records: records.len(),
            truncated: false,
        })
        .unwrap();
        if !records.is_empty() {
            fetch
                .accept(SymbolNamePage {
                    digest,
                    cursor: 0,
                    next: None,
                    entries: records,
                })
                .unwrap();
        }
        Arc::new(fetch.finish().unwrap())
    }
    fn binding(corpus: &TextCorpus) -> TextBinding {
        TextBinding {
            binary_sha256: "a".repeat(64),
            generation: 1,
            search_id: 1,
            annotation_revision: 1,
            inventory_revision: 1,
            symbol_revision: 1,
            linkage_revision: 1,
            strings_revision: 1,
            symbol_digest: corpus.symbols.as_ref().map(|s| s.digest().into()),
            linkage_digest: corpus.linkage.as_ref().map(|s| s.digest.clone()),
        }
    }
    fn builder(store: &mut FunctionResults) -> TextCorpusBuilder {
        TextCorpusBuilder::new(
            store
                .reserve_transient(TEXT_CORPUS_BASE_BYTES, &[])
                .unwrap(),
        )
        .unwrap()
    }
    fn push(
        builder: &mut TextCorpusBuilder,
        store: &mut FunctionResults,
        key: TextSourceKey,
        address: u64,
        text: &str,
        provenance: TextProvenance,
    ) -> bool {
        let lease = builder.reservation().clone();
        builder
            .push(key, address, text, provenance, |n| {
                store.grow_transient(&lease, n, &[])
            })
            .unwrap()
    }
    fn search(
        store: &mut FunctionResults,
        corpus: TextCorpus,
        query: &str,
        sources: TextSources,
    ) -> TextSearchResult {
        let spec = TextSearchSpec {
            query: query.into(),
            match_case: false,
            sources,
        };
        let binding = binding(&corpus);
        run(
            corpus,
            spec,
            binding,
            store
                .reserve_transient(TEXT_JOB_RESERVATION_BYTES, &[])
                .unwrap(),
            &TextCancellation::default(),
        )
    }
    fn symbol(address: u64, raw: &str, display: Option<&str>) -> SymbolName {
        SymbolName {
            address,
            raw: raw.into(),
            display: display.map(str::to_owned),
        }
    }

    #[test]
    fn raw_display_inventory_and_orphan_names_keep_exact_identities() {
        // Literal already-derived display names: no demangler runs in this test.
        for (raw, display, query) in [
            ("_ZN4demo3fooEv", "demo::foo", "foo"),
            ("_RNvC4demo3bar", "demo::bar", "bar"),
            ("?baz@@YAHH@Z", "baz", "baz"),
        ] {
            let mut store = FunctionResults::default();
            let mut capture = builder(&mut store);
            push(
                &mut capture,
                &mut store,
                TextSourceKey::Name(10),
                10,
                "user_label",
                TextProvenance::Saved,
            );
            push(
                &mut capture,
                &mut store,
                TextSourceKey::Label(10),
                10,
                "user_label",
                TextProvenance::Live,
            );
            let corpus = capture.finish(
                Some(names(vec![
                    symbol(10, raw, Some(display)),
                    symbol(20, raw, Some(display)),
                ])),
                None,
                [SourceStatus::Available; 6],
            );
            let result = search(&mut store, corpus, query, TextSources::NAMES);
            assert_eq!(
                result.hits.iter().map(|h| h.key).collect::<Vec<_>>(),
                [TextSourceKey::Name(10), TextSourceKey::Name(20)]
            );
            assert!(result.hits.iter().all(|h| h.matched_variants
                == VARIANT_RAW | VARIANT_DISPLAY
                && h.snippet == display));
        }
        let mut store = FunctionResults::default();
        let corpus = builder(&mut store).finish(
            Some(names(vec![
                symbol(123, "_ZN4demo3fooEv", Some("demo::foo")),
                symbol(456, "?unsupported", None),
            ])),
            None,
            [SourceStatus::Available; 6],
        );
        let result = search(&mut store, corpus, "_ZN4", TextSources::NAMES);
        assert_eq!(result.hits[0].snippet, "_ZN4demo3fooEv");
        assert_eq!(result.hits[0].text_range, 0..4);
        assert_eq!(result.hits[0].address, Some(123));
        assert_eq!(result.hits[0].matched_variants, VARIANT_RAW);
    }

    #[test]
    fn equal_linkage_names_ordinals_aliases_and_forwarders_stay_separate() {
        use crate::linkage::{Export, ExportTarget, Import, ImportKind};
        let mut store = FunctionResults::default();
        let import = |id, library| Import {
            id,
            library,
            raw: Some("same".into()),
            display: None,
            ordinal: None,
            scope: None,
            version: None,
            kind: ImportKind::Normal,
            weak: false,
            slot: Some(100 + id as u64),
            stub: None,
        };
        let linkage = Arc::new(Linkage {
            digest: "b".repeat(64),
            libraries: Box::default(),
            imports: vec![
                import(0, Some(0)),
                import(1, Some(1)),
                Import {
                    raw: None,
                    ordinal: Some(27),
                    ..import(2, None)
                },
            ]
            .into(),
            exports: vec![
                Export {
                    id: 0,
                    raw: Some("same".into()),
                    display: None,
                    ordinal: None,
                    version: None,
                    target: ExportTarget::Data { address: 900 },
                },
                Export {
                    id: 1,
                    raw: Some("same".into()),
                    display: None,
                    ordinal: None,
                    version: None,
                    target: ExportTarget::Data { address: 900 },
                },
                Export {
                    id: 2,
                    raw: Some("same".into()),
                    display: None,
                    ordinal: None,
                    version: None,
                    target: ExportTarget::Forwarder {
                        target: "excluded.dll.target".into(),
                    },
                },
                Export {
                    id: 3,
                    raw: Some("same".into()),
                    display: None,
                    ordinal: None,
                    version: None,
                    target: ExportTarget::Unresolved,
                },
            ]
            .into(),
            locations: Box::default(),
            gaps: Box::default(),
        });
        let corpus = builder(&mut store).finish(
            None,
            Some(Arc::clone(&linkage)),
            [SourceStatus::Available; 6],
        );
        let result = search(&mut store, corpus, "same", TextSources::ALL);
        assert_eq!(
            result.hits.iter().map(|h| h.key).collect::<Vec<_>>(),
            [
                TextSourceKey::Import(0),
                TextSourceKey::Import(1),
                TextSourceKey::Export(0),
                TextSourceKey::Export(1),
                TextSourceKey::Export(2),
                TextSourceKey::Export(3)
            ]
        );
        assert_eq!(result.hits[4].address, None);
        assert_eq!(result.hits[5].address, None);
        let corpus = builder(&mut store).finish(
            None,
            Some(Arc::clone(&linkage)),
            [SourceStatus::Available; 6],
        );
        let result = search(&mut store, corpus, "ordinal 27", TextSources::IMPORTS);
        assert_eq!(
            result.hits.iter().map(|h| h.key).collect::<Vec<_>>(),
            [TextSourceKey::Import(2)]
        );
        let corpus = builder(&mut store).finish(None, Some(linkage), [SourceStatus::Available; 6]);
        assert!(
            search(&mut store, corpus, "excluded", TextSources::ALL)
                .hits
                .is_empty()
        );
    }

    #[test]
    fn source_toggles_saved_previews_and_utf8_ranges_never_shift_addresses() {
        let mut store = FunctionResults::default();
        let mut capture = builder(&mut store);
        for key in [
            TextSourceKey::Name(5),
            TextSourceKey::Label(5),
            TextSourceKey::Comment(5),
            TextSourceKey::String(0),
        ] {
            push(
                &mut capture,
                &mut store,
                key,
                5,
                "é\nneedle\t🦀",
                TextProvenance::Saved,
            );
        }
        let result = search(
            &mut store,
            capture.finish(None, None, [SourceStatus::Available; 6]),
            "NEEDLE",
            TextSources::COMMENTS,
        );
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].key, TextSourceKey::Comment(5));
        assert_eq!(result.hits[0].address, Some(5));
        assert_eq!(result.hits[0].text_range, 3..9);
        assert_eq!(result.hits[0].snippet, "é\\nneedle\\t🦀");
        assert_eq!(result.hits[0].provenance, TextProvenance::Saved);
        assert_eq!(result.state, SearchState::Complete);
        let text = format!("{}\nMATCH\t{}", "🦀".repeat(100), "\0".repeat(200));
        let range = 401..406;
        let snippet = snippet(&text, range);
        assert!(snippet.len() <= MAX_SEARCH_SNIPPET_BYTES && snippet.contains("MATCH\\t"));
        assert!(!snippet.chars().any(char::is_control));
        for sources in [TextSources(0), TextSources(64), TextSources(255)] {
            assert!(
                TextSearchSpec {
                    query: "a".into(),
                    match_case: false,
                    sources
                }
                .validate()
                .is_err()
            );
        }
        assert!(
            TextSearchSpec {
                query: "".into(),
                match_case: false,
                sources: TextSources::ALL
            }
            .validate()
            .is_err()
        );
        assert!(
            TextSearchSpec {
                query: "é".repeat(129),
                match_case: false,
                sources: TextSources::ALL
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn aggregate_corpus_and_result_caps_cover_large_live_and_saved_sources() {
        let mut store = FunctionResults::default();
        let mut capture = builder(&mut store);
        let field = "a".repeat(crate::session::MAX_COMMENT_BYTES);
        let mut accepted = 0;
        for address in 0..crate::session::MAX_ANNOTATIONS as u64 {
            if !push(
                &mut capture,
                &mut store,
                TextSourceKey::Comment(address),
                address,
                &field,
                TextProvenance::Live,
            ) {
                break;
            }
            accepted += 1;
        }
        assert!(accepted > 128 && accepted < 512); // Live comments can exceed the 8 MiB file cap.
        assert!(capture.bytes() <= MAX_SEARCH_CORPUS_BYTES);
        let result = search(
            &mut store,
            capture.finish(None, None, [SourceStatus::Available; 6]),
            "z",
            TextSources::COMMENTS,
        );
        assert_eq!(result.state, SearchState::Partial);
        assert!(result.hits.is_empty());
        drop(result);
        let mut capture = builder(&mut store);
        for index in 0..MAX_PROJECT_STRINGS {
            assert!(push(
                &mut capture,
                &mut store,
                TextSourceKey::String(index),
                index as u64,
                "saved match",
                TextProvenance::Saved
            ));
        }
        let result = search(
            &mut store,
            capture.finish(None, None, [SourceStatus::Available; 6]),
            "match",
            TextSources::STRINGS,
        );
        assert_eq!(result.hits.len(), MAX_SEARCH_RESULTS);
        assert_eq!(result.state, SearchState::Partial);
        assert_eq!(result.hits[9999].key, TextSourceKey::String(9999));
        assert!(
            result.hits.capacity() * size_of::<TextHit>()
                + result
                    .hits
                    .iter()
                    .map(|h| h.snippet.capacity())
                    .sum::<usize>()
                <= MAX_SEARCH_RESULT_BYTES
        );
    }

    #[test]
    fn unavailable_and_partial_metadata_and_cancellation_are_explicit() {
        let mut store = FunctionResults::default();
        let corpus = builder(&mut store).finish(None, None, [SourceStatus::Unavailable; 6]);
        let result = search(&mut store, corpus, "x", TextSources::ALL);
        assert_eq!(result.state, SearchState::Partial);
        let mut capture = builder(&mut store);
        push(
            &mut capture,
            &mut store,
            TextSourceKey::Comment(1),
            1,
            "one",
            TextProvenance::Live,
        );
        let corpus = capture.finish(None, None, [SourceStatus::Partial; 6]);
        let cancel = TextCancellation::default();
        cancel.cancel();
        let result = run(
            corpus,
            TextSearchSpec {
                query: "one".into(),
                match_case: true,
                sources: TextSources::ALL,
            },
            binding(&builder(&mut store).finish(None, None, [SourceStatus::Available; 6])),
            store
                .reserve_transient(TEXT_JOB_RESERVATION_BYTES, &[])
                .unwrap(),
            &cancel,
        );
        assert_eq!(result.state, SearchState::Canceled);
        assert!(result.hits.is_empty());
        let corpus = builder(&mut store).finish(None, None, [SourceStatus::Available; 6]);
        let binding = binding(&corpus);
        let mut job = TextJob::start(
            corpus,
            TextSearchSpec {
                query: "x".into(),
                match_case: false,
                sources: TextSources::ALL,
            },
            binding,
            store
                .reserve_transient(TEXT_JOB_RESERVATION_BYTES, &[])
                .unwrap(),
        )
        .unwrap();
        while !job.is_finished() {
            std::thread::yield_now();
        }
        let result = job.try_finish().unwrap().unwrap();
        assert_eq!(result.state, SearchState::Complete);
        assert!(job.try_finish().unwrap().is_none());
    }
}
