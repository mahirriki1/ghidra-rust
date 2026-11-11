//! Program-scope Listing rows. A row is positioned by `(address, rank)`,
//! never by a global index, so rows can be added as function bodies load
//! without moving the viewport. Rows are derived on demand from three
//! sources: the ordered sections, the ordered function inventory and the
//! decoded instruction runs of loaded function views. Bytes no loaded view
//! decoded stay undefined; nothing is linearly disassembled or guessed.
//!
//! A [`Layout`] also borrows the session's [`Expansions`]: undefined bytes
//! inside an expanded address interval are one [`Row::Byte`] each, and the
//! collapsed `??` rows around them are clipped to the intervals. Decoded
//! instructions, pending bodies and zero-filled tails ignore expansions.
//!
//! Body rows are derived in two steps. `Layout::unexpanded` finds the row
//! covering an address from decoded runs, entries and section bounds; an
//! undefined zone it returns is then split by `Layout::undefined` into byte
//! rows and the collapsed parts between intervals. Further evidence (data
//! rows, split marks) belongs in the first step, clipping the undefined zone
//! as entries do; because expanded intervals override data rows, a data row
//! overlapping an interval falls back to its undefined zone there.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::function_presentation::{Listing, ListingIndex};
use crate::model::{FunctionInfo, FunctionView, MAX_BYTE_READ, SectionInfo, function_at};
use crate::result_store::{Bytes, ProgramContext, RESULT_STORE_BUDGET};

/// Order of rows sharing one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    Section,
    Function,
    Body,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Position {
    pub address: u64,
    pub rank: Rank,
}

impl Position {
    pub fn new(address: u64, rank: Rank) -> Self {
        Self { address, rank }
    }
}

/// One Program-listing row. Body rows cover `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Row {
    /// The start of `info.sections[section]`.
    Section {
        section: usize,
        start: u64,
    },
    Function {
        entry: u64,
    },
    /// A decoded instruction of the loaded view of `owner`.
    Instruction {
        owner: u64,
        start: u64,
        end: u64,
    },
    /// File-backed bytes no loaded view decoded.
    Undefined {
        start: u64,
        end: u64,
    },
    /// A section's bytes beyond its file-backed part.
    ZeroFill {
        start: u64,
        end: u64,
    },
    /// Bytes after the entry of a function whose view is not loaded yet.
    Pending {
        entry: u64,
        start: u64,
        end: u64,
    },
    /// One undefined file-backed byte inside an expanded interval.
    Byte {
        address: u64,
    },
}

impl Row {
    pub fn position(&self) -> Position {
        match *self {
            Self::Section { start, .. } => Position::new(start, Rank::Section),
            Self::Function { entry } => Position::new(entry, Rank::Function),
            Self::Instruction { start, .. }
            | Self::Undefined { start, .. }
            | Self::ZeroFill { start, .. }
            | Self::Pending { start, .. }
            | Self::Byte { address: start } => Position::new(start, Rank::Body),
        }
    }

    /// Bytes a body row covers; headers cover none.
    pub fn span(&self) -> Option<(u64, u64)> {
        match *self {
            Self::Section { .. } | Self::Function { .. } => None,
            Self::Instruction { start, end, .. }
            | Self::Undefined { start, end }
            | Self::ZeroFill { start, end }
            | Self::Pending { start, end, .. } => Some((start, end)),
            Self::Byte { address } => Some((address, address + 1)),
        }
    }

    /// The first position after this row.
    fn after(&self) -> Position {
        match *self {
            Self::Section { start, .. } => Position::new(start, Rank::Function),
            Self::Function { entry } => Position::new(entry, Rank::Body),
            // An entry can lie inside an instruction that began earlier;
            // its header follows that instruction's own position.
            _ => {
                let (start, _) = self.span().expect("body row");
                Position::new(start + 1, Rank::Section)
            }
        }
    }

    /// The function a row belongs to by evidence: its header, pending body
    /// or decoded instruction.
    pub fn function(&self) -> Option<u64> {
        match *self {
            Self::Function { entry } | Self::Pending { entry, .. } => Some(entry),
            Self::Instruction { owner, .. } => Some(owner),
            _ => None,
        }
    }
}

/// A non-empty section's bounds; `file_end` ends its file-backed bytes.
#[derive(Clone, Copy, Debug)]
struct Span {
    section: usize,
    start: u64,
    file_end: u64,
    end: u64,
}

/// One loaded function view offered to [`ProgramRows::new`].
pub struct BodySource<'a> {
    pub owner: u64,
    pub listing: Listing<'a>,
}

/// The decoded instruction runs of loaded views over the section layout.
/// Each run is claimed once: identical instructions of several views are
/// shown once, by the first claimant; a later instruction overlapping a
/// claimed one with different bounds is omitted here (it remains in its own
/// function's Listing and graph). Instructions that are empty or not inside
/// one section's file-backed bytes are omitted too.
pub struct ProgramRows {
    spans: Vec<Span>,
    runs: BTreeMap<u64, (u64, u64)>,
    /// Entries whose view was loaded or failed; others are pending.
    settled: BTreeSet<u64>,
}

impl ProgramRows {
    /// `bodies` in claim order: the displayed function first, then the
    /// cached views by ascending entry. `failed` entries have no view.
    pub fn new<'a>(
        sections: &[SectionInfo],
        bodies: impl IntoIterator<Item = BodySource<'a>>,
        failed: impl IntoIterator<Item = u64>,
    ) -> Self {
        let mut spans: Vec<Span> = Vec::new();
        for (index, section) in sections.iter().enumerate() {
            let Some(end) = section.address.checked_add(section.size) else {
                continue;
            };
            if section.size == 0 || spans.last().is_some_and(|last| last.end > section.address) {
                continue;
            }
            spans.push(Span {
                section: index,
                start: section.address,
                file_end: section.address + section.size.min(section.file_size),
                end,
            });
        }
        let mut rows = Self {
            spans,
            runs: BTreeMap::new(),
            settled: failed.into_iter().collect(),
        };
        for body in bodies {
            rows.settled.insert(body.owner);
            for instruction in body.listing.iter() {
                let start = instruction.address;
                let Some(end) = start
                    .checked_add(instruction.bytes.len() as u64)
                    .filter(|end| *end > start)
                else {
                    continue;
                };
                if !rows.span_at(start).is_some_and(|span| end <= span.file_end) {
                    continue;
                }
                let before = rows.runs.range(..end).next_back();
                if before.is_some_and(|(_, &(other_end, _))| other_end > start) {
                    // Identical instructions are already shown; any other
                    // overlap would make two rows claim the same bytes.
                    continue;
                }
                rows.runs.insert(start, (end, body.owner));
            }
        }
        rows
    }

    /// Navigation over these rows, the current inventory, which must be
    /// ordered by address, and the expanded byte intervals.
    pub fn layout<'a>(
        &'a self,
        functions: &'a [FunctionInfo],
        expansions: &'a Expansions,
    ) -> Layout<'a> {
        Layout {
            rows: self,
            functions,
            expansions,
        }
    }

    /// The byte page holding file-backed `address`: aligned to
    /// [`BYTE_PAGE`] from its section's start and clipped to the section's
    /// file-backed end, so one read never leaves one section's bytes.
    pub fn byte_page(&self, address: u64) -> Option<(u64, usize)> {
        let span = self
            .span_at(address)
            .filter(|span| address < span.file_end)?;
        let page = BYTE_PAGE as u64;
        let start = span.start + (address - span.start) / page * page;
        let length = (span.file_end - start).min(page);
        Some((start, length as usize))
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }

    fn span_at(&self, address: u64) -> Option<&Span> {
        let index = self.spans.partition_point(|span| span.end <= address);
        self.spans.get(index).filter(|span| span.start <= address)
    }

    /// The owner of the run starting exactly at `address`.
    pub fn instruction_owner(&self, address: u64) -> Option<u64> {
        self.runs.get(&address).map(|&(_, owner)| owner)
    }
}

#[derive(Clone, Copy)]
pub struct Layout<'a> {
    rows: &'a ProgramRows,
    functions: &'a [FunctionInfo],
    expansions: &'a Expansions,
}

impl Layout<'_> {
    fn is_entry(&self, address: u64) -> bool {
        function_at(self.functions, address).is_some()
    }

    /// The greatest entry in `[low, high]`.
    fn last_entry(&self, low: u64, high: u64) -> Option<u64> {
        let index = self.functions.partition_point(|f| f.address <= high);
        let entry = self.functions.get(index.checked_sub(1)?)?.address;
        (entry >= low).then_some(entry)
    }

    /// The least entry in `(low, high)`.
    fn next_entry(&self, low: u64, high: u64) -> Option<u64> {
        let index = self.functions.partition_point(|f| f.address <= low);
        let entry = self.functions.get(index)?.address;
        (entry < high).then_some(entry)
    }

    /// The body row covering `address`, which lies in `span`.
    fn body(&self, span: &Span, address: u64) -> Row {
        match self.unexpanded(span, address) {
            Row::Undefined { start, end } => self.undefined(address, start, end),
            row => row,
        }
    }

    /// An undefined zone `[start, end)` holding `address`, under the
    /// expansions: a byte row inside an interval, else the collapsed part
    /// between the neighbouring intervals.
    fn undefined(&self, address: u64, start: u64, end: u64) -> Row {
        let expansions = &self.expansions.ranges;
        let before = expansions.range(..=address).next_back();
        if before.is_some_and(|(_, &interval_end)| interval_end > address) {
            return Row::Byte { address };
        }
        let start = before.map_or(start, |(_, &interval_end)| start.max(interval_end));
        let end = expansions
            .range(address + 1..)
            .next()
            .map_or(end, |(&interval_start, _)| end.min(interval_start));
        Row::Undefined { start, end }
    }

    /// The body row covering `address` without expansions.
    fn unexpanded(&self, span: &Span, address: u64) -> Row {
        let runs = &self.rows.runs;
        if let Some((&start, &(end, owner))) = runs.range(..=address).next_back()
            && end > address
        {
            return Row::Instruction { owner, start, end };
        }
        let (zone_start, zone_end) = if address < span.file_end {
            (span.start, span.file_end)
        } else {
            (span.file_end, span.end)
        };
        let mut start = zone_start;
        if let Some((_, &(end, _))) = runs.range(..=address).next_back() {
            start = start.max(end);
        }
        if let Some(entry) = self.last_entry(start, address) {
            start = entry;
        }
        let mut end = zone_end;
        if let Some((&next, _)) = runs.range(address + 1..zone_end).next() {
            end = next;
        }
        if let Some(entry) = self.next_entry(address, end) {
            end = entry;
        }
        if address >= span.file_end {
            Row::ZeroFill { start, end }
        } else if self.is_entry(start) && !self.rows.settled.contains(&start) {
            Row::Pending {
                entry: start,
                start,
                end,
            }
        } else {
            Row::Undefined { start, end }
        }
    }

    /// The first row at or after `position`.
    pub fn at_or_after(&self, mut position: Position) -> Option<Row> {
        loop {
            let spans = &self.rows.spans;
            let span = spans.get(spans.partition_point(|span| span.end <= position.address))?;
            if span.start > position.address {
                position = Position::new(span.start, Rank::Section);
            }
            let address = position.address;
            if address == span.start && position.rank <= Rank::Section {
                return Some(Row::Section {
                    section: span.section,
                    start: span.start,
                });
            }
            if position.rank <= Rank::Function && self.is_entry(address) {
                return Some(Row::Function { entry: address });
            }
            let body = self.body(span, address);
            let (start, end) = body.span().expect("body row");
            if start == address {
                return Some(body);
            }
            // Entries inside an instruction that began earlier still head
            // their own function.
            if let Some(entry) = self.next_entry(address, end) {
                return Some(Row::Function { entry });
            }
            position = Position::new(end, Rank::Section);
        }
    }

    /// The last row strictly before `position`.
    pub fn before(&self, position: Position) -> Option<Row> {
        let address = position.address;
        if let Some(span) = self.rows.span_at(address) {
            if position.rank == Rank::Body && self.is_entry(address) {
                return Some(Row::Function { entry: address });
            }
            if position.rank > Rank::Section && address == span.start {
                return Some(Row::Section {
                    section: span.section,
                    start: span.start,
                });
            }
        }
        let previous = address.checked_sub(1)?;
        let spans = &self.rows.spans;
        let index = spans.partition_point(|span| span.end <= previous);
        let (span, at) = match spans.get(index) {
            Some(span) if span.start <= previous => (span, previous),
            _ => {
                let span = spans.get(index.checked_sub(1)?)?;
                (span, span.end - 1)
            }
        };
        let body = self.body(span, at);
        let (start, _) = body.span().expect("body row");
        if let Some(entry) = start
            .checked_add(1)
            .and_then(|low| self.last_entry(low, at))
        {
            return Some(Row::Function { entry });
        }
        Some(body)
    }

    pub fn next(&self, row: &Row) -> Option<Row> {
        self.at_or_after(row.after())
    }

    pub fn previous(&self, row: &Row) -> Option<Row> {
        self.before(row.position())
    }

    /// The row at `position`, else the body row covering its address, else
    /// the nearest following (or, at the end, preceding) row. Used to keep a
    /// viewport anchored while rows change.
    pub fn resolve(&self, position: Position) -> Option<Row> {
        if let Some(span) = self.rows.span_at(position.address) {
            match position.rank {
                Rank::Section if span.start == position.address => {
                    return Some(Row::Section {
                        section: span.section,
                        start: span.start,
                    });
                }
                Rank::Function if self.is_entry(position.address) => {
                    return Some(Row::Function {
                        entry: position.address,
                    });
                }
                Rank::Body => return Some(self.body(span, position.address)),
                _ => {}
            }
        }
        self.at_or_after(position).or_else(|| self.before(position))
    }

    /// The row at exactly `position`, if one starts there.
    pub fn exact(&self, position: Position) -> Option<Row> {
        self.resolve(position)
            .filter(|row| row.position() == position)
    }

    pub fn first(&self) -> Option<Row> {
        self.at_or_after(Position::new(0, Rank::Section))
    }

    pub fn last(&self) -> Option<Row> {
        self.before(Position::new(u64::MAX, Rank::Body))
    }

    /// The row a cursor at exactly `address` stands on: the row of `rank`
    /// when one starts there, else the instruction starting there, else the
    /// function header, else any other row starting there. An address no
    /// row starts at has none; nothing nearby is substituted.
    pub fn cursor(&self, address: u64, rank: Option<Rank>) -> Option<Row> {
        if let Some(row) = rank.and_then(|rank| self.exact(Position::new(address, rank))) {
            return Some(row);
        }
        let body = self.exact(Position::new(address, Rank::Body));
        if let Some(row @ Row::Instruction { .. }) = body {
            return Some(row);
        }
        self.exact(Position::new(address, Rank::Function))
            .or(body)
            .or_else(|| self.exact(Position::new(address, Rank::Section)))
    }

    /// The first and last rows of the section holding `address`.
    pub fn section_bounds(&self, address: u64) -> Option<(Row, Row)> {
        let span = self.rows.span_at(address)?;
        let last = self.before(Position::new(span.end, Rank::Section))?;
        Some((
            Row::Section {
                section: span.section,
                start: span.start,
            },
            last,
        ))
    }

    /// See [`ProgramRows::byte_page`].
    pub fn byte_page(&self, address: u64) -> Option<(u64, usize)> {
        self.rows.byte_page(address)
    }

    /// The expanded run holding the byte row at `address`: its undefined
    /// zone intersected with the covering interval.
    pub fn byte_run(&self, address: u64) -> Option<(u64, u64)> {
        let span = self.rows.span_at(address)?;
        let Row::Undefined { start, end } = self.unexpanded(span, address) else {
            return None;
        };
        let (interval_start, interval_end) = self.expansions.covering(address)?;
        Some((start.max(interval_start), end.min(interval_end)))
    }

    /// Where a reveal of `address` lands: an entry's header, else the body
    /// row covering it.
    pub fn reveal(&self, address: u64) -> Option<Row> {
        self.rows.span_at(address)?;
        if self.is_entry(address) {
            return Some(Row::Function { entry: address });
        }
        self.resolve(Position::new(address, Rank::Body))
    }
}

/// Bytes one expand action shows as byte rows; the rest of the gap stays one
/// collapsed `??` row.
pub const EXPAND_STEP: u64 = MAX_BYTE_READ as u64;
/// Expanded intervals one session keeps; more evict the farthest.
pub const MAX_EXPANSIONS: usize = 64;

/// Session-only expanded address intervals: sorted, disjoint, with
/// adjacent intervals merged. Keyed by address, not by gap, because gap
/// bounds move as bodies load; only undefined bytes inside an interval
/// become byte rows.
#[derive(Default)]
pub struct Expansions {
    ranges: BTreeMap<u64, u64>,
    /// Advances on every change, invalidating materialized rows.
    epoch: u64,
}

impl Expansions {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The interval holding `address`.
    pub fn covering(&self, address: u64) -> Option<(u64, u64)> {
        self.ranges
            .range(..=address)
            .next_back()
            .filter(|(_, end)| **end > address)
            .map(|(&start, &end)| (start, end))
    }

    /// Expands `[start, end)`, merging it with overlapping or adjacent
    /// intervals. Beyond [`MAX_EXPANSIONS`] the interval farthest from the
    /// new one goes first, never the new one or one holding `keep`.
    pub fn expand(&mut self, start: u64, end: u64, keep: Option<u64>) {
        if start >= end {
            return;
        }
        let (mut start, mut end) = (start, end);
        let touching: Vec<(u64, u64)> = self
            .ranges
            .range(..=end)
            .rev()
            .take_while(|(_, other_end)| **other_end >= start)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (other_start, other_end) in touching {
            self.ranges.remove(&other_start);
            start = start.min(other_start);
            end = end.max(other_end);
        }
        self.ranges.insert(start, end);
        while self.ranges.len() > MAX_EXPANSIONS {
            let distance = |s: u64, e: u64| {
                if e <= start {
                    start - e
                } else {
                    s.saturating_sub(end)
                }
            };
            let victim = self
                .ranges
                .iter()
                .filter(|&(&s, &e)| s != start && keep.is_none_or(|k| k < s || k >= e))
                .max_by_key(|&(&s, &e)| distance(s, e))
                .map(|(&s, _)| s);
            match victim {
                Some(victim) => {
                    self.ranges.remove(&victim);
                }
                None => break,
            }
        }
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Collapses `[start, end)`; intervals around it keep their other parts.
    pub fn collapse(&mut self, start: u64, end: u64) {
        let overlapping: Vec<(u64, u64)> = self
            .ranges
            .range(..end)
            .rev()
            .take_while(|(_, other_end)| **other_end > start)
            .map(|(&s, &e)| (s, e))
            .collect();
        if overlapping.is_empty() {
            return;
        }
        for (other_start, other_end) in overlapping {
            self.ranges.remove(&other_start);
            if other_start < start {
                self.ranges.insert(other_start, start);
            }
            if other_end > end {
                self.ranges.insert(end, other_end);
            }
        }
        self.epoch = self.epoch.wrapping_add(1);
    }
}

/// The interval one expand action on `row` adds: up to [`EXPAND_STEP`]
/// bytes from the start of a collapsed `??` row. Other rows never expand.
pub fn expand_interval(row: &Row) -> Option<(u64, u64)> {
    match *row {
        Row::Undefined { start, end } => Some((start, end.min(start.saturating_add(EXPAND_STEP)))),
        _ => None,
    }
}

/// Bytes one Listing byte read requests: the Hex page size.
pub const BYTE_PAGE: usize = crate::hex_ui::PAGE_BYTES;
/// Pages the Program listing keeps: 16 KiB, not charged to the store.
pub const MAX_BYTE_PAGES: usize = 4;
/// Pages whose read failed; once this many failed, none are requested.
pub const MAX_FAILED_PAGES: usize = 64;

/// The bytes byte rows show: at most [`MAX_BYTE_PAGES`] pages, as
/// [`ProgramRows::byte_page`] lays them out. A page is shown only when its
/// read returned every byte.
#[derive(Default)]
pub struct ByteCache {
    pages: BTreeMap<u64, Vec<u8>>,
    failed: BTreeSet<u64>,
}

impl ByteCache {
    pub fn len(&self) -> usize {
        self.pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    pub fn contains(&self, page: u64) -> bool {
        self.pages.contains_key(&page)
    }

    pub fn is_failed(&self, page: u64) -> bool {
        self.failed.contains(&page)
    }

    /// The cached byte at `address`.
    pub fn byte(&self, address: u64) -> Option<u8> {
        let (&start, bytes) = self.pages.range(..=address).next_back()?;
        bytes.get(usize::try_from(address - start).ok()?).copied()
    }

    /// Every byte of `[start, end)`, when all of them are cached.
    pub fn span(&self, start: u64, end: u64) -> Option<Vec<u8>> {
        let length = usize::try_from(end.checked_sub(start)?).ok()?;
        if length == 0 || length > MAX_BYTE_PAGES * BYTE_PAGE {
            return None;
        }
        (start..end).map(|address| self.byte(address)).collect()
    }

    /// The first of `wanted` pages (top first) worth reading now: not
    /// cached, not failed, and with room for it without evicting a page of
    /// `visible`. Nothing once [`MAX_FAILED_PAGES`] reads failed.
    pub fn next(&self, wanted: &[(u64, usize)], visible: &[u64]) -> Option<(u64, usize)> {
        if self.failed.len() >= MAX_FAILED_PAGES {
            return None;
        }
        let full = self.pages.len() >= MAX_BYTE_PAGES
            && self.pages.keys().all(|page| visible.contains(page));
        if full {
            return None;
        }
        wanted
            .iter()
            .copied()
            .find(|(page, _)| !self.contains(*page) && !self.is_failed(*page))
    }

    /// Keeps a complete page, evicting the page farthest from `top` that
    /// is not `visible`. Returns false, changing nothing, when every cached
    /// page is visible.
    pub fn accept(&mut self, page: u64, bytes: Vec<u8>, top: u64, visible: &[u64]) -> bool {
        if self.pages.len() >= MAX_BYTE_PAGES && !self.pages.contains_key(&page) {
            let victim = self
                .pages
                .keys()
                .copied()
                .filter(|cached| !visible.contains(cached))
                .max_by_key(|cached| cached.abs_diff(top));
            let Some(victim) = victim else {
                return false;
            };
            self.pages.remove(&victim);
        }
        self.failed.remove(&page);
        self.pages.insert(page, bytes);
        true
    }

    /// The read of `page` failed; it is not requested again this session.
    pub fn fail(&mut self, page: u64) {
        if self.failed.len() < MAX_FAILED_PAGES {
            self.failed.insert(page);
        }
    }

    /// Releases every page; failures stay recorded.
    pub fn release(&mut self) {
        self.pages.clear();
    }
}

/// A zero-fill tail weighs at most this many bytes on the address bar, so a
/// huge `.bss` cannot shrink the file-backed sections to nothing.
const ZERO_FILL_WEIGHT: u64 = 4096;

/// The address bar's coordinate system: file-backed bytes in proportion,
/// each zero-fill tail clamped to [`ZERO_FILL_WEIGHT`]. Monotonic in both
/// directions; addresses between sections map to the next section's start.
pub struct AddressScale {
    /// `(start, file bytes, zero-fill bytes, weight before this section)`.
    spans: Vec<(u64, u64, u64, u128)>,
    total: u128,
}

impl AddressScale {
    pub fn new(rows: &ProgramRows) -> Self {
        let mut total = 0u128;
        let spans = rows
            .spans
            .iter()
            .map(|span| {
                let file = span.file_end - span.start;
                let zero = span.end - span.file_end;
                let before = total;
                total += u128::from(file) + u128::from(zero.min(ZERO_FILL_WEIGHT));
                (span.start, file, zero, before)
            })
            .collect();
        Self { spans, total }
    }

    /// `address` as a fraction in `[0, 1]`.
    pub fn fraction(&self, address: u64) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let index = self
            .spans
            .partition_point(|&(start, file, zero, _)| start + file + zero <= address);
        let Some(&(start, file, zero, before)) = self.spans.get(index) else {
            return 1.0;
        };
        let offset = address.saturating_sub(start);
        let weight = if offset <= file {
            u128::from(offset)
        } else {
            let zero_weight = zero.min(ZERO_FILL_WEIGHT);
            u128::from(file)
                + u128::from(offset - file) * u128::from(zero_weight) / u128::from(zero.max(1))
        };
        ((before + weight) as f64 / self.total as f64).clamp(0.0, 1.0)
    }

    /// The address at `fraction` of the bar, inverse to [`Self::fraction`].
    pub fn address(&self, fraction: f64) -> Option<u64> {
        let &(last_start, last_file, last_zero, _) = self.spans.last()?;
        let last = last_start + (last_file + last_zero - 1);
        if fraction >= 1.0 {
            return Some(last);
        }
        let target = (fraction.clamp(0.0, 1.0) * self.total as f64) as u128;
        let index = self
            .spans
            .partition_point(|&(_, _, _, before)| before <= target)
            .saturating_sub(1);
        let (start, file, zero, before) = self.spans[index];
        let weight = target - before;
        let offset = if weight < u128::from(file) {
            weight as u64
        } else {
            let zero_weight = u128::from(zero.min(ZERO_FILL_WEIGHT));
            if zero_weight == 0 {
                file.saturating_sub(1)
            } else {
                let extra = (weight - u128::from(file)).min(zero_weight - 1);
                file + (extra * u128::from(zero) / zero_weight) as u64
            }
        };
        Some(start.saturating_add(offset).min(last))
    }
}

/// Program-listing caches stay below this share of the result-store budget.
pub const LISTING_CACHE_BUDGET: usize = RESULT_STORE_BUDGET / 8;

/// A conservative charge for one run in the B-tree of [`ProgramRows`]: a
/// 24-byte entry plus node and edge overhead.
const RUN_INDEX_BYTES: usize = 64;

/// A validated function view retained for the Program listing, with the
/// program context it was computed under.
pub struct CachedBody {
    view: FunctionView,
    index: ListingIndex,
    context: Option<Arc<ProgramContext>>,
    bytes: usize,
}

impl CachedBody {
    /// `view` must already have passed reply validation. A body without a
    /// context is shown but recomputed when next visible.
    pub fn new(view: FunctionView, context: Option<Arc<ProgramContext>>) -> Option<Self> {
        let index = ListingIndex::new(&view);
        // Each listed instruction may also hold one entry of the derived
        // `ProgramRows` run index; it is charged here, with its view.
        let bytes = Bytes::of::<Self>()
            .add_total(crate::function_presentation::view_bytes(&view))
            .slots::<(u32, u32)>(index.len())
            .add_total(index.len().checked_mul(RUN_INDEX_BYTES))
            .plus(256)
            .total()?;
        Some(Self {
            view,
            index,
            context,
            bytes,
        })
    }

    pub fn view(&self) -> &FunctionView {
        &self.view
    }

    pub fn listing(&self) -> Listing<'_> {
        self.index.listing(&self.view)
    }

    /// Whether this view was computed under exactly `context`.
    pub fn is_current(&self, context: &Arc<ProgramContext>) -> bool {
        self.context
            .as_ref()
            .is_some_and(|own| Arc::ptr_eq(own, context))
    }
}

/// Session-only views of functions scrolled past, charged to the shared
/// result-store budget by the caller's `charge` and capped by
/// [`LISTING_CACHE_BUDGET`]. The views farthest from the viewport go first.
#[derive(Default)]
pub struct ListingCache {
    bodies: BTreeMap<u64, Arc<CachedBody>>,
    failed: BTreeMap<u64, Arc<ProgramContext>>,
    /// Entries whose request timed out, crashed or failed the worker. They
    /// stay blocked for the binary generation, under every context.
    blocked: BTreeSet<u64>,
    bytes: usize,
    /// Advances on every change, invalidating derived rows.
    epoch: u64,
}

impl ListingCache {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bodies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bodies.is_empty()
    }

    pub fn get(&self, entry: u64) -> Option<&Arc<CachedBody>> {
        self.bodies.get(&entry)
    }

    pub fn bodies(&self) -> impl Iterator<Item = (u64, &Arc<CachedBody>)> {
        self.bodies.iter().map(|(&entry, body)| (entry, body))
    }

    /// Entries without a view: failed under some context, or blocked.
    pub fn failed(&self) -> impl Iterator<Item = u64> + '_ {
        self.failed.keys().chain(&self.blocked).copied()
    }

    /// Whether `entry` lacks a view computed under `context`, has not
    /// already failed under it and is not blocked.
    pub fn needs(&self, entry: u64, context: &Arc<ProgramContext>) -> bool {
        !self
            .bodies
            .get(&entry)
            .is_some_and(|body| body.is_current(context))
            && !self
                .failed
                .get(&entry)
                .is_some_and(|failed| Arc::ptr_eq(failed, context))
            && !self.blocked.contains(&entry)
    }

    /// Never requests `entry` again for this binary generation.
    pub fn block(&mut self, entry: u64) {
        if self.blocked.insert(entry) {
            self.epoch = self.epoch.wrapping_add(1);
        }
    }

    /// The lowest cached entry whose view decoded exactly `pc`.
    pub fn owner_of(&self, pc: u64) -> Option<u64> {
        self.bodies
            .iter()
            .find(|(entry, body)| **entry == pc || body.listing().contains(pc))
            .map(|(&entry, _)| entry)
    }

    pub fn fail(&mut self, entry: u64, context: Arc<ProgramContext>) {
        self.failed.insert(entry, context);
        self.epoch = self.epoch.wrapping_add(1);
    }

    /// Retains `body` for `entry`, replacing any older view, evicting the
    /// views farthest from `center` while the cache exceeds its cap or
    /// `charge` refuses the new total. Returns whether `body` was retained.
    pub fn insert(
        &mut self,
        entry: u64,
        body: CachedBody,
        center: u64,
        mut charge: impl FnMut(usize) -> bool,
    ) -> bool {
        self.epoch = self.epoch.wrapping_add(1);
        self.failed.remove(&entry);
        if let Some(old) = self.bodies.remove(&entry) {
            self.bytes -= old.bytes;
        }
        let bytes = body.bytes;
        if bytes > LISTING_CACHE_BUDGET {
            charge(self.bytes);
            return false;
        }
        self.bodies.insert(entry, Arc::new(body));
        self.bytes += bytes;
        loop {
            if self.bytes <= LISTING_CACHE_BUDGET && charge(self.bytes) {
                return self.bodies.contains_key(&entry);
            }
            let Some(victim) = self
                .bodies
                .keys()
                .copied()
                .max_by_key(|address| address.abs_diff(center))
            else {
                charge(0);
                return false;
            };
            let removed = self.bodies.remove(&victim).expect("victim exists");
            self.bytes -= removed.bytes;
        }
    }

    /// Frees every view and per-context failure. Blocked entries stay
    /// blocked; a new binary starts from a new cache.
    pub fn clear(&mut self) {
        if !self.bodies.is_empty() || !self.failed.is_empty() {
            self.epoch = self.epoch.wrapping_add(1);
        }
        self.bodies.clear();
        self.failed.clear();
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BasicBlock, Instruction};

    static NONE: Expansions = Expansions {
        ranges: BTreeMap::new(),
        epoch: 0,
    };

    fn section(address: u64, size: u64, file_size: u64) -> SectionInfo {
        SectionInfo {
            name: format!("s{address:x}"),
            address,
            size,
            file_offset: 0,
            file_size,
            executable: true,
        }
    }

    fn view(entry: u64, instructions: &[(u64, usize)]) -> FunctionView {
        FunctionView {
            address: entry,
            blocks: vec![BasicBlock {
                address: instructions.first().map_or(entry, |i| i.0),
                instructions: instructions
                    .iter()
                    .map(|&(address, length)| Instruction {
                        address,
                        bytes: vec![0x90; length],
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

    fn functions(entries: &[u64]) -> Vec<FunctionInfo> {
        entries
            .iter()
            .map(|&address| FunctionInfo {
                address,
                name: format!("f{address:x}"),
            })
            .collect()
    }

    fn rows(sections: &[SectionInfo], views: &[FunctionView], failed: &[u64]) -> ProgramRows {
        let indexes: Vec<_> = views.iter().map(ListingIndex::new).collect();
        ProgramRows::new(
            sections,
            views.iter().zip(&indexes).map(|(view, index)| BodySource {
                owner: view.address,
                listing: index.listing(view),
            }),
            failed.iter().copied(),
        )
    }

    fn forward(layout: &Layout<'_>) -> Vec<Row> {
        let mut all = Vec::new();
        let mut row = layout.at_or_after(Position::new(0, Rank::Section));
        while let Some(current) = row {
            assert!(all.len() < 10_000, "forward iteration terminates");
            all.push(current);
            row = layout.next(&current);
        }
        all
    }

    fn backward(layout: &Layout<'_>) -> Vec<Row> {
        let mut all = Vec::new();
        let mut row = layout.before(Position::new(u64::MAX, Rank::Body));
        while let Some(current) = row {
            assert!(all.len() < 10_000, "backward iteration terminates");
            all.push(current);
            row = layout.previous(&current);
        }
        all.reverse();
        all
    }

    /// Every mapped byte is covered by exactly one body row, in order, and
    /// positions strictly increase.
    fn check_partition(sections: &[SectionInfo], all: &[Row]) {
        for pair in all.windows(2) {
            assert!(pair[0].position() < pair[1].position(), "{pair:?}");
        }
        let covered: Vec<(u64, u64)> = all.iter().filter_map(Row::span).collect();
        let mut expected = Vec::new();
        for section in sections.iter().filter(|s| s.size > 0) {
            expected.push((section.address, section.address + section.size));
        }
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in covered {
            match merged.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => merged.push((start, end)),
            }
        }
        let mut expected_merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in expected {
            match expected_merged.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => expected_merged.push((start, end)),
            }
        }
        assert_eq!(merged, expected_merged);
        for row in all {
            if let Row::ZeroFill { start, end } = row {
                let section = sections
                    .iter()
                    .find(|s| s.address <= *start && *end <= s.address + s.size)
                    .unwrap();
                assert!(*start >= section.address + section.file_size.min(section.size));
            }
        }
    }

    /// Sections, loaded views, inventory entries and failed entries.
    type Synthetic = (Vec<SectionInfo>, Vec<FunctionView>, Vec<u64>, Vec<u64>);

    fn synthetic_layouts() -> Vec<Synthetic> {
        vec![
            // Two functions with a gap, an unloaded entry, a zero-fill tail,
            // a separate data section and a hole between sections.
            (
                vec![section(0x1000, 0x100, 0x80), section(0x2000, 0x40, 0x40)],
                vec![
                    view(0x1000, &[(0x1000, 2), (0x1002, 3), (0x1010, 1)]),
                    view(0x1040, &[(0x1040, 4)]),
                ],
                vec![0x1000, 0x1040, 0x1060, 0x2010],
                vec![],
            ),
            // Overlapping claims: identical shared instruction, a misaligned
            // overlap that is omitted, an entry inside another's instruction
            // and a failed entry.
            (
                vec![section(0x4000, 0x40, 0x40)],
                vec![
                    view(0x4000, &[(0x4000, 4), (0x4004, 4), (0x4008, 2)]),
                    view(0x4004, &[(0x4004, 4), (0x4009, 3)]),
                ],
                vec![0x4000, 0x4002, 0x4004, 0x4020, 0x4030],
                vec![0x4030],
            ),
            // Contiguous sections, an instruction crossing their boundary
            // (omitted), a section ending at u64::MAX with a huge tail.
            (
                vec![
                    section(0x10, 0x10, 0x10),
                    section(0x20, 0x10, 0x10),
                    section(u64::MAX - 0x1_0000_0000, 0x1_0000_0000, 0x20),
                ],
                vec![view(0x1c, &[(0x1c, 8)])],
                vec![0x1c, u64::MAX - 0x1_0000_0000],
                vec![],
            ),
            // No functions at all.
            (vec![section(0x0, 0x20, 0x8)], vec![], vec![], vec![]),
        ]
    }

    #[test]
    fn synthetic_layouts_partition_mapped_bytes_once_and_reverse_exactly() {
        for (sections, views, entries, failed) in synthetic_layouts() {
            let program = rows(&sections, &views, &failed);
            let inventory = functions(&entries);
            let layout = program.layout(&inventory, &NONE);
            let all = forward(&layout);
            check_partition(&sections, &all);
            assert_eq!(backward(&layout), all, "backward = reverse of forward");
            for entry in &entries {
                assert!(all.contains(&Row::Function { entry: *entry }), "{entry:x}");
            }
            // Every row resolves to itself and follows its predecessor.
            for (index, row) in all.iter().enumerate() {
                assert_eq!(layout.resolve(row.position()), Some(*row));
                if index > 0 {
                    assert_eq!(layout.previous(row), Some(all[index - 1]));
                }
            }
        }
    }

    #[test]
    fn rows_come_only_from_loaded_views_and_mark_pending_entries() {
        let (sections, views, entries, _) = synthetic_layouts().remove(0);
        let program = rows(&sections, &views, &[]);
        let inventory = functions(&entries);
        let layout = program.layout(&inventory, &NONE);
        let all = forward(&layout);
        assert_eq!(
            all[..6],
            [
                Row::Section {
                    section: 0,
                    start: 0x1000
                },
                Row::Function { entry: 0x1000 },
                Row::Instruction {
                    owner: 0x1000,
                    start: 0x1000,
                    end: 0x1002
                },
                Row::Instruction {
                    owner: 0x1000,
                    start: 0x1002,
                    end: 0x1005
                },
                Row::Undefined {
                    start: 0x1005,
                    end: 0x1010
                },
                Row::Instruction {
                    owner: 0x1000,
                    start: 0x1010,
                    end: 0x1011
                },
            ]
        );
        assert!(all.contains(&Row::Pending {
            entry: 0x1060,
            start: 0x1060,
            end: 0x1080
        }));
        assert!(all.contains(&Row::ZeroFill {
            start: 0x1080,
            end: 0x1100
        }));
        assert!(all.contains(&Row::Pending {
            entry: 0x2010,
            start: 0x2010,
            end: 0x2040
        }));
        // A failed entry is undefined, not pending.
        let failed = rows(&sections, &views, &[0x1060]);
        let layout = failed.layout(&inventory, &NONE);
        assert!(forward(&layout).contains(&Row::Undefined {
            start: 0x1060,
            end: 0x1080
        }));
        // Overlaps: the shared instruction keeps the first claimant, and the
        // misaligned one is omitted rather than shown twice.
        let (sections, views, entries, failed) = synthetic_layouts().remove(1);
        let program = rows(&sections, &views, &failed);
        let inventory = functions(&entries);
        let all = forward(&program.layout(&inventory, &NONE));
        assert!(all.contains(&Row::Instruction {
            owner: 0x4000,
            start: 0x4004,
            end: 0x4008
        }));
        assert!(
            !all.iter()
                .any(|row| matches!(row, Row::Instruction { start: 0x4009, .. }))
        );
        // The instruction crossing contiguous sections is omitted.
        let (sections, views, entries, failed) = synthetic_layouts().remove(2);
        let program = rows(&sections, &views, &failed);
        let inventory = functions(&entries);
        assert!(
            !forward(&program.layout(&inventory, &NONE))
                .iter()
                .any(|row| matches!(row, Row::Instruction { .. }))
        );
    }

    #[test]
    fn cursor_rows_are_exact_and_section_bounds_cover_each_section() {
        for (sections, views, entries, failed) in synthetic_layouts() {
            let program = rows(&sections, &views, &failed);
            let inventory = functions(&entries);
            let layout = program.layout(&inventory, &NONE);
            let all = forward(&layout);
            assert_eq!(layout.first(), all.first().copied());
            assert_eq!(layout.last(), all.last().copied());
            for row in &all {
                let position = row.position();
                assert_eq!(
                    layout.cursor(position.address, Some(position.rank)),
                    Some(*row)
                );
                // Without a rank, an instruction wins over the header that
                // shares its address, which wins over the section.
                let rankless = layout.cursor(position.address, None).unwrap();
                assert_eq!(rankless.position().address, position.address);
                if all.iter().any(|other| {
                    matches!(other, Row::Instruction { start, .. } if *start == position.address)
                }) {
                    assert!(matches!(rankless, Row::Instruction { .. }));
                }
                // Inside a row, never the nearest one.
                if let Some((start, end)) = row.span()
                    && end - start > 1
                    && !all
                        .iter()
                        .any(|other| other.position().address == start + 1)
                {
                    assert_eq!(layout.cursor(start + 1, None), None, "{row:?}");
                }
            }
            for (index, section) in sections.iter().enumerate().filter(|(_, s)| s.size > 0) {
                let Some((first, last)) = layout.section_bounds(section.address + section.size - 1)
                else {
                    panic!("{index}: bounds");
                };
                assert_eq!(
                    first,
                    Row::Section {
                        section: index,
                        start: section.address
                    }
                );
                let after = all.iter().position(|row| *row == last).unwrap() + 1;
                assert!(
                    all.get(after)
                        .is_none_or(|next| matches!(next, Row::Section { .. })),
                    "{last:?} ends its section"
                );
            }
        }
        // Unmapped addresses have no section.
        let (sections, views, entries, _) = synthetic_layouts().remove(0);
        let program = rows(&sections, &views, &[]);
        let inventory = functions(&entries);
        assert_eq!(
            program.layout(&inventory, &NONE).section_bounds(0x1800),
            None
        );
    }

    #[test]
    fn address_scale_is_monotonic_and_clamps_zero_fill() {
        for (sections, views, _, _) in synthetic_layouts() {
            let program = rows(&sections, &views, &[]);
            let scale = AddressScale::new(&program);
            let mut probes: Vec<u64> = vec![0, 1, u64::MAX - 1, u64::MAX];
            for s in &sections {
                for offset in [0, 1, s.file_size, s.size / 2, s.size - 1, s.size] {
                    probes.push(s.address.saturating_add(offset));
                }
                probes.push(s.address.saturating_sub(1));
            }
            probes.sort_unstable();
            let fractions: Vec<f64> = probes.iter().map(|&a| scale.fraction(a)).collect();
            assert!(fractions.windows(2).all(|w| w[0] <= w[1]), "{fractions:?}");
            assert!(fractions.iter().all(|f| (0.0..=1.0).contains(f)));
            let mut previous = 0;
            for step in 0..=100 {
                let address = scale.address(f64::from(step) / 100.0).unwrap();
                assert!(address >= previous, "address_at is monotonic");
                assert!(program.span_at(address).is_some(), "{address:x} is mapped");
                previous = address;
            }
        }
        // A 4 GiB zero-fill tail weighs no more than a small fixed share.
        let program = rows(
            &[
                section(0x1000, 0x10000, 0x10000),
                section(0x100000, 1 << 32, 0x10),
            ],
            &[],
            &[],
        );
        let scale = AddressScale::new(&program);
        assert!(scale.fraction(0x100010) > 0.9);
        assert!(scale.fraction(0x9000) < 0.6);
        assert_eq!(scale.address(1.0), Some(0x100000 + (1 << 32) - 1));
        assert_eq!(scale.address(0.0), Some(0x1000));
    }

    #[test]
    fn cache_needs_track_context_failures_and_budget_eviction() {
        let context = Arc::new(ProgramContext {
            binary_sha256: "a".into(),
            engine_fingerprint: "e",
            signature_fingerprint: "s",
            signature_state: String::new(),
            inventory_state: "1".into(),
            function_name_state: String::new(),
        });
        let newer = Arc::new(ProgramContext {
            inventory_state: "2".into(),
            ..(*context).clone()
        });
        let mut cache = ListingCache::default();
        let mut charged = 0;
        assert!(cache.needs(0x1000, &context));
        let body = CachedBody::new(view(0x1000, &[(0x1000, 1)]), Some(context.clone())).unwrap();
        assert!(cache.insert(0x1000, body, 0x1000, |bytes| {
            charged = bytes;
            true
        }));
        assert_eq!(charged, cache.bytes());
        assert!(!cache.needs(0x1000, &context));
        assert!(cache.needs(0x1000, &newer), "stale bodies are recomputed");
        assert_eq!(cache.owner_of(0x1000), Some(0x1000));
        cache.fail(0x2000, context.clone());
        assert!(!cache.needs(0x2000, &context), "failures are not retried");
        assert!(cache.needs(0x2000, &newer), "but are under a new context");
        cache.block(0x3000);
        cache.clear();
        assert!(!cache.needs(0x3000, &newer), "crashes stay blocked");
        let body = CachedBody::new(view(0x1000, &[(0x1000, 1)]), Some(context.clone())).unwrap();
        assert!(cache.insert(0x1000, body, 0x1000, |_| true));
        // A refused charge evicts the farthest view first, then the new one.
        let near = CachedBody::new(view(0x1100, &[(0x1100, 1)]), Some(context.clone())).unwrap();
        let limit = cache.bytes() + 1;
        let mut refusals = 0;
        assert!(cache.insert(0x1100, near, 0x1100, |bytes| {
            let fits = bytes <= limit;
            refusals += usize::from(!fits);
            fits
        }));
        assert_eq!(refusals, 1);
        assert!(cache.get(0x1000).is_none() && cache.get(0x1100).is_some());
        let far = CachedBody::new(view(0x9000, &[(0x9000, 1)]), Some(context)).unwrap();
        assert!(!cache.insert(0x9000, far, 0x1100, |bytes| bytes == 0));
        assert!(cache.is_empty() && cache.bytes() == 0);
    }

    /// A small deterministic generator for reproducible random layouts.
    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, bound: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) % bound.max(1)
        }
    }

    #[test]
    fn random_expansions_partition_bytes_once_and_reverse_exactly() {
        let mut random = Lcg(7);
        for (sections, views, entries, failed) in synthetic_layouts() {
            let program = rows(&sections, &views, &failed);
            let inventory = functions(&entries);
            for _ in 0..24 {
                let mut expansions = Expansions::default();
                for _ in 0..random.below(6) + 1 {
                    let section = &sections[random.below(sections.len() as u64) as usize];
                    let reach = section.size.min(0x180);
                    let start = section.address + random.below(reach);
                    let end = start.saturating_add(random.below(0x60) + 1);
                    if random.below(4) == 0 {
                        expansions.collapse(start, end);
                    } else {
                        expansions.expand(start, end, None);
                    }
                }
                let layout = program.layout(&inventory, &expansions);
                let all = forward(&layout);
                check_partition(&sections, &all);
                assert_eq!(backward(&layout), all, "backward = reverse of forward");
                for (index, row) in all.iter().enumerate() {
                    assert_eq!(layout.resolve(row.position()), Some(*row));
                    if index > 0 {
                        assert_eq!(layout.previous(row), Some(all[index - 1]));
                    }
                    match *row {
                        Row::Byte { address } => {
                            let (start, end) = layout.byte_run(address).expect("a run");
                            assert!(start <= address && address < end);
                            assert!(expansions.covering(address).is_some());
                            // The run is exactly the consecutive byte rows.
                            let first = all.iter().position(|r| *r == Row::Byte { address: start });
                            let last = all
                                .iter()
                                .position(|r| *r == Row::Byte { address: end - 1 });
                            assert_eq!(last.unwrap() - first.unwrap(), (end - start - 1) as usize);
                        }
                        Row::Undefined { start, end } => {
                            assert!(
                                (start..end).all(|a| expansions.covering(a).is_none()),
                                "{row:?} is collapsed"
                            );
                        }
                        Row::ZeroFill { .. } | Row::Pending { .. } | Row::Instruction { .. } => {
                            let (start, _) = row.span().unwrap();
                            assert_eq!(layout.byte_run(start), None);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    #[test]
    fn one_expansion_shows_at_most_64_kib_and_leaves_the_rest_collapsed() {
        let sections = [section(0x10000, 0x30000, 0x30000)];
        let program = rows(&sections, &[], &[]);
        let gap = Row::Undefined {
            start: 0x10000,
            end: 0x40000,
        };
        assert_eq!(
            program
                .layout(&[], &NONE)
                .first()
                .and_then(|first| { program.layout(&[], &NONE).next(&first) }),
            Some(gap)
        );
        let (start, end) = expand_interval(&gap).unwrap();
        assert_eq!((start, end), (0x10000, 0x10000 + EXPAND_STEP));
        let mut expansions = Expansions::default();
        expansions.expand(start, end, None);
        let layout = program.layout(&[], &expansions);
        let last = Row::Byte { address: end - 1 };
        let remainder = Row::Undefined {
            start: end,
            end: 0x40000,
        };
        assert_eq!(layout.next(&last), Some(remainder));
        assert_eq!(layout.previous(&remainder), Some(last));
        assert_eq!(layout.byte_run(end - 1), Some((start, end)));
        // Expanding the remainder joins the same run.
        let (more_start, more_end) = expand_interval(&remainder).unwrap();
        expansions.expand(more_start, more_end, None);
        assert_eq!(expansions.len(), 1);
        assert_eq!(
            program.layout(&[], &expansions).byte_run(start),
            Some((start, start + 2 * EXPAND_STEP))
        );
        // Zero-filled and decoded rows never expand.
        assert_eq!(
            expand_interval(&Row::ZeroFill {
                start: 0,
                end: 0x10
            }),
            None
        );
    }

    #[test]
    fn bodies_loaded_inside_an_interval_win_over_byte_rows() {
        let sections = [section(0x1000, 0x100, 0x100)];
        let mut expansions = Expansions::default();
        expansions.expand(0x1000, 0x1040, None);
        let empty = rows(&sections, &[], &[]);
        let layout = empty.layout(&[], &expansions);
        assert_eq!(
            layout.resolve(Position::new(0x1010, Rank::Body)),
            Some(Row::Byte { address: 0x1010 })
        );
        // A body loads over part of the interval; an unloaded entry also
        // lies in it.
        let loaded = rows(&sections, &[view(0x1010, &[(0x1010, 4), (0x1014, 4)])], &[]);
        let inventory = functions(&[0x1010, 0x1030]);
        let layout = loaded.layout(&inventory, &expansions);
        let all = forward(&layout);
        check_partition(&sections, &all);
        assert!(all.contains(&Row::Instruction {
            owner: 0x1010,
            start: 0x1014,
            end: 0x1018
        }));
        assert!(!all.contains(&Row::Byte { address: 0x1014 }));
        assert!(all.contains(&Row::Pending {
            entry: 0x1030,
            start: 0x1030,
            end: 0x1100
        }));
        assert_eq!(layout.byte_run(0x1000), Some((0x1000, 0x1010)));
        assert_eq!(layout.byte_run(0x1020), Some((0x1018, 0x1030)));
        assert_eq!(layout.byte_run(0x1030), None);
        // The interval is untouched: an unloaded body would show bytes again.
        assert_eq!(expansions.covering(0x1014), Some((0x1000, 0x1040)));
    }

    #[test]
    fn the_65th_interval_evicts_the_farthest_but_never_the_selected_one() {
        let interval = |index: u64| (index * 0x100, index * 0x100 + 0x10);
        let mut expansions = Expansions::default();
        for index in 0..MAX_EXPANSIONS as u64 {
            let (start, end) = interval(index);
            expansions.expand(start, end, None);
        }
        assert_eq!(expansions.len(), MAX_EXPANSIONS);
        // Adjacent to an existing interval: merged, nothing evicted.
        expansions.expand(0x10, 0x20, None);
        assert_eq!(expansions.len(), MAX_EXPANSIONS);
        assert_eq!(expansions.covering(0x1f), Some((0, 0x20)));
        let epoch = expansions.epoch();
        expansions.expand(0x10000, 0x10010, None);
        assert_ne!(expansions.epoch(), epoch);
        assert_eq!(expansions.len(), MAX_EXPANSIONS);
        assert_eq!(expansions.covering(0), None, "the farthest went");
        assert!(expansions.covering(0x10000).is_some(), "the new one stays");
        // The farthest holds the selection: the next farthest goes instead.
        expansions.expand(0x20000, 0x20010, Some(0x105));
        assert_eq!(expansions.covering(0x105), Some((0x100, 0x110)));
        assert_eq!(expansions.covering(0x205), None);
        assert_eq!(expansions.len(), MAX_EXPANSIONS);
        // Collapsing the middle of an interval keeps its two sides.
        expansions.collapse(0x104, 0x108);
        assert_eq!(expansions.covering(0x103), Some((0x100, 0x104)));
        assert_eq!(expansions.covering(0x108), Some((0x108, 0x110)));
        assert_eq!(expansions.covering(0x105), None);
    }

    #[test]
    fn byte_pages_are_section_aligned_bounded_and_keep_visible_pages() {
        // A section not aligned to the page size, with a short file part.
        let sections = [
            section(0x1010, 0x3000, 0x2100),
            section(0x8000, 0x100, 0x100),
        ];
        let program = rows(&sections, &[], &[]);
        assert_eq!(program.byte_page(0x1010), Some((0x1010, BYTE_PAGE)));
        assert_eq!(program.byte_page(0x2020), Some((0x2010, BYTE_PAGE)));
        assert_eq!(program.byte_page(0x3100), Some((0x3010, 0x100)), "file end");
        assert_eq!(program.byte_page(0x3110), None, "zero-filled");
        assert_eq!(program.byte_page(0x8050), Some((0x8000, 0x100)));
        assert_eq!(program.byte_page(0x7000), None, "unmapped");
        let mut cache = ByteCache::default();
        let page = |start: u64| (start, 0x10);
        let wanted = [page(0x100), page(0x200)];
        assert_eq!(cache.next(&wanted, &[]), Some(page(0x100)));
        assert!(cache.accept(0x100, vec![0xab; 0x10], 0x100, &[]));
        assert_eq!(cache.byte(0x10f), Some(0xab));
        assert_eq!(cache.byte(0x110), None);
        assert_eq!(cache.span(0x100, 0x104), Some(vec![0xab; 4]));
        assert_eq!(cache.span(0x10e, 0x112), None, "partly cached");
        assert_eq!(cache.next(&wanted, &[]), Some(page(0x200)));
        cache.fail(0x200);
        assert_eq!(cache.next(&wanted, &[]), None, "failures are not retried");
        for start in [0x300, 0x400, 0x500] {
            assert!(cache.accept(start, vec![1; 0x10], 0x100, &[]));
        }
        assert_eq!(cache.len(), MAX_BYTE_PAGES);
        // A fifth page evicts the one farthest from the top, but not a
        // visible one.
        assert!(cache.accept(0x600, vec![2; 0x10], 0x100, &[0x500]));
        assert!(cache.contains(0x500) && !cache.contains(0x400));
        assert_eq!(cache.len(), MAX_BYTE_PAGES);
        // With all four visible, no fifth is requested or kept.
        let visible = [0x100, 0x300, 0x500, 0x600];
        assert_eq!(cache.next(&[page(0x700)], &visible), None);
        assert!(!cache.accept(0x700, vec![3; 0x10], 0x100, &visible));
        assert!(!cache.contains(0x700));
        assert_eq!(cache.next(&[page(0x700)], &visible[..3]), Some(page(0x700)));
        // After enough failures nothing more is requested.
        for start in 0..MAX_FAILED_PAGES as u64 {
            cache.fail(0x10000 + start * 0x1000);
        }
        assert_eq!(cache.next(&[page(0x700)], &[]), None);
    }
}
