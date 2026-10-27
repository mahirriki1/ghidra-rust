//! Bounded memory-search contracts, matching, and atomic parent adoption.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::*;
use crate::result_store::TransientReservation;

/// Parent results, domain construction/reader context, spec and matcher scratch.
/// Reserve this before constructing a session; it is below the result-byte cap.
pub const MEMORY_SEARCH_RESERVATION_BYTES: usize =
    MAX_SEARCH_RESULTS * size_of::<MemoryHit>() + 4 * MAX_SECTIONS * size_of::<Span>() + 32 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryPattern {
    Hex {
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_SEARCH_PATTERN_BYTES>")]
        bytes: Vec<u8>,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_SEARCH_PATTERN_BYTES>")]
        mask: Vec<u8>,
    },
    Ascii {
        #[serde(deserialize_with = "crate::bounded::string::<_, MAX_SEARCH_PATTERN_BYTES>")]
        text: String,
    },
    Utf16Le {
        #[serde(deserialize_with = "crate::bounded::string::<_, MAX_SEARCH_PATTERN_BYTES>")]
        text: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySearchSpec {
    pub pattern: MemoryPattern,
    pub match_case: bool,
}

impl MemorySearchSpec {
    pub fn hex(input: &str) -> Result<Self, String> {
        if input.len() > 3 * MAX_SEARCH_PATTERN_BYTES {
            return Err("Hex pattern is too long".into());
        }
        let (mut bytes, mut mask) = (Vec::new(), Vec::new());
        for token in input.split_ascii_whitespace() {
            if bytes.len() == MAX_SEARCH_PATTERN_BYTES || token.len() != 2 {
                return Err("Use two hex digits or ??".into());
            }
            if token == "??" {
                bytes.push(0);
                mask.push(0);
            } else {
                if !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("Use two hex digits or ??".into());
                }
                bytes.push(u8::from_str_radix(token, 16).map_err(|_| "Use two hex digits or ??")?);
                mask.push(255);
            }
        }
        let spec = Self {
            pattern: MemoryPattern::Hex { bytes, mask },
            match_case: true,
        };
        spec.compile()?;
        Ok(spec)
    }

    pub fn compile(&self) -> Result<CompiledPattern, String> {
        let (mut bytes, mask, utf16) = match &self.pattern {
            MemoryPattern::Hex { bytes, mask } => {
                if bytes.is_empty()
                    || bytes.len() > MAX_SEARCH_PATTERN_BYTES
                    || bytes.len() != mask.len()
                    || mask.iter().any(|m| !matches!(m, 0 | 255))
                    || !mask.contains(&255)
                {
                    return Err("Invalid hex mask".into());
                }
                (bytes.clone(), mask.clone(), false)
            }
            MemoryPattern::Ascii { text } => {
                if !text.is_ascii() || text.len() > MAX_SEARCH_PATTERN_BYTES {
                    return Err("Use an ASCII literal of at most 256 bytes".into());
                }
                (text.as_bytes().to_vec(), vec![255; text.len()], false)
            }
            MemoryPattern::Utf16Le { text } => {
                if text.len() > MAX_SEARCH_PATTERN_BYTES {
                    return Err("Text pattern is too long".into());
                }
                let mut bytes = Vec::new();
                for unit in text.encode_utf16() {
                    if bytes.len() + 2 > MAX_SEARCH_PATTERN_BYTES {
                        return Err("Encoded pattern exceeds 256 bytes".into());
                    }
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                let mask = vec![255; bytes.len()];
                (bytes, mask, true)
            }
        };
        if bytes.is_empty() || bytes.len() > MAX_SEARCH_PATTERN_BYTES {
            return Err("Pattern must contain 1–256 bytes".into());
        }
        for (byte, mask) in bytes.iter_mut().zip(&mask) {
            *byte &= mask;
        }
        let folding = !self.match_case && !matches!(self.pattern, MemoryPattern::Hex { .. });
        Ok(CompiledPattern::build(bytes, mask, folding, utf16))
    }

    /// Cached presentation of the submitted literal; wildcards remain unknown.
    pub fn canonical(&self) -> Result<String, String> {
        let compiled = self.compile()?;
        Ok(match &self.pattern {
            MemoryPattern::Hex { .. } => compiled
                .bytes
                .iter()
                .zip(&compiled.mask)
                .map(|(b, m)| {
                    if *m == 0 {
                        "??".into()
                    } else {
                        format!("{b:02X}")
                    }
                })
                .collect::<Vec<_>>()
                .join(" "),
            MemoryPattern::Ascii { text } | MemoryPattern::Utf16Le { text } => text.clone(),
        })
    }
}

/// Four-word Shift-And state; work per input byte is independent of pattern length.
pub struct CompiledPattern {
    table: Box<[[u64; 4]; 256]>,
    bytes: Vec<u8>,
    mask: Vec<u8>,
    folding: bool,
    utf16: bool,
}

impl CompiledPattern {
    fn build(bytes: Vec<u8>, mask: Vec<u8>, folding: bool, utf16: bool) -> Self {
        let mut table = Box::new([[0u64; 4]; 256]);
        for (position, (&byte, &mask)) in bytes.iter().zip(&mask).enumerate() {
            let alternate = folding
                && byte.is_ascii_alphabetic()
                && (!utf16 || (position % 2 == 0 && bytes.get(position + 1) == Some(&0)));
            for candidate in 0..=255u8 {
                if mask == 0 || candidate == byte || (alternate && candidate == (byte ^ 32)) {
                    table[candidate as usize][position / 64] |= 1 << (position % 64);
                }
            }
        }
        Self {
            table,
            bytes,
            mask,
            folding,
            utf16,
        }
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn feed(&self, state: &mut [u64; 4], byte: u8) -> bool {
        let mut carry = 1;
        for (word, mask) in state.iter_mut().zip(self.table[byte as usize]) {
            let next = *word >> 63;
            *word = ((*word << 1) | carry) & mask;
            carry = next;
        }
        state[(self.len() - 1) / 64] & (1 << ((self.len() - 1) % 64)) != 0
    }
}

pub(crate) fn compile_text_literal(
    bytes: Vec<u8>,
    mask: Vec<u8>,
    match_case: bool,
) -> Result<CompiledPattern, String> {
    if bytes.is_empty() || bytes.len() > MAX_SEARCH_PATTERN_BYTES || bytes.len() != mask.len() {
        return Err("Invalid text literal".into());
    }
    Ok(CompiledPattern::build(bytes, mask, !match_case, false))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchBinding {
    #[serde(deserialize_with = "crate::bounded::string::<_, 64>")]
    pub binary_sha256: String,
    pub generation: u64,
    pub search_id: u64,
    pub worker_epoch: u64,
    pub page: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchCursor {
    pub section: u16,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryHit {
    pub address: u64,
    pub length: u16,
    pub section_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchStop {
    More,
    Complete,
    ScanLimit,
    ResultLimit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemorySearchPage {
    pub binding: SearchBinding,
    #[serde(deserialize_with = "crate::bounded::string::<_, 64>")]
    pub spec_digest: String,
    pub start_cursor: SearchCursor,
    pub next_cursor: Option<SearchCursor>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_SEARCH_PAGE_RESULTS>")]
    pub hits: Vec<MemoryHit>,
    pub scanned: u64,
    pub stop: SearchStop,
}

#[derive(Clone, Debug)]
struct Span {
    address: u64,
    file_offset: u64,
    length: u64,
    prefix: u64,
}

/// Prefix ranks count mapped aliases separately and include unmatchable tails.
#[derive(Clone, Debug)]
pub struct SearchDomain {
    spans: Vec<Span>,
    total: u64,
    clipped: bool,
    identity: [u8; 32],
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl SearchDomain {
    pub fn new(sections: &[SectionInfo], file_len: u64) -> Result<Self, String> {
        if sections.len() > MAX_SECTIONS || sections.len() > u16::MAX as usize {
            return Err("Too many search sections".into());
        }
        let mut ranges = Vec::with_capacity(sections.len());
        let mut spans = Vec::with_capacity(sections.len());
        let (mut total, mut mapped) = (0u64, 0u64);
        let mut hash = Sha256::new();
        hash.update(b"ghidra-rust-search-domain-v1\0");
        hash.update(file_len.to_le_bytes());
        for section in sections {
            let end = section
                .address
                .checked_add(section.size)
                .ok_or("Section address overflow")?;
            let file_end = section
                .file_offset
                .checked_add(section.file_size)
                .ok_or("Section file overflow")?;
            if section.file_size > section.size || file_end > file_len {
                return Err("Invalid file-backed search section".into());
            }
            if section.size != 0 {
                ranges.push((section.address, end));
            }
            mapped = mapped
                .checked_add(section.file_size)
                .ok_or("Search domain overflow")?;
            let length = section
                .file_size
                .min(crate::analysis::MAX_IMAGE_BYTES - total);
            spans.push(Span {
                address: section.address,
                file_offset: section.file_offset,
                length,
                prefix: total,
            });
            total += length;
            for field in [
                section.address,
                section.size,
                section.file_offset,
                section.file_size,
            ] {
                hash.update(field.to_le_bytes());
            }
        }
        ranges.sort_unstable();
        if ranges.windows(2).any(|r| r[0].1 > r[1].0) {
            return Err("Overlapping virtual search sections".into());
        }
        Ok(Self {
            spans,
            total,
            clipped: mapped > total,
            identity: hash.finalize().into(),
        })
    }

    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn clipped(&self) -> bool {
        self.clipped
    }
    pub fn end(&self) -> SearchCursor {
        SearchCursor {
            section: self.spans.len() as u16,
            offset: 0,
        }
    }
    pub fn start(&self) -> SearchCursor {
        self.cursor(0).expect("zero rank")
    }

    pub fn cursor(&self, rank: u64) -> Result<SearchCursor, String> {
        if rank > self.total {
            return Err("Search rank exceeds domain".into());
        }
        if rank == self.total {
            return Ok(self.end());
        }
        let index = self
            .spans
            .partition_point(|span| span.prefix + span.length <= rank);
        Ok(SearchCursor {
            section: index as u16,
            offset: rank - self.spans[index].prefix,
        })
    }

    pub fn rank(&self, cursor: SearchCursor) -> Result<u64, String> {
        if cursor == self.end() {
            return Ok(self.total);
        }
        let span = self
            .spans
            .get(cursor.section as usize)
            .ok_or("Invalid search cursor section")?;
        if cursor.offset >= span.length {
            return Err("Noncanonical search cursor".into());
        }
        Ok(span.prefix + cursor.offset)
    }

    pub fn digest(&self, image: &str, pattern: &CompiledPattern) -> Result<String, String> {
        if !valid_digest(image) {
            return Err("Invalid search image digest".into());
        }
        let mut hash = Sha256::new();
        hash.update(b"ghidra-rust-memory-search-v1\0");
        hash.update(image.as_bytes());
        hash.update(self.identity);
        hash.update((pattern.len() as u16).to_le_bytes());
        hash.update(&pattern.bytes);
        hash.update(&pattern.mask);
        hash.update([pattern.folding as u8, pattern.utf16 as u8]);
        Ok(format!("{:x}", hash.finalize()))
    }

    pub fn request_context(&self, request: &Request) -> Result<SearchPageContext, String> {
        let Request::SearchMemory {
            binding,
            spec,
            cursor,
            remaining_results,
        } = request
        else {
            return Err("Expected memory search request".into());
        };
        if binding.page >= MAX_SEARCH_STEPS || *remaining_results > MAX_SEARCH_RESULTS {
            return Err("Invalid memory search allowance".into());
        }
        self.rank(*cursor)?;
        let pattern = spec.compile()?;
        Ok(SearchPageContext {
            binding: binding.clone(),
            digest: self.digest(&binding.binary_sha256, &pattern)?,
            cursor: *cursor,
            remaining_results: *remaining_results,
            length: pattern.len() as u16,
        })
    }

    /// Validates a whole page without changing any parent state.
    pub fn validate_page(
        &self,
        context: &SearchPageContext,
        page: &MemorySearchPage,
    ) -> Result<(), String> {
        let _timing = crate::performance::span("search_page_validation");
        if page.binding != context.binding
            || page.spec_digest != context.digest
            || page.start_cursor != context.cursor
        {
            return Err("Memory search reply binding mismatch".into());
        }
        let start = self.rank(context.cursor)?;
        let end = start
            .checked_add(page.scanned)
            .filter(|end| *end <= self.total)
            .ok_or("Invalid search progress")?;
        let step_end = self.total.min(start.saturating_add(MAX_SEARCH_STEP_BYTES));
        let limit = context.remaining_results.clamp(1, MAX_SEARCH_PAGE_RESULTS);
        if end > step_end || page.hits.len() > limit || (page.scanned == 0 && start != self.total) {
            return Err("Invalid search page work".into());
        }
        let mut previous = None;
        for hit in &page.hits {
            let span = self
                .spans
                .get(hit.section_index as usize)
                .ok_or("Invalid search hit section")?;
            let offset = hit
                .address
                .checked_sub(span.address)
                .ok_or("Invalid search hit address")?;
            let hit_end = offset
                .checked_add(hit.length as u64)
                .ok_or("Search hit overflow")?;
            if hit.length != context.length
                || hit_end > span.length
                || hit.address.checked_add(hit.length as u64).is_none()
            {
                return Err("Invalid search hit extent".into());
            }
            let rank = span
                .prefix
                .checked_add(offset)
                .ok_or("Search hit rank overflow")?;
            if rank < start || rank >= end || previous.is_some_and(|p| p >= rank) {
                return Err("Search hits outside tested range or unordered".into());
            }
            previous = Some(rank);
        }
        if context.remaining_results == 0 && !page.hits.is_empty() {
            if page.stop != SearchStop::ResultLimit
                || page.next_cursor.is_some()
                || previous != end.checked_sub(1)
            {
                return Err("Invalid search result probe".into());
            }
            return Ok(());
        }
        let full = page.hits.len() == limit;
        if full && previous != end.checked_sub(1) {
            return Err("Full search page did not resume after its last hit".into());
        }
        if !full && end != step_end {
            return Err("Short search page skipped work".into());
        }
        if end == self.total {
            let expected = if self.clipped {
                SearchStop::ScanLimit
            } else {
                SearchStop::Complete
            };
            if page.stop != expected || page.next_cursor.is_some() {
                return Err("Invalid search terminal reason".into());
            }
        } else if page.stop != SearchStop::More || page.next_cursor != Some(self.cursor(end)?) {
            return Err("Invalid search continuation".into());
        }
        Ok(())
    }

    /// Scan only immutable, exact file slices. Each restart reconstructs state.
    pub fn scan(
        &self,
        snapshot: &[u8],
        pattern: &CompiledPattern,
        context: &SearchPageContext,
    ) -> Result<MemorySearchPage, String> {
        let timing = crate::performance::span("search_page_scan");
        let start = self.rank(context.cursor)?;
        let step_end = self.total.min(start.saturating_add(MAX_SEARCH_STEP_BYTES));
        let limit = context.remaining_results.clamp(1, MAX_SEARCH_PAGE_RESULTS);
        let mut hits = Vec::with_capacity(limit);
        let mut end = step_end;
        'sections: for (index, span) in self
            .spans
            .iter()
            .enumerate()
            .skip(context.cursor.section as usize)
        {
            let begin = start.saturating_sub(span.prefix);
            let fresh_end = step_end.saturating_sub(span.prefix).min(span.length);
            if begin >= fresh_end {
                continue;
            }
            let read_end = fresh_end
                .saturating_add(pattern.len() as u64 - 1)
                .min(span.length);
            let file_start = span
                .file_offset
                .checked_add(begin)
                .ok_or("Search file offset overflow")?;
            let file_end = span
                .file_offset
                .checked_add(read_end)
                .ok_or("Search file end overflow")?;
            let bytes = snapshot
                .get(
                    usize::try_from(file_start).map_err(|_| "Search offset overflow")?
                        ..usize::try_from(file_end).map_err(|_| "Search end overflow")?,
                )
                .ok_or("Search outside snapshot")?;
            let mut state = [0; 4];
            let mut consumed = 0u64;
            for chunk in bytes.chunks(MAX_BYTE_READ) {
                for &byte in chunk {
                    consumed += 1;
                    if pattern.feed(&mut state, byte) {
                        let offset = begin + consumed - pattern.len() as u64;
                        if offset >= fresh_end {
                            continue;
                        }
                        hits.push(MemoryHit {
                            address: span
                                .address
                                .checked_add(offset)
                                .ok_or("Search address overflow")?,
                            length: pattern.len() as u16,
                            section_index: index as u16,
                        });
                        if hits.len() == limit {
                            end = span.prefix + offset + 1;
                            break 'sections;
                        }
                    }
                }
            }
        }
        let stop = if context.remaining_results == 0 && !hits.is_empty() {
            SearchStop::ResultLimit
        } else if end == self.total {
            if self.clipped {
                SearchStop::ScanLimit
            } else {
                SearchStop::Complete
            }
        } else {
            SearchStop::More
        };
        let page = MemorySearchPage {
            binding: context.binding.clone(),
            spec_digest: context.digest.clone(),
            start_cursor: context.cursor,
            next_cursor: if stop == SearchStop::More {
                Some(self.cursor(end)?)
            } else {
                None
            },
            hits,
            scanned: end - start,
            stop,
        };
        self.validate_page(context, &page)?;
        timing.finish(page.scanned);
        Ok(page)
    }
}

#[derive(Clone, Debug)]
pub struct SearchPageContext {
    pub binding: SearchBinding,
    pub digest: String,
    pub cursor: SearchCursor,
    pub remaining_results: usize,
    pub length: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchState {
    Searching,
    Complete,
    Partial,
    Canceled,
    Stale,
    Unavailable,
}

/// Single logical query; attempts are charged before dispatch, including abandoned pages.
pub struct MemorySearchSession {
    domain: SearchDomain,
    spec: MemorySearchSpec,
    binding: SearchBinding,
    cursor: SearchCursor,
    pending: Option<SearchPageContext>,
    hits: Vec<MemoryHit>,
    state: SearchState,
    scanned: u64,
    attempts: u64,
    work: u64,
    _reservation: TransientReservation,
}

impl MemorySearchSession {
    pub fn new(
        info: &BinaryInfo,
        generation: u64,
        search_id: u64,
        spec: MemorySearchSpec,
        reservation: TransientReservation,
    ) -> Result<Self, String> {
        if reservation.capacity() < MEMORY_SEARCH_RESERVATION_BYTES {
            return Err("Memory search reservation is too small".into());
        }
        spec.compile()?;
        let spec = spec.clone();
        if !valid_digest(&info.sha256) {
            return Err("Invalid search binary digest".into());
        }
        let domain = SearchDomain::new(&info.sections, info.file_len)?;
        let cursor = domain.start();
        Ok(Self {
            domain,
            spec,
            binding: SearchBinding {
                binary_sha256: info.sha256.clone(),
                generation,
                search_id,
                worker_epoch: 0,
                page: 0,
            },
            cursor,
            pending: None,
            hits: Vec::with_capacity(MAX_SEARCH_RESULTS),
            state: SearchState::Searching,
            scanned: 0,
            attempts: 0,
            work: 0,
            _reservation: reservation,
        })
    }
    pub fn hits(&self) -> &[MemoryHit] {
        &self.hits
    }
    pub fn state(&self) -> SearchState {
        self.state
    }
    pub fn scanned(&self) -> u64 {
        self.scanned
    }
    pub fn attempts(&self) -> u64 {
        self.attempts
    }
    /// Conservative execution allowance, including abandoned attempts and lookahead.
    pub fn work(&self) -> u64 {
        self.work
    }
    pub fn cursor(&self) -> SearchCursor {
        self.cursor
    }
    pub fn spec(&self) -> &MemorySearchSpec {
        &self.spec
    }

    pub fn next_request(&mut self, worker_epoch: u64) -> Result<Option<Request>, String> {
        if self.state != SearchState::Searching || self.pending.is_some() {
            return Ok(None);
        }
        if self.attempts == MAX_SEARCH_STEPS {
            self.state = SearchState::Partial;
            return Ok(None);
        }
        self.binding.worker_epoch = worker_epoch;
        self.binding.page = self.attempts;
        let request = Request::SearchMemory {
            binding: self.binding.clone(),
            spec: self.spec.clone(),
            cursor: self.cursor,
            remaining_results: MAX_SEARCH_RESULTS - self.hits.len(),
        };
        self.pending = Some(self.domain.request_context(&request)?);
        self.attempts += 1;
        self.work = self
            .work
            .checked_add(MAX_SEARCH_STEP_BYTES + MAX_SEARCH_PATTERN_BYTES as u64 - 1)
            .ok_or("Search work overflow")?;
        Ok(Some(request))
    }

    pub fn accept(&mut self, page: MemorySearchPage) -> Result<(), String> {
        if self.state != SearchState::Searching {
            return Err("Search is no longer active".into());
        }
        let pending = self.pending.as_ref().ok_or("No search page in flight")?;
        self.domain.validate_page(pending, &page)?;
        let scanned = self
            .scanned
            .checked_add(page.scanned)
            .filter(|n| *n <= self.domain.total)
            .ok_or("Cumulative search work overflow")?;
        let cursor = self
            .domain
            .cursor(self.domain.rank(self.cursor)? + page.scanned)?;
        let attempted = MAX_SEARCH_STEP_BYTES + MAX_SEARCH_PATTERN_BYTES as u64 - 1;
        let actual_bound = page.scanned
            + if page.scanned == 0 {
                0
            } else {
                pending.length as u64 - 1
            };
        let work = self
            .work
            .checked_sub(attempted - actual_bound)
            .ok_or("Invalid cumulative search work")?;
        if pending.remaining_results != 0 {
            self.hits.extend_from_slice(&page.hits);
        }
        self.work = work;
        self.scanned = scanned;
        self.cursor = cursor;
        self.state = match page.stop {
            SearchStop::More => SearchState::Searching,
            SearchStop::Complete => SearchState::Complete,
            SearchStop::ScanLimit | SearchStop::ResultLimit => SearchState::Partial,
        };
        self.pending = None;
        if self.attempts == MAX_SEARCH_STEPS && self.state == SearchState::Searching {
            self.state = SearchState::Partial;
        }
        crate::performance::event("search_memory_results", self.hits.len() as u64);
        Ok(())
    }
    /// Called only when the old transport has been invalidated/reaped.
    pub fn abandon_page(&mut self) {
        self.pending = None;
    }
    pub fn cancel(&mut self) {
        self.pending = None;
        self.state = SearchState::Canceled;
    }
    pub fn stale(&mut self) {
        self.pending = None;
        self.state = SearchState::Stale;
    }
    pub fn unavailable(&mut self) {
        self.pending = None;
        self.state = SearchState::Unavailable;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ascii(text: &str, match_case: bool) -> MemorySearchSpec {
        MemorySearchSpec {
            pattern: MemoryPattern::Ascii { text: text.into() },
            match_case,
        }
    }
    fn utf16(text: &str, match_case: bool) -> MemorySearchSpec {
        MemorySearchSpec {
            pattern: MemoryPattern::Utf16Le { text: text.into() },
            match_case,
        }
    }
    fn offsets(spec: MemorySearchSpec, bytes: &[u8]) -> Vec<usize> {
        let pattern = spec.compile().unwrap();
        let mut state = [0; 4];
        bytes
            .iter()
            .enumerate()
            .filter(|&(_, &b)| pattern.feed(&mut state, b))
            .map(|(i, _)| i + 1 - pattern.len())
            .collect()
    }
    fn section(address: u64, offset: u64, length: u64) -> SectionInfo {
        SectionInfo {
            name: "test".into(),
            address,
            size: length,
            file_offset: offset,
            file_size: length,
            executable: false,
        }
    }
    fn request(spec: MemorySearchSpec, cursor: SearchCursor, remaining_results: usize) -> Request {
        Request::SearchMemory {
            spec,
            cursor,
            remaining_results,
            binding: SearchBinding {
                binary_sha256: "a".repeat(64),
                generation: 1,
                search_id: 2,
                worker_epoch: 3,
                page: 0,
            },
        }
    }
    fn info(length: usize) -> BinaryInfo {
        BinaryInfo {
            path: String::new(),
            architecture: "x86".into(),
            format: "ELF".into(),
            entry: 0,
            file_len: length as u64,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![section(0x1000, 0, length as u64)],
            functions: vec![],
            functions_truncated: false,
            warnings: vec![],
        }
    }
    fn new_session(
        info: &BinaryInfo,
        generation: u64,
        id: u64,
        spec: MemorySearchSpec,
    ) -> MemorySearchSession {
        let mut results = crate::function_results::FunctionResults::default();
        MemorySearchSession::new(
            info,
            generation,
            id,
            spec,
            results
                .reserve_transient(MEMORY_SEARCH_RESERVATION_BYTES, &[])
                .unwrap(),
        )
        .unwrap()
    }
    fn collect(bytes: &[u8], spec: MemorySearchSpec) -> MemorySearchSession {
        let info = info(bytes.len());
        let domain = SearchDomain::new(&info.sections, info.file_len).unwrap();
        let mut session = new_session(&info, 1, 1, spec.clone());
        while let Some(request) = session.next_request(1).unwrap() {
            let context = domain.request_context(&request).unwrap();
            let page = domain
                .scan(bytes, &spec.compile().unwrap(), &context)
                .unwrap();
            session.accept(page).unwrap();
        }
        session
    }

    #[test]
    fn specified_literal_and_wildcard_offsets_include_overlaps() {
        assert_eq!(offsets(ascii("ABA", true), b"ABABA"), [0, 2]);
        assert_eq!(
            offsets(
                MemorySearchSpec::hex("41 ?? 41").unwrap(),
                &[0x41, 0, 0x41, 255, 0x41]
            ),
            [0, 2]
        );
        assert_eq!(offsets(ascii("aB", false), b"AbabAB"), [0, 2, 4]);
        assert!(offsets(ascii("aB", true), b"AbabAB").is_empty());
        assert_eq!(offsets(ascii("\0", true), &[1, 0, 0, 2]), [1, 2]);
        for bad in ["", "??", "?? ??", "4?", "?4", "4", "4142", "gg", "41 ? 42"] {
            assert!(MemorySearchSpec::hex(bad).is_err(), "{bad}");
        }
        assert!(ascii("é", true).compile().is_err());
        assert!(ascii(&"x".repeat(257), true).compile().is_err());
        assert!(utf16(&"x".repeat(129), true).compile().is_err());
        assert!(MemorySearchSpec::hex(&"41 ".repeat(257)).is_err());
    }

    #[test]
    fn utf16_folds_units_at_both_parities_without_folding_other_units() {
        let bytes = [255, 65, 0, 97, 0, 0, 65, 0];
        assert_eq!(offsets(utf16("A", false), &bytes), [1, 3, 6]);
        assert_eq!(offsets(utf16("A", true), &bytes), [1, 6]);
        assert_eq!(
            offsets(
                utf16("😀", false),
                &[0, 0x3d, 0xd8, 0, 0xde, 0x3d, 0xd8, 0, 0xde]
            ),
            [1, 5]
        );
        assert_eq!(offsets(utf16("\u{141}", false), &[0x41, 1, 0x61, 1]), [0]);
        for length in [1, 64, 65, 128, 129, 255, 256] {
            let mut bytes = vec![0; length + 2];
            bytes[1..length + 1].fill(b'A');
            assert_eq!(
                offsets(ascii(&"A".repeat(length), true), &bytes),
                [1],
                "{length}"
            );
        }
    }

    #[test]
    fn boundaries_and_hit_pages_resume_exact_first_untested_start() {
        let mut bytes = vec![0; MAX_SEARCH_STEP_BYTES as usize + 32];
        for offset in [MAX_BYTE_READ - 1, MAX_SEARCH_STEP_BYTES as usize - 1] {
            bytes[offset..offset + 3].copy_from_slice(b"ABA");
        }
        let session = collect(&bytes, ascii("ABA", true));
        assert_eq!(
            session
                .hits()
                .iter()
                .map(|h| h.address - 0x1000)
                .collect::<Vec<_>>(),
            [65535, 1048575]
        );
        assert_eq!(session.state(), SearchState::Complete);
        assert_eq!(session.scanned(), bytes.len() as u64);
        let session = collect(&vec![b'A'; 600], ascii("AA", true));
        assert_eq!(session.hits().len(), 599);
        assert_eq!(session.hits().first().unwrap().address, 0x1000);
        assert_eq!(session.hits().last().unwrap().address, 0x1000 + 598);
        assert_eq!(session.attempts(), 3);
        for (count, state) in [
            (10_000, SearchState::Complete),
            (10_001, SearchState::Partial),
        ] {
            let session = collect(&vec![b'A'; count], ascii("A", true));
            assert_eq!(session.hits().len(), 10_000);
            assert_eq!(session.state(), state);
            assert_eq!(session.attempts(), if count == 10_000 { 40 } else { 41 });
        }
    }

    #[test]
    fn domains_exclude_zero_fill_and_section_splits_but_keep_file_aliases() {
        let mut sections = vec![section(1, 0, 1), section(2, 1, 1), section(50, 0, 2)];
        sections[1].size = 20;
        let domain = SearchDomain::new(&sections, 2).unwrap();
        let request = request(ascii("AB", true), domain.start(), MAX_SEARCH_RESULTS);
        let page = domain
            .scan(
                b"AB",
                &ascii("AB", true).compile().unwrap(),
                &domain.request_context(&request).unwrap(),
            )
            .unwrap();
        assert_eq!(
            page.hits,
            [MemoryHit {
                address: 50,
                length: 2,
                section_index: 2
            }]
        );
        assert_eq!(page.scanned, 4);
        assert_eq!(
            domain.rank(SearchCursor {
                section: 0,
                offset: 1
            }),
            Err("Noncanonical search cursor".into())
        );
        let empty = SearchDomain::new(&[section(0, 0, 0), section(5, 0, 1)], 1).unwrap();
        assert_eq!(
            empty.start(),
            SearchCursor {
                section: 1,
                offset: 0
            }
        );
        assert!(SearchDomain::new(&[section(u64::MAX, 0, 1)], 1).is_err());
        assert!(SearchDomain::new(&[section(0, u64::MAX, 1)], u64::MAX).is_err());
        assert!(SearchDomain::new(&[section(1, 0, 2), section(2, 0, 2)], 2).is_err());
        let clipped = SearchDomain::new(
            &[
                section(0, 0, crate::analysis::MAX_IMAGE_BYTES),
                section(1 << 40, 0, 4),
            ],
            crate::analysis::MAX_IMAGE_BYTES,
        )
        .unwrap();
        assert!(clipped.clipped());
        assert_eq!(clipped.total(), crate::analysis::MAX_IMAGE_BYTES);
        let context = clipped
            .request_context(&request_at_end(ascii("AB", true), clipped.end()))
            .unwrap();
        assert_eq!(
            clipped
                .scan(&[], &ascii("AB", true).compile().unwrap(), &context)
                .unwrap()
                .stop,
            SearchStop::ScanLimit
        );
    }
    fn request_at_end(spec: MemorySearchSpec, cursor: SearchCursor) -> Request {
        request(spec, cursor, 0)
    }

    #[test]
    fn page_adoption_is_atomic_and_attempts_survive_replacement() {
        let bytes = vec![b'A'; 300];
        let info = info(bytes.len());
        let domain = SearchDomain::new(&info.sections, info.file_len).unwrap();
        let spec = ascii("A", true);
        let mut session = new_session(&info, 1, 1, spec.clone());
        let first = session.next_request(1).unwrap().unwrap();
        let page = domain
            .scan(
                &bytes,
                &spec.compile().unwrap(),
                &domain.request_context(&first).unwrap(),
            )
            .unwrap();
        session.accept(page.clone()).unwrap();
        let next = session.next_request(2).unwrap().unwrap();
        let valid = domain
            .scan(
                &bytes,
                &spec.compile().unwrap(),
                &domain.request_context(&next).unwrap(),
            )
            .unwrap();
        let mut invalid = valid.clone();
        invalid.hits.last_mut().unwrap().length = 2;
        assert!(session.accept(invalid).is_err());
        assert_eq!(session.hits().len(), 256);
        assert_eq!(session.scanned(), 256);
        assert!(session.accept(page).is_err());
        session.abandon_page();
        let retry = session.next_request(3).unwrap().unwrap();
        assert_eq!(session.attempts(), 3);
        let retry = domain
            .scan(
                &bytes,
                &spec.compile().unwrap(),
                &domain.request_context(&retry).unwrap(),
            )
            .unwrap();
        session.accept(retry).unwrap();
        assert_eq!(session.hits().len(), 300);
        assert_eq!(session.scanned(), 300);
        assert_eq!(session.work(), MAX_SEARCH_STEP_BYTES + 255 + 300);
        let mut session = new_session(&info, 1, 1, spec);
        for _ in 0..MAX_SEARCH_STEPS {
            assert!(session.next_request(1).unwrap().is_some());
            session.abandon_page();
        }
        assert!(session.next_request(1).unwrap().is_none());
        assert_eq!(session.state(), SearchState::Partial);
        assert_eq!(
            session.work(),
            MAX_SEARCH_STEPS * (MAX_SEARCH_STEP_BYTES + 255)
        );
    }

    #[test]
    fn protocol_adversaries_and_wire_size_proof() {
        let spec = ascii("A", true);
        let domain = SearchDomain::new(&[section(0, 0, 300)], 300).unwrap();
        let context = domain
            .request_context(&request(spec.clone(), domain.start(), 300))
            .unwrap();
        let valid = domain
            .scan(&[b'A'; 300], &spec.compile().unwrap(), &context)
            .unwrap();
        for modify in [
            |p: &mut MemorySearchPage| p.binding.search_id += 1,
            |p: &mut MemorySearchPage| p.binding.generation += 1,
            |p: &mut MemorySearchPage| p.binding.worker_epoch += 1,
            |p: &mut MemorySearchPage| p.binding.page += 1,
            |p: &mut MemorySearchPage| p.binding.binary_sha256 = "b".repeat(64),
            |p: &mut MemorySearchPage| p.spec_digest = "b".repeat(64),
            |p: &mut MemorySearchPage| p.scanned = MAX_SEARCH_STEP_BYTES + 1,
            |p: &mut MemorySearchPage| p.scanned = 0,
            |p: &mut MemorySearchPage| p.hits[0].section_index = 1,
            |p: &mut MemorySearchPage| p.hits[0].length = 2,
            |p: &mut MemorySearchPage| p.hits[1] = p.hits[0],
            |p: &mut MemorySearchPage| p.hits.swap(0, 1),
            |p: &mut MemorySearchPage| p.hits[0].address = 299,
            |p: &mut MemorySearchPage| {
                p.next_cursor = Some(SearchCursor {
                    section: 0,
                    offset: 255,
                })
            },
            |p: &mut MemorySearchPage| p.next_cursor = None,
            |p: &mut MemorySearchPage| p.stop = SearchStop::ResultLimit,
            |p: &mut MemorySearchPage| p.stop = SearchStop::Complete,
        ] {
            let mut page = valid.clone();
            modify(&mut page);
            assert!(domain.validate_page(&context, &page).is_err());
        }
        let encoded = serde_json::to_vec(&WorkerResponse {
            id: 1,
            response: Response::MemorySearch(valid.clone()),
        })
        .unwrap();
        crate::bounded::check_reply(&encoded).unwrap();
        let mut unknown = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
        unknown["response"]["surprise"] = true.into();
        assert!(serde_json::from_value::<WorkerResponse>(unknown).is_err());
        let mut oversized = encoded.clone();
        oversized.extend(vec![b' '; MAX_MEMORY_SEARCH_REPLY_BYTES]);
        assert!(crate::bounded::check_reply(&oversized).is_err());
        let mut long_digest = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
        long_digest["response"]["spec_digest"] = "a".repeat(65).into();
        assert!(crate::bounded::check_reply(&serde_json::to_vec(&long_digest).unwrap()).is_err());
        let mut nested = serde_json::from_slice::<serde_json::Value>(&encoded).unwrap();
        nested["response"]["hits"] = serde_json::json!(vec![0; 3000]);
        assert!(crate::bounded::check_reply(&serde_json::to_vec(&nested).unwrap()).is_err());
        let nesting = format!(
            r#"{{"id":1,"response":{{"kind":"memory_search","hits":{}0{}}}}}"#,
            "[".repeat(130),
            "]".repeat(130)
        );
        assert!(crate::bounded::check_reply(nesting.as_bytes()).is_err());
        assert!(
            domain
                .request_context(&request(
                    spec.clone(),
                    domain.start(),
                    MAX_SEARCH_RESULTS + 1
                ))
                .is_err()
        );
        for cursor in [
            SearchCursor {
                section: 0,
                offset: 300,
            },
            SearchCursor {
                section: 1,
                offset: 1,
            },
            SearchCursor {
                section: 2,
                offset: 0,
            },
        ] {
            assert!(
                domain
                    .request_context(&request(spec.clone(), cursor, 1))
                    .is_err()
            );
        }
        let wide_spec =
            MemorySearchSpec::hex(&vec!["FF"; MAX_SEARCH_PATTERN_BYTES].join(" ")).unwrap();
        let wire_request = serde_json::to_vec(&WorkerRequest {
            id: u64::MAX,
            request: request(wide_spec, domain.start(), MAX_SEARCH_RESULTS),
        })
        .unwrap();
        assert!(wire_request.len() < 8 * 1024);
        let mut unknown = serde_json::from_slice::<serde_json::Value>(&wire_request).unwrap();
        unknown["request"]["surprise"] = true.into();
        assert!(serde_json::from_value::<WorkerRequest>(unknown).is_err());
        let literal = serde_json::json!({"pattern": {"kind":"ascii", "text": "a".repeat(257)}, "match_case":false});
        assert!(serde_json::from_value::<MemorySearchSpec>(literal).is_err());
        let decoded: WorkerResponse = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(decoded.response, Response::MemorySearch(..)));
        let mut value = serde_json::to_value(&valid).unwrap();
        value["extra"] = true.into();
        assert!(serde_json::from_value::<MemorySearchPage>(value).is_err());
        let mut page = valid;
        page.hits = vec![
            MemoryHit {
                address: u64::MAX,
                length: u16::MAX,
                section_index: u16::MAX
            };
            MAX_SEARCH_PAGE_RESULTS
        ];
        page.binding.generation = u64::MAX;
        page.binding.search_id = u64::MAX;
        page.binding.worker_epoch = u64::MAX;
        page.binding.page = u64::MAX;
        page.start_cursor = SearchCursor {
            section: u16::MAX,
            offset: u64::MAX,
        };
        page.next_cursor = Some(page.start_cursor);
        page.scanned = u64::MAX;
        let wire = serde_json::to_vec(&WorkerResponse {
            id: u64::MAX,
            response: Response::MemorySearch(page.clone()),
        })
        .unwrap();
        assert!(wire.len() + 1 < 27 * 1024);
        crate::bounded::check_reply(&wire).unwrap();
        page.hits.push(page.hits[0]);
        assert!(
            serde_json::from_value::<MemorySearchPage>(serde_json::to_value(page).unwrap())
                .is_err()
        );
    }
}
