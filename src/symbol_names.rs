//! Bounded symbol-name tables: worker-only demangling plus the parent's
//! validated, paged copy.
//!
//! [`demangle`] and [`SymbolTable::build`] run only in a disposable analysis
//! worker, under its existing memory and deadline limits. Input, emitted text,
//! formatter calls and supported parser recursion are bounded here; backend
//! work that emits no text still relies on process containment. Unwinding
//! panics become omissions, not partial names. The desktop never demangles:
//! it validates pages into [`SymbolNames`] and only looks names up.
//!
//! Raw names and addresses remain the caller's identity. Results are display
//! text only and must never establish types, references or no-return evidence.
//! See docs/demangling.md for the audited versions and the MSVC release gate.

use std::fmt::{self, Write};

use sha2::{Digest, Sha256};

use crate::model::{
    MAX_SYMBOL_DISPLAY_BYTES, MAX_SYMBOL_FORMAT_WRITES, MAX_SYMBOL_MSVC_PARSE_WORK,
    MAX_SYMBOL_NAME_PAGE_BYTES, MAX_SYMBOL_NAME_PAGE_RECORDS, MAX_SYMBOL_NAME_RECORDS,
    MAX_SYMBOL_NAME_TABLE_BYTES, MAX_SYMBOL_RAW_BYTES, SYMBOL_DEMANGLE_RECURSION_LIMIT, SymbolName,
    SymbolNamePage, SymbolNameSummary, symbol_record_bytes,
};

/// Container-specific linker decoration, supplied from validated image metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolFormat {
    Other,
    MachO,
    Pe,
}

/// Which parser produced display text, not proof of the source language.
/// Some legacy Rust and Itanium encodings are ambiguous; Rust is tried first,
/// matching the pinned engine's existing policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemangleBackend {
    Rust,
    Itanium,
    Msvc,
}

#[derive(Debug, PartialEq, Eq)]
pub struct DemangledName {
    pub text: String,
    pub backend: DemangleBackend,
}

/// Reasons to use the caller's raw/effective fallback in its entirety.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameOmission {
    InputLimit,
    Invalid,
    OutputLimit,
    WorkLimit,
    BackendUnavailable,
    Panicked,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DemangleOutcome {
    /// The name has no supported mangling prefix. No fallback copy is allocated.
    Plain,
    Display(DemangledName),
    Omitted(NameOmission),
}

/// Build a compact qualified name with no function parameter list or return
/// type. `raw` is borrowed, never rewritten. Oversized or invalid output is
/// discarded entirely, including any prefix emitted before a failure.
pub fn demangle(raw: &str, format: SymbolFormat) -> DemangleOutcome {
    if raw.len() > MAX_SYMBOL_RAW_BYTES {
        return DemangleOutcome::Omitted(NameOmission::InputLimit);
    }
    if raw.is_empty() || raw.chars().any(disallowed) {
        return DemangleOutcome::Omitted(NameOmission::Invalid);
    }
    std::panic::catch_unwind(|| demangle_inner(raw, format))
        .unwrap_or(DemangleOutcome::Omitted(NameOmission::Panicked))
}

fn disallowed(c: char) -> bool {
    c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')
}

fn demangle_inner(raw: &str, format: SymbolFormat) -> DemangleOutcome {
    // Remove exactly one container underscore, only for known mangling prefixes.
    // Never normalize the raw identity or an analyst label in place.
    let name =
        if format == SymbolFormat::MachO && (raw.starts_with("__Z") || raw.starts_with("__R")) {
            &raw[1..]
        } else {
            raw
        };
    if name.starts_with('?') {
        if format != SymbolFormat::Pe {
            return DemangleOutcome::Omitted(NameOmission::BackendUnavailable);
        }
        let limits = ghidra_rust_msvc_demangler::Limits {
            input_bytes: MAX_SYMBOL_RAW_BYTES,
            output_bytes: MAX_SYMBOL_DISPLAY_BYTES,
            format_work: MAX_SYMBOL_FORMAT_WRITES,
            parse_work: MAX_SYMBOL_MSVC_PARSE_WORK,
            depth: SYMBOL_DEMANGLE_RECURSION_LIMIT as usize,
        };
        return match ghidra_rust_msvc_demangler::demangle(name, limits) {
            Ok(text) => {
                let mut output = CappedName::new();
                let result = output.write_str(&text);
                output.finish(result, DemangleBackend::Msvc)
            }
            Err(error) => DemangleOutcome::Omitted(if error.is_output_limit() {
                NameOmission::OutputLimit
            } else if error.is_work_limit() || error.is_recursion_limit_exceeded() {
                NameOmission::WorkLimit
            } else {
                NameOmission::Invalid
            }),
        };
    }
    if !name.starts_with("_R") && !name.starts_with("_Z") {
        return DemangleOutcome::Plain;
    }
    let mut output = CappedName::new();
    if let Ok(symbol) = rustc_demangle::try_demangle(name) {
        let result = write!(&mut output, "{symbol:#}");
        return output.finish(result, DemangleBackend::Rust);
    }
    let options =
        cpp_demangle::ParseOptions::default().recursion_limit(SYMBOL_DEMANGLE_RECURSION_LIMIT);
    let Ok(symbol) = cpp_demangle::Symbol::new_with_options(name.as_bytes(), &options) else {
        return DemangleOutcome::Omitted(NameOmission::Invalid);
    };
    let options = cpp_demangle::DemangleOptions::new()
        .no_params()
        .no_return_type()
        .recursion_limit(SYMBOL_DEMANGLE_RECURSION_LIMIT);
    let result = symbol.structured_demangle(&mut output, &options);
    output.finish(result, DemangleBackend::Itanium)
}

/// A formatting sink rather than a truncation after an unbounded allocation.
/// `write_str` rejects before appending, including when the write straddles a
/// UTF-8 boundary. A sticky failure cannot turn into a successful partial name.
struct CappedName {
    text: String,
    writes: usize,
    failure: Option<NameOmission>,
}

impl CappedName {
    fn new() -> Self {
        Self {
            text: String::with_capacity(MAX_SYMBOL_DISPLAY_BYTES),
            writes: 0,
            failure: None,
        }
    }

    fn finish(self, result: fmt::Result, backend: DemangleBackend) -> DemangleOutcome {
        if let Some(reason) = self.failure {
            return DemangleOutcome::Omitted(reason);
        }
        // The Rust backend can defer a v0 backreference error until printing,
        // reporting it as text while returning Ok. Reject its diagnostics too.
        // False negatives for names spelling these markers are intentional.
        let rust_error = backend == DemangleBackend::Rust
            && [
                "{invalid syntax}",
                "{recursion limit reached}",
                "{size limit reached}",
            ]
            .iter()
            .any(|marker| self.text.contains(marker));
        if result.is_err() || self.text.is_empty() || rust_error {
            DemangleOutcome::Omitted(NameOmission::Invalid)
        } else {
            DemangleOutcome::Display(DemangledName {
                // Do not retain the sink's 1 KiB scratch capacity for every
                // short name in the future program-wide table.
                text: self.text.into_boxed_str().into_string(),
                backend,
            })
        }
    }
}

impl Write for CappedName {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        if self.failure.is_some() {
            return Err(fmt::Error);
        }
        let failure = if self.writes == MAX_SYMBOL_FORMAT_WRITES {
            Some(NameOmission::WorkLimit)
        } else if text.len() > MAX_SYMBOL_DISPLAY_BYTES - self.text.len() {
            Some(NameOmission::OutputLimit)
        } else if text.chars().any(disallowed) {
            Some(NameOmission::Invalid)
        } else {
            None
        };
        if let Some(reason) = failure {
            self.failure = Some(reason);
            return Err(fmt::Error);
        }
        self.writes += 1;
        self.text.push_str(text);
        Ok(())
    }
}

/// Container suffix the pinned engine appends to an import stub whose
/// demangled name collides with a defined function.
const PLT_SUFFIX: &str = "@plt";

/// One engine function entry at open, before any analyst replay.
pub struct SymbolSource<'a> {
    pub address: u64,
    /// The exact original symbol: the loader symbol the engine recorded, or the
    /// PE metadata name, never a shortened or collision-suffixed engine name.
    pub raw: &'a str,
    /// The engine's own name for this function at open.
    pub engine: &'a str,
}

/// The worker's immutable table for one opened image. Records exist only
/// where display or lookup gains something: a demangled name, or a raw symbol
/// the engine name does not spell exactly.
pub struct SymbolTable {
    records: Vec<SymbolName>,
    /// Aligned with `records`; never sent. Pseudocode substitutes a display
    /// name only for a token that still spells the engine's open-time name.
    engine: Vec<Box<str>>,
    summary: SymbolNameSummary,
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::build(std::iter::empty(), SymbolFormat::Other)
    }
}

impl SymbolTable {
    /// `sources` must be in strictly increasing address order; others are
    /// skipped. Records beyond the count or byte budget are omitted.
    pub fn build<'a>(
        sources: impl IntoIterator<Item = SymbolSource<'a>>,
        format: SymbolFormat,
    ) -> Self {
        let mut records = Vec::new();
        let mut engine = Vec::new();
        let mut bytes = 0usize;
        let mut truncated = false;
        let mut previous = None;
        for source in sources {
            if previous.is_some_and(|previous| previous >= source.address)
                || !valid_text(source.raw, MAX_SYMBOL_RAW_BYTES)
                || source.engine.len() > MAX_SYMBOL_RAW_BYTES
            {
                continue;
            }
            previous = Some(source.address);
            let display = match demangle(source.raw, format) {
                DemangleOutcome::Display(name) => Some(name.text),
                _ => None,
            }
            .and_then(|mut display| {
                // Keep the engine's import-stub disambiguation visible.
                if source.engine.ends_with(PLT_SUFFIX) && !source.raw.ends_with(PLT_SUFFIX) {
                    if display.len() + PLT_SUFFIX.len() > MAX_SYMBOL_DISPLAY_BYTES {
                        return None;
                    }
                    display.push_str(PLT_SUFFIX);
                }
                (display != source.raw).then_some(display)
            });
            if display.is_none() && source.raw == source.engine {
                continue;
            }
            let record = SymbolName {
                address: source.address,
                raw: source.raw.to_owned(),
                display,
            };
            let size = symbol_record_bytes(&record);
            if records.len() == MAX_SYMBOL_NAME_RECORDS
                || size > MAX_SYMBOL_NAME_TABLE_BYTES - bytes
            {
                truncated = true;
                break;
            }
            bytes += size;
            records.push(record);
            engine.push(source.engine.into());
        }
        let summary = SymbolNameSummary {
            digest: digest(&records),
            records: records.len(),
            truncated,
        };
        Self {
            records,
            engine,
            summary,
        }
    }

    pub fn summary(&self) -> &SymbolNameSummary {
        &self.summary
    }

    /// Records from `cursor`, packed by count and encoded size. A cursor at the
    /// end of a non-empty table is rejected rather than answered empty.
    pub fn page(&self, cursor: usize) -> Result<SymbolNamePage, String> {
        if cursor >= self.records.len() {
            return Err("Symbol-name cursor is outside the table".into());
        }
        let mut bytes = 0;
        let entries: Vec<_> = self.records[cursor..]
            .iter()
            .take(MAX_SYMBOL_NAME_PAGE_RECORDS)
            .enumerate()
            .take_while(|(index, record)| {
                bytes += symbol_record_bytes(record);
                *index == 0 || bytes <= MAX_SYMBOL_NAME_PAGE_BYTES
            })
            .map(|(_, record)| record.clone())
            .collect();
        let end = cursor + entries.len();
        Ok(SymbolNamePage {
            digest: self.summary.digest.clone(),
            cursor,
            next: (end < self.records.len()).then_some(end),
            entries,
        })
    }

    /// The display name to print for a function-name token at an exact,
    /// engine-verified `address`, only while `text` is the engine's open-time
    /// name. Analyst renames and other text are never replaced.
    pub fn display_for(&self, address: u64, text: &str) -> Option<&str> {
        let index = self
            .records
            .binary_search_by_key(&address, |record| record.address)
            .ok()?;
        (*self.engine[index] == *text)
            .then(|| self.records[index].display.as_deref())
            .flatten()
    }
}

fn valid_text(text: &str, limit: usize) -> bool {
    !text.is_empty() && text.len() <= limit && !text.chars().any(disallowed)
}

fn hash_record(hash: &mut Sha256, record: &SymbolName) {
    hash.update(record.address.to_le_bytes());
    hash.update((record.raw.len() as u64).to_le_bytes());
    hash.update(record.raw.as_bytes());
    match &record.display {
        Some(display) => {
            hash.update([1]);
            hash.update((display.len() as u64).to_le_bytes());
            hash.update(display.as_bytes());
        }
        None => hash.update([0]),
    }
}

/// Order-sensitive identity of a complete table.
pub fn digest(records: &[SymbolName]) -> String {
    let mut hash = Sha256::new();
    for record in records {
        hash_record(&mut hash, record);
    }
    format!("{:x}", hash.finalize())
}

/// A validated, adopted table. Lookups are by exact address; text queries
/// compare exact strings and never become identities.
#[derive(Debug, Default)]
pub struct SymbolNames {
    digest: String,
    records: Box<[SymbolName]>,
    truncated: bool,
}

impl SymbolNames {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn truncated(&self) -> bool {
        self.truncated
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[SymbolName] {
        &self.records
    }

    pub fn get(&self, address: u64) -> Option<&SymbolName> {
        self.records
            .binary_search_by_key(&address, |record| record.address)
            .ok()
            .map(|index| &self.records[index])
    }

    /// First address whose exact raw symbol or display name is `query`.
    pub fn find(&self, query: &str) -> Option<u64> {
        let exact = |pick: fn(&SymbolName) -> Option<&str>| {
            self.records
                .iter()
                .find(|record| pick(record) == Some(query))
                .map(|record| record.address)
        };
        exact(|record| Some(&record.raw)).or_else(|| exact(|record| record.display.as_deref()))
    }

    /// Allocation capacity retained by this table.
    pub fn retained_bytes(&self) -> usize {
        self.records.iter().fold(
            size_of::<Self>() + self.digest.capacity() + size_of_val(&*self.records),
            |bytes, record| {
                bytes + record.raw.capacity() + record.display.as_ref().map_or(0, String::capacity)
            },
        )
    }
}

/// Parent-side accumulation of one worker table's pages. Every page must
/// continue the previous cursor, match the announced digest and stay within
/// the per-page and cumulative bounds; the completed records must hash to it.
pub struct SymbolNameFetch {
    summary: SymbolNameSummary,
    records: Vec<SymbolName>,
    bytes: usize,
    hash: Sha256,
}

impl SymbolNameFetch {
    pub fn new(summary: SymbolNameSummary) -> Result<Self, String> {
        if summary.records > MAX_SYMBOL_NAME_RECORDS
            || summary.digest.len() != 64
            || !summary
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("Invalid symbol-name table summary".into());
        }
        Ok(Self {
            records: Vec::with_capacity(summary.records.min(MAX_SYMBOL_NAME_PAGE_RECORDS)),
            summary,
            bytes: 0,
            hash: Sha256::new(),
        })
    }

    pub fn summary(&self) -> &SymbolNameSummary {
        &self.summary
    }

    /// Next cursor to request, or `None` when every record arrived.
    pub fn cursor(&self) -> Option<usize> {
        (self.records.len() < self.summary.records).then_some(self.records.len())
    }

    /// Validates and appends one page; nothing is appended on error.
    pub fn accept(&mut self, page: SymbolNamePage) -> Result<(), String> {
        let cursor = self.cursor().ok_or("Unexpected symbol-name page")?;
        let end = cursor.saturating_add(page.entries.len());
        let mut previous = self.records.last().map(|record| record.address);
        let mut page_bytes = 0usize;
        for record in &page.entries {
            if previous.is_some_and(|previous| previous >= record.address)
                || !valid_text(&record.raw, MAX_SYMBOL_RAW_BYTES)
                || record.display.as_deref().is_some_and(|display| {
                    !valid_text(display, MAX_SYMBOL_DISPLAY_BYTES) || display == record.raw
                })
            {
                return Err("Invalid or unordered symbol-name record".into());
            }
            previous = Some(record.address);
            page_bytes = page_bytes.saturating_add(symbol_record_bytes(record));
        }
        if page.digest != self.summary.digest
            || page.cursor != cursor
            || page.entries.is_empty()
            || page.entries.len() > MAX_SYMBOL_NAME_PAGE_RECORDS
            || end > self.summary.records
            || page.next != (end < self.summary.records).then_some(end)
            || page.entries.len() > 1 && page_bytes > MAX_SYMBOL_NAME_PAGE_BYTES
            || page_bytes > MAX_SYMBOL_NAME_TABLE_BYTES - self.bytes
        {
            return Err("Symbol-name page does not continue its table within bounds".into());
        }
        if end == self.summary.records {
            let mut hash = self.hash.clone();
            for record in &page.entries {
                hash_record(&mut hash, record);
            }
            if format!("{:x}", hash.finalize()) != self.summary.digest {
                return Err("Symbol-name pages do not match their table digest".into());
            }
        }
        for record in &page.entries {
            hash_record(&mut self.hash, record);
        }
        self.bytes += page_bytes;
        self.records.extend(page.entries);
        Ok(())
    }

    /// The adopted table once [`Self::cursor`] is `None`.
    pub fn finish(self) -> Option<SymbolNames> {
        (self.records.len() == self.summary.records).then(|| SymbolNames {
            digest: self.summary.digest,
            records: self.records.into_boxed_slice(),
            truncated: self.summary.truncated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn display(raw: &str, format: SymbolFormat) -> String {
        match demangle(raw, format) {
            DemangleOutcome::Display(name) => name.text,
            other => panic!("{raw}: {other:?}"),
        }
    }

    #[test]
    fn qualified_cpp_names_keep_overloads_separate_by_raw_identity() {
        let names = ["_ZN4demo3fooEi", "_ZN4demo3fooEd"];
        for name in names {
            assert_eq!(display(name, SymbolFormat::Other), "demo::foo");
        }
        assert_ne!(names[0], names[1]);
        for (raw, expected) in [
            ("_ZN4demo3fooIiEEvT_", "demo::foo<int>"),
            ("_ZN4demo6WidgetC1Ev", "demo::Widget::Widget"),
            ("_ZN4demo6WidgetplEi", "demo::Widget::operator+"),
        ] {
            assert_eq!(display(raw, SymbolFormat::Other), expected);
        }
    }

    #[test]
    fn msvc_compact_pe_names_preserve_raw_identity_and_fallbacks() {
        for (raw, expected) in [
            ("??0Widget@demo@@QEAA@XZ", "demo::Widget::Widget"),
            ("??1Widget@demo@@QEAA@XZ", "demo::Widget::~Widget"),
            ("??HWidget@demo@@QEAAHH@Z", "demo::Widget::operator+"),
            (
                "??$identity@H@inner@demo@@YAHH@Z",
                "demo::inner::identity<int>",
            ),
            (
                "?foo@?A0x12345678@demo@@YAXXZ",
                "demo::`anonymous namespace'::foo",
            ),
            ("??_7Widget@demo@@6B@", "demo::Widget::`vftable'"),
        ] {
            let original = raw.to_owned();
            assert_eq!(
                demangle(raw, SymbolFormat::Pe),
                DemangleOutcome::Display(DemangledName {
                    text: expected.into(),
                    backend: DemangleBackend::Msvc,
                })
            );
            assert_eq!(raw, original);
            assert_eq!(
                demangle(raw, SymbolFormat::MachO),
                DemangleOutcome::Omitted(NameOmission::BackendUnavailable)
            );
        }
        for raw in ["?overloaded@@YAHH@Z", "?overloaded@@YANN@Z"] {
            assert_eq!(display(raw, SymbolFormat::Pe), "overloaded");
        }
        let long = format!("?{}@@YAXXZ", "a".repeat(MAX_SYMBOL_DISPLAY_BYTES + 1));
        assert_eq!(
            demangle(&long, SymbolFormat::Pe),
            DemangleOutcome::Omitted(NameOmission::OutputLimit)
        );
        let hidden_bomb = format!("?f@@YAXV?$T@H@@{}@Z", "0".repeat(3000));
        let output_bomb = format!("??$f@V{}@@{}@@YAXXZ", "a".repeat(32), "0".repeat(40));
        let deep = format!("?x@@3{}HA", "PEA".repeat(1000));
        for raw in [
            hidden_bomb,
            output_bomb,
            deep,
            "?".into(),
            "?foo@@YAXXZjunk".into(),
        ] {
            assert!(
                matches!(
                    demangle(&raw, SymbolFormat::Pe),
                    DemangleOutcome::Omitted(_)
                ),
                "{raw}"
            );
        }
    }

    #[test]
    fn rust_legacy_and_v0_display_without_legacy_hash() {
        for name in ["_ZN4demo3foo17h0123456789abcdefE", "_RNvC4demo3foo"] {
            assert_eq!(display(name, SymbolFormat::Other), "demo::foo");
        }
    }

    #[test]
    fn container_prefix_is_explicit_and_raw_names_stay_untouched() {
        let raw = "__ZN4demo3fooEi".to_owned();
        let original = raw.clone();
        assert_eq!(demangle(&raw, SymbolFormat::Other), DemangleOutcome::Plain);
        assert_eq!(display(&raw, SymbolFormat::MachO), "demo::foo");
        assert_eq!(display("__RNvC4demo3foo", SymbolFormat::MachO), "demo::foo");
        assert_eq!(
            demangle("___ZN4demo3fooEi", SymbolFormat::MachO),
            DemangleOutcome::Plain
        );
        assert_eq!(raw, original);
    }

    #[test]
    fn invalid_oversized_and_unavailable_names_fall_back_without_display() {
        for raw in ["", "_Z!", "_RNv", "_ZN1aE\n", "_Z\0bad"] {
            assert_eq!(
                demangle(raw, SymbolFormat::Other),
                DemangleOutcome::Omitted(NameOmission::Invalid)
            );
        }
        assert_eq!(
            demangle(&"x".repeat(MAX_SYMBOL_RAW_BYTES + 1), SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::InputLimit)
        );
        assert_eq!(
            demangle("?foo@@YAXH@Z", SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::BackendUnavailable)
        );
        assert_eq!(
            demangle("exit", SymbolFormat::Other),
            DemangleOutcome::Plain
        );
        let long = "a".repeat(MAX_SYMBOL_DISPLAY_BYTES + 1);
        assert_eq!(
            demangle(&format!("_Z{}{long}v", long.len()), SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::OutputLimit)
        );
    }

    #[test]
    fn deep_types_and_malformed_prefixes_never_publish_partial_names() {
        let deep = format!("_Z3foo{}i", "P".repeat(1000));
        assert_eq!(
            demangle(&deep, SymbolFormat::Other),
            DemangleOutcome::Omitted(NameOmission::Invalid)
        );
        // Every truncation of representative complex encodings is untrusted.
        for name in [
            "_ZN4demo3fooIiEEvT_",
            "_RNvC4demo3foo",
            "_ZN4demo6WidgetC1Ev",
        ] {
            for end in 1..name.len() {
                if let DemangleOutcome::Display(display) =
                    demangle(&name[..end], SymbolFormat::Other)
                {
                    assert!(!display.text.is_empty());
                    assert!(display.text.len() <= MAX_SYMBOL_DISPLAY_BYTES);
                    assert!(!display.text.chars().any(disallowed));
                }
            }
        }
    }

    #[test]
    fn utf8_and_formatter_work_exhaustion_discard_the_entire_result() {
        let mut sink = CappedName::new();
        sink.write_str(&"a".repeat(MAX_SYMBOL_DISPLAY_BYTES - 1))
            .unwrap();
        assert!(sink.write_str("é").is_err());
        // Even a formatter that swallows the error cannot publish its prefix.
        assert_eq!(
            sink.finish(Ok(()), DemangleBackend::Rust),
            DemangleOutcome::Omitted(NameOmission::OutputLimit)
        );
        let mut sink = CappedName::new();
        for _ in 0..MAX_SYMBOL_FORMAT_WRITES {
            sink.write_str("").unwrap();
        }
        assert!(sink.write_str("").is_err());
        assert_eq!(
            sink.finish(Ok(()), DemangleBackend::Rust),
            DemangleOutcome::Omitted(NameOmission::WorkLimit)
        );
    }

    #[test]
    fn rust_deferred_backreference_errors_are_not_display_names() {
        // The referenced type is hidden inside a valid crate identifier, so
        // the initial parser can accept it; formatting must reject the cycle.
        let depth = 500;
        let mut raw = format!("_RIC{depth}");
        let backref_start = raw.len() - 2;
        raw.push_str(&"R".repeat(depth));
        raw.push('B');
        raw.push(char::from_digit((backref_start - 1) as u32, 36).unwrap());
        raw.push_str("_E");
        assert!(matches!(
            demangle(&raw, SymbolFormat::Other),
            DemangleOutcome::Omitted(_)
        ));
    }

    fn source<'a>(address: u64, raw: &'a str, engine: &'a str) -> SymbolSource<'a> {
        SymbolSource {
            address,
            raw,
            engine,
        }
    }

    fn fetch_all(table: &SymbolTable) -> SymbolNames {
        let mut fetch = SymbolNameFetch::new(table.summary().clone()).unwrap();
        while let Some(cursor) = fetch.cursor() {
            fetch.accept(table.page(cursor).unwrap()).unwrap();
        }
        fetch.finish().unwrap()
    }

    #[test]
    fn tables_keep_exact_raw_identities_and_omit_names_with_nothing_to_add() {
        let table = SymbolTable::build(
            [
                source(0x1000, "_ZN4demo3fooEi", "demo::foo"),
                source(0x1010, "_ZN4demo3fooEd", "demo::foo"),
                source(0x1020, "?foo@@YAXH@Z", "?foo@@YAXH@Z"),
                source(0x1030, "main", "main"),
                // A collision-suffixed PE engine name keeps its exact source symbol.
                source(0x1040, "?bar@@YAXXZ", "?bar@@YAXXZ_1040"),
                source(0x1050, "_ZN4demo3fooEi", "demo::foo@plt"),
                source(0x1050, "_ZN4demo3barEv", "demo::bar"),
                source(0x1060, "_Z\u{1}bad", "x"),
            ],
            SymbolFormat::Other,
        );
        let names = fetch_all(&table);
        let raw: Vec<_> = (0..7)
            .filter_map(|i| names.get(0x1000 + i * 0x10))
            .map(|record| (record.raw.as_str(), record.display.as_deref()))
            .collect();
        assert_eq!(
            raw,
            [
                ("_ZN4demo3fooEi", Some("demo::foo")),
                ("_ZN4demo3fooEd", Some("demo::foo")),
                ("?bar@@YAXXZ", None),
                ("_ZN4demo3fooEi", Some("demo::foo@plt")),
            ]
        );
        assert!(names.get(0x1020).is_none(), "MSVC names stay raw");
        assert!(!names.truncated());
        // Overloads share a display name; exact raw lookup still separates them.
        assert_eq!(names.find("_ZN4demo3fooEd"), Some(0x1010));
        assert_eq!(names.find("demo::foo"), Some(0x1000));
        assert_eq!(names.find("demo"), None);
    }

    #[test]
    fn pseudocode_names_replace_only_the_engine_open_time_text() {
        let table = SymbolTable::build(
            [source(0x1000, "__RNvC4demo3foo", "__RNvC4demo3foo")],
            SymbolFormat::MachO,
        );
        assert_eq!(
            table.display_for(0x1000, "__RNvC4demo3foo"),
            Some("demo::foo")
        );
        assert_eq!(table.display_for(0x1000, "analyst_label"), None);
        assert_eq!(table.display_for(0x1001, "__RNvC4demo3foo"), None);
    }

    #[test]
    fn pages_are_bounded_and_reassemble_the_announced_table() {
        let raws: Vec<String> = (0..3000)
            .map(|i| format!("_ZN4demo{}name{i}Ev", 4 + i.to_string().len()))
            .collect();
        let long = format!("_ZN4demo{}{}Ev", 2000, "x".repeat(2000));
        let mut sources: Vec<_> = raws
            .iter()
            .enumerate()
            .map(|(i, raw)| source(0x1000 + i as u64, raw, "engine"))
            .collect();
        sources.push(source(0x10_0000, &long, "engine"));
        let table = SymbolTable::build(sources, SymbolFormat::Other);
        assert_eq!(table.summary().records, 3001);
        let mut cursor = Some(0);
        let mut pages = 0;
        while let Some(at) = cursor {
            let page = table.page(at).unwrap();
            let bytes: usize = page.entries.iter().map(symbol_record_bytes).sum();
            assert!(page.entries.len() <= MAX_SYMBOL_NAME_PAGE_RECORDS);
            assert!(page.entries.len() == 1 || bytes <= MAX_SYMBOL_NAME_PAGE_BYTES);
            let encoded = serde_json::to_vec(&crate::model::WorkerResponse {
                id: u64::MAX,
                response: crate::model::Response::SymbolNames { page: page.clone() },
            })
            .unwrap();
            crate::bounded::check_reply(&encoded).unwrap();
            cursor = page.next;
            pages += 1;
        }
        assert!(pages >= 3, "{pages} pages");
        assert!(table.page(3001).is_err());
        let names = fetch_all(&table);
        assert_eq!(names.len(), 3001);
        assert_eq!(names.digest(), table.summary().digest);
        assert_eq!(
            names.get(0x1000 + 2999).unwrap().display.as_deref(),
            Some("demo::name2999")
        );
        assert!(names.retained_bytes() > 3001 * size_of::<SymbolName>());
    }

    #[test]
    fn tables_stop_at_their_record_and_byte_budgets() {
        let raws: Vec<String> = (0..=MAX_SYMBOL_NAME_RECORDS)
            .map(|i| format!("r{i}"))
            .collect();
        let table = SymbolTable::build(
            raws.iter()
                .enumerate()
                .map(|(i, raw)| source(i as u64, raw, "engine")),
            SymbolFormat::Other,
        );
        assert_eq!(table.summary().records, MAX_SYMBOL_NAME_RECORDS);
        assert!(table.summary().truncated);
        let raw = "x".repeat(MAX_SYMBOL_RAW_BYTES);
        let table = SymbolTable::build(
            (0..4096).map(|i| source(i, &raw, "engine")),
            SymbolFormat::Other,
        );
        let bytes: usize = (0..table.summary().records)
            .map(|_| {
                symbol_record_bytes(&SymbolName {
                    address: 0,
                    raw: raw.clone(),
                    display: None,
                })
            })
            .sum();
        assert!(table.summary().truncated && bytes <= MAX_SYMBOL_NAME_TABLE_BYTES);
        let oversized = "x".repeat(MAX_SYMBOL_RAW_BYTES + 1);
        assert_eq!(
            SymbolTable::build([source(1, &oversized, "engine")], SymbolFormat::Other)
                .summary()
                .records,
            0
        );
    }

    #[test]
    fn fetch_rejects_pages_that_do_not_continue_the_announced_table() {
        let table = SymbolTable::build(
            [
                source(0x1000, "_ZN4demo3fooEi", "demo::foo"),
                source(0x1010, "_ZN4demo3barEv", "demo::bar"),
            ],
            SymbolFormat::Other,
        );
        let page = table.page(0).unwrap();
        let fetch = || SymbolNameFetch::new(table.summary().clone()).unwrap();
        let rejected = |edit: &dyn Fn(&mut SymbolNamePage)| {
            let mut page = page.clone();
            edit(&mut page);
            let mut fetch = fetch();
            assert!(fetch.accept(page).is_err());
            assert_eq!(fetch.cursor(), Some(0), "nothing appended");
        };
        rejected(&|page| page.digest = "0".repeat(64));
        rejected(&|page| page.cursor = 1);
        rejected(&|page| page.next = Some(2));
        rejected(&|page| page.entries.reverse());
        rejected(&|page| page.entries.clear());
        rejected(&|page| page.entries[1].display = Some("demo::baz".into()));
        rejected(&|page| page.entries[0].display = Some(page.entries[0].raw.clone()));
        rejected(&|page| page.entries[0].raw.push('\n'));
        rejected(&|page| page.entries[0].display = Some("x".repeat(MAX_SYMBOL_DISPLAY_BYTES + 1)));
        let mut complete = fetch();
        complete.accept(page.clone()).unwrap();
        assert_eq!(complete.cursor(), None);
        assert!(complete.accept(page).is_err(), "no page after the last");
        let mut summary = table.summary().clone();
        summary.records = MAX_SYMBOL_NAME_RECORDS + 1;
        assert!(SymbolNameFetch::new(summary).is_err());
        let empty = SymbolTable::default();
        assert!(fetch_all(&empty).is_empty());
    }
}
