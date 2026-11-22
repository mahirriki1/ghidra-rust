//! Same-image DWARF prototypes. All parsing is worker-side and fails toward inference.
mod abbreviations;
pub(crate) mod abi;
pub(crate) mod caller;
pub mod companion;
pub(crate) mod companion_path;
mod encodings;
mod locations;
mod units;
use ghidra_decompiler::{
    program::Program,
    types::{TypeFactory, TypeId, TypeMetatype},
};
use gimli as g;
use object::{Object, ObjectSection, ObjectSymbol};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const DEBUG_FINGERPRINT: &str = "debug-dwarf-v8:268c3a406d8d964bc00ae2ead4d3e1e1373aaa27";
// LLVM/Clang DWARF extension used by the original COFF regression fixture.
const DW_CC_LLVM_X86_STDCALL: g::DwCc = g::DwCc(0xb1);
const MAX_UNITS: usize = 65_536;
const MAX_DIES: usize = 8_000_000;
/// Flat-array safety bound for one subprogram's children. Scanning stops at
/// the first body entry, so this is reached only by malformed input.
const MAX_SUBTREE: usize = 262_144;
const MAX_TYPE_NODES: usize = 256;
const MAX_TYPE_DEPTH: usize = 16;
/// Parameter, typedef and structure names. Function names use the shared
/// symbol-name limit so long mangled linkage names still match.
const MAX_TYPE_NAME_BYTES: usize = 64;
/// Validated DIE records retained for lazy extraction (8 bytes each).
const MAX_METADATA_BYTES: usize = 8 * MAX_DIES + 16 * 1024 * 1024;
/// Most per-binary skip entries a client may send or a project may save.
pub const MAX_SKIPPED_FUNCTIONS: usize = 1024;

type R<'a> = g::EndianSlice<'a, g::LittleEndian>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugOptions {
    pub enabled: bool,
    #[serde(default)]
    pub companion_path: Option<String>,
    /// Functions whose renders use no debug prototypes, neither their own nor
    /// their callees', after a worker failure was attributed to them.
    #[serde(default, deserialize_with = "deserialize_skipped")]
    pub skip: Vec<u64>,
}
impl Default for DebugOptions {
    fn default() -> Self {
        Self {
            enabled: true,
            companion_path: None,
            skip: Vec::new(),
        }
    }
}
fn deserialize_skipped<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u64>, D::Error> {
    crate::bounded::vec::<_, u64, MAX_SKIPPED_FUNCTIONS>(deserializer)
}
/// Kept in BinaryInfo warnings so project schema 6 preserves the reason while
/// retaining the safer effective setting: disabled until explicitly enabled.
pub const OPEN_FALLBACK_WARNING: &str = "Open failed with debug info enabled; debug info was disabled and remains disabled in saved projects until explicitly enabled.";
/// Shown with a function whose render skipped debug prototypes.
pub const SKIPPED_FUNCTION_WARNING: &str =
    "Debug prototypes skipped for this function after a worker failure";
pub const ENGINE_FAILURE_WARNING: &str =
    "Debug prototypes skipped for this function after a decompiler error";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugUseStatus {
    Enabled,
    Disabled,
    DisabledAfterOpenFailure,
}
impl DebugUseStatus {
    pub fn of(enabled: bool, info: &crate::model::BinaryInfo) -> Self {
        if enabled {
            Self::Enabled
        } else if has_open_fallback(info) {
            Self::DisabledAfterOpenFailure
        } else {
            Self::Disabled
        }
    }
}
pub(crate) fn has_open_fallback(info: &crate::model::BinaryInfo) -> bool {
    info.warnings.iter().any(|w| w == OPEN_FALLBACK_WARNING)
}
pub(crate) fn has_fallback(info: &crate::model::BinaryInfo) -> bool {
    has_open_fallback(info)
}
pub(crate) fn is_fallback_warning(warning: &str) -> bool {
    warning == OPEN_FALLBACK_WARNING
}
pub(crate) fn inherit_fallback(
    info: &mut crate::model::BinaryInfo,
    old: &crate::model::BinaryInfo,
) {
    if !has_fallback(info) && has_open_fallback(old) {
        record_open_fallback(info);
    }
}
pub(crate) fn record_open_fallback(info: &mut crate::model::BinaryInfo) {
    if has_open_fallback(info) {
        return;
    }
    if info.warnings.len() >= crate::model::MAX_WARNINGS {
        info.warnings.truncate(crate::model::MAX_WARNINGS - 1);
    }
    info.warnings.push(OPEN_FALLBACK_WARNING.into());
}
/// Adds `entry` to a client-side skip list. Returns false (unchanged) when it
/// is already listed or the list is full.
pub fn add_skipped(skip: &mut Vec<u64>, entry: u64) -> bool {
    if skip.contains(&entry) || skip.len() >= MAX_SKIPPED_FUNCTIONS {
        return false;
    }
    skip.push(entry);
    skip.sort_unstable();
    true
}

type Key = (usize, usize);
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugFormat {
    Dwarf,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugStatus {
    Applied,
    Partial,
    Unsupported,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugSummary {
    #[serde(deserialize_with = "crate::bounded::string::<_, 96>")]
    pub state: String,
    pub functions: usize,
    pub format: DebugFormat,
    pub status: DebugStatus,
    #[serde(default)]
    pub source: Option<companion::DebugSource>,
}
pub(crate) const MAX_PROBE_ATTEMPTS: u8 = 2;

/// Where an entry's debug prototype stands in this worker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    #[default]
    Undecided,
    /// Accepted from a caller's unlocked callee probe only. Callers use it;
    /// its own render must still pass the locked-output check.
    Provisional,
    Verified,
    Rejected,
}

/// One entry's decision state. Absence of a prototype comes from the
/// immutable exact-entry index, never from this value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EntryState {
    pub status: Status,
    /// Direct verifications (an undecided target's probe and locked render,
    /// or a provisional entry's own locked render) that could not finish.
    pub target_attempts: u8,
    /// Caller-side callee probes that could not finish.
    pub callee_attempts: u8,
}

impl EntryState {
    pub(crate) fn decision(self) -> Decision {
        match self.status {
            Status::Undecided => Decision::Undecided,
            Status::Provisional | Status::Verified => Decision::Accepted,
            Status::Rejected => Decision::Rejected,
        }
    }

    pub(crate) fn deferred_target(mut self) -> Self {
        match self.status {
            Status::Undecided => {
                self.target_attempts = self
                    .target_attempts
                    .saturating_add(1)
                    .min(MAX_PROBE_ATTEMPTS);
            }
            Status::Provisional if self.target_attempts + 1 >= MAX_PROBE_ATTEMPTS => {
                self = Self {
                    status: Status::Rejected,
                    ..Self::default()
                };
            }
            Status::Provisional => self.target_attempts += 1,
            _ => {}
        }
        self
    }

    /// Whether `self -> next` is a transition a debug render may report.
    pub(crate) fn allows(&self, next: &EntryState) -> bool {
        next.target_attempts <= MAX_PROBE_ATTEMPTS
            && next.callee_attempts <= MAX_PROBE_ATTEMPTS
            && match next.status {
                Status::Verified | Status::Rejected => {
                    next.target_attempts == 0 && next.callee_attempts == 0
                }
                Status::Provisional => {
                    next.target_attempts < MAX_PROBE_ATTEMPTS && next.callee_attempts == 0
                }
                Status::Undecided => true,
            }
            && match (self.status, next.status) {
                (Status::Undecided, Status::Undecided)
                | (Status::Provisional, Status::Provisional) => {
                    next.target_attempts >= self.target_attempts
                        && next.callee_attempts >= self.callee_attempts
                }
                (Status::Rejected, Status::Rejected) => next == self,
                (Status::Rejected, _) => false,
                (Status::Verified, Status::Verified | Status::Rejected) => true,
                (Status::Verified, _) => false,
                (Status::Provisional, Status::Undecided) => false,
                _ => true,
            }
    }
}

/// One entry's state before and after a debug render, as that render
/// reports it back to the worker that started it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Change {
    pub entry: u64,
    pub old: EntryState,
    pub new: EntryState,
}

/// The current debug state of one entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    /// No usable DWARF prototype for this exact entry.
    Absent,
    Undecided,
    Accepted,
    Rejected,
}
#[derive(Default)]
pub struct DebugIndex {
    units: Vec<usize>,
    entries: BTreeMap<u64, Option<Key>>,
    pub summary: Option<DebugSummary>,
    /// Decision states that differ from the default (undecided, no
    /// attempts). An embedded index keeps its own entries' states.
    states: BTreeMap<u64, EntryState>,
    /// While a debug render runs: each touched entry's first old state and
    /// its latest state (top-level index only).
    journal: Option<BTreeMap<u64, (EntryState, EntryState)>>,
    /// Entries whose debug prototype is currently installed in the engine,
    /// with the prototype each had before its first install.
    installed: BTreeMap<u64, crate::signatures::SavedPrototype>,
    abbreviations: abbreviations::Tables,
    validated: BTreeMap<usize, Arc<encodings::Validated>>,
    symbols: BTreeMap<u64, BTreeSet<String>>,
    code_sections: Vec<crate::model::SectionInfo>,
    section_ranges: Vec<(g::SectionId, std::ops::Range<usize>)>,
    /// The immutable bytes the validation certificates were made for. Holding
    /// them here keeps every certified allocation alive and unchanged.
    image: Option<Arc<[u8]>>,
    companion: Option<Arc<[u8]>>,
    embedded: Option<Box<DebugIndex>>,
    companion_file: Option<Arc<std::fs::File>>,
}
fn dwarf<'a>(
    bytes: &'a [u8],
    ranges: &mut Vec<(g::SectionId, std::ops::Range<usize>)>,
) -> Option<g::Dwarf<R<'a>>> {
    let object = object::File::parse(bytes).ok()?;
    g::Dwarf::load(|id| {
        let data = object
            .section_by_name(id.name())
            .or_else(|| object.section_by_name(&id.name().replacen(".", "__", 1)))
            .and_then(|section| {
                let (offset, length) = section.file_range()?;
                let range = usize::try_from(offset).ok()?
                    ..usize::try_from(offset.checked_add(length)?).ok()?;
                let data = bytes.get(range.clone())?;
                ranges.push((id, range));
                Some(data)
            })
            .unwrap_or(&[]);
        Ok::<_, g::Error>(R::new(data, g::LittleEndian))
    })
    .ok()
}
fn symbol_index(
    object: &object::File<'_>,
    info: &crate::model::BinaryInfo,
) -> BTreeMap<u64, BTreeSet<String>> {
    let mut symbols: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    let strip_prefix = object.format() == object::BinaryFormat::MachO
        || (object.format() == object::BinaryFormat::Pe
            && object.architecture() == object::Architecture::I386);
    let mut symbol_bytes = 0usize;
    for symbol in object
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.is_definition())
    {
        let entry = symbol.address();
        if info
            .functions
            .binary_search_by_key(&entry, |f| f.address)
            .is_err()
        {
            continue;
        }
        if let Ok(raw) = symbol.name()
            && raw.len() <= crate::model::MAX_FUNCTION_NAME_BYTES
        {
            let names = symbols.entry(entry).or_default();
            if names.len() < 16
                && symbol_bytes + raw.len() * 2 + 256 <= crate::model::MAX_SYMBOL_NAME_TABLE_BYTES
            {
                symbol_bytes += raw.len() * 2 + 256;
                names.insert(raw.to_owned());
                if strip_prefix {
                    names.insert(raw.strip_prefix('_').unwrap_or(raw).to_owned());
                }
            }
        }
    }
    symbols
}
/// Hand-written assembly carries subprograms without types or parameters,
/// which would read as a confident `void f(void)`.
fn assembler_unit(unit: &units::CheckedUnit<'_>) -> bool {
    matches!(
        unit.root().attr_value(g::DW_AT_language),
        Some(g::AttributeValue::Language(g::DW_LANG_Mips_Assembler))
    )
}
impl DebugIndex {
    pub fn build(bytes: &Arc<[u8]>, info: &crate::model::BinaryInfo) -> Self {
        let timing = crate::performance::span("open_debug_index");
        let mut index = Self {
            code_sections: info.sections.clone(),
            ..Self::default()
        };
        let Some(object) = object::File::parse(&**bytes).ok() else {
            return index;
        };
        if crate::architecture::Target::for_image(&object).is_err() {
            return index;
        }
        if object
            .section_by_name(".debug_info")
            .or_else(|| object.section_by_name("__debug_info"))
            .is_none()
            && !object
                .sections()
                .any(|s| s.name().is_ok_and(|n| n.starts_with(".zdebug_")))
        {
            return index;
        }
        index.summary = Some(DebugSummary {
            state: DEBUG_FINGERPRINT.into(),
            functions: 0,
            format: DebugFormat::Dwarf,
            status: DebugStatus::Applied,
            source: None,
        });
        let compressed = object.sections().any(|s| {
            s.name().is_ok_and(|n| n.starts_with(".zdebug_"))
                || s.compressed_file_range()
                    .is_ok_and(|r| r.format != object::CompressionFormat::None)
        });
        let mut partial = compressed;
        index.symbols = symbol_index(&object, info);
        if !compressed && let Some(mut dwarf) = dwarf(bytes, &mut index.section_ranges) {
            let mut headers = dwarf.units();
            let mut budget = encodings::Budget::index();
            let mut metadata_bytes = 0usize;
            'units: loop {
                let header = match headers.next() {
                    Ok(Some(h)) => h,
                    Ok(None) => break,
                    Err(_) => {
                        partial = true;
                        break;
                    }
                };
                if index.units.len() == MAX_UNITS {
                    partial = true;
                    break;
                }
                let Some(offset) = header.offset().to_debug_info_offset(&header) else {
                    continue;
                };
                match index
                    .abbreviations
                    .prepare(&mut dwarf, header.debug_abbrev_offset().0)
                {
                    Ok(()) => {}
                    // One malformed table loses only the units that use it.
                    // Those units are never listed, so no lazy reference can
                    // reach an unprepared table.
                    Err(abbreviations::TableError::Malformed) => {
                        partial = true;
                        continue;
                    }
                    Err(abbreviations::TableError::Exhausted) => {
                        partial = true;
                        break;
                    }
                }
                index.units.push(offset.0);
                let unit = match units::prototype_unit(&dwarf, header, &mut budget) {
                    Ok(u) => u,
                    Err(_) => {
                        partial = true;
                        if budget.exhausted() {
                            break;
                        }
                        continue;
                    }
                };
                metadata_bytes += unit.dies.allocated_bytes();
                if metadata_bytes > MAX_METADATA_BYTES {
                    partial = true;
                    break;
                }
                index.validated.insert(offset.0, Arc::clone(&unit.dies));
                if assembler_unit(&unit) {
                    continue;
                }
                for meta in unit.dies.iter() {
                    if meta.tag != g::DW_TAG_subprogram {
                        continue;
                    }
                    let Some(die) = unit.decoded(meta.offset as usize) else {
                        partial = true;
                        break;
                    };
                    // A typeless concrete LTO unit may refer to a separate,
                    // typed source unit. Verify that source during extraction.
                    if !unit.dies.has_types
                        && die.attr_value(g::DW_AT_abstract_origin).is_none()
                        && die.attr_value(g::DW_AT_specification).is_none()
                        && die.attr_value(g::DW_AT_type).is_none()
                    {
                        continue;
                    }
                    let Some(value) = die.attr_value(g::DW_AT_low_pc) else {
                        continue;
                    };
                    let Ok(Some(entry)) = dwarf.attr_address(&unit, value) else {
                        continue;
                    };
                    if entry == 0
                        || unit.is_tombstone_address(entry)
                        || info
                            .functions
                            .binary_search_by_key(&entry, |f| f.address)
                            .is_err()
                        || !crate::call_analysis::code_address(info, entry)
                    {
                        continue;
                    }
                    // Name and origin resolution is lazy; retain the exact symbol names only
                    // via the immutable image and check again during extraction.
                    if index.entries.len() == crate::model::MAX_FUNCTIONS {
                        partial = true;
                        break 'units;
                    }
                    index
                        .entries
                        .entry(entry)
                        .and_modify(|v| *v = None)
                        .or_insert(Some((offset.0, die.offset().0)));
                }
            }
        } else {
            partial = true;
        }
        index.image = Some(Arc::clone(bytes));
        let summary = index.summary.as_mut().unwrap();
        summary.functions = index.entries.values().filter(|v| v.is_some()).count();
        summary.status = if compressed {
            DebugStatus::Unsupported
        } else if partial {
            DebugStatus::Partial
        } else {
            DebugStatus::Applied
        };
        if partial {
            summary.state.push_str(":partial")
        }
        timing.finish(summary.functions as u64);
        index
    }
    pub fn with_companion(
        binary: &Arc<[u8]>,
        info: &crate::model::BinaryInfo,
        path: &std::path::Path,
    ) -> Self {
        let Some((snapshot, source, file)) = companion::read(binary, path) else {
            return Self::build(binary, info);
        };
        let mut index = Self::build(&snapshot, info);
        let embedded = Self::build(binary, info);
        // A dSYM may carry its own symbol table. Match only the original
        // image's symbols, never a name supplied by the companion itself.
        index.symbols = if embedded.symbols.is_empty() {
            object::File::parse(&**binary)
                .ok()
                .map(|object| symbol_index(&object, info))
                .unwrap_or_default()
        } else {
            embedded.symbols.clone()
        };
        if index.summary.is_none() {
            return embedded;
        }
        index
            .entries
            .retain(|entry, _| !embedded.entries.contains_key(entry));
        while index.entries.len() + embedded.entries.len() > crate::model::MAX_FUNCTIONS {
            index.entries.pop_last();
        }
        if let Some(summary) = &mut index.summary {
            summary.functions = index.entries.len() + embedded.entries.len();
            if embedded
                .summary
                .as_ref()
                .is_some_and(|s| s.status != DebugStatus::Applied)
            {
                summary.status = DebugStatus::Partial;
            }
        }
        index.embedded = Some(Box::new(embedded));
        if let Some(summary) = &mut index.summary {
            use sha2::{Digest, Sha256};
            summary.state = format!(
                "debug-dwarf-v8:{:x}",
                Sha256::digest(format!("{}:{}", DEBUG_FINGERPRINT, source.sha256))
            );
            summary.source = Some(source);
        }
        index.companion = Some(snapshot);
        index.companion_file = Some(file);
        index
    }
    /// True when any DWARF prototype may be installed for this binary.
    pub fn active(&self) -> bool {
        self.summary.as_ref().is_some_and(|s| !s.state.is_empty())
    }
    fn owner(&self, entry: u64) -> &Self {
        match &self.embedded {
            Some(embedded) if embedded.entries.contains_key(&entry) => embedded,
            _ => self,
        }
    }
    fn owner_mut(&mut self, entry: u64) -> &mut Self {
        if self
            .embedded
            .as_ref()
            .is_some_and(|e| e.entries.contains_key(&entry))
        {
            return self.embedded.as_mut().unwrap();
        }
        self
    }
    /// Whether this exact entry has a DWARF prototype candidate.
    pub(crate) fn indexed(&self, entry: u64) -> bool {
        self.owner(entry)
            .entries
            .get(&entry)
            .is_some_and(|key| key.is_some())
    }
    pub(crate) fn state(&self, entry: u64) -> EntryState {
        self.owner(entry)
            .states
            .get(&entry)
            .copied()
            .unwrap_or_default()
    }
    /// The one place entry states change. Records the change in an active
    /// journal: the first old value and the latest new value per entry.
    fn set_state(&mut self, entry: u64, new: EntryState) {
        let old = self.state(entry);
        if old == new {
            return;
        }
        if let Some(journal) = self.journal.as_mut() {
            journal.entry(entry).or_insert((old, new)).1 = new;
        }
        let owner = self.owner_mut(entry);
        if new == EntryState::default() {
            owner.states.remove(&entry);
        } else {
            owner.states.insert(entry, new);
        }
    }
    fn update(&mut self, entry: u64, change: impl FnOnce(&mut EntryState)) {
        let mut state = self.state(entry);
        change(&mut state);
        self.set_state(entry, state);
    }
    /// A final decision; attempt counts no longer apply.
    fn decide(&mut self, entry: u64, status: Status) {
        self.set_state(
            entry,
            EntryState {
                status,
                ..Default::default()
            },
        );
    }

    /// Starts recording state changes for one debug render.
    pub(crate) fn begin_journal(&mut self) {
        self.journal = Some(BTreeMap::new());
    }
    /// The net changes since [`Self::begin_journal`], sorted by entry, with
    /// writes that restored an entry's old state removed.
    pub(crate) fn take_journal(&mut self) -> Vec<Change> {
        self.journal
            .take()
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, (old, new))| old != new)
            .map(|(entry, (old, new))| Change { entry, old, new })
            .collect()
    }
    /// Checks a debug render's reported changes against this index without
    /// applying any: each entry must be one of `allowed`, sorted and unique,
    /// have a prototype, start from its current state and make an allowed
    /// transition.
    pub(crate) fn check_changes(&self, changes: &[Change], allowed: &[u64]) -> bool {
        changes.windows(2).all(|pair| pair[0].entry < pair[1].entry)
            && changes.iter().all(|change| {
                allowed.contains(&change.entry)
                    && self.indexed(change.entry)
                    && self.state(change.entry) == change.old
                    && change.old != change.new
                    && change.old.allows(&change.new)
            })
    }
    /// Applies changes accepted by [`Self::check_changes`].
    pub(crate) fn apply_changes(&mut self, changes: &[Change]) {
        for change in changes {
            self.set_state(change.entry, change.new);
        }
    }
    /// Clears raw decisions in the disposable managed executor.
    pub(crate) fn reset_decisions(&mut self) {
        self.states.clear();
        if let Some(embedded) = self.embedded.as_mut() {
            embedded.reset_decisions();
        }
    }

    /// Seeds a fresh worker's decision for one indexed entry from the host's
    /// committed book, before any journal opens. Refuses entries without a
    /// prototype, an already decided entry and an impossible state.
    pub(crate) fn seed(&mut self, entry: u64, state: EntryState) -> bool {
        if self.journal.is_some()
            || !self.indexed(entry)
            || self.state(entry) != EntryState::default()
            || !EntryState::default().allows(&state)
        {
            return false;
        }
        self.set_state(entry, state);
        true
    }

    pub(crate) fn decision(&self, entry: u64) -> Decision {
        if !self.indexed(entry) {
            return Decision::Absent;
        }
        self.state(entry).decision()
    }
    pub fn undecided(&self, entry: u64) -> bool {
        self.decision(entry) == Decision::Undecided
    }
    pub(crate) fn is_installed(&self, entry: u64) -> bool {
        self.owner(entry).installed.contains_key(&entry)
    }
    pub(crate) fn installed_entries(&self) -> Vec<u64> {
        let mut entries = self.installed.keys().copied().collect::<Vec<_>>();
        if let Some(embedded) = &self.embedded {
            entries.extend(embedded.installed_entries());
        }
        entries
    }
    /// Parses `entry`'s prototype; one that cannot be extracted is rejected.
    fn candidate(&mut self, entry: u64) -> Option<Prototype> {
        let owner = self.owner_mut(entry);
        let key = owner.entries.get(&entry).copied().flatten()?;
        let debug_bytes = owner.companion.as_ref().or(owner.image.as_ref())?;
        let prototype = {
            let mut dwarf = g::Dwarf::load(|id| {
                Ok::<_, g::Error>(R::new(
                    owner
                        .section_ranges
                        .iter()
                        .find(|(section, _)| *section == id)
                        .and_then(|(_, range)| debug_bytes.get(range.clone()))
                        .unwrap_or(&[]),
                    g::LittleEndian,
                ))
            })
            .ok();
            dwarf.as_mut().and_then(|dwarf| {
                owner.abbreviations.attach(dwarf);
                let resolver =
                    Resolver::with_validation(dwarf, &owner.units, Some(&owner.validated));
                resolver.prototype(key, owner.symbols.get(&entry)?)
            })
        };
        if prototype.is_none() {
            self.decide(entry, Status::Rejected);
        }
        prototype
    }

    pub(crate) fn install_accepted(&mut self, program: &mut Program, entry: u64) -> bool {
        self.decision(entry) == Decision::Accepted
            && self.candidate(entry).is_some_and(|prototype| {
                self.install_candidate(program, entry, prototype, None, true)
            })
    }

    /// Whether a render of `entry` itself may still try its undecided
    /// prototype.
    pub(crate) fn target_attempts_left(&self, entry: u64) -> bool {
        self.decision(entry) == Decision::Undecided
            && self.state(entry).target_attempts < MAX_PROBE_ATTEMPTS
    }

    /// Whether a caller may still probe `entry` as an undecided callee.
    pub(crate) fn callee_attempts_left(&self, entry: u64) -> bool {
        self.decision(entry) == Decision::Undecided
            && self.state(entry).callee_attempts < MAX_PROBE_ATTEMPTS
    }

    /// Whether `entry` is accepted only from a caller's unlocked probe.
    pub(crate) fn provisional(&self, entry: u64) -> bool {
        self.indexed(entry) && self.state(entry).status == Status::Provisional
    }

    /// Probe the rendered function while its own ABI is still unlocked.
    /// An incomplete probe is charged as one unavailable attempt. The caller
    /// installs the result with [`Self::install_probed`] and verifies that
    /// install using its locked render.
    pub(crate) fn probe_pending(&mut self, program: &mut Program, entry: u64) -> Option<Probed> {
        if !self.target_attempts_left(entry) {
            return None;
        }
        let prototype = self.candidate(entry)?;
        let sections = &self.owner(entry).code_sections;
        let evidence = crate::decompile::probe_abi(program, entry, sections).ok();
        if let Some(evidence) = evidence
            && evidence.complete
        {
            Some(Probed {
                prototype,
                evidence,
            })
        } else {
            self.defer_target(entry);
            None
        }
    }

    /// Installs a probed target prototype for a render that verifies it.
    pub(crate) fn install_probed(
        &mut self,
        program: &mut Program,
        entry: u64,
        probed: Probed,
    ) -> bool {
        self.install_candidate(
            program,
            entry,
            probed.prototype,
            Some(&probed.evidence),
            false,
        )
    }

    /// Charges one direct verification of `entry` that could not finish:
    /// an undecided target stays undecided for a later render; a
    /// provisional entry is rejected on its last attempt, so it cannot stay
    /// in use by callers without ever being confirmed by its own render.
    pub(crate) fn defer_target(&mut self, entry: u64) {
        if !self.indexed(entry) {
            return;
        }
        self.set_state(entry, self.state(entry).deferred_target());
    }

    /// A definitive engine failure of `entry`'s own locked render: a
    /// provisional prototype is withdrawn at once.
    pub(crate) fn fail_direct(&mut self, entry: u64) {
        if self.provisional(entry) {
            self.decide(entry, Status::Rejected);
        }
    }

    pub(crate) fn prepare_callee(&mut self, entry: u64) -> Option<Prototype> {
        if self.state(entry).callee_attempts >= MAX_PROBE_ATTEMPTS {
            return None;
        }
        self.candidate(entry)
    }

    pub(crate) fn finish_callee(
        &mut self,
        program: &mut Program,
        entry: u64,
        prototype: Prototype,
        evidence: Option<&abi::Evidence>,
    ) -> bool {
        let Some(evidence) = evidence else {
            self.update(entry, |state| {
                state.callee_attempts = state
                    .callee_attempts
                    .saturating_add(1)
                    .min(MAX_PROBE_ATTEMPTS)
            });
            return false;
        };
        let installed = self.install_candidate(program, entry, prototype, Some(evidence), false);
        if installed {
            // Unlocked evidence vouches for callers' use of the prototype,
            // not for the callee's own locked render; see `verify`.
            self.decide(entry, Status::Provisional);
        }
        installed
    }

    fn install_candidate(
        &mut self,
        program: &mut Program,
        entry: u64,
        prototype: Prototype,
        inputs: Option<&abi::Evidence>,
        accepted: bool,
    ) -> bool {
        let owner = self.owner_mut(entry);
        match apply(
            program,
            entry,
            prototype,
            &owner.code_sections,
            accepted,
            inputs,
        ) {
            Ok(saved) => {
                // A reinstall keeps the original pre-install prototype.
                owner.installed.entry(entry).or_insert(saved);
                true
            }
            Err(_) => {
                owner.uninstall(program, entry);
                self.decide(entry, Status::Rejected);
                false
            }
        }
    }

    /// Records the decision for a pending install, or for a provisional
    /// callee's own render, from the input registers its locked render
    /// read. On disagreement the prototype is removed and rejected, so the
    /// function and its later callers keep inference. Incomplete evidence is
    /// one unavailable direct verification.
    pub(crate) fn verify(
        &mut self,
        program: &mut Program,
        entry: u64,
        evidence: &abi::Evidence,
    ) -> bool {
        let status = self.state(entry).status;
        if matches!(status, Status::Verified | Status::Rejected) || !self.is_installed(entry) {
            return status == Status::Verified;
        }
        if !evidence.complete {
            self.defer_target(entry);
            self.owner_mut(entry).uninstall(program, entry);
            return false;
        }
        let accepted =
            crate::signatures::installed_inputs_agree(program.architecture(), entry, evidence)
                .is_ok();
        self.decide(
            entry,
            if accepted {
                Status::Verified
            } else {
                Status::Rejected
            },
        );
        if !accepted {
            self.owner_mut(entry).uninstall(program, entry);
        }
        accepted
    }
    /// Removes an installed debug prototype, restoring inference. `reject`
    /// also prevents any later install of this entry.
    pub(crate) fn rollback(&mut self, program: &mut Program, entry: u64, reject: bool) {
        if reject && self.indexed(entry) {
            self.decide(entry, Status::Rejected);
        }
        self.owner_mut(entry).uninstall(program, entry);
    }
    fn uninstall(&mut self, program: &mut Program, entry: u64) {
        if let Some(saved) = self.installed.remove(&entry) {
            // A failed restore leaves the function as the engine had it; the
            // next render reports any resulting error normally.
            let _ = crate::signatures::uninstall_debug(program.architecture(), entry, &saved);
        }
    }
}
struct Resolver<'a, 'b> {
    dwarf: &'a g::Dwarf<R<'b>>,
    units: &'a [usize],
    cache: std::cell::RefCell<BTreeMap<usize, std::rc::Rc<units::CheckedUnit<'b>>>>,
    decoded: std::cell::RefCell<BTreeMap<Key, std::rc::Rc<g::DebuggingInformationEntry<R<'b>>>>>,
    decoded_bytes: std::cell::Cell<usize>,
    budget: std::cell::RefCell<encodings::Budget>,
    validated: Option<&'a BTreeMap<usize, std::sync::Arc<encodings::Validated>>>,
}
impl<'a, 'b> Resolver<'a, 'b> {
    #[cfg(test)]
    fn new(dwarf: &'a g::Dwarf<R<'b>>, units: &'a [usize]) -> Self {
        Self::with_validation(dwarf, units, None)
    }
    fn with_validation(
        dwarf: &'a g::Dwarf<R<'b>>,
        units: &'a [usize],
        validated: Option<&'a BTreeMap<usize, std::sync::Arc<encodings::Validated>>>,
    ) -> Self {
        Self {
            dwarf,
            units,
            cache: Default::default(),
            decoded: Default::default(),
            decoded_bytes: Default::default(),
            budget: std::cell::RefCell::new(encodings::Budget::lazy()),
            validated,
        }
    }
    fn unit(&self, key: Key) -> Option<std::rc::Rc<units::CheckedUnit<'b>>> {
        if let Some(unit) = self.cache.borrow().get(&key.0) {
            return Some(std::rc::Rc::clone(unit));
        }
        // Per-extraction cache: repeated references never reparse a CU root.
        // The type-node/reference/parameter budgets bound ordinary demand;
        // this explicit limit also bounds malformed cross-CU origin chains.
        if self.cache.borrow().len() >= 512 {
            return None;
        }
        let header = self
            .dwarf
            .debug_info
            .header_from_offset(g::DebugInfoOffset(key.0))
            .ok()?;
        let unit = std::rc::Rc::new(
            units::prototype_unit_cached(
                self.dwarf,
                header,
                &mut self.budget.borrow_mut(),
                self.validated.and_then(|cache| cache.get(&key.0)).cloned(),
            )
            .ok()?,
        );
        self.cache
            .borrow_mut()
            .insert(key.0, std::rc::Rc::clone(&unit));
        Some(unit)
    }
    fn die(&self, key: Key) -> Option<std::rc::Rc<g::DebuggingInformationEntry<R<'b>>>> {
        if let Some(die) = self.decoded.borrow().get(&key) {
            return Some(std::rc::Rc::clone(die));
        }
        if self.decoded.borrow().len() >= 4096 {
            return None;
        }
        let unit = self.unit(key)?;
        unit.position(key.1)?;
        // Charge the maximum attribute vector before allocating/decoding it.
        let bytes = self.decoded_bytes.get().checked_add(
            256 + abbreviations::MAX_ATTRIBUTES * std::mem::size_of::<g::Attribute<R<'b>>>(),
        )?;
        if bytes > 8 * 1024 * 1024 {
            return None;
        }
        self.decoded_bytes.set(bytes);
        let die = unit.decoded(key.1)?;
        self.decoded
            .borrow_mut()
            .insert(key, std::rc::Rc::clone(&die));
        Some(die)
    }
    fn children(&self, key: Key) -> Option<Vec<Key>> {
        let unit = self.unit(key)?;
        let position = unit.position(key.1)?;
        let root = unit.dies[position].depth;
        let mut children = Vec::new();
        for (i, meta) in unit.dies[position + 1..].iter().enumerate() {
            if meta.depth <= root {
                break;
            }
            if i >= MAX_SUBTREE {
                return None;
            }
            if meta.depth != root + 1 {
                continue;
            }
            match meta.tag {
                g::DW_TAG_formal_parameter | g::DW_TAG_unspecified_parameters => {
                    children.push((key.0, meta.offset as usize));
                    if children.len() > crate::signatures::MAX_PARAMETERS {
                        return None;
                    }
                }
                // Producers list parameters before the body. Stop at the
                // first body entry instead of walking every local and scope.
                g::DW_TAG_variable
                | g::DW_TAG_lexical_block
                | g::DW_TAG_inlined_subroutine
                | g::DW_TAG_label
                | g::DW_TAG_call_site
                | g::DW_TAG_GNU_call_site => break,
                _ => {}
            }
        }
        Some(children)
    }
    fn reference(&self, key: Key, value: g::AttributeValue<R<'b>>) -> Option<Key> {
        match value {
            g::AttributeValue::UnitRef(o) => Some((key.0, o.0)),
            g::AttributeValue::DebugInfoRef(o) => {
                let i = self.units.partition_point(|&u| u <= o.0).checked_sub(1)?;
                let u = self.units[i];
                let unit = self.unit((u, 0))?;
                Some((u, o.to_unit_offset(&unit.header)?.0))
            }
            _ => None,
        }
    }
    fn attr(
        &self,
        mut key: Key,
        name: g::DwAt,
    ) -> Result<Option<(Key, g::AttributeValue<R<'b>>)>, ()> {
        let mut seen = BTreeSet::new();
        for _ in 0..=4 {
            if !seen.insert(key) {
                return Err(());
            }
            let die = self.die(key).ok_or(())?;
            if let Some(v) = die.attr_value(name) {
                return Ok(Some((key, v)));
            }
            let Some(v) = die
                .attr_value(g::DW_AT_abstract_origin)
                .or(die.attr_value(g::DW_AT_specification))
            else {
                return Ok(None);
            };
            key = self.reference(key, v).ok_or(())?;
        }
        Err(())
    }
    fn name(&self, key: Key, attr: g::DwAt, max: usize) -> Option<String> {
        let (key, value) = self.attr(key, attr).ok()??;
        let unit = self.unit(key)?;
        encodings::name(self.dwarf, &unit, value, max)
    }
    fn ty(
        &self,
        key: Key,
        seen: &mut BTreeSet<Key>,
        nodes: &mut usize,
        depth: usize,
    ) -> Option<Ty> {
        *nodes += 1;
        if depth > MAX_TYPE_DEPTH || *nodes > MAX_TYPE_NODES || !seen.insert(key) {
            return None;
        }
        let die = self.die(key)?;
        let mut target = || -> Option<Ty> {
            let Some((owner, value)) = self.attr(key, g::DW_AT_type).ok()? else {
                return Some(Ty::Void);
            };
            self.ty(
                self.reference(owner, value)?,
                &mut seen.clone(),
                nodes,
                depth + 1,
            )
        };
        let size = die
            .attr_value(g::DW_AT_byte_size)
            .and_then(|v| v.udata_value());
        Some(match die.tag() {
            g::DW_TAG_unspecified_type => Ty::Void,
            g::DW_TAG_const_type
            | g::DW_TAG_volatile_type
            | g::DW_TAG_restrict_type
            | g::DW_TAG_atomic_type => target()?,
            g::DW_TAG_pointer_type | g::DW_TAG_reference_type | g::DW_TAG_rvalue_reference_type => {
                Ty::Pointer(Box::new(target()?))
            }
            g::DW_TAG_typedef => Ty::Typedef(
                self.name(key, g::DW_AT_name, MAX_TYPE_NAME_BYTES)
                    .filter(|n| crate::semantic::validate_name(n).is_ok())?,
                Box::new(target()?),
            ),
            g::DW_TAG_structure_type | g::DW_TAG_union_type | g::DW_TAG_class_type => Ty::Opaque(
                self.name(key, g::DW_AT_name, MAX_TYPE_NAME_BYTES)
                    .filter(|n| crate::semantic::validate_name(n).is_ok()),
            ),
            g::DW_TAG_subroutine_type => Ty::Code,
            g::DW_TAG_enumeration_type => {
                let size = i32::try_from(size?).ok()?;
                if ![1, 2, 4, 8].contains(&size) {
                    return None;
                }
                Ty::Base(size, TypeMetatype::Int, false)
            }
            g::DW_TAG_base_type => {
                let g::AttributeValue::Encoding(encoding) = die.attr_value(g::DW_AT_encoding)?
                else {
                    return None;
                };
                let size = i32::try_from(size?).ok()?;
                if ![1, 2, 4, 8].contains(&size) {
                    return None;
                }
                let (meta, character) = match encoding {
                    g::DW_ATE_signed => (TypeMetatype::Int, false),
                    g::DW_ATE_unsigned => (TypeMetatype::Uint, false),
                    g::DW_ATE_signed_char | g::DW_ATE_unsigned_char | g::DW_ATE_UTF => {
                        (TypeMetatype::Int, true)
                    }
                    g::DW_ATE_boolean => (TypeMetatype::Bool, false),
                    g::DW_ATE_float if [4, 8].contains(&size) => (TypeMetatype::Float, false),
                    _ => return None,
                };
                Ty::Base(size, meta, character)
            }
            _ => return None,
        })
    }
    /// Follow the source declaration, checking any spelling the producer
    /// attached to an intermediate or concrete instance before inheriting types.
    fn prototype_source(&self, mut key: Key) -> Option<Key> {
        const MAX_NAME: usize = crate::model::MAX_FUNCTION_NAME_BYTES;
        for _ in 0..=4 {
            let die = self.die(key)?;
            if die.tag() != g::DW_TAG_subprogram {
                return None;
            }
            let origin = die.attr_value(g::DW_AT_abstract_origin);
            let Some(next) = origin.or(die.attr_value(g::DW_AT_specification)) else {
                let unit = self.unit(key)?;
                return (!assembler_unit(&unit)).then_some(key);
            };
            let next = self.reference(key, next)?;
            for attribute in [g::DW_AT_name, g::DW_AT_linkage_name] {
                if let Some(value) = die.attr_value(attribute) {
                    let own =
                        encodings::name(self.dwarf, self.unit(key)?.as_ref(), value, MAX_NAME)?;
                    let inherited = self.name(next, attribute, MAX_NAME);
                    if compiler_clone(&own)
                        || inherited.as_ref().is_some_and(|name| *name != own)
                        || (origin.is_some()
                            && attribute == g::DW_AT_linkage_name
                            && inherited.is_none()
                            && self.name(next, g::DW_AT_name, MAX_NAME).as_ref() != Some(&own))
                    {
                        return None;
                    }
                }
            }
            key = next;
        }
        None
    }
    fn prototype(&self, key: Key, names: &BTreeSet<String>) -> Option<Prototype> {
        let name = self
            .name(
                key,
                g::DW_AT_linkage_name,
                crate::model::MAX_FUNCTION_NAME_BYTES,
            )
            .or_else(|| self.name(key, g::DW_AT_name, crate::model::MAX_FUNCTION_NAME_BYTES))?;
        if !names.contains(&name) || compiler_clone(&name) {
            return None;
        }
        let source = self.prototype_source(key)?;
        if [g::DW_AT_name, g::DW_AT_linkage_name]
            .into_iter()
            .filter_map(|attribute| {
                self.name(source, attribute, crate::model::MAX_FUNCTION_NAME_BYTES)
            })
            .any(|name| compiler_clone(&name))
        {
            return None;
        }
        let (owner, value) = self.attr(key, g::DW_AT_low_pc).ok()??;
        let entry = self
            .dwarf
            .attr_address(self.unit(owner)?.as_ref(), value)
            .ok()??;
        let calling_convention = match self.attr(key, g::DW_AT_calling_convention).ok()? {
            None => g::DW_CC_normal,
            Some((_, g::AttributeValue::CallingConvention(cc))) => cc,
            _ => return None,
        };
        if !matches!(calling_convention, g::DW_CC_normal | DW_CC_LLVM_X86_STDCALL) {
            return None;
        }
        let mut nodes = 0;
        // Omitted return types mean void only after locating a typed
        // source unit. A formal parameter always needs an explicit type.
        let output = match self.attr(key, g::DW_AT_type).ok()? {
            Some((owner, value)) => self.ty(
                self.reference(owner, value)?,
                &mut BTreeSet::new(),
                &mut nodes,
                0,
            )?,
            None if self.unit(source)?.dies.has_types => Ty::Void,
            None => return None,
        };
        // Concrete children take priority; an abstract-only child list is followed
        // only when the concrete instance has no formal parameters.
        let mut parameter_key = key;
        let mut children = Vec::new();
        for _ in 0..=4 {
            children = self.children(parameter_key)?;
            if !children.is_empty() {
                break;
            }
            let die = self.die(parameter_key)?;
            let next = die
                .attr_value(g::DW_AT_abstract_origin)
                .or(die.attr_value(g::DW_AT_specification));
            let Some(next) = next else {
                break;
            };
            parameter_key = self.reference(parameter_key, next)?;
        }
        let mut inputs = Vec::new();
        let mut locations = locations::Locations::default();
        for child in children {
            let die = self.die(child)?;
            if die.tag() == g::DW_TAG_unspecified_parameters {
                return None;
            }
            if self.attr(child, g::DW_AT_const_value).ok()?.is_some() {
                return None;
            }
            let (owner, value) = self.attr(child, g::DW_AT_type).ok()??;
            let ty = self.ty(
                self.reference(owner, value)?,
                &mut BTreeSet::new(),
                &mut nodes,
                0,
            )?;
            let name = self
                .name(child, g::DW_AT_name, MAX_TYPE_NAME_BYTES)
                .filter(|n| crate::semantic::validate_name(n).is_ok())
                .unwrap_or_else(|| format!("param_{}", inputs.len() + 1));
            let mut register = None;
            if let Some((owner, value)) = self.attr(child, g::DW_AT_location).ok()? {
                let unit = self.unit(owner)?;
                let expression = if let g::AttributeValue::Exprloc(e) = value {
                    Some(e)
                } else {
                    locations
                        .at_entry(self.dwarf, &unit, owner.0, value, entry)
                        .ok()?
                };
                if let Some(expression) = expression {
                    let mut ops = expression.operations(unit.encoding());
                    if let Some(g::Operation::Register { register: r }) = ops.next().ok()?
                        && ops.next().ok()?.is_none()
                    {
                        register = Some(r.0)
                    }
                }
            }
            inputs.push((name, ty, register));
        }
        Some(Prototype {
            calling_convention,
            output,
            inputs,
        })
    }
}
fn compiler_clone(name: &str) -> bool {
    name.split('.').skip(1).any(|suffix| {
        matches!(
            suffix,
            "isra"
                | "constprop"
                | "part"
                | "cold"
                | "clone"
                | "lto_priv"
                | "llvm"
                | "localalias"
                | "split"
                | "simdclone"
                | "omp_fn"
        )
    })
}

enum Ty {
    Void,
    Base(i32, TypeMetatype, bool),
    Pointer(Box<Ty>),
    Typedef(String, Box<Ty>),
    Opaque(Option<String>),
    Code,
}
impl Ty {
    fn engine(
        &self,
        types: &mut TypeFactory,
        indirect: bool,
    ) -> ghidra_decompiler::error::Result<TypeId> {
        use ghidra_decompiler::error::Error;
        match self {
            Self::Void => types.get_type_void(),
            Self::Base(size, meta, character) => {
                if *character {
                    types.get_type_char(*size)
                } else {
                    types.get_base_no_char(*size, *meta)
                }
            }
            Self::Pointer(to) => {
                let to = to.engine(types, true)?;
                types.get_type_pointer(types.get_size_of_pointer(), to, 1)
            }
            Self::Typedef(name, to) => {
                let to = to.engine(types, indirect)?;
                Ok(types.get_typedef(to, name, 0, 0).unwrap_or(to))
            }
            // Fields are not modelled, so a named structure becomes a named
            // one-byte opaque pointee: never the engine's zero-size
            // incomplete structure, which its data-type splitter divides by.
            Self::Opaque(name) if indirect => match name {
                Some(n) if zero_size_opaque() => types.get_type_struct(n),
                Some(n) => opaque_pointee(types, n),
                None => types.get_type_void(),
            },
            Self::Code if indirect => types.get_type_code(),
            _ => Err(Error::Lowlevel("Unsupported DWARF type by value".into())),
        }
    }
}
#[cfg(test)]
std::thread_local! {
    /// Restores the engine's zero-size incomplete structure, to exercise
    /// recovery from the engine failure it causes.
    pub(crate) static ZERO_SIZE_OPAQUE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Test hook: restore the engine's zero-size incomplete structure, in this
/// thread (unit tests) or in every render of a worker started with
/// `GHIDRA_RUST_TEST_ZERO_SIZE_OPAQUE`, to exercise recovery from the engine
/// failure it causes inside the isolated debug render.
fn zero_size_opaque() -> bool {
    static ENVIRONMENT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    #[cfg(test)]
    if ZERO_SIZE_OPAQUE.get() {
        return true;
    }
    *ENVIRONMENT.get_or_init(|| std::env::var_os("GHIDRA_RUST_TEST_ZERO_SIZE_OPAQUE").is_some())
}
/// A named one-byte pointee with byte-granular arithmetic, like `void *`.
/// A name already bound to another engine type falls back to `void`.
fn opaque_pointee(types: &mut TypeFactory, name: &str) -> ghidra_decompiler::error::Result<TypeId> {
    if let Some(existing) = types.find_by_name(name) {
        let datatype = types.get(existing);
        return if datatype.get_size() == 1 && datatype.get_metatype() == TypeMetatype::Unknown {
            Ok(existing)
        } else {
            types.get_type_void()
        };
    }
    let named = types.get_base_named(1, TypeMetatype::Unknown, name)?;
    let datatype = types.get(named);
    if datatype.get_size() == 1
        && datatype.get_metatype() == TypeMetatype::Unknown
        && datatype.get_name() == name
    {
        Ok(named)
    } else {
        types.get_type_void()
    }
}
/// A target's debug prototype and the inputs of its unlocked probe.
pub(crate) struct Probed {
    prototype: Prototype,
    evidence: abi::Evidence,
}

pub(crate) struct Prototype {
    calling_convention: g::DwCc,
    output: Ty,
    inputs: Vec<(String, Ty, Option<u16>)>,
}
fn apply(
    program: &mut Program,
    entry: u64,
    prototype: Prototype,
    sections: &[crate::model::SectionInfo],
    accepted: bool,
    inputs: Option<&abi::Evidence>,
) -> Result<crate::signatures::SavedPrototype, String> {
    let abi = program.language_id().to_owned();
    // The return-stack adjustment comes from the CFG, never from a render.
    let extra_pop = if !accepted && abi.starts_with("x86:LE:32:") {
        Some(crate::analysis::debug_return_pop(program, entry, sections)?)
    } else {
        None
    };
    let arch = program.architecture();
    if prototype.calling_convention == DW_CC_LLVM_X86_STDCALL
        && arch
            .defaultfp
            .is_none_or(|id| arch.proto_models[id].get_name() != "__stdcall")
    {
        return Err("DWARF convention differs from the engine default".into());
    }
    let types = arch.types.as_mut().ok_or("Missing types")?;
    let outtype = prototype
        .output
        .engine(types, false)
        .map_err(|e| e.to_string())?;
    let intypes = prototype
        .inputs
        .iter()
        .map(|(_, t, _)| t.engine(types, false))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let pieces = ghidra_decompiler::fspec::PrototypePieces {
        model: arch.defaultfp,
        name: String::new(),
        outtype: Some(outtype),
        intypes,
        innames: prototype.inputs.iter().map(|(n, _, _)| n.clone()).collect(),
        first_var_arg_slot: -1,
    };
    let registers = prototype
        .inputs
        .iter()
        .map(|(_, _, r)| *r)
        .collect::<Vec<_>>();
    crate::signatures::install_debug(arch, entry, pieces, &registers, &abi, extra_pop, inputs)
}

impl DebugSummary {
    pub fn validate(&self) -> Result<(), String> {
        if (self.state.is_empty() && self.source.is_none())
            || self.state.len() > 96
            || !self
                .state
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
            || self.functions > crate::model::MAX_FUNCTIONS
        {
            return Err("Invalid debug summary".into());
        }
        if let Some(source) = &self.source {
            source.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct DwarfBuilder {
        info: Vec<u8>,
        abbrev: Vec<u8>,
    }
    impl DwarfBuilder {
        fn chain(count: usize, cycle: bool) -> Self {
            // CU(children), typedef(type ref4), signed-int(size, encoding),
            // pointer(type ref4), named typedef(string,type ref4).
            let abbrev = vec![
                1, 0x11, 1, 0, 0, 2, 0x16, 0, 0x49, 0x13, 0, 0, 3, 0x24, 0, 0x0b, 0x0b, 0x3e, 0x0b,
                0, 0, 4, 0x0f, 0, 0x49, 0x13, 0, 0, 5, 0x16, 0, 0x03, 0x08, 0x49, 0x13, 0, 0, 0,
            ];
            let mut info = vec![0; 11];
            info[4..6].copy_from_slice(&4u16.to_le_bytes());
            info[10] = 8;
            info.push(1);
            for i in 0..count {
                info.push(4);
                let target = if cycle && i == count - 1 {
                    12
                } else {
                    12 + (i + 1) * 5
                };
                info.extend_from_slice(&(target as u32).to_le_bytes());
            }
            info.extend_from_slice(&[3, 4, 5, 0]);
            let len = (info.len() - 4) as u32;
            info[..4].copy_from_slice(&len.to_le_bytes());
            Self { info, abbrev }
        }
        fn dwarf(&self) -> g::Dwarf<R<'_>> {
            g::Dwarf::load(|id| {
                Ok::<_, g::Error>(R::new(
                    match id {
                        g::SectionId::DebugInfo => &self.info,
                        g::SectionId::DebugAbbrev => &self.abbrev,
                        _ => &[],
                    },
                    g::LittleEndian,
                ))
            })
            .unwrap()
        }
    }
    #[test]
    fn cyclic_and_deep_types_fail_closed() {
        for (count, cycle) in [(1, true), (15, true), (10_000, false)] {
            let fixture = DwarfBuilder::chain(count, cycle);
            let dwarf = fixture.dwarf();
            let resolver = Resolver::new(&dwarf, &[0]);
            let mut nodes = 0;
            assert!(
                resolver
                    .ty((0, 12), &mut BTreeSet::new(), &mut nodes, 0)
                    .is_none()
            );
            assert!(nodes <= MAX_TYPE_DEPTH + 2);
        }
    }
    #[test]
    fn valid_pointer_and_bad_reference_are_distinct() {
        let mut fixture = DwarfBuilder::chain(1, false);
        let dwarf = fixture.dwarf();
        let resolver = Resolver::new(&dwarf, &[0]);
        assert!(matches!(
            resolver.ty((0, 12), &mut BTreeSet::new(), &mut 0, 0),
            Some(Ty::Pointer(_))
        ));
        fixture.info[13..17].copy_from_slice(&u32::MAX.to_le_bytes());
        let dwarf = fixture.dwarf();
        let resolver = Resolver::new(&dwarf, &[0]);
        assert!(
            resolver
                .ty((0, 12), &mut BTreeSet::new(), &mut 0, 0)
                .is_none()
        );
    }
    #[test]
    fn resolver_decodes_each_validated_die_once_and_rejects_payload_offsets() {
        let fixture = DwarfBuilder::chain(1, false);
        let dwarf = fixture.dwarf();
        let resolver = Resolver::new(&dwarf, &[0]);
        let first = resolver.die((0, 12)).unwrap();
        for _ in 0..100 {
            resolver.attr((0, 12), g::DW_AT_type).unwrap();
            let next = resolver.die((0, 12)).unwrap();
            assert!(std::rc::Rc::ptr_eq(&first, &next));
        }
        assert_eq!(resolver.decoded.borrow().len(), 1);
        assert!(resolver.die((0, 13)).is_none());
    }
    #[test]
    fn truncated_units_and_forged_lengths_do_not_panic() {
        let fixture = DwarfBuilder::chain(2, false);
        for len in 0..fixture.info.len() {
            let truncated = DwarfBuilder {
                info: fixture.info[..len].to_vec(),
                abbrev: fixture.abbrev.clone(),
            };
            let dwarf = truncated.dwarf();
            let resolver = Resolver::new(&dwarf, &[0]);
            assert!(
                resolver
                    .ty((0, 12), &mut BTreeSet::new(), &mut 0, 0)
                    .is_none()
            );
        }
    }
    #[test]
    fn index_rejects_hostile_specs_and_bounds_shared_table_work() {
        for (attributes, dies, units) in [
            (20_000usize, 20_000usize, 1usize),
            (400_000, 400_000, 1),
            (abbreviations::MAX_ATTRIBUTES, 1, MAX_UNITS + 1),
        ] {
            let mut abbrev = vec![1, 0x11, 0];
            for _ in 0..attributes {
                abbrev.extend_from_slice(&[3, 0x19]);
            }
            abbrev.extend_from_slice(&[0, 0, 0]);
            let mut info = Vec::new();
            for _ in 0..units {
                let mut unit = vec![0; 11];
                unit[4..6].copy_from_slice(&4u16.to_le_bytes());
                unit[10] = 8;
                unit.resize(unit.len() + dies, 1);
                let length = (unit.len() - 4) as u32;
                unit[..4].copy_from_slice(&length.to_le_bytes());
                info.extend_from_slice(&unit);
            }
            let image = crate::architecture::fixtures::replace_elf_dwarf(
                crate::architecture::fixtures::dwarf_prototype(false, 0).0,
                &info,
                &abbrev,
            );
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("hostile");
            std::fs::write(&path, &image).unwrap();
            let opened = crate::analysis::LoadedProgram::open_debug(
                path.to_str().unwrap(),
                &DebugOptions {
                    enabled: false,
                    ..Default::default()
                },
            )
            .unwrap();
            let index = DebugIndex::build(&image.into(), &opened.info);
            let summary = index.summary.as_ref().unwrap();
            // One table preflight reads only the permitted attributes plus the
            // terminator (or first excess specification), even across units.
            assert_eq!(
                index.abbreviations.specification_work(),
                abbreviations::MAX_ATTRIBUTES + 1
            );
            if attributes > abbreviations::MAX_ATTRIBUTES {
                assert!(index.abbreviations.tables.is_empty());
                assert!(index.units.is_empty());
                assert!(index.validated.is_empty());
            } else {
                assert_eq!(index.abbreviations.tables.len(), 1);
                assert_eq!(index.units.len(), MAX_UNITS);
                assert_eq!(index.validated.len(), MAX_UNITS);
            }
            assert_eq!(summary.status, DebugStatus::Partial);
            assert_eq!(summary.functions, 0);
        }
    }
    fn section(image: &[u8], index: usize) -> Vec<u8> {
        let at = 0x400 + index * 64;
        let offset = u64::from_le_bytes(image[at + 24..at + 32].try_into().unwrap()) as usize;
        let size = u64::from_le_bytes(image[at + 32..at + 40].try_into().unwrap()) as usize;
        image[offset..offset + size].to_vec()
    }
    #[test]
    fn a_malformed_abbreviation_table_loses_only_its_own_units() {
        let (image, entry) = crate::architecture::fixtures::dwarf_prototype(false, 0);
        let (info, mut abbrev) = (section(&image, 5), section(&image, 6));
        // A leading unit whose table has more attributes than any DIE may use.
        let bad_table = abbrev.len() as u32;
        abbrev.extend_from_slice(&[1, 0x11, 0]);
        for _ in 0..=abbreviations::MAX_ATTRIBUTES {
            abbrev.extend_from_slice(&[3, 8]);
        }
        abbrev.extend_from_slice(&[0, 0, 0]);
        let mut bad = vec![0; 11];
        bad[4..6].copy_from_slice(&4u16.to_le_bytes());
        bad[6..10].copy_from_slice(&bad_table.to_le_bytes());
        bad[10] = 8;
        bad.extend_from_slice(&[1, 0]);
        let length = (bad.len() - 4) as u32;
        bad[..4].copy_from_slice(&length.to_le_bytes());
        bad.extend_from_slice(&info);
        let image = crate::architecture::fixtures::replace_elf_dwarf(image, &bad, &abbrev);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fixture");
        std::fs::write(&path, &image).unwrap();
        let mut loaded = crate::analysis::LoadedProgram::open(path.to_str().unwrap()).unwrap();
        let summary = loaded.debug_summary().unwrap();
        assert_eq!(summary.status, DebugStatus::Partial);
        assert_eq!(summary.functions, 1, "later units still index");
        // The later unit's prototype is still extracted. (Rendering it needs
        // the isolated debug render, which a multithreaded libtest process
        // never runs; real workers cover that path.)
        let index = loaded.debug_index_mut();
        assert_eq!(index.decision(entry), Decision::Undecided);
        assert!(index.candidate(entry).is_some());
        assert_eq!(index.decision(entry), Decision::Undecided);
    }
    #[test]
    fn client_skip_lists_are_bounded_and_sorted() {
        let mut skip = Vec::new();
        assert!(add_skipped(&mut skip, 9));
        assert!(add_skipped(&mut skip, 3));
        assert!(!add_skipped(&mut skip, 9));
        assert_eq!(skip, [3, 9]);
        let full: Vec<u64> = (0..MAX_SKIPPED_FUNCTIONS as u64).collect();
        let mut bounded = full.clone();
        assert!(!add_skipped(&mut bounded, u64::MAX));
        let json = |n: usize| {
            format!(
                "{{\"enabled\":true,\"skip\":[{}]}}",
                (0..n).map(|i| i.to_string()).collect::<Vec<_>>().join(",")
            )
        };
        let options: DebugOptions = serde_json::from_str(&json(MAX_SKIPPED_FUNCTIONS)).unwrap();
        assert_eq!(options.skip, full);
        assert!(serde_json::from_str::<DebugOptions>(&json(MAX_SKIPPED_FUNCTIONS + 1)).is_err());
    }

    fn journal_index(count: u64) -> DebugIndex {
        let mut index = DebugIndex::default();
        for entry in 0..count {
            index.entries.insert(0x1000 + entry * 16, Some((0, 0)));
            if entry % 2 == 0 {
                index.states.insert(
                    0x1000 + entry * 16,
                    EntryState {
                        status: Status::Verified,
                        ..Default::default()
                    },
                );
            }
        }
        index
    }

    #[test]
    fn journals_record_only_net_changes_of_touched_entries() {
        let mut index = journal_index(5000);
        let (a, b, c) = (0x1010, 0x1030, 0x1050);
        index.begin_journal();
        for _ in 0..100 {
            index.defer_target(a);
            index.update(b, |state| state.callee_attempts = 1);
            index.update(b, |state| state.callee_attempts = 0);
        }
        index.decide(c, Status::Provisional);
        index.defer_target(c);
        let changes = index.take_journal();
        // `b` returned to its old state; `a` saturated at the limit.
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert_eq!(changes[0].entry, a);
        assert_eq!(changes[0].old, EntryState::default());
        assert_eq!(changes[0].new.target_attempts, MAX_PROBE_ATTEMPTS);
        assert_eq!(changes[1].entry, c);
        assert_eq!(changes[1].new.status, Status::Provisional);
        assert_eq!(changes[1].new.target_attempts, 1);
        // Another worker with the same starting state adopts them exactly.
        let mut parent = journal_index(5000);
        assert!(parent.check_changes(&changes, &[a, c]));
        parent.apply_changes(&changes);
        assert_eq!(parent.state(a), index.state(a));
        assert_eq!(parent.state(c), index.state(c));
        assert_eq!(parent.states.len(), index.states.len());
    }

    #[test]
    fn invalid_reported_changes_are_refused_as_a_whole() {
        let index = journal_index(8);
        let undecided = 0x1010;
        let verified = 0x1000;
        let to = |status, target_attempts| EntryState {
            status,
            target_attempts,
            callee_attempts: 0,
        };
        let change = |entry, old, new| Change { entry, old, new };
        let good = change(undecided, EntryState::default(), to(Status::Provisional, 0));
        assert!(index.check_changes(&[good], &[undecided]));
        // Not one of the job's entries, or no prototype at all.
        assert!(!index.check_changes(&[good], &[verified]));
        assert!(!index.check_changes(
            &[change(
                0x9999,
                EntryState::default(),
                to(Status::Verified, 0)
            )],
            &[0x9999]
        ));
        // Stale old state, a no-op, an unsorted list, a reopened decision
        // or an attempt count over the limit.
        assert!(!index.check_changes(
            &[change(
                undecided,
                to(Status::Verified, 0),
                to(Status::Rejected, 0)
            )],
            &[undecided]
        ));
        assert!(!index.check_changes(
            &[change(
                undecided,
                EntryState::default(),
                EntryState::default()
            )],
            &[undecided]
        ));
        let other = change(0x1030, EntryState::default(), to(Status::Rejected, 0));
        assert!(!index.check_changes(&[other, good], &[undecided, 0x1030]));
        assert!(!index.check_changes(
            &[change(
                verified,
                to(Status::Verified, 0),
                to(Status::Undecided, 0)
            )],
            &[verified]
        ));
        assert!(!index.check_changes(
            &[change(
                undecided,
                EntryState::default(),
                to(Status::Undecided, 3)
            )],
            &[undecided]
        ));
    }

    #[test]
    fn provisional_entries_are_withdrawn_after_two_unavailable_verifications() {
        let mut index = journal_index(2);
        let entry = 0x1010;
        index.decide(entry, Status::Provisional);
        index.defer_target(entry);
        assert_eq!(index.decision(entry), Decision::Accepted);
        index.defer_target(entry);
        assert_eq!(index.decision(entry), Decision::Rejected);
        // A definitive engine failure withdraws at once.
        let mut index = journal_index(2);
        index.decide(entry, Status::Provisional);
        index.fail_direct(entry);
        assert_eq!(index.decision(entry), Decision::Rejected);
        // Undecided targets keep their own attempt accounting.
        let mut index = journal_index(2);
        index.defer_target(entry);
        index.defer_target(entry);
        assert!(index.undecided(entry));
        assert!(!index.target_attempts_left(entry));
        assert!(index.callee_attempts_left(entry));
    }
}
