//! Imports and exports an image declares, as one bounded, paged table.
//!
//! The worker derives the table once from its immutable snapshot (see
//! `analysis::linkage`); the desktop validates pages into [`Linkage`] and
//! groups it off the GUI thread into a [`LinkageView`]. Records describe
//! declarations only: they never resolve runtime addresses, load libraries,
//! establish prototypes or create functions. Addresses are exact image
//! locations that passed format and section checks in both processes.
//!
//! Record identities are dense per-kind indices in the worker's deterministic
//! order for one snapshot. Names, demangled display text and library paths are
//! display data and never become identities.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{
    BinaryInfo, MAX_SYMBOL_DISPLAY_BYTES, MAX_SYMBOL_RAW_BYTES, SectionInfo, json_escaped_len,
};

/// Imports across every library, including delay-load imports.
pub const MAX_IMPORTS: usize = 10_000;
pub const MAX_EXPORTS: usize = 16_384;
/// Additional slot/stub locations beyond each import's primary pair.
pub const MAX_LINKAGE_LOCATIONS: usize = 16_384;
pub const MAX_LINKAGE_LIBRARIES: usize = 1_024;
/// Library names, versions and forwarder strings.
pub const MAX_LINKAGE_LABEL_BYTES: usize = 256;
/// Total JSON-escaped text of one table: names, display names, libraries,
/// versions and forwarders combined.
pub const MAX_LINKAGE_TEXT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_LINKAGE_RECORDS: usize =
    MAX_IMPORTS + MAX_EXPORTS + MAX_LINKAGE_LOCATIONS + MAX_LINKAGE_LIBRARIES;
/// Format table entries one adapter may examine, charged before deduplication.
pub const MAX_LINKAGE_SCAN: usize = 500_000;
pub const MAX_LINKAGE_SCAN_BYTES: usize = 8 * 1024 * 1024;
/// One reply carries at most this many records and encoded record bytes,
/// whichever fills first. A single record always fits.
pub const MAX_LINKAGE_PAGE_RECORDS: usize = 1024;
pub const MAX_LINKAGE_PAGE_BYTES: usize = 64 * 1024;
pub const MAX_LINKAGE_GAPS: usize = 16;
pub const LINKAGE_POLICY: u32 = 1;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Library {
    pub id: u32,
    /// Display-only dependency name or path, exactly as declared.
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportKind {
    Normal,
    /// A PE delay-load descriptor. Its slot is not a resolved runtime target.
    Delay,
}

/// Mach-O lookup scopes that are not entries of the dependency list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportScope {
    SelfImage,
    MainExecutable,
    DynamicLookup,
    FlatNamespace,
}

impl ImportScope {
    pub fn label(self) -> &'static str {
        match self {
            Self::SelfImage => "Self",
            Self::MainExecutable => "Main executable",
            Self::DynamicLookup => "Dynamic lookup",
            Self::FlatNamespace => "Flat namespace",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Import {
    pub id: u32,
    /// The exact declared symbol; absent for ordinal-only imports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Worker-derived demangled name, display only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    /// A library declared as this import's owner by the format itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ImportScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub kind: ImportKind,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub weak: bool,
    /// The pointer-sized, file-backed slot the loader fills.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    /// An existing code stub verified to read this import's slot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stub: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExportTarget {
    /// File-backed executable code.
    Code { address: u64 },
    /// An ELF IFUNC resolver in file-backed code, not the resolved function.
    Resolver { address: u64 },
    /// Mapped data, possibly zero-filled or declared inside executable memory.
    Data { address: u64 },
    /// Forwarded to another image; never followed.
    Forwarder { target: String },
    /// Declared, but outside every supported mapping.
    Unresolved,
}

impl ExportTarget {
    pub fn address(&self) -> Option<u64> {
        match *self {
            Self::Code { address } | Self::Resolver { address } | Self::Data { address } => {
                Some(address)
            }
            Self::Forwarder { .. } | Self::Unresolved => None,
        }
    }

    pub fn code(&self) -> bool {
        matches!(self, Self::Code { .. } | Self::Resolver { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordinal: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub target: ExportTarget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocationKind {
    Stub,
    Slot,
}

/// A further verified location of one import, beyond its primary slot/stub.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Location {
    pub import: u32,
    pub kind: LocationKind,
    pub address: u64,
}

/// Records arrive libraries first, then imports, exports and locations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case")]
pub enum LinkageRecord {
    Library(Library),
    Import(Import),
    Export(Export),
    Location(Location),
}

impl LinkageRecord {
    fn order(&self) -> u8 {
        match self {
            Self::Library(_) => 0,
            Self::Import(_) => 1,
            Self::Export(_) => 2,
            Self::Location(_) => 3,
        }
    }
}

/// Why a table is not exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkageGap {
    ImportLimit,
    ExportLimit,
    LocationLimit,
    LibraryLimit,
    TextLimit,
    ScanLimit,
    Malformed,
    DelayVariant,
    BindOpcodes,
    ChainedFixups,
    ExportTrie,
}

impl LinkageGap {
    pub fn label(self) -> &'static str {
        match self {
            Self::ImportLimit => "Import limit",
            Self::ExportLimit => "Export limit",
            Self::LocationLimit => "Location limit",
            Self::LibraryLimit => "Library limit",
            Self::TextLimit => "Name budget",
            Self::ScanLimit => "Scan limit",
            Self::Malformed => "Malformed entries",
            Self::DelayVariant => "Unsupported delay imports",
            Self::BindOpcodes => "dyld bind opcodes",
            Self::ChainedFixups => "Chained fixups",
            Self::ExportTrie => "Export trie",
        }
    }
}

/// Identity of one snapshot's declaration table; pages must reproduce it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkageSummary {
    pub image_sha256: String,
    pub policy: u32,
    /// SHA-256 over the image hash, policy and every encoded record, in order.
    pub digest: String,
    pub libraries: usize,
    pub imports: usize,
    pub exports: usize,
    pub locations: usize,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_LINKAGE_GAPS }>")]
    pub gaps: Vec<LinkageGap>,
}

impl LinkageSummary {
    pub fn records(&self) -> usize {
        self.libraries
            .saturating_add(self.imports)
            .saturating_add(self.exports)
            .saturating_add(self.locations)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkagePage {
    pub digest: String,
    pub cursor: usize,
    /// Cursor of the following page; absent on the last page.
    pub next: Option<usize>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_LINKAGE_PAGE_RECORDS }>")]
    pub entries: Vec<LinkageRecord>,
}

/// A symbol, version or library string: non-empty, bounded, no control text.
pub(crate) fn valid_text(text: &str, limit: usize) -> bool {
    !text.is_empty()
        && text.len() <= limit
        && !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
}

/// Exact encoded size of one record inside a page.
pub fn record_bytes(record: &LinkageRecord) -> usize {
    serde_json::to_vec(record).map_or(usize::MAX, |encoded| encoded.len() + 1)
}

/// JSON-escaped text a record charges to [`MAX_LINKAGE_TEXT_BYTES`].
pub fn record_text(record: &LinkageRecord) -> usize {
    let text = |value: &Option<String>| value.as_deref().map_or(0, json_escaped_len);
    match record {
        LinkageRecord::Library(library) => json_escaped_len(&library.name),
        LinkageRecord::Import(import) => {
            text(&import.raw) + text(&import.display) + text(&import.version)
        }
        LinkageRecord::Export(export) => {
            text(&export.raw)
                + text(&export.display)
                + text(&export.version)
                + match &export.target {
                    ExportTarget::Forwarder { target } => json_escaped_len(target),
                    _ => 0,
                }
        }
        LinkageRecord::Location(_) => 0,
    }
}

fn hash_record(hash: &mut Sha256, record: &LinkageRecord) -> Result<(), String> {
    let encoded = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    hash.update((encoded.len() as u64).to_le_bytes());
    hash.update(&encoded);
    Ok(())
}

/// Order-sensitive identity of a complete table.
fn table_hash(image_sha256: &str) -> Sha256 {
    let mut hash = Sha256::new();
    hash.update(b"ghidra-rust-linkage\0");
    hash.update(LINKAGE_POLICY.to_le_bytes());
    hash.update(image_sha256.as_bytes());
    hash
}

fn digest_for(records: &[LinkageRecord], image_sha256: &str) -> String {
    let mut hash = table_hash(image_sha256);
    for record in records {
        // Serializing these plain records cannot fail.
        let _ = hash_record(&mut hash, record);
    }
    format!("{:x}", hash.finalize())
}

/// The worker's immutable, paged table.
pub struct LinkageTable {
    records: Vec<LinkageRecord>,
    sizes: Vec<u32>,
    summary: LinkageSummary,
}

impl LinkageTable {
    /// `records` must already satisfy [`LinkageFetch`]'s structural rules.
    pub(crate) fn new(records: Vec<LinkageRecord>, gaps: Vec<LinkageGap>) -> Self {
        let count = |order| records.iter().filter(|r| r.order() == order).count();
        let summary = LinkageSummary {
            image_sha256: "0".repeat(64),
            policy: LINKAGE_POLICY,
            digest: digest_for(&records, &"0".repeat(64)),
            libraries: count(0),
            imports: count(1),
            exports: count(2),
            locations: count(3),
            gaps,
        };
        let sizes = records
            .iter()
            .map(|record| u32::try_from(record_bytes(record)).unwrap_or(u32::MAX))
            .collect();
        Self {
            records,
            sizes,
            summary,
        }
    }

    pub(crate) fn with_image(mut self, image_sha256: &str) -> Self {
        self.summary.image_sha256 = image_sha256.to_owned();
        self.summary.digest = digest_for(&self.records, image_sha256);
        self
    }

    pub fn summary(&self) -> &LinkageSummary {
        &self.summary
    }

    pub fn records(&self) -> &[LinkageRecord] {
        &self.records
    }

    /// Records from `cursor`, packed by count and encoded size. A cursor at
    /// the end of a non-empty table is rejected rather than answered empty.
    pub fn page(&self, cursor: usize) -> Result<LinkagePage, String> {
        if cursor > self.records.len() || cursor == self.records.len() && cursor != 0 {
            return Err("Linkage cursor is outside the table".into());
        }
        let mut bytes = 0usize;
        let count = self.sizes[cursor..]
            .iter()
            .take(MAX_LINKAGE_PAGE_RECORDS)
            .enumerate()
            .take_while(|(index, size)| {
                bytes = bytes.saturating_add(**size as usize);
                *index == 0 || bytes <= MAX_LINKAGE_PAGE_BYTES - 1024
            })
            .count();
        let end = cursor + count;
        Ok(LinkagePage {
            digest: self.summary.digest.clone(),
            cursor,
            next: (end < self.records.len()).then_some(end),
            entries: self.records[cursor..end].to_vec(),
        })
    }
}

/// Image facts the desktop re-checks every address against.
struct Mapping<'a> {
    info: &'a BinaryInfo,
    pointer: u64,
}

impl Mapping<'_> {
    fn section(&self, address: u64) -> Option<&SectionInfo> {
        let sections = &self.info.sections;
        let index = sections.partition_point(|section| section.address <= address);
        sections.get(index.checked_sub(1)?)
    }

    fn slot(&self, address: u64) -> bool {
        address != 0
            && self
                .section(address)
                .is_some_and(|section| section.backs(address, self.pointer))
    }

    fn code(&self, address: u64) -> bool {
        address != 0 && crate::call_analysis::code_address(self.info, address)
    }

    fn mapped(&self, address: u64) -> bool {
        address != 0
            && self
                .section(address)
                .is_some_and(|section| address - section.address < section.size)
    }
}

fn check(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("Invalid linkage record: {message}"))
    }
}

fn optional_text(value: &Option<String>, limit: usize) -> bool {
    value.as_deref().is_none_or(|text| valid_text(text, limit))
}

fn names_valid(raw: &Option<String>, display: &Option<String>) -> bool {
    optional_text(raw, MAX_SYMBOL_RAW_BYTES)
        && match (raw, display) {
            (_, None) => true,
            (Some(raw), Some(display)) => {
                valid_text(display, MAX_SYMBOL_DISPLAY_BYTES) && display != raw
            }
            (None, Some(_)) => false,
        }
}

/// Parent-side accumulation of one worker table's pages. Every page must
/// continue the previous cursor and the announced digest and counts; records
/// are checked against the displayed image before anything is appended.
pub struct LinkageFetch {
    summary: LinkageSummary,
    records: Vec<LinkageRecord>,
    counts: [usize; 4],
    text: usize,
    hash: Sha256,
    addresses: BTreeMap<(LocationKind, u64), u32>,
}

impl LinkageFetch {
    pub fn new(summary: LinkageSummary, image_sha256: &str) -> Result<Self, String> {
        let gaps_ordered = summary.gaps.windows(2).all(|pair| pair[0] < pair[1]);
        if summary.image_sha256 != image_sha256
            || summary.image_sha256.len() != 64
            || !summary
                .image_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || summary.policy != LINKAGE_POLICY
            || summary.libraries > MAX_LINKAGE_LIBRARIES
            || summary.imports > MAX_IMPORTS
            || summary.exports > MAX_EXPORTS
            || summary.locations > MAX_LINKAGE_LOCATIONS
            || summary.gaps.len() > MAX_LINKAGE_GAPS
            || summary.records() == 0 && summary.digest != digest_for(&[], image_sha256)
            || !gaps_ordered
            || summary.digest.len() != 64
            || !summary
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("Invalid linkage summary".into());
        }
        Ok(Self {
            records: Vec::with_capacity(summary.records().min(MAX_LINKAGE_PAGE_RECORDS)),
            hash: table_hash(image_sha256),
            summary,
            counts: [0; 4],
            text: 0,
            addresses: BTreeMap::new(),
        })
    }

    pub fn summary(&self) -> &LinkageSummary {
        &self.summary
    }

    /// Next cursor to request, or `None` when every record arrived.
    pub fn cursor(&self) -> Option<usize> {
        (self.records.len() < self.summary.records()).then_some(self.records.len())
    }

    fn validate(
        &self,
        record: &LinkageRecord,
        counts: &[usize; 4],
        previous: Option<&LinkageRecord>,
        mapping: &Mapping<'_>,
    ) -> Result<(), String> {
        let order = record.order() as usize;
        check(
            previous.is_none_or(|previous| previous.order() <= record.order()),
            "records are out of order",
        )?;
        let id = counts[order];
        match record {
            LinkageRecord::Library(library) => {
                check(library.id as usize == id, "library identity")?;
                check(
                    valid_text(&library.name, MAX_LINKAGE_LABEL_BYTES),
                    "library name",
                )?;
            }
            LinkageRecord::Import(import) => {
                check(import.id as usize == id, "import identity")?;
                check(
                    import.raw.is_some() || import.ordinal.is_some(),
                    "import identity",
                )?;
                check(names_valid(&import.raw, &import.display), "import name")?;
                check(
                    optional_text(&import.version, MAX_LINKAGE_LABEL_BYTES),
                    "import version",
                )?;
                check(
                    import
                        .library
                        .is_none_or(|library| (library as usize) < counts[0]),
                    "import library",
                )?;
                check(
                    import.library.is_none() || import.scope.is_none(),
                    "import scope",
                )?;
                check(import.slot.is_none_or(|a| mapping.slot(a)), "import slot")?;
                check(import.stub.is_none_or(|a| mapping.code(a)), "import stub")?;
            }
            LinkageRecord::Export(export) => {
                check(export.id as usize == id, "export identity")?;
                check(
                    export.raw.is_some() || export.ordinal.is_some(),
                    "export identity",
                )?;
                check(names_valid(&export.raw, &export.display), "export name")?;
                check(
                    optional_text(&export.version, MAX_LINKAGE_LABEL_BYTES),
                    "export version",
                )?;
                let target = match &export.target {
                    ExportTarget::Code { address } | ExportTarget::Resolver { address } => {
                        mapping.code(*address)
                    }
                    ExportTarget::Data { address } => mapping.mapped(*address),
                    ExportTarget::Forwarder { target } => {
                        valid_text(target, MAX_SYMBOL_RAW_BYTES + MAX_LINKAGE_LABEL_BYTES)
                    }
                    ExportTarget::Unresolved => true,
                };
                check(target, "export destination")?;
            }
            LinkageRecord::Location(location) => {
                check((location.import as usize) < counts[1], "location owner")?;
                if let Some(LinkageRecord::Location(previous)) = previous {
                    check(
                        (previous.import, previous.kind, previous.address)
                            < (location.import, location.kind, location.address),
                        "locations are out of order",
                    )?;
                }
                check(
                    match location.kind {
                        LocationKind::Slot => mapping.slot(location.address),
                        LocationKind::Stub => mapping.code(location.address),
                    },
                    "location address",
                )?;
            }
        }
        Ok(())
    }

    /// Validates and appends one page; nothing is appended on error.
    pub fn accept(&mut self, page: LinkagePage, info: &BinaryInfo) -> Result<(), String> {
        if self.summary.image_sha256 != info.sha256 {
            return Err("Linkage image binding changed".into());
        }
        let cursor = self.cursor().ok_or("Unexpected linkage page")?;
        let pointer = crate::architecture::properties(&info.architecture)
            .ok_or("Unsupported architecture for linkage")?
            .0;
        let mapping = Mapping { info, pointer };
        let end = cursor.saturating_add(page.entries.len());
        if page.digest != self.summary.digest
            || page.cursor != cursor
            || page.entries.is_empty()
            || page.entries.len() > MAX_LINKAGE_PAGE_RECORDS
            || end > self.summary.records()
            || page.next != (end < self.summary.records()).then_some(end)
        {
            return Err("Linkage page does not continue its table".into());
        }
        let mut counts = self.counts;
        let mut text = self.text;
        let mut page_bytes = 0usize;
        let mut addresses = BTreeMap::new();
        let mut previous = self.records.last();
        for record in &page.entries {
            self.validate(record, &counts, previous, &mapping)?;
            let mut address = |kind, pc, owner| -> Result<(), String> {
                let key = (kind, pc);
                check(
                    !self.addresses.contains_key(&key) && addresses.insert(key, owner).is_none(),
                    "duplicate or conflicting location",
                )
            };
            match record {
                LinkageRecord::Import(import) => {
                    if let Some(pc) = import.stub {
                        address(LocationKind::Stub, pc, import.id)?;
                    }
                    if let Some(pc) = import.slot {
                        address(LocationKind::Slot, pc, import.id)?;
                    }
                }
                LinkageRecord::Location(location) => {
                    address(location.kind, location.address, location.import)?
                }
                _ => {}
            }
            counts[record.order() as usize] += 1;
            text = text.saturating_add(record_text(record));
            page_bytes = page_bytes.saturating_add(record_bytes(record));
            previous = Some(record);
        }
        let limits = [
            self.summary.libraries,
            self.summary.imports,
            self.summary.exports,
            self.summary.locations,
        ];
        if counts
            .iter()
            .zip(limits)
            .any(|(count, limit)| *count > limit)
            || page_bytes > MAX_LINKAGE_PAGE_BYTES - 1024
            || text > MAX_LINKAGE_TEXT_BYTES
        {
            return Err("Linkage page exceeds its announced bounds".into());
        }
        let mut hash = self.hash.clone();
        for record in &page.entries {
            hash_record(&mut hash, record)?;
        }
        if end == self.summary.records() {
            if counts != limits {
                return Err("Linkage pages do not match their announced counts".into());
            }
            if format!("{:x}", hash.clone().finalize()) != self.summary.digest {
                return Err("Linkage pages do not match their table digest".into());
            }
        }
        self.hash = hash;
        self.addresses.extend(addresses);
        self.counts = counts;
        self.text = text;
        self.records.extend(page.entries);
        Ok(())
    }

    /// The adopted table once [`Self::cursor`] is `None`.
    pub fn finish(self) -> Option<Linkage> {
        if self.cursor().is_some() {
            return None;
        }
        let mut linkage = Linkage {
            digest: self.summary.digest,
            gaps: self.summary.gaps.into_boxed_slice(),
            ..Default::default()
        };
        let (mut libraries, mut imports, mut exports, mut locations) =
            (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for record in self.records {
            match record {
                LinkageRecord::Library(library) => libraries.push(library),
                LinkageRecord::Import(import) => imports.push(import),
                LinkageRecord::Export(export) => exports.push(export),
                LinkageRecord::Location(location) => locations.push(location),
            }
        }
        linkage.libraries = libraries.into_boxed_slice();
        linkage.imports = imports.into_boxed_slice();
        linkage.exports = exports.into_boxed_slice();
        linkage.locations = locations.into_boxed_slice();
        Some(linkage)
    }
}

/// A validated, adopted table.
#[derive(Debug, Default)]
pub struct Linkage {
    pub digest: String,
    pub libraries: Box<[Library]>,
    pub imports: Box<[Import]>,
    pub exports: Box<[Export]>,
    /// Ordered by import, kind and address.
    pub locations: Box<[Location]>,
    pub gaps: Box<[LinkageGap]>,
}

/// Exact addresses of one import: stubs first, then slots, each ascending.
pub fn import_locations(linkage: &Linkage, import: &Import) -> Vec<(LocationKind, u64)> {
    let start = linkage
        .locations
        .partition_point(|location| location.import < import.id);
    let mut found: Vec<_> = import
        .stub
        .map(|address| (LocationKind::Stub, address))
        .into_iter()
        .chain(import.slot.map(|address| (LocationKind::Slot, address)))
        .chain(
            linkage.locations[start..]
                .iter()
                .take_while(|location| location.import == import.id)
                .map(|location| (location.kind, location.address)),
        )
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

impl Linkage {
    pub fn partial(&self) -> bool {
        !self.gaps.is_empty()
    }

    /// Allocation capacity retained by this table.
    pub fn retained_bytes(&self) -> usize {
        let text = |value: &Option<String>| value.as_ref().map_or(0, String::capacity);
        size_of::<Self>()
            + self.digest.capacity()
            + size_of_val(&*self.libraries)
            + size_of_val(&*self.imports)
            + size_of_val(&*self.exports)
            + size_of_val(&*self.locations)
            + size_of_val(&*self.gaps)
            + self
                .libraries
                .iter()
                .map(|library| library.name.capacity())
                .sum::<usize>()
            + self
                .imports
                .iter()
                .map(|i| text(&i.raw) + text(&i.display) + text(&i.version))
                .sum::<usize>()
            + self
                .exports
                .iter()
                .map(|e| {
                    text(&e.raw)
                        + text(&e.display)
                        + text(&e.version)
                        + match &e.target {
                            ExportTarget::Forwarder { target } => target.capacity(),
                            _ => 0,
                        }
                })
                .sum::<usize>()
    }
}

/// How an import's owning library is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupKey {
    Library(u32),
    Scope(ImportScope),
    Unknown,
}

pub struct ImportGroup {
    pub key: GroupKey,
    pub label: String,
    pub members: Box<[u32]>,
}

/// Grouped and sorted presentation order, built off the GUI thread. Order
/// uses declared text only, so analyst renames never re-sort it.
pub struct LinkageView {
    pub linkage: Arc<Linkage>,
    pub groups: Box<[ImportGroup]>,
    /// Every import by declared name across libraries, then in group order.
    pub imports: Box<[u32]>,
    /// Group index of each import, by import identity.
    pub import_groups: Box<[u32]>,
    pub exports: Box<[u32]>,
}

fn sort_name<'a>(raw: &'a Option<String>, display: &'a Option<String>) -> &'a str {
    display.as_deref().or(raw.as_deref()).unwrap_or("")
}

fn compare_text(left: &str, right: &str) -> Ordering {
    left.bytes()
        .map(|b| b.to_ascii_lowercase())
        .cmp(right.bytes().map(|b| b.to_ascii_lowercase()))
        .then_with(|| left.cmp(right))
}

impl LinkageView {
    pub fn build(linkage: Arc<Linkage>) -> Self {
        let mut keyed: Vec<(GroupKey, u32)> = linkage
            .imports
            .iter()
            .map(|import| {
                let key = match (import.library, import.scope) {
                    (Some(library), _) => GroupKey::Library(library),
                    (None, Some(scope)) => GroupKey::Scope(scope),
                    (None, None) => GroupKey::Unknown,
                };
                (key, import.id)
            })
            .collect();
        let name = |key: GroupKey| match key {
            GroupKey::Library(id) => linkage.libraries[id as usize].name.as_str(),
            GroupKey::Scope(scope) => scope.label(),
            GroupKey::Unknown => "Unknown library",
        };
        // Named libraries alphabetically, then special scopes, then unknown.
        let rank = |key: GroupKey| match key {
            GroupKey::Library(_) => 0,
            GroupKey::Scope(_) => 1,
            GroupKey::Unknown => 2,
        };
        keyed.sort_by(|(left_key, left), (right_key, right)| {
            let (a, b) = (
                &linkage.imports[*left as usize],
                &linkage.imports[*right as usize],
            );
            rank(*left_key)
                .cmp(&rank(*right_key))
                .then_with(|| compare_text(name(*left_key), name(*right_key)))
                .then_with(|| left_key.cmp(right_key))
                .then_with(|| {
                    compare_text(sort_name(&a.raw, &a.display), sort_name(&b.raw, &b.display))
                })
                .then_with(|| a.ordinal.cmp(&b.ordinal))
                .then_with(|| left.cmp(right))
        });
        let mut groups: Vec<ImportGroup> = Vec::new();
        let mut members = Vec::new();
        for (index, (key, id)) in keyed.iter().enumerate() {
            members.push(*id);
            if keyed.get(index + 1).is_none_or(|(next, _)| next != key) {
                groups.push(ImportGroup {
                    key: *key,
                    label: name(*key).to_owned(),
                    members: std::mem::take(&mut members).into_boxed_slice(),
                });
            }
        }
        let mut import_groups = vec![0u32; linkage.imports.len()];
        for (index, group) in groups.iter().enumerate() {
            for &id in &group.members {
                import_groups[id as usize] = index as u32;
            }
        }
        // `keyed` is already in group order; a stable sort keeps it for ties.
        let mut imports: Vec<u32> = keyed.iter().map(|(_, id)| *id).collect();
        imports.sort_by(|left, right| {
            let (a, b) = (
                &linkage.imports[*left as usize],
                &linkage.imports[*right as usize],
            );
            // Ordinal-only imports follow named ones.
            let unnamed = |import: &Import| import.raw.is_none() && import.display.is_none();
            unnamed(a)
                .cmp(&unnamed(b))
                .then_with(|| {
                    compare_text(sort_name(&a.raw, &a.display), sort_name(&b.raw, &b.display))
                })
                .then_with(|| a.ordinal.cmp(&b.ordinal))
        });
        let mut exports: Vec<u32> = linkage.exports.iter().map(|export| export.id).collect();
        exports.sort_by(|left, right| {
            let (a, b) = (
                &linkage.exports[*left as usize],
                &linkage.exports[*right as usize],
            );
            // Ordinal-only exports follow named ones.
            a.raw
                .is_none()
                .cmp(&b.raw.is_none())
                .then_with(|| {
                    compare_text(sort_name(&a.raw, &a.display), sort_name(&b.raw, &b.display))
                })
                .then_with(|| a.ordinal.cmp(&b.ordinal))
                .then_with(|| left.cmp(right))
        });
        Self {
            linkage,
            groups: groups.into_boxed_slice(),
            imports: imports.into_boxed_slice(),
            import_groups: import_groups.into_boxed_slice(),
            exports: exports.into_boxed_slice(),
        }
    }

    /// Allocation capacity retained by the table and this presentation.
    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.linkage.retained_bytes()
            + size_of_val(&*self.groups)
            + self
                .groups
                .iter()
                .map(|group| group.label.capacity() + size_of_val(&*group.members))
                .sum::<usize>()
            + size_of_val(&*self.imports)
            + size_of_val(&*self.import_groups)
            + size_of_val(&*self.exports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BinaryInfo, SectionInfo};

    pub(crate) fn info() -> BinaryInfo {
        BinaryInfo {
            path: "fixture".into(),
            architecture: "x86-64".into(),
            format: "PE".into(),
            entry: 0x1000,
            file_len: 0x3000,
            sha256: "0".repeat(64),
            source_identity: None,
            sections: vec![
                SectionInfo {
                    name: ".text".into(),
                    address: 0x1000,
                    size: 0x1000,
                    file_offset: 0x400,
                    file_size: 0x1000,
                    executable: true,
                },
                SectionInfo {
                    name: ".data".into(),
                    address: 0x2000,
                    size: 0x2000,
                    file_offset: 0x1400,
                    file_size: 0x100,
                    executable: false,
                },
            ],
            functions: Vec::new(),
            functions_truncated: false,
            warnings: Vec::new(),
        }
    }

    fn import(id: u32, raw: &str, library: Option<u32>) -> LinkageRecord {
        LinkageRecord::Import(Import {
            id,
            raw: Some(raw.into()),
            display: None,
            ordinal: None,
            library,
            scope: None,
            version: None,
            kind: ImportKind::Normal,
            weak: false,
            slot: Some(0x2000 + u64::from(id) * 8),
            stub: None,
        })
    }

    fn library(id: u32, name: &str) -> LinkageRecord {
        LinkageRecord::Library(Library {
            id,
            name: name.into(),
        })
    }

    fn fetch_all(table: &LinkageTable, info: &BinaryInfo) -> Result<Linkage, String> {
        let mut fetch = LinkageFetch::new(table.summary().clone(), &info.sha256)?;
        while let Some(cursor) = fetch.cursor() {
            fetch.accept(table.page(cursor)?, info)?;
        }
        fetch.finish().ok_or_else(|| "incomplete".into())
    }

    #[test]
    fn equal_names_in_different_libraries_stay_distinct_rows() {
        let table = LinkageTable::new(
            vec![
                library(0, "b.dll"),
                library(1, "A.dll"),
                import(0, "Shared", Some(0)),
                import(1, "Shared", Some(1)),
                import(2, "Alone", None),
                import(3, "Early", Some(0)),
            ],
            Vec::new(),
        );
        let linkage = fetch_all(&table, &info()).unwrap();
        let view = LinkageView::build(Arc::new(linkage));
        let groups: Vec<_> = view
            .groups
            .iter()
            .map(|group| (group.label.as_str(), group.members.to_vec()))
            .collect();
        assert_eq!(
            groups,
            [
                ("A.dll", vec![1]),
                ("b.dll", vec![3, 0]),
                ("Unknown library", vec![2])
            ]
        );
        assert!(view.retained_bytes() > view.linkage.retained_bytes());
    }

    #[test]
    fn pages_are_bounded_and_reassemble_the_announced_table() {
        let raw = "x".repeat(MAX_SYMBOL_RAW_BYTES);
        let mut records = vec![library(0, "lib")];
        records.extend((0..3000).map(|id| {
            let mut record = import(id, &format!("name{id}"), Some(0));
            if let LinkageRecord::Import(import) = &mut record {
                import.slot = None;
                if id % 500 == 0 {
                    import.raw = Some(raw.clone());
                }
            }
            record
        }));
        let table = LinkageTable::new(records, vec![LinkageGap::Malformed]);
        let mut cursor = Some(0);
        let mut pages = 0;
        while let Some(at) = cursor {
            let page = table.page(at).unwrap();
            assert!(page.entries.len() <= MAX_LINKAGE_PAGE_RECORDS);
            let encoded = serde_json::to_vec(&crate::model::WorkerResponse {
                id: u64::MAX,
                response: crate::model::Response::Linkage {
                    summary: table.summary().clone(),
                    page: page.clone(),
                },
            })
            .unwrap();
            crate::bounded::check_reply(&encoded).unwrap();
            cursor = page.next;
            pages += 1;
        }
        assert!(pages >= 3, "{pages} pages");
        assert!(table.page(3001).is_err());
        let linkage = fetch_all(&table, &info()).unwrap();
        assert_eq!(linkage.imports.len(), 3000);
        assert!(linkage.partial());
    }

    #[test]
    fn worst_case_records_fit_one_page_and_reply_preflight() {
        let long = "\"".repeat(MAX_SYMBOL_RAW_BYTES);
        let record = LinkageRecord::Export(Export {
            id: u32::MAX,
            raw: Some(long.clone()),
            display: Some("\\".repeat(MAX_SYMBOL_DISPLAY_BYTES)),
            ordinal: Some(u32::MAX),
            version: Some("\"".repeat(MAX_LINKAGE_LABEL_BYTES)),
            target: ExportTarget::Forwarder {
                target: "\"".repeat(MAX_SYMBOL_RAW_BYTES + MAX_LINKAGE_LABEL_BYTES),
            },
        });
        let page = LinkagePage {
            digest: "f".repeat(64),
            cursor: usize::MAX,
            next: Some(usize::MAX),
            entries: vec![record; 1],
        };
        let encoded = serde_json::to_vec(&crate::model::WorkerResponse {
            id: u64::MAX,
            response: crate::model::Response::Linkage {
                summary: LinkageTable::new(vec![], vec![]).summary().clone(),
                page,
            },
        })
        .unwrap();
        assert!(encoded.len() < MAX_LINKAGE_PAGE_BYTES);
        crate::bounded::check_reply(&encoded).unwrap();
        // Full pages of the smallest records stay inside the node budget.
        let page = LinkagePage {
            digest: "f".repeat(64),
            cursor: 0,
            next: None,
            entries: (0..MAX_LINKAGE_PAGE_RECORDS as u32)
                .map(|id| {
                    LinkageRecord::Location(Location {
                        import: id,
                        kind: LocationKind::Slot,
                        address: u64::from(id),
                    })
                })
                .collect(),
        };
        let encoded = serde_json::to_vec(&crate::model::WorkerResponse {
            id: 1,
            response: crate::model::Response::Linkage {
                summary: LinkageTable::new(vec![], vec![]).summary().clone(),
                page,
            },
        })
        .unwrap();
        crate::bounded::check_reply(&encoded).unwrap();
    }

    #[test]
    fn fetch_rejects_pages_that_do_not_continue_or_fit_the_image() {
        let table = LinkageTable::new(
            vec![
                library(0, "lib"),
                import(0, "a", Some(0)),
                import(1, "b", None),
                LinkageRecord::Export(Export {
                    id: 0,
                    raw: Some("data".into()),
                    display: None,
                    ordinal: None,
                    version: None,
                    target: ExportTarget::Data { address: 0x3000 },
                }),
                LinkageRecord::Location(Location {
                    import: 1,
                    kind: LocationKind::Slot,
                    address: 0x2080,
                }),
            ],
            Vec::new(),
        );
        let info = info();
        let page = table.page(0).unwrap();
        let rejected = |edit: &dyn Fn(&mut LinkagePage)| {
            let mut page = page.clone();
            edit(&mut page);
            let mut fetch = LinkageFetch::new(table.summary().clone(), &info.sha256).unwrap();
            assert!(fetch.accept(page, &info).is_err());
            assert_eq!(fetch.cursor(), Some(0), "nothing appended");
        };
        fn import_at(page: &mut LinkagePage, index: usize) -> &mut Import {
            match &mut page.entries[index] {
                LinkageRecord::Import(import) => import,
                _ => unreachable!(),
            }
        }
        rejected(&|page| page.digest = "0".repeat(64));
        rejected(&|page| page.cursor = 1);
        rejected(&|page| page.next = Some(2));
        rejected(&|page| page.entries.swap(0, 1));
        rejected(&|page| page.entries.clear());
        rejected(&|page| import_at(page, 1).id = 1);
        rejected(&|page| import_at(page, 1).library = Some(1));
        rejected(&|page| import_at(page, 1).raw = None);
        rejected(&|page| import_at(page, 1).raw = Some("a\n".into()));
        rejected(&|page| import_at(page, 1).display = Some("a".into()));
        rejected(&|page| import_at(page, 2).display = Some("b2".into()));
        // Zero, unmapped and partially backed slots never pass.
        for slot in [0, 0x1_0000, 0x20fc] {
            rejected(&|page| import_at(page, 1).slot = Some(slot));
        }
        rejected(&|page| import_at(page, 1).stub = Some(0x2000));
        rejected(&|page| {
            page.entries[3] = LinkageRecord::Export(Export {
                id: 0,
                raw: Some("data".into()),
                display: None,
                ordinal: None,
                version: None,
                target: ExportTarget::Data { address: 0x8000 },
            })
        });
        rejected(&|page| {
            page.entries[4] = LinkageRecord::Location(Location {
                import: 2,
                kind: LocationKind::Slot,
                address: 0x2080,
            })
        });
        let mut fetch = LinkageFetch::new(table.summary().clone(), &info.sha256).unwrap();
        fetch.accept(page.clone(), &info).unwrap();
        assert!(fetch.accept(page, &info).is_err(), "no page after the last");
        let linkage = fetch.finish().unwrap();
        assert_eq!(
            import_locations(&linkage, &linkage.imports[1]),
            [(LocationKind::Slot, 0x2008), (LocationKind::Slot, 0x2080)]
        );
        let mut summary = table.summary().clone();
        summary.imports = MAX_IMPORTS + 1;
        assert!(LinkageFetch::new(summary, &info.sha256).is_err());
        let mut summary = table.summary().clone();
        summary.gaps = vec![LinkageGap::ScanLimit, LinkageGap::ImportLimit];
        assert!(LinkageFetch::new(summary, &info.sha256).is_err());
    }

    #[test]
    fn bindings_empty_tables_and_conflicting_locations_fail_closed() {
        let info = info();
        let empty = LinkageTable::new(vec![], vec![]);
        assert!(empty.page(0).unwrap().entries.is_empty());
        assert!(
            LinkageFetch::new(empty.summary().clone(), &info.sha256)
                .unwrap()
                .finish()
                .is_some()
        );
        assert!(LinkageFetch::new(empty.summary().clone(), &"a".repeat(64)).is_err());
        let mut summary = empty.summary().clone();
        summary.digest = "f".repeat(64);
        assert!(LinkageFetch::new(summary, &info.sha256).is_err());
        let mut summary = empty.summary().clone();
        summary.policy += 1;
        assert!(LinkageFetch::new(summary, &info.sha256).is_err());

        let table = LinkageTable::new(vec![import(0, "one", None)], vec![]);
        let mut page = table.page(0).unwrap();
        if let LinkageRecord::Import(import) = &mut page.entries[0] {
            import.raw = Some("tampered".into());
        }
        let mut fetch = LinkageFetch::new(table.summary().clone(), &info.sha256).unwrap();
        assert!(fetch.accept(page, &info).is_err());
        // Failed digest validation must not retain staged address ownership.
        fetch.accept(table.page(0).unwrap(), &info).unwrap();
        assert!(fetch.finish().is_some());

        let mut records = vec![import(0, "first", None), import(1, "other", None)];
        if let LinkageRecord::Import(import) = &mut records[1] {
            import.slot = Some(0x2000);
        }
        let conflict = LinkageTable::new(records, vec![]);
        assert!(fetch_all(&conflict, &info).is_err());
        let encoded = serde_json::json!({"digest":"f".repeat(64),"cursor":0,"next":null,"entries": vec![serde_json::json!({"record":"library", "id":0,"name":"x"}); MAX_LINKAGE_PAGE_RECORDS + 1]});
        assert!(serde_json::from_value::<LinkagePage>(encoded).is_err());
    }
}
