//! Bounded import/export adapters over the worker's immutable image snapshot.
//!
//! PE descriptors are read by `crate::pe` into a [`Builder`]; ELF dynamic
//! symbols and Mach-O symbol tables are read here with the pinned `object`
//! crate's low-level iterators, never its allocating whole-list helpers. Every
//! adapter charges one cumulative scan budget before it deduplicates. Library
//! ownership is recorded only where the format declares it: an ELF symbol's
//! version-need file or a Mach-O two-level ordinal. Dependency lists alone
//! never assign an owner. Slots come from exact relocation or indirect-symbol
//! records; stubs only from engine import-stub evidence with an unambiguous
//! identity. [`Builder::finish`] applies the desktop's own address rules so
//! both processes agree on every location. Display names are demangled here.
use std::collections::{BTreeMap, BTreeSet};

use object::Endianness;
use object::elf;
use object::macho;
use object::read::elf::{FileHeader, Rel, Rela, SectionHeader, Sym};
use object::read::macho::{MachHeader, Nlist, Segment};

use crate::linkage::*;
use crate::model::{BinaryInfo, MAX_SYMBOL_RAW_BYTES, json_escaped_len};
use crate::symbol_names::{DemangleOutcome, SymbolFormat, demangle};

/// Declared text, exactly: valid UTF-8 without control characters.
fn text(bytes: &[u8], limit: usize) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    valid_text(text, limit).then(|| text.to_owned())
}

pub(crate) struct ImportSpec<'a> {
    pub raw: Option<&'a [u8]>,
    pub ordinal: Option<u32>,
    pub library: Option<u32>,
    pub scope: Option<ImportScope>,
    pub version: Option<&'a [u8]>,
    pub kind: ImportKind,
    pub weak: bool,
    pub slot: Option<u64>,
}

pub(crate) struct ExportSpec<'a> {
    pub raw: Option<&'a [u8]>,
    pub ordinal: Option<u32>,
    pub version: Option<&'a [u8]>,
    pub target: ExportTarget,
}

/// Accumulates one image's records within every table bound. Omitted
/// identities are recorded as gaps, never truncated.
#[derive(Default)]
pub(crate) struct Builder {
    libraries: Vec<Library>,
    library_ids: BTreeMap<String, u32>,
    imports: Vec<Import>,
    slots: BTreeMap<u64, u32>,
    exports: Vec<Export>,
    locations: Vec<Location>,
    text: usize,
    scanned: usize,
    scanned_bytes: usize,
    gaps: BTreeSet<LinkageGap>,
}

impl Builder {
    pub fn gap(&mut self, gap: LinkageGap) {
        self.gaps.insert(gap);
    }

    /// Charges `entries` format records; false once the budget is spent.
    pub fn scan(&mut self, entries: usize) -> bool {
        match self.scanned.checked_add(entries) {
            Some(total) if total <= MAX_LINKAGE_SCAN => {
                self.scanned = total;
                true
            }
            _ => {
                self.scanned = MAX_LINKAGE_SCAN;
                self.gap(LinkageGap::ScanLimit);
                false
            }
        }
    }

    pub fn scan_bytes(&mut self, entries: usize, width: usize) -> bool {
        let Some(bytes) = entries.checked_mul(width) else {
            self.gap(LinkageGap::ScanLimit);
            return false;
        };
        if !self.scan(entries) || bytes > MAX_LINKAGE_SCAN_BYTES - self.scanned_bytes {
            self.gap(LinkageGap::ScanLimit);
            return false;
        }
        self.scanned_bytes += bytes;
        true
    }

    fn charge(&mut self, bytes: usize) -> bool {
        if bytes > MAX_LINKAGE_TEXT_BYTES - self.text {
            self.gap(LinkageGap::TextLimit);
            return false;
        }
        self.text += bytes;
        true
    }

    pub fn c_string<'a>(&mut self, bytes: &'a [u8], maximum: usize) -> Option<&'a [u8]> {
        let available = MAX_LINKAGE_SCAN_BYTES - self.scanned_bytes;
        if available == 0 {
            self.gap(LinkageGap::ScanLimit);
            return None;
        }
        let bytes = &bytes[..bytes.len().min(maximum + 1).min(available)];
        let length = bytes.iter().position(|byte| *byte == 0);
        let work = length.map_or(bytes.len(), |length| length + 1);
        self.scanned_bytes += work;
        if length.is_none() && self.scanned_bytes == MAX_LINKAGE_SCAN_BYTES {
            self.gap(LinkageGap::ScanLimit);
        }
        let bytes = &bytes[..length?];
        (!bytes.is_empty() && bytes.len() <= maximum).then_some(bytes)
    }

    pub fn exports_full(&self) -> bool {
        self.exports.len() >= MAX_EXPORTS
    }

    pub fn imports_full(&self) -> bool {
        self.imports.len() >= MAX_IMPORTS
    }

    /// The identity of a declared library name, shared by equal names.
    pub fn library(&mut self, name: &[u8]) -> Option<u32> {
        let Some(name) = text(name, MAX_LINKAGE_LABEL_BYTES) else {
            self.gap(LinkageGap::Malformed);
            return None;
        };
        if let Some(&id) = self.library_ids.get(&name) {
            return Some(id);
        }
        if self.libraries.len() >= MAX_LINKAGE_LIBRARIES {
            self.gap(LinkageGap::LibraryLimit);
            return None;
        }
        if !self.charge(json_escaped_len(&name)) {
            return None;
        }
        let id = self.libraries.len() as u32;
        self.library_ids.insert(name.clone(), id);
        self.libraries.push(Library { id, name });
        Some(id)
    }

    /// A symbol name and optional version. An invalid name keeps only its
    /// ordinal identity; without one the record is omitted.
    fn identity(
        &mut self,
        raw: Option<&[u8]>,
        ordinal: Option<u32>,
        version: Option<&[u8]>,
    ) -> Option<(Option<String>, Option<String>)> {
        let name = raw.and_then(|raw| text(raw, MAX_SYMBOL_RAW_BYTES));
        if raw.is_some() && name.is_none() {
            self.gap(LinkageGap::Malformed);
            ordinal?;
        }
        if name.is_none() && ordinal.is_none() {
            self.gap(LinkageGap::Malformed);
            return None;
        }
        let version = version.and_then(|version| {
            let text = text(version, MAX_LINKAGE_LABEL_BYTES);
            if text.is_none() {
                self.gap(LinkageGap::Malformed);
            }
            text
        });
        let bytes = name.as_deref().map_or(0, json_escaped_len)
            + version.as_deref().map_or(0, json_escaped_len);
        self.charge(bytes).then_some((name, version))
    }

    pub fn import(&mut self, spec: ImportSpec<'_>) -> Option<u32> {
        if self.imports_full() {
            self.gap(LinkageGap::ImportLimit);
            return None;
        }
        // One loader-written slot belongs to one declaration.
        if let Some(previous) = spec.slot.and_then(|slot| self.slots.get(&slot)).copied() {
            self.imports[previous as usize].slot = None;
            self.gap(LinkageGap::Malformed);
            return None;
        }
        let (raw, version) = self.identity(spec.raw, spec.ordinal, spec.version)?;
        if let Some(slot) = spec.slot {
            self.slots.insert(slot, self.imports.len() as u32);
        }
        let id = self.imports.len() as u32;
        self.imports.push(Import {
            id,
            raw,
            display: None,
            ordinal: spec.ordinal,
            library: spec.library,
            scope: spec.scope.filter(|_| spec.library.is_none()),
            version,
            kind: spec.kind,
            weak: spec.weak,
            slot: spec.slot,
            stub: None,
        });
        Some(id)
    }

    pub fn export(&mut self, spec: ExportSpec<'_>) -> Option<u32> {
        if self.exports.len() >= MAX_EXPORTS {
            self.gap(LinkageGap::ExportLimit);
            return None;
        }
        let (raw, version) = self.identity(spec.raw, spec.ordinal, spec.version)?;
        let target = match spec.target {
            ExportTarget::Forwarder { target } if !self.charge(json_escaped_len(&target)) => {
                ExportTarget::Unresolved
            }
            target => target,
        };
        let id = self.exports.len() as u32;
        self.exports.push(Export {
            id,
            raw,
            display: None,
            ordinal: spec.ordinal,
            version,
            target,
        });
        Some(id)
    }

    /// Records a further verified location; the first stub becomes primary.
    pub fn location(&mut self, import: u32, kind: LocationKind, address: u64) {
        let Some(record) = self.imports.get_mut(import as usize) else {
            return;
        };
        let primary = match kind {
            LocationKind::Stub => &mut record.stub,
            LocationKind::Slot => &mut record.slot,
        };
        if primary.is_none() {
            *primary = Some(address);
        } else if *primary != Some(address) {
            if self.locations.len() >= MAX_LINKAGE_LOCATIONS {
                self.gap(LinkageGap::LocationLimit);
                return;
            }
            self.locations.push(Location {
                import,
                kind,
                address,
            });
        }
    }

    /// Applies the desktop's address rules, adds display names while the
    /// text budget allows, and orders the records for paging.
    pub fn finish(mut self, info: &BinaryInfo, format: SymbolFormat) -> LinkageTable {
        let _finishing = crate::performance::span("open_linkage_finish");
        let pointer = crate::architecture::properties(&info.architecture).map_or(0, |p| p.0);
        let section = |address: u64| {
            let index = info.sections.partition_point(|s| s.address <= address);
            index
                .checked_sub(1)
                .and_then(|index| info.sections.get(index))
        };
        let code = |address: u64| address != 0 && crate::call_analysis::code_address(info, address);
        let slot = |address: u64| {
            pointer != 0
                && address != 0
                && section(address).is_some_and(|section| section.backs(address, pointer))
        };
        let mapped = |address: u64| {
            address != 0
                && section(address).is_some_and(|section| address - section.address < section.size)
        };
        // Conflicting declarations never keep a first-wins address association.
        let mut owners = BTreeMap::new();
        let mut add = |id, kind, address| {
            owners
                .entry((kind, address))
                .and_modify(|owner| {
                    if *owner != Some(id) {
                        *owner = None;
                    }
                })
                .or_insert(Some(id));
        };
        for import in &self.imports {
            if let Some(address) = import.slot {
                add(import.id, LocationKind::Slot, address);
            }
            if let Some(address) = import.stub {
                add(import.id, LocationKind::Stub, address);
            }
        }
        for location in &self.locations {
            add(location.import, location.kind, location.address);
        }
        let mut malformed = owners.values().any(Option::is_none);
        for import in &mut self.imports {
            if import.slot.is_some_and(|address| {
                !slot(address)
                    || owners.get(&(LocationKind::Slot, address)) != Some(&Some(import.id))
            }) {
                import.slot = None;
                malformed = true;
            }
            if import.stub.is_some_and(|address| {
                !code(address)
                    || owners.get(&(LocationKind::Stub, address)) != Some(&Some(import.id))
            }) {
                import.stub = None;
            }
        }
        self.locations.retain(|location| {
            owners.get(&(location.kind, location.address)) == Some(&Some(location.import))
                && match location.kind {
                    LocationKind::Slot => slot(location.address),
                    LocationKind::Stub => code(location.address),
                }
        });
        for export in &mut self.exports {
            export.target = match std::mem::replace(&mut export.target, ExportTarget::Unresolved) {
                ExportTarget::Code { address } | ExportTarget::Data { address }
                    if code(address) =>
                {
                    ExportTarget::Code { address }
                }
                ExportTarget::Resolver { address } if code(address) => {
                    ExportTarget::Resolver { address }
                }
                ExportTarget::Code { address }
                | ExportTarget::Resolver { address }
                | ExportTarget::Data { address }
                    if mapped(address) =>
                {
                    ExportTarget::Data { address }
                }
                ExportTarget::Code { .. }
                | ExportTarget::Resolver { .. }
                | ExportTarget::Data { .. } => ExportTarget::Unresolved,
                target => target,
            };
        }
        if malformed {
            self.gap(LinkageGap::Malformed);
        }
        let demangled = |raw: &Option<String>| match raw.as_deref().map(|raw| demangle(raw, format))
        {
            Some(DemangleOutcome::Display(name)) if Some(&name.text) != raw.as_ref() => {
                Some(name.text)
            }
            _ => None,
        };
        let mut text = self.text;
        let mut over_budget = false;
        let mut charge = |display: Option<String>| {
            let display = display?;
            let bytes = json_escaped_len(&display);
            if bytes > MAX_LINKAGE_TEXT_BYTES - text {
                over_budget = true;
                return None;
            }
            text += bytes;
            Some(display)
        };
        for import in &mut self.imports {
            import.display = charge(demangled(&import.raw));
        }
        for export in &mut self.exports {
            export.display = charge(demangled(&export.raw));
        }
        if over_budget {
            self.gap(LinkageGap::TextLimit);
        }
        self.locations
            .sort_unstable_by_key(|l| (l.import, l.kind, l.address));
        self.locations.dedup();
        let imports = &self.imports;
        self.locations.retain(|location| {
            let record = &imports[location.import as usize];
            let primary = match location.kind {
                LocationKind::Stub => record.stub,
                LocationKind::Slot => record.slot,
            };
            primary != Some(location.address)
        });
        let records = self
            .libraries
            .into_iter()
            .map(LinkageRecord::Library)
            .chain(self.imports.into_iter().map(LinkageRecord::Import))
            .chain(self.exports.into_iter().map(LinkageRecord::Export))
            .chain(self.locations.into_iter().map(LinkageRecord::Location))
            .collect();
        LinkageTable::new(
            records,
            self.gaps.into_iter().take(MAX_LINKAGE_GAPS).collect(),
        )
        .with_image(&info.sha256)
    }
}

/// An existing engine import stub: its address and exact original symbol.
pub(crate) struct EngineStub<'a> {
    pub address: u64,
    pub raw: &'a str,
}

/// Exact slot encoded by a conventional stub in the immutable snapshot.
/// Name equality alone never establishes a relationship to an import.
fn stub_slot(bytes: &[u8], info: &BinaryInfo, address: u64) -> Option<u64> {
    let width = if info.architecture == "AArch64" {
        12
    } else {
        6
    };
    let index = info
        .sections
        .partition_point(|section| section.address <= address)
        .checked_sub(1)?;
    let section = &info.sections[index];
    if !section.executable || !section.backs(address, width) {
        return None;
    }
    let at = usize::try_from(
        section
            .file_offset
            .checked_add(address.checked_sub(section.address)?)?,
    )
    .ok()?;
    let code = bytes.get(at..at.checked_add(width as usize)?)?;
    if info.architecture == "AArch64" {
        crate::pe_symbols::aarch64_veneer_slot(
            address,
            [
                u32::from_le_bytes(code[0..4].try_into().ok()?),
                u32::from_le_bytes(code[4..8].try_into().ok()?),
                u32::from_le_bytes(code[8..12].try_into().ok()?),
            ],
        )
    } else {
        crate::pe_symbols::x86_thunk_slot(
            address,
            code,
            crate::architecture::properties(&info.architecture)?.0 as u32,
        )
    }
}

/// The import/export table of a freshly opened image. `pe` carries records
/// already read by the PE metadata parser.
pub(crate) fn table(
    bytes: &[u8],
    info: &BinaryInfo,
    pe: Option<Builder>,
    stubs: &[EngineStub<'_>],
) -> LinkageTable {
    let _building = crate::performance::span("open_linkage");
    let (builder, format) = match info.format.as_str() {
        "PE" => {
            let mut builder = pe.unwrap_or_default();
            let slots: BTreeMap<_, _> = builder
                .imports
                .iter()
                .filter_map(|import| import.slot.map(|slot| (slot, import.id)))
                .collect();
            for function in info
                .functions
                .iter()
                .take(crate::pe_symbols::MAX_THUNK_TARGETS)
            {
                if let Some(id) =
                    stub_slot(bytes, info, function.address).and_then(|slot| slots.get(&slot))
                {
                    builder.location(*id, LocationKind::Stub, function.address);
                }
            }
            if info.functions.len() > crate::pe_symbols::MAX_THUNK_TARGETS {
                builder.gap(LinkageGap::LocationLimit);
            }
            (builder, SymbolFormat::Pe)
        }
        "ELF" => {
            let mut builder = Builder::default();
            match object::FileKind::parse(bytes) {
                Ok(object::FileKind::Elf32) => {
                    elf_table::<elf::FileHeader32<Endianness>>(&mut builder, bytes, info, stubs)
                }
                Ok(object::FileKind::Elf64) => {
                    elf_table::<elf::FileHeader64<Endianness>>(&mut builder, bytes, info, stubs)
                }
                _ => builder.gap(LinkageGap::Malformed),
            }
            (builder, SymbolFormat::Other)
        }
        "Mach-O" => {
            let mut builder = Builder::default();
            match object::FileKind::parse(bytes) {
                Ok(object::FileKind::MachO32) => {
                    macho_table::<macho::MachHeader32<Endianness>>(&mut builder, bytes, info)
                }
                Ok(object::FileKind::MachO64) => {
                    macho_table::<macho::MachHeader64<Endianness>>(&mut builder, bytes, info)
                }
                _ => builder.gap(LinkageGap::Malformed),
            }
            (builder, SymbolFormat::MachO)
        }
        _ => (Builder::default(), SymbolFormat::Other),
    };
    builder.finish(info, format)
}

/// Dynamic relocation types that fill an import's pointer slot.
fn slot_relocation(machine: u16, r_type: u32) -> Option<bool> {
    // `Some(true)` for lazy PLT slots, `Some(false)` for GOT data slots.
    match (machine, r_type) {
        (elf::EM_X86_64, elf::R_X86_64_JUMP_SLOT) | (elf::EM_386, elf::R_386_JMP_SLOT) => {
            Some(true)
        }
        (elf::EM_AARCH64, elf::R_AARCH64_JUMP_SLOT) => Some(true),
        (elf::EM_X86_64, elf::R_X86_64_GLOB_DAT)
        | (elf::EM_386, elf::R_386_GLOB_DAT)
        | (elf::EM_AARCH64, elf::R_AARCH64_GLOB_DAT) => Some(false),
        _ => None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Version<'a> {
    name: &'a [u8],
    file: Option<&'a [u8]>,
}

fn u16_at(data: &[u8], offset: usize, little: bool) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

fn u32_at(data: &[u8], offset: usize, little: bool) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn string_at<'a>(data: &'a [u8], offset: u32, limit: usize, out: &mut Builder) -> Option<&'a [u8]> {
    out.c_string(data.get(offset as usize..)?, limit)
}

/// Read forward-only version chains ourselves. The convenience VersionTable
/// scans them repeatedly and allocates by the largest untrusted version index.
fn versions<'a>(
    data: &'a [u8],
    strings: &'a [u8],
    little: bool,
    need: bool,
    out: &mut Builder,
    result: &mut BTreeMap<u16, Option<Version<'a>>>,
) -> Option<()> {
    let mut offset = 0usize;
    loop {
        if !out.scan_bytes(1, if need { 16 } else { 20 }) {
            return Some(());
        }
        let record = data.get(offset..)?;
        if u16_at(record, 0, little)? != 1 {
            return None;
        }
        let (count, auxiliary, next, file, definition) = if need {
            (
                u16_at(record, 2, little)?,
                u32_at(record, 8, little)?,
                u32_at(record, 12, little)?,
                Some(string_at(
                    strings,
                    u32_at(record, 4, little)?,
                    MAX_LINKAGE_LABEL_BYTES,
                    out,
                )?),
                None,
            )
        } else {
            (
                u16_at(record, 6, little)?,
                u32_at(record, 12, little)?,
                u32_at(record, 16, little)?,
                None,
                Some(u16_at(record, 4, little)? & elf::VERSYM_VERSION),
            )
        };
        let minimum = if need { 16 } else { 20 };
        if count == 0 || auxiliary < minimum {
            return None;
        }
        let mut aux_offset = auxiliary as usize;
        for index in 0..count {
            if !out.scan_bytes(1, if need { 16 } else { 8 }) {
                return Some(());
            }
            let aux = record.get(aux_offset..)?;
            let (id, name_at, next_aux, minimum_aux) = if need {
                (
                    u16_at(aux, 6, little)? & elf::VERSYM_VERSION,
                    u32_at(aux, 8, little)?,
                    u32_at(aux, 12, little)?,
                    16,
                )
            } else {
                (
                    definition?,
                    u32_at(aux, 0, little)?,
                    u32_at(aux, 4, little)?,
                    8,
                )
            };
            let name = string_at(strings, name_at, MAX_LINKAGE_LABEL_BYTES, out)?;
            if id >= 2 && (need || index == 0) {
                let version = Version { name, file };
                result
                    .entry(id)
                    .and_modify(|previous| {
                        if *previous != Some(version) {
                            *previous = None;
                            out.gap(LinkageGap::Malformed);
                        }
                    })
                    .or_insert(Some(version));
            }
            if index + 1 < count {
                if next_aux < minimum_aux {
                    return None;
                }
                aux_offset = aux_offset.checked_add(next_aux as usize)?;
            } else if next_aux != 0 {
                return None;
            }
        }
        if next == 0 {
            return Some(());
        }
        if next < minimum || (next as usize) < aux_offset.checked_add(if need { 16 } else { 8 })? {
            return None;
        }
        offset = offset.checked_add(next as usize)?;
    }
}

fn elf_table<Elf: FileHeader<Endian = Endianness>>(
    out: &mut Builder,
    bytes: &[u8],
    info: &BinaryInfo,
    stubs: &[EngineStub<'_>],
) {
    let Ok(header) = Elf::parse(bytes) else {
        out.gap(LinkageGap::Malformed);
        return;
    };
    let Ok(endian) = header.endian() else {
        out.gap(LinkageGap::Malformed);
        return;
    };
    let machine = header.e_machine(endian);
    let Ok(sections) = header.sections(endian, bytes) else {
        out.gap(LinkageGap::Malformed);
        return;
    };
    let symbols = match sections.symbols(endian, bytes, elf::SHT_DYNSYM) {
        Ok(symbols) => symbols,
        Err(_) => {
            out.gap(LinkageGap::Malformed);
            return;
        }
    };
    // A static image without dynamic symbols declares no imports or exports.
    if symbols.is_empty() {
        return;
    }
    let Ok(strings) = sections
        .section(symbols.string_section())
        .and_then(|section| section.data(endian, bytes))
    else {
        out.gap(LinkageGap::Malformed);
        return;
    };
    let name = |symbol: &Elf::Sym, out: &mut Builder| {
        string_at(strings, symbol.st_name(endian), MAX_SYMBOL_RAW_BYTES, out)
    };
    let mut versym = &[][..];
    let mut version_names = BTreeMap::new();
    let mut versions_valid = true;
    for section in sections.iter() {
        if !out.scan_bytes(1, size_of::<Elf::SectionHeader>()) {
            break;
        }
        let kind = section.sh_type(endian);
        if !matches!(
            kind,
            elf::SHT_GNU_VERSYM | elf::SHT_GNU_VERNEED | elf::SHT_GNU_VERDEF
        ) {
            continue;
        }
        let Ok(data) = section.data(endian, bytes) else {
            out.gap(LinkageGap::Malformed);
            continue;
        };
        let linked = section.sh_link(endian) as usize;
        if kind == elf::SHT_GNU_VERSYM && linked == symbols.section().0 {
            if !versym.is_empty() || data.len() < symbols.len().saturating_mul(2) {
                out.gap(LinkageGap::Malformed);
                versions_valid = false;
            } else {
                versym = data;
            }
        } else if kind != elf::SHT_GNU_VERSYM && linked == symbols.string_section().0 {
            if data.len() > MAX_LINKAGE_SCAN_BYTES {
                out.gap(LinkageGap::ScanLimit);
                continue;
            }
            if versions(
                data,
                strings,
                endian == Endianness::Little,
                kind == elf::SHT_GNU_VERNEED,
                out,
                &mut version_names,
            )
            .is_none()
            {
                out.gap(LinkageGap::Malformed);
                versions_valid = false;
            }
        } else {
            out.gap(LinkageGap::Malformed);
            versions_valid = false;
        }
    }
    if !versions_valid {
        version_names.clear();
    }
    // Dynamic symbol index → import id, and each import name's declarations.
    let mut imported = BTreeMap::new();
    let mut names: BTreeMap<&[u8], (u32, usize)> = BTreeMap::new();
    for (index, symbol) in symbols.iter().enumerate().skip(1) {
        if !out.scan_bytes(1, size_of::<Elf::Sym>()) {
            break;
        }
        let Some(raw) = name(symbol, out) else {
            out.gap(LinkageGap::Malformed);
            continue;
        };
        let bind = symbol.st_bind();
        if raw.is_empty() || bind == elf::STB_LOCAL {
            continue;
        }
        let version_index = u16_at(versym, index * 2, endian == Endianness::Little).unwrap_or(1)
            & elf::VERSYM_VERSION;
        let version = version_names.get(&version_index).copied().flatten();
        if version_index >= 2 && version.is_none() {
            out.gap(LinkageGap::Malformed);
        }
        if symbol.st_shndx(endian) == elf::SHN_UNDEF {
            let library = version
                .and_then(|version| version.file)
                .and_then(|file| out.library(file));
            let id = out.import(ImportSpec {
                raw: Some(raw),
                ordinal: None,
                library,
                scope: None,
                version: version.map(|version| version.name),
                kind: ImportKind::Normal,
                weak: bind == elf::STB_WEAK,
                slot: None,
            });
            if let Some(id) = id {
                imported.insert(index as u32, id);
                names.entry(raw).or_insert((id, 0)).1 += 1;
            }
            continue;
        }
        let visible = matches!(
            symbol.st_visibility(),
            elf::STV_DEFAULT | elf::STV_PROTECTED
        );
        let exported = matches!(bind, elf::STB_GLOBAL | elf::STB_WEAK | elf::STB_GNU_UNIQUE);
        if !visible || !exported {
            continue;
        }
        let address: u64 = symbol.st_value(endian).into();
        let section = symbol.st_shndx(endian);
        let target = match symbol.st_type() {
            _ if section == elf::SHN_ABS || section == elf::SHN_COMMON => ExportTarget::Unresolved,
            elf::STT_FUNC => ExportTarget::Code { address },
            elf::STT_GNU_IFUNC => ExportTarget::Resolver { address },
            elf::STT_OBJECT | elf::STT_NOTYPE => ExportTarget::Data { address },
            elf::STT_TLS => ExportTarget::Unresolved,
            _ => continue,
        };
        out.export(ExportSpec {
            raw: Some(raw),
            ordinal: None,
            version: version.map(|version| version.name),
            target,
        });
    }
    // Every other declaration sharing an import's name makes its engine stub
    // ambiguous: the engine identifies a stub's slot only by symbol name.
    for (index, symbol) in symbols.iter().enumerate().skip(1) {
        if !out.scan_bytes(1, size_of::<Elf::Sym>()) {
            break;
        }
        if !imported.contains_key(&(index as u32))
            && let Some(entry) = name(symbol, out).and_then(|raw| names.get_mut(raw))
        {
            entry.1 += 1;
        }
    }
    // Slot → (import, lazy); `None` marks conflicting relocations.
    let mut slots: BTreeMap<u64, Option<(u32, bool)>> = BTreeMap::new();
    let mut record = |offset: u64, r_type: u32, sym: u32, out: &mut Builder| {
        let Some(lazy) = slot_relocation(machine, r_type) else {
            return;
        };
        let Some(&id) = imported.get(&sym) else {
            return;
        };
        if slots.len() >= MAX_IMPORTS + MAX_LINKAGE_LOCATIONS && !slots.contains_key(&offset) {
            out.gap(LinkageGap::LocationLimit);
            return;
        }
        slots
            .entry(offset)
            .and_modify(|existing| {
                if existing.is_some_and(|(other, _)| other != id) {
                    *existing = None;
                }
            })
            .or_insert(Some((id, lazy)));
    };
    'tables: for section in sections.iter() {
        if !out.scan_bytes(1, size_of::<Elf::SectionHeader>()) {
            break;
        }
        if section.sh_link(endian) as usize != symbols.section().0 {
            continue;
        }
        match (section.rel(endian, bytes), section.rela(endian, bytes)) {
            (Ok(Some((records, _))), _) => {
                for rel in records {
                    if !out.scan_bytes(1, size_of::<Elf::Rel>()) {
                        break 'tables;
                    }
                    record(
                        rel.r_offset(endian).into(),
                        rel.r_type(endian),
                        rel.r_sym(endian),
                        out,
                    );
                }
            }
            (_, Ok(Some((records, _)))) => {
                for rela in records {
                    if !out.scan_bytes(1, size_of::<Elf::Rela>()) {
                        break 'tables;
                    }
                    record(
                        rela.r_offset(endian).into(),
                        rela.r_type(endian, false),
                        rela.r_sym(endian, false),
                        out,
                    );
                }
            }
            (Err(_), _) | (_, Err(_)) => out.gap(LinkageGap::Malformed),
            _ => {}
        }
    }
    // Lazy PLT slots first, so they become the primary slot.
    let mut ordered: Vec<_> = slots
        .into_iter()
        .filter_map(|(slot, owner)| owner.map(|(id, lazy)| (id, !lazy, slot)))
        .collect();
    ordered.sort_unstable();
    let mut verified_slots = BTreeMap::new();
    for (id, _, slot) in ordered {
        verified_slots.insert(slot, id);
        out.location(id, LocationKind::Slot, slot);
    }
    if out.gaps.contains(&LinkageGap::ScanLimit) {
        return;
    }
    let mut stub_owners: Vec<_> = stubs
        .iter()
        .filter_map(|stub| {
            let &(id, declarations) = names.get(stub.raw.as_bytes())?;
            let slot = stub_slot(bytes, info, stub.address)?;
            let matches = verified_slots.get(&slot) == Some(&id);
            (declarations == 1 && matches).then_some((id, stub.address))
        })
        .collect();
    stub_owners.sort_unstable();
    for (id, address) in stub_owners {
        out.location(id, LocationKind::Stub, address);
    }
}

fn macho_table<Mach: MachHeader<Endian = Endianness>>(
    out: &mut Builder,
    bytes: &[u8],
    info: &BinaryInfo,
) {
    let malformed = |out: &mut Builder| out.gap(LinkageGap::Malformed);
    let Ok(header) = Mach::parse(bytes, 0) else {
        return malformed(out);
    };
    let Ok(endian) = header.endian() else {
        return malformed(out);
    };
    let two_level = header.flags(endian) & macho::MH_TWOLEVEL != 0;
    let pointer = crate::architecture::properties(&info.architecture).map_or(0, |p| p.0);
    let Ok(mut commands) = header.load_commands(endian, bytes, 0) else {
        return malformed(out);
    };
    // Dependency ordinals count every library command, including omitted names.
    let mut dylibs: Vec<Option<u32>> = Vec::new();
    let mut symtab = None;
    let mut dysymtab = None;
    let mut indirect_sections = Vec::new();
    let mut declared_sections = Vec::new();
    loop {
        let command = match commands.next() {
            Ok(Some(command)) => command,
            Ok(None) => break,
            Err(_) => {
                malformed(out);
                break;
            }
        };
        if !out.scan_bytes(1, command.raw_data().len()) {
            return;
        }
        match command.variant() {
            Ok(object::read::macho::LoadCommandVariant::Dylib(dylib)) => {
                let library = command
                    .raw_data()
                    .get(dylib.dylib.name.offset.get(endian) as usize..)
                    .and_then(|bytes| out.c_string(bytes, MAX_LINKAGE_LABEL_BYTES))
                    .and_then(|name| out.library(name));
                if library.is_none() {
                    malformed(out);
                }
                if dylibs.len() < 253 {
                    dylibs.push(library);
                } else {
                    out.gap(LinkageGap::LibraryLimit);
                }
            }
            Ok(object::read::macho::LoadCommandVariant::Symtab(command)) => symtab = Some(command),
            Ok(object::read::macho::LoadCommandVariant::Dysymtab(command)) => {
                dysymtab = Some(command)
            }
            Ok(object::read::macho::LoadCommandVariant::Segment64(segment, data)) => {
                match segment.sections(endian, data) {
                    Ok(sections) => {
                        for section in sections {
                            if !out.scan(1) {
                                return;
                            }
                            if declared_sections.len() >= crate::model::MAX_SECTIONS {
                                out.gap(LinkageGap::ScanLimit);
                                return;
                            }
                            declared_sections
                                .push((section.addr.get(endian), section.size.get(endian)));
                            let kind = section.flags.get(endian) & macho::SECTION_TYPE;
                            let entry = match kind {
                                macho::S_NON_LAZY_SYMBOL_POINTERS
                                | macho::S_LAZY_SYMBOL_POINTERS => pointer,
                                macho::S_SYMBOL_STUBS => u64::from(section.reserved2.get(endian)),
                                _ => continue,
                            };
                            if indirect_sections.len() >= crate::model::MAX_SECTIONS {
                                out.gap(LinkageGap::ScanLimit);
                                return;
                            }
                            indirect_sections.push((
                                kind == macho::S_SYMBOL_STUBS,
                                section.addr.get(endian),
                                section.size.get(endian),
                                entry,
                                section.reserved1.get(endian),
                            ));
                        }
                    }
                    Err(_) => malformed(out),
                }
            }
            Ok(object::read::macho::LoadCommandVariant::Segment32(segment, data)) => {
                match segment.sections(endian, data) {
                    Ok(sections) => {
                        for section in sections {
                            if !out.scan(1) {
                                return;
                            }
                            if declared_sections.len() >= crate::model::MAX_SECTIONS {
                                out.gap(LinkageGap::ScanLimit);
                                return;
                            }
                            declared_sections.push((
                                u64::from(section.addr.get(endian)),
                                u64::from(section.size.get(endian)),
                            ));
                            let kind = section.flags.get(endian) & macho::SECTION_TYPE;
                            let entry = match kind {
                                macho::S_NON_LAZY_SYMBOL_POINTERS
                                | macho::S_LAZY_SYMBOL_POINTERS => pointer,
                                macho::S_SYMBOL_STUBS => u64::from(section.reserved2.get(endian)),
                                _ => continue,
                            };
                            if indirect_sections.len() >= crate::model::MAX_SECTIONS {
                                out.gap(LinkageGap::ScanLimit);
                                return;
                            }
                            indirect_sections.push((
                                kind == macho::S_SYMBOL_STUBS,
                                u64::from(section.addr.get(endian)),
                                u64::from(section.size.get(endian)),
                                entry,
                                section.reserved1.get(endian),
                            ));
                        }
                    }
                    Err(_) => malformed(out),
                }
            }
            Ok(object::read::macho::LoadCommandVariant::DyldInfo(dyld)) => {
                if dyld.export_size.get(endian) != 0 {
                    out.gap(LinkageGap::ExportTrie);
                }
                if dyld.bind_size.get(endian) != 0
                    || dyld.weak_bind_size.get(endian) != 0
                    || dyld.lazy_bind_size.get(endian) != 0
                {
                    out.gap(LinkageGap::BindOpcodes);
                }
            }
            Ok(_) => match command.cmd() {
                macho::LC_DYLD_EXPORTS_TRIE => out.gap(LinkageGap::ExportTrie),
                macho::LC_DYLD_CHAINED_FIXUPS => out.gap(LinkageGap::ChainedFixups),
                _ => {}
            },
            Err(_) => {
                if matches!(
                    command.cmd(),
                    macho::LC_LOAD_DYLIB
                        | macho::LC_LOAD_WEAK_DYLIB
                        | macho::LC_REEXPORT_DYLIB
                        | macho::LC_LAZY_LOAD_DYLIB
                        | macho::LC_LOAD_UPWARD_DYLIB
                ) && dylibs.len() < 253
                {
                    dylibs.push(None);
                }
                malformed(out);
            }
        }
    }
    let Some(symtab) = symtab else {
        return;
    };
    let Ok(symbols) = symtab.symbols::<Mach, _>(endian, bytes) else {
        return malformed(out);
    };
    let start = symtab.stroff.get(endian) as usize;
    let Some(strings) = start
        .checked_add(symtab.strsize.get(endian) as usize)
        .and_then(|end| bytes.get(start..end))
    else {
        return malformed(out);
    };
    let mut imported = BTreeMap::new();
    for (index, symbol) in symbols.iter().enumerate() {
        if !out.scan_bytes(1, size_of::<Mach::Nlist>()) {
            break;
        }
        let kind = symbol.n_type();
        if kind & macho::N_STAB != 0 || kind & macho::N_EXT == 0 {
            continue;
        }
        let Some(raw) = string_at(strings, symbol.n_strx(endian), MAX_SYMBOL_RAW_BYTES, out) else {
            malformed(out);
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let address = symbol.n_value(endian).into();
        match kind & macho::N_TYPE {
            // A nonzero undefined value is a common definition, not an import.
            macho::N_UNDF if address == 0 => {
                let description = symbol.n_desc(endian);
                let (library, scope) = if !two_level {
                    (None, Some(ImportScope::FlatNamespace))
                } else {
                    match (description >> 8) as u8 {
                        macho::SELF_LIBRARY_ORDINAL => (None, Some(ImportScope::SelfImage)),
                        macho::DYNAMIC_LOOKUP_ORDINAL => (None, Some(ImportScope::DynamicLookup)),
                        macho::EXECUTABLE_ORDINAL => (None, Some(ImportScope::MainExecutable)),
                        ordinal => match dylibs.get(usize::from(ordinal) - 1) {
                            Some(library) => (*library, None),
                            // Never wrap into an unrelated dependency.
                            None => {
                                malformed(out);
                                (None, None)
                            }
                        },
                    }
                };
                if let Some(id) = out.import(ImportSpec {
                    raw: Some(raw),
                    ordinal: None,
                    library,
                    scope,
                    version: None,
                    kind: ImportKind::Normal,
                    weak: description & macho::N_WEAK_REF != 0,
                    slot: None,
                }) {
                    imported.insert(index as u32, id);
                }
            }
            macho::N_SECT if kind & macho::N_PEXT == 0 => {
                let valid_section = symbol
                    .n_sect()
                    .checked_sub(1)
                    .and_then(|index| declared_sections.get(index as usize))
                    .is_some_and(|(base, size)| {
                        address
                            .checked_sub(*base)
                            .is_some_and(|offset| offset < *size)
                    });
                if !valid_section {
                    malformed(out);
                }
                out.export(ExportSpec {
                    raw: Some(raw),
                    ordinal: None,
                    version: None,
                    target: if valid_section {
                        ExportTarget::Code { address }
                    } else {
                        ExportTarget::Unresolved
                    },
                });
            }
            _ => {}
        }
    }
    let Some(dysymtab) = dysymtab.filter(|_| !indirect_sections.is_empty()) else {
        return;
    };
    let start = u64::from(dysymtab.indirectsymoff.get(endian));
    let entries = dysymtab.nindirectsyms.get(endian) as usize;
    let Some(table) = usize::try_from(start)
        .ok()
        .and_then(|start| bytes.get(start..start.checked_add(entries.checked_mul(4)?)?))
    else {
        return malformed(out);
    };
    let entry = |index: u64| -> Option<u32> {
        let at = usize::try_from(index).ok()?.checked_mul(4)?;
        Some(u32::from_le_bytes(table.get(at..at + 4)?.try_into().ok()?))
    };
    let little = endian == Endianness::Little;
    for (stub, address, size, width, first) in indirect_sections {
        if width == 0 || !little || !size.is_multiple_of(width) {
            malformed(out);
            continue;
        }
        let count = size / width;
        if !out.scan_bytes(usize::try_from(count).unwrap_or(usize::MAX), 4) {
            break;
        }
        for index in 0..count {
            let Some(symbol) = u64::from(first).checked_add(index).and_then(entry) else {
                malformed(out);
                break;
            };
            if symbol & (macho::INDIRECT_SYMBOL_LOCAL | macho::INDIRECT_SYMBOL_ABS) != 0 {
                continue;
            }
            let (Some(&id), Some(location)) = (
                imported.get(&symbol),
                index
                    .checked_mul(width)
                    .and_then(|offset| address.checked_add(offset)),
            ) else {
                continue;
            };
            let kind = if stub {
                LocationKind::Stub
            } else {
                LocationKind::Slot
            };
            out.location(id, kind, location);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BinaryInfo, SectionInfo};

    fn info(format: &str, architecture: &str, sections: Vec<SectionInfo>) -> BinaryInfo {
        BinaryInfo {
            path: "fixture".into(),
            architecture: architecture.into(),
            format: format.into(),
            entry: 0,
            file_len: 0,
            sha256: "0".repeat(64),
            source_identity: None,
            sections,
            functions: Vec::new(),
            functions_truncated: false,
            warnings: Vec::new(),
        }
    }

    fn section(name: &str, address: u64, size: u64, offset: u64, executable: bool) -> SectionInfo {
        SectionInfo {
            name: name.into(),
            address,
            size,
            file_offset: offset,
            file_size: size,
            executable,
        }
    }

    fn records(table: &LinkageTable) -> (Vec<Library>, Vec<Import>, Vec<Export>, Vec<Location>) {
        let mut out = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for record in table.records() {
            match record.clone() {
                LinkageRecord::Library(library) => out.0.push(library),
                LinkageRecord::Import(import) => out.1.push(import),
                LinkageRecord::Export(export) => out.2.push(export),
                LinkageRecord::Location(location) => out.3.push(location),
            }
        }
        out
    }

    fn named<'a>(imports: &'a [Import], raw: &str) -> &'a Import {
        imports
            .iter()
            .find(|import| import.raw.as_deref() == Some(raw))
            .unwrap_or_else(|| panic!("{raw} missing"))
    }

    #[test]
    fn builder_bounds_identities_slots_and_text_without_truncating() {
        let info = info(
            "PE",
            "x86-64",
            vec![
                section(".text", 0x1000, 0x1000, 0x400, true),
                section(".data", 0x2000, 0x1000, 0x1400, false),
            ],
        );
        let mut builder = Builder::default();
        let library = builder.library(b"KERNEL32.dll");
        assert_eq!(builder.library(b"KERNEL32.dll"), library);
        assert_eq!(builder.library(b"bad\nname"), None);
        let spec = |raw: Option<&'static [u8]>, ordinal, slot| ImportSpec {
            raw,
            ordinal,
            library,
            scope: Some(ImportScope::SelfImage),
            version: None,
            kind: ImportKind::Normal,
            weak: false,
            slot,
        };
        let first = builder.import(spec(Some(b"Exit"), None, Some(0x2000)));
        assert!(first.is_some());
        // A second declaration of the same slot is ambiguous and omitted.
        assert!(
            builder
                .import(spec(Some(b"Other"), None, Some(0x2000)))
                .is_none()
        );
        // An unrepresentable name keeps only its ordinal identity.
        let ordinal = builder
            .import(spec(Some(b"\xff"), Some(7), Some(0x2008)))
            .unwrap();
        assert!(
            builder
                .import(spec(Some(b"\xff"), None, Some(0x2010)))
                .is_none()
        );
        // Slots must be pointer-wide and file-backed in the shared rules.
        builder.import(spec(Some(b"Edge"), None, Some(0x2ffc)));
        builder.location(first.unwrap(), LocationKind::Slot, 0x2018);
        builder.location(first.unwrap(), LocationKind::Stub, 0x1001);
        builder.export(ExportSpec {
            raw: Some(b"?foo@demo@@YAXXZ"),
            ordinal: Some(1),
            version: None,
            target: ExportTarget::Code { address: 0x2100 },
        });
        builder.export(ExportSpec {
            raw: None,
            ordinal: Some(2),
            version: None,
            target: ExportTarget::Data { address: 0x1010 },
        });
        builder.export(ExportSpec {
            raw: Some(b"far"),
            ordinal: None,
            version: None,
            target: ExportTarget::Data { address: 0x9000 },
        });
        let table = builder.finish(&info, SymbolFormat::Pe);
        let (libraries, imports, exports, locations) = records(&table);
        assert_eq!(libraries.len(), 1);
        assert_eq!(imports.len(), 3);
        assert_eq!(imports[ordinal as usize].raw, None);
        assert_eq!(imports[ordinal as usize].ordinal, Some(7));
        assert_eq!(imports[0].scope, None, "a library excludes a scope");
        assert_eq!(named(&imports, "Edge").slot, None);
        assert_eq!(imports[0].stub, Some(0x1001));
        assert_eq!(imports[0].slot, Some(0x2018));
        assert!(locations.is_empty());
        assert_eq!(exports[0].display.as_deref(), Some("demo::foo"));
        assert_eq!(exports[0].target, ExportTarget::Data { address: 0x2100 });
        assert_eq!(exports[1].target, ExportTarget::Code { address: 0x1010 });
        assert_eq!(exports[2].target, ExportTarget::Unresolved);
        assert!(table.summary().gaps.contains(&LinkageGap::Malformed));
        // The table passes the desktop's own validation.
        let mut fetch = LinkageFetch::new(table.summary().clone(), &info.sha256).unwrap();
        fetch.accept(table.page(0).unwrap(), &info).unwrap();
        assert!(fetch.finish().is_some());
    }

    #[test]
    fn caps_mark_the_table_partial() {
        let info = info("PE", "x86-64", Vec::new());
        let mut builder = Builder::default();
        for index in 0..=MAX_IMPORTS {
            builder.import(ImportSpec {
                raw: None,
                ordinal: Some(index as u32),
                library: None,
                scope: None,
                version: None,
                kind: ImportKind::Delay,
                weak: false,
                slot: None,
            });
        }
        assert!(builder.scan(MAX_LINKAGE_SCAN - 1));
        assert!(!builder.scan(2));
        let table = builder.finish(&info, SymbolFormat::Pe);
        assert_eq!(table.summary().imports, MAX_IMPORTS);
        assert_eq!(
            table.summary().gaps,
            [LinkageGap::ImportLimit, LinkageGap::ScanLimit]
        );
        let mut builder = Builder::default();
        let long = vec![b'a'; MAX_SYMBOL_RAW_BYTES];
        let mut added = 0;
        while builder
            .export(ExportSpec {
                raw: Some(&long),
                ordinal: None,
                version: None,
                target: ExportTarget::Unresolved,
            })
            .is_some()
        {
            added += 1;
        }
        assert_eq!(added, MAX_LINKAGE_TEXT_BYTES / MAX_SYMBOL_RAW_BYTES);
        assert!(builder.gaps.contains(&LinkageGap::TextLimit));
    }

    // Original synthetic ELF64 image: dynamic symbols, a version-need table,
    // and JUMP_SLOT/GLOB_DAT relocations. Offsets equal virtual addresses.
    struct ElfImage {
        bytes: Vec<u8>,
        info: BinaryInfo,
    }

    fn put(bytes: &mut [u8], at: usize, value: &[u8]) {
        bytes[at..at + value.len()].copy_from_slice(value);
    }

    fn elf_image(conflict: bool) -> ElfImage {
        let mut b = vec![0u8; 0x1000];
        put(&mut b, 0, b"\x7fELF\x02\x01\x01");
        put(&mut b, 16, &3u16.to_le_bytes()); // ET_DYN
        put(&mut b, 18, &elf::EM_X86_64.to_le_bytes());
        put(&mut b, 20, &1u32.to_le_bytes());
        put(&mut b, 52, &64u16.to_le_bytes());
        put(&mut b, 58, &64u16.to_le_bytes()); // e_shentsize
        let shoff = 0xc00usize;
        put(&mut b, 40, &(shoff as u64).to_le_bytes());
        let sections = 8u16;
        put(&mut b, 60, &sections.to_le_bytes());
        put(&mut b, 62, &1u16.to_le_bytes()); // e_shstrndx
        // String tables.
        let shstr = b"\0.shstrtab\0.dynstr\0.dynsym\0.gnu.version\0.gnu.version_r\0.rela.plt\0.got\0.text\0";
        put(&mut b, 0x100, shstr);
        let dynstr = b"\0puts\0weak_hook\0exported\0dup\0libc.so.6\0GLIBC_2.2.5\0table\0";
        put(&mut b, 0x200, dynstr);
        let at = |s: &[u8], name: &str| {
            s.windows(name.len() + 1)
                .position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0)
                .unwrap() as u32
        };
        // .dynsym at 0x300: null, puts (UNDEF, v2), weak_hook (UNDEF weak),
        // exported (FUNC .text), dup (UNDEF), dup (FUNC defined), table (OBJECT).
        let symbol =
            |b: &mut Vec<u8>, index: usize, name: u32, info: u8, shndx: u16, value: u64| {
                let o = 0x300 + index * 24;
                put(b, o, &name.to_le_bytes());
                b[o + 4] = info;
                put(b, o + 6, &shndx.to_le_bytes());
                put(b, o + 8, &value.to_le_bytes());
            };
        symbol(&mut b, 1, at(dynstr, "puts"), 0x12, 0, 0);
        symbol(&mut b, 2, at(dynstr, "weak_hook"), 0x22, 0, 0);
        symbol(&mut b, 3, at(dynstr, "exported"), 0x12, 7, 0x800);
        symbol(&mut b, 4, at(dynstr, "dup"), 0x12, 0, 0);
        symbol(&mut b, 5, at(dynstr, "dup"), 0x12, 7, 0x810);
        symbol(&mut b, 6, at(dynstr, "table"), 0x11, 6, 0x908);
        // .gnu.version at 0x420: puts uses version index 2.
        // The original fixture contains conventional RIP-relative PLT jumps.
        put(&mut b, 0x840, &[0xff, 0x25, 0xba, 0, 0, 0]);
        put(&mut b, 0x850, &[0xff, 0x25, 0xca, 0, 0, 0]);
        for index in 2..7 {
            put(&mut b, 0x420 + index * 2, &1u16.to_le_bytes());
        }
        put(&mut b, 0x420 + 2, &2u16.to_le_bytes());
        // .gnu.version_r at 0x440: one Verneed with one Vernaux.
        put(&mut b, 0x440, &1u16.to_le_bytes());
        put(&mut b, 0x442, &1u16.to_le_bytes());
        put(&mut b, 0x444, &at(dynstr, "libc.so.6").to_le_bytes());
        put(&mut b, 0x448, &16u32.to_le_bytes());
        put(&mut b, 0x44c, &0u32.to_le_bytes());
        put(&mut b, 0x450 + 6, &2u16.to_le_bytes()); // vna_other
        put(&mut b, 0x450 + 8, &at(dynstr, "GLIBC_2.2.5").to_le_bytes());
        // .rela.plt at 0x480: JUMP_SLOT puts@0x900, GLOB_DAT puts@0x910,
        // JUMP_SLOT weak_hook@0x918 (and a conflicting dup at the same slot).
        let rela = |b: &mut Vec<u8>, index: usize, offset: u64, symbol: u64, kind: u64| {
            let o = 0x480 + index * 24;
            put(b, o, &offset.to_le_bytes());
            put(b, o + 8, &((symbol << 32) | kind).to_le_bytes());
        };
        rela(&mut b, 0, 0x900, 1, u64::from(elf::R_X86_64_JUMP_SLOT));
        rela(&mut b, 1, 0x910, 1, u64::from(elf::R_X86_64_GLOB_DAT));
        rela(&mut b, 2, 0x918, 2, u64::from(elf::R_X86_64_JUMP_SLOT));
        rela(
            &mut b,
            3,
            if conflict { 0x918 } else { 0x920 },
            4,
            u64::from(elf::R_X86_64_GLOB_DAT),
        );
        // Section headers.
        let header = |b: &mut Vec<u8>,
                      index: usize,
                      name: &str,
                      kind: u32,
                      flags: u64,
                      offset: u64,
                      size: u64,
                      link: u32,
                      info: u32,
                      entsize: u64| {
            let o = shoff + index * 64;
            put(b, o, &at(shstr, name).to_le_bytes());
            put(b, o + 4, &kind.to_le_bytes());
            put(b, o + 8, &flags.to_le_bytes());
            put(b, o + 16, &offset.to_le_bytes());
            put(b, o + 24, &offset.to_le_bytes());
            put(b, o + 32, &size.to_le_bytes());
            put(b, o + 40, &link.to_le_bytes());
            put(b, o + 44, &info.to_le_bytes());
            put(b, o + 48, &8u64.to_le_bytes());
            put(b, o + 56, &entsize.to_le_bytes());
        };
        header(
            &mut b,
            1,
            ".shstrtab",
            elf::SHT_STRTAB,
            0,
            0x100,
            shstr.len() as u64,
            0,
            0,
            0,
        );
        header(
            &mut b,
            2,
            ".dynstr",
            elf::SHT_STRTAB,
            2,
            0x200,
            dynstr.len() as u64,
            0,
            0,
            0,
        );
        header(
            &mut b,
            3,
            ".dynsym",
            elf::SHT_DYNSYM,
            2,
            0x300,
            7 * 24,
            2,
            1,
            24,
        );
        header(
            &mut b,
            4,
            ".gnu.version",
            elf::SHT_GNU_VERSYM,
            2,
            0x420,
            14,
            3,
            0,
            2,
        );
        header(
            &mut b,
            5,
            ".gnu.version_r",
            elf::SHT_GNU_VERNEED,
            2,
            0x440,
            0x20,
            2,
            1,
            0,
        );
        header(
            &mut b,
            6,
            ".got",
            elf::SHT_PROGBITS,
            3,
            0x900,
            0x40,
            0,
            0,
            8,
        );
        header(
            &mut b,
            7,
            ".text",
            elf::SHT_PROGBITS,
            6,
            0x800,
            0x100,
            0,
            0,
            0,
        );
        // .rela.plt replaces the unused null-adjacent slot 0's neighbor.
        header(&mut b, 0, "", 0, 0, 0, 0, 0, 0, 0);
        let mut extra = b.clone();
        extra.resize(0x1000 + 64, 0);
        // Append a ninth header for .rela.plt beyond the table end.
        let _ = extra;
        put(&mut b, 60, &(sections + 1).to_le_bytes());
        header(
            &mut b,
            8,
            ".rela.plt",
            elf::SHT_RELA,
            2,
            0x480,
            4 * 24,
            3,
            0,
            24,
        );
        let info = info(
            "ELF",
            "x86-64",
            vec![
                section(".text", 0x800, 0x100, 0x800, true),
                section(".got", 0x900, 0x40, 0x900, false),
            ],
        );
        ElfImage { bytes: b, info }
    }

    #[test]
    fn elf_versions_slots_weak_and_unambiguous_engine_stubs() {
        let image = elf_image(false);
        let stubs = [
            EngineStub {
                address: 0x840,
                raw: "puts",
            },
            EngineStub {
                address: 0x850,
                raw: "dup",
            },
            EngineStub {
                address: 0x860,
                raw: "unknown",
            },
        ];
        let table = table(&image.bytes, &image.info, None, &stubs);
        let (libraries, imports, exports, locations) = records(&table);
        assert_eq!(libraries[0].name, "libc.so.6");
        let puts = named(&imports, "puts");
        assert_eq!(puts.library, Some(0));
        assert_eq!(puts.version.as_deref(), Some("GLIBC_2.2.5"));
        assert_eq!((puts.slot, puts.stub), (Some(0x900), Some(0x840)));
        assert_eq!(
            locations,
            [Location {
                import: puts.id,
                kind: LocationKind::Slot,
                address: 0x910
            }]
        );
        let weak = named(&imports, "weak_hook");
        assert!(weak.weak);
        assert_eq!(weak.library, None, "no version need: unknown library");
        assert_eq!(weak.slot, Some(0x918));
        // `dup` is also defined, so the engine stub's slot is ambiguous.
        let dup = named(&imports, "dup");
        assert_eq!((dup.slot, dup.stub), (Some(0x920), None));
        let exported: Vec<_> = exports
            .iter()
            .map(|e| (e.raw.as_deref().unwrap(), e.target.clone()))
            .collect();
        assert_eq!(
            exported,
            [
                ("exported", ExportTarget::Code { address: 0x800 }),
                ("dup", ExportTarget::Code { address: 0x810 }),
                ("table", ExportTarget::Data { address: 0x908 }),
            ]
        );
        assert!(
            table.summary().gaps.is_empty(),
            "{:?}",
            table.summary().gaps
        );
    }

    #[test]
    fn conflicting_elf_relocations_establish_no_slot() {
        let image = elf_image(true);
        let table = table(&image.bytes, &image.info, None, &[]);
        let (_, imports, _, _) = records(&table);
        assert_eq!(named(&imports, "weak_hook").slot, None);
        assert_eq!(named(&imports, "dup").slot, None);
        assert_eq!(named(&imports, "puts").slot, Some(0x900));
        for end in (0..image.bytes.len()).step_by(61) {
            let _ = super::table(&image.bytes[..end], &image.info, None, &[]);
        }
    }

    #[test]
    fn elf_malformed_versions_and_wrong_stub_slots_remain_unresolved() {
        let mut image = elf_image(false);
        // A matching raw name with a jump to another symbol's slot proves no link.
        put(&mut image.bytes, 0x842, &0xd2u32.to_le_bytes());
        let stubs = [EngineStub {
            address: 0x840,
            raw: "puts",
        }];
        let (_, imports, _, _) = records(&table(&image.bytes, &image.info, None, &stubs));
        assert_eq!(named(&imports, "puts").stub, None);
        // A forward chain that points back into its own header is malformed.
        put(&mut image.bytes, 0x44c, &1u32.to_le_bytes());
        let table = table(&image.bytes, &image.info, None, &[]);
        let (_, imports, _, _) = records(&table);
        assert_eq!(named(&imports, "puts").library, None);
        assert!(table.summary().gaps.contains(&LinkageGap::Malformed));

        let mut builder = Builder::default();
        assert!(builder.scan_bytes(1, MAX_LINKAGE_SCAN_BYTES));
        assert!(!builder.scan_bytes(1, 1));
        assert!(builder.gaps.contains(&LinkageGap::ScanLimit));
    }

    // Original synthetic arm64 Mach-O: two dylibs, special and invalid
    // ordinals, a __got pointer section, a __stubs section and exports.
    fn macho_image(two_level: bool) -> (Vec<u8>, BinaryInfo) {
        let mut b = vec![0u8; 0x2000];
        let p32 = |b: &mut Vec<u8>, at: usize, v: u32| put(b, at, &v.to_le_bytes());
        let p64 = |b: &mut Vec<u8>, at: usize, v: u64| put(b, at, &v.to_le_bytes());
        let name16 = |b: &mut Vec<u8>, at: usize, v: &str| put(b, at, v.as_bytes());
        p32(&mut b, 0, 0xfeedfacf);
        p32(&mut b, 4, 0x100000c);
        p32(&mut b, 12, 2);
        p32(&mut b, 24, if two_level { macho::MH_TWOLEVEL } else { 0 });
        let mut at = 32;
        let mut commands = 0;
        // LC_SEGMENT_64 __TEXT: __text and __stubs (12-byte stubs).
        p32(&mut b, at, macho::LC_SEGMENT_64);
        p32(&mut b, at + 4, 72 + 2 * 80);
        name16(&mut b, at + 8, "__TEXT");
        p32(&mut b, at + 64, 2);
        let s = at + 72;
        name16(&mut b, s, "__text");
        name16(&mut b, s + 16, "__TEXT");
        p64(&mut b, s + 32, 0x1_0000_1000);
        p64(&mut b, s + 40, 0x100);
        p32(&mut b, s + 48, 0x1000);
        let s = s + 80;
        name16(&mut b, s, "__stubs");
        name16(&mut b, s + 16, "__TEXT");
        p64(&mut b, s + 32, 0x1_0000_1100);
        p64(&mut b, s + 40, 24);
        p32(&mut b, s + 48, 0x1100);
        p32(&mut b, s + 64, macho::S_SYMBOL_STUBS);
        p32(&mut b, s + 68, 3);
        p32(&mut b, s + 72, 12);
        at += 72 + 2 * 80;
        commands += 1;
        // LC_SEGMENT_64 __DATA_CONST: __got with three slots.
        p32(&mut b, at, macho::LC_SEGMENT_64);
        p32(&mut b, at + 4, 72 + 80);
        name16(&mut b, at + 8, "__DATA_CONST");
        p32(&mut b, at + 64, 1);
        let s = at + 72;
        name16(&mut b, s, "__got");
        name16(&mut b, s + 16, "__DATA_CONST");
        p64(&mut b, s + 32, 0x1_0000_1200);
        p64(&mut b, s + 40, 24);
        p32(&mut b, s + 48, 0x1200);
        p32(&mut b, s + 64, macho::S_NON_LAZY_SYMBOL_POINTERS);
        p32(&mut b, s + 68, 0);
        at += 72 + 80;
        commands += 1;
        for path in ["/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"] {
            p32(&mut b, at, macho::LC_LOAD_DYLIB);
            p32(&mut b, at + 4, 56);
            p32(&mut b, at + 8, 24);
            put(&mut b, at + 24, path.as_bytes());
            at += 56;
            commands += 1;
        }
        // LC_SYMTAB at 0x1800 with strings at 0x1900.
        p32(&mut b, at, macho::LC_SYMTAB);
        p32(&mut b, at + 4, 24);
        p32(&mut b, at + 8, 0x1800);
        p32(&mut b, at + 12, 6);
        p32(&mut b, at + 16, 0x1900);
        p32(&mut b, at + 20, 0x100);
        at += 24;
        commands += 1;
        // LC_DYSYMTAB with five indirect entries at 0x1a00.
        p32(&mut b, at, macho::LC_DYSYMTAB);
        p32(&mut b, at + 4, 80);
        p32(&mut b, at + 56, 0x1a00);
        p32(&mut b, at + 60, 5);
        at += 80;
        commands += 1;
        p32(&mut b, 16, commands);
        p32(&mut b, 20, (at - 32) as u32);
        let strings = b"\0_puts\0__ZN4demo3fooEv\0_lookup\0_bad\0_main\0_hidden\0";
        put(&mut b, 0x1900, strings);
        let offset = |name: &str| {
            strings
                .windows(name.len() + 1)
                .position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0)
                .unwrap() as u32
        };
        let nlist = |b: &mut Vec<u8>, index: usize, name: &str, kind: u8, desc: u16, value: u64| {
            let o = 0x1800 + index * 16;
            put(b, o, &offset(name).to_le_bytes());
            b[o + 4] = kind;
            if kind & macho::N_TYPE == macho::N_SECT {
                b[o + 5] = 1;
            }
            put(b, o + 6, &desc.to_le_bytes());
            put(b, o + 8, &value.to_le_bytes());
        };
        nlist(&mut b, 0, "_puts", macho::N_EXT, 1 << 8, 0);
        nlist(
            &mut b,
            1,
            "__ZN4demo3fooEv",
            macho::N_EXT,
            (2 << 8) | macho::N_WEAK_REF,
            0,
        );
        nlist(&mut b, 2, "_lookup", macho::N_EXT, 0xfe << 8, 0);
        nlist(&mut b, 3, "_bad", macho::N_EXT, 9 << 8, 0);
        nlist(
            &mut b,
            4,
            "_main",
            macho::N_EXT | macho::N_SECT,
            0,
            0x1_0000_1000,
        );
        nlist(
            &mut b,
            5,
            "_hidden",
            macho::N_EXT | macho::N_PEXT | macho::N_SECT,
            0,
            0x1_0000_1010,
        );
        // Stubs: _puts, foo. Slots: _puts, local, _lookup.
        for (index, symbol) in [0u32, macho::INDIRECT_SYMBOL_LOCAL, 2, 0, 1]
            .into_iter()
            .enumerate()
        {
            p32(&mut b, 0x1a00 + index * 4, symbol);
        }
        let info = info(
            "Mach-O",
            "AArch64",
            vec![
                section("__text", 0x1_0000_1000, 0x100, 0x1000, true),
                section("__stubs", 0x1_0000_1100, 24, 0x1100, true),
                section("__got", 0x1_0000_1200, 24, 0x1200, false),
            ],
        );
        (b, info)
    }

    #[test]
    fn macho_ordinals_special_scopes_and_indirect_locations() {
        let (bytes, info) = macho_image(true);
        let table = table(&bytes, &info, None, &[]);
        let (libraries, imports, exports, locations) = records(&table);
        let names: Vec<_> = libraries.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            names,
            ["/usr/lib/libSystem.B.dylib", "/usr/lib/libc++.1.dylib"]
        );
        let puts = named(&imports, "_puts");
        assert_eq!(puts.library, Some(0));
        assert_eq!(
            (puts.stub, puts.slot),
            (Some(0x1_0000_1100), Some(0x1_0000_1200))
        );
        let foo = named(&imports, "__ZN4demo3fooEv");
        assert_eq!((foo.library, foo.weak), (Some(1), true));
        assert_eq!(foo.display.as_deref(), Some("demo::foo"));
        assert_eq!(foo.stub, Some(0x1_0000_110c));
        let lookup = named(&imports, "_lookup");
        assert_eq!(lookup.scope, Some(ImportScope::DynamicLookup));
        assert_eq!(lookup.slot, Some(0x1_0000_1210));
        // An ordinal past the dependency list never wraps into a library.
        let bad = named(&imports, "_bad");
        assert_eq!((bad.library, bad.scope), (None, None));
        assert!(locations.is_empty());
        assert_eq!(exports.len(), 1, "private externs are not exported");
        assert_eq!(
            exports[0].target,
            ExportTarget::Code {
                address: 0x1_0000_1000
            }
        );
        assert_eq!(table.summary().gaps, [LinkageGap::Malformed]);
        let (bytes, info) = macho_image(false);
        let (_, imports, _, _) = records(&super::table(&bytes, &info, None, &[]));
        assert!(
            imports
                .iter()
                .all(|import| import.scope == Some(ImportScope::FlatNamespace))
        );
        for end in (0..bytes.len()).step_by(53) {
            let _ = super::table(&bytes[..end], &info, None, &[]);
        }
    }
}
