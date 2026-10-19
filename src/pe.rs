//! Bounded, file-backed PE metadata recovery. This does not execute or decode code.
use std::collections::BTreeMap;

use crate::model::{MAX_FUNCTIONS, SectionInfo};

mod arm64;

pub(crate) const MAX_IMPORTS: usize = 10_000;
const MAX_TABLE_ENTRIES: u32 = 500_000;
const MAX_DIRECTORY_BYTES: u32 = 8 * 1024 * 1024;
pub(crate) const MAX_NAME_BYTES: usize = 256;

#[derive(Default)]
pub(crate) struct PeMetadata {
    pub functions: BTreeMap<u64, String>,
    pub imports: BTreeMap<u64, String>,
    pub function_ranges: Vec<(u64, u64)>,
    pub functions_truncated: bool,
    pub warnings: Vec<String>,
}

impl PeMetadata {
    fn warn(&mut self, text: &str) {
        if !self.warnings.iter().any(|old| old == text) {
            self.warnings.push(text.to_owned());
        }
    }

    fn function(&mut self, address: u64, name: String) {
        if self.functions.contains_key(&address) || self.functions.len() < MAX_FUNCTIONS {
            self.functions.insert(address, name);
        } else {
            self.functions_truncated = true;
            self.warn(&format!("PE function metadata is limited to {MAX_FUNCTIONS} functions; additional entries were omitted."));
        }
    }
}

struct Region {
    rva: u64,
    end: u64,
    offset: usize,
    executable: bool,
}

struct Image<'a> {
    bytes: &'a [u8],
    regions: Vec<Region>,
    base: u64,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

impl<'a> Image<'a> {
    fn region(&self, rva: u32, length: usize) -> Option<&Region> {
        let start = u64::from(rva);
        let index = self.regions.partition_point(|region| region.rva <= start);
        let region = self.regions.get(index.checked_sub(1)?)?;
        (length > 0 && start.checked_add(length as u64)? <= region.end).then_some(region)
    }

    fn data(&self, rva: u32, length: usize) -> Option<&'a [u8]> {
        let region = self.region(rva, length)?;
        let offset = region
            .offset
            .checked_add(usize::try_from(u64::from(rva) - region.rva).ok()?)?;
        self.bytes.get(offset..offset.checked_add(length)?)
    }

    fn address(&self, rva: u32) -> Option<u64> {
        self.base.checked_add(u64::from(rva))
    }

    fn function_address(&self, begin: u32, end: Option<u32>) -> Option<u64> {
        let length = end.map_or(Some(1), |end| {
            end.checked_sub(begin).map(|size| size as usize)
        })?;
        self.region(begin, length)?.executable.then_some(())?;
        self.address(begin)
    }

    fn name(&self, rva: u32) -> Option<String> {
        let region = self.region(rva, 1)?;
        let available = usize::try_from(region.end - u64::from(rva))
            .ok()?
            .min(MAX_NAME_BYTES + 1);
        let data = self.data(rva, available)?;
        let end = data.iter().position(|byte| *byte == 0)?;
        if end == 0
            || end > MAX_NAME_BYTES
            || !data[..end].iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return None;
        }
        String::from_utf8(data[..end].to_vec()).ok()
    }

    fn directory(&self, rva: u32, size: u32) -> Option<&'a [u8]> {
        (size <= MAX_DIRECTORY_BYTES).then_some(())?;
        self.data(rva, size as usize)
    }
}

/// Read only metadata already present in this immutable image. Pointer-bearing
/// tables are translated through nonoverlapping, file-backed mapped regions.
pub(crate) fn parse(bytes: &[u8], sections: &[SectionInfo]) -> Result<Option<PeMetadata>, String> {
    if !bytes.starts_with(b"MZ") {
        return Ok(None);
    }
    let invalid = || "Malformed or unsupported PE metadata headers".to_owned();
    let pe = u32_at(bytes, 0x3c).ok_or_else(invalid)? as usize;
    let coff = pe.checked_add(4).ok_or_else(invalid)?;
    if bytes.get(pe..coff) != Some(b"PE\0\0") {
        return Err(invalid());
    }
    let machine = u16_at(bytes, coff).ok_or_else(invalid)?;
    let optional_size =
        u16_at(bytes, coff.checked_add(16).ok_or_else(invalid)?).ok_or_else(invalid)? as usize;
    let optional = coff.checked_add(20).ok_or_else(invalid)?;
    let header = bytes
        .get(optional..optional.checked_add(optional_size).ok_or_else(invalid)?)
        .ok_or_else(invalid)?;
    let (is64, directory_start, directory_count_at, base) =
        match u16_at(header, 0).ok_or_else(invalid)? {
            0x10b => (
                false,
                96,
                92,
                u64::from(u32_at(header, 28).ok_or_else(invalid)?),
            ),
            0x20b => (true, 112, 108, u64_at(header, 24).ok_or_else(invalid)?),
            _ => return Err(invalid()),
        };
    let count = u32_at(header, directory_count_at).ok_or_else(invalid)? as usize;
    if count > header.len().saturating_sub(directory_start) / 8 {
        return Err(invalid());
    }
    let headers_size = u32_at(header, 60).ok_or_else(invalid)? as usize;
    if headers_size > bytes.len() || sections.len() > 4096 {
        return Err(invalid());
    }
    let mut regions = Vec::with_capacity(sections.len() + 1);
    if headers_size > 0 {
        regions.push(Region {
            rva: 0,
            end: headers_size as u64,
            offset: 0,
            executable: false,
        });
    }
    for section in sections {
        let size = section.size.min(section.file_size);
        if size == 0 {
            continue;
        }
        let rva = section.address.checked_sub(base).ok_or_else(invalid)?;
        let end = rva
            .checked_add(size)
            .filter(|end| *end <= u64::from(u32::MAX) + 1)
            .ok_or_else(invalid)?;
        let offset = usize::try_from(section.file_offset).map_err(|_| invalid())?;
        if section
            .file_offset
            .checked_add(size)
            .is_none_or(|end| end > bytes.len() as u64)
        {
            return Err(invalid());
        }
        regions.push(Region {
            rva,
            end,
            offset,
            executable: section.executable,
        });
    }
    regions.sort_unstable_by_key(|region| region.rva);
    if regions.windows(2).any(|pair| pair[0].end > pair[1].rva) {
        return Err(
            "Overlapping PE file-backed mappings prevent unambiguous metadata recovery".into(),
        );
    }
    let image = Image {
        bytes,
        regions,
        base,
    };
    let directory = |index: usize| -> Option<(u32, u32)> {
        if index >= count {
            return None;
        }
        let at = directory_start + index * 8;
        let rva = u32_at(header, at)?;
        let size = u32_at(header, at + 4)?;
        (rva != 0 && size != 0).then_some((rva, size))
    };
    let mut metadata = PeMetadata::default();
    if let Some(entry) = u32_at(header, 16).and_then(|rva| image.function_address(rva, None)) {
        metadata.function(entry, "entry".into());
    }
    if let Some((rva, size)) = directory(0) {
        exports(&image, rva, size, &mut metadata);
    }
    if matches!(machine, 0x8664 | 0xaa64)
        && is64
        && let Some((rva, size)) = directory(3)
    {
        let entry = u32_at(header, 16)
            .and_then(|rva| image.address(rva))
            .unwrap_or(image.base);
        if machine == 0xaa64 {
            arm64::runtime_functions(&image, rva, size, entry, &mut metadata);
        } else {
            runtime_functions(&image, rva, size, entry, &mut metadata);
        }
    }
    if let Some((rva, size)) = directory(1) {
        imports(&image, rva, size, is64, &mut metadata);
    }
    Ok(Some(metadata))
}

fn runtime_functions(image: &Image<'_>, rva: u32, size: u32, entry: u64, out: &mut PeMetadata) {
    let Some(data) = image.directory(rva, size) else {
        out.functions_truncated |= size > MAX_DIRECTORY_BYTES;
        out.warn("PE exception directory is not bounded file-backed data; runtime functions were omitted.");
        return;
    };
    if !size.is_multiple_of(12) {
        out.warn("PE exception directory has an incomplete runtime-function record.");
    }
    if size / 12 > MAX_TABLE_ENTRIES {
        out.functions_truncated = true;
        out.warn("PE runtime-function table exceeds the scan limit; recovery is partial.");
    }
    for record in data
        .as_chunks::<12>()
        .0
        .iter()
        .take(MAX_TABLE_ENTRIES as usize)
    {
        let begin = u32_at(record, 0).unwrap_or(0);
        let end = u32_at(record, 4).unwrap_or(0);
        let unwind = u32_at(record, 8).unwrap_or(0);
        if begin == 0 && end == 0 && unwind == 0 {
            continue;
        }
        let address = image.function_address(begin, Some(end));
        if let Some(address) = address.filter(|_| unwind != 0 && image.data(unwind, 4).is_some()) {
            if let Some(end_address) = image.address(end) {
                out.function_ranges.push((address, end_address));
            }
        } else {
            out.warn("Some PE runtime-function records have invalid code extents or unreadable unwind metadata and were omitted.");
        }
    }
    out.function_ranges.sort_unstable();
    out.function_ranges.dedup();
    // Preserve exact ranges for address navigation, but bound the symbol inventory.
    // For very large images prefer actual runtime entries near the entry point.
    let candidates = out.function_ranges.iter().map(|range| range.0).collect();
    register_runtime_starts(candidates, entry, out);
}

fn register_runtime_starts(mut candidates: Vec<u64>, entry: u64, out: &mut PeMetadata) {
    candidates.sort_unstable_by_key(|address| (address.abs_diff(entry), *address));
    let count_before = out.functions.len();
    let mut omitted = false;
    for address in candidates {
        if out.functions.contains_key(&address) {
            continue;
        }
        if out.functions.len() >= MAX_FUNCTIONS {
            omitted = true;
            break;
        }
        out.function(address, format!("FUN_{address:x}"));
    }
    if omitted {
        out.functions_truncated = true;
        out.warn(&format!("PE metadata contains {} validated runtime-function ranges; the function list is limited to {MAX_FUNCTIONS} entries, prioritizing the entry point, exports, and runtime starts closest to entry ({count_before} entry/export symbols). Address navigation can still use the retained ranges.", out.function_ranges.len()));
    }
}

fn exports(image: &Image<'_>, rva: u32, size: u32, out: &mut PeMetadata) {
    let Some(directory) = image.directory(rva, size).filter(|data| data.len() >= 40) else {
        out.functions_truncated |= size > MAX_DIRECTORY_BYTES;
        out.warn("PE export directory is not bounded file-backed data; exports were omitted.");
        return;
    };
    let functions = u32_at(directory, 20).unwrap_or(0);
    let names = u32_at(directory, 24).unwrap_or(0);
    let addresses_rva = u32_at(directory, 28).unwrap_or(0);
    let names_rva = u32_at(directory, 32).unwrap_or(0);
    let ordinals_rva = u32_at(directory, 36).unwrap_or(0);
    if functions > MAX_TABLE_ENTRIES || names > MAX_TABLE_ENTRIES {
        out.functions_truncated = true;
        out.warn("PE export tables exceed the scan limit; exports were omitted.");
        return;
    }
    let Some(addresses) = image.data(addresses_rva, functions as usize * 4) else {
        if functions != 0 {
            out.warn("PE export address table is invalid; exports were omitted.");
        }
        return;
    };
    let forward_end = u64::from(rva) + u64::from(size);
    let target = |index: usize| -> Option<u64> {
        let function_rva = u32_at(addresses, index.checked_mul(4)?)?;
        if function_rva == 0
            || (u64::from(function_rva) >= u64::from(rva) && u64::from(function_rva) < forward_end)
        {
            return None;
        }
        image.function_address(function_rva, None)
    };
    for index in 0..functions as usize {
        if let Some(address) = target(index)
            && !out.functions.contains_key(&address)
        {
            out.function(address, format!("FUN_{address:x}"));
        }
    }
    if names == 0 {
        return;
    }
    let Some((name_table, ordinal_table)) = image
        .data(names_rva, names as usize * 4)
        .zip(image.data(ordinals_rva, names as usize * 2))
    else {
        out.warn("PE export name or ordinal table is invalid; exports retain generated names.");
        return;
    };
    for index in 0..names as usize {
        let name_rva = u32_at(name_table, index * 4).unwrap_or(0);
        let ordinal = u16_at(ordinal_table, index * 2).unwrap_or(u16::MAX) as usize;
        if ordinal >= functions as usize {
            out.warn(
                "Some PE export name ordinals are outside the address table and were omitted.",
            );
            continue;
        }
        if let Some(address) = target(ordinal) {
            if let Some(name) = image.name(name_rva) {
                out.function(address, name);
            } else {
                out.warn("Some PE export names are empty, overlong or unsupported text and were omitted.");
            }
        }
    }
}

fn imports(image: &Image<'_>, rva: u32, size: u32, is64: bool, out: &mut PeMetadata) {
    let Some(data) = image.directory(rva, size) else {
        out.warn("PE import directory is not bounded file-backed data; imports were omitted.");
        return;
    };
    let width = if is64 { 8 } else { 4 };
    let ordinal_flag = if is64 { 1u64 << 63 } else { 1u64 << 31 };
    let mut terminated = false;
    let mut scanned = 0usize;
    for descriptor in data
        .as_chunks::<20>()
        .0
        .iter()
        .take(MAX_TABLE_ENTRIES as usize)
    {
        if descriptor.iter().all(|byte| *byte == 0) {
            terminated = true;
            break;
        }
        let original = u32_at(descriptor, 0).unwrap_or(0);
        let iat = u32_at(descriptor, 16).unwrap_or(0);
        let lookup = if original == 0 { iat } else { original };
        if lookup == 0 || iat == 0 {
            out.warn("Some PE import descriptors have no lookup/IAT table and were omitted.");
            continue;
        }
        let mut thunk_terminated = false;
        for index in 0..=MAX_IMPORTS {
            if scanned >= MAX_TABLE_ENTRIES as usize || out.imports.len() >= MAX_IMPORTS {
                out.warn("PE import recovery reached its bounded scan/result limit; additional imports were omitted.");
                return;
            }
            scanned += 1;
            let offset = (index * width) as u32;
            let entry = lookup
                .checked_add(offset)
                .and_then(|rva| image.data(rva, width));
            let value = entry.and_then(|entry| {
                if is64 {
                    u64_at(entry, 0)
                } else {
                    u32_at(entry, 0).map(u64::from)
                }
            });
            let Some(value) = value else {
                break;
            };
            if value == 0 {
                thunk_terminated = true;
                break;
            }
            let Some(slot) = iat
                .checked_add(offset)
                .filter(|slot| image.data(*slot, width).is_some())
                .and_then(|slot| image.address(slot))
            else {
                break;
            };
            let name = if value & ordinal_flag != 0 {
                // Only the ordinal flag and low 16 bits are specified for this form.
                (value & !(ordinal_flag | 0xffff) == 0)
                    .then(|| format!("ordinal_{}", value & 0xffff))
            } else {
                u32::try_from(value)
                    .ok()
                    .filter(|rva| *rva <= 0x7fff_ffff)
                    .filter(|rva| image.data(*rva, 2).is_some())
                    .and_then(|rva| rva.checked_add(2))
                    .and_then(|rva| image.name(rva))
            };
            if let Some(name) = name {
                out.imports.insert(slot, name);
            } else {
                out.warn("Some PE imports have invalid, overlong or unsupported names/ordinals and were omitted.");
            }
        }
        if !thunk_terminated {
            out.warn("Some PE import lookup/IAT tables are invalid or unterminated; recovery is partial.");
        }
    }
    if !terminated {
        out.warn("PE import directory has no bounded terminating descriptor; recovery is partial.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    pub(super) fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    pub(super) fn file(rva: usize) -> usize {
        rva - 0x2000 + 0x400
    }

    // Original synthetic metadata, with no third-party executable bytes.
    pub(super) fn fixture(is64: bool) -> (Vec<u8>, Vec<SectionInfo>) {
        let mut bytes = vec![0u8; 0xa00];
        bytes[..2].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut bytes, 0x84, if is64 { 0x8664 } else { 0x14c });
        put16(&mut bytes, 0x94, if is64 { 0xf0 } else { 0xe0 });
        let optional = 0x98;
        put16(&mut bytes, optional, if is64 { 0x20b } else { 0x10b });
        put32(&mut bytes, optional + 16, 0x1000);
        let base = if is64 { 0x1_4000_0000 } else { 0x40_0000 };
        if is64 {
            put64(&mut bytes, optional + 24, base);
        } else {
            put32(&mut bytes, optional + 28, base as u32);
        }
        put32(&mut bytes, optional + 60, 0x200);
        let directories = optional + if is64 { 112 } else { 96 };
        put32(&mut bytes, directories - 4, 16);
        for (index, rva, size) in [(0, 0x2200, 0xa0), (1, 0x2300, 40), (3, 0x2000, 24)] {
            put32(&mut bytes, directories + index * 8, rva);
            put32(&mut bytes, directories + index * 8 + 4, size);
        }
        for (offset, value) in [
            (0, 0x1000),
            (4, 0x1020),
            (8, 0x2100),
            (12, 0x1040),
            (16, 0x1080),
            (20, 0x2100),
        ] {
            put32(&mut bytes, file(0x2000) + offset, value);
        }
        bytes[file(0x2100)] = 1;
        for (offset, value) in [(20, 2), (24, 1), (28, 0x2280), (32, 0x2288), (36, 0x2290)] {
            put32(&mut bytes, file(0x2200) + offset, value);
        }
        put32(&mut bytes, file(0x2280), 0x1040);
        put32(&mut bytes, file(0x2284), 0x2250);
        put32(&mut bytes, file(0x2288), 0x22b0);
        put16(&mut bytes, file(0x2290), 0);
        bytes[file(0x22b0)..file(0x22b0) + 12].copy_from_slice(b"branch_loop\0");
        put32(&mut bytes, file(0x2300), 0x2380);
        put32(&mut bytes, file(0x2300) + 12, 0x23c0);
        put32(&mut bytes, file(0x2300) + 16, 0x23a0);
        bytes[file(0x23c0)..file(0x23c0) + 13].copy_from_slice(b"KERNEL32.dll\0");
        bytes[file(0x23d2)..file(0x23d2) + 12].copy_from_slice(b"ExitProcess\0");
        if is64 {
            put64(&mut bytes, file(0x2380), 0x23d0);
            put64(&mut bytes, file(0x2388), (1 << 63) | 7);
        } else {
            put32(&mut bytes, file(0x2380), 0x23d0);
            put32(&mut bytes, file(0x2384), (1 << 31) | 7);
        }
        let sections = vec![
            SectionInfo {
                name: ".text".into(),
                address: base + 0x1000,
                size: 0x200,
                file_offset: 0x200,
                file_size: 0x200,
                executable: true,
            },
            SectionInfo {
                name: ".rdata".into(),
                address: base + 0x2000,
                size: 0x600,
                file_offset: 0x400,
                file_size: 0x600,
                executable: false,
            },
        ];
        (bytes, sections)
    }

    #[test]
    fn recovers_amd64_runtime_exports_and_real_iat_names() {
        let (bytes, sections) = fixture(true);
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert_eq!(result.functions.len(), 2);
        assert_eq!(result.functions[&0x1_4000_1000], "entry");
        assert_eq!(result.functions[&0x1_4000_1040], "branch_loop");
        assert_eq!(result.imports[&0x1_4000_23a0], "ExitProcess");
        assert_eq!(result.imports[&0x1_4000_23a8], "ordinal_7");
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    }

    #[test]
    fn pe32_import_width_and_original_thunk_fallback() {
        let (mut bytes, sections) = fixture(false);
        put32(&mut bytes, file(0x2300), 0);
        let lookup = bytes[file(0x2380)..file(0x2380) + 12].to_vec();
        bytes[file(0x23a0)..file(0x23a0) + 12].copy_from_slice(&lookup);
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert_eq!(result.imports[&0x40_23a0], "ExitProcess");
        assert_eq!(result.imports[&0x40_23a4], "ordinal_7");
        assert_eq!(result.functions[&0x40_1040], "branch_loop");
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn rejects_runtime_extents_outside_code_and_unreadable_unwind() {
        let (mut bytes, sections) = fixture(true);
        // Leave exports absent so their independent evidence cannot add a start.
        put32(&mut bytes, 0x98 + 112, 0);
        put32(&mut bytes, file(0x2000) + 4, 0x1300);
        put32(&mut bytes, file(0x2000) + 20, 0x2600);
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert_eq!(result.functions.len(), 1);
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("invalid code extents"))
        );
    }

    #[test]
    fn respects_directory_size_and_name_bounds() {
        let (mut bytes, sections) = fixture(true);
        put32(&mut bytes, 0x98 + 112 + 8 + 4, 19);
        bytes[file(0x22b0)..file(0x22b0) + MAX_NAME_BYTES + 1].fill(b'A');
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert!(result.imports.is_empty());
        assert_eq!(result.functions[&0x1_4000_1040], "FUN_140001040");
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("export names"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("terminating descriptor"))
        );
    }

    #[test]
    fn rejects_overlapping_maps_and_truncated_headers_without_panics() {
        let (bytes, mut sections) = fixture(true);
        for end in 0..0x188 {
            let _ = parse(&bytes[..end], &sections);
        }
        sections[1].address = sections[0].address + 1;
        assert!(parse(&bytes, &sections).is_err());
        assert!(parse(b"not a PE", &[]).unwrap().is_none());
    }

    #[test]
    fn large_runtime_table_preserves_entry_neighborhood_and_exact_far_ranges() {
        let (mut bytes, mut sections) = fixture(true);
        let count = MAX_FUNCTIONS + 100;
        let table_size = count * 12;
        let text_size = (count * 4).next_multiple_of(0x10000);
        let table_offset = 0x1000 + text_size;
        let table_rva = 0x20000 + text_size as u32;
        bytes.resize(table_offset + table_size + 0xa0, 0);
        sections[0].file_offset = 0x1000;
        sections[0].file_size = text_size as u64;
        sections[0].size = text_size as u64;
        sections[1].address = 0x1_4000_0000 + u64::from(table_rva);
        sections[1].file_offset = table_offset as u64;
        sections[1].file_size = (table_size + 0xa0) as u64;
        sections[1].size = (table_size + 0xa0) as u64;
        put32(&mut bytes, 0x98 + 112, 0);
        put32(&mut bytes, 0x98 + 112 + 8, 0);
        put32(&mut bytes, 0x98 + 112 + 24, table_rva);
        put32(&mut bytes, 0x98 + 112 + 28, table_size as u32);
        let entry_rva = 0x1000 + (count as u32 - 1) * 4;
        put32(&mut bytes, 0x98 + 16, entry_rva);
        for index in 0..count {
            let begin = 0x1000 + index as u32 * 4;
            put32(&mut bytes, table_offset + index * 12, begin);
            put32(&mut bytes, table_offset + index * 12 + 4, begin + 4);
            put32(
                &mut bytes,
                table_offset + index * 12 + 8,
                table_rva + table_size as u32,
            );
        }
        bytes[table_offset + table_size] = 1;
        let export_rva = table_rva + table_size as u32 + 0x20;
        let export_offset = table_offset + table_size + 0x20;
        put32(&mut bytes, 0x98 + 112, export_rva);
        put32(&mut bytes, 0x98 + 116, 0x80);
        for (offset, value) in [
            (20, 1),
            (24, 1),
            (28, export_rva + 40),
            (32, export_rva + 44),
            (36, export_rva + 48),
            (40, 0x1000),
            (44, export_rva + 52),
        ] {
            put32(&mut bytes, export_offset + offset, value);
        }
        bytes[export_offset + 52..export_offset + 64].copy_from_slice(b"branch_loop\0");
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert_eq!(result.functions.len(), MAX_FUNCTIONS);
        assert_eq!(
            result.functions[&(0x1_4000_0000 + u64::from(entry_rva))],
            "entry"
        );
        assert_eq!(result.functions[&0x1_4000_1000], "branch_loop");
        assert!(!result.functions.contains_key(&0x1_4000_1004));
        assert!(result.functions_truncated);
        assert_eq!(result.function_ranges.len(), count);
        assert_eq!(result.function_ranges[0], (0x1_4000_1000, 0x1_4000_1004));
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("closest to entry"))
        );
    }

    #[test]
    fn huge_and_wrapping_directory_descriptors_are_not_followed() {
        let (mut bytes, sections) = fixture(true);
        put32(&mut bytes, 0x98 + 112 + 24, u32::MAX - 1);
        put32(&mut bytes, 0x98 + 112 + 28, u32::MAX);
        put32(&mut bytes, file(0x2300), u32::MAX - 1);
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert!(result.function_ranges.is_empty());
        assert!(result.imports.is_empty());
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("exception directory"))
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.contains("lookup/IAT tables"))
        );
    }

    #[test]
    fn import_hint_must_also_be_file_backed() {
        let (mut bytes, sections) = fixture(true);
        bytes[file(0x2000)..file(0x2000) + 5].copy_from_slice(b"Good\0");
        // Name bytes are mapped, but the required preceding hint lies in a gap.
        put64(&mut bytes, file(0x2380), 0x1ffe);
        let result = parse(&bytes, &sections).unwrap().unwrap();
        assert!(!result.imports.contains_key(&0x1_4000_23a0));
        assert_eq!(result.imports[&0x1_4000_23a8], "ordinal_7");
    }
}
