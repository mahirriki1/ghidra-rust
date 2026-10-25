//! A bounded ELF64 init/fini and `.eh_frame` range reader, not an unwinder.
use std::collections::BTreeMap;

use object::elf;
use object::read::elf::{Dyn, SectionHeader};
use object::{Object, ObjectSection, ObjectSymbol};

use crate::code_pointers::{CodePointers, elf64};
use crate::model::*;

#[derive(Default)]
pub(crate) struct FunctionMetadata {
    pub fdes: BTreeMap<u64, u64>,
    pub symbols: BTreeMap<u64, u64>,
    pub callbacks: Vec<FunctionAdmission>,
    pub records: usize,
    pub partial: bool,
}

impl FunctionMetadata {
    pub fn parse(bytes: &[u8], info: &BinaryInfo, pointers: &CodePointers) -> Self {
        let mut result = Self::default();
        let Some(file) = elf64(bytes) else {
            return result;
        };
        let endian = file.endian();
        for symbol in file.symbols() {
            if result.records == MAX_METADATA_RECORDS {
                result.partial = true;
                break;
            }
            result.records += 1;
            if symbol.kind() == object::SymbolKind::Text
                && symbol.size() != 0
                && let Some(end) = symbol.address().checked_add(symbol.size())
                && code_range(info, symbol.address(), end)
            {
                result
                    .symbols
                    .entry(symbol.address())
                    .and_modify(|v| *v = (*v).max(end))
                    .or_insert(end);
            }
        }
        if let Some(section) = file.section_by_name(".eh_frame") {
            // Name locates the section; allocation, backing and contents establish evidence.
            let size = section.size();
            if info
                .sections
                .iter()
                .any(|s| !s.executable && s.backs(section.address(), size))
            {
                match section
                    .data()
                    .ok()
                    .and_then(|data| read_fdes(data, section.address(), info, &mut result.records))
                {
                    Some(ranges) => result.fdes = ranges,
                    None => result.partial = true,
                }
            }
        }
        let mut tags = BTreeMap::new();
        let mut dynamic_count = 0;
        for section in file.elf_section_table().iter() {
            if section.sh_type(endian) != elf::SHT_DYNAMIC {
                continue;
            }
            dynamic_count += 1;
            let Ok(Some((records, _))) = section.dynamic(endian, bytes) else {
                result.partial = true;
                return result;
            };
            if dynamic_count != 1
                || section.sh_entsize(endian) != 16
                || !section.sh_size(endian).is_multiple_of(16)
                || !info.sections.iter().any(|s| {
                    !s.executable && s.backs(section.sh_addr(endian), section.sh_size(endian))
                })
            {
                result.partial = true;
                return result;
            }
            let mut terminated = false;
            for (index, record) in records.iter().enumerate() {
                if result.records == MAX_METADATA_RECORDS {
                    result.partial = true;
                    return result;
                }
                result.records += 1;
                let tag = record.d_tag(endian);
                if tag == u64::from(elf::DT_NULL) {
                    terminated = true;
                    break;
                }
                if ![
                    elf::DT_INIT,
                    elf::DT_FINI,
                    elf::DT_INIT_ARRAY,
                    elf::DT_FINI_ARRAY,
                    elf::DT_INIT_ARRAYSZ,
                    elf::DT_FINI_ARRAYSZ,
                ]
                .iter()
                .any(|&t| tag == u64::from(t))
                {
                    continue;
                }
                let Some(source) = section.sh_addr(endian).checked_add(index as u64 * 16) else {
                    result.partial = true;
                    return result;
                };
                if tags.insert(tag, (record.d_val(endian), source)).is_some() {
                    result.partial = true;
                    return result;
                }
            }
            if !terminated {
                result.partial = true;
                return result;
            }
        }
        for tag in [elf::DT_INIT, elf::DT_FINI] {
            if let Some(&(entry, source)) = tags.get(&u64::from(tag))
                && crate::call_analysis::code_address(info, entry)
            {
                result
                    .callbacks
                    .push(witness(entry, source, PointerEncoding::Direct));
            }
        }
        for (kind, tag, size_tag) in [
            (
                elf::SHT_INIT_ARRAY,
                elf::DT_INIT_ARRAY,
                elf::DT_INIT_ARRAYSZ,
            ),
            (
                elf::SHT_FINI_ARRAY,
                elf::DT_FINI_ARRAY,
                elf::DT_FINI_ARRAYSZ,
            ),
        ] {
            let (Some(&(address, _)), Some(&(size, _))) =
                (tags.get(&u64::from(tag)), tags.get(&u64::from(size_tag)))
            else {
                continue;
            };
            let sections: Vec<_> = file
                .elf_section_table()
                .iter()
                .filter(|s| s.sh_type(endian) == kind)
                .collect();
            if sections.len() != 1
                || size == 0
                || !size.is_multiple_of(8)
                || !address.is_multiple_of(8)
            {
                result.partial = true;
                continue;
            }
            let section = sections[0];
            if section.sh_addr(endian) != address
                || section.sh_size(endian) != size
                || section.sh_entsize(endian) != 8
                || !pointers
                    .ranges
                    .iter()
                    .any(|&(a, b)| a == address && address.checked_add(size) == Some(b))
            {
                result.partial = true;
                continue;
            }
            for index in 0..size / 8 {
                if result.records == MAX_METADATA_RECORDS
                    || result.callbacks.len() == MAX_FUNCTION_ADMISSIONS
                {
                    result.partial = true;
                    break;
                }
                result.records += 1;
                let Some(slot) = address.checked_add(index * 8) else {
                    result.partial = true;
                    break;
                };
                if let Some((entry, encoding)) = pointers.pointer(bytes, &info.sections, slot)
                    && crate::call_analysis::code_address(info, entry)
                {
                    result.callbacks.push(witness(entry, slot, encoding));
                }
            }
        }
        result.callbacks.sort_by_key(|w| (w.source, w.entry));
        // Exact init/fini callback forwarding bodies provide callable semantics
        // even when the destination has no unwind record (common CRT code).
        let mut forwarders = Vec::new();
        for callback in &result.callbacks {
            let mut pc = callback.entry;
            let prefix = crate::pe_symbols::mapped_bytes(bytes, &info.sections, pc, 4, true);
            if prefix == Some(&[0xf3, 0x0f, 0x1e, 0xfa][..]) {
                pc = match pc.checked_add(4) {
                    Some(v) => v,
                    None => continue,
                };
            }
            let Some(body) = crate::pe_symbols::mapped_bytes(bytes, &info.sections, pc, 5, true)
            else {
                continue;
            };
            if body[0] != 0xe9 {
                continue;
            }
            let offset = i64::from(i32::from_le_bytes(
                body[1..5].try_into().expect("five bytes"),
            ));
            let Some(entry) = pc.checked_add(5).and_then(|p| p.checked_add_signed(offset)) else {
                continue;
            };
            if entry == callback.entry || !crate::call_analysis::code_address(info, entry) {
                continue;
            }
            forwarders.push(FunctionAdmission {
                entry,
                reason: AdmissionReason::CrtForwarder,
                source: pc,
                owner: Some(callback.entry),
                encoding: PointerEncoding::Direct,
                boundary: BoundaryEvidence::Forwarder,
                table: None,
            });
        }
        result.callbacks.extend(forwarders);
        result
    }

    pub fn compatible(&self, entry: u64, intervals: &[(u64, u64)]) -> bool {
        intervals.iter().all(|&(low, high)| {
            [&self.fdes, &self.symbols].iter().all(|ranges| {
                let containing = ranges.range(..=low).next_back();
                !containing.is_some_and(|(&start, &end)| start != entry && end > low)
                    && !ranges
                        .range(low.saturating_add(1)..high)
                        .any(|(&start, _)| start != entry)
                    && !ranges
                        .get(&entry)
                        .is_some_and(|&end| low >= end || high > end)
            })
        })
    }

    pub fn interior(&self, address: u64) -> bool {
        [&self.fdes, &self.symbols].iter().any(|ranges| {
            ranges
                .range(..address)
                .next_back()
                .is_some_and(|(_, &end)| address < end)
        })
    }
}

fn witness(entry: u64, source: u64, encoding: PointerEncoding) -> FunctionAdmission {
    FunctionAdmission {
        entry,
        reason: AdmissionReason::InitMetadata,
        source,
        owner: None,
        encoding,
        boundary: BoundaryEvidence::Format,
        table: None,
    }
}

fn code_range(info: &BinaryInfo, start: u64, end: u64) -> bool {
    end > start
        && info
            .sections
            .iter()
            .any(|s| s.executable && s.backs(start, end - start))
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let v = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn uleb(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte()?;
            if shift == 63 && byte & 0x7e != 0 {
                return None;
            }
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0u64;
        for shift in (0..70).step_by(7) {
            let byte = self.byte()?;
            if shift == 63 && !matches!(byte, 0 | 0x7f) {
                return None;
            }
            value |= u64::from(byte & 0x7f).checked_shl(shift)?;
            if byte & 0x80 == 0 {
                let bits = shift + 7;
                if byte & 0x40 != 0 && bits < 64 {
                    value |= u64::MAX << bits;
                }
                return Some(value as i64);
            }
        }
        None
    }
    fn u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        let v = u32::from_le_bytes(self.bytes.get(self.pos..end)?.try_into().ok()?);
        self.pos = end;
        Some(v)
    }
}

fn read_fdes(
    bytes: &[u8],
    base: u64,
    info: &BinaryInfo,
    records: &mut usize,
) -> Option<BTreeMap<u64, u64>> {
    let mut cursor = 0usize;
    let mut cies = BTreeMap::new();
    let mut ranges = BTreeMap::new();
    while cursor < bytes.len() {
        if *records == MAX_METADATA_RECORDS {
            return None;
        }
        *records += 1;
        let mut head = Reader { bytes, pos: cursor };
        let length = head.u32()? as usize;
        if length == 0 {
            if !bytes[head.pos..].iter().all(|&b| b == 0) {
                return None;
            }
            break;
        }
        if length < 4 || length == u32::MAX as usize {
            return None;
        }
        let end = head.pos.checked_add(length)?;
        let mut r = Reader {
            bytes: bytes.get(..end)?,
            pos: head.pos,
        };
        let id_at = r.pos;
        let id = r.u32()? as usize;
        if id == 0 {
            let version = r.byte()?;
            if !matches!(version, 1 | 3) {
                return None;
            }
            // Only zR is understood. Unknown augmentations establish no ranges.
            if [r.byte()?, r.byte()?, r.byte()?] != *b"zR\0" {
                return None;
            }
            if r.uleb()? == 0 {
                return None;
            }
            r.sleb()?;
            if version == 1 {
                r.byte()?;
            } else {
                r.uleb()?;
            }
            if r.uleb()? != 1 || r.byte()? != 0x1b {
                return None;
            } // pcrel|sdata4
            cies.insert(cursor, ());
        } else {
            let cie = id_at.checked_sub(id)?;
            cies.get(&cie)?;
            let pc_base = base.checked_add(r.pos as u64)?;
            let displacement = i64::from(r.u32()? as i32);
            let start = pc_base.checked_add_signed(displacement)?;
            let length = r.u32()?;
            // The range encoding takes only the unsigned representation bits.
            if length == 0 || length > i32::MAX as u32 {
                return None;
            }
            let high = start.checked_add(u64::from(length))?;
            let augmentation = usize::try_from(r.uleb()?).ok()?;
            if r.pos.checked_add(augmentation)? > end || !code_range(info, start, high) {
                return None;
            }
            if ranges.insert(start, high).is_some() {
                return None;
            }
        }
        cursor = end;
    }
    let ordered: Vec<_> = ranges.iter().collect();
    if ordered.windows(2).any(|w| *w[0].1 > *w[1].0) {
        return None;
    }
    Some(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> BinaryInfo {
        BinaryInfo {
            path: "synthetic".into(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 0x1000,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x1000,
                file_offset: 0,
                file_size: 0x1000,
                executable: true,
            }],
            functions: vec![],
            functions_truncated: false,
            warnings: vec![],
        }
    }
    fn record(bytes: &mut Vec<u8>, payload: &[u8]) {
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    fn fde(bytes: &mut Vec<u8>, start: u64, size: u32) {
        let id = bytes.len() as u32 + 4;
        let pc = 0x3000 + u64::from(id) + 4;
        let mut payload = id.to_le_bytes().to_vec();
        payload.extend_from_slice(&((start as i64 - pc as i64) as i32).to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        payload.push(0);
        record(bytes, &payload);
    }
    fn frame() -> Vec<u8> {
        let mut bytes = vec![];
        record(
            &mut bytes,
            &[0, 0, 0, 0, 1, b'z', b'R', 0, 1, 0x78, 16, 1, 0x1b],
        );
        fde(&mut bytes, 0x1010, 8);
        fde(&mut bytes, 0x1020, 16);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }
    fn parse(bytes: &[u8]) -> Option<BTreeMap<u64, u64>> {
        read_fdes(bytes, 0x3000, &info(), &mut 0)
    }

    #[test]
    fn pcrel_ranges_are_exact_and_not_an_unwinder() {
        assert_eq!(
            parse(&frame()).unwrap(),
            BTreeMap::from([(0x1010, 0x1018), (0x1020, 0x1030)])
        );
        let metadata = FunctionMetadata {
            fdes: parse(&frame()).unwrap(),
            ..Default::default()
        };
        assert!(!metadata.interior(0x1010));
        assert!(metadata.interior(0x1011));
        assert!(metadata.compatible(0x1010, &[(0x1010, 0x1018)]));
        assert!(!metadata.compatible(0x1010, &[(0x1010, 0x1019)]));
        assert!(!metadata.compatible(0x1010, &[(0x1021, 0x1022)]));
    }

    #[test]
    fn malformed_truncated_overlapping_and_unsupported_frames_fail_closed() {
        let bytes = frame();
        for end in 18..34 {
            assert!(parse(&bytes[..end]).is_none(), "truncated at {end}");
        }
        for (at, value) in [(10, b'P'), (16, 0), (21, 0xff), (32, 0xff)] {
            let mut bad = bytes.clone();
            bad[at] = value;
            assert!(parse(&bad).is_none(), "mutation at {at}");
        }
        let mut overlap = bytes[..bytes.len() - 4].to_vec();
        fde(&mut overlap, 0x1014, 8);
        overlap.extend_from_slice(&[0; 4]);
        assert!(parse(&overlap).is_none());
        let mut outside = bytes[..17].to_vec();
        fde(&mut outside, 0x1fff, 8);
        assert!(parse(&outside).is_none());
        let mut budget = MAX_METADATA_RECORDS;
        assert!(read_fdes(&bytes, 0x3000, &info(), &mut budget).is_none());
        assert!(read_fdes(&bytes, u64::MAX, &info(), &mut 0).is_none());
    }

    #[test]
    fn leb_overflows_and_unsupported_extended_lengths_are_rejected() {
        let mut unsigned = Reader {
            bytes: &[0xff; 10],
            pos: 0,
        };
        assert!(unsigned.uleb().is_none());
        let mut signed = Reader {
            bytes: &[0xff; 10],
            pos: 0,
        };
        assert!(signed.sleb().is_none());
        assert!(parse(&[0xff; 8]).is_none());
    }
}
