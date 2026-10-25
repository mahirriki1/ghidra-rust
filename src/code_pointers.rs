//! Read-only ELF64 pointer slots. Relocations always override on-disk bytes.
use std::collections::BTreeMap;

use object::elf;
use object::read::elf::{Dyn, ElfFile64, FileHeader, Rela, SectionHeader, Sym};
use object::{Endianness, Object};

use crate::model::{MAX_METADATA_RECORDS, MAX_SECTIONS, PointerEncoding, SectionInfo};

// ELF gABI dynamic tags absent from object 0.37's constants.
const DT_RELRSZ: u32 = 35;
const DT_RELR: u32 = 36;

#[derive(Default)]
pub(crate) struct CodePointers {
    pub ranges: Vec<(u64, u64)>,
    pub records: usize,
    pie: bool,
    relocations: BTreeMap<u64, Option<(u64, PointerEncoding)>>,
}

pub(crate) fn elf64(bytes: &[u8]) -> Option<ElfFile64<'_, Endianness>> {
    let file = ElfFile64::parse(bytes).ok()?;
    let header = file.elf_header();
    (file.is_little_endian()
        && header.e_machine(file.endian()) == elf::EM_X86_64
        && matches!(header.e_type(file.endian()), elf::ET_EXEC | elf::ET_DYN)
        && file.elf_section_table().len() <= MAX_SECTIONS)
        .then_some(file)
}

impl CodePointers {
    pub fn parse(bytes: &[u8], sections: &[SectionInfo]) -> Result<Self, ()> {
        let file = elf64(bytes).ok_or(())?;
        let endian = file.endian();
        let table = file.elf_section_table();
        let mut result = Self {
            pie: file.elf_header().e_type(endian) == elf::ET_DYN,
            ..Default::default()
        };
        // Section headers may not conceal dynamic relocation tables. Require
        // each declared table's exact mapped section, size and entry width.
        let mut tags = BTreeMap::new();
        for section in table
            .iter()
            .filter(|s| s.sh_type(endian) == elf::SHT_DYNAMIC)
        {
            let (records, _) = section.dynamic(endian, bytes).map_err(|_| ())?.ok_or(())?;
            if section.sh_entsize(endian) != 16 || !section.sh_size(endian).is_multiple_of(16) {
                return Err(());
            }
            result.records = result.records.checked_add(records.len()).ok_or(())?;
            if result.records > MAX_METADATA_RECORDS {
                return Err(());
            }
            let mut terminated = false;
            for record in records {
                let tag = record.d_tag(endian);
                if tag == u64::from(elf::DT_NULL) {
                    terminated = true;
                    break;
                }
                if [elf::DT_REL, elf::DT_RELSZ, DT_RELR, DT_RELRSZ]
                    .iter()
                    .any(|&t| tag == u64::from(t))
                {
                    return Err(());
                }
                if [
                    elf::DT_RELA,
                    elf::DT_RELASZ,
                    elf::DT_RELAENT,
                    elf::DT_JMPREL,
                    elf::DT_PLTRELSZ,
                    elf::DT_PLTREL,
                ]
                .iter()
                .any(|&t| tag == u64::from(t))
                    && tags.insert(tag, record.d_val(endian)).is_some()
                {
                    return Err(());
                }
            }
            if !terminated {
                return Err(());
            }
        }
        for (address_tag, size_tag, entry_tag, width) in [
            (elf::DT_RELA, elf::DT_RELASZ, elf::DT_RELAENT, 24),
            (
                elf::DT_JMPREL,
                elf::DT_PLTRELSZ,
                elf::DT_PLTREL,
                u64::from(elf::DT_RELA),
            ),
        ] {
            match (
                tags.get(&u64::from(address_tag)),
                tags.get(&u64::from(size_tag)),
            ) {
                (None, None) => {}
                (Some(&address), Some(&size))
                    if size.is_multiple_of(24)
                        && tags.get(&u64::from(entry_tag)) == Some(&width)
                        && table.iter().any(|s| {
                            s.sh_type(endian) == elf::SHT_RELA
                                && s.sh_addr(endian) == address
                                && s.sh_size(endian) == size
                        }) => {}
                _ => return Err(()),
            }
        }

        for section in table.iter() {
            let flags = section.sh_flags(endian);
            if flags & u64::from(elf::SHF_ALLOC | elf::SHF_COMPRESSED)
                == u64::from(elf::SHF_ALLOC | elf::SHF_COMPRESSED)
            {
                return Err(());
            }

            if flags & u64::from(elf::SHF_ALLOC) != 0
                && flags & u64::from(elf::SHF_EXECINSTR | elf::SHF_COMPRESSED) == 0
                && section.sh_type(endian) != elf::SHT_NOBITS
            {
                let address = section.sh_addr(endian);
                let length = section.sh_size(endian);
                if length != 0 {
                    let end = address.checked_add(length).ok_or(())?;
                    let offset = section.sh_offset(endian);
                    let file_end = offset.checked_add(length).ok_or(())?;
                    if file_end > bytes.len() as u64
                        || !sections
                            .iter()
                            .any(|s| !s.executable && s.backs(address, length))
                    {
                        return Err(());
                    }
                    result.ranges.push((address, end));
                }
            }
            // Unsupported REL/RELR semantics must never expose raw fallback slots.
            if matches!(section.sh_type(endian), elf::SHT_REL | elf::SHT_RELR) {
                return Err(());
            }
            if section.sh_type(endian) != elf::SHT_RELA {
                continue;
            }
            if section.sh_entsize(endian) != 24 || !section.sh_size(endian).is_multiple_of(24) {
                return Err(());
            }
            let (records, link) = section.rela(endian, bytes).map_err(|_| ())?.ok_or(())?;
            result.records = result.records.checked_add(records.len()).ok_or(())?;
            if result.records > MAX_METADATA_RECORDS {
                return Err(());
            }
            let symbols = table
                .symbol_table_by_index(endian, bytes, link)
                .map_err(|_| ())?;
            for record in records {
                let slot = record.r_offset(endian);
                let kind = record.r_type(endian, false);
                // These encodings write one native slot. Unknown widths (COPY,
                // TLSDESC, etc.) make this source unsupported, never raw bytes.
                if !matches!(
                    kind,
                    elf::R_X86_64_NONE
                        | elf::R_X86_64_64
                        | elf::R_X86_64_GLOB_DAT
                        | elf::R_X86_64_JUMP_SLOT
                        | elf::R_X86_64_RELATIVE
                        | elf::R_X86_64_IRELATIVE
                        | elf::R_X86_64_DTPMOD64
                        | elf::R_X86_64_DTPOFF64
                        | elf::R_X86_64_TPOFF64
                ) {
                    return Err(());
                }

                let index = record.r_sym(endian, false);
                let addend = record.r_addend(endian);
                let value = if index == 0 && kind == elf::R_X86_64_RELATIVE {
                    u64::try_from(addend)
                        .ok()
                        .map(|v| (v, PointerEncoding::Relative))
                } else if matches!(kind, elf::R_X86_64_64 | elf::R_X86_64_GLOB_DAT) {
                    symbols
                        .symbol(object::SymbolIndex(index as usize))
                        .ok()
                        .and_then(|symbol| {
                            let local = symbol.st_bind() == elf::STB_LOCAL
                                || matches!(
                                    symbol.st_visibility(),
                                    elf::STV_HIDDEN | elf::STV_INTERNAL | elf::STV_PROTECTED
                                );
                            (local
                                && symbol.st_shndx(endian) != elf::SHN_UNDEF
                                && symbol.st_shndx(endian) < elf::SHN_LORESERVE
                                && symbol.st_type() == elf::STT_FUNC)
                                .then(|| symbol.st_value(endian).checked_add_signed(addend))
                                .flatten()
                                .map(|v| (v, PointerEncoding::LocalSymbol))
                        })
                } else {
                    None
                };
                // An unaligned relocation poisons both native slots it may overlap.
                let aligned = slot & !7;
                let value = if slot == aligned { value } else { None };
                result
                    .relocations
                    .entry(aligned)
                    .and_modify(|v| *v = None)
                    .or_insert(value);
                if slot != aligned {
                    let next = aligned.checked_add(8).ok_or(())?;
                    result.relocations.insert(next, None);
                }
            }
        }
        result.ranges.sort_unstable();
        if result.ranges.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(());
        }
        Ok(result)
    }

    pub fn pointer(
        &self,
        bytes: &[u8],
        sections: &[SectionInfo],
        slot: u64,
    ) -> Option<(u64, PointerEncoding)> {
        if !slot.is_multiple_of(8) {
            return None;
        }
        let raw = crate::pe_symbols::mapped_bytes(bytes, sections, slot, 8, false)?;
        if let Some(value) = self.relocations.get(&slot) {
            return *value;
        }
        if self.pie {
            return None;
        }
        Some((
            u64::from_le_bytes(raw.try_into().ok()?),
            PointerEncoding::Absolute,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn p16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn p32(b: &mut [u8], at: usize, v: u32) {
        b[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn p64(b: &mut [u8], at: usize, v: u64) {
        b[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn image(pie: bool) -> (Vec<u8>, Vec<SectionInfo>) {
        let mut b = vec![0; 0x500];
        b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        p16(&mut b, 16, if pie { elf::ET_DYN } else { elf::ET_EXEC });
        p16(&mut b, 18, elf::EM_X86_64);
        p32(&mut b, 20, 1);
        p64(&mut b, 40, 0x300);
        p16(&mut b, 52, 64);
        p16(&mut b, 58, 64);
        p16(&mut b, 60, 6);
        p16(&mut b, 62, 4);
        for (index, kind, flags, addr, off, len, link, entsize) in [
            (1, elf::SHT_PROGBITS, 6, 0x1000, 0x100, 32, 0, 0),
            (2, elf::SHT_PROGBITS, 2, 0x2000, 0x120, 32, 0, 0),
            (3, elf::SHT_SYMTAB, 0, 0, 0x180, 48, 4, 24),
            (4, elf::SHT_STRTAB, 0, 0, 0x1c0, 1, 0, 0),
            (5, elf::SHT_RELA, 2, 0x3000, 0x200, 48, 3, 24),
        ] {
            let at = 0x300 + index * 64;
            p32(&mut b, at + 4, kind);
            p64(&mut b, at + 8, flags);
            p64(&mut b, at + 16, addr);
            p64(&mut b, at + 24, off);
            p64(&mut b, at + 32, len);
            p32(&mut b, at + 40, link);
            p64(&mut b, at + 48, 8);
            p64(&mut b, at + 56, entsize);
        }
        b[0x198 + 4] = elf::STT_FUNC;
        p16(&mut b, 0x198 + 6, 1);
        p64(&mut b, 0x198 + 8, 0x1000);
        for (at, slot, target) in [(0x200, 0x2000, 0x1000), (0x218, 0x2008, 0x1010)] {
            p64(&mut b, at, slot);
            p64(&mut b, at + 8, u64::from(elf::R_X86_64_RELATIVE));
            p64(&mut b, at + 16, target);
        }
        let sections = vec![
            SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 32,
                file_offset: 0x100,
                file_size: 32,
                executable: true,
            },
            SectionInfo {
                name: ".data".into(),
                address: 0x2000,
                size: 32,
                file_offset: 0x120,
                file_size: 32,
                executable: false,
            },
            SectionInfo {
                name: ".rela".into(),
                address: 0x3000,
                size: 48,
                file_offset: 0x200,
                file_size: 48,
                executable: false,
            },
        ];
        (b, sections)
    }
    #[test]
    fn relative_values_use_link_coordinates_and_unsupported_slots_never_fall_back() {
        let (mut bytes, sections) = image(true);
        p64(&mut bytes, 0x120, 0x1018);
        let pointers = CodePointers::parse(&bytes, &sections).unwrap();
        assert_eq!(
            pointers.pointer(&bytes, &sections, 0x2000),
            Some((0x1000, PointerEncoding::Relative))
        );
        assert_eq!(pointers.pointer(&bytes, &sections, 0x2010), None);
        p64(&mut bytes, 0x208, u64::from(elf::R_X86_64_IRELATIVE));
        let pointers = CodePointers::parse(&bytes, &sections).unwrap();
        assert_eq!(pointers.pointer(&bytes, &sections, 0x2000), None);
    }
    #[test]
    fn duplicates_unaligned_slots_and_interposable_symbols_establish_nothing() {
        let (mut bytes, sections) = image(false);
        p64(&mut bytes, 0x218, 0x2000);
        assert_eq!(
            CodePointers::parse(&bytes, &sections)
                .unwrap()
                .pointer(&bytes, &sections, 0x2000),
            None
        );
        p64(&mut bytes, 0x218, 0x2001);
        let pointers = CodePointers::parse(&bytes, &sections).unwrap();
        assert_eq!(pointers.pointer(&bytes, &sections, 0x2000), None);
        assert_eq!(pointers.pointer(&bytes, &sections, 0x2008), None);
        p64(&mut bytes, 0x218, 0x2008);
        p64(
            &mut bytes,
            0x208,
            (1u64 << 32) | u64::from(elf::R_X86_64_64),
        );
        p64(&mut bytes, 0x210, 0);
        bytes[0x198 + 4] = (elf::STB_GLOBAL << 4) | elf::STT_FUNC;
        assert_eq!(
            CodePointers::parse(&bytes, &sections)
                .unwrap()
                .pointer(&bytes, &sections, 0x2000),
            None
        );
        bytes[0x198 + 5] = elf::STV_HIDDEN;
        assert_eq!(
            CodePointers::parse(&bytes, &sections)
                .unwrap()
                .pointer(&bytes, &sections, 0x2000),
            Some((0x1000, PointerEncoding::LocalSymbol))
        );
    }
    #[test]
    fn malformed_record_width_unknown_writes_and_overflows_fail_closed() {
        let (bytes, sections) = image(false);
        for (at, value) in [(0x300 + 5 * 64 + 56, 8), (0x208, 9999), (0x200, u64::MAX)] {
            let mut bad = bytes.clone();
            p64(&mut bad, at, value);
            assert!(CodePointers::parse(&bad, &sections).is_err());
        }
    }
}
