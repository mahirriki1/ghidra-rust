//! File offset ↔ address mapping over the published section table.
//!
//! Only `BinaryInfo.sections` and `file_len` are consulted: nothing reads or
//! parses the binary. The table is section-based, so bytes outside every
//! section (headers, load commands, padding, non-loaded sections, overlays)
//! have no address, and zero-filled memory has no file offset. Every range is
//! re-checked with checked arithmetic, and an overflowing section is a
//! non-match, so the functions are total on untrusted input.

use crate::model::SectionInfo;

/// Where a file offset is loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileAddress {
    One(u64),
    /// Two or more sections back the byte: the two lowest addresses, and
    /// whether further sections back it too.
    Several {
        first: u64,
        second: u64,
        more: bool,
    },
    Unmapped(Unmapped),
}

/// Why a file offset has no address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unmapped {
    /// At or beyond the file length.
    PastEnd,
    /// No section has file bytes.
    NoSectionBytes,
    /// Before the first section's bytes: file headers, and any padding or
    /// non-loaded bytes before the first section (the section table cannot
    /// tell them apart).
    BeforeSections,
    /// Between sections: padding, or bytes that are not loaded.
    Gap,
    /// After the last section's bytes: non-loaded sections, tables, overlays.
    Trailing,
}

impl Unmapped {
    pub fn reason(self) -> &'static str {
        match self {
            Self::PastEnd => "File offset is past the end of the file",
            Self::NoSectionBytes => "No section has file bytes",
            Self::BeforeSections => "File offset is before every loaded section and has no address",
            Self::Gap => "File offset is between sections and has no address",
            Self::Trailing => "File offset is after every loaded section",
        }
    }
}

impl SectionInfo {
    /// The file offset of `address` when this section's file bytes back it.
    /// A section whose address or file range wraps backs nothing.
    pub fn file_offset_at(&self, address: u64) -> Option<u64> {
        let backed = self.size.min(self.file_size);
        self.address.checked_add(backed)?;
        self.file_offset.checked_add(backed)?;
        let relative = address.checked_sub(self.address)?;
        (relative < backed)
            .then(|| self.file_offset.checked_add(relative))
            .flatten()
    }
}

/// The address that file byte `offset` is loaded at. One bounded pass over
/// the sections; nothing proportional to the input is allocated.
pub fn address_at(sections: &[SectionInfo], file_len: u64, offset: u64) -> FileAddress {
    if offset >= file_len {
        return FileAddress::Unmapped(Unmapped::PastEnd);
    }
    let mut hits: [Option<u64>; 2] = [None, None];
    let mut more = false;
    // File extent of all sections' bytes, for the reason of a miss.
    let mut extent: Option<(u64, u64)> = None;
    for section in sections {
        let backed = section.size.min(section.file_size);
        if backed == 0 {
            continue;
        }
        let Some(file_end) = section.file_offset.checked_add(backed) else {
            continue;
        };
        if section.address.checked_add(backed).is_none() {
            continue;
        }
        extent = Some(
            extent.map_or((section.file_offset, file_end), |(low, high)| {
                (low.min(section.file_offset), high.max(file_end))
            }),
        );
        let Some(address) = offset
            .checked_sub(section.file_offset)
            .filter(|&relative| relative < backed)
            .and_then(|relative| section.address.checked_add(relative))
        else {
            continue;
        };
        match hits {
            [None, _] => hits[0] = Some(address),
            [Some(first), None] => hits = [Some(first.min(address)), Some(first.max(address))],
            [Some(first), Some(second)] => {
                more = true;
                hits = if address < first {
                    [Some(address), Some(first)]
                } else if address < second {
                    [Some(first), Some(address)]
                } else {
                    hits
                };
            }
        }
    }
    match (hits, extent) {
        ([Some(address), None], _) => FileAddress::One(address),
        ([Some(first), Some(second)], _) => FileAddress::Several {
            first,
            second,
            more,
        },
        (_, None) => FileAddress::Unmapped(Unmapped::NoSectionBytes),
        (_, Some((low, _))) if offset < low => FileAddress::Unmapped(Unmapped::BeforeSections),
        (_, Some((_, high))) if offset >= high => FileAddress::Unmapped(Unmapped::Trailing),
        _ => FileAddress::Unmapped(Unmapped::Gap),
    }
}

/// The file offset of `address`, from the address-ordered sections. O(log n),
/// so it is cheap every frame. Zero-fill, gaps and an inconsistent ordering
/// give `None`, never a neighbouring section's offset.
pub fn offset_of(sections: &[SectionInfo], address: u64) -> Option<u64> {
    let index = sections.partition_point(|section| section.address <= address);
    sections.get(index.checked_sub(1)?)?.file_offset_at(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(address: u64, size: u64, file_offset: u64, file_size: u64) -> SectionInfo {
        SectionInfo {
            name: format!("s{address:x}"),
            address,
            size,
            file_offset,
            file_size,
            executable: false,
        }
    }

    fn unmapped(reason: Unmapped) -> FileAddress {
        FileAddress::Unmapped(reason)
    }

    #[test]
    fn sections_with_different_deltas_map_both_ways_up_to_their_last_byte() {
        // A text-like section 0x400000 above its bytes, then data 0x401000 above.
        let sections = [
            section(0x401000, 0x200, 0x1000, 0x200),
            section(0x404000, 0x30, 0x3000, 0x30),
        ];
        for (offset, address) in [
            (0x1000, 0x401000),
            (0x11ff, 0x4011ff),
            (0x3000, 0x404000),
            (0x302f, 0x40402f),
        ] {
            assert_eq!(
                address_at(&sections, 0x4000, offset),
                FileAddress::One(address)
            );
            assert_eq!(offset_of(&sections, address), Some(offset));
        }
        assert_eq!(
            address_at(&sections, 0x4000, 0x1200),
            unmapped(Unmapped::Gap)
        );
        assert_eq!(
            address_at(&sections, 0x4000, 0x3030),
            unmapped(Unmapped::Trailing)
        );
        assert_eq!(
            address_at(&sections, 0x4000, 0),
            unmapped(Unmapped::BeforeSections)
        );
        assert_eq!(
            address_at(&sections, 0x4000, 0xfff),
            unmapped(Unmapped::BeforeSections)
        );
        assert_eq!(offset_of(&sections, 0x401200), None);
        assert_eq!(offset_of(&sections, 0x400fff), None);
        assert_eq!(offset_of(&sections, 0x404030), None);
    }

    #[test]
    fn zero_fill_never_claims_an_offset_and_has_none() {
        // `.bss`-like sections are published at offset 0, or (as ELF places
        // them) at the next section's offset, with no file bytes.
        let sections = [
            section(0x1000, 0x100, 0x100, 0x100),
            section(0x2000, 0x100, 0, 0),
            section(0x3000, 0x100, 0x200, 0),
            section(0x4000, 0x100, 0x200, 0x100),
        ];
        assert_eq!(
            address_at(&sections, 0x300, 0),
            unmapped(Unmapped::BeforeSections)
        );
        assert_eq!(
            address_at(&sections, 0x300, 0x200),
            FileAddress::One(0x4000)
        );
        for address in [0x2000, 0x20ff, 0x3000, 0x30ff] {
            assert_eq!(offset_of(&sections, address), None, "{address:#x}");
        }
        assert_eq!(
            address_at(&[section(0x2000, 0x100, 0, 0)], 0x300, 0),
            unmapped(Unmapped::NoSectionBytes)
        );
    }

    #[test]
    fn a_partly_backed_section_has_no_offset_in_its_virtual_tail() {
        let sections = [section(0x5000, 0x2000, 0x400, 0x200)];
        assert_eq!(offset_of(&sections, 0x51ff), Some(0x5ff));
        assert_eq!(offset_of(&sections, 0x5200), None);
        assert_eq!(offset_of(&sections, 0x6fff), None);
        assert_eq!(
            address_at(&sections, 0x1000, 0x5ff),
            FileAddress::One(0x51ff)
        );
        // The raw byte after the backed bytes belongs to no address.
        assert_eq!(
            address_at(&sections, 0x1000, 0x600),
            unmapped(Unmapped::Trailing)
        );
        // A file size beyond the section size backs only the section size.
        let sections = [section(0x5000, 0x10, 0x400, 0x200)];
        assert_eq!(
            address_at(&sections, 0x1000, 0x410),
            unmapped(Unmapped::Trailing)
        );
        assert_eq!(offset_of(&sections, 0x5010), None);
    }

    #[test]
    fn shared_bytes_name_the_two_lowest_addresses() {
        let two = [
            section(0x1000, 0x100, 0x200, 0x100),
            section(0x8000, 0x100, 0x280, 0x100),
        ];
        assert_eq!(
            address_at(&two, 0x1000, 0x290),
            FileAddress::Several {
                first: 0x1090,
                second: 0x8010,
                more: false
            }
        );
        // Bytes only one section backs still map uniquely.
        assert_eq!(address_at(&two, 0x1000, 0x27f), FileAddress::One(0x107f));
        assert_eq!(address_at(&two, 0x1000, 0x300), FileAddress::One(0x8080));
        // A third sharer, even listed out of order, keeps the lowest two.
        let three = [
            section(0x8000, 0x100, 0x280, 0x100),
            section(0x9000, 0x100, 0x200, 0x100),
            section(0x1000, 0x100, 0x200, 0x100),
        ];
        assert_eq!(
            address_at(&three, 0x1000, 0x290),
            FileAddress::Several {
                first: 0x1090,
                second: 0x8010,
                more: true
            }
        );
    }

    #[test]
    fn the_end_of_the_file_and_overflowing_ranges_never_resolve() {
        let sections = [section(0x1000, 0x100, 0, 0x100)];
        assert_eq!(
            address_at(&sections, 0x100, 0x100),
            unmapped(Unmapped::PastEnd)
        );
        assert_eq!(
            address_at(&sections, 0x100, u64::MAX),
            unmapped(Unmapped::PastEnd)
        );
        assert_eq!(address_at(&sections, 0, 0), unmapped(Unmapped::PastEnd));
        // A file range or an address range that wraps is not a section.
        let wrapping = [
            section(0x1000, 0x100, u64::MAX - 0x10, 0x100),
            section(u64::MAX - 0x10, 0x100, 0x10, 0x100),
        ];
        for offset in [0, 0x10, 0x20, u64::MAX - 1] {
            assert_eq!(
                address_at(&wrapping, u64::MAX, offset),
                unmapped(Unmapped::NoSectionBytes),
                "{offset:#x}"
            );
        }
        assert_eq!(offset_of(&wrapping, 0x1000), None);
        assert_eq!(offset_of(&wrapping, u64::MAX), None);
        // Ranges may end exactly at u64::MAX.
        let edge = [section(u64::MAX - 0x10, 0x10, u64::MAX - 0x10, 0x10)];
        assert_eq!(
            address_at(&edge, u64::MAX, u64::MAX - 1),
            FileAddress::One(u64::MAX - 1)
        );
        assert_eq!(offset_of(&edge, u64::MAX - 1), Some(u64::MAX - 1));
        assert_eq!(offset_of(&edge, u64::MAX), None);
    }

    #[test]
    fn every_section_edge_of_a_full_inventory_round_trips() {
        // 4096 sections, alternating deltas, zero-fill tails and gaps, as
        // validated tables allow.
        let sections: Vec<_> = (0..crate::model::MAX_SECTIONS as u64)
            .map(|index| {
                let file_size = if index % 3 == 0 { 0 } else { 0x40 };
                section(
                    0x10_0000 + index * 0x1000,
                    0x80,
                    0x400 + index * 0x50,
                    file_size,
                )
            })
            .collect();
        let file_len = 0x400 + crate::model::MAX_SECTIONS as u64 * 0x50;
        for section in &sections {
            let last = section.address + 0x3f;
            for address in [section.address, last] {
                match offset_of(&sections, address) {
                    Some(offset) => {
                        assert_ne!(section.file_size, 0);
                        assert_eq!(
                            address_at(&sections, file_len, offset),
                            FileAddress::One(address)
                        );
                    }
                    None => assert_eq!(section.file_size, 0),
                }
            }
            assert_eq!(offset_of(&sections, section.address + 0x40), None);
            assert_eq!(offset_of(&sections, section.address + 0x800), None);
        }
    }
}
