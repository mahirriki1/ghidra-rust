//! Preflight every DIE encoding before any eager gimli DIE decoder sees it.
//! This is an allowlist of all forms supported by gimli 0.34's parse_attribute.
//!
//! Form(s)                                      Maximum encoded bytes
//! addr                                        address_size (1/2/4/8)
//! data1/ref1/flag/strx1/addrx1                  1
//! data2/ref2/strx2/addrx2                       2
//! strx3/addrx3                                3
//! data4/ref4/ref_sup4/strx4/addrx4              4
//! data8/ref8/ref_sup8/ref_sig8                  8
//! data16                                      16
//! sec_offset/strp/strp_sup/line_strp/           offset_size (4/8)
//!   GNU_ref_alt/GNU_strp_alt
//! ref_addr                                    address_size in v2, else offset_size
//! udata/sdata/ref_udata/strx/addrx/loclistx/     10 (64-bit LEB, overflow rejected)
//!   rnglistx/GNU_str_index/GNU_addr_index
//! string                                      4096 payload + NUL; bounded scan
//! block1                                      255 payload + 1 length byte
//! block2/block4                               4096 payload + 2/4 length bytes
//! block/exprloc                               4096 payload + <=10 length bytes
//! flag_present/implicit_const                 0 (implicit value: <=10 abbrev bytes)
//! indirect/null/unknown                       rejected; indirect depth = 0
//!
//! Abbreviation codes also use <=10 bytes. A DIE is <=16 KiB and <=64 attrs.
//! Nesting depth is a u8: a 256th level fails its checked increment.
//! Whole-pass byte/attribute/record budgets include null DIEs and zero-byte
//! forms. Boundaries are retained so a forged reference into payload bytes can
//! never enter an unvalidated decoder. No sibling offsets bypass this scan.
use super::{R, abbreviations, g};
use gimli::{Reader, Section};
use std::{ops::Deref, sync::Arc};

pub(super) const MAX_VALUE_BYTES: usize = 4096;
const MAX_DIE_BYTES: usize = 16 * 1024;
pub(super) struct Budget {
    bytes: usize,
    attributes: usize,
    records: usize,
}
impl Budget {
    pub fn index() -> Self {
        Self {
            // An image never exceeds MAX_IMAGE_BYTES, so this covers any
            // whole .debug_info; records and attributes bound the work.
            bytes: crate::analysis::MAX_IMAGE_BYTES as usize,
            attributes: abbreviations::MAX_ATTRIBUTE_WORK,
            records: super::MAX_DIES,
        }
    }
    pub fn lazy() -> Self {
        Self {
            bytes: 8 * 1024 * 1024,
            attributes: 1_000_000,
            records: 262_144,
        }
    }
    pub fn exhausted(&self) -> bool {
        self.bytes == 0 || self.attributes == 0 || self.records == 0
    }
    fn charge(counter: &mut usize, cost: usize) -> Result<(), ()> {
        *counter = counter.checked_sub(cost).ok_or_else(|| {
            *counter = 0;
        })?;
        Ok(())
    }
}

/// The only variable integer decoder used by preflight, including abbrevs.
/// SLEB's tenth payload is either 0 or 0x7f; ULEB's is 0 or 1.
pub(super) fn leb(reader: &mut R<'_>, signed: bool) -> Result<u64, ()> {
    let mut value = 0;
    for i in 0..10 {
        let byte = reader.read_u8().map_err(|_| ())?;
        let payload = byte & 0x7f;
        if i == 9
            && if signed {
                payload != 0 && payload != 0x7f
            } else {
                payload > 1
            }
        {
            return Err(());
        }
        value |= u64::from(payload) << (i * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(())
}

fn form(reader: &mut R<'_>, encoding: g::Encoding, form: g::DwForm) -> Result<(), ()> {
    let offset_size = usize::from(encoding.format.word_size());
    let length = match form {
        g::DW_FORM_addr => match encoding.address_size {
            1 | 2 | 4 | 8 => usize::from(encoding.address_size),
            _ => return Err(()),
        },
        g::DW_FORM_data1
        | g::DW_FORM_ref1
        | g::DW_FORM_flag
        | g::DW_FORM_strx1
        | g::DW_FORM_addrx1 => 1,
        g::DW_FORM_data2 | g::DW_FORM_ref2 | g::DW_FORM_strx2 | g::DW_FORM_addrx2 => 2,
        g::DW_FORM_strx3 | g::DW_FORM_addrx3 => 3,
        g::DW_FORM_data4
        | g::DW_FORM_ref4
        | g::DW_FORM_ref_sup4
        | g::DW_FORM_strx4
        | g::DW_FORM_addrx4 => 4,
        g::DW_FORM_data8 | g::DW_FORM_ref8 | g::DW_FORM_ref_sup8 | g::DW_FORM_ref_sig8 => 8,
        g::DW_FORM_data16 => 16,
        g::DW_FORM_sec_offset
        | g::DW_FORM_strp
        | g::DW_FORM_strp_sup
        | g::DW_FORM_line_strp
        | g::DW_FORM_GNU_ref_alt
        | g::DW_FORM_GNU_strp_alt => offset_size,
        g::DW_FORM_ref_addr => {
            if encoding.version == 2 {
                usize::from(encoding.address_size)
            } else {
                offset_size
            }
        }
        g::DW_FORM_udata
        | g::DW_FORM_ref_udata
        | g::DW_FORM_strx
        | g::DW_FORM_addrx
        | g::DW_FORM_loclistx
        | g::DW_FORM_rnglistx
        | g::DW_FORM_GNU_str_index
        | g::DW_FORM_GNU_addr_index => {
            leb(reader, false)?;
            return Ok(());
        }
        g::DW_FORM_sdata => {
            leb(reader, true)?;
            return Ok(());
        }
        g::DW_FORM_string => {
            // Never scan the entire remaining section, including unused attrs.
            let scan = reader.len().min(MAX_VALUE_BYTES + 1);
            let Some(length) = reader.slice()[..scan].iter().position(|&b| b == 0) else {
                // Account for the scan even when the string is rejected.
                reader.skip(scan).map_err(|_| ())?;
                return Err(());
            };
            length + 1
        }
        g::DW_FORM_block1
        | g::DW_FORM_block2
        | g::DW_FORM_block4
        | g::DW_FORM_block
        | g::DW_FORM_exprloc => {
            let length = match form {
                g::DW_FORM_block1 => u64::from(reader.read_u8().map_err(|_| ())?),
                g::DW_FORM_block2 => u64::from(reader.read_u16().map_err(|_| ())?),
                g::DW_FORM_block4 => u64::from(reader.read_u32().map_err(|_| ())?),
                _ => leb(reader, false)?,
            };
            let length = usize::try_from(length).map_err(|_| ())?;
            if length > MAX_VALUE_BYTES {
                return Err(());
            }
            length
        }
        g::DW_FORM_flag_present | g::DW_FORM_implicit_const => 0,
        // Includes DW_FORM_indirect: reject before reading even its first link.
        _ => return Err(()),
    };
    reader.skip(length).map_err(|_| ())
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Die {
    pub offset: u32,
    pub depth: u8,
    pub tag: g::DwTag,
}
/// Worker-only validation certificate. Pointer values establish identity only;
/// they are never dereferenced. The owning index holds an `Arc` of the
/// immutable image (and of any companion) plus the abbreviation `Arc`s for the
/// certificate's entire lifetime, so a certified allocation is never freed or
/// reused while the certificate exists. A different allocation/table always
/// requires bounded validation again.
pub(super) struct Validated {
    dies: Box<[Die]>,
    pub has_types: bool,
    input: usize,
    length: usize,
    abbreviation: usize,
    offset: g::UnitSectionOffset<usize>,
    encoding: g::Encoding,
}
impl Deref for Validated {
    type Target = [Die];
    fn deref(&self) -> &Self::Target {
        &self.dies
    }
}
impl Validated {
    pub fn matches(&self, header: &g::UnitHeader<R<'_>>, abbrevs: &g::Abbreviations) -> bool {
        header
            .range_from(g::UnitOffset(header.header_size())..)
            .is_ok_and(|reader| {
                self.input == reader.slice().as_ptr() as usize
                    && self.length == reader.len()
                    && self.abbreviation == abbrevs as *const _ as usize
                    && self.offset == header.offset()
                    && self.encoding == header.encoding()
            })
    }
    pub fn allocated_bytes(&self) -> usize {
        256 + self.dies.len() * std::mem::size_of::<Die>()
    }
}
pub(super) fn validate(
    header: &g::UnitHeader<R<'_>>,
    abbrevs: &g::Abbreviations,
    budget: &mut Budget,
) -> Result<Arc<Validated>, ()> {
    if !matches!(header.address_size(), 1 | 2 | 4 | 8) {
        return Err(());
    }
    let mut reader = header
        .range_from(g::UnitOffset(header.header_size())..)
        .map_err(|_| ())?;
    let input = reader.slice().as_ptr() as usize;
    let length = reader.len();
    let end = header.header_size().checked_add(reader.len()).ok_or(())?;
    let mut result = Vec::new();
    let mut depth = 0u8;
    let mut has_types = false;
    while !reader.is_empty() {
        Budget::charge(&mut budget.records, 1)?;
        // Restrict the reader before even the abbreviation code is decoded.
        let offset = end - reader.len();
        let mut bounded = reader;
        bounded
            .truncate(reader.len().min(MAX_DIE_BYTES).min(budget.bytes))
            .map_err(|_| ())?;
        let start = bounded.len();
        let decoded = (|| -> Result<Option<Die>, ()> {
            let code = leb(&mut bounded, false)?;
            if code == 0 {
                depth = depth.checked_sub(1).ok_or(())?;
                Ok(None)
            } else {
                let abbrev = abbrevs.get(code).ok_or(())?;
                if abbrev.attributes().len() > abbreviations::MAX_ATTRIBUTES {
                    return Err(());
                }
                Budget::charge(&mut budget.attributes, abbrev.attributes().len().max(1))?;
                for attr in abbrev.attributes() {
                    form(&mut bounded, header.encoding(), attr.form())?;
                }
                let die = Die {
                    offset: u32::try_from(offset).map_err(|_| ())?,
                    depth,
                    tag: abbrev.tag(),
                };
                if abbrev.has_children() {
                    depth = depth.checked_add(1).ok_or(())?;
                }
                Ok(Some(die))
            }
        })();
        let consumed = start - bounded.len();
        Budget::charge(&mut budget.bytes, consumed)?;
        reader.skip(consumed).map_err(|_| ())?;
        // Failed decoding still spends its bytes and work. Otherwise repeated
        // malformed CUs could repeatedly scan outside the aggregate budget.
        if let Some(die) = decoded? {
            has_types |= matches!(
                die.tag,
                g::DW_TAG_base_type
                    | g::DW_TAG_pointer_type
                    | g::DW_TAG_reference_type
                    | g::DW_TAG_rvalue_reference_type
                    | g::DW_TAG_typedef
                    | g::DW_TAG_structure_type
                    | g::DW_TAG_union_type
                    | g::DW_TAG_class_type
                    | g::DW_TAG_enumeration_type
                    | g::DW_TAG_array_type
                    | g::DW_TAG_subroutine_type
            );
            result.push(die);
        }
    }
    // A CU with an unterminated child list is malformed, even if the last DIE
    // itself fit. A leaf root (depth zero) needs no null terminator.
    if result.is_empty() || depth != 0 {
        return Err(());
    }
    Ok(Arc::new(Validated {
        dies: result.into_boxed_slice(),
        has_types,
        input,
        length,
        abbreviation: abbrevs as *const _ as usize,
        offset: header.offset(),
        encoding: header.encoding(),
    }))
}

/// All referenced string scans are bounded too, before gimli's get_str/attr_string.
/// A name longer than `max` bytes is rejected after scanning at most `max + 1`.
pub(super) fn name<'a>(
    dwarf: &g::Dwarf<R<'a>>,
    unit: &g::Unit<R<'a>>,
    value: g::AttributeValue<R<'a>>,
    max: usize,
) -> Option<String> {
    let (mut reader, offset) = match value {
        g::AttributeValue::String(reader) => {
            if reader.len() > max {
                return None;
            }
            return Some(std::str::from_utf8(reader.slice()).ok()?.to_owned());
        }
        g::AttributeValue::DebugStrRef(offset) => (*dwarf.debug_str.reader(), offset.0),
        g::AttributeValue::DebugLineStrRef(offset) => (*dwarf.debug_line_str.reader(), offset.0),
        g::AttributeValue::DebugStrOffsetsIndex(index) => (
            *dwarf.debug_str.reader(),
            dwarf.string_offset(unit, index).ok()?.0,
        ),
        _ => return None,
    };
    reader.skip(offset).ok()?;
    let length = reader.slice().iter().take(max + 1).position(|&b| b == 0)?;
    Some(std::str::from_utf8(&reader.slice()[..length]).ok()?.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejected_strings_still_exhaust_the_aggregate_work_budget() {
        let mut info = vec![0; 11];
        info[4..6].copy_from_slice(&4u16.to_le_bytes());
        info[10] = 8;
        info.push(1);
        info.extend_from_slice(&[b'x'; 64]);
        let length = (info.len() - 4) as u32;
        info[..4].copy_from_slice(&length.to_le_bytes());
        let abbrev = [1, 0x11, 0, 3, 8, 0, 0, 0];
        let header = g::DebugInfo::new(&info, g::LittleEndian)
            .units()
            .next()
            .unwrap()
            .unwrap();
        let table = g::DebugAbbrev::new(&abbrev, g::LittleEndian)
            .abbreviations(g::DebugAbbrevOffset(0))
            .unwrap();
        let mut budget = Budget {
            bytes: 16,
            attributes: 64,
            records: 64,
        };
        assert!(validate(&header, &table, &mut budget).is_err());
        assert_eq!(
            budget.bytes, 0,
            "the failed scan must consume the allowance"
        );
        assert!(budget.exhausted());
    }
    #[test]
    fn validation_certificates_cannot_be_reused_for_other_bytes_or_tables() {
        let original = [11, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1, b'o', b'k', 0];
        let abbrev = [1, 0x11, 0, 3, 8, 0, 0, 0];
        let mut dwarf = g::Dwarf::load(|id| {
            Ok::<_, g::Error>(R::new(
                match id {
                    g::SectionId::DebugInfo => &original,
                    g::SectionId::DebugAbbrev => &abbrev,
                    _ => &[],
                },
                g::LittleEndian,
            ))
        })
        .unwrap();
        let mut tables = super::super::abbreviations::Tables::default();
        tables.prepare(&mut dwarf, 0).unwrap();
        let header = dwarf.units().next().unwrap().unwrap();
        let unit =
            super::super::units::prototype_unit(&dwarf, header, &mut Budget::lazy()).unwrap();
        assert!(unit.dies.matches(&header, &unit.abbreviations));
        let other_table = dwarf
            .debug_abbrev
            .abbreviations(g::DebugAbbrevOffset(0))
            .unwrap();
        assert!(!unit.dies.matches(&header, &other_table));
        let mut changed = original.to_vec();
        changed[12..].fill(b'x'); // no NUL; the old certificate must not apply
        let mut other = g::Dwarf::load(|id| {
            Ok::<_, g::Error>(R::new(
                match id {
                    g::SectionId::DebugInfo => &changed,
                    g::SectionId::DebugAbbrev => &abbrev,
                    _ => &[],
                },
                g::LittleEndian,
            ))
        })
        .unwrap();
        tables.attach(&mut other);
        let header = other.units().next().unwrap().unwrap();
        assert!(!unit.dies.matches(&header, &unit.abbreviations));
        assert!(
            super::super::units::prototype_unit_cached(
                &other,
                header,
                &mut Budget::lazy(),
                Some(Arc::clone(&unit.dies))
            )
            .is_err()
        );
    }
    #[test]
    fn referenced_strings_and_maximum_inline_payloads_are_bounded() {
        let text = vec![b'x'; 8 * 1024 * 1024];
        let info = [8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1];
        let abbrev = [1, 0x11, 0, 0, 0, 0];
        let offsets = [0; 4];
        let mut dwarf = g::Dwarf::load(|id| {
            Ok::<_, g::Error>(R::new(
                match id {
                    g::SectionId::DebugInfo => &info,
                    g::SectionId::DebugAbbrev => &abbrev,
                    g::SectionId::DebugStr | g::SectionId::DebugLineStr => &text,
                    g::SectionId::DebugStrOffsets => &offsets,
                    _ => &[],
                },
                g::LittleEndian,
            ))
        })
        .unwrap();
        super::super::abbreviations::Tables::default()
            .prepare(&mut dwarf, 0)
            .unwrap();
        let unit = super::super::units::prototype_unit(
            &dwarf,
            dwarf.units().next().unwrap().unwrap(),
            &mut Budget::lazy(),
        )
        .unwrap();
        for value in [
            g::AttributeValue::DebugStrRef(g::DebugStrOffset(0)),
            g::AttributeValue::DebugLineStrRef(g::DebugLineStrOffset(0)),
            g::AttributeValue::DebugStrOffsetsIndex(g::DebugStrOffsetsIndex(0)),
        ] {
            assert!(name(&dwarf, &unit, value, 256).is_none());
        }
        let mut inline = vec![b'x'; 4096];
        inline.push(0);
        let mut reader = R::new(&inline, g::LittleEndian);
        form(&mut reader, unit.encoding(), g::DW_FORM_string).unwrap();
        assert!(reader.is_empty());
        let mut expression = vec![0x80, 0x20]; // ULEB128(4096)
        expression.resize(4098, 0x50);
        let mut reader = R::new(&expression, g::LittleEndian);
        form(&mut reader, unit.encoding(), g::DW_FORM_exprloc).unwrap();
        assert!(reader.is_empty());
    }
    #[test]
    fn all_gimli_forms_have_explicit_bounded_encodings() {
        // Independent DWARF widths, checked against gimli only after preflight.
        for version in [2, 4, 5] {
            for format in [g::Format::Dwarf32, g::Format::Dwarf64] {
                for address_size in [4, 8] {
                    let encoding = g::Encoding {
                        version,
                        format,
                        address_size,
                    };
                    let offset = usize::from(format.word_size());
                    let groups: &[(usize, &[g::DwForm])] = &[
                        (address_size as usize, &[g::DW_FORM_addr]),
                        (
                            1,
                            &[
                                g::DW_FORM_data1,
                                g::DW_FORM_ref1,
                                g::DW_FORM_flag,
                                g::DW_FORM_strx1,
                                g::DW_FORM_addrx1,
                            ],
                        ),
                        (
                            2,
                            &[
                                g::DW_FORM_data2,
                                g::DW_FORM_ref2,
                                g::DW_FORM_strx2,
                                g::DW_FORM_addrx2,
                            ],
                        ),
                        (3, &[g::DW_FORM_strx3, g::DW_FORM_addrx3]),
                        (
                            4,
                            &[
                                g::DW_FORM_data4,
                                g::DW_FORM_ref4,
                                g::DW_FORM_ref_sup4,
                                g::DW_FORM_strx4,
                                g::DW_FORM_addrx4,
                            ],
                        ),
                        (
                            8,
                            &[
                                g::DW_FORM_data8,
                                g::DW_FORM_ref8,
                                g::DW_FORM_ref_sup8,
                                g::DW_FORM_ref_sig8,
                            ],
                        ),
                        (16, &[g::DW_FORM_data16]),
                        (
                            offset,
                            &[
                                g::DW_FORM_sec_offset,
                                g::DW_FORM_strp,
                                g::DW_FORM_strp_sup,
                                g::DW_FORM_line_strp,
                                g::DW_FORM_GNU_ref_alt,
                                g::DW_FORM_GNU_strp_alt,
                            ],
                        ),
                        (
                            if version == 2 {
                                address_size as usize
                            } else {
                                offset
                            },
                            &[g::DW_FORM_ref_addr],
                        ),
                        (
                            1,
                            &[
                                g::DW_FORM_udata,
                                g::DW_FORM_sdata,
                                g::DW_FORM_ref_udata,
                                g::DW_FORM_strx,
                                g::DW_FORM_addrx,
                                g::DW_FORM_loclistx,
                                g::DW_FORM_rnglistx,
                                g::DW_FORM_GNU_str_index,
                                g::DW_FORM_GNU_addr_index,
                                g::DW_FORM_string,
                                g::DW_FORM_block1,
                                g::DW_FORM_block,
                                g::DW_FORM_exprloc,
                            ],
                        ),
                        (2, &[g::DW_FORM_block2]),
                        (4, &[g::DW_FORM_block4]),
                        (0, &[g::DW_FORM_flag_present, g::DW_FORM_implicit_const]),
                    ];
                    let abbrevs = g::Abbreviations::default();
                    for &(width, forms) in groups {
                        for &encoding_form in forms {
                            let bytes = vec![0; width];
                            let mut reader = R::new(&bytes, g::LittleEndian);
                            form(&mut reader, encoding, encoding_form).unwrap();
                            assert!(reader.is_empty(), "{encoding_form}");
                            let mut raw = g::EntriesRaw::new(
                                R::new(&bytes, g::LittleEndian),
                                encoding,
                                &abbrevs,
                                g::UnitOffset(0),
                            );
                            raw.read_attribute(g::AttributeSpecification::new(
                                g::DW_AT_const_value,
                                encoding_form,
                                (encoding_form == g::DW_FORM_implicit_const).then_some(0),
                            ))
                            .unwrap();
                            assert!(raw.is_empty(), "{encoding_form}");
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn variable_forms_reject_excess_lengths_and_leb_overflow_before_gimli() {
        let encoding = g::Encoding {
            version: 4,
            format: g::Format::Dwarf32,
            address_size: 8,
        };
        for encoding_form in [
            g::DW_FORM_udata,
            g::DW_FORM_sdata,
            g::DW_FORM_ref_udata,
            g::DW_FORM_strx,
            g::DW_FORM_addrx,
            g::DW_FORM_loclistx,
            g::DW_FORM_rnglistx,
            g::DW_FORM_GNU_str_index,
            g::DW_FORM_GNU_addr_index,
            g::DW_FORM_block,
            g::DW_FORM_exprloc,
        ] {
            for bytes in [&[0x80; 11][..], &[0xff; 10][..]] {
                assert!(
                    form(&mut R::new(bytes, g::LittleEndian), encoding, encoding_form).is_err(),
                    "{encoding_form}"
                );
            }
        }
        let text = vec![b'x'; MAX_VALUE_BYTES + 2];
        assert!(
            form(
                &mut R::new(&text, g::LittleEndian),
                encoding,
                g::DW_FORM_string
            )
            .is_err()
        );
        for (encoding_form, prefix) in [
            (g::DW_FORM_exprloc, vec![0x81, 0x20]),
            (g::DW_FORM_block, vec![0x81, 0x20]),
            (g::DW_FORM_block2, vec![1, 16]),
            (g::DW_FORM_block4, vec![1, 16, 0, 0]),
        ] {
            let mut bytes = prefix;
            bytes.extend_from_slice(&text);
            assert!(
                form(
                    &mut R::new(&bytes, g::LittleEndian),
                    encoding,
                    encoding_form
                )
                .is_err()
            );
        }
        for encoding_form in [g::DW_FORM_indirect, g::DW_FORM_null, g::DwForm(0xffff)] {
            let mut reader = R::new(&text, g::LittleEndian);
            assert!(form(&mut reader, encoding, encoding_form).is_err());
            assert_eq!(
                reader.len(),
                text.len(),
                "rejected forms must not scan payloads"
            );
        }
    }
}
