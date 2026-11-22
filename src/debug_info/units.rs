//! Prototype-only CU metadata. Never call gimli's eager Unit::new: it loads
//! unused line headers (directory/file vectors), even for unrelated DIEs.
use super::{R, encodings, g};
use std::{ops::Deref, rc::Rc, sync::Arc};
pub(super) struct CheckedUnit<'a> {
    pub unit: g::Unit<R<'a>>,
    pub dies: Arc<encodings::Validated>,
    root: Rc<g::DebuggingInformationEntry<R<'a>>>,
}
impl<'a> Deref for CheckedUnit<'a> {
    type Target = g::Unit<R<'a>>;
    fn deref(&self) -> &Self::Target {
        &self.unit
    }
}
impl<'a> CheckedUnit<'a> {
    pub fn root(&self) -> &g::DebuggingInformationEntry<R<'a>> {
        &self.root
    }
    pub fn position(&self, offset: usize) -> Option<usize> {
        self.dies
            .binary_search_by_key(&offset, |die| die.offset as usize)
            .ok()
    }
    pub fn decoded(&self, offset: usize) -> Option<Rc<g::DebuggingInformationEntry<R<'a>>>> {
        self.position(offset)?;
        if self.root.offset().0 == offset {
            return Some(Rc::clone(&self.root));
        }
        // Every encoding in this CU was bounded before any entry() call. A
        // forged reference into a string/block is rejected by position().
        Some(Rc::new(self.unit.entry(g::UnitOffset(offset)).ok()?))
    }
}
pub(super) fn prototype_unit<'a>(
    dwarf: &g::Dwarf<R<'a>>,
    header: g::UnitHeader<R<'a>>,
    budget: &mut encodings::Budget,
) -> Result<CheckedUnit<'a>, ()> {
    prototype_unit_cached(dwarf, header, budget, None)
}
pub(super) fn prototype_unit_cached<'a>(
    dwarf: &g::Dwarf<R<'a>>,
    header: g::UnitHeader<R<'a>>,
    budget: &mut encodings::Budget,
    validated: Option<Arc<encodings::Validated>>,
) -> Result<CheckedUnit<'a>, ()> {
    // Abbreviations were preflighted and cached at index time. Reading a root
    // below parses at most MAX_ATTRIBUTES fields. No line/string tables, list
    // headers, DWO files or supplementary files are loaded here.
    if !matches!(
        header.type_(),
        g::UnitType::Compilation | g::UnitType::Partial
    ) {
        return Err(());
    }
    let abbreviations = dwarf.abbreviations(&header).map_err(|_| ())?;
    let dies = match validated.filter(|checked| checked.matches(&header, &abbreviations)) {
        Some(checked) => checked,
        None => encodings::validate(&header, &abbreviations, budget)?,
    };
    let root = Rc::new(
        header
            .entry(&abbreviations, g::UnitOffset(dies[0].offset as usize))
            .map_err(|_| ())?,
    );
    let encoding = header.encoding();
    let mut unit = g::Unit {
        abbreviations,
        header,
        name: None,
        comp_dir: None,
        line_program: None,
        dwo_id: None,
        low_pc: 0,
        str_offsets_base: g::DebugStrOffsetsBase::default_for_encoding_and_file(
            encoding,
            dwarf.file_type,
        ),
        addr_base: g::DebugAddrBase(0),
        loclists_base: g::DebugLocListsBase::default_for_encoding_and_file(
            encoding,
            dwarf.file_type,
        ),
        rnglists_base: g::DebugRngListsBase::default_for_encoding_and_file(
            encoding,
            dwarf.file_type,
        ),
    };
    let low_pc = {
        let mut low_pc = None;
        let mut str_base = unit.str_offsets_base;
        let mut addr_base = unit.addr_base;
        let mut loc_base = unit.loclists_base;
        let mut rng_base = unit.rnglists_base;
        for attr in root.attrs() {
            match attr.value() {
                g::AttributeValue::DebugStrOffsetsBase(value)
                    if attr.name() == g::DW_AT_str_offsets_base =>
                {
                    str_base = value
                }
                g::AttributeValue::DebugAddrBase(value)
                    if matches!(attr.name(), g::DW_AT_addr_base | g::DW_AT_GNU_addr_base) =>
                {
                    addr_base = value
                }
                g::AttributeValue::DebugLocListsBase(value)
                    if attr.name() == g::DW_AT_loclists_base =>
                {
                    loc_base = value
                }
                g::AttributeValue::DebugRngListsBase(value)
                    if matches!(
                        attr.name(),
                        g::DW_AT_rnglists_base | g::DW_AT_GNU_ranges_base
                    ) =>
                {
                    rng_base = value
                }
                value if attr.name() == g::DW_AT_low_pc => low_pc = Some(value),
                _ => (),
            }
        }
        unit.str_offsets_base = str_base;
        unit.addr_base = addr_base;
        unit.loclists_base = loc_base;
        unit.rnglists_base = rng_base;
        low_pc
    };
    // addrx resolves with a checked, fixed-width read; it parses no header or
    // collection. strx/loclistx are likewise resolved only when actually used.
    if let Some(value) = low_pc {
        unit.low_pc = dwarf
            .attr_address(&unit, value)
            .map_err(|_| ())?
            .ok_or(())?;
    }
    Ok(CheckedUnit { unit, dies, root })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_used_numeric_bases_and_fixed_address_reads_are_evaluated() {
        let abbrev = [
            1, 0x11, 0, 0x10, 0x17, 0x72, 0x17, 0x73, 0x17, 0x8c, 1, 0x17, 0x74, 0x17, 0x11, 0x1b,
            3, 0x1a, 0x1b, 0x1a, 0, 0, 0,
        ];
        let mut info = vec![0; 12];
        info[4..6].copy_from_slice(&5u16.to_le_bytes());
        info[6] = 1;
        info[7] = 8;
        info.push(1);
        info.extend_from_slice(&0u32.to_le_bytes()); // stmt_list: deliberately bad line header
        for base in [0u32, 0, 0, 0] {
            info.extend_from_slice(&base.to_le_bytes());
        }
        info.extend_from_slice(&[0, 0, 0]); // low_pc=addrx(0); ignored name/comp_dir=strx(0)
        let length = (info.len() - 4) as u32;
        info[..4].copy_from_slice(&length.to_le_bytes());
        let address = 0x401000u64.to_le_bytes();
        let poison = [0xff; 32];
        let mut dwarf = g::Dwarf::load(|id| {
            Ok::<_, g::Error>(R::new(
                match id {
                    g::SectionId::DebugInfo => &info,
                    g::SectionId::DebugAbbrev => &abbrev,
                    g::SectionId::DebugAddr => &address,
                    g::SectionId::DebugLine
                    | g::SectionId::DebugStrOffsets
                    | g::SectionId::DebugLocLists
                    | g::SectionId::DebugRngLists => &poison,
                    _ => &[],
                },
                g::LittleEndian,
            ))
        })
        .unwrap();
        let mut tables = crate::debug_info::abbreviations::Tables::default();
        tables.prepare(&mut dwarf, 0).unwrap();
        let unit = prototype_unit(
            &dwarf,
            dwarf.units().next().unwrap().unwrap(),
            &mut encodings::Budget::lazy(),
        )
        .unwrap();
        assert_eq!(unit.low_pc, 0x401000);
        assert!(unit.line_program.is_none() && unit.name.is_none() && unit.comp_dir.is_none());
        assert_eq!(unit.addr_base.0, 0);
        assert_eq!(unit.str_offsets_base.0, 0);
        assert_eq!(unit.loclists_base.0, 0);
        assert_eq!(unit.rnglists_base.0, 0);
        let resolver = crate::debug_info::Resolver::new(&dwarf, &[0]);
        let first = resolver.unit((0, 0)).unwrap();
        let second = resolver.unit((0, 0)).unwrap();
        assert!(std::rc::Rc::ptr_eq(&first, &second));
    }
}
