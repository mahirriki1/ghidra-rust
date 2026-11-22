//! Count raw records (including base selections), not yielded locations. A
//! bounded reader prevents a single expression from bypassing the byte budget.
use super::{R, g};
use gimli::Reader;
use std::collections::BTreeMap;
const MAX_LIST_RECORDS: usize = 64;
const MAX_LIST_BYTES: usize = 8 * 1024;
const MAX_FUNCTION_RECORDS: usize = 256;
const MAX_FUNCTION_BYTES: usize = 32 * 1024;
// Any raw record's non-expression fields fit in 64 bytes: a tag, up to
// three 10-byte LEB values, or two 8-byte addresses and a length.
const RAW_HEADER_BOUND: usize = 64;
#[derive(Default)]
pub(super) struct Locations<'a> {
    records: usize,
    bytes: usize,
    cache: BTreeMap<(usize, usize), Option<g::Expression<R<'a>>>>,
}
impl<'a> Locations<'a> {
    pub fn at_entry(
        &mut self,
        dwarf: &g::Dwarf<R<'a>>,
        unit: &g::Unit<R<'a>>,
        unit_offset: usize,
        value: g::AttributeValue<R<'a>>,
        entry: u64,
    ) -> Result<Option<g::Expression<R<'a>>>, ()> {
        let offset = dwarf
            .attr_locations_offset(unit, value)
            .map_err(|_| ())?
            .ok_or(())?;
        if let Some(expression) = self.cache.get(&(unit_offset, offset.0)) {
            return Ok(*expression);
        }
        let allowance = MAX_LIST_BYTES.min(MAX_FUNCTION_BYTES.checked_sub(self.bytes).ok_or(())?);
        let end = offset.0.checked_add(allowance).ok_or(())?;
        let bounded = dwarf.locations.borrow(|reader| {
            let mut reader = *reader;
            reader
                .truncate(reader.len().min(end))
                .expect("truncate only shrinks a reader");
            reader
        });
        let mut list = bounded
            .locations(
                offset,
                unit.encoding(),
                unit.low_pc,
                &dwarf.debug_addr,
                unit.addr_base,
            )
            .map_err(|_| ())?;
        let mut bytes = 0usize;
        let mut found = None;
        // Include the terminating record in both budgets. If a truncated
        // reader reaches EOF, conservative byte charges exhaust the budget
        // before it can be mistaken for a harmless missing entry location.
        for _ in 0..MAX_LIST_RECORDS {
            self.records += 1;
            self.bytes += RAW_HEADER_BOUND;
            bytes += RAW_HEADER_BOUND;
            if self.records > MAX_FUNCTION_RECORDS
                || self.bytes > MAX_FUNCTION_BYTES
                || bytes > allowance
            {
                return Err(());
            }
            let Some(raw) = list.next_raw().map_err(|_| ())? else {
                self.cache.insert((unit_offset, offset.0), found);
                return Ok(found);
            };
            let data_bytes = match &raw {
                g::RawLocListEntry::BaseAddress { .. }
                | g::RawLocListEntry::BaseAddressx { .. } => 0,
                g::RawLocListEntry::AddressOrOffsetPair { data, .. }
                | g::RawLocListEntry::StartxEndx { data, .. }
                | g::RawLocListEntry::StartxLength { data, .. }
                | g::RawLocListEntry::OffsetPair { data, .. }
                | g::RawLocListEntry::DefaultLocation { data }
                | g::RawLocListEntry::StartEnd { data, .. }
                | g::RawLocListEntry::StartLength { data, .. } => data.0.len(),
            };
            self.bytes = self.bytes.checked_add(data_bytes).ok_or(())?;
            bytes = bytes.checked_add(data_bytes).ok_or(())?;
            if self.bytes > MAX_FUNCTION_BYTES || bytes > allowance {
                return Err(());
            }
            if let Some(location) = list.convert_raw(raw).map_err(|_| ())?
                && location.range.begin <= entry
                && entry < location.range.end
            {
                if found.is_some() {
                    return Err(());
                }
                found = Some(location.data);
            }
        }
        Err(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dwarf(version: u16, locations: &[u8]) -> g::Dwarf<R<'_>> {
        let info4 = &[8, 0, 0, 0, 4, 0, 0, 0, 0, 0, 8, 1][..];
        let info5 = &[9, 0, 0, 0, 5, 0, 1, 8, 0, 0, 0, 0, 1][..];
        let abbrev = &[1, 0x11, 0, 0, 0, 0][..];
        g::Dwarf::load(|id| {
            Ok::<_, g::Error>(R::new(
                match id {
                    g::SectionId::DebugInfo => {
                        if version == 4 {
                            info4
                        } else {
                            info5
                        }
                    }
                    g::SectionId::DebugAbbrev => abbrev,
                    g::SectionId::DebugLoc if version == 4 => locations,
                    g::SectionId::DebugLocLists if version == 5 => locations,
                    _ => &[],
                },
                g::LittleEndian,
            ))
        })
        .unwrap()
    }
    fn unit<'a>(dwarf: &mut g::Dwarf<R<'a>>) -> g::Unit<R<'a>> {
        let mut tables = super::super::abbreviations::Tables::default();
        tables.prepare(dwarf, 0).unwrap();
        super::super::units::prototype_unit(
            dwarf,
            dwarf.units().next().unwrap().unwrap(),
            &mut super::super::encodings::Budget::lazy(),
        )
        .unwrap()
        .unit
    }
    #[test]
    fn raw_base_records_are_bounded_for_both_location_encodings() {
        for version in [4, 5] {
            let mut data = Vec::new();
            for _ in 0..100_000 {
                if version == 4 {
                    data.extend_from_slice(&u64::MAX.to_le_bytes());
                } else {
                    data.push(g::DW_LLE_base_address.0);
                }
                data.extend_from_slice(&0x401000u64.to_le_bytes());
            }
            if version == 4 {
                data.extend_from_slice(&[0; 16]);
            } else {
                data.push(g::DW_LLE_end_of_list.0);
            }
            let mut dwarf = dwarf(version, &data);
            let unit = unit(&mut dwarf);
            let mut work = Locations::default();
            assert!(
                work.at_entry(
                    &dwarf,
                    &unit,
                    0,
                    g::AttributeValue::LocationListsRef(g::LocationListsOffset(0)),
                    0x401000
                )
                .is_err()
            );
            assert!(work.records <= MAX_LIST_RECORDS && work.bytes <= MAX_FUNCTION_BYTES);
        }
    }
    #[test]
    fn oversized_expressions_are_rejected_before_decoding_and_shared_lists_are_cached() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x401000u64.to_le_bytes());
        data.extend_from_slice(&0x401004u64.to_le_bytes());
        data.extend_from_slice(&9000u16.to_le_bytes());
        data.resize(data.len() + 9000, 0x50);
        data.extend_from_slice(&[0; 16]);
        let mut oversized = dwarf(4, &data);
        let unit = unit(&mut oversized);
        let mut work = Locations::default();
        assert!(
            work.at_entry(
                &oversized,
                &unit,
                0,
                g::AttributeValue::LocationListsRef(g::LocationListsOffset(0)),
                0x401000
            )
            .is_err()
        );
        data.clear();
        data.extend_from_slice(&0x401000u64.to_le_bytes());
        data.extend_from_slice(&0x401004u64.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0x50);
        data.extend_from_slice(&[0; 16]);
        let mut dwarf = dwarf(4, &data);
        let unit = super::tests::unit(&mut dwarf);
        let mut work = Locations::default();
        let value = g::AttributeValue::LocationListsRef(g::LocationListsOffset(0));
        assert!(
            work.at_entry(&dwarf, &unit, 0, value, 0x401000)
                .unwrap()
                .is_some()
        );
        let charged = (work.records, work.bytes);
        for _ in 0..32 {
            assert!(
                work.at_entry(&dwarf, &unit, 0, value, 0x401000)
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(charged, (work.records, work.bytes));
    }
}
