//! Preflight abbreviation syntax before gimli allocates attribute vectors.
//! Budgets include repeated DIE attribute evaluation and shared-table parsing.
use super::{R, g};
use gimli::{Reader, Section};
use std::{collections::BTreeMap, sync::Arc};
pub(super) const MAX_ATTRIBUTES: usize = 64;
const MAX_TABLE_BYTES: usize = 1024 * 1024;
const MAX_TABLE_ENTRIES: usize = 4096;
/// Charged per table: section bytes, plus 256 per abbreviation and 64 per
/// attribute specification for gimli's maps, records and vectors (above
/// their actual size). A large C++ or Rust image needs a few MiB.
const MAX_CACHE_BYTES: usize = 64 * 1024 * 1024;
/// Specifications parsed across all tables, including failed ones. Each
/// unit of work reads at most about 31 bytes.
const MAX_SPEC_WORK: usize = 16_000_000;
/// DIE attributes preflighted across the index pass.
pub(super) const MAX_ATTRIBUTE_WORK: usize = 64_000_000;
const MAX_FAILED_TABLES: usize = 65_536;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TableError {
    /// This table is unusable; units using other tables still index.
    Malformed,
    /// An aggregate budget is spent; no further table can be prepared.
    Exhausted,
}
#[derive(Default)]
pub(super) struct Tables {
    pub tables: BTreeMap<usize, Arc<g::Abbreviations>>,
    failed: std::collections::BTreeSet<usize>,
    bytes: usize,
    work: usize,
}
impl Tables {
    #[cfg(test)]
    pub(super) fn specification_work(&self) -> usize {
        self.work
    }

    pub fn prepare(
        &mut self,
        dwarf: &mut g::Dwarf<R<'_>>,
        offset: usize,
    ) -> Result<(), TableError> {
        if self.tables.contains_key(&offset) {
            return Ok(());
        }
        if self.failed.contains(&offset) {
            return Err(TableError::Malformed);
        }
        if self.work > MAX_SPEC_WORK || self.failed.len() >= MAX_FAILED_TABLES {
            return Err(TableError::Exhausted);
        }
        let result = self.parse(dwarf, offset);
        if result == Err(TableError::Malformed) {
            self.failed.insert(offset);
        }
        result
    }
    fn parse(&mut self, dwarf: &mut g::Dwarf<R<'_>>, offset: usize) -> Result<(), TableError> {
        use TableError::{Exhausted, Malformed};
        let mut reader = *dwarf.debug_abbrev.reader();
        reader.skip(offset).map_err(|_| Malformed)?;
        reader
            .truncate(reader.len().min(MAX_TABLE_BYTES))
            .map_err(|_| Malformed)?;
        let start = reader.len();
        let mut entries = 0usize;
        let mut specs = 0usize;
        loop {
            if start - reader.len() >= MAX_TABLE_BYTES {
                return Err(Malformed);
            }
            let leb = |reader: &mut R<'_>, signed| {
                super::encodings::leb(reader, signed).map_err(|_| Malformed)
            };
            let code = leb(&mut reader, false)?;
            if code == 0 {
                break;
            }
            entries += 1;
            if entries > MAX_TABLE_ENTRIES {
                return Err(Malformed);
            }
            leb(&mut reader, false)?; // tag
            reader.read_u8().map_err(|_| Malformed)?; // children (gimli validates value)
            let mut attributes = 0;
            loop {
                self.work += 1;
                if self.work > MAX_SPEC_WORK {
                    return Err(Exhausted);
                }
                if start - reader.len() >= MAX_TABLE_BYTES {
                    return Err(Malformed);
                }
                let name = leb(&mut reader, false)?;
                let form = leb(&mut reader, false)?;
                if name == 0 && form == 0 {
                    break;
                }
                attributes += 1;
                specs += 1;
                if attributes > MAX_ATTRIBUTES {
                    return Err(Malformed);
                }
                if form == u64::from(g::DW_FORM_implicit_const.0) {
                    leb(&mut reader, true)?;
                }
            }
        }
        // Include gimli's maps, per-abbreviation records, and attribute vectors;
        // bound allocated metadata as well as bytes consumed from the section.
        let cost = (start - reader.len())
            .checked_add(entries * 256)
            .and_then(|n| n.checked_add(specs * 64))
            .ok_or(Exhausted)?;
        self.bytes = self
            .bytes
            .checked_add(cost)
            .filter(|&n| n <= MAX_CACHE_BYTES)
            .ok_or(Exhausted)?;
        let table = Arc::new(
            dwarf
                .debug_abbrev
                .abbreviations(g::DebugAbbrevOffset(offset))
                .map_err(|_| Malformed)?,
        );
        dwarf
            .abbreviations_cache
            .set::<R<'_>>(g::DebugAbbrevOffset(offset), Arc::clone(&table));
        self.tables.insert(offset, table);
        Ok(())
    }
    pub fn attach(&self, dwarf: &mut g::Dwarf<R<'_>>) {
        for (&offset, table) in &self.tables {
            dwarf
                .abbreviations_cache
                .set::<R<'_>>(g::DebugAbbrevOffset(offset), Arc::clone(table));
        }
    }
}
