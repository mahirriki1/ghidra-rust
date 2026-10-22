//! Exact, bounded links between decompiler UTF-8 spans and machine instructions.
use crate::model::{
    CodeMapping, MAX_CODE_ADDRESS_REFS, MAX_CODE_MAPPINGS, MAX_MAPPING_ADDRESSES, SectionInfo,
};
use std::collections::BTreeSet;
use std::ops::Range;

/// Checked, merged executable intervals. Repeated PC lookups are logarithmic in
/// the section count instead of multiplying both public collection budgets.
pub(crate) struct ExecutableRanges(Vec<(u64, u64)>);

impl ExecutableRanges {
    pub(crate) fn new(sections: &[SectionInfo]) -> Result<Self, String> {
        let mut intervals = Vec::new();
        for section in sections.iter().filter(|section| section.executable) {
            let length = section.size.min(section.file_size);
            let end = section
                .address
                .checked_add(length)
                .ok_or("Executable section address overflows")?;
            if length != 0 {
                intervals.push((section.address, end));
            }
        }
        intervals.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
        for (start, end) in intervals {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(Self(merged))
    }

    pub(crate) fn contains(&self, address: u64) -> bool {
        self.contains_with(address, || {})
    }

    fn contains_with(&self, address: u64, mut probe: impl FnMut()) -> bool {
        let index = self.0.partition_point(|(start, _)| {
            probe();
            *start <= address
        });
        index > 0 && address < self.0[index - 1].1
    }
}

/// Checked, merged virtual-address intervals of all mapped sections, including
/// zero-filled tails. Spans may cross contiguous sections but never gaps, and
/// each lookup is logarithmic in the section count.
pub(crate) struct MappedRanges(Vec<(u64, u64)>);

impl MappedRanges {
    pub(crate) fn new(sections: &[SectionInfo]) -> Result<Self, String> {
        let mut intervals = Vec::with_capacity(sections.len());
        for section in sections {
            let end = section
                .address
                .checked_add(section.size)
                .ok_or("Mapped section range overflows the address space")?;
            if section.size != 0 {
                intervals.push((section.address, end));
            }
        }
        intervals.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(intervals.len());
        for (start, end) in intervals {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        Ok(Self(merged))
    }

    pub(crate) fn contains(&self, address: u64) -> bool {
        self.interval(address).is_some()
    }

    /// Whether every byte of a non-empty span is mapped. Overflowing spans are not.
    pub(crate) fn contains_span(&self, address: u64, length: u64) -> bool {
        length != 0
            && address
                .checked_add(length)
                .is_some_and(|end| self.interval(address).is_some_and(|last| end <= last))
    }

    fn interval(&self, address: u64) -> Option<u64> {
        let index = self.0.partition_point(|(start, _)| *start <= address);
        let (_, end) = *self.0.get(index.checked_sub(1)?)?;
        (address < end).then_some(end)
    }
}

pub fn validate_mappings(
    text: &str,
    mappings: &[CodeMapping],
    sections: &[SectionInfo],
) -> Result<(), String> {
    if mappings.len() > MAX_CODE_MAPPINGS {
        return Err("Decompiler mapping count exceeds its limit".into());
    }
    let executable = ExecutableRanges::new(sections)?;
    let mut previous = 0;
    let mut references = 0usize;
    for mapping in mappings {
        if mapping.start < previous
            || mapping.start >= mapping.end
            || mapping.end > text.len()
            || !text.is_char_boundary(mapping.start)
            || !text.is_char_boundary(mapping.end)
        {
            return Err(
                "Decompiler mapping has invalid, overlapping, or non-UTF-8 text ranges".into(),
            );
        }
        if mapping.addresses.is_empty() || mapping.addresses.len() > MAX_MAPPING_ADDRESSES {
            return Err("Decompiler mapping address count exceeds its limit".into());
        }
        references += mapping.addresses.len();
        if references > MAX_CODE_ADDRESS_REFS {
            return Err("Decompiler mapping address references exceed their limit".into());
        }
        let mut seen = BTreeSet::new();
        for &address in &mapping.addresses {
            if !seen.insert(address) {
                return Err("Decompiler mapping contains duplicate instruction addresses".into());
            }
            if !executable.contains(address) {
                return Err("Decompiler mapping contains an unmapped instruction address".into());
            }
        }
        previous = mapping.end;
    }
    Ok(())
}

#[derive(Default)]
pub struct SemanticSelection {
    pub mappings: Vec<CodeMapping>,
    pub addresses: BTreeSet<u64>,
    pub ranges: Vec<Range<usize>>,
}
impl SemanticSelection {
    pub fn clear(&mut self) {
        *self = Self::default();
    }
    pub fn select_instruction(&mut self, address: u64) {
        self.addresses.clear();
        self.addresses.insert(address);
        self.update_ranges();
    }
    /// Engine addresses printed for exactly the expression at `byte`.
    pub fn addresses_at(&self, byte: usize) -> &[u64] {
        let index = self.mappings.partition_point(|m| m.end <= byte);
        self.mappings
            .get(index)
            .filter(|m| m.start <= byte && byte < m.end)
            .map_or(&[], |m| m.addresses.as_slice())
    }
    pub fn select_code(&mut self, byte: usize) -> Option<u64> {
        let index = self.mappings.partition_point(|m| m.end <= byte);
        let mapping = self
            .mappings
            .get(index)
            .filter(|m| m.start <= byte && byte < m.end)?;
        let primary = mapping
            .addresses
            .iter()
            .find(|a| self.addresses.contains(a))
            .copied()
            .or_else(|| mapping.addresses.first().copied())?;
        self.addresses = mapping.addresses.iter().copied().collect();
        self.update_ranges();
        Some(primary)
    }
    fn update_ranges(&mut self) {
        self.ranges = self
            .mappings
            .iter()
            .filter(|m| m.addresses.iter().any(|a| self.addresses.contains(a)))
            .map(|m| m.start..m.end)
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_ranges_cross_contiguous_sections_but_not_gaps() {
        let section = |address, size| SectionInfo {
            name: String::new(),
            address,
            size,
            file_offset: 0,
            file_size: 0,
            executable: false,
        };
        // Unordered input; 0x1000..0x1010 is contiguous, then a gap.
        let ranges =
            MappedRanges::new(&[section(0x1008, 8), section(0x1000, 8), section(0x2000, 4)])
                .unwrap();
        assert!(ranges.contains(0x1000) && ranges.contains(0x100f) && ranges.contains(0x2003));
        assert!(!ranges.contains(0x0fff) && !ranges.contains(0x1010) && !ranges.contains(0x2004));
        assert!(ranges.contains_span(0x1004, 12));
        assert!(!ranges.contains_span(0x1004, 13));
        assert!(!ranges.contains_span(0x1000, 0));
        assert!(!ranges.contains_span(0x2000, u64::MAX));
        assert!(MappedRanges::new(&[section(u64::MAX - 1, 4)]).is_err());
    }

    #[test]
    fn maximum_mapping_references_use_a_logarithmic_section_lookup_budget() {
        let sections: Vec<_> = (0..4096_u64)
            .map(|index| SectionInfo {
                name: format!("section{index}"),
                address: 0x1000 + index * 0x100,
                size: 16,
                file_offset: 0,
                file_size: 16,
                executable: true,
            })
            .collect();
        let intervals = ExecutableRanges::new(&sections).unwrap();
        let address = sections.last().unwrap().address;
        let mut probes = 0;
        for _ in 0..MAX_CODE_ADDRESS_REFS {
            assert!(intervals.contains_with(address, || probes += 1));
        }
        assert!(probes <= MAX_CODE_ADDRESS_REFS * 14);
        assert!(!intervals.contains(address + 16));
        let text = "x ".repeat(MAX_CODE_MAPPINGS);
        let mappings: Vec<_> = (0..MAX_CODE_MAPPINGS)
            .map(|index| CodeMapping {
                start: index * 2,
                end: index * 2 + 1,
                addresses: vec![address, address + 1, address + 2, address + 3],
            })
            .collect();
        validate_mappings(&text, &mappings, &sections).unwrap();
        let mut overflowing = sections[0].clone();
        overflowing.address = u64::MAX;
        assert!(ExecutableRanges::new(&[overflowing]).is_err());
    }
    fn sections() -> Vec<SectionInfo> {
        vec![SectionInfo {
            name: "code".into(),
            address: 0x1000,
            size: 32,
            file_offset: 0,
            file_size: 32,
            executable: true,
        }]
    }
    #[test]
    fn exact_many_to_many_mapping_keeps_unmapped_text_unmapped() {
        let mut selection = SemanticSelection {
            mappings: vec![
                CodeMapping {
                    start: 2,
                    end: 4,
                    addresses: vec![0x1000, 0x1001],
                },
                CodeMapping {
                    start: 6,
                    end: 8,
                    addresses: vec![0x1000],
                },
            ],
            ..Default::default()
        };
        selection.select_instruction(0x1000);
        assert_eq!(selection.ranges, vec![2..4, 6..8]);
        assert_eq!(selection.select_code(2), Some(0x1000));
        assert_eq!(selection.addresses, BTreeSet::from([0x1000, 0x1001]));
        assert_eq!(selection.select_code(4), None);
        assert_eq!(selection.select_code(0), None);
        selection.select_instruction(0x1010);
        assert!(selection.ranges.is_empty());
    }
    #[test]
    fn validation_rejects_bad_utf8_ranges_overlap_and_address_budgets() {
        let text = "é🦀 value";
        let valid = CodeMapping {
            start: 2,
            end: 6,
            addresses: vec![0x1000],
        };
        validate_mappings(text, std::slice::from_ref(&valid), &sections()).unwrap();
        for mapping in [
            CodeMapping {
                start: 1,
                ..valid.clone()
            },
            CodeMapping {
                end: 3,
                ..valid.clone()
            },
            CodeMapping {
                end: text.len() + 1,
                ..valid.clone()
            },
            CodeMapping {
                addresses: vec![],
                ..valid.clone()
            },
            CodeMapping {
                addresses: vec![0x1000; 65],
                ..valid.clone()
            },
            CodeMapping {
                addresses: vec![0x9000],
                ..valid.clone()
            },
        ] {
            assert!(validate_mappings(text, &[mapping], &sections()).is_err());
        }
        assert!(validate_mappings(text, &[valid.clone(), valid], &sections()).is_err());
    }
}
