//! Validation and indexed navigation of bounded worker reference evidence.
use std::collections::BTreeMap;

use crate::model::*;

impl AnalysisProgress {
    pub fn validate_after(&self, previous: Option<&Self>) -> Result<(), String> {
        if self.functions_examined > MAX_ANALYSIS_FUNCTIONS
            || self.decode_attempts > MAX_ANALYSIS_INSTRUCTIONS
            || (self.stage == AnalysisStage::Seeds
                && (self.functions_examined != 0 || self.decode_attempts != 0))
            || previous.is_some_and(|old| {
                self.stage < old.stage
                    || self.functions_examined < old.functions_examined
                    || self.decode_attempts < old.decode_attempts
            })
        {
            return Err("Invalid analysis progress bounds or ordering".into());
        }
        Ok(())
    }
}

/// An aligned instruction start inside a file-backed executable section, using
/// indexed checked lookups. Discovery seed admission uses the same rule.
pub fn code_address(info: &BinaryInfo, address: u64) -> bool {
    let alignment = if info.architecture == "AArch64" { 4 } else { 1 };
    address.is_multiple_of(alignment)
        && info
            .sections
            .partition_point(|section| section.address <= address)
            .checked_sub(1)
            .and_then(|index| info.sections.get(index))
            .is_some_and(|section| {
                section.executable
                    && address
                        .checked_sub(section.address)
                        .and_then(|offset| offset.checked_add(alignment))
                        .is_some_and(|end| end <= section.file_size.min(section.size))
            })
}

/// A worker function inventory as reference evidence owners. `data` adds the
/// data-analysis instruction checks applied when a reply carries data evidence.
pub fn validate_inventory(
    info: &BinaryInfo,
    functions: &[FunctionInfo],
    data: bool,
) -> Result<(), String> {
    if functions.len() > MAX_FUNCTIONS {
        return Err("Call analysis exceeds its work or result bounds".into());
    }
    validate_functions(functions, MAX_FUNCTION_NAME_BYTES, true)?;
    let valid = |address| code_address(info, address);
    for (index, function) in functions.iter().enumerate() {
        if !valid(function.address)
            || function.name.len() > 256
            || (index > 0 && functions[index - 1].address >= function.address)
        {
            return Err("Invalid analysis function inventory".into());
        }
    }
    if data {
        crate::data_analysis::validate_inventory(info, functions)?;
    }
    Ok(())
}

impl CallAnalysis {
    pub fn validate(&self, info: &BinaryInfo, functions: &[FunctionInfo]) -> Result<(), String> {
        validate_inventory(info, functions, self.data.is_some())?;
        self.validate_evidence(info, functions)
    }

    /// Bounds and ownership of this reply's evidence, for `functions` already
    /// accepted by [`validate_inventory`] with at least the same strictness.
    pub fn validate_evidence(
        &self,
        info: &BinaryInfo,
        functions: &[FunctionInfo],
    ) -> Result<(), String> {
        if !self.work_within(1)
            || self.failed_functions > self.functions_examined
            || functions.len() > MAX_FUNCTIONS
        {
            return Err("Call analysis exceeds its work or result bounds".into());
        }
        self.validate_references(info, |caller| {
            functions
                .binary_search_by_key(&caller, |f| f.address)
                .is_ok()
        })?;
        if let Some(data) = &self.data {
            data.validate_evidence(info, functions, self.decode_attempts)?;
        }
        Ok(())
    }

    /// Accounting consistent with `batches` committed worker replies; one batch
    /// is a single reply. Counters add across batches while evidence is merged.
    /// Failures are checked by callers: interrupted seeds fail unexamined.
    pub(crate) fn work_within(&self, batches: usize) -> bool {
        let scaled = |limit: usize| batches.saturating_mul(limit);
        let calls = self
            .references
            .len()
            .checked_add(self.unresolved_calls)
            .and_then(|count| count.checked_add(self.skipped_fallthrough_calls));
        !(self.functions_examined > scaled(MAX_ANALYSIS_FUNCTIONS)
            || self.decode_attempts > scaled(MAX_ANALYSIS_INSTRUCTIONS)
            || self.references.len() > MAX_CALL_REFERENCES
            || calls.is_none_or(|calls| {
                calls > scaled(MAX_CALL_REFERENCES) || calls > self.decode_attempts
            }))
    }

    /// Address, owner, ordering, and duplicate checks shared by worker replies
    /// and saved discovery snapshots; work bounds are checked by each caller.
    pub(crate) fn validate_references(
        &self,
        info: &BinaryInfo,
        owned: impl Fn(u64) -> bool,
    ) -> Result<(), String> {
        let valid = |address| code_address(info, address);
        for (index, reference) in self.references.iter().enumerate() {
            if !valid(reference.caller)
                || !valid(reference.address)
                || !valid(reference.target)
                || !owned(reference.caller)
                || (index > 0 && self.references[index - 1] >= *reference)
            {
                return Err("Invalid call evidence addresses, ordering, or duplicates".into());
            }
        }
        Ok(())
    }
}

/// Constructed once on result adoption. Frames visit only visible reference rows.
/// Derived desktop reference index. Public for the opt-in integration profiler
/// to measure the same construction as the GUI, after validating its evidence.
#[doc(hidden)]
pub struct CallIndex {
    pub report: CallAnalysis,
    pub incoming: BTreeMap<u64, Vec<usize>>,
    pub outgoing: BTreeMap<u64, Vec<usize>>,
    pub data_incoming: BTreeMap<u64, Vec<usize>>,
    pub data_outgoing: BTreeMap<u64, Vec<usize>>,
}

impl CallIndex {
    pub fn new(report: CallAnalysis) -> Self {
        let mut incoming: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut outgoing: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (index, reference) in report.references.iter().enumerate() {
            incoming.entry(reference.target).or_default().push(index);
            outgoing.entry(reference.caller).or_default().push(index);
        }
        let mut data_incoming: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        let mut data_outgoing: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        if let Some(data) = &report.data {
            for (index, reference) in data.references.iter().enumerate() {
                data_incoming
                    .entry(reference.target)
                    .or_default()
                    .push(index);
                data_outgoing
                    .entry(reference.function)
                    .or_default()
                    .push(index);
            }
        }
        Self {
            report,
            incoming,
            outgoing,
            data_incoming,
            data_outgoing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (BinaryInfo, CallAnalysis) {
        let info = BinaryInfo {
            path: "fixture".into(),
            architecture: "AArch64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 256,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 256,
                file_offset: 0,
                file_size: 256,
                executable: true,
            }],
            functions: vec![
                FunctionInfo {
                    address: 0x1000,
                    name: "caller".into(),
                },
                FunctionInfo {
                    address: 0x1040,
                    name: "callee".into(),
                },
            ],
            functions_truncated: false,
            warnings: vec![],
        };
        let report = CallAnalysis {
            references: vec![CallReference {
                caller: 0x1000,
                address: 0x1004,
                target: 0x1040,
            }],
            functions_examined: 2,
            decode_attempts: 4,
            ..Default::default()
        };
        (info, report)
    }

    #[test]
    fn rejects_unmapped_unaligned_duplicate_or_inconsistent_call_evidence() {
        let (info, report) = fixture();
        report.validate(&info, &info.functions).unwrap();
        for reference in [
            CallReference {
                caller: 0x1000,
                address: 0x1002,
                target: 0x1040,
            },
            CallReference {
                caller: 0x1000,
                address: 0x1004,
                target: 0x1100,
            },
            CallReference {
                caller: 0x1020,
                address: 0x1004,
                target: 0x1040,
            },
        ] {
            let mut invalid = report.clone();
            invalid.references[0] = reference;
            assert!(invalid.validate(&info, &info.functions).is_err());
        }
        let mut duplicate = report.clone();
        duplicate.references.push(duplicate.references[0].clone());
        assert!(duplicate.validate(&info, &info.functions).is_err());
        let mut overflow = report.clone();
        overflow.unresolved_calls = usize::MAX;
        assert!(overflow.validate(&info, &info.functions).is_err());
        let mut too_little_work = report.clone();
        too_little_work.decode_attempts = 0;
        assert!(too_little_work.validate(&info, &info.functions).is_err());
        let mut invalid = info.clone();
        invalid.sections[0].file_size = 6;
        assert!(report.validate(&invalid, &invalid.functions).is_err());
        invalid = info.clone();
        invalid.functions.reverse();
        assert!(report.validate(&invalid, &invalid.functions).is_err());
    }

    #[test]
    fn indexes_distinct_call_sites_for_both_navigation_directions() {
        let (info, mut report) = fixture();
        report.references.push(CallReference {
            caller: 0x1000,
            address: 0x1008,
            target: 0x1040,
        });
        report.validate(&info, &info.functions).unwrap();
        let index = CallIndex::new(report);
        assert_eq!(index.incoming[&0x1040], vec![0, 1]);
        assert_eq!(index.outgoing[&0x1000], vec![0, 1]);
        assert!(!index.incoming.contains_key(&0x1000));
    }

    #[test]
    fn data_indexes_keep_access_kind_and_exact_start_separate_from_calls() {
        let (info, mut report) = fixture();
        report.data = Some(DataAnalysis {
            references: vec![
                DataReference {
                    function: 0x1000,
                    address: 0x1004,
                    target: 0x1080,
                    size: 4,
                    access: DataAccess::Read,
                    provenance: DataProvenance::InstructionLocal,
                },
                DataReference {
                    function: 0x1000,
                    address: 0x1004,
                    target: 0x1080,
                    size: 4,
                    access: DataAccess::Write,
                    provenance: DataProvenance::InstructionLocal,
                },
                DataReference {
                    function: 0x1040,
                    address: 0x1044,
                    target: 0x1082,
                    size: 2,
                    access: DataAccess::Read,
                    provenance: DataProvenance::InstructionLocal,
                },
            ],
            operations_charged: 3,
            accesses_examined: 3,
            ..Default::default()
        });
        report.validate(&info, &info.functions).unwrap();
        let index = CallIndex::new(report);
        assert_eq!(index.data_incoming[&0x1080], vec![0, 1]);
        assert_eq!(index.data_incoming[&0x1082], vec![2]);
        assert!(!index.data_incoming.contains_key(&0x1081));
        assert_eq!(index.data_outgoing[&0x1000], vec![0, 1]);
        assert_eq!(index.data_outgoing[&0x1040], vec![2]);
        assert_eq!(index.incoming[&0x1040], vec![0]);
    }
}
