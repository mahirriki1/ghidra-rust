//! Parent-owned pointer-recovery continuation, evidence and cumulative allowances.
use std::collections::{BTreeMap, BTreeSet};

use crate::discovery::{WorkerInventory, inventory_validation_rows};
use crate::model::*;

#[derive(Default)]
pub(crate) struct PointerDiscovery {
    pub cursor: Option<PointerCursor>,
    pub flight: bool,
    pub partial: bool,
    pub admissions: BTreeMap<u64, FunctionAdmission>,
    steps: usize,
    records: usize,
    slots: usize,
    candidates: usize,
    decode_attempts: usize,
    inventory_rows: usize,
    interruptions: usize,
    epoch: Option<u64>,
    covered: BTreeSet<u64>,
}

impl PointerDiscovery {
    pub fn accounting(&self) -> RecoveryAccounting {
        RecoveryAccounting {
            metadata_records: self.records,
            pointer_slots: self.slots,
            candidates: self.candidates,
            decode_attempts: self.decode_attempts,
            cursor_steps: self.steps,
            inventory_rows: self.inventory_rows,
            witnesses: self.admissions.len(),
        }
    }

    pub fn enable(&mut self) {
        self.cursor = Some(PointerCursor::default());
    }
    pub fn interrupt(&mut self) {
        if !self.flight {
            return;
        }
        self.flight = false;
        self.interruptions += 1;
        if self.interruptions >= MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
            self.cursor = None;
            self.partial = true;
        }
    }

    pub fn check_preparation(&mut self, records: usize) -> Result<(), String> {
        if records > MAX_METADATA_RECORDS * 2 - self.records {
            self.cursor = None;
            self.partial = true;
            return Err("Pointer metadata rebuild budget exhausted".into());
        }
        Ok(())
    }
    pub fn record_preparation(&mut self, records: usize) {
        self.records += records;
    }

    pub fn preflight(
        &mut self,
        base: Option<&WorkerInventory>,
        requested: Option<u64>,
        batch: &DiscoveryBatch,
    ) -> Result<usize, String> {
        let scan = batch.pointers.as_ref().ok_or("Missing pointer scan")?;
        let rows =
            inventory_validation_rows(base, requested, batch.binding.epoch, &batch.inventory);
        if self.steps >= MAX_POINTER_STEPS
            || scan.records > MAX_METADATA_RECORDS * 2 - self.records
            || scan.slots > MAX_POINTER_SLOTS - self.slots
            || scan.candidates > MAX_FUNCTION_ADMISSIONS - self.candidates
            || rows > MAX_PATTERN_INVENTORY_VALIDATION_ROWS - self.inventory_rows
            || batch.admissions.len() > MAX_FUNCTION_ADMISSIONS - self.admissions.len()
        {
            self.cursor = None;
            self.flight = false;
            self.partial = true;
            return Err("Pointer recovery work budget exhausted".into());
        }
        Ok(rows)
    }

    pub fn validate(
        &self,
        info: &BinaryInfo,
        batch: &DiscoveryBatch,
        inventory: &WorkerInventory,
    ) -> Result<(), String> {
        let scan = batch.pointers.as_ref().ok_or("Missing pointer scan")?;
        let cursor = self.cursor.ok_or("Pointer recovery already complete")?;
        let a = &batch.analysis;
        if scan.records > MAX_METADATA_RECORDS * 2 - self.records
            || scan.slots > MAX_POINTER_SLOTS - self.slots
            || scan.candidates > MAX_FUNCTION_ADMISSIONS - self.candidates
            || self.steps >= MAX_POINTER_STEPS
            || !self.flight
            || batch.patterns.is_some()
            || batch.recovery_records != 0
            || !batch.outcomes.is_empty()
            || a.functions_examined != 0
            || a.decode_attempts != 0
            || !a.references.is_empty()
            || a.unresolved_calls != 0
            || a.skipped_fallthrough_calls != 0
            || a.failed_functions != 0
            || a.data.is_some()
            || scan.candidates > MAX_PATTERN_VALIDATIONS
            || scan.decode_attempts > MAX_ANALYSIS_INSTRUCTIONS
            || scan.slots > MAX_PATTERN_SCAN_BYTES as usize / 8
            || batch.admissions.len() > scan.candidates
            || scan.covered.len() > MAX_PATTERN_COVERAGE
            || scan.covered.windows(2).any(|w| w[0] >= w[1])
            || scan.covered.iter().any(|&entry| {
                function_at(inventory.functions(), entry).is_none()
                    || self.epoch == Some(batch.binding.epoch) && self.covered.contains(&entry)
            })
        {
            return Err("Invalid pointer-recovery accounting".into());
        }
        if cursor.phase == PointerPhase::Tables {
            let (offset, total) = table_slot_offset(info, cursor.position)?;
            let next_offset = match scan.next {
                Some(next) if next.phase == PointerPhase::Tables => {
                    table_slot_offset(info, next.position)?.0
                }
                Some(next) if next.phase == PointerPhase::Tails => total,
                None if scan.partial => offset.saturating_add(scan.slots as u64),
                _ => return Err("Pointer tables completed without a tail phase".into()),
            };
            if next_offset.checked_sub(offset) != Some(scan.slots as u64) {
                return Err("Uncharged pointer-table cursor progress".into());
            }
        }
        if let Some(next) = scan.next {
            let valid_run = next.run_start.is_some() == next.first_target.is_some()
                && next.pending.is_none_or(|p| {
                    next.confirmed
                        && next.run_start.is_some_and(|start| start <= p)
                        && p <= next.position
                        && p.is_multiple_of(8)
                })
                && next
                    .run_start
                    .is_none_or(|start| start < next.position && start.is_multiple_of(8))
                && (!next.confirmed || next.run_start.is_some())
                && next
                    .first_target
                    .is_none_or(|a| crate::call_analysis::code_address(info, a));
            let phase_transition = next.phase == cursor.phase
                || matches!(
                    (cursor.phase, next.phase),
                    (PointerPhase::Metadata, PointerPhase::Tables)
                        | (PointerPhase::Tables, PointerPhase::Tails)
                ) && next
                    == (PointerCursor {
                        phase: next.phase,
                        ..Default::default()
                    });
            if !phase_transition
                || next.phase < cursor.phase
                || next.phase == cursor.phase && next.position < cursor.position
                || cursor.phase == PointerPhase::Metadata
                    && next.phase == cursor.phase
                    && next
                        .position
                        .checked_sub(cursor.position)
                        .is_none_or(|steps| steps > scan.candidates as u64)
                || next.phase != PointerPhase::Tables
                    && (next.run_start.is_some() || next.pending.is_some() || next.confirmed)
                || !valid_run
                || next == cursor && scan.covered.is_empty()
                || next.phase == cursor.phase
                    && next.position > cursor.position
                    && scan.slots == 0
                    && scan.candidates == 0
                    && scan.covered.is_empty()
            {
                return Err("Invalid pointer-recovery cursor".into());
            }
        }
        validate_admissions(info, batch, inventory, &self.admissions)?;
        for witness in &batch.admissions {
            let correct_phase = match cursor.phase {
                PointerPhase::Metadata => matches!(
                    witness.reason,
                    AdmissionReason::InitMetadata | AdmissionReason::CrtForwarder
                ),
                PointerPhase::Tails => witness.reason == AdmissionReason::CorroboratedTail,
                PointerPhase::Tables => witness.reason == AdmissionReason::PointerTable,
            };
            if !correct_phase
                || !matches!(
                    witness.reason,
                    AdmissionReason::PointerTable
                        | AdmissionReason::InitMetadata
                        | AdmissionReason::CorroboratedTail
                        | AdmissionReason::CrtForwarder
                )
            {
                return Err("Wrong admission phase".into());
            }
        }
        Ok(())
    }

    pub fn commit(&mut self, batch: &DiscoveryBatch, rows: usize) {
        let scan = batch.pointers.as_ref().expect("validated pointer scan");
        self.steps += 1;
        self.records += scan.records;
        self.slots += scan.slots;
        self.candidates += scan.candidates;
        self.decode_attempts += scan.decode_attempts;
        self.inventory_rows += rows;
        self.cursor = scan.next;
        self.partial |= scan.partial || batch.truncated;
        self.flight = false;
        self.interruptions = 0;
        if self.epoch != Some(batch.binding.epoch) {
            self.epoch = Some(batch.binding.epoch);
            self.covered.clear();
        }
        self.covered.extend(scan.covered.iter().copied());
        self.retain(batch);
    }

    pub fn retain(&mut self, batch: &DiscoveryBatch) {
        for witness in &batch.admissions {
            self.admissions.entry(witness.entry).or_insert(*witness);
        }
    }
}

/// Counts native slots in the parent's validated mapped data, so an address
/// gap or a fabricated cursor cannot replenish or skip charged source work.
fn table_slot_offset(info: &BinaryInfo, address: u64) -> Result<(u64, u64), String> {
    let mut before = 0u64;
    let mut offset = None;
    for section in info
        .sections
        .iter()
        .filter(|s| !s.executable && s.file_size != 0)
    {
        let start = section
            .address
            .checked_add(7)
            .map(|v| v & !7)
            .ok_or("Pointer slot alignment overflow")?;
        let end = section
            .address
            .checked_add(section.size.min(section.file_size))
            .ok_or("Pointer section overflow")?;
        let slots = end.saturating_sub(start) / 8;
        if offset.is_none() && address <= end {
            if address <= start {
                offset = Some(before);
            } else if address.is_multiple_of(8) || address == end {
                offset = before.checked_add((address - start) / 8);
            } else {
                return Err("Unaligned pointer cursor".into());
            }
        }
        before = before
            .checked_add(slots)
            .ok_or("Pointer slot count overflow")?;
    }
    let offset = offset
        .or((address == 0).then_some(0))
        .ok_or("Pointer cursor outside mapped data")?;
    Ok((offset, before))
}

pub(crate) fn validate_admissions(
    info: &BinaryInfo,
    batch: &DiscoveryBatch,
    inventory: &WorkerInventory,
    previous: &BTreeMap<u64, FunctionAdmission>,
) -> Result<(), String> {
    if batch.admissions.len() > MAX_PATTERN_ADMISSIONS
        || previous.len() + batch.admissions.len() > MAX_FUNCTION_ADMISSIONS
        || batch
            .admissions
            .windows(2)
            .any(|w| w[0].entry >= w[1].entry)
    {
        return Err("Invalid admission witness count/order".into());
    }
    for w in &batch.admissions {
        if previous.contains_key(&w.entry)
            || !crate::call_analysis::code_address(info, w.entry)
            || function_at(inventory.functions(), w.entry).is_none()
            || w.owner
                .is_some_and(|owner| function_at(inventory.functions(), owner).is_none())
        {
            return Err("Invalid admission identity".into());
        }
        let source_code = crate::call_analysis::code_address(info, w.source);
        let source_data = info
            .sections
            .iter()
            .any(|s| !s.executable && s.backs(w.source, 8));
        let valid = match w.reason {
            AdmissionReason::PointerTable => {
                source_data
                    && w.source.is_multiple_of(8)
                    && w.owner.is_none()
                    && matches!(
                        w.boundary,
                        BoundaryEvidence::Fde | BoundaryEvidence::Pattern
                    )
                    && w.table.is_some_and(|t| {
                        t <= w.source
                            && t.is_multiple_of(8)
                            && info.sections.iter().any(|s| {
                                !s.executable
                                    && w.source
                                        .checked_sub(t)
                                        .and_then(|n| n.checked_add(8))
                                        .is_some_and(|n| s.backs(t, n))
                            })
                    })
            }
            AdmissionReason::InitMetadata => {
                source_data
                    && w.owner.is_none()
                    && w.table.is_none()
                    && w.boundary == BoundaryEvidence::Format
            }
            AdmissionReason::CorroboratedTail | AdmissionReason::CrtForwarder => {
                source_code
                    && w.owner.is_some()
                    && w.table.is_none()
                    && w.encoding == PointerEncoding::Direct
                    && w.boundary
                        == if w.reason == AdmissionReason::CrtForwarder {
                            BoundaryEvidence::Forwarder
                        } else {
                            BoundaryEvidence::Fde
                        }
            }
            AdmissionReason::Pattern => {
                source_code
                    && w.source == w.entry
                    && w.owner.is_none()
                    && w.table.is_none()
                    && w.boundary == BoundaryEvidence::Pattern
            }
        };
        if !valid {
            return Err(format!(
                "Invalid admission witness source at {:#x} ({:?}, {:#x})",
                w.entry, w.reason, w.source
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::Discovery;

    fn info() -> BinaryInfo {
        BinaryInfo {
            path: "synthetic".into(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 128,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![
                SectionInfo {
                    name: ".text".into(),
                    address: 0x1000,
                    size: 64,
                    file_offset: 0,
                    file_size: 64,
                    executable: true,
                },
                SectionInfo {
                    name: ".data".into(),
                    address: 0x2000,
                    size: 64,
                    file_offset: 64,
                    file_size: 64,
                    executable: false,
                },
            ],
            functions: vec![FunctionInfo {
                address: 0x1000,
                name: "entry".into(),
            }],
            functions_truncated: false,
            warnings: vec![],
        }
    }
    fn setup() -> (BinaryInfo, Discovery, DiscoveryBatch) {
        let info = info();
        let mut state = Discovery::new(Some(info.entry), [info.entry], false);
        state.enable_patterns(&info);
        let Request::DiscoverBatch { binding, .. } = state.begin(1, 1, 0).unwrap() else {
            panic!()
        };
        let batch = DiscoveryBatch {
            binding,
            inventory: InventoryChange::Replace {
                revision: 1,
                functions: vec![
                    info.functions[0].clone(),
                    FunctionInfo {
                        address: 0x1020,
                        name: "callback".into(),
                    },
                ],
            },
            truncated: false,
            analysis: CallAnalysis::default(),
            outcomes: vec![],
            patterns: None,
            pointers: Some(Box::new(PointerScan {
                next: Some(PointerCursor {
                    phase: PointerPhase::Tables,
                    ..Default::default()
                }),
                records: 2,
                candidates: 1,
                decode_attempts: 1,
                ..Default::default()
            })),
            admissions: vec![FunctionAdmission {
                entry: 0x1020,
                reason: AdmissionReason::InitMetadata,
                source: 0x2000,
                owner: None,
                encoding: PointerEncoding::Relative,
                boundary: BoundaryEvidence::Format,
                table: None,
            }],
            recovery_records: 0,
        };
        (info, state, batch)
    }

    #[test]
    fn stale_replies_invalid_witnesses_and_unwitnessed_additions_are_atomic() {
        for mutation in 0..5 {
            let (info, mut state, mut batch) = setup();
            match mutation {
                0 => batch.binding.epoch += 1,
                1 => batch.admissions[0].source = 0x3000,
                2 => batch.admissions[0].owner = Some(0x1001),
                3 => batch.admissions.clear(),
                _ => batch.pointers.as_mut().unwrap().next = Some(PointerCursor::default()),
            }
            assert!(state.commit_reply(&info, None, None, &mut batch).is_err());
            assert!(state.admission(0x1020).is_none());
            assert_eq!(state.recovery_accounting().cursor_steps, 0);
        }
        let (info, mut state, mut batch) = setup();
        state.commit_reply(&info, None, None, &mut batch).unwrap();
        assert_eq!(
            state.admission(0x1020).unwrap().reason,
            AdmissionReason::InitMetadata
        );
        let json = serde_json::to_value(state.save()).unwrap();
        assert!(json.get("admissions").is_none());
        assert!(state.commit_reply(&info, None, None, &mut batch).is_err());
    }
    #[test]
    fn cumulative_allowances_do_not_reset_on_worker_replacement() {
        let (info, mut state, mut batch) = setup();
        state.pointer_recovery.records = MAX_METADATA_RECORDS * 2 - 1;
        assert!(state.commit_reply(&info, None, None, &mut batch).is_err());
        assert!(state.pointer_recovery.partial && state.pointer_recovery.cursor.is_none());
        assert!(state.admission(0x1020).is_none());
        let (info, mut state, mut batch) = setup();
        state.pointer_recovery.inventory_rows = MAX_PATTERN_INVENTORY_VALIDATION_ROWS;
        assert!(state.commit_reply(&info, None, None, &mut batch).is_err());
        assert!(state.pointer_recovery.partial);
    }
    #[test]
    fn evidence_floods_are_bounded_during_deserialization_and_interruption_is_terminal() {
        let (_, mut state, mut batch) = setup();
        batch.admissions = vec![batch.admissions[0]; MAX_PATTERN_ADMISSIONS + 1];
        assert!(
            serde_json::from_value::<DiscoveryBatch>(serde_json::to_value(batch).unwrap()).is_err()
        );
        state.interrupt();
        state.begin(1, 2, 0).unwrap();
        state.interrupt();
        assert!(state.pointer_recovery.partial && state.pointer_recovery.cursor.is_none());
    }
}
