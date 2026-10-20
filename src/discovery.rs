//! Parent-owned continuation. Projects store committed results as a
//! display-only snapshot; continuation state itself is never persisted.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::model::*;

/// Saved discovery format and evidence semantics. A different value discards a
/// project's saved discovery while keeping its other cached results.
pub const DISCOVERY_FINGERPRINT: &str = "discovery-v1-calls-v1-data-v1";

/// Committed discovery results as stored in a project. After loading they are
/// display-only: Discover starts a fresh queue instead of trusting saved
/// statuses, so a forged "complete" snapshot cannot suppress recomputation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverySnapshot {
    pub fingerprint: String,
    /// Strictly increasing addresses per status; together at most
    /// `MAX_FUNCTIONS` entries. Seeds of an unfinished batch remain pending.
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
    pub pending: Vec<u64>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
    pub done: Vec<u64>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
    pub limited: Vec<u64>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_FUNCTIONS }>")]
    pub failed: Vec<u64>,
    pub batches: usize,
    pub capped: bool,
    pub report: CallAnalysis,
}

impl DiscoverySnapshot {
    /// Treats every field as untrusted. Structural consistency only: this does
    /// not establish that the evidence matches the binary's instructions.
    pub fn validate(&self, info: &BinaryInfo) -> Result<(), String> {
        let total = [&self.pending, &self.done, &self.limited, &self.failed]
            .iter()
            .try_fold(0usize, |total, list| total.checked_add(list.len()))
            .filter(|&total| total <= MAX_FUNCTIONS)
            .ok_or("Saved discovery exceeds the function limit")?;
        let mut statuses = Vec::with_capacity(total);
        for (list, status) in [
            (&self.pending, Status::Pending),
            (&self.done, Status::Done),
            (&self.limited, Status::PartialByOwnLimit),
            (&self.failed, Status::Failed),
        ] {
            for (index, &address) in list.iter().enumerate() {
                if !crate::call_analysis::code_address(info, address)
                    || (index > 0 && list[index - 1] >= address)
                {
                    return Err("Invalid saved discovery function addresses or ordering".into());
                }
                statuses.push((address, status));
            }
        }
        statuses.sort_unstable_by_key(|&(address, _)| address);
        if statuses.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("Saved discovery lists a function more than once".into());
        }
        let status = |address| {
            statuses
                .binary_search_by_key(&address, |&(address, _)| address)
                .ok()
                .map(|index| statuses[index].1)
        };
        let examined = |address| status(address).is_some_and(|status| status != Status::Pending);
        let report = &self.report;
        let terminal = self.done.len() + self.limited.len();
        // Interrupted seeds can fail without being examined by a batch.
        if !report.work_within(self.batches)
            || report.failed_functions != self.failed.len()
            || report.functions_examined < terminal.max(self.batches)
            || report.functions_examined > terminal + self.failed.len()
            || report
                .data
                .as_ref()
                .is_some_and(|data| !data.work_within(report.decode_attempts, self.batches))
        {
            return Err("Saved discovery accounting is inconsistent".into());
        }
        report.validate_references(info, examined)?;
        if report
            .references
            .iter()
            .any(|reference| status(reference.target).is_none() && !self.capped)
        {
            return Err("Saved call targets were not admitted to discovery".into());
        }
        if let Some(data) = &report.data {
            data.validate_references(info, examined)?;
        }
        // Never trust a separate completeness claim; derive what must be partial.
        if (!self.pending.is_empty()
            || !self.limited.is_empty()
            || !self.failed.is_empty()
            || info.functions_truncated
            || self.capped
            || report.data.as_ref().is_some_and(|data| data.partial))
            && !report.partial
        {
            return Err("Saved discovery claims complete coverage it does not have".into());
        }
        Ok(())
    }

    pub fn remaining(&self) -> usize {
        self.pending.len()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Pending,
    Done,
    PartialByOwnLimit,
    Failed,
}

#[derive(Clone, Debug)]
struct Entry {
    status: Status,
    interruptions: usize,
}

#[derive(Default)]
pub struct Discovery {
    entries: BTreeMap<u64, Entry>,
    pending: VecDeque<u64>,
    flight: Option<(DiscoveryBinding, Vec<u64>)>,
    sequence: u64,
    pub batches: usize,
    pub report: CallAnalysis,
    pub capped: bool,
}

impl Discovery {
    pub fn new(entry: Option<u64>, seeds: impl IntoIterator<Item = u64>, partial: bool) -> Self {
        let mut state = Self::default();
        state.report.partial = partial;
        for address in entry.into_iter().chain(seeds) {
            state.admit(address);
        }
        state
    }

    fn admit(&mut self, address: u64) {
        if self.entries.contains_key(&address) {
            return;
        }
        if self.entries.len() == MAX_FUNCTIONS {
            self.capped = true;
            return;
        }
        self.entries.insert(
            address,
            Entry {
                status: Status::Pending,
                interruptions: 0,
            },
        );
        self.pending.push_back(address);
    }

    pub fn remaining(&self) -> usize {
        self.pending.len() + self.flight.as_ref().map_or(0, |(_, seeds)| seeds.len())
    }

    pub fn status(&self, address: u64) -> Option<Status> {
        self.entries.get(&address).map(|entry| entry.status)
    }

    pub fn partial(&self) -> bool {
        self.capped
            || self.report.partial
            || self.report.data.as_ref().is_some_and(|data| data.partial)
            || self.remaining() != 0
    }

    pub fn begin(&mut self, generation: u64, epoch: u64, revision: u64) -> Option<Request> {
        if self.flight.is_some() || self.pending.is_empty() {
            return None;
        }
        let limit = if self.entries[&self.pending[0]].interruptions > 0 {
            1
        } else {
            MAX_ANALYSIS_FUNCTIONS
        };
        let seeds: Vec<_> = self
            .pending
            .drain(..limit.min(self.pending.len()))
            .collect();
        self.sequence = self.sequence.checked_add(1)?;
        let binding = DiscoveryBinding {
            generation,
            epoch,
            revision,
            batch: self.sequence,
        };
        self.flight = Some((binding, seeds.clone()));
        Some(Request::DiscoverBatch { binding, seeds })
    }

    /// Dropping the in-flight computation never drops committed evidence. Retry
    /// interrupted seeds individually, and never more than the shared limit.
    pub fn interrupt(&mut self) {
        if let Some((_, seeds)) = self.flight.take() {
            for address in seeds.into_iter().rev() {
                let entry = self.entries.get_mut(&address).expect("scheduled seed");
                entry.interruptions += 1;
                if entry.interruptions >= MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
                    entry.status = Status::Failed;
                    self.report.failed_functions += 1;
                    self.report.partial = true;
                } else {
                    self.pending.push_front(address);
                }
            }
        }
    }

    /// Validate everything before changing any committed counters or evidence.
    /// Runs on the parent's background adoption job, never the GUI thread.
    pub fn commit(&mut self, info: &BinaryInfo, batch: &DiscoveryBatch) -> Result<(), String> {
        let (binding, seeds) = self
            .flight
            .as_ref()
            .ok_or("No discovery batch is pending")?;
        if *binding != batch.binding {
            return Err("Stale discovery batch binding".into());
        }
        batch.analysis.validate(info, &batch.functions)?;
        if batch.outcomes.len() != batch.analysis.functions_examined
            || batch.outcomes.is_empty()
            || batch.outcomes.len() > seeds.len()
            || batch
                .outcomes
                .iter()
                .zip(seeds)
                .any(|(outcome, seed)| outcome.address != *seed)
            || batch
                .outcomes
                .iter()
                .filter(|o| o.status == DiscoveryStatus::Failed)
                .count()
                != batch.analysis.failed_functions
            || batch
                .outcomes
                .iter()
                .any(|o| o.status == DiscoveryStatus::PartialByOwnLimit)
                && !batch.analysis.partial
        {
            return Err("Discovery outcomes do not match the requested seed prefix".into());
        }
        let owners: BTreeSet<_> = batch.outcomes.iter().map(|o| o.address).collect();
        if batch
            .analysis
            .references
            .iter()
            .any(|r| !owners.contains(&r.caller))
            || batch
                .analysis
                .data
                .iter()
                .flat_map(|d| &d.references)
                .any(|r| !owners.contains(&r.function))
        {
            return Err("Discovery evidence belongs to an unexamined function".into());
        }
        let (_, seeds) = self.flight.take().expect("validated flight");
        for outcome in &batch.outcomes {
            self.entries
                .get_mut(&outcome.address)
                .expect("validated seed")
                .status = match outcome.status {
                DiscoveryStatus::Done => Status::Done,
                DiscoveryStatus::PartialByOwnLimit => Status::PartialByOwnLimit,
                DiscoveryStatus::Failed => Status::Failed,
            };
        }
        for &address in seeds[batch.outcomes.len()..].iter().rev() {
            self.pending.push_front(address);
        }
        for reference in &batch.analysis.references {
            self.admit(reference.target);
        }
        for function in &batch.functions {
            self.admit(function.address);
        }
        self.batches += 1;
        let report = &mut self.report;
        let update = &batch.analysis;
        report.functions_examined += update.functions_examined;
        report.decode_attempts += update.decode_attempts;
        report.unresolved_calls += update.unresolved_calls;
        report.skipped_fallthrough_calls += update.skipped_fallthrough_calls;
        report.failed_functions += update.failed_functions;
        report.partial |= update.partial || batch.truncated;
        merge(
            &mut report.references,
            &update.references,
            MAX_CALL_REFERENCES,
            &mut self.capped,
        );
        if let Some(update) = &update.data {
            let data = report.data.get_or_insert_with(DataAnalysis::default);
            merge(
                &mut data.references,
                &update.references,
                MAX_DATA_REFERENCES,
                &mut self.capped,
            );
            data.operations_charged += update.operations_charged;
            data.accesses_examined += update.accesses_examined;
            data.unresolved_accesses += update.unresolved_accesses;
            data.omitted_accesses += update.omitted_accesses;
            data.unsupported_instructions += update.unsupported_instructions;
            data.partial |= update.partial;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> CallAnalysis {
        let mut report = self.report.clone();
        report.partial = self.partial();
        report
    }

    /// Committed results for a project. In-flight seeds are still pending.
    pub fn save(&self) -> DiscoverySnapshot {
        let mut saved = DiscoverySnapshot {
            fingerprint: DISCOVERY_FINGERPRINT.into(),
            pending: Vec::new(),
            done: Vec::new(),
            limited: Vec::new(),
            failed: Vec::new(),
            batches: self.batches,
            capped: self.capped,
            report: self.snapshot(),
        };
        for (&address, entry) in &self.entries {
            match entry.status {
                Status::Pending => &mut saved.pending,
                Status::Done => &mut saved.done,
                Status::PartialByOwnLimit => &mut saved.limited,
                Status::Failed => &mut saved.failed,
            }
            .push(address);
        }
        saved
    }
}

fn merge<T: Ord + Clone>(destination: &mut Vec<T>, source: &[T], cap: usize, capped: &mut bool) {
    let mut values: BTreeSet<_> = std::mem::take(destination).into_iter().collect();
    for value in source {
        if values.len() < cap || values.contains(value) {
            values.insert(value.clone());
        } else {
            *capped = true;
        }
    }
    *capped |= values.len() == cap;
    *destination = values.into_iter().collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(count: u64) -> BinaryInfo {
        BinaryInfo {
            path: "test".into(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 0x100000,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x100000,
                file_offset: 0,
                file_size: 0x100000,
                executable: true,
            }],
            functions: (0..count)
                .map(|n| FunctionInfo {
                    address: 0x1000 + n * 16,
                    name: format!("f{n}"),
                })
                .collect(),
            functions_truncated: false,
            warnings: vec![],
        }
    }

    fn batch(request: Request, info: &BinaryInfo) -> DiscoveryBatch {
        let Request::DiscoverBatch { binding, seeds } = request else {
            panic!()
        };
        DiscoveryBatch {
            binding,
            functions: info.functions.clone(),
            truncated: false,
            outcomes: seeds
                .iter()
                .map(|&address| DiscoveryOutcome {
                    address,
                    status: DiscoveryStatus::Done,
                })
                .collect(),
            analysis: CallAnalysis {
                functions_examined: seeds.len(),
                decode_attempts: seeds.len(),
                ..Default::default()
            },
        }
    }

    #[test]
    fn all_seeds_beyond_128_and_later_callees_are_examined_once() {
        let info = info(300);
        let mut state = Discovery::new(
            Some(info.entry),
            info.functions.iter().map(|f| f.address),
            false,
        );
        let mut first = batch(state.begin(1, 1, 0).unwrap(), &info);
        first.analysis.references.push(CallReference {
            caller: info.entry,
            address: info.entry,
            target: 0x9000,
        });
        state.commit(&info, &first).unwrap();
        while let Some(request) = state.begin(1, 1, 0) {
            state.commit(&info, &batch(request, &info)).unwrap();
        }
        assert_eq!(state.report.functions_examined, 301);
        assert_eq!(
            state.status(info.functions[299].address),
            Some(Status::Done)
        );
        assert_eq!(state.status(0x9000), Some(Status::Done));
        assert_eq!(state.report.references.len(), 1);
        assert_eq!(state.remaining(), 0);
    }

    #[test]
    fn cancellation_and_epoch_change_keep_commits_and_bound_failed_retries() {
        let info = info(140);
        let mut state = Discovery::new(
            Some(info.entry),
            info.functions.iter().map(|f| f.address),
            false,
        );
        let first = batch(state.begin(1, 1, 0).unwrap(), &info);
        state.commit(&info, &first).unwrap();
        let abandoned = batch(state.begin(1, 1, 0).unwrap(), &info);
        state.interrupt();
        assert_eq!(state.report.functions_examined, 128);
        let retry = batch(state.begin(1, 2, 0).unwrap(), &info);
        assert_eq!(retry.outcomes.len(), 1, "isolate interrupted seeds");
        assert!(state.commit(&info, &abandoned).is_err());
        state.interrupt();
        assert_eq!(
            state.status(retry.outcomes[0].address),
            Some(Status::Failed)
        );
        while let Some(request) = state.begin(1, 3, 0) {
            state.commit(&info, &batch(request, &info)).unwrap();
        }
        assert_eq!(state.report.functions_examined, 139);
        assert!(state.partial());
        assert!(state.begin(1, 3, 0).is_none());
    }

    #[test]
    fn stale_duplicate_invalid_replies_are_atomic() {
        let info = info(1);
        let mut state = Discovery::new(Some(info.entry), [], false);
        let first = batch(state.begin(1, 4, 5).unwrap(), &info);
        for change in 0..5 {
            let mut invalid = first.clone();
            match change {
                0 => invalid.binding.epoch += 1,
                1 => invalid.binding.generation += 1,
                2 => invalid.binding.revision += 1,
                3 => invalid.outcomes[0].address += 1,
                _ => invalid.analysis.functions_examined = MAX_ANALYSIS_FUNCTIONS + 1,
            }
            assert!(state.commit(&info, &invalid).is_err());
            assert_eq!(state.report.functions_examined, 0);
            assert_eq!(state.remaining(), 1);
        }
        state.commit(&info, &first).unwrap();
        assert!(state.commit(&info, &first).is_err());
        assert_eq!(state.report.functions_examined, 1);
    }

    #[test]
    fn unfinished_batch_suffix_resumes_but_limited_function_is_terminal() {
        let info = info(3);
        let mut state = Discovery::new(
            Some(info.entry),
            info.functions.iter().map(|f| f.address),
            false,
        );
        let mut first = batch(state.begin(1, 1, 0).unwrap(), &info);
        first.outcomes.truncate(1);
        first.outcomes[0].status = DiscoveryStatus::PartialByOwnLimit;
        first.analysis.functions_examined = 1;
        first.analysis.partial = true;
        state.commit(&info, &first).unwrap();
        assert_eq!(state.status(info.entry), Some(Status::PartialByOwnLimit));
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { seeds, .. } = &request else {
            panic!()
        };
        assert_eq!(seeds, &[0x1010, 0x1020]);
        state.commit(&info, &batch(request, &info)).unwrap();
        assert_eq!(state.remaining(), 0);
        assert!(state.partial());
        assert!(state.begin(1, 1, 0).is_none());
    }

    #[test]
    fn aggregate_cap_is_partial_without_stopping_seed_coverage() {
        let info = info(2);
        let mut state = Discovery::new(Some(info.entry), [], false);
        let mut first = batch(state.begin(1, 1, 0).unwrap(), &info);
        first.outcomes.truncate(1);
        first.analysis.functions_examined = 1;
        first.analysis.decode_attempts = MAX_ANALYSIS_INSTRUCTIONS;
        first.analysis.references = (0..MAX_CALL_REFERENCES)
            .map(|n| CallReference {
                caller: info.entry,
                address: info.entry + n as u64,
                target: 0x1010,
            })
            .collect();
        first.analysis.data = Some(DataAnalysis {
            references: (0..MAX_DATA_REFERENCES)
                .map(|n| DataReference {
                    function: info.entry,
                    address: info.entry,
                    target: 0x11000 + n as u64,
                    size: 1,
                    access: DataAccess::Read,
                    provenance: DataProvenance::InstructionLocal,
                })
                .collect(),
            operations_charged: MAX_DATA_REFERENCES,
            accesses_examined: MAX_DATA_REFERENCES,
            ..Default::default()
        });
        state.commit(&info, &first).unwrap();
        let mut second = batch(state.begin(1, 1, 0).unwrap(), &info);
        second.analysis.data = Some(DataAnalysis {
            references: vec![DataReference {
                function: 0x1010,
                address: 0x1010,
                target: 0x11000,
                size: 1,
                access: DataAccess::Read,
                provenance: DataProvenance::InstructionLocal,
            }],
            operations_charged: 1,
            accesses_examined: 1,
            ..Default::default()
        });
        second.analysis.references.push(CallReference {
            caller: 0x1010,
            address: 0x1010,
            target: info.entry,
        });
        state.commit(&info, &second).unwrap();
        assert!(state.capped);
        assert!(state.partial());
        assert_eq!(state.report.references.len(), MAX_CALL_REFERENCES);
        assert_eq!(
            state.report.data.as_ref().unwrap().references.len(),
            MAX_DATA_REFERENCES
        );
        assert!(state.snapshot().partial);
        assert_eq!(state.remaining(), 0);
    }

    #[test]
    fn interrupted_failures_cannot_claim_complete_saved_coverage() {
        let info = info(1);
        let mut state = Discovery::new(Some(info.entry), [], false);
        for epoch in 1..=MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
            state.begin(1, epoch as u64, 0).unwrap();
            state.interrupt();
        }
        let mut saved = state.save();
        assert_eq!(saved.failed, [info.entry]);
        assert_eq!((saved.batches, saved.report.functions_examined), (0, 0));
        saved.validate(&info).unwrap();
        saved.report.partial = false;
        assert!(saved.validate(&info).is_err());
    }

    #[test]
    fn saved_snapshots_round_trip_and_reject_forged_accounting_or_evidence() {
        let info = info(200);
        let mut state = Discovery::new(
            Some(info.entry),
            info.functions.iter().map(|f| f.address),
            false,
        );
        let mut first = batch(state.begin(1, 1, 0).unwrap(), &info);
        first.analysis.references.push(CallReference {
            caller: info.entry,
            address: info.entry,
            target: 0x9000,
        });
        first.analysis.data = Some(DataAnalysis {
            references: vec![DataReference {
                function: info.entry,
                address: info.entry,
                target: 0x11000,
                size: 4,
                access: DataAccess::Read,
                provenance: DataProvenance::InstructionLocal,
            }],
            operations_charged: 1,
            accesses_examined: 1,
            ..Default::default()
        });
        state.commit(&info, &first).unwrap();
        // Two interruptions fail the next seed without a batch examining it.
        state.begin(1, 1, 0).unwrap();
        state.interrupt();
        state.begin(1, 2, 0).unwrap();
        state.interrupt();
        let saved = state.save();
        assert_eq!((saved.done.len(), saved.failed.len()), (128, 1));
        assert!(saved.pending.contains(&0x9000));
        let json = serde_json::to_vec(&saved).unwrap();
        let parsed: DiscoverySnapshot = serde_json::from_slice(&json).unwrap();
        parsed.validate(&info).unwrap();
        let mut extra: serde_json::Value = serde_json::from_slice(&json).unwrap();
        extra["complete"] = true.into();
        assert!(serde_json::from_value::<DiscoverySnapshot>(extra).is_err());

        type Forge = fn(&mut DiscoverySnapshot);
        let forgeries: [(&str, Forge); 9] = [
            ("unordered", |s| s.pending.reverse()),
            ("listed twice", |s| {
                s.done.push(s.failed[0]);
                s.done.sort_unstable();
            }),
            ("outside code", |s| s.pending.push(0x9_0000_0000)),
            ("failure count", |s| s.report.failed_functions = 0),
            ("examined count", |s| s.report.functions_examined += 100),
            ("pending owner", |s| {
                s.done.retain(|&address| address != 0x1000);
                s.pending.insert(0, 0x1000);
            }),
            ("unadmitted target", |s| s.pending.retain(|&a| a != 0x9000)),
            ("false completeness", |s| s.report.partial = false),
            ("no batches", |s| s.batches = 0),
        ];
        for (name, forge) in forgeries {
            let mut forged = saved.clone();
            forge(&mut forged);
            assert!(forged.validate(&info).is_err(), "accepted {name}");
        }
    }
}
