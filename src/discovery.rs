//! Parent-owned continuation. Projects store committed results as a
//! display-only snapshot; continuation state itself is never persisted.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::*;

/// Saved discovery format and evidence semantics. A different value discards a
/// project's saved discovery while keeping its other cached results.
pub const DISCOVERY_FINGERPRINT: &str =
    "discovery-v1-calls-v1-data-v1-switch-v1-patterns-v1-noreturn-v1";

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

/// A complete worker function inventory accepted as evidence owners, shared
/// between adoption jobs and identified by worker epoch and revision.
#[derive(Clone, Debug)]
pub struct WorkerInventory {
    functions: Arc<Vec<FunctionInfo>>,
    epoch: u64,
    revision: u64,
    /// Data-evidence owner checks were applied, as for replies carrying data.
    data_checked: bool,
}

impl WorkerInventory {
    pub fn functions(&self) -> &[FunctionInfo] {
        &self.functions
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// The inventory a batch reply describes. `base` is the last inventory
    /// adopted from this worker epoch, if any, and `requested` the revision the
    /// request named. Changed inventories are validated in full; an unchanged
    /// one shares the already validated base. `data` applies the extra owner
    /// checks for a reply carrying data evidence. Also reports whether rows changed.
    pub fn adopt(
        info: &BinaryInfo,
        base: Option<&Self>,
        requested: Option<u64>,
        epoch: u64,
        change: InventoryChange,
        data: bool,
    ) -> Result<(Self, bool), String> {
        let base = base.filter(|base| base.epoch == epoch);
        let revision = change.revision();
        if base.is_some_and(|base| {
            revision < base.revision
                || revision == base.revision && !matches!(change, InventoryChange::Unchanged { .. })
        }) {
            return Err("Worker inventory revision moved backwards".into());
        }
        let previous = base
            .filter(|base| requested == Some(base.revision))
            .map(|base| (base.revision, base.functions()));
        match change.apply(previous)? {
            None => {
                let mut base = base
                    .cloned()
                    .ok_or("Unchanged inventory has no adopted base")?;
                if data && !base.data_checked {
                    crate::data_analysis::validate_inventory(info, base.functions())?;
                    base.data_checked = true;
                }
                Ok((base, false))
            }
            Some(functions) => {
                crate::call_analysis::validate_inventory(info, &functions, data)?;
                Ok((
                    Self {
                        functions: Arc::new(functions),
                        epoch,
                        revision,
                        data_checked: data,
                    },
                    true,
                ))
            }
        }
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

/// The function-start pattern phase, which runs whenever the seed queue is
/// empty until the whole executable image has been scanned.
#[derive(Clone, Debug, Default)]
pub struct PatternPhase {
    /// Where the next scan step continues; `None` once complete.
    pub cursor: Option<u64>,
    pub scanned_bytes: u64,
    pub matches: usize,
    pub validated: usize,
    pub admitted: usize,
    pub partial: bool,
    interruptions: usize,
    /// Consecutive steps that neither advanced nor admitted nor decoded.
    stalls: usize,
}

#[derive(Default)]
pub struct Discovery {
    entries: BTreeMap<u64, Entry>,
    pending: VecDeque<u64>,
    /// Seeds of the batch in flight; empty for a pattern-scan step.
    flight: Option<(DiscoveryBinding, Vec<u64>)>,
    pub patterns: Option<PatternPhase>,
    sequence: u64,
    /// Worker epoch and inventory revision whose addresses are all admitted.
    admitted: Option<(u64, u64)>,
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

    /// Whether function-start patterns apply: a supported pattern set and
    /// an image whose discovery is not disabled as packed.
    pub fn patterns_apply(info: &BinaryInfo) -> bool {
        crate::function_patterns::supported(&info.architecture, &info.format)
            && !crate::packing::has_upx_warning(info)
    }

    /// Adds the pattern phase, scanning from the start of the image.
    pub fn start_patterns(&mut self) {
        self.patterns = Some(PatternPhase {
            cursor: Some(0),
            ..Default::default()
        });
    }

    /// Adds the pattern phase when [`Self::patterns_apply`].
    pub fn enable_patterns(&mut self, info: &BinaryInfo) {
        if Self::patterns_apply(info) {
            self.start_patterns();
        }
    }

    pub fn remaining(&self) -> usize {
        self.pending.len() + self.flight.as_ref().map_or(0, |(_, seeds)| seeds.len())
    }

    /// Whether a pattern-scan step remains.
    pub fn scanning(&self) -> bool {
        self.patterns
            .as_ref()
            .is_some_and(|phase| phase.cursor.is_some())
    }

    pub fn status(&self, address: u64) -> Option<Status> {
        self.entries.get(&address).map(|entry| entry.status)
    }

    pub fn partial(&self) -> bool {
        self.capped
            || self.report.partial
            || self.report.data.as_ref().is_some_and(|data| data.partial)
            || self.remaining() != 0
            || self
                .patterns
                .as_ref()
                .is_some_and(|phase| phase.partial || phase.cursor.is_some())
    }

    pub fn begin(&mut self, generation: u64, epoch: u64, revision: u64) -> Option<Request> {
        if self.flight.is_some() {
            return None;
        }
        if self.pending.is_empty() {
            // Scan only once every known seed has been walked, so candidates
            // are judged against all established code.
            let cursor = self.patterns.as_ref()?.cursor?;
            self.sequence = self.sequence.checked_add(1)?;
            let binding = DiscoveryBinding {
                generation,
                epoch,
                revision,
                batch: self.sequence,
            };
            self.flight = Some((binding, Vec::new()));
            return Some(Request::DiscoverBatch {
                binding,
                inventory_base: None,
                seeds: Vec::new(),
                patterns: Some(cursor),
            });
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
        Some(Request::DiscoverBatch {
            binding,
            inventory_base: None,
            seeds,
            patterns: None,
        })
    }

    /// Dropping the in-flight computation never drops committed evidence. Retry
    /// interrupted seeds individually, and never more than the shared limit.
    pub fn interrupt(&mut self) {
        if let Some((_, seeds)) = self.flight.take() {
            if seeds.is_empty()
                && let Some(phase) = &mut self.patterns
            {
                phase.interruptions += 1;
                if phase.interruptions >= MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
                    phase.cursor = None;
                    phase.partial = true;
                }
            }
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
    /// `inventory` is the complete worker inventory the batch produced.
    pub fn commit(
        &mut self,
        info: &BinaryInfo,
        batch: &DiscoveryBatch,
        inventory: &WorkerInventory,
    ) -> Result<(), String> {
        let (binding, seeds) = self
            .flight
            .as_ref()
            .ok_or("No discovery batch is pending")?;
        if *binding != batch.binding {
            return Err("Stale discovery batch binding".into());
        }
        if inventory.revision != batch.inventory.revision() {
            return Err("Discovery batch does not match its inventory".into());
        }
        let functions = inventory.functions();
        batch.analysis.validate_evidence(info, functions)?;
        if seeds.is_empty() {
            return self.commit_patterns(info, batch, inventory);
        }
        if batch.patterns.is_some() {
            return Err("A seed batch reply carries a pattern scan".into());
        }
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
        // Entries are never removed, so an inventory admitted by an earlier
        // commit only repeats no-ops and the sticky cap.
        let key = (inventory.epoch, inventory.revision);
        if self.admitted != Some(key) {
            for function in functions {
                self.admit(function.address);
            }
            self.admitted = Some(key);
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

    /// Commits a pattern-scan step: admitted starts must be new aligned code
    /// entries in the reply's inventory, and the cursor may only move forward.
    fn commit_patterns(
        &mut self,
        info: &BinaryInfo,
        batch: &DiscoveryBatch,
        inventory: &WorkerInventory,
    ) -> Result<(), String> {
        let scan = batch
            .patterns
            .as_ref()
            .ok_or("A pattern-scan step returned no scan")?;
        let phase = self.patterns.as_mut().ok_or("No pattern scan is pending")?;
        let cursor = phase.cursor.ok_or("The pattern scan is already complete")?;
        let analysis = &batch.analysis;
        if !batch.outcomes.is_empty()
            || analysis.functions_examined != 0
            || analysis.decode_attempts != 0
            || !analysis.references.is_empty()
            || analysis.unresolved_calls != 0
            || analysis.skipped_fallthrough_calls != 0
            || analysis.failed_functions != 0
            || analysis.data.is_some()
            || scan.next.is_some_and(|next| next < cursor)
            || scan.admitted.len() > MAX_PATTERN_ADMISSIONS
            || scan.admitted.len() > scan.validated
            || scan.validated > scan.matches
            || scan.admitted.windows(2).any(|pair| pair[0] >= pair[1])
            || scan.admitted.iter().any(|&address| {
                address < cursor
                    || self.entries.contains_key(&address)
                    || !crate::call_analysis::code_address(info, address)
                    || function_at(inventory.functions(), address).is_none()
            })
        {
            return Err("Invalid function-start pattern scan".into());
        }
        let progressed =
            scan.next != Some(cursor) || !scan.admitted.is_empty() || scan.covered != 0;
        phase.stalls = if progressed { 0 } else { phase.stalls + 1 };
        phase.cursor = scan.next;
        if phase.stalls >= MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
            phase.cursor = None;
            phase.partial = true;
        }
        phase.scanned_bytes = phase.scanned_bytes.saturating_add(scan.scanned_bytes);
        phase.matches = phase.matches.saturating_add(scan.matches);
        phase.validated = phase.validated.saturating_add(scan.validated);
        phase.admitted = phase.admitted.saturating_add(scan.admitted.len());
        phase.partial |= scan.partial;
        phase.interruptions = 0;
        self.flight = None;
        self.report.partial |= batch.truncated;
        let key = (inventory.epoch, inventory.revision);
        if self.admitted != Some(key) {
            for function in inventory.functions() {
                self.admit(function.address);
            }
            self.admitted = Some(key);
        }
        Ok(())
    }

    /// Reconstructs a batch reply's complete inventory from `base`, the last
    /// inventory adopted from that worker, then commits the batch. `requested`
    /// is the revision the request named. Shared by the desktop's adoption job
    /// and integration tests. Also reports whether the inventory rows changed.
    pub fn commit_reply(
        &mut self,
        info: &BinaryInfo,
        base: Option<&WorkerInventory>,
        requested: Option<u64>,
        batch: &mut DiscoveryBatch,
    ) -> Result<(WorkerInventory, bool), String> {
        let revision = batch.inventory.revision();
        let change = std::mem::replace(
            &mut batch.inventory,
            InventoryChange::Unchanged { revision },
        );
        let adoption = crate::performance::span("parent_inventory_adopt");
        let (inventory, changed) = WorkerInventory::adopt(
            info,
            base,
            requested,
            batch.binding.epoch,
            change,
            batch.analysis.data.is_some(),
        )?;
        adoption.finish(u64::from(changed));
        self.commit(info, batch, &inventory)?;
        Ok((inventory, changed))
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

/// Test helper: adopts a batch carrying a complete inventory and commits it.
#[cfg(test)]
pub(crate) fn commit_replacement(
    state: &mut Discovery,
    info: &BinaryInfo,
    batch: &DiscoveryBatch,
) -> Result<(), String> {
    state
        .commit_reply(info, None, None, &mut batch.clone())
        .map(|_| ())
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
        let Request::DiscoverBatch { binding, seeds, .. } = request else {
            panic!()
        };
        DiscoveryBatch {
            binding,
            inventory: InventoryChange::Replace {
                revision: binding.batch,
                functions: info.functions.clone(),
            },
            truncated: false,
            patterns: None,
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
    fn the_pattern_scan_runs_after_seeds_and_admits_only_new_inventory_starts() {
        let mut info = info(1);
        let mut state = Discovery::new(Some(info.entry), [], false);
        state.enable_patterns(&info);
        // Seeds first; the scan starts only once the queue is empty.
        let request = state.begin(1, 1, 0).unwrap();
        assert!(matches!(
            request,
            Request::DiscoverBatch { patterns: None, .. }
        ));
        commit_replacement(&mut state, &info, &batch(request, &info)).unwrap();
        let scan_step = |state: &mut Discovery| {
            let request = state.begin(1, 1, 0).unwrap();
            let Request::DiscoverBatch {
                binding,
                ref seeds,
                patterns: Some(cursor),
                ..
            } = request
            else {
                panic!("expected a pattern scan: {request:?}");
            };
            assert!(seeds.is_empty());
            (request, binding, cursor)
        };
        let (_, binding, cursor) = scan_step(&mut state);
        assert_eq!(cursor, 0);
        info.functions.push(FunctionInfo {
            address: 0x2000,
            name: "FUN_00002000".into(),
        });
        let reply = |admitted: Vec<u64>, next| DiscoveryBatch {
            binding,
            inventory: InventoryChange::Replace {
                revision: binding.batch,
                functions: info.functions.clone(),
            },
            truncated: false,
            analysis: CallAnalysis::default(),
            outcomes: vec![],
            patterns: Some(PatternScan {
                next,
                scanned_bytes: 0x1000,
                matches: 4,
                validated: 2,
                admitted,
                ..Default::default()
            }),
        };
        // Starts must be new functions in the reply's own inventory.
        for invalid in [vec![0x3000], vec![0x2000, 0x2000], vec![0x2001]] {
            let mut state = Discovery::new(None, [], false);
            state.start_patterns();
            let request = state.begin(1, 1, 0).unwrap();
            let Request::DiscoverBatch { binding, .. } = request else {
                panic!()
            };
            let mut reply = reply(invalid, Some(0x2000));
            reply.binding = binding;
            assert!(commit_replacement(&mut state, &info, &reply).is_err());
        }
        commit_replacement(&mut state, &info, &reply(vec![0x2000], Some(0x2000))).unwrap();
        // The admitted start is an ordinary seed before the scan continues.
        assert_eq!(state.remaining(), 1);
        let request = state.begin(1, 1, 0).unwrap();
        assert!(matches!(&request, Request::DiscoverBatch { seeds, .. } if seeds == &[0x2000]));
        commit_replacement(&mut state, &info, &batch(request, &info)).unwrap();
        let (_, binding, cursor) = scan_step(&mut state);
        assert_eq!(cursor, 0x2000);
        let mut backwards = reply(vec![], Some(0x1000));
        backwards.binding = binding;
        assert!(commit_replacement(&mut state, &info, &backwards).is_err());
        let mut done = reply(vec![], None);
        done.binding = binding;
        commit_replacement(&mut state, &info, &done).unwrap();
        assert!(state.begin(1, 1, 0).is_none());
        assert!(!state.scanning() && !state.partial());
        assert_eq!(state.patterns.as_ref().unwrap().admitted, 1);
    }

    #[test]
    fn interrupted_or_stalled_pattern_scans_end_partial() {
        let info = info(0);
        let mut state = Discovery::new(None, [], false);
        state.start_patterns();
        for _ in 0..MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
            assert!(state.begin(1, 1, 0).is_some());
            state.interrupt();
        }
        assert!(state.begin(1, 1, 0).is_none());
        assert!(state.partial());
        let mut state = Discovery::new(None, [], false);
        state.start_patterns();
        while let Some(request) = state.begin(1, 1, 0) {
            let Request::DiscoverBatch { binding, .. } = request else {
                panic!()
            };
            let stalled = DiscoveryBatch {
                binding,
                inventory: InventoryChange::Replace {
                    revision: binding.batch,
                    functions: vec![],
                },
                truncated: false,
                analysis: CallAnalysis::default(),
                outcomes: vec![],
                patterns: Some(PatternScan {
                    next: Some(0),
                    ..Default::default()
                }),
            };
            commit_replacement(&mut state, &info, &stalled).unwrap();
        }
        assert!(state.patterns.as_ref().unwrap().partial && state.partial());
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
        commit_replacement(&mut state, &info, &first).unwrap();
        while let Some(request) = state.begin(1, 1, 0) {
            commit_replacement(&mut state, &info, &batch(request, &info)).unwrap();
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
        commit_replacement(&mut state, &info, &first).unwrap();
        let abandoned = batch(state.begin(1, 1, 0).unwrap(), &info);
        state.interrupt();
        assert_eq!(state.report.functions_examined, 128);
        let retry = batch(state.begin(1, 2, 0).unwrap(), &info);
        assert_eq!(retry.outcomes.len(), 1, "isolate interrupted seeds");
        assert!(commit_replacement(&mut state, &info, &abandoned).is_err());
        state.interrupt();
        assert_eq!(
            state.status(retry.outcomes[0].address),
            Some(Status::Failed)
        );
        while let Some(request) = state.begin(1, 3, 0) {
            commit_replacement(&mut state, &info, &batch(request, &info)).unwrap();
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
            assert!(commit_replacement(&mut state, &info, &invalid).is_err());
            assert_eq!(state.report.functions_examined, 0);
            assert_eq!(state.remaining(), 1);
        }
        commit_replacement(&mut state, &info, &first).unwrap();
        assert!(commit_replacement(&mut state, &info, &first).is_err());
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
        commit_replacement(&mut state, &info, &first).unwrap();
        assert_eq!(state.status(info.entry), Some(Status::PartialByOwnLimit));
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { seeds, .. } = &request else {
            panic!()
        };
        assert_eq!(seeds, &[0x1010, 0x1020]);
        commit_replacement(&mut state, &info, &batch(request, &info)).unwrap();
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
        commit_replacement(&mut state, &info, &first).unwrap();
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
        commit_replacement(&mut state, &info, &second).unwrap();
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
        commit_replacement(&mut state, &info, &first).unwrap();
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
