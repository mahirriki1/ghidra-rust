//! Parent-owned continuation. Projects store committed results as a
//! display-only snapshot; continuation state itself is never persisted.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::model::*;

/// Saved discovery format and evidence semantics. A different value discards a
/// project's saved discovery while keeping its other cached results.
pub const DISCOVERY_FINGERPRINT: &str =
    "discovery-v1-calls-v1-data-v1-switch-v1-patterns-v2-noreturn-v1-pointers-v1-addresses-v1";

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
    /// None means not analyzed/absent from this publication, distinct from a
    /// completed function with no outgoing evidence.
    pub fn status(&self, address: u64) -> Option<Status> {
        [
            (&self.pending, Status::Pending),
            (&self.done, Status::Done),
            (&self.limited, Status::PartialByOwnLimit),
            (&self.failed, Status::Failed),
        ]
        .into_iter()
        .find_map(|(list, status)| list.binary_search(&address).ok().map(|_| status))
    }

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
            || report.addresses.as_ref().is_some_and(|addresses| {
                !addresses.work_within(report.decode_attempts, self.batches)
            })
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
        if let Some(addresses) = &report.addresses {
            addresses.validate_references(info, examined)?;
        }
        // Never trust a separate completeness claim; derive what must be partial.
        if (!self.pending.is_empty()
            || !self.limited.is_empty()
            || !self.failed.is_empty()
            || info.functions_truncated
            || self.capped
            || report.data.as_ref().is_some_and(|data| data.partial)
            || report
                .addresses
                .as_ref()
                .is_some_and(|addresses| addresses.partial))
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

/// A local work stop is distinct from malformed or stale worker data.
#[derive(Debug)]
pub enum ReplyCommit {
    Adopted(WorkerInventory, bool),
    PatternBudgetExhausted,
}
impl ReplyCommit {
    pub fn into_adopted(self) -> Option<(WorkerInventory, bool)> {
        match self {
            Self::Adopted(inventory, changed) => Some((inventory, changed)),
            Self::PatternBudgetExhausted => None,
        }
    }
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
    pub admitted: usize,
    pub partial: bool,
    interruptions: usize,
    /// Consecutive steps that neither advanced nor admitted nor decoded.
    stalls: usize,
    /// Accepted replies that did cursor work, excluding coverage-only setup.
    cursor_steps: usize,
    /// Cursor steps that resumed within a match chunk without charging bytes.
    resume_steps: usize,
    /// Parent-computed complete inventory rows reconstructed and validated.
    inventory_validation_rows: usize,
    /// Coverage identities already accepted from the current worker. A fresh
    /// worker must rebuild them, so the set is scoped to its epoch.
    coverage_epoch: Option<u64>,
    covered: BTreeSet<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct PatternCharge {
    cursor_step: bool,
    resume_step: bool,
    inventory_validation_rows: usize,
}

enum PatternPreflight {
    SeedBatch,
    Pattern(PatternCharge),
    Exhausted,
}

/// Terminal attempts among the currently admitted functions, not whole-image coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FunctionProgress {
    pub processed: usize,
    pub total: usize,
}

#[derive(Default)]
pub struct Discovery {
    entries: BTreeMap<u64, Entry>,
    pending: VecDeque<u64>,
    /// Seeds of the batch in flight; empty for a pattern-scan step.
    flight: Option<(DiscoveryBinding, Vec<u64>)>,
    pub patterns: Option<PatternPhase>,
    pub(crate) pointer_recovery: crate::pointer_discovery::PointerDiscovery,
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
            self.start_sources(info.architecture == "x86-64" && info.format == "ELF");
        }
    }

    /// Starts enabled sources after the caller checks `patterns_apply`. The
    /// worker independently checks the architecture before pointer recovery.
    pub fn start_sources(&mut self, elf_pointers: bool) {
        if elf_pointers {
            self.pointer_recovery.enable();
        }
        self.start_patterns();
    }

    pub fn remaining(&self) -> usize {
        self.pending.len() + self.flight.as_ref().map_or(0, |(_, seeds)| seeds.len())
    }

    /// Allocation-free counts. In-flight seeds remain unfinished until adoption;
    /// failed and limited attempts are terminal, just like successful walks.
    pub fn progress(&self) -> FunctionProgress {
        let total = self.entries.len();
        FunctionProgress {
            processed: total - self.remaining(),
            total,
        }
    }

    /// Whether a pattern-scan step remains.
    pub fn scanning(&self) -> bool {
        self.pointer_recovery.cursor.is_some()
            || self
                .patterns
                .as_ref()
                .is_some_and(|phase| phase.cursor.is_some())
    }

    pub fn recovery_accounting(&self) -> crate::model::RecoveryAccounting {
        self.pointer_recovery.accounting()
    }

    pub fn admission(&self, address: u64) -> Option<&FunctionAdmission> {
        self.pointer_recovery.admissions.get(&address)
    }

    pub fn status(&self, address: u64) -> Option<Status> {
        self.entries.get(&address).map(|entry| entry.status)
    }

    pub fn partial(&self) -> bool {
        self.capped
            || self.pointer_recovery.partial
            || self.pointer_recovery.cursor.is_some()
            || self.report.partial
            || self.report.data.as_ref().is_some_and(|data| data.partial)
            || self
                .report
                .addresses
                .as_ref()
                .is_some_and(|addresses| addresses.partial)
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
        if self.pointer_recovery.admissions.len() > MAX_FUNCTION_ADMISSIONS - MAX_PATTERN_ADMISSIONS
        {
            if self.pointer_recovery.cursor.take().is_some() {
                self.pointer_recovery.partial = true;
            }
            if let Some(phase) = &mut self.patterns
                && phase.cursor.take().is_some()
            {
                phase.partial = true;
            }
        }

        if let Some(cursor) = self.pointer_recovery.cursor
            && (self.pending.is_empty() || cursor.phase == PointerPhase::Metadata)
        {
            self.sequence = self.sequence.checked_add(1)?;
            let binding = DiscoveryBinding {
                generation,
                epoch,
                revision,
                batch: self.sequence,
            };
            self.flight = Some((binding, Vec::new()));
            self.pointer_recovery.flight = true;
            return Some(Request::DiscoverBatch {
                binding,
                inventory_base: None,
                seeds: Vec::new(),
                patterns: Some(DiscoveryCursor::Pointers(cursor)),
            });
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
                patterns: Some(crate::model::DiscoveryCursor::Patterns(cursor)),
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
            if self.pointer_recovery.flight {
                self.pointer_recovery.interrupt();
                return;
            }
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
        self.commit_charged(info, batch, inventory, 0)
    }

    fn commit_charged(
        &mut self,
        info: &BinaryInfo,
        batch: &DiscoveryBatch,
        inventory: &WorkerInventory,
        inventory_validation_rows: usize,
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
        self.pointer_recovery
            .check_preparation(batch.recovery_records)?;
        let functions = inventory.functions();
        batch.analysis.validate_evidence(info, functions)?;
        if seeds.is_empty() {
            if self.pointer_recovery.flight {
                self.pointer_recovery.validate(info, batch, inventory)?;
                if batch
                    .admissions
                    .iter()
                    .any(|w| self.entries.contains_key(&w.entry))
                    || inventory.functions().iter().any(|f| {
                        !self.entries.contains_key(&f.address)
                            && batch
                                .admissions
                                .binary_search_by_key(&f.address, |w| w.entry)
                                .is_err()
                    })
                {
                    return Err("Pointer admissions do not match inventory additions".into());
                }

                self.pointer_recovery
                    .commit(batch, inventory_validation_rows);
                self.flight = None;
                self.admit_inventory(inventory);
                return Ok(());
            }
            return self.commit_patterns(info, batch, inventory, inventory_validation_rows);
        }
        if batch.pointers.is_some() || !batch.admissions.is_empty() {
            return Err("Seed batch carries source evidence".into());
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
            || batch
                .analysis
                .addresses
                .iter()
                .flat_map(|a| &a.references)
                .any(|r| !owners.contains(&r.function))
        {
            return Err("Discovery evidence belongs to an unexamined function".into());
        }
        self.pointer_recovery
            .record_preparation(batch.recovery_records);
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
        self.admit_inventory(inventory);
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
        if let Some(update) = &update.addresses {
            // Address evidence never admits functions; its cap marks only
            // address coverage partial.
            let addresses = report.addresses.get_or_insert_with(Box::default);
            let mut capped = false;
            merge(
                &mut addresses.references,
                &update.references,
                MAX_ADDRESS_REFERENCES,
                &mut capped,
            );
            addresses.candidates_examined += update.candidates_examined;
            addresses.omitted_candidates += update.omitted_candidates;
            addresses.unsupported_instructions += update.unsupported_instructions;
            addresses.partial |= update.partial || capped;
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
        inventory_validation_rows: usize,
    ) -> Result<(), String> {
        let scan = batch
            .patterns
            .as_ref()
            .ok_or("A pattern-scan step returned no scan")?;
        let phase = self.patterns.as_ref().ok_or("No pattern scan is pending")?;
        let cursor = phase.cursor.ok_or("The pattern scan is already complete")?;
        let analysis = &batch.analysis;
        let same_coverage_epoch = phase.coverage_epoch == Some(batch.binding.epoch);
        let progress = pattern_scan_progress(info, cursor, scan)?;
        if !batch.outcomes.is_empty()
            || analysis.functions_examined != 0
            || analysis.decode_attempts != 0
            || !analysis.references.is_empty()
            || analysis.unresolved_calls != 0
            || analysis.skipped_fallthrough_calls != 0
            || analysis.failed_functions != 0
            || analysis.data.is_some()
            || analysis.addresses.is_some()
            || scan.next.is_some_and(|next| next < cursor)
            || scan.scanned_bytes > MAX_PATTERN_SCAN_BYTES
            || scan.matches > MAX_PATTERN_MATCHES
            || scan.validated > MAX_PATTERN_VALIDATIONS
            || scan.admitted.len() > MAX_PATTERN_ADMISSIONS
            || scan.covered.len() > MAX_PATTERN_COVERAGE
            || scan.admitted.len() > scan.validated
            || scan.validated > scan.matches
            || scan.admitted.windows(2).any(|pair| pair[0] >= pair[1])
            || scan.covered.windows(2).any(|pair| pair[0] >= pair[1])
            || scan.covered.iter().any(|&address| {
                !self.entries.contains_key(&address)
                    || function_at(inventory.functions(), address).is_none()
                    || same_coverage_epoch && phase.covered.contains(&address)
            })
            || scan.admitted.iter().any(|&address| {
                address < cursor
                    || self.entries.contains_key(&address)
                    || !crate::call_analysis::code_address(info, address)
                    || function_at(inventory.functions(), address).is_none()
            })
            || !progress
        {
            return Err("Invalid function-start pattern scan".into());
        }
        if batch.pointers.is_some() || batch.recovery_records != 0 {
            return Err("Pattern batch carries pointer work".into());
        }
        crate::pointer_discovery::validate_admissions(
            info,
            batch,
            inventory,
            &self.pointer_recovery.admissions,
        )?;
        if batch.admissions.iter().any(|w| {
            w.reason != AdmissionReason::Pattern || scan.admitted.binary_search(&w.entry).is_err()
        }) {
            return Err("Invalid pattern witness".into());
        }
        let scanned_bytes = phase
            .scanned_bytes
            .checked_add(scan.scanned_bytes)
            .ok_or("Function-start scan byte counter overflow")?;
        let admitted = phase
            .admitted
            .checked_add(scan.admitted.len())
            .ok_or("Function-start admission counter overflow")?;
        let charge = pattern_charge(cursor, scan, inventory_validation_rows);
        let cursor_steps = phase
            .cursor_steps
            .checked_add(usize::from(charge.cursor_step))
            .ok_or("Function-start cursor-step counter overflow")?;
        let resume_steps = phase
            .resume_steps
            .checked_add(usize::from(charge.resume_step))
            .ok_or("Function-start resume-step counter overflow")?;
        let inventory_validation_rows = phase
            .inventory_validation_rows
            .checked_add(charge.inventory_validation_rows)
            .ok_or("Function-start inventory-work counter overflow")?;
        let stalls =
            if scan.next != Some(cursor) || !scan.admitted.is_empty() || !scan.covered.is_empty() {
                0
            } else {
                phase
                    .stalls
                    .checked_add(1)
                    .ok_or("Function-start stall counter overflow")?
            };
        let phase = self.patterns.as_mut().expect("validated pattern phase");
        if phase.coverage_epoch != Some(batch.binding.epoch) {
            phase.coverage_epoch = Some(batch.binding.epoch);
            phase.covered.clear();
        }
        phase.covered.extend(scan.covered.iter().copied());
        phase.stalls = stalls;
        phase.cursor_steps = cursor_steps;
        phase.resume_steps = resume_steps;
        phase.inventory_validation_rows = inventory_validation_rows;
        phase.cursor = scan.next;
        if phase.stalls >= MAX_DISCOVERY_INTERRUPTION_ATTEMPTS
            || phase.cursor_steps >= MAX_PATTERN_CURSOR_STEPS && phase.cursor.is_some()
            || phase.resume_steps >= MAX_PATTERN_RESUME_STEPS && phase.cursor.is_some()
            || phase.inventory_validation_rows >= MAX_PATTERN_INVENTORY_VALIDATION_ROWS
                && phase.cursor.is_some()
        {
            phase.cursor = None;
            phase.partial = true;
        }
        phase.scanned_bytes = scanned_bytes;
        phase.admitted = admitted;
        phase.partial |= scan.partial;
        self.flight = None;
        self.report.partial |= batch.truncated;
        self.pointer_recovery.retain(batch);
        self.admit_inventory(inventory);
        Ok(())
    }

    fn admit_inventory(&mut self, inventory: &WorkerInventory) {
        let key = (inventory.epoch, inventory.revision);
        if self.admitted != Some(key) {
            for function in inventory.functions() {
                self.admit(function.address);
            }
            self.admitted = Some(key);
        }
    }

    /// Reconstructs a batch reply's complete inventory from `base`, the last
    /// inventory adopted from that worker, then commits the batch. `requested`
    /// is the revision the request named. Shared by the desktop's adoption job
    /// and integration tests. Also reports whether the inventory rows changed.
    /// `PatternBudgetExhausted` is an expected pattern-work stop: the entire payload was
    /// discarded without adoption. The caller must request replacement inventory.
    pub fn commit_reply(
        &mut self,
        info: &BinaryInfo,
        base: Option<&WorkerInventory>,
        requested: Option<u64>,
        batch: &mut DiscoveryBatch,
    ) -> Result<ReplyCommit, String> {
        if self
            .flight
            .as_ref()
            .is_none_or(|(binding, _)| *binding != batch.binding)
        {
            return Err("Stale discovery batch binding".into());
        }
        self.pointer_recovery
            .check_preparation(batch.recovery_records)?;
        let pointer_rows = if self.pointer_recovery.flight {
            if self
                .flight
                .as_ref()
                .is_none_or(|(binding, _)| *binding != batch.binding)
            {
                return Err("Stale pointer batch".into());
            }
            Some(self.pointer_recovery.preflight(base, requested, batch)?)
        } else {
            None
        };
        let preflight = if pointer_rows.is_some() {
            PatternPreflight::SeedBatch
        } else {
            self.pattern_preflight(base, requested, batch)?
        };
        if matches!(preflight, PatternPreflight::Exhausted) {
            return Ok(ReplyCommit::PatternBudgetExhausted);
        }
        let inventory_validation_rows = match preflight {
            PatternPreflight::Pattern(charge) => charge.inventory_validation_rows,
            PatternPreflight::SeedBatch => pointer_rows.unwrap_or(0),
            PatternPreflight::Exhausted => unreachable!(),
        };
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
            batch.analysis.instruction_evidence(),
        )?;
        adoption.finish(u64::from(changed));
        self.commit_charged(info, batch, &inventory, inventory_validation_rows)?;
        Ok(ReplyCommit::Adopted(inventory, changed))
    }

    /// Charges parent-observed protocol work before inventory reconstruction or
    /// full-row validation. Worker counters cannot increase these allowances.
    fn pattern_preflight(
        &mut self,
        base: Option<&WorkerInventory>,
        requested: Option<u64>,
        batch: &DiscoveryBatch,
    ) -> Result<PatternPreflight, String> {
        let (binding, seeds) = self
            .flight
            .as_ref()
            .ok_or("No discovery batch is pending")?;
        if *binding != batch.binding {
            return Err("Stale discovery batch binding".into());
        }
        if !seeds.is_empty() {
            return Ok(PatternPreflight::SeedBatch);
        }
        let scan = batch
            .patterns
            .as_ref()
            .ok_or("A pattern-scan step returned no scan")?;
        let phase = self.patterns.as_ref().ok_or("No pattern scan is pending")?;
        let cursor = phase.cursor.ok_or("The pattern scan is already complete")?;
        validate_inventory_base(base, requested, batch.binding.epoch, &batch.inventory)?;
        let rows =
            inventory_validation_rows(base, requested, batch.binding.epoch, &batch.inventory);
        let charge = pattern_charge(cursor, scan, rows);
        let cursor_steps = phase
            .cursor_steps
            .checked_add(usize::from(charge.cursor_step));
        let resume_steps = phase
            .resume_steps
            .checked_add(usize::from(charge.resume_step));
        let inventory_rows = phase
            .inventory_validation_rows
            .checked_add(charge.inventory_validation_rows);
        if cursor_steps.is_none_or(|steps| steps > MAX_PATTERN_CURSOR_STEPS)
            || resume_steps.is_none_or(|steps| steps > MAX_PATTERN_RESUME_STEPS)
            || inventory_rows.is_none_or(|rows| rows > MAX_PATTERN_INVENTORY_VALIDATION_ROWS)
        {
            // Scalars only: no symbol names, addresses or unvalidated payload
            // contents enter diagnostics. Overflow remains an exhausted charge.
            for (name, value) in [
                ("pattern_budget_cursor_before", phase.cursor_steps),
                (
                    "pattern_budget_cursor_charge",
                    usize::from(charge.cursor_step),
                ),
                ("pattern_budget_cursor_limit", MAX_PATTERN_CURSOR_STEPS),
                ("pattern_budget_resume_before", phase.resume_steps),
                (
                    "pattern_budget_resume_charge",
                    usize::from(charge.resume_step),
                ),
                ("pattern_budget_resume_limit", MAX_PATTERN_RESUME_STEPS),
                (
                    "pattern_budget_inventory_before",
                    phase.inventory_validation_rows,
                ),
                (
                    "pattern_budget_inventory_charge",
                    charge.inventory_validation_rows,
                ),
                (
                    "pattern_budget_inventory_limit",
                    MAX_PATTERN_INVENTORY_VALIDATION_ROWS,
                ),
            ] {
                crate::performance::event(name, value as u64);
            }
            let phase = self.patterns.as_mut().expect("validated pattern phase");
            phase.cursor = None;
            phase.partial = true;
            self.flight = None;
            self.report.partial = true;
            return Ok(PatternPreflight::Exhausted);
        }
        Ok(PatternPreflight::Pattern(charge))
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

/// Validates cursor movement in the scan's file-backed executable byte space.
/// Virtual-address gaps cost no scan bytes, while a resume inside the current
/// chunk may be ahead of `scanned_bytes` because that chunk must be rescanned.
fn pattern_scan_progress(
    info: &BinaryInfo,
    cursor: u64,
    scan: &PatternScan,
) -> Result<bool, String> {
    let (cursor_offset, total) = pattern_scan_offset(info, cursor)?;
    let valid = match scan.next {
        Some(next) if next == cursor => scan.scanned_bytes == 0,
        Some(next) => {
            let backed = info
                .sections
                .iter()
                .any(|section| section.executable && section.backs(next, 1));
            let (next_offset, next_total) = pattern_scan_offset(info, next)?;
            let advanced = next_offset.checked_sub(cursor_offset);
            let uncharged = advanced.and_then(|advanced| advanced.checked_sub(scan.scanned_bytes));
            next_total == total
                && next > cursor
                && backed
                && (scan.scanned_bytes != 0 || scan.matches != 0)
                && uncharged.is_some_and(|bytes| {
                    bytes < PATTERN_SCAN_CHUNK_BYTES as u64 && (bytes == 0 || scan.matches != 0)
                })
        }
        None => {
            let remaining = total
                .checked_sub(cursor_offset)
                .ok_or("Function-start scan cursor exceeds its byte space")?;
            scan.scanned_bytes <= remaining && (scan.partial || scan.scanned_bytes == remaining)
        }
    };
    Ok(valid)
}

fn pattern_charge(cursor: u64, scan: &PatternScan, inventory_rows: usize) -> PatternCharge {
    let cursor_step = scan.next != Some(cursor)
        || scan.scanned_bytes != 0
        || scan.matches != 0
        || scan.validated != 0
        || !scan.admitted.is_empty()
        || scan.partial;
    PatternCharge {
        cursor_step,
        resume_step: cursor_step
            && scan.scanned_bytes == 0
            && scan.next.is_some_and(|next| next != cursor),
        inventory_validation_rows: inventory_rows,
    }
}

/// Constant-work checks must precede local budget classification.
fn validate_inventory_base(
    base: Option<&WorkerInventory>,
    requested: Option<u64>,
    epoch: u64,
    change: &InventoryChange,
) -> Result<(), String> {
    let base = base.filter(|base| base.epoch == epoch);
    if base.is_some_and(|base| {
        change.revision() < base.revision
            || change.revision() == base.revision
                && !matches!(change, InventoryChange::Unchanged { .. })
    }) {
        return Err("Worker inventory revision moved backwards".into());
    }
    match change {
        InventoryChange::Replace { .. } => Ok(()),
        InventoryChange::Unchanged { revision }
            if base.is_some_and(|base| {
                requested == Some(base.revision) && *revision == base.revision
            }) =>
        {
            Ok(())
        }
        InventoryChange::Delta {
            base: from,
            revision,
            ..
        } if from.checked_add(1) == Some(*revision)
            && base
                .is_some_and(|base| requested == Some(base.revision) && *from == base.revision) =>
        {
            Ok(())
        }
        _ => Err("Worker inventory has no valid adopted base".into()),
    }
}

/// Rows cloned and validated by inventory reconstruction.
pub(crate) fn inventory_validation_rows(
    base: Option<&WorkerInventory>,
    requested: Option<u64>,
    epoch: u64,
    change: &InventoryChange,
) -> usize {
    match change {
        InventoryChange::Replace { functions, .. } => functions.len(),
        InventoryChange::Delta {
            base: from,
            upserts,
            removals,
            ..
        } => base
            .filter(|base| {
                base.epoch == epoch && requested == Some(base.revision) && *from == base.revision
            })
            .map_or(0, |base| {
                base.functions
                    .len()
                    .saturating_add(upserts.len())
                    .saturating_add(removals.len())
            }),
        InventoryChange::Unchanged { .. } => 0,
    }
}

/// Returns the number of executable file-backed bytes before `address` and the
/// total scan extent. Sections are validated as ordered and non-overlapping at
/// load time; checked sums keep reply adoption fail-closed if that ever changes.
fn pattern_scan_offset(info: &BinaryInfo, address: u64) -> Result<(u64, u64), String> {
    let mut before = 0u64;
    let mut offset = None;
    for section in info
        .sections
        .iter()
        .filter(|section| section.executable && section.file_size != 0)
    {
        let length = section.size.min(section.file_size);
        let end = section
            .address
            .checked_add(length)
            .ok_or("Function-start scan section address overflow")?;
        if offset.is_none() {
            if address <= section.address {
                offset = Some(before);
            } else if address < end {
                offset = Some(
                    before
                        .checked_add(address - section.address)
                        .ok_or("Function-start scan offset overflow")?,
                );
            }
        }
        before = before
            .checked_add(length)
            .ok_or("Function-start scan byte extent overflow")?;
    }
    Ok((offset.unwrap_or(before), before))
}

/// Test helper: adopts a batch carrying a complete inventory and commits it.
impl crate::result_store::Retained for DiscoverySnapshot {
    fn retained_bytes(&self) -> Option<usize> {
        use crate::result_store::Bytes;
        let mut bytes = Bytes::of::<Self>()
            .plus(self.fingerprint.capacity())
            .slots::<u64>(self.pending.capacity())
            .slots::<u64>(self.done.capacity())
            .slots::<u64>(self.limited.capacity())
            .slots::<u64>(self.failed.capacity())
            .slots::<CallReference>(self.report.references.capacity());
        if let Some(data) = &self.report.data {
            bytes = bytes.slots::<DataReference>(data.references.capacity());
        }
        if let Some(addresses) = &self.report.addresses {
            bytes = bytes.slots::<AddressReference>(addresses.references.capacity());
        }
        bytes.total()
    }
}

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
            pointers: None,
            admissions: Vec::new(),
            recovery_records: 0,
        }
    }

    fn pattern_state(info: &BinaryInfo) -> Discovery {
        let mut state = Discovery::new(None, info.functions.iter().map(|f| f.address), false);
        for entry in state.entries.values_mut() {
            entry.status = Status::Done;
        }
        state.pending.clear();
        state.start_patterns();
        state
    }

    fn pattern_reply(
        binding: DiscoveryBinding,
        info: &BinaryInfo,
        next: Option<u64>,
        covered: Vec<u64>,
    ) -> DiscoveryBatch {
        DiscoveryBatch {
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
                covered,
                ..Default::default()
            }),
            pointers: None,
            admissions: Vec::new(),
            recovery_records: 0,
        }
    }

    #[test]
    fn live_progress_counts_terminal_attempts_and_growing_inventory() {
        let mut info = info(2);
        let mut state = Discovery::new(None, info.functions.iter().map(|f| f.address), false);
        assert_eq!(
            state.progress(),
            FunctionProgress {
                processed: 0,
                total: 2
            }
        );
        let request = state.begin(1, 1, 0).unwrap();
        assert_eq!(
            state.progress().processed,
            0,
            "in-flight work remains unfinished"
        );
        let mut first = batch(request, &info);
        first.outcomes.truncate(1);
        first.analysis.functions_examined = 1;
        first.analysis.decode_attempts = 1;
        commit_replacement(&mut state, &info, &first).unwrap();
        assert_eq!(
            state.progress(),
            FunctionProgress {
                processed: 1,
                total: 2
            }
        );

        // New inventory grows the denominator without inflating processed counts.
        info.functions.extend((0..3).map(|index| FunctionInfo {
            address: 0x1040 + index * 16,
            name: format!("new{index}"),
        }));
        let request = state.begin(1, 1, 0).unwrap();
        let mut second = batch(request, &info);
        second.outcomes[0].status = DiscoveryStatus::PartialByOwnLimit;
        second.analysis.partial = true;
        commit_replacement(&mut state, &info, &second).unwrap();
        assert_eq!(
            state.progress(),
            FunctionProgress {
                processed: 2,
                total: 5
            }
        );
        let request = state.begin(1, 1, 0).unwrap();
        let mut failed = batch(request, &info);
        failed.outcomes[0].status = DiscoveryStatus::Failed;
        failed.analysis.failed_functions = 1;
        commit_replacement(&mut state, &info, &failed).unwrap();
        assert_eq!(
            state.progress(),
            FunctionProgress {
                processed: 5,
                total: 5
            }
        );
        assert!(state.partial());

        // Exhausting interruption retries also constitutes a terminal attempt.
        let mut state = Discovery::new(None, [0x1000], false);
        for _ in 0..MAX_DISCOVERY_INTERRUPTION_ATTEMPTS {
            state.begin(1, 1, 0).unwrap();
            state.interrupt();
        }
        assert_eq!(
            state.progress(),
            FunctionProgress {
                processed: 1,
                total: 1
            }
        );
        assert_eq!(state.status(0x1000), Some(Status::Failed));
    }

    #[test]
    fn the_pattern_scan_runs_after_seeds_and_admits_only_new_inventory_starts() {
        let mut info = info(1);
        let mut state = Discovery::new(Some(info.entry), [], false);
        state.start_patterns();
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
                patterns: Some(crate::model::DiscoveryCursor::Patterns(cursor)),
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
            pointers: None,
            admissions: Vec::new(),
            recovery_records: 0,
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
        done.patterns.as_mut().unwrap().scanned_bytes = 0xff000;
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
                pointers: None,
                admissions: Vec::new(),
                recovery_records: 0,
            };
            commit_replacement(&mut state, &info, &stalled).unwrap();
        }
        assert!(state.patterns.as_ref().unwrap().partial && state.partial());
    }

    #[test]
    fn pattern_coverage_must_be_distinct_within_each_worker_epoch() {
        let info = info(2);
        let mut state = pattern_state(&info);
        let first = state.begin(1, 7, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = first else {
            panic!()
        };
        let covered = vec![info.functions[0].address];
        commit_replacement(
            &mut state,
            &info,
            &pattern_reply(binding, &info, Some(0), covered.clone()),
        )
        .unwrap();

        let repeated = state.begin(1, 7, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = repeated else {
            panic!()
        };
        let repeated = pattern_reply(binding, &info, Some(0), covered);
        for _ in 0..3 {
            assert!(commit_replacement(&mut state, &info, &repeated).is_err());
            let phase = state.patterns.as_ref().unwrap();
            assert_eq!(phase.cursor, Some(0));
            assert_eq!(phase.covered.len(), 1, "a rejected reply is atomic");
        }
    }

    #[test]
    fn pattern_preparation_can_span_batches_and_restart_in_a_new_epoch() {
        let info = info(2);
        let mut state = pattern_state(&info);
        for &address in &[info.functions[0].address, info.functions[1].address] {
            let request = state.begin(1, 11, 0).unwrap();
            let Request::DiscoverBatch { binding, .. } = request else {
                panic!()
            };
            commit_replacement(
                &mut state,
                &info,
                &pattern_reply(binding, &info, Some(0), vec![address]),
            )
            .unwrap();
        }
        assert_eq!(state.patterns.as_ref().unwrap().covered.len(), 2);

        // A replacement worker has no coverage state, so replaying the same
        // identities is necessary and valid once in its new epoch.
        let request = state.begin(1, 12, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        commit_replacement(
            &mut state,
            &info,
            &pattern_reply(
                binding,
                &info,
                Some(0),
                info.functions.iter().map(|f| f.address).collect(),
            ),
        )
        .unwrap();
        let phase = state.patterns.as_ref().unwrap();
        assert_eq!(phase.coverage_epoch, Some(12));
        assert_eq!(phase.covered.len(), 2);
        assert!(!phase.partial);
    }

    #[test]
    fn pattern_scan_counters_are_bounded_and_overflow_is_atomic() {
        let info = info(0);
        let mut state = pattern_state(&info);
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut oversized = pattern_reply(binding, &info, None, vec![]);
        oversized.patterns.as_mut().unwrap().scanned_bytes = MAX_PATTERN_SCAN_BYTES + 1;
        oversized.patterns.as_mut().unwrap().partial = true;
        assert!(commit_replacement(&mut state, &info, &oversized).is_err());
        assert_eq!(state.patterns.as_ref().unwrap().scanned_bytes, 0);

        state.patterns.as_mut().unwrap().scanned_bytes = u64::MAX;
        let mut overflow = pattern_reply(binding, &info, Some(0x1001), vec![]);
        overflow.patterns.as_mut().unwrap().scanned_bytes = 1;
        assert!(commit_replacement(&mut state, &info, &overflow).is_err());
        assert_eq!(state.patterns.as_ref().unwrap().scanned_bytes, u64::MAX);
    }

    #[test]
    fn pattern_cursor_progress_is_charged_in_executable_bytes() {
        let mut info = info(0);
        info.sections = vec![
            SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: MAX_PATTERN_SCAN_BYTES,
                file_offset: 0,
                file_size: MAX_PATTERN_SCAN_BYTES,
                executable: true,
            },
            SectionInfo {
                name: ".far".into(),
                address: 0x1_0000_0000,
                size: 0x1000,
                file_offset: MAX_PATTERN_SCAN_BYTES,
                file_size: 0x1000,
                executable: true,
            },
        ];
        info.file_len = MAX_PATTERN_SCAN_BYTES + 0x1000;

        let mut state = pattern_state(&info);
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut across_gap = pattern_reply(binding, &info, Some(0x1_0000_0000), vec![]);
        across_gap.patterns.as_mut().unwrap().scanned_bytes = MAX_PATTERN_SCAN_BYTES;
        commit_replacement(&mut state, &info, &across_gap).unwrap();
        assert_eq!(state.patterns.as_ref().unwrap().cursor, Some(0x1_0000_0000));

        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut done = pattern_reply(binding, &info, None, vec![]);
        done.patterns.as_mut().unwrap().scanned_bytes = 0x1000;
        commit_replacement(&mut state, &info, &done).unwrap();
        assert!(!state.scanning());
        assert_eq!(
            state.patterns.as_ref().unwrap().scanned_bytes,
            MAX_PATTERN_SCAN_BYTES + 0x1000
        );
    }

    #[test]
    fn pattern_cursor_rejects_free_or_overlong_forward_jumps() {
        let info = info(0);
        let mut state = pattern_state(&info);
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };

        // Moving through the unmapped prefix without any scan or match work
        // used to reset the stall counter indefinitely one address at a time.
        let free = pattern_reply(binding, &info, Some(0x1000), vec![]);
        assert!(commit_replacement(&mut state, &info, &free).is_err());
        assert_eq!(state.patterns.as_ref().unwrap().cursor, Some(0));

        // An uncharged match resume must remain inside the one current chunk.
        let mut overlong = pattern_reply(
            binding,
            &info,
            Some(0x1000 + PATTERN_SCAN_CHUNK_BYTES as u64),
            vec![],
        );
        let scan = overlong.patterns.as_mut().unwrap();
        scan.matches = 1;
        scan.validated = 1;
        assert!(commit_replacement(&mut state, &info, &overlong).is_err());
        assert_eq!(state.patterns.as_ref().unwrap().cursor, Some(0));
    }

    #[test]
    fn pattern_cursor_accepts_a_match_resume_inside_the_current_chunk() {
        let info = info(0);
        let mut state = pattern_state(&info);
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut resumed = pattern_reply(binding, &info, Some(0x1020), vec![]);
        let scan = resumed.patterns.as_mut().unwrap();
        scan.matches = MAX_PATTERN_VALIDATIONS + 1;
        scan.validated = MAX_PATTERN_VALIDATIONS;
        commit_replacement(&mut state, &info, &resumed).unwrap();
        assert_eq!(state.patterns.as_ref().unwrap().cursor, Some(0x1020));
        assert_eq!(state.patterns.as_ref().unwrap().scanned_bytes, 0);
    }

    #[test]
    fn pattern_cursor_limit_contains_plausible_fabricated_progress() {
        let info = info(0);
        let mut state = pattern_state(&info);
        state.patterns.as_mut().unwrap().cursor_steps = MAX_PATTERN_CURSOR_STEPS - 1;
        let request = state.begin(1, 1, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut resumed = pattern_reply(binding, &info, Some(0x1001), vec![]);
        let scan = resumed.patterns.as_mut().unwrap();
        scan.matches = 1;
        scan.validated = 1;
        commit_replacement(&mut state, &info, &resumed).unwrap();
        let phase = state.patterns.as_ref().unwrap();
        assert_eq!(phase.cursor_steps, MAX_PATTERN_CURSOR_STEPS);
        assert!(phase.cursor.is_none() && phase.partial);
    }

    #[test]
    fn match_resume_budget_is_smaller_and_distinct_from_coverage_preparation() {
        let info = info(1);
        let mut state = pattern_state(&info);
        state.patterns.as_mut().unwrap().resume_steps = MAX_PATTERN_RESUME_STEPS - 1;

        // A coverage-only reply does not consume either cursor allowance.
        let request = state.begin(1, 7, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        commit_replacement(
            &mut state,
            &info,
            &pattern_reply(binding, &info, Some(0), vec![info.entry]),
        )
        .unwrap();
        let phase = state.patterns.as_ref().unwrap();
        assert_eq!(phase.cursor_steps, 0);
        assert_eq!(phase.resume_steps, MAX_PATTERN_RESUME_STEPS - 1);
        assert_eq!(phase.cursor, Some(0));

        // A plausible one-byte forward resume with no charged scan bytes uses
        // the final independent resume allowance and ends explicitly partial.
        let request = state.begin(1, 7, 0).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut resumed = pattern_reply(binding, &info, Some(0x1001), vec![]);
        let scan = resumed.patterns.as_mut().unwrap();
        scan.matches = 1;
        scan.validated = 1;
        commit_replacement(&mut state, &info, &resumed).unwrap();
        let phase = state.patterns.as_ref().unwrap();
        assert_eq!(phase.resume_steps, MAX_PATTERN_RESUME_STEPS);
        assert!(phase.cursor.is_none() && phase.partial);
    }

    #[test]
    fn exhausted_pattern_allowance_does_not_hide_invalid_base_or_binding() {
        let info = info(2);
        let mut state = Discovery::new(None, [], false);
        state.start_patterns();
        state.patterns.as_mut().unwrap().inventory_validation_rows =
            MAX_PATTERN_INVENTORY_VALIDATION_ROWS;
        let Request::DiscoverBatch { binding, .. } = state.begin(1, 1, 0).unwrap() else {
            panic!()
        };
        let mut reply = pattern_reply(binding, &info, Some(0), vec![]);
        reply.inventory = InventoryChange::Unchanged { revision: 999 };
        assert!(
            state
                .commit_reply(&info, None, Some(999), &mut reply)
                .is_err()
        );
        assert!(state.scanning());
        reply.inventory = InventoryChange::Replace {
            revision: 1,
            functions: info.functions.clone(),
        };
        reply.binding.epoch += 1;
        assert!(state.commit_reply(&info, None, None, &mut reply).is_err());
        reply.binding = binding;
        assert!(matches!(
            state.commit_reply(&info, None, None, &mut reply).unwrap(),
            ReplyCommit::PatternBudgetExhausted
        ));
        // The rejected revision is not a base, even after explicitly starting
        // another phase. A replacement is required before unchanged can work.
        state.start_patterns();
        let Request::DiscoverBatch { binding, .. } = state.begin(1, 1, 0).unwrap() else {
            panic!()
        };
        reply.binding = binding;
        reply.inventory = InventoryChange::Unchanged { revision: 1 };
        assert!(state.commit_reply(&info, None, None, &mut reply).is_err());
        assert_eq!(state.admitted, None);
    }

    #[test]
    fn pattern_inventory_work_exhaustion_fails_closed_and_preserves_prior_commits() {
        let info = info(2);
        let mut state = Discovery::new(
            Some(info.entry),
            info.functions.iter().map(|function| function.address),
            false,
        );
        let mut first = batch(state.begin(1, 1, 0).unwrap(), &info);
        first.analysis.references.push(CallReference {
            caller: info.entry,
            address: info.entry,
            target: info.functions[1].address,
        });
        let (inventory, changed) = state
            .commit_reply(&info, None, None, &mut first)
            .unwrap()
            .into_adopted()
            .unwrap();
        assert!(changed);
        let prior_references = state.report.references.clone();
        let prior_functions_examined = state.report.functions_examined;
        let prior_decode_attempts = state.report.decode_attempts;
        let prior_batches = state.batches;

        state.start_patterns();
        state.patterns.as_mut().unwrap().inventory_validation_rows =
            MAX_PATTERN_INVENTORY_VALIDATION_ROWS - 1;
        let request = state.begin(1, 1, inventory.revision()).unwrap();
        let Request::DiscoverBatch { binding, .. } = request else {
            panic!()
        };
        let mut reply = pattern_reply(binding, &info, Some(0), vec![info.entry]);
        let InventoryChange::Replace { functions, .. } = &mut reply.inventory else {
            panic!()
        };
        functions[1] = functions[0].clone();
        reply.analysis.functions_examined = usize::MAX;
        reply.analysis.references.push(CallReference {
            caller: u64::MAX,
            address: u64::MAX,
            target: u64::MAX,
        });
        reply.outcomes.push(DiscoveryOutcome {
            address: u64::MAX,
            status: DiscoveryStatus::Done,
        });
        let scan = reply.patterns.as_mut().unwrap();
        scan.matches = MAX_PATTERN_MATCHES + 1;
        scan.covered = vec![u64::MAX];

        assert!(
            state
                .commit_reply(
                    &info,
                    Some(&inventory),
                    Some(inventory.revision()),
                    &mut reply
                )
                .unwrap()
                .into_adopted()
                .is_none()
        );
        let InventoryChange::Replace { functions, .. } = &reply.inventory else {
            panic!()
        };
        assert_eq!(functions[0], functions[1]);
        let phase = state.patterns.as_ref().unwrap();
        assert_eq!(
            phase.inventory_validation_rows,
            MAX_PATTERN_INVENTORY_VALIDATION_ROWS - 1
        );
        assert!(phase.cursor.is_none() && phase.partial);
        assert!(state.flight.is_none());
        assert_eq!(state.report.references, prior_references);
        assert_eq!(state.report.functions_examined, prior_functions_examined);
        assert_eq!(state.report.decode_attempts, prior_decode_attempts);
        assert_eq!(state.batches, prior_batches);
        assert_eq!(state.admitted, Some((1, inventory.revision())));
        assert_eq!(inventory.functions(), info.functions);
        assert!(state.report.partial);
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

    fn taken(function: u64, address: u64, target: u64) -> AddressReference {
        AddressReference {
            function,
            address,
            target,
            provenance: DataProvenance::InstructionLocal,
        }
    }

    #[test]
    fn address_evidence_merges_under_its_own_cap_and_never_admits_functions() {
        let info = info(2);
        let mut state = Discovery::new(Some(info.entry), [], false);
        let mut first = batch(state.begin(1, 1, 0).unwrap(), &info);
        first.outcomes.truncate(1);
        first.analysis.functions_examined = 1;
        first.analysis.decode_attempts = MAX_ANALYSIS_INSTRUCTIONS;
        // Taken code addresses that are not functions stay unadmitted.
        first.analysis.addresses = Some(Box::new(AddressAnalysis {
            references: (0..MAX_ADDRESS_REFERENCES as u64)
                .map(|n| taken(info.entry, info.entry + n % 64, 0x50000 + n))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            candidates_examined: MAX_ADDRESS_CANDIDATES,
            ..Default::default()
        }));
        commit_replacement(&mut state, &info, &first).unwrap();
        assert_eq!(state.status(0x50000), None);
        assert!(!state.capped);
        let addresses = state.report.addresses.as_ref().unwrap();
        assert_eq!(addresses.references.len(), MAX_ADDRESS_REFERENCES);
        assert!(addresses.partial && state.partial());

        // Forged replies leave the publication unchanged: x86 evidence cannot
        // be propagated, and owners must be this batch's examined seeds.
        let request = state.begin(1, 1, 0).unwrap();
        let mut second = batch(request, &info);
        second.analysis.addresses = Some(Box::new(AddressAnalysis {
            references: vec![AddressReference {
                provenance: DataProvenance::Propagated,
                ..taken(0x1010, 0x1010, 0x60000)
            }],
            candidates_examined: 1,
            ..Default::default()
        }));
        assert!(commit_replacement(&mut state, &info, &second).is_err());
        second.analysis.addresses.as_mut().unwrap().references =
            vec![taken(info.entry, 0x1010, 0x60000)];
        assert!(commit_replacement(&mut state, &info, &second).is_err());
        second.analysis.addresses.as_mut().unwrap().references =
            vec![taken(0x1010, 0x1010, 0x0fff)];
        assert!(commit_replacement(&mut state, &info, &second).is_err());
        assert_eq!(state.batches, 1);

        // The cumulative cap holds while seed coverage continues.
        second.analysis.addresses.as_mut().unwrap().references =
            vec![taken(0x1010, 0x1010, 0x60000)];
        commit_replacement(&mut state, &info, &second).unwrap();
        let addresses = state.report.addresses.as_ref().unwrap();
        assert_eq!(addresses.references.len(), MAX_ADDRESS_REFERENCES);
        assert_eq!(addresses.candidates_examined, MAX_ADDRESS_CANDIDATES + 1);
        assert_eq!(state.remaining(), 0);

        // The publication round-trips and cannot hide its partial coverage.
        let saved = state.save();
        let json = serde_json::to_vec(&saved).unwrap();
        let parsed: DiscoverySnapshot = serde_json::from_slice(&json).unwrap();
        parsed.validate(&info).unwrap();
        let mut forged = parsed.clone();
        forged.report.partial = false;
        forged.capped = false;
        assert!(forged.validate(&info).is_err());
        let mut forged = parsed;
        forged
            .report
            .addresses
            .as_mut()
            .unwrap()
            .candidates_examined = 0;
        assert!(forged.validate(&info).is_err());
    }

    #[test]
    fn legacy_discovery_without_addresses_decodes_as_unavailable() {
        let info = info(1);
        let mut state = Discovery::new(Some(info.entry), [], false);
        let first = batch(state.begin(1, 1, 0).unwrap(), &info);
        commit_replacement(&mut state, &info, &first).unwrap();
        let mut json: serde_json::Value = serde_json::to_value(state.save()).unwrap();
        // Absent, not an empty examined result.
        assert!(json["report"].get("addresses").is_none());
        json["report"]["addresses"] = serde_json::Value::Null;
        let parsed: DiscoverySnapshot = serde_json::from_value(json).unwrap();
        assert!(parsed.report.addresses.is_none());
        parsed.validate(&info).unwrap();
    }

    #[test]
    fn pattern_steps_cannot_carry_address_evidence() {
        let info = info(2);
        let mut state = pattern_state(&info);
        let Request::DiscoverBatch { binding, .. } = state.begin(1, 7, 0).unwrap() else {
            panic!()
        };
        let mut reply = pattern_reply(binding, &info, Some(0), vec![info.functions[0].address]);
        reply.analysis.addresses = Some(Box::default());
        assert!(commit_replacement(&mut state, &info, &reply).is_err());
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
