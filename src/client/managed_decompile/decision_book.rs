//! Host-owned decisions and verified results for the current program context.
//! Workers receive a bounded seed and can only propose a change. Both
//! executors share this acceptance path.

use super::{Final, Prepared, Settlement, check_candidate, count, remaining_ms};
use crate::analysis::managed::{self, DebugOffer, PeerJob, Report, Seed, Ticket};
use crate::analysis::{
    CALLEE_UNVERIFIED_WARNING, CALLER_EVIDENCE_WARNING, DebugOutcome, OPTIONAL_UNAVAILABLE_WARNING,
    OWN_EVIDENCE_WARNING, Published, RESULT_CACHE_BYTES, RESULT_CACHE_ENTRIES,
    RESULT_CACHE_MAX_ENTRY, SETUP_CUTOFF_WARNING, UNVERIFIED_WARNING, Unchanged,
};
use crate::debug_info::{Change, Decision, EntryState, Status};
use crate::model::{BinaryInfo, MAX_FUNCTIONS, Response};
use crate::semantic::{LocalRename, SemanticInfo};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Instant;

#[derive(Default)]
pub(crate) struct DecisionBook {
    program: String,
    version: u64,
    latest_logical_id: u64,
    active: Option<Ticket>,
    states: BTreeMap<u64, EntryState>,
    large: BTreeSet<u64>,
    failed: BTreeSet<u64>,
    results: VecDeque<Cached>,
    bytes: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    decision: EntryState,
    large: bool,
    failed: bool,
}

struct Cached {
    context: String,
    code: Response,
    dependencies: Vec<(u64, Stamp)>,
    bytes: usize,
}

/// Immutable context of one managed action, held by its desktop/headless
/// owner through presentation and acceptance.
pub(crate) struct Transaction {
    pub(crate) job: PeerJob,
    offer: DebugOffer,
    cutoff: Instant,
    failed: bool,
}

/// A checked outcome and its proposed effects. Can be freely abandoned.
pub(crate) struct Staged {
    pub(crate) result: Final,
    effect: Option<Effect>,
}

struct Effect {
    ticket: Ticket,
    changes: Vec<Change>,
    large: Vec<u64>,
    failed: bool,
    cache: Option<Cached>,
    expiry: bool,
}

impl Transaction {
    /// The cutoff the transaction began with: a fork's acceptance window,
    /// or a sibling's hard cap.
    pub(crate) fn cutoff(&self) -> Instant {
        self.cutoff
    }
}

impl DecisionBook {
    /// The book's version and the sizes of its decisions, large and failed
    /// flags and cached results (for the Linux real-worker desktop test).
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn test_summary(&self) -> (u64, usize, usize, usize, usize) {
        (
            self.version,
            self.states.len(),
            self.large.len(),
            self.failed.len(),
            self.results.len(),
        )
    }

    pub(crate) fn begin(
        &mut self,
        prepared: &Prepared,
        renames: Vec<LocalRename>,
        cutoff: Instant,
    ) -> Option<Transaction> {
        let offer = prepared.offer.as_ref()?;
        let address = prepared.address;
        if offer.logical_id <= self.latest_logical_id
            || managed::context_digest(&offer.binding.program, address, &renames)
                != offer.binding.context
        {
            return None;
        }
        // Reuse across primary replacement only after it demonstrates the
        // same program context. A verified change retires the prior book.
        if self.program != offer.binding.program {
            let version = self.version.checked_add(1)?;
            self.program.clone_from(&offer.binding.program);
            self.states.clear();
            self.large.clear();
            self.failed.clear();
            self.results.clear();
            self.bytes = 0;
            self.version = version;
        }
        let ticket = Ticket {
            logical_id: offer.logical_id,
            nonce: offer.nonce,
            book_version: self.version,
        };
        if !ticket.valid() {
            return None;
        }
        let mut states = offer
            .callees
            .iter()
            .copied()
            .chain(offer.target_work.then_some(address))
            .filter_map(|entry| self.states.get(&entry).copied().map(|state| (entry, state)))
            .collect::<Vec<_>>();
        states.sort_unstable_by_key(|&(entry, _)| entry);
        let seed = Seed {
            states,
            large: offer
                .callees
                .iter()
                .copied()
                .filter(|entry| self.large.contains(entry))
                .collect(),
        };
        let failed = self.failed.contains(&address);
        let job = PeerJob {
            ticket,
            address,
            remaining_ms: remaining_ms(cutoff),
            renames,
            binding: offer.binding.clone(),
            target_work: !failed && offer.target_work && seed.target_eligible(address),
            graph_prepared: offer.graph_prepared,
            callees: if failed {
                Vec::new()
            } else {
                offer
                    .callees
                    .iter()
                    .copied()
                    .filter(|&entry| seed.callee_eligible(entry))
                    .collect()
            },
            seed,
        };
        self.latest_logical_id = ticket.logical_id;
        self.active = Some(ticket);
        Some(Transaction {
            job,
            offer: offer.clone(),
            cutoff,
            failed,
        })
    }

    pub(crate) fn cancel(&mut self, transaction: &Transaction) {
        if self.active == Some(transaction.job.ticket) {
            self.active = None;
        }
    }

    fn stamp(&self, entry: u64) -> Stamp {
        Stamp {
            decision: self.states.get(&entry).copied().unwrap_or_default(),
            large: self.large.contains(&entry),
            failed: self.failed.contains(&entry),
        }
    }

    /// Look up a result only when this primary has attested the context and
    /// no intervening request can have changed it.
    pub(crate) fn cached(
        &mut self,
        program: Option<&str>,
        address: u64,
        renames: &[LocalRename],
        refresh: bool,
    ) -> Option<Response> {
        if refresh || program != Some(self.program.as_str()) {
            return None;
        }
        let context = managed::context_digest(&self.program, address, renames);
        let index = self
            .results
            .iter()
            .position(|cached| cached.context == context)?;
        let cached = self.results.remove(index)?;
        if cached
            .dependencies
            .iter()
            .any(|&(entry, stamp)| stamp != self.stamp(entry))
        {
            self.bytes -= cached.bytes;
            return None;
        }
        let response = cached.code.clone();
        self.results.push_back(cached);
        count(|stats| stats.cache_hits += 1);
        crate::performance::event("debug_result_cache_hit", address);
        Some(response)
    }

    /// [`Self::accept_until`] the transaction's own cutoff.
    #[cfg(test)]
    pub(crate) fn accept(&mut self, transaction: &Transaction, staged: &mut Staged) -> bool {
        self.accept_until(transaction, staged, transaction.cutoff)
    }

    /// One serialized commit of attempts, sparse decisions, failure/large
    /// flags and the LRU. Non-expiry effects must be accepted before
    /// `cutoff`: a sibling passes its active render cutoff. The caller
    /// first checks its own display/command binding and can retain its
    /// baseline if any check fails.
    pub(crate) fn accept_until(
        &mut self,
        transaction: &Transaction,
        staged: &mut Staged,
        cutoff: Instant,
    ) -> bool {
        let ticket = transaction.job.ticket;
        if self.active != Some(ticket)
            || ticket.book_version != self.version
            || self.program != transaction.job.binding.program
            || staged
                .effect
                .as_ref()
                .is_some_and(|effect| effect.ticket != ticket)
        {
            return false;
        }
        self.active = None;
        let Some(effect) = staged.effect.take() else {
            return true;
        };
        if !effect.expiry && Instant::now() >= cutoff {
            return false;
        }
        let Some(version) = self.version.checked_add(1) else {
            return false;
        };
        if self.states.len().saturating_add(
            effect
                .changes
                .iter()
                .filter(|change| !self.states.contains_key(&change.entry))
                .count(),
        ) > MAX_FUNCTIONS
            || self.large.len().saturating_add(
                effect
                    .large
                    .iter()
                    .filter(|entry| !self.large.contains(entry))
                    .count(),
            ) > MAX_FUNCTIONS
            || (effect.failed && self.failed.len() == MAX_FUNCTIONS)
        {
            return false;
        }
        for change in effect.changes {
            self.states.insert(change.entry, change.new);
        }
        self.large.extend(effect.large);
        if effect.failed {
            self.failed.insert(transaction.job.address);
        }
        if let Some(mut cache) = effect.cache {
            for (entry, stamp) in &mut cache.dependencies {
                *stamp = self.stamp(*entry);
            }
            if cache
                .dependencies
                .iter()
                .all(|(_, stamp)| stamp.decision.status != Status::Provisional)
            {
                self.insert(cache);
            }
        }
        self.version = version;
        true
    }

    fn insert(&mut self, cached: Cached) {
        if let Some(index) = self
            .results
            .iter()
            .position(|entry| entry.context == cached.context)
        {
            self.bytes -= self.results.remove(index).expect("cache index").bytes;
        }
        self.bytes += cached.bytes;
        self.results.push_back(cached);
        while self.bytes > RESULT_CACHE_BYTES || self.results.len() > RESULT_CACHE_ENTRIES {
            self.bytes -= self.results.pop_front().expect("overflowing cache").bytes;
        }
    }
}

impl Transaction {
    pub(crate) fn has_work(&self) -> bool {
        self.job.target_work || !self.job.callees.is_empty()
    }

    pub(crate) fn stage_reply(
        &self,
        prepared: &Prepared,
        response: Response,
        direct: bool,
        info: &BinaryInfo,
        signature_context: &str,
    ) -> Staged {
        match response {
            Response::DebugFinished {
                ticket,
                measured,
                outcome,
            } if ticket == self.job.ticket && measured == self.job.binding => {
                self.stage_outcome(prepared, outcome.0, info, signature_context)
            }
            Response::DebugUnavailable { ticket, reason } if ticket == self.job.ticket => {
                self.stage_fallback(direct && reason == "expired", reason == "unavailable")
            }
            _ => Staged::unverified(),
        }
    }

    pub(crate) fn stage_outcome(
        &self,
        prepared: &Prepared,
        outcome: DebugOutcome,
        info: &BinaryInfo,
        signature_context: &str,
    ) -> Staged {
        let (report, render) = outcome.split();
        let (changes, large) = report.decisions();
        let address = self.job.address;
        let callees = &self.job.callees;
        let target_work = self.job.target_work;
        let state_after = |entry| state_after(&self.job.seed, changes, entry);
        if !changes.windows(2).all(|pair| pair[0].entry < pair[1].entry)
            || changes.iter().any(|change| {
                !(if change.entry == address {
                    target_work
                } else {
                    callees.binary_search(&change.entry).is_ok()
                }) || change.old != self.job.seed.state(change.entry)
                    || change.old == change.new
                    || !change.old.allows(&change.new)
            })
            || !large.windows(2).all(|pair| pair[0] < pair[1])
            || large
                .iter()
                .any(|entry| callees.binary_search(entry).is_err())
        {
            return Staged::unverified();
        }
        let (owned, callee_shown, vetoed, own_vetoed, failed) = match &report {
            Report::Candidate {
                target_owns,
                installed_callees,
                compared,
                vetoed,
                ..
            } => {
                if !*compared
                    || (!*target_owns && installed_callees.is_empty())
                    || (*vetoed && (!*target_owns || !installed_callees.is_empty()))
                    || (*target_owns
                        && (!target_work || state_after(address).status != Status::Verified))
                    || !installed_callees.windows(2).all(|pair| pair[0] < pair[1])
                    || installed_callees.iter().any(|entry| {
                        callees.binary_search(entry).is_err()
                            || state_after(*entry).decision() != Decision::Accepted
                    })
                    || render.as_ref().is_none_or(|render| {
                        check_candidate(address, render, info, signature_context).is_err()
                    })
                {
                    return Staged::unverified();
                }
                (*target_owns, !*vetoed, *vetoed, false, false)
            }
            Report::UseReference { reason, .. } => {
                if (*reason == Unchanged::OwnEvidenceLost && !target_work)
                    || (*reason == Unchanged::EvidenceLost && callees.is_empty())
                {
                    return Staged::unverified();
                }
                (
                    false,
                    true,
                    *reason == Unchanged::EvidenceLost,
                    *reason == Unchanged::OwnEvidenceLost,
                    false,
                )
            }
            Report::Failed { .. } => (false, false, false, false, true),
        };
        let calls = render
            .as_ref()
            .map_or(self.offer.calls.as_slice(), |body| &body.calls);
        let mut settlement = self.warnings(calls, changes, callee_shown, owned, failed);
        if vetoed {
            // Caller veto replaces the independent unverified-callee warning.
            settlement
                .warnings
                .retain(|warning| warning != CALLEE_UNVERIFIED_WARNING);
            settlement
                .warnings
                .insert(0, CALLER_EVIDENCE_WARNING.into());
        }
        if own_vetoed {
            settlement
                .warnings
                .retain(|warning| warning != UNVERIFIED_WARNING);
            settlement.warnings.insert(0, OWN_EVIDENCE_WARNING.into());
        }
        let cache = self.cache(prepared, render.as_deref(), &settlement, changes);
        Staged {
            result: match render {
                Some(render) => Final::Candidate(render, settlement),
                None => Final::Baseline(settlement),
            },
            effect: Some(Effect {
                ticket: self.job.ticket,
                changes: changes.to_vec(),
                large: large.to_vec(),
                failed,
                cache,
                expiry: false,
            }),
        }
    }

    pub(crate) fn stage_no_work(&self, prepared: &Prepared) -> Staged {
        let settlement = self.warnings(&self.offer.calls, &[], false, false, self.failed);
        let cache = self.cache(prepared, None, &settlement, &[]);
        Staged {
            result: Final::Baseline(settlement),
            effect: cache.map(|cache| Effect {
                ticket: self.job.ticket,
                changes: Vec::new(),
                large: Vec::new(),
                failed: false,
                cache: Some(cache),
                expiry: false,
            }),
        }
    }

    pub(crate) fn stage_fallback(&self, expired_direct: bool, unavailable: bool) -> Staged {
        let address = self.job.address;
        let old = self.job.seed.state(address);
        let new = old.deferred_target();
        let changes = if expired_direct && self.job.target_work && old != new {
            vec![Change {
                entry: address,
                old,
                new,
            }]
        } else {
            Vec::new()
        };
        let mut settlement = self.warnings(&self.offer.calls, &changes, false, false, false);
        if unavailable {
            settlement
                .warnings
                .insert(0, OPTIONAL_UNAVAILABLE_WARNING.into());
        }
        Staged {
            result: Final::Baseline(settlement),
            effect: (!changes.is_empty()).then_some(Effect {
                ticket: self.job.ticket,
                changes,
                large: Vec::new(),
                failed: false,
                cache: None,
                expiry: true,
            }),
        }
    }

    /// A sibling whose setup used up its allowance before any render: the
    /// baseline with its callee warnings and one setup reason in place of
    /// the generic target warning. No journal, cache entry or skip.
    pub(crate) fn stage_setup_cutoff(&self) -> Staged {
        let mut settlement = self.warnings(&self.offer.calls, &[], false, false, self.failed);
        settlement
            .warnings
            .retain(|warning| warning != UNVERIFIED_WARNING);
        settlement.warnings.insert(0, SETUP_CUTOFF_WARNING.into());
        Staged {
            result: Final::Baseline(settlement),
            effect: None,
        }
    }

    fn warnings(
        &self,
        calls: &[u64],
        changes: &[Change],
        callees_shown: bool,
        owned: bool,
        failed: bool,
    ) -> Settlement {
        let decision = |entry| state_after(&self.job.seed, changes, entry).decision();
        let mut warnings = Vec::new();
        if failed {
            warnings.push(crate::debug_info::ENGINE_FAILURE_WARNING.into());
        } else {
            if self.offer.target_work
                && !owned
                && matches!(
                    decision(self.job.address),
                    Decision::Undecided | Decision::Accepted
                )
            {
                warnings.push(UNVERIFIED_WARNING.into());
            }
            if calls.iter().any(|entry| {
                self.offer.callees.binary_search(entry).is_ok()
                    && match decision(*entry) {
                        Decision::Undecided => true,
                        Decision::Accepted => !callees_shown,
                        _ => false,
                    }
            }) {
                warnings.push(CALLEE_UNVERIFIED_WARNING.into());
            }
        }
        Settlement {
            warnings,
            debug_owned: owned,
        }
    }

    fn cache(
        &self,
        prepared: &Prepared,
        render: Option<&Published>,
        settlement: &Settlement,
        changes: &[Change],
    ) -> Option<Cached> {
        if !self.offer.cacheable
            || !settlement.warnings.is_empty()
            || render.is_some_and(|body| {
                !body.calls_complete
                    || body.text.ends_with(crate::decompile::TRUNCATION_TRAILER)
                    || body
                        .calls
                        .iter()
                        .any(|entry| self.offer.calls.binary_search(entry).is_err())
            })
        {
            return None;
        }
        let mut dependencies = vec![self.job.address];
        dependencies.extend(&self.offer.calls);
        dependencies.extend(&self.offer.callees);
        if let Some(body) = render {
            dependencies.extend(&body.calls);
        }
        dependencies.sort_unstable();
        dependencies.dedup();
        if dependencies
            .iter()
            .any(|&entry| state_after(&self.job.seed, changes, entry).status == Status::Provisional)
        {
            return None;
        }
        let (text, mappings, semantics) = render.map_or(
            (&prepared.text, &prepared.mappings, &prepared.semantics),
            |body| (&body.text, &body.mappings, &body.semantics),
        );
        let bytes = code_bytes(text, mappings, semantics)?
            .saturating_add(
                dependencies
                    .len()
                    .saturating_mul(std::mem::size_of::<(u64, Stamp)>()),
            )
            .saturating_add(256);
        if bytes > RESULT_CACHE_MAX_ENTRY {
            return None;
        }
        let mut semantics = semantics.clone();
        if settlement.debug_owned {
            semantics.prototype_source = crate::semantic::PrototypeSource::DebugInfo;
        }
        Some(Cached {
            context: self.job.binding.context.clone(),
            code: Response::Decompiled {
                address: self.job.address,
                text: text.clone(),
                mappings: mappings.clone(),
                semantics,
            },
            dependencies: dependencies
                .into_iter()
                .map(|entry| {
                    (
                        entry,
                        Stamp {
                            decision: EntryState::default(),
                            large: false,
                            failed: false,
                        },
                    )
                })
                .collect(),
            bytes,
        })
    }
}

impl Staged {
    pub(crate) fn take_result(&mut self) -> Final {
        std::mem::replace(&mut self.result, Final::Baseline(Settlement::default()))
    }

    pub(crate) fn unverified() -> Self {
        Self {
            result: Final::Baseline(Settlement {
                warnings: vec![UNVERIFIED_WARNING.into()],
                debug_owned: false,
            }),
            effect: None,
        }
    }
}

fn state_after(seed: &Seed, changes: &[Change], entry: u64) -> EntryState {
    changes
        .binary_search_by_key(&entry, |change| change.entry)
        .map_or_else(|_| seed.state(entry), |index| changes[index].new)
}

fn code_bytes(
    text: &str,
    mappings: &[crate::model::CodeMapping],
    semantics: &SemanticInfo,
) -> Option<usize> {
    let mapping_bytes = mappings.iter().fold(0usize, |bytes, mapping| {
        bytes
            .saturating_add(std::mem::size_of::<crate::model::CodeMapping>())
            .saturating_add(std::mem::size_of_val(mapping.addresses.as_slice()))
    });
    Some(
        text.len()
            .saturating_add(mapping_bytes)
            .saturating_add(crate::function_presentation::semantic_bytes(semantics)?),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::managed::{Binding, Executor};
    use crate::model::SectionInfo;
    use std::time::Duration;

    const TARGET: u64 = 0x1000;
    const CALLEE: u64 = 0x1200;

    fn baseline(id: u64, address: u64, calls: Vec<u64>) -> Prepared {
        let program = "a".repeat(64);
        let text = format!("void FUN_{address:x}() {{ }}");
        let semantics = SemanticInfo::default();
        let binding = Binding {
            context: managed::context_digest(&program, address, &[]),
            baseline: managed::baseline_digest(address, &text, &[], &semantics, &calls),
            facts: "b".repeat(64),
            program,
        };
        Prepared {
            address,
            text,
            mappings: Vec::new(),
            semantics,
            offer: Some(DebugOffer {
                logical_id: id,
                nonce: id,
                executor: Executor::Sibling,
                reference_us: 1,
                elapsed_us: 2,
                binding,
                calls: calls.clone(),
                graph_prepared: true,
                target_work: true,
                callees: calls,
                cacheable: true,
            }),
        }
    }

    fn info() -> BinaryInfo {
        BinaryInfo {
            format: "ELF".into(),
            architecture: "x86-64".into(),
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: TARGET,
                size: 0x1000,
                file_size: 0x1000,
                file_offset: 0,
                executable: true,
            }],
            path: String::new(),
            entry: TARGET,
            file_len: 0x1000,
            sha256: "c".repeat(64),
            source_identity: Default::default(),
            functions: Vec::new(),
            functions_truncated: false,
            warnings: Vec::new(),
        }
    }

    fn start(book: &mut DecisionBook, baseline: &Prepared) -> Transaction {
        book.begin(
            baseline,
            Vec::new(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap()
    }

    fn verified() -> EntryState {
        EntryState {
            status: Status::Verified,
            ..Default::default()
        }
    }

    fn rejected() -> EntryState {
        EntryState {
            status: Status::Rejected,
            ..Default::default()
        }
    }

    fn reference(book: &mut DecisionBook, request: &Prepared) {
        let tx = start(book, request);
        let mut staged = tx.stage_outcome(
            request,
            DebugOutcome::UseReference {
                reason: Unchanged::NothingInstalled,
                changes: vec![Change {
                    entry: request.address,
                    old: tx.job.seed.state(request.address),
                    new: rejected(),
                }],
                large: Vec::new(),
            },
            &info(),
            "",
        );
        assert!(book.accept(&tx, &mut staged));
    }

    #[test]
    fn managed_debug_cache_tracks_related_decisions_and_refresh_bypasses_hits() {
        let mut book = DecisionBook::default();
        let warm = baseline(1, TARGET, vec![CALLEE]);
        let tx = start(&mut book, &warm);
        let mut staged = tx.stage_outcome(
            &warm,
            DebugOutcome::Candidate {
                render: Box::new(Published {
                    text: "void typed() { callee(); }".into(),
                    mappings: Vec::new(),
                    semantics: SemanticInfo::default(),
                    calls: vec![CALLEE],
                    calls_complete: true,
                }),
                target_owns: true,
                installed_callees: vec![CALLEE],
                compared: true,
                vetoed: false,
                changes: [TARGET, CALLEE]
                    .into_iter()
                    .map(|entry| Change {
                        entry,
                        old: EntryState::default(),
                        new: verified(),
                    })
                    .collect(),
                large: Vec::new(),
            },
            &info(),
            "",
        );
        assert!(book.accept(&tx, &mut staged));
        let program = tx.job.binding.program.as_str();
        for _ in 0..30 {
            let Some(Response::Decompiled {
                text, semantics, ..
            }) = book.cached(Some(program), TARGET, &[], false)
            else {
                panic!("verified hit")
            };
            assert_eq!(text, "void typed() { callee(); }");
            assert_eq!(
                semantics.prototype_source,
                crate::semantic::PrototypeSource::DebugInfo
            );
        }
        assert!(book.cached(Some(program), TARGET, &[], true).is_none());
        let other_callee = baseline(2, 0x1201, Vec::new());
        reference(&mut book, &other_callee);
        assert!(book.cached(Some(program), TARGET, &[], false).is_some());
        let dependency = baseline(3, CALLEE, Vec::new());
        reference(&mut book, &dependency);
        assert!(book.cached(Some(program), TARGET, &[], false).is_none());
    }

    #[test]
    fn managed_debug_cache_evicts_and_oversized_results_do_not_replace_warm_entries() {
        let mut book = DecisionBook::default();
        let first = baseline(1, TARGET, Vec::new());
        reference(&mut book, &first);
        let program = first.offer.as_ref().unwrap().binding.program.as_str();
        let mut oversized = baseline(2, TARGET + 1, Vec::new());
        oversized.text = "a".repeat(RESULT_CACHE_MAX_ENTRY);
        reference(&mut book, &oversized);
        assert!(book.cached(Some(program), TARGET + 1, &[], false).is_none());
        assert!(book.cached(Some(program), TARGET, &[], false).is_some());
        for index in 0..RESULT_CACHE_ENTRIES as u64 {
            reference(
                &mut book,
                &baseline(index + 3, TARGET + index + 2, Vec::new()),
            );
        }
        assert!(book.cached(Some(program), TARGET, &[], false).is_none());

        let second = baseline(100, TARGET, Vec::new());
        let tx = start(&mut book, &second);
        assert!(
            !tx.has_work(),
            "LRU eviction preserves independent decisions"
        );
        let mut stage = tx.stage_no_work(&second);
        assert!(book.accept(&tx, &mut stage));
        let mut fresh = DecisionBook::default();
        reference(&mut fresh, &first);
        let cached = |book: &mut DecisionBook| {
            serde_json::to_value(book.cached(Some(program), TARGET, &[], false).unwrap()).unwrap()
        };
        assert_eq!(cached(&mut book), cached(&mut fresh));
    }

    #[test]
    fn managed_debug_stale_queued_completion_and_expiry_have_no_effect() {
        let mut book = DecisionBook::default();
        let before = baseline(1, TARGET, Vec::new());
        let tx = start(&mut book, &before);
        let mut staged = tx.stage_outcome(
            &before,
            DebugOutcome::UseReference {
                reason: Unchanged::NothingInstalled,
                changes: vec![Change {
                    entry: TARGET,
                    old: EntryState::default(),
                    new: rejected(),
                }],
                large: Vec::new(),
            },
            &info(),
            "",
        );
        let mut expiry = tx.stage_fallback(true, false);
        book.cancel(&tx);
        let next = baseline(2, TARGET, Vec::new());
        let current = start(&mut book, &next);
        assert!(!book.accept(&tx, &mut staged));
        assert!(!book.accept(&tx, &mut expiry));
        assert!(
            !book.accept(&current, &mut staged),
            "a staged effect must name its own ticket"
        );
        assert_eq!(book.stamp(TARGET).decision, EntryState::default());
        assert!(
            book.cached(Some(&tx.job.binding.program), TARGET, &[], false)
                .is_none()
        );

        let next = baseline(3, TARGET, Vec::new());
        let current = start(&mut book, &next);
        let mut expiry = current.stage_fallback(true, false);
        assert!(book.accept(&current, &mut expiry));
        assert_eq!(book.stamp(TARGET).decision.target_attempts, 1);
        assert!(!book.accept(&current, &mut expiry));
        assert!(book.begin(&next, Vec::new(), Instant::now()).is_none());
    }

    /// A sibling's non-expiry effects are admitted until its active render
    /// cutoff, not its earlier setup deadline nor its later hard cap.
    #[test]
    fn managed_scheduler_sibling_effects_need_the_active_render_cutoff() {
        let outcome = |tx: &Transaction, request: &Prepared| {
            tx.stage_outcome(
                request,
                DebugOutcome::UseReference {
                    reason: Unchanged::NothingInstalled,
                    changes: vec![Change {
                        entry: TARGET,
                        old: tx.job.seed.state(TARGET),
                        new: rejected(),
                    }],
                    large: Vec::new(),
                },
                &info(),
                "",
            )
        };
        let now = Instant::now();
        // Setup ended before now, the render cutoff is ahead: accepted.
        let mut book = DecisionBook::default();
        let request = baseline(1, TARGET, Vec::new());
        let tx = book
            .begin(&request, Vec::new(), now + Duration::from_secs(20))
            .unwrap();
        let mut staged = outcome(&tx, &request);
        assert!(book.accept_until(&tx, &mut staged, now + Duration::from_secs(5)));
        assert_eq!(book.stamp(TARGET).decision.status, Status::Rejected);
        // Admitted just after the render cutoff but before the hard cap:
        // nothing changes.
        let mut book = DecisionBook::default();
        let tx = book
            .begin(&request, Vec::new(), now + Duration::from_secs(20))
            .unwrap();
        let mut staged = outcome(&tx, &request);
        assert!(!book.accept_until(&tx, &mut staged, now));
        assert_eq!(book.stamp(TARGET).decision, EntryState::default());
        assert!(
            book.cached(Some(&tx.job.binding.program), TARGET, &[], false)
                .is_none()
        );
    }

    /// A setup cutoff keeps the baseline with one setup reason in place of
    /// the generic target warning, its callee warning, and no effect.
    #[test]
    fn managed_scheduler_setup_cutoff_stages_the_baseline_with_one_reason() {
        let mut book = DecisionBook::default();
        let request = baseline(1, TARGET, vec![CALLEE]);
        let tx = start(&mut book, &request);
        let mut staged = tx.stage_setup_cutoff();
        let Final::Baseline(settlement) = &staged.result else {
            panic!("a setup cutoff keeps the baseline");
        };
        assert_eq!(
            settlement.warnings,
            [SETUP_CUTOFF_WARNING, CALLEE_UNVERIFIED_WARNING]
        );
        assert!(!settlement.debug_owned && staged.effect.is_none());
        assert!(book.accept_until(&tx, &mut staged, Instant::now()));
        assert_eq!(book.stamp(TARGET), Stamp::default_for_test());
        assert!(
            book.cached(Some(&tx.job.binding.program), TARGET, &[], false)
                .is_none()
        );
    }

    impl Stamp {
        fn default_for_test() -> Self {
            Self {
                decision: EntryState::default(),
                large: false,
                failed: false,
            }
        }
    }

    impl std::fmt::Debug for Stamp {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "Stamp({:?}, {}, {})",
                self.decision, self.large, self.failed
            )
        }
    }
}
