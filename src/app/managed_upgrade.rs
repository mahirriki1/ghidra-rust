//! Two-stage presentation of managed decompiles. The baseline (exactly the
//! render without debug information) is shown as soon as it arrives; at most
//! one checked optional debug render then settles it in place, without
//! moving the view, selection, cursor or history. Optional work never enters
//! the ordinary pending/retry slot, never records a per-function skip, and a
//! stale settlement changes nothing.
use super::*;
use crate::client::managed_decompile::{self as managed, Optional};
use crate::result_store::TransientReservation;
use std::collections::BTreeSet;
mod preparation;
pub(super) type CodePreparation = preparation::Preparation;

type BaselineResult = Result<(managed::Prepared, PreparedDecompilation), String>;

pub(super) struct PreparingBaseline {
    pending: Pending,
    received: mpsc::Receiver<(BaselineResult, Option<TransientReservation>)>,
    generation: u64,
    epoch: u64,
    managed_revision: Option<u64>,
    failure: Option<String>,
}

enum SettlementWork {
    Reply(Box<Response>, bool),
    Peer(managed::PeerEnd),
    NoWork,
    Fallback(bool),
    Unverified,
}

struct PreparedSettlement {
    staged: managed::Staged,
    code: PreparedDecompilation,
    same_text: bool,
    same: bool,
}

type Finishing = mpsc::Receiver<(Option<PreparedSettlement>, TransientReservation)>;

/// Optional replies whose request was abandoned; their answers are dropped.
const ABANDONED_REPLIES: usize = 16;

/// Effective names a debug peer replays, keyed by the binary generation,
/// annotation revision, symbol revision and inventory length.
pub(super) type PeerFunctions = ((u64, u64, u64, usize), Arc<Vec<FunctionInfo>>);

/// A displayed baseline awaiting its optional render's settlement, bound to
/// everything the request was made under.
pub(super) struct DisplayedUpgrade {
    prepared: Arc<managed::Prepared>,
    transaction: Option<Arc<managed::Transaction>>,
    /// A fork's acceptance window; a sibling's hard cap.
    cutoff: Instant,
    /// When the baseline was adopted: a sibling's setup allowance starts
    /// here, so repaint delay before its launch consumes it.
    published: Instant,
    hard: Instant,
    optional: Option<Optional>,
    /// A sibling's timing, kept after its attempt ended for acceptance.
    timing: Option<Arc<managed::PeerTiming>>,
    /// A sibling waiting for its image's slot: its setup allowance is
    /// already running, and the slot is retried on each poll until it is
    /// spent.
    slot_wait: Option<Arc<managed::PeerTiming>>,
    generation: u64,
    epoch: u64,
    selection: u64,
    revision: u64,
    result: Option<ResultBinding>,
    local: String,
    signature_context: String,
    debug: bool,
    /// The displayed baseline allocation; settlement requires it still shown.
    code: Shared<PreparedDecompilation>,
    /// The status the baseline set; a later foreground status is kept.
    status: String,
    /// The egui pass that adopted the baseline; a settlement is applied in a
    /// later pass, so the baseline is painted at least once.
    pass: u64,
    staged: Option<SettlementWork>,
    finishing: Option<Finishing>,
    _baseline_charge: Option<TransientReservation>,
}

impl DesktopApp {
    /// The committed signature context the worker renders under.
    pub(super) fn committed_signature_context(&self) -> String {
        match &self.session {
            Some(session) if !session.signatures.is_empty() => {
                signatures::state_digest(&session.signatures)
            }
            _ => String::new(),
        }
    }

    /// Moves validation, digesting and highlighting for a managed miss
    /// off the event loop. The frame's original request remains authoritative.
    pub(super) fn receive_prepared(
        &mut self,
        pending: Pending,
        response: Response,
        context: &egui::Context,
    ) {
        if !self.baseline_current(&pending) {
            return;
        }
        let Request::Decompile { address } = pending.request else {
            return;
        };
        let Some(info) = &self.info else { return };
        let info = super::info_without_functions(info);
        let signature_context = self.committed_signature_context();
        self.cancel_upgrade();
        let estimate = match &response {
            Response::PreparedDecompile {
                text,
                mappings,
                semantics,
                ..
            } => {
                PreparedDecompilation::estimated_bytes(text, mappings, semantics).saturating_mul(2)
            }
            _ => return,
        };
        let charge = self.results.reserve_transient(estimate, &[address]);
        let prepare = move || {
            let result = managed::admit_prepared(address, response, &info, &signature_context).map(
                |mut prepared| {
                    if charge.is_none() && !cfg!(test) {
                        prepared.offer = None;
                    }
                    let code = PreparedDecompilation::prepare(
                        address,
                        prepared.text.clone(),
                        prepared.mappings.clone(),
                        prepared.semantics.clone(),
                    );
                    (prepared, code)
                },
            );
            (result, charge)
        };
        // Synthetic tests exercise the exact same validation and adoption
        // without waiting on a worker or scheduling another OS thread.
        if cfg!(test) && self.client.is_none() {
            let (result, charge) = prepare();
            self.adopt_baseline(pending, result, charge, context);
            return;
        }
        match self.code_preparation.submit(context, prepare) {
            Ok(received) => {
                self.preparing_baseline = Some(PreparingBaseline {
                    pending,
                    received,
                    generation: self.generation,
                    epoch: self.worker_epoch,
                    managed_revision: self.client.as_ref().map(|client| client.managed_revision),
                    failure: None,
                })
            }
            Err(error) => self.status = format!("Cannot prepare decompiled source: {error}"),
        }
    }

    fn baseline_current(&self, pending: &Pending) -> bool {
        matches!(pending.request, Request::Decompile { address } if self.view().is_some_and(|view| view.address == address))
            && pending.selection == self.selection_generation
            && pending.revision == self.revision
            && (pending.result.is_none() || self.results.current(pending.result.as_ref()))
    }

    pub(super) fn defer_baseline_failure(&mut self, error: String) {
        if let Some(preparing) = &mut self.preparing_baseline {
            preparing.failure = Some(error);
        }
    }

    pub(super) fn poll_baseline(&mut self, context: &egui::Context) {
        let Some(preparing) = self.preparing_baseline.take() else {
            return;
        };
        let (result, charge) = match preparing.received.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => {
                self.preparing_baseline = Some(preparing);
                return;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                (Err("Decompiled source preparation stopped".into()), None)
            }
        };
        if preparing.generation == self.generation
            && preparing.epoch == self.worker_epoch
            && preparing.managed_revision
                == self.client.as_ref().map(|client| client.managed_revision)
            && self.baseline_current(&preparing.pending)
        {
            self.adopt_baseline(preparing.pending, result, charge, context);
        }
        if let Some(error) = preparing.failure {
            self.stop_worker();
            self.status = error;
        }
    }

    fn adopt_baseline(
        &mut self,
        pending: Pending,
        result: BaselineResult,
        charge: Option<TransientReservation>,
        context: &egui::Context,
    ) {
        let (prepared, code) = match result {
            Ok(ready) => ready,
            Err(error) => {
                self.stop_worker();
                self.clear_decompilation();
                self.status = format!("Invalid decompiler reply: {}", crop(&error, 512));
                return;
            }
        };
        let address = prepared.address;
        let signature_context = self.committed_signature_context();
        self.result_revision = self.result_revision.wrapping_add(1);
        // Display-only: a baseline never fills the reusable result slot.
        let code =
            self.results
                .admit_decompilation(None, code, ResultOrigin::Computed, Some(address));
        self.adopt_decompilation(Shared::clone(&code), ResultOrigin::Computed);
        let published = Instant::now();
        let hard = managed::hard_cap(pending.started, DEADLINE);
        let cutoff =
            prepared
                .offer
                .as_ref()
                .map_or(pending.started, |offer| match offer.executor {
                    crate::analysis::managed::Executor::ForkHere => {
                        managed::cutoff(pending.started, DEADLINE, offer, None)
                    }
                    // A sibling's phases are bounded separately within this cap.
                    crate::analysis::managed::Executor::Sibling => hard,
                });
        let renames = self.function_renames(address);
        let transaction = (pending.result.is_some() || cfg!(test) && self.client.is_none())
            .then(|| self.decision_book.begin(&prepared, renames, cutoff))
            .flatten()
            .map(Arc::new);
        if let Some(client) = self.client.as_mut() {
            client.managed_program = transaction
                .as_ref()
                .map(|tx| tx.job.binding.program.clone());
        }
        let staged = transaction.is_none().then_some(SettlementWork::Unverified);
        self.upgrade = Some(DisplayedUpgrade {
            prepared: Arc::new(prepared),
            transaction,
            cutoff,
            published,
            hard,
            optional: None,
            timing: None,
            slot_wait: None,
            generation: self.generation,
            epoch: self.worker_epoch,
            selection: self.selection_generation,
            revision: self.revision,
            result: pending.result,
            local: self.local_override_state(address),
            signature_context,
            debug: self.use_debug_info,
            code,
            status: self.status.clone(),
            pass: context.cumulative_pass_nr(),
            staged,
            finishing: None,
            _baseline_charge: charge,
        });
        context.request_repaint();
    }

    pub(super) fn managed_preempts_maintenance(&self) -> bool {
        self.preparing_baseline.is_some()
            || self.upgrade.as_ref().is_some_and(|upgrade| {
                matches!(upgrade.optional, Some(Optional::Fork { .. }))
                    || upgrade.optional.is_none()
                        && upgrade.staged.is_none()
                        && upgrade.finishing.is_none()
            })
    }

    fn start_optional(
        &mut self,
        upgrade: &mut DisplayedUpgrade,
        context: &egui::Context,
    ) -> Option<Optional> {
        let waiting = upgrade.slot_wait.take();
        if let Some(timing) = &waiting
            && settle_spent_setup(upgrade, timing)
        {
            return None;
        }
        if self.pending.is_some() || !self.queue.is_empty() {
            // A sibling already waiting keeps its running allowance.
            upgrade.slot_wait = waiting;
            return None;
        }
        let offer = upgrade.prepared.offer.as_ref()?;
        let mut job = upgrade.transaction.as_ref()?.job.clone();
        job.remaining_ms = managed::remaining_ms(upgrade.cutoff);
        job.check().ok()?;
        match offer.executor {
            crate::analysis::managed::Executor::ForkHere => {
                let id = self
                    .client
                    .as_mut()?
                    .send(managed::optional_request(job, offer.executor))
                    .ok()?;
                Some(Optional::Fork { id, direct: false })
            }
            crate::analysis::managed::Executor::Sibling => {
                let peer = self.peer_context()?;
                let slot = peer.launch.slot.clone();
                let _trace = crate::performance::context(job.ticket.logical_id);
                let retried = waiting.is_some();
                let timing = match waiting {
                    Some(timing) => timing,
                    None => {
                        let grace = managed::setup_grace(slot.setup_sample(), None);
                        let timing = Arc::new(managed::PeerTiming::new(
                            upgrade.published,
                            grace,
                            managed::render_allowance(offer.reference_us, None),
                            upgrade.hard,
                        ));
                        managed::trace_budget(
                            &timing,
                            upgrade.published,
                            upgrade.hard,
                            grace,
                            slot.setup_sample(),
                        );
                        timing
                    }
                };
                if settle_spent_setup(upgrade, &timing) {
                    return None;
                }
                // Never wait on the GUI thread: a retiring peer is retried
                // on the next poll within the same setup allowance.
                let Ok(reservation) = slot.try_reserve() else {
                    if !retried {
                        crate::performance::event("sibling_busy", 0);
                    }
                    upgrade.slot_wait = Some(timing);
                    return None;
                };
                let wake = context.clone();
                managed::start_peer(peer, job, reservation, timing, None, move || {
                    wake.request_repaint()
                })
                .ok()
                .map(Optional::Peer)
            }
        }
    }

    /// The exact local renames the engine receives for `function`.
    pub(super) fn function_renames(&self, function: u64) -> Vec<LocalRename> {
        self.session
            .as_ref()
            .map(|session| {
                session
                    .local_renames
                    .iter()
                    .filter(|r| r.identity.function == function)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The committed state a debug peer replays, shared between attempts
    /// until names or the inventory change.
    fn peer_context(&mut self) -> Option<Arc<managed::PeerContext>> {
        let client = self.client.as_ref()?;
        let info = self.info.as_ref()?;
        let key = (
            self.generation,
            self.revision,
            self.symbol_revision,
            info.functions.len(),
        );
        let functions = match &self.peer_functions {
            Some((cached, functions)) if *cached == key => Arc::clone(functions),
            _ => {
                let functions = Arc::new(info.functions.clone());
                self.peer_functions = Some((key, Arc::clone(&functions)));
                functions
            }
        };
        let image = BinaryInfo {
            path: info.path.clone(),
            architecture: info.architecture.clone(),
            format: info.format.clone(),
            entry: info.entry,
            file_len: info.file_len,
            sha256: info.sha256.clone(),
            source_identity: info.source_identity,
            sections: info.sections.clone(),
            functions: Vec::new(),
            functions_truncated: info.functions_truncated,
            warnings: Vec::new(),
        };
        Some(Arc::new(managed::PeerContext {
            launch: client.peer_launch(),
            enabled: self.use_debug_info,
            skip: self.debug_skip.clone(),
            info: Arc::new(image),
            debug_state: self.debug_state.clone(),
            functions,
            long_names: self
                .applied_names
                .iter()
                .filter(|(_, name)| name.len() > MAX_FUNCTION_NAME_BYTES)
                .map(|(&address, name)| FunctionInfo {
                    address,
                    name: name.clone(),
                })
                .collect(),
            signatures: Arc::new(
                self.session
                    .as_ref()
                    .map_or_else(Vec::new, |session| session.signatures.clone()),
            ),
            unapplied: self.signature_unapplied.clone(),
            signature_context: self.committed_signature_context(),
        }))
    }

    /// Takes a reply that belongs to optional work; returns any other reply.
    pub(super) fn take_optional_reply(&mut self, reply: WorkerResponse) -> Option<WorkerResponse> {
        if let Some(index) = self.abandoned_replies.iter().position(|&id| id == reply.id) {
            if !matches!(reply.response, Response::DebugStarted { .. }) {
                self.abandoned_replies.remove(index);
            }
            return None;
        }
        let Some(upgrade) = &mut self.upgrade else {
            return Some(reply);
        };
        let Some(Optional::Fork { id, direct }) = &mut upgrade.optional else {
            return Some(reply);
        };
        if *id != reply.id {
            return Some(reply);
        }
        if let Response::DebugStarted {
            direct: launched, ..
        } = reply.response
        {
            *direct = launched;
            return None;
        }
        let direct = *direct;
        upgrade.optional = None;
        upgrade.staged = Some(SettlementWork::Reply(Box::new(reply.response), direct));
        None
    }

    fn abandon_reply(&mut self, id: u64) {
        if self.abandoned_replies.len() == ABANDONED_REPLIES {
            self.abandoned_replies.pop_front();
        }
        self.abandoned_replies.push_back(id);
    }

    /// Drops the optional work of the displayed baseline. A fork exchange
    /// still answers (and is ignored); a sibling is stopped and reaped off
    /// the GUI thread. Independently settled decisions are kept.
    pub(super) fn cancel_upgrade(&mut self) {
        self.preparing_baseline = None;
        self.code_preparation.cancel();
        let Some(upgrade) = self.upgrade.take() else {
            return;
        };
        if let Some(transaction) = &upgrade.transaction {
            self.decision_book.cancel(transaction);
        }
        match upgrade.optional {
            Some(Optional::Fork { id, .. }) => self.abandon_reply(id),
            Some(Optional::Peer(run)) => run.cancel(),
            None => {}
        }
    }

    /// Polls one optional job and publishes its settlement after the baseline frame.
    pub(super) fn poll_upgrade(&mut self, context: &egui::Context) {
        let Some(mut upgrade) = self.upgrade.take() else {
            return;
        };
        if !self.upgrade_current(&upgrade) {
            self.upgrade = Some(upgrade);
            self.cancel_upgrade();
            return;
        }
        if context.cumulative_pass_nr() <= upgrade.pass {
            self.upgrade = Some(upgrade);
            context.request_repaint();
            return;
        }
        if upgrade.staged.is_none() && upgrade.optional.is_none() && upgrade.finishing.is_none() {
            match upgrade.transaction.as_ref().map(|tx| tx.has_work()) {
                Some(true) => upgrade.optional = self.start_optional(&mut upgrade, context),
                Some(false) => upgrade.staged = Some(SettlementWork::NoWork),
                None => {}
            }
            if upgrade.staged.is_none() && upgrade.optional.is_none() && upgrade.slot_wait.is_none()
            {
                upgrade.staged = Some(SettlementWork::Unverified);
            }
        }
        // A sibling is polled against its current phase deadline.
        if let Some(Optional::Peer(run)) = &upgrade.optional
            && let Some(end) = run.poll().or_else(|| {
                let now = Instant::now();
                (now >= run.deadline()).then(|| run.expire(now)).flatten()
            })
        {
            upgrade.timing = Some(Arc::clone(run.timing()));
            upgrade.optional = None;
            upgrade.staged = Some(SettlementWork::Peer(end));
        }
        if Instant::now() >= upgrade.cutoff
            && let Some(Optional::Fork { id, direct }) = upgrade.optional
        {
            self.abandon_reply(id);
            upgrade.optional = None;
            upgrade.staged = Some(SettlementWork::Fallback(direct));
        }
        if let Some(work) = upgrade.staged.take() {
            let Some(info) = self.info.as_ref() else {
                return;
            };
            let info = super::info_without_functions(info);
            let signature = upgrade.signature_context.clone();
            let baseline = Arc::clone(&upgrade.code);
            let prepared = Arc::clone(&upgrade.prepared);
            let transaction = upgrade.transaction.clone();
            let estimate = work.estimated_bytes(&prepared);
            let prepare = move || {
                work.finish(
                    &prepared,
                    transaction.as_deref(),
                    &info,
                    &signature,
                    &baseline,
                )
            };
            if cfg!(test) && self.client.is_none() {
                if let Some(ready) = prepare() {
                    self.apply_settlement(upgrade, ready);
                }
                context.request_repaint();
                return;
            }
            if let Some(charge) = self
                .results
                .reserve_transient(estimate, &[upgrade.prepared.address])
                && let Ok(receiver) = self
                    .code_preparation
                    .submit(context, move || (prepare(), charge))
            {
                upgrade.finishing = Some(receiver);
            } else {
                self.retain_baseline(upgrade);
                context.request_repaint();
                return;
            }
        }
        if let Some(finishing) = &upgrade.finishing {
            match finishing.try_recv() {
                Ok((Some(ready), charge)) => {
                    drop(charge);
                    self.apply_settlement(upgrade, ready);
                    context.request_repaint();
                    return;
                }
                Ok((None, _)) | Err(mpsc::TryRecvError::Disconnected) => {
                    self.retain_baseline(upgrade);
                    context.request_repaint();
                    return;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        self.upgrade = Some(upgrade);
        context.request_repaint_after(Duration::from_millis(50));
    }

    fn retain_baseline(&mut self, upgrade: DisplayedUpgrade) {
        if let Some(transaction) = &upgrade.transaction {
            self.decision_book.cancel(transaction);
        }
        if self.status == upgrade.status {
            self.status = crate::analysis::UNVERIFIED_WARNING.into();
        }
    }

    /// Whether `upgrade` still describes exactly what is displayed.
    fn upgrade_current(&self, upgrade: &DisplayedUpgrade) -> bool {
        let address = upgrade.prepared.address;
        upgrade.generation == self.generation
            && upgrade.epoch == self.worker_epoch
            && upgrade.selection == self.selection_generation
            && upgrade.revision == self.revision
            && upgrade.debug == self.use_debug_info
            && self.view().is_some_and(|view| view.address == address)
            && self
                .code
                .as_ref()
                .is_some_and(|code| Arc::ptr_eq(code, &upgrade.code))
            && (upgrade.result.is_none() || self.results.current(upgrade.result.as_ref()))
            && self.local_override_state(address) == upgrade.local
            && self.signature_editor.is_none()
            && self
                .browser_dialog
                .as_ref()
                .is_none_or(|dialog| !matches!(dialog.kind, BrowserDialogKind::RenameLocal { .. }))
            && self.signature_change.is_none()
            && self.signature_replay.is_none()
            && self.committed_signature_context() == upgrade.signature_context
            && upgrade.transaction.as_ref().is_none_or(|tx| {
                self.client.as_ref().is_none_or(|client| {
                    client.managed_program.as_deref() == Some(tx.job.binding.program.as_str())
                })
            })
    }

    /// Replaces the displayed baseline with its final render in one action.
    fn apply_settlement(&mut self, upgrade: DisplayedUpgrade, mut ready: PreparedSettlement) {
        if !self.upgrade_current(&upgrade) {
            return;
        }
        // A sibling's effects must be accepted before its active render
        // cutoff (retained after the attempt ended); a fork's before its
        // window.
        let acceptance = match (&upgrade.timing, &upgrade.transaction) {
            (Some(timing), _) => timing.acceptance(),
            (None, Some(transaction)) => transaction.cutoff(),
            (None, None) => upgrade.cutoff,
        };
        if let Some(transaction) = &upgrade.transaction
            && !self
                .decision_book
                .accept_until(transaction, &mut ready.staged, acceptance)
        {
            self.retain_baseline(upgrade);
            return;
        }
        let PreparedSettlement {
            code,
            same_text,
            same,
            ..
        } = ready;
        let address = upgrade.prepared.address;
        if !same {
            self.result_revision = self.result_revision.wrapping_add(1);
        }
        let code = self.results.admit_decompilation(
            upgrade.result.as_ref(),
            code,
            ResultOrigin::Computed,
            Some(address),
        );
        self.replace_decompilation(code, same_text, &upgrade.status);
    }

    /// The same function's final render, in place: the view, cursor, pan,
    /// zoom, history, focus and selected machine addresses stay. Semantic
    /// ranges are rebound only from exact engine addresses; token actions
    /// survive only an identical text and token set.
    fn replace_decompilation(
        &mut self,
        code: Shared<PreparedDecompilation>,
        same_text: bool,
        baseline_status: &str,
    ) {
        let _adoption = crate::performance::span("function_result_adopt_upgrade");
        let previous = self.code.take();
        let local = previous.as_ref().and_then(|previous| {
            relocate_local(self.selected_local?, previous.semantics(), code.semantics())
        });
        let call = previous.as_ref().and_then(|previous| {
            relocate_call(
                self.selected_call?,
                self.selected_call_byte?,
                self.view()?,
                previous.mappings(),
                &code,
            )
        });
        if !same_text {
            self.code_text_revision = self.code_text_revision.wrapping_add(1);
        }
        if !same_text
            || self.selected_local != local
            || self.selected_call.is_some() && call.is_none()
        {
            self.xref_choices = None;
        }
        self.selected_local = local;
        if local.is_none() {
            self.decompiler_rename_context = false;
        }
        self.selected_call_byte = call;
        if call.is_none() {
            self.selected_call = None;
        }
        let same_rows = same_text
            && previous
                .as_ref()
                .is_some_and(|previous| previous.mappings() == code.mappings());
        if !same_rows {
            self.comment_rows_key = None;
        }
        self.semantic.mappings = code.mappings().clone();
        self.semantic.rebind(self.selected);
        // A user-requested one-shot scroll follows its machine address.
        if self.pending_code_scroll.is_some() {
            self.pending_code_scroll = self
                .semantic
                .ranges
                .first()
                .map(|range| code.lines().partition_point(|(_, end)| *end <= range.start));
        }
        self.saved_analysis = false;
        if self.status == baseline_status {
            self.status = code
                .semantics()
                .warnings
                .first()
                .cloned()
                .unwrap_or_else(|| "Ready".into());
        }
        self.code = Some(code);
    }
}

/// Settles a sibling whose setup allowance is spent before any peer
/// started (host work or a busy slot since the baseline was published) as
/// its setup cutoff, through the ordinary off-thread settlement.
fn settle_spent_setup(upgrade: &mut DisplayedUpgrade, timing: &Arc<managed::PeerTiming>) -> bool {
    let Some(end) = timing.spent_setup(Instant::now()) else {
        return false;
    };
    crate::performance::event("sibling_no_budget", 0);
    upgrade.timing = Some(Arc::clone(timing));
    upgrade.staged = Some(SettlementWork::Peer(end));
    true
}

fn relocate_local(index: usize, old: &SemanticInfo, new: &SemanticInfo) -> Option<usize> {
    let identity = &old.locals.get(index)?.identity;
    let mut matches = new
        .locals
        .iter()
        .enumerate()
        .filter(|(_, local)| &local.identity == identity);
    let (replacement, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    new.tokens
        .iter()
        .any(|token| {
            matches!(token.kind, TokenKind::Local { local: Some(index) }
        if index == replacement)
        })
        .then_some(replacement)
}

fn relocate_call(
    target: u64,
    byte: usize,
    view: &FunctionView,
    previous: &[CodeMapping],
    code: &PreparedDecompilation,
) -> Option<usize> {
    let sites: BTreeSet<_> = view
        .calls
        .iter()
        .filter(|site| site.target == Some(target))
        .map(|site| site.address)
        .collect();
    let site_at = |mappings: &[CodeMapping], byte| {
        let index = mappings.partition_point(|mapping| mapping.end <= byte);
        let mapping = mappings
            .get(index)
            .filter(|mapping| mapping.start <= byte)?;
        let mut matches = mapping.addresses.iter().filter(|pc| sites.contains(pc));
        let address = *matches.next()?;
        matches.next().is_none().then_some(address)
    };
    let current = site_at(previous, byte)?;
    let mut tokens = code.semantics().tokens.iter().filter(|token| {
        matches!(token.kind, TokenKind::Call { target: address } if address == target)
            && site_at(code.mappings(), token.start) == Some(current)
    });
    let replacement = tokens.next()?.start;
    tokens.next().is_none().then_some(replacement)
}

impl SettlementWork {
    fn candidate(&self) -> Option<&crate::analysis::Published> {
        let outcome = match self {
            Self::Reply(response, _) => match response.as_ref() {
                Response::DebugFinished { outcome, .. } => &outcome.0,
                _ => return None,
            },
            Self::Peer(managed::PeerEnd::Finished(outcome)) => outcome,
            _ => return None,
        };
        match outcome {
            crate::analysis::DebugOutcome::Candidate { render, .. } => Some(render),
            _ => None,
        }
    }

    fn estimated_bytes(&self, baseline: &managed::Prepared) -> usize {
        let (text, mappings, semantics) = self.candidate().map_or(
            (
                &baseline.text,
                baseline.mappings.as_slice(),
                &baseline.semantics,
            ),
            |body| (&body.text, body.mappings.as_slice(), &body.semantics),
        );
        PreparedDecompilation::estimated_bytes(text, mappings, semantics).saturating_mul(2)
    }

    fn finish(
        self,
        prepared: &managed::Prepared,
        transaction: Option<&managed::Transaction>,
        info: &BinaryInfo,
        signature: &str,
        baseline: &PreparedDecompilation,
    ) -> Option<PreparedSettlement> {
        let mut staged = match (self, transaction) {
            (Self::Reply(reply, direct), Some(tx)) => {
                tx.stage_reply(prepared, *reply, direct, info, signature)
            }
            (Self::Peer(managed::PeerEnd::Finished(outcome)), Some(tx)) => {
                tx.stage_outcome(prepared, *outcome, info, signature)
            }
            // Only an acknowledged direct attempt defers the target.
            (Self::Peer(managed::PeerEnd::Expired) | Self::Fallback(true), Some(tx)) => {
                tx.stage_fallback(true, false)
            }
            (
                Self::Peer(managed::PeerEnd::NotLaunched(_) | managed::PeerEnd::RenderCutoff)
                | Self::Fallback(false),
                Some(tx),
            ) => tx.stage_fallback(false, false),
            (Self::Peer(managed::PeerEnd::SetupCutoff(_)), Some(tx)) => tx.stage_setup_cutoff(),
            (Self::NoWork, Some(tx)) => tx.stage_no_work(prepared),
            _ => managed::Staged::unverified(),
        };
        let (text, mappings, semantics) = staged.take_result().render(prepared);
        let same_text = text == baseline.text();
        let same = same_text
            && mappings.as_slice() == &**baseline.mappings()
            && &semantics == baseline.semantics();
        let code = if same_text {
            baseline.rebind(mappings, semantics, &info.sections)
        } else {
            PreparedDecompilation::validate(
                prepared.address,
                text,
                mappings,
                semantics,
                &info.sections,
            )
        }
        .ok()?;
        Some(PreparedSettlement {
            staged,
            code,
            same_text,
            same,
        })
    }
}

#[cfg(test)]
impl DesktopApp {
    /// Test hook: binds the displayed baseline to an optional exchange `id`.
    pub(super) fn test_upgrade_reply(&mut self, id: u64) {
        if let Some(upgrade) = &mut self.upgrade {
            upgrade.optional = Some(Optional::Fork { id, direct: false });
            upgrade.staged = None;
        }
    }
    pub(super) fn test_upgrade_nonce(&self) -> Option<u64> {
        self.upgrade
            .as_ref()
            .and_then(|upgrade| upgrade.prepared.offer.as_ref().map(|offer| offer.nonce))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{rendered_text, semantic_app};
    use super::*;
    use crate::analysis::managed::{Binding, DebugOffer, Executor, PeerOutcome, Ticket};

    const BASELINE: &str = "int entry(int param_1) { return café + 1; }";
    /// More than the largest setup allowance.
    #[cfg(target_os = "linux")]
    const SETUP_SPENT: Duration = Duration::from_secs(6);
    const UPGRADED: &str = "int entry(char *output) { return café + 1; }";

    fn prototype(name: &str) -> SemanticInfo {
        SemanticInfo {
            prototype: Some(signatures::InferredSignature {
                return_type: None,
                abi: "x86:LE:64:default:gcc".into(),
                parameters: vec![signatures::InferredParameter {
                    name: name.into(),
                    ty: None,
                }],
                unsupported: Vec::new(),
            }),
            ..SemanticInfo::default()
        }
    }

    fn mapping(text: &str, addresses: Vec<u64>) -> Vec<CodeMapping> {
        vec![CodeMapping {
            start: text.find("return").unwrap(),
            end: text.find(';').unwrap() + 1,
            addresses,
        }]
    }

    /// A baseline reply for the displayed function with a fork offer.
    fn prepared(nonce: u64) -> Response {
        let semantics = prototype("param_1");
        let mappings = mapping(BASELINE, vec![0x1004, 0x1008]);
        let calls = vec![0x1004];
        let baseline = crate::analysis::managed::baseline_digest(
            0x1000, BASELINE, &mappings, &semantics, &calls,
        );
        let program = "0".repeat(64);
        Response::PreparedDecompile {
            address: 0x1000,
            text: BASELINE.into(),
            mappings,
            semantics,
            offer: DebugOffer {
                logical_id: nonce,
                nonce,
                executor: Executor::ForkHere,
                reference_us: 1_000,
                elapsed_us: 2_000,
                binding: Binding {
                    context: crate::analysis::managed::context_digest(&program, 0x1000, &[]),
                    program,
                    baseline,
                    facts: "0".repeat(64),
                },
                calls,
                target_work: true,
                graph_prepared: false,
                callees: vec![0x1004],
                cacheable: true,
            },
        }
    }

    fn pending(app: &DesktopApp) -> Pending {
        Pending {
            id: 1,
            request: Request::Decompile { address: 0x1000 },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: None,
        }
    }

    fn settled(nonce: u64, text: Option<&str>) -> WorkerResponse {
        use crate::analysis::{DebugOutcome, Published, Unchanged};
        use crate::debug_info::{Change, EntryState, Status};
        let Response::PreparedDecompile { offer, .. } = prepared(nonce) else {
            unreachable!()
        };
        WorkerResponse {
            id: 7,
            response: Response::DebugFinished {
                ticket: Ticket {
                    logical_id: nonce,
                    nonce,
                    book_version: 1,
                },
                measured: offer.binding,
                outcome: PeerOutcome(match text {
                    Some(text) => DebugOutcome::Candidate {
                        render: Box::new(Published {
                            text: text.into(),
                            mappings: mapping(text, vec![0x1008]),
                            semantics: prototype("output"),
                            calls: Vec::new(),
                            calls_complete: true,
                        }),
                        target_owns: true,
                        installed_callees: Vec::new(),
                        compared: true,
                        vetoed: false,
                        changes: vec![Change {
                            entry: 0x1000,
                            old: EntryState::default(),
                            new: EntryState {
                                status: Status::Verified,
                                ..EntryState::default()
                            },
                        }],
                        large: Vec::new(),
                    },
                    None => DebugOutcome::UseReference {
                        reason: Unchanged::EvidenceLost,
                        changes: vec![Change {
                            entry: 0x1000,
                            old: EntryState::default(),
                            new: EntryState {
                                status: Status::Rejected,
                                ..EntryState::default()
                            },
                        }],
                        large: Vec::new(),
                    },
                }),
            },
        }
    }

    fn frame(context: &egui::Context, app: &mut DesktopApp) -> Vec<String> {
        let mut output = context.run_ui(egui::RawInput::default(), |ui| app.side_panel(ui));
        output.textures_delta.clear();
        rendered_text(&output)
    }

    /// The first paint shows the inferred baseline even when its settlement
    /// arrived in the same event drain; the next pass replaces it in place.
    #[test]
    fn baseline_paints_first_then_upgrades_in_place() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = semantic_app();
        app.select_instruction(0x1008);
        let view = app.view().unwrap().address;
        let history = app.history.clone();
        app.receive(pending(&app), prepared(3), &context);
        assert_eq!(app.decompiled(), BASELINE);
        assert_eq!(app.test_upgrade_nonce(), Some(3));
        app.test_upgrade_reply(7);
        let revision = app.result_revision;
        app.receive_worker_reply(settled(3, Some(UPGRADED)), &context);
        app.poll_upgrade(&context);
        let first = frame(&context, &mut app);
        assert!(first.iter().any(|row| row.contains("param_1")), "{first:?}");
        assert!(
            first.iter().any(|row| row == "Inferred signature"),
            "{first:?}"
        );
        assert_eq!(app.decompiled(), BASELINE, "the baseline is painted first");
        app.pending_code_scroll = None;
        app.poll_upgrade(&context);
        assert_eq!(app.decompiled(), UPGRADED);
        let second = frame(&context, &mut app);
        assert!(
            second.iter().any(|row| row.contains("char *output")),
            "{second:?}"
        );
        assert!(
            second.iter().any(|row| row == "Debug info signature"),
            "{second:?}"
        );
        assert_eq!(
            app.semantics().prototype_source,
            crate::semantic::PrototypeSource::DebugInfo
        );
        // Nothing moved: the function, the selected machine address (now
        // highlighted only through the new exact mapping), history, and no
        // forced scroll.
        assert_eq!(app.view().unwrap().address, view);
        assert_eq!(app.selected, Some(0x1008));
        assert_eq!(app.history, history);
        assert_eq!(app.semantic.ranges.len(), 1);
        assert_eq!(app.pending_code_scroll, None);
        assert_eq!(app.result_revision, revision.wrapping_add(1));
        assert!(app.upgrade.is_none());
    }

    /// A warning-only settlement keeps the text, line ranges and syntax
    /// highlighting, and only adds the warning.
    #[test]
    fn warning_only_settlement_reuses_the_prepared_text() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        app.receive(pending(&app), prepared(4), &context);
        let baseline = Arc::clone(app.code.as_ref().unwrap());
        app.test_upgrade_reply(7);
        let prepares = crate::function_presentation::prepared_count();
        app.receive_worker_reply(settled(4, None), &context);
        frame(&context, &mut app);
        app.poll_upgrade(&context);
        assert_eq!(crate::function_presentation::prepared_count(), prepares);
        let code = app.code.as_ref().unwrap();
        assert!(!Arc::ptr_eq(code, &baseline));
        assert_eq!(code.text(), BASELINE);
        assert!(std::ptr::eq(code.lines(), baseline.lines()));
        assert!(std::ptr::eq(code.highlighted(), baseline.highlighted()));
        assert_eq!(
            code.semantics().warnings,
            [crate::analysis::CALLER_EVIDENCE_WARNING]
        );
        assert_eq!(
            code.semantics().prototype_source,
            crate::semantic::PrototypeSource::Inferred
        );
    }

    /// Any change of what the baseline was bound to discards its
    /// settlement: navigation, an annotation revision, a toggle, or a newer
    /// baseline (A→B→A ends with the newest request's own settlement).
    #[test]
    fn stale_settlements_change_nothing() {
        let context = egui::Context::default();
        for case in 0..4 {
            let mut app = semantic_app();
            app.receive(pending(&app), prepared(5), &context);
            app.test_upgrade_reply(7);
            let revision = app.result_revision;
            match case {
                0 => app.selection_generation = app.selection_generation.wrapping_add(1),
                1 => app.revision = app.revision.wrapping_add(1),
                2 => app.use_debug_info = !app.use_debug_info,
                _ => {
                    // A newer baseline for the same function replaces the
                    // old optional exchange; the old reply is ignored.
                    app.receive(pending(&app), prepared(6), &context);
                    assert_eq!(app.test_upgrade_nonce(), Some(6));
                }
            }
            let shown = Arc::clone(app.code.as_ref().unwrap());
            app.receive_worker_reply(settled(5, Some(UPGRADED)), &context);
            frame(&context, &mut app);
            app.poll_upgrade(&context);
            frame(&context, &mut app);
            app.poll_upgrade(&context);
            assert_eq!(app.decompiled(), BASELINE, "case {case}");
            if case < 3 {
                assert!(
                    Arc::ptr_eq(app.code.as_ref().unwrap(), &shown),
                    "case {case}"
                );
                assert_eq!(app.result_revision, revision, "case {case}");
            } else {
                // Only the newest request settles: without a worker it
                // keeps its baseline with the unsettled warning.
                assert_eq!(
                    app.semantics().warnings,
                    [crate::analysis::UNVERIFIED_WARNING],
                    "case {case}"
                );
                assert_eq!(
                    app.semantics().prototype_source,
                    crate::semantic::PrototypeSource::Inferred
                );
            }
            assert!(app.debug_skip.is_empty(), "case {case}");
        }
    }

    /// Navigation clears the displayed code and with it the optional work;
    /// a late reply to the abandoned exchange is dropped, not treated as an
    /// unexpected reply.
    #[test]
    fn cancelled_upgrades_drop_their_late_reply() {
        let context = egui::Context::default();
        let mut app = semantic_app();
        app.receive(pending(&app), prepared(8), &context);
        app.test_upgrade_reply(7);
        app.clear_decompilation();
        assert!(app.upgrade.is_none());
        let status = app.status.clone();
        app.receive_worker_reply(settled(8, Some(UPGRADED)), &context);
        assert_eq!(app.status, status);
        assert!(app.abandoned_replies.is_empty());
        assert!(app.code.is_none());
    }

    #[test]
    fn managed_debug_relocates_actions_only_by_exact_identity() {
        use crate::semantic::{LocalStorage, LocalVariable, SemanticToken};
        let local = |offset| LocalVariable {
            identity: LocalIdentity {
                function: 0x1000,
                engine: crate::semantic::LOCAL_FINGERPRINT.into(),
                storage: LocalStorage::Stack,
                offset,
                size: 4,
                verification: "a".repeat(64),
            },
            name: "variable".into(),
            signature_parameter: None,
        };
        let old = SemanticInfo {
            locals: vec![local(16)],
            ..Default::default()
        };
        let mut new = SemanticInfo {
            locals: vec![local(24), local(16)],
            tokens: vec![SemanticToken {
                start: 1,
                end: 2,
                kind: TokenKind::Local { local: Some(1) },
            }],
            ..Default::default()
        };
        assert_eq!(relocate_local(0, &old, &new), Some(1));
        new.locals[1].identity.verification = "b".repeat(64);
        assert_eq!(relocate_local(0, &old, &new), None);

        let app = semantic_app();
        let mut view = app.view().unwrap().clone();
        let target = 0x1040;
        view.calls = [0x1004, 0x1008]
            .into_iter()
            .map(|address| CallSite {
                address,
                target: Some(target),
                no_return: None,
            })
            .collect();
        let old = vec![CodeMapping {
            start: 2,
            end: 6,
            addresses: vec![0x1004],
        }];
        let tokens = [8, 16]
            .into_iter()
            .map(|start| SemanticToken {
                start,
                end: start + 4,
                kind: TokenKind::Call { target },
            })
            .collect();
        let make = |second| {
            PreparedDecompilation::prepare(
                0x1000,
                "        call    call".into(),
                vec![
                    CodeMapping {
                        start: 8,
                        end: 12,
                        addresses: vec![0x1004],
                    },
                    CodeMapping {
                        start: 16,
                        end: 20,
                        addresses: vec![second],
                    },
                ],
                SemanticInfo {
                    tokens: Vec::clone(&tokens),
                    ..Default::default()
                },
            )
        };
        assert_eq!(
            relocate_call(target, 2, &view, &old, &make(0x1008)),
            Some(8)
        );
        assert_eq!(relocate_call(target, 2, &view, &old, &make(0x1004)), None);
        assert_eq!(relocate_call(target, 6, &view, &old, &make(0x1008)), None);
    }

    #[test]
    fn managed_debug_offer_changes_cannot_authorize_optional_work() {
        let app = semantic_app();
        let info = app.info.as_ref().unwrap();
        for field in ["text", "mapping", "semantics", "calls"] {
            let mut reply = prepared(11);
            let Response::PreparedDecompile {
                text,
                mappings,
                semantics,
                offer,
                ..
            } = &mut reply
            else {
                unreachable!()
            };
            match field {
                "text" => text.replace_range(0..1, "u"),
                "mapping" => mappings[0].addresses.pop().map(drop).unwrap(),
                "semantics" => semantics.warnings.push("changed".into()),
                _ => offer.calls.push(0x1008),
            }
            let checked = managed::admit_prepared(0x1000, reply, info, "").unwrap();
            assert!(
                checked.offer.is_none(),
                "altered {field} must settle the baseline"
            );
        }
    }

    #[test]
    fn managed_debug_project_snapshots_pin_the_displayed_version() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("fixture.bin");
        std::fs::write(&binary, [0; 256]).unwrap();
        let project = directory.path().join("managed.grproj");
        let context = egui::Context::default();
        let mut app = semantic_app();
        let info = app.info.as_mut().unwrap();
        info.path = binary.to_string_lossy().into_owned();
        info.sha256 = crate::session::fingerprint(&binary).unwrap();
        info.source_identity = FileIdentity::from_file(&std::fs::File::open(&binary).unwrap());
        app.binary_protection = Some(
            BinaryProtection::open(&binary)
                .unwrap()
                .bind_snapshot(info)
                .unwrap(),
        );
        app.session = Some(Session::new(info.sha256.clone()));
        app.use_debug_info = true;
        app.debug_skip.clear();
        app.project_path = Some(project.clone());

        app.receive(pending(&app), prepared(12), &context);
        let baseline = Arc::clone(app.code.as_ref().unwrap());
        app.test_upgrade_reply(7);
        app.save_project(false, &context);
        app.receive_worker_reply(settled(12, Some(UPGRADED)), &context);
        frame(&context, &mut app);
        app.poll_upgrade(&context);
        assert_eq!(app.decompiled(), UPGRADED);

        let wait_save = |app: &mut DesktopApp| {
            let start = Instant::now();
            while app.file_job.is_some() {
                app.poll_files(&context);
                assert!(start.elapsed() < Duration::from_secs(10), "{}", app.status);
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        wait_save(&mut app);
        let data = ProjectData::load(&project).unwrap().data;
        assert_eq!(data.decompiled.as_deref(), Some(baseline.text()));
        assert_eq!(data.mappings, baseline.mappings().as_ref());
        assert_eq!(&data.semantics, baseline.semantics());
        assert!(data.use_debug_info && data.debug_skip.is_empty());
        assert!(
            app.dirty(),
            "The upgrade changed the live result during the save"
        );

        app.save_project(false, &context);
        wait_save(&mut app);
        let saved = ProjectData::load(&project).unwrap().data;
        assert_eq!(saved.decompiled.as_deref(), Some(UPGRADED));
        assert_eq!(
            saved.semantics.prototype_source,
            crate::semantic::PrototypeSource::DebugInfo
        );
        assert_eq!(saved.mappings, app.semantic.mappings.as_ref());
        assert!(saved.debug_skip.is_empty());
        assert!(!app.dirty());
    }

    /// A forced sibling (`--no-fork`) on a real worker: a setup allowance
    /// already spent by host work at the first poll, and a slot held by a
    /// retiring peer until the allowance runs out, both settle as the setup
    /// cutoff; a slot freed in time is retried without blocking and starts
    /// the peer. No setup cutoff records a decision, cache entry or skip,
    /// or keeps the slot.
    #[cfg(target_os = "linux")]
    #[test]
    fn managed_scheduler_desktop_sibling_setup_cutoff_and_busy_slot() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("sample");
        assert!(
            std::process::Command::new("gcc")
                .args(["-O0", "-g", "tests/fixtures/sample.c", "-o"])
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
        let worker = test_worker().unwrap_or_else(|error| panic!("{error}"));
        let context = egui::Context::default();
        let mut app = DesktopApp::empty(None);
        app.client = Some(
            WorkerClient::start_with_worker_arguments(
                context.clone(),
                &binary,
                &worker,
                None,
                true,
                vec![crate::worker::NO_FORK_ARGUMENT.into()],
            )
            .unwrap(),
        );
        app.opening = Some(Opening {
            path: binary.clone(),
            preserve: false,
            follow: Some(Queued::from(Request::Bytes {
                address: 0,
                length: 1,
            })),
            revision: app.revision,
            follow_origin: app.request_origin(),
        });
        app.send_direct(Request::Open {
            path: binary.to_str().unwrap().into(),
            debug: crate::debug_info::DebugOptions {
                enabled: true,
                ..Default::default()
            },
        });
        let deadline = Instant::now() + DEADLINE;
        while app.opening.is_some() || app.pending.is_some() || app.results.preparing() {
            app.poll_worker(&context);
            assert!(Instant::now() < deadline, "Open: {}", app.status);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!app.debug_state.is_empty(), "{}", app.status);
        let address = |app: &DesktopApp, name: &str| {
            let info = app.info.as_ref().unwrap();
            info.functions
                .iter()
                .find(|function| function.name == name)
                .unwrap()
                .address
        };
        // Navigates and adopts the sibling baseline without an egui pass,
        // so its optional work has not started.
        let baseline = |app: &mut DesktopApp, address: u64| {
            app.navigate(address, false, &context);
            let deadline = Instant::now() + DEADLINE;
            while !app
                .upgrade
                .as_ref()
                .is_some_and(|upgrade| upgrade.prepared.address == address)
            {
                app.poll_worker(&context);
                app.poll_graph_preparation(&context);
                assert!(app.client.is_some(), "{}", app.status);
                assert!(Instant::now() < deadline, "baseline: {}", app.status);
                std::thread::sleep(Duration::from_millis(1));
            }
            let upgrade = app.upgrade.as_ref().unwrap();
            assert!(upgrade.transaction.as_ref().unwrap().has_work());
            assert!(matches!(
                upgrade.prepared.offer.as_ref().unwrap().executor,
                crate::analysis::managed::Executor::Sibling
            ));
        };
        let step = |app: &mut DesktopApp| {
            context
                .run_ui(egui::RawInput::default(), |_| {})
                .textures_delta
                .clear();
            app.poll_worker(&context);
            app.poll_graph_preparation(&context);
        };
        let settle = |app: &mut DesktopApp| {
            let deadline = Instant::now() + DEADLINE;
            while app.upgrade.is_some() {
                step(app);
                assert!(Instant::now() < deadline, "settle: {}", app.status);
                std::thread::sleep(Duration::from_millis(2));
            }
        };
        let slot = app.client.as_ref().unwrap().peer_launch().slot;
        let cut_off = |app: &DesktopApp| {
            let warnings = &app.semantics().warnings;
            assert_eq!(
                warnings
                    .iter()
                    .filter(|w| *w == crate::analysis::SETUP_CUTOFF_WARNING)
                    .count(),
                1,
                "{warnings:?}"
            );
            assert!(
                !warnings
                    .iter()
                    .any(|w| w == crate::analysis::UNVERIFIED_WARNING)
            );
            assert_eq!(
                app.semantics().prototype_source,
                crate::semantic::PrototypeSource::Inferred
            );
            assert_eq!(app.status, crate::analysis::SETUP_CUTOFF_WARNING);
        };

        // Host work after adoption spent the whole allowance.
        let function = address(&app, "decode_xor");
        baseline(&mut app, function);
        let book = app.decision_book.test_summary();
        let upgrade = app.upgrade.as_mut().unwrap();
        upgrade.published -= SETUP_SPENT;
        settle(&mut app);
        cut_off(&app);
        assert_eq!(app.decision_book.test_summary(), book);
        assert!(app.debug_skip.is_empty());
        drop(slot.try_reserve().expect("no peer reservation was taken"));

        // A retiring peer holds the slot: the desktop keeps polling within
        // the cold two-second allowance, then settles the setup cutoff.
        let function = address(&app, "main");
        baseline(&mut app, function);
        let book = app.decision_book.test_summary();
        let held = slot.try_reserve().unwrap();
        let waiting = Instant::now();
        while waiting.elapsed() < Duration::from_millis(200) {
            step(&mut app);
            let upgrade = app.upgrade.as_ref().expect("waits for the slot");
            assert!(upgrade.slot_wait.is_some() && upgrade.optional.is_none());
            assert!(upgrade.staged.is_none() && upgrade.finishing.is_none());
            std::thread::sleep(Duration::from_millis(5));
        }
        settle(&mut app);
        drop(held);
        cut_off(&app);
        assert_eq!(app.decision_book.test_summary(), book);
        assert!(app.debug_skip.is_empty());
        drop(slot.try_reserve().expect("the cutoff keeps no reservation"));

        // A slot freed within the allowance is retried and starts the peer.
        let function = address(&app, "branch_loop");
        baseline(&mut app, function);
        let held = slot.try_reserve().unwrap();
        for _ in 0..3 {
            step(&mut app);
            assert!(app.upgrade.as_ref().unwrap().slot_wait.is_some());
        }
        drop(held);
        let deadline = Instant::now() + DEADLINE;
        while !app
            .upgrade
            .as_ref()
            .is_some_and(|upgrade| matches!(upgrade.optional, Some(Optional::Peer(_))))
        {
            step(&mut app);
            assert!(
                app.upgrade.is_some(),
                "settled without a peer: {}",
                app.status
            );
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        settle(&mut app);
        assert!(
            !app.semantics()
                .warnings
                .iter()
                .any(|w| w == crate::analysis::UNVERIFIED_WARNING),
            "{:?}",
            app.semantics().warnings
        );
        app.client.take().unwrap().stop_and_wait().unwrap();
    }

    /// Headless egui measurement of the real desktop navigation, worker
    /// polling, and Decompiler dock. All analysis subprocesses use the
    /// Cargo/explicit test worker in worker mode.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "opt-in managed desktop sweep, requires B3_IMAGE, B3_MODE and B3_OUTPUT"]
    fn managed_debug_sweep() {
        use std::io::Write;
        let image = PathBuf::from(std::env::var_os("B3_IMAGE").expect("B3_IMAGE"));
        let mode = std::env::var("B3_MODE").expect("B3_MODE");
        assert!(matches!(mode.as_str(), "off" | "fork" | "sibling"));
        let enabled = mode != "off";
        let order = std::env::var("B3_ORDER").unwrap_or_else(|_| "asc".into());
        assert!(matches!(order.as_str(), "asc" | "desc"));
        let prefix = std::env::var("B3_OUTPUT").expect("B3_OUTPUT");
        let mut output =
            std::io::BufWriter::new(std::fs::File::create(format!("{prefix}.jsonl")).unwrap());
        let worker = test_worker().expect("built release headless worker");
        let context = egui::Context::default();
        theme::install(&context);
        let mut app = DesktopApp::empty(None);
        app.client = Some(
            WorkerClient::start_with_worker_arguments(
                context.clone(),
                &image,
                &worker,
                None,
                enabled,
                (mode == "sibling")
                    .then(|| crate::worker::NO_FORK_ARGUMENT.into())
                    .into_iter()
                    .collect(),
            )
            .unwrap(),
        );
        app.opening = Some(Opening {
            path: image.clone(),
            preserve: false,
            // Initialize the real desktop via Opened without automatically
            // decompiling one inventory entry before its measured visit.
            follow: Some(Queued::from(Request::Bytes {
                address: 0,
                length: 1,
            })),
            revision: app.revision,
            follow_origin: app.request_origin(),
        });
        app.send_direct(Request::Open {
            path: image.to_str().unwrap().into(),
            debug: crate::debug_info::DebugOptions {
                enabled,
                ..Default::default()
            },
        });
        let start = Instant::now();
        while app.opening.is_some() || app.pending.is_some() || app.results.preparing() {
            app.poll_worker(&context);
            assert!(start.elapsed() < DEADLINE, "Open: {}", app.status);
            std::thread::sleep(Duration::from_millis(1));
        }
        let info = app.info.as_ref().expect("verified Open");
        assert!(app.client.is_some(), "{}", app.status);
        assert!(
            !enabled || !app.debug_state.is_empty(),
            "image has no debug information"
        );
        let mut functions = info.functions.clone();
        assert!(
            functions
                .windows(2)
                .all(|pair| pair[0].address < pair[1].address)
        );
        if order == "desc" {
            functions.reverse();
        }
        if let Ok(repeat) = std::env::var("B3_REPEAT") {
            let (address, count) = repeat.split_once(',').expect("address,count");
            let address = address.trim_start_matches("0x");
            let address = u64::from_str_radix(address, 16).unwrap();
            functions = vec![
                functions
                    .into_iter()
                    .find(|function| function.address == address)
                    .unwrap();
                count.parse().unwrap()
            ];
        }
        for FunctionInfo { address, name } in functions {
            let navigation = Instant::now();
            app.navigate(address, false, &context);
            let mut graph_dispatch = None;
            let mut graph_ready = None;
            let mut decompile_dispatch = None;
            let mut optional_dispatch = None;
            let mut first_paint = None;
            let mut first = None;
            let mut saw_offer = false;
            loop {
                if let Some(pending) = &app.pending {
                    match pending.request {
                        Request::Graph { address: entry } if address == entry => {
                            graph_dispatch.get_or_insert(pending.started);
                        }
                        Request::Decompile { address: entry } if address == entry => {
                            decompile_dispatch.get_or_insert(pending.started);
                        }
                        _ => {}
                    }
                }
                app.poll_worker(&context);
                app.poll_graph_preparation(&context);
                let now = Instant::now();
                if app.view().is_some_and(|view| view.address == address) {
                    graph_ready.get_or_insert(now);
                }
                if let Some(upgrade) = &app.upgrade {
                    saw_offer = true;
                    if upgrade.optional.is_some() {
                        optional_dispatch.get_or_insert(now);
                    }
                }
                if let Some(code) = app.code.as_ref().filter(|code| code.address() == address) {
                    if first_paint.is_none() {
                        first = Some(Arc::clone(code));
                        let _paint = frame(&context, &mut app);
                        first_paint = Some(Instant::now());
                    }
                    if app.upgrade.is_none() {
                        break;
                    }
                }
                if app.client.is_none() || navigation.elapsed() > 2 * DEADLINE {
                    output.flush().unwrap();
                    panic!("Incomplete {mode} {address:#x} {name}: {}", app.status);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let ready = Instant::now();
            let _paint = frame(&context, &mut app);
            let final_paint = Instant::now();
            let code = app.code.as_ref().unwrap();
            let first = first.unwrap();
            let first_paint = first_paint.unwrap();
            let changed = first.text() != code.text()
                || first.mappings() != code.mappings()
                || first.semantics().prototype_source != code.semantics().prototype_source;
            let relative = |time: Option<Instant>| {
                time.map(|time| time.saturating_duration_since(navigation).as_secs_f64())
            };
            let dispatch = decompile_dispatch.unwrap_or(navigation);
            let row = serde_json::json!({
                "address": address,
                "name": name,
                "source": code.semantics().prototype_source,
                "text": code.text(),
                "header": code.text().split('{').next().unwrap_or_default().trim(),
                "warnings": code.semantics().warnings,
                "mappings": code.mappings().as_ref(),
                "prototype": code.semantics().prototype,
                "semantics": code.semantics(),
                "baseline_text": first.text(),
                "baseline_mappings": first.mappings().as_ref(),
                "baseline_semantics": first.semantics(),
                "graph_dispatch": relative(graph_dispatch),
                "graph_ready": relative(graph_ready),
                "decompile_dispatch": relative(decompile_dispatch),
                "optional_dispatch": relative(optional_dispatch),
                "final_ready": relative(Some(ready)),
                "first_paint": relative(Some(first_paint)),
                "final_paint": relative(Some(final_paint)),
                "first_latency": first_paint.saturating_duration_since(dispatch).as_secs_f64(),
                "time": final_paint.saturating_duration_since(dispatch).as_secs_f64(),
                "upgrade_latency": changed.then(|| final_paint.duration_since(first_paint).as_secs_f64()),
                "offer": saw_offer,
                "cache_hit": decompile_dispatch.is_none(),
            });
            serde_json::to_writer(&mut output, &row).unwrap();
            writeln!(output).unwrap();
        }
        output.flush().unwrap();
        let elapsed = start.elapsed();
        if let Some(worker) = app.client.take() {
            worker.stop_and_wait().unwrap();
        }
        eprintln!(
            "managed {mode}/{order}: {elapsed:?}; {:?}",
            crate::client::managed_stats()
        );
    }
}
