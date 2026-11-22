//! Host coordination of managed two-phase decompiles, shared by the desktop
//! and the Analyzer.
//!
//! A managed request (`PrepareDecompile`) returns either a final render or a
//! *baseline* — exactly the render without debug information — with an
//! offer for one optional debug render. The host publishes the baseline at
//! once, then settles it at most once: through the primary's own disposable
//! fork (`TryPreparedDebug`), or through a fresh single-use sibling worker
//! that this module starts, replays and validates off the GUI thread. The
//! shared client decision book applies checked journals only at acceptance. Optional failures never become ordinary failures: the
//! baseline stays usable and no per-function skip is recorded.
use super::{WorkerClient, WorkerEvent};
use crate::analysis::managed::{DebugOffer, PeerJob};
mod decision_book;
use crate::analysis::{DebugOutcome, Published};
use crate::model::{
    BinaryInfo, CodeMapping, FunctionInfo, Request, Response, SectionInfo, SignatureStatus,
};
use crate::semantic::SemanticInfo;
use crate::session::BinaryProtection;
pub(crate) use decision_book::{DecisionBook, Staged, Transaction};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

/// Kept below the host's request deadline for publishing a settlement.
pub(crate) const SETTLEMENT_RESERVE: Duration = Duration::from_secs(3);
const OPTIONAL_FLOOR: Duration = Duration::from_secs(3);
const OPTIONAL_RATIO: u32 = 3;
/// A sibling's setup allowance (startup, Open and replay) before its image
/// has a setup sample, and the bounds of the adaptive allowance after one.
const SETUP_COLD: Duration = Duration::from_secs(2);
const SETUP_MIN: Duration = Duration::from_secs(1);
const SETUP_MAX: Duration = Duration::from_secs(5);
const SETUP_RATIO: u32 = 2;
/// A phase with less than one whole wire millisecond left sends nothing.
const MIN_PHASE: Duration = Duration::from_millis(1);
/// Process-wide counters of managed requests, for measurement harnesses.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManagedStats {
    /// Baselines with a valid offer.
    pub prepared: u64,
    /// Sibling attempts started.
    pub peers: u64,
    /// Sibling attempts that never launched direct work (start, Open,
    /// replay or eligibility), excluding digest mismatches.
    pub peer_not_launched: u64,
    /// Sibling recaptures whose digests differed from the primary's.
    pub peer_mismatch: u64,
    pub peer_context_mismatch: u64,
    pub peer_baseline_mismatch: u64,
    pub peer_facts_mismatch: u64,
    /// Launched sibling attempts without a result by the cutoff.
    pub peer_expired: u64,
    /// Sibling attempts whose setup (retirement wait, startup, Open or
    /// replay) used up its allowance before any render was sent.
    pub peer_setup_cutoff: u64,
    /// Sibling attempts with a validated result.
    pub peer_finished: u64,
    /// Settlements that replaced the baseline with a candidate.
    pub replaced: u64,
    /// Settlements that kept the baseline (with or without warnings).
    pub kept: u64,
    /// Direct verified managed-cache hits.
    pub cache_hits: u64,
}

static STATS: std::sync::Mutex<ManagedStats> = std::sync::Mutex::new(ManagedStats {
    prepared: 0,
    peers: 0,
    peer_not_launched: 0,
    peer_mismatch: 0,
    peer_context_mismatch: 0,
    peer_baseline_mismatch: 0,
    peer_facts_mismatch: 0,
    peer_expired: 0,
    peer_setup_cutoff: 0,
    peer_finished: 0,
    replaced: 0,
    kept: 0,
    cache_hits: 0,
});

fn count(update: impl FnOnce(&mut ManagedStats)) {
    update(&mut STATS.lock().unwrap_or_else(|error| error.into_inner()));
}

/// The counters so far.
#[doc(hidden)]
pub fn stats() -> ManagedStats {
    *STATS.lock().unwrap_or_else(|error| error.into_inner())
}

/// Checks a decompiler payload against the opened image and the committed
/// signature context, as for every ordinary `Decompiled` reply.
pub(crate) fn check_code(
    address: u64,
    text: &str,
    mappings: &[CodeMapping],
    semantics: &SemanticInfo,
    sections: &[SectionInfo],
    signature_context: &str,
) -> Result<(), String> {
    if text.len() > crate::model::MAX_DECOMPILED_BYTES {
        return Err("Decompiler text exceeds limit".into());
    }
    crate::selection::validate_mappings(text, mappings, sections)?;
    semantics.validate(text, address, sections)?;
    let expected = crate::semantic::local_fingerprint(signature_context);
    if semantics
        .locals
        .iter()
        .any(|local| local.identity.engine != expected)
    {
        return Err("Incompatible semantic local identity".into());
    }
    Ok(())
}

/// The latest instant optional work of a request dispatched at `dispatched`
/// under a host deadline `timeout` may use: the deadline less
/// [`SETTLEMENT_RESERVE`].
pub(crate) fn hard_cap(dispatched: Instant, timeout: Duration) -> Instant {
    dispatched
        .checked_add(timeout.saturating_sub(SETTLEMENT_RESERVE))
        .unwrap_or(dispatched)
}

/// `start + allowance`, never past `hard`.
fn capped(start: Instant, allowance: Duration, hard: Instant) -> Instant {
    start
        .checked_add(allowance)
        .map_or(hard, |end| end.min(hard))
}

/// The optional-acceptance cutoff of a fork render dispatched at
/// `dispatched` under a host deadline `timeout`: the earlier of the deadline
/// less [`SETTLEMENT_RESERVE`] and the reference's end plus three times its
/// duration (at least three seconds). The reference end is anchored to the
/// host's dispatch, which precedes the worker's receipt.
///
/// `floor` replaces [`OPTIONAL_FLOOR`] only for host tests, whose positive
/// checks must not depend on how quickly a loaded host renders.
pub(crate) fn cutoff(
    dispatched: Instant,
    timeout: Duration,
    offer: &DebugOffer,
    floor: Option<Duration>,
) -> Instant {
    let end = dispatched
        .checked_add(Duration::from_micros(offer.elapsed_us))
        .unwrap_or(dispatched);
    let window = end
        .checked_add(render_allowance(offer.reference_us, floor))
        .unwrap_or(end);
    hard_cap(dispatched, timeout).min(window)
}

/// The render allowance of an optional render: three times the reference
/// render, at least three seconds (or a host test's `floor`).
pub(crate) fn render_allowance(reference_us: u64, floor: Option<Duration>) -> Duration {
    floor
        .unwrap_or(OPTIONAL_FLOOR)
        .max(Duration::from_micros(reference_us).saturating_mul(OPTIONAL_RATIO))
}

/// One host-side observation of a sibling's setup, from its startup attempt
/// to validated readiness. A censored sample is a lower bound: the setup
/// used its whole allowance without finishing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SetupSample {
    pub(crate) elapsed: Duration,
    pub(crate) censored: bool,
}

/// The setup allowance after a baseline: two seconds before the image has
/// a sample, otherwise twice the recent sample within one to five seconds.
/// A host test's `floor` raises the minimum.
pub(crate) fn setup_grace(sample: Option<SetupSample>, floor: Option<Duration>) -> Duration {
    let grace = sample.map_or(SETUP_COLD, |sample| {
        sample
            .elapsed
            .saturating_mul(SETUP_RATIO)
            .clamp(SETUP_MIN, SETUP_MAX)
    });
    floor.map_or(grace, |floor| grace.max(floor))
}

/// The image's next sample: a complete observation replaces the previous
/// one; a lower bound never replaces a larger recent sample.
pub(crate) fn next_sample(previous: Option<SetupSample>, observed: SetupSample) -> SetupSample {
    match previous {
        Some(previous) if observed.censored && previous.elapsed >= observed.elapsed => previous,
        _ => observed,
    }
}

/// What a setup cut off by its own allowance records: a lower bound from
/// the startup attempt, but never less than half the allowance it used up
/// from publication. Time spent before the launch (a retiring peer, host
/// work) then never shortens the next allowance below the exhausted one.
pub(crate) fn censored_sample(
    published: Instant,
    setup_until: Instant,
    launched: Instant,
    at: Instant,
) -> SetupSample {
    let used = setup_until.saturating_duration_since(published).as_nanos();
    let floor = Duration::from_nanos(
        u64::try_from(used.div_ceil(u128::from(SETUP_RATIO))).unwrap_or(u64::MAX),
    );
    SetupSample {
        elapsed: at.saturating_duration_since(launched).max(floor),
        censored: true,
    }
}

/// Where a sibling's setup was when it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SetupStage {
    /// Waiting for an earlier peer of the image to be reaped.
    Retirement,
    Startup,
    Open,
    Replay,
}

impl SetupStage {
    fn trace_phase(self) -> &'static str {
        match self {
            Self::Retirement => "sibling_cutoff_retirement",
            Self::Startup => "sibling_cutoff_startup",
            Self::Open => "sibling_cutoff_open",
            Self::Replay => "sibling_cutoff_replay",
        }
    }
}

/// Which budget ended a phase: its own allowance or the request's hard cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Limit {
    Phase = 1,
    Hard = 2,
}

/// The phase a cutoff ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cut {
    Setup(SetupStage),
    Render,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndCause {
    Cutoff {
        cut: Cut,
        limit: Limit,
        /// When the phase began and when it was cut.
        since: Instant,
        at: Instant,
    },
    Cancelled,
    /// The attempt thread finished on its own.
    Done,
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Setup {
        stage: SetupStage,
        since: Instant,
    },
    Render {
        since: Instant,
        until: Instant,
    },
    Ended {
        cause: EndCause,
        acceptance: Instant,
    },
}

/// The timing of one sibling ticket, shared by its transaction, attempt
/// thread and host: an immutable hard cap and setup deadline, the render
/// allowance that starts at readiness, and one synchronized phase. Host
/// timeouts and peer readiness claim transitions under the same lock, which
/// is never held while spawning, waiting or doing I/O. A closed phase never
/// reopens.
pub(crate) struct PeerTiming {
    hard: Instant,
    setup_until: Instant,
    render: Duration,
    /// Whether the peer acknowledged launching direct debug work.
    direct: AtomicBool,
    state: Mutex<TimingState>,
}

struct TimingState {
    phase: Phase,
    /// The startup attempt, once made.
    launched: Option<Instant>,
}

impl PeerTiming {
    /// Setup runs from `published` (the baseline's publication) for `grace`,
    /// and the render for `render` from readiness, both within `hard`.
    pub(crate) fn new(
        published: Instant,
        grace: Duration,
        render: Duration,
        hard: Instant,
    ) -> Self {
        Self {
            hard,
            setup_until: capped(published, grace, hard),
            render,
            direct: AtomicBool::new(false),
            state: Mutex::new(TimingState {
                phase: Phase::Setup {
                    stage: SetupStage::Retirement,
                    since: published,
                },
                launched: None,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TimingState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    pub(crate) fn setup_until(&self) -> Instant {
        self.setup_until
    }

    /// Whether at least one whole millisecond of setup is left at `now`.
    pub(crate) fn has_budget(&self, now: Instant) -> bool {
        self.setup_until.saturating_duration_since(now) >= MIN_PHASE
    }

    pub(crate) fn direct(&self) -> bool {
        self.direct.load(Ordering::Acquire)
    }

    fn deadline_of(&self, phase: &Phase) -> Instant {
        match *phase {
            Phase::Setup { .. } => self.setup_until,
            Phase::Render { until, .. } => until,
            Phase::Ended { acceptance, .. } => acceptance,
        }
    }

    /// The current phase's deadline; a host polls this, not a fixed one.
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline_of(&self.lock().phase)
    }

    /// The cutoff that admits non-expiry effects: the render deadline once
    /// the peer was ready (retained after the phase ends), otherwise the
    /// setup deadline.
    pub(crate) fn acceptance(&self) -> Instant {
        self.deadline_of(&self.lock().phase)
    }

    /// Closes the open phase with `cause` (the caller holds the lock).
    fn close(&self, state: &mut TimingState, cause: EndCause) -> EndCause {
        let acceptance = self.deadline_of(&state.phase);
        if let Phase::Ended { cause, .. } = state.phase {
            return cause;
        }
        state.phase = Phase::Ended { cause, acceptance };
        cause
    }

    /// Cuts the open phase at `now` if its deadline passed; counted and
    /// traced exactly once per ticket.
    fn cut_if_due(&self, state: &mut TimingState, now: Instant) -> Option<EndCause> {
        let (cut, since, until) = match state.phase {
            Phase::Ended { cause, .. } => return Some(cause),
            Phase::Setup { stage, since } => (Cut::Setup(stage), since, self.setup_until),
            Phase::Render { since, until } => (Cut::Render, since, until),
        };
        if now < until {
            return None;
        }
        let limit = if until >= self.hard {
            Limit::Hard
        } else {
            Limit::Phase
        };
        let cause = self.close(
            state,
            EndCause::Cutoff {
                cut,
                limit,
                since,
                at: now,
            },
        );
        let direct = self.direct();
        count(|stats| match cut {
            Cut::Setup(_) => stats.peer_setup_cutoff += 1,
            Cut::Render if direct => stats.peer_expired += 1,
            Cut::Render => stats.peer_not_launched += 1,
        });
        let phase = match cut {
            Cut::Setup(stage) => stage.trace_phase(),
            Cut::Render => "sibling_cutoff_render",
        };
        crate::performance::interval(phase, since, now, limit as u64);
        Some(cause)
    }

    /// Fails once the attempt was cancelled or its current phase is over.
    fn check(&self, cancel: &AtomicBool, now: Instant) -> Result<(), String> {
        let mut state = self.lock();
        // A cancellation never replaces a cutoff the host already claimed.
        if cancel.load(Ordering::Acquire) {
            return Err(cause_error(self.close(&mut state, EndCause::Cancelled)));
        }
        if let Some(cause) = self.cut_if_due(&mut state, now) {
            return Err(cause_error(cause));
        }
        Ok(())
    }

    /// Enters a later setup stage at `now`, after the same checks.
    fn enter(&self, stage: SetupStage, cancel: &AtomicBool, now: Instant) -> Result<(), String> {
        self.check(cancel, now)?;
        let mut state = self.lock();
        if let Phase::Setup { since, .. } = state.phase {
            state.phase = Phase::Setup { stage, since };
            if stage == SetupStage::Startup {
                state.launched = Some(now);
            }
        }
        Ok(())
    }

    /// Validated readiness at `now`: the one transition from setup to the
    /// render, whose deadline it returns. Declines when the setup is over,
    /// the attempt was cancelled, or less than a millisecond of render is
    /// left. The setup sample is recorded on success.
    fn ready(
        &self,
        cancel: &AtomicBool,
        now: Instant,
    ) -> Result<(Instant, Option<Instant>), String> {
        self.check(cancel, now)?;
        let mut state = self.lock();
        let Phase::Setup { .. } = state.phase else {
            return Err("Debug peer readiness out of order".into());
        };
        let until = capped(now, self.render, self.hard);
        state.phase = Phase::Render { since: now, until };
        if until.saturating_duration_since(now) < MIN_PHASE {
            let cause = self
                .cut_if_due(&mut state, until)
                .expect("an empty render is due");
            return Err(cause_error(cause));
        }
        Ok((until, state.launched))
    }

    /// The host's view at `now`: the end if the attempt is over or its
    /// current phase (re-read under the lock) has expired.
    pub(crate) fn expire(&self, now: Instant) -> Option<EndCause> {
        self.cut_if_due(&mut self.lock(), now)
    }

    /// Before any peer starts: the setup cutoff at `now` when less than one
    /// whole millisecond of the setup allowance is left (host work since
    /// publication spent it), closed, counted and traced like any other.
    pub(crate) fn spent_setup(&self, now: Instant) -> Option<PeerEnd> {
        if self.has_budget(now) {
            return None;
        }
        let cause = self.cut_if_due(&mut self.lock(), now.max(self.setup_until))?;
        PeerEnd::of(cause, self.direct())
    }

    /// The attempt thread is done; any open phase closes as finished.
    fn finish(&self) -> EndCause {
        let mut state = self.lock();
        self.close(&mut state, EndCause::Done)
    }

    /// The startup attempt, once made.
    fn launched(&self) -> Option<Instant> {
        self.lock().launched
    }
}

/// Traces a sibling ticket's budgets at baseline publication: the setup
/// allowance, what is left of the hard cap, and the image's setup sample.
pub(crate) fn trace_budget(
    timing: &PeerTiming,
    published: Instant,
    hard: Instant,
    grace: Duration,
    sample: Option<SetupSample>,
) {
    let ms = |duration: Duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
    crate::performance::interval(
        "sibling_published",
        published,
        published,
        ms(timing.setup_until.saturating_duration_since(published)),
    );
    crate::performance::event("sibling_setup_grace_ms", ms(grace));
    crate::performance::event(
        "sibling_hard_remaining_ms",
        ms(hard.saturating_duration_since(published)),
    );
    if let Some(sample) = sample {
        crate::performance::event(
            if sample.censored {
                "sibling_setup_sample_lower_bound_us"
            } else {
                "sibling_setup_sample_us"
            },
            u64::try_from(sample.elapsed.as_micros()).unwrap_or(u64::MAX),
        );
    }
}

fn cause_error(cause: EndCause) -> String {
    match cause {
        EndCause::Cancelled => "cancelled".into(),
        EndCause::Cutoff { .. } => "expired".into(),
        EndCause::Done => "Debug peer attempt is over".into(),
    }
}

/// Milliseconds left until `cutoff`, zero when it passed.
pub(crate) fn remaining_ms(cutoff: Instant) -> u64 {
    u64::try_from(cutoff.saturating_duration_since(Instant::now()).as_millis()).unwrap_or(u64::MAX)
}

/// A validated baseline and its offer.
#[derive(Clone, Debug)]
pub(crate) struct Prepared {
    pub(crate) address: u64,
    pub(crate) text: String,
    pub(crate) mappings: Vec<CodeMapping>,
    pub(crate) semantics: SemanticInfo,
    /// Absent when the offer is malformed or unrepresentable: the baseline
    /// then settles as it is.
    pub(crate) offer: Option<DebugOffer>,
}

/// Checks a `PreparedDecompile` reply for `address`. A malformed baseline
/// is a first-phase protocol error; a malformed offer only drops the offer.
pub(crate) fn admit_prepared(
    expected: u64,
    response: Response,
    info: &BinaryInfo,
    signature_context: &str,
) -> Result<Prepared, String> {
    let Response::PreparedDecompile {
        address,
        text,
        mappings,
        semantics,
        offer,
    } = response
    else {
        return Err("Not a prepared decompilation".into());
    };
    if address != expected {
        return Err("Prepared decompilation of a different function".into());
    }
    check_code(
        address,
        &text,
        &mappings,
        &semantics,
        &info.sections,
        signature_context,
    )?;
    if semantics.prototype_source != crate::semantic::PrototypeSource::Inferred {
        return Err("A baseline cannot claim a debug prototype".into());
    }
    let offer = check_offer(address, &text, &mappings, &semantics, offer, info).ok();
    if offer.is_some() {
        count(|stats| stats.prepared += 1);
    }
    Ok(Prepared {
        address,
        text,
        mappings,
        semantics,
        offer,
    })
}

fn sorted(values: &[u64]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn check_offer(
    address: u64,
    text: &str,
    mappings: &[CodeMapping],
    semantics: &SemanticInfo,
    offer: DebugOffer,
    info: &BinaryInfo,
) -> Result<DebugOffer, String> {
    let digest =
        crate::analysis::managed::baseline_digest(address, text, mappings, semantics, &offer.calls);
    let code = |entry: u64| crate::call_analysis::code_address(info, entry);
    if !code(address)
        || offer.reference_us > offer.elapsed_us
        || offer.elapsed_us > crate::model::WORKER_REQUEST_TIMEOUT.as_micros() as u64
        || offer.nonce == 0
        || offer.logical_id == 0
        || [
            &offer.binding.program,
            &offer.binding.context,
            &offer.binding.facts,
        ]
        .into_iter()
        .any(|digest| !crate::search::valid_digest(digest))
        || (offer.cacheable && info.format == "PE")
        || digest != offer.binding.baseline
        || !sorted(&offer.calls)
        || offer.calls.iter().any(|&entry| !code(entry))
        || !sorted(&offer.callees)
        || offer
            .callees
            .iter()
            .any(|callee| *callee == address || !offer.calls.contains(callee) || !code(*callee))
        || (!offer.target_work && offer.callees.is_empty())
    {
        return Err("Malformed debug offer".into());
    }
    Ok(offer)
}

/// The final render of a prepared request: `base` (the baseline or an
/// accepted candidate) with the settlement's debug warnings and provenance.
pub(crate) fn compose(
    base: (String, Vec<CodeMapping>, SemanticInfo),
    settlement: &Settlement,
) -> (String, Vec<CodeMapping>, SemanticInfo) {
    let (text, mappings, semantics) = base;
    crate::analysis::compose(
        Published {
            text,
            mappings,
            semantics,
            calls: Vec::new(),
            calls_complete: true,
        },
        &settlement.warnings,
        settlement.debug_owned,
    )
}

/// Checks a fork's candidate body in a settlement for `address`.
pub(crate) fn check_candidate(
    address: u64,
    render: &Published,
    info: &BinaryInfo,
    signature_context: &str,
) -> Result<(), String> {
    check_code(
        address,
        &render.text,
        &render.mappings,
        &render.semantics,
        &info.sections,
        signature_context,
    )?;
    if render.semantics.prototype_source != crate::semantic::PrototypeSource::Inferred
        || !sorted(&render.calls)
        || render
            .calls
            .iter()
            .any(|&entry| !crate::call_analysis::code_address(info, entry))
    {
        return Err("Malformed debug candidate".into());
    }
    Ok(())
}

/// The one optional-peer slot of a primary's image. A replacement primary
/// has a fresh slot, and with it a fresh setup history.
#[derive(Default, Clone)]
pub(crate) struct PeerSlot(Arc<PeerSlotState>);

#[derive(Default)]
struct PeerSlotState {
    active: Mutex<Option<Arc<AtomicBool>>>,
    reaped: Condvar,
    /// The image's recent setup sample.
    setup: Mutex<Option<SetupSample>>,
}

/// The result of waiting for the slot.
pub(crate) enum Reserve {
    Reserved(PeerReservation),
    Cancelled,
    Deadline,
}

/// The longest single wait before cancellation and time are rechecked.
const RESERVE_POLL: Duration = Duration::from_millis(20);

impl PeerSlot {
    fn claim(&self, active: &mut Option<Arc<AtomicBool>>) -> PeerReservation {
        let cancel = Arc::new(AtomicBool::new(false));
        *active = Some(Arc::clone(&cancel));
        PeerReservation {
            slot: self.clone(),
            cancel,
        }
    }

    /// Reserves the slot only if it is free now; never waits (the desktop).
    pub(crate) fn try_reserve(&self) -> Result<PeerReservation, String> {
        let mut active = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if active.is_some() {
            return Err("Previous debug peer is still retiring".into());
        }
        Ok(self.claim(&mut active))
    }

    /// Waits for an earlier peer to be reaped, then reserves the slot. Under
    /// the slot lock the caller's cancellation is checked first and `until`
    /// second, including when the slot is already free, and again after
    /// every wake; waits last at most 20 ms. Never call on the GUI thread.
    pub(crate) fn wait_reserve(&self, until: Instant, cancelled: &dyn Fn() -> bool) -> Reserve {
        let mut active = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        loop {
            if cancelled() {
                return Reserve::Cancelled;
            }
            let now = Instant::now();
            if now >= until {
                return Reserve::Deadline;
            }
            if active.is_none() {
                return Reserve::Reserved(self.claim(&mut active));
            }
            let wait = until.saturating_duration_since(now).min(RESERVE_POLL);
            active = self
                .0
                .reaped
                .wait_timeout(active, wait)
                .unwrap_or_else(|error| error.into_inner())
                .0;
        }
    }

    pub(crate) fn cancel(&self) {
        if let Some(stop) = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
        {
            stop.store(true, Ordering::Release);
        }
    }

    /// The image's recent setup sample.
    pub(crate) fn setup_sample(&self) -> Option<SetupSample> {
        *self
            .0
            .setup
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn observe_setup(&self, observed: SetupSample) {
        let mut sample = self
            .0
            .setup
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *sample = Some(next_sample(*sample, observed));
    }

    pub(crate) fn stop_and_wait(&self) -> Result<(), String> {
        self.cancel();
        let active = self
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (active, _) = self
            .0
            .reaped
            .wait_timeout_while(active, Duration::from_secs(10), |active| active.is_some())
            .unwrap_or_else(|error| error.into_inner());
        if active.is_some() {
            return Err("Cannot stop and reap the optional debug peer".into());
        }
        Ok(())
    }
}

/// Exclusive use of a [`PeerSlot`] until dropped, which wakes waiters.
pub(crate) struct PeerReservation {
    slot: PeerSlot,
    cancel: Arc<AtomicBool>,
}

impl Drop for PeerReservation {
    fn drop(&mut self) {
        let mut active = self
            .slot
            .0
            .active
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *active = None;
        self.slot.0.reaped.notify_all();
    }
}

/// What a debug peer starts from: the primary's trusted executable and
/// internal arguments, its retained image path, protection and lease, and
/// its exact accepted companion (`None` = explicitly none).
#[derive(Clone)]
pub(crate) struct PeerLaunch {
    pub(crate) exe: PathBuf,
    pub(crate) binary: PathBuf,
    pub(crate) companion: Option<crate::debug_info::companion::DebugSource>,
    pub(crate) protection: BinaryProtection,
    pub(crate) lease: Option<Arc<dyn Send + Sync>>,
    pub(crate) worker_args: Vec<std::ffi::OsString>,
    pub(crate) slot: PeerSlot,
}

/// The immutable, committed state a peer must reproduce before it renders:
/// the primary's verified image, debug state, effective function names and
/// signatures with their acknowledged unapplied statuses.
pub(crate) struct PeerContext {
    pub(crate) launch: PeerLaunch,
    pub(crate) enabled: bool,
    pub(crate) skip: Vec<u64>,
    pub(crate) info: Arc<BinaryInfo>,
    pub(crate) debug_state: String,
    /// Effective (engine-spelled) names, sorted by address.
    pub(crate) functions: Arc<Vec<FunctionInfo>>,
    pub(crate) long_names: Vec<FunctionInfo>,
    pub(crate) signatures: Arc<Vec<crate::signatures::FunctionSignature>>,
    pub(crate) unapplied: Vec<SignatureStatus>,
    /// The committed signature context the primary renders under.
    pub(crate) signature_context: String,
}

/// How a sibling's attempt ended.
#[derive(Debug)]
pub(crate) enum PeerEnd {
    /// Nothing was attempted: start, Open, identity, replay or digest
    /// failure.
    NotLaunched(String),
    /// The setup allowance ran out at this stage before any render was
    /// sent.
    SetupCutoff(SetupStage),
    /// The render allowance ran out before the peer acknowledged direct
    /// work.
    RenderCutoff,
    /// Direct work started but no valid result arrived by the cutoff.
    Expired,
    /// A malformed or unauthenticated result.
    Invalid,
    /// A validated result.
    Finished(Box<DebugOutcome>),
    /// The host cancelled the attempt.
    Cancelled,
}

impl PeerEnd {
    /// The end a closed phase means; `None` for an attempt that finished
    /// on its own (its own reply then decides).
    fn of(cause: EndCause, direct: bool) -> Option<Self> {
        match cause {
            EndCause::Cutoff {
                cut: Cut::Setup(stage),
                ..
            } => Some(Self::SetupCutoff(stage)),
            EndCause::Cutoff {
                cut: Cut::Render, ..
            } if direct => Some(Self::Expired),
            EndCause::Cutoff {
                cut: Cut::Render, ..
            } => Some(Self::RenderCutoff),
            EndCause::Cancelled => Some(Self::Cancelled),
            EndCause::Done => None,
        }
    }

    /// A small, stable outcome code for the host trace.
    pub(crate) fn code(&self) -> u64 {
        match self {
            Self::Finished(_) => 1,
            Self::Invalid => 2,
            Self::NotLaunched(_) => 3,
            // 40 + the stage: retirement, startup, Open, replay.
            Self::SetupCutoff(stage) => 40 + *stage as u64,
            Self::RenderCutoff => 5,
            Self::Expired => 6,
            Self::Cancelled => 7,
        }
    }
}

/// A running sibling attempt. Dropping it cancels the attempt; the worker
/// thread still stops and reaps the peer before releasing its lease.
pub(crate) struct PeerRun {
    receiver: mpsc::Receiver<PeerEnd>,
    cancel: Arc<AtomicBool>,
    timing: Arc<PeerTiming>,
}

impl PeerRun {
    /// The attempt's end, once.
    pub(crate) fn poll(&self) -> Option<PeerEnd> {
        self.receiver.try_recv().ok()
    }
    /// Blocks for the attempt's end until `until`.
    pub(crate) fn wait(&self, until: Instant) -> Option<PeerEnd> {
        self.receiver
            .recv_timeout(until.saturating_duration_since(Instant::now()))
            .ok()
    }
    /// The current phase's deadline.
    pub(crate) fn deadline(&self) -> Instant {
        self.timing.deadline()
    }
    /// The host's cutoff at `now`: the end when the current phase (re-read
    /// under the timing lock) has expired, which also stops the attempt.
    /// `None` while the phase is still open, including when the peer
    /// became ready just before.
    pub(crate) fn expire(&self, now: Instant) -> Option<PeerEnd> {
        let end = PeerEnd::of(self.timing.expire(now)?, self.timing.direct())?;
        self.cancel();
        Some(end)
    }
    pub(crate) fn timing(&self) -> &Arc<PeerTiming> {
        &self.timing
    }
    pub(crate) fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

impl Drop for PeerRun {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Starts one sibling attempt for `job` on a background thread with the
/// reserved slot, which starts, opens, replays and runs the peer within
/// `timing`, validates its answer, stops and reaps it, and then sends the
/// end and calls `wake`. `cancelled` is the caller's own cancellation,
/// rechecked immediately before the peer process starts.
pub(crate) fn start_peer(
    context: Arc<PeerContext>,
    job: PeerJob,
    reservation: PeerReservation,
    timing: Arc<PeerTiming>,
    cancelled: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
    wake: impl Fn() + Send + 'static,
) -> Result<PeerRun, String> {
    job.check()?;
    let cancel = Arc::clone(&reservation.cancel);
    let (sender, receiver) = mpsc::sync_channel(1);
    let shared = Arc::clone(&timing);
    std::thread::Builder::new()
        .name("debug-peer".into())
        .spawn(move || {
            // Wire ids restart in every peer; the trace uses the logical id.
            let _context = crate::performance::context(job.ticket.logical_id);
            count(|stats| stats.peers += 1);
            let mut peer = Reaping(None);
            let stop = &reservation.cancel;
            if cancelled.as_ref().is_some_and(|cancelled| cancelled()) {
                stop.store(true, Ordering::Release);
            }
            let result = run_peer(&context, &job, &shared, stop, &mut peer);
            // Close the phases first: a host polling from now on waits for
            // this end instead of claiming a cutoff of its own.
            let closed = shared.finish();
            let direct = shared.direct();
            let end = match (result, PeerEnd::of(closed, direct)) {
                (_, Some(end)) => end,
                (Ok(end), None) => end,
                (Err(_), None) if stop.load(Ordering::Acquire) => PeerEnd::Cancelled,
                (Err(error), None) if direct => {
                    if error.starts_with("Analysis worker exited:") {
                        PeerEnd::Expired
                    } else {
                        PeerEnd::Invalid
                    }
                }
                (Err(error), None) => PeerEnd::NotLaunched(error),
            };
            if let (
                EndCause::Cutoff {
                    cut: Cut::Setup(stage),
                    limit: Limit::Phase,
                    since,
                    at,
                },
                Some(launched),
            ) = (closed, shared.launched())
                && stage != SetupStage::Retirement
            {
                // A real setup that used its whole allowance: a lower bound.
                let observed = censored_sample(since, shared.setup_until(), launched, at);
                context.launch.slot.observe_setup(observed);
                crate::performance::event(
                    "sibling_setup_lower_bound_us",
                    u64::try_from(observed.elapsed.as_micros()).unwrap_or(u64::MAX),
                );
            }
            count(|stats| match &end {
                PeerEnd::NotLaunched(reason) if reason.starts_with("digest-") => {
                    stats.peer_mismatch += 1;
                    match reason.as_str() {
                        "digest-context" => stats.peer_context_mismatch += 1,
                        "digest-baseline" => stats.peer_baseline_mismatch += 1,
                        "digest-facts" => stats.peer_facts_mismatch += 1,
                        _ => {}
                    }
                }
                PeerEnd::NotLaunched(_) => stats.peer_not_launched += 1,
                PeerEnd::Expired if !matches!(closed, EndCause::Cutoff { .. }) => {
                    stats.peer_expired += 1
                }
                PeerEnd::Finished(_) => stats.peer_finished += 1,
                // Cutoffs are counted once, where the phase closed.
                PeerEnd::Expired
                | PeerEnd::SetupCutoff(_)
                | PeerEnd::RenderCutoff
                | PeerEnd::Cancelled
                | PeerEnd::Invalid => {}
            });
            crate::performance::event("sibling_direct", u64::from(direct));
            crate::performance::event("sibling_end", end.code());
            // The host can settle while the peer is still being reaped; the
            // reservation keeps the slot busy until the process is gone.
            if sender.send(end).is_ok() {
                wake();
            }
            let reap = Instant::now();
            drop(peer);
            crate::performance::interval("sibling_reap", reap, Instant::now(), 0);
            drop(reservation);
        })
        .map_err(|error| format!("Cannot start debug peer thread: {error}"))?;
    Ok(PeerRun {
        receiver,
        cancel,
        timing,
    })
}

/// Stops and reaps a peer before its lease is released, on every path.
struct Reaping(Option<WorkerClient>);
impl Drop for Reaping {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            // A failed reap falls back to the client's own asynchronous drop,
            // which still keeps the lease until the process exits.
            let _ = worker.stop_and_wait();
        }
    }
}

fn run_peer(
    context: &PeerContext,
    job: &PeerJob,
    timing: &PeerTiming,
    cancel: &AtomicBool,
    peer: &mut Reaping,
) -> Result<PeerEnd, String> {
    let check = || timing.check(cancel, Instant::now());
    let startup = Instant::now();
    timing.enter(SetupStage::Startup, cancel, startup)?;
    peer.0 = Some(WorkerClient::start_peer(&context.launch)?);
    let opening = Instant::now();
    crate::performance::interval("sibling_startup", startup, opening, 0);
    timing.enter(SetupStage::Open, cancel, opening)?;
    let worker = peer.0.as_mut().expect("started peer");
    let path = worker
        .protection()
        .path()
        .to_str()
        .ok_or("The binary path must be UTF-8")?
        .to_owned();
    let Response::Opened { info, debug, .. } = exchange(
        worker,
        Request::Open {
            debug: crate::debug_info::DebugOptions {
                companion_path: None,
                enabled: context.enabled,
                skip: context.skip.clone(),
            },
            path,
        },
        timing,
        cancel,
    )?
    else {
        return Err("Unexpected peer open reply".into());
    };
    // The same file and the same accepted debug state as the primary: a
    // fresh guard agreeing only with its own Open proves too little.
    let found_companion = debug.as_ref().and_then(|summary| summary.source.as_ref());
    let same_companion = match (context.launch.companion.as_ref(), found_companion) {
        (Some(expected), Some(actual)) => {
            expected.identity == actual.identity
                && expected.sha256 == actual.sha256
                && expected.uuid == actual.uuid
        }
        (None, None) => true,
        _ => false,
    };
    if !same_companion
        || !worker.protection().same_source(&context.launch.protection)
        || !crate::project::same_image(&context.info, &info)
        || debug.as_ref().map_or("", |summary| summary.state.as_str()) != context.debug_state
    {
        return Err("Debug peer opened a different image or debug state".into());
    }
    let replaying = Instant::now();
    crate::performance::interval("sibling_open", opening, replaying, 0);
    timing.enter(SetupStage::Replay, cancel, replaying)?;
    let replay: Vec<FunctionInfo> = context
        .functions
        .iter()
        .filter(|function| {
            crate::model::function_at(&info.functions, function.address).is_none_or(|current| {
                current.name != crate::model::inventory_spelling(&function.name)
            })
        })
        .map(|function| FunctionInfo {
            address: function.address,
            name: crate::model::inventory_spelling(&function.name).to_owned(),
        })
        .collect();
    let mut acknowledged = 0u64;
    for chunk in crate::model::sync_chunks(&replay) {
        check()?;
        if !matches!(
            exchange(
                worker,
                Request::SyncFunctions {
                    functions: chunk.to_vec(),
                },
                timing,
                cancel,
            )?,
            Response::FunctionsSynced
        ) {
            return Err("Unexpected peer synchronization reply".into());
        }
        acknowledged += 1;
    }
    for function in &context.long_names {
        check()?;
        match exchange(
            worker,
            Request::Rename {
                address: function.address,
                name: function.name.clone(),
            },
            timing,
            cancel,
        )? {
            Response::Renamed { address, name }
                if address == function.address && name == function.name => {}
            _ => return Err("Debug peer name replay differs".into()),
        }
        acknowledged += 1;
    }
    if !context.signatures.is_empty() {
        check()?;
        let digest = crate::signatures::state_digest(&context.signatures);
        match exchange(
            worker,
            Request::SyncSignatures {
                binary_sha256: context.info.sha256.clone(),
                context: digest.clone(),
                signatures: (*context.signatures).clone(),
            },
            timing,
            cancel,
        )? {
            Response::SignaturesSynced {
                binary_sha256,
                context: actual,
                unapplied,
            } if binary_sha256 == context.info.sha256
                && actual == digest
                && actual == context.signature_context
                && unapplied == context.unapplied => {}
            _ => return Err("Debug peer signature replay differs".into()),
        }
        acknowledged += 1;
    } else if !context.signature_context.is_empty() {
        return Err("Debug peer signature context differs".into());
    }
    // The one transition to the render: its allowance starts here.
    let ready = Instant::now();
    crate::performance::interval("sibling_replay", replaying, ready, acknowledged);
    let (until, launched) = timing.ready(cancel, ready)?;
    if let Some(launched) = launched {
        let elapsed = ready.saturating_duration_since(launched);
        context.launch.slot.observe_setup(SetupSample {
            elapsed,
            censored: false,
        });
        crate::performance::event(
            "sibling_setup_observed_us",
            u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
        );
    }
    let request = Request::RenderDebugOnce {
        job: PeerJob {
            remaining_ms: remaining_ms(until),
            ..job.clone()
        },
    };
    let render = crate::performance::span("sibling_render");
    let reply = exchange(worker, request, timing, cancel);
    render.finish(remaining_ms(until));
    match reply? {
        Response::DebugFinished {
            ticket,
            measured,
            outcome,
        } => {
            if ticket != job.ticket || measured != job.binding {
                return Ok(PeerEnd::Invalid);
            }
            // A complete frame can arrive at the cutoff. The host will
            // validate it and reject a late result as a whole.
            Ok(PeerEnd::Finished(Box::new(outcome.0)))
        }
        Response::DebugUnavailable { reason, .. } if !timing.direct() => {
            Ok(PeerEnd::NotLaunched(reason))
        }
        _ => Err("Unexpected debug peer reply".into()),
    }
}

/// One request/terminal-reply exchange with a peer within the current
/// phase of `timing` and `cancel`, both checked before the request is sent
/// and while waiting. A `DebugStarted` notice records direct work.
fn exchange(
    worker: &mut WorkerClient,
    request: Request,
    timing: &PeerTiming,
    cancel: &AtomicBool,
) -> Result<Response, String> {
    timing.check(cancel, Instant::now())?;
    let id = worker.send(request)?;
    let mut started = false;
    loop {
        timing.check(cancel, Instant::now())?;
        match worker.poll() {
            Some(WorkerEvent::Failed(message)) => return Err(message),
            Some(WorkerEvent::Reply(reply)) => {
                if reply.id != id {
                    return Err("Debug peer replied to a different request".into());
                }
                match reply.response {
                    Response::DebugStarted { direct, .. } if !started => {
                        started = true;
                        timing.direct.store(direct, Ordering::Release);
                    }
                    Response::DebugStarted { .. } | Response::Progress { .. } => {
                        return Err("Unexpected debug peer notice".into());
                    }
                    Response::Error { message } => return Err(message),
                    response => return Ok(response),
                }
            }
            None => std::thread::sleep(Duration::from_millis(2)),
        }
    }
}

/// The host's single slot for optional work.
pub(crate) enum Optional {
    Fork { id: u64, direct: bool },
    Peer(PeerRun),
}

/// Metadata added to a checked final render.
#[derive(Default)]
pub(crate) struct Settlement {
    pub(crate) warnings: Vec<String>,
    pub(crate) debug_owned: bool,
}

/// What settled a prepared request.
pub(crate) enum Final {
    Baseline(Settlement),
    Candidate(Box<Published>, Settlement),
}

impl Final {
    pub(crate) fn render(self, prepared: &Prepared) -> (String, Vec<CodeMapping>, SemanticInfo) {
        count(|stats| match self {
            Final::Baseline(_) => stats.kept += 1,
            Final::Candidate(..) => stats.replaced += 1,
        });
        match self {
            Final::Baseline(settlement) => compose(
                (
                    prepared.text.clone(),
                    prepared.mappings.clone(),
                    prepared.semantics.clone(),
                ),
                &settlement,
            ),
            Final::Candidate(render, settlement) => {
                let Published {
                    text,
                    mappings,
                    semantics,
                    ..
                } = *render;
                compose((text, mappings, semantics), &settlement)
            }
        }
    }
}

/// A fresh logical `PrepareDecompile`. `inference_only` is the one-shot
/// recovery after an earlier attempt stopped before its baseline.
pub(crate) fn prepare_request(
    address: u64,
    renames: Vec<crate::semantic::LocalRename>,
    refresh: bool,
    inference_only: bool,
) -> Result<Request, String> {
    static LOGICAL_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let logical_id = LOGICAL_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .map_err(|_| "Logical decompile request counter overflow")?;
    Ok(Request::PrepareDecompile {
        logical_id,
        address,
        renames,
        refresh,
        inference_only,
    })
}

pub(crate) fn optional_request(
    job: PeerJob,
    executor: crate::analysis::managed::Executor,
) -> Request {
    match executor {
        crate::analysis::managed::Executor::ForkHere => Request::TryPreparedDebug { job },
        crate::analysis::managed::Executor::Sibling => Request::RenderDebugOnce { job },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const MS: Duration = Duration::from_millis(1);
    const SECOND: Duration = Duration::from_secs(1);

    fn sample(ms: u64, censored: bool) -> Option<SetupSample> {
        Some(SetupSample {
            elapsed: Duration::from_millis(ms),
            censored,
        })
    }

    fn offer(reference_us: u64, elapsed_us: u64) -> DebugOffer {
        DebugOffer {
            logical_id: 1,
            nonce: 1,
            executor: crate::analysis::managed::Executor::ForkHere,
            reference_us,
            elapsed_us,
            binding: crate::analysis::managed::Binding {
                program: String::new(),
                context: String::new(),
                baseline: String::new(),
                facts: String::new(),
            },
            calls: Vec::new(),
            target_work: true,
            graph_prepared: false,
            callees: Vec::new(),
            cacheable: false,
        }
    }

    #[test]
    fn managed_scheduler_setup_allowance_policy() {
        // Cold, lower and upper clamps, a middle sample and the test floor.
        assert_eq!(setup_grace(None, None), 2 * SECOND);
        assert_eq!(setup_grace(sample(100, false), None), SECOND);
        assert_eq!(setup_grace(sample(1_200, false), None), 2_400 * MS);
        assert_eq!(setup_grace(sample(4_000, false), None), 5 * SECOND);
        assert_eq!(
            setup_grace(sample(100, false), Some(10 * SECOND)),
            10 * SECOND
        );
        // A cutoff that used the whole allowance grows the next one (cold
        // 2 s, then 4 s, then the 5 s cap); a complete sample resets it.
        let mut current = None;
        let mut graces = Vec::new();
        for _ in 0..3 {
            let grace = setup_grace(current, None);
            graces.push(grace);
            current = Some(next_sample(
                current,
                SetupSample {
                    elapsed: grace,
                    censored: true,
                },
            ));
        }
        assert_eq!(graces, [2 * SECOND, 4 * SECOND, 5 * SECOND]);
        current = Some(next_sample(current, sample(300, false).unwrap()));
        assert_eq!(setup_grace(current, None), SECOND);
        // A late launch: the cold allowance was mostly spent waiting before
        // the startup attempt, which was then cut 0.4 s in. The recorded
        // lower bound keeps the next allowance at the exhausted 2 s instead
        // of shrinking it to 1 s; a launch at publication still grows it.
        let published = Instant::now();
        let until = published + 2 * SECOND;
        let late = censored_sample(published, until, published + 1_600 * MS, until);
        assert_eq!(late, sample(1_000, true).unwrap());
        assert_eq!(setup_grace(Some(next_sample(None, late)), None), 2 * SECOND);
        let prompt = censored_sample(published, until, published, until);
        assert_eq!(
            setup_grace(Some(next_sample(None, prompt)), None),
            4 * SECOND
        );
        // From a short complete sample's 1 s allowance, a late launch keeps 1 s.
        let until = published + SECOND;
        let late = censored_sample(published, until, published + 900 * MS, until);
        assert_eq!(
            setup_grace(Some(next_sample(sample(300, false), late)), None),
            SECOND
        );
        // An odd allowance is never rounded below itself.
        let until = published + Duration::from_nanos(1_500_000_001);
        let late = censored_sample(published, until, until, until);
        assert!(setup_grace(Some(late), None) >= until - published);
        // A small lower bound never replaces a larger recent sample.
        assert_eq!(
            next_sample(sample(3_000, false), sample(500, true).unwrap()),
            sample(3_000, false).unwrap()
        );
        assert_eq!(
            next_sample(sample(3_000, false), sample(4_000, true).unwrap()),
            sample(4_000, true).unwrap()
        );
    }

    #[test]
    fn managed_scheduler_budgets_are_clipped_by_the_hard_cap() {
        let start = Instant::now();
        let hard = hard_cap(start, Duration::from_secs(30));
        assert_eq!(hard, start + Duration::from_secs(27));
        assert_eq!(hard_cap(start, SECOND), start, "the reserve saturates");
        // Setup is clipped by the hard cap; so is the render from readiness.
        let timing = PeerTiming::new(start, 5 * SECOND, 10 * SECOND, start + 3 * SECOND);
        assert_eq!(timing.setup_until(), start + 3 * SECOND);
        let timing = PeerTiming::new(start, 2 * SECOND, 10 * SECOND, start + 5 * SECOND);
        let never = AtomicBool::new(false);
        let (until, _) = timing.ready(&never, start + SECOND).unwrap();
        assert_eq!(until, start + 5 * SECOND);
        // An overflowing allowance is the hard cap, never a wrap.
        let timing = PeerTiming::new(start, Duration::MAX, Duration::MAX, start + SECOND);
        assert_eq!(timing.setup_until(), start + SECOND);
        // Less than one whole millisecond declines the phase.
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, start + 500 * MS);
        assert!(timing.has_budget(start + 499 * MS));
        assert!(!timing.has_budget(start + 499 * MS + Duration::from_micros(1)));
        assert!(!timing.has_budget(start + 500 * MS));
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, start + SECOND);
        let ready = start + SECOND - Duration::from_micros(500);
        assert!(
            timing.ready(&never, ready).is_err(),
            "a sub-millisecond render"
        );
        assert!(matches!(
            timing.expire(ready),
            Some(EndCause::Cutoff {
                cut: Cut::Render,
                limit: Limit::Hard,
                ..
            })
        ));
    }

    #[test]
    fn managed_scheduler_fork_window_is_unchanged() {
        let start = Instant::now();
        let timeout = Duration::from_secs(30);
        for (reference, elapsed, floor) in [
            (1_000, 2_000, None),
            (2_000_000, 2_500_000, None),
            (9_000_000, 9_500_000, None),
            (1_000, 2_000, Some(10 * SECOND)),
            (1_000, 26_000_000, None),
        ] {
            let end = start + Duration::from_micros(elapsed);
            let window = floor
                .unwrap_or(3 * SECOND)
                .max(Duration::from_micros(reference) * 3);
            let expected = (start + timeout - 3 * SECOND).min(end + window);
            assert_eq!(
                cutoff(start, timeout, &offer(reference, elapsed), floor),
                expected
            );
        }
    }

    /// A peer ready just before its setup deadline gets its whole render
    /// allowance: a reply after the setup deadline but before the render
    /// deadline is current, and acceptance uses the render deadline.
    #[test]
    fn managed_scheduler_readiness_moves_the_deadline_once() {
        let start = Instant::now();
        let hard = start + Duration::from_secs(27);
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, hard);
        let never = AtomicBool::new(false);
        timing.enter(SetupStage::Startup, &never, start).unwrap();
        timing
            .enter(SetupStage::Open, &never, start + 100 * MS)
            .unwrap();
        timing
            .enter(SetupStage::Replay, &never, start + 1_500 * MS)
            .unwrap();
        let ready = start + 2 * SECOND - MS;
        let (until, launched) = timing.ready(&never, ready).unwrap();
        assert_eq!((until, launched), (ready + 3 * SECOND, Some(start)));
        assert_eq!(timing.deadline(), until);
        // The host's timeout at the old setup deadline re-reads the phase.
        assert!(timing.expire(start + 2 * SECOND + MS).is_none());
        assert!(timing.check(&never, start + 4 * SECOND).is_ok());
        assert_eq!(timing.acceptance(), until);
        // At the render deadline the phase is cut once, before the hard cap.
        let cause = timing.expire(until).unwrap();
        assert!(matches!(
            cause,
            EndCause::Cutoff {
                cut: Cut::Render,
                limit: Limit::Phase,
                ..
            }
        ));
        assert!(matches!(
            PeerEnd::of(cause, false),
            Some(PeerEnd::RenderCutoff)
        ));
        assert!(matches!(PeerEnd::of(cause, true), Some(PeerEnd::Expired)));
        // The retained cutoff survives the thread finishing late.
        assert_eq!(timing.finish(), cause);
        assert_eq!(timing.acceptance(), until);
    }

    /// Setup that runs out before the render is a typed setup cutoff at its
    /// stage; late readiness can neither reopen it nor send a render.
    #[test]
    fn managed_scheduler_setup_cutoff_is_final() {
        let start = Instant::now();
        let hard = start + Duration::from_secs(27);
        let never = AtomicBool::new(false);
        // Thread-detected: readiness after a delayed replay acknowledgement.
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, hard);
        timing.enter(SetupStage::Startup, &never, start).unwrap();
        timing
            .enter(SetupStage::Open, &never, start + SECOND)
            .unwrap();
        timing
            .enter(SetupStage::Replay, &never, start + 1_900 * MS)
            .unwrap();
        assert_eq!(
            timing.ready(&never, start + 2 * SECOND),
            Err("expired".into())
        );
        let cause = timing.expire(start + 2 * SECOND).unwrap();
        assert!(matches!(
            cause,
            EndCause::Cutoff {
                cut: Cut::Setup(SetupStage::Replay),
                limit: Limit::Phase,
                ..
            }
        ));
        assert!(matches!(
            PeerEnd::of(cause, false),
            Some(PeerEnd::SetupCutoff(SetupStage::Replay))
        ));
        // Host-forced during a delayed Open; the stale readiness after it
        // is refused and the cause stays the host's.
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, hard);
        timing.enter(SetupStage::Startup, &never, start).unwrap();
        timing
            .enter(SetupStage::Open, &never, start + 100 * MS)
            .unwrap();
        let host = timing.expire(start + 2 * SECOND).unwrap();
        assert!(timing.ready(&never, start + 2 * SECOND + MS).is_err());
        assert!(timing.enter(SetupStage::Replay, &never, start).is_err());
        assert_eq!(timing.expire(start + 10 * SECOND), Some(host));
        assert_eq!(timing.finish(), host);
        assert!(matches!(
            host,
            EndCause::Cutoff {
                cut: Cut::Setup(SetupStage::Open),
                ..
            }
        ));
        // A setup deadline at the hard cap is attributed to the hard cap.
        let timing = PeerTiming::new(start, 5 * SECOND, 3 * SECOND, start + SECOND);
        assert!(matches!(
            timing.expire(start + SECOND),
            Some(EndCause::Cutoff {
                cut: Cut::Setup(SetupStage::Retirement),
                limit: Limit::Hard,
                ..
            })
        ));
        // A cancellation is its own end and never becomes a cutoff.
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, hard);
        let cancelled = AtomicBool::new(true);
        assert!(timing.check(&cancelled, start + 5 * SECOND).is_err());
        assert_eq!(timing.expire(start + 5 * SECOND), Some(EndCause::Cancelled));
    }

    /// A setup allowance that host work spent before any peer started is
    /// the typed setup cutoff, even with a sub-millisecond remainder, and
    /// the phase stays closed; with budget left nothing is claimed.
    #[test]
    fn managed_scheduler_spent_setup_is_the_setup_cutoff() {
        let start = Instant::now();
        let hard = start + Duration::from_secs(27);
        let grace = 5 * MS;
        let timing = PeerTiming::new(start, grace, 3 * SECOND, hard);
        assert!(timing.spent_setup(start + 3 * MS).is_none());
        assert_eq!(timing.deadline(), start + grace);
        let early = start + grace - Duration::from_micros(500);
        assert!(matches!(
            timing.spent_setup(early),
            Some(PeerEnd::SetupCutoff(SetupStage::Retirement))
        ));
        assert!(matches!(
            timing.expire(early),
            Some(EndCause::Cutoff {
                cut: Cut::Setup(SetupStage::Retirement),
                limit: Limit::Phase,
                ..
            })
        ));
        assert_eq!(timing.acceptance(), start + grace);
        let never = AtomicBool::new(false);
        assert!(timing.enter(SetupStage::Startup, &never, early).is_err());
        assert!(timing.launched().is_none());
        // Long past the allowance, and clipped by the hard cap.
        let timing = PeerTiming::new(start, grace, 3 * SECOND, hard);
        assert!(matches!(
            timing.spent_setup(start + SECOND),
            Some(PeerEnd::SetupCutoff(SetupStage::Retirement))
        ));
        let timing = PeerTiming::new(start, 2 * SECOND, 3 * SECOND, start + SECOND);
        assert!(matches!(
            timing.spent_setup(start + SECOND),
            Some(PeerEnd::SetupCutoff(SetupStage::Retirement))
        ));
        assert!(matches!(
            timing.expire(start + SECOND),
            Some(EndCause::Cutoff {
                limit: Limit::Hard,
                ..
            })
        ));
    }

    /// A waiter's outcome, its reservation and when it returned.
    type Waited = (&'static str, Option<PeerReservation>, Instant);

    /// Runs `wait_reserve` on another thread and returns its outcome; the
    /// cancellation predicate signals `waiting` once the call has waited.
    fn waiter(
        slot: &PeerSlot,
        until: Instant,
        cancel: Arc<AtomicBool>,
    ) -> (mpsc::Receiver<()>, std::thread::JoinHandle<Waited>) {
        let (waiting, waited) = mpsc::sync_channel(1);
        let slot = slot.clone();
        let handle = std::thread::spawn(move || {
            let calls = AtomicUsize::new(0);
            let cancelled = || {
                if calls.fetch_add(1, Ordering::Relaxed) == 1 {
                    let _ = waiting.try_send(());
                }
                cancel.load(Ordering::Acquire)
            };
            let outcome = match slot.wait_reserve(until, &cancelled) {
                Reserve::Reserved(reservation) => ("reserved", Some(reservation)),
                Reserve::Cancelled => ("cancelled", None),
                Reserve::Deadline => ("deadline", None),
            };
            (outcome.0, outcome.1, Instant::now())
        });
        (waited, handle)
    }

    #[test]
    fn managed_scheduler_retirement_wait_is_cancellable_before_reservation() {
        let slot = PeerSlot::default();
        let held = slot.try_reserve().unwrap();
        // Cancelled while waiting, long before its setup deadline and while
        // the first reservation is still held.
        let cancel = Arc::new(AtomicBool::new(false));
        let (waited, handle) = waiter(&slot, Instant::now() + 20 * SECOND, Arc::clone(&cancel));
        waited.recv_timeout(10 * SECOND).unwrap();
        let cancelled_at = Instant::now();
        cancel.store(true, Ordering::Release);
        let (outcome, reservation, returned) = handle.join().unwrap();
        assert_eq!(outcome, "cancelled");
        assert!(reservation.is_none());
        assert!(returned.saturating_duration_since(cancelled_at) < 2 * SECOND);
        assert!(
            slot.try_reserve().is_err(),
            "the first owner still holds it"
        );
        // A short deadline with the slot still held: no reservation.
        let (_, handle) = waiter(
            &slot,
            Instant::now() + 50 * MS,
            Arc::new(AtomicBool::new(false)),
        );
        let (outcome, reservation, _) = handle.join().unwrap();
        assert_eq!(outcome, "deadline");
        assert!(reservation.is_none());
        // Released afterwards: nothing was reserved late; a new live caller
        // reserves it.
        drop(held);
        assert!(slot.try_reserve().is_ok());
        let (_, handle) = waiter(
            &slot,
            Instant::now() + SECOND,
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(handle.join().unwrap().0, "reserved");
    }

    #[test]
    fn managed_scheduler_wait_reserve_boundaries() {
        let slot = PeerSlot::default();
        // A free slot with a pre-cancelled token, and at its deadline.
        let cancelled = || true;
        assert!(matches!(
            slot.wait_reserve(Instant::now() + SECOND, &cancelled),
            Reserve::Cancelled
        ));
        let live = || false;
        assert!(matches!(
            slot.wait_reserve(Instant::now(), &live),
            Reserve::Deadline
        ));
        assert!(slot.try_reserve().is_ok(), "neither reserved the slot");
        // A normal release wakes a waiting live caller.
        let held = slot.try_reserve().unwrap();
        let (waited, handle) = waiter(
            &slot,
            Instant::now() + 20 * SECOND,
            Arc::new(AtomicBool::new(false)),
        );
        waited.recv_timeout(10 * SECOND).unwrap();
        let released = Instant::now();
        drop(held);
        let (outcome, reservation, returned) = handle.join().unwrap();
        assert_eq!(outcome, "reserved");
        assert!(reservation.is_some());
        assert!(returned.saturating_duration_since(released) < 2 * SECOND);
        // The desktop's busy path returns at once.
        let tried = Instant::now();
        assert!(slot.try_reserve().is_err());
        assert!(tried.elapsed() < SECOND);
        drop(reservation);
    }
}
