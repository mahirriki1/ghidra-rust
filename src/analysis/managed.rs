//! The private two-phase decompile protocol between a host and its workers.
//!
//! A managed request first publishes the ordinary render (the *baseline*,
//! exactly the render without debug information) and, when debug
//! prototypes may change it, an offer for one optional debug render. The
//! optional render runs either in a disposable fork of the primary worker
//! ([`Executor::ForkHere`], single-threaded Linux workers) or in a fresh
//! single-use sibling worker ([`Executor::Sibling`], Windows and threaded
//! workers) that opens the same verified image, replays the committed names
//! and signatures, recaptures the baseline and proves it identical by digest
//! before any lock. The host owns the managed decisions. A disposable
//! executor seeds its index from the job and returns an uncommitted journal.
//! None of these messages are part of the public headless API.
use super::{DebugOutcome, Published, Unchanged};
use crate::debug_info::{Change, EntryState};
use crate::model::{MAX_GRAPH_CALLS, Response};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Target plus direct callees of one job.
pub(crate) const MAX_JOB_ENTRIES: usize = MAX_GRAPH_CALLS + 1;
/// A SHA-256 digest in lowercase hexadecimal.
const DIGEST_HEX: usize = 64;

/// Which process runs a prepared request's optional debug render.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Executor {
    /// A disposable fork of the primary worker.
    ForkHere,
    /// A fresh single-use worker started by the host.
    Sibling,
}

/// A host logical request and its single-use decision transaction.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub(crate) logical_id: u64,
    pub(crate) nonce: u64,
    pub(crate) book_version: u64,
}

impl Ticket {
    pub(crate) fn valid(self) -> bool {
        self.logical_id != 0 && self.nonce != 0 && self.book_version != 0
    }
}

/// Digests that bind an optional render to its baseline.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    /// Verified image and effective program state, independent of the function.
    #[serde(deserialize_with = "crate::bounded::string::<_, DIGEST_HEX>")]
    pub(crate) program: String,
    /// The program context, entry and exact local overrides.
    #[serde(deserialize_with = "crate::bounded::string::<_, DIGEST_HEX>")]
    pub(crate) context: String,
    /// Address, publishable text, mappings, semantics and observed calls.
    #[serde(deserialize_with = "crate::bounded::string::<_, DIGEST_HEX>")]
    pub(crate) baseline: String,
    /// The reference render's normalized caller evidence.
    #[serde(deserialize_with = "crate::bounded::string::<_, DIGEST_HEX>")]
    pub(crate) facts: String,
}

/// A prepared request's optional debug work, from the primary.
#[doc(hidden)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DebugOffer {
    /// The host's logical request.
    pub(crate) logical_id: u64,
    /// Fresh per Open, consumed by at most one Try.
    pub(crate) nonce: u64,
    pub(crate) executor: Executor,
    /// The reference render's own duration.
    pub(crate) reference_us: u64,
    /// From the worker's receipt of the request to the reference's end.
    pub(crate) elapsed_us: u64,
    pub(crate) binding: Binding,
    /// Every direct call the reference observed, sorted.
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
    pub(crate) calls: Vec<u64>,
    /// Whether the target's own debug prototype may be probed or installed.
    pub(crate) target_work: bool,
    pub(crate) graph_prepared: bool,
    /// Eligible direct callees, sorted; a subset of `calls`.
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
    pub(crate) callees: Vec<u64>,
    /// The effective program state allows verified result reuse.
    pub(crate) cacheable: bool,
}

/// Sparse decisions scoped to the indexed entries in one offer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Seed {
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_JOB_ENTRIES>")]
    pub(crate) states: Vec<(u64, EntryState)>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
    pub(crate) large: Vec<u64>,
}

impl Seed {
    pub(crate) fn state(&self, entry: u64) -> EntryState {
        self.states
            .binary_search_by_key(&entry, |&(key, _)| key)
            .map_or_else(|_| EntryState::default(), |index| self.states[index].1)
    }

    pub(crate) fn target_eligible(&self, entry: u64) -> bool {
        use crate::debug_info::{Decision, MAX_PROBE_ATTEMPTS};
        let state = self.state(entry);
        match state.decision() {
            Decision::Accepted => true,
            Decision::Undecided => state.target_attempts < MAX_PROBE_ATTEMPTS,
            _ => false,
        }
    }

    pub(crate) fn callee_eligible(&self, entry: u64) -> bool {
        use crate::debug_info::{Decision, MAX_PROBE_ATTEMPTS};
        let state = self.state(entry);
        match state.decision() {
            Decision::Accepted => true,
            Decision::Undecided => {
                state.callee_attempts < MAX_PROBE_ATTEMPTS
                    && self.large.binary_search(&entry).is_err()
            }
            _ => false,
        }
    }
}

/// One optional debug render in a disposable executor.
#[doc(hidden)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerJob {
    pub(crate) ticket: Ticket,
    pub(crate) address: u64,
    pub(crate) remaining_ms: u64,
    #[serde(
        deserialize_with = "crate::bounded::vec::<_, _, { crate::semantic::MAX_FUNCTION_RENAMES }>"
    )]
    pub(crate) renames: Vec<crate::semantic::LocalRename>,
    pub(crate) binding: Binding,
    pub(crate) target_work: bool,
    pub(crate) graph_prepared: bool,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
    pub(crate) callees: Vec<u64>,
    pub(crate) seed: Seed,
}

impl PeerJob {
    /// Structural checks shared by the host and the sibling.
    pub(crate) fn check(&self) -> Result<(), String> {
        let sorted = |values: &[u64]| values.windows(2).all(|pair| pair[0] < pair[1]);
        if !self.ticket.valid()
            || self.remaining_ms == 0
            || self.remaining_ms > crate::model::WORKER_REQUEST_TIMEOUT.as_millis() as u64
            || [
                &self.binding.program,
                &self.binding.context,
                &self.binding.baseline,
                &self.binding.facts,
            ]
            .into_iter()
            .any(|digest| !crate::search::valid_digest(digest))
            || !sorted(&self.callees)
            || self.callees.contains(&self.address)
            || !sorted(&self.seed.large)
            || self.seed.large.contains(&self.address)
            || !self
                .seed
                .states
                .windows(2)
                .all(|pair| pair[0].0 < pair[1].0)
            || self.seed.states.iter().any(|(_, state)| {
                *state == EntryState::default() || !EntryState::default().allows(state)
            })
            || (self.target_work && !self.seed.target_eligible(self.address))
            || self
                .callees
                .iter()
                .any(|&entry| !self.seed.callee_eligible(entry))
            || (!self.target_work && self.callees.is_empty())
        {
            return Err("Malformed debug job".into());
        }
        crate::semantic::validate_renames(&self.renames, Some(self.address))
    }
}

/// [`DebugOutcome`] of a sibling, as the sibling reports it.
#[doc(hidden)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PeerOutcome(pub(crate) DebugOutcome);

/// A debug render's outcome without its rendered body: what the primary
/// needs to check and commit a sibling's decisions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Report {
    Candidate {
        /// The candidate render's direct calls, sorted.
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
        calls: Vec<u64>,
        target_owns: bool,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
        installed_callees: Vec<u64>,
        compared: bool,
        vetoed: bool,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_JOB_ENTRIES>")]
        changes: Vec<Change>,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
        large: Vec<u64>,
    },
    UseReference {
        reason: Unchanged,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_JOB_ENTRIES>")]
        changes: Vec<Change>,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
        large: Vec<u64>,
    },
    Failed {
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_JOB_ENTRIES>")]
        changes: Vec<Change>,
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_GRAPH_CALLS>")]
        large: Vec<u64>,
    },
}

impl Report {
    pub(crate) fn decisions(&self) -> (&[Change], &[u64]) {
        match self {
            Self::Candidate { changes, large, .. }
            | Self::UseReference { changes, large, .. }
            | Self::Failed { changes, large } => (changes, large),
        }
    }
}

pub(crate) fn unavailable(ticket: Ticket, reason: &str) -> Response {
    Response::DebugUnavailable {
        ticket,
        reason: reason.into(),
    }
}

impl DebugOutcome {
    /// The outcome's report, and the candidate's render if any.
    pub(crate) fn split(self) -> (Report, Option<Box<Published>>) {
        match self {
            DebugOutcome::Candidate {
                render,
                target_owns,
                installed_callees,
                compared,
                vetoed,
                changes,
                large,
            } => (
                Report::Candidate {
                    calls: render.calls.clone(),
                    target_owns,
                    installed_callees,
                    compared,
                    vetoed,
                    changes,
                    large,
                },
                Some(render),
            ),
            DebugOutcome::UseReference {
                reason,
                changes,
                large,
            } => (
                Report::UseReference {
                    reason,
                    changes,
                    large,
                },
                None,
            ),
            DebugOutcome::Failed { changes, large } => (Report::Failed { changes, large }, None),
        }
    }
}

/// The primary's retained single-use fork preparation.
pub(crate) struct Pending {
    pub(crate) offer: DebugOffer,
    pub(crate) job: super::PreparedJob,
}

/// Domain-separated SHA-256 over length-prefixed fields.
struct Hasher(Sha256);
impl Hasher {
    fn new(domain: &str) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.bytes(domain.as_bytes());
        hasher
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
    }
    fn json(&mut self, value: &impl Serialize) {
        // Every hashed value is a struct or sequence; serde_json writes
        // fields in declaration order and sequences in order.
        struct DigestWriter<'a>(&'a mut Sha256);
        impl std::io::Write for DigestWriter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // JSON cannot contain a raw NUL; use it to delimit its streamed
        // representation without allocating a copy of mappings or tokens.
        self.0.update(b"\0json\0");
        serde_json::to_writer(DigestWriter(&mut self.0), value)
            .expect("serializable digest inputs");
        self.0.update(b"\0");
    }
    fn finish(self) -> String {
        self.0
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Digest of a publishable baseline: entry, clipped text, mappings,
/// semantics (engine and local warnings included, before any debug warning)
/// and the sorted observed calls.
pub(crate) fn baseline_digest(
    address: u64,
    text: &str,
    mappings: &[crate::model::CodeMapping],
    semantics: &crate::semantic::SemanticInfo,
    calls: &[u64],
) -> String {
    let mut hasher = Hasher::new("ghidra-rust/managed-baseline/v1");
    hasher.bytes(&address.to_le_bytes());
    hasher.bytes(text.as_bytes());
    hasher.json(&mappings);
    hasher.json(semantics);
    hasher.json(&calls);
    hasher.finish()
}

/// Digest of a reference render's normalized caller evidence; empty
/// evidence (no capture) has its own digest.
pub(crate) fn facts_digest(facts: Option<&crate::debug_info::caller::Facts>) -> String {
    let mut hasher = Hasher::new("ghidra-rust/managed-facts/v1");
    match facts {
        Some(facts) => {
            // Independent storage is a set. Engine varnode order may vary
            // across otherwise equivalent renders. Formal and operand order
            // affect the audit, and sites are already sorted by exact PC.
            let mut independent = facts.independent.clone();
            independent.sort_unstable();
            independent.dedup();
            hasher.bytes(b"some");
            hasher.json(&facts.complete);
            hasher.json(&facts.formals);
            hasher.json(&independent);
            hasher.json(&facts.sites);
        }
        None => hasher.bytes(b"none"),
    }
    hasher.finish()
}

pub(crate) fn inventory_digest(functions: &[crate::model::FunctionInfo]) -> String {
    let mut hasher = Hasher::new("ghidra-rust/managed-inventory/v1");
    hasher.json(&functions);
    hasher.finish()
}

/// Digest of the decision-independent program state a sibling must reproduce.
#[allow(clippy::too_many_arguments)]
pub(crate) fn program_digest(
    info: &crate::model::BinaryInfo,
    language: &str,
    inventory: &str,
    debug: Option<&crate::debug_info::DebugSummary>,
    skipped: &std::collections::BTreeSet<u64>,
    signature_context: &str,
    applied: &std::collections::BTreeSet<u64>,
    long_names: &std::collections::BTreeMap<u64, String>,
) -> String {
    let mut hasher = Hasher::new("ghidra-rust/managed-program/v1");
    hasher.bytes(info.sha256.as_bytes());
    hasher.bytes(&info.file_len.to_le_bytes());
    hasher.json(&info.source_identity);
    hasher.bytes(info.format.as_bytes());
    hasher.bytes(language.as_bytes());
    hasher.bytes(inventory.as_bytes());
    hasher.json(skipped);
    match debug {
        Some(summary) => {
            hasher.bytes(summary.state.as_bytes());
            match &summary.source {
                Some(source) => {
                    hasher.bytes(source.uuid.as_bytes());
                    hasher.bytes(source.sha256.as_bytes());
                    hasher.json(&source.identity);
                }
                None => hasher.bytes(b"embedded"),
            }
        }
        None => hasher.bytes(b"no-debug"),
    }
    hasher.bytes(signature_context.as_bytes());
    hasher.json(applied);
    hasher.json(long_names);
    hasher.finish()
}

pub(crate) fn context_digest(
    program: &str,
    address: u64,
    renames: &[crate::semantic::LocalRename],
) -> String {
    let mut hasher = Hasher::new("ghidra-rust/managed-context/v3");
    hasher.bytes(program.as_bytes());
    hasher.bytes(&address.to_le_bytes());
    hasher.json(&renames);
    hasher.finish()
}

/// A sibling's measured digests and outcome (`DebugFinished`).
pub(crate) fn finished(ticket: Ticket, measured: Binding, outcome: DebugOutcome) -> Response {
    Response::DebugFinished {
        ticket,
        measured,
        outcome: PeerOutcome(outcome),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::debug_info::caller::{Facts, Space, Storage};

    #[test]
    fn managed_debug_evidence_digest_normalizes_only_the_unordered_storage() {
        let register = Storage {
            space: Space::Register,
            offset: 8,
            size: 8,
        };
        let stack = Storage {
            space: Space::Stack,
            offset: 32,
            size: 8,
        };
        let first = Facts {
            complete: true,
            independent: vec![register, stack],
            ..Facts::default()
        };
        let mut second = Facts {
            independent: vec![stack, register, register],
            ..first.clone()
        };
        assert_eq!(facts_digest(Some(&first)), facts_digest(Some(&second)));
        second.independent.remove(0);
        assert_ne!(facts_digest(Some(&first)), facts_digest(Some(&second)));
        assert_ne!(facts_digest(Some(&Facts::default())), facts_digest(None));
    }
}
