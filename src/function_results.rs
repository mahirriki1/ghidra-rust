//! Per-function result coordination shared by the desktop and measurement
//! harnesses: program-context identity, exact lookup, admission bound to the
//! request that produced a result, refresh bypass, and miss preparation.
//!
//! Misses run in the existing warm worker, as navigation always has. A stored
//! result therefore reflects the engine knowledge when it was computed, like
//! Ghidra's decompiler cache; Refresh always recomputes. A different miss
//! policy (such as a fresh, canonical engine context) belongs in
//! [`FunctionResults::miss_requests`] alone.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

use sha2::{Digest, Sha256};

use crate::function_presentation::{PreparedDecompilation, PreparedGraph};
use crate::model::{FunctionInfo, Request};
use crate::result_store::{
    Admission, DecompileKey, FunctionKey, ProgramContext, RESULT_STORE_BUDGET, ResultOrigin,
    ResultStore, Retained, Shared, StoreCounters, StoreUsage,
};
use crate::semantic::LocalRename;
use crate::signatures::FunctionSignature;

pub type FunctionStore = ResultStore<PreparedGraph, PreparedDecompilation>;

/// Captured when a function request is sent. A reply is admitted only while
/// its key is still current and the function was not refreshed meanwhile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultBinding {
    pub key: DecompileKey,
    pub refresh: u64,
}

impl ResultBinding {
    pub fn address(&self) -> u64 {
        self.key.function.address
    }
}

/// Stored components for one function; missing ones must be computed.
pub struct FunctionHit {
    pub graph: Option<(Shared<PreparedGraph>, ResultOrigin)>,
    pub decompiled: Option<(Shared<PreparedDecompilation>, ResultOrigin)>,
}

impl FunctionHit {
    pub fn complete(&self, decompile: bool) -> bool {
        self.graph.is_some() && (!decompile || self.decompiled.is_some())
    }
}

/// Why stored results were dropped, for measurement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalidation {
    Refresh = 1,
    LocalNames = 2,
    FunctionNames = 3,
    Inventory = 4,
    Signatures = 5,
    Closed = 6,
}

/// Digest of one function's complete ordered local-name overrides, including
/// records the engine may not apply. Printed names alone are insufficient.
pub fn local_override_state(renames: &[LocalRename], function: u64) -> String {
    let mut records: Vec<_> = renames
        .iter()
        .filter(|rename| rename.identity.function == function)
        .map(|rename| (&rename.identity, &rename.name))
        .collect();
    if records.is_empty() {
        return String::new();
    }
    records.sort();
    let bytes = serde_json::to_vec(&records).expect("Local overrides serialize");
    format!("{:x}", Sha256::digest(bytes))
}

/// Content projections are built only when their inputs change. Neither lookup
/// nor navigation walks the program inventory or all local override records.
struct Inputs {
    functions: Vec<FunctionInfo>,
    locals: Vec<LocalRename>,
}

struct InputState {
    inventory: String,
    names: String,
    locals: BTreeMap<u64, String>,
}

impl Inputs {
    fn preparation_bytes(&self) -> usize {
        let mut bytes = crate::result_store::Bytes::of::<Self>()
            .slots::<FunctionInfo>(self.functions.capacity())
            .slots::<LocalRename>(self.locals.capacity());
        for function in &self.functions {
            bytes = bytes.plus(function.name.capacity());
        }
        for local in &self.locals {
            bytes = bytes
                .plus(local.name.capacity())
                .plus(local.identity.engine.capacity())
                .plus(local.identity.verification.capacity());
        }
        // Temporary grouping/serialization and the completed digest map can
        // coexist with the input iterator backing. Report a conservative bound.
        bytes
            .total()
            .and_then(|bytes| bytes.checked_mul(2))
            .unwrap_or(usize::MAX)
    }

    fn digest(self) -> InputState {
        let _preparation = crate::performance::span("function_result_context_preparation");
        let mut inventory = Sha256::new();
        let mut names = Sha256::new();
        for function in self.functions {
            inventory.update(function.address.to_le_bytes());
            names.update(function.address.to_le_bytes());
            names.update((function.name.len() as u64).to_le_bytes());
            names.update(function.name.as_bytes());
        }
        let mut grouped: BTreeMap<u64, Vec<LocalRename>> = BTreeMap::new();
        for local in self.locals {
            grouped
                .entry(local.identity.function)
                .or_default()
                .push(local);
        }
        InputState {
            inventory: format!("{:x}", inventory.finalize()),
            names: format!("{:x}", names.finalize()),
            locals: grouped
                .into_iter()
                .map(|(function, records)| (function, local_override_state(&records, function)))
                .collect(),
        }
    }
}

pub struct FunctionResults {
    store: FunctionStore,
    binary_sha256: String,
    signature_state: String,
    inventory_state: String,
    function_name_state: String,
    local_states: BTreeMap<u64, String>,
    // Only one request can be in flight. A refresh serial also conservatively
    // rejects a reply if another function was refreshed while it was running.
    refresh: u64,
    input_job: Option<Receiver<(u64, InputState)>>,
    input_epoch: u64,
    next_inputs: Option<Inputs>,
    input_failed: bool,
    preparation_bytes: usize,
}

impl Default for FunctionResults {
    fn default() -> Self {
        Self::new(RESULT_STORE_BUDGET)
    }
}

impl FunctionResults {
    pub fn new(budget: usize) -> Self {
        Self {
            store: ResultStore::new(budget),
            binary_sha256: String::new(),
            signature_state: String::new(),
            inventory_state: String::new(),
            function_name_state: String::new(),
            refresh: 0,
            local_states: BTreeMap::new(),
            input_job: None,
            input_epoch: 0,
            next_inputs: None,
            input_failed: false,
            preparation_bytes: 0,
        }
    }

    /// A newly opened or restored binary with its committed signature state.
    pub fn open(&mut self, binary_sha256: &str, signatures: &[FunctionSignature]) {
        self.store.clear();
        self.refresh = self.refresh.wrapping_add(1);
        self.local_states.clear();
        self.input_epoch = self.input_epoch.wrapping_add(1);
        self.next_inputs = None;
        self.input_failed = false;
        self.binary_sha256 = binary_sha256.into();
        self.signature_state = crate::signatures::state_digest(signatures);
        self.publish_context();
    }

    pub fn close(&mut self) {
        if self.store.context().is_some() {
            crate::performance::event("function_result_invalidation", Invalidation::Closed as u64);
        }
        self.store.clear();
        self.refresh = self.refresh.wrapping_add(1);
        self.local_states.clear();
        self.input_epoch = self.input_epoch.wrapping_add(1);
        self.next_inputs = None;
        self.input_failed = false;
        self.binary_sha256.clear();
    }

    /// The committed signature state changed. Staged states never call this.
    pub fn signatures_committed(&mut self, signatures: &[FunctionSignature]) {
        let state = crate::signatures::state_digest(signatures);
        if state != self.signature_state {
            self.signature_state = state;
            self.changed(Invalidation::Signatures);
        }
    }

    /// Schedules complete content digests off the UI thread. One running job
    /// and one replaceable input slot bound rapid edits; stale jobs never publish.
    pub fn update_inputs(&mut self, functions: Vec<FunctionInfo>, locals: Vec<LocalRename>) {
        self.next_inputs = Some(Inputs { functions, locals });
        self.input_failed = false;
        self.start_inputs();
    }

    fn start_inputs(&mut self) {
        if self.input_job.is_some() {
            return;
        }
        let Some(inputs) = self.next_inputs.take() else {
            return;
        };
        self.preparation_bytes = inputs.preparation_bytes();
        crate::performance::event(
            "result_store_preparation_bytes",
            self.preparation_bytes as u64,
        );
        let (sender, receiver) = mpsc::sync_channel(1);
        let epoch = self.input_epoch;
        match std::thread::Builder::new()
            .name("function-context".into())
            .spawn(move || {
                let _ = sender.send((epoch, inputs.digest()));
            }) {
            Ok(_) => self.input_job = Some(receiver),
            Err(_) => self.input_failed = true,
        }
    }

    pub fn preparing(&self) -> bool {
        self.input_job.is_some() || self.next_inputs.is_some()
    }

    pub fn poll_inputs(&mut self) -> bool {
        let Some(job) = &self.input_job else {
            return false;
        };
        match job.try_recv() {
            Ok((epoch, state)) => {
                self.input_job = None;
                self.preparation_bytes = 0;
                if epoch != self.input_epoch {
                    self.start_inputs();
                    return false;
                }
                if self.next_inputs.is_some() {
                    self.start_inputs();
                    return false;
                }
                // Includes sparse local-state B-tree nodes and context/key
                // bookkeeping. Payloads charge their own allocations separately.
                if !self
                    .store
                    .set_metadata_bytes(4096 + state.locals.len() * 2048)
                {
                    self.input_failed = true;
                    return false;
                }
                self.inventory_state = state.inventory;
                self.function_name_state = state.names;
                self.local_states = state.locals;
                return self.publish_context();
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.input_job = None;
                self.input_failed = true;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        false
    }

    pub fn local_state(&self, address: u64) -> String {
        self.local_states.get(&address).cloned().unwrap_or_default()
    }

    /// Input projection changed; block hits until content digests are ready.
    pub fn inputs_changed(&mut self, reason: Invalidation) {
        crate::performance::event("function_result_invalidation", reason as u64);
        self.refresh = self.refresh.wrapping_add(1);
    }

    fn changed(&mut self, reason: Invalidation) {
        if self.store.context().is_some() {
            crate::performance::event("function_result_invalidation", reason as u64);
            self.publish_context();
        }
    }

    fn publish_context(&mut self) -> bool {
        self.store.set_context(Arc::new(ProgramContext {
            binary_sha256: self.binary_sha256.clone(),
            engine_fingerprint: crate::project::ENGINE_FINGERPRINT,
            signature_fingerprint: crate::signatures::SIGNATURE_FINGERPRINT,
            signature_state: self.signature_state.clone(),
            inventory_state: self.inventory_state.clone(),
            function_name_state: self.function_name_state.clone(),
        }))
    }

    fn key(&self, address: u64) -> Option<FunctionKey> {
        if self.preparing() || self.input_failed {
            return None;
        }
        Some(FunctionKey {
            context: self.store.context()?.clone(),
            address,
        })
    }

    /// The binding for a request about to be sent for `address`.
    pub fn binding(&self, address: u64, local_override_state: String) -> Option<ResultBinding> {
        Some(ResultBinding {
            key: DecompileKey {
                function: self.key(address)?,
                local_override_state,
            },
            refresh: self.refresh,
        })
    }

    pub fn lookup(&mut self, address: u64, local_override_state: &str) -> FunctionHit {
        let lookup = crate::performance::span("function_result_lookup");
        let Some(key) = self.key(address) else {
            lookup.finish(0);
            return FunctionHit {
                graph: None,
                decompiled: None,
            };
        };
        let hit = self.store.lookup(&key, local_override_state);
        lookup.finish(u64::from(hit.graph.is_some()) + u64::from(hit.decompiled.is_some()));
        FunctionHit {
            graph: hit.graph,
            decompiled: hit.decompiled,
        }
    }

    /// Warm-worker miss policy: request each missing component from the
    /// existing worker, which already holds the replayed program context.
    pub fn miss_requests(hit: &FunctionHit, address: u64, decompile: bool) -> Vec<Request> {
        if hit.graph.is_none() {
            crate::performance::event("function_result_miss_graph", address);
            // The graph reply schedules decompilation when it is still missing.
            return vec![Request::Graph { address }];
        }
        if decompile && hit.decompiled.is_none() {
            crate::performance::event("function_result_miss_decompile", address);
            return vec![Request::Decompile { address }];
        }
        Vec::new()
    }

    pub fn current(&self, binding: Option<&ResultBinding>) -> bool {
        binding.is_some_and(|binding| {
            self.store.context() == Some(&binding.key.function.context)
                && !self.preparing()
                && !self.input_failed
                && self.refresh == binding.refresh
        })
    }

    /// Stores a validated graph when its binding is still current; the result
    /// is displayable either way. `protect` is the displayed function.
    pub fn admit_graph(
        &mut self,
        binding: Option<&ResultBinding>,
        graph: PreparedGraph,
        origin: ResultOrigin,
        protect: Option<u64>,
    ) -> Shared<PreparedGraph> {
        let current = self.current(binding);
        let admission = match (current, binding) {
            (true, Some(binding)) => {
                self.store
                    .admit_graph(&binding.key.function, graph, origin, protect)
            }
            _ => self.uncached(graph),
        };
        self.report(admission)
    }

    pub fn admit_decompilation(
        &mut self,
        binding: Option<&ResultBinding>,
        code: PreparedDecompilation,
        origin: ResultOrigin,
        protect: Option<u64>,
    ) -> Shared<PreparedDecompilation> {
        let current = self.current(binding);
        let admission = match (current, binding) {
            (true, Some(binding)) => {
                self.store
                    .admit_decompilation(&binding.key, code, origin, protect)
            }
            _ => self.uncached(code),
        };
        self.report(admission)
    }

    /// Displays without storing, still charged to the uncached-current slot.
    fn uncached<T: Retained>(&mut self, value: T) -> Admission<T> {
        Admission::Uncached(self.store.uncached(value))
    }

    fn report<T>(&self, admission: Admission<T>) -> Shared<T> {
        let usage = self.usage();
        crate::performance::event("function_result_admitted", u64::from(admission.stored()));
        crate::performance::result_store_usage(usage, self.store.counters());
        admission.into_shared()
    }

    /// Refresh bypasses the store: both components are recomputed and any
    /// reply already in flight for this function is no longer storable.
    pub fn refresh(&mut self, address: u64) {
        crate::performance::event("function_result_invalidation", Invalidation::Refresh as u64);
        self.store.invalidate(address);
        self.bump_refresh(address);
    }

    /// Decompiler-only Refresh or a local-name edit in this function.
    pub fn refresh_decompilation(&mut self, address: u64, reason: Invalidation) {
        crate::performance::event("function_result_invalidation", reason as u64);
        self.store.invalidate_decompilation(address);
        self.bump_refresh(address);
    }

    fn bump_refresh(&mut self, _address: u64) {
        self.refresh = self.refresh.wrapping_add(1);
    }

    pub fn usage(&self) -> StoreUsage {
        let mut usage = self.store.usage();
        usage.preparation = self.preparation_bytes.saturating_add(
            self.next_inputs
                .as_ref()
                .map_or(0, Inputs::preparation_bytes),
        );
        usage
    }

    pub fn can_replace_discovery(
        &self,
        new: &Arc<crate::call_analysis::CallIndex>,
        old: &Arc<crate::call_analysis::CallIndex>,
        saved_owner: bool,
        protect: &[u64],
    ) -> bool {
        self.store.can_replace_publication(
            new.snapshot(),
            new,
            (old.snapshot(), old),
            1 + usize::from(saved_owner),
            protect,
        )
    }

    pub fn retain_discovery(
        &mut self,
        index: &Arc<crate::call_analysis::CallIndex>,
        protect: &[u64],
    ) -> bool {
        self.store
            .retain_publication(index.snapshot(), index, protect)
    }

    pub fn counters(&self) -> StoreCounters {
        self.store.counters()
    }
}
