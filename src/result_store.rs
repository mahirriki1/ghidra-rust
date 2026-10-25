//! Bounded in-memory store of immutable, validated per-function results.
//!
//! Each payload is charged by allocation capacity when it is admitted and the
//! charge is released only when its last owner drops. Views, save jobs, and
//! other snapshots therefore keep evicted or invalidated payloads charged, and
//! repeated snapshots of one payload never count twice or bypass the budget.
//! Only reconstructible analysis is stored; annotations never enter the store.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Retained-result allocation budget: function payloads, their prepared
/// presentation data, keys, bookkeeping, and the shared discovery publication.
/// This bounds the store, not total desktop memory.
pub const RESULT_STORE_BUDGET: usize = 64 * 1024 * 1024;

/// Fixed bookkeeping charged per stored component: the index slot, the shared
/// allocation header, and its key.
const COMPONENT_OVERHEAD: usize = 256;

/// Allocation bytes a value retains, including its own size. `None` means the
/// count overflowed; such a value can never be admitted.
pub trait Retained {
    fn retained_bytes(&self) -> Option<usize>;
}

/// Checked allocation-capacity accumulator.
#[derive(Clone, Copy, Debug)]
pub struct Bytes(Option<usize>);

impl Bytes {
    pub fn of<T>() -> Self {
        Self(Some(size_of::<T>()))
    }

    pub fn plus(self, bytes: usize) -> Self {
        Self(self.0.and_then(|total| total.checked_add(bytes)))
    }

    /// Adds another checked count; an overflowed count stays overflowed.
    pub fn add_total(self, other: Option<usize>) -> Self {
        match other {
            Some(bytes) => self.plus(bytes),
            None => Self(None),
        }
    }

    /// Backing storage of `capacity` elements, excluding their heap data.
    pub fn slots<T>(self, capacity: usize) -> Self {
        match capacity.checked_mul(size_of::<T>()) {
            Some(bytes) => self.plus(bytes),
            None => Self(None),
        }
    }

    pub fn total(self) -> Option<usize> {
        self.0
    }
}

#[derive(Default)]
struct Ledger {
    charged: AtomicUsize,
}

impl Ledger {
    fn charged(&self) -> usize {
        self.charged.load(Ordering::Acquire)
    }
}

/// One immutable payload and its allocation charge.
pub struct Stored<T> {
    value: T,
    bytes: usize,
    ledger: Arc<Ledger>,
}

impl<T> Stored<T> {
    fn charge(value: T, bytes: usize, ledger: &Arc<Ledger>) -> Arc<Self> {
        ledger.charged.fetch_add(bytes, Ordering::AcqRel);
        Arc::new(Self {
            value,
            bytes,
            ledger: ledger.clone(),
        })
    }

    /// Bytes charged for this payload while any owner retains it.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl<T> Deref for Stored<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T> Drop for Stored<T> {
    fn drop(&mut self) {
        self.ledger.charged.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub type Shared<T> = Arc<Stored<T>>;

/// Every program-wide input that can change engine output. A change to any
/// field makes all stored function results unreachable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramContext {
    pub binary_sha256: String,
    pub engine_fingerprint: &'static str,
    pub signature_fingerprint: &'static str,
    /// Digest of the complete committed signature state, including records
    /// the engine could not apply.
    pub signature_state: String,
    /// Advances whenever the analyzed function inventory changes.
    pub inventory_state: u64,
    /// Advances whenever a function name replayed to the engine changes.
    pub function_name_state: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionKey {
    pub context: Arc<ProgramContext>,
    pub address: u64,
}

/// Decompiled output also depends on that function's local-name overrides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecompileKey {
    pub function: FunctionKey,
    pub local_override_state: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultOrigin {
    Computed,
    /// Restored from a project; provenance stays visible until recomputed.
    Saved,
}

/// What admission did with a payload. Both carry a displayable result.
pub enum Admission<T> {
    Stored(Shared<T>),
    /// The budget, a context change, or an uncountable size prevented storage.
    /// The payload is charged to the single uncached-current slot instead.
    Uncached(Shared<T>),
}

impl<T> Admission<T> {
    pub fn into_shared(self) -> Shared<T> {
        match self {
            Self::Stored(value) | Self::Uncached(value) => value,
        }
    }

    pub fn stored(&self) -> bool {
        matches!(self, Self::Stored(_))
    }
}

struct Component<T> {
    value: Shared<T>,
    origin: ResultOrigin,
}

impl<T> Component<T> {
    fn pinned(&self) -> bool {
        Arc::strong_count(&self.value) > 1
    }
}

struct Record<G, D> {
    graph: Option<Component<G>>,
    decompiled: Option<(String, Component<D>)>,
    used: u64,
}

impl<G, D> Record<G, D> {
    fn indexed(&self) -> (usize, usize) {
        let mut total = 0;
        let mut pinned = 0;
        if let Some(graph) = &self.graph {
            total += graph.value.bytes;
            pinned += if graph.pinned() { graph.value.bytes } else { 0 };
        }
        if let Some((_, code)) = &self.decompiled {
            total += code.value.bytes;
            pinned += if code.pinned() { code.value.bytes } else { 0 };
        }
        (total, pinned)
    }

    /// Drops components no snapshot retains; returns the bytes released.
    fn evict_unpinned(&mut self) -> usize {
        let mut released = 0;
        if self.graph.as_ref().is_some_and(|graph| !graph.pinned()) {
            released += self.graph.take().map_or(0, |graph| graph.value.bytes);
        }
        if self
            .decompiled
            .as_ref()
            .is_some_and(|(_, code)| !code.pinned())
        {
            released += self
                .decompiled
                .take()
                .map_or(0, |(_, code)| code.value.bytes);
        }
        released
    }

    fn is_empty(&self) -> bool {
        self.graph.is_none() && self.decompiled.is_none()
    }
}

/// Stored components for one exact key. Missing components must be computed.
pub struct Hit<G, D> {
    pub graph: Option<(Shared<G>, ResultOrigin)>,
    pub decompiled: Option<(Shared<D>, ResultOrigin)>,
}

/// Cumulative store events, for measurement only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreCounters {
    pub admitted: u64,
    pub uncached: u64,
    pub evicted: u64,
    pub evicted_bytes: u64,
    pub invalidated: u64,
}

/// Point-in-time accounting, for measurement only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreUsage {
    pub budget: usize,
    /// Every live admitted allocation, indexed or not.
    pub charged: usize,
    pub indexed: usize,
    /// Charged bytes that eviction cannot release because a snapshot or
    /// another owner retains them.
    pub pinned: usize,
    pub uncached: usize,
    pub records: usize,
}

pub struct ResultStore<G, D> {
    context: Option<Arc<ProgramContext>>,
    records: HashMap<u64, Record<G, D>>,
    ledger: Arc<Ledger>,
    uncached: Arc<Ledger>,
    budget: usize,
    clock: u64,
    counters: StoreCounters,
}

impl<G: Retained, D: Retained> ResultStore<G, D> {
    pub fn new(budget: usize) -> Self {
        Self {
            context: None,
            records: HashMap::new(),
            ledger: Arc::default(),
            uncached: Arc::default(),
            budget,
            clock: 0,
            counters: StoreCounters::default(),
        }
    }

    pub fn context(&self) -> Option<&Arc<ProgramContext>> {
        self.context.as_ref()
    }

    /// Adopts the current program context. Results from any other context
    /// become unreachable and are dropped. Returns whether it changed.
    pub fn set_context(&mut self, context: Arc<ProgramContext>) -> bool {
        if self.context.as_ref() == Some(&context) {
            return false;
        }
        self.invalidate_all();
        self.context = Some(context);
        true
    }

    /// Drops every stored result and the context, as for a closed binary.
    pub fn clear(&mut self) {
        self.invalidate_all();
        self.context = None;
    }

    fn invalidate_all(&mut self) {
        self.counters.invalidated += self.records.len() as u64;
        self.records.clear();
    }

    /// The exact stored components; marks them most recently used.
    pub fn lookup(&mut self, key: &FunctionKey, local_override_state: &str) -> Hit<G, D> {
        let mut hit = Hit {
            graph: None,
            decompiled: None,
        };
        if self.context.as_ref() != Some(&key.context) {
            return hit;
        }
        self.clock += 1;
        if let Some(record) = self.records.get_mut(&key.address) {
            record.used = self.clock;
            hit.graph = record
                .graph
                .as_ref()
                .map(|graph| (graph.value.clone(), graph.origin));
            hit.decompiled = record
                .decompiled
                .as_ref()
                .filter(|(state, _)| state == local_override_state)
                .map(|(_, code)| (code.value.clone(), code.origin));
        }
        hit
    }

    /// Stores a graph/listing result, replacing any graph for the address.
    pub fn admit_graph(
        &mut self,
        key: &FunctionKey,
        value: G,
        origin: ResultOrigin,
        protect: Option<u64>,
    ) -> Admission<G> {
        let Some(bytes) = self.admission_bytes(&key.context, &value, 0) else {
            return Admission::Uncached(self.uncached_slot(value));
        };
        if let Some(record) = self.records.get_mut(&key.address) {
            record.graph = None;
        }
        if !self.make_room(bytes, &[key.address, protect.unwrap_or(key.address)]) {
            return Admission::Uncached(self.uncached_slot(value));
        }
        let shared = Stored::charge(value, bytes, &self.ledger);
        self.record(key.address).graph = Some(Component {
            value: shared.clone(),
            origin,
        });
        self.counters.admitted += 1;
        Admission::Stored(shared)
    }

    /// Stores one indivisible decompilation (text, mappings, semantics and
    /// prototype together) for its exact local-override state.
    pub fn admit_decompilation(
        &mut self,
        key: &DecompileKey,
        value: D,
        origin: ResultOrigin,
        protect: Option<u64>,
    ) -> Admission<D> {
        let address = key.function.address;
        let state = key.local_override_state.len();
        let Some(bytes) = self.admission_bytes(&key.function.context, &value, state) else {
            return Admission::Uncached(self.uncached_slot(value));
        };
        if let Some(record) = self.records.get_mut(&address) {
            record.decompiled = None;
        }
        if !self.make_room(bytes, &[address, protect.unwrap_or(address)]) {
            return Admission::Uncached(self.uncached_slot(value));
        }
        let shared = Stored::charge(value, bytes, &self.ledger);
        self.record(address).decompiled = Some((
            key.local_override_state.clone(),
            Component {
                value: shared.clone(),
                origin,
            },
        ));
        self.counters.admitted += 1;
        Admission::Stored(shared)
    }

    /// Charges a non-evictable shared allocation, such as the committed
    /// discovery publication, after making room by evicting function results.
    /// It is always kept: dropping it could misreport reference coverage.
    pub fn charge_retained<T: Retained>(&mut self, value: T, protect: &[u64]) -> Shared<T> {
        let bytes = value.retained_bytes().unwrap_or(usize::MAX / 4);
        self.make_room(bytes, protect);
        Stored::charge(value, bytes, &self.ledger)
    }

    /// Refresh: both components of one function are recomputed.
    pub fn invalidate(&mut self, address: u64) {
        if self.records.remove(&address).is_some() {
            self.counters.invalidated += 1;
        }
    }

    /// A local-name edit: only that function's decompilation is recomputed.
    pub fn invalidate_decompilation(&mut self, address: u64) {
        if let Some(record) = self.records.get_mut(&address)
            && record.decompiled.take().is_some()
        {
            self.counters.invalidated += 1;
            if record.is_empty() {
                self.records.remove(&address);
            }
        }
    }

    pub fn counters(&self) -> StoreCounters {
        self.counters
    }

    pub fn usage(&self) -> StoreUsage {
        let (indexed, indexed_pinned) =
            self.records
                .values()
                .fold((0usize, 0usize), |(total, pinned), record| {
                    let (bytes, held) = record.indexed();
                    (total.saturating_add(bytes), pinned.saturating_add(held))
                });
        let charged = self.ledger.charged();
        StoreUsage {
            budget: self.budget,
            charged,
            indexed,
            pinned: charged
                .saturating_sub(indexed)
                .saturating_add(indexed_pinned),
            uncached: self.uncached.charged(),
            records: self.records.len(),
        }
    }

    fn admission_bytes(
        &self,
        context: &Arc<ProgramContext>,
        value: &impl Retained,
        key_bytes: usize,
    ) -> Option<usize> {
        if self.context.as_ref() != Some(context) {
            return None;
        }
        value
            .retained_bytes()?
            .checked_add(COMPONENT_OVERHEAD)?
            .checked_add(key_bytes)
            .filter(|&bytes| bytes <= self.budget)
    }

    /// Evicts least recently used, unprotected, unpinned components until
    /// `bytes` more fit. Pinned components stay: evicting them frees nothing.
    fn make_room(&mut self, bytes: usize, protect: &[u64]) -> bool {
        loop {
            let charged = self.ledger.charged();
            if charged
                .checked_add(bytes)
                .is_some_and(|total| total <= self.budget)
            {
                return true;
            }
            let victim = self
                .records
                .iter()
                .filter(|(address, record)| {
                    !protect.contains(address)
                        && (record.graph.as_ref().is_some_and(|graph| !graph.pinned())
                            || record
                                .decompiled
                                .as_ref()
                                .is_some_and(|(_, code)| !code.pinned()))
                })
                .min_by_key(|(_, record)| record.used)
                .map(|(&address, _)| address);
            let Some(address) = victim else {
                return false;
            };
            let record = self.records.get_mut(&address).expect("victim exists");
            let released = record.evict_unpinned();
            self.counters.evicted += 1;
            self.counters.evicted_bytes += released as u64;
            if record.is_empty() {
                self.records.remove(&address);
            }
        }
    }

    fn uncached_slot<T: Retained>(&mut self, value: T) -> Shared<T> {
        self.counters.uncached += 1;
        let bytes = value.retained_bytes().unwrap_or(0);
        Stored::charge(value, bytes, &self.uncached)
    }

    fn record(&mut self, address: u64) -> &mut Record<G, D> {
        self.clock += 1;
        let used = self.clock;
        let record = self.records.entry(address).or_insert(Record {
            graph: None,
            decompiled: None,
            used,
        });
        record.used = used;
        record
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Blob(usize);
    impl Retained for Blob {
        fn retained_bytes(&self) -> Option<usize> {
            Some(self.0)
        }
    }

    type Store = ResultStore<Blob, Blob>;

    fn context(signature_state: &str) -> Arc<ProgramContext> {
        Arc::new(ProgramContext {
            binary_sha256: "a".repeat(64),
            engine_fingerprint: "engine",
            signature_fingerprint: "signatures",
            signature_state: signature_state.into(),
            inventory_state: 0,
            function_name_state: 0,
        })
    }

    fn key(context: &Arc<ProgramContext>, address: u64) -> FunctionKey {
        FunctionKey {
            context: context.clone(),
            address,
        }
    }

    fn code_key(context: &Arc<ProgramContext>, address: u64, locals: &str) -> DecompileKey {
        DecompileKey {
            function: key(context, address),
            local_override_state: locals.into(),
        }
    }

    const UNIT: usize = 1000;
    fn unit() -> usize {
        UNIT + COMPONENT_OVERHEAD
    }

    #[test]
    fn hits_require_the_exact_context_and_local_override_state() {
        let mut store = Store::new(RESULT_STORE_BUDGET);
        let current = context("one");
        store.set_context(current.clone());
        assert!(
            store
                .admit_graph(
                    &key(&current, 0x10),
                    Blob(UNIT),
                    ResultOrigin::Computed,
                    None
                )
                .stored()
        );
        assert!(
            store
                .admit_decompilation(
                    &code_key(&current, 0x10, "locals-a"),
                    Blob(UNIT),
                    ResultOrigin::Saved,
                    None,
                )
                .stored()
        );
        let hit = store.lookup(&key(&current, 0x10), "locals-a");
        assert!(hit.graph.is_some());
        assert_eq!(hit.decompiled.map(|code| code.1), Some(ResultOrigin::Saved));
        // A different local-override state is a partial hit, never stale text.
        let partial = store.lookup(&key(&current, 0x10), "locals-b");
        assert!(partial.graph.is_some() && partial.decompiled.is_none());
        drop((hit.graph, partial));
        // A structurally equal but separately built context still matches.
        assert!(
            store
                .lookup(&key(&context("one"), 0x10), "locals-a")
                .graph
                .is_some()
        );
        assert!(
            store
                .lookup(&key(&context("two"), 0x10), "locals-a")
                .graph
                .is_none()
        );
        // Results computed under another context are never admitted.
        let stale = context("old");
        assert!(
            !store
                .admit_graph(&key(&stale, 0x20), Blob(UNIT), ResultOrigin::Computed, None)
                .stored()
        );
        assert!(store.set_context(context("two")));
        assert!(
            store
                .lookup(&key(&context("two"), 0x10), "locals-a")
                .graph
                .is_none()
        );
        assert_eq!(store.usage().charged, 0);
    }

    #[test]
    fn eviction_is_lru_and_never_exceeds_the_budget_with_snapshots() {
        let mut store = Store::new(unit() * 3);
        let current = context("");
        store.set_context(current.clone());
        for address in 1..=3 {
            store.admit_graph(
                &key(&current, address),
                Blob(UNIT),
                ResultOrigin::Computed,
                None,
            );
        }
        // Touch 1 so 2 is the least recently used.
        store.lookup(&key(&current, 1), "");
        // A snapshot of 3 pins it; repeated snapshots do not add charges.
        let pinned = store.lookup(&key(&current, 3), "").graph.unwrap().0;
        let again = store.lookup(&key(&current, 3), "").graph.unwrap().0;
        assert_eq!(store.usage().charged, unit() * 3);
        store.admit_graph(&key(&current, 4), Blob(UNIT), ResultOrigin::Computed, None);
        assert!(store.lookup(&key(&current, 2), "").graph.is_none());
        assert!(store.lookup(&key(&current, 1), "").graph.is_some());
        assert!(store.usage().charged <= store.usage().budget);
        // Invalidating a pinned result removes it from the index, but its
        // charge remains until the last snapshot drops.
        store.invalidate(3);
        assert!(store.lookup(&key(&current, 3), "").graph.is_none());
        assert_eq!(store.usage().charged, unit() * 3);
        assert_eq!(store.usage().pinned, unit());
        // With 3 still pinned, admitting two more evicts the unpinned ones
        // rather than exceeding the budget.
        store.admit_graph(&key(&current, 5), Blob(UNIT), ResultOrigin::Computed, None);
        store.admit_graph(&key(&current, 6), Blob(UNIT), ResultOrigin::Computed, None);
        assert!(store.usage().charged <= store.usage().budget);
        drop((pinned, again));
        assert_eq!(store.usage().charged, unit() * 2);
        assert_eq!(store.counters().evicted, 3);
    }

    #[test]
    fn pinned_results_defer_admission_to_the_uncached_slot() {
        let mut store = Store::new(unit() * 2);
        let current = context("");
        store.set_context(current.clone());
        let first = store
            .admit_graph(&key(&current, 1), Blob(UNIT), ResultOrigin::Computed, None)
            .into_shared();
        let second = store
            .admit_graph(&key(&current, 2), Blob(UNIT), ResultOrigin::Computed, None)
            .into_shared();
        let third = store.admit_graph(
            &key(&current, 3),
            Blob(UNIT),
            ResultOrigin::Computed,
            Some(2),
        );
        assert!(!third.stored());
        let usage = store.usage();
        assert_eq!((usage.charged, usage.uncached), (unit() * 2, UNIT));
        drop(third);
        assert_eq!(store.usage().uncached, 0);
        // An oversized payload is displayable but never stored.
        assert!(
            !store
                .admit_graph(
                    &key(&current, 4),
                    Blob(usize::MAX),
                    ResultOrigin::Computed,
                    None
                )
                .stored()
        );
        drop((first, second));
        assert!(
            store
                .admit_graph(&key(&current, 3), Blob(UNIT), ResultOrigin::Computed, None)
                .stored()
        );
    }

    #[test]
    fn local_edits_and_refresh_invalidate_only_their_components() {
        let mut store = Store::new(RESULT_STORE_BUDGET);
        let current = context("");
        store.set_context(current.clone());
        for address in [1, 2] {
            store.admit_graph(
                &key(&current, address),
                Blob(1),
                ResultOrigin::Computed,
                None,
            );
            store.admit_decompilation(
                &code_key(&current, address, ""),
                Blob(1),
                ResultOrigin::Computed,
                None,
            );
        }
        store.invalidate_decompilation(1);
        let one = store.lookup(&key(&current, 1), "");
        assert!(one.graph.is_some() && one.decompiled.is_none());
        let two = store.lookup(&key(&current, 2), "");
        assert!(two.graph.is_some() && two.decompiled.is_some());
        store.invalidate(2);
        let two = store.lookup(&key(&current, 2), "");
        assert!(two.graph.is_none() && two.decompiled.is_none());
        store.clear();
        assert!(store.context().is_none());
        assert!(store.lookup(&key(&current, 1), "").graph.is_none());
    }

    #[test]
    fn retained_discovery_charges_shrink_room_for_function_results() {
        let mut store = Store::new(unit() * 2);
        let current = context("");
        store.set_context(current.clone());
        store.admit_graph(&key(&current, 1), Blob(UNIT), ResultOrigin::Computed, None);
        store.admit_graph(&key(&current, 2), Blob(UNIT), ResultOrigin::Computed, None);
        let publication = store.charge_retained(Blob(unit()), &[2]);
        assert!(store.lookup(&key(&current, 1), "").graph.is_none());
        assert!(store.lookup(&key(&current, 2), "").graph.is_some());
        assert_eq!(store.usage().charged, unit() * 2);
        drop(publication);
        assert_eq!(store.usage().charged, unit());
    }
}
