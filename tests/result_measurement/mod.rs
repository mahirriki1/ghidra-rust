//! Shared Linux/Windows hooks for production store lookup and prepared adoption.
use ghidra_rust::function_presentation::{PreparedDecompilation, PreparedGraph};
use ghidra_rust::function_results::FunctionResults;
use ghidra_rust::graph::GraphCanvas;
use ghidra_rust::model::{BinaryInfo, FunctionView, Response};
use ghidra_rust::result_store::ResultOrigin;
use ghidra_rust::selection::SemanticSelection;
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub struct CachedResults {
    pub results: FunctionResults,
}
impl CachedResults {
    pub fn new(info: &BinaryInfo) -> Self {
        let mut results = FunctionResults::default();
        results.open(&info.sha256, &[]);
        results.update_inputs(info.functions.clone(), vec![]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while results.preparing() {
            assert!(Instant::now() < deadline);
            results.poll_inputs();
            std::thread::yield_now();
        }
        Self { results }
    }
    pub fn admit(&mut self, info: &BinaryInfo, view: FunctionView, response: Response) {
        let address = view.address;
        let binding = self.results.binding(address, String::new()).unwrap();
        self.results.admit_graph(
            Some(&binding),
            PreparedGraph::validate(view, info).unwrap(),
            ResultOrigin::Computed,
            Some(address),
        );
        let Response::Decompiled {
            address: returned,
            text,
            mappings,
            semantics,
        } = response
        else {
            panic!("Expected decompilation");
        };
        assert_eq!(address, returned);
        semantics.validate(&text, address, &info.sections).unwrap();
        let code =
            PreparedDecompilation::validate(address, text, mappings, semantics, &info.sections)
                .unwrap();
        self.results.admit_decompilation(
            Some(&binding),
            code,
            ResultOrigin::Computed,
            Some(address),
        );
    }
    pub fn measure(&mut self, pair: [u64; 2]) -> Value {
        let mut durations = Vec::new();
        let mut misses = 0;
        for _ in 0..100 {
            for address in [pair[0], pair[1], pair[0]] {
                let start = Instant::now();
                let hit = self.results.lookup(address, "");
                misses += FunctionResults::miss_requests(&hit, address, true).len();
                let graph = hit.graph.unwrap().0;
                let code = hit.decompiled.unwrap().0;
                let _canvas = GraphCanvas::with_geometry(graph.view(), graph.geometry());
                let mut selection = SemanticSelection {
                    mappings: code.mappings().clone(),
                    ..Default::default()
                };
                selection.select_instruction(address);
                std::hint::black_box((graph.listing().position(address), code.lines(), selection));
                durations.push(start.elapsed().as_secs_f64() * 1000.);
            }
        }
        assert_eq!(misses, 0);
        durations.sort_by(f64::total_cmp);
        let usage = self.results.usage();
        json!({ "scope": "production coordinator lookup plus prepared graph camera and semantic selection adoption; excludes native rendering",
            "visits": durations.len(), "worker_requests_on_hits": misses,
            "p50_lookup_adoption_ms": durations[durations.len()/2],
            "p95_lookup_adoption_ms": durations[(durations.len()*95).div_ceil(100)-1],
            "max_lookup_adoption_ms": durations.last(), "budget_bytes": usage.budget,
            "charged_bytes": usage.charged, "pinned_bytes": usage.pinned,
            "uncached_current_bytes": usage.uncached, "evicted_bytes": self.results.counters().evicted_bytes })
    }
}
