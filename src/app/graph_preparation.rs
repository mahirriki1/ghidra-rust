//! Off-thread graph presentation. Accepted function views get their listing
//! index and base geometry, and the displayed graph its comment and call-name
//! rows, on one lazily started thread per desktop. It holds at most one
//! running job, one replaceable pending job and one finished result; the GUI
//! never waits for it. Each submission keeps its continuation here, and the
//! desktop re-checks that continuation against current state on adoption.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};

use eframe::egui;

use crate::function_presentation::PreparedGraph;
use crate::function_results::ResultBinding;
use crate::graph::GraphGeometry;
use crate::model::{CodeMapping, FunctionView};
use crate::result_store::{Shared, Stored, TransientReservation};
use crate::semantic::SemanticInfo;

pub(super) enum Work {
    /// A validated worker or project view.
    Base(FunctionView),
    #[cfg(test)]
    Panic,
    /// Bounded row prefixes for the PCs of an adopted graph.
    Annotated {
        graph: Shared<PreparedGraph>,
        comments: BTreeMap<u64, String>,
        call_names: BTreeMap<u64, String>,
    },
}

pub(super) enum Output {
    Failed,
    Base(PreparedGraph),
    Annotated(Arc<GraphGeometry>),
}

/// What adopting a finished job continues, and the state it was bound to.
pub(super) enum Continuation {
    /// A live graph reply, checked again exactly as on its arrival.
    Live {
        generation: u64,
        selection: u64,
        revision: u64,
        result: Option<ResultBinding>,
        address: u64,
    },
    /// The graph-dependent remainder of a project restore.
    Saved(Box<SavedRestore>),
    Annotation(AnnotationKey),
}

pub(super) struct SavedRestore {
    pub generation: u64,
    pub selection: u64,
    pub binding: Option<ResultBinding>,
    pub selected: Option<u64>,
    pub decompiled: Option<String>,
    pub mappings: Vec<CodeMapping>,
    pub semantics: SemanticInfo,
}

impl SavedRestore {
    /// Held decompiler output, charged with the job.
    pub fn retained_bytes(&self) -> usize {
        use crate::result_store::Bytes;
        let mut bytes = Bytes::of::<Self>()
            .plus(self.decompiled.as_ref().map_or(0, String::capacity))
            .slots::<CodeMapping>(self.mappings.capacity())
            .add_total(crate::function_presentation::semantic_bytes(
                &self.semantics,
            ));
        for mapping in &self.mappings {
            bytes = bytes.slots::<u64>(mapping.addresses.capacity());
        }
        bytes.total().unwrap_or(usize::MAX)
    }
}

/// The displayed graph and every revision its comment rows depend on.
#[derive(Clone, Debug)]
pub(super) struct AnnotationKey {
    pub generation: u64,
    pub selection: u64,
    pub revision: u64,
    pub symbol_revision: u64,
    /// Held weakly, so the address cannot be reused while it is compared.
    pub graph: Weak<Stored<PreparedGraph>>,
}

impl AnnotationKey {
    /// The part of the key a canvas records; canvases never outlive their graph.
    pub fn revisions(&self) -> (u64, u64, u64) {
        (self.generation, self.revision, self.symbol_revision)
    }
}

impl PartialEq for AnnotationKey {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.selection == other.selection
            && self.revision == other.revision
            && self.symbol_revision == other.symbol_revision
            && Weak::ptr_eq(&self.graph, &other.graph)
    }
}

struct Job {
    serial: u64,
    work: Work,
    charge: Option<TransientReservation>,
}

pub(super) struct Finished {
    serial: u64,
    output: Output,
    charge: Option<TransientReservation>,
}

#[derive(Default)]
struct Slots {
    pending: Option<Job>,
    running: Option<u64>,
    finished: Option<Finished>,
    shutdown: bool,
    #[cfg(test)]
    paused: bool,
}

struct Inner {
    slots: Mutex<Slots>,
    wake: Condvar,
    /// The latest submitted serial; zero after cancellation. A running job
    /// for any other serial stops at its next phase and never publishes.
    wanted: AtomicU64,
}

impl Inner {
    fn slots(&self) -> MutexGuard<'_, Slots> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[derive(Default)]
pub(super) struct GraphPreparation {
    inner: Option<Arc<Inner>>,
    serial: u64,
    expected: Option<(u64, Continuation)>,
    /// Charge for the annotated geometry the canvas shows.
    adopted: Option<TransientReservation>,
    #[cfg(test)]
    submitted: usize,
}

impl GraphPreparation {
    /// Replaces any pending job and finished result with `work`. Only the
    /// latest submission can be adopted.
    pub fn submit(
        &mut self,
        work: Work,
        continuation: Continuation,
        charge: Option<TransientReservation>,
        context: &egui::Context,
    ) -> Result<(), String> {
        let inner = self.worker(context)?;
        self.serial = self.serial.wrapping_add(1).max(1);
        let serial = self.serial;
        inner.wanted.store(serial, Ordering::Release);
        let replaced = {
            let mut slots = inner.slots();
            slots.finished = None;
            slots.pending.replace(Job {
                serial,
                work,
                charge,
            })
        };
        inner.wake.notify_one();
        drop(replaced);
        self.expected = Some((serial, continuation));
        #[cfg(test)]
        {
            self.submitted += 1;
        }
        Ok(())
    }

    fn worker(&mut self, context: &egui::Context) -> Result<Arc<Inner>, String> {
        if let Some(inner) = &self.inner {
            return Ok(inner.clone());
        }
        let inner = Arc::new(Inner {
            slots: Mutex::default(),
            wake: Condvar::new(),
            wanted: AtomicU64::new(0),
        });
        let worker = inner.clone();
        let context = context.clone();
        std::thread::Builder::new()
            .name("graph-presentation".into())
            .spawn(move || run(&worker, &context))
            .map_err(|error| format!("Cannot start graph preparation: {error}"))?;
        self.inner = Some(inner.clone());
        Ok(inner)
    }

    /// Forgets every submission and the adopted charge without waiting for
    /// a running job, which still finishes but cannot publish.
    pub fn cancel(&mut self) {
        self.expected = None;
        self.adopted = None;
        if let Some(inner) = &self.inner {
            inner.wanted.store(0, Ordering::Release);
            let dropped = {
                let mut slots = inner.slots();
                (slots.pending.take(), slots.finished.take())
            };
            drop(dropped);
        }
    }

    /// The finished latest submission, if any. Superseded results are dropped.
    pub fn poll(&mut self) -> Option<(Continuation, Output, Option<TransientReservation>)> {
        let finished = self.inner.as_ref()?.slots().finished.take()?;
        if self.expected.as_ref()?.0 != finished.serial {
            return None;
        }
        let (_, continuation) = self.expected.take()?;
        Some((continuation, finished.output, finished.charge))
    }

    /// Whether the latest submission is still awaited and satisfies `test`.
    pub fn awaits(&self, test: impl FnOnce(&Continuation) -> bool) -> bool {
        self.expected
            .as_ref()
            .is_some_and(|(_, continuation)| test(continuation))
    }

    pub fn set_adopted_charge(&mut self, charge: Option<TransientReservation>) {
        self.adopted = charge;
    }

    /// While paused, a taken job stays running before it computes anything.
    #[cfg(test)]
    pub fn pause(&mut self, paused: bool, context: &egui::Context) {
        let inner = self.worker(context).unwrap();
        inner.slots().paused = paused;
        inner.wake.notify_all();
    }

    /// Waits until the worker has taken a job. Tests only.
    #[cfg(test)]
    pub fn wait_running(&self) {
        let inner = self.inner.as_ref().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while inner.slots().running.is_none() {
            assert!(std::time::Instant::now() < deadline, "no job started");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    /// `(pending, running, finished)` occupancy, for bounded-handoff tests.
    #[cfg(test)]
    pub fn occupancy(&self) -> (bool, bool, bool) {
        self.inner.as_ref().map_or((false, false, false), |inner| {
            let slots = inner.slots();
            (
                slots.pending.is_some(),
                slots.running.is_some(),
                slots.finished.is_some(),
            )
        })
    }

    #[cfg(test)]
    pub fn submitted(&self) -> usize {
        self.submitted
    }

    #[cfg(test)]
    pub fn adopted_charge(&self) -> Option<usize> {
        self.adopted.as_ref().map(TransientReservation::bytes)
    }

    /// Waits until no job is pending or running. Tests only: the desktop
    /// never blocks on this thread.
    #[cfg(test)]
    pub fn settle(&self) {
        let Some(inner) = &self.inner else {
            return;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            {
                let slots = inner.slots();
                if slots.pending.is_none() && slots.running.is_none() {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "graph preparation stalled"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

impl Drop for GraphPreparation {
    fn drop(&mut self) {
        if let Some(inner) = &self.inner {
            inner.wanted.store(0, Ordering::Release);
            let dropped = {
                let mut slots = inner.slots();
                slots.shutdown = true;
                (slots.pending.take(), slots.finished.take())
            };
            inner.wake.notify_all();
            drop(dropped);
        }
    }
}

fn run(inner: &Inner, context: &egui::Context) {
    loop {
        let job = {
            let mut slots = inner.slots();
            loop {
                if slots.shutdown {
                    return;
                }
                if let Some(job) = slots.pending.take() {
                    slots.running = Some(job.serial);
                    #[cfg(test)]
                    while slots.paused && !slots.shutdown {
                        slots = inner
                            .wake
                            .wait(slots)
                            .unwrap_or_else(PoisonError::into_inner);
                    }
                    break job;
                }
                slots = inner
                    .wake
                    .wait(slots)
                    .unwrap_or_else(PoisonError::into_inner);
            }
        };
        let serial = job.serial;
        let cancelled = || inner.wanted.load(Ordering::Acquire) != serial;
        // A panic discards this job only; the thread keeps serving the desktop.
        let output = std::panic::catch_unwind(AssertUnwindSafe(|| match job.work {
            #[cfg(test)]
            Work::Panic => panic!("injected preparation failure"),
            Work::Base(view) => PreparedGraph::prepare(view, &cancelled).map(Output::Base),
            Work::Annotated {
                graph,
                comments,
                call_names,
            } => {
                let _layout = crate::performance::span("gui_graph_comment_layout");
                GraphGeometry::prepare(graph.view(), &comments, &call_names, &cancelled)
                    .map(|geometry| Output::Annotated(Arc::new(geometry)))
            }
        }))
        .unwrap_or(Some(Output::Failed));
        let mut slots = inner.slots();
        slots.running = None;
        if let Some(output) = output
            && !cancelled()
            && !slots.shutdown
        {
            slots.finished = Some(Finished {
                serial,
                output,
                charge: job.charge,
            });
            drop(slots);
            context.request_repaint();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::app::tests::keyboard_app;
    use crate::app::{DesktopApp, Pending, ProjectOpen, Tab};
    use crate::model::{BasicBlock, Instruction, Request, Response};
    use crate::project::{LoadedProject, ProjectData};
    use crate::session::Annotation;

    fn view(rows: u64, mnemonic: &str) -> FunctionView {
        FunctionView {
            address: 0x1000,
            blocks: vec![BasicBlock {
                address: 0x1000,
                instructions: (0..rows)
                    .map(|row| Instruction {
                        address: 0x1000 + row * 4,
                        bytes: vec![0x90],
                        mnemonic: mnemonic.into(),
                        operands: format!("r{row}"),
                    })
                    .collect(),
            }],
            edges: vec![],
            calls: vec![],
            warnings: vec![],
        }
    }

    fn pending(app: &DesktopApp) -> Pending {
        Pending {
            id: 1,
            request: Request::Graph { address: 0x1000 },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: None,
        }
    }

    fn reply(app: &mut DesktopApp, view: FunctionView, context: &egui::Context) {
        app.receive(pending(app), Response::Graph { view }, context);
    }

    fn mnemonic(app: &DesktopApp) -> Option<&str> {
        let instruction = app.view()?.blocks.first()?.instructions.first()?;
        Some(&instruction.mnemonic)
    }

    fn project(app: &DesktopApp, view: FunctionView) -> ProjectOpen {
        let source = "int entry() { return 7; }";
        let data = ProjectData {
            info: app.info.clone().unwrap(),
            session: app.session.clone().unwrap(),
            view: Some(view),
            decompiled: Some(source.into()),
            mappings: vec![CodeMapping {
                start: source.find("return").unwrap(),
                end: source.find(';').unwrap() + 1,
                addresses: vec![0x1004],
            }],
            semantics: Default::default(),
            strings: Vec::new(),
            strings_truncated: false,
            crypto: Vec::new(),
            crypto_truncated: false,
            selected_address: Some(0x1000),
            discovery: None,
        };
        ProjectOpen {
            project: LoadedProject {
                data,
                binary: None,
                source_hint: "fixture".into(),
                cache_compatible: true,
            },
            project_path: "analysis.grproj".into(),
            binary_path: "fixture".into(),
            discovery_index: None,
        }
    }

    fn frame(app: &mut DesktopApp, context: &egui::Context) -> Vec<String> {
        let time = context.input(|input| input.time) + 0.1;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 700.0),
                )),
                time: Some(time),
                ..Default::default()
            },
            |ui| app.main_panel(ui),
        );
        output.textures_delta.clear();
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) => Some(text.galley.text().to_owned()),
                _ => None,
            })
            .collect()
    }

    fn comment(app: &mut DesktopApp, address: u64, text: &str) {
        app.edit_annotation(
            address,
            Annotation {
                comment: text.into(),
                ..Default::default()
            },
        );
    }

    #[test]
    fn graph_preparation_discards_stale_results() {
        let context = egui::Context::default();
        // Navigating away cancels a running base job without waiting for it.
        let mut app = keyboard_app();
        app.graph_preparation.pause(true, &context);
        reply(&mut app, view(4, "old"), &context);
        app.graph_preparation.wait_running();
        assert!(app.view().is_none() && app.canvas.is_none());
        app.navigate(0x1040, true, &context);
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert!(app.view().is_none() && app.canvas.is_none());
        assert_eq!(app.graph_preparation.occupancy(), (false, false, false));

        // Another binary generation at the same address, or an annotation edit
        // during preparation, is rejected at adoption as on arrival.
        for change in 0..2 {
            let mut app = keyboard_app();
            app.graph_preparation.pause(true, &context);
            reply(&mut app, view(4, "old"), &context);
            app.graph_preparation.wait_running();
            if change == 0 {
                app.generation += 1;
            } else {
                app.revision += 1;
            }
            app.graph_preparation.pause(false, &context);
            app.settle_graph();
            assert!(app.view().is_none(), "change {change}");
        }

        // A same-function refresh supersedes a running job for that address.
        let mut app = keyboard_app();
        reply(&mut app, view(4, "first"), &context);
        app.settle_graph();
        assert_eq!(mnemonic(&app), Some("first"));
        let before = pending(&app);
        app.graph_preparation.pause(true, &context);
        app.receive(
            before,
            Response::Graph {
                view: view(4, "stale"),
            },
            &context,
        );
        app.graph_preparation.wait_running();
        app.refresh_function(&context);
        reply(&mut app, view(4, "fresh"), &context);
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert_eq!(mnemonic(&app), Some("fresh"));
        assert!(!app.cached_graph);

        // A saved continuation never adopts after navigation: no graph,
        // mappings or provenance from the abandoned project view.
        let mut app = keyboard_app();
        let saved = project(&app, view(4, "saved"));
        app.graph_preparation.pause(true, &context);
        app.restore_project(saved, &context);
        app.graph_preparation.wait_running();
        assert!(app.view().is_none() && app.code.is_none() && !app.cached_graph);
        app.navigate(0x1040, true, &context);
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert!(app.view().is_none() && app.code.is_none());
        assert!(!app.cached_graph && !app.saved_analysis);
        assert!(app.semantic.mappings.is_empty());

        // A replacement project restored meanwhile wins; its graph, mappings
        // and Saved provenance are adopted together.
        let mut app = keyboard_app();
        let first = project(&app, view(4, "first"));
        let second = project(&app, view(4, "second"));
        app.graph_preparation.pause(true, &context);
        app.restore_project(first, &context);
        app.graph_preparation.wait_running();
        app.restore_project(second, &context);
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert_eq!(mnemonic(&app), Some("second"));
        assert!(app.cached_graph && app.saved_analysis);
        assert_eq!(app.semantic.mappings.len(), 1);
        assert_eq!(app.status, "Project opened · saved analysis");
        assert_eq!(app.history.len(), 1);
    }

    #[test]
    fn annotation_geometry_tracks_revisions_and_keeps_the_camera() {
        let context = egui::Context::default();
        crate::theme::install(&context);
        let mut app = keyboard_app();
        app.tab = Tab::Graph;
        comment(&mut app, 0x1004, "first note");
        reply(&mut app, view(12, "mov"), &context);
        app.settle_graph();
        // Base geometry adopts at once; comment rows follow off-thread.
        frame(&mut app, &context);
        app.settle_graph();
        assert!(frame(&mut app, &context).contains(&"; first note".to_owned()));
        let camera = app.canvas.as_ref().unwrap().camera();
        let submitted = app.graph_preparation.submitted();
        // Idle frames with an unchanged key do no work.
        for _ in 0..3 {
            frame(&mut app, &context);
        }
        assert_eq!(app.graph_preparation.submitted(), submitted);
        assert!(app.graph_preparation.adopted_charge().unwrap() > 0);

        // An edited comment is not displayed as current while it prepares.
        app.graph_preparation.pause(true, &context);
        comment(&mut app, 0x1004, "second note");
        let texts = frame(&mut app, &context);
        assert!(!texts.iter().any(|text| text.contains("note")));
        app.graph_preparation.wait_running();
        // Another edit during preparation makes that job stale.
        comment(&mut app, 0x1008, "third note");
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert!(app.canvas.as_ref().unwrap().comment_rows().is_empty());
        frame(&mut app, &context);
        app.settle_graph();
        let texts = frame(&mut app, &context);
        assert!(texts.contains(&"; second note".to_owned()));
        assert!(texts.contains(&"; third note".to_owned()));
        assert!(!texts.iter().any(|text| text.contains("first note")));
        assert_eq!(app.canvas.as_ref().unwrap().camera(), camera);

        // A name revision re-prepares; a function switch drops a late result.
        let submitted = app.graph_preparation.submitted();
        app.symbol_revision += 1;
        app.graph_preparation.pause(true, &context);
        frame(&mut app, &context);
        assert_eq!(app.graph_preparation.submitted(), submitted + 1);
        app.graph_preparation.wait_running();
        app.navigate(0x1040, true, &context);
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert!(app.canvas.is_none());
        assert!(app.graph_preparation.adopted_charge().is_none());
    }

    #[test]
    fn graph_preparation_is_bounded_and_reused() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        let baseline = app.results.usage().charged;
        app.graph_preparation.pause(true, &context);
        reply(&mut app, view(4, "first"), &context);
        app.graph_preparation.wait_running();
        // A reply storm keeps one running, one pending and no finished slot.
        for index in 0..64 {
            reply(&mut app, view(4, &format!("m{index}")), &context);
            assert_eq!(app.graph_preparation.occupancy(), (true, true, false));
        }
        assert_eq!(app.graph_preparation.submitted(), 65);
        // Running and pending inputs are charged to the store's ledger.
        let charged = app.results.usage().charged;
        assert!(charged > baseline);
        assert!(charged - baseline >= 2 * PreparedGraph::estimated_bytes(&view(4, "m0")));
        app.graph_preparation.pause(false, &context);
        app.settle_graph();
        assert_eq!(mnemonic(&app), Some("m63"));
        assert_eq!(app.graph_preparation.occupancy(), (false, false, false));
        // Cancelling queued work releases its charge.
        let adopted = app.results.usage().charged;
        app.graph_preparation.pause(true, &context);
        reply(&mut app, view(4, "late"), &context);
        app.graph_preparation.wait_running();
        reply(&mut app, view(4, "later"), &context);
        assert!(app.results.usage().charged > adopted);
        app.graph_preparation.cancel();
        app.graph_preparation.pause(false, &context);
        app.graph_preparation.settle();
        assert_eq!(app.results.usage().charged, adopted);
        assert_eq!(mnemonic(&app), Some("m63"));

        // A stored result adopts immediately and shares its geometry.
        let graph = app.graph.clone().unwrap();
        let submitted = app.graph_preparation.submitted();
        app.canvas = None;
        app.adopt_graph(graph.clone(), crate::result_store::ResultOrigin::Computed);
        assert!(app.canvas.as_ref().unwrap().shows(&graph.geometry()));
        assert_eq!(app.graph_preparation.submitted(), submitted);

        // Dropping the desktop never joins a running job.
        app.graph_preparation.pause(true, &context);
        reply(&mut app, view(4, "running"), &context);
        app.graph_preparation.wait_running();
        let started = Instant::now();
        drop(app);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn graph_adoption_keeps_an_inflight_worker_reply_bound() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        reply(&mut app, view(4, "mov"), &context);
        let mut maintenance = pending(&app);
        maintenance.id = 77;
        maintenance.request = Request::Linkage {
            cursor: 0,
            digest: None,
        };
        app.pending = Some(maintenance);
        app.settle_graph();
        assert!(app.view().is_some());
        assert_eq!(app.pending.as_ref().unwrap().id, 77);
        assert!(matches!(
            app.pending.as_ref().unwrap().request,
            Request::Linkage { .. }
        ));
        assert!(
            app.queue
                .iter()
                .any(|request| matches!(request, Request::Decompile { address: 0x1000 }))
        );
    }

    #[test]
    fn graph_preparation_requires_a_memory_reservation() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        app.results = crate::function_results::FunctionResults::new(0);
        reply(&mut app, view(4, "mov"), &context);
        assert_eq!(app.graph_preparation.submitted(), 0);
        assert!(app.status.contains("memory budget"));
        assert!(app.view().is_none());
    }

    #[test]
    fn preparation_failure_reports_and_the_worker_recovers() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        let continuation = Continuation::Live {
            generation: app.generation,
            selection: app.selection_generation,
            revision: app.revision,
            result: None,
            address: 0x1000,
        };
        app.graph_preparation
            .submit(Work::Panic, continuation, None, &context)
            .unwrap();
        app.settle_graph();
        assert!(app.status.contains("Graph presentation failed"));
        assert!(!app.graph_preparation.awaits(|_| true));
        reply(&mut app, view(4, "recovered"), &context);
        app.settle_graph();
        assert_eq!(mnemonic(&app), Some("recovered"));
    }

    #[test]
    fn graph_preparation_starts_only_after_validation() {
        let context = egui::Context::default();
        let mut app = keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.file_len = 0x4000;
        info.sections[0].size = 0x4000;
        info.sections[0].file_size = 0x4000;
        let limit = crate::model::MAX_GRAPH_INSTRUCTIONS as u64;
        reply(&mut app, view(limit + 1, "over"), &context);
        assert!(app.status.contains("Instruction count"), "{}", app.status);
        assert_eq!(app.graph_preparation.submitted(), 0);
        reply(&mut app, view(limit, "full"), &context);
        app.settle_graph();
        assert_eq!(app.listing().len(), crate::model::MAX_GRAPH_INSTRUCTIONS);
    }
}
