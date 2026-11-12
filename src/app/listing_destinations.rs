//! Non-code destinations in the Program listing. In Program scope, Go To,
//! search hits, linkage slots and data exports, string and label jumps,
//! history and Hex's Show in Listing put the cursor on the exact row that
//! starts at the destination. Where none starts there, the covering row is
//! made to hold one: a collapsed `??` row expands the 4 KiB page(s) holding
//! the span, a data row entered past its start expands its item (each
//! capped at one expand step), and a zero-filled tail gains a session-only
//! split mark without any byte read. A destination inside a pending body
//! lands once that body's rows arrive. A destination inside a decoded
//! instruction has no row; callers then keep opening Hex (Show in Listing
//! alone lands on the covering instruction).
//!
//! Landing only moves the Program cursor: it never navigates, opens a
//! function, changes the selection generation or sends a request.

use eframe::egui;

use super::program_listing::{ListingScope, Reveal};
use super::{DesktopApp, Tab};
use crate::linkage_ui::Place;
use crate::program_listing::{Position, ProgramRows, Rank, Row};
use crate::search_jobs::Destination;

/// A destination inside a pending body, re-evaluated whenever the derived
/// rows change while the cursor still stands at its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Landing {
    generation: u64,
    address: u64,
    length: u64,
    /// The rows it was last evaluated against.
    serial: u64,
}

/// Where a landing ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    /// The cursor stands on a row starting at the destination.
    Row,
    /// The destination lies in a pending body; it lands once rows change.
    Pending,
    /// No exact row can exist there.
    None,
}

impl DesktopApp {
    /// Puts the Program cursor on the row starting at exactly `address`,
    /// preferring `rank` among rows sharing it, and shows the Listing. A
    /// collapsed `??` or data row covering it is expanded first, and a
    /// zero-filled tail split there; inside a pending body the cursor waits
    /// for the body. Returns false, changing nothing, outside Program scope,
    /// outside every section row, and inside a decoded instruction unless
    /// `covering`, which lands on that instruction's own row instead.
    pub(super) fn land_in_listing(
        &mut self,
        address: u64,
        length: u64,
        rank: Option<Rank>,
        covering: bool,
        context: &egui::Context,
    ) -> bool {
        if !self.program_scope() {
            return false;
        }
        self.program_rows_sync();
        self.program_evidence_sync();
        match self.place_listing_cursor(address, length, rank, covering, context) {
            Outcome::None => false,
            Outcome::Row | Outcome::Pending => {
                self.tab = Tab::Listing;
                true
            }
        }
    }

    fn place_listing_cursor(
        &mut self,
        address: u64,
        length: u64,
        rank: Option<Rank>,
        covering: bool,
        context: &egui::Context,
    ) -> Outcome {
        let keep = self.selected;
        let Some(layout) = self.program_layout() else {
            return Outcome::None;
        };
        if !layout.contains(address) {
            return Outcome::None;
        }
        if let Some(row) = layout.cursor(address, rank) {
            self.land_on(row, context);
            return Outcome::Row;
        }
        let Some(row) = layout
            .resolve(Position::new(address, Rank::Body))
            .filter(|row| row.span().is_some_and(|(s, e)| s <= address && address < e))
        else {
            return Outcome::None;
        };
        match row {
            Row::Undefined { .. } | Row::Data { .. } => {
                let Some((start, end)) = layout.landing_interval(&row, address, length) else {
                    return Outcome::None;
                };
                self.program.expanded.expand(start, end, keep);
            }
            Row::ZeroFill { .. } => self.program.anchor = Some(address),
            Row::Pending { .. } => {
                self.await_landing(address, length);
                return Outcome::Pending;
            }
            Row::Instruction { .. } if covering => {
                self.land_on(row, context);
                return Outcome::Row;
            }
            _ => return Outcome::None,
        }
        match self
            .program_layout()
            .and_then(|layout| layout.exact(Position::new(address, Rank::Body)))
        {
            Some(row) => {
                self.land_on(row, context);
                Outcome::Row
            }
            None => Outcome::None,
        }
    }

    /// Moves the cursor onto `row`. Unlike a key move it arms no follow:
    /// a landing never opens a function, also not after the cursor rests.
    fn land_on(&mut self, row: Row, context: &egui::Context) {
        self.program.landing = None;
        self.data_location = None;
        self.move_program_cursor(row, context);
        self.program.follow = None;
    }

    /// Selects `address` inside a pending body and reveals it; the cursor
    /// lands there once the body's rows arrive.
    fn await_landing(&mut self, address: u64, length: u64) {
        self.data_location = None;
        self.reference_focus = None;
        self.set_selected_address(address);
        self.semantic.addresses.clear();
        self.semantic.ranges.clear();
        self.program.cursor = None;
        self.program.follow = None;
        self.program.reveal = Some(Reveal::Address(address));
        self.program.landing = Some(Landing {
            generation: self.generation,
            address,
            length,
            serial: self.program.rows_serial,
        });
    }

    /// Re-evaluates a pending landing once the rows changed. It lapses when
    /// the selection, binary, scope or data location moved on, and it never
    /// switches tabs, records history or opens a function.
    pub(super) fn resume_landing(&mut self, context: &egui::Context) {
        let Some(landing) = self.program.landing else {
            return;
        };
        if landing.generation != self.generation
            || self.selected != Some(landing.address)
            || self.data_location.is_some()
            || !self.program_scope()
        {
            self.program.landing = None;
            return;
        }
        if landing.serial == self.program.rows_serial {
            return;
        }
        self.program.landing = None;
        if self.place_listing_cursor(landing.address, landing.length, None, false, context)
            == Outcome::Pending
            && let Some(landing) = &mut self.program.landing
        {
            landing.serial = self.program.rows_serial;
        }
    }

    /// The place Back returns to: a Hex span, a Program row without a
    /// function owner (with its rank), else the selected code address.
    pub(super) fn current_place(&self) -> Option<Place> {
        let selected = self.selected?;
        if let Some((address, length)) = self.data_location {
            return Some(Place::Data { address, length });
        }
        if self.program_scope()
            && let Some(row) = self
                .program_layout()
                .and_then(|layout| self.program_cursor(&layout))
            && row.function().is_none()
        {
            return Some(Place::Listing {
                address: selected,
                rank: row.position().rank,
            });
        }
        // A landing still waiting for its body stays a listing place, so a
        // later decode there never turns Back into opening a function.
        if self.program_scope()
            && self.program.landing.as_ref().is_some_and(|landing| {
                landing.generation == self.generation && landing.address == selected
            })
        {
            return Some(Place::Listing {
                address: selected,
                rank: Rank::Body,
            });
        }
        Some(Place::Code(selected))
    }

    /// The history entry for where a landing put the cursor, and its owner.
    fn landed_place(&self, fallback: u64) -> (Place, u64) {
        let address = self.selected.unwrap_or(fallback);
        let row = self
            .program_layout()
            .and_then(|layout| self.program_cursor(&layout));
        match (row, row.and_then(|row| row.function())) {
            (Some(_), Some(owner)) => (Place::Code(address), owner),
            (Some(row), None) => (
                Place::Listing {
                    address,
                    rank: row.position().rank,
                },
                address,
            ),
            (None, _) => (
                Place::Listing {
                    address,
                    rank: Rank::Body,
                },
                address,
            ),
        }
    }

    /// A non-code destination in Program scope: lands on its exact row,
    /// recorded for Back/Forward when `record`. False in Function scope or
    /// where no exact row can exist; the caller then opens Hex.
    pub(super) fn land_destination(
        &mut self,
        address: u64,
        length: u64,
        record: bool,
        context: &egui::Context,
    ) -> bool {
        if !self.program_scope() {
            return false;
        }
        // Without a selection the current entry stays as recorded.
        let departure = self
            .current_place()
            .or_else(|| self.history.get(self.history_index).copied());
        if !self.land_in_listing(address, length, None, false, context) {
            return false;
        }
        if record {
            let (place, owner) = self.landed_place(address);
            self.record_departure(departure, place, owner);
        }
        true
    }

    /// Revisits a recorded Program row: in Program scope its exact row,
    /// else (or where none can exist) the byte in Hex.
    pub(super) fn restore_listing_place(
        &mut self,
        address: u64,
        rank: Rank,
        context: &egui::Context,
    ) {
        if !self.land_in_listing(address, 1, Some(rank), false, context) {
            self.open_data(address, 1, context);
        }
    }

    /// Hex's Show in Listing for the span `[address, address + length)`.
    /// Proven code opens in its owner; any other address switches to the
    /// Program scope and lands on its row, or on the instruction covering
    /// it. Back returns to the Hex span. An address no section row covers
    /// changes nothing.
    pub(super) fn show_in_listing(&mut self, address: u64, length: u64, context: &egui::Context) {
        let Some(info) = self.info.as_ref() else {
            return;
        };
        let departure = Some(Place::Data { address, length });
        let destination =
            crate::search_jobs::resolve(info, address, 1, |pc| self.observed_owner(pc));
        if let Some(Destination::Code { owner, .. }) = destination {
            self.set_listing_scope(ListingScope::Program);
            self.record_departure(departure, Place::Code(address), owner);
            self.navigate_location(address, Some(owner), false, context);
            self.tab = Tab::Listing;
            return;
        }
        let rows = ProgramRows::new(&info.sections, [], []);
        if !rows.contains(address) {
            self.status = format!("No listing row at {address:#x}");
            return;
        }
        self.set_listing_scope(ListingScope::Program);
        if self.land_in_listing(address, length, None, true, context) {
            let (place, owner) = self.landed_place(address);
            self.record_departure(departure, place, owner);
        } else {
            self.status = format!("No listing row at {address:#x}");
        }
    }

    /// Labels tree Go to and Comments jumps. Code proven by an inventory
    /// entry or an observed owner opens in that owner. Any other address
    /// lands on its Program row; without one, a non-code address decodes
    /// and an executable one opens in Hex. No function is ever guessed.
    pub(super) fn navigate_annotation(
        &mut self,
        address: u64,
        record: bool,
        context: &egui::Context,
    ) {
        self.update_comment_rows();
        let Some(info) = self.info.as_ref() else {
            return;
        };
        let code = crate::call_analysis::code_address(info, address);
        match crate::search_jobs::resolve(info, address, 1, |pc| self.observed_owner(pc)) {
            Some(Destination::Code { owner, .. }) => {
                self.navigate_location(address, Some(owner), record, context);
            }
            Some(Destination::Data { .. }) => {
                if self.land_destination(address, 1, record, context) {
                    return;
                }
                if !code {
                    // Comments can belong to data; it decodes as before.
                    self.navigate_location(address, None, record, context);
                } else if record {
                    self.navigate_data(address, 1, context);
                } else {
                    self.open_data(address, 1, context);
                }
            }
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::super::program_listing::ListingScope;
    use super::super::tests as fixture;
    use super::super::{Pending, Tab};
    use super::*;
    use crate::hex_ui::HexAction;
    use crate::model::{
        BasicBlock, FunctionInfo, FunctionView, Instruction, ListingBinding, ListingOutcome,
        Request, Response, SectionInfo, StringEntry,
    };
    use crate::theme;

    fn view(entry: u64, count: u64) -> FunctionView {
        FunctionView {
            address: entry,
            blocks: vec![BasicBlock {
                address: entry,
                instructions: (0..count)
                    .map(|i| Instruction {
                        address: entry + i * 4,
                        bytes: vec![0x90; 4],
                        mnemonic: "nop".into(),
                        operands: String::new(),
                    })
                    .collect(),
            }],
            edges: vec![],
            calls: vec![],
            warnings: vec![],
        }
    }

    /// Delivers a Listing reply with the given views, as the worker would.
    fn deliver(app: &mut DesktopApp, views: Vec<FunctionView>) {
        let context = egui::Context::default();
        app.program.token += 1;
        let entries: Vec<u64> = views.iter().map(|view| view.address).collect();
        let binding = ListingBinding {
            generation: app.generation,
            token: app.program.token,
        };
        let pending = Pending {
            id: 1,
            request: Request::Listing {
                binding,
                entries: entries.clone(),
            },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: app.results.binding(entries[0], String::new()),
        };
        let outcomes = views
            .into_iter()
            .map(|view| ListingOutcome {
                entry: view.address,
                view: Some(view),
            })
            .collect();
        app.receive(pending, Response::Listing { binding, outcomes }, &context);
    }

    /// Program scope over `.text` 0x1000–0x1100 (`entry` displayed with
    /// four rows, `next` cached with two, `third` at 0x1080 pending) and
    /// `.data` 0x10000–0x50000: file-backed to 0x40000, then zero-filled,
    /// with a 16-byte string candidate at 0x18000. Rows of `.data`: its
    /// header, `??` 0x10000–0x18000, the string, `??` 0x18010–0x40000 and
    /// the zero-filled tail.
    fn dest_app() -> DesktopApp {
        let mut app = fixture::keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.sections.push(SectionInfo {
            name: ".data".into(),
            address: 0x10000,
            size: 0x40000,
            file_offset: 0x100,
            file_size: 0x30000,
            executable: false,
        });
        info.file_len = 0x30100;
        info.functions.push(FunctionInfo {
            address: 0x1080,
            name: "third".into(),
        });
        let functions = info.functions.clone();
        app.strings = vec![StringEntry {
            length: Some(0x10),
            address: 0x18000,
            text: "s".repeat(0x10),
            encoding: "ASCII".into(),
        }];
        app.results.open(&"a".repeat(64), &[]);
        app.results.update_inputs(functions, vec![]);
        let deadline = Instant::now() + Duration::from_secs(2);
        while app.results.preparing() {
            assert!(Instant::now() < deadline);
            app.results.poll_inputs();
            std::thread::yield_now();
        }
        fixture::show_view(&mut app, view(0x1000, 4));
        app.result_scope = Some(0x1000);
        app.tab = Tab::Listing;
        app.set_listing_scope(ListingScope::Program);
        deliver(&mut app, vec![view(0x1040, 2)]);
        app.history = vec![Place::Code(0x1000)];
        app
    }

    struct Harness {
        context: egui::Context,
        app: DesktopApp,
        time: f64,
    }

    impl Harness {
        fn new(app: DesktopApp) -> Self {
            let context = egui::Context::default();
            theme::install(&context);
            context.set_pixels_per_point(1.25);
            context.all_styles_mut(|style| {
                style.animation_time = 0.0;
                style.scroll_animation = egui::style::ScrollAnimation::none();
            });
            let mut harness = Self {
                context,
                app,
                time: 0.0,
            };
            harness.frame();
            harness.frame();
            harness
        }

        fn frame(&mut self) -> egui::FullOutput {
            self.time += 0.5;
            let app = &mut self.app;
            let mut output = self.context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(700.0, 600.0),
                    )),
                    time: Some(self.time),
                    ..Default::default()
                },
                |ui| {
                    app.main_panel(ui);
                    app.release_menu(ui.ctx());
                    app.handle_shortcuts(ui.ctx());
                    app.poll_cursor_follow(ui.ctx());
                },
            );
            output.textures_delta.clear();
            output
        }

        fn go_to(&mut self, query: &str) {
            let context = self.context.clone();
            self.app.go_to(query, &context).unwrap();
            self.frame();
        }

        fn step(&mut self, forward: bool) {
            let context = self.context.clone();
            self.app.history_step(forward, &context);
            self.frame();
        }

        fn land(&mut self, address: u64, rank: Rank) -> bool {
            let context = self.context.clone();
            let landed = self
                .app
                .land_in_listing(address, 1, Some(rank), false, &context);
            self.frame();
            landed
        }

        fn hex(&mut self, action: HexAction) {
            let context = self.context.clone();
            self.app.handle_hex_action(action, &context);
            self.frame();
        }

        fn cursor(&self) -> Option<Row> {
            let layout = self.app.program_layout()?;
            self.app.program_cursor(&layout)
        }

        fn exact(&self, address: u64) -> Option<Row> {
            self.app
                .program_layout()?
                .exact(Position::new(address, Rank::Body))
        }

        /// The screen y of the row whose address column shows `address`.
        fn row_y(&mut self, address: u64) -> Option<f32> {
            let output = self.frame();
            let needle = format!("{address:08x}");
            output.shapes.iter().find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text)
                    if text.galley.text().split_whitespace().next() == Some(&needle) =>
                {
                    Some(text.pos.y)
                }
                _ => None,
            })
        }

        fn graph_requests(&self) -> usize {
            let graph = |r: &Request| matches!(r, Request::Graph { .. });
            self.app.queue.iter().filter(|r| graph(r)).count()
                + usize::from(self.app.pending.as_ref().is_some_and(|p| graph(&p.request)))
        }

        fn byte_requests(&self) -> usize {
            let bytes = |r: &Request| matches!(r, Request::Bytes { .. });
            self.app.queue.iter().filter(|r| bytes(r)).count()
                + usize::from(self.app.pending.as_ref().is_some_and(|p| bytes(&p.request)))
                + usize::from(self.app.discovery_bytes.is_some())
        }
    }

    /// Any function request queues instead of vanishing without a worker.
    fn queueing(mut app: DesktopApp) -> Harness {
        app.discovery_job = Some(mpsc::sync_channel(1).1);
        Harness::new(app)
    }

    fn listing(address: u64, rank: Rank) -> Place {
        Place::Listing { address, rank }
    }

    #[test]
    fn go_to_into_a_collapsed_gap_expands_only_its_clipped_page() {
        let mut h = Harness::new(dest_app());
        h.app.program.assume_worker = true;
        let (epoch, selection) = (h.app.worker_epoch, h.app.selection_generation);
        h.go_to("18020");
        // The page holding it, clipped to the row after the string.
        assert_eq!(h.app.program.expanded.len(), 1);
        assert_eq!(
            h.app.program.expanded.covering(0x18020),
            Some((0x18010, 0x19000))
        );
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x18020 }));
        assert_eq!(h.exact(0x18010), Some(Row::Byte { address: 0x18010 }));
        assert_eq!(
            h.exact(0x19000),
            Some(Row::Undefined {
                start: 0x19000,
                end: 0x40000
            })
        );
        assert_eq!((h.app.selected, h.app.tab), (Some(0x18020), Tab::Listing));
        assert!(h.app.data_location.is_none() && h.app.program.follow.is_none());
        assert_eq!(h.app.worker_epoch, epoch);
        assert_eq!(h.app.selection_generation, selection);
        assert_eq!(h.app.result_scope, Some(0x1000));
        assert_eq!(h.graph_requests(), 0);
        assert_eq!(
            h.app.history,
            [Place::Code(0x1000), listing(0x18020, Rank::Body)]
        );
        assert!(h.row_y(0x18020).is_some(), "the byte row is shown");
        // Its bytes are read at the Program listing's own priority.
        assert_eq!(h.app.next_listing_page(), Some((0x18000, 0x1000)));
    }

    #[test]
    fn a_search_hit_expands_every_page_its_span_touches_and_function_scope_keeps_hex() {
        for program in [true, false] {
            let mut h = Harness::new(dest_app());
            if !program {
                h.app.set_listing_scope(ListingScope::Function);
            }
            let context = h.context.clone();
            h.app.open_search_data(0x38ffe, 4, &context);
            h.frame();
            let span = Place::Data {
                address: 0x38ffe,
                length: 4,
            };
            if program {
                assert_eq!(
                    h.app.program.expanded.covering(0x38ffe),
                    Some((0x38000, 0x3a000))
                );
                assert_eq!(h.cursor(), Some(Row::Byte { address: 0x38ffe }));
                assert_eq!(h.app.history.last(), Some(&listing(0x38ffe, Rank::Body)));
            } else {
                assert_eq!(h.app.tab, Tab::Hex);
                assert_eq!(h.app.data_location, Some((0x38ffe, 4)));
                assert_eq!(h.app.history.last(), Some(&span));
            }
        }
    }

    #[test]
    fn a_destination_past_64_kib_into_a_gap_expands_its_own_page() {
        let mut h = Harness::new(dest_app());
        h.go_to("38010");
        assert_eq!(
            h.app.program.expanded.covering(0x38010),
            Some((0x38000, 0x39000))
        );
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x38010 }));
        assert_eq!(
            h.exact(0x18010),
            Some(Row::Undefined {
                start: 0x18010,
                end: 0x38000
            })
        );
        assert_eq!(
            h.exact(0x39000),
            Some(Row::Undefined {
                start: 0x39000,
                end: 0x40000
            })
        );
    }

    #[test]
    fn the_65th_auto_expansion_evicts_an_old_interval_while_the_pin_holds() {
        let mut h = Harness::new(dest_app());
        for i in 0..64 {
            let start = 0x20000 + i * 0x100;
            h.app.program.expanded.expand(start, start + 0x10, None);
        }
        // The departure stands in the farthest interval; it is kept.
        assert!(h.land(0x20000, Rank::Body));
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x20000 }));
        h.go_to("3f010");
        let expanded = &h.app.program.expanded;
        assert_eq!(expanded.len(), crate::program_listing::MAX_EXPANSIONS);
        assert_eq!(expanded.covering(0x3f010), Some((0x3f000, 0x40000)));
        assert!(expanded.covering(0x20000).is_some(), "the departure's");
        assert!(expanded.covering(0x20100).is_none(), "the farthest other");
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x3f010 }));
        let y = h.row_y(0x3f010).expect("the landed row is shown");
        assert!(h.app.program.pin.is_some());
        // Rows changing elsewhere never move the landed row.
        deliver(&mut h.app, vec![view(0x1080, 2)]);
        assert_eq!(h.row_y(0x3f010), Some(y));
        assert_eq!(h.row_y(0x3f010), Some(y));
    }

    #[test]
    fn a_string_hit_lands_on_its_row_and_mid_string_expands_the_item() {
        let mut h = Harness::new(dest_app());
        h.go_to("18000");
        assert!(matches!(
            h.cursor(),
            Some(Row::Data {
                start: 0x18000,
                end: 0x18010,
                ..
            })
        ));
        assert!(h.app.program.expanded.is_empty());
        h.go_to("18004");
        assert_eq!(
            h.app.program.expanded.covering(0x18004),
            Some((0x18000, 0x18010))
        );
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x18004 }));
        assert_eq!(h.exact(0x18000), Some(Row::Byte { address: 0x18000 }));
        // Back returns to the string row's own rank and address.
        h.step(false);
        assert!(matches!(h.cursor(), Some(Row::Byte { address: 0x18000 })));
        assert_eq!(h.app.selected, Some(0x18000));
    }

    #[test]
    fn a_destination_inside_an_instruction_falls_back_to_hex() {
        let mut h = queueing(dest_app());
        h.go_to("1002");
        assert_eq!(h.app.tab, Tab::Hex);
        assert_eq!(h.app.data_location, Some((0x1002, 1)));
        assert!(h.app.program.expanded.is_empty() && h.app.program.anchor.is_none());
        assert_eq!(
            h.app.history.last(),
            Some(&Place::Data {
                address: 0x1002,
                length: 1
            })
        );
        assert_eq!(h.graph_requests(), 0);
    }

    #[test]
    fn a_zero_fill_destination_gets_an_anchor_and_reads_nothing() {
        let mut h = Harness::new(dest_app());
        h.app.program.assume_worker = true;
        h.go_to("48000");
        assert_eq!(h.app.program.anchor, Some(0x48000));
        assert_eq!(
            h.cursor(),
            Some(Row::ZeroFill {
                start: 0x48000,
                end: 0x50000
            })
        );
        assert_eq!(
            h.exact(0x40000),
            Some(Row::ZeroFill {
                start: 0x40000,
                end: 0x48000
            })
        );
        assert!(h.app.program.expanded.is_empty());
        assert!(h.row_y(0x48000).is_some());
        h.frame();
        assert_eq!(h.app.next_listing_page(), None);
        assert!(h.app.program.bytes.is_empty());
        assert_eq!(h.byte_requests(), 0);
        assert_eq!(h.app.history.last(), Some(&listing(0x48000, Rank::Body)));
    }

    #[test]
    fn a_pending_destination_lands_after_the_listing_reply_without_tab_or_history() {
        for (count, expected) in [
            // The body ends before it: its bytes expand.
            (1, Row::Byte { address: 0x1088 }),
            // An instruction starts there: the cursor stands on it.
            (
                4,
                Row::Instruction {
                    owner: 0x1080,
                    start: 0x1088,
                    end: 0x108c,
                },
            ),
        ] {
            let mut h = queueing(dest_app());
            let selection = h.app.selection_generation;
            h.go_to("1088");
            assert_eq!((h.app.selected, h.app.tab), (Some(0x1088), Tab::Listing));
            assert_eq!(h.cursor(), None, "no row starts there yet");
            assert!(h.app.program.landing.is_some());
            let history = h.app.history.clone();
            assert_eq!(history.last(), Some(&listing(0x1088, Rank::Body)));
            h.frame();
            deliver(&mut h.app, vec![view(0x1080, count)]);
            h.frame();
            assert_eq!(h.cursor(), Some(expected), "{count}");
            assert!(h.app.program.landing.is_none());
            assert_eq!(h.app.history, history);
            assert_eq!(h.app.tab, Tab::Listing);
            assert_eq!(h.app.selection_generation, selection);
            // Never opens a function, also once the cursor rests.
            for _ in 0..3 {
                h.frame();
            }
            assert_eq!(h.app.result_scope, Some(0x1000));
            assert!(h.app.program.follow.is_none());
            assert_eq!(h.graph_requests(), 0);
        }
    }

    #[test]
    fn a_pending_landing_lapses_once_the_selection_moves_on() {
        let mut h = Harness::new(dest_app());
        h.go_to("1088");
        h.go_to("10010");
        // Leaving a landing that still waits for its body keeps it a listing
        // place: a later decode there never makes Back open a function.
        assert!(h.app.history.contains(&listing(0x1088, Rank::Body)));
        assert!(
            !h.app
                .history
                .contains(&crate::linkage_ui::Place::Code(0x1088))
        );
        deliver(&mut h.app, vec![view(0x1080, 1)]);
        h.frame();
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x10010 }));
        assert!(h.app.program.expanded.covering(0x1088).is_none());
    }

    #[test]
    fn back_and_forward_tell_a_section_header_from_its_first_byte() {
        let mut h = Harness::new(dest_app());
        assert!(h.land(0x10000, Rank::Section));
        let header = Row::Section {
            section: 1,
            start: 0x10000,
        };
        assert_eq!(h.cursor(), Some(header));
        h.go_to("38010");
        assert_eq!(h.app.history[0], listing(0x10000, Rank::Section));
        h.step(false);
        assert_eq!(h.cursor(), Some(header));
        h.step(true);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x38010 }));
        let first = Row::Undefined {
            start: 0x10000,
            end: 0x18000,
        };
        assert!(h.land(0x10000, Rank::Body));
        assert_eq!(h.cursor(), Some(first));
        h.go_to("38010");
        h.step(false);
        assert_eq!(h.cursor(), Some(first));
        h.step(false);
        assert_eq!(h.cursor(), Some(header));
        assert_eq!(h.app.result_scope, Some(0x1000));
    }

    #[test]
    fn a_code_destination_records_the_header_row_it_leaves() {
        let mut h = queueing(dest_app());
        assert!(h.land(0x10000, Rank::Section));
        h.go_to("1044");
        assert_eq!(h.app.history[0], listing(0x10000, Rank::Section));
        assert_eq!(h.app.history[1], Place::Code(0x1044));
    }

    #[test]
    fn back_to_a_byte_row_after_a_manual_collapse_expands_it_again() {
        let mut h = Harness::new(dest_app());
        h.go_to("38010");
        h.go_to("10010");
        h.app.toggle_bytes(Row::Byte { address: 0x38010 });
        assert!(h.app.program.expanded.covering(0x38010).is_none());
        h.step(false);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x38010 }));
        assert_eq!(
            h.app.program.expanded.covering(0x38010),
            Some((0x38000, 0x39000))
        );
        h.step(true);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x10010 }));
    }

    #[test]
    fn a_label_jump_to_an_unowned_executable_address_requests_no_graph() {
        for program in [false, true] {
            let mut h = queueing(dest_app());
            if !program {
                h.app.set_listing_scope(ListingScope::Function);
            }
            let note = crate::session::Annotation {
                label: "g_inside".into(),
                ..Default::default()
            };
            h.app.edit_annotation(0x1030, note);
            let context = h.context.clone();
            h.app.navigate_annotation(0x1030, true, &context);
            h.frame();
            assert_eq!(h.graph_requests(), 0, "{program}");
            assert_eq!(h.app.result_scope, Some(0x1000));
            assert_eq!(h.app.selected, Some(0x1030));
            if program {
                assert_eq!(h.app.tab, Tab::Listing);
                // The label splits the gap, so a row starts there.
                assert_eq!(
                    h.cursor(),
                    Some(Row::Undefined {
                        start: 0x1030,
                        end: 0x1040
                    })
                );
                assert_eq!(h.app.history.last(), Some(&listing(0x1030, Rank::Body)));
            } else {
                assert_eq!(h.app.tab, Tab::Hex);
                assert_eq!(h.app.data_location, Some((0x1030, 1)));
            }
        }
    }

    #[test]
    fn show_in_listing_lands_on_the_span_and_back_restores_the_hex_span() {
        let mut h = Harness::new(dest_app());
        h.app.set_listing_scope(ListingScope::Function);
        let context = h.context.clone();
        h.app.navigate_data(0x38010, 4, &context);
        assert_eq!(h.app.hex.focused_span(), Some((0x38010, 4)));
        h.hex(HexAction::ShowListing {
            address: 0x38010,
            length: 4,
        });
        assert!(h.app.program_scope());
        assert_eq!(h.app.tab, Tab::Listing);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x38010 }));
        let span = Place::Data {
            address: 0x38010,
            length: 4,
        };
        assert_eq!(
            h.app.history,
            [Place::Code(0x1000), span, listing(0x38010, Rank::Body)]
        );
        h.step(false);
        assert_eq!(h.app.tab, Tab::Hex);
        assert_eq!(h.app.hex.focused_span(), Some((0x38010, 4)));
        h.step(true);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x38010 }));
    }

    #[test]
    fn show_in_listing_inside_an_instruction_lands_on_it_and_proven_code_opens() {
        let mut h = queueing(dest_app());
        let context = h.context.clone();
        h.app.navigate_data(0x1002, 1, &context);
        h.hex(HexAction::ShowListing {
            address: 0x1002,
            length: 1,
        });
        let covering = Row::Instruction {
            owner: 0x1000,
            start: 0x1000,
            end: 0x1004,
        };
        assert_eq!(h.cursor(), Some(covering));
        assert_eq!((h.app.selected, h.app.tab), (Some(0x1000), Tab::Listing));
        assert_eq!(h.app.history.last(), Some(&Place::Code(0x1000)));
        assert_eq!(h.graph_requests(), 0);
        // A proven instruction of a cached function opens in its owner.
        h.app.navigate_data(0x1044, 4, &context);
        h.hex(HexAction::ShowListing {
            address: 0x1044,
            length: 4,
        });
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.app.selected, Some(0x1044));
        assert_eq!(h.app.tab, Tab::Listing);
        assert_eq!(
            &h.app.history[h.app.history.len() - 2..],
            [
                Place::Data {
                    address: 0x1044,
                    length: 4
                },
                Place::Code(0x1044)
            ]
        );
    }

    #[test]
    fn show_in_listing_outside_every_section_row_changes_nothing() {
        let mut app = dest_app();
        // Overlaps `.text`, so it has no Program rows of its own.
        app.info.as_mut().unwrap().sections.push(SectionInfo {
            name: ".over".into(),
            address: 0x10f8,
            size: 0x20,
            file_offset: 0,
            file_size: 0x20,
            executable: false,
        });
        let mut h = Harness::new(app);
        h.app.set_listing_scope(ListingScope::Function);
        let context = h.context.clone();
        h.app.navigate_data(0x1108, 1, &context);
        let before = (
            h.app.history.clone(),
            h.app.history_index,
            h.app.selected,
            h.app.data_location,
            h.app.tab,
        );
        h.hex(HexAction::ShowListing {
            address: 0x1108,
            length: 1,
        });
        assert!(!h.app.program_scope());
        assert_eq!(
            (
                h.app.history.clone(),
                h.app.history_index,
                h.app.selected,
                h.app.data_location,
                h.app.tab,
            ),
            before
        );
        assert!(h.app.status.starts_with("No listing row"));
    }

    #[test]
    fn a_signature_edit_keeps_explicit_call_targets_as_code_for_back() {
        let mut h = queueing(dest_app());
        h.app.set_listing_scope(ListingScope::Function);
        let context = h.context.clone();
        // A call target outside the inventory, opened explicitly.
        h.app.navigate(0x10c0, true, &context);
        h.app.navigate(0x1040, true, &context);
        h.app.invalidate_signature_analysis();
        h.app.discovery_job = Some(mpsc::sync_channel(1).1);
        h.app.history_step(false, &context);
        assert_eq!(h.app.result_scope, Some(0x10c0), "code, not Hex");
        assert_ne!(h.app.tab, Tab::Hex);
        assert!(h.app.data_location.is_none());
    }
}
