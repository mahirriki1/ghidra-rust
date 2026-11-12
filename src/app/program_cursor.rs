//! The Program-scope Listing cursor. Every Program row is a stop: section
//! and function headers, instructions, `??` gaps, zero-filled tails and
//! pending bodies, and the byte rows of expanded gaps. Up/Down and
//! PageUp/PageDown cross functions and gaps; Home/End stay within the
//! cursor's function, expanded byte run or (on a header or gap without
//! one) section; Ctrl+Home/End reach the program's first and last rows.
//! Enter follows an instruction's target, expands a `??` row, collapses a
//! byte row's run, or opens the function a pointer-table witness row points
//! at; on import slot and string rows it does nothing. Data rows are stops
//! without an owner: they never follow, and Home/End reach their section's
//! bounds. `DesktopApp.selected` stays the cursor's address; the row's rank
//! only tells rows sharing that address apart.
//!
//! Once the cursor rests in a function other than the displayed one, the
//! Decompiler and Function Graph follow it: [`FOLLOW_REST`] after the last
//! move, with no listing key held, no dialog, text field or menu owning
//! input, a running worker and no request that a follow would have to
//! restart. Following is a quiet re-resolution: no history entry, no reveal
//! and no view move. Without a worker it never sends anything.

use std::time::Duration;

use eframe::egui;

use super::listing_cursor::{Command, filter_keys};
use super::program_listing::Reveal;
use super::{DesktopApp, Tab};
use crate::program_listing::{Layout, Position, Rank, Row};

/// Seconds of cursor rest before the displayed function follows it.
pub(super) const FOLLOW_REST: f64 = 0.2;

/// A follow armed by a cursor move. It lapses when the binary, the scope or
/// the selected address changes, and any explicit navigation drops it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Follow {
    /// Input time, in seconds, after which the cursor is at rest.
    due: f64,
    generation: u64,
    address: u64,
}

impl DesktopApp {
    pub(super) fn program_layout(&self) -> Option<Layout<'_>> {
        let rows = self.program.current_rows(self.generation)?;
        Some(
            rows.layout(&self.info.as_ref()?.functions, &self.program.expanded)
                .with_evidence(&self.program.evidence.index)
                .with_anchor(self.program.anchor),
        )
    }

    /// The row the cursor stands on: exactly a row starting at `selected`,
    /// or none, never a nearby row.
    pub(super) fn program_cursor(&self, layout: &Layout<'_>) -> Option<Row> {
        let address = self.selected?;
        let rank = self
            .program
            .cursor
            .filter(|position| position.address == address)
            .map(|position| position.rank);
        layout.cursor(address, rank)
    }

    /// Applies this batch's Program-scope listing keys and returns the held
    /// mask. Movement applies to the rows drawn last frame.
    pub(super) fn program_cursor_keys(
        &mut self,
        context: &egui::Context,
        page: usize,
        command: bool,
        held: u16,
    ) -> u16 {
        let layout = self.program_layout();
        let mut row = layout.and_then(|layout| self.program_cursor(&layout));
        let mut moved = false;
        let mut follow = None;
        let mut toggle = None;
        let mut witness = None;
        let held = context.input_mut(|input| {
            filter_keys(&mut input.events, held, command, true, |action| {
                let Some(layout) = layout else {
                    return false;
                };
                if action == Command::Enter {
                    match row {
                        Some(Row::Instruction { owner, start, .. }) => {
                            follow = self
                                .row_follow_target(owner, start)
                                .map(|target| (owner, target));
                        }
                        Some(row @ (Row::Undefined { .. } | Row::Byte { .. })) => {
                            toggle = Some(row);
                        }
                        Some(Row::Data {
                            kind: crate::listing_evidence::EvidenceKind::Pointer { entry, .. },
                            ..
                        }) => witness = Some(entry),
                        _ => {}
                    }
                    return follow.is_some() || toggle.is_some() || witness.is_some();
                }
                if let Some(next) = self.program_step(&layout, row, action, page) {
                    row = Some(next);
                }
                moved = true;
                false
            })
        });
        if moved && let Some(row) = row {
            self.move_program_cursor(row, context);
            context.request_repaint();
        }
        if let Some(row) = toggle {
            self.toggle_bytes(row);
            context.request_repaint();
        }
        if let Some((owner, target)) = follow {
            self.program.follow = None;
            self.follow_row_target(owner, target, context);
            context.request_repaint();
            return 0;
        }
        if let Some(entry) = witness {
            self.follow_witness(entry, context);
            context.request_repaint();
            return 0;
        }
        held
    }

    /// Where `action` takes a cursor on `row`. Without a cursor row,
    /// movement starts at the viewport's edge: Down and PageDown land on
    /// the first fully shown row, Up and PageUp on the last.
    fn program_step(
        &self,
        layout: &Layout<'_>,
        row: Option<Row>,
        action: Command,
        page: usize,
    ) -> Option<Row> {
        let walk = |mut row: Row, steps: usize, forward: bool| {
            for _ in 0..steps {
                let next = if forward {
                    layout.next(&row)
                } else {
                    layout.previous(&row)
                };
                match next {
                    Some(next) => row = next,
                    None => break,
                }
            }
            row
        };
        let edge = |last: bool| {
            self.program
                .edges()
                .and_then(|(first, end)| layout.resolve(if last { end } else { first }))
                .or_else(|| layout.first())
        };
        match action {
            Command::First => layout.first(),
            Command::Last => layout.last(),
            Command::Home | Command::End => {
                let (first, last) = self.row_extent(layout, row.or_else(|| edge(false))?)?;
                Some(if action == Command::Home { first } else { last })
            }
            Command::Up | Command::PageUp => {
                let steps = if action == Command::Up { 1 } else { page };
                row.map_or_else(|| edge(true), |row| Some(walk(row, steps, false)))
            }
            Command::Down | Command::PageDown => {
                let steps = if action == Command::Down { 1 } else { page };
                row.map_or_else(|| edge(false), |row| Some(walk(row, steps, true)))
            }
            Command::Enter => row,
        }
    }

    /// The rows Home and End reach from `row`: its function's first and
    /// last decoded instructions; an expanded run's first and last bytes
    /// from a byte row; a section's first and last rows from a section
    /// header, gap, data row or zero-filled tail.
    fn row_extent(&self, layout: &Layout<'_>, row: Row) -> Option<(Row, Row)> {
        match row {
            Row::Byte { address } => {
                let (start, end) = layout.byte_run(address)?;
                Some((Row::Byte { address: start }, Row::Byte { address: end - 1 }))
            }
            Row::Function { entry }
            | Row::Pending { entry, .. }
            | Row::Instruction { owner: entry, .. } => self.function_extent(layout, entry),
            Row::Section { start, .. }
            | Row::Undefined { start, .. }
            | Row::Data { start, .. }
            | Row::ZeroFill { start, .. } => layout.section_bounds(start),
        }
    }

    /// The first and last instructions of `entry`'s loaded view that are
    /// Program rows. Without such a view: its header, then its pending row.
    fn function_extent(&self, layout: &Layout<'_>, entry: u64) -> Option<(Row, Row)> {
        let instruction = |address: u64| {
            layout
                .exact(Position::new(address, Rank::Body))
                .filter(|row| matches!(row, Row::Instruction { owner, .. } if *owner == entry))
        };
        if let Some((_, listing)) = self.row_view(entry) {
            let first = listing.iter().find_map(|i| instruction(i.address));
            let last = (0..listing.len())
                .rev()
                .find_map(|index| instruction(listing.get(index)?.address));
            if let (Some(first), Some(last)) = (first, last) {
                return Some((first, last));
            }
        }
        let header = layout.exact(Position::new(entry, Rank::Function))?;
        let pending = layout
            .exact(Position::new(entry, Rank::Body))
            .filter(|row| matches!(row, Row::Pending { .. }));
        Some((header, pending.unwrap_or(header)))
    }

    /// Puts the cursor on `row`, reveals it once and arms a follow when the
    /// row belongs to a function other than the displayed (or loading) one.
    /// Rows of the displayed function select as a click would; others clear
    /// the pseudocode highlight, which only the displayed mappings provide.
    pub(super) fn move_program_cursor(&mut self, row: Row, context: &egui::Context) {
        let position = row.position();
        let address = position.address;
        let owner = row.function();
        // The cursor supersedes the exact instruction a loading function
        // would otherwise select (and reveal in its graph) on arrival.
        self.reference_focus = owner
            .filter(|&owner| {
                self.result_scope == Some(owner) && self.view().is_none_or(|v| v.address != owner)
            })
            .map(|owner| (owner, address));
        if owner.is_some() && owner == self.view().map(|view| view.address) {
            if self.selected != Some(address) || !self.semantic.addresses.contains(&address) {
                self.select_instruction(address);
            }
            if let Some(canvas) = &mut self.canvas {
                canvas.reveal_instruction(address);
            }
        } else if self.selected != Some(address) || !self.semantic.addresses.is_empty() {
            self.data_location = None;
            self.set_selected_address(address);
            self.semantic.addresses.clear();
            self.semantic.ranges.clear();
        }
        // After the selection, which forgets the row of an explicit one.
        self.program.cursor = Some(position);
        self.program.reveal = Some(Reveal::Row(position));
        self.program.follow = owner
            .filter(|&owner| self.result_scope != Some(owner))
            .map(|_| Follow {
                due: context.input(|input| input.time) + FOLLOW_REST,
                generation: self.generation,
                address,
            });
        if self.program.follow.is_some() {
            context.request_repaint_after(Duration::from_secs_f64(FOLLOW_REST));
        }
    }

    fn follow_current(&self, follow: &Follow) -> bool {
        self.program_scope()
            && follow.generation == self.generation
            && self.selected == Some(follow.address)
    }

    /// Whether a worker is running. A follow never starts one: after a
    /// cancel, crash or deadline stop, resting sends nothing.
    fn follow_worker(&self) -> bool {
        #[cfg(test)]
        if self.program.assume_worker {
            return true;
        }
        self.client.is_some()
    }

    /// Whether following now would send at most one request, to a running
    /// worker, behind work already in flight: it never restarts or reopens
    /// the worker or supersedes a request the user is waiting on. Queued,
    /// unsent function requests are retired by the follow's own navigation.
    fn follow_may_send(&self) -> bool {
        use super::graph_preparation::Continuation;
        self.follow_worker()
            && self.opening.is_none()
            && self.pending.as_ref().is_none_or(super::queues_behind)
            && !self.graph_preparation.awaits(|continuation| {
                matches!(
                    continuation,
                    Continuation::Live { .. } | Continuation::Saved(_)
                )
            })
    }

    /// The per-frame deadline check: follows once the cursor has rested.
    /// Before the deadline it only schedules the frame that ends the rest.
    pub(super) fn poll_cursor_follow(&mut self, context: &egui::Context) {
        let Some(follow) = self.program.follow else {
            return;
        };
        if !self.follow_current(&follow) {
            self.program.follow = None;
            return;
        }
        let now = context.input(|input| input.time);
        if now < follow.due {
            context.request_repaint_after(Duration::from_secs_f64(follow.due - now));
            return;
        }
        // A held key, dialog, focused text field, open menu or request ends
        // with an event or reply, which brings the next frame; the follow
        // waits for it.
        if (self.tab == Tab::Listing && self.listing_keys_held())
            || self.navigation_shortcuts_blocked(context)
            || !self.follow_may_send()
        {
            return;
        }
        self.flush_cursor_follow(context);
    }

    /// Follows the cursor's function now, if a follow is armed, it may send
    /// without restarting or preempting the worker, and the cursor still
    /// stands on a row owned by a function not displayed. Otherwise the
    /// follow stays armed and sends nothing.
    pub(super) fn flush_cursor_follow(&mut self, context: &egui::Context) {
        if !self.follow_may_send() {
            return;
        }
        let Some(follow) = self.program.follow.take() else {
            return;
        };
        if !self.follow_current(&follow) {
            return;
        }
        let Some(owner) = self
            .program_layout()
            .and_then(|layout| self.program_cursor(&layout))
            .and_then(|row| row.function())
        else {
            return;
        };
        if self.result_scope != Some(owner) {
            self.reresolve_displayed(owner, Some(follow.address), context);
            context.request_repaint();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::super::program_listing::ListingScope;
    use super::super::tests as fixture;
    use super::super::{Pending, Tab};
    use super::*;
    use crate::model::{
        BasicBlock, FunctionInfo, FunctionView, Instruction, ListingBinding, ListingOutcome,
        Request, Response, SectionInfo,
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

    fn listing_pending(app: &mut DesktopApp, entries: Vec<u64>) -> Pending {
        app.program.token += 1;
        Pending {
            id: 1,
            request: Request::Listing {
                binding: ListingBinding {
                    generation: app.generation,
                    token: app.program.token,
                },
                entries: entries.clone(),
            },
            started: Instant::now(),
            selection: app.selection_generation,
            revision: app.revision,
            byte_origin: (app.selected, app.tab),
            bytes: None,
            result: app.results.binding(entries[0], String::new()),
        }
    }

    /// `.text` 0x1000–0x1100 holds `entry` (displayed, four rows), `next`
    /// (two) and `third` (two), each followed by a `??` gap; `.data` is one
    /// gap. Rows: section, entry, 4 × code, ??, next, 2 × code, ??, third,
    /// 2 × code, ??, section, ??.
    fn program_app() -> DesktopApp {
        let context = egui::Context::default();
        let mut app = fixture::keyboard_app();
        let info = app.info.as_mut().unwrap();
        info.sections.push(SectionInfo {
            name: ".data".into(),
            address: 0x2000,
            size: 0x40,
            file_offset: 0x100,
            file_size: 0x40,
            executable: false,
        });
        info.file_len = 0x140;
        info.functions.push(FunctionInfo {
            address: 0x1080,
            name: "third".into(),
        });
        let functions = info.functions.clone();
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
        let pending = listing_pending(&mut app, vec![0x1040, 0x1080]);
        let response = Response::Listing {
            binding: match &pending.request {
                Request::Listing { binding, .. } => *binding,
                _ => unreachable!(),
            },
            outcomes: vec![
                ListingOutcome {
                    entry: 0x1040,
                    view: Some(view(0x1040, 2)),
                },
                ListingOutcome {
                    entry: 0x1080,
                    view: Some(view(0x1080, 2)),
                },
            ],
        };
        app.receive(pending, response, &context);
        app.history = vec![crate::linkage_ui::Place::Code(0x1000)];
        app.program.assume_worker = true;
        app
    }

    fn key(key: egui::Key, repeat: bool, modifiers: egui::Modifiers) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat,
            modifiers,
        }
    }

    fn press(k: egui::Key) -> egui::Event {
        key(k, false, egui::Modifiers::NONE)
    }

    fn release(key: egui::Key) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: false,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }

    /// Frames through the Listing pane, then menu release and the global
    /// shortcuts, at `step` seconds of input time per frame.
    struct Harness {
        context: egui::Context,
        app: DesktopApp,
        time: f64,
        step: f64,
        editor: bool,
        remaining: Vec<egui::Event>,
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
                step: 0.5,
                editor: false,
                remaining: Vec::new(),
            };
            harness.frame(vec![]);
            harness.frame(vec![]);
            harness
        }

        fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
            self.time += self.step;
            let Self {
                context,
                app,
                remaining,
                editor,
                ..
            } = self;
            let editor = *editor;
            let mut text = String::new();
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(700.0, 600.0),
                    )),
                    time: Some(self.time),
                    events,
                    ..Default::default()
                },
                |ui| {
                    if editor {
                        ui.add(egui::TextEdit::singleline(&mut text))
                            .request_focus();
                    }
                    app.main_panel(ui);
                    *remaining = ui.input(|input| input.events.clone());
                    // As `draw` ends a frame.
                    app.release_menu(ui.ctx());
                    app.handle_shortcuts(ui.ctx());
                    app.poll_cursor_follow(ui.ctx());
                },
            );
            output.textures_delta.clear();
            output
        }

        fn tap(&mut self, k: egui::Key, modifiers: egui::Modifiers) {
            self.frame(vec![key(k, false, modifiers), release(k)]);
        }

        /// Clicks the instruction row at `address` to activate the keys.
        fn click(&mut self, address: u64) {
            let point = self.point(address);
            self.frame(fixture::pointer_events(point));
        }

        fn point(&mut self, address: u64) -> egui::Pos2 {
            let output = self.frame(vec![]);
            let needle = format!("{address:08x}");
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text)
                        if text.galley.text().split_whitespace().next() == Some(&needle) =>
                    {
                        Some(text.pos + text.galley.rect.center().to_vec2())
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("row {needle} is rendered"))
        }

        fn cursor(&self) -> Option<Row> {
            let layout = self.app.program_layout()?;
            self.app.program_cursor(&layout)
        }

        /// The painted disclosure triangle of the row at `address`.
        fn disclosure(&mut self, address: u64) -> egui::Pos2 {
            let row = self.point(address);
            let output = self.frame(vec![]);
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text)
                        if text.galley.text() == "??"
                            && (text.pos.y + text.galley.rect.center().y - row.y).abs() < 2.0 =>
                    {
                        Some(egui::pos2(text.pos.x - 4.0, row.y))
                    }
                    _ => None,
                })
                .expect("the row's mnemonic")
        }

        fn double_click(&mut self, point: egui::Pos2) {
            self.frame(fixture::pointer_events(point));
            self.time -= self.step - 0.1;
            self.frame(fixture::pointer_events(point));
        }

        fn graph_requests(&self) -> usize {
            let graph = |r: &Request| matches!(r, Request::Graph { .. });
            self.app.queue.iter().filter(|r| graph(r)).count()
                + usize::from(self.app.pending.as_ref().is_some_and(|p| graph(&p.request)))
        }

        fn left_over(&self, wanted: egui::Key) -> bool {
            self.remaining.iter().any(|event| {
                matches!(event, egui::Event::Key { key, pressed: true, .. } if *key == wanted)
            })
        }
    }

    /// The rows Down visits from the `entry` header to the end.
    fn walk(h: &mut Harness) -> Vec<Row> {
        let mut seen = Vec::new();
        for _ in 0..32 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
            let row = h.cursor().expect("the cursor is on a row");
            if seen.last() == Some(&row) {
                break;
            }
            seen.push(row);
        }
        seen
    }

    #[test]
    fn down_visits_every_row_and_up_reverses_it() {
        let mut h = Harness::new(program_app());
        h.click(0x1000);
        // Instruction 0x1000 first; the section and entry headers above.
        assert_eq!(
            h.cursor(),
            Some(Row::Instruction {
                owner: 0x1000,
                start: 0x1000,
                end: 0x1004
            })
        );
        h.tap(egui::Key::ArrowUp, egui::Modifiers::NONE);
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1000 }));
        assert_eq!(h.app.selected, Some(0x1000));
        let down = walk(&mut h);
        assert_eq!(down.len(), 15, "{down:?}");
        assert!(down.contains(&Row::Undefined {
            start: 0x1010,
            end: 0x1040
        }));
        assert!(down.contains(&Row::Section {
            section: 1,
            start: 0x2000
        }));
        // Each stop selects exactly its row's address.
        let mut up = Vec::new();
        for _ in 0..down.len() {
            up.push(h.cursor().unwrap());
            assert_eq!(h.app.selected, Some(up.last().unwrap().position().address));
            h.tap(egui::Key::ArrowUp, egui::Modifiers::NONE);
        }
        up.reverse();
        assert_eq!(up, down);
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1000 }));
    }

    #[test]
    fn holding_down_across_functions_follows_once_at_rest_without_history() {
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        // Requests queue behind a background Listing instead of restarting.
        let pending = listing_pending(&mut h.app, vec![0x1080]);
        h.app.pending = Some(pending);
        let (generation, history) = (h.app.selection_generation, h.app.history.clone());
        h.step = 0.05;
        h.frame(vec![press(egui::Key::ArrowDown)]);
        // Held across `next` and into `third` (thirteen rows), with OS
        // repeats far apart: no request, no navigation, no history.
        h.step = 0.5;
        for _ in 0..7 {
            h.frame(vec![key(egui::Key::ArrowDown, true, egui::Modifiers::NONE)]);
            assert_eq!(h.graph_requests(), 0);
            assert_eq!(h.app.result_scope, Some(0x1000));
            assert_eq!(h.app.selection_generation, generation);
            assert!(h.app.program.follow.is_some() || h.cursor().unwrap().function().is_none());
        }
        assert_eq!(h.app.selected, Some(0x1084), "third's second row");
        // Released: the rest is measured from the last move.
        h.step = 0.05;
        h.frame(vec![release(egui::Key::ArrowDown)]);
        assert_eq!(
            h.graph_requests(),
            0,
            "the deadline is measured from the move"
        );
        h.frame(vec![]);
        assert_eq!(h.graph_requests(), 0);
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert_eq!(h.graph_requests(), 1);
        assert!(
            h.app
                .queue
                .iter()
                .any(|r| matches!(r, Request::Graph { address: 0x1080 }))
        );
        assert_eq!(h.app.result_scope, Some(0x1080));
        assert_eq!(h.app.selected, Some(0x1084), "the cursor stays");
        assert_eq!(h.app.history, history, "cursor travel adds no history");
        assert!(h.app.program.follow.is_none());
        for _ in 0..4 {
            h.frame(vec![]);
        }
        assert_eq!(h.graph_requests(), 1, "exactly one follow");
    }

    #[test]
    fn follow_never_moves_the_view_or_pins_it_and_waits_for_user_requests() {
        let context = egui::Context::default();
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
        // A Graph request the user started holds the follow back.
        h.app.pending = Some(Pending {
            request: Request::Graph { address: 0x1000 },
            ..listing_pending(&mut h.app, vec![0x1040])
        });
        // As a user scroll would: the move's pin ends.
        h.app.program.pin = None;
        let top = h.app.program.top;
        let generation = h.app.selection_generation;
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.app.selection_generation, generation, "waits");
        }
        h.app.pending = None;
        h.frame(vec![]);
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.app.selected, Some(0x1040));
        // The followed function's graph arrives and selects quietly.
        let pending = Pending {
            request: Request::Graph { address: 0x1040 },
            result: h.app.results.binding(0x1040, String::new()),
            selection: h.app.selection_generation,
            ..listing_pending(&mut h.app, vec![0x1040])
        };
        h.app.receive(
            pending,
            Response::Graph {
                view: view(0x1040, 2),
            },
            &context,
        );
        h.app.settle_graph();
        assert_eq!(h.app.view().map(|v| v.address), Some(0x1040));
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.app.program.top, top, "the view does not move");
            assert!(h.app.program.pin.is_none(), "and is not pinned");
            assert!(h.app.program.reveal.is_none());
        }
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
        assert!(h.app.undisplayed_call.is_none());
        // Back in the displayed function, nothing is armed.
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert!(h.app.program.follow.is_none());
        // Gaps have no owner: resting there follows nothing.
        for _ in 0..2 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        assert!(matches!(h.cursor(), Some(Row::Undefined { .. })));
        assert!(h.app.program.follow.is_none());
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert_eq!(h.app.result_scope, Some(0x1040));
    }

    #[test]
    fn space_flushes_a_pending_follow_and_navigation_cancels_it() {
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.step = 0.05;
        for _ in 0..3 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        assert_eq!(h.app.selected, Some(0x1040), "next's first instruction");
        assert!(h.app.program.follow.is_some());
        h.tap(egui::Key::Space, egui::Modifiers::NONE);
        assert_eq!(h.app.tab, Tab::Graph);
        assert_eq!(h.app.result_scope, Some(0x1040), "flushed first");
        assert_eq!(h.app.selected, Some(0x1040));
        assert_eq!(h.app.history.len(), 1);

        // An explicit navigation drops an armed follow.
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.step = 0.05;
        for _ in 0..3 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        assert!(h.app.program.follow.is_some());
        h.tap(egui::Key::ArrowDown, egui::Modifiers::CTRL);
        assert_eq!(
            h.app.result_scope,
            Some(0x1080),
            "Ctrl+Down from the cursor"
        );
        assert!(h.app.program.follow.is_none());
        h.step = 0.5;
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert_eq!(h.app.result_scope, Some(0x1080));
    }

    #[test]
    fn space_never_preempts_a_request_the_user_is_waiting_on() {
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.step = 0.05;
        for _ in 0..3 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        assert!(h.app.program.follow.is_some());
        // A user scan is running: following now would restart the worker.
        h.app.pending = Some(Pending {
            request: Request::Strings,
            result: None,
            ..listing_pending(&mut h.app, vec![0x1040])
        });
        let epoch = h.app.worker_epoch;
        h.tap(egui::Key::Space, egui::Modifiers::NONE);
        assert_eq!(h.app.tab, Tab::Graph, "Space still toggles");
        assert_eq!(h.app.result_scope, Some(0x1000), "nothing followed");
        assert!(h.app.program.follow.is_some(), "the switch keeps waiting");
        assert_eq!(h.app.worker_epoch, epoch, "never restarted");
        assert!(matches!(
            h.app.pending.as_ref().map(|p| &p.request),
            Some(Request::Strings)
        ));
        // Once the scan ends, the waiting switch goes.
        h.app.pending = None;
        h.step = 0.5;
        h.frame(vec![]);
        assert_eq!(h.app.result_scope, Some(0x1040));
    }

    #[test]
    fn home_end_stay_in_the_function_or_section_and_ctrl_reaches_the_ends() {
        let ctrl = egui::Modifiers::CTRL;
        let none = egui::Modifiers::NONE;
        let mut h = Harness::new(program_app());
        h.click(0x1044);
        h.tap(egui::Key::End, none);
        assert_eq!(h.app.selected, Some(0x1044));
        h.tap(egui::Key::Home, none);
        assert_eq!(h.app.selected, Some(0x1040));
        // From the header too.
        h.tap(egui::Key::ArrowUp, none);
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
        h.tap(egui::Key::End, none);
        assert_eq!(h.app.selected, Some(0x1044));
        // On a gap: its section's first and last rows.
        h.tap(egui::Key::ArrowDown, none);
        assert!(matches!(
            h.cursor(),
            Some(Row::Undefined { start: 0x1048, .. })
        ));
        h.tap(egui::Key::End, none);
        assert_eq!(
            h.cursor(),
            Some(Row::Undefined {
                start: 0x1088,
                end: 0x1100
            })
        );
        h.tap(egui::Key::Home, none);
        assert_eq!(
            h.cursor(),
            Some(Row::Section {
                section: 0,
                start: 0x1000
            })
        );
        h.tap(egui::Key::End, ctrl);
        assert_eq!(
            h.cursor(),
            Some(Row::Undefined {
                start: 0x2000,
                end: 0x2040
            })
        );
        h.tap(egui::Key::Home, none);
        assert_eq!(
            h.cursor(),
            Some(Row::Section {
                section: 1,
                start: 0x2000
            })
        );
        h.tap(egui::Key::Home, ctrl);
        assert_eq!(
            h.cursor(),
            Some(Row::Section {
                section: 0,
                start: 0x1000
            })
        );
        // Ctrl+Home never repeats, and the Function scope leaves it alone.
        h.frame(vec![key(egui::Key::Home, false, ctrl)]);
        h.app.select_instruction(0x1044);
        h.frame(vec![key(egui::Key::Home, true, ctrl)]);
        assert_eq!(h.app.selected, Some(0x1044));
        h.frame(vec![release(egui::Key::Home)]);
        assert!(!h.app.listing_keys_held(), "released without its modifier");
        let mut app = program_app();
        app.set_listing_scope(ListingScope::Function);
        let mut h = Harness::new(app);
        h.click(0x1000);
        h.tap(egui::Key::End, ctrl);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(h.left_over(egui::Key::End), "not a Function-scope key");
    }

    #[test]
    fn back_to_an_instruction_of_a_cached_function_opens_its_owner() {
        let context = egui::Context::default();
        let mut app = program_app();
        // `next`'s second instruction, known only from its cached body.
        let code = crate::linkage_ui::Place::Code;
        app.history = vec![code(0x1044), code(0x1000)];
        app.history_index = 1;
        app.history_jump(0, &context);
        assert_eq!(
            app.result_scope,
            Some(0x1040),
            "its proved owner, never a function guessed at the address"
        );
        assert_eq!(app.selected, Some(0x1044));
    }

    #[test]
    fn a_cursor_on_no_row_starts_at_the_viewport_edge() {
        let mut h = Harness::new(program_app());
        h.click(0x1000);
        // Inside the gap after `entry`, where no row starts.
        h.app.select_instruction(0x1020);
        h.frame(vec![]);
        assert_eq!(h.cursor(), None);
        let (first, last) = h.app.program.shown.unwrap();
        assert!(first.address < 0x1010 && last.address > 0x1040);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.cursor().map(|row| row.position()), Some(first));
        h.app.select_instruction(0x1020);
        h.frame(vec![]);
        h.tap(egui::Key::ArrowUp, egui::Modifiers::NONE);
        let (_, last) = h.app.program.shown.unwrap();
        assert_eq!(h.cursor().map(|row| row.position()), Some(last));
        assert_ne!(h.app.selected, Some(0x1010), "never the nearest row");
    }

    #[test]
    fn program_keys_keep_the_focus_modal_and_repeat_guards() {
        // A text field owns the keys and releases the Listing.
        let mut h = Harness::new(program_app());
        h.click(0x1000);
        h.editor = true;
        h.frame(vec![]);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.app.selected, Some(0x1000));
        h.editor = false;
        h.frame(vec![]);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.app.selected, Some(0x1000), "a new click is needed");
        assert!(h.left_over(egui::Key::ArrowDown));

        // A modal dialog keeps them, and holds an armed follow.
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.step = 0.05;
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert!(h.app.program.follow.is_some());
        h.app.help_dialog = Some(crate::help::HelpDialog::Shortcuts);
        let selected = h.app.selected;
        h.step = 0.5;
        for k in [egui::Key::ArrowDown, egui::Key::End, egui::Key::Enter] {
            h.tap(k, egui::Modifiers::NONE);
            assert_eq!(h.app.selected, selected);
            assert!(h.left_over(k));
        }
        assert_eq!(h.app.result_scope, Some(0x1000), "no follow under a dialog");
        h.app.help_dialog = None;
        h.frame(vec![]);
        assert_eq!(h.app.result_scope, Some(0x1040), "then it follows");

        // A repeat needs its own accepted press.
        let mut h = Harness::new(program_app());
        h.frame(vec![press(egui::Key::ArrowDown)]);
        h.click(0x1000);
        h.frame(vec![key(egui::Key::ArrowDown, true, egui::Modifiers::NONE)]);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(!h.left_over(egui::Key::ArrowDown), "still the Listing's");
        h.frame(vec![release(egui::Key::ArrowDown)]);
        h.frame(vec![press(egui::Key::ArrowDown)]);
        h.frame(vec![key(egui::Key::ArrowDown, true, egui::Modifiers::NONE)]);
        assert_eq!(h.app.selected, Some(0x1008));
        // A held key blocks the follow until released.
        h.app.program.follow = Some(Follow {
            due: 0.0,
            generation: h.app.generation,
            address: 0x1008,
        });
        h.frame(vec![]);
        assert!(h.app.program.follow.is_some(), "held");
        h.frame(vec![release(egui::Key::ArrowDown)]);
        assert!(h.app.program.follow.is_none());
    }

    #[test]
    fn enter_follows_from_the_rows_own_view() {
        let mut app = program_app();
        // `next` calls `third`; its view is cached, not displayed.
        let mut next = view(0x1040, 2);
        next.calls.push(crate::model::CallSite {
            address: 0x1044,
            target: Some(0x1080),
            no_return: None,
        });
        let body = crate::program_listing::CachedBody::new(next, None).unwrap();
        app.program.cache.insert(0x1040, body, 0x1040, |_| true);
        let mut h = Harness::new(app);
        h.click(0x100c);
        h.step = 0.05;
        for _ in 0..4 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        assert_eq!(h.app.selected, Some(0x1044));
        h.tap(egui::Key::Enter, egui::Modifiers::NONE);
        assert_eq!(h.app.selected, Some(0x1080));
        assert_eq!(h.app.result_scope, Some(0x1080));
        assert_eq!(
            h.app
                .history
                .iter()
                .map(|place| place.address())
                .collect::<Vec<_>>(),
            [0x1044, 0x1080],
            "an explicit navigation, departing from the cursor"
        );
        assert!(h.app.program.follow.is_none());
    }

    /// Clicks `entry`'s row at 0x100c and moves onto `next`'s first
    /// instruction, arming a follow that is not yet due.
    fn armed() -> Harness {
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.step = 0.05;
        for _ in 0..3 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        assert_eq!(h.app.selected, Some(0x1040));
        assert!(h.app.program.follow.is_some());
        h.step = 0.5;
        h
    }

    #[test]
    fn a_follow_waits_while_a_text_field_or_menu_owns_input() {
        let mut h = armed();
        h.editor = true;
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.app.result_scope, Some(0x1000), "a text field has focus");
            assert!(h.app.program.follow.is_some(), "and the follow waits");
        }
        h.editor = false;
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.app.selected, Some(0x1040));

        let mut h = armed();
        // Opened before the cursor has rested.
        h.step = 0.05;
        let point = h.point(0x1044);
        h.frame(fixture::secondary_events(point));
        assert!(egui::Popup::is_any_open(&h.context));
        assert!(h.app.program.follow.is_some(), "a menu does not select");
        h.step = 0.5;
        for _ in 0..3 {
            h.frame(vec![]);
            assert_eq!(h.app.result_scope, Some(0x1000), "a menu is open");
            assert!(h.app.program.follow.is_some());
        }
        h.tap(egui::Key::Escape, egui::Modifiers::NONE);
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert!(!egui::Popup::is_any_open(&h.context));
        assert_eq!(h.app.result_scope, Some(0x1040));
    }

    #[test]
    fn without_a_worker_resting_and_space_send_nothing() {
        let mut app = program_app();
        app.program.assume_worker = false;
        app.binary_path = Some("/nonexistent/ghidra-rust-follow".into());
        app.worker_epoch = 5;
        let mut h = Harness::new(app);
        h.click(0x100c);
        for _ in 0..3 {
            h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        }
        for _ in 0..3 {
            h.frame(vec![]);
        }
        h.tap(egui::Key::Space, egui::Modifiers::NONE);
        assert_eq!(h.app.tab, Tab::Graph);
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert_eq!(h.app.selected, Some(0x1040), "the cursor stays");
        assert_eq!(h.app.result_scope, Some(0x1000));
        assert_eq!(h.app.worker_epoch, 5, "never restarted");
        assert!(h.app.opening.is_none() && h.app.pending.is_none());
        assert!(h.app.queue.is_empty());
    }

    #[test]
    fn renaming_from_another_functions_header_keeps_the_cursor_and_follow() {
        let mut h = Harness::new(program_app());
        h.click(0x100c);
        h.step = 0.05;
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        h.tap(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
        let pending = Pending {
            request: Request::Rename {
                address: 0x1040,
                name: "renamed".into(),
            },
            result: None,
            ..listing_pending(&mut h.app, vec![0x1040])
        };
        let context = h.context.clone();
        h.app.receive(
            pending,
            Response::Renamed {
                address: 0x1040,
                name: "renamed".into(),
            },
            &context,
        );
        assert_eq!(h.app.selected, Some(0x1040), "the cursor stays on next");
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
        assert!(h.app.program.follow.is_some(), "and its follow");
        assert!(h.app.undisplayed_call.is_none());
        h.step = 0.5;
        h.frame(vec![]);
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
    }

    #[test]
    fn an_explicit_navigation_forgets_the_row_kind() {
        let mut h = Harness::new(program_app());
        h.click(0x1004);
        h.tap(egui::Key::Home, egui::Modifiers::CTRL);
        assert_eq!(
            h.cursor(),
            Some(Row::Section {
                section: 0,
                start: 0x1000
            })
        );
        h.tap(egui::Key::ArrowDown, egui::Modifiers::CTRL);
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.app.program.cursor, None, "the row kind is forgotten");
        assert!(matches!(
            h.cursor(),
            Some(Row::Instruction { start: 0x1040, .. })
        ));
        // History recorded the header it left, and Back lands exactly there
        // without reopening its address's function.
        assert_eq!(
            h.app.history[0],
            crate::linkage_ui::Place::Listing {
                address: 0x1000,
                rank: Rank::Section
            }
        );
        h.tap(egui::Key::ArrowLeft, egui::Modifiers::ALT);
        assert_eq!(h.app.selected, Some(0x1000));
        assert_eq!(
            h.cursor(),
            Some(Row::Section {
                section: 0,
                start: 0x1000
            })
        );
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.graph_requests(), 0);
    }

    #[test]
    fn enter_toggles_gaps_in_place_without_navigating() {
        let none = egui::Modifiers::NONE;
        let mut h = Harness::new(program_app());
        // Gap rows are clickable cursor stops without an owner to follow.
        let before = (
            h.app.selection_generation,
            h.app.history.clone(),
            h.app.result_scope,
        );
        h.click(0x1010);
        let gap = Row::Undefined {
            start: 0x1010,
            end: 0x1040,
        };
        assert_eq!(h.cursor(), Some(gap));
        assert!(h.app.program.follow.is_none());
        let y = h.point(0x1010).y;
        h.tap(egui::Key::Enter, none);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x1010 }));
        assert_eq!(h.point(0x1010).y, y, "the toggled row stays put");
        assert_eq!(h.point(0x1011).y, y + theme::ROW_HEIGHT);
        // Byte rows are stops; Home/End reach the run's first and last bytes.
        h.tap(egui::Key::ArrowDown, none);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x1011 }));
        h.tap(egui::Key::End, none);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x103f }));
        h.tap(egui::Key::ArrowDown, none);
        assert_eq!(h.cursor(), Some(Row::Function { entry: 0x1040 }));
        h.tap(egui::Key::ArrowUp, none);
        h.tap(egui::Key::Home, none);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x1010 }));
        assert_eq!(h.app.program.expanded.len(), 1);
        // Collapsing from inside a run scrolled partly above the view: the
        // collapsed row takes the toggled row's place and gets the cursor.
        // (`.data`'s bytes keep enough rows below to avoid the end clamp.)
        h.app.program.expanded.expand(0x1088, 0x1100, None);
        h.app.program.expanded.expand(0x2000, 0x2040, None);
        h.app.program.pin = None;
        h.app.program.top = Some(Position::new(0x10a0, Rank::Body));
        h.frame(vec![]);
        h.click(0x10a2);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x10a2 }));
        let y = h.point(0x10a2).y;
        h.tap(egui::Key::Enter, none);
        assert_eq!(
            h.cursor(),
            Some(Row::Undefined {
                start: 0x1088,
                end: 0x1100
            })
        );
        assert_eq!(h.app.selected, Some(0x1088));
        assert_eq!(h.point(0x1088).y, y);
        assert!(h.app.program.expanded.covering(0x10a2).is_none());
        // Nothing of this navigated, re-selected or recorded history.
        assert_eq!(
            (
                h.app.selection_generation,
                h.app.history.clone(),
                h.app.result_scope
            ),
            before
        );
        assert!(h.app.program.follow.is_none());
        assert!(h.graph_requests() == 0);
    }

    #[test]
    fn a_collapse_joining_the_collapsed_part_before_it_keeps_the_cursor() {
        let mut h = Harness::new(program_app());
        // Only the end of the gap is expanded: `??` 0x1010–0x1020, then bytes.
        h.app.program.expanded.expand(0x1020, 0x1040, None);
        h.click(0x1025);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x1025 }));
        let y = h.point(0x1020).y;
        h.tap(egui::Key::Enter, egui::Modifiers::NONE);
        let joined = Row::Undefined {
            start: 0x1010,
            end: 0x1040,
        };
        assert_eq!(h.cursor(), Some(joined), "on the joined row, not lost");
        assert_eq!(h.app.selected, Some(0x1010));
        assert_eq!(h.app.program.pin.map(|(at, _)| at), Some(joined.position()));
        // The joined row is drawn where the run's former `??` part was.
        assert_eq!(h.point(0x1010).y, y - theme::ROW_HEIGHT);
    }

    #[test]
    fn double_click_and_the_disclosure_triangle_toggle_gaps() {
        let mut h = Harness::new(program_app());
        h.step = 0.5;
        let point = h.point(0x1048);
        h.double_click(point);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x1048 }));
        assert!(h.app.program.expanded.covering(0x107f).is_some());
        // A double-click inside the run collapses it; the cursor moves to
        // its start.
        let point = h.point(0x104c);
        h.double_click(point);
        assert_eq!(
            h.cursor(),
            Some(Row::Undefined {
                start: 0x1048,
                end: 0x1080
            })
        );
        assert!(h.app.program.expanded.is_empty());
        // The triangle toggles without moving the cursor.
        let triangle = h.disclosure(0x1010);
        h.frame(fixture::pointer_events(triangle));
        assert!(h.app.program.expanded.covering(0x1010).is_some());
        assert_eq!(h.app.selected, Some(0x1048));
        let triangle = h.disclosure(0x1010);
        h.frame(fixture::pointer_events(triangle));
        assert!(h.app.program.expanded.is_empty());
        // Zero-filled tails never expand.
        let mut app = program_app();
        let info = app.info.as_mut().unwrap();
        info.sections[1].file_size = 0x20;
        let mut h = Harness::new(app);
        let point = h.point(0x2020);
        h.double_click(point);
        assert!(matches!(h.cursor(), Some(Row::ZeroFill { .. })));
        h.tap(egui::Key::Enter, egui::Modifiers::NONE);
        assert!(h.app.program.expanded.is_empty());
    }

    #[test]
    fn enter_toggles_only_with_the_keys_owned_and_never_repeats() {
        let none = egui::Modifiers::NONE;
        // A focused text field owns Enter.
        let mut h = Harness::new(program_app());
        h.click(0x1010);
        h.editor = true;
        h.frame(vec![]);
        h.tap(egui::Key::Enter, none);
        assert!(h.app.program.expanded.is_empty());
        // A modal dialog leaves Enter to itself.
        let mut h = Harness::new(program_app());
        h.click(0x1010);
        h.app.help_dialog = Some(crate::help::HelpDialog::Shortcuts);
        h.tap(egui::Key::Enter, none);
        assert!(h.app.program.expanded.is_empty());
        assert!(h.left_over(egui::Key::Enter));
        h.app.help_dialog = None;
        // A held Enter toggles once.
        h.frame(vec![press(egui::Key::Enter)]);
        for _ in 0..3 {
            h.frame(vec![key(egui::Key::Enter, true, none)]);
        }
        h.frame(vec![release(egui::Key::Enter)]);
        assert_eq!(h.cursor(), Some(Row::Byte { address: 0x1010 }));
        assert_eq!(h.app.program.expanded.len(), 1);
        // Headers do not toggle.
        h.tap(egui::Key::Home, egui::Modifiers::CTRL);
        h.tap(egui::Key::Enter, none);
        assert_eq!(h.app.program.expanded.len(), 1);
        // Without a click on the Listing, the keys are not its own.
        let mut h = Harness::new(program_app());
        h.app.select_instruction(0x1010);
        h.tap(egui::Key::Enter, none);
        assert!(h.app.program.expanded.is_empty(), "not clicked");
    }

    fn string(address: u64, length: u32) -> crate::model::StringEntry {
        crate::model::StringEntry {
            address,
            length: Some(length),
            text: "s".repeat(length as usize),
            encoding: "ASCII".into(),
        }
    }

    fn witness(source: u64, entry: u64) -> crate::model::FunctionAdmission {
        crate::model::FunctionAdmission {
            source,
            entry,
            reason: crate::model::AdmissionReason::PointerTable,
            encoding: crate::model::PointerEncoding::Absolute,
            owner: None,
            boundary: crate::model::BoundaryEvidence::Fde,
            table: None,
        }
    }

    /// [`program_app`] plus evidence: a string over `entry`'s code (no
    /// row), a string in the first `.text` gap, an import slot, a pointer
    /// witness to `next` and a string in `.data`, and a labelled global and
    /// an exported one in a new zero-filled `.bss`.
    fn evidence_app() -> DesktopApp {
        let context = egui::Context::default();
        let mut app = program_app();
        app.info.as_mut().unwrap().sections.push(SectionInfo {
            name: ".bss".into(),
            address: 0x3000,
            size: 0x1000,
            file_offset: 0x140,
            file_size: 0,
            executable: false,
        });
        app.strings = vec![string(0x100a, 4), string(0x1018, 8), string(0x2018, 8)];
        app.source_epochs.bump_strings();
        app.linkage.build(
            crate::linkage::Linkage {
                digest: String::new(),
                libraries: Box::new([]),
                exports: vec![crate::linkage::Export {
                    id: 0,
                    raw: Some("g_export".into()),
                    display: None,
                    ordinal: None,
                    version: None,
                    target: crate::linkage::ExportTarget::Data { address: 0x3800 },
                }]
                .into_boxed_slice(),
                gaps: Box::new([]),
                locations: Box::new([]),
                imports: vec![crate::linkage::Import {
                    id: 0,
                    raw: Some("printf".into()),
                    display: None,
                    ordinal: None,
                    library: None,
                    scope: None,
                    version: None,
                    kind: crate::linkage::ImportKind::Normal,
                    weak: false,
                    slot: Some(0x2000),
                    stub: None,
                }]
                .into_boxed_slice(),
            },
            &context,
        );
        for _ in 0..5000 {
            app.poll_linkage();
            if app.linkage.prepared().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(app.linkage.prepared().is_some());
        let mut state = crate::discovery::Discovery::new(None, [0x1000], false);
        state
            .pointer_recovery
            .admissions
            .insert(0x1040, witness(0x2010, 0x1040));
        app.discovery = Some(state);
        app.session.as_mut().unwrap().annotations.insert(
            0x3100,
            crate::session::Annotation {
                label: "g_counter".into(),
                ..Default::default()
            },
        );
        app.revision += 1;
        app
    }

    fn data(start: u64, end: u64, kind: crate::listing_evidence::EvidenceKind) -> Row {
        Row::Data { start, end, kind }
    }

    fn undefined(start: u64, end: u64) -> Row {
        Row::Undefined { start, end }
    }

    fn at(h: &Harness, address: u64) -> Option<Row> {
        h.app.program_layout()?.cursor(address, None)
    }

    #[test]
    fn data_rows_are_owner_less_stops_and_up_down_stay_exact() {
        use crate::listing_evidence::EvidenceKind::{ImportSlot, Pointer, String};
        let mut h = Harness::new(evidence_app());
        h.click(0x1000);
        h.tap(egui::Key::ArrowUp, egui::Modifiers::NONE);
        let down = walk(&mut h);
        let tail: Vec<Row> = down
            .iter()
            .copied()
            .skip_while(|row| {
                *row != Row::Section {
                    section: 1,
                    start: 0x2000,
                }
            })
            .collect();
        assert_eq!(
            tail,
            [
                Row::Section {
                    section: 1,
                    start: 0x2000
                },
                data(0x2000, 0x2008, ImportSlot(0)),
                undefined(0x2008, 0x2010),
                data(
                    0x2010,
                    0x2018,
                    Pointer {
                        source: 0x2010,
                        entry: 0x1040
                    }
                ),
                data(0x2018, 0x2020, String(2)),
                undefined(0x2020, 0x2040),
                Row::Section {
                    section: 2,
                    start: 0x3000
                },
                Row::ZeroFill {
                    start: 0x3000,
                    end: 0x3100
                },
                Row::ZeroFill {
                    start: 0x3100,
                    end: 0x3800
                },
                Row::ZeroFill {
                    start: 0x3800,
                    end: 0x4000
                },
            ]
        );
        // The string in the `.text` gap is a row; the one over code is not.
        assert!(down.contains(&data(0x1018, 0x1020, String(1))));
        assert!(down.contains(&undefined(0x1010, 0x1018)));
        assert!(
            !down
                .iter()
                .any(|row| matches!(row, Row::Data { start: 0x100a, .. }))
        );
        // Walking back up visits exactly the same rows.
        let mut up = Vec::new();
        for _ in 0..down.len() {
            up.push(h.cursor().unwrap());
            assert_eq!(h.app.selected, Some(up.last().unwrap().position().address));
            h.tap(egui::Key::ArrowUp, egui::Modifiers::NONE);
        }
        up.reverse();
        assert_eq!(up, down);
        // Data rows have no owner: resting on one never follows, and the
        // graph shows nothing related.
        h.click(0x2018);
        assert_eq!(h.cursor(), Some(data(0x2018, 0x2020, String(2))));
        assert!(h.app.program.follow.is_none());
        assert!(h.app.semantic.addresses.is_empty());
        for _ in 0..3 {
            h.frame(vec![]);
        }
        assert_eq!(h.graph_requests(), 0);
        // Home and End reach the section's bounds.
        h.tap(egui::Key::Home, egui::Modifiers::NONE);
        assert_eq!(
            h.cursor(),
            Some(Row::Section {
                section: 1,
                start: 0x2000
            })
        );
        h.tap(egui::Key::End, egui::Modifiers::NONE);
        assert_eq!(h.cursor(), Some(undefined(0x2020, 0x2040)));
    }

    #[test]
    fn enter_opens_a_witness_target_with_history_but_not_slots_or_strings() {
        let mut h = Harness::new(evidence_app());
        for address in [0x2000, 0x2018] {
            h.click(address);
            let (history, scope) = (h.app.history.clone(), h.app.result_scope);
            h.tap(egui::Key::Enter, egui::Modifiers::NONE);
            assert_eq!(h.app.selected, Some(address));
            assert_eq!(h.app.history, history);
            assert_eq!(h.app.result_scope, scope);
            assert_eq!(h.graph_requests(), 0);
            assert!(h.app.program.expanded.is_empty(), "data rows never expand");
        }
        h.click(0x2010);
        let before = h.app.history.len();
        h.tap(egui::Key::Enter, egui::Modifiers::NONE);
        assert_eq!(h.app.result_scope, Some(0x1040));
        assert_eq!(h.app.selected, Some(0x1040));
        assert!(h.app.history.len() > before, "recorded in history");
        // Double-clicking the witness row does the same.
        h.app.navigate(0x1000, true, &h.context.clone());
        let point = h.point(0x2010);
        h.double_click(point);
        assert_eq!(h.app.result_scope, Some(0x1040));
    }

    #[test]
    fn zero_fill_marks_are_addressable_without_reading_bytes() {
        let mut h = Harness::new(evidence_app());
        h.click(0x3100);
        assert_eq!(
            h.cursor(),
            Some(Row::ZeroFill {
                start: 0x3100,
                end: 0x3800
            })
        );
        h.frame(vec![]);
        assert!(h.app.program.bytes.is_empty());
        assert!(
            h.app
                .pending
                .iter()
                .map(|p| &p.request)
                .chain(&h.app.queue)
                .all(|r| !matches!(r, Request::Bytes { .. }))
        );
    }

    #[test]
    fn committed_witnesses_and_references_apply_without_a_rebuild() {
        use crate::listing_evidence::EvidenceKind::Pointer;
        let context = egui::Context::default();
        let mut h = Harness::new(evidence_app());
        let builds = h.app.program.evidence.builds;
        assert!(builds > 0);
        // One committed batch with a new witness into the `.data` gap.
        let mut state = h.app.discovery.take().unwrap();
        let added = witness(0x2028, 0x1080);
        state.pointer_recovery.admissions.insert(0x1080, added);
        h.app.deferred_discovery = Some(super::super::DiscoveryUpdate {
            budget_exhausted: false,
            partial_index: None,
            generation: h.app.generation,
            saved: std::sync::Arc::new(state.save()),
            state,
            publication: Ok(None),
        });
        h.app.poll_discovery(&context);
        h.frame(vec![]);
        let row = data(
            0x2028,
            0x2030,
            Pointer {
                source: 0x2028,
                entry: 0x1080,
            },
        );
        assert_eq!(at(&h, 0x2028), Some(row));
        assert_eq!(h.app.program.evidence.builds, builds, "no rebuild");
        // A later commit extends the run's references; the earlier witness
        // stays and the new data target splits the gap after it.
        let state = h.app.discovery.take().unwrap();
        let mut calls = crate::call_analysis::CallIndex::new(Default::default());
        calls.data_incoming.insert(0x2038, vec![0]);
        h.app.deferred_discovery = Some(super::super::DiscoveryUpdate {
            budget_exhausted: true,
            partial_index: Some(std::sync::Arc::new(calls)),
            generation: h.app.generation,
            saved: std::sync::Arc::new(state.save()),
            state,
            publication: Ok(None),
        });
        h.app.poll_discovery(&context);
        assert!(h.app.deferred_discovery.is_none());
        h.frame(vec![]);
        assert_eq!(h.app.program.evidence.builds, builds, "no rebuild");
        assert_eq!(at(&h, 0x2028), Some(row));
        assert_eq!(at(&h, 0x2038), Some(undefined(0x2038, 0x2040)));
        assert_eq!(at(&h, 0x2030), Some(undefined(0x2030, 0x2038)));
        // Another run's report replaces it: a rebuild, keeping the
        // committed witnesses.
        h.app.set_call_index(None);
        h.frame(vec![]);
        assert_eq!(h.app.program.evidence.builds, builds + 1);
        assert_eq!(at(&h, 0x2028), Some(row));
        assert_eq!(at(&h, 0x2030), Some(undefined(0x2030, 0x2040)));
    }

    #[test]
    fn a_rebuild_while_a_commit_is_in_flight_keeps_every_committed_witness() {
        use crate::listing_evidence::EvidenceKind::Pointer;
        let context = egui::Context::default();
        let mut h = Harness::new(evidence_app());
        let earlier = data(
            0x2010,
            0x2018,
            Pointer {
                source: 0x2010,
                entry: 0x1040,
            },
        );
        assert_eq!(at(&h, 0x2010), Some(earlier));
        // The state is away in its background commit, as `receive` takes
        // it, when a strings adoption forces a rebuild.
        let mut state = h.app.discovery.take().unwrap();
        h.app.source_epochs.bump_strings();
        h.frame(vec![]);
        assert!(h.app.program_evidence_current());
        assert_ne!(at(&h, 0x2010), Some(earlier), "no witnesses while away");
        let added = witness(0x2028, 0x1080);
        state.pointer_recovery.admissions.insert(0x1080, added);
        h.app.deferred_discovery = Some(super::super::DiscoveryUpdate {
            budget_exhausted: false,
            partial_index: None,
            generation: h.app.generation,
            saved: std::sync::Arc::new(state.save()),
            state,
            publication: Ok(None),
        });
        let builds = h.app.program.evidence.builds;
        h.app.poll_discovery(&context);
        h.frame(vec![]);
        assert_eq!(h.app.program.evidence.builds, builds, "in place");
        assert_eq!(at(&h, 0x2010), Some(earlier));
        assert!(matches!(
            at(&h, 0x2028),
            Some(Row::Data {
                kind: Pointer { entry: 0x1080, .. },
                ..
            })
        ));
    }

    #[test]
    fn signature_and_local_edits_do_not_rebuild_but_a_session_load_does() {
        let mut h = Harness::new(evidence_app());
        let builds = h.app.program.evidence.builds;
        // Revisions that touch no annotation keep the index.
        h.app.revision += 7;
        h.frame(vec![]);
        assert_eq!(h.app.program.evidence.builds, builds);
        h.app.program.evidence.replace_annotations();
        h.frame(vec![]);
        assert_eq!(h.app.program.evidence.builds, builds + 1);
    }

    #[test]
    fn label_and_comment_edits_and_undo_update_marks_in_place() {
        let context = egui::Context::default();
        let mut h = Harness::new(evidence_app());
        let builds = h.app.program.evidence.builds;
        assert_eq!(at(&h, 0x2030), None, "inside the gap");
        h.app.edit_annotation(
            0x2030,
            crate::session::Annotation {
                label: "g_table".into(),
                ..Default::default()
            },
        );
        h.frame(vec![]);
        assert_eq!(at(&h, 0x2030), Some(undefined(0x2030, 0x2040)));
        h.app.edit_annotation(
            0x2030,
            crate::session::Annotation {
                comment: "kept".into(),
                ..Default::default()
            },
        );
        h.frame(vec![]);
        assert_eq!(at(&h, 0x2030), Some(undefined(0x2030, 0x2040)));
        h.app
            .edit_annotation(0x2030, crate::session::Annotation::default());
        h.frame(vec![]);
        assert_eq!(at(&h, 0x2030), None, "both empty: unmarked");
        h.app.undo(&context);
        h.frame(vec![]);
        assert_eq!(at(&h, 0x2030), Some(undefined(0x2030, 0x2040)));
        h.app.undo(&context);
        h.app.undo(&context);
        h.frame(vec![]);
        assert_eq!(at(&h, 0x2030), None);
        assert_eq!(h.app.program.evidence.builds, builds, "no rebuild");
        // Clearing a zero-filled global's label joins its tail again.
        h.app
            .edit_annotation(0x3100, crate::session::Annotation::default());
        h.frame(vec![]);
        assert_eq!(at(&h, 0x3100), None);
        assert_eq!(
            at(&h, 0x3000),
            Some(Row::ZeroFill {
                start: 0x3000,
                end: 0x3800
            })
        );
    }

    #[test]
    fn a_binary_change_clears_the_evidence() {
        let mut h = Harness::new(evidence_app());
        assert!(h.app.program.evidence.index.covering(0x2000).is_some());
        h.app.generation += 1;
        assert!(!h.app.program_evidence_current());
        h.app.clear_views();
        assert!(h.app.program.evidence.index.covering(0x2000).is_none());
        assert!(!h.app.program_evidence_current());
        // Function scope releases it too.
        let mut h = Harness::new(evidence_app());
        h.app.set_listing_scope(ListingScope::Function);
        assert!(h.app.program.evidence.index.covering(0x2000).is_none());
    }

    #[test]
    fn data_rows_keep_the_mnemonic_unknown_and_show_their_evidence() {
        let mut h = Harness::new(evidence_app());
        let mut calls = crate::call_analysis::CallIndex::new(Default::default());
        calls.data_incoming.insert(0x2020, vec![0, 1]);
        h.app.set_call_index(Some(std::sync::Arc::new(calls)));
        h.frame(vec![]);
        let text = fixture::rendered_text(&h.frame(vec![]));
        for wanted in [
            "printf",
            "00001040  next",
            "\"ssssssss\"",
            "20h  XREF[2]",
            "700h  g_counter",
            "800h  g_export",
        ] {
            assert!(text.iter().any(|t| t == wanted), "{wanted}: {text:?}");
        }
        // Every data row keeps `??` as its mnemonic: three in `.data`, one
        // in `.text`, beside the collapsed and zero-filled rows.
        let unknown = text.iter().filter(|t| *t == "??").count();
        assert!(unknown >= 4 + 6, "{unknown}");
    }
}
