//! Listing keyboard cursor: Up/Down, PageUp/PageDown and Home/End move the
//! selected instruction of the current function's Listing, and Enter follows
//! an evidenced target. `DesktopApp.selected` stays the only cursor address;
//! this state is transient and never saved.

use std::sync::{Arc, Weak};

use eframe::egui;

use crate::function_presentation::{Listing, PreparedGraph};
use crate::model::{BinaryInfo, EdgeKind, FunctionView};
use crate::result_store::Stored;
use crate::theme;

/// The displayed listing a cursor and its metrics belong to. Function
/// address alone is insufficient after a refresh or another binary.
#[derive(Clone, Debug)]
pub(super) struct ViewKey {
    generation: u64,
    selection: u64,
    entry: u64,
    /// Held weakly, so the address cannot be reused while it is compared.
    graph: Weak<Stored<PreparedGraph>>,
}

impl PartialEq for ViewKey {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.selection == other.selection
            && self.entry == other.entry
            && Weak::ptr_eq(&self.graph, &other.graph)
    }
}

/// The last drawn listing body. `area` adds its scroll bars; `chrome` is the
/// pane height above and below the body, so a resized pane yields this
/// frame's body height before layout.
#[derive(Clone, Debug)]
struct Viewport {
    key: ViewKey,
    area: egui::Rect,
    layer: egui::LayerId,
    chrome: f32,
}

#[derive(Default)]
pub(super) struct ListingCursor {
    /// Listing interaction ownership, acquired only by a body click.
    active: Option<ViewKey>,
    viewport: Option<Viewport>,
    /// Keys whose accepted press has not been released; repeats need one.
    held: u8,
    drawn_frame: Option<u64>,
    available: f32,
}

impl ListingCursor {
    fn deactivate(&mut self) {
        self.active = None;
        self.held = 0;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Enter,
}

impl Command {
    fn of(key: egui::Key) -> Option<Self> {
        Some(match key {
            egui::Key::ArrowUp => Self::Up,
            egui::Key::ArrowDown => Self::Down,
            egui::Key::PageUp => Self::PageUp,
            egui::Key::PageDown => Self::PageDown,
            egui::Key::Home => Self::Home,
            egui::Key::End => Self::End,
            egui::Key::Enter => Self::Enter,
            _ => return None,
        })
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }

    /// Home, End and Enter follow the command policy: no OS repeats.
    fn repeats(self) -> bool {
        matches!(self, Self::Up | Self::Down | Self::PageUp | Self::PageDown)
    }
}

/// Rows per page in a body `height` points tall, keeping one row of overlap.
fn page_rows(height: f32) -> usize {
    ((height / theme::ROW_HEIGHT).floor() as usize)
        .saturating_sub(1)
        .max(1)
}

/// The row a movement lands on in a listing of `len` rows. A selection
/// absent from the listing starts at a fixed boundary, never a nearby row.
fn step(index: Option<usize>, command: Command, len: usize, page: usize) -> Option<usize> {
    let last = len.checked_sub(1)?;
    Some(match (index.map(|row| row.min(last)), command) {
        (_, Command::Home) | (None, Command::Down | Command::PageDown) => 0,
        (_, Command::End) | (None, Command::Up | Command::PageUp) => last,
        (Some(row), Command::Up) => row.saturating_sub(1),
        (Some(row), Command::Down) => row.saturating_add(1).min(last),
        (Some(row), Command::PageUp) => row.saturating_sub(page),
        (Some(row), Command::PageDown) => row.saturating_add(page).min(last),
        (row, Command::Enter) => return row,
    })
}

/// The one destination evidenced for the instruction at exactly `pc`: a
/// unique resolved call, else the taken edge of the block it terminates.
/// Ambiguous, unresolved or non-code targets give none. Branch edges also
/// split blocks at fallthrough, so a Branch to the next instruction is inert.
pub(super) fn follow_target(
    view: &FunctionView,
    listing: Listing<'_>,
    info: &BinaryInfo,
    pc: u64,
) -> Option<u64> {
    let instruction = listing.get(listing.position(pc)?)?;
    let target = match unique(
        view.calls.iter().filter(|call| call.address == pc),
        |call| call.target,
    ) {
        Some(target) => target?,
        None => {
            let ends = |source: u64| {
                view.blocks.iter().any(|block| {
                    block.address == source
                        && block
                            .instructions
                            .last()
                            .is_some_and(|last| last.address == pc)
                })
            };
            let edges: Vec<_> = view.edges.iter().filter(|e| ends(e.source)).collect();
            if edges.iter().any(|e| e.kind == EdgeKind::True) {
                unique(edges.iter().filter(|e| e.kind != EdgeKind::False), |edge| {
                    (edge.kind == EdgeKind::True && edge.evidence.is_none())
                        .then_some(edge.target)
                        .flatten()
                })??
            } else {
                let [edge] = edges.as_slice() else {
                    return None;
                };
                let next = (!instruction.bytes.is_empty())
                    .then(|| pc.checked_add(instruction.bytes.len() as u64))
                    .flatten()?;
                match edge {
                    crate::model::Edge {
                        kind: EdgeKind::Branch,
                        target: Some(target),
                        evidence: None,
                        ..
                    } if *target != next => *target,
                    _ => return None,
                }
            }
        }
    };
    crate::call_analysis::code_address(info, target).then_some(target)
}

/// `None` without items; otherwise the shared value, or `Some(None)` when any
/// item has none or two disagree.
fn unique<'a, T: 'a>(
    items: impl Iterator<Item = &'a T>,
    value: impl Fn(&T) -> Option<u64>,
) -> Option<Option<u64>> {
    let mut found = None;
    for item in items {
        let next = value(item);
        match found {
            None => found = Some(next),
            Some(previous) if previous != next || next.is_none() => return Some(None),
            Some(_) => {}
        }
    }
    found
}

impl super::DesktopApp {
    /// Whether keyboard commands must leave input to dialogs, text fields,
    /// popups and file operations.
    pub(super) fn navigation_shortcuts_blocked(&self, context: &egui::Context) -> bool {
        self.opening.is_some()
            || self.file_job.is_some()
            || self.intent.is_some()
            || self.browser_dialog.is_some()
            || self.help_dialog.is_some()
            || self.updater.open
            || self.analyze_prompt.is_some()
            || self.signature_editor.is_some()
            || self.signature_change.is_some()
            || context.egui_wants_keyboard_input()
            || egui::Popup::is_any_open(context)
            || context.memory(|memory| memory.top_modal_layer().is_some())
    }

    fn listing_view_key(&self) -> Option<ViewKey> {
        let graph = self.graph.as_ref()?;
        Some(ViewKey {
            generation: self.generation,
            selection: self.selection_generation,
            entry: graph.address(),
            graph: Arc::downgrade(graph),
        })
    }

    /// Runs first in the Listing pane, before its rows and scroll area see the
    /// batch. Accepted navigation keys are removed even at an endpoint.
    pub(super) fn listing_cursor_input(&mut self, ui: &egui::Ui) {
        let context = ui.ctx().clone();
        let frame = context.cumulative_frame_nr();
        let key = self.listing_view_key();
        let cursor = &mut self.listing_cursor;
        // Undrawn last frame means the pane was left; a click reactivates.
        let continuous = cursor
            .drawn_frame
            .is_some_and(|drawn| drawn == frame || drawn.wrapping_add(1) == frame);
        cursor.drawn_frame = Some(frame);
        cursor.available = ui.available_height();
        let (Some(key), true) = (key, continuous) else {
            cursor.deactivate();
            return;
        };
        if cursor.active.as_ref() != Some(&key) {
            cursor.deactivate();
            return;
        }
        let Some(viewport) = cursor.viewport.clone().filter(|v| v.key == key) else {
            cursor.deactivate();
            return;
        };
        let (presses, unfocused) = context.input(|input| {
            let presses: Vec<_> = input
                .events
                .iter()
                .filter_map(|event| match event {
                    egui::Event::PointerButton {
                        pressed: true, pos, ..
                    } => Some(*pos),
                    _ => None,
                })
                .collect();
            let unfocused = !input.focused
                || input
                    .events
                    .iter()
                    .any(|event| matches!(event, egui::Event::WindowFocused(false)));
            (presses, unfocused)
        });
        let outside = presses.into_iter().any(|pos| {
            !viewport.area.contains(pos) || context.layer_id_at(pos) != Some(viewport.layer)
        });
        if outside {
            cursor.deactivate();
            return;
        }
        if unfocused {
            cursor.held = 0;
            return;
        }
        // A focused widget owns the keys; its Enter can arrive in the frame
        // it surrenders focus, so the Listing needs a new click afterwards.
        if context.egui_wants_keyboard_input() {
            self.listing_cursor.deactivate();
            return;
        }
        if self.navigation_shortcuts_blocked(&context) || self.info.is_none() {
            self.listing_cursor.held = 0;
            return;
        }
        let page = page_rows(self.listing_cursor.available - viewport.chrome);
        let loaded = self.info.is_some();
        // A same-batch command (dialog, history, tab switch) wins.
        let command = context.input(|input| {
            input.events.iter().any(|event| {
                super::shortcut(event)
                    .is_some_and(|action| loaded || matches!(action, super::Shortcut::Help))
            })
        });
        let listing = super::listing_of(&self.graph);
        let start = self.selected.and_then(|pc| listing.position(pc));
        let mut index = start;
        let mut moved = false;
        let mut follow = None;
        let mut held = if command { 0 } else { self.listing_cursor.held };
        let view = super::graph_view(&self.graph);
        let info = self.info.as_ref();
        context.input_mut(|input| {
            input.events.retain(|event| {
                let egui::Event::Key {
                    key,
                    pressed,
                    repeat,
                    modifiers,
                    ..
                } = event
                else {
                    return true;
                };
                let Some(action) = Command::of(*key) else {
                    return true;
                };
                if !pressed {
                    held &= !action.bit();
                    return true;
                }
                if !modifiers.is_none() {
                    return true;
                }
                if command || follow.is_some() {
                    return false;
                }
                if !repeat {
                    held |= action.bit();
                } else if !action.repeats() || held & action.bit() == 0 {
                    return false;
                }
                if action == Command::Enter {
                    follow = index
                        .and_then(|row| listing.get(row))
                        .zip(view.zip(info))
                        .and_then(|(instruction, (view, info))| {
                            follow_target(view, listing, info, instruction.address)
                        });
                } else {
                    index = step(index, action, listing.len(), page);
                    moved = true;
                }
                false
            });
        });
        self.listing_cursor.held = if follow.is_some() { 0 } else { held };
        if moved && let Some(row) = index {
            self.move_listing_cursor(row);
            context.request_repaint();
        }
        if let Some(target) = follow {
            self.follow_listing_target(target, &context);
            context.request_repaint();
        }
    }

    /// Records the drawn body and activates on a primary click inside it.
    /// Called after the rows, so the pane's extent ends at their scroll bars.
    pub(super) fn listing_cursor_drawn(&mut self, ui: &egui::Ui, body: egui::Rect) {
        let Some(key) = self.listing_view_key() else {
            return;
        };
        let clicked = ui.input(|input| {
            input
                .pointer
                .primary_clicked()
                .then(|| input.pointer.interact_pos())
                .flatten()
        });
        let clicked = clicked.is_some_and(|pos| {
            body.contains(pos) && ui.ctx().layer_id_at(pos) == Some(ui.layer_id())
        });
        let cursor = &mut self.listing_cursor;
        cursor.viewport = Some(Viewport {
            key: key.clone(),
            area: egui::Rect::from_min_max(body.min, ui.min_rect().max),
            layer: ui.layer_id(),
            chrome: (cursor.available - body.height()).max(0.0),
        });
        if clicked {
            cursor.active = Some(key);
        }
    }

    /// Selects exactly row `row` as a click would and reveals it once.
    fn move_listing_cursor(&mut self, row: usize) {
        let Some(address) = self.listing().get(row).map(|i| i.address) else {
            return;
        };
        if self.selected != Some(address) {
            self.select_instruction(address);
        }
        self.pending_listing_scroll = Some(row);
        if let Some(canvas) = &mut self.canvas {
            canvas.reveal_instruction(address);
        }
    }

    /// Follows a resolved target with history; one inside this listing stays
    /// in its owner function.
    pub(super) fn follow_listing_target(&mut self, target: u64, context: &egui::Context) {
        let owner = self
            .view()
            .map(|view| view.address)
            .filter(|_| self.listing().contains(target));
        self.navigate_location(target, owner, true, context);
    }

    /// The Enter / double-click destination of the listing row at `pc`.
    pub(super) fn listing_follow_target(&self, pc: u64) -> Option<u64> {
        follow_target(self.view()?, self.listing(), self.info.as_ref()?, pc)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests as fixture;
    use super::super::{DesktopApp, Tab};
    use super::*;
    use crate::linkage_ui::Place;
    use crate::model::{BasicBlock, CallSite, Edge, EdgeEvidence, Instruction};

    fn instruction(address: u64, length: usize, mnemonic: &str) -> Instruction {
        Instruction {
            address,
            bytes: vec![0x90; length],
            mnemonic: mnemonic.into(),
            operands: String::new(),
        }
    }

    fn block(address: u64, instructions: &[(u64, usize)]) -> BasicBlock {
        BasicBlock {
            address,
            instructions: instructions
                .iter()
                .map(|&(address, length)| instruction(address, length, "op"))
                .collect(),
        }
    }

    fn edge(source: u64, target: Option<u64>, kind: EdgeKind) -> Edge {
        Edge {
            source,
            target,
            kind,
            evidence: None,
        }
    }

    fn call(address: u64, target: Option<u64>) -> CallSite {
        CallSite {
            address,
            target,
            no_return: None,
        }
    }

    /// 0x1000: nop; call 0x1040; jne 0x1010 / 0x1008: jmp 0x1010 / 0x1010: ret.
    fn branch_view() -> FunctionView {
        FunctionView {
            address: 0x1000,
            blocks: vec![
                block(0x1000, &[(0x1000, 1), (0x1001, 5), (0x1006, 2)]),
                block(0x1008, &[(0x1008, 2)]),
                block(0x1010, &[(0x1010, 1)]),
            ],
            edges: vec![
                edge(0x1000, Some(0x1010), EdgeKind::True),
                edge(0x1000, Some(0x1008), EdgeKind::False),
                edge(0x1008, Some(0x1010), EdgeKind::Branch),
            ],
            calls: vec![call(0x1001, Some(0x1040))],
            warnings: vec![],
        }
    }

    fn branch_app() -> DesktopApp {
        let mut app = fixture::keyboard_app();
        fixture::show_view(&mut app, branch_view());
        app.history = vec![Place::Code(0x1000)];
        app
    }

    fn rows_app(count: u64) -> DesktopApp {
        let mut app = fixture::semantic_app();
        fixture::set_listing(
            &mut app,
            (0..count)
                .map(|row| instruction(0x1000 + row * 4, 4, "nop"))
                .collect(),
        );
        app
    }

    fn key(key: egui::Key, repeat: bool) -> egui::Event {
        egui::Event::Key {
            key,
            physical_key: Some(key),
            pressed: true,
            repeat,
            modifiers: egui::Modifiers::NONE,
        }
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

    fn wheel(point: egui::Pos2, delta: f32) -> Vec<egui::Event> {
        vec![
            egui::Event::PointerMoved(point),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                phase: egui::TouchPhase::Move,
                source: egui::MouseWheelSource::Unknown,
                delta: egui::vec2(0.0, delta),
                modifiers: egui::Modifiers::NONE,
            },
        ]
    }

    /// Frames through the real Listing pane (or the whole desktop), recording
    /// the input left for widgets after it.
    struct Harness {
        context: egui::Context,
        app: DesktopApp,
        size: egui::Vec2,
        time: f64,
        desktop: bool,
        editor: bool,
        focused: bool,
        remaining: Vec<egui::Event>,
    }

    impl Harness {
        fn new(app: DesktopApp, scale: f32, size: egui::Vec2) -> Self {
            let context = egui::Context::default();
            theme::install(&context);
            context.set_pixels_per_point(scale);
            context.all_styles_mut(|style| {
                style.animation_time = 0.0;
                style.scroll_animation = egui::style::ScrollAnimation::none();
            });
            let mut harness = Self {
                context,
                app,
                size,
                time: 0.0,
                desktop: false,
                editor: false,
                focused: true,
                remaining: Vec::new(),
            };
            harness.frame(vec![]);
            harness
        }

        fn desktop(app: DesktopApp) -> Self {
            let mut harness = Self::new(app, 1.0, egui::vec2(1400.0, 800.0));
            harness.desktop = true;
            harness.frame(vec![]);
            harness
        }

        fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
            self.time += 0.5;
            let Self {
                context,
                app,
                remaining,
                ..
            } = self;
            let (desktop, editor) = (self.desktop, self.editor);
            let mut text = String::new();
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                    time: Some(self.time),
                    focused: self.focused,
                    events,
                    ..Default::default()
                },
                |ui| {
                    if editor {
                        ui.add(egui::TextEdit::singleline(&mut text))
                            .request_focus();
                    }
                    if desktop {
                        app.draw(ui);
                    } else {
                        app.main_panel(ui);
                    }
                    *remaining = ui.input(|input| input.events.clone());
                },
            );
            output.textures_delta.clear();
            output
        }

        /// Taps `keys`: presses, then releases, in one batch.
        fn keys(&mut self, keys: &[egui::Key]) -> egui::FullOutput {
            let presses = keys.iter().map(|&k| key(k, false));
            self.frame(presses.chain(keys.iter().map(|&k| release(k))).collect())
        }

        fn click(&mut self, address: u64) {
            let output = self.frame(vec![]);
            let point = row_point(&output, address);
            self.frame(fixture::pointer_events(point));
        }

        fn left_over(&self, wanted: egui::Key) -> bool {
            self.remaining.iter().any(|event| {
                matches!(event, egui::Event::Key { key, pressed: true, .. } if *key == wanted)
            })
        }
    }

    /// Listing rows fully inside their clip, by their address cell.
    fn visible_rows(output: &egui::FullOutput) -> Vec<u64> {
        output
            .shapes
            .iter()
            .filter_map(|shape| {
                let egui::epaint::Shape::Text(text) = &shape.shape else {
                    return None;
                };
                let bounds = text.galley.rect.translate(text.pos.to_vec2());
                let first = text.galley.text().split_whitespace().next()?;
                (first.len() == 8
                    && text.galley.text().starts_with(first)
                    && shape.clip_rect.contains_rect(bounds))
                .then(|| u64::from_str_radix(first, 16).ok())
                .flatten()
            })
            .collect()
    }

    fn row_point(output: &egui::FullOutput, address: u64) -> egui::Pos2 {
        let needle = format!("{address:08x}");
        output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text)
                    if text.galley.text().split_whitespace().next() == Some(&needle) =>
                {
                    Some(text.pos + text.galley.rect.left_center().to_vec2() + egui::vec2(8.0, 0.0))
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("listing row {needle} is rendered"))
    }

    fn history(app: &DesktopApp) -> Vec<u64> {
        app.history.iter().map(|place| place.address()).collect()
    }

    #[test]
    fn listing_cursor_moves_in_exact_address_order() {
        let mut app = fixture::keyboard_app();
        // Blocks out of address order, with gaps between instructions.
        fixture::show_view(
            &mut app,
            FunctionView {
                address: 0x1000,
                blocks: vec![
                    block(0x1010, &[(0x1010, 3), (0x1013, 1)]),
                    block(0x1000, &[(0x1000, 2), (0x1007, 1)]),
                ],
                edges: vec![],
                calls: vec![],
                warnings: vec![],
            },
        );
        app.history = vec![Place::Code(0x1000)];
        let mut h = Harness::new(app, 1.0, egui::vec2(700.0, 400.0));
        h.click(0x1000);
        let generation = h.app.selection_generation;
        let mut seen = Vec::new();
        for _ in 0..4 {
            h.keys(&[egui::Key::ArrowDown]);
            seen.push(h.app.selected.unwrap());
        }
        assert_eq!(seen, [0x1007, 0x1010, 0x1013, 0x1013]);
        h.keys(&[egui::Key::ArrowUp]);
        assert_eq!(h.app.selected, Some(0x1010));
        assert_eq!(h.app.selection_generation, generation);
        assert!(h.app.queue.is_empty() && h.app.pending.is_none());
        assert_eq!(history(&h.app), [0x1000], "rows are not history entries");
    }

    #[test]
    fn listing_cursor_pages_use_viewport_and_clamp() {
        let page = |height: f32| {
            let mut h = Harness::new(rows_app(400), 1.0, egui::vec2(700.0, height));
            h.click(0x1000);
            let visible = visible_rows(&h.frame(vec![])).len();
            h.keys(&[egui::Key::PageDown]);
            let row = (h.app.selected.unwrap() - 0x1000) as usize / 4;
            assert!(
                (2..visible).contains(&row) && row + 2 >= visible,
                "one page keeps an overlap: row {row} of {visible} visible"
            );
            let output = h.frame(vec![]);
            assert!(visible_rows(&output).contains(&h.app.selected.unwrap()));
            h.keys(&[egui::Key::PageUp]);
            assert_eq!(h.app.selected, Some(0x1000));
            h.keys(&[egui::Key::PageUp, egui::Key::ArrowUp]);
            assert_eq!(h.app.selected, Some(0x1000));
            assert!(
                !h.left_over(egui::Key::PageUp),
                "endpoint keys are consumed"
            );
            h.keys(&[egui::Key::End]);
            assert_eq!(h.app.selected, Some(0x1000 + 399 * 4));
            h.keys(&[egui::Key::End, egui::Key::PageDown, egui::Key::ArrowDown]);
            assert_eq!(h.app.selected, Some(0x1000 + 399 * 4));
            h.keys(&[egui::Key::Home]);
            assert_eq!(h.app.selected, Some(0x1000));
            row
        };
        let (short, tall) = (page(300.0), page(700.0));
        assert!(tall > short + 10, "{short} {tall}");

        // A resize applies to the very next page, before the body is redrawn.
        let mut h = Harness::new(rows_app(400), 1.0, egui::vec2(700.0, 300.0));
        h.click(0x1000);
        h.size = egui::vec2(700.0, 700.0);
        h.keys(&[egui::Key::PageDown]);
        assert_eq!((h.app.selected.unwrap() - 0x1000) as usize / 4, tall);

        for count in [0, 1] {
            let mut h = Harness::new(rows_app(1), 1.0, egui::vec2(700.0, 300.0));
            h.click(0x1000);
            if count == 0 {
                fixture::set_listing(&mut h.app, vec![]);
                h.frame(vec![]);
            }
            for k in [egui::Key::ArrowDown, egui::Key::PageUp, egui::Key::End] {
                h.keys(&[k]);
                assert_eq!(h.app.selected, Some(0x1000));
            }
        }
    }

    #[test]
    fn listing_cursor_uses_click_semantics_for_mapped_and_unmapped_rows() {
        let snapshot = |app: &DesktopApp| {
            (
                app.selected,
                app.semantic.addresses.clone(),
                app.semantic.ranges.clone(),
                app.pending_code_scroll,
                app.pending_comment_scroll,
            )
        };
        let mut clicked = Harness::new(fixture::semantic_app(), 1.0, egui::vec2(800.0, 400.0));
        clicked.click(0x1004);
        let mut keyed = Harness::new(fixture::semantic_app(), 1.0, egui::vec2(800.0, 400.0));
        keyed.click(0x1000);
        keyed.keys(&[egui::Key::ArrowDown]);
        assert_eq!(snapshot(&keyed.app), snapshot(&clicked.app));
        let expression = keyed.app.semantic.ranges.clone();
        assert_eq!(expression.len(), 1);
        // Two instructions printed as one expression share its range.
        keyed.keys(&[egui::Key::ArrowDown]);
        assert_eq!(keyed.app.semantic.ranges, expression);
        assert_eq!(
            keyed.app.semantic.addresses,
            std::collections::BTreeSet::from([0x1008])
        );
        // The unmapped entry stays unmapped; nothing nearby is borrowed.
        let output = keyed.keys(&[egui::Key::Home]);
        assert_eq!(keyed.app.selected, Some(0x1000));
        assert!(keyed.app.semantic.ranges.is_empty());
        assert!(keyed.app.pending_code_scroll.is_none());
        let row_y = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if text.galley.text() == "00001000" => {
                    Some(text.pos.y)
                }
                _ => None,
            })
            .unwrap();
        let colors: std::collections::BTreeSet<_> = output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if (text.pos.y - row_y).abs() < 1.0 => {
                    Some(&text.galley.job.sections)
                }
                _ => None,
            })
            .flatten()
            .map(|section| section.format.color.to_array())
            .collect();
        assert!(colors.contains(&theme::SYNTAX_KEYWORD.to_array()) && colors.len() > 2);
    }

    #[test]
    fn listing_cursor_reveal_is_one_shot_at_fractional_scale() {
        let last = 0x1000 + 1999 * 4;
        for scale in [1.0, 1.25] {
            let mut h = Harness::new(rows_app(2000), scale, egui::vec2(700.0, 500.0));
            h.click(0x1000);
            h.keys(&[egui::Key::End]);
            assert!(h.app.pending_listing_scroll.is_none(), "consumed");
            for _ in 0..2 {
                assert!(visible_rows(&h.frame(vec![])).contains(&last), "{scale}");
            }
            let body = row_point(&h.frame(vec![]), last);
            for _ in 0..4 {
                h.frame(wheel(body, 2000.0));
            }
            for _ in 0..3 {
                let rows = visible_rows(&h.frame(vec![]));
                assert!(!rows.is_empty() && !rows.contains(&last), "{scale}");
            }
            assert_eq!(h.app.selected, Some(last));
            // Even a clamped press reveals its row again.
            h.keys(&[egui::Key::ArrowDown]);
            assert!(visible_rows(&h.frame(vec![])).contains(&last), "{scale}");
            h.keys(&[egui::Key::ArrowUp]);
            let rows = visible_rows(&h.frame(vec![]));
            assert!(
                rows.contains(&(last - 4)) && rows.contains(&last),
                "{scale}"
            );
        }
    }

    #[test]
    fn listing_cursor_consumes_keys_before_scroll_area() {
        let mut h = Harness::new(rows_app(400), 1.25, egui::vec2(700.0, 400.0));
        h.click(0x1000);
        let before = visible_rows(&h.frame(vec![]));
        let body = row_point(&h.frame(vec![]), 0x1004);
        let shift = egui::Event::Key {
            key: egui::Key::ArrowDown,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::SHIFT,
        };
        let mut events = wheel(body, 0.0);
        events.extend([key(egui::Key::ArrowDown, false), shift]);
        h.frame(events);
        assert_eq!(h.app.selected, Some(0x1004), "exactly one row");
        assert!(h.app.pending_listing_scroll.is_none());
        assert!(
            h.remaining
                .iter()
                .any(|e| matches!(e, egui::Event::MouseWheel { .. })),
            "wheel input is left to the scroll area"
        );
        let downs: Vec<_> = h
            .remaining
            .iter()
            .filter_map(|event| match event {
                egui::Event::Key {
                    key: egui::Key::ArrowDown,
                    modifiers,
                    ..
                } => Some(*modifiers),
                _ => None,
            })
            .collect();
        assert_eq!(
            downs,
            [egui::Modifiers::SHIFT],
            "modified keys are not ours"
        );
        assert_eq!(
            visible_rows(&h.frame(vec![])),
            before,
            "no scroll on a visible row"
        );
        // A batch moves once, to its final row.
        h.frame(vec![
            key(egui::Key::ArrowDown, false),
            release(egui::Key::ArrowDown),
            key(egui::Key::ArrowDown, false),
            key(egui::Key::ArrowDown, true),
        ]);
        assert_eq!(h.app.selected, Some(0x100c + 4));
    }

    #[test]
    fn listing_cursor_guards_and_activation() {
        type Setup = fn(&mut Harness);
        let blocked: [(&str, Setup); 8] = [
            ("text editor", |h| h.editor = true),
            ("help", |h| {
                h.app.help_dialog = Some(crate::help::HelpDialog::Shortcuts)
            }),
            ("browser dialog", |h| {
                h.app.browser_dialog = Some(super::super::BrowserDialog {
                    kind: super::super::BrowserDialogKind::GoTo,
                    text: String::new(),
                    error: None,
                    focus: false,
                    generation: h.app.generation,
                })
            }),
            ("update", |h| h.app.updater.open = true),
            ("intent", |h| {
                h.app.intent = Some(super::super::Intent::OpenDialog)
            }),
            ("file job", |h| {
                h.app.file_job = Some(std::sync::mpsc::channel().1)
            }),
            ("popup", |h| {
                let output = h.frame(vec![]);
                let point = row_point(&output, 0x1004);
                h.frame(vec![
                    egui::Event::PointerMoved(point),
                    egui::Event::PointerButton {
                        pos: point,
                        button: egui::PointerButton::Secondary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                    egui::Event::PointerButton {
                        pos: point,
                        button: egui::PointerButton::Secondary,
                        pressed: false,
                        modifiers: egui::Modifiers::NONE,
                    },
                ]);
                assert!(egui::Popup::is_any_open(&h.context));
            }),
            ("inactive pane", |h| h.app.listing_cursor.active = None),
        ];
        for (name, setup) in blocked {
            let mut h = Harness::new(fixture::semantic_app(), 1.0, egui::vec2(800.0, 400.0));
            h.click(0x1000);
            setup(&mut h);
            let before = history(&h.app);
            for k in [egui::Key::ArrowDown, egui::Key::End] {
                h.keys(&[k]);
                assert_eq!(h.app.selected, Some(0x1000), "{name}");
                assert!(h.left_over(k), "{name}: input stays with its owner");
            }
            // An open menu may use Enter itself, but never to follow a row.
            h.keys(&[egui::Key::Enter]);
            assert!(h.left_over(egui::Key::Enter), "{name}");
            assert_eq!(history(&h.app), before, "{name}");
        }

        // Text focus releases the Listing, so the Enter that ends an edit
        // never follows a row; a new click is needed.
        let mut h = Harness::new(fixture::semantic_app(), 1.0, egui::vec2(800.0, 400.0));
        h.click(0x1000);
        h.editor = true;
        h.frame(vec![]);
        h.editor = false;
        h.frame(vec![]);
        h.keys(&[egui::Key::ArrowDown]);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(h.left_over(egui::Key::ArrowDown));

        // The Listing's own scroll bar keeps the keys.
        let mut h = Harness::new(rows_app(400), 1.0, egui::vec2(700.0, 400.0));
        h.click(0x1000);
        let viewport = h.app.listing_cursor.viewport.clone().unwrap();
        let bar = egui::pos2(viewport.area.right() - 3.0, viewport.area.center().y);
        h.frame(fixture::pointer_events(bar));
        assert!(h.app.listing_cursor.active.is_some());
        h.keys(&[egui::Key::ArrowDown]);
        assert_eq!(h.app.selected, Some(0x1004));

        // Hover alone does not activate; a press outside the body releases
        // the keys before same-batch movement.
        let mut h = Harness::new(fixture::semantic_app(), 1.0, egui::vec2(800.0, 400.0));
        let hover = row_point(&h.frame(vec![]), 0x1004);
        let output = h.frame(vec![egui::Event::PointerMoved(hover)]);
        h.keys(&[egui::Key::ArrowDown]);
        assert_eq!(h.app.selected, Some(0x1000));
        let title = fixture::text_position(&output, "entry", 1);
        h.click(0x1000);
        let mut events = fixture::pointer_events(title);
        events.push(key(egui::Key::ArrowDown, false));
        h.frame(events);
        h.keys(&[egui::Key::ArrowDown]);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(h.left_over(egui::Key::ArrowDown));
        // Clicking empty body space reactivates without choosing a row.
        let below = row_point(&h.frame(vec![]), 0x1008) + egui::vec2(0.0, 120.0);
        h.frame(fixture::pointer_events(below));
        assert_eq!(h.app.selected, Some(0x1000));
        h.keys(&[egui::Key::ArrowDown]);
        assert_eq!(h.app.selected, Some(0x1004));

        // Losing application focus disarms a held key.
        h.frame(vec![key(egui::Key::ArrowDown, false)]);
        h.focused = false;
        h.frame(vec![]);
        h.focused = true;
        h.frame(vec![key(egui::Key::ArrowDown, true)]);
        assert_eq!(h.app.selected, Some(0x1008));

        // Key events delivered with focus loss must not move an inactive
        // application, even if the backend includes a fresh press in the batch.
        let mut h = Harness::new(rows_app(10), 1.0, egui::vec2(700.0, 400.0));
        h.click(0x1000);
        h.focused = false;
        h.frame(vec![
            egui::Event::WindowFocused(false),
            key(egui::Key::End, false),
        ]);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(h.left_over(egui::Key::End));
        assert_eq!(h.app.listing_cursor.held, 0);

        // A global command in the same batch wins over movement.
        let mut h = Harness::desktop(fixture::semantic_app());
        h.click(0x1000);
        h.keys(&[egui::Key::ArrowDown, egui::Key::F1]);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(h.app.help_dialog.is_some());
        h.app.help_dialog = None;
        h.frame(vec![]);
        h.frame(vec![]);
        h.keys(&[egui::Key::Space, egui::Key::ArrowDown]);
        assert_eq!((h.app.selected, h.app.tab), (Some(0x1000), Tab::Graph));
    }

    #[test]
    fn listing_cursor_repeats_do_not_cross_view_changes() {
        let mut h = Harness::new(rows_app(64), 1.0, egui::vec2(700.0, 400.0));
        // A key held from before activation repeats without moving.
        h.frame(vec![key(egui::Key::ArrowDown, false)]);
        h.click(0x1000);
        h.frame(vec![key(egui::Key::ArrowDown, true)]);
        assert_eq!(h.app.selected, Some(0x1000));
        assert!(
            !h.left_over(egui::Key::ArrowDown),
            "still owned by the Listing"
        );
        h.frame(vec![release(egui::Key::ArrowDown)]);
        h.frame(vec![key(egui::Key::ArrowDown, false)]);
        h.frame(vec![key(egui::Key::ArrowDown, true)]);
        h.frame(vec![key(egui::Key::ArrowDown, true)]);
        assert_eq!(h.app.selected, Some(0x100c));
        // Home/End never repeat.
        h.frame(vec![key(egui::Key::End, false)]);
        h.app.select_instruction(0x1000);
        h.frame(vec![key(egui::Key::End, true)]);
        assert_eq!(h.app.selected, Some(0x1000));

        type Change = fn(&mut Harness);
        let changes: [(&str, Change); 4] = [
            ("navigation", |h| {
                let context = h.context.clone();
                h.app.navigate(0x1040, true, &context);
                let rows: Vec<_> = (0..8).map(|r| (0x1040 + r * 4, 4)).collect();
                fixture::show_view(
                    &mut h.app,
                    FunctionView {
                        address: 0x1040,
                        blocks: vec![block(0x1040, &rows)],
                        edges: vec![],
                        calls: vec![],
                        warnings: vec![],
                    },
                );
            }),
            ("refresh", |h| {
                let view = h.app.view().unwrap().clone();
                fixture::show_view(&mut h.app, view);
            }),
            ("generation", |h| h.app.generation += 1),
            ("tab", |h| {
                h.app.tab = Tab::Graph;
                h.frame(vec![]);
                h.app.tab = Tab::Listing;
            }),
        ];
        for (name, change) in changes {
            let mut h = Harness::new(rows_app(64), 1.0, egui::vec2(700.0, 400.0));
            h.click(0x1000);
            h.frame(vec![key(egui::Key::ArrowDown, false)]);
            change(&mut h);
            let selected = h.app.selected;
            h.frame(vec![key(egui::Key::ArrowDown, true)]);
            h.frame(vec![key(egui::Key::ArrowDown, false)]);
            assert_eq!(
                h.app.selected, selected,
                "{name}: reactivation needs a click"
            );
        }

        // Holding Enter follows one call, never a chain.
        let mut h = Harness::new(branch_app(), 1.0, egui::vec2(700.0, 400.0));
        h.click(0x1001);
        h.frame(vec![key(egui::Key::Enter, false)]);
        assert_eq!(h.app.selected, Some(0x1040));
        let after = history(&h.app);
        fixture::show_view(&mut h.app, branch_view());
        h.frame(vec![key(egui::Key::Enter, true)]);
        h.frame(vec![key(egui::Key::Enter, true)]);
        assert_eq!(history(&h.app), after);
    }

    #[test]
    fn listing_enter_follows_call_and_returns_to_departure() {
        let mut h = Harness::new(branch_app(), 1.0, egui::vec2(700.0, 400.0));
        let original = h.app.graph.clone().unwrap();
        h.click(0x1000);
        h.keys(&[egui::Key::ArrowDown]);
        assert_eq!(history(&h.app), [0x1000]);
        h.keys(&[egui::Key::Enter]);
        assert_eq!(h.app.selected, Some(0x1040));
        assert_eq!(history(&h.app), [0x1001, 0x1040]);
        assert!(
            h.app.view().is_none(),
            "the callee is requested, not guessed"
        );
        let context = h.context.clone();
        h.app.history_step(false, &context);
        assert_eq!(h.app.selected, Some(0x1001));
        // The caller's result arrives and reveals the exact departure.
        h.app
            .adopt_graph(original, crate::result_store::ResultOrigin::Computed);
        assert_eq!(h.app.selected, Some(0x1001));
        assert_eq!(h.app.pending_listing_scroll, Some(1));
        h.app.history_step(true, &context);
        assert_eq!(h.app.selected, Some(0x1040));
    }

    #[test]
    fn listing_branch_follow_uses_exact_terminal_edges() {
        let info = fixture::keyboard_app().info.unwrap();
        let resolve = |view: &FunctionView, pc| {
            let graph = PreparedGraph::new(view.clone());
            follow_target(view, graph.listing(), &info, pc)
        };
        let view = branch_view();
        assert_eq!(resolve(&view, 0x1001), Some(0x1040), "call");
        assert_eq!(resolve(&view, 0x1006), Some(0x1010), "taken edge");
        assert_eq!(resolve(&view, 0x1008), Some(0x1010), "jump");
        assert_eq!(resolve(&view, 0x1000), None, "not a block terminator");
        assert_eq!(resolve(&view, 0x1010), None, "no successor");
        assert_eq!(resolve(&view, 0x1003), None, "not an instruction start");

        let variant = |edit: fn(&mut FunctionView)| {
            let mut view = branch_view();
            edit(&mut view);
            view
        };
        type Edit = fn(&mut FunctionView);
        let inert: [(&str, Edit, u64); 10] = [
            (
                "fallthrough split",
                |v| v.edges[2].target = Some(0x100a),
                0x1008,
            ),
            ("false only", |v| v.edges[2].kind = EdgeKind::False, 0x1008),
            ("unknown", |v| v.edges[2].kind = EdgeKind::Unknown, 0x1008),
            (
                "switch table",
                |v| {
                    v.edges[2].evidence = Some(EdgeEvidence::EngineJumpTable);
                    v.edges.push(Edge {
                        evidence: Some(EdgeEvidence::EngineJumpTable),
                        ..edge(0x1008, Some(0x1000), EdgeKind::Branch)
                    });
                },
                0x1008,
            ),
            (
                "conflicting taken",
                |v| v.edges.push(edge(0x1000, Some(0x1008), EdgeKind::Unknown)),
                0x1006,
            ),
            ("unresolved taken", |v| v.edges[0].target = None, 0x1006),
            (
                "conflicting calls",
                |v| v.calls.push(call(0x1001, Some(0x1080))),
                0x1001,
            ),
            (
                "unresolved call before an edge",
                |v| v.calls.push(call(0x1008, None)),
                0x1008,
            ),
            (
                "outside executable bytes",
                |v| v.edges[2].target = Some(0x9000),
                0x1008,
            ),
            (
                "empty encoding",
                |v| v.blocks[1].instructions[0].bytes.clear(),
                0x1008,
            ),
        ];
        for (name, edit, pc) in inert {
            assert_eq!(resolve(&variant(edit), pc), None, "{name}");
        }
        let overflow = FunctionView {
            address: u64::MAX - 1,
            blocks: vec![block(u64::MAX - 1, &[(u64::MAX - 1, 4)])],
            edges: vec![edge(u64::MAX - 1, Some(0x1000), EdgeKind::Branch)],
            calls: vec![],
            warnings: vec![],
        };
        assert_eq!(resolve(&overflow, u64::MAX - 1), None, "overflow");

        // A local target stays in the owner function, with history.
        let mut h = Harness::new(branch_app(), 1.0, egui::vec2(700.0, 400.0));
        let graph = h.app.graph.clone().unwrap();
        h.click(0x1008);
        let generation = h.app.selection_generation;
        h.keys(&[egui::Key::Enter]);
        assert_eq!(h.app.selected, Some(0x1010));
        assert!(Arc::ptr_eq(h.app.graph.as_ref().unwrap(), &graph));
        assert_eq!(h.app.selection_generation, generation);
        assert!(h.app.queue.is_empty() && h.app.pending.is_none());
        assert_eq!(history(&h.app), [0x1008, 0x1010]);
        // Still the active listing: keep moving, then go back.
        h.frame(vec![]);
        h.keys(&[egui::Key::ArrowUp]);
        assert_eq!(h.app.selected, Some(0x1008));
        let context = h.context.clone();
        h.app.history_step(false, &context);
        assert_eq!(h.app.selected, Some(0x1008));
        assert!(Arc::ptr_eq(h.app.graph.as_ref().unwrap(), &graph));
    }

    #[test]
    fn listing_double_click_and_enter_share_follow_behavior() {
        for row in [0x1001, 0x1006] {
            let mut keyed = Harness::new(branch_app(), 1.0, egui::vec2(700.0, 400.0));
            keyed.click(row);
            keyed.keys(&[egui::Key::Enter]);

            let mut clicked = Harness::new(branch_app(), 1.0, egui::vec2(700.0, 400.0));
            let point = row_point(&clicked.frame(vec![]), row);
            clicked.frame(fixture::pointer_events(point));
            clicked.time += 0.1 - 0.5;
            clicked.frame(fixture::pointer_events(point));
            assert_eq!(clicked.app.selected, keyed.app.selected, "{row:#x}");
            assert_eq!(history(&clicked.app), history(&keyed.app), "{row:#x}");
            assert_eq!(
                history(&clicked.app)[0],
                row,
                "departure is the clicked row"
            );
        }
        // Rows without evidence do nothing on double-click.
        let mut h = Harness::new(branch_app(), 1.0, egui::vec2(700.0, 400.0));
        let point = row_point(&h.frame(vec![]), 0x1000);
        h.frame(fixture::pointer_events(point));
        h.time -= 0.4;
        h.frame(fixture::pointer_events(point));
        assert_eq!(h.app.selected, Some(0x1000));
        assert_eq!(history(&h.app), [0x1000]);
    }
}
