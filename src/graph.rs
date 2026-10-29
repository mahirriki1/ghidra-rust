//! A bounded native instruction CFG. Every returned row is laid out at its true
//! height; painting visits only the rows inside the viewport, and zoomed-out
//! blocks draw compact row marks instead of text. Construct a new canvas when
//! analysis changes; selection changes alone intentionally retain the camera.

use crate::model::{
    EdgeEvidence, EdgeKind, FunctionView, MAX_GRAPH_BLOCKS, MAX_GRAPH_EDGES, MAX_GRAPH_INSTRUCTIONS,
};
use crate::theme::{self, ROW_HEIGHT};
use eframe::egui::{
    self, Align2, Color32, FontId, Pos2, Rangef, Rect, Sense, Stroke, StrokeKind, Vec2, pos2, vec2,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ops::Range;
use std::sync::Arc;

const WIDTH: f32 = 420.0;
const HEADER: f32 = 32.0;
/// Space below a block's last row.
const FOOTER: f32 = 8.0;
/// Characters shown of one instruction or comment row.
const ROW_CHARS: usize = 53;
const MIN_ZOOM: f32 = 0.0001;
const MAX_ZOOM: f32 = 2.5;
const READABLE_ZOOM: f32 = 0.85;
const ARROWHEAD_ZOOM: f32 = 0.35;
const HEADER_TEXT_ZOOM: f32 = 0.65;
const ROW_TEXT_ZOOM: f32 = 0.75;
const ROW_GAP: f32 = 100.0;
/// Overview row marks are at least this many physical pixels apart; denser
/// rows share one mark.
const MARK_PIXELS: f32 = 2.0;
/// Approximate advance of the 12-point monospace row font.
const CHAR_WIDTH: f32 = 7.2;
/// Screen margin kept above an entry block and beside a wide one.
const REVEAL_MARGIN: f32 = 24.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RowKind {
    Instruction,
    Comment,
}

/// One display row. A comment row carries its instruction's exact PC.
struct GraphRow {
    address: u64,
    kind: RowKind,
    text: String,
    /// Byte boundary of a bounded callee display name within `text`.
    name_start: Option<usize>,
}

struct Node {
    address: u64,
    rect: Rect,
    rows: Vec<GraphRow>,
    /// Formatted once with the geometry, not per frame.
    header: String,
    is_return: bool,
}

struct RoutedEdge {
    points: Vec<Pos2>,
    /// Route and label extent, so off-screen edges are rejected cheaply.
    bounds: Rect,
    kind: EdgeKind,
    label: String,
    label_position: Pos2,
    unresolved: bool,
}

/// Immutable block placement and routed edges for one view and comment set.
/// Shared between a function's stored result and every canvas showing it.
pub struct GraphGeometry {
    nodes: Vec<Node>,
    edges: Vec<RoutedEdge>,
    bounds: Rect,
    /// `(address, node, row)` of every instruction row, ordered by address.
    instructions: Box<[(u64, u32, u32)]>,
    /// `(block address, node)`, ordered by address.
    blocks: Box<[(u64, u32)]>,
}

#[cfg(test)]
type Layout = GraphGeometry;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reveal {
    /// The exact instruction row; a header-only block shows its header.
    Instruction(u64),
    /// The entry block's header and first row, near the top.
    Entry,
}

pub struct GraphCanvas {
    function: u64,
    /// Geometry without comment rows, reused while the function has none.
    base: Arc<GraphGeometry>,
    layout: Arc<GraphGeometry>,
    zoom: f32,
    pan: Vec2,
    needs_fit: bool,
    needs_initial_view: bool,
    reveal: Option<Reveal>,
    /// Annotation revisions of the displayed or awaited comment geometry.
    comment_key: Option<(u64, u64, u64)>,
    /// Base geometry stands in until geometry for `comment_key` is adopted;
    /// camera requests wait for it, so they apply to the final rows.
    awaiting: bool,
    /// The instruction under the last secondary click, kept while its context
    /// menu stays open and the pointer moves. Reset with the function.
    context: Option<u64>,
    #[cfg(test)]
    painted: Painted,
}

/// Row work done by the last frame, for bounded-paint tests.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
struct Painted {
    text_rows: usize,
    marks: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphAction {
    Select(u64),
    Navigate(u64),
}

fn instruction_action(view: &FunctionView, address: u64, double_clicked: bool) -> GraphAction {
    if double_clicked
        && let Some(target) = view
            .calls
            .iter()
            .find(|call| call.address == address)
            .and_then(|call| call.target)
    {
        return GraphAction::Navigate(target);
    }
    GraphAction::Select(address)
}

impl GraphCanvas {
    pub fn new(view: &FunctionView) -> Self {
        Self::with_geometry(view, Arc::new(GraphGeometry::new(view)))
    }

    /// A fresh camera over prepared geometry for `view`.
    pub fn with_geometry(view: &FunctionView, geometry: Arc<GraphGeometry>) -> Self {
        Self {
            function: view.address,
            layout: geometry.clone(),
            base: geometry,
            zoom: 1.0,
            pan: Vec2::ZERO,
            needs_fit: false,
            needs_initial_view: true,
            reveal: None,
            comment_key: None,
            awaiting: false,
            context: None,
            #[cfg(test)]
            painted: Painted::default(),
        }
    }

    /// Queues one reveal of the exact instruction row. An address outside
    /// the graph leaves the camera alone.
    pub fn reveal_instruction(&mut self, address: u64) {
        self.reveal = Some(Reveal::Instruction(address));
    }

    /// The annotation revisions last requested of this canvas.
    pub fn annotation(&self) -> Option<(u64, u64, u64)> {
        self.comment_key
    }

    /// Whether comment geometry for [`Self::annotation`] is still awaited.
    pub fn awaiting(&self) -> bool {
        self.awaiting
    }

    /// Shows the base geometry for annotation revisions `key`. With
    /// `awaiting`, comment geometry for `key` is being prepared: edited or
    /// deleted comments are no longer displayed, and the camera is kept.
    pub fn show_base(&mut self, key: (u64, u64, u64), awaiting: bool) {
        self.layout = self.base.clone();
        self.comment_key = Some(key);
        self.awaiting = awaiting;
    }

    /// Adopts prepared comment geometry for exactly the awaited `key`,
    /// retaining the camera and any pending reveal.
    pub fn adopt_annotation(&mut self, key: (u64, u64, u64), geometry: Arc<GraphGeometry>) -> bool {
        if !self.awaiting || self.comment_key != Some(key) {
            return false;
        }
        self.layout = geometry;
        self.awaiting = false;
        true
    }

    #[cfg(test)]
    pub(crate) fn camera(&self) -> (f32, Vec2) {
        (self.zoom, self.pan)
    }

    /// Whether the canvas displays exactly `geometry`.
    #[cfg(test)]
    pub(crate) fn shows(&self, geometry: &Arc<GraphGeometry>) -> bool {
        Arc::ptr_eq(&self.layout, geometry)
    }

    /// Displayed comment rows, for app lifecycle tests.
    #[cfg(test)]
    pub(crate) fn comment_rows(&self) -> Vec<String> {
        self.layout
            .nodes
            .iter()
            .flat_map(|node| &node.rows)
            .filter(|row| row.kind == RowKind::Comment)
            .map(|row| row.text.clone())
            .collect()
    }

    /// Synchronous comment layout for headless tests.
    #[cfg(test)]
    fn set_comments(
        &mut self,
        view: &FunctionView,
        key: (u64, u64, u64),
        comments: &BTreeMap<u64, String>,
        call_names: impl FnOnce() -> BTreeMap<u64, String>,
    ) {
        if self.comment_key != Some(key) {
            let call_names = &call_names();
            self.show_base(key, true);
            let geometry = Arc::new(Layout::annotated(view, comments, call_names));
            self.adopt_annotation(key, geometry);
        }
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        view: &FunctionView,
        selected: Option<u64>,
    ) -> Option<GraphAction> {
        self.show_selected(ui, view, selected, &BTreeSet::new(), |_, _| {})
    }

    /// `menu` fills the canvas context menu for the instruction captured by
    /// the opening secondary click, or `None` outside every block.
    pub fn show_selected(
        &mut self,
        ui: &mut egui::Ui,
        view: &FunctionView,
        selected: Option<u64>,
        related: &BTreeSet<u64>,
        menu: impl FnOnce(&mut egui::Ui, Option<u64>),
    ) -> Option<GraphAction> {
        // The app replaces the canvas with its graph; geometry is never
        // rebuilt here for another view.
        if self.function != view.address {
            return None;
        }
        let mut zoom_change = 1.0;
        ui.horizontal_wrapped(|ui| {
            if ui.button("Fit").clicked() {
                self.needs_fit = true;
            }
            if ui.button("Entry").clicked() {
                self.reveal = Some(Reveal::Entry);
            }
            if ui.button("−").clicked() {
                zoom_change /= 1.2;
            }
            if ui.button("+").clicked() {
                zoom_change *= 1.2;
            }
            ui.label(format!("{:.0}%", self.zoom * 100.0))
                .on_hover_text("Drag to pan · Ctrl+wheel to zoom · double-click a call to follow");
            egui::containers::menu::MenuButton::from_button(
                egui::Button::new(egui::RichText::new("Legend").color(theme::MUTED))
                    .frame_when_inactive(false),
            )
            .ui(ui, |ui| {
                for (kind, label) in [
                    (EdgeKind::True, "T: true"),
                    (EdgeKind::False, "F: false"),
                    (EdgeKind::Branch, "B: branch"),
                    (EdgeKind::Branch, "S: recovered switch"),
                    (EdgeKind::Unknown, "?: unresolved"),
                ] {
                    ui.colored_label(edge_color(kind), label);
                }
            })
            .0
            .on_hover_text("T true · F false · B branch\nS recovered switch · ? unresolved");
            let warnings = graph_notes(view).collect::<Vec<_>>();
            if !warnings.is_empty() {
                theme::warning_menu(ui, warnings.len(), |ui| {
                    ui.set_max_width(420.0);
                    egui::ScrollArea::vertical()
                        .max_height(260.0)
                        .show(ui, |ui| {
                            for warning in warnings {
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(warning).color(theme::WARNING),
                                    )
                                    .wrap(),
                                );
                            }
                        });
                })
                .response
                .on_hover_text("Graph warnings");
            }
        });
        let size = ui.available_size().max(vec2(1.0, 1.0));
        let (canvas, response) = ui.allocate_exact_size(size, Sense::click_and_drag());
        if self.awaiting {
            // Fit, Entry and reveals apply once the final rows are adopted.
        } else if self.needs_initial_view {
            self.initial_view(canvas.size());
        } else if self.needs_fit {
            self.fit(canvas.size());
        }
        self.change_zoom(zoom_change, canvas.size() * 0.5);
        if !self.awaiting
            && let Some(reveal) = self.reveal.take()
        {
            self.reveal_at(reveal, canvas.size());
        }

        if response.dragged() {
            self.pan += response.drag_delta();
        }
        if response.hovered() {
            let (zoom_delta, scroll, pointer) = ui.input(|input| {
                (
                    input.zoom_delta(),
                    input.smooth_scroll_delta,
                    input.pointer.hover_pos(),
                )
            });
            if let Some(pointer) = pointer {
                self.change_zoom(zoom_delta, pointer - canvas.min);
            }
            // Ctrl-wheel is supplied as zoom_delta by egui. Ordinary wheel scroll
            // remains useful for panning a large graph without dragging.
            self.pan += scroll;
        }
        #[cfg(test)]
        {
            self.painted = Painted::default();
        }
        let painter = ui.painter_at(canvas);
        painter.rect_filled(canvas, 0.0, theme::GRAPH_BACKGROUND);
        let layout = Arc::clone(&self.layout);
        if self.needs_initial_view {
            // No camera yet: awaiting the first comment geometry.
            return None;
        }
        if layout.nodes.is_empty() {
            painter.text(
                canvas.center(),
                Align2::CENTER_CENTER,
                "No decoded basic blocks",
                FontId::proportional(16.0),
                theme::MUTED,
            );
            return None;
        }
        let (zoom, pan) = (self.zoom, self.pan);
        let screen = |point: Pos2| canvas.min + pan + point.to_vec2() * zoom;
        // The canvas in world coordinates, computed once per frame.
        let world = Rect::from_min_max(
            (-pan / zoom).to_pos2(),
            ((canvas.size() - pan) / zoom).to_pos2(),
        );
        let ppp = ui.ctx().pixels_per_point();
        let text_rows = zoom >= ROW_TEXT_ZOOM;
        let margin = 24.0 / zoom;
        for edge in &layout.edges {
            if !edge.bounds.expand(margin).intersects(world) {
                continue;
            }
            let points: Vec<_> = edge.points.iter().copied().map(screen).collect();
            let stroke = Stroke::new(1.5, edge_color(edge.kind));
            for pair in points.windows(2) {
                // Clip before making dashes: a long off-screen edge must not
                // allocate thousands of invisible paint shapes when zoomed in.
                let Some((start, end)) = clip_segment(pair[0], pair[1], canvas.expand(2.0)) else {
                    continue;
                };
                if edge.unresolved {
                    dashed_line(&painter, start, end, stroke);
                } else {
                    painter.line_segment([start, end], stroke);
                }
            }
            if zoom >= ARROWHEAD_ZOOM
                && let [.., previous, tip] = points.as_slice()
                && canvas.expand(10.0).contains(*tip)
            {
                let direction = (*tip - *previous).normalized();
                let side = vec2(-direction.y, direction.x);
                painter.line_segment([*tip, *tip - direction * 9.0 + side * 4.0], stroke);
                painter.line_segment([*tip, *tip - direction * 9.0 - side * 4.0], stroke);
            }
            if zoom >= READABLE_ZOOM {
                let at = screen(edge.label_position);
                if !canvas.expand(24.0).contains(at) {
                    continue;
                }
                // Labels scale with their routes, and disappear in overview.
                let galley = painter.layout_no_wrap(
                    edge.label.clone(),
                    FontId::monospace(11.0 * zoom),
                    stroke.color,
                );
                painter.rect_filled(
                    Rect::from_min_size(at - vec2(2.0, 1.0), galley.size() + vec2(4.0, 2.0)),
                    2.0,
                    theme::GRAPH_BACKGROUND,
                );
                painter.galley(at, galley, stroke.color);
            }
        }
        // Selection is resolved through the exact address index once per
        // frame, never by scanning each block's rows.
        let mut highlighted = vec![false; layout.nodes.len()];
        let mut accents = Vec::new();
        for &address in selected.iter().chain(related) {
            if let Some((node, row)) = layout.instruction(address) {
                highlighted[node] = true;
                accents.push((node, row));
            } else if let Some(node) = layout.block(address) {
                highlighted[node] = true;
            }
        }
        accents.sort_unstable();
        accents.dedup();
        let mut clicked = None;
        let secondary = response.secondary_clicked();
        if secondary {
            self.context = None;
        }
        for (index, node) in layout.nodes.iter().enumerate() {
            if !node.rect.intersects(world) {
                continue;
            }
            let rect = Rect::from_min_max(screen(node.rect.min), screen(node.rect.max));
            let is_selected = highlighted[index];
            let radius = theme::scaled_radius(zoom);
            painter.rect_filled(rect, radius, theme::VIEW);
            painter.rect_stroke(
                rect,
                radius,
                Stroke::new(
                    if is_selected { 2.0 } else { 1.0 },
                    if is_selected {
                        theme::BLUE
                    } else {
                        theme::BORDER
                    },
                ),
                StrokeKind::Inside,
            );
            let header = Rect::from_min_max(rect.min, pos2(rect.max.x, rect.min.y + HEADER * zoom));
            let header_color = if is_selected {
                theme::NODE_SELECTED
            } else if node.address == view.address {
                theme::NODE_ENTRY
            } else if node.is_return {
                theme::NODE_RETURN
            } else {
                theme::HEADER
            };
            let top = radius.saturating_sub(1);
            painter.rect_filled(
                header.shrink(zoom.min(1.0)),
                egui::CornerRadius {
                    nw: top,
                    ne: top,
                    sw: 0,
                    se: 0,
                },
                header_color,
            );
            let node_painter = painter.with_clip_rect(rect.intersect(canvas));
            if zoom >= HEADER_TEXT_ZOOM {
                node_painter.text(
                    header.left_center() + vec2(9.0 * zoom, 0.0),
                    Align2::LEFT_CENTER,
                    &node.header,
                    FontId::monospace(14.0 * zoom),
                    theme::TEXT,
                );
            }
            let rows = node.visible_rows(world);
            let row_rect = |row: usize, count: usize| {
                Rect::from_min_size(
                    pos2(
                        rect.min.x,
                        rect.min.y + (HEADER + row as f32 * ROW_HEIGHT) * zoom,
                    ),
                    vec2(rect.width(), count as f32 * ROW_HEIGHT * zoom),
                )
            };
            let first = accents.partition_point(|&(node, row)| (node, row) < (index, rows.start));
            let node_accents = accents[first..]
                .iter()
                .take_while(|&&(node, row)| node == index && row < rows.end)
                .map(|&(_, row)| row);
            if text_rows {
                for row in rows.clone() {
                    let line = &node.rows[row];
                    let area = row_rect(row, 1);
                    if selected == Some(line.address) || related.contains(&line.address) {
                        node_painter.rect_filled(
                            area.shrink2(vec2(2.0, 0.0)),
                            0.0,
                            theme::CURRENT_LINE,
                        );
                    }
                    let color = match line.kind {
                        RowKind::Instruction => theme::TEXT,
                        RowKind::Comment => theme::SYNTAX_COMMENT,
                    };
                    let mut job = egui::text::LayoutJob::default();
                    let split = line.name_start.unwrap_or(line.text.len());
                    job.append(
                        &line.text[..split],
                        0.0,
                        egui::TextFormat {
                            font_id: FontId::monospace(12.0 * zoom),
                            color,
                            ..Default::default()
                        },
                    );
                    if split < line.text.len() {
                        job.append(
                            &line.text[split..],
                            0.0,
                            egui::TextFormat {
                                font_id: FontId::proportional(13.0 * zoom),
                                color: theme::SYNTAX_FUNCTION,
                                ..Default::default()
                            },
                        );
                    }
                    let galley = node_painter.layout_job(job);
                    node_painter.galley(
                        area.left_center() + vec2(8.0 * zoom, -galley.size().y * 0.5),
                        galley,
                        theme::TEXT,
                    );
                    #[cfg(test)]
                    {
                        self.painted.text_rows += 1;
                    }
                }
            } else {
                // Rows too small to read become marks, binned so that at most
                // one is drawn per few physical pixels of the viewport.
                let pitch = ROW_HEIGHT * zoom * ppp;
                let per_mark = if pitch >= MARK_PIXELS {
                    1
                } else {
                    ((MARK_PIXELS / pitch).ceil() as usize).max(1)
                };
                let thickness = |area: Rect| (area.height() * 0.5).max(1.0 / ppp);
                for mark in rows.start / per_mark..rows.end.div_ceil(per_mark) {
                    let row = mark * per_mark;
                    let line = &node.rows[row];
                    let area = row_rect(row, per_mark.min(node.rows.len() - row));
                    let chars = line.text.len().min(ROW_CHARS + 1) as f32;
                    let width = (chars * CHAR_WIDTH * zoom).min(rect.width() - 16.0 * zoom);
                    node_painter.rect_filled(
                        Rect::from_min_size(
                            pos2(
                                area.left() + 8.0 * zoom,
                                area.center().y - thickness(area) * 0.5,
                            ),
                            vec2(width.max(0.0), thickness(area)),
                        ),
                        0.0,
                        match line.kind {
                            RowKind::Comment if per_mark == 1 => theme::SYNTAX_COMMENT,
                            _ => theme::MUTED.gamma_multiply(0.6),
                        },
                    );
                    #[cfg(test)]
                    {
                        self.painted.marks += 1;
                    }
                }
                for row in node_accents {
                    let area = row_rect(row, 1);
                    let height = area.height().max(MARK_PIXELS / ppp);
                    node_painter.rect_filled(
                        Rect::from_center_size(area.center(), vec2(area.width(), height))
                            .shrink2(vec2(2.0, 0.0)),
                        0.0,
                        theme::BLUE,
                    );
                    #[cfg(test)]
                    {
                        self.painted.marks += 1;
                    }
                }
            }
            if (response.clicked() || response.double_clicked())
                && let Some(pointer) = response.interact_pointer_pos()
                && rect.contains(pointer)
            {
                let world = ((pointer - canvas.min) - pan) / zoom;
                let address = node.hit_at(world.to_pos2(), zoom);
                clicked = Some(instruction_action(view, address, response.double_clicked()));
            }
            if secondary
                && let Some(pointer) = response.interact_pointer_pos()
                && rect.contains(pointer)
            {
                let world = ((pointer - canvas.min) - pan) / zoom;
                let address = node.hit_at(world.to_pos2(), zoom);
                self.context = Some(address);
                clicked = Some(GraphAction::Select(address));
            }
        }
        let context = self.context;
        response.context_menu(|ui| menu(ui, context));
        clicked
    }

    fn fit(&mut self, size: Vec2) {
        let bounds = self.layout.bounds;
        self.zoom = ((size.x - 48.0).max(1.0) / bounds.width().max(1.0))
            .min((size.y - 48.0).max(1.0) / bounds.height().max(1.0))
            .clamp(MIN_ZOOM, 1.2);
        self.pan = size * 0.5 - bounds.center().to_vec2() * self.zoom;
        self.needs_fit = false;
    }

    fn initial_view(&mut self, size: Vec2) {
        self.fit(size);
        self.needs_initial_view = false;
        // Fit is an explicit overview action. Opening a large function should
        // instead start at its entry with instruction text large enough to read.
        if self.zoom < READABLE_ZOOM {
            self.zoom = ((size.x - 48.0) / WIDTH).clamp(READABLE_ZOOM, 1.0);
            if let Some(entry) = self.layout.block(self.function) {
                let entry = self.layout.nodes[entry].rect;
                self.pan = vec2(
                    size.x * 0.5 - entry.center().x * self.zoom,
                    REVEAL_MARGIN - entry.top() * self.zoom,
                );
            }
        }
    }

    /// Brings the target row into view at readable scale. The camera is left
    /// alone when the row is already visible; a block taller than the canvas
    /// is never centered as a whole.
    fn reveal_at(&mut self, reveal: Reveal, size: Vec2) {
        let layout = &self.layout;
        let (node, target) = match reveal {
            Reveal::Instruction(address) => {
                if let Some((node, row)) = layout.instruction(address) {
                    (node, layout.nodes[node].row_rect(row))
                } else if let Some(node) = layout.block(address) {
                    (node, layout.nodes[node].entry_rect())
                } else {
                    return;
                }
            }
            Reveal::Entry => {
                let Some(node) = layout.block(self.function) else {
                    return;
                };
                (node, layout.nodes[node].entry_rect())
            }
        };
        let block = layout.nodes[node].rect;
        self.zoom = self.zoom.max(READABLE_ZOOM);
        let on_screen = |rect: Rect, pan: Vec2, zoom: f32| {
            Rect::from_min_max(
                Pos2::ZERO + pan + rect.min.to_vec2() * zoom,
                Pos2::ZERO + pan + rect.max.to_vec2() * zoom,
            )
        };
        let block = on_screen(block, self.pan, self.zoom);
        let mut target = on_screen(target, self.pan, self.zoom);
        // A block wider than the canvas only needs its row text visible.
        let fits = block.width() <= size.x;
        if !fits {
            target.max.x = target.min.x + size.x * 0.5;
        }
        if Rect::from_min_size(Pos2::ZERO, size).contains_rect(target) {
            return;
        }
        if target.left() < 0.0 || target.right() > size.x {
            self.pan.x += if fits {
                size.x * 0.5 - block.center().x
            } else {
                REVEAL_MARGIN.min(size.x * 0.1) - block.left()
            };
        }
        if target.top() < 0.0 || target.bottom() > size.y || reveal == Reveal::Entry {
            self.pan.y += match reveal {
                Reveal::Entry => REVEAL_MARGIN.min(size.y * 0.1) - target.top(),
                Reveal::Instruction(_) => size.y * 0.5 - target.center().y,
            };
        }
    }

    fn change_zoom(&mut self, factor: f32, anchor: Vec2) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let next = (self.zoom * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        self.pan = anchor - (anchor - self.pan) * (next / self.zoom);
        self.zoom = next;
    }
}

impl Node {
    fn row_rect(&self, row: usize) -> Rect {
        Rect::from_min_size(
            pos2(
                self.rect.left(),
                self.rect.top() + HEADER + row as f32 * ROW_HEIGHT,
            ),
            vec2(self.rect.width(), ROW_HEIGHT),
        )
    }

    /// The header and first row: what Entry shows of a tall block.
    fn entry_rect(&self) -> Rect {
        let rows = self.rows.len().min(1) as f32;
        Rect::from_min_size(
            self.rect.min,
            vec2(self.rect.width(), HEADER + rows * ROW_HEIGHT),
        )
    }

    /// Rows intersecting world-space `view`, including partial ones.
    fn visible_rows(&self, view: Rect) -> Range<usize> {
        let top = self.rect.top() + HEADER;
        theme::visible_rows(
            Rangef::new(
                view.top() - top,
                view.bottom().min(self.rect.bottom()) - top,
            ),
            ROW_HEIGHT,
            self.rows.len(),
        )
    }

    /// The exact PC under world `point` at readable scale. Header, footer and
    /// overview clicks select the block.
    fn hit_at(&self, point: Pos2, zoom: f32) -> u64 {
        let offset = point.y - self.rect.top() - HEADER;
        if zoom >= ROW_TEXT_ZOOM && offset >= 0.0 {
            let row = (offset / ROW_HEIGHT).floor() as usize;
            if let Some(row) = self.rows.get(row) {
                return row.address;
            }
        }
        self.address
    }
}

impl GraphGeometry {
    pub fn new(view: &FunctionView) -> Self {
        Self::annotated(view, &BTreeMap::new(), &BTreeMap::new())
    }

    /// Allocation capacity retained by this geometry, including itself.
    pub fn retained_bytes(&self) -> Option<usize> {
        use crate::result_store::Bytes;
        let mut bytes = Bytes::of::<Self>()
            .slots::<Node>(self.nodes.capacity())
            .slots::<RoutedEdge>(self.edges.capacity())
            .slots::<(u64, u32, u32)>(self.instructions.len())
            .slots::<(u64, u32)>(self.blocks.len());
        for node in &self.nodes {
            bytes = bytes
                .slots::<GraphRow>(node.rows.capacity())
                .plus(node.header.capacity());
            for row in &node.rows {
                bytes = bytes.plus(row.text.capacity());
            }
        }
        for edge in &self.edges {
            bytes = bytes
                .slots::<Pos2>(edge.points.capacity())
                .plus(edge.label.capacity());
        }
        bytes.total()
    }

    /// The node and row of the instruction at exactly `address`.
    fn instruction(&self, address: u64) -> Option<(usize, usize)> {
        let index = self
            .instructions
            .binary_search_by_key(&address, |entry| entry.0)
            .ok()?;
        let (_, node, row) = self.instructions[index];
        Some((node as usize, row as usize))
    }

    /// The node of the block starting at exactly `address`.
    fn block(&self, address: u64) -> Option<usize> {
        let index = self
            .blocks
            .binary_search_by_key(&address, |entry| entry.0)
            .ok()?;
        Some(self.blocks[index].1 as usize)
    }

    /// Geometry with comment rows and verified call names, by instruction
    /// address. Text beyond [`row_prefix`] is never displayed.
    pub fn annotated(
        view: &FunctionView,
        comments: &BTreeMap<u64, String>,
        call_names: &BTreeMap<u64, String>,
    ) -> Self {
        Self::prepare(view, comments, call_names, &|| false).expect("never cancelled")
    }

    /// A conservative allocation estimate for preparing `view` with
    /// `comment_rows` comment rows, charged before the work starts.
    pub fn estimated_bytes(view: &FunctionView, comment_rows: usize) -> usize {
        let blocks = view.blocks.len().min(MAX_GRAPH_BLOCKS);
        let instructions = view
            .blocks
            .iter()
            .take(blocks)
            .map(|block| block.instructions.len())
            .fold(0usize, usize::saturating_add)
            .min(MAX_GRAPH_INSTRUCTIONS);
        let rows = instructions.saturating_add(comment_rows.min(instructions));
        // Each row holds at most ROW_CHARS + 1 four-byte characters.
        let row = size_of::<GraphRow>() + (ROW_CHARS + 1) * 4;
        let edge = size_of::<RoutedEdge>() + 6 * size_of::<Pos2>() + 64;
        let node = size_of::<Node>() + size_of::<(u64, u32)>() + 48;
        size_of::<Self>()
            .saturating_add(rows.saturating_mul(row))
            .saturating_add(instructions.saturating_mul(size_of::<(u64, u32, u32)>()))
            .saturating_add(blocks.saturating_mul(node))
            .saturating_add(view.edges.len().min(MAX_GRAPH_EDGES).saturating_mul(edge))
    }

    /// Lays out every row of `view` once. `cancelled` is polled between
    /// phases; a cancelled preparation returns `None`.
    pub fn prepare(
        view: &FunctionView,
        comments: &BTreeMap<u64, String>,
        call_names: &BTreeMap<u64, String>,
        cancelled: &dyn Fn() -> bool,
    ) -> Option<Self> {
        let no_return: BTreeSet<_> = view
            .calls
            .iter()
            .filter(|call| call.no_return.is_some())
            .map(|call| call.address)
            .collect();
        let mut blocks: BTreeMap<_, _> = BTreeMap::new();
        for block in view.blocks.iter().take(MAX_GRAPH_BLOCKS) {
            blocks.entry(block.address).or_insert(block);
        }
        let mut successors: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for edge in view.edges.iter().take(MAX_GRAPH_EDGES) {
            if let Some(target) = edge.target
                && blocks.contains_key(&edge.source)
                && blocks.contains_key(&target)
            {
                successors.entry(edge.source).or_default().insert(target);
            }
        }
        let mut ranks = BTreeMap::<u64, usize>::new();
        let roots = std::iter::once(view.address).chain(blocks.keys().copied());
        for root in roots {
            if !blocks.contains_key(&root) || ranks.contains_key(&root) {
                continue;
            }
            let first_rank = ranks.values().max().map_or(0, |rank| rank + 1);
            ranks.insert(root, first_rank);
            let mut queue = VecDeque::from([root]);
            while let Some(source) = queue.pop_front() {
                let next = ranks[&source] + 1;
                for target in successors.get(&source).into_iter().flatten() {
                    if !ranks.contains_key(target) {
                        ranks.insert(*target, next);
                        queue.push_back(*target);
                    }
                }
            }
        }
        let mut rows: BTreeMap<usize, Vec<u64>> = BTreeMap::new();
        for (&address, &rank) in &ranks {
            rows.entry(rank).or_default().push(address);
        }
        let max_columns = rows.values().map(Vec::len).max().unwrap_or(1);
        let total_width = max_columns as f32 * (WIDTH + 60.0) - 60.0;
        let mut nodes = Vec::with_capacity(blocks.len());
        // Defensive only: validated views never exceed the aggregate budget,
        // and a larger view is reported by `graph_notes`.
        let mut budget = MAX_GRAPH_INSTRUCTIONS;
        let mut y = 0.0;
        for addresses in rows.values() {
            let mut row_height: f32 = 0.0;
            let row_width = addresses.len() as f32 * (WIDTH + 60.0) - 60.0;
            for (column, address) in addresses.iter().enumerate() {
                if cancelled() {
                    return None;
                }
                let block = blocks[address];
                let instructions = &block.instructions[..block.instructions.len().min(budget)];
                budget -= instructions.len();
                let mut lines = Vec::with_capacity(instructions.len());
                for instruction in instructions {
                    let callee = call_names
                        .get(&instruction.address)
                        .map_or(String::new(), |name| format!("  {name}"));
                    let code = format!(
                        "{:08x}  {:<8} {}",
                        instruction.address, instruction.mnemonic, instruction.operands
                    );
                    let text = crop(&format!("{code}{callee}"), ROW_CHARS);
                    let name_start = (!callee.is_empty() && code.len() + 2 < text.len())
                        .then_some(code.len() + 2);
                    lines.push(GraphRow {
                        address: instruction.address,
                        kind: RowKind::Instruction,
                        text,
                        name_start,
                    });
                    if let Some(comment) = comments.get(&instruction.address) {
                        lines.push(GraphRow {
                            address: instruction.address,
                            kind: RowKind::Comment,
                            name_start: None,
                            text: format!(
                                "; {}",
                                crate::annotation_display::preview(comment, ROW_CHARS)
                            ),
                        });
                    }
                }
                lines.shrink_to_fit();
                let height = HEADER + lines.len() as f32 * ROW_HEIGHT + FOOTER;
                row_height = row_height.max(height);
                let rect = Rect::from_min_size(
                    pos2(
                        (total_width - row_width) / 2.0 + column as f32 * (WIDTH + 60.0),
                        y,
                    ),
                    vec2(WIDTH, height),
                );
                let no_return = instructions
                    .last()
                    .is_some_and(|instruction| no_return.contains(&instruction.address));
                nodes.push(Node {
                    address: *address,
                    rect,
                    rows: lines,
                    header: format!(
                        "block {address:x}{}",
                        if no_return { " [no return]" } else { "" }
                    ),
                    is_return: instructions
                        .last()
                        .is_some_and(|instruction| instruction.mnemonic.starts_with("RET")),
                });
            }
            // A rank starts below the tallest block of the previous one.
            y += row_height + ROW_GAP;
        }
        if cancelled() {
            return None;
        }
        let mut instruction_index = Vec::with_capacity(MAX_GRAPH_INSTRUCTIONS - budget);
        for (node, block) in nodes.iter().enumerate() {
            for (row, line) in block.rows.iter().enumerate() {
                if line.kind == RowKind::Instruction {
                    instruction_index.push((line.address, node as u32, row as u32));
                }
            }
        }
        // Stable: a duplicate address keeps its first row.
        instruction_index.sort_by_key(|entry| entry.0);
        instruction_index.dedup_by_key(|entry| entry.0);
        let mut block_index: Vec<_> = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.address, index as u32))
            .collect();
        block_index.sort_unstable();
        let positions: BTreeMap<_, _> =
            nodes.iter().map(|node| (node.address, node.rect)).collect();
        let row_bounds: BTreeMap<_, _> = rows
            .iter()
            .map(|(&rank, addresses)| {
                let bounds = addresses
                    .iter()
                    .map(|address| positions[address])
                    .reduce(Rect::union)
                    .expect("layout rows contain nodes");
                (rank, bounds)
            })
            .collect();
        let mut bounds = nodes
            .iter()
            .map(|node| node.rect)
            .reduce(Rect::union)
            .unwrap_or(Rect::from_min_size(Pos2::ZERO, vec2(1.0, 1.0)));
        let mut edges = Vec::new();
        let mut left_lanes = Vec::new();
        let mut right_lanes = Vec::new();
        for (index, edge) in view.edges.iter().take(MAX_GRAPH_EDGES).enumerate() {
            if cancelled() {
                return None;
            }
            let Some(source) = positions.get(&edge.source) else {
                continue;
            };
            let (label, color_kind) = match edge.kind {
                EdgeKind::True => ("T", EdgeKind::True),
                EdgeKind::False => ("F", EdgeKind::False),
                EdgeKind::Branch if edge.evidence == Some(EdgeEvidence::EngineJumpTable) => {
                    ("S", EdgeKind::Branch)
                }
                EdgeKind::Branch => ("B", EdgeKind::Branch),
                EdgeKind::Unknown => ("?", EdgeKind::Unknown),
            };
            let offset = match edge.kind {
                EdgeKind::True => -24.0,
                EdgeKind::False => 24.0,
                _ => 0.0,
            };
            let start = source.center_bottom() + vec2(offset, 0.0);
            let (points, label, unresolved) =
                if let Some(target) = edge.target.and_then(|address| positions.get(&address)) {
                    let end = target.center_top() + vec2(offset, 0.0);
                    let source_rank = ranks[&edge.source];
                    let target_rank = ranks[&edge.target.expect("resolved target")];
                    if target_rank == source_rank + 1 {
                        // Only adjacent rows may use the inter-row corridor.
                        // Routing a skipped rank this way cuts through nodes.
                        let middle =
                            (row_bounds[&source_rank].bottom() + target.top()) / 2.0 + offset * 0.3;
                        (
                            vec![start, pos2(start.x, middle), pos2(end.x, middle), end],
                            label.to_owned(),
                            false,
                        )
                    } else {
                        let source_y = row_bounds[&source_rank].bottom() + 24.0 + offset * 0.2;
                        let target_y = target.top() - 24.0 + offset * 0.2;
                        let left = match edge.kind {
                            EdgeKind::True => true,
                            EdgeKind::False => false,
                            _ => {
                                let center = (source.center().x + target.center().x) * 0.5;
                                if (center - total_width * 0.5).abs() < 1.0 {
                                    index % 2 == 0
                                } else {
                                    center < total_width * 0.5
                                }
                            }
                        };
                        let lane = allocate_lane(
                            if left {
                                &mut left_lanes
                            } else {
                                &mut right_lanes
                            },
                            source_y,
                            target_y,
                        );
                        let channel = if left {
                            -32.0 - lane as f32 * 18.0
                        } else {
                            total_width + 32.0 + lane as f32 * 18.0
                        };
                        let backward = target_rank <= source_rank;
                        (
                            vec![
                                start,
                                pos2(start.x, source_y),
                                pos2(channel, source_y),
                                pos2(channel, target_y),
                                pos2(end.x, target_y),
                                end,
                            ],
                            if backward {
                                format!("{label} ↶")
                            } else {
                                label.to_owned()
                            },
                            false,
                        )
                    }
                } else {
                    let end = pos2(
                        start.x + 110.0,
                        row_bounds[&ranks[&edge.source]].bottom() + 40.0,
                    );
                    let target = edge.target.map_or_else(
                        || "unresolved".into(),
                        |address| format!("{address:x} outside graph"),
                    );
                    (
                        vec![start, pos2(start.x, end.y), end],
                        format!("{label} → {target}"),
                        true,
                    )
                };
            let label_position = if unresolved {
                *points.last().unwrap() + vec2(4.0, -7.0)
            } else {
                points[1] + vec2(5.0, -15.0)
            };
            // Conservative label extent: the readable label font is 11 points.
            let label_width = (label.chars().count() as f32 * CHAR_WIDTH + 8.0)
                .max(if unresolved { 190.0 } else { 40.0 });
            let edge_bounds = Rect::from_points(&points)
                .union(Rect::from_min_size(label_position, vec2(label_width, 18.0)));
            bounds = bounds.union(edge_bounds);
            edges.push(RoutedEdge {
                points,
                bounds: edge_bounds,
                kind: if unresolved {
                    EdgeKind::Unknown
                } else {
                    color_kind
                },
                label,
                label_position,
                unresolved,
            });
        }
        if cancelled() {
            return None;
        }
        Some(Self {
            nodes,
            edges,
            bounds,
            instructions: instruction_index.into(),
            blocks: block_index.into(),
        })
    }
}

/// The bounded prefix of a comment or name that can reach a graph row, so
/// annotation snapshots never copy longer text.
pub fn row_prefix(text: &str) -> String {
    text.chars().take(ROW_CHARS + 1).collect()
}

fn crop(text: &str, limit: usize) -> String {
    let mut characters = text.chars();
    let prefix: String = characters.by_ref().take(limit).collect();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

// Reuse an outer lane only when its vertical intervals are disjoint. The old
// modulo-eight channels stacked unrelated loops on exactly the same trunk.
fn allocate_lane(lanes: &mut Vec<Vec<(f32, f32)>>, start: f32, end: f32) -> usize {
    let interval = (start.min(end) - 8.0, start.max(end) + 8.0);
    let index = lanes
        .iter()
        .position(|occupied| {
            occupied
                .iter()
                .all(|&(min, max)| interval.1 < min || interval.0 > max)
        })
        .unwrap_or_else(|| {
            lanes.push(Vec::new());
            lanes.len() - 1
        });
    lanes[index].push(interval);
    index
}

fn clip_segment(start: Pos2, end: Pos2, clip: Rect) -> Option<(Pos2, Pos2)> {
    let delta = end - start;
    let mut min: f32 = 0.0;
    let mut max: f32 = 1.0;
    for (origin, direction, lower, upper) in [
        (start.x, delta.x, clip.left(), clip.right()),
        (start.y, delta.y, clip.top(), clip.bottom()),
    ] {
        if direction.abs() <= f32::EPSILON {
            if origin < lower || origin > upper {
                return None;
            }
        } else {
            let a = (lower - origin) / direction;
            let b = (upper - origin) / direction;
            min = min.max(a.min(b));
            max = max.min(a.max(b));
            if min > max {
                return None;
            }
        }
    }
    Some((start + delta * min, start + delta * max))
}

// Display-only compatibility for saved graphs; never alter stored diagnostics.
const LEGACY_CFG_NOTE: &str = "CFG uses bounded static instruction flow with engine switch-table recovery; exceptions, no-return calls, and other indirect jumps may be incomplete.";

fn graph_notes(view: &FunctionView) -> impl Iterator<Item = &str> {
    let instructions = view
        .blocks
        .iter()
        .take(MAX_GRAPH_BLOCKS)
        .map(|block| block.instructions.len())
        .fold(0usize, usize::saturating_add);
    view.warnings
        .iter()
        .map(String::as_str)
        .filter(|note| *note != LEGACY_CFG_NOTE)
        .chain(
            (view.blocks.len() > MAX_GRAPH_BLOCKS).then_some("Graph preview limited to 128 blocks"),
        )
        .chain(
            (instructions > MAX_GRAPH_INSTRUCTIONS)
                .then_some("Graph preview limited to 2048 instructions"),
        )
}

fn edge_color(kind: EdgeKind) -> Color32 {
    match kind {
        EdgeKind::True => theme::EDGE_TRUE,
        EdgeKind::False => theme::ERROR,
        EdgeKind::Branch => theme::BLUE,
        EdgeKind::Unknown => theme::WARNING,
    }
}

fn dashed_line(painter: &egui::Painter, start: Pos2, end: Pos2, stroke: Stroke) {
    let length = start.distance(end);
    if length <= f32::EPSILON {
        return;
    }
    let direction = (end - start) / length;
    let mut distance = 0.0;
    while distance < length {
        painter.line_segment(
            [
                start + direction * distance,
                start + direction * (distance + 6.0).min(length),
            ],
            stroke,
        );
        distance += 11.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{BasicBlock, CallSite, Edge, Instruction};

    #[test]
    fn toolbar_preserves_saved_diagnostics_and_exposes_legend() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut view = fixture();
        let near = format!("{LEGACY_CFG_NOTE} Custom detail.");
        view.warnings = vec![
            LEGACY_CFG_NOTE.into(),
            "Decode failed".into(),
            "Instruction budget reached".into(),
            "Unresolved indirect jump".into(),
            "Partial switch table".into(),
            near.clone(),
        ];
        let stored = view.warnings.clone();
        let mut canvas = GraphCanvas::new(&view);
        let frame = |canvas: &mut GraphCanvas, events| {
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(500.0, 500.0))),
                    events,
                    ..Default::default()
                },
                |ui| {
                    canvas.show(ui, &view, None);
                },
            );
            output.textures_delta.clear();
            output
        };
        let text = |out: &egui::FullOutput| {
            out.shapes
                .iter()
                .filter_map(|s| {
                    if let egui::Shape::Text(t) = &s.shape {
                        Some(t.galley.text().to_owned())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        };
        let click = |out: &egui::FullOutput, label: &str| {
            let pos = out
                .shapes
                .iter()
                .find_map(|s| {
                    if let egui::Shape::Text(t) = &s.shape {
                        (t.galley.text() == label).then_some(t.pos + vec2(8.0, 5.0))
                    } else {
                        None
                    }
                })
                .unwrap();
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ]
        };
        frame(&mut canvas, vec![]);
        let out = frame(&mut canvas, vec![]);
        frame(&mut canvas, click(&out, "    5"));
        let out = frame(&mut canvas, vec![]);
        let texts = text(&out);
        assert!(texts.contains(&"Partial switch table".into()));
        assert!(texts.contains(&near));
        assert!(!texts.contains(&LEGACY_CFG_NOTE.into()));
        assert_eq!(view.warnings, stored);
        egui::Popup::close_all(&context);
        let out = frame(&mut canvas, vec![]);
        frame(&mut canvas, click(&out, "Legend"));
        let texts = text(&frame(&mut canvas, vec![]));
        for label in [
            "T: true",
            "F: false",
            "B: branch",
            "S: recovered switch",
            "?: unresolved",
        ] {
            assert!(texts.contains(&label.into()), "{label}");
        }
        view.warnings = vec![LEGACY_CFG_NOTE.into()];
        assert_eq!(graph_notes(&view).count(), 0);
    }

    fn fixture() -> FunctionView {
        FunctionView {
            address: 0x401146,
            blocks: [0x401146, 0x40115a, 0x40116b, 0x40117d, 0x401190]
                .into_iter()
                .map(|address| BasicBlock {
                    address,
                    instructions: vec![
                        Instruction {
                            address,
                            bytes: vec![0x83, 0xf8, 0x05],
                            mnemonic: "cmp".into(),
                            operands: "eax, 5".into(),
                        },
                        Instruction {
                            address: address + 3,
                            bytes: vec![0x75, 0x05],
                            mnemonic: "jne".into(),
                            operands: "0x40116b".into(),
                        },
                    ],
                })
                .collect(),
            edges: vec![
                Edge {
                    source: 0x401146,
                    target: Some(0x40115a),
                    kind: EdgeKind::True,
                    evidence: None,
                },
                Edge {
                    source: 0x401146,
                    target: Some(0x40116b),
                    kind: EdgeKind::False,
                    evidence: None,
                },
                Edge {
                    source: 0x40115a,
                    target: Some(0x40117d),
                    kind: EdgeKind::Branch,
                    evidence: None,
                },
                Edge {
                    source: 0x40116b,
                    target: Some(0x40117d),
                    kind: EdgeKind::Branch,
                    evidence: None,
                },
                Edge {
                    source: 0x40117d,
                    target: Some(0x401146),
                    kind: EdgeKind::True,
                    evidence: None,
                },
                Edge {
                    source: 0x401190,
                    target: None,
                    kind: EdgeKind::Unknown,
                    evidence: None,
                },
            ],
            calls: vec![],
            warnings: vec![],
        }
    }

    fn large_fixture() -> FunctionView {
        let mut view = fixture();
        view.address = 0x400000;
        view.blocks = (0..MAX_GRAPH_BLOCKS)
            .map(|index| {
                let address = view.address + index as u64 * 0x100;
                BasicBlock {
                    address,
                    instructions: (0..12)
                        .map(|instruction| Instruction {
                            address: address + instruction * 3,
                            bytes: vec![0x83, 0xf8, 0x05],
                            mnemonic: "cmp".into(),
                            operands: "a_very_long_operand".repeat(20),
                        })
                        .collect(),
                }
            })
            .collect();
        view.edges = view
            .blocks
            .windows(2)
            .map(|blocks| Edge {
                source: blocks[0].address,
                target: Some(blocks[1].address),
                kind: EdgeKind::Branch,
                evidence: None,
            })
            .collect();
        // Overlapping loop intervals must have distinct outer lanes.
        for source in [125, 126, 127] {
            view.edges.push(Edge {
                source: view.blocks[source].address,
                target: Some(view.address),
                kind: EdgeKind::True,
                evidence: None,
            });
        }
        view
    }

    fn screen_rect(graph: &GraphCanvas, rect: Rect) -> Rect {
        Rect::from_min_max(
            Pos2::ZERO + graph.pan + rect.min.to_vec2() * graph.zoom,
            Pos2::ZERO + graph.pan + rect.max.to_vec2() * graph.zoom,
        )
    }

    #[test]
    fn large_graph_starts_at_readable_entry_and_explicit_fit_shows_entire_graph() {
        let view = large_fixture();
        let mut graph = GraphCanvas::new(&view);
        let size = vec2(700.0, 720.0);
        let viewport = Rect::from_min_size(Pos2::ZERO, size);
        graph.initial_view(size);
        assert!(graph.zoom >= READABLE_ZOOM);
        let entry = graph
            .layout
            .nodes
            .iter()
            .find(|node| node.address == view.address)
            .unwrap();
        assert!(viewport.contains_rect(screen_rect(&graph, entry.rect)));
        graph.fit(size);
        assert!(graph.zoom < 0.08, "old zoom floor could not fit 128 blocks");
        assert!(viewport.contains_rect(screen_rect(&graph, graph.layout.bounds)));
        for node in &graph.layout.nodes {
            assert!(viewport.contains_rect(screen_rect(&graph, node.rect)));
        }
    }

    #[test]
    fn overview_hides_labels_and_readable_text_is_clipped_to_its_node() {
        let view = large_fixture();
        let mut graph = GraphCanvas::new(&view);
        let context = egui::Context::default();
        let input = || egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(760.0, 900.0))),
            ..Default::default()
        };
        let mut readable = context.run_ui(input(), |ui| {
            graph.show(ui, &view, None);
        });
        readable.textures_delta.clear();
        let row = readable
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) if text.galley.text().contains("cmp") => {
                    Some((shape.clip_rect, text))
                }
                _ => None,
            })
            .expect("initial view draws readable instructions");
        assert!(row.0.width() <= WIDTH * graph.zoom + 0.01);
        assert!(row.1.galley.text().chars().count() <= 54);
        graph.needs_fit = true;
        let mut overview = context.run_ui(input(), |ui| {
            graph.show(ui, &view, None);
        });
        overview.textures_delta.clear();
        assert!(graph.zoom < HEADER_TEXT_ZOOM);
        for shape in &overview.shapes {
            if let egui::epaint::Shape::Text(text) = &shape.shape {
                let text = text.galley.text();
                assert!(!text.starts_with("block "));
                assert!(!text.contains("cmp"));
                assert!(!text.contains("more instructions"));
            }
        }
    }

    #[test]
    fn revealing_an_instruction_from_overview_is_readable_and_one_shot() {
        let view = large_fixture();
        let mut graph = GraphCanvas::new(&view);
        let context = egui::Context::default();
        let input = || egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(760.0, 900.0))),
            ..Default::default()
        };
        graph.needs_initial_view = false;
        graph.fit(vec2(700.0, 720.0));
        let last = view.blocks.last().unwrap();
        graph.reveal_instruction(last.instructions[10].address);
        let mut output = context.run_ui(input(), |ui| {
            graph.show(ui, &view, Some(last.instructions[10].address));
        });
        output.textures_delta.clear();
        assert!(graph.zoom >= READABLE_ZOOM);
        assert!(graph.reveal.is_none());
        assert!(output.shapes.iter().any(|shape| {
            matches!(&shape.shape, egui::epaint::Shape::Text(text)
                if text.galley.text().starts_with(&format!("{:08x}", last.instructions[10].address)))
        }));
        graph.pan += vec2(70.0, -30.0);
        let camera = (graph.zoom, graph.pan);
        let mut output = context.run_ui(input(), |ui| {
            graph.show(ui, &view, Some(last.instructions[10].address));
        });
        output.textures_delta.clear();
        assert_eq!((graph.zoom, graph.pan), camera);
    }

    #[test]
    fn nonlocal_edges_have_separate_outer_lanes_and_avoid_node_interiors() {
        let layout = Layout::new(&large_fixture());
        let loops: Vec<_> = layout
            .edges
            .iter()
            .filter(|edge| edge.label.contains('↶'))
            .collect();
        assert_eq!(loops.len(), 3);
        let lanes: BTreeSet<_> = loops
            .iter()
            .map(|edge| edge.points[2].x.to_bits())
            .collect();
        assert_eq!(lanes.len(), loops.len());
        for edge in loops {
            for pair in edge.points.windows(2) {
                for node in &layout.nodes {
                    assert!(clip_segment(pair[0], pair[1], node.rect.shrink(0.1)).is_none());
                }
            }
        }
    }

    #[test]
    fn long_edges_are_clipped_before_generating_dashes() {
        let clip = Rect::from_min_size(pos2(10.0, 20.0), vec2(600.0, 720.0));
        let (start, end) =
            clip_segment(pos2(100.0, -40_000.0), pos2(100.0, 40_000.0), clip).unwrap();
        assert!((start - pos2(100.0, clip.top())).length() < 0.01);
        assert!((end - pos2(100.0, clip.bottom())).length() < 0.01);
        assert!(start.distance(end) <= clip.height() + 0.01);
        assert!(clip_segment(pos2(-10.0, -40_000.0), pos2(-10.0, 40_000.0), clip).is_none());
    }

    #[test]
    fn cycles_and_disconnected_nodes_have_deterministic_nonoverlapping_layout() {
        let view = fixture();
        let layout = Layout::new(&view);
        assert_eq!(layout.nodes.len(), 5);
        for (index, node) in layout.nodes.iter().enumerate() {
            for other in &layout.nodes[index + 1..] {
                assert!(!node.rect.intersects(other.rect));
            }
        }
        let mut shuffled = fixture();
        shuffled.blocks.reverse();
        let again = Layout::new(&shuffled);
        assert_eq!(
            layout
                .nodes
                .iter()
                .map(|node| (node.address, node.rect))
                .collect::<Vec<_>>(),
            again
                .nodes
                .iter()
                .map(|node| (node.address, node.rect))
                .collect::<Vec<_>>()
        );
        assert!(layout.edges.iter().any(|edge| edge.label.contains('↶')));
        assert!(layout.edges.iter().any(|edge| edge.unresolved));
    }

    #[test]
    fn hit_testing_selects_instruction_or_header_and_zoom_preserves_anchor() {
        let view = fixture();
        let mut graph = GraphCanvas::new(&view);
        let node = &graph.layout.nodes[0];
        assert_eq!(
            node.hit_at(node.rect.min + vec2(20.0, 10.0), 1.0),
            node.address
        );
        assert_eq!(
            node.hit_at(node.rect.min + vec2(20.0, HEADER + ROW_HEIGHT + 5.0), 1.0),
            node.address + 3
        );
        assert_eq!(
            node.hit_at(node.rect.min + vec2(20.0, HEADER + ROW_HEIGHT + 5.0), 0.3),
            node.address
        );
        graph.pan = vec2(40.0, 60.0);
        let anchor = vec2(150.0, 200.0);
        let before = (anchor - graph.pan) / graph.zoom;
        graph.change_zoom(1.4, anchor);
        assert!(((anchor - graph.pan) / graph.zoom - before).length() < 0.001);
    }

    #[test]
    fn following_calls_uses_call_metadata_and_keeps_branch_and_indirect_selection() {
        let mut view = fixture();
        view.calls = vec![
            CallSite {
                address: 0x401149,
                target: Some(0x402000),
                no_return: None,
            },
            CallSite {
                address: 0x40115d,
                target: None,
                no_return: None,
            },
        ];
        // A resolved call follows its call-site target, independently of CFG edges
        // or the display text in the instruction operands.
        assert_eq!(
            instruction_action(&view, 0x401149, true),
            GraphAction::Navigate(0x402000)
        );
        assert_eq!(
            instruction_action(&view, 0x401149, false),
            GraphAction::Select(0x401149)
        );
        assert_eq!(
            instruction_action(&view, 0x401146, true),
            GraphAction::Select(0x401146)
        );
        assert_eq!(
            instruction_action(&view, 0x40115d, true),
            GraphAction::Select(0x40115d)
        );
    }

    #[test]
    fn headless_native_render_retains_camera_across_selection_changes() {
        let view = fixture();
        let mut graph = GraphCanvas::new(&view);
        let context = egui::Context::default();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            graph.show(ui, &view, Some(0x401146));
        });
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        let camera = (graph.zoom, graph.pan);
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            graph.show(ui, &view, Some(0x40116b));
        });
        output.textures_delta.clear();
        assert_eq!(camera, (graph.zoom, graph.pan));
    }

    #[test]
    fn graph_comment_rows_keep_exact_address_hits_and_update_without_resetting_camera() {
        let view = fixture();
        let address = view.address + 3;
        let mut graph = GraphCanvas::new(&view);
        let context = egui::Context::default();
        let mut comments = BTreeMap::from([(address, "branch comment */ literal".into())]);
        graph.set_comments(&view, (1, 1, 0), &comments, BTreeMap::new);
        // Keep the entry on screen at readable scale for an actual paint check.
        graph.zoom = 1.0;
        graph.pan = vec2(5.0, 5.0);
        graph.needs_initial_view = false;
        let node = graph
            .layout
            .nodes
            .iter()
            .find(|n| n.address == view.address)
            .unwrap();
        assert_eq!(
            (
                node.rows[2].address,
                node.rows[2].kind,
                node.rows[2].text.as_str()
            ),
            (address, RowKind::Comment, "; branch comment */ literal")
        );
        assert_eq!(
            node.hit_at(node.rect.min + vec2(10.0, HEADER + 2.5 * ROW_HEIGHT), 1.0),
            address
        );
        let camera = (graph.zoom, graph.pan);
        // Center the entry for the paint check; fixture layout has several columns.
        graph.pan = vec2(5.0, 5.0) - node.rect.min.to_vec2();
        let mut output = context.run_ui(egui::RawInput::default(), |ui| {
            graph.show(ui, &view, Some(address));
        });
        assert!(output.shapes.iter().any(|shape| matches!(&shape.shape,
            egui::epaint::Shape::Text(text) if text.galley.text().contains("branch comment */ literal"))));
        output.textures_delta.clear();
        graph.pan = camera.1;
        comments.insert(address, "edited".into());
        graph.set_comments(&view, (1, 2, 0), &comments, BTreeMap::new);
        assert_eq!((graph.zoom, graph.pan), camera);
        assert!(
            graph
                .layout
                .nodes
                .iter()
                .flat_map(|n| &n.rows)
                .any(|row| row.address == address && row.text == "; edited")
        );
        comments.clear();
        graph.set_comments(&view, (1, 3, 0), &comments, BTreeMap::new);
        assert!(
            !graph
                .layout
                .nodes
                .iter()
                .flat_map(|n| &n.rows)
                .any(|row| row.kind == RowKind::Comment)
        );
    }

    fn row_instruction(address: u64, index: u64) -> Instruction {
        Instruction {
            address,
            bytes: vec![0x48, 0x89, 0xc7, 0x90],
            mnemonic: "mov".into(),
            operands: format!("r{index}, rdi"),
        }
    }

    /// One block holding the whole aggregate instruction budget, a call near
    /// its end and a header-only exit block.
    fn tall_fixture() -> FunctionView {
        let entry = 0x10_0000;
        let instructions: Vec<_> = (0..MAX_GRAPH_INSTRUCTIONS as u64)
            .map(|index| row_instruction(entry + index * 4, index))
            .collect();
        let late_call = instructions[2040].address;
        FunctionView {
            address: entry,
            blocks: vec![
                BasicBlock {
                    address: entry,
                    instructions,
                },
                BasicBlock {
                    address: 0x20_0000,
                    instructions: vec![],
                },
            ],
            edges: vec![Edge {
                source: entry,
                target: Some(0x20_0000),
                kind: EdgeKind::Branch,
                evidence: None,
            }],
            calls: vec![
                CallSite {
                    address: late_call,
                    target: Some(0x30_0000),
                    no_return: None,
                },
                CallSite {
                    address: late_call + 4,
                    target: None,
                    no_return: None,
                },
            ],
            warnings: vec![],
        }
    }

    /// The aggregate budget spread over every block, in uneven sizes.
    fn distributed_fixture() -> FunctionView {
        let mut view = large_fixture();
        let mut total = 0;
        for (index, block) in view.blocks.iter_mut().enumerate() {
            let count = if index % 2 == 0 { 8 } else { 24 };
            total += count;
            block.instructions = (0..count as u64)
                .map(|row| row_instruction(block.address + row * 4, row))
                .collect();
        }
        assert_eq!(total, MAX_GRAPH_INSTRUCTIONS);
        view
    }

    fn context(scale: f32) -> egui::Context {
        let context = egui::Context::default();
        theme::install(&context);
        context.set_pixels_per_point(scale);
        // egui applies a changed zoom factor before it reads a screen size.
        context
            .run_ui(egui::RawInput::default(), |_| {})
            .textures_delta
            .clear();
        context
    }

    fn paint(
        context: &egui::Context,
        graph: &mut GraphCanvas,
        view: &FunctionView,
        size: Vec2,
        events: Vec<egui::Event>,
        selected: Option<u64>,
    ) -> (egui::FullOutput, Option<GraphAction>) {
        let mut action = None;
        let time = context.input(|input| input.time) + 0.1;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
                time: Some(time),
                events,
                ..Default::default()
            },
            |ui| {
                action = graph.show_selected(ui, view, selected, &BTreeSet::new(), |_, _| {});
            },
        );
        output.textures_delta.clear();
        (output, action)
    }

    fn texts(output: &egui::FullOutput) -> Vec<(String, Pos2)> {
        output
            .shapes
            .iter()
            .filter_map(|shape| match &shape.shape {
                egui::Shape::Text(text) => Some((text.galley.text().to_owned(), text.pos)),
                _ => None,
            })
            .collect()
    }

    fn row_text(output: &egui::FullOutput, address: u64) -> Option<Pos2> {
        let prefix = format!("{address:08x}  ");
        texts(output)
            .into_iter()
            .find_map(|(text, pos)| text.starts_with(&prefix).then_some(pos))
    }

    fn click(pos: Pos2, count: usize) -> Vec<egui::Event> {
        let mut events = vec![egui::Event::PointerMoved(pos)];
        for _ in 0..count {
            for pressed in [true, false] {
                events.push(egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                });
            }
        }
        events
    }

    fn row_count(graph: &GraphCanvas) -> usize {
        graph.layout.nodes.iter().map(|node| node.rows.len()).sum()
    }

    #[test]
    fn full_block_paints_and_selects_rows_after_eight() {
        let view = tall_fixture();
        let entry = &view.blocks[0].instructions;
        for scale in [1.0, 1.25] {
            let context = context(scale);
            let mut graph = GraphCanvas::new(&view);
            let size = vec2(760.0, 600.0);
            assert_eq!(row_count(&graph), MAX_GRAPH_INSTRUCTIONS);
            let block = &graph.layout.nodes[0];
            assert_eq!(
                block.rect.height(),
                HEADER + MAX_GRAPH_INSTRUCTIONS as f32 * ROW_HEIGHT + FOOTER
            );
            paint(&context, &mut graph, &view, size, vec![], None);
            for row in [8, 9, MAX_GRAPH_INSTRUCTIONS / 2, MAX_GRAPH_INSTRUCTIONS - 1] {
                let address = entry[row].address;
                graph.reveal_instruction(address);
                let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
                assert_eq!(context.pixels_per_point(), scale);
                let pos = row_text(&output, address).expect("revealed row is painted");
                assert!(
                    texts(&output)
                        .iter()
                        .all(|(text, _)| !text.contains("more rows"))
                );
                let (_, action) = paint(
                    &context,
                    &mut graph,
                    &view,
                    size,
                    click(pos + vec2(30.0, 2.0), 1),
                    None,
                );
                assert_eq!(action, Some(GraphAction::Select(address)), "row {row}");
            }
            // A late resolved call follows its call-site target; an unresolved
            // one only selects.
            for (row, expected) in [
                (2040, GraphAction::Navigate(0x30_0000)),
                (2041, GraphAction::Select(entry[2041].address)),
            ] {
                graph.reveal_instruction(entry[row].address);
                let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
                let pos = row_text(&output, entry[row].address).unwrap();
                // Idle frames separate this double click from earlier clicks.
                for _ in 0..4 {
                    paint(&context, &mut graph, &view, size, vec![], None);
                }
                let mut actions = Vec::new();
                for _ in 0..2 {
                    let events = click(pos + vec2(30.0, 2.0), 1);
                    actions.extend(paint(&context, &mut graph, &view, size, events, None).1);
                }
                assert_eq!(actions.last(), Some(&expected), "row {row}");
            }
        }
    }

    #[test]
    fn full_height_layout_routes_edges_at_real_ports() {
        let mut view = fixture();
        // Uneven heights, including comment rows, across ranks.
        view.blocks[1].instructions = (0..40)
            .map(|row| row_instruction(view.blocks[1].address + row * 4, row))
            .collect();
        let comments: BTreeMap<_, _> = view.blocks[1]
            .instructions
            .iter()
            .step_by(3)
            .map(|instruction| (instruction.address, "note".to_owned()))
            .collect();
        let layout = Layout::annotated(&view, &comments, &BTreeMap::new());
        let node = |address| {
            layout
                .nodes
                .iter()
                .find(|node| node.address == address)
                .unwrap()
        };
        let tall = node(view.blocks[1].address);
        assert_eq!(tall.rows.len(), 40 + comments.len());
        assert_eq!(
            tall.rect.height(),
            HEADER + tall.rows.len() as f32 * ROW_HEIGHT + FOOTER
        );
        for (index, a) in layout.nodes.iter().enumerate() {
            for b in &layout.nodes[index + 1..] {
                assert!(!a.rect.intersects(b.rect));
            }
        }
        for (edge, routed) in view.edges.iter().zip(&layout.edges) {
            let source = node(edge.source).rect;
            let start = routed.points[0];
            assert_eq!(start.y, source.bottom());
            assert!(source.x_range().contains(start.x));
            if let Some(target) = edge.target {
                let target = node(target).rect;
                let end = *routed.points.last().unwrap();
                assert_eq!(end.y, target.top());
                assert!(target.x_range().contains(end.x));
                // Interior route segments never cross a block.
                for pair in routed.points[1..routed.points.len() - 1].windows(2) {
                    for other in &layout.nodes {
                        assert!(clip_segment(pair[0], pair[1], other.rect.shrink(0.1)).is_none());
                    }
                }
            }
            assert!(
                routed
                    .bounds
                    .contains_rect(Rect::from_points(&routed.points))
            );
            assert!(layout.bounds.contains_rect(routed.bounds));
        }
        // A rank starts below the tallest block of the previous rank.
        let below = node(view.blocks[3].address).rect;
        assert!(below.top() >= tall.rect.bottom() + ROW_GAP - 0.01);
        let mut shuffled = view.clone();
        shuffled.blocks.reverse();
        let again = Layout::annotated(&shuffled, &comments, &BTreeMap::new());
        let rects = |layout: &Layout| {
            layout
                .nodes
                .iter()
                .map(|node| (node.address, node.rect))
                .collect::<Vec<_>>()
        };
        assert_eq!(rects(&layout), rects(&again));
    }

    #[test]
    fn tall_block_reveal_targets_exact_instruction_once() {
        let view = tall_fixture();
        let context = context(1.0);
        let size = vec2(760.0, 600.0);
        let mut graph = GraphCanvas::new(&view);
        graph.needs_initial_view = false;
        graph.fit(size);
        let last = view.blocks[0].instructions.last().unwrap().address;
        graph.reveal_instruction(last);
        let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
        assert!(graph.zoom >= READABLE_ZOOM);
        assert!(graph.reveal.is_none());
        let pos = row_text(&output, last).unwrap();
        assert!((pos.y - size.y * 0.5).abs() < ROW_HEIGHT * graph.zoom);
        // Manual pans and idle frames keep the camera.
        graph.pan += vec2(-30.0, 400.0);
        let camera = (graph.zoom, graph.pan);
        paint(&context, &mut graph, &view, size, vec![], Some(last));
        assert_eq!((graph.zoom, graph.pan), camera);
        // An already visible row leaves the camera alone.
        let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
        let visible = texts(&output)
            .into_iter()
            .find_map(|(text, pos)| {
                let address = u64::from_str_radix(text.get(..8)?, 16).ok()?;
                (pos.y > size.y * 0.5).then_some(address)
            })
            .unwrap();
        graph.reveal_instruction(visible);
        paint(&context, &mut graph, &view, size, vec![], None);
        assert_eq!((graph.zoom, graph.pan), camera);
        // An address absent from the graph is a consumed no-op.
        for absent in [last + 2, 0x40_0000] {
            graph.reveal_instruction(absent);
            paint(&context, &mut graph, &view, size, vec![], None);
            assert!(graph.reveal.is_none());
            assert_eq!((graph.zoom, graph.pan), camera);
        }
        // Entry shows the entry header and first rows, not the block middle.
        graph.reveal = Some(Reveal::Entry);
        let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
        assert!(row_text(&output, view.address).is_some());
        assert!(
            texts(&output)
                .iter()
                .any(|(text, _)| text == "block 100000")
        );
        // The header-only block reveals its header.
        graph.reveal_instruction(0x20_0000);
        let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
        assert!(
            texts(&output)
                .iter()
                .any(|(text, _)| text == "block 200000")
        );
        // Empty graphs have finite fallback bounds and no rows to reveal.
        let empty = FunctionView {
            blocks: vec![],
            edges: vec![],
            calls: vec![],
            ..view.clone()
        };
        let mut graph = GraphCanvas::new(&empty);
        graph.reveal_instruction(view.address);
        graph.reveal = Some(Reveal::Entry);
        paint(&context, &mut graph, &empty, size, vec![], None);
        assert!(graph.zoom.is_finite() && graph.pan.x.is_finite() && graph.pan.y.is_finite());
    }

    #[test]
    fn tall_graph_starts_at_readable_entry_rows() {
        let view = tall_fixture();
        let size = vec2(700.0, 720.0);
        let mut graph = GraphCanvas::new(&view);
        graph.initial_view(size);
        assert!(graph.zoom >= READABLE_ZOOM);
        let viewport = Rect::from_min_size(Pos2::ZERO, size);
        let entry = &graph.layout.nodes[graph.layout.block(view.address).unwrap()];
        let (rows, entry) = (entry.entry_rect().union(entry.row_rect(8)), entry.rect);
        assert!(viewport.contains_rect(screen_rect(&graph, rows)));
        // Fit still shows the true overall bounds.
        graph.fit(size);
        assert!(viewport.contains_rect(screen_rect(&graph, graph.layout.bounds)));
        assert!(viewport.contains_rect(screen_rect(&graph, entry)));
    }

    #[test]
    fn row_culling_bounds_paint_work() {
        let mut view = tall_fixture();
        let comments: BTreeMap<_, _> = view.blocks[0]
            .instructions
            .iter()
            .map(|instruction| (instruction.address, "c".to_owned()))
            .collect();
        view.edges.clear();
        let context = context(1.25);
        let mut graph = GraphCanvas::new(&view);
        graph.set_comments(&view, (1, 1, 0), &comments, BTreeMap::new);
        assert_eq!(row_count(&graph), 2 * MAX_GRAPH_INSTRUCTIONS);
        let size = vec2(600.0, 400.0);
        graph.needs_initial_view = false;
        graph.zoom = 1.0;
        let node = graph.layout.nodes[0].rect;
        // Start mid-row so both the first and last visible rows are partial.
        graph.pan = vec2(10.0, -(node.top() + HEADER + 1000.5 * ROW_HEIGHT));
        let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
        let canvas = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Rect(rect) if rect.fill == theme::GRAPH_BACKGROUND => Some(rect.rect),
                _ => None,
            })
            .unwrap();
        let visible = (canvas.height() / ROW_HEIGHT).ceil() as usize + 1;
        assert!(graph.painted.text_rows <= visible, "{:?}", graph.painted);
        assert!(graph.painted.text_rows >= visible - 2);
        // The first painted row is the partially visible one.
        let partial = &graph.layout.nodes[0].rows[1000];
        let label = &partial.text;
        let pos = texts(&output)
            .into_iter()
            .find_map(|(text, pos)| (&text == label).then_some(pos))
            .unwrap();
        assert!(pos.y < canvas.top());
        // Painted work depends on the viewport, not the block height.
        let mut short = view.clone();
        short.blocks[0].instructions.truncate(600);
        let mut small = GraphCanvas::new(&short);
        small.set_comments(&short, (1, 1, 0), &comments, BTreeMap::new);
        small.needs_initial_view = false;
        small.zoom = 1.0;
        small.pan = graph.pan;
        paint(&context, &mut small, &short, size, vec![], None);
        assert_eq!(small.painted.text_rows, graph.painted.text_rows);
    }

    #[test]
    fn overview_bars_are_bounded_and_text_free() {
        let view = tall_fixture();
        for scale in [1.0, 1.25] {
            let context = context(scale);
            let size = vec2(760.0, 600.0);
            let mut graph = GraphCanvas::new(&view);
            graph.needs_initial_view = false;
            graph.fit(size);
            let selected = view.blocks[0].instructions[1500].address;
            let (output, _) = paint(&context, &mut graph, &view, size, vec![], Some(selected));
            assert!(graph.zoom < ROW_TEXT_ZOOM);
            for (text, _) in texts(&output) {
                assert!(
                    !text.contains("mov") && !text.starts_with("block "),
                    "{text}"
                );
            }
            // At most one mark per two physical pixels, plus the selection.
            let physical = size.y * scale;
            assert!(graph.painted.marks > 0);
            assert!(
                graph.painted.marks as f32 <= physical / MARK_PIXELS + 3.0,
                "{:?}",
                graph.painted
            );
            let accent = output.shapes.iter().any(|shape| {
                matches!(&shape.shape, egui::Shape::Rect(rect)
                    if rect.fill == theme::BLUE && rect.rect.is_finite()
                        && rect.rect.height() * scale >= MARK_PIXELS - 0.01)
            });
            assert!(accent, "selected row stays identifiable");
            for shape in &output.shapes {
                if let egui::Shape::Rect(rect) = &shape.shape {
                    assert!(rect.rect.is_finite());
                }
            }
            // At the minimum zoom very few bins remain.
            graph.zoom = MIN_ZOOM;
            graph.pan = size * 0.5;
            paint(&context, &mut graph, &view, size, vec![], None);
            assert!(graph.painted.marks <= 3, "{:?}", graph.painted);
            // Either side of the text threshold.
            graph.zoom = ROW_TEXT_ZOOM - 0.01;
            graph.pan = vec2(10.0, 10.0);
            paint(&context, &mut graph, &view, size, vec![], None);
            assert_eq!(graph.painted.text_rows, 0);
            assert!(graph.painted.marks > 0);
            graph.zoom = ROW_TEXT_ZOOM;
            let (output, _) = paint(&context, &mut graph, &view, size, vec![], None);
            assert!(graph.painted.text_rows > 0 && graph.painted.marks == 0);
            assert!(row_text(&output, view.address).is_some());
        }
    }

    #[test]
    fn full_graph_hits_comment_and_instruction_addresses() {
        let view = tall_fixture();
        let instructions = &view.blocks[0].instructions;
        let deep = instructions[1900].address;
        let comments = BTreeMap::from([(deep, "deep".to_owned())]);
        let layout = Layout::annotated(&view, &comments, &BTreeMap::new());
        let node = &layout.nodes[0];
        let at = |y: f32| node.rect.min + vec2(40.0, y);
        let row = |index: usize| HEADER + index as f32 * ROW_HEIGHT;
        assert_eq!(node.hit_at(at(HEADER - 0.01), 1.0), node.address);
        assert_eq!(node.hit_at(at(row(0)), 1.0), instructions[0].address);
        // Half-open row intervals.
        assert_eq!(node.hit_at(at(row(1) - 0.01), 1.0), instructions[0].address);
        assert_eq!(node.hit_at(at(row(1)), 1.0), instructions[1].address);
        // The comment row follows its instruction and resolves to its PC;
        // later rows shift by one.
        assert_eq!(node.hit_at(at(row(1900) + 1.0), 1.0), deep);
        assert_eq!(node.hit_at(at(row(1901) + 1.0), 1.0), deep);
        assert_eq!(
            node.hit_at(at(row(1902) + 1.0), 1.0),
            instructions[1901].address
        );
        let last = node.rows.len();
        assert_eq!(
            node.hit_at(at(row(last) - 1.0), 1.0),
            instructions.last().unwrap().address
        );
        assert_eq!(node.hit_at(at(row(last) + 1.0), 1.0), node.address);
        // Overview selects the block.
        assert_eq!(node.hit_at(at(row(1900) + 1.0), 0.3), node.address);
        // Reveal targets the instruction row, never its comment.
        assert_eq!(layout.instruction(deep), Some((0, 1900)));
        assert_eq!(
            layout.instruction(instructions[1901].address),
            Some((0, 1902))
        );
    }

    #[test]
    fn full_graph_fractional_scale_resize_drag() {
        let view = tall_fixture();
        for scale in [1.0, 1.25] {
            let context = context(scale);
            let mut graph = GraphCanvas::new(&view);
            let layout = Arc::as_ptr(&graph.layout);
            let mut size = vec2(700.0, 500.0);
            paint(&context, &mut graph, &view, size, vec![], None);
            assert_eq!(context.pixels_per_point(), scale);
            let start = pos2(300.0, 300.0);
            let press = vec![
                egui::Event::PointerMoved(start),
                egui::Event::PointerButton {
                    pos: start,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ];
            paint(&context, &mut graph, &view, size, press, None);
            let mut camera = graph.pan;
            for step in 1..=6 {
                // Resize while dragging: each delta applies exactly once.
                size += vec2(-25.0, 15.0);
                let to = start + vec2(0.0, -40.0 * step as f32);
                paint(
                    &context,
                    &mut graph,
                    &view,
                    size,
                    vec![egui::Event::PointerMoved(to)],
                    None,
                );
                if step > 1 {
                    assert!((graph.pan - camera - vec2(0.0, -40.0)).length() < 0.01);
                }
                camera = graph.pan;
            }
            let release = vec![egui::Event::PointerButton {
                pos: start + vec2(0.0, -240.0),
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }];
            paint(&context, &mut graph, &view, size, release, None);
            // Idle, resize and selection frames neither relayout nor move.
            let camera = (graph.zoom, graph.pan);
            for (size, selected) in [(size, None), (size + vec2(80.0, 40.0), Some(view.address))] {
                paint(&context, &mut graph, &view, size, vec![], selected);
                assert_eq!((graph.zoom, graph.pan), camera);
            }
            assert_eq!(Arc::as_ptr(&graph.layout), layout);
            // Zoom extremes stay finite and preserve the anchor.
            for factor in [1e-9, 1e9] {
                let anchor = vec2(120.0, 80.0);
                let before = (anchor - graph.pan) / graph.zoom;
                graph.change_zoom(factor, anchor);
                assert!((MIN_ZOOM..=MAX_ZOOM).contains(&graph.zoom));
                assert!(graph.pan.x.is_finite() && graph.pan.y.is_finite());
                let after = (anchor - graph.pan) / graph.zoom;
                assert!((after - before).length() <= before.length() * 1e-4 + 0.01);
            }
            graph.change_zoom(f32::NAN, Vec2::ZERO);
            graph.change_zoom(0.0, Vec2::ZERO);
            assert!(graph.zoom.is_finite());
        }
    }

    #[test]
    fn distributed_budget_lays_out_every_row() {
        let view = distributed_fixture();
        let layout = Layout::new(&view);
        assert_eq!(
            layout.nodes.iter().map(|n| n.rows.len()).sum::<usize>(),
            MAX_GRAPH_INSTRUCTIONS
        );
        assert_eq!(layout.instructions.len(), MAX_GRAPH_INSTRUCTIONS);
        for block in &view.blocks {
            let (node, _) = layout.instruction(block.address).unwrap();
            assert_eq!(layout.nodes[node].rows.len(), block.instructions.len());
            let last = block.instructions.last().unwrap().address;
            assert_eq!(
                layout.instruction(last),
                Some((node, block.instructions.len() - 1))
            );
        }
        let bytes = layout.retained_bytes().unwrap();
        assert!(bytes > MAX_GRAPH_INSTRUCTIONS * (size_of::<GraphRow>() + 20));
        // Defensive: an unvalidated view over the aggregate budget is laid out
        // to the budget and reported, never presented as complete.
        let mut over = view;
        let extra = row_instruction(over.blocks[0].address + 0x80, 99);
        over.blocks[0].instructions.push(extra);
        let layout = Layout::new(&over);
        assert_eq!(
            layout.nodes.iter().map(|n| n.rows.len()).sum::<usize>(),
            MAX_GRAPH_INSTRUCTIONS
        );
        assert!(graph_notes(&over).any(|note| note.contains("2048 instructions")));
    }
    #[test]
    fn graph_call_names_keep_body_font_and_exact_row_selection() {
        let view = tall_fixture();
        let pc = view.calls[0].address;
        let context = context(1.25);
        let mut graph = GraphCanvas::new(&view);
        graph.set_comments(&view, (1, 1, 1), &BTreeMap::new(), || {
            BTreeMap::from([(pc, "callee_name".into())])
        });
        graph.reveal_instruction(pc);
        let (output, _) = paint(
            &context,
            &mut graph,
            &view,
            vec2(760.0, 600.0),
            vec![],
            Some(pc),
        );
        let text = output
            .shapes
            .iter()
            .find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text().contains("callee_name") => Some(text),
                _ => None,
            })
            .expect("late callee is painted");
        let section = text.galley.job.sections.last().unwrap();
        assert_eq!(
            section.format.font_id.family,
            egui::FontFamily::Proportional
        );
        assert_eq!(section.format.color, theme::SYNTAX_FUNCTION);
        let pos = text.pos + vec2(30.0, 2.0);
        let (_, action) = paint(
            &context,
            &mut graph,
            &view,
            vec2(760.0, 600.0),
            click(pos, 1),
            None,
        );
        assert_eq!(action, Some(GraphAction::Select(pc)));
    }
}
