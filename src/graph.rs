//! A bounded native instruction CFG. Construct a new canvas when analysis changes;
//! selection changes alone intentionally retain the current camera.

use crate::model::{EdgeKind, FunctionView};
use crate::theme;
use eframe::egui::{
    self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Vec2, pos2, vec2,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const WIDTH: f32 = 420.0;
const HEADER: f32 = 32.0;
const ROW: f32 = 20.0;
const PREVIEW: usize = 8;
const MAX_BLOCKS: usize = 128;
const MAX_EDGES: usize = 4096;
const MIN_ZOOM: f32 = 0.0001;
const READABLE_ZOOM: f32 = 0.85;
const ARROWHEAD_ZOOM: f32 = 0.35;
const HEADER_TEXT_ZOOM: f32 = 0.65;
const ROW_TEXT_ZOOM: f32 = 0.75;
const ROW_GAP: f32 = 100.0;

struct Node {
    address: u64,
    rect: Rect,
    instruction_addresses: BTreeSet<u64>,
    rows: Vec<(u64, String)>,
    remaining: usize,
}

struct RoutedEdge {
    points: Vec<Pos2>,
    kind: EdgeKind,
    label: String,
    label_position: Pos2,
    unresolved: bool,
}

struct Layout {
    nodes: Vec<Node>,
    edges: Vec<RoutedEdge>,
    bounds: Rect,
}

pub struct GraphCanvas {
    function: u64,
    layout: Layout,
    zoom: f32,
    pan: Vec2,
    needs_fit: bool,
    needs_initial_view: bool,
    reveal: Option<u64>,
    comment_key: Option<(u64, u64)>,
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
        Self {
            function: view.address,
            layout: Layout::new(view),
            zoom: 1.0,
            pan: Vec2::ZERO,
            needs_fit: false,
            needs_initial_view: true,
            reveal: None,
            comment_key: None,
        }
    }

    pub fn reveal_instruction(&mut self, address: u64) {
        self.reveal = Some(address);
    }

    /// Refresh only derived geometry, retaining the user's camera and pending
    /// reveal. Previews are bounded and cached by the app's annotation revision.
    pub fn set_comments(
        &mut self,
        view: &FunctionView,
        key: (u64, u64),
        comments: &BTreeMap<u64, String>,
    ) {
        if self.function != view.address {
            *self = Self::new(view);
        }
        if self.comment_key != Some(key) {
            let _layout = crate::performance::span("gui_graph_comment_layout");
            self.layout = Layout::with_comments(view, comments);
            self.comment_key = Some(key);
        }
    }

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        view: &FunctionView,
        selected: Option<u64>,
    ) -> Option<GraphAction> {
        self.show_selected(ui, view, selected, &BTreeSet::new())
    }

    pub fn show_selected(
        &mut self,
        ui: &mut egui::Ui,
        view: &FunctionView,
        selected: Option<u64>,
        related: &BTreeSet<u64>,
    ) -> Option<GraphAction> {
        if self.function != view.address {
            *self = Self::new(view);
        }
        let mut zoom_change = 1.0;
        ui.horizontal(|ui| {
            if ui.button("Fit").clicked() {
                self.needs_fit = true;
            }
            if ui.button("Entry").clicked() {
                self.reveal = Some(self.function);
            }
            if ui.button("−").clicked() {
                zoom_change /= 1.2;
            }
            if ui.button("+").clicked() {
                zoom_change *= 1.2;
            }
            ui.label(format!("{:.0}%", self.zoom * 100.0));
            ui.small("Drag to pan · Ctrl+wheel to zoom · double-click a call to follow");
        });
        ui.horizontal_wrapped(|ui| {
            for (kind, label) in [
                (EdgeKind::True, "T: true"),
                (EdgeKind::False, "F: false"),
                (EdgeKind::Branch, "B: branch"),
                (EdgeKind::Unknown, "?: unresolved"),
            ] {
                ui.colored_label(edge_color(kind), label);
            }
            if view.blocks.len() > MAX_BLOCKS {
                ui.label("Graph preview limited to 128 blocks");
            }
        });
        let size = ui.available_size().max(vec2(1.0, 1.0));
        let (canvas, response) = ui.allocate_exact_size(size, Sense::click_and_drag());
        if self.needs_initial_view {
            self.initial_view(canvas.size());
        } else if self.needs_fit {
            self.fit(canvas.size());
        }
        self.change_zoom(zoom_change, canvas.size() * 0.5);
        if let Some(address) = self.reveal.take() {
            self.reveal_at(address, canvas.size());
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
        let painter = ui.painter_at(canvas);
        painter.rect_filled(canvas, 0.0, theme::GRAPH_BACKGROUND);
        if self.layout.nodes.is_empty() {
            painter.text(
                canvas.center(),
                Align2::CENTER_CENTER,
                "No decoded basic blocks",
                FontId::proportional(16.0),
                theme::MUTED,
            );
            return None;
        }
        let screen = |point: Pos2| canvas.min + self.pan + point.to_vec2() * self.zoom;
        for edge in &self.layout.edges {
            let points: Vec<_> = edge.points.iter().copied().map(screen).collect();
            if !Rect::from_points(&points).expand(24.0).intersects(canvas) {
                continue;
            }
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
            if self.zoom >= ARROWHEAD_ZOOM
                && let [.., previous, tip] = points.as_slice()
                && canvas.expand(10.0).contains(*tip)
            {
                let direction = (*tip - *previous).normalized();
                let side = vec2(-direction.y, direction.x);
                painter.line_segment([*tip, *tip - direction * 9.0 + side * 4.0], stroke);
                painter.line_segment([*tip, *tip - direction * 9.0 - side * 4.0], stroke);
            }
            if self.zoom >= READABLE_ZOOM {
                let at = screen(edge.label_position);
                if !canvas.expand(24.0).contains(at) {
                    continue;
                }
                // Labels scale with their routes, and disappear in overview.
                let galley = painter.layout_no_wrap(
                    edge.label.clone(),
                    FontId::monospace(11.0 * self.zoom),
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
        let mut clicked = None;
        for node in &self.layout.nodes {
            let rect = Rect::from_min_max(screen(node.rect.min), screen(node.rect.max));
            if !rect.intersects(canvas) {
                continue;
            }
            let is_selected = selected == Some(node.address)
                || selected.is_some_and(|address| node.instruction_addresses.contains(&address))
                || node
                    .instruction_addresses
                    .iter()
                    .any(|a| related.contains(a));
            let radius = theme::scaled_radius(self.zoom);
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
            let header =
                Rect::from_min_max(rect.min, pos2(rect.max.x, rect.min.y + HEADER * self.zoom));
            let is_return = view
                .blocks
                .iter()
                .find(|block| block.address == node.address)
                .and_then(|block| block.instructions.last())
                .is_some_and(|instruction| instruction.mnemonic.starts_with("RET"));
            let header_color = if is_selected {
                theme::NODE_SELECTED
            } else if node.address == view.address {
                theme::NODE_ENTRY
            } else if is_return {
                theme::NODE_RETURN
            } else {
                theme::HEADER
            };
            let top = radius.saturating_sub(1);
            painter.rect_filled(
                header.shrink(self.zoom.min(1.0)),
                egui::CornerRadius {
                    nw: top,
                    ne: top,
                    sw: 0,
                    se: 0,
                },
                header_color,
            );
            let node_painter = painter.with_clip_rect(rect.intersect(canvas));
            if self.zoom >= HEADER_TEXT_ZOOM {
                node_painter.text(
                    header.left_center() + vec2(9.0 * self.zoom, 0.0),
                    Align2::LEFT_CENTER,
                    format!("block {:x}", node.address),
                    FontId::monospace(14.0 * self.zoom),
                    theme::TEXT,
                );
            }
            let first_row = selected
                .and_then(|address| node.rows.iter().position(|(a, _)| *a == address))
                .map_or(0, |index| {
                    index
                        .saturating_sub(PREVIEW / 2)
                        .min(node.rows.len().saturating_sub(PREVIEW))
                });
            if self.zoom >= ROW_TEXT_ZOOM {
                for (index, (address, text)) in
                    node.rows.iter().skip(first_row).take(PREVIEW).enumerate()
                {
                    let row = Rect::from_min_size(
                        pos2(
                            rect.min.x,
                            rect.min.y + (HEADER + index as f32 * ROW) * self.zoom,
                        ),
                        vec2(rect.width(), ROW * self.zoom),
                    );
                    if selected == Some(*address) || related.contains(address) {
                        painter.rect_filled(row.shrink2(vec2(2.0, 0.0)), 0.0, theme::CURRENT_LINE);
                    }
                    node_painter.text(
                        row.left_center() + vec2(8.0 * self.zoom, 0.0),
                        Align2::LEFT_CENTER,
                        text,
                        FontId::monospace(12.0 * self.zoom),
                        if text.starts_with("; ") {
                            theme::SYNTAX_COMMENT
                        } else {
                            theme::TEXT
                        },
                    );
                }
                if node.remaining > 0 {
                    node_painter.text(
                        screen(pos2(node.rect.left() + 8.0, node.rect.bottom() - 11.0)),
                        Align2::LEFT_CENTER,
                        format!("… {} more rows", node.remaining),
                        FontId::monospace(11.0 * self.zoom),
                        theme::MUTED,
                    );
                }
            }
            if (response.clicked() || response.double_clicked())
                && let Some(pointer) = response.interact_pointer_pos()
                && rect.contains(pointer)
            {
                let world = ((pointer - canvas.min) - self.pan) / self.zoom;
                let address = node.hit_at(pos2(world.x, world.y), self.zoom, first_row);
                clicked = Some(instruction_action(view, address, response.double_clicked()));
            }
        }
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
            if let Some(entry) = self
                .layout
                .nodes
                .iter()
                .find(|n| n.address == self.function)
            {
                self.pan = vec2(
                    size.x * 0.5 - entry.rect.center().x * self.zoom,
                    24.0 - entry.rect.top() * self.zoom,
                );
            }
        }
    }

    fn reveal_at(&mut self, address: u64, size: Vec2) {
        let Some(node) =
            self.layout.nodes.iter().find(|node| {
                node.address == address || node.instruction_addresses.contains(&address)
            })
        else {
            return;
        };
        self.zoom = self.zoom.max(READABLE_ZOOM);
        let visible = Rect::from_min_max(
            Pos2::ZERO + self.pan + node.rect.min.to_vec2() * self.zoom,
            Pos2::ZERO + self.pan + node.rect.max.to_vec2() * self.zoom,
        );
        if !Rect::from_min_size(Pos2::ZERO, size).contains_rect(visible) {
            self.pan += size * 0.5 - visible.center().to_vec2();
        }
    }

    fn change_zoom(&mut self, factor: f32, anchor: Vec2) {
        if !factor.is_finite() || factor <= 0.0 {
            return;
        }
        let next = (self.zoom * factor).clamp(MIN_ZOOM, 2.5);
        self.pan = anchor - (anchor - self.pan) * (next / self.zoom);
        self.zoom = next;
    }
}

impl Node {
    #[cfg(test)]
    fn hit(&self, point: Pos2, zoom: f32) -> u64 {
        self.hit_at(point, zoom, 0)
    }
    fn hit_at(&self, point: Pos2, zoom: f32, first_row: usize) -> u64 {
        let row = (point.y - self.rect.min.y - HEADER) / ROW;
        if zoom >= ROW_TEXT_ZOOM && row >= 0.0 && row < PREVIEW as f32 {
            self.rows
                .get(first_row + row.floor() as usize)
                .map_or(self.address, |(address, _)| *address)
        } else {
            self.address
        }
    }
}

impl Layout {
    fn new(view: &FunctionView) -> Self {
        Self::with_comments(view, &BTreeMap::new())
    }

    fn with_comments(view: &FunctionView, comments: &BTreeMap<u64, String>) -> Self {
        let mut blocks: BTreeMap<_, _> = BTreeMap::new();
        for block in view.blocks.iter().take(MAX_BLOCKS) {
            blocks.entry(block.address).or_insert(block);
        }
        let mut successors: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for edge in view.edges.iter().take(MAX_EDGES) {
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
        let mut nodes = Vec::new();
        let mut y = 0.0;
        for addresses in rows.values() {
            let mut row_height: f32 = 0.0;
            let row_width = addresses.len() as f32 * (WIDTH + 60.0) - 60.0;
            for (column, address) in addresses.iter().enumerate() {
                let block = blocks[address];
                let display_rows = block.instructions.len()
                    + block
                        .instructions
                        .iter()
                        .filter(|i| comments.contains_key(&i.address))
                        .count();
                let remaining = display_rows.saturating_sub(PREVIEW);
                let height = HEADER
                    + display_rows.min(PREVIEW) as f32 * ROW
                    + if remaining > 0 { 23.0 } else { 8.0 };
                row_height = row_height.max(height);
                let rect = Rect::from_min_size(
                    pos2(
                        (total_width - row_width) / 2.0 + column as f32 * (WIDTH + 60.0),
                        y,
                    ),
                    vec2(WIDTH, height),
                );
                nodes.push(Node {
                    address: *address,
                    rect,
                    instruction_addresses: block
                        .instructions
                        .iter()
                        .map(|instruction| instruction.address)
                        .collect(),
                    rows: block
                        .instructions
                        .iter()
                        .flat_map(|instruction| {
                            let mut rows = vec![(
                                instruction.address,
                                crop(
                                    &format!(
                                        "{:08x}  {:<8} {}",
                                        instruction.address,
                                        instruction.mnemonic,
                                        instruction.operands
                                    ),
                                    53,
                                ),
                            )];
                            if let Some(comment) = comments.get(&instruction.address) {
                                rows.push((
                                    instruction.address,
                                    format!(
                                        "; {}",
                                        crate::annotation_display::preview(comment, 53)
                                    ),
                                ));
                            }
                            rows
                        })
                        .collect(),
                    remaining,
                });
            }
            y += row_height + ROW_GAP;
        }
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
        for (index, edge) in view.edges.iter().take(MAX_EDGES).enumerate() {
            let Some(source) = positions.get(&edge.source) else {
                continue;
            };
            let (label, color_kind) = match edge.kind {
                EdgeKind::True => ("T", EdgeKind::True),
                EdgeKind::False => ("F", EdgeKind::False),
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
            bounds = bounds
                .union(Rect::from_points(&points))
                .union(Rect::from_min_size(
                    label_position,
                    vec2(if unresolved { 190.0 } else { 40.0 }, 18.0),
                ));
            edges.push(RoutedEdge {
                points,
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
        Self {
            nodes,
            edges,
            bounds,
        }
    }
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
                },
                Edge {
                    source: 0x401146,
                    target: Some(0x40116b),
                    kind: EdgeKind::False,
                },
                Edge {
                    source: 0x40115a,
                    target: Some(0x40117d),
                    kind: EdgeKind::Branch,
                },
                Edge {
                    source: 0x40116b,
                    target: Some(0x40117d),
                    kind: EdgeKind::Branch,
                },
                Edge {
                    source: 0x40117d,
                    target: Some(0x401146),
                    kind: EdgeKind::True,
                },
                Edge {
                    source: 0x401190,
                    target: None,
                    kind: EdgeKind::Unknown,
                },
            ],
            calls: vec![],
            warnings: vec![],
        }
    }

    fn large_fixture() -> FunctionView {
        let mut view = fixture();
        view.address = 0x400000;
        view.blocks = (0..MAX_BLOCKS)
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
            })
            .collect();
        // Overlapping loop intervals must have distinct outer lanes.
        for source in [125, 126, 127] {
            view.edges.push(Edge {
                source: view.blocks[source].address,
                target: Some(view.address),
                kind: EdgeKind::True,
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
            node.hit(node.rect.min + vec2(20.0, 10.0), 1.0),
            node.address
        );
        assert_eq!(
            node.hit(node.rect.min + vec2(20.0, HEADER + ROW + 5.0), 1.0),
            node.address + 3
        );
        assert_eq!(
            node.hit(node.rect.min + vec2(20.0, HEADER + ROW + 5.0), 0.3),
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
            },
            CallSite {
                address: 0x40115d,
                target: None,
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
        graph.set_comments(&view, (1, 1), &comments);
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
            node.rows[2],
            (address, "; branch comment */ literal".into())
        );
        assert_eq!(
            node.hit_at(node.rect.min + vec2(10.0, HEADER + 2.5 * ROW), 1.0, 0),
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
        graph.set_comments(&view, (1, 2), &comments);
        assert_eq!((graph.zoom, graph.pan), camera);
        assert!(
            graph
                .layout
                .nodes
                .iter()
                .flat_map(|n| &n.rows)
                .any(|(pc, text)| *pc == address && text == "; edited")
        );
        comments.clear();
        graph.set_comments(&view, (1, 3), &comments);
        assert!(
            !graph
                .layout
                .nodes
                .iter()
                .flat_map(|n| &n.rows)
                .any(|(_, text)| text.starts_with("; "))
        );
    }
}
