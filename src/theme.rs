//! Carbon: a dense near-black desktop with Ghidra's dragon orange as accent.
//!
//! The pane layout follows Ghidra's docking providers; titles use editor-style
//! tabs and the syntax colors follow One Dark. Controls remain native egui
//! widgets.
use eframe::egui::{
    self, Color32, CornerRadius, FontId, Frame, Margin, RichText, Stroke, TextStyle, Ui,
};

pub const VIEW: Color32 = Color32::from_rgb(28, 29, 32);
pub const CHROME: Color32 = Color32::from_rgb(21, 22, 24);
pub const HEADER: Color32 = Color32::from_rgb(38, 40, 44);
pub const BORDER: Color32 = Color32::from_rgb(46, 48, 53);
pub const TEXT: Color32 = Color32::from_rgb(220, 223, 228);
pub const MUTED: Color32 = Color32::from_rgb(128, 134, 145);
pub const BLUE: Color32 = Color32::from_rgb(97, 175, 239);
pub const ACCENT: Color32 = Color32::from_rgb(240, 136, 62);
pub const CURRENT_LINE: Color32 = Color32::from_rgb(62, 68, 81);
pub const SELECTION: Color32 = Color32::from_rgb(70, 48, 30);
pub const WARNING: Color32 = Color32::from_rgb(229, 192, 123);
pub const ERROR: Color32 = Color32::from_rgb(224, 108, 117);
pub const SYNTAX_COMMENT: Color32 = Color32::from_rgb(127, 132, 142);
pub const SYNTAX_CONSTANT: Color32 = Color32::from_rgb(209, 154, 102);
pub const SYNTAX_VARIABLE: Color32 = Color32::from_rgb(224, 108, 117);
pub const SYNTAX_KEYWORD: Color32 = Color32::from_rgb(198, 120, 221);
pub const SYNTAX_TYPE: Color32 = Color32::from_rgb(229, 192, 123);
pub const SYNTAX_FUNCTION: Color32 = Color32::from_rgb(97, 175, 239);
pub const GRAPH_BACKGROUND: Color32 = CHROME;
pub const EDGE_TRUE: Color32 = Color32::from_rgb(152, 195, 121);
pub const NODE_SELECTED: Color32 = Color32::from_rgb(92, 58, 30);
pub const NODE_ENTRY: Color32 = Color32::from_rgb(34, 68, 46);
pub const NODE_RETURN: Color32 = Color32::from_rgb(90, 36, 40);
pub const NODE_RADIUS: u8 = 3;
/// Instructions or tokens linked to the selection, below the selection itself.
pub const RELATED: Color32 = Color32::from_rgb(52, 42, 34);
/// Height of one dense listing or table row; virtualized lists rely on it.
pub const ROW_HEIGHT: f32 = 20.0;
/// Bytes shown in the Listing's byte column before eliding the remainder.
pub const LISTING_BYTES: usize = 8;
const ADDRESS: Color32 = MUTED;
const BYTES: Color32 = Color32::from_rgb(92, 99, 112);
const MNEMONIC: Color32 = SYNTAX_KEYWORD;
const HOVER: Color32 = Color32::from_rgb(44, 46, 51);
const INPUT: Color32 = Color32::from_rgb(18, 19, 21);

pub fn install(context: &egui::Context) {
    context.set_theme(egui::Theme::Dark);
    // The proportional font lacks arrows such as → and ↶; fall back to the
    // bundled monospace font instead of drawing missing-glyph boxes.
    let mut fonts = egui::FontDefinitions::default();
    if let Some(monospace) = fonts
        .families
        .get(&egui::FontFamily::Monospace)
        .and_then(|family| family.first())
        .cloned()
    {
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push(monospace);
    }
    context.set_fonts(fonts);
    let mut style = egui::Style::default();
    let visuals = &mut style.visuals;
    *visuals = egui::Visuals::dark();
    visuals.override_text_color = Some(TEXT);
    visuals.weak_text_color = Some(MUTED);
    visuals.panel_fill = CHROME;
    visuals.window_fill = VIEW;
    visuals.extreme_bg_color = INPUT;
    visuals.text_edit_bg_color = Some(INPUT);
    visuals.faint_bg_color = HOVER;
    visuals.selection.bg_fill = SELECTION;
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);
    visuals.hyperlink_color = BLUE;
    visuals.error_fg_color = ERROR;
    visuals.warn_fg_color = WARNING;
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.menu_corner_radius = CornerRadius::same(8);
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.popup_shadow = egui::Shadow {
        offset: [0, 6],
        blur: 18,
        spread: 0,
        color: Color32::from_black_alpha(110),
    };
    visuals.window_shadow = visuals.popup_shadow;
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::same(3);
        widget.expansion = 0.0;
        widget.fg_stroke.color = TEXT;
        widget.bg_stroke = Stroke::new(1.0, BORDER);
    }
    // Soft filled controls without outlines; pressing keeps the accent.
    visuals.widgets.inactive.bg_fill = HOVER;
    visuals.widgets.inactive.weak_bg_fill = HOVER;
    visuals.widgets.inactive.bg_stroke = Stroke::NONE;
    visuals.widgets.hovered.bg_fill = HOVER.gamma_multiply(1.35);
    visuals.widgets.hovered.weak_bg_fill = visuals.widgets.hovered.bg_fill;
    visuals.widgets.hovered.bg_stroke = Stroke::NONE;
    visuals.widgets.active.bg_fill = SELECTION;
    visuals.widgets.active.weak_bg_fill = SELECTION;
    visuals.widgets.active.bg_stroke = Stroke::new(1.5, ACCENT);
    visuals.widgets.open.weak_bg_fill = HOVER;
    visuals.widgets.open.bg_stroke = Stroke::NONE;
    // Desktop-style scroll bars stay visible in a fixed gutter at the edge of
    // each view instead of floating over, and tracking, the visible rows.
    style.spacing.scroll = egui::style::ScrollStyle {
        bar_width: 8.0,
        bar_inner_margin: 2.0,
        dormant_background_opacity: 0.5,
        dormant_handle_opacity: 0.7,
        ..egui::style::ScrollStyle::solid()
    };
    style.spacing.item_spacing = egui::vec2(5.0, 3.0);
    style.spacing.button_padding = egui::vec2(6.0, 2.0);
    style.spacing.interact_size.y = 20.0;
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(13.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(13.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(13.0));
    context.set_style_of(egui::Theme::Dark, style);
}

/// Frame for a top-level analysis pane.
pub fn view_frame() -> Frame {
    Frame::NONE.fill(VIEW).inner_margin(Margin::symmetric(8, 6))
}

/// Frame for a pane nested inside another pane's frame.
pub fn inner_frame() -> Frame {
    Frame::NONE.fill(VIEW).inner_margin(Margin {
        left: 0,
        right: 0,
        top: 0,
        bottom: 6,
    })
}

pub fn toolbar_frame(style: &egui::Style) -> Frame {
    Frame::side_top_panel(style).inner_margin(Margin::symmetric(8, 3))
}

pub fn status_frame(style: &egui::Style) -> Frame {
    Frame::side_top_panel(style).inner_margin(Margin::symmetric(8, 3))
}

/// A ratio of admitted function attempts, or activity when the work is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarProgress {
    Activity,
    KnownFunctions { processed: usize, total: usize },
}

/// The parent uses a right-to-left layout, fixing both modes to the same track.
pub fn analysis_activity(
    ui: &mut Ui,
    label: &str,
    elapsed: std::time::Duration,
    progress: BarProgress,
) {
    let (track, response) = ui.allocate_exact_size(egui::vec2(88.0, 6.0), egui::Sense::hover());
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::ProgressIndicator, ui.is_enabled(), label)
    });
    if ui.is_rect_visible(track) {
        ui.painter()
            .rect_filled(track, 3, ui.visuals().extreme_bg_color);
        let segment = match progress {
            BarProgress::KnownFunctions { processed, total } if total != 0 => {
                let fraction = processed.min(total) as f32 / total as f32;
                egui::Rect::from_min_size(
                    track.min,
                    egui::vec2(track.width() * fraction, track.height()),
                )
            }
            _ => {
                let width = track.width() * 0.28;
                let phase = (elapsed.as_secs_f32() * std::f32::consts::PI).sin() * 0.5 + 0.5;
                egui::Rect::from_min_size(
                    track.min + egui::vec2((track.width() - width) * phase, 0.0),
                    egui::vec2(width, track.height()),
                )
            }
        };
        if segment.width() > 0.0 {
            ui.painter()
                .rect_filled(segment, 3, ui.visuals().selection.stroke.color);
        }
        // Elapsed wall time keeps updating in both modes, including waits.
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(66));
    }
    ui.add(egui::Label::new(RichText::new(label).small()).truncate());
}

/// A compact warning menu with a font-independent triangle, like the history icons.
pub fn warning_menu<R>(
    ui: &mut Ui,
    count: usize,
    contents: impl FnOnce(&mut Ui) -> R,
) -> egui::InnerResponse<Option<R>> {
    // Reserve the icon's space in the button label.
    let menu = ui.menu_button(
        RichText::new(format!("    {count}")).color(WARNING),
        contents,
    );
    menu.response.widget_info(|| {
        egui::WidgetInfo::labeled(
            egui::Role::Button,
            ui.is_enabled(),
            format!("{count} warnings"),
        )
    });
    let center = egui::pos2(
        menu.response.rect.left() + ui.spacing().button_padding.x + 5.0,
        menu.response.rect.center().y,
    );
    let painter = ui.painter();
    painter.add(egui::Shape::closed_line(
        vec![
            center + egui::vec2(0.0, -6.0),
            center + egui::vec2(6.0, 5.0),
            center + egui::vec2(-6.0, 5.0),
        ],
        Stroke::new(1.0, WARNING),
    ));
    painter.line_segment(
        [
            center + egui::vec2(0.0, -2.0),
            center + egui::vec2(0.0, 1.0),
        ],
        Stroke::new(1.2, WARNING),
    );
    painter.circle_filled(center + egui::vec2(0.0, 3.0), 0.7, WARNING);
    menu
}

/// The shared project logo, kept within the existing menu row.
pub fn brand_mark(ui: &mut Ui) -> egui::Response {
    crate::brand::menu_mark(ui)
}

/// A toolbar history button drawn without depending on an arrow font glyph.
pub fn history_button(ui: &mut Ui, forward: bool, enabled: bool) -> egui::Response {
    let label = if forward { "Forward" } else { "Back" };
    let tooltip = if forward {
        "Forward (Alt+Right)"
    } else {
        "Back (Alt+Left)"
    };
    let response = ui.add_enabled(
        enabled,
        egui::Button::new("")
            .min_size(egui::vec2(26.0, 22.0))
            .frame_when_inactive(false),
    );
    response
        .widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, response.enabled(), label));
    if ui.is_rect_visible(response.rect) {
        let center = response.rect.center();
        let direction = if forward { 1.0 } else { -1.0 };
        let tip = center + egui::vec2(5.0 * direction, 0.0);
        let tail = center - egui::vec2(5.0 * direction, 0.0);
        let color = if response.enabled() {
            ui.style().interact(&response).fg_stroke.color
        } else {
            MUTED.gamma_multiply(0.45)
        };
        let stroke = Stroke::new(1.8, color);
        let painter = ui.painter();
        painter.line_segment([tail, tip], stroke);
        painter.line_segment([tip - egui::vec2(4.0 * direction, 4.0), tip], stroke);
        painter.line_segment([tip - egui::vec2(4.0 * direction, -4.0), tip], stroke);
    }
    response
        .on_hover_text(tooltip)
        .on_disabled_hover_text(tooltip)
}

/// An editor-style tab on a recessed strip, with trailing actions. `active`
/// marks the focused provider with an accent rule.
pub fn dock_header(ui: &mut Ui, title: &str, active: bool, actions: impl FnOnce(&mut Ui)) {
    let mut current = active;
    dock_tabs(ui, &mut current, &[(active, title)], actions);
}

/// A dock title strip whose entries are editor-style tabs; the selected tab
/// joins the pane below it. Returns whether the selection changed.
pub fn dock_tabs<T: PartialEq + Copy>(
    ui: &mut Ui,
    current: &mut T,
    tabs: &[(T, &str)],
    actions: impl FnOnce(&mut Ui),
) -> bool {
    const HEIGHT: f32 = 26.0;
    let mut changed = false;
    let (strip, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), HEIGHT),
        egui::Sense::hover(),
    );
    let painter = ui.painter().with_clip_rect(strip.intersect(ui.clip_rect()));
    painter.rect_filled(strip, 0, CHROME);
    painter.hline(
        strip.x_range(),
        strip.bottom() - 0.5,
        Stroke::new(1.0, BORDER),
    );
    // Lay out the actual trailing widgets first, using their own text styles.
    // Their measured bounds reserve space before any tab paint or hit regions.
    let actions_rect = strip.shrink2(egui::vec2(4.0, 0.0));
    let mut actions_ui = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("dock-actions")
            .max_rect(actions_rect)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    actions_ui.set_clip_rect(actions_rect.intersect(ui.clip_rect()));
    actions(&mut actions_ui);
    let actions_width = actions_ui.min_rect().width();
    let tabs_right = if actions_width > 0.0 {
        actions_rect.right() - actions_width - 8.0
    } else {
        strip.right()
    };
    let tabs_rect = egui::Rect::from_min_max(
        strip.min,
        egui::pos2(tabs_right.max(strip.left()), strip.bottom()),
    );
    let painter = painter.with_clip_rect(tabs_rect.intersect(ui.clip_rect()));
    let font = FontId::proportional(13.0);
    let tab_width: f32 = tabs
        .iter()
        .map(|(_, label)| {
            painter
                .layout_no_wrap((*label).to_owned(), font.clone(), TEXT)
                .size()
                .x
                + 23.0
        })
        .sum();
    if tab_width > tabs_rect.width() {
        let selected = tabs
            .iter()
            .find(|(value, _)| value == current)
            .unwrap_or(&tabs[0]);
        let label = match selected.1 {
            "Symbol Tree" => "Symbols",
            "Program Trees" => "Program",
            name => name,
        };
        let mut tabs_ui = ui.new_child(
            egui::UiBuilder::new()
                .id_salt("dock-overflow")
                .max_rect(tabs_rect)
                .layout(egui::Layout::left_to_right(egui::Align::Center)),
        );
        tabs_ui.set_clip_rect(tabs_rect.intersect(ui.clip_rect()));
        tabs_ui.menu_button(RichText::new(label).color(TEXT), |ui| {
            for (value, label) in tabs {
                if ui.selectable_label(*current == *value, *label).clicked() {
                    changed = *current != *value;
                    *current = *value;
                    ui.close();
                }
            }
        });
        ui.add_space(2.0);
        return changed;
    }
    let mut x = strip.left();
    for (index, (value, label)) in tabs.iter().enumerate() {
        let galley = painter.layout_no_wrap((*label).to_owned(), font.clone(), TEXT);
        let tab = egui::Rect::from_min_size(
            egui::pos2(x, strip.top() + 3.0),
            egui::vec2(galley.size().x + 22.0, HEIGHT - 3.0),
        );
        x = tab.right() + 1.0;
        let response = ui
            .interact(
                tab,
                ui.scope_id().with(("dock-tab", index)),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::Default);
        let selected = *current == *value;
        response
            .widget_info(|| egui::WidgetInfo::selected(egui::Role::Tab, true, selected, *label));
        let fill = if selected {
            VIEW
        } else if response.hovered() {
            HOVER
        } else {
            HEADER
        };
        painter.rect_filled(
            tab,
            CornerRadius {
                nw: 4,
                ne: 4,
                sw: 0,
                se: 0,
            },
            fill,
        );
        if selected {
            painter.hline(
                tab.x_range().shrink(1.0),
                tab.top() + 1.0,
                Stroke::new(2.0, ACCENT),
            );
        }
        painter.galley(
            egui::pos2(tab.left() + 11.0, tab.center().y - galley.size().y / 2.0),
            galley,
            if selected { TEXT } else { MUTED },
        );
        if response.clicked() && !selected {
            *current = *value;
            changed = true;
        }
    }
    ui.add_space(2.0);
    changed
}

/// One entry of a view switcher, underlined when selected. Behaves like
/// `selectable_value`.
pub fn tab<T: PartialEq>(ui: &mut Ui, current: &mut T, value: T, label: &str) -> egui::Response {
    let selected = *current == value;
    let mut response = ui.add(
        egui::Button::new(RichText::new(label).color(if selected { TEXT } else { MUTED }))
            .frame_when_inactive(false)
            .min_size(egui::vec2(0.0, 24.0)),
    );
    if selected {
        let rect = response.rect;
        ui.painter().hline(
            rect.x_range().shrink(2.0),
            rect.bottom() + 1.0,
            Stroke::new(2.0, ACCENT),
        );
    }
    if response.clicked() && !selected {
        *current = value;
        response.mark_changed();
    }
    response
}

/// Hex digits used for addresses in a listing ending at `last`.
pub fn address_digits(last: u64) -> usize {
    (64 - last.leading_zeros() as usize).div_ceil(4).max(8)
}

/// Instruction bytes for the fixed-width byte column; long encodings are
/// elided so the mnemonic column stays aligned.
pub fn listing_bytes(bytes: &[u8]) -> String {
    let shown = if bytes.len() > LISTING_BYTES {
        LISTING_BYTES - 1
    } else {
        bytes.len()
    };
    let mut text = String::with_capacity(LISTING_BYTES * 3);
    for (index, byte) in bytes[..shown].iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&format!("{byte:02x}"));
    }
    if shown < bytes.len() {
        text.push('…');
    }
    text
}

/// Character offsets of the Listing's Address, Bytes, Mnemonic and Operands
/// columns.
pub fn listing_columns(address_digits: usize) -> [usize; 4] {
    let bytes = address_digits + 2;
    let mnemonic = bytes + LISTING_BYTES * 3 + 1;
    [0, bytes, mnemonic, mnemonic + 11]
}

pub fn listing_row(
    address: u64,
    address_digits: usize,
    bytes: &[u8],
    mnemonic: &str,
    operands: &str,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let bytes_width = LISTING_BYTES * 3 - 1;
    for (text, color) in [
        (format!("{address:0address_digits$x}  "), ADDRESS),
        (format!("{:<bytes_width$}  ", listing_bytes(bytes)), BYTES),
        (format!("{mnemonic:<10} "), MNEMONIC),
        (operands.to_owned(), TEXT),
    ] {
        job.append(&text, 0.0, mono_format(color));
    }
    job
}

pub fn mono_format(color: Color32) -> egui::TextFormat {
    egui::TextFormat {
        font_id: FontId::monospace(13.0),
        color,
        ..Default::default()
    }
}

/// Width of one monospace character in the shared code font.
pub fn glyph_width(ui: &Ui) -> f32 {
    ui.fonts_mut(|fonts| fonts.glyph_width(&FontId::monospace(13.0), '0'))
}

/// Rows of `pitch` overlapping the content-space range `viewport`.
pub fn visible_rows(viewport: egui::Rangef, pitch: f32, count: usize) -> std::ops::Range<usize> {
    if count == 0 || pitch <= 0.0 || viewport.max <= 0.0 {
        return 0..0;
    }
    let first = ((viewport.min.max(0.0) / pitch).floor() as usize).min(count);
    let last = ((viewport.max / pitch).ceil() as usize).clamp(first, count);
    first..last
}

/// Whether `row` lies entirely inside the content-space range `viewport`.
pub fn row_visible(viewport: egui::Rangef, pitch: f32, row: usize) -> bool {
    let top = row as f32 * pitch;
    top >= viewport.min && top + pitch <= viewport.max
}

/// A virtualized list of `row_height` rows filling the available space.
///
/// Every row spans the full content width, so the scroll range and bars do not
/// depend on which rows happen to be visible. `reveal` brings a row into view,
/// centered, only when it is not already fully visible. `add_row` receives the
/// row index and its screen rectangle.
pub fn rows<R>(
    ui: &mut Ui,
    id_salt: impl std::hash::Hash + std::fmt::Debug,
    count: usize,
    row_height: f32,
    content_width: f32,
    reveal: Option<usize>,
    mut add_row: impl FnMut(&mut Ui, usize, egui::Rect) -> Option<R>,
) -> (Option<R>, egui::scroll_area::ScrollAreaOutput<()>) {
    let mut result = None;
    let salt = egui::IdSalt::new(id_salt);
    let id = ui.make_persistent_id(egui::IdSalt::new(salt));
    let horizontal = content_width > 0.0;
    let pixels_per_point = ui.pixels_per_point();
    let pixel = 1.0 / pixels_per_point;
    let mut area = egui::ScrollArea::new([horizontal, true])
        .id_salt(salt)
        .auto_shrink([false, false]);
    // Apply the reveal before showing so the row is in view on this frame.
    if let Some(row) = reveal.filter(|row| *row < count) {
        let offset = egui::scroll_area::State::load(ui.ctx(), id)
            .map_or(0.0, |state| state.clamped_offset().y);
        // A horizontal scroll bar's gutter hides the bottom of the view.
        let gutter = ui.spacing().scroll.allocated_width();
        let viewport_width = ui.available_width()
            - if row_height * count as f32 > ui.available_height() {
                gutter
            } else {
                0.0
            };
        let height = ui.available_height()
            - if horizontal && content_width > viewport_width + pixel {
                gutter
            } else {
                0.0
            };
        if !row_visible(egui::Rangef::new(offset, offset + height), row_height, row) {
            let content = row_height * count as f32;
            let centered = (row as f32 + 0.5) * row_height - height / 2.0;
            area = area.vertical_scroll_offset(centered.clamp(0.0, (content - height).max(0.0)));
        }
    }
    let output = area.show_viewport(ui, |ui, viewport| {
        // egui pixel-rounds the child rect independently of the viewport.
        // Filling that rounded child can exceed the viewport by a fraction of
        // a pixel and enable a needless bar. Fit against the actual viewport,
        // snap real horizontal content, and ignore sub-pixel overflow.
        let fit_width = (viewport.width() * pixels_per_point).floor() / pixels_per_point;
        let requested_width = (content_width * pixels_per_point).round() / pixels_per_point;
        let width = if horizontal && requested_width > viewport.width() + pixel {
            requested_width
        } else {
            fit_width
        };
        let origin = ui.max_rect().min;
        ui.allocate_rect(
            egui::Rect::from_min_size(origin, egui::vec2(width, row_height * count as f32)),
            egui::Sense::hover(),
        );
        for row in visible_rows(viewport.y_range(), row_height, count) {
            let rect = egui::Rect::from_min_size(
                origin + egui::vec2(0.0, row as f32 * row_height),
                egui::vec2(width, row_height),
            );
            if let Some(value) = add_row(ui, row, rect) {
                result = Some(value);
            }
        }
    });
    debug_assert_eq!(output.id, id, "reveal reads this scroll area's state");
    (result, output)
}

/// A clickable full-width row with hover, related and selected fills.
pub fn row_response(
    ui: &mut Ui,
    id: egui::Id,
    rect: egui::Rect,
    selected: bool,
    related: bool,
) -> egui::Response {
    let response = ui.interact(rect, id, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let fill = if selected {
            Some(SELECTION)
        } else if related {
            Some(RELATED)
        } else if response.hovered() {
            Some(HOVER)
        } else {
            None
        };
        if let Some(fill) = fill {
            ui.painter().rect_filled(rect, 0, fill);
        }
        if selected {
            ui.painter().rect_filled(
                egui::Rect::from_min_size(rect.min, egui::vec2(2.0, rect.height())),
                0,
                ACCENT,
            );
        }
    }
    response
}

/// Paint one line of text in a row cell, vertically centered and clipped to
/// `cell` with an ellipsis rather than overlapping the next column.
pub fn cell_text(ui: &Ui, cell: egui::Rect, text: impl Into<egui::WidgetText>, color: Color32) {
    if !ui.is_rect_visible(cell) {
        return;
    }
    let galley = text.into().into_galley(
        ui,
        Some(egui::TextWrapMode::Truncate),
        (cell.width() - 6.0).max(0.0),
        TextStyle::Monospace,
    );
    let position = egui::pos2(cell.left() + 6.0, cell.center().y - galley.size().y / 2.0);
    ui.painter()
        .with_clip_rect(cell.intersect(ui.clip_rect()))
        .galley(position, galley, color);
}

/// A column-heading strip in the shared header style. `columns` holds each
/// title and its x offset from the strip's left edge; `scroll_x` follows a
/// horizontally scrolled body.
pub fn column_header(ui: &mut Ui, columns: &[(&str, f32)], scroll_x: f32) -> egui::Rect {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), ROW_HEIGHT),
        egui::Sense::hover(),
    );
    paint_column_header(ui, rect, columns, scroll_x);
    rect
}

/// Paint a header strip into an already allocated rectangle.
pub fn paint_column_header(ui: &Ui, rect: egui::Rect, columns: &[(&str, f32)], scroll_x: f32) {
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter().with_clip_rect(rect.intersect(ui.clip_rect()));
    painter.rect_filled(rect, 0, HEADER);
    painter.hline(
        rect.x_range(),
        rect.bottom() - 0.5,
        Stroke::new(1.0, BORDER),
    );
    for (title, x) in columns {
        painter.text(
            egui::pos2(rect.left() + 6.0 + x - scroll_x, rect.center().y),
            egui::Align2::LEFT_CENTER,
            *title,
            FontId::proportional(12.0),
            MUTED,
        );
    }
}

/// A muted placeholder centered in an empty view.
pub fn empty_state(ui: &mut Ui, text: &str) {
    ui.add_space(24.0);
    ui.vertical_centered(|ui| ui.weak(text));
}

/// Graph block corner radius at the current zoom.
pub fn scaled_radius(zoom: f32) -> u8 {
    (f32::from(NODE_RADIUS) * zoom.min(1.5)).round() as u8
}

#[cfg(test)]
mod tests {
    use eframe::egui;

    #[test]
    fn fractional_scale_rows_keep_scrollbars_geometry_and_offsets_stable() {
        for scale in [1.25, 1.5] {
            for requested in [0.0, 250.1, 450.3] {
                let context = egui::Context::default();
                super::install(&context);
                context.set_pixels_per_point(scale);
                context.style_mut_of(egui::Theme::Dark, |style| style.animation_time = 0.0);
                let mut stable = None;
                for frame in 0..24 {
                    let mut output = context.run_ui(
                        egui::RawInput {
                            time: Some(frame as f64 * 0.1),
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                egui::vec2(260.0, 400.0),
                            )),
                            ..Default::default()
                        },
                        |ui| {
                            let (_, out) = super::rows::<()>(
                                ui,
                                "fractional-rows",
                                1000,
                                20.0,
                                requested,
                                None,
                                |ui, row, rect| {
                                    let _ = super::row_response(
                                        ui,
                                        ui.scope_id().with(row),
                                        rect,
                                        false,
                                        false,
                                    );
                                    super::cell_text(ui, rect, "A function or string", super::TEXT);
                                    None
                                },
                            );
                            // After the vertical gutter settles, a 0.1-point excess is
                            // below one physical pixel and must not enable horizontal scrolling.
                            if frame >= 3 {
                                let horizontal = out.content_size.x > out.inner_rect.width().ceil();
                                assert_eq!(
                                    horizontal,
                                    requested > 400.0,
                                    "scale={scale}, width={requested}: content={:?} inner={:?}",
                                    out.content_size,
                                    out.inner_rect
                                );
                                let geometry = (
                                    horizontal,
                                    out.content_size.y > out.inner_rect.height(),
                                    out.inner_rect,
                                    out.state.clamped_offset(),
                                );
                                if let Some(previous) = stable {
                                    assert_eq!(
                                        geometry, previous,
                                        "scale={scale}, width={requested}, frame={frame}"
                                    );
                                }
                                stable = Some(geometry);
                            }
                        },
                    );
                    output.textures_delta.clear();
                }
            }
        }
    }

    #[test]
    fn narrow_dock_headers_keep_painted_saved_text_and_both_views_reachable() {
        for width in [360.0, 260.0, 180.0, 120.0] {
            let context = egui::Context::default();
            super::install(&context);
            let mut current = false;
            let mut action = egui::Rect::NOTHING;
            let mut frame = |events: Vec<egui::Event>| {
                let mut output = context.run_ui(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(width, 200.0),
                        )),
                        events,
                        ..Default::default()
                    },
                    |ui| {
                        super::dock_tabs(
                            ui,
                            &mut current,
                            &[(false, "Symbol Tree"), (true, "Program Trees")],
                            |ui| {
                                action = ui.weak("Saved").rect;
                            },
                        );
                    },
                );
                output.textures_delta.clear();
                output
            };
            frame(vec![]);
            let output = frame(vec![]);
            let saved = output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::Shape::Text(text) if text.galley.text() == "Saved" => {
                        let bounds = text.galley.rect.translate(text.pos.to_vec2());
                        assert!(
                            shape.clip_rect.contains_rect(bounds),
                            "{width}: {bounds:?} vs {:?}",
                            shape.clip_rect
                        );
                        Some(bounds)
                    }
                    _ => None,
                })
                .unwrap();
            let tab = output.shapes.iter().find_map(|shape| match &shape.shape {
                egui::Shape::Text(text) if text.galley.text() == "Symbols" => {
                    Some(text.pos + egui::vec2(8.0, 5.0))
                }
                _ => None,
            });
            if let Some(pos) = tab {
                assert!(pos.x < saved.left());
                let click = |pos| {
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
                frame(click(pos));
                let output = frame(vec![]);
                let texts = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::Shape::Text(text) => Some((text.galley.text(), text.pos)),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert!(texts.iter().any(|(text, _)| *text == "Symbol Tree"));
                let pos = texts
                    .iter()
                    .find(|(text, _)| *text == "Program Trees")
                    .unwrap()
                    .1
                    + egui::vec2(8.0, 5.0);
                frame(click(pos));
                let output = frame(vec![]);
                assert!(output.shapes.iter().any(|shape| matches!(&shape.shape, egui::Shape::Text(text) if text.galley.text() == "Saved")));
                assert!(current);
            }
            assert!(action.left() >= saved.left() - 1.0);
        }
    }

    #[test]
    fn interface_fonts_render_the_arrows_used_in_labels_and_graph_exits() {
        let context = egui::Context::default();
        super::install(&context);
        // Fonts are loaded by the first frame.
        context
            .run_ui(egui::RawInput::default(), |_| {})
            .textures_delta
            .clear();
        for font in [
            egui::FontId::proportional(13.0),
            egui::FontId::monospace(13.0),
        ] {
            assert!(
                context.fonts_mut(|fonts| fonts.has_glyphs(&font, "→↶·…—")),
                "{font:?}"
            );
        }
    }

    #[test]
    fn visible_rows_cover_partial_rows_at_both_edges_and_stay_in_bounds() {
        let range = |min, max| egui::Rangef::new(min, max);
        assert_eq!(super::visible_rows(range(0.0, 100.0), 20.0, 1000), 0..5);
        assert_eq!(super::visible_rows(range(10.0, 101.0), 20.0, 1000), 0..6);
        assert_eq!(
            super::visible_rows(range(19_990.0, 20_100.0), 20.0, 1000),
            999..1000
        );
        assert_eq!(super::visible_rows(range(0.0, 100.0), 20.0, 0), 0..0);
        assert!(super::row_visible(range(40.0, 100.0), 20.0, 2));
        assert!(!super::row_visible(range(41.0, 100.0), 20.0, 2));
        assert!(!super::row_visible(range(0.0, 100.0), 20.0, 5));
    }

    #[test]
    fn revealing_rows_scrolls_only_when_needed_and_centers_the_target() {
        let context = egui::Context::default();
        super::install(&context);
        let frame = |reveal: Option<usize>| {
            let mut offset = 0.0;
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(400.0, 300.0),
                    )),
                    ..Default::default()
                },
                |ui| {
                    let (_, rows) =
                        super::rows::<()>(ui, "rows", 1000, 20.0, 900.0, reveal, |_, _, _| None);
                    offset = rows.state.clamped_offset().y;
                    assert_eq!(rows.content_size.x, 900.0, "width is independent of rows");
                },
            );
            output.textures_delta.clear();
            offset
        };
        frame(None);
        assert_eq!(frame(Some(5)), 0.0, "a visible row does not move the view");
        let offset = frame(Some(500));
        let center = 500.0 * 20.0 + 10.0;
        assert!(
            (offset..offset + 300.0).contains(&(center - 20.0)),
            "row 500 is in view at offset {offset}"
        );
        assert!(
            (offset + 150.0 - center).abs() < 25.0,
            "and roughly centered"
        );
        assert_eq!(
            frame(Some(500)),
            offset,
            "revealing it again keeps the view"
        );
    }

    #[test]
    fn long_encodings_keep_listing_columns_aligned() {
        let short = super::listing_row(0x1000, 8, &[0x90], "NOP", "");
        let long = super::listing_row(0x1001, 8, &[0x66; 15], "NOP", "word ptr [rax]");
        let mnemonic = super::listing_columns(8)[2];
        for job in [short, long] {
            let at = job.text.find("NOP").unwrap();
            assert_eq!(job.text[..at].chars().count(), mnemonic, "{}", job.text);
        }
        assert_eq!(super::listing_bytes(&[0x66; 15]), "66 66 66 66 66 66 66…");
        assert_eq!(super::address_digits(0x1000), 8);
        assert_eq!(super::address_digits(0x1_4000_1000), 9);
    }
}
