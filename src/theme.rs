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
const ADDRESS: Color32 = MUTED;
const BYTES: Color32 = Color32::from_rgb(92, 99, 112);
const MNEMONIC: Color32 = SYNTAX_KEYWORD;
const HOVER: Color32 = Color32::from_rgb(44, 46, 51);
const INPUT: Color32 = Color32::from_rgb(18, 19, 21);

pub fn install(context: &egui::Context) {
    context.set_theme(egui::Theme::Dark);
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
    // Virtualized listing and function rows assume this row height.
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

/// Activity without an invented completion percentage. The parent uses a
/// right-to-left status layout, so the track stays at the window's right edge.
pub fn analysis_activity(ui: &mut Ui, task: &str, elapsed: std::time::Duration) {
    let (track, response) = ui.allocate_exact_size(egui::vec2(88.0, 6.0), egui::Sense::hover());
    let label = format!("{task} · {:.1}s", elapsed.as_secs_f32());
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::ProgressIndicator, ui.is_enabled(), &label)
    });
    response.on_hover_text("Analysis is running. Use Analysis → Cancel analysis to stop it.");
    if ui.is_rect_visible(track) {
        ui.painter()
            .rect_filled(track, 3, ui.visuals().extreme_bg_color);
        let width = track.width() * 0.28;
        let phase = (elapsed.as_secs_f32() * std::f32::consts::PI).sin() * 0.5 + 0.5;
        let segment = egui::Rect::from_min_size(
            track.min + egui::vec2((track.width() - width) * phase, 0.0),
            egui::vec2(width, track.height()),
        );
        ui.painter()
            .rect_filled(segment, 3, ui.visuals().selection.stroke.color);
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(66));
    }
    ui.label(RichText::new(label).small());
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
    let background = ui.painter().add(egui::Shape::Noop);
    let row = ui.horizontal(|ui| {
        ui.set_min_height(26.0);
        ui.add_space(4.0);
        let title = ui.label(RichText::new(title).color(if active { TEXT } else { MUTED }));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.add_space(4.0);
            actions(ui);
        });
        title.rect
    });
    let strip = row.response.rect.expand2(egui::vec2(2.0, 1.0));
    let tab = egui::Rect::from_x_y_ranges(
        row.inner.x_range().expand(10.0),
        (strip.top() + 3.0)..=strip.bottom(),
    );
    let painter = ui.painter();
    painter.set(
        background,
        egui::Shape::Vec(vec![
            egui::Shape::rect_filled(strip, 3, CHROME),
            egui::Shape::rect_filled(
                tab,
                CornerRadius {
                    nw: 4,
                    ne: 4,
                    sw: 0,
                    se: 0,
                },
                if active { VIEW } else { HEADER },
            ),
        ]),
    );
    if active {
        painter.hline(tab.x_range(), tab.top() + 1.0, Stroke::new(2.0, ACCENT));
    }
    ui.add_space(4.0);
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

pub fn listing_row(
    address: u64,
    bytes: &str,
    mnemonic: &str,
    operands: &str,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    for (text, color) in [
        (format!("{address:08x}  "), ADDRESS),
        (format!("{bytes:<25} "), BYTES),
        (format!("{mnemonic:<10} "), MNEMONIC),
        (operands.to_owned(), TEXT),
    ] {
        job.append(
            &text,
            0.0,
            egui::TextFormat {
                font_id: FontId::monospace(13.0),
                color,
                ..Default::default()
            },
        );
    }
    job
}

/// Graph block corner radius at the current zoom.
pub fn scaled_radius(zoom: f32) -> u8 {
    (f32::from(NODE_RADIUS) * zoom.min(1.5)).round() as u8
}
