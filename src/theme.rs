//! Classic Ghidra-inspired desktop chrome and dark analysis views.
//!
//! Color references: the cloned Ghidra gui, docking, listing, and decompiler
//! theme properties. Controls remain native Rust/egui widgets.
use eframe::egui::{self, Color32, CornerRadius, FontId, Frame, RichText, Stroke, TextStyle, Ui};

pub const VIEW: Color32 = Color32::from_rgb(30, 30, 30);
pub const CHROME: Color32 = Color32::from_rgb(45, 45, 48);
pub const HEADER: Color32 = Color32::from_rgb(56, 56, 56);
pub const BORDER: Color32 = Color32::from_rgb(85, 85, 85);
pub const TEXT: Color32 = Color32::from_rgb(221, 221, 221);
pub const MUTED: Color32 = Color32::from_rgb(168, 168, 168);
pub const BLUE: Color32 = Color32::from_rgb(135, 206, 250);
pub const CURRENT_LINE: Color32 = Color32::from_rgb(36, 59, 64);
pub const SELECTION: Color32 = Color32::from_rgb(45, 61, 91);
pub const WARNING: Color32 = Color32::from_rgb(255, 228, 181);
pub const ERROR: Color32 = Color32::from_rgb(240, 128, 128);
pub const SYNTAX_COMMENT: Color32 = Color32::from_rgb(238, 130, 238);
pub const SYNTAX_CONSTANT: Color32 = Color32::from_rgb(112, 192, 112);
pub const SYNTAX_VARIABLE: Color32 = Color32::from_rgb(192, 192, 128);
pub const GRAPH_BACKGROUND: Color32 = Color32::from_rgb(36, 36, 36);
const ACTIVE_HEADER: Color32 = Color32::from_rgb(52, 75, 115);

/// Compact Graphite controls around the familiar Ghidra analysis panes.
pub fn install(context: &egui::Context) {
    context.set_theme(egui::Theme::Dark);
    let mut style = egui::Style::default();
    let visuals = &mut style.visuals;
    *visuals = egui::Visuals::dark();
    let chrome = Color32::from_rgb(37, 42, 51);
    let border = Color32::from_rgb(62, 70, 82);
    let text = Color32::from_rgb(231, 234, 240);
    let accent = Color32::from_rgb(116, 179, 255);
    let selected = Color32::from_rgb(37, 62, 94);
    visuals.override_text_color = Some(text);
    visuals.weak_text_color = Some(Color32::from_rgb(165, 176, 192));
    visuals.panel_fill = chrome;
    visuals.window_fill = chrome;
    visuals.extreme_bg_color = Color32::from_rgb(22, 26, 33);
    visuals.text_edit_bg_color = Some(visuals.extreme_bg_color);
    visuals.selection.bg_fill = selected;
    visuals.selection.stroke = Stroke::new(1.0, accent);
    visuals.hyperlink_color = accent;
    visuals.error_fg_color = Color32::from_rgb(255, 158, 158);
    visuals.warn_fg_color = Color32::from_rgb(238, 202, 133);
    visuals.window_corner_radius = CornerRadius::same(12);
    visuals.window_stroke = Stroke::new(1.0, border);
    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::same(3);
        widget.expansion = 0.0;
        widget.fg_stroke.color = text;
        widget.bg_stroke = Stroke::new(1.0, border);
    }
    visuals.widgets.inactive.bg_fill = chrome;
    visuals.widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    visuals.widgets.hovered.bg_fill = selected;
    visuals.widgets.hovered.weak_bg_fill = selected;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, accent);
    visuals.widgets.active.bg_fill = selected;
    visuals.widgets.active.weak_bg_fill = selected;
    visuals.widgets.active.bg_stroke = Stroke::new(1.5, accent);
    style.spacing.item_spacing = egui::vec2(5.0, 3.0);
    style.spacing.button_padding = egui::vec2(5.0, 2.0);
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

pub fn view_frame() -> Frame {
    Frame::NONE.fill(VIEW).inner_margin(5)
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
            .rect_filled(track, 2, ui.visuals().extreme_bg_color);
        let width = track.width() * 0.28;
        let phase = (elapsed.as_secs_f32() * std::f32::consts::PI).sin() * 0.5 + 0.5;
        let segment = egui::Rect::from_min_size(
            track.min + egui::vec2((track.width() - width) * phase, 0.0),
            egui::vec2(width, track.height()),
        );
        ui.painter()
            .rect_filled(segment, 2, ui.visuals().selection.stroke.color);
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
        egui::Button::new("").min_size(egui::vec2(26.0, 22.0)),
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

/// A compact provider title bar rather than a rounded dashboard heading.
pub fn dock_header(ui: &mut Ui, title: &str, active: bool, actions: impl FnOnce(&mut Ui)) {
    Frame::NONE
        .fill(if active { ACTIVE_HEADER } else { HEADER })
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(4)
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new(title).color(if active { Color32::WHITE } else { TEXT }));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
            });
        });
}

pub fn listing_row(
    address: u64,
    bytes: &str,
    mnemonic: &str,
    operands: &str,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    for (text, color) in [
        (format!("{address:08x}  "), TEXT),
        (format!("{bytes:<25} "), BLUE),
        (format!("{mnemonic:<10} "), Color32::from_rgb(178, 200, 255)),
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
