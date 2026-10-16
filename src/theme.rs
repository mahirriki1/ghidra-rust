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

pub fn install(context: &egui::Context) {
    context.set_visuals(egui::Visuals::dark());
    context.global_style_mut(|style| {
        let visuals = &mut style.visuals;
        visuals.panel_fill = CHROME;
        visuals.window_fill = CHROME;
        visuals.extreme_bg_color = VIEW;
        visuals.text_edit_bg_color = Some(VIEW);
        visuals.code_bg_color = VIEW;
        visuals.faint_bg_color = Color32::from_rgb(39, 39, 43);
        visuals.weak_text_color = Some(MUTED);
        visuals.selection.bg_fill = SELECTION;
        visuals.selection.stroke = Stroke::new(1.0, TEXT);
        visuals.hyperlink_color = BLUE;
        visuals.warn_fg_color = WARNING;
        visuals.error_fg_color = ERROR;
        visuals.window_corner_radius = CornerRadius::ZERO;
        visuals.menu_corner_radius = CornerRadius::ZERO;
        visuals.window_stroke = Stroke::new(1.0, BORDER);
        for widget in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            widget.corner_radius = CornerRadius::ZERO;
            widget.expansion = 0.0;
            widget.fg_stroke = Stroke::new(1.0, TEXT);
            widget.bg_stroke = Stroke::new(1.0, BORDER);
        }
        visuals.widgets.noninteractive.bg_fill = CHROME;
        visuals.widgets.noninteractive.weak_bg_fill = CHROME;
        visuals.widgets.inactive.bg_fill = CHROME;
        visuals.widgets.inactive.weak_bg_fill = CHROME;
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(65, 65, 70);
        visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(55, 65, 85);
        visuals.widgets.active.bg_fill = HEADER;
        visuals.widgets.active.weak_bg_fill = HEADER;
        visuals.widgets.open.bg_fill = HEADER;
        visuals.widgets.open.weak_bg_fill = HEADER;
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
        style.animation_time = 0.0;
    });
}

pub fn view_frame() -> Frame {
    Frame::NONE.fill(VIEW).inner_margin(5)
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
