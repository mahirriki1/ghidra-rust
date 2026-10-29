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
    paint_warning_icon(
        ui.painter(),
        egui::pos2(
            menu.response.rect.left() + ui.spacing().button_padding.x + 5.0,
            menu.response.rect.center().y,
        ),
    );
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

/// A lone dock title with declared actions. Actions that do not fit move into
/// a More actions menu; the caller dispatches the returned action afterwards.
pub fn dock_header_actions<A: Copy>(
    ui: &mut Ui,
    title: &str,
    saved: Option<(&str, &str)>,
    actions: &[DockAction<'_, A>],
) -> Option<A> {
    let mut current = false;
    dock_strip(ui, &mut current, &[(false, title)], saved, actions, |_| {}).action
}

/// A dock title strip whose entries are editor-style tabs; the selected tab
/// joins the pane below it. `saved` supplies the preferred provenance label and
/// tooltip; narrow strips shorten it to "Saved". Tabs that do not fit stay
/// reachable through a More tabs menu beside the active tab. Returns whether
/// selection changed.
pub fn dock_tabs<T: PartialEq + Copy>(
    ui: &mut Ui,
    current: &mut T,
    tabs: &[(T, &str)],
    saved: Option<(&str, &str)>,
    passive: impl FnOnce(&mut Ui),
) -> bool {
    dock_strip::<T, ()>(ui, current, tabs, saved, &[], passive).changed
}

/// A header control declared up front, so a narrow strip can move it into
/// the More actions menu instead of clipping it. A lower `priority` stays
/// inline longer; inline actions keep their declaration order from the right.
#[derive(Clone, Copy, Debug)]
pub struct DockAction<'a, A> {
    pub id: A,
    pub label: &'a str,
    pub tooltip: &'a str,
    pub enabled: bool,
    pub priority: u8,
    pub kind: DockActionKind<'a>,
}

#[derive(Clone, Copy, Debug)]
pub enum DockActionKind<'a> {
    Button,
    /// A checkbox showing the current value; activation reports the action.
    Toggle(bool),
    /// A warning count whose menu lists each warning; it reports no action.
    Warnings(&'a [String]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DockResponse<A> {
    changed: bool,
    action: Option<A>,
}

const DOCK_HEIGHT: f32 = 26.0;
const DOCK_GAP: f32 = 4.0;
const DOCK_TAB_PAD: f32 = 11.0;
const DOCK_TIGHT_PAD: f32 = 4.0;
const DOCK_ACTION_PAD: f32 = 3.0;
/// Width of the More tabs and More actions buttons.
const DOCK_ICON: f32 = 20.0;
const DOCK_RIGHT: f32 = 4.0;

/// Widths, in points rounded up to physical pixels, that one strip lays out
/// this frame. Placement depends on nothing else.
#[derive(Clone, Debug, PartialEq)]
struct DockMeasure {
    available: f32,
    tabs: Vec<f32>,
    selected: Option<usize>,
    minimum_tab: f32,
    /// One physical pixel between adjacent tabs.
    tab_gap: f32,
    /// Compact and preferred provenance label widths.
    saved: Option<(f32, f32)>,
    /// Inline width and priority of each declared action.
    actions: Vec<(f32, u8)>,
}

#[derive(Clone, Debug, PartialEq)]
struct DockLayout {
    /// Painted width of each visible tab, in tab order.
    tabs: Vec<Option<f32>>,
    more_tabs: bool,
    saved_full: bool,
    inline: Vec<bool>,
    more_actions: bool,
}

impl DockMeasure {
    /// Reserved before any discretionary item: the overflow buttons, the
    /// compact provenance label and an ellipsized active tab.
    fn reserved(&self, more_tabs: bool, more_actions: bool) -> f32 {
        let mut used = 0.0;
        if more_actions {
            used += DOCK_ICON + DOCK_GAP;
        }
        if let Some((compact, _)) = self.saved {
            used += compact + DOCK_GAP;
        }
        if more_tabs {
            used += DOCK_ICON + self.tab_gap;
        }
        if !self.tabs.is_empty() {
            used += self.minimum_tab;
        }
        used
    }

    /// One strict priority chain: the active tab's full label, actions by
    /// priority, the preferred provenance label, then other tabs in order. The
    /// first item that does not fit ends the chain, so a wider strip only
    /// ever shows more.
    fn place(&self, more_tabs: bool, more_actions: bool) -> DockLayout {
        let mut layout = DockLayout {
            tabs: vec![None; self.tabs.len()],
            more_tabs,
            saved_full: false,
            inline: vec![false; self.actions.len()],
            more_actions,
        };
        let mut used = self.reserved(more_tabs, more_actions);
        let mut open = true;
        if let Some(selected) = self.selected {
            used -= self.minimum_tab;
            let room = (self.available - used).max(0.0);
            let full = self.tabs[selected];
            let width = if full <= room {
                full
            } else {
                open = false;
                room
            };
            layout.tabs[selected] = Some(width);
            used += width;
        }
        let mut fits = |width: f32, open: &mut bool| {
            *open = *open && used + width <= self.available;
            if *open {
                used += width;
            }
            *open
        };
        let mut order: Vec<usize> = (0..self.actions.len()).collect();
        order.sort_by_key(|&index| self.actions[index].1);
        for index in order {
            layout.inline[index] = fits(self.actions[index].0 + DOCK_GAP, &mut open);
        }
        if let Some((compact, full)) = self.saved {
            layout.saved_full = fits(full - compact, &mut open);
        }
        for (index, &width) in self.tabs.iter().enumerate() {
            if Some(index) != self.selected && fits(width + self.tab_gap, &mut open) {
                layout.tabs[index] = Some(width);
            }
        }
        layout
    }

    /// The first arrangement whose overflow buttons cover what it hides.
    fn layout(&self) -> DockLayout {
        let many_tabs = self.tabs.len() > 1;
        let any_actions = !self.actions.is_empty();
        [(false, false), (false, true), (true, false), (true, true)]
            .into_iter()
            .filter(|&(tabs, actions)| (many_tabs || !tabs) && (any_actions || !actions))
            .map(|(tabs, actions)| self.place(tabs, actions))
            .find(|layout| {
                (layout.more_tabs || layout.tabs.iter().all(Option::is_some))
                    && (layout.more_actions || layout.inline.iter().all(|inline| *inline))
            })
            .unwrap_or_else(|| self.place(many_tabs, any_actions))
    }
}

/// Round a width up, or an available extent down, to whole physical pixels.
fn ceil_pixels(points: f32, pixels_per_point: f32) -> f32 {
    (points * pixels_per_point - 1e-3).ceil() / pixels_per_point
}

fn floor_pixels(points: f32, pixels_per_point: f32) -> f32 {
    (points * pixels_per_point + 1e-3).floor() / pixels_per_point
}

fn text_width(ui: &Ui, text: &str, font: &FontId) -> f32 {
    ui.fonts_mut(|fonts| {
        fonts
            .layout_no_wrap(text.to_owned(), font.clone(), TEXT)
            .size()
            .x
    })
}

fn dock_strip<T: PartialEq + Copy, A: Copy>(
    ui: &mut Ui,
    current: &mut T,
    tabs: &[(T, &str)],
    saved: Option<(&str, &str)>,
    actions: &[DockAction<'_, A>],
    passive: impl FnOnce(&mut Ui),
) -> DockResponse<A> {
    let mut response = DockResponse {
        changed: false,
        action: None,
    };
    if let Some((value, _)) = tabs.first()
        && !tabs.iter().any(|(value, _)| value == current)
    {
        *current = *value;
        response.changed = true;
    }
    let (strip, strip_response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), DOCK_HEIGHT),
        egui::Sense::hover(),
    );
    // Allocation order scopes every tab, control and popup to this strip.
    let base = strip_response.id;
    let ppp = ui.pixels_per_point();
    let clip = strip.intersect(ui.clip_rect());
    let painter = ui.painter().with_clip_rect(clip);
    painter.rect_filled(strip, 0, CHROME);
    painter.hline(
        strip.x_range(),
        strip.bottom() - 0.5,
        Stroke::new(1.0, BORDER),
    );
    // Text origins are pixel-rounded independently of galley widths. Leave
    // one physical pixel of paint room inside the nonoverlapping strip gaps.
    let slack = egui::vec2(1.0 / ppp, 0.0);
    let tab_font = FontId::proportional(13.0);
    let button_font = TextStyle::Button.resolve(ui.style());
    let body_font = TextStyle::Body.resolve(ui.style());
    let pad = DOCK_ACTION_PAD;
    let tab_pad = if actions.is_empty() {
        DOCK_TAB_PAD
    } else {
        DOCK_TIGHT_PAD
    };
    let selected = tabs.iter().position(|(value, _)| value == current);
    let minimum_tab = ceil_pixels(text_width(ui, "…", &tab_font) + DOCK_TIGHT_PAD * 2.0, ppp);
    let saved_widths = saved.map(|(preferred, _)| {
        (
            ceil_pixels(text_width(ui, "Saved", &body_font), ppp),
            ceil_pixels(text_width(ui, preferred, &body_font), ppp),
        )
    });
    let action_widths: Vec<(f32, u8)> = actions
        .iter()
        .map(|action| {
            let content = match action.kind {
                DockActionKind::Button => text_width(ui, action.label, &button_font),
                DockActionKind::Toggle(_) => {
                    ui.spacing().icon_width
                        + ui.spacing().icon_spacing
                        + text_width(ui, action.label, &button_font)
                }
                DockActionKind::Warnings(warnings) => {
                    WARNING_ICON + text_width(ui, &warnings.len().to_string(), &button_font)
                }
            };
            (ceil_pixels(content + pad * 2.0, ppp), action.priority)
        })
        .collect();
    let mut measure = DockMeasure {
        available: 0.0,
        tabs: tabs
            .iter()
            .map(|(_, label)| ceil_pixels(text_width(ui, label, &tab_font) + tab_pad * 2.0, ppp))
            .collect(),
        selected,
        minimum_tab,
        tab_gap: 1.0 / ppp,
        saved: saved_widths,
        actions: action_widths,
    };
    // Passive content is laid out once from the right, after the space the
    // tabs, provenance and overflow buttons can never give up.
    let right = strip.right() - DOCK_RIGHT;
    let passive_rect = egui::Rect::from_min_max(
        egui::pos2(
            (strip.left() + measure.reserved(tabs.len() > 1, !actions.is_empty()) + DOCK_GAP)
                .min(right),
            strip.top(),
        ),
        egui::pos2(right, strip.bottom()),
    );
    let mut passive_ui = ui.new_child(
        egui::UiBuilder::new()
            .id_salt(base.with("dock-passive"))
            .max_rect(passive_rect)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    passive_ui.set_clip_rect(passive_rect.expand2(slack).intersect(clip));
    passive(&mut passive_ui);
    let mut right = if passive_ui.min_rect().width() > 0.0 {
        passive_ui.min_rect().left().max(passive_rect.left()) - DOCK_GAP
    } else {
        right
    };
    measure.available = floor_pixels(right - strip.left(), ppp).max(0.0);
    let layout = measure.layout();
    let control_rect = |left: f32, right: f32| {
        egui::Rect::from_min_max(
            egui::pos2(left, strip.center().y - 10.0),
            egui::pos2(right, strip.center().y + 10.0),
        )
    };
    if layout.more_actions {
        let rect = control_rect(right - DOCK_ICON, right);
        right = rect.left() - DOCK_GAP;
        if let Some(action) = more_actions_menu(ui, base, rect, clip, actions, &layout.inline) {
            response.action = Some(action);
        }
    }
    for (index, action) in actions.iter().enumerate() {
        if !layout.inline[index] {
            continue;
        }
        let rect = control_rect(right - measure.actions[index].0, right);
        right = rect.left() - DOCK_GAP;
        if inline_action(ui, base.with(("dock-action", index)), rect, clip, action) {
            response.action = Some(action.id);
        }
    }
    if let (Some((label, tooltip)), Some((compact, full))) = (saved, measure.saved) {
        let (label, width) = if layout.saved_full {
            (label, full)
        } else {
            ("Saved", compact)
        };
        let rect = egui::Rect::from_min_max(
            egui::pos2(right - width, strip.top()),
            egui::pos2(right, strip.bottom()),
        );
        right = rect.left() - DOCK_GAP;
        let galley = painter.layout_no_wrap(label.to_owned(), body_font.clone(), MUTED);
        painter
            .with_clip_rect(rect.expand2(slack).intersect(clip))
            .galley(
                egui::pos2(rect.left(), rect.center().y - galley.size().y / 2.0),
                galley,
                MUTED,
            );
        ui.interact(
            rect.intersect(clip),
            base.with("dock-saved"),
            egui::Sense::hover(),
        )
        .on_hover_text(tooltip);
    }
    let tabs_rect = egui::Rect::from_min_max(
        strip.min,
        egui::pos2(right.max(strip.left()), strip.bottom()),
    );
    let tab_clip = tabs_rect.intersect(clip);
    let tab_painter = painter.with_clip_rect(tab_clip.expand2(slack).intersect(clip));
    let mut x = strip.left();
    for (index, (value, label)) in tabs.iter().enumerate() {
        let Some(width) = layout.tabs[index] else {
            continue;
        };
        let full = width >= measure.tabs[index];
        let pad = if full { tab_pad } else { DOCK_TIGHT_PAD };
        let mut job =
            egui::text::LayoutJob::simple_singleline((*label).to_owned(), tab_font.clone(), TEXT);
        job.wrap = egui::text::TextWrapping::truncate_at_width((width - pad * 2.0).max(0.0));
        let galley = tab_painter.layout_job(job);
        let tab = egui::Rect::from_min_size(
            egui::pos2(x, strip.top() + 3.0),
            egui::vec2(width, DOCK_HEIGHT - 3.0),
        );
        x = tab.right() + measure.tab_gap;
        let interact = tab.intersect(tab_clip);
        let tab_response = ui
            .interact(
                interact,
                base.with(("dock-tab", index)),
                egui::Sense::click(),
            )
            .on_hover_cursor(egui::CursorIcon::Default);
        let tab_response = if galley.elided || !full {
            tab_response.on_hover_text(*label)
        } else {
            tab_response
        };
        let selected = *current == *value;
        tab_response
            .widget_info(|| egui::WidgetInfo::selected(egui::Role::Tab, true, selected, *label));
        let fill = if selected {
            VIEW
        } else if tab_response.hovered() {
            HOVER
        } else {
            HEADER
        };
        tab_painter.rect_filled(
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
            tab_painter.hline(
                tab.x_range().shrink(1.0),
                tab.top() + 1.0,
                Stroke::new(2.0, ACCENT),
            );
        }
        tab_painter.galley(
            egui::pos2(tab.left() + pad, tab.center().y - galley.size().y / 2.0),
            galley,
            if selected { TEXT } else { MUTED },
        );
        if tab_response.clicked() && !selected {
            *current = *value;
            response.changed = true;
        }
    }
    if layout.more_tabs {
        let rect = control_rect(x, x + DOCK_ICON);
        let rect = rect.intersect(egui::Rect::from_min_max(
            strip.min,
            egui::pos2(
                tabs_rect.right().max(strip.left() + DOCK_ICON),
                strip.bottom(),
            ),
        ));
        let hidden: Vec<usize> = (0..tabs.len())
            .filter(|&index| layout.tabs[index].is_none())
            .collect();
        if let Some(index) = more_tabs_menu(ui, base, rect, clip, strip.bottom(), tabs, &hidden) {
            if tabs[index].0 != *current {
                response.changed = true;
            }
            *current = tabs[index].0;
        }
    }
    ui.add_space(2.0);
    response
}

/// Room for the painted warning triangle before its count.
const WARNING_ICON: f32 = 16.0;

/// The menu button listing hidden tabs in their order; returns the chosen one.
/// Entries are rebuilt from the current tab list each frame.
fn more_tabs_menu<T>(
    ui: &mut Ui,
    base: egui::Id,
    rect: egui::Rect,
    clip: egui::Rect,
    bottom: f32,
    tabs: &[(T, &str)],
    hidden: &[usize],
) -> Option<usize> {
    let button = icon_button(
        ui,
        base.with("dock-more-tabs"),
        rect,
        clip,
        "More tabs",
        "»",
        false,
    );
    let popup = egui::Popup::menu(&button).id(base.with("dock-more-tabs").with("dock-popup"));
    let max_height = (ui.ctx().content_rect().bottom() - bottom - 12.0).max(ROW_HEIGHT * 3.0);
    let mut chosen = None;
    popup.show(|ui| {
        egui::ScrollArea::vertical()
            .max_height(max_height)
            .show(ui, |ui| {
                for &index in hidden {
                    if ui.selectable_label(false, tabs[index].1).clicked() {
                        chosen = Some(index);
                        ui.close();
                    }
                }
            });
    });
    chosen
}

/// The More actions menu: every action not shown inline, with its current
/// enabled and checked state. Returns an activated action.
fn more_actions_menu<A: Copy>(
    ui: &mut Ui,
    base: egui::Id,
    rect: egui::Rect,
    clip: egui::Rect,
    actions: &[DockAction<'_, A>],
    inline: &[bool],
) -> Option<A> {
    let button = icon_button(
        ui,
        base.with("dock-more-actions"),
        rect,
        clip,
        "More actions",
        "⋯",
        actions.iter().zip(inline).any(|(action, inline)| {
            !inline
                && matches!(action.kind, DockActionKind::Warnings(warnings) if !warnings.is_empty())
        }),
    );
    let mut chosen = None;
    egui::Popup::menu(&button)
        .id(base.with("dock-more-actions").with("dock-popup"))
        .show(|ui| {
            for (action, _) in actions.iter().zip(inline).filter(|(_, inline)| !**inline) {
                match action.kind {
                    DockActionKind::Button => {
                        if ui
                            .add_enabled(action.enabled, egui::Button::new(action.label))
                            .on_hover_text(action.tooltip)
                            .on_disabled_hover_text(action.tooltip)
                            .clicked()
                        {
                            chosen = Some(action.id);
                            ui.close();
                        }
                    }
                    DockActionKind::Toggle(checked) => {
                        let mut value = checked;
                        if ui
                            .add_enabled(
                                action.enabled,
                                egui::Checkbox::new(&mut value, action.label),
                            )
                            .on_hover_text(action.tooltip)
                            .on_disabled_hover_text(action.tooltip)
                            .clicked()
                        {
                            chosen = Some(action.id);
                            ui.close();
                        }
                    }
                    DockActionKind::Warnings(warnings) => {
                        ui.menu_button(
                            RichText::new(format!("{} ({})", action.label, warnings.len()))
                                .color(WARNING),
                            |ui| warning_list(ui, warnings),
                        )
                        .response
                        .on_hover_text(action.tooltip);
                    }
                }
            }
        });
    chosen
}

fn warning_list(ui: &mut Ui, warnings: &[String]) {
    ui.set_max_width(420.0);
    egui::ScrollArea::vertical()
        .max_height(260.0)
        .show(ui, |ui| {
            for warning in warnings {
                ui.add(egui::Label::new(RichText::new(warning).color(WARNING)).wrap());
            }
        });
}

/// A compact overflow button with an accessible name and matching tooltip.
fn icon_button(
    ui: &mut Ui,
    id: egui::Id,
    rect: egui::Rect,
    clip: egui::Rect,
    name: &str,
    icon: &str,
    warning: bool,
) -> egui::Response {
    let response = ui
        .interact(rect.intersect(clip), id, egui::Sense::click())
        .on_hover_text(name);
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, true, name));
    let painter = ui.painter().with_clip_rect(clip);
    let open = egui::Popup::is_id_open(ui.ctx(), id.with("dock-popup"));
    let visuals = if open {
        &ui.visuals().widgets.open
    } else {
        ui.style().interact(&response)
    };
    if response.hovered() || open {
        painter.rect_filled(rect, 3, visuals.weak_bg_fill);
    }
    painter.text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        icon,
        FontId::proportional(13.0),
        if warning {
            WARNING
        } else if response.hovered() || open {
            TEXT
        } else {
            MUTED
        },
    );
    response
}

/// Place standard egui controls within the measured slot. Warning counts use
/// the shared triangle and a detail popup.
fn inline_action<A>(
    ui: &mut Ui,
    id: egui::Id,
    rect: egui::Rect,
    clip: egui::Rect,
    action: &DockAction<'_, A>,
) -> bool {
    let mut child = ui.new_child(egui::UiBuilder::new().id_salt(id).max_rect(rect));
    child.set_clip_rect(rect.intersect(clip));
    child.spacing_mut().button_padding.x = DOCK_ACTION_PAD;
    if !action.enabled {
        child.disable();
    }
    let response = match action.kind {
        DockActionKind::Button => child.put(rect, egui::Button::new(action.label).small()),
        DockActionKind::Toggle(mut checked) => {
            child.put(rect, egui::Checkbox::new(&mut checked, action.label))
        }
        DockActionKind::Warnings(warnings) => {
            let response = child.interact(rect.intersect(clip), id, egui::Sense::click());
            response.widget_info(|| {
                egui::WidgetInfo::labeled(
                    egui::Role::Button,
                    response.enabled(),
                    format!("{} warnings", warnings.len()),
                )
            });
            let visuals = child.style().interact(&response);
            let painter = child.painter();
            painter.rect_filled(rect, visuals.corner_radius, visuals.weak_bg_fill);
            let pad = child.spacing().button_padding.x;
            paint_warning_icon(
                painter,
                egui::pos2(rect.left() + pad + 5.0, rect.center().y),
            );
            painter.text(
                egui::pos2(rect.left() + pad + WARNING_ICON, rect.center().y),
                egui::Align2::LEFT_CENTER,
                warnings.len().to_string(),
                TextStyle::Button.resolve(child.style()),
                WARNING,
            );
            egui::Popup::menu(&response).show(|ui| warning_list(ui, warnings));
            response.on_hover_text(action.tooltip);
            return false;
        }
    };
    response
        .on_hover_text(action.tooltip)
        .on_disabled_hover_text(action.tooltip)
        .clicked()
}

fn paint_warning_icon(painter: &egui::Painter, center: egui::Pos2) {
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

/// Horizontal cell extents of a Listing row, as offsets from its left edge.
/// They follow the row's actual width rather than its longest content: bytes
/// shrink and then disappear before the mnemonic or operands lose room, and
/// only then does the address ellipsize.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ListingColumns {
    pub address: egui::Rangef,
    pub bytes: Option<egui::Rangef>,
    pub mnemonic: egui::Rangef,
    pub operands: egui::Rangef,
}

/// Text inset at a Listing row's left edge, and room kept at its right.
const LISTING_INSET: f32 = 6.0;
const LISTING_END: f32 = 4.0;

pub fn listing_columns(
    width: f32,
    glyph: f32,
    address_digits: usize,
    pixels_per_point: f32,
) -> ListingColumns {
    let g = glyph.max(0.0);
    let available = (floor_pixels(width, pixels_per_point) - LISTING_INSET - LISTING_END).max(0.0);
    let (wide, narrow) = (2.0 * g, g);
    let address_full = address_digits as f32 * g;
    let (mnemonic_min, operands_min) = (5.0 * g, 8.0 * g);
    let code = wide + mnemonic_min + narrow + operands_min;
    let mut address = address_full;
    let mut gaps = (wide, narrow);
    let mut mnemonic = mnemonic_min;
    let mut bytes = None;
    if available >= address_full + code {
        let mut extra = available - address_full - code;
        let mut take = |limit: f32| {
            let taken = extra.min(limit);
            extra -= taken;
            taken
        };
        mnemonic += take(5.0 * g);
        // Comfortable operands come before any bytes; the operands cell
        // receives whatever remains.
        take(12.0 * g);
        let bytes_full = (LISTING_BYTES * 3 - 1) as f32 * g;
        if extra >= 5.0 * g + wide {
            let width = (extra - wide).min(bytes_full);
            bytes = Some(width);
        }
    } else if available >= (4.0 * g).min(address_full) + code {
        address = available - code;
    } else {
        // Below the supported minimum: shrink every part in proportion.
        let minimum = (4.0 * g).min(address_full) + code;
        let scale = if minimum > 0.0 {
            available / minimum
        } else {
            0.0
        };
        address = (4.0 * g).min(address_full) * scale;
        gaps = (wide * scale, narrow * scale);
        mnemonic = mnemonic_min * scale;
    }
    let snap = |x: f32| (x * pixels_per_point).round() / pixels_per_point;
    let end = LISTING_INSET + available;
    let mut x = LISTING_INSET;
    let mut cell = |width: f32, gap: f32| {
        let range = egui::Rangef::new(snap(x).min(end), snap(x + width).min(end));
        x += width + gap;
        range
    };
    let address = cell(address, gaps.0);
    let bytes = bytes.map(|width| cell(width, gaps.0));
    let mnemonic = cell(mnemonic, gaps.1);
    let operands = egui::Rangef::new(snap(x).min(end), end);
    ListingColumns {
        address,
        bytes,
        mnemonic,
        operands,
    }
}

/// The text of one Listing row; `callee` and `comment` follow the operands.
pub struct ListingRow<'a> {
    pub address: u64,
    pub address_digits: usize,
    pub bytes: &'a [u8],
    pub mnemonic: &'a str,
    pub operands: &'a str,
    pub callee: Option<&'a str>,
    pub comment: Option<&'a str>,
}

/// Which parts of a painted Listing row lost content to their cells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListingElided {
    pub address: bool,
    pub bytes: bool,
    pub code: bool,
}

/// Paint a Listing row as independent single-line cells, each clipped to its
/// column and ellipsized rather than pushing the next one aside.
pub fn listing_cells(
    ui: &Ui,
    rect: egui::Rect,
    columns: &ListingColumns,
    row: &ListingRow<'_>,
) -> ListingElided {
    let mut elided = ListingElided {
        bytes: row.bytes.len() > LISTING_BYTES
            || (columns.bytes.is_none() && !row.bytes.is_empty()),
        ..Default::default()
    };
    if !ui.is_rect_visible(rect) {
        return elided;
    }
    let slack = 1.0 / ui.pixels_per_point();
    let paint = |range: egui::Rangef, mut job: egui::text::LayoutJob| {
        let cell = egui::Rect::from_x_y_ranges(
            egui::Rangef::new(rect.left() + range.min, rect.left() + range.max),
            rect.y_range(),
        );
        if cell.width() <= 0.0 {
            return !job.text.is_empty();
        }
        job.wrap = egui::text::TextWrapping::truncate_at_width(cell.width());
        let galley = ui.fonts_mut(|fonts| fonts.layout_job(job));
        let truncated = galley.elided;
        ui.painter()
            .with_clip_rect(
                cell.expand2(egui::vec2(slack, 0.0))
                    .intersect(rect)
                    .intersect(ui.clip_rect()),
            )
            .galley(
                egui::pos2(cell.left(), cell.center().y - galley.size().y / 2.0),
                galley,
                TEXT,
            );
        truncated
    };
    let mono =
        |text: String, color| egui::text::LayoutJob::single_section(text, mono_format(color));
    let mut address = format!("{:0digits$x}", row.address, digits = row.address_digits);
    let font = FontId::monospace(13.0);
    // Keep the changing low digits visible when a wide address must shorten.
    let shortened = text_width(ui, &address, &font) > columns.address.span() + slack;
    if shortened {
        let digits = ((columns.address.span() - text_width(ui, "…", &font)) / glyph_width(ui))
            .max(0.0)
            .floor() as usize;
        address = format!("…{}", &address[address.len() - digits.min(address.len())..]);
    }
    let clipped = paint(columns.address, mono(address, ADDRESS));
    elided.address = shortened || clipped;
    if let Some(range) = columns.bytes {
        elided.bytes |= paint(range, mono(listing_bytes(row.bytes), BYTES));
    }
    elided.code = paint(columns.mnemonic, mono(row.mnemonic.to_owned(), MNEMONIC));
    let mut code = mono(row.operands.to_owned(), TEXT);
    if let Some(name) = row.callee {
        code.append(
            &format!("  {name}"),
            0.0,
            egui::TextFormat {
                font_id: FontId::proportional(13.0),
                color: SYNTAX_FUNCTION,
                valign: egui::Align::Center,
                ..Default::default()
            },
        );
    }
    if let Some(comment) = row.comment {
        code.append(&format!("  ; {comment}"), 0.0, mono_format(SYNTAX_COMMENT));
    }
    elided.code |= paint(columns.operands, code);
    elided
}

/// The Listing's column headings, aligned with `listing_cells` and clipped to
/// the same cells.
pub fn paint_listing_header(ui: &Ui, rect: egui::Rect, columns: &ListingColumns) {
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
    let cells = [
        ("Address", Some(columns.address)),
        ("Bytes", columns.bytes),
        ("Mnemonic", Some(columns.mnemonic)),
        ("Operands", Some(columns.operands)),
    ];
    for (title, range) in cells {
        let Some(range) = range else { continue };
        let range = egui::Rangef::new(range.min + rect.left(), range.max + rect.left());
        let cell = egui::Rect::from_x_y_ranges(range, rect.y_range());
        if cell.width() <= 0.0 {
            continue;
        }
        let mut job = egui::text::LayoutJob::simple_singleline(
            title.to_owned(),
            FontId::proportional(12.0),
            MUTED,
        );
        job.wrap = egui::text::TextWrapping::truncate_at_width(cell.width());
        let galley = painter.layout_job(job);
        painter
            .with_clip_rect(cell.intersect(painter.clip_rect()))
            .galley(
                egui::pos2(cell.left(), cell.center().y - galley.size().y / 2.0),
                galley,
                MUTED,
            );
    }
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
                            Some((
                                "Saved",
                                "Saved tree results; recompute each analysis to verify.",
                            )),
                            |_| {},
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
                egui::Shape::Text(text) if text.galley.text() == "»" => {
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
        }
    }

    #[test]
    fn saved_dock_titles_truncate_without_clipping_provenance_or_counts() {
        for scale in [1.0, 1.25] {
            for width in [360.0, 260.0, 180.0, 120.0] {
                for (title, count, partial) in [
                    ("Functions", Some("15"), false),
                    ("Functions", Some("262144"), false),
                    ("Functions", Some("15"), width >= 180.0),
                    ("Decompiler", None, false),
                    ("Function Graph", None, false),
                    ("Hex / Memory Map", None, false),
                ] {
                    let context = egui::Context::default();
                    super::install(&context);
                    context.set_pixels_per_point(scale);
                    let mut title_rect = egui::Rect::NOTHING;
                    let frame = || {
                        let mut output = context.run_ui(
                            egui::RawInput {
                                screen_rect: Some(egui::Rect::from_min_size(
                                    egui::Pos2::ZERO,
                                    egui::vec2(width, 150.0),
                                )),
                                ..Default::default()
                            },
                            |ui| {
                                super::dock_tabs(
                                    ui,
                                    &mut false,
                                    &[(false, title)],
                                    Some(("Saved analysis", "Saved results")),
                                    |ui| {
                                        if title == "Decompiler" {
                                            for label in ["Copy", "Refresh", "Signature…", "Auto"]
                                            {
                                                let _ = ui.small_button(label);
                                            }
                                        }
                                        if let Some(count) = count {
                                            ui.weak(count);
                                        }
                                        if partial {
                                            ui.colored_label(super::WARNING, "Partial");
                                        }
                                    },
                                );
                            },
                        );
                        output.textures_delta.clear();
                        output
                    };
                    frame();
                    let output = frame();
                    let mut saved_rect = egui::Rect::NOTHING;
                    let mut count_rect = None;
                    let mut found_title = false;
                    for shape in &output.shapes {
                        if let egui::Shape::Text(text) = &shape.shape {
                            let label = text.galley.text();
                            let bounds = text.galley.rect.translate(text.pos.to_vec2());
                            if label == title
                                || label == "Saved"
                                || label == "Saved analysis"
                                || Some(label) == count
                                || label == "Partial"
                            {
                                assert!(
                                    shape.clip_rect.contains_rect(bounds),
                                    "{title}, width={width}, scale={scale}, label={label}: {bounds:?}, clip={:?}",
                                    shape.clip_rect
                                );
                            }
                            if label == title {
                                found_title = true;
                                title_rect = bounds;
                                if title == "Functions" {
                                    assert_eq!(text.galley.elided, width <= 120.0);
                                }
                                if text.galley.elided {
                                    assert_eq!(
                                        text.galley.rows.last().unwrap().glyphs.last().unwrap().chr,
                                        '…'
                                    );
                                }
                            } else if label == "Saved" || label == "Saved analysis" {
                                assert!(
                                    text.galley
                                        .job
                                        .sections
                                        .iter()
                                        .all(|section| section.format.color == super::MUTED)
                                );
                                saved_rect = bounds;
                                if title == "Functions" {
                                    let compact = width <= 180.0;
                                    assert_eq!(
                                        label,
                                        if compact { "Saved" } else { "Saved analysis" }
                                    );
                                }
                            } else if Some(label) == count {
                                count_rect = Some(bounds);
                            }
                        }
                    }
                    assert!(found_title && saved_rect.is_positive());
                    assert!(title_rect.right() <= saved_rect.left());
                    assert_eq!(count_rect.is_some(), count.is_some());
                    if let Some(count_rect) = count_rect {
                        assert!(saved_rect.right() <= count_rect.left());
                    }
                }
            }
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
    fn long_encodings_are_bounded_without_changing_cell_geometry() {
        assert_eq!(super::listing_bytes(&[0x66; 15]), "66 66 66 66 66 66 66…");
        assert_eq!(super::address_digits(0x1000), 8);
        assert_eq!(super::address_digits(0x1_4000_1000), 9);
    }
}

#[cfg(test)]
mod narrow_tests;
