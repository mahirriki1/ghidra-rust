//! Windows window controls share the menu row instead of adding a second title bar.

use eframe::egui;

/// Other desktops retain their native decorations and window-manager behavior.
pub fn configure_viewport(viewport: egui::ViewportBuilder) -> egui::ViewportBuilder {
    if cfg!(windows) {
        viewport.with_decorations(false)
    } else {
        viewport
    }
}

/// Call after the application menus. Only the remaining empty space is draggable.
pub fn menu_bar_controls(ui: &mut egui::Ui) {
    #[cfg(windows)]
    controls(ui);
    #[cfg(not(windows))]
    let _ = ui;
}

/// Call from the root UI after its panels so borderless windows remain resizable.
pub fn resize_borders(ui: &mut egui::Ui) {
    #[cfg(windows)]
    resize_edges(ui);
    #[cfg(not(windows))]
    let _ = ui;
}

#[cfg(any(windows, test))]
fn controls(ui: &mut egui::Ui) -> [egui::Rect; 4] {
    // Reserve precisely one menu-row height. The remaining viewport height is
    // available here too, so using available_size() directly would grow the bar.
    let height = ui.spacing().interact_size.y;
    let (area, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::hover(),
    );
    let button_width = 36.0_f32.min(area.width() / 3.0);
    let drag_rect = egui::Rect::from_min_max(
        area.min,
        egui::pos2(area.right() - button_width * 3.0, area.bottom()),
    );
    let drag = ui.interact(
        drag_rect,
        ui.scope_id().with("window_drag"),
        egui::Sense::click_and_drag(),
    );
    let maximized = ui
        .ctx()
        .input(|input| input.viewport().maximized == Some(true));
    if drag.double_clicked_by(egui::PointerButton::Primary) {
        ui.ctx()
            .send_viewport_cmd(egui::ViewportCommand::Maximized(!maximized));
    } else if drag.drag_started_by(egui::PointerButton::Primary) {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    drag.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Label, ui.is_enabled(), "Window drag area")
    });
    let mut rects = [drag_rect; 4];
    for (index, action) in [Action::Minimize, Action::Maximize, Action::Close]
        .into_iter()
        .enumerate()
    {
        let rect = egui::Rect::from_min_size(
            egui::pos2(drag_rect.right() + index as f32 * button_width, area.top()),
            egui::vec2(button_width, height),
        );
        let response = control_button(ui, action, maximized, rect);
        if response.clicked() {
            ui.ctx().send_viewport_cmd(action.command(maximized));
        }
        rects[index + 1] = rect;
    }
    rects
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy)]
enum Action {
    Minimize,
    Maximize,
    Close,
}

#[cfg(any(windows, test))]
impl Action {
    fn command(self, maximized: bool) -> egui::ViewportCommand {
        match self {
            Self::Minimize => egui::ViewportCommand::Minimized(true),
            Self::Maximize => egui::ViewportCommand::Maximized(!maximized),
            // Let DesktopApp's existing close-request handler protect unsaved work.
            Self::Close => egui::ViewportCommand::Close,
        }
    }

    fn label(self, maximized: bool) -> &'static str {
        match self {
            Self::Minimize => "Minimize",
            Self::Maximize if maximized => "Restore window",
            Self::Maximize => "Maximize",
            Self::Close => "Close window",
        }
    }
}

#[cfg(any(windows, test))]
fn control_button(
    ui: &mut egui::Ui,
    action: Action,
    maximized: bool,
    rect: egui::Rect,
) -> egui::Response {
    let label = action.label(maximized);
    let response = ui.interact(rect, ui.scope_id().with(label), egui::Sense::click());
    response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Button, ui.is_enabled(), label));
    if ui.is_rect_visible(rect) {
        let visuals = ui.style().interact(&response);
        if response.hovered() || response.is_pointer_button_down_on() {
            let fill = if matches!(action, Action::Close) {
                egui::Color32::from_rgb(180, 40, 40)
            } else {
                visuals.bg_fill
            };
            ui.painter().rect_filled(rect, 0, fill);
        }
        let stroke = egui::Stroke::new(1.2, visuals.fg_stroke.color);
        let center = rect.center();
        let icon = egui::Rect::from_center_size(center, egui::vec2(10.0, 10.0));
        match action {
            Action::Minimize => {
                ui.painter().line_segment(
                    [center - egui::vec2(5.0, 0.0), center + egui::vec2(5.0, 0.0)],
                    stroke,
                );
            }
            Action::Maximize => {
                if maximized {
                    let front = icon.translate(egui::vec2(-1.5, 1.5));
                    let back = icon.translate(egui::vec2(1.5, -1.5));
                    ui.painter()
                        .line_segment([back.left_top(), back.right_top()], stroke);
                    ui.painter()
                        .line_segment([back.right_top(), back.right_bottom()], stroke);
                    ui.painter()
                        .line_segment([back.left_top(), front.left_top()], stroke);
                    ui.painter()
                        .line_segment([front.right_bottom(), back.right_bottom()], stroke);
                    ui.painter()
                        .rect_stroke(front, 0, stroke, egui::StrokeKind::Inside);
                } else {
                    ui.painter()
                        .rect_stroke(icon, 0, stroke, egui::StrokeKind::Inside);
                }
            }
            Action::Close => {
                ui.painter()
                    .line_segment([icon.left_top(), icon.right_bottom()], stroke);
                ui.painter()
                    .line_segment([icon.right_top(), icon.left_bottom()], stroke);
            }
        }
    }
    response.on_hover_text(label)
}

#[cfg(any(windows, test))]
fn resize_edges(ui: &mut egui::Ui) {
    if ui.ctx().input(|input| {
        input.viewport().maximized == Some(true) || input.viewport().fullscreen == Some(true)
    }) {
        return;
    }
    let outer = ui.ctx().viewport_rect();
    let side = 4.0;
    let corner = 10.0;
    use egui::viewport::ResizeDirection as D;
    let edges = [
        (
            D::NorthWest,
            egui::Rect::from_min_size(outer.min, egui::vec2(corner, corner)),
            egui::CursorIcon::ResizeNwSe,
        ),
        (
            D::NorthEast,
            egui::Rect::from_min_size(
                outer.right_top() - egui::vec2(corner, 0.0),
                egui::vec2(corner, corner),
            ),
            egui::CursorIcon::ResizeNeSw,
        ),
        (
            D::SouthWest,
            egui::Rect::from_min_size(
                outer.left_bottom() - egui::vec2(0.0, corner),
                egui::vec2(corner, corner),
            ),
            egui::CursorIcon::ResizeNeSw,
        ),
        (
            D::SouthEast,
            egui::Rect::from_min_size(
                outer.max - egui::vec2(corner, corner),
                egui::vec2(corner, corner),
            ),
            egui::CursorIcon::ResizeNwSe,
        ),
        (
            D::North,
            egui::Rect::from_min_max(
                outer.min + egui::vec2(corner, 0.0),
                outer.right_top() + egui::vec2(-corner, side),
            ),
            egui::CursorIcon::ResizeVertical,
        ),
        (
            D::South,
            egui::Rect::from_min_max(
                outer.left_bottom() + egui::vec2(corner, -side),
                outer.max - egui::vec2(corner, 0.0),
            ),
            egui::CursorIcon::ResizeVertical,
        ),
        (
            D::West,
            egui::Rect::from_min_max(
                outer.min + egui::vec2(0.0, corner),
                outer.left_bottom() + egui::vec2(side, -corner),
            ),
            egui::CursorIcon::ResizeHorizontal,
        ),
        (
            D::East,
            egui::Rect::from_min_max(
                outer.right_top() + egui::vec2(-side, corner),
                outer.max - egui::vec2(0.0, corner),
            ),
            egui::CursorIcon::ResizeHorizontal,
        ),
    ];
    for (index, (direction, rect, cursor)) in edges.into_iter().enumerate() {
        let response = ui.interact(
            rect,
            ui.scope_id().with(("native_resize", index)),
            egui::Sense::drag(),
        );
        if response.hovered() || response.dragged() {
            ui.ctx().set_cursor_icon(cursor);
        }
        if response.drag_started_by(egui::PointerButton::Primary) {
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::BeginResize(direction));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Desktop {
        context: egui::Context,
        menu: egui::Rect,
        controls: [egui::Rect; 4],
        menu_clicked: bool,
        maximized: bool,
        time: f64,
    }

    impl Default for Desktop {
        fn default() -> Self {
            Self {
                context: egui::Context::default(),
                menu: egui::Rect::NOTHING,
                controls: [egui::Rect::NOTHING; 4],
                menu_clicked: false,
                maximized: false,
                time: 0.0,
            }
        }
    }

    impl Desktop {
        fn frame(&mut self, events: Vec<egui::Event>) -> Vec<egui::ViewportCommand> {
            let mut input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 640.0),
                )),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            self.time += 1.0 / 60.0;
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .maximized = Some(self.maximized);
            let mut output = self.context.run_ui(input, |root| {
                egui::Panel::top("menu").show(root, |ui| {
                    egui::MenuBar::new().ui(ui, |ui| {
                        let response = ui.button("File");
                        self.menu = response.rect;
                        self.menu_clicked |= response.clicked();
                        self.controls = controls(ui);
                    });
                });
                resize_edges(root);
            });
            output.textures_delta.clear();
            output
                .viewport_output
                .remove(&egui::ViewportId::ROOT)
                .unwrap()
                .commands
        }

        fn click(&mut self, position: egui::Pos2) -> Vec<egui::ViewportCommand> {
            self.frame(vec![
                egui::Event::PointerMoved(position),
                button(position, true),
                button(position, false),
            ])
        }

        fn warm_up(&mut self) {
            self.frame(Vec::new());
            self.frame(Vec::new());
        }
    }

    fn button(pos: egui::Pos2, pressed: bool) -> egui::Event {
        egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        }
    }

    #[test]
    fn controls_align_right_without_growing_or_intercepting_the_menu() {
        let mut desktop = Desktop::default();
        desktop.warm_up();
        assert!(desktop.controls[0].left() > desktop.menu.right());
        assert!(desktop.controls[3].right() > 980.0);
        assert!(desktop.controls[3].bottom() < 40.0);
        assert!(desktop.click(desktop.menu.center()).is_empty());
        assert!(desktop.menu_clicked);
    }

    #[test]
    fn pointer_controls_emit_minimize_maximize_restore_and_close() {
        for (index, maximized, expected) in [
            (1, false, egui::ViewportCommand::Minimized(true)),
            (2, false, egui::ViewportCommand::Maximized(true)),
            (2, true, egui::ViewportCommand::Maximized(false)),
            (3, false, egui::ViewportCommand::Close),
        ] {
            let mut desktop = Desktop {
                maximized,
                ..Default::default()
            };
            desktop.warm_up();
            assert_eq!(
                desktop.click(desktop.controls[index].center()),
                vec![expected]
            );
            assert!(!desktop.menu_clicked);
        }
    }

    #[test]
    fn blank_menu_space_supports_drag_and_double_click() {
        let mut desktop = Desktop::default();
        desktop.warm_up();
        let point = desktop.controls[0].center();
        assert!(desktop.click(point).is_empty());
        assert_eq!(
            desktop.click(point),
            vec![egui::ViewportCommand::Maximized(true)]
        );

        let mut desktop = Desktop::default();
        desktop.warm_up();
        let point = desktop.controls[0].center();
        desktop.frame(vec![egui::Event::PointerMoved(point), button(point, true)]);
        let output = desktop.frame(vec![egui::Event::PointerMoved(
            point + egui::vec2(20.0, 0.0),
        )]);
        assert_eq!(output, vec![egui::ViewportCommand::StartDrag]);
    }

    #[test]
    fn resize_edges_start_native_resize_but_are_disabled_when_maximized() {
        for maximized in [false, true] {
            let mut desktop = Desktop {
                maximized,
                ..Default::default()
            };
            desktop.warm_up();
            let point = egui::pos2(999.0, 320.0);
            let mut output =
                desktop.frame(vec![egui::Event::PointerMoved(point), button(point, true)]);
            output.extend(desktop.frame(vec![egui::Event::PointerMoved(
                point - egui::vec2(12.0, 0.0),
            )]));
            if maximized {
                assert!(output.is_empty());
            } else {
                assert_eq!(
                    output,
                    vec![egui::ViewportCommand::BeginResize(
                        egui::viewport::ResizeDirection::East
                    )]
                );
            }
        }
    }
}
