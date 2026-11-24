//! The read-only Registers, Stack and Memory tabs of a live debug session.
//!
//! Integration contract, as in `hex_ui`: this module owns no I/O and no
//! session state. The caller passes the data of one stop and dispatches the
//! returned [`LiveAction`]. Static addresses come only from the backend's
//! exact `Location` mapping; nothing here infers one.
use eframe::egui::{self, RichText, TextEdit};

use crate::theme;

/// Bytes the Memory tab reads and shows at once.
pub(crate) const MEMORY_PAGE: u64 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LiveAction {
    /// Open a backend-mapped static address in the Listing, with history.
    GoTo(u64),
    /// Switch to the Memory tab at the page holding a runtime address.
    ShowMemory(u64),
    SelectFrame(usize),
    /// Open a Stack frame that has a destination.
    OpenFrame(usize),
    /// Show the page holding a runtime address.
    MemoryAt(u64),
    /// The address field holds no hexadecimal address.
    InvalidAddress,
}

/// The 16-byte aligned page start for a runtime address.
pub(crate) fn page_start(address: u64) -> u64 {
    address & !(theme::HEX_ROW_BYTES as u64 - 1)
}

/// The length of the page at `start`, short only at the top of the space.
pub(crate) fn page_length(start: u64) -> usize {
    MEMORY_PAGE.min(u64::MAX - start) as usize
}

pub(crate) struct RegisterRow<'a> {
    pub name: &'a str,
    pub value: u64,
    /// Changed since the previous stop of the same session.
    pub changed: bool,
    /// The backend's static address for the value.
    pub static_address: Option<u64>,
    /// The containing function's name and offset, when one is known.
    pub function: Option<String>,
}

pub(crate) struct FrameRow {
    pub runtime: u64,
    pub static_address: Option<u64>,
    /// The function text and whether it is the app's own name rather than
    /// GDB's.
    pub function: Option<(String, bool)>,
    /// Whether the caller has a destination for this frame.
    pub openable: bool,
}

pub(crate) struct MemoryPage<'a> {
    pub runtime: u64,
    pub bytes: Result<&'a [u8], &'a str>,
    /// Read at the current stop; older bytes are muted.
    pub current: bool,
}

pub(crate) struct MemoryView<'a> {
    pub address: Option<u64>,
    pub text: &'a mut String,
    pub rsp: Option<u64>,
    pub rip: Option<u64>,
    pub page: Option<MemoryPage<'a>>,
}

/// Paints `cells` (text, color, left offset) across `rect`.
fn paint_cells(ui: &egui::Ui, rect: egui::Rect, cells: &[(&str, egui::Color32, f32)]) {
    for (index, (text, color, left)) in cells.iter().enumerate() {
        if text.is_empty() {
            continue;
        }
        let right = cells
            .get(index + 1)
            .map_or(rect.width(), |(_, _, right)| *right);
        let cell = egui::Rect::from_x_y_ranges(
            rect.left() + left..=rect.left() + right.max(*left),
            rect.y_range(),
        );
        theme::cell_text(ui, cell, RichText::new(*text).monospace(), *color);
    }
}

pub(crate) fn registers(ui: &mut egui::Ui, rows: &[RegisterRow<'_>]) -> Option<LiveAction> {
    let glyph = theme::glyph_width(ui);
    let columns = [0.0, 10.0 * glyph, 31.0 * glyph];
    // Narrow panes scroll sideways rather than cut values short.
    let width = columns[2] + 32.0 * glyph;
    let header = theme::column_header(ui, &[], 0.0);
    let (action, output) = theme::rows(
        ui,
        "live-registers",
        rows.len(),
        theme::ROW_HEIGHT,
        width,
        None,
        |ui, index, rect| {
            let row = &rows[index];
            let response = theme::row_response(
                ui,
                ui.scope_id().with(("live-register", index)),
                rect,
                false,
                false,
            );
            let value = format!("{:#018x}", row.value);
            let value_color = if row.changed {
                theme::WARNING
            } else {
                theme::TEXT
            };
            let place = match (row.static_address, &row.function) {
                (Some(_), Some(function)) => (function.clone(), theme::TEXT),
                (Some(address), None) => (format!("{address:x}"), theme::MUTED),
                (None, _) => (String::new(), theme::MUTED),
            };
            paint_cells(
                ui,
                rect,
                &[
                    (row.name, theme::MUTED, columns[0]),
                    (&value, value_color, columns[1]),
                    (&place.0, place.1, columns[2]),
                ],
            );
            let mut action = None;
            response.context_menu(|ui| {
                if ui.button("Copy value").clicked() {
                    ui.ctx().copy_text(format!("{:#x}", row.value));
                    ui.close();
                }
                if ui.button("Show in Memory").clicked() {
                    action = Some(LiveAction::ShowMemory(row.value));
                    ui.close();
                }
                if let Some(address) = row.static_address
                    && ui.button("Go to").clicked()
                {
                    action = Some(LiveAction::GoTo(address));
                    ui.close();
                }
            });
            action
        },
    );
    theme::paint_column_header(
        ui,
        header,
        &[("Register", columns[0]), ("Value", columns[1])],
        output.state.clamped_offset().x,
    );
    action
}

/// The Stack table. With `keys`, Enter opens the selected mapped frame.
pub(crate) fn stack(
    ui: &mut egui::Ui,
    rows: &[FrameRow],
    selected: Option<usize>,
    keys: bool,
) -> Option<LiveAction> {
    let glyph = theme::glyph_width(ui);
    let columns = [0.0, 5.0 * glyph, 25.0 * glyph, 43.0 * glyph];
    let header = theme::column_header(ui, &[], 0.0);
    let (action, output) = theme::rows(
        ui,
        "live-stack",
        rows.len(),
        theme::ROW_HEIGHT,
        columns[3] + 32.0 * glyph,
        None,
        |ui, index, rect| {
            let row = &rows[index];
            let response = theme::row_response(
                ui,
                ui.scope_id().with(("live-frame", index)),
                rect,
                selected == Some(index),
                false,
            );
            let number = index.to_string();
            let address = format!("{:#x}", row.runtime);
            let mapped = row
                .static_address
                .map_or_else(String::new, |address| format!("{address:x}"));
            let (function, color) = match &row.function {
                Some((text, true)) => (text.as_str(), theme::TEXT),
                Some((text, false)) => (text.as_str(), theme::MUTED),
                None => ("", theme::MUTED),
            };
            paint_cells(
                ui,
                rect,
                &[
                    (&number, theme::MUTED, columns[0]),
                    (&address, theme::TEXT, columns[1]),
                    (&mapped, theme::TEXT, columns[2]),
                    (function, color, columns[3]),
                ],
            );
            if response.double_clicked() {
                return row.openable.then_some(LiveAction::OpenFrame(index));
            }
            response.clicked().then_some(LiveAction::SelectFrame(index))
        },
    );
    theme::paint_column_header(
        ui,
        header,
        &[
            ("#", columns[0]),
            ("Address", columns[1]),
            ("Static", columns[2]),
            ("Function", columns[3]),
        ],
        output.state.clamped_offset().x,
    );
    if action.is_some() || !keys {
        return action;
    }
    let target = selected.filter(|index| rows.get(*index).is_some_and(|row| row.openable))?;
    let enter = ui.input_mut(|input| {
        let index = input.events.iter().position(|event| {
            matches!(
                event,
                egui::Event::Key {
                    key: egui::Key::Enter,
                    pressed: true,
                    repeat: false,
                    modifiers,
                    ..
                } if modifiers.is_none()
            )
        });
        index.map(|index| input.events.remove(index)).is_some()
    });
    enter.then_some(LiveAction::OpenFrame(target))
}

pub(crate) fn memory(ui: &mut egui::Ui, view: MemoryView<'_>) -> Option<LiveAction> {
    let mut action = None;
    // Wraps in narrow panes so every control stays reachable.
    ui.horizontal_wrapped(|ui| {
        let previous = view
            .address
            .filter(|start| *start > 0)
            .map(|start| start.saturating_sub(MEMORY_PAGE));
        let next = view
            .address
            .and_then(|start| start.checked_add(MEMORY_PAGE))
            .filter(|next| page_length(*next) > 0);
        for (label, target) in [("Prev", previous), ("Next", next)] {
            if ui
                .add_enabled(target.is_some(), egui::Button::new(label))
                .clicked()
            {
                action = target.map(LiveAction::MemoryAt);
            }
        }
        let edit = ui.add(
            TextEdit::singleline(view.text)
                .font(egui::TextStyle::Monospace)
                .desired_width(154.0_f32.min(ui.max_rect().width() - 8.0).max(48.0))
                .char_limit(18)
                .hint_text("Address"),
        );
        if edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
            action = Some(match parse_address(view.text) {
                Some(address) => LiveAction::MemoryAt(address),
                None => LiveAction::InvalidAddress,
            });
        }
        for (label, value) in [("rsp", view.rsp), ("rip", view.rip)] {
            if ui
                .add_enabled(value.is_some(), egui::Button::new(label))
                .clicked()
            {
                action = value.map(LiveAction::MemoryAt);
            }
        }
    });
    let Some(page) = view.page else {
        return action;
    };
    let bytes = match page.bytes {
        Ok(bytes) => bytes,
        Err(message) => {
            theme::empty_state_hover(ui, "Unreadable", Some(message));
            return action;
        }
    };
    let color = if page.current {
        theme::TEXT
    } else {
        theme::MUTED
    };
    let width = theme::hex_row_width(theme::glyph_width(ui));
    // Each page starts at its top.
    theme::rows(
        ui,
        ("live-memory", page.runtime),
        bytes.len().div_ceil(theme::HEX_ROW_BYTES),
        theme::ROW_HEIGHT,
        width,
        None,
        |ui, row, rect| {
            let start = row * theme::HEX_ROW_BYTES;
            let end = (start + theme::HEX_ROW_BYTES).min(bytes.len());
            let address = page.runtime.checked_add(start as u64)?;
            theme::paint_hex_row(ui, rect, address, &bytes[start..end], color);
            None::<()>
        },
    );
    action
}

fn parse_address(text: &str) -> Option<u64> {
    let text = text.trim();
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(text, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `show` in a `width`-point pane at 1.25 pixels per point and
    /// returns each drawn text with its rect, clip rect and elision.
    fn narrow(
        width: f32,
        show: impl FnMut(&mut egui::Ui),
    ) -> Vec<(String, egui::Rect, egui::Rect, bool)> {
        let context = egui::Context::default();
        theme::install(&context);
        context.set_pixels_per_point(1.25);
        let mut show = show;
        let mut output = egui::FullOutput::default();
        // A second pass settles layout sizes.
        for _ in 0..2 {
            output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 400.0),
                    )),
                    ..Default::default()
                },
                |ui| show(ui),
            );
            output.textures_delta.clear();
        }
        output
            .shapes
            .iter()
            .filter_map(|clipped| match &clipped.shape {
                egui::Shape::Text(text) => Some((
                    text.galley.text().to_owned(),
                    text.galley.rect.translate(text.pos.to_vec2()),
                    clipped.clip_rect,
                    text.galley.elided,
                )),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn narrow_panes_keep_memory_controls_reachable_and_values_whole() {
        for width in [160.0, 260.0] {
            let mut text = String::from("7fffffffe000");
            let texts = narrow(width, |ui| {
                memory(
                    ui,
                    MemoryView {
                        address: Some(0x7fff_ffff_e000),
                        text: &mut text,
                        rsp: Some(0x7fff_ffff_e128),
                        rip: Some(0x5555_5555_5139),
                        page: None,
                    },
                );
            });
            for label in ["Prev", "Next", "rsp", "rip"] {
                let (_, rect, clip, _) = texts
                    .iter()
                    .find(|(text, ..)| text == label)
                    .unwrap_or_else(|| panic!("{label} at {width}"));
                assert!(
                    clip.contains_rect(*rect) && rect.right() <= width,
                    "{label} at {width}"
                );
            }
            let rows = [RegisterRow {
                name: "rsp",
                value: 0x7fff_ffff_e128,
                changed: false,
                static_address: None,
                function: None,
            }];
            let texts = narrow(width, |ui| {
                registers(ui, &rows);
            });
            let value = texts
                .iter()
                .find(|(text, ..)| text == "0x00007fffffffe128")
                .expect("value drawn");
            assert!(!value.3, "the value is not cut short at {width}");
        }
    }

    #[test]
    fn pages_are_aligned_and_never_cross_the_top_of_the_address_space() {
        assert_eq!(page_start(0x7fff_ffff_e12f), 0x7fff_ffff_e120);
        assert_eq!(page_length(0x1000), 1024);
        let top = page_start(u64::MAX);
        assert_eq!(page_length(top), 15);
        assert!(top.checked_add(page_length(top) as u64).is_some());
        assert_eq!(parse_address(" 0X1f "), Some(0x1f));
        assert_eq!(parse_address("rsp"), None);
        assert_eq!(parse_address(""), None);
    }
}
