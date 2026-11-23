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
    theme::column_header(ui, &[("Register", columns[0]), ("Value", columns[1])], 0.0);
    theme::rows(
        ui,
        "live-registers",
        rows.len(),
        theme::ROW_HEIGHT,
        0.0,
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
    )
    .0
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
    theme::column_header(
        ui,
        &[
            ("#", columns[0]),
            ("Address", columns[1]),
            ("Static", columns[2]),
            ("Function", columns[3]),
        ],
        0.0,
    );
    let (action, _) = theme::rows(
        ui,
        "live-stack",
        rows.len(),
        theme::ROW_HEIGHT,
        0.0,
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
                return row.static_address.map(LiveAction::GoTo);
            }
            response.clicked().then_some(LiveAction::SelectFrame(index))
        },
    );
    if action.is_some() || !keys {
        return action;
    }
    let target = selected
        .and_then(|index| rows.get(index))
        .and_then(|row| row.static_address)?;
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
    enter.then_some(LiveAction::GoTo(target))
}

pub(crate) fn memory(ui: &mut egui::Ui, view: MemoryView<'_>) -> Option<LiveAction> {
    let mut action = None;
    ui.horizontal(|ui| {
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
                .desired_width(154.0)
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
    theme::rows(
        ui,
        "live-memory",
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
