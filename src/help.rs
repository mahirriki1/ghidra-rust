//! Compact Help dialogs and the shared shortcut reference.
use crate::theme;
use eframe::egui::{self, RichText};

/// Display catalog, also available to future command/navigation surfaces.
pub(crate) const SHORTCUTS: &[(&str, &str)] = &[
    ("F1", "Keyboard shortcuts"),
    ("L", "Rename function / label / local"),
    ("G", "Go to address or name"),
    (";", "Edit comment"),
    ("X", "Xrefs to selection"),
    ("Space", "Toggle Listing / Graph"),
    ("Alt+Left / Right", "Back / forward"),
    (SAVE_KEYS, "Save project"),
    (UNDO_KEYS, "Undo annotation"),
];

#[cfg(target_os = "macos")]
const SAVE_KEYS: &str = "Cmd+S";
#[cfg(not(target_os = "macos"))]
const SAVE_KEYS: &str = "Ctrl+S";
#[cfg(target_os = "macos")]
const UNDO_KEYS: &str = "Cmd+Z";
#[cfg(not(target_os = "macos"))]
const UNDO_KEYS: &str = "Ctrl+Z";
const ABOUT_SCOPE: &str = "Experimental x86 / x86-64 / AArch64 reverse engineering.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HelpDialog {
    Shortcuts,
    About,
}

impl HelpDialog {
    /// Returns whether the dialog should stay open. Modal owns Escape/focus,
    /// just like the existing browser and analysis dialogs.
    pub fn show(self, context: &egui::Context) -> bool {
        let modal = egui::Modal::new(egui::Id::unique("help-dialog")).show(context, |ui| {
            let (key_width, width) = match self {
                Self::Shortcuts => shortcut_dimensions(ui),
                Self::About => (0.0, text_width(ui, ABOUT_SCOPE)),
            };
            ui.set_width(width);
            let mut close = false;
            ui.horizontal(|ui| {
                if self == Self::About {
                    theme::brand_mark(ui);
                }
                ui.heading(match self {
                    Self::Shortcuts => "Keyboard shortcuts",
                    Self::About => "About Ghidra Rust",
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    close = ui.button("×").on_hover_text("Close (Escape)").clicked();
                });
            });
            ui.separator();
            match self {
                Self::Shortcuts => {
                    shortcut_table(ui, key_width);
                    ui.weak("Shortcuts pause while typing or in dialogs.");
                }
                Self::About => {
                    ui.label(concat!("Version ", env!("CARGO_PKG_VERSION")));
                    ui.label(ABOUT_SCOPE);
                    ui.horizontal(|ui| {
                        ui.hyperlink_to(
                            "LICENSE",
                            "https://github.com/mahirriki1/ghidra-rust/blob/main/LICENSE",
                        );
                        ui.hyperlink_to(
                            "NOTICE",
                            "https://github.com/mahirriki1/ghidra-rust/blob/main/NOTICE",
                        )
                        .on_hover_text("Ghidra and third-party attribution");
                    });
                }
            }
            close
        });
        !(modal.inner || modal.should_close())
    }
}

fn text_width(ui: &egui::Ui, text: &str) -> f32 {
    egui::WidgetText::from(text)
        .into_galley(
            ui,
            Some(egui::TextWrapMode::Extend),
            f32::INFINITY,
            egui::TextStyle::Body,
        )
        .size()
        .x
}

fn shortcut_dimensions(ui: &egui::Ui) -> (f32, f32) {
    let padding = ui.spacing().button_padding.x * 2.0;
    let key_width = SHORTCUTS
        .iter()
        .map(|(keys, _)| keys.len())
        .max()
        .unwrap_or_default() as f32
        * theme::glyph_width(ui)
        + padding;
    let action_width = SHORTCUTS
        .iter()
        .map(|(_, action)| text_width(ui, action))
        .fold(0.0_f32, f32::max)
        + padding;
    (key_width, key_width + action_width)
}

fn shortcut_table(ui: &mut egui::Ui, key_width: f32) {
    theme::column_header(ui, &[("Shortcut", 0.0), ("Action", key_width)], 0.0);
    let (body, _) = ui.allocate_exact_size(
        egui::vec2(
            ui.available_width(),
            theme::ROW_HEIGHT * SHORTCUTS.len() as f32,
        ),
        egui::Sense::hover(),
    );
    for (index, (keys, action)) in SHORTCUTS.iter().enumerate() {
        let row = egui::Rect::from_min_size(
            body.min + egui::vec2(0.0, index as f32 * theme::ROW_HEIGHT),
            egui::vec2(body.width(), theme::ROW_HEIGHT),
        );
        let (key_cell, action_cell) = row.split_left_right_at_x(row.left() + key_width);
        theme::cell_text(ui, key_cell, *keys, theme::TEXT);
        theme::cell_text(
            ui,
            action_cell,
            RichText::new(*action).text_style(egui::TextStyle::Body),
            theme::TEXT,
        );
    }
}
