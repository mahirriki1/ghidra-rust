//! Search dialogs and the central Search result table. Rendering only: the
//! desktop owns scheduling, bindings and navigation.
use eframe::egui::{self, RichText};

use crate::linkage::Linkage;
use crate::linkage_ui::{LinkageItem, Place};
use crate::model::{MAX_SEARCH_PATTERN_BYTES, SectionInfo};
use crate::search::{MemoryPattern, MemorySearchSpec, SearchState};
use crate::search_jobs::{MemoryMode, ResultTable, SearchKind, SearchView};
use crate::search_text::{
    SourceStatus, TextProvenance, TextSearchSpec, TextSourceKey, TextSources, VARIANT_DISPLAY,
    VARIANT_INVENTORY, VARIANT_RAW,
};
use crate::theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DialogKind {
    Memory,
    Text,
}

/// An open search modal, bound to the binary generation it was opened for.
pub(crate) struct SearchDialog {
    pub kind: DialogKind,
    pub generation: u64,
    focus: bool,
}

impl SearchDialog {
    pub fn new(kind: DialogKind, generation: u64) -> Self {
        Self {
            kind,
            generation,
            focus: true,
        }
    }
}

/// The last submitted or edited dialog values, kept until the binary closes.
pub(crate) struct SearchForm {
    pub memory_query: String,
    pub memory_mode: MemoryMode,
    pub memory_case: bool,
    pub text_query: String,
    pub text_case: bool,
    pub text_sources: TextSources,
}

impl Default for SearchForm {
    fn default() -> Self {
        Self {
            memory_query: String::new(),
            memory_mode: MemoryMode::Hex,
            memory_case: false,
            text_query: String::new(),
            text_case: false,
            text_sources: TextSources::ALL,
        }
    }
}

const SOURCES: [(TextSources, &str); 6] = [
    (TextSources::NAMES, "Names"),
    (TextSources::IMPORTS, "Imports"),
    (TextSources::EXPORTS, "Exports"),
    (TextSources::LABELS, "Labels"),
    (TextSources::COMMENTS, "Comments"),
    (TextSources::STRINGS, "Strings"),
];

impl SearchForm {
    pub fn memory_spec(&self) -> Result<MemorySearchSpec, String> {
        let text = self.memory_query.clone();
        let spec = match self.memory_mode {
            MemoryMode::Hex => return MemorySearchSpec::hex(&self.memory_query),
            MemoryMode::Ascii => MemorySearchSpec {
                pattern: MemoryPattern::Ascii { text },
                match_case: self.memory_case,
            },
            MemoryMode::Utf16Le => MemorySearchSpec {
                pattern: MemoryPattern::Utf16Le { text },
                match_case: self.memory_case,
            },
        };
        spec.compile()?;
        Ok(spec)
    }

    pub fn text_spec(&self) -> Result<TextSearchSpec, String> {
        let spec = TextSearchSpec {
            query: self.text_query.clone(),
            match_case: self.text_case,
            sources: self.text_sources,
        };
        spec.validate()?;
        Ok(spec)
    }
}

pub(crate) enum Submit {
    Memory(MemorySearchSpec, MemoryMode),
    Text(TextSearchSpec),
}

pub(crate) enum DialogResult {
    Open,
    Close,
    Submit(Submit),
}

/// Shows the modal. Escape, the backdrop and Cancel close it; Search and
/// Enter submit only a valid query.
pub(crate) fn show_dialog(
    context: &egui::Context,
    dialog: &mut SearchDialog,
    form: &mut SearchForm,
) -> DialogResult {
    let mut submit = false;
    let mut cancel = false;
    let modal = egui::Modal::new(egui::Id::unique("search-dialog")).show(context, |ui| {
        ui.set_width(420.0);
        match dialog.kind {
            DialogKind::Memory => {
                ui.heading("Search Memory");
            }
            DialogKind::Text => {
                ui.heading("Search Program Text")
                    .on_hover_text("Loaded text");
            }
        }
        let (validity, field) = match dialog.kind {
            DialogKind::Memory => {
                ui.horizontal(|ui| {
                    for mode in [MemoryMode::Hex, MemoryMode::Ascii, MemoryMode::Utf16Le] {
                        ui.selectable_value(&mut form.memory_mode, mode, mode.label());
                    }
                });
                let hex = form.memory_mode == MemoryMode::Hex;
                let mut edit = egui::TextEdit::singleline(&mut form.memory_query)
                    .id(egui::Id::unique("search-memory-query"))
                    .char_limit(if hex {
                        3 * MAX_SEARCH_PATTERN_BYTES
                    } else {
                        MAX_SEARCH_PATTERN_BYTES
                    })
                    .desired_width(f32::INFINITY);
                if hex {
                    edit = edit
                        .font(egui::TextStyle::Monospace)
                        .hint_text("4D 5A ?? 00");
                }
                let output = edit.show(ui);
                ui.add_enabled_ui(!hex, |ui| {
                    case_box(ui, &mut form.memory_case);
                });
                (form.memory_spec().map(|_| ()), output)
            }
            DialogKind::Text => {
                let output = egui::TextEdit::singleline(&mut form.text_query)
                    .id(egui::Id::unique("search-text-query"))
                    .char_limit(MAX_SEARCH_PATTERN_BYTES)
                    .desired_width(f32::INFINITY)
                    .show(ui);
                case_box(ui, &mut form.text_case);
                egui::Grid::new("search-text-sources")
                    .num_columns(3)
                    .show(ui, |ui| {
                        for (index, (source, label)) in SOURCES.iter().enumerate() {
                            let mut on = form.text_sources.contains(*source);
                            if ui.checkbox(&mut on, *label).changed() {
                                form.text_sources.0 ^= source.0;
                            }
                            if index % 3 == 2 {
                                ui.end_row();
                            }
                        }
                    });
                (form.text_spec().map(|_| ()), output)
            }
        };
        let empty = match dialog.kind {
            DialogKind::Memory => form.memory_query.trim().is_empty(),
            DialogKind::Text => form.text_query.is_empty(),
        };
        if let (Err(error), false) = (&validity, empty) {
            // Over the field's own (focus) border, so it reads as invalid.
            ui.painter().rect_stroke(
                field.response.rect,
                2,
                egui::Stroke::new(1.5, theme::ERROR),
                egui::StrokeKind::Inside,
            );
            egui::Response::clone(&field.response).on_hover_text(error);
        }
        if dialog.focus {
            let mut field = field;
            field.response.request_focus();
            field
                .state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::select_all(&field.galley)));
            field.state.store(context, field.response.id);
            dialog.focus = false;
        }
        let valid = validity.is_ok();
        submit |= valid && context.input(|input| input.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            let search = ui.add_enabled(valid, egui::Button::new("Search"));
            if let Err(error) = &validity
                && !empty
            {
                search.clone().on_disabled_hover_text(error);
            }
            submit |= search.clicked();
            cancel |= ui.button("Cancel").clicked();
        });
    });
    if cancel || modal.should_close() {
        return DialogResult::Close;
    }
    if !submit {
        return DialogResult::Open;
    }
    match dialog.kind {
        DialogKind::Memory => form
            .memory_spec()
            .map(|spec| DialogResult::Submit(Submit::Memory(spec, form.memory_mode))),
        DialogKind::Text => form
            .text_spec()
            .map(|spec| DialogResult::Submit(Submit::Text(spec))),
    }
    .unwrap_or(DialogResult::Open)
}

fn case_box(ui: &mut egui::Ui, value: &mut bool) {
    let response = ui.checkbox(value, "Match case");
    if !*value {
        response.on_hover_text("ASCII case folding");
    }
}

/// What a result-table interaction asks the desktop to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResultAction {
    Open(usize),
    /// An explicit import location chosen from a row's menu.
    OpenPlace(usize, LinkageItem, Place),
    Cancel,
    Edit(DialogKind),
}

/// Read-only facts the table needs besides the search itself.
pub(crate) struct ResultContext<'a> {
    pub sections: &'a [SectionInfo],
    /// The adopted table when it is still the one a text search captured.
    pub linkage: Option<&'a Linkage>,
    pub pointer: u64,
    /// Whether a row currently has an exact destination.
    pub openable: &'a dyn Fn(usize) -> bool,
}

pub(crate) fn state_label(state: SearchState) -> (&'static str, egui::Color32) {
    match state {
        SearchState::Searching => ("Searching", theme::MUTED),
        SearchState::Complete => ("Complete", theme::MUTED),
        SearchState::Partial => ("Partial", theme::WARNING),
        SearchState::Canceled => ("Canceled", theme::MUTED),
        SearchState::Stale => ("Stale", theme::WARNING),
        SearchState::Unavailable => ("Unavailable", theme::ERROR),
    }
}

/// A terse explanation of a non-complete state, for its tooltip.
fn state_hover(view: &SearchView) -> Option<String> {
    let state = view.state();
    match (&view.kind, state) {
        (_, SearchState::Stale) => Some("Sources changed".into()),
        (SearchKind::Memory(_), SearchState::Partial) => Some("Result or scan limit".into()),
        (SearchKind::Text(text), SearchState::Partial | SearchState::Complete) => {
            let notes: Vec<String> = SOURCES
                .iter()
                .zip(text.sources().unwrap_or([SourceStatus::Available; 6]))
                .filter(|((source, _), status)| {
                    text.spec.sources.contains(*source) && *status != SourceStatus::Available
                })
                .map(|((_, label), status)| {
                    format!(
                        "{label} {}",
                        if status == SourceStatus::Partial {
                            "partial"
                        } else {
                            "unavailable"
                        }
                    )
                })
                .collect();
            if notes.is_empty() {
                (state == SearchState::Partial).then(|| "Result or text limit".into())
            } else {
                Some(notes.join(" · "))
            }
        }
        _ => None,
    }
}

fn kind_label(key: TextSourceKey) -> &'static str {
    match key {
        TextSourceKey::Name(_) => "Name",
        TextSourceKey::Import(_) => "Import",
        TextSourceKey::Export(_) => "Export",
        TextSourceKey::Label(_) => "Label",
        TextSourceKey::Comment(_) => "Comment",
        TextSourceKey::String(_) => "String",
    }
}

fn linkage_item(key: TextSourceKey) -> Option<LinkageItem> {
    match key {
        TextSourceKey::Import(id) => Some(LinkageItem::Import(id)),
        TextSourceKey::Export(id) => Some(LinkageItem::Export(id)),
        _ => None,
    }
}

/// Body-font text, like the neighbouring tree and list rows.
fn body(text: impl Into<String>) -> RichText {
    RichText::new(text).text_style(egui::TextStyle::Body)
}

/// Column offsets from the pane width and the code font; never from the
/// longest result, so hostile text cannot widen the table. Returns the
/// optional middle column's offset and the last column's offset.
fn columns(ui: &egui::Ui, digits: usize, middle: f32) -> (Option<f32>, f32) {
    let glyph = theme::glyph_width(ui);
    let width = ui.available_width();
    let address = ((digits + 2) as f32 * glyph).min(width * 0.4);
    let room = (middle * glyph).min((width - address) * 0.35);
    // A middle column must fit its heading and leave the last column room.
    if room >= 8.0 * glyph {
        (Some(address), address + room)
    } else {
        (None, address)
    }
}

/// The Search tab: a compact header and a virtualized result table.
pub(crate) fn show_results(
    ui: &mut egui::Ui,
    view: &SearchView,
    table: &mut ResultTable,
    context: &ResultContext<'_>,
) -> Option<ResultAction> {
    let mut action = None;
    header(ui, view, &mut action);
    let digits = theme::address_digits(
        context
            .sections
            .iter()
            .map(|s| s.address.saturating_add(s.size))
            .max()
            .unwrap_or(0),
    );
    let (memory, middle_title, last_title) = match view.kind {
        SearchKind::Memory(_) => (true, "Section", "Match"),
        SearchKind::Text(_) => (false, "Kind", "Text"),
    };
    let (middle_x, last_x) = columns(ui, digits, if memory { 12.0 } else { 9.0 });
    let mut titles = vec![("Address", 0.0)];
    if let Some(x) = middle_x {
        titles.push((middle_title, x));
    }
    titles.push((last_title, last_x));
    theme::column_header(ui, &titles, 0.0);
    let selected = table.selected;
    let id = view.id;
    let count = view.count();
    let mut clicked = None;
    let (_, output) = theme::rows::<()>(
        ui,
        ("search-results", id),
        count,
        theme::ROW_HEIGHT,
        0.0,
        None,
        |ui, index, rect| {
            let response = theme::row_response(
                ui,
                ui.scope_id().with(("search-row", id, index)),
                rect,
                selected == Some(index),
                false,
            );
            let cell = |left: f32, right: Option<f32>| {
                egui::Rect::from_x_y_ranges(
                    rect.left() + left..=right.map_or(rect.right(), |x| rect.left() + x),
                    rect.y_range(),
                )
            };
            let middle_end = Some(last_x);
            let address_end = Some(middle_x.unwrap_or(last_x));
            let mut item = None;
            let response = match &view.kind {
                SearchKind::Memory(search) => {
                    let hit = search.hits()[index];
                    theme::cell_text(
                        ui,
                        cell(0.0, address_end),
                        RichText::new(format!("{:0digits$x}", hit.address)).monospace(),
                        theme::MUTED,
                    );
                    if let Some(x) = middle_x {
                        let name = context
                            .sections
                            .get(usize::from(hit.section_index))
                            .map_or("", |section| section.name.as_str());
                        theme::cell_text(ui, cell(x, middle_end), body(name), theme::MUTED);
                    }
                    let pattern = if search.mode == MemoryMode::Hex {
                        RichText::new(&search.pattern).monospace()
                    } else {
                        body(&search.pattern)
                    };
                    theme::cell_text(ui, cell(last_x, None), pattern, theme::TEXT);
                    response.on_hover_text(format!("{} bytes", hit.length))
                }
                SearchKind::Text(search) => {
                    let hit = &search.hits()[index];
                    item = linkage_item(hit.key);
                    let (address, color) = match hit.address {
                        Some(address) => (format!("{address:0digits$x}"), theme::MUTED),
                        None => ("—".into(), theme::MUTED),
                    };
                    theme::cell_text(
                        ui,
                        cell(0.0, address_end),
                        RichText::new(address).monospace(),
                        color,
                    );
                    if let Some(x) = middle_x {
                        theme::cell_text(
                            ui,
                            cell(x, middle_end),
                            body(kind_label(hit.key)),
                            theme::MUTED,
                        );
                    }
                    let color = if hit.address.is_some() {
                        theme::TEXT
                    } else {
                        theme::MUTED
                    };
                    theme::cell_text(ui, cell(last_x, None), body(&hit.snippet), color);
                    response.on_hover_ui(|ui| {
                        ui.label(kind_label(hit.key));
                        let variants: Vec<&str> = [
                            (VARIANT_INVENTORY, "inventory"),
                            (VARIANT_RAW, "raw"),
                            (VARIANT_DISPLAY, "display"),
                        ]
                        .iter()
                        .filter(|(bit, _)| hit.matched_variants & bit != 0)
                        .map(|(_, label)| *label)
                        .collect();
                        if !variants.is_empty() {
                            ui.weak(variants.join(" · "));
                        }
                        if hit.provenance == TextProvenance::Saved {
                            ui.weak("Saved analysis");
                        }
                    })
                }
            };
            if response.double_clicked() {
                action = Some(ResultAction::Open(index));
            } else if response.clicked() {
                clicked = Some(index);
            }
            response.context_menu(|ui| {
                if ui
                    .add_enabled((context.openable)(index), egui::Button::new("Open"))
                    .clicked()
                {
                    action = Some(ResultAction::Open(index));
                    ui.close();
                }
                if let (Some(item), Some(linkage)) = (item, context.linkage) {
                    let places = crate::linkage_ui::places(linkage, item, context.pointer);
                    if places.len() > 1 {
                        for place in places {
                            let label = match place {
                                Place::Code(address) => format!("Go to {address:x}"),
                                Place::Data { address, .. } => format!("Go to slot {address:x}"),
                            };
                            if ui.button(label).clicked() {
                                action = Some(ResultAction::OpenPlace(index, item, place));
                                ui.close();
                            }
                        }
                    }
                }
            });
            None
        },
    );
    if let Some(index) = clicked {
        table.selected = Some(index);
        table.focus = true;
    } else if ui.input(|input| {
        input.pointer.any_pressed()
            && input
                .pointer
                .interact_pos()
                .is_none_or(|pos| !output.inner_rect.contains(pos))
    }) {
        table.focus = false;
    }
    let ctx = ui.ctx();
    if table.focus
        && action.is_none()
        && !ctx.egui_wants_keyboard_input()
        && !egui::Popup::is_any_open(ctx)
        && ctx.memory(|memory| memory.top_modal_layer().is_none())
        && let Some(index) = table.selected.filter(|&index| index < count)
        && ui.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Enter))
    {
        action = Some(ResultAction::Open(index));
    }
    action
}

/// Query/mode control at the left; state, count and Cancel at the right.
fn header(ui: &mut egui::Ui, view: &SearchView, action: &mut Option<ResultAction>) {
    let (strip, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), theme::ROW_HEIGHT + 4.0),
        egui::Sense::hover(),
    );
    let inner = strip.shrink2(egui::vec2(4.0, 0.0));
    let mut right = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("search-header-actions")
            .max_rect(inner)
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    right.set_clip_rect(inner.intersect(ui.clip_rect()));
    if view.active() && right.button("Cancel").clicked() {
        *action = Some(ResultAction::Cancel);
    }
    let (state, color) = state_label(view.state());
    let chip = right.colored_label(color, format!("{state} · {}", view.count()));
    if let Some(hover) = state_hover(view) {
        chip.on_hover_text(hover);
    }
    let used = right.min_rect();
    let left_rect = inner.with_max_x((used.left() - 8.0).max(inner.left()));
    let mut left = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("search-header-query")
            .max_rect(left_rect)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    left.set_clip_rect(left_rect.intersect(ui.clip_rect()));
    let (mode, query, kind) = match &view.kind {
        SearchKind::Memory(search) => (
            search.mode.label(),
            if search.mode == MemoryMode::Hex {
                RichText::new(&search.pattern).monospace()
            } else {
                body(&search.pattern)
            },
            DialogKind::Memory,
        ),
        SearchKind::Text(search) => ("Text", body(&search.spec.query), DialogKind::Text),
    };
    left.weak(mode);
    if left
        .add(egui::Button::new(query).truncate())
        .on_hover_text("Edit search")
        .clicked()
    {
        *action = Some(ResultAction::Edit(kind));
    }
}
