//! Sorted and filtered chooser rows on the shared virtual-row helpers.
use super::FileDialogKind;
use super::io::{Entry, EntryKind, unix_text};
use crate::theme::{self, SortDirection};
use eframe::egui::{self, RichText, Stroke};
use std::cmp::Ordering;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SortColumn {
    Name,
    Size,
    Modified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SortState {
    pub(super) column: SortColumn,
    pub(super) direction: SortDirection,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            column: SortColumn::Name,
            direction: SortDirection::Ascending,
        }
    }
}

impl SortState {
    /// Repeating a column toggles; a new Size or Modified sort starts newest
    /// or largest first.
    pub(super) fn click(&mut self, column: SortColumn) {
        if self.column == column {
            self.direction = match self.direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            self.column = column;
            self.direction = if column == SortColumn::Name {
                SortDirection::Ascending
            } else {
                SortDirection::Descending
            };
        }
    }
}

fn known_first<T: Ord>(left: Option<T>, right: Option<T>, direction: SortDirection) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) if direction == SortDirection::Descending => right.cmp(&left),
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Folders first, missing metadata last, then the field, the case-folded
/// label and the native name, in either direction.
pub(super) fn compare(left: &Entry, right: &Entry, sort: SortState) -> Ordering {
    let folder = |entry: &Entry| entry.kind != EntryKind::Directory;
    folder(left).cmp(&folder(right)).then_with(|| {
        let field = match sort.column {
            SortColumn::Name => Ordering::Equal,
            SortColumn::Size => known_first(left.size, right.size, sort.direction),
            SortColumn::Modified => known_first(left.modified, right.modified, sort.direction),
        };
        field.then_with(|| {
            let name = left
                .key
                .cmp(&right.key)
                .then_with(|| left.name.cmp(&right.name));
            if sort.column == SortColumn::Name && sort.direction == SortDirection::Descending {
                name.reverse()
            } else {
                name
            }
        })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TypeFilter {
    All,
    Projects,
    Annotations,
    Pe,
}

impl TypeFilter {
    /// The choices for `kind`; the first is the default.
    pub(super) fn choices(kind: FileDialogKind) -> &'static [Self] {
        match kind {
            FileDialogKind::OpenBinary | FileDialogKind::LocateProjectBinary => {
                &[Self::All, Self::Pe]
            }
            FileDialogKind::OpenProject | FileDialogKind::SaveProject => {
                &[Self::Projects, Self::All]
            }
            FileDialogKind::OpenAnnotations | FileDialogKind::SaveAnnotations => {
                &[Self::Annotations, Self::All]
            }
        }
    }

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::All => "All files",
            Self::Projects => "Projects (*.grproj)",
            Self::Annotations => "Annotations (*.json)",
            Self::Pe => "PE files (*.exe, *.dll, *.sys)",
        }
    }

    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::All => &[],
            Self::Projects => &["grproj"],
            Self::Annotations => &["json"],
            Self::Pe => &["exe", "dll", "sys"],
        }
    }

    /// Filters hide files only. Folders, links and unknown kinds stay visible.
    pub(super) fn accepts(self, entry: &Entry) -> bool {
        if self == Self::All
            || matches!(
                entry.kind,
                EntryKind::Directory | EntryKind::Link | EntryKind::Unknown
            )
        {
            return true;
        }
        Path::new(&entry.name).extension().is_some_and(|extension| {
            self.extensions().iter().any(|wanted| {
                extension
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(wanted.as_bytes())
            })
        })
    }
}

/// Indexes of the entries passing both filters, in sorted order.
pub(super) fn visible(
    entries: &[Entry],
    text: &str,
    filter: TypeFilter,
    sort: SortState,
) -> Vec<usize> {
    let needle = text.to_lowercase();
    let mut visible: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, entry)| {
            filter.accepts(entry) && (needle.is_empty() || entry.key.contains(&needle))
        })
        .map(|(index, _)| index)
        .collect();
    visible.sort_by(|&left, &right| compare(&entries[left], &entries[right], sort));
    visible
}

/// Column widths in logical points for one frame; hidden columns are `None`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Columns {
    pub(super) name: f32,
    pub(super) size: Option<f32>,
    pub(super) modified: Option<f32>,
}

/// Size the columns from the table width with a vertical gutter always
/// reserved, so a scroll bar appearing never moves the header.
pub(super) fn columns(table_width: f32, gutter: f32, outer_width: f32) -> Columns {
    let wide = outer_width >= 760.0;
    let size = (outer_width >= 360.0).then_some(if wide { 80.0 } else { 64.0 });
    let modified = (outer_width >= 480.0).then_some(if wide { 144.0 } else { 112.0 });
    let name = (table_width - gutter - size.unwrap_or(0.0) - modified.unwrap_or(0.0)).max(0.0);
    Columns {
        name,
        size,
        modified,
    }
}

pub(super) enum TableEvent {
    Select(usize),
    Activate(usize),
}

pub(super) struct TableView<'a> {
    pub(super) entries: &'a [Entry],
    pub(super) visible: &'a [usize],
    pub(super) selected: Option<usize>,
    pub(super) reveal: Option<usize>,
    pub(super) sort: SortState,
    pub(super) generation: u64,
    pub(super) columns: Columns,
    pub(super) focus: egui::Id,
    pub(super) next_focus: egui::Id,
}

pub(super) struct TableOutput {
    pub(super) event: Option<TableEvent>,
    pub(super) sort: Option<SortColumn>,
    /// Whole rows in the body viewport, for PageUp/PageDown.
    pub(super) page: usize,
}

const ICON: f32 = 22.0;

/// Paint a folder, document or link glyph without relying on font coverage.
fn paint_icon(painter: &egui::Painter, cell: egui::Rect, kind: EntryKind) {
    let center = egui::pos2(cell.left() + 6.0 + 7.0, cell.center().y);
    let stroke = Stroke::new(1.0, theme::MUTED);
    match kind {
        EntryKind::Directory => {
            let body =
                egui::Rect::from_center_size(center + egui::vec2(0.0, 1.0), egui::vec2(13.0, 9.0));
            let tab = egui::Rect::from_min_size(
                body.left_top() - egui::vec2(0.0, 2.0),
                egui::vec2(5.0, 3.0),
            );
            painter.rect_filled(tab, 1, theme::BLUE.gamma_multiply(0.8));
            painter.rect_filled(body, 1, theme::BLUE.gamma_multiply(0.8));
        }
        _ => {
            let page = egui::Rect::from_center_size(center, egui::vec2(9.0, 12.0));
            painter.rect_stroke(page, 1, stroke, egui::StrokeKind::Inside);
            if kind == EntryKind::Link {
                let start = page.left_bottom() + egui::vec2(2.0, -2.5);
                let end = page.center() + egui::vec2(1.5, -1.5);
                painter.line_segment([start, end], Stroke::new(1.2, theme::TEXT));
                painter.line_segment(
                    [end, end + egui::vec2(-3.0, 0.0)],
                    Stroke::new(1.2, theme::TEXT),
                );
                painter.line_segment(
                    [end, end + egui::vec2(0.0, 3.0)],
                    Stroke::new(1.2, theme::TEXT),
                );
            }
        }
    }
}

fn group_digits(value: u64) -> String {
    let digits = value.to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    grouped
}

fn row_tooltip(ui: &mut egui::Ui, entry: &Entry) {
    ui.set_max_width(480.0);
    ui.add(egui::Label::new(&entry.label).wrap());
    if let Some(size) = entry.size {
        ui.weak(format!("{} bytes", group_digits(size)));
    }
    if let Some(modified) = entry.modified {
        ui.weak(unix_text(modified));
    }
}

fn header_index(column: SortColumn, columns: Columns) -> Option<usize> {
    match column {
        SortColumn::Name => Some(0),
        SortColumn::Size => columns.size.map(|_| 1),
        SortColumn::Modified => columns
            .modified
            .map(|_| 1 + usize::from(columns.size.is_some())),
    }
}

/// The sort menu for columns hidden at narrow widths.
fn sort_menu(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    id: egui::Id,
    sort: SortState,
) -> Option<SortColumn> {
    const COLUMNS: [SortColumn; 3] = [SortColumn::Name, SortColumn::Size, SortColumn::Modified];
    let active = COLUMNS.iter().position(|column| *column == sort.column);
    theme::sort_menu(ui, rect, id, &["Name", "Size", "Modified"], active)
        .map(|index| COLUMNS[index])
}

/// Draw the header and virtual body into the remaining space.
pub(super) fn draw(ui: &mut egui::Ui, view: TableView<'_>) -> TableOutput {
    let columns = view.columns;
    let mut titles = vec![("Name", 0.0)];
    let mut x = columns.name;
    if let Some(size) = columns.size {
        titles.push(("Size", x));
        x += size;
    }
    if columns.modified.is_some() {
        titles.push(("Modified", x));
    }
    let active = header_index(view.sort.column, columns).map(|index| (index, view.sort.direction));
    let (header, clicked) =
        theme::sortable_column_header(ui, "file-chooser-header", &titles, 0.0, active);
    let mut sort = clicked.map(|index| match titles[index].0 {
        "Size" => SortColumn::Size,
        "Modified" => SortColumn::Modified,
        _ => SortColumn::Name,
    });
    if columns.size.is_none() || columns.modified.is_none() {
        let gutter = ui.spacing().scroll.allocated_width();
        let rect = egui::Rect::from_min_size(
            egui::pos2(header.right() - gutter - 22.0, header.top() + 1.0),
            egui::vec2(20.0, header.height() - 2.0),
        );
        sort = sort.or(sort_menu(
            ui,
            rect,
            ui.scope_id().with("file-chooser-sort"),
            view.sort,
        ));
    }
    // The persistent keyboard target is registered before the rows, so a
    // click on a row can claim focus for the table after this widget's
    // click-elsewhere handling.
    let body = ui.available_rect_before_wrap();
    let target = ui.interact(body, view.focus, egui::Sense::focusable_noninteractive());
    target.widget_info(|| egui::WidgetInfo::labeled(egui::Role::List, true, "Files"));
    let focused = target.has_focus();
    let shift = ui.input(|input| input.modifiers.shift);
    let (event, output) = theme::rows(
        ui,
        "file-chooser-rows",
        view.visible.len(),
        theme::ROW_HEIGHT,
        0.0,
        view.reveal,
        |ui, row, rect| {
            let index = view.visible[row];
            let entry = &view.entries[index];
            let id = egui::Id::unique(("file-chooser-row", view.generation, index));
            let response = theme::row_response(ui, id, rect, view.selected == Some(index), false);
            response.widget_info(|| {
                egui::WidgetInfo::selected(
                    egui::Role::ListItem,
                    true,
                    view.selected == Some(index),
                    &entry.label,
                )
            });
            let mut x = rect.left();
            let name = egui::Rect::from_x_y_ranges(x..=x + columns.name, rect.y_range());
            paint_icon(ui.painter(), name, entry.kind);
            theme::cell_text(
                ui,
                egui::Rect::from_x_y_ranges(name.left() + ICON..=name.right(), rect.y_range()),
                RichText::new(&entry.label).text_style(egui::TextStyle::Body),
                theme::TEXT,
            );
            x += columns.name;
            if let Some(width) = columns.size {
                let cell = egui::Rect::from_x_y_ranges(x..=x + width, rect.y_range());
                theme::cell_text(ui, cell, &entry.size_text, theme::MUTED);
                x += width;
            }
            if let Some(width) = columns.modified {
                let cell = egui::Rect::from_x_y_ranges(x..=x + width, rect.y_range());
                theme::cell_text(ui, cell, &entry.modified_text, theme::MUTED);
            }
            if response.gained_focus() && !response.clicked() {
                // Tab passes over the rows as one stop.
                let next = if shift { view.focus } else { view.next_focus };
                ui.memory_mut(|memory| memory.request_focus(next));
            }
            let result = if response.double_clicked() {
                Some(TableEvent::Activate(index))
            } else if response.clicked() {
                Some(TableEvent::Select(index))
            } else {
                None
            };
            if result.is_some() {
                ui.memory_mut(|memory| memory.request_focus(view.focus));
            }
            response.on_hover_ui(|ui| row_tooltip(ui, entry));
            result
        },
    );
    if focused && ui.is_rect_visible(output.inner_rect) {
        ui.painter().rect_stroke(
            output.inner_rect,
            0,
            Stroke::new(1.0, theme::ACCENT.gamma_multiply(0.6)),
            egui::StrokeKind::Inside,
        );
    }
    TableOutput {
        event,
        sort,
        page: ((output.inner_rect.height() / theme::ROW_HEIGHT).floor() as usize).max(1),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    pub(in crate::file_dialog) fn entry(name: &str, kind: EntryKind, size: Option<u64>) -> Entry {
        Entry {
            path: Path::new("/d").join(name),
            name: name.into(),
            kind,
            label: name.into(),
            key: name.to_lowercase(),
            size,
            modified: size.map(|size| SystemTime::UNIX_EPOCH + Duration::from_secs(size)),
            size_text: String::new(),
            modified_text: String::new(),
        }
    }

    fn names(entries: &[Entry], order: &[usize]) -> Vec<String> {
        order
            .iter()
            .map(|&index| entries[index].label.clone())
            .collect()
    }

    #[test]
    fn sorting_keeps_folders_first_and_missing_metadata_last() {
        let entries = [
            entry("b", EntryKind::Directory, None),
            entry("c", EntryKind::File, Some(10)),
            entry("A", EntryKind::Directory, None),
            entry("d", EntryKind::File, None),
            entry("e", EntryKind::File, Some(30)),
            entry("C", EntryKind::File, Some(10)),
        ];
        let mut sort = SortState::default();
        let order = |sort| names(&entries, &visible(&entries, "", TypeFilter::All, sort));
        assert_eq!(order(sort), ["A", "b", "C", "c", "d", "e"]);
        sort.click(SortColumn::Name);
        assert_eq!(order(sort), ["b", "A", "e", "d", "c", "C"]);
        // Size starts largest first; ties fall back to the name.
        sort.click(SortColumn::Size);
        assert_eq!(sort.direction, SortDirection::Descending);
        assert_eq!(order(sort), ["A", "b", "e", "C", "c", "d"]);
        sort.click(SortColumn::Size);
        assert_eq!(order(sort), ["A", "b", "C", "c", "e", "d"]);
        sort.click(SortColumn::Modified);
        assert_eq!(order(sort), ["A", "b", "e", "C", "c", "d"]);
        // The text filter matches case-insensitively, folders included.
        let filtered = visible(&entries, "B", TypeFilter::All, SortState::default());
        assert_eq!(names(&entries, &filtered), ["b"]);
    }

    #[test]
    fn kind_filters_do_not_hide_directories_or_extensionless_binaries() {
        use FileDialogKind::*;
        let defaults: Vec<_> = [
            OpenBinary,
            OpenProject,
            LocateProjectBinary,
            SaveProject,
            OpenAnnotations,
            SaveAnnotations,
        ]
        .map(|kind| TypeFilter::choices(kind)[0])
        .into();
        use TypeFilter::*;
        assert_eq!(
            defaults,
            [All, Projects, All, Projects, Annotations, Annotations]
        );
        for kind in [OpenProject, SaveProject, OpenAnnotations, SaveAnnotations] {
            assert!(TypeFilter::choices(kind).contains(&All));
        }
        let entries = [
            entry("folder.d", EntryKind::Directory, None),
            entry("elf", EntryKind::File, Some(1)),
            entry("CASE.GRPROJ", EntryKind::File, Some(1)),
            entry("notes.Json", EntryKind::File, Some(1)),
            entry("LIB.DLL", EntryKind::File, Some(1)),
            entry("link", EntryKind::Link, None),
        ];
        let shown = |filter| {
            names(
                &entries,
                &visible(&entries, "", filter, SortState::default()),
            )
        };
        assert_eq!(shown(All).len(), entries.len());
        assert_eq!(shown(Projects), ["folder.d", "CASE.GRPROJ", "link"]);
        assert_eq!(shown(Annotations), ["folder.d", "link", "notes.Json"]);
        assert_eq!(shown(Pe), ["folder.d", "LIB.DLL", "link"]);
    }

    #[test]
    fn narrow_columns_hide_metadata_before_the_name() {
        let wide = columns(696.0, 10.0, 880.0);
        assert_eq!((wide.size, wide.modified), (Some(80.0), Some(144.0)));
        assert_eq!(wide.name, 696.0 - 10.0 - 80.0 - 144.0);
        let compact = columns(476.0, 10.0, 640.0);
        assert_eq!((compact.size, compact.modified), (Some(64.0), Some(112.0)));
        let narrow = columns(400.0, 10.0, 420.0);
        assert_eq!((narrow.size, narrow.modified), (Some(64.0), None));
        let tiny = columns(300.0, 10.0, 340.0);
        assert_eq!((tiny.size, tiny.modified, tiny.name), (None, None, 290.0));
    }
}
