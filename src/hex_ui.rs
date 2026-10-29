//! Read-only, page-bounded Hex + memory-map provider.
//!
//! Integration contract: own one panel per binary generation (replace it when
//! changing binaries), pass that generation's immutable section inventory, and
//! dispatch returned actions outside the GUI thread. Correlate `Read` with the
//! parent's worker request and binary generation, then call `accept` or `fail`.
//! Call `cancel` when the parent abandons that request. This module owns no I/O,
//! worker, function selection, annotations, or image/section inventory.

use eframe::egui::{self, RichText, ScrollArea, TextEdit};

use crate::model::{MAX_BYTE_READ, SectionInfo};
use crate::theme;

const PAGE_BYTES: usize = if MAX_BYTE_READ < 4096 {
    MAX_BYTE_READ
} else {
    4096
};
const ROW_BYTES: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HexAction {
    Read {
        token: u64,
        address: u64,
        length: usize,
    },
    Decode {
        address: u64,
        bytes: Vec<u8>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PageSpec {
    section: usize,
    address: u64,
    length: usize,
}

#[derive(Clone, Copy)]
struct Pending {
    token: u64,
    page: PageSpec,
}

struct Page {
    spec: PageSpec,
    bytes: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct HexPanel {
    initialized: bool,
    section: Option<usize>,
    address_text: String,
    generation: u64,
    target: Option<PageSpec>,
    pending: Option<Pending>,
    loaded: Option<Page>,
    // Both endpoints are offsets in the single page; the anchor survives Shift.
    selection: Option<(usize, usize)>,
    scroll_row: Option<usize>,
    error: Option<String>,
    navigation_error: Option<String>,
}

impl HexPanel {
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        sections: &[SectionInfo],
    ) -> Option<HexAction> {
        let mut action = self.initialize(sections);
        if sections.is_empty() {
            ui.weak("No mapped sections");
        } else if let Some(index) = self.section_table(ui, sections, action.is_none()) {
            action = self.open_section(index, sections);
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            let previous = self.neighbor(sections, false);
            let next = self.neighbor(sections, true);
            if ui
                .add_enabled(
                    action.is_none() && previous.is_some(),
                    egui::Button::new("Prev"),
                )
                .clicked()
                && let Some(address) = previous
            {
                action = self.turn_page(address, sections);
            }
            if ui
                .add_enabled(
                    action.is_none() && next.is_some(),
                    egui::Button::new("Next"),
                )
                .clicked()
                && let Some(address) = next
            {
                action = self.turn_page(address, sections);
            }
            ui.label("VA (hex)");
            let edit = ui.add(
                TextEdit::singleline(&mut self.address_text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(154.0)
                    .char_limit(18),
            );
            let enter = edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            let jump = ui
                .add_enabled(action.is_none(), egui::Button::new("Go"))
                .clicked();
            if action.is_none() && (jump || enter) {
                match parse_address(&self.address_text) {
                    Ok(address) => action = self.go_to(address, sections),
                    Err(message) => self.navigation_error = Some(message.into()),
                }
            }
            if ui
                .add_enabled(
                    action.is_none()
                        && !self.is_loading()
                        && self.error.is_some()
                        && self.target.is_some(),
                    egui::Button::new("Retry"),
                )
                .clicked()
            {
                action = self.retry(sections);
            }
            if ui
                .add_enabled(
                    action.is_none() && self.selection_range().is_some() && self.loaded.is_some(),
                    egui::Button::new("Decode selection"),
                )
                .clicked()
                && let Some((address, bytes)) = self.selected_bytes()
            {
                action = Some(HexAction::Decode { address, bytes });
            }
        });
        if let Some(message) = &self.navigation_error {
            ui.colored_label(theme::ERROR, message);
        }
        if let Some(message) = &self.error {
            ui.colored_label(theme::ERROR, message);
        }
        if self.is_loading() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.weak("Loading byte page…");
            });
        } else if self.loaded.is_some() {
            self.byte_page(ui, sections);
        } else if self.error.is_none() {
            ui.weak("Select a section or address.");
        }
        action
    }

    pub(crate) fn open_section(
        &mut self,
        index: usize,
        sections: &[SectionInfo],
    ) -> Option<HexAction> {
        self.initialized = true;
        let result = sections
            .get(index)
            .ok_or_else(|| "Section is no longer available".to_owned())
            .and_then(|section| page_for(index, section, section.address));
        match result {
            Ok(page) => self.navigate(page, None, page.address),
            Err(message) => {
                self.navigation_error = Some(message);
                None
            }
        }
    }

    pub(crate) fn go_to(&mut self, address: u64, sections: &[SectionInfo]) -> Option<HexAction> {
        self.go_to_span(address, 1, sections)
    }

    /// Exact navigation that also selects up to `length` bytes from `address`,
    /// clipped to its page and to the section's file-backed bytes. Zero-fill
    /// or unbacked destinations keep the single-byte focus. A file-backed span
    /// of at most one page that crosses its default page instead reads a page
    /// beginning at `address`, so the whole span stays selected.
    pub(crate) fn go_to_span(
        &mut self,
        address: u64,
        length: u64,
        sections: &[SectionInfo],
    ) -> Option<HexAction> {
        self.initialized = true;
        // Preserve the selected mapping when virtual ranges overlap.
        let preferred = self.section.filter(|&index| {
            sections
                .get(index)
                .is_some_and(|section| contains(section, address))
        });
        let index = preferred.or_else(|| {
            sections
                .iter()
                .position(|section| contains(section, address))
        });
        let result = index
            .ok_or_else(|| "Address is unmapped or its section range overflows".to_owned())
            .and_then(|index| span_page(index, &sections[index], address, length))
            .and_then(|page| {
                let offset = page_offset(page, address)?;
                Ok((page, offset))
            });
        match result {
            Ok((page, offset)) => {
                // Explicit span navigation is a new consumer/selection even
                // within a pending page. Give it its own token so an old
                // consumer's late reply cannot cancel or populate this one.
                let action = if self.target == Some(page) && self.pending.is_some() {
                    let action = self.start_read(page);
                    self.set_focus(Some(offset), address);
                    action
                } else {
                    self.navigate(page, Some(offset), address)
                };
                let section = &sections[page.section];
                let backed = section
                    .address
                    .saturating_add(section.file_size.min(section.size))
                    .saturating_sub(address);
                let span = length.min(backed).min((page.length - offset) as u64).max(1) as usize;
                self.selection = Some((offset, offset + span - 1));
                action
            }
            Err(message) => {
                // Invalid navigation cannot discard a valid page or pending read.
                self.navigation_error = Some(message);
                None
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn focused_span(&self) -> Option<(u64, u64)> {
        let range = self.selection_range()?;
        Some((
            self.target?.address + range.start as u64,
            range.len() as u64,
        ))
    }

    fn turn_page(&mut self, address: u64, sections: &[SectionInfo]) -> Option<HexAction> {
        let index = self.section?;
        let page = sections
            .get(index)
            .ok_or_else(|| "Section is no longer available".to_owned())
            .and_then(|section| page_for(index, section, address));
        match page {
            Ok(page) => self.navigate(page, None, address),
            Err(message) => {
                self.navigation_error = Some(message);
                None
            }
        }
    }

    /// A stale token never changes state. A malformed reply for the live token
    /// ends that request and leaves an explicit Retry state.
    pub(crate) fn accept(
        &mut self,
        token: u64,
        address: u64,
        bytes: Vec<u8>,
    ) -> Result<(), String> {
        let Some(pending) = self.pending.filter(|pending| pending.token == token) else {
            return Err("Stale or canceled Hex reply".into());
        };
        if !self.expects(token, address, bytes.len()) {
            let message = format!(
                "Hex reply range mismatch: expected {:#x} / {} bytes, received {address:#x} / {} bytes",
                pending.page.address,
                pending.page.length,
                bytes.len(),
            );
            self.fail(token, message.clone());
            return Err(message);
        }
        self.pending = None;
        self.error = None;
        self.loaded = Some(Page {
            spec: pending.page,
            bytes,
        });
        Ok(())
    }

    pub(crate) fn fail(&mut self, token: u64, message: impl Into<String>) {
        if self.pending.is_some_and(|pending| pending.token == token) {
            self.pending = None;
            self.error = Some(message.into());
        }
    }

    /// Retains the target for Retry, but invalidates acceptance immediately.
    /// The parent owns cancellation/termination of any actual worker request.
    pub(crate) fn cancel(&mut self, message: impl Into<String>) {
        self.initialized = true;
        self.pending = None;
        self.error = Some(message.into());
    }

    pub(crate) fn expects(&self, token: u64, address: u64, length: usize) -> bool {
        self.pending.is_some_and(|pending| {
            pending.token == token
                && pending.page.address == address
                && pending.page.length == length
                && length > 0
                && length <= PAGE_BYTES
        })
    }

    pub(crate) fn is_loading(&self) -> bool {
        self.pending.is_some()
    }

    #[cfg(test)]
    pub(crate) fn loaded_page(&self) -> Option<(u64, &[u8])> {
        self.loaded
            .as_ref()
            .map(|page| (page.spec.address, page.bytes.as_slice()))
    }

    /// Copies only an explicitly selected page-local slice, never a whole image.
    pub(crate) fn selected_bytes(&self) -> Option<(u64, Vec<u8>)> {
        let page = self.loaded.as_ref()?;
        let range = self.selection_range()?;
        let offset = u64::try_from(range.start).ok()?;
        let address = page.spec.address.checked_add(offset)?;
        let bytes = page.bytes.get(range)?.to_vec();
        Some((address, bytes))
    }

    fn initialize(&mut self, sections: &[SectionInfo]) -> Option<HexAction> {
        if self.initialized || sections.is_empty() {
            return None;
        }
        self.initialized = true;
        sections
            .iter()
            .position(|section| section.size != 0)
            .and_then(|index| self.open_section(index, sections))
    }

    fn navigate(
        &mut self,
        page: PageSpec,
        focus: Option<usize>,
        address: u64,
    ) -> Option<HexAction> {
        if self.target != Some(page) {
            let action = self.start_read(page)?;
            self.set_focus(focus, address);
            Some(action)
        } else {
            // Neither selecting the same section nor jumping within a failed
            // page retries a canceled/failed read. Only Retry does that.
            self.navigation_error = None;
            self.set_focus(focus, address);
            None
        }
    }

    fn set_focus(&mut self, focus: Option<usize>, address: u64) {
        self.address_text = format!("{address:x}");
        self.selection = focus.map(|offset| (offset, offset));
        self.scroll_row = Some(focus.unwrap_or(0) / ROW_BYTES);
    }

    fn start_read(&mut self, page: PageSpec) -> Option<HexAction> {
        let Some(token) = self.generation.checked_add(1) else {
            self.navigation_error =
                Some("Hex request token space exhausted; reopen this binary".into());
            return None;
        };
        self.generation = token;
        self.section = Some(page.section);
        self.target = Some(page);
        self.pending = Some(Pending { token, page });
        self.loaded = None;
        self.selection = None;
        self.error = None;
        self.navigation_error = None;
        Some(HexAction::Read {
            token,
            address: page.address,
            length: page.length,
        })
    }

    fn retry(&mut self, sections: &[SectionInfo]) -> Option<HexAction> {
        if self.pending.is_some() {
            return None;
        }
        let target = self.target?;
        let result = sections
            .get(target.section)
            .ok_or_else(|| "Section is no longer available".to_owned())
            .and_then(|section| {
                if still_valid(target, section) {
                    Ok(target)
                } else {
                    Err("Section metadata changed; reopen this binary".into())
                }
            });
        match result {
            Ok(page) => {
                let action = self.start_read(page)?;
                self.set_focus(None, page.address);
                Some(action)
            }
            Err(message) => {
                self.navigation_error = Some(message);
                None
            }
        }
    }

    fn neighbor(&self, sections: &[SectionInfo], forward: bool) -> Option<u64> {
        let page = self.target?;
        let section = sections.get(page.section)?;
        let end = section_end(section).ok()?;
        // Neighbours are the default pages adjoining this one. After an exact
        // span page, Prev can return to the section's first page.
        let address = if forward {
            let address = page.address.checked_add(u64::try_from(page.length).ok()?)?;
            if address >= end {
                return None;
            }
            address
        } else {
            if page.address <= section.address {
                return None;
            }
            page.address.checked_sub(1)?
        };
        page_for(page.section, section, address)
            .ok()
            .map(|page| page.address)
    }

    fn selection_range(&self) -> Option<std::ops::Range<usize>> {
        let (anchor, head) = self.selection?;
        Some(anchor.min(head)..anchor.max(head).checked_add(1)?)
    }

    fn select_offset(&mut self, offset: usize, shift: bool) {
        let Some(page) = &self.loaded else { return };
        if offset >= page.bytes.len() {
            return;
        }
        let anchor = if shift {
            self.selection.map_or(offset, |(anchor, _)| anchor)
        } else {
            offset
        };
        self.selection = Some((anchor, offset));
    }

    fn section_table(
        &self,
        ui: &mut egui::Ui,
        sections: &[SectionInfo],
        enabled: bool,
    ) -> Option<usize> {
        let height = (ui.available_height() * 0.28).clamp(48.0, 132.0) + theme::ROW_HEIGHT;
        let glyph = theme::glyph_width(ui);
        let columns = [0.0, 20.0 * glyph, 60.0 * glyph, 110.0 * glyph];
        let width = columns[3] + 6.0 * glyph;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                let header = theme::column_header(ui, &[], 0.0);
                let (chosen, output) = theme::rows(
                    ui,
                    "hex-memory-map",
                    sections.len(),
                    theme::ROW_HEIGHT,
                    width,
                    None,
                    |ui, index, rect| {
                        let section = &sections[index];
                        let valid = validate_section(section);
                        let usable = enabled && valid.is_ok();
                        let response = theme::row_response(
                            ui,
                            ui.scope_id().with(("hex-section", index)),
                            rect,
                            self.section == Some(index),
                            false,
                        );
                        let response = match &valid {
                            Err(message) => response.on_hover_text(message),
                            Ok(()) => response.on_hover_text(&section.name),
                        };
                        let virtual_range = match section.address.checked_add(section.size) {
                            Some(end) => format!("{:#x}..{end:#x}", section.address),
                            None => "Virtual range overflow".into(),
                        };
                        let file_range = if section.file_size == 0 {
                            format!("No file bytes; zero-fill {} B", section.size)
                        } else {
                            match section.file_offset.checked_add(section.file_size) {
                                Some(end) => format!(
                                    "{:#x}..{end:#x}; backed {} / {} B",
                                    section.file_offset,
                                    section.file_size.min(section.size),
                                    section.size,
                                ),
                                None => "File range overflow".into(),
                            }
                        };
                        let color = if usable { theme::TEXT } else { theme::MUTED };
                        let cells = [
                            (section.name.as_str(), color),
                            (virtual_range.as_str(), theme::MUTED),
                            (file_range.as_str(), theme::MUTED),
                            (if section.executable { "X" } else { "—" }, color),
                        ];
                        for (column, (text, color)) in cells.into_iter().enumerate() {
                            let right = columns.get(column + 1).copied().unwrap_or(width);
                            let cell = egui::Rect::from_x_y_ranges(
                                rect.left() + columns[column]..=rect.left() + right,
                                rect.y_range(),
                            );
                            theme::cell_text(ui, cell, RichText::new(text).monospace(), color);
                        }
                        (usable && response.clicked()).then_some(index)
                    },
                );
                theme::paint_column_header(
                    ui,
                    header,
                    &[
                        ("Section", columns[0]),
                        ("Virtual [start, end)", columns[1]),
                        ("File [start, end) / mapped backing", columns[2]),
                        ("Exec", columns[3]),
                    ],
                    output.state.clamped_offset().x,
                );
                chosen
            },
        )
        .inner
    }

    fn byte_page(&mut self, ui: &mut egui::Ui, sections: &[SectionInfo]) {
        let Some(page) = &self.loaded else { return };
        let Some(section) = sections.get(page.spec.section) else {
            ui.colored_label(
                theme::ERROR,
                "Section is no longer available; reopen this binary",
            );
            return;
        };
        if !still_valid(page.spec, section) {
            ui.colored_label(theme::ERROR, "Section metadata changed; reopen this binary");
            return;
        }
        let Some(end) = u64::try_from(page.bytes.len())
            .ok()
            .and_then(|length| page.spec.address.checked_add(length))
        else {
            ui.colored_label(theme::ERROR, "Invalid byte-page range");
            return;
        };
        ui.label(
            RichText::new(format!(
                "{:#x}..{end:#x} · {} bytes",
                page.spec.address,
                page.bytes.len()
            ))
            .monospace(),
        )
        .on_hover_text("Click to select · Shift-click to extend · muted bytes are zero-fill.");
        let font = egui::FontId::monospace(13.0);
        let glyph = ui
            .painter()
            .layout_no_wrap("0".into(), font.clone(), theme::TEXT)
            .size()
            .x;
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace).max(20.0);
        let selected = self.selection_range();
        let mut scroll = ScrollArea::both()
            .id_salt("hex-byte-page")
            .auto_shrink([false, false]);
        // Only consume this when a loaded page can actually be shown. In-flight
        // reads must not eat the requested one-shot target.
        if let Some(row) = self.scroll_row.take() {
            scroll = scroll
                .vertical_scroll_offset(row as f32 * (row_height + ui.spacing().item_spacing.y));
        }
        let mut click = None;
        scroll.show_rows(
            ui,
            row_height,
            page.bytes.len().div_ceil(ROW_BYTES),
            |ui, rows| {
                for row in rows {
                    let Some(start) = row.checked_mul(ROW_BYTES) else {
                        continue;
                    };
                    let Some(row_end) = start.checked_add(ROW_BYTES) else {
                        continue;
                    };
                    let row_end = row_end.min(page.bytes.len());
                    let Ok(backing) = row_backing(section, page.spec, start, row_end) else {
                        continue;
                    };
                    let Some(address) = u64::try_from(start)
                        .ok()
                        .and_then(|offset| page.spec.address.checked_add(offset))
                    else {
                        continue;
                    };
                    let (rect, _) = ui.allocate_exact_size(
                        egui::vec2(glyph * 145.0, row_height),
                        egui::Sense::hover(),
                    );
                    let painter = ui.painter();
                    painter.text(
                        rect.min,
                        egui::Align2::LEFT_TOP,
                        format!("{address:016x}"),
                        font.clone(),
                        theme::MUTED,
                    );
                    let hex_x = rect.left() + glyph * 19.0;
                    let ascii_x = hex_x + glyph * 51.0;
                    for offset in start..row_end {
                        let column = offset - start;
                        let Ok((byte_address, file_offset)) =
                            byte_location(section, page.spec, offset)
                        else {
                            continue;
                        };
                        let byte = page.bytes[offset];
                        let color = if file_offset.is_some() {
                            theme::TEXT
                        } else {
                            theme::MUTED
                        };
                        let hex = format!("{byte:02x}");
                        let ascii = if (0x20..=0x7e).contains(&byte) {
                            char::from(byte)
                        } else {
                            '.'
                        }
                        .to_string();
                        let hex_rect = egui::Rect::from_min_size(
                            egui::pos2(
                                hex_x + glyph * (column * 3 + usize::from(column >= 8)) as f32,
                                rect.top(),
                            ),
                            egui::vec2(glyph * 2.5, row_height),
                        );
                        let ascii_rect = egui::Rect::from_min_size(
                            egui::pos2(ascii_x + glyph * column as f32, rect.top()),
                            egui::vec2(glyph, row_height),
                        );
                        for (view, cell, text) in
                            [("hex", hex_rect, hex), ("ascii", ascii_rect, ascii)]
                        {
                            let response = ui.interact(
                                cell,
                                ui.scope_id().with(("hex-byte", offset, view)),
                                egui::Sense::click(),
                            );
                            if selected
                                .as_ref()
                                .is_some_and(|range| range.contains(&offset))
                            {
                                painter.rect_filled(cell, 1, theme::SELECTION);
                            } else if response.hovered() {
                                painter.rect_filled(cell, 1, theme::CURRENT_LINE);
                            }
                            painter.text(
                                cell.min,
                                egui::Align2::LEFT_TOP,
                                text,
                                font.clone(),
                                color,
                            );
                            if response.clicked() {
                                click = Some((offset, ui.input(|input| input.modifiers.shift)));
                            }
                            response.on_hover_ui(|ui| {
                                ui.monospace(format!("VA {byte_address:#x} · {byte:02x}"));
                                match file_offset {
                                    Some(offset) => {
                                        ui.monospace(format!("File offset {offset:#x}"));
                                    }
                                    None => {
                                        ui.weak("Zero-fill; no file offset");
                                    }
                                }
                            });
                        }
                    }
                    let status = match backing.file_offset {
                        Some(offset) => format!(
                            "file {} B @ {offset:#x}; zero-fill {} B",
                            backing.file_bytes, backing.zero_bytes
                        ),
                        None => format!("zero-fill {} B; no file offset", backing.zero_bytes),
                    };
                    painter.text(
                        egui::pos2(ascii_x + glyph * 18.0, rect.top()),
                        egui::Align2::LEFT_TOP,
                        status,
                        font.clone(),
                        theme::MUTED,
                    );
                }
            },
        );
        if let Some((offset, shift)) = click {
            self.select_offset(offset, shift);
            ui.ctx().request_repaint();
        }
    }
}

fn parse_address(text: &str) -> Result<u64, &'static str> {
    let text = text.trim();
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    u64::from_str_radix(text, 16).map_err(|_| "Enter a valid hexadecimal virtual address")
}

fn section_end(section: &SectionInfo) -> Result<u64, String> {
    section
        .address
        .checked_add(section.size)
        .ok_or_else(|| "Section virtual range overflows".into())
}

fn validate_section(section: &SectionInfo) -> Result<(), String> {
    if section.size == 0 {
        return Err("Empty section (0 bytes)".into());
    }
    section_end(section)?;
    section
        .file_offset
        .checked_add(section.file_size)
        .ok_or("Section file range overflows")?;
    Ok(())
}

fn contains(section: &SectionInfo, address: u64) -> bool {
    section.size != 0
        && section_end(section).is_ok_and(|end| section.address <= address && address < end)
}

fn page_for(index: usize, section: &SectionInfo, address: u64) -> Result<PageSpec, String> {
    validate_section(section)?;
    if !contains(section, address) {
        return Err("Address lies outside this section".into());
    }
    let capacity = u64::try_from(PAGE_BYTES).map_err(|_| "Invalid Hex page limit")?;
    if capacity == 0 {
        return Err("Byte reading is disabled by the shared limit".into());
    }
    let offset = address
        .checked_sub(section.address)
        .ok_or("Address precedes section")?;
    let aligned = (offset / capacity)
        .checked_mul(capacity)
        .ok_or("Page alignment overflow")?;
    let base = section
        .address
        .checked_add(aligned)
        .ok_or("Page address overflow")?;
    let length = section
        .size
        .checked_sub(aligned)
        .ok_or("Page exceeds section")?
        .min(capacity);
    base.checked_add(length).ok_or("Page end overflow")?;
    // Only the page-sized value, never the section size or absolute address,
    // crosses into usize. Huge virtual zero-fill tails remain metadata.
    let length = usize::try_from(length).map_err(|_| "Page does not fit host offsets")?;
    Ok(PageSpec {
        section: index,
        address: base,
        length,
    })
}

/// The default page for `address`, unless a fully file-backed span of at most
/// one page crosses its end: then a page beginning at `address`, clipped to the
/// section. Longer or zero-fill spans keep the default page.
fn span_page(
    index: usize,
    section: &SectionInfo,
    address: u64,
    length: u64,
) -> Result<PageSpec, String> {
    let page = page_for(index, section, address)?;
    let backed_end = section
        .address
        .checked_add(section.file_size.min(section.size))
        .ok_or("Section virtual range overflows")?;
    let page_end = page
        .address
        .checked_add(u64::try_from(page.length).map_err(|_| "Invalid page length")?)
        .ok_or("Page end overflow")?;
    let crosses = length > 1
        && usize::try_from(length).is_ok_and(|length| length <= PAGE_BYTES)
        && address
            .checked_add(length)
            .is_some_and(|end| end <= backed_end && end > page_end);
    if crosses {
        page_at(index, section, address)
    } else {
        Ok(page)
    }
}

/// A page beginning exactly at `address`, at most one page and within the section.
fn page_at(index: usize, section: &SectionInfo, address: u64) -> Result<PageSpec, String> {
    validate_section(section)?;
    if !contains(section, address) {
        return Err("Address lies outside this section".into());
    }
    let remaining = section_end(section)?
        .checked_sub(address)
        .ok_or("Address exceeds section")?;
    let length = remaining.min(u64::try_from(PAGE_BYTES).map_err(|_| "Invalid Hex page limit")?);
    let length = usize::try_from(length).map_err(|_| "Page does not fit host offsets")?;
    Ok(PageSpec {
        section: index,
        address,
        length,
    })
}

/// Whether `page` is still a default or exact-span page of `section`.
fn still_valid(page: PageSpec, section: &SectionInfo) -> bool {
    page_for(page.section, section, page.address).ok() == Some(page)
        || page_at(page.section, section, page.address).ok() == Some(page)
}

fn page_offset(page: PageSpec, address: u64) -> Result<usize, String> {
    let offset = address
        .checked_sub(page.address)
        .ok_or("Address precedes page")?;
    let length = u64::try_from(page.length).map_err(|_| "Invalid page length")?;
    if offset >= length {
        return Err("Address exceeds page".into());
    }
    usize::try_from(offset).map_err(|_| "Page offset does not fit host offsets".into())
}

fn byte_location(
    section: &SectionInfo,
    page: PageSpec,
    offset: usize,
) -> Result<(u64, Option<u64>), String> {
    if offset >= page.length || offset >= PAGE_BYTES {
        return Err("Byte offset exceeds page".into());
    }
    let offset = u64::try_from(offset).map_err(|_| "Invalid page offset")?;
    let address = page
        .address
        .checked_add(offset)
        .ok_or("Byte address overflow")?;
    let relative = address
        .checked_sub(section.address)
        .ok_or("Byte precedes section")?;
    if relative >= section.size {
        return Err("Byte exceeds section".into());
    }
    let file_offset = if relative < section.file_size.min(section.size) {
        Some(
            section
                .file_offset
                .checked_add(relative)
                .ok_or("Byte file offset overflow")?,
        )
    } else {
        None
    };
    Ok((address, file_offset))
}

#[derive(Debug, PartialEq, Eq)]
struct RowBacking {
    file_offset: Option<u64>,
    file_bytes: usize,
    zero_bytes: usize,
}

fn row_backing(
    section: &SectionInfo,
    page: PageSpec,
    start: usize,
    end: usize,
) -> Result<RowBacking, String> {
    if end <= start || end > page.length || end > PAGE_BYTES {
        return Err("Invalid page row range".into());
    }
    let (address, file_offset) = byte_location(section, page, start)?;
    let relative = address
        .checked_sub(section.address)
        .ok_or("Row precedes section")?;
    let count = end.checked_sub(start).ok_or("Invalid row size")?;
    let backed = section.file_size.min(section.size);
    let remaining = if relative < backed {
        backed
            .checked_sub(relative)
            .ok_or("Invalid row backing range")?
    } else {
        0
    };
    let file_bytes = remaining.min(u64::try_from(count).map_err(|_| "Invalid row size")?);
    if let Some(offset) = file_offset {
        offset
            .checked_add(file_bytes)
            .ok_or("Row file end overflow")?;
    }
    let file_bytes = usize::try_from(file_bytes).map_err(|_| "Invalid row backing size")?;
    let zero_bytes = count
        .checked_sub(file_bytes)
        .ok_or("Invalid row backing size")?;
    Ok(RowBacking {
        file_offset,
        file_bytes,
        zero_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(address: u64, size: u64, file_size: u64) -> SectionInfo {
        SectionInfo {
            name: ".data".into(),
            address,
            size,
            file_offset: 0x80,
            file_size,
            executable: false,
        }
    }

    fn read(action: Option<HexAction>) -> (u64, u64, usize) {
        match action.expect("expected read action") {
            HexAction::Read {
                token,
                address,
                length,
            } => (token, address, length),
            HexAction::Decode { .. } => panic!("unexpected decode action"),
        }
    }

    fn deliver(panel: &mut HexPanel, request: (u64, u64, usize)) {
        let (token, address, length) = request;
        panel.accept(token, address, vec![0; length]).unwrap();
    }

    fn frame(
        context: &egui::Context,
        panel: &mut HexPanel,
        sections: &[SectionInfo],
        width: f32,
    ) -> Option<HexAction> {
        let mut action = None;
        let mut output = context.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 640.0),
                )),
                ..Default::default()
            },
            |ui| {
                if let Some(next) = panel.show(ui, sections) {
                    assert!(action.is_none(), "more than one action in one UI frame");
                    action = Some(next);
                }
            },
        );
        output.textures_delta.clear();
        action
    }

    #[test]
    fn unaligned_section_pages_are_relative_and_last_page_is_clipped() {
        let sections = [section(0x1003, 0x2005, 0x1007)];
        let mut panel = HexPanel::default();
        let first = read(panel.open_section(0, &sections));
        assert_eq!((first.1, first.2), (0x1003, 4096));
        deliver(&mut panel, first);
        panel.select_offset(2, false);
        let middle = read(panel.turn_page(0x2003, &sections));
        assert_eq!((middle.1, middle.2), (0x2003, 4096));
        deliver(&mut panel, middle);
        assert!(panel.selected_bytes().is_none(), "paging clears selection");
        let last = read(panel.go_to(0x3007, &sections));
        assert_eq!((last.1, last.2), (0x3003, 5));
        assert_eq!(panel.neighbor(&sections, false), Some(0x2003));
        assert_eq!(panel.neighbor(&sections, true), None);
        deliver(&mut panel, last);
        assert_eq!(panel.selected_bytes(), Some((0x3007, vec![0])));
        assert!(panel.go_to(0x3008, &sections).is_none());
        assert_eq!(panel.loaded_page().unwrap().0, 0x3003);
    }

    #[test]
    fn successive_span_navigation_renews_pending_page_without_losing_the_exact_span() {
        let sections = [section(0x2000, 0x100, 0x100)];
        let mut panel = HexPanel::default();
        let old = read(panel.go_to_span(0x2008, 8, &sections));
        let latest = read(panel.go_to_span(0x2020, 4, &sections));
        assert_ne!(old.0, latest.0);
        assert!(!panel.expects(old.0, old.1, old.2));
        assert!(panel.expects(latest.0, latest.1, latest.2));
        assert_eq!(panel.focused_span(), Some((0x2020, 4)));
        deliver(&mut panel, latest);
        assert_eq!(panel.selected_bytes(), Some((0x2020, vec![0; 4])));
    }

    #[test]
    fn exact_spans_select_only_file_backed_bytes_of_their_page() {
        // 0x40 file-backed bytes followed by zero-fill.
        let sections = [section(0x2000, 0x100, 0x40)];
        let mut panel = HexPanel::default();
        let request = read(panel.go_to_span(0x2008, 8, &sections));
        deliver(&mut panel, request);
        assert_eq!(panel.selected_bytes(), Some((0x2008, vec![0; 8])));
        // Clipped where file backing ends; within the loaded page.
        assert!(panel.go_to_span(0x203c, 8, &sections).is_none());
        assert_eq!(panel.selected_bytes(), Some((0x203c, vec![0; 4])));
        // Unbacked bytes keep only the exact focus; a span never grows past it.
        assert!(panel.go_to_span(0x20f0, 8, &sections).is_none());
        assert_eq!(panel.selected_bytes(), Some((0x20f0, vec![0])));
        assert!(panel.go_to_span(0x2100, 8, &sections).is_none());
        assert_eq!(panel.selected_bytes(), Some((0x20f0, vec![0])));
    }

    #[test]
    fn crossing_spans_read_a_page_at_their_start_and_paging_returns_to_default_pages() {
        // Pages default to 0x1000, 0x2000, 0x3000; all bytes are file-backed.
        let sections = [section(0x1000, 0x2800, 0x2800)];
        let mut panel = HexPanel::default();
        let request = read(panel.go_to_span(0x1ff0, 0x20, &sections));
        assert_eq!((request.1, request.2), (0x1ff0, PAGE_BYTES));
        deliver(&mut panel, request);
        assert_eq!(panel.focused_span(), Some((0x1ff0, 0x20)));
        assert_eq!(panel.selected_bytes(), Some((0x1ff0, vec![0; 0x20])));
        // Prev reaches the section's first page even within its first 4 KiB.
        assert_eq!(panel.neighbor(&sections, false), Some(0x1000));
        assert_eq!(panel.neighbor(&sections, true), Some(0x2000));
        // A Retry of the exact page is not mistaken for changed metadata.
        panel.cancel("interrupted");
        let retry = read(panel.retry(&sections));
        assert_eq!((retry.1, retry.2), (0x1ff0, PAGE_BYTES));
        deliver(&mut panel, retry);
        let previous = read(panel.turn_page(0x1000, &sections));
        assert_eq!((previous.1, previous.2), (0x1000, PAGE_BYTES));
        assert_eq!(panel.neighbor(&sections, false), None);
        // Near the section end the exact page is clipped to the section.
        let tail = read(panel.go_to_span(0x37f8, 8, &sections));
        assert_eq!((tail.1, tail.2), (0x3000, 0x800));
        let crossing = read(panel.go_to_span(0x2ffc, 8, &sections));
        assert_eq!((crossing.1, crossing.2), (0x2ffc, 0x804));
        deliver(&mut panel, crossing);
        assert_eq!(panel.selected_bytes(), Some((0x2ffc, vec![0; 8])));
        assert_eq!(panel.neighbor(&sections, false), Some(0x2000));
        assert_eq!(panel.neighbor(&sections, true), None);
    }

    #[test]
    fn oversized_or_zero_fill_spans_keep_default_page_clipping() {
        let sections = [section(0x1000, 0x3000, 0x1004)];
        let mut panel = HexPanel::default();
        // Longer than a page: default page, clipped selection.
        let long = read(panel.go_to_span(0x1ff0, PAGE_BYTES as u64 + 1, &sections));
        assert_eq!((long.1, long.2), (0x1000, PAGE_BYTES));
        deliver(&mut panel, long);
        assert_eq!(panel.focused_span(), Some((0x1ff0, 0x10)));
        // Crossing into zero-fill: default page, file-backed bytes only.
        assert!(panel.go_to_span(0x1ffc, 0x10, &sections).is_none());
        assert_eq!(panel.focused_span(), Some((0x1ffc, 4)));
        // A second jump into an in-flight exact page gets a fresh token.
        let first = read(panel.go_to_span(0x1ff8, 0x0c, &sections));
        let second = read(panel.go_to_span(0x1ff8, 0x0c, &sections));
        assert_eq!(first.1, 0x1ff8);
        assert_ne!(first.0, second.0);
        assert!(!panel.expects(first.0, first.1, first.2));
        assert!(panel.expects(second.0, second.1, second.2));
    }

    #[test]
    fn bss_page_near_the_top_of_a_huge_section_stays_bounded() {
        let sections = [section(0, u64::MAX, 3)];
        let mut panel = HexPanel::default();
        let request = read(panel.go_to(u64::MAX - 1, &sections));
        assert_eq!((request.1, request.2), (u64::MAX - 4095, 4095));
        assert!(request.2 <= PAGE_BYTES);
        deliver(&mut panel, request);
        let page = panel.target.unwrap();
        assert_eq!(
            byte_location(&sections[0], page, 4094).unwrap(),
            (u64::MAX - 1, None)
        );
        assert!(panel.go_to(u64::MAX, &sections).is_none());
        assert_eq!(panel.loaded_page().unwrap().1.len(), 4095);
        assert!(panel.pending.is_none());
    }

    #[test]
    fn gap_empty_and_overflow_navigation_cannot_discard_a_valid_page_or_selection() {
        let mut file_overflow = section(0x3000, 16, 16);
        file_overflow.file_offset = u64::MAX - 8;
        let sections = [
            section(0x1000, 32, 32),
            section(0x2000, 0, 0),
            section(u64::MAX - 8, 16, 0),
            file_overflow,
        ];
        let mut panel = HexPanel::default();
        let request = read(panel.go_to(0x1005, &sections));
        deliver(&mut panel, request);
        for address in [0x1020, 0x2000, 0x3000, u64::MAX] {
            assert!(panel.go_to(address, &sections).is_none());
            assert!(panel.navigation_error.is_some());
            assert_eq!(panel.loaded_page().unwrap().0, 0x1000);
            assert_eq!(panel.selected_bytes(), Some((0x1005, vec![0])));
            assert!(!panel.is_loading());
        }
        assert!(panel.open_section(1, &sections).is_none());
        assert!(panel.open_section(2, &sections).is_none());
        assert!(panel.open_section(usize::MAX, &sections).is_none());
        assert!(panel.loaded_page().is_some());
        assert_eq!(panel.generation, request.0);
    }

    #[test]
    fn mixed_backing_counts_actual_file_bytes_and_never_gives_bss_a_file_offset() {
        let section = section(0x1003, 40, 19);
        let page = page_for(0, &section, 0x1003).unwrap();
        assert_eq!(
            row_backing(&section, page, 0, 16).unwrap(),
            RowBacking {
                file_offset: Some(0x80),
                file_bytes: 16,
                zero_bytes: 0,
            }
        );
        assert_eq!(
            row_backing(&section, page, 16, 32).unwrap(),
            RowBacking {
                file_offset: Some(0x90),
                file_bytes: 3,
                zero_bytes: 13,
            }
        );
        assert_eq!(
            byte_location(&section, page, 18).unwrap(),
            (0x1015, Some(0x92))
        );
        assert_eq!(byte_location(&section, page, 19).unwrap(), (0x1016, None));
        assert_eq!(
            row_backing(&section, page, 32, 40).unwrap(),
            RowBacking {
                file_offset: None,
                file_bytes: 0,
                zero_bytes: 8,
            }
        );
        let mut padded_file = section;
        padded_file.file_size = 128;
        assert_eq!(
            row_backing(&padded_file, page, 32, 40).unwrap().file_bytes,
            8
        );
        assert!(byte_location(&padded_file, page, 40).is_err());
    }

    #[test]
    fn file_ranges_can_end_at_u64_max_but_cannot_wrap() {
        let mut section = section(u64::MAX - 32, 32, 17);
        section.file_offset = u64::MAX - 17;
        let page = page_for(0, &section, u64::MAX - 1).unwrap();
        assert_eq!(
            byte_location(&section, page, 16).unwrap(),
            (u64::MAX - 16, Some(u64::MAX - 1))
        );
        assert_eq!(
            byte_location(&section, page, 17).unwrap(),
            (u64::MAX - 15, None)
        );
        assert_eq!(row_backing(&section, page, 16, 32).unwrap().file_bytes, 1);
        section.file_offset = u64::MAX - 16;
        assert!(page_for(0, &section, section.address).is_err());
    }

    #[test]
    fn live_reply_requires_exact_address_length_and_token() {
        let sections = [section(0x1000, 19, 19)];
        let mut panel = HexPanel::default();
        let (token, address, length) = read(panel.open_section(0, &sections));
        assert!(panel.expects(token, address, length));
        assert!(!panel.expects(token, address + 1, length));
        assert!(!panel.expects(token, address, length - 1));
        assert!(!panel.expects(token, address, length + 1));
        assert!(!panel.expects(token + 1, address, length));
        assert!(panel.accept(token + 1, address, vec![7; length]).is_err());
        assert!(panel.is_loading());
        assert!(panel.accept(token, address + 1, vec![7; length]).is_err());
        assert!(!panel.is_loading());
        assert!(panel.loaded_page().is_none());
        let request = read(panel.retry(&sections));
        assert!(
            panel
                .accept(request.0, address, vec![7; length + 1])
                .is_err()
        );
        let request = read(panel.retry(&sections));
        assert!(
            panel
                .accept(request.0, address, vec![7; length - 1])
                .is_err()
        );
        let request = read(panel.retry(&sections));
        panel.accept(request.0, address, vec![7; length]).unwrap();
        assert_eq!(panel.loaded_page(), Some((address, &[7_u8; 19][..])));
        assert!(panel.accept(request.0, address, vec![8; length]).is_err());
        assert_eq!(panel.loaded_page().unwrap().1[0], 7);
    }

    #[test]
    fn stale_failure_and_canceled_reply_cannot_change_a_new_request() {
        let sections = [section(0x1000, 8192, 8192)];
        let mut panel = HexPanel::default();
        let old = read(panel.open_section(0, &sections));
        let current = read(panel.go_to(0x2000, &sections));
        panel.fail(old.0, "stale error");
        assert!(panel.error.is_none());
        assert!(panel.accept(old.0, old.1, vec![0; old.2]).is_err());
        assert!(panel.expects(current.0, current.1, current.2));
        panel.cancel("Canceled by parent");
        assert!(!panel.expects(current.0, current.1, current.2));
        assert!(
            panel
                .accept(current.0, current.1, vec![0; current.2])
                .is_err()
        );
        assert_eq!(panel.error.as_deref(), Some("Canceled by parent"));
        assert!(panel.go_to(0x2001, &sections).is_none());
        assert!(!panel.is_loading());
        let retried = read(panel.retry(&sections));
        assert!(retried.0 > current.0);
        panel.fail(current.0, "late failure");
        assert!(panel.expects(retried.0, retried.1, retried.2));
        deliver(&mut panel, retried);
        assert!(panel.error.is_none());
    }

    #[test]
    fn selection_uses_exact_page_slice_with_a_stable_shift_anchor() {
        let sections = [section(0x1003, 4112, 4112)];
        let mut panel = HexPanel::default();
        let (token, address, length) = read(panel.open_section(0, &sections));
        let mut bytes = vec![0; length];
        bytes[2..7].copy_from_slice(&[0x20, 0x41, 0x7e, 0x7f, 0xff]);
        panel.accept(token, address, bytes).unwrap();
        assert!(panel.selected_bytes().is_none());
        panel.select_offset(6, false);
        panel.select_offset(2, true);
        assert_eq!(
            panel.selected_bytes(),
            Some((0x1005, vec![0x20, 0x41, 0x7e, 0x7f, 0xff]))
        );
        panel.select_offset(4, true);
        assert_eq!(
            panel.selected_bytes(),
            Some((0x1007, vec![0x7e, 0x7f, 0xff]))
        );
        panel.select_offset(3, false);
        assert_eq!(panel.selected_bytes(), Some((0x1006, vec![0x41])));
        panel.select_offset(PAGE_BYTES, true);
        assert_eq!(panel.selected_bytes(), Some((0x1006, vec![0x41])));
        let request = read(panel.go_to(0x2003, &sections));
        assert!(panel.loaded_page().is_none());
        assert!(panel.selected_bytes().is_none());
        deliver(&mut panel, request);
        assert_eq!(panel.selected_bytes(), Some((0x2003, vec![0])));
    }

    #[test]
    fn hex_and_ascii_clicks_share_selection_and_decode_the_exact_slice() {
        let context = egui::Context::default();
        theme::install(&context);
        let sections = [section(0x1000, 3, 2)];
        let mut panel = HexPanel::default();
        let (token, address, _) = read(panel.open_section(0, &sections));
        panel.accept(token, address, vec![0x41, 0x7e, 0]).unwrap();
        let frame = |panel: &mut HexPanel, point: Option<egui::Pos2>, shift| {
            let modifiers = egui::Modifiers {
                shift,
                ..Default::default()
            };
            let mut events = vec![egui::Event::ModifiersChanged(modifiers)];
            if let Some(pos) = point {
                events.extend([
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers,
                    },
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: false,
                        modifiers,
                    },
                ]);
            }
            let mut action = None;
            let mut output = context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 640.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ui| {
                    if let Some(next) = panel.show(ui, &sections) {
                        assert!(action.is_none());
                        action = Some(next);
                    }
                },
            );
            output.textures_delta.clear();
            (action, output)
        };
        let position = |output: &egui::FullOutput, label: &str| {
            output
                .shapes
                .iter()
                .find_map(|shape| match &shape.shape {
                    egui::epaint::Shape::Text(text) if text.galley.text() == label => {
                        Some(text.pos + text.galley.size() * 0.5)
                    }
                    _ => None,
                })
                .expect("visible byte or action")
        };
        let _ = frame(&mut panel, None, false);
        let (_, output) = frame(&mut panel, None, false);
        let first_hex = position(&output, "41");
        assert!(frame(&mut panel, Some(first_hex), false).0.is_none());
        assert_eq!(panel.selected_bytes(), Some((0x1000, vec![0x41])));
        let (_, output) = frame(&mut panel, None, false);
        let second_ascii = position(&output, "~");
        assert!(frame(&mut panel, Some(second_ascii), true).0.is_none());
        assert_eq!(panel.selected_bytes(), Some((0x1000, vec![0x41, 0x7e])));
        let (_, output) = frame(&mut panel, None, false);
        let decode = position(&output, "Decode selection");
        assert_eq!(
            frame(&mut panel, Some(decode), false).0,
            Some(HexAction::Decode {
                address: 0x1000,
                bytes: vec![0x41, 0x7e],
            })
        );
        assert_eq!(panel.loaded_page(), Some((0x1000, &[0x41, 0x7e, 0][..])));
    }

    #[test]
    fn headless_states_initialize_once_and_never_retry_on_idle_frames() {
        let context = egui::Context::default();
        theme::install(&context);
        let mut panel = HexPanel::default();
        assert!(frame(&context, &mut panel, &[], 480.0).is_none());
        let sections = [section(0, 0, 0), section(0x1003, 8195, 4099)];
        let first = read(frame(&context, &mut panel, &sections, 480.0));
        assert_eq!((first.1, first.2), (0x1003, 4096));
        for _ in 0..3 {
            assert!(frame(&context, &mut panel, &sections, 480.0).is_none());
        }
        assert_eq!(panel.scroll_row, Some(0));
        panel.fail(first.0, "Read failed");
        for _ in 0..3 {
            assert!(frame(&context, &mut panel, &sections, 480.0).is_none());
        }
        assert!(panel.open_section(1, &sections).is_none());
        assert!(!panel.is_loading());
        let retried = read(panel.retry(&sections));
        deliver(&mut panel, retried);
        assert!(frame(&context, &mut panel, &sections, 1200.0).is_none());
        assert_eq!(panel.scroll_row, None);
        assert!(panel.go_to(0x1f80, &sections).is_none());
        assert_eq!(panel.scroll_row, Some((0x1f80 - 0x1003) / 16));
        assert!(frame(&context, &mut panel, &sections, 320.0).is_none());
        assert_eq!(panel.scroll_row, None);
        for _ in 0..3 {
            assert!(frame(&context, &mut panel, &sections, 320.0).is_none());
        }
        let last = read(panel.go_to(0x3004, &sections));
        deliver(&mut panel, last);
        assert!(frame(&context, &mut panel, &sections, 1200.0).is_none());
        panel.cancel("Canceled");
        for _ in 0..3 {
            assert!(frame(&context, &mut panel, &sections, 480.0).is_none());
        }
    }

    #[test]
    fn all_empty_or_invalid_sections_do_not_issue_automatic_repeated_reads() {
        let mut empty = HexPanel::default();
        assert!(empty.initialize(&[section(0x1000, 0, 0)]).is_none());
        assert!(empty.initialize(&[section(0x1000, 16, 16)]).is_none());
        let mut invalid = HexPanel::default();
        let sections = [section(u64::MAX, 1, 0)];
        assert!(invalid.initialize(&sections).is_none());
        assert!(invalid.initialize(&sections).is_none());
        assert_eq!(invalid.generation, 0);
        assert!(invalid.navigation_error.is_some());
        let mut canceled = HexPanel::default();
        canceled.cancel("Canceled before first frame");
        assert!(canceled.initialize(&[section(0x1000, 16, 16)]).is_none());
    }

    #[test]
    fn token_exhaustion_preserves_loaded_bytes_instead_of_reusing_a_token() {
        let sections = [section(0x1000, 8192, 8192)];
        let mut panel = HexPanel::default();
        let request = read(panel.open_section(0, &sections));
        deliver(&mut panel, request);
        panel.generation = u64::MAX;
        assert!(panel.go_to(0x2000, &sections).is_none());
        assert!(panel.navigation_error.is_some());
        assert_eq!(panel.loaded_page().unwrap().0, 0x1000);
        assert!(!panel.is_loading());
    }
}
