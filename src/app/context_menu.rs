//! Exact-target context menus. A secondary click captures the clicked row
//! or pseudocode byte once, bound to the state it was resolved against.
//! Items are derived from that capture alone, never from the selection, a
//! display position or printed text, and a command runs only after the
//! binding and the item are revalidated.

use std::borrow::Cow;
use std::sync::{Arc, Weak};

use eframe::egui;

use super::{DesktopApp, Tab, code_lines, graph_view, hex, listing_of, semantics_of};
use crate::function_presentation::{PreparedDecompilation, PreparedGraph};
use crate::model::{BinaryInfo, Instruction, StringEntry, function_at};
use crate::result_store::Stored;
use crate::semantic::{SemanticToken, TokenKind};
use crate::table_sort::{bounded_text, tsv_row};
use crate::theme;
use crate::xrefs::{TargetKind, TargetSet, XrefTarget};

/// What a menu was opened on: stable identities only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MenuSource {
    /// A Listing row of the function at `entry`.
    Instruction {
        entry: u64,
        pc: u64,
    },
    /// A pseudocode line of the function at `entry`, and the clicked byte
    /// when the click landed on its text.
    Code {
        entry: u64,
        line: usize,
        byte: Option<usize>,
    },
    FunctionRow(u64),
    /// A Strings row: its index in the scanned list and its start.
    StringRow {
        index: usize,
        address: u64,
    },
    TreeFunction(u64),
    TreeLabel(u64),
    TreeString {
        index: usize,
        address: u64,
    },
    TreeSection(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MenuCommand {
    GoTo,
    ShowGraph,
    ShowHex,
    Rename,
    Comment,
    Xrefs(XrefTarget),
    CopyAddress,
    CopyBytes,
    CopyInstruction,
    CopyToken,
    CopyLine,
    CopyRow,
    Decode,
}

/// The state a capture was resolved against. Snapshots are held weakly, so
/// their addresses cannot be reused while compared and nothing is pinned.
#[derive(Clone, Debug)]
struct MenuBinding {
    generation: u64,
    selection: u64,
    revision: u64,
    references: u64,
    /// Source list publication and rebuild epochs of table and tree rows.
    rows: (u64, u64),
    tab: Option<Tab>,
    graph: Option<Weak<Stored<PreparedGraph>>>,
    code: Option<Weak<Stored<PreparedDecompilation>>>,
}

fn same<T>(a: &Option<Weak<T>>, b: &Option<Weak<T>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Weak::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

impl PartialEq for MenuBinding {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.selection == other.selection
            && self.revision == other.revision
            && self.references == other.references
            && self.rows == other.rows
            && self.tab == other.tab
            && same(&self.graph, &other.graph)
            && same(&self.code, &other.code)
    }
}

struct ActiveMenu {
    source: MenuSource,
    binding: MenuBinding,
}

/// The one open exact-target menu of the desktop.
#[derive(Default)]
pub(super) struct ContextMenus {
    active: Option<ActiveMenu>,
    /// The frame a menu last owned input, including its closing frame.
    input_frame: Option<u64>,
}

struct MenuItem {
    command: MenuCommand,
    label: Cow<'static, str>,
    enabled: bool,
    hover: Option<String>,
}

impl MenuItem {
    fn new(command: MenuCommand, label: &'static str) -> Self {
        Self {
            command,
            label: Cow::Borrowed(label),
            enabled: true,
            hover: None,
        }
    }

    fn enabled(mut self, enabled: bool, disabled_hover: &str) -> Self {
        self.enabled = enabled;
        if !enabled {
            self.hover = Some(disabled_hover.into());
        }
        self
    }

    fn hover(mut self, hover: String) -> Self {
        self.hover = Some(hover);
        self
    }
}

/// Navigation/view, edit/xrefs, then copy/byte tools.
type MenuGroups = [Vec<MenuItem>; 3];

/// Explicit xref choices, then the displayed function when it is distinct.
/// An omitted-count disclosure moves to the last choice's tooltip.
fn xref_items(items: &mut Vec<MenuItem>, targets: &TargetSet, function: Option<u64>) {
    for target in &targets.targets {
        items.push(MenuItem {
            command: MenuCommand::Xrefs(*target),
            label: Cow::Owned(format!(
                "Xrefs to {} {:x}",
                target.kind.label(),
                target.address
            )),
            enabled: true,
            hover: None,
        });
    }
    if targets.omitted() > 0
        && let Some(last) = items.last_mut()
    {
        last.hover = Some(format!("{} more targets omitted", targets.omitted()));
    }
    if let Some(function) = function
        && targets.targets.iter().all(|t| t.address != function)
    {
        items.push(MenuItem::new(
            MenuCommand::Xrefs(XrefTarget {
                address: function,
                kind: TargetKind::Function,
            }),
            "Xrefs to this function",
        ));
    }
}

/// Bytes a string row selects, by its encoding; never zero.
pub(super) fn string_span(string: &StringEntry) -> usize {
    let length = if string.encoding.contains("16") {
        string.text.encode_utf16().count().saturating_mul(2)
    } else {
        string.text.len()
    };
    length.clamp(1, crate::decode::MAX_INPUT)
}

/// Address digits of the Functions table.
pub(super) fn function_digits(info: &BinaryInfo) -> usize {
    theme::address_digits(info.functions.last().map_or(0, |f| f.address))
}

/// Address digits of the Strings table.
pub(super) fn string_digits(info: Option<&BinaryInfo>) -> usize {
    info.map_or(8, |info| {
        theme::address_digits(
            info.sections
                .iter()
                .map(|s| s.address.saturating_add(s.size))
                .max()
                .unwrap_or(0),
        )
    })
}

impl DesktopApp {
    /// The current binding of `source`, or `None` when it no longer exists
    /// in the displayed state.
    fn menu_binding(&self, source: MenuSource) -> Option<MenuBinding> {
        let mut binding = MenuBinding {
            generation: self.generation,
            selection: self.selection_generation,
            revision: self.revision,
            references: self.reference_revision,
            rows: (0, 0),
            tab: None,
            graph: None,
            code: None,
        };
        let functions = (self.source_epochs.inventory, self.table_sorts.function_rows);
        let strings = (self.source_epochs.strings, self.table_sorts.string_rows);
        match source {
            MenuSource::Instruction { entry, .. } => {
                let graph = self.graph.as_ref().filter(|g| g.address() == entry)?;
                binding.graph = Some(Arc::downgrade(graph));
                binding.tab = Some(Tab::Listing);
            }
            MenuSource::Code { entry, .. } => {
                let code = self.code.as_ref().filter(|c| c.address() == entry)?;
                binding.code = Some(Arc::downgrade(code));
                binding.graph = self.graph.as_ref().map(Arc::downgrade);
            }
            MenuSource::FunctionRow(_) | MenuSource::TreeFunction(_) => binding.rows = functions,
            MenuSource::StringRow { .. } => {
                binding.rows = strings;
                binding.tab = Some(Tab::Strings);
            }
            MenuSource::TreeString { .. } => binding.rows = strings,
            MenuSource::TreeLabel(_) | MenuSource::TreeSection(_) => {}
        }
        Some(binding)
    }

    fn menu_current(&self, source: MenuSource) -> bool {
        self.menus.active.as_ref().is_some_and(|menu| {
            menu.source == source && self.menu_binding(source).as_ref() == Some(&menu.binding)
        })
    }

    /// The menu `response` shows this frame. A secondary click captures
    /// `source` into `opened`; afterwards the row keeps showing that
    /// capture, not whatever byte the pointer is over now, while it is
    /// current and its own popup is open.
    pub(super) fn menu_shown(
        &self,
        response: &egui::Response,
        source: MenuSource,
        opened: &mut Option<MenuSource>,
    ) -> Option<MenuSource> {
        if response.secondary_clicked() {
            *opened = Some(source);
            return self.menu_binding(source).map(|_| source);
        }
        let captured = self.menus.active.as_ref()?.source;
        let row = match (captured, source) {
            (
                MenuSource::Code { entry, line, .. },
                MenuSource::Code {
                    entry: shown,
                    line: at,
                    ..
                },
            ) => entry == shown && line == at,
            _ => captured == source,
        };
        (row && self.menu_current(captured)
            && egui::Popup::is_id_open(&response.ctx, egui::Popup::default_response_id(response)))
        .then_some(captured)
    }

    /// Paints the items of `source` into an open popup; a click records one
    /// command and closes the menu.
    pub(super) fn menu_body(
        &self,
        ui: &mut egui::Ui,
        source: MenuSource,
        chosen: &mut Option<(MenuSource, MenuCommand)>,
    ) {
        let mut first = true;
        for group in self.menu_items(source) {
            if group.is_empty() {
                continue;
            }
            if !first {
                ui.separator();
            }
            first = false;
            for item in group {
                let response = ui.add_enabled(item.enabled, egui::Button::new(item.label));
                let response = match &item.hover {
                    Some(hover) if item.enabled => response.on_hover_text(hover),
                    Some(hover) => response.on_disabled_hover_text(hover),
                    None => response,
                };
                if response.clicked() {
                    *chosen = Some((source, item.command));
                    ui.close();
                }
            }
        }
    }

    /// Adopts this frame's capture, then runs at most one command after
    /// revalidating it. The capture is consumed by its first command.
    pub(super) fn finish_menu(
        &mut self,
        opened: Option<MenuSource>,
        chosen: Option<(MenuSource, MenuCommand)>,
        context: &egui::Context,
    ) {
        if self.menus.active.is_some() || opened.is_some() || chosen.is_some() {
            self.menus.input_frame = Some(context.cumulative_frame_nr());
        }
        if let Some(source) = opened {
            self.menus.active = self
                .menu_binding(source)
                .map(|binding| ActiveMenu { source, binding });
        }
        if let Some((source, command)) = chosen {
            self.run_menu(source, command, context);
        }
        if let Some(menu) = &self.menus.active
            && !self.menu_current(menu.source)
        {
            self.menus.active = None;
        }
    }

    /// Releases a dismissed menu once no popup remains open.
    pub(super) fn release_menu(&mut self, context: &egui::Context) {
        if self.menus.active.is_some() && !egui::Popup::is_any_open(context) {
            self.menus.input_frame = Some(context.cumulative_frame_nr());
            self.menus.active = None;
        }
    }

    /// A menu owns keyboard input while open and in the frame it closes.
    pub(super) fn menu_owns_input(&self, context: &egui::Context) -> bool {
        self.menus.input_frame == Some(context.cumulative_frame_nr())
    }

    fn run_menu(&mut self, source: MenuSource, command: MenuCommand, context: &egui::Context) {
        let Some(menu) = self.menus.active.take() else {
            return;
        };
        if menu.source != source
            || self.menu_binding(source).as_ref() != Some(&menu.binding)
            || !self
                .menu_items(source)
                .iter()
                .flatten()
                .any(|item| item.command == command && item.enabled)
        {
            return;
        }
        match command {
            MenuCommand::CopyAddress
            | MenuCommand::CopyBytes
            | MenuCommand::CopyInstruction
            | MenuCommand::CopyToken
            | MenuCommand::CopyLine
            | MenuCommand::CopyRow => {
                if let Some(text) = self.menu_copy_text(source, command) {
                    context.copy_text(text);
                }
            }
            MenuCommand::Xrefs(target) => {
                if let MenuSource::StringRow { address, .. }
                | MenuSource::TreeString { address, .. } = source
                {
                    self.select_string(address);
                }
                self.open_xrefs(target);
            }
            MenuCommand::GoTo => self.menu_go_to(source, context),
            MenuCommand::ShowGraph => {
                if let MenuSource::Instruction { pc, .. } = source {
                    self.select_instruction(pc);
                    self.tab = Tab::Graph;
                    if let Some(canvas) = &mut self.canvas {
                        canvas.reveal_instruction(pc);
                    }
                }
            }
            MenuCommand::ShowHex => match source {
                MenuSource::Instruction { pc, .. } => {
                    if let Some(instruction) = self.menu_instruction(pc) {
                        let length = instruction.bytes.len() as u64;
                        self.navigate_data(pc, length, context);
                    }
                }
                MenuSource::TreeSection(index) => self.open_hex_section(index, context),
                _ => {}
            },
            MenuCommand::Rename => self.menu_rename(source),
            MenuCommand::Comment => match source {
                MenuSource::Instruction { pc, .. } => self.open_comment(pc),
                MenuSource::FunctionRow(address) => {
                    if self.view().is_none_or(|view| view.address != address) {
                        self.navigate(address, true, context);
                    }
                    self.open_comment(address);
                }
                _ => {}
            },
            MenuCommand::Decode => {
                if let MenuSource::Instruction { pc, .. } = source
                    && let Some(bytes) = self.menu_instruction(pc).map(|i| i.bytes.clone())
                {
                    self.decode_loaded_bytes(pc, bytes);
                }
            }
        }
    }

    fn menu_go_to(&mut self, source: MenuSource, context: &egui::Context) {
        match source {
            MenuSource::Instruction { pc, .. } => {
                if let Some(target) = self.listing_follow_target(pc) {
                    self.follow_listing_target(target, context);
                }
            }
            MenuSource::Code { .. } => {
                if let Some(TokenKind::Call { target }) = self.menu_token(source).map(|t| &t.kind) {
                    let target = *target;
                    self.navigate(target, true, context);
                }
            }
            MenuSource::FunctionRow(address) | MenuSource::TreeFunction(address) => {
                self.navigate(address, true, context);
            }
            MenuSource::StringRow { .. } | MenuSource::TreeString { .. } => {
                if let Some(string) = self.menu_string(source) {
                    let (address, span) = (string.address, string_span(string) as u64);
                    self.navigate_data(address, span, context);
                }
            }
            MenuSource::TreeLabel(address) => self.navigate_annotation(address, true, context),
            MenuSource::TreeSection(_) => {}
        }
    }

    /// Opens the rename for the captured identity. Drafts stay bound to the
    /// annotation revision they were opened against.
    fn menu_rename(&mut self, source: MenuSource) {
        match source {
            MenuSource::Instruction { pc, .. } => self.begin_address_rename(pc),
            MenuSource::FunctionRow(address) => self.begin_address_rename(address),
            MenuSource::Code { .. } => match self.menu_token(source).map(|t| t.kind.clone()) {
                Some(TokenKind::Call { target }) => self.begin_address_rename(target),
                Some(TokenKind::Local { local: Some(index) }) => {
                    self.begin_local_rename(index);
                }
                _ => return,
            },
            _ => return,
        }
        if let Some(dialog) = &mut self.browser_dialog {
            dialog.revision = Some(self.revision);
        }
    }

    fn menu_instruction(&self, pc: u64) -> Option<&Instruction> {
        let listing = listing_of(&self.graph);
        listing.position(pc).and_then(|row| listing.get(row))
    }

    fn menu_string(&self, source: MenuSource) -> Option<&StringEntry> {
        let (MenuSource::StringRow { index, address } | MenuSource::TreeString { index, address }) =
            source
        else {
            return None;
        };
        self.strings.get(index).filter(|s| s.address == address)
    }

    /// The semantic token under the captured byte of the bound pseudocode.
    fn menu_token(&self, source: MenuSource) -> Option<&SemanticToken> {
        let MenuSource::Code {
            byte: Some(byte), ..
        } = source
        else {
            return None;
        };
        semantics_of(&self.code).token_at(byte)
    }

    /// The captured pseudocode line, without its line break.
    fn menu_line(&self, line: usize) -> Option<&str> {
        let code = self.code.as_deref()?;
        let &(start, end) = code_lines(&self.code).get(line)?;
        code.text()
            .get(start..end)
            .map(|text| text.trim_end_matches(['\n', '\r']))
    }

    fn menu_items(&self, source: MenuSource) -> MenuGroups {
        let mut groups: MenuGroups = Default::default();
        let [navigation, edit, copy] = &mut groups;
        let Some(info) = self.info.as_ref() else {
            return groups;
        };
        match source {
            MenuSource::Instruction { entry, pc } => {
                let (Some(view), Some(instruction)) =
                    (graph_view(&self.graph), self.menu_instruction(pc))
                else {
                    return groups;
                };
                if let Some(target) = self.listing_follow_target(pc) {
                    navigation.push(
                        MenuItem::new(MenuCommand::GoTo, "Go to target")
                            .hover(format!("{target:x}")),
                    );
                }
                navigation.push(
                    MenuItem::new(MenuCommand::ShowGraph, "Show in Graph")
                        .enabled(self.canvas.is_some(), "No graph"),
                );
                let length = instruction.bytes.len() as u64;
                let backed = length > 0 && info.sections.iter().any(|s| s.backs(pc, length));
                navigation.push(
                    MenuItem::new(MenuCommand::ShowHex, "Show in Hex")
                        .enabled(backed, "No file-backed bytes"),
                );
                edit.push(MenuItem::new(MenuCommand::Rename, "Rename…"));
                edit.push(MenuItem::new(MenuCommand::Comment, "Comment…"));
                let targets = crate::xrefs::instruction_targets(
                    Some((info, view)),
                    self.call_index.as_deref(),
                    entry,
                    [pc],
                );
                xref_items(edit, &targets, Some(entry));
                let bytes = !instruction.bytes.is_empty();
                copy.push(MenuItem::new(MenuCommand::CopyAddress, "Copy address"));
                copy.push(
                    MenuItem::new(MenuCommand::CopyBytes, "Copy bytes").enabled(bytes, "No bytes"),
                );
                copy.push(MenuItem::new(
                    MenuCommand::CopyInstruction,
                    "Copy instruction",
                ));
                copy.push(
                    MenuItem::new(MenuCommand::Decode, "Decode bytes").enabled(bytes, "No bytes"),
                );
            }
            MenuSource::Code { entry, line, byte } => {
                if self.menu_line(line).is_none() {
                    return groups;
                }
                let semantics = semantics_of(&self.code);
                let mapped = || {
                    byte.map_or_else(TargetSet::default, |byte| {
                        crate::xrefs::instruction_targets(
                            graph_view(&self.graph).map(|view| (info, view)),
                            self.call_index.as_deref(),
                            entry,
                            self.semantic.addresses_at(byte).iter().copied(),
                        )
                    })
                };
                match self.menu_token(source).map(|t| &t.kind) {
                    Some(&TokenKind::Call { target }) => {
                        navigation.push(
                            MenuItem::new(MenuCommand::GoTo, "Go to target")
                                .hover(format!("{target:x}")),
                        );
                        edit.push(MenuItem::new(MenuCommand::Rename, "Rename…").enabled(
                            function_at(&info.functions, target).is_some(),
                            "No known function",
                        ));
                        let targets = TargetSet::single(XrefTarget {
                            address: target,
                            kind: TargetKind::CallTarget,
                        });
                        xref_items(edit, &targets, Some(entry));
                        copy.push(MenuItem::new(MenuCommand::CopyToken, "Copy token"));
                        copy.push(MenuItem::new(MenuCommand::CopyAddress, "Copy address"));
                    }
                    Some(&TokenKind::Local { local }) => {
                        let local = local.and_then(|index| semantics.locals.get(index));
                        edit.push(match local {
                            Some(local) if local.signature_parameter.is_some() => {
                                MenuItem::new(MenuCommand::Rename, "Edit signature…")
                            }
                            Some(_) => MenuItem::new(MenuCommand::Rename, "Rename…"),
                            None => MenuItem::new(MenuCommand::Rename, "Rename…")
                                .enabled(false, "No storage identity"),
                        });
                        xref_items(edit, &mapped(), Some(entry));
                        copy.push(MenuItem::new(MenuCommand::CopyToken, "Copy token"));
                    }
                    None => {
                        xref_items(edit, &mapped(), Some(entry));
                        copy.push(MenuItem::new(MenuCommand::CopyLine, "Copy line"));
                    }
                }
            }
            MenuSource::FunctionRow(address) => {
                if function_at(&info.functions, address).is_none() {
                    return groups;
                }
                navigation.push(MenuItem::new(MenuCommand::GoTo, "Go to"));
                edit.push(MenuItem::new(MenuCommand::Rename, "Rename…"));
                edit.push(MenuItem::new(MenuCommand::Comment, "Comment…"));
                xref_items(edit, &TargetSet::default(), Some(address));
                copy.push(MenuItem::new(MenuCommand::CopyRow, "Copy row"));
            }
            MenuSource::TreeFunction(address) => {
                if function_at(&info.functions, address).is_none() {
                    return groups;
                }
                navigation.push(MenuItem::new(MenuCommand::GoTo, "Go to"));
                copy.push(MenuItem::new(MenuCommand::CopyRow, "Copy row"));
            }
            MenuSource::StringRow { address, .. } | MenuSource::TreeString { address, .. } => {
                if self.menu_string(source).is_none() {
                    return groups;
                }
                navigation.push(MenuItem::new(MenuCommand::GoTo, "Go to"));
                edit.push(MenuItem::new(
                    MenuCommand::Xrefs(XrefTarget {
                        address,
                        kind: TargetKind::StringStart,
                    }),
                    "Xrefs to…",
                ));
                copy.push(MenuItem::new(MenuCommand::CopyRow, "Copy row"));
            }
            MenuSource::TreeLabel(address) => {
                if self.menu_label(address).is_none() {
                    return groups;
                }
                navigation.push(MenuItem::new(MenuCommand::GoTo, "Go to"));
                copy.push(MenuItem::new(MenuCommand::CopyRow, "Copy row"));
            }
            MenuSource::TreeSection(index) => {
                if info.sections.get(index).is_none() {
                    return groups;
                }
                navigation.push(MenuItem::new(MenuCommand::ShowHex, "Show in Hex"));
                copy.push(MenuItem::new(MenuCommand::CopyRow, "Copy row"));
            }
        }
        groups
    }

    fn menu_label(&self, address: u64) -> Option<&str> {
        self.session
            .as_ref()?
            .annotations
            .get(&address)
            .map(|note| note.label.as_str())
            .filter(|label| !label.is_empty())
    }

    /// Bounded clipboard text from cached values only.
    fn menu_copy_text(&self, source: MenuSource, command: MenuCommand) -> Option<String> {
        let info = self.info.as_ref()?;
        Some(match (source, command) {
            (MenuSource::Instruction { pc, .. }, MenuCommand::CopyAddress) => format!("{pc:#x}"),
            (MenuSource::Instruction { pc, .. }, MenuCommand::CopyBytes) => {
                hex(&self.menu_instruction(pc)?.bytes)
            }
            (MenuSource::Instruction { pc, .. }, MenuCommand::CopyInstruction) => {
                let instruction = self.menu_instruction(pc)?;
                let operands = !instruction.operands.is_empty();
                bounded_text([
                    instruction.mnemonic.as_str(),
                    if operands { " " } else { "" },
                    instruction.operands.as_str(),
                ])
            }
            (MenuSource::Code { .. }, MenuCommand::CopyToken) => {
                let token = self.menu_token(source)?;
                bounded_text([code_text_slice(&self.code, token.start, token.end)?])
            }
            (MenuSource::Code { .. }, MenuCommand::CopyAddress) => {
                match self.menu_token(source)?.kind {
                    TokenKind::Call { target } => format!("{target:#x}"),
                    TokenKind::Local { .. } => return None,
                }
            }
            (MenuSource::Code { line, .. }, MenuCommand::CopyLine) => {
                bounded_text([self.menu_line(line)?])
            }
            (MenuSource::FunctionRow(address), MenuCommand::CopyRow) => {
                let function = function_at(&info.functions, address)?;
                let (label, _) =
                    super::function_display(self.session.as_ref(), self.symbols(), function);
                let digits = function_digits(info);
                let address = format!("{address:0digits$x}");
                tsv_row([address.as_str(), label])
            }
            (MenuSource::TreeFunction(address), MenuCommand::CopyRow) => {
                let function = function_at(&info.functions, address)?;
                let (label, _) =
                    super::function_display(self.session.as_ref(), self.symbols(), function);
                tsv_row([label])
            }
            (MenuSource::StringRow { address, .. }, MenuCommand::CopyRow) => {
                let string = self.menu_string(source)?;
                let digits = string_digits(Some(info));
                let address = format!("{address:0digits$x}");
                tsv_row([address.as_str(), &string.encoding, &string.text])
            }
            (MenuSource::TreeString { .. }, MenuCommand::CopyRow) => {
                tsv_row([self.menu_string(source)?.text.as_str()])
            }
            (MenuSource::TreeLabel(address), MenuCommand::CopyRow) => {
                tsv_row([self.menu_label(address)?])
            }
            (MenuSource::TreeSection(index), MenuCommand::CopyRow) => {
                let section = info.sections.get(index)?;
                let address = format!("{:x}", section.address);
                tsv_row([section.name.as_str(), address.as_str()])
            }
            _ => return None,
        })
    }
}

/// A validated slice of the displayed pseudocode.
fn code_text_slice(
    code: &Option<super::Shared<PreparedDecompilation>>,
    start: usize,
    end: usize,
) -> Option<&str> {
    code.as_deref()?.text().get(start..end)
}

#[cfg(test)]
mod tests {
    use super::super::tests as fixture;
    use super::super::{BrowserDialogKind, DesktopApp, Tab};
    use super::*;
    use crate::linkage_ui::Place;
    use crate::model::{BasicBlock, CallSite, CodeMapping, FunctionView, Instruction};
    use crate::semantic::{LocalIdentity, LocalStorage, LocalVariable, SemanticInfo};
    use crate::session::Annotation;

    fn instruction(address: u64, bytes: &[u8], mnemonic: &str, operands: &str) -> Instruction {
        Instruction {
            address,
            bytes: bytes.to_vec(),
            mnemonic: mnemonic.into(),
            operands: operands.into(),
        }
    }

    fn view() -> FunctionView {
        FunctionView {
            address: 0x1000,
            blocks: vec![BasicBlock {
                address: 0x1000,
                instructions: vec![
                    instruction(0x1000, &[0x55], "push", "rbp"),
                    instruction(0x1001, &[0xe8, 0x3a, 0, 0, 0], "call", "0x1040"),
                    instruction(0x1006, &[], "nop", ""),
                    instruction(0x1007, &[0xc3], "ret", ""),
                ],
            }],
            edges: vec![],
            calls: vec![CallSite {
                address: 0x1001,
                target: Some(0x1040),
                no_return: None,
            }],
            warnings: vec![],
        }
    }

    /// `entry` calls `next` at 0x1001; 0x1006 has no cached bytes.
    fn menu_app() -> DesktopApp {
        let mut app = fixture::keyboard_app();
        fixture::show_view(&mut app, view());
        app.history = vec![Place::Code(0x1000)];
        app.history_index = 0;
        app
    }

    const SOURCE: &str = "void entry(int p) {\n  x(); x();\n  a = b + c + p;\n}\n";

    fn at(needle: &str) -> usize {
        SOURCE.find(needle).unwrap()
    }

    fn identity(offset: u64) -> LocalIdentity {
        LocalIdentity {
            function: 0x1000,
            engine: crate::semantic::LOCAL_FINGERPRINT.into(),
            storage: LocalStorage::Register,
            offset,
            size: 4,
            verification: "a".repeat(64),
        }
    }

    fn mappings() -> Vec<CodeMapping> {
        vec![
            CodeMapping {
                start: at("x();"),
                end: at("x();") + 4,
                addresses: vec![0x1001],
            },
            CodeMapping {
                start: at("a ="),
                end: at("p;") + 2,
                addresses: vec![0x1000, 0x1007],
            },
        ]
    }

    /// Two printed `x` calls with different targets, the second neither a
    /// known function nor mapped; locals with and without storage identity
    /// and a signature parameter.
    fn semantics() -> SemanticInfo {
        let token = |start: usize, kind| SemanticToken {
            start,
            end: start + 1,
            kind,
        };
        let local = |offset, name: &str, signature_parameter| LocalVariable {
            identity: identity(offset),
            name: name.into(),
            signature_parameter,
        };
        SemanticInfo {
            tokens: vec![
                token(at("p)"), TokenKind::Local { local: Some(2) }),
                token(at("x();"), TokenKind::Call { target: 0x1040 }),
                token(at("x();") + 5, TokenKind::Call { target: 0x1080 }),
                token(at("a ="), TokenKind::Local { local: Some(0) }),
                token(at("b +"), TokenKind::Local { local: Some(1) }),
                token(at("c +"), TokenKind::Local { local: None }),
                token(at("p;"), TokenKind::Local { local: Some(2) }),
            ],
            locals: vec![
                local(0, "a", None),
                local(8, "b", None),
                local(16, "p", Some(0)),
            ],
            ..Default::default()
        }
    }

    fn code_app() -> DesktopApp {
        let mut app = menu_app();
        fixture::show_code(&mut app, SOURCE, mappings(), semantics());
        app
    }

    #[derive(Clone, Copy)]
    enum Pane {
        Listing,
        Decompiler,
    }

    struct Desk {
        context: egui::Context,
        app: DesktopApp,
        time: f64,
        size: egui::Vec2,
    }

    impl Desk {
        fn new(app: DesktopApp) -> Self {
            let context = egui::Context::default();
            theme::install(&context);
            context.all_styles_mut(|style| style.animation_time = 0.0);
            Self {
                context,
                app,
                time: 0.0,
                size: egui::vec2(1000.0, 700.0),
            }
        }

        /// One frame of `pane`, then the desktop's end-of-frame release and
        /// shortcut handling.
        fn frame(&mut self, pane: Pane, events: Vec<egui::Event>) -> egui::FullOutput {
            self.time += 1.0;
            let app = &mut self.app;
            let mut output = self.context.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                    events,
                    time: Some(self.time),
                    ..Default::default()
                },
                |ui| {
                    match pane {
                        Pane::Listing => app.main_panel(ui),
                        Pane::Decompiler => app.side_panel(ui),
                    }
                    app.release_menu(ui.ctx());
                    app.handle_shortcuts(ui.ctx());
                },
            );
            output.textures_delta.clear();
            output
        }

        /// Secondary-clicks `needle` at `byte`, then moves the pointer away;
        /// returns the repainted menu.
        fn open(&mut self, pane: Pane, needle: &str, byte: usize) -> egui::FullOutput {
            if egui::Popup::is_any_open(&self.context) {
                self.frame(pane, vec![escape()]);
            }
            let output = self.frame(pane, vec![]);
            let point = fixture::text_position(&output, needle, byte);
            self.frame(pane, fixture::secondary_events(point));
            self.frame(pane, vec![egui::Event::PointerMoved(egui::pos2(2.0, 2.0))])
        }

        fn choose(&mut self, pane: Pane, menu: &egui::FullOutput, item: &str) -> egui::FullOutput {
            let point = fixture::text_position(menu, item, 0);
            self.frame(pane, fixture::pointer_events(point))
        }

        /// Runs a command of `source` directly, as a stale popup would.
        fn dispatch(&mut self, source: MenuSource, command: MenuCommand) -> egui::FullOutput {
            let app = &mut self.app;
            let mut output = self.context.run_ui(egui::RawInput::default(), |ui| {
                app.finish_menu(None, Some((source, command)), ui.ctx());
            });
            output.textures_delta.clear();
            output
        }
    }

    fn escape() -> egui::Event {
        fixture::key_event(egui::Key::Escape, egui::Modifiers::NONE)
    }

    fn copies(output: &egui::FullOutput) -> Vec<String> {
        output
            .platform_output
            .commands
            .iter()
            .filter_map(|command| match command {
                egui::OutputCommand::CopyText(text) => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    fn shows(output: &egui::FullOutput, item: &str) -> bool {
        fixture::rendered_text(output)
            .iter()
            .any(|text| text == item)
    }

    /// History, selection and navigation generation.
    fn position(app: &DesktopApp) -> (Vec<Place>, Option<u64>, u64) {
        (app.history.clone(), app.selected, app.selection_generation)
    }

    const CALL: MenuSource = MenuSource::Instruction {
        entry: 0x1000,
        pc: 0x1001,
    };

    #[test]
    fn listing_menu_acts_on_the_clicked_row_and_opening_changes_nothing() {
        let mut desk = Desk::new(menu_app());
        desk.app.select_instruction(0x1000);
        let before = position(&desk.app);
        let menu = desk.open(Pane::Listing, "00001001", 3);
        assert_eq!(position(&desk.app), before, "opening never navigates");
        for item in [
            "Go to target",
            "Show in Graph",
            "Show in Hex",
            "Rename…",
            "Comment…",
            "Xrefs to call target 1040",
            "Xrefs to this function",
            "Copy address",
            "Copy bytes",
            "Copy instruction",
            "Decode bytes",
        ] {
            assert!(shows(&menu, item), "{item}");
        }
        for (item, expected) in [
            ("Copy address", "0x1001"),
            ("Copy bytes", "e8 3a 00 00 00"),
            ("Copy instruction", "call 0x1040"),
        ] {
            let menu = desk.open(Pane::Listing, "00001001", 3);
            let output = desk.choose(Pane::Listing, &menu, item);
            assert_eq!(copies(&output), [expected]);
            // Consumed: later frames neither copy again nor reopen it.
            let output = desk.frame(Pane::Listing, vec![]);
            assert!(copies(&output).is_empty() && !shows(&output, item));
        }
        assert_eq!(position(&desk.app), before, "copies never navigate");

        // Edits target the row's own instruction, never its call target.
        let menu = desk.open(Pane::Listing, "00001001", 3);
        desk.choose(Pane::Listing, &menu, "Rename…");
        let dialog = desk.app.browser_dialog.take().unwrap();
        assert!(matches!(
            dialog.kind,
            BrowserDialogKind::Rename {
                address: 0x1001,
                function: false
            }
        ));
        let menu = desk.open(Pane::Listing, "00001001", 3);
        desk.choose(Pane::Listing, &menu, "Comment…");
        assert!(desk.app.annotations_open && desk.app.focus_comment);
        assert_eq!(desk.app.selected, Some(0x1001));
        assert_eq!(desk.app.history, before.0);

        let menu = desk.open(Pane::Listing, "00001001", 3);
        desk.choose(Pane::Listing, &menu, "Show in Graph");
        assert_eq!(
            (desk.app.tab, desk.app.selected),
            (Tab::Graph, Some(0x1001))
        );
        assert_eq!(desk.app.history, before.0, "a view change is not history");

        desk.app.tab = Tab::Listing;
        let menu = desk.open(Pane::Listing, "00001001", 3);
        desk.choose(Pane::Listing, &menu, "Show in Hex");
        assert_eq!(desk.app.tab, Tab::Hex);
        assert_eq!(desk.app.data_location, Some((0x1001, 5)));
        assert_eq!(
            desk.app.history.last(),
            Some(&Place::Data {
                address: 0x1001,
                length: 5
            })
        );
        let recorded = desk.app.history.len();

        desk.app.tab = Tab::Listing;
        let menu = desk.open(Pane::Listing, "00001001", 3);
        desk.choose(Pane::Listing, &menu, "Go to target");
        assert_eq!(desk.app.history.last(), Some(&Place::Code(0x1040)));
        assert_eq!(desk.app.history.len(), recorded + 1);
    }

    #[test]
    fn unavailable_bytes_and_unbacked_spans_disable_their_commands() {
        let mut app = menu_app();
        app.info.as_mut().unwrap().sections[0].file_size = 7;
        let mut desk = Desk::new(app);
        for (row, disabled) in [
            (
                0x1006,
                &[
                    MenuCommand::CopyBytes,
                    MenuCommand::Decode,
                    MenuCommand::ShowHex,
                ][..],
            ),
            (0x1007, &[MenuCommand::ShowHex][..]),
        ] {
            let source = MenuSource::Instruction {
                entry: 0x1000,
                pc: row,
            };
            let groups = desk.app.menu_items(source);
            for item in groups.iter().flatten() {
                assert_eq!(
                    item.enabled,
                    !disabled.contains(&item.command),
                    "{row:x} {}",
                    item.label
                );
            }
            // A disabled item cannot run even from a captured menu.
            desk.open(Pane::Listing, &format!("{row:08x}"), 3);
            let output = desk.dispatch(source, MenuCommand::CopyBytes);
            assert_eq!(copies(&output).is_empty(), row == 0x1006);
        }
        // An instruction without operands copies only its mnemonic.
        desk.open(Pane::Listing, "00001007", 3);
        let output = desk.dispatch(
            MenuSource::Instruction {
                entry: 0x1000,
                pc: 0x1007,
            },
            MenuCommand::CopyInstruction,
        );
        assert_eq!(copies(&output), ["ret"]);
    }

    #[test]
    fn captured_menus_expire_with_their_state_but_survive_repaints() {
        type Change = (&'static str, fn(&mut DesktopApp));
        let changes: [Change; 6] = [
            ("same-entry graph", |app| fixture::show_view(app, view())),
            ("annotation edit", |app| {
                app.edit_annotation(
                    0x1007,
                    Annotation {
                        comment: "changed".into(),
                        ..Default::default()
                    },
                )
            }),
            ("undo", |app| app.undo(&egui::Context::default())),
            ("navigation away and back", |app| {
                let context = egui::Context::default();
                app.navigate(0x1040, true, &context);
                app.navigate(0x1000, true, &context);
                fixture::show_view(app, view());
            }),
            ("reopened binary", |app| app.generation += 1),
            ("reference evidence", |app| app.set_call_index(None)),
        ];
        for (name, change) in changes {
            let mut app = menu_app();
            if name == "undo" {
                app.edit_annotation(
                    0x1007,
                    Annotation {
                        comment: "before".into(),
                        ..Default::default()
                    },
                );
            }
            let mut desk = Desk::new(app);
            desk.open(Pane::Listing, "00001001", 3);
            change(&mut desk.app);
            assert!(
                copies(&desk.dispatch(CALL, MenuCommand::CopyAddress)).is_empty(),
                "{name}"
            );
            let output = desk.frame(Pane::Listing, vec![]);
            assert!(!shows(&output, "Copy address"), "{name}");
            assert!(desk.app.menus.active.is_none(), "{name}");
        }
        // Repaints and pointer movement keep a valid capture.
        let mut desk = Desk::new(menu_app());
        desk.open(Pane::Listing, "00001001", 3);
        for x in [100.0, 600.0, 900.0] {
            let output = desk.frame(
                Pane::Listing,
                vec![egui::Event::PointerMoved(egui::pos2(x, 650.0))],
            );
            assert!(shows(&output, "Copy address"));
        }
        assert_eq!(
            copies(&desk.dispatch(CALL, MenuCommand::CopyAddress)),
            ["0x1001"]
        );

        // The same function's pseudocode or graph replaced under a code
        // menu, with generation, navigation and revisions unchanged.
        let token = MenuSource::Code {
            entry: 0x1000,
            line: 1,
            byte: Some(at("x();")),
        };
        for replace in [
            (|app: &mut DesktopApp| fixture::show_code(app, SOURCE, mappings(), semantics()))
                as fn(&mut DesktopApp),
            |app| fixture::show_view(app, view()),
        ] {
            let mut desk = Desk::new(code_app());
            desk.open(Pane::Decompiler, "x(); x();", 2);
            let key = desk.app.xref_key();
            replace(&mut desk.app);
            assert_eq!(desk.app.xref_key(), key);
            assert!(copies(&desk.dispatch(token, MenuCommand::CopyToken)).is_empty());
            assert!(!shows(&desk.frame(Pane::Decompiler, vec![]), "Copy token"));
        }
    }

    #[test]
    fn decompiler_menus_use_only_semantic_identities() {
        let mut desk = Desk::new(code_app());
        let before = position(&desk.app);
        // Equal printed names, different real targets.
        let menu = desk.open(Pane::Decompiler, "x(); x();", 7);
        for item in ["Go to target", "Rename…", "Copy token", "Copy address"] {
            assert!(shows(&menu, item), "{item}");
        }
        let output = desk.choose(Pane::Decompiler, &menu, "Copy address");
        assert_eq!(copies(&output), ["0x1080"]);
        let unknown = MenuSource::Code {
            entry: 0x1000,
            line: 1,
            byte: Some(at("x();") + 5),
        };
        desk.open(Pane::Decompiler, "x(); x();", 7);
        desk.dispatch(unknown, MenuCommand::Rename);
        assert!(desk.app.browser_dialog.is_none(), "no function is invented");

        let menu = desk.open(Pane::Decompiler, "x(); x();", 2);
        desk.choose(Pane::Decompiler, &menu, "Rename…");
        let dialog = desk.app.browser_dialog.take().unwrap();
        assert!(matches!(
            dialog.kind,
            BrowserDialogKind::Rename {
                address: 0x1040,
                function: true
            }
        ));
        assert_eq!(dialog.revision, Some(desk.app.revision));
        assert_eq!(position(&desk.app), before, "the callee is not visited");

        let menu = desk.open(Pane::Decompiler, "a = b", 6);
        desk.choose(Pane::Decompiler, &menu, "Rename…");
        let dialog = desk.app.browser_dialog.take().unwrap();
        assert!(matches!(
            &dialog.kind,
            BrowserDialogKind::RenameLocal { identity: chosen } if *chosen == identity(8)
        ));
        let menu = desk.open(Pane::Decompiler, "a = b", 6);
        assert_eq!(
            copies(&desk.choose(Pane::Decompiler, &menu, "Copy token")),
            ["b"]
        );

        // A printed local without storage identity can only be copied.
        let menu = desk.open(Pane::Decompiler, "a = b", 10);
        assert!(shows(&menu, "Copy token") && !shows(&menu, "Copy address"));
        let source = MenuSource::Code {
            entry: 0x1000,
            line: 2,
            byte: Some(at("c +")),
        };
        assert!(
            desk.app
                .menu_items(source)
                .iter()
                .flatten()
                .any(|item| item.command == MenuCommand::Rename && !item.enabled)
        );
        desk.dispatch(source, MenuCommand::Rename);
        assert!(desk.app.browser_dialog.is_none());

        let menu = desk.open(Pane::Decompiler, "void entry(int p)", 15);
        assert!(shows(&menu, "Edit signature…") && !shows(&menu, "Rename…"));

        // Mapped text that is not a token: no token, address or rename
        // commands, and no first-of-many PC.
        let menu = desk.open(Pane::Decompiler, "a = b", 4);
        for item in ["Copy token", "Copy address", "Rename…"] {
            assert!(!shows(&menu, item), "{item}");
        }
        assert!(shows(&menu, "Xrefs to this function"));
        let output = desk.choose(Pane::Decompiler, &menu, "Copy line");
        assert_eq!(copies(&output), ["  a = b + c + p;"]);
        assert_eq!(position(&desk.app), before, "secondary clicks never select");

        // Legacy pseudocode cannot rename an older selection.
        let mut app = menu_app();
        fixture::show_code(&mut app, SOURCE, vec![], SemanticInfo::default());
        app.select_instruction(0x1007);
        let mut desk = Desk::new(app);
        let menu = desk.open(Pane::Decompiler, "a = b", 6);
        assert!(shows(&menu, "Copy line") && !shows(&menu, "Rename…"));
        assert!(!shows(&menu, "Copy address") && !shows(&menu, "Copy token"));
    }

    #[test]
    fn an_open_or_closing_menu_owns_its_keys_and_runs_once() {
        let key = |key| fixture::key_event(key, egui::Modifiers::NONE);
        let mut desk = Desk::new(menu_app());
        desk.app.select_instruction(0x1000);
        let before = position(&desk.app);
        desk.open(Pane::Listing, "00001001", 3);
        let output = desk.frame(
            Pane::Listing,
            vec![
                key(egui::Key::L),
                key(egui::Key::G),
                key(egui::Key::Space),
                key(egui::Key::X),
                fixture::key_event(egui::Key::Z, egui::Modifiers::COMMAND),
            ],
        );
        assert!(shows(&output, "Copy address"), "the menu stays open");
        assert!(desk.app.browser_dialog.is_none() && desk.app.tab == Tab::Listing);
        assert_eq!(position(&desk.app), before);

        // Keys arriving with the activating click stay with the menu.
        let point = fixture::text_position(&output, "Copy address", 0);
        let mut events = fixture::pointer_events(point);
        events.extend([key(egui::Key::Space), key(egui::Key::L)]);
        let output = desk.frame(Pane::Listing, events);
        assert_eq!(copies(&output), ["0x1001"]);
        assert!(desk.app.browser_dialog.is_none() && desk.app.tab == Tab::Listing);
        // Held repeats and releases neither copy again nor toggle.
        let output = desk.frame(
            Pane::Listing,
            vec![
                egui::Event::Key {
                    key: egui::Key::Space,
                    physical_key: None,
                    pressed: true,
                    repeat: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::Key {
                    key: egui::Key::Space,
                    physical_key: None,
                    pressed: false,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        assert!(copies(&output).is_empty() && desk.app.tab == Tab::Listing);
        // Shortcuts return once the menu has closed.
        desk.frame(Pane::Listing, vec![key(egui::Key::Space)]);
        assert_eq!(desk.app.tab, Tab::Graph);

        // Escape dismisses without an action or a selection change.
        desk.app.tab = Tab::Listing;
        desk.open(Pane::Listing, "00001001", 3);
        desk.frame(Pane::Listing, vec![escape()]);
        let output = desk.frame(Pane::Listing, vec![]);
        assert!(!shows(&output, "Copy address") && copies(&output).is_empty());
        assert!(desk.app.menus.active.is_none());
        assert_eq!(position(&desk.app), before);
    }

    #[test]
    fn menu_rename_drafts_are_discarded_when_annotations_change() {
        let mut desk = Desk::new(menu_app());
        let menu = desk.open(Pane::Listing, "00001001", 3);
        desk.choose(Pane::Listing, &menu, "Rename…");
        desk.app.browser_dialog.as_mut().unwrap().text = "renamed".into();
        desk.app.edit_annotation(
            0x1007,
            Annotation {
                comment: "elsewhere".into(),
                ..Default::default()
            },
        );
        let app = &mut desk.app;
        let mut output = desk.context.run_ui(
            egui::RawInput {
                events: vec![fixture::key_event(egui::Key::Enter, egui::Modifiers::NONE)],
                ..Default::default()
            },
            |ui| app.browser_dialog(ui.ctx()),
        );
        output.textures_delta.clear();
        assert!(app.browser_dialog.is_none());
        let session = app.session.as_ref().unwrap();
        assert!(
            session
                .annotations
                .get(&0x1001)
                .is_none_or(|n| n.label.is_empty())
        );
    }

    #[test]
    fn strings_menus_keep_source_identity_through_sorting_and_filtering() {
        let mut app = menu_app();
        app.strings = [
            (0x1010, "dup"),
            (0x1020, "dup"),
            (0x1030, "zeta"),
            (0x1040, "dup"),
        ]
        .map(|(address, text)| StringEntry {
            address,
            text: text.into(),
            encoding: "utf-8".into(),
        })
        .into();
        app.strings_scanned = true;
        app.string_filter = "dup".into();
        app.rebuild_string_filter();
        app.table_sorts
            .strings
            .set(Some((0, theme::SortDirection::Descending)));
        app.select_string(0x1010);
        app.tab = Tab::Strings;
        let mut desk = Desk::new(app);
        desk.frame(Pane::Listing, vec![]);
        let output = desk.frame(Pane::Listing, vec![]);
        // Descending and filtered: 1040, 1020, 1010; the selection is 1010.
        let digits = string_digits(desk.app.info.as_ref());
        let second = fixture::text_position(&output, &format!("{:0digits$x}", 0x1020), 0);
        desk.frame(Pane::Listing, fixture::secondary_events(second));
        let menu = desk.frame(Pane::Listing, vec![]);
        let output = desk.choose(Pane::Listing, &menu, "Copy row");
        assert_eq!(
            copies(&output),
            [format!("{:0digits$x}\tutf-8\tdup", 0x1020)]
        );
        assert_eq!(desk.app.selected, Some(0x1010), "copying never selects");
        desk.frame(Pane::Listing, vec![]);
        desk.frame(Pane::Listing, fixture::secondary_events(second));
        let menu = desk.frame(Pane::Listing, vec![]);
        desk.choose(Pane::Listing, &menu, "Go to");
        assert_eq!(desk.app.data_location, Some((0x1020, 3)));
        assert_eq!(desk.app.tab, Tab::Hex);
        assert_eq!(
            desk.app.table_sorts.strings.applied(),
            Some((0, theme::SortDirection::Descending))
        );
        assert_eq!(desk.app.string_filter, "dup");
    }

    #[test]
    fn menus_fit_narrow_fractional_screens_and_keep_fixed_rows() {
        let mut desk = Desk::new(menu_app());
        desk.context.set_pixels_per_point(1.25);
        desk.size = egui::vec2(360.0, 220.0);
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, desk.size);
        let rows = |output: &egui::FullOutput| {
            ["00001000", "00001001", "00001006", "00001007"]
                .map(|row| fixture::text_position(output, row, 0).y)
        };
        let output = desk.frame(Pane::Listing, vec![]);
        let before = rows(&output);
        // The last row, near the bottom-right corner.
        let menu = desk.open(Pane::Listing, "00001007", 7);
        for item in [
            "Comment…",
            "Copy address",
            "Copy instruction",
            "Decode bytes",
        ] {
            let point = fixture::text_position(&menu, item, 0);
            assert!(screen.contains(point), "{item} at {point:?}");
        }
        assert_eq!(rows(&menu), before, "rows keep their height under a menu");
        let output = desk.choose(Pane::Listing, &menu, "Copy address");
        assert_eq!(copies(&output), ["0x1007"]);
    }

    #[test]
    fn copied_text_is_bounded_and_utf8_safe() {
        let mut app = menu_app();
        let long = format!("{}\t\n", "é".repeat(20_000));
        app.session.as_mut().unwrap().annotations.insert(
            0x1007,
            Annotation {
                label: long.clone(),
                ..Default::default()
            },
        );
        let row = app
            .menu_copy_text(MenuSource::TreeLabel(0x1007), MenuCommand::CopyRow)
            .unwrap();
        assert!(row.len() <= 16 * 1024 && row.ends_with('…'));
        assert!(!row.contains('\t') && !row.contains('\n'));
        let line = format!("int {} = 1;", "é".repeat(20_000));
        fixture::show_code(&mut app, &line, vec![], SemanticInfo::default());
        let copied = app
            .menu_copy_text(
                MenuSource::Code {
                    entry: 0x1000,
                    line: 0,
                    byte: None,
                },
                MenuCommand::CopyLine,
            )
            .unwrap();
        assert!(copied.len() <= 16 * 1024 && copied.ends_with('…'));
        assert!(line.starts_with(copied.trim_end_matches('…')));
    }
}
