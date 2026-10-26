//! Capture machine locations from the engine's semantic print marks.
//!
//! An action decorator reads analyzed p-code immediately before printing. The
//! normal Program::decompile path still performs string enrichment, analysis,
//! pretty printing, and cleanup. Neither cached source nor the engine is patched.

use crate::model::{
    CodeMapping, MAX_CODE_ADDRESS_REFS, MAX_CODE_MAPPINGS, MAX_DECOMPILED_BYTES,
    MAX_MAPPING_ADDRESSES, SectionInfo,
};
use crate::selection::ExecutableRanges;
use crate::semantic::{LocalRename, MAX_TOKENS, SemanticInfo, SemanticToken, TokenKind};
use crate::symbol_names::SymbolTable;
use ghidra_decompiler::action::{Action, ActionBase, ActionGroupList};
use ghidra_decompiler::architecture::Architecture;
use ghidra_decompiler::error::{Error, Result};
use ghidra_decompiler::funcdata::Funcdata;
use ghidra_decompiler::op::{OpId, PcodeOp};
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::prettyprint::*;
use ghidra_decompiler::program::Program;
use ghidra_decompiler::space::SpaceRef;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

/// Appended to decompiler text cut at the prototype size limit.
pub const TRUNCATION_TRAILER: &str =
    "\n/* Decompiler output truncated at the 2 MiB prototype limit. */\n";

const MAX_CAPTURED_OPS: usize = 131_072;
const MAX_STATEMENT_DEPTH: usize = 256;
const TEXT_BUDGET: usize = MAX_DECOMPILED_BYTES - 100;

#[derive(Default)]
struct Capture {
    operations: BTreeMap<OpId, u64>,
    spans: Vec<CodeMapping>,
    truncated: bool,
    calls: BTreeMap<OpId, u64>,
    locals: crate::local_symbols::Locals,
    tokens: Vec<SemanticToken>,
    prototype: Option<crate::signatures::InferredSignature>,
}

type Shared = Arc<Mutex<Capture>>;
type ReturnedAction = Arc<Mutex<Option<Box<dyn Action>>>>;

struct CaptureAction {
    inner: Option<Box<dyn Action>>,
    returned: ReturnedAction,
    capture: Shared,
    executable: ExecutableRanges,
    renames: Vec<LocalRename>,
    signature_context: String,
    signature_owned: bool,
    abi: String,
}

impl CaptureAction {
    fn inner(&self) -> &dyn Action {
        self.inner.as_deref().expect("Installed action")
    }
    fn inner_mut(&mut self) -> &mut dyn Action {
        self.inner.as_deref_mut().expect("Installed action")
    }
}

impl Drop for CaptureAction {
    fn drop(&mut self) {
        *self
            .returned
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = self.inner.take();
    }
}

impl Action for CaptureAction {
    fn base(&self) -> &ActionBase {
        self.inner().base()
    }
    fn base_mut(&mut self) -> &mut ActionBase {
        self.inner_mut().base_mut()
    }
    fn clone_action(&self, groups: &ActionGroupList) -> Option<Box<dyn Action>> {
        self.inner().clone_action(groups)
    }
    fn reset(&mut self, data: &mut Funcdata, architecture: &mut Architecture) {
        self.inner_mut().reset(data, architecture);
    }
    fn apply(&mut self, data: &mut Funcdata, architecture: &mut Architecture) -> Result<i32> {
        self.inner_mut().apply(data, architecture)
    }
    fn perform(&mut self, data: &mut Funcdata, architecture: &mut Architecture) -> Result<i32> {
        let engine = crate::performance::span("engine_action");
        let result = self.inner_mut().perform(data, architecture)?;
        engine.finish(0);
        let _capture = crate::performance::span("semantic_capture");
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        capture.operations.clear();
        capture.prototype = Some(crate::signatures::capture(data, architecture, &self.abi));
        capture.locals = crate::local_symbols::capture(
            data,
            architecture,
            &self.renames,
            &self.signature_context,
            self.signature_owned,
        )?;
        if capture.locals.variables.is_empty() && capture.locals.warnings.is_empty() {
            capture.locals.warnings = self
                .renames
                .iter()
                .map(|r| {
                    format!(
                        "Local rename '{}' not applied: no supported recovered identity",
                        r.name
                    )
                })
                .collect();
        }
        let code_space = architecture.manager.get_default_code_space();
        let mut current = data.obank.begin_alive();
        for _ in 0..MAX_CAPTURED_OPS {
            let Some(id) = current else { break };
            let operation = data.op(id);
            let address = operation.get_addr();
            let pc = address.get_offset();
            if !address.is_invalid()
                && address
                    .get_space()
                    .zip(code_space.as_ref())
                    .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
                && self.executable.contains(pc)
            {
                capture.operations.insert(id, pc);
            }
            if operation.code() == OpCode::Call
                && operation.num_input() > 0
                && let Some(spec) = data.get_call_specs_op(id)
            {
                let target = data.call_spec(spec).get_entry_address();
                if !target.is_invalid()
                    && target
                        .get_space()
                        .zip(code_space.as_ref())
                        .is_some_and(|(a, b)| Arc::ptr_eq(a, b))
                    && code_space
                        .as_ref()
                        .is_some_and(|space| space.get_word_size() == 1)
                    && self.executable.contains(target.get_offset())
                {
                    capture.calls.insert(id, target.get_offset());
                }
            }
            current = data.obank.next_in_list(id, PcodeOp::INSERT_LIST);
        }
        Ok(result)
    }
}

/// Return bounded C and sorted, non-overlapping UTF-8 byte mappings. Instructions
/// eliminated by optimization have no invented source location.
pub fn render(
    program: &mut Program,
    address: u64,
    sections: &[SectionInfo],
) -> Result<(String, Vec<CodeMapping>, SemanticInfo)> {
    render_with_locals(program, address, sections, &[])
}

pub fn render_with_locals(
    program: &mut Program,
    address: u64,
    sections: &[SectionInfo],
    renames: &[LocalRename],
) -> Result<(String, Vec<CodeMapping>, SemanticInfo)> {
    render_with_context(program, address, sections, renames, "", false)
}

pub fn render_with_context(
    program: &mut Program,
    address: u64,
    sections: &[SectionInfo],
    renames: &[LocalRename],
    signature_context: &str,
    signature_owned: bool,
) -> Result<(String, Vec<CodeMapping>, SemanticInfo)> {
    render_named(
        program,
        address,
        sections,
        renames,
        signature_context,
        signature_owned,
        None,
    )
}

/// [`render_with_context`] that prints worker-derived display names for the
/// declaration and verified direct-call name tokens. Names are chosen while
/// emitting, so every mapping and token offset measures the final text.
pub fn render_named(
    program: &mut Program,
    address: u64,
    sections: &[SectionInfo],
    renames: &[LocalRename],
    signature_context: &str,
    signature_owned: bool,
    names: Option<Arc<SymbolTable>>,
) -> Result<(String, Vec<CodeMapping>, SemanticInfo)> {
    crate::semantic::validate_renames(renames, Some(address)).map_err(Error::Lowlevel)?;
    if signature_context.len() > 96 || (signature_owned && signature_context.is_empty()) {
        return Err(Error::Lowlevel(
            "Invalid signature rendering context".into(),
        ));
    }
    let abi = program.language_id().to_string();
    let capture = Shared::default();
    let executable = ExecutableRanges::new(sections).map_err(Error::Lowlevel)?;
    let returned = ReturnedAction::default();
    let architecture = program.architecture();
    let name = architecture
        .allacts
        .currentact
        .clone()
        .ok_or_else(|| Error::Lowlevel("No decompiler action selected".into()))?;
    let print_index = architecture.print;
    let printer = architecture
        .printlist
        .get_mut(print_index)
        .and_then(Option::as_mut)
        .ok_or_else(|| Error::Lowlevel("No decompiler printer selected".into()))?;
    let mut pretty = EmitPrettyPrint::new();
    let line_size = printer.base().emit.get_max_line_size();
    if line_size > 0 {
        pretty.set_max_line_size(line_size)?;
    }
    pretty.set_indent_increment(printer.base().emit.get_indent_increment());
    pretty.lowlevel = Box::new(LocationEmitter::new(Arc::clone(&capture), address, names));
    let original_action = architecture
        .allacts
        .actionmap
        .remove(&name)
        .ok_or_else(|| Error::Lowlevel("Decompiler action unavailable".into()))?;
    let original_emit = std::mem::replace(&mut printer.base_mut().emit, Box::new(pretty));
    architecture.allacts.actionmap.insert(
        name.clone(),
        Box::new(CaptureAction {
            inner: Some(original_action),
            returned: Arc::clone(&returned),
            capture: Arc::clone(&capture),
            executable,
            renames: renames.to_vec(),
            signature_context: signature_context.into(),
            signature_owned,
            abi,
        }),
    );
    let engine = crate::performance::span("engine_decompile_inclusive");
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| program.decompile(address)));
    engine.finish(0);
    let architecture = program.architecture();
    drop(architecture.allacts.actionmap.remove(&name));
    if let Some(original_action) = returned
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
        architecture.allacts.actionmap.insert(name, original_action);
    }
    architecture.printlist[print_index]
        .as_mut()
        .expect("Restored printer")
        .base_mut()
        .emit = original_emit;
    let mut text = result.unwrap_or_else(|payload| std::panic::resume_unwind(payload))?;
    let mut capture = capture.lock().unwrap_or_else(|error| error.into_inner());
    let flattening = crate::performance::span("mapping_flatten");
    let mappings = flatten(std::mem::take(&mut capture.spans), &text);
    flattening.finish(mappings.len() as u64);
    if capture.truncated {
        text.push_str(TRUNCATION_TRAILER);
    }
    let semantics = SemanticInfo {
        prototype: capture.prototype.take(),
        tokens: std::mem::take(&mut capture.tokens),
        locals: std::mem::take(&mut capture.locals.variables),
        warnings: std::mem::take(&mut capture.locals.warnings),
    };
    let _validation = crate::performance::span("semantic_validate");
    semantics
        .validate(&text, address, sections)
        .map_err(Error::Lowlevel)?;
    Ok((text, mappings, semantics))
}

struct Statement {
    start: usize,
    addresses: BTreeSet<u64>,
}

struct LocationEmitter {
    base: EmitBase,
    text: Vec<u8>,
    capture: Shared,
    statements: Vec<Statement>,
    overflow_depth: usize,
    saturated: bool,
    declarations: Vec<Option<usize>>,
    declaration_overflow: usize,
    function: u64,
    names: Option<Arc<SymbolTable>>,
}

impl LocationEmitter {
    fn new(capture: Shared, function: u64, names: Option<Arc<SymbolTable>>) -> Self {
        Self {
            function,
            names,
            base: EmitBase::new(),
            text: Vec::new(),
            capture,
            statements: Vec::new(),
            overflow_depth: 0,
            saturated: false,
            declarations: Vec::new(),
            declaration_overflow: 0,
        }
    }
    fn location(&self, mark: Option<OpMark>) -> Option<u64> {
        let mark = mark?;
        self.capture
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .operations
            .get(&mark.id)
            .copied()
    }
    fn record(&self, start: usize, addresses: Vec<u64>) {
        if start >= self.text.len() || addresses.is_empty() {
            return;
        }
        let mut capture = self
            .capture
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if capture.spans.len() < MAX_CODE_MAPPINGS {
            capture.spans.push(CodeMapping {
                start,
                end: self.text.len(),
                addresses,
            });
        }
    }
    fn semantic_token(&self, start: usize, text: &str, kind: TokenKind) {
        if self.text.len() - start != text.len() || text.is_empty() {
            return;
        }
        let mut capture = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        if capture.tokens.len() < MAX_TOKENS {
            capture.tokens.push(SemanticToken {
                start,
                end: self.text.len(),
                kind,
            });
        }
    }
    fn append(&mut self, text: &str) {
        if self.saturated {
            return;
        }
        let mut count = TEXT_BUDGET.saturating_sub(self.text.len()).min(text.len());
        while !text.is_char_boundary(count) {
            count -= 1;
        }
        self.text.extend_from_slice(&text.as_bytes()[..count]);
        if count < text.len() {
            self.saturated = true;
            self.capture
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .truncated = true;
        }
    }
    fn spaces_bounded(&mut self, count: i32) {
        if self.saturated {
            return;
        }
        let count = count.max(0) as usize;
        let available = TEXT_BUDGET.saturating_sub(self.text.len());
        self.text
            .resize(self.text.len() + count.min(available), b' ');
        if count > available {
            self.saturated = true;
            self.capture
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .truncated = true;
        }
    }
    fn token(&mut self, text: &str, mark: Option<OpMark>) -> Result<()> {
        let start = self.text.len();
        self.append(text);
        // A fully omitted token must not contribute PCs to an earlier visible
        // prefix of the same statement. A partial visible token retains its PC.
        if self.text.len() == start {
            return Ok(());
        }
        let pc = self.location(mark);
        for statement in &mut self.statements {
            if let Some(pc) = pc
                && statement.addresses.len() < MAX_MAPPING_ADDRESSES
            {
                statement.addresses.insert(pc);
            }
        }
        if self.statements.is_empty()
            && let Some(pc) = pc
        {
            self.record(start, vec![pc]);
        }
        Ok(())
    }
}

macro_rules! no_output {
    ($($name:ident($($argument:ident:$ty:ty),*) -> $result:ty = $value:expr;)*) => {
        $(fn $name(&mut self, $($argument:$ty),*) -> Result<$result> { Ok($value) })*
    };
}

impl Emit for LocationEmitter {
    fn base(&self) -> &EmitBase {
        &self.base
    }
    fn base_mut(&mut self) -> &mut EmitBase {
        &mut self.base
    }
    fn as_dyn(&mut self) -> &mut dyn Emit {
        self
    }
    no_output! {
        begin_document() -> i32 = 0;
        end_document(_id:i32) -> () = ();
        begin_function(_function:Option<&FuncMark>) -> i32 = 0;
        end_function(_id:i32) -> () = ();
        begin_block(_block:Option<BlockMark>) -> i32 = 0;
        end_block(_id:i32) -> () = ();
        begin_return_type(_node:Option<VarnodeMark>) -> i32 = 0;
        end_return_type(_id:i32) -> () = ();
        begin_func_proto() -> i32 = 0;
        end_func_proto(_id:i32) -> () = ();
    }
    fn begin_var_decl(&mut self, symbol: Option<SymbolMark>) -> Result<i32> {
        let index = symbol.and_then(|s| {
            self.capture
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .locals
                .symbols
                .get(&s.id)
                .copied()
        });
        if self.declaration_overflow > 0 || self.declarations.len() >= MAX_STATEMENT_DEPTH {
            self.declaration_overflow = self.declaration_overflow.saturating_add(1);
        } else {
            self.declarations.push(index);
        }
        Ok(0)
    }
    fn end_var_decl(&mut self, _id: i32) -> Result<()> {
        if self.declaration_overflow > 0 {
            self.declaration_overflow -= 1;
        } else {
            self.declarations.pop();
        }
        Ok(())
    }
    fn begin_statement(&mut self, mark: Option<OpMark>) -> Result<i32> {
        if self.overflow_depth > 0 || self.statements.len() >= MAX_STATEMENT_DEPTH {
            self.overflow_depth = self.overflow_depth.saturating_add(1);
            return Ok(-1);
        }
        let addresses = self.location(mark).into_iter().collect();
        self.statements.push(Statement {
            start: self.text.len(),
            addresses,
        });
        Ok(self.statements.len() as i32)
    }
    fn end_statement(&mut self, _id: i32) -> Result<()> {
        // EmitPrettyPrint forwards its own token IDs, rather than the return
        // values from this lowlevel emitter's begin_statement.
        if self.overflow_depth > 0 {
            self.overflow_depth = self.overflow_depth.saturating_sub(1);
            return Ok(());
        }
        if let Some(statement) = self.statements.pop() {
            self.record(statement.start, statement.addresses.into_iter().collect());
        }
        Ok(())
    }
    fn tag_line(&mut self) -> Result<()> {
        self.tag_line_indent(self.base.indentlevel)
    }
    fn tag_line_indent(&mut self, indent: i32) -> Result<()> {
        self.append("\n");
        self.spaces_bounded(indent);
        Ok(())
    }
    fn tag_variable(
        &mut self,
        text: &str,
        highlight: SyntaxHighlight,
        node: Option<VarnodeMark>,
        op: Option<OpMark>,
    ) -> Result<()> {
        let start = self.text.len();
        self.token(text, op)?;
        if matches!(
            highlight,
            SyntaxHighlight::VarColor | SyntaxHighlight::ParamColor
        ) {
            let capture = self.capture.lock().unwrap_or_else(|e| e.into_inner());
            let local = match node {
                Some(node) => capture.locals.nodes.get(&node.id).copied(),
                None if self.declaration_overflow == 0 => {
                    self.declarations.last().copied().flatten()
                }
                None => None,
            };
            // Optimized output can print a captured member under another
            // variable's name. Such a token is not verified as that local, so
            // it stays unsupported instead of rejecting the whole result.
            let local = local.filter(|&index| {
                capture
                    .locals
                    .variables
                    .get(index)
                    .is_some_and(|variable| variable.name == text)
            });
            drop(capture);
            self.semantic_token(start, text, TokenKind::Local { local });
        }
        Ok(())
    }
    fn tag_op(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        op: Option<OpMark>,
    ) -> Result<()> {
        self.token(text, op)
    }
    fn tag_func_name(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        function: Option<&FuncMark>,
        op: Option<OpMark>,
    ) -> Result<()> {
        let start = self.text.len();
        // Function prototypes have no CALL op. Indirect calls never enter this map.
        let target = op.and_then(|op| {
            self.capture
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .calls
                .get(&op.id)
                .copied()
        });
        let entry = function.map(|mark| mark.entry.get_offset());
        // Only a verified direct-call target, or this function's own
        // declaration, has an exact address. Everything else keeps engine text.
        let named = match (target, op) {
            (Some(target), _) => entry.is_none_or(|entry| entry == target).then_some(target),
            (None, None) => entry.filter(|&entry| entry == self.function),
            (None, Some(_)) => None,
        };
        let names = self.names.clone();
        let shown = named
            .zip(names.as_deref())
            .and_then(|(address, names)| names.display_for(address, text))
            .unwrap_or(text);
        self.token(shown, op)?;
        if let Some(target) = target {
            self.semantic_token(start, shown, TokenKind::Call { target });
        }
        Ok(())
    }
    fn tag_type(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        _datatype: Option<&TypeMark>,
    ) -> Result<()> {
        self.token(text, None)
    }
    fn tag_field(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        _datatype: Option<&TypeMark>,
        _offset: i32,
        op: Option<OpMark>,
    ) -> Result<()> {
        self.token(text, op)
    }
    fn tag_bit_field(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        _datatype: Option<&TypeMark>,
        _id: i32,
        op: Option<OpMark>,
    ) -> Result<()> {
        self.token(text, op)
    }
    fn tag_comment(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        _space: Option<&SpaceRef>,
        _offset: u64,
    ) -> Result<()> {
        self.token(text, None)
    }
    fn tag_label(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        _space: Option<&SpaceRef>,
        _offset: u64,
    ) -> Result<()> {
        self.token(text, None)
    }
    fn tag_case_label(
        &mut self,
        text: &str,
        _highlight: SyntaxHighlight,
        op: Option<OpMark>,
        _value: u64,
    ) -> Result<()> {
        self.token(text, op)
    }
    fn print(&mut self, text: &str, _highlight: SyntaxHighlight) -> Result<()> {
        self.token(text, None)
    }
    fn open_paren(&mut self, paren: &str, id: i32) -> Result<i32> {
        self.append(paren);
        self.base.parenlevel += 1;
        Ok(id)
    }
    fn close_paren(&mut self, paren: &str, _id: i32) -> Result<()> {
        self.append(paren);
        self.base.parenlevel -= 1;
        Ok(())
    }
    fn spaces(&mut self, count: i32, _bump: i32) -> Result<()> {
        self.spaces_bounded(count);
        Ok(())
    }
    fn set_output_stream(&mut self, text: Vec<u8>) {
        self.text = text;
    }
    fn get_output_stream(&mut self) -> &mut Vec<u8> {
        &mut self.text
    }
    fn emits_markup(&self) -> bool {
        false
    }
}

fn flatten(spans: Vec<CodeMapping>, text: &str) -> Vec<CodeMapping> {
    let mut events = Vec::with_capacity(spans.len() * 2);
    for (index, span) in spans.iter().enumerate() {
        if span.start >= span.end
            || span.end > text.len()
            || !text.is_char_boundary(span.start)
            || !text.is_char_boundary(span.end)
        {
            continue;
        }
        events.push((span.start, true, index));
        events.push((span.end, false, index));
    }
    events.sort_unstable();
    let mut active = BTreeSet::new();
    let mut mappings: Vec<CodeMapping> = Vec::new();
    let mut references = 0;
    let mut cursor = 0;
    while cursor < events.len() {
        let position = events[cursor].0;
        while cursor < events.len() && events[cursor].0 == position {
            let (_, begin, index) = events[cursor];
            let key = (spans[index].end - spans[index].start, index);
            if begin {
                active.insert(key);
            } else {
                active.remove(&key);
            }
            cursor += 1;
        }
        let Some(&(end, _, _)) = events.get(cursor) else {
            break;
        };
        let Some(&(_, index)) = active.first() else {
            continue;
        };
        let addresses = &spans[index].addresses;
        if let Some(previous) = mappings.last_mut()
            && previous.end == position
            && previous.addresses == *addresses
        {
            previous.end = end;
            continue;
        }
        if mappings.len() >= MAX_CODE_MAPPINGS
            || addresses.len() > MAX_CODE_ADDRESS_REFS - references
        {
            break;
        }
        references += addresses.len();
        mappings.push(CodeMapping {
            start: position,
            end,
            addresses: addresses.clone(),
        });
    }
    mappings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omitted_tokens_cannot_add_locations_to_a_truncated_visible_statement() {
        let capture = Shared::default();
        capture.lock().unwrap().operations.extend([
            (OpId(0), 0x401010),
            (OpId(1), 0x401013),
            (OpId(2), 0x401016),
        ]);
        let mut emitter = LocationEmitter::new(Arc::clone(&capture), 0, None);
        let first = OpMark {
            id: OpId(0),
            time: 1,
        };
        emitter.begin_statement(Some(first)).unwrap();
        emitter
            .tag_op("x", SyntaxHighlight::NoColor, Some(first))
            .unwrap();
        emitter.spaces_bounded((TEXT_BUDGET - 1) as i32);
        for id in [OpId(1), OpId(2)] {
            emitter
                .tag_op(
                    "omitted",
                    SyntaxHighlight::NoColor,
                    Some(OpMark { id, time: 2 }),
                )
                .unwrap();
        }
        emitter.end_statement(1).unwrap();
        let text = String::from_utf8(emitter.text).unwrap();
        let mappings = flatten(std::mem::take(&mut capture.lock().unwrap().spans), &text);
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].addresses, [0x401010]);
        assert!(capture.lock().unwrap().truncated);
    }

    #[test]
    fn expression_statement_retains_multiple_machine_locations_and_utf8_spans() {
        let capture = Shared::default();
        capture
            .lock()
            .unwrap()
            .operations
            .extend([(OpId(0), 0x401010), (OpId(1), 0x401013)]);
        let mut emitter = LocationEmitter::new(Arc::clone(&capture), 0, None);
        emitter
            .begin_statement(Some(OpMark {
                id: OpId(0),
                time: 1,
            }))
            .unwrap();
        emitter
            .tag_variable(
                "π",
                SyntaxHighlight::VarColor,
                None,
                Some(OpMark {
                    id: OpId(0),
                    time: 1,
                }),
            )
            .unwrap();
        emitter.print(" + ", SyntaxHighlight::NoColor).unwrap();
        emitter
            .tag_op(
                "x",
                SyntaxHighlight::NoColor,
                Some(OpMark {
                    id: OpId(1),
                    time: 2,
                }),
            )
            .unwrap();
        emitter.end_statement(12345).unwrap();
        let text = String::from_utf8(emitter.text.clone()).unwrap();
        let mappings = flatten(std::mem::take(&mut capture.lock().unwrap().spans), &text);
        assert_eq!(mappings.len(), 1);
        assert_eq!(&text[mappings[0].start..mappings[0].end], "π + x");
        assert_eq!(mappings[0].addresses, [0x401010, 0x401013]);
    }

    #[test]
    fn oversized_unicode_and_nested_statements_stay_bounded() {
        let capture = Shared::default();
        let mut emitter = LocationEmitter::new(Arc::clone(&capture), 0, None);
        for _ in 0..MAX_STATEMENT_DEPTH + 20 {
            emitter.begin_statement(None).unwrap();
        }
        emitter
            .print(
                &"界".repeat(TEXT_BUDGET / 3 + 100),
                SyntaxHighlight::NoColor,
            )
            .unwrap();
        for _ in 0..MAX_STATEMENT_DEPTH + 20 {
            emitter.end_statement(999).unwrap();
        }
        assert!(emitter.text.len() <= TEXT_BUDGET);
        assert!(std::str::from_utf8(&emitter.text).is_ok());
        assert!(capture.lock().unwrap().truncated);
        assert!(emitter.statements.is_empty());
        assert_eq!(emitter.overflow_depth, 0);
    }

    #[test]
    fn nested_mappings_choose_inner_statement_and_never_overlap() {
        let text = "a β c";
        let mappings = flatten(
            vec![
                CodeMapping {
                    start: 0,
                    end: text.len(),
                    addresses: vec![1],
                },
                CodeMapping {
                    start: 2,
                    end: 4,
                    addresses: vec![2, 3],
                },
            ],
            text,
        );
        assert_eq!(
            mappings
                .iter()
                .map(|mapping| (mapping.start, mapping.end))
                .collect::<Vec<_>>(),
            [(0, 2), (2, 4), (4, 6)]
        );
        assert_eq!(mappings[1].addresses, [2, 3]);
    }
}
