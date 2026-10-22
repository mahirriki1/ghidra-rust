//! Bounded instruction control-flow recovery: the resumable walk shared by
//! graphs, discovery and pattern validation, with switch tables and calls
//! that never return.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{InstructionPcode, Program};

use super::{MAX_BLOCKS, MAX_INSTRUCTIONS, engine_error, executable, warning};
use crate::model::*;

pub(super) struct Decoded {
    pub(super) instruction: Instruction,
    pub(super) next: Vec<(Option<u64>, EdgeKind)>,
    pub(super) terminal: bool,
}

/// Test-only raw instruction CFG and its decode count, without switch or
/// no-return evidence. `functions` must be ordered by address.
#[cfg(test)]
pub(super) fn recover_graph_counted(
    program: &Program,
    sections: &[SectionInfo],
    functions: &[FunctionInfo],
    entry: u64,
    pe_ranges: &[(u64, u64)],
) -> Result<(FunctionView, usize), String> {
    if !functions.is_sorted_by_key(|function| function.address) {
        return Err("Function inventory is not ordered by address".into());
    }
    let mut remaining = MAX_INSTRUCTIONS;
    let recovered = recover_graph_budgeted(
        program,
        &Bounds {
            sections,
            is_function: &|address| function_at(functions, address).is_some(),
            pe_ranges,
        },
        entry,
        &mut remaining,
        &Arc::default(),
        None,
    )?;
    Ok((recovered.view, MAX_INSTRUCTIONS - remaining))
}

pub(super) struct GraphRecovery {
    pub(super) view: FunctionView,
    pub(super) calls: Vec<(CallSite, u64)>,
    pub(super) partial: bool,
    /// Every decoded instruction's byte range, including any the view omits.
    pub(super) intervals: Vec<(u64, u64)>,
}

pub(super) const EXTERNAL_EXIT: &str = "A path reaches another known function entry or PE runtime-region start; displayed as an external/tail exit.";

/// Merged byte ranges of instructions decoded from established functions.
/// Pattern candidates must not start or run inside them.
#[derive(Default)]
pub(super) struct Coverage {
    pub(super) ranges: BTreeMap<u64, u64>,
    /// Functions whose walks contributed, so each is decoded once per worker.
    pub(super) walked: BTreeSet<u64>,
    /// Ranges were dropped at the limit; nothing may rely on absence.
    pub(super) incomplete: bool,
}

impl Coverage {
    const MAX_RANGES: usize = 1 << 20;

    pub(super) fn add(&mut self, function: u64, intervals: &[(u64, u64)]) {
        self.walked.insert(function);
        for &(start, end) in intervals {
            let (mut start, mut end) = (start, end);
            // Absorb every range that overlaps or touches [start, end).
            while let Some((&other, &other_end)) = self.ranges.range(..=end).next_back() {
                if other_end < start {
                    break;
                }
                start = start.min(other);
                end = end.max(other_end);
                self.ranges.remove(&other);
            }
            if self.ranges.len() == Self::MAX_RANGES {
                self.incomplete = true;
                continue;
            }
            self.ranges.insert(start, end);
        }
    }

    pub(super) fn contains(&self, address: u64) -> bool {
        self.overlaps(address, address.saturating_add(1))
    }

    pub(super) fn overlaps(&self, start: u64, end: u64) -> bool {
        self.ranges
            .range(..end)
            .next_back()
            .is_some_and(|(_, &other_end)| other_end > start)
    }

    /// Whether established code ends exactly at `address`.
    pub(super) fn ends_at(&self, address: u64) -> bool {
        self.ranges
            .range(..address)
            .next_back()
            .is_some_and(|(_, &end)| end == address)
    }
}

/// Where a walk may decode: aligned file-backed executable bytes, stopping at
/// other established function entries and PE runtime-function starts.
pub(super) struct Bounds<'a> {
    pub(super) sections: &'a [SectionInfo],
    pub(super) is_function: &'a dyn Fn(u64) -> bool,
    pub(super) pe_ranges: &'a [(u64, u64)],
}

pub(super) fn recover_graph_budgeted(
    program: &Program,
    bounds: &Bounds<'_>,
    entry: u64,
    remaining: &mut usize,
    no_return: &Arc<crate::no_return::NoReturnIndex>,
    mut data: Option<&mut crate::data_analysis::DataCollector<'_>>,
) -> Result<GraphRecovery, String> {
    let mut walk =
        Walk::new(program, bounds.sections, entry, data.as_deref_mut())?.with_no_return(no_return);
    walk.run(program, bounds, remaining, data.as_deref_mut());
    walk.finish(data)
}

/// Like [`recover_graph_budgeted`], also resolving switch tables through the
/// engine when the walk reaches an indirect jump. `entry` must already be an
/// engine function for recovery to run.
pub(super) fn recover_graph_switched(
    program: &mut Program,
    bounds: &Bounds<'_>,
    entry: u64,
    remaining: &mut usize,
    budget: &mut SwitchBudget,
    no_return: &Arc<crate::no_return::NoReturnIndex>,
    mut data: Option<&mut crate::data_analysis::DataCollector<'_>>,
) -> Result<GraphRecovery, String> {
    let mut walk =
        Walk::new(program, bounds.sections, entry, data.as_deref_mut())?.with_no_return(no_return);
    walk.run(program, bounds, remaining, data.as_deref_mut());
    if walk.switches(program, bounds.sections, budget) {
        walk.run(program, bounds, remaining, data.as_deref_mut());
    }
    walk.finish(data)
}

/// Engine switch recoveries one request may start. Each is synchronous, so
/// the elapsed allowance only stops further recoveries from starting.
pub(crate) struct SwitchBudget {
    pub(super) invocations: usize,
    pub(super) spent: Duration,
}

impl SwitchBudget {
    const MAX_INVOCATIONS: usize = 32;
    const MAX_ELAPSED: Duration = Duration::from_secs(5);

    pub(crate) fn new() -> Self {
        Self {
            invocations: 0,
            spent: Duration::ZERO,
        }
    }

    pub(super) fn available(&self) -> bool {
        self.invocations < Self::MAX_INVOCATIONS && self.spent < Self::MAX_ELAPSED
    }
}

/// An instruction-flow walk that can pause at unresolved indirect jumps,
/// accept validated switch destinations, and resume with the same budget.
pub(super) struct Walk {
    pub(super) entry: u64,
    pub(super) alignment: u64,
    pub(super) pending: VecDeque<u64>,
    pub(super) visited: BTreeSet<u64>,
    pub(super) nodes: BTreeMap<u64, Decoded>,
    pub(super) leaders: BTreeSet<u64>,
    pub(super) warnings: Vec<String>,
    pub(super) calls: Vec<CallSite>,
    pub(super) call_evidence: Vec<(CallSite, u64)>,
    /// Decoded indirect jumps without established destinations.
    pub(super) indirect: BTreeSet<u64>,
    /// Branch/destination pairs established by an engine jump table.
    pub(super) switched: BTreeSet<(u64, u64)>,
    pub(super) no_return: Arc<crate::no_return::NoReturnIndex>,
}

impl Walk {
    pub(super) fn new(
        program: &Program,
        sections: &[SectionInfo],
        entry: u64,
        data: Option<&mut crate::data_analysis::DataCollector<'_>>,
    ) -> Result<Self, String> {
        let alignment = crate::architecture::instruction_alignment(program.language_id());
        if !entry.is_multiple_of(alignment) {
            return Err(format!(
                "Instructions require {alignment}-byte aligned addresses."
            ));
        }
        if !executable(sections, entry, alignment as usize) {
            return Err(format!(
                "{entry:#x} is outside file-backed executable sections."
            ));
        }
        if let Some(data) = data {
            data.begin_function();
        }
        Ok(Self {
            entry,
            alignment,
            pending: VecDeque::from([entry]),
            visited: BTreeSet::new(),
            nodes: BTreeMap::new(),
            leaders: BTreeSet::from([entry]),
            warnings: Vec::new(),
            calls: Vec::new(),
            call_evidence: Vec::new(),
            indirect: BTreeSet::new(),
            switched: BTreeSet::new(),
            no_return: Arc::default(),
        })
    }

    /// Ends blocks at calls this index recognizes as never returning.
    pub(super) fn with_no_return(mut self, index: &Arc<crate::no_return::NoReturnIndex>) -> Self {
        self.no_return = Arc::clone(index);
        self
    }

    pub(super) fn run(
        &mut self,
        program: &Program,
        bounds: &Bounds<'_>,
        remaining: &mut usize,
        mut data: Option<&mut crate::data_analysis::DataCollector<'_>>,
    ) {
        let Bounds {
            sections,
            is_function,
            pe_ranges,
        } = *bounds;
        let (entry, alignment) = (self.entry, self.alignment);
        let warnings = &mut self.warnings;
        let nodes = &mut self.nodes;
        while let Some(address) = self.pending.pop_front() {
            if !self.visited.insert(address) {
                continue;
            }
            if *remaining == 0 {
                warning(
                    warnings,
                    "Instruction work budget reached; recovery is incomplete.",
                );
                // Unvisited work stays pending only for this walk's report.
                self.pending.clear();
                break;
            }
            if !address.is_multiple_of(alignment)
                || !executable(sections, address, alignment as usize)
            {
                warning(
                    warnings,
                    "A control-flow target leaves the supported executable regions.",
                );
                continue;
            }
            if (address != entry && is_function(address))
                || (address != entry
                    && pe_ranges
                        .binary_search_by_key(&address, |range| range.0)
                        .is_ok())
            {
                warning(warnings, EXTERNAL_EXIT);
                continue;
            }
            if let Some((&start, node)) = nodes.range(..=address).next_back()
                && start < address
                && address - start < node.instruction.bytes.len() as u64
            {
                warning(
                    warnings,
                    "Overlapping instructions encountered; ambiguous targets were not followed.",
                );
                continue;
            }
            // Charge failures as well as successful decodes; shared discovery work
            // must never grow past its budget when hostile bytes fail to decode.
            *remaining -= 1;
            let instruction = match program.disassemble(address, 1).map_err(engine_error) {
                Ok(mut instructions) if !instructions.is_empty() => instructions.remove(0),
                Ok(_) => {
                    warning(warnings, format!("No instruction decoded at {address:#x}."));
                    continue;
                }
                Err(error) => {
                    warning(warnings, format!("Cannot decode {address:#x}: {error}"));
                    continue;
                }
            };
            if instruction.address != address
                || instruction.length == 0
                || (alignment == 4 && instruction.length != 4)
                || !executable(sections, address, instruction.length)
            {
                warning(
                    warnings,
                    "An instruction crosses the boundary of an executable region.",
                );
                continue;
            }
            let Some(next_address) = address.checked_add(instruction.length as u64) else {
                warning(warnings, "Instruction address overflow.");
                continue;
            };
            if nodes.range(address + 1..next_address).next().is_some() {
                warning(
                    warnings,
                    "Overlapping instructions encountered; ambiguous instructions were not followed.",
                );
                continue;
            }
            let pcode = match program.pcode(address, 1).map_err(engine_error) {
                Ok(mut code) if !code.is_empty() => code.remove(0),
                Ok(_) => {
                    warning(warnings, format!("Missing p-code at {address:#x}."));
                    continue;
                }
                Err(error) => {
                    warning(
                        warnings,
                        format!("Cannot recover flow at {address:#x}: {error}"),
                    );
                    continue;
                }
            };
            if pcode.address != address || pcode.length != instruction.length {
                warning(
                    warnings,
                    format!("Instruction/p-code length mismatch at {address:#x}."),
                );
                continue;
            }
            if let Some(data) = data.as_mut() {
                data.inspect(entry, &pcode);
            }
            let call_start = self.calls.len();
            let no_return = &self.no_return;
            let (next, terminal, indirect) = flow(
                &pcode,
                next_address,
                &mut self.calls,
                warnings,
                &mut |code, operation| {
                    no_return.call(program, code, operation, sections, remaining)
                },
            );
            self.call_evidence.extend(
                self.calls[call_start..]
                    .iter()
                    .cloned()
                    .map(|call| (call, next_address)),
            );
            if indirect {
                self.indirect.insert(address);
            }
            for (target, _) in &next {
                if let Some(target) = target {
                    if terminal {
                        self.leaders.insert(*target);
                    }
                    self.pending.push_back(*target);
                }
            }
            nodes.insert(
                address,
                Decoded {
                    instruction: Instruction {
                        address,
                        bytes: instruction.bytes,
                        mnemonic: instruction.mnemonic,
                        operands: instruction.operands,
                    },
                    next,
                    terminal,
                },
            );
        }
    }

    pub(super) fn intervals(&self) -> Vec<(u64, u64)> {
        self.nodes
            .iter()
            .map(|(&address, node)| (address, address + node.instruction.bytes.len() as u64))
            .collect()
    }

    /// Whether this walk is strong enough evidence that `entry` starts a
    /// function no established code contains: every instruction decoded and
    /// lies outside `coverage`, every path ends in a return, a known no-return call or an explicit
    /// branch to an established function, and direct calls reach code.
    pub(super) fn complete_function(
        &self,
        coverage: &Coverage,
        is_function: &dyn Fn(u64) -> bool,
        is_code: &dyn Fn(u64) -> bool,
        min_instructions: usize,
    ) -> bool {
        let terminal_exit = self
            .nodes
            .values()
            .any(|node| node.terminal && node.next.is_empty());
        terminal_exit
            && self.nodes.len() >= min_instructions.max(1)
            && self.indirect.is_empty()
            && self.pending.is_empty()
            && self.warnings.iter().all(|warning| warning == EXTERNAL_EXIT)
            && self.nodes.iter().all(|(&address, node)| {
                let end = address + node.instruction.bytes.len() as u64;
                !coverage.overlaps(address, end)
                    && node.next.iter().all(|&(target, kind)| match target {
                        Some(target) if self.nodes.contains_key(&target) => true,
                        // Only an explicit jump may leave for another function;
                        // running into one is not a function boundary.
                        Some(target) => {
                            node.terminal && kind == EdgeKind::Branch && is_function(target)
                        }
                        None => false,
                    })
            })
            && self.calls.iter().all(|call| {
                call.target.is_none_or(|target| {
                    is_code(target) && (is_function(target) || !coverage.contains(target))
                })
            })
    }

    /// Asks the engine for this function's switch tables when the walk has
    /// unresolved indirect jumps, and queues validated destinations. Returns
    /// whether any destination was queued.
    pub(super) fn switches(
        &mut self,
        program: &mut Program,
        sections: &[SectionInfo],
        budget: &mut SwitchBudget,
    ) -> bool {
        if self.indirect.is_empty() {
            return false;
        }
        if !budget.available() {
            warning(
                &mut self.warnings,
                "Switch recovery was skipped by this request's work allowance.",
            );
            return false;
        }
        budget.invocations += 1;
        let started = Instant::now();
        let recovered = crate::switch_analysis::recover(program, self.entry);
        budget.spent += started.elapsed();
        match recovered {
            Ok(recovered) => self.apply(recovered, sections),
            Err(error) => {
                warning(&mut self.warnings, error);
                false
            }
        }
    }

    /// Admits engine-established destinations of decoded indirect jumps.
    /// Each must be an aligned file-backed executable address; anything less
    /// than a complete, valid table keeps an unresolved successor.
    pub(super) fn apply(
        &mut self,
        recovered: crate::switch_analysis::Recovered,
        sections: &[SectionInfo],
    ) -> bool {
        if recovered.truncated {
            warning(
                &mut self.warnings,
                "Switch recovery reached its table limits; some destinations were not examined.",
            );
        }
        let mut queued = false;
        for table in recovered.tables {
            // Ownership comes from the exact decoded branch, never proximity.
            if !self.indirect.contains(&table.branch) {
                continue;
            }
            let mut rejected = false;
            let mut targets = BTreeSet::new();
            for target in table.targets {
                if target.is_multiple_of(self.alignment)
                    && executable(sections, target, self.alignment as usize)
                {
                    targets.insert(target);
                } else {
                    rejected = true;
                }
            }
            if targets.is_empty() {
                continue;
            }
            let Some(node) = self.nodes.get_mut(&table.branch) else {
                continue;
            };
            node.next = targets
                .iter()
                .map(|&target| (Some(target), EdgeKind::Branch))
                .collect();
            if table.partial || rejected {
                node.next.push((None, EdgeKind::Unknown));
                warning(
                    &mut self.warnings,
                    format!(
                        "The switch at {:#x} was only partly recovered.",
                        table.branch
                    ),
                );
            }
            self.indirect.remove(&table.branch);
            for target in targets {
                self.switched.insert((table.branch, target));
                self.leaders.insert(target);
                self.pending.push_back(target);
            }
            queued = true;
        }
        queued
    }

    pub(super) fn finish(
        mut self,
        mut data: Option<&mut crate::data_analysis::DataCollector<'_>>,
    ) -> Result<GraphRecovery, String> {
        let intervals = self.intervals();
        let Walk {
            entry,
            nodes,
            mut leaders,
            ref mut warnings,
            ..
        } = self;
        if nodes.is_empty() {
            return Err("No instructions could be recovered at the selected address.".into());
        }
        for &address in &self.indirect {
            warning(
                warnings,
                format!("The indirect jump at {address:#x} has unresolved targets."),
            );
        }
        // A merge also begins a block, including fallthrough merges into a backward target.
        let mut predecessors = BTreeMap::<u64, usize>::new();
        for node in nodes.values() {
            for (target, _) in &node.next {
                if let Some(target) = target {
                    *predecessors.entry(*target).or_default() += 1;
                }
            }
        }
        leaders.extend(
            predecessors
                .into_iter()
                .filter_map(|(address, count)| (count > 1).then_some(address)),
        );
        let mut blocks = Vec::new();
        let mut edges = Vec::new();
        let mut assigned = BTreeSet::new();
        for start in leaders.iter().copied().filter(|a| nodes.contains_key(a)) {
            if assigned.contains(&start) {
                continue;
            }
            if blocks.len() >= MAX_BLOCKS {
                warning(
                    warnings,
                    "Graph limited to 128 basic blocks; recovery is incomplete.",
                );
                break;
            }
            let mut block = BasicBlock {
                address: start,
                instructions: Vec::new(),
            };
            let mut current = start;
            while let Some(node) = nodes.get(&current) {
                if !assigned.insert(current) {
                    break;
                }
                block.instructions.push(node.instruction.clone());
                if !node.terminal
                    && node.next.len() == 1
                    && let Some(next) = node.next[0].0
                    && nodes.contains_key(&next)
                    && !leaders.contains(&next)
                    && !assigned.contains(&next)
                {
                    current = next;
                    continue;
                }
                for (target, kind) in &node.next {
                    if edges.len() == crate::model::MAX_GRAPH_EDGES {
                        warning(
                            warnings,
                            "Graph edge limit reached; recovery is incomplete.",
                        );
                        break;
                    }
                    edges.push(Edge {
                        source: start,
                        target: *target,
                        kind: *kind,
                        evidence: target
                            .is_some_and(|target| self.switched.contains(&(current, target)))
                            .then_some(EdgeEvidence::EngineJumpTable),
                    });
                }
                break;
            }
            blocks.push(block);
        }
        if assigned.len() < nodes.len() {
            warning(
                warnings,
                "Some recovered instructions are omitted by graph limits or ambiguous block boundaries.",
            );
        }
        if let Some(data) = data.as_mut() {
            data.propagate(entry, blocks.iter());
        }
        let partial = !warnings.is_empty();
        warning(
            warnings,
            "CFG uses bounded static instruction flow with engine switch-table recovery; exceptions, no-return calls, and other indirect jumps may be incomplete.",
        );
        Ok(GraphRecovery {
            view: FunctionView {
                address: entry,
                blocks,
                edges,
                // Evidence is shown only where its block is; every call stays
                // listed for navigation.
                calls: self
                    .calls
                    .into_iter()
                    .map(|mut call| {
                        if !assigned.contains(&call.address) {
                            call.no_return = None;
                        }
                        call
                    })
                    .collect(),
                warnings: std::mem::take(warnings),
            },
            calls: self.call_evidence,
            partial,
            intervals,
        })
    }
}

/// Machine-level successors of one instruction, whether it ends a block, and
/// whether it is an indirect jump whose destinations are still unknown.
pub(super) fn flow(
    code: &InstructionPcode,
    fallthrough: u64,
    calls: &mut Vec<CallSite>,
    warnings: &mut Vec<String>,
    no_return: &mut dyn FnMut(&InstructionPcode, usize) -> Option<NoReturnEvidence>,
) -> (Vec<(Option<u64>, EdgeKind)>, bool, bool) {
    let mut transfer = None;
    let mut indirect = false;
    let mut internal = false;
    let call_start = calls.len();
    let mut call_operation = None;
    for (index, operation) in code.operations.iter().enumerate() {
        let direct = operation
            .inputs
            .first()
            .filter(|v| v.space == "ram")
            .map(|v| v.offset);
        match operation.opcode {
            OpCode::Call | OpCode::Callind => {
                if calls.len() >= MAX_INSTRUCTIONS {
                    warning(
                        warnings,
                        "Call-site budget reached; recovery is incomplete.",
                    );
                    continue;
                }
                calls.push(CallSite {
                    address: code.address,
                    target: if operation.opcode == OpCode::Call {
                        direct
                    } else {
                        None
                    },
                    no_return: None,
                });
                call_operation = Some(index);
            }
            OpCode::Branch | OpCode::Cbranch => {
                if operation.inputs.first().is_some_and(|v| v.space == "const") {
                    internal = true;
                } else {
                    let edges = if operation.opcode == OpCode::Cbranch {
                        vec![
                            (direct, EdgeKind::True),
                            (Some(fallthrough), EdgeKind::False),
                        ]
                    } else {
                        vec![(
                            direct,
                            if direct.is_some() {
                                EdgeKind::Branch
                            } else {
                                EdgeKind::Unknown
                            },
                        )]
                    };
                    if transfer.replace(edges).is_some() {
                        internal = true;
                    }
                }
            }
            OpCode::Branchind => {
                transfer = Some(vec![(None, EdgeKind::Unknown)]);
                indirect = true;
            }
            OpCode::Return => {
                transfer = Some(Vec::new());
            }
            _ => {}
        }
    }
    if internal || calls.len() > call_start + 1 {
        calls.truncate(call_start);
        warning(
            warnings,
            format!(
                "Instruction {:#x} contains internal p-code branches; machine-level successors were left unknown.",
                code.address
            ),
        );
        (vec![(None, EdgeKind::Unknown)], true, false)
    } else if let Some(edges) = transfer {
        (edges, true, indirect)
    } else if let Some(call) = calls.get_mut(call_start)
        && let Some(operation) = call_operation
        // A call to its own fallthrough reads the program counter.
        && call.target != Some(fallthrough)
        && let Some(evidence) = no_return(code, operation)
    {
        // The following bytes are not this call's successor.
        call.no_return = Some(evidence);
        (Vec::new(), true, false)
    } else {
        (vec![(Some(fallthrough), EdgeKind::Branch)], false, false)
    }
}
