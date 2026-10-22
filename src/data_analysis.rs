//! Bounded memory-access evidence from public engine p-code: instruction-local
//! constant pointers, plus AArch64 block-local register-constant propagation.
//!
//! Adapts direct-memory reference rules and constant-transfer/unknown-output
//! rules from Ghidra's SymbolicPropogator.java
//! (9a723ce99952771b8368329503aa589ae233e916), Apache-2.0. See NOTICE.
use std::collections::{BTreeMap, BTreeSet};

use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{InstructionPcode, PcodeOperation, PcodeVarnode};

use crate::model::*;

pub(crate) struct DataCollector<'a> {
    sections: &'a [SectionInfo],
    data_space: &'a str,
    pointer_bytes: u32,
    references: BTreeSet<DataReference>,
    report: DataAnalysis,
    /// Compact p-code of the current function's admitted instructions, kept
    /// only when block-local propagation is enabled. A missing address is a
    /// barrier that clears all known values.
    retained: Option<BTreeMap<u64, Retained>>,
    retained_operations: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Space {
    Const,
    Register,
    Unique,
    Other,
}

#[derive(Clone, Copy)]
struct Var {
    space: Space,
    offset: u64,
    size: u32,
}

struct Op {
    opcode: OpCode,
    output: Option<Var>,
    inputs: Vec<Var>,
}

/// An access counted as unresolved by [`DataCollector::inspect`]; only these
/// may later be resolved, so each access is accounted exactly once.
struct Unresolved {
    operation: usize,
    size: u32,
    access: DataAccess,
}

struct Retained {
    operations: Vec<Op>,
    unresolved: Vec<Unresolved>,
}

#[derive(Clone, Copy)]
struct Known {
    value: u64,
    /// Depends on a value established by an earlier instruction.
    carried: bool,
}

pub(crate) fn mask(size: u32) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (size * 8)) - 1
    }
}

/// Known little-endian values in register or unique storage, keyed by start.
#[derive(Default)]
struct Values {
    entries: BTreeMap<(bool, u64), (u32, Known)>,
    exhausted: bool,
}

impl Values {
    fn key(var: Var) -> Option<(bool, u64)> {
        match var.space {
            Space::Register => Some((false, var.offset)),
            Space::Unique => Some((true, var.offset)),
            _ => None,
        }
    }

    fn read(&self, var: Var) -> Option<Known> {
        if !(1..=8).contains(&var.size) {
            return None;
        }
        if var.space == Space::Const {
            return Some(Known {
                value: var.offset & mask(var.size),
                carried: false,
            });
        }
        let (unique, offset) = Self::key(var)?;
        let end = offset.checked_add(u64::from(var.size))?;
        // Only a single entry that fully contains the read can supply it.
        let (&(space, start), &(size, known)) =
            self.entries.range(..=(unique, offset)).next_back()?;
        if space != unique {
            return None;
        }
        let shift = offset - start;
        (start.checked_add(u64::from(size))? >= end && shift < 8).then(|| Known {
            value: (known.value >> (shift * 8)) & mask(var.size),
            carried: known.carried,
        })
    }

    fn write(&mut self, var: Var, value: Option<Known>) {
        let Some((unique, offset)) = Self::key(var) else {
            return;
        };
        let Some(end) = offset.checked_add(u64::from(var.size)) else {
            self.entries.clear();
            return;
        };
        // Invalidate every overlapping alias (for example Wn within Xn). All
        // entries are at most eight bytes, so overlaps start within 8 bytes.
        let overlapping: Vec<_> = self
            .entries
            .range((unique, offset.saturating_sub(7))..(unique, end))
            .filter(|(key, (size, _))| key.1.saturating_add(u64::from(*size)) > offset)
            .map(|(&key, _)| key)
            .collect();
        for key in overlapping {
            self.entries.remove(&key);
        }
        if let Some(known) = value
            && (1..=8).contains(&var.size)
        {
            if self.entries.len() >= MAX_DATA_TRACKED_VALUES {
                self.entries.clear();
                self.exhausted = true;
            }
            self.entries.insert((unique, offset), (var.size, known));
        }
    }

    fn end_instruction(&mut self) {
        self.entries.retain(|&(unique, _), _| !unique);
        for (_, known) in self.entries.values_mut() {
            known.carried = true;
        }
    }
}

/// Finite-width p-code arithmetic. Returns `None` for unsupported operations
/// or malformed widths, which makes the output unknown.
fn evaluate(op: &Op, values: &Values) -> Option<Known> {
    use OpCode::*;
    let output = op.output?;
    if !(1..=8).contains(&output.size) {
        return None;
    }
    let input = |index: usize| -> Option<(Var, Known)> {
        let var = *op.inputs.get(index)?;
        Some((var, values.read(var)?))
    };
    let same = |var: Var| var.size == output.size;
    let (value, carried) = match (op.opcode, op.inputs.len()) {
        (Copy, 1) => {
            let (a, x) = input(0)?;
            same(a).then_some((x.value, x.carried))?
        }
        (IntAdd | IntSub | IntAnd | IntOr | IntXor, 2) => {
            let ((a, x), (b, y)) = (input(0)?, input(1)?);
            if !same(a) || !same(b) {
                return None;
            }
            let value = match op.opcode {
                IntAdd => x.value.wrapping_add(y.value),
                IntSub => x.value.wrapping_sub(y.value),
                IntAnd => x.value & y.value,
                IntOr => x.value | y.value,
                _ => x.value ^ y.value,
            };
            (value, x.carried || y.carried)
        }
        (IntLeft | IntRight, 2) => {
            let ((a, x), (_, y)) = (input(0)?, input(1)?);
            if !same(a) {
                return None;
            }
            // P-code shifts of at least the operand width produce zero.
            let value = match u32::try_from(y.value)
                .ok()
                .and_then(|shift| (shift < output.size * 8).then_some(shift))
            {
                Some(shift) if op.opcode == IntLeft => x.value << shift,
                Some(shift) => x.value >> shift,
                None => 0,
            };
            (value, x.carried || y.carried)
        }
        (IntZext | IntSext, 1) => {
            let (a, x) = input(0)?;
            if a.size >= output.size {
                return None;
            }
            let bits = a.size * 8;
            let value = if op.opcode == IntSext && (x.value >> (bits - 1)) & 1 == 1 {
                x.value | !mask(a.size)
            } else {
                x.value
            };
            (value, x.carried)
        }
        (Subpiece, 2) => {
            let ((a, x), (b, y)) = (input(0)?, input(1)?);
            if b.space != Space::Const
                || y.value.checked_add(u64::from(output.size))? > u64::from(a.size)
            {
                return None;
            }
            (x.value >> (y.value * 8), x.carried)
        }
        (Piece, 2) => {
            let ((a, x), (b, y)) = (input(0)?, input(1)?);
            if a.size + b.size != output.size {
                return None;
            }
            ((x.value << (b.size * 8)) | y.value, x.carried || y.carried)
        }
        _ => return None,
    };
    Some(Known {
        value: value & mask(output.size),
        carried,
    })
}

impl<'a> DataCollector<'a> {
    pub fn new(sections: &'a [SectionInfo], data_space: &'a str, pointer_bytes: u32) -> Self {
        Self {
            sections,
            data_space,
            pointer_bytes,
            references: BTreeSet::new(),
            report: DataAnalysis::default(),
            retained: None,
            retained_operations: 0,
        }
    }

    /// Enables AArch64 block-local propagation; other targets stay
    /// instruction-local.
    pub fn with_propagation(mut self) -> Self {
        self.retained = Some(BTreeMap::new());
        self
    }

    pub fn begin_function(&mut self) {
        if let Some(retained) = &mut self.retained {
            retained.clear();
        }
        self.retained_operations = 0;
    }

    fn var(&self, value: &PcodeVarnode) -> Var {
        let space = match value.space.as_str() {
            "const" => Space::Const,
            "register" => Space::Register,
            "unique" => Space::Unique,
            _ => Space::Other,
        };
        Var {
            space,
            offset: value.offset,
            size: value.size,
        }
    }

    pub fn inspect(&mut self, function: u64, code: &InstructionPcode) {
        // Preflight the whole instruction before admitting evidence: internal
        // p-code branches make even preceding operations conditional.
        let charged = code
            .operations
            .len()
            .min(MAX_DATA_OPERATIONS_PER_INSTRUCTION)
            .min(MAX_DATA_OPERATIONS - self.report.operations_charged);
        self.report.operations_charged += charged;
        if charged
            < code
                .operations
                .len()
                .min(MAX_DATA_OPERATIONS_PER_INSTRUCTION)
        {
            self.report.partial = true;
            return;
        }
        if code.operations.len() > MAX_DATA_OPERATIONS_PER_INSTRUCTION
            || code
                .operations
                .iter()
                .any(|operation| !supported(operation))
        {
            self.report.unsupported_instructions += 1;
            self.report.partial = true;
            return;
        }
        let mut unresolved = Vec::new();
        for (index, operation) in code.operations.iter().enumerate() {
            use OpCode::*;
            match operation.opcode {
                Call | Callind | Branch | Branchind | Cbranch | Return => continue,
                Load | Store => {
                    let (size, access) = if operation.opcode == Load {
                        (operation.output.as_ref().unwrap().size, DataAccess::Read)
                    } else {
                        (operation.inputs[2].size, DataAccess::Write)
                    };
                    if self.candidate() {
                        let pointer = &operation.inputs[1];
                        if operation.space.as_deref() != Some(self.data_space) || !valid_size(size)
                        {
                            self.report.omitted_accesses += 1;
                        } else if pointer.space != "const" {
                            self.report.unresolved_accesses += 1;
                            unresolved.push(Unresolved {
                                operation: index,
                                size,
                                access,
                            });
                        } else if !fits_width(pointer.offset, pointer.size)
                            || pointer.size > self.pointer_bytes
                        {
                            self.report.omitted_accesses += 1;
                        } else {
                            self.record(
                                function,
                                code.address,
                                pointer.offset,
                                size,
                                access,
                                DataProvenance::InstructionLocal,
                            );
                        }
                    }
                    // Input zero is address-space metadata, never a value read.
                    for input in operation.inputs.iter().skip(1) {
                        self.value(function, code.address, input, DataAccess::Read);
                    }
                }
                _ => {
                    for input in &operation.inputs {
                        self.value(function, code.address, input, DataAccess::Read);
                    }
                }
            }
            if let Some(output) = &operation.output {
                self.value(function, code.address, output, DataAccess::Write);
            }
        }
        self.retain(code, unresolved);
    }

    fn retain(&mut self, code: &InstructionPcode, unresolved: Vec<Unresolved>) {
        let Some(retained) = &self.retained else {
            return;
        };
        if retained.contains_key(&code.address) {
            return;
        }
        if code.operations.len() > MAX_DATA_RETAINED_OPERATIONS - self.retained_operations {
            // The instruction becomes a barrier; later accesses stay unresolved.
            self.report.partial = true;
            return;
        }
        self.retained_operations += code.operations.len();
        let operations = code
            .operations
            .iter()
            .map(|operation| Op {
                opcode: operation.opcode,
                output: operation.output.as_ref().map(|output| self.var(output)),
                inputs: operation
                    .inputs
                    .iter()
                    .map(|input| self.var(input))
                    .collect(),
            })
            .collect();
        self.retained.as_mut().unwrap().insert(
            code.address,
            Retained {
                operations,
                unresolved,
            },
        );
    }

    /// Resolves retained accesses using register constants carried forward
    /// within each basic block. Knowledge resets at every block start, so
    /// joins, loops, and other predecessors never contribute values.
    pub fn propagate<'b>(&mut self, function: u64, blocks: impl Iterator<Item = &'b BasicBlock>) {
        let Some(mut retained) = self.retained.take() else {
            return;
        };
        for block in blocks {
            let mut values = Values::default();
            for instruction in &block.instructions {
                let Some(code) = retained.remove(&instruction.address) else {
                    values = Values::default();
                    continue;
                };
                self.propagate_instruction(function, instruction.address, &code, &mut values);
            }
        }
        // Accesses outside displayed blocks were not given propagation.
        if retained.values().any(|code| !code.unresolved.is_empty()) {
            self.report.partial = true;
        }
        retained.clear();
        self.retained = Some(retained);
        self.retained_operations = 0;
    }

    fn propagate_instruction(
        &mut self,
        function: u64,
        address: u64,
        code: &Retained,
        values: &mut Values,
    ) {
        let mut pending = code.unresolved.iter().peekable();
        for (index, op) in code.operations.iter().enumerate() {
            if let Some(access) = pending.next_if(|access| access.operation == index) {
                let pointer = op.inputs[1];
                if let Some(known) = values.read(pointer)
                    && pointer.size <= self.pointer_bytes
                {
                    self.report.unresolved_accesses -= 1;
                    let provenance = if known.carried {
                        DataProvenance::Propagated
                    } else {
                        DataProvenance::InstructionLocal
                    };
                    self.record(
                        function,
                        address,
                        known.value,
                        access.size,
                        access.access,
                        provenance,
                    );
                }
            }
            match op.opcode {
                // Calls may clobber any register under every supported ABI.
                OpCode::Call | OpCode::Callind => *values = Values::default(),
                _ => {
                    if let Some(output) = op.output {
                        // Loaded values are never modeled.
                        let value = (op.opcode != OpCode::Load)
                            .then(|| evaluate(op, values))
                            .flatten();
                        values.write(output, value);
                        self.report.partial |= values.exhausted;
                    }
                }
            }
        }
        values.end_instruction();
    }

    fn candidate(&mut self) -> bool {
        if self.report.accesses_examined == MAX_DATA_REFERENCES {
            self.report.partial = true;
            false
        } else {
            self.report.accesses_examined += 1;
            true
        }
    }

    fn value(&mut self, function: u64, address: u64, value: &PcodeVarnode, access: DataAccess) {
        if matches!(value.space.as_str(), "const" | "register" | "unique") {
            return;
        }
        if self.candidate() {
            if value.space == self.data_space {
                self.record(
                    function,
                    address,
                    value.offset,
                    value.size,
                    access,
                    DataProvenance::InstructionLocal,
                );
            } else {
                self.report.omitted_accesses += 1;
            }
        }
    }

    fn record(
        &mut self,
        function: u64,
        address: u64,
        target: u64,
        size: u32,
        access: DataAccess,
        provenance: DataProvenance,
    ) {
        if mapped_range(self.sections, target, size, self.pointer_bytes, false) {
            self.references.insert(DataReference {
                function,
                address,
                target,
                size,
                access,
                provenance,
            });
        } else {
            self.report.omitted_accesses += 1;
        }
    }

    pub fn finish(mut self) -> DataAnalysis {
        self.report.references = self.references.into_iter().collect();
        self.report
    }
}

fn supported(operation: &PcodeOperation) -> bool {
    use OpCode::*;
    if operation.inputs.len() > MAX_DATA_OPERATION_INPUTS {
        return false;
    }
    match operation.opcode {
        Load => operation.inputs.len() == 2 && operation.output.is_some(),
        Store => operation.inputs.len() == 3 && operation.output.is_none(),
        Branch | Cbranch => operation
            .inputs
            .first()
            .is_some_and(|target| target.space != "const"),
        Call | Callind | Branchind | Return => true,
        Copy | IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal
        | IntZext | IntSext | IntAdd | IntSub | IntCarry | IntScarry | IntSborrow | Int2comp
        | IntNegate | IntXor | IntAnd | IntOr | IntLeft | IntRight | IntSright | IntMult
        | IntDiv | IntSdiv | IntRem | IntSrem | BoolNegate | BoolXor | BoolAnd | BoolOr
        | FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd
        | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt | FloatInt2float
        | FloatFloat2float | FloatTrunc | FloatCeil | FloatFloor | FloatRound | Piece
        | Subpiece | Popcount | Lzcount => true,
        // High-level, processor-specific, and unknown operations need separate
        // semantics; accepting their operands would invent unconditional reads.
        _ => false,
    }
}

/// One logical access, regardless of how its pointer was established.
fn same_access(a: &DataReference, b: &DataReference) -> bool {
    (a.function, a.address, a.target, a.size, a.access)
        == (b.function, b.address, b.target, b.size, b.access)
}

fn valid_size(size: u32) -> bool {
    (1..=MAX_DATA_ACCESS_BYTES).contains(&size)
}

fn fits_width(address: u64, bytes: u32) -> bool {
    (1..=8).contains(&bytes) && (bytes == 8 || address < (1u64 << (bytes * 8)))
}

fn mapped_range(
    sections: &[SectionInfo],
    address: u64,
    size: u32,
    pointer_bytes: u32,
    executable: bool,
) -> bool {
    if !valid_size(size) || !fits_width(address, pointer_bytes) {
        return false;
    }
    let Some(end) = address.checked_add(u64::from(size)) else {
        return false;
    };
    if !fits_width(end - 1, pointer_bytes) {
        return false;
    }
    sections
        .partition_point(|section| section.address <= address)
        .checked_sub(1)
        .and_then(|index| sections.get(index))
        .is_some_and(|section| {
            (!executable || section.executable)
                && section
                    .address
                    .checked_add(section.size.min(section.file_size))
                    .is_some_and(|section_end| end <= section_end)
        })
}

impl DataAnalysis {
    pub fn validate(
        &self,
        info: &BinaryInfo,
        functions: &[FunctionInfo],
        decode_attempts: usize,
    ) -> Result<(), String> {
        validate_inventory(info, functions)?;
        self.validate_evidence(info, functions, decode_attempts)
    }

    /// Bounds and ownership of this reply's evidence for an inventory already
    /// accepted by [`validate_inventory`].
    pub(crate) fn validate_evidence(
        &self,
        info: &BinaryInfo,
        functions: &[FunctionInfo],
        decode_attempts: usize,
    ) -> Result<(), String> {
        if !self.work_within(decode_attempts, 1) || functions.len() > MAX_FUNCTIONS {
            return Err("Data analysis exceeds its work or result bounds".into());
        }
        self.validate_references(info, |owner| {
            functions
                .binary_search_by_key(&owner, |function| function.address)
                .is_ok()
        })
    }

    /// Accounting consistent with `batches` committed worker replies; one batch
    /// is a single reply. Counters add across batches while evidence is merged.
    pub(crate) fn work_within(&self, decode_attempts: usize, batches: usize) -> bool {
        let counted = self
            .references
            .len()
            .checked_add(self.unresolved_accesses)
            .and_then(|count| count.checked_add(self.omitted_accesses));
        let operation_limit = decode_attempts.checked_mul(MAX_DATA_OPERATIONS_PER_INSTRUCTION);
        let access_limit = self
            .operations_charged
            .checked_mul(MAX_DATA_OPERATION_INPUTS + 2);
        let scaled = |limit: usize| batches.saturating_mul(limit);
        !(decode_attempts > scaled(MAX_ANALYSIS_INSTRUCTIONS)
            || self.operations_charged > scaled(MAX_DATA_OPERATIONS)
            || self.accesses_examined > scaled(MAX_DATA_REFERENCES)
            || self.references.len() > MAX_DATA_REFERENCES
            || self.unsupported_instructions > decode_attempts
            || counted.is_none_or(|count| count > self.accesses_examined)
            || operation_limit.is_none_or(|limit| self.operations_charged > limit)
            || access_limit.is_none_or(|limit| self.accesses_examined > limit)
            || (!self.partial && self.unsupported_instructions != 0))
    }

    /// Address, owner, ordering, and duplicate checks shared by worker replies
    /// and saved discovery snapshots; work bounds are checked by each caller.
    pub(crate) fn validate_references(
        &self,
        info: &BinaryInfo,
        owned: impl Fn(u64) -> bool,
    ) -> Result<(), String> {
        let (alignment, pointer_bytes) = layout(info)?;
        for (index, reference) in self.references.iter().enumerate() {
            if !valid_pc(info, alignment, pointer_bytes, reference.function)
                || !valid_pc(info, alignment, pointer_bytes, reference.address)
                || !owned(reference.function)
                || !mapped_range(
                    &info.sections,
                    reference.target,
                    reference.size,
                    pointer_bytes,
                    false,
                )
                || (index > 0 && self.references[index - 1] >= *reference)
                || (index > 0 && same_access(&self.references[index - 1], reference))
                || (reference.provenance == DataProvenance::Propagated
                    && info.architecture != "AArch64")
            {
                return Err("Invalid data evidence addresses, ordering, or duplicates".into());
            }
        }
        Ok(())
    }
}

/// Instruction alignment and pointer width after checking section layout.
/// Inventory entries owning data evidence must be valid instruction starts.
pub(crate) fn validate_inventory(
    info: &BinaryInfo,
    functions: &[FunctionInfo],
) -> Result<(), String> {
    if functions.len() > MAX_FUNCTIONS {
        return Err("Data analysis exceeds its work or result bounds".into());
    }
    let (alignment, pointer_bytes) = layout(info)?;
    for (index, function) in functions.iter().enumerate() {
        if !valid_pc(info, alignment, pointer_bytes, function.address)
            || function.name.len() > 256
            || (index > 0 && functions[index - 1].address >= function.address)
        {
            return Err("Invalid data analysis function inventory".into());
        }
    }
    Ok(())
}

fn layout(info: &BinaryInfo) -> Result<(u32, u32), String> {
    if info.sections.len() > 4096 {
        return Err("Data analysis exceeds its work or result bounds".into());
    }
    let mut previous_end = None;
    for section in &info.sections {
        let end = section.address.checked_add(section.size);
        let file_end = section
            .file_offset
            .checked_add(section.size.min(section.file_size));
        if section.size == 0
            || end.is_none()
            || file_end.is_none_or(|end| end > info.file_len)
            || previous_end.is_some_and(|end| end > section.address)
        {
            return Err("Invalid data analysis section bounds or ordering".into());
        }
        previous_end = end;
    }
    match info.architecture.as_str() {
        "x86" => Ok((1, 4)),
        "x86-64" => Ok((1, 8)),
        "AArch64" => Ok((4, 8)),
        _ => Err("Unsupported data analysis architecture".into()),
    }
}

fn valid_pc(info: &BinaryInfo, alignment: u32, pointer_bytes: u32, address: u64) -> bool {
    address.is_multiple_of(u64::from(alignment))
        && mapped_range(&info.sections, address, alignment, pointer_bytes, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_decompiler::program::Program;

    fn sections() -> Vec<SectionInfo> {
        vec![
            SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x200,
                file_offset: 0,
                file_size: 0x200,
                executable: true,
            },
            SectionInfo {
                name: ".data".into(),
                address: 0x2000,
                size: 0x200,
                file_offset: 0x200,
                file_size: 0x100,
                executable: false,
            },
        ]
    }

    fn value(space: &str, offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.into(),
            offset,
            size,
        }
    }

    fn copy(input: PcodeVarnode) -> PcodeOperation {
        PcodeOperation {
            opcode: OpCode::Copy,
            output: Some(value("register", 0, input.size)),
            inputs: vec![input],
            space: None,
        }
    }

    fn load(pointer: PcodeVarnode, size: u32) -> PcodeOperation {
        PcodeOperation {
            opcode: OpCode::Load,
            output: Some(value("register", 0, size)),
            inputs: vec![value("const", 0x1100, 8), pointer],
            space: Some("ram".into()),
        }
    }

    fn instruction(operations: Vec<PcodeOperation>) -> InstructionPcode {
        InstructionPcode {
            address: 0x1000,
            length: 4,
            operations,
        }
    }

    fn collect(operations: Vec<PcodeOperation>, pointer_bytes: u32) -> DataAnalysis {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", pointer_bytes);
        collector.inspect(0x1000, &instruction(operations));
        collector.finish()
    }

    fn real(language: &str, bytes: Vec<u8>, count: usize) -> DataAnalysis {
        let pointer_bytes = if language.starts_with("x86:LE:32:") {
            4
        } else {
            8
        };
        let program = Program::from_raw_bytes(bytes, language, 0x1000).unwrap();
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", pointer_bytes);
        for code in program.pcode(0x1000, count).unwrap() {
            collector.inspect(0x1000, &code);
        }
        collector.finish()
    }

    /// Real AArch64 p-code for `words`, inspected in order, then propagated
    /// over blocks given as instruction indices.
    fn propagated(words: &[u32], blocks: &[&[usize]]) -> DataAnalysis {
        let bytes = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let program = Program::from_raw_bytes(bytes, "AARCH64:LE:64:v8A:default", 0x1000).unwrap();
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8).with_propagation();
        collector.begin_function();
        for code in program.pcode(0x1000, words.len()).unwrap() {
            collector.inspect(0x1000, &code);
        }
        let blocks: Vec<_> = blocks
            .iter()
            .map(|indices| BasicBlock {
                address: 0x1000 + 4 * indices[0] as u64,
                instructions: indices
                    .iter()
                    .map(|&index| Instruction {
                        address: 0x1000 + 4 * index as u64,
                        bytes: words[index].to_le_bytes().to_vec(),
                        mnemonic: String::new(),
                        operands: String::new(),
                    })
                    .collect(),
            })
            .collect();
        collector.propagate(0x1000, blocks.iter());
        let report = collector.finish();
        assert!(
            report.references.len() + report.unresolved_accesses + report.omitted_accesses
                <= report.accesses_examined
        );
        report
    }

    fn targets(report: &DataAnalysis) -> Vec<(u64, u64, u32, DataAccess, DataProvenance)> {
        report
            .references
            .iter()
            .map(|r| (r.address, r.target, r.size, r.access, r.provenance))
            .collect()
    }

    const ADRP_X1_NEXT_PAGE: u32 = 0xb000_0001; // adrp x1, 0x2000
    const ADD_X1_0X10: u32 = 0x9100_4021; // add x1, x1, #0x10
    const LDR_X2_X1: u32 = 0xf940_0022; // ldr x2, [x1]

    #[test]
    fn block_local_propagation_resolves_composed_addresses() {
        use DataAccess::*;
        use DataProvenance::*;
        let all = |count: usize| (0..count).collect::<Vec<_>>();
        for (words, expected) in [
            // adrp; add; ldr / str w2, [x1, #4]
            (
                vec![ADRP_X1_NEXT_PAGE, ADD_X1_0X10, LDR_X2_X1, 0xb900_0422],
                vec![
                    (0x1008, 0x2010, 8, Read, Propagated),
                    (0x100c, 0x2014, 4, Write, Propagated),
                ],
            ),
            // adrp; ldr x2, [x1, #8]
            (
                vec![ADRP_X1_NEXT_PAGE, 0xf940_0422],
                vec![(0x1004, 0x2008, 8, Read, Propagated)],
            ),
            // movz x3, #0x2000; movk x3, #0, lsl #16; ldr x4, [x3, #0x18]
            (
                vec![0xd284_0003, 0xf2a0_0003, 0xf940_0c64],
                vec![(0x1008, 0x2018, 8, Read, Propagated)],
            ),
            // adr x5, +0x100; ldrb w6, [x5]
            (
                vec![0x1000_0805, 0x3940_00a6],
                vec![(0x1004, 0x1100, 1, Read, Propagated)],
            ),
            // A 32-bit add writes the zero-extended X register.
            (
                vec![ADRP_X1_NEXT_PAGE, 0x1100_4021, LDR_X2_X1],
                vec![(0x1008, 0x2010, 8, Read, Propagated)],
            ),
        ] {
            let report = propagated(&words, &[&all(words.len())]);
            assert_eq!(targets(&report), expected, "{words:x?}");
            assert_eq!(report.unresolved_accesses, 0, "{words:x?}");
            assert!(!report.partial, "{words:x?}");
        }
    }

    #[test]
    fn calls_unknown_writes_loads_and_block_starts_reset_knowledge() {
        for (words, blocks) in [
            // bl; ldr: direct calls clobber registers.
            (
                vec![ADRP_X1_NEXT_PAGE, 0x9400_0002, LDR_X2_X1],
                vec![vec![0, 1, 2]],
            ),
            // blr x8; ldr: indirect calls too.
            (
                vec![ADRP_X1_NEXT_PAGE, 0xd63f_0100, LDR_X2_X1],
                vec![vec![0, 1, 2]],
            ),
            // mov w1, w7: an unknown write to W1 invalidates X1.
            (
                vec![ADRP_X1_NEXT_PAGE, 0x2a07_03e1, LDR_X2_X1],
                vec![vec![0, 1, 2]],
            ),
            // ldr x1, [x1]; ldr x2, [x1]: loaded pointers are never chased.
            (
                vec![ADRP_X1_NEXT_PAGE, 0xf940_0021, LDR_X2_X1],
                vec![vec![0, 1, 2]],
            ),
            // The load starts another block: no incoming values are reused.
            (vec![ADRP_X1_NEXT_PAGE, LDR_X2_X1], vec![vec![0], vec![1]]),
            // svc #0 is an unsupported user operation and acts as a barrier.
            (
                vec![ADRP_X1_NEXT_PAGE, 0xd400_0001, LDR_X2_X1],
                vec![vec![0, 1, 2]],
            ),
        ] {
            let blocks: Vec<_> = blocks.iter().map(Vec::as_slice).collect();
            let report = propagated(&words, &blocks);
            // The intermediate load may resolve; the final one must not.
            assert!(
                report.references.iter().all(
                    |r| r.address != 0x1008 && (r.address != 0x1004 || words[1] == 0xf940_0021)
                ),
                "{words:x?}: {report:?}"
            );
            assert!(report.unresolved_accesses >= 1, "{words:x?}");
        }
    }

    #[test]
    fn propagated_targets_must_be_mapped_file_backed_ranges() {
        // adrp x1, 0x2000; ldr x2, [x1, #0xf8] reads the last 8 file bytes.
        let report = propagated(&[ADRP_X1_NEXT_PAGE, 0xf940_7c22], &[&[0, 1]]);
        assert_eq!(targets(&report)[0].1, 0x20f8);
        // #0x100 is zero-fill; adrp x1, 0x3000 is unmapped.
        for words in [[ADRP_X1_NEXT_PAGE, 0xf940_8022], [0xd000_0001, LDR_X2_X1]] {
            let report = propagated(&words, &[&[0, 1]]);
            assert!(report.references.is_empty(), "{words:x?}");
            assert_eq!(report.omitted_accesses, 1, "{words:x?}");
            assert_eq!(report.unresolved_accesses, 0, "{words:x?}");
        }
    }

    #[test]
    fn retained_operation_budget_marks_partial_coverage() {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8).with_propagation();
        collector.begin_function();
        let nop = InstructionPcode {
            address: 0,
            length: 4,
            operations: vec![copy(value("const", 0, 8))],
        };
        for address in 0..MAX_DATA_RETAINED_OPERATIONS as u64 {
            collector.inspect(
                0x1000,
                &InstructionPcode {
                    address,
                    ..nop.clone()
                },
            );
        }
        assert!(!collector.report.partial);
        collector.inspect(
            0x1000,
            &InstructionPcode {
                address: u64::MAX,
                ..nop
            },
        );
        assert!(collector.report.partial);
    }

    #[test]
    fn tracked_value_budget_drops_knowledge_and_marks_partial_coverage() {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8).with_propagation();
        let mut operations = Vec::new();
        for index in 0..=MAX_DATA_TRACKED_VALUES as u64 {
            let mut operation = copy(value("const", 0x2000, 8));
            operation.output = Some(value("register", index * 8, 8));
            operations.push(operation);
        }
        operations.push(load(value("register", 0, 8), 8));
        collector.inspect(0x1000, &instruction(operations));
        collector.propagate(
            0x1000,
            [&BasicBlock {
                address: 0x1000,
                instructions: vec![Instruction {
                    address: 0x1000,
                    bytes: vec![0; 4],
                    mnemonic: String::new(),
                    operands: String::new(),
                }],
            }]
            .into_iter(),
        );
        let report = collector.finish();
        assert!(report.references.is_empty());
        assert_eq!(report.unresolved_accesses, 1);
        assert!(report.partial);
    }

    #[test]
    fn value_tracking_uses_little_endian_aliases_and_checked_widths() {
        let register = |offset, size| Var {
            space: Space::Register,
            offset,
            size,
        };
        let mut values = Values::default();
        let known = |value| {
            Some(Known {
                value,
                carried: false,
            })
        };
        values.write(register(0x10, 8), known(0x1122_3344_5566_7788));
        assert_eq!(values.read(register(0x10, 4)).unwrap().value, 0x5566_7788);
        assert_eq!(values.read(register(0x14, 2)).unwrap().value, 0x3344);
        assert!(values.read(register(0x14, 8)).is_none());
        values.write(register(0x10, 4), None);
        assert!(values.read(register(0x10, 8)).is_none());
        assert!(values.read(register(0x14, 4)).is_none());
        values.write(register(u64::MAX, 8), known(1));
        assert!(values.entries.is_empty());
        for index in 0..=MAX_DATA_TRACKED_VALUES as u64 {
            values.write(register(index * 8, 8), known(index));
        }
        assert!(values.entries.len() <= MAX_DATA_TRACKED_VALUES);
        let op = |opcode, inputs: Vec<Var>, size| Op {
            opcode,
            output: Some(register(0x100, size)),
            inputs,
        };
        let constant = |offset, size| Var {
            space: Space::Const,
            offset,
            size,
        };
        let eval = |op: Op| evaluate(&op, &Values::default()).map(|known| known.value);
        assert_eq!(
            eval(op(OpCode::IntSext, vec![constant(0x80, 1)], 8)),
            Some(u64::MAX - 0x7f)
        );
        assert_eq!(
            eval(op(
                OpCode::IntLeft,
                vec![constant(1, 8), constant(64, 8)],
                8
            )),
            Some(0)
        );
        assert_eq!(
            eval(op(
                OpCode::Subpiece,
                vec![constant(0x1122, 2), constant(1, 4)],
                1
            )),
            Some(0x11)
        );
        assert_eq!(
            eval(op(
                OpCode::Subpiece,
                vec![constant(0x1122, 2), constant(2, 4)],
                1
            )),
            None
        );
        assert_eq!(
            eval(op(
                OpCode::Piece,
                vec![constant(0x11, 1), constant(0x22, 1)],
                2
            )),
            Some(0x1122)
        );
        assert_eq!(
            eval(op(OpCode::IntAdd, vec![constant(1, 4), constant(1, 8)], 8)),
            None
        );
        assert_eq!(
            eval(op(OpCode::IntMult, vec![constant(2, 8), constant(2, 8)], 8)),
            None
        );
    }

    #[test]
    fn engine_absolute_rip_and_literal_memory_accesses() {
        for (language, bytes, expected) in [
            (
                "x86:LE:32:default:gcc",
                vec![0xa1, 0x00, 0x11, 0, 0],
                vec![(4, DataAccess::Read)],
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x8b, 0x05, 0xf9, 0, 0, 0],
                vec![(8, DataAccess::Read)],
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x89, 0x05, 0xf9, 0, 0, 0],
                vec![(8, DataAccess::Write)],
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x83, 0x05, 0xf8, 0, 0, 0, 1],
                vec![(8, DataAccess::Read), (8, DataAccess::Write)],
            ),
            (
                "AARCH64:LE:64:v8A:default",
                0x58000800u32.to_le_bytes().to_vec(),
                vec![(8, DataAccess::Read)],
            ),
        ] {
            let report = real(language, bytes, 1);
            assert!(!report.partial, "{language}: {report:?}");
            let actual: Vec<_> = report
                .references
                .iter()
                .map(|reference| {
                    assert_eq!(reference.function, 0x1000);
                    assert_eq!(reference.address, 0x1000);
                    assert_eq!(reference.target, 0x1100);
                    (reference.size, reference.access)
                })
                .collect();
            assert_eq!(actual, expected, "{language}");
        }
    }

    #[test]
    fn engine_constants_and_dynamic_addresses_do_not_invent_references() {
        for (language, bytes, count, unresolved) in [
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x8d, 0x05, 0xf9, 0, 0, 0],
                1,
                false,
            ),
            (
                "x86:LE:64:default:gcc",
                vec![0xb8, 0x00, 0x11, 0, 0],
                1,
                false,
            ),
            ("x86:LE:64:default:gcc", vec![0x48, 0x8b, 0x00], 1, true),
            (
                "x86:LE:64:default:gcc",
                vec![0x48, 0x8b, 0x04, 0x24],
                1,
                true,
            ),
            ("x86:LE:64:default:gcc", vec![0xe8, 0xfb, 0, 0, 0], 1, true),
            (
                "AARCH64:LE:64:v8A:default",
                0x10000800u32.to_le_bytes().to_vec(),
                1,
                false,
            ),
            (
                "AARCH64:LE:64:v8A:default",
                [0x90000010u32, 0xf9408211]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
                2,
                true,
            ),
        ] {
            let report = real(language, bytes, count);
            assert!(report.references.is_empty(), "{language}: {report:?}");
            assert_eq!(
                report.unresolved_accesses > 0,
                unresolved,
                "{language}: {report:?}"
            );
        }
    }

    #[test]
    fn load_store_use_pointer_slot_and_value_width_and_account_for_memory_values() {
        let store = PcodeOperation {
            opcode: OpCode::Store,
            output: None,
            inputs: vec![
                value("const", 0x1100, 8),
                value("const", 0x2000, 8),
                value("ram", 0x1104, 4),
            ],
            space: Some("ram".into()),
        };
        let mut read = load(value("const", 0x2000, 8), 8);
        read.output = Some(value("ram", 0x1108, 8));
        let report = collect(vec![store, read], 8);
        assert_eq!(report.accesses_examined, 4);
        assert_eq!(
            report
                .references
                .iter()
                .map(|r| (r.target, r.size, r.access))
                .collect::<Vec<_>>(),
            vec![
                (0x1104, 4, DataAccess::Read),
                (0x1108, 8, DataAccess::Write),
                (0x2000, 4, DataAccess::Write),
                (0x2000, 8, DataAccess::Read),
            ]
        );
        let indirect = collect(vec![load(value("ram", 0x2000, 8), 4)], 8);
        assert_eq!(indirect.accesses_examined, 2);
        assert_eq!(indirect.unresolved_accesses, 1);
        assert_eq!(indirect.references.len(), 1);
        assert_eq!(indirect.references[0].target, 0x2000);
        assert_eq!(indirect.references[0].size, 8);
        assert_eq!(indirect.references[0].access, DataAccess::Read);
    }

    #[test]
    fn no_register_unique_or_cross_instruction_propagation() {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8);
        for space in ["register", "unique"] {
            let mut establish = copy(value("const", 0x2000, 8));
            establish.output = Some(value(space, 0, 8));
            collector.inspect(0x1000, &instruction(vec![establish]));
            collector.inspect(0x1000, &instruction(vec![load(value(space, 0, 8), 8)]));
        }
        let report = collector.finish();
        assert!(report.references.is_empty());
        assert_eq!(report.unresolved_accesses, 2);
        assert!(!report.partial);
    }

    #[test]
    fn refuses_conditional_internal_flow_and_unsupported_instructions_atomically() {
        for opcode in [
            OpCode::Branch,
            OpCode::Cbranch,
            OpCode::Callother,
            OpCode::Multiequal,
            OpCode::Indirect,
            OpCode::Ptradd,
            OpCode::New,
        ] {
            let unsupported = PcodeOperation {
                opcode,
                output: None,
                inputs: vec![value("const", 1, 8)],
                space: None,
            };
            let report = collect(vec![copy(value("ram", 0x1100, 8)), unsupported], 8);
            assert!(report.references.is_empty());
            assert_eq!(report.accesses_examined, 0);
            assert_eq!(report.operations_charged, 2);
            assert_eq!(report.unsupported_instructions, 1);
            assert!(report.partial);
        }
        for opcode in [
            OpCode::Branch,
            OpCode::Cbranch,
            OpCode::Call,
            OpCode::Callind,
            OpCode::Branchind,
            OpCode::Return,
        ] {
            let report = collect(
                vec![PcodeOperation {
                    opcode,
                    output: Some(value("ram", 0x1108, 8)),
                    inputs: vec![value("ram", 0x1100, 8)],
                    space: None,
                }],
                8,
            );
            assert!(report.references.is_empty());
            assert_eq!(report.accesses_examined, 0);
        }
    }

    #[test]
    fn omits_unmapped_bss_crossing_overflow_bad_width_and_other_spaces() {
        for (target, size) in [
            (0x3000, 8),
            (0x2100, 8),
            (0x20fc, 8),
            (u64::MAX, 8),
            (0x2000, 0),
            (0x2000, 65),
        ] {
            let report = collect(vec![copy(value("ram", target, size))], 8);
            assert!(report.references.is_empty());
            assert_eq!(report.omitted_accesses, 1);
            assert_eq!(report.accesses_examined, 1);
        }
        let mut wrong_space = load(value("const", 0x2000, 8), 8);
        wrong_space.space = Some("other".into());
        let report = collect(vec![wrong_space, copy(value("other", 0x1100, 8))], 8);
        assert!(report.references.is_empty());
        assert_eq!(report.omitted_accesses, 2);
        // The space-ID metadata happens to look mapped, but creates no read.
        let report = collect(vec![load(value("const", 0x3000, 8), 8)], 8);
        assert!(report.references.is_empty());
        assert_eq!(report.accesses_examined, 1);
    }

    #[test]
    fn rejects_pointer_truncation_and_target_width_overflow() {
        for (pointer, pointer_bytes) in [
            (value("const", 0x1_0000_2000, 4), 8),
            (value("const", 0x2000, 8), 4),
            (value("const", 0x2000, 0), 8),
            (value("const", 0x2000, 9), 8),
        ] {
            let report = collect(vec![load(pointer, 8)], pointer_bytes);
            assert!(report.references.is_empty());
            assert_eq!(report.omitted_accesses, 1);
        }
        let high = vec![SectionInfo {
            name: "high".into(),
            address: 0xffff_fff0,
            size: 64,
            file_offset: 0,
            file_size: 64,
            executable: false,
        }];
        let mut collector = DataCollector::new(&high, "ram", 4);
        collector.inspect(
            0x1000,
            &instruction(vec![copy(value("ram", 0xffff_fffc, 8))]),
        );
        assert_eq!(collector.finish().omitted_accesses, 1);
    }

    #[test]
    fn charges_duplicates_before_dedup_and_bounds_candidates_and_operations() {
        let sections = sections();
        let mut collector = DataCollector::new(&sections, "ram", 8);
        let code = instruction(vec![
            copy(value("ram", 0x1100, 8));
            MAX_DATA_OPERATIONS_PER_INSTRUCTION
        ]);
        for _ in 0..MAX_DATA_REFERENCES / MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1 {
            collector.inspect(0x1000, &code);
        }
        let report = collector.finish();
        assert_eq!(report.references.len(), 1);
        assert_eq!(report.accesses_examined, MAX_DATA_REFERENCES);
        assert_eq!(
            report.operations_charged,
            MAX_DATA_REFERENCES + MAX_DATA_OPERATIONS_PER_INSTRUCTION
        );
        assert!(report.partial);

        let mut collector = DataCollector::new(&sections, "ram", 8);
        let no_access = instruction(vec![
            copy(value("const", 0x1100, 8));
            MAX_DATA_OPERATIONS_PER_INSTRUCTION
        ]);
        for _ in 0..MAX_DATA_OPERATIONS / MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1 {
            collector.inspect(0x1000, &no_access);
        }
        let report = collector.finish();
        assert_eq!(report.operations_charged, MAX_DATA_OPERATIONS);
        assert_eq!(report.accesses_examined, 0);
        assert!(report.partial);

        let report = collect(
            vec![copy(value("ram", 0x1100, 8)); MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1],
            8,
        );
        assert_eq!(
            report.operations_charged,
            MAX_DATA_OPERATIONS_PER_INSTRUCTION
        );
        assert_eq!(report.unsupported_instructions, 1);
        assert!(report.references.is_empty());
        let mut operation = copy(value("ram", 0x1100, 8));
        operation.inputs = vec![value("ram", 0x1100, 8); MAX_DATA_OPERATION_INPUTS + 1];
        let report = collect(vec![operation], 8);
        assert_eq!(report.unsupported_instructions, 1);
        assert_eq!(report.accesses_examined, 0);
    }

    fn binary() -> BinaryInfo {
        BinaryInfo {
            path: "fixture".into(),
            architecture: "AArch64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 0x300,
            sha256: "a".repeat(64),
            source_identity: None,
            sections: sections(),
            functions: vec![FunctionInfo {
                address: 0x1000,
                name: "caller".into(),
            }],
            functions_truncated: false,
            warnings: vec![],
        }
    }

    #[test]
    fn validates_transport_bounds_addresses_owner_order_and_accounting() {
        let info = binary();
        let report = collect(vec![copy(value("ram", 0x2000, 8))], 8);
        report.validate(&info, &info.functions, 1).unwrap();
        for (function, address, target, size) in [
            (0x1004, 0x1000, 0x2000, 8), // unknown owner
            (0x1000, 0x1002, 0x2000, 8), // unaligned instruction
            (0x1000, 0x2000, 0x2000, 8), // nonexecutable instruction
            (0x1000, 0x1000, 0x2100, 8), // BSS
            (0x1000, 0x1000, 0x20fc, 8), // crosses backed end
            (0x1000, 0x1000, u64::MAX, 8),
            (0x1000, 0x1000, 0x2000, 0),
            (0x1000, 0x1000, 0x2000, 65),
        ] {
            let mut invalid = report.clone();
            invalid.references[0] = DataReference {
                function,
                address,
                target,
                size,
                access: DataAccess::Read,
                provenance: DataProvenance::InstructionLocal,
            };
            assert!(invalid.validate(&info, &info.functions, 1).is_err());
        }
        let mut invalid = report.clone();
        invalid.references.push(invalid.references[0].clone());
        invalid.accesses_examined = 2;
        assert!(invalid.validate(&info, &info.functions, 1).is_err());
        for invalid in [
            DataAnalysis {
                operations_charged: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                accesses_examined: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                unresolved_accesses: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                omitted_accesses: usize::MAX,
                ..report.clone()
            },
            DataAnalysis {
                unsupported_instructions: 2,
                partial: true,
                ..report.clone()
            },
            DataAnalysis {
                operations_charged: 0,
                ..report.clone()
            },
            DataAnalysis {
                accesses_examined: 0,
                ..report.clone()
            },
            DataAnalysis {
                operations_charged: MAX_DATA_OPERATIONS_PER_INSTRUCTION + 1,
                ..report.clone()
            },
        ] {
            assert!(invalid.validate(&info, &info.functions, 1).is_err());
        }
        assert!(report.validate(&info, &info.functions, 0).is_err());
        assert!(report.validate(&info, &info.functions, usize::MAX).is_err());
        let mut invalid = info.clone();
        invalid.functions.push(invalid.functions[0].clone());
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.architecture = "x86".into();
        invalid.sections.push(SectionInfo {
            name: "high".into(),
            address: 0x1_0000_2000,
            size: 64,
            file_offset: 0,
            file_size: 64,
            executable: false,
        });
        let mut high = report.clone();
        high.references[0].target = 0x1_0000_2000;
        assert!(high.validate(&invalid, &invalid.functions, 1).is_err());
    }

    #[test]
    fn rejects_spoofed_section_backing_order_overlap_and_overflow() {
        let info = binary();
        let report = collect(vec![copy(value("ram", 0x2000, 8))], 8);
        let mut invalid = info.clone();
        invalid.sections[1].file_size = invalid.sections[1].size;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections[1].file_offset = u64::MAX;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections.reverse();
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections[1].address = 0x1100;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections[1].address = u64::MAX - 1;
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
        let mut invalid = info.clone();
        invalid.sections = vec![info.sections[0].clone(); 4097];
        assert!(report.validate(&invalid, &invalid.functions, 1).is_err());
    }
}
