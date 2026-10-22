//! Recovers `main` in stripped, dynamically linked ELF executables from the C
//! runtime's startup call `__libc_start_main(main, ...)` in the entry function.
//!
//! Evidence must be complete or nothing is recovered: engine p-code along a
//! bounded straight-line path from the entry, an import whose identity is
//! verified from the ELF's own dynamic relocations and symbols, and a first
//! argument whose value is a constant or a relocated pointer slot. Supported:
//! x86-64 System V ELF executables (ET_EXEC or PIE) with `PT_INTERP`. AArch64
//! awaits original dynamically linked fixtures; static, i386, musl
//! `_start_c`, and wrapper startup variants are deliberately unsupported.
use std::collections::{BTreeMap, BTreeSet};

use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{FunctionSource, InstructionPcode, PcodeVarnode, Program};
use object::Endianness;
use object::elf;

use object::read::elf::{
    ElfFile64, FileHeader, ProgramHeader, Rela, SectionHeader, Sym, SymbolTable,
};

use crate::data_analysis::mask;

const LIBC_START_MAIN: &str = "__libc_start_main";
/// Contiguous bytes the entry path may span.
const MAX_ENTRY_BYTES: u64 = 256;
/// Instructions decoded across the entry path, stub checks and the candidate.
const MAX_INSTRUCTIONS: usize = 64;
const MAX_OPERATIONS: usize = 4096;
const MAX_OPERATIONS_PER_INSTRUCTION: usize = 256;
/// Tracked register and temporary values; more makes the path unsupported.
const MAX_VALUES: usize = 128;
/// Import stubs claiming the libc name that are checked against its slots,
/// and relocated slots for that import.
const MAX_STUBS: usize = 4;
/// Leading landing-pad or no-op instructions skipped by the wrapper check.
const MAX_PREFIX: usize = 4;

/// A recovered startup callback and the evidence that established it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Recovery {
    pub main: u64,
    /// The call instruction that passes `main` to the libc import.
    pub call: u64,
}

/// Why recognition produced no result. Only exhausted budgets are reported to
/// the analyst; an unrecognized startup shape is the normal quiet outcome.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Miss {
    NotApplicable,
    Unrecognized,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Constant(u64),
    /// The pointer-sized contents of an image slot, not yet interpreted.
    Loaded(u64),
    /// An address derived from the entry stack pointer, whose stores cannot
    /// change image slots.
    Stack,
}

/// The executable's dynamic relocations, with the libc import's slots.
/// Lookups scan the records again rather than indexing them: recognition needs
/// only a handful, and the records are bounded by the image size.
struct Relocations<'a> {
    endian: Endianness,
    tables: Vec<&'a [elf::Rela64<Endianness>]>,
    symbols: SymbolTable<'a, elf::FileHeader64<Endianness>>,
    libc_slots: BTreeSet<u64>,
}

impl Relocations<'_> {
    fn records(&self) -> impl Iterator<Item = &elf::Rela64<Endianness>> {
        self.tables.iter().flat_map(|records| records.iter())
    }

    /// The only relocation at `slot`; conflicting relocations establish nothing.
    fn single(&self, slot: u64) -> Option<&elf::Rela64<Endianness>> {
        let mut found = None;
        for record in self.records() {
            if record.r_offset(self.endian) == slot && found.replace(record).is_some() {
                return None;
            }
        }
        found
    }

    /// The link-time value of a slot holding a pointer to a local definition.
    fn pointer(&self, slot: u64) -> Option<u64> {
        let endian = self.endian;
        let record = self.single(slot)?;
        let (r_type, symbol, addend) = (
            record.r_type(endian, false),
            record.r_sym(endian, false),
            record.r_addend(endian),
        );
        if symbol == 0 {
            return (r_type == elf::R_X86_64_RELATIVE)
                .then(|| u64::try_from(addend).ok())
                .flatten();
        }
        let symbol = self
            .symbols
            .symbol(object::SymbolIndex(symbol as usize))
            .ok()?;
        // A function defined in the executable itself; executables are not
        // interposed, so the slot holds this link-time address.
        (matches!(r_type, elf::R_X86_64_GLOB_DAT | elf::R_X86_64_64)
            && symbol.st_shndx(endian) != elf::SHN_UNDEF
            && symbol.st_type() == elf::STT_FUNC)
            .then(|| symbol.st_value(endian).checked_add_signed(addend))
            .flatten()
    }
}

fn relocations<'a>(bytes: &'a [u8], architecture: &str) -> Result<Relocations<'a>, Miss> {
    if architecture != "x86-64" {
        return Err(Miss::NotApplicable);
    }
    let Ok(file) = ElfFile64::<Endianness>::parse(bytes) else {
        return Err(Miss::NotApplicable);
    };
    let endian = file.endian();
    let header = file.elf_header();
    if !matches!(header.e_type(endian), elf::ET_EXEC | elf::ET_DYN)
        || !file
            .elf_program_headers()
            .iter()
            .any(|segment| segment.p_type(endian) == elf::PT_INTERP)
    {
        return Err(Miss::NotApplicable);
    }
    // Every relocation against the dynamic symbol table: import slots and
    // pointer slots usually live in different sections.
    let sections = file.elf_section_table();
    let mut symbols = None;
    let mut tables = Vec::new();
    for section in sections.iter() {
        if section.sh_type(endian) != elf::SHT_RELA {
            continue;
        }
        let Ok(Some((records, link))) = section.rela(endian, bytes) else {
            continue;
        };
        if sections
            .section(link)
            .map_or(true, |linked| linked.sh_type(endian) != elf::SHT_DYNSYM)
        {
            continue;
        }
        match symbols {
            None => match sections.symbol_table_by_index(endian, bytes, link) {
                Ok(table) => symbols = Some((link, table)),
                Err(_) => return Err(Miss::Unrecognized),
            },
            // One dynamic symbol table names every import.
            Some((existing, _)) if existing != link => return Err(Miss::Unrecognized),
            Some(_) => {}
        }
        tables.push(records);
    }
    let Some((_, symbols)) = symbols else {
        return Err(Miss::Unrecognized);
    };
    let imports: BTreeSet<u32> = symbols
        .symbols()
        .iter()
        .enumerate()
        .filter(|(_, symbol)| {
            symbol.st_shndx(endian) == elf::SHN_UNDEF
                && symbols.symbol_name(endian, *symbol) == Ok(LIBC_START_MAIN.as_bytes())
        })
        .filter_map(|(index, _)| u32::try_from(index).ok())
        .collect();
    let mut relocations = Relocations {
        endian,
        tables,
        symbols,
        libc_slots: BTreeSet::new(),
    };
    let mut candidates = BTreeSet::new();
    for record in relocations.records() {
        if matches!(
            record.r_type(endian, false),
            elf::R_X86_64_GLOB_DAT | elf::R_X86_64_JUMP_SLOT
        ) && imports.contains(&record.r_sym(endian, false))
        {
            candidates.insert(record.r_offset(endian));
            if candidates.len() > MAX_STUBS {
                return Err(Miss::Unrecognized);
            }
        }
    }
    candidates.retain(|&slot| relocations.single(slot).is_some());
    if candidates.is_empty() {
        return Err(Miss::Unrecognized);
    }
    relocations.libc_slots = candidates;
    Ok(relocations)
}

/// Verified glibc startup import slots, also used when `main` already has a
/// symbol. Failure to recognize the relocation layout establishes no slots.
pub(crate) fn libc_start_slots(bytes: &[u8], architecture: &str) -> BTreeSet<u64> {
    relocations(bytes, architecture)
        .map(|r| r.libc_slots)
        .unwrap_or_default()
}

/// Register and temporary values along one straight-line path. Writes that
/// overlap a tracked value forget it; reads need the exact stored extent.
/// Image slots keep their relocated contents only until the path may have
/// stored to them.
struct State {
    values: BTreeMap<(bool, u64), (u32, Value)>,
    pointer_bytes: u32,
    /// Memory ranges written at constant addresses.
    stored: Vec<(u64, u64)>,
    /// A store whose address is neither constant nor stack-derived.
    unknown_store: bool,
}

impl State {
    fn key(varnode: &PcodeVarnode) -> Option<(bool, u64)> {
        match varnode.space.as_str() {
            "register" => Some((false, varnode.offset)),
            "unique" => Some((true, varnode.offset)),
            _ => None,
        }
    }

    fn read(&self, varnode: &PcodeVarnode) -> Option<Value> {
        match varnode.space.as_str() {
            "const" => return Some(Value::Constant(varnode.offset & mask(varnode.size))),
            // A pointer-sized operand at a fixed image address, such as a GOT
            // slot read by `call *slot(%rip)`.
            "ram" if varnode.size == self.pointer_bytes => return self.slot(varnode.offset),
            _ => {}
        }
        let &(size, value) = self.values.get(&Self::key(varnode)?)?;
        match value {
            _ if size == varnode.size => Some(value),
            // Little-endian low bytes of a known constant.
            Value::Constant(constant) if varnode.size < size => {
                Some(Value::Constant(constant & mask(varnode.size)))
            }
            _ => None,
        }
    }

    fn write(&mut self, varnode: &PcodeVarnode, value: Option<Value>) -> Result<(), Miss> {
        let Some(key) = Self::key(varnode) else {
            return Ok(());
        };
        let end = key.1.saturating_add(u64::from(varnode.size));
        self.values.retain(|&(unique, start), &mut (size, _)| {
            unique != key.0 || start >= end || start.saturating_add(u64::from(size)) <= key.1
        });
        if let Some(value) = value {
            if self.values.len() >= MAX_VALUES {
                return Err(Miss::Exhausted);
            }
            self.values.insert(key, (varnode.size, value));
        }
        Ok(())
    }

    fn new(pointer_bytes: u32) -> Self {
        Self {
            values: BTreeMap::new(),
            pointer_bytes,
            stored: Vec::new(),
            unknown_store: false,
        }
    }

    /// The contents of the pointer slot at `address`, unless overwritten.
    fn slot(&self, address: u64) -> Option<Value> {
        let end = address.checked_add(u64::from(self.pointer_bytes))?;
        let overwritten = self.unknown_store
            || self
                .stored
                .iter()
                .any(|&(start, stop)| start < end && address < stop);
        (!overwritten).then_some(Value::Loaded(address))
    }

    /// A pointer-sized read through `address`.
    fn load(&self, address: Option<Value>, size: u32) -> Option<Value> {
        match address {
            Some(Value::Constant(address)) if size == self.pointer_bytes => self.slot(address),
            _ => None,
        }
    }

    fn store(&mut self, address: Option<Value>, size: u32) -> Result<(), Miss> {
        match address {
            Some(Value::Stack) => {}
            Some(Value::Constant(start)) => match start.checked_add(u64::from(size)) {
                Some(end) if self.stored.len() < MAX_VALUES => self.stored.push((start, end)),
                Some(_) => return Err(Miss::Exhausted),
                None => self.unknown_store = true,
            },
            _ => self.unknown_store = true,
        }
        Ok(())
    }

    fn clear_temporaries(&mut self) {
        self.values.retain(|&(unique, _), _| !unique);
    }
}

fn evaluate(opcode: OpCode, inputs: &[Option<Value>], output_size: u32) -> Option<Value> {
    use OpCode::*;
    let constant = |index: usize| match inputs.get(index)? {
        Some(Value::Constant(value)) => Some(*value),
        _ => None,
    };
    let stack = |index: usize| inputs.get(index) == Some(&Some(Value::Stack));
    let output = mask(output_size);
    let value = match opcode {
        Copy => return *inputs.first()?,
        // Stack adjustment and realignment, as in `and $-16, %rsp`.
        IntAdd if stack(0) && constant(1).is_some() || stack(1) && constant(0).is_some() => {
            return Some(Value::Stack);
        }
        IntSub | IntAnd if stack(0) && constant(1).is_some() => return Some(Value::Stack),
        IntAdd => constant(0)?.wrapping_add(constant(1)?),
        IntSub => constant(0)?.wrapping_sub(constant(1)?),
        IntAnd => constant(0)? & constant(1)?,
        IntOr => constant(0)? | constant(1)?,
        IntXor => constant(0)? ^ constant(1)?,
        IntLeft => constant(0)?.checked_shl(u32::try_from(constant(1)?).ok()?)?,
        IntRight => constant(0)?.checked_shr(u32::try_from(constant(1)?).ok()?)?,
        IntZext => constant(0)?,
        _ => return None,
    };
    Some(Value::Constant(value & output))
}

/// The call that consumed the argument, or why the path ended.
enum Stop {
    /// A call into the verified libc import, with the argument at that point.
    Libc {
        call: u64,
        argument: Option<Value>,
    },
    /// An indirect branch through a slot, as in an import stub.
    Jump(Value),
    Other,
}

struct Walker<'a> {
    program: &'a Program,
    pointer_bytes: u32,
    argument: PcodeVarnode,
    stack: PcodeVarnode,
    libc_slots: &'a BTreeSet<u64>,
    libc_stubs: BTreeSet<u64>,
    instructions: usize,
    operations: usize,
}

impl Walker<'_> {
    fn decode(&mut self, address: u64) -> Result<Option<InstructionPcode>, Miss> {
        if self.instructions >= MAX_INSTRUCTIONS {
            return Err(Miss::Exhausted);
        }
        self.instructions += 1;
        let Ok(mut decoded) = self.program.pcode(address, 1) else {
            return Ok(None);
        };
        let Some(code) = decoded.pop() else {
            return Ok(None);
        };
        if code.length == 0 || code.operations.len() > MAX_OPERATIONS_PER_INSTRUCTION {
            return Ok(None);
        }
        self.operations += code.operations.len();
        if self.operations > MAX_OPERATIONS {
            return Err(Miss::Exhausted);
        }
        Ok(Some(code))
    }

    /// Follows sequential instructions from `start` until a call or transfer.
    fn walk(&mut self, start: u64, limit: u64) -> Result<Stop, Miss> {
        let mut state = State::new(self.pointer_bytes);
        state.write(&self.stack, Some(Value::Stack))?;
        let mut address = start;
        let end = start.saturating_add(limit);
        while address < end {
            let Some(code) = self.decode(address)? else {
                return Ok(Stop::Other);
            };
            state.clear_temporaries();
            for operation in &code.operations {
                use OpCode::*;
                match operation.opcode {
                    Call => {
                        let Some(target) = operation.inputs.first() else {
                            return Ok(Stop::Other);
                        };
                        if target.space != "const" && self.libc_stubs.contains(&target.offset) {
                            return Ok(Stop::Libc {
                                call: code.address,
                                argument: state.read(&self.argument),
                            });
                        }
                        return Ok(Stop::Other);
                    }
                    Callind => {
                        let target = operation.inputs.first().and_then(|t| state.read(t));
                        if let Some(Value::Loaded(slot)) = target
                            && self.libc_slots.contains(&slot)
                        {
                            return Ok(Stop::Libc {
                                call: code.address,
                                argument: state.read(&self.argument),
                            });
                        }
                        return Ok(Stop::Other);
                    }
                    Branchind => {
                        return Ok(match operation.inputs.first().and_then(|t| state.read(t)) {
                            Some(value) => Stop::Jump(value),
                            None => Stop::Other,
                        });
                    }
                    // Internal p-code branches make the path conditional.
                    Branch | Cbranch | Return => return Ok(Stop::Other),
                    Store => {
                        let address = operation.inputs.get(1).and_then(|a| state.read(a));
                        let size = operation.inputs.get(2).map_or(0, |value| value.size);
                        state.store(address, size)?;
                    }
                    _ => {
                        let Some(output) = &operation.output else {
                            continue;
                        };
                        let inputs: Vec<_> =
                            operation.inputs.iter().map(|i| state.read(i)).collect();
                        let value = match operation.opcode {
                            Load => state.load(inputs.get(1).copied().flatten(), output.size),
                            opcode => evaluate(opcode, &inputs, output.size),
                        };
                        state.write(output, value)?;
                    }
                }
            }
            address = match address.checked_add(code.length as u64) {
                Some(next) => next,
                None => return Ok(Stop::Other),
            };
        }
        Ok(Stop::Other)
    }
}

/// Whether `address` begins with only landing pads or no-ops followed by an
/// unconditional transfer: a wrapper whose target could also be `main`.
fn is_wrapper(walker: &mut Walker<'_>, mut address: u64) -> Result<bool, Miss> {
    for _ in 0..=MAX_PREFIX {
        let Some(code) = walker.decode(address)? else {
            return Ok(true);
        };
        if !code.operations.is_empty() {
            return Ok(code
                .operations
                .iter()
                .any(|op| matches!(op.opcode, OpCode::Branch | OpCode::Branchind)));
        }
        address = match address.checked_add(code.length as u64) {
            Some(next) => next,
            None => return Ok(true),
        };
    }
    Ok(true)
}

/// Recognizes the startup call and returns the unvalidated candidate.
/// `code_address` must accept only aligned file-backed executable starts.
pub(crate) fn recognize(
    program: &mut Program,
    bytes: &[u8],
    architecture: &str,
    entry: u64,
    pointer_bytes: u32,
    code_address: impl Fn(u64) -> bool,
) -> Result<Recovery, Miss> {
    let relocations = relocations(bytes, architecture)?;
    // The first integer argument in the System V AMD64 calling convention,
    // and the stack pointer.
    let (argument, stack) = {
        let translator = program
            .architecture()
            .translator()
            .map_err(|_| Miss::Unrecognized)?;
        let register = |name| {
            let storage = translator
                .get_register(name)
                .map_err(|_| Miss::Unrecognized)?;
            Ok(PcodeVarnode {
                space: "register".into(),
                offset: storage.offset,
                size: storage.size,
            })
        };
        (register("RDI")?, register("RSP")?)
    };
    if argument.size != pointer_bytes || stack.size != pointer_bytes {
        return Err(Miss::Unrecognized);
    }
    let claimed: Vec<_> = program
        .functions()
        .map_err(|_| Miss::Unrecognized)?
        .into_iter()
        .filter(|function| {
            // `symbol` keeps the import name only when a collision renamed
            // the stub; otherwise the name is the import's.
            function.source == FunctionSource::ImportStub
                && function.symbol.as_deref().unwrap_or(&function.name) == LIBC_START_MAIN
        })
        .map(|function| function.address)
        .take(MAX_STUBS + 1)
        .collect();
    if claimed.len() > MAX_STUBS {
        return Err(Miss::Exhausted);
    }
    let mut walker = Walker {
        program,
        pointer_bytes,
        argument,
        stack,
        libc_slots: &relocations.libc_slots,
        libc_stubs: BTreeSet::new(),
        instructions: 0,
        operations: 0,
    };
    // An engine-named stub is accepted only if it jumps through a verified
    // libc slot; the name alone is not import evidence.
    for stub in claimed {
        if let Stop::Jump(Value::Loaded(slot)) = walker.walk(stub, MAX_ENTRY_BYTES)?
            && relocations.libc_slots.contains(&slot)
        {
            walker.libc_stubs.insert(stub);
        }
    }
    let Stop::Libc { call, argument } = walker.walk(entry, MAX_ENTRY_BYTES)? else {
        return Err(Miss::Unrecognized);
    };
    let main = match argument {
        Some(Value::Constant(address)) => address,
        Some(Value::Loaded(slot)) => relocations.pointer(slot).ok_or(Miss::Unrecognized)?,
        Some(Value::Stack) | None => return Err(Miss::Unrecognized),
    };
    if main == entry
        || walker.libc_stubs.contains(&main)
        || !code_address(main)
        || is_wrapper(&mut walker, main)?
    {
        return Err(Miss::Unrecognized);
    }
    Ok(Recovery { main, call })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(offset: u64, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: "register".into(),
            offset,
            size,
        }
    }

    #[test]
    fn partial_and_overlapping_writes_forget_the_argument() {
        let mut state = State::new(8);
        let rdi = register(0x38, 8);
        state.write(&rdi, Some(Value::Constant(0x3090))).unwrap();
        // The low half of a known constant is still known.
        assert_eq!(
            state.read(&register(0x38, 4)),
            Some(Value::Constant(0x3090))
        );
        // Writing only the low byte leaves the full register unknown.
        state.write(&register(0x38, 1), None).unwrap();
        assert_eq!(state.read(&rdi), None);
        state.write(&rdi, Some(Value::Constant(0x3090))).unwrap();
        state
            .write(&register(0x3c, 4), Some(Value::Constant(0)))
            .unwrap();
        assert_eq!(state.read(&rdi), None);
    }

    #[test]
    fn only_pointer_sized_fixed_reads_name_a_slot() {
        let state = State::new(8);
        let slot = |size| PcodeVarnode {
            space: "ram".into(),
            offset: 0x9fc0,
            size,
        };
        assert_eq!(state.read(&slot(8)), Some(Value::Loaded(0x9fc0)));
        assert_eq!(state.read(&slot(4)), None);
        assert_eq!(state.load(Some(Value::Constant(0x9fc0)), 4), None);
        // A slot's contents are not a constant to compute with.
        assert_eq!(
            evaluate(
                OpCode::IntAdd,
                &[Some(Value::Loaded(0x9fc0)), Some(Value::Constant(8))],
                8
            ),
            None
        );
    }

    #[test]
    fn stores_that_may_reach_a_slot_hide_its_relocated_contents() {
        let mut state = State::new(8);
        // Pushes through the realigned entry stack leave slots intact.
        let aligned = evaluate(
            OpCode::IntAnd,
            &[Some(Value::Stack), Some(Value::Constant(!0xf))],
            8,
        );
        assert_eq!(aligned, Some(Value::Stack));
        state.store(aligned, 8).unwrap();
        assert_eq!(
            state.load(Some(Value::Constant(0x9fc0)), 8),
            Some(Value::Loaded(0x9fc0))
        );
        // A store overlapping the slot's last byte overwrites it.
        state.store(Some(Value::Constant(0x9fc7)), 1).unwrap();
        assert_eq!(state.load(Some(Value::Constant(0x9fc0)), 8), None);
        assert_eq!(
            state.load(Some(Value::Constant(0x9fc8)), 8),
            Some(Value::Loaded(0x9fc8))
        );
        // An unknown destination could be any slot.
        state.store(None, 8).unwrap();
        assert_eq!(state.load(Some(Value::Constant(0x9fc8)), 8), None);
        // Stack contents are never slot contents.
        assert_eq!(state.load(Some(Value::Stack), 8), None);
    }
}
