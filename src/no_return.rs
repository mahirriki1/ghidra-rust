//! Calls to functions that never return, recognized by exact import or symbol
//! identity against Ghidra's named lists (see `data/no-return/README.md`).
//! A recognized call ends its block: the bytes after it are not its successor.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, OnceLock};

use ghidra_decompiler::address::Address;
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{FunctionSource, InstructionPcode, Program};

use crate::model::{NoReturnEvidence, SectionInfo};

const ELF: &str = include_str!("../data/no-return/ElfFunctionsThatDoNotReturn");
const PE: &str = include_str!("../data/no-return/PEFunctionsThatDoNotReturn");
const MACHO: &str = include_str!("../data/no-return/MachOFunctionsThatDoNotReturn");

/// Upstream entries that can return and therefore never end a block here:
/// the C runtime cleanup functions return to their caller, and Linux `reboot`
/// returns on failure (and for some commands on success). `CxxFrameHandler3`
/// is an exception-dispatch personality routine, not an ordinary call target.
const EXCLUDED: [&str; 4] = ["cexit", "c_exit", "reboot", "CxxFrameHandler3"];
/// ELF names that do not return but are absent upstream: the hidden local
/// stack-protector failure entry and glibc's startup routine.
const ELF_SUPPLEMENT: [&str; 2] = ["stack_chk_fail_local", "libc_start_main"];

/// Most named no-return entries and import slots retained per image.
const MAX_ENTRIES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Container {
    Elf,
    Pe,
    MachO,
}

impl Container {
    fn of(format: &str) -> Option<Self> {
        match format {
            "ELF" => Some(Self::Elf),
            "PE" => Some(Self::Pe),
            "Mach-O" => Some(Self::MachO),
            _ => None,
        }
    }

    fn names(self) -> &'static BTreeSet<&'static str> {
        static SETS: [OnceLock<BTreeSet<&'static str>>; 3] =
            [OnceLock::new(), OnceLock::new(), OnceLock::new()];
        let (index, text, supplement): (usize, &'static str, &[&'static str]) = match self {
            Self::Elf => (0, ELF, &ELF_SUPPLEMENT),
            Self::Pe => (1, PE, &[]),
            Self::MachO => (2, MACHO, &[]),
        };
        SETS[index].get_or_init(|| {
            text.lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .chain(supplement.iter().copied())
                .map(|name| name.trim_start_matches('_'))
                .filter(|name| !name.is_empty() && !EXCLUDED.contains(name))
                .collect()
        })
    }

    /// The comparable form of a loader-provided name, as Ghidra compares
    /// names with leading underscores removed. Only container decorations
    /// are removed: ELF symbol versions and `@plt`, PE `__imp_` and x86
    /// stdcall `@bytes` suffixes. C++ decorated names stay intact.
    fn normalize(self, name: &str, import: bool) -> &str {
        let mut name = name;
        match self {
            Self::Elf => {
                name = name.strip_suffix("@plt").unwrap_or(name);
                name = name.split_once('@').map_or(name, |(base, _)| base);
            }
            Self::Pe => {
                if import {
                    name = name.strip_prefix("__imp_").unwrap_or(name);
                }
                if !name.starts_with('?')
                    && let Some((base, bytes)) = name.rsplit_once('@')
                    && !bytes.is_empty()
                    && bytes.bytes().all(|byte| byte.is_ascii_digit())
                {
                    name = base;
                }
            }
            Self::MachO => {}
        }
        name.trim_start_matches('_')
    }

    fn matches(self, name: &str, import: bool) -> bool {
        self.names().contains(self.normalize(name, import))
    }
}

/// No-return call targets of one image, derived from its immutable symbols and
/// imports when it is opened and never from later renames.
#[derive(Debug, Default)]
pub(crate) struct NoReturnIndex {
    /// Executable entries of named functions and ELF/Mach-O import stubs.
    targets: BTreeSet<u64>,
    /// Named PE import address table slots and verified glibc startup slots.
    slots: BTreeSet<u64>,
    pointer_bytes: u32,
    /// Import-thunk checks of direct call targets, decoded once per worker.
    thunks: Mutex<BTreeMap<u64, Option<u64>>>,
    /// Names were unavailable or omitted at the limit.
    pub incomplete: bool,
}

impl NoReturnIndex {
    /// `is_code` accepts aligned file-backed executable entries; `imports`
    /// maps PE import address table slots to imported names.
    pub(crate) fn build(
        program: &Program,
        format: &str,
        pointer_bytes: u32,
        imports: &BTreeMap<u64, String>,
        is_code: impl Fn(u64) -> bool,
    ) -> Self {
        let mut index = Self {
            pointer_bytes,
            ..Self::default()
        };
        let Some(container) = Container::of(format) else {
            return index;
        };
        let Ok(functions) = program.functions() else {
            index.incomplete = true;
            return index;
        };
        for function in functions {
            let identity = function.symbol.as_deref().unwrap_or(&function.name);
            if matches!(
                function.source,
                FunctionSource::ImportStub
                    | FunctionSource::SymbolTable
                    | FunctionSource::DynamicSymbol
            ) && is_code(function.address)
                && container.matches(identity, function.source == FunctionSource::ImportStub)
                && !(container == Container::Elf
                    && function.source == FunctionSource::ImportStub
                    && container.normalize(identity, true) == "libc_start_main")
            {
                index.insert_target(function.address);
            }
        }
        if container == Container::Pe {
            for (&slot, name) in imports {
                if container.matches(name, true) {
                    if index.slots.len() + index.targets.len() == MAX_ENTRIES {
                        index.incomplete = true;
                        break;
                    }
                    index.slots.insert(slot);
                }
            }
        }
        index
    }

    fn insert_target(&mut self, address: u64) {
        if self.slots.len() + self.targets.len() == MAX_ENTRIES {
            self.incomplete = true;
        } else {
            self.targets.insert(address);
        }
    }

    pub(crate) fn add_startup_slots(&mut self, slots: impl IntoIterator<Item = u64>) {
        for slot in slots {
            if self.slots.len() + self.targets.len() >= MAX_ENTRIES {
                self.incomplete = true;
                break;
            }
            self.slots.insert(slot);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.slots.is_empty()
    }

    /// Whether the call at `operation` in `code` never returns. Direct calls
    /// must target a named entry, or an exact x86 `JMP [slot]` import thunk;
    /// indirect calls must read exactly one named PE import slot.
    pub(crate) fn call(
        &self,
        program: &Program,
        code: &InstructionPcode,
        operation: usize,
        sections: &[SectionInfo],
        remaining: &mut usize,
    ) -> Option<NoReturnEvidence> {
        if self.is_empty() {
            return None;
        }
        let call = code.operations.get(operation)?;
        let target = call.inputs.first()?;
        match call.opcode {
            OpCode::Call if target.space == "ram" => {
                if self.targets.contains(&target.offset) {
                    return Some(NoReturnEvidence::NamedTarget);
                }
                let slot = self.thunk_slot(program, target.offset, sections, remaining)?;
                self.slots
                    .contains(&slot)
                    .then_some(NoReturnEvidence::ImportSlot { slot })
            }
            OpCode::Callind => {
                let slot = self.read_slot(code, operation)?;
                self.slots
                    .contains(&slot)
                    .then_some(NoReturnEvidence::ImportSlot { slot })
            }
            _ => None,
        }
    }

    /// The import slot of a direct call target that is an exact thunk. Each
    /// target is decoded once per worker; a decode is charged to the walk's
    /// work allowance, and one that does not fit is skipped, not cached.
    fn thunk_slot(
        &self,
        program: &Program,
        target: u64,
        sections: &[SectionInfo],
        remaining: &mut usize,
    ) -> Option<u64> {
        if self.slots.is_empty() {
            return None;
        }
        let mut thunks = self
            .thunks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(&slot) = thunks.get(&target) {
            return slot;
        }
        let arm64 = program.language_id().starts_with("AARCH64:");
        let count = if arm64 { 3 } else { 1 };
        let available = remaining.checked_sub(count)?;
        *remaining = available;
        let slot = self.decode_thunk(program, target, sections, arm64);
        if thunks.len() < MAX_ENTRIES {
            thunks.insert(target, slot);
        }
        slot
    }

    /// Resolve only a conventional x86 import jump or ARM64 ADRP/LDR/BR
    /// veneer in file-backed executable code.
    fn decode_thunk(
        &self,
        program: &Program,
        target: u64,
        sections: &[SectionInfo],
        arm64: bool,
    ) -> Option<u64> {
        let (count, length) = if arm64 { (3, 12) } else { (1, 6) };
        if arm64 && !target.is_multiple_of(4)
            || !sections
                .iter()
                .any(|section| section.executable && section.backs(target, length))
        {
            return None;
        }
        let decoded = program.disassemble(target, count).ok()?;
        if decoded.len() != count {
            return None;
        }
        // Reject other function entries before requesting engine p-code.
        let slot = if arm64 {
            if !decoded.iter().zip(["ADRP", "LDR", "BR"]).enumerate().all(
                |(i, (instruction, mnemonic))| {
                    instruction.address == target + i as u64 * 4
                        && instruction.length == 4
                        && instruction.bytes.len() == 4
                        && instruction.mnemonic.eq_ignore_ascii_case(mnemonic)
                },
            ) {
                return None;
            }
            let words = std::array::from_fn(|i| {
                u32::from_le_bytes(decoded[i].bytes.as_slice().try_into().unwrap())
            });
            crate::pe_symbols::aarch64_veneer_slot(target, words)?
        } else {
            let instruction = &decoded[0];
            if instruction.address != target
                || instruction.length != 6
                || !instruction.mnemonic.eq_ignore_ascii_case("JMP")
            {
                return None;
            }
            crate::pe_symbols::x86_thunk_slot(target, &instruction.bytes, self.pointer_bytes)?
        };
        let code = program.pcode(target, count).ok()?;
        if code.len() != count {
            return None;
        }
        if arm64 {
            if !code.iter().zip(&decoded).all(|(pcode, instruction)| {
                pcode.address == instruction.address && pcode.length == 4
            }) {
                return None;
            }
            // The exact instruction encoding fixes register flow. Also require
            // the expected load and final indirect branch in engine p-code.
            if !code[1].operations.iter().any(|op| {
                op.opcode == OpCode::Load
                    && op
                        .output
                        .as_ref()
                        .is_some_and(|out| out.size == self.pointer_bytes)
            }) || code[2].operations.last()?.opcode != OpCode::Branchind
            {
                return None;
            }
            Some(slot)
        } else {
            let pcode = &code[0];
            if pcode.address != target
                || pcode.length != 6
                || pcode.operations.last()?.opcode != OpCode::Branchind
            {
                return None;
            }
            (self.read_slot(pcode, pcode.operations.len() - 1)? == slot).then_some(slot)
        }
    }

    /// The slot that the indirect transfer at `operation` reads, when its
    /// target is exactly one pointer-sized load from a constant address made
    /// earlier in the same instruction.
    fn read_slot(&self, code: &InstructionPcode, operation: usize) -> Option<u64> {
        let target = code.operations.get(operation)?.inputs.first()?;
        if target.size != self.pointer_bytes {
            return None;
        }
        if target.space == "ram" {
            return Some(target.offset);
        }
        if target.space != "unique" {
            return None;
        }
        // The single definition of the temporary, and nothing else written.
        let mut definition = None;
        for earlier in &code.operations[..operation] {
            let Some(output) = &earlier.output else {
                continue;
            };
            if output.space == "unique"
                && output.offset < target.offset.checked_add(u64::from(target.size))?
                && target.offset < output.offset.checked_add(u64::from(output.size))?
                && (output.offset != target.offset
                    || output.size != target.size
                    || definition.replace(earlier).is_some())
            {
                return None;
            }
        }
        let definition = definition?;
        match definition.opcode {
            OpCode::Copy => definition
                .inputs
                .first()
                .filter(|input| input.space == "ram" && input.size == self.pointer_bytes)
                .map(|input| input.offset),
            OpCode::Load => definition
                .inputs
                .get(1)
                .filter(|address| address.space == "const")
                .map(|address| address.offset),
            _ => None,
        }
    }
}

/// Marks the engine's own prototypes of named no-return functions, so the
/// decompiler also stops at calls to them. Returns whether every target was
/// marked; an unmarked one only keeps the decompiler's ordinary call flow.
pub(crate) fn mark_engine(program: &mut Program, index: &NoReturnIndex) -> bool {
    mark_targets(program, index.targets.iter().copied())
}

pub(crate) fn mark_targets(program: &mut Program, targets: impl IntoIterator<Item = u64>) -> bool {
    let architecture = program.architecture();
    let Some(space) = architecture.manager.get_default_code_space() else {
        return false;
    };
    let mut complete = true;
    for address in targets {
        let entry = Address::new(space.clone(), address);
        let symbol = architecture.symboltab_ref().ok().and_then(|symbols| {
            symbols
                .get_global_scope()
                .and_then(|scope| symbols.scope_query_function(scope, &entry))
        });
        complete &= symbol.is_some_and(|symbol| {
            architecture
                .with_function(symbol, |function, _| {
                    function.funcp.set_no_return(true);
                    Ok(())
                })
                .is_ok()
        });
    }
    complete
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(format: &str, name: &str) -> bool {
        Container::of(format).is_some_and(|container| container.matches(name, true))
    }

    #[test]
    fn names_compare_without_underscores_or_container_decorations() {
        assert!(named("ELF", "exit"));
        assert!(named("ELF", "_exit"));
        assert!(named("ELF", "__stack_chk_fail"));
        assert!(named("ELF", "exit@GLIBC_2.2.5"));
        assert!(named("ELF", "abort@plt"));
        assert!(named("ELF", "__stack_chk_fail_local"));
        assert!(named("ELF", "__libc_start_main"));
        assert!(named("PE", "__imp_ExitProcess"));
        assert!(!Container::Pe.matches("__imp_ExitProcess", false));
        assert!(named("PE", "_CxxThrowException@8"));
        assert!(named("PE", "?terminate@@YAXXZ"));
        assert!(named("Mach-O", "_objc_exception_throw"));
        // Wrong container, partial names, returning cleanup and decorations
        // of another container never match.
        assert!(!named("ELF", "ExitProcess"));
        assert!(!named("PE", "exit@GLIBC_2.2.5"));
        assert!(!named("ELF", "exit_group_helper"));
        assert!(!named("ELF", "my_exit"));
        assert!(!named("ELF", "Exit"));
        for returning in ["_cexit", "c_exit", "reboot"] {
            assert!(!named("ELF", returning) && !named("PE", returning));
        }
        assert!(!named("PE", "__CxxFrameHandler3"));
        assert!(!named("Unknown", "exit"));
    }

    fn pcode(bytes: &[u8]) -> (Program, InstructionPcode) {
        let program =
            Program::from_raw_bytes(bytes.to_vec(), "x86:LE:64:default:windows", 0x1000).unwrap();
        let code = program.pcode(0x1000, 1).unwrap().pop().unwrap();
        (program, code)
    }

    fn sections() -> Vec<SectionInfo> {
        vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: 0x100,
            file_offset: 0,
            file_size: 0x100,
            executable: true,
        }]
    }

    fn resolve(
        index: &NoReturnIndex,
        program: &Program,
        code: &InstructionPcode,
        operation: usize,
    ) -> Option<NoReturnEvidence> {
        index.call(program, code, operation, &sections(), &mut 16)
    }

    fn call_index(code: &InstructionPcode) -> usize {
        code.operations
            .iter()
            .position(|op| matches!(op.opcode, OpCode::Call | OpCode::Callind))
            .unwrap()
    }

    #[test]
    fn indirect_calls_resolve_only_through_named_import_slots() {
        // call qword ptr [rip + 0x10]: slot 0x1016.
        let (program, code) = pcode(&[0xff, 0x15, 0x10, 0x00, 0x00, 0x00]);
        let index = |slots: &[u64]| NoReturnIndex {
            slots: slots.iter().copied().collect(),
            pointer_bytes: 8,
            ..Default::default()
        };
        let operation = call_index(&code);
        assert_eq!(
            resolve(&index(&[0x1016]), &program, &code, operation),
            Some(NoReturnEvidence::ImportSlot { slot: 0x1016 })
        );
        assert_eq!(resolve(&index(&[0x1018]), &program, &code, operation), None);
        // call rax reads no slot.
        let (program, code) = pcode(&[0xff, 0xd0]);
        assert_eq!(
            resolve(&index(&[0x1016]), &program, &code, call_index(&code)),
            None
        );
    }

    #[test]
    fn x86_32_import_calls_and_budgeted_arm64_veneers() {
        let program = Program::from_raw_bytes(
            vec![0xff, 0x15, 0x80, 0x10, 0, 0],
            "x86:LE:32:default:windows",
            0x1000,
        )
        .unwrap();
        let code = program.pcode(0x1000, 1).unwrap().pop().unwrap();
        let index = NoReturnIndex {
            slots: [0x1080].into(),
            pointer_bytes: 4,
            ..Default::default()
        };
        assert_eq!(
            resolve(&index, &program, &code, call_index(&code)),
            Some(NoReturnEvidence::ImportSlot { slot: 0x1080 })
        );

        // BL 0x1040; ... ADRP x16; LDR x17,[x16,#0x80]; BR x17.
        let mut bytes = vec![0; 0x100];
        bytes[..4].copy_from_slice(&0x9400_0010u32.to_le_bytes());
        for (i, word) in [0x9000_0010u32, 0xf940_4211, 0xd61f_0220]
            .into_iter()
            .enumerate()
        {
            bytes[0x40 + i * 4..0x44 + i * 4].copy_from_slice(&word.to_le_bytes());
        }
        let program = Program::from_raw_bytes(bytes, "AARCH64:LE:64:v8A:windows", 0x1000).unwrap();
        let code = program.pcode(0x1000, 1).unwrap().pop().unwrap();
        let index = || NoReturnIndex {
            slots: [0x1080].into(),
            pointer_bytes: 8,
            ..Default::default()
        };
        let call = |index: &NoReturnIndex, sections: &[SectionInfo], remaining: &mut usize| {
            index.call(&program, &code, call_index(&code), sections, remaining)
        };
        let veneer = Some(NoReturnEvidence::ImportSlot { slot: 0x1080 });
        // The three-instruction check is charged once, then remembered.
        let resolved = index();
        let mut remaining = 3;
        assert_eq!(call(&resolved, &sections(), &mut remaining), veneer);
        assert_eq!(remaining, 0);
        assert_eq!(call(&resolved, &sections(), &mut remaining), veneer);
        // A check that does not fit is skipped without consuming the rest.
        let short = index();
        let mut remaining = 2;
        assert_eq!(call(&short, &sections(), &mut remaining), None);
        assert_eq!(remaining, 2);
        assert_eq!(call(&short, &sections(), &mut 3), veneer);
        let mut truncated = sections();
        truncated[0].file_size = 0x48;
        assert_eq!(call(&index(), &truncated, &mut 3), None);
    }

    #[test]
    fn partial_temporary_writes_cannot_establish_an_import_call() {
        let (program, mut code) = pcode(&[0xff, 0x15, 0x10, 0, 0, 0]);
        let operation = call_index(&code);
        let index = NoReturnIndex {
            slots: [0x1016].into(),
            pointer_bytes: 8,
            ..Default::default()
        };
        // A conflicting partial definition of the call temporary invalidates
        // the otherwise real import-slot load.
        let target = code.operations[operation].inputs[0].clone();
        let mut overwrite = code.operations[operation - 1].clone();
        overwrite.output = Some(ghidra_decompiler::program::PcodeVarnode { size: 1, ..target });
        code.operations.insert(operation, overwrite);
        assert_eq!(resolve(&index, &program, &code, operation + 1), None);
    }

    #[test]
    fn direct_calls_resolve_named_entries_and_exact_import_thunks() {
        // call 0x1010; padding; at 0x1010: jmp qword ptr [rip + 0x20] (slot 0x1036).
        let mut bytes = vec![0xe8, 0x0b, 0x00, 0x00, 0x00];
        bytes.resize(0x10, 0x90);
        bytes.extend([0xff, 0x25, 0x20, 0x00, 0x00, 0x00]);
        bytes.resize(0x40, 0x90);
        let (program, code) = pcode(&bytes);
        let operation = call_index(&code);
        let named = NoReturnIndex {
            targets: [0x1010].into(),
            pointer_bytes: 8,
            ..Default::default()
        };
        assert_eq!(
            resolve(&named, &program, &code, operation),
            Some(NoReturnEvidence::NamedTarget)
        );
        let thunk = |slot| NoReturnIndex {
            slots: [slot].into(),
            pointer_bytes: 8,
            ..Default::default()
        };
        assert_eq!(
            resolve(&thunk(0x1036), &program, &code, operation),
            Some(NoReturnEvidence::ImportSlot { slot: 0x1036 })
        );
        assert_eq!(resolve(&thunk(0x1038), &program, &code, operation), None);
    }
}
