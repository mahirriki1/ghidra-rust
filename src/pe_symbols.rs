//! Register already validated PE metadata through the pinned engine's public APIs.
use std::collections::{BTreeMap, BTreeSet};

use ghidra_decompiler::address::Address;
use ghidra_decompiler::database::{Database, ScopeId};
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::Program;
use ghidra_decompiler::types::TypeMetatype;
use ghidra_decompiler::varnode::Varnode;

use crate::model::{MAX_FUNCTIONS, SectionInfo};
use crate::pe::{MAX_IMPORTS, MAX_NAME_BYTES, PeMetadata};

pub(crate) const MAX_THUNK_TARGETS: usize = 2048;

fn truncated(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn unique_name(
    table: &Database,
    global: ScopeId,
    retired_names: &BTreeSet<String>,
    requested: &str,
    address: u64,
    fallback: &str,
) -> String {
    // Preserve decorations such as MSVC's '?'/'@' and DLL-qualified imports.
    // Whitespace and control characters cannot become printer syntax/new lines.
    let mut base = String::new();
    for character in requested.chars() {
        let character = if character.is_control() || character.is_whitespace() {
            '_'
        } else {
            character
        };
        if base.len() + character.len_utf8() > MAX_NAME_BYTES {
            break;
        }
        base.push(character);
    }
    if base.is_empty() {
        base = format!("{fallback}_{address:x}");
    }
    // Public scope insertion and rename APIs update this index before the next
    // registration. Include global data/labels as well as functions, without
    // copying the entire symbol arena for each new import thunk.
    let occupied = |name: &str| {
        table.scope_find_first_by_name(global, name).is_some() || retired_names.contains(name)
    };
    if !occupied(&base) {
        return base;
    }
    let mut collision = 0usize;
    loop {
        let suffix = if collision == 0 {
            format!("_{address:x}")
        } else {
            format!("_{address:x}_{collision}")
        };
        let candidate = format!(
            "{}{}",
            truncated(&base, MAX_NAME_BYTES - suffix.len()),
            suffix
        );
        if !occupied(&candidate) {
            return candidate;
        }
        collision += 1;
    }
}

pub(crate) fn register(
    program: &mut Program,
    metadata: &PeMetadata,
    pointer_bytes: i32,
) -> Result<(), String> {
    if !matches!(pointer_bytes, 4 | 8) {
        return Err("Unsupported PE import pointer width".into());
    }
    if metadata.functions.len() > MAX_FUNCTIONS || metadata.imports.len() > MAX_IMPORTS {
        return Err("PE symbol metadata exceeds the registration limits".into());
    }
    let architecture = program.architecture();
    let code_space = architecture
        .manager
        .get_default_code_space()
        .ok_or("Missing default code space while registering PE symbols")?;
    let data_space = architecture
        .manager
        .get_default_data_space()
        .ok_or("Missing default data space while registering PE symbols")?;
    let global = architecture
        .symboltab_ref()
        .map_err(|error| error.explain().to_string())?
        .get_global_scope()
        .ok_or("Missing global scope while registering PE symbols")?;
    let retired_names = BTreeSet::new();

    for (&offset, requested) in &metadata.functions {
        let address = Address::new(code_space.clone(), offset);
        let table = architecture
            .symboltab_ref()
            .map_err(|error| error.explain().to_string())?;
        // Preserve an existing exact function name and avoid overlapping data or
        // code symbols. These entries have already passed file-backed validation.
        if table.scope_find_function(global, &address).is_some()
            || table.scope_find_overlap(global, &address, 1).is_some()
        {
            continue;
        }
        let name = unique_name(table, global, &retired_names, requested, offset, "FUN");
        Database::scope_add_function(architecture, global, &address, &name).map_err(|error| {
            format!(
                "Cannot register PE function at {offset:#x}: {}",
                error.explain()
            )
        })?;
    }

    let pointer_type = architecture
        .types_mut()
        .and_then(|types| types.get_base(pointer_bytes, TypeMetatype::Unknown))
        .map_err(|error| error.explain().to_string())?;
    for (&offset, requested) in &metadata.imports {
        // The engine's overlap query uses an inclusive last address internally.
        // Reject wraparound even though the snapshot parser already checks slots.
        if offset.checked_add(pointer_bytes as u64).is_none() {
            return Err("PE import slot address overflow".into());
        }
        let address = Address::new(data_space.clone(), offset);
        let table = architecture
            .symboltab_ref()
            .map_err(|error| error.explain().to_string())?;
        if table
            .scope_find_overlap(global, &address, pointer_bytes)
            .is_some()
        {
            continue;
        }
        let name = unique_name(
            table,
            global,
            &retired_names,
            &format!("__imp_{requested}"),
            offset,
            "__imp",
        );
        // An IAT entry is a pointer-sized data slot. It is not executable code,
        // and its name does not establish an imported prototype or target address.
        let entry = Database::scope_add_symbol_at(
            architecture,
            global,
            &name,
            Some(pointer_type),
            &address,
            &Address::invalid(),
        )
        .map_err(|error| {
            format!(
                "Cannot register PE import at {offset:#x}: {}",
                error.explain()
            )
        })?;
        // PE IAT slots are filled by the Windows loader. The raw on-disk lookup
        // value is not their runtime value, even when the containing section is
        // marked read-only. Match the engine's external-reference registration
        // by preventing read-only constant propagation for this exact symbol.
        let table = architecture
            .symboltab_mut()
            .map_err(|error| error.explain().to_string())?;
        let symbol = table.entry(entry).get_symbol();
        table.symbol_mut(symbol).flags &= !Varnode::READONLY;
    }
    Ok(())
}

/// Name import jumps reached by real direct calls in a bounded recovered CFG.
/// This deliberately does not scan arbitrary executable bytes for signatures.
pub(crate) fn register_import_thunks(
    program: &mut Program,
    imports: &BTreeMap<u64, String>,
    snapshot: &[u8],
    sections: &[SectionInfo],
    targets: &BTreeSet<u64>,
    pointer_bytes: i32,
) -> Result<(), String> {
    if !matches!(pointer_bytes, 4 | 8) {
        return Err("Unsupported PE import pointer width".into());
    }
    if imports.len() > MAX_IMPORTS || targets.len() > MAX_THUNK_TARGETS {
        return Err("PE import thunk candidates exceed the registration limits".into());
    }
    let mut metadata = PeMetadata::default();
    for &target in targets {
        let index = sections.partition_point(|section| section.address <= target);
        let Some(section) = index.checked_sub(1).and_then(|index| sections.get(index)) else {
            continue;
        };
        let Some(relative_end) = target
            .checked_sub(section.address)
            .and_then(|offset| offset.checked_add(6))
        else {
            continue;
        };
        if !section.executable || relative_end > section.file_size || relative_end > section.size {
            continue;
        }
        let Some(start) = section
            .file_offset
            .checked_add(relative_end - 6)
            .and_then(|offset| usize::try_from(offset).ok())
        else {
            continue;
        };
        let Some(bytes) = start
            .checked_add(6)
            .and_then(|end| snapshot.get(start..end))
        else {
            continue;
        };
        if bytes[..2] != [0xff, 0x25] {
            continue;
        }
        let slot = x86_thunk_slot(target, bytes, pointer_bytes as u32);
        let Some(name) = slot.and_then(|slot| imports.get(&slot)) else {
            continue;
        };
        let Ok(decoded) = program.disassemble(target, 1) else {
            continue;
        };
        if decoded.len() != 1
            || decoded[0].length != 6
            || !decoded[0].mnemonic.eq_ignore_ascii_case("JMP")
        {
            continue;
        }
        let Ok(pcode) = program.pcode(target, 1) else {
            continue;
        };
        if pcode.len() != 1
            || pcode[0].length != 6
            || !pcode[0]
                .operations
                .iter()
                .any(|operation| operation.opcode == OpCode::Branchind)
        {
            continue;
        }
        metadata.functions.insert(target, name.clone());
    }
    register(program, &metadata, pointer_bytes)
}

/// Resolve only the conventional three-instruction ARM64 PE import veneer.
/// The inputs are established function entries or confirmed call targets, never
/// arbitrary offsets from a signature scan. The IAT remains loader-written data;
/// naming this veneer does not resolve its indirect branch to a runtime address.
pub(crate) fn register_aarch64_import_thunks(
    program: &mut Program,
    imports: &BTreeMap<u64, String>,
    snapshot: &[u8],
    sections: &[SectionInfo],
    targets: &BTreeSet<u64>,
) -> Result<(), String> {
    let mut remaining = MAX_THUNK_TARGETS * 3;
    register_aarch64_import_thunks_budgeted(
        program,
        imports,
        snapshot,
        sections,
        targets,
        &mut remaining,
    )
    .map(|_| ())
}

/// Charge the same shared instruction budget used by confirmed-call discovery.
/// False means a syntactically eligible candidate could not fit the budget.
pub(crate) fn register_aarch64_import_thunks_budgeted(
    program: &mut Program,
    imports: &BTreeMap<u64, String>,
    snapshot: &[u8],
    sections: &[SectionInfo],
    targets: &BTreeSet<u64>,
    remaining: &mut usize,
) -> Result<bool, String> {
    if imports.len() > MAX_IMPORTS || targets.len() > MAX_THUNK_TARGETS {
        return Err("PE import thunk candidates exceed the registration limits".into());
    }
    let mut metadata = PeMetadata::default();
    let mut complete = true;
    for &target in targets {
        if target % 4 != 0 {
            continue;
        }
        let Some(bytes) = mapped_bytes(snapshot, sections, target, 12, true) else {
            continue;
        };
        let words = [0, 4, 8]
            .map(|offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()));
        let Some(slot) = aarch64_veneer_slot(target, words) else {
            continue;
        };
        let Some(name) = imports.get(&slot) else {
            continue;
        };
        if slot % 8 != 0 || mapped_bytes(snapshot, sections, slot, 8, false).is_none() {
            continue;
        }
        let Some(available) = remaining.checked_sub(3) else {
            complete = false;
            break;
        };
        *remaining = available;
        let Ok(decoded) = program.disassemble(target, 3) else {
            continue;
        };
        if decoded.len() != 3
            || !decoded.iter().zip(["ADRP", "LDR", "BR"]).enumerate().all(
                |(index, (instruction, mnemonic))| {
                    instruction.address == target + index as u64 * 4
                        && instruction.length == 4
                        && instruction.bytes == bytes[index * 4..index * 4 + 4]
                        && instruction.mnemonic.eq_ignore_ascii_case(mnemonic)
                },
            )
        {
            continue;
        }
        let Ok(pcode) = program.pcode(target, 3) else {
            continue;
        };
        if pcode.len() != 3
            || !pcode.iter().enumerate().all(|(index, instruction)| {
                instruction.address == target + index as u64 * 4 && instruction.length == 4
            })
            || !pcode[1].operations.iter().any(|operation| {
                operation.opcode == OpCode::Load
                    && operation
                        .output
                        .as_ref()
                        .is_some_and(|output| output.size == 8)
            })
            || !pcode[2].operations.iter().any(|operation| {
                operation.opcode == OpCode::Branchind
                    && operation
                        .inputs
                        .first()
                        .is_some_and(|input| input.size == 8)
            })
            || pcode
                .iter()
                .flat_map(|instruction| &instruction.operations)
                .any(|operation| {
                    matches!(
                        operation.opcode,
                        OpCode::Branch
                            | OpCode::Cbranch
                            | OpCode::Call
                            | OpCode::Callind
                            | OpCode::Return
                    )
                })
        {
            continue;
        }
        metadata.functions.insert(target, name.clone());
    }

    // Most candidates are already generic functions recovered from unwind data
    // or calls. Register missing entries first, then promote only exact generated
    // names. Preserve exports and analyst-chosen meaningful names.
    let existing = program
        .functions()
        .map_err(|error| error.explain().to_string())?
        .into_iter()
        .map(|function| (function.address, function.name))
        .collect::<BTreeMap<_, _>>();
    register(program, &metadata, 8)?;
    let architecture = program.architecture();
    let table = architecture
        .symboltab_ref()
        .map_err(|error| error.explain().to_string())?;
    let global = table
        .get_global_scope()
        .ok_or("Missing global scope while naming ARM64 veneers")?;
    // The previous name-set implementation reserved names present at the start
    // of this pass, even after a veneer rename. Retain just those removed names
    // (bounded by MAX_THUNK_TARGETS), preserving collision suffixes exactly.
    let mut retired_names = BTreeSet::new();
    for (&address, requested) in &metadata.functions {
        let Some(old_name) = existing.get(&address) else {
            continue;
        };
        if old_name != &format!("FUN_{address:x}") && old_name != &format!("FUN_{address:08x}") {
            continue;
        }
        let table = program
            .architecture()
            .symboltab_ref()
            .map_err(|error| error.explain().to_string())?;
        let name = unique_name(table, global, &retired_names, requested, address, "FUN");
        program
            .set_function_name(address, &name)
            .map_err(|error| error.explain().to_string())?;
        retired_names.insert(old_name.clone());
        // Program::set_function_name updates its record and global symbol, but
        // not already materialized Funcdata/local scopes in the pinned engine.
        let architecture = program.architecture();
        let code = architecture
            .manager
            .get_default_code_space()
            .ok_or("Missing code space while naming ARM64 veneers")?;
        let symbol = architecture
            .symboltab_ref()
            .map_err(|error| error.explain().to_string())?
            .scope_find_function(global, &Address::new(code, address))
            .ok_or("Missing function while naming ARM64 veneer")?;
        architecture
            .with_function(symbol, |function, architecture| {
                architecture.clear_analysis(function);
                function.name = name.clone();
                function.display_name = name.clone();
                if let Some(scope) = function.get_scope_local() {
                    let local = architecture.symboltab_mut()?.scope_mut(scope);
                    local.name = name.clone();
                    local.display_name = name.clone();
                }
                Ok(())
            })
            .map_err(|error| error.explain().to_string())?;
    }
    Ok(complete)
}

/// The file-backed bytes of `[address, address + size)` within one section
/// whose executability matches `executable`.
pub(crate) fn mapped_bytes<'a>(
    snapshot: &'a [u8],
    sections: &[SectionInfo],
    address: u64,
    size: u64,
    executable: bool,
) -> Option<&'a [u8]> {
    let index = sections.partition_point(|section| section.address <= address);
    let section = sections.get(index.checked_sub(1)?)?;
    let offset = address.checked_sub(section.address)?;
    let end = offset.checked_add(size)?;
    if section.executable != executable || end > section.file_size || end > section.size {
        return None;
    }
    address.checked_add(size)?;
    let start = usize::try_from(section.file_offset.checked_add(offset)?).ok()?;
    snapshot.get(start..start.checked_add(usize::try_from(size).ok()?)?)
}

/// Slot encoded by the conventional x86 import jump. The caller validates
/// executable membership and confirms the engine's decoded flow.
pub(crate) fn x86_thunk_slot(address: u64, bytes: &[u8], pointer_bytes: u32) -> Option<u64> {
    if bytes.len() != 6 || bytes[..2] != [0xff, 0x25] {
        return None;
    }
    let operand = u32::from_le_bytes(bytes[2..6].try_into().ok()?);
    match pointer_bytes {
        8 => address
            .checked_add(6)?
            .checked_add_signed(i64::from(operand as i32)),
        4 => Some(u64::from(operand)),
        _ => None,
    }
}

pub(crate) fn aarch64_veneer_slot(address: u64, [adrp, ldr, branch]: [u32; 3]) -> Option<u64> {
    // ADRP Xn; LDR Xm,[Xn,#imm12*8]; BR Xm. W-register loads, SP/ZR,
    // pre/post-indexed loads and register-offset forms are deliberately excluded.
    if adrp & 0x9f00_0000 != 0x9000_0000
        || ldr & 0xffc0_0000 != 0xf940_0000
        || branch & 0xffff_fc1f != 0xd61f_0000
    {
        return None;
    }
    let base = adrp & 31;
    let loaded = ldr & 31;
    if base == 31 || loaded == 31 || (ldr >> 5) & 31 != base || (branch >> 5) & 31 != loaded {
        return None;
    }
    let immediate = ((adrp >> 29) & 3) | (((adrp >> 5) & 0x7ffff) << 2);
    let signed_pages = i64::from((immediate as i32) << 11 >> 11);
    (address & !0xfff)
        .checked_add_signed(signed_pages * 4096)?
        .checked_add(u64::from((ldr >> 10) & 0xfff) * 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARM64_VENEER: [u32; 3] = [0x9000_0010, 0xf940_4211, 0xd61f_0220];

    #[test]
    fn arm64_veneer_naming_respects_shared_instruction_budget() {
        let (bytes, sections, metadata) = arm64_fixture(ARM64_VENEER);
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "AARCH64:LE:64:v8A:windows", 0x1000).unwrap();
        register(&mut program, &metadata, 8).unwrap();
        let targets = BTreeSet::from([0x1040]);
        for available in [0, 1, 2] {
            let mut remaining = available;
            assert!(
                !register_aarch64_import_thunks_budgeted(
                    &mut program,
                    &metadata.imports,
                    &bytes,
                    &sections,
                    &targets,
                    &mut remaining,
                )
                .unwrap()
            );
            assert_eq!(remaining, available);
            assert_eq!(program.functions().unwrap()[1].name, "FUN_1040");
        }
        let mut remaining = 3;
        assert!(
            register_aarch64_import_thunks_budgeted(
                &mut program,
                &metadata.imports,
                &bytes,
                &sections,
                &targets,
                &mut remaining,
            )
            .unwrap()
        );
        assert_eq!(remaining, 0);
        assert_eq!(program.functions().unwrap()[1].name, "ExitProcess");
    }

    fn arm64_fixture(words: [u32; 3]) -> (Vec<u8>, Vec<SectionInfo>, PeMetadata) {
        let mut bytes = vec![0; 0x100];
        // Original safe fixture: save LR; BL 0x1040; restore LR; RET.
        for (index, word) in [
            0xa9bf_7bfdu32,
            0x9100_03fd,
            0x9400_000e,
            0xa8c1_7bfd,
            0xd65f_03c0,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        for (index, word) in words.into_iter().enumerate() {
            bytes[0x40 + index * 4..0x44 + index * 4].copy_from_slice(&word.to_le_bytes());
        }
        // This raw lookup value deliberately resembles code. It must never be
        // treated as the import's runtime destination.
        bytes[0x80..0x88].copy_from_slice(&0x1040u64.to_le_bytes());
        let sections = vec![
            SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x80,
                file_offset: 0,
                file_size: 0x80,
                executable: true,
            },
            SectionInfo {
                name: ".idata".into(),
                address: 0x1080,
                size: 0x80,
                file_offset: 0x80,
                file_size: 0x80,
                executable: false,
            },
        ];
        let mut metadata = PeMetadata::default();
        metadata.functions.insert(0x1000, "caller".into());
        metadata.functions.insert(0x1040, "FUN_1040".into());
        metadata.imports.insert(0x1080, "ExitProcess".into());
        (bytes, sections, metadata)
    }

    #[test]
    fn arm64_import_veneer_promotes_materialized_generic_function_without_resolving_branch() {
        let (bytes, sections, metadata) = arm64_fixture(ARM64_VENEER);
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "AARCH64:LE:64:v8A:windows", 0x1000).unwrap();
        register(&mut program, &metadata, 8).unwrap();
        // Exercise the pinned engine's independently cached Funcdata and scope.
        let before = program.decompile(0x1040).unwrap();
        assert!(before.contains("FUN_1040"), "{before}");
        register_aarch64_import_thunks(
            &mut program,
            &metadata.imports,
            &bytes,
            &sections,
            &BTreeSet::from([0x1040]),
        )
        .unwrap();
        assert_eq!(program.functions().unwrap()[1].name, "ExitProcess");
        let definition = program.decompile(0x1040).unwrap();
        assert!(definition.contains("ExitProcess("), "{definition}");
        assert!(!definition.contains("FUN_1040"), "{definition}");
        let caller = program.decompile(0x1000).unwrap();
        assert!(caller.contains("ExitProcess("), "{caller}");
        let branch = program.pcode(0x1048, 1).unwrap();
        assert!(
            branch[0]
                .operations
                .iter()
                .any(|op| op.opcode == OpCode::Branchind)
        );
        assert!(
            !branch[0]
                .operations
                .iter()
                .any(|op| op.opcode == OpCode::Branch)
        );
    }

    #[test]
    fn arm64_veneer_rejects_unestablished_or_malformed_targets_and_slots() {
        // Wrong base/destination relationships, SP/ZR, 32-bit load, post-index
        // load, direct jump, and a well-formed load from a non-IAT address.
        for words in [
            [ARM64_VENEER[0], 0xf940_4231, ARM64_VENEER[2]],
            [ARM64_VENEER[0], ARM64_VENEER[1], 0xd61f_0200],
            [0x9000_001f, 0xf940_43f1, ARM64_VENEER[2]],
            [ARM64_VENEER[0], 0xf940_421f, 0xd61f_03e0],
            [ARM64_VENEER[0], 0xb940_8211, ARM64_VENEER[2]],
            [ARM64_VENEER[0], 0xf840_8611, ARM64_VENEER[2]],
            [ARM64_VENEER[0], ARM64_VENEER[1], 0x1400_0000],
            [ARM64_VENEER[0], 0xf940_4611, ARM64_VENEER[2]],
        ] {
            let (bytes, sections, metadata) = arm64_fixture(words);
            let mut program =
                Program::from_raw_bytes(bytes.clone(), "AARCH64:LE:64:v8A:windows", 0x1000)
                    .unwrap();
            register(&mut program, &metadata, 8).unwrap();
            register_aarch64_import_thunks(
                &mut program,
                &metadata.imports,
                &bytes,
                &sections,
                &BTreeSet::from([0x1040]),
            )
            .unwrap();
            assert_eq!(
                program.functions().unwrap()[1].name,
                "FUN_1040",
                "{words:x?}"
            );
        }
        let (bytes, sections, metadata) = arm64_fixture(ARM64_VENEER);
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "AARCH64:LE:64:v8A:windows", 0x1000).unwrap();
        register(&mut program, &metadata, 8).unwrap();
        for targets in [BTreeSet::new(), BTreeSet::from([0x1041])] {
            register_aarch64_import_thunks(
                &mut program,
                &metadata.imports,
                &bytes,
                &sections,
                &targets,
            )
            .unwrap();
            assert_eq!(program.functions().unwrap()[1].name, "FUN_1040");
        }
        for (section_index, backed) in [(0, 0x4b), (1, 7)] {
            let mut truncated = sections.clone();
            truncated[section_index].file_size = backed;
            register_aarch64_import_thunks(
                &mut program,
                &metadata.imports,
                &bytes,
                &truncated,
                &BTreeSet::from([0x1040]),
            )
            .unwrap();
            assert_eq!(program.functions().unwrap()[1].name, "FUN_1040");
        }
        register_aarch64_import_thunks(
            &mut program,
            &metadata.imports,
            &bytes[..0x87],
            &sections,
            &BTreeSet::from([0x1040]),
        )
        .unwrap();
        assert_eq!(program.functions().unwrap()[1].name, "FUN_1040");
    }

    #[test]
    fn arm64_veneer_preserves_export_names_and_checks_signed_page_arithmetic() {
        let (bytes, sections, mut metadata) = arm64_fixture(ARM64_VENEER);
        metadata.functions.insert(0x1040, "MeaningfulExport".into());
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "AARCH64:LE:64:v8A:windows", 0x1000).unwrap();
        register(&mut program, &metadata, 8).unwrap();
        register_aarch64_import_thunks(
            &mut program,
            &metadata.imports,
            &bytes,
            &sections,
            &BTreeSet::from([0x1040]),
        )
        .unwrap();
        assert_eq!(program.functions().unwrap()[1].name, "MeaningfulExport");
        // ADRP X16,+0x1000 and ADRP X16,-0x1000, respectively.
        let positive = [0xb000_0010, ARM64_VENEER[1], ARM64_VENEER[2]];
        let negative = [0xf0ff_fff0, ARM64_VENEER[1], ARM64_VENEER[2]];
        assert_eq!(aarch64_veneer_slot(0x2040, negative), Some(0x1080));
        assert_eq!(aarch64_veneer_slot(0, negative), None);
        assert_eq!(aarch64_veneer_slot(!3u64, positive), None);
        assert_eq!(aarch64_veneer_slot(0x1040, positive), Some(0x2080));
    }

    #[test]
    fn imported_slot_name_reaches_decompiler_without_becoming_code() {
        let mut bytes = vec![0xcc; 0x100];
        // call qword ptr [rip + 0x7a]; ret -- the import slot is 0x1080.
        bytes[..7].copy_from_slice(&[0xff, 0x15, 0x7a, 0, 0, 0, 0xc3]);
        let mut program =
            Program::from_raw_bytes(bytes, "x86:LE:64:default:windows", 0x1000).unwrap();
        {
            // Real PE import tables often live in a read-only section. A raw
            // lookup value must not be mistaken for its loader-populated value.
            let architecture = program.architecture();
            let data = architecture.manager.get_default_data_space().unwrap();
            let manager = architecture.manager.clone();
            architecture.symboltab_mut().unwrap().set_property_range(
                Varnode::READONLY,
                &ghidra_decompiler::address::Range::new(data, 0x1080, 0x1087),
                &manager,
            );
        }
        let mut metadata = PeMetadata::default();
        metadata.functions.insert(0x1000, "caller".into());
        metadata.imports.insert(0x1080, "ExitProcess".into());
        register(&mut program, &metadata, 8).unwrap();

        let functions = program.functions().unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].address, 0x1000);
        let text = program.decompile(0x1000).unwrap();
        assert!(text.contains("ExitProcess"), "{text}");

        let architecture = program.architecture();
        let table = architecture.symboltab_ref().unwrap();
        let global = table.get_global_scope().unwrap();
        let data = architecture.manager.get_default_data_space().unwrap();
        let entry = table
            .scope_find_overlap(global, &Address::new(data, 0x1080), 8)
            .unwrap();
        assert_eq!(table.entry(entry).get_size(), 8);
        assert!(!table.symbol(table.entry(entry).get_symbol()).is_function());
        assert_eq!(
            table.symbol(table.entry(entry).get_symbol()).get_flags() & Varnode::READONLY,
            0
        );
    }

    #[test]
    fn preserves_existing_symbols_and_resolves_duplicate_export_names() {
        let mut program =
            Program::from_raw_bytes(vec![0xc3; 0x100], "x86:LE:64:default:windows", 0x1000)
                .unwrap();
        program.set_function_name(0x1000, "original").unwrap();
        program.set_data_name(0x1084, "existing_data").unwrap();
        let mut metadata = PeMetadata::default();
        metadata.functions.insert(0x1000, "replacement".into());
        metadata.functions.insert(0x1010, "?export@@YAHH@Z".into());
        metadata.functions.insert(0x1020, "?export@@YAHH@Z".into());
        // The existing one-byte data symbol falls inside this eight-byte slot.
        metadata.imports.insert(0x1080, "must_not_overlap".into());
        register(&mut program, &metadata, 8).unwrap();

        let functions = program.functions().unwrap();
        assert_eq!(functions.len(), 3);
        assert_eq!(functions[0].name, "original");
        assert_eq!(functions[1].name, "?export@@YAHH@Z");
        assert_eq!(functions[2].name, "?export@@YAHH@Z_1020");
        assert_eq!(program.data_symbols().unwrap()[0].name, "existing_data");
        let architecture = program.architecture();
        let table = architecture.symboltab_ref().unwrap();
        assert!(
            !table
                .symbols
                .iter()
                .any(|(_, symbol)| symbol.get_name() == "must_not_overlap")
        );
    }

    fn assert_global_name_index(program: &mut Program) {
        let table = program.architecture().symboltab_ref().unwrap();
        let global = table.get_global_scope().unwrap();
        let arena = table
            .symbols
            .iter()
            .filter(|(_, symbol)| symbol.get_scope() == global)
            .map(|(_, symbol)| symbol.get_name().to_owned())
            .collect::<BTreeSet<_>>();
        let index = table
            .scope(global)
            .nametree
            .keys()
            .map(|key| key.name.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(index, arena);
    }

    #[test]
    fn indexed_names_preserve_collisions_across_symbol_kinds_and_mutations() {
        for language in [
            "x86:LE:32:default:windows",
            "x86:LE:64:default:windows",
            "AARCH64:LE:64:v8A:windows",
        ] {
            let mut program = Program::from_raw_bytes(vec![0; 0x1000], language, 0x1000).unwrap();
            program.set_function_name(0x1000, "taken").unwrap();
            program.set_data_name(0x1800, "taken_1020").unwrap();
            program.set_data_name(0x1810, "taken_1020_1").unwrap();
            program.set_data_name(0x1820, "__imp_ExitProcess").unwrap();
            let (global, label) = {
                let architecture = program.architecture();
                let code = architecture.manager.get_default_code_space().unwrap();
                let global = architecture
                    .symboltab_ref()
                    .unwrap()
                    .get_global_scope()
                    .unwrap();
                let label = Database::scope_add_code_label(
                    architecture,
                    global,
                    &Address::new(code.clone(), 0x1100),
                    "taken_1030",
                )
                .unwrap();
                // Symbols created through the public database API, outside
                // Program's private records, participate in collisions too.
                Database::scope_add_function(
                    architecture,
                    global,
                    &Address::new(code.clone(), 0x1110),
                    "outside",
                )
                .unwrap();
                let child = architecture
                    .symboltab_mut()
                    .unwrap()
                    .scope_build_sub_scope(global, 9001, "nested", 0);
                architecture
                    .symboltab_mut()
                    .unwrap()
                    .attach_scope(child, Some(global))
                    .unwrap();
                Database::scope_add_code_label(
                    architecture,
                    child,
                    &Address::new(code, 0x1120),
                    "nested_only",
                )
                .unwrap();
                (global, label)
            };
            assert_global_name_index(&mut program);
            let mut metadata = PeMetadata::default();
            metadata.functions.extend([
                (0x1020, "taken".into()),
                (0x1030, "taken".into()),
                (0x1040, "outside".into()),
                (0x1050, "nested_only".into()),
                (0x1060, "with\nspace".into()),
            ]);
            metadata.imports.insert(0x1900, "ExitProcess".into());
            let width = if language.contains(":32:") { 4 } else { 8 };
            register(&mut program, &metadata, width).unwrap();
            let functions = program
                .functions()
                .unwrap()
                .into_iter()
                .map(|function| (function.address, function.name))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(functions[&0x1020], "taken_1020_2");
            assert_eq!(functions[&0x1030], "taken_1030_1");
            assert_eq!(functions[&0x1040], "outside_1040");
            assert_eq!(functions[&0x1050], "nested_only");
            assert_eq!(functions[&0x1060], "with_space");
            {
                let architecture = program.architecture();
                let data = architecture.manager.get_default_data_space().unwrap();
                let table = architecture.symboltab_ref().unwrap();
                let entry = table
                    .scope_find_overlap(global, &Address::new(data, 0x1900), width)
                    .unwrap();
                assert_eq!(
                    table.symbol(table.entry(entry).get_symbol()).get_name(),
                    "__imp_ExitProcess_1900"
                );
            }
            assert_global_name_index(&mut program);

            program.set_function_name(0x1000, "renamed").unwrap();
            program
                .architecture()
                .symboltab_mut()
                .unwrap()
                .scope_remove_symbol(global, label);
            let mut later = PeMetadata::default();
            later.functions.insert(0x1070, "taken".into());
            later.functions.insert(0x1080, "taken_1030".into());
            register(&mut program, &later, width).unwrap();
            let functions = program
                .functions()
                .unwrap()
                .into_iter()
                .map(|function| (function.address, function.name))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(functions[&0x1070], "taken");
            assert_eq!(functions[&0x1080], "taken_1030");
            assert_global_name_index(&mut program);
        }
    }

    #[test]
    fn veneer_promotion_keeps_retired_names_reserved_for_the_whole_pass() {
        let (mut bytes, sections, mut metadata) = arm64_fixture(ARM64_VENEER);
        for (index, word) in [0x9000_0010u32, 0xf940_4611, 0xd61f_0220]
            .into_iter()
            .enumerate()
        {
            bytes[0x50 + index * 4..0x54 + index * 4].copy_from_slice(&word.to_le_bytes());
        }
        metadata.functions.insert(0x1050, "FUN_1050".into());
        metadata.imports.insert(0x1080, "Renamed".into());
        metadata.imports.insert(0x1088, "FUN_1040".into());
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "AARCH64:LE:64:v8A:windows", 0x1000).unwrap();
        register(&mut program, &metadata, 8).unwrap();
        register_aarch64_import_thunks(
            &mut program,
            &metadata.imports,
            &bytes,
            &sections,
            &BTreeSet::from([0x1040, 0x1050]),
        )
        .unwrap();
        let functions = program
            .functions()
            .unwrap()
            .into_iter()
            .map(|function| (function.address, function.name))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(functions[&0x1040], "Renamed");
        assert_eq!(functions[&0x1050], "FUN_1040_1050");
        assert_global_name_index(&mut program);
    }

    #[test]
    fn names_only_reached_import_jumps_for_both_pe_pointer_widths() {
        for (pointer_bytes, language) in [
            (4, "x86:LE:32:default:windows"),
            (8, "x86:LE:64:default:windows"),
        ] {
            let mut bytes = vec![0xcc; 0x100];
            // CALL 0x1040; RET. The code at 0x1060 is never a call target.
            bytes[..6].copy_from_slice(&[0xe8, 0x3b, 0, 0, 0, 0xc3]);
            bytes[0x40..0x46].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
            bytes[0x60..0x66].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
            let (called_operand, uncalled_operand) = if pointer_bytes == 8 {
                (0x3au32, 0x22u32)
            } else {
                (0x1080u32, 0x1088u32)
            };
            bytes[0x42..0x46].copy_from_slice(&called_operand.to_le_bytes());
            bytes[0x62..0x66].copy_from_slice(&uncalled_operand.to_le_bytes());
            let mut program = Program::from_raw_bytes(bytes.clone(), language, 0x1000).unwrap();
            let mut metadata = PeMetadata::default();
            metadata.functions.insert(0x1000, "caller".into());
            metadata.imports.insert(0x1080, "ExitProcess".into());
            metadata.imports.insert(0x1088, "UncalledImport".into());
            register(&mut program, &metadata, pointer_bytes).unwrap();
            let sections = vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 0x100,
                file_offset: 0,
                file_size: 0x100,
                executable: true,
            }];
            register_import_thunks(
                &mut program,
                &metadata.imports,
                &bytes,
                &sections,
                &BTreeSet::from([0x1040]),
                pointer_bytes,
            )
            .unwrap();

            let functions = program.functions().unwrap();
            assert_eq!(functions.len(), 2);
            assert_eq!(functions[1].address, 0x1040);
            assert_eq!(functions[1].name, "ExitProcess");
            assert!(!functions.iter().any(|function| function.address == 0x1060));
            let text = program.decompile(0x1000).unwrap();
            assert!(text.contains("ExitProcess("), "{text}");
            assert!(!text.contains("__imp_ExitProcess"), "{text}");
        }
    }
}
