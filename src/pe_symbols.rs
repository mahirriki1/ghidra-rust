//! Register already validated PE metadata through the pinned engine's public APIs.
use std::collections::{BTreeMap, BTreeSet};

use ghidra_decompiler::address::Address;
use ghidra_decompiler::database::Database;
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::Program;
use ghidra_decompiler::types::TypeMetatype;
use ghidra_decompiler::varnode::Varnode;

use crate::model::SectionInfo;
use crate::pe::{MAX_FUNCTIONS, MAX_IMPORTS, MAX_NAME_BYTES, PeMetadata};

pub(crate) const MAX_THUNK_TARGETS: usize = 2048;

fn truncated(text: &str, limit: usize) -> &str {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn unique_name(
    names: &mut BTreeSet<String>,
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
    if names.insert(base.clone()) {
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
        if names.insert(candidate.clone()) {
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
    // Include every existing global symbol, including symbols registered outside
    // Program's private records. Build the inventory once instead of repeatedly
    // calling Program::set_function_name's linear uniqueness checks.
    let mut names = architecture
        .symboltab_ref()
        .map_err(|error| error.explain().to_string())?
        .symbols
        .iter()
        .filter(|(_, symbol)| symbol.get_scope() == global)
        .map(|(_, symbol)| symbol.get_name().to_owned())
        .collect::<BTreeSet<_>>();

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
        let name = unique_name(&mut names, requested, offset, "FUN");
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
        if architecture
            .symboltab_ref()
            .map_err(|error| error.explain().to_string())?
            .scope_find_overlap(global, &address, pointer_bytes)
            .is_some()
        {
            continue;
        }
        let name = unique_name(&mut names, &format!("__imp_{requested}"), offset, "__imp");
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
        let operand = [bytes[2], bytes[3], bytes[4], bytes[5]];
        let slot = if pointer_bytes == 8 {
            target
                .checked_add(6)
                .and_then(|next| next.checked_add_signed(i64::from(i32::from_le_bytes(operand))))
        } else {
            Some(u64::from(u32::from_le_bytes(operand)))
        };
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

#[cfg(test)]
mod tests {
    use super::*;

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
