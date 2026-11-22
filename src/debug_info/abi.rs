//! DWARF register numbering. Storage remains assigned by the engine's ABI model.
pub(crate) fn register(language: &str, number: u16) -> Option<String> {
    if language.starts_with("AARCH64:") {
        return match number {
            0..=30 => Some(format!("x{number}")),
            31 => Some("sp".into()),
            64..=95 => Some(format!("q{}", number - 64)),
            _ => None,
        };
    }
    let names: &[&str] = if language.starts_with("x86:LE:32:") {
        &[
            "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI", "EIP",
        ]
    } else {
        &[
            "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
            "R12", "R13", "R14", "R15", "RIP",
        ]
    };
    if let Some(name) = names.get(usize::from(number)) {
        return Some((*name).into());
    }
    let start = if language.starts_with("x86:LE:32:") {
        21
    } else {
        17
    };
    let count = if language.starts_with("x86:LE:32:") {
        8
    } else {
        16
    };
    (start..start + count)
        .contains(&number)
        .then(|| format!("XMM{}", number - start))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dwarf_register_numbers_are_not_shared_across_abis() {
        for (abi, n, expected) in [
            ("x86:LE:32:default:gcc", 1, "ECX"),
            ("x86:LE:32:default:windows", 2, "EDX"),
            ("x86:LE:64:default:gcc", 5, "RDI"),
            ("x86:LE:64:default:windows", 2, "RCX"),
            ("AARCH64:LE:64:v8A:default", 0, "x0"),
            ("AARCH64:LE:64:v8A:windows", 64, "q0"),
            ("AARCH64:LE:64:AppleSilicon:default", 31, "sp"),
        ] {
            assert_eq!(register(abi, n).as_deref(), Some(expected));
        }
        assert!(register("AARCH64:LE:64:v8A:default", 63).is_none());
    }
}

/// Facts collected before any DWARF locks are installed. These are not DWARF
/// locations: they describe actual read-before-write inputs from lifted code.
#[derive(Default)]
pub(crate) struct Evidence {
    pub inputs: Vec<(ghidra_decompiler::address::Address, i32)>,
    pub complete: bool,
}
/// Visits only input varnodes (the engine's definition order keeps them
/// contiguous), so evidence is complete regardless of function size.
/// Keep input evidence even when its reads fall outside the recovered CFG.
/// For instance, that CFG may be missing jump-table destinations.
pub(crate) fn capture(data: &ghidra_decompiler::funcdata::Funcdata) -> Evidence {
    use ghidra_decompiler::varnode::Varnode;
    let mut result = Evidence {
        complete: true,
        ..Default::default()
    };
    let (Ok(mut cursor), Ok(end)) = (
        data.begin_def_flags(Varnode::INPUT),
        data.end_def_flags(Varnode::INPUT),
    ) else {
        result.complete = false;
        return result;
    };
    for _ in 0..MAX_INPUT_VARNODES {
        if cursor == end {
            return result;
        }
        let Some(id) = data.vbank.def_at(&cursor) else {
            // The ordered input range ended before its end marker: the
            // evidence cannot be shown complete.
            result.complete = false;
            return result;
        };
        let vn = data.vn(id);
        if vn.is_input()
            && !vn.is_spacebase()
            && !vn.has_no_descend()
            && vn.get_addr().get_space().is_some_and(|s| {
                s.get_type() == ghidra_decompiler::space::SpaceType::Processor
                    && s.get_name() == "register"
            })
        {
            if result.inputs.len() == 256 {
                result.complete = false;
                return result;
            }
            result.inputs.push((vn.get_addr().clone(), vn.get_size()));
        }
        cursor = data.vbank.def_next(&cursor);
    }
    result.complete = false;
    result
}
/// Input varnodes visited (register, stack and other spaces together).
const MAX_INPUT_VARNODES: usize = 16_384;
