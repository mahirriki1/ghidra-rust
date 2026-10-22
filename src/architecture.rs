//! The desktop's supported instruction sets and container-specific ABIs.
//! Keep this narrower than the engine's embedded processor catalog.
use object::read::macho::MachHeader;
use object::{Architecture, BinaryFormat, Object};

#[derive(Clone, Copy, Debug)]
pub(crate) struct Target {
    pub name: &'static str,
    pub language: &'static str,
    pub pointer_bytes: i32,
    pub instruction_alignment: u64,
}

impl Target {
    pub fn for_image(image: &object::File<'_>) -> Result<Self, String> {
        if !image.is_little_endian() {
            return Err("Only little-endian executables are supported.".into());
        }
        if let Some(sub) = image.sub_architecture() {
            return Err(format!(
                "Unsupported architecture variant {sub:?}; ARM64EC and arm64e are not supported yet."
            ));
        }
        if image.architecture() == Architecture::Aarch64
            && let object::File::MachO64(macho) = image
        {
            // object 0.37 recognizes arm64e only when cpusubtype is exactly 2.
            // Capability/version bits in the high byte must not bypass rejection.
            let subtype = macho.macho_header().cpusubtype(macho.endian());
            if subtype != object::macho::CPU_SUBTYPE_ARM64_ALL {
                return Err(format!(
                    "Unsupported Mach-O ARM64 subtype {subtype:#x}; only baseline arm64 is supported, not arm64e."
                ));
            }
        }
        let pe = image.format() == BinaryFormat::Pe;
        let (name, language) = match image.architecture() {
            Architecture::I386 => {
                let language = if pe { "x86:LE:32:default:windows" } else { "x86:LE:32:default:gcc" };
                ("x86", language)
            }
            Architecture::X86_64 => {
                let language = if pe { "x86:LE:64:default:windows" } else { "x86:LE:64:default:gcc" };
                ("x86-64", language)
            }
            Architecture::Aarch64 if image.is_64() => {
                let language = match image.format() {
                    BinaryFormat::Pe => "AARCH64:LE:64:v8A:windows",
                    BinaryFormat::MachO => "AARCH64:LE:64:AppleSilicon:default",
                    _ => "AARCH64:LE:64:v8A:default",
                };
                ("AArch64", language)
            }
            Architecture::Arm => return Err("ARM/Thumb is not supported yet: instruction-mode context and interworking require additional loader support.".into()),
            other => return Err(format!("Unsupported architecture {other:?}; supported architectures are x86, x86-64, and little-endian AArch64 (64-bit ABI).")),
        };
        let (pointer_bytes, instruction_alignment) = properties(name).expect("supported name");
        Ok(Self {
            name,
            language,
            pointer_bytes: pointer_bytes as i32,
            instruction_alignment,
        })
    }
}

/// Pointer width and instruction alignment of a supported architecture, by
/// the display name `BinaryInfo::architecture` reports.
pub(crate) fn properties(name: &str) -> Option<(u64, u64)> {
    match name {
        "x86" => Some((4, 1)),
        "x86-64" => Some((8, 1)),
        "AArch64" => Some((8, 4)),
        _ => None,
    }
}

pub(crate) fn instruction_alignment(language: &str) -> u64 {
    if language.starts_with("AARCH64:") {
        4
    } else {
        1
    }
}

#[cfg(test)]
#[path = "../tests/common/mod.rs"]
mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;

    fn target(bytes: &[u8]) -> Result<Target, String> {
        Target::for_image(&object::File::parse(bytes).unwrap())
    }

    #[test]
    fn aarch64_uses_container_specific_abis() {
        for ((bytes, _), language) in [
            (fixtures::elf(true), "AARCH64:LE:64:v8A:default"),
            (fixtures::pe(), "AARCH64:LE:64:v8A:windows"),
            (fixtures::arm64_pe_metadata(), "AARCH64:LE:64:v8A:windows"),
            (fixtures::macho(), "AARCH64:LE:64:AppleSilicon:default"),
        ] {
            let target = target(&bytes).unwrap();
            assert_eq!(target.language, language);
            assert_eq!(target.pointer_bytes, 8);
            assert_eq!(target.instruction_alignment, 4);
        }
    }

    #[test]
    fn rejects_arm64ec_and_arm64e_including_capability_bits() {
        let (mut pe, _) = fixtures::pe();
        pe[0x84..0x86].copy_from_slice(&0xa641u16.to_le_bytes());
        assert!(target(&pe).unwrap_err().contains("Arm64EC"));
        let (mut macho, _) = fixtures::macho();
        for subtype in [2u32, 0x80000002, 0x82000002, 1] {
            macho[8..12].copy_from_slice(&subtype.to_le_bytes());
            assert!(target(&macho).unwrap_err().contains("arm64e"));
        }
    }

    #[test]
    fn rejects_big_endian_ilp32_arm_thumb_and_other_processors() {
        // Minimal ELF headers need no cross compiler or executable sections to
        // exercise architecture/ABI selection before the engine is initialized.
        for (class, little, machine, message) in [
            (2, false, 183u16, "little-endian"),
            (1, true, 183, "Unsupported architecture"),
            (1, true, 40, "ARM/Thumb"),
            (2, true, 243, "Unsupported architecture"),
        ] {
            let mut bytes = vec![0; 64];
            bytes[..7].copy_from_slice(&[
                0x7f,
                b'E',
                b'L',
                b'F',
                class,
                if little { 1 } else { 2 },
                1,
            ]);
            let machine = if little {
                machine.to_le_bytes()
            } else {
                machine.to_be_bytes()
            };
            bytes[18..20].copy_from_slice(&machine);
            assert!(target(&bytes).unwrap_err().contains(message));
        }
    }
}
