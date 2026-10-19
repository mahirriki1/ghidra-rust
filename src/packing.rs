//! Conservative diagnostics for packed images whose original code is unavailable.

use crate::model::{BinaryInfo, SectionInfo};

pub const UPX_PACKED_WARNING: &str = "UPX-packed PE detected: the visible entry code is an unpacking stub and strings may be compressed data. Decompilation and function discovery are disabled for this image; unpack a copy with UPX and open the unpacked copy.";
pub const UPX_ANALYSIS_ERROR: &str = "This PE is UPX-packed. Decompilation and function discovery of its unpacking stub are disabled because they can exhaust the analysis worker. Unpack a separate copy with UPX (for example, upx -d -o unpacked.exe original.exe), then open that copy. Listing, function graph, strings, and byte inspection remain available.";

/// Recognize this loader's diagnostic so the UI can avoid automatically
/// requesting analysis that the worker will reject. Saved warnings are display
/// data: the worker derives its own guard from the freshly parsed image.
pub fn has_upx_warning(info: &BinaryInfo) -> bool {
    info.warnings.iter().any(|note| note == UPX_PACKED_WARNING)
}

/// Called after the loader has validated nonoverlapping mapped sections.
/// Section names alone or a UPX string in ordinary application data are not
/// sufficient evidence. This is deliberately limited to the conventional UPX
/// PE layout; it is not a general packer detector or an authenticity check.
pub(crate) fn detect_upx_pe(
    format: &str,
    entry: u64,
    sections: &[SectionInfo],
    bytes: &[u8],
) -> bool {
    format == "PE"
        && sections
            .iter()
            .any(|section| section.name == "UPX0" && section.size > 0 && section.file_size == 0)
        && sections.iter().any(|section| {
            section.name == "UPX1"
                && section.executable
                && section.file_size > 0
                && section.file_size <= section.size
                && entry
                    .checked_sub(section.address)
                    .is_some_and(|relative| relative < section.file_size)
                && section
                    .file_offset
                    .checked_add(section.file_size)
                    .is_some_and(|end| end <= bytes.len() as u64)
        })
        && bytes[..bytes.len().min(64 * 1024)]
            .windows(4)
            .any(|window| window == b"UPX!")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packed_shape() -> (Vec<SectionInfo>, Vec<u8>) {
        let sections = vec![
            SectionInfo {
                name: "UPX0".into(),
                address: 0x140001000,
                size: 0x4000,
                file_offset: 0,
                file_size: 0,
                executable: true,
            },
            SectionInfo {
                name: "UPX1".into(),
                address: 0x140005000,
                size: 0x1000,
                file_offset: 0x400,
                file_size: 0x800,
                executable: true,
            },
        ];
        let mut bytes = vec![0; 0xc00];
        bytes[0x3e0..0x3e4].copy_from_slice(b"UPX!");
        (sections, bytes)
    }

    #[test]
    fn conventional_upx_pe_requires_all_independent_signals() {
        let (sections, bytes) = packed_shape();
        assert!(detect_upx_pe("PE", 0x140005100, &sections, &bytes));
        assert!(!detect_upx_pe("ELF", 0x140005100, &sections, &bytes));
        assert!(!detect_upx_pe("PE", 0x140001100, &sections, &bytes));
        assert!(!detect_upx_pe("PE", 0x140005800, &sections, &bytes));

        let mut no_header = bytes.clone();
        no_header[0x3e0..0x3e4].fill(0);
        assert!(!detect_upx_pe("PE", 0x140005100, &sections, &no_header));
        for section in 0..2 {
            let mut renamed = sections.clone();
            renamed[section].name = ".text".into();
            assert!(!detect_upx_pe("PE", 0x140005100, &renamed, &bytes));
        }
        let mut backed = sections.clone();
        backed[0].file_size = 1;
        assert!(!detect_upx_pe("PE", 0x140005100, &backed, &bytes));
        let mut nonexec = sections.clone();
        nonexec[1].executable = false;
        assert!(!detect_upx_pe("PE", 0x140005100, &nonexec, &bytes));
    }

    #[test]
    fn marker_search_is_bounded_and_invalid_ranges_do_not_match() {
        let (sections, mut bytes) = packed_shape();
        bytes[0x3e0..0x3e4].fill(0);
        bytes.resize(65540, 0);
        bytes[65536..65540].copy_from_slice(b"UPX!");
        assert!(!detect_upx_pe("PE", 0x140005100, &sections, &bytes));
        let (mut sections, bytes) = packed_shape();
        sections[1].file_offset = u64::MAX;
        assert!(!detect_upx_pe("PE", 0x140005100, &sections, &bytes));
        assert!(!detect_upx_pe("PE", 0, &[], &[]));
    }
}
