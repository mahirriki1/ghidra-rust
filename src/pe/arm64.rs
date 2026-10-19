//! Independent ARM64 PE metadata reader, based on Microsoft's ARM64 exception
//! handling specification (see docs/analysis.md). This recovers code regions and
//! primary entries; it does not unwind a stack or interpret language handlers.
use super::{Image, MAX_DIRECTORY_BYTES, MAX_TABLE_ENTRIES, PeMetadata, u32_at};

const INVALID: &str = "Some ARM64 PE runtime records are malformed, unsupported, or outside file-backed code; recovery is partial.";
const FRAGMENT: &str = "ARM64 PE fragment records retain code ranges but do not independently establish functions; fragment ownership and exception flow are not recovered.";

pub(super) fn runtime_functions(
    image: &Image<'_>,
    rva: u32,
    size: u32,
    entry: u64,
    out: &mut PeMetadata,
) {
    let Some(data) = image.directory(rva, size).filter(|_| rva.is_multiple_of(4)) else {
        incomplete(
            out,
            "ARM64 PE exception directory is not bounded aligned file-backed data; runtime functions were omitted.",
        );
        return;
    };
    if !size.is_multiple_of(8) || size / 8 > MAX_TABLE_ENTRIES {
        incomplete(
            out,
            "ARM64 PE runtime-function table is incomplete or exceeds the scan limit; recovery is partial.",
        );
    }
    let records = data.as_chunks::<8>().0;
    // Reject ambiguous ordering before publishing any table-derived entries.
    // An all-zero tail is padding, not an executable entry at RVA zero.
    let mut previous = None;
    let mut padding = false;
    for record in records.iter().take(MAX_TABLE_ENTRIES as usize) {
        let begin = u32_at(record, 0).unwrap();
        let unwind = u32_at(record, 4).unwrap();
        if begin == 0 && unwind == 0 {
            padding = true;
            continue;
        }
        if padding || previous.is_some_and(|old| begin <= old) {
            incomplete(
                out,
                "ARM64 PE runtime-function starts are not strictly ordered; table-derived functions were omitted.",
            );
            return;
        }
        previous = Some(begin);
    }
    // Charge every xdata read, including repeated references and failed records.
    // This prevents record count times xdata size from multiplying work budgets.
    let mut budget = MAX_DIRECTORY_BYTES as usize;
    let mut ranges = Vec::new();
    for record in records.iter().take(MAX_TABLE_ENTRIES as usize) {
        let begin = u32_at(record, 0).unwrap();
        let unwind = u32_at(record, 4).unwrap();
        if begin == 0 && unwind == 0 {
            continue;
        }
        if unwind & 3 == 3 {
            incomplete(
                out,
                "ARM64 PE parent .pdata links (jump islands) are not followed; they do not independently establish functions.",
            );
            continue;
        }
        let extent = match unwind & 3 {
            0 => xdata(image, unwind, &mut budget),
            flag => {
                let length = ((unwind >> 2) & 0x7ff) * 4;
                let reg_i = (unwind >> 16) & 0xf;
                (length != 0 && reg_i <= 10).then_some((length, flag == 2))
            }
        };
        let Some((length, fragment)) = extent else {
            incomplete(out, INVALID);
            continue;
        };
        let valid = || {
            if !begin.is_multiple_of(4) {
                return None;
            }
            let end = begin.checked_add(length)?;
            let address = image.function_address(begin, Some(end))?;
            Some((address, image.address(end)?, fragment))
        };
        if let Some(range) = valid() {
            ranges.push(range);
        } else {
            incomplete(out, INVALID);
        }
    }
    // Starts are ordered. Omit every member of a transitive overlap group; an
    // attacker cannot choose which conflicting metadata wins by reordering it.
    let mut candidates = Vec::new();
    let mut at = 0;
    while at < ranges.len() {
        let mut next = at + 1;
        let mut end = ranges[at].1;
        while next < ranges.len() && ranges[next].0 < end {
            end = end.max(ranges[next].1);
            next += 1;
        }
        if next == at + 1 {
            let (begin, end, fragment) = ranges[at];
            out.function_ranges.push((begin, end));
            if fragment {
                incomplete(out, FRAGMENT);
            } else {
                candidates.push(begin);
            }
        } else {
            incomplete(
                out,
                "Overlapping ARM64 PE runtime regions were omitted; recovery is partial.",
            );
        }
        at = next;
    }
    super::register_runtime_starts(candidates, entry, out);
}

fn incomplete(out: &mut PeMetadata, text: &str) {
    out.functions_truncated = true;
    out.warn(text);
}

fn charge(budget: &mut usize, bytes: usize) -> Option<()> {
    *budget = budget.checked_sub(bytes)?;
    Some(())
}

/// Return the covered byte length and whether this is a secondary region.
/// Validate storage, scope indices and opcode boundaries, without executing
/// unwinding or claiming the stack/register semantics have been reconstructed.
fn xdata(image: &Image<'_>, rva: u32, budget: &mut usize) -> Option<(u32, bool)> {
    if rva == 0 || !rva.is_multiple_of(4) {
        return None;
    }
    charge(budget, 4)?;
    let header = u32_at(image.data(rva, 4)?, 0)?;
    let length = (header & 0x3ffff).checked_mul(4)?;
    if length == 0 || (header >> 18) & 3 != 0 {
        return None;
    }
    let exception_handler = (header >> 20) & 1 != 0;
    let single_epilog = (header >> 21) & 1 != 0;
    let mut epilogs = (header >> 22) & 31;
    let mut words = header >> 27;
    let mut header_size = 4usize;
    if epilogs == 0 && words == 0 {
        charge(budget, 4)?;
        let extended = u32_at(image.data(rva.checked_add(4)?, 4)?, 0)?;
        if extended >> 24 != 0 {
            return None;
        }
        epilogs = extended & 0xffff;
        words = (extended >> 16) & 0xff;
        header_size = 8;
    }
    let scope_bytes = if single_epilog {
        0
    } else {
        epilogs as usize * 4
    };
    let code_bytes = words as usize * 4;
    let size = header_size + scope_bytes + code_bytes + usize::from(exception_handler) * 4;
    charge(budget, size - header_size)?;
    let data = image.data(rva, size)?;
    let code_start = header_size + scope_bytes;
    let code = &data[code_start..code_start + code_bytes];
    // One forward walk establishes opcode boundaries. One reverse walk validates
    // all referenced sequences, avoiding a separate code walk for every epilog.
    let mut boundaries = vec![false; code.len() + 1];
    let mut next = vec![0; code.len()];
    let mut at = 0;
    while at < code.len() {
        boundaries[at] = true;
        let width = match code[at] {
            0x00..=0xbf | 0xe1 | 0xe3..=0xe6 | 0xfc => 1,
            0xc0..=0xdf | 0xe2 => 2,
            0xe0 => 4,
            0xe7 if code.get(at + 1).is_some_and(|byte| byte & 0x80 == 0)
                && code.get(at + 2).is_some_and(|byte| byte & 0xc0 != 0xc0) =>
            {
                3
            }
            // Custom context/trap encodings and reserved opcodes are deferred.
            _ => return None,
        };
        next[at] = at.checked_add(width).filter(|end| *end <= code.len())?;
        at = next[at];
    }
    let mut terminates = vec![false; code.len() + 1];
    let mut chained = vec![false; code.len() + 1];
    for at in (0..code.len()).rev().filter(|at| boundaries[*at]) {
        terminates[at] = code[at] == 0xe4 || terminates[next[at]];
        chained[at] = code[at] != 0xe4 && (code[at] == 0xe5 || chained[next[at]]);
    }
    if !terminates[0] {
        return None;
    }
    let valid_index = |index: usize| index < code.len() && boundaries[index] && terminates[index];
    if single_epilog {
        if !valid_index(epilogs as usize) {
            return None;
        }
    } else {
        let mut previous = None;
        for scope in data[header_size..code_start].as_chunks::<4>().0 {
            let scope = u32_at(scope, 0)?;
            let start = (scope & 0x3ffff) * 4;
            if start >= length
                || (scope >> 18) & 0xf != 0
                || previous.is_some_and(|old| start <= old)
                || !valid_index((scope >> 22) as usize)
            {
                return None;
            }
            previous = Some(start);
        }
    }
    if exception_handler {
        let handler = u32_at(data, code_start + code_bytes)?;
        if !handler.is_multiple_of(4) || image.function_address(handler, None).is_none() {
            return None;
        }
    }
    Some((length, chained[0]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SectionInfo;
    use crate::pe::tests::{file, fixture, put16, put32};

    const BASE: u64 = 0x1_4000_0000;

    fn arm64(records: &[(u32, u32)]) -> (Vec<u8>, Vec<SectionInfo>) {
        let (mut bytes, sections) = fixture(true);
        put16(&mut bytes, 0x84, 0xaa64);
        // Keep the entry's independent evidence, remove unrelated exports/imports.
        bytes[0x108..0x118].fill(0);
        bytes[file(0x2000)..file(0x2100)].fill(0);
        put32(&mut bytes, 0x108 + 3 * 8 + 4, (records.len() * 8) as u32);
        for (index, (begin, unwind)) in records.iter().enumerate() {
            put32(&mut bytes, file(0x2000) + index * 8, *begin);
            put32(&mut bytes, file(0x2000) + index * 8 + 4, *unwind);
        }
        (bytes, sections)
    }

    fn parse(bytes: &[u8], sections: &[SectionInfo]) -> PeMetadata {
        crate::pe::parse(bytes, sections).unwrap().unwrap()
    }

    fn header(length: u32, epilogs: u32, words: u32) -> u32 {
        (length / 4) | (epilogs << 22) | (words << 27)
    }

    #[test]
    fn packed_normal_entries_and_fragments_have_distinct_evidence() {
        let (bytes, sections) = arm64(&[
            (0x1020, 0x20 | 1),
            (0x1040, 0x10 | 2),
            (0x1080, 0x2000 | 3), // parent link is not a packed length
        ]);
        let result = parse(&bytes, &sections);
        assert_eq!(result.functions.len(), 2); // entry + normal record
        assert!(result.functions.contains_key(&(BASE + 0x1020)));
        assert!(!result.functions.contains_key(&(BASE + 0x1040)));
        assert!(!result.functions.contains_key(&(BASE + 0x1080)));
        assert_eq!(
            result.function_ranges,
            [
                (BASE + 0x1020, BASE + 0x1040),
                (BASE + 0x1040, BASE + 0x1050)
            ]
        );
        assert!(result.functions_truncated);
        assert!(
            result
                .warnings
                .iter()
                .any(|note| note.contains("parent .pdata"))
        );
    }

    #[test]
    fn full_and_extended_xdata_recover_entries_but_chains_only_regions() {
        let (mut bytes, sections) = arm64(&[(0x1020, 0x2100), (0x1040, 0x2120), (0x1080, 0x2140)]);
        // Normal prolog + explicit epilog sharing the same sequence.
        put32(&mut bytes, file(0x2100), header(0x20, 1, 1));
        put32(&mut bytes, file(0x2104), 6); // epilog at +24, code index0
        bytes[file(0x2108)..file(0x210c)].copy_from_slice(&[0xe1, 0x81, 0xe4, 0xe3]);
        // Extended header, epilog index0 packed in E=1 header.
        put32(&mut bytes, file(0x2120), header(0x20, 0, 0) | 1 << 21);
        put32(&mut bytes, file(0x2124), 1 << 16);
        bytes[file(0x2128)..file(0x212c)].copy_from_slice(&[0xe1, 0x81, 0xe4, 0xe3]);
        // Chained scope: a phantom parent prolog is not a new function.
        put32(&mut bytes, file(0x2140), header(0x10, 0, 1));
        bytes[file(0x2144)..file(0x2148)].copy_from_slice(&[0xe5, 0x81, 0xe4, 0xe3]);
        let result = parse(&bytes, &sections);
        assert_eq!(result.functions.len(), 3);
        assert!(result.functions.contains_key(&(BASE + 0x1020)));
        assert!(result.functions.contains_key(&(BASE + 0x1040)));
        assert!(!result.functions.contains_key(&(BASE + 0x1080)));
        assert_eq!(result.function_ranges.len(), 3);
    }

    #[test]
    fn invalid_records_do_not_create_functions_or_poison_good_entries() {
        for (begin, unwind) in [
            (0x1021, 0x10 | 1),            // misalignment
            (0x1020, 1),                   // zero length
            (0x1020, 0x10 | 1 | 11 << 16), // impossible integer register count
            (0x11f0, 0x20 | 1),            // outside file-backed code
            (0xffff_fffc, 0x10 | 1),       // RVA overflow
            (0x1020, 0x25fc),              // truncated xdata
        ] {
            let (bytes, sections) = arm64(&[(begin, unwind)]);
            let result = parse(&bytes, &sections);
            assert_eq!(result.functions.len(), 1, "{begin:x} {unwind:x}");
            assert!(result.function_ranges.is_empty());
            assert!(result.functions_truncated);
        }
        let (bytes, sections) = arm64(&[(0x1020, 1), (0x1040, 0x10 | 1)]);
        assert!(
            parse(&bytes, &sections)
                .functions
                .contains_key(&(BASE + 0x1040))
        );
    }

    #[test]
    fn overlapping_and_unordered_runtime_regions_are_not_accepted() {
        for records in [
            vec![(0x1020, 0x30 | 1), (0x1040, 0x30 | 1), (0x1060, 0x20 | 1)],
            vec![(0x1040, 0x10 | 1), (0x1020, 0x10 | 1)],
            vec![(0x1020, 0x10 | 1), (0x1020, 0x10 | 1)],
            vec![(0, 0), (0x1020, 0x10 | 1)],
        ] {
            let (bytes, sections) = arm64(&records);
            let result = parse(&bytes, &sections);
            assert_eq!(result.functions.len(), 1);
            assert!(result.function_ranges.is_empty());
            assert!(result.functions_truncated);
        }
    }

    #[test]
    fn validates_xdata_version_scopes_opcode_boundaries_and_handler() {
        // Each case starts with valid nonextended xdata containing one epilog.
        for (offset, value) in [
            (0, header(0x20, 1, 1) | 1 << 18), // unknown version
            (4, 8),                            // scope starts at end of region
            (4, 1 << 18),                      // reserved scope bits
            (4, 1 << 22),                      // middle of two-byte unwind opcode
            (4, 4 << 22),                      // code index outside pool
            (8, 0xe3e3_e3e3),                  // no terminating end
            (8, 0xe3e4_00e8),                  // unsupported custom stack opcode
            (8, 0xe4c0_11e7),                  // reserved SVE predicate encoding
        ] {
            let (mut bytes, sections) = arm64(&[(0x1020, 0x2100)]);
            put32(&mut bytes, file(0x2100), header(0x20, 1, 1));
            put32(&mut bytes, file(0x2104), 6);
            bytes[file(0x2108)..file(0x210c)].copy_from_slice(&[0xc8, 0, 0xe4, 0xe3]);
            put32(&mut bytes, file(0x2100) + offset, value);
            assert_eq!(
                parse(&bytes, &sections).functions.len(),
                1,
                "{offset} {value:x}"
            );
        }
        let (mut bytes, sections) = arm64(&[(0x1020, 0x2100)]);
        put32(&mut bytes, file(0x2100), header(0x20, 0, 1) | 1 << 20);
        bytes[file(0x2104)..file(0x2108)].copy_from_slice(&[0x81, 0xe4, 0xe3, 0xe3]);
        put32(&mut bytes, file(0x2108), 0x1100);
        assert_eq!(parse(&bytes, &sections).functions.len(), 2);
        put32(&mut bytes, file(0x2108), 0x2000); // handler points to data
        assert_eq!(parse(&bytes, &sections).functions.len(), 1);
    }

    #[test]
    fn xdata_budget_charges_repeated_references_and_failed_reads() {
        let bytes = [4, 0, 0, 8, 0x81, 0xe4, 0xe3, 0xe3];
        let image = Image {
            bytes: &bytes,
            base: 0,
            regions: vec![super::super::Region {
                rva: 4,
                end: 12,
                offset: 0,
                executable: false,
            }],
        };
        let mut budget = 12;
        assert_eq!(xdata(&image, 4, &mut budget), Some((16, false)));
        assert_eq!(budget, 4);
        assert!(xdata(&image, 4, &mut budget).is_none());
        assert_eq!(budget, 0);
        assert!(xdata(&image, 4, &mut budget).is_none());
        let mut budget = 4;
        assert!(xdata(&image, 100, &mut budget).is_none());
        assert_eq!(budget, 0);
    }
}
