//! Shared bounded function-candidate validation. No engine registration occurs here.
use super::*;

pub(super) fn candidate_entry(loaded: &LoadedProgram, start: u64) -> bool {
    executable(
        &loaded.info.sections,
        start,
        loaded.target.instruction_alignment as usize,
    ) && start.is_multiple_of(loaded.target.instruction_alignment)
        && !loaded.coverage.incomplete
        && !loaded.coverage.contains(start)
        && !loaded
            .pe_ranges
            .iter()
            .any(|&(low, high)| low < start && start < high)
        && !loaded
            .pointers
            .as_ref()
            .is_some_and(|p| p.metadata.interior(start))
}

impl Walk {
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
        let terminal_exit = self.nodes.values().any(|node| {
            node.terminal
                && (node.next.is_empty()
                    || node.next.iter().any(|&(target, kind)| {
                        kind == EdgeKind::Branch && target.is_some_and(is_function)
                    }))
        });
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
}

/// Exact vendored funcstart corroboration, with the same constraints as the
/// ordinary pattern pass. The window is bounded by MAX_PATTERN_BYTES.
pub(super) fn pattern_boundary(loaded: &LoadedProgram, entry: u64) -> Option<usize> {
    let set =
        crate::function_patterns::PatternSet::select(loaded.target.name, &loaded.info.format)?;
    let patterns = set.patterns().ok()?;
    let section = loaded
        .info
        .sections
        .iter()
        .find(|s| s.executable && s.backs(entry, 1))?;
    let bytes = crate::pe_symbols::mapped_bytes(
        &loaded.snapshot,
        &loaded.info.sections,
        section.address,
        section.size.min(section.file_size),
        true,
    )?;
    let position = usize::try_from(entry.checked_sub(section.address)?).ok()?;
    let low = position.saturating_sub(crate::function_patterns::MAX_PATTERN_BYTES);
    let mut found = Vec::new();
    if !patterns.scan(
        bytes,
        section.address,
        low..position.checked_add(1)?,
        &mut found,
        MAX_PATTERN_MATCHES_PER_CHUNK,
    ) {
        return None;
    }
    found
        .iter()
        .filter(|m| m.start == entry)
        .filter_map(|m| {
            let start = patterns.patterns[m.pattern].start;
            (!start.after_defined || entry == section.address || loaded.coverage.ends_at(entry))
                .then_some(start.min_instructions)
        })
        .min()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pure_tail_body_is_complete_but_fallthrough_is_not() {
        for (bytes, valid) in [(vec![0xe9, 11, 0, 0, 0], true), (vec![0x90; 16], false)] {
            let mut bytes = bytes;
            bytes.resize(17, 0xc3);
            let program =
                Program::from_raw_bytes(bytes.clone(), "x86:LE:64:default:gcc", 0x1000).unwrap();
            let sections = vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 17,
                file_offset: 0,
                file_size: 17,
                executable: true,
            }];
            let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
            let known = |a| a == 0x1010;
            let mut remaining = MAX_INSTRUCTIONS;
            walk.run(
                &program,
                &Bounds {
                    sections: &sections,
                    is_function: &known,
                    pe_ranges: &[],
                    tail_entry: None,
                },
                &mut remaining,
                None,
            );
            assert_eq!(
                walk.complete_function(&Coverage::default(), &known, &|_| true, 1),
                valid
            );
        }
    }
}
