//! The function-start pattern phase of discovery. See
//! `docs/analysis.md#function-start-patterns`.
use super::*;

/// Executable bytes, matches, candidate walks per pattern-scan request.
const PATTERN_SCAN_BYTES: u64 = 1024 * 1024;
const PATTERN_CHUNK_BYTES: usize = 64 * 1024;
const PATTERN_MATCHES: usize = 4_096;
const PATTERN_VALIDATIONS: usize = 128;

impl LoadedProgram {
    /// One bounded step of the function-start pattern scan from `cursor`.
    /// Established functions this worker has not decoded are walked first, so
    /// candidates inside existing code are rejected. Candidates are examined in
    /// address order; each admitted start's code joins the coverage at once.
    pub(super) fn scan_patterns(
        &mut self,
        cursor: u64,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<(PatternScan, Discovered), String> {
        let _span = crate::performance::span("discovery_function_patterns");
        let mut scan = PatternScan {
            next: Some(cursor),
            ..Default::default()
        };
        let mut discovered = Discovered {
            added: Vec::new(),
            opaque: false,
        };
        let Some(set) =
            crate::function_patterns::PatternSet::select(self.target.name, &self.info.format)
        else {
            scan.next = None;
            return Ok((scan, discovered));
        };
        let patterns = set.patterns()?;
        let mut remaining = MAX_ANALYSIS_INSTRUCTIONS;
        let mut switches = SwitchBudget::new();
        // Coverage first: a candidate is judged against all established code.
        let unwalked: Vec<_> = self
            .info
            .functions
            .iter()
            .map(|function| function.address)
            .filter(|address| !self.coverage.walked.contains(address))
            .collect();
        for address in unwalked {
            if remaining < MAX_INSTRUCTIONS {
                scan.partial = true;
                return Ok((scan, discovered));
            }
            let functions = &self.info.functions;
            let is_function = |candidate| function_at(functions, candidate).is_some();
            let mut budget = MAX_INSTRUCTIONS;
            let recovered = recover_graph_switched(
                &mut self.program,
                &Bounds {
                    sections: &self.info.sections,
                    is_function: &is_function,
                    pe_ranges: &self.pe_ranges,
                },
                address,
                &mut budget,
                &mut switches,
                &self.no_return,
                None,
            );
            remaining -= MAX_INSTRUCTIONS - budget;
            let intervals = recovered.map(|r| r.intervals).unwrap_or_default();
            self.coverage.add(address, &intervals);
            scan.covered += 1;
        }
        if self.coverage.incomplete {
            scan.partial = true;
            scan.next = None;
            return Ok((scan, discovered));
        }
        progress(AnalysisProgress {
            stage: AnalysisStage::Calls,
            functions_examined: 0,
            decode_attempts: MAX_ANALYSIS_INSTRUCTIONS - remaining,
        })?;
        let mut name_bytes = self
            .info
            .functions
            .iter()
            .map(|function| json_escaped_len(&function.name))
            .fold(0usize, usize::saturating_add)
            .min(MAX_FUNCTION_NAME_JSON_BYTES);
        let mut added = BTreeMap::new();
        let mut sections: Vec<_> = self
            .info
            .sections
            .iter()
            .filter(|section| {
                section.executable
                    && section.file_size > 0
                    // Import stubs are not function starts.
                    && !section.name.starts_with(".plt")
            })
            .collect();
        sections.sort_by_key(|section| section.address);
        let alignment = self.target.instruction_alignment;
        let mut matches = Vec::new();
        scan.next = 'scan: {
            for section in sections {
                let length = section.size.min(section.file_size);
                let Some(end) = section.address.checked_add(length) else {
                    continue;
                };
                if end <= cursor {
                    continue;
                }
                let Some(bytes) = usize::try_from(section.file_offset)
                    .ok()
                    .and_then(|offset| {
                        self.snapshot
                            .get(offset..offset.checked_add(usize::try_from(length).ok()?)?)
                    })
                else {
                    continue;
                };
                let mut position = cursor.saturating_sub(section.address) as usize;
                while position < bytes.len() {
                    if scan.scanned_bytes >= PATTERN_SCAN_BYTES {
                        break 'scan Some(section.address + position as u64);
                    }
                    let chunk = (bytes.len() - position).min(PATTERN_CHUNK_BYTES);
                    matches.clear();
                    // A flood of matches in one chunk is left unexamined.
                    scan.partial |= !patterns.scan(
                        bytes,
                        section.address,
                        position..position + chunk,
                        &mut matches,
                        PATTERN_MATCHES,
                    );
                    scan.matches += matches.len();
                    for found in &matches {
                        let start = found.start;
                        let pattern = &patterns.patterns[found.pattern];
                        let known = |address| {
                            added.contains_key(&address)
                                || function_at(&self.info.functions, address).is_some()
                        };
                        if known(start)
                            || !start.is_multiple_of(alignment)
                            || start >= end
                            || self.coverage.contains(start)
                            || self
                                .pe_ranges
                                .iter()
                                .any(|&(low, high)| low < start && start < high)
                            || pattern.start.after_defined
                                && start != section.address
                                && !self.coverage.ends_at(start)
                        {
                            continue;
                        }
                        if remaining < MAX_INSTRUCTIONS
                            || scan.validated == PATTERN_VALIDATIONS
                            || scan.admitted.len() == MAX_PATTERN_ADMISSIONS
                        {
                            // Unexamined, not rejected: resume at this match.
                            break 'scan Some(found.at);
                        }
                        scan.validated += 1;
                        let mut budget = MAX_INSTRUCTIONS;
                        let mut walk = Walk::new(&self.program, &self.info.sections, start, None)?
                            .with_no_return(&self.no_return);
                        walk.run(
                            &self.program,
                            &Bounds {
                                sections: &self.info.sections,
                                is_function: &|address| address != start && known(address),
                                pe_ranges: &self.pe_ranges,
                            },
                            &mut budget,
                            None,
                        );
                        remaining -= MAX_INSTRUCTIONS - budget;
                        let sections = &self.info.sections;
                        let is_code = |address: u64| {
                            address.is_multiple_of(alignment)
                                && executable(sections, address, alignment as usize)
                        };
                        if !walk.complete_function(
                            &self.coverage,
                            &known,
                            &is_code,
                            pattern.start.min_instructions,
                        ) {
                            continue;
                        }
                        if !admit_discovered(
                            &mut self.program,
                            self.info.functions.len(),
                            &mut added,
                            &mut name_bytes,
                            start,
                        )? {
                            scan.partial = true;
                            break 'scan None;
                        }
                        self.coverage.add(start, &walk.intervals());
                        scan.admitted.push(start);
                    }
                    position += chunk;
                    scan.scanned_bytes += chunk as u64;
                }
            }
            None
        };
        scan.admitted.sort_unstable();
        discovered.added = added
            .into_iter()
            .map(|(address, name)| FunctionInfo { address, name })
            .collect();
        Ok((scan, discovered))
    }
}
