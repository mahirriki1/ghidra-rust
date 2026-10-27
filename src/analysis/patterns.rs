//! The function-start pattern phase of discovery. See
//! `docs/analysis.md#function-start-patterns`.
use super::*;

impl LoadedProgram {
    /// One bounded step of the function-start pattern scan from `cursor`.
    /// Established functions this worker has not decoded are walked first, so
    /// candidates inside existing code are rejected. Candidates are examined in
    /// address order; each admitted start's code joins the coverage at once.
    pub(super) fn scan_patterns(
        &mut self,
        cursor: u64,
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
        for function in &self.info.functions {
            let address = function.address;
            if self.coverage.walked.contains(&address) {
                continue;
            }
            if remaining < MAX_INSTRUCTIONS || scan.covered.len() == MAX_PATTERN_COVERAGE {
                return Ok((scan, discovered));
            }
            let functions = &self.info.functions;
            let is_function = |candidate| function_at(functions, candidate).is_some();
            let mut budget = MAX_INSTRUCTIONS;
            let recovered = recover_walk_switched(
                &mut self.program,
                &Bounds {
                    tail_entry: None,
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
            let intervals = recovered.map(|walk| walk.intervals()).unwrap_or_default();
            self.coverage.add(address, &intervals);
            scan.covered.push(address);
        }
        if self.coverage.incomplete {
            scan.partial = true;
            scan.next = None;
            return Ok((scan, discovered));
        }
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
            .filter(|section| section.executable && section.file_size > 0)
            .collect();
        sections.sort_by_key(|section| section.address);
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
                let Some(bytes) = crate::pe_symbols::mapped_bytes(
                    &self.snapshot,
                    &self.info.sections,
                    section.address,
                    length,
                    true,
                ) else {
                    continue;
                };
                let mut position = cursor.saturating_sub(section.address) as usize;
                while position < bytes.len() {
                    if scan.scanned_bytes == MAX_PATTERN_SCAN_BYTES
                        || scan.matches == MAX_PATTERN_MATCHES
                    {
                        break 'scan Some(section.address + position as u64);
                    }
                    let byte_budget = usize::try_from(MAX_PATTERN_SCAN_BYTES - scan.scanned_bytes)
                        .unwrap_or(usize::MAX);
                    let chunk = (bytes.len() - position)
                        .min(PATTERN_SCAN_CHUNK_BYTES)
                        .min(byte_budget);
                    matches.clear();
                    // A flood of matches in one chunk is left unexamined.
                    scan.partial |= !patterns.scan(
                        bytes,
                        section.address,
                        position..position + chunk,
                        &mut matches,
                        MAX_PATTERN_MATCHES_PER_CHUNK.min(MAX_PATTERN_MATCHES - scan.matches),
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
                            || !function_candidates::candidate_entry(self, start)
                            || start >= end
                            || pattern.start.after_defined
                                && start != section.address
                                && !self.coverage.ends_at(start)
                        {
                            continue;
                        }
                        if remaining < MAX_INSTRUCTIONS
                            || scan.validated == MAX_PATTERN_VALIDATIONS
                            || scan.admitted.len() == MAX_PATTERN_ADMISSIONS
                        {
                            // Unexamined, not rejected: resume at this match.
                            break 'scan Some(found.at);
                        }
                        scan.validated += 1;
                        let mut budget = MAX_INSTRUCTIONS;
                        let mut walk = Walk::new(
                            &self.program,
                            &self.info.sections,
                            start,
                            &self.no_return,
                            None,
                        )?;
                        walk.run(
                            &self.program,
                            &Bounds {
                                tail_entry: None,
                                sections: &self.info.sections,
                                is_function: &|address| address != start && known(address),
                                pe_ranges: &self.pe_ranges,
                            },
                            &mut budget,
                            None,
                        );
                        remaining -= MAX_INSTRUCTIONS - budget;
                        let info = &self.info;
                        let is_code = |address| crate::call_analysis::code_address(info, address);
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;

    fn x86_section(name: &str, bytes: Vec<u8>) -> LoadedProgram {
        let size = bytes.len() as u64;
        LoadedProgram {
            program: Program::from_raw_bytes(bytes.clone(), "x86:LE:64:default:gcc", 0x1000)
                .unwrap(),
            target: crate::architecture::Target {
                name: "x86-64",
                language: "x86:LE:64:default:gcc",
                pointer_bytes: 8,
                instruction_alignment: 1,
            },
            snapshot: Arc::from(bytes),
            pe_ranges: vec![],
            pe_imports: BTreeMap::new(),
            upx_packed: false,
            info: BinaryInfo {
                path: "synthetic".into(),
                architecture: "x86-64".into(),
                format: "ELF".into(),
                entry: 0x1000,
                file_len: size,
                sha256: "a".repeat(64),
                source_identity: None,
                sections: vec![SectionInfo {
                    name: name.into(),
                    address: 0x1000,
                    size,
                    file_offset: 0,
                    file_size: size,
                    executable: true,
                }],
                functions: vec![],
                functions_truncated: false,
                warnings: vec![],
            },
            inventory: Default::default(),
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::default(),
            symbol_names: Arc::default(),
            linkage: None,
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
        }
    }

    fn run_scan(loaded: &mut LoadedProgram) -> (PatternScan, Discovered) {
        loaded.scan_patterns(0).unwrap()
    }

    #[test]
    fn pattern_batches_follow_the_desktop_progress_protocol() {
        // The desktop stops a worker whose discovery progress does not start
        // at Seeds or whose reply does not match a final Publish event, so a
        // pattern step must satisfy both or discovery can never finish.
        let mut loaded = x86_section(".text", vec![0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]);
        let mut events: Vec<AnalysisProgress> = Vec::new();
        let reply = loaded
            .handle_with_progress(
                Request::DiscoverBatch {
                    binding: DiscoveryBinding {
                        generation: 1,
                        epoch: 1,
                        revision: 0,
                        batch: 1,
                    },
                    inventory_base: None,
                    seeds: Vec::new(),
                    patterns: Some(crate::model::DiscoveryCursor::Patterns(0)),
                },
                &mut |event| {
                    event.validate_event(events.len() + 1, events.last())?;
                    events.push(event);
                    Ok(())
                },
            )
            .unwrap();
        let Response::DiscoveryBatch { batch } = reply else {
            panic!("Expected a discovery batch");
        };
        assert_eq!(batch.patterns.unwrap().admitted, [0x1000]);
        batch.analysis.validate_final(events.last()).unwrap();
    }

    #[test]
    fn executable_plt_names_do_not_suppress_valid_pattern_starts() {
        // PUSH RBP; MOV RBP,RSP; POP RBP; RET is a complete GCC-patterned
        // function. The section name is untrusted metadata, not stub evidence.
        let mut loaded = x86_section(".plt.hidden", vec![0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]);
        let (scan, discovered) = run_scan(&mut loaded);
        assert_eq!(scan.scanned_bytes, loaded.snapshot.len() as u64);
        assert_eq!(scan.admitted, [0x1000]);
        assert_eq!(
            discovered
                .added
                .iter()
                .map(|f| f.address)
                .collect::<Vec<_>>(),
            [0x1000]
        );
    }

    #[test]
    fn conventional_plt_stubs_are_scanned_but_not_admitted() {
        // A conventional x86-64 ELF PLT0 entry followed by one lazy-binding
        // entry. Neither has a complete returning function body.
        let bytes = vec![
            0xff, 0x35, 0x02, 0x00, 0x00, 0x00, 0xff, 0x25, 0x04, 0x00, 0x00, 0x00, 0x0f, 0x1f,
            0x40, 0x00, 0xff, 0x25, 0x02, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0xe9,
            0xe0, 0xff, 0xff, 0xff,
        ];
        let mut loaded = x86_section(".plt", bytes);
        let (scan, discovered) = run_scan(&mut loaded);
        assert_eq!(scan.scanned_bytes, loaded.snapshot.len() as u64);
        assert!(scan.admitted.is_empty());
        assert!(discovered.added.is_empty());

        // Even a prologue-shaped stub is rejected when its only exit is an
        // unresolved indirect jump; candidate validation remains the guard.
        let mut loaded = x86_section(
            ".plt.sec",
            vec![0x55, 0x48, 0x89, 0xe5, 0xff, 0x25, 0, 0, 0, 0],
        );
        let (scan, discovered) = run_scan(&mut loaded);
        assert_eq!(scan.scanned_bytes, loaded.snapshot.len() as u64);
        assert!(scan.admitted.is_empty());
        assert!(discovered.added.is_empty());
    }
}
