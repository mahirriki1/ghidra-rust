//! Resumable x86-64 ELF pointer evidence; no arbitrary instruction constants.
use super::*;
use crate::code_pointers::CodePointers;
use crate::elf_function_metadata::FunctionMetadata;

pub(super) struct PointerRecovery {
    pub(super) pointers: CodePointers,
    pub(super) metadata: FunctionMetadata,
    reported: bool,
    failed: bool,
}

impl LoadedProgram {
    pub(super) fn prepare_pointers(&mut self) {
        if self.pointers.is_some() || self.target.name != "x86-64" || self.info.format != "ELF" {
            return;
        }
        let parsed = CodePointers::parse(&self.snapshot, &self.info.sections);
        let failed = parsed.is_err();
        let pointers = parsed.unwrap_or_default();
        let metadata = if failed {
            FunctionMetadata::default()
        } else {
            FunctionMetadata::parse(&self.snapshot, &self.info, &pointers)
        };
        self.pointers = Some(PointerRecovery {
            pointers,
            metadata,
            reported: false,
            failed,
        });
    }

    pub(super) fn take_pointer_preparation(&mut self) -> usize {
        let Some(state) = &mut self.pointers else {
            return 0;
        };
        if state.reported {
            return 0;
        }
        state.reported = true;
        if state.failed {
            MAX_METADATA_RECORDS
        } else {
            state
                .pointers
                .records
                .saturating_add(state.metadata.records)
        }
    }

    pub(super) fn scan_pointers(
        &mut self,
        mut cursor: PointerCursor,
    ) -> Result<(PointerScan, Discovered, Vec<FunctionAdmission>), String> {
        self.prepare_pointers();
        let mut scan = PointerScan::default();
        let mut admissions = Vec::new();
        let mut added = BTreeMap::new();
        let mut name_bytes = self
            .info
            .functions
            .iter()
            .map(|f| json_escaped_len(&f.name))
            .fold(0usize, usize::saturating_add);
        scan.records = self.take_pointer_preparation();
        let Some(state) = self.pointers.as_mut() else {
            return Err("Pointer recovery requires x86-64 ELF".into());
        };
        scan.partial = state.failed || state.metadata.partial;
        if state.failed {
            return Ok((
                scan,
                Discovered {
                    added: vec![],
                    opaque: false,
                },
                admissions,
            ));
        }
        let mut remaining = MAX_ANALYSIS_INSTRUCTIONS;
        let mut switches = SwitchBudget::new();
        if cursor.phase == PointerPhase::Tables {
            for function in &self.info.functions {
                let address = function.address;
                if self.coverage.walked.contains(&address) {
                    continue;
                }
                if remaining < MAX_INSTRUCTIONS || scan.covered.len() == MAX_PATTERN_COVERAGE {
                    scan.next = Some(cursor);
                    scan.decode_attempts = MAX_ANALYSIS_INSTRUCTIONS - remaining;
                    return Ok((
                        scan,
                        Discovered {
                            added: Vec::new(),
                            opaque: false,
                        },
                        admissions,
                    ));
                }
                let mut budget = MAX_INSTRUCTIONS;
                let metadata = &self.pointers.as_ref().expect("prepared").metadata;
                let walk = recover_walk_switched(
                    &mut self.program,
                    &Bounds {
                        tail_entry: Some(&|a| metadata.fdes.contains_key(&a)),
                        sections: &self.info.sections,
                        is_function: &|a| function_at(&self.info.functions, a).is_some(),
                        pe_ranges: &self.pe_ranges,
                    },
                    address,
                    &mut budget,
                    &mut switches,
                    &self.no_return,
                    None,
                );
                remaining -= MAX_INSTRUCTIONS - budget;
                self.coverage
                    .add(address, &walk.map(|w| w.intervals()).unwrap_or_default());
                scan.covered.push(address);
            }
        }
        loop {
            if admissions.len() == MAX_PATTERN_ADMISSIONS
                || scan.candidates == MAX_PATTERN_VALIDATIONS
                || remaining < MAX_INSTRUCTIONS
                || scan.slots == MAX_PATTERN_SCAN_BYTES as usize / 8
            {
                scan.next = Some(cursor);
                break;
            }
            let candidate = match cursor.phase {
                PointerPhase::Metadata => {
                    let Some(witness) = self
                        .pointers
                        .as_ref()
                        .and_then(|p| p.metadata.callbacks.get(cursor.position as usize))
                        .copied()
                    else {
                        cursor = PointerCursor {
                            phase: PointerPhase::Tables,
                            ..Default::default()
                        };
                        scan.next = Some(cursor);
                        break;
                    };
                    cursor.position += 1;
                    scan.candidates += 1;
                    Some(witness)
                }
                PointerPhase::Tails => {
                    let index = self
                        .info
                        .functions
                        .partition_point(|f| f.address < cursor.position);
                    let Some(function) = self.info.functions.get(index) else {
                        break;
                    };
                    scan.candidates += 1;
                    let address = function.address;
                    cursor.position = address.checked_add(1).ok_or("Tail cursor overflow")?;
                    let state = self.pointers.as_ref().expect("prepared");
                    let mut budget = MAX_INSTRUCTIONS;
                    let walk = recover_walk_switched(
                        &mut self.program,
                        &Bounds {
                            tail_entry: Some(&|a| state.metadata.fdes.contains_key(&a)),
                            sections: &self.info.sections,
                            is_function: &|a| function_at(&self.info.functions, a).is_some(),
                            pe_ranges: &self.pe_ranges,
                        },
                        address,
                        &mut budget,
                        &mut switches,
                        &self.no_return,
                        None,
                    )?;
                    remaining -= MAX_INSTRUCTIONS - budget;
                    // Coverage preparation is charged and monotonic in owning entry.
                    let newly_covered = !self.coverage.walked.contains(&address);
                    self.coverage.add(address, &walk.intervals());
                    let mut targets = Vec::new();
                    for (&source, node) in &walk.nodes {
                        if !node.terminal {
                            continue;
                        }
                        for &(target, kind) in &node.next {
                            let Some(entry) = target else {
                                continue;
                            };
                            if kind != EdgeKind::Branch
                                || entry == address
                                || !state.metadata.fdes.contains_key(&entry)
                            {
                                continue;
                            }
                            targets.push(FunctionAdmission {
                                entry,
                                reason: AdmissionReason::CorroboratedTail,
                                source,
                                owner: Some(address),
                                encoding: PointerEncoding::Direct,
                                boundary: BoundaryEvidence::Fde,
                                table: None,
                            });
                        }
                    }
                    if targets.len() > MAX_ANALYSIS_INSTRUCTIONS / MAX_INSTRUCTIONS - 1 {
                        scan.partial = true;
                        if newly_covered {
                            scan.covered.push(address);
                        }
                        continue;
                    }
                    // A function's tail targets are a small bounded set. Don't advance
                    // the owner unless the whole set fits this request's allowance.
                    if targets.len() > MAX_PATTERN_VALIDATIONS - scan.candidates
                        || targets.len() > MAX_PATTERN_ADMISSIONS - admissions.len()
                        || targets.len().saturating_mul(MAX_INSTRUCTIONS) > remaining
                    {
                        cursor.position = address;
                        scan.next = Some(cursor);
                        break;
                    }
                    if newly_covered {
                        scan.covered.push(address);
                    }
                    for witness in targets {
                        scan.candidates += 1;
                        self.validate_pointer_candidate(
                            witness,
                            &mut remaining,
                            &mut added,
                            &mut name_bytes,
                            &mut admissions,
                        )?;
                    }
                    None
                }
                PointerPhase::Tables => {
                    let state = self.pointers.as_ref().expect("prepared");
                    if let Some(pending) = cursor.pending {
                        if pending < cursor.position {
                            cursor.pending = pending.checked_add(8);
                            scan.candidates += 1;
                            state
                                .pointers
                                .pointer(&self.snapshot, &self.info.sections, pending)
                                .map(|(entry, encoding)| FunctionAdmission {
                                    entry,
                                    reason: AdmissionReason::PointerTable,
                                    source: pending,
                                    owner: None,
                                    encoding,
                                    boundary: BoundaryEvidence::Fde,
                                    table: cursor.run_start,
                                })
                        } else {
                            cursor.pending = None;
                            continue;
                        }
                    } else {
                        let range = state
                            .pointers
                            .ranges
                            .iter()
                            .find(|&&(_, end)| end > cursor.position);
                        let Some(&(start, end)) = range else {
                            cursor = PointerCursor {
                                phase: PointerPhase::Tails,
                                ..Default::default()
                            };
                            scan.next = Some(cursor);
                            break;
                        };
                        let aligned = start.checked_add(7).ok_or("Pointer range overflow")? & !7;
                        if cursor.position < aligned
                            || cursor.position == aligned
                                && cursor.run_start.is_some_and(|s| s < aligned)
                        {
                            cursor.position = aligned;
                            cursor.run_start = None;
                            cursor.first_target = None;
                            cursor.confirmed = false;
                        }
                        let slot = cursor.position;
                        let next = slot.checked_add(8).ok_or("Pointer cursor overflow")?;
                        if next > end {
                            cursor.position = end;
                            cursor.run_start = None;
                            cursor.first_target = None;
                            cursor.confirmed = false;
                            continue;
                        }
                        cursor.position = next;
                        scan.slots += 1;
                        let pointer = state
                            .pointers
                            .pointer(&self.snapshot, &self.info.sections, slot)
                            .filter(|&(target, _)| {
                                crate::call_analysis::code_address(&self.info, target)
                            });
                        let Some((entry, encoding)) = pointer else {
                            cursor.run_start = None;
                            cursor.first_target = None;
                            cursor.confirmed = false;
                            continue;
                        };
                        if cursor.confirmed {
                            scan.candidates += 1;
                            Some(FunctionAdmission {
                                entry,
                                reason: AdmissionReason::PointerTable,
                                source: slot,
                                owner: None,
                                encoding,
                                boundary: BoundaryEvidence::Fde,
                                table: cursor.run_start,
                            })
                        } else {
                            if cursor.first_target.is_some_and(|first| first != entry) {
                                cursor.confirmed = true;
                                cursor.pending = cursor.run_start;
                            } else if cursor.first_target.is_none() {
                                cursor.first_target = Some(entry);
                                cursor.run_start = Some(slot);
                            }
                            None
                        }
                    }
                }
            };
            if let Some(witness) = candidate {
                self.validate_pointer_candidate(
                    witness,
                    &mut remaining,
                    &mut added,
                    &mut name_bytes,
                    &mut admissions,
                )?;
            }
        }
        scan.decode_attempts = MAX_ANALYSIS_INSTRUCTIONS - remaining;
        admissions.sort_by_key(|w| w.entry);
        let discovered = Discovered {
            added: added
                .into_iter()
                .map(|(address, name)| FunctionInfo { address, name })
                .collect(),
            opaque: false,
        };
        Ok((scan, discovered, admissions))
    }

    fn validate_pointer_candidate(
        &mut self,
        mut witness: FunctionAdmission,
        remaining: &mut usize,
        added: &mut BTreeMap<u64, String>,
        name_bytes: &mut usize,
        admissions: &mut Vec<FunctionAdmission>,
    ) -> Result<(), String> {
        let entry = witness.entry;
        if witness.owner.is_some_and(|owner| {
            function_at(&self.info.functions, owner).is_none() && !added.contains_key(&owner)
        }) {
            return Ok(());
        }
        if function_at(&self.info.functions, entry).is_some()
            || added.contains_key(&entry)
            || !function_candidates::candidate_entry(self, entry)
        {
            return Ok(());
        }
        let metadata = &self.pointers.as_ref().expect("prepared").metadata;
        let mut minimum = 1;
        if witness.reason == AdmissionReason::PointerTable && !metadata.fdes.contains_key(&entry) {
            let Some(pattern_minimum) = function_candidates::pattern_boundary(self, entry) else {
                return Ok(());
            };
            minimum = pattern_minimum;
            witness.boundary = BoundaryEvidence::Pattern;
        }
        let known = |a| function_at(&self.info.functions, a).is_some() || added.contains_key(&a);
        let mut budget = MAX_INSTRUCTIONS;
        let mut walk = Walk::new(
            &self.program,
            &self.info.sections,
            entry,
            &self.no_return,
            None,
        )?;
        walk.run(
            &self.program,
            &Bounds {
                tail_entry: None,
                sections: &self.info.sections,
                is_function: &|a| known(a) || metadata.fdes.contains_key(&a),
                pe_ranges: &self.pe_ranges,
            },
            &mut budget,
            None,
        );
        *remaining -= MAX_INSTRUCTIONS - budget;
        let metadata_entry = matches!(
            witness.reason,
            AdmissionReason::InitMetadata | AdmissionReason::CrtForwarder
        );
        let valid = if metadata_entry {
            !walk.nodes.is_empty()
                && walk
                    .intervals()
                    .iter()
                    .all(|&(a, b)| !self.coverage.overlaps(a, b))
        } else {
            walk.complete_function(
                &self.coverage,
                &known,
                &|a| crate::call_analysis::code_address(&self.info, a),
                minimum,
            )
        };
        let intervals = walk.intervals();
        let crosses_entry = intervals.iter().any(|&(low, high)| {
            let index = self.info.functions.partition_point(|f| f.address <= low);
            self.info
                .functions
                .get(index)
                .is_some_and(|f| f.address < high)
                || added.range(low.saturating_add(1)..high).next().is_some()
        });
        if !valid || crosses_entry || !metadata.compatible(entry, &intervals) {
            return Ok(());
        }
        if !admit_discovered(
            &mut self.program,
            self.info.functions.len(),
            added,
            name_bytes,
            entry,
        )? {
            return Err("Function admission limit reached".into());
        }
        self.coverage.add(entry, &walk.intervals());
        admissions.push(witness);
        Ok(())
    }
}
