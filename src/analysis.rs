//! Bounded, synchronous analysis. This module runs in the disposable worker process.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(test)]
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use ghidra_decompiler::address::Address;
use ghidra_decompiler::opcodes::OpCode;
use ghidra_decompiler::program::{InstructionPcode, Program};
use object::{Object, ObjectSection, SectionFlags, SectionKind};
use sha2::{Digest, Sha256};

use crate::model::*;

const MAX_INSTRUCTIONS: usize = 2048;
const MAX_BLOCKS: usize = 128;
const MAX_BYTES: usize = 64 * 1024;
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RESULTS: usize = 10_000;
const SCAN_CHUNK: usize = 256 * 1024;
const MAX_STRING_PREVIEW: usize = 512;
const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

pub struct LoadedProgram {
    program: Program,
    target: crate::architecture::Target,
    // The engine currently takes ownership of a Vec, so the immutable scan snapshot
    // duplicates at most 128 MiB. Both copies originate from exactly the hashed bytes.
    // This favors consistent analysis over live file reads; engine snapshot sharing is future work.
    snapshot: Arc<[u8]>,
    pe_ranges: Vec<(u64, u64)>,
    pe_imports: BTreeMap<u64, String>,
    upx_packed: bool,
    pub info: BinaryInfo,
}

fn engine_error(error: ghidra_decompiler::error::Error) -> String {
    error.explain().to_string()
}

fn warning(warnings: &mut Vec<String>, message: impl Into<String>) {
    let message = message.into();
    if warnings.len() < 64 && !warnings.contains(&message) {
        warnings.push(message);
    }
}

fn mapped(section: &SectionInfo, address: u64) -> bool {
    address >= section.address && address - section.address < section.size
}

fn executable(sections: &[SectionInfo], address: u64, length: usize) -> bool {
    sections.iter().any(|section| {
        section.executable
            && mapped(section, address)
            && address - section.address < section.file_size
            && (length as u64) <= section.file_size.min(section.size) - (address - section.address)
    })
}

#[cfg(test)]
fn metadata(path: &Path, bytes: &[u8]) -> Result<BinaryInfo, String> {
    metadata_with_target(path, bytes).map(|(info, _)| info)
}

fn metadata_with_target(
    path: &Path,
    bytes: &[u8],
) -> Result<(BinaryInfo, crate::architecture::Target), String> {
    let object = object::File::parse(bytes).map_err(|e| format!("Cannot parse executable: {e}"))?;
    let format = match object.format() {
        object::BinaryFormat::Elf => "ELF",
        object::BinaryFormat::Pe => "PE",
        object::BinaryFormat::MachO => "Mach-O",
        other => {
            return Err(format!(
                "Unsupported executable format {other:?}; use ELF, PE, or Mach-O."
            ));
        }
    };
    if !matches!(
        object.kind(),
        object::ObjectKind::Executable | object::ObjectKind::Dynamic
    ) {
        return Err("Only linked executables and shared libraries are supported; relocatable object files are not supported yet.".into());
    }
    let target = crate::architecture::Target::for_image(&object)?;
    let mut sections = Vec::new();
    for section in object.sections() {
        let kind = section.kind();
        let (allocated, executable) = match section.flags() {
            SectionFlags::Elf { sh_flags } => (
                sh_flags & u64::from(object::elf::SHF_ALLOC) != 0,
                sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0,
            ),
            SectionFlags::Coff { characteristics } => (
                characteristics & object::pe::IMAGE_SCN_MEM_DISCARDABLE == 0,
                characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0,
            ),
            _ => (
                matches!(
                    kind,
                    SectionKind::Text
                        | SectionKind::Data
                        | SectionKind::ReadOnlyData
                        | SectionKind::ReadOnlyDataWithRel
                        | SectionKind::ReadOnlyString
                        | SectionKind::UninitializedData
                        | SectionKind::Tls
                        | SectionKind::UninitializedTls
                ),
                kind == SectionKind::Text,
            ),
        };
        if !allocated || section.size() == 0 {
            continue;
        }
        if sections.len() >= 4096 {
            return Err(
                "Executables with more than 4096 mapped sections are not supported yet.".into(),
            );
        }
        section
            .address()
            .checked_add(section.size())
            .ok_or("Section address overflow")?;
        let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
        if file_offset
            .checked_add(file_size)
            .is_none_or(|end| end > bytes.len() as u64)
        {
            return Err(format!(
                "Section {} extends past the file",
                section.name().unwrap_or("?")
            ));
        }
        sections.push(SectionInfo {
            name: section
                .name()
                .unwrap_or("<unnamed>")
                .chars()
                .take(256)
                .collect(),
            address: section.address(),
            size: section.size(),
            file_offset,
            file_size: file_size.min(section.size()),
            executable,
        });
    }
    sections.sort_by_key(|section| section.address);
    if !sections.iter().any(|s| s.executable && s.file_size > 0) {
        return Err("No supported executable sections found; sectionless executables are not supported yet.".into());
    }
    for pair in sections.windows(2) {
        if pair[0].address + pair[0].size > pair[1].address {
            return Err("Overlapping mapped sections are not supported by this prototype.".into());
        }
    }
    // object 0.37 exposes LC_MAIN's file offset, not a virtual address.
    // Translate only through validated file-backed executable sections. A Mach-O
    // without a supported LC_MAIN entry remains navigable by symbols/address.
    let entry = if object.format() == object::BinaryFormat::MachO {
        let offset = object.entry();
        let mut entry = None;
        // A zero value also means no LC_MAIN in object 0.37. Do not invent an
        // entry for legacy LC_UNIXTHREAD images or file-offset aliases.
        if offset != 0 {
            for section in &sections {
                let Some(relative) = offset.checked_sub(section.file_offset) else {
                    continue;
                };
                if section.executable && relative < section.file_size {
                    if entry.is_some() {
                        return Err(
                            "Mach-O entry file offset has ambiguous executable mappings.".into(),
                        );
                    }
                    entry = section.address.checked_add(relative);
                }
            }
        }
        entry.unwrap_or(0)
    } else {
        object.entry()
    };
    let mut info = BinaryInfo {
        path: path.to_string_lossy().into_owned(), architecture: target.name.into(), format: format.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)), source_identity: None,
        entry, file_len: bytes.len() as u64, sections, functions: Vec::new(), functions_truncated: false,
        warnings: vec!["Prototype analysis: symbols and supported PE function metadata load immediately; deeper function discovery is explicit. Optimized C++/Rust types and source reconstruction are incomplete.".into(), "Function lists are capped at 10,000 entries and names at 256 bytes in this prototype.".into()],
    };
    if crate::packing::detect_upx_pe(&info.format, info.entry, &info.sections, bytes) {
        warning(&mut info.warnings, crate::packing::UPX_PACKED_WARNING);
    }
    Ok((info, target))
}

impl LoadedProgram {
    pub fn open(path: &str) -> Result<Self, String> {
        let path = Path::new(path);
        #[cfg(windows)]
        crate::windows::validate_local_path(path)
            .map_err(|e| format!("Unsupported input binary path: {e}"))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        crate::windows::configure_read(&mut options);
        let mut file = options
            .open(path)
            .map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
        #[cfg(windows)]
        crate::windows::verify_regular_file(&file)
            .map_err(|e| format!("Cannot inspect input binary: {e}"))?;
        let file_metadata = file.metadata().map_err(|e| e.to_string())?;
        if !file_metadata.is_file() {
            return Err("Choose a regular executable file.".into());
        }
        if file_metadata.len() > MAX_IMAGE_BYTES {
            return Err("This prototype limits executable files to 128 MiB.".into());
        }
        // Bounded reading also handles a file growing after the metadata check.
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_IMAGE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Cannot read executable: {e}"))?;
        if bytes.len() as u64 > MAX_IMAGE_BYTES {
            return Err("Executable grew beyond the 128 MiB prototype limit while reading.".into());
        }
        let (mut info, target) = metadata_with_target(path, &bytes)?;
        // This flag comes only from the freshly parsed immutable image, never a
        // saved project's warnings or cached analysis.
        let upx_packed = crate::packing::has_upx_warning(&info);
        if target.name == "AArch64" {
            warning(
                &mut info.warnings,
                "AArch64 analysis is experimental: indirect branches, jump tables, exception flow, and newer ISA extensions may be incomplete.",
            );
        }
        info.source_identity = FileIdentity::from_file(&file);
        let snapshot = Arc::from(bytes.as_slice());
        let pe = crate::pe::parse(&bytes, &info.sections)?;
        let mut program =
            Program::from_image(&path.to_string_lossy(), bytes, Some(target.language))
                .map_err(engine_error)?;
        if program.language_id() != target.language {
            return Err(
                "Engine language does not match the validated binary architecture and ABI.".into(),
            );
        }
        let mut pe_ranges = Vec::new();
        let mut pe_imports = BTreeMap::new();
        if let Some(pe) = pe {
            crate::pe_symbols::register(&mut program, &pe, target.pointer_bytes)?;
            info.functions_truncated = pe.functions_truncated;
            for note in pe.warnings {
                warning(&mut info.warnings, note);
            }
            pe_ranges = pe.function_ranges;
            pe_imports = pe.imports;
        }
        info.functions = function_list(&program, &mut info)?;
        if !upx_packed && target.name == "AArch64" && !pe_imports.is_empty() {
            let targets = info
                .functions
                .iter()
                .map(|function| function.address)
                .take(crate::pe_symbols::MAX_THUNK_TARGETS)
                .collect();
            crate::pe_symbols::register_aarch64_import_thunks(
                &mut program,
                &pe_imports,
                &snapshot,
                &info.sections,
                &targets,
            )?;
            if info.functions.len() > crate::pe_symbols::MAX_THUNK_TARGETS {
                warning(
                    &mut info.warnings,
                    "ARM64 PE import-veneer naming on open is limited to the first 2,048 established function entries; discovery and selected-function analysis can name additional confirmed targets.",
                );
            }
            info.functions = function_list(&program, &mut info)?;
        }
        if !info.entry.is_multiple_of(target.instruction_alignment)
            || !executable(
                &info.sections,
                info.entry,
                target.instruction_alignment as usize,
            )
        {
            info.warnings.push("The binary entry point is not a supported aligned file-backed instruction address; select a function from the list.".into());
        }
        Ok(Self {
            program,
            target,
            snapshot,
            pe_ranges,
            pe_imports,
            upx_packed,
            info,
        })
    }

    pub fn handle(&mut self, request: Request) -> Result<Response, String> {
        self.handle_with_progress(request, &mut |_| Ok(()))
    }

    pub(crate) fn handle_with_progress(
        &mut self,
        request: Request,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<Response, String> {
        match request {
            Request::Graph { address } => Ok(Response::Graph {
                view: recover_graph_with_ranges(
                    &self.program,
                    &self.info.sections,
                    &self.info.functions,
                    address,
                    &self.pe_ranges,
                )?,
            }),
            Request::Decompile { address } => {
                self.check_unpacked()?;
                self.check_code(address)?;
                self.resolve_import_thunks(address)?;
                let (mut text, mut mappings) =
                    crate::decompile::render(&mut self.program, address, &self.info.sections)
                        .map_err(engine_error)?;
                if text.len() > MAX_DECOMPILED_BYTES {
                    let mut end = MAX_DECOMPILED_BYTES - 100;
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    text.truncate(end);
                    mappings.retain(|mapping| mapping.end <= end);
                    text.push_str(
                        "\n/* Decompiler output truncated at the 2 MiB prototype limit. */\n",
                    );
                }
                Ok(Response::Decompiled {
                    address,
                    text,
                    mappings,
                })
            }
            Request::Discover => {
                self.check_unpacked()?;
                // Selected-function analysis can materialize and name a callee
                // since the last published inventory. Preserve those names.
                self.info.functions = function_list(&self.program, &mut self.info)?;
                let analysis = self.discover_calls(progress)?;
                self.info.functions = function_list(&self.program, &mut self.info)?;
                Ok(Response::Functions {
                    functions: self.info.functions.clone(),
                    truncated: self.info.functions_truncated || analysis.partial,
                    analysis,
                })
            }
            Request::Rename { address, name } => {
                self.check_code(address)?;
                if name.trim().is_empty() || name.len() > 1024 || name.chars().any(char::is_control)
                {
                    return Err(
                        "Function names must contain 1–1024 bytes and no control characters."
                            .into(),
                    );
                }
                self.program
                    .set_function_name(address, &name)
                    .map_err(engine_error)?;
                self.synchronize_function_name(address, &name)?;
                self.info.functions = function_list(&self.program, &mut self.info)?;
                Ok(Response::Renamed { address, name })
            }
            Request::Bytes { address, length } => {
                let bytes = read_virtual(&self.snapshot, &self.info.sections, address, length)?;
                Ok(Response::Bytes { address, bytes })
            }
            Request::Strings => self.strings(MIN_STRING_LENGTH),
            Request::StringsWithOptions { minimum_length } => self.strings(minimum_length),
            Request::Crypto => self.crypto(),
            Request::Open { .. } => Err("Open is handled by the worker.".into()),
        }
    }

    fn check_unpacked(&self) -> Result<(), String> {
        if self.upx_packed {
            return Err(crate::packing::UPX_ANALYSIS_ERROR.into());
        }
        Ok(())
    }

    fn discover_calls(
        &mut self,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<CallAnalysis, String> {
        // Adapted from Ghidra FunctionAnalyzer's established-call rule and its
        // fallthrough-call exclusion. See NOTICE and docs/analysis.md. Decode
        // through public pinned-engine APIs; never promote arbitrary constants.
        let mut report = CallAnalysis {
            partial: self.info.functions_truncated,
            ..Default::default()
        };
        let emit =
            |stage,
             report: &CallAnalysis,
             progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>| {
                progress(AnalysisProgress {
                    stage,
                    functions_examined: report.functions_examined,
                    decode_attempts: report.decode_attempts,
                })
            };
        emit(AnalysisStage::Seeds, &report, progress)?;
        let space = self
            .program
            .architecture()
            .manager
            .get_default_data_space()
            .ok_or("Missing default data space during reference analysis")?;
        if space.get_word_size() != 1 {
            return Err("Data references require a byte-addressed memory space".into());
        }
        let space_name = space.get_name().to_owned();
        let mut data = crate::data_analysis::DataCollector::new(
            &self.info.sections,
            &space_name,
            self.target.pointer_bytes as u32,
        );
        let mut known: BTreeMap<_, _> = self
            .info
            .functions
            .iter()
            .map(|f| (f.address, f.name.clone()))
            .collect();
        report.partial |= known.len() > MAX_ANALYSIS_FUNCTIONS;
        let mut pending = VecDeque::new();
        let mut scheduled = BTreeSet::new();
        if self.check_code(self.info.entry).is_ok() {
            scheduled.insert(self.info.entry);
            pending.push_back(self.info.entry);
        }
        for &address in known.keys().take(MAX_ANALYSIS_FUNCTIONS) {
            if scheduled.insert(address) {
                pending.push_back(address);
            }
        }
        let mut references = BTreeSet::new();
        emit(AnalysisStage::Calls, &report, progress)?;
        while let Some(address) = pending.pop_front() {
            if report.functions_examined == MAX_ANALYSIS_FUNCTIONS
                || report.decode_attempts == MAX_ANALYSIS_INSTRUCTIONS
            {
                report.partial = true;
                break;
            }
            report.functions_examined += 1;
            let functions: Vec<_> = known
                .iter()
                .map(|(&address, name)| FunctionInfo {
                    address,
                    name: name.clone(),
                })
                .collect();
            let available =
                (MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts).min(MAX_INSTRUCTIONS);
            let mut remaining = available;
            let recovered = recover_graph_budgeted(
                &self.program,
                &self.info.sections,
                &functions,
                address,
                &self.pe_ranges,
                &mut remaining,
                Some(&mut data),
            );
            report.decode_attempts += available - remaining;
            match recovered {
                Ok(recovered) => {
                    report.partial |= recovered.partial;
                    // Failed decoding must not materialize a new engine function.
                    if !known.contains_key(&address) {
                        if known.len() < MAX_RESULTS {
                            let name = format!("FUN_{address:08x}");
                            self.program
                                .set_function_name(address, &name)
                                .map_err(engine_error)?;
                            known.insert(address, name);
                        } else {
                            report.partial = true;
                            continue;
                        }
                    }
                    for (call, fallthrough) in recovered.calls {
                        if references.len()
                            + report.unresolved_calls
                            + report.skipped_fallthrough_calls
                            >= MAX_CALL_REFERENCES
                        {
                            report.partial = true;
                            break;
                        }
                        let Some(target) = call
                            .target
                            .filter(|target| self.check_code(*target).is_ok())
                        else {
                            report.unresolved_calls += 1;
                            report.partial = true;
                            continue;
                        };
                        if target == fallthrough {
                            report.skipped_fallthrough_calls += 1;
                            continue;
                        }
                        let reference = CallReference {
                            caller: address,
                            address: call.address,
                            target,
                        };
                        if references.len() == MAX_CALL_REFERENCES
                            && !references.contains(&reference)
                        {
                            report.partial = true;
                            continue;
                        }
                        references.insert(reference);
                        if scheduled.len() < MAX_RESULTS && scheduled.insert(target) {
                            pending.push_back(target);
                        } else if !scheduled.contains(&target) {
                            report.partial = true;
                        }
                    }
                }
                Err(_) => {
                    report.failed_functions += 1;
                    report.partial = true;
                }
            }
            emit(AnalysisStage::Calls, &report, progress)?;
        }
        report.references = references.into_iter().collect();
        report.data = Some(data.finish());
        if self.target.name == "AArch64" && !self.pe_imports.is_empty() {
            let targets: BTreeSet<_> = report
                .references
                .iter()
                .map(|reference| reference.target)
                .chain(known.keys().copied())
                .collect();
            report.partial |= targets.len() > crate::pe_symbols::MAX_THUNK_TARGETS;
            let targets = targets
                .into_iter()
                .take(crate::pe_symbols::MAX_THUNK_TARGETS)
                .collect();
            let mut remaining = MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts;
            report.partial |= !crate::pe_symbols::register_aarch64_import_thunks_budgeted(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
                &mut remaining,
            )?;
            report.decode_attempts = MAX_ANALYSIS_INSTRUCTIONS - remaining;
        }
        emit(AnalysisStage::Publish, &report, progress)?;
        Ok(report)
    }

    fn check_code(&self, address: u64) -> Result<(), String> {
        if !address.is_multiple_of(self.target.instruction_alignment) {
            return Err(format!(
                "{} instructions require {}-byte aligned addresses.",
                self.target.name, self.target.instruction_alignment
            ));
        }
        if executable(
            &self.info.sections,
            address,
            self.target.instruction_alignment as usize,
        ) {
            Ok(())
        } else {
            Err(format!(
                "{address:#x} is outside file-backed executable sections."
            ))
        }
    }

    fn resolve_import_thunks(&mut self, entry: u64) -> Result<(), String> {
        if self.pe_imports.is_empty() {
            return Ok(());
        }
        let mut pending = VecDeque::from([entry]);
        let mut visited = BTreeSet::new();
        let mut targets = BTreeSet::from([entry]);
        // The decompiler can follow a tail branch into another known function.
        // Resolve imports from those exact CFG call targets as well, with a
        // fixed work budget. Never treat arbitrary byte matches as code entries.
        while visited.len() < 8 {
            let Some(address) = pending.pop_front() else {
                break;
            };
            if !visited.insert(address) {
                continue;
            }
            let Ok(view) = recover_graph_with_ranges(
                &self.program,
                &self.info.sections,
                &self.info.functions,
                address,
                &self.pe_ranges,
            ) else {
                continue;
            };
            for target in view.calls.iter().filter_map(|call| call.target) {
                if targets.len() < crate::pe_symbols::MAX_THUNK_TARGETS {
                    targets.insert(target);
                }
            }
            let blocks: BTreeSet<_> = view.blocks.iter().map(|block| block.address).collect();
            for target in view.edges.iter().filter_map(|edge| edge.target) {
                if !blocks.contains(&target)
                    && self
                        .pe_ranges
                        .binary_search_by_key(&target, |range| range.0)
                        .is_ok()
                    && !visited.contains(&target)
                {
                    pending.push_back(target);
                }
            }
        }
        if self.target.name == "AArch64" {
            return crate::pe_symbols::register_aarch64_import_thunks(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
            );
        }
        crate::pe_symbols::register_import_thunks(
            &mut self.program,
            &self.pe_imports,
            &self.snapshot,
            &self.info.sections,
            &targets,
            self.target.pointer_bytes,
        )
    }

    fn synchronize_function_name(&mut self, address: u64, name: &str) -> Result<(), String> {
        // In the pinned engine, Program::set_function_name updates the symbol but
        // leaves an already materialized Funcdata and its local scope unchanged.
        // Update those public engine objects too, so definitions and call sites
        // use the same name. This is a model/cache update, never a text rewrite.
        let architecture = self.program.architecture();
        let space = architecture
            .manager
            .get_default_code_space()
            .ok_or("Missing default code space while renaming function")?;
        let symbol = {
            let table = architecture
                .symboltab
                .as_deref()
                .ok_or("Missing symbol table while renaming function")?;
            let global = table
                .get_global_scope()
                .ok_or("Missing global scope while renaming function")?;
            let symbol = table
                .scope_query_function(global, &Address::new(space, address))
                .ok_or("Renamed function symbol was not found")?;
            let entry = table
                .symbol_get_first_whole_map(symbol)
                .map_err(engine_error)?;
            if table.entry(entry).get_addr().get_offset() != address {
                return Err("Renaming requires the start address of a function.".into());
            }
            symbol
        };
        architecture
            .with_function(symbol, |function, architecture| {
                architecture.clear_analysis(function);
                function.name = name.to_string();
                function.display_name = name.to_string();
                if let Some(scope) = function.get_scope_local() {
                    let local = architecture.symboltab_mut()?.scope_mut(scope);
                    local.name = name.to_string();
                    local.display_name = name.to_string();
                }
                Ok(())
            })
            .map_err(engine_error)
    }

    fn strings(&mut self, minimum_length: usize) -> Result<Response, String> {
        scan_strings(&self.snapshot, &self.info.sections, minimum_length)
    }

    fn crypto(&mut self) -> Result<Response, String> {
        let mut matches = Vec::new();
        let mut scanned = 0u64;
        let mut truncated = false;
        // Overlap preserves signatures that straddle chunk boundaries.
        const OVERLAP: usize = crate::crypto::MAX_SIGNATURE_LEN - 1;
        for section in &self.info.sections {
            let size = section.file_size.min(MAX_SCAN_BYTES - scanned);
            if size < section.file_size {
                truncated = true;
            }
            if size == 0 {
                continue;
            }
            let mut offset = 0u64;
            while offset < size {
                let count = (size - offset).min(SCAN_CHUNK as u64) as usize;
                let overlap_start = offset.saturating_sub(OVERLAP as u64);
                let base = section.address + overlap_start;
                let file_start = (section.file_offset + overlap_start) as usize;
                let file_end = (section.file_offset + offset + count as u64) as usize;
                let chunk = self
                    .snapshot
                    .get(file_start..file_end)
                    .ok_or("Section extends past immutable image snapshot")?;
                let chunk_limit = MAX_RESULTS.min(crate::crypto::MAX_MATCHES);
                let found = crate::crypto::scan_region(chunk, base, chunk_limit);
                let chunk_limited = found.len() >= chunk_limit;
                // Matches fully contained in the preceding overlap were already reported.
                for hit in found {
                    if offset == 0
                        || hit.address.saturating_add(hit.length as u64) > section.address + offset
                    {
                        matches.push(hit);
                    }
                }
                if matches.len() >= MAX_RESULTS || chunk_limited {
                    matches.truncate(MAX_RESULTS);
                    return Ok(Response::Crypto {
                        matches,
                        truncated: true,
                    });
                }
                offset += count as u64;
            }
            scanned += size;
        }
        matches.sort_by_key(|m| m.address);
        Ok(Response::Crypto { matches, truncated })
    }
}

fn function_list(program: &Program, info: &mut BinaryInfo) -> Result<Vec<FunctionInfo>, String> {
    let alignment = crate::architecture::instruction_alignment(program.language_id());
    let code_entry = |address: u64| {
        address.is_multiple_of(alignment) && executable(&info.sections, address, alignment as usize)
    };
    let mut entries = program
        .functions()
        .map_err(engine_error)?
        .into_iter()
        .filter(|f| code_entry(f.address));
    let mut functions: Vec<_> = entries
        .by_ref()
        .take(MAX_RESULTS)
        .map(|f| FunctionInfo {
            address: f.address,
            name: bounded_name(&f.name),
        })
        .collect();
    let truncated = entries.next().is_some();
    if code_entry(info.entry) && !functions.iter().any(|f| f.address == info.entry) {
        if functions.len() == MAX_RESULTS {
            functions.pop();
            info.functions_truncated = true;
        }
        functions.push(FunctionInfo {
            address: info.entry,
            name: "entry".into(),
        });
    }
    functions.sort_by_key(|f| f.address);
    functions.dedup_by_key(|f| f.address);
    info.functions_truncated |= truncated;
    Ok(functions)
}

fn bounded_name(name: &str) -> String {
    let mut end = name.len().min(256);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

fn read_virtual(
    snapshot: &[u8],
    sections: &[SectionInfo],
    address: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    if length > MAX_BYTES {
        return Err("Byte selections are limited to 64 KiB.".into());
    }
    address
        .checked_add(length as u64)
        .ok_or("Byte range overflows address space")?;
    let mut output = vec![0; length];
    let mut written = 0;
    while written < length {
        let current = address + written as u64;
        let section = sections
            .iter()
            .find(|s| mapped(s, current))
            .ok_or_else(|| format!("Unmapped address {current:#x}; selection crosses a gap."))?;
        let offset = current - section.address;
        let count = (section.size - offset).min((length - written) as u64) as usize;
        let backed = section.file_size.saturating_sub(offset).min(count as u64) as usize;
        if backed > 0 {
            let start = (section.file_offset + offset) as usize;
            let source = snapshot
                .get(start..start + backed)
                .ok_or("Section extends past immutable image snapshot")?;
            output[written..written + backed].copy_from_slice(source);
        }
        // Mapped uninitialized tails are zero-filled, unlike unmapped gaps.
        written += count;
    }
    Ok(output)
}

fn printable(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// Scan immutable mapped bytes with a bounded result preview and one extra match
/// to distinguish an exactly full result from an actually truncated result.
fn scan_strings(
    snapshot: &[u8],
    sections: &[SectionInfo],
    minimum_length: usize,
) -> Result<Response, String> {
    if !(MIN_STRING_LENGTH..=MAX_STRING_MINIMUM).contains(&minimum_length) {
        return Err(format!(
            "Minimum string length must be between {MIN_STRING_LENGTH} and {MAX_STRING_MINIMUM}."
        ));
    }
    let mut strings = Vec::new();
    let mut scanned = 0u64;
    let mut truncated = false;
    'sections: for section in sections {
        let size = section.file_size.min(MAX_SCAN_BYTES - scanned);
        if size < section.file_size {
            truncated = true;
        }
        if size == 0 {
            continue;
        }
        let mut ascii = StringRun::new(minimum_length);
        // Both parities are scanned: packed UTF-16 strings need not be aligned.
        let mut wide = [
            StringRun::new(minimum_length),
            StringRun::new(minimum_length),
        ];
        let mut previous = None;
        let mut offset = 0u64;
        while offset < size {
            let count = (size - offset).min(SCAN_CHUNK as u64) as usize;
            let start = section
                .file_offset
                .checked_add(offset)
                .and_then(|start| usize::try_from(start).ok())
                .ok_or("Section file offset overflows")?;
            let end = start
                .checked_add(count)
                .ok_or("Section file offset overflows")?;
            let chunk = snapshot
                .get(start..end)
                .ok_or("Section extends past immutable image snapshot")?;
            for (index, &byte) in chunk.iter().enumerate() {
                let address = section
                    .address
                    .checked_add(offset + index as u64)
                    .ok_or("Section virtual address overflows")?;
                ascii.feed(
                    printable(byte).then_some(byte as char),
                    address,
                    "ASCII",
                    &mut strings,
                );
                if let Some(low) = previous {
                    let start = address - 1;
                    wide[(start & 1) as usize].feed(
                        (byte == 0 && printable(low)).then_some(low as char),
                        start,
                        "UTF-16LE",
                        &mut strings,
                    );
                }
                previous = Some(byte);
                if strings.len() > MAX_STRING_RESULTS {
                    truncated = true;
                    break 'sections;
                }
            }
            offset += count as u64;
        }
        ascii.flush("ASCII", &mut strings);
        for run in &mut wide {
            run.flush("UTF-16LE", &mut strings);
        }
        scanned += size;
        if strings.len() > MAX_STRING_RESULTS {
            truncated = true;
            break;
        }
    }
    strings.truncate(MAX_STRING_RESULTS);
    strings.sort_by_key(|s| s.address);
    Ok(Response::Strings { strings, truncated })
}

struct StringRun {
    minimum_length: usize,
    start: u64,
    count: usize,
    text: String,
}

impl Default for StringRun {
    fn default() -> Self {
        Self::new(MIN_STRING_LENGTH)
    }
}

impl StringRun {
    fn new(minimum_length: usize) -> Self {
        Self {
            minimum_length,
            start: 0,
            count: 0,
            text: String::new(),
        }
    }

    fn feed(
        &mut self,
        character: Option<char>,
        address: u64,
        encoding: &str,
        output: &mut Vec<StringEntry>,
    ) {
        if let Some(character) = character {
            if self.count == 0 {
                self.start = address;
            }
            self.count += 1;
            if self.text.len() < MAX_STRING_PREVIEW {
                self.text.push(character);
            }
        } else {
            self.flush(encoding, output);
        }
    }

    fn flush(&mut self, encoding: &str, output: &mut Vec<StringEntry>) {
        if self.count >= self.minimum_length && output.len() <= MAX_STRING_RESULTS {
            let mut text = std::mem::take(&mut self.text);
            if self.count > MAX_STRING_PREVIEW {
                text.push('…');
            }
            output.push(StringEntry {
                address: self.start,
                text,
                encoding: encoding.into(),
            });
        }
        self.count = 0;
        self.text.clear();
    }
}

struct Decoded {
    instruction: Instruction,
    next: Vec<(Option<u64>, EdgeKind)>,
    terminal: bool,
}

/// Recover reachable basic blocks from raw instruction p-code, without running decompilation.
pub fn recover_graph(
    program: &Program,
    sections: &[SectionInfo],
    functions: &[FunctionInfo],
    entry: u64,
) -> Result<FunctionView, String> {
    recover_graph_with_ranges(program, sections, functions, entry, &[])
}

fn recover_graph_with_ranges(
    program: &Program,
    sections: &[SectionInfo],
    functions: &[FunctionInfo],
    entry: u64,
    pe_ranges: &[(u64, u64)],
) -> Result<FunctionView, String> {
    recover_graph_counted(program, sections, functions, entry, pe_ranges).map(|(view, _)| view)
}

fn recover_graph_counted(
    program: &Program,
    sections: &[SectionInfo],
    functions: &[FunctionInfo],
    entry: u64,
    pe_ranges: &[(u64, u64)],
) -> Result<(FunctionView, usize), String> {
    let mut remaining = MAX_INSTRUCTIONS;
    let recovered = recover_graph_budgeted(
        program,
        sections,
        functions,
        entry,
        pe_ranges,
        &mut remaining,
        None,
    )?;
    Ok((recovered.view, MAX_INSTRUCTIONS - remaining))
}

struct GraphRecovery {
    view: FunctionView,
    calls: Vec<(CallSite, u64)>,
    partial: bool,
}

fn recover_graph_budgeted(
    program: &Program,
    sections: &[SectionInfo],
    functions: &[FunctionInfo],
    entry: u64,
    pe_ranges: &[(u64, u64)],
    remaining: &mut usize,
    mut data: Option<&mut crate::data_analysis::DataCollector<'_>>,
) -> Result<GraphRecovery, String> {
    let alignment = crate::architecture::instruction_alignment(program.language_id());
    if !entry.is_multiple_of(alignment) {
        return Err(format!(
            "Instructions require {alignment}-byte aligned addresses."
        ));
    }
    if !executable(sections, entry, alignment as usize) {
        return Err(format!(
            "{entry:#x} is outside file-backed executable sections."
        ));
    }
    let other_entries: BTreeSet<_> = functions
        .iter()
        .map(|f| f.address)
        .filter(|a| *a != entry)
        .collect();
    let mut pending = VecDeque::from([entry]);
    let mut visited = BTreeSet::new();
    let mut nodes = BTreeMap::<u64, Decoded>::new();
    let mut leaders = BTreeSet::from([entry]);
    let mut warnings = Vec::new();
    let mut calls = Vec::new();
    let mut call_evidence = Vec::new();
    while let Some(address) = pending.pop_front() {
        if !visited.insert(address) {
            continue;
        }
        if *remaining == 0 {
            warning(
                &mut warnings,
                "Instruction work budget reached; recovery is incomplete.",
            );
            break;
        }
        if !address.is_multiple_of(alignment) || !executable(sections, address, alignment as usize)
        {
            warning(
                &mut warnings,
                "A control-flow target leaves the supported executable regions.",
            );
            continue;
        }
        if other_entries.contains(&address)
            || (address != entry
                && pe_ranges
                    .binary_search_by_key(&address, |range| range.0)
                    .is_ok())
        {
            warning(
                &mut warnings,
                "A path reaches another known function entry or PE runtime-region start; displayed as an external/tail exit.",
            );
            continue;
        }
        if let Some((&start, node)) = nodes.range(..=address).next_back()
            && start < address
            && address - start < node.instruction.bytes.len() as u64
        {
            warning(
                &mut warnings,
                "Overlapping instructions encountered; ambiguous targets were not followed.",
            );
            continue;
        }
        // Charge failures as well as successful decodes; shared discovery work
        // must never grow past its budget when hostile bytes fail to decode.
        *remaining -= 1;
        let instruction = match program.disassemble(address, 1).map_err(engine_error) {
            Ok(mut instructions) if !instructions.is_empty() => instructions.remove(0),
            Ok(_) => {
                warning(
                    &mut warnings,
                    format!("No instruction decoded at {address:#x}."),
                );
                continue;
            }
            Err(error) => {
                warning(
                    &mut warnings,
                    format!("Cannot decode {address:#x}: {error}"),
                );
                continue;
            }
        };
        if instruction.address != address
            || instruction.length == 0
            || (alignment == 4 && instruction.length != 4)
            || !executable(sections, address, instruction.length)
        {
            warning(
                &mut warnings,
                "An instruction crosses the boundary of an executable region.",
            );
            continue;
        }
        let next_address = address
            .checked_add(instruction.length as u64)
            .ok_or("Instruction address overflow")?;
        if nodes.range(address + 1..next_address).next().is_some() {
            warning(
                &mut warnings,
                "Overlapping instructions encountered; ambiguous instructions were not followed.",
            );
            continue;
        }
        let pcode = match program.pcode(address, 1).map_err(engine_error) {
            Ok(mut code) if !code.is_empty() => code.remove(0),
            Ok(_) => {
                warning(&mut warnings, format!("Missing p-code at {address:#x}."));
                continue;
            }
            Err(error) => {
                warning(
                    &mut warnings,
                    format!("Cannot recover flow at {address:#x}: {error}"),
                );
                continue;
            }
        };
        if pcode.address != address || pcode.length != instruction.length {
            warning(
                &mut warnings,
                format!("Instruction/p-code length mismatch at {address:#x}."),
            );
            continue;
        }
        if let Some(data) = data.as_mut() {
            data.inspect(entry, &pcode);
        }
        let call_start = calls.len();
        let (next, terminal) = flow(&pcode, next_address, &mut calls, &mut warnings);
        call_evidence.extend(
            calls[call_start..]
                .iter()
                .cloned()
                .map(|call| (call, next_address)),
        );
        for (target, _) in &next {
            if let Some(target) = target {
                if terminal {
                    leaders.insert(*target);
                }
                pending.push_back(*target);
            }
        }
        nodes.insert(
            address,
            Decoded {
                instruction: Instruction {
                    address,
                    bytes: instruction.bytes,
                    mnemonic: instruction.mnemonic,
                    operands: instruction.operands,
                },
                next,
                terminal,
            },
        );
    }
    if nodes.is_empty() {
        return Err("No instructions could be recovered at the selected address.".into());
    }
    // A merge also begins a block, including fallthrough merges into a backward target.
    let mut predecessors = BTreeMap::<u64, usize>::new();
    for node in nodes.values() {
        for (target, _) in &node.next {
            if let Some(target) = target {
                *predecessors.entry(*target).or_default() += 1;
            }
        }
    }
    leaders.extend(
        predecessors
            .into_iter()
            .filter_map(|(address, count)| (count > 1).then_some(address)),
    );
    let mut blocks = Vec::new();
    let mut edges = Vec::new();
    let mut assigned = BTreeSet::new();
    for start in leaders.iter().copied().filter(|a| nodes.contains_key(a)) {
        if assigned.contains(&start) {
            continue;
        }
        if blocks.len() >= MAX_BLOCKS {
            warning(
                &mut warnings,
                "Graph limited to 128 basic blocks; recovery is incomplete.",
            );
            break;
        }
        let mut block = BasicBlock {
            address: start,
            instructions: Vec::new(),
        };
        let mut current = start;
        while let Some(node) = nodes.get(&current) {
            if !assigned.insert(current) {
                break;
            }
            block.instructions.push(node.instruction.clone());
            if !node.terminal
                && node.next.len() == 1
                && let Some(next) = node.next[0].0
                && nodes.contains_key(&next)
                && !leaders.contains(&next)
                && !assigned.contains(&next)
            {
                current = next;
                continue;
            }
            for (target, kind) in &node.next {
                edges.push(Edge {
                    source: start,
                    target: *target,
                    kind: *kind,
                });
            }
            break;
        }
        blocks.push(block);
    }
    if assigned.len() < nodes.len() {
        warning(
            &mut warnings,
            "Some recovered instructions are omitted by graph limits or ambiguous block boundaries.",
        );
    }
    let partial = !warnings.is_empty();
    warning(
        &mut warnings,
        "CFG uses bounded static instruction flow; indirect jump tables, exceptions, and no-return calls may be incomplete.",
    );
    Ok(GraphRecovery {
        view: FunctionView {
            address: entry,
            blocks,
            edges,
            calls,
            warnings,
        },
        calls: call_evidence,
        partial,
    })
}

fn flow(
    code: &InstructionPcode,
    fallthrough: u64,
    calls: &mut Vec<CallSite>,
    warnings: &mut Vec<String>,
) -> (Vec<(Option<u64>, EdgeKind)>, bool) {
    let mut transfer = None;
    let mut internal = false;
    let call_start = calls.len();
    for operation in &code.operations {
        let direct = operation
            .inputs
            .first()
            .filter(|v| v.space == "ram")
            .map(|v| v.offset);
        match operation.opcode {
            OpCode::Call | OpCode::Callind => {
                if calls.len() >= MAX_INSTRUCTIONS {
                    warning(
                        warnings,
                        "Call-site budget reached; recovery is incomplete.",
                    );
                    continue;
                }
                calls.push(CallSite {
                    address: code.address,
                    target: if operation.opcode == OpCode::Call {
                        direct
                    } else {
                        None
                    },
                });
            }
            OpCode::Branch | OpCode::Cbranch => {
                if operation.inputs.first().is_some_and(|v| v.space == "const") {
                    internal = true;
                } else {
                    let edges = if operation.opcode == OpCode::Cbranch {
                        vec![
                            (direct, EdgeKind::True),
                            (Some(fallthrough), EdgeKind::False),
                        ]
                    } else {
                        vec![(
                            direct,
                            if direct.is_some() {
                                EdgeKind::Branch
                            } else {
                                EdgeKind::Unknown
                            },
                        )]
                    };
                    if transfer.replace(edges).is_some() {
                        internal = true;
                    }
                }
            }
            OpCode::Branchind => {
                transfer = Some(vec![(None, EdgeKind::Unknown)]);
                warning(warnings, "An indirect jump has unresolved targets.");
            }
            OpCode::Return => {
                transfer = Some(Vec::new());
            }
            _ => {}
        }
    }
    if internal || calls.len() > call_start + 1 {
        calls.truncate(call_start);
        warning(
            warnings,
            format!(
                "Instruction {:#x} contains internal p-code branches; machine-level successors were left unknown.",
                code.address
            ),
        );
        (vec![(None, EdgeKind::Unknown)], true)
    } else if let Some(edges) = transfer {
        (edges, true)
    } else {
        (vec![(Some(fallthrough), EdgeKind::Branch)], false)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn raw_aarch64(bytes: Vec<u8>) -> LoadedProgram {
        let mut image = elf_fixture();
        image[18..20].copy_from_slice(&183u16.to_le_bytes());
        let (mut info, target) = metadata_with_target(Path::new("synthetic"), &image).unwrap();
        info.entry = 0x1000;
        info.sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        LoadedProgram {
            program: Program::from_raw_bytes(bytes.clone(), target.language, 0x1000).unwrap(),
            target,
            snapshot: Arc::from(bytes),
            info,
            pe_ranges: vec![],
            pe_imports: BTreeMap::new(),
            upx_packed: false,
        }
    }

    fn raw_x86(bytes: Vec<u8>) -> LoadedProgram {
        let mut loaded = raw_aarch64(bytes.clone());
        loaded.target = crate::architecture::Target {
            name: "x86-64",
            language: "x86:LE:64:default:gcc",
            pointer_bytes: 8,
            instruction_alignment: 1,
        };
        loaded.info.architecture = "x86-64".into();
        loaded.program = Program::from_raw_bytes(bytes, loaded.target.language, 0x1000).unwrap();
        loaded
    }

    fn discover(loaded: &mut LoadedProgram) -> (Vec<FunctionInfo>, CallAnalysis) {
        let Response::Functions {
            functions,
            analysis,
            ..
        } = loaded.handle(Request::Discover).unwrap()
        else {
            panic!("Expected discovery")
        };
        analysis.validate(&loaded.info, &functions).unwrap();
        (functions, analysis)
    }

    #[test]
    fn confirmed_calls_discover_with_symbols_preserve_names_and_stop_cycles() {
        let mut bytes = vec![0xcc; 0x50];
        bytes[..16].copy_from_slice(&[
            0xe8, 0x1b, 0, 0, 0, // call 1020
            0xe8, 0x16, 0, 0, 0, // call 1020 from another site
            0xb8, 0x40, 0x10, 0, 0, // numeric value 1040 is not a function seed
            0xc3,
        ]);
        bytes[0x20..0x26].copy_from_slice(&[0xe8, 0xdb, 0xff, 0xff, 0xff, 0xc3]); // call root; ret
        bytes[0x40] = 0xc3;
        let mut loaded = raw_x86(bytes);
        loaded
            .program
            .set_function_name(0x1000, "root_name")
            .unwrap();
        loaded.info.functions = function_list(&loaded.program, &mut loaded.info).unwrap();
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].name, "root_name");
        assert_eq!(functions[1].address, 0x1020);
        assert_eq!(report.functions_examined, 2);
        assert_eq!(
            report.references,
            vec![
                CallReference {
                    caller: 0x1000,
                    address: 0x1000,
                    target: 0x1020
                },
                CallReference {
                    caller: 0x1000,
                    address: 0x1005,
                    target: 0x1020
                },
                CallReference {
                    caller: 0x1020,
                    address: 0x1020,
                    target: 0x1000
                },
            ]
        );
        let (_, repeated) = discover(&mut loaded);
        assert_eq!(repeated.references, report.references);
    }

    #[test]
    fn calls_to_fallthrough_do_not_split_functions_and_indirect_calls_stay_unknown() {
        let mut loaded = raw_x86(vec![0xe8, 0, 0, 0, 0, 0x58, 0xff, 0xd0, 0xc3]);
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0].address, 0x1000);
        assert!(report.references.is_empty());
        // The x86 SLEIGH language emits a branch for call-to-next-PC already.
        assert_eq!(report.skipped_fallthrough_calls, 0);
        assert_eq!(report.unresolved_calls, 1);
        assert!(report.partial);
    }

    #[test]
    fn failed_decode_is_charged_and_does_not_create_a_function() {
        let mut bytes = vec![0xcc; 0x21];
        bytes[..6].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 1020; ret
        bytes[0x20] = 0xe8; // Truncated call at the actual target.
        let mut loaded = raw_x86(bytes);
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 1);
        assert!(
            loaded
                .program
                .functions()
                .unwrap()
                .iter()
                .all(|f| f.address != 0x1020)
        );
        assert_eq!(report.decode_attempts, 3);
        assert_eq!(report.failed_functions, 1);
        assert!(report.partial);
    }

    #[test]
    fn aarch64_call_to_fallthrough_is_not_a_function_candidate() {
        let mut bytes = 0x94000001u32.to_le_bytes().to_vec(); // BL next PC
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
        let mut loaded = raw_aarch64(bytes);
        let (functions, report) = discover(&mut loaded);
        assert_eq!(functions.len(), 1);
        assert!(report.references.is_empty());
        assert_eq!(report.skipped_fallthrough_calls, 1);
    }

    #[test]
    fn discovery_has_an_exact_shared_decode_budget_and_monotonic_progress() {
        let stride = MAX_INSTRUCTIONS + 1;
        let mut bytes = vec![0x90; stride * 9];
        for function in 0..9 {
            bytes[(function + 1) * stride - 1] = 0xc3;
        }
        let mut loaded = raw_x86(bytes);
        for function in 0..9 {
            loaded
                .program
                .set_function_name(
                    0x1000 + (function * stride) as u64,
                    &format!("seed_{function}"),
                )
                .unwrap();
        }
        loaded.info.functions = function_list(&loaded.program, &mut loaded.info).unwrap();
        let mut events: Vec<AnalysisProgress> = Vec::new();
        let Response::Functions { analysis, .. } = loaded
            .handle_with_progress(Request::Discover, &mut |event| {
                event.validate_after(events.last()).unwrap();
                events.push(event);
                Ok(())
            })
            .unwrap()
        else {
            panic!("Expected discovery")
        };
        assert_eq!(analysis.decode_attempts, MAX_ANALYSIS_INSTRUCTIONS);
        assert_eq!(analysis.functions_examined, 8);
        assert!(analysis.partial);
        assert_eq!(events.first().unwrap().stage, AnalysisStage::Seeds);
        assert_eq!(events.last().unwrap().stage, AnalysisStage::Publish);
        assert!(events.len() <= MAX_ANALYSIS_FUNCTIONS + 3);
    }

    #[test]
    fn packed_image_rejects_expensive_analysis_without_poisoning_other_requests() {
        let mut loaded = raw_aarch64(0xd65f03c0u32.to_le_bytes().to_vec());
        // Simulate the already validated packed-image flag with a tiny safe
        // engine fixture; no real packed application or decompression is run.
        loaded.upx_packed = true;
        assert!(
            loaded
                .handle_with_progress(Request::Discover, &mut |_| panic!(
                    "Packed input must be rejected before progress/work"
                ))
                .is_err()
        );
        for request in [Request::Decompile { address: 0x1000 }, Request::Discover] {
            assert_eq!(
                loaded.handle(request).unwrap_err(),
                crate::packing::UPX_ANALYSIS_ERROR
            );
        }
        assert!(matches!(
            loaded.handle(Request::Graph { address: 0x1000 }),
            Ok(Response::Graph { .. })
        ));
        assert!(matches!(
            loaded.handle(Request::Strings),
            Ok(Response::Strings { .. })
        ));
        let Response::Bytes { bytes, .. } = loaded
            .handle(Request::Bytes {
                address: 0x1000,
                length: 4,
            })
            .unwrap()
        else {
            panic!("Packed-image guard must leave byte inspection usable");
        };
        assert_eq!(bytes, 0xd65f03c0u32.to_le_bytes());
    }

    #[test]
    fn aarch64_discovery_counts_decoded_instructions_omitted_by_block_limit() {
        // Each unconditional B starts a block. Decode 256 instructions but retain
        // only 128 blocks; discovery must charge all decoded instructions.
        let mut bytes = 0x14000001u32.to_le_bytes().repeat(255);
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
        let mut loaded = raw_aarch64(bytes);
        let (view, count) =
            recover_graph_counted(&loaded.program, &loaded.info.sections, &[], 0x1000, &[])
                .unwrap();
        assert_eq!(count, 256);
        assert_eq!(view.blocks.len(), MAX_BLOCKS);
        assert_eq!(
            view.blocks
                .iter()
                .map(|block| block.instructions.len())
                .sum::<usize>(),
            128
        );
        let Response::Functions { truncated, .. } = loaded.handle(Request::Discover).unwrap()
        else {
            panic!("Expected function list");
        };
        assert!(
            truncated,
            "Graph truncation must be visible during discovery"
        );
    }

    #[test]
    fn call_evidence_survives_display_block_limits() {
        let mut bytes = 0x14000001u32.to_le_bytes().repeat(140);
        bytes.extend_from_slice(&0x94000002u32.to_le_bytes()); // BL helper, after the display cutoff
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes());
        bytes.extend_from_slice(&0xd65f03c0u32.to_le_bytes()); // helper
        let mut loaded = raw_aarch64(bytes);
        let (_, report) = discover(&mut loaded);
        assert_eq!(
            report.references,
            vec![CallReference {
                caller: 0x1000,
                address: 0x1000 + 140 * 4,
                target: 0x1000 + 142 * 4
            }]
        );
        assert!(report.partial);
        assert!(report.decode_attempts > 128);
    }

    #[test]
    fn aarch64_discovery_reports_unvisited_seeds_without_losing_known_names() {
        let mut loaded = raw_aarch64(0xd65f03c0u32.to_le_bytes().repeat(130));
        for index in 0..130 {
            loaded
                .program
                .set_function_name(0x1000 + index * 4, &format!("original_{index}"))
                .unwrap();
        }
        loaded.info.functions = function_list(&loaded.program, &mut loaded.info).unwrap();
        let Response::Functions {
            functions,
            truncated,
            ..
        } = loaded.handle(Request::Discover).unwrap()
        else {
            panic!("Expected function list");
        };
        assert!(
            truncated,
            "Omitted seeds must not report complete discovery"
        );
        assert_eq!(functions.len(), 130);
        assert!(functions.iter().any(|f| f.name == "original_129"));
    }

    pub(crate) fn elf_fixture() -> Vec<u8> {
        fn put16(bytes: &mut [u8], offset: usize, value: u16) {
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn put32(bytes: &mut [u8], offset: usize, value: u32) {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        fn put64(bytes: &mut [u8], offset: usize, value: u64) {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut bytes = vec![0; 0x380];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 2);
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 24, 0x401000);
        put64(&mut bytes, 32, 64);
        put64(&mut bytes, 40, 0x280);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 54, 56);
        put16(&mut bytes, 56, 2);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, 4);
        put16(&mut bytes, 62, 3);
        let text = [
            0x85, 0xc0, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ];
        let data = b"fixture ASCII\0\0W\0i\0d\0e\0\0\0expand 32-byte k\0";
        let names = b"\0.text\0.rodata\0.shstrtab\0";
        bytes[0x100..0x100 + text.len()].copy_from_slice(&text);
        bytes[0x200..0x200 + data.len()].copy_from_slice(data);
        bytes[0x240..0x240 + names.len()].copy_from_slice(names);
        for (slot, offset, address, size, flags) in [
            (0, 0x100, 0x401000, text.len(), 5),
            (1, 0x200, 0x402000, data.len(), 4),
        ] {
            let header = 64 + slot * 56;
            put32(&mut bytes, header, 1);
            put32(&mut bytes, header + 4, flags);
            put64(&mut bytes, header + 8, offset);
            put64(&mut bytes, header + 16, address);
            put64(&mut bytes, header + 24, address);
            put64(&mut bytes, header + 32, size as u64);
            put64(&mut bytes, header + 40, size as u64);
            put64(&mut bytes, header + 48, 0x100);
        }
        for (slot, name, address, offset, size, flags) in [
            (1, 1, 0x401000, 0x100, text.len(), 6),
            (2, 7, 0x402000, 0x200, data.len(), 2),
            (3, 15, 0, 0x240, names.len(), 0),
        ] {
            let header = 0x280 + slot * 64;
            put32(&mut bytes, header, name);
            put32(&mut bytes, header + 4, if slot == 3 { 3 } else { 1 });
            put64(&mut bytes, header + 8, flags);
            put64(&mut bytes, header + 16, address);
            put64(&mut bytes, header + 24, offset);
            put64(&mut bytes, header + 32, size as u64);
            put64(&mut bytes, header + 48, 1);
        }
        bytes
    }

    fn graph(bytes: &[u8]) -> FunctionView {
        let program =
            Program::from_raw_bytes(bytes.to_vec(), "x86:LE:64:default:gcc", 0x1000).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        recover_graph(&program, &sections, &[], 0x1000).unwrap()
    }

    #[test]
    fn conditional_branch_forms_three_blocks() {
        // test eax,eax; je taken; mov eax,1; ret; taken: xor eax,eax; ret
        let view = graph(&[
            0x85, 0xc0, 0x74, 0x06, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ]);
        assert_eq!(view.blocks.len(), 3);
        assert!(
            view.edges.iter().any(|e| e.source == 0x1000
                && e.target == Some(0x100a)
                && e.kind == EdgeKind::True)
        );
        assert!(
            view.edges.iter().any(|e| e.source == 0x1000
                && e.target == Some(0x1004)
                && e.kind == EdgeKind::False)
        );
    }

    #[test]
    fn graph_honors_function_entries_outside_the_displayed_inventory() {
        // jmp 0x1005; mov eax,1; ret. The jump is a known function's tail entry,
        // retained in PE ranges even when that function is outside the UI page.
        let bytes = vec![0xe9, 0, 0, 0, 0, 0xb8, 1, 0, 0, 0, 0xc3];
        let program =
            Program::from_raw_bytes(bytes.clone(), "x86:LE:64:default:windows", 0x1000).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: bytes.len() as u64,
            file_offset: 0,
            file_size: bytes.len() as u64,
            executable: true,
        }];
        let view = recover_graph_with_ranges(&program, &sections, &[], 0x1000, &[(0x1005, 0x100b)])
            .unwrap();
        assert_eq!(
            view.blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .count(),
            1
        );
        assert!(
            view.warnings
                .iter()
                .any(|warning| warning.contains("another known function entry"))
        );
    }

    #[test]
    fn imports_resolve_through_confirmed_calls_in_a_tail_function() {
        let mut bytes = vec![0xcc; 0x100];
        bytes[..5].copy_from_slice(&[0xe9, 0x0b, 0, 0, 0]); // tail to 0x1010
        bytes[0x10..0x16].copy_from_slice(&[0xe8, 0x0b, 0, 0, 0, 0xc3]);
        bytes[0x20..0x26].copy_from_slice(&[0xff, 0x25, 0x5a, 0, 0, 0]);
        let mut program =
            Program::from_raw_bytes(bytes.clone(), "x86:LE:64:default:windows", 0x1000).unwrap();
        let mut symbols = crate::pe::PeMetadata::default();
        symbols.functions.insert(0x1000, "entry".into());
        symbols.functions.insert(0x1010, "tail".into());
        symbols.imports.insert(0x1080, "ExitProcess".into());
        crate::pe_symbols::register(&mut program, &symbols, 8).unwrap();
        let sections = vec![SectionInfo {
            name: ".text".into(),
            address: 0x1000,
            size: 0x100,
            file_offset: 0,
            file_size: 0x100,
            executable: true,
        }];
        let mut info = BinaryInfo {
            path: "synthetic".into(),
            architecture: "x86-64".into(),
            format: "PE".into(),
            entry: 0x1000,
            file_len: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            source_identity: None,
            sections,
            functions: vec![],
            functions_truncated: false,
            warnings: vec![],
        };
        info.functions = function_list(&program, &mut info).unwrap();
        let mut loaded = LoadedProgram {
            target: crate::architecture::Target::for_image(
                &object::File::parse(elf_fixture().as_slice()).unwrap(),
            )
            .unwrap(),
            program,
            snapshot: Arc::from(bytes),
            info,
            pe_ranges: vec![(0x1000, 0x1005), (0x1010, 0x1016)],
            pe_imports: symbols.imports,
            upx_packed: false,
        };
        loaded.resolve_import_thunks(0x1000).unwrap();
        assert!(
            loaded
                .program
                .functions()
                .unwrap()
                .iter()
                .any(|function| function.address == 0x1020 && function.name == "ExitProcess")
        );
        let Response::Decompiled { text, .. } = loaded
            .handle(Request::Decompile { address: 0x1010 })
            .unwrap()
        else {
            panic!("Expected decompiler result")
        };
        assert!(text.contains("ExitProcess"), "{text}");
    }

    #[test]
    fn backward_branch_splits_a_loop_without_redecoding() {
        // xor ecx,ecx; loop: inc ecx; cmp ecx,3; jne loop; ret
        let view = graph(&[0x31, 0xc9, 0xff, 0xc1, 0x83, 0xf9, 3, 0x75, 0xf9, 0xc3]);
        assert_eq!(view.blocks.len(), 3);
        assert!(
            view.edges.iter().any(|e| e.source == 0x1002
                && e.target == Some(0x1002)
                && e.kind == EdgeKind::True)
        );
        assert_eq!(
            view.blocks
                .iter()
                .map(|b| b.instructions.len())
                .sum::<usize>(),
            5
        );
    }

    #[test]
    fn call_is_a_call_site_and_indirect_jump_is_unknown() {
        // call 0x100a; jmp rax; padding; ret
        let view = graph(&[0xe8, 5, 0, 0, 0, 0xff, 0xe0, 0x90, 0x90, 0x90, 0xc3]);
        assert_eq!(view.calls.len(), 1);
        assert_eq!(view.calls[0].target, Some(0x100a));
        assert_eq!(view.blocks.len(), 1);
        assert!(
            view.edges
                .iter()
                .any(|e| e.target.is_none() && e.kind == EdgeKind::Unknown)
        );
        assert!(!view.edges.iter().any(|e| e.target == Some(0x100a)));
    }

    #[test]
    fn internal_pcode_branches_do_not_become_machine_addresses() {
        use ghidra_decompiler::program::{PcodeOperation, PcodeVarnode};
        let code = InstructionPcode {
            address: 0x1000,
            length: 2,
            operations: vec![PcodeOperation {
                opcode: OpCode::Cbranch,
                output: None,
                inputs: vec![PcodeVarnode {
                    space: "const".into(),
                    offset: 3,
                    size: 8,
                }],
                space: None,
            }],
        };
        let mut calls = Vec::new();
        let mut warnings = Vec::new();
        let (edges, terminal) = flow(&code, 0x1002, &mut calls, &mut warnings);
        assert!(terminal);
        assert_eq!(edges, vec![(None, EdgeKind::Unknown)]);
        assert!(warnings[0].contains("internal p-code branches"));
    }

    #[test]
    fn mapped_reads_zero_fill_tails_and_refuse_gaps() {
        let snapshot = [1, 2, 3, 4];
        let sections = [SectionInfo {
            name: "data".into(),
            address: 0x4000,
            size: 6,
            file_offset: 0,
            file_size: 4,
            executable: false,
        }];
        assert_eq!(
            read_virtual(&snapshot, &sections, 0x4002, 4).unwrap(),
            [3, 4, 0, 0]
        );
        assert!(
            read_virtual(&snapshot, &sections, 0x4002, 5)
                .unwrap_err()
                .contains("gap")
        );
        assert!(read_virtual(&snapshot, &sections, 0x4000, MAX_BYTES + 1).is_err());
    }

    #[test]
    fn rejects_non_executable_input() {
        assert!(metadata(Path::new("bad"), b"not an executable").is_err());
    }

    #[test]
    fn elf_metadata_uses_virtual_addresses_and_rejects_other_architectures() {
        let mut bytes = elf_fixture();
        let info = metadata(Path::new("fixture.elf"), &bytes).unwrap();
        assert_eq!(info.entry, 0x401000);
        assert_eq!(info.sections.len(), 2);
        assert_eq!(info.sections[0].file_offset, 0x100);
        assert_eq!(info.sections[1].address, 0x402000);
        assert_eq!(info.sha256.len(), 64);
        bytes[18..20].copy_from_slice(&243u16.to_le_bytes());
        assert!(
            metadata(Path::new("fixture.elf"), &bytes)
                .unwrap_err()
                .contains("Unsupported architecture")
        );
    }

    #[test]
    fn real_elf_snapshot_survives_original_mutation_for_all_analysis() {
        let path = std::env::temp_dir().join(format!("ghidra-rust-elf-{}", std::process::id()));
        std::fs::write(&path, elf_fixture()).unwrap();
        let mut loaded = LoadedProgram::open(path.to_str().unwrap()).unwrap();
        let expected_hash = format!("{:x}", Sha256::digest(elf_fixture()));
        assert_eq!(loaded.info.sha256, expected_hash);
        // Engine instructions, auxiliary bytes, strings, and crypto must all use
        // the originally hashed image even if the original file is overwritten.
        std::fs::write(&path, b"The original file no longer contains an ELF image.").unwrap();
        assert_eq!(loaded.info.functions[0].address, 0x401000);
        let Response::Graph { view } = loaded.handle(Request::Graph { address: 0x401000 }).unwrap()
        else {
            panic!("Expected graph");
        };
        assert_eq!(view.blocks.len(), 3);
        let Response::Strings { strings, truncated } = loaded.handle(Request::Strings).unwrap()
        else {
            panic!("Expected strings");
        };
        assert!(!truncated);
        assert!(
            strings.iter().any(|s| s.address == 0x402000
                && s.text == "fixture ASCII"
                && s.encoding == "ASCII")
        );
        assert!(
            strings
                .iter()
                .any(|s| s.address == 0x40200f && s.text == "Wide" && s.encoding == "UTF-16LE")
        );
        let Response::Bytes { bytes, .. } = loaded
            .handle(Request::Bytes {
                address: 0x402000,
                length: 7,
            })
            .unwrap()
        else {
            panic!("Expected bytes");
        };
        assert_eq!(&bytes, b"fixture");
        let Response::Crypto { matches, truncated } = loaded.handle(Request::Crypto).unwrap()
        else {
            panic!("Expected crypto matches");
        };
        assert!(!truncated);
        assert!(
            matches
                .iter()
                .any(|hit| hit.algorithm.starts_with("ChaCha / Salsa"))
        );
        let expected_text = loaded.program.decompile(0x401000).unwrap();
        let Response::Decompiled { text, mappings, .. } = loaded
            .handle(Request::Decompile { address: 0x401000 })
            .unwrap()
        else {
            panic!("Expected decompilation");
        };
        assert!(!text.is_empty());
        assert_eq!(
            text, expected_text,
            "Semantic collection must preserve the engine's C output"
        );
        assert!(
            !mappings.is_empty(),
            "Real engine p-code must produce machine locations"
        );
        assert!(mappings.windows(2).all(|pair| pair[0].end <= pair[1].start));
        let machine_addresses: BTreeSet<_> = view
            .blocks
            .iter()
            .flat_map(|block| {
                block
                    .instructions
                    .iter()
                    .map(|instruction| instruction.address)
            })
            .collect();
        for mapping in &mappings {
            assert!(mapping.start < mapping.end && mapping.end <= text.len());
            assert!(text.is_char_boundary(mapping.start) && text.is_char_boundary(mapping.end));
            assert!(
                mapping
                    .addresses
                    .iter()
                    .all(|address| machine_addresses.contains(address))
            );
        }
        loaded
            .handle(Request::Rename {
                address: 0x401000,
                name: "fixture_entry".into(),
            })
            .unwrap();
        assert!(
            loaded
                .info
                .functions
                .iter()
                .any(|f| f.name == "fixture_entry")
        );
        let Response::Decompiled { text, .. } = loaded
            .handle(Request::Decompile { address: 0x401000 })
            .unwrap()
        else {
            panic!("Expected decompilation after rename");
        };
        assert!(
            text.contains("fixture_entry"),
            "Materialized function name must follow symbol rename: {text}"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn function_names_are_capped_at_utf8_boundaries() {
        let name = "界".repeat(200);
        let bounded = bounded_name(&name);
        assert!(bounded.len() <= 256);
        assert_eq!(bounded.chars().count(), 85);
    }

    #[test]
    fn refuses_oversized_image_before_reading() {
        let path = std::env::temp_dir().join(format!("ghidra-rust-large-{}", std::process::id()));
        File::create(&path)
            .unwrap()
            .set_len(MAX_IMAGE_BYTES + 1)
            .unwrap();
        let error = LoadedProgram::open(path.to_str().unwrap()).err().unwrap();
        assert!(error.contains("128 MiB"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn string_minimum_filters_noise_before_the_result_budget() {
        let mut bytes = b"abcd\0".repeat(MAX_STRING_RESULTS + 100);
        let target_offset = bytes.len();
        bytes.extend_from_slice(b"meaningful string\0");
        let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap() else {
            panic!("Expected string results");
        };
        assert!(!truncated);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].address, 0x1000 + target_offset as u64);
        assert_eq!(strings[0].text, "meaningful string");

        let Response::Strings { strings, truncated } =
            scan_test_strings(&bytes, MIN_STRING_LENGTH).unwrap()
        else {
            panic!("Expected legacy string results");
        };
        assert!(truncated);
        assert_eq!(strings.len(), MAX_STRING_RESULTS);
    }

    #[test]
    fn string_limit_requires_an_additional_matching_result() {
        let mut bytes = b"token6\0".repeat(MAX_STRING_RESULTS);
        bytes.extend_from_slice(b"abcd\0");
        let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap() else {
            panic!("Expected string results");
        };
        assert_eq!(strings.len(), MAX_STRING_RESULTS);
        assert!(!truncated, "Exactly the result limit is still complete");

        bytes.extend_from_slice(b"one more match");
        let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap() else {
            panic!("Expected string results after section-final flush");
        };
        assert_eq!(strings.len(), MAX_STRING_RESULTS);
        assert!(truncated);
    }

    #[test]
    fn string_minimum_preserves_ascii_and_unaligned_wide_chunk_boundaries() {
        for wide in [false, true] {
            let start = SCAN_CHUNK - 3;
            let mut bytes = vec![0; start];
            for &byte in b"boundary string" {
                bytes.push(byte);
                if wide {
                    bytes.push(0);
                }
            }
            // Flush on the section boundary, including the odd UTF-16 parity.
            let Response::Strings { strings, truncated } = scan_test_strings(&bytes, 6).unwrap()
            else {
                panic!("Expected string results");
            };
            assert!(!truncated);
            assert_eq!(strings.len(), 1);
            assert_eq!(strings[0].address, 0x1000 + start as u64);
            assert_eq!(strings[0].text, "boundary string");
            assert_eq!(strings[0].encoding, if wide { "UTF-16LE" } else { "ASCII" });
        }
    }

    #[test]
    fn string_minimum_is_bounded_and_legacy_protocol_remains_accepted() {
        for invalid in [0, MIN_STRING_LENGTH - 1, MAX_STRING_MINIMUM + 1, usize::MAX] {
            assert!(scan_test_strings(b"valid string", invalid).is_err());
        }
        assert!(scan_test_strings(b"valid string", MIN_STRING_LENGTH).is_ok());
        assert!(scan_test_strings(b"valid string", MAX_STRING_MINIMUM).is_ok());
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"kind":"strings"}"#).unwrap(),
            Request::Strings
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(
                r#"{"kind":"strings_with_options","minimum_length":6}"#
            )
            .unwrap(),
            Request::StringsWithOptions { minimum_length: 6 }
        ));
    }

    fn scan_test_strings(bytes: &[u8], minimum_length: usize) -> Result<Response, String> {
        scan_strings(
            bytes,
            &[SectionInfo {
                name: "test strings".into(),
                address: 0x1000,
                size: bytes.len() as u64,
                file_offset: 0,
                file_size: bytes.len() as u64,
                executable: false,
            }],
            minimum_length,
        )
    }

    #[test]
    fn long_string_preview_is_bounded() {
        let mut run = StringRun::default();
        let mut strings = Vec::new();
        for offset in 0..5000 {
            run.feed(Some('a'), 0x1000 + offset, "ASCII", &mut strings);
        }
        run.flush("ASCII", &mut strings);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].address, 0x1000);
        assert!(strings[0].text.len() <= MAX_STRING_PREVIEW + 3);
        assert!(strings[0].text.ends_with('…'));
    }
}
