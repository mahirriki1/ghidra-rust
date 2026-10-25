//! Bounded, synchronous analysis. This module runs in the disposable worker process.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
#[cfg(test)]
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use ghidra_decompiler::address::Address;
use ghidra_decompiler::program::Program;
use object::{Object, ObjectSection, SectionFlags, SectionKind};
use sha2::{Digest, Sha256};

use crate::model::*;

mod cfg;
mod function_candidates;
mod patterns;
mod pointers;
mod strings;

use cfg::*;
use strings::*;

const MAX_INSTRUCTIONS: usize = 2048;
const MAX_BLOCKS: usize = 128;
const MAX_BYTES: usize = MAX_BYTE_READ;
const MAX_SCAN_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CRYPTO_RESULTS: usize = 10_000;
const SCAN_CHUNK: usize = 256 * 1024;
const MAX_STRING_PREVIEW: usize = 512;
/// Largest executable the worker opens.
pub const MAX_IMAGE_BYTES: u64 = 128 * 1024 * 1024;

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
    inventory: crate::inventory::Inventory,
    /// Instructions decoded from established functions in this worker.
    coverage: Coverage,
    pointers: Option<pointers::PointerRecovery>,
    /// Calls that never return, from the image's own symbols and imports.
    no_return: Arc<crate::no_return::NoReturnIndex>,
    signatures: Vec<crate::signatures::FunctionSignature>,
    applied_signatures: BTreeSet<u64>,
    signature_state: Option<String>,
    analysis_started: bool,
}

/// Engine functions a discovery pass named, and whether it changed the engine
/// in ways it cannot enumerate.
struct Discovered {
    added: Vec<FunctionInfo>,
    opaque: bool,
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

/// Whether `address` is in the section's virtual extent, including any
/// zero-filled tail beyond its file-backed bytes.
fn mapped(section: &SectionInfo, address: u64) -> bool {
    address >= section.address && address - section.address < section.size
}

/// Whether `length` bytes (at least one) at `address` are file-backed code.
fn executable(sections: &[SectionInfo], address: u64, length: usize) -> bool {
    let length = (length as u64).max(1);
    sections
        .iter()
        .any(|section| section.executable && section.backs(address, length))
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
        path: path.to_string_lossy().into_owned(),
        architecture: target.name.into(),
        format: format.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
        source_identity: None,
        entry,
        file_len: bytes.len() as u64,
        sections,
        functions: Vec::new(),
        functions_truncated: false,
        warnings: Vec::new(),
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
        let reading = crate::performance::span("open_read");
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_IMAGE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("Cannot read executable: {e}"))?;
        if bytes.len() as u64 > MAX_IMAGE_BYTES {
            return Err("Executable grew beyond the 128 MiB prototype limit while reading.".into());
        }
        reading.finish(bytes.len() as u64);
        let metadata_time = crate::performance::span("open_metadata_hash");
        let (mut info, target) = metadata_with_target(path, &bytes)?;
        metadata_time.finish(0);
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
        let snapshot_time = crate::performance::span("open_snapshot_copy");
        let snapshot = Arc::from(bytes.as_slice());
        snapshot_time.finish(bytes.len() as u64);
        let pe_time = crate::performance::span("open_pe_parse");
        let pe = crate::pe::parse(&bytes, &info.sections)?;
        pe_time.finish(0);
        let engine_load = crate::performance::span("open_engine_image");
        let mut program =
            Program::from_image(&path.to_string_lossy(), bytes, Some(target.language))
                .map_err(engine_error)?;
        engine_load.finish(0);
        if program.language_id() != target.language {
            return Err(
                "Engine language does not match the validated binary architecture and ABI.".into(),
            );
        }
        let mut pe_ranges = Vec::new();
        let mut pe_imports = BTreeMap::new();
        if let Some(pe) = pe {
            let _registration = crate::performance::span("open_pe_register");
            crate::pe_symbols::register(&mut program, &pe, target.pointer_bytes)?;
            info.functions_truncated = pe.functions_truncated;
            for note in pe.warnings {
                warning(&mut info.warnings, note);
            }
            pe_ranges = pe.function_ranges;
            pe_imports = pe.imports;
        }
        let (functions, mut rejected) = select_functions(&program, &info, &BTreeSet::new())?;
        info.functions_truncated |= rejected;
        info.functions = functions;
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
            let functions;
            (functions, rejected) = select_functions(&program, &info, &BTreeSet::new())?;
            info.functions_truncated |= rejected;
            info.functions = functions;
        }
        if info.format == "ELF" && !info.functions_truncated {
            rejected |= recover_elf_main(&mut program, &mut info, &target, &snapshot)?;
        }
        let mut no_return = crate::no_return::NoReturnIndex::build(
            &program,
            &info.format,
            target.pointer_bytes as u32,
            &pe_imports,
            |address| crate::call_analysis::code_address(&info, address),
        );
        if info.format == "ELF" {
            no_return.add_startup_slots(
                crate::elf_startup::libc_start_slots(&snapshot, &info.architecture)
                    .into_iter()
                    .filter(|&slot| {
                        info.sections
                            .iter()
                            .any(|section| section.backs(slot, target.pointer_bytes as u64))
                    }),
            );
        }
        if no_return.incomplete || !crate::no_return::mark_engine(&mut program, &no_return) {
            warning(
                &mut info.warnings,
                "No-return recognition is incomplete; some calls that never return keep a fallthrough.",
            );
        }
        let mut inventory = crate::inventory::Inventory::default();
        inventory.certify(&info.functions, !rejected);
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
            inventory,
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::new(no_return),
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
        })
    }

    pub fn handle(&mut self, request: Request) -> Result<Response, String> {
        self.handle_with_progress(request, &mut |_| Ok(()))
    }

    fn decompile(
        &mut self,
        address: u64,
        renames: &[crate::semantic::LocalRename],
    ) -> Result<Response, String> {
        crate::semantic::validate_renames(renames, Some(address))?;
        self.check_unpacked()?;
        self.check_code(address)?;
        // Import resolution and the engine can name or create functions.
        self.inventory.take_certificate(&self.info.functions);
        let imports = crate::performance::span("decompile_import_resolution");
        self.resolve_import_thunks(address)?;
        imports.finish(0);
        let _rendering = crate::performance::span("decompile_render");
        let context = if self.signatures.is_empty() {
            String::new()
        } else {
            crate::signatures::state_digest(&self.signatures)
        };
        let owned = self.applied_signatures.contains(&address);
        let (mut text, mut mappings, mut semantics) = crate::decompile::render_with_context(
            &mut self.program,
            address,
            &self.info.sections,
            renames,
            &context,
            owned,
        )
        .map_err(engine_error)?;
        if text.len() > MAX_DECOMPILED_BYTES {
            let mut end = MAX_DECOMPILED_BYTES - 100;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            mappings.retain(|mapping| mapping.end <= end);
            semantics.tokens.retain(|token| token.end <= end);
            text.push_str(crate::decompile::TRUNCATION_TRAILER);
        }
        Ok(Response::Decompiled {
            address,
            text,
            mappings,
            semantics,
        })
    }

    /// The displayed CFG. Known functions of unpacked images also resolve
    /// switch tables; other addresses keep raw instruction flow.
    fn graph(&mut self, address: u64) -> Result<FunctionView, String> {
        let functions = &self.info.functions;
        if !functions.is_sorted_by_key(|function| function.address) {
            return Err("Function inventory is not ordered by address".into());
        }
        let mut remaining = MAX_INSTRUCTIONS;
        let is_function = |candidate| function_at(functions, candidate).is_some();
        let recovered = if self.upx_packed || !is_function(address) {
            recover_graph_budgeted(
                &self.program,
                &Bounds {
                    tail_entry: None,
                    sections: &self.info.sections,
                    is_function: &is_function,
                    pe_ranges: &self.pe_ranges,
                },
                address,
                &mut remaining,
                &self.no_return,
                None,
            )?
        } else {
            recover_graph_switched(
                &mut self.program,
                &Bounds {
                    tail_entry: None,
                    sections: &self.info.sections,
                    is_function: &is_function,
                    pe_ranges: &self.pe_ranges,
                },
                address,
                &mut remaining,
                &mut SwitchBudget::new(),
                &self.no_return,
                None,
            )?
        };
        Ok(recovered.view)
    }

    pub(crate) fn handle_with_progress(
        &mut self,
        request: Request,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<Response, String> {
        if matches!(
            request,
            Request::Graph { .. }
                | Request::Decompile { .. }
                | Request::DecompileWithLocals { .. }
                | Request::Discover
                | Request::DiscoverBatch { .. }
        ) {
            self.analysis_started = true;
        }
        match request {
            Request::Graph { address } => Ok(Response::Graph {
                view: self.graph(address)?,
            }),
            Request::Decompile { address } => self.decompile(address, &[]),
            Request::DecompileWithLocals { address, renames } => self.decompile(address, &renames),
            Request::Discover => {
                self.check_unpacked()?;
                // Selected-function analysis can materialize and name a callee
                // since the last published inventory. Preserve those names.
                self.rebuild_inventory(&BTreeSet::new())?;
                self.inventory.take_certificate(&self.info.functions);
                let (analysis, _, _) = self.discover_calls(None, progress)?;
                // Evidence owners must survive inventory admission so every
                // published reference has its caller in the same reply.
                let owners = analysis
                    .references
                    .iter()
                    .map(|reference| reference.caller)
                    .chain(
                        analysis
                            .data
                            .iter()
                            .flat_map(|data| data.references.iter().map(|r| r.function)),
                    )
                    .collect();
                self.rebuild_inventory(&owners)?;
                Ok(Response::Functions {
                    functions: self.info.functions.clone(),
                    truncated: self.info.functions_truncated || analysis.partial,
                    analysis,
                })
            }
            Request::DiscoverBatch {
                binding,
                inventory_base,
                seeds,
                patterns: Some(DiscoveryCursor::Pointers(cursor)),
            } => {
                self.check_unpacked()?;
                if !seeds.is_empty() {
                    return Err("A pointer scan has no seeds".into());
                }
                let empty = AnalysisProgress {
                    stage: AnalysisStage::Seeds,
                    functions_examined: 0,
                    decode_attempts: 0,
                };
                progress(empty.clone())?;
                let certificate = self.inventory.take_certificate(&self.info.functions);
                let (scan, discovered, admissions) = self.scan_pointers(cursor)?;
                self.update_batch_inventory(certificate, &BTreeSet::new(), discovered)?;
                let inventory = self
                    .inventory
                    .publish(inventory_base, &self.info.functions)?;
                progress(AnalysisProgress {
                    stage: AnalysisStage::Publish,
                    ..empty
                })?;
                Ok(Response::DiscoveryBatch {
                    batch: DiscoveryBatch {
                        binding,
                        inventory,
                        truncated: self.info.functions_truncated,
                        analysis: CallAnalysis::default(),
                        outcomes: Vec::new(),
                        patterns: None,
                        pointers: Some(Box::new(scan)),
                        admissions,
                        recovery_records: 0,
                    },
                })
            }
            Request::DiscoverBatch {
                binding,
                inventory_base,
                seeds,
                patterns: Some(crate::model::DiscoveryCursor::Patterns(cursor)),
            } => {
                self.check_unpacked()?;
                if !seeds.is_empty() {
                    return Err("A pattern-scan batch has no seeds".into());
                }
                // Same progress protocol as seed batches: the scan reports no
                // examined functions or call-analysis decode work.
                let empty = AnalysisProgress {
                    stage: AnalysisStage::Seeds,
                    functions_examined: 0,
                    decode_attempts: 0,
                };
                progress(empty.clone())?;
                let certificate = self.inventory.take_certificate(&self.info.functions);
                let (scan, discovered) = self.scan_patterns(cursor)?;
                self.update_batch_inventory(certificate, &BTreeSet::new(), discovered)?;
                let inventory = self
                    .inventory
                    .publish(inventory_base, &self.info.functions)?;
                progress(AnalysisProgress {
                    stage: AnalysisStage::Publish,
                    ..empty
                })?;
                Ok(Response::DiscoveryBatch {
                    batch: DiscoveryBatch {
                        binding,
                        inventory,
                        truncated: self.info.functions_truncated,
                        analysis: CallAnalysis {
                            partial: self.info.functions_truncated,
                            ..Default::default()
                        },
                        outcomes: Vec::new(),
                        admissions: scan
                            .admitted
                            .iter()
                            .map(|&entry| FunctionAdmission {
                                entry,
                                reason: AdmissionReason::Pattern,
                                source: entry,
                                owner: None,
                                encoding: PointerEncoding::Direct,
                                boundary: BoundaryEvidence::Pattern,
                                table: None,
                            })
                            .collect(),
                        patterns: Some(scan),
                        pointers: None,
                        recovery_records: 0,
                    },
                })
            }
            Request::DiscoverBatch {
                binding,
                inventory_base,
                seeds,
                patterns: None,
            } => {
                self.check_unpacked()?;
                if seeds.is_empty()
                    || seeds.len() > MAX_ANALYSIS_FUNCTIONS
                    || seeds.iter().copied().collect::<BTreeSet<_>>().len() != seeds.len()
                {
                    return Err("Invalid discovery seed batch".into());
                }
                for &address in &seeds {
                    self.check_code(address)?;
                }
                #[cfg(debug_assertions)]
                let truncated_before = self.info.functions_truncated;
                let certificate = self.inventory.take_certificate(&self.info.functions);
                let (analysis, outcomes, discovered) =
                    self.discover_calls(Some(&seeds), progress)?;
                let recovery_records = self.take_pointer_preparation();
                let owners = outcomes.iter().map(|outcome| outcome.address).collect();
                self.update_batch_inventory(certificate, &owners, discovered)?;
                #[cfg(debug_assertions)]
                {
                    // The full selection remains the oracle for every shortcut.
                    let (expected, rejected) =
                        select_functions(&self.program, &self.info, &owners)?;
                    assert_eq!(self.info.functions, expected, "inventory shortcut diverged");
                    assert_eq!(self.info.functions_truncated, truncated_before || rejected);
                }
                let publishing = crate::performance::span("inventory_publish");
                let inventory = self
                    .inventory
                    .publish(inventory_base, &self.info.functions)?;
                publishing.finish(match &inventory {
                    InventoryChange::Unchanged { .. } => 0,
                    InventoryChange::Delta {
                        upserts, removals, ..
                    } => (upserts.len() + removals.len()) as u64,
                    InventoryChange::Replace { functions, .. } => functions.len() as u64,
                });
                Ok(Response::DiscoveryBatch {
                    batch: DiscoveryBatch {
                        binding,
                        inventory,
                        truncated: self.info.functions_truncated,
                        analysis,
                        outcomes,
                        patterns: None,
                        pointers: None,
                        admissions: Vec::new(),
                        recovery_records,
                    },
                })
            }
            Request::SyncSignatures {
                binary_sha256,
                context,
                signatures,
            } => {
                crate::signatures::validate_signatures(&signatures)?;
                if binary_sha256 != self.info.sha256
                    || context != crate::signatures::state_digest(&signatures)
                {
                    return Err("Signature state does not match this binary or its digest".into());
                }
                if self.analysis_started || self.signature_state.is_some() {
                    return Err(
                        "Signature replacement requires a fresh worker before analysis".into(),
                    );
                }
                let abi = crate::signatures::current_abi(&self.info)?;
                let mut unapplied = Vec::new();
                let mut compatible = Vec::new();
                for signature in &signatures {
                    self.check_code(signature.function)?;
                    if signature.engine != crate::signatures::SIGNATURE_FINGERPRINT
                        || signature.abi != abi
                    {
                        unapplied.push(SignatureStatus { function: signature.function,
                            reason: "Saved signature has an incompatible engine or ABI; edit it to apply to this image".into() });
                    } else if function_at(&self.info.functions, signature.function).is_none() {
                        unapplied.push(SignatureStatus { function: signature.function,
                            reason: "Saved signature entry is absent from the current function inventory; recompute discovery before editing it".into() });
                    } else {
                        compatible.push(signature.clone());
                    }
                }
                crate::signatures::apply(&mut self.program, &compatible, &abi)?;
                self.applied_signatures = compatible
                    .iter()
                    .map(|signature| signature.function)
                    .collect();
                self.signatures = signatures;
                self.signature_state = Some(context.clone());
                Ok(Response::SignaturesSynced {
                    binary_sha256,
                    context,
                    unapplied,
                })
            }
            Request::SyncFunctions { functions } => {
                validate_functions(&functions, MAX_FUNCTION_NAME_BYTES, true)?;
                if functions.len() > MAX_DISCOVERY_SYNC_FUNCTIONS {
                    return Err("Oversized function synchronization".into());
                }
                // Validate the entire request before touching the engine. The
                // inventory admission routine retains its shared name/count caps.
                for function in &functions {
                    self.check_code(function.address)?;
                }
                if functions.iter().all(|function| {
                    function_at(&self.info.functions, function.address)
                        .is_some_and(|current| current.name == function.name)
                }) {
                    return Ok(Response::FunctionsSynced);
                }
                self.inventory.take_certificate(&self.info.functions);
                for function in functions {
                    self.program
                        .set_function_name(function.address, &function.name)
                        .map_err(engine_error)?;
                }
                self.rebuild_inventory(&BTreeSet::new())?;
                Ok(Response::FunctionsSynced)
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
                self.inventory.take_certificate(&self.info.functions);
                self.program
                    .set_function_name(address, &name)
                    .map_err(engine_error)?;
                self.synchronize_function_name(address, &name)?;
                self.rebuild_inventory(&BTreeSet::new())?;
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

    /// Replaces the inventory, journaling the change for the next publication.
    fn set_inventory(&mut self, functions: Vec<FunctionInfo>) {
        self.inventory.record(&self.info.functions, &functions);
        self.info.functions = functions;
    }

    /// [`function_list`] for `required` owners, certifying ordinary selections.
    fn rebuild_inventory(&mut self, required: &BTreeSet<u64>) -> Result<(), String> {
        let (functions, rejected) = select_functions(&self.program, &self.info, required)?;
        self.info.functions_truncated |= rejected;
        self.set_inventory(functions);
        // When every candidate fits, owner priority cannot change the selection.
        if required.is_empty() || !rejected {
            self.inventory.certify(&self.info.functions, !rejected);
        }
        Ok(())
    }

    /// Brings the inventory to `function_list(required)` after a batch. A
    /// certificate taken before the batch proves when no rebuild is needed:
    /// promoting already admitted owners leaves a greedy selection unchanged,
    /// and functions the batch named join a selection that admitted everything
    /// because discovery only names them within the same budgets.
    fn update_batch_inventory(
        &mut self,
        certificate: Option<bool>,
        required: &BTreeSet<u64>,
        discovered: Discovered,
    ) -> Result<(), String> {
        let owned = |functions: &[FunctionInfo]| {
            required
                .iter()
                .all(|&address| function_at(functions, address).is_some())
        };
        match certificate {
            Some(complete) if !discovered.opaque && discovered.added.is_empty() => {
                if complete || owned(&self.info.functions) {
                    crate::performance::event("inventory_reused", 0);
                    self.inventory.certify(&self.info.functions, complete);
                    Ok(())
                } else {
                    self.rebuild_inventory(required)
                }
            }
            Some(true) if !discovered.opaque => {
                crate::performance::event("inventory_extended", discovered.added.len() as u64);
                let mut added = discovered.added;
                added.sort_unstable_by_key(|function| function.address);
                for function in &added {
                    self.inventory.insert(function);
                }
                let current = std::mem::take(&mut self.info.functions);
                let mut merged = Vec::with_capacity(current.len() + added.len());
                let mut added = added.into_iter().peekable();
                for function in current {
                    while let Some(new) = added.next_if(|new| new.address < function.address) {
                        merged.push(new);
                    }
                    merged.push(function);
                }
                merged.extend(added);
                self.info.functions = merged;
                self.inventory.certify(&self.info.functions, true);
                Ok(())
            }
            _ => {
                // Establish the ordinary selection, which serves any owners it admits.
                let (functions, rejected) =
                    select_functions(&self.program, &self.info, &BTreeSet::new())?;
                if !rejected || owned(&functions) {
                    self.info.functions_truncated |= rejected;
                    self.set_inventory(functions);
                    self.inventory.certify(&self.info.functions, !rejected);
                    Ok(())
                } else {
                    self.rebuild_inventory(required)
                }
            }
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
        seeds: Option<&[u64]>,
        progress: &mut dyn FnMut(AnalysisProgress) -> Result<(), String>,
    ) -> Result<(CallAnalysis, Vec<DiscoveryOutcome>, Discovered), String> {
        let _discovery = crate::performance::span("discovery_decode_cfg_data_admission");
        self.prepare_pointers();
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
        if self.target.name == "AArch64" {
            data = data.with_propagation();
        }
        // The published inventory plus functions this pass names. Borrowed, so a
        // batch does not copy every name of a large inventory.
        let published = &self.info.functions;
        let mut added = BTreeMap::new();
        let mut opaque = false;
        let known = |added: &BTreeMap<u64, String>, address| {
            added.contains_key(&address) || function_at(published, address).is_some()
        };
        report.partial |= seeds.is_none() && published.len() > MAX_ANALYSIS_FUNCTIONS;
        let mut name_bytes = published
            .iter()
            .map(|function| json_escaped_len(&function.name))
            .fold(0usize, usize::saturating_add)
            .min(MAX_FUNCTION_NAME_JSON_BYTES);
        let mut pending = VecDeque::new();
        let mut scheduled = BTreeSet::new();
        if let Some(seeds) = seeds {
            pending.extend(seeds.iter().copied());
            scheduled.extend(seeds.iter().copied());
        } else {
            if self.check_code(self.info.entry).is_ok() {
                scheduled.insert(self.info.entry);
                pending.push_back(self.info.entry);
            }
            for address in published
                .iter()
                .map(|function| function.address)
                .take(MAX_ANALYSIS_FUNCTIONS)
            {
                if scheduled.insert(address) {
                    pending.push_back(address);
                }
            }
        }
        let mut decoding = crate::performance::Accumulator::new("discovery_recovery_accumulated");
        let mut switches = SwitchBudget::new();
        let mut outcomes = Vec::new();
        let mut references = BTreeSet::new();
        emit(AnalysisStage::Calls, &report, progress)?;
        while let Some(address) = pending.pop_front() {
            if report.functions_examined == MAX_ANALYSIS_FUNCTIONS
                || report.decode_attempts == MAX_ANALYSIS_INSTRUCTIONS
                || seeds.is_some()
                    && MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts < MAX_INSTRUCTIONS
            {
                // Leave unstarted seeds pending. A batch limit is not a limit
                // on this function's own walk or cumulative session coverage.
                report.partial |= seeds.is_none();
                break;
            }
            report.functions_examined += 1;
            let available =
                (MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts).min(MAX_INSTRUCTIONS);
            let mut remaining = available;
            let sections = &self.info.sections;
            let pe_ranges = &self.pe_ranges;
            let mut walk = decoding.measure(|| {
                let mut walk = Walk::new(
                    &self.program,
                    sections,
                    address,
                    &self.no_return,
                    Some(&mut data),
                )?;
                walk.run(
                    &self.program,
                    &Bounds {
                        tail_entry: Some(&|a| {
                            self.pointers
                                .as_ref()
                                .is_some_and(|p| p.metadata.fdes.contains_key(&a))
                        }),
                        sections,
                        is_function: &|candidate| known(&added, candidate),
                        pe_ranges,
                    },
                    &mut remaining,
                    Some(&mut data),
                );
                Ok::<_, String>(walk)
            });
            // Switch recovery needs an engine function, so a walk that decoded
            // anything names its entry first. Failed decoding never does.
            let mut admitted = true;
            if let Ok(pending) = &walk
                && !pending.nodes.is_empty()
                && !known(&added, address)
            {
                admitted = admit_discovered(
                    &mut self.program,
                    published.len(),
                    &mut added,
                    &mut name_bytes,
                    address,
                )?;
            }
            if admitted
                && !self.upx_packed
                && let Ok(pending) = &mut walk
                && pending.switches(&mut self.program, sections, &mut switches)
            {
                decoding.measure(|| {
                    pending.run(
                        &self.program,
                        &Bounds {
                            tail_entry: Some(&|a| {
                                self.pointers
                                    .as_ref()
                                    .is_some_and(|p| p.metadata.fdes.contains_key(&a))
                            }),
                            sections,
                            is_function: &|candidate| known(&added, candidate),
                            pe_ranges,
                        },
                        &mut remaining,
                        Some(&mut data),
                    )
                });
            }
            let recovered = walk.and_then(|walk| walk.finish(Some(&mut data)));
            report.decode_attempts += available - remaining;
            match recovered {
                Ok(recovered) => {
                    if admitted {
                        self.coverage.add(address, &recovered.intervals);
                    }
                    report.partial |= recovered.partial;
                    outcomes.push(DiscoveryOutcome {
                        address,
                        status: if recovered.partial {
                            DiscoveryStatus::PartialByOwnLimit
                        } else {
                            DiscoveryStatus::Done
                        },
                    });
                    if !admitted {
                        report.partial = true;
                        continue;
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
                        if seeds.is_some() {
                            // Confirmed targets are queued by the parent for a later batch.
                        } else if scheduled.len() < MAX_FUNCTIONS && scheduled.insert(target) {
                            pending.push_back(target);
                        } else if !scheduled.contains(&target) {
                            report.partial = true;
                        }
                    }
                }
                Err(_) => {
                    report.failed_functions += 1;
                    outcomes.push(DiscoveryOutcome {
                        address,
                        status: DiscoveryStatus::Failed,
                    });
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
                .chain(if seeds.is_some() {
                    outcomes.iter().map(|o| o.address).collect::<Vec<_>>()
                } else {
                    published
                        .iter()
                        .map(|function| function.address)
                        .chain(added.keys().copied())
                        .collect()
                })
                .collect();
            report.partial |= targets.len() > crate::pe_symbols::MAX_THUNK_TARGETS;
            let targets = targets
                .into_iter()
                .take(crate::pe_symbols::MAX_THUNK_TARGETS)
                .collect();
            let mut remaining = MAX_ANALYSIS_INSTRUCTIONS - report.decode_attempts;
            // Import promotion renames engine functions without enumerating them.
            opaque = true;
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
        let added = added
            .into_iter()
            .map(|(address, name)| FunctionInfo { address, name })
            .collect();
        Ok((report, outcomes, Discovered { added, opaque }))
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
        let mut no_return_targets = BTreeSet::new();
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
            let mut remaining = MAX_INSTRUCTIONS;
            let Ok(recovered) = recover_graph_budgeted(
                &self.program,
                &Bounds {
                    tail_entry: None,
                    sections: &self.info.sections,
                    is_function: &|pc| function_at(&self.info.functions, pc).is_some(),
                    pe_ranges: &self.pe_ranges,
                },
                address,
                &mut remaining,
                &self.no_return,
                None,
            ) else {
                continue;
            };
            // Naming uses every bounded decoded call, including those omitted
            // from the displayed graph by its separate block limit.
            no_return_targets.extend(
                recovered
                    .calls
                    .iter()
                    .map(|(call, _)| call)
                    .filter(|call| call.no_return.is_some())
                    .filter_map(|call| call.target),
            );
            for target in recovered.calls.iter().filter_map(|(call, _)| call.target) {
                if targets.len() < crate::pe_symbols::MAX_THUNK_TARGETS {
                    targets.insert(target);
                }
            }
            let view = recovered.view;
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
            crate::pe_symbols::register_aarch64_import_thunks(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
            )?;
        } else {
            crate::pe_symbols::register_import_thunks(
                &mut self.program,
                &self.pe_imports,
                &self.snapshot,
                &self.info.sections,
                &targets,
                self.target.pointer_bytes,
            )?;
        }
        // An unmarked thunk only keeps the decompiler's ordinary call flow.
        crate::no_return::mark_targets(&mut self.program, no_return_targets);
        Ok(())
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
                let chunk_limit = MAX_CRYPTO_RESULTS.min(crate::crypto::MAX_MATCHES);
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
                if matches.len() >= MAX_CRYPTO_RESULTS || chunk_limited {
                    matches.truncate(MAX_CRYPTO_RESULTS);
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

/// Names a function discovered at `address` within the shared inventory
/// count and escaped-name budgets. Returns whether it was admitted.
fn admit_discovered(
    program: &mut Program,
    published: usize,
    added: &mut BTreeMap<u64, String>,
    name_bytes: &mut usize,
    address: u64,
) -> Result<bool, String> {
    let name = format!("FUN_{address:08x}");
    let bytes = json_escaped_len(&name);
    if published + added.len() >= MAX_FUNCTIONS
        || bytes > MAX_FUNCTION_NAME_JSON_BYTES - *name_bytes
    {
        return Ok(false);
    }
    program
        .set_function_name(address, &name)
        .map_err(engine_error)?;
    *name_bytes += bytes;
    added.insert(address, name);
    Ok(true)
}

/// Names `main` when a stripped ELF executable's startup code passes it to
/// the imported `__libc_start_main`, then republishes the inventory. Existing
/// functions and names always win; a failed recognition leaves the inventory
/// unchanged. Returns whether republishing rejected any inventory candidate,
/// which is also recorded as truncation.
fn recover_elf_main(
    program: &mut Program,
    info: &mut BinaryInfo,
    target: &crate::architecture::Target,
    bytes: &[u8],
) -> Result<bool, String> {
    let _span = crate::performance::span("open_elf_startup");
    let known = |address| function_at(&info.functions, address).is_some();
    if info
        .functions
        .iter()
        .any(|function| function.name == "main")
        || info.functions.len() >= MAX_FUNCTIONS
    {
        return Ok(false);
    }
    let recovery = match crate::elf_startup::recognize(
        program,
        bytes,
        target.name,
        info.entry,
        target.pointer_bytes as u32,
        |address| crate::call_analysis::code_address(info, address) && !known(address),
    ) {
        Ok(recovery) => recovery,
        Err(crate::elf_startup::Miss::Exhausted) => {
            warning(
                &mut info.warnings,
                "ELF startup recognition stopped at its work limit; main was not recovered.",
            );
            return Ok(false);
        }
        Err(_) => return Ok(false),
    };
    // A global symbol already named main (for example a data label) keeps
    // its name; the callback stays an unnamed discovery candidate instead.
    let occupied = program
        .data_symbols()
        .map_err(engine_error)?
        .iter()
        .any(|symbol| symbol.name == "main");
    if occupied || program.set_function_name(recovery.main, "main").is_err() {
        return Ok(false);
    }
    // The engine cannot forget the new function, so a publication that omits
    // it is merely incomplete rather than an open failure.
    let (functions, rejected) = select_functions(program, info, &BTreeSet::from([recovery.main]))?;
    info.functions_truncated |= rejected;
    if function_at(&functions, recovery.main).is_none_or(|function| function.name != "main") {
        warning(
            &mut info.warnings,
            "A recovered ELF startup callback did not fit the function list; main was not published.",
        );
        info.functions_truncated = true;
        return Ok(true);
    }
    info.functions = functions;
    warning(
        &mut info.warnings,
        format!(
            "Recovered main at {:#x} from the first argument passed to the imported __libc_start_main at {:#x}. This name is analysis-derived, not an ELF symbol.",
            recovery.main, recovery.call
        ),
    );
    Ok(rejected)
}

/// Publishes the engine inventory within the shared count and escaped-name
/// budgets. The entry and `required` addresses (owners of evidence in the same
/// reply) are admitted first; remaining entries follow engine address order.
#[cfg(test)]
fn function_list(
    program: &Program,
    info: &mut BinaryInfo,
    required: &BTreeSet<u64>,
) -> Result<Vec<FunctionInfo>, String> {
    let (functions, rejected) = select_functions(program, info, required)?;
    info.functions_truncated |= rejected;
    Ok(functions)
}

/// The published inventory for the engine's functions: the entry first, then
/// `required` owners, then the rest, each admitted while the count and name
/// budgets allow. Also reports whether any candidate was rejected.
fn select_functions(
    program: &Program,
    info: &BinaryInfo,
    required: &BTreeSet<u64>,
) -> Result<(Vec<FunctionInfo>, bool), String> {
    let _inventory = crate::performance::span("inventory_rebuild");
    let alignment = crate::architecture::instruction_alignment(program.language_id());
    let code_entry = |address: u64| {
        address.is_multiple_of(alignment) && executable(&info.sections, address, alignment as usize)
    };
    let entries: Vec<_> = program
        .functions()
        .map_err(engine_error)?
        .into_iter()
        .filter(|f| code_entry(f.address))
        .map(|f| FunctionInfo {
            address: f.address,
            name: bounded_name(&f.name),
        })
        .collect();
    let mut admitted = BTreeMap::new();
    let mut name_bytes = 0usize;
    let mut truncated = false;
    let mut admit = |function: FunctionInfo, admitted: &mut BTreeMap<u64, String>| {
        if admitted.contains_key(&function.address) {
            return;
        }
        let bytes = json_escaped_len(&function.name);
        if admitted.len() < MAX_FUNCTIONS && bytes <= MAX_FUNCTION_NAME_JSON_BYTES - name_bytes {
            name_bytes += bytes;
            admitted.insert(function.address, function.name);
        } else {
            truncated = true;
        }
    };
    if code_entry(info.entry) {
        let name = entries
            .iter()
            .find(|f| f.address == info.entry)
            .map_or_else(|| "entry".into(), |f| f.name.clone());
        admit(
            FunctionInfo {
                address: info.entry,
                name,
            },
            &mut admitted,
        );
    }
    let (first, rest): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|f| required.contains(&f.address));
    for function in first.into_iter().chain(rest) {
        admit(function, &mut admitted);
    }
    Ok((
        admitted
            .into_iter()
            .map(|(address, name)| FunctionInfo { address, name })
            .collect(),
        truncated,
    ))
}

fn bounded_name(name: &str) -> String {
    let mut end = name.len().min(MAX_FUNCTION_NAME_BYTES);
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

#[cfg(test)]
pub(crate) mod tests {
    use super::strings::StringRun;
    use super::*;
    use ghidra_decompiler::opcodes::OpCode;
    use ghidra_decompiler::program::InstructionPcode;

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
            inventory: Default::default(),
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::default(),
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
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

    fn bulk_functions(loaded: &mut LoadedProgram, names: impl Iterator<Item = (u64, String)>) {
        let metadata = crate::pe::PeMetadata {
            functions: names.collect(),
            ..Default::default()
        };
        crate::pe_symbols::register(&mut loaded.program, &metadata, 8).unwrap();
    }

    #[test]
    fn no_return_calls_preserve_other_paths_and_ignore_later_renames() {
        // JNE 0x1007; CALL 0x1020; RET. The RET is reachable by the branch,
        // even though the call itself cannot fall through to it.
        let mut bytes = vec![0x75, 5, 0xe8, 0x19, 0, 0, 0, 0xc3];
        bytes.resize(0x21, 0xc3);
        let mut loaded = raw_x86(bytes);
        bulk_functions(&mut loaded, [(0x1020, "exit".into())].into_iter());
        loaded.no_return = Arc::new(crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        ));
        loaded
            .synchronize_function_name(0x1020, "renamed_exit")
            .unwrap();
        let view = loaded.graph(0x1000).unwrap();
        assert_eq!(view.calls[0].no_return, Some(NoReturnEvidence::NamedTarget));
        let call_block = view
            .blocks
            .iter()
            .find(|b| b.instructions.last().unwrap().address == 0x1002)
            .unwrap();
        assert!(
            !view
                .edges
                .iter()
                .any(|edge| edge.source == call_block.address)
        );
        assert!(view.blocks.iter().any(|b| b.address == 0x1007));

        // Renaming a returning function to a listed name does not create evidence.
        let mut loaded = raw_x86(vec![0xe8, 1, 0, 0, 0, 0xc3, 0xc3]);
        bulk_functions(&mut loaded, [(0x1006, "helper".into())].into_iter());
        loaded.no_return = Arc::new(crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        ));
        loaded.synchronize_function_name(0x1006, "abort").unwrap();
        let view = loaded.graph(0x1000).unwrap();
        assert_eq!(view.calls[0].no_return, None);
        assert!(
            view.blocks
                .iter()
                .flat_map(|b| &b.instructions)
                .any(|i| i.address == 0x1005)
        );
    }

    #[test]
    fn no_return_does_not_override_call_to_own_fallthrough_or_internal_flow() {
        // The engine lowers a literal CALL-next to a branch. Use the normal
        // CALL p-code form with an explicit next-instruction target to cover
        // the flow guard independently of that SLEIGH optimization.
        let loaded = raw_x86(vec![0xe8, 0x1b, 0, 0, 0, 0xc3]);
        let mut code = loaded.program.pcode(0x1000, 1).unwrap().pop().unwrap();
        code.operations
            .iter_mut()
            .find(|op| op.opcode == OpCode::Call)
            .unwrap()
            .inputs[0]
            .offset = 0x1005;
        let mut calls = Vec::new();
        let mut warnings = Vec::new();
        let (edges, terminal, _) = flow(&code, 0x1005, &mut calls, &mut warnings, &mut |_, _| {
            Some(NoReturnEvidence::NamedTarget)
        });
        assert!(!terminal);
        assert_eq!(edges, [(Some(0x1005), EdgeKind::Branch)]);
        assert_eq!(calls[0].no_return, None);
        // Force a non-fallthrough target and internal p-code flow. Neither
        // an address match nor a prototype may override ambiguous machine flow.
        let call = code
            .operations
            .iter_mut()
            .find(|op| op.opcode == OpCode::Call)
            .unwrap();
        call.inputs[0].offset = 0x1020;
        code.operations
            .push(ghidra_decompiler::program::PcodeOperation {
                opcode: OpCode::Cbranch,
                output: None,
                inputs: vec![ghidra_decompiler::program::PcodeVarnode {
                    space: "const".into(),
                    offset: 1,
                    size: 8,
                }],
                space: None,
            });
        calls.clear();
        let (edges, terminal, _) = flow(&code, 0x1005, &mut calls, &mut warnings, &mut |_, _| {
            Some(NoReturnEvidence::NamedTarget)
        });
        assert!(terminal && calls.is_empty());
        assert_eq!(edges, [(None, EdgeKind::Unknown)]);
    }

    #[test]
    fn no_return_terminal_can_establish_a_pattern_candidate() {
        let mut bytes = vec![0xe8, 0x1b, 0, 0, 0];
        bytes.resize(0x21, 0xc3);
        let mut loaded = raw_x86(bytes);
        bulk_functions(&mut loaded, [(0x1020, "abort".into())].into_iter());
        let index = Arc::new(crate::no_return::NoReturnIndex::build(
            &loaded.program,
            "ELF",
            8,
            &BTreeMap::new(),
            |_| true,
        ));
        let mut walk =
            Walk::new(&loaded.program, &loaded.info.sections, 0x1000, &index, None).unwrap();
        walk.run(
            &loaded.program,
            &Bounds {
                tail_entry: None,
                sections: &loaded.info.sections,
                is_function: &|pc| pc == 0x1020,
                pe_ranges: &[],
            },
            &mut 16,
            None,
        );
        assert_eq!(walk.nodes.len(), 1);
        assert!(walk.complete_function(&Coverage::default(), &|pc| pc == 0x1020, &|_| true, 1));
    }

    #[test]
    fn full_inventory_reserves_entry_and_evidence_owners() {
        let mut loaded = raw_x86(vec![0xc3; MAX_FUNCTIONS + 8]);
        bulk_functions(
            &mut loaded,
            (0..MAX_FUNCTIONS as u64).map(|i| (0x1008 + i, format!("FUN_{:x}", 0x1008 + i))),
        );
        loaded.program.set_function_name(0x1001, "owner").unwrap();
        let owners = BTreeSet::from([0x1001]);
        let functions = function_list(&loaded.program, &mut loaded.info, &owners).unwrap();
        assert_eq!(functions.len(), MAX_FUNCTIONS);
        assert_eq!(functions[0].address, 0x1000);
        assert_eq!(functions[0].name, "entry");
        assert_eq!(functions[1].name, "owner");
        assert!(loaded.info.functions_truncated);
        // Address order admits the lowest remaining entries; two are omitted.
        assert_eq!(
            functions.last().unwrap().address,
            0x1008 + MAX_FUNCTIONS as u64 - 3
        );
        validate_functions(&functions, MAX_FUNCTION_NAME_BYTES, true).unwrap();
    }

    #[test]
    fn inventory_names_respect_the_escaped_byte_budget() {
        let count = MAX_FUNCTION_NAME_JSON_BYTES / 250 + 16;
        let mut loaded = raw_x86(vec![0xc3; count + 8]);
        // Quotes double when escaped: 125 of them cost 250 bytes.
        bulk_functions(
            &mut loaded,
            (0..count as u64).map(|i| (0x1008 + i, format!("{}{i:x}", "\"".repeat(125)))),
        );
        let functions = function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
        assert!(loaded.info.functions_truncated);
        assert!(functions.len() < count);
        let escaped: usize = functions.iter().map(|f| json_escaped_len(&f.name)).sum();
        assert!(escaped <= MAX_FUNCTION_NAME_JSON_BYTES);
        assert!(escaped > MAX_FUNCTION_NAME_JSON_BYTES - 512);
        validate_functions(&functions, MAX_FUNCTION_NAME_BYTES, true).unwrap();
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
        loaded.info.functions =
            function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
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
        loaded.info.functions =
            function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
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
        loaded.info.functions =
            function_list(&loaded.program, &mut loaded.info, &BTreeSet::new()).unwrap();
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

    #[test]
    fn discovery_batches_publish_reconstructable_inventory_changes() {
        let mut bytes = vec![0xcc; 0x50];
        bytes[..6].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]); // call 1020; ret
        bytes[0x20] = 0xc3;
        bytes[0x40] = 0xc3;
        let mut loaded = raw_x86(bytes);
        for (address, name) in [(0x1000, "root"), (0x1040, "leaf")] {
            loaded.program.set_function_name(address, name).unwrap();
        }
        loaded.rebuild_inventory(&BTreeSet::new()).unwrap();
        let mut adopted: Option<(u64, Vec<FunctionInfo>)> = None;
        let mut batch = |loaded: &mut LoadedProgram, base: Option<u64>, seed: u64| {
            let binding = DiscoveryBinding {
                generation: 1,
                epoch: 1,
                revision: 0,
                batch: seed,
            };
            let Response::DiscoveryBatch { batch } = loaded
                .handle(Request::DiscoverBatch {
                    binding,
                    inventory_base: base,
                    seeds: vec![seed],
                    patterns: None,
                })
                .unwrap()
            else {
                panic!("Expected a discovery batch");
            };
            let change = batch.inventory;
            let revision = change.revision();
            let previous = adopted
                .as_ref()
                .filter(|(adopted, _)| Some(*adopted) == base)
                .map(|(revision, functions)| (*revision, functions.as_slice()));
            if let Some(functions) = change.clone().apply(previous).unwrap() {
                adopted = Some((revision, functions));
            }
            assert_eq!(adopted.as_ref().unwrap().1, loaded.info.functions);
            change
        };
        assert!(matches!(
            batch(&mut loaded, None, 0x1000),
            InventoryChange::Replace { revision: 1, .. }
        ));
        // The confirmed callee is named by discovery and sent as one new row.
        let InventoryChange::Delta {
            upserts, removals, ..
        } = batch(&mut loaded, Some(1), 0x1020)
        else {
            panic!("Expected the named callee as a delta");
        };
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].name, "FUN_00001020");
        assert!(removals.is_empty());
        assert!(matches!(
            batch(&mut loaded, Some(2), 0x1040),
            InventoryChange::Unchanged { revision: 2 }
        ));
        loaded
            .handle(Request::Rename {
                address: 0x1040,
                name: "renamed_leaf".into(),
            })
            .unwrap();
        let InventoryChange::Delta { upserts, .. } = batch(&mut loaded, Some(2), 0x1000) else {
            panic!("Expected the rename as a delta");
        };
        assert_eq!(upserts.len(), 1);
        assert_eq!(upserts[0].name, "renamed_leaf");
        // Engine work outside discovery invalidates the shortcut, not correctness.
        loaded
            .handle(Request::Decompile { address: 0x1000 })
            .unwrap();
        let current = batch(&mut loaded, Some(3), 0x1040).revision();
        assert!(matches!(
            batch(&mut loaded, Some(current - 1), 0x1040),
            InventoryChange::Replace { .. }
        ));
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
        recover_graph_counted(&program, &sections, &[], 0x1000, &[])
            .unwrap()
            .0
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
        let (view, _) =
            recover_graph_counted(&program, &sections, &[], 0x1000, &[(0x1005, 0x100b)]).unwrap();
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
        info.functions = function_list(&program, &mut info, &BTreeSet::new()).unwrap();
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
            inventory: Default::default(),
            coverage: Coverage::default(),
            pointers: None,
            no_return: Arc::default(),
            signatures: Vec::new(),
            applied_signatures: BTreeSet::new(),
            signature_state: None,
            analysis_started: false,
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
    fn coverage_merges_ranges_and_reports_instruction_ends() {
        let mut coverage = Coverage::default();
        coverage.add(
            0x1000,
            &[(0x1000, 0x1004), (0x1004, 0x1006), (0x1010, 0x1012)],
        );
        assert_eq!(coverage.ranges.len(), 2);
        assert!(coverage.contains(0x1005) && !coverage.contains(0x1006));
        assert!(coverage.overlaps(0x0fff, 0x1001) && !coverage.overlaps(0x1006, 0x1010));
        assert!(coverage.ends_at(0x1006) && coverage.ends_at(0x1012));
        assert!(!coverage.ends_at(0x1004) && !coverage.ends_at(0x1010));
        // A bridging range joins its neighbours.
        coverage.add(0x1006, &[(0x1006, 0x1010)]);
        assert_eq!(
            coverage.ranges.into_iter().collect::<Vec<_>>(),
            [(0x1000, 0x1012)]
        );
    }

    #[test]
    fn pattern_candidates_need_complete_independent_code() {
        let check = |bytes: &[u8], coverage: &Coverage, known: &[u64]| {
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
            let is_function = |address| known.contains(&address);
            let mut remaining = MAX_INSTRUCTIONS;
            let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
            walk.run(
                &program,
                &Bounds {
                    tail_entry: None,
                    sections: &sections,
                    is_function: &is_function,
                    pe_ranges: &[],
                },
                &mut remaining,
                None,
            );
            let is_code = |address| (0x1000..0x1000 + bytes.len() as u64).contains(&address);
            walk.complete_function(coverage, &is_function, &is_code, 0)
        };
        let empty = Coverage::default();
        // push rbp; mov rbp,rsp; pop rbp; ret
        let frame = [0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3];
        assert!(check(&frame, &empty, &[]));
        // Its bytes already belong to decoded code.
        let mut covered = Coverage::default();
        covered.add(0x2000, &[(0x1004, 0x1005)]);
        assert!(!check(&frame, &covered, &[]));
        // push rbp; jmp rax: an unresolved indirect jump.
        assert!(!check(&[0x55, 0xff, 0xe0], &empty, &[]));
        // push rbp; nop; then a known function: running into it is no exit.
        assert!(!check(&[0x55, 0x90, 0xc3], &empty, &[0x1002]));
        // push rbp; je +1; ret; ret: both paths return.
        assert!(check(&[0x55, 0x74, 0x01, 0xc3, 0xc3], &empty, &[]));
        // A path ending in an explicit jump to a known function is accepted
        // beside a return, but a call into the middle of decoded code is not.
        assert!(check(
            &[0x74, 0x01, 0xc3, 0xeb, 0x00, 0xc3],
            &empty,
            &[0x1005]
        ));
        let mut interior = Coverage::default();
        interior.add(0x1000, &[(0x1006, 0x100a)]);
        // call 0x1007; ret; padding.
        let call = [0xe8, 0x02, 0x00, 0x00, 0x00, 0xc3, 0x90, 0x90, 0x90, 0x90];
        assert!(!check(&call, &interior, &[]));
        assert!(check(&call, &empty, &[]));
    }

    #[test]
    fn switch_destinations_are_validated_before_they_become_edges() {
        use crate::switch_analysis::{Recovered, Table};
        // jmp rax; ret; ret
        let bytes = [0xff, 0xe0, 0xc3, 0xc3];
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
        let mut remaining = MAX_INSTRUCTIONS;
        let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
        walk.run(
            &program,
            &Bounds {
                tail_entry: None,
                sections: &sections,
                is_function: &|_| false,
                pe_ranges: &[],
            },
            &mut remaining,
            None,
        );
        let table = |branch, targets: &[u64], partial| Table {
            branch,
            targets: targets.to_vec(),
            partial,
        };
        // A table must belong to the exact decoded jump; the second one has a
        // repeated entry and an address outside executable sections.
        let queued = walk.apply(
            Recovered {
                tables: vec![
                    table(0x1001, &[0x1003], false),
                    table(0x1000, &[0x1002, 0x1003, 0x1002, 0x9000], false),
                ],
                truncated: false,
            },
            &sections,
        );
        assert!(queued);
        walk.run(
            &program,
            &Bounds {
                tail_entry: None,
                sections: &sections,
                is_function: &|_| false,
                pe_ranges: &[],
            },
            &mut remaining,
            None,
        );
        let view = walk.finish(None).unwrap().view;
        let mut switched: Vec<_> = view
            .edges
            .iter()
            .filter(|edge| edge.evidence == Some(EdgeEvidence::EngineJumpTable))
            .map(|edge| (edge.source, edge.target))
            .collect();
        switched.sort();
        assert_eq!(switched, [(0x1000, Some(0x1002)), (0x1000, Some(0x1003))]);
        // The rejected entry leaves an unresolved successor, never an edge.
        assert!(
            view.edges
                .iter()
                .any(|e| e.source == 0x1000 && e.target.is_none() && e.evidence.is_none())
        );
        assert!(!view.edges.iter().any(|e| e.target == Some(0x9000)));
        assert!(
            view.warnings
                .iter()
                .any(|w| w.contains("only partly recovered"))
        );
        assert!(
            !view
                .warnings
                .iter()
                .any(|w| w.contains("unresolved targets"))
        );
    }

    #[test]
    fn a_table_without_valid_destinations_leaves_the_jump_unresolved() {
        use crate::switch_analysis::{Recovered, Table};
        let bytes = [0xff, 0xe0, 0xc3];
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
        let mut remaining = MAX_INSTRUCTIONS;
        let mut walk = Walk::new(&program, &sections, 0x1000, &Arc::default(), None).unwrap();
        walk.run(
            &program,
            &Bounds {
                tail_entry: None,
                sections: &sections,
                is_function: &|_| false,
                pe_ranges: &[],
            },
            &mut remaining,
            None,
        );
        let recovered = Recovered {
            tables: vec![Table {
                branch: 0x1000,
                targets: vec![0x9000],
                partial: false,
            }],
            truncated: false,
        };
        assert!(!walk.apply(recovered, &sections));
        let view = walk.finish(None).unwrap().view;
        assert!(view.edges.iter().all(|e| e.evidence.is_none()));
        assert!(
            view.warnings
                .iter()
                .any(|w| w.contains("0x1000 has unresolved targets"))
        );
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
        let (edges, terminal, _) = flow(&code, 0x1002, &mut calls, &mut warnings, &mut |_, _| None);
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
        assert!(info.warnings.is_empty());
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
