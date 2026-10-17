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
    // The engine currently takes ownership of a Vec, so the immutable scan snapshot
    // duplicates at most 128 MiB. Both copies originate from exactly the hashed bytes.
    // This favors consistent analysis over live file reads; engine snapshot sharing is future work.
    snapshot: Arc<[u8]>,
    pe_ranges: Vec<(u64, u64)>,
    pe_imports: BTreeMap<u64, String>,
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

fn metadata(path: &Path, bytes: &[u8]) -> Result<BinaryInfo, String> {
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
    let architecture = match object.architecture() {
        object::Architecture::I386 => "x86",
        object::Architecture::X86_64 => "x86-64",
        other => {
            return Err(format!(
                "Unsupported architecture {other:?}; this prototype supports x86 and x86-64 only."
            ));
        }
    };
    if !object.is_little_endian() {
        return Err("Only little-endian x86 executables are supported.".into());
    }
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
    Ok(BinaryInfo {
        path: path.to_string_lossy().into_owned(), architecture: architecture.into(), format: format.into(),
        sha256: format!("{:x}", Sha256::digest(bytes)), source_identity: None,
        entry: object.entry(), file_len: bytes.len() as u64, sections, functions: Vec::new(), functions_truncated: false,
        warnings: vec!["Prototype analysis: symbols and supported PE function metadata load immediately; deeper function discovery is explicit. Optimized C++/Rust types and source reconstruction are incomplete.".into(), "Function lists are capped at 10,000 entries and names at 256 bytes in this prototype.".into()],
    })
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
        let mut info = metadata(path, &bytes)?;
        info.source_identity = FileIdentity::from_file(&file);
        let snapshot = Arc::from(bytes.as_slice());
        let pe = crate::pe::parse(&bytes, &info.sections)?;
        let mut program =
            Program::from_image(&path.to_string_lossy(), bytes, None).map_err(engine_error)?;
        let mut pe_ranges = Vec::new();
        let mut pe_imports = BTreeMap::new();
        if let Some(pe) = pe {
            crate::pe_symbols::register(
                &mut program,
                &pe,
                if info.architecture == "x86-64" { 8 } else { 4 },
            )?;
            info.functions_truncated = pe.functions_truncated;
            for note in pe.warnings {
                warning(&mut info.warnings, note);
            }
            pe_ranges = pe.function_ranges;
            pe_imports = pe.imports;
        }
        info.functions = function_list(&program, &mut info)?;
        if !executable(&info.sections, info.entry, 1) {
            info.warnings.push("The binary entry point is not inside a supported executable section; select a function from the list.".into());
        }
        Ok(Self {
            program,
            snapshot,
            pe_ranges,
            pe_imports,
            info,
        })
    }

    pub fn handle(&mut self, request: Request) -> Result<Response, String> {
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
                self.program.discover_functions().map_err(engine_error)?;
                self.info.functions = function_list(&self.program, &mut self.info)?;
                Ok(Response::Functions {
                    functions: self.info.functions.clone(),
                    truncated: self.info.functions_truncated,
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
            Request::Strings => self.strings(),
            Request::Crypto => self.crypto(),
            Request::Open { .. } => Err("Open is handled by the worker.".into()),
        }
    }

    fn check_code(&self, address: u64) -> Result<(), String> {
        if executable(&self.info.sections, address, 1) {
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
        let mut targets = BTreeSet::new();
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
        crate::pe_symbols::register_import_thunks(
            &mut self.program,
            &self.pe_imports,
            &self.snapshot,
            &self.info.sections,
            &targets,
            if self.info.architecture == "x86-64" {
                8
            } else {
                4
            },
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

    fn strings(&mut self) -> Result<Response, String> {
        let mut strings = Vec::new();
        let mut scanned = 0u64;
        let mut truncated = false;
        for section in &self.info.sections {
            let size = section.file_size.min(MAX_SCAN_BYTES - scanned);
            if size < section.file_size {
                truncated = true;
            }
            if size == 0 {
                continue;
            }
            let mut ascii = StringRun::default();
            // Both parities are scanned: packed UTF-16 strings need not be aligned.
            let mut wide = [StringRun::default(), StringRun::default()];
            let mut previous = None;
            let mut offset = 0u64;
            while offset < size {
                let count = (size - offset).min(SCAN_CHUNK as u64) as usize;
                let start = (section.file_offset + offset) as usize;
                let chunk = self
                    .snapshot
                    .get(start..start + count)
                    .ok_or("Section extends past immutable image snapshot")?;
                for (index, &byte) in chunk.iter().enumerate() {
                    let address = section.address + offset + index as u64;
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
                    if strings.len() >= MAX_RESULTS {
                        strings.truncate(MAX_RESULTS);
                        return Ok(Response::Strings {
                            strings,
                            truncated: true,
                        });
                    }
                }
                offset += count as u64;
            }
            ascii.flush("ASCII", &mut strings);
            for run in &mut wide {
                run.flush("UTF-16LE", &mut strings);
            }
            scanned += size;
            if strings.len() >= MAX_RESULTS {
                strings.truncate(MAX_RESULTS);
                truncated = true;
                break;
            }
        }
        strings.sort_by_key(|s| s.address);
        Ok(Response::Strings { strings, truncated })
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
    let mut entries = program
        .functions()
        .map_err(engine_error)?
        .into_iter()
        .filter(|f| executable(&info.sections, f.address, 1));
    let mut functions: Vec<_> = entries
        .by_ref()
        .take(MAX_RESULTS)
        .map(|f| FunctionInfo {
            address: f.address,
            name: bounded_name(&f.name),
        })
        .collect();
    let truncated = entries.next().is_some();
    if executable(&info.sections, info.entry, 1)
        && !functions.iter().any(|f| f.address == info.entry)
    {
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

#[derive(Default)]
struct StringRun {
    start: u64,
    count: usize,
    text: String,
}

impl StringRun {
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
        if self.count >= 4 && output.len() < MAX_RESULTS {
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
    if !executable(sections, entry, 1) {
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
    while let Some(address) = pending.pop_front() {
        if !visited.insert(address) {
            continue;
        }
        if nodes.len() >= MAX_INSTRUCTIONS {
            warning(
                &mut warnings,
                "Graph limited to 2048 instructions; recovery is incomplete.",
            );
            break;
        }
        if !executable(sections, address, 1) {
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
                "A path reaches another known function entry; displayed as an external/tail exit.",
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
        if instruction.length == 0 || !executable(sections, address, instruction.length) {
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
        if pcode.length != instruction.length {
            warning(
                &mut warnings,
                format!("Instruction/p-code length mismatch at {address:#x}."),
            );
            continue;
        }
        let (next, terminal) = flow(&pcode, next_address, &mut calls, &mut warnings);
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
    warning(
        &mut warnings,
        "CFG uses bounded static instruction flow; indirect jump tables, exceptions, and no-return calls may be incomplete.",
    );
    Ok(FunctionView {
        address: entry,
        blocks,
        edges,
        calls,
        warnings,
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
    for operation in &code.operations {
        let direct = operation
            .inputs
            .first()
            .filter(|v| v.space == "ram")
            .map(|v| v.offset);
        match operation.opcode {
            OpCode::Call | OpCode::Callind => calls.push(CallSite {
                address: code.address,
                target: if operation.opcode == OpCode::Call {
                    direct
                } else {
                    None
                },
            }),
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
    if internal {
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
            program,
            snapshot: Arc::from(bytes),
            info,
            pe_ranges: vec![(0x1000, 0x1005), (0x1010, 0x1016)],
            pe_imports: symbols.imports,
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
        bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
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
