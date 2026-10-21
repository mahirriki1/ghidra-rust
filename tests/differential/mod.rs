//! Corpus preparation, ground truth and request documents for the opt-in
//! Ghidra differential benchmark. Generated inputs are analyzed, never run.
#![allow(dead_code)]

use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SymbolKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const SCHEMA_VERSION: u64 = 1;
/// Benchmark admission ceiling; matches the production input-size limit.
pub const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_REQUESTED: usize = 32;
pub const MAX_C_BYTES_PER_FUNCTION: usize = 256 * 1024;
pub const MAX_C_BYTES_TOTAL: usize = 8 * 1024 * 1024;
pub const MAX_ERROR_BYTES: usize = 4096;
pub const MAX_ANALYZER_OPTIONS: usize = 4096;
pub const MAX_CALL_INSTRUCTIONS: usize = 2_000_000;
pub const MAX_REQUEST_BYTES: u64 = 1024 * 1024;
pub const DECOMPILE_TIMEOUT_SECONDS: u64 = 30;
/// Ghidra's whole-analysis and the native discovery-phase ceilings.
pub const ANALYSIS_TIMEOUT_SECONDS: u64 = 300;
/// Startup functions emitted by the C runtime rather than the corpus.
pub const RUNTIME_FUNCTIONS: [&str; 8] = [
    "_init",
    "_fini",
    "_start",
    "_dl_relocate_static_pie",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__do_global_dtors_aux",
];

const SOURCES: [&str; 2] = [
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/differential/corpus.c"
    ),
    concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/differential/many_functions.c"
    ),
];

pub fn hex(value: u64) -> String {
    format!("{value:#x}")
}

pub fn parse_hex(text: &str) -> Result<u64, String> {
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| format!("Address {text:?} lacks a 0x prefix"))?;
    if digits.is_empty() || digits.len() > 16 || digits.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(format!("Invalid canonical address {text:?}"));
    }
    u64::from_str_radix(digits, 16).map_err(|error| format!("Invalid address {text:?}: {error}"))
}

/// A requested decompilation target, fixed before either analyzer runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Requested {
    pub va: String,
    pub rva: String,
    /// Symbol at this entry in the unstripped build, for reports only.
    pub label: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    pub max_functions: usize,
    pub max_function_name_bytes: usize,
    pub max_calls: usize,
    pub max_call_instructions: usize,
    pub max_c_bytes_per_function: usize,
    pub max_c_bytes_total: usize,
    pub max_error_bytes: usize,
    pub max_analyzer_options: usize,
    pub decompile_timeout_seconds: u64,
    pub analysis_timeout_seconds: u64,
}

impl Limits {
    pub fn current() -> Self {
        Self {
            max_functions: ghidra_rust::model::MAX_FUNCTIONS,
            max_function_name_bytes: ghidra_rust::model::MAX_FUNCTION_NAME_BYTES,
            max_calls: ghidra_rust::model::MAX_CALL_REFERENCES,
            max_call_instructions: MAX_CALL_INSTRUCTIONS,
            max_c_bytes_per_function: MAX_C_BYTES_PER_FUNCTION,
            max_c_bytes_total: MAX_C_BYTES_TOTAL,
            max_error_bytes: MAX_ERROR_BYTES,
            max_analyzer_options: MAX_ANALYZER_OPTIONS,
            decompile_timeout_seconds: DECOMPILE_TIMEOUT_SECONDS,
            analysis_timeout_seconds: ANALYSIS_TIMEOUT_SECONDS,
        }
    }
}

/// The document each fresh tool process receives. Paths are absolute and
/// written by the controller; exports must not already exist.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunRequest {
    pub schema_version: u64,
    pub document_type: String,
    pub run_id: String,
    pub case_id: String,
    pub repetition: usize,
    pub tool: String,
    pub input_path: PathBuf,
    pub input_sha256: String,
    pub input_bytes: u64,
    /// Minimum ELF PT_LOAD virtual address; canonical RVAs are relative to it.
    pub load_base: String,
    pub requested: Vec<Requested>,
    pub output: PathBuf,
    pub limits: Limits,
}

impl RunRequest {
    pub fn read(path: &Path) -> Result<Self, String> {
        let length = fs::metadata(path).map_err(|e| e.to_string())?.len();
        if length > MAX_REQUEST_BYTES {
            return Err("Run request exceeds its size limit".into());
        }
        let request: Self = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|error| format!("Invalid run request: {error}"))?;
        if request.schema_version != SCHEMA_VERSION || request.document_type != "run_request" {
            return Err("Unsupported run request version".into());
        }
        if request.requested.len() > MAX_REQUESTED {
            return Err("Too many requested decompilations".into());
        }
        parse_hex(&request.load_base)?;
        for requested in &request.requested {
            parse_hex(&requested.va)?;
            parse_hex(&requested.rva)?;
        }
        Ok(request)
    }
}

/// One analyzed input: a corpus build or a trusted external ELF.
pub struct Case {
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub load_base: u64,
    pub requested: Vec<Requested>,
    /// Ground-truth document, absent for external inputs.
    pub truth: Option<Value>,
    pub build: Value,
}

fn command_output(command: &mut Command) -> Result<String, String> {
    let output = command
        .env("LC_ALL", "C")
        .output()
        .map_err(|error| format!("Cannot run {command:?}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{command:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{command:?} printed non-UTF-8 output"))
}

pub fn tool_version(tool: &str) -> String {
    command_output(Command::new(tool).arg("--version"))
        .map(|text| text.lines().next().unwrap_or_default().to_owned())
        .unwrap_or_else(|error| format!("unavailable: {error}"))
}

#[derive(Clone, Debug)]
struct Symbol {
    address: u64,
    size: u64,
    names: Vec<String>,
    binding: &'static str,
}

const SHF_ALLOC: u64 = 2;

/// Name, address, size and contents of an `SHF_ALLOC` section.
type AllocatedSection = (String, u64, u64, Vec<u8>);
/// Direct (source, destination) call RVAs and per-function construct features.
type ObjdumpEvidence = (Vec<(u64, u64)>, BTreeMap<u64, Value>);

fn allocated_sections(image: &object::File<'_>) -> Result<Vec<AllocatedSection>, String> {
    let mut sections = Vec::new();
    for section in image.sections() {
        let SectionFlags::Elf { sh_flags } = section.flags() else {
            return Err("Expected ELF section flags".into());
        };
        if sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        let data = section
            .data()
            .map_err(|error| format!("Unreadable section: {error}"))?;
        sections.push((
            section.name().unwrap_or_default().to_owned(),
            section.address(),
            section.size(),
            data.to_vec(),
        ));
    }
    Ok(sections)
}

/// Checks the properties every analyzed input must satisfy and returns the
/// minimum PT_LOAD virtual address, which anchors canonical RVAs.
pub fn load_base(bytes: &[u8]) -> Result<u64, String> {
    let image = object::File::parse(bytes).map_err(|error| format!("Not an object: {error}"))?;
    if image.format() != object::BinaryFormat::Elf
        || image.architecture() != object::Architecture::X86_64
    {
        return Err("The differential benchmark currently supports x86-64 ELF only".into());
    }
    image
        .segments()
        .map(|segment| segment.address())
        .min()
        .ok_or_else(|| "ELF image has no PT_LOAD segments".into())
}

fn rva(address: u64, base: u64) -> Result<u64, String> {
    address
        .checked_sub(base)
        .ok_or_else(|| format!("Address {address:#x} precedes the load base"))
}

/// Extracts defined function symbols, merging aliases at one address.
fn function_symbols(image: &object::File<'_>) -> Result<Vec<Symbol>, String> {
    let executable: BTreeSet<_> = image
        .sections()
        .filter(|section| section.kind() == object::SectionKind::Text)
        .map(|section| section.index().0)
        .collect();
    let mut by_address: BTreeMap<u64, Symbol> = BTreeMap::new();
    for symbol in image.symbols() {
        if symbol.kind() != SymbolKind::Text || !symbol.is_definition() {
            continue;
        }
        let Some(section) = symbol.section_index() else {
            continue;
        };
        if !executable.contains(&section.0) {
            continue;
        }
        let name = symbol
            .name()
            .map_err(|_| "Non-UTF-8 symbol name".to_string())?
            .to_owned();
        let binding = if symbol.is_weak() {
            "weak"
        } else if symbol.is_global() {
            "global"
        } else {
            "local"
        };
        let entry = by_address.entry(symbol.address()).or_insert(Symbol {
            address: symbol.address(),
            size: symbol.size(),
            names: Vec::new(),
            binding,
        });
        entry.size = entry.size.max(symbol.size());
        entry.names.push(name);
    }
    for symbol in by_address.values_mut() {
        symbol.names.sort();
    }
    Ok(by_address.into_values().collect())
}

fn scope(names: &[String]) -> &'static str {
    if names
        .iter()
        .any(|name| name == "main" || name.starts_with("bench_"))
    {
        "primary"
    } else if names
        .iter()
        .any(|name| RUNTIME_FUNCTIONS.contains(&name.as_str()))
    {
        "runtime"
    } else {
        "other"
    }
}

/// Direct calls and per-function construct diagnostics decoded by GNU objdump,
/// an independent decoder. Only direct `call` operands become call truth.
fn objdump_evidence(
    path: &Path,
    base: u64,
    primary: &[(u64, u64)],
    entries: &BTreeSet<u64>,
) -> Result<ObjdumpEvidence, String> {
    let text = command_output(
        Command::new("objdump")
            .args(["-d", "-w", "--no-show-raw-insn"])
            .arg(path),
    )?;
    let containing = |pc: u64| {
        primary
            .iter()
            .find(|(start, size)| pc >= *start && pc - start < *size)
            .map(|(start, _)| *start)
    };
    let mut calls = BTreeSet::new();
    let mut features: BTreeMap<u64, (bool, bool, BTreeSet<u64>)> = BTreeMap::new();
    for line in text.lines() {
        let Some((pc, instruction)) = line.trim().split_once(':') else {
            continue;
        };
        let Ok(pc) = u64::from_str_radix(pc, 16) else {
            continue;
        };
        let Some(owner) = containing(pc) else {
            continue;
        };
        let mut fields = instruction.split_whitespace();
        let Some(mnemonic) = fields.next() else {
            continue;
        };
        let operand = fields.next().unwrap_or_default();
        let feature = features.entry(owner).or_default();
        match mnemonic {
            "call" | "callq" if operand.starts_with('*') => feature.1 = true,
            "call" | "callq" => {
                let target = u64::from_str_radix(operand, 16)
                    .map_err(|_| format!("Unexpected objdump call operand {operand:?}"))?;
                calls.insert((rva(pc, base)?, rva(target, base)?));
            }
            "jmp" | "jmpq" if operand.starts_with('*') => feature.0 = true,
            "jmp" | "jmpq" => {
                if let Ok(target) = u64::from_str_radix(operand, 16)
                    && target != owner
                    && entries.contains(&target)
                {
                    feature.2.insert(rva(target, base)?);
                }
            }
            _ => {}
        }
    }
    let features = features
        .into_iter()
        .map(|(owner, (indirect_jump, indirect_call, tails))| {
            Ok((
                rva(owner, base)?,
                json!({
                    "indirect_jump": indirect_jump,
                    "indirect_call": indirect_call,
                    "tail_jump_targets": tails.into_iter().map(hex).collect::<Vec<_>>(),
                }),
            ))
        })
        .collect::<Result<_, String>>()?;
    Ok((calls.into_iter().collect(), features))
}

/// Ground truth from the unstripped build, bound to both file hashes.
fn truth(
    case_id: &str,
    unstripped: &Path,
    stripped_sha256: &str,
) -> Result<(Value, Vec<Requested>), String> {
    let bytes = fs::read(unstripped).map_err(|e| e.to_string())?;
    let base = load_base(&bytes)?;
    let image = object::File::parse(bytes.as_slice()).map_err(|e| e.to_string())?;
    let symbols = function_symbols(&image)?;
    let mut sections = Vec::new();
    let mut plt = Vec::new();
    for section in image.sections() {
        if section.kind() != object::SectionKind::Text {
            continue;
        }
        let name = section.name().unwrap_or_default();
        let (offset, _) = section
            .file_range()
            .ok_or("Executable section is not file-backed")?;
        let record = json!({
            "name": name, "rva": hex(rva(section.address(), base)?),
            "size": section.size(), "file_offset": offset,
        });
        if name.starts_with(".plt") {
            plt.push(record.clone());
        }
        sections.push(record);
    }
    let primary: Vec<_> = symbols
        .iter()
        .filter(|symbol| scope(&symbol.names) == "primary" && symbol.size > 0)
        .map(|symbol| (symbol.address, symbol.size))
        .collect();
    let entries: BTreeSet<_> = symbols.iter().map(|symbol| symbol.address).collect();
    let (calls, features) = objdump_evidence(unstripped, base, &primary, &entries)?;
    let mut functions = Vec::new();
    for symbol in &symbols {
        let at = rva(symbol.address, base)?;
        functions.push(json!({
            "rva": hex(at), "size": symbol.size, "names": symbol.names,
            "binding": symbol.binding, "scope": scope(&symbol.names),
            "features": features.get(&at),
        }));
    }
    // Every authored construct function plus evenly spaced members of the
    // 300-function bank, chosen before either tool runs.
    let named = |symbol: &&Symbol| {
        symbol.names.iter().any(|name| {
            name == "main"
                || (name.starts_with("bench_")
                    && !name.starts_with("bench_many_")
                    && !name.contains('.'))
        }) || symbol
            .names
            .iter()
            .any(|name| name == "bench_many_dispatch")
    };
    let mut requested: Vec<_> = symbols.iter().filter(named).collect();
    let bank: Vec<_> = symbols
        .iter()
        .filter(|symbol| {
            symbol.names.iter().any(|name| {
                name.strip_prefix("bench_many_")
                    .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
            })
        })
        .collect();
    let remaining = MAX_REQUESTED.saturating_sub(requested.len());
    if remaining > 0 && !bank.is_empty() {
        for index in 0..remaining.min(bank.len()) {
            requested.push(bank[index * bank.len() / remaining.min(bank.len())]);
        }
    }
    requested.truncate(MAX_REQUESTED);
    let requested = requested
        .into_iter()
        .map(|symbol| {
            Ok(Requested {
                va: hex(symbol.address),
                rva: hex(rva(symbol.address, base)?),
                label: symbol.names.first().cloned(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let truth = json!({
        "schema_version": SCHEMA_VERSION, "document_type": "ground_truth",
        "case_id": case_id, "unstripped_sha256": ghidra_rust::session::fingerprint(unstripped)?,
        "stripped_sha256": stripped_sha256, "load_base": hex(base),
        "entry_rva": hex(rva(image.entry(), base)?),
        "executable_sections": sections, "plt_sections": plt,
        "functions": functions,
        "calls": calls.iter().map(|(from, to)| json!({"from_rva": hex(*from), "target_rva": hex(*to)})).collect::<Vec<_>>(),
        "requested": requested,
        "source": "unstripped .symtab STT_FUNC definitions and GNU objdump direct calls",
    });
    Ok((truth, requested))
}

/// Stripping must leave every allocated section and the entry point in place,
/// so truth from the unstripped build applies to the stripped file.
fn verify_strip_correspondence(unstripped: &Path, stripped: &Path) -> Result<(), String> {
    let a = fs::read(unstripped).map_err(|e| e.to_string())?;
    let b = fs::read(stripped).map_err(|e| e.to_string())?;
    let a = object::File::parse(a.as_slice()).map_err(|e| e.to_string())?;
    let b = object::File::parse(b.as_slice()).map_err(|e| e.to_string())?;
    if a.entry() != b.entry() || allocated_sections(&a)? != allocated_sections(&b)? {
        return Err("Stripping changed allocated sections or the entry point".into());
    }
    if b.symbols().next().is_some() {
        return Err("Stripped input still contains .symtab symbols".into());
    }
    Ok(())
}

fn admit(path: &Path) -> Result<(String, u64, u64), String> {
    let bytes = fs::metadata(path).map_err(|e| e.to_string())?.len();
    if bytes > MAX_INPUT_BYTES {
        return Err(format!("{} exceeds the 128 MiB limit", path.display()));
    }
    let base = load_base(&fs::read(path).map_err(|e| e.to_string())?)?;
    Ok((ghidra_rust::session::fingerprint(path)?, bytes, base))
}

/// Builds the four GCC configurations, each unstripped and stripped.
pub fn corpus(directory: &Path, selected: Option<&str>) -> Result<(Vec<Case>, Value), String> {
    let gcc = tool_version("gcc");
    let mut cases = Vec::new();
    let mut commands = Vec::new();
    for (optimization, pie) in [("O0", false), ("O0", true), ("O2", false), ("O2", true)] {
        let config = format!("{optimization}-{}", if pie { "pie" } else { "nopie" });
        let ids = [format!("{config}-symbols"), format!("{config}-stripped")];
        if selected.is_some_and(|wanted| !ids.iter().any(|id| id == wanted)) {
            continue;
        }
        let unstripped = directory.join(&ids[0]);
        let stripped = directory.join(&ids[1]);
        let mut args: Vec<String> = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
            .into_iter()
            .map(String::from)
            .collect();
        args.push(format!("-{optimization}"));
        args.extend(
            if pie {
                ["-fPIE", "-pie"]
            } else {
                ["-fno-pie", "-no-pie"]
            }
            .map(String::from),
        );
        args.extend(SOURCES.map(String::from));
        args.push("-o".into());
        args.push(unstripped.to_string_lossy().into_owned());
        command_output(Command::new("gcc").args(&args))?;
        command_output(
            Command::new("strip")
                .args(["--strip-all", "-o"])
                .arg(&stripped)
                .arg(&unstripped),
        )?;
        verify_strip_correspondence(&unstripped, &stripped)?;
        commands.push(json!({"config": config, "gcc_args": args,
            "strip": ["strip", "--strip-all", "-o", "<stripped>", "<unstripped>"]}));
        let (stripped_sha256, _, _) = admit(&stripped)?;
        let (truth, requested) = truth(&config, &unstripped, &stripped_sha256)?;
        for (id, path) in [(&ids[0], &unstripped), (&ids[1], &stripped)] {
            if selected.is_some_and(|wanted| wanted != id) {
                continue;
            }
            let (sha256, bytes, load_base) = admit(path)?;
            cases.push(Case {
                id: id.clone(),
                path: path.clone(),
                sha256,
                bytes,
                load_base,
                requested: requested.clone(),
                truth: Some(truth.clone()),
                build: json!({"config": config, "stripped": path == &stripped}),
            });
        }
    }
    let provenance = json!({
        "gcc": gcc, "strip": tool_version("strip"), "objdump": tool_version("objdump"),
        "sources": SOURCES.iter().map(|source| Ok(json!({
            "path": Path::new(source).strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(Path::new(source)),
            "sha256": ghidra_rust::session::fingerprint(Path::new(source))?,
        }))).collect::<Result<Vec<_>, String>>()?,
        "commands": commands,
    });
    Ok((cases, provenance))
}

/// A trusted external x86-64 ELF selected by the analyst. It is read, hashed
/// and analyzed in place; nothing is written to it.
pub fn external(path: &Path, addresses: Option<&str>) -> Result<Case, String> {
    let path = path
        .canonicalize()
        .map_err(|error| format!("Cannot resolve external input: {error}"))?;
    let (sha256, bytes, base) = admit(&path)?;
    let image_bytes = fs::read(&path).map_err(|e| e.to_string())?;
    let image = object::File::parse(image_bytes.as_slice()).map_err(|e| e.to_string())?;
    let addresses: Vec<u64> = match addresses {
        Some(list) => list
            .split(',')
            .map(|address| parse_hex(address.trim()))
            .collect::<Result<_, _>>()?,
        None => vec![image.entry()],
    };
    if addresses.is_empty() || addresses.len() > MAX_REQUESTED {
        return Err(format!("Select 1–{MAX_REQUESTED} addresses"));
    }
    let requested = addresses
        .into_iter()
        .map(|va| {
            Ok(Requested {
                va: hex(va),
                rva: hex(rva(va, base)?),
                label: None,
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(Case {
        id: "external".into(),
        path,
        sha256,
        bytes,
        load_base: base,
        requested,
        truth: None,
        build: json!({"config": "external", "stripped": null}),
    })
}
