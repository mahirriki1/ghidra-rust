//! Portable project snapshots. Cached analysis is data, never executable SQL or code.
//!
//! A project stores a bounded current-function cache, annotations, and optionally
//! the exact analyzed input. The decompiler's internal database is rebuilt on open.
use crate::discovery::{DISCOVERY_FINGERPRINT, DiscoverySnapshot};
use crate::model::{
    BinaryInfo, CodeMapping, CryptoMatch, EdgeKind, FunctionView, MAX_CRYPTO_MATCHES,
    MAX_DECOMPILED_BYTES, MAX_GRAPH_BLOCKS, MAX_GRAPH_CALLS, MAX_GRAPH_EDGES,
    MAX_GRAPH_INSTRUCTIONS, MAX_INSTRUCTION_BYTES, MAX_PROJECT_STRINGS, MAX_SECTIONS, MAX_WARNINGS,
    SectionInfo, StringEntry, validate_functions,
};
use crate::selection::{MappedRanges, validate_mappings};
use crate::session::{self, BinaryProtection, Session};
use rusqlite::{Connection, OpenFlags, OptionalExtension, config::DbConfig, limits::Limit, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const APPLICATION_ID: i64 = 0x4752504a; // GRPJ
/// Version 3 adds semantic tokens and local renames; versions 1/2 still open.
const VERSION: i64 = 3;
pub const ENGINE_FINGERPRINT: &str = "ghidra-rust-project-v3-semantic-v1-mapping-v1-pe-v1-aarch64-v1-calls-v1-arm64pe-v1-inventory-v2-elfcrt-v1-switch-v1-noreturn-v1:268c3a406d8d964bc00ae2ead4d3e1e1373aaa27";
const MAX_BINARY: usize = 128 * 1024 * 1024;
const MAX_BODY: usize = 48 * 1024 * 1024;
const MAX_PROJECT: u64 = 224 * 1024 * 1024;
/// A full function inventory uses about 1.3 million metadata nodes.
const MAX_JSON_NODES: usize = 3_000_000;
const SCHEMA: &str = "CREATE TABLE project_data (key TEXT NOT NULL, value BLOB NOT NULL)";

#[derive(Clone, Debug)]
pub struct ProjectData {
    pub info: BinaryInfo,
    pub session: Session,
    pub view: Option<FunctionView>,
    pub decompiled: Option<String>,
    pub mappings: Vec<CodeMapping>,
    pub semantics: crate::semantic::SemanticInfo,
    pub strings: Vec<StringEntry>,
    pub strings_truncated: bool,
    pub crypto: Vec<CryptoMatch>,
    pub crypto_truncated: bool,
    pub selected_address: Option<u64>,
    /// Shared with the desktop so capturing a save never copies the evidence.
    pub discovery: Option<Arc<DiscoverySnapshot>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    engine: String,
    #[serde(default)]
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { crate::model::MAX_CODE_MAPPINGS }>")]
    mappings: Vec<CodeMapping>,
    #[serde(default)]
    semantics: crate::semantic::SemanticInfo,
    info: BinaryInfo,
    view: Option<FunctionView>,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_PROJECT_STRINGS }>")]
    strings: Vec<StringEntry>,
    strings_truncated: bool,
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, { MAX_CRYPTO_MATCHES }>")]
    crypto: Vec<CryptoMatch>,
    crypto_truncated: bool,
    selected_address: Option<u64>,
}

/// Owns the private extracted input until the last worker using it is stopped.
#[derive(Clone, Debug)]
pub struct EmbeddedBinary {
    path: Arc<tempfile::TempPath>,
}
impl EmbeddedBinary {
    pub fn path(&self) -> &Path {
        self.path.as_ref().as_ref()
    }
}

#[derive(Debug)]
pub struct LoadedProject {
    pub data: ProjectData,
    pub binary: Option<EmbeddedBinary>,
    /// Display-only. An external input must be explicitly selected by the user.
    pub source_hint: String,
    pub cache_compatible: bool,
}

impl ProjectData {
    pub fn save(
        &self,
        path: &Path,
        protection: &BinaryProtection,
        embed_binary: bool,
    ) -> Result<(), String> {
        self.validate()?;
        if let Some(discovery) = &self.discovery {
            discovery.validate(&self.info)?;
        }
        protection.ensure_bound(&self.info.sha256)?;
        protection.verify_identity(&self.info)?;
        // Check both modes against the immutable worker fingerprint. An external
        // reference to an already modified file would otherwise be unreopenable.
        let image = protection.verified_snapshot()?;
        if image.len() as u64 != self.info.file_len {
            return Err("Binary length changed after analysis".into());
        }
        let mut persisted_info = self.info.clone();
        persisted_info.source_identity = None; // live file identities are not portable capabilities
        let body = Body {
            engine: ENGINE_FINGERPRINT.into(),
            mappings: self.mappings.clone(),
            semantics: self.semantics.clone(),
            info: persisted_info,
            view: self.view.clone(),
            strings: self.strings.clone(),
            strings_truncated: self.strings_truncated,
            crypto: self.crypto.clone(),
            crypto_truncated: self.crypto_truncated,
            selected_address: self.selected_address,
        };
        let body = encode(&body, MAX_BODY)?;
        check_json_budget(&body)?;
        // Metadata and discovery share one decoded-JSON budget.
        let discovery = self
            .discovery
            .as_ref()
            .map(|discovery| encode(&**discovery, MAX_BODY - body.len()))
            .transpose()?;
        if let Some(discovery) = &discovery {
            check_json_budget(discovery)?;
        }
        let annotations = encode(&self.session, session::MAX_SESSION_BYTES as usize)?;
        let destination = session::safe_destination(path, protection)?;
        protect_binary_destination(&destination, &self.info)?;
        let directory = destination
            .parent()
            .ok_or("Project path has no directory")?;
        let (temporary, file) = session::create_temporary(
            directory,
            destination
                .file_name()
                .ok_or("Project path must name a file")?,
        )?;
        drop(file);
        let result = (|| {
            let mut db = Connection::open_with_flags(
                &temporary,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .map_err(sql_error)?;
            configure(&db, false)?;
            db.execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA temp_store=MEMORY;",
            )
            .map_err(sql_error)?;
            db.pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(sql_error)?;
            db.pragma_update(None, "user_version", VERSION)
                .map_err(sql_error)?;
            db.execute_batch(SCHEMA).map_err(sql_error)?;
            let transaction = db.transaction().map_err(sql_error)?;
            for (key, value) in [
                ("body", body.as_slice()),
                ("annotations", annotations.as_slice()),
            ] {
                transaction
                    .execute(
                        "INSERT INTO project_data (key,value) VALUES (?1,?2)",
                        params![key, value],
                    )
                    .map_err(sql_error)?;
            }
            if let Some(discovery) = &discovery {
                transaction
                    .execute(
                        "INSERT INTO project_data (key,value) VALUES ('discovery',?1)",
                        params![discovery],
                    )
                    .map_err(sql_error)?;
            }
            if let Some(text) = &self.decompiled {
                transaction
                    .execute(
                        "INSERT INTO project_data (key,value) VALUES ('decompiled',?1)",
                        params![text.as_bytes()],
                    )
                    .map_err(sql_error)?;
            }
            if embed_binary {
                transaction
                    .execute(
                        "INSERT INTO project_data (key,value) VALUES ('binary',?1)",
                        params![&image],
                    )
                    .map_err(sql_error)?;
            }
            transaction.commit().map_err(sql_error)?;
            db.close().map_err(|(_, error)| sql_error(error))?;
            verify_written_database(&temporary)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&temporary)
                .map_err(|e| format!("Cannot reopen project: {e}"))?;
            #[cfg(unix)]
            if let Ok(metadata) = fs::symlink_metadata(&destination) {
                use std::os::unix::fs::PermissionsExt;
                file.set_permissions(fs::Permissions::from_mode(
                    metadata.permissions().mode() & 0o600,
                ))
                .map_err(|e| format!("Cannot protect project: {e}"))?;
            }
            file.sync_all()
                .map_err(|e| format!("Cannot sync project: {e}"))?;
            drop(file);
            session::safe_destination(&destination, protection)?;
            protect_binary_destination(&destination, &self.info)?;
            session::atomic_replace(&temporary, &destination)
                .map_err(|e| format!("Cannot replace project: {e}"))?;
            if let Ok(file) = File::open(directory) {
                let _ = file.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
            // SQLite rolls back on close. Remove only generated companion names.
            let _ = fs::remove_file(format!("{}-journal", temporary.display()));
        }
        result
    }

    pub fn load(path: &Path) -> Result<LoadedProject, String> {
        // Read a private bounded copy: SQLite must not follow attacker-controlled
        // journals, race concurrent edits, or open a FIFO through a replaced path.
        let file = session::open_regular_file(path, MAX_PROJECT)?;
        let mut snapshot = tempfile::NamedTempFile::new()
            .map_err(|e| format!("Cannot create private project snapshot: {e}"))?;
        let copied = std::io::copy(&mut file.take(MAX_PROJECT + 1), snapshot.as_file_mut())
            .map_err(|e| format!("Cannot snapshot project: {e}"))?;
        if copied > MAX_PROJECT {
            return Err("Project exceeds the 224 MiB size limit".into());
        }
        snapshot
            .flush()
            .map_err(|e| format!("Cannot flush project snapshot: {e}"))?;
        let uri = immutable_uri(snapshot.path())?;
        let db = Connection::open_with_flags(
            uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(sql_error)?;
        configure(&db, true)?;
        let version = verify_database(&db)?;
        let body_bytes = read_blob(&db, "body", MAX_BODY)?.ok_or("Project metadata is missing")?;
        check_json_budget(&body_bytes)?;
        let body: Body = serde_json::from_slice(&body_bytes)
            .map_err(|e| format!("Invalid project metadata: {e}"))?;
        // Version 1 never recorded discovery; absence is not "never analyzed".
        let discovery = if version >= 2 {
            read_blob(&db, "discovery", MAX_BODY - body_bytes.len())?
        } else {
            None
        };
        let discovery = discovery
            .map(|bytes| {
                check_json_budget(&bytes)?;
                serde_json::from_slice::<DiscoverySnapshot>(&bytes)
                    .map_err(|e| format!("Invalid saved discovery: {e}"))
            })
            .transpose()?;
        let annotations = read_blob(&db, "annotations", session::MAX_SESSION_BYTES as usize)?
            .ok_or("Project annotations are missing")?;
        let session: Session = serde_json::from_slice(&annotations)
            .map_err(|e| format!("Invalid project annotations: {e}"))?;
        let decompiled = read_blob(&db, "decompiled", MAX_DECOMPILED_BYTES)?
            .map(String::from_utf8)
            .transpose()
            .map_err(|_| "Project decompilation is not UTF-8")?;
        let source_hint = body.info.path.clone();
        let compatible = body.engine == ENGINE_FINGERPRINT
            && body
                .semantics
                .locals
                .iter()
                .all(|v| v.identity.engine == crate::semantic::LOCAL_FINGERPRINT);
        let mut data = ProjectData {
            info: body.info,
            session,
            view: body.view,
            decompiled,
            mappings: body.mappings,
            semantics: body.semantics,
            strings: body.strings,
            strings_truncated: body.strings_truncated,
            crypto: body.crypto,
            crypto_truncated: body.crypto_truncated,
            selected_address: body.selected_address,
            discovery: None,
        };
        data.validate()?;
        // A different engine or discovery format discards only saved discovery.
        if let Some(discovery) = discovery
            && compatible
            && discovery.fingerprint == DISCOVERY_FINGERPRINT
        {
            discovery.validate(&data.info)?;
            data.discovery = Some(Arc::new(discovery));
        }
        let binary = if let Some((rowid, length)) = blob_properties(&db, "binary", MAX_BINARY)? {
            if length as u64 != data.info.file_len {
                return Err("Embedded binary length does not match project metadata".into());
            }
            let mut file = tempfile::NamedTempFile::new()
                .map_err(|e| format!("Cannot create private embedded binary: {e}"))?;
            let mut blob = db
                .blob_open("main", "project_data", "value", rowid, true)
                .map_err(sql_error)?;
            let mut hash = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            let mut copied = 0usize;
            loop {
                let length = blob
                    .read(&mut buffer)
                    .map_err(|e| format!("Cannot read embedded binary: {e}"))?;
                if length == 0 {
                    break;
                }
                copied = copied
                    .checked_add(length)
                    .ok_or("Embedded binary size overflow")?;
                bounded(copied, MAX_BINARY, "Embedded binary")?;
                hash.update(&buffer[..length]);
                file.write_all(&buffer[..length])
                    .map_err(|e| format!("Cannot extract embedded binary: {e}"))?;
            }
            if copied != length || format!("{:x}", hash.finalize()) != data.info.sha256 {
                return Err(
                    "Embedded binary does not match the project SHA-256 fingerprint".into(),
                );
            }
            file.flush()
                .map_err(|e| format!("Cannot flush embedded binary: {e}"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                file.as_file()
                    .set_permissions(fs::Permissions::from_mode(0o400))
                    .map_err(|e| format!("Cannot protect embedded binary: {e}"))?;
            }
            // Close the writable handle before Windows opens a deny-write guard.
            Some(EmbeddedBinary {
                path: Arc::new(file.into_temp_path()),
            })
        } else {
            None
        };
        // A different engine can reuse annotations, but must regenerate analysis.
        if !compatible {
            data.view = None;
            data.decompiled = None;
            data.mappings.clear();
            data.semantics = Default::default();
            data.strings.clear();
            data.crypto.clear();
        }
        data.info.source_identity = None;
        Ok(LoadedProject {
            data,
            binary,
            source_hint,
            cache_compatible: compatible,
        })
    }

    fn validate(&self) -> Result<(), String> {
        // Legacy projects allowed 4 KiB names and no aggregate name budget.
        let ranges = validate_info(&self.info, 4096, false)?;
        self.session.validate_ranges_with(&ranges)?;
        let executable = crate::selection::ExecutableRanges::new(&self.info.sections)?;
        if self
            .session
            .local_renames
            .iter()
            .any(|r| !executable.contains(r.identity.function))
        {
            return Err("Local rename function is not executable file-backed code".into());
        }
        if self.info.sha256 != self.session.binary_sha256 {
            return Err("Project metadata and annotation fingerprints differ".into());
        }
        if let Some(address) = self.selected_address {
            mapped(&ranges, address)?;
        }
        if self
            .decompiled
            .as_ref()
            .is_some_and(|s| s.len() > MAX_DECOMPILED_BYTES)
        {
            return Err("Decompilation exceeds the 2 MiB size limit".into());
        }
        if let Some(text) = &self.decompiled {
            validate_mappings(text, &self.mappings, &self.info.sections)?;
            self.semantics.validate(
                text,
                self.view
                    .as_ref()
                    .ok_or("Semantic cache has no function")?
                    .address,
                &self.info.sections,
            )?;
        } else if !self.mappings.is_empty()
            || !self.semantics.tokens.is_empty()
            || !self.semantics.locals.is_empty()
            || !self.semantics.warnings.is_empty()
        {
            return Err("Decompiler mappings have no corresponding text".into());
        }
        if self.decompiled.is_some() && self.view.is_none() {
            return Err("Decompilation has no corresponding function view".into());
        }
        validate_strings(&self.strings, MAX_PROJECT_STRINGS, &ranges)?;
        validate_crypto(&self.crypto, &ranges)?;
        if let Some(view) = &self.view {
            validate_view(view, &ranges, &self.info)?;
            // Saved graphs have always required mapped exits and call sites.
            for edge in &view.edges {
                if let Some(target) = edge.target {
                    mapped(&ranges, target)?;
                }
            }
            for call in &view.calls {
                mapped(&ranges, call.address)?;
                if let Some(target) = call.target {
                    mapped(&ranges, target)?;
                }
            }
        }
        Ok(())
    }

    /// Compare persisted mapping metadata with a fresh parse of the chosen input.
    pub fn validate_against(&self, actual: &BinaryInfo) -> Result<(), String> {
        self.validate()?;
        let a = &self.info;
        if a.sha256 != actual.sha256
            || a.file_len != actual.file_len
            || a.architecture != actual.architecture
            || a.format != actual.format
            || a.entry != actual.entry
            || a.sections.len() != actual.sections.len()
            || !a.sections.iter().zip(&actual.sections).all(|(a, b)| {
                a.name == b.name
                    && a.address == b.address
                    && a.size == b.size
                    && a.file_offset == b.file_offset
                    && a.file_size == b.file_size
                    && a.executable == b.executable
            })
        {
            return Err("Project metadata does not match the freshly analyzed binary".into());
        }
        Ok(())
    }
}

/// An embedded project's live guard protects its private extracted image. Also
/// reject the original pathname and any chosen destination containing the same
/// binary bytes; this never follows or automatically opens the saved source hint.
pub(crate) fn protect_binary_destination(
    destination: &Path,
    info: &BinaryInfo,
) -> Result<(), String> {
    #[cfg(windows)]
    crate::windows::validate_local_path(destination)
        .map_err(|e| format!("Cannot save project: {e}"))?;
    let hint = Path::new(&info.path);
    #[cfg(not(windows))]
    let same_hint = hint.is_absolute() && hint == destination;
    #[cfg(windows)]
    let same_hint = hint.is_absolute()
        && hint
            .to_string_lossy()
            .trim_start_matches(r"\\?\")
            .eq_ignore_ascii_case(destination.to_string_lossy().trim_start_matches(r"\\?\"));
    if same_hint {
        return Err("Cannot save a project over the original input binary pathname".into());
    }
    match fs::symlink_metadata(destination) {
        Ok(metadata) if metadata.is_file() && metadata.len() == info.file_len => {
            let file = session::open_regular_file(destination, MAX_BINARY as u64)?;
            let mut hash = Sha256::new();
            let mut bytes = [0u8; 64 * 1024];
            let mut reader = file.take(MAX_BINARY as u64 + 1);
            let mut count = 0u64;
            loop {
                let length = reader
                    .read(&mut bytes)
                    .map_err(|e| format!("Cannot inspect project destination: {e}"))?;
                if length == 0 {
                    break;
                }
                count += length as u64;
                if count > MAX_BINARY as u64 {
                    return Err("Project destination changed during validation".into());
                }
                hash.update(&bytes[..length]);
            }
            if count == info.file_len && format!("{:x}", hash.finalize()) == info.sha256 {
                return Err(
                    "Cannot save a project over a file containing the original input binary".into(),
                );
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Cannot inspect project destination: {error}")),
    }
    Ok(())
}

/// Returns the accepted project version.
fn verify_database(db: &Connection) -> Result<i64, String> {
    let application: i64 = db
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(sql_error)?;
    let version: i64 = db
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(sql_error)?;
    if application != APPLICATION_ID {
        return Err("File is not a Ghidra Rust project".into());
    }
    if !(1..=VERSION).contains(&version) {
        return Err(format!(
            "Unsupported project version {version} (expected 1 to {VERSION})"
        ));
    }
    // No views, virtual tables, triggers, generated columns, or attacker SQL.
    // Only this exact ordinary table definition is accepted before reading it.
    let schema: Vec<(String, String, String, String)> = {
        let mut statement = db.prepare("SELECT type,name,tbl_name,CASE WHEN length(sql)<=512 THEN sql ELSE NULL END FROM sqlite_schema LIMIT 2").map_err(sql_error)?;
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(sql_error)?
            .collect::<rusqlite::Result<_>>()
            .map_err(sql_error)?
    };
    if schema
        != vec![(
            "table".into(),
            "project_data".into(),
            "project_data".into(),
            SCHEMA.into(),
        )]
    {
        return Err("Project has an unsupported or unsafe database schema".into());
    }

    // Read at most one key beyond the version's record limit. Check their type
    // and length inside SQL before any Rust String allocation or
    // DISTINCT/ordering over attacker-sized keys.
    let records = if version >= 2 { 5 } else { 4 };
    let mut statement=db.prepare("SELECT typeof(key),length(key),CASE WHEN typeof(key)='text' AND length(key)<=16 THEN key ELSE NULL END FROM project_data LIMIT 6").map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut keys = std::collections::BTreeSet::new();
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql_error)? {
        count += 1;
        if count > records {
            return Err("Project contains an invalid record count".into());
        }
        let kind: String = row.get(0).map_err(sql_error)?;
        let length: i64 = row.get(1).map_err(sql_error)?;
        if kind != "text" || !(1..=16).contains(&length) {
            return Err("Project record key has an invalid type or size".into());
        }
        let key: String = row.get(2).map_err(sql_error)?;
        if !matches!(
            key.as_str(),
            "body" | "annotations" | "decompiled" | "binary"
        ) && !(version >= 2 && key == "discovery")
        {
            return Err("Project contains unsupported records".into());
        }
        if !keys.insert(key) {
            return Err("Project contains duplicate records".into());
        }
    }
    if !keys.contains("body") || !keys.contains("annotations") {
        return Err("Project metadata or annotations are missing".into());
    }
    Ok(version)
}

fn verify_written_database(path: &Path) -> Result<(), String> {
    let file = session::open_regular_file(path, MAX_PROJECT)?;
    let mut header = [0u8; 16];
    (&file)
        .read_exact(&mut header)
        .map_err(|e| format!("Cannot verify written project: {e}"))?;
    if &header != b"SQLite format 3\0" {
        return Err("Written project has an invalid SQLite header".into());
    }
    let db = Connection::open_with_flags(
        immutable_uri(path)?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(sql_error)?;
    configure(&db, true)?;
    verify_database(&db)?;
    for (key, limit) in [
        ("body", MAX_BODY),
        ("discovery", MAX_BODY),
        ("annotations", session::MAX_SESSION_BYTES as usize),
        ("decompiled", MAX_DECOMPILED_BYTES),
        ("binary", MAX_BINARY),
    ] {
        blob_properties(&db, key, limit)?;
    }
    Ok(())
}

/// Binary metadata bounds shared by projects and worker `Opened` replies.
/// Counts and sections are checked before any per-element address work; the
/// returned intervals make each later address check logarithmic.
pub(crate) fn validate_info(
    info: &BinaryInfo,
    max_name_bytes: usize,
    name_budget: bool,
) -> Result<MappedRanges, String> {
    bounded(info.sections.len(), MAX_SECTIONS, "Section count")?;
    bounded(info.warnings.len(), MAX_WARNINGS, "Warning count")?;
    if info.file_len > MAX_BINARY as u64 {
        return Err("Binary exceeds the 128 MiB size limit".into());
    }
    bounded(info.path.len(), 32 * 1024, "Source hint")?;
    bounded(info.architecture.len(), 128, "Architecture")?;
    bounded(info.format.len(), 128, "Binary format")?;
    bounded(info.sha256.len(), 64, "Binary fingerprint")?;
    for warning in &info.warnings {
        bounded(warning.len(), 4096, "Warning text")?;
    }
    let mut previous_end = None;
    for section in &info.sections {
        bounded(section.name.len(), 4096, "Section name")?;
        let end = section
            .address
            .checked_add(section.size)
            .ok_or("Section address overflows")?;
        let file_end = section
            .file_offset
            .checked_add(section.file_size)
            .ok_or("Section file range overflows")?;
        if file_end > info.file_len || section.file_size > section.size {
            return Err("Section exceeds the binary bounds".into());
        }
        // The loader publishes ordered, non-overlapping sections.
        if previous_end.is_some_and(|previous| previous > section.address) {
            return Err("Sections are unordered or overlapping".into());
        }
        previous_end = Some(end);
    }
    let ranges = MappedRanges::new(&info.sections)?;
    validate_functions(&info.functions, max_name_bytes, name_budget)?;
    for function in &info.functions {
        mapped(&ranges, function.address)?;
    }
    Ok(ranges)
}

pub(crate) fn validate_strings(
    strings: &[StringEntry],
    maximum: usize,
    ranges: &MappedRanges,
) -> Result<(), String> {
    bounded(strings.len(), maximum, "String count")?;
    for string in strings {
        bounded(string.text.len(), 4096, "String text")?;
        bounded(string.encoding.len(), 64, "String encoding")?;
        mapped(ranges, string.address)?;
    }
    Ok(())
}

pub(crate) fn validate_crypto(crypto: &[CryptoMatch], ranges: &MappedRanges) -> Result<(), String> {
    bounded(crypto.len(), MAX_CRYPTO_MATCHES, "Crypto match count")?;
    for item in crypto {
        bounded(item.algorithm.len(), 256, "Algorithm name")?;
        bounded(item.signature.len(), 1024, "Signature name")?;
        bounded(item.length, MAX_BINARY, "Signature length")?;
        mapped_range(ranges, item.address, item.length)?;
    }
    Ok(())
}

/// A copy of a live graph that project files can store. Saved graphs have always
/// required mapped exit and call targets, so earlier releases can open them. Live
/// exits into unmapped gaps, such as the fallthrough after a no-return call at
/// the end of a section, are saved as unresolved instead of failing the save.
pub(crate) fn persistable_view(view: &FunctionView, sections: &[SectionInfo]) -> FunctionView {
    let mut view = view.clone();
    // Invalid section metadata is rejected by the project validation itself.
    if let Ok(ranges) = MappedRanges::new(sections) {
        let edges = view.edges.iter_mut().map(|edge| &mut edge.target);
        let calls = view.calls.iter_mut().map(|call| &mut call.target);
        for target in edges.chain(calls) {
            if target.is_some_and(|address| !ranges.contains(address)) {
                *target = None;
            }
        }
        for edge in &mut view.edges {
            if edge.target.is_none() {
                edge.evidence = None;
            }
        }
    }
    view
}

/// Structural graph bounds shared by projects and worker replies. Exits and
/// call targets may legitimately leave the displayed blocks, so only their
/// sources are checked here.
pub(crate) fn validate_view(
    view: &FunctionView,
    ranges: &MappedRanges,
    info: &BinaryInfo,
) -> Result<(), String> {
    bounded(view.blocks.len(), MAX_GRAPH_BLOCKS, "Basic block count")?;
    bounded(view.edges.len(), MAX_GRAPH_EDGES, "Edge count")?;
    bounded(view.calls.len(), MAX_GRAPH_CALLS, "Call count")?;
    bounded(view.warnings.len(), MAX_WARNINGS, "Graph warning count")?;
    let count = view
        .blocks
        .iter()
        .map(|b| b.instructions.len())
        .fold(0usize, usize::saturating_add);
    bounded(count, MAX_GRAPH_INSTRUCTIONS, "Instruction count")?;
    mapped(ranges, view.address)?;
    for warning in &view.warnings {
        bounded(warning.len(), 4096, "Graph warning text")?;
    }
    let mut blocks = std::collections::BTreeSet::new();
    let mut instructions = std::collections::BTreeSet::new();
    for block in &view.blocks {
        if !blocks.insert(block.address) {
            return Err("Graph has duplicate basic blocks".into());
        }
        mapped(ranges, block.address)?;
        if block
            .instructions
            .first()
            .is_some_and(|i| i.address != block.address)
        {
            return Err("Basic block address does not match its first instruction".into());
        }
        for instruction in &block.instructions {
            if !instructions.insert(instruction.address) {
                return Err("Graph has duplicate instructions".into());
            }
            bounded(
                instruction.bytes.len(),
                MAX_INSTRUCTION_BYTES,
                "Instruction bytes",
            )?;
            bounded(instruction.mnemonic.len(), 128, "Instruction mnemonic")?;
            bounded(instruction.operands.len(), 4096, "Instruction operands")?;
            mapped_range(ranges, instruction.address, instruction.bytes.len())?;
        }
    }
    if view.calls.iter().any(|call| call.no_return.is_some()) {
        use crate::model::NoReturnEvidence;
        let (pointer_bytes, _) = crate::architecture::properties(&info.architecture)
            .ok_or("Unknown architecture for no-return evidence")?;
        let mut sites = std::collections::BTreeMap::<u64, usize>::new();
        for call in &view.calls {
            *sites.entry(call.address).or_default() += 1;
        }
        let terminals = view
            .blocks
            .iter()
            .filter_map(|block| {
                block
                    .instructions
                    .last()
                    .map(|instruction| (instruction.address, block.address))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        let outgoing = view
            .edges
            .iter()
            .map(|edge| edge.source)
            .collect::<std::collections::BTreeSet<_>>();
        for call in &view.calls {
            let Some(evidence) = call.no_return else {
                continue;
            };
            let block = terminals
                .get(&call.address)
                .ok_or("No-return call is not the last displayed instruction of a block")?;
            if sites[&call.address] != 1 || outgoing.contains(block) {
                return Err("No-return call has conflicting sites or outgoing edges".into());
            }
            match evidence {
                NoReturnEvidence::NamedTarget => {
                    let target = call.target.ok_or("Named no-return call has no target")?;
                    if !crate::call_analysis::code_address(info, target) {
                        return Err(
                            "Named no-return target is not executable file-backed code".into()
                        );
                    }
                }
                NoReturnEvidence::ImportSlot { slot } => {
                    if !info
                        .sections
                        .iter()
                        .any(|section| section.backs(slot, pointer_bytes))
                    {
                        return Err("No-return import slot is not fully file-backed".into());
                    }
                }
            }
        }
    }
    for edge in &view.edges {
        if !blocks.contains(&edge.source) {
            return Err("Graph edge source is not a basic block".into());
        }
        if edge.evidence.is_some() {
            // Switch evidence describes an established branch destination.
            let target = edge
                .target
                .filter(|_| edge.kind == EdgeKind::Branch)
                .ok_or("Graph switch evidence lacks a branch destination")?;
            mapped(ranges, target)?;
        }
    }
    Ok(())
}

fn mapped_range(ranges: &MappedRanges, address: u64, length: usize) -> Result<(), String> {
    if length == 0 {
        return Err("Project cache contains an empty mapped range".into());
    }
    address
        .checked_add(length as u64)
        .ok_or("Project cache range overflows")?;
    if ranges.contains_span(address, length as u64) {
        Ok(())
    } else {
        Err("Project cache range includes unmapped bytes".into())
    }
}

fn mapped(ranges: &MappedRanges, address: u64) -> Result<(), String> {
    if ranges.contains(address) {
        Ok(())
    } else {
        Err(format!(
            "Project cache contains unmapped address {address:#x}"
        ))
    }
}
fn bounded(length: usize, maximum: usize, what: &str) -> Result<(), String> {
    if length > maximum {
        Err(format!("{what} exceeds its {maximum} size limit"))
    } else {
        Ok(())
    }
}
fn sql_error(error: rusqlite::Error) -> String {
    format!("Invalid project database: {error}")
}

fn configure(db: &Connection, read_only: bool) -> Result<(), String> {
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(sql_error)?;
    db.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(sql_error)?;
    for (limit, value) in [
        (Limit::SQLITE_LIMIT_LENGTH, (MAX_BINARY + 1024) as i32),
        (Limit::SQLITE_LIMIT_SQL_LENGTH, 4096),
        (Limit::SQLITE_LIMIT_COLUMN, 16),
        (Limit::SQLITE_LIMIT_EXPR_DEPTH, 32),
        (Limit::SQLITE_LIMIT_COMPOUND_SELECT, 4),
        (Limit::SQLITE_LIMIT_VDBE_OP, 10_000),
        (Limit::SQLITE_LIMIT_FUNCTION_ARG, 16),
        (Limit::SQLITE_LIMIT_ATTACHED, 0),
        (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, 16),
        (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, 0),
        (Limit::SQLITE_LIMIT_WORKER_THREADS, 0),
        (Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 1024),
    ] {
        db.set_limit(limit, value).map_err(sql_error)?;
    }
    db.busy_timeout(Duration::from_millis(0))
        .map_err(sql_error)?;
    let steps = AtomicUsize::new(0);
    let deadline = Instant::now() + Duration::from_secs(15);
    db.progress_handler(
        1000,
        Some(move || steps.fetch_add(1, Ordering::Relaxed) > 20_000 || Instant::now() > deadline),
    )
    .map_err(sql_error)?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;").map_err(sql_error)?;
    if read_only {
        db.execute_batch("PRAGMA query_only=ON;")
            .map_err(sql_error)?;
    }
    Ok(())
}

fn blob_properties(
    db: &Connection,
    key: &str,
    maximum: usize,
) -> Result<Option<(i64, usize)>, String> {
    let properties: Option<(i64, String, i64)> = db
        .query_row(
            "SELECT rowid,typeof(value),length(value) FROM project_data WHERE key=?1",
            [key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(sql_error)?;
    let Some((rowid, kind, length)) = properties else {
        return Ok(None);
    };
    if kind != "blob" || length < 0 || length as u64 > maximum as u64 {
        return Err(format!(
            "Project {key} record exceeds its size limit or has an invalid type"
        ));
    }
    Ok(Some((rowid, length as usize)))
}
fn read_blob(db: &Connection, key: &str, maximum: usize) -> Result<Option<Vec<u8>>, String> {
    if blob_properties(db, key, maximum)?.is_none() {
        return Ok(None);
    };
    db.query_row(
        "SELECT value FROM project_data WHERE key=?1",
        [key],
        |row| row.get(0),
    )
    .optional()
    .map_err(sql_error)
}

fn immutable_uri(path: &Path) -> Result<String, String> {
    let path = path.to_str().ok_or("Private snapshot path is not UTF-8")?;
    #[cfg(windows)]
    let path = path
        .replace('\\', "/")
        .trim_start_matches("//?/")
        .to_owned();
    let mut uri = String::from("file:");
    #[cfg(windows)]
    if !path.starts_with('/') {
        uri.push('/');
    }
    for byte in path.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"/-_.~:".contains(byte) {
            uri.push(*byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

struct Capped {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(
                "Project record exceeds its size limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T, maximum: usize) -> Result<Vec<u8>, String> {
    let mut output = Capped {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|e| format!("Cannot serialize project: {e}"))?;
    Ok(output.bytes)
}

/// Bound collection construction before materializing hostile cached DTOs.
fn check_json_budget(bytes: &[u8]) -> Result<(), String> {
    crate::bounded::check_json(bytes, MAX_JSON_NODES, 256 * 1024)
        .map_err(|e| format!("Invalid project metadata: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FileIdentity, FunctionInfo, SectionInfo};
    use crate::session::Annotation;

    fn sample(directory: &Path) -> (ProjectData, BinaryProtection) {
        let path = directory.join("original.bin");
        fs::write(&path, b"example binary").unwrap();
        let protection = BinaryProtection::open(&path).unwrap();
        let info = BinaryInfo {
            // Match WorkerClient's canonical display path. Windows runner temp
            // paths may use an 8.3 alias that canonicalize expands to its name.
            path: protection.path().to_string_lossy().into_owned(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0x1000,
            file_len: 14,
            sha256: session::fingerprint(&path).unwrap(),
            source_identity: FileIdentity::from_file(&File::open(&path).unwrap()),
            sections: vec![SectionInfo {
                name: ".text".into(),
                address: 0x1000,
                size: 14,
                file_offset: 0,
                file_size: 14,
                executable: true,
            }],
            functions: vec![FunctionInfo {
                address: 0x1000,
                name: "main".into(),
            }],
            functions_truncated: false,
            warnings: vec![],
        };
        let mut session = Session::new(info.sha256.clone());
        session.annotations.insert(
            0x1000,
            Annotation {
                label: "entry".into(),
                comment: "saved note".into(),
                decoded: vec![],
            },
        );
        let data = ProjectData {
            semantics: Default::default(),
            info: info.clone(),
            session,
            view: Some(FunctionView {
                address: 0x1000,
                blocks: vec![],
                edges: vec![],
                calls: vec![],
                warnings: vec![],
            }),
            decompiled: Some("int main(void) { return 0; }".into()),
            mappings: vec![CodeMapping {
                start: 17,
                end: 25,
                addresses: vec![0x1000],
            }],
            strings: vec![],
            strings_truncated: false,
            crypto: vec![],
            crypto_truncated: false,
            selected_address: Some(0x1000),
            discovery: None,
        };
        (data, protection.bind_snapshot(&info).unwrap())
    }

    #[test]
    fn embedded_project_round_trip_and_private_extraction_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let (data, protection) = sample(directory.path());
        let path = directory.path().join("portable.grproj");
        data.save(&path, &protection, true).unwrap();
        assert!(fs::read(&path).unwrap().starts_with(b"SQLite format 3\0"));
        let loaded = ProjectData::load(&path).unwrap();
        assert_eq!(
            loaded.data.session.annotations[&0x1000].comment,
            "saved note"
        );
        assert_eq!(loaded.data.decompiled, data.decompiled);
        assert_eq!(loaded.data.mappings.len(), 1);
        assert_eq!(loaded.data.mappings[0].addresses, vec![0x1000]);
        assert_eq!(loaded.data.selected_address, Some(0x1000));
        assert!(loaded.cache_compatible);
        assert!(loaded.data.info.source_identity.is_none());
        let extracted = loaded.binary.as_ref().unwrap().path().to_owned();
        assert_eq!(fs::read(&extracted).unwrap(), b"example binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&extracted).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        let lease = loaded.binary.clone();
        drop(loaded);
        assert!(extracted.exists());
        drop(lease);
        assert!(!extracted.exists());
    }

    #[test]
    fn external_project_requires_explicit_matching_source_and_does_not_open_hint() {
        let directory = tempfile::tempdir().unwrap();
        let (mut data, protection) = sample(directory.path());
        data.info.path = "\\\\server\\share\\untrusted.exe".into();
        let path = directory.path().join("external.grproj");
        data.save(&path, &protection, false).unwrap();
        let loaded = ProjectData::load(&path).unwrap();
        assert!(loaded.binary.is_none());
        assert_eq!(loaded.source_hint, data.info.path);
        protection.verify_sha256(&loaded.data.info.sha256).unwrap();
        let other = directory.path().join("other");
        fs::write(&other, b"different binary").unwrap();
        assert!(
            BinaryProtection::open(&other)
                .unwrap()
                .verify_sha256(&loaded.data.info.sha256)
                .unwrap_err()
                .contains("mismatch")
        );
    }

    #[test]
    fn changed_input_and_binary_alias_destinations_are_rejected_without_data_loss() {
        let directory = tempfile::tempdir().unwrap();
        let (data, protection) = sample(directory.path());
        let original = fs::read(protection.path()).unwrap();
        assert!(data.save(protection.path(), &protection, true).is_err());
        let alias = directory.path().join("alias.grproj");
        fs::hard_link(protection.path(), &alias).unwrap();
        assert!(data.save(&alias, &protection, true).is_err());
        assert_eq!(fs::read(&alias).unwrap(), original);
        let project = directory.path().join("safe.grproj");
        data.save(&project, &protection, true).unwrap();
        let saved = fs::read(&project).unwrap();
        #[cfg(windows)]
        assert!(fs::write(protection.path(), b"mutated binary").is_err());
        #[cfg(not(windows))]
        {
            fs::write(protection.path(), b"mutated binary").unwrap();
            assert!(
                data.save(&project, &protection, true)
                    .unwrap_err()
                    .contains("changed")
            );
        }
        assert_eq!(fs::read(&project).unwrap(), saved);
    }

    fn discovered(data: &ProjectData) -> DiscoverySnapshot {
        use crate::discovery::Discovery;
        use crate::model::{CallAnalysis, CallReference, DiscoveryBatch, DiscoveryOutcome};
        let mut state = Discovery::new(Some(0x1000), [0x1000], false);
        let Some(crate::model::Request::DiscoverBatch { binding, .. }) = state.begin(1, 1, 0)
        else {
            panic!()
        };
        let batch = DiscoveryBatch {
            binding,
            inventory: crate::model::InventoryChange::Replace {
                revision: 1,
                functions: data.info.functions.clone(),
            },
            truncated: false,
            patterns: None,
            outcomes: vec![DiscoveryOutcome {
                address: 0x1000,
                status: crate::model::DiscoveryStatus::Done,
            }],
            analysis: CallAnalysis {
                references: vec![CallReference {
                    caller: 0x1000,
                    address: 0x1004,
                    target: 0x1008,
                }],
                functions_examined: 1,
                decode_attempts: 3,
                ..Default::default()
            },
        };
        crate::discovery::commit_replacement(&mut state, &data.info, &batch).unwrap();
        state.save()
    }

    #[test]
    fn pre_semantic_version_2_project_retains_notes_and_refreshes_old_caches() {
        let directory = tempfile::tempdir().unwrap();
        let (mut data, protection) = sample(directory.path());
        data.discovery = Some(Arc::new(discovered(&data)));
        let path = directory.path().join("legacy.grproj");
        data.save(&path, &protection, true).unwrap();
        let db = Connection::open(&path).unwrap();
        let bytes = read_blob(&db, "body", MAX_BODY).unwrap().unwrap();
        let mut body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        body.as_object_mut().unwrap().remove("semantics");
        body["engine"] = "ghidra-rust-project-v1-mapping-v1-pe-v1-aarch64-v1-calls-v1-arm64pe-v1-inventory-v2-elfcrt-v1-switch-v1-noreturn-v1:268c3a406d8d964bc00ae2ead4d3e1e1373aaa27".into();
        db.execute(
            "UPDATE project_data SET value=?1 WHERE key='body'",
            [serde_json::to_vec(&body).unwrap()],
        )
        .unwrap();
        let mut notes = serde_json::to_value(&data.session).unwrap();
        notes.as_object_mut().unwrap().remove("local_renames");
        db.execute(
            "UPDATE project_data SET value=?1 WHERE key='annotations'",
            [serde_json::to_vec(&notes).unwrap()],
        )
        .unwrap();
        db.execute_batch("PRAGMA user_version=2").unwrap();
        drop(db);
        let reopened = ProjectData::load(&path).unwrap();
        assert!(!reopened.cache_compatible);
        assert_eq!(
            serde_json::to_value(&reopened.data.session.annotations).unwrap(),
            serde_json::to_value(&data.session.annotations).unwrap()
        );
        assert!(reopened.data.view.is_none() && reopened.data.discovery.is_none());
        assert!(reopened.data.decompiled.is_none());
        assert!(reopened.data.semantics.tokens.is_empty());
        assert!(reopened.data.session.local_renames.is_empty());
        assert!(reopened.binary.is_some());
    }

    #[test]
    fn saved_discovery_round_trips_and_version_1_projects_still_open() {
        let directory = tempfile::tempdir().unwrap();
        let (mut data, protection) = sample(directory.path());
        let saved = discovered(&data);
        assert_eq!(
            (saved.done.as_slice(), saved.pending.as_slice()),
            (&[0x1000][..], &[0x1008][..])
        );
        data.discovery = Some(Arc::new(saved));
        let path = directory.path().join("discovered.grproj");
        data.save(&path, &protection, true).unwrap();
        let loaded = ProjectData::load(&path).unwrap().data.discovery.unwrap();
        assert_eq!(
            loaded.report.references,
            data.discovery.as_ref().unwrap().report.references
        );
        assert_eq!(loaded.pending, [0x1008]);

        // A different discovery format drops only discovery.
        let mut other = (**data.discovery.as_ref().unwrap()).clone();
        other.fingerprint = "discovery-v0".into();
        let mut older = data.clone();
        older.discovery = Some(Arc::new(other));
        older.save(&path, &protection, true).unwrap();
        let reopened = ProjectData::load(&path).unwrap();
        assert!(reopened.data.discovery.is_none() && reopened.cache_compatible);

        // Version 2 metadata predates semantic tokens; no text fallback is inferred.
        data.save(&path, &protection, true).unwrap();
        let db = Connection::open(&path).unwrap();
        let bytes = read_blob(&db, "body", MAX_BODY).unwrap().unwrap();
        let mut legacy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        legacy.as_object_mut().unwrap().remove("semantics");
        db.execute(
            "UPDATE project_data SET value=?1 WHERE key='body'",
            [serde_json::to_vec(&legacy).unwrap()],
        )
        .unwrap();
        db.execute_batch("PRAGMA user_version=2").unwrap();
        drop(db);
        let reopened = ProjectData::load(&path).unwrap();
        assert!(reopened.data.discovery.is_some());
        assert!(reopened.data.semantics.tokens.is_empty());

        // Existing version 1 files open without discovery.
        let db = Connection::open(&path).unwrap();
        db.execute_batch("PRAGMA user_version=1; DELETE FROM project_data WHERE key='discovery'")
            .unwrap();
        drop(db);
        let reopened = ProjectData::load(&path).unwrap();
        assert!(reopened.data.discovery.is_none() && reopened.data.view.is_some());

        // Forged evidence is rejected on save and when written directly.
        let mut forged = (**data.discovery.as_ref().unwrap()).clone();
        forged.report.partial = false;
        let mut hostile = data.clone();
        hostile.discovery = Some(Arc::new(forged.clone()));
        assert!(hostile.save(&path, &protection, true).is_err());
        data.save(&path, &protection, true).unwrap();
        let db = Connection::open(&path).unwrap();
        db.execute(
            "UPDATE project_data SET value=?1 WHERE key='discovery'",
            [serde_json::to_vec(&forged).unwrap()],
        )
        .unwrap();
        drop(db);
        assert!(
            ProjectData::load(&path)
                .unwrap_err()
                .contains("complete coverage")
        );
    }

    #[test]
    fn no_return_evidence_roundtrips_and_rejects_inconsistent_graphs() {
        use crate::model::{CallSite, NoReturnEvidence};
        let directory = tempfile::tempdir().unwrap();
        let (mut data, protection) = sample(directory.path());
        let view = data.view.as_mut().unwrap();
        view.blocks = vec![crate::model::BasicBlock {
            address: 0x1000,
            instructions: vec![crate::model::Instruction {
                address: 0x1000,
                bytes: vec![0xe8, 3, 0, 0, 0],
                mnemonic: "CALL".into(),
                operands: "0x1008".into(),
            }],
        }];
        view.edges.clear();
        view.calls = vec![CallSite {
            address: 0x1000,
            target: Some(0x1008),
            no_return: Some(NoReturnEvidence::NamedTarget),
        }];
        let path = directory.path().join("noreturn.grproj");
        data.save(&path, &protection, true).unwrap();
        let loaded = ProjectData::load(&path).unwrap();
        assert_eq!(
            loaded.data.view.unwrap().calls[0].no_return,
            Some(NoReturnEvidence::NamedTarget)
        );
        let legacy: CallSite = serde_json::from_str(r#"{"address":4096,"target":4104}"#).unwrap();
        assert_eq!(legacy.no_return, None);
        let mut invalid = data.clone();
        invalid
            .view
            .as_mut()
            .unwrap()
            .calls
            .push(data.view.as_ref().unwrap().calls[0].clone());
        assert!(invalid.validate().is_err());
        let mut invalid = data.clone();
        invalid.view.as_mut().unwrap().calls[0].address = 0x1001;
        assert!(invalid.validate().is_err());
        let mut invalid = data.clone();
        invalid
            .view
            .as_mut()
            .unwrap()
            .edges
            .push(crate::model::Edge {
                source: 0x1000,
                target: Some(0x1008),
                kind: EdgeKind::Branch,
                evidence: None,
            });
        assert!(invalid.validate().is_err());
        for (slot, valid) in [(0x1006, true), (0x1007, false), (u64::MAX, false)] {
            let mut data = data.clone();
            let call = &mut data.view.as_mut().unwrap().calls[0];
            call.target = None;
            call.no_return = Some(NoReturnEvidence::ImportSlot { slot });
            assert_eq!(data.validate().is_ok(), valid, "slot {slot:#x}");
        }
        let mut invalid = data.clone();
        invalid.info.sections[0].executable = false;
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn rejects_hostile_schema_versions_types_and_tampered_embedded_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let (data, protection) = sample(directory.path());
        let path = directory.path().join("test.grproj");
        for mutation in [
            "PRAGMA user_version=0",
            "PRAGMA user_version=4",
            // Version 1 never had discovery records.
            "PRAGMA user_version=1; INSERT INTO project_data VALUES ('discovery',x'7b7d')",
            "INSERT INTO project_data VALUES ('discovery',x'7b7d')",
            "INSERT INTO project_data VALUES ('discovery','{}')",
            // Metadata and discovery share one 48 MiB budget.
            "INSERT INTO project_data VALUES ('discovery',zeroblob(50331000))",
            "UPDATE project_data SET key=zeroblob(1048576) WHERE key='binary'",
            "UPDATE project_data SET key=printf('%1048576s','x') WHERE key='binary'",
            "PRAGMA application_id=0",
            "CREATE VIEW extra AS SELECT * FROM project_data",
            "UPDATE project_data SET value='not a blob' WHERE key='body'",
            "UPDATE project_data SET value=x'00' WHERE key='binary'",
            "INSERT INTO project_data VALUES ('unsupported',x'00')",
            "INSERT INTO project_data SELECT key,value FROM project_data WHERE key='body'",
            "CREATE TRIGGER bad AFTER UPDATE ON project_data BEGIN DELETE FROM project_data; END",
            "UPDATE project_data SET value=zeroblob(2097153) WHERE key='decompiled'",
        ] {
            data.save(&path, &protection, true).unwrap();
            let db = Connection::open(&path).unwrap();
            db.execute_batch(mutation).unwrap();
            drop(db);
            assert!(ProjectData::load(&path).is_err(), "accepted {mutation}");
        }
        fs::write(&path, b"not a database").unwrap();
        assert!(ProjectData::load(&path).is_err());
        assert!(
            ProjectData::load(directory.path())
                .unwrap_err()
                .contains("regular")
        );
    }

    #[test]
    fn embedded_reopen_cannot_overwrite_original_path_or_matching_alias() {
        let directory = tempfile::tempdir().unwrap();
        let (data, protection) = sample(directory.path());
        let project = directory.path().join("saved.grproj");
        data.save(&project, &protection, true).unwrap();
        let loaded = ProjectData::load(&project).unwrap();
        let alias = directory.path().join("original-copy");
        fs::copy(protection.path(), &alias).unwrap();
        assert!(
            protect_binary_destination(&alias, &loaded.data.info)
                .unwrap_err()
                .contains("original input binary")
        );
        assert!(
            protect_binary_destination(protection.path(), &loaded.data.info)
                .unwrap_err()
                .contains("pathname")
        );
        assert_eq!(fs::read(&alias).unwrap(), b"example binary");
    }

    #[test]
    fn live_exits_into_unmapped_gaps_are_saved_as_unresolved() {
        use crate::model::{BasicBlock, CallSite, Edge, EdgeKind, Instruction};
        let directory = tempfile::tempdir().unwrap();
        let (mut data, protection) = sample(directory.path());
        let view = data.view.as_mut().unwrap();
        view.blocks = vec![BasicBlock {
            address: 0x1000,
            instructions: vec![Instruction {
                address: 0x1000,
                bytes: vec![0xe8, 0, 0, 0, 0],
                mnemonic: "CALL".into(),
                operands: "0x9000".into(),
            }],
        }];
        // The section ends at 0x100e: a fallthrough past it and a call outside
        // every section are live-only targets.
        view.edges = vec![
            Edge {
                source: 0x1000,
                target: Some(0x100e),
                kind: EdgeKind::Branch,
                evidence: None,
            },
            Edge {
                source: 0x1000,
                target: Some(0x1005),
                kind: EdgeKind::True,
                evidence: None,
            },
        ];
        view.calls = vec![
            CallSite {
                address: 0x1000,
                target: Some(0x9000),
                no_return: None,
            },
            CallSite {
                address: 0x1000,
                target: Some(0x1008),
                no_return: None,
            },
        ];
        let project = directory.path().join("gaps.grproj");
        assert!(
            data.save(&project, &protection, true)
                .unwrap_err()
                .contains("unmapped")
        );
        let live = data.view.take().unwrap();
        data.view = Some(persistable_view(&live, &data.info.sections));
        data.save(&project, &protection, true).unwrap();
        let view = ProjectData::load(&project).unwrap().data.view.unwrap();
        let edges: Vec<_> = view
            .edges
            .iter()
            .map(|edge| (edge.target, edge.kind))
            .collect();
        assert_eq!(
            edges,
            [(None, EdgeKind::Branch), (Some(0x1005), EdgeKind::True)]
        );
        let calls: Vec<_> = view.calls.iter().map(|call| call.target).collect();
        assert_eq!(calls, [None, Some(0x1008)]);
    }

    #[test]
    fn forged_ranges_graph_duplicates_and_metadata_mismatch_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let (original, _) = sample(directory.path());
        let mut data = original.clone();
        data.info.sections[0].file_size += 1;
        assert!(data.validate_against(&original.info).is_err());
        let mut data = original.clone();
        data.selected_address = Some(0x9000);
        assert!(data.validate().unwrap_err().contains("unmapped"));
        let mut data = original.clone();
        data.info.functions[0].address = 0x9000;
        assert!(data.validate().unwrap_err().contains("unmapped"));
        let mut data = original.clone();
        data.view.as_mut().unwrap().blocks = vec![
            crate::model::BasicBlock {
                address: 0x1000,
                instructions: vec![]
            };
            2
        ];
        assert!(data.validate().unwrap_err().contains("duplicate"));
        let mut data = original.clone();
        data.view.as_mut().unwrap().edges.push(crate::model::Edge {
            source: 0x1000,
            target: None,
            kind: crate::model::EdgeKind::Unknown,
            evidence: None,
        });
        assert!(data.validate().unwrap_err().contains("not a basic block"));
        // Switch evidence must name a mapped branch destination.
        let switch = |target, kind| {
            let mut data = original.clone();
            let view = data.view.as_mut().unwrap();
            view.blocks.push(crate::model::BasicBlock {
                address: 0x1000,
                instructions: vec![],
            });
            view.edges.push(crate::model::Edge {
                source: 0x1000,
                target,
                kind,
                evidence: Some(crate::model::EdgeEvidence::EngineJumpTable),
            });
            data.validate()
        };
        for (target, kind, error) in [
            (None, EdgeKind::Branch, "lacks a branch destination"),
            (Some(0x1000), EdgeKind::True, "lacks a branch destination"),
            (Some(0x9000), EdgeKind::Branch, "unmapped"),
        ] {
            assert!(switch(target, kind).unwrap_err().contains(error));
        }
        switch(Some(0x1000), EdgeKind::Branch).unwrap();
        // Graphs saved before switch recovery carry no evidence field.
        let legacy: crate::model::Edge =
            serde_json::from_str(r#"{"source":4096,"target":4101,"kind":"Branch"}"#).unwrap();
        assert_eq!(legacy.evidence, None);
        let mut data = original.clone();
        data.view
            .as_mut()
            .unwrap()
            .calls
            .push(crate::model::CallSite {
                address: 0x1000,
                target: Some(0x9000),
                no_return: None,
            });
        assert!(data.validate().unwrap_err().contains("unmapped"));
        let mut data = original.clone();
        data.crypto.push(CryptoMatch {
            address: 0x100d,
            algorithm: "test".into(),
            signature: "test".into(),
            length: 2,
        });
        assert!(data.validate().unwrap_err().contains("unmapped"));
        let mut data = original.clone();
        data.info.warnings.push("a".repeat(4097));
        assert!(data.validate().unwrap_err().contains("Warning text"));
    }

    #[test]
    fn incompatible_engine_discards_cached_analysis_but_keeps_annotations() {
        let directory = tempfile::tempdir().unwrap();
        let (data, protection) = sample(directory.path());
        let path = directory.path().join("old.grproj");
        data.save(&path, &protection, false).unwrap();
        let db = Connection::open(&path).unwrap();
        let bytes = read_blob(&db, "body", MAX_BODY).unwrap().unwrap();
        let mut body: Body = serde_json::from_slice(&bytes).unwrap();
        body.engine =
            "ghidra-rust-project-v1-mapping-v1-pe-v1:268c3a406d8d964bc00ae2ead4d3e1e1373aaa27"
                .into();
        db.execute(
            "UPDATE project_data SET value=?1 WHERE key='body'",
            [encode(&body, MAX_BODY).unwrap()],
        )
        .unwrap();
        drop(db);
        let loaded = ProjectData::load(&path).unwrap();
        assert!(!loaded.cache_compatible);
        assert!(loaded.data.view.is_none());
        assert!(loaded.data.decompiled.is_none());
        assert_eq!(loaded.data.session.annotations[&0x1000].label, "entry");
    }

    #[test]
    fn excess_collections_fail_while_deserializing_and_sections_must_be_ordered() {
        let directory = tempfile::tempdir().unwrap();
        let (data, protection) = sample(directory.path());
        let path = directory.path().join("warnings.grproj");
        data.save(&path, &protection, false).unwrap();
        let db = Connection::open(&path).unwrap();
        let bytes = read_blob(&db, "body", MAX_BODY).unwrap().unwrap();
        let mut body: Body = serde_json::from_slice(&bytes).unwrap();
        body.info.warnings = vec![String::new(); MAX_WARNINGS + 1];
        db.execute(
            "UPDATE project_data SET value=?1 WHERE key='body'",
            [encode(&body, MAX_BODY).unwrap()],
        )
        .unwrap();
        drop(db);
        let error = ProjectData::load(&path).unwrap_err();
        assert!(error.contains("128-element limit"), "{error}");

        let mut unordered = data.clone();
        unordered.info.sections = vec![
            SectionInfo {
                name: ".b".into(),
                address: 0x1008,
                size: 8,
                file_offset: 0,
                file_size: 0,
                executable: false,
            },
            unordered.info.sections[0].clone(),
        ];
        assert!(unordered.validate().unwrap_err().contains("unordered"));

        // Legacy projects keep their larger per-name bound.
        let mut legacy = data;
        legacy.info.functions[0].name = "n".repeat(4096);
        legacy.validate().unwrap();
        legacy.info.functions[0].name.push('n');
        assert!(legacy.validate().is_err());
    }

    #[test]
    fn bounded_records_and_collection_preflight_preserve_previous_project() {
        let directory = tempfile::tempdir().unwrap();
        let (mut data, protection) = sample(directory.path());
        let path = directory.path().join("bounded.grproj");
        data.save(&path, &protection, true).unwrap();
        let original = fs::read(&path).unwrap();
        data.decompiled = Some("a".repeat(MAX_DECOMPILED_BYTES + 1));
        assert!(data.save(&path, &protection, true).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(
            check_json_budget(format!("[{}]", vec!["0"; MAX_JSON_NODES + 1].join(",")).as_bytes())
                .unwrap_err()
                .contains("budget")
        );
        let oversized = directory.path().join("large.grproj");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_PROJECT + 1)
            .unwrap();
        assert!(
            ProjectData::load(&oversized)
                .unwrap_err()
                .contains("size limit")
        );
    }
}
