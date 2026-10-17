//! Versioned sidecar annotations. Saving a session never edits the input program.

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::model::{BinaryInfo, FileIdentity, SectionInfo};

const SESSION_VERSION: u32 = 1;
pub(crate) const MAX_SESSION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ANNOTATIONS: usize = 10_000;
const MAX_LABEL_BYTES: usize = 256;
const MAX_COMMENT_BYTES: usize = 64 * 1024;
const MAX_DECODED_PER_ANNOTATION: usize = 32;
const MAX_DECODED_TEXT_BYTES: usize = 256 * 1024;
const MAX_DECODED_SOURCE_BYTES: usize = 64 * 1024;
const MAX_PARAMETERS_BYTES: usize = 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Retains the actual analyzed file across renames, unlinking, and worker restarts.
/// Never serialize this live capability into a portable annotation sidecar.
#[derive(Clone, Debug)]
pub struct BinaryProtection {
    // Keeping the descriptor open also prevents reuse of the protected inode.
    _file: Arc<File>,
    original_path: PathBuf,
    identity: FileIdentity,
    snapshot_sha256: Option<String>,
}

impl BinaryProtection {
    pub fn open(path: &Path) -> Result<Self, String> {
        #[cfg(windows)]
        crate::windows::validate_local_path(path)
            .map_err(|e| format!("Cannot open input binary: {e}"))?;
        let original_path = fs::canonicalize(path)
            .map_err(|error| format!("Cannot resolve input binary: {error}"))?;
        #[cfg(windows)]
        crate::windows::validate_local_path(&original_path)
            .map_err(|e| format!("Cannot open input binary: {e}"))?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        crate::windows::configure_read(&mut options);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // A raced special-file substitution must not block the GUI thread.
            // The canonical final component must also remain a non-symlink.
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let file = options
            .open(&original_path)
            .map_err(|error| format!("Cannot open input binary: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("Cannot inspect input binary: {error}"))?;
        if !metadata.is_file() {
            return Err("Input binary must be a regular file".into());
        }
        #[cfg(windows)]
        crate::windows::verify_regular_file(&file)
            .map_err(|error| format!("Cannot inspect input binary: {error}"))?;
        let identity = FileIdentity::from_file(&file)
            .ok_or("Input file identity protection is unsupported on this platform")?;
        Ok(Self {
            _file: Arc::new(file),
            original_path,
            identity,
            snapshot_sha256: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.original_path
    }

    /// The worker must have opened the same file as the retained host descriptor.
    pub fn verify_identity(&self, info: &BinaryInfo) -> Result<(), String> {
        if info.source_identity != Some(self.identity) {
            return Err("Input binary was replaced while opening; reopen it explicitly".into());
        }
        Ok(())
    }

    pub fn bind_snapshot(mut self, info: &BinaryInfo) -> Result<Self, String> {
        self.verify_identity(info)?;
        validate_fingerprint(&info.sha256)?;
        self.snapshot_sha256 = Some(info.sha256.clone());
        Ok(self)
    }

    pub fn same_source(&self, other: &Self) -> bool {
        self.identity == other.identity
    }

    /// Read the retained file, rather than following a pathname that may have changed.
    /// Reject concurrent changes if the bytes no longer match the analyzed image.
    pub fn verified_snapshot(&self) -> Result<Vec<u8>, String> {
        let expected = self
            .snapshot_sha256
            .as_deref()
            .ok_or("Binary has no verified analysis snapshot")?;
        let bytes = self.read_snapshot()?;
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(
                "Input binary changed after analysis; reopen it before saving a project".into(),
            );
        }
        Ok(bytes)
    }

    /// Verify an explicitly selected external binary before starting analysis.
    pub fn verify_sha256(&self, expected: &str) -> Result<(), String> {
        validate_fingerprint(expected)?;
        if format!("{:x}", Sha256::digest(self.read_snapshot()?)) != expected {
            return Err("Project belongs to a different binary (SHA-256 mismatch)".into());
        }
        Ok(())
    }

    pub fn verify_current_snapshot(&self) -> Result<(), String> {
        self.verified_snapshot().map(|_| ())
    }

    pub(crate) fn ensure_bound(&self, hash: &str) -> Result<(), String> {
        if self.snapshot_sha256.as_deref() == Some(hash) {
            Ok(())
        } else {
            Err("Project is not bound to the protected binary snapshot".into())
        }
    }

    fn read_snapshot(&self) -> Result<Vec<u8>, String> {
        const MAX: usize = 128 * 1024 * 1024;
        let length = self
            ._file
            .metadata()
            .map_err(|e| format!("Cannot inspect binary: {e}"))?
            .len();
        if length > MAX as u64 {
            return Err("Binary exceeds the 128 MiB size limit".into());
        }
        let mut bytes = Vec::with_capacity(length as usize);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            #[cfg(unix)]
            let count = {
                use std::os::unix::fs::FileExt;
                self._file.read_at(&mut buffer, bytes.len() as u64)
            };
            #[cfg(windows)]
            let count = {
                use std::os::windows::fs::FileExt;
                self._file.seek_read(&mut buffer, bytes.len() as u64)
            };
            #[cfg(not(any(unix, windows)))]
            let count: std::io::Result<usize> = Err(std::io::Error::other("Unsupported platform"));
            let count = count.map_err(|e| format!("Cannot read protected binary: {e}"))?;
            if count == 0 {
                break;
            }
            if count > MAX.saturating_sub(bytes.len()) {
                return Err("Binary exceeds the 128 MiB size limit".into());
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        Ok(bytes)
    }
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Annotation {
    pub label: String,
    pub comment: String,
    #[serde(deserialize_with = "deserialize_decoded")]
    pub decoded: Vec<DecodedAnnotation>,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct DecodedAnnotation {
    pub operation: String,
    pub source_address: u64,
    pub source_length: usize,
    pub parameters: String,
    pub text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Session {
    pub version: u32,
    pub binary_sha256: String,
    #[serde(deserialize_with = "deserialize_annotations")]
    pub annotations: BTreeMap<u64, Annotation>,
}

impl Session {
    pub fn new(sha256: String) -> Self {
        Self {
            version: SESSION_VERSION,
            binary_sha256: sha256,
            annotations: BTreeMap::new(),
        }
    }

    pub fn load(path: &Path, expected_sha256: &str) -> Result<Self, String> {
        #[cfg(windows)]
        crate::windows::validate_local_path(path)
            .map_err(|e| format!("Cannot open session: {e}"))?;
        validate_fingerprint(expected_sha256)?;
        // Reject existing special files and symlinks before opening. The flags
        // and opened descriptor check below also cover a raced substitution.
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("Cannot inspect session: {error}"))?;
        if !path_metadata.is_file() {
            return Err(
                "Session input must be a regular file, not a symbolic link or special file".into(),
            );
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        crate::windows::configure_read(&mut options);
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
        }
        let file = options
            .open(path)
            .map_err(|error| format!("Cannot open session: {error}"))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("Cannot inspect opened session: {error}"))?;
        if !metadata.is_file() {
            return Err("Session input must be a regular file".into());
        }
        #[cfg(windows)]
        crate::windows::verify_regular_file(&file)
            .map_err(|error| format!("Cannot inspect session: {error}"))?;
        if metadata.len() > MAX_SESSION_BYTES {
            return Err("Session exceeds the 8 MiB size limit".into());
        }
        // Also bound the actual read: the file may grow after metadata was checked.
        let mut bytes = Vec::new();
        file.take(MAX_SESSION_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Cannot read session: {error}"))?;
        if bytes.len() as u64 > MAX_SESSION_BYTES {
            return Err("Session exceeds the 8 MiB size limit".into());
        }
        let session: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("Invalid session JSON: {error}"))?;
        session.validate()?;
        if session.binary_sha256 != expected_sha256 {
            return Err("Session belongs to a different binary (SHA-256 mismatch)".into());
        }
        Ok(session)
    }

    /// Validate decoded source spans against the current immutable image's
    /// mapped regions. Like virtual byte reads, spans may cross contiguous
    /// sections and include mapped zero-filled tails, but never unmapped gaps.
    pub fn validate_ranges(&self, sections: &[SectionInfo]) -> Result<(), String> {
        self.validate()?;
        for annotation in self.annotations.values() {
            for decoded in &annotation.decoded {
                if decoded.source_length == 0 {
                    return Err("Decoded source range must contain at least one byte".into());
                }
                let end = decoded
                    .source_address
                    .checked_add(decoded.source_length as u64)
                    .ok_or("Decoded source range overflows the address space")?;
                let mut current = decoded.source_address;
                while current < end {
                    let section = sections
                        .iter()
                        .find(|section| {
                            current >= section.address && current - section.address < section.size
                        })
                        .ok_or_else(|| {
                            format!("Decoded source includes unmapped address {current:#x}")
                        })?;
                    // Validate section arithmetic rather than trusting persisted or
                    // future backend metadata to make monotonic progress for us.
                    let section_end = section
                        .address
                        .checked_add(section.size)
                        .ok_or("Mapped section range overflows the address space")?;
                    current = end.min(section_end);
                }
            }
        }
        Ok(())
    }

    /// Save annotations to a sidecar, rejecting the binary and its aliases.
    pub fn save(&self, path: &Path, protection: &BinaryProtection) -> Result<(), String> {
        self.save_with_guards(path, protection, &[])
    }

    /// Extra protected files (such as the active project) are checked at both
    /// validation and publication, and their handles stay live for the operation.
    pub(crate) fn save_with_guards(
        &self,
        path: &Path,
        protection: &BinaryProtection,
        guards: &[BinaryProtection],
    ) -> Result<(), String> {
        self.save_inner(path, protection, guards, || {})
    }

    fn save_inner(
        &self,
        path: &Path,
        protection: &BinaryProtection,
        guards: &[BinaryProtection],
        before_publication: impl FnOnce(),
    ) -> Result<(), String> {
        self.validate()?;
        if protection.snapshot_sha256.as_deref() != Some(self.binary_sha256.as_str()) {
            return Err("Session is not bound to the protected binary snapshot".into());
        }
        // Cap output while serializing, before allocating an unbounded JSON copy.
        // In particular, JSON escaping can expand otherwise valid field contents.
        let mut output = CappedOutput(Vec::new());
        serde_json::to_writer_pretty(&mut output, self)
            .map_err(|error| format!("Cannot serialize session: {error}"))?;
        let path = safe_destination(path, protection)?;
        for guard in guards {
            safe_destination(&path, guard)?;
        }
        let directory = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let filename = path.file_name().ok_or("Session path must name a file")?;
        let (temporary, mut file) = create_temporary(directory, filename)?;
        let result = (|| {
            file.write_all(&output.0)
                .map_err(|error| format!("Cannot write session: {error}"))?;
            #[cfg(unix)]
            if let Ok(metadata) = fs::symlink_metadata(&path) {
                use std::os::unix::fs::PermissionsExt;
                if metadata.is_file() {
                    // Retain a user's tighter owner restrictions, while keeping
                    // annotations private even if the old sidecar was public.
                    file.set_permissions(fs::Permissions::from_mode(
                        metadata.permissions().mode() & 0o600,
                    ))
                    .map_err(|error| format!("Cannot protect session permissions: {error}"))?;
                }
            }
            file.sync_all()
                .map_err(|error| format!("Cannot sync session: {error}"))?;
            drop(file);
            before_publication();
            // Same-directory rename atomically publishes the complete file. A failed
            // rename leaves the previous destination intact (including on Windows).
            // Recheck immediately before publication as well. We never open the
            // destination for writing, including when it names a symlink.
            safe_destination(&path, protection)?;
            for guard in guards {
                safe_destination(&path, guard)?;
            }
            atomic_replace(&temporary, &path)
                .map_err(|error| format!("Cannot replace session: {error}"))?;
            // Some filesystems/platforms do not support syncing directories. The
            // file itself was synced before publication; do not report a failed
            // save after the destination has already been successfully replaced.
            if let Ok(directory_file) = File::open(directory) {
                let _ = directory_file.sync_all();
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.version != SESSION_VERSION {
            return Err(format!(
                "Unsupported session version {} (expected 1)",
                self.version
            ));
        }
        validate_fingerprint(&self.binary_sha256)?;
        if self.annotations.len() > MAX_ANNOTATIONS {
            return Err("Session annotation count exceeds the 10000 annotation limit".into());
        }
        for annotation in self.annotations.values() {
            check_field("Annotation label", annotation.label.len(), MAX_LABEL_BYTES)?;
            check_field(
                "Annotation comment",
                annotation.comment.len(),
                MAX_COMMENT_BYTES,
            )?;
            if annotation.decoded.len() > MAX_DECODED_PER_ANNOTATION {
                return Err("Annotation exceeds the 32 decoded results limit".into());
            }
            for decoded in &annotation.decoded {
                check_field(
                    "Decoded operation",
                    decoded.operation.len(),
                    MAX_LABEL_BYTES,
                )?;
                check_field(
                    "Decoded parameters",
                    decoded.parameters.len(),
                    MAX_PARAMETERS_BYTES,
                )?;
                check_field("Decoded text", decoded.text.len(), MAX_DECODED_TEXT_BYTES)?;
                check_field(
                    "Decoded source",
                    decoded.source_length,
                    MAX_DECODED_SOURCE_BYTES,
                )?;
                let length = u64::try_from(decoded.source_length)
                    .map_err(|_| "Decoded source length exceeds the address space")?;
                decoded
                    .source_address
                    .checked_add(length)
                    .ok_or("Decoded source range overflows the address space")?;
            }
        }
        Ok(())
    }
}

// Bound collection construction itself, rather than allocating all the entries
// and only then rejecting the resulting Session in validate().
fn deserialize_annotations<'de, D>(deserializer: D) -> Result<BTreeMap<u64, Annotation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct AnnotationsVisitor;
    impl<'de> Visitor<'de> for AnnotationsVisitor {
        type Value = BTreeMap<u64, Annotation>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a map with at most 10000 annotations")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut annotations = BTreeMap::new();
            let mut count = 0;
            while let Some(address) = access.next_key::<u64>()? {
                if count == MAX_ANNOTATIONS {
                    return Err(serde::de::Error::custom(
                        "Session annotation count exceeds the 10000 annotation limit",
                    ));
                }
                annotations.insert(address, access.next_value()?);
                // Duplicate keys still consume the deserialization budget.
                count += 1;
            }
            Ok(annotations)
        }
    }
    deserializer.deserialize_map(AnnotationsVisitor)
}

fn deserialize_decoded<'de, D>(deserializer: D) -> Result<Vec<DecodedAnnotation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct DecodedSeed {
        allowed: bool,
    }
    impl<'de> DeserializeSeed<'de> for DecodedSeed {
        type Value = DecodedAnnotation;

        fn deserialize<E>(self, deserializer: E) -> Result<Self::Value, E::Error>
        where
            E: serde::Deserializer<'de>,
        {
            if !self.allowed {
                return Err(serde::de::Error::custom(
                    "Annotation exceeds the 32 decoded results limit",
                ));
            }
            DecodedAnnotation::deserialize(deserializer)
        }
    }
    struct DecodedVisitor;
    impl<'de> Visitor<'de> for DecodedVisitor {
        type Value = Vec<DecodedAnnotation>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a sequence with at most 32 decoded results")
        }

        fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut decoded = Vec::new();
            while let Some(value) = access.next_element_seed(DecodedSeed {
                allowed: decoded.len() < MAX_DECODED_PER_ANNOTATION,
            })? {
                decoded.push(value);
            }
            Ok(decoded)
        }
    }
    deserializer.deserialize_seq(DecodedVisitor)
}

fn check_field(name: &str, length: usize, maximum: usize) -> Result<(), String> {
    if length > maximum {
        Err(format!("{name} exceeds its {maximum} byte size limit"))
    } else {
        Ok(())
    }
}

struct CappedOutput(Vec<u8>);

impl Write for CappedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > (MAX_SESSION_BYTES as usize).saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "Session exceeds the 8 MiB size limit",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Resolve the parent once, so changing a symlink in a user-supplied directory
/// path does not redirect the eventual rename. Final symlinks/reparse points are
/// rejected instead of being followed or replaced.
pub(crate) fn safe_destination(
    path: &Path,
    protection: &BinaryProtection,
) -> Result<PathBuf, String> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let filename = path.file_name().ok_or("Session path must name a file")?;
    let directory = fs::canonicalize(directory)
        .map_err(|error| format!("Cannot resolve session directory: {error}"))?;
    let destination = directory.join(filename);
    #[cfg(windows)]
    crate::windows::validate_local_path(&destination)
        .map_err(|e| format!("Cannot save session: {e}"))?;
    if destination == protection.original_path {
        return Err("Cannot save a session over the input binary".into());
    }
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err("Session destination must not be a symbolic link".into());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err("Session destination must not be a reparse point".into());
                }
            }
            if fs::canonicalize(&destination)
                .map_err(|error| format!("Cannot resolve session destination: {error}"))?
                == protection.original_path
            {
                return Err("Cannot save a session over the input binary".into());
            }
            if !metadata.is_file() {
                return Err("Session destination must be a regular file".into());
            }
            let file = open_regular_file(&destination, u64::MAX)?;
            if FileIdentity::from_file(&file) == Some(protection.identity) {
                return Err("Cannot save a session over a hard link to the input binary".into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("Cannot inspect session destination: {error}")),
    }
    Ok(destination)
}

fn validate_fingerprint(fingerprint: &str) -> Result<(), String> {
    if fingerprint.len() != 64
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Binary SHA-256 must contain 64 lowercase hexadecimal digits".into());
    }
    Ok(())
}

pub(crate) fn create_temporary(
    directory: &Path,
    filename: &std::ffi::OsStr,
) -> Result<(PathBuf, File), String> {
    for _ in 0..100 {
        let mut temporary_name = std::ffi::OsString::from(".");
        temporary_name.push(filename);
        temporary_name.push(format!(
            ".{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let path = directory.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("Cannot create temporary session: {error}")),
        }
    }
    Err("Cannot allocate a unique temporary session file".into())
}

/// Open only a regular, non-symlink file, bounding its reported length before use.
pub(crate) fn open_regular_file(path: &Path, maximum: u64) -> Result<File, String> {
    #[cfg(windows)]
    crate::windows::validate_local_path(path).map_err(|e| format!("Cannot open file: {e}"))?;
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("Cannot inspect file: {e}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("Input must be a regular file, not a symbolic link or special file".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    crate::windows::configure_read(&mut options);
    let file = options
        .open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    #[cfg(windows)]
    crate::windows::verify_regular_file(&file).map_err(|e| format!("Cannot inspect file: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("Cannot inspect opened file: {e}"))?;
    if !metadata.is_file() {
        return Err("Input must be a regular file".into());
    }
    if metadata.len() > maximum {
        return Err("File exceeds its size limit".into());
    }
    Ok(file)
}

pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        crate::windows::atomic_replace(source, destination)
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination)
    }
}

/// Stream the input without retaining an additional copy of the binary in memory.
pub fn fingerprint(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|error| format!("Cannot open binary: {error}"))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let length = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash binary: {error}"))?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_rechecks_active_project_identity_after_temporary_file_is_written() {
        let directory = TestDirectory::new();
        let binary = directory.binary();
        let hash = fingerprint(&binary).unwrap();
        let protection = protect(&binary, &hash);
        let project_path = directory.path("active.grproj");
        fs::write(&project_path, b"existing project bytes").unwrap();
        let project_guard = BinaryProtection::open(&project_path).unwrap();
        let destination = directory.path("annotations.json");
        let result =
            Session::new(hash).save_inner(&destination, &protection, &[project_guard], || {
                fs::hard_link(&project_path, &destination).unwrap();
            });
        assert!(result.is_err());
        assert_eq!(fs::read(&project_path).unwrap(), b"existing project bytes");
        assert_eq!(fs::read(&destination).unwrap(), b"existing project bytes");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 3);
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ghidra-rust-session-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn protection(&self) -> BinaryProtection {
            protect(&self.binary(), &"a".repeat(64))
        }
        fn binary(&self) -> PathBuf {
            let path = self.path("program.bin");
            if !path.exists() {
                fs::write(&path, b"\x7fELFexample program").unwrap();
            }
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn protect(path: &Path, hash: &str) -> BinaryProtection {
        let protection = BinaryProtection::open(path).unwrap();
        let info = reported_info(&protection, hash);
        protection.bind_snapshot(&info).unwrap()
    }

    fn reported_info(protection: &BinaryProtection, hash: &str) -> BinaryInfo {
        BinaryInfo {
            path: protection.path().to_string_lossy().into_owned(),
            architecture: "x86-64".into(),
            format: "ELF".into(),
            entry: 0,
            file_len: 0,
            sha256: hash.into(),
            source_identity: Some(protection.identity),
            sections: Vec::new(),
            functions: Vec::new(),
            functions_truncated: false,
            warnings: Vec::new(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn retains_original_file_protection_when_name_is_replaced_or_removed() {
        let directory = TestDirectory::new();
        let binary = directory.binary();
        let original = fs::read(&binary).unwrap();
        let hash = fingerprint(&binary).unwrap();
        let session = populated_session(hash.clone());
        let protection = protect(&binary, &hash);
        let renamed = directory.path("renamed.bin");
        let hard = directory.path("renamed-hardlink.bin");
        fs::rename(&binary, &renamed).unwrap();
        fs::hard_link(&renamed, &hard).unwrap();
        fs::write(&binary, b"replacement binary").unwrap();
        for destination in [&binary, &renamed, &hard] {
            assert!(session.save(destination, &protection).is_err());
        }
        assert_eq!(fs::read(&binary).unwrap(), b"replacement binary");
        assert_eq!(fs::read(&renamed).unwrap(), original);
        assert_eq!(fs::read(&hard).unwrap(), original);
        fs::remove_file(&binary).unwrap();
        for destination in [&binary, &renamed, &hard] {
            assert!(session.save(destination, &protection).is_err());
        }
        assert!(!binary.exists());
        // Neither a missing original name nor a stopped worker prevents safe saves.
        let sidecar = directory.path("annotations.json");
        session.save(&sidecar, &protection).unwrap();
        assert_eq!(Session::load(&sidecar, &hash).unwrap().annotations.len(), 1);
        assert_eq!(fs::read(&renamed).unwrap(), original);
        assert_eq!(fs::read(&hard).unwrap(), original);
    }

    #[test]
    fn identity_binding_rejects_replaced_worker_input_and_unbound_snapshots() {
        let directory = TestDirectory::new();
        let binary = directory.binary();
        let hash = fingerprint(&binary).unwrap();
        let protection = BinaryProtection::open(&binary).unwrap();
        let session = Session::new(hash.clone());
        let sidecar = directory.path("annotations.json");
        assert!(session.save(&sidecar, &protection).is_err());
        let renamed = directory.path("renamed.bin");
        fs::rename(&binary, renamed).unwrap();
        fs::write(&binary, b"a different file").unwrap();
        let replacement = BinaryProtection::open(&binary).unwrap();
        let replacement_info = reported_info(&replacement, &hash);
        assert!(protection.verify_identity(&replacement_info).is_err());
        assert!(!protection.same_source(&replacement));
        assert!(protection.clone().bind_snapshot(&replacement_info).is_err());
        let mut missing_identity = reported_info(&protection, &hash);
        missing_identity.source_identity = None;
        assert!(protection.clone().bind_snapshot(&missing_identity).is_err());
        let info = reported_info(&protection, &hash);
        let bound = protection.bind_snapshot(&info).unwrap();
        assert!(Session::new("b".repeat(64)).save(&sidecar, &bound).is_err());
        session.save(&sidecar, &bound).unwrap();
        assert!(!sidecar.with_extension("tmp").exists());
    }

    #[test]
    fn identical_bytes_in_a_different_file_do_not_count_as_a_source_alias() {
        let directory = TestDirectory::new();
        let binary = directory.binary();
        let hash = fingerprint(&binary).unwrap();
        let protection = protect(&binary, &hash);
        let destination = directory.path("same-content.json");
        fs::copy(&binary, &destination).unwrap();
        Session::new(hash.clone())
            .save(&destination, &protection)
            .unwrap();
        assert!(Session::load(&destination, &hash).is_ok());
        assert_eq!(fingerprint(&binary).unwrap(), hash);
    }

    fn populated_session(hash: String) -> Session {
        let mut session = Session::new(hash);
        session.annotations.insert(
            0x401000,
            Annotation {
                label: "decode_payload".into(),
                comment: "Reads the configuration".into(),
                decoded: vec![DecodedAnnotation {
                    operation: "xor".into(),
                    source_address: 0x402000,
                    source_length: 6,
                    parameters: "key=2a".into(),
                    text: "secret".into(),
                }],
            },
        );
        session
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_load_rejects_fifo_without_waiting() {
        const CHILD_PATH: &str = "GHIDRA_RUST_SESSION_FIFO_TEST";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            assert!(
                Session::load(Path::new(&path), &"a".repeat(64))
                    .unwrap_err()
                    .contains("regular file")
            );
            return;
        }
        let directory = TestDirectory::new();
        let fifo = directory.path("annotations.fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        // Isolate the potentially blocking regression in a subprocess so failure
        // cannot leave a reader thread or a hung test executable behind.
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "session::tests::session_load_rejects_fifo_without_waiting",
            ])
            .env(CHILD_PATH, &fifo)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("Session::load blocked while opening a FIFO");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn session_load_rejects_directories_symlinks_and_devices() {
        use std::os::unix::fs::symlink;
        let directory = TestDirectory::new();
        let sidecar = directory.path("annotations.json");
        let link = directory.path("link.json");
        Session::new("a".repeat(64))
            .save(&sidecar, &directory.protection())
            .unwrap();
        symlink(&sidecar, &link).unwrap();
        for path in [&directory.0, &link, Path::new("/dev/null")] {
            assert!(
                Session::load(path, &"a".repeat(64))
                    .unwrap_err()
                    .contains("regular file")
            );
        }
    }

    #[test]
    fn session_collection_limits_reject_before_parsing_excess_values() {
        let directory = TestDirectory::new();
        let path = directory.path("over-limit.json");
        let hash = "a".repeat(64);
        let annotation = serde_json::to_string(&Annotation::default()).unwrap();
        for duplicate_keys in [false, true] {
            let mut json = format!(r#"{{"version":1,"binary_sha256":"{hash}","annotations":{{"#);
            for index in 0..MAX_ANNOTATIONS {
                let address = if duplicate_keys { 0 } else { index };
                json.push_str(&format!(r#""{address}":{annotation},"#));
            }
            // This value is malformed deliberately: the count failure must win
            // before the parser tries constructing the next Annotation.
            json.push_str(r#""10001":not-valid-json}}"#);
            fs::write(&path, json).unwrap();
            assert!(
                Session::load(&path, &hash)
                    .unwrap_err()
                    .contains("annotation count")
            );
        }
        let decoded = serde_json::to_string(&DecodedAnnotation::default()).unwrap();
        let mut json = format!(
            r#"{{"version":1,"binary_sha256":"{hash}","annotations":{{"0":{{"label":"","comment":"","decoded":["#
        );
        for _ in 0..MAX_DECODED_PER_ANNOTATION {
            json.push_str(&decoded);
            json.push(',');
        }
        json.push_str("not-valid-json]}}}");
        fs::write(&path, json).unwrap();
        assert!(
            Session::load(&path, &hash)
                .unwrap_err()
                .contains("decoded results limit")
        );
    }

    #[test]
    fn decoded_ranges_follow_mapped_virtual_bytes_including_zero_filled_tails() {
        let section = |address, size, file_size| SectionInfo {
            name: "mapped".into(),
            address,
            size,
            file_offset: 0,
            file_size,
            executable: false,
        };
        // Sections are intentionally out of order; neither iteration order nor
        // file-backed lengths determine virtual address coverage.
        let sections = [section(0x1008, 8, 0), section(0x1000, 8, 4)];
        let mut session = populated_session("a".repeat(64));
        let set_range = |session: &mut Session, address, length| {
            let decoded = &mut session.annotations.get_mut(&0x401000).unwrap().decoded[0];
            decoded.source_address = address;
            decoded.source_length = length;
        };
        for (address, length) in [(0x1000, 16), (0x1002, 12), (0x100f, 1)] {
            set_range(&mut session, address, length);
            session.validate_ranges(&sections).unwrap();
        }
        for (address, length, error) in [
            (0x0fff, 1, "unmapped"),
            (0x100f, 2, "unmapped"),
            (0x1010, 1, "unmapped"),
            (0x1000, 0, "at least one"),
            (u64::MAX, 1, "overflows"),
        ] {
            set_range(&mut session, address, length);
            assert!(
                session
                    .validate_ranges(&sections)
                    .unwrap_err()
                    .contains(error)
            );
        }
        set_range(&mut session, 0x1004, 12);
        let gap = [section(0x1000, 8, 8), section(0x1009, 8, 8)];
        assert!(
            session
                .validate_ranges(&gap)
                .unwrap_err()
                .contains("unmapped")
        );
        set_range(&mut session, u64::MAX - 1, 1);
        assert!(
            session
                .validate_ranges(&[section(u64::MAX - 2, 8, 0)])
                .unwrap_err()
                .contains("section range overflows")
        );
        Session::new("a".repeat(64)).validate_ranges(&[]).unwrap();
    }

    #[test]
    fn annotations_round_trip_without_modifying_the_binary() {
        let directory = TestDirectory::new();
        let binary = directory.path("program.bin");
        fs::write(&binary, b"\x7fELFexample program").unwrap();
        let original = fs::read(&binary).unwrap();
        let hash = fingerprint(&binary).unwrap();
        let session = populated_session(hash.clone());
        let sidecar = directory.path("program.session.json");
        session.save(&sidecar, &protect(&binary, &hash)).unwrap();
        let loaded = Session::load(&sidecar, &hash).unwrap();
        assert_eq!(
            serde_json::to_value(session).unwrap(),
            serde_json::to_value(loaded).unwrap()
        );
        assert_eq!(fs::read(binary).unwrap(), original);
    }

    #[test]
    fn fingerprint_matches_a_known_sha256() {
        let directory = TestDirectory::new();
        let binary = directory.path("abc");
        fs::write(&binary, b"abc").unwrap();
        assert_eq!(
            fingerprint(&binary).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_mismatched_binary_malformed_json_and_schema() {
        let directory = TestDirectory::new();
        let path = directory.path("session.json");
        let hash = "a".repeat(64);
        Session::new(hash.clone())
            .save(&path, &directory.protection())
            .unwrap();
        assert!(
            Session::load(&path, &"b".repeat(64))
                .unwrap_err()
                .contains("different binary")
        );
        fs::write(&path, b"{not json").unwrap();
        assert!(
            Session::load(&path, &hash)
                .unwrap_err()
                .contains("Invalid session JSON")
        );
        for version in [0, 2, u32::MAX] {
            fs::write(
                &path,
                format!(r#"{{"version":{version},"binary_sha256":"{hash}","annotations":{{}}}}"#),
            )
            .unwrap();
            assert!(
                Session::load(&path, &hash)
                    .unwrap_err()
                    .contains("Unsupported session version")
            );
        }
        fs::write(&path, r#"{"version":1}"#).unwrap();
        assert!(Session::load(&path, &hash).is_err());
    }

    #[test]
    fn rejects_oversized_files_and_invalid_fingerprints() {
        let directory = TestDirectory::new();
        let path = directory.path("session.json");
        let file = File::create(&path).unwrap();
        file.set_len(MAX_SESSION_BYTES + 1).unwrap();
        // The loader deliberately denies write sharing on Windows. Close the
        // fixture's writable handle so this reaches the size-limit check.
        drop(file);
        assert!(
            Session::load(&path, &"a".repeat(64))
                .unwrap_err()
                .contains("size limit")
        );
        for hash in [
            String::new(),
            "g".repeat(64),
            "A".repeat(64),
            "0".repeat(63),
        ] {
            assert!(
                Session::new(hash)
                    .save(&path, &directory.protection())
                    .is_err()
            );
        }
        assert_eq!(fs::metadata(path).unwrap().len(), MAX_SESSION_BYTES + 1);
    }

    #[test]
    fn replaces_complete_session_and_preserves_destination_on_validation_error() {
        let directory = TestDirectory::new();
        let path = directory.path("session.json");
        let hash = "a".repeat(64);
        Session::new(hash.clone())
            .save(&path, &directory.protection())
            .unwrap();
        let mut replacement = populated_session(hash.clone());
        replacement.save(&path, &directory.protection()).unwrap();
        assert_eq!(
            Session::load(&path, &hash).unwrap().annotations[&0x401000].label,
            "decode_payload"
        );
        let saved = fs::read(&path).unwrap();
        replacement.version = 2;
        assert!(replacement.save(&path, &directory.protection()).is_err());
        assert_eq!(fs::read(&path).unwrap(), saved);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn rename_failure_cleans_up_temporary_file_and_preserves_destination() {
        let directory = TestDirectory::new();
        let destination = directory.path("existing-directory");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep"), b"untouched").unwrap();
        assert!(
            Session::new("a".repeat(64))
                .save(&destination, &directory.protection())
                .is_err()
        );
        assert_eq!(fs::read(destination.join("keep")).unwrap(), b"untouched");
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[test]
    fn refuses_oversized_serialization_and_overflowing_decoded_ranges() {
        let directory = TestDirectory::new();
        let path = directory.path("session.json");
        let mut session = populated_session("a".repeat(64));
        session.annotations.get_mut(&0x401000).unwrap().comment =
            "x".repeat(MAX_SESSION_BYTES as usize);
        assert!(
            session
                .save(&path, &directory.protection())
                .unwrap_err()
                .contains("size limit")
        );
        assert!(!path.exists());
        session
            .annotations
            .get_mut(&0x401000)
            .unwrap()
            .comment
            .clear();
        session.annotations.get_mut(&0x401000).unwrap().decoded[0].source_address = u64::MAX;
        assert!(
            session
                .save(&path, &directory.protection())
                .unwrap_err()
                .contains("overflows")
        );
        assert!(!path.exists());
    }

    #[test]
    fn refuses_original_binary_and_canonical_alias_without_modifying_bytes() {
        let directory = TestDirectory::new();
        let binary = directory.binary();
        let original = fs::read(&binary).unwrap();
        let session = populated_session(fingerprint(&binary).unwrap());
        for destination in [&binary, &directory.path("./program.bin")] {
            assert!(
                session
                    .save(destination, &protect(&binary, &session.binary_sha256))
                    .unwrap_err()
                    .contains("input binary")
            );
            assert_eq!(fs::read(&binary).unwrap(), original);
        }
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symbolic_and_hard_links_to_binary() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let directory = TestDirectory::new();
        let binary = directory.binary();
        let original = fs::read(&binary).unwrap();
        let symbolic = directory.path("symbolic.json");
        let hard = directory.path("hard.json");
        symlink(&binary, &symbolic).unwrap();
        fs::hard_link(&binary, &hard).unwrap();
        let session = populated_session(fingerprint(&binary).unwrap());
        assert!(
            session
                .save(&symbolic, &protect(&binary, &session.binary_sha256))
                .unwrap_err()
                .contains("symbolic link")
        );
        assert!(
            session
                .save(&hard, &protect(&binary, &session.binary_sha256))
                .unwrap_err()
                .contains("hard link")
        );
        assert!(
            session
                .save(&binary, &protect(&symbolic, &session.binary_sha256))
                .is_err()
        );
        assert!(
            session
                .save(
                    &directory.path("./program.bin"),
                    &protect(&hard, &session.binary_sha256)
                )
                .is_err()
        );
        assert_eq!(fs::read(&binary).unwrap(), original);
        assert_eq!(fs::read(&symbolic).unwrap(), original);
        assert_eq!(fs::read(&hard).unwrap(), original);
        assert_eq!(
            fs::metadata(&hard).unwrap().ino(),
            fs::metadata(&binary).unwrap().ino()
        );
        assert!(
            fs::symlink_metadata(symbolic)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 3);
    }

    #[test]
    fn loaded_sessions_reject_excessive_counts_and_fields() {
        let directory = TestDirectory::new();
        let path = directory.path("malicious.json");
        let hash = "a".repeat(64);
        let check = |session: &Session, expected: &str| {
            let bytes = serde_json::to_vec(session).unwrap();
            assert!(bytes.len() < MAX_SESSION_BYTES as usize);
            fs::write(&path, bytes).unwrap();
            assert!(Session::load(&path, &hash).unwrap_err().contains(expected));
            assert!(
                session
                    .save(&directory.path("rejected.json"), &directory.protection())
                    .is_err()
            );
            assert!(!directory.path("rejected.json").exists());
        };
        let mut session = Session::new(hash.clone());
        for address in 0..=MAX_ANNOTATIONS as u64 {
            session.annotations.insert(address, Annotation::default());
        }
        check(&session, "annotation count");
        let mut session = populated_session(hash.clone());
        session.annotations.get_mut(&0x401000).unwrap().label = "x".repeat(MAX_LABEL_BYTES + 1);
        check(&session, "label");
        let mut session = populated_session(hash.clone());
        session.annotations.get_mut(&0x401000).unwrap().comment = "x".repeat(MAX_COMMENT_BYTES + 1);
        check(&session, "comment");
        let mut session = populated_session(hash.clone());
        session.annotations.get_mut(&0x401000).unwrap().decoded =
            vec![DecodedAnnotation::default(); MAX_DECODED_PER_ANNOTATION + 1];
        check(&session, "decoded results");
        let mut session = populated_session(hash.clone());
        session.annotations.get_mut(&0x401000).unwrap().decoded[0].text =
            "x".repeat(MAX_DECODED_TEXT_BYTES + 1);
        check(&session, "Decoded text");
        let mut session = populated_session(hash.clone());
        session.annotations.get_mut(&0x401000).unwrap().decoded[0].parameters =
            "x".repeat(MAX_PARAMETERS_BYTES + 1);
        check(&session, "parameters");
        let mut session = populated_session(hash.clone());
        session.annotations.get_mut(&0x401000).unwrap().decoded[0].source_length =
            MAX_DECODED_SOURCE_BYTES + 1;
        check(&session, "Decoded source");
    }

    #[test]
    fn escaped_serialization_is_capped_and_preserves_existing_session() {
        let directory = TestDirectory::new();
        let path = directory.path("session.json");
        let binary = directory.binary();
        let mut session = populated_session(fingerprint(&binary).unwrap());
        session
            .save(&path, &protect(&binary, &session.binary_sha256))
            .unwrap();
        let original = fs::read(&path).unwrap();
        // Small input fields expand sixfold when JSON escapes NUL characters.
        // Each field passes its bound, while the aggregate output exceeds 8 MiB.
        session.annotations.get_mut(&0x401000).unwrap().decoded = vec![
            DecodedAnnotation {
                text: "\0".repeat(64 * 1024),
                ..DecodedAnnotation::default()
            };
            MAX_DECODED_PER_ANNOTATION
        ];
        assert!(
            session
                .save(&path, &protect(&binary, &session.binary_sha256))
                .unwrap_err()
                .contains("8 MiB")
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn session_files_are_private_and_retain_tighter_owner_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new();
        let path = directory.path("session.json");
        let binary = directory.binary();
        let session = populated_session(fingerprint(&binary).unwrap());
        session
            .save(&path, &protect(&binary, &session.binary_sha256))
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        session
            .save(&path, &protect(&binary, &session.binary_sha256))
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );
    }
}
