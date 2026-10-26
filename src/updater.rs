//! Explicit, bounded update jobs. Only a manifest authenticated by the embedded
//! Ed25519 key can authorize bytes, versions, or target names for installation.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

use crate::session::{BinaryProtection, safe_destination};

mod backup_cleanup;
use backup_cleanup::BackupCleanup;

const REPOSITORY: &str = "mahirriki1/ghidra-rust";
const RELEASES_URL: &str = "https://api.github.com/repos/mahirriki1/ghidra-rust/releases";
const DOWNLOAD_ROOT: &str = "https://github.com/mahirriki1/ghidra-rust/releases/download/";
const PUBLIC_KEY: &str = include_str!("../data/update-public-key.txt");
const MAX_RELEASE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MANIFEST: u64 = 16 * 1024;
const MAX_BINARY: u64 = 512 * 1024 * 1024;
const MAX_NOTICES: u64 = 16 * 1024 * 1024;
const MAX_NOTES: usize = 32 * 1024;
const BACKUP_RANDOM_CHARS: usize = 6;
#[cfg(windows)]
const MAX_BACKUP_ENTRIES_SCANNED: usize = 4096;
#[cfg(windows)]
const MAX_BACKUPS_REMOVED: usize = 128;

pub fn supported() -> bool {
    target().is_some()
}

fn target() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("linux-x64")
    } else if cfg!(all(windows, target_arch = "x86_64")) {
        Some("windows-x64")
    } else {
        None
    }
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    body: Option<String>,
    assets: Vec<ReleaseAsset>,
}

#[derive(Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    repository: String,
    version: String,
    binaries: BTreeMap<String, Artifact>,
    notices: Artifact,
}

#[derive(Clone)]
pub struct Available {
    pub version: String,
    pub notes: String,
    pub release_url: String,
    binary: Artifact,
    notices: Artifact,
    executable: BinaryProtection,
}

pub struct Prepared {
    pub release: Available,
    directory: TempDir,
}

#[derive(Debug)]
pub struct Installed {
    pub executable: PathBuf,
    pub backup: PathBuf,
    pub notices: PathBuf,
}

/// Set only after installation succeeds. Main relaunches after eframe has
/// dropped the desktop and its retained image/worker ownership.
#[derive(Default, Clone)]
pub struct RestartSlot(Arc<Mutex<Option<Restart>>>);

pub struct Restart {
    pub executable: PathBuf,
    pub project: Option<PathBuf>,
}

impl RestartSlot {
    pub fn set(&self, restart: Restart) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Some(restart);
    }

    pub fn take(&self) -> Option<Restart> {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
    }
}

pub struct Job<T> {
    receiver: mpsc::Receiver<Result<T, String>>,
    cancelled: Arc<AtomicBool>,
    received: Arc<AtomicU64>,
    pub total: u64,
}

impl<T: Send + 'static> Job<T> {
    #[cfg(test)]
    pub(crate) fn pending_for_test() -> (Self, mpsc::SyncSender<Result<T, String>>) {
        let (sender, receiver) = mpsc::sync_channel(1);
        (
            Self {
                receiver,
                cancelled: Arc::new(AtomicBool::new(false)),
                received: Arc::new(AtomicU64::new(0)),
                total: 0,
            },
            sender,
        )
    }

    fn start(
        context: &eframe::egui::Context,
        total: u64,
        task: impl FnOnce(&AtomicBool, &AtomicU64) -> Result<T, String> + Send + 'static,
    ) -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicU64::new(0));
        let cancel = Arc::clone(&cancelled);
        let progress = Arc::clone(&received);
        let context = context.clone();
        let errors = sender.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("application-update".into())
            .spawn(move || {
                let result = task(&cancel, &progress);
                let _ = sender.send(result);
                context.request_repaint();
            })
        {
            let _ = errors.send(Err(format!("Cannot start update job: {error}")));
        }
        Self {
            receiver,
            cancelled,
            received,
            total,
        }
    }

    pub fn poll(&self) -> Option<Result<T, String>> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("Update job stopped unexpectedly".into()))
            }
        }
    }

    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

impl<T> Drop for Job<T> {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), String> {
    if cancelled.load(Ordering::Relaxed) {
        Err("Update cancelled".into())
    } else {
        Ok(())
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(5)
        .timeout_global(Some(Duration::from_secs(300)))
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(15)))
        .timeout_per_read(Some(Duration::from_secs(5)))
        .timeout_recv_body(Some(Duration::from_secs(240)))
        .build()
        .into()
}

fn get(agent: &ureq::Agent, url: &str) -> Result<ureq::http::Response<ureq::Body>, String> {
    agent
        .get(url)
        .header(
            "User-Agent",
            concat!("ghidra-rust/", env!("CARGO_PKG_VERSION")),
        )
        .header(
            "Accept",
            if url.starts_with(RELEASES_URL) {
                "application/vnd.github+json"
            } else {
                "application/octet-stream"
            },
        )
        .call()
        .map_err(|error| format!("Cannot download update information: {error}"))
}

fn read_bounded(
    mut reader: impl Read,
    limit: u64,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        check_cancelled(cancelled)?;
        let size = reader
            .read(&mut chunk)
            .map_err(|error| format!("Update read failed: {error}"))?;
        if size == 0 {
            return Ok(bytes);
        }
        if bytes.len() as u64 + size as u64 > limit {
            return Err("Update response exceeds its size limit".into());
        }
        bytes.extend_from_slice(&chunk[..size]);
    }
}

fn fetch(
    agent: &ureq::Agent,
    url: &str,
    limit: u64,
    cancelled: &AtomicBool,
) -> Result<Vec<u8>, String> {
    check_cancelled(cancelled)?;
    let mut response = get(agent, url)?;
    read_bounded(response.body_mut().as_reader(), limit, cancelled)
}

fn plain_version(value: &str) -> Option<Version> {
    let version = Version::parse(value).ok()?;
    (version.pre.is_empty() && version.build.is_empty()).then_some(version)
}

fn newest(releases: Vec<Release>, current: &Version) -> Option<Release> {
    releases
        .into_iter()
        .filter(|release| !release.draft && (current.major == 0 || !release.prerelease))
        .filter_map(|release| {
            let version = plain_version(release.tag_name.strip_prefix('v')?)?;
            (version > *current).then_some((version, release))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, release)| release)
}

fn artifact_url(version: &str, name: &str) -> String {
    format!("{DOWNLOAD_ROOT}v{version}/{name}")
}

fn require_asset(
    release: &Release,
    version: &str,
    name: &str,
    size: Option<u64>,
    limit: u64,
) -> Result<(), String> {
    let mut assets = release.assets.iter().filter(|asset| asset.name == name);
    let asset = assets
        .next()
        .ok_or_else(|| format!("Release has no {name}. It may predate verified in-app updates."))?;
    if assets.next().is_some()
        || asset.size == 0
        || asset.size > limit
        || size.is_some_and(|size| asset.size != size)
        || asset.browser_download_url != artifact_url(version, name)
    {
        return Err(format!("Release has invalid update metadata for {name}"));
    }
    Ok(())
}

fn verify_manifest(
    bytes: &[u8],
    signature: &[u8],
    public: &str,
    version: &str,
    platform: &str,
) -> Result<(Artifact, Artifact), String> {
    if bytes.len() as u64 > MAX_MANIFEST || signature.len() != 64 {
        return Err("Invalid update manifest size or signature".into());
    }
    let key = base64::engine::general_purpose::STANDARD
        .decode(public.trim())
        .map_err(|_| "Invalid embedded update key")?;
    let key = VerifyingKey::from_bytes(&key.try_into().map_err(|_| "Invalid embedded update key")?)
        .map_err(|_| "Invalid embedded update key")?;
    let signature = Signature::from_slice(signature).map_err(|_| "Invalid update signature")?;
    key.verify_strict(bytes, &signature)
        .map_err(|_| "Update signature verification failed; nothing was installed")?;
    let manifest: Manifest = serde_json::from_slice(bytes)
        .map_err(|error| format!("Invalid update manifest: {error}"))?;
    if manifest.format != 1
        || manifest.repository != REPOSITORY
        || manifest.version != version
        || plain_version(version).is_none()
        || manifest.binaries.len() != 2
    {
        return Err("Update manifest does not match this release".into());
    }
    for (platform, binary) in &manifest.binaries {
        let suffix = match platform.as_str() {
            "linux-x64" => "linux-x64",
            "windows-x64" => "windows-x64.exe",
            _ => return Err("Unsupported update target".into()),
        };
        validate_artifact(
            binary,
            &format!("ghidra-rust-{version}-{suffix}"),
            MAX_BINARY,
        )?;
    }
    validate_artifact(
        &manifest.notices,
        &format!("ghidra-rust-{version}-update-notices.txt"),
        MAX_NOTICES,
    )?;
    let binary = manifest
        .binaries
        .get(platform)
        .ok_or("Release does not support this desktop")?
        .clone();
    Ok((binary, manifest.notices))
}

fn validate_artifact(artifact: &Artifact, name: &str, limit: u64) -> Result<(), String> {
    if artifact.name != name
        || artifact.size == 0
        || artifact.size > limit
        || artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Invalid signed update artifact".into());
    }
    Ok(())
}

pub fn check(context: &eframe::egui::Context) -> Job<Option<Available>> {
    Job::start(context, 0, |cancel, _| {
        let platform =
            target().ok_or("In-app updates support Linux x64 and Windows x64 portable builds")?;
        let executable =
            BinaryProtection::open(&std::env::current_exe().map_err(|error| error.to_string())?)?;
        let current =
            plain_version(env!("CARGO_PKG_VERSION")).ok_or("Invalid application version")?;
        let agent = agent();
        let mut releases = Vec::new();
        // Bounded listing includes alpha releases and does not rely on /latest.
        for page in 1..=3 {
            let url = format!("{RELEASES_URL}?per_page=20&page={page}");
            let bytes = fetch(&agent, &url, MAX_RELEASE_BYTES, cancel)?;
            let batch: Vec<Release> = serde_json::from_slice(&bytes)
                .map_err(|error| format!("Invalid release list: {error}"))?;
            if batch.len() > 20 {
                return Err("Release list exceeds its count limit".into());
            }
            let last = batch.len() < 20;
            releases.extend(batch);
            if last {
                break;
            }
        }
        let Some(release) = newest(releases, &current) else {
            return Ok(None);
        };
        let version = release
            .tag_name
            .strip_prefix('v')
            .ok_or("Invalid release version")?;
        require_asset(&release, version, "update.json", None, MAX_MANIFEST)?;
        require_asset(&release, version, "update.json.sig", Some(64), 64)?;
        let bytes = fetch(
            &agent,
            &artifact_url(version, "update.json"),
            MAX_MANIFEST,
            cancel,
        )?;
        let signature = fetch(
            &agent,
            &artifact_url(version, "update.json.sig"),
            64,
            cancel,
        )?;
        let (binary, notices) = verify_manifest(&bytes, &signature, PUBLIC_KEY, version, platform)?;
        require_asset(
            &release,
            version,
            &binary.name,
            Some(binary.size),
            MAX_BINARY,
        )?;
        require_asset(
            &release,
            version,
            &notices.name,
            Some(notices.size),
            MAX_NOTICES,
        )?;
        let mut notes = release.body.unwrap_or_default();
        let mut end = notes.len().min(MAX_NOTES);
        while !notes.is_char_boundary(end) {
            end -= 1;
        }
        if end < notes.len() {
            notes.truncate(end);
            notes.push_str("\n[More notes on the release page]");
        }
        Ok(Some(Available {
            version: version.into(),
            notes,
            release_url: format!("https://github.com/{REPOSITORY}/releases/tag/v{version}"),
            binary,
            notices,
            executable,
        }))
    })
}

fn copy_verified(
    mut reader: impl Read,
    mut writer: impl Write,
    artifact: &Artifact,
    cancel: &AtomicBool,
    progress: &AtomicU64,
) -> Result<(), String> {
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        check_cancelled(cancel)?;
        let size = reader
            .read(&mut chunk)
            .map_err(|error| format!("Update download failed: {error}"))?;
        if size == 0 {
            break;
        }
        total += size as u64;
        if total > artifact.size {
            return Err("Update download exceeds its signed size".into());
        }
        writer
            .write_all(&chunk[..size])
            .map_err(|error| format!("Cannot stage update: {error}"))?;
        digest.update(&chunk[..size]);
        progress.fetch_add(size as u64, Ordering::Relaxed);
    }
    if total != artifact.size || format!("{:x}", digest.finalize()) != artifact.sha256 {
        return Err(
            "Update download failed SHA-256 or size verification; nothing was installed".into(),
        );
    }
    Ok(())
}

pub fn download(context: &eframe::egui::Context, release: Available) -> Job<Arc<Prepared>> {
    Job::start(
        context,
        release.binary.size + release.notices.size,
        move |cancel, progress| {
            // Probe directory access before fetching a potentially large executable.
            let parent = release
                .executable
                .path()
                .parent()
                .ok_or("Executable has no installation directory")?;
            let probe = NamedTempFile::new_in(parent).map_err(|error| format!("The installation folder is not writable: {error}. Move the portable app to a writable folder."))?;
            drop(probe);
            let directory = staging_directory()?;
            let agent = agent();
            for artifact in [&release.binary, &release.notices] {
                check_cancelled(cancel)?;
                let mut response = get(&agent, &artifact_url(&release.version, &artifact.name))?;
                let mut output = create_staged(&directory, artifact)?;
                copy_verified(
                    response.body_mut().as_reader(),
                    &mut output,
                    artifact,
                    cancel,
                    progress,
                )?;
                output.sync_all().map_err(|error| error.to_string())?;
            }
            Ok(Arc::new(Prepared { release, directory }))
        },
    )
}

fn staging_directory() -> Result<TempDir, String> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("ghidra-update-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Set permissions at creation; chmod afterward would leave a race.
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder
        .tempdir()
        .map_err(|error| format!("Cannot create private update staging: {error}"))
}

fn create_staged(directory: &TempDir, artifact: &Artifact) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(directory.path().join(&artifact.name))
        .map_err(|error| format!("Cannot create new update artifact: {error}"))
}

fn check_destination(
    release: &Available,
    protections: &[BinaryProtection],
) -> Result<PathBuf, String> {
    let destination = release.executable.path();
    let current = BinaryProtection::open(destination)?;
    if !current.same_source(&release.executable) {
        return Err(
            "The installed executable changed during the update; check for updates again".into(),
        );
    }
    for protection in protections {
        safe_destination(destination, protection)?;
    }
    // Also reject final symlinks even when no binary is being analyzed.
    if fs::symlink_metadata(destination)
        .map_err(|error| error.to_string())?
        .file_type()
        .is_symlink()
    {
        return Err("The installed executable must not be a symlink".into());
    }
    Ok(destination.to_owned())
}

#[cfg(any(windows, test))]
fn is_backup_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    #[cfg(windows)]
    let Some(name) = name.strip_suffix(".exe") else {
        return false;
    };
    let Some((version, random)) = name
        .strip_prefix("ghidra-rust-previous-")
        .and_then(|name| name.rsplit_once('-'))
    else {
        return false;
    };
    // tempfile 3 generates six ASCII alphanumeric characters by default. Set
    // that length explicitly at creation too, so a dependency update cannot
    // silently broaden the set of files eligible for cleanup.
    Version::parse(version).is_ok()
        && random.len() == BACKUP_RANDOM_CHARS
        && random.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn install(prepared: &Prepared, protections: &[BinaryProtection]) -> Result<Installed, String> {
    let release = &prepared.release;
    let destination = check_destination(release, protections)?;
    let parent = destination
        .parent()
        .ok_or("Executable has no installation directory")?;
    let mut cleanup = BackupCleanup::prepare(parent, &release.executable);
    let cancel = AtomicBool::new(false);
    let progress = AtomicU64::new(0);
    let mut staged = NamedTempFile::new_in(parent)
        .map_err(|error| format!("Cannot stage update in the installation folder: {error}"))?;
    let input = crate::session::open_regular_file(
        &prepared.directory.path().join(&release.binary.name),
        release.binary.size,
    )?;
    copy_verified(
        input,
        staged.as_file_mut(),
        &release.binary,
        &cancel,
        &progress,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        staged
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
    }
    staged
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    let mut notices = tempfile::Builder::new()
        .prefix(&format!("ghidra-rust-{}-notices-", release.version))
        .suffix(".txt")
        .tempfile_in(parent)
        .map_err(|error| error.to_string())?;
    let input = crate::session::open_regular_file(
        &prepared.directory.path().join(&release.notices.name),
        release.notices.size,
    )?;
    copy_verified(
        input,
        notices.as_file_mut(),
        &release.notices,
        &cancel,
        &progress,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        notices
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|error| error.to_string())?;
    }
    notices
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    let backup = tempfile::Builder::new()
        .prefix(&format!(
            "ghidra-rust-previous-{}-",
            env!("CARGO_PKG_VERSION")
        ))
        .suffix(if cfg!(windows) { ".exe" } else { "" })
        .rand_bytes(BACKUP_RANDOM_CHARS)
        .tempfile_in(parent)
        .map_err(|error| error.to_string())?;
    for protection in protections {
        safe_destination(backup.path(), protection)?;
        safe_destination(notices.path(), protection)?;
    }
    #[cfg(not(windows))]
    let mut backup = backup;
    #[cfg(not(windows))]
    {
        let original = File::open(&destination).map_err(|error| error.to_string())?;
        // Copy from the file whose identity was retained before downloading.
        if !release.executable.matches_file(&original) {
            return Err("Installed executable changed before backup".into());
        }
        std::io::copy(&mut original.take(MAX_BINARY + 1), backup.as_file_mut())
            .map_err(|error| error.to_string())?;
        if backup
            .as_file()
            .metadata()
            .map_err(|error| error.to_string())?
            .len()
            > MAX_BINARY
        {
            return Err("Installed executable exceeds the backup limit".into());
        }
        backup
            .as_file()
            .set_permissions(
                fs::metadata(&destination)
                    .map_err(|error| error.to_string())?
                    .permissions(),
            )
            .map_err(|error| error.to_string())?;
        backup
            .as_file()
            .sync_all()
            .map_err(|error| error.to_string())?;
    }
    check_destination(release, protections)?;
    cleanup.check_member(staged.path(), staged.as_file());
    cleanup.check_member(notices.path(), notices.as_file());
    cleanup.check_member(backup.path(), backup.as_file());
    let (backup_file, backup_path) = backup.keep().map_err(|error| error.to_string())?;
    drop(backup_file);
    let (notices_file, notices_path) = notices.keep().map_err(|error| error.to_string())?;
    #[cfg(windows)]
    let published_file = {
        // Windows permits renaming a running executable but not unlinking it.
        // Retain the previous executable as the newest recovery copy.
        crate::session::atomic_replace(&destination, &backup_path)
            .map_err(|error| format!("Cannot retain the previous executable: {error}"))?;
        let result = (|| {
            for protection in protections {
                safe_destination(&destination, protection)?;
            }
            let file = staged
                .persist_noclobber(&destination)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(file)
        })();
        match result {
            Ok(file) => file,
            Err(error) => return Err(rollback_publication(&error, &backup_path, &destination)),
        }
    };
    #[cfg(not(windows))]
    let published_file = {
        check_destination(release, protections)?;
        staged.persist(&destination).map_err(|error| {
            format!(
                "Cannot publish update: {error}. Previous executable: {}",
                backup_path.display()
            )
        })?
    };
    // Publication has succeeded; cleanup must never turn success into failure
    // or enter rollback. Pin and verify all retained identities first. The new
    // backup is the version that was running, even if the new app cannot start.
    #[cfg(windows)]
    let _ = (|| -> Result<(), String> {
        let Some(backup_file) = cleanup.recovery_file(&backup_path) else {
            return Ok(());
        };
        let published = BinaryProtection::from_open_file(&destination, published_file)?;
        let notices = BinaryProtection::from_open_file(&notices_path, notices_file)?;
        let backup = BinaryProtection::from_open_file(&backup_path, backup_file)?;
        if !backup.same_source(&release.executable) {
            return Ok(());
        }
        // These are the actual owned identities, not a path reopened after
        // publication. Membership mismatch disables cleanup atomically.
        cleanup.check_guard(&destination, &published);
        cleanup.check_guard(&backup_path, &backup);
        cleanup.check_guard(&notices_path, &notices);
        let mut guards = protections.to_vec();
        guards.extend([release.executable.clone(), published, backup, notices]);
        cleanup.prune(&guards);
        Ok(())
    })();
    #[cfg(not(windows))]
    drop((published_file, notices_file));
    Ok(Installed {
        executable: destination,
        backup: backup_path,
        notices: notices_path,
    })
}

#[cfg(windows)]
fn rollback_publication(
    error: &str,
    backup: &std::path::Path,
    destination: &std::path::Path,
) -> String {
    // Do not overwrite a file that appeared after the rename.
    match crate::windows::rename_no_replace(backup, destination) {
        Ok(()) => format!(
            "Cannot publish update: {error}. The previous executable was restored at {}",
            destination.display()
        ),
        Err(rollback) => format!(
            "Cannot publish update: {error}. Restoring the previous executable also failed: {rollback}. Recovery executable retained at {}",
            backup.display()
        ),
    }
}

pub fn install_job(
    context: &eframe::egui::Context,
    prepared: Arc<Prepared>,
    protections: Vec<BinaryProtection>,
    worker: Option<crate::client::WorkerClient>,
) -> Job<Installed> {
    Job::start(context, 0, move |_, _| {
        if let Some(worker) = worker {
            worker.stop_and_wait()?;
        }
        install(&prepared, &protections)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn release(version: &str, prerelease: bool, draft: bool) -> Release {
        Release {
            tag_name: format!("v{version}"),
            prerelease,
            draft,
            body: None,
            assets: vec![],
        }
    }

    fn artifact(name: &str, bytes: &[u8]) -> Artifact {
        Artifact {
            name: name.into(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    fn signed_manifest() -> (serde_json::Value, SigningKey, String) {
        // Test-only key, unrelated to the production trust root.
        let key = SigningKey::from_bytes(&[42; 32]);
        let public =
            base64::engine::general_purpose::STANDARD.encode(key.verifying_key().to_bytes());
        let record = |name: &str| json!({"name": name, "size": 20, "sha256": "ab".repeat(32)});
        let value = json!({"format": 1, "repository": REPOSITORY, "version": "0.0.9",
            "binaries": {
                "linux-x64": record("ghidra-rust-0.0.9-linux-x64"),
                "windows-x64": record("ghidra-rust-0.0.9-windows-x64.exe")
            }, "notices": record("ghidra-rust-0.0.9-update-notices.txt") });
        (value, key, public)
    }

    fn prepared() -> (TempDir, Prepared) {
        let installation = tempfile::tempdir().unwrap();
        let destination = installation.path().join("app");
        fs::write(&destination, b"old executable").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let binary = artifact("ghidra-rust-0.0.9-linux-x64", b"new executable");
        let notices = artifact(
            "ghidra-rust-0.0.9-update-notices.txt",
            b"current license notices",
        );
        fs::write(directory.path().join(&binary.name), b"new executable").unwrap();
        fs::write(
            directory.path().join(&notices.name),
            b"current license notices",
        )
        .unwrap();
        let release = Available {
            version: "0.0.9".into(),
            notes: String::new(),
            release_url: String::new(),
            binary,
            notices,
            executable: BinaryProtection::open(&destination).unwrap(),
        };
        (installation, Prepared { release, directory })
    }

    #[test]
    fn release_selection_includes_alphas_only_for_alpha_builds_and_never_downgrades() {
        let releases = || {
            vec![
                release("0.0.8", true, false),
                release("0.0.10", true, false),
                release("0.0.9", true, false),
                release("0.0.11", true, true),
                release("invalid", false, false),
            ]
        };
        assert_eq!(
            newest(releases(), &Version::new(0, 0, 7)).unwrap().tag_name,
            "v0.0.10"
        );
        assert!(newest(releases(), &Version::new(0, 0, 10)).is_none());
        assert_eq!(
            newest(
                vec![
                    release("1.1.0", true, false),
                    release("1.0.1", false, false)
                ],
                &Version::new(1, 0, 0)
            )
            .unwrap()
            .tag_name,
            "v1.0.1"
        );
        assert!(plain_version("0.0.9-alpha.1").is_none());
        assert!(plain_version("0.0.9+other").is_none());
    }

    #[test]
    fn signature_binds_manifest_to_repository_version_target_and_artifact_bounds() {
        let (manifest, key, public) = signed_manifest();
        let verify = |manifest: &serde_json::Value, version: &str, platform: &str| {
            let bytes = serde_json::to_vec(manifest).unwrap();
            let signature = key.sign(&bytes).to_bytes();
            verify_manifest(&bytes, &signature, &public, version, platform)
        };
        assert!(verify(&manifest, "0.0.9", "linux-x64").is_ok());
        assert!(verify(&manifest, "0.0.8", "linux-x64").is_err());
        assert!(verify(&manifest, "0.0.9", "linux-arm64").is_err());
        for replacement in [json!("../escape"), json!("https://example.com/app")] {
            let mut bad = manifest.clone();
            bad["binaries"]["linux-x64"]["name"] = replacement;
            assert!(verify(&bad, "0.0.9", "linux-x64").is_err());
        }
        let mut bad = manifest.clone();
        bad["repository"] = json!("other/project");
        assert!(verify(&bad, "0.0.9", "linux-x64").is_err());
        bad = manifest.clone();
        bad["binaries"]["linux-x64"]["size"] = json!(MAX_BINARY + 1);
        assert!(verify(&bad, "0.0.9", "linux-x64").is_err());
        let mut bytes = serde_json::to_vec(&manifest).unwrap();
        let signature = key.sign(&bytes).to_bytes();
        bytes.push(b' ');
        assert!(verify_manifest(&bytes, &signature, &public, "0.0.9", "linux-x64").is_err());
        assert!(verify_manifest(&bytes, &[0; 64], &public, "0.0.9", "linux-x64").is_err());
        assert!(verify_manifest(&bytes, &signature, PUBLIC_KEY, "0.0.9", "linux-x64").is_err());
    }

    #[test]
    fn missing_unsigned_duplicate_or_redirected_assets_are_rejected() {
        let mut release = release("0.0.9", true, false);
        assert!(require_asset(&release, "0.0.9", "update.json.sig", Some(64), 64).is_err());
        release.assets.push(ReleaseAsset {
            name: "update.json.sig".into(),
            browser_download_url: artifact_url("0.0.9", "update.json.sig"),
            size: 64,
        });
        assert!(require_asset(&release, "0.0.9", "update.json.sig", Some(64), 64).is_ok());
        release.assets[0].browser_download_url = "https://other.invalid/signature".into();
        assert!(require_asset(&release, "0.0.9", "update.json.sig", Some(64), 64).is_err());
        release.assets[0].browser_download_url = artifact_url("0.0.9", "update.json.sig");
        release.assets.push(ReleaseAsset {
            name: "update.json.sig".into(),
            browser_download_url: artifact_url("0.0.9", "update.json.sig"),
            size: 64,
        });
        assert!(require_asset(&release, "0.0.9", "update.json.sig", Some(64), 64).is_err());
    }

    #[test]
    fn downloads_reject_corruption_truncation_extra_bytes_and_cancellation() {
        let expected = artifact("app", b"abcd");
        let cancel = AtomicBool::new(false);
        let progress = AtomicU64::new(0);
        for input in [b"abc".as_slice(), b"abce", b"abcde"] {
            assert!(copy_verified(input, std::io::sink(), &expected, &cancel, &progress).is_err());
        }
        assert!(
            copy_verified(
                b"abcd".as_slice(),
                std::io::sink(),
                &expected,
                &cancel,
                &progress
            )
            .is_ok()
        );
        cancel.store(true, Ordering::Relaxed);
        assert!(
            copy_verified(
                b"abcd".as_slice(),
                std::io::sink(),
                &expected,
                &cancel,
                &progress
            )
            .is_err()
        );
        assert!(read_bounded(b"abcde".as_slice(), 4, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn install_retains_recovery_copy_and_new_notices_without_touching_other_files() {
        let (installation, prepared) = prepared();
        let unrelated = installation.path().join("analyst.grproj");
        fs::write(&unrelated, b"project contents").unwrap();
        let installed = install(&prepared, &[]).unwrap();
        assert_eq!(fs::read(&installed.executable).unwrap(), b"new executable");
        assert_eq!(fs::read(&installed.backup).unwrap(), b"old executable");
        assert_eq!(
            fs::read(&installed.notices).unwrap(),
            b"current license notices"
        );
        assert_eq!(fs::read(&unrelated).unwrap(), b"project contents");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                fs::metadata(&installed.executable)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o111,
                0
            );
            assert_eq!(
                fs::metadata(&installed.notices)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644
            );
        }
    }

    fn backup_path(directory: &Path, stem: &str) -> PathBuf {
        directory.join(format!(
            "ghidra-rust-previous-{stem}{}",
            if cfg!(windows) { ".exe" } else { "" }
        ))
    }

    #[test]
    fn successful_install_applies_platform_retention_and_keeps_protected_aliases() {
        let (installation, prepared) = prepared();
        let old = [
            "0.0.1-Ab09Zx",
            "0.0.2-xyz123",
            "0.0.3-alpha.1+build.2-A1b2C3",
        ]
        .map(|name| backup_path(installation.path(), name));
        for path in &old {
            fs::write(path, b"older recovery copy").unwrap();
        }
        let similar = [
            "ghidra-rust-previous-notes.txt",
            "ghidra-rust-previous-0.0.1-abc12",
            "ghidra-rust-previous-0.0.1-abc1234",
            "ghidra-rust-previous-0.0.1-ab_123",
            "ghidra-rust-previous-0.0.1-abc123.exe.extra",
            "ghidra-rust-previous-0.0.1-abc123.txt",
            "ghidra-rust-previous-01.0.1-abc123",
            "ghidra-rust-previous-v0.0.1-abc123",
            "ghidra-rust-previous-0.0.1-abc123.exe.exe",
            "analyst.grproj",
        ];
        let mut kept: Vec<_> = similar
            .iter()
            .map(|name| installation.path().join(name))
            .collect();
        // Also exercise invalid stems with the platform's correct extension.
        kept.extend(
            [
                "notes-abc123",
                "0.0.1-abc12",
                "01.0.1-abc123",
                "0.0.1-ab_123",
            ]
            .map(|name| backup_path(installation.path(), name)),
        );
        kept.push(installation.path().join(if cfg!(windows) {
            "ghidra-rust-previous-0.0.1-abc123"
        } else {
            "ghidra-rust-previous-0.0.1-abc123.exe"
        }));
        for path in &kept {
            fs::write(path, b"keep this file").unwrap();
        }
        let input = installation.path().join("input");
        fs::write(&input, b"protected input").unwrap();
        let protection = BinaryProtection::open(&input).unwrap();
        let input_alias = backup_path(installation.path(), "0.0.1-Input1");
        fs::hard_link(&input, &input_alias).unwrap();
        // The retained handle must protect aliases even after its original path moves.
        fs::rename(&input, installation.path().join("renamed-input")).unwrap();
        let current_alias = backup_path(installation.path(), "0.0.1-App123");
        fs::hard_link(prepared.release.executable.path(), &current_alias).unwrap();
        let nested = backup_path(installation.path(), "0.0.1-Dir123");
        fs::create_dir(&nested).unwrap();
        let nested_backup = backup_path(&nested, "0.0.1-abc123");
        fs::write(&nested_backup, b"nested file").unwrap();

        let installed = install(&prepared, &[protection]).unwrap();
        #[cfg(windows)]
        assert!(old.iter().all(|path| !path.exists()));
        #[cfg(not(windows))]
        assert!(
            old.iter()
                .all(|path| fs::read(path).unwrap() == b"older recovery copy")
        );
        assert_eq!(fs::read(&installed.backup).unwrap(), b"old executable");
        assert!(is_backup_name(installed.backup.file_name().unwrap()));
        assert_eq!(fs::read(&installed.executable).unwrap(), b"new executable");
        assert_eq!(
            fs::read(&installed.notices).unwrap(),
            b"current license notices"
        );
        for path in &kept {
            assert_eq!(
                fs::read(path).unwrap(),
                b"keep this file",
                "{}",
                path.display()
            );
        }
        assert_eq!(fs::read(input_alias).unwrap(), b"protected input");
        assert_eq!(fs::read(current_alias).unwrap(), b"old executable");
        assert_eq!(fs::read(nested_backup).unwrap(), b"nested file");
    }

    #[test]
    fn cleanup_preserves_all_retained_file_aliases() {
        let (installation, prepared) = prepared();
        let installed = install(&prepared, &[]).unwrap();
        let paths = [&installed.executable, &installed.backup, &installed.notices];
        let guards: Vec<_> = paths
            .iter()
            .map(|path| BinaryProtection::open(path).unwrap())
            .collect();
        let aliases: Vec<_> = paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                let alias = backup_path(installation.path(), &format!("0.0.1-Alias{index}"));
                fs::hard_link(path, &alias).unwrap();
                alias
            })
            .collect();
        BackupCleanup::prepare(installation.path(), &guards[0]).prune(&guards);
        for (alias, path) in aliases.iter().zip(paths) {
            assert_eq!(fs::read(alias).unwrap(), fs::read(path).unwrap());
        }
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn cleanup_skips_symlinks_and_keeps_their_targets() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink as symlink_file;
        #[cfg(windows)]
        use std::os::windows::fs::symlink_file;
        let (installation, prepared) = prepared();
        let outside = tempfile::tempdir().unwrap();
        let target = backup_path(outside.path(), "0.0.1-Target");
        fs::write(&target, b"external recovery copy").unwrap();
        let candidate = backup_path(installation.path(), "0.0.1-Link12");
        let result = symlink_file(&target, &candidate);
        #[cfg(windows)]
        if result
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(1314))
        {
            eprintln!(
                "Windows file-symlink case unavailable: no developer mode/symlink privilege; junction case runs separately"
            );
            return;
        }
        result.unwrap();
        let unrelated_link = installation.path().join("recovery-link");
        symlink_file(&target, &unrelated_link).unwrap();
        let ordinary_target = outside.path().join("ordinary-target");
        fs::write(&ordinary_target, b"ordinary target").unwrap();
        let second_candidate = backup_path(installation.path(), "0.0.1-Link34");
        symlink_file(&ordinary_target, &second_candidate).unwrap();
        install(&prepared, &[]).unwrap();
        for path in [&candidate, &unrelated_link, &second_candidate] {
            assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
        }
        assert_eq!(fs::read(target).unwrap(), b"external recovery copy");
        assert_eq!(fs::read(ordinary_target).unwrap(), b"ordinary target");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unreadable_cleanup_directory_does_not_fail_install() {
        use std::os::unix::fs::PermissionsExt;
        let (installation, prepared) = prepared();
        let old = backup_path(installation.path(), "0.0.1-abc123");
        fs::write(&old, b"old recovery copy").unwrap();
        // Linux keeps all copies without enumeration or deletion, including
        // when the installation directory cannot be enumerated.
        fs::set_permissions(installation.path(), fs::Permissions::from_mode(0o300)).unwrap();
        let result = install(&prepared, &[]);
        fs::set_permissions(installation.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let installed = result.unwrap();
        assert_eq!(fs::read(installed.executable).unwrap(), b"new executable");
        assert_eq!(fs::read(old).unwrap(), b"old recovery copy");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_cleanup_cannot_follow_substituted_parents_or_delete_replacements() {
        use std::os::unix::fs::symlink;
        let outer = tempfile::tempdir().unwrap();
        let installation = outer.path().join("installation");
        let retained = outer.path().join("retained");
        let outside = outer.path().join("outside");
        fs::create_dir(&installation).unwrap();
        fs::create_dir(&outside).unwrap();
        let input = installation.join("protected-input");
        fs::write(&input, b"input").unwrap();
        let guard = BinaryProtection::open(&input).unwrap();
        let cleanup = BackupCleanup::prepare(&installation, &guard);
        let candidate = backup_path(&installation, "0.0.1-Old123");
        fs::write(&candidate, b"old backup").unwrap();
        let outside_candidate = backup_path(&outside, "0.0.1-Old123");
        fs::hard_link(&input, &outside_candidate).unwrap();
        fs::rename(&installation, &retained).unwrap();
        symlink(&outside, &installation).unwrap();
        cleanup.prune(std::slice::from_ref(&guard));
        assert_eq!(fs::read(&outside_candidate).unwrap(), b"input");
        assert_eq!(
            fs::read(backup_path(&retained, "0.0.1-Old123")).unwrap(),
            b"old backup"
        );
        let protected_alias = backup_path(&retained, "0.0.1-Alias1");
        fs::hard_link(retained.join("protected-input"), &protected_alias).unwrap();
        cleanup.prune(&[guard]);
        assert_eq!(fs::read(protected_alias).unwrap(), b"input");
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_stays_with_the_pinned_directory_after_parent_substitution() {
        use backup_cleanup::Boundary;
        for after_seal in [false, true] {
            for ancestor in [false, true] {
                let outer = tempfile::tempdir().unwrap();
                let parent = outer.path().join("parent");
                let installation = parent.join("installation");
                let outside_parent = outer.path().join("outside");
                let outside = outside_parent.join("installation");
                let retained = outer.path().join("retained");
                fs::create_dir_all(&installation).unwrap();
                fs::create_dir_all(&outside).unwrap();
                let executable = installation.join("app");
                fs::write(&executable, b"retained executable").unwrap();
                let guard = BinaryProtection::open(&executable).unwrap();
                let cleanup = BackupCleanup::prepare(&installation, &guard);
                assert!(cleanup.available());
                // Exercise directory confinement independently of any sharing
                // restriction imposed by the running-file protection handle.
                drop(guard);
                let name = "0.0.1-Old123";
                let candidate = backup_path(&installation, name);
                let outside_candidate = backup_path(&outside, name);
                fs::write(&candidate, b"old backup").unwrap();
                fs::write(&outside_candidate, b"outside copy").unwrap();
                let substituted = if ancestor { &parent } else { &installation };
                let redirect = if ancestor { &outside_parent } else { &outside };
                let (mut attempted, mut swapped) = (false, false);
                cleanup.prune_with(&[], |boundary, entry| {
                    let selected = if after_seal {
                        matches!(boundary, Boundary::Open)
                            && entry == candidate.file_name().unwrap()
                    } else {
                        matches!(boundary, Boundary::Seal)
                    };
                    if !selected {
                        return;
                    }
                    attempted = true;
                    match fs::rename(substituted, &retained) {
                        Ok(()) => {
                            let result = std::process::Command::new("cmd.exe")
                                .args(["/d", "/c", "mklink", "/J"])
                                .arg(substituted)
                                .arg(redirect)
                                .output()
                                .unwrap();
                            assert!(
                                result.status.success(),
                                "{}",
                                String::from_utf8_lossy(&result.stderr)
                            );
                            swapped = true;
                        }
                        Err(error) => {
                            assert!(
                                matches!(error.raw_os_error(), Some(5 | 32)),
                                "unexpected replacement failure: {error}"
                            );
                        }
                    }
                });
                assert!(
                    attempted,
                    "the attacker operation completed or was rejected at the synchronized boundary"
                );
                eprintln!(
                    "Windows directory substitution: ancestor={ancestor}, sealed={after_seal}, completed={swapped}"
                );
                assert_eq!(fs::read(&outside_candidate).unwrap(), b"outside copy");
                let actual = if swapped {
                    if ancestor {
                        retained.join("installation")
                    } else {
                        retained.clone()
                    }
                } else {
                    installation.clone()
                };
                assert!(!backup_path(&actual, name).exists());
                assert_eq!(
                    fs::read(actual.join("app")).unwrap(),
                    b"retained executable"
                );
                if swapped {
                    fs::remove_dir(substituted).unwrap();
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_rejects_protected_substitutions_and_prevents_postcheck_swaps() {
        use backup_cleanup::Boundary;
        for phase in 0..3 {
            for which in 0..6 {
                let (installation, prepared) = prepared();
                let installed = install(&prepared, &[]).unwrap();
                let input = installation.path().join("input");
                let extra = installation.path().join("extra");
                fs::write(&input, b"input").unwrap();
                fs::write(&extra, b"extra").unwrap();
                let extra_guard = BinaryProtection::open(&extra).unwrap();
                let renamed = installation.path().join("renamed-extra");
                fs::rename(&extra, &renamed).unwrap();
                let paths = [
                    &installed.backup,
                    &installed.executable,
                    &installed.backup,
                    &installed.notices,
                    &input,
                    &renamed,
                ];
                let expected: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
                let mut guards = vec![prepared.release.executable.clone()];
                for path in &paths[1..5] {
                    guards.push(BinaryProtection::open(path).unwrap());
                }
                guards.push(extra_guard);
                let cleanup = BackupCleanup::prepare(installation.path(), &guards[1]);
                assert!(cleanup.available());
                let candidate = backup_path(installation.path(), "0.0.1-Old123");
                let replacement = installation.path().join("replacement-alias");
                let retired = installation.path().join("retired-old-backup");
                fs::write(&candidate, b"old backup").unwrap();
                fs::hard_link(paths[which], &replacement).unwrap();
                let (mut attempted, mut replaced) = (false, false);
                cleanup.prune_with(&guards, |boundary, name| {
                    let selected = match (phase, boundary) {
                        (0, Boundary::Seal) => true,
                        (1, Boundary::Open) | (2, Boundary::Delete) => {
                            name == candidate.file_name().unwrap()
                        }
                        _ => false,
                    };
                    if !selected {
                        return;
                    }
                    attempted = true;
                    if phase == 2 {
                        assert!(
                            fs::rename(&candidate, &retired).is_err(),
                            "the validated DELETE handle must prevent substitution"
                        );
                        assert!(fs::rename(&replacement, &candidate).is_err());
                    } else {
                        match fs::rename(&candidate, &retired) {
                            Ok(()) => {
                                fs::rename(&replacement, &candidate).unwrap();
                                replaced = true;
                            }
                            Err(error) => {
                                assert_eq!(phase, 1, "pre-seal replacement must run: {error}");
                                assert!(
                                    matches!(error.raw_os_error(), Some(5 | 32)),
                                    "unexpected replacement failure: {error}"
                                );
                            }
                        }
                    }
                });
                assert!(attempted);
                if phase == 0 {
                    assert!(replaced);
                }
                for (path, expected) in paths.iter().zip(expected) {
                    assert_eq!(fs::read(path).unwrap(), expected);
                }
                if replaced {
                    assert_eq!(
                        fs::read(&candidate).unwrap(),
                        fs::read(paths[which]).unwrap()
                    );
                } else {
                    assert!(!candidate.exists());
                    assert_eq!(
                        fs::read(&replacement).unwrap(),
                        fs::read(paths[which]).unwrap()
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_membership_mismatches_disable_the_entire_cleanup_pass() {
        for which in 0..3 {
            let (installation, prepared) = prepared();
            let installed = install(&prepared, &[]).unwrap();
            let paths = [&installed.executable, &installed.backup, &installed.notices];
            let guards: Vec<_> = paths
                .iter()
                .map(|path| BinaryProtection::open(path).unwrap())
                .collect();
            let mut cleanup = BackupCleanup::prepare(installation.path(), &guards[0]);
            assert!(cleanup.available());
            let old = backup_path(installation.path(), "0.0.1-Old123");
            fs::write(&old, b"old backup").unwrap();
            let moved = installation.path().join("retained-output");
            fs::rename(paths[which], &moved).unwrap();
            fs::write(paths[which], b"replacement").unwrap();
            cleanup.check_guard(paths[which], &guards[which]);
            assert!(!cleanup.available());
            cleanup.prune(&guards);
            assert_eq!(fs::read(old).unwrap(), b"old backup");
            assert_eq!(fs::read(paths[which]).unwrap(), b"replacement");
            assert!(moved.is_file());
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_cleanup_keeps_reserved_names_and_obeys_the_removal_limit() {
        let (installation, prepared) = prepared();
        let protected = backup_path(installation.path(), "0.0.1-Input1");
        fs::write(&protected, b"input").unwrap();
        let guard = BinaryProtection::open(&protected).unwrap();
        fs::rename(&protected, installation.path().join("renamed-input")).unwrap();
        fs::write(&protected, b"reserved path replacement").unwrap();
        let copies: Vec<_> = (0..MAX_BACKUPS_REMOVED + 3)
            .map(|index| {
                let path = backup_path(installation.path(), &format!("0.0.1-{index:06}"));
                fs::write(&path, b"old backup").unwrap();
                path
            })
            .collect();
        install(&prepared, &[guard]).unwrap();
        assert_eq!(copies.iter().filter(|path| path.exists()).count(), 3);
        assert_eq!(fs::read(protected).unwrap(), b"reserved path replacement");
    }

    #[cfg(windows)]
    #[test]
    fn windows_staged_identity_mismatch_and_unavailable_capabilities_keep_backups() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::*;
        let (installation, prepared) = prepared();
        let old = backup_path(installation.path(), "0.0.1-Old123");
        fs::write(&old, b"old backup").unwrap();
        let mut cleanup = BackupCleanup::prepare(installation.path(), &prepared.release.executable);
        assert!(cleanup.available());
        let staged = NamedTempFile::new_in(installation.path()).unwrap();
        fs::rename(staged.path(), installation.path().join("retained-stage")).unwrap();
        fs::write(staged.path(), b"replacement stage").unwrap();
        cleanup.check_member(staged.path(), staged.as_file());
        assert!(!cleanup.available());
        cleanup.prune(std::slice::from_ref(&prepared.release.executable));
        assert_eq!(fs::read(&old).unwrap(), b"old backup");
        drop(staged);

        // An existing directory writer prevents the restrictive preparation
        // handle. This must disable cleanup without blocking publication.
        let writer = OpenOptions::new()
            .access_mode(FILE_ADD_FILE | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(installation.path())
            .unwrap();
        let unavailable = BackupCleanup::prepare(installation.path(), &prepared.release.executable);
        assert!(!unavailable.available());
        let installed = install(&prepared, &[]).unwrap();
        assert_eq!(fs::read(installed.executable).unwrap(), b"new executable");
        assert_eq!(fs::read(installed.backup).unwrap(), b"old executable");
        assert_eq!(fs::read(old).unwrap(), b"old backup");
        drop(writer);
    }

    #[cfg(windows)]
    #[test]
    fn windows_non_ascii_protected_names_conservatively_disable_cleanup() {
        let (installation, prepared) = prepared();
        let old = backup_path(installation.path(), "0.0.1-Old123");
        let input = installation.path().join("input-caf\u{e9}");
        fs::write(&old, b"old backup").unwrap();
        fs::write(&input, b"input").unwrap();
        let guard = BinaryProtection::open(&input).unwrap();
        let installed = install(&prepared, &[guard]).unwrap();
        assert_eq!(fs::read(old).unwrap(), b"old backup");
        assert_eq!(fs::read(input).unwrap(), b"input");
        assert_eq!(fs::read(installed.executable).unwrap(), b"new executable");
    }

    #[cfg(windows)]
    #[test]
    fn locked_backup_does_not_fail_install_and_unlocked_backup_is_pruned() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
        let (installation, prepared) = prepared();
        let old = backup_path(installation.path(), "0.0.1-Locked");
        fs::write(&old, b"locked recovery copy").unwrap();
        let locked = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&old)
            .unwrap();
        let installed = install(&prepared, &[]).unwrap();
        assert_eq!(fs::read(&old).unwrap(), b"locked recovery copy");
        assert_eq!(fs::read(installed.executable).unwrap(), b"new executable");
        drop(locked);
        let guards = [BinaryProtection::open(&installed.backup).unwrap()];
        BackupCleanup::prepare(installation.path(), &guards[0]).prune(&guards);
        assert!(!old.exists());
        assert_eq!(fs::read(installed.backup).unwrap(), b"old executable");
    }

    #[cfg(windows)]
    #[test]
    fn running_previous_executable_is_kept_without_failing_install() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;
        let (installation, prepared) = prepared();
        let running = backup_path(installation.path(), "0.0.1-Run123");
        fs::copy(std::env::current_exe().unwrap(), &running).unwrap();
        // Reuse the existing inert subprocess fixture; CreateProcess maps the
        // image before returning, so the executable is already in use here.
        let mut child = Command::new(&running)
            .args(["--ignored", "--exact", "windows::tests::job_child_waits"])
            .env("GRUST_WINDOWS_JOB_TEST", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        let result = install(&prepared, &[]);
        let still_running = child.try_wait().unwrap().is_none();
        let kept = running.is_file();
        let _ = child.kill();
        child.wait().unwrap();
        let installed = result.unwrap();
        assert!(still_running);
        assert!(kept);
        assert_eq!(fs::read(installed.executable).unwrap(), b"new executable");
        assert_eq!(fs::read(installed.backup).unwrap(), b"old executable");
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_skips_junctions_without_visiting_the_target() {
        let (installation, prepared) = prepared();
        let outside = tempfile::tempdir().unwrap();
        let target = backup_path(outside.path(), "0.0.1-abc123");
        fs::write(&target, b"junction target").unwrap();
        let junction = backup_path(installation.path(), "0.0.1-Junct1");
        let status = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        install(&prepared, &[]).unwrap();
        assert!(fs::symlink_metadata(&junction).is_ok());
        assert_eq!(fs::read(target).unwrap(), b"junction target");
        fs::remove_dir(junction).unwrap();
    }

    #[test]
    fn protected_input_aliases_and_changed_executables_block_installation() {
        let (installation, prepared) = prepared();
        let destination = prepared.release.executable.path();
        let alias = installation.path().join("input-alias");
        fs::hard_link(destination, &alias).unwrap();
        let protection = BinaryProtection::open(&alias).unwrap();
        assert!(
            install(&prepared, &[protection])
                .unwrap_err()
                .contains("input binary")
        );
        assert_eq!(fs::read(destination).unwrap(), b"old executable");
        let replacement = installation.path().join("replacement");
        fs::write(&replacement, b"replaced externally").unwrap();
        // Windows allows renaming the retained executable, but refuses replacing
        // it in place while BinaryProtection keeps its handle open.
        let previous = installation.path().join("previous");
        fs::rename(destination, &previous).unwrap();
        crate::session::atomic_replace(&replacement, destination).unwrap();
        assert!(install(&prepared, &[]).unwrap_err().contains("changed"));
        assert_eq!(fs::read(destination).unwrap(), b"replaced externally");
        assert_eq!(fs::read(&previous).unwrap(), b"old executable");
        assert_eq!(fs::read(&alias).unwrap(), b"old executable");
    }

    #[test]
    fn tampered_staging_is_reverified_before_installation() {
        let (installation, prepared) = prepared();
        let old = backup_path(installation.path(), "0.0.1-abc123");
        fs::write(&old, b"existing recovery copy").unwrap();
        fs::write(
            prepared
                .directory
                .path()
                .join(&prepared.release.binary.name),
            b"bad executable",
        )
        .unwrap();
        assert!(install(&prepared, &[]).is_err());
        assert_eq!(fs::read(old).unwrap(), b"existing recovery copy");
        assert_eq!(
            fs::read(prepared.release.executable.path()).unwrap(),
            b"old executable"
        );
    }

    #[test]
    fn staging_is_private_and_cannot_truncate_an_existing_artifact() {
        let directory = staging_directory().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(directory.path()).unwrap().permissions().mode() & 0o077,
                0
            );
        }
        let expected = artifact("artifact", b"verified bytes");
        let mut file = create_staged(&directory, &expected).unwrap();
        file.write_all(b"original contents").unwrap();
        assert!(create_staged(&directory, &expected).is_err());
        assert_eq!(
            fs::read(directory.path().join(&expected.name)).unwrap(),
            b"original contents"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[cfg(unix)]
    #[test]
    fn planted_staging_symlinks_are_rejected_on_creation_and_installation() {
        use std::os::unix::fs::symlink;
        let (installation, prepared) = prepared();
        let victim = installation.path().join("victim");
        fs::write(&victim, b"new executable").unwrap();
        let directory = staging_directory().unwrap();
        symlink(
            &victim,
            directory.path().join(&prepared.release.binary.name),
        )
        .unwrap();
        assert!(create_staged(&directory, &prepared.release.binary).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"new executable");
        let staged = prepared
            .directory
            .path()
            .join(&prepared.release.binary.name);
        fs::remove_file(&staged).unwrap();
        symlink(&victim, &staged).unwrap();
        assert!(
            install(&prepared, &[])
                .unwrap_err()
                .contains("symbolic link")
        );
        assert_eq!(
            fs::read(prepared.release.executable.path()).unwrap(),
            b"old executable"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"new executable");
    }

    #[cfg(windows)]
    #[test]
    fn windows_rollback_reports_restoration_and_preserves_an_existing_destination() {
        let directory = tempfile::tempdir().unwrap();
        let backup = directory.path().join("previous.exe");
        let destination = directory.path().join("app.exe");
        fs::write(&backup, b"old executable").unwrap();
        let message = rollback_publication("test failure", &backup, &destination);
        assert!(message.contains("was restored"));
        assert!(message.contains(&destination.display().to_string()));
        assert!(!backup.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"old executable");
        fs::write(&backup, b"recovery executable").unwrap();
        let message = rollback_publication("test failure", &backup, &destination);
        assert!(message.contains("also failed"));
        assert!(message.contains(&backup.display().to_string()));
        assert_eq!(fs::read(&destination).unwrap(), b"old executable");
        assert_eq!(fs::read(&backup).unwrap(), b"recovery executable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_python_openssl_signer_interoperates_with_the_rust_verifier() {
        let directory = staging_directory().unwrap();
        let script = r#"
import io, pathlib, runpy, sys, tarfile, zipfile
signer = runpy.run_path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
private, public = root / 'test-key.pem', root / 'test-public.txt'
signer['initialize'](private, public)
for platform in ('linux-x64', 'windows-x64'):
    name = 'ghidra-rust-0.0.9-' + platform
    (root / (name + ('.exe' if platform == 'windows-x64' else ''))).write_bytes(b'test executable')
    if platform == 'linux-x64':
        with tarfile.open(root / (name + '.tar.gz'), 'w:gz') as archive:
            member = tarfile.TarInfo(name + '/LICENSE')
            member.size = 12
            archive.addfile(member, io.BytesIO(b'test license'))
    else:
        with zipfile.ZipFile(root / (name + '.zip'), 'w') as archive:
            archive.writestr(name + '/LICENSE', b'test license')
signer['sign'](root, '0.0.9', private, public)
"#;
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(script)
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/sign-updates.py"
            ))
            .arg(directory.path())
            .output()
            .expect("Python 3 and OpenSSL are required for update-signing tests");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let manifest = fs::read(directory.path().join("update.json")).unwrap();
        let signature = fs::read(directory.path().join("update.json.sig")).unwrap();
        let public = fs::read_to_string(directory.path().join("test-public.txt")).unwrap();
        assert!(verify_manifest(&manifest, &signature, &public, "0.0.9", "linux-x64").is_ok());
        assert!(verify_manifest(&manifest, &signature, &public, "0.0.9", "windows-x64").is_ok());
        assert!(verify_manifest(&manifest, &signature, PUBLIC_KEY, "0.0.9", "linux-x64").is_err());
    }
}
