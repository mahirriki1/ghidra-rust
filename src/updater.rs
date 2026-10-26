//! Explicit, bounded update jobs. Only a manifest authenticated by the embedded
//! Ed25519 key can authorize bytes, versions, or target names for installation.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
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

const REPOSITORY: &str = "mahirriki1/ghidra-rust";
const RELEASES_URL: &str = "https://api.github.com/repos/mahirriki1/ghidra-rust/releases";
const DOWNLOAD_ROOT: &str = "https://github.com/mahirriki1/ghidra-rust/releases/download/";
const PUBLIC_KEY: &str = include_str!("../data/update-public-key.txt");
const MAX_RELEASE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MANIFEST: u64 = 16 * 1024;
const MAX_BINARY: u64 = 512 * 1024 * 1024;
const MAX_NOTICES: u64 = 16 * 1024 * 1024;
const MAX_NOTES: usize = 32 * 1024;

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

fn install(prepared: &Prepared, protections: &[BinaryProtection]) -> Result<Installed, String> {
    let release = &prepared.release;
    let destination = check_destination(release, protections)?;
    let parent = destination
        .parent()
        .ok_or("Executable has no installation directory")?;
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
    let (backup_file, backup_path) = backup.keep().map_err(|error| error.to_string())?;
    drop(backup_file);
    let (notices_file, notices_path) = notices.keep().map_err(|error| error.to_string())?;
    drop(notices_file);
    #[cfg(windows)]
    {
        // Windows permits renaming a running executable but not unlinking it.
        // Retain the previous executable permanently as the recovery copy.
        crate::session::atomic_replace(&destination, &backup_path)
            .map_err(|error| format!("Cannot retain the previous executable: {error}"))?;
        let result = (|| {
            for protection in protections {
                safe_destination(&destination, protection)?;
            }
            staged
                .persist_noclobber(&destination)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(())
        })();
        if let Err(error) = result {
            return Err(rollback_publication(&error, &backup_path, &destination));
        }
    }
    #[cfg(not(windows))]
    {
        check_destination(release, protections)?;
        staged.persist(&destination).map_err(|error| {
            format!(
                "Cannot publish update: {error}. Previous executable: {}",
                backup_path.display()
            )
        })?;
    }
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
        let (_installation, prepared) = prepared();
        fs::write(
            prepared
                .directory
                .path()
                .join(&prepared.release.binary.name),
            b"bad executable",
        )
        .unwrap();
        assert!(install(&prepared, &[]).is_err());
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
