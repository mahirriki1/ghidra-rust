//! Private pipe handoff. The helper pins the installed executable and every
//! protected input before the desktop releases its handles or exits.
use super::*;
mod failure_cleanup;
use crate::model::FileIdentity;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::process::{Child, ChildStdin, Command, Stdio};
use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

const MAX_HANDOFF: u64 = 256 * 1024;
const WAIT_MS: u32 = 30_000;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Guard {
    path: PathBuf,
    identity: FileIdentity,
}

impl Guard {
    /// Retain only the installed file's identity. Even this handle must close
    /// before replacing a previously loaded image; input handles are separate.
    fn open_installed(&self) -> Result<BinaryProtection, String> {
        let file =
            crate::windows::open_for_identity(&self.path).map_err(|error| error.to_string())?;
        let guard = BinaryProtection::from_open_file(&self.path, file)?;
        if guard.file_identity() != self.identity {
            return Err("Installed executable changed before the helper retained it".into());
        }
        Ok(guard)
    }

    fn new(guard: &BinaryProtection) -> Self {
        Self {
            path: guard.path().into(),
            identity: guard.file_identity(),
        }
    }

    fn open(&self) -> Result<BinaryProtection, String> {
        let guard = BinaryProtection::open(&self.path)?;
        if guard.file_identity() != self.identity {
            return Err("An update input changed before the helper could retain it".into());
        }
        Ok(guard)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    parent: u32,
    version: String,
    executable: Guard,
    protections: Vec<Guard>,
    binary: Artifact,
    notices: Artifact,
}

#[derive(Debug)]
pub(super) struct Handoff {
    child: Child,
    pipe: Option<ChildStdin>,
    directory: Option<TempDir>,
}

impl Drop for Handoff {
    fn drop(&mut self) {
        if self.directory.is_some() {
            // No commit: never let a cancelled/failed handoff install anything.
            self.pipe.take();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

impl Handoff {
    pub(super) fn commit(mut self, project: Option<PathBuf>) -> Result<(), String> {
        send(
            self.pipe.as_mut().ok_or("Update helper disconnected")?,
            &project,
        )?;
        // The helper now owns this private directory. It waits for this process
        // to terminate, publishes, then passes cleanup to the relaunched app.
        let _ = self
            .directory
            .take()
            .ok_or("Missing update staging")?
            .keep();
        self.pipe.take();
        Ok(())
    }
}

fn send(writer: &mut impl Write, value: &impl Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() as u64 >= MAX_HANDOFF {
        return Err("Update handoff exceeds its limit".into());
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .and_then(|()| writer.flush())
        .map_err(|error| error.to_string())
}

fn receive<T: serde::de::DeserializeOwned>(reader: &mut impl BufRead) -> Result<T, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_HANDOFF + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_HANDOFF || bytes.last() != Some(&b'\n') {
        return Err("Invalid update helper message".into());
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("Invalid update handoff: {error}"))
}

fn parent_process(pid: u32) -> Result<OwnedHandle, String> {
    // SAFETY: OpenProcess returns a new owned handle with only wait access;
    // null is checked before taking ownership. The handle pins the process
    // object, so PID reuse cannot change which process we wait for.
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(format!(
            "Cannot retain updater parent: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn wait_for_exit(process: &OwnedHandle) -> Result<(), String> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: process owns a live SYNCHRONIZE handle for this bounded wait.
    if unsafe { WaitForSingleObject(process.as_raw_handle(), WAIT_MS) } != WAIT_OBJECT_0 {
        return Err(
            "Timed out waiting for the app to exit; the executable was not replaced".into(),
        );
    }
    Ok(())
}

pub(super) fn prepare(
    prepared: &Prepared,
    protections: &[BinaryProtection],
) -> Result<Installed, String> {
    let destination = check_destination(&prepared.release, protections)?;
    let directory = staging_directory()?;
    // Run a copy of the current trusted updater, never downloaded code, before
    // installation. All copies are bounded and reverified by the helper.
    let helper = directory.path().join("helper.exe");
    let mut source = File::open(&destination).map_err(|error| error.to_string())?;
    if FileIdentity::from_file(&source) != Some(prepared.release.executable.file_identity()) {
        return Err("Installed executable changed before helper staging".into());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&helper)
        .map_err(|error| error.to_string())?;
    if std::io::copy(
        &mut Read::by_ref(&mut source).take(MAX_BINARY + 1),
        &mut output,
    )
    .map_err(|error| error.to_string())?
        > MAX_BINARY
    {
        return Err("Updater helper exceeds its size limit".into());
    }
    output.sync_all().map_err(|error| error.to_string())?;
    drop(output);
    for artifact in [&prepared.release.binary, &prepared.release.notices] {
        let mut output = create_staged(&directory, artifact)?;
        copy_verified(
            crate::session::open_regular_file(
                &prepared.directory.path().join(&artifact.name),
                artifact.size,
            )?,
            &mut output,
            artifact,
            &AtomicBool::new(false),
            &AtomicU64::new(0),
        )?;
        output.sync_all().map_err(|error| error.to_string())?;
    }
    if read_notices(directory.path(), &prepared.release.notices)? != prepared.notices_text {
        return Err("Update notices changed after acceptance".into());
    }
    let mut child = Command::new(&helper)
        .arg("--update-helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Cannot start update helper: {error}"))?;
    let pipe = child.stdin.take().ok_or("Missing helper input")?;
    let stdout = child.stdout.take().ok_or("Missing helper output")?;
    let mut handoff = Handoff {
        child,
        pipe: Some(pipe),
        directory: Some(directory),
    };
    send(
        handoff.pipe.as_mut().unwrap(),
        &Plan {
            parent: std::process::id(),
            version: prepared.release.version.clone(),
            executable: Guard::new(&prepared.release.executable),
            protections: protections.iter().map(Guard::new).collect(),
            binary: prepared.release.binary.clone(),
            notices: prepared.release.notices.clone(),
        },
    )?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let response: Result<String, String> = receive(&mut BufReader::new(stdout));
        let _ = sender.send(response);
    });
    let response = receiver
        .recv_timeout(Duration::from_millis(WAIT_MS.into()))
        .map_err(|_| "Update helper did not become ready".to_string())??;
    if response != "ready" {
        return Err(response);
    }
    Ok(Installed {
        executable: destination,
        helper: Some(handoff),
    })
}

/// Internal entry point; only pipe messages authorize a handoff. Until commit
/// and parent exit, the helper does not change the installed executable.
pub fn run_helper() -> Result<(), String> {
    let mut input = BufReader::new(std::io::stdin());
    let plan: Plan = receive(&mut input)?;
    if plain_version(&plan.version).is_none() {
        return Err("Invalid helper release version".into());
    }
    if plan.protections.len() > 1 {
        return Err("Too many protected update inputs".into());
    }
    let process = parent_process(plan.parent)?;
    let executable = plan.executable.open_installed()?;
    let protections = plan
        .protections
        .iter()
        .map(Guard::open)
        .collect::<Result<Vec<_>, _>>()?;
    // current_exe may omit Windows' verbatim prefix whereas BinaryProtection
    // canonicalizes its paths. Use one canonical spelling for all artifact guards.
    let helper = fs::canonicalize(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let directory_path = helper.parent().ok_or("Missing helper directory")?;
    if helper.file_name() != Some(std::ffi::OsStr::new("helper.exe"))
        || !directory_path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with("ghidra-update-"))
    {
        return Err("The updater must run from its private helper directory".into());
    }
    let helper_guard = BinaryProtection::open(&helper)?;
    let pinned = crate::windows::PinnedUpdateDirectory::open(directory_path)
        .map_err(|error| error.to_string())?;
    // These are generated artifact basenames; reject any pipe-supplied path.
    validate_artifact(
        &plan.binary,
        &format!("ghidra-rust-{}-windows-x64.exe", plan.version),
        MAX_BINARY,
    )?;
    validate_artifact(
        &plan.notices,
        &format!("ghidra-rust-{}-update-notices.txt", plan.version),
        MAX_NOTICES,
    )?;
    // Borrow the path; never create a recursive-cleanup owner from IPC data.
    let directory = StagingDirectory {
        path: directory_path.into(),
        _owner: None,
    };
    let notices_text = read_notices(directory.path(), &plan.notices)?;
    let prepared = Prepared {
        release: Available {
            version: plan.version,
            notes: String::new(),
            release_url: String::new(),
            executable,
            binary: plan.binary,
            notices: plan.notices,
        },
        directory,
        notice_lines: notice_lines(&notices_text)?,
        notices_text,
    };
    check_destination(&prepared.release, &protections)?;
    // Retain the exact private artifacts throughout publication and cleanup.
    let mut artifacts = vec![Guard::new(&helper_guard)];
    let mut retained_artifacts = Vec::new();
    for artifact in [&prepared.release.binary, &prepared.release.notices] {
        let file = pinned
            .identity(std::ffi::OsStr::new(&artifact.name))
            .map_err(|error| error.to_string())?;
        let guard = BinaryProtection::from_open_file(
            &prepared.directory.path().join(&artifact.name),
            file,
        )?;
        artifacts.push(Guard::new(&guard));
        retained_artifacts.push(guard);
    }
    let version = prepared.release.version.clone();
    let destination = prepared.release.executable.path().to_owned();
    let staging_path = prepared.directory.path().to_owned();
    let outcome = (|| -> Result<(), String> {
        send(&mut std::io::stdout(), &"ready")?;
        let project: Option<PathBuf> = receive(&mut input)?;
        wait_for_exit(&process)?;
        // No mapped image remains at the destination. Atomic replacement can now
        // retain its original name without a recovery executable or rename gap.
        let installed = install_after_exit(prepared, &protections)
            .map_err(|error| format!("{error}. Launch {} manually.", destination.display()))?;
        let cleanup = Cleanup {
            version,
            parent: std::process::id(),
            artifacts: artifacts.clone(),
            protected: protections.iter().map(Guard::new).collect(),
            project,
        };
        let mut child = Command::new(&installed.executable)
            .arg("--update-cleanup")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|error| {
                format!(
                    "Update installed. Launch {} manually: {error}",
                    installed.executable.display()
                )
            })?;
        send(
            child.stdin.as_mut().ok_or("Missing cleanup pipe")?,
            &cleanup,
        )?;
        let stdout = child.stdout.take().ok_or("Missing cleanup response")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = sender.send(receive::<String>(&mut BufReader::new(stdout)));
        });
        let response = receiver
            .recv_timeout(Duration::from_millis(WAIT_MS.into()))
            .map_err(|_| {
                format!(
                    "Update installed. Launch {} manually; cleanup did not respond.",
                    installed.executable.display()
                )
            })??;
        if response != "ready" {
            return Err("Cleanup handoff failed".into());
        }

        Ok(())
    })();
    if let Err(error) = outcome {
        let cleanup = failure_cleanup::schedule(&pinned, &artifacts, &protections);
        return Err(match cleanup {
            Ok(()) => {
                format!("{error}. Temporary updater cleanup is scheduled after this helper exits.")
            }
            Err(cleanup) => format!(
                "{error}. Temporary updater cleanup could not be scheduled: {cleanup}. Files may remain at {}",
                staging_path.display()
            ),
        });
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    version: String,
    parent: u32,
    artifacts: Vec<Guard>,
    protected: Vec<Guard>,
    project: Option<PathBuf>,
}

pub fn run_cleanup() -> Result<Option<PathBuf>, String> {
    let cleanup: Cleanup = receive(&mut BufReader::new(std::io::stdin()))?;
    // Once publication succeeded, cleanup is optional. Acknowledge even when
    // capabilities cannot be prepared, so the helper can exit and the desktop
    // can open normally. No cleanup fallback uses path-based file deletion.
    let project = cleanup.project.clone();
    if let Err(error) = clean(&cleanup) {
        let _ = send(&mut std::io::stdout(), &"ready");
        eprintln!("Update cleanup skipped: {error}");
    }
    Ok(project)
}

fn clean(cleanup: &Cleanup) -> Result<(), String> {
    let process = parent_process(cleanup.parent)?;
    if plain_version(&cleanup.version).is_none()
        || cleanup.artifacts.len() != 3
        || cleanup.protected.len() > 1
    {
        return Err("Invalid cleanup artifact count".into());
    }
    let helper = &cleanup.artifacts[0];
    let parent = helper.path.parent().ok_or("Missing helper directory")?;
    if helper.path.file_name() != Some(std::ffi::OsStr::new("helper.exe")) {
        return Err("Unexpected updater helper name".into());
    }
    let directory =
        crate::windows::PinnedUpdateDirectory::open(parent).map_err(|error| error.to_string())?;
    let mut retained = Vec::new();
    let expected = [
        "helper.exe".to_string(),
        format!("ghidra-rust-{}-windows-x64.exe", cleanup.version),
        format!("ghidra-rust-{}-update-notices.txt", cleanup.version),
    ];
    for (artifact, expected) in cleanup.artifacts.iter().zip(expected) {
        if artifact.path.file_name() != Some(std::ffi::OsStr::new(&expected)) {
            return Err("Unexpected cleanup artifact name".into());
        }
        if artifact.path.parent() != Some(parent) {
            return Err("Cleanup artifact escaped staging".into());
        }
        let name = artifact.path.file_name().ok_or("Missing cleanup name")?;
        let file = directory
            .identity(name)
            .map_err(|error| error.to_string())?;
        if FileIdentity::from_file(&file) != Some(artifact.identity)
            || cleanup
                .protected
                .iter()
                .any(|guard| guard.identity == artifact.identity)
        {
            return Err("Updater cleanup identity changed or is protected".into());
        }
        retained.push(file);
    }
    send(&mut std::io::stdout(), &"ready")?;
    // Cleanup failures must not prevent opening the successfully updated app.
    if wait_for_exit(&process).is_ok()
        && let Ok(sealed) = directory.sealed()
    {
        delete_artifacts(&sealed, &cleanup.artifacts);
        // Close retained artifact handles before testing directory emptiness.
        drop(retained);
        // Keep the verified capability through deletion: an empty directory
        // or junction substituted at the original pathname is never touched.
        let _ = sealed.remove_empty();
    }
    Ok(())
}

fn delete_artifacts(directory: &crate::windows::CleanupDirectory, artifacts: &[Guard]) {
    for artifact in artifacts {
        if let Some(name) = artifact.path.file_name()
            && let Ok(file) = directory.deletion(name)
            && FileIdentity::from_file(&file) == Some(artifact.identity)
        {
            let _ = crate::windows::delete_open_file(&file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_messages_preserve_paths_and_reject_truncation_and_oversize() {
        let project = Some(PathBuf::from("C:/分析/project.grproj"));
        let mut bytes = Vec::new();
        send(&mut bytes, &project).unwrap();
        assert_eq!(
            receive::<Option<PathBuf>>(&mut bytes.as_slice()).unwrap(),
            project
        );
        bytes.pop();
        assert!(receive::<Option<PathBuf>>(&mut bytes.as_slice()).is_err());
        assert!(send(&mut Vec::new(), &"x".repeat(MAX_HANDOFF as usize)).is_err());
        let bytes = vec![b'x'; MAX_HANDOFF as usize + 1];
        assert!(receive::<String>(&mut bytes.as_slice()).is_err());
    }

    #[test]
    fn helper_refuses_changed_protected_input() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        fs::write(&input, b"protected").unwrap();
        let retained = BinaryProtection::open(&input).unwrap();
        let guard = Guard::new(&retained);
        fs::rename(&input, directory.path().join("moved")).unwrap();
        fs::write(&input, b"replacement").unwrap();
        assert!(guard.open().is_err());
    }

    #[test]
    fn cleanup_uses_pinned_directory_and_skips_replaced_artifacts() {
        let outer = tempfile::tempdir().unwrap();
        let root = outer.path().join("staging");
        let moved = outer.path().join("moved");
        fs::create_dir(&root).unwrap();
        let helper = root.join("helper.exe");
        let notices = root.join("notices.txt");
        fs::write(&helper, b"helper").unwrap();
        fs::write(&notices, b"notices").unwrap();
        let helper_guard = BinaryProtection::open(&helper).unwrap();
        let notice_guard = BinaryProtection::open(&notices).unwrap();
        let artifacts = [Guard::new(&helper_guard), Guard::new(&notice_guard)];
        let pinned = crate::windows::PinnedUpdateDirectory::open(&root).unwrap();
        // Exercise the directory capability separately from the read handles
        // which can themselves prohibit directory renames on Windows. Linked
        // fixture files retain these IDs until the test moves/deletes them.
        drop(helper_guard);
        drop(notice_guard);
        let swapped = match fs::rename(&root, &moved) {
            Ok(()) => true,
            Err(error) => {
                assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
                false // OS-enforced sharing can also reject this attack.
            }
        };
        if swapped {
            fs::create_dir(&root).unwrap();
            fs::write(&helper, b"outside replacement").unwrap();
        }
        let actual = if swapped { &moved } else { &root };
        fs::rename(actual.join("notices.txt"), actual.join("retired")).unwrap();
        fs::write(actual.join("notices.txt"), b"protected replacement").unwrap();
        delete_artifacts(&pinned.sealed().unwrap(), &artifacts);
        assert!(!actual.join("helper.exe").exists());
        if swapped {
            assert_eq!(fs::read(helper).unwrap(), b"outside replacement");
        }
        assert_eq!(
            fs::read(actual.join("notices.txt")).unwrap(),
            b"protected replacement"
        );
        assert_eq!(fs::read(actual.join("retired")).unwrap(), b"notices");
    }
}
