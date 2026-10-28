//! Failure-only janitor using the OS PowerShell. Its pipe contains only handles
//! duplicated into that process, never a filename or command assembled from data.
use super::*;
use std::os::windows::{ffi::OsStringExt, io::AsRawHandle, process::CommandExt};
use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, GetCurrentProcess};

const SCRIPT: &str = include_str!("failure_cleanup.ps1");

struct Broker {
    child: Child,
    armed: bool,
}

impl Drop for Broker {
    fn drop(&mut self) {
        if !self.armed {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn duplicate(child: &Child, source: HANDLE, access: Option<u32>) -> Result<usize, String> {
    let mut target = std::ptr::null_mut();
    // SAFETY: child owns a live process handle with DUP_HANDLE access. source
    // is either a live owned file handle or the current-process pseudo handle.
    // The new handle belongs exclusively to child; killing an unarmed broker
    // closes every handle already duplicated into it, including on partial failure.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            child.as_raw_handle(),
            &mut target,
            access.unwrap_or(0),
            0,
            if access.is_some() {
                0
            } else {
                DUPLICATE_SAME_ACCESS
            },
        )
    } == 0
    {
        return Err(format!(
            "Cannot transfer cleanup handle: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(target as usize)
}

pub(super) fn schedule(
    directory: &crate::windows::PinnedUpdateDirectory,
    artifacts: &[Guard],
    protections: &[BinaryProtection],
) -> Result<(), String> {
    let sealed = directory.sealed().map_err(|error| error.to_string())?;
    let mut files = Vec::new();
    for artifact in artifacts {
        let Some(name) = artifact.path.file_name() else {
            continue;
        };
        let Ok(file) = sealed.deletion(name) else {
            continue;
        };
        if FileIdentity::from_file(&file) == Some(artifact.identity)
            && !protections
                .iter()
                .any(|guard| guard.file_identity() == artifact.identity)
        {
            files.push(file);
        }
    }
    if files.is_empty() {
        return Err("No owned cleanup artifacts could be retained".into());
    }
    // This deletes only an empty directory through its retained object. Unknown
    // entries and protected/replaced artifacts prevent directory deletion.
    if let Ok(directory) = sealed.empty_deletion() {
        files.push(directory);
    }
    let mut system = [0u16; 512];
    // SAFETY: system is a live writable UTF-16 buffer of the supplied size.
    let count = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    if count == 0 || count >= system.len() {
        return Err("Cannot locate the Windows cleanup runtime".into());
    }
    let powershell = PathBuf::from(std::ffi::OsString::from_wide(&system[..count]))
        .join("WindowsPowerShell/v1.0/powershell.exe");
    let encoded = SCRIPT
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let encoded = base64::engine::general_purpose::STANDARD.encode(encoded);
    let child = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("Cannot start failure cleanup: {error}"))?;
    let mut broker = Broker {
        child,
        armed: false,
    };
    // SAFETY: GetCurrentProcess returns a valid pseudo handle; duplicate turns
    // it into a real handle with wait-only access inside this broker process.
    let process = duplicate(
        &broker.child,
        unsafe { GetCurrentProcess() },
        Some(PROCESS_SYNCHRONIZE),
    )?;
    let handles = files
        .iter()
        .map(|file| duplicate(&broker.child, file.as_raw_handle(), None))
        .collect::<Result<Vec<_>, _>>()?;
    #[derive(Serialize)]
    struct Handles {
        wait: usize,
        files: Vec<usize>,
    }
    send(
        broker.child.stdin.as_mut().ok_or("Missing janitor input")?,
        &Handles {
            wait: process,
            files: handles,
        },
    )?;
    let stdout = broker.child.stdout.take().ok_or("Missing janitor output")?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(receive::<String>(&mut BufReader::new(stdout)));
    });
    let response = receiver
        .recv_timeout(Duration::from_millis(WAIT_MS.into()))
        .map_err(|_| "Failure cleanup did not become ready".to_string())??;
    if response != "ready" {
        return Err("Failure cleanup refused the handoff".into());
    }
    broker.armed = true;
    Ok(())
}
