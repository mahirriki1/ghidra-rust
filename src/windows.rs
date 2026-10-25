//! Windows file identity and worker resource containment.
//!
//! Job objects limit resource use and lifetime. They do not isolate the worker
//! from the user's files, registry, credentials, or network.

use crate::model::FileIdentity;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{
    ffi::OsStrExt,
    fs::OpenOptionsExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::Path;
use std::process::Child;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};
use windows_sys::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
};

/// Open the final path component itself, then reject reparse points using its
/// handle. This covers a substitution between the path check and CreateFile.
pub fn configure_read(options: &mut OpenOptions) {
    options
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
}

/// Reject namespaces that can invoke devices, alternate data streams, or remote
/// filesystems before any filesystem lookup. Canonical results must be checked
/// again because a local-looking path can traverse a junction to a UNC share.
pub fn validate_local_path(path: &Path) -> io::Result<()> {
    use std::path::{Component, Prefix};
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
                _ => {
                    return Err(io::Error::other(
                        "Only local Windows drive paths are supported",
                    ));
                }
            },
            Component::Normal(name) => {
                if name
                    .encode_wide()
                    .any(|character| character == 0 || character == u16::from(b':'))
                {
                    return Err(io::Error::other(
                        "Device names and alternate data streams are unsupported",
                    ));
                }
                let text = name.to_string_lossy();
                let base = text
                    .trim_end_matches([' ', '.'])
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches([' ', '.']);
                let upper = base.to_ascii_uppercase();
                let reserved = matches!(
                    upper.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                ) || ["COM", "LPT"].iter().any(|prefix| {
                    upper.strip_prefix(prefix).is_some_and(|number| {
                        matches!(
                            number,
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )
                    })
                });
                if reserved {
                    return Err(io::Error::other("DOS device names are unsupported"));
                }
            }
            _ => {}
        }
    }
    // A bare drive prefix is relative to Windows' per-drive current directory.
    // Reject it so all drive-qualified names have an explicit root.
    if !path.has_root()
        && matches!(
            path.components().next(),
            Some(std::path::Component::Prefix(_))
        )
    {
        return Err(io::Error::other(
            "Drive-relative Windows paths are unsupported",
        ));
    }
    // GetFullPathName (used by absolute) expands local relative paths without
    // resolving filesystem links. Check mapped drives before canonicalize can
    // contact their remote filesystem.
    let absolute = std::path::absolute(path)?;
    let drive = match absolute.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
            _ => {
                return Err(io::Error::other(
                    "Only local Windows drive paths are supported",
                ));
            }
        },
        _ => return Err(io::Error::other("Cannot determine local Windows drive")),
    };
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: root is a live, NUL-terminated UTF-16 drive-root string.
    match unsafe { GetDriveTypeW(root.as_ptr()) } {
        DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_RAMDISK | DRIVE_CDROM => Ok(()),
        DRIVE_REMOTE => Err(io::Error::other(
            "Network-mapped Windows drives are unsupported",
        )),
        _ => Err(io::Error::other(
            "Windows drive is unavailable or has an unknown type",
        )),
    }
}

pub fn verify_regular_file(file: &File) -> io::Result<()> {
    let handle = file.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the live File owns handle; info is writable for the documented size.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(io::Error::other("Input must be a disk file"));
    }
    // SAFETY: same live handle and initialized output storage as above.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(io::Error::other(
            "Input must be a regular file without a reparse point",
        ));
    }
    Ok(())
}

pub fn file_identity(file: &File) -> io::Result<FileIdentity> {
    verify_regular_file(file)?;
    let mut info = FILE_ID_INFO::default();
    // SAFETY: the live File owns the handle; info is valid FILE_ID_INFO storage.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let id = info.FileId.Identifier;
    if info.VolumeSerialNumber == 0 || id.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other(
            "Windows filesystem returned an unsupported zero file identity",
        ));
    }
    Ok(FileIdentity {
        device: info.VolumeSerialNumber,
        inode: u64::from_le_bytes(id[..8].try_into().expect("Eight-byte file ID half")),
        inode_high: u64::from_le_bytes(id[8..].try_into().expect("Eight-byte file ID half")),
    })
}

/// Same-volume replacement supports existing destinations on Windows, unlike
/// std::fs::rename. Callers already synced and closed the temporary file.
pub fn atomic_replace(temporary: &Path, destination: &Path) -> io::Result<()> {
    move_file(
        temporary,
        destination,
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    )
}

/// Roll back an update without overwriting a file created after publication failed.
pub fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    move_file(source, destination, MOVEFILE_WRITE_THROUGH)
}

fn move_file(temporary: &Path, destination: &Path, flags: u32) -> io::Result<()> {
    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut text: Vec<u16> = path.as_os_str().encode_wide().collect();
        if text.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Path contains NUL",
            ));
        }
        text.push(0);
        Ok(text)
    }
    let temporary = wide(temporary)?;
    let destination = wide(destination)?;
    // SAFETY: both buffers are live NUL-terminated UTF-16 strings. COPY_ALLOWED
    // is deliberately absent: replacement must remain a same-volume rename.
    if unsafe { MoveFileExW(temporary.as_ptr(), destination.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

struct Handle(OwnedHandle);

impl Handle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: callers pass uniquely owned kernel handles returned by
            // successful CreateJobObjectW, CreateToolhelp32Snapshot, or OpenThread
            // calls. Null and INVALID_HANDLE_VALUE were rejected above. OwnedHandle
            // closes exactly once and safely transfers ownership between threads.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
        }
    }

    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

/// Retained until worker shutdown. Closing the last non-inherited job handle terminates
/// its worker even if the GUI exits without running Rust destructors.
pub struct WorkerJob {
    _handle: Handle,
}

impl WorkerJob {
    /// Child must have been created with CREATE_SUSPENDED. It executes no Rust
    /// worker code until resource limits and membership have been established.
    pub fn assign_and_resume(child: &Child) -> io::Result<Self> {
        // SAFETY: null attributes/name create a private, non-inheritable job.
        let job = Handle::new(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })?;
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        limits.ProcessMemoryLimit = 2 * 1024 * 1024 * 1024;
        // SAFETY: initialized limits structure and a live, owned job handle.
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: job and child handles remain live throughout assignment.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        resume_initial_thread(child.id())?;
        Ok(Self { _handle: job })
    }
}

fn resume_initial_thread(process_id: u32) -> io::Result<()> {
    // std::process::Child does not expose the primary thread handle. A newly
    // suspended process has its initial thread, which can be found by PID while
    // its process handle prevents PID reuse.
    // SAFETY: ToolHelp snapshot returns an owned handle and retains no pointers.
    let snapshot = Handle::new(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) })?;
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    // SAFETY: entry has the documented size and remains writable for enumeration.
    let mut exists = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) } != 0;
    let mut initial_thread = None;
    while exists {
        if entry.th32OwnerProcessID == process_id
            && initial_thread.replace(entry.th32ThreadID).is_some()
        {
            return Err(io::Error::other(
                "Suspended worker has more than one thread",
            ));
        }
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        // SAFETY: same initialized writable entry and live snapshot as above.
        exists = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) } != 0;
    }
    // SAFETY: read immediately after the failed enumeration call. Any failure
    // other than end-of-list could hide another thread, so fail closed.
    let enumeration_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    if enumeration_error != windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES {
        return Err(io::Error::from_raw_os_error(enumeration_error as i32));
    }
    let thread_id = initial_thread
        .ok_or_else(|| io::Error::other("Cannot find suspended worker's initial thread"))?;
    // SAFETY: the process is still suspended and live; this owned handle has
    // only permission to resume the one thread found for that process.
    let thread = Handle::new(unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) })?;
    // SAFETY: thread is a live handle with THREAD_SUSPEND_RESUME access.
    let suspended = unsafe { ResumeThread(thread.as_raw_handle()) };
    if suspended != 1 {
        return Err(if suspended == u32::MAX {
            io::Error::last_os_error()
        } else {
            io::Error::other(format!(
                "Worker initial thread was not suspended exactly once (ResumeThread returned {suspended})"
            ))
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_windows_names_are_rejected_before_filesystem_access() {
        for name in [
            r"\\server\share\binary.exe",
            r"\\?\UNC\server\share\binary.exe",
            r"\\.\PhysicalDrive0",
            r"\\?\GLOBALROOT\Device\HarddiskVolume1\binary.exe",
            r"C:\binary.exe:stream",
            r"C:\NUL",
            r"C:\con.txt",
            r"C:\CON .txt",
            r"C:\COM1.exe",
            r"C:\lpt²",
            r"C:relative.exe",
        ] {
            assert!(
                validate_local_path(Path::new(name)).is_err(),
                "Accepted {name}"
            );
        }
        for name in [
            r"C:\binaries\sample.exe",
            r"\\?\C:\binaries\sample.exe",
            r"relative\sample.exe",
        ] {
            validate_local_path(Path::new(name)).unwrap();
        }
    }

    #[test]
    fn file_identity_tracks_hard_links_and_atomic_replacement() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        let alias = directory.path().join("alias");
        let replacement = directory.path().join("replacement");
        std::fs::write(&original, b"first").unwrap();
        std::fs::hard_link(&original, &alias).unwrap();
        let mut options = OpenOptions::new();
        options.read(true);
        configure_read(&mut options);
        let pinned = options.open(&original).unwrap();
        let identity = file_identity(&pinned).unwrap();
        assert_eq!(
            identity,
            file_identity(&File::open(&alias).unwrap()).unwrap()
        );
        // Delete sharing permits moving the guarded input. MoveFileExW need
        // not replace an open destination; exercise replacement of an ordinary
        // closed output while the old input remains pinned under another name.
        std::fs::rename(&original, directory.path().join("retained")).unwrap();
        std::fs::write(&original, b"old destination").unwrap();
        std::fs::write(&replacement, b"second").unwrap();
        atomic_replace(&replacement, &original).unwrap();
        assert_eq!(identity, file_identity(&pinned).unwrap());
        assert_ne!(
            identity,
            file_identity(&File::open(&original).unwrap()).unwrap()
        );
        assert_eq!(std::fs::read(&original).unwrap(), b"second");
        drop(pinned);
        directory.close().unwrap();
    }

    #[test]
    fn suspended_worker_is_limited_and_killed_when_job_closes() {
        use std::os::windows::process::CommandExt;
        use std::process::{Command, Stdio};
        use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "windows::tests::job_child_waits"])
            .env("GRUST_WINDOWS_JOB_TEST", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        let job = match WorkerJob::assign_and_resume(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Cannot assign test child to job: {error}");
            }
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: live job, correctly sized writable output; returned length is
        // optional and intentionally null.
        assert_ne!(
            unsafe {
                QueryInformationJobObject(
                    job._handle.as_raw_handle(),
                    JobObjectExtendedLimitInformation,
                    (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(limits.ProcessMemoryLimit, 2 * 1024 * 1024 * 1024);
        assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
        assert!(child.try_wait().unwrap().is_none());
        // The updater transfers worker ownership to a background job. Closing
        // the owned job handle there must retain kill-on-close behavior.
        std::thread::spawn(move || drop(job)).join().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("Closing job did not terminate worker");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    #[ignore = "Subprocess fixture for the job lifecycle test"]
    fn job_child_waits() {
        if std::env::var_os("GRUST_WINDOWS_JOB_TEST").is_none() {
            return;
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}
