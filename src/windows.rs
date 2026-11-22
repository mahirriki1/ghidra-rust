//! Windows file identity and worker resource containment.
//!
//! Job objects limit resource use and lifetime. They do not isolate the worker
//! from the user's files, registry, credentials, or network.

mod update_directory;
mod worker_process;
pub(crate) use update_directory::{CleanupDirectory, PinnedUpdateDirectory};
pub(crate) use worker_process::WorkerProcess;

use crate::model::FileIdentity;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{
    ffi::OsStrExt,
    fs::OpenOptionsExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::path::Path;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::*;
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

/// Inspect an output's identity without conflicting with its existing writer
/// (for example, an updater-owned tempfile). This handle never reads its bytes.
pub fn open_for_identity(path: &Path) -> io::Result<File> {
    validate_local_path(path)?;
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_regular_file(&file)?;
    Ok(file)
}

/// Delete the exact regular file that was inspected, rather than resolving its
/// name again. Sharing violations (including running executables) are errors.
pub fn delete_open_file(file: &File) -> io::Result<()> {
    verify_regular_file(file)?;
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: file owns a live handle opened with DELETE access. info is an
    // initialized FILE_DISPOSITION_INFO of the supplied size, live for the call.
    // The kernel marks this handle's file for deletion when its last handle closes.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
            // successful Win32 calls that transfer ownership. Null and
            // INVALID_HANDLE_VALUE were rejected above. OwnedHandle
            // closes exactly once and safely transfers ownership between threads.
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
        }
    }

    fn as_raw_handle(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
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
}
