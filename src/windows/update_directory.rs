//! Directory-relative cleanup capability. No original-path lookup authorizes
//! a destructive operation after this directory has been opened.
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{
    ffi::OsStrExt,
    fs::OpenOptionsExt,
    io::{AsRawHandle, FromRawHandle},
};
use std::path::{Component, Path, Prefix};
use std::ptr;

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
};
use windows_sys::Win32::Foundation::{
    OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

pub(crate) struct PinnedUpdateDirectory {
    directory: File,
}

/// Only a sealed directory can enumerate cleanup victims or open DELETE handles.
pub(crate) struct CleanupDirectory {
    directory: File,
}

fn invalid() -> io::Error {
    io::Error::other("Unsupported update-directory containment")
}

fn child_name(name: &OsStr) -> io::Result<Vec<u16>> {
    let name: Vec<_> = name.encode_wide().collect();
    if name.is_empty()
        || name.len() > 255
        || name == [46]
        || name == [46, 46]
        || name.iter().any(|c| [0, 47, 92, 58].contains(c))
    {
        return Err(invalid());
    }
    Ok(name)
}

fn relative(parent: &File, name: &OsStr, directory: bool, deletion: bool) -> io::Result<File> {
    let name = child_name(name)?;
    let share = if directory {
        FILE_SHARE_READ | FILE_SHARE_DELETE
    } else if deletion {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
    };
    open_relative(parent, name, directory, deletion, share)
}

fn open_relative(
    parent: &File,
    mut name: Vec<u16>,
    directory: bool,
    deletion: bool,
    share: FILE_SHARE_MODE,
) -> io::Result<File> {
    let length = u16::try_from(name.len() * 2).map_err(|_| invalid())?;
    let text = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: if name.is_empty() {
            ptr::null_mut()
        } else {
            name.as_mut_ptr()
        },
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &text,
        // Enumeration supplied the exact candidate spelling. In a case-sensitive
        // directory, an insensitive lookup could select a non-eligible sibling
        // after that entry disappears. Bootstrap/identity opens remain guarded
        // by retained file identities; deletion opens must use the exact name.
        Attributes: OBJ_DONT_REPARSE | if deletion { 0 } else { OBJ_CASE_INSENSITIVE },
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle = ptr::null_mut();
    let mut status_block = IO_STATUS_BLOCK::default();
    let access = if directory {
        FILE_GENERIC_READ | FILE_TRAVERSE | if deletion { DELETE } else { 0 }
    } else {
        FILE_READ_ATTRIBUTES | SYNCHRONIZE | if deletion { DELETE } else { 0 }
    };
    // Directory read access plus no write sharing excludes an existing or new
    // writer that could turn the opened directory into a reparse point.
    // Delete sharing permits parent renames: all subsequent opens remain relative
    // to the retained object. Identity-only file opens permit owned temp writers.
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if directory {
            FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    // SAFETY: parent owns a live directory handle; name is a checked child or
    // an internally generated self reference. text/attributes/output live through this synchronous
    // call. FILE_OPEN never creates/replaces anything; no reparse point is followed.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status_block,
            ptr::null(),
            0,
            share,
            FILE_OPEN,
            options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: translating the returned NTSTATUS has no pointer arguments.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return Err(invalid());
    }
    // SAFETY: successful NtCreateFile transfers this unique owned handle to File,
    // which closes it exactly once, including every validation-error return.
    let file = unsafe { File::from_raw_handle(handle) };
    if directory {
        verify_directory(&file)?;
    } else {
        super::verify_regular_file(&file)?;
    }
    Ok(file)
}

fn verify_directory(file: &File) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file is live and info is writable initialized output storage.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
    {
        return Err(invalid());
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
        != FILE_ATTRIBUTE_DIRECTORY
    {
        return Err(invalid());
    }
    Ok(())
}

fn directory_id(directory: &File) -> io::Result<(u64, [u8; 16])> {
    let mut id = FILE_ID_INFO::default();
    // SAFETY: directory owns a live handle and id is initialized writable output
    // of the exact FILE_ID_INFO size required by this information class.
    if unsafe {
        GetFileInformationByHandleEx(
            directory.as_raw_handle(),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of_val(&id) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if id.VolumeSerialNumber == 0 || id.FileId.Identifier.iter().all(|byte| *byte == 0) {
        return Err(invalid());
    }
    Ok((id.VolumeSerialNumber, id.FileId.Identifier))
}

fn reopen(directory: &File, share: FILE_SHARE_MODE) -> io::Result<File> {
    let expected = directory_id(directory)?;
    // Both names are generated here, never supplied by an enumerated entry.
    // These bounded self-relative forms cannot select a parent or an ambient
    // pathname. Require the full volume/128-bit identity to prove the reopened
    // object is the original retained directory, regardless of filesystem form.
    let mut error = invalid();
    for name in [Vec::new(), vec![46]] {
        match open_relative(directory, name, true, false, share) {
            Ok(file) if directory_id(&file)? == expected => return Ok(file),
            Ok(_) => return Err(invalid()),
            Err(failure) => error = failure,
        }
    }
    Err(error)
}

impl PinnedUpdateDirectory {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        super::validate_local_path(path)?;
        let mut parts = path.components();
        let drive = match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(invalid()),
            },
            _ => return Err(invalid()),
        };
        if parts.next() != Some(Component::RootDir) {
            return Err(invalid());
        }
        let root = format!("\\\\?\\{}:\\", char::from(drive));
        // Bootstrap only a local drive root; no attacker-controlled ancestor
        // path is traversed. Each subsequent component is opened relatively.
        let mut directory = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(root)?;
        verify_directory(&directory)?;
        // A drive mapping may have changed after GetDriveType. Requiring a
        // local volume GUID from this actual root handle fails closed for UNC
        // shares and filesystems that cannot establish a local volume binding.
        let mut volume = [0u16; 128];
        // SAFETY: directory owns a live root handle; volume is writable for
        // the supplied UTF-16 length, and no pointer survives the call.
        let count = unsafe {
            GetFinalPathNameByHandleW(
                directory.as_raw_handle(),
                volume.as_mut_ptr(),
                volume.len() as u32,
                VOLUME_NAME_GUID,
            )
        } as usize;
        let prefix: Vec<_> = "\\\\?\\Volume{".encode_utf16().collect();
        if count == 0
            || count >= volume.len()
            || !volume[..count].starts_with(&prefix)
            || !volume[..count].ends_with(&[125, 92])
        {
            return Err(invalid());
        }
        for component in parts {
            let Component::Normal(name) = component else {
                return Err(invalid());
            };
            directory = relative(&directory, name, true, false).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("Cannot pin update-directory component: {error}"),
                )
            })?;
        }
        // Installation still uses existing path-based renames. Retain this
        // object with permissive sharing until publication completes; cleanup
        // separately acquires its restrictive handle or skips the entire pass.
        let directory = reopen(
            &directory,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        )
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("Cannot retain update-directory publication handle: {error}"),
            )
        })?;
        Ok(Self { directory })
    }

    pub(crate) fn sealed(&self) -> io::Result<CleanupDirectory> {
        Ok(CleanupDirectory {
            directory: reopen(&self.directory, FILE_SHARE_READ | FILE_SHARE_DELETE)?,
        })
    }

    pub(crate) fn identity(&self, name: &OsStr) -> io::Result<File> {
        relative(&self.directory, name, false, false)
    }
}

impl CleanupDirectory {
    /// Obtain DELETE access to the same directory object; disposition will only
    /// remove it once empty. No ambient pathname or recursive removal is used.
    pub(crate) fn empty_deletion(&self) -> io::Result<File> {
        let expected = directory_id(&self.directory)?;
        let mut error = invalid();
        for name in [Vec::new(), vec![46]] {
            match open_relative(
                &self.directory,
                name,
                true,
                true,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ) {
                Ok(file) if directory_id(&file)? == expected => return Ok(file),
                Ok(_) => return Err(invalid()),
                Err(failure) => error = failure,
            }
        }
        Err(error)
    }

    pub(crate) fn deletion(&self, name: &OsStr) -> io::Result<File> {
        relative(&self.directory, name, false, true)
    }

    /// Remove this verified directory only if it is empty. Never resolve its
    /// original pathname after releasing the directory capability.
    pub(crate) fn remove_empty(&self) -> io::Result<()> {
        let file = self.empty_deletion()?;
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: empty_deletion returns a live DELETE handle to this exact
        // verified directory. info is initialized and live for its exact size;
        // the kernel refuses a nonempty directory and never recursively deletes.
        if unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle(),
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_names_cannot_escape_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let pinned = PinnedUpdateDirectory::open(directory.path()).unwrap();
        for name in ["", ".", "..", "x\\y", "x/y", "x:y", "x\0y"] {
            assert!(pinned.identity(OsStr::new(name)).is_err());
        }
    }

    #[test]
    fn empty_directory_cleanup_preserves_path_replacements_and_nonempty_contents() {
        for junction in [false, true] {
            let outer = tempfile::tempdir().unwrap();
            let original = outer.path().join("original");
            let moved = outer.path().join("moved");
            let outside = outer.path().join("outside");
            std::fs::create_dir(&original).unwrap();
            std::fs::create_dir(&outside).unwrap();
            let pinned = PinnedUpdateDirectory::open(&original).unwrap();
            let cleanup = pinned.sealed().unwrap();
            drop(pinned);
            let swapped = match std::fs::rename(&original, &moved) {
                Ok(()) => true,
                Err(error) => {
                    assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
                    false // Open-directory sharing can itself block the attack.
                }
            };
            eprintln!("directory replacement: junction={junction}, swapped={swapped}");
            if swapped {
                if junction {
                    let result = std::process::Command::new("cmd.exe")
                        .args(["/d", "/c", "mklink", "/J"])
                        .arg(&original)
                        .arg(&outside)
                        .output()
                        .unwrap();
                    assert!(result.status.success());
                } else {
                    std::fs::create_dir(&original).unwrap();
                }
            }
            let actual = if swapped { &moved } else { &original };
            // Refuse to remove a directory that still contains any data.
            std::fs::write(actual.join("keep"), b"keep this data").unwrap();
            assert!(cleanup.remove_empty().is_err());
            assert_eq!(
                std::fs::read(actual.join("keep")).unwrap(),
                b"keep this data"
            );
            std::fs::remove_file(actual.join("keep")).unwrap();
            cleanup.remove_empty().unwrap();
            drop(cleanup);
            assert!(!actual.exists());
            if swapped {
                assert!(
                    std::fs::symlink_metadata(&original).is_ok(),
                    "replacement was removed"
                );
                // Make replacement preservation observable even when it was empty
                // at the cleanup boundary (the vulnerable pathname case).
                std::fs::write(original.join("replacement-survived"), b"safe").unwrap();
                if junction {
                    std::fs::remove_dir(&original).unwrap();
                }
            }
            assert!(outside.exists());
        }
    }

    #[test]
    fn capability_setup_rejects_junction_ancestors_and_has_no_path_fallback() {
        let outer = tempfile::tempdir().unwrap();
        let target = outer.path().join("target");
        let nested = target.join("nested");
        let junction = outer.path().join("link");
        std::fs::create_dir_all(&nested).unwrap();
        let result = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(PinnedUpdateDirectory::open(&junction.join("nested")).is_err());
        std::fs::remove_dir(junction).unwrap();
        assert!(nested.is_dir());
    }
}
