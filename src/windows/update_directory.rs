//! Directory-relative cleanup capability. No original-path lookup authorizes
//! a destructive operation after this directory has been opened.
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
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
    ERROR_NO_MORE_FILES, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, RtlNtStatusToDosError,
    UNICODE_STRING,
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
        FILE_GENERIC_READ | FILE_TRAVERSE
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
    pub(crate) fn deletion(&self, name: &OsStr) -> io::Result<File> {
        relative(&self.directory, name, false, true)
    }

    /// Enumerate the retained object, charging every record before filtering.
    /// A false visitor return stops immediately without another directory query.
    pub(crate) fn visit(
        &self,
        maximum: usize,
        mut visitor: impl FnMut(&OsStr) -> bool,
    ) -> io::Result<usize> {
        let mut storage = [0u64; 8192]; // Fixed 64 KiB, aligned for Windows output.
        let mut scanned = 0;
        let mut restart = true;
        while scanned < maximum {
            storage.fill(0);
            let class = if restart {
                FileIdBothDirectoryRestartInfo
            } else {
                FileIdBothDirectoryInfo
            };
            restart = false;
            // SAFETY: directory owns a synchronous directory handle opened with
            // FILE_LIST_DIRECTORY. storage is live, writable and 8-byte aligned;
            // its exact byte size is passed and no pointer survives this call.
            let success = unsafe {
                GetFileInformationByHandleEx(
                    self.directory.as_raw_handle(),
                    class,
                    storage.as_mut_ptr().cast(),
                    size_of_val(&storage) as u32,
                )
            };
            if success == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    return Ok(scanned);
                }
                return Err(error);
            }
            // SAFETY: every u64 is initialized; viewing its full allocation as
            // bytes preserves alignment/lifetime and cannot read outside storage.
            let data = unsafe {
                std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), size_of_val(&storage))
            };
            let mut offset = 0usize;
            loop {
                let (name, next) = entry(data, offset)?;
                scanned += 1;
                if !visitor(&name) || scanned == maximum {
                    return Ok(scanned);
                }
                let Some(next) = next else {
                    break;
                };
                offset = next;
            }
        }
        Ok(scanned)
    }
}

/// Parse bounded directory records without dereferencing variable-length C
/// structs. File IDs/attributes are hints; opened handles are authoritative.
fn entry(data: &[u8], at: usize) -> io::Result<(OsString, Option<usize>)> {
    let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    let read32 = |offset: usize| -> io::Result<u32> {
        let start = at.checked_add(offset).ok_or_else(invalid)?;
        let bytes = data
            .get(start..start.checked_add(4).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| invalid())?))
    };
    let next = read32(std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, NextEntryOffset))? as usize;
    let length = read32(std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength))? as usize;
    if length == 0 || length > 510 || !length.is_multiple_of(2) {
        return Err(invalid());
    }
    let start = at.checked_add(header).ok_or_else(invalid)?;
    let end = start.checked_add(length).ok_or_else(invalid)?;
    let bytes = data.get(start..end).ok_or_else(invalid)?;
    let name: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    if name.contains(&0) {
        return Err(invalid());
    }
    let next = if next == 0 {
        None
    } else {
        if next < header + length || !next.is_multiple_of(8) {
            return Err(invalid());
        }
        let offset = at
            .checked_add(next)
            .filter(|next| *next < data.len())
            .ok_or_else(invalid)?;
        Some(offset)
    };
    Ok((OsString::from_wide(&name), next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_iteration_charges_nonmatching_entries_and_stops_at_the_budget() {
        let directory = tempfile::tempdir().unwrap();
        for index in 0..12 {
            std::fs::write(directory.path().join(format!("unrelated-{index}")), []).unwrap();
        }
        let prepared = PinnedUpdateDirectory::open(directory.path()).unwrap();
        let pinned = prepared.sealed().unwrap();
        let mut visited = 0;
        assert_eq!(
            pinned
                .visit(7, |_| {
                    visited += 1;
                    true
                })
                .unwrap(),
            7
        );
        assert_eq!(visited, 7);
        let mut visited = 0;
        assert_eq!(
            pinned
                .visit(4096, |_| {
                    visited += 1;
                    false
                })
                .unwrap(),
            1
        );
        assert_eq!(visited, 1);
        for name in ["", ".", "..", "x\\y", "x/y", "x:y", "x\0y"] {
            assert!(prepared.identity(OsStr::new(name)).is_err());
        }
    }

    #[test]
    fn directory_record_parser_rejects_truncated_overlapping_and_overlong_names() {
        let header = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
        let length_at = std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileNameLength);
        let mut record = vec![0u8; header + 8];
        record[length_at..length_at + 4].copy_from_slice(&2u32.to_le_bytes());
        record[header..header + 2].copy_from_slice(&u16::from(b'x').to_le_bytes());
        assert_eq!(entry(&record, 0).unwrap(), (OsString::from("x"), None));
        for length in [0u32, 1, 512, u32::MAX] {
            let mut broken = record.clone();
            broken[length_at..length_at + 4].copy_from_slice(&length.to_le_bytes());
            assert!(entry(&broken, 0).is_err());
        }
        for next in [1u32, header as u32, u32::MAX] {
            let mut broken = record.clone();
            broken[..4].copy_from_slice(&next.to_le_bytes());
            assert!(entry(&broken, 0).is_err());
        }
        assert!(entry(&record[..header], 0).is_err());
        assert!(entry(&record, usize::MAX).is_err());
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
