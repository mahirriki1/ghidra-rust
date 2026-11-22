//! Open companion candidates without traversing links or admitting directories.
//! Call from a file task/controller, never from the GUI thread.
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};
pub(crate) struct Prepared {
    pub path: PathBuf,
    pub file: Arc<File>,
}
pub(crate) fn prepare(path: &Path) -> Result<Prepared, String> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    let file = open(&path).map_err(|e| format!("Cannot use debug companion: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > crate::analysis::MAX_IMAGE_BYTES {
        return Err("Debug companion must be a regular file of at most 128 MiB".into());
    }
    Ok(Prepared {
        path,
        file: Arc::new(file),
    })
}
#[cfg(target_os = "linux")]
fn open(path: &Path) -> std::io::Result<File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
        path::Component,
    };
    let mut directory = File::open("/")?;
    let parts: Vec<_> = path
        .components()
        .filter(|p| !matches!(p, Component::RootDir))
        .collect();
    if parts.is_empty() {
        return Err(std::io::Error::other("Missing file name"));
    }
    for (i, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else {
            return Err(std::io::Error::other("Non-normal companion path component"));
        };
        let name = CString::new(name.as_bytes()).map_err(std::io::Error::other)?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | if i + 1 < parts.len() {
                libc::O_DIRECTORY
            } else {
                0
            };
        // SAFETY: directory is a live directory descriptor; name is NUL-terminated.
        // Each returned descriptor is immediately owned by exactly one File.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat succeeded and transferred a fresh descriptor to us.
        directory = unsafe { File::from_raw_fd(fd) };
    }
    Ok(directory)
}
#[cfg(windows)]
fn open(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ,
    };
    crate::windows::validate_local_path(path)?;
    // Retain every directory without FILE_SHARE_DELETE to prevent ancestor
    // junction substitution until the final file has been opened and checked.
    let mut parents = Vec::new();
    let mut current = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (i, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            continue;
        }
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(std::io::Error::other("Non-normal companion path component"));
        }
        let metadata = std::fs::symlink_metadata(&current)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other(
                "Companion paths cannot contain reparse points",
            ));
        }
        if i + 1 < components.len() {
            let directory = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&current)?;
            if directory.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(std::io::Error::other(
                    "Companion directory is a reparse point",
                ));
            }
            parents.push(directory);
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    crate::windows::configure_read(&mut options);
    let file = options.open(path)?;
    crate::windows::verify_regular_file(&file)?;
    Ok(file)
}
#[cfg(not(any(target_os = "linux", windows)))]
fn open(_: &Path) -> std::io::Result<File> {
    Err(std::io::Error::other(
        "Secure companion opening is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_bounded_regular_files_are_admitted() {
        let dir = tempfile::tempdir().unwrap();
        assert!(prepare(dir.path()).is_err());
        let file = dir.path().join("regular");
        std::fs::write(&file, b"original").unwrap();
        assert!(prepare(&file).is_ok());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_components_fifo_and_swapped_paths_are_rejected_or_pinned() {
        use std::{io::Read, os::unix::fs::symlink};
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"original").unwrap();
        let link = dir.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(prepare(&link).is_err());
        let parent = dir.path().join("parent");
        symlink(dir.path(), &parent).unwrap();
        assert!(prepare(&parent.join("file")).is_err());
        let fifo = dir.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        assert!(prepare(&fifo).is_err());
        let prepared = prepare(&file).unwrap();
        std::fs::rename(&file, dir.path().join("old")).unwrap();
        std::fs::write(&file, b"replacement").unwrap();
        let mut text = String::new();
        prepared
            .file
            .try_clone()
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "original");
    }
}
