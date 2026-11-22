//! Linux desktop integration. Wayland compositors such as KDE Plasma ignore
//! icons that a window sets itself; they look up the window's app id in a
//! `.desktop` entry. On each desktop start this writes, in the user's own XDG
//! data directory only:
//!
//! - `applications/io.github.mahirriki1.GhidraRust.desktop`, whose `Exec=`
//!   names the running executable, and
//! - `icons/hicolor/256x256/apps/io.github.mahirriki1.GhidraRust.png`.
//!
//! The entry's first line carries a SHA-256 of the rest of the file. Only an
//! intact entry written this way is ever replaced or removed, so an entry the
//! user edited, emptied, or replaced (for example with a menu editor) is left
//! alone. Files are rewritten only when their content differs. Directories
//! below the data directory must be real directories owned by the user;
//! symlinks are not followed, and missing directories are created only below
//! one the user already owns. Every write goes to a new temporary file that
//! atomically replaces the old one. Failures are ignored: the desktop works
//! without the entry.
use crate::brand::{APP_ID, ICON_PNG};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

/// The packaged entry. Self-registration substitutes its `Exec=` and
/// `TryExec=` lines; the tarball ships it unchanged under `share/`.
const TEMPLATE: &str = include_str!("../packaging/linux/io.github.mahirriki1.GhidraRust.desktop");
const TEMPLATE_EXEC: &str = "Exec=ghidra-rust %f";
const TEMPLATE_TRY_EXEC: &str = "TryExec=ghidra-rust";
const ICON_DIRECTORY: [&str; 4] = ["icons", "hicolor", "256x256", "apps"];
/// First line of a self-written entry, followed by the lowercase hex SHA-256
/// of everything after that line.
const SIGNATURE_PREFIX: &str = "# Written by Ghidra Rust when the desktop starts. sha256=";
/// Read limits for files this module inspects; larger files are never ours.
const MAX_ENTRY_BYTES: u64 = 64 * 1024;
const MAX_ICON_BYTES: u64 = 4 * 1024 * 1024;
/// Temporary files older than this are leftovers of an interrupted write.
const STALE_TEMPORARY_AGE: Duration = Duration::from_secs(10 * 60);
const MAX_SCANNED_NAMES: usize = 16 * 1024;

/// What a registration attempt did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both files were already current.
    Unchanged,
    /// At least one file was created or replaced.
    Written,
    /// A system data directory already provides the entry, e.g. a distro
    /// package. A user-level copy would shadow it, so nothing was written and
    /// an intact self-written user entry and its icon were removed.
    Packaged,
    /// The user's entry was edited, emptied, or is not a regular file; it and
    /// the icon were left alone.
    Customized,
}

/// Where to register and which executable `Exec=` should launch.
#[derive(Debug, Clone)]
pub struct Environment {
    pub data_home: PathBuf,
    pub data_dirs: Vec<PathBuf>,
    pub executable: PathBuf,
}

impl Environment {
    /// The XDG locations and the running executable, or `None` when any of
    /// them cannot be determined or the desktop was started by `cargo run`.
    pub fn from_process() -> Option<Self> {
        // `cargo run` sets this. A build inside a worktree's `target/` must
        // not take over the user's menu entry and vanish with the worktree.
        if std::env::var_os("CARGO_PKG_NAME").is_some() {
            return None;
        }
        let data_home = data_home(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))?;
        let executable = std::env::current_exe().ok()?;
        // A replaced executable reads back as "path (deleted)"; skip it.
        if !std::fs::metadata(&executable).is_ok_and(|m| m.is_file()) {
            return None;
        }
        Some(Self {
            data_home,
            data_dirs: data_dirs(std::env::var_os("XDG_DATA_DIRS")),
            executable,
        })
    }
}

/// Registers the running desktop on a background thread; errors are ignored.
pub fn register_in_background() {
    let _ = std::thread::Builder::new()
        .name("desktop-entry".into())
        .spawn(|| {
            if let Some(environment) = Environment::from_process() {
                let _ = install(&environment);
            }
        });
}

/// `$XDG_DATA_HOME`, or `$HOME/.local/share`. Relative values are invalid
/// under the XDG Base Directory specification and are ignored.
pub fn data_home(xdg_data_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute =
        |value: Option<OsString>| value.map(PathBuf::from).filter(|path| path.is_absolute());
    absolute(xdg_data_home).or_else(|| absolute(home).map(|home| home.join(".local/share")))
}

/// The absolute entries of `$XDG_DATA_DIRS`, defaulting to
/// `/usr/local/share:/usr/share` when it is unset or has none.
pub fn data_dirs(value: Option<OsString>) -> Vec<PathBuf> {
    let absolute = |value: &OsStr| -> Vec<PathBuf> {
        std::env::split_paths(value)
            .filter(|path| path.is_absolute())
            .collect()
    };
    let listed = value.as_deref().map(absolute).unwrap_or_default();
    if listed.is_empty() {
        absolute(OsStr::new("/usr/local/share:/usr/share"))
    } else {
        listed
    }
}

/// The signed desktop entry for `executable`, or `None` when the path is not
/// UTF-8, is relative, or contains control characters an entry cannot carry.
pub fn desktop_entry(executable: &Path) -> Option<String> {
    let path = executable.to_str()?;
    if !executable.is_absolute() || path.chars().any(char::is_control) {
        return None;
    }
    // Exec arguments are quoted, with `"`, `` ` ``, `$` and `\` escaped and
    // `%` doubled. The string-value escape of `\` then applies on top.
    let mut quoted = String::from("\"");
    for c in path.chars() {
        match c {
            '"' | '`' | '$' | '\\' => quoted.extend(['\\', c]),
            '%' => quoted.push_str("%%"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    let exec = format!("Exec={} %f", quoted.replace('\\', "\\\\"));
    let try_exec = format!("TryExec={}", path.replace('\\', "\\\\"));
    let mut body = String::from(
        "# Ghidra Rust keeps this file up to date while it is unchanged.\n\
         # Edit it, or empty it, to keep your own version instead.\n",
    );
    for line in TEMPLATE.lines() {
        body.push_str(match line {
            TEMPLATE_EXEC => &exec,
            TEMPLATE_TRY_EXEC => &try_exec,
            line => line,
        });
        body.push('\n');
    }
    Some(format!(
        "{SIGNATURE_PREFIX}{}\n{body}",
        hex_sha256(body.as_bytes())
    ))
}

/// Whether `content` is an intact entry written by [`desktop_entry`], from
/// this or any other version.
fn is_own_entry(content: &[u8]) -> bool {
    let Some(newline) = content.iter().position(|&b| b == b'\n') else {
        return false;
    };
    let (first, body) = (&content[..newline], &content[newline + 1..]);
    first
        .strip_prefix(SIGNATURE_PREFIX.as_bytes())
        .is_some_and(|digest| digest == hex_sha256(body).as_bytes())
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Writes or refreshes the user's entry and icon for `environment`.
pub fn install(environment: &Environment) -> io::Result<Outcome> {
    let desktop_name = format!("{APP_ID}.desktop");
    let icon_name = format!("{APP_ID}.png");
    if provided_by_system(environment, &desktop_name) {
        remove_own_files(environment, &desktop_name, &icon_name)?;
        return Ok(Outcome::Packaged);
    }
    let entry = desktop_entry(&environment.executable).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "unsupported executable path")
    })?;
    ensure_data_home(&environment.data_home, effective_uid())?;
    let root = Directory::open(&environment.data_home)?;
    let applications = root.child("applications")?;
    let desktop_current = match applications.read_regular(&desktop_name, MAX_ENTRY_BYTES) {
        Existing::Missing => false,
        Existing::Regular(content) if content == entry.as_bytes() => true,
        Existing::Regular(content) if is_own_entry(&content) => false,
        Existing::Regular(_) | Existing::Other => return Ok(Outcome::Customized),
    };
    let mut icons = root.child(ICON_DIRECTORY[0])?;
    for name in &ICON_DIRECTORY[1..] {
        icons = icons.child(name)?;
    }
    // Write the icon first so the entry never names a missing icon.
    let icon_written = match icons.read_regular(&icon_name, MAX_ICON_BYTES) {
        Existing::Regular(content) if content == ICON_PNG => false,
        _ => {
            icons.replace(&icon_name, ICON_PNG)?;
            true
        }
    };
    if !desktop_current {
        applications.replace(&desktop_name, entry.as_bytes())?;
    }
    Ok(if icon_written || !desktop_current {
        Outcome::Written
    } else {
        Outcome::Unchanged
    })
}

/// Whether a data directory other than the user's own provides the entry.
/// Directories are compared by device and inode, so a symlink or bind mount
/// of the user's own data directory does not count as a package.
fn provided_by_system(environment: &Environment, desktop_name: &str) -> bool {
    let identity = |path: &Path| std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()));
    let own = identity(&environment.data_home);
    environment.data_dirs.iter().any(|directory| {
        let same = own.is_some() && identity(directory) == own;
        !same && directory.join("applications").join(desktop_name).is_file()
    })
}

/// Removes an intact self-written user entry and its icon, which would
/// otherwise shadow a packaged entry. Never creates directories.
fn remove_own_files(
    environment: &Environment,
    desktop_name: &str,
    icon_name: &str,
) -> io::Result<()> {
    let Ok(root) = Directory::open(&environment.data_home) else {
        return Ok(());
    };
    let Ok(applications) = root.existing_child("applications") else {
        return Ok(());
    };
    match applications.read_regular(desktop_name, MAX_ENTRY_BYTES) {
        Existing::Regular(content) if is_own_entry(&content) => {}
        _ => return Ok(()),
    }
    // Remove the icon first so a failure never leaves an entry without one.
    let mut icons = root.existing_child(ICON_DIRECTORY[0]);
    for name in &ICON_DIRECTORY[1..] {
        icons = icons.and_then(|directory| directory.existing_child(name));
    }
    if let Ok(icons) = icons
        && matches!(
            icons.read_regular(icon_name, MAX_ICON_BYTES),
            Existing::Regular(_)
        )
    {
        icons.remove(icon_name)?;
    }
    applications.remove(desktop_name)
}

/// Creates `path` and any missing parents with mode 0700, but only below an
/// existing directory owned by `uid`. Under `sudo -E` the effective user is
/// root while `HOME` is still the user's, and root-owned folders in the
/// user's home would break their other applications.
fn ensure_data_home(path: &Path, uid: u32) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut current = path;
    let anchor = loop {
        match std::fs::metadata(current) {
            Ok(metadata) => break metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current);
                current = current.parent().ok_or(error)?;
            }
            Err(error) => return Err(error),
        }
    };
    // An existing data directory is checked by `Directory::open` instead.
    if missing.is_empty() {
        return Ok(());
    }
    if !anchor.is_dir() || anchor.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "data directory parent is owned by another user",
        ));
    }
    for directory in missing.iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Err(error) if error.kind() != io::ErrorKind::AlreadyExists => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// What a name in a [`Directory`] refers to.
enum Existing {
    Missing,
    /// A regular file no larger than the read limit, and its content.
    Regular(Vec<u8>),
    /// A symlink, directory, FIFO, oversized file, or an unreadable entry.
    Other,
}

/// An open directory owned by the current user; children are reached with
/// `*at` calls relative to it, so no path component is re-resolved.
struct Directory(OwnedFd);

impl Directory {
    fn open(path: &Path) -> io::Result<Self> {
        let path = c_string(path.as_os_str())?;
        // SAFETY: `path` is a live NUL-terminated string; a non-negative
        // result is a new descriptor owned only by this wrapper.
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        Self::owned(fd)
    }

    /// Opens or creates `name`; refuses symlinks and other users' directories.
    fn child(&self, name: &str) -> io::Result<Self> {
        let name_c = c_string(OsStr::new(name))?;
        // SAFETY: the parent descriptor is open for `self`'s lifetime and
        // `name_c` is a live NUL-terminated single component.
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        self.existing_child(name)
    }

    /// Opens `name` without creating it; refuses symlinks and other users'
    /// directories.
    fn existing_child(&self, name: &str) -> io::Result<Self> {
        let name = c_string(OsStr::new(name))?;
        // SAFETY: the parent descriptor and NUL-terminated name are live;
        // O_NOFOLLOW makes a symlinked component fail, and a non-negative
        // result is a new descriptor owned by the wrapper.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        Self::owned(fd)
    }

    fn owned(fd: libc::c_int) -> io::Result<Self> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by open/openat and has no other owner.
        let directory = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        let metadata = File::from(directory.0.try_clone()?).metadata()?;
        if metadata.uid() != effective_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is owned by another user",
            ));
        }
        Ok(directory)
    }

    /// Classifies `name` and reads it when it is a regular file of at most
    /// `limit` bytes. Never follows a symlink or blocks on a FIFO.
    fn read_regular(&self, name: &str, limit: u64) -> Existing {
        let Ok(name) = c_string(OsStr::new(name)) else {
            return Existing::Other;
        };
        // SAFETY: the directory descriptor and NUL-terminated name are live;
        // a non-negative result is a new descriptor owned by the File below.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return match io::Error::last_os_error().kind() {
                io::ErrorKind::NotFound => Existing::Missing,
                _ => Existing::Other,
            };
        }
        // SAFETY: `fd` was just opened above and has no other owner.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file
            .metadata()
            .is_ok_and(|m| m.is_file() && m.len() <= limit)
        {
            return Existing::Other;
        }
        let mut content = Vec::new();
        match file.take(limit + 1).read_to_end(&mut content) {
            Ok(_) if content.len() as u64 <= limit => Existing::Regular(content),
            _ => Existing::Other,
        }
    }

    /// Atomically replaces `name` with `content`. An existing symlink entry is
    /// replaced, not followed.
    fn replace(&self, name: &str, content: &[u8]) -> io::Result<()> {
        self.remove_stale_temporaries(name);
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let temporary = format!(
            ".{name}.{}.{}.tmp",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let temporary_c = c_string(OsStr::new(&temporary))?;
        let target_c = c_string(OsStr::new(name))?;
        // SAFETY: the directory descriptor and NUL-terminated name are live;
        // O_EXCL|O_NOFOLLOW only ever creates a new regular file, whose
        // descriptor the File below takes sole ownership of.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temporary_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just created above and has no other owner.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let written = file.write_all(content).and_then(|()| file.sync_all());
        drop(file);
        let result = written.and_then(|()| {
            let fd = self.0.as_raw_fd();
            // SAFETY: both names are live NUL-terminated components of the
            // same open directory; renameat replaces a symlink entry itself.
            if unsafe { libc::renameat(fd, temporary_c.as_ptr(), fd, target_c.as_ptr()) } == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        });
        if result.is_err() {
            // SAFETY: as above; this removes only the temporary entry.
            unsafe { libc::unlinkat(self.0.as_raw_fd(), temporary_c.as_ptr(), 0) };
        }
        result
    }

    /// Removes the directory entry `name` itself; a symlink is not followed.
    fn remove(&self, name: &str) -> io::Result<()> {
        let name = c_string(OsStr::new(name))?;
        // SAFETY: the directory descriptor and NUL-terminated name are live;
        // unlinkat without AT_REMOVEDIR removes only a non-directory entry.
        if unsafe { libc::unlinkat(self.0.as_raw_fd(), name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Best effort: removes `.{name}.*.tmp` regular files owned by the user
    /// that an interrupted [`Self::replace`] left behind. Recent ones may
    /// belong to another instance that is still writing and are kept.
    fn remove_stale_temporaries(&self, name: &str) {
        let prefix = format!(".{name}.");
        // Lists the open directory itself rather than re-resolving its path.
        let Ok(entries) = std::fs::read_dir(format!("/proc/self/fd/{}", self.0.as_raw_fd())) else {
            return;
        };
        let cutoff = SystemTime::now().checked_sub(STALE_TEMPORARY_AGE);
        for entry in entries.flatten().take(MAX_SCANNED_NAMES) {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if !file_name.starts_with(&prefix) || !file_name.ends_with(".tmp") {
                continue;
            }
            // DirEntry::metadata does not follow symlinks.
            let stale = entry.metadata().is_ok_and(|m| {
                m.is_file()
                    && m.uid() == effective_uid()
                    && m.modified()
                        .is_ok_and(|modified| cutoff.is_some_and(|cutoff| modified < cutoff))
            });
            if stale {
                let _ = self.remove(file_name);
            }
        }
    }
}

fn c_string(value: &OsStr) -> io::Result<CString> {
    CString::new(value.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn environment(root: &Path, executable: &str) -> Environment {
        Environment {
            data_home: root.join("data"),
            data_dirs: vec![root.join("system")],
            executable: PathBuf::from(executable),
        }
    }

    fn desktop_path(env: &Environment) -> PathBuf {
        env.data_home.join(format!("applications/{APP_ID}.desktop"))
    }

    fn icon_path(env: &Environment) -> PathBuf {
        env.data_home
            .join(format!("icons/hicolor/256x256/apps/{APP_ID}.png"))
    }

    /// Names in the directory of `path` other than `path` itself.
    fn others(path: &Path) -> Vec<OsString> {
        std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.as_os_str() != path.file_name().unwrap())
            .collect()
    }

    fn package(root: &Path) {
        let system = root.join("system/applications");
        std::fs::create_dir_all(&system).unwrap();
        std::fs::write(system.join(format!("{APP_ID}.desktop")), b"packaged").unwrap();
    }

    #[test]
    fn writes_once_then_leaves_fresh_files_alone() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra rust/ghidra-rust");
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        let entry = std::fs::read_to_string(desktop_path(&env)).unwrap();
        assert!(entry.contains("\nExec=\"/opt/ghidra rust/ghidra-rust\" %f\n"));
        assert!(entry.contains("\nTryExec=/opt/ghidra rust/ghidra-rust\n"));
        assert!(entry.contains(&format!("\nIcon={APP_ID}\n")));
        assert!(entry.contains(&format!("\nStartupWMClass={APP_ID}\n")));
        assert_eq!(std::fs::read(icon_path(&env)).unwrap(), ICON_PNG);
        let inodes = |env: &Environment| {
            [desktop_path(env), icon_path(env)].map(|p| std::fs::metadata(p).unwrap().ino())
        };
        let before = inodes(&env);
        assert_eq!(install(&env).unwrap(), Outcome::Unchanged);
        assert_eq!(inodes(&env), before);
        assert_eq!(others(&desktop_path(&env)), Vec::<OsString>::new());
        assert_eq!(others(&icon_path(&env)), Vec::<OsString>::new());
    }

    #[test]
    fn rewrites_stale_entry_and_icon() {
        let root = tempfile::tempdir().unwrap();
        let mut env = environment(root.path(), "/old/ghidra-rust");
        install(&env).unwrap();
        env.executable = PathBuf::from("/new/ghidra-rust");
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        let entry = std::fs::read_to_string(desktop_path(&env)).unwrap();
        assert!(entry.contains("\nExec=\"/new/ghidra-rust\" %f\n"));
        assert!(!entry.contains("/old/"));
        std::fs::write(icon_path(&env), b"stale").unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        assert_eq!(std::fs::read(icon_path(&env)).unwrap(), ICON_PNG);
    }

    #[test]
    fn edited_emptied_or_special_entries_are_kept() {
        let root = tempfile::tempdir().unwrap();
        let mut env = environment(root.path(), "/old/ghidra-rust");
        install(&env).unwrap();
        env.executable = PathBuf::from("/new/ghidra-rust");
        // A menu editor that keeps comments but hides the entry.
        let mut edited = std::fs::read(desktop_path(&env)).unwrap();
        edited.extend_from_slice(b"NoDisplay=true\n");
        std::fs::write(desktop_path(&env), &edited).unwrap();
        std::fs::write(icon_path(&env), b"user icon").unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Customized);
        assert_eq!(std::fs::read(desktop_path(&env)).unwrap(), edited);
        assert_eq!(std::fs::read(icon_path(&env)).unwrap(), b"user icon");
        // An empty file is a lasting opt-out.
        std::fs::write(desktop_path(&env), b"").unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Customized);
        assert_eq!(std::fs::read(desktop_path(&env)).unwrap(), b"");
        // A FIFO is neither read nor waited on.
        std::fs::remove_file(desktop_path(&env)).unwrap();
        let fifo = c_string(desktop_path(&env).as_os_str()).unwrap();
        // SAFETY: `fifo` is a live NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(install(&env).unwrap(), Outcome::Customized);
        assert!(
            !std::fs::symlink_metadata(desktop_path(&env))
                .unwrap()
                .is_file()
        );
    }

    #[test]
    fn leaves_a_symlinked_entry_alone_without_writing_through_it() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        let target = root.path().join("dotfiles-entry");
        std::fs::write(&target, b"keep").unwrap();
        std::fs::create_dir_all(env.data_home.join("applications")).unwrap();
        symlink(&target, desktop_path(&env)).unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Customized);
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(
            std::fs::symlink_metadata(desktop_path(&env))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn data_home_follows_the_xdg_rules() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            data_home(os("/xdg/data"), os("/home/u")),
            Some(PathBuf::from("/xdg/data"))
        );
        for ignored in ["", "relative/data"] {
            assert_eq!(
                data_home(os(ignored), os("/home/u")),
                Some(PathBuf::from("/home/u/.local/share"))
            );
        }
        assert_eq!(data_home(None, os("relative")), None);
        assert_eq!(data_home(None, None), None);
        let default = [
            PathBuf::from("/usr/local/share"),
            PathBuf::from("/usr/share"),
        ];
        for value in [None, os(""), os("rel:other")] {
            assert_eq!(data_dirs(value), default);
        }
        assert_eq!(
            data_dirs(os("/a:rel:/b")),
            [PathBuf::from("/a"), PathBuf::from("/b")]
        );
    }

    #[test]
    fn refuses_symlinked_directories_below_the_data_home() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(&env.data_home).unwrap();
        symlink(&elsewhere, env.data_home.join("applications")).unwrap();
        assert!(install(&env).is_err());
        assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
    }

    #[test]
    fn missing_data_home_is_created_private_and_only_under_an_owned_parent() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("home/.local/share");
        // As under `sudo -E`: the existing parent belongs to someone else.
        let error = ensure_data_home(&path, effective_uid().wrapping_add(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!root.path().join("home").exists());
        ensure_data_home(&path, effective_uid()).unwrap();
        for directory in ["home", "home/.local", "home/.local/share"] {
            let mode = std::fs::metadata(root.path().join(directory))
                .unwrap()
                .mode();
            assert_eq!(mode & 0o777, 0o700, "{directory}");
        }
        // A data directory that is a symlink to an owned directory is used.
        let linked = root.path().join("linked");
        symlink(&path, &linked).unwrap();
        let env = Environment {
            data_home: linked,
            ..environment(root.path(), "/opt/ghidra-rust")
        };
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        assert!(
            path.join(format!("applications/{APP_ID}.desktop"))
                .is_file()
        );
    }

    #[test]
    fn unwritable_data_home_fails_without_writing() {
        if effective_uid() == 0 {
            return; // Root ignores permissions.
        }
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        std::fs::create_dir(&env.data_home).unwrap();
        std::fs::set_permissions(&env.data_home, std::fs::Permissions::from_mode(0o555)).unwrap();
        let result = install(&env);
        std::fs::set_permissions(&env.data_home, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read_dir(&env.data_home).unwrap().count(), 0);
    }

    #[test]
    fn packaged_entry_removes_only_our_intact_user_files() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        install(&env).unwrap();
        package(root.path());
        assert_eq!(install(&env).unwrap(), Outcome::Packaged);
        assert!(!desktop_path(&env).exists());
        assert!(!icon_path(&env).exists());
        // Without a user data directory nothing is created.
        let fresh = Environment {
            data_home: root.path().join("absent"),
            ..env.clone()
        };
        assert_eq!(install(&fresh).unwrap(), Outcome::Packaged);
        assert!(!fresh.data_home.exists());
        // An edited user entry overrides the package on purpose; keep it.
        std::fs::write(desktop_path(&env), b"[Desktop Entry]\nName=Mine\n").unwrap();
        std::fs::write(icon_path(&env), ICON_PNG).unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Packaged);
        assert!(desktop_path(&env).exists());
        assert!(icon_path(&env).exists());
    }

    #[test]
    fn own_data_home_listed_in_data_dirs_is_not_a_package() {
        let root = tempfile::tempdir().unwrap();
        let mut env = environment(root.path(), "/opt/ghidra-rust");
        install(&env).unwrap();
        // Listed directly and through a symlink: same device and inode.
        let alias = root.path().join("alias");
        symlink(&env.data_home, &alias).unwrap();
        env.data_dirs = vec![env.data_home.clone(), alias];
        env.executable = PathBuf::from("/moved/ghidra-rust");
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        assert!(
            std::fs::read_to_string(desktop_path(&env))
                .unwrap()
                .contains("/moved/")
        );
    }

    #[test]
    fn interrupted_writes_leave_no_lasting_temporaries() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        // A failed rename (a directory where the icon goes) cleans up.
        std::fs::create_dir_all(icon_path(&env)).unwrap();
        assert!(install(&env).is_err());
        assert_eq!(others(&icon_path(&env)), Vec::<OsString>::new());
        std::fs::remove_dir(icon_path(&env)).unwrap();
        // A crash leftover is removed once it is old; a fresh one may still
        // belong to another instance and is kept.
        let applications = env.data_home.join("applications");
        let old = applications.join(format!(".{APP_ID}.desktop.1.0.tmp"));
        let fresh = applications.join(format!(".{APP_ID}.desktop.2.0.tmp"));
        for path in [&old, &fresh] {
            std::fs::write(path, b"partial").unwrap();
        }
        File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(SystemTime::now() - 2 * STALE_TEMPORARY_AGE)
            .unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn concurrent_installs_agree() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        let results: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4).map(|_| scope.spawn(|| install(&env))).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(results.iter().all(Result::is_ok), "{results:?}");
        let expected = desktop_entry(&env.executable).unwrap();
        assert_eq!(
            std::fs::read_to_string(desktop_path(&env)).unwrap(),
            expected
        );
        assert_eq!(std::fs::read(icon_path(&env)).unwrap(), ICON_PNG);
        assert_eq!(others(&desktop_path(&env)), Vec::<OsString>::new());
        assert_eq!(others(&icon_path(&env)), Vec::<OsString>::new());
    }

    /// Undoes the string-value escape and then the Exec quoting, independently
    /// of the writer, and returns the arguments of an `Exec=` value.
    fn exec_arguments(value: &str) -> Vec<String> {
        let mut unescaped = String::new();
        let mut chars = value.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next().unwrap() {
                    '\\' => unescaped.push('\\'),
                    other => panic!("unexpected string escape \\{other}"),
                }
            } else {
                unescaped.push(c);
            }
        }
        let (mut arguments, mut current) = (Vec::new(), None::<String>);
        let mut chars = unescaped.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '"' => {
                    let mut argument = String::new();
                    loop {
                        match chars.next().expect("unterminated quote") {
                            '"' => break,
                            '\\' => argument.push(chars.next().unwrap()),
                            '%' => {
                                assert_eq!(chars.next(), Some('%'));
                                argument.push('%');
                            }
                            other => argument.push(other),
                        }
                    }
                    current.get_or_insert_default().push_str(&argument);
                }
                ' ' => arguments.extend(current.take()),
                other => current.get_or_insert_default().push(other),
            }
        }
        arguments.extend(current);
        arguments
    }

    #[test]
    fn exec_round_trips_reserved_characters_and_entries_are_signed() {
        let path = r#"/a b/"q"`$\%'x/ghidra-rust"#;
        let entry = desktop_entry(Path::new(path)).unwrap();
        let value = |key: &str| {
            entry
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .to_owned()
        };
        assert_eq!(exec_arguments(&value("Exec=")), [path, "%f"]);
        assert_eq!(value("TryExec=").replace("\\\\", "\\"), path);
        assert_eq!(desktop_entry(Path::new("/a\nb/ghidra-rust")), None);
        assert_eq!(desktop_entry(Path::new("relative/ghidra-rust")), None);
        let lines =
            |text: &str, prefix: &str| text.lines().filter(|l| l.starts_with(prefix)).count();
        assert_eq!(lines(TEMPLATE, TEMPLATE_EXEC), 1);
        assert_eq!(lines(TEMPLATE, TEMPLATE_TRY_EXEC), 1);
        assert_eq!(lines(&entry, "Exec="), 1);
        assert_eq!(lines(&entry, "TryExec="), 1);
        // The signature covers every byte after the first line.
        assert!(is_own_entry(entry.as_bytes()));
        let mut changed = entry.clone().into_bytes();
        *changed.last_mut().unwrap() = b' ';
        assert!(!is_own_entry(&changed));
        assert!(!is_own_entry(b""));
        assert!(!is_own_entry(TEMPLATE.as_bytes()));
    }
}
