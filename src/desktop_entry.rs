//! Linux desktop integration. Wayland compositors such as KDE Plasma ignore
//! icons that a window sets itself; they look up the window's app id in a
//! `.desktop` entry. On each desktop start this writes, in the user's own XDG
//! data directory only:
//!
//! - `applications/io.github.mahirriki1.GhidraRust.desktop`, whose `Exec=`
//!   names the running executable, and
//! - `icons/hicolor/256x256/apps/io.github.mahirriki1.GhidraRust.png`.
//!
//! Files are rewritten only when their content differs. Directories below the
//! data directory must be real directories owned by the user; symlinks are not
//! followed. Every write goes to a new temporary file that atomically replaces
//! the old one. Failures are ignored: the desktop works without the entry.
use crate::brand::{APP_ID, ICON_PNG};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// The packaged entry. Self-registration substitutes its `Exec=` and
/// `TryExec=` lines; the tarball ships it unchanged under `share/`.
const TEMPLATE: &str = include_str!("../packaging/linux/io.github.mahirriki1.GhidraRust.desktop");
const TEMPLATE_EXEC: &str = "Exec=ghidra-rust %f";
const TEMPLATE_TRY_EXEC: &str = "TryExec=ghidra-rust";
const ICON_DIRECTORY: [&str; 4] = ["icons", "hicolor", "256x256", "apps"];

/// What a registration attempt did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both files were already current.
    Unchanged,
    /// At least one file was created or replaced.
    Written,
    /// A system data directory already provides the entry, e.g. a distro
    /// package. The user-level copy would shadow it, so nothing was written.
    Packaged,
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
    /// them cannot be determined.
    pub fn from_process() -> Option<Self> {
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

/// `$XDG_DATA_DIRS`, defaulting to `/usr/local/share:/usr/share`.
pub fn data_dirs(value: Option<OsString>) -> Vec<PathBuf> {
    let value = value.filter(|value| !value.is_empty());
    let value = value
        .as_deref()
        .unwrap_or(OsStr::new("/usr/local/share:/usr/share"));
    std::env::split_paths(value)
        .filter(|path| path.is_absolute())
        .collect()
}

/// The desktop entry for `executable`, or `None` when the path is not UTF-8
/// or contains control characters that an entry cannot carry.
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
    let mut entry = String::from(
        "# Written by Ghidra Rust when the desktop starts.\n\
         # Delete this file and the icon it names to remove it.\n",
    );
    for line in TEMPLATE.lines() {
        entry.push_str(match line {
            TEMPLATE_EXEC => &exec,
            TEMPLATE_TRY_EXEC => &try_exec,
            line => line,
        });
        entry.push('\n');
    }
    Some(entry)
}

/// Writes or refreshes the user's entry and icon for `environment`.
pub fn install(environment: &Environment) -> io::Result<Outcome> {
    let desktop_name = format!("{APP_ID}.desktop");
    let own_home = std::fs::canonicalize(&environment.data_home).ok();
    let packaged = environment.data_dirs.iter().any(|directory| {
        std::fs::canonicalize(directory).ok() != own_home
            && directory.join("applications").join(&desktop_name).is_file()
    });
    if packaged {
        return Ok(Outcome::Packaged);
    }
    let entry = desktop_entry(&environment.executable).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "unsupported executable path")
    })?;
    // The data directory itself is the user's choice and may be a symlink.
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&environment.data_home)?;
    let root = Directory::open(&environment.data_home)?;
    let mut icons = root.child("icons")?;
    for name in &ICON_DIRECTORY[1..] {
        icons = icons.child(name)?;
    }
    // Write the icon first so the entry never names a missing icon.
    let icon = icons.replace_if_changed(&format!("{APP_ID}.png"), ICON_PNG)?;
    let applications = root.child("applications")?;
    let desktop = applications.replace_if_changed(&desktop_name, entry.as_bytes())?;
    Ok(if icon || desktop {
        Outcome::Written
    } else {
        Outcome::Unchanged
    })
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
        let name = c_string(OsStr::new(name))?;
        // SAFETY: the parent descriptor is open for `self`'s lifetime and
        // `name` is a live NUL-terminated single component.
        if unsafe { libc::mkdirat(self.0.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
        // SAFETY: as above; O_NOFOLLOW makes a symlinked component fail, and
        // a non-negative result is a new descriptor owned by the wrapper.
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
        // SAFETY: geteuid has no preconditions and cannot fail.
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "directory is owned by another user",
            ));
        }
        Ok(directory)
    }

    /// Replaces `name` with `content` unless it already holds exactly that.
    /// Returns whether it wrote. An existing symlink is replaced, not followed.
    fn replace_if_changed(&self, name: &str, content: &[u8]) -> io::Result<bool> {
        if self.read_matches(name, content) {
            return Ok(false);
        }
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
        result.map(|()| true)
    }

    /// Whether `name` is a regular file holding exactly `content`. Reads at
    /// most one byte more than `content`, and never blocks on a FIFO.
    fn read_matches(&self, name: &str, content: &[u8]) -> bool {
        let Ok(name) = c_string(OsStr::new(name)) else {
            return false;
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
            return false;
        }
        // SAFETY: `fd` was just opened above and has no other owner.
        let file = unsafe { File::from_raw_fd(fd) };
        if !file
            .metadata()
            .is_ok_and(|m| m.is_file() && m.len() == content.len() as u64)
        {
            return false;
        }
        let mut existing = Vec::with_capacity(content.len() + 1);
        file.take(content.len() as u64 + 1)
            .read_to_end(&mut existing)
            .is_ok_and(|_| existing == content)
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
        // Nothing but the two files is left behind.
        let leftovers = std::fs::read_dir(env.data_home.join("applications"))
            .unwrap()
            .count();
        assert_eq!(leftovers, 1);
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
        assert_eq!(
            data_dirs(None),
            [
                PathBuf::from("/usr/local/share"),
                PathBuf::from("/usr/share")
            ]
        );
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
    fn replaces_a_symlinked_entry_without_writing_through_it() {
        let root = tempfile::tempdir().unwrap();
        let env = environment(root.path(), "/opt/ghidra-rust");
        let victim = root.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        std::fs::create_dir_all(env.data_home.join("applications")).unwrap();
        symlink(&victim, desktop_path(&env)).unwrap();
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        assert!(
            std::fs::symlink_metadata(desktop_path(&env))
                .unwrap()
                .is_file()
        );
    }

    #[test]
    fn unwritable_data_home_fails_without_writing() {
        // SAFETY: geteuid has no preconditions. Root ignores permissions.
        if unsafe { libc::geteuid() } == 0 {
            return;
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
    fn packaged_entry_wins_unless_it_is_our_own() {
        let root = tempfile::tempdir().unwrap();
        let mut env = environment(root.path(), "/opt/ghidra-rust");
        install(&env).unwrap();
        // The user's own data home listed in XDG_DATA_DIRS is not a package.
        env.data_dirs.push(env.data_home.clone());
        env.executable = PathBuf::from("/moved/ghidra-rust");
        assert_eq!(install(&env).unwrap(), Outcome::Written);
        let system = root.path().join("system/applications");
        std::fs::create_dir_all(&system).unwrap();
        std::fs::write(system.join(format!("{APP_ID}.desktop")), b"packaged").unwrap();
        env.executable = PathBuf::from("/again/ghidra-rust");
        assert_eq!(install(&env).unwrap(), Outcome::Packaged);
        assert!(
            std::fs::read_to_string(desktop_path(&env))
                .unwrap()
                .contains("/moved/")
        );
    }

    #[test]
    fn exec_quotes_reserved_characters() {
        let entry = desktop_entry(Path::new(r#"/a b/"q"`$\%/ghidra-rust"#)).unwrap();
        assert!(
            entry.contains(r#"Exec="/a b/\\"q\\"\\`\\$\\\\%%/ghidra-rust" %f"#),
            "{entry}"
        );
        assert!(
            entry.contains(r#"TryExec=/a b/"q"`$\\%/ghidra-rust"#),
            "{entry}"
        );
        assert_eq!(desktop_entry(Path::new("/a\nb/ghidra-rust")), None);
        assert_eq!(desktop_entry(Path::new("relative/ghidra-rust")), None);
        let exec_lines =
            |text: &str, prefix: &str| text.lines().filter(|l| l.starts_with(prefix)).count();
        assert_eq!(exec_lines(TEMPLATE, TEMPLATE_EXEC), 1);
        assert_eq!(exec_lines(TEMPLATE, TEMPLATE_TRY_EXEC), 1);
        assert_eq!(exec_lines(&entry, "Exec="), 1);
        assert_eq!(exec_lines(&entry, "TryExec="), 1);
    }
}
