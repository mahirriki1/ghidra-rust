//! Places discovery and session-only recent directories. Candidates and probes
//! run on the chooser reader; rendering only reads the cached results.
use super::io::{EntryKind, Filesystem, MAX_PATH_UNITS, native_units};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Place {
    pub(super) label: String,
    pub(super) path: PathBuf,
}

impl Place {
    fn new(label: &str, path: PathBuf) -> Self {
        Self {
            label: label.into(),
            path,
        }
    }
}

pub(super) enum PlacesWork {
    Candidates,
    Probe(Place),
}

/// Recent directories visited in this session, newest first.
pub(super) const MAX_RECENTS: usize = 12;
#[cfg(target_os = "linux")]
const USER_DIRS_LIMIT: usize = 16 << 10;

/// Whether `path` is a directory, following one final link.
pub(super) fn probe(fs: &dyn Filesystem, path: &Path) -> bool {
    match fs.kind(path) {
        Ok(EntryKind::Directory) => true,
        Ok(EntryKind::Link) => matches!(fs.target_kind(path), Ok(EntryKind::Directory)),
        _ => false,
    }
}

fn absolute_var(fs: &dyn Filesystem, key: &str) -> Option<PathBuf> {
    fs.var(key)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute() && native_units(path.as_os_str()) <= MAX_PATH_UNITS)
}

fn home_places(home: &Path, special: [Option<PathBuf>; 3]) -> Vec<Place> {
    let mut places = vec![Place::new("Home", home.to_owned())];
    for (label, path) in ["Desktop", "Documents", "Downloads"]
        .into_iter()
        .zip(special)
    {
        if let Some(path) = path
            && !places.iter().any(|place| place.path == path)
        {
            places.push(Place::new(label, path));
        }
    }
    places
}

/// Unprobed Places candidates; `/` is always shown without a probe.
#[cfg(target_os = "linux")]
pub(super) fn candidates(fs: &dyn Filesystem) -> Vec<Place> {
    let Some(home) = absolute_var(fs, "HOME") else {
        return Vec::new();
    };
    let config = absolute_var(fs, "XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
    let settings = fs
        .read_limited(&config.join("user-dirs.dirs"), USER_DIRS_LIMIT)
        .map(|bytes| parse_user_dirs(&bytes, &home))
        .unwrap_or_default();
    let fallback = ["Desktop", "Documents", "Downloads"];
    let special = std::array::from_fn(|index| match &settings[index] {
        UserDir::Unset => Some(home.join(fallback[index])),
        UserDir::Disabled => None,
        UserDir::Path(path) => Some(path.clone()),
    });
    home_places(&home, special)
}

/// The USERPROFILE folders and local drive roots, probed one per step.
#[cfg(windows)]
pub(super) fn candidates(fs: &dyn Filesystem) -> Vec<Place> {
    let mut places = absolute_var(fs, "USERPROFILE")
        .map(|home| {
            let special = ["Desktop", "Documents", "Downloads"].map(|name| Some(home.join(name)));
            home_places(&home, special)
        })
        .unwrap_or_default();
    for drive in b'A'..=b'Z' {
        let drive = char::from(drive);
        places.push(Place {
            label: format!("{drive}:"),
            path: PathBuf::from(format!("{drive}:\\")),
        });
    }
    places
}

#[cfg(not(any(target_os = "linux", windows)))]
pub(super) fn candidates(fs: &dyn Filesystem) -> Vec<Place> {
    absolute_var(fs, "HOME")
        .map(|home| home_places(&home, [None, None, None]))
        .unwrap_or_default()
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum UserDir {
    #[default]
    Unset,
    /// Explicitly set to HOME, which turns the folder off.
    Disabled,
    Path(PathBuf),
}

/// Parse the three supported `user-dirs.dirs` assignments as literal data:
/// a quoted absolute path or `$HOME`/`${HOME}` prefix with backslash escapes.
/// Nothing is sourced or expanded; other values count as unset.
#[cfg(target_os = "linux")]
pub(super) fn parse_user_dirs(bytes: &[u8], home: &Path) -> [UserDir; 3] {
    let mut settings: [UserDir; 3] = Default::default();
    for line in bytes.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        let Some(split) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let index = match &line[..split] {
            b"XDG_DESKTOP_DIR" => 0,
            b"XDG_DOCUMENTS_DIR" => 1,
            b"XDG_DOWNLOAD_DIR" => 2,
            _ => continue,
        };
        settings[index] = user_dir(&line[split + 1..], home).unwrap_or_default();
    }
    settings
}

#[cfg(target_os = "linux")]
fn user_dir(value: &[u8], home: &Path) -> Option<UserDir> {
    use std::os::unix::ffi::OsStringExt;
    let inner = value.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    if inner.len() > MAX_PATH_UNITS {
        return None;
    }
    let (relative, rest) = if let Some(rest) = inner.strip_prefix(b"${HOME}") {
        (true, rest)
    } else if let Some(rest) = inner.strip_prefix(b"$HOME") {
        (true, rest)
    } else {
        (false, inner)
    };
    if relative && !(rest.is_empty() || rest.starts_with(b"/")) {
        return None;
    }
    let mut literal = Vec::with_capacity(rest.len());
    let mut bytes = rest.iter();
    while let Some(&byte) = bytes.next() {
        match byte {
            b'\\' => literal.push(*bytes.next()?),
            b'"' | b'`' | b'$' => return None,
            _ => literal.push(byte),
        }
    }
    let literal = PathBuf::from(std::ffi::OsString::from_vec(literal));
    let path = if relative {
        home.join(literal.strip_prefix("/").unwrap_or(&literal))
    } else if literal.is_absolute() {
        literal
    } else {
        return None;
    };
    if native_units(path.as_os_str()) > MAX_PATH_UNITS {
        return None;
    }
    Some(if path == home {
        UserDir::Disabled
    } else {
        UserDir::Path(path)
    })
}

/// Places discovery for the open dialog: one candidate step, then one probe
/// per step so demanded reads can run in between.
#[derive(Default)]
pub(super) struct Places {
    dialog: u64,
    queue: Option<VecDeque<Place>>,
    requested: bool,
    done: bool,
    fresh: Vec<Place>,
    complete: Option<Vec<Place>>,
}

impl Places {
    pub(super) fn restart(&mut self, dialog: u64) {
        self.dialog = dialog;
        self.queue = None;
        self.requested = false;
        self.done = false;
        self.fresh.clear();
    }

    pub(super) fn next(&mut self) -> Option<(u64, PlacesWork)> {
        if self.requested || self.done {
            return None;
        }
        let work = match &mut self.queue {
            None => PlacesWork::Candidates,
            Some(queue) => match queue.pop_front() {
                Some(place) => PlacesWork::Probe(place),
                None => {
                    self.finish();
                    return None;
                }
            },
        };
        self.requested = true;
        Some((self.dialog, work))
    }

    fn finish(&mut self) {
        self.done = true;
        self.complete = Some(std::mem::take(&mut self.fresh));
    }

    pub(super) fn candidates(&mut self, dialog: u64, places: Vec<Place>) {
        if dialog == self.dialog {
            self.requested = false;
            self.queue = Some(places.into());
        }
    }

    pub(super) fn probed(&mut self, dialog: u64, place: Place, directory: bool) {
        if dialog == self.dialog {
            self.requested = false;
            if directory && !self.fresh.iter().any(|known| known.path == place.path) {
                self.fresh.push(place);
            }
        }
    }

    /// Stop discovery after a reader failure rather than retrying forever.
    pub(super) fn lost(&mut self, dialog: u64) {
        if dialog == self.dialog && !self.done {
            self.finish();
        }
    }

    /// The last complete list while rediscovering, else results so far.
    pub(super) fn shown(&self) -> &[Place] {
        self.complete.as_deref().unwrap_or(&self.fresh)
    }
}

#[derive(Default)]
pub(super) struct Recents(VecDeque<PathBuf>);

impl Recents {
    /// Record a verified directory. Over-length paths are skipped rather than
    /// truncated, so every recent remains an exact native path.
    pub(super) fn record(&mut self, path: &Path) {
        if native_units(path.as_os_str()) > MAX_PATH_UNITS {
            return;
        }
        self.0.retain(|known| known != path);
        self.0.push_front(path.to_owned());
        self.0.truncate(MAX_RECENTS);
    }

    pub(super) fn remove(&mut self, path: &Path) {
        self.0.retain(|known| known != path);
    }

    pub(super) fn paths(&self) -> impl ExactSizeIterator<Item = &PathBuf> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn xdg_places_are_bounded_literal_and_existing_only() {
        use super::super::io::fake::Fake;
        let home = Path::new("/home/u");
        let parsed = parse_user_dirs(
            b"# comment\n\
              XDG_DESKTOP_DIR=\"$HOME/Schreibtisch\"\n\
              XDG_DOCUMENTS_DIR=\"$HOME\"\n\
              XDG_DOWNLOAD_DIR=\"$(rm -rf ~)\"\n\
              XDG_MUSIC_DIR=\"/music\"\n",
            home,
        );
        assert_eq!(
            parsed,
            [
                UserDir::Path("/home/u/Schreibtisch".into()),
                UserDir::Disabled,
                UserDir::Unset,
            ]
        );
        let parsed = parse_user_dirs(
            b"XDG_DESKTOP_DIR=\"${HOME}/My \\\"Desk\\\"\"\n\
              XDG_DOCUMENTS_DIR=\"/srv/docs\"\n\
              XDG_DOWNLOAD_DIR=\"`id`\"\n",
            home,
        );
        assert_eq!(
            parsed,
            [
                UserDir::Path("/home/u/My \"Desk\"".into()),
                UserDir::Path("/srv/docs".into()),
                UserDir::Unset,
            ]
        );
        for invalid in [
            &b"XDG_DESKTOP_DIR=relative/path"[..],
            b"XDG_DESKTOP_DIR=\"relative\"",
            b"XDG_DESKTOP_DIR=\"$HOMEX/a\"",
            b"XDG_DESKTOP_DIR=\"$USER/a\"",
        ] {
            assert_eq!(parse_user_dirs(invalid, home)[0], UserDir::Unset);
        }
        let mut long = b"XDG_DESKTOP_DIR=\"/".to_vec();
        long.extend(std::iter::repeat_n(b'a', MAX_PATH_UNITS));
        long.push(b'"');
        assert_eq!(parse_user_dirs(&long, home)[0], UserDir::Unset);

        // No HOME: nothing beyond the always-present root.
        assert!(candidates(&Fake::default()).is_empty());
        let fs = Fake::default();
        fs.var("HOME", "/home/u");
        fs.file(
            "/home/u/.config/user-dirs.dirs",
            b"XDG_DESKTOP_DIR=\"$HOME/Schreibtisch\"\nXDG_DOCUMENTS_DIR=\"$HOME\"\n",
        );
        let found = candidates(&fs);
        let labels: Vec<_> = found.iter().map(|place| place.label.as_str()).collect();
        assert_eq!(labels, ["Home", "Desktop", "Downloads"]);
        assert_eq!(found[1].path, Path::new("/home/u/Schreibtisch"));
        // An oversized file is ignored in favor of the defaults.
        fs.file(
            "/home/u/.config/user-dirs.dirs",
            &vec![b'#'; USER_DIRS_LIMIT + 1],
        );
        let labels: Vec<_> = candidates(&fs)
            .into_iter()
            .map(|place| place.path)
            .collect();
        assert_eq!(labels[2], Path::new("/home/u/Documents"));
        // A relative XDG_CONFIG_HOME is ignored.
        fs.var("XDG_CONFIG_HOME", "relative");
        assert_eq!(candidates(&fs).len(), 4);

        // Only confirmed directories are shown, one probe per step.
        fs.dir("/home/u", &[]);
        fs.dir("/home/u/Desktop", &[]);
        fs.set("/home/u/Documents", Ok(EntryKind::File));
        let mut places = Places::default();
        places.restart(1);
        for _ in 0..16 {
            let Some((dialog, work)) = places.next() else {
                break;
            };
            match work {
                PlacesWork::Candidates => places.candidates(dialog, candidates(&fs)),
                PlacesWork::Probe(place) => {
                    let directory = probe(&fs, &place.path);
                    places.probed(dialog, place, directory);
                }
            }
        }
        assert!(places.next().is_none());
        let shown: Vec<_> = places
            .shown()
            .iter()
            .map(|place| place.label.as_str())
            .collect();
        assert_eq!(shown, ["Home", "Desktop"]);
        // A stale dialog's results are ignored.
        places.restart(2);
        places.probed(1, Place::new("Stale", "/stale".into()), true);
        assert!(places.shown().iter().all(|place| place.label != "Stale"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_places_and_paths_obey_local_policy() {
        use super::super::io::fake::Fake;
        let fs = Fake::default();
        fs.var("USERPROFILE", r"C:\Users\u");
        let found = candidates(&fs);
        assert_eq!(found[0].path, Path::new(r"C:\Users\u"));
        assert_eq!(found[1].path, Path::new(r"C:\Users\u\Desktop"));
        let drives: Vec<_> = found
            .iter()
            .filter(|place| place.label.len() == 2)
            .map(|place| place.path.clone())
            .collect();
        assert_eq!(drives.len(), 26);
        assert_eq!(drives[2], Path::new(r"C:\"));
        // Unavailable drives are omitted by the probe.
        fs.dir(r"C:\", &[]);
        assert!(probe(&fs, Path::new(r"C:\")));
        assert!(!probe(&fs, Path::new(r"Q:\")));
        // A relative USERPROFILE is ignored.
        let fs = Fake::default();
        fs.var("USERPROFILE", r"Users\u");
        assert_eq!(candidates(&fs).len(), 26);
    }

    #[test]
    fn recents_are_session_bounded_and_skip_overlong_paths() {
        let mut recents = Recents::default();
        for index in 0..14 {
            recents.record(Path::new(&format!("/r{index}")));
        }
        assert_eq!(recents.paths().len(), MAX_RECENTS);
        assert_eq!(recents.paths().next().unwrap(), Path::new("/r13"));
        recents.record(Path::new("/r5"));
        assert_eq!(recents.paths().next().unwrap(), Path::new("/r5"));
        assert_eq!(recents.paths().len(), MAX_RECENTS);
        recents.record(&PathBuf::from(format!("/{}", "x".repeat(MAX_PATH_UNITS))));
        assert_eq!(recents.paths().next().unwrap(), Path::new("/r5"));
        recents.remove(Path::new("/r5"));
        assert!(recents.paths().all(|path| path != Path::new("/r5")));
    }
}
