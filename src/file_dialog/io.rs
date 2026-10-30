//! Bounded chooser filesystem work. One shared reader slot runs every listing,
//! candidate inspection and Places probe off the GUI thread.
use super::places::{self, Place, PlacesWork};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::SystemTime;

/// Directory results yielded per listing, not counting the truncation probe.
pub(super) const MAX_ENTRIES: usize = 4096;
/// Aggregate native-path, label and search-key bytes retained per listing.
pub(super) const MAX_PAYLOAD: usize = 16 << 20;
/// Native path units (Unix bytes, Windows UTF-16 units) of an actionable path.
pub(super) const MAX_PATH_UNITS: usize = 4096;
/// Characters accepted by the path and file-name editors.
pub(super) const MAX_EDIT_CHARS: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EntryKind {
    Directory,
    File,
    Link,
    Other,
    Unknown,
}

pub(super) struct Entry {
    pub(super) path: PathBuf,
    pub(super) name: OsString,
    pub(super) kind: EntryKind,
    pub(super) label: String,
    pub(super) key: String,
    pub(super) size: Option<u64>,
    pub(super) modified: Option<SystemTime>,
    pub(super) size_text: String,
    pub(super) modified_text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Partial {
    /// More than [`MAX_ENTRIES`] results.
    Truncated,
    /// Over-length paths were skipped or the payload budget was reached.
    Budget,
    /// Enumeration failed after some results.
    Failed,
}

pub(super) struct Listing {
    pub(super) directory: PathBuf,
    pub(super) entries: Vec<Entry>,
    pub(super) partial: Option<Partial>,
}

/// One enumerated name with its non-following type and metadata.
pub(super) struct RawEntry {
    pub(super) name: OsString,
    pub(super) kind: Option<EntryKind>,
    pub(super) size: Option<u64>,
    pub(super) modified: Option<SystemTime>,
}

pub(super) type RawEntries = Box<dyn Iterator<Item = io::Result<RawEntry>>>;

/// The chooser's only filesystem and environment access. Every method runs
/// on the reader thread; tests substitute deterministic implementations.
pub(super) trait Filesystem: Send + Sync + 'static {
    fn read_dir(&self, path: &Path) -> io::Result<RawEntries>;
    /// The kind of `path` itself, without following a final link.
    fn kind(&self, path: &Path) -> io::Result<EntryKind>;
    /// The kind of a link's target.
    fn target_kind(&self, path: &Path) -> io::Result<EntryKind>;
    #[cfg(target_os = "linux")]
    fn read_limited(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>>;
    fn var(&self, key: &str) -> Option<OsString>;
}

pub(super) struct NativeFilesystem;

fn kind_of(file_type: std::fs::FileType) -> EntryKind {
    if file_type.is_symlink() {
        EntryKind::Link
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_file() {
        EntryKind::File
    } else {
        EntryKind::Other
    }
}

impl Filesystem for NativeFilesystem {
    fn read_dir(&self, path: &Path) -> io::Result<RawEntries> {
        #[cfg(windows)]
        {
            // A local-looking path can traverse a junction to a share.
            crate::windows::validate_local_path(path)?;
            crate::windows::validate_local_path(&std::fs::canonicalize(path)?)?;
        }
        Ok(Box::new(std::fs::read_dir(path)?.map(|entry| {
            entry.map(|entry| {
                // DirEntry metadata does not follow a final link.
                let metadata = entry.metadata().ok();
                let kind = entry.file_type().ok().map(kind_of);
                RawEntry {
                    name: entry.file_name(),
                    size: metadata
                        .as_ref()
                        .filter(|metadata| metadata.is_file())
                        .map(std::fs::Metadata::len),
                    modified: metadata.and_then(|metadata| metadata.modified().ok()),
                    kind,
                }
            })
        })))
    }

    fn kind(&self, path: &Path) -> io::Result<EntryKind> {
        #[cfg(windows)]
        crate::windows::validate_local_path(path)?;
        std::fs::symlink_metadata(path).map(|metadata| kind_of(metadata.file_type()))
    }

    fn target_kind(&self, path: &Path) -> io::Result<EntryKind> {
        #[cfg(windows)]
        crate::windows::validate_local_path(&std::fs::canonicalize(path)?)?;
        std::fs::metadata(path).map(|metadata| kind_of(metadata.file_type()))
    }

    #[cfg(target_os = "linux")]
    fn read_limited(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(io::Error::other("file too large"));
        }
        Ok(bytes)
    }

    fn var(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }
}

pub(super) fn native_units(value: &OsStr) -> usize {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().count()
    }
    #[cfg(not(windows))]
    {
        value.as_encoded_bytes().len()
    }
}

/// A display-only label: lossy UTF-8 with controls, line separators and bidi
/// overrides shown as escapes. Never convert a label back into a path.
pub(super) fn display(value: &OsStr) -> String {
    let lossy = value.to_string_lossy();
    let mut label = String::with_capacity(lossy.len());
    for character in lossy.chars() {
        if character.is_control()
            || matches!(
                character,
                '\u{061c}'
                    | '\u{200e}'
                    | '\u{200f}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2066}'..='\u{2069}'
            )
        {
            let _ = write!(label, "\\u{{{:x}}}", u32::from(character));
        } else {
            label.push(character);
        }
    }
    label
}

pub(super) fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if value < 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.0} {}", UNITS[unit])
    }
}

/// A compact relative age; future times carry a leading `+`.
pub(super) fn age_text(modified: SystemTime, now: SystemTime) -> String {
    let (age, sign) = match now.duration_since(modified) {
        Ok(age) => (age, ""),
        Err(error) => (error.duration(), "+"),
    };
    let seconds = age.as_secs();
    match seconds {
        0..60 if sign.is_empty() => "now".into(),
        0..60 => format!("+{seconds} s"),
        60..3600 => format!("{sign}{} min", seconds / 60),
        3600..86_400 => format!("{sign}{} h", seconds / 3600),
        86_400..31_536_000 => format!("{sign}{} d", seconds / 86_400),
        _ => format!("{sign}{} y", seconds / 31_536_000),
    }
}

/// Exact modification time for a tooltip, without calendar conversion.
pub(super) fn unix_text(modified: SystemTime) -> String {
    match modified.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(after) => format!("Unix {} UTC", after.as_secs()),
        Err(before) => format!("Unix -{} UTC", before.duration().as_secs()),
    }
}

/// Collect at most [`MAX_ENTRIES`] results plus one truncation probe. Errors,
/// budgets and over-length paths stop or skip safely and mark the listing
/// partial; a canceled read returns `None`.
pub(super) fn collect_listing(
    directory: PathBuf,
    results: impl Iterator<Item = io::Result<RawEntry>>,
    now: SystemTime,
    canceled: &dyn Fn() -> bool,
) -> Option<Listing> {
    let mut entries = Vec::new();
    let mut partial = None;
    let mut payload = 0usize;
    for (attempt, result) in results.enumerate() {
        if canceled() {
            return None;
        }
        if attempt == MAX_ENTRIES {
            partial = Some(Partial::Truncated);
            break;
        }
        let Ok(raw) = result else {
            partial = Some(Partial::Failed);
            break;
        };
        let path = directory.join(&raw.name);
        let units = native_units(path.as_os_str());
        if units > MAX_PATH_UNITS {
            partial = Some(Partial::Budget);
            continue;
        }
        let label = display(&raw.name);
        let key = label.to_lowercase();
        let cost = units
            .saturating_add(raw.name.len())
            .saturating_add(label.len())
            .saturating_add(key.len());
        if payload.saturating_add(cost) > MAX_PAYLOAD {
            partial = Some(Partial::Budget);
            break;
        }
        payload += cost;
        let kind = raw.kind.unwrap_or(EntryKind::Unknown);
        let size = raw.size.filter(|_| kind != EntryKind::Directory);
        entries.push(Entry {
            path,
            kind,
            label,
            key,
            size,
            modified: raw.modified,
            size_text: size.map(size_text).unwrap_or_default(),
            modified_text: raw
                .modified
                .map(|modified| age_text(modified, now))
                .unwrap_or_default(),
            name: raw.name,
        });
    }
    Some(Listing {
        directory,
        entries,
        partial,
    })
}

/// A proposed open/save target and the default extension to try after the
/// raw name has been classified.
#[derive(Clone, Debug)]
pub(super) struct Candidate {
    pub(super) path: PathBuf,
    pub(super) extension: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Directory(PathBuf),
    /// Anything present that is not a directory, including dangling links.
    Existing(PathBuf),
    Missing(PathBuf),
    Failed(String),
}

/// `None` means absent. Permission and loop errors stay errors.
fn classify(fs: &dyn Filesystem, path: &Path) -> io::Result<Option<EntryKind>> {
    match fs.kind(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
        Ok(EntryKind::Link) => match fs.target_kind(path) {
            Ok(EntryKind::Directory) => Ok(Some(EntryKind::Directory)),
            // A dangling link is never a safely absent target.
            Ok(_) => Ok(Some(EntryKind::Link)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Some(EntryKind::Link)),
            Err(error) => Err(error),
        },
        Ok(kind) => Ok(Some(kind)),
    }
}

/// Classify the raw name before adding a default extension, so a folder named
/// like the target navigates instead of becoming `name.ext`.
pub(super) fn inspect(fs: &dyn Filesystem, candidate: Candidate) -> Verdict {
    let verdict = |path: PathBuf, kind: io::Result<Option<EntryKind>>| match kind {
        Ok(Some(EntryKind::Directory)) => Verdict::Directory(path),
        Ok(Some(_)) => Verdict::Existing(path),
        Ok(None) => Verdict::Missing(path),
        Err(error) => Verdict::Failed(error.to_string()),
    };
    let raw = classify(fs, &candidate.path);
    match (&raw, candidate.extension) {
        (Ok(Some(EntryKind::Directory)) | Err(_), _) => verdict(candidate.path, raw),
        (_, Some(extension)) if candidate.path.extension().is_none() => {
            let path = candidate.path.with_extension(extension);
            let kind = classify(fs, &path);
            verdict(path, kind)
        }
        _ => verdict(candidate.path, raw),
    }
}

pub(super) enum Work {
    Read(PathBuf),
    Inspect(Candidate),
    Places(PlacesWork),
}

pub(super) enum Outcome {
    Listing(Result<Listing, String>),
    Inspected(Verdict),
    Candidates(Vec<Place>),
    Probed(Place, bool),
    /// Superseded before completion.
    Canceled,
    /// The reader could not start or exited without replying.
    Lost(String),
}

pub(super) struct Reply {
    pub(super) dialog: u64,
    pub(super) token: u64,
    /// An optional Places step rather than demanded work.
    pub(super) optional: bool,
    pub(super) outcome: Outcome,
}

struct Job {
    dialog: u64,
    token: u64,
    work: Work,
}

struct Running {
    dialog: u64,
    token: u64,
    optional: bool,
    receiver: Receiver<Outcome>,
}

/// Releases the shared reader slot when the reader's filesystem work ends.
pub(super) struct DirectoryPermit(pub(super) Arc<AtomicBool>);

impl Drop for DirectoryPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) type Spawner = fn(Box<dyn FnOnce() + Send>) -> io::Result<()>;

pub(super) fn spawn_thread(task: Box<dyn FnOnce() + Send>) -> io::Result<()> {
    std::thread::Builder::new()
        .name("file-chooser-io".into())
        .spawn(task)
        .map(drop)
}

/// One running job and one replaceable demanded job. Optional Places steps
/// run only when nothing is demanded. A blocked syscall keeps the slot; no
/// second reader is ever started to work around it.
pub(super) struct Scheduler {
    fs: Arc<dyn Filesystem>,
    busy: Arc<AtomicBool>,
    latest: Arc<AtomicU64>,
    next_token: u64,
    pending: Option<Job>,
    running: Option<Running>,
    failed: Option<Reply>,
    spawn: Spawner,
}

impl Scheduler {
    pub(super) fn new(fs: Arc<dyn Filesystem>, busy: Arc<AtomicBool>, spawn: Spawner) -> Self {
        Self {
            fs,
            busy,
            latest: Arc::new(AtomicU64::new(0)),
            next_token: 0,
            pending: None,
            running: None,
            failed: None,
            spawn,
        }
    }

    pub(super) fn native() -> Self {
        Self::new(
            Arc::new(NativeFilesystem),
            Arc::new(AtomicBool::new(false)),
            spawn_thread,
        )
    }

    fn token(&mut self) -> u64 {
        self.next_token += 1;
        self.next_token
    }

    /// Replace any pending demand. A running demanded read stops at its next
    /// cooperative check; a syscall already blocked in the OS cannot.
    pub(super) fn demand(&mut self, dialog: u64, work: Work) -> u64 {
        let token = self.token();
        self.latest.store(token, Ordering::Release);
        self.pending = Some(Job {
            dialog,
            token,
            work,
        });
        token
    }

    /// Drop all demanded work, as on cancel or completion.
    pub(super) fn cancel(&mut self) {
        self.pending = None;
        let token = self.token();
        self.latest.store(token, Ordering::Release);
    }

    pub(super) fn running(&self) -> bool {
        self.running.is_some()
    }

    pub(super) fn idle(&self) -> bool {
        self.running.is_none() && self.pending.is_none() && self.failed.is_none()
    }

    pub(super) fn poll(&mut self) -> Option<Reply> {
        if let Some(reply) = self.failed.take() {
            return Some(reply);
        }
        let running = self.running.as_ref()?;
        let outcome = match running.receiver.try_recv() {
            Ok(outcome) => outcome,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Outcome::Lost("Reader stopped".into()),
        };
        let running = self.running.take()?;
        Some(Reply {
            dialog: running.dialog,
            token: running.token,
            optional: running.optional,
            outcome,
        })
    }

    /// Block until the running job replies, for deterministic tests.
    #[cfg(test)]
    pub(super) fn wait(&mut self, timeout: std::time::Duration) -> Option<Reply> {
        if let Some(reply) = self.failed.take() {
            return Some(reply);
        }
        let running = self.running.as_ref()?;
        let outcome = match running.receiver.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => return None,
            Err(mpsc::RecvTimeoutError::Disconnected) => Outcome::Lost("Reader stopped".into()),
        };
        let running = self.running.take()?;
        Some(Reply {
            dialog: running.dialog,
            token: running.token,
            optional: running.optional,
            outcome,
        })
    }

    /// Start the pending demand, or else `optional`, if the shared slot is
    /// free. The permit is taken before spawning; spawn failure releases it.
    pub(super) fn start(&mut self, optional: impl FnOnce() -> Option<(u64, PlacesWork)>) {
        if self.running.is_some() || self.failed.is_some() {
            return;
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let permit = DirectoryPermit(self.busy.clone());
        let job = match self.pending.take() {
            Some(job) => job,
            None => match optional() {
                Some((dialog, work)) => {
                    let token = self.token();
                    Job {
                        dialog,
                        token,
                        work: Work::Places(work),
                    }
                }
                None => return,
            },
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let (dialog, token) = (job.dialog, job.token);
        let optional = matches!(job.work, Work::Places(_));
        let fs = self.fs.clone();
        let latest = self.latest.clone();
        let task = Box::new(move || {
            let outcome = run(&*fs, job.work, &|| latest.load(Ordering::Acquire) != token);
            drop(permit);
            let _ = sender.send(outcome);
        });
        match (self.spawn)(task) {
            Ok(()) => {
                self.running = Some(Running {
                    dialog,
                    token,
                    optional,
                    receiver,
                })
            }
            Err(error) => {
                self.failed = Some(Reply {
                    dialog,
                    token,
                    optional,
                    outcome: Outcome::Lost(format!("Cannot start reader: {error}")),
                })
            }
        }
    }
}

fn run(fs: &dyn Filesystem, work: Work, canceled: &dyn Fn() -> bool) -> Outcome {
    match work {
        Work::Read(path) => {
            if canceled() {
                return Outcome::Canceled;
            }
            let results = match fs.read_dir(&path) {
                Ok(results) => results,
                Err(error) => return Outcome::Listing(Err(error.to_string())),
            };
            match collect_listing(path, results, SystemTime::now(), canceled) {
                Some(listing) => Outcome::Listing(Ok(listing)),
                None => Outcome::Canceled,
            }
        }
        Work::Inspect(candidate) => {
            if canceled() {
                return Outcome::Canceled;
            }
            Outcome::Inspected(inspect(fs, candidate))
        }
        Work::Places(PlacesWork::Candidates) => Outcome::Candidates(places::candidates(fs)),
        Work::Places(PlacesWork::Probe(place)) => {
            let directory = places::probe(fs, &place.path);
            Outcome::Probed(place, directory)
        }
    }
}

/// A deterministic in-memory filesystem whose reads can be held open.
#[cfg(test)]
pub(super) mod fake {
    use super::{EntryKind, Filesystem, RawEntries, RawEntry};
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::{self, Receiver, Sender};

    type Kind = Result<EntryKind, io::ErrorKind>;
    /// Reports that a held read started, and waits for its release.
    type Gate = (Sender<()>, Receiver<()>);

    #[derive(Default)]
    pub(in crate::file_dialog) struct Fake {
        dirs: Mutex<HashMap<PathBuf, Vec<(OsString, EntryKind)>>>,
        kinds: Mutex<HashMap<PathBuf, Kind>>,
        targets: Mutex<HashMap<PathBuf, Kind>>,
        gates: Mutex<HashMap<PathBuf, Gate>>,
        #[cfg(target_os = "linux")]
        files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        vars: Mutex<HashMap<String, OsString>>,
        active: AtomicUsize,
        pub(in crate::file_dialog) peak: AtomicUsize,
        pub(in crate::file_dialog) reads: AtomicUsize,
        pub(in crate::file_dialog) calls: AtomicUsize,
        read_paths: Mutex<Vec<PathBuf>>,
    }

    impl Fake {
        pub(in crate::file_dialog) fn dir(&self, path: &str, entries: &[(&str, EntryKind)]) {
            let path = PathBuf::from(path);
            let mut kinds = self.kinds.lock().unwrap();
            for (name, kind) in entries {
                kinds.insert(path.join(name), Ok(*kind));
            }
            kinds.insert(path.clone(), Ok(EntryKind::Directory));
            self.dirs.lock().unwrap().insert(
                path,
                entries
                    .iter()
                    .map(|(name, kind)| (OsString::from(name), *kind))
                    .collect(),
            );
        }

        pub(in crate::file_dialog) fn set(&self, path: &str, kind: Kind) {
            self.kinds.lock().unwrap().insert(path.into(), kind);
        }

        pub(in crate::file_dialog) fn target(&self, path: &str, kind: Kind) {
            self.targets.lock().unwrap().insert(path.into(), kind);
        }

        #[cfg(target_os = "linux")]
        pub(in crate::file_dialog) fn file(&self, path: &str, bytes: &[u8]) {
            self.files
                .lock()
                .unwrap()
                .insert(path.into(), bytes.to_vec());
        }

        pub(in crate::file_dialog) fn var(&self, key: &str, value: &str) {
            self.vars.lock().unwrap().insert(key.into(), value.into());
        }

        /// Hold the next read of `path` until the returned sender sends or
        /// drops. The receiver reports that the read has started.
        pub(in crate::file_dialog) fn gate(&self, path: &str) -> (Sender<()>, Receiver<()>) {
            let (release, wait) = mpsc::channel();
            let (entered, started) = mpsc::channel();
            self.gates
                .lock()
                .unwrap()
                .insert(path.into(), (entered, wait));
            (release, started)
        }

        pub(in crate::file_dialog) fn read_paths(&self) -> Vec<PathBuf> {
            self.read_paths.lock().unwrap().clone()
        }

        fn enter(&self) -> Guard<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(active, Ordering::SeqCst);
            Guard(self)
        }
    }

    struct Guard<'a>(&'a Fake);

    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.active.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl Filesystem for Fake {
        fn read_dir(&self, path: &Path) -> io::Result<RawEntries> {
            let _guard = self.enter();
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.read_paths.lock().unwrap().push(path.to_owned());
            let gate = self.gates.lock().unwrap().remove(path);
            if let Some((entered, wait)) = gate {
                let _ = entered.send(());
                let _ = wait.recv();
            }
            if let Some(Err(error)) = self.kinds.lock().unwrap().get(path) {
                return Err((*error).into());
            }
            let entries = self
                .dirs
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or(io::ErrorKind::NotFound)?;
            Ok(Box::new(entries.into_iter().map(|(name, kind)| {
                Ok(RawEntry {
                    name,
                    size: (kind == EntryKind::File).then_some(1),
                    modified: None,
                    kind: Some(kind),
                })
            })))
        }

        fn kind(&self, path: &Path) -> io::Result<EntryKind> {
            let _guard = self.enter();
            match self.kinds.lock().unwrap().get(path) {
                Some(kind) => kind.map_err(io::Error::from),
                None => Err(io::ErrorKind::NotFound.into()),
            }
        }

        fn target_kind(&self, path: &Path) -> io::Result<EntryKind> {
            let _guard = self.enter();
            match self.targets.lock().unwrap().get(path) {
                Some(kind) => kind.map_err(io::Error::from),
                None => Err(io::ErrorKind::NotFound.into()),
            }
        }

        #[cfg(target_os = "linux")]
        fn read_limited(&self, path: &Path, limit: usize) -> io::Result<Vec<u8>> {
            let _guard = self.enter();
            let bytes = self
                .files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or(io::ErrorKind::NotFound)?;
            if bytes.len() > limit {
                return Err(io::Error::other("file too large"));
            }
            Ok(bytes)
        }

        fn var(&self, key: &str) -> Option<OsString> {
            self.vars.lock().unwrap().get(key).cloned()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;

    fn raw(name: &str, kind: Option<EntryKind>) -> io::Result<RawEntry> {
        Ok(RawEntry {
            name: name.into(),
            kind,
            size: Some(7),
            modified: None,
        })
    }

    #[test]
    fn listing_caps_attempts_and_payload_and_survives_metadata_failures() {
        let now = SystemTime::now();
        let never = || false;
        // At most 4,096 yielded results plus one probe for truncation.
        let consumed = std::cell::Cell::new(0);
        let many = (0..10_000).map(|index| {
            consumed.set(consumed.get() + 1);
            raw(&format!("f{index}"), Some(EntryKind::File))
        });
        let listing = collect_listing("/d".into(), many, now, &never).unwrap();
        assert_eq!(listing.entries.len(), MAX_ENTRIES);
        assert_eq!(listing.partial, Some(Partial::Truncated));
        assert_eq!(consumed.get(), MAX_ENTRIES + 1);
        let exact = (0..MAX_ENTRIES).map(|index| raw(&format!("f{index}"), None));
        let listing = collect_listing("/d".into(), exact, now, &never).unwrap();
        assert_eq!(listing.partial, None);

        // An iterator error keeps earlier entries and stops enumeration.
        let consumed = std::cell::Cell::new(0);
        let failing = (0..100).map(|index| {
            consumed.set(consumed.get() + 1);
            if index == 3 {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                raw(&format!("f{index}"), Some(EntryKind::File))
            }
        });
        let listing = collect_listing("/d".into(), failing, now, &never).unwrap();
        assert_eq!(listing.entries.len(), 3);
        assert_eq!(listing.partial, Some(Partial::Failed));
        assert_eq!(consumed.get(), 4);

        // Missing type or metadata leaves a usable entry with blank fields.
        let unknown = [Ok(RawEntry {
            name: "mystery".into(),
            kind: None,
            size: None,
            modified: None,
        })];
        let listing = collect_listing("/d".into(), unknown.into_iter(), now, &never).unwrap();
        let entry = &listing.entries[0];
        assert_eq!(entry.kind, EntryKind::Unknown);
        assert_eq!(entry.path, Path::new("/d/mystery"));
        assert!(entry.size_text.is_empty() && entry.modified_text.is_empty());
        // Folder sizes are blank even when the platform reports one.
        let folder = [raw("sub", Some(EntryKind::Directory))];
        let listing = collect_listing("/d".into(), folder.into_iter(), now, &never).unwrap();
        assert_eq!(listing.entries[0].size, None);

        // Over-length paths are skipped, never shortened into another path.
        let deep = PathBuf::from(format!("/{}", "d".repeat(MAX_PATH_UNITS - 4)));
        let names = [raw("ok", None), raw("much-too-long", None)];
        let listing = collect_listing(deep.clone(), names.into_iter(), now, &never).unwrap();
        assert_eq!(listing.entries.len(), 1);
        assert_eq!(listing.entries[0].path, deep.join("ok"));
        assert_eq!(listing.partial, Some(Partial::Budget));

        // The aggregate payload budget stops long listings early.
        let long = PathBuf::from(format!("/{}", "p".repeat(3500)));
        let consumed = std::cell::Cell::new(0);
        let heavy = (0..MAX_ENTRIES).map(|index| {
            consumed.set(consumed.get() + 1);
            raw(&format!("{index:0>250}"), Some(EntryKind::File))
        });
        let listing = collect_listing(long, heavy, now, &never).unwrap();
        assert_eq!(listing.partial, Some(Partial::Budget));
        assert!(listing.entries.len() < MAX_ENTRIES);
        assert_eq!(consumed.get(), listing.entries.len() + 1);

        // A superseded read stops between results.
        let calls = std::cell::Cell::new(0);
        let canceled = || {
            calls.set(calls.get() + 1);
            calls.get() > 2
        };
        let names = (0..100).map(|index| raw(&format!("f{index}"), None));
        assert!(collect_listing("/d".into(), names, now, &canceled).is_none());
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn labels_escape_controls_and_bidi_without_changing_paths() {
        assert_eq!(
            display(OsStr::new("a\nb\u{202e}c\u{2028}")),
            "a\\u{a}b\\u{202e}c\\u{2028}"
        );
        assert_eq!(display(OsStr::new(" spaced ")), " spaced ");
        assert_eq!(size_text(1023), "1023 B");
        assert_eq!(size_text(1536), "1.5 KiB");
        assert_eq!(size_text(50 << 20), "50 MiB");
        let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        let ago = |seconds| now - std::time::Duration::from_secs(seconds);
        assert_eq!(age_text(ago(5), now), "now");
        assert_eq!(age_text(ago(120), now), "2 min");
        assert_eq!(age_text(ago(3 * 3600), now), "3 h");
        assert_eq!(age_text(ago(5 * 86_400), now), "5 d");
        assert_eq!(
            age_text(now + std::time::Duration::from_secs(180), now),
            "+3 min"
        );
        assert_eq!(unix_text(now), "Unix 1000000 UTC");
    }

    #[test]
    fn inspection_classifies_before_the_default_extension() {
        let fs = Fake::default();
        fs.dir("/d", &[("report", EntryKind::Directory)]);
        fs.dir("/d/other.grproj", &[]);
        fs.set("/d/kept.grproj", Ok(EntryKind::File));
        fs.set("/d/denied", Err(io::ErrorKind::PermissionDenied));
        fs.set("/d/dangling", Ok(EntryKind::Link));
        fs.set("/d/linked", Ok(EntryKind::Link));
        fs.target("/d/linked", Ok(EntryKind::Directory));
        let project = |name: &str| {
            inspect(
                &fs,
                Candidate {
                    path: Path::new("/d").join(name),
                    extension: Some("grproj"),
                },
            )
        };
        assert_eq!(project("report"), Verdict::Directory("/d/report".into()));
        assert_eq!(
            project("other"),
            Verdict::Directory("/d/other.grproj".into())
        );
        assert_eq!(project("kept"), Verdict::Existing("/d/kept.grproj".into()));
        assert_eq!(project("new"), Verdict::Missing("/d/new.grproj".into()));
        // An explicit extension is never rewritten.
        assert_eq!(
            project("notes.txt"),
            Verdict::Missing("/d/notes.txt".into())
        );
        assert!(matches!(project("denied"), Verdict::Failed(_)));
        // A dangling link is present, not a safely absent target.
        let plain = |name: &str| {
            inspect(
                &fs,
                Candidate {
                    path: Path::new("/d").join(name),
                    extension: None,
                },
            )
        };
        assert_eq!(plain("dangling"), Verdict::Existing("/d/dangling".into()));
        assert_eq!(plain("linked"), Verdict::Directory("/d/linked".into()));
        assert_eq!(plain("notes"), Verdict::Missing("/d/notes".into()));
    }
}
