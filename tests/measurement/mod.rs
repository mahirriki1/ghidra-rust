//! Linux `/proc` process-tree memory sampling shared by opt-in measurement
//! clients. Observations are sequential, non-atomic estimates.
#![allow(dead_code)]

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::time::{Duration, Instant};

pub const SAMPLE_INTERVAL: Duration = Duration::from_millis(10);
const MAX_PROCESSES: usize = 64;
// A JVM and its native helpers have far more threads than the Rust client.
const MAX_THREADS: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Memory {
    pub processes: usize,
    pub rss_kib: u64,
    pub pss_kib: u64,
}

pub struct Sampler {
    root: u32,
    pub last: Instant,
    pub samples: usize,
    pub peak_rss_kib: u64,
    pub peak_pss_kib: u64,
    pub max_processes: usize,
    /// Largest interval between consecutive samples, including collection.
    pub max_gap: Duration,
    /// Cumulative time spent reading `/proc`, which perturbs the measured work.
    pub collection: Duration,
    // Birth ticks distinguish the root's descendants from later PID reuse. We
    // never signal a sampled PID; owners terminate and reap their children.
    pub children: BTreeMap<u32, u64>,
}

/// Whether a `/proc` read failed because the process exited meanwhile.
fn exited(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

pub fn birth(pid: u32) -> Option<u64> {
    process_state(pid).map(|state| state.0)
}

fn process_state(pid: u32) -> Option<(u64, char)> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if exited(&error) => return None,
        Err(error) => panic!("Cannot inspect process {pid}: {error}"),
    };
    // comm can contain spaces and ')'; fields after the final ')' start at3.
    let mut fields = stat
        .rsplit_once(')')
        .expect("Kernel process comm")
        .1
        .split_whitespace();
    let state = fields.next().unwrap().chars().next().unwrap();
    let ticks = fields
        .nth(18)
        .unwrap()
        .parse()
        .expect("Kernel process birth ticks");
    Some((ticks, state))
}

fn process_tree(root: u32) -> Vec<u32> {
    let mut pending = VecDeque::from([root]);
    let mut processes = BTreeSet::new();
    while let Some(pid) = pending.pop_front() {
        if !processes.insert(pid) {
            continue;
        }
        assert!(
            processes.len() <= MAX_PROCESSES,
            "Unexpected process count in measured tree"
        );
        let tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(tasks) => tasks,
            Err(error) if exited(&error) => continue,
            Err(error) => panic!("Cannot enumerate measured process threads: {error}"),
        };
        // Children can be spawned from any thread, not necessarily the thread
        // group leader. Reading only /task/<pid>/children misses them.
        for (index, task) in tasks.enumerate() {
            assert!(
                index < MAX_THREADS,
                "Unexpected thread count in measured tree"
            );
            let task = match task {
                Ok(task) => task,
                Err(error) if exited(&error) => continue,
                Err(error) => panic!("Cannot enumerate measured process threads: {error}"),
            };
            let children = match fs::read_to_string(task.path().join("children")) {
                Ok(children) => children,
                Err(error) if exited(&error) => continue,
                Err(error) => panic!("Cannot enumerate measured children: {error}"),
            };
            for child in children.split_whitespace() {
                pending.push_back(child.parse().expect("Kernel child PID"));
            }
        }
    }
    processes.into_iter().collect()
}

fn kib(text: &str, key: &str) -> u64 {
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("Missing {key} memory metric"));
    let mut fields = value.split_whitespace();
    let amount = fields.next().unwrap().parse().expect("Kernel memory count");
    assert_eq!(fields.next(), Some("kB"));
    amount
}

impl Sampler {
    /// Samples `root` and all of its descendants. The root is excluded from
    /// `children`, so it may be the caller's own process.
    pub fn new(root: u32) -> Self {
        Self {
            root,
            last: Instant::now(),
            samples: 0,
            peak_rss_kib: 0,
            peak_pss_kib: 0,
            max_processes: 0,
            max_gap: Duration::ZERO,
            collection: Duration::ZERO,
            children: BTreeMap::new(),
        }
    }

    /// Sums contemporaneous RSS and PSS. An exited root yields zero processes,
    /// which does not update the observed peaks.
    pub fn sample(&mut self) -> Memory {
        let started = Instant::now();
        if self.samples > 0 {
            self.max_gap = self.max_gap.max(started - self.last);
        }
        let mut memory = Memory::default();
        for pid in process_tree(self.root) {
            let Some((start, state)) = process_state(pid) else {
                continue;
            };
            if pid != self.root {
                self.children.insert(pid, start);
            }
            if matches!(state, 'Z' | 'X') {
                continue;
            }
            let maps = match fs::read_to_string(format!("/proc/{pid}/smaps_rollup")) {
                Ok(maps) => maps,
                // A process which exited during enumeration has no resident
                // pages to attribute; a process tearing down its address space
                // reports ESRCH. Permission failures must not become zero.
                Err(error)
                    if exited(&error)
                        || process_state(pid)
                            .is_none_or(|(_, state)| matches!(state, 'Z' | 'X')) =>
                {
                    continue;
                }
                Err(error) => panic!("Cannot measure process {pid}: {error}"),
            };
            // An exiting process can briefly expose an empty rollup.
            if maps.is_empty() || birth(pid) != Some(start) {
                continue;
            }
            memory.processes += 1;
            memory.rss_kib = memory.rss_kib.checked_add(kib(&maps, "Rss:")).unwrap();
            memory.pss_kib = memory.pss_kib.checked_add(kib(&maps, "Pss:")).unwrap();
        }
        self.last = Instant::now();
        self.collection += self.last - started;
        self.samples += 1;
        self.peak_rss_kib = self.peak_rss_kib.max(memory.rss_kib);
        self.peak_pss_kib = self.peak_pss_kib.max(memory.pss_kib);
        self.max_processes = self.max_processes.max(memory.processes);
        memory
    }

    /// Whether any observed descendant is still the same live process.
    pub fn descendants_alive(&self) -> bool {
        self.children
            .iter()
            .any(|(&pid, &ticks)| birth(pid) == Some(ticks))
    }
}
