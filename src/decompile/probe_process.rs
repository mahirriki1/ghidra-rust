//! Linux probe and debug-render isolation. The worker's protocol uses stdin and stdout.
use serde::{Serialize, de::DeserializeOwned};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Instant;

const MAX_FRAME_BYTES: usize = 16 * 1024;
const BATCH_CPU_SECONDS: libc::rlim_t = 2;
const PROBE_CPU_MICROSECONDS: i64 = 250_000;

pub(super) fn single_threaded() -> bool {
    // Fail closed if procfs cannot establish that the caller is the sole
    // thread. In particular, the performance writer and libtest can hold
    // Rust/allocator locks that would never be released in a forked child.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .is_some_and(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Threads:"))
                .is_some_and(|count| count.trim() == "1")
        })
}

pub(super) fn run<T: Serialize + DeserializeOwned>(
    count: usize,
    deadline: Instant,
    probe: impl FnMut(usize) -> Option<T>,
) -> Vec<Option<T>> {
    run_with_limits(
        count,
        deadline,
        BATCH_CPU_SECONDS,
        PROBE_CPU_MICROSECONDS,
        probe,
    )
}

/// [`run`] with the child's total CPU seconds and each probe's CPU time.
pub(super) fn run_with_limits<T: Serialize + DeserializeOwned>(
    count: usize,
    deadline: Instant,
    batch_cpu_seconds: libc::rlim_t,
    probe_cpu_microseconds: i64,
    mut probe: impl FnMut(usize) -> Option<T>,
) -> Vec<Option<T>> {
    if count == 0 || Instant::now() >= deadline {
        return Vec::new();
    }
    let (Ok((parent, mut child)), Ok(null)) = (UnixStream::pair(), File::open("/dev/null")) else {
        return Vec::new();
    };
    if !single_threaded() {
        return Vec::new();
    }

    // SAFETY: procfs confirmed this is the sole thread immediately before
    // fork. No other thread can create a thread or leave a lock held in the
    // child. We never return to the caller or run inherited destructors there.
    let (parent_pid, pid) = unsafe { (libc::getpid(), libc::fork()) };
    if pid < 0 {
        return Vec::new();
    }
    if pid == 0 {
        // SAFETY: both socket endpoints and null are open and private to
        // this call. The child owns its descriptor table and resource limits.
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent_pid
                || libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) < 0
                || libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) < 0
                || libc::setrlimit(
                    libc::RLIMIT_CPU,
                    &libc::rlimit {
                        rlim_cur: batch_cpu_seconds,
                        rlim_max: batch_cpu_seconds,
                    },
                ) != 0
                || libc::signal(libc::SIGPROF, libc::SIG_DFL) == libc::SIG_ERR
            {
                libc::_exit(1);
            }
        }
        // Keep the catch around both the engine and the reply writer.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(parent);
            for i in 0..count {
                let timer = libc::itimerval {
                    it_interval: libc::timeval {
                        tv_sec: 0,
                        tv_usec: 0,
                    },
                    it_value: libc::timeval {
                        tv_sec: (probe_cpu_microseconds / 1_000_000) as libc::time_t,
                        tv_usec: (probe_cpu_microseconds % 1_000_000) as libc::suseconds_t,
                    },
                };
                // SAFETY: timer is fully initialized and copied by setitimer.
                // ITIMER_PROF counts this child's user and system CPU time.
                if unsafe { libc::setitimer(libc::ITIMER_PROF, &timer, std::ptr::null_mut()) } != 0
                {
                    return false;
                }
                let reply = probe(i);
                if serde_json::to_writer(&mut child, &reply).is_err()
                    || child.write_all(b"\n").is_err()
                {
                    return false;
                }
            }
            true
        }));
        // SAFETY: child exit bypasses inherited worker frames and all Rust
        // destructors, including the panic payload's possibly panicking Drop.
        unsafe { libc::_exit(if matches!(result, Ok(true)) { 0 } else { 1 }) }
    }

    drop(child);
    let replies = read_replies(parent, count, deadline, MAX_FRAME_BYTES);
    // SAFETY: pid denotes our unreaped child. Kill also covers timeout or
    // malformed IPC. A zombie retains its pid until waitpid succeeds.
    unsafe { stop(pid) };
    replies
}

/// Kills and reaps `pid`.
///
/// # Safety
/// `pid` must be this process's own child that has not been reaped, so it
/// cannot name a recycled process (a zombie keeps its pid until reaped).
unsafe fn stop(pid: libc::pid_t) {
    // SAFETY: the caller guarantees pid is our unreaped child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        while libc::waitpid(pid, std::ptr::null_mut(), 0) == -1
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {}
    }
}

/// One disposable copy of this process computing an optional result while
/// the caller waits. Dropping it kills and reaps the copy.
pub(crate) struct Isolated {
    pid: libc::pid_t,
    socket: UnixStream,
    max_frame: usize,
}

/// A writer that refuses to grow past its limit, so an oversized reply is
/// never fully allocated before it is rejected.
struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for Bounded {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.bytes.len() + data.len() > self.limit {
            return Err(std::io::Error::other("reply exceeds its frame limit"));
        }
        self.bytes.extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Forks a child that runs `work` once under a `cpu_seconds` CPU limit. The
/// child inherits this process's scheduling policy and priority: it never
/// runs alongside work it could slow down, because the caller starts it only
/// after its own result is complete. The child writes one reply of at most
/// `max_frame` bytes and exits. `None` when this process is not
/// single-threaded or the child cannot be started; `work` never runs in this
/// process.
pub(super) fn spawn_isolated<T: Serialize>(
    cpu_seconds: libc::rlim_t,
    max_frame: usize,
    work: impl FnOnce() -> Option<T>,
) -> Option<Isolated> {
    let (Ok((parent, mut child)), Ok(null)) = (UnixStream::pair(), File::open("/dev/null")) else {
        return None;
    };
    if !single_threaded() {
        return None;
    }
    // SAFETY: procfs confirmed this is the sole thread immediately before
    // fork. No other thread can create a thread or leave a lock held in the
    // child. The child never returns to the caller or runs inherited
    // destructors.
    let (parent_pid, pid) = unsafe { (libc::getpid(), libc::fork()) };
    if pid < 0 {
        return None;
    }
    if pid == 0 {
        // SAFETY: both socket endpoints and null are open and private to
        // this call. The child owns its descriptor table and resource limits.
        unsafe {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                || libc::getppid() != parent_pid
                || libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) < 0
                || libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) < 0
                || libc::setrlimit(
                    libc::RLIMIT_CPU,
                    &libc::rlimit {
                        rlim_cur: cpu_seconds.max(1),
                        rlim_max: cpu_seconds.max(1),
                    },
                ) != 0
                || libc::signal(libc::SIGPROF, libc::SIG_DFL) == libc::SIG_ERR
            {
                libc::_exit(1);
            }
        }
        // Keep the catch around both the work and the reply writer.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(parent);
            let mut frame = Bounded {
                bytes: Vec::new(),
                limit: max_frame.saturating_sub(1),
            };
            serde_json::to_writer(&mut frame, &work()).ok()?;
            frame.bytes.push(b'\n');
            child.write_all(&frame.bytes).ok()
        }));
        // SAFETY: child exit bypasses inherited worker frames and all Rust
        // destructors, including the panic payload's possibly panicking Drop.
        unsafe { libc::_exit(if matches!(result, Ok(Some(()))) { 0 } else { 1 }) }
    }
    drop(child);
    Some(Isolated {
        pid,
        socket: parent,
        max_frame,
    })
}

/// Why an isolated child produced no reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    /// Deadline or process exit before any frame.
    Expired,
    /// Partial, malformed or oversized frame.
    Invalid,
    /// The parent's caller asked to abandon the child first.
    Preempted,
}

/// How often a preemptible wait checks its caller.
const PREEMPT_POLL: std::time::Duration = std::time::Duration::from_millis(20);

impl Isolated {
    /// The child's reply if it arrives by `deadline`; the child is then
    /// stopped either way. A reply above the frame limit, a malformed frame
    /// or an exit without a reply is [`Stop::Expired`]. Waiting also stops,
    /// and stops the child, as soon as `preempt` returns true; it is checked
    /// about every 20 ms.
    #[allow(
        dead_code,
        reason = "generic adapter used by the standalone process harness"
    )]
    pub(crate) fn reply_preemptible<T: DeserializeOwned>(
        self,
        deadline: Instant,
        preempt: &mut dyn FnMut() -> bool,
    ) -> Result<T, Stop> {
        self.reply_checked(deadline, preempt, |_| true)
    }

    pub(crate) fn reply_checked<T: DeserializeOwned>(
        mut self,
        deadline: Instant,
        preempt: &mut dyn FnMut() -> bool,
        preflight: impl FnOnce(&[u8]) -> bool,
    ) -> Result<T, Stop> {
        let mut frame = Vec::new();
        loop {
            if preempt() {
                return Err(Stop::Preempted);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero()
                || self
                    .socket
                    .set_read_timeout(Some(left.min(PREEMPT_POLL)))
                    .is_err()
            {
                return Err(Stop::Expired);
            }
            let mut buffer = [0; 65536];
            let n = match self.socket.read(&mut buffer) {
                Ok(0) if frame.is_empty() => return Err(Stop::Expired),
                Ok(0) => return Err(Stop::Invalid),
                Ok(n) => n,
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => return Err(Stop::Invalid),
            };
            let data = &buffer[..n];
            let end = data.iter().position(|&byte| byte == b'\n');
            let take = end.map_or(n, |end| end + 1);
            if frame.len() + take > self.max_frame {
                return Err(Stop::Invalid);
            }
            frame.extend_from_slice(&data[..take]);
            if end.is_some() {
                if take < n || !preflight(&frame) {
                    return Err(Stop::Invalid);
                }
                let reply = serde_json::from_slice::<Option<T>>(&frame).ok().flatten();
                if Instant::now() >= deadline {
                    return Err(Stop::Invalid);
                }
                return reply.ok_or(Stop::Invalid);
            }
        }
    }
}

impl Drop for Isolated {
    fn drop(&mut self) {
        // SAFETY: pid is our child and only this Drop reaps it.
        unsafe { stop(self.pid) }
    }
}

fn read_replies<T: DeserializeOwned>(
    mut socket: UnixStream,
    count: usize,
    deadline: Instant,
    max_frame: usize,
) -> Vec<Option<T>> {
    let mut replies = Vec::with_capacity(count);
    let mut frame = Vec::new();
    while replies.len() < count {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            break;
        }
        let mut buffer = [0; 65536];
        let Ok(n) = socket.read(&mut buffer) else {
            break;
        };
        if n == 0 {
            break;
        }
        for fragment in buffer[..n].split_inclusive(|&byte| byte == b'\n') {
            if frame.len() + fragment.len() > max_frame {
                return replies;
            }
            frame.extend_from_slice(fragment);
            if fragment.ends_with(b"\n") {
                let Ok(reply) = serde_json::from_slice(&frame) else {
                    return replies;
                };
                replies.push(reply);
                frame.clear();
                if replies.len() == count {
                    break;
                }
            }
        }
    }
    replies
}
