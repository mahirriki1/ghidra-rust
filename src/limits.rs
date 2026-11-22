//! Resource limits for the disposable analysis process, not an OS security sandbox.
//! The GUI never installs these limits on itself.

/// Reset the CPU soft limit to twenty-one seconds beyond this process's
/// consumption, for one worker request. Debug-prototype work never extends
/// it: it runs only in a disposable child with its own limit.
#[cfg(any(target_os = "linux", windows))]
pub fn begin_request() -> Result<(), String> {
    set_request_allowance(21)
}

#[cfg(target_os = "linux")]
pub fn configure_worker() -> Result<(), String> {
    set_limit(libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024)?;
    set_limit(libc::RLIMIT_CORE, 0)?;
    // SAFETY: prctl is called with the documented integer-only arguments for
    // PR_SET_NO_NEW_PRIVS; no pointers or borrowed Rust data cross this call.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "Cannot restrict worker privileges: {}",
            std::io::Error::last_os_error()
        ));
    }
    exit_on_cpu_limit()?;
    exit_on_crash()
}

/// Exit status of a worker that exhausted its per-request CPU budget
/// (128 + SIGXCPU, as a shell reports the signal).
pub const CPU_LIMIT_EXIT: i32 = 128 + 24;

/// Fatal signals a Linux worker exits on with `128 + signal` instead of
/// dumping core; see [`crash_signal`].
#[cfg(target_os = "linux")]
const CRASH_SIGNALS: [(libc::c_int, &str); 5] = [
    (libc::SIGABRT, "SIGABRT"),
    (libc::SIGSEGV, "SIGSEGV"),
    (libc::SIGBUS, "SIGBUS"),
    (libc::SIGILL, "SIGILL"),
    (libc::SIGFPE, "SIGFPE"),
];

/// Exit code the Windows CPU watchdog terminates its worker with.
#[cfg(windows)]
pub const WATCHDOG_EXIT: u32 = 124;

/// Whether a worker that exited with `status` was stopped at its
/// per-request CPU limit on this platform: on Linux the SIGXCPU handler's
/// [`CPU_LIMIT_EXIT`] or the signal itself, on Windows the watchdog's
/// [`WATCHDOG_EXIT`]. Other exits are ordinary process loss.
pub fn cpu_limit_stop(status: &std::process::ExitStatus) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;
        status.code() == Some(CPU_LIMIT_EXIT) || status.signal() == Some(libc::SIGXCPU)
    }
    #[cfg(windows)]
    {
        // Windows reports the 32-bit exit code reinterpreted as an i32.
        status.code() == Some(WATCHDOG_EXIT as i32)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = status;
        false
    }
}

/// The fatal signal a Linux worker that exited with `status` crashed on:
/// the crash handler's `128 + signal` exit, or death by the signal itself
/// (a second fault inside the handler, or a process without it). Never the
/// CPU limit; `None` on other platforms.
pub fn crash_signal(status: &std::process::ExitStatus) -> Option<&'static str> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::ExitStatusExt;
        let signal = status
            .code()
            .and_then(|code| code.checked_sub(128))
            .or_else(|| status.signal())?;
        CRASH_SIGNALS
            .iter()
            .find(|&&(known, _)| known == signal)
            .map(|&(_, name)| name)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = status;
        None
    }
}

/// Installs `handler` for `signal` with `flags` and an empty mask.
#[cfg(target_os = "linux")]
fn install_handler(
    signal: libc::c_int,
    handler: extern "C" fn(libc::c_int),
    flags: libc::c_int,
) -> std::io::Result<()> {
    // SAFETY: action is zero-initialised and then fully set up before use;
    // sigemptyset receives valid storage, and sigaction copies the struct and
    // retains no pointer to it. Every handler passed here only calls _exit.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as libc::sighandler_t;
        action.sa_flags = flags;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(signal, &action, std::ptr::null_mut()) != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// A crash (abort, invalid access, illegal instruction or arithmetic
/// fault) would otherwise dump core: with a piped `core_pattern` the kernel
/// hands it to the desktop's crash reporter even with RLIMIT_CORE at zero,
/// so every faulting worker raised a "crash" notification. Exit with
/// `128 + signal` instead; the client reports it as a crash. Forked probe
/// and debug children inherit the handlers.
///
/// The handler only calls `_exit`, which is async-signal-safe and touches
/// no Rust, allocator or engine state, so it is sound from any interrupted
/// context. `SA_RESETHAND` restores the default action on entry, so a
/// second fault inside the handler ends the process normally rather than
/// looping; `SA_ONSTACK` runs it on the thread's alternate signal stack
/// where Rust installed one, so a stack overflow still reaches it.
#[cfg(target_os = "linux")]
fn exit_on_crash() -> Result<(), String> {
    extern "C" fn on_crash(signal: libc::c_int) {
        // SAFETY: _exit is async-signal-safe and touches no Rust state.
        unsafe { libc::_exit(signal.wrapping_add(128)) }
    }
    for (signal, name) in CRASH_SIGNALS {
        install_handler(signal, on_crash, libc::SA_RESETHAND | libc::SA_ONSTACK)
            .map_err(|error| format!("Cannot install worker {name} handler: {error}"))?;
    }
    Ok(())
}

/// SIGXCPU's default action dumps core. Even with RLIMIT_CORE at zero the
/// kernel still hands the crash to the desktop's core handler, so each budget
/// stop surfaced as a "crash" notification. Exit with a distinct status
/// instead; the client reports it as a CPU limit.
#[cfg(target_os = "linux")]
fn exit_on_cpu_limit() -> Result<(), String> {
    extern "C" fn on_cpu_limit(_: libc::c_int) {
        // SAFETY: _exit is async-signal-safe and touches no Rust state.
        unsafe { libc::_exit(CPU_LIMIT_EXIT) }
    }
    install_handler(libc::SIGXCPU, on_cpu_limit, 0)
        .map_err(|error| format!("Cannot install worker CPU-limit handler: {error}"))
}

#[cfg(target_os = "linux")]
fn set_limit(resource: libc::__rlimit_resource_t, ceiling: libc::rlim_t) -> Result<(), String> {
    let mut existing = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: existing is writable storage for exactly one libc::rlimit.
    if unsafe { libc::getrlimit(resource, existing.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: getrlimit returned success and initialized the entire structure.
    let existing = unsafe { existing.assume_init() };
    let ceiling = ceiling.min(existing.rlim_max);
    let limits = libc::rlimit {
        rlim_cur: ceiling,
        rlim_max: ceiling,
    };
    // SAFETY: limits is a valid initialized rlimit and setrlimit retains no pointer.
    if unsafe { libc::setrlimit(resource, &limits) } != 0 {
        return Err(format!(
            "Cannot set worker resource limit: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Reset the CPU soft limit to `allowance` seconds beyond this process's
/// consumption. Preserve the inherited hard limit so later requests can update
/// their budget.
#[cfg(target_os = "linux")]
fn set_request_allowance(allowance: u64) -> Result<(), String> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: both pointers designate writable storage for their declared types.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0
        || unsafe { libc::getrlimit(libc::RLIMIT_CPU, limits.as_mut_ptr()) } != 0
    {
        return Err(format!(
            "Cannot inspect worker CPU budget: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: both calls returned success and initialized their output structures.
    let usage = unsafe { usage.assume_init() };
    // SAFETY: getrlimit above returned success.
    let mut limits = unsafe { limits.assume_init() };
    let seconds = usage.ru_utime.tv_sec.max(0) as u64 + usage.ru_stime.tv_sec.max(0) as u64;
    limits.rlim_cur = seconds.saturating_add(allowance).min(limits.rlim_max);
    // SAFETY: limits is initialized and only read for the duration of the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &limits) } != 0 {
        return Err(format!(
            "Cannot set worker CPU budget: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn configure_worker() -> Result<(), String> {
    use windows_sys::Win32::System::{JobObjects::IsProcessInJob, Threading::GetCurrentProcess};
    let mut contained = 0;
    // SAFETY: GetCurrentProcess returns a pseudo-handle valid for this process;
    // contained is writable BOOL storage. A null job queries any membership.
    if unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut contained) } == 0 {
        return Err(format!(
            "Cannot inspect worker job: {}",
            std::io::Error::last_os_error()
        ));
    }
    if contained == 0 {
        return Err("Windows analysis worker must be launched in a resource-limited job".into());
    }
    // The parent establishes job memory and process-count limits before resuming
    // this process. CPU time is sampled here so every request gets a fresh budget.
    static WATCHDOG: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    WATCHDOG
        .get_or_init(|| {
            std::thread::Builder::new()
                .name("analysis-cpu-budget".into())
                .spawn(|| {
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        let limit = CPU_DEADLINE.load(std::sync::atomic::Ordering::Relaxed);
                        if limit != u64::MAX
                            && process_cpu_ticks().is_none_or(|ticks| ticks > limit)
                        {
                            use windows_sys::Win32::System::Threading::TerminateProcess;
                            // SAFETY: terminating only this disposable worker through
                            // its current-process pseudo-handle. No Rust cleanup is
                            // required; the parent treats the closed pipe as failure.
                            unsafe { TerminateProcess(GetCurrentProcess(), WATCHDOG_EXIT) };
                            std::process::abort();
                        }
                    }
                })
                .map(|_| ())
                .map_err(|error| format!("Cannot start CPU budget watchdog: {error}"))
        })
        .clone()
}

#[cfg(windows)]
static CPU_DEADLINE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);

#[cfg(windows)]
fn process_cpu_ticks() -> Option<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: four distinct FILETIME outputs are writable and the process handle
    // is the documented current-process pseudo-handle.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return None;
    }
    let ticks =
        |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
    Some(ticks(kernel).saturating_add(ticks(user)))
}

#[cfg(windows)]
fn set_request_allowance(allowance: u64) -> Result<(), String> {
    let consumed = process_cpu_ticks().ok_or_else(|| {
        format!(
            "Cannot inspect worker CPU budget: {}",
            std::io::Error::last_os_error()
        )
    })?;
    // Windows process times use 100 ns ticks. The watchdog also counts engine
    // threads' CPU, rather than allowing each thread a separate twenty seconds.
    // The original Windows request allowance was twenty seconds.
    let allowance = allowance.min(20);
    CPU_DEADLINE.store(
        consumed.saturating_add(allowance.saturating_mul(10_000_000)),
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(())
}

/// CPU time this process may still use before its soft `RLIMIT_CPU`
/// (the current request's allowance) stops it. `None` when unknown.
#[cfg(target_os = "linux")]
pub fn cpu_headroom() -> Option<std::time::Duration> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    // SAFETY: both pointers designate writable storage for their declared
    // types; the calls retain no pointer.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0
        || unsafe { libc::getrlimit(libc::RLIMIT_CPU, limits.as_mut_ptr()) } != 0
    {
        return None;
    }
    // SAFETY: both calls returned success and initialized their outputs.
    let (usage, limits) = unsafe { (usage.assume_init(), limits.assume_init()) };
    if limits.rlim_cur == libc::RLIM_INFINITY {
        return Some(std::time::Duration::MAX);
    }
    let time = |t: libc::timeval| {
        std::time::Duration::new(t.tv_sec.max(0) as u64, 0)
            + std::time::Duration::from_micros(t.tv_usec.clamp(0, 999_999) as u64)
    };
    // The kernel signals SIGXCPU when whole seconds of use reach the soft
    // limit.
    std::time::Duration::from_secs(limits.rlim_cur)
        .checked_sub(time(usage.ru_utime) + time(usage.ru_stime))
}

/// Unknown here: callers publish without optional work.
#[cfg(not(target_os = "linux"))]
pub fn cpu_headroom() -> Option<std::time::Duration> {
    None
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn configure_worker() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn begin_request() -> Result<(), String> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn exhausting_the_cpu_budget_exits_cleanly_instead_of_dumping_core() {
        // SAFETY: the child only makes raw syscalls (sigaction, setrlimit) and
        // spins until the kernel stops it; it never returns into the harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            if super::exit_on_cpu_limit().is_err() {
                // SAFETY: async-signal-safe exit in the forked child.
                unsafe { libc::_exit(1) }
            }
            let limits = libc::rlimit {
                rlim_cur: 1,
                rlim_max: 10,
            };
            // SAFETY: limits is initialised and only read by the call.
            unsafe { libc::setrlimit(libc::RLIMIT_CPU, &limits) };
            let mut spin = 0u64;
            loop {
                spin = std::hint::black_box(spin.wrapping_add(1));
            }
        }
        let mut status = 0;
        // SAFETY: child is our own child pid and status is writable.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(
            !libc::WIFSIGNALED(status),
            "worker died by signal {}",
            libc::WTERMSIG(status)
        );
        assert_eq!(libc::WEXITSTATUS(status), super::CPU_LIMIT_EXIT);
    }

    /// Runs `fault` in a forked child with the crash handlers and returns
    /// its raw wait status.
    fn crash_child(fault: fn()) -> libc::c_int {
        // SAFETY: the child only installs handlers and faults; it never
        // returns into the harness.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            if super::exit_on_crash().is_err() {
                // SAFETY: async-signal-safe exit in the forked child.
                unsafe { libc::_exit(1) }
            }
            fault();
            // SAFETY: as above; reached only if the fault did not fire.
            unsafe { libc::_exit(2) }
        }
        let mut status = 0;
        // SAFETY: child is our own child pid and status is writable.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        status
    }

    #[test]
    fn a_crashing_worker_exits_cleanly_instead_of_dumping_core() {
        use std::os::unix::process::ExitStatusExt;
        let faults: [(fn(), libc::c_int); 3] = [
            (|| std::process::abort(), libc::SIGABRT),
            (
                || {
                    // SAFETY: the forked child raises the fault itself;
                    // the handler exits before raise returns.
                    unsafe { libc::raise(libc::SIGSEGV) };
                },
                libc::SIGSEGV,
            ),
            (
                || {
                    // SAFETY: as above.
                    unsafe { libc::raise(libc::SIGFPE) };
                },
                libc::SIGFPE,
            ),
        ];
        for (fault, signal) in faults {
            let status = crash_child(fault);
            assert!(
                !libc::WIFSIGNALED(status),
                "worker died by signal {}",
                libc::WTERMSIG(status)
            );
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 128 + signal);
            let status = std::process::ExitStatus::from_raw(status);
            assert!(super::crash_signal(&status).is_some());
            assert!(!super::cpu_limit_stop(&status));
        }
        assert_eq!(
            libc::WEXITSTATUS(crash_child(|| std::process::abort())),
            134
        );
    }

    #[test]
    fn crash_exits_are_classified_apart_from_the_cpu_limit() {
        use std::os::unix::process::ExitStatusExt;
        let exited = |code: i32| std::process::ExitStatus::from_raw(code << 8);
        let killed = std::process::ExitStatus::from_raw;
        assert_eq!(super::crash_signal(&exited(134)), Some("SIGABRT"));
        assert_eq!(super::crash_signal(&exited(139)), Some("SIGSEGV"));
        assert_eq!(super::crash_signal(&exited(135)), Some("SIGBUS"));
        assert_eq!(super::crash_signal(&exited(132)), Some("SIGILL"));
        assert_eq!(super::crash_signal(&exited(136)), Some("SIGFPE"));
        // A second fault inside the handler dies by the signal itself.
        assert_eq!(super::crash_signal(&killed(libc::SIGSEGV)), Some("SIGSEGV"));
        // The CPU limit, ordinary exits and a host kill are not crashes.
        for status in [
            exited(super::CPU_LIMIT_EXIT),
            killed(libc::SIGXCPU),
            exited(0),
            exited(1),
            exited(124),
            killed(libc::SIGKILL),
        ] {
            assert_eq!(super::crash_signal(&status), None, "{status}");
        }
    }
}
