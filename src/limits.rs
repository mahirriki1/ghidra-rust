//! Resource limits for the disposable analysis process, not an OS security sandbox.
//! The GUI never installs these limits on itself.

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
    Ok(())
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

/// Reset the CPU soft limit to twenty seconds beyond this process's consumption.
/// Preserve the inherited hard limit so later requests can update their budget.
#[cfg(target_os = "linux")]
pub fn begin_request() -> Result<(), String> {
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
    limits.rlim_cur = seconds.saturating_add(21).min(limits.rlim_max);
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
                            unsafe { TerminateProcess(GetCurrentProcess(), 124) };
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
pub fn begin_request() -> Result<(), String> {
    let consumed = process_cpu_ticks().ok_or_else(|| {
        format!(
            "Cannot inspect worker CPU budget: {}",
            std::io::Error::last_os_error()
        )
    })?;
    // Windows process times use 100 ns ticks. The watchdog also counts engine
    // threads' CPU, rather than allowing each thread a separate twenty seconds.
    CPU_DEADLINE.store(
        consumed.saturating_add(20 * 10_000_000),
        std::sync::atomic::Ordering::Relaxed,
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn configure_worker() -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn begin_request() -> Result<(), String> {
    Ok(())
}
