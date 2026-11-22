//! Creates workers already in their own resource and lifetime job.

use super::Handle;
use std::ffi::OsStr;
use std::io::{self, PipeReader, PipeWriter};
use std::marker::PhantomData;
use std::os::windows::{ffi::OsStrExt, io::AsRawHandle, process::ExitStatusExt};
use std::path::Path;
use std::process::ExitStatus;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::{JobObjects::*, Threading::*};

pub(crate) struct WorkerProcess {
    process: Handle,
    job: Handle,
    id: u32,
    pub(crate) stdin: Option<PipeWriter>,
    pub(crate) stdout: Option<PipeReader>,
    pub(crate) stderr: Option<PipeReader>,
}

impl WorkerProcess {
    pub(crate) fn spawn<'a>(
        exe: &Path,
        arguments: impl IntoIterator<Item = &'a OsStr>,
    ) -> io::Result<Self> {
        let exe = std::path::absolute(exe)?;
        let mut command = Vec::new();
        // Windows paths cannot contain a double quote. The executable token
        // (argv[0]) has its own, simpler quoting rules.
        command.push(u16::from(b'"'));
        for unit in exe.as_os_str().encode_wide() {
            if unit == 0 || unit == u16::from(b'"') {
                return Err(io::Error::other("Invalid analysis worker path"));
            }
            command.push(unit);
        }
        command.push(u16::from(b'"'));
        let application: Vec<_> = exe.as_os_str().encode_wide().chain([0]).collect();
        for argument in arguments {
            append_argument(&mut command, argument)?;
        }
        command.push(0);

        let job = worker_job()?;
        let (worker_input, stdin) = io::pipe()?;
        let (stdout, worker_output) = io::pipe()?;
        let (stderr, worker_error) = io::pipe()?;
        let worker_input = inherit(&worker_input)?;
        let worker_output = inherit(&worker_output)?;
        let worker_error = inherit(&worker_error)?;
        let handles = [
            worker_input.as_raw_handle(),
            worker_output.as_raw_handle(),
            worker_error.as_raw_handle(),
        ];
        let jobs = [job.as_raw_handle()];
        let mut attributes = Attributes::new(&handles, &jobs)?;
        let startup = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: size_of::<STARTUPINFOEXW>() as u32,
                dwFlags: STARTF_USESTDHANDLES,
                hStdInput: handles[0],
                hStdOutput: handles[1],
                hStdError: handles[2],
                ..Default::default()
            },
            lpAttributeList: attributes.as_mut_ptr(),
        };
        let mut process = PROCESS_INFORMATION::default();
        // SAFETY: application is NUL-terminated, command is writable and
        // NUL-terminated, and both attribute arrays and their handles live
        // through the call. The new process inherits only the three listed
        // pipe ends and is in its configured job before it can run.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                null(),
                null(),
                &startup.StartupInfo,
                &mut process,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let process_handle = Handle::new(process.hProcess);
        drop(Handle::new(process.hThread));
        Ok(Self {
            process: process_handle?,
            job,
            id: process.dwProcessId,
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr: Some(stderr),
        })
    }

    pub(crate) fn id(&self) -> u32 {
        self.id
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        // SAFETY: this live private job contains at most its one worker.
        if unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        wait_for_exit(&self.process, 0)
    }

    pub(crate) fn wait(&mut self) -> io::Result<ExitStatus> {
        drop(self.stdin.take());
        wait_for_exit(&self.process, INFINITE)?
            .ok_or_else(|| io::Error::other("Infinite worker wait timed out"))
    }
}

fn wait_for_exit(process: &Handle, timeout: u32) -> io::Result<Option<ExitStatus>> {
    let process = process.as_raw_handle();
    // SAFETY: the process handle lives throughout the wait and exit-code query.
    match unsafe { WaitForSingleObject(process, timeout) } {
        WAIT_TIMEOUT => Ok(None),
        WAIT_OBJECT_0 => {
            let mut code = 0;
            // SAFETY: process has terminated and code is a writable DWORD.
            if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(ExitStatus::from_raw(code)))
        }
        _ => Err(io::Error::last_os_error()),
    }
}

fn worker_job() -> io::Result<Handle> {
    // SAFETY: null attributes and name create a private, non-inheritable job.
    let job = Handle::new(unsafe { CreateJobObjectW(null(), null()) })?;
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = 2 * 1024 * 1024 * 1024;
    // SAFETY: initialized limits structure and a live, owned job handle.
    if unsafe {
        SetInformationJobObject(
            job.as_raw_handle(),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&limits) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(job)
}

fn inherit(pipe: &impl AsRawHandle) -> io::Result<Handle> {
    // SAFETY: the pseudo-handle designates the current process.
    let process = unsafe { GetCurrentProcess() };
    let mut inherited = null_mut();
    // SAFETY: pipe is open in the current process and inherited is writable.
    // Only the duplicate is inheritable, never the original or the host end.
    if unsafe {
        DuplicateHandle(
            process,
            pipe.as_raw_handle(),
            process,
            &mut inherited,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Handle::new(inherited)
}

struct Attributes<'a> {
    storage: Vec<usize>,
    values: PhantomData<&'a [HANDLE]>,
}

impl<'a> Attributes<'a> {
    fn new(handles: &'a [HANDLE], jobs: &'a [HANDLE]) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: the null first argument requests the allocation size only.
        let result = unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut bytes) };
        let error = io::Error::last_os_error();
        if result != 0 || error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(error);
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: storage is aligned and at least the queried size.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 2, 0, &mut bytes)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = Self {
            storage,
            values: PhantomData,
        };
        for (kind, value) in [
            (PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles),
            (PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs),
        ] {
            // SAFETY: initialized list, correct length in bytes, and the
            // borrowed handle lists outlive the attribute list.
            if unsafe {
                UpdateProcThreadAttribute(
                    attributes.as_mut_ptr(),
                    0,
                    kind as usize,
                    value.as_ptr().cast(),
                    size_of_val(value),
                    null_mut(),
                    null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(attributes)
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}

impl Drop for Attributes<'_> {
    fn drop(&mut self) {
        // SAFETY: the initialized list is still backed by storage.
        unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) }
    }
}

fn append_argument(command: &mut Vec<u16>, argument: &OsStr) -> io::Result<()> {
    const QUOTE: u16 = b'"' as u16;
    const SLASH: u16 = b'\\' as u16;
    command.extend([u16::from(b' '), QUOTE]);
    let mut slashes = 0;
    for unit in argument.encode_wide() {
        match unit {
            0 => return Err(io::Error::other("Invalid analysis worker argument")),
            SLASH => {
                slashes += 1;
                continue;
            }
            QUOTE => command.extend(std::iter::repeat_n(SLASH, slashes + 1)),
            _ => {}
        }
        command.extend(std::iter::repeat_n(SLASH, slashes));
        command.push(unit);
        slashes = 0;
    }
    command.extend(std::iter::repeat_n(SLASH, 2 * slashes));
    command.push(QUOTE);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{IsTerminal, Read, Write};

    #[test]
    fn workers_have_independent_jobs_and_die_when_their_job_closes() {
        let exe = std::env::current_exe().unwrap();
        let run_child = || {
            let mut child = WorkerProcess::spawn(
                &exe,
                [
                    "--ignored",
                    "--exact",
                    "windows::worker_process::tests::job_child_waits",
                ]
                .map(OsStr::new),
            )
            .unwrap();
            child.stdin.as_mut().unwrap().write_all(b"W").unwrap();
            child
        };
        let mut first = run_child();
        let mut second = run_child();
        assert!(first.try_wait().unwrap().is_none());
        assert!(second.try_wait().unwrap().is_none());
        for (worker, other) in [(&first, &second), (&second, &first)] {
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // SAFETY: live job, writable limits structure of the given size.
            assert_ne!(
                unsafe {
                    QueryInformationJobObject(
                        worker.job.as_raw_handle(),
                        JobObjectExtendedLimitInformation,
                        (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        size_of_val(&limits) as u32,
                        null_mut(),
                    )
                },
                0
            );
            assert_eq!(limits.ProcessMemoryLimit, 2 * 1024 * 1024 * 1024);
            assert_eq!(limits.BasicLimitInformation.ActiveProcessLimit, 1);
            for (job, expected) in [(&worker.job, 1), (&other.job, 0)] {
                let mut member = 0;
                // SAFETY: both handles are live and member is writable.
                let checked = unsafe {
                    IsProcessInJob(
                        worker.process.as_raw_handle(),
                        job.as_raw_handle(),
                        &mut member,
                    )
                };
                assert_ne!(checked, 0);
                assert_eq!(member, expected);
            }
        }
        // Closing only the first job must terminate its worker independently
        // of the second job and the still-open process and stdin handles.
        std::thread::spawn(move || drop(first.job)).join().unwrap();
        assert!(wait_for_exit(&first.process, 5_000).unwrap().is_some());
        assert!(second.try_wait().unwrap().is_none());
        second.kill().unwrap();
        assert!(wait_for_exit(&second.process, 5_000).unwrap().is_some());
    }

    #[test]
    #[ignore = "Subprocess fixture for the job lifecycle test"]
    fn job_child_waits() {
        let stdin = io::stdin();
        let mut marker = [0];
        if !stdin.is_terminal() && stdin.lock().read_exact(&mut marker).is_ok() && marker == *b"W" {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}
