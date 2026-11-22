#[cfg(target_os = "linux")]
#[path = "../src/decompile/probe_process.rs"]
mod probe_process;

#[cfg(target_os = "linux")]
fn main() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    if std::env::args().nth(1).as_deref() == Some("--probe-child-test") {
        assert!(probe_process::single_threaded());
        let deadline = || Instant::now() + Duration::from_secs(3);
        let result = std::panic::catch_unwind(|| {
            probe_process::run(3, deadline(), |index| {
                if index == 0 {
                    return Some(42);
                }
                use std::io::Read;
                assert_eq!(std::io::stdin().read(&mut [0]).unwrap(), 0);
                std::io::stdout().write_all(b"child diagnostic\n").unwrap();
                std::io::stdout().flush().unwrap();
                panic!("injected engine panic");
            })
        });
        assert_eq!(result.unwrap(), vec![Some(42)]);
        let mut request = String::new();
        std::io::stdin().read_line(&mut request).unwrap();
        assert_eq!(request, "next request\n");
        println!("parent reply");

        let before = child_cpu_time();
        let timed = probe_process::run(3, deadline(), |index| {
            if index == 1 {
                loop {
                    std::hint::spin_loop();
                }
            }
            Some(index)
        });
        assert_eq!(timed, vec![Some(0)]);
        let elapsed = child_cpu_time() - before;
        assert!(
            (0.20..1.0).contains(&elapsed),
            "child consumed {elapsed}s of CPU"
        );

        // A disposable debug render: its reply arrives, it inherits this
        // process's priority, and its protocol descriptors are private.
        // SAFETY: getpriority only reads this process's nice value.
        let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
        let inherited = probe_process::spawn_isolated(2, 1024, || {
            use std::io::Read;
            assert_eq!(std::io::stdin().read(&mut [0]).unwrap(), 0);
            std::io::stdout()
                .write_all(b"isolated diagnostic\n")
                .unwrap();
            std::io::stdout().flush().unwrap();
            // SAFETY: as above.
            Some(unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) })
        })
        .unwrap();
        assert_eq!(
            inherited
                .reply_preemptible::<i32>(deadline(), &mut || false)
                .ok(),
            Some(nice)
        );
        assert_no_children();
        // An expired child yields nothing by its deadline and is reaped.
        let started = Instant::now();
        let spinning = probe_process::spawn_isolated(5, 1024, || -> Option<u32> {
            loop {
                std::hint::spin_loop();
            }
        })
        .unwrap();
        assert_eq!(
            spinning
                .reply_preemptible::<u32>(started + Duration::from_millis(400), &mut || false)
                .ok(),
            None
        );
        let elapsed = started.elapsed();
        assert!(
            (Duration::from_millis(350)..Duration::from_secs(3)).contains(&elapsed),
            "{elapsed:?}"
        );
        assert_no_children();
        // Its own CPU limit stops a spinning child well before the deadline.
        let started = Instant::now();
        let limited = probe_process::spawn_isolated(1, 1024, || -> Option<u32> {
            loop {
                std::hint::spin_loop();
            }
        })
        .unwrap();
        assert_eq!(
            limited
                .reply_preemptible::<u32>(started + Duration::from_secs(8), &mut || false)
                .ok(),
            None
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_no_children();
        // A reply above the frame limit is never read; nor is a malformed
        // one, or none at all.
        let large = probe_process::spawn_isolated(2, 64, || Some("x".repeat(100))).unwrap();
        assert_eq!(
            large
                .reply_preemptible::<String>(deadline(), &mut || false)
                .ok(),
            None
        );
        let malformed = probe_process::spawn_isolated(2, 64, || Some("text")).unwrap();
        assert_eq!(
            malformed
                .reply_preemptible::<u32>(deadline(), &mut || false)
                .ok(),
            None
        );
        let silent = probe_process::spawn_isolated(2, 64, || -> Option<u32> {
            // SAFETY: exits the disposable child without a reply.
            unsafe { libc::_exit(0) }
        })
        .unwrap();
        assert_eq!(
            silent
                .reply_preemptible::<u32>(deadline(), &mut || false)
                .ok(),
            None
        );
        let nothing = probe_process::spawn_isolated(2, 64, || -> Option<u32> { None }).unwrap();
        assert_eq!(
            nothing
                .reply_preemptible::<u32>(deadline(), &mut || false)
                .ok(),
            None
        );
        assert_no_children();
        // Newer host input abandons a stalled child at once, as preemption
        // (never as expiry), and the child is reaped.
        let stalled = probe_process::spawn_isolated(5, 64, || -> Option<u32> {
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        })
        .unwrap();
        let started = Instant::now();
        let mut polls = 0;
        let preempted =
            stalled.reply_preemptible::<u32>(started + Duration::from_secs(8), &mut || {
                polls += 1;
                started.elapsed() > Duration::from_millis(150)
            });
        assert_eq!(preempted, Err(probe_process::Stop::Preempted));
        assert!(polls > 1, "the caller is consulted while waiting");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_no_children();

        std::thread::scope(|scope| {
            let thread = scope.spawn(std::thread::park);
            let single_threaded = probe_process::single_threaded();
            let replies = probe_process::run::<u32>(1, deadline(), |_| Some(1));
            let isolated = probe_process::spawn_isolated(1, 64, || Some(1)).is_none();
            thread.thread().unpark();
            assert!(!single_threaded);
            assert!(replies.is_empty());
            assert!(isolated, "a multithreaded process never forks");
        });
        return;
    }

    let mut process = Command::new(std::env::current_exe().unwrap())
        .arg("--probe-child-test")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    process
        .stdin
        .take()
        .unwrap()
        .write_all(b"next request\n")
        .unwrap();
    let output = process.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"parent reply\n");
    assert!(String::from_utf8_lossy(&output.stderr).contains("injected engine panic"));
}

/// Every child this process started has been reaped.
#[cfg(target_os = "linux")]
fn assert_no_children() {
    // SAFETY: a nonblocking wait for any child; no status is requested.
    let reaped = unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(reaped, -1, "an unreaped child remains");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[cfg(target_os = "linux")]
fn child_cpu_time() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: usage is writable storage for one rusage. The call initializes
    // it on success. The probe runner has already reaped its child.
    let usage = unsafe {
        assert_eq!(
            libc::getrusage(libc::RUSAGE_CHILDREN, usage.as_mut_ptr()),
            0
        );
        usage.assume_init()
    };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1_000_000.0;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

#[cfg(not(target_os = "linux"))]
fn main() {}
