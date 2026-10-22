//! Opt-in developer telemetry. No binary contents or names enter these records.
//! Files are created exclusively; existing files can never be overwritten.
#[cfg(feature = "performance")]
mod enabled {
    use std::cell::{Cell, RefCell};
    use std::io::{BufWriter, Write};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
    use std::sync::{Mutex, OnceLock, RwLock};
    use std::time::{Duration, Instant};

    const MAX_RECORDS: u64 = 100_000;
    const MAX_EVENTS: u64 = MAX_RECORDS - 2;
    struct Trace {
        sender: SyncSender<Message>,
        dropped: AtomicU64,
        attempted: AtomicU64,
        origin: Instant,
        accepting: RwLock<bool>,
        writer: Mutex<Option<std::thread::JoinHandle<()>>>,
    }
    enum Message {
        Record(Record),
        Flush(Record, SyncSender<bool>),
    }
    #[derive(serde::Serialize)]
    struct Record {
        pid: u32,
        request: u64,
        peer: u64,
        phase: &'static str,
        start_us: u64,
        elapsed_us: u64,
        value: u64,
        dropped: u64,
        panicking: bool,
    }
    static TRACE: OnceLock<Option<Trace>> = OnceLock::new();
    thread_local! {
        static REQUEST: Cell<u64> = const { Cell::new(0) };
        static PEER: Cell<u64> = const { Cell::new(0) };
        static NAVIGATION: RefCell<Option<Navigation>> = const { RefCell::new(None) };
    }

    pub fn init() -> Result<(), String> {
        // The Linux worker's cleared environment deliberately does not expose
        // the host output directory. Containment is unchanged.
        let Some(directory) = std::env::var_os("GHIDRA_RUST_PERF_DIR") else {
            return Ok(());
        };
        if TRACE.get().is_some() {
            return Ok(());
        }
        let file = tempfile::Builder::new()
            .prefix(&format!("trace-{}-", std::process::id()))
            .suffix(".jsonl")
            .tempfile_in(directory)
            .map_err(|e| format!("Cannot create performance trace: {e}"))?;
        let (started, ready) = sync_channel(1);
        let (sender, receiver) = sync_channel::<Message>(1024);
        let writer = std::thread::Builder::new()
            .name("performance-trace".into())
            .spawn(move || {
                // The temporary file still removes itself if thread creation
                // fails. Persist only inside the successfully started writer.
                let (file, _) = match file.keep() {
                    Ok(file) => file,
                    Err(error) => {
                        let _ = started.send(Err(error.to_string()));
                        return;
                    }
                };
                let mut file = BufWriter::with_capacity(64 * 1024, file);
                if started.send(Ok(())).is_err() {
                    return;
                }
                for message in receiver {
                    match message {
                        Message::Record(record) => {
                            let checkpoint = record.phase == "request_published"
                                || record.phase == "navigation_frame_submission";
                            if serde_json::to_writer(&mut file, &record).is_err()
                                || file.write_all(b"\n").is_err()
                                || checkpoint && file.flush().is_err()
                            {
                                break;
                            }
                        }
                        Message::Flush(summary, done) => {
                            let ok = serde_json::to_writer(&mut file, &summary).is_ok()
                                && file.write_all(b"\n").is_ok()
                                && file.flush().is_ok();
                            let _ = done.try_send(ok);
                            break;
                        }
                    }
                }
            })
            .map_err(|e| format!("Cannot start performance trace: {e}"))?;
        ready
            .recv_timeout(Duration::from_secs(2))
            .map_err(|e| format!("Performance writer startup: {e}"))??;
        let _ = TRACE.set(Some(Trace {
            sender,
            dropped: AtomicU64::new(0),
            attempted: AtomicU64::new(0),
            origin: Instant::now(),
            accepting: RwLock::new(true),
            writer: Mutex::new(Some(writer)),
        }));
        event("trace_started", 0);
        Ok(())
    }

    pub struct Peer(u64);
    pub fn peer(pid: u64) -> Peer {
        Peer(PEER.replace(pid))
    }
    impl Drop for Peer {
        fn drop(&mut self) {
            PEER.set(self.0);
        }
    }
    struct Navigation {
        selection: u64,
        code: Option<Span>,
        listed: bool,
    }
    pub struct Context(u64);
    pub fn context(request: u64) -> Context {
        Context(REQUEST.replace(request))
    }
    impl Drop for Context {
        fn drop(&mut self) {
            REQUEST.set(self.0);
        }
    }
    pub struct Span {
        phase: &'static str,
        request: u64,
        started: Option<Instant>,
    }
    pub fn span(phase: &'static str) -> Span {
        Span {
            phase,
            request: REQUEST.get(),
            started: TRACE.get().and_then(Option::as_ref).map(|_| Instant::now()),
        }
    }
    impl Span {
        pub fn finish(self, value: u64) {
            if let Some(started) = self.started {
                emit(self.phase, self.request, started, value, None);
            }
            std::mem::forget(self);
        }
    }
    impl Drop for Span {
        fn drop(&mut self) {
            if let Some(started) = self.started {
                emit(self.phase, self.request, started, 0, None);
            }
        }
    }
    fn emit(
        phase: &'static str,
        request: u64,
        started: Instant,
        value: u64,
        elapsed: Option<Duration>,
    ) {
        let Some(Some(trace)) = TRACE.get() else {
            return;
        };
        // Concurrent readers do not wait on the GUI thread. The exclusive
        // shutdown lock drains all admitted producers before health is taken.
        let Ok(accepting) = trace.accepting.try_read() else {
            return;
        };
        if !*accepting {
            return;
        }
        let attempt = trace.attempted.fetch_add(1, Ordering::Relaxed);
        if attempt >= MAX_EVENTS {
            trace.dropped.fetch_add(1, Ordering::Relaxed);
            if attempt > MAX_EVENTS {
                return;
            }
        }
        let record = Record {
            pid: std::process::id(),
            request,
            peer: PEER.get(),
            phase: if attempt == MAX_EVENTS {
                "trace_limit_reached"
            } else {
                phase
            },
            start_us: started.saturating_duration_since(trace.origin).as_micros() as u64,
            elapsed_us: elapsed.unwrap_or_else(|| started.elapsed()).as_micros() as u64,
            value,
            dropped: trace.dropped.load(Ordering::Relaxed),
            panicking: std::thread::panicking(),
        };
        if matches!(
            trace.sender.try_send(Message::Record(record)),
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_))
        ) {
            trace.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub struct Accumulator {
        span: Span,
        elapsed: Duration,
        count: u64,
    }
    impl Accumulator {
        pub fn new(phase: &'static str) -> Self {
            Self {
                span: span(phase),
                elapsed: Duration::ZERO,
                count: 0,
            }
        }
        pub fn measure<T>(&mut self, work: impl FnOnce() -> T) -> T {
            let start = self.span.started.map(|_| Instant::now());
            let result = work();
            if let Some(start) = start {
                self.elapsed += start.elapsed();
            }
            self.count += 1;
            result
        }
    }
    impl Drop for Accumulator {
        fn drop(&mut self) {
            if let Some(started) = self.span.started.take() {
                emit(
                    self.span.phase,
                    self.span.request,
                    started,
                    self.count,
                    Some(self.elapsed),
                );
            }
        }
    }
    /// Only call after the desktop/worker event loop has stopped. A killed
    /// worker may leave a truncated last record; consumers must report this.
    pub fn flush() -> Result<(), String> {
        NAVIGATION.with_borrow_mut(|navigation| {
            if let Some(nav) = navigation.take() {
                event("navigation_shutdown", nav.selection);
                if let Some(span) = nav.code {
                    span.finish(0);
                }
            }
        });
        let Some(Some(trace)) = TRACE.get() else {
            return Ok(());
        };
        let mut accepting = trace.accepting.write().unwrap_or_else(|e| e.into_inner());
        if !*accepting {
            return Err("Performance trace already closed".into());
        }
        *accepting = false;
        drop(accepting);
        let (done, receiver) = sync_channel(1);
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut message = Message::Flush(
            Record {
                pid: std::process::id(),
                request: 0,
                peer: 0,
                phase: "trace_health",
                start_us: trace.origin.elapsed().as_micros() as u64,
                elapsed_us: 0,
                value: trace.attempted.load(Ordering::Relaxed),
                dropped: trace.dropped.load(Ordering::Relaxed),
                panicking: false,
            },
            done,
        );
        loop {
            match trace.sender.try_send(message) {
                Ok(()) => break,
                Err(TrySendError::Full(returned)) if Instant::now() < deadline => {
                    message = returned;
                    std::thread::yield_now();
                }
                _ => return Err("Performance trace could not flush".into()),
            }
        }
        if let Ok(written) =
            receiver.recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            if let Some(writer) = trace
                .writer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                writer
                    .join()
                    .map_err(|_| "Performance trace writer panicked")?;
            }
            if written {
                Ok(())
            } else {
                Err("Performance trace writer failed".into())
            }
        } else {
            Err("Performance trace writer failed or timed out".into())
        }
    }
    pub fn navigation_begin(selection: u64) {
        NAVIGATION.with_borrow_mut(|navigation| {
            if let Some(nav) = navigation.take() {
                let _context = context(nav.selection);
                event("navigation_superseded", nav.selection);
                if let Some(span) = nav.code {
                    span.finish(0);
                }
            }
            let _context = context(selection);
            event("navigation_begin", selection);
            *navigation = Some(Navigation {
                selection,
                code: Some(span("navigation_frame_submission")),
                listed: false,
            });
        });
    }
    pub fn navigation_frame(selection: u64, listing: bool, code: bool) {
        NAVIGATION.with_borrow_mut(|navigation| {
            let Some(nav) = navigation.as_mut().filter(|nav| nav.selection == selection) else {
                return;
            };
            let _context = context(selection);
            if listing && !nav.listed {
                event("listing_frame_submission", selection);
                nav.listed = true;
            }
            if code && let Some(span) = nav.code.take() {
                span.finish(1);
            }
            if nav.listed && nav.code.is_none() {
                *navigation = None;
            }
        });
    }
    pub fn event(phase: &'static str, value: u64) {
        emit(phase, REQUEST.get(), Instant::now(), value, None);
    }
}

#[cfg(feature = "performance")]
pub use enabled::*;

#[cfg(not(feature = "performance"))]
mod disabled {
    pub fn init() -> Result<(), String> {
        Ok(())
    }
    pub struct Peer;
    pub fn peer(_: u64) -> Peer {
        Peer
    }
    pub struct Context;
    pub fn context(_: u64) -> Context {
        Context
    }
    pub struct Span;
    pub fn span(_: &'static str) -> Span {
        Span
    }
    impl Span {
        pub fn finish(self, _: u64) {}
    }
    pub fn event(_: &'static str, _: u64) {}
    pub struct Accumulator;
    impl Accumulator {
        pub fn new(_: &'static str) -> Self {
            Self
        }
        pub fn measure<T>(&mut self, work: impl FnOnce() -> T) -> T {
            work()
        }
    }
    pub fn flush() -> Result<(), String> {
        Ok(())
    }
    pub fn navigation_begin(_: u64) {}
    pub fn navigation_frame(_: u64, _: bool, _: bool) {}
}
#[cfg(not(feature = "performance"))]
pub use disabled::*;

pub fn operation(request: &crate::model::Request) -> &'static str {
    use crate::model::Request::*;
    match request {
        Open { .. } => "open",
        Graph { .. } => "graph",
        Decompile { .. } | DecompileWithLocals { .. } => "decompile",
        Discover | DiscoverBatch { .. } => "discover",
        SyncFunctions { .. } => "sync_functions",
        SyncSignatures { .. } => "sync_signatures",
        Rename { .. } => "rename",
        Bytes { .. } => "bytes",
        Strings | StringsWithOptions { .. } => "strings",
        Crypto => "crypto",
    }
}
