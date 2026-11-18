//! Live debugging through an optional, local GDB process on Linux x86-64.
//! Operations can block for I/O and belong on a background thread. Callers
//! explicitly select a trusted executable to run under their own account.
mod mapping;
mod mi;

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::model::{BinaryInfo, MAX_BYTE_READ, MAX_FUNCTION_NAME_BYTES};
use crate::session::BinaryProtection;

use mapping::{Image, Inferior, Mapping};
use mi::{FieldAccess, Fields, Record, Transport, Value};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_BREAKPOINTS: usize = 128;
const MAX_FRAMES: usize = 32;
const MAX_REGISTER_NAMES: usize = 4096;
const GENERAL_REGISTERS: &[&str] = &[
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs", "fs_base", "gs_base",
];

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Io(io::Error),
    Protocol(String),
    Rejected(String),
    Timeout,
}

impl Error {
    fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) | Self::Protocol(message) | Self::Rejected(message) => {
                f.write_str(message)
            }
            Self::Io(error) => error.fmt(f),
            Self::Timeout => f.write_str("Timed out waiting for GDB"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// A runtime location and its address in the verified static executable, when
/// it is an exact file-backed code mapping. Other modules have no static address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    pub runtime: u64,
    pub static_address: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub reason: String,
    pub thread: u32,
    pub location: Location,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub location: Location,
    pub function: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    Stopped(Stop),
    Exited { reason: String, code: Option<u32> },
    Closed,
}

/// Owns one launched inferior and its debugger. Launch pauses before the
/// first instruction. A failed launch cleans up both processes before returning.
pub struct Debugger {
    gdb: Gdb,
    image: Image,
    // Pin the analyzed inode through teardown, even if its pathname changes.
    _source: BinaryProtection,
    mapping: Option<Mapping>,
    state: State,
    stop_id: u64,
    register_names: Vec<(usize, String)>,
    breakpoints: BTreeSet<u32>,
}

impl Debugger {
    /// `info` must come from the current static analysis of `path`. The file
    /// is checked independently against its SHA-256 and retained by descriptor.
    /// `gdb` must be an absolute path to a trusted GDB executable.
    pub fn launch(path: &Path, info: &BinaryInfo, gdb: &Path) -> Result<Self, Error> {
        if !gdb.is_absolute() {
            return Err(Error::Invalid("Select GDB by absolute path".into()));
        }
        if info.format != "ELF"
            || info.architecture != "x86-64"
            || !crate::call_analysis::code_address(info, info.entry)
        {
            return Err(Error::Invalid(
                "Live debugging requires an x86-64 ELF executable with a file-backed entry".into(),
            ));
        }
        crate::project::validate_info(info, MAX_FUNCTION_NAME_BYTES, true)
            .map_err(Error::Invalid)?;
        let mut source = BinaryProtection::open(path).map_err(Error::Invalid)?;
        if info.source_identity.is_some() {
            source = source.bind_snapshot(info).map_err(Error::Invalid)?;
        }
        source.verify_sha256(&info.sha256).map_err(Error::Invalid)?;
        let identity = source.file_identity();
        let path_argument = mi::quote(source.path().as_os_str().as_bytes());
        let mut debugger = Self {
            gdb: Gdb::start(gdb)?,
            image: Image::new(info, identity),
            _source: source,
            mapping: None,
            state: State::Running,
            stop_id: 0,
            register_names: Vec::new(),
            breakpoints: BTreeSet::new(),
        };
        let setup_deadline = Instant::now() + REQUEST_TIMEOUT;
        for command in [
            "-gdb-set confirm off",
            "-gdb-set mi-async on",
            "-gdb-set startup-with-shell off",
            "-gdb-set disable-randomization off",
            "-gdb-set stop-on-solib-events 0",
            "-gdb-set trust-readonly-sections off",
            "-inferior-tty-set /dev/null",
            &format!("-file-exec-and-symbols {path_argument}"),
        ] {
            debugger.request_until(command, "done", setup_deadline)?;
        }
        // starti stops in the loader (or at the program entry for static
        // executables). No target instructions run before we verify this image.
        debugger.request_until(
            "-interpreter-exec console starti",
            "running",
            setup_deadline,
        )?;
        match debugger.wait(REQUEST_TIMEOUT)? {
            State::Stopped(_) => (),
            State::Running => return Err(Error::Timeout),
            _ => {
                return Err(Error::Invalid(
                    "GDB did not stop before the first instruction".into(),
                ));
            }
        }
        debugger
            ._source
            .verify_sha256(&info.sha256)
            .map_err(Error::Invalid)?;
        // A later exec can replace the image or move the same PIE. Stop before
        // the replacement runs so old absolute breakpoints cannot be reused.
        debugger.request("-interpreter-exec console \"catch exec\"", "done")?;
        Ok(debugger)
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Waits for a stop or exit. If the duration expires while the target is
    /// running, returns `Running` and leaves the session available to pause.
    /// Waits are capped at five seconds so callers can service their event loop.
    pub fn wait(&mut self, timeout: Duration) -> Result<&State, Error> {
        let deadline = Instant::now() + timeout.min(REQUEST_TIMEOUT);
        let result = (|| {
            while matches!(self.state, State::Running) {
                let Some(record) = self.gdb.transport.next(deadline)? else {
                    break;
                };
                self.event(record)?;
            }
            Ok(())
        })();
        self.finish(result)?;
        Ok(&self.state)
    }

    pub fn resume(&mut self) -> Result<(), Error> {
        self.start_execution("-exec-continue")
    }

    pub fn step_instruction(&mut self) -> Result<(), Error> {
        self.start_execution("-exec-step-instruction")
    }

    pub fn pause(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Running) {
            return Err(Error::Invalid("Pausing requires a running target".into()));
        }
        match self.request("-exec-interrupt", "done") {
            Ok(_) => Ok(()),
            // A breakpoint can win the race with an interrupt request.
            Err(Error::Rejected(_))
                if matches!(self.state, State::Stopped(_) | State::Exited { .. }) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    pub fn insert_breakpoint(&mut self, static_address: u64) -> Result<u32, Error> {
        self.stopped()?;
        if self.breakpoints.len() >= MAX_BREAKPOINTS {
            return Err(Error::Invalid("Too many debugger breakpoints".into()));
        }
        let runtime = self
            .mapping
            .as_ref()
            .and_then(|mapping| mapping.to_runtime(&self.image, static_address))
            .ok_or_else(|| {
                Error::Invalid("Breakpoint address is outside the mapped executable code".into())
            })?;
        let fields = self.inspect(&format!("-break-insert *{runtime:#x}"))?;
        let result = (|| {
            let breakpoint = fields.required("bkpt")?.tuple()?;
            let id = unsigned(breakpoint.text("number")?)?;
            if address(breakpoint.text("addr")?)? != runtime
                || id == 0
                || !self.breakpoints.insert(id)
            {
                return Err(Error::protocol("Unexpected breakpoint identity or address"));
            }
            Ok(id)
        })();
        self.finish(result)
    }

    pub fn remove_breakpoint(&mut self, id: u32) -> Result<(), Error> {
        self.stopped()?;
        if !self.breakpoints.contains(&id) {
            return Err(Error::Invalid("Unknown debugger breakpoint".into()));
        }
        self.inspect(&format!("-break-delete {id}"))?;
        self.breakpoints.remove(&id);
        Ok(())
    }

    pub fn stack(&mut self) -> Result<Vec<Frame>, Error> {
        let thread = self.stopped()?.thread;
        let fields = self.inspect(&format!(
            "-stack-list-frames --thread {thread} 0 {}",
            MAX_FRAMES - 1
        ))?;
        let result = (|| {
            let frames = fields.list("stack")?;
            if frames.len() > MAX_FRAMES {
                return Err(Error::protocol("Too many stack frames"));
            }
            frames
                .iter()
                .enumerate()
                .map(|(level, frame)| {
                    let fields = frame.tuple()?;
                    if usize::try_from(unsigned(fields.text("level")?)?).ok() != Some(level) {
                        return Err(Error::protocol("Unexpected stack frame order"));
                    }
                    let runtime = address(fields.text("addr")?)?;
                    let function = fields
                        .field("func")?
                        .map(Value::text)
                        .transpose()?
                        .map(display_text);
                    Ok(Frame {
                        location: self.location(runtime),
                        function,
                    })
                })
                .collect()
        })();
        self.finish(result)
    }

    pub fn registers(&mut self) -> Result<Vec<Register>, Error> {
        let thread = self.stopped()?.thread;
        if self.register_names.is_empty() {
            let fields = self.inspect("-data-list-register-names")?;
            let result = register_names(&fields);
            self.register_names = self.finish(result)?;
        }
        let numbers = self
            .register_names
            .iter()
            .map(|(index, _)| index.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        let fields = self.inspect(&format!(
            "-data-list-register-values --thread {thread} --frame 0 x {numbers}"
        ))?;
        let result = (|| {
            let values = fields.list("register-values")?;
            if values.len() > self.register_names.len() {
                return Err(Error::protocol("Too many register values"));
            }
            let mut seen = BTreeSet::new();
            let mut registers = Vec::new();
            for value in values {
                let fields = value.tuple()?;
                let index = unsigned(fields.text("number")?)? as usize;
                let Some((_, name)) = self.register_names.iter().find(|(n, _)| *n == index) else {
                    return Err(Error::protocol("Unexpected register number"));
                };
                if !seen.insert(index) {
                    return Err(Error::protocol("Duplicate register value"));
                }
                let value = fields.text("value")?;
                if value != "<unavailable>" {
                    registers.push(Register {
                        name: name.clone(),
                        value: address(value)?,
                    });
                }
            }
            Ok(registers)
        })();
        self.finish(result)
    }

    /// Reads exactly `length` live bytes. A wholly or partly unreadable range
    /// returns an error. File bytes never stand in for unavailable live bytes.
    pub fn read_memory(&mut self, runtime: u64, length: usize) -> Result<Vec<u8>, Error> {
        if length == 0 || length > MAX_BYTE_READ || runtime.checked_add(length as u64).is_none() {
            return Err(Error::Invalid("Invalid live memory range".into()));
        }
        let fields = self.inspect(&format!("-data-read-memory-bytes {runtime:#x} {length}"))?;
        let result = (|| {
            let rows = fields.list("memory")?;
            let mut bytes = Vec::with_capacity(length);
            for row in rows {
                let row = row.tuple()?;
                let contents = row.text("contents")?.as_bytes();
                let begin = address(row.text("begin")?)?;
                let end = address(row.text("end")?)?;
                let valid = contents.len().is_multiple_of(2)
                    && begin == runtime + bytes.len() as u64
                    && end.checked_sub(begin) == Some((contents.len() / 2) as u64)
                    && contents.len() / 2 <= length - bytes.len();
                if !valid {
                    return Err(Error::Rejected(
                        "GDB did not return the complete live memory range".into(),
                    ));
                }
                for pair in contents.as_chunks::<2>().0 {
                    let pair = std::str::from_utf8(pair)
                        .map_err(|_| Error::protocol("Non-ASCII memory data"))?;
                    bytes.push(
                        u8::from_str_radix(pair, 16)
                            .map_err(|_| Error::protocol("Invalid memory data"))?,
                    );
                }
            }
            if bytes.len() != length {
                return Err(Error::Rejected(
                    "GDB did not return the complete live memory range".into(),
                ));
            }
            Ok(bytes)
        })();
        self.finish(result)
    }

    fn stopped(&self) -> Result<&Stop, Error> {
        match &self.state {
            State::Stopped(stop) => Ok(stop),
            _ => Err(Error::Invalid(
                "This debugger operation requires a stopped target".into(),
            )),
        }
    }

    fn location(&self, runtime: u64) -> Location {
        Location {
            runtime,
            static_address: self
                .mapping
                .as_ref()
                .and_then(|mapping| mapping.to_static(&self.image, runtime)),
        }
    }

    fn start_execution(&mut self, command: &str) -> Result<(), Error> {
        self.stopped()?;
        let prior_stop = self.stop_id;
        self.request(command, "running")?;
        if self.stop_id == prior_stop && !matches!(self.state, State::Exited { .. }) {
            self.state = State::Running;
            self.mapping = None;
        }
        Ok(())
    }

    fn inspect(&mut self, command: &str) -> Result<Fields, Error> {
        self.stopped()?;
        let stop = self.stop_id;
        let fields = self.request(command, "done")?;
        if self.stop_id != stop || !matches!(self.state, State::Stopped(_)) {
            return Err(Error::Invalid(
                "The target stopped state changed during inspection".into(),
            ));
        }
        Ok(fields)
    }

    fn request(&mut self, command: &str, expected: &str) -> Result<Fields, Error> {
        self.request_until(command, expected, Instant::now() + REQUEST_TIMEOUT)
    }

    fn request_until(
        &mut self,
        command: &str,
        expected: &str,
        deadline: Instant,
    ) -> Result<Fields, Error> {
        let result = (|| {
            let token = self.gdb.send(command)?;
            loop {
                let record = self.gdb.transport.next(deadline)?.ok_or(Error::Timeout)?;
                if record.kind == b'^' {
                    if record.token != Some(token) {
                        return Err(Error::protocol(
                            "GDB replied with an unexpected request token",
                        ));
                    }
                    if record.class == "error" {
                        return Err(Error::Rejected(display_text(record.fields.text("msg")?)));
                    }
                    if record.class != expected {
                        return Err(Error::protocol("Unexpected GDB response class"));
                    }
                    return Ok(record.fields);
                }
                self.event(record)?;
            }
        })();
        self.finish(result)
    }

    fn event(&mut self, record: Record) -> Result<(), Error> {
        let fields = record.fields;
        match (record.kind, record.class.as_str()) {
            (b'=', "thread-group-started") => {
                if fields.text("id")? != "i1" || self.gdb.inferior.is_some() {
                    return Err(Error::protocol("Unexpected GDB inferior"));
                }
                self.gdb.inferior = Some(Inferior::open(
                    unsigned(fields.text("pid")?)?,
                    self.gdb.child.id(),
                )?);
            }
            (b'*', "running") => {
                self.state = State::Running;
                self.mapping = None;
            }
            (b'*', "stopped") => {
                let reason = fields.text("reason")?;
                if reason == "exec" {
                    return Err(Error::protocol(
                        "The target replaced its executable. Start a new debug session.",
                    ));
                }
                if matches!(reason, "exited" | "exited-normally" | "exited-signalled") {
                    let code = match reason {
                        "exited-normally" => Some(0),
                        "exited" => {
                            let code = fields.text("exit-code")?;
                            // GDB/MI exit status is printed as an octal integer.
                            Some(
                                u32::from_str_radix(code, 8)
                                    .map_err(|_| Error::protocol("Invalid inferior exit code"))?,
                            )
                        }
                        _ => None,
                    };
                    self.state = State::Exited {
                        reason: reason.into(),
                        code,
                    };
                    self.mapping = None;
                    self.gdb.inferior = None;
                    return Ok(());
                }
                if fields.text("stopped-threads")? != "all" {
                    return Err(Error::protocol(
                        "GDB must stop all threads before inspection",
                    ));
                }
                let inferior = self
                    .gdb
                    .inferior
                    .as_ref()
                    .ok_or_else(|| Error::protocol("No tracked inferior at stop"))?;
                self.mapping = Some(
                    self.image
                        .mapping(inferior)
                        .map_err(|error| Error::protocol(error.to_string()))?,
                );
                let runtime = address(fields.required("frame")?.tuple()?.text("addr")?)?;
                let thread = unsigned(fields.text("thread-id")?)?;
                if thread == 0 {
                    return Err(Error::protocol("GDB reported an invalid thread"));
                }
                self.stop_id = self
                    .stop_id
                    .checked_add(1)
                    .ok_or_else(|| Error::protocol("Too many debugger stops"))?;
                self.state = State::Stopped(Stop {
                    reason: display_text(reason),
                    thread,
                    location: self.location(runtime),
                });
            }
            (b'^', _) => return Err(Error::protocol("Unsolicited GDB response")),
            _ => (),
        }
        Ok(())
    }

    fn finish<T>(&mut self, result: Result<T, Error>) -> Result<T, Error> {
        if matches!(
            &result,
            Err(Error::Io(_) | Error::Protocol(_) | Error::Timeout)
        ) {
            self.gdb.shutdown();
            self.mapping = None;
            self.state = State::Closed;
        }
        result
    }
}

struct Gdb {
    child: Child,
    transport: Transport,
    sequence: u64,
    inferior: Option<Inferior>,
    closed: bool,
}

impl Gdb {
    fn start(executable: &Path) -> Result<Self, Error> {
        let mut child = Command::new(executable)
            .args([
                "--nx",
                "--quiet",
                "--interpreter=mi3",
                "-iex",
                "set auto-load off",
                "-iex",
                "set debuginfod enabled off",
            ])
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().expect("piped stdin");
        let output = child.stdout.take().expect("piped stdout");
        match Transport::new(input, output) {
            Ok(transport) => Ok(Self {
                child,
                transport,
                sequence: 0,
                inferior: None,
                closed: false,
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }

    fn send(&mut self, command: &str) -> Result<u64, Error> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::protocol("GDB command counter overflow"))?;
        self.transport.send(self.sequence, command)?;
        Ok(self.sequence)
    }

    fn shutdown(&mut self) {
        if std::mem::replace(&mut self.closed, true) {
            return;
        }
        // Let GDB reap its child normally. If the debugger died or stopped
        // responding, kill the owned inferior by pidfd before killing GDB.
        let sent = self.send("-gdb-exit").is_ok();
        if sent && wait_for_exit(&mut self.child, SHUTDOWN_TIMEOUT) {
            // An abnormal GDB exit may leave the tracked child live.
            if let Some(inferior) = self.inferior.take() {
                inferior.terminate();
            }
            return;
        }
        if let Some(inferior) = self.inferior.take() {
            inferior.terminate();
            if wait_for_exit(&mut self.child, SHUTDOWN_TIMEOUT) {
                return;
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Gdb {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => return false,
        }
    }
}

fn register_names(fields: &Fields) -> Result<Vec<(usize, String)>, Error> {
    let names = fields.list("register-names")?;
    if names.len() > MAX_REGISTER_NAMES {
        return Err(Error::protocol("Too many register names"));
    }
    let mut registers = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, name) in names.iter().enumerate() {
        let name = name.text()?;
        if GENERAL_REGISTERS.contains(&name) {
            if !seen.insert(name) {
                return Err(Error::protocol("Duplicate general register name"));
            }
            registers.push((index, name.to_owned()));
        }
    }
    if !seen.contains("rip") || !seen.contains("rsp") {
        return Err(Error::protocol(
            "GDB did not expose x86-64 general registers",
        ));
    }
    Ok(registers)
}

fn display_text(text: &str) -> String {
    text.chars()
        .take(1024)
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn unsigned(text: &str) -> Result<u32, Error> {
    text.parse()
        .map_err(|_| Error::protocol("Invalid MI unsigned integer"))
}

fn address(text: &str) -> Result<u64, Error> {
    mapping::hex(
        text.strip_prefix("0x")
            .ok_or_else(|| Error::protocol("Expected hexadecimal MI address"))?,
    )
}
