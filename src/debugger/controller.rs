//! One background thread per live debug session. Callers only send commands
//! and poll events, so no GDB request ever blocks the caller's thread. Off
//! Linux x86-64 the same types exist, but [`Controller`] is uninhabited and
//! [`Controller::launch`] reports [`super::Error::Unavailable`].
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use crate::model::BinaryInfo;

use super::{Frame, GDB_PATH, Location, Register, Stop};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    Instruction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Resume,
    Step(StepKind),
    Pause,
    /// Declarative: the complete desired set of static breakpoint addresses
    /// and the caller's revision for it. While the target runs, the latest
    /// set waits and applies at the next stop, before that stop's snapshot.
    /// A set larger than [`super::MAX_BREAKPOINTS`] is refused unchanged.
    Breakpoints {
        revision: u64,
        addresses: BTreeSet<u64>,
    },
    /// Read live memory at the stop identified by `stop`. A read for any
    /// other stop, or while running, is answered with an error.
    ReadMemory {
        token: u64,
        stop: u64,
        runtime: u64,
        length: usize,
    },
    /// End the session and the target.
    Stop,
}

/// The state captured at one stop. Every part comes from the same stop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// The controller's stop counter; the loader stop is 1.
    pub stop_seq: u64,
    pub stop: Stop,
    pub registers: Result<Vec<Register>, String>,
    pub frames: Result<Vec<Frame>, String>,
    /// The `Location` of each register value, in register order. Empty when
    /// the registers are unavailable.
    pub register_locations: Vec<Location>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreakpointStatus {
    Set,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Stopped(Box<Snapshot>),
    Running,
    /// The status of every desired address of the applied revision, plus any
    /// undesired address that is still set because its removal failed.
    Breakpoints {
        revision: u64,
        status: BTreeMap<u64, BreakpointStatus>,
    },
    Memory {
        token: u64,
        stop_seq: u64,
        runtime: u64,
        result: Result<Vec<u8>, String>,
    },
    /// A command was refused, or partly failed, and the session is still usable.
    Refused {
        message: String,
    },
    Exited {
        code: Option<u32>,
        signal: Option<String>,
    },
    /// Always the last event. `error` explains a session that could not
    /// start or had to close, such as a target `exec` or a GDB failure.
    Ended {
        error: Option<String>,
    },
}

pub struct Launch {
    pub path: PathBuf,
    /// The current static analysis of `path`. Functions are not needed.
    pub info: BinaryInfo,
    /// The initial breakpoint revision and static addresses, applied at the
    /// loader stop before its snapshot.
    pub breakpoints: (u64, BTreeSet<u64>),
    /// Resume after the loader stop instead of waiting there.
    pub run: bool,
    /// An absolute path to a trusted GDB executable.
    pub gdb: PathBuf,
    /// Called after each event is queued, for example to request a repaint.
    pub notify: Arc<dyn Fn() + Send + Sync>,
}

impl Launch {
    /// A paused launch with no breakpoints under [`GDB_PATH`].
    pub fn new(path: PathBuf, info: BinaryInfo, notify: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            path,
            info,
            breakpoints: (0, BTreeSet::new()),
            run: false,
            gdb: PathBuf::from(GDB_PATH),
            notify,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use supported::Controller;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod supported {
    use std::cell::Cell;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::mpsc::{self, RecvTimeoutError, TryRecvError};
    use std::time::{Duration, Instant};

    use super::{BreakpointStatus, Command, Event, Launch, Snapshot, StepKind};
    use crate::debugger::{Debugger, Error, MAX_BREAKPOINTS, State};

    /// How long a running session waits for GDB before checking commands.
    const RUN_POLL: Duration = Duration::from_millis(50);

    /// How long a pause waits for its stop before reading further commands.
    const PAUSE_WAIT: Duration = Duration::from_secs(1);

    /// Reported when the session thread ended without sending `Ended`.
    const UNEXPECTED_END: &str = "The debugger session stopped unexpectedly";

    /// Owns the command and event channels of one session thread. Dropping it
    /// never blocks: the thread notices the closed channel and ends the target.
    pub struct Controller {
        commands: mpsc::Sender<Command>,
        events: mpsc::Receiver<Event>,
        /// Whether `try_recv` has returned an `Ended` event.
        ended: Cell<bool>,
    }

    impl Controller {
        /// Starts the session thread. Launch failures arrive as `Ended`.
        pub fn launch(launch: Launch) -> Result<Self, Error> {
            let (commands, command_receiver) = mpsc::channel();
            let (event_sender, events) = mpsc::channel();
            std::thread::Builder::new()
                .name("live-debug".into())
                .spawn(move || {
                    Session {
                        events: event_sender,
                        notify: launch.notify.clone(),
                    }
                    .run(launch, command_receiver)
                })?;
            Ok(Self {
                commands,
                events,
                ended: Cell::new(false),
            })
        }

        /// Returns `false` once the session thread has ended.
        pub fn send(&self, command: Command) -> bool {
            self.commands.send(command).is_ok()
        }

        /// The next queued event. `Ended` is always returned exactly once:
        /// a thread that stopped without sending it, such as after a panic,
        /// is reported with an error.
        pub fn try_recv(&self) -> Option<Event> {
            match self.events.try_recv() {
                Ok(event) => {
                    if matches!(event, Event::Ended { .. }) {
                        self.ended.set(true);
                    }
                    Some(event)
                }
                Err(TryRecvError::Disconnected) if !self.ended.replace(true) => {
                    Some(Event::Ended {
                        error: Some(UNEXPECTED_END.into()),
                    })
                }
                Err(_) => None,
            }
        }

        /// Stops the session and waits up to `timeout` for `Ended`. Returns
        /// whether the session ended in time. Other events are discarded.
        pub fn shutdown(self, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            // A thread that is already gone has sent its final event.
            let _ = self.commands.send(Command::Stop);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self.events.recv_timeout(remaining) {
                    Ok(Event::Ended { .. }) | Err(RecvTimeoutError::Disconnected) => return true,
                    Ok(_) => (),
                    Err(RecvTimeoutError::Timeout) => return false,
                }
            }
        }
    }

    struct Session {
        events: mpsc::Sender<Event>,
        notify: std::sync::Arc<dyn Fn() + Send + Sync>,
    }

    impl Session {
        fn emit(&self, event: Event) {
            // A dropped receiver means nobody is listening anymore.
            let _ = self.events.send(event);
            (self.notify)();
        }

        fn run(self, launch: Launch, commands: mpsc::Receiver<Command>) {
            let error = match Debugger::launch(&launch.path, &launch.info, &launch.gdb) {
                Ok(mut debugger) => {
                    let result =
                        self.control(&mut debugger, launch.breakpoints, launch.run, &commands);
                    // Dropping the debugger ends the target and reaps GDB, so
                    // `Ended` is only reported once both are gone.
                    drop(debugger);
                    result.err()
                }
                Err(error) => Some(error),
            };
            self.emit(Event::Ended {
                error: error.map(|error| error.to_string()),
            });
        }

        /// The session state machine. Returns `Err` only for an error that
        /// closed the debugger; recoverable errors become `Refused` events.
        fn control(
            &self,
            debugger: &mut Debugger,
            initial: (u64, BTreeSet<u64>),
            mut run: bool,
            commands: &mpsc::Receiver<Command>,
        ) -> Result<(), Error> {
            let mut pending = Some(initial);
            let mut stop_seq = 0u64;
            // Whether the current stop has been reported. Every successful
            // resume or step clears it, even if GDB stopped during the request.
            let mut reported = false;
            loop {
                match debugger.state() {
                    State::Closed => {
                        return Err(Error::Protocol("The debugger session closed".into()));
                    }
                    State::Exited { code, signal, .. } => {
                        self.emit(Event::Exited {
                            code: *code,
                            signal: signal.clone(),
                        });
                        return Ok(());
                    }
                    State::Stopped(_) => {
                        if !reported {
                            if let Some((revision, addresses)) = pending.take() {
                                self.sync(debugger, revision, &addresses)?;
                            }
                            stop_seq = stop_seq
                                .checked_add(1)
                                .ok_or_else(|| Error::Protocol("Too many debugger stops".into()))?;
                            let snapshot = snapshot(debugger, stop_seq)?;
                            self.emit(Event::Stopped(Box::new(snapshot)));
                            reported = true;
                        }
                        let command = if run {
                            // Commands queued during the launch come before the
                            // automatic resume, so an early stop or pause keeps
                            // the target from running.
                            match commands.try_recv() {
                                Ok(Command::Stop) | Err(TryRecvError::Disconnected) => {
                                    return Ok(());
                                }
                                Ok(Command::Pause) => {
                                    run = false;
                                    continue;
                                }
                                Ok(command @ (Command::Resume | Command::Step(_))) => {
                                    run = false;
                                    command
                                }
                                Ok(command) => command,
                                Err(TryRecvError::Empty) => {
                                    run = false;
                                    Command::Resume
                                }
                            }
                        } else {
                            match commands.recv() {
                                Ok(command) => command,
                                Err(_) => return Ok(()),
                            }
                        };
                        match command {
                            Command::Resume | Command::Step(_) => {
                                let result = match command {
                                    Command::Step(StepKind::Instruction) => {
                                        debugger.step_instruction()
                                    }
                                    _ => debugger.resume(),
                                };
                                if self.recoverable(debugger, result)?.is_some() {
                                    reported = false;
                                    self.emit(Event::Running);
                                }
                            }
                            Command::Breakpoints {
                                revision,
                                addresses,
                            } => self.sync(debugger, revision, &addresses)?,
                            Command::ReadMemory {
                                token,
                                stop,
                                runtime,
                                length,
                            } => {
                                let result = if stop == stop_seq {
                                    let result = debugger.read_memory(runtime, length);
                                    fatal_or_message(debugger, result)?
                                } else {
                                    Err("stale".into())
                                };
                                self.emit(Event::Memory {
                                    token,
                                    stop_seq,
                                    runtime,
                                    result,
                                });
                            }
                            Command::Pause => self.emit(Event::Refused {
                                message: "The target is not running".into(),
                            }),
                            Command::Stop => return Ok(()),
                        }
                    }
                    State::Running => {
                        loop {
                            match commands.try_recv() {
                                Ok(Command::Pause) => {
                                    let result = debugger.pause();
                                    if self.recoverable(debugger, result)?.is_some() {
                                        // The stop arrives after the interrupt
                                        // is accepted. Later commands belong to
                                        // that stop, so wait a bounded time for
                                        // it before reading them.
                                        let deadline = Instant::now() + PAUSE_WAIT;
                                        while matches!(debugger.state(), State::Running)
                                            && Instant::now() < deadline
                                        {
                                            debugger.wait(RUN_POLL)?;
                                        }
                                        break;
                                    }
                                }
                                Ok(Command::Breakpoints {
                                    revision,
                                    addresses,
                                }) => pending = Some((revision, addresses)),
                                Ok(Command::ReadMemory { token, runtime, .. }) => {
                                    self.emit(Event::Memory {
                                        token,
                                        stop_seq,
                                        runtime,
                                        result: Err("running".into()),
                                    })
                                }
                                Ok(Command::Resume | Command::Step(_)) => {
                                    self.emit(Event::Refused {
                                        message: "The target is already running".into(),
                                    })
                                }
                                Ok(Command::Stop) | Err(TryRecvError::Disconnected) => {
                                    return Ok(());
                                }
                                Err(TryRecvError::Empty) => break,
                            }
                        }
                        debugger.wait(RUN_POLL)?;
                    }
                }
            }
        }

        /// Applies the desired breakpoint set while stopped and reports the
        /// status of each desired address. Removals run first to free slots.
        fn sync(
            &self,
            debugger: &mut Debugger,
            revision: u64,
            addresses: &BTreeSet<u64>,
        ) -> Result<(), Error> {
            if addresses.len() > MAX_BREAKPOINTS {
                self.emit(Event::Refused {
                    message: format!("A session holds up to {MAX_BREAKPOINTS} breakpoints"),
                });
                return Ok(());
            }
            let current = debugger.breakpoint_ids().collect::<Vec<_>>();
            let mut status = BTreeMap::new();
            for &(address, id) in &current {
                if addresses.contains(&address) {
                    status.insert(address, BreakpointStatus::Set);
                } else {
                    let result = debugger.remove_breakpoint(id);
                    if let Err(message) = fatal_or_message(debugger, result)? {
                        // Still armed, so the caller must keep showing it.
                        status.insert(
                            address,
                            BreakpointStatus::Failed(format!("Could not remove: {message}")),
                        );
                    }
                }
            }
            for &address in addresses {
                if status.contains_key(&address) {
                    continue;
                }
                let result = debugger.insert_breakpoint(address);
                let entry = match fatal_or_message(debugger, result)? {
                    Ok(_) => BreakpointStatus::Set,
                    Err(message) => BreakpointStatus::Failed(message),
                };
                status.insert(address, entry);
            }
            self.emit(Event::Breakpoints { revision, status });
            Ok(())
        }

        /// Turns a recoverable error into a `Refused` event and `None`.
        fn recoverable<T>(
            &self,
            debugger: &Debugger,
            result: Result<T, Error>,
        ) -> Result<Option<T>, Error> {
            match fatal_or_message(debugger, result)? {
                Ok(value) => Ok(Some(value)),
                Err(message) => {
                    self.emit(Event::Refused { message });
                    Ok(None)
                }
            }
        }
    }

    /// Propagates an error that closed the session. A recoverable error,
    /// such as an invalid address or a GDB rejection, becomes its message.
    fn fatal_or_message<T>(
        debugger: &Debugger,
        result: Result<T, Error>,
    ) -> Result<Result<T, String>, Error> {
        match result {
            Ok(value) => Ok(Ok(value)),
            Err(error) if matches!(debugger.state(), State::Closed) => Err(error),
            Err(error) => Ok(Err(error.to_string())),
        }
    }

    fn snapshot(debugger: &mut Debugger, stop_seq: u64) -> Result<Snapshot, Error> {
        let State::Stopped(stop) = debugger.state() else {
            return Err(Error::Protocol("Expected a stopped target".into()));
        };
        let stop = stop.clone();
        let result = debugger.registers();
        let registers = fatal_or_message(debugger, result)?;
        let result = debugger.stack();
        let frames = fatal_or_message(debugger, result)?;
        let register_locations = registers
            .as_ref()
            .map(|registers| {
                registers
                    .iter()
                    .map(|register| debugger.location(register.value))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Snapshot {
            stop_seq,
            stop,
            registers,
            frames,
            register_locations,
        })
    }
}

/// Uninhabited: live debugging requires Linux x86-64.
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub enum Controller {}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
impl Controller {
    pub fn launch(_launch: Launch) -> Result<Self, super::Error> {
        Err(super::Error::Unavailable(
            "Live debugging requires Linux x86-64".into(),
        ))
    }

    pub fn send(&self, _command: Command) -> bool {
        match *self {}
    }

    pub fn try_recv(&self) -> Option<Event> {
        match *self {}
    }

    pub fn shutdown(self, _timeout: std::time::Duration) -> bool {
        match self {}
    }
}
