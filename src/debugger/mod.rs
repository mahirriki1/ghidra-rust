//! Live debugging through an optional, local GDB process on Linux x86-64.
//!
//! The data types and the session [`controller`] compile on every platform so
//! callers can branch on [`SUPPORTED`] instead of gating each call site. Only
//! the GDB backend is limited to Linux x86-64; elsewhere the controller cannot
//! be constructed. Callers explicitly select a trusted executable to run under
//! their own account.
use std::fmt;
use std::io;

pub mod controller;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod gdb;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod mapping;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod mi;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use gdb::Debugger;

pub use crate::model::MAX_BYTE_READ;

/// Whether this build has a live debugger backend.
pub const SUPPORTED: bool = cfg!(all(target_os = "linux", target_arch = "x86_64"));
/// The trusted GDB executable used by default.
pub const GDB_PATH: &str = "/usr/bin/gdb";
/// Breakpoints a session holds at once.
pub const MAX_BREAKPOINTS: usize = 128;
/// Stack frames reported per stop.
pub const MAX_FRAMES: usize = 32;

#[derive(Debug)]
pub enum Error {
    /// The request was refused before reaching the target; the session is usable.
    Invalid(String),
    Io(io::Error),
    Protocol(String),
    /// GDB refused the request; the session is usable.
    Rejected(String),
    Timeout,
    /// No debugger backend is available on this platform or installation.
    Unavailable(String),
}

impl Error {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message)
            | Self::Protocol(message)
            | Self::Rejected(message)
            | Self::Unavailable(message) => f.write_str(message),
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
    /// GDB's stop reason, such as `breakpoint-hit` or `signal-received`.
    pub reason: String,
    pub thread: u32,
    pub location: Location,
    /// The signal for a `signal-received` stop, such as `SIGINT` after a pause.
    pub signal: Option<String>,
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
    Exited {
        reason: String,
        code: Option<u32>,
        /// The terminating signal of an `exited-signalled` target.
        signal: Option<String>,
    },
    Closed,
}
