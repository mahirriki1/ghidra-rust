# Linux live debugger backend

The Rust `debugger::Debugger` API runs a local x86-64 Linux ELF executable
under GDB. It supports breakpoints, pause, continue, instruction stepping,
stack frames, general registers, and reads of up to 64 KiB of live memory.
`debugger::controller::Controller` runs one such session on its own thread.
The desktop listing and headless JSON API have no live debugger commands yet.

The debugger types and the controller compile on every platform, and
`debugger::SUPPORTED` reports whether this build has a backend. Only Linux
x86-64 builds include the GDB backend. On other platforms,
`Controller::launch` returns `Error::Unavailable`.

## Try a breakpoint

Install GDB with MI3 support at `/usr/bin/gdb`. The debugger uses Linux procfs
and PID file descriptors, which require Linux 5.3 or newer. The example runs
static analysis first, so it also needs the normal Linux worker setup.
[Linux setup](linux.md)

From a source checkout:

```sh
debugger_demo=$(mktemp -d)
cc -g -O0 -fPIE -pie tests/fixtures/debugger.c -o "$debugger_demo/fixture"
cargo run --locked --example live-debug -- "$debugger_demo/fixture" debug_point
```

The example pauses at `debug_point` and prints the live address, its matching
static address, general registers, and stack. You can supply a `0x`-prefixed
static address instead of a function name. The example ends the debug session
when it exits.

## Use the Rust API

Pass an explicitly selected executable, its current static `BinaryInfo`, and an
absolute path to the GDB executable to `Debugger::launch`. For example, obtain
`BinaryInfo` from the headless Rust controller's `Info` command. The debugger
verifies the SHA-256 and, when supplied, the opened file identity. It launches
with ASLR left enabled, stops before the first target instruction, and checks
that Linux loaded the expected file. That first stop can be in the ELF loader.

Insert breakpoints using static addresses, then call `resume` or
`step_instruction`. Each static address takes one breakpoint. Inserting it
again is refused, and `breakpoint_ids` lists the inserted addresses with
their GDB ids. A session holds up to 128 breakpoints. `wait` reports
`Running`, a stop, or exit. A wait that expires leaves the running target
available to `pause`. Individual GDB requests have a five-second deadline. Perform these calls on a background thread.
A stop caused by a signal names it, so a pause reports `SIGINT` rather than a
fault such as `SIGSEGV`. An exit caused by a signal also names the signal.

If GDB is missing at the selected path, or cannot be executed, launch returns
`Error::Unavailable` with the message "GDB is required at /usr/bin/gdb".

A stopped address maps back to the static image only when it agrees with the
kernel's relocated entry point, an executable mapping of the same file, and a
file-backed analyzed code section at the same file offset. Stack frames from
other images can still show their runtime address and GDB's symbol text.

## Use the session controller

`Controller::launch` takes a `Launch` with the executable, its `BinaryInfo`,
an initial breakpoint set and its revision, whether to run past the loader
stop, the GDB path (`/usr/bin/gdb` by default), and a notification callback.
It starts a dedicated thread and returns at once. Launch failures arrive as
the final `Ended` event. Callers send `Command`s and poll `Event`s with
`try_recv`. The callback runs after each event is queued, for example to
request a repaint.

- Each stop produces one `Stopped` snapshot. It holds the stop, the general
  registers, up to 32 stack frames, and the static location of each register
  value, all from that stop. The loader stop has sequence number 1, and each
  later stop increments it.
- `Breakpoints` sends the complete desired set of static addresses with a
  revision. When the target is stopped, it applies immediately. While the
  target runs, the latest set waits and applies at the next stop, before
  that stop's snapshot. The reply lists every desired address as set or
  failed with a reason. An address that could not be removed stays listed
  as failed, because it is still set. A set of more than 128 addresses is
  refused and leaves the breakpoints unchanged.
- `ReadMemory` names the stop sequence it was made for. A read for an older
  stop is answered with `stale`, and one sent while running with `running`.
  The session stays usable in both cases.
- Commands that do not fit the current state, such as pausing a stopped
  target, are answered with `Refused`. A pause, stop, or resume sent while
  a running launch is still starting replaces its automatic resume, so the
  target stays at the loader stop or ends there.
- `Exited` reports the exit code or signal. `Ended` is always the last event.
  It carries an error when the session could not start or had to close, for
  example after an `exec` or a GDB failure. The target and GDB are gone when
  it arrives. If the session thread stops without sending it, `try_recv`
  reports `Ended` with an error instead.
- `Stop` ends the session. Dropping the `Controller` also ends it without
  blocking. A running session normally notices within 50 ms, and a stopped
  one at once. A GDB request already in progress can delay this by up to its
  five-second deadline. `Controller::shutdown` sends `Stop` and waits a bounded time for
  `Ended`.

## Execution limits

Launch only executables you trust to run under your account. Live sessions
execute the selected program with your permissions, outside the static
analysis worker's sandbox. GDB initialization files, auto-load scripts, and
debuginfod are disabled. This first backend supports one locally launched
process with all threads stopped for inspection. Standard input and output
for the target go to `/dev/null`. The API tracks and cleans up the direct
debuggee. If that process replaces its executable with `exec`, the session
ends before the replacement runs. Child processes are outside its supervision.
If the host process crashes rather than ending the session, GDB exits and the
detached target can keep running. Debugging requires Linux x86-64; Windows
and other platforms have no live debugger.

Attach, remote targets, live memory writes, saved traces, emulation, and
Windows debugger support are outside this backend's scope.
