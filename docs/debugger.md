# Linux live debugger

The Rust `debugger::Debugger` API runs a local x86-64 Linux ELF executable
under GDB. It supports breakpoints, pause, continue, instruction stepping,
stack frames, general registers, and reads of up to 64 KiB of live memory.
`debugger::controller::Controller` runs one such session on its own thread.
The desktop runs sessions from its **Debug** menu. The headless JSON API has
no live debugger commands yet.

The debugger types and the controller compile on every platform, and
`debugger::SUPPORTED` reports whether this build has a backend. Only Linux
x86-64 builds include the GDB backend. On other platforms,
`Controller::launch` returns `Error::Unavailable`.

## Debug from the desktop

Linux x86-64 builds show a **Debug** menu between **Analysis** and **Help**.
It works on an x86-64 ELF executable with a file-backed entry point that you
opened directly. A binary embedded in a project is a private copy that cannot
run, so open the executable itself to debug it. Other builds have no Debug
menu, and the keys below do nothing there.

| Key | Action |
| --- | --- |
| `F5` | Start and run to the first breakpoint, or continue when stopped |
| `Shift+F5` | Stop: end the target and the session |
| `F6` | Pause a running target |
| `F9` | Toggle a breakpoint at the selected instruction |
| `F11` | Step one instruction |

**Debug → Start paused** launches and stops before the first target
instruction, usually in the ELF loader. The toolbar's run, pause, step and
stop buttons repeat these commands for a debuggable binary. Like the other
shortcuts, the keys do nothing while you type in a field, while a dialog or
menu is open, or during a file operation. While a binary opens or reopens,
only Pause and Stop respond. A held key acts once.

The first start of each opened binary asks you to confirm **Run program**.
Enter does not confirm it. The confirmation lasts until you open or reopen a
binary, close it, or open a project.

Breakpoints go on exact decoded instruction starts: the selected instruction
in the Function listing, or the cursor row in the Program listing. Right-click
an instruction for **Set breakpoint** or **Remove breakpoint**, and use
**Debug → Clear breakpoints** to remove them all. A session holds up to 128.
Breakpoints last for the opened binary and are not saved in projects.

The Listing reserves a narrow gutter for debuggable binaries, so its columns
do not move when a session starts or ends:

- A filled red dot is a breakpoint, inserted when a session runs.
- A red ring is a breakpoint added or removed while the target runs. The
  change applies at the next stop, so a removed breakpoint can still stop
  the target until then.
- A grey ring with a cross could not be inserted or removed. Hover the row
  for the reason.
- A green arrow and row fill mark the stopped PC.

At each stop, the Listing selects the PC when a known function's decoded
listing contains it, and the Decompiler highlights the expressions that the
engine maps to that instruction. An instruction with no engine mapping
highlights nothing. These moves add no Back/Forward history. A stop does not
move the selection while a binary opens, while you type in a field, or while
the Annotations editor holds an unsaved edit. A stop outside
the analyzed executable, for example in the loader or libc, leaves the
selection where it was. The status bar shows the state: **Launching**,
**Running**, **Stopped @ address** (or the runtime address outside the image),
a fault signal such as **SIGSEGV @ address**, and **Exited 19** or **Killed by
SIGKILL** after the target ends. Hover the stop for its thread, runtime address
and reason. Click it, or choose **Debug → Go to PC**, to return to the PC with
history.

Run control takes one command at a time. Keys that do not apply to the
current state, such as Pause while stopped, do nothing. Opening another binary
or project, reopening a changed file, closing the binary, and quitting each end
a live session without asking, and the status bar notes it. Quitting waits up to 1.5 seconds for GDB and
the target to end.

## Try a breakpoint from the Rust API

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
Windows debugger support are outside this backend's scope. The desktop does
not yet show registers, the stack, or memory, and has no step over, step out,
or run to cursor.
