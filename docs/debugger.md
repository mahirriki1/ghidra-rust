# Linux live debugger backend

The Rust `debugger::Debugger` API runs a local x86-64 Linux ELF executable
under GDB. It supports breakpoints, pause, continue, instruction stepping,
stack frames, general registers, and reads of up to 64 KiB of live memory.
The desktop listing and headless JSON API have no live debugger commands yet.

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
`step_instruction`. `wait` reports `Running`, a stop, or exit. A wait that
expires leaves the running target available to `pause`. Individual GDB requests
have a five-second deadline. Perform these calls on a background thread.

A stopped address maps back to the static image only when it agrees with the
kernel's relocated entry point, an executable mapping of the same file, and a
file-backed analyzed code section at the same file offset. Stack frames from
other images can still show their runtime address and GDB's symbol text.

## Execution limits

Launch only executables you trust to run under your account. Live sessions
execute the selected program with your permissions, outside the static
analysis worker's sandbox. GDB initialization files, auto-load scripts, and
debuginfod are disabled. This first backend supports one locally launched
process with all threads stopped for inspection. Standard input and output
for the target go to `/dev/null`. The API tracks and cleans up the direct
debuggee. If that process replaces its executable with `exec`, the session
ends before the replacement runs. Child processes are outside its supervision.

Attach, remote targets, live memory writes, saved traces, emulation, and
Windows debugger support are outside this backend's scope.
