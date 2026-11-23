- Add a live debug session controller to the Rust API. It runs each GDB
  session on its own thread and reports one consistent snapshot per stop:
  registers, up to 32 stack frames, and which register values point into the
  analyzed executable.
- Apply breakpoints from a complete desired set. Changes made while the target
  runs apply at the next stop. Each address reports whether it was set, and
  an address that could not be removed is still reported. Sets larger than
  128 addresses are refused.
- Stopping or pausing a session while its launch is still starting keeps the
  target at the loader stop instead of letting it run first.
- Report an unexpected end of the session thread as an ended session with an
  error, so callers never wait for a session that is gone.
- Refuse live memory reads made for an earlier stop or while running.
- Report the signal of a stop or exit, so a pause shows `SIGINT` rather than
  looking like a fault.
- Refuse a second breakpoint at the same static address.
- Report a missing GDB as "GDB is required at /usr/bin/gdb" instead of an
  I/O error.
- The debugger types now build on every platform. Live debugging still
  requires Linux x86-64, and the desktop and headless JSON API have no live
  debugger commands yet.
