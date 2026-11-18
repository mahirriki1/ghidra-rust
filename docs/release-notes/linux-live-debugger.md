- Add a Linux x86-64 Rust debugger backend using an optional external GDB.
  Launch a trusted ELF executable, set breakpoints, pause, step, continue,
  and inspect registers, stack frames, and live memory. Map stopped addresses
  to the verified static image even when ASLR relocates the executable.
- Add a source example that stops at a function breakpoint and prints the
  static and runtime addresses, registers, and stack. Desktop and headless
  JSON controls are future work. Debugging executes the target outside the
  static analysis sandbox and is intended for trusted binaries.
