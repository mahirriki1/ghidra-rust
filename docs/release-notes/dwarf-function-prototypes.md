- The Decompiler can use bounded same-file DWARF function parameter names,
  scalar/pointer/typedef types and return types. Pointers to named structures
  show the structure name with an opaque one-byte pointee (fields are not
  modelled); the engine never receives a zero-size structure, which previously
  made some renders fail with a division by zero. Applied user signatures take
  precedence; verified user local renames retain their existing identity rules.
- **Analysis → Use debug info** controls debug prototypes per binary and is
  saved in projects. Switching it restarts analysis and refreshes pseudocode.
  Debug-owned prototypes show **Debug info signature**.
- Project schema 6 records debug state. Older projects remain readable;
  changing debug state invalidates pseudocode while retaining graphs and notes.
- Local-variable names, aggregate layouts, variadic prototypes, PDB, split DWARF
  and compressed DWARF remain unsupported. Unsupported or ambiguous prototypes
  retain inferred signatures.
- DWARF prototype reading covers ELF, PE and thin Mach-O on the supported
  x86-32, x86-64 and AArch64 ABIs; dSYM companions are arm64 only.
  Unsupported register/storage combinations
  retain inference. Aggregate layouts and source local names remain unchanged.
- Mach-O can use embedded DWARF, an automatically discovered adjacent dSYM,
  or **Analysis → Load debug info…**. Companions must match LC_UUID and the
  baseline arm64 slice, are limited to 128 MiB, and are parsed only by the worker; the desktop independently verifies their hash.
  Linux binds only the securely opened candidate inode read-only. Projects record path,
  UUID and SHA-256; signature provenance exposes them and reopen verifies again.
  Companion identities are retained to protect aliases against project/annotation
  saves. Windows worker containment remains resource-only.
- Register-input and x86-32 return-stack checks veto non-default conventions
  even when GCC omits DWARF convention or location markers. The locked render
  adds a second input check, and both passes keep evidence even when the
  recovered CFG misses switch destinations. A return-type disagreement alone
  can reflect a tail call or a missed result, so it leaves the DWARF type in
  place.
- The desktop shows ordinary inference as soon as it is available, then
  applies a checked DWARF result in place when the optional render succeeds.
  Selection, scroll position and navigation history are preserved. Saving
  during the optional render captures the inferred pseudocode currently
  visible. Headless `function` returns one terminal v1 response.
- Optional rendering uses a disposable fork in a single-threaded Linux worker
  and a separate, single-use worker on Windows or with a threaded primary.
  A timeout or failure after the ordinary render keeps usable inferred code
  and never adds a saved per-function skip. A sibling verifies its image and
  recaptured analysis before applying prototypes. Both executors receive the
  controller's decisions for eligible entries and can use a verified callee
  after it has been visited directly. Cancelled and superseded requests leave
  decisions and reusable results unchanged.
- A sibling (always used on Windows) has a separate setup budget for peer
  startup, Open and replay. It starts when the inferred result is published:
  two seconds at first, then twice the image's measured setup time, between
  one and five seconds. The render budget of three times the ordinary render,
  at least three seconds, starts only when the peer is ready. When setup runs
  out, no render is sent. The function keeps its inferred prototypes with
  `Debug setup timed out` and nothing is recorded against it. A later Refresh can still upgrade. The `performance`
  host trace records each sibling phase and the one cutoff reason. No
  Windows latency improvement is claimed from Linux measurements.
- Fixed: after a worker stopped before the ordinary render, the desktop's
  one inference-only retry could still be sent after navigation to data.
  Its result could replace the decompilation while Hex was selected. The
  retry now travels with its own queued request, original selection and
  refresh setting. Function or data navigation, an annotation edit or a new
  Refresh drops it before anything is sent, and Cancel stops it while the
  replacement worker starts or replays. A stopped Refresh retries as a
  Refresh once. A full-function Refresh carries its refresh from the graph
  to the decompilation. A function rename acknowledgement no longer reopens
  the code view over a data selection.
- Limitation: after renaming a function while data is selected, the
  decompiler pane keeps showing the previous name until that function is
  shown again, which renders it with the new name.
- Fixed (desktop): a sibling whose setup budget was already spent when its
  optional render could start, or whose image's peer slot was still held by
  a retiring peer, settled with the generic unverified warning. The desktop
  now checks a busy slot again on each repaint without blocking, starts the
  peer once the slot is free, and reports `Debug setup timed out` when the
  setup budget runs out, as headless does.
- Fixed: a sibling setup cut off after a late launch (for example behind a
  retiring peer) could shorten the next setup budget below the two-second cold
  budget. A cut-off setup now never shortens the next budget.
- Fixed: a headless sibling waiting for an earlier peer to be reaped ignored
  cancellation until its deadline. It could also reserve a peer just as the
  command was cancelled. The wait is now cancellable and reserves nothing
  once cancelled or past its setup deadline.
- Packaging refuses executables built with the test-only `test-hooks`
  feature. Both the Linux and Windows packagers run their staged executables
  and fail before publishing anything unless each refuses the fault argument,
  also when run directly. Both select one Cargo target directory and one
  release layout, so the probed, archived and standalone executables are the
  same build.
- Fixed: a callee's debug prototype could silently drop a caller's live
  argument at an unrelated call. In libfprint-2,
  `fp_device_async_initable_init_async` (`0xe1d0`) lost its fifth parameter
  and the fourth argument of `g_task_new`, although the machine code copies
  that parameter into RCX for the call, and both renders reported inferred
  prototypes without a warning. The worker now records the caller's real input
  uses and corroborated call arguments (exact machine PC, slot, ABI register
  and value origin) in its ordinary render, and drops the callee prototypes
  when a render with them loses one, showing `Callee debug prototypes omitted
  because this render lost argument evidence`. A function's own prototype is
  checked the same way: in libssl.so.1.1 `SSL_enable_ct`,
  `SSL_set_ct_validation_callback` and `SSL_write_early_data` previously
  dropped the line-number argument of an `ERR_put_error` call; they now keep
  inferred prototypes with `Debug prototype omitted because this render lost
  argument evidence`. Callee prototypes that keep every corroborated argument
  still improve callers. Stack-passed arguments are not yet corroborated.
- A callee accepted from a caller's probe is provisional until its own render
  passes the locked-render check. Two expired direct verifications, or one
  engine error withdraws it from later managed renders in the verified
  program context;
  previously an expiry or error could leave it in use indefinitely. Opening a
  caller first no longer gives a function a debug prototype that opening it
  directly rejects (libfprint-2 `dft_dir_powers`). Caller pseudocode already
  rendered with a withdrawn prototype is kept until refreshed.
- Desktop and headless controllers can reuse a clean, verified render while its
  program context, local overrides and call dependencies still match. The
  managed cache holds up to 64 entries and 8 MiB, with a 2 MiB per-entry limit.
  PE bypasses this cache. Refresh renders anew with the current decisions.
  Projects record debug pseudocode as `debug-dwarf-v8`, so pseudocode saved by
  earlier rules is recomputed while graphs and annotations are kept.
- Function-name replay acknowledges names longer than the inventory limit.
  During a decompiler upgrade, local actions follow a matching full variable
  identity and call actions follow an unambiguous exact machine call site.
  Rewritten text clears obsolete character selections.
- Historical raw-worker timing (Linux release workers on 2026-11-18, wall
  time to the single terminal reply, every function per pass): debug-enabled
  decompile took about 2.4× debug-off time for
  libssl.so.1.1 and 2.6× for libfprint-2, against 1.87× and 1.61× for the
  previous build in the round-9 review (at higher, uneven load). The increase
  reflects waiting for the optional work after the ordinary render. These
  timings predate the desktop’s two-stage display.
  Functions under 20 ms gained a median 9 ms and 16 ms. Debug-owned prototypes
  fell from 770 to 763 (libssl) and 956 to 950 (libfprint), mostly where a
  prototype dropped an argument the machine code passes.
- Abbreviation preflight and shared-table caches bound attribute work and memory;
  exhausted budgets report Partial. Budgets now fit large C++/Rust images, and a
  malformed abbreviation table loses only its own units. Open retries once
  without debug info after a worker failure. Disabling debug info avoids all
  companion access.
- Linkage and function names up to 256 bytes match their symbols (most C++ and
  Rust names were previously skipped). Assembler and name-only units such as
  GCC/G++ `-g1` and Rust `debuginfo=1` keep inferred prototypes, including the
  precompiled Rust standard library where it ships limited debuginfo.
  GCC IPA clones and entries whose names conflict with their abstract origin
  retain inferred signatures. Ordinary LTO entries can inherit types from a
  matching source unit. Nesting up to 255 levels and very large function bodies
  remain supported.
- Companion resolution rejects symlink/reparse components, directories and special
  files. Project-recorded paths are hints; non-automatic companions require
  explicit selection. Debug actions respect file/open/signature operations.
- Headless hosts can disable debug info or explicitly select a companion using
  CLI options or Rust Options. Reused scalar types no longer exhaust a cumulative
  resolution-step limit based on navigation order.
- Prototype indexing and lazy extraction avoid unused DWARF line programs and
  directory/file tables. Numeric table bases use checked lookups without eager
  header allocation. Shared CU metadata is cached during extraction.
- Location checks bound raw records, including base-address selections, and bytes
  per list and per function. Exhaustion retains inference instead of accepting
  missing entry-register evidence.
- A debug-enabled Open failure now leaves a persistent warning when the retry
  disables debug info. Projects save that disabled setting and warning until
  explicitly enabled again; if the retry fails too, the setting is unchanged.
  Headless Info reports the effective setting and `disabled_after_open_failure`
  status; desktop warnings remain visible.
- Every DIE encoding is validated before eager parsing, including unused
  attributes. Indirect forms, oversized inline strings/blocks/expressions and
  malformed variable integers fall back to inference. Lazy references must
  target validated DIE boundaries; decoded attributes are cached per prototype.
- If the worker exits (including at its CPU limit) or times out before a
  debug-enabled Decompile returns its inferred baseline, that function is
  rendered once more in a fresh worker with ordinary inference only. No
  per-function skip is recorded or saved, because such a stop does not show
  that debug info was the cause; on a loaded host it is usually the ordinary
  render reaching its limit. A later view or Refresh can still apply the debug
  prototype. If the retry fails too, the ordinary error is reported. Rejected
  replies (also late ones), engine errors and cancellations are not retried;
  a reply cut off by the worker's exit counts as that exit, including the
  Windows CPU watchdog's stop, which is now reported as the CPU time limit.
  The retry is accepted only with an inferred prototype. On the desktop it
  belongs to the request that stopped: navigation, data navigation, Refresh or
  an annotation edit while the fresh worker starts retire it, and Analysis →
  Cancel analysis stays available during that startup. Skips saved by
  earlier builds (headless Info lists `debug_skipped_functions`) are still
  honored. An engine error inside the optional debug render keeps the
  function's own inferred render. Headless `--use-debug-info` re-enables debug
  info for a saved project and clears skips.
- Limitation: a function command that needs this recovery can take longer than
  one worker timeout, and a render that reaches its limit in both attempts
  still fails.
- Fixed (Linux): when the analysis worker reaches its per-request CPU budget it
  now exits with status 152 instead of being killed by `SIGXCPU`, so desktops
  no longer report each budget stop as an application crash (for example KDE's
  crash notification). The status bar reports that the CPU time limit was
  reached.
- Fixed (Linux): an analysis worker, debug peer or forked render child that
  aborts or faults (`SIGABRT`, `SIGSEGV`, `SIGBUS`, `SIGILL` or `SIGFPE`) now
  exits with status 128 plus the signal number instead of dumping core, so
  the desktop's crash reporter no longer opens for it. The status bar reports
  the crash and its signal, separately from the CPU time limit. Rust's
  stack-overflow message is no longer printed for such a worker.
- Fixed (Linux): stopping an analysis worker while bubblewrap was still
  setting up its sandbox could leave a sandbox process waiting forever, outside
  `--die-with-parent`. Workers now lead their own process group, which is
  killed as a whole, and are started from one long-lived thread, because
  `--die-with-parent` follows the thread that started bubblewrap, not the
  application.
- Fixed (Windows): a worker starts inside its own resource Job Object, so
  closing the application during startup cannot leave a suspended worker
  holding the executable open. Only its protocol and diagnostic pipes are
  inherited.
- Fixed: completing an optional debug render releases the peer slot before
  publishing the result. An immediate Refresh or function request can use its
  own peer and reuse the verified callee decisions from the completed render.
- Fixed: a file or project request made while another file operation was
  running was dropped silently. It now reports `Wait for the current file
  operation`, and a recovery retry no longer stops the worker when it cannot
  start a replacement.
