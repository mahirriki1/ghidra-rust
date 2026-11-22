# Headless analysis API v1

Use `ghidra-rust-headless` to analyze a binary or checkpoint a project without
a desktop window or OpenGL context. The native archives include the console
binary. Install a fresh archive to update it. The in-app updater replaces the
desktop executable only.

## Start a session

```sh
cargo build --release --locked
printf '%s\n' '{"api_version":1,"id":1,"command":{"kind":"info"}}' |
  target/release/ghidra-rust-headless --binary ./program
```

On Windows, run `ghidra-rust-headless.exe`. Use `--help` for the complete
startup syntax.

| Startup option | Purpose |
| --- | --- |
| `--binary PATH` | Analyze a binary, or provide the matching image for an external project |
| `--project PATH` | Reopen a project. Embedded projects supply their own image and reject `--binary`. |
| `--output-project PATH` | Allow commands to save a checkpoint at this path |
| `--no-debug-info` | Open without reading debug info or any companion file |
| `--use-debug-info` | Re-enable debug info for a saved project and clear its saved per-function skips |
| `--debug-info PATH` | Use this Mach-O dSYM companion. Project paths never select one. |

A session belongs to one verified image. Start a new process to change it.
Project source hints never select a file automatically.

## Framing and commands

Send one UTF-8 JSON request per stdin line. Each request uses `api_version: 1`
and a strictly increasing, nonzero unsigned 64-bit `id`. Addresses are
unsigned JSON integers in decimal. Preserve 64-bit values exactly, including
when using JavaScript clients.

Every request line gets one terminal reply with either `result` or `error`.
Errors have a snake-case `code` and a bounded `message`. A rejected request
consumes its ID if that ID is new and increasing. A missing, zero, unreadable,
or non-increasing ID gives `"id": null`. Command errors are reported in JSON.
Startup and transport failures return a failing process exit status.

| Command kind | Fields | Result |
| --- | --- | --- |
| `info` | — | Verified image metadata, debug setting and status, known functions, unapplied saved signatures |
| `annotations` | — | Session annotations, local overrides, and signatures |
| `function` | `address`, optional `refresh` (false) | Listing/CFG, pseudocode, mappings, semantic data, origins, cache status |
| `discover` | — | One bounded discovery step, committed snapshot, and `complete` |
| `strings` | `minimum_length` | ASCII and printable-ASCII UTF-16LE results, with truncation status |
| `crypto` | — | Constant matches and truncation status |
| `bytes` | `address`, `length` | Up to 64 KiB of mapped bytes, including zero fill |
| `linkage` | `cursor`, optional `digest` | Validated imports/exports page and summary |
| `save_project` | optional `embed_binary` (true) | Atomic checkpoint and stored function count |

In a session started with `--output-project PATH`, send these lines after
`info`. Replace `4198400` with a function entry from that reply.

```json
{"api_version":1,"id":2,"command":{"kind":"function","address":4198400}}
{"api_version":1,"id":3,"command":{"kind":"save_project","embed_binary":true}}
```

- **Function** reports `graph_origin` and `decompiled_origin` as `computed`
  or `saved`. `cache_hit` means both components were available and may have
  saved provenance. Use `refresh: true` to recompute both. Checkpoints retain
  existing annotations and track the last requested function. Opening and
  saving without a function request preserves the previous selection.
- **Discover** runs one step per call. Repeat until `complete` is true and
  check the snapshot for partial, failed, and capped work. Completion means
  the queue and scans are exhausted. An explicit run starts fresh from a
  reopened project.
- **Linkage** starts at cursor 0 without a digest. Pass each response's
  `next` cursor and summary digest until `next` is null. Start at 0 to
  restart a failed or unfinished fetch.

## Debug information

Debug info is on for a new binary. A reopened project keeps its saved
setting. The Rust `Options` equivalents of the startup options are
`use_debug_info: Some(false)`, `use_debug_info: Some(true)`, and
`debug_info: Some(path)`. These additions keep the API at version 1.

- **Function** semantics include `prototype_source`: `inferred` or
  `debug_info`.
- **Info** adds `use_debug_info` (the effective setting), `debug_status`
  (`enabled`, `disabled`, or `disabled_after_open_failure`), and
  `debug_skipped_functions`. The status describes the setting, not whether
  a given function has usable DWARF.
- If Open fails or times out with debug info on, the controller retries once
  with it off and adds a warning to `info.warnings`. Checkpoints save the
  disabled setting and the warning, so later opens keep both. A successful
  Open with debug info explicitly enabled clears the warning. Nothing turns
  debug info back on automatically.

Each `function` command still returns one response. The worker finishes the
ordinary inferred render first. Optional DWARF work then runs in a disposable
fork on a single-threaded Linux worker, or in a separate single-use sibling
worker on Windows and with threaded workers. The response carries the checked
debug render if it was accepted in time, or the inferred render with a
warning. A sibling has its own setup budget before its render budget. When
setup runs out, the result keeps inference with `Debug setup timed out`, and a
later `refresh: true` can still upgrade it. Cancelling while an earlier
sibling is still being reaped ends the command at once with `cancelled`.
[Budgets and warnings](analysis.md#debug-information)

The controller keeps verified prototype decisions and can reuse a clean
debug render while the program context and its call dependencies still match.
PE requests bypass this reuse. `refresh: true` renders anew with the current
decisions. A later `save_project` saves the result with its origin and
signature provenance.

If the worker exits (including at its CPU limit) or misses its deadline
before it returns usable pseudocode, the controller starts one fresh worker
for the same verified image and context. That worker renders the function once
with inference only. No skip is recorded, and Info, the project, and later
opens are unchanged. The function keeps `Debug prototype is unverified` when it
has debug data, and a later `function` or `refresh` can still apply the
prototype. If the retry also fails, the command reports the ordinary error and
the worker stays stopped. Rejected or mismatched replies, engine errors, and
cancellations are never retried this way. A command that needs this retry can
take longer than one worker timeout.

`debug_skipped_functions` lists skips saved by earlier versions, at most
1,024. They still apply, and those functions report `Debug prototypes skipped
for this function after a worker failure`. `--use-debug-info` clears the list.
An engine error in a debug render keeps the function's inferred render, with
`Debug prototypes skipped for this function after a decompiler error`.

## Limits and lifecycle

- Request lines are capped at 64 KiB. An oversized line returns an error
  and closes the stream. Replies are capped at 32 MiB and encoded before
  publication. An oversized reply is replaced by a small error.
- A worker request has a 30-second deadline. A command can use multiple
  requests. File I/O and console output have separate lifetimes.
- On a failed discovery step, completed batches stay committed. Failed
  seeds or interrupted scans get one retry. A later `discover` may start
  a verified replacement worker and replay names and signatures. At most
  three replacement attempts are allowed per session.
- A stopped worker leaves committed results in the controller. `info`,
  `annotations`, and `save_project` remain usable. Other analysis commands
  return `session_closed` until discovery starts a replacement. Engine errors
  in `function`, `discover`, `strings`, and `crypto` stop the worker and return
  `worker_failed`. Engine errors in `bytes` and `linkage` return
  `command_failed` and leave the worker running.
- The Rust `CancellationToken` stops in-flight analysis permanently for the
  session. EOF closes the console after the current command. Closing the
  controller reaps the worker before releasing an extracted image.

The Rust integration is `ghidra_rust::headless::Analyzer`. Pass a trusted
executable that supports `--analysis-worker`, plus `Input` and `Options`, to
`Analyzer::open`. The console executable supports this worker mode. A service
wrapper must choose the worker and file paths itself. Version 1 provides
a console and Rust API. HTTP, authentication, cloud sync, and annotation
editing are outside its scope. [Controller](../src/headless.rs) ·
[Console protocol](../src/headless/protocol.rs)

The platform limits also apply here. Linux needs bubblewrap and working
unprivileged user namespaces. Windows workers retain filesystem and network
access. SQLite parses projects in the parent process. Use trusted Windows
inputs and trusted projects. [Trust boundaries](analysis.md#resource-limits-and-trust-boundaries)
