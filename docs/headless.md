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
| `info` | — | Verified image metadata, known functions, unapplied saved signatures |
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
