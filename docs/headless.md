# Headless analysis API v1

`ghidra-rust-headless` is a console program backed by the same contained worker
and bounded result store as the desktop. It creates no window or OpenGL context.
The Rust controller is public as `ghidra_rust::headless::Analyzer`.

The console is the initial transport for future service integrations. There is
no HTTP listener, authentication service, cloud storage, or device sync in this
version. The desktop currently keeps its existing controller. Both controllers
use the same engine, project format, result coordination, and worker transport.
GUI dependencies are still part of the build; this is not a minimal core-only
Cargo configuration. Java and Python are not runtime requirements.

## Start a session

From source:

```sh
cargo build --release --locked
printf '%s\n' '{"api_version":1,"id":1,"command":{"kind":"info"}}' |
  target/release/ghidra-rust-headless --binary ./program
```

The native Linux tarball and Windows ZIP include the headless executable and
this guide. The desktop in-app updater replaces only the desktop executable;
install a fresh archive to update the headless tool too. On Windows use `ghidra-rust-headless.exe`; it retains the console
subsystem in release builds. `cargo run --release --locked` still starts the
desktop by default. The headless target can also be run with
`cargo run --release --locked --bin ghidra-rust-headless -- --help`.

Bind to a binary using `--binary PATH`, or reopen a portable project with
`--project PATH`. An external project additionally requires `--binary PATH`;
source hints never select files automatically. Embedded projects supply their
own verified image and reject an additional `--binary` option.

Configure checkpoint destinations at startup using `--output-project PATH`.
Commands never carry paths or select worker executables. Hosts wrapping the API
must choose these capabilities themselves. A session always belongs to one
verified binary. Start a new process to change it.

## Framing and commands

Each stdin line is one UTF-8 JSON request. IDs are nonzero unsigned 64-bit
integers and must strictly increase for accepted requests. Addresses are JSON
unsigned integers, in decimal. Clients must preserve 64-bit integers exactly;
JavaScript clients need a lossless JSON decoder rather than rounding large
addresses through `Number`. Version 1 produces exactly one terminal JSON
reply per request, with the same ID:

```json
{"api_version":1,"id":1,"command":{"kind":"info"}}
```

Successful replies contain `result`; failed replies contain `error` with a
snake-case `code` and a bounded `message`. Malformed requests use an available
numeric ID when one can be safely recovered, otherwise `null`. Ordinary command
errors are returned as data; a successful process exit does not mean every
command succeeded. Startup and transport failures exit unsuccessfully. Help and
version options produce conventional text instead of JSON.

| Command | Fields | Result |
| --- | --- | --- |
| `info` | — | Verified image metadata, known functions, unapplied saved signatures |
| `annotations` | — | Preserved session annotations, local overrides and signatures |
| `function` | `address`, optional `refresh` (default false) | Listing/CFG, pseudocode, exact mappings, semantics, per-component origin, cache hit |
| `discover` | — | One bounded discovery step and its committed snapshot, with `complete` |
| `strings` | `minimum_length` | ASCII / printable-ASCII UTF-16LE scan results and truncation flag |
| `crypto` | — | Heuristic constant matches and truncation flag |
| `bytes` | `address`, `length` | A mapped range, at most 64 KiB, including mapped zero fill |
| `linkage` | `cursor`, optional `digest` | A validated imports/exports page and its summary |
| `save_project` | optional `embed_binary` (default true) | Atomic checkpoint at the configured output path and stored function count |

Start linkage at cursor 0 without a digest. Continue with the exact returned
`next` cursor and summary digest until `next` is null. Intermediate accumulation
shares the session memory budget and is released after the final page. A new
cursor-0 request restarts the fetch.

A discovery call may inspect metadata before examining instructions, so its
snapshot's function-batch count can remain zero initially. Repeat while
`complete` is false. Completion means the bounded run has no queued/scanning
work; it does not prove exhaustive code coverage. Inspect the snapshot's
`partial`, capped, failed and limited results. Saved discovery is display data;
an explicit discovery run always begins fresh rather than trusting saved
completion claims. Inventory changes invalidate incompatible function results.

Function `graph_origin` and `decompiled_origin` are `computed` or `saved`.
`cache_hit` reports whether both components were already available for this
request. A hit may still be saved analysis; binary hash matching does not
authenticate cached results. `refresh: true` recomputes both components.
Signatures and effective function names are replayed before analysis, and saved
local overrides accompany each decompilation. Editing annotations, prototypes,
or local overrides is not exposed by this version; existing records survive
checkpointing.

For example, after obtaining an address from `info`:

```json
{"api_version":1,"id":2,"command":{"kind":"function","address":4198400}}
{"api_version":1,"id":3,"command":{"kind":"save_project","embed_binary":true}}
```

The address above is illustrative; use a real executable file-backed entry in
your own image. Selection in checkpoints follows the last requested function;
opening and immediately saving a project preserves its exact prior selection.

## Limits and lifecycle

- Requests are at most 64 KiB. Oversized frames produce an error and close the
  stream; their remainder is never interpreted as another request.
- Replies are at most the shared 32 MiB worker-reply budget. Responses are
  completely encoded before publication; an oversized response becomes one
  small error frame. An interrupted output write cannot be retried safely.
- Each worker request has the desktop's 30-second wall-time ceiling. Progress
  events are validated internally and never extend the deadline. A function
  operation can require separate graph and decompiler requests; startup may
  replay several bounded name batches. File I/O and response writes are not
  covered by the worker deadline.
- The same input, graph, pseudocode, discovery, scan and project budgets apply
  as on the desktop. Function results use the shared 64 MiB session store;
  worker memory, input snapshots, preparation, discovery metadata and client
  response copies are additional. Project checkpoints retain the schema-v5
  function-count and serialized-byte caps. Oversized/evicted results are
  recomputed on demand.
- The Rust `CancellationToken` lets another thread stop in-flight analysis.
  Cancellation, timeouts, malformed worker replies and worker errors close the
  worker and require a new analysis session. Dropping the controller stops and
  reaps its worker; extracted-image ownership survives through reaping.
- EOF closes the console after the current command. Terminating the console
  closes its worker containment as well. A service wrapper can use the Rust
  cancellation token when a client disconnects.

Linux requires bubblewrap, working unprivileged user namespaces, and the normal
native dependencies described in [the Linux guide](linux.md). Windows uses its
existing resource-limited jobs and watchdogs; it provides no filesystem/network
sandbox for hostile inputs. Project SQLite parsing also runs in the parent,
outside worker containment. Use trusted projects. macOS remains unvalidated.

For Rust callers, select a trusted executable supporting `--analysis-worker`,
then pass `Input` and `Options` to `Analyzer::open`. The console binary is the
recommended worker executable; it needs no display. Do not let remote requests
choose that executable or the host's input/output paths.
