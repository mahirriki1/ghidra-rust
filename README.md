# Ghidra Rust

An early alpha native Rust reverse engineering desktop with Ghidra-derived
decompilation and IDA-inspired function-graph navigation. The desktop runs without
Java or Python. It is an initial implementation, not a full Ghidra replacement.

## Run

Use Rust 1.98 or newer, a native C/C++ build toolchain, and an OpenGL-capable desktop.
Linux analysis requires **bubblewrap** (`bwrap`) and working unprivileged user
namespaces. The Linux sandbox setup currently targets conventional `/usr`-based
distributions. Windows x64 has an experimental native MSVC build path and
Windows-specific file identity and worker resource controls. See the
[Windows build/run guide](docs/windows.md) for the portable package, validation
script, and desktop check. macOS remains unvalidated.

```sh
cargo run --release --locked
```

Use **Open binary**, **Open project**, or drop a file into the window. You can also pass a file path
when launching the desktop executable. The initial engine build can take several
minutes. Release builds are appropriate for evaluating interactive performance.

For downloadable Linux/Windows packages and the workflow to ship every version,
see [building and shipping releases](docs/releases.md). Version tags build both
platforms and retain executables, complete archives, and checksums as workflow
artifacts. [Linux runtime requirements](docs/linux.md) include compatible glibc,
desktop graphics, and bubblewrap; Linux downloads are not universal static builds.

### Native Windows

For a prebuilt download, double-click `ghidra-rust-VERSION-windows-x64.exe` from a
local Windows folder to open the GUI directly. No build tools are required to run
it. The ZIP bundle includes documentation and the accompanying license notices.
See the [Windows guide](docs/windows.md#run-the-prebuilt-exe).

Install Rust and Visual Studio Build Tools with **Desktop development with C++**
(including an x64 MSVC toolchain and Windows SDK), as described in
[Microsoft's Rust setup guide](https://learn.microsoft.com/en-us/windows/dev-environment/rust/setup).
From PowerShell in this repository on Windows:

```powershell
rustup toolchain install 1.98.1-x86_64-pc-windows-msvc --component rustfmt,clippy
cargo +1.98.1-x86_64-pc-windows-msvc build --release --locked --target x86_64-pc-windows-msvc
.\target\x86_64-pc-windows-msvc\release\ghidra-rust.exe
```

The built desktop is `target\x86_64-pc-windows-msvc\release\ghidra-rust.exe`. It uses native Windows
OpenGL and does not need WSL, bubblewrap, Java, or Python. Build it from a Windows
checkout rather than copying the Linux executable. SQLite is bundled into the
build, and the MSVC runtime is linked statically; a separate SQLite or MSVC runtime
installation is unnecessary. Local disk files are
supported; device paths, alternate streams, UNC paths, and mapped network drives
are rejected. File systems must support the Windows file-ID APIs.

For the full Windows checks and a ZIP with licenses, run:

```powershell
rustup run 1.98.1-x86_64-pc-windows-msvc powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows.ps1
```

The standalone EXE, ZIP, and SHA-256 checksums are written under `target\dist`. Extract the ZIP and
double-click `ghidra-rust.exe`. The Windows CI job uses this same script and retains
the package as a workflow artifact after successful checks. See
[Windows instructions and troubleshooting](docs/windows.md) for details.

Windows worker limits are resource controls, **not a security sandbox**. Use this
experimental Windows build with trusted inputs. It has no filesystem or network
isolation equivalent to the Linux worker.

The workspace follows Ghidra's familiar layout: Symbol/Program Trees and Functions
on the left, the Listing or Function Graph in the middle, and the Decompiler on
the right. Annotation editing opens in a separate tool window. File selection is
built into the app and does not require a desktop file-dialog portal.

The default appearance keeps Ghidra's classic layout in dark mode: charcoal toolbars
and provider headers, dark analysis views, rectangular controls, and colored listing
columns. Decompiled code uses Ghidra's dark syntax palette for keywords, types,
comments, constants/strings, and identifiers. Highlighting is lexical; semantic
roles such as parameters versus globals require richer engine token information.
Text is tokenized when a new result arrives and visible lines are drawn from cached
spans. The cache is capped at 65,536 spans; unusually dense results fall back to
plain text while retaining the complete pseudocode for copying.

![Dark native desktop with symbols/functions, listing, and decompiler](docs/images/desktop-dark-listing.png)

## Keyboard and navigation

- **L:** rename the selected function entry or set an address label. The existing
  name is selected; **Enter** applies and **Escape** cancels. Labels and function
  renames are saved in projects or exported JSON annotations. Local-variable renaming is deferred.
- **G:** go to a hexadecimal address or an exact known function/label name.
- **;:** open the comment editor at the selected address.
- **Space:** switch Listing / Function Graph.
- **Alt+Left / Alt+Right:** history, also available through the top arrow buttons.
- **Ctrl+S / Ctrl+Z:** save project / undo an annotation outside text editors
  (Command on macOS).

Shortcuts do not fire while typing, using a dialog, or waiting for file operations.
Double-click a resolved call instruction in the listing or graph to navigate to
its target. In the decompiler, double-click a recognized function name with an
unambiguous known call target; strings, comments, unresolved calls, and ambiguous
names do not trigger jumps. Decompiler navigation currently requires matching
function names for call-target jumps.

Selecting an instruction in the Listing or Function Graph highlights the
corresponding pseudocode statement/expression. Clicking a mapped pseudocode
statement selects its associated instructions, scrolls the listing, and reveals
the selected CFG block. These links come from the engine's p-code print marks,
not line-number or text matching, and are saved in projects. One expression may
correspond to several instructions. Instructions removed during optimization,
unmapped declarations, and results outside the bounded graph can have no visible
counterpart; the app does not invent one. Double-clicking a known call still
navigates to that function.

![Selected CFG instruction and corresponding pseudocode](docs/images/desktop-selection-sync.png)

## Current workflow

- Open linked x86/x86-64 ELF, PE, or Mach-O images with file-backed mapped sections.
  Other architectures, raw images, archives, relocatable objects, and sectionless
  images are currently rejected explicitly.
- Browse/filter known functions; start at `main` when found, otherwise the entry
  point. PE exports and x64 exception-table function entries load on open, including
  stripped images. The list is capped at 10,000 entries; large PEs prioritize the
  entry point, exports, and runtime functions near entry, with a visible partial-list
  notice. **Discover functions** explicitly runs additional engine discovery.
  Complete function recovery is not guaranteed.
- Navigate a function's instruction CFG with pan, zoom, branch labels, and
  unresolved-flow markers. CFG recovery is bounded; warnings identify unsupported
  or incomplete cases such as indirect flow. Calls are displayed separately from
  intra-function branches.
- Switch between the graph and listing. Read separately requested C-like
  decompilation, inspect outgoing direct calls, and navigate by address.
- Scan mapped bytes for ASCII and a printable ASCII subset of UTF-16LE strings.
  The tree shows **not scanned** until a scan runs. This is not complete Unicode
  or Rust string-slice recovery. **Analysis notes** shows loading and coverage limits.
- Use **Decode** for selected memory or pasted text/hex: UTF-8, UTF-16LE/BE,
  standard padded Base64, hex, or XOR. XOR keys use explicit `hex:` or `text:`
  prefixes. Common-decoding suggestions are heuristics and require analyst review.
- Use **FindCrypt** for a small independent set of standardized crypto constants.
  Results are navigable candidates, with algorithm-family ambiguities preserved.
  See [signature coverage and provenance](docs/crypto-signatures.md). This is not
  parity with every FindCrypt database and does not recover encryption keys.
- Save a `.grproj` project, or export/import the existing versioned JSON annotation
  sidecars. Both are bound to the binary's SHA-256. The app does not patch binaries
  or write Ghidra/IDA project databases.

## Project files

**File → Save project** or **Ctrl+S** creates a single SQLite `.grproj` file.
It stores function names, comments, decoded annotations, the known function list,
the current function's graph/listing and pseudocode, string/crypto scan results,
and the selected address. It is a snapshot of these results; it does not serialize
the upstream decompiler's complete internal database or all previously visited
functions. The engine reopens the binary before accepting saved results.

**File → Include binary in project** is enabled initially. Keeping it checked
embeds the exact analyzed binary, so the project can move between Linux and
Windows without the original file. Uncheck it for a smaller file; opening that
project explicitly asks you to locate the binary and verifies its SHA-256.
Stored source paths are display hints and are never opened automatically.
**Save project as** creates another copy. Saved graph/pseudocode is marked
**Saved analysis**; **Analysis → Refresh function** recomputes it. A changed
engine fingerprint discards cached results and retains compatible annotations.

Saving builds and syncs a new database beside the destination, then replaces the
destination atomically. A complete project needs no `.rep`, WAL, or other database
companion directory. Original input identities and matching binary destinations
are protected from overwrite. **Export annotations (JSON)** keeps the earlier
sidecar workflow available; exporting JSON does not mark an existing project saved.
There is no autosave or Ghidra `.gpr`/`.rep` or IDA `.i64` import compatibility.

Projects are untrusted persisted data, not authenticated analysis. A matching
binary hash does not prove that saved pseudocode or comments are accurate. The
loader checks versions, schema, mappings, collection bounds, and binary identity,
but SQLite currently parses the private project snapshot in a GUI background
thread rather than a sandboxed process. Use projects from trusted sources.

C++ and Rust binaries use the supported machine-code analysis path. Available
symbol demangling comes from the upstream engine; MSVC demangling, sophisticated
class/trait recovery, and reconstruction of original source are not provided.
Decompiler location links refer to machine instructions in the current function;
they do not provide source-level variable/type editing or recovery of the
original source language.

## Responsiveness and boundaries

Engine work runs in a disposable subprocess. Navigating while analysis is busy,
canceling, a transport failure, or a 30-second wall-time limit stops that worker.
The next action can reopen it. UI results are bound to the current request,
selection, and annotation state. Dialogs, session I/O, and decoding jobs run in
background threads. Lists draw visible rows and graph geometry is cached.

Linux workers run under bubblewrap with private namespaces, no network, read-only
`/usr`, a read-only executable, and only the selected input file exposed from the
user's data. The analysis image is immutable for the session. Linux workers also
have a 2 GiB address-space cap, no core dumps, no privilege escalation, and a
per-request CPU soft budget of about 20 seconds. These controls reduce exposure;
they do not establish that this application or its upstream engine is free of
vulnerabilities. Windows workers start suspended, join a kill-on-close job with
a 2 GiB process-memory limit and one-process limit, then resume; they also have a
per-request CPU watchdog. Windows jobs do not isolate filesystem/network access.
Other non-Linux process sandboxing has not been implemented.

Prototype resource limits include 128 MiB input files, 2,048 recovered instructions
and 128 blocks per graph, 64 KiB byte selections, bounded function/result lists,
64 MiB scanned data, 2 MiB decompiler text, 32,768 semantic ranges with at most
64 instruction addresses each and 131,072 total address references, 8 MiB annotation
sidecars, and 192 MiB projects. The
snapshot currently duplicates image bytes retained by the engine; total memory
must be measured before making efficiency claims.

Function-list and decompiler-text limits bound returned results, after the engine
has constructed its internal data. They are not preallocation limits inside the
upstream engine. Linux address-space/CPU limits, Windows job/watchdog limits, and the GUI deadline contain
resource failures in that worker. Stable original-file identity is also retained
outside the worker so renaming/replacing the input pathname cannot defeat session
write protection. Platforms without the implemented identity support fail closed.

If the local Wayland/Mesa setup cannot initialize OpenGL, this X11 software-rendering
configuration is useful for troubleshooting:

```sh
env -u WAYLAND_DISPLAY LIBGL_ALWAYS_SOFTWARE=1 cargo run --release --locked
```

Software rendering is a compatibility option, not a performance optimization.

## Development and validation

```sh
cargo fmt --all --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

Linux process integration tests compile the small original C fixture using GCC.
Unit tests cover real x86 CFG behavior, malformed/bounded requests, immutable image
reads, decoding, signature detection, session identity/write protection, and GUI
components rendered without a display.

The pinned analysis dependency is
[`koute/ghidra-decompiler`](https://github.com/koute/ghidra-decompiler/tree/268c3a406d8d964bc00ae2ead4d3e1e1373aaa27)
at commit `268c3a406d8d964bc00ae2ead4d3e1e1373aaa27`. It supplies the engine and
embedded language data; a separate Ghidra source checkout is unnecessary for
building or running this desktop.

The Linux prototype passed unit/UI tests, real worker-process integration,
production bubblewrap worker/project integration, formatting, strict Clippy, and
an optimized build. Native GUI checks exercised
the three-pane layout, graph/decompiler navigation, string decoding, crypto scanning,
manual file-path entry, and saving/reopening annotations and an embedded project.
Native Windows x64 validation with Rust 1.98.1 and MSVC compiled bundled SQLite,
linked debug and release executables, and passed unit/UI tests plus the real
PE worker/project integration test in both debug and release. One ignored unit
test is a subprocess fixture exercised by the job-lifecycle test. The release
OpenGL GUI was launched on Windows and used to save and reopen an embedded
project with saved listing/pseudocode. The EXE imports Windows system DLLs without
MSVC-runtime or SQLite DLL dependencies. These are local results; consult GitHub
Actions for hosted results for the exact commit. The Windows build script is
shared with CI.

PE loading supplies export names, x64 runtime-function starts, and named import
slots to the decompiler. Ordinary import jump thunks reached by confirmed calls
are named during bounded function analysis. PDB types, imported API prototypes,
library signature matching, delay imports, and Windows Control Flow Guard
substitutions remain incomplete. Known hexadecimal addresses remain navigable.
The PE integration tests check named exports and recovery after exports are removed.

The PE analysis update invalidates older saved graph/decompiler caches when a
project reopens; compatible annotations are retained. When comparing against a
Ghidra project, compare the recorded executable SHA-256 and the selected function
address. An installed program can change at the same path after an update.

The Windows sandbox and project-parser trust limitations above remain explicit;
the application has not had a comprehensive security or dependency audit. One stalled directory read
can still remain blocked, but repeated cancellations cannot accumulate reader threads.
Final publication is not relative to retained directory handles; same-user parent
directory substitutions and Windows delete-sharing renames remain residual races.
Existing Java plugins, a general plugin SDK, Python scripting, a user-facing CLI,
debugger integration, type/variable editing, automatic custom decryption, and
Ghidra project import are later work. Performance improvements over Ghidra have
not yet been measured.
