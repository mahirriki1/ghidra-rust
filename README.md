# <img src="docs/images/ghidra-rust-logo.svg" width="40" height="40" alt="Ghidra Rust logo"> Ghidra Rust

An early-alpha native Rust reverse-engineering desktop with Ghidra-derived
decompilation and function-graph navigation. Its long-term goal is a faster,
more modern replacement for Ghidra's everyday analysis workflow.

Today it is an experimental subset, not a complete Ghidra or IDA replacement.
The desktop runs without Java or Python. [Measured comparisons and their scope](docs/analysis-performance.md)
are recorded separately; no general speed advantage over Ghidra is claimed yet.

![Function graph with linked instruction and pseudocode selection](docs/images/desktop-selection-sync.png)

## Highlights

- Familiar layout: symbols and functions on the left, Listing / Function Graph
  in the middle, and a full-height Decompiler on the right.
- C-like decompilation with linked instruction selection, call navigation,
  and Back / Forward history.
- Function discovery, confirmed call, data-access and address-taking
  references, and bounded recovery from supported metadata, pointer tables,
  and function-start patterns.
- Strings, Hex / Memory Map, byte decoding, and FindCrypt-style constant scans.
- Memory search for hex, ASCII or UTF-16LE patterns, and text search over
  loaded names, imports, exports, labels, comments and string previews.
- Declared imports grouped by library and exports in the Symbol Tree, plus
  flat, filterable Imports and Exports tabs in the Functions dock, with exact
  navigation and references.
- Compact C++, Rust and MSVC display names with the raw symbol on hover.
  See [demangling](docs/demangling.md).
- Function labels, comments, supported local renames, and limited function
  signature editing.
- Portable `.grproj` snapshots with optional embedded binaries.

## Quick start

Download a Linux x64 or Windows x64 package from
[GitHub Releases](https://github.com/mahirriki1/ghidra-rust/releases).
See the [Linux guide](docs/linux.md) or [Windows guide](docs/windows.md)
for installation, runtime requirements, and troubleshooting.

To run from source, use Rust 1.98.1, a native C/C++ toolchain, and an
OpenGL-capable desktop:

```sh
cargo run --release --locked
```

The first engine build can take minutes; use release builds to evaluate performance.

Choose **Open binary**, **Open project**, or drop a file into the window.
The executable also accepts a file path when launched.

Opening a binary offers **Analyze binary?**. Choose discovery, strings, and
optional FindCrypt scanning; continue browsing while analysis runs.
Use **Analysis → Auto analyze…** to reopen these choices.

Linux analysis requires **bubblewrap** and working unprivileged user namespaces.
Windows source builds require native MSVC tools. macOS remains unvalidated.

## Supported formats and architectures

Inputs must be linked executables or shared libraries with file-backed
executable sections.

| Format | x86 / x86-64 | AArch64 |
| --- | --- | --- |
| ELF | Supported | Little-endian, 64-bit AAPCS |
| PE | Supported | Windows ARM64 PE32+ |
| Mach-O | Thin images | Thin baseline Apple Silicon arm64 |

Unsupported inputs include ARM32/Thumb, big-endian images, AArch64 ILP32,
arm64e, ARM64EC/hybrid images, other processors, raw images, archives,
relocatable objects, universal/fat Mach-O, and sectionless images.

Analyzing ARM64 on x64 does not establish native ARM64 desktop support.
See [architecture coverage](docs/architectures.md).

## Using the desktop

Browse or filter Functions, then select a function to inspect its listing,
graph, and pseudocode. Pan and zoom the graph; **Fit** shows an overview and
**Entry** returns to readable entry code.
**Legend** and graph warnings are in the graph toolbar.

Double-click a resolved call instruction or decompiler call-name token to
open its target. Back / Forward returns to previous instruction selections.

Selecting an instruction highlights its mapped pseudocode; selecting mapped
pseudocode selects the corresponding instructions. Links use genuine engine
addresses. Several instructions can share an expression, and optimized-away
instructions may have no visible counterpart.

The Symbol Tree lists **Imports**, grouped by declaring library (or **Unknown
library**), and **Exports**. The function filter applies to them too. Click a
row to select it; double-click to open it. An import opens its verified stub as
code, or else its slot in Hex at that exact address. Code exports open as code
and data exports open in Hex; neither creates a function. Forwarded and
unresolved exports have no destination. Right-click for every known location.
Names prefer your label at the row's address, then the demangled name; hover
shows the raw name, library, ordinal and other declared facts.

The Functions dock below has **Functions**, **Imports** and **Exports** tabs.
The Imports and Exports tabs list every entry by name, with its address and
library (or export ordinal), and each has its own filter. They share the Symbol
Tree's selection, opening behaviour and context menu.

Visited functions reuse compatible session results. **Analysis → Refresh
function** recomputes the selected function. This session cache does not mean
every visited function is saved in a project.

### Keyboard shortcuts

| Shortcut | Action |
| --- | --- |
| `F1` | Open Keyboard shortcuts |
| `L` | Rename the selected function, address label, or supported local |
| `G` | Go to a hexadecimal address or exact function, label, raw or display name |
| `;` | Edit the comment at the selected address |
| `X` | Show references to the selection's exact target |
| `S` | Search memory |
| `Ctrl+F` | Search program text |
| `Space` | Switch Listing / Function Graph |
| `Alt+Left` / `Alt+Right` | Back / Forward |
| `Ctrl+S` | Save project |
| `Ctrl+Z` | Undo an annotation outside text editors |
| `Up` / `Down` | Listing: previous / next instruction |
| `PageUp` / `PageDown` | Listing: previous / next page |
| `Home` / `End` | Listing: first / last instruction of the function |
| `Enter` | Listing: follow the selected call or branch target |

On macOS, Save, Undo and program-text search use Command. Shortcuts pause while
typing, in dialogs, and during file operations.

Listing keys apply after clicking the Listing and stay within the current
function; clicking elsewhere, focusing a text field or switching tabs releases
them. Enter and Listing double-click follow a resolved call or a single taken
branch target; ambiguous, unresolved or switch-table destinations, and a jump
to the next instruction, are not followed.

**Help → Keyboard shortcuts** opens the same reference as F1.
**Help → About Ghidra Rust** shows the version and license/notice links.

**Help → Check for updates…** checks GitHub on request, including newer alpha
releases while running a `0.x` version. Download a verified update, then choose
**Install and restart**. Unsaved work uses the normal save/discard/cancel prompt;
a saved project reopens after restart. Linux x64 and Windows x64 portable builds
require a writable installation folder. Review and accept the license and dependency
notices before installation. Updates replace the executable at its existing path;
notices remain available in **Help → About Ghidra Rust**. Older or unsigned releases cannot
be installed through the updater. See [update setup and recovery](docs/releases.md#in-app-updates).

### References and inspection

Use **X** or **Xrefs to…** to inspect confirmed call/data targets. Multiple
targets require an explicit choice. On a **Strings** row, **X** lists the code
that reads, writes or takes the address of that string's first byte. On an
**Imports** or **Exports** row, **X** uses its exact address, or offers its stub
and slot locations as choices.
**References → Data references** filters by **All / Read / Write / Address**.
Address-taking (x86 LEA/immediates, AArch64 ADR/ADRP+ADD) is concrete address
formation, not proof of pointer use. References cover examined functions;
an empty result does not prove that no references exist.

**Strings** (**View → Defined Strings**) scans ASCII and printable-ASCII UTF-16LE;
it does not provide complete Unicode or Rust string-slice recovery.

**Hex / Memory Map** browses mapped sections of the analyzed snapshot.
Select bytes and choose **Decode selection**. Unmapped headers, overlays,
and runtime process memory are outside this view.

### Search

**Search → Memory…** (`S`) finds hex bytes (`??` matches any one byte), ASCII
or UTF-16LE text in the mapped, file-backed bytes of the analyzed snapshot.
**Search → Program text…** (`Ctrl+F`) finds a literal in the names, imports,
exports, labels, comments and string previews already loaded in the desktop. It
does not fetch more metadata, demangle, or search listing or pseudocode text.

Results appear in a **Search** tab with a state and count: Searching, Complete,
Partial, Canceled, Stale or Unavailable. Click selects a row; double-click,
Enter, or **Open** in its menu goes there. A match opens as code only at a known
function entry or at an instruction already observed in a recovered graph or
decompiler mapping. Otherwise it opens in Hex at its exact bytes, even inside
code. Strings open in Hex; imports and exports open like their Functions-dock
rows. Back / Forward records each destination.

Search state is transient: it is not saved in projects and is cleared when the
binary or project changes. Program-text results become **Stale** when the
searched names, annotations, tables or strings change; search again to refresh.
See [search scope and limits](docs/analysis.md#search).

**Decode** supports UTF-8, UTF-16LE/BE, hex, Base64, and supplied-key XOR.
**FindCrypt** finds a small set of standardized constants; matches are
candidates, not proof of encryption or recovered keys.
See [coverage and provenance](docs/crypto-signatures.md).

### Annotations and signatures

Use **L** and **;** to edit names and comments, or open **View → Annotations**
to browse them. Local renaming requires a verified recovered symbol.

Use **Signature…** above the Decompiler to edit supported integer/void/pointer
prototypes under the binary's ABI. This is not general type or variable-storage
editing. See [editing limits](docs/analysis.md#annotations-and-signatures).

The status-bar warning indicator opens loading and coverage notes.
Discovery can be partial; its activity indicator is not a whole-program
completion percentage. Use **Analysis → Cancel analysis** to stop a run.

## Projects

**File → Save project** or **Ctrl+S** creates one SQLite `.grproj` file.
It stores annotations, the known function list, the displayed function's
listing/graph and pseudocode, scan results, and committed discovery results.
It does not save every visited function or the engine's complete database.
Imports and exports are not saved; reopening rebuilds them from the verified binary.

**File → Include binary in project** is enabled initially. Embedded projects
include the analyzed binary. Without it, reopening asks you to select the
binary and verifies its SHA-256; saved source paths are display hints only.

Reopened results are labeled **Saved analysis** until recomputed.
Use **Analysis → Refresh function** for listing/graph and pseudocode, and
**Analysis → Discover functions** for fresh references. A matching binary hash
does not authenticate cached analysis.

**Export annotations (JSON)…** and **Open annotations…** preserve JSON sidecars.
There is no autosave or Ghidra/IDA project import. The app does not patch inputs.

**Open projects only from trusted sources:** SQLite parses `.grproj` files
inside the desktop process, outside the contained analysis worker.

## Security and isolation

Analysis runs in a disposable worker with cancellation and a 30-second
per-request wall-time limit. A stopped worker can be reopened for later work.

Linux workers use bubblewrap containment and resource limits.
See [Linux requirements and isolation](docs/linux.md).

**Windows worker limits control resources only; there is no filesystem or
network sandbox. Use trusted inputs.** See the [Windows guide](docs/windows.md).

## Documentation

| Topic | Guide |
| --- | --- |
| Linux installation and troubleshooting | [Linux](docs/linux.md) |
| Windows installation, building, and troubleshooting | [Windows](docs/windows.md) |
| Formats, instruction sets, and ABI exclusions | [Architecture coverage](docs/architectures.md) |
| Discovery, editing, project formats, and limits | [Analysis coverage](docs/analysis.md) |
| C++, Rust and MSVC display names | [Demangling](docs/demangling.md) |
| Constant signatures and decoding | [Coverage and provenance](docs/crypto-signatures.md) |
| Measurement methods and recorded results | [Analysis measurements](docs/analysis-performance.md) |
| Packaging and publishing releases | [Release workflow](docs/releases.md) |
| Contributor rules | [AGENTS.md](AGENTS.md) |

## Building and contributing

Follow [AGENTS.md](AGENTS.md) and the platform guides. For Rust changes:

```sh
cargo fmt --all --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
```

Tests run locally; GitHub Actions builds, lints, and packages without running
them. Report which platforms you actually validated. Documentation-only changes
need factual and link checks, not an application rebuild.

See [NOTICE](NOTICE) for the pinned engine and attribution; licensed under [Apache 2.0](LICENSE).
