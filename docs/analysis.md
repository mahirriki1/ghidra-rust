# Analysis coverage

Ghidra Rust analyzes linked binaries in a disposable worker. Discovery is
bounded and reports partial results when it runs out of work budget or cannot
resolve code. Use the status-bar warning indicator for details.
[Supported inputs](architectures.md)

## Desktop workflows

### Listing and graph

- **Listing → Program** shows sections, known functions, decoded instructions,
  and undefined bytes in address order. Bodies near the viewport load in the
  background. Switch to **Function** to see only the current function.
- Click the Listing to use arrows and Page Up/Down. Home/End jump to the ends
  of the current function, section, or expanded byte run. Ctrl+Home/End jump to
  the ends of the Program listing. Pausing the cursor on a function row updates
  the Graph and Decompiler. Cursor movement adds no history.
- In the graph, pan and zoom or select **Fit** for an overview and **Entry**
  for readable entry code. The minimap recenters the view. **Legend** explains
  edge labels, and the warning menu explains incomplete graphs.
- Selecting an instruction or pseudocode uses the engine's address mappings.
  Several instructions can share one expression, and optimized-away
  instructions can have no visible counterpart.
- Double-click a resolved call to follow it. In the Listing, double-click
  also follows branches with one known destination. Back/Forward restore prior locations. Ctrl+Up/Down go to the
  previous/next known function by address.

### Go to an address

Press **G** or use the toolbar address field. Whole addresses and exact names
are tried first. Use hexadecimal addresses such as `401000` or `0x401000`.
For a named base, `main+20-4` adds hex `20` and subtracts hex `4`. Use up to
16 offset terms. An exact name such as `operator+` or `next-1` still works.

Use `file(4620)` or `file(0x120c)` to go to the same file byte. File offsets
are decimal by default and must map to exactly one loaded section. The status
bar shows the current file offset where available. See
[Program-listing destinations](#program-listing-destinations) for where jumps land.

### Tables and file chooser

- **Functions**, **Imports**, **Exports**, **Strings**, and **References**
  support column sorting. Click a heading again to reverse the sort and a
  third time to restore the original order. Use **Copy row** for tab-separated
  visible fields.
- Right-click a row or pseudocode token for actions on that item. Listing
  menus include navigation, Hex, references, annotations, and copy commands.
  Hidden tabs and controls move into **»** or **⋯** in narrow panes.
- In the file chooser, Ctrl+L edits the path, Enter opens the selected item,
  and Backspace goes up. Places and recent folders provide shortcuts. A
  directory lists up to 4,096 entries. If it shows **Partial**, type the path
  to reach an omitted file. On Windows, paths must be on local drives.

## Auto analysis

Choose **Analysis → Auto analyze…** to run strings, optional FindCrypt, and
function discovery in that order. Discovery and strings are enabled initially.
Navigation takes priority over background work. **Cancel analysis** stops the
remaining steps. Committed discovery stays available and can be resumed with
**Discover functions**. **Rediscover from scratch** starts a new run.

## Confirmed calls and functions

Discovery starts from the entry point and functions established by symbols,
exports, and supported runtime metadata. It follows decoded direct calls to
valid code addresses, excluding calls to their own fallthrough. Unknown
indirect targets and address constants do not create functions. Shared
libraries without an entry point open at a known function when available.

Detected conventional UPX PE stubs disable discovery and decompilation. You can
still inspect the listing, graph, strings, and bytes.

## No-return calls

Recognized calls such as `exit`, `abort`, and `ExitProcess` show
**[no return]** and end their graph block. Recognition uses original symbols,
verified import stubs, or supported import slots. Analyst labels and custom
wrappers supply no evidence. Other branches can still reach subsequent code.
[Name lists and policy](../data/no-return/README.md)

## Stripped ELF startup

For conventional dynamically linked x86-64 glibc ELF, the worker can recover
`main` from the entry point's call to `__libc_start_main`. It checks the
import relocation and the value passed in RDI. This yields a function entry
rather than a synthetic call reference. Static binaries, musl startup, and
other instruction sets fall outside this recovery.

## ELF pointers and tail boundaries

On x86-64 ELF, discovery can recover init/fini callbacks and targets from
aligned pointer runs in file-backed data. Ordinary runs need two distinct
targets, supported relocations or absolute addresses, and target starts
corroborated by a validated frame-description entry or a function-start
pattern. Accepted targets also need a complete, nonoverlapping walk.
Corroborated tail jumps produce graph edges without call references.
Unknown relocation formats and unsupported unwind records limit coverage.

## Function-start patterns

After known functions are processed, x86-64 ELF and PE discovery can scan for
GCC or Windows function-start patterns. A match needs an aligned address
outside established code and a complete walk without overlaps or unresolved
indirect jumps. Rules that require adjacent defined code or a minimum
instruction count are enforced. Optimized functions can be missed.
Hover the evidence marker in Functions to see why an entry was admitted.
[Pattern files and provenance](../data/function-starts/README.md)

## Switch tables

The worker can recover jump-table destinations through the engine's flow
analysis. Accepted destinations appear as `S` edges and let discovery examine
calls inside cases. Unknown computed jumps remain unresolved. Switch
destinations alone do not create functions.

## Direct data accesses

Discovery records reads and writes to concrete, file-backed addresses. This
includes x86 absolute/RIP-relative accesses and AArch64 literal loads.
AArch64 also carries known register values within a basic block, as in
`ADRP; ADD; LDR`. In the **Data references** view, `Read*` and `Write*`
identify this evidence. Values loaded through pointers are not followed.
Accesses must fit within one file-backed section.

## Imports and exports

Browse imports grouped by library in the Symbol Tree or use the flat
**Imports** and **Exports** tabs in the Functions dock. Hover for raw names
and declaration details. An import opens its verified stub or, if none is
known, its slot. A code export opens as code and a data export goes to its
address. Forwarded and unresolved entries have no local destination.
Use **X** to query one exact location or choose among known stubs and slots.

| Format | Covered metadata and common gaps |
| --- | --- |
| PE | Named and ordinal imports, RVA-based delay declarations, export aliases, data exports, and forwarders. Older delay forms and many thunk shapes remain unresolved. |
| ELF | Dynamic symbols and versions, supported relocation slots, and conventional PLT and IBT stubs. A library dependency alone does not identify the owner of an import. |
| Thin Mach-O | External symbols, library ordinals, and indirect-symbol slots and stubs. Chained fixups, binding opcode programs, and export-trie-only entries are outside coverage. |

The table is rebuilt from the verified binary when a project opens. Its
header indicates **Loading**, **Partial**, or **Unavailable** when applicable.

## Address formation

Discovery can record concrete pointer-width addresses formed by instructions,
such as x86 `LEA` and AArch64 `ADR` or `ADRP; ADD`. It reports these as
**Address** references without a read/write width. Targets must be file-backed
and at or above `0x1000`. Some constants can match an address by coincidence.
AArch64 rows marked `Address*` used values carried within a basic block.

## References and progress

Press **X** or use **Xrefs to…** for the selected address, instruction target,
call token, or string. A string looks up its first byte. When several targets
are available, choose one. **References** shows confirmed calls.
**Data references** filters **All**, **Read**, **Write**, and **Address**.
Select a source to inspect the instruction that produced the evidence.

References only cover examined functions in committed batches. An empty list
can reflect incomplete coverage. The status bar shows activity, batch counts,
and omissions. Counts can increase as discovery finds more functions.

## ARM64 PE runtime metadata and import veneers

Supported packed and full unwind records supply primary function entries.
Fragments alone supply no entries. Conventional `ADRP; LDR; BR` veneers
at known entries can get names from verified import slots, while their runtime
branch remains unresolved. Parent links and unsupported unwind forms can make
coverage partial.

## Upstream provenance and remaining work

Call recovery and concrete data references adapt Ghidra's `FunctionAnalyzer`
and `SymbolicPropogator` at revision `9a723ce99952771b8368329503aa589ae233e916`.
Address formation adapts the Ghidra 12.2 `COPY`, `STORE`, and `INT_ADD`
cases in `SymbolicPropogator` at `8ca9077040cc43cd790babcfccf19475622a3e9a`.
The ARM64 PE reader follows Microsoft's exception-handling format.
[Upstream attribution](../NOTICE) ·
[Ghidra call analysis](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/FunctionAnalyzer.java) ·
[Ghidra reference analysis](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/program/util/SymbolicPropogator.java) ·
[ARM64 exception handling](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170)

Cross-block propagation, exceptions, inferred no-return wrappers, and
complete stripped recovery remain outside the current coverage. The
Decompiler and Function Graph can report different amounts of recovered flow.

## Per-function session results

Revisiting a function can reuse its listing, graph, and pseudocode.
**Analysis → Refresh function** recomputes them with the current worker.
Compatible results survive worker restarts. Function renames, inventory changes,
and signature edits can invalidate results. Local renames invalidate that
function's pseudocode. Comments and decoded notes can reuse existing analysis.

The session keeps up to 64 MiB of accounted result allocations and evicts
inactive, unpinned entries first. If a pinned result prevents admission,
the current view can still display uncached. Worker allocations, image copies,
temporary preparation, and uncached results also contribute to memory use.

## Annotations and signatures

- **L** renames functions, address labels, and supported locals. A local needs
  verified whole register or stack storage. When an override no longer
  matches, it stays saved and shows **not applied**.
- **;** edits a comment. Comments appear in the Listing and Graph and beside
  mapped pseudocode where possible. **View → Annotations** browses edits.
  Ctrl+Z undoes annotations outside text fields.
- **Signature…** edits a function's prototype under the binary's ABI. Choose
  `void` for a scalar return, signed or unsigned 8-, 16-, 32-, or 64-bit
  integers, or pointers up to four levels deep. Up to 32 named parameters
  are supported. Types apply to known direct calls. Variadics, aggregates,
  floats, alternate calling conventions, and general storage editing are
  outside the supported subset.

## Strings and byte inspection

**Strings** scans ASCII and printable-ASCII UTF-16LE. The character minimum
defaults to six and can be set from four to 64. Increase it and rescan to reduce
noise. A truncated preview can still have a known full byte length.

**Hex / Memory Map** shows mapped sections in 4 KiB pages. Use **VA (hex)**
to jump, click or Shift-click to select bytes, and use **Decode selection**
to transform them. Headers, overlays, and live process memory lie outside
this view. Zero-fill has no file offset. [Decode and FindCrypt](crypto-signatures.md)

### Listing evidence

Program scope shows each undefined gap as a `??` row. Enter or double-click
expands up to 64 KiB into byte rows. Repeat on a byte row to collapse its run.
Zero-filled rows do not expand.

Import slots, recovered absolute pointer entries, and scanned strings can
appear on undefined rows. Check the hover text for their evidence. A pointer
entry can open its function, and **Show in Hex** selects the file-backed bytes
of a row. Pointer-table evidence is rebuilt by discovery after reopening a project.

### Program-listing destinations

Known code entries or observed instructions open in their function. In
**Program** scope, other mapped addresses generally land at the exact row.
A jump into undefined bytes expands the relevant pages, and a zero-filled
tail can get a row at that address without reading any bytes. An address
inside a decoded instruction usually opens in Hex. **Show in Listing** from
Hex instead selects the containing instruction and records the prior Hex
selection for Back.

In **Function** scope, Go and memory-search results without a known code
destination open in Hex. Expanded runs, Hex selections, and search results
last for the session.

## Search

| Search | What it covers |
| --- | --- |
| **Memory** (`S`) | File-backed mapped sections. Enter space-separated hex bytes with optional `??` wildcards, literal ASCII, or UTF-16LE. A match stays within one section. |
| **Program text** (`Ctrl+F`) | Literal matches in loaded names, imports, exports, labels, comments, and string previews. Listing text and pseudocode are outside this search. |

Double-click a result or press Enter to open its location. Results can be
**Partial** if a source is unavailable, loading, or over budget. Program-text
results go **Stale** when the underlying text changes. Search again to refresh.

## Project formats and saved analysis

A `.grproj` file stores annotations, the known function inventory, selection,
view results, string and crypto scans, and committed discovery. It also keeps up
to 128 recent retained functions within a 16 MiB serialized result limit.
Missing components are recomputed on demand. The engine database and
session-only UI state are outside the snapshot.

**File → Include binary in project** is on initially. For an external project,
select the binary yourself on reopen. The app verifies its SHA-256. Saved
source paths are display hints. Current saves use schema version 5 and can
read versions 1–4. Older releases may reject newer projects. Incompatible
analysis caches are dropped while annotations are retained.

The saved Listing address reopens in its known function or lands on its
Program row when possible. Reopening labels results **Saved analysis**.
**Refresh function** replaces saved listing/graph and pseudocode.
**Discover functions** starts fresh to replace saved discovery. The binary hash
checks file identity while the saved analysis retains its own provenance.

**Export annotations (JSON)…** and **Open annotations…** support sidecars.
Project saves and annotation exports verify the retained image before atomic
publication and protect the input binary from being overwritten. There is no
autosave or Ghidra/IDA project import.

## Resource limits and trust boundaries

| Operation | Main limit |
| --- | --- |
| Binary / project / annotation JSON | 128 MiB / 224 MiB / 8 MiB |
| Function inventory | 262,144 entries, with a separate name budget |
| Single function walk / graph | 2,048 instruction attempts / 128 displayed blocks |
| Discovery batch | 128 seeds / 16,384 decode attempts |
| Strings | 64 MiB scanned / 10,000 results |
| Memory search | 256-byte pattern / 128 MiB of mapped file-backed bytes / 10,000 results |
| Program-text search | 32 MiB of text scanned / 10,000 results |
| Decode | 64 KiB input or key / 256 KiB output |
| Pseudocode | 2 MiB per result |
| Worker request | 30 seconds wall time, including progress messages |

Linux isolates the analysis worker with bubblewrap. Windows jobs and watchdogs
limit resources and leave filesystem and network access available. Use
trusted Windows inputs. SQLite parses projects in the desktop process on
both platforms. Use trusted projects even when the embedded binary's hash
matches. [Linux isolation](linux.md#worker-isolation) · [Windows setup](windows.md)

The implementation defines the authoritative bounds and compatibility rules.
[Worker limits](../src/model.rs) · [Project validation](../src/project.rs) ·
[Annotation limits](../src/session.rs)
