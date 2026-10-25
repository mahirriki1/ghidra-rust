# Analysis coverage

**Analysis → Discover functions** performs bounded discovery in a disposable
worker for linked x86, x86-64, and little-endian AArch64 images. See
[architecture coverage](architectures.md) for container and ABI restrictions;
input architecture does not establish native desktop host support.

## Auto analysis

Opening a binary shows **Analyze binary?**; **Analysis → Auto analyze…** reopens
these choices. Discovery and strings default on; FindCrypt is optional. Choices
last for the session. Selected steps run sequentially: strings, FindCrypt, then
discovery. Navigation preempts scans, which rerun afterwards; failed or timed-out
steps are not retried. Results do not switch tabs. **Cancel analysis** stops the
remaining steps; detected packed images skip discovery.

## Confirmed calls and functions

The walk starts from the validated entry and functions supplied by symbols,
exports, and supported runtime metadata. Genuine direct-call targets must be
aligned, file-backed executable addresses. Calls to their own fallthrough do
not seed functions. The deterministic session queue admits the entry first,
then known functions in address order, then newly confirmed callees. Duplicate
entries are examined once per session.

Constants and unresolved register targets do not create functions. Pointer and
pattern recovery are separate validated phases below. Calls are separate from
intrafunction CFG edges; machine-code call evidence does not establish source
function boundaries or complete runtime call coverage.

[Work limits](#resource-limits-and-trust-boundaries) apply per batch as well as
across the session. Failed decodes and work omitted by display limits count.
A batch leaves a seed pending if its full walk allowance is unavailable.
Limited walks are terminal for the session; repeated Discover does not restart
them. Coverage remains partial while seeds are pending, walks fail or hit
limits, or references are omitted, even if seed processing continues.

Inventory admission prioritizes the entry, then address-ordered engine symbols;
PE additionally prioritizes exports and runtime starts nearest the entry.
Discovery reserves callers owning published evidence. Count or name-budget
omissions mark the inventory partial. Batch replies can be unchanged, deltas,
or full inventories; the desktop reconstructs and validates the complete result
before atomic adoption.

Conventional UPX PE detection disables discovery and decompilation of the packed
stub. Listing, CFG, strings, and byte inspection remain available. Detection
covers conventional UPX PE layouts, not every packer. The app neither unpacks
nor executes inputs.

## No-return calls

Calls to recognized names such as `exit`, `abort`, `__stack_chk_fail`, and
`ExitProcess` end their CFG block without a successor. Actual call sites and
direct targets remain available; a separate branch can still reach later code.
The graph header and call list show **[no return]**, with evidence in hover text.

Recognition uses original symbols/import stubs and the container's Ghidra list,
with native exclusions and supplements in [the provenance](../data/no-return/README.md).
Names match exactly after narrow decoration removal. Substrings, analyst renames,
and demangled leaf names never establish evidence. Index omissions appear in
the status-bar warning popup. Worker restart rebuilds the index from the binary.

Named PE IAT calls, conventional x86 `JMP [IAT]` thunks, and exact ARM64
`ADRP/LDR/BR` veneers can establish no-return behavior. The slot remains data;
indirect runtime targets stay unresolved. Extra thunk checks consume the walk
budget. Verified x86-64 ELF startup slots for `__libc_start_main` also qualify;
other ELF `-fno-plt` calls and register-carried import pointers do not.

The engine prototype flag improves pseudocode for recognized named functions
and resolved PE thunks; direct IAT-call termination is a desktop CFG guarantee
only. Custom wrappers are not inferred. Recursive cycles, failed decodes, and
bytes after unresolved calls are not proof. Exceptions and longjmp destinations
are not reconstructed. Saved markers never seed live classification.

## Stripped ELF startup

Conventional dynamically linked x86-64 ELF glibc startup passes `main` to
`__libc_start_main` as a pointer, beyond direct-call discovery. On open, a bounded
straight-line p-code walk follows the entry to that call through a GOT slot or
an import stub using one. The ELF's own `GLOB_DAT`/`JUMP_SLOT` relocations against
the undefined dynamic symbol establish the slot; names alone do not.

`RDI` must hold a complete constant or a slot value established by a supported
`RELATIVE` or defined-function symbol relocation. Entry-stack stores are allowed;
a potentially aliasing store discards relocated slot contents. Conditional
branches, jumps, unrelated calls, partial writes, and unsupported relocations
fail closed. Candidates must be aligned file-backed executable addresses,
exclude existing functions/import stubs/the entry, and reject startup wrappers
consisting of landing pads and an unconditional jump.

The recovered function is named `main` unless any function or data symbol already
owns that name. The status-bar warning popup records the recovered address,
establishing call, and analysis-derived name. The desktop opens it and discovery
follows its direct calls. No `_start → main` call reference is invented.

AArch64, i386, static/static-PIE, musl `_start_c`, sectionless files, and
wrapper-based startup are not recognized. Pointer and pattern recovery can
supply other unreachable functions only within their supported scope.

## ELF pointers and tail boundaries

On x86-64 little-endian linked ELF, discovery first admits validated
`DT_INIT`/`DT_FINI` entries and matching typed arrays, even with partial CFGs.
Exact `ENDBR64; JMP` or `JMP` rel8/rel32 callbacks can establish forwarding
destinations. After queued seeds drain, native-width aligned slots in allocated,
file-backed non-executable data are scanned. A run needs two distinct executable
targets; nulls, section boundaries, and invalid slots end it. Corroborated direct
tail jumps are examined after table seeds drain.

ET_EXEC slots use checked absolute addresses; supported RELA overrides bytes.
PIE RELATIVE addends retain link-time coordinates. Defined function symbols need
local binding or non-interposable visibility. IFUNC resolvers are never executed.
Conflicting relocations poison slots; REL/RELR, unknown write widths, malformed
tables, and mismatched dynamic/section relocation declarations are unsupported.

Table targets need an exact validated FDE start or vetted function-start pattern
and a complete bounded CFG outside established code. The `.eh_frame` subset is
DWARF32 CIE versions 1/3, `zR`, and PC-relative signed 32-bit pointers. Unsupported,
truncated, overlapping, or unbacked records establish no ranges. This does not
unwind stacks or turn every FDE into a function. Direct jumps stop at exact FDE
boundaries; validated destinations gain tail edges without call references.
Conditional cold paths keep their call coverage; cold fragments are not separate
functions.

Cursors retain pointer-run and validation positions across batches and worker
replacement. Cumulative work and reconstruction are bounded; exhaustion leaves
partial coverage. Instruction address-taking, PE/AArch64 pointer sources, and
persistent source witnesses remain unsupported.

## Function-start patterns

After queued functions drain, x86-64 ELF and PE discovery scans executable
file-backed sections with Ghidra's GCC or Windows function-start patterns,
vendored unchanged with [provenance](../data/function-starts/README.md).
A match becomes a `FUN_` function only when:

- It is aligned, outside established instructions and PE runtime-function ranges,
  and not already a function.
- `after="defined"` matches begin exactly after established code or at section
  start; padding alone does not qualify.
- Its complete walk fits the shared [function limit](#resource-limits-and-trust-boundaries),
  with no overlap, unresolved indirect jump, internal p-code branch, or unexplained
  warning. Paths end in returns, recognized no-return calls, or explicit jumps to
  known functions. Falling into another function is rejected; pure tail bodies
  qualify. Direct calls must target code outside other functions' interiors.
  Numeric `validcode` supplies a minimum instruction count.

Candidates are admitted in address order and immediately join established code;
later overlapping matches fail. Admitted functions become ordinary call-discovery
seeds. `codeboundary`, `possiblefuncstart`, `setcontext`, and patterns requiring an
existing function never create one. After worker replacement, bounded decoding
reconstructs established coverage before judging new matches.

Scans and cumulative cursor/reconstruction work are bounded. Match floods,
interruptions, stalled steps, or a full inventory leave coverage partial.
Optimized code without recognizable prologues can be missed. AArch64, 32-bit x86,
and Mach-O have no pattern set.

A function-row glyph exposes the first pointer/pattern admission reason, source,
and boundary evidence on hover. Witnesses are session-only and omitted from
projects; reopened results retain saved provenance until recomputed.

## Switch tables

For a computed jump, the worker can run the engine's flow analysis with jump-table
recovery without full decompilation. Tables must belong to the exact decoded
jump; destinations must be aligned file-backed executable addresses. Duplicates
merge, and walking resumes under the function budget, exposing calls in cases.
Graph edges are labeled `S`.

The graph uses bounded static flow recovery; exceptions, no-return calls, and
indirect flow may be incomplete. Function-specific diagnostics appear in the
conditional graph-toolbar warning menu, and **Legend** explains edge letters.
No graph warnings does not establish complete runtime flow.

Table size, recovery count, and recovery time are bounded; exhausted or incomplete
recovery remains partial with an unresolved successor and warning. Unknown
register/pointer jumps remain unresolved. Destinations never become functions
solely from switch evidence; another function's entry is an external exit.
Detected packed images skip recovery.

## Direct data accesses

Discovery inspects decoded p-code for genuine memory operands and literal-address
`LOAD`/`STORE`, including x86 absolute/RIP-relative accesses and ARM64 literal
loads. Read-modify-write retains both kinds. Evidence records source function,
instruction PC, target, width, and kind.

x86 evidence is instruction-local. AArch64 additionally propagates concrete
register constants within each basic block, for example `ADRP; ADD; LDR` and
`MOVZ`/`MOVK` with supported arithmetic, shifts, and extensions. These accesses
show `Read*` / `Write*` in **Data accesses**; hover the Access cell for
“* Address from register constants in this block.” Unmarked accesses use
instruction-local evidence. Block boundaries, calls, unsupported/omitted
instructions, and overlapping register writes clear knowledge.
Loaded pointers are never chased: `ADRP; LDR` identifies the slot, not its value.
Address formation alone and call arguments create no references. Cross-branch
values and switch-recovery table reads are excluded. Internal p-code branches,
user operations, and unsupported semantics omit the instruction as partial.

The entire access must fit the ABI and one validated file-backed section.
Executable literal pools qualify; zero fill, unmapped/cross-section ranges,
oversized accesses, and overflow do not. Sources must be aligned known executable
addresses. Shared operation, candidate, and state limits mark omissions partial;
see [limits](#resource-limits-and-trust-boundaries). This is access evidence,
not data-object or pointer classification.

## References and progress

**References** shows confirmed incoming/outgoing calls for the selected function.
Callers, callees, and source PCs navigate directly. A call omitted by graph display
limits still selects its exact PC with a notice; **Go to** can inspect it separately.
References cover examined functions in committed batches. Empty does not prove
that no references exist; absent reports remain **not analyzed**.

**X** uses the decompiler call token's genuine target, selected instructions'
call/data targets, or otherwise the selected address/function. Multiple targets
require an explicit choice. Context menus offer **Xrefs to…** on functions,
instructions, and call tokens. **Data accesses** filters by displayed function
or exact target start, not overlapping interiors. Source buttons select PCs;
target buttons send only accessed bytes to Decode, preserving code history and
selection. Delayed replies cannot override a newer selection or tab. Committed
references stay visible while subsequent batches run.

The status bar remains active through setup, adoption, foreground waits, and
worker recovery. Known-function counts can grow and their fill can decrease as
calls reveal work; they are not whole-program completion percentages or ETAs.
Elapsed time includes setup and waits; step counts identify selected analyses,
not portions of runtime. Processed counts include failed and limited attempts
and exclude in-flight work. Other phases show activity. Hover for phase/count
details. Worker **Seeds**, **Calls** (shown as **Analyzing references**), and
**Publish** stages report batch work; progress never resets CPU or wall-time
deadlines.

Cancel terminates the worker and pauses discovery while retaining committed
batches and the remaining queue. Discover resumes with a new elapsed clock.
Interactive requests take priority between batches. Fresh workers receive bounded
inventory/name replay. Interrupted seeds retry once, then fail; three unrelated
worker restarts without a committed batch pause discovery. Batch or replay failure
also pauses for explicit continuation. Results bind to request, worker epoch,
binary generation, annotation revision, and batch sequence. Stale replies cannot
double-count evidence; selection and display-name changes do not invalidate
machine references from the immutable image.

## ARM64 PE runtime metadata and import veneers

Ordered runtime records from the exception directory recover primary entries and
validated code regions from normal packed and supported version-zero full `.xdata`
records. Entry/export names win. Packed fragments and chained phantom prologs
retain regions but do not independently seed functions; exports or calls can
still reach them. Parent `.pdata` links, custom context/trap unwind codes,
SVE `save_any`, reserved/unsupported forms, unordered tables, and overlapping
regions are omitted with partial warnings. Storage, alignment, code lengths,
epilog indices, and opcode boundaries are validated. This is metadata recovery,
not stack unwinding or exception flow. Leaf functions need other evidence.

At known entries or confirmed calls, engine instructions and p-code recognize
exact `ADRP Xn; LDR Xm,[Xn,#offset]; BR Xm` veneers reaching a named aligned,
file-backed non-executable IAT slot. Generic names can be promoted; meaningful
names stay intact. No pattern scan seeds functions; on-disk IAT values are not
runtime destinations. The CFG branch remains unresolved. BTI-prefixed/other
shapes, delay imports, and imported prototypes remain deferred. Bounded naming
and discovery can omit candidates as partial. Conventional UPX stubs skip
load-time veneer decoding, discovery, and decompilation.

## Upstream provenance and remaining work

Confirmed-call and call-to-fallthrough rules adapt
[Ghidra FunctionAnalyzer.java](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/FunctionAnalyzer.java)
at `9a723ce99952771b8368329503aa589ae233e916`, under Apache License 2.0.
Direct-memory `COPY`/`LOAD`/`STORE` and AArch64 constant/unknown-output rules adapt
[Ghidra SymbolicPropogator.java](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/program/util/SymbolicPropogator.java)
at the same revision. This bounded adaptation tracks concrete values within one
block, without the Java Program database or analysis framework.

The pinned `ghidra-decompiler` revision is
`268c3a406d8d964bc00ae2ead4d3e1e1373aaa27`, with recorded Ghidra base `d6192cb3f9`.
Attribution remains in [NOTICE](../NOTICE). The independent ARM64 PE reader follows
[Microsoft's exception-handling format](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170);
veneer recognition uses public engine APIs. No Java or Python runtime is added.

Remaining work includes cross-block propagation, speculative operand references,
exception flow, inferred no-return wrappers, and complete stripped recovery.
Engine decompilation may expose constructs the independent CFG cannot establish.
There is no source/class/trait reconstruction or MSVC demangling. Plugins,
scripting, debugger integration, and general type/variable-storage editing remain
future capabilities.

Comparisons require the same executable hash and comparable scope, end-to-end
time, and total memory including workers and duplicated bytes. No general speed
or memory advantage over Ghidra is claimed. Report native platform validation
separately from input architecture; see [measurements](analysis-performance.md).

## Per-function session results

Immutable validated listing/graph and pseudocode results retain presentation
indexes, highlighting, geometry, mappings, semantic tokens, inferred prototypes,
and unapplied-local warnings. View cameras and selections remain mutable;
exact instruction history precedes cache adoption. Empty success differs from
missing results; failed analysis is not cached.

Compatibility depends on binary SHA-256, engine/signature fingerprints,
committed signatures, inventory, effective function names, and per-function local
identities/names. Background jobs compute changed projections. Request, selection,
and revision bindings still apply; stale replies and staged signatures cannot
populate committed state. Worker restart preserves compatible results.

- Local rename/remove/undo invalidates that function's pseudocode.
- Function name changes invalidate graph and pseudocode, including callers;
  references and byte scans remain.
- Signature acknowledgement clears graph, pseudocode, and discovery, preserving
  annotations, inventory, and byte scans.
- Inventory address changes invalidate graph/pseudocode; committed references
  remain attached to their publication.
- Comments/decoded notes retain analysis, including comment-only JSON imports.
- Refresh bypasses stored components; rediscovery replaces saved evidence while
  retaining compatible function results.

The [session-store budget](#resource-limits-and-trust-boundaries) accounts for
payload capacities, prepared presentation, bookkeeping, and discovery publication.
Inactive unpinned components are evicted least recently used. Shared snapshots
remain charged until their last owner drops, including project-save pins.
If pins prevent admission, current results can display uncached and discovery
publication waits. Annotations are never evicted. Allocation accounting is not
total process memory; preparation, uncached results, workers, and images add more.
Saves track result revisions so older saves cannot mark newer results saved.

Misses use the warm worker, whose shared type knowledge can change later Refresh
output. There is no canonical fresh replay for each miss. Projects persist only
the displayed function; saving all retained functions needs a format migration.

## Annotations and signatures

Comments appear beside Listing instructions and on Graph rows. The Decompiler
shows each once above a genuinely mapped statement, with entry comments at top;
unmapped ones remain under **Comments without visible code**. Double-click a
comment, use its context menu, or press **;** for full text. **View → Annotations**
opens a filterable address/label/comment browser. Address navigation preserves
observed function context and history; data addresses open Decode.

Local renaming requires a verified symbol with one whole stack/register storage
mapping, including recovered parameters. Declarations and uses change together.
Names are C identifiers of 1–64 ASCII bytes; keywords and local collisions fail.
Globals, split/conflicting storage, dynamic/unique temporaries, fields, objects
larger than 256 bytes, and unverified tokens are unsupported. They cannot silently
rename an address label. Identity collection and override counts are bounded in
[semantic.rs](../src/semantic.rs).

Overrides bind to binary, function, engine, storage, type, and recovered uses.
Revisit/restart/reopen/import replays only compatible identities. Missing,
ambiguous, changed, or incompatible overrides stay saved and visibly **not applied**;
Refresh cannot redirect them. **Ctrl+Z** (Command on macOS) undoes annotations.

**Signature…**, the function context menu, and annotation editor expose supported
prototypes. Unsupported inferred types require an explicit supported choice.
Types are `void`, signed/unsigned 8/16/32/64-bit integers, and pointers up to four
levels. Scalar `void` is return-only. The binary's ABI applies; alternate calling
conventions, floats, aggregates, arrays, and variadics are unsupported. Up to
32 named parameters use distinct C identifiers. Aggregate state is bounded in
[signatures.rs](../src/signatures.rs).

All signatures install before caller analysis; known direct calls use callee
types and ordered parameters. Indirect calls, imports, and thunk propagation
are excluded. Apply/remove/undo verifies a fresh worker and complete replay before
atomic commit. Failure/cancel retains committed state and attempts fresh recovery;
incompatible or missing-entry overrides remain visibly **not applied**. This is
prototype editing, not a general type or variable-storage editor.

## Strings and byte inspection

Strings scans mapped bytes for ASCII and printable-ASCII UTF-16LE, not complete
Unicode or Rust string slices. **Not scanned** differs from empty. The minimum
defaults to 6 characters, selectable from 4–64 before the result cap; filtering
searches loaded results only. Increase the minimum and rescan to reduce noise.
Partial scans are labeled; [scan limits](#resource-limits-and-trust-boundaries) apply.

**Hex / Memory Map**, also opened from Program Tree sections, shows mapped sections
and their exclusive virtual/file ranges. Browse section-relative 4 KiB pages
using **Prev/Next** or **VA (hex)**. Invalid jumps preserve the page. File bytes
show offsets on hover; zero-filled bytes have none. Unmapped headers, overlays,
and runtime process memory are outside this immutable snapshot view.

Click/Shift-click hex or ASCII bytes, then **Decode selection** for the exact
slice and address. Page changes clear selection. Browsing preserves navigation
and annotations; pages/selections are transient. Reads wait for busy analysis;
rapid paging retains the newest request only. Failed/canceled reads require
**Retry**. Decoder behavior and constant-match caveats are in
[coverage and provenance](crypto-signatures.md).

## Project formats and saved analysis

A `.grproj` SQLite snapshot stores annotations, known functions, displayed-function
listing/graph and pseudocode, string/crypto results, selection, and committed
discovery. It does not serialize every visited function or the engine database.
Embedded binaries extract privately and remain owned through worker reaping;
external binaries require explicit selection and SHA-256 verification. Source
paths are display hints. The engine reopens the verified binary before adopting
cached results. There is no autosave or Ghidra/IDA import.

Current saves use project schema version 4, adding function signatures. Versions
1–3 remain readable; older releases reject newer schemas. Version 2 introduced
saved discovery; version 3 added semantic tokens and local-name overrides.
JSON v1/v2 remain readable: legacy local overrides use v2; signatures and local
identities recovered under signature context use v3. Signature-context upgrades
refresh older analysis caches while retaining annotations.

Saved inventory and results retain **Saved analysis** provenance until recomputed.
Refresh replaces function results; Discover discards saved discovery and starts
fresh rather than resuming saved statuses. **Rediscover from scratch** also
replaces session discovery. Saved queues, retries, worker bindings, and admission
witnesses are not persisted; unfinished batch seeds remain pending.

Loading validates exact schema, bounded collections, ordered unique addresses,
executable membership, mapping bounds, source ownership, targets, and consistency
of partial/status/counter data. This checks structure, not instruction truth.
Unmapped graph exits and call targets save as unresolved.
Engine or discovery-format fingerprint mismatches discard incompatible caches
while keeping annotations. A matching binary hash does not authenticate analysis.

Saves publish complete new files atomically after destination checks, retaining
all protected-input guards through replacement. They never patch the binary,
including pathname aliases. See [trust boundaries](#resource-limits-and-trust-boundaries)
for project parsing and residual filesystem limitations.

## Resource limits and trust boundaries

| Scope | Limit / behavior |
| --- | --- |
| Files | 128 MiB binary; 224 MiB project; 8 MiB JSON annotations |
| Known functions | 262,144; omitted entries mean a partial inventory |
| Function walk / graph | 2,048 instruction attempts / 128 displayed blocks |
| Discovery batch | 128 seeds / 16,384 decode attempts; not cumulative ceilings |
| References | 16,384 call refs and separately 16,384 data refs |
| Strings | 64 MiB scanned data / 10,000 results |
| Bytes / decode | 64 KiB input and XOR keys / 256 KiB output; oversize is rejected |
| Pseudocode | 2 MiB returned text |
| Session result store | 64 MiB accounted allocations; see [eviction](#per-function-session-results) |
| Worker request | 30-second wall-time deadline; progress does not extend it |

Returned-result limits do not bound the engine's internal allocations. Total
memory includes workers, retained image copies, and uncached results. Linux
[containment](linux.md#worker-isolation) and Windows [resource controls](windows.md#build-and-launch)
contain worker failures; other platforms lack implemented process sandboxing.
Projects are parsed by SQLite inside the desktop process. Schema, bounds, and
SHA-256 checks do not authenticate saved analysis; open projects only from trusted sources.

Input identities remain protected across pathname replacement. Atomic saves
still have residual same-user parent-directory and Windows delete-sharing rename
races; publication is not relative to retained directory handles. A stalled
directory read can remain blocked, but cancellations do not accumulate reader
threads. Limit sources: [model.rs](../src/model.rs), [analysis/](../src/analysis/),
[project.rs](../src/project.rs), [session.rs](../src/session.rs),
[semantic.rs](../src/semantic.rs), and [signatures.rs](../src/signatures.rs).
