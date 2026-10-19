# Analysis coverage

**Analysis → Discover functions** performs bounded confirmed-call discovery in
the disposable worker. It runs on linked x86, x86-64, and little-endian AArch64
ELF, PE, and baseline arm64 Mach-O images already supported by the desktop.
See [architecture coverage](architectures.md) for container and ABI restrictions.
Analyzing an AArch64 image on an x64 host does not establish native ARM-host
desktop support.

## Confirmed calls and functions

The walk starts from the validated image entry point and known functions supplied
by symbols, PE exports, and supported PE runtime-function metadata. It decodes
reachable instructions and adds only genuine direct-call targets in file-backed
executable memory as new function candidates. Targets must meet the selected
architecture's alignment requirements. A call to its own fallthrough address does
not seed a function. Duplicate entries are examined once per run.

Arbitrary constants, prologue byte patterns, and unresolved register targets do
not create functions. Unknown indirect calls and branches remain unresolved.
Calls are separate from intrafunction control-flow edges. An established call
instruction is machine-code evidence; it does not reconstruct a source-language
function boundary or prove that all possible runtime calls have been found.

Each run examines at most 128 function entries and makes at most 16,384 decode
attempts in total. Each function has a 2,048-attempt limit, and its displayed graph
has at most 128 blocks. The shared limit is charged for failed decodes and decoded
work omitted by display limits, so it cannot be exceeded by a final function walk.
ARM64 import-veneer confirmation during discovery charges three attempts per
eligible candidate against this same shared budget, before calling the engine.
The call-reference collection is also capped at 16,384 entries. Coverage is marked
partial when work limits or recovery failures prevent a complete walk.

The known-function inventory is a separate, larger budget: at most 262,144
entries, 256 bytes per name, and 8 MiB of JSON-escaped names in total, so the
largest inventory plus both reference classes fits the 32 MiB worker reply.
Each retained function costs roughly 1.2 KiB across the worker and desktop
processes; see [analysis measurements](analysis-performance.md#large-function-inventories).
Entries beyond either budget are omitted and the list is marked partial. Open
admits the entry point first and then engine symbols in address order (PE images
prioritize exports and runtime starts nearest the entry before that). Discovery
replies also reserve the callers that own published evidence. Raising the
inventory does not widen the 128-function discovery walk.

Conventional UPX PE detection still prevents discovery and decompilation of the
packed stub. Listing, CFG, strings, and byte inspection remain available. The
desktop neither unpacks nor executes the input.

## Direct data accesses

The same discovery walk inspects already decoded instruction p-code for direct
memory reads and writes. It records genuine memory-space input/output operands
(including x86 absolute/RIP-relative accesses) and literal-address `LOAD`/`STORE`
operations (including ARM64 literal loads). Read-modify-write operations retain
both access kinds. Source function, instruction PC, target, width and access kind
are retained; no additional instruction decode or image-byte copy is required.

This pass does not propagate values through registers or temporaries, including
between operations of one instruction. `LEA`, `ADR` and `ADRP` address formation
alone creates no memory reference. An `ADRP; LDR` pair, pointer chasing, unknown
register addresses and jump tables require later analysis. Internal p-code
branches, processor-specific user operations and unsupported semantics omit the
whole instruction with partial coverage. Control-flow operands are excluded.
This is memory-access evidence, not data-object or pointer classification.

Targets must fit the selected ABI and their entire 1–64-byte access must lie in
one validated file-backed section. Executable literal pools are accepted; zero
fill, unmapped addresses, cross-section ranges and overflowing arithmetic are
omitted. Instruction and function sources must be known file-backed executable
addresses with the architecture's alignment.

The shared pass budget charges at most 131,072 p-code operations, with at most
256 per instruction and 16 inputs per operation. At most 16,384 access candidates
are inspected, including unresolved, omitted and duplicate candidates before
deduplication. Budget or unsupported-instruction omissions mark coverage partial.
These limits supplement the existing function, decode and worker resource limits.

## References and progress

After discovery, the middle pane's **References** tab shows incoming and outgoing
confirmed calls for the selected function. Callers, callees, and source instruction
addresses are navigable. A call site omitted by the caller graph's display limits
still selects its exact address and shows an explicit notice; use **Go to** to
inspect that address separately. Incoming references cover only the functions examined
in the current discovery run; an empty list does not prove that no caller exists.

The **Data accesses** selector shows accesses from the displayed function or
accesses beginning at an exact hexadecimal target address. This exact-start
filter does not search for accesses whose interior overlaps that address. Source
buttons select the genuine instruction PC, including the explicit display-limit
notice when necessary. Target buttons request only the accessed bytes in
**Decode**; they do not create functions or invented semantic mappings. Byte
inspection preserves code selection and function history; Decode displays its
own source address. A delayed byte reply cannot replace a newer selection or
force a switch from a newer tab.
Rows are virtualized and the incoming/outgoing indexes are built once per result.

The reference index is computed for the current session and is not serialized in
`.grproj` files. Reopening a project requires another discovery run to rebuild it.
The existing saved function inventory keeps its saved-result provenance; a
matching binary hash does not authenticate cached results. The `calls-v1` analysis
fingerprint, together with `arm64pe-v1`, invalidates older cached analysis while
preserving compatible annotations. The project schema and JSON annotation format
remain unchanged.

Data references are also session-only and do not change persisted function,
graph or decompiler results, so this increment keeps the existing fingerprint.
Legacy replies without a data report are shown as not analyzed, not as a fresh
empty result. Work counters, sorted/unique evidence, source ownership and complete
mapped target extents are validated before adoption.

The worker reports **Seeds**, **Calls** (shown as **Analyzing references**), and
**Publish** stages with the number of
functions examined and decode attempts charged. The total remains indeterminate:
following a confirmed call can reveal more work. These counts are work measures,
not completion percentages. Cancellation still terminates the disposable worker,
and progress messages do not reset CPU or wall-time deadlines. Existing binary
identity, immutable snapshots, result validation, and platform resource controls
continue to apply.

## ARM64 PE runtime metadata and import veneers

Opening a Windows ARM64 PE reads its ordered eight-byte runtime records from the
exception directory. Normal packed records and supported version-zero full
`.xdata` records establish primary function entries and validated file-backed
code regions. Existing entry/export names take priority. Packed fragments and
full records with chained phantom prologs retain regions but do not independently
seed functions. They can still be reached through separate export or confirmed
call evidence. Parent `.pdata` links, custom context/trap unwind codes, SVE-specific
`save_any` forms and reserved or unsupported encodings are omitted with a partial
coverage warning. This is metadata recovery, not stack unwinding or exception-flow
reconstruction. Leaf functions without runtime records still require other evidence.

Directory storage is capped at 8 MiB and 500,000 records. An additional shared
8 MiB inspection budget covers all full unwind records, including repeated
references and failed reads. Code lengths, alignment, version, storage extents,
epilog indices and opcode boundaries are validated. Unordered tables and groups
of overlapping regions are omitted. The shared 262,144-function inventory cap
and entry/export/nearest-runtime-start priority remain in effect.

At established entries or confirmed direct-call targets, a bounded recognizer
names the exact `ADRP Xn; LDR Xm,[Xn,#offset]; BR Xm` veneer when its checked
address calculation reaches a named, aligned, file-backed non-executable IAT
slot. Engine instructions and p-code confirm the sequence. Generic generated
function names can be promoted; meaningful names remain intact. No byte-pattern
scan seeds functions and the on-disk IAT value is never a runtime destination.
The independent CFG keeps the register branch unresolved. BTI-prefixed and other
veneer shapes, delay imports, and imported prototypes remain deferred.

Naming on open checks at most 2,048 known entries, with at most 6,144 engine
instruction attempts. Selected-function decompilation checks at most eight CFGs
with the existing 2,048-attempt per-CFG limit, then at most 2,048 veneer candidates.
Discovery instead charges veneer instruction attempts within its shared 16,384
limit; reaching a candidate or instruction limit marks the report partial. Stage
counts cover discovery work and do not include loading or separately requested
decompilation. Conventional UPX stubs remain excluded from discovery,
decompilation and load-time veneer decoding.

## Upstream provenance and remaining work

The confirmed-call and call-to-fallthrough exclusion rules are adapted from
[Ghidra FunctionAnalyzer.java](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/FunctionAnalyzer.java)
at revision `9a723ce99952771b8368329503aa589ae233e916`, under Apache License 2.0.
The Rust adaptation uses the desktop's existing instruction recovery, bounded
queues, explicit result provenance, and public engine APIs. Attribution is
retained in [NOTICE](../NOTICE).

The direct-memory `COPY`/`LOAD`/`STORE` reference rules adapt a bounded subset of
[Ghidra SymbolicPropogator.java](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/program/util/SymbolicPropogator.java)
at the same revision and license. The original Java pass propagates symbolic
state and uses the Program database; this adaptation does neither. Other direct
memory operands use the public engine's p-code semantics. Original x86 and ARM64
instruction fixtures test positive evidence and deliberate non-recovery, and real
contained workers cover ARM64 literal accesses in ELF, PE and Mach-O.

The pinned `ghidra-decompiler` revision remains
`268c3a406d8d964bc00ae2ead4d3e1e1373aaa27`; its recorded Ghidra base is
`d6192cb3f9`. Ghidra's Java `AutoAnalysisManager` and `Analyzer` framework depend
on its Program database and event system. These increments adapt selected
algorithms into the native worker; they do not port that framework or add a Java
or Python runtime dependency.

The ARM64 PE metadata reader is an independent implementation of
[Microsoft's ARM64 exception-handling format](https://learn.microsoft.com/en-us/cpp/build/arm64-exception-handling?view=msvc-170).
It is separate from Ghidra's Java database analyzers. The import recognizer uses
public APIs from the unchanged pinned engine. Original assembly and synthetic PE
metadata fixtures cover isolated runtime entries, fragments, a real named import
call and an unresolved veneer branch through production worker containment.

Switch/jump-table recovery, general constant propagation, speculative operand
references, exception flow, no-return analysis, and complete stripped-function
recovery are not supplied by this pass. Existing engine behavior may still expose
some of these constructs during decompilation; this pass does not establish
their missing targets for the desktop's independent CFG.

No speed or memory improvement over Ghidra is claimed. Comparisons must measure
end-to-end time and total memory, including workers and duplicated image bytes,
using the same executable hash and comparable analysis scope. Native platform
validation must be reported separately from the architecture of the input image.
See [analysis measurements](analysis-performance.md) for the opt-in Linux
client/worker baseline and its explicit scope limits.
