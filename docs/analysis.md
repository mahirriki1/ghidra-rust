# Analysis coverage

**Analysis → Discover functions** performs bounded confirmed-call discovery in
the disposable worker. It runs on linked x86, x86-64, and little-endian AArch64
ELF, PE, and baseline arm64 Mach-O images already supported by the desktop.
See [architecture coverage](architectures.md) for container and ABI restrictions.
Analyzing an AArch64 image on an x64 host does not establish native ARM-host
desktop support.

## Auto analysis

Opening a binary (not a saved project) shows an **Analyze binary?** dialog, and
**Analysis → Auto analyze…** shows the same choices later. Function discovery and
defined strings are checked by default; FindCrypt is optional. Choices last for
the session. Selected analyses run one at a time, only while the worker has no
other request: strings, then FindCrypt, then discovery. Navigation preempts a
running scan, which reruns afterwards; a failed or timed-out step is not retried.
Automatic results do not switch the middle tab. **Analysis → Cancel analysis**
stops the remaining steps. Packed images that disable discovery skip that step.

## Confirmed calls and functions

The walk starts from the validated image entry point and known functions supplied
by symbols, PE exports, and supported PE runtime-function metadata. It decodes
reachable instructions and adds only genuine direct-call targets in file-backed
executable memory as new function candidates. Targets must meet the selected
architecture's alignment requirements. A call to its own fallthrough address does
not seed a function. The parent owns a deterministic session queue: entry first, then the admitted
function inventory in its existing address order. Duplicate entries are examined
once per session; newly confirmed callees are scheduled for later batches.

Arbitrary constants and unresolved register targets do not create functions;
function-start patterns are a separate, strictly validated phase described below. Unknown indirect calls and branches remain unresolved.
Calls are separate from intrafunction control-flow edges. An established call
instruction is machine-code evidence; it does not reconstruct a source-language
function boundary or prove that all possible runtime calls have been found.

Each worker batch examines at most 128 explicit function seeds and makes at most
16,384 decode attempts. The parent continues across all admitted seeds; there is
no 128-function cumulative ceiling. Each function has a 2,048-attempt limit,
and its displayed graph has at most 128 blocks. The shared limit is charged for failed decodes and decoded
work omitted by display limits, so it cannot be exceeded by a final function walk.
ARM64 import-veneer confirmation during discovery charges three attempts per
eligible candidate against this same shared budget, before calling the engine.
The call-reference collection is capped at 16,384 entries per batch and in the
session aggregate. Data references have a separate 16,384-entry aggregate cap.
Both classes are deduplicated before atomic adoption. Reaching an aggregate cap
marks coverage partial while seed processing continues. Coverage is also partial
while seeds remain pending or recovery limits/failures prevent a complete walk.
A function is pending, done, partial by its own recovery limits, or failed. A
limited walk is terminal for the session; it does not restart on each Discover.
A batch stops before starting a function when fewer than 2,048 decode attempts
remain, leaving that suffix pending rather than giving it a smaller own budget.

The known-function inventory is a separate, larger budget: at most 262,144
entries, 256 bytes per name, and 8 MiB of JSON-escaped names in total, so the
largest inventory plus both reference classes fits the 32 MiB worker reply.
Each retained function costs roughly 1.2 KiB across the worker and desktop
processes; see [analysis measurements](analysis-performance.md#large-function-inventories).
Entries beyond either budget are omitted and the list is marked partial. Open
admits the entry point first and then engine symbols in address order (PE images
prioritize exports and runtime starts nearest the entry before that). Discovery
replies also reserve the callers that own published evidence. The
inventory bounds cumulative seed admission; the smaller function/decode budgets
apply independently to each batch.

Batch replies publish the inventory relative to the revision the desktop last
adopted from the same worker: unchanged, a bounded delta of upserted and removed
entries, or the complete list when the desktop holds no matching revision (each
new worker's first batch, after a rename, or after more than 16,384 journaled
changes). The desktop reconstructs and validates the complete inventory before
committing a batch, so admission, evidence ownership and partial coverage are
the same as with complete replies. The worker skips rebuilding the inventory
when it can prove the result unchanged: the batch named nothing and every owner
was already admitted, or every candidate already fit and the batch only added
the functions it named within the same budgets. Otherwise it applies the full
admission order above. During discovery the desktop retains one additional copy
of the adopted inventory, bounded by the same count and name budgets.

Conventional UPX PE detection still prevents discovery and decompilation of the
packed stub. Listing, CFG, strings, and byte inspection remain available. The
desktop neither unpacks nor executes the input.

## No-return calls

Calls to named functions such as `exit`, `abort`, `__stack_chk_fail`, and
`ExitProcess` end their CFG block with no successor. Their actual call sites
and direct targets remain available for discovery and navigation. A separate
branch can still reach code after the call. The graph header and call list show
**[no return]**; listing hover text and call-list hover text explain the evidence.
This prevents padding or a neighbouring function after such a call from being
claimed as part of its caller, including during function-start pattern validation.

Recognition uses the binary's original function symbols/import stubs and the
Ghidra list for its container, with the explicit native exclusions and
supplements documented in [the data provenance](../data/no-return/README.md).
Names compare exactly after narrow container-specific decoration removal;
substrings, analyst renames, and demangled leaf names never establish evidence.
At most 4,096 named entries and import slots are retained per image; omissions
are reported in Analysis notes. Reopening the worker rebuilds the index from
the immutable binary, independently of saved analysis and synchronized names.

PE calls through a named IAT slot, a conventional x86 `JMP [IAT]` thunk, or an
exact ARM64 `ADRP/LDR/BR` veneer can also establish no-return behavior. The IAT
slot stays data, and an indirect call's runtime address remains unresolved.
Extra thunk decodes, including failed checks, consume the walk's instruction
budget. The verified `__libc_start_main` slots from the x86-64 ELF startup
recognizer are supported even when `main` already has a symbol. Other ELF
`-fno-plt` calls and register-carried import pointers remain unsupported.

The engine's public prototype flag is set for recognized named functions and
resolved PE thunks before decompilation. This improves pseudocode for those
calls; direct IAT-call termination is currently a desktop CFG guarantee only.
The pinned engine, executable formats, compiler output, and ABI still limit
what pseudocode can recover. No engine cache or dependency was changed.

Wrapper inference is deferred: a custom function whose only action is calling
`exit` does not automatically become no-return in its callers. Suspicious bytes
after an unresolved call, recursive cycles, and decode failures are not proof.
Exceptions and longjmp-style nonlocal destinations are not reconstructed.
Old graph/discovery caches refresh under the new fingerprints; annotations and
the SQLite schema remain compatible. Saved markers retain saved-analysis
provenance and never seed live classification.

## Stripped ELF startup

Stripped executables have no symbol for `main`. In a dynamically linked x86-64
ELF executable (non-PIE or PIE, with an interpreter), glibc's entry code passes
`main` to the imported `__libc_start_main` as a pointer rather than calling it, so
direct-call discovery from the entry cannot reach it. On open, the worker
follows the entry's straight-line instructions in engine p-code (at most 256
bytes and 64 instructions, with fixed p-code and tracked-value budgets) until a
call. The call must target `__libc_start_main` through a GOT slot or an engine
import stub that itself jumps through such a slot. Slots are identified from the
ELF's own `GLOB_DAT`/`JUMP_SLOT` relocations against the undefined dynamic symbol,
not from names alone. The first argument (`RDI`) must then hold either a complete
constant or the contents of a slot whose `RELATIVE` relocation, or symbol
relocation against a function defined in the executable, establishes the
address. A slot is trusted only while the path has not stored to it: stores
through the entry stack pointer are allowed, but a store at a constant address
overlapping the slot, or at any other computed address, discards its relocated
contents. A conditional branch, jump, unrelated call, partial register write or
unsupported relocation ends recognition with no result rather than a guess.

The candidate must be an aligned file-backed executable address that is not the
entry, an import stub or an existing function, and must not begin with only
landing pads followed by an unconditional jump (a startup wrapper). It is then
named `main` unless any function or data symbol already has that name, so real
symbols always win. **Analysis notes** records the recovered address, the call
that established it, and that the name is analysis-derived rather than an ELF
symbol. The desktop then opens `main` as it does for unstripped binaries, and
discovery follows its direct calls. No `_start → main` call reference is
invented: the handoff remains an indirect call.

This recognizes conventional glibc startup. AArch64 (pending original dynamic
fixtures), i386, static and static-PIE executables, musl's `_start_c` helper,
sectionless (`sstrip`) files, and wrapper-based startup variants are not
recognized. Functions reachable only through pointer tables or as callbacks
still need function-start patterns or broader pointer analysis.

## Function-start patterns

Functions reached only through pointer tables or callbacks have no direct call.
On x86-64 ELF and PE, once every queued function has been walked, discovery scans
all executable file-backed sections with Ghidra's function-start byte patterns:
the GCC set for ELF, the Windows set for PE, vendored unchanged
with their [provenance](../data/function-starts/README.md). A match is only a
candidate. It is admitted as a `FUN_` function only when:

- it is aligned, not already a function, not inside an instruction decoded from
  an established function, and not inside a PE runtime-function range;
- for patterns marked `after="defined"`, established code ends exactly at it or
  it begins its section (padding alone does not count);
- its own instruction walk decodes completely within 2,048 instructions with no
  overlap with established code, no unresolved indirect jump, no internal p-code
  branch, and no warning; every path ends in a return or an explicit jump to a
  known function (running into another function is rejected), at least one
  return exists, and every direct call targets executable code outside other
  functions' interiors; numeric `validcode` sets a minimum instruction count.

Candidates are examined in address order and each admitted function's code
joins the established code immediately, so a later match inside it is
rejected. Admitted starts become ordinary discovery seeds, so their direct
calls are followed. `codeboundary`, `possiblefuncstart`, `setcontext` and
patterns that require an existing function never create one. Before scanning,
the worker decodes any established function it has not walked, so a restarted
worker still judges candidates against all known code. Replies identify at most
16,384 newly covered entries; the parent verifies that each is a known inventory
entry and accepts it only once per worker epoch. A replacement worker may rebuild
the same coverage in bounded batches under its new epoch. The parent also checks
scan cursors against the ordered file-backed executable byte space: address gaps
cost no scan bytes, forward cursors must land in that space, and an uncharged
resume may advance only within the current 64 KiB match chunk. Coverage-only
preparation is accounted by those distinct function identities
rather than by a cursor allowance, so a full 262,144-entry inventory can be
rebuilt across multiple bounded replies and worker epochs. Cursor work has a
separate parent-owned ceiling of 256 accepted replies, including at most 64
uncharged match-point resumes. The parent also permits at most 2,097,152 complete
inventory rows to be reconstructed and validated during the pattern phase; this
check runs before an expensive adoption. Reaching any cumulative limit ends the
phase explicitly partial. Worker-reported match, validation, and byte counters do
not replenish the parent-owned allowances.

Each scan step covers at most 1 MiB, 4,096 matches per 64 KiB chunk (65,536 in
one reply), 128 validated candidates, 128 admissions and 16,384 decode attempts,
then resumes from where it stopped. A match flood, an interrupted or stalled
step, or a full inventory leaves the scan partial. Optimized code without a
recognizable prologue (for example GCC `-O2` leaf functions) is not recovered. AArch64,
32-bit x86 and Mach-O have no pattern set yet. Function rows do not yet record
which evidence created them; the discovery summary reports the number of
pattern-derived starts.

## Switch tables

A computed jump such as `jmp *table(,%rdi,8)` has no destination in its own
encoding. When the instruction walk of a known function reaches one, the worker
runs the engine's flow analysis with jump-table recovery for that function, as
Ghidra's switch analyzer does, without the rest of decompilation. Each table
must belong to the exact decoded indirect jump, and each destination must be an
aligned file-backed executable address; duplicates are merged. The walk then
resumes from those destinations under the same instruction budget, so calls in
switch cases become ordinary call evidence for discovery. In the graph these
edges are labeled `S`.

A table the engine marks partial, one at its 256-entry limit, or one with any
rejected destination keeps an additional unresolved successor and a warning.
A jump without a recovered table stays unresolved, as does every jump through
an unknown register or pointer. Engine flow may follow at most 2,048
instructions per recovery; at most 32 tables and 1,024 entries are copied out.
One request starts at most 32 recoveries and none after 5 seconds of recovery
time; later functions keep their unresolved jumps with a warning, and their
discovery outcome is partial. Destinations are never promoted to new functions,
and a destination that is another known function's entry remains an external
exit. Detected packed images skip recovery. Projects saved earlier remain
readable; the changed engine fingerprint discards their cached results while
keeping annotations.

## Direct data accesses

The same discovery walk inspects already decoded instruction p-code for direct
memory reads and writes. It records genuine memory-space input/output operands
(including x86 absolute/RIP-relative accesses) and literal-address `LOAD`/`STORE`
operations (including ARM64 literal loads). Read-modify-write operations retain
both access kinds. Source function, instruction PC, target, width and access kind
are retained; no additional instruction decode or image-byte copy is required.

On x86 the pass is instruction-local. On AArch64, accesses whose pointer is a
register are revisited after the function's blocks are known, using concrete
constants carried forward within one basic block: `ADRP`/`ADR`/`MOVZ`/`MOVK`
results combined through `ADD`, `SUB`, `AND`, `OR`, `XOR`, shifts, extensions
and `PIECE`/`SUBPIECE`. Such references are labeled **propagated**; literal and
other single-instruction pointers are **instruction-local**. Knowledge is
cleared at every block start (including single-predecessor blocks, joins and
loop heads), at every direct or indirect call, and after unsupported or
omitted instructions; any write invalidates overlapping register aliases such as
`Wn` within `Xn`. Loaded values are never treated as known, so pointer chasing
stays unresolved, and `ADRP; LDR` resolves the slot that is read, not the
pointer stored there. Address formation alone (`LEA`, `ADR`, `ADRP`, or call
arguments) still creates no reference. Table entries read by switch recovery
and values carried across branches are not reported as data references. Internal p-code branches, processor-specific
user operations and unsupported semantics omit the whole instruction with
partial coverage. Control-flow operands are excluded. This is memory-access
evidence, not data-object or pointer classification.

Targets must fit the selected ABI and their entire 1–64-byte access must lie in
one validated file-backed section. Executable literal pools are accepted; zero
fill, unmapped addresses, cross-section ranges and overflowing arithmetic are
omitted. Instruction and function sources must be known file-backed executable
addresses with the architecture's alignment.

Each batch's shared pass budget charges at most 131,072 p-code operations, with at most
256 per instruction and 16 inputs per operation. At most 16,384 access candidates
are inspected, including unresolved, omitted and duplicate candidates before
deduplication. Budget or unsupported-instruction omissions mark coverage partial.
AArch64 propagation retains at most 16,384 compact p-code operations per
function and 128 known register/temporary values; exhausting either, or
accesses in instructions beyond the 128-block graph limit, also marks coverage
partial. Propagation charges no additional decode or operation budget.
These limits supplement the existing function, decode and worker resource limits.

## References and progress

After discovery, the middle pane's **References** tab shows incoming and outgoing
confirmed calls for the selected function. Callers, callees, and source instruction
addresses are navigable. A call site omitted by the caller graph's display limits
still selects its exact address and shows an explicit notice; use **Go to** to
inspect that address separately. Incoming references cover only the functions examined
in committed batches of the current session; an empty list does not prove that no caller exists.

The **Data accesses** selector shows accesses from the displayed function or
accesses beginning at an exact hexadecimal target address. This exact-start
filter does not search for accesses whose interior overlaps that address. Source
buttons select the genuine instruction PC, including the explicit display-limit
notice when necessary. Target buttons request only the accessed bytes in
**Decode**; they do not create functions or invented semantic mappings. Byte
inspection preserves code selection and function history; Decode displays its
own source address. A delayed byte reply cannot replace a newer selection or
force a switch from a newer tab.
Rows are virtualized. Batch validation, aggregate merging, and incoming/outgoing
index construction run in a parent background job. Committed references remain
visible during subsequent batches and navigation.

Saving a project stores cumulative results through the last committed discovery
batch: per-function statuses (seeds of an unfinished batch stay pending), cumulative counters, and
call and data references. The queue order, retry counts, and worker bindings are
not saved. A reopened project shows these results as **Saved analysis** in the
References tab and the discovery summary. They are display-only: **Discover**
discards them and starts a fresh queue, so a saved "complete" state cannot
suppress recomputation. **Analysis → Rediscover from scratch** likewise discards
session results and examines every known function again.

Saved discovery is untrusted input. Loading checks counts against the shared
function and reference limits, strictly ordered and unique addresses under the
same executable-code rule as seed admission, evidence owned by examined
functions, admitted call targets, cumulative counters consistent with the saved
batch count, and that pending, failed, limited, or capped results are marked
partial. This establishes structural consistency, not that the evidence matches the
instructions. Metadata and discovery share the 48 MiB metadata budget. The
discovery record has its own format fingerprint: a mismatch, or an incompatible
engine fingerprint, drops saved discovery while keeping annotations. Project
schema version 2 introduced this optional record; version 1 projects still open
without saved discovery. Current saves use version 3 for semantic tokens and local
name overrides, and still load version 2. Older releases reject newer project
versions. JSON v1 annotations remain readable; adding local names uses JSON v2. The existing saved function inventory keeps its saved-result
provenance; a matching binary hash does not authenticate cached results.

Legacy replies without a data report are shown as not analyzed, not as a fresh
empty result. Work counters, sorted/unique evidence, source ownership and complete
mapped target extents are validated before adoption.

The worker reports **Seeds**, **Calls** (shown as **Analyzing references**), and
**Publish** stages with the number of
functions examined and decode attempts charged in that batch. The UI also shows
cumulative functions examined, remaining seeds, committed batches, and a visible
partial/complete indicator. The total can grow:
following a confirmed call can reveal more work. These counts are work measures,
not completion percentages. Cancel still terminates the disposable worker and pauses the run, retaining
completed batches. Discover continues it after a worker restart. Interactive
requests run between batches, without discarding program-wide evidence. On
restart, inventory entries the fresh worker lacks or names differently (such as
discovered functions and renames) are replayed before the next batch in
requests packed by encoded size (at most 1,024 entries and 48 KiB of entries
each, below the 60 KiB request limit). Interrupted seeds retry individually at
most once; a second interruption marks them failed. When an unrelated request
(such as a decompilation) fails, times out, or ends the worker, a running
discovery continues on a fresh worker; after three such restarts without a
committed batch, or when a discovery batch or name replay itself fails, the run
pauses for explicit continuation. Pattern-scan steps report the same
`Seeds`/`Publish` progress sequence as seed batches. Batch replies are bound to their request ID, worker
epoch, binary generation, annotation revision at dispatch, and batch sequence.
Selection changes and annotation display-name edits do not invalidate machine
reference evidence from the immutable image. Stale/duplicate replies cannot
double-count committed results. Progress messages do not reset CPU or wall-time
deadlines. Existing binary
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

The direct-memory `COPY`/`LOAD`/`STORE` reference rules, and the constant
transfer and unknown-output rules used for AArch64 block-local propagation,
adapt a bounded subset of
[Ghidra SymbolicPropogator.java](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/program/util/SymbolicPropogator.java)
at the same revision and license. The original Java pass propagates symbolic
state across flow and uses the Program database; this adaptation tracks only
concrete register constants within one block and uses neither. Other direct
memory operands use the public engine's p-code semantics. Original x86 and ARM64
instruction fixtures test positive evidence and deliberate non-recovery, and real
contained workers cover ARM64 literal and propagated `ADRP; ADD; LDR` accesses,
plus a call that clobbers the base register, in ELF, PE and Mach-O.

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

Cross-block constant propagation, speculative operand references, exception
flow, inferred no-return wrappers, and complete stripped-function recovery are not
supplied by this pass. Existing engine behavior may still expose some of these
constructs during decompilation; this pass does not establish their missing
targets for the desktop's independent CFG. Switch tables are the exception
described above.

No speed or memory improvement over Ghidra is claimed. Comparisons must measure
end-to-end time and total memory, including workers and duplicated image bytes,
using the same executable hash and comparable analysis scope. Native platform
validation must be reported separately from the architecture of the input image.
See [analysis measurements](analysis-performance.md) for the opt-in Linux
client/worker baseline and its explicit scope limits.
