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

Arbitrary constants, prologue byte patterns, and unresolved register targets do
not create functions. Unknown indirect calls and branches remain unresolved.
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
arguments) still creates no reference. Jump tables and values carried across
branches require later analysis. Internal p-code branches, processor-specific
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
discovered functions and renames) are replayed in small bounded requests before
the next batch. Interrupted seeds retry individually at most
once; a second interruption marks them failed. Errors and timeouts pause the run
for explicit continuation. Batch replies are bound to their request ID, worker
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

Switch/jump-table recovery, cross-block constant propagation, speculative operand
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
