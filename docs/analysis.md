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
The call-reference collection is also capped at 16,384 entries. Coverage is marked
partial when work limits or recovery failures prevent a complete walk. The known
function list retains its existing 10,000-entry cap.

Conventional UPX PE detection still prevents discovery and decompilation of the
packed stub. Listing, CFG, strings, and byte inspection remain available. The
desktop neither unpacks nor executes the input.

## References and progress

After discovery, the middle pane's **References** tab shows incoming and outgoing
confirmed calls for the selected function. Callers, callees, and source instruction
addresses are navigable. A call site omitted by the caller graph's display limits
still selects its exact address and shows an explicit notice; use **Go to** to
inspect that address separately. Incoming references cover only the functions examined
in the current discovery run; an empty list does not prove that no caller exists.

The reference index is computed for the current session and is not serialized in
`.grproj` files. Reopening a project requires another discovery run to rebuild it.
The existing saved function inventory keeps its saved-result provenance; a
matching binary hash does not authenticate cached results. The `calls-v1` analysis
fingerprint invalidates older cached analysis while preserving compatible
annotations. The project schema and JSON annotation format remain unchanged.

The worker reports **Seeds**, **Calls**, and **Publish** stages with the number of
functions examined and decode attempts charged. The total remains indeterminate:
following a confirmed call can reveal more work. These counts are work measures,
not completion percentages. Cancellation still terminates the disposable worker,
and progress messages do not reset CPU or wall-time deadlines. Existing binary
identity, immutable snapshots, result validation, and platform resource controls
continue to apply.

## Upstream provenance and remaining work

The confirmed-call and call-to-fallthrough exclusion rules are adapted from
[Ghidra FunctionAnalyzer.java](https://github.com/NationalSecurityAgency/ghidra/blob/9a723ce99952771b8368329503aa589ae233e916/Ghidra/Features/Base/src/main/java/ghidra/app/plugin/core/function/FunctionAnalyzer.java)
at revision `9a723ce99952771b8368329503aa589ae233e916`, under Apache License 2.0.
The Rust adaptation uses the desktop's existing instruction recovery, bounded
queues, explicit result provenance, and public engine APIs. Attribution is
retained in [NOTICE](../NOTICE).

The pinned `ghidra-decompiler` revision remains
`268c3a406d8d964bc00ae2ead4d3e1e1373aaa27`; its recorded Ghidra base is
`d6192cb3f9`. Ghidra's Java `AutoAnalysisManager` and `Analyzer` framework depend
on its Program database and event system. This increment adapts one useful
algorithm into the native worker; it does not port that framework or add a Java
or Python runtime dependency.

ARM64 PE unwind metadata and ADRP/LDR/BR IAT veneer recovery remain deferred.
Switch/jump-table recovery, general constant propagation, speculative operand
references, exception flow, no-return analysis, and complete stripped-function
recovery are not supplied by this pass. Existing engine behavior may still expose
some of these constructs during decompilation; this pass does not establish
their missing targets for the desktop's independent CFG.

No speed or memory improvement over Ghidra is claimed. Comparisons must measure
end-to-end time and total memory, including workers and duplicated image bytes,
using the same executable hash and comparable analysis scope. Native platform
validation must be reported separately from the architecture of the input image.
