# Analysis measurements

The opt-in Linux x64 baseline measures the production contained worker from an
analysis client. Run it with the pinned toolchain and two build jobs:

```sh
PATH=/home/maki/.cargo/bin:$PATH CARGO_BUILD_JOBS=2 \
  cargo +1.98.1 test --release --locked --test analysis_baseline -- --ignored --nocapture
```

Use your own Cargo installation path when needed. GCC, bubblewrap, working user
namespaces and readable Linux `/proc` memory accounting are required. The test
fails if production containment or memory inspection fails. It never substitutes
an unrestricted worker. The baseline is excluded from normal test runs and
compiles to no tests on other platforms. It adds no desktop runtime dependency
or application command-line option.

The test generates original x86-64 ELF and AArch64 ELF/PE/Mach-O fixtures under
ignored `target/analysis-baseline/`. An additional ARM64 PE contains supported
runtime records and an import veneer; an eight-MiB padded copy exercises retained
image memory. Inputs are analyzed, never executed. A generated original C fixture with 300
named functions exercises inventories beyond one discovery batch. Three fresh
workers per fixture produce twenty-one rows in a uniquely named JSON file in
that directory.
The input hashes are checked before and after each run. Fixtures are removed
after worker shutdown; the JSON remains available for local comparison.

## Timing and memory scope

The timed sequence includes client/context creation, protected worker startup,
Open, resumable Discover through queue exhaustion, a second Discover action, Graph,
Decompile, transport and result validation. The second action must perform no
repeated seed walks.
Each request retains its normal deadline; progress cannot extend it. The report
records separate request times, elapsed time through validated decompilation,
and a separate shutdown/reaping time. Fixture compilation, builds and hashing
are outside the timed sequence. Fixture creation and hashing warm filesystem
caches; these are fresh-process measurements, not cold-cache timings.

The sampler enumerates children of every thread and follows descendants,
including bubblewrap supervisors and workers. It reads each process's
`smaps_rollup` about every ten milliseconds while waiting, and at request
completion. Client memory, worker memory, duplicated retained image bytes and
retained result objects all contribute. Counts and process start ticks guard
enumeration and shutdown accounting. The client must observe multiple processes
and wait for observed descendants to be reaped.

The report contains summed RSS and PSS observations, before-start/load/retained
result samples, maximum observed aggregates, sample/process counts, per-batch
and cumulative discovery work counts (including data-access candidates,
operations and omissions), newly admitted functions, second-action work,
serialized discovery reply bytes, and request latency. Discovery latency is the
sum of worker request times; queue construction and aggregate merging are
outside those individual timings. A second Discover after queue exhaustion
performs no worker request. RSS can count shared pages repeatedly. PSS apportions
them among processes. See the [Linux kernel's `/proc` documentation](https://docs.kernel.org/filesystems/proc.html).
Process reads are sequential, so aggregates are non-atomic estimates. Short peaks
can be missed and changing memory can skew totals in either direction. Sampling
also adds overhead to the measured latency. These are observations, not exact
process-tree high-water marks or performance thresholds.

Worker and sampler executable hashes, input hashes, engine/cache fingerprint,
Git revision/dirty state, compiler versions, kernel and available CPU count help
identify the measured configuration. The client process and allocator persist
across repetitions; workers are fresh. Retained client memory and filesystem
caches can affect later rows. Keep all repetitions when reporting results.

## Large function inventories

The opt-in `tests/large_pe.rs` run (`GHIDRA_RUST_TEST_LARGE_PE`) was sampled with
an ad hoc `/proc` process-tree sampler on Linux x64 (WSL2) against a trusted
82 MB x64 PE whose exception table holds 261,509 runtime functions. The run
includes Open, one decompilation, a string scan, and embedded project
save/reopen in the test client; only the inventory limit changed between rows.

| Inventory limit | Functions listed | Peak summed RSS | Largest process RSS |
| --- | --- | --- | --- |
| 10,000 | 10,000 | 610 MiB | 353 MiB |
| 100,000 | 100,000 | 721 MiB | 419 MiB |
| 262,144 | 261,540 (complete) | 913 MiB | 542 MiB |

That is about 1.2 KiB per retained function across worker and client. These
are single-host observations of a test client, not desktop GUI memory.

## Limits and comparison

This baseline has no native window or rendering loop. Its client is a test
process, so it is **not total desktop memory or interactive GUI latency**.
Windows and native ARM-host measurements require separate native runs. Project
save/reopen, large real-world programs and full Ghidra analysis are outside this
fixture workload. An eight-MiB padded file exercises image retention without
simulating an eight-MiB program's analysis complexity.

The Linux worker integration test also compares direct-call source PCs and
destinations in the original C fixture against GNU objdump. This is a limited
independent decoder comparison, not a Ghidra differential run.
On x86-64 it also compares the original global read/write fixture's source PCs,
access kinds and widths against GNU objdump's resolved RIP-relative operands.
Ghidra differential runs require a separately available built runtime; these
tests do not build or change the read-only source checkout. The
[differential benchmark](#differential-comparison-with-ghidra) below is the
cross-tool workflow.

No improvement over Ghidra follows from these numbers or from using Rust.
A cross-tool comparison must use identical input hashes and selected addresses,
comparable pass scope/settings, native platform details, process-tree memory,
and complete timings including each tool's startup and analysis. A separate
desktop measurement must include the actual GUI and its workers before making
desktop efficiency claims.

## Differential comparison with Ghidra

The opt-in Linux x86-64 differential benchmark analyzes identical inputs with
the production contained worker and with a separately installed Ghidra, then
reports quality and cost side by side. It measures; it does not establish that
either tool is better. Download and verify an official
[Ghidra release](https://github.com/NationalSecurityAgency/ghidra/releases)
outside this repository (the benchmark was developed against 12.1.4 with
OpenJDK 27), then run:

```sh
GHIDRA_RUST_BENCH_GHIDRA_HOME="$HOME/tools/ghidra_12.1.4_PUBLIC" \
GHIDRA_RUST_BENCH_REPEATS=3 \
  cargo +1.98.1 test --release --locked --test ghidra_differential \
  benchmark_against_ghidra -- --exact --ignored --nocapture --test-threads=1
```

GCC, binutils (`strip`, `objdump`), Python 3, bubblewrap and a Java runtime
accepted by the selected Ghidra are required. `JAVA_HOME` is honored when set.
Optional variables:

- `GHIDRA_RUST_BENCH_REPEATS`: 1–20 repetitions per tool and input (default 3).
- `GHIDRA_RUST_BENCH_CASE`: one corpus case, for example `O2-pie-stripped`.
- `GHIDRA_RUST_BENCH_INPUT`: a trusted external x86-64 ELF analyzed in place
  instead of the corpus. It has no ground truth, so only cross-tool overlap,
  decompilation outcomes and cost are reported.
- `GHIDRA_RUST_BENCH_ADDRESSES`: up to 32 comma-separated `0x` virtual
  addresses to decompile in the external input (default: its entry point).

Each run writes a new `target/ghidra-differential/run-*` directory containing
generated inputs, `truth-*.json`, one directory per tool run (request, export,
process log, and Ghidra's headless and script logs), `suite.json`, and the
comparator's `report.json` and `report.txt`. Ghidra's per-run project, settings,
cache and temporary directories are deleted after each run is measured. The test fails after writing every
report if any run failed, timed out or produced no export; failures are kept.

### Corpus and ground truth

`tests/fixtures/differential/` holds original C: dense and sparse switches,
indirect and tail calls, standard and custom no-return calls, recursion,
static helpers, globals, strings, and 300 distinct functions reachable only
through a retained pointer table. GCC builds it at `-O0` and `-O2`, PIE and
non-PIE (`-Wall -Wextra -Werror`, no `-g`); `strip --strip-all` produces a
stripped copy of each, giving eight inputs. The generated binaries are never
executed. Truth comes from the unstripped build: defined `STT_FUNC` symbols in
executable sections (aliases merged) and direct `call` instructions decoded by
GNU objdump. The harness checks that stripping left the entry point and every
allocated section's address, size and contents unchanged, so this truth also
applies to the stripped copy. Truth also records which constructs survived
compilation (indirect jumps, indirect calls, direct tail jumps); source text
alone does not establish them.

Before either tool runs, the harness fixes up to 32 decompilation targets per
configuration: every authored construct function and `main`, then evenly spaced
members of the 300-function bank. Both tools receive the same ordered list.

### What each tool runs

The ghidra-rust arm re-executes the test binary as a fresh client process per
repetition. It starts the production bubblewrap-contained worker; missing
containment is a failure, never an unrestricted fallback. It opens the input,
then runs resumable discovery from the production inventory and entry point to
queue exhaustion (300-second ceiling). Truth symbols and requested addresses are
not seeds. Inventories and call evidence are frozen before decompilation, because
decompilation can name or create functions. A requested address absent from the
frozen inventory is `not_discovered`; no function is forced into existence.
Requests keep the production 30-second deadline. A timed-out or failed worker is
not reused, so later targets are `not_attempted_after_failure`.

The Ghidra arm runs `support/analyzeHeadless` with a fresh project, settings,
cache and temporary directories under the run directory, removes inherited JVM
option variables, and passes `-loader ElfLoader -loader-loadLibraries false
-max-cpu 1 -analysisTimeoutPerFile 300` with a 2 GiB heap. Ghidra's **default
analyzer selection** is used and every analyzer option is recorded. This profile
(`ghidra-default-analyzers-cpu1`) is not a matched scope: Ghidra runs many more
analyses than ghidra-rust's direct-call discovery and function-start patterns.
`scripts/ghidra/DifferentialExport.java`
is original benchmark tooling executed by that installation as a pre- and
post-analysis script; the desktop never loads it, and it adds no Java dependency
to the application. Its pre-script verifies the imported program's SHA-256.
Its post-script freezes the function and call inventories, then decompiles the
requested set with a 30-second timeout each.

Ghidra rebases ELF images (64-bit PIE to `0x100000` by default). Exports use
**canonical RVAs** relative to the minimum `PT_LOAD` address. Ghidra addresses
are first corrected by `image base − ELF original image base`, and the script
fails if that original base differs from the independently parsed `PT_LOAD`
minimum. Exports keep raw addresses, which the comparator checks against each
RVA. Reported executable blocks are compared with the ELF's section addresses
and file offsets.

### Quality metrics

Function matching is exact entry-address equality; names, nearest addresses and
pseudocode similarity never establish a match. The **primary scope** is the
authored `bench_*` functions and `main`, including compiler-created clones such
as `.cold` parts. Recall is the fraction of their entries a tool reports.
Precision counts only tool entries inside nonzero authored symbol extents; an
entry elsewhere is not proven false merely because corpus symbols do not
describe it. Zero denominators are reported as unavailable. C runtime startup
functions form a separate runtime-recall stratum, and the report includes
whole-image symbol recall and the number of entries outside all symbols.

Call metrics compare exact (source instruction, literal destination) pairs for
direct `call` instructions inside primary extents, separately for PLT and internal
destinations. Thunks are not followed. Ghidra can override a jump's flow into a
call during analysis (tail calls, PLT jumps); the script labels those
`flow_override`, and the comparator counts them without scoring them as calls.
Indirect calls are excluded from call truth.

Each requested decompilation has exactly one status: `success`,
`not_discovered`, `timeout`, `error`, `cancelled`, `output_truncated` or
`not_attempted_after_failure`. Success is also reported relative to discovered
targets. For targets where both tools succeed untruncated, the comparator strips
comments and whitespace and renames identifiers by first occurrence, keeping
keywords, operators, literals and strings. It reports normalized exact matches
and token-trigram Dice similarity. This is **diagnostic text similarity, not
semantic equivalence or decompiler correctness**. Exports retain at most 256 KiB
of C per function and 8 MiB per run.

### Cost metrics and limits

Wall time runs from process spawn to exit. It includes the Rust client and
worker startup, or the JVM launcher, script compilation, import, analysis,
export and project deletion. Exports add per-phase timings from each tool's own
clock. Ghidra's pure import time is not available from script boundaries. The
reported JVM uptime at the pre-script covers JVM startup, import and preparation.
Memory uses the same `/proc` sampler as the baseline, rooted at each launched
process: it follows every descendant, including bubblewrap supervisors, the JVM
and Ghidra's native decompiler. It records the peak contemporaneous RSS/PSS sum,
sample count, largest gap and collection time. Distributions use nearest-rank
percentiles; with three repetitions p95 is the maximum. Raw values are retained.

Repetitions interleave the two tools for each input and alternate which tool
starts per input. Application caches are fresh per run; filesystem caches are
uncontrolled. Ghidra runs **without** the worker's sandbox, so external inputs
must be trusted. Its 2 GiB heap limit is not equivalent to the worker's 2 GiB
address-space limit. The Ghidra release and the pinned engine's upstream
decompiler baseline differ. Results describe this corpus, compiler and host.
Other compilers, C++, PE, Mach-O, AArch64 and real-world programs need separate
inputs before broader conclusions. `python3 -I scripts/compare-ghidra-benchmark.py
--suite SUITE.json --format table` re-renders a report; `--rust`, `--ghidra` and
optional `--truth` compare one export pair as JSON.

## Native Windows phase tracing and desktop sampling

Build the optional developer instrumentation with the pinned native MSVC
compiler. Check both tools, since a mismatched `PATH` can select another rustc:

```powershell
$env:RUSTUP_TOOLCHAIN = '1.98.1-x86_64-pc-windows-msvc'
cargo -V
rustc -vV
cargo build --release --locked --features performance --target x86_64-pc-windows-msvc
.\scripts\measure-windows-desktop.ps1 `
  -Executable .\target\x86_64-pc-windows-msvc\release\ghidra-rust.exe `
  -InputBinary C:\path\to\supported-program.exe -Trace -Seconds 180
```

The script launches the actual desktop with the selected image as a data
argument. It never launches the image. Interact with this window during sampling:
record the analysis options and selected addresses, dismiss the first-open prompt,
navigate A→B→A, switch Listing/Graph, exercise selection and history, and interrupt
and resume discovery. Repeat fresh launches and retain every run, including
failures. Avoid builds during measurements. Hashes, process identities, Windows
version, CPU information, sample gaps and sampler overhead are recorded under a
new `target/analysis-baseline/desktop-*` directory. Sampling ends after the duration
or after the owned desktop and workers exit; expiry leaves the desktop open.

`-Trace` sets `GHIDRA_RUST_PERF_DIR` to that new directory. With the `performance`
feature enabled, each process creates a unique trace file exclusively; it cannot
overwrite an existing file. The normal build has no trace writer. Records contain
constant phase labels and numeric metrics, not binary bytes, paths, symbol names
or decompiled text. A bounded nonblocking queue moves writes off the GUI and
analysis threads. At most 100,000 records, including saturation and shutdown
health, are written per process. Records report queue drops; the limit marker and shutdown
health identify incomplete traces. Forced worker termination can lose the tail
or leave a partial final line. Reject dropped traces for complete attribution;
use only certified completed prefixes of interrupted worker traces as described
below. A failure to create the requested trace fails startup; later writer failure does not alter analysis behavior and makes the trace unusable.
Linux worker containment and its cleared environment remain unchanged; this
feature does not make a host log directory available inside bubblewrap.

Phases cover protected worker startup, read/metadata/hash/snapshot/engine load,
inventory reconstruction and cloning, discovery CFG/decode/data collection,
serialization and pipe writes, parent parsing/validation, discovery commit,
reference-index/saved-snapshot construction, GUI adoption/filtering, graph
geometry, import resolution, inclusive engine decompilation, semantic capture,
mapping flattening and highlighting. Durations are local to each process. Join
parent request IDs with the worker PID from `worker_start`, and retain the
parent generation/epoch/selection/annotation-revision records. A restarted
worker has a new PID and its own request sequence. Accumulated discovery recovery
is a subset of discovery work; inclusive spans overlap and must not be summed
as independent costs. Progress reply serialization is included in discovery.

`navigation_frame_submission` runs from navigation dispatch through adoption and
the matching desktop UI pass; value 1 marks pseudocode submission, value 0 a
superseded navigation. `listing_frame_submission` marks its first graph/listing
UI pass. These are **frame submission proxies**, not display-presentation fences.
The initial navigation may overlap the modal analysis prompt; measure scripted
post-prompt navigation separately. Validate these records with native observation
or screenshots. No headless test establishes visible desktop responsiveness.

The external sampler includes the launched desktop and its observed descendants
at the exact executable path, including retiring workers. Concurrent unrelated
instances at that path are rejected. PID plus creation
time distinguishes process instances. Working sets may double-count shared
pages. Private bytes measure committed private virtual memory, not resident
memory or PSS. Reads are sequential, can miss short-lived workers/peaks, and add
overhead. Preserve per-process samples and contemporaneous sums; do not add
independent process peaks. Compare tracing enabled/disabled before attributing
small differences to an optimization. Fresh-process runs do not imply cold
filesystem caches or a comparison with Ghidra.

For a repeatable native worker/client workload, compile `tests/fixtures/sample.c`
using the MSVC flags in `scripts/build-windows.ps1`, set `GHIDRA_RUST_TEST_PE` to
that generated PE, and run:

```powershell
cargo test --release --locked --features performance --target x86_64-pc-windows-msvc `
  --test windows_analysis_baseline -- --ignored --nocapture --test-threads=1
```

The ignored test uses the production `WorkerClient` and Windows jobs, generated
AArch64 ELF/PE/Mach-O images, additional original simple/branch/data/large-inventory
cases. It checks evidence, mappings, semantic identities,
repeated navigation and restart/replay. Raw request replies/digests, memory samples,
parent commit/index/snapshot timings, coverage and build identities remain under
ignored `target/analysis-baseline/windows-*`. These files can contain input paths,
symbols and pseudocode; keep real-input reports local. This is a test client,
not the GUI. Use the separate desktop sampler for actual GUI observations.

`GHIDRA_RUST_BENCH_MODE=latency` (default) samples memory only between requests,
after stopping each request timer. This applies to every request, including Open,
discovery and inventory replay. `GHIDRA_RUST_BENCH_MODE=memory` also samples while
waiting for replies, preserving observations of active worker/client overlap;
its synchronous process snapshots and JSON flushes delay polling and contribute
to request latency. Both modes retain boundary samples with client and live
worker memory and check worker identity, shutdown and reaping. Latency mode can
miss transient active-worker peaks entirely; memory mode can also miss short
peaks. Samples are sequential, non-atomic observations. The ten-millisecond
interval is a minimum gap after a completed sample while waiting in memory mode,
not a guaranteed cadence. Metadata, run-start/completion and request records
identify the mode; compare corresponding sequences only within the same mode.
Request times run from send through the caller polling the terminal reply,
including reader parsing/validation and progress handling, before the terminal
boundary sample and report serialization. No reader-thread receipt timestamp is
measured. The nominal one-millisecond poll sleep may overshoot with Windows
timer/scheduling granularity, so these are caller-observed latencies. Memory rows
record collection duration and per-process cumulative `page_fault_count`;
`memory_sample_timing` records collection plus memory JSON write/flush duration.
That duration excludes its own timing-record write; per-request in-flight and
completed-run cumulative sampling totals include it. Other report/progress writes
are outside those overhead totals. Sampling overhead is observer wall time,
not a correction to subtract from request latency. Page-fault counts include
soft faults, may wrap and do not identify hard-fault or I/O latency.

`GHIDRA_RUST_BENCH_REPEATS` selects 1–20 repetitions (default 3).
`GHIDRA_RUST_BENCH_INPUT` adds any supported trusted image without executing it;
`GHIDRA_RUST_BENCH_A` and `GHIDRA_RUST_BENCH_B` optionally select two hexadecimal
function addresses. External discovery defaults to eight batches per worker.
`GHIDRA_RUST_BENCH_EXTERNAL_BATCHES=0` opts into exhaustion; another positive
value explicitly caps that measurement. Reports preserve pending counts and
partial coverage. Original/generated fixtures always run to queue exhaustion.
A cap here controls the benchmark workload, not production analysis budgets.
For exported native source copies without `.git`, supply
`GHIDRA_RUST_BENCH_SOURCE_METADATA` as a JSON file recording the original Git
revision/status and exported source hashes. `GHIDRA_RUST_BENCH_BUILD_METADATA`
can bind the fixture compiler/version/flags record. Otherwise the harness reads
Git metadata from its checkout and records unknown fixture compiler provenance.
When swapping exported source revisions in one build directory, invalidate the
application artifacts before rebuilding, for example with `cargo clean -p
ghidra-rust --release --target x86_64-pc-windows-msvc`. A source-copy tool can
preserve timestamps older than the cached objects, allowing Cargo to reuse
objects from a different source revision. Source hashes alone do not establish
which code those cached objects contain. Retain executable hashes and verify
the expected worker phases before comparing builds.

Normal `WorkerClient` destruction terminates its disposable worker, including on
ordinary desktop shutdown. A missing worker `trace_health` is therefore expected.
For worker phase attribution, use only a completed prefix ending in
`request_published`: this marker follows the terminal reply's bounded encoding,
pipe write and flush, and reports cumulative dropped-record count. Require the
initial `trace_started`, zero drops and no limit marker through that prefix, plus
a matching terminal reply independently received by the parent. Later incomplete
requests and a truncated tail do not certify any additional work. Whole-process
attribution still requires final health. `request_result_error` preserves failures.
The read-only summarizer applies these conservative prefix rules:

```sh
python3 scripts/summarize-analysis-trace.py target/analysis-baseline/desktop-RUN
```

Its phase distributions include only certified prefixes or a complete process;
it never treats a killed worker's missing lifetime tail as completed work. Check
parent replies separately and keep the raw records when comparing results.

Restart replay can expand the worker's initial inventory with newly discovered
functions. Those entries affect CFG boundaries, so terminal coverage statuses
can legitimately differ from the first pass even when evidence and pseudocode
match. Reports retain both contexts and every status digest. Controlled fixtures
enforce coverage equality when the initial inventories are equivalent; expanded
contexts are identified explicitly. Compare before/after implementations within
the same initial or replay context rather than equating these two workloads.

A→B→A can change C and mapping offsets even with an unchanged inventory: the
original AArch64 data fixture acquires shared global-type knowledge when its
callee is analyzed. The harness validates each result and records every digest
difference rather than assuming immutable engine context. The session result
store intentionally keeps the first validated result until Refresh; misses use
the warm worker. Refresh can therefore differ after shared global-type learning.
Function names and CFG inventory remain explicit cache dependencies. Before/after comparisons must use corresponding request sequences.

### Observer and allocator effects

A native Windows investigation of the inventory-delta change found two distinct
effects on the same large PE workload. Synchronous in-request memory collection
took about 20–22 ms per observation and delayed caller polling by up to 23 ms.
Use latency mode for request comparisons and a separate memory-mode run for
active-work observations; neither mode measures display presentation.

Removing discovery's temporary inventories also changed the worker's heap
history. A later import-registration pass still copied roughly 262,000 global
names into a temporary set. With fewer committed free heap pages available,
that copy incurred more page faults and decompilation took about 9–15 ms longer.
An experiment restoring the discarded allocations restored the earlier timings
and fault counts, with identical analysis results. This does not justify keeping
the discovery allocations: it identifies another avoidable copy.

PE registration now checks collisions through the pinned engine's public global
scope name index. New symbols enter that index before the next registration;
there is no retained copy of all global names. ARM64 veneer promotion reserves
only names retired during its current bounded pass, preserving the earlier
collision suffixes even after the engine releases a renamed symbol's old name.
Regression coverage compares the complete index and arena name sets, including
global data, labels, nested scopes, insertion, rename and deletion. The debug
inventory-publication oracle also compares an unchanged reply against the
previously published shadow rows, so an unjournaled mutation is detectable.

An accepted native Windows release session compared the parent implementation
(`a19d7c7`) with indexed registration in A/B/B/A order, three repetitions per
arm. Both application crates were rebuilt after clearing their artifacts; the
same latency-mode harness drove both executables. Rust and Cargo were 1.98.1
MSVC. Ten original/generated inputs produced 120 fixture repetitions, each with
a fresh worker, discovery, A/B/A navigation, worker restart and replay.

| Large x64 PE decompile, caller-observed median | Parent | Indexed names | Samples per build |
| --- | ---: | ---: | ---: |
| First A in each worker | 106.8 ms | 20.5 ms | 12 |
| A revisit | 18.1 ms | 16.1 ms | 12 |
| B | 2.8 ms | 3.0 ms | 12 |

First-A ranges were 94.0–121.0 ms and 14.9–25.4 ms respectively. These requests
followed the same eight discovery batches: 1,024 functions examined, 20,151
decode attempts and 260,590 pending functions, with partial coverage explicit.
All initial/replayed inventory, coverage/status/queue, call/data evidence and
graph/decompiled-result fingerprints matched across every fixture repetition.
Those result fingerprints include mappings and semantic identities. No uniform
speedup is claimed for functions that need no new registration or other formats.

Separate traced memory-mode runs observed first-A import resolution at about
92 ms in the parent and 1.4–1.8 ms with indexed names. One repetition per build
observed peak contemporaneous client-plus-worker private-byte sums of 784 and
772 MiB. These are sampled committed private bytes, not unique resident memory;
the observer adds overhead and can miss peaks. They are not latency-mode memory
measurements. Native desktop checks covered the large input's A/B/A navigation,
selection and Graph, plus fixture local rename/undo, comment retention, semantic
call navigation/history, refresh and embedded-project save/reopen. GUI frame
submission proxies are not display-presentation measurements. Filesystem cache
state was uncontrolled, and this is not a comparison against Ghidra.

## Per-function store measurements

`tests/analysis_baseline.rs` retains its original first-visit timing and memory
endpoints, then adds a separate two-function store workload. It measures 300
A/B/A compatible visits through the production coordinator, base graph camera and
semantic-selection adoption. `cached_visits` reports p50/p95/max, zero-request
verification and retained/pinned/uncached bytes. `B_graph_miss_ms` and
`B_decompile_miss_ms` retain the second function's actual warm-worker miss costs;
`cache_retained_memory` samples the client and worker tree with both functions
retained. The sampler still uses contemporaneous RSS/PSS and a 10 ms interval;
it can miss short peaks. Native rendering is outside these coordinator timings.
The Windows baseline writes the same store workload as `cached_function_visits`
after its independent warm-engine A/B/A correctness comparison. Run it natively
on Windows; compiling this code on Linux does not validate Windows behavior.

With `--features performance`, `function_result_lookup_adoption` measures the
native desktop's synchronous lookup/adoption separately from the existing
navigation frame-submission clock. Graph/code component misses, invalidation
reasons, admission, context preparation, retained/pinned/uncached/preparation bytes
and cumulative evicted bytes are trace events. The trace summarizer includes
these events only from its existing certified request prefixes or a complete
process trace; zero-duration lookup records remain counted as events.

For an original fixture, build with `--features capture,performance` and set
`GHIDRA_RUST_CAPTURE_CACHE_CHECK=A,B` (hexadecimal function entries),
`GHIDRA_RUST_CAPTURE_TO=<new.ppm>`, and optionally
`GHIDRA_RUST_CAPTURE_PROJECT=<new.grproj>`. This developer-only native scenario
checks A/B/A sharing, exact instruction Back/Forward, instruction/code selection,
graph rendering, Refresh recomputation and v4 save/reopen, then captures the final
frame. Results and metrics stay outside normal desktop UI. Use fresh artifact
paths and retain the raw trace; the scenario asserts its expected outcomes.

The budget is retained allocation accounting, not process RSS. Mutable discovery
continuation, temporary projections/presentation, uncached current results and
image/worker allocations remain outside it. B-tree/key overhead is charged
conservatively; payloads charge string/vector capacities with checked arithmetic.
These measurements make no comparison with Ghidra and do not establish cold-cache
or end-to-end display latency.
