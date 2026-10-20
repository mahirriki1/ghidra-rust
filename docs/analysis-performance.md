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
tests do not build or change the read-only source checkout.

No improvement over Ghidra follows from these numbers or from using Rust.
A cross-tool comparison must use identical input hashes and selected addresses,
comparable pass scope/settings, native platform details, process-tree memory,
and complete timings including each tool's startup and analysis. A separate
desktop measurement must include the actual GUI and its workers before making
desktop efficiency claims.

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
difference rather than assuming immutable engine context. Any future result
cache must account for global types as well as function names, imports and CFG
boundaries. Before/after comparisons must use corresponding request sequences.
