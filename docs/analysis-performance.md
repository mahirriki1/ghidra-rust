# Analysis measurements

Choose the workload that matches what you want to measure.

| Question | Workload |
| --- | --- |
| How much time and memory do the Linux client and worker use? | [Linux worker baseline](#linux-worker-baseline) |
| How do discovery and decompilation results compare with Ghidra? | [Differential benchmark](#differential-comparison-with-ghidra) |
| Where does the Windows desktop spend time? | [Windows desktop sampler](#native-windows-phase-tracing-and-desktop-sampling) |
| How much does revisiting a function cost? | [Function result store](#per-function-store-measurements) |

## Linux worker baseline

Run this on Linux x64 with GCC, bubblewrap, working user namespaces, and
access to process-tree `/proc` accounting.

```sh
CARGO_BUILD_JOBS=2 cargo +1.98.1 test --release --locked \
  --test analysis_baseline -- --ignored --nocapture
```

Reports are written under `target/analysis-baseline/`. Three fresh workers
per fixture open generated x86-64 ELF and AArch64 ELF/PE/Mach-O inputs, run
discovery, request a graph and decompilation, then shut down. The harness
also checks that a second discovery after queue exhaustion does no work.

## Timing and memory scope

The timed sequence includes startup, analysis, transport, and result
validation. The report separates shutdown and leaves fixture compilation
and hashing outside the timed sequence. The inputs and executable hashes,
engine fingerprint, compiler, and host identify each run.

The sampler reads the client and its descendants, including bubblewrap and
workers. RSS can count shared pages more than once. PSS apportions shared
pages. Figures include duplicated image bytes and retained results, but
sequential samples can miss brief peaks. Sampling itself adds overhead.
Fresh workers can still read from a warm filesystem cache.

## Large function inventories

A separate Linux x64 WSL2 test opened a trusted 82 MB x64 PE with
261,509 runtime-function records, decompiled one function, scanned strings,
and saved and reopened an embedded project. Only the inventory limit changed.

| Inventory cap | Functions listed | Peak summed RSS | Largest process RSS |
| --- | ---: | ---: | ---: |
| 10,000 | 10,000 | 610 MiB | 353 MiB |
| 100,000 | 100,000 | 721 MiB | 419 MiB |
| 262,144 | 261,540 (complete) | 913 MiB | 542 MiB |

Run the large-PE test with a local trusted input if you need a similar
workload. [Fixture guide](../tests/fixtures/README.md#optional-large-pe)

## Limits and comparison

Assess the same binary hashes and addresses, record pass settings, and include
the full process tree and end-to-end time. Report which host and tool versions
ran each workload. Use a native desktop run for interactive responsiveness.
The fixture baselines establish results for their workloads only. They do
not establish a general speed or memory advantage over Ghidra.

## Differential comparison with Ghidra

On Linux x64, install GCC, binutils, Python 3, and bubblewrap. Use a separately
installed Ghidra and a compatible Java runtime. The recorded baseline used
Ghidra 12.2 and JDK 25. Ghidra analyzes outside the Rust worker sandbox, so use
trusted external inputs. [Official Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases)

```sh
GHIDRA_RUST_BENCH_GHIDRA_HOME="$HOME/tools/ghidra_12.2_PUBLIC" \
GHIDRA_RUST_BENCH_REPEATS=3 \
  cargo +1.98.1 test --release --locked --test ghidra_differential \
  benchmark_against_ghidra -- --exact --ignored --nocapture --test-threads=1
```

| Optional setting | Effect |
| --- | --- |
| `GHIDRA_RUST_BENCH_REPEATS` | 1–20 repetitions per tool and input, default 3 |
| `GHIDRA_RUST_BENCH_CASE` | One case, for example `O2-pie-stripped` |
| `GHIDRA_RUST_BENCH_INPUT` | A trusted external x86-64 ELF. It has no ground truth. |
| `GHIDRA_RUST_BENCH_ADDRESSES` | Up to 32 comma-separated hexadecimal virtual addresses for an external input. Defaults to its entry point. |

Each suite writes a new `target/ghidra-differential/run-*` directory, or uses
`CARGO_TARGET_DIR`. It keeps input truth, per-tool exports and logs,
`suite.json`, `report.json`, and `report.txt`. Failed runs stay in the report.
To render an existing suite again, run:

```sh
python3 -I scripts/compare-ghidra-benchmark.py --suite SUITE.json --format table
```

### Corpus and ground truth

The original C corpus is built with GCC at `-O0` and `-O2`, PIE and non-PIE,
with a stripped copy of each. Truth uses defined function symbols and direct
calls decoded by GNU objdump. The harness checks that stripping preserves the
entry and allocated sections. Both tools receive the same decompilation
targets. Truth and requested targets do not seed discovery.
[Corpus fixtures](../tests/fixtures/README.md#differential-corpus)

### What each tool runs

- **Ghidra Rust** uses a fresh, production-contained worker. It runs the same
  bounded discovery as the desktop and freezes functions and calls before
  decompiling. Missing targets are reported as undiscovered.
- **Ghidra** runs `analyzeHeadless` with default analyzers, one analysis CPU,
  no library loading, a 2 GiB JVM heap, and a 300-second analysis ceiling.
  It runs additional passes beyond the Rust discovery scope. The exporter
  records the analyzer configuration and checks the imported image hash.

Addresses are compared as RVAs relative to the lowest ELF load segment after
correcting for Ghidra's rebasing. [Ghidra exporter](../scripts/ghidra/DifferentialExport.java)

### Pointer recovery measurement scope

On 2026-10-25, three Linux repetitions recovered 321 of 323 primary entries in
both optimized stripped inputs, including all 300 pointer-table entries.
The two missing entries were cold fragments. Measured primary precision was
100%, and confirmed-call precision and recall were unchanged. This corpus
has unwind or pattern evidence. Input without that evidence can have lower
recall. Additional retained memory and discovery time need their own matched
before/after run.

### Quality metrics

Function matches require exact entry addresses. Primary recall covers authored
functions and their compiler-generated clones. Primary precision scores reported
entries inside authored symbol extents. Startup symbols and entries outside
these extents are counted separately. Call metrics compare exact instruction
and destination pairs. Indirect calls and flow-overridden jumps are excluded.

The report gives a decompilation outcome per target. Text similarity uses
normalized identifiers and token trigrams. It measures resemblance between
outputs. Semantic correctness requires independent validation.

### Cost metrics and limits

Wall time covers process launch, import, analysis, export, and exit. Each tool
also reports its own phase timings. Process-tree RSS/PSS includes the JVM,
native decompiler, and bubblewrap descendants where applicable. Filesystem
caches are uncontrolled, and the JVM heap and worker address-space caps
measure different resources. Keep all repetitions, including failures.

## Native Windows phase tracing and desktop sampling

Build with the pinned MSVC toolchain and run the sampler against a trusted
input. The input is passed to the desktop as data.

```powershell
$env:RUSTUP_TOOLCHAIN = '1.98.1-x86_64-pc-windows-msvc'
cargo build --release --locked --features performance --target x86_64-pc-windows-msvc
.\scripts\measure-windows-desktop.ps1 `
  -Executable .\target\x86_64-pc-windows-msvc\release\ghidra-rust.exe `
  -InputBinary C:\path\to\program.exe -Trace -Seconds 180
```

Record the selected addresses and analysis options. Use fresh A→B→A runs
with Listing/Graph switches, selection, and history. Output goes under
`target/analysis-baseline/desktop-*`. Expiring the timer leaves the desktop open.
Working sets can double-count shared pages. Private bytes measure committed
private virtual memory. Keep contemporaneous sums and per-process samples.

With `-Trace`, each instrumented process writes bounded phase records. GUI
frame submission measures an application event before display presentation.
Parent and worker phases can overlap. Match request IDs with the worker PID.
The summarizer accepts a completed trace or a clean worker prefix ending at
`request_published`. For an interrupted worker, also verify that the parent
received the terminal reply. Drops and truncated tails can invalidate data.

```sh
python3 scripts/summarize-analysis-trace.py target/analysis-baseline/desktop-RUN
```

For the native worker/client baseline, compile the C fixture with the
Windows build script's flags, set `GHIDRA_RUST_TEST_PE`, and run:

```powershell
cargo test --release --locked --features performance --target x86_64-pc-windows-msvc `
  --test windows_analysis_baseline -- --ignored --nocapture --test-threads=1
```

Reports are under `target/analysis-baseline/windows-*` and may include input
paths, symbols, and pseudocode. Keep real-input reports local. Compare request
times using the same `GHIDRA_RUST_BENCH_MODE`. The default `latency` samples
memory at request boundaries. The `memory` mode also samples in flight and
can delay polling. Sampling is approximate in both modes.

`GHIDRA_RUST_BENCH_INPUT` adds a trusted image, and
`GHIDRA_RUST_BENCH_A` / `GHIDRA_RUST_BENCH_B` choose function addresses.
External discovery defaults to eight batches. Use
`GHIDRA_RUST_BENCH_EXTERNAL_BATCHES=0` to run to queue exhaustion.
See the harness for source/build metadata options and raw report fields.
[Windows baseline](../tests/windows_analysis_baseline.rs)

### Observer and allocator effects

On one native Windows x64 PE, synchronous memory observations took 20–22 ms
and delayed polling by up to 23 ms. Heap history also changed the cost of
an unchanged import-registration pass. An experiment restored prior
allocations and reproduced the earlier timings and fault counts.

A subsequent native Windows run compared parent `a19d7c7` and indexed symbol
registration in A/B/B/A order with Rust 1.98.1 MSVC. There were 120 fixture
repetitions with fresh workers. The large PE results followed the same eight
discovery batches and produced matching evidence and result fingerprints.

| Large x64 PE decompile, median caller-observed time | Parent | Indexed names | Samples per build |
| --- | ---: | ---: | ---: |
| First A | 106.8 ms | 20.5 ms | 12 |
| A revisit | 18.1 ms | 16.1 ms | 12 |
| B | 2.8 ms | 3.0 ms | 12 |

Separate memory-mode runs observed about 92 ms versus 1.4–1.8 ms for first-A
import resolution. One repetition per build observed summed client-plus-worker
private-byte peaks of 784 and 772 MiB. These observations apply to this workload
and retain the sampling limitations above.

## Per-function store measurements

The Linux and Windows baseline tests include 300 compatible A/B/A visits
through the result coordinator. They record cache-hit adoption, actual worker
misses, retained memory, and whether hits send worker requests. The 64 MiB
session store counts retained allocations. Workers, image copies, temporary
preparation, and uncached results also contribute to process memory.

With `capture,performance`, set `GHIDRA_RUST_CAPTURE_CACHE_CHECK=A,B`
(hexadecimal function entries), `GHIDRA_RUST_CAPTURE_TO`, and optionally
`GHIDRA_RUST_CAPTURE_PROJECT` to new output paths. The desktop scenario checks
navigation, mappings, refresh, project reuse, and navigation during restart.
[Capture setup](images/README.md)

### Recorded Linux fixture run (2026-10-25)

Linux x86-64, Rust 1.98.1, GCC 16.2.1. The before file was
`baseline-Z3B5Aq.json` at `a1ac9fe`. The after file was
`baseline-pB7RDA.json` at dirty `c1633fe`, with the implementation committed
as `5b89555`. Six input hashes matched. The generated 300-seed input differed,
so its figures are after-only.

Across 6,300 compatible visits, cache hits issued no worker requests.
Each row shows the three runs' p95 coordinator-adoption times.

| Fixture | Per-run p95 (ms) | Retained charge (bytes) |
| --- | --- | ---: |
| ARM64 ELF | 0.000247, 0.000266, 0.000266 | 31,412 |
| ARM64 Mach-O | 0.000278, 0.000689, 0.000248 | 31,457 |
| ARM64 PE | 0.000247, 0.000249, 0.000241 | 31,436 |
| ARM64 PE metadata | 0.000254, 0.000240, 0.000344 | 30,106 |
| ARM64 PE metadata, 8 MiB | 0.000289, 0.000246, 0.000238 | 30,106 |
| x86-64 ELF | 0.000344, 0.000369, 0.000302 | 49,659 |
| x86-64 ELF, 300 seeds | 0.000452, 0.000623, 0.000422 | 38,849 |

For the hash-matched x86-64 C fixture, median first graph requests were
1.073/1.079 ms before/after, and first decompilations were 4.267/3.280 ms.
Median one-function process-tree PSS was 58,271/58,675 KiB. With two functions
and shared discovery retained, after-run PSS was 58,739–58,842 KiB. The
shared host and changed retention make these figures unsuitable for an
end-to-end improvement claim.

Native Linux and Windows desktop checks passed navigation, selection, refresh,
v4 project reopen, and worker-restart assertions on the fixture. The Linux
desktop used X11 software rendering, and Windows ran in an x64 virtual machine
with software OpenGL. Four Linux cache-hit adoption spans were 7–9 µs. These
spans exclude display presentation.
