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
image memory. Inputs are analyzed, never executed. Three fresh workers per
fixture produce eighteen rows in a uniquely named JSON file in that directory.
The input hashes are checked before and after each run. Fixtures are removed
after worker shutdown; the JSON remains available for local comparison.

## Timing and memory scope

The timed sequence includes client/context creation, protected worker startup,
Open, Discover, Graph, Decompile, transport and result validation.
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
result samples, maximum observed aggregates, sample/process counts, request work
counts (including data-access candidates, operations and omissions) and result
sizes. RSS can count shared pages repeatedly. PSS apportions
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
