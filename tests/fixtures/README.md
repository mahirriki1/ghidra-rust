# Native analysis fixture

`sample.c` is a small deterministic source fixture for manually checking the
initial Linux x86-64 workflow. Build it locally; generated executables should not
be committed. From the repository root, on an x86-64 Linux system with GCC:

```sh
gcc -g -O0 -fno-inline -fno-pie -no-pie tests/fixtures/sample.c -o /tmp/ghidra-rust-sample
```

Open `/tmp/ghidra-rust-sample` in the GUI and verify:

- The function list includes `main`, `branch_loop`, and `decode_xor`.
- `branch_loop` has conditional edges and a loop in the function graph.
- Selecting functions updates disassembly and requests actual decompilation.
- The strings view includes `aGVsbG8gcmV2ZXJzZXI=`. Base64 decoding yields
  `hello reverser`.
- Selecting the six bytes at `xor_message` and applying XOR with key `2a`
  yields `secret`.
- The crypto scan identifies the AES S-box prefix at `aes_sbox_prefix`.
- A function rename, comment, and saved decoded result survive a session
  save/reopen, including a portable embedded `.grproj`. The executable's SHA-256
  remains unchanged. Reopening a project displays its saved analysis provenance.

On native Windows, the [build script](../../docs/windows.md) compiles this PE
fixture and tests both debug and release GUI-subsystem workers. To run just the
worker integration check from an x64 Visual Studio developer command prompt:

```bat
mkdir target\windows-fixture
cl /nologo /Od /Zi /Fo:target\windows-fixture\sample.obj /Fd:target\windows-fixture\compiler.pdb /Fe:target\windows-fixture\sample.exe tests\fixtures\sample.c /link /INCREMENTAL:NO /PDB:target\windows-fixture\sample.pdb /EXPORT:branch_loop /EXPORT:base64_message /EXPORT:aes_sbox_prefix
set GHIDRA_RUST_TEST_PE=%CD%\target\windows-fixture\sample.exe
cargo test --locked --target x86_64-pc-windows-msvc --test windows_worker
cargo test --release --locked --target x86_64-pc-windows-msvc --test windows_worker
```

The Windows integration test uses the production suspended worker/job startup,
opens the PE from Unicode paths, verifies handle identity and writer exclusion,
requests real graph/decompiler/string results, and saves/replaces/reopens an
embedded project. `scripts/build-windows.ps1` compiles the fixture and sets this
variable when run locally without `-SkipTests`.
It verifies exported names reach the decompiler and that a private copy with its
export directory removed still recovers functions from x64 runtime metadata.
Without the variable, this integration check skips locally; Windows unit tests
still exercise file identity, replacement, path validation, and job lifetime.

On Linux, `scripts/build-linux.sh` runs both the direct worker protocol test and
the production WorkerClient/bubblewrap test in debug and release. The latter
requires working unprivileged namespaces and tests the host's loader layout,
Unicode paths, analysis mappings, and embedded project replacement/reopening.
It fails if sandbox startup fails; it does not substitute an unrestricted worker.
On the original linked C fixture, the Linux integration also compares confirmed
call instruction addresses and direct destinations with GNU objdump from binutils.

For an optional large-PE check, copy a trusted executable beneath ignored
`target/local-input`, set `GHIDRA_RUST_TEST_LARGE_PE` to that copy, and run
`cargo test --release --locked --test large_pe -- --ignored --nocapture`.
On Windows also pass `--target x86_64-pc-windows-msvc`. Optional hexadecimal
`GHIDRA_RUST_TEST_FUNCTION` selects a function; `GHIDRA_RUST_TEST_IMPORT` checks
an expected imported name in its pseudocode. The check uses production worker
containment and stores temporary projects beneath `target/large-pe-test`.
It never executes the selected input. Do not commit third-party executables or
their analysis projects.

The crypto table contains standardized numeric constants from AES (FIPS 197),
not a copied signature database. This fixture does not establish broad processor,
compiler, binary-format, C++, or Rust compatibility. Compiler-generated startup
code and addresses can vary with the compiler and system libraries.

## Differential corpus

`differential/corpus.c` and `differential/many_functions.c` are original C for
the opt-in [Ghidra differential benchmark](../../docs/analysis-performance.md#differential-comparison-with-ghidra).
They cover dense and sparse switches, indirect and tail calls, standard and
custom no-return calls, recursion, static helpers, globals, strings, and 300
distinct functions reachable only through a pointer table. The benchmark builds
them with GCC at `-O0`/`-O2`, PIE and non-PIE, plus stripped copies, beneath
ignored `target/ghidra-differential/`. The binaries are analyzed, never executed.
Optimization can remove or reshape constructs; the generated ground truth
records which jump tables, indirect calls and tail jumps actually survived.

`switch.c` is an original fixture for [switch tables](../../docs/analysis.md#switch-tables).
At `-O2`, GCC emits its dense switch as a jump table; `case_only` is called only
from one case, and `computed` tail-jumps through an unknown function pointer.
`tests/linux_worker.rs` builds PIE and non-PIE copies, checks the recovered `S`
edges, the case's call reference and decompilation, the unresolved computed jump,
and discovery of `case_only` in a stripped copy.

`callbacks.c` is an original fixture for
[function-start patterns](../../docs/analysis.md#function-start-patterns): four
callbacks reached only through a table of function pointers, and a helper called
only from them. `tests/linux_worker.rs` builds stripped `-O0`/`-O2`, PIE and
non-PIE copies and checks that every pattern-derived function exists in the
unstripped twin, and that `-O0` recovers all five.

`noreturn.c` is an original fixture for [no-return calls](../../docs/analysis.md#no-return-calls).
The Linux worker test compiles `-O0`/`-O2`, PIE and non-PIE, with stack protection,
and checks that `exit`, `abort`, and stack-failure calls end their blocks without
claiming neighbouring instructions. Stripped copies exercise discovery and
separate recovery of a callback after a no-return call. The binaries are never
executed. Synthetic x86/x64 IAT calls and ARM64 import veneers have separate
engine/worker regression coverage.

## AArch64

`aarch64.S` is original assembly with explicit little-endian instruction words.
`tests/common/mod.rs` generates minimal linked ELF64, Windows ARM64 PE32+, and
baseline arm64 Mach-O containers from it in temporary paths. The instructions
are analyzed, never executed. No cross compiler or emulator is required.
`cargo test --locked --test aarch64` exercises contained native workers, genuine
semantic mappings, and protected embedded projects for all three containers;
it also checks stripped ELF discovery and invalid instruction boundaries.
The release build scripts run this test against the optimized worker too.
See [architecture coverage](../../docs/architectures.md) for unsupported modes
and platform validation limits.

`fixture_indirect` deliberately jumps through unknown register `x2`. The engine's
"Could not recover jumptable" warning is expected there; this fixture contains
no actual jump table. Its call-like pseudocode fallback does not establish a call
target. The instruction graph retains an unresolved jump instead.

`arm64-pe.S` adds original metadata-only functions, a fragment, a caller, and a
conventional import veneer. `common::arm64_pe_metadata` embeds these in a stripped
PE with original synthetic packed/full runtime records and a named IAT slot.
The contained worker regression verifies isolated function recovery, excludes
the fragment as independent function evidence, names the confirmed import call,
retains an unresolved register branch, and checks unchanged input bytes/hash.
