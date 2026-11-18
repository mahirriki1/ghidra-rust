# Analysis fixtures

These original fixtures exercise the loader and worker. Build generated files
under ignored `target/` or a temporary directory. Open them for analysis
without running them.

## Desktop smoke test

On Linux x86-64, build the C fixture from the repository root.

```sh
gcc -g -O0 -fno-inline -fno-pie -no-pie tests/fixtures/sample.c -o /tmp/ghidra-rust-sample
```

On Windows, the native build script compiles the same source into
`target\windows-fixture\sample.exe`. [Windows build steps](../../docs/windows.md#reproduce-the-windows-checks-and-portable-zip)

Open the resulting file. Check these behaviors in the desktop.

1. Find `main`, `branch_loop`, and `decode_xor` in Functions. Open
   `branch_loop` and check its conditional edges and loop.
2. Select mapped instructions and pseudocode in both directions. Follow a
   resolved call and return with Back. Rename a function, add a comment,
   and check Undo.
3. Decode `aGVsbG8gcmV2ZXJzZXI=` as Base64 to get `hello reverser`. Select
   six bytes at `xor_message` and decode with key `hex:2a` to get `secret`.
   FindCrypt should report the AES S-box prefix at `aes_sbox_prefix`.
4. After discovery, check that **X** on the `address taken` string lists
   `remember_label`, and on the Base64 string lists `main`.
5. Save and reopen an embedded project, then try an external-binary project.
   Check annotations, selection, and **Saved analysis** provenance. Verify
   the input's SHA-256 stays the same and the worker exits with the app.

## Worker integration

The Linux build script exercises the direct protocol and the production
bubblewrap client. It requires working unprivileged namespaces. The Linux
integration compares direct-call addresses and targets with GNU objdump.

The Windows build script sets `GHIDRA_RUST_TEST_PE` for the native PE worker
test in debug and release. Run that integration separately by pointing the
variable at the built fixture. Without it, the PE check skips.

```powershell
$env:GHIDRA_RUST_TEST_PE = (Resolve-Path target/windows-fixture/sample.exe).Path
cargo test --locked --target x86_64-pc-windows-msvc --test windows_worker
cargo test --release --locked --target x86_64-pc-windows-msvc --test windows_worker
```

## Optional large PE

Put a trusted PE under ignored `target/local-input`. Set
`GHIDRA_RUST_TEST_LARGE_PE` to the copy and run:

```sh
cargo test --release --locked --test large_pe -- --ignored --nocapture
```

On Windows, add `--target x86_64-pc-windows-msvc` before `--`. Set
`GHIDRA_RUST_TEST_FUNCTION` to a hexadecimal function entry or
`GHIDRA_RUST_TEST_IMPORT` to an expected imported name when needed.
Temporary projects stay under `target/large-pe-test`.

## Demangling backend

`demangle.rs`, `demangle.cpp`, and `demangle_msvc.cpp` test compiler-generated
symbols, including Rust v0, C++ overloads and templates, and MSVC names.
The backend tests inspect object symbols directly. Linked
`demangle_program.cpp` and `demangle_program.rs` cover worker display names.
Linux uses G++ and rustc. The Windows build script sets
`GHIDRA_RUST_TEST_PE_CPP` for the MSVC DLL fixture.
[Display-name behavior](../../docs/demangling.md)

## Differential corpus

`differential/corpus.c` and `differential/many_functions.c` cover switches,
calls, no-return cases, globals, strings, and a 300-function pointer table.
The benchmark builds GCC `-O0` and `-O2`, PIE and non-PIE, with stripped
copies. It records which constructs survived compilation.
[Differential benchmark](../../docs/analysis-performance.md#differential-comparison-with-ghidra)

Other focused x86-64 fixtures include:

| Source | Coverage |
| --- | --- |
| `switch.c` | A recoverable jump table and an unresolved computed jump |
| `callbacks.c` | Function-start pattern recovery in stripped builds |
| `noreturn.c` | Terminating calls and adjacent code |
| `pointer-tables.S` | Valid and rejected pointer-table candidates and batch boundaries |
| `linkage.c` | ELF imports, exports, and immutable snapshot handling |

## AArch64

`aarch64.S` supplies instruction words for minimal ELF, ARM64 PE32+, and
baseline arm64 Mach-O files. `arm64-pe.S` adds PE runtime records and an
import veneer. No cross compiler or emulator is required. The unknown jump
in `fixture_indirect` is expected to remain unresolved.

```sh
cargo test --locked --test aarch64
```

See the input ABI limits before interpreting results.
[Architecture coverage](../../docs/architectures.md)
