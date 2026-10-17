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
embedded project. CI compiles the fixture and sets this variable.
It verifies exported names reach the decompiler and that a private copy with its
export directory removed still recovers functions from x64 runtime metadata.
Without the variable, this integration check skips locally; Windows unit tests
still exercise file identity, replacement, path validation, and job lifetime.

On Linux, `scripts/build-linux.sh` runs both the direct worker protocol test and
the production WorkerClient/bubblewrap test in debug and release. The latter
requires working unprivileged namespaces and tests the host's loader layout,
Unicode paths, analysis mappings, and embedded project replacement/reopening.
It fails if sandbox startup fails; it does not substitute an unrestricted worker.

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
