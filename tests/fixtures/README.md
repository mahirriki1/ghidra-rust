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

On native Windows, build from an x64 Visual Studio developer command prompt:

```bat
cl /nologo /Od /Zi /Fe:sample.exe tests\fixtures\sample.c /link /EXPORT:branch_loop /EXPORT:base64_message /EXPORT:aes_sbox_prefix
set GHIDRA_RUST_TEST_PE=%CD%\sample.exe
cargo test --locked --test windows_worker
```

The Windows integration test uses the production suspended worker/job startup,
opens the PE, verifies handle identity and writer exclusion, and requests real
graph/decompiler/string results. CI compiles the fixture and sets this variable.
Without the variable, this integration check skips locally; Windows unit tests
still exercise file identity, replacement, path validation, and job lifetime.

The crypto table contains standardized numeric constants from AES (FIPS 197),
not a copied signature database. This fixture does not establish broad processor,
compiler, binary-format, C++, or Rust compatibility. Compiler-generated startup
code and addresses can vary with the compiler and system libraries.
