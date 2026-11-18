# Bounded MSVC demangler

This local crate, `ghidra-rust-msvc-demangler` 0.1.0, is derived from
`vendor/msvc-demangler/lib.rs` in the published `symbolic-demangle` 13.9.0
archive. Its SHA-256 is
`2a213276280a1a737ff5fb89ae2a70ba51d1d4608e74736beb92f257f125f1aa`.
The archive identifies the source snapshot. The local crate version is
independent of the upstream parser version.
[Source archive](https://crates.io/api/v1/crates/symbolic-demangle/13.9.0/download) ·
[Original parser](https://github.com/mstange/msvc-demangler-rust)

The upstream [MIT license](LICENSE.MIT) and [LLVM license](LICENSE.LLVM) are
copied unchanged. The upstream README attributes the recursion-limit change
to Sentry.

## Local modifications

- The public API is `demangle(input, Limits)`, which returns compact names.
  The syntax tree stays private, and the implementation uses safe Rust.
- Parser helpers check expanded tree height and charge node and payload visits
  against a cumulative budget. Clone and equality work is charged before it
  occurs, including backreferences to function types omitted from display.
- Cached and returned trees have a depth limit of 128. Between checks,
  helpers add at most two wrapper edges, so rejected temporary trees have
  at most 130 logical levels for recursive drop.
- The capped formatter budgets method entries, parameter visits, and attempted
  writes. Invalid syntax, trailing input, overflow, or exhaustion discards
  the whole result.

These budgets cover parsing and output operations. Use the disposable worker's
time and process limits to cover allocator and runtime overhead.
[Application limits](../../src/model.rs) · [Display behavior](../../docs/demangling.md)

Run the crate's regressions separately from root-package tests.

```sh
cargo test --locked -p ghidra-rust-msvc-demangler
cargo clippy --locked -p ghidra-rust-msvc-demangler --all-targets -- -D warnings
```
