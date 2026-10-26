# Bounded MSVC demangler

This is a local path crate, `ghidra-rust-msvc-demangler` **0.1.0**, derived from
`vendor/msvc-demangler/lib.rs` in the published **symbolic-demangle 13.9.0**
archive. Exact source:

- <https://crates.io/api/v1/crates/symbolic-demangle/13.9.0/download>
- Archive SHA-256: `2a213276280a1a737ff5fb89ae2a70ba51d1d4608e74736beb92f257f125f1aa`
- Original parser: <https://github.com/mstange/msvc-demangler-rust>
- The archive's vendored copy does not identify a separate msvc-demangler crate
  version or Git revision. Its source snapshot is pinned by the archive hash;
  do not infer an upstream parser version from our local crate version.
- Upstream `LICENSE.MIT` and `LICENSE.LLVM` are copied unchanged. The original
  vendored README attributes its recursion-limit modification to Sentry.

## Local modifications

- Replace public AST/parse/serialize and unbounded convenience APIs with one
  `demangle(input, Limits)` entry point producing compact qualified names.
  AST types are private. No unsafe code is permitted.
- Require parser depth, input, cumulative parse-work, serializer-work and output
  budgets supplied from the application's shared `src/model.rs` constants.
  Depth has an additional structural ceiling of 128 even for other callers.
- Wrap every AST-returning parser helper in `bounded_recursion`. Check expanded
  tree height and charge each visited node and leaf payload byte at every
  successful helper return, conservatively counting repeated admission walks.
  Parser entries also cost one unit. `budget.rs` traverses iteratively, charging
  before adding each pending node. This budget is cumulative across the parse,
  including nested parses and template-local backreference contexts.
- Precharge complete expanded trees before all four clone sites: memorized name
  and type insertion, name backreferences, and type backreferences (including
  parameter-list shortcuts). Equality/deduplication walks are precharged for
  each possible comparison. Owned anonymous-namespace/string bytes and borrowed
  leaf slice lengths are charged too. These bounds include parameters/return
  types that the compact serializer will omit. AST creation consumes bounded
  input and budgeted helper calls; no unbounded expansion occurs before checks.
- Bound destruction by construction. Each helper checks its returned expanded
  tree to depth 128; cached trees and clones obey that limit. Between checks,
  a helper adds at most two logical AST edges (the `ParseResult`/`Symbol` or
  `Name`/`Operator` wrappers). Thus even a rejected temporary has depth at most
  130. Sibling vectors drop their elements sequentially. Rust drop glue and
  derived `Clone`/`PartialEq` still recurse over these depth-bounded trees;
  there is no unrestricted externally constructible AST.
- Replace the serializer's unrestricted byte vector with `CappedSink`.
  Every serializer method entry, parameter-list visit (including empty packs)
  and attempted sink append costs work. Every append checks byte capacity before
  mutation, and every error propagates immediately. Integer formatting uses
  fixed-size `itoa` buffers. No lossy UTF-8 expansion or partial result escapes.
- Reject trailing input, checked integer overflow and invalid class-less
  constructor/destructor output. Make compact vbtable names self-contained.
  Preserve the parser's existing best-effort MSVC grammar rather than claim
  complete compiler or Microsoft `undname` compatibility.
- Add original regression inputs covering real names, exponential function-type
  backreferences, hidden parameter expansion, huge templates, output bombs,
  malformed/truncated/random inputs, depth, clone precharging and capped writes.

The 32,768-unit parse budget is deliberately conservative: it is a cumulative
node/payload/clone-work budget, not a promise to accept 32,768 distinct AST nodes.
It bounds expansion allocations, while linear input scanners and allocator,
UTF-8, vector-growth and runtime overhead are not individually metered CPU
instructions. Keep use inside the disposable worker and its process limits.

From the repository root, run these tests in addition to the application's
ordinary checks (Cargo does not run dependency unit tests by default):

```sh
cargo test --locked -p ghidra-rust-msvc-demangler
cargo clippy --locked -p ghidra-rust-msvc-demangler --all-targets -- -D warnings
```
