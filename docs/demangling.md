# Demangled display names

Itanium C++ and Rust (legacy and v0) function names display as compact
qualified names, such as `demo::Widget::operator+` or `demo::foo<int>`, without
parameter lists, return types or Rust legacy hashes. They appear in Functions,
the symbol tree, Listing and Function Graph call targets, References rows,
headers and Go to. Pseudocode prints them in the function's own declaration and
in verified direct-call tokens. Long names truncate to one row; hovering shows
the full shown name with the exact raw symbol beneath it (call tokens and call
rows keep their existing action line). The pseudocode declaration itself has no
hover; the decompiler header above it does. MSVC-decorated names in PE images use a
locally maintained, hardened backend; see [the MSVC backend](#msvc-backend).

Display names are C-like analysis text, not compilable C++ or Rust. They never
establish types, prototypes, classes, references or no-return behavior.
Overloads can share one display name; their raw symbols and addresses keep them
apart.

## Naming policy and identity

An analyst label always wins. Otherwise the desktop shows the worker's display
name, then the effective inventory name. Function labels, comments, local-rename
identities, signatures, project data and result-cache inputs remain bound to
addresses and the inventory's effective names, exactly as before. Demangling
writes no annotation, creates no undo history and never marks a project dirty.

**Go to** accepts a hexadecimal address, an exact label or inventory name, an
exact raw symbol, or an exact display name. The Functions filter matches both
the shown name and the raw symbol. When several functions share a name, the
first address wins; use the address to choose another.

Pseudocode substitutes a display name only for a token whose address the engine
verified (the decompiled function's entry, or a captured direct `CALL` target)
and only while the token still spells the engine's open-time name. Analyst
renames therefore print unchanged, and the name is chosen while text is emitted,
so every mapping and token offset measures the final text. Other identifiers,
including global data, keep engine text.

No-return recognition keeps using the original symbols. A demangled leaf name
such as `exit` from `_Z4exitv` is never evidence.

## Worker table and protocol

`src/symbol_names.rs` builds one immutable table in the analysis worker when it
opens an image, before any analyst rename is replayed. Raw names are the exact
loader symbols the engine recorded, or exact PE export names; never the engine's
shortened or collision-suffixed names. A record exists only for a demangled name
or a raw symbol the inventory name does not spell exactly. Import stubs keep the
engine's `@plt` suffix. Mach-O handling removes at most one extra underscore
from a recognized mangling prefix. Only the primary function name per address is
kept; aliases are not tabulated.

`Opened` replies announce the table's record count and SHA-256 digest. The
desktop then requests `SymbolNames` pages while the worker is otherwise idle,
after user actions and replays and before discovery batches. Limits in
`model.rs`:

- 65,536 records and 8 MiB of encoded record bytes per table; later records are
  omitted and their functions keep the inventory name.
- Pages of at most 1,024 records or 64 KiB of encoded records, whichever fills
  first. The reply preflight also bounds node counts, string sizes and line size.
- 4,096 raw bytes and 1,024 display bytes per record, with no control characters.

The adopted table and its lowercased filter keys are bounded by these limits;
they are not charged to the 64 MiB function-result store.

Each page must continue the previous cursor, keep addresses strictly ordered and
match the announced digest; the complete table must hash to it. Pages bind to
the binary generation, worker epoch and request ID. Nothing is displayed until
every page validates. A stale page is dropped. An invalid page stops the worker
and that table is not requested again for the binary; raw and inventory names
remain usable. A replacement worker for the same image keeps an adopted table or
continues an unfinished one. The table is not saved in projects: opening a
project rebuilds it from the hash-verified binary, so projects keep schema 4 and
annotation JSON v1–v3. No engine or discovery fingerprint changed.

## Backend limits and fallback

The worker's `demangle` bounds input to 4,096 UTF-8 bytes, accepted display text
to 1,024 bytes, and successful formatter writes to 8,192. The sink refuses a
write before appending past either limit and discards the entire result after an
error. It rejects control characters and Unicode line separators; it does not
truncate or sanitize an identity. Oversized or invalid names keep the inventory
name in full rather than a partial display.

The backend uses `cpp_demangle` **0.5.1** and `rustc-demangle` **0.1.28** as
direct dependencies at the versions the engine already locked. It tries Rust
first, as the engine does, then Itanium C++. A successful parser does not
authenticate the source language: some legacy Rust and Itanium encodings
overlap.

- C++ uses `ParseOptions` and `DemangleOptions` depth limits of 128 and writes
  through `structured_demangle` into the capped sink. The source is
  [`cpp_demangle` 0.5.1](https://docs.rs/crate/cpp_demangle/0.5.1/source/src/lib.rs).
- Rust uses hashless alternate formatting into the same sink. The pinned v0
  parser has a depth limit of 500. Its own one-million-byte print ceiling is not
  used as the display budget. Deferred backreference errors can appear as inline
  diagnostics while formatting succeeds; the helper rejects their diagnostic
  markers, accepting possible false negatives for unusual names spelling the
  same markers. See [`rustc-demangle` 0.1.28](https://docs.rs/crate/rustc-demangle/0.1.28/source/src/).
- Unwinding panics cause fallback. Stack overflow, abort, OOM and backend work
  that emits no text still require the worker's process memory limits and request
  deadline. A formatter-write limit is not a bound on every parser operation.

The pinned engine's own `demangle` feature remains enabled. At load it names
ELF/Mach-O functions, import stubs and global data with compact C++/Rust names,
and pseudocode prints those data names. Disabling it would turn global data and
GOT names back into raw symbols, which this table does not cover. Its load-time
formatting has `cpp_demangle`'s default recursion limits but no output cap of
its own; it runs only in the contained worker. Inventory names longer than 256
bytes remain shortened; the table's display name can be longer. PE functions
are registered without engine demangling, so Itanium or Rust PE exports gain
display names only through this table.

The Rust and Itanium direct crates offer MIT OR Apache-2.0 licenses; packaging
already collects their license texts from the resolved Cargo packages. The MSVC
path crate reuses the locked `bitflags` 2.13.2 and `itoa` 1.0.18 packages. No new
runtime or registry package/version is introduced.

## MSVC backend

PE callers select `SymbolFormat::Pe`. MSVC-looking `?` names then use the local
`ghidra-rust-msvc-demangler` path crate in `third_party/msvc-demangler/` and
report `DemangleBackend::Msvc`. Other formats retain `BackendUnavailable` for
those names. These are additive enum variants; `demangle` and the result
structure signatures are unchanged. Compact names include namespaces, templates,
constructors, destructors, operators (including conversion targets) and special
names such as `vftable`. Ordinary function parameters and return types are omitted.
The raw identity remains borrowed and unchanged. Parser or budget failures
produce whole-name fallback; no prefix is published.

The source is the Rust parser vendored in the published
[`symbolic-demangle` 13.9.0 archive](https://crates.io/api/v1/crates/symbolic-demangle/13.9.0/download),
SHA-256 `2a213276280a1a737ff5fb89ae2a70ba51d1d4608e74736beb92f257f125f1aa`.
Its upstream recursion limit alone did not meet our release gate: memorized-tree
clones and serialization were unbudgeted. We maintain the patched source here,
independently of the engine. Exact provenance, unchanged upstream license texts,
modifications and the destruction-depth argument are recorded in
[`third_party/msvc-demangler/README.md`](../third_party/msvc-demangler/README.md).

The application supplies these shared `model.rs` limits:

| Boundary | Limit and enforcement |
| --- | --- |
| Input | `MAX_SYMBOL_RAW_BYTES`: 4,096 UTF-8 bytes before parsing |
| Parser depth | `SYMBOL_DEMANGLE_RECURSION_LIMIT`: 128 guarded AST-returning helper calls |
| Expanded tree depth | 128 logical AST edges/nodes along a path, checked on helper returns and before clones; rejected temporaries add at most two wrapper edges, bounding recursive drop to 130 logical levels |
| Parse/clone expansion | `MAX_SYMBOL_MSVC_PARSE_WORK`: 32,768 cumulative units for helper entries, tree-node visits and payload bytes, including all clone preflights, deduplication comparisons, nested parses and hidden function types |
| Serialization work | `MAX_SYMBOL_FORMAT_WRITES`: 8,192 total method entries, parameter visits and attempted sink appends; includes no-output visits |
| Output | `MAX_SYMBOL_DISPLAY_BYTES`: 1,024 bytes; a capped sink checks before each append, then strict UTF-8 and shared display-character validation |

The parse budget is conservative and counts repeated walks, not only distinct
nodes. Backreference trees are checked and fully charged before cloning. Input
scanners and leaf allocation are bounded by input bytes; output, cloned payloads,
AST expansion and traversal scratch space have explicit bounds. These counters
are not instruction-level CPU or total process-memory meters. Allocator overhead,
linear scans, runtime/stack overhead, and unexpected abort/OOM/backend defects
still require the worker's resource limits and deadline. `catch_unwind` only
handles unwinding panics. No unsafe code is used. This remains a best-effort
MSVC grammar subset, with conservative fallback for rejected valid names.

Run `cargo test --locked -p ghidra-rust-msvc-demangler` separately to exercise
the vendored crate's internal adversarial checks; ordinary root `cargo test`
also covers PE integration, raw identity and fallback through `symbol_names`.

## Tests

`tests/demangle_backend.rs` compiles original Rust v0 symbols on native Linux and
Windows, including a Unicode identifier, and original C++ overloads/templates
with G++ on Linux, inspecting object symbol tables without executing them. Rust
legacy symbols have literal regression coverage: stable Rust 1.98.1 rejects
`-Csymbol-mangling-version=legacy` without unstable options.

`tests/linux_worker.rs` links original C++ (`demangle_program.cpp`, G++) and
`no_std` Rust v0 (`demangle_program.rs`) executables and checks raw records,
pseudocode call tokens, label precedence, no-return refusal and project reopen
in the sandboxed worker. Rust executables that link `std` carry a `.tbss`
section that the loader currently rejects as overlapping, which is why that
fixture avoids `std`. `tests/windows_worker.rs` checks a Rust v0 dylib's exports
and an MSVC-built DLL of the same C++ fixture, whose decorated exports display
demangled;
`scripts/build-windows.ps1` builds that DLL and sets `GHIDRA_RUST_TEST_PE_CPP`.
On native Windows, the original `tests/fixtures/demangle_msvc.cpp` is also
compiled with MSVC to an object; tests inspect constructors, destructors,
operators, templates, nested/anonymous namespaces, overload identities and a
vftable without executing it. Native macOS remains unvalidated.
