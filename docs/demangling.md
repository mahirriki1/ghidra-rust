# Demangling backend

`src/symbol_names.rs` provides compact display-name primitives for future worker
integration. It is not connected to binary loading, the worker protocol, the
desktop, or project caches yet. The existing engine naming behavior remains in
use; this foundation does not add MSVC names to the desktop.

Call `symbol_names::demangle` only inside the disposable analysis worker. Supply
the image's validated container format. Keep the raw symbol and address as
identity; the helper borrows the raw string and never edits it. Results contain
qualified display text without a function parameter list or return type, or an
explicit fallback reason. These names provide no type or no-return evidence.

## Limits and fallback

Shared limits in `model.rs` bound input to 4,096 UTF-8 bytes, accepted display text
to 1,024 bytes, and successful formatter writes to 8,192. The sink refuses a write
before appending past either limit and discards the entire result after an error.
It rejects control characters and Unicode line separators; it does not truncate
or sanitize an identity. Mach-O handling removes at most one extra underscore
from a recognized mangling prefix, only when the caller selects that format.

The backend reuses the already locked `cpp_demangle` **0.5.1** and
`rustc-demangle` **0.1.28**, now direct dependencies. It tries Rust first, as the
pinned engine does, then Itanium C++. A successful parser does not authenticate
the source language: some legacy Rust and Itanium encodings overlap. Compact
names may collide, especially overloads, so callers must preserve raw identities
and addresses.

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

No new runtime, dependency version or transitive package is introduced. Both
direct crates offer MIT OR Apache-2.0 licenses; packaging already collects their
license texts from the resolved Cargo packages.

## MSVC release gate

MSVC-looking names return `BackendUnavailable`. Do not replace this with a call
to an unbounded convenience API or treat `catch_unwind` as stack-overflow or OOM
containment.

The published [`symbolic-demangle` 13.9.0 archive](https://crates.io/api/v1/crates/symbolic-demangle/13.9.0/download)
(SHA-256 `2a213276280a1a737ff5fb89ae2a70ba51d1d4608e74736beb92f257f125f1aa`)
contains an MSVC-only feature and a vendored native Rust parser. Its
`src/lib.rs` passes a recursion limit of 128. However,
`vendor/msvc-demangler/lib.rs` clones memorized name/type trees on backreferences
without a cumulative node/clone budget (`memorize_name`, `memorize_type`,
`read_var_type_inner`, `read_func_params`). `serialize` constructs a `Vec<u8>`
through recursive serializer methods without an output/work budget. Limiting the
accepted String after that allocation does not bound transient expansion. The
vendored README describes a recursion-limit modification, not additional work
or output controls. This release has not passed the project's MSVC acceptance
gate and is not added as a dependency.

Before enabling MSVC, use an audited backend with explicit parser depth,
node/backreference expansion, serializer work and output limits. Account for
destruction depth as well. A hardened fork must retain its upstream license and
attribution and be pinned independently of the engine. This document does not
claim an exploitable upstream vulnerability or that no other release can meet
these requirements.

## Integration still required

The future symbol table must capture exact original names before engine replay
or shortening, bound total records/bytes and paged replies, charge retained
metadata, bind asynchronous adoption and caches, and preserve analyst-label
precedence. Disable the engine's existing demangling only when that replacement
path is ready. Persisted presentation needs a compatible fingerprint change;
annotation identities must remain intact. None of these lifecycle changes or
the UI changes are part of this helper.

`tests/demangle_backend.rs` compiles original Rust v0 symbols on native Linux and
Windows, including a Unicode identifier, and original C++ overloads/templates
with G++ on Linux. It inspects their object symbol tables without executing them.
Rust legacy symbols have literal regression coverage: stable Rust 1.98.1 rejects
`-Csymbol-mangling-version=legacy` without unstable options, which the tests do
not enable. Object fixtures test name handling only; they do not extend the
desktop's linked-image loader support. MSVC, native macOS and the planned UI
integration are not established by these tests.
