# Demangled display names

Ghidra Rust shows compact names for Itanium C++, Rust legacy and v0, and MSVC
symbols in PE. For example, `demo::Widget::operator+` appears without its
parameter list or return type. Hover a name for the exact raw symbol.

## Naming policy and identity

An analyst label takes precedence. Otherwise a demangled name is shown where
available. Display names are used in the Listing, Function Graph, tables,
Decompiler headers, and verified function declarations or direct-call tokens.
The raw symbol and address still distinguish overloads with the same display name.

**Go to** accepts exact display and raw names. If one name matches several
functions, it opens the lowest address. Use an address to pick another.
The Functions filter matches display and raw names. Naming does not infer
types, references, or no-return behavior.

## Worker table and protocol

The worker builds a bounded symbol table from the binary. The desktop uses
validated pages only after checking the full table digest. A rejected or
unavailable table leaves inventory names usable. Opening a project rebuilds
the table from the verified input. [Symbol table implementation](../src/symbol_names.rs)

## Backend limits and fallback

The app uses the pinned `cpp_demangle` and `rustc-demangle` crates plus a
local MSVC parser. The worker limits raw names to 4,096 UTF-8 bytes and
display output to 1,024 bytes, with separate formatting work limits. Invalid
text or exceeded budgets fall back to the inventory name. The engine also
demangles some symbols while loading, inside the worker's process limits.

## MSVC backend

The local parser recognizes common constructors, destructors, operators,
templates, and special names such as vftables. It limits recursion, expanded
tree size, cloning work, formatting work, and output size. The provenance,
licenses, and parser invariants are documented with the crate.
[MSVC demangler](../third_party/msvc-demangler/README.md)

## Tests

The backend tests inspect compiler-produced Rust and C++ symbols without
executing the fixtures. Native worker tests also check naming in pseudocode,
label precedence, project reopen, and Windows DLL exports.
[Fixture guide](../tests/fixtures/README.md#demangling-backend)

```sh
cargo test --locked --test demangle_backend
cargo test --locked -p ghidra-rust-msvc-demangler
```
