- Show compact Itanium C++ and Rust (legacy and v0) function names, such as
  `demo::Widget::operator+`, in Functions, the symbol tree, Listing and Function
  Graph call targets, References rows, headers, and the pseudocode declaration
  and verified direct-call tokens. Hover shows the exact raw symbol.
- Itanium and Rust PE exports, such as a Rust dylib's v0 exports, now get
  display names. ELF and Mach-O names the engine already demangled keep the
  same text and now show their raw symbol on hover.
- Go to accepts an exact raw symbol or display name, and the Functions filter
  matches either form. Overloads can share a display name; addresses keep them
  apart and Go to chooses the first.
- Analyst labels always win over display names, including in pseudocode.
  Labels, comments, local renames, signatures and project data remain bound to
  addresses; demangling never edits annotations or marks a project dirty.
- Display names are derived in the contained worker from bounded raw input,
  with whole-name fallback for invalid, oversized or unsupported symbols. They
  are fetched in validated, digest-bound pages, never saved in projects, and
  rebuilt when a project's verified binary is reopened. Existing projects and
  annotations load unchanged.
- MSVC-decorated names stay raw: the reviewed published MSVC demangler did not
  pass the project's safety gate, and a hardened backend is future work.
- Demangled names never establish types, prototypes or no-return behavior; a
  name such as `demo::exit` does not end a block.
- Tables are limited to 65,536 records and 8 MiB; omitted functions keep their
  inventory names. Inventory names over 256 bytes stay shortened in the engine.
