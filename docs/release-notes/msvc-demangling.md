- Add a worker-only MSVC display-name backend for PE symbols, including qualified
  constructors, destructors, operators, templates, namespaces and vftable names;
  ordinary function parameters and return types are omitted. Worker/UI symbol
  table integration remains separate from this backend change.
- Vendor the licensed Rust MSVC parser from symbolic-demangle 13.9.0 with explicit
  parser/expanded-tree depth, cumulative node/backreference expansion, serializer
  work and output budgets. Invalid or over-budget names retain their complete raw
  fallback, with no partial display text or change to raw-name identity.
- Cover hostile nesting, template/backreference expansion and malformed symbols
  with regressions, and inspect an original MSVC C++ object fixture on Windows
  without executing it. Demangling remains a conservative grammar subset and
  still requires the disposable worker's resource limits and deadline.
