# Function-start patterns

These files are copied unchanged from Ghidra (Apache License 2.0; see the
repository `NOTICE`) at revision `9a723ce99952771b8368329503aa589ae233e916`:

| File | Upstream path | SHA-256 |
|---|---|---|
| `x86-64gcc_patterns.xml` | `Ghidra/Processors/x86/data/patterns/x86-64gcc_patterns.xml` | `5aab53b51b73bb5b58342d2e18fa69db9f40d39e2382930284047cb586b36e2e` |
| `x86-64win_patterns.xml` | `Ghidra/Processors/x86/data/patterns/x86-64win_patterns.xml` | `3bf60152a78d7efef81dc338146245c7c484bd75b9d584a680d558356f3adf5e` |

`src/function_patterns.rs` embeds them with `include_str!` and parses them once
with a strict parser for the element subset they use; a unit test requires both
to compile. The GCC set applies to x86-64 ELF and the Windows set to x86-64 PE.

Only `funcstart` actions nominate candidates. `after="defined"` and numeric
`validcode` are honored; `codeboundary`, `possiblefuncstart`, `setcontext` and
`validcode="function"` never create a function here. See
[function-start patterns](../../docs/analysis.md#function-start-patterns) for
how candidates are validated.

To update, copy the new upstream files unchanged, record the revision and
hashes above, and rerun the unit tests and the differential benchmark.
