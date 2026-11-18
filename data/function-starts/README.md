# Function-start patterns

These Apache-2.0 files are copied unchanged from Ghidra revision
`9a723ce99952771b8368329503aa589ae233e916`, under
`Ghidra/Processors/x86/data/patterns/`. [Attribution](../../NOTICE)

| File | Input | SHA-256 |
| --- | --- | --- |
| `x86-64gcc_patterns.xml` | x86-64 ELF | `5aab53b51b73bb5b58342d2e18fa69db9f40d39e2382930284047cb586b36e2e` |
| `x86-64win_patterns.xml` | x86-64 PE | `3bf60152a78d7efef81dc338146245c7c484bd75b9d584a680d558356f3adf5e` |

Only `funcstart` can nominate a new function. The parser honors
`after="defined"` and numeric `validcode`. Discovery validates each candidate
against decoded code. [Function-start validation](../../docs/analysis.md#function-start-patterns) ·
[Parser](../../src/function_patterns.rs)

To update, copy the upstream files unchanged, record their revision and
hashes, and run the parser tests and differential benchmark.
