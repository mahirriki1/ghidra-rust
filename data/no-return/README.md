# Named no-return functions

These Apache-2.0 lists are copied unchanged from Ghidra revision
`9a723ce99952771b8368329503aa589ae233e916`, under
`Ghidra/Features/Base/data/`. [License](../../LICENSE) · [Attribution](../../NOTICE)

| File | SHA-256 |
| --- | --- |
| `ElfFunctionsThatDoNotReturn` | `f1c76795ab15d2e2f954443aa81175e971fae4c954deffc127c801fddab9d9b3` |
| `PEFunctionsThatDoNotReturn` | `04dec43e29d4203244e4353a1ffb682efdc6f51d292bbf6561343dafcd382d9d` |
| `MachOFunctionsThatDoNotReturn` | `7c076a4e8d963887488ed631e4e4650766188fa83d48f760c4f5929bd91484ad` |

The worker selects the list by file format. It compares names case-sensitively
after removing common platform decorations, while preserving decorated C++
names. It excludes `cexit`, `c_exit`, `reboot`, and `CxxFrameHandler3` and
adds ELF `__stack_chk_fail_local` and `__libc_start_main`. Compiler-specific
Rust and Go lists require compiler identification and are outside this policy.
Analyst renames and saved results do not affect recognition.
[Recognition details](../../docs/analysis.md#no-return-calls) ·
[Name normalization](../../src/no_return.rs)

To update, copy the upstream files unchanged, record their revision and
hashes, review the exclusions and additions, and update the project/discovery
fingerprint if the policy changes. Run the focused tests, worker integration,
and differential benchmark.
