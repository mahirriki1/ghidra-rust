# Named no-return functions

These three files are copied unchanged from Ghidra (Apache License 2.0; see
`LICENSE` and `NOTICE`) at revision `9a723ce99952771b8368329503aa589ae233e916`, from
`Ghidra/Features/Base/data/`:

| File | SHA-256 |
|---|---|
| `ElfFunctionsThatDoNotReturn` | `f1c76795ab15d2e2f954443aa81175e971fae4c954deffc127c801fddab9d9b3` |
| `PEFunctionsThatDoNotReturn` | `04dec43e29d4203244e4353a1ffb682efdc6f51d292bbf6561343dafcd382d9d` |
| `MachOFunctionsThatDoNotReturn` | `7c076a4e8d963887488ed631e4e4650766188fa83d48f760c4f5929bd91484ad` |

`src/no_return.rs` embeds these lists and selects one by the validated container.
Names compare case-sensitively with leading underscores removed. ELF symbol
versions and PLT suffixes, PE import prefixes in import context, and numeric
stdcall suffixes are normalized; decorated C++ names remain intact.

The native policy excludes `cexit`, `c_exit`, `reboot`, and `CxxFrameHandler3`:
cleanup/reboot functions can return, and the exception-dispatch personality is
not treated as an unconditional terminating call. The upstream files stay intact.
The ELF policy separately adds `__stack_chk_fail_local` and `__libc_start_main`;
the startup import is recognized through verified dynamic-relocation slots.
The Rust and Go lists are not used because compiler identification is absent.

Symbols establish an original named target, not proof about arbitrary runtime
behavior. Renames and saved results never modify the worker's classification.
See [coverage and limitations](../../docs/analysis.md#no-return-calls).

To update, copy all three upstream files unchanged, record their revision and
hashes here, review the native exclusions/supplements, and rerun focused tests,
the worker integration tests, and the differential benchmark. Changes to this
policy require a project/discovery fingerprint update.
