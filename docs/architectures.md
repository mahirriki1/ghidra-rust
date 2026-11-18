# Architecture coverage

The loader chooses the instruction set and compiler ABI from the executable
header. Input files need file-backed executable sections.

| Format | x86 and x86-64 | AArch64 |
| --- | --- | --- |
| ELF | Linked executables and shared libraries | Little-endian, 64-bit AAPCS |
| PE | Linked executables and DLLs | Windows ARM64 PE32+ |
| Mach-O | Thin linked images | Thin baseline Apple Silicon arm64 |

AArch64 code addresses must be four-byte aligned, with four file-backed bytes
per instruction. Direct branches, calls, and returns are decoded. Unknown
`BR` and `BLR` targets can remain unresolved.

## Limits

ARM32/Thumb, big-endian images, AArch64 ILP32, arm64e, ARM64EC, other
processors, raw firmware, archives, relocatable objects, fat Mach-O, and
sectionless images are unsupported. Pointer authentication and authenticated
or chained fixups are outside current coverage.

Symbols, exports, and supported runtime metadata seed functions. Direct-call
discovery works across the supported formats. Function-start pattern scans
cover x86-64 ELF and PE, while pointer-table recovery covers x86-64 ELF.
Windows ARM64 PE supports selected unwind records and import veneers.
[Discovery details](analysis.md)

Linux x64 and Windows x64 are the packaged desktop platforms. Analyzing an
AArch64 file on x64 establishes input support. Native ARM hosts and macOS
remain unvalidated.

## Regression fixtures

The tests use original assembly to generate minimal linked AArch64 ELF, PE,
and Mach-O images. They check contained workers, flow graphs, semantic
mappings, and project save/reopen. A native AArch64 compiler or emulator is
unnecessary. [Fixture guide](../tests/fixtures/README.md#aarch64)

```sh
cargo test --locked --test aarch64
cargo test --release --locked --test aarch64
```
