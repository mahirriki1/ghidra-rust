# Architecture coverage

The desktop selects its instruction set and compiler ABI from the executable
header before initializing the pinned decompiler. It has no raw-image processor
chooser or instruction-mode override. The machine being analyzed can differ from
the machine running the desktop; opening an image never executes it.

Linked executables and shared libraries with file-backed executable sections are
supported for:

- x86 and x86-64 ELF, PE, and Mach-O, preserving the existing engine ABIs.
- Little-endian AArch64 ELF with the generic 64-bit AAPCS ABI.
- Windows ARM64 PE32+ with the engine's Windows ABI.
- Thin baseline arm64 Mach-O with the engine's Apple Silicon language and ABI.

AArch64 instructions require four-byte aligned addresses and four file-backed
bytes. Invalid function entries are omitted from the list; a bad entry point
produces a loading warning. Graphs recover bounded instruction p-code through
public engine APIs: direct `B`/`BL`, conditional branches and returns retain their
machine successors, calls have separate call targets, and unresolved `BR`/`BLR`
flow stays unresolved. This is static analysis, not emulation. Instruction-level
internal p-code branches can conservatively leave successors unknown.

Decompilation uses genuine engine address marks; optimized-away instructions can
have no pseudocode counterpart. Verified local renaming uses the same
storage-backed subset on each architecture. Projects are saved as version 4,
including function signatures; versions 1–3 remain readable. See
[project formats and saved analysis](analysis.md#project-formats-and-saved-analysis)
for compatibility and provenance.

## Limits

ARM32/Thumb, big-endian images, AArch64 ILP32, arm64e (including subtype capability
bits), ARM64EC/hybrid images, other processors, universal/fat Mach-O, relocatable
objects, raw firmware and sectionless images are not supported. ARM/Thumb needs
explicit mode context, interworking, and mixed code/data support before enabling.

ELF/Mach-O symbols and PE exports seed the function list. Mach-O LC_MAIN file
offsets are translated through executable sections to virtual entry addresses.
Explicit discovery follows genuine decoded direct-call targets from the entry
and known functions on x86, x86-64, and AArch64 across the supported containers.
Constants and unknown indirect targets do not seed functions. Strictly validated
[function-start patterns](analysis.md#function-start-patterns) cover x86-64 ELF/PE;
[pointer/init metadata and FDE-corroborated tails](analysis.md#elf-pointers-and-tail-boundaries)
cover x86-64 ELF. PE, AArch64, and Mach-O pointer recovery remain unsupported.
Coverage can be partial; see [discovery and limits](analysis.md).
AArch64 PE reads normal packed and supported full unwind records to recover
stripped primary entries, and names exact ADRP/LDR/BR import veneers at established
entries and confirmed call targets. Fragment records do not independently seed
functions; parent links and unsupported unwind forms remain explicit omissions.
Export names and import slots reach the decompiler. x64 PE runtime-function
recovery and x86 import-thunk naming remain available for those architectures.

Indirect branches, jump tables, exception flow, no-return calls, stripped imports,
newer vector/ISA extensions, and platform runtime metadata can be incomplete.
Pointer authentication and authenticated/chained fixups are not recovered. See
[analysis boundaries](analysis.md#resource-limits-and-trust-boundaries) and
[NOTICE](../NOTICE) for limits and attribution.

## Regression fixtures

`tests/fixtures/aarch64.S` is original instruction source with explicit instruction
words. Tests generate minimal linked ELF, PE, and Mach-O containers in temporary
directories; no AArch64 compiler, emulator, or third-party binary is required.
Contained-worker tests exercise decoding, CFGs, semantic mappings, discovery,
annotations, and embedded projects using the production worker controls.

```sh
cargo test --locked --test aarch64
cargo test --release --locked --test aarch64
```

These tests analyze AArch64 input with the native host worker. They do not establish
native ARM-host desktop support or complete platform/compiler compatibility.
Linux results do not establish native Windows execution. Platform trust boundaries
are documented in the [Linux](linux.md#worker-isolation) and [Windows](windows.md)
guides.
