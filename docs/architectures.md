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

Decompilation uses the same engine pipeline and genuine semantic address marks as
x86. Optimized-away instructions can have no pseudocode counterpart. Projects
retain their binary SHA-256, file identity protections, explicit saved-analysis
provenance, and bounded mapping validation. The architecture/ABI cache fingerprint
invalidates older cached results while retaining compatible JSON annotations; the
project schema remains version 1.

## Limits

ARM32/Thumb, big-endian images, AArch64 ILP32, arm64e (including subtype capability
bits), ARM64EC/hybrid images, other processors, universal/fat Mach-O, relocatable
objects, raw firmware and sectionless images are not supported. The pinned engine
embeds more processors than this desktop enables. Its ARM loader clears Thumb
symbol bits without installing the mode context needed by this application's
independent decoding and decompilation paths. Mapping symbols, Thumb context,
interworking, and mixed code/data need a separate implementation and regression
fixtures before ARM/Thumb can be enabled reliably.

ELF/Mach-O symbols and PE exports seed the function list. Mach-O LC_MAIN file
offsets are translated through executable sections to virtual entry addresses.
Explicit AArch64 discovery follows genuine direct-call targets from the entry
and known functions, with limits of 128 function graphs and roughly 16,384
instructions (plus at most one final bounded graph). It omits guesses based on
constants, indirect targets, and prologue patterns. Coverage is partial when these
budgets are reached; complete function recovery is not guaranteed.
AArch64 PE does not read ARM64 unwind records to recover stripped function entries
and does not name ADRP/LDR/BR import veneers. Export names and import slots still
reach the decompiler. x64 PE runtime-function recovery and x86 import-thunk naming
remain available for those architectures.

Indirect branches, jump tables, exception flow, no-return calls, stripped imports,
newer vector/ISA extensions, and platform runtime metadata can be incomplete.
Pointer authentication and authenticated/chained fixups are not recovered. The
existing function, graph, byte, memory, CPU, and wall-time limits apply unchanged.
The engine revision and upstream attribution in NOTICE are unchanged.

## Regression fixtures

`tests/fixtures/aarch64.S` is original instruction source with explicit instruction
words. Tests generate minimal linked ELF, PE, and Mach-O containers in temporary
directories; no AArch64 compiler, emulator, or third-party binary is required.
The contained-worker integration test covers real disassembly, branch/loop/call
recovery, unresolved indirect flow, decompilation with semantic mappings,
renaming, stripped-image discovery, invalid instruction addresses, and protected
embedded-project save/reopen. On Linux it uses production bubblewrap isolation;
on Windows it uses the production job/watchdog worker path.

```sh
cargo test --locked --test aarch64
cargo test --release --locked --test aarch64
```

These tests analyze AArch64 input with the native host worker. They do not establish
native ARM-host desktop support or complete platform/compiler compatibility.
Linux results do not establish native Windows execution. Windows still has
resource controls rather than a hostile-input filesystem/network sandbox, and
SQLite project parsing remains outside the worker.
