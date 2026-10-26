- Record where code takes an address without accessing it: x86 `LEA reg,[rip+X]`,
  `MOV reg, imm`, immediate stores and pushes, and AArch64 `ADR`, completed
  `ADRP; ADD` and `MOVZ`/`MOVK` compositions. Discovery evaluates engine p-code
  during its existing bounded walk and keeps this evidence separate from data
  reads and writes.
- Count only final pointer-width general-register values the instruction formed
  and pointer-width stored values. Flags, the program counter, the stack pointer,
  loaded contents, register copies, call return addresses and link registers are
  excluded. A store can show both a write to its slot and the address it stored.
- Report AArch64 `ADRP; ADD` once at the `ADD`, within one basic block; a page
  base on its own is never reported. x86 evidence is instruction-local.
- Accept targets that fit the ABI, lie at or above `0x1000`, and name a
  file-backed byte. Executable bytes qualify. Small constants, zero fill, gaps and
  overflow are counted as omitted. The floor drops genuine pointers in
  low-address images, and a mapped constant may still be a coincidental scalar.
- Rename **References → Data accesses** to **Data references** and add an
  **Address** filter beside **All / Read / Write**. Address rows show `—` for
  width, mark carried AArch64 values with `Address*`, open their exact source
  instruction, and decode 64 bytes at the target. A taken function entry opens
  normally; other taken code bytes are only inspected, never made functions.
- Press **X**, or choose **Xrefs to…**, on a **Strings** table row or a program-tree
  string to list the code that reads, writes or takes the address of exactly that
  string's first byte. Switching to Listing or Function Graph restores the code
  selection as the **X** target.
- Show both call and data-reference counts for an explicit target, so a function
  whose address is also taken does not hide its non-call users.
- Cap address-taking evidence at 16,384 references per reply and per discovery,
  and 16,384 candidates per batch. Reaching a cap marks coverage **Partial** while
  discovery continues. Address evidence never creates functions, CFG edges or
  no-return evidence.
- Discard saved discovery from earlier releases when a project opens, under a new
  discovery fingerprint, and keep annotations and other compatible results; run
  Discover to recompute references. Earlier releases discard discovery saved by
  this version. Saved address rows keep **Saved analysis** until rediscovered.
