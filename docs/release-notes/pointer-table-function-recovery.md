- Recover x86-64 ELF functions from validated init/fini metadata and aligned code
  pointer tables, including PIE RELATIVE relocations and small callback tables.
- Require exact unwind-range or existing pattern corroboration and bounded CFG
  validation for table entries; reject instruction offcuts and known interiors.
- Preserve FDE-corroborated unconditional tail boundaries, accept pure tail-only
  functions, and recognize narrowly verified init/fini forwarding callbacks.
- Resume source scanning and pending table validation across batches and worker
  replacement under cumulative parent-owned work and evidence limits.
- Show a compact function-row glyph with admission details on hover. Witnesses
  remain in memory and are omitted from saved projects; the project schema and
  annotation formats are unchanged.
- Instruction address-taking, PE/AArch64 pointer recovery, general unwind formats
  and separate cold-fragment modeling remain unsupported.
