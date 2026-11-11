- Reject worker Graph/Listing replies and function inventories whose code entries
  are outside aligned executable file-backed bytes, and require each complete
  instruction span to remain in executable file-backed bytes. Executable PLT,
  stubs and veneers remain eligible; data imports and exports remain metadata.
- Reject compatible project caches containing non-code functions or graphs rather
  than displaying them as saved analysis. These structural checks do not
  authenticate cached analysis or worker-reported section metadata.
- Independently verify the retained binary SHA-256 before annotation export in
  the background file job. A mismatched worker hash or changed binary refuses
  export without replacing an existing sidecar; atomic-save guards remain active.
- Recognize Mach-O instruction attributes and symbol-stub section types when
  building executable ranges, retaining code in `__stubs`, `__auth_stubs` and
  instruction-marked sections that the object parser does not classify by name.
- Migrate old Mach-O projects when their sections exactly match the worker's
  bounded legacy section list and fresh sections only add executable code.
  Migration runs in `Opened` using metadata only; binary parsing stays in the
  contained worker, without redundant migration reads or hashes in the desktop.
  Retain annotations and adopt fresh sections while discarding
  view, decompilation, discovery, strings and crypto caches. Other metadata
  mismatches still reject loading. The new Mach-O cache fingerprint refreshes
  older Mach-O results; ELF/PE caches from the previous fingerprint remain usable.
  Limitation: a project saved for an unusual Mach-O whose previously included
  sections change executability under the new rules (for example `__text` in a
  segment without execute permission) cannot be migrated and is rejected.
- Check ABI alignment for every instruction start and signature/local-rename
  function key. Mach-O instruction attributes only admit code within a containing
  segment whose initial permissions include execute.
- Index Mach-O executable segment ranges once and bound segments and nonempty
  allocated section candidates to 4,096 each, avoiding repeated segment scans.
- Pin the previous ELF/PE engine-fingerprint compatibility exception with a test
  that requires it to be revisited when the current fingerprint changes.
