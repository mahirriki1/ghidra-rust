- In the Listing's **Program** scope, undefined gaps now show evidence rows.
  Their mnemonic stays `??`, because nothing is defined there yet. An import
  slot shows the import's name. An absolute pointer-table entry that
  discovery committed shows its target address and function name. A scanned
  or saved string shows a muted, italic quoted preview as a candidate.
  Hovering shows where the evidence came from: library and kind for slots,
  the discovery evidence for pointer entries, and encoding, length and
  scanned-or-saved for strings.
- Evidence rows appear only when their whole span lies in one undefined,
  file-backed gap. Decoded instructions, function entries (also of bodies
  still loading) and expanded byte runs always win. An import slot wins over
  a pointer entry, which wins over a string; among overlapping strings, the
  longest wins. Evidence that loses is not shown at all, never cut short, and
  its bytes stay `??`. Expanding a gap shows its evidence as byte rows.
- Data and address reference targets, data exports, labels and comments now
  start a row of their own inside `??` gaps and zero-filled tails. Globals in
  `.bss` become addressable rows without any byte reads. Such a row shows the
  label (or the data export's name), a reference count and the comment. Inside an evidence row they don't
  split it; the row's hover lists them instead. Label and comment edits,
  including undo, update these rows at once.
- Evidence rows are cursor stops that belong to no function, so resting on
  one switches nothing. Home/End go to their section's first and last rows.
  Enter or a double-click on a pointer entry opens its target function with
  Back/Forward history; on import slots and strings they do nothing. The
  right-click menu offers **Show in Hex** for the row's exact bytes, **Xrefs
  to address** and **Copy address**. Evidence rows never expand.
- The evidence index is built once per change of the binary, import table,
  strings or reference report, when an annotations file is loaded, and when
  the Program scope is shown again after the Function scope. Each committed
  discovery batch adds its pointer entries and new reference targets, and
  label or comment edits update their rows, without a rebuild.
- No evidence row starts at a function entry, even one whose body failed to
  load. Text-like bytes later inside a function whose body failed to load can
  still show as a candidate string until that body loads. Pointer
  entries are not saved in projects: after a reopen they return only once
  discovery runs again.
- String scans now record each string's full byte length, even when its
  preview is truncated. Clicking a string row and its **Go to** use that
  length (up to 64 KiB) instead of the preview's size. This is an additive
  field of the version 4 project format: older projects still open, and
  older builds ignore the field and drop it when they save again. Strings
  saved without a length become evidence rows only when their preview is
  complete ASCII; otherwise they only start a row at their address.
