- Fix the Listing scroll bar: it now stays at the right edge of the view instead
  of following the widest visible row, the horizontal range no longer changes as
  rows scroll into view, and rows no longer drift from the scroll position in
  long functions. Each function keeps its own Listing and decompiler scroll
  position instead of inheriting the previous function's offset.
- Scroll the Listing or decompiler to a selected counterpart only when it is out
  of view, and center it, instead of jumping it to the top on every click.
- Keep Listing columns aligned for long encodings: the byte column shows up to
  eight bytes and elides the rest (hover a row for every byte). Column headers
  now line up with the data and scroll horizontally with it.
- Fix discovery pausing on x86-64 PE and ELF images. Function-start pattern
  steps reported progress the desktop rejected, which stopped the worker and
  left discovery paused at "scanning"; they now follow the same progress
  sequence as other batches. The status no longer shows "paused" while a worker
  restarts for navigation.
- Continue discovery on a fresh worker when an unrelated request, such as a
  decompilation, fails, times out, or ends the worker. After three restarts
  without a committed batch, or when discovery itself fails, it still pauses.
- Replay function names to a restarted worker in size-packed requests (up to
  1,024 names each, instead of 16), so discovery resumes after far fewer round
  trips on large binaries.
- Shrink the side panes with the window so the Listing and other central views
  remain visible in small windows.
- Show the Functions list, Strings, FindCrypt, both References tables, and the
  Hex memory map as column-headed tables with full-width row selection and
  fixed-height rows. Scroll bars are visible gutters at view edges.
- Merge pane titles and view switchers into one editor-style tab strip, and move
  explanatory text into tooltips. Status lines, errors, saved-analysis
  provenance, partial-coverage warnings, and "an empty result does not
  establish absence" notes remain visible.
- In References, click a call row to open its call instruction, double-click to
  open the other function, and right-click for xrefs; click a data row to open
  the accessing instruction, and right-click to decode its bytes or list
  accesses at its target. Propagated data accesses are marked with `*`.
