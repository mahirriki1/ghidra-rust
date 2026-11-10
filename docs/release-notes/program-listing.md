- Choose **Program** in the Listing's title row to list the whole program in
  address order: a row for each section start, each known function's name and
  every instruction of loaded functions. **Function** remains the default and
  behaves as before.
- Bytes no loaded function decoded appear as one collapsed `??` row with
  their byte count; zero-filled section tails have their own dimmer row, and
  a function whose body has not loaded yet shows a muted `…` row. Nothing is
  linearly disassembled or guessed.
- Bodies of the functions in view, then a few beyond them in the scroll
  direction, load in batches of at most 32 functions with the lowest worker
  priority: after the selected function's graph and pseudocode, searches,
  symbol and import table pages and automatic analysis. While discovery runs,
  each committed discovery batch is followed by at most one batch for the
  bodies in view only, so the view fills in during long discovery runs;
  bodies beyond the view wait until discovery ends. Discovery waits for that
  batch at most a few seconds, and not at all when nothing in view needs a
  body.
- A batch starts no new function after about 250 ms or once its views reach
  4 MiB, and starts no further switch-table recovery once those recoveries
  have taken 250 ms, so a click queued behind a batch waits at most that long
  plus one function's analysis. A function whose tables the batch could not
  recover is never shown incomplete: it is left for a later batch, or, when
  it was the first function of its batch, shown as `??` until it is opened
  or the next change.
  Scrolling never reopens a stopped worker.
- Loaded bodies are the same views the Function Graph shows, kept for the
  session within the shared result memory budget, dropped farthest-from-view
  first, refreshed while visible after discovery, rename or signature changes,
  and released when switching back to **Function**. A function that fails to
  load is requested again only after such a change or a switch to
  **Function** and back; opening it shows its full body.
- If a batch stops or times out the analysis worker, its functions are
  retried one per request in order; only a function whose own request fails
  is skipped for that binary, and the others load normally. After eight such
  failures the binary's Program listing loads no more bodies. These failures
  never use up discovery's worker restarts, and outside discovery they never
  reopen the worker.
- The Program listing scrolls by address, so rows loading, new functions
  appearing and the selected function being refreshed during discovery, after
  a rename (including its undo) or after a signature edit keep both the
  view and the selected instruction. Use the wheel or drag the address bar
  at the right edge, which spans every section; large zero-filled tails take
  little room on it.
- Clicking an instruction opens its function in the Graph and Decompiler;
  double-click follows its call or branch target, and the right-click menu
  works on the instructions of any loaded function. Pseudocode highlights
  still come only from the displayed function's mappings.
- Functions-list clicks, pseudocode selections, Go (including `name+offset`),
  Previous / Next function and Back / Forward scroll the Program listing to the
  destination once, only when it is not already fully visible. The
  destination then keeps its place on screen while bodies above it load or
  discovery adds functions, until you scroll, use the address bar or
  navigate elsewhere. In the Program
  scope, Go also treats an instruction seen in a loaded body as code in that
  function.
- Limitations: instructions a function decodes far from its entry stay `??`
  until that function loads; an instruction overlapping another function's
  instruction with different bounds appears only in its own function; Listing
  keys still move within the displayed function; non-code destinations open
  in Hex; and the scope, position and loaded bodies are not saved in projects.
