- In the Listing's **Program** scope, Up/Down and PageUp/PageDown now move
  through the whole program: across function boundaries, section headers,
  function headers, collapsed `??` and zero-fill rows and pending `…` rows.
  Every row is a cursor stop, and the selection becomes the row's address: a
  function header's entry, a section's start, a gap's first byte, or the
  instruction itself. Rows sharing an address (a section start, its first
  function's header and first instruction) are separate stops. An address no
  row starts at (for example inside a gap) moves from the edge of the view,
  never to a nearby row.
- In the Program scope, Home/End go to the first/last instruction of the
  cursor's function, or to its section's first/last row from a section
  header, `??` or zero-fill row; a function whose body has not loaded goes to
  its header and `…` row. New Ctrl+Home/Ctrl+End go to the program's first and
  last rows. The **Function** scope keys are unchanged.
- When the Program cursor rests for about 200 ms, with no Listing key held,
  on a row of a function other than the displayed one, the Function Graph and
  Decompiler switch to that function without moving or pinning the listing
  and without a Back/Forward entry. Holding a key across many functions sends
  nothing until the cursor rests, then loads only the final function. The
  switch waits while a dialog, text field or menu owns input and while any
  non-background request is running (a graph, pseudocode, string or FindCrypt
  scan, byte read, rename or signature sync), and queues behind background
  work. It never starts, restarts or preempts the analysis worker: after a
  cancel, crash or deadline stop, resting switches nothing and the cursor
  stays where it is. Section headers, `??` and zero-fill rows belong to no function, so
  resting there switches nothing; a pending `…` row or a header follows its
  function.
- From the Listing, `Space` starts a waiting switch immediately when the
  worker is free and then toggles to the Graph, which may still be loading
  the cursor's function; otherwise it only toggles and the switch keeps
  waiting. Enter follows the selected
  row's call or branch target from that row's own function, adding history as
  before. Clicks, Go, Previous/Next function and Back/Forward cancel a waiting
  switch. Renaming a function from its header keeps the cursor there and
  still switches to it.
- The Program cursor is highlighted on every row kind, and pseudocode
  highlights still come only from the displayed function: moving onto another
  function's row clears them until that function is shown.
- Limitations: a follow waits for any non-background request already sent
  to the worker to finish, so a long string or FindCrypt scan holds it; if rows change under the cursor so that none
  starts at its address any more, the next key starts from the edge of the
  view; and which of several rows sharing an address holds the cursor is
  session-only, like the Program scope itself.
