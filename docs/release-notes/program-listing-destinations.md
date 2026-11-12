- In the Listing's **Program** scope, non-code destinations now land on their
  exact Program row instead of opening Hex: **Go** (`G` and the toolbar),
  memory and program-text search results, import slots and data exports from
  the Symbol Tree and Imports/Exports, **Go to** on Strings and Symbol Tree
  rows, label and comment jumps, and Back/Forward. A string search result
  lands on its string row. The **Function** scope keeps opening Hex.
- Where no row starts at the destination, the Program listing makes one. A
  `??` row expands only the 4 KiB page or pages holding the destination's
  bytes (up to 64 KiB, clipped to that row), and an evidence row entered past
  its start expands its bytes. These count toward the 64 expanded runs kept
  for the session; when a 65th is needed, the run farthest away collapses,
  never the new one or the one you left. A zero-filled tail is split at the
  destination without reading any bytes. Landing keeps the row where it is
  on screen, never opens a function and sends nothing to the analysis
  worker.
- A destination inside a function whose body is still loading selects that
  address and lands once the body arrives, without switching tabs or adding
  history. A destination inside a decoded instruction has no row of its own
  and still opens in Hex.
- Back/Forward returns to the exact Program row you left: a section header
  and the first byte below it are told apart, and a byte row whose run was
  collapsed since is expanded again. These history entries last for the
  session only.
- **Hex / Memory Map** has a **Show in Listing** button beside **Decode
  selection**. It switches the Listing to the Program scope and puts the
  cursor on the selected bytes' row (or the page's first byte without a
  selection). Known code opens in its function, bytes inside a decoded
  instruction select that instruction, and Back returns to the same Hex span.
  Bytes of a section that has no Program rows change nothing, and the status
  bar says so.
- Label and comment jumps (the Labels tree's **Go to** and the Annotations
  browser) no longer open an address as a guessed function, in either scope.
  They open code only at a known function entry or an instruction a loaded
  function was seen to decode. Any other executable address lands on its
  Program row, or opens in Hex in the Function scope. Data addresses land on
  their Program row in the Program scope and open in Decode in the Function
  scope or when no row can exist.
- **Show in Hex** on a Listing row now first puts the cursor on that row, so
  Back returns to it. Opening the right-click menu still selects nothing.
- After a signature edit, Back/Forward to a function you opened explicitly,
  including a call target outside the function list, opens it as code again
  instead of in Hex.
