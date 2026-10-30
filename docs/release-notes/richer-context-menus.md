- Right-click menus now act on exactly the row or pseudocode token that was
  clicked. Opening a menu no longer moves the selection, adds history or
  follows a call; a decompiler right-click no longer selects the statement
  under the pointer. Left-click selection and double-click navigation are
  unchanged.
- Listing rows offer **Go to target** (the same resolved call or single
  branch target as Enter and double-click), **Show in Graph** (reveals that
  instruction once), **Show in Hex** (selects the instruction's file-backed
  bytes and records the step for Back / Forward), separate **Rename…** and
  **Comment…** for the clicked instruction's address rather than its call
  target, the existing xref choices, and **Copy address**, **Copy bytes**,
  **Copy instruction** and **Decode bytes**. Copy address gives a `0x`-prefixed
  address; Copy bytes gives lowercase hex separated by spaces; Copy
  instruction gives the mnemonic and operands without addresses, bytes,
  comments or callee names. Rows without cached bytes, or whose bytes are not
  file-backed, disable the byte commands.
- Decompiler call tokens offer **Go to target**, **Rename…** of the called
  function, its call-target xrefs, **Copy token** and **Copy address** of the
  real call target, even when two calls print the same name. Calls to code
  that is not a known function keep navigation and xrefs but cannot be
  renamed. Local tokens offer **Rename…** (or **Edit signature…** for a
  parameter) only with a verified storage identity, and **Copy token**. Other
  pseudocode offers only **Copy line**, the complete source line, and the
  xrefs of its mapped instructions; it never falls back to an earlier
  selection's address.
- The Functions table adds **Go to** and splits **Rename / comment…** into
  **Rename…** and **Comment…** for the clicked function. Strings rows add
  **Go to**, which opens the string's bytes in Hex. Symbol Tree function,
  label, string and section leaves gain **Go to** (or **Show in Hex** for a
  section) and **Copy row**, and Symbol Tree import, export and location
  leaves gain **Copy row**. Forwarded and unresolved exports still have no
  destination. Sorting and filtering never change which row a menu acts on.
- An open menu, or a rename dialog opened from one, is discarded instead of
  acting on changed data when the binary is reopened, the function or
  pseudocode is replaced or refreshed, annotations are edited or undone,
  reference evidence changes, or the source table is rebuilt. Shortcut keys
  pressed while a menu is open, or in the frame its command runs, are not
  passed to the desktop or the Listing.
- Copied single values are limited to 16 KiB and never split a character.
  Copying uses cached results only and starts no file or worker reads.
- Search results, Hex, the function graph, reference tables and the
  annotation browser keep their existing menus. Decompiler xrefs remain
  references to mapped instructions or call targets, not to local variables.
