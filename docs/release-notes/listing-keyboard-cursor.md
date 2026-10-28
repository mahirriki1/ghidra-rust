- Move through the current function's Listing with Up/Down, PageUp/PageDown,
  and Home/End after clicking the listing; off-screen selections scroll into
  view once, and pages follow the visible listing height.
- Follow resolved calls and unambiguous branch targets with Enter or a Listing
  double-click (previously calls only); Back returns to the exact departure
  instruction, and a branch inside the function stays in that function.
- Keyboard instruction selection uses the same genuine engine mappings as
  clicks; unmapped instructions remain unmapped, and moving does not start
  analysis or add history entries.
- Text editors, dialogs, menus and file operations keep their existing key
  handling. Clicking outside the Listing (its scroll bars excepted), focusing
  a text field or switching tabs releases the keys until the Listing is clicked
  again; held keys never carry into another function.
- Switch-table, unresolved or conflicting destinations, and a jump to the
  next instruction, are not followed.
