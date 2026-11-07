- **Navigation → Previous function** and **Next function** (`Ctrl+Up` /
  `Ctrl+Down`) open the nearest known function entry before or after the
  current location. Previous from inside a function opens its own entry
  first. The current location is the selected Hex bytes (or the start of the
  shown Hex page) while Hex is open, otherwise the selected address,
  including a function still loading; typed toolbar text is never used.
- Stepping follows the address-ordered function inventory, not the Functions
  table's sort or filter. While discovery runs, only adopted entries count;
  a truncated inventory steps through its known entries. Neither command
  wraps: at the first or last entry, or with no location or no functions, the
  menu item is disabled and the shortcut does nothing.
- Stepping keeps the Function Graph tab when it is open and otherwise shows
  Listing. Each step is recorded for Back / Forward, including the Hex
  selection (or shown page) it left.
- A small arrow beside each toolbar Back and Forward button lists that
  direction's destinations, nearest first, with the address and the current
  label, function or symbol name; code inside a function shows its observed
  owner and offset, and Hex destinations are marked. Choosing a row jumps
  straight there without adding, removing or reordering history entries,
  restoring recorded Hex spans and opening code in its observed function.
  The list closes when history, names or the open binary change.
- Previous / Next function and the history lists are unavailable while a
  binary or project is opening, a file operation runs, or a dialog is open.
  The shortcuts also pause while typing or with a menu open.
