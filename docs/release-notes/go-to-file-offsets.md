- **G** and the toolbar address field accept `file(offset)` and go to the
  address that byte of the input file is loaded at. Where it lands (the
  function, the Program listing row, or Hex) is exactly where that address
  goes, and Back/Forward and the history lists record the address.
- As in Ghidra, the offset is decimal unless it starts with `0x`/`0X`:
  `file(4620)` and `file(0x120c)` are the same byte, while `file(120c)` is
  rejected with the reason. The keyword ignores case and spaces may surround
  the offset. An exact label or function name such as `file(1)` still wins.
- Go queries take up to 16 chained hexadecimal `+`/`-` terms after an
  address or exact name, such as `main+10-4` or `401000+20+8`. Terms apply left
  to right, and any step that overflows or underflows is rejected. The fewest
  trailing terms whose remaining text is a base are used, so names containing
  `+` or `-` keep working. A leading `+1040` is still the address `0x1040`;
  `*`, `/`, other parentheses, offsets relative to the current location, and
  terms after `file(…)` are rejected.
- File offsets with no loaded address are rejected with a reason and change
  nothing: bytes before every loaded section (file headers or padding),
  padding or non-loaded bytes between sections, bytes after every loaded
  section (non-loaded sections, tables, overlays), and offsets past the end of
  the file. An offset that two sections share is rejected and names both
  addresses. Zero-filled memory has no file offset.
- The status bar shows the current location's file offset as a `file(0x…)`
  token, always in hex so it can be pasted into Go; it follows the Hex
  selection on the Hex tab and is hidden where there is no offset and on
  narrow windows. Listing rows in both scopes gain **Copy file offset**, which
  copies the offset as `0x…` (like **Copy address**) and is disabled on
  zero-filled rows.
- Fixed: after the toolbar field rejected a query, its error stayed in the
  status bar through later successful Go To and Back/Forward navigation. The
  next navigation now clears it, unless another message has replaced it.
- Limitation: the mapping uses the published sections only. Bytes that the
  operating system maps from headers or segment padding have no address in
  the app, and Hex still shows only mapped section bytes, not raw file bytes.
