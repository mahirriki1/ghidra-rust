- In the Listing's **Program** scope, a collapsed `??` row now expands into
  one row per undefined byte: press Enter on it, double-click it, click its
  triangle or choose **Expand** from its right-click menu. Each byte row shows
  its address, `??`, the byte's value in hex and, when printable, its
  character. One expansion shows up to 64 KiB; the rest of the run stays one
  `??` row and can be expanded again. Enter, a double-click, the triangle on
  the run's first byte or **Collapse** on any byte row collapses its run.
- Expanding or collapsing keeps the toggled row where it is on screen, does
  not navigate and adds no Back/Forward history. Collapsing moves a cursor
  inside the run to the run's first byte. Up to 64 expanded runs are kept for
  the session; beyond that the one farthest away collapses, never the one
  holding the cursor. Expansions follow addresses, so a function body that
  loads inside an expanded run still shows its instructions there.
- Byte rows read their values in 4 KiB pages, aligned to their section and
  never past its file-backed bytes, at the Program listing's lowest priority:
  after the displayed function's graph and pseudocode, user byte reads in Hex
  or Decode, searches, table pages and automatic analysis, and during
  discovery only in the turn between batches. A page read never cancels a
  user's Hex or Decode read, and a click while one is in flight waits for it
  instead of restarting the analysis worker. At most four pages are kept;
  a byte shows `??` alone until its page loads. A page whose read fails or
  returns fewer bytes than asked is not requested again for that binary.
- `??`, byte and zero-fill rows are now clickable cursor stops. They belong
  to no function, so resting on them switches nothing. Home/End on a byte row
  go to the first/last byte of its run. Zero-filled tails never expand and
  never read bytes.
- Right-clicking a `??`, byte or zero-fill row offers **Show in Hex**, which
  opens Hex with exactly that row's file-backed bytes selected (disabled on
  zero-filled bytes), **Expand** or **Collapse**, **Xrefs to address**,
  **Copy address** and, once the bytes are loaded, **Copy bytes**.
- Back/Forward to an address that is neither a known function entry nor an
  instruction a loaded function decoded, such as a `??` or byte row the
  cursor left before **Show in Hex**, now returns the Program cursor to the
  row starting there instead of opening a function at it; without such a row
  (for example in the **Function** scope) it opens Hex, as Go does. It never
  sends a graph, pseudocode or Decode request for that address. A function
  opened explicitly outside the inventory, such as a call target, is still
  reopened as a function.
- Bytes whose page could not be read keep `??` in a muted error tone; bytes
  still loading keep the usual muted `??`.
- Limitations: Go and the address bar do not expand gaps; Back returns to a
  row by its address only, so at a section's first byte it lands on the row
  after the section header; and expansions, loaded bytes and failed pages
  are session-only and are not saved in projects.
