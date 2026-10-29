- Add **Search → Memory…** (`S`) for hex bytes with `??` whole-byte wildcards,
  ASCII or UTF-16LE literals of up to 256 encoded bytes, with optional ASCII
  case folding, over the mapped file-backed bytes of every section.
- Add **Search → Program text…** (`Ctrl+F`, `Cmd+F` on macOS) for a literal in
  loaded names (inventory, raw and display), imports, exports, labels, comments
  and string previews, with a toggle per source. It never fetches more names or
  demangles, and listing/pseudocode text is not searched.
- Show results in a central **Search** tab with Address/Section/Match or
  Address/Kind/Text columns and a compact Searching, Complete, Partial, Canceled,
  Stale or Unavailable state with its count.
- Open a match as code only at a known function entry or an instruction already
  observed in a graph, decompiler mapping or history; any other match opens in
  Hex at its exact bytes, even inside code. Strings open in Hex; imports and
  exports open like their Functions-dock rows. Back / Forward records each one.
- Keep the whole selection when a Hex destination of up to 4 KiB crosses a page,
  and let **Prev** return to the section's first page from such a page.
- Run memory pages alternately with symbol-name, import/export and discovery
  work; navigation waits for the current bounded page, and **Cancel** keeps the
  matches found so far.
- Report Partial when result, page or text limits are reached or a selected
  source is unavailable or truncated; Complete covers only the loaded sources.
- Mark program-text results Stale when searched names, tables, strings or
  annotations change, rather than refreshing them automatically.
- Search results are transient: they are not saved in projects and are cleared
  when the binary or project changes.
