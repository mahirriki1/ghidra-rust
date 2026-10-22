- Show cross-references from context: right-click an instruction in the Listing
  or Function Graph, a decompiler expression, the Listing or Decompiler function
  header, or a Functions entry and choose **Xrefs to…**, or press **X**. Targets
  come only from decoded call sites whose targets are file-backed executable
  code, confirmed call/data evidence at the exact instruction, or a decompiler
  call token's engine target.
- Offer every distinct target as an explicit choice when one selection has
  several, such as an instruction that reads and writes different addresses or a
  decompiler expression mapped to several instructions. No target is picked
  silently or inferred from matching names, text, or nearby addresses.
- Inspect references to an exact address in the References tab independently of
  the displayed function, then return with **Current function**. Enter an exact
  hex address and press **Show xrefs** to inspect any address.
- Filter call references by incoming or outgoing direction and data accesses by
  reads or writes, and filter rows by known function name or hexadecimal address
  (with or without `0x`). Names only label and filter rows; duplicate names never
  merge distinct targets. Follow a counterpart's **Xrefs** to walk callers.
- Record the exact call or access instruction, and its owning function, in
  Back/Forward history when opening a reference source. Sources inside the
  displayed function are selected without reloading it.
- Right-click a string for confirmed data accesses that begin exactly at its
  first byte. Accesses to later bytes, address-only uses, and loaded pointers to
  the string are not recorded by the current analysis.
- Keep saved-analysis provenance, partial-coverage warnings, unresolved counts,
  and the note that an empty result does not establish absence visible for
  contextual results. Captured menu targets and choices expire when the binary,
  selection, annotations, or reference evidence change.
- Byte-pattern search, caller trees, and bookmarks remain future work.
