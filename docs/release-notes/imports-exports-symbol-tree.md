- Show **Imports (n)** and **Exports (n)** in the Symbol Tree. Imports are grouped
  by declaring library, Mach-O lookup scope or **Unknown library**; equal names in
  different libraries stay separate rows. Headers show only **Loading**,
  **Partial** (hover lists coverage gaps) or **Unavailable**.
- Name each row by the analyst label at its exact address, then the worker's
  demangled name, then the raw declaration, then `ordinal N`, without reordering
  the tree. Hover shows the raw name, library, version, ordinal and delay/weak
  facts, stub and slot, or an export's destination or forwarding target. The
  function filter also filters imports and exports.
- Click to select an import or export and double-click to open it, with
  Back/Forward history. Imports open their verified stub as code, or else their
  slot in Hex at that exact address with the pointer-width slot selected. Code
  and resolver exports open as code; data exports open in Hex and never become
  functions. Forwarded and unresolved entries are selectable but do not navigate.
  Further verified stubs and slots appear as child rows and in the row's context
  menu.
- Press **X** on an import or export row to see references to its exact address,
  or choose among an import's stubs and slots. Entries without an address have no
  reference action, and no call from an import slot to its external symbol is
  invented.
- Read imports and exports through bounded, paged worker metadata that is bound
  to the analyzed image and table digest. Pages load only while the worker is
  otherwise idle, are dropped after another binary opens or analysis is
  cancelled, and are grouped off the GUI thread within the shared session
  memory budget.
- Preserve PE aliases, ordinal-only and data exports, forwarders, and conventional
  RVA-form delay imports without adding delay imports to analysis registration.
  ELF ownership uses symbol-version requirements; unowned declarations remain
  unknown. Mach-O uses nlist declarations, library ordinals and indirect symbols.
- Imports, exports, group expansion and the filter are not saved in projects;
  reopening rebuilds them from the verified binary with unchanged project and
  annotation formats. dyld binding opcodes, chained fixups and export tries remain
  unsupported and mark the tree **Partial**.
