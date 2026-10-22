- Edit a known function's return type and ordered, named parameters through the
  Decompiler's Signature control, function context menu, or annotation editor.
  Supported types include signed and unsigned 8/16/32/64-bit integers, void
  returns, and pointers with up to four pointer levels under the image's ABI.
- Apply signatures through the analysis engine before decompiling resolved
  direct callers, so corrected types and parameter lists affect recovered code.
  Unsupported inferred types require an explicit supported choice.
- Apply, remove, and undo signature overrides by verifying a fresh worker and
  replaying the complete signature state. Canceled or failed edits retain the
  committed state and attempt one recovery; incompatible saved overrides remain
  visible as unapplied and can be restored through undo.
- Save signatures in project v4 and JSON annotation v3 files while continuing to
  read earlier formats. Older analysis caches are refreshed while annotations and
  embedded binaries are retained; older application releases reject new formats.
- Bind recovered local names and analysis caches to the complete signature
  state. Signature-owned parameter names are edited through the signature editor;
  local overrides whose verified identities change remain saved and unapplied.
- Retain instruction selection, semantic code links, and navigation history when
  regenerating analysis. Signature changes invalidate graph, decompiler, and
  discovery/reference results while retaining byte-based string and crypto scans.
- Limit signature editing to fixed-arity prototypes: at most 32 parameters per
  function, 64 edited functions, 256 parameters per session, and 48 KiB of signature
  data. Alternate calling conventions, floating-point and aggregate types,
  variadics, indirect-call signatures, and imported-function propagation remain
  outside this milestone.
