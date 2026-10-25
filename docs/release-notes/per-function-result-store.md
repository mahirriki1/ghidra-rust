- Revisit analyzed functions and use Back/Forward with immediate reuse of compatible
  graph/listing and pseudocode results, without a worker request. Exact instruction
  selection and the existing Saved analysis provenance survive synchronous adoption.
- Retain immutable text, mappings, semantic tokens, inferred prototypes, local warnings,
  listing indexes, highlighting and base graph geometry in a bounded 64 MiB session
  store. Inactive analysis is evicted; annotations are retained. Save-pinned snapshots
  remain charged, and current uncached/preparation allocations are reported separately.
- Refresh explicitly recomputes results. Local edits invalidate only that function's
  pseudocode; function names, inventory and committed signatures invalidate their
  dependent results. Comment-only annotation imports preserve analysis.
- Share one committed discovery publication between reference indexes and project
  saves, preserving pending, partial, failed and unexamined coverage distinctions.
  Failed signature staging retains committed reference evidence.
- Keep projects at version 4: only the displayed function's graph and pseudocode are
  saved. Analysis arriving or invalidating during a save remains unsaved afterward.
- Use the existing warm worker for cache misses. Stored pseudocode reflects engine
  knowledge when computed; Refresh can differ after other functions teach shared
  global types. This is not a fresh-context cache or whole-program persistence.
- Add separate cache/adoption, miss, allocation and native capture measurement hooks;
  diagnostic numbers remain in traces and measurement reports, outside the desktop UI.
