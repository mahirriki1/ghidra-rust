- Saving a project now preserves analysis for recent retained functions alongside
  the displayed function, so revisiting them after reopening can reuse listing,
  graph, pseudocode, and exact semantic mappings without reanalysis.
- Additional results are bounded to 128 retained functions and 16 MiB of saved
  data. Reopening also applies presentation and session memory budgets; evicted
  or oversized components are recomputed on demand.
- Restored components retain Saved analysis provenance until refreshed. Refresh,
  signature changes, and name/context changes retain existing invalidation rules.
- Projects now use schema version 5. Versions 1–4 remain readable; older builds
  cannot open version 5 projects. Exact saved listing positions remain supported.
- This adds cross-session persistence; automatic saving, cloud synchronization,
  and a remote analysis API are not included.
