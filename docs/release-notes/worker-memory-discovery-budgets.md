- Release cleared instruction and varnode backing storage after engine flow
  recovery and decompilation, while retaining function symbols, scopes,
  signatures, locked locals and address-based overrides. Functions with retained
  jump-table overrides, callbacks or debug modification state conservatively
  retain their banks to avoid reusing instruction identities still referenced
  by that state.
- Treat parent function-start pattern work exhaustion as partial discovery
  rather than invalid worker data. Discard the entire pending payload, retain
  previously committed evidence and request fresh inventory synchronization;
  malformed bindings and invalid inventory bases remain errors. Work allowances
  and charging rules are unchanged.
- Bound automatic worker recovery across an entire discovery run, including
  successfully replayed batches, so repeated coverage failures cannot continually
  replenish the recovery allowance. Coverage identities still require the
  worker's corresponding instruction exclusion ranges.
- Continuously drain worker diagnostics with bounded storage and report observed
  child exit status and a sanitized allocator-failure hint on spontaneous output
  closure. Raw engine diagnostics are never displayed; unavailable exit status
  remains unknown. Request deadlines and platform resource limits are unchanged.
- Clear printer expression stacks before reusing instruction banks, including
  converted printing panics and errors, and preserve the original emitter and
  action. Account partial-discovery snapshots and indexes through the session
  result store, deferring publication while a save pins prior evidence. Schedule
  exit-classification polling while the desktop is idle and deliver EOF failure
  only once.
