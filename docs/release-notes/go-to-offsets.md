- **G** and the toolbar address field now resolve the same queries: a
  hexadecimal address, then an exact label, function name, raw symbol or
  display name. The toolbar previously accepted only hexadecimal addresses.
- Either one accepts one hexadecimal offset after the last `+` or `-`, such as
  `main+0x20` or `0x401000-0x10`. The offset is an optional `0x` followed by
  1–16 hex digits. A whole-query name match always wins, so names containing
  `+` or `-` (`operator+`, `operator->`, `a-b`) still resolve as names, and
  `operator++0x10` means `operator+` plus `0x10`.
- Nested arithmetic, signed or malformed offsets, results that overflow or
  underflow, and results outside mapped memory are rejected. The check
  applies to the final address, so a base outside mapped memory is fine when
  the result is mapped. The toolbar now also rejects unmapped addresses.
- Go opens code only at a known function entry or at an instruction the
  current graph, pseudocode or history observed, inside that function. Any
  other mapped address, including executable bytes that are not a known entry
  (for example, a function not yet discovered or beyond a truncated
  inventory), opens in Hex instead of as a guessed function. Address zero
  opens in Hex when it is mapped.
- Going to code keeps the Function Graph tab when it is open and switches
  other tabs to Listing. Every successful Go is recorded for Back / Forward.
- A rejected query leaves the selection, history and tab unchanged. The
  dialog shows the error inline; the toolbar keeps the typed text and reports
  the error in the status bar.
