- Correct discovery summaries that continued to show “running” after final
  result adoption, retaining final counts and partial-coverage warnings.
- Replace persistent graph warning and legend rows with compact toolbar controls,
  retaining function-specific recovery warnings and saved-result provenance.
- Keep saved tree provenance visible in narrow panes, with compact access to
  both tree views when full tab names do not fit.
- Keep counts and saved-analysis provenance visible in narrow Functions,
  Decompiler, and central view headers: provenance shortens to “Saved” and a
  title that still does not fit ends in an ellipsis instead of being cut off.
  A narrow Decompiler header keeps Copy, Refresh, and the warning count, leaving
  Signature and Auto to the context and View menus.
- Shorten the saved-project status to “Project opened · saved analysis”; the
  saved-result tooltips still say how to recompute each result.
- Move feature explanations into concise tooltips and warning menus while keeping
  partial coverage, unsupported results, and decoding uncertainty visible.
- Stabilize Functions and Strings scrolling at fractional Linux display scales:
  use vertical-only lists where appropriate and pixel-snapped widths for tables
  that need horizontal scrolling, ignoring sub-pixel overflow.
- Refresh the native graph screenshot to show the updated Carbon interface,
  compact graph toolbar, and genuine linked instruction/pseudocode selection.
