- The function graph shows a compact overview in its lower-right corner: one
  silhouette per returned block and an outline of the visible area, which
  follows every pan and zoom. It shows no edges, text or selection.
- Clicking the overview centers the graph on that point at the current zoom.
  Clicks in its margins center on the nearest edge of the graph. The click
  never selects an instruction, follows a call, adds Back / Forward history
  or changes annotations.
- Drags, the mouse wheel, Ctrl+wheel, right-clicks and double-clicks on the
  overview do not reach the graph beneath it. A graph pan that starts outside
  the overview continues across it, and an open graph context menu stays
  open. An open dialog blocks overview clicks.
- Revealing an instruction row that the overview covers centers that row
  vertically, so it is no longer hidden. **Fit** still fits the whole graph
  to the full pane.
- The overview is hidden in graph panes smaller than about 320 × 240 points,
  for graphs without decoded blocks, and until a function's first annotated
  layout is ready. The camera is not saved in projects.
