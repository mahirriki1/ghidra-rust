- Function Graph blocks show every instruction row returned for the function
  instead of an eight-row preview with a "more rows" footer. Block heights,
  rank spacing and edge connections follow the full rows, including comments.
- Graph painting skips off-screen blocks, rows and edges. Zoomed out, blocks
  draw compact row marks, binned to the display's pixel density, instead of
  unreadable instruction text; the selected row stays marked.
- Clicking any row, including deep comment rows of a tall block, selects its
  exact instruction. Revealing an instruction from the Listing cursor,
  pseudocode or a navigation moves the camera only when that row is not
  already visible, and Entry returns to the entry block's header near the top
  instead of centering a tall block.
- Graph indexes and layout, including comment and call-name rows, are prepared
  off the GUI thread. Results for a previous function, binary, selection,
  annotation revision or project are discarded; saved projects keep their
  Saved provenance and adopt graph, pseudocode and mappings together.
- While edited comments or names are laid out again, the graph briefly shows
  rows without comments rather than outdated text, and keeps the camera.
- The graph remains limited to the analyzer's bounded results of 2,048
  instructions and 128 blocks per function. This change does not recover more
  instructions or control flow.
- Graph presentation respects the session memory budget; annotation layout
  falls back to base rows when its temporary allocation cannot fit.
