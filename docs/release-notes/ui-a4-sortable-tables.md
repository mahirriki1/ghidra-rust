- Sort the Functions, Imports, Exports, Strings, Calls and Data references
  tables by clicking a column heading: the first click sorts ascending, the
  second descending, and the third restores the original order. The heading
  arrow shows the order currently displayed.
- Addresses, sizes, call sites and ordinals sort numerically and names and
  strings case-insensitively. Unknown or empty values, such as a forwarded
  export's address or a taken address's size, stay last in both directions,
  and equal values keep their original order. Text comparisons use the first
  1 KiB of each value.
- Sorting keeps the active filter and the selected function, string, import or
  export. After a sort change the selection scrolls into view once; later
  filtering does not move the view. Tables over 4,096 rows, or with long text
  values, sort on a background thread and keep their previous order until the
  new one is ready. At most two sorts run at once.
- The Calls direction column is now headed **Dir** and sorts From before To.
  Its Function column sorts by the counterpart's shown name, unnamed last.
  Data reference kinds sort Read, Write, then Address, each direct before
  propagated (`*`).
- When a narrow Imports or Exports list hides its Library or Ordinal column,
  the **⋯** button in the heading still sorts by it.
- Right-click a row in any of these tables and choose **Copy row** to copy its
  visible columns as tab-separated text, with full names rather than clipped
  cells. Tabs, line breaks and backslashes inside a value are escaped, and a
  copied row is limited to 16 KiB.
- Sort choices are not saved. They reset when a binary closes or a project
  is reopened. Search results and FindCrypt matches are not sortable.
