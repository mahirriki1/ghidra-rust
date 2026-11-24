- Show Registers, Stack and Memory tabs during live debugging on Linux
  x86-64. They appear with the first session for an opened binary, stay after
  the target exits, and leave when the binary changes.
- Tint registers that changed since the previous stop of the same session,
  and name a register's function and offset only when the debugger maps its
  value into the executable. Right-click a register to copy it, show it in
  Memory, or go to its mapped address.
- Name stack frames in the executable with the app's own function names. A
  caller is named by its decoded call instruction, so a call that ends a
  function is not attributed to the next one. Double-click a mapped frame,
  or press Enter on it, to open it with history; a frame in a function the
  app has not decoded opens as data, and frames outside the executable do
  not open.
- Read live memory in 1 KiB hex and ASCII pages, starting at `rsp`, with
  rsp, rip, address and paging controls. Pages re-read at each stop, replies
  for older stops are dropped, and unreadable ranges say so.
- Keep the active debug tab in front when a stop moves the Listing to the PC.
