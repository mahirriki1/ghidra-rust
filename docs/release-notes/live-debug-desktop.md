- Debug a directly opened x86-64 ELF executable from the new **Debug** menu
  on Linux x86-64. F5 starts and runs to the first breakpoint, or continues;
  Shift+F5 stops, F6 pauses, and F11 steps one instruction. **Start paused**
  stops before the first target instruction. Toolbar buttons repeat these
  commands.
- The first start of each opened binary asks you to confirm running it. The
  confirmation ends when you open, reopen, or close a binary or open a
  project.
- Press F9, or right-click an instruction, to toggle a breakpoint on an exact
  decoded instruction in the Function or Program listing. A gutter shows set,
  pending, and failed breakpoints, and the stopped PC. Changes made while the
  target runs apply at the next stop. Breakpoints are not saved in projects.
- Each stop selects the PC in the Listing and highlights the engine-mapped
  pseudocode, without adding Back/Forward history. Stops in the loader or
  libc leave the selection in place. The status bar shows the stop, signal,
  or exit code; click it or choose **Debug → Go to PC** to return to the PC.
- Opening or closing a binary, opening a project, and quitting end a live
  session without asking. Debugging is unavailable for binaries embedded in
  projects and on other platforms, which show no Debug menu.
