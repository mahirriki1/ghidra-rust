- Failed Windows updates now schedule a separate cleanup process before the
  helper exits, covering cancellation, blocked executable replacement, and failed
  relaunch. It waits for the helper to close, then deletes only owned artifacts
  using duplicated, identity-checked handles and removes the folder only if empty.
- The failure janitor uses Windows’ built-in PowerShell without evaluating input
  paths or commands. If it cannot start, the failure message identifies the
  temporary folder. Locked files, restricted PowerShell, interruptions, or leaving
  the helper’s error dialog open for more than five minutes can still leave files.
- Native Windows process regressions exercise the production helper and cleanup
  entry points, including preservation of substituted protected-file aliases.
- Windows helpers close their own installed-file identity handle after the final
  destination check, allowing replacement of the previously loaded executable.
  All analyzed-input and staged-artifact protections remain pinned.
