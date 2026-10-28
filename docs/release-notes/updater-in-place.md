- In-app updates replace the executable at its existing name and location without
  retaining another executable in the installation folder. Linux uses atomic
  replacement; a temporary Windows helper waits for the app to exit first.
- Review the verified license and dependency notices in the updater and explicitly
  accept them before Install and restart becomes available. Cancelling preserves
  the installed version and the normal unsaved-work prompt remains in effect.
- Native release build scripts embed dependency notices for offline viewing in
  Help → About, replacing the updater’s versioned notice sidecars. Windows builds
  require Python 3.11+ for notice collection; running the app does not.
- Windows removes temporary helper artifacts after restart using checked file
  identities. Cleanup failures may leave files in the system temporary folder;
  older recovery executables and notice files are left for manual removal. Updates
  initiated by older installed versions still follow their old updater workflow.
- Reverting a completed update requires downloading an older release. A failed
  installation leaves the installed executable unchanged; a failed restart can
  be recovered by launching the app manually at its usual path.
