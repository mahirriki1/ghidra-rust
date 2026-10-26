- Successful in-app updates retain the just-created previous executable and prune
  older recovery copies only after the verified replacement has been published.
  Failed installations and rollbacks leave existing recovery copies alone.
- Cleanup only considers regular files in the installation directory with the
  exact recovery name: `ghidra-rust-previous-VERSION-XXXXXX`, with a valid semantic
  version, six ASCII letters or digits, and `.exe` on Windows. Symlinks, Windows
  reparse points, protected inputs, and hard-link aliases of protected or retained
  files are kept; dependency notices and similarly named files are untouched.
- Cleanup errors never fail an update. Running or locked Windows copies are
  skipped; the scan and removal limits can also leave extra copies for later
  updates or manual removal.
- Windows updates validate staged files correctly while an unrelated input
  remains protected, including protection against its hard-link aliases.
