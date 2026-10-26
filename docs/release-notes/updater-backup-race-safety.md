- Windows recovery cleanup uses a directory handle prepared before publication,
  verifies staged and published file membership, and enumerates and opens children
  relative to the retained directory. Parent-directory substitutions cannot
  redirect cleanup to unrelated files; deletion uses the same checked handle.
- Linux retains all previous executables. Automatic pruning is disabled because
  pathname deletion cannot preserve the protected-file guarantee during concurrent
  replacement. Remove obsolete Linux copies manually after verifying an update.
- Cleanup remains best effort. Unsupported containment, identities or protected
  filename comparisons retain extra Windows copies; non-ASCII protected basenames
  currently disable pruning for that update. These cleanup safeguards do not
  change the existing path-based installation and rollback limitations.
