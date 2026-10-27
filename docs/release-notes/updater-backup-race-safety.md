- Windows recovery cleanup uses a directory handle prepared before publication,
  verifies staged and published file membership, and enumerates and opens children
  relative to the retained directory. Parent-directory substitutions cannot
  redirect cleanup to unrelated files; deletion uses the same checked handle.
- Windows cleanup opens enumerated backup names with exact case, so a removed
  entry cannot redirect deletion to a differently cased, ineligible sibling in
  a case-sensitive installation directory.
- Linux retains all previous executables. Automatic pruning is disabled because
  pathname deletion cannot preserve the protected-file guarantee during concurrent
  replacement. Remove obsolete Linux copies manually after verifying an update.
- Cleanup remains best effort. Unsupported containment, identities or protected
  filename comparisons retain extra Windows copies; non-ASCII protected basenames
  currently disable pruning for that update. These cleanup safeguards do not
  change the existing path-based installation and rollback limitations.
