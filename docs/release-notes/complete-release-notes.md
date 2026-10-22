- Lead release descriptions with detailed bullets for the features and fixes in
  that version, collected from checked-in release-note entries across the full
  range since the previous published release.
- Retain the complete linked commit history, including direct commits and merged
  branches, without the previous 100-commit cutoff or duplicate generated PR list.
- Refresh release notes when resuming a draft, and exclude failed tags and
  releases from unrelated or newer source history when choosing the baseline.
- Correct build information to state that hosted CI builds, lints, and packages;
  tests run locally before merging.
