# Writing release notes

For each pull request or direct change to main, add a uniquely named Markdown
file here, such as `hex-memory-map.md`. Write one `- ` bullet per user-visible
feature, fix, workflow change, or relevant limitation. Describe the resulting
behavior, rather than only repeating the PR title. Indent wrapped lines by two
spaces. Do not include headings, build claims, or agent/review transcripts.

For example:

```markdown
- Browse loaded sections in a Hex / Memory Map tab with 4 KiB pages.
- Select hex or ASCII bytes and send that exact range and address to Decode.
- Distinguish file-backed bytes from zero-filled memory; page state is transient.
```

Keep each entry in the repository after publication. Use a new file for later
changes instead of editing an old entry. The publisher collects added entries
between the previous published version and the release source. An amended entry
also appears again so corrections are visible. Failed/reserved tags and draft
releases do not establish a baseline. The first release includes every entry.

The release starts with these detailed bullets, followed by expandable complete
commit history and a comparison link. If a range has no entries, its entire
commit list supplies the bullets. History has no 100-commit limit and includes
direct commits and every merged branch, rather than just the latest PR.

Run the release regressions locally without building the desktop:

```sh
python3 -m unittest discover -s scripts -p 'test_release.py'
```

To preview notes locally, supply the published version tags (one per line) in a
file, and use full local commit IDs for the source and snapshot:

```sh
python3 scripts/release-notes.py \
  --source SOURCE_SHA --snapshot SNAPSHOT_SHA --tag vX.Y.Z \
  --published-tags /tmp/published-tags.txt \
  --repo mahirriki1/ghidra-rust --server-url https://github.com \
  --run-id RUN_ID --output /tmp/release-notes.md
```

This command only reads local history and writes the preview file. It does not
publish a release or call GitHub. Ensure the checkout has full history and the
published tags before previewing.
