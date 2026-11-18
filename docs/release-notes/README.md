# Writing release notes

For each PR or direct change to main, add a uniquely named Markdown file in
this directory. Use one `- ` bullet per user-visible change or limitation.
Indent wrapped lines by two spaces. Use no headings or build claims.

```markdown
- Browse loaded sections in Hex / Memory Map in 4 KiB pages.
- Send the exact selected byte range to Decode.
```

Keep published files and add a new file for later changes. The publisher
collects added or amended entries since the previous published version.
Its notes also include the complete commit history. When the range has no
entries, the commit list supplies the change bullets.

Run the release-note tests locally:

```sh
python3 -m unittest discover -s scripts -p 'test_release.py'
```

To preview notes, use full local history, full commit IDs, and a file with
one published version tag per line.

```sh
python3 scripts/release-notes.py \
  --source SOURCE_SHA --snapshot SNAPSHOT_SHA --tag vX.Y.Z \
  --published-tags /tmp/published-tags.txt \
  --repo mahirriki1/ghidra-rust --server-url https://github.com \
  --run-id RUN_ID --output /tmp/release-notes.md
```

The preview reads local history and writes a Markdown file.
