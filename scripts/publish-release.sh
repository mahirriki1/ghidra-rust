#!/usr/bin/env bash
# Publish only the complete, verified files from this workflow's native jobs.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
: "${RELEASE_TAG:?}" "${RELEASE_VERSION:?}" "${RELEASE_SHA:?}" "${SOURCE_SHA:?}"
: "${GH_REPO:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_SERVER_URL:?}"

release_json="$RUNNER_TEMP/release.json"
notes="$RUNNER_TEMP/release-notes.md"
# 0.x versions are unstable and publish as GitHub pre-releases, which are never
# marked latest. Bumping the manifest to 1.0.0 publishes the first stable release.
prerelease=false
if [[ "$RELEASE_VERSION" == 0.* ]]; then prerelease=true; fi
# Distinguish an absent release from authentication/network/API failures. Reruns
# resume a draft; an already published release keeps its original assets.
gh api --paginate "repos/$GH_REPO/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"$RELEASE_TAG\")" > "$release_json"
if [[ -s "$release_json" ]] && [[ $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["draft"])' "$release_json") == False ]]; then
    echo "$RELEASE_TAG is already published."
    exit 0
fi

# Only published releases can form the baseline; reserved/failed tags cannot.
gh api --paginate "repos/$GH_REPO/releases?per_page=100" \
    --jq '.[] | select(.draft == false) | .tag_name' > "$RUNNER_TEMP/published-tags.txt"
python3 scripts/release-notes.py --source "$SOURCE_SHA" --snapshot "$RELEASE_SHA" \
    --tag "$RELEASE_TAG" --published-tags "$RUNNER_TEMP/published-tags.txt" \
    --repo "$GH_REPO" --server-url "$GITHUB_SERVER_URL" --run-id "$GITHUB_RUN_ID" \
    --output "$notes"

if [[ ! -s "$release_json" ]]; then
    gh release create "$RELEASE_TAG" --verify-tag --target "$RELEASE_SHA" \
        --title "Ghidra Rust $RELEASE_VERSION (alpha)" --draft --prerelease="$prerelease" \
        --notes-file "$notes"
else
    # A resumed draft may predate this generator, a newly published baseline, or
    # the pre-release policy.
    gh release edit "$RELEASE_TAG" --notes-file "$notes" --prerelease="$prerelease"
fi
# Keep failed uploads in a draft. A rerun can safely replace a partial upload.
gh release upload "$RELEASE_TAG" target/release-assets/* --clobber
gh release view "$RELEASE_TAG" --json assets --jq '.assets[].name' > "$RUNNER_TEMP/release-assets.txt"
python3 - "$RUNNER_TEMP/release-assets.txt" <<'PY'
from pathlib import Path
import sys
expected = {p.name for p in Path("target/release-assets").iterdir()}
actual = set(Path(sys.argv[1]).read_text().splitlines())
if actual != expected:
    sys.exit("Uploaded release assets do not match the complete verified package set")
PY

# A slower old build must not replace a newer main update as the latest release.
main_sha=$(gh api "repos/$GH_REPO/git/ref/heads/main" --jq '.object.sha')
latest=false
if [[ "$prerelease" == false && "$main_sha" == "$SOURCE_SHA" ]]; then latest=true; fi
gh release edit "$RELEASE_TAG" --draft=false --prerelease="$prerelease" --latest="$latest" --verify-tag
release_url=$(gh release view "$RELEASE_TAG" --json url --jq .url)
echo "Published $release_url"
echo "Published [$RELEASE_TAG]($release_url) with both native executables, archives, and checksums." >> "$GITHUB_STEP_SUMMARY"
