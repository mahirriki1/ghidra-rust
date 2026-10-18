#!/usr/bin/env bash
# Publish only the complete, verified files from this workflow's native jobs.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
: "${RELEASE_TAG:?}" "${RELEASE_VERSION:?}" "${RELEASE_SHA:?}" "${SOURCE_SHA:?}"
: "${GH_REPO:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_SERVER_URL:?}"

release_json="$RUNNER_TEMP/release.json"
notes="$RUNNER_TEMP/release-notes.md"
# Distinguish an absent release from authentication/network/API failures. Reruns
# resume a draft; an already published release keeps its original assets.
gh api --paginate "repos/$GH_REPO/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"$RELEASE_TAG\")" > "$release_json"
if [[ -s "$release_json" ]] && [[ $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["draft"])' "$release_json") == False ]]; then
    echo "$RELEASE_TAG is already published."
    exit 0
fi

# Use a published lower version, excluding reserved/failed tags and newer builds
# that may have finished first. Also include direct commits in the update notes.
gh api --paginate "repos/$GH_REPO/releases?per_page=100" \
    --jq '.[] | select(.draft == false) | .tag_name' > "$RUNNER_TEMP/published-tags.txt"
previous=$(python3 - "$RUNNER_TEMP/published-tags.txt" "$RELEASE_VERSION" <<'PY'
from pathlib import Path
import re
import sys
current = tuple(map(int, sys.argv[2].split(".")))
versions = []
for tag in Path(sys.argv[1]).read_text().splitlines():
    if re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        version = tuple(map(int, tag[1:].split(".")))
        if version < current:
            versions.append((version, tag))
print(max(versions)[1] if versions else "")
PY
)

cat > "$notes" <<EOF
Early alpha release from main commit $SOURCE_SHA. Release snapshot: $RELEASE_SHA.

Downloads include native Windows x64 and Linux x64 executables, complete ZIP/tar.gz bundles with license notices, and SHA-256 checksums. No Rust, Java, or Python runtime is required.

Windows needs a working OpenGL driver and trusted local inputs; worker resource controls do not isolate filesystem/network access. Linux is built on Ubuntu 24.04 and needs compatible glibc/system libraries, desktop OpenGL, bubblewrap, and unprivileged user namespaces. For the standalone Linux download, grant execute permission with chmod +x. Builds are unsigned.

[Native build and test results]($GITHUB_SERVER_URL/$GH_REPO/actions/runs/$GITHUB_RUN_ID). Both platforms passed formatting, unit/headless UI tests, strict Clippy, optimized builds, and real worker/project integration checks. Hosted CI does not validate an interactive OpenGL desktop.

EOF

range="$SOURCE_SHA"
notes_args=()
if [[ -n "$previous" ]]; then
    range="$previous..$SOURCE_SHA"
    notes_args+=(--notes-start-tag "$previous")
fi
printf '\nChanges in this update (up to 100 commits):\n\n' >> "$notes"
git log "$range" --no-merges --max-count=100 --format='- %s (%h)' >> "$notes"

if [[ ! -s "$release_json" ]]; then
    gh release create "$RELEASE_TAG" --verify-tag --target "$RELEASE_SHA" \
        --title "Ghidra Rust $RELEASE_VERSION (alpha)" --draft \
        --generate-notes --notes-file "$notes" "${notes_args[@]}"
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
if [[ "$main_sha" == "$SOURCE_SHA" ]]; then latest=true; fi
gh release edit "$RELEASE_TAG" --draft=false --latest="$latest" --verify-tag
release_url=$(gh release view "$RELEASE_TAG" --json url --jq .url)
echo "Published $release_url"
echo "Published [$RELEASE_TAG]($release_url) with both native executables, archives, and checksums." >> "$GITHUB_STEP_SUMMARY"
