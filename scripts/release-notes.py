#!/usr/bin/env python3
"""Render complete release notes from committed bullet entries and Git history."""

import argparse
from pathlib import Path
import re
import subprocess
import sys


ENTRY_DIRECTORY = "docs/release-notes"
VERSION_TAG = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
AUTOMATIC_TAG = re.compile(r"Automatic release from main ([0-9a-f]{40}); workflow run [0-9]+")


def git(*args):
    return subprocess.check_output(["git", *args], text=True, encoding="utf-8").strip()


def release_source(tag):
    """Automatic version snapshots are siblings of main, not main ancestors."""
    ref = f"refs/tags/{tag}"
    subject = git("for-each-ref", "--format=%(contents:subject)", ref)
    if marker := AUTOMATIC_TAG.fullmatch(subject):
        parent = git("rev-parse", f"{ref}^{{commit}}^")
        if parent != marker[1]:
            raise ValueError(f"Automatic tag {tag} does not match its recorded source")
        return parent
    return git("rev-parse", f"{ref}^{{commit}}")


def previous_release(published_tags, tag, source):
    current = VERSION_TAG.fullmatch(tag)
    if not current:
        raise ValueError("Expected a vX.Y.Z release tag")
    version = tuple(map(int, current.groups()))
    candidates = []
    for candidate in set(published_tags):
        match = VERSION_TAG.fullmatch(candidate)
        if match and tuple(map(int, match.groups())) < version:
            candidates.append((tuple(map(int, match.groups())), candidate))
    for _, candidate in sorted(candidates, reverse=True):
        result = subprocess.run(["git", "merge-base", "--is-ancestor",
                                 release_source(candidate), source], check=False)
        if result.returncode == 0:
            return candidate
        if result.returncode != 1:
            raise ValueError(f"Cannot check source ancestry for {candidate}")
    return None


def entries(source, previous):
    if previous:
        names = git("diff", "--name-only", "--diff-filter=AM", previous, source,
                    "--", ENTRY_DIRECTORY).splitlines()
    else:
        names = git("ls-tree", "-r", "--name-only", source, "--", ENTRY_DIRECTORY).splitlines()
    result = []
    for name in sorted(names):
        if not name.endswith(".md") or name == f"{ENTRY_DIRECTORY}/README.md":
            continue
        content = git("show", f"{source}:{name}")
        if not content or not content.startswith("- ") or any(
            line and not line.startswith(("- ", "  ")) for line in content.splitlines()
        ):
            raise ValueError(f"{name} must contain Markdown bullets and indented continuations")
        result.append(content)
    return result


def escape_markdown(text):
    return re.sub(r"([\\`*_{}\[\]<>()#|!])", r"\\\1", text)


def render(source, snapshot, tag, published_tags, repo, server_url, run_id):
    source = git("rev-parse", "--verify", f"{source}^{{commit}}")
    snapshot = git("rev-parse", "--verify", f"{snapshot}^{{commit}}")
    previous = previous_release(published_tags, tag, source)
    revision_range = f"{previous}..{source}" if previous else source
    # Do not cap the history or restrict it to the first parent: stacked and
    # multi-commit PRs, direct commits, and merge resolutions all belong here.
    commits = git("log", "--reverse", "--topo-order", "--format=%H%x00%s", revision_range)
    base = f"{server_url.rstrip('/')}/{repo}"
    bullets = []
    for line in commits.splitlines():
        sha, subject = line.split("\0", 1)
        bullets.append(f"- {escape_markdown(subject)} ([{sha[:7]}]({base}/commit/{sha}))")
    changes = entries(source, previous)
    lines = [f"## What's changed in {tag}", ""]
    if changes:
        noun = "commit" if len(bullets) == 1 else "commits"
        lines.extend(["\n".join(changes), "", "<details>",
                      f"<summary>All {len(bullets)} {noun} in this release</summary>", "",
                      "\n".join(bullets) or "No source changes since the previous release.",
                      "", "</details>"])
    else:
        lines.append("\n".join(bullets) or "No source changes since the previous release.")
    if previous:
        lines.extend(["", f"[Full changelog: {previous} → {tag}]({base}/compare/{previous}...{tag})"])
    else:
        lines.extend(["", f"[Full history]({base}/commits/{source})"])
    lines.extend([
        "", "## Downloads", "",
        "- **Windows x64:** standalone `.exe` or complete `.zip` bundle.",
        "- **Linux x64:** standalone executable or complete `.tar.gz` bundle. "
        "Run `chmod +x` on the standalone download.",
        "- Bundles include license notices. Every download has a SHA-256 checksum; builds are unsigned.",
        "", "No Rust, Java, or Python runtime is required. Windows needs OpenGL and trusted local inputs; "
        "worker resource controls do not isolate filesystem/network access. Linux needs Ubuntu 24.04-compatible "
        "glibc/system libraries, desktop OpenGL, bubblewrap, and unprivileged user namespaces.",
        "", "## Build information", "",
        f"[Native build results]({base}/actions/runs/{run_id}): formatting, strict Clippy, optimized "
        "Linux/Windows builds, packaging, and checksum verification. Hosted CI does not run tests "
        "or validate an interactive desktop; tests must pass locally before merging.",
        "", f"Source: [{source[:7]}]({base}/commit/{source}). "
        f"Release snapshot: [{snapshot[:7]}]({base}/commit/{snapshot}).", "",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("source", "snapshot", "tag", "published-tags", "repo", "server-url", "run-id", "output"):
        parser.add_argument(f"--{argument}", required=True)
    args = parser.parse_args()
    content = render(args.source, args.snapshot, args.tag,
                     Path(args.published_tags).read_text(encoding="utf-8").splitlines(),
                     args.repo, args.server_url, args.run_id)
    Path(args.output).write_text(content, encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Release notes failed: {error}")
