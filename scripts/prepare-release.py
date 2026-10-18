#!/usr/bin/env python3
"""Reserve an automatic patch tag in a disposable CI checkout (Python 3.11+)."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")


def git(*args, check=True):
    return subprocess.run(["git", *args], check=check, text=True, stdout=subprocess.PIPE)


def read_version():
    package = tomllib.loads(Path("Cargo.toml").read_text())["package"]
    if package["name"] != "ghidra-rust" or not VERSION.fullmatch(package["version"]):
        raise ValueError("Automatic releases require a ghidra-rust X.Y.Z version")
    lock = tomllib.loads(Path("Cargo.lock").read_text())
    entries = [p for p in lock["package"] if p["name"] == package["name"] and "source" not in p]
    if len(entries) != 1 or entries[0]["version"] != package["version"]:
        raise ValueError("Manifest and lockfile application versions must match")
    return package["version"]


def write_version(old, new):
    manifest = Path("Cargo.toml")
    content, count = re.subn(r'(?m)^version = "' + re.escape(old) + r'"$',
                             f'version = "{new}"', manifest.read_text(), count=1)
    if count != 1:
        raise ValueError("Cannot locate the manifest application version")
    manifest.write_text(content)
    lock = Path("Cargo.lock")
    content, count = re.subn(r'(?m)^(name = "ghidra-rust"\nversion = )"' + re.escape(old) + r'"$',
                             rf'\g<1>"{new}"', lock.read_text())
    if count != 1:
        raise ValueError("Cannot locate the lockfile application version")
    lock.write_text(content)
    if read_version() != new:
        raise ValueError("The prepared release version is inconsistent")


def prepare(source, run_id):
    if not re.fullmatch(r"[0-9a-f]{40}", source) or not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("Expected a full source commit SHA and numeric workflow run ID")
    if git("status", "--porcelain").stdout:
        raise ValueError("Use a clean disposable checkout for release preparation")
    marker = f"Automatic release from main {source}; workflow run {run_id}"
    for _ in range(5):
        git("fetch", "origin", "--tags")
        tags = git("for-each-ref", "--format=%(refname:short)%09%(contents:subject)", "refs/tags").stdout
        for line in tags.splitlines():
            tag, _, subject = line.partition("\t")
            if subject == marker:
                git("checkout", "--detach", tag)
                if git("rev-parse", "HEAD^").stdout.strip() != source or tag != "v" + read_version():
                    raise ValueError("Existing run tag does not match its source and version")
                return {"tag": tag, "version": read_version(), "sha": git("rev-parse", "HEAD").stdout.strip()}

        git("checkout", "--detach", source)
        old = read_version()
        version = tuple(map(int, old.split(".")))
        for line in tags.splitlines():
            tag = line.partition("\t")[0]
            match = VERSION.fullmatch(tag.removeprefix("v")) if tag.startswith("v") else None
            if match:
                major, minor, patch = map(int, match.groups())
                version = max(version, (major, minor, patch + 1))
        new = ".".join(map(str, version))
        write_version(old, new)
        git("add", "Cargo.toml", "Cargo.lock")
        git("-c", "user.name=github-actions[bot]", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "commit", "--allow-empty", "-m", f"Release version {new}")
        tag = "v" + new
        git("-c", "user.name=github-actions[bot]", "-c",
            "user.email=41898282+github-actions[bot]@users.noreply.github.com",
            "tag", "-a", tag, "-m", marker)
        tag_object = git("rev-parse", tag).stdout.strip()
        result = git("push", "origin", f"refs/tags/{tag}", check=False)
        if result.returncode:
            remote = git("ls-remote", "origin", f"refs/tags/{tag}").stdout.split()
            if not remote:
                raise ValueError("Tag publication failed; no release was reserved")
            if remote[0] != tag_object:
                # Another main update reserved this number first. Never move
                # its tag; fetch it and allocate the next patch on a new attempt.
                git("tag", "-d", tag)
                continue
        return {"tag": tag, "version": new, "sha": git("rev-parse", "HEAD").stdout.strip()}
    raise ValueError("Could not reserve a version after five concurrent tag conflicts; rerun this job")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    result = prepare(args.source, args.run_id)
    if output := os.environ.get("GITHUB_OUTPUT"):
        with open(output, "a", encoding="utf-8") as stream:
            for key, value in result.items():
                stream.write(f"{key}={value}\n")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        sys.exit(f"Release preparation failed: {error}")
