#!/usr/bin/env python3
"""Check release/tag metadata without building the application (Python 3.11+)."""

import argparse
import os
from pathlib import Path
import re
import sys
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="Require this tag to equal v<Cargo.toml version>")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    with (root / "Cargo.toml").open("rb") as source:
        package = tomllib.load(source)["package"]
    with (root / "Cargo.lock").open("rb") as source:
        lock = tomllib.load(source)
    version = package["version"]
    if not re.fullmatch(
        r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version
    ):
        raise ValueError(f"Unsupported release version: {version!r}")
    locked = [
        entry
        for entry in lock["package"]
        if entry["name"] == package["name"] and "source" not in entry
    ]
    if len(locked) != 1 or locked[0]["version"] != version:
        raise ValueError("The application version in Cargo.lock must match Cargo.toml")
    tag = args.tag
    if tag is None and os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = os.environ.get("GITHUB_REF_NAME", "")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"Release tag {tag!r} must equal v{version}")
    print(f"Validated {package['name']} {version}" + (f" (tag {tag})" if tag else ""))


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError) as error:
        print(f"Release version check failed: {error}", file=sys.stderr)
        sys.exit(1)
