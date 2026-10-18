#!/usr/bin/env python3
"""Validate both packaged native builds without executing or extracting them."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import sys
import tarfile
import tomllib
import zipfile


ROOT = Path(__file__).resolve().parent.parent
REQUIRED = ("README.md", "LICENSE", "NOTICE", "THIRD-PARTY.json",
            "docs/releases.md", "docs/linux.md", "docs/windows.md")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        result.update(chunk)
    return result.hexdigest()


def check_name(name, prefix):
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts and "\\" not in name
            and bool(path.parts) and path.parts[0] == prefix, f"Unsafe archive member: {name}")


def metadata(stream, version, target):
    value = json.loads(stream.read(8 * 1024 * 1024 + 1))
    require(value["target"] == target, "Incorrect package target")
    app = [p for p in value["packages"] if p["name"] == "ghidra-rust"]
    require(len(app) == 1 and app[0]["version"] == version, "Incorrect bundled application version")


def verify(directory, version):
    prefix = f"ghidra-rust-{version}"
    linux = f"{prefix}-linux-x64"
    windows = f"{prefix}-windows-x64"
    files = [linux, linux + ".tar.gz", windows + ".exe", windows + ".zip"]
    expected = set(files + [name + ".sha256" for name in files])
    require({p.name for p in directory.iterdir()} == expected, "Expected both executables, both archives, and four checksums")
    require(all(p.is_file() and not p.is_symlink() for p in directory.iterdir()), "Assets must be ordinary files")
    hashes = {}
    for name in files:
        checksum = (directory / (name + ".sha256")).read_text(encoding="utf-8")
        match = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(name) + r"\n?", checksum)
        require(match is not None, f"Invalid checksum file: {name}")
        with (directory / name).open("rb") as stream:
            hashes[name] = digest(stream)
        require(hashes[name] == match[1], f"Checksum mismatch: {name}")
        print(f"SHA-256 verified: {name}")

    with tarfile.open(directory / (linux + ".tar.gz"), "r:gz") as archive:
        for member in archive:
            check_name(member.name, linux)
            require(member.isfile(), "Linux package must contain regular files only")
        for name in REQUIRED:
            require(archive.getmember(f"{linux}/{name}").isfile(), f"Missing bundle file: {name}")
        binary = archive.getmember(f"{linux}/ghidra-rust")
        require(binary.mode & 0o111, "Bundled Linux application is not executable")
        with archive.extractfile(binary) as stream:
            require(digest(stream) == hashes[linux], "Linux archive executable differs from standalone")
        with archive.extractfile(f"{linux}/THIRD-PARTY.json") as stream:
            metadata(stream, version, "x86_64-unknown-linux-gnu")
        with archive.extractfile(f"{linux}/BUILD-INFO.json") as stream:
            info = json.loads(stream.read(1024 * 1024 + 1))
            require(info["application_version"] == version and info["target"] == "x86_64-unknown-linux-gnu",
                    "Incorrect Linux build metadata")
            print("Linux GLIBC requirement:", info["maximum_required_glibc_symbol_version"])

    with zipfile.ZipFile(directory / (windows + ".zip")) as archive:
        for name in archive.namelist():
            check_name(name, windows)
        for name in REQUIRED:
            archive.getinfo(f"{windows}/{name}")
        with archive.open(f"{windows}/ghidra-rust.exe") as stream:
            require(digest(stream) == hashes[windows + ".exe"], "Windows archive executable differs from standalone")
        with archive.open(f"{windows}/THIRD-PARTY.json") as stream:
            metadata(stream, version, "x86_64-pc-windows-msvc")

    with (directory / (windows + ".exe")).open("rb") as stream:
        require(stream.read(2) == b"MZ", "Windows application must be PE")
        stream.seek(0x3c)
        offset = struct.unpack("<I", stream.read(4))[0]
        stream.seek(offset)
        require(stream.read(6) == b"PE\0\0\x64\x86", "Windows application must be x64 PE")
        stream.seek(offset + 24)
        require(stream.read(2) == b"\x0b\x02", "Windows application must be PE32+")
        stream.seek(offset + 24 + 68)
        require(stream.read(2) == b"\x02\0", "Windows application must use the GUI subsystem")
    with (directory / linux).open("rb") as stream:
        header = stream.read(20)
        require(header[:7] == b"\x7fELF\x02\x01\x01" and header[18:20] == b"\x3e\0",
                "Linux application must be little-endian x64 ELF")
    print("Both native x64 packages, embedded executable copies, notices, versions, and checksums verified.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    with (ROOT / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream)["package"]["version"]
    verify(args.directory, version)


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, ValueError, struct.error, tarfile.TarError, zipfile.BadZipFile) as error:
        sys.exit(f"Release asset verification failed: {error}")
