#!/usr/bin/env python3
"""Create an Ed25519 update key or sign verified release assets using OpenSSL."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_KEY = ROOT / "data/update-public-key.txt"
MAX_NOTICES = 16 * 1024 * 1024
MAX_BINARY = 512 * 1024 * 1024


def openssl(*args):
    # Never pass key material in arguments or echo OpenSSL's input.
    return subprocess.check_output(["openssl", *args], stderr=subprocess.PIPE)


def public_key(private):
    der = openssl("pkey", "-in", str(private), "-pubout", "-outform", "DER")
    if len(der) != 44 or der[:12] != bytes.fromhex("302a300506032b6570032100"):
        raise ValueError("Update signing requires an Ed25519 key")
    return base64.b64encode(der[12:]).decode("ascii")


def initialize(private, public):
    if private.exists() or public.exists():
        raise ValueError("Refusing to overwrite an existing signing key or trust root")
    private.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Create the destination privately before handing it to OpenSSL.
    with private.open("xb"):
        private.chmod(0o600)
    try:
        openssl("genpkey", "-algorithm", "ED25519", "-out", str(private))
        public.parent.mkdir(parents=True, exist_ok=True)
        public.write_text(public_key(private) + "\n", encoding="ascii")
    except Exception:
        private.unlink(missing_ok=True)
        raise


def artifact(directory, name):
    path = directory / name
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_BINARY:
        raise ValueError(f"Invalid update artifact: {name}")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"name": name, "size": path.stat().st_size, "sha256": digest}


def collect_notices(directory, version):
    output = bytearray()

    def append(name, stream, size):
        if size > MAX_NOTICES - len(output):
            raise ValueError("Release notices exceed the update budget")
        output.extend(f"\n===== {name} =====\n".encode())
        output.extend(stream.read(size + 1))
        if len(output) > MAX_NOTICES:
            raise ValueError("Release notices exceed the update budget")

    def legal(name):
        parts = name.split("/")
        return len(parts) >= 2 and (parts[1] == "third-party" or
                                   parts[1:] in (["LICENSE"], ["NOTICE"], ["THIRD-PARTY.json"]))

    prefix = f"ghidra-rust-{version}"
    with tarfile.open(directory / f"{prefix}-linux-x64.tar.gz", "r:gz") as archive:
        for member in archive:
            if member.isfile() and legal(member.name):
                with archive.extractfile(member) as stream:
                    append(member.name, stream, member.size)
    with zipfile.ZipFile(directory / f"{prefix}-windows-x64.zip") as archive:
        for member in archive.infolist():
            if not member.is_dir() and legal(member.filename):
                with archive.open(member) as stream:
                    append(member.filename, stream, member.file_size)
    if not output:
        raise ValueError("Release packages contain no notices")
    return output


def sign(directory, version, private, public=PUBLIC_KEY):
    if public_key(private) != public.read_text(encoding="ascii").strip():
        raise ValueError("Signing key does not match the application's embedded public key")
    prefix = f"ghidra-rust-{version}"
    binaries = {}
    for target, name in (("linux-x64", prefix + "-linux-x64"),
                         ("windows-x64", prefix + "-windows-x64.exe")):
        binaries[target] = artifact(directory, name)
    notices_name = f"{prefix}-update-notices.txt"
    (directory / notices_name).write_bytes(collect_notices(directory, version))
    manifest = {"format": 1, "repository": "mahirriki1/ghidra-rust", "version": version,
                "binaries": binaries, "notices": artifact(directory, notices_name)}
    manifest_path = directory / "update.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                             encoding="utf-8")
    signature = openssl("pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                        "-in", str(manifest_path))
    if len(signature) != 64:
        raise ValueError("Unexpected Ed25519 signature length")
    (directory / "update.json.sig").write_bytes(signature)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init-key", type=Path, help="Create private PEM here and embed its public key")
    group.add_argument("--sign", type=Path, help="Directory of already-verified release packages")
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--public-key", type=Path, default=PUBLIC_KEY)
    args = parser.parse_args()
    if args.init_key:
        initialize(args.init_key, args.public_key)
        print(f"Private key created at {args.init_key}; keep it private and backed up.")
        print("Configure the UPDATE_SIGNING_KEY GitHub Actions secret before publishing updates.")
        return
    with (ROOT / "Cargo.toml").open("rb") as stream:
        version = tomllib.load(stream)["package"]["version"]
    if args.key_file:
        sign(args.sign, version, args.key_file, args.public_key)
    else:
        key = os.environ.pop("UPDATE_SIGNING_KEY", "")
        if not key:
            raise ValueError("UPDATE_SIGNING_KEY is not configured")
        with tempfile.TemporaryDirectory(prefix="ghidra-update-signing-") as temporary:
            private = Path(temporary) / "private.pem"
            with private.open("x", encoding="ascii") as stream:
                private.chmod(0o600)
                stream.write(key)
            sign(args.sign, version, private, args.public_key)
    print("Signed update manifest and collected both packages' license notices.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError, zipfile.BadZipFile) as error:
        # CalledProcessError only describes argv, which contains paths, never keys.
        raise SystemExit(f"Update signing failed: {error}") from None
