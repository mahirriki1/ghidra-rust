#!/usr/bin/env python3
"""Package an existing native Linux x64 release; no builds or downloads."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parent.parent
TARGET = "x86_64-unknown-linux-gnu"
NOTICE_NAME = re.compile(r"LICENSE|COPYRIGHT|COPYING|NOTICE|^OFL(?:[._-]|$)", re.I)
CODE_NOTICE_NAME = re.compile(r"LICENSE|COPYING|^OFL(?:[._-]|$)", re.I)
SAFE_NAME = re.compile(r"[A-Za-z0-9_.+-]+")
SKIP_DIRECTORIES = {".git", ".agents", ".codex", ".aws", "target"}


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True, encoding="utf-8")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def package_file(root, relative):
    """Resolve a package-relative regular file without following symlinks."""
    root = Path(root)
    candidate = Path(os.path.abspath(root / relative))
    try:
        parts = candidate.relative_to(root).parts
    except ValueError as error:
        raise ValueError(f"File escapes package: {root / relative}") from error
    current = root
    for part in ("", *parts):
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Refusing a symlink in packaging input: {current}")
    if not candidate.is_file():
        raise ValueError(f"Required packaging file is missing: {candidate}")
    return candidate


def copy_file(source, destination):
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"Required regular packaging file is missing: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def notice_files(root):
    if root.is_symlink():
        raise ValueError(f"Dependency root is a symlink: {root}")
    for directory, dirs, files in os.walk(root, followlinks=False):
        directory = Path(directory)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRECTORIES
                         and not (directory / d).is_symlink())
        for name in sorted(files):
            path = directory / name
            if NOTICE_NAME.search(name) and not path.is_symlink():
                yield package_file(root, path.relative_to(root))


def collect_notices(metadata, application, bundle):
    resolved = {node["id"] for node in metadata["resolve"]["nodes"]}
    destinations = set()
    packages = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"], p["id"])):
        if package["id"] not in resolved:
            continue
        entry = {key: package.get(key) for key in ("name", "version", "license", "authors", "repository")}
        entry["source"] = package.get("source") or "local workspace"
        if package["id"] == application["id"]:
            entry.update(notice_directory=".", notice_files=["LICENSE", "NOTICE"])
            packages.append(entry)
            continue
        name = f'{package["name"]}-{package["version"]}'
        if not SAFE_NAME.fullmatch(name) or name in destinations:
            raise ValueError(f"Unsafe or duplicate dependency directory: {name}")
        destinations.add(name)
        root = Path(package["manifest_path"]).parent
        files = set(notice_files(root))
        code_license = package.get("license") or ""
        if package["name"] == "epaint_default_fonts":
            expected = "(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0"
            if code_license != expected:
                raise ValueError(f"Review changed font-package licenses: {code_license}")
            for font in ("Hack-Regular.txt", "OFL.txt", "UFL.txt",
                         "emoji-icon-font-mit-license.txt", "egui-icons.txt"):
                files.add(package_file(root, f"fonts/{font}"))
            code_license = "MIT OR Apache-2.0"
        if package.get("license_file"):
            files.add(package_file(root, package["license_file"]))
        notice_directory = f"third-party/{name}"
        copied = []
        for file in sorted(files):
            relative = file.relative_to(root)
            copy_file(file, bundle / notice_directory / relative)
            copied.append(relative.as_posix())
        # A nested asset license does not cover the crate's Rust code.
        code_notices = [f for f in files if f.parent == root and CODE_NOTICE_NAME.search(f.name)]
        fallback = None
        if not package.get("license_file") and not code_notices:
            # Plain alternatives allow selecting an offered license. Composite
            # AND/WITH expressions must supply their own complete license texts.
            choices = [c.strip() for c in re.split(r"\s+OR\s+", code_license.replace("(", "").replace(")", ""))]
            plain = all(re.fullmatch(r"[A-Za-z0-9.+-]+", c) for c in choices)
            if plain and "Apache-2.0" in choices:
                license_id, source, original = "Apache-2.0", "https://www.apache.org/licenses/LICENSE-2.0.txt", ROOT / "LICENSE"
            elif plain and "BSL-1.0" in choices:
                license_id, source, original = "BSL-1.0", "https://www.boost.org/LICENSE_1_0.txt", ROOT / "scripts/licenses/BSL-1.0.txt"
            else:
                raise ValueError(f"No code license text in {name}; unsupported fallback: {package.get('license')!r}")
            filename = f"LICENSE-{license_id}.txt"
            copy_file(original, bundle / notice_directory / filename)
            copied.append(filename)
            fallback = {"license": license_id, "source": source, "file": filename}
        entry.update(notice_directory=notice_directory, notice_files=copied, fallback_license=fallback)
        packages.append(entry)
    write_json(bundle / "THIRD-PARTY.json", {
        "target": TARGET,
        "description": "Linux-resolved Cargo packages, including build dependencies; embedded asset licenses retain their package-relative paths.",
        "packages": packages,
    })


def assert_executable(path):
    with path.open("rb") as binary:
        header = binary.read(64)
    if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Release executable must be a little-endian ELF64 image")
    image_type, machine, version = struct.unpack_from("<HHI", header, 16)
    if image_type not in (2, 3) or machine != 62 or version != 1:
        raise ValueError("Release executable must be Linux x86_64 ET_EXEC or ET_DYN")
    if not os.access(path, os.X_OK):
        raise ValueError(f"Release binary is not executable: {path}")


def build_info(binary, compiler):
    versions = sorted(set(re.findall(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", run("readelf", "--version-info", str(binary)))),
                      key=lambda v: tuple(map(int, v.split("."))))
    libraries = re.findall(r"\(NEEDED\).*\[([^\]]+)\]", run("readelf", "--dynamic", str(binary)))
    return {
        "target": TARGET,
        "rustc": compiler,
        "host": TARGET,
        "required_glibc_symbol_versions": [f"GLIBC_{v}" for v in versions],
        "maximum_required_glibc_symbol_version": f"GLIBC_{versions[-1]}" if versions else None,
        "needed_shared_libraries": libraries,
        "runtime_requirements": [
            "Conventional glibc-based GNU/Linux x64; this is not a universal static binary or AppImage.",
            "Compatible system shared libraries and an OpenGL-capable X11 or Wayland desktop.",
            "bubblewrap (bwrap), working unprivileged user namespaces, and a conventional /usr-based filesystem for analysis workers.",
            "The measured GLIBC symbol requirement is a minimum; it does not certify compatibility with every distribution.",
            "No Rust or Python runtime is required by the shipped application.",
        ],
    }


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    path.with_name(path.name + ".sha256").write_text(f"{digest.hexdigest()}  {path.name}\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-directory", default=os.environ.get("CARGO_TARGET_DIR"))
    args = parser.parse_args()
    if sys.platform != "linux" or os.environ.get("CARGO_BUILD_TARGET", TARGET) != TARGET:
        raise ValueError(f"Package natively on Linux with the {TARGET} toolchain and build target")
    for command in ("cargo", "rustc", "strip", "readelf"):
        if not shutil.which(command):
            raise ValueError(f"Required build tool is missing: {command}")
    compiler = run("rustc", "-vV").strip()
    if f"host: {TARGET}" not in compiler.splitlines():
        raise ValueError(f"Use the native {TARGET} Rust toolchain")
    env = os.environ.copy()
    if args.target_directory:
        env["CARGO_TARGET_DIR"] = str((ROOT / args.target_directory).absolute())
    metadata = json.loads(run("cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", TARGET, env=env))
    application = next(p for p in metadata["packages"] if Path(p["manifest_path"]) == ROOT / "Cargo.toml")
    target = Path(metadata["target_directory"])
    executable = target / TARGET / "release/ghidra-rust" if os.environ.get("CARGO_BUILD_TARGET") else target / "release/ghidra-rust"
    executable = package_file(executable.parent, executable.name)
    assert_executable(executable)
    name = f'ghidra-rust-{application["version"]}-linux-x64'
    if not SAFE_NAME.fullmatch(name):
        raise ValueError("Application version cannot be used safely in an archive filename")
    dist = target / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".package-", dir=dist) as temporary:
        staging = Path(temporary)
        bundle = staging / name
        bundled_binary = bundle / "ghidra-rust"
        copy_file(executable, bundled_binary)
        run("strip", "--strip-unneeded", str(bundled_binary))
        bundled_binary.chmod(0o755)
        assert_executable(bundled_binary)
        for relative in ("README.md", "LICENSE", "NOTICE", "docs/releases.md", "docs/crypto-signatures.md"):
            copy_file(package_file(ROOT, relative), bundle / relative)
        for relative in ("docs/linux.md", "docs/windows.md"):
            if (ROOT / relative).exists():
                copy_file(package_file(ROOT, relative), bundle / relative)
        images = ROOT / "docs/images"
        if images.is_dir():
            for directory, dirs, files in os.walk(images, followlinks=False):
                if any((Path(directory) / d).is_symlink() for d in dirs):
                    raise ValueError("Documentation images must not contain symlink directories")
                for file in files:
                    relative = (Path(directory) / file).relative_to(ROOT)
                    copy_file(package_file(ROOT, relative), bundle / relative)
        collect_notices(metadata, application, bundle)
        info = build_info(bundled_binary, compiler)
        info["application_version"] = application["version"]
        write_json(bundle / "BUILD-INFO.json", info)
        archive = staging / f"{name}.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.PAX_FORMAT) as output:
            # Add only ordinary files with known package-relative names. In
            # particular, never encode symlinks, devices, or host absolute paths.
            for file in sorted(bundle.rglob("*")):
                if file.is_file():
                    entry = output.gettarinfo(str(file), arcname=file.relative_to(staging).as_posix())
                    entry.uid = entry.gid = 0
                    entry.uname = entry.gname = ""
                    with file.open("rb") as source:
                        output.addfile(entry, source)
        # Use a distinct location because the bundle directory has this name.
        standalone = staging / "standalone" / name
        copy_file(bundled_binary, standalone)
        standalone.chmod(0o755)
        for file in (archive, standalone):
            destination = dist / file.name
            checksum(file)
            os.replace(file, destination)
            os.replace(file.with_name(file.name + ".sha256"), dist / (file.name + ".sha256"))
            print(f"Created {destination}")
        print(f"Maximum required GLIBC symbol: {info['maximum_required_glibc_symbol_version']}")
        print("Distribute the tar.gz to retain documentation and license notices.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, StopIteration, subprocess.CalledProcessError) as error:
        sys.exit(f"Packaging failed: {error}")
