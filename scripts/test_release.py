"""Release regressions using temporary local Git repositories and package files."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("release_assets", SCRIPTS / "verify-release-assets.py")
assets = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assets)


class VersionReservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "checkout"
        self.repo.mkdir()
        self.git("init", "--bare", str(self.root / "remote.git"))
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release-test@example.invalid")
        (self.repo / "Cargo.toml").write_text('[package]\nname = "ghidra-rust"\nversion = "0.0.3"\n')
        (self.repo / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "ghidra-rust"\nversion = "0.0.3"\n')
        self.git("add", "Cargo.toml", "Cargo.lock")
        self.git("commit", "-m", "Main update")
        self.source = self.git("rev-parse", "HEAD")
        self.git("tag", "-a", "v0.0.3", "-m", "Previous release")
        self.git("remote", "add", "origin", str(self.root / "remote.git"))
        self.git("push", "origin", "main", "--tags")

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True, stderr=subprocess.DEVNULL).strip()

    def prepare(self, run_id, success=True):
        env = os.environ.copy()
        env.pop("GITHUB_OUTPUT", None)
        result = subprocess.run([sys.executable, str(SCRIPTS / "prepare-release.py"),
                                 "--source", self.source, "--run-id", str(run_id)],
                                cwd=self.repo, env=env, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout.splitlines()[-1])
        self.assertNotEqual(result.returncode, 0)
        return result

    def test_consecutive_updates_increment_patch_without_changing_main(self):
        first = self.prepare(100)
        second = self.prepare(101)
        self.assertEqual((first["tag"], second["tag"]), ("v0.0.4", "v0.0.5"))
        self.assertEqual(self.git("rev-parse", "main"), self.source)
        self.assertEqual(self.git("rev-parse", "v0.0.5^"), self.source)
        self.assertIn('version = "0.0.5"', self.git("show", "v0.0.5:Cargo.lock"))
        self.assertTrue(self.git("ls-remote", "origin", "refs/tags/v0.0.5"))

    def test_retry_reuses_the_original_immutable_snapshot(self):
        first = self.prepare(100)
        self.assertEqual(self.prepare(100), first)
        self.assertEqual(self.git("tag", "--list", "v0.0.4"), "v0.0.4")
        self.assertEqual(self.git("tag", "--list", "v0.0.5"), "")

    def test_concurrent_reservation_keeps_the_other_runs_tag(self):
        hook = self.repo / ".git/hooks/pre-push"
        hook.write_text("#!/bin/sh\n" + "git --git-dir=" + shlex.quote(str(self.root / "remote.git"))
                        + " tag v0.0.4 " + self.source + " 2>/dev/null || true\n")
        hook.chmod(0o755)
        self.assertEqual(self.prepare(100)["tag"], "v0.0.5")
        self.assertEqual(self.git("rev-parse", "v0.0.4"), self.source)

    def test_intentional_higher_manifest_version_is_respected(self):
        for name in ("Cargo.toml", "Cargo.lock"):
            path = self.repo / name
            path.write_text(path.read_text().replace('version = "0.0.3"', 'version = "0.1.0"'))
        self.git("commit", "-am", "Next minor version")
        self.source = self.git("rev-parse", "HEAD")
        self.assertEqual(self.prepare(100)["tag"], "v0.1.0")

    def test_mismatched_lockfile_does_not_reserve_a_tag(self):
        lock = self.repo / "Cargo.lock"
        lock.write_text(lock.read_text().replace('version = "0.0.3"', 'version = "0.0.2"'))
        self.git("commit", "-am", "Invalid metadata")
        self.source = self.git("rev-parse", "HEAD")
        self.assertIn("must match", self.prepare(100, success=False).stderr)
        self.assertEqual(self.git("ls-remote", "origin", "refs/tags/v0.0.4"), "")


class PackageVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.version = "0.0.4"
        self.linux = "ghidra-rust-0.0.4-linux-x64"
        self.windows = "ghidra-rust-0.0.4-windows-x64"
        elf = bytearray(20)
        elf[:7] = b"\x7fELF\x02\x01\x01"
        elf[18:20] = b"\x3e\0"
        pe = bytearray(256)
        pe[:2] = b"MZ"
        struct.pack_into("<I", pe, 0x3c, 128)
        pe[128:134] = b"PE\0\0\x64\x86"
        pe[152:154] = b"\x0b\x02"
        pe[220:222] = b"\x02\0"
        (self.root / self.linux).write_bytes(elf)
        (self.root / (self.windows + ".exe")).write_bytes(pe)
        with tarfile.open(self.root / (self.linux + ".tar.gz"), "w:gz") as archive:
            files = self.bundle("x86_64-unknown-linux-gnu")
            files["ghidra-rust"] = bytes(elf)
            files["BUILD-INFO.json"] = json.dumps({"application_version": self.version,
                "target": "x86_64-unknown-linux-gnu", "maximum_required_glibc_symbol_version": "GLIBC_2.39"}).encode()
            for name, value in files.items():
                member = tarfile.TarInfo(self.linux + "/" + name)
                member.size = len(value)
                member.mode = 0o755 if name == "ghidra-rust" else 0o644
                archive.addfile(member, io.BytesIO(value))
        self.write_windows(bytes(pe))
        self.checksums()

    def bundle(self, target):
        files = {name: b"Bundled documentation/license" for name in assets.REQUIRED}
        files["THIRD-PARTY.json"] = json.dumps({"target": target, "packages": [
            {"name": "ghidra-rust", "version": self.version}]}).encode()
        return files

    def write_windows(self, executable):
        with zipfile.ZipFile(self.root / (self.windows + ".zip"), "w") as archive:
            for name, value in self.bundle("x86_64-pc-windows-msvc").items():
                archive.writestr(self.windows + "/" + name, value)
            archive.writestr(self.windows + "/ghidra-rust.exe", executable)

    def checksums(self):
        for file in self.root.iterdir():
            if not file.name.endswith(".sha256"):
                checksum = hashlib.sha256(file.read_bytes()).hexdigest()
                file.with_name(file.name + ".sha256").write_text(f"{checksum}  {file.name}\n")

    def test_complete_matching_native_packages_are_accepted(self):
        assets.verify(self.root, self.version)

    def test_missing_windows_download_is_rejected(self):
        (self.root / (self.windows + ".exe")).unlink()
        with self.assertRaisesRegex(ValueError, "Expected both"):
            assets.verify(self.root, self.version)

    def test_corrupted_download_is_rejected(self):
        (self.root / self.linux).write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            assets.verify(self.root, self.version)

    def test_inconsistent_archive_executable_is_rejected_even_with_valid_checksums(self):
        self.write_windows(b"another executable")
        self.checksums()
        with self.assertRaisesRegex(ValueError, "Windows archive executable differs"):
            assets.verify(self.root, self.version)


if __name__ == "__main__":
    unittest.main()
