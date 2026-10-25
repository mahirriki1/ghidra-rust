"""Release regressions using temporary local Git repositories and package files."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
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


class ReleaseNotesTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.entry("already-shipped.md", "- An earlier feature.\n")
        self.commit("Already shipped")
        self.base = self.git("rev-parse", "HEAD")
        self.automatic_tag("v0.0.3", self.base)

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True,
                                       stderr=subprocess.DEVNULL).strip()

    def entry(self, name, content):
        path = self.repo / "docs/release-notes" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def commit(self, message):
        self.git("add", ".")
        self.git("commit", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def automatic_tag(self, tag, source):
        self.git("checkout", "--detach", source)
        snapshot = self.commit("Release version " + tag[1:])
        self.git("tag", "-a", tag, "-m", f"Automatic release from main {source}; workflow run 100")
        self.git("checkout", "main")
        return snapshot

    def notes(self, published=("v0.0.3",), source="main", tag="v0.0.5", success=True):
        # Keep preview input/output outside the repository under test.
        with tempfile.TemporaryDirectory() as directory:
            tags = Path(directory) / "tags.txt"
            tags.write_text("\n".join(published), encoding="utf-8")
            output = Path(directory) / "notes.md"
            result = subprocess.run([
                sys.executable, str(SCRIPTS / "release-notes.py"),
                "--source", source, "--snapshot", source, "--tag", tag,
                "--published-tags", str(tags), "--repo", "example/project",
                "--server-url", "https://github.com", "--run-id", "123",
                "--output", str(output),
            ], cwd=self.repo, text=True, capture_output=True)
            if not success:
                self.assertNotEqual(result.returncode, 0)
                return result.stderr
            self.assertEqual(result.returncode, 0, result.stderr)
            return output.read_text(encoding="utf-8")

    def test_collects_detailed_entries_from_every_merged_branch_and_direct_commits(self):
        for number in (1, 2):
            self.git("checkout", "-b", f"feature-{number}")
            self.entry(f"feature-{number}.md", f"- Feature {number} behavior.\n- Feature {number} limit.\n")
            self.commit(f"Implement feature {number}")
            self.commit(f"Fix feature {number} edge case")
            self.git("checkout", "main")
            self.git("merge", "--no-ff", f"feature-{number}", "-m", f"Merge PR {number}")
        direct = self.commit("Direct update")
        notes = self.notes()
        summary, history = notes.split("<details>", 1)
        for number in (1, 2):
            self.assertIn(f"- Feature {number} behavior.", summary)
            self.assertIn(f"- Feature {number} limit.", summary)
            self.assertIn(f"Fix feature {number} edge case", history)
            self.assertIn(f"Merge PR {number}", history)
        self.assertIn(f"/commit/{direct}", history)
        self.assertNotIn("An earlier feature", notes)
        self.assertNotIn("Already shipped", notes)
        self.assertNotIn("Release version", notes)
        self.assertIn("All 7 commits", notes)
        self.assertIn("/compare/v0.0.3...v0.0.5", notes)

    def test_fallback_includes_more_than_100_commits(self):
        for number in range(105):
            self.commit(f"Change {number:03}")
        notes = self.notes()
        self.assertEqual(notes.count("- Change "), 105)
        self.assertLess(notes.index("Change 000"), notes.index("Change 104"))
        self.assertNotIn("<details>", notes)

    def test_first_release_includes_all_entries_and_history(self):
        self.entry("new.md", "- New feature.\n")
        self.commit("New change")
        notes = self.notes(published=())
        self.assertIn("- An earlier feature.", notes)
        self.assertIn("- New feature.", notes)
        self.assertIn("Already shipped", notes)
        self.assertIn("[Full history]", notes)

    def test_reserved_tags_and_higher_published_versions_do_not_hide_changes(self):
        self.commit("Change before failed release")
        self.automatic_tag("v0.0.4", self.git("rev-parse", "main"))
        self.commit("Change after failed release")
        notes = self.notes(published=("v0.0.3", "v0.0.6", "nightly"))
        self.assertIn("Change before failed release", notes)
        self.assertIn("Change after failed release", notes)
        self.assertIn("/compare/v0.0.3...v0.0.5", notes)

    def test_lower_version_from_newer_source_is_not_used_as_baseline(self):
        current = self.commit("Current source update")
        newer = self.commit("Newer main update")
        self.automatic_tag("v0.0.4", newer)
        notes = self.notes(published=("v0.0.3", "v0.0.4"), source=current)
        self.assertIn("Current source update", notes)
        self.assertNotIn("Newer main update", notes)
        self.assertIn("/compare/v0.0.3...v0.0.5", notes)

    def test_highest_applicable_published_version_and_manual_tags(self):
        self.commit("Already published manual change")
        self.git("tag", "v0.0.4")
        self.commit("Current manual change")
        notes = self.notes(published=("v0.0.4", "v0.0.3"))
        self.assertIn("Current manual change", notes)
        self.assertNotIn("Already published manual change", notes)
        self.assertIn("/compare/v0.0.4...v0.0.5", notes)

    def test_amended_entries_are_visible_and_working_tree_entries_are_ignored(self):
        self.entry("already-shipped.md", "- Corrected feature limitation.\n")
        self.commit("Correct release note")
        self.entry("uncommitted.md", "- Uncommitted feature.\n")
        notes = self.notes()
        self.assertIn("- Corrected feature limitation.", notes)
        self.assertNotIn("Uncommitted feature", notes)

    def test_empty_update_excludes_automatic_version_snapshot(self):
        notes = self.notes()
        self.assertIn("No source changes since the previous release.", notes)
        self.assertNotIn("Release version", notes)

    def test_invalid_entry_fails_instead_of_publishing_incomplete_notes(self):
        self.entry("invalid.md", "A PR title without change bullets.\n")
        self.commit("Bad entry")
        self.assertIn("must contain Markdown bullets", self.notes(success=False))

    def test_readme_is_not_a_release_entry_and_commit_titles_are_escaped(self):
        self.entry("README.md", "# Instructions, not release notes\n")
        self.commit("Fix [labels] and *formatting*")
        notes = self.notes()
        self.assertIn(r"Fix \[labels\] and \*formatting\*", notes)
        self.assertNotIn("Instructions, not release notes", notes)
        self.assertIn("Hosted CI does not run tests", notes)

    def run_publisher(self, state, version="0.0.5"):
        self.entry("new.md", "- Complete feature details.\n- A separate fix.\n")
        source = self.commit("Feature update")
        scripts = self.repo / "scripts"
        scripts.mkdir()
        for name in ("publish-release.sh", "release-notes.py"):
            shutil.copyfile(SCRIPTS / name, scripts / name)
        binary = self.repo / "bin"
        binary.mkdir()
        fake = binary / "gh"
        fake.write_text("#!/usr/bin/env python3\n" + '''
import json
import os
import sys
args = sys.argv[1:]
with open(os.environ["GH_CALL_LOG"], "a") as stream:
    stream.write(json.dumps(args) + "\\n")
if args[0] == "api":
    if "/releases?" in args[2]:
        if ".draft == false" in args[-1]:
            print("v0.0.3")
        elif os.environ["RELEASE_STATE"] != "absent":
            print(json.dumps({"draft": os.environ["RELEASE_STATE"] == "draft"}))
    elif "/git/ref/heads/main" in args[1]:
        print(os.environ["SOURCE_SHA"])
    else:
        sys.exit("Unexpected API call")
elif args[:2] == ["release", "view"]:
    if "assets" in args:
        print("package.zip")
    else:
        print("https://github.com/example/project/releases/tag/v0.0.5")
elif args[:2] not in (["release", "create"], ["release", "edit"], ["release", "upload"]):
    sys.exit("Unexpected gh call")
''', encoding="utf-8")
        fake.chmod(0o755)
        assets_dir = self.repo / "target/release-assets"
        assets_dir.mkdir(parents=True)
        (assets_dir / "package.zip").write_bytes(b"already verified package")
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "calls.jsonl"
            env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ["PATH"],
                       RELEASE_TAG=f"v{version}", RELEASE_VERSION=version, RELEASE_SHA=source,
                       SOURCE_SHA=source, GH_REPO="example/project", GITHUB_RUN_ID="123",
                       GITHUB_SERVER_URL="https://github.com", RUNNER_TEMP=directory,
                       GITHUB_STEP_SUMMARY=str(Path(directory) / "summary"),
                       GH_CALL_LOG=str(log), RELEASE_STATE=state)
            result = subprocess.run(["bash", str(scripts / "publish-release.sh")],
                                    cwd=self.repo, env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            notes = Path(directory) / "release-notes.md"
            return calls, notes.read_text() if notes.exists() else None

    def test_new_release_uses_complete_notes_without_github_generated_duplicate(self):
        calls, notes = self.run_publisher("absent")
        creates = [call for call in calls if call[:2] == ["release", "create"]]
        self.assertEqual(len(creates), 1)
        self.assertIn("--notes-file", creates[0])
        self.assertNotIn("--generate-notes", creates[0])
        self.assertIn("- Complete feature details.", notes)
        self.assertIn("- A separate fix.", notes)

    def test_resumed_draft_refreshes_notes_before_upload_and_publication(self):
        calls, notes = self.run_publisher("draft")
        self.assertFalse(any(call[:2] == ["release", "create"] for call in calls))
        refresh = next(i for i, call in enumerate(calls) if "--notes-file" in call)
        upload = next(i for i, call in enumerate(calls) if call[:2] == ["release", "upload"])
        publish = next(i for i, call in enumerate(calls) if "--draft=false" in call)
        self.assertLess(refresh, upload)
        self.assertLess(upload, publish)
        self.assertIn("- Complete feature details.", notes)

    def test_already_published_release_keeps_its_notes_and_assets(self):
        calls, notes = self.run_publisher("published")
        self.assertEqual(len(calls), 1)
        self.assertIsNone(notes)

    @staticmethod
    def publication(calls):
        return next(call for call in calls if "--draft=false" in call)

    def assert_unstable_prerelease(self, state):
        calls, _ = self.run_publisher(state, "0.0.5")
        staged = next(call for call in calls
                      if call[:2] == ["release", "create"] or "--notes-file" in call)
        self.assertIn("--prerelease=true", staged)
        publish = self.publication(calls)
        self.assertIn("--prerelease=true", publish)
        self.assertIn("--latest=false", publish)

    def test_new_unstable_version_publishes_as_prerelease_never_marked_latest(self):
        self.assert_unstable_prerelease("absent")

    def test_resumed_unstable_draft_becomes_a_prerelease(self):
        self.assert_unstable_prerelease("draft")

    def test_first_stable_version_publishes_as_latest_release(self):
        calls, _ = self.run_publisher("absent", "1.0.0")
        create = next(call for call in calls if call[:2] == ["release", "create"])
        self.assertIn("--prerelease=false", create)
        publish = self.publication(calls)
        self.assertIn("--prerelease=false", publish)
        self.assertIn("--latest=true", publish)


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
