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
        self.console = bytearray(pe)
        self.console[220:222] = b"\x03\0"
        (self.root / self.linux).write_bytes(elf)
        (self.root / (self.windows + ".exe")).write_bytes(pe)
        with tarfile.open(self.root / (self.linux + ".tar.gz"), "w:gz") as archive:
            files = self.bundle("x86_64-unknown-linux-gnu")
            files["ghidra-rust"] = bytes(elf)
            files["ghidra-rust-headless"] = bytes(elf)
            files["BUILD-INFO.json"] = json.dumps({"application_version": self.version,
                "target": "x86_64-unknown-linux-gnu", "maximum_required_glibc_symbol_version": "GLIBC_2.39"}).encode()
            for name, value in files.items():
                member = tarfile.TarInfo(self.linux + "/" + name)
                member.size = len(value)
                member.mode = 0o755 if name in ("ghidra-rust", "ghidra-rust-headless") else 0o644
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
            archive.writestr(self.windows + "/ghidra-rust-headless.exe", self.console)

    def checksums(self):
        for file in self.root.iterdir():
            if not file.name.endswith(".sha256"):
                checksum = hashlib.sha256(file.read_bytes()).hexdigest()
                file.with_name(file.name + ".sha256").write_text(f"{checksum}  {file.name}\n")

    def test_complete_matching_native_packages_are_accepted(self):
        assets.verify(self.root, self.version)

    def test_gui_subsystem_in_headless_archive_is_rejected(self):
        path = self.root / (self.windows + ".zip")
        with zipfile.ZipFile(path) as archive:
            files = {name: archive.read(name) for name in archive.namelist()}
        name = self.windows + "/ghidra-rust-headless.exe"
        image = bytearray(files[name])
        offset = struct.unpack_from("<I", image, 0x3c)[0]
        image[offset + 24 + 68:offset + 24 + 70] = b"\x02\0"
        files[name] = image
        with zipfile.ZipFile(path, "w") as archive:
            for name, value in files.items():
                archive.writestr(name, value)
        self.checksums()
        with self.assertRaisesRegex(ValueError, "console subsystem"):
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


package_spec = importlib.util.spec_from_file_location("package_linux", SCRIPTS / "package-linux.py")
packager = importlib.util.module_from_spec(package_spec)
package_spec.loader.exec_module(packager)


class LinuxPackagingSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "target dïr"

    def pair(self, directory, members=packager.MEMBERS):
        directory.mkdir(parents=True, exist_ok=True)
        for member in members:
            (directory / member).write_bytes(b"\x7fELF")
        return directory

    def stub(self, body):
        path = Path(self.temporary.name) / "probe stub"
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
        return path

    def test_refusal_probe_requires_a_nonzero_exit_and_the_exact_diagnostic(self):
        script = 'test "$1 $2" = "--analysis-worker --test-debug-fault=stall@0x0" || exit 9\n'
        packager.assert_refuses_test_hooks(self.stub(script + 'echo "Unexpected analysis worker argument" >&2; exit 1'))
        packager.assert_refuses_test_hooks(self.stub(script + 'printf "Unexpected analysis worker argument\\r\\n" >&2; exit 1'))
        cases = {
            "exit 0": "exited successfully",
            'echo "Unexpected analysis worker argument" >&2; exit 0': "exited successfully",
            'echo "Error: Unexpected analysis worker argument" >&2; exit 1': "without the refusal",
            'echo "Unexpected analysis worker argument"; exit 1': "without the refusal",
            'echo "Cannot raise the address-space limit" >&2; exit 1': "without the refusal",
            'echo "Unexpected analysis worker argument" >&2; kill -KILL $$': "signal 9",
        }
        for body, reason in cases.items():
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, f"Staged probe stub .*{reason}"):
                packager.assert_refuses_test_hooks(self.stub(script + body))

    def test_refusal_probe_fails_on_timeout_or_start_failure(self):
        timeout = packager.HOOK_PROBE_TIMEOUT
        packager.HOOK_PROBE_TIMEOUT = 0.5
        self.addCleanup(setattr, packager, "HOOK_PROBE_TIMEOUT", timeout)
        with self.assertRaisesRegex(ValueError, "did not refuse .* within"):
            packager.assert_refuses_test_hooks(self.stub("exec sleep 30"))
        with self.assertRaisesRegex(ValueError, "could not run the test-hook probe"):
            packager.assert_refuses_test_hooks(Path(self.temporary.name) / "missing")

    def test_target_root_prefers_argument_then_environment_then_metadata(self):
        self.assertEqual(packager.target_root("/a", "/b", "/c"), Path("/a"))
        self.assertEqual(packager.target_root(None, "/b", "/c"), Path("/b"))
        self.assertEqual(packager.target_root("", "", "/c"), Path("/c"))
        # Relative overrides follow Cargo: the current directory, not the repository.
        previous = os.getcwd()
        os.chdir(self.temporary.name)
        try:
            self.assertEqual(packager.target_root(None, "relative", "/c"),
                             Path(os.path.abspath("relative")))
            self.assertEqual(packager.target_root("relative", None, "/c"),
                             Path(os.path.abspath("relative")))
        finally:
            os.chdir(previous)
        self.assertNotEqual(Path(self.temporary.name).resolve(), packager.ROOT.resolve())

    def test_release_pair_comes_from_one_layout(self):
        host = self.root / "release"
        native = self.root / packager.TARGET / "release"
        with self.assertRaisesRegex(ValueError, "No complete release pair"):
            packager.select_release(self.root, None)
        self.pair(native, ["ghidra-rust"])
        self.pair(host)
        # A partial native pair is never combined with the host pair.
        self.assertEqual(packager.select_release(self.root, None), host)
        with self.assertRaisesRegex(ValueError, "missing: .*ghidra-rust-headless"):
            packager.select_release(self.root, packager.TARGET)
        self.pair(native)
        with self.assertRaisesRegex(ValueError, "Both .* hold a release pair"):
            packager.select_release(self.root, None)
        self.assertEqual(packager.select_release(self.root, "host"), host)
        self.assertEqual(packager.select_release(self.root, packager.TARGET), native)
        (host / "ghidra-rust-headless").unlink()
        self.assertEqual(packager.select_release(self.root, None), native)
        with self.assertRaisesRegex(ValueError, "Unsupported packaging target"):
            packager.select_release(self.root, "aarch64-unknown-linux-gnu")

    def test_cargo_artifacts_select_the_built_pair(self):
        def artifact(name, path, manifest=packager.ROOT / "Cargo.toml", kind="bin"):
            return json.dumps({"reason": "compiler-artifact", "manifest_path": str(manifest),
                               "target": {"kind": [kind], "name": name}, "executable": str(path)})
        native = self.root / packager.TARGET / "release"
        messages = "\n".join([
            json.dumps({"reason": "build-script-executed"}),
            artifact("ghidra-rust", self.root / "elsewhere/ghidra-rust", manifest=Path("/other/Cargo.toml")),
            artifact("ghidra-rust", native / "ghidra-rust"),
            artifact("ghidra-rust-headless", native / "ghidra-rust-headless"),
            json.dumps({"reason": "build-finished", "success": True}),
        ])
        self.assertEqual(packager.select_from_artifacts(messages), (self.root, packager.TARGET))
        host = self.root / "release"
        flat = artifact("ghidra-rust", host / "ghidra-rust") + "\n" + artifact(
            "ghidra-rust-headless", host / "ghidra-rust-headless")
        self.assertEqual(packager.select_from_artifacts(flat), (self.root, "host"))
        mixed = artifact("ghidra-rust", host / "ghidra-rust") + "\n" + artifact(
            "ghidra-rust-headless", native / "ghidra-rust-headless")
        with self.assertRaisesRegex(ValueError, "different directories"):
            packager.select_from_artifacts(mixed)
        with self.assertRaisesRegex(ValueError, "did not report .*ghidra-rust-headless"):
            packager.select_from_artifacts(artifact("ghidra-rust", host / "ghidra-rust"))


# Opt-in: directories holding real release pairs built with and without
# `--features test-hooks`. The pairs are copied into private roots.
HOOKED_RELEASE = os.environ.get("GHIDRA_RUST_TEST_HOOKED_RELEASE")
CLEAN_RELEASE = os.environ.get("GHIDRA_RUST_TEST_CLEAN_RELEASE")


@unittest.skipUnless(HOOKED_RELEASE and CLEAN_RELEASE and sys.platform == "linux",
                     "set GHIDRA_RUST_TEST_HOOKED_RELEASE and GHIDRA_RUST_TEST_CLEAN_RELEASE")
class LinuxPackagingGateTests(unittest.TestCase):
    """Runs the real packager on real release pairs in private roots whose
    paths contain spaces and non-ASCII characters."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="package gäte ")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.hooked = Path(HOOKED_RELEASE)
        self.clean = Path(CLEAN_RELEASE)

    def place(self, root, layout, desktop, headless):
        release = root / "release" if layout == "host" else root / packager.TARGET / "release"
        release.mkdir(parents=True, exist_ok=True)
        for source, name in ((desktop, "ghidra-rust"), (headless, "ghidra-rust-headless")):
            shutil.copy2(source / name, release / name)
        return root

    def package(self, *arguments, env=None):
        environment = {k: v for k, v in os.environ.items()
                       if k not in ("CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_BUILD_TARGET_DIR")}
        environment.update(env or {})
        return subprocess.run([sys.executable, str(SCRIPTS / "package-linux.py"), *arguments],
                              cwd=self.base, env=environment, capture_output=True, text=True)

    def public(self, root):
        dist = root / "dist"
        return {p.name: p.read_bytes() for p in dist.iterdir()} if dist.is_dir() else {}

    def assert_published(self, root):
        dist = root / "dist"
        names = sorted(p.name for p in dist.iterdir())
        self.assertFalse([n for n in names if n.startswith(".package-")], names)
        [archive] = [dist / n for n in names if n.endswith(".tar.gz")]
        standalone = dist / archive.name[:-len(".tar.gz")]
        for file in (archive, standalone):
            digest = hashlib.sha256(file.read_bytes()).hexdigest()
            self.assertEqual((dist / (file.name + ".sha256")).read_text(), f"{digest}  {file.name}\n")
        with tarfile.open(archive) as members:
            desktop = members.extractfile(f"{standalone.name}/ghidra-rust").read()
            members.extractfile(f"{standalone.name}/ghidra-rust-headless").read()
        self.assertEqual(hashlib.sha256(desktop).digest(), hashlib.sha256(standalone.read_bytes()).digest())

    def test_hooked_members_fail_on_the_named_staged_executable(self):
        root = self.base / "röot one"
        self.place(root, "host", self.clean, self.clean)
        self.assertEqual(self.package("--target-directory", str(root)).returncode, 0)
        previous = self.public(root)
        for desktop, headless, named in ((self.hooked, self.hooked, "ghidra-rust"),
                                         (self.clean, self.hooked, "ghidra-rust-headless"),
                                         (self.hooked, self.clean, "ghidra-rust")):
            with self.subTest(desktop=desktop.name, headless=headless.name):
                self.place(root, "host", desktop, headless)
                result = self.package("--target-directory", str(root))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"Staged {named} failed the test-hook refusal gate", result.stderr)
                self.assertEqual(self.public(root), previous)

    def test_clean_pair_is_packaged_from_the_requested_root_and_layout(self):
        root = self.base / "röot two"
        decoy = self.base / "decöy"
        self.place(root, packager.TARGET, self.clean, self.clean)
        # Decoys: a hooked pair in the other layout and under the environment.
        self.place(root, "host", self.hooked, self.hooked)
        self.place(decoy, "host", self.hooked, self.hooked)
        ambiguous = self.package("--target-directory", str(root))
        self.assertNotEqual(ambiguous.returncode, 0)
        self.assertIn("hold a release pair", ambiguous.stderr)
        result = self.package("--target-directory", str(root), "--target", packager.TARGET,
                              env={"CARGO_TARGET_DIR": str(decoy), "CARGO_BUILD_TARGET": "host"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_published(root)
        self.assertFalse((decoy / "dist").exists())
        # The environment, then Cargo config, select the root when no argument does.
        for env in ({"CARGO_TARGET_DIR": str(root), "CARGO_BUILD_TARGET": packager.TARGET},
                    {"CARGO_BUILD_TARGET_DIR": str(root), "CARGO_BUILD_TARGET": packager.TARGET}):
            with self.subTest(env=sorted(env)):
                result = self.package(env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assert_published(root)

    def test_missing_second_member_fails_without_combining_layouts(self):
        root = self.base / "röot three"
        self.place(root, "host", self.clean, self.clean)
        native = root / packager.TARGET / "release"
        native.mkdir(parents=True)
        shutil.copy2(self.clean / "ghidra-rust", native / "ghidra-rust")
        result = self.package("--target-directory", str(root), "--target", packager.TARGET)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing", result.stderr)
        self.assertFalse((root / "dist").exists() and any((root / "dist").iterdir()))


if __name__ == "__main__":
    unittest.main()
