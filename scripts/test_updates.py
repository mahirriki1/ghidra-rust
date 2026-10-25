"""Offline regression coverage for the production OpenSSL update-signing format."""
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

SCRIPTS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("sign_updates", SCRIPTS / "sign-updates.py")
updates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updates)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for release signing")
class UpdateSigningTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.txt"
        updates.initialize(self.private, self.public)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.version = "0.0.9"
        prefix = f"ghidra-rust-{self.version}"
        (self.assets / f"{prefix}-linux-x64").write_bytes(b"Linux executable")
        (self.assets / f"{prefix}-windows-x64.exe").write_bytes(b"Windows executable")
        files = {"LICENSE": b"Application license", "NOTICE": b"Engine attribution",
                 "THIRD-PARTY.json": b'{"packages":[]}',
                 "third-party/font/embedded/OFL.txt": b"Embedded font license",
                 "third-party/dependency/LICENSE": b"Dependency license",
                 "README.md": b"Not a legal notice"}
        with tarfile.open(self.assets / f"{prefix}-linux-x64.tar.gz", "w:gz") as archive:
            for name, content in files.items():
                info = tarfile.TarInfo(f"{prefix}-linux-x64/{name}")
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        with zipfile.ZipFile(self.assets / f"{prefix}-windows-x64.zip", "w") as archive:
            for name, content in files.items():
                archive.writestr(f"{prefix}-windows-x64/{name}", content)

    def test_private_key_is_private_and_existing_trust_roots_cannot_be_overwritten(self):
        self.assertEqual(len(base64.b64decode(self.public.read_text())), 32)
        if os.name != "nt":
            self.assertEqual(self.private.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            updates.initialize(self.private, self.public)

    def test_manifest_signature_digests_and_complete_notices_round_trip(self):
        updates.sign(self.assets, self.version, self.private, self.public)
        manifest = json.loads((self.assets / "update.json").read_bytes())
        self.assertEqual(manifest["repository"], "mahirriki1/ghidra-rust")
        self.assertEqual(manifest["version"], self.version)
        self.assertEqual(set(manifest["binaries"]), {"linux-x64", "windows-x64"})
        for record in [*manifest["binaries"].values(), manifest["notices"]]:
            content = (self.assets / record["name"]).read_bytes()
            self.assertEqual(record["size"], len(content))
            self.assertEqual(record["sha256"], hashlib.sha256(content).hexdigest())
        notices = (self.assets / manifest["notices"]["name"]).read_text()
        self.assertEqual(notices.count("Embedded font license"), 2)
        self.assertEqual(notices.count("Dependency license"), 2)
        self.assertIn("Engine attribution", notices)
        self.assertNotIn("Not a legal notice", notices)
        public_pem = self.root / "public.pem"
        public_pem.write_bytes(updates.openssl("pkey", "-in", str(self.private), "-pubout"))
        args = ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(public_pem),
                "-in", str(self.assets / "update.json"), "-sigfile", str(self.assets / "update.json.sig")]
        self.assertEqual(len((self.assets / "update.json.sig").read_bytes()), 64)
        self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
        with (self.assets / "update.json").open("ab") as stream:
            stream.write(b" ")
        self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)

    def test_signing_fails_closed_for_an_unrelated_key_and_oversized_notices(self):
        other_private = self.root / "other-private.pem"
        other_public = self.root / "other-public.txt"
        updates.initialize(other_private, other_public)
        with self.assertRaisesRegex(ValueError, "does not match"):
            updates.sign(self.assets, self.version, other_private, self.public)
        budget = updates.MAX_NOTICES
        try:
            updates.MAX_NOTICES = 4
            with self.assertRaisesRegex(ValueError, "budget"):
                updates.sign(self.assets, self.version, self.private, self.public)
        finally:
            updates.MAX_NOTICES = budget


if __name__ == "__main__":
    unittest.main()
