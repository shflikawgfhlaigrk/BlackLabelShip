"""Exercise the actual backup shell entrypoint with synthetic files and PG tools."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

TEAM = Path.home() / "BlackLabel-Team"
SCRIPT = TEAM / "bin/backup.sh"


class SourceBackupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.team = self.root / "team"
        self.content = self.root / "content"
        self.backups = self.root / "backups"
        self.pg = self.root / "pg"
        for path in [self.team / "bin", self.team / "STATE", self.team / "AGENTS",
                     self.content / "BlackLabel-Premium-Design", self.content / "BlackLabelShip", self.pg]:
            path.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(TEAM / "bin/backup-excludes.txt", self.team / "bin/backup-excludes.txt")
        for name in ["CHARTER.md", "ROSTER.md", "LOOP.md", "STATE/memory.md", "AGENTS/worker.md"]:
            (self.team / name).write_text("Ordinary business data to preserve: " + name)
        (self.content / "BlackLabelShip/ships.jsonl").write_text('{"synthetic":true}\n')
        (self.content / "BlackLabel-Premium-Design/standard.md").write_text("preserve design data")
        nested = self.team / "STATE/ace-live-routing/fresh-install-backup/files/Users/example/Library/Application Support/BlackLabel/Codex"
        nested.mkdir(parents=True)
        (nested / "auth.json").write_text('{"access_token":"synthetic-login-must-be-excluded"}')
        (nested / "auth.json.bak").write_text("synthetic-old-login-must-be-excluded")
        (nested / "settings.json").write_text('{"business_setting":"preserve"}')
        self.excluded = ["STATE/.env", "STATE/cloudflare.token", "STATE/backup-key.txt", "STATE/id_ed25519",
                         "STATE/.wrangler/config/default.toml", "STATE/subdir/credentials.json",
                         "STATE/old-app/credentials.v1.key", "STATE/old-app/gold-context-v1.key"]
        for name in self.excluded:
            path = self.team / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic-credential-to-exclude")
        (self.pg / "pg_dump").write_text('''#!/usr/bin/env python3
import pathlib,sys
if pathlib.Path(__file__).with_name('fail-dump').exists(): sys.exit(23)
pathlib.Path(sys.argv[sys.argv.index('-f')+1]).write_bytes(b'SYNTHETIC_PG_DUMP')
''')
        (self.pg / "pg_restore").write_text('''#!/usr/bin/env python3
import pathlib,sys
sys.exit(0 if pathlib.Path(sys.argv[-1]).read_bytes()==b'SYNTHETIC_PG_DUMP' else 24)
''')
        for binary in self.pg.iterdir():
            binary.chmod(0o700)
        self.env = {**os.environ, "BACKUP_TEAM_ROOT": str(self.team), "BACKUP_CONTENT_ROOT": str(self.content),
                    "BACKUPS_ROOT": str(self.backups), "BACKUP_PGBIN": str(self.pg)}

    def tearDown(self):
        self.temp.cleanup()

    def run_backup(self):
        return subprocess.run(["/bin/bash", str(SCRIPT)], env=self.env, capture_output=True, text=True, timeout=20)

    def test_backup_excludes_nested_current_and_old_credentials(self):
        result = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        archive = next(self.backups.glob("*/*.tar.gz"))
        with tarfile.open(archive) as source:
            names = source.getnames()
            contents = b"".join(source.extractfile(member).read() for member in source if member.isfile())
        self.assertNotIn(b"synthetic-login", contents)
        self.assertNotIn(b"synthetic-old-login", contents)
        self.assertNotIn(b"synthetic-credential", contents)
        for name in self.excluded:
            self.assertNotIn(name, names)
        self.assertTrue(any(name.endswith("settings.json") for name in names))
        for name in ["STATE/memory.md", "ships.jsonl", "AGENTS/worker.md", "BlackLabel-Premium-Design/standard.md"]:
            self.assertIn(name, names)
        self.assertTrue((self.team / self.excluded[0]).exists())
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(archive.parent.stat().st_mode & 0o777, 0o700)
        manifests = list(self.backups.glob("*/SHA256SUMS.*"))
        self.assertEqual(len(manifests), 1)
        rows = manifests[0].read_text().splitlines()
        self.assertEqual(len(rows), 3)
        for row in rows:
            expected, name = row.split(None, 1)
            self.assertEqual(hashlib.sha256((manifests[0].parent / name).read_bytes()).hexdigest(), expected)
        self.assertFalse(list(self.backups.glob("*/.SHA256SUMS.*.partial")))

    def test_database_failure_never_publishes_completion(self):
        (self.pg / "fail-dump").touch()
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(list(self.backups.glob("*/SHA256SUMS.*")))

    def test_missing_exclusion_policy_fails_closed(self):
        (self.team / "bin/backup-excludes.txt").unlink()
        result = self.run_backup()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backups.exists())

    def run_offsite(self, key_exists=True):
        key = self.root / "synthetic-key"
        if key_exists:
            key.write_text("synthetic-offsite-test-key-12345678\n")
            key.chmod(0o600)
        env = {**self.env, "BACKUP_KEYFILE": str(key), "SNAP_WAIT_SECS": "0",
               "SNAP_STATE_DIR": str(self.root / "offsite-state"), "OFFSITE_LOG": str(self.root / "offsite.log"),
               "BACKUP_LOCAL_TEST_STORE": str(self.root / "object-store")}
        return subprocess.run(["/bin/bash", str(Path(__file__).parent / "backup_offsite_snapshot.sh")],
                              env=env, capture_output=True, text=True, timeout=60)

    def test_shell_to_encrypted_backup_integration(self):
        self.assertEqual(self.run_backup().returncode, 0)
        result = self.run_offsite()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OFFLINE TEST COMPLETE", result.stdout)
        self.assertNotIn("OFF-SITE COMPLETE", result.stdout)
        receipt = json.loads((self.root / "offsite-state/last-upload.json").read_text())
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(len(receipt["files"]), 3)
        self.assertTrue((self.root / "object-store/encrypted-v1/LATEST.gpg").exists())

    def test_shell_missing_key_fails_without_plaintext_fallback(self):
        self.assertEqual(self.run_backup().returncode, 0)
        result = self.run_offsite(key_exists=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FATAL", result.stdout)
        self.assertNotIn("OFF-SITE COMPLETE", result.stdout)
        self.assertFalse(list((self.root / "object-store").rglob("*.gpg")))

    def test_shell_incomplete_manifest_fails_before_upload(self):
        self.assertEqual(self.run_backup().returncode, 0)
        manifest = next(self.backups.glob("*/SHA256SUMS.*"))
        manifest.write_text(manifest.read_text().splitlines()[0] + "\n")
        result = self.run_offsite()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FATAL", result.stdout)
        self.assertFalse((self.root / "object-store").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
