"""Offline checks for the scheduled off-site wrapper's overlap and cleanup gates."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parent / "backup_offsite.sh"


class OffsiteSchedulerGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fake_python = self.bin / "fake-python"
        self.key = self.root / "secrets" / "backup-key.txt"
        self.key.parent.mkdir()
        self.log = self.root / "offsite.log"
        self.tmp = self.root / "tmp"
        self.tmp.mkdir()
        self.deploy = self.root / "deploy"
        self.deploy.mkdir()
        self.content = self.root / "content"
        (self.content / "BlackLabelShip").mkdir(parents=True)
        (self.content / "BlackLabelShip" / "ships.jsonl").write_text("synthetic ledger\n")
        (self.content / ".utah" / "secrets").mkdir(parents=True)
        (self.content / ".utah" / "secrets" / "synthetic.txt").write_text("synthetic\n")

    def run_wrapper(self):
        env = {**os.environ, "BACKUP_PYTHON": str(self.fake_python),
               "BACKUP_KEYFILE": str(self.key), "OFFSITE_LOG": str(self.log),
               "BACKUP_CONTENT_ROOT": str(self.content), "OFFSITE_DEPLOY_ROOT": str(self.deploy),
               "SNAP_STATE_DIR": str(self.root / "state"), "TMPDIR": str(self.tmp),
               "PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}
        return subprocess.run(["/bin/zsh", str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30)

    def test_busy_preflight_stops_before_plaintext_staging(self):
        self.fake_python.write_text("#!/bin/sh\nexit 1\n")
        self.fake_python.chmod(0o700)
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("preflight not idle", self.log.read_text())
        self.assertFalse(self.key.exists())
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_failed_upload_disposes_staged_plaintext(self):
        self.fake_python.write_text("#!/bin/sh\nexit 0\n")
        self.fake_python.chmod(0o700)
        fake_npx = self.bin / "npx"
        fake_npx.write_text("#!/bin/sh\nexit 1\n")
        fake_npx.chmod(0o700)
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 1)
        self.assertIn("R2 upload failed", self.log.read_text())
        self.assertEqual(list(self.tmp.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
