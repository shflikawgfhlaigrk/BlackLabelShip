"""Selection uses the newest real attempt and a bounded elapsed-time window."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from tools.select_snapshot_attempt import MAX_AGE_SECONDS, select


class SnapshotAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 10, 23, 0, 15, tzinfo=timezone.utc)

    def attempt(self, started, status="complete", pid=1):
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        folder = self.root / started.strftime("%Y-%m-%d")
        folder.mkdir(exist_ok=True)
        manifest = folder / ("SHA256SUMS." + stamp)
        manifest.write_text("synthetic manifest checked by the uploader\n")
        identity = stamp + "-" + str(pid)
        record = {
            "schema": "blacklabel.backup-attempt.v1",
            "snapshot_stamp": stamp,
            "attempt_id": identity,
            "started_at": started.isoformat(),
            "status": status,
            "snapshot_dir": str(folder),
            "exit_code": 0 if status == "complete" else 1,
            "snapshot_complete": status == "complete",
            "checksum_manifest": str(manifest),
        }
        path = folder / ("ATTEMPT." + identity + ".json")
        path.write_text(json.dumps(record))
        return path, manifest, record

    def test_fresh_completed_attempt_crossing_utc_midnight_is_ready(self):
        _, manifest, _ = self.attempt(self.now - timedelta(minutes=30))
        self.assertEqual(select(self.root, self.now),
                         ("ready", str(manifest.parent), manifest.name))

    def test_newer_failure_never_falls_back_to_older_success(self):
        self.attempt(self.now - timedelta(minutes=30))
        self.attempt(self.now - timedelta(minutes=5), "failed")
        self.assertEqual(select(self.root, self.now), ("failed", "", ""))

    def test_newer_running_attempt_waits_instead_of_reusing_success(self):
        self.attempt(self.now - timedelta(minutes=30))
        self.attempt(self.now - timedelta(minutes=5), "running")
        self.assertEqual(select(self.root, self.now), ("wait", "", ""))

    def test_expired_and_future_attempts_fail(self):
        for delta in [timedelta(seconds=MAX_AGE_SECONDS + 1), timedelta(minutes=-6)]:
            with self.subTest(delta=delta):
                with tempfile.TemporaryDirectory() as folder:
                    prior = self.root
                    self.root = Path(folder)
                    self.attempt(self.now - delta)
                    self.assertEqual(select(self.root, self.now), ("failed", "", ""))
                    self.root = prior

    def test_missing_manifest_fails(self):
        _, manifest, _ = self.attempt(self.now - timedelta(minutes=5))
        manifest.unlink()
        self.assertEqual(select(self.root, self.now), ("failed", "", ""))

    def test_malformed_newest_attempt_never_falls_back(self):
        self.attempt(self.now - timedelta(minutes=30))
        path, _, _ = self.attempt(self.now - timedelta(minutes=5))
        path.write_text("{")
        self.assertEqual(select(self.root, self.now), ("failed", "", ""))

    def test_empty_root_waits_and_symlink_root_fails(self):
        self.assertEqual(select(self.root, self.now), ("wait", "", ""))
        link = self.root / "linked-root"
        link.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(select(link, self.now), ("failed", "", ""))


if __name__ == "__main__":
    unittest.main()
