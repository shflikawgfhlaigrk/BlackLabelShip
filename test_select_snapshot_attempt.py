from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from tools import select_snapshot_attempt as selector


class SelectSnapshotAttemptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = datetime(2026, 9, 28, 5, 30, tzinfo=timezone.utc)

    def attempt(self, started: datetime, status: str = "complete", *, suffix: str = "123") -> Path:
        stamp = started.strftime("%Y%m%dT%H%M%SZ")
        directory = self.root / started.strftime("%Y-%m-%d")
        directory.mkdir(exist_ok=True)
        manifest = directory / f"SHA256SUMS.{stamp}"
        manifest.write_text("synthetic complete manifest\n")
        attempt_id = f"{stamp}-{suffix}"
        receipt = directory / f"ATTEMPT.{attempt_id}.json"
        receipt.write_text(json.dumps({
            "schema": "blacklabel.backup-attempt.v1",
            "attempt_id": attempt_id,
            "started_at": started.isoformat(),
            "status": status,
            "snapshot_stamp": stamp,
            "snapshot_dir": str(directory),
            "snapshot_complete": status == "complete",
            "exit_code": 0 if status == "complete" else 1,
            "checksum_manifest": str(manifest) if status == "complete" else None,
        }))
        return receipt

    def test_fresh_complete_receipt_selects_exact_manifest(self):
        receipt = self.attempt(self.now - timedelta(minutes=15))
        self.assertEqual(selector.select(self.root, self.now),
                         ("ready", str(receipt.parent), "SHA256SUMS.20260928T051500Z"))

    def test_running_waits_and_failure_overrides_older_success(self):
        self.attempt(self.now - timedelta(minutes=30))
        self.attempt(self.now - timedelta(minutes=15), "running")
        self.assertEqual(selector.select(self.root, self.now)[0], "wait")
        self.attempt(self.now - timedelta(minutes=5), "failed")
        self.assertEqual(selector.select(self.root, self.now)[0], "failed")

    def test_yesterday_or_stale_complete_does_not_satisfy_today(self):
        self.attempt(self.now - timedelta(days=1))
        self.assertEqual(selector.select(self.root, self.now)[0], "failed")

    def test_mismatched_receipt_and_manifest_fail(self):
        receipt = self.attempt(self.now)
        value = json.loads(receipt.read_text())
        value["checksum_manifest"] = str(receipt.parent / "SHA256SUMS.wrong")
        receipt.write_text(json.dumps(value))
        self.assertEqual(selector.select(self.root, self.now)[0], "failed")

    def test_no_attempt_waits(self):
        self.assertEqual(selector.select(self.root, self.now)[0], "wait")

    def test_producer_second_boundary_is_allowed(self):
        receipt = self.attempt(self.now - timedelta(minutes=15))
        value = json.loads(receipt.read_text())
        value["started_at"] = (self.now - timedelta(minutes=15) + timedelta(seconds=1)).isoformat()
        receipt.write_text(json.dumps(value))
        self.assertEqual(selector.select(self.root, self.now)[0], "ready")


if __name__ == "__main__":
    unittest.main()
