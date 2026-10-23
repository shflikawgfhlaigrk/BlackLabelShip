from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import encrypted_snapshot as base
from tools import source_rescue_offsite as rescue


class SourceRescueOffsiteTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.source = self.root / "source-rescue-2026-09-28"
        self.source.mkdir()
        data = {
            "team-local-257-commits.bundle": b"bundle-data\n",
            "team-working-tree.patch.gz": b"patch-data\n",
            "team-untracked.tar.gz": b"untracked-data\n",
        }
        hashes = {}
        for name, body in data.items():
            (self.source / name).write_bytes(body)
            hashes[name] = hashlib.sha256(body).hexdigest()
        (self.source / "SHA256SUMS").write_text(
            "".join(f"{hashes[name]}  {name}\n" for name in data)
        )
        (self.source / "RESCUE-RECEIPT.json").write_text(json.dumps({
            "source_repo": "BlackLabel-Team", "artifacts_sha256": hashes,
        }))
        self.key = self.root / "key.txt"
        self.key.write_text("local-test-passphrase-that-is-not-production\n")
        self.key.chmod(0o600)
        self.state = base.private_dir(self.root / "state")
        self.store = base.LocalStore(self.root / "remote")

    def test_local_encrypted_round_trip_and_no_overwrite(self):
        snapshot = rescue.inspect(self.source)
        work = base.private_dir(self.root / "work")
        crypto = base.GPG(self.key, work)
        report = rescue.upload(snapshot, self.store, crypto, work, self.state, 1024 * 1024)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["verified_parts"], 5)
        self.assertTrue((self.root / "remote" / rescue.LATEST).exists())
        destination = self.root / "restored"
        restored = rescue.verify(self.store, crypto, work, destination=destination)
        self.assertEqual(restored["operation"], "restore")
        for name in rescue.NAMES:
            self.assertEqual((destination / name).read_bytes(), (self.source / name).read_bytes())
        with self.assertRaises(base.BackupError):
            rescue.verify(self.store, crypto, work, destination=destination)

    def test_wrong_checksum_receipt_fails_before_upload(self):
        receipt = json.loads((self.source / "RESCUE-RECEIPT.json").read_text())
        receipt["artifacts_sha256"]["team-untracked.tar.gz"] = "0" * 64
        (self.source / "RESCUE-RECEIPT.json").write_text(json.dumps(receipt))
        with self.assertRaises(base.BackupError):
            rescue.inspect(self.source)

    def test_pointer_failure_resumes_without_replacing_manifest(self):
        class FailPointerStore:
            def __init__(self, inner):
                self.inner = inner
                self.identity = inner.identity

            def put(self, key, path):
                if key == rescue.LATEST:
                    raise base.BackupError("injected pointer failure")
                return self.inner.put(key, path)

            def get(self, key, path, limit):
                return self.inner.get(key, path, limit)

        snapshot = rescue.inspect(self.source)
        work = base.private_dir(self.root / "work")
        crypto = base.GPG(self.key, work)
        with self.assertRaisesRegex(base.BackupError, "injected pointer failure"):
            rescue.upload(snapshot, FailPointerStore(self.store), crypto, work, self.state, 1024 * 1024)
        journals = list(self.state.glob("*.json"))
        self.assertEqual(len(journals), 1)
        prefix = json.loads(journals[0].read_text())["prefix"]
        manifest = self.root / "remote" / prefix / "manifest.json.gpg"
        before = base.digest(manifest)
        report = rescue.upload(snapshot, self.store, crypto, work, self.state, 1024 * 1024)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(base.digest(manifest), before)
        self.assertEqual(rescue.load_manifest(self.store, crypto, work)["prefix"], prefix)


if __name__ == "__main__":
    unittest.main()
