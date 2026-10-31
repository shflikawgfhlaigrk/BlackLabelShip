"""Recovery must never move backwards when an older uploader finishes late."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import Mock
import contextlib
import urllib.error

from tools import encrypted_snapshot as backup
from tools import source_rescue_offsite as rescue
from tools import select_snapshot_attempt as selector


class LatestPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = backup.private_dir(self.root / "work")
        self.key = self.root / "key"
        self.key.write_text("synthetic-local-backup-regression-key\n")
        self.key.chmod(0o600)
        self.crypto = backup.GPG(self.key, self.work)
        self.store = backup.LocalStore(self.root / "remote")

    def snapshot(self, stamp):
        directory = self.root / datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").strftime("%Y-%m-%d")
        directory.mkdir(exist_ok=True)
        names = [f"blacklabel-{stamp}.dump", f"utah-{stamp}.dump", f"brain-state-{stamp}.tar.gz"]
        for name in names:
            (directory / name).write_bytes(name.encode())
        (directory / f"SHA256SUMS.{stamp}").write_text("".join(
            f"{backup.digest(directory / name)}  ./{name}\n" for name in names))
        return backup.read_snapshot(directory, f"SHA256SUMS.{stamp}")

    def upload(self, snapshot, name):
        return backup.upload(snapshot, self.store, self.crypto, self.work,
                             self.root / (name + ".json"), chunk_bytes=4096)

    def test_older_upload_cannot_replace_newer_or_fail_on_completed_resume(self):
        older = self.snapshot("20261030T230000Z")
        newer = self.snapshot("20261031T010000Z")
        new = self.upload(newer, "new")
        old = self.upload(older, "old")
        self.assertEqual(backup.load_manifest(self.store, self.crypto, self.work)["prefix"], new["prefix"])
        self.assertFalse(old["latest_published"])
        self.assertEqual(old["latest_status"], "retained_newer")
        again = self.upload(older, "old")
        self.assertEqual(again["prefix"], old["prefix"])
        self.assertEqual(again["latest_prefix"], new["prefix"])

    def test_interrupted_old_pointer_resume_keeps_newer_and_immutable_manifest(self):
        older = self.snapshot("20261030T230000Z")
        newer = self.snapshot("20261031T010000Z")
        original = self.store.put
        def fail_pointer(key, path):
            if key == "encrypted-v1/LATEST.gpg":
                raise backup.BackupError("injected pointer failure")
            return original(key, path)
        with patch.object(self.store, "put", side_effect=fail_pointer):
            with self.assertRaises(backup.BackupError):
                self.upload(older, "old")
        state = json.loads((self.root / "old.json").read_text())
        manifest = self.store.path(state["manifest"]["key"])
        before = backup.digest(manifest)
        new = self.upload(newer, "new")
        old = self.upload(older, "old")
        self.assertEqual(backup.digest(manifest), before)
        self.assertEqual(old["latest_prefix"], new["prefix"])
        self.assertFalse(old["latest_published"])

    def test_corrupt_existing_pointer_fails_closed(self):
        self.store.path("encrypted-v1").mkdir()
        pointer = self.store.path("encrypted-v1/LATEST.gpg")
        pointer.write_bytes(b"not authenticated ciphertext")
        with self.assertRaises(backup.BackupError):
            self.upload(self.snapshot("20261031T010000Z"), "new")
        self.assertEqual(pointer.read_bytes(), b"not authenticated ciphertext")

    def test_competing_newer_writer_wins_between_read_and_conditional_write(self):
        seed = self.upload(self.snapshot("20261030T220000Z"), "seed")
        key = "encrypted-v1/LATEST.gpg"
        seed_pointer = self.store.path(key).read_bytes()
        newer = self.upload(self.snapshot("20261031T010000Z"), "newer")
        new_pointer = self.store.path(key).read_bytes()
        self.store.path(key).write_bytes(seed_pointer)
        original = self.store.put_if_version
        conflicts = []
        def competing_write(pointer_key, path, version):
            if not conflicts:
                self.store.path(key).write_bytes(new_pointer)
                conflicts.append(True)
            return original(pointer_key, path, version)
        with patch.object(self.store, "put_if_version", side_effect=competing_write):
            older = self.upload(self.snapshot("20261030T230000Z"), "older")
        self.assertEqual(older["latest_prefix"], newer["prefix"])
        self.assertEqual(older["latest_status"], "retained_newer")
        self.assertEqual(self.store.path(key).read_bytes(), new_pointer)
        self.assertNotEqual(seed["prefix"], newer["prefix"])

    def test_local_compare_and_swap_rejects_stale_and_create_only_versions(self):
        key = "fixture.gpg"
        first = self.root / "first"
        first.write_bytes(b"cipher-one")
        second = self.root / "second"
        second.write_bytes(b"cipher-two")
        self.assertTrue(self.store.put_if_version(key, first, None))
        version = self.store.get(key, self.root / "read", 100)
        self.assertFalse(self.store.put_if_version(key, second, None))
        self.assertTrue(self.store.put_if_version(key, second, version))
        self.assertFalse(self.store.put_if_version(key, first, version))
        self.assertEqual(self.store.path(key).read_bytes(), b"cipher-two")

    def rescue_snapshot(self, date):
        directory = self.root / ("source-rescue-" + date)
        directory.mkdir()
        names = sorted(rescue.NAMES - {"SHA256SUMS", "RESCUE-RECEIPT.json"})
        hashes = {}
        for name in names:
            (directory / name).write_bytes((date + name).encode())
            hashes[name] = backup.digest(directory / name)
        (directory / "SHA256SUMS").write_text("".join(f"{hashes[name]}  {name}\n" for name in names))
        (directory / "RESCUE-RECEIPT.json").write_text(json.dumps({"source_repo":"BlackLabel-Team", "artifacts_sha256":hashes}))
        return rescue.inspect(directory)

    def test_source_rescue_older_resume_retains_newer(self):
        newer = self.rescue_snapshot("2026-10-31")
        older = self.rescue_snapshot("2026-10-30")
        state = backup.private_dir(self.root / "rescue-state")
        new = rescue.upload(newer, self.store, self.crypto, self.work, state, 4096)
        old = rescue.upload(older, self.store, self.crypto, self.work, state, 4096)
        self.assertEqual(rescue.load_manifest(self.store, self.crypto, self.work)["prefix"], new["prefix"])
        self.assertEqual(old["latest_status"], "retained_newer")
        self.assertFalse(old["latest_published"])
        self.assertEqual(rescue.upload(older, self.store, self.crypto, self.work, state, 4096)["prefix"], old["prefix"])

    def test_r2_condition_headers_and_conflict_never_use_blind_put(self):
        credential = self.root / "credential"
        credential.write_text("synthetic-token")
        credential.chmod(0o600)
        store = backup.R2Store("a" * 32, "test-bucket", credential)
        cipher = self.root / "cipher"
        cipher.write_bytes(b"synthetic-ciphertext")
        conditions = []
        @contextlib.contextmanager
        def request(key, method, source=None, condition=None):
            conditions.append(condition)
            response = Mock()
            response.read.return_value = b'{"success":true}'
            yield response
        with patch.object(store, "request", side_effect=request), patch.object(store, "put") as blind:
            self.assertTrue(store.put_if_version("key.gpg", cipher, None))
            self.assertTrue(store.put_if_version("key.gpg", cipher, '"version-one"'))
            blind.assert_not_called()
        self.assertEqual(conditions, [{"If-None-Match":"*"}, {"If-Match":'"version-one"'}])
        error = urllib.error.HTTPError("https://example.invalid", 412, "conflict", {}, None)
        with patch.object(store, "request", side_effect=error), patch.object(store, "put") as blind:
            self.assertFalse(store.put_if_version("key.gpg", cipher, '"version-one"'))
            blind.assert_not_called()

    def test_r2_read_access_error_is_not_missing(self):
        credential = self.root / "credential"
        credential.write_text("synthetic-token")
        credential.chmod(0o600)
        store = backup.R2Store("a" * 32, "test-bucket", credential)
        for status, error_type in ((403, backup.BackupError), (404, FileNotFoundError)):
            with self.subTest(status=status), patch.object(store, "request", side_effect=
                    urllib.error.HTTPError("https://example.invalid", status, "failure", {}, None)):
                with self.assertRaises(error_type):
                    store.get("key.gpg", self.root / "read", 100)


class MidnightSelectionTests(unittest.TestCase):
    def test_fresh_previous_day_is_ready(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            now = datetime(2026, 10, 31, 0, 10, tzinfo=timezone.utc)
            started = now - timedelta(minutes=20)
            stamp = started.strftime("%Y%m%dT%H%M%SZ")
            directory = root / started.strftime("%Y-%m-%d")
            directory.mkdir()
            manifest = directory / ("SHA256SUMS." + stamp)
            manifest.write_text("synthetic manifest\n")
            attempt = stamp + "-1"
            (directory / ("ATTEMPT." + attempt + ".json")).write_text(json.dumps({
                "schema":"blacklabel.backup-attempt.v1", "attempt_id":attempt,
                "snapshot_stamp":stamp, "started_at":started.isoformat(),
                "snapshot_dir":str(directory), "checksum_manifest":str(manifest),
                "status":"complete", "exit_code":0, "snapshot_complete":True}))
            self.assertEqual(selector.select(root, now), ("ready", str(directory), manifest.name))


if __name__ == "__main__":
    unittest.main()
