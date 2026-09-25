"""Real GPG, offline object-store and failure-injection backup regressions."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location("encrypted_snapshot", Path(__file__).parent / "tools/encrypted_snapshot.py")
backup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup)
STAMP = "20260911T190000Z"


class BackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        root = Path(cls.fixture.name)
        cls.key = root / "key"
        cls.key.write_text("synthetic-backup-test-passphrase-123456\n")
        cls.key.chmod(0o600)
        cls.source = root / "2026-09-11"
        cls.source.mkdir()
        cls.payloads = {f"blacklabel-{STAMP}.dump": b"test-database-one-" * 120,
                        f"brain-state-{STAMP}.tar.gz": b"test-brain-state-" * 120,
                        f"utah-{STAMP}.dump": b"test-database-two-" * 120}
        for name, data in cls.payloads.items():
            (cls.source / name).write_bytes(data)
        cls.sums = "".join(hashlib.sha256(data).hexdigest() + "  ./" + name + "\n" for name, data in cls.payloads.items())
        (cls.source / ("SHA256SUMS." + STAMP)).write_text(cls.sums)
        cls.snapshot = backup.read_snapshot(cls.source)
        work = root / "work"
        work.mkdir(mode=0o700)
        cls.crypto = backup.GPG(cls.key, work)
        cls.baseline = backup.LocalStore(root / "baseline")
        cls.result = backup.upload(cls.snapshot, cls.baseline, cls.crypto, work, root / "journal.json", chunk_bytes=1024)
        cls.prefix = cls.result["prefix"]
        cls.manifest = backup.load_manifest(cls.baseline, cls.crypto, work)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.crypto = backup.GPG(self.key, self.work)
        self.store = backup.LocalStore(self.root / "store")
        shutil.copytree(self.baseline.root, self.store.root, dirs_exist_ok=True)

    def tearDown(self):
        self.temp.cleanup()

    def first_part(self):
        return self.store.path(self.manifest["files"][0]["parts"][0]["key"])

    def changed_manifest(self, transform):
        value = copy.deepcopy(self.manifest)
        transform(value)
        cipher = self.root / "changed.gpg"
        self.crypto.encrypt(backup.encode(value), cipher)
        self.store.put(self.prefix + "/manifest.json.gpg", cipher)

    def test_roundtrip_all_three_multichunk_files(self):
        destination = self.root / "restored"
        result = backup.verify(self.store, self.crypto, self.work, destination=destination)
        self.assertEqual(result["status"], "passed")
        self.assertGreater(result["verified_parts"], 3)
        for name, expected in self.payloads.items():
            self.assertEqual((destination / name).read_bytes(), expected)
        restored_sums = (destination / ("SHA256SUMS." + STAMP)).read_text().splitlines()
        self.assertEqual(set(restored_sums), set(self.sums.splitlines()))
        self.assertEqual(destination.stat().st_mode & 0o777, 0o700)

    def test_verify_without_restoring(self):
        result = backup.verify(self.store, self.crypto, self.work, self.prefix)
        self.assertEqual(result["operation"], "verify")
        self.assertFalse(list(self.work.glob(".encrypted-restore-*")))

    def test_remote_contains_only_ciphertext(self):
        for path in self.store.root.rglob("*"):
            if path.is_file():
                self.assertEqual(path.suffix, ".gpg")
                data = path.read_bytes()
                self.assertNotIn(b"test-database-one-", data)
                self.assertNotIn(b"test-brain-state-", data)
                self.assertNotIn(self.key.read_bytes().strip(), data)

    def test_no_gpg_agent_or_persistent_plaintext_staging(self):
        self.assertFalse(list(self.work.rglob("S.gpg-agent*")))
        self.assertFalse(list(self.work.glob("*.gpg")))

    def test_wrong_key_rejects_without_destination(self):
        wrong = self.root / "wrong"
        wrong.write_text("different-synthetic-passphrase-987654\n")
        wrong.chmod(0o600)
        crypto = backup.GPG(wrong, self.work)
        destination = self.root / "restored"
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, crypto, self.work, destination=destination)
        self.assertFalse(destination.exists())

    def test_direct_gpg_tampering_rejected(self):
        cipher = self.root / "tampered.gpg"
        self.crypto.encrypt(b"sensitive-test-content" * 60, cipher)
        data = bytearray(cipher.read_bytes())
        data[-30] ^= 1
        cipher.write_bytes(data)
        with self.assertRaises(backup.BackupError):
            self.crypto.decrypt(cipher)

    def test_truncated_ciphertext_rejected(self):
        path = self.first_part()
        path.write_bytes(path.read_bytes()[:-17])
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_corrupt_ciphertext_preserves_no_restore(self):
        path = self.first_part()
        data = bytearray(path.read_bytes())
        data[-30] ^= 1
        path.write_bytes(data)
        destination = self.root / "restored"
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix, destination)
        self.assertFalse(destination.exists())
        self.assertFalse(list(self.root.glob(".encrypted-restore-*")))

    def test_missing_part_rejects(self):
        self.first_part().unlink()
        with self.assertRaises(FileNotFoundError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_missing_manifest_rejects(self):
        self.store.path(self.prefix + "/manifest.json.gpg").unlink()
        with self.assertRaises(FileNotFoundError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_manifest_path_traversal_rejected(self):
        self.changed_manifest(lambda m: m["files"][0].update(name="../escaped"))
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)
        self.assertFalse((self.root / "escaped").exists())

    def test_manifest_duplicate_member_rejected(self):
        self.changed_manifest(lambda m: m["files"].__setitem__(1, m["files"][0]))
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_manifest_wrong_order_rejected(self):
        self.changed_manifest(lambda m: m["files"][0]["parts"].reverse())
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_manifest_cross_snapshot_part_rejected(self):
        self.changed_manifest(lambda m: m["files"][0]["parts"][0].update(key="another-snapshot/part.gpg"))
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_whole_file_digest_rejected(self):
        self.changed_manifest(lambda m: m["files"][0].update(sha256="0" * 64))
        with self.assertRaisesRegex(backup.BackupError, "whole-file"):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def test_latest_binds_exact_manifest_ciphertext(self):
        self.changed_manifest(lambda m: m.update(verified_at="2026-09-11T20:00:00Z"))
        with self.assertRaisesRegex(backup.BackupError, "binding"):
            backup.verify(self.store, self.crypto, self.work)

    def test_existing_destination_preserved(self):
        destination = self.root / "restored"
        destination.mkdir()
        (destination / "user-work").write_text("preserve this")
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix, destination)
        self.assertEqual((destination / "user-work").read_text(), "preserve this")

    def test_dangling_symlink_destination_rejected(self):
        destination = self.root / "restored"
        destination.symlink_to(self.root / "absent", target_is_directory=True)
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix, destination)

    def test_public_keyfile_rejected(self):
        path = self.root / "public-key"
        path.write_text("synthetic-key-with-enough-characters")
        path.chmod(0o644)
        with self.assertRaises(backup.BackupError):
            backup.GPG(path, self.work)

    def test_symlink_keyfile_rejected(self):
        path = self.root / "key-link"
        path.symlink_to(self.key)
        with self.assertRaises(backup.BackupError):
            backup.GPG(path, self.work)

    def test_missing_key_rejected(self):
        with self.assertRaises(FileNotFoundError):
            backup.GPG(self.root / "missing", self.work)

    def test_decrypt_output_bound(self):
        with self.assertRaisesRegex(backup.BackupError, "bound"):
            self.crypto.decrypt(self.first_part(), io.BytesIO(), 1)

    def test_manifest_size_bound(self):
        self.changed_manifest(lambda m: m["files"][0]["parts"][0].update(bytes=backup.CHUNK_BYTES + 1))
        with self.assertRaises(backup.BackupError):
            backup.verify(self.store, self.crypto, self.work, self.prefix)

    def upload_new(self, **kwargs):
        return backup.upload(self.snapshot, self.store, self.crypto, self.work, self.root / "journal.json", chunk_bytes=4096, **kwargs)

    def test_failed_part_upload_preserves_previous_latest(self):
        latest = self.store.path("encrypted-v1/LATEST.gpg").read_bytes()
        original = self.store.put
        def put(key, path):
            if "/artifacts/" in key:
                raise backup.BackupError("Injected upload failure")
            original(key, path)
        with patch.object(self.store, "put", side_effect=put), self.assertRaises(backup.BackupError):
            self.upload_new()
        self.assertEqual(self.store.path("encrypted-v1/LATEST.gpg").read_bytes(), latest)
        state = json.loads((self.root / "journal.json").read_text())
        self.assertEqual(state["status"], "incomplete")
        self.assertFalse(self.store.path(state["prefix"] + "/manifest.json.gpg").exists())

    def test_corrupt_upload_readback_never_completes(self):
        latest = self.store.path("encrypted-v1/LATEST.gpg").read_bytes()
        original = self.store.get
        def get(key, path, limit):
            original(key, path, limit)
            if "/artifacts/" in key:
                data = bytearray(Path(path).read_bytes())
                data[-1] ^= 1
                Path(path).write_bytes(data)
        with patch.object(self.store, "get", side_effect=get), self.assertRaises(backup.BackupError):
            self.upload_new()
        self.assertEqual(self.store.path("encrypted-v1/LATEST.gpg").read_bytes(), latest)

    def test_interrupted_upload_resumes_verified_parts(self):
        original = self.store.put
        calls = []
        def put(key, path):
            calls.append(key)
            if len(calls) == 2:
                raise backup.BackupError("Injected interruption")
            original(key, path)
        with patch.object(self.store, "put", side_effect=put), self.assertRaises(backup.BackupError):
            self.upload_new()
        first = json.loads((self.root / "journal.json").read_text())
        self.assertEqual(len(first["parts"]), 1)
        result = self.upload_new()
        self.assertEqual(result["prefix"], first["prefix"])
        self.assertEqual(result["status"], "passed")
        self.assertEqual(backup.verify(self.store, self.crypto, self.work)["status"], "passed")

    def test_bad_source_checksum_does_not_publish(self):
        wrong = copy.deepcopy(self.snapshot)
        wrong["rows"][0]["sha256"] = "0" * 64
        latest = self.store.path("encrypted-v1/LATEST.gpg").read_bytes()
        with self.assertRaisesRegex(backup.BackupError, "checksum"):
            backup.upload(wrong, self.store, self.crypto, self.work, self.root / "journal.json", chunk_bytes=4096)
        self.assertEqual(self.store.path("encrypted-v1/LATEST.gpg").read_bytes(), latest)

    def test_changed_source_identity_rejected_before_upload(self):
        wrong = copy.deepcopy(self.snapshot)
        wrong["rows"][0]["source_identity"][-1] += 1
        with self.assertRaisesRegex(backup.BackupError, "changed"):
            backup.upload(wrong, self.store, self.crypto, self.work, self.root / "journal.json")

    def test_manifest_upload_failure_preserves_latest(self):
        latest = self.store.path("encrypted-v1/LATEST.gpg").read_bytes()
        original = self.store.put
        def put(key, path):
            if key.endswith("manifest.json.gpg"):
                raise backup.BackupError("Injected manifest failure")
            original(key, path)
        with patch.object(self.store, "put", side_effect=put), self.assertRaises(backup.BackupError):
            self.upload_new()
        self.assertEqual(self.store.path("encrypted-v1/LATEST.gpg").read_bytes(), latest)

    def test_concurrent_uploader_lock(self):
        journal = self.root / "journal.json"
        with backup.journal_lock(journal), self.assertRaisesRegex(backup.BackupError, "active uploader"):
            self.upload_new()

    def test_canary_cannot_publish_latest(self):
        with self.assertRaises(backup.BackupError):
            self.upload_new(namespace="encrypted-canary-v1")

    def test_canary_does_not_change_production_pointer(self):
        latest = self.store.path("encrypted-v1/LATEST.gpg").read_bytes()
        result = self.upload_new(namespace="encrypted-canary-v1", publish_latest=False)
        self.assertFalse(result["latest_published"])
        self.assertEqual(self.store.path("encrypted-v1/LATEST.gpg").read_bytes(), latest)

    def test_source_duplicate_and_traversal_rejected(self):
        source = self.root / "2026-09-11"
        shutil.copytree(self.source, source)
        path = source / ("SHA256SUMS." + STAMP)
        for bad in (self.sums.splitlines()[0] + "\n", self.sums.replace("./blacklabel-", "../blacklabel-")):
            with self.subTest(bad=bad[:20]):
                path.write_text(bad)
                with self.assertRaises(backup.BackupError):
                    backup.read_snapshot(source)

    def test_symlink_source_rejected(self):
        source = self.root / "2026-09-11"
        shutil.copytree(self.source, source)
        name = next(iter(self.payloads))
        (source / name).unlink()
        (source / name).symlink_to(self.source / name)
        with self.assertRaises(backup.BackupError):
            backup.read_snapshot(source)

    def test_authenticated_redirect_rejected(self):
        with self.assertRaises(backup.BackupError):
            backup.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://elsewhere.invalid")

    def test_pointer_failure_resume_preserves_manifest_ciphertext(self):
        original = self.store.put
        def put(key, path):
            if key == "encrypted-v1/LATEST.gpg":
                raise backup.BackupError("Injected pointer failure")
            original(key, path)
        with patch.object(self.store, "put", side_effect=put), self.assertRaises(backup.BackupError):
            self.upload_new()
        state = json.loads((self.root / "journal.json").read_text())
        manifest = self.store.path(state["manifest"]["key"])
        saved = manifest.read_bytes()
        result = self.upload_new()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(manifest.read_bytes(), saved)
        self.assertEqual(backup.verify(self.store, self.crypto, self.work)["status"], "passed")

    def test_oauth_expiry_refreshes_before_transmission(self):
        credential = self.root / "current.toml"
        credential.write_text('oauth_token = "synthetic-expired"\nexpiration_time = "2020-01-01T00:00:00Z"\n')
        credential.chmod(0o600)
        store = backup.R2Store("a" * 32, "test-bucket", credential)
        def refresh():
            credential.write_text('oauth_token = "synthetic-refreshed"\nexpiration_time = "2099-01-01T00:00:00Z"\n')
        with patch.object(store, "refresh_oauth", side_effect=refresh) as call:
            self.assertEqual(store.token(), "synthetic-refreshed")
            call.assert_called_once()

    def test_unsuccessful_oauth_refresh_fails_closed(self):
        credential = self.root / "expired.toml"
        credential.write_text('oauth_token = "synthetic-expired"\nexpiration_time = "2020-01-01T00:00:00Z"\n')
        credential.chmod(0o600)
        store = backup.R2Store("a" * 32, "test-bucket", credential)
        with patch.object(store, "refresh_oauth"), self.assertRaises(backup.BackupError):
            store.token()


class R2LifetimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.credential = self.root / 'current.toml'
        self.now = backup.dt.datetime(2026, 9, 21, tzinfo=backup.dt.timezone.utc)
        self.elapsed = 0
        self.write_expiry(3600)
        self.store = backup.R2Store('a' * 32, 'test-bucket', self.credential)
        real_datetime = backup.dt.datetime
        owner = self
        class Clock(real_datetime):
            @classmethod
            def now(cls, tz=None):
                return owner.now + backup.dt.timedelta(seconds=owner.elapsed)
        self.datetime_patch = patch.object(backup.dt, 'datetime', Clock)
        self.datetime_patch.start()
        self.addCleanup(self.datetime_patch.stop)
        self.addCleanup(self.temp.cleanup)

    def write_expiry(self, seconds, token='synthetic'):
        expires = self.now + backup.dt.timedelta(seconds=self.elapsed + seconds)
        self.credential.write_text(f'oauth_token = "{token}"\nexpiration_time = "{expires.isoformat()}"\n')
        self.credential.chmod(0o600)

    def sleep(self, seconds):
        self.elapsed += seconds

    def test_near_expiry_waits_for_actual_expiry_before_refresh(self):
        for lifetime in (60, 121, 209):
            with self.subTest(lifetime=lifetime):
                self.elapsed = 0
                self.write_expiry(lifetime)
                def refresh():
                    self.assertGreaterEqual(self.elapsed, lifetime)
                    self.write_expiry(3600, 'synthetic-new')
                with patch.object(backup.time, 'monotonic', side_effect=lambda: self.elapsed), \
                     patch.object(backup.time, 'sleep', side_effect=self.sleep), \
                     patch.object(self.store, 'refresh_oauth', side_effect=refresh) as call:
                    self.assertEqual(self.store.token(), 'synthetic-new')
                    call.assert_called_once()
                    self.assertLess(self.elapsed, backup.OAUTH_WAIT_SECONDS)

    def test_noop_refresh_never_transmits_short_lived_token(self):
        self.write_expiry(60)
        with patch.object(backup.time, 'monotonic', side_effect=lambda: self.elapsed), \
             patch.object(backup.time, 'sleep', side_effect=self.sleep), \
             patch.object(self.store, 'refresh_oauth'), \
             patch.object(self.store.opener, 'open') as transmit, \
             self.assertRaisesRegex(backup.BackupError, 'insufficient lifetime'):
            with self.store.request('fixture.gpg', 'PUT'):
                pass
        transmit.assert_not_called()

    def test_insufficient_refreshed_headroom_rejected(self):
        self.write_expiry(-1)
        with patch.object(self.store, 'refresh_oauth', side_effect=lambda: self.write_expiry(121)), \
             self.assertRaisesRegex(backup.BackupError, 'insufficient lifetime'):
            self.store.token()

    def test_missing_malformed_and_naive_expiry_rejected_without_transmission(self):
        for expiry in (None, 'not-a-date', '2026-09-21T03:00:00'):
            with self.subTest(expiry=expiry):
                text = 'oauth_token = "synthetic"\n'
                if expiry is not None:
                    text += f'expiration_time = "{expiry}"\n'
                self.credential.write_text(text)
                with patch.object(self.store.opener, 'open') as transmit, \
                     self.assertRaises(backup.BackupError):
                    with self.store.request('fixture.gpg', 'PUT'):
                        pass
                transmit.assert_not_called()

    def test_clock_rollback_has_monotonic_wait_bound(self):
        self.write_expiry(60)
        def wait(seconds):
            self.elapsed += seconds
            self.now -= backup.dt.timedelta(seconds=seconds)
        with patch.object(backup.time, 'monotonic', side_effect=lambda: self.elapsed), \
             patch.object(backup.time, 'sleep', side_effect=wait), \
             patch.object(self.store, 'refresh_oauth') as refresh, \
             self.assertRaisesRegex(backup.BackupError, 'wait deadline'):
            self.store.token()
        self.assertEqual(self.elapsed, backup.OAUTH_WAIT_SECONDS)
        refresh.assert_not_called()

    def test_concurrent_normal_refresh_avoids_second_refresh(self):
        self.write_expiry(121)
        def wait(seconds):
            self.sleep(seconds)
            self.write_expiry(3600, 'concurrent-synthetic')
        with patch.object(backup.time, 'monotonic', side_effect=lambda: self.elapsed), \
             patch.object(backup.time, 'sleep', side_effect=wait), \
             patch.object(self.store, 'refresh_oauth') as refresh:
            self.assertEqual(self.store.token(), 'concurrent-synthetic')
        refresh.assert_not_called()

    def test_fresh_oauth_and_dedicated_token_do_not_refresh(self):
        with patch.object(self.store, 'refresh_oauth') as refresh:
            self.assertEqual(self.store.token(), 'synthetic')
        refresh.assert_not_called()
        dedicated = self.root / 'r2.token'
        dedicated.write_text('synthetic-dedicated')
        dedicated.chmod(0o600)
        self.assertEqual(backup.R2Store('a' * 32, 'test-bucket', dedicated).token(), 'synthetic-dedicated')

    def test_response_body_obeys_wall_deadline_and_restores_handler(self):
        before = backup.signal.getsignal(backup.signal.SIGALRM)
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        with patch.object(backup, 'REQUEST_SECONDS', 0.03), \
             patch.object(self.store.opener, 'open', return_value=response), \
             self.assertRaisesRegex(backup.BackupError, 'wall deadline'):
            with self.store.request('fixture.gpg', 'GET'):
                time.sleep(0.2)
        response.__exit__.assert_called_once()
        self.assertEqual(backup.signal.getitimer(backup.signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(backup.signal.getsignal(backup.signal.SIGALRM), before)

    def test_existing_alarm_is_preserved_and_no_request_is_sent(self):
        with patch.object(backup.signal, 'getitimer', return_value=(20.0, 0.0)), \
             patch.object(backup.signal, 'setitimer') as reset, \
             patch.object(self.store.opener, 'open') as transmit, \
             self.assertRaisesRegex(backup.BackupError, 'Existing alarm'):
            with self.store.request('fixture.gpg', 'GET'):
                pass
        transmit.assert_not_called()
        reset.assert_not_called()

    def test_ineligible_runner_rejects_before_token_refresh_or_wait(self):
        for lifetime in (-1, 60, 121):
            for unsupported in ('alarm', 'thread'):
                with self.subTest(lifetime=lifetime, unsupported=unsupported):
                    self.write_expiry(lifetime)
                    guard = (patch.object(backup.signal, 'getitimer', return_value=(20.0, 0.0))
                             if unsupported == 'alarm' else
                             patch.object(backup.threading, 'current_thread', return_value=object()))
                    with guard, patch.object(self.store, 'token') as token, \
                         patch.object(self.store, 'refresh_oauth') as refresh, \
                         patch.object(backup.time, 'sleep') as wait, \
                         patch.object(self.store.opener, 'open') as transmit, \
                         self.assertRaises(backup.BackupError):
                        with self.store.request('fixture.gpg', 'PUT'):
                            pass
                    for call in (token, refresh, wait, transmit):
                        call.assert_not_called()

    def test_refresh_timeout_is_sanitized(self):
        self.store.credential_file = Path.home() / '.wrangler/config/default.toml'
        with patch.object(backup.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['synthetic'], 120)), \
             self.assertRaisesRegex(backup.BackupError, '^Current Wrangler OAuth refresh did not finish$'):
            self.store.refresh_oauth()


if __name__ == "__main__":
    unittest.main(verbosity=2)
