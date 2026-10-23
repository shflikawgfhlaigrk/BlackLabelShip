"""Exercise the real wrapper and decrypted archives using synthetic data only."""
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


class OffsiteWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scripts = self.root / 'scripts'
        self.commands = self.root / 'commands'
        self.content = self.root / 'content'
        for p in (self.scripts/'tools', self.commands, self.content/'BlackLabelShip',
                  self.content/'.utah/secrets', self.root/'deploy'):
            p.mkdir(parents=True, exist_ok=True)
        self.script = self.scripts/'backup_offsite.sh'
        shutil.copy2(Path(__file__).parent/'backup_offsite.sh', self.script)
        (self.scripts/'tools/encrypted_snapshot.py').write_text(
            'import os, sys\nassert sys.argv[1] == "idle"\nsys.exit(int(os.environ.get("TEST_BUSY", "0")))\n')
        (self.content/'BlackLabelShip/ships.jsonl').write_text('{"synthetic":true}\n')
        (self.content/'.utah/secrets/fixture').write_text('synthetic-only\n')
        self.key = self.root/'key'
        self.key.write_text('synthetic-offsite-wrapper-key-12345\n')
        self.key.chmod(0o600)
        npx = self.commands/'npx'
        npx.write_text('''#!/usr/bin/env python3
import os, pathlib, shutil, sys
a=sys.argv[1:]
with open(os.environ['WRAPPER_TEST_CALLS'], 'a') as f: f.write('synthetic-provider-call\\n')
if 'export' in a:
    pathlib.Path(a[a.index('--output')+1]).write_text('-- synthetic SQL\\n')
else:
    if os.environ.get('TEST_LATEST_FAIL') and any(x.endswith('/latest.tar.gz.enc') for x in a): sys.exit(1)
    shutil.copyfile(a[a.index('--file')+1], os.environ['TEST_ARCHIVE'])
''')
        npx.chmod(0o700)
        self.calls = self.root/'calls'
        self.archive = self.root/'archive.enc'
        self.env = dict(os.environ, PATH=str(self.commands)+':/usr/bin:/bin',
                        BACKUP_CONTENT_ROOT=str(self.content),
                        OFFSITE_DEPLOY_ROOT=str(self.root/'deploy'),
                        BACKUP_KEYFILE=str(self.key), OFFSITE_LOG=str(self.root/'log'),
                        SNAP_STATE_DIR=str(self.root/'state'),
                        WRAPPER_TEST_CALLS=str(self.calls), TEST_ARCHIVE=str(self.archive))

    def run_wrapper(self, snapshot_exit=None, args=()):
        if snapshot_exit is not None:
            snapshot = self.scripts/'backup_offsite_snapshot.sh'
            snapshot.write_text(f'#!/bin/bash\necho synthetic-snapshot-ran\nexit {snapshot_exit}\n')
            snapshot.chmod(0o700)
        return subprocess.run(['/bin/zsh',str(self.script),*args],env=self.env,
                              capture_output=True,text=True,timeout=20)

    def assert_state_uploaded(self, result):
        self.assertIn('state bundle complete:', result.stdout, result.stdout+result.stderr)
        self.assertEqual(len(self.calls.read_text().splitlines()), 3)

    def test_failed_snapshot_preserves_partial_success_and_fails_job(self):
        r = self.run_wrapper(7)
        self.assert_state_uploaded(r)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('overall backup incomplete', r.stdout)
        self.assertNotIn('] backup complete:', r.stdout)

    def test_missing_snapshot_never_claims_complete(self):
        r = self.run_wrapper()
        self.assert_state_uploaded(r)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('snapshot entrypoint missing', r.stdout)
        self.assertNotIn('] backup complete:', r.stdout)

    def test_both_lanes_success_completes(self):
        r = self.run_wrapper(0)
        self.assert_state_uploaded(r)
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        self.assertIn('] backup complete:', r.stdout)

    def test_symlink_vault_is_restored_as_regular_files(self):
        vault = self.root/'vault'
        (self.content/'.utah/secrets').rename(vault)
        (self.content/'.utah/secrets').symlink_to(vault, target_is_directory=True)
        (vault/'nested').mkdir()
        (vault/'nested/config').write_bytes(b'synthetic-nested-config\n')
        r = self.run_wrapper(args=['--state-only'])
        self.assert_state_uploaded(r)
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        decrypted = subprocess.run(['openssl','enc','-d','-aes-256-cbc','-pbkdf2',
            '-in',str(self.archive),'-pass','file:'+str(self.key)],capture_output=True,check=True)
        with tarfile.open(fileobj=io.BytesIO(decrypted.stdout),mode='r:gz') as tf:
            self.assertFalse(any(m.issym() for m in tf.getmembers()))
            self.assertTrue(tf.getmember('blacklabel-state/secrets/fixture').isfile())
            self.assertEqual(tf.extractfile('blacklabel-state/secrets/fixture').read(),b'synthetic-only\n')
            self.assertEqual(tf.extractfile('blacklabel-state/secrets/nested/config').read(),b'synthetic-nested-config\n')

    def test_missing_vault_stops_before_network(self):
        shutil.rmtree(self.content/'.utah/secrets')
        r = self.run_wrapper(args=['--state-only'])
        self.assertNotEqual(r.returncode,0)
        self.assertFalse(self.calls.exists())
        self.assertNotIn('state bundle complete:',r.stdout)

    def test_empty_vault_stops_before_network(self):
        (self.content/'.utah/secrets/fixture').unlink()
        r = self.run_wrapper(args=['--state-only'])
        self.assertNotEqual(r.returncode,0)
        self.assertFalse(self.calls.exists())

    def test_daily_only_does_not_touch_busy_snapshot_lane(self):
        self.env['TEST_BUSY']='1'
        r = self.run_wrapper(0,args=['--state-only'])
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assert_state_uploaded(r)
        self.assertNotIn('synthetic-snapshot-ran',r.stdout)
        self.assertNotIn('] backup complete:',r.stdout)

    def test_full_run_retains_busy_preflight(self):
        self.env['TEST_BUSY']='1'
        r = self.run_wrapper(0)
        self.assertNotEqual(r.returncode,0)
        self.assertFalse(self.calls.exists())

    def test_latest_failure_cannot_claim_daily_success(self):
        self.env['TEST_LATEST_FAIL']='1'
        r = self.run_wrapper(args=['--state-only'])
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn('state bundle complete:',r.stdout)

    def test_invalid_arguments_cannot_upload(self):
        for args in (['--unknown'], ['--state-only','extra']):
            r = self.run_wrapper(args=args)
            self.assertEqual(r.returncode,2)
            self.assertFalse(self.calls.exists())


if __name__ == '__main__':
    unittest.main()
