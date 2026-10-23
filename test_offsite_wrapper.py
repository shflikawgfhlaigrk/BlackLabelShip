"""Exercise the real offsite entrypoint with isolated data and no remote tools."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class OffsiteWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.scripts = self.root / 'scripts'
        self.commands = self.root / 'commands'
        self.content = self.root / 'content'
        for p in (self.scripts, self.commands, self.content/'BlackLabelShip',
                  self.content/'.utah/secrets', self.root/'deploy'):
            p.mkdir(parents=True, exist_ok=True)
        self.script = self.scripts/'backup_offsite.sh'
        shutil.copy2(Path(__file__).parent/'backup_offsite.sh', self.script)
        (self.content/'BlackLabelShip/ships.jsonl').write_text('{"synthetic":true}\n')
        (self.content/'.utah/secrets/fixture').write_text('synthetic-only\n')
        key = self.root/'key'
        key.write_text('synthetic-offsite-wrapper-key-12345\n')
        key.chmod(0o600)
        npx = self.commands/'npx'
        npx.write_text('#!/bin/sh\nprintf "synthetic-provider-call\\n" >> "$WRAPPER_TEST_CALLS"\nexit 0\n')
        npx.chmod(0o700)
        self.calls = self.root/'calls'
        self.env = dict(os.environ, PATH=str(self.commands)+':/usr/bin:/bin',
                        BACKUP_CONTENT_ROOT=str(self.content),
                        OFFSITE_DEPLOY_ROOT=str(self.root/'deploy'),
                        BACKUP_KEYFILE=str(key), OFFSITE_LOG=str(self.root/'log'),
                        WRAPPER_TEST_CALLS=str(self.calls))

    def run_wrapper(self, snapshot_exit=None):
        if snapshot_exit is not None:
            snapshot = self.scripts/'backup_offsite_snapshot.sh'
            snapshot.write_text(f'#!/bin/bash\necho synthetic-snapshot-ran\nexit {snapshot_exit}\n')
            snapshot.chmod(0o700)
        result = subprocess.run(['/bin/zsh',str(self.script)],env=self.env,
                                capture_output=True,text=True,timeout=20)
        self.assertIn('state bundle complete:', result.stdout)
        self.assertEqual(len(self.calls.read_text().splitlines()), 3)
        return result

    def test_failed_snapshot_preserves_partial_success_and_fails_job(self):
        r = self.run_wrapper(7)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('overall backup incomplete', r.stdout)
        self.assertNotIn('] backup complete:', r.stdout)

    def test_missing_snapshot_never_claims_complete(self):
        r = self.run_wrapper()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('snapshot entrypoint missing', r.stdout)
        self.assertNotIn('] backup complete:', r.stdout)

    def test_both_lanes_success_completes(self):
        r = self.run_wrapper(0)
        self.assertEqual(r.returncode, 0, r.stdout+r.stderr)
        self.assertIn('] backup complete:', r.stdout)
        self.assertIn('encrypted snapshot off-site OK', r.stdout)


if __name__ == '__main__':
    unittest.main()
