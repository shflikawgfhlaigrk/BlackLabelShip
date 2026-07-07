#!/usr/bin/env python3
"""Ship-contract tests for the Windows lane (STAGED-ONLY, fail-closed).

stdlib unittest only (repo is py3.9-safe, no pytest dependency on the ship road).
Run: python3 test_windows_lane.py    (or: python3 -m unittest test_windows_lane -v)

Covers the two load-bearing invariants of the Windows road:
  (a) UNSIGNED -> road STOPS at the signing gate: NO R2/wrangler call, NO
      manifest write, a -UNSIGNED-STAGED artifact + a ships-staged.jsonl line,
      and ships.jsonl is NOT touched.
  (b) signing_identity present -> road REACHES the (mocked) upload stage and
      writes ships.jsonl with platform:"windows", staged_only:false.
"""
import os
import sys
import json
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ship  # noqa: E402


WIN_CFG = {
    "platform": "windows",
    "repo": "~",  # any dir that exists; win_build/win_preflight are mocked anyway
    "bundle_id": "com.blacklabel.circuit",
    "app_name": "Circuit-Setup.exe",
    "build_mode_default": "ci-pull",
    "build_cmd_ci": "gh run download {run} --name circuit-windows --dir {out}",
    "ci_workflow": "windows-build.yml",
    "ci_artifact_name": "circuit-windows",
    "built_artifact_windows": "Circuit-Setup.exe",
    "signing_identity": "UNSIGNED",
    "sign_cmd": "signtool sign /sha1 {thumbprint} {artifact}",
    "defender_scan_cmd": "Start-MpScan -ScanPath {artifact}",
    "clean_buyer_gauntlet_cmd": "manual",
    "r2_dl_key_windows": "dl/circuit-windows.zip",
    "r2_updates_key_windows": "updates/circuit-windows/{build}.zip",
    "manifest_endpoint_windows": "/api/version/circuit-windows",
    "dl_url_windows": "https://blacklabelbots.com/dl/circuit-windows.zip",
    "ports": ["8923"],
}


class WindowsLaneTest(unittest.TestCase):
    def setUp(self):
        # Isolate all filesystem side effects into a temp sandbox.
        self.tmp = tempfile.mkdtemp(prefix="winlane-test-")
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work, exist_ok=True)
        # A fake built artifact win_build "produces".
        self.artifact = os.path.join(self.work, "Circuit-Setup.exe")
        with open(self.artifact, "wb") as f:
            f.write(b"MZ\x90\x00fake-windows-installer-bytes")
        self.ledger = os.path.join(self.tmp, "ships.jsonl")
        self.staging = os.path.join(self.tmp, "ships-staged.jsonl")

        self._real_win_build = ship.win_build  # keep a handle to the unmocked fn
        patchers = [
            mock.patch.object(ship, "WORK_DIR", self.work),
            mock.patch.object(ship, "LEDGER", self.ledger),
            mock.patch.object(ship, "STAGING_LEDGER", self.staging),
            mock.patch.object(ship, "APPS_DIR", self.tmp),  # config path lookups
            # Stub the two stages that touch the network / another agent's repo.
            mock.patch.object(ship, "win_preflight", return_value="abc1234"),
            mock.patch.object(ship, "win_build", return_value=self.artifact),
        ]
        self.mocks = [p.start() for p in patchers]
        self.addCleanup(mock.patch.stopall)

    def _write_cfg(self, name, overrides=None):
        cfg = dict(WIN_CFG)
        if overrides:
            cfg.update(overrides)
        path = os.path.join(self.tmp, name + ".toml")
        # cmd_ship_windows reloads from disk via load_config; write a real TOML-lite.
        with open(path, "w") as f:
            for k, v in cfg.items():
                if isinstance(v, list):
                    inner = ", ".join(f'"{x}"' for x in v)
                    f.write(f'{k} = [{inner}]\n')
                else:
                    f.write(f'{k} = "{v}"\n')
        return path

    def _lines(self, path):
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return [json.loads(l) for l in f if l.strip()]

    # ---- (a) UNSIGNED -> stops at signing gate, fail-closed ----
    def test_unsigned_stages_only_never_uploads(self):
        self._write_cfg("circuit-windows")  # signing_identity == UNSIGNED
        # Any attempt to shell out (wrangler/signtool) or bump a manifest is a FAIL.
        with mock.patch.object(ship, "_run") as run, \
             mock.patch.object(ship, "win_upload") as up, \
             mock.patch.object(ship, "win_sign_scan_gauntlet") as sign, \
             mock.patch("subprocess.run") as sub:
            rc = ship.cmd_ship_windows("circuit-windows", None, None)

        self.assertEqual(rc, 0)
        # Signing gate held: no sign, no upload, no subprocess/_run (no wrangler).
        sign.assert_not_called()
        up.assert_not_called()
        run.assert_not_called()
        sub.assert_not_called()

        # A -UNSIGNED-STAGED artifact exists in work/.
        staged = [f for f in os.listdir(self.work) if "UNSIGNED-STAGED" in f]
        self.assertEqual(len(staged), 1, f"expected one staged artifact, got {staged}")

        # Staging ledger written; ships.jsonl NOT touched.
        st = self._lines(self.staging)
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["platform"], "windows")
        self.assertTrue(st[0]["staged_only"])
        self.assertFalse(st[0]["uploaded"])
        self.assertFalse(st[0]["manifest_bumped"])
        self.assertEqual(len(self._lines(self.ledger)), 0,
                         "ships.jsonl must NOT be written for an unsigned artifact")

    # ---- (b) signed identity present -> reaches upload stage ----
    def test_signed_reaches_upload_and_ships_ledger(self):
        self._write_cfg("circuit-windows",
                        {"signing_identity": "AA11BB22CC33DEADBEEFCERTTHUMBPRINT"})
        # Mock the externals (signtool/Defender/wrangler) so the road can run
        # end-to-end without a Windows box; reaching win_upload IS the assertion.
        with mock.patch.object(ship, "win_upload",
                               return_value="dl/circuit-windows.zip") as up, \
             mock.patch("subprocess.run",
                        return_value=mock.Mock(returncode=0)):
            rc = ship.cmd_ship_windows("circuit-windows", None, None)

        self.assertEqual(rc, 0)
        up.assert_called_once()  # the signed path reached the (mocked) upload stage

        # ships.jsonl gets the real ship line; staging ledger untouched.
        led = self._lines(self.ledger)
        self.assertEqual(len(led), 1)
        self.assertEqual(led[0]["platform"], "windows")
        self.assertFalse(led[0]["staged_only"])
        self.assertTrue(led[0]["uploaded"])
        self.assertEqual(len(self._lines(self.staging)), 0)

    # ---- guard: rig mode is Founder-gated (blocked) ----
    def test_rig_mode_blocked(self):
        # Call the REAL win_build (setUp mocked the module attr); WORK_DIR is
        # still patched to the temp sandbox, so no real work/ dir is touched.
        with self.assertRaises(SystemExit):
            # rig mode must SystemExit via fail() (no hypervisor on this Mac)
            self._real_win_build(WIN_CFG, "circuit-windows", "rig", None)

    # ---- guard: a macOS config rejected by the Windows road ----
    def test_macos_config_rejected_by_windows_road(self):
        # Write a config WITHOUT platform=windows; the road must refuse it.
        path = os.path.join(self.tmp, "notwin.toml")
        with open(path, "w") as f:
            f.write('repo = "~"\n')  # no platform key
        with self.assertRaises(SystemExit):
            ship.cmd_ship_windows("notwin", None, None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
