#!/usr/bin/env python3
"""Ship-contract tests for the iOS App Store lane (STAGED-ONLY, fail-closed).

stdlib unittest only (py3.9-safe, mirrors test_windows_lane.py on the ship road).
Run: python3 test_ios_lane.py    (or: python3 -m unittest test_ios_lane -v)

Covers the load-bearing invariants of the iOS road:
  (a) toolchain guard REJECTS (beta / 17F113 / macOS 26A) -> road STOPS: NO
      export, NO upload, a `<app>-ios-UNSIGNED-STAGED-ONLY.ipa` artifact + a
      ships-staged.jsonl line, and ships.jsonl is NOT touched.
  (b) guard passes but NO signing identity -> same STAGED-only terminus.
  (c) guard passes AND signing_identity present -> road REACHES the (mocked)
      export/upload boundary and writes ships.jsonl (staged_only:false).
  (d) a non-iOS config is refused by the iOS road.
  (e) the REAL guard bash script rejects a beta Xcode with exit 65 (unmocked;
      actively proves rejection on the beta host, skips on a release host).
"""
import os
import sys
import json
import tempfile
import unittest
import subprocess
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ios_lane  # noqa: E402

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "appstore_toolchain_guard.sh")

IOS_CFG = {
    "platform": "ios",
    "repo": "~",  # any existing dir; ios_preflight/ios_build are mocked anyway
    "bundle_id": "com.blacklabel.homefront.guardian",
    "app_name": "HomefrontGuardian",
    "ci_workflow": "ios-appstore.yml",
    "build_cmd_ci": ("gh run download {run} --repo mthburnsbarber-web/HomefrontGuardian "
                     "--name homefrontguardian-ios-UNSIGNED-STAGED-ONLY --dir {out}"),
    "ci_artifact_name": "homefrontguardian-ios-UNSIGNED-STAGED-ONLY",
    "built_artifact_ios": "homefrontguardian-ios-UNSIGNED-STAGED-ONLY.ipa",
    "signing_identity": "UNSIGNED",
    "export_plist": "ci/ExportOptions-AppStore-iOS.plist",
}


class IOSLaneTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ioslane-test-")
        self.work = os.path.join(self.tmp, "work")
        # ios_build pulls the CI artifact into work/<app>-iosbuild/, mirroring reality;
        # ios_stage_unsigned copies it UP into work/ under the clean staged name.
        build_out = os.path.join(self.work, "homefrontguardian-ios-iosbuild")
        os.makedirs(build_out, exist_ok=True)
        self.artifact = os.path.join(build_out, "homefrontguardian-ios-UNSIGNED-STAGED-ONLY.ipa")
        with open(self.artifact, "wb") as f:
            f.write(b"PK\x03\x04fake-ipa-payload-bytes")
        self.ledger = os.path.join(self.tmp, "ships.jsonl")
        self.staging = os.path.join(self.tmp, "ships-staged.jsonl")

        patchers = [
            mock.patch.object(ios_lane, "WORK_DIR", self.work),
            mock.patch.object(ios_lane, "LEDGER", self.ledger),
            mock.patch.object(ios_lane, "STAGING_LEDGER", self.staging),
            mock.patch.object(ios_lane, "APPS_DIR", self.tmp),  # config path lookups
            # Stub the stages that touch the network / another agent's repo.
            mock.patch.object(ios_lane, "ios_preflight", return_value="abc1234"),
            mock.patch.object(ios_lane, "ios_build", return_value=self.artifact),
        ]
        self.mocks = [p.start() for p in patchers]
        self.addCleanup(mock.patch.stopall)

    def _write_cfg(self, name, overrides=None):
        cfg = dict(IOS_CFG)
        if overrides:
            cfg.update(overrides)
        path = os.path.join(self.tmp, name + ".toml")
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

    def _assert_staged_only(self):
        """Shared assertions for both STAGED-only terminal paths."""
        # The source artifact lives in a work/<app>-iosbuild/ subdir; a non-recursive
        # listing of work/ sees only the staged copy the terminus wrote.
        staged = [f for f in os.listdir(self.work) if f.endswith("-ios-UNSIGNED-STAGED-ONLY.ipa")]
        self.assertEqual(len(staged), 1, f"expected one staged artifact, got {staged}")
        st = self._lines(self.staging)
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["platform"], "ios")
        self.assertTrue(st[0]["staged_only"])
        self.assertFalse(st[0]["uploaded"])
        self.assertFalse(st[0]["manifest_bumped"])
        self.assertEqual(len(self._lines(self.ledger)), 0,
                         "ships.jsonl must NOT be written for a staged-only artifact")

    # ---- (a) guard REJECTS (beta toolchain) -> staged, fail-closed ----
    def test_beta_toolchain_stages_only_never_uploads(self):
        # Even with a signing identity present, a guard rejection stages only.
        self._write_cfg("homefrontguardian-ios",
                        {"signing_identity": "REALCERTHASH"})
        with mock.patch.object(ios_lane, "ios_guard", return_value=65) as guard, \
             mock.patch.object(ios_lane, "ios_export") as exp, \
             mock.patch.object(ios_lane, "ios_upload") as up, \
             mock.patch.object(ios_lane, "_run") as run, \
             mock.patch("subprocess.run") as sub:
            rc = ios_lane.cmd_ship_ios("homefrontguardian-ios")

        self.assertEqual(rc, 0)
        guard.assert_called_once()
        exp.assert_not_called()
        up.assert_not_called()
        run.assert_not_called()
        sub.assert_not_called()
        self._assert_staged_only()
        self.assertIn("guard REJECTED", self._lines(self.staging)[0]["reason"])

    # ---- (b) guard passes but UNSIGNED -> staged, fail-closed ----
    def test_unsigned_stages_only_never_uploads(self):
        self._write_cfg("homefrontguardian-ios")  # signing_identity == UNSIGNED
        with mock.patch.object(ios_lane, "ios_guard", return_value=0), \
             mock.patch.object(ios_lane, "ios_export") as exp, \
             mock.patch.object(ios_lane, "ios_upload") as up, \
             mock.patch.object(ios_lane, "_run") as run, \
             mock.patch("subprocess.run") as sub:
            rc = ios_lane.cmd_ship_ios("homefrontguardian-ios")

        self.assertEqual(rc, 0)
        exp.assert_not_called()
        up.assert_not_called()
        run.assert_not_called()
        sub.assert_not_called()
        self._assert_staged_only()
        self.assertIn("unsigned", self._lines(self.staging)[0]["reason"])

    # ---- (c) guard passes AND signed -> reaches upload boundary ----
    def test_signed_and_guard_pass_reaches_upload(self):
        self._write_cfg("homefrontguardian-ios",
                        {"signing_identity": "AA11BB22CC33DEADBEEFCERTHASH"})
        with mock.patch.object(ios_lane, "ios_guard", return_value=0), \
             mock.patch.object(ios_lane, "ios_export", return_value=self.artifact), \
             mock.patch.object(ios_lane, "ios_upload", return_value="boundary") as up:
            rc = ios_lane.cmd_ship_ios("homefrontguardian-ios")

        self.assertEqual(rc, 0)
        up.assert_called_once()  # signed path reached the (mocked) upload boundary
        led = self._lines(self.ledger)
        self.assertEqual(len(led), 1)
        self.assertEqual(led[0]["platform"], "ios")
        self.assertFalse(led[0]["staged_only"])
        self.assertTrue(led[0]["uploaded"])
        self.assertEqual(len(self._lines(self.staging)), 0)

    # ---- (d) a non-iOS config is refused by the iOS road ----
    def test_non_ios_config_rejected(self):
        path = os.path.join(self.tmp, "notios.toml")
        with open(path, "w") as f:
            f.write('platform = "windows"\nrepo = "~"\n')
        with self.assertRaises(SystemExit):
            ios_lane.cmd_ship_ios("notios")

    # ---- (e) the REAL guard rejects a beta Xcode (unmocked, host-truthful) ----
    def test_real_guard_rejects_beta_xcode(self):
        """Runs the actual guard bash against a beta Xcode path. On the current
        beta host (/Applications/Xcode.app == 26.6/17F113) this actively proves
        rejection (exit 65). On a release host it points APPSTORE_DEVELOPER_DIR
        at a non-existent Xcode-beta.app so the guard still fails closed."""
        self.assertTrue(os.path.isfile(GUARD), f"guard missing at {GUARD}")
        beta_dir = "/Applications/Xcode-beta.app/Contents/Developer"
        # If a real host Xcode is itself the rejected beta build, point at it to
        # prove the version/build screens; else use the (absent) beta path which
        # trips the missing-Xcode screen. Either way the guard MUST exit 65.
        host_ver = subprocess.run(["xcodebuild", "-version"], capture_output=True, text=True).stdout
        if "17F113" in host_ver or "Xcode 27." in host_ver:
            dev_dir = subprocess.run(["xcode-select", "-p"], capture_output=True, text=True).stdout.strip()
        else:
            dev_dir = beta_dir
        r = subprocess.run(
            ["bash", "-c", f'source "{GUARD}"; appstore_select_xcode'],
            capture_output=True, text=True,
            env={**os.environ, "APPSTORE_DEVELOPER_DIR": dev_dir},
        )
        self.assertEqual(r.returncode, 65,
                         f"guard must reject beta/rejected toolchain (exit 65); "
                         f"got {r.returncode}. stderr={r.stderr.strip()}")
        self.assertIn("App Store guard", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
