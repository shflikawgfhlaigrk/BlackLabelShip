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
import re
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
    # The Authenticode /dl road is now DORMANT (founder ruling 2026-07-20:
    # store-first). These cases exercise that self-dist road, so they opt into it
    # explicitly; the store/MSIX road (the default) is covered by StoreLaneTest.
    "distribution": "selfdist",
    "build_mode_default": "ci-pull",
    "build_cmd_ci": ("gh run download {run} --repo mthburnsbarber-web/BlackLabelCircuit "
                     "--name circuit-windows-UNSIGNED-STAGED-ONLY --dir {out}"),
    "ci_workflow": "windows-spike.yml",
    "ci_artifact_name": "circuit-windows-UNSIGNED-STAGED-ONLY",
    "built_artifact_windows": "circuit-windows-UNSIGNED-STAGED-ONLY.exe",
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
        self.artifact = os.path.join(self.work, "circuit-windows-UNSIGNED-STAGED-ONLY.exe")
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

        # A -UNSIGNED-STAGED artifact exists in work/. Match the exact staged
        # suffix — the SOURCE artifact's own name now contains
        # "UNSIGNED-STAGED-ONLY", so a substring match would count it too.
        staged = [f for f in os.listdir(self.work) if f.endswith("-UNSIGNED-STAGED.exe")]
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

    # ---- (b) signed identity present + founder GO -> reaches upload stage ----
    def test_signed_reaches_upload_and_ships_ledger(self):
        self._write_cfg("circuit-windows",
                        {"signing_identity": "AA11BB22CC33DEADBEEFCERTTHUMBPRINT"})
        # A signed publish goes public + writes ships.jsonl — an owner-only act (CHARTER §3), so it
        # needs the founder GO artifact just like the Mac roads. Provide it (APPS_DIR is the sandbox).
        with open(os.path.join(self.tmp, "circuit-windows.GO"), "w") as f:
            f.write("GO — ship circuit windows b5. Michael, 2026-07-14\n")
        # Mock the externals (signtool/Defender/wrangler) so the road can run
        # end-to-end without a Windows box; reaching win_upload IS the assertion.
        with mock.patch.object(ship, "win_upload",
                               return_value="dl/circuit-windows.zip") as up, \
             mock.patch("subprocess.run",
                        return_value=mock.Mock(returncode=0)):
            rc = ship.cmd_ship_windows("circuit-windows", None, None)

        self.assertEqual(rc, 0)
        up.assert_called_once()  # the signed path reached the (mocked) upload stage

        # ships.jsonl gets the real ship line (with the recorded GO); staging ledger untouched.
        led = self._lines(self.ledger)
        self.assertEqual(len(led), 1)
        self.assertEqual(led[0]["platform"], "windows")
        self.assertFalse(led[0]["staged_only"])
        self.assertTrue(led[0]["uploaded"])
        self.assertTrue(led[0]["go"].startswith("GO — ship circuit windows b5"))
        self.assertEqual(len(self._lines(self.staging)), 0)

    # ---- (b2) signed identity but NO founder GO -> fail-closed, nothing public ----
    def test_signed_without_go_refuses_and_never_uploads(self):
        self._write_cfg("circuit-windows",
                        {"signing_identity": "AA11BB22CC33DEADBEEFCERTTHUMBPRINT"})
        # No circuit-windows.GO in the sandbox APPS_DIR. The signed path must STOP before any public
        # upload or ledger write — a cert is not authorization to publish.
        with mock.patch.object(ship, "win_upload") as up, \
             mock.patch.object(ship, "win_sign_scan_gauntlet") as sign, \
             mock.patch("subprocess.run",
                        return_value=mock.Mock(returncode=0)):
            with self.assertRaises(SystemExit) as cm:
                ship.cmd_ship_windows("circuit-windows", None, None)

        self.assertNotEqual(cm.exception.code, 0)
        up.assert_not_called()   # no public bytes
        sign.assert_not_called()  # gate_go runs before signing
        self.assertEqual(len(self._lines(self.ledger)), 0,
                         "ships.jsonl must NOT be written without a founder GO")

    # ---- (c) a config authored to the PLAN §W0.2 literal key names validates
    #          AND still fails closed when unsigned ----
    def test_plan_literal_keys_validate_and_still_fail_closed(self):
        # Drop the implementation's build_cmd_ci/sign_cmd and use the plan's
        # canonical spellings build_cmd_windows/sign_windows. The schema must
        # accept them (not trip the unknown-keys guard) and the road must STILL
        # stop at the signing gate while signing_identity == UNSIGNED.
        overrides = {
            "build_cmd_windows": ("gh run download {run} --repo mthburnsbarber-web/BlackLabelCircuit "
                                  "--name circuit-windows-UNSIGNED-STAGED-ONLY --dir {out}"),
            "sign_windows": "signtool sign /sha1 {thumbprint} {artifact}",
        }
        cfg = dict(WIN_CFG)
        cfg.pop("build_cmd_ci", None)
        cfg.pop("sign_cmd", None)
        cfg.update(overrides)
        path = os.path.join(self.tmp, "circuit-windows.toml")
        with open(path, "w") as f:
            for k, v in cfg.items():
                if isinstance(v, list):
                    inner = ", ".join(f'"{x}"' for x in v)
                    f.write(f'{k} = [{inner}]\n')
                else:
                    f.write(f'{k} = "{v}"\n')
        # validate_windows must NOT reject the plan-literal keys.
        loaded = ship.load_any(path)
        self.assertEqual(loaded["platform"], "windows")
        self.assertIn("build_cmd_windows", loaded)
        self.assertIn("sign_windows", loaded)
        # And the road still fails closed (unsigned -> staged only, no upload).
        with mock.patch.object(ship, "_run") as run, \
             mock.patch.object(ship, "win_upload") as up, \
             mock.patch.object(ship, "win_sign_scan_gauntlet") as sign, \
             mock.patch("subprocess.run") as sub:
            rc = ship.cmd_ship_windows("circuit-windows", None, None)
        self.assertEqual(rc, 0)
        sign.assert_not_called()
        up.assert_not_called()
        run.assert_not_called()
        sub.assert_not_called()
        self.assertEqual(len(self._lines(self.ledger)), 0,
                         "plan-literal-key config must still fail closed (no ships.jsonl)")
        self.assertEqual(len(self._lines(self.staging)), 1)

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


class StoreLaneTest(unittest.TestCase):
    """The STORE-FIRST (MSIX via Partner Center) road — the primary tail after the
    founder ruling 2026-07-20. Fail-closed authority = the PARTNER_CENTER_READY
    marker (one founder-only account, PENDING), NOT an Authenticode cert."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="winstore-test-")
        self.work = os.path.join(self.tmp, "work")
        os.makedirs(self.work, exist_ok=True)
        # win_build "produces" an .msix (the CI/builder snapshot ran makeappx).
        self.msix = os.path.join(self.work, "circuit-windows.msix")
        with open(self.msix, "wb") as f:
            f.write(b"PK\x03\x04fake-msix-package-bytes")
        self.ledger = os.path.join(self.tmp, "ships.jsonl")
        self.staging = os.path.join(self.tmp, "ships-staged.jsonl")
        patchers = [
            mock.patch.object(ship, "WORK_DIR", self.work),
            mock.patch.object(ship, "LEDGER", self.ledger),
            mock.patch.object(ship, "STAGING_LEDGER", self.staging),
            mock.patch.object(ship, "APPS_DIR", self.tmp),
            mock.patch.object(ship, "win_preflight", return_value="abc1234"),
            mock.patch.object(ship, "win_build", return_value=self.msix),
        ]
        self.mocks = [p.start() for p in patchers]
        self.addCleanup(mock.patch.stopall)

    def _write_store_cfg(self, name, overrides=None):
        cfg = dict(WIN_CFG)
        cfg["distribution"] = "store"
        cfg["built_artifact_windows"] = "circuit-windows.msix"
        cfg["store_submission_cmd"] = "msstore submit {msix} --sha {sha}"
        cfg["msix_package_cmd"] = "makeappx pack /d {artifact} /p {out}"
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

    def _mark_partner_center_ready(self):
        with open(os.path.join(self.tmp, "PARTNER_CENTER_READY"), "w") as f:
            f.write("Partner Center account registered. Michael, 2026-07-21\n")

    # ---- (a) no Partner Center account -> MSIX packaged, submission STAGED, nothing submitted ----
    def test_store_no_account_stages_locally(self):
        self._write_store_cfg("circuit-windows")  # NO PARTNER_CENTER_READY marker
        with mock.patch.object(ship, "win_store_submit") as submit, \
             mock.patch("subprocess.run") as sub:
            rc = ship.cmd_ship_windows("circuit-windows", None, None)

        self.assertEqual(rc, 0)
        submit.assert_not_called()          # nothing submitted to Partner Center
        sub.assert_not_called()             # ci-pull mode: no makeappx shell-out either

        staged = [f for f in os.listdir(self.work) if f.endswith("-STORE-STAGED.msix")]
        self.assertEqual(len(staged), 1, f"expected one store-staged msix, got {staged}")

        st = self._lines(self.staging)
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["channel"], "store")
        self.assertTrue(st[0]["staged_only"])
        self.assertFalse(st[0]["submitted"])
        self.assertEqual(len(self._lines(self.ledger)), 0,
                         "ships.jsonl must NOT be written without a Partner Center account")

    # ---- (b) account marker + founder GO -> reaches the (mocked) Store submission ----
    def test_store_with_account_and_go_reaches_submit(self):
        self._write_store_cfg("circuit-windows")
        self._mark_partner_center_ready()
        with open(os.path.join(self.tmp, "circuit-windows.GO"), "w") as f:
            f.write("GO — publish circuit to the Microsoft Store. Michael, 2026-07-21\n")
        with mock.patch.object(ship, "win_store_submit",
                               return_value="deadbeef") as submit, \
             mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
            rc = ship.cmd_ship_windows("circuit-windows", None, None)

        self.assertEqual(rc, 0)
        submit.assert_called_once()         # the store path reached the (mocked) submit stage
        led = self._lines(self.ledger)
        self.assertEqual(len(led), 1)
        self.assertEqual(led[0]["channel"], "store")
        self.assertFalse(led[0]["staged_only"])
        self.assertTrue(led[0]["submitted"])
        self.assertTrue(led[0]["go"].startswith("GO — publish circuit"))
        self.assertEqual(len(self._lines(self.staging)), 0)

    # ---- (b2) account marker but NO founder GO -> fail-closed, nothing submitted ----
    def test_store_with_account_but_no_go_refuses(self):
        self._write_store_cfg("circuit-windows")
        self._mark_partner_center_ready()   # account exists, but no GO
        with mock.patch.object(ship, "win_store_submit") as submit, \
             mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
            with self.assertRaises(SystemExit) as cm:
                ship.cmd_ship_windows("circuit-windows", None, None)
        self.assertNotEqual(cm.exception.code, 0)
        submit.assert_not_called()          # a ready account is not authorization to publish
        self.assertEqual(len(self._lines(self.ledger)), 0,
                         "ships.jsonl must NOT be written without a founder GO")

    # ---- (c) store road REQUIRES a .msix — a bare .exe cannot get free MS signing ----
    def test_store_rejects_non_msix_artifact(self):
        # win_build returns an .exe; store distribution must refuse it (ci-pull mode
        # can't run makeappx on a Mac), fail-closed before any staging.
        exe = os.path.join(self.work, "circuit-windows.exe")
        with open(exe, "wb") as f:
            f.write(b"MZ\x90\x00not-an-msix")
        self._write_store_cfg("circuit-windows",
                              {"built_artifact_windows": "circuit-windows.exe"})
        with mock.patch.object(ship, "win_build", return_value=exe), \
             mock.patch.object(ship, "win_store_submit") as submit:
            with self.assertRaises(SystemExit):
                ship.cmd_ship_windows("circuit-windows", None, None)
        submit.assert_not_called()
        self.assertEqual(len(self._lines(self.staging)), 0)
        self.assertEqual(len(self._lines(self.ledger)), 0)

    # ---- (d) store is the DEFAULT when a config omits `distribution` ----
    def test_store_is_default_distribution(self):
        cfg = dict(WIN_CFG)
        cfg.pop("distribution", None)        # omit it entirely
        cfg["built_artifact_windows"] = "circuit-windows.msix"
        path = os.path.join(self.tmp, "circuit-windows.toml")
        with open(path, "w") as f:
            for k, v in cfg.items():
                if isinstance(v, list):
                    inner = ", ".join(f'"{x}"' for x in v)
                    f.write(f'{k} = [{inner}]\n')
                else:
                    f.write(f'{k} = "{v}"\n')
        loaded = ship.load_any(path)         # validates; must default to store
        self.assertEqual(loaded.get("distribution", "store"), "store")
        with mock.patch.object(ship, "win_store_submit") as submit, \
             mock.patch("subprocess.run"):
            rc = ship.cmd_ship_windows("circuit-windows", None, None)  # no marker => stage
        self.assertEqual(rc, 0)
        submit.assert_not_called()
        st = self._lines(self.staging)
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["channel"], "store")


class WinBuildCiPullTest(unittest.TestCase):
    """First real coverage of win_build's ci-pull run-id resolution. Every other
    Windows test mocks win_build wholesale, so this path — latest-run lookup,
    {run} substitution, and its fail-closed guards — was previously unproven.
    Mocks ONLY the gh/subprocess boundary (ship._run for the run-list lookup and
    subprocess.run for the download), never win_build itself, so the real
    resolution + substitution logic runs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="winbuild-test-")
        self.work = os.path.join(self.tmp, "work")
        mock.patch.object(ship, "WORK_DIR", self.work).start()
        self.addCleanup(mock.patch.stopall)
        self.cfg = dict(WIN_CFG)

    def _download_that_writes_artifact(self, seen=None):
        """A subprocess.run stand-in that 'downloads' by creating the pulled
        artifact inside the --dir it was told to, then returns rc=0."""
        def _side(cmd, **kw):
            if seen is not None:
                seen["cmd"] = cmd
            m = re.search(r"--dir (\S+)", cmd)
            os.makedirs(m.group(1), exist_ok=True)
            open(os.path.join(m.group(1), self.cfg["built_artifact_windows"]), "w").close()
            return mock.Mock(returncode=0)
        return _side

    def test_latest_run_resolution_pins_id_into_download_command(self):
        seen = {}
        gh_list = mock.Mock(stdout="28862877880\n", stderr="", returncode=0)
        with mock.patch.object(ship, "_run", return_value=gh_list), \
             mock.patch("subprocess.run", side_effect=self._download_that_writes_artifact(seen)):
            art = ship.win_build(self.cfg, "circuit-windows", "ci-pull", None)
        # the resolved run id is injected straight into the {run} slot, single-spaced
        self.assertIn("gh run download 28862877880 --repo", seen["cmd"])
        self.assertNotIn("download  ", seen["cmd"])  # no orphaned empty slot survives
        self.assertTrue(art.endswith(self.cfg["built_artifact_windows"]))
        self.assertTrue(os.path.isfile(art))

    def test_explicit_run_ref_skips_lookup_and_pins_id(self):
        seen = {}

        def _no_lookup(*a, **kw):
            raise AssertionError("latest-run lookup must not run when --run is given")

        with mock.patch.object(ship, "_run", side_effect=_no_lookup), \
             mock.patch("subprocess.run", side_effect=self._download_that_writes_artifact(seen)):
            ship.win_build(self.cfg, "circuit-windows", "ci-pull", "99")
        self.assertIn("gh run download 99 --repo", seen["cmd"])

    def test_missing_run_placeholder_fails_closed(self):
        # A template with no {run} slot would pull an ambiguous 'gh run download'.
        self.cfg["build_cmd_ci"] = ("gh run download --repo mthburnsbarber-web/BlackLabelCircuit "
                                    "--name x --dir {out}")
        gh_list = mock.Mock(stdout="123\n", stderr="", returncode=0)
        with mock.patch.object(ship, "_run", return_value=gh_list), \
             mock.patch("subprocess.run") as sub:
            with self.assertRaises(SystemExit):
                ship.win_build(self.cfg, "circuit-windows", "ci-pull", None)
        sub.assert_not_called()  # never reached the download

    def test_missing_repo_slug_fails_closed(self):
        self.cfg["build_cmd_ci"] = "gh run download {run} --name x --dir {out}"  # no --repo
        with mock.patch("subprocess.run") as sub:
            with self.assertRaises(SystemExit):
                ship.win_build(self.cfg, "circuit-windows", "ci-pull", None)
        sub.assert_not_called()

    def test_no_successful_ci_run_fails_closed(self):
        empty = mock.Mock(stdout="\n", stderr="", returncode=0)  # no green run to pull
        with mock.patch.object(ship, "_run", return_value=empty), \
             mock.patch("subprocess.run") as sub:
            with self.assertRaises(SystemExit):
                ship.win_build(self.cfg, "circuit-windows", "ci-pull", None)
        sub.assert_not_called()

    def test_artifact_absent_after_pull_fails_closed(self):
        # Download "succeeds" (rc=0) but writes nothing — the isfile guard must trip.
        gh_list = mock.Mock(stdout="28862877880\n", stderr="", returncode=0)
        with mock.patch.object(ship, "_run", return_value=gh_list), \
             mock.patch("subprocess.run", return_value=mock.Mock(returncode=0)):
            with self.assertRaises(SystemExit):
                ship.win_build(self.cfg, "circuit-windows", "ci-pull", None)

    def test_rig_mode_blocked_founder_gate(self):
        with mock.patch("subprocess.run") as sub:
            with self.assertRaises(SystemExit):
                ship.win_build(self.cfg, "circuit-windows", "rig", None)
        sub.assert_not_called()  # no build attempted with no hypervisor


if __name__ == "__main__":
    unittest.main(verbosity=2)
