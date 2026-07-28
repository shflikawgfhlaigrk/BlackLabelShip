#!/usr/bin/env python3
"""Regression lock for the sink-side secret redaction in ship.py.

stdlib unittest only (repo is py3.9-safe, no pytest on the ship road).
Run: python3 test_redaction.py   (or: python3 -m unittest test_redaction -v)

bl-ship's output goes to an operator terminal AND to CI logs. Every credential
this road handles rides in a subprocess argv (notarytool --key/--key-id/--issuer,
signtool /p), and a tool error or a TimeoutExpired/CalledProcessError renders the
full argv. These tests assert the scrub happens at the sink, so a print added
later is safe by default.
"""
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ship  # noqa: E402


class RedactionTest(unittest.TestCase):
    def setUp(self):
        self._saved = set(ship._SECRETS)
        self.addCleanup(lambda: (ship._SECRETS.clear(), ship._SECRETS.update(self._saved)))

    # ---- argv shapes emitted by the tools this road shells out to ----
    def test_notarytool_argv_credentials_are_masked(self):
        argv = ("xcrun notarytool submit app.zip --key /Users/x/.utah/secrets/AuthKey_ABC.p8 "
                "--key-id 9XY8ZW7V6U --issuer 69a6de70-1111-2222-3333-444455556666")
        out = ship.redact(argv)
        for leaked in ("AuthKey_ABC.p8", "9XY8ZW7V6U", "69a6de70-1111-2222-3333-444455556666"):
            self.assertNotIn(leaked, out, f"{leaked} survived redaction: {out}")

    def test_signtool_pfx_password_is_masked(self):
        out = ship.redact("signtool sign /fd SHA256 /p S3cretPfxPw app.exe")
        self.assertNotIn("S3cretPfxPw", out)
        self.assertIn("app.exe", out)  # non-secret argv survives

    def test_apple_app_specific_password_is_masked(self):
        out = ship.redact("notarytool: auth failed for abcd-efgh-ijkl-mnop")
        self.assertNotIn("abcd-efgh-ijkl-mnop", out)

    def test_bearer_token_is_masked(self):
        out = ship.redact("authorization: Bearer gho_0123456789abcdefXYZ")
        self.assertNotIn("gho_0123456789abcdefXYZ", out)

    def test_dl_gate_key_in_url_is_masked(self):
        url = "https://example.invalid/dl/app.zip?k=c76acb879e8fe0d8d69a9b081e01758d"
        out = ship.redact(url)
        self.assertNotIn("c76acb879e8fe0d8d69a9b081e01758d", out)

    # ---- runtime-registered values ----
    def test_registered_secret_is_masked_anywhere(self):
        ship.register_secret("SUPERSECRETVALUE123")
        out = ship.redact("tool said: SUPERSECRETVALUE123 is invalid")
        self.assertNotIn("SUPERSECRETVALUE123", out)

    def test_unsigned_sentinel_is_never_registered(self):
        ship.register_secret(ship.UNSIGNED)
        self.assertNotIn(ship.UNSIGNED, ship._SECRETS)
        # the STAGED-ONLY messages must still say "UNSIGNED" out loud
        self.assertIn("UNSIGNED", ship.redact("staged: UNSIGNED (founder gate)"))

    def test_home_path_is_collapsed_not_published(self):
        home = os.path.expanduser("~")
        out = ship.redact(f"{home}/.utah/secrets/notary.json unusable")
        self.assertNotIn(home, out)
        self.assertIn("~/.utah/secrets/notary.json", out)

    # ---- the sink itself ----
    def test_fail_redacts_before_printing(self):
        ship.register_secret("LEAKYCREDENTIAL9")
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf), self.assertRaises(SystemExit):
            ship.fail("notarize failed: LEAKYCREDENTIAL9")
        printed = buf.getvalue()
        self.assertNotIn("LEAKYCREDENTIAL9", printed)
        self.assertIn("FAIL:", printed)
        self.assertIn("notarize failed:", printed)  # message still actionable

    # ---- end-to-end: the real _notary_auth() road, not just redact() in isolation ----
    def test_notary_auth_credentials_never_reach_the_fail_sink(self):
        """Drive synthetic credentials through the real inline-API-key path.

        This is the property the CodeQL py/clear-text-logging alert on the fail()
        sink turns on, so it is locked end-to-end rather than pattern-by-pattern:
        _notary_auth() -> notarytool argv -> fail(). The first assertion is the
        positive control — if the sentinel ever stops reaching argv the rest of
        this test would pass vacuously.
        """
        import json
        import tempfile

        sentinel = "SENTINEL_LEAK_CANARY_12345"
        tmp = tempfile.mkdtemp(prefix="ship-redaction-test-")
        key_path = os.path.join(tmp, "AuthKey_%s.p8" % sentinel)
        with open(key_path, "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----\n")
        notary_json = os.path.join(tmp, "notary.json")
        with open(notary_json, "w") as f:
            json.dump({"key_path": key_path, "key_id": sentinel,
                       "issuer": sentinel + "-6de70-1111-2222"}, f)

        with mock.patch.object(ship, "NOTARY_SECRETS", notary_json), \
             mock.patch.object(ship, "_run", return_value=mock.Mock(returncode=1)):
            auth, label = ship._notary_auth()   # returncode=1 => keychain miss => inline fallback

        self.assertEqual(label, "inline-apikey")
        argv = ["xcrun", "notarytool", "submit", "app.zip"] + list(auth) + ["--no-wait"]
        argv_str = " ".join(argv)
        # POSITIVE CONTROL: the credential really does ride in the argv.
        self.assertIn(sentinel, argv_str, "sentinel must reach argv or this test is vacuous")

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf), self.assertRaises(SystemExit):
            ship.fail("notarize: submit failed: " + argv_str)
        printed = buf.getvalue()
        self.assertNotIn(sentinel, printed, "credential survived the fail() sink: %s" % printed)
        self.assertIn("notarize: submit failed:", printed)  # message stays actionable

    def test_subprocess_argv_dump_is_masked(self):
        """TimeoutExpired / CalledProcessError render the FULL argv — the exact
        vector this redaction exists for."""
        import subprocess

        ship.register_secret("SENTINELKEYID9XY8")
        argv = ["xcrun", "notarytool", "submit", "app.zip",
                "--key-id", "SENTINELKEYID9XY8", "--issuer", "abc-123"]
        for exc in (subprocess.TimeoutExpired(argv, 30),
                    subprocess.CalledProcessError(1, argv, output="boom")):
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf), self.assertRaises(SystemExit):
                ship.fail("notarize: %s" % exc)
            self.assertNotIn("SENTINELKEYID9XY8", buf.getvalue(),
                             "%s leaked argv" % type(exc).__name__)

    def test_notary_secrets_absolute_path_not_in_no_auth_message(self):
        # The no-auth message must name the file without publishing $HOME.
        self.assertEqual(ship.NOTARY_SECRETS_DISPLAY, "~/.utah/secrets/notary.json")
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf), \
             mock.patch.object(ship, "_run", return_value=mock.Mock(returncode=1)), \
             mock.patch.object(ship, "NOTARY_SECRETS", "/nonexistent/notary.json"), \
             self.assertRaises(SystemExit):
            ship._notary_auth()
        printed = buf.getvalue()
        self.assertNotIn(os.path.expanduser("~") + "/.utah", printed)
        self.assertIn("~/.utah/secrets/notary.json", printed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
