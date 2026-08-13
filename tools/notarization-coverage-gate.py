#!/usr/bin/env python3
"""notarization-coverage-gate — prove a notarization ticket COVERS the artifact.

"Accepted" alone is not coverage: a .pkg can be Accepted while an inner .app
was skipped (unsigned nested component, stale payload) and Gatekeeper then
blocks that app on first launch. This gate fetches the notarytool submission
LOG (the JSON behind LogFileURL) and asserts, fail-closed:

  1. log fetch + parse succeeds                                  else exit 1
  2. status == "Accepted"                                        else exit 2
  3. no blocking issues (severity other than "warning";
     warnings are printed loudly but do not fail Accepted logs)  else exit 3
  4. artifact coverage in ticketContents:
       *.pkg  — every inner .app named by the pkg's own component
                PackageInfo <bundle path="….app"> entries has a ticket
                entry (plus any --require-app extras)
       *.app  — the app bundle itself has a ticket entry
       other  — ticketContents is non-empty (plus --require-app)  else exit 4
  5. xcrun stapler validate <artifact> (skipped for .zip — zips
     cannot carry a staple; ship.py staples the .app inside)     else exit 5
  6. usage / dependency / auth errors                            exit 6

Standalone:
  tools/notarization-coverage-gate.py --submission-id <UUID> --artifact <path>
      [--require-app Name.app]... [--skip-staple]

Wired into bl-ship stage_notarize (ship.py) after Accepted+staple, so every
macOS ship proves ticket coverage before upload. Auth mirrors ship.py
_notary_auth: BL_NOTARY keychain profile when resolvable, else the App Store
Connect API key from ~/.utah/secrets/notary.json. python3-stdlib only.
"""
import argparse
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

NOTARY_PROFILE = os.environ.get("NOTARY_PROFILE", "BL_NOTARY")
NOTARY_SECRETS = os.path.expanduser("~/.utah/secrets/notary.json")


def die(code, msg):
    print(f"coverage-gate: FAIL [{code}] {msg}", file=sys.stderr)
    raise SystemExit(code)


def notary_auth():
    r = subprocess.run(["security", "find-generic-password", "-s",
                        f"com.apple.gke.notary.tool.saved-creds.{NOTARY_PROFILE}"],
                       capture_output=True)
    if r.returncode == 0:
        return ["--keychain-profile", NOTARY_PROFILE], f"keychain:{NOTARY_PROFILE}"
    try:
        with open(NOTARY_SECRETS) as f:
            d = json.load(f)
        key = os.path.expanduser(d["key_path"])
        if os.path.exists(key) and d.get("key_id") and d.get("issuer"):
            return (["--key", key, "--key-id", d["key_id"], "--issuer", d["issuer"]],
                    "inline-apikey")
    except (OSError, ValueError, KeyError):
        pass
    die(6, f"no notary auth: keychain profile {NOTARY_PROFILE} missing and "
           f"{NOTARY_SECRETS} unusable")


def fetch_log(sid):
    auth, label = notary_auth()
    tmp = tempfile.mkdtemp(prefix="covgate-")
    out = os.path.join(tmp, "log.json")
    r = subprocess.run(["xcrun", "notarytool", "log", sid, *auth, out],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die(1, f"notarytool log fetch failed ({label}): "
               f"{(r.stderr or r.stdout).strip()[:300]}")
    try:
        with open(out) as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        die(1, f"submission log unparsable: {e}")


def expected_apps_for_pkg(pkg_path):
    """Inner .app names from the pkg's OWN component manifests (no payload extraction)."""
    tmp = tempfile.mkdtemp(prefix="covgate-pkg-")
    dest = os.path.join(tmp, "x")
    r = subprocess.run(["pkgutil", "--expand", pkg_path, dest],
                       capture_output=True, text=True)
    if r.returncode != 0:
        die(6, f"pkgutil --expand failed: {(r.stderr or r.stdout).strip()[:200]}")
    apps = set()
    for root, _dirs, files in os.walk(dest):
        for fn in files:
            if fn != "PackageInfo":
                continue
            data = open(os.path.join(root, fn), encoding="utf-8", errors="replace").read()
            for m in re.finditer(r'<bundle[^>]*\spath="([^"]+\.app)"', data):
                apps.add(os.path.basename(m.group(1)))
    shutil.rmtree(tmp, ignore_errors=True)
    return sorted(apps)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--submission-id", required=True)
    ap.add_argument("--artifact", required=True)
    ap.add_argument("--require-app", action="append", default=[],
                    help="extra inner .app name that MUST hold a ticket")
    ap.add_argument("--skip-staple", action="store_true")
    a = ap.parse_args()
    art = os.path.expanduser(a.artifact)
    if not os.path.exists(art):
        die(6, f"artifact missing: {art}")

    log = fetch_log(a.submission_id)
    status = log.get("status")
    print(f"coverage-gate: submission {a.submission_id}")
    print(f"  status: {status} | statusSummary: {log.get('statusSummary', '?')}")
    if status != "Accepted":
        die(2, f"status is {status!r}, not Accepted")

    issues = log.get("issues") or []
    blocking = [i for i in issues if (i.get("severity") or "").lower() != "warning"]
    for i in issues:
        sev = (i.get("severity") or "?").lower()
        print(f"  issue[{sev}]: {i.get('path', '?')}: {i.get('message', '?')[:140]}")
    if blocking:
        die(3, f"{len(blocking)} blocking issue(s) in submission log")
    print(f"  issues: {'none' if not issues else str(len(issues)) + ' warning(s) only'}")

    tickets = log.get("ticketContents") or []
    ticket_paths = [t.get("path", "") for t in tickets]
    print(f"  ticketContents: {len(tickets)} entries")
    low = art.lower()
    if low.endswith(".pkg"):
        expected = expected_apps_for_pkg(art)
    elif low.endswith(".app") or low.rstrip("/").endswith(".app"):
        expected = [os.path.basename(art.rstrip("/"))]
    else:
        expected = []
    expected = sorted(set(expected) | set(a.require_app))
    if not expected and not tickets:
        die(4, "no ticketContents at all — nothing was ticketed")
    missing = []
    for app in expected:
        hit = any(p.endswith("/" + app) or p == app or ("/" + app + "/") in p
                  for p in ticket_paths)
        print(f"  inner-app ticket {'PASS' if hit else 'MISS'}: {app}")
        if not hit:
            missing.append(app)
    if missing:
        die(4, f"inner .app(s) WITHOUT a notarization ticket: {', '.join(missing)}")

    if a.skip_staple or low.endswith(".zip"):
        print("  staple: SKIPPED (zip artifacts cannot carry a staple)")
    else:
        r = subprocess.run(["xcrun", "stapler", "validate", art],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die(5, f"stapler validate failed: {(r.stdout or r.stderr).strip()[:200]}")
        print(f"  staple: PASS (stapler validate {os.path.basename(art)})")

    print(f"coverage-gate: PASS — Accepted, no blocking issues, "
          f"{len(expected)} inner app(s) ticketed, staple checked")


if __name__ == "__main__":
    main()
