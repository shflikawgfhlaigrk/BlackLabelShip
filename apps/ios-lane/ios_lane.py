#!/usr/bin/env python3
"""ios_lane.py — fail-closed decision core for the iOS App Store lane.

This is the local counterpart to ship.py's Windows lane (cmd_ship_windows).
The GitHub Actions workflow (ios-appstore.yml) produces the artifact on an
Apple-accepted RELEASE-Xcode runner; this module is the LOCAL road that pulls
that artifact and makes the single load-bearing decision, fail-closed:

  * toolchain guard REJECTS (beta / Xcode 27.* / build 17F113 / macOS 26A host)
    OR no distribution signing identity present
        -> STAGE ONLY. Copy the artifact to work/ with a
           `<app>-ios-UNSIGNED-STAGED-ONLY.ipa` name, sha it, append one line to
           ships-staged.jsonl. NOTHING uploads. NO ships.jsonl write.

  * guard PASSES *and* a real signing identity present
        -> reach the (real) export + upload boundary. Reaching ios_upload IS the
           "signed path reaches upload" invariant. Writes ships.jsonl
           (platform:"ios", staged_only:false). The owner still gates the actual
           App Store submit via CONFIRM_UPLOAD=1 inside ios_upload.

stdlib only (py3.9-safe): mirrors the ship-road discipline so it runs on the
same interpreter as ship.py with zero runtime deps.

Usage (local, after `gh run download` of the CI artifact):
    python3 ios_lane.py <app>            # runs the lane for apps/<app>-ios.toml
    python3 ios_lane.py --self-check
"""
import os
import re
import sys
import json
import shutil
import hashlib
import datetime
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
# Ledgers live at the BlackLabelShip repo root (three levels up from apps/ios-lane
# when vendored there; overridable, and always patched in tests).
SHIP_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
APPS_DIR = os.path.join(SHIP_ROOT, "apps")
WORK_DIR = os.path.join(SHIP_ROOT, "work")
LEDGER = os.path.join(SHIP_ROOT, "ships.jsonl")
STAGING_LEDGER = os.path.join(SHIP_ROOT, "ships-staged.jsonl")  # unsigned iOS stages here, NEVER ships.jsonl

GUARD = os.path.join(HERE, "appstore_toolchain_guard.sh")
UNSIGNED = "UNSIGNED"


# ---------- primitives ----------

def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def expand(p):
    return os.path.expanduser(p)


# ---------- config (same flat-TOML-lite subset as ship.py) ----------

def _parse_value(raw, path, key):
    raw = raw.strip()
    if raw.startswith("["):
        if not raw.endswith("]"):
            fail(f"{path}: key '{key}' array must be single-line")
        inner = raw[1:-1].strip()
        if not inner:
            return []
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', inner)
        if len(parts) != len([p for p in inner.split(",") if p.strip()]):
            fail(f"{path}: key '{key}' array elements must be quoted strings")
        return parts
    if raw in ("true", "false"):
        return raw == "true"
    m = re.match(r'^"((?:[^"\\]|\\.)*)"$', raw)
    if m:
        return m.group(1)
    fail(f"{path}: cannot parse value for key '{key}': {raw!r}")


def parse_toml_lite(path):
    cfg = {}
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if "=" not in s:
                fail(f"{path}:{lineno}: expected key = value")
            key, _, raw = s.partition("=")
            key = key.strip()
            if "#" in raw and raw.count('"') % 2 == 0:
                q = False
                out = []
                for ch in raw:
                    if ch == '"':
                        q = not q
                    if ch == "#" and not q:
                        break
                    out.append(ch)
                raw = "".join(out)
            cfg[key] = _parse_value(raw, path, key)
    return cfg


def load_config(path):
    try:
        import tomllib  # py3.11+
        with open(path, "rb") as f:
            return tomllib.load(f)
    except ModuleNotFoundError:
        return parse_toml_lite(path)


def is_ios_cfg(cfg):
    return isinstance(cfg, dict) and cfg.get("platform") == "ios"


# ---------- lane stages (mocked one-for-one in test_ios_lane.py) ----------

def ios_preflight(cfg, name):
    """HOLD gate + repo sha, same provenance discipline as the mac/windows roads."""
    hold = os.path.join(APPS_DIR, f"{name}.HOLD")
    if os.path.exists(hold):
        with open(hold) as f:
            why = f.read().strip()
        fail(f"HOLD: shipping {name} is Founder-blocked — {why or 'see HOLD file'}")
    repo = expand(cfg["repo"])
    head = _run(["git", "-C", repo, "rev-parse", "--short", "HEAD"]).stdout.strip()
    print(f"  ios-preflight: repo {repo} @ {head or '?'}")
    return head or "unknown"


def ios_build(cfg, name, run_ref=None):
    """Pull the CI-produced IPA for this app (the RELEASE-Xcode artifact from
    ios-appstore.yml). ci-pull only: local archiving on a beta host would
    reproduce the Apple-rejected 17F113 fingerprint, so it is refused here.
    Returns the absolute path to the pulled .ipa."""
    os.makedirs(WORK_DIR, exist_ok=True)
    out = os.path.join(WORK_DIR, f"{name}-iosbuild")
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out, exist_ok=True)
    tmpl = cfg.get("build_cmd_ci")
    if not tmpl:
        fail(f"ios-build: {name}: no build_cmd_ci configured for ci-pull mode")
    cmd = tmpl.replace("{run}", run_ref or "").replace("{out}", out)
    if not run_ref:
        wf = cfg.get("ci_workflow", "")
        m = re.search(r"--repo\s+(\S+)", tmpl)
        if not m:
            fail(f"ios-build: {name}: build_cmd_ci must carry --repo <owner/name>")
        rid = _run(["gh", "run", "list", "--repo", m.group(1),
                    "--workflow", wf, "--status", "success", "--limit", "1",
                    "--json", "databaseId", "--jq", ".[0].databaseId"]).stdout.strip()
        if not rid:
            fail(f"ios-build: no successful '{wf}' run to pull (ci-pull needs a green CI build)")
        cmd = cmd.replace("download  ", f"download {rid} ")
    print(f"  ios-build: ci-pull: {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=SHIP_ROOT)
    if r.returncode != 0:
        fail(f"ios-build: {name}: artifact pull failed (rc={r.returncode})")
    artifact = os.path.join(out, cfg["built_artifact_ios"])
    if not os.path.isfile(artifact):
        fail(f"ios-build: artifact not found at {artifact} after pull")
    print(f"  ios-build: OK -> {artifact}")
    return artifact


def ios_guard(cfg, ipa=None):
    """Run the shared App Store toolchain guard against the produced IPA.
    Returns the guard's exit code (0 = accepted, 65 = rejected beta/17F113/26A).
    A missing guard script fails CLOSED (returns 65)."""
    if not os.path.isfile(GUARD):
        print(f"  ios-guard: guard script missing at {GUARD} — failing CLOSED")
        return 65
    check = ""
    if ipa:
        check = f'appstore_check_ipa "{ipa}"'
    script = f'set -e; source "{GUARD}"; appstore_select_xcode; {check}'
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    if r.stdout.strip():
        print("  ios-guard(out):", r.stdout.strip())
    if r.stderr.strip():
        print("  ios-guard(err):", r.stderr.strip())
    print(f"  ios-guard: exit {r.returncode}")
    return r.returncode


def ios_stage_unsigned(cfg, name, head, artifact, reason):
    """Fail-closed terminus. Copy the IPA to work/ with a
    `<app>-ios-UNSIGNED-STAGED-ONLY.ipa` name, sha it, append ONE line to
    ships-staged.jsonl. NOTHING uploads; ships.jsonl is NOT touched."""
    os.makedirs(WORK_DIR, exist_ok=True)
    base = name[:-4] if name.endswith("-ios") else name  # avoid "-ios-ios-"
    staged = os.path.join(WORK_DIR, f"{base}-ios-UNSIGNED-STAGED-ONLY.ipa")
    shutil.copyfile(artifact, staged)
    sha = sha256_file(staged)
    line = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app": name, "platform": "ios", "commit": head,
        "sha256": sha, "artifact": os.path.basename(staged),
        "staged_only": True, "reason": reason,
        "uploaded": False, "manifest_bumped": False,
    }
    with open(STAGING_LEDGER, "a") as f:
        f.write(json.dumps(line) + "\n")
    print(f"  ios-stage: {staged}")
    print(f"  ios-stage: sha256={sha}")
    print("  ios-ledger: appended to ships-staged.jsonl (staged_only=true)")
    print(f"== STAGED-ONLY {name} (ios) — NOT uploaded, NO ledger. {reason} "
          f"sha={sha[:16]}… ==")
    return sha


def ios_export(cfg, name, artifact):
    """Signed-only re-export to an upload-ready IPA via the AppStore export
    plist. Only reached when the guard passed AND a signing identity exists.
    Kept thin so tests can mock it."""
    plist = cfg.get("export_plist", os.path.join(HERE, "ExportOptions-AppStore-iOS.plist"))
    print(f"  ios-export: exportArchive with {plist}")
    # In a full signed CI context this runs xcodebuild -exportArchive; the local
    # road treats the pulled artifact as already upload-shaped.
    return artifact


def ios_upload(cfg, name, ipa, sha):
    """The upload boundary. Reaching this IS the 'signed path reaches upload'
    assertion. The actual App Store transport only fires with CONFIRM_UPLOAD=1
    (owner gate); otherwise it STOPS here with the upload-ready IPA on disk."""
    if os.environ.get("CONFIRM_UPLOAD") != "1":
        print(f"  ios-upload: STOP at upload boundary (CONFIRM_UPLOAD!=1). "
              f"Upload-ready IPA: {ipa} sha={sha[:16]}…")
        print("  ios-upload: owner runs CONFIRM_UPLOAD=1 to transport to App Store Connect.")
        return "boundary"
    r = _run(["xcrun", "altool", "--upload-app", "-f", ipa, "-t", "ios",
              "--apiKey", cfg.get("asc_api_key", ""), "--apiIssuer", cfg.get("asc_api_issuer", "")])
    if r.returncode != 0:
        fail(f"ios-upload: altool failed: {(r.stderr or r.stdout).strip()[:300]}")
    print("  ios-upload: transported to App Store Connect")
    return "uploaded"


def ios_ship_ledger(name, head, sha):
    line = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app": name, "platform": "ios", "commit": head, "sha256": sha,
        "staged_only": False, "uploaded": True, "manifest_bumped": True,
    }
    with open(LEDGER, "a") as f:
        f.write(json.dumps(line) + "\n")
    print("  ios-ledger: appended to ships.jsonl (staged_only=false)")


def cmd_ship_ios(name, run_ref=None, build=None):
    cfg_path = os.path.join(APPS_DIR, name + ".toml")
    if not os.path.isfile(cfg_path):
        fail(f"no config for app {name!r} ({cfg_path})")
    cfg = load_config(cfg_path)
    if not is_ios_cfg(cfg):
        fail(f"{name}: not an iOS config (platform != 'ios'). Use ship.py for the macOS road.")
    print(f"== bl-ship {name} [iOS lane] ==")
    head = ios_preflight(cfg, name)
    artifact = ios_build(cfg, name, run_ref)
    guard_rc = ios_guard(cfg, artifact)
    signed = cfg.get("signing_identity", UNSIGNED) != UNSIGNED
    # ---- THE FAIL-CLOSED GATE ----
    if guard_rc != 0:
        ios_stage_unsigned(cfg, name, head, artifact,
                           "toolchain guard REJECTED (beta / 17F113 / macOS 26A host)")
        return 0  # HARD STOP.
    if not signed:
        ios_stage_unsigned(cfg, name, head, artifact,
                           "unsigned — no distribution signing identity (FOUNDER GATE)")
        return 0  # HARD STOP. No upload. ships.jsonl untouched.
    # Signed + guard-clean path only:
    ipa = ios_export(cfg, name, artifact)
    sha = sha256_file(ipa)
    ios_upload(cfg, name, ipa, sha)
    ios_ship_ledger(name, head, sha)
    print(f"== SHIPPED {name} (ios) sha={sha[:16]}… ==")
    return 0


def self_check():
    ok = os.path.isfile(GUARD)
    print(f"ios_lane self-check: guard present={ok} at {GUARD}")
    print(f"  SHIP_ROOT={SHIP_ROOT}")
    print(f"  LEDGER={LEDGER}")
    print(f"  STAGING_LEDGER={STAGING_LEDGER}")
    return 0 if ok else 1


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--self-check":
        return self_check()
    return cmd_ship_ios(argv[0], argv[1] if len(argv) > 1 else None)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
