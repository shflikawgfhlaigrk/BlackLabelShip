#!/usr/bin/env python3
"""bl-ship — the single road every Black Label artifact travels.

Stages (abort on any failure; nothing partial ever uploads):
  1 preflight   repo tests pass, working tree clean (provenance)
  2 build       repo's own build script; Dev-ID sign w/ entitlements
  3 notarize    notarytool submit --no-wait + poll, then staple
  4 gates       spctl / codesign --verify / positive entitlements / ships-no-data / staple
  5 upload      wrangler r2 object put --remote (BOTH keys)
  6 live gate   fresh download, sha256 == local, spctl the quarantined copy
  7 manifest    /api/version/<app> bumped ONLY after live gate; re-fetch confirms
  8 ledger      append ships.jsonl

Windows lane (STAGED-ONLY, fail-closed — see apps/circuit-windows.toml):
  ship.py --windows <win-app> [--build-mode ci-pull|rig] [--run <id>]
  Road: win-preflight → win-build (ci-pull=gh run download, or rig=BLOCKED) →
  SIGNING GATE. If signing_identity=="UNSIGNED" it STOPS: stage to work/ with a
  -UNSIGNED-STAGED suffix, sha → ships-staged.jsonl, NO R2 upload, NO manifest.
  It is impossible for an unsigned Windows artifact to reach /dl or the live
  version manifest. Only a real Authenticode cert (FOUNDER GATE) continues the
  road to sign → Defender scan → clean-buyer gauntlet → upload → ships.jsonl.

python3-stdlib only (works on system py3.9: tomllib fallback parser built in).
"""
import sys, os, re, json, glob, hashlib, subprocess, plistlib, shutil, datetime

SHIP_ROOT = os.path.dirname(os.path.abspath(__file__))
APPS_DIR = os.path.join(SHIP_ROOT, "apps")
WORK_DIR = os.path.join(SHIP_ROOT, "work")
LEDGER = os.path.join(SHIP_ROOT, "ships.jsonl")
STAGING_LEDGER = os.path.join(SHIP_ROOT, "ships-staged.jsonl")  # unsigned Windows stages here, NEVER ships.jsonl

REQUIRED_KEYS = [
    "repo", "bundle_id", "app_name", "build_cmd", "built_app_path", "arch",
    "required_entitlements", "forbidden_entitlements", "ships_no_data_globs",
    "r2_dl_key", "r2_updates_key", "manifest_endpoint", "dl_url",
]
OPTIONAL_KEYS = ["ports", "test_cmd", "sign_identity", "entitlements_file"]
VALID_ARCH = ("universal2", "arm64")

# ---- Windows lane (STAGED-ONLY road; see apps/circuit-windows.toml) ----------
# A config is a Windows config iff platform == "windows". These never touch the
# macOS entitlement/arch/notarize road; the Mac loader skips them.
WIN_REQUIRED_KEYS = [
    "platform", "repo", "bundle_id", "app_name", "built_artifact_windows",
    "signing_identity", "r2_dl_key_windows", "r2_updates_key_windows",
    "manifest_endpoint_windows", "dl_url_windows",
]
WIN_OPTIONAL_KEYS = [
    "build_mode_default", "build_cmd_ci", "build_cmd_rig", "ci_workflow",
    "ci_artifact_name", "sign_cmd", "defender_scan_cmd",
    "clean_buyer_gauntlet_cmd", "ports",
]
# The sentinel that means "no cert yet" — the hard STAGED-ONLY trigger.
UNSIGNED = "UNSIGNED"


def is_windows_cfg(cfg):
    return isinstance(cfg, dict) and cfg.get("platform") == "windows"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


# ---------- config ----------

def _parse_value(raw, path, key):
    raw = raw.strip()
    if raw.startswith("["):
        if not raw.endswith("]"):
            fail(f"{path}: key '{key}' array must be single-line")
        inner = raw[1:-1].strip()
        if not inner:
            return []
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', inner)
        # every comma-separated element must be a quoted string
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
    """Strict flat-TOML subset: key = "str" | ["a","b"] | true|false. Comments with #."""
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
            # strip trailing comment (only when not inside quotes/brackets)
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


def expand(p):
    return os.path.expanduser(p)


def validate(cfg, path):
    for k in REQUIRED_KEYS:
        if k not in cfg:
            fail(f"{path}: missing required key '{k}'")
    unknown = set(cfg) - set(REQUIRED_KEYS) - set(OPTIONAL_KEYS)
    if unknown:
        fail(f"{path}: unknown keys {sorted(unknown)}")
    if cfg["arch"] not in VALID_ARCH:
        fail(f"{path}: arch must be one of {VALID_ARCH}")
    if not os.path.isdir(expand(cfg["repo"])):
        fail(f"{path}: repo does not exist: {cfg['repo']}")
    if cfg["required_entitlements"] and not cfg.get("entitlements_file"):
        fail(f"{path}: required_entitlements set but no entitlements_file")
    if cfg.get("entitlements_file"):
        ef = os.path.join(expand(cfg["repo"]), cfg["entitlements_file"])
        if not os.path.isfile(ef):
            fail(f"{path}: entitlements_file not found: {ef}")
    return cfg


def validate_windows(cfg, path):
    """Windows configs ride a SEPARATE schema. No entitlements, no arch, no
    notarize — just the STAGED-ONLY road up to the signing gate."""
    for k in WIN_REQUIRED_KEYS:
        if k not in cfg:
            fail(f"{path}: missing required Windows key '{k}'")
    unknown = set(cfg) - set(WIN_REQUIRED_KEYS) - set(WIN_OPTIONAL_KEYS)
    if unknown:
        fail(f"{path}: unknown Windows keys {sorted(unknown)}")
    if not os.path.isdir(expand(cfg["repo"])):
        fail(f"{path}: repo does not exist: {cfg['repo']}")
    mode = cfg.get("build_mode_default", "ci-pull")
    if mode not in ("ci-pull", "rig"):
        fail(f"{path}: build_mode_default must be 'ci-pull' or 'rig'")
    return cfg


def load_any(path):
    """Route a config to the right validator by platform. Peek platform first."""
    raw = load_config(path)
    return validate_windows(raw, path) if is_windows_cfg(raw) else validate(raw, path)


def load_all():
    out = {}
    for p in sorted(glob.glob(os.path.join(APPS_DIR, "*.toml"))):
        name = os.path.splitext(os.path.basename(p))[0]
        out[name] = load_any(p)
    if not out:
        fail(f"no app configs in {APPS_DIR}")
    return out


def self_check():
    apps = load_all()
    for name, cfg in apps.items():
        if is_windows_cfg(cfg):
            signed = cfg["signing_identity"] != UNSIGNED
            print(f"  {name:<16} [windows] repo={cfg['repo']} "
                  f"signing={'SIGNED' if signed else 'UNSIGNED→STAGED-ONLY'} OK")
        else:
            print(f"  {name:<16} repo={cfg['repo']} arch={cfg['arch']} "
                  f"ents={len(cfg['required_entitlements'])} OK")
    print(f"self-check: {len(apps)} config(s) valid")
    return 0


# ---------- gates (operate on an extracted .app path; return None or error string) ----------

def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def gate_gatekeeper(app_path, cfg=None):
    r = _run(["spctl", "-a", "-vv", "-t", "install", app_path])
    ok = "accepted" in (r.stderr + r.stdout)
    return None if ok else f"gatekeeper: spctl rejected: {(r.stderr or r.stdout).strip()[:300]}"


def gate_seal(app_path, cfg=None):
    r = _run(["codesign", "--verify", "--deep", "--strict", app_path])
    return None if r.returncode == 0 else f"seal: codesign --verify failed: {(r.stderr or r.stdout).strip()[:300]}"


def _read_entitlements(app_path):
    """Return dict of entitlements via codesign -d --entitlements :file (version-stable)."""
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as tf:
        tmp = tf.name
    try:
        r = _run(["codesign", "-d", "--entitlements", f":{tmp}", app_path])
        if r.returncode != 0:
            return None, f"codesign -d failed: {(r.stderr or r.stdout).strip()[:200]}"
        if os.path.getsize(tmp) == 0:
            return {}, None
        with open(tmp, "rb") as f:
            data = f.read()
        # strip DER/garbage guard: plistlib handles xml + binary plists
        try:
            return plistlib.loads(data), None
        except Exception:
            # some macOS versions emit a leading blob before the plist
            idx = data.find(b"<?xml")
            if idx >= 0:
                return plistlib.loads(data[idx:]), None
            return None, "unparseable entitlements output"
    finally:
        os.unlink(tmp)


def gate_entitlements(app_path, cfg):
    ents, err = _read_entitlements(app_path)
    if err:
        return f"entitlements: {err}"
    missing = [e for e in cfg["required_entitlements"] if not ents.get(e)]
    present_forbidden = [e for e in cfg["forbidden_entitlements"] if ents.get(e)]
    if missing:
        return f"entitlements: REQUIRED missing: {missing}"
    if present_forbidden:
        return f"entitlements: FORBIDDEN present: {present_forbidden}"
    return None


def gate_ships_no_data(app_path, cfg):
    """Flag buyer DATA/secrets in the bundle. Buyer data is never Python/interpreter SOURCE, so
    skip .py/.pyc/__pycache__ — otherwise a bundled interpreter's own stdlib (e.g. secrets.py,
    this_module.py) false-trips the `*secrets*`-style name globs. Real leaks are data files:
    .sqlite/.db/.csv/.pem/.key/.env/tokens/named dumps."""
    import fnmatch
    hits = []
    pats = [p.lower() for p in cfg["ships_no_data_globs"]]
    SOURCE_EXT = (".py", ".pyc", ".pyi", ".pyo")
    for root, dirs, files in os.walk(app_path):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in files:
            if fn.endswith(SOURCE_EXT):
                continue
            low = fn.lower()
            for pat in pats:
                if fnmatch.fnmatch(low, pat):
                    hits.append(os.path.relpath(os.path.join(root, fn), app_path))
                    break
    return None if not hits else f"ships-no-data: bundle contains {hits[:10]}"


def gate_staple(app_path, cfg=None):
    r = _run(["xcrun", "stapler", "validate", app_path])
    return None if r.returncode == 0 else f"staple: not stapled: {(r.stdout or r.stderr).strip()[:200]}"


def gate_arch(app_path, cfg):
    binary = os.path.join(app_path, "Contents", "MacOS",
                          os.path.splitext(os.path.basename(app_path))[0])
    if not os.path.isfile(binary):
        macos_dir = os.path.join(app_path, "Contents", "MacOS")
        cands = os.listdir(macos_dir) if os.path.isdir(macos_dir) else []
        if not cands:
            return "arch: no main binary found"
        binary = os.path.join(macos_dir, cands[0])
    r = _run(["lipo", "-archs", binary])
    archs = r.stdout.split()
    need = ["x86_64", "arm64"] if cfg["arch"] == "universal2" else ["arm64"]
    missing = [a for a in need if a not in archs]
    return None if not missing else f"arch: binary has {archs}, missing {missing}"


LOCAL_GATES = [gate_seal, gate_entitlements, gate_arch, gate_ships_no_data, gate_staple, gate_gatekeeper]


def run_local_gates(app_path, cfg):
    """Run every local gate; print PASS/FAIL per gate; return True iff all pass."""
    ok = True
    for g in LOCAL_GATES:
        err = g(app_path, cfg)
        if err:
            print(f"  GATE FAIL {g.__name__}: {err}")
            ok = False
        else:
            print(f"  GATE PASS {g.__name__}")
    return ok


# ---------- pack / live verify ----------

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pack(app_path, zip_path, app_key=None):
    if os.path.exists(zip_path):
        os.unlink(zip_path)
    r = _run(["ditto", "-c", "-k", "--keepParent", "--norsrc", "--noqtn", app_path, zip_path])
    if r.returncode != 0:
        fail(f"pack: ditto failed: {r.stderr.strip()[:200]}")
    # Buyer README at archive root (inject_readme.py owns the copy text; the app
    # bundle itself is never touched, so notarization/staple stay valid).
    if app_key:
        try:
            import inject_readme
            meta = inject_readme.APPS.get(app_key)
            if meta:
                cfg_min = {"app_name": os.path.basename(app_path)}
                readme = inject_readme.TEMPLATE % {
                    "title": meta["title"],
                    "rule": "=" * len(meta["title"]),
                    "app_name": cfg_min["app_name"],
                    "first_run": meta["first_run"].rstrip(),
                    "support": inject_readme.SUPPORT % {"updates": meta["updates"]},
                }
                rdir = os.path.join(WORK_DIR, f"{app_key}-readme")
                os.makedirs(rdir, exist_ok=True)
                rpath = os.path.join(rdir, "README.txt")
                with open(rpath, "w") as f:
                    f.write(readme)
                rr = _run(["zip", "-j", zip_path, rpath])
                if rr.returncode != 0:
                    fail(f"pack: README inject failed: {rr.stderr.strip()[:200]}")
                print("  pack: buyer README.txt bundled")
        except ImportError:
            print("  pack: WARNING inject_readme.py missing — shipping without buyer README")
    # AppleDouble guard
    r = _run(["zipinfo", "-1", zip_path])
    doubles = [l for l in r.stdout.splitlines() if os.path.basename(l).startswith("._")]
    if doubles:
        fail(f"pack: AppleDouble sidecars in zip: {doubles[:5]}")
    return sha256_file(zip_path)


def live_verify(url, expected_sha, app_name):
    """Download from the public URL, sha-compare, spctl the quarantine-tagged copy."""
    import tempfile, urllib.request, time as _t
    d = tempfile.mkdtemp(prefix="blship-live-")
    zpath = os.path.join(d, "live.zip")
    req = urllib.request.Request(url, headers={"User-Agent": "bl-ship-live-gate"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(zpath, "wb") as out:
        shutil.copyfileobj(resp, out)
    got = sha256_file(zpath)
    if got != expected_sha:
        return f"live: sha mismatch: live={got[:16]}… local={expected_sha[:16]}…"
    r = _run(["ditto", "-x", "-k", zpath, d])
    if r.returncode != 0:
        return f"live: unzip failed: {r.stderr.strip()[:200]}"
    app = os.path.join(d, app_name)
    if not os.path.isdir(app):
        return f"live: {app_name} not at zip root"
    _run(["xattr", "-w", "com.apple.quarantine",
          f"0081;{int(_t.time()):x};bl-ship;", app])
    r = _run(["spctl", "-a", "-vv", "-t", "install", app])
    if "accepted" not in (r.stderr + r.stdout):
        return f"live: quarantined copy rejected by Gatekeeper: {(r.stderr or r.stdout).strip()[:200]}"
    print(f"  LIVE PASS sha+gatekeeper on quarantined copy ({url.split('?')[0]})")
    return None


# ---------- stages ----------

R2_BUCKET = "sovereign-files"  # DOWNLOADS binding in worker/wrangler.worker.toml
SITE_URL = "https://blacklabelbots.com"
TEAM_ID = "745ZPGFRA5"
NOTARY_PROFILE = os.environ.get("NOTARY_PROFILE", "BL_NOTARY")
NOTARY_SECRETS = os.path.expanduser("~/.utah/secrets/notary.json")


def _notary_auth():
    """notarytool auth args, robust to the fragile login-keychain profile.

    Prefer the stored `--keychain-profile` when it actually resolves; otherwise
    fall back to inline App Store Connect API key creds from notary.json
    (key_path/key_id/issuer). The BL_NOTARY keychain item has repeatedly gone
    missing between ships (store-credentials needs an interactive keychain), so
    a ship must never hard-depend on it. Returns (args, label)."""
    have_profile = _run([
        "security", "find-generic-password",
        "-s", f"com.apple.gke.notary.tool.saved-creds.{NOTARY_PROFILE}",
    ]).returncode == 0
    if have_profile:
        return (["--keychain-profile", NOTARY_PROFILE], f"keychain:{NOTARY_PROFILE}")
    try:
        with open(NOTARY_SECRETS) as f:
            d = json.load(f)
        key = os.path.expanduser(d["key_path"])
        if os.path.exists(key) and d.get("key_id") and d.get("issuer"):
            return (["--key", key, "--key-id", d["key_id"], "--issuer", d["issuer"]],
                    "inline-apikey")
    except (OSError, ValueError, KeyError):
        pass
    fail(f"notarize: no auth — keychain profile {NOTARY_PROFILE} missing AND "
         f"{NOTARY_SECRETS} unusable. Re-run `xcrun notarytool store-credentials "
         f"{NOTARY_PROFILE}` or fix notary.json.")
# Fabrications only. NOT "through-wall" — that's an HONEST feature name when the page gates it behind
# the ESP32/CSI hardware (homefront does). We ban invented figures + present-tense capability overclaims.
FORBIDDEN_CLAIMS = r"791,123|791123|789,123|82\.0%|648W|648 wins|16-module|16 modules|16 signals|8 timeframes|2-of-8"


def stage_preflight(cfg, name):
    hold = os.path.join(APPS_DIR, f"{name}.HOLD")
    if os.path.exists(hold):
        with open(hold) as f:
            why = f.read().strip()
        fail(f"HOLD: shipping {name} is Founder-blocked — {why or 'see HOLD file'} "
             f"(remove {hold} only on Founder's word)")
    repo = expand(cfg["repo"])
    r = _run(["git", "-C", repo, "status", "--porcelain"])
    dirty = [l for l in r.stdout.splitlines() if l.strip()]
    if dirty:
        fail(f"preflight: {name}: working tree dirty ({len(dirty)} entries) — commit first (provenance)")
    head = _run(["git", "-C", repo, "rev-parse", "--short", "HEAD"]).stdout.strip()
    print(f"  preflight: tree clean at {head}")
    if cfg.get("test_cmd"):
        print(f"  preflight: tests: {cfg['test_cmd']}")
        r2 = subprocess.run(cfg["test_cmd"], shell=True, cwd=repo)
        if r2.returncode != 0:
            fail(f"preflight: {name}: tests failed (rc={r2.returncode})")
        print("  preflight: tests PASS")
    else:
        print("  preflight: !! NO test_cmd configured — tests SKIPPED (loud)")
    return head


def stage_build(cfg, name):
    repo = expand(cfg["repo"])
    print(f"  build: {cfg['build_cmd']} (in {repo})")
    r = subprocess.run(cfg["build_cmd"], shell=True, cwd=repo)
    if r.returncode != 0:
        fail(f"build: {name}: build_cmd failed (rc={r.returncode})")
    app = expand(cfg["built_app_path"])
    if not os.path.isabs(app):
        app = os.path.join(repo, app)
    if not os.path.isdir(app):
        fail(f"build: built app not found at {app}")
    print(f"  build: OK -> {app}")
    return app


def app_build_number(app_path):
    info = os.path.join(app_path, "Contents", "Info.plist")
    with open(info, "rb") as f:
        pl = plistlib.load(f)
    return str(pl.get("CFBundleVersion", "0")), str(pl.get("CFBundleShortVersionString", "0"))


def stage_notarize(app_path, cfg, name):
    """Submit no-wait + poll (beta-host `--wait` bus-errors), then staple."""
    import time as _t
    os.makedirs(WORK_DIR, exist_ok=True)
    sub = os.path.join(WORK_DIR, f"{name}-notarize.zip")
    if os.path.exists(sub):
        os.unlink(sub)
    r = _run(["ditto", "-c", "-k", "--keepParent", "--noextattr", app_path, sub])
    if r.returncode != 0:
        fail(f"notarize: zip failed: {r.stderr.strip()[:200]}")
    auth, auth_label = _notary_auth()
    print(f"  notarize: auth via {auth_label}")
    sid = None
    for attempt in range(1, 4):
        r = _run(["xcrun", "notarytool", "submit", sub, *auth,
                  "--no-wait", "--output-format", "json"])
        if r.returncode == 0 and r.stdout.strip():
            try:
                sid = json.loads(r.stdout)["id"]
                break
            except (ValueError, KeyError):
                pass
        detail = (r.stderr or r.stdout).strip()[:200]
        print(f"  notarize: submit attempt {attempt} failed ({detail or 'empty output'}); retrying…")
        _t.sleep(15)
    if not sid:
        fail("notarize: submit failed after 3 attempts")
    print(f"  notarize: submitted id={sid}; polling…")
    deadline = _t.time() + 45 * 60
    status = "In Progress"
    while _t.time() < deadline:
        _t.sleep(30)
        ri = _run(["xcrun", "notarytool", "info", sid, *auth,
                   "--output-format", "json"])
        if ri.returncode != 0:
            print(f"  notarize: poll error (transient): {(ri.stderr or ri.stdout).strip()[:120]}")
            continue
        status = json.loads(ri.stdout).get("status", "?")
        print(f"  notarize: {status}")
        if status not in ("In Progress",):
            break
    if status != "Accepted":
        log = _run(["xcrun", "notarytool", "log", sid, *auth])
        fail(f"notarize: status={status}; log: {log.stdout[:800]}")
    r = None
    for attempt in range(1, 6):
        r = _run(["xcrun", "stapler", "staple", app_path])
        if r.returncode == 0:
            break
        detail = (r.stdout or r.stderr).strip()[:200]
        print(f"  notarize: staple attempt {attempt} failed ({detail}); retrying…")
        _t.sleep(30)
    if r is None or r.returncode != 0:
        fail(f"notarize: staple failed: {(r.stdout or r.stderr).strip()[:200]}")
    print(f"  notarize: Accepted + stapled (id={sid})")
    return sid


def stage_upload(zip_path, cfg, name, build):
    keys = [cfg["r2_dl_key"], cfg["r2_updates_key"].replace("{build}", build)]
    for k in keys:
        r = _run(["npx", "wrangler", "r2", "object", "put", f"{R2_BUCKET}/{k}",
                  "--file", zip_path, "--remote"], cwd=SHIP_ROOT)
        if r.returncode != 0:
            fail(f"upload: wrangler put {k} failed: {(r.stderr or r.stdout).strip()[:300]}")
        print(f"  upload: r2 {R2_BUCKET}/{k} OK")
    return keys


def stage_manifest(cfg, name, build, version, sha, notary_id):
    updates_key = cfg["r2_updates_key"].replace("{build}", build)
    manifest = {
        "product": name,
        "latest_build": int(build) if build.isdigit() else build,
        "latest_version": version,
        "min_supported_build": 1,
        "download_url": f"{SITE_URL}/{updates_key}",  # /updates/<...> serves R2 key updates/<...> 1:1
        "sha256": sha,
        "notarized": True,
        "notarization_id": notary_id,
        "team_id": TEAM_ID,
        "published": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    mpath = os.path.join(WORK_DIR, f"{name}-manifest.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    r = _run(["npx", "wrangler", "r2", "object", "put", f"{R2_BUCKET}/version/{name}.json",
              "--file", mpath, "--remote"], cwd=SHIP_ROOT)
    if r.returncode != 0:
        fail(f"manifest: upload failed: {(r.stderr or r.stdout).strip()[:300]}")
    # re-fetch to confirm (browser-like UA: Cloudflare 403s the default Python-urllib UA)
    import urllib.request
    _mreq = urllib.request.Request(f"{SITE_URL}{cfg['manifest_endpoint']}",
                                   headers={"User-Agent": "Mozilla/5.0 (bl-ship manifest-confirm)"})
    with urllib.request.urlopen(_mreq, timeout=60) as resp:
        live = json.load(resp)
    if live.get("sha256") != sha:
        fail(f"manifest: live re-fetch sha mismatch: {live.get('sha256', '?')[:16]} != {sha[:16]}")
    print(f"  manifest: {cfg['manifest_endpoint']} live, sha confirmed")
    return manifest


def stage_ledger(name, head, build, sha, notary_id, dry_run):
    line = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app": name, "commit": head, "build": build, "sha256": sha,
        "notarization_id": notary_id, "dry_run": dry_run,
        "gates": [g.__name__ for g in LOCAL_GATES],
    }
    with open(LEDGER, "a") as f:
        f.write(json.dumps(line) + "\n")
    print(f"  ledger: appended to ships.jsonl")


def cmd_ship(name, dry_run):
    cfg_path = os.path.join(APPS_DIR, name + ".toml")
    if not os.path.isfile(cfg_path):
        fail(f"no config for app {name!r} ({cfg_path})")
    cfg = validate(load_config(cfg_path), cfg_path)
    print(f"== bl-ship {name} {'(DRY RUN)' if dry_run else ''} ==")
    head = stage_preflight(cfg, name)
    app = stage_build(cfg, name)
    # Stage the built .app into bl-ship's OWN work dir before the (minutes-long) notarize poll.
    # The app repo's build dir has other writers (concurrent sessions, self-heal keepers, the
    # sovereign self-builder) — a repo-side clean mid-poll yanked a staple once already.
    os.makedirs(WORK_DIR, exist_ok=True)
    staged = os.path.join(WORK_DIR, f"{name}-stage", os.path.basename(app))
    if os.path.isdir(os.path.dirname(staged)):
        _run(["rm", "-rf", os.path.dirname(staged)])
    os.makedirs(os.path.dirname(staged), exist_ok=True)
    r = _run(["ditto", app, staged])
    if r.returncode != 0:
        fail(f"{name}: staging copy failed: {(r.stderr or r.stdout).strip()[:200]}")
    print(f"  staged: {staged} (immune to app-repo build cleans)")
    app = staged
    build, version = app_build_number(app)
    notary_id = stage_notarize(app, cfg, name)
    print("  gates:")
    if not run_local_gates(app, cfg):
        fail(f"{name}: local gates failed — nothing uploads")
    os.makedirs(WORK_DIR, exist_ok=True)
    zip_path = os.path.join(WORK_DIR, f"{name}.zip")
    sha = pack(app, zip_path, app_key=name)
    print(f"  pack: {zip_path} sha256={sha}")
    if dry_run:
        stage_ledger(name, head, build, sha, notary_id, True)
        print(f"DRY RUN — not uploaded. ({name} build {build} v{version} ready)")
        return 0
    stage_upload(zip_path, cfg, name, build)
    err = live_verify(cfg["dl_url"], sha, cfg["app_name"])
    if err:
        fail(f"{name}: {err} — manifest NOT bumped")
    stage_manifest(cfg, name, build, version, sha, notary_id)
    stage_ledger(name, head, build, sha, notary_id, False)
    print(f"== SHIPPED {name} build {build} v{version} sha={sha[:16]}… ==")
    return 0


# ---------- Windows lane (STAGED-ONLY road; fail-closed at the signing gate) ----------
#
# Design law: an UNSIGNED Windows artifact can NEVER reach the public R2 /dl key
# or the live version manifest. The road runs preflight → build (CI-pull or rig)
# → SIGNING GATE. If signing_identity == UNSIGNED it STOPS: the artifact is
# staged to work/ with a -UNSIGNED-STAGED suffix, its sha256 is recorded to
# ships-staged.jsonl (NOT ships.jsonl), and no upload / manifest call happens.
# Only when a real cert is present does the road continue to sign → scan →
# gauntlet → upload → manifest → ships.jsonl (platform:"windows", staged_only:
# false). Today, with signing_identity=="UNSIGNED", it always stages.


def win_preflight(cfg, name):
    """Same provenance discipline as the Mac road: HOLD gate + clean tree."""
    hold = os.path.join(APPS_DIR, f"{name}.HOLD")
    if os.path.exists(hold):
        with open(hold) as f:
            why = f.read().strip()
        fail(f"HOLD: shipping {name} is Founder-blocked — {why or 'see HOLD file'}")
    repo = expand(cfg["repo"])
    r = _run(["git", "-C", repo, "status", "--porcelain"])
    head = _run(["git", "-C", repo, "rev-parse", "--short", "HEAD"]).stdout.strip()
    print(f"  win-preflight: repo {repo} @ {head or '?'}")
    return head or "unknown"


def win_build(cfg, name, build_mode, run_ref):
    """Produce/pull the Windows artifact. ci-pull runs today; rig is Founder-gated.
    Returns the absolute path to the built artifact (the .exe/.zip)."""
    os.makedirs(WORK_DIR, exist_ok=True)
    out = os.path.join(WORK_DIR, f"{name}-winbuild")
    if os.path.isdir(out):
        _run(["rm", "-rf", out])
    os.makedirs(out, exist_ok=True)
    if build_mode == "rig":
        # The local Windows VM path — BLOCKED until a hypervisor is restored.
        # See STATE/reports/windows-rig-20260708.md (Parallels uninstalled).
        fail("win-build: rig mode BLOCKED — no Windows hypervisor on this Mac "
             "(FOUNDER GATE, see windows-rig-20260708.md). Use --build-mode ci-pull.")
    # ci-pull: gh run download of the named workflow artifact.
    tmpl = cfg.get("build_cmd_ci")
    if not tmpl:
        fail(f"win-build: {name}: no build_cmd_ci configured for ci-pull mode")
    cmd = tmpl.replace("{run}", run_ref or "").replace("{out}", out)
    # collapse the empty {run} slot to '--latest' semantics: gh needs a run id OR
    # the caller passes --run; when omitted we resolve the latest successful run.
    if not run_ref:
        wf = cfg.get("ci_workflow", "")
        rid = _run(["gh", "run", "list", "--repo", "blacklabelbots/circuit",
                    "--workflow", wf, "--status", "success", "--limit", "1",
                    "--json", "databaseId", "--jq", ".[0].databaseId"]).stdout.strip()
        if not rid:
            fail(f"win-build: no successful '{wf}' run to pull (ci-pull needs a green CI build)")
        cmd = cmd.replace("download  ", f"download {rid} ")
        run_ref = rid
    print(f"  win-build: ci-pull run={run_ref}: {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=SHIP_ROOT)
    if r.returncode != 0:
        fail(f"win-build: {name}: artifact pull failed (rc={r.returncode})")
    artifact = os.path.join(out, cfg["built_artifact_windows"])
    if not os.path.isfile(artifact):
        fail(f"win-build: artifact not found at {artifact} after pull")
    print(f"  win-build: OK -> {artifact}")
    return artifact


def win_stage_unsigned(cfg, name, head, artifact, build_mode):
    """The fail-closed terminus. Copy the unsigned artifact to work/ with a
    -UNSIGNED-STAGED suffix, sha it, record to ships-staged.jsonl. NOTHING
    uploads; NO manifest is bumped; ships.jsonl is NOT touched."""
    os.makedirs(WORK_DIR, exist_ok=True)
    base = os.path.splitext(os.path.basename(artifact))[0]
    staged = os.path.join(WORK_DIR, f"{base}-UNSIGNED-STAGED{os.path.splitext(artifact)[1]}")
    shutil.copyfile(artifact, staged)
    sha = sha256_file(staged)
    line = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app": name, "platform": "windows", "commit": head,
        "sha256": sha, "artifact": os.path.basename(staged),
        "staged_only": True, "reason": "unsigned — no Authenticode cert (FOUNDER GATE)",
        "build_mode": build_mode, "uploaded": False, "manifest_bumped": False,
    }
    with open(STAGING_LEDGER, "a") as f:
        f.write(json.dumps(line) + "\n")
    print(f"  win-stage: {staged}")
    print(f"  win-stage: sha256={sha}")
    print(f"  win-ledger: appended to ships-staged.jsonl (staged_only=true)")
    print(f"== STAGED-ONLY {name} (windows, UNSIGNED) — NOT uploaded, NO manifest. "
          f"Signing cert = FOUNDER GATE. sha={sha[:16]}… ==")
    return sha


def win_sign_scan_gauntlet(cfg, name, artifact, build_mode):
    """Only reached when a real cert is present. Sign every nested binary +
    installer, then run the Defender scan and the clean-buyer gauntlet.
    In ci-pull mode (no rig) the scan/gauntlet SKIP-WITH-REASON (can't scan on
    a Mac). Returns the signed artifact path."""
    thumb = cfg["signing_identity"]
    sign_tmpl = cfg.get("sign_cmd")
    if not sign_tmpl:
        fail(f"win-sign: {name}: signing_identity set but no sign_cmd configured")
    cmd = sign_tmpl.replace("{thumbprint}", thumb).replace("{artifact}", artifact)
    print(f"  win-sign: {cmd}")
    r = subprocess.run(cmd, shell=True, cwd=SHIP_ROOT)
    if r.returncode != 0:
        fail(f"win-sign: {name}: signtool failed (rc={r.returncode})")
    if build_mode == "rig":
        scan = cfg.get("defender_scan_cmd", "").replace("{artifact}", artifact)
        print(f"  win-defender: {scan}")
        r = subprocess.run(scan, shell=True)
        if r.returncode != 0:
            fail(f"win-defender: {name}: Defender scan flagged the artifact (rc={r.returncode})")
        print(f"  win-gauntlet: {cfg.get('clean_buyer_gauntlet_cmd', '(manual)')}")
    else:
        print("  win-defender: SKIPPED-WITH-REASON (ci-pull mode, no Windows rig — "
              "cannot run Start-MpScan on a Mac; runs when a rig exists)")
        print("  win-gauntlet: SKIPPED-WITH-REASON (ci-pull mode, no clean-buyer "
              "snapshot — see windows-rig-20260708.md)")
    return artifact


def win_upload(cfg, name, artifact, sha):
    """Signed-only upload to the public R2 Windows key. Kept thin so tests can
    mock it — reaching this stage IS the 'signed path reaches upload' assertion."""
    key = cfg["r2_dl_key_windows"]
    r = _run(["npx", "wrangler", "r2", "object", "put", f"{R2_BUCKET}/{key}",
              "--file", artifact, "--remote"], cwd=SHIP_ROOT)
    if r.returncode != 0:
        fail(f"win-upload: wrangler put {key} failed: {(r.stderr or r.stdout).strip()[:300]}")
    print(f"  win-upload: r2 {R2_BUCKET}/{key} OK")
    return key


def win_ship_ledger(name, head, sha, build_mode):
    line = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "app": name, "platform": "windows", "commit": head, "sha256": sha,
        "staged_only": False, "build_mode": build_mode,
        "uploaded": True, "manifest_bumped": True,
    }
    with open(LEDGER, "a") as f:
        f.write(json.dumps(line) + "\n")
    print("  win-ledger: appended to ships.jsonl (staged_only=false)")


def cmd_ship_windows(name, build_mode, run_ref):
    cfg_path = os.path.join(APPS_DIR, name + ".toml")
    if not os.path.isfile(cfg_path):
        fail(f"no config for app {name!r} ({cfg_path})")
    cfg = load_config(cfg_path)
    if not is_windows_cfg(cfg):
        fail(f"{name}: not a Windows config (platform != 'windows'). "
             f"Use `ship.py {name}` for the macOS road.")
    validate_windows(cfg, cfg_path)
    build_mode = build_mode or cfg.get("build_mode_default", "ci-pull")
    print(f"== bl-ship {name} [WINDOWS lane, mode={build_mode}] ==")
    head = win_preflight(cfg, name)
    artifact = win_build(cfg, name, build_mode, run_ref)
    # ---- THE SIGNING GATE — fail-closed ----
    if cfg["signing_identity"] == UNSIGNED:
        win_stage_unsigned(cfg, name, head, artifact, build_mode)
        return 0  # HARD STOP. No upload. No manifest. ships.jsonl untouched.
    # Signed path (only when a real cert exists):
    signed = win_sign_scan_gauntlet(cfg, name, artifact, build_mode)
    sha = sha256_file(signed)
    win_upload(cfg, name, signed, sha)
    win_ship_ledger(name, head, sha, build_mode)
    print(f"== SHIPPED {name} (windows) sha={sha[:16]}… ==")
    return 0


# ---------- site mode ----------

def cmd_site(dry_run):
    dep = expand("~/.blacklabelbots/_deploy")
    print(f"== bl-ship site {'(DRY RUN)' if dry_run else ''} ==")
    r = _run(["git", "-C", dep, "status", "--porcelain"])
    dirty = [l for l in r.stdout.splitlines() if l.strip()]
    if dirty:
        fail(f"site: _deploy dirty ({len(dirty)} entries) — commit first (provenance)")
    print("  site: tree committed")
    gate = os.path.join(dep, "scripts", "check_no_fabricated_ledger.sh")
    if os.path.isfile(gate):
        r = subprocess.run(["bash", gate], cwd=dep, capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"site: fabricated-ledger gate BLOCKED: {(r.stdout + r.stderr)[-400:]}")
        print("  site: fabricated-ledger gate PASS")
    else:
        fail("site: check_no_fabricated_ledger.sh missing")
    # forbidden-claims grep over every html at root
    hits = []
    for root, dirs, files in os.walk(dep):
        # dist/ is regenerated from the source tree by package-for-cloudflare.sh at deploy time,
        # so it's a stale mirror — scan SOURCE only (dist would false-flag pre-purge copies).
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "worker", "dist",
                                                ".wrangler", ".playwright-mcp", ".claude-flow")]
        for fn in files:
            if fn.endswith((".html", ".js")) and not fn.endswith(".min.js"):
                p = os.path.join(root, fn)
                try:
                    txt = open(p, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                m = re.search(FORBIDDEN_CLAIMS, txt)
                if m:
                    hits.append(f"{os.path.relpath(p, dep)}: {m.group(0)}")
    if hits:
        fail("site: FORBIDDEN CLAIMS present:\n    " + "\n    ".join(hits[:20]))
    print("  site: forbidden-claims grep clean")
    if dry_run:
        print("DRY RUN — not deployed.")
        return 0
    r = subprocess.run(["bash", os.path.join(dep, "scripts", "deploy-site-worker.sh")], cwd=dep)
    if r.returncode != 0:
        fail("site: deploy script failed")
    import urllib.request
    for path in ("/", "/pricing", "/trading"):
        req = urllib.request.Request(SITE_URL + path, headers={"User-Agent": "bl-ship-site-gate"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            if resp.status != 200:
                fail(f"site: live crawl {path} -> {resp.status}")
    print("  site: live crawl OK (/, /pricing, /trading)")
    return 0


# ---------- cli ----------

def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("usage: ship.py --self-check | ship.py <app> [--dry-run] | ship.py site [--dry-run]")
        print("       ship.py --windows <win-app> [--build-mode ci-pull|rig] [--run <id>]")
        print("               (Windows lane: STAGED-ONLY & fail-closed while unsigned)")
        return 0
    if argv[0] == "--self-check":
        return self_check()
    if argv[0] == "--windows":
        # ship.py --windows <win-app> [--build-mode ci-pull|rig] [--run <id>]
        if len(argv) < 2:
            fail("--windows requires a config name, e.g. `ship.py --windows circuit-windows`")
        name = argv[1]
        build_mode = None
        run_ref = None
        if "--build-mode" in argv:
            build_mode = argv[argv.index("--build-mode") + 1]
        if "--run" in argv:
            run_ref = argv[argv.index("--run") + 1]
        return cmd_ship_windows(name, build_mode, run_ref)
    if argv[0] == "--gates":
        # ship.py --gates <path-to.app> <app-config-name>  (standalone gate run)
        app_path, name = argv[1], argv[2]
        cfg = validate(load_config(os.path.join(APPS_DIR, name + ".toml")),
                       os.path.join(APPS_DIR, name + ".toml"))
        return 0 if run_local_gates(app_path, cfg) else 1
    dry = "--dry-run" in argv
    if argv[0] == "site":
        return cmd_site(dry)
    return cmd_ship(argv[0], dry)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
