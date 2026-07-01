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

python3-stdlib only (works on system py3.9: tomllib fallback parser built in).
"""
import sys, os, re, json, glob, hashlib, subprocess, plistlib, shutil, datetime

SHIP_ROOT = os.path.dirname(os.path.abspath(__file__))
APPS_DIR = os.path.join(SHIP_ROOT, "apps")
WORK_DIR = os.path.join(SHIP_ROOT, "work")
LEDGER = os.path.join(SHIP_ROOT, "ships.jsonl")

REQUIRED_KEYS = [
    "repo", "bundle_id", "app_name", "build_cmd", "built_app_path", "arch",
    "required_entitlements", "forbidden_entitlements", "ships_no_data_globs",
    "r2_dl_key", "r2_updates_key", "manifest_endpoint", "dl_url",
]
OPTIONAL_KEYS = ["ports", "test_cmd", "sign_identity", "entitlements_file"]
VALID_ARCH = ("universal2", "arm64")


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


def load_all():
    out = {}
    for p in sorted(glob.glob(os.path.join(APPS_DIR, "*.toml"))):
        name = os.path.splitext(os.path.basename(p))[0]
        out[name] = validate(load_config(p), p)
    if not out:
        fail(f"no app configs in {APPS_DIR}")
    return out


def self_check():
    apps = load_all()
    for name, cfg in apps.items():
        print(f"  {name:<12} repo={cfg['repo']} arch={cfg['arch']} "
              f"ents={len(cfg['required_entitlements'])} OK")
    print(f"self-check: {len(apps)} config(s) valid")
    return 0


# ---------- cli ----------

def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("usage: ship.py --self-check | ship.py <app> [--dry-run] | ship.py site [--dry-run]")
        return 0
    if argv[0] == "--self-check":
        return self_check()
    fail(f"unknown command {argv[0]!r} (stages land in later tasks)")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
