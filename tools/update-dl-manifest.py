#!/usr/bin/env python3
"""update-dl-manifest — regenerate the signed /dl SHA256SUMS after a ship.

Ship-truth manifest (§5.1): blacklabelbots.com serves a minisign-signed
SHA256SUMS covering every /dl artifact (worker ALLOWED map). This tool keeps it
current. It is wired into bl-ship stage_upload (ship.py) so every macOS ship
re-signs the manifest for the artifact it just uploaded; it can also rebuild
the whole manifest from R2.

Buyer verification (documented on purpose, keep stable):
    minisign -Vm SHA256SUMS -p minisign.pub && shasum -a 256 -c SHA256SUMS

Modes
    --r2key <key> --sha <sha256>   upsert the line(s) for one R2 object; the
                                   buyer-facing filename(s) come from
                                   tools/dl-manifest-objects.tsv
    --full                         re-stream EVERY object in the tsv from R2
                                   and rebuild all lines (slow; receipts only)

Key material (house secrets pattern, ~/.utah/secrets/minisign/):
    minisign.key  encrypted secret key (0600)   minisign.pub  public key
    password      key password (0600) — read and piped to minisign stdin,
                  NEVER printed and NEVER passed via argv

Exit codes
    0 OK — manifest signed, uploaded, and confirmed live
    2 usage error (bad/missing arguments, r2key not in tsv)
    3 signing failure (minisign missing, bad password, key missing)
    4 R2 upload failure
    5 live confirmation failure (served manifest/signature do not verify)
    6 dependency/secret missing (tsv, wrangler, secrets dir)

python3-stdlib only. Single-writer: callers hold the bl-ship lane.
"""
import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import urllib.request

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
SHIP_ROOT = os.path.dirname(TOOLS_DIR)
TSV = os.path.join(TOOLS_DIR, "dl-manifest-objects.tsv")
R2_BUCKET = "sovereign-files"
R2_PREFIX = "manifest"           # served by worker /dl allow-list entries
SITE_URL = "https://blacklabelbots.com"
SECRETS_DIR = os.path.expanduser("~/.utah/secrets/minisign")
SEC_KEY = os.path.join(SECRETS_DIR, "minisign.key")
PUB_KEY = os.path.join(SECRETS_DIR, "minisign.pub")
PASSWORD_FILE = os.path.join(SECRETS_DIR, "password")
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# wrangler r2 get/put run from a dir with wrangler installed (the site worker tree)
WRANGLER_CWD = os.path.expanduser("~/.blacklabelbots/_deploy")


def die(code, msg):
    print(f"update-dl-manifest: {msg}", file=sys.stderr)
    raise SystemExit(code)


def load_tsv():
    if not os.path.isfile(TSV):
        die(6, f"object list missing: {TSV}")
    mapping = {}  # r2key -> [buyer filenames]
    for line in open(TSV):
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, fname = line.split("\t")
        mapping.setdefault(key, []).append(fname)
    return mapping


def r2_stream_sha(key):
    p = subprocess.Popen(
        ["npx", "wrangler", "r2", "object", "get", f"{R2_BUCKET}/{key}",
         "--pipe", "--remote"],
        cwd=WRANGLER_CWD, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    h, n = hashlib.sha256(), 0
    while True:
        chunk = p.stdout.read(1 << 20)
        if not chunk:
            break
        h.update(chunk)
        n += len(chunk)
    if p.wait() != 0 or n == 0:
        return None, 0
    return h.hexdigest(), n


def fetch_current_lines():
    """Current manifest from R2 (source of truth the worker serves). Absent -> empty."""
    p = subprocess.run(
        ["npx", "wrangler", "r2", "object", "get",
         f"{R2_BUCKET}/{R2_PREFIX}/SHA256SUMS", "--pipe", "--remote"],
        cwd=WRANGLER_CWD, capture_output=True)
    if p.returncode != 0 or not p.stdout:
        return {}
    lines = {}
    for raw in p.stdout.decode("utf-8", "replace").splitlines():
        raw = raw.rstrip()
        if not raw or "  " not in raw:
            continue
        sha, fname = raw.split("  ", 1)
        lines[fname] = sha
    return lines


def sign(manifest_path):
    if not os.path.isfile(SEC_KEY) or not os.path.isfile(PASSWORD_FILE):
        die(6, f"minisign key material missing under {SECRETS_DIR}")
    with open(PASSWORD_FILE) as f:
        pw = f.read().strip()
    sig = manifest_path + ".minisig"
    if os.path.exists(sig):
        os.unlink(sig)
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    r = subprocess.run(
        ["minisign", "-S", "-s", SEC_KEY, "-m", manifest_path,
         "-t", f"Black Label ship-truth manifest {ts} — sha256 of every /dl artifact",
         "-c", "Black Label Bots download manifest; verify: minisign -Vm SHA256SUMS -p minisign.pub"],
        input=(pw + "\n").encode(), capture_output=True)
    del pw
    if r.returncode != 0 or not os.path.isfile(sig):
        die(3, f"minisign -S failed rc={r.returncode}")
    v = subprocess.run(["minisign", "-V", "-p", PUB_KEY, "-m", manifest_path],
                       capture_output=True)
    if v.returncode != 0:
        die(3, "self-verify after signing failed")
    return sig


def r2_put(local, key, content_type="text/plain; charset=utf-8"):
    r = subprocess.run(
        ["npx", "wrangler", "r2", "object", "put", f"{R2_BUCKET}/{key}",
         "--file", local, "--content-type", content_type, "--remote"],
        cwd=WRANGLER_CWD, capture_output=True, text=True)
    if r.returncode != 0:
        die(4, f"wrangler put {key} failed: {(r.stderr or r.stdout).strip()[:300]}")


def confirm_live(expect_lines):
    """Fetch the SERVED manifest + sig and verify signature + expected lines."""
    tmp = tempfile.mkdtemp(prefix="dlmanifest-")
    got = {}
    for f in ("SHA256SUMS", "SHA256SUMS.minisig", "minisign.pub"):
        req = urllib.request.Request(f"{SITE_URL}/dl/{f}",
                                     headers={"User-Agent": "Mozilla/5.0 (bl-ship manifest-confirm)"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read()
        with open(os.path.join(tmp, f), "wb") as fh:
            fh.write(data)
        got[f] = data
    v = subprocess.run(["minisign", "-V", "-p", os.path.join(tmp, "minisign.pub"),
                        "-m", os.path.join(tmp, "SHA256SUMS")], capture_output=True, text=True)
    if v.returncode != 0:
        die(5, "live-served SHA256SUMS does not verify against live-served minisign.pub")
    live = got["SHA256SUMS"].decode()
    for fname, sha in expect_lines.items():
        if f"{sha}  {fname}" not in live:
            die(5, f"live manifest missing/stale line for {fname}")
    print(f"  manifest: live /dl/SHA256SUMS verified (minisign OK, {len(expect_lines)} line(s) confirmed)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--r2key")
    ap.add_argument("--sha")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()
    mapping = load_tsv()

    if a.full:
        lines = {}
        for key, fnames in mapping.items():
            sha, n = r2_stream_sha(key)
            if sha is None or sha == EMPTY_SHA:
                print(f"  manifest: SKIP {key} (absent in R2)")
                continue
            for fn in fnames:
                lines[fn] = sha
            print(f"  manifest: {key} {sha[:16]}… ({n}b)")
    elif a.r2key and a.sha:
        if a.r2key not in mapping:
            die(2, f"r2key {a.r2key!r} not in {TSV} — add it there AND to the worker "
                   f"/dl ALLOWED map before shipping a new artifact")
        if not (len(a.sha) == 64 and all(c in "0123456789abcdef" for c in a.sha.lower())):
            die(2, "--sha must be a hex sha256")
        # The TSV is the active delivery allow-list. Prune filenames removed
        # from it so an incremental ship cannot keep advertising a stale,
        # disabled artifact forever.
        allowed_filenames = {fname for fnames in mapping.values() for fname in fnames}
        lines = {
            fname: sha
            for fname, sha in fetch_current_lines().items()
            if fname in allowed_filenames
        }
        for fn in mapping[a.r2key]:
            lines[fn] = a.sha.lower()
    else:
        die(2, "need --full OR (--r2key K --sha H)")

    if not lines:
        die(2, "refusing to publish an empty manifest")
    tmp = tempfile.mkdtemp(prefix="dlmanifest-")
    mpath = os.path.join(tmp, "SHA256SUMS")
    with open(mpath, "w") as f:
        for fn in sorted(lines):
            f.write(f"{lines[fn]}  {fn}\n")
    sig = sign(mpath)
    r2_put(mpath, f"{R2_PREFIX}/SHA256SUMS")
    r2_put(sig, f"{R2_PREFIX}/SHA256SUMS.minisig")
    r2_put(PUB_KEY, f"{R2_PREFIX}/minisign.pub")
    if a.full:
        confirm_live(lines)
    else:
        confirm_live({fn: lines[fn] for fn in mapping[a.r2key]})
    print(f"  manifest: SHA256SUMS ({len(lines)} lines) signed + uploaded + live-confirmed")


if __name__ == "__main__":
    main()
