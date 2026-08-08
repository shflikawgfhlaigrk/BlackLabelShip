#!/usr/bin/env python3
"""Dry-run the bl-ship Windows STORE staging terminus against a REAL MSIX container.

Why this exists (construction-engineer, W02 tail):
  test_windows_lane.py proves the store road's CONTROL FLOW, but it mocks
  subprocess entirely and stages a fixture file — it never moves the bytes of an
  actual MSIX (a zip/OPC container). This harness closes that gap: it feeds a
  genuine PK-magic .msix through the real win_stage_store_submission() and proves
  the ships-staged.jsonl channel=store line, the -STORE-STAGED.msix copy, and the
  sha256, end to end.

Fail-closed and side-effect-free by construction:
  * WORK_DIR / STAGING_LEDGER / LEDGER are redirected into a TemporaryDirectory.
  * The REAL ships-staged.jsonl and ships.jsonl are hashed before and after and
    the run FAILS if either byte-changed. Nothing is submitted anywhere; this
    function has no Partner Center path in it at all.

MSIX source, in preference order:
  1. a real CI-pulled Circuit.msix (once an MSIX-producing CI lane lands), then
  2. a container zipped from Circuit's real windows/msix-layout tree, then
  3. a minimal in-temp layout, so the harness still runs on a bare checkout.
The chosen source is printed — a run on source (2) or (3) proves the staging
terminus, NOT that a makeappx-packed artifact exists.

The 'ci-artifact' label is EARNED, not inferred from the path. `makeappx pack`
GENERATES [Content_Types].xml and AppxBlockMap.xml into the output package;
windows/msix-layout contains neither, so no self-zipped tree — and no file merely
dropped at dist/Circuit.msix — can forge that label. A file sitting at the CI
artifact path that is not OPC-packed is a hard FAIL, not a silent downgrade to
source (2): a bogus artifact must be loud, never quietly absorbed into a PASS.

Usage: python3 tools/store_stage_dryrun.py       (rc=0 pass, rc=1 fail)
       python3 tools/store_stage_dryrun.py --selftest   (prove the classifier fires both ways)
       python3 tools/store_stage_dryrun.py --gate       (report upstream preconditions; always rc=0)
"""

import hashlib
import json
import os
import sys
import tempfile
import zipfile

SHIP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, SHIP_ROOT)
import ship  # noqa: E402

CIRCUIT_WIN = os.path.expanduser("~/Circuit/windows")
REAL_MSIX = os.path.join(CIRCUIT_WIN, "dist", "Circuit.msix")
REAL_LAYOUT = os.path.join(CIRCUIT_WIN, "msix-layout")


def sha256_path(path):
    if not os.path.exists(path):
        return "ABSENT"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def zip_tree(src_dir, out_path):
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _dirs, files in os.walk(src_dir):
            for name in files:
                full = os.path.join(root, name)
                z.write(full, os.path.relpath(full, src_dir))


# Parts that `makeappx pack` GENERATES into the container. windows/msix-layout has
# neither, so their presence is what separates a real packed MSIX from a zipped tree.
OPC_PARTS = ("[Content_Types].xml", "AppxBlockMap.xml")


def opc_packed_reason(path):
    """Return None if `path` is a makeappx-packed MSIX, else why it is not."""
    if not os.path.isfile(path):
        return "file absent"
    with open(path, "rb") as f:
        if f.read(2) != b"PK":
            return "not a zip/OPC container (no PK magic)"
    try:
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
    except zipfile.BadZipFile:
        return "zip central directory is unreadable"
    missing = [p for p in OPC_PARTS if p not in names]
    if missing:
        return "missing makeappx-generated part(s): " + ", ".join(missing)
    return None


class BogusArtifact(Exception):
    """A file occupies the CI artifact path but did not come from makeappx."""


def make_msix(tmp):
    """Return (path_to_msix, provenance_label)."""
    if os.path.exists(REAL_MSIX):
        reason = opc_packed_reason(REAL_MSIX)
        if reason:
            raise BogusArtifact(
                f"{REAL_MSIX} exists but is NOT a makeappx-packed MSIX ({reason}). "
                "Refusing to label it 'ci-artifact' or to fall back to the zipped layout.")
        return REAL_MSIX, "ci-artifact:Circuit.msix (OPC-verified: %s)" % ", ".join(OPC_PARTS)
    out = os.path.join(tmp, "Circuit.msix")
    if os.path.isdir(REAL_LAYOUT):
        zip_tree(REAL_LAYOUT, out)
        return out, "zipped-from:Circuit/windows/msix-layout (NOT makeappx-packed)"
    layout = os.path.join(tmp, "layout")
    os.makedirs(os.path.join(layout, "Assets"))
    with open(os.path.join(layout, "AppxManifest.xml"), "w") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<Package />\n')
    with open(os.path.join(layout, "Circuit.exe"), "wb") as f:
        f.write(b"MZ placeholder - staged only, never executed\n")
    zip_tree(layout, out)
    return out, "minimal-in-temp layout (no Circuit checkout present)"


def main():
    failures = []
    real_before = {p: sha256_path(os.path.join(SHIP_ROOT, p))
                   for p in ("ships-staged.jsonl", "ships.jsonl")}

    with tempfile.TemporaryDirectory() as tmp:
        try:
            msix, provenance = make_msix(tmp)
        except BogusArtifact as exc:
            print("STORE-STAGE DRY-RUN: FAIL")
            print(f"  - {exc}")
            return 1
        with open(msix, "rb") as f:
            magic = f.read(2)
        if magic != b"PK":
            failures.append(f"source msix is not a zip/OPC container (magic={magic!r})")

        work = os.path.join(tmp, "work")
        staging = os.path.join(tmp, "ships-staged.jsonl")
        ledger = os.path.join(tmp, "ships.jsonl")
        orig = (ship.WORK_DIR, ship.STAGING_LEDGER, ship.LEDGER)
        ship.WORK_DIR, ship.STAGING_LEDGER, ship.LEDGER = work, staging, ledger
        try:
            sha = ship.win_stage_store_submission(
                {"app": "circuit-windows"}, "circuit-windows",
                "DRYRUN-HEAD", msix, "ci-pull")
        finally:
            ship.WORK_DIR, ship.STAGING_LEDGER, ship.LEDGER = orig

        staged = [f for f in os.listdir(work) if f.endswith("-STORE-STAGED.msix")]
        if len(staged) != 1:
            failures.append(f"expected exactly one -STORE-STAGED.msix, got {staged}")
        else:
            staged_path = os.path.join(work, staged[0])
            if sha256_path(staged_path) != sha:
                failures.append("staged copy sha256 does not match the recorded sha256")
            if sha256_path(msix) != sha:
                failures.append("staged copy differs from the source msix bytes")

        lines = [json.loads(l) for l in open(staging) if l.strip()] if os.path.exists(staging) else []
        if len(lines) != 1:
            failures.append(f"expected 1 ships-staged.jsonl line, got {len(lines)}")
        else:
            row = lines[0]
            for key, want in (("channel", "store"), ("platform", "windows"),
                              ("staged_only", True), ("submitted", False),
                              ("manifest_bumped", False)):
                if row.get(key) != want:
                    failures.append(f"staged row {key}={row.get(key)!r}, expected {want!r}")
            if row.get("sha256") != sha:
                failures.append("staged row sha256 disagrees with the staged artifact")

        if os.path.exists(ledger) and os.path.getsize(ledger) > 0:
            failures.append("ships.jsonl was written — the staged road must never touch it")

        print(f"  msix source     : {provenance}")
        print(f"  staged artifact : {staged[0] if staged else '(none)'}")
        print(f"  sha256          : {sha}")
        print(f"  staged rows     : {len(lines)} (channel=store, staged_only=true, submitted=false)")

    for path, before in real_before.items():
        if sha256_path(os.path.join(SHIP_ROOT, path)) != before:
            failures.append(f"REAL {path} was modified by this dry-run — not side-effect-free")

    if failures:
        print("STORE-STAGE DRY-RUN: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("STORE-STAGE DRY-RUN: PASS (isolated temp root; real ledgers byte-identical)")
    return 0


def selftest():
    """Prove the OPC classifier fires BOTH ways — a gate that only ever passes is vacuous."""
    cases = []
    with tempfile.TemporaryDirectory() as tmp:
        junk = os.path.join(tmp, "junk.msix")
        with open(junk, "wb") as f:
            f.write(b"not a zip at all\n")
        cases.append(("plain bytes", junk, True))

        if os.path.isdir(REAL_LAYOUT):
            zipped = os.path.join(tmp, "zipped-layout.msix")
            zip_tree(REAL_LAYOUT, zipped)
            cases.append(("zipped windows/msix-layout (the forgery this guards)", zipped, True))

        packed = os.path.join(tmp, "packed.msix")
        with zipfile.ZipFile(packed, "w") as z:
            for part in OPC_PARTS:
                z.writestr(part, "<x/>")
            z.writestr("AppxManifest.xml", "<Package/>")
        cases.append(("synthetic makeappx-shaped container", packed, False))

        cases.append(("absent path", os.path.join(tmp, "nope.msix"), True))

        failures = []
        for label, path, want_rejected in cases:
            reason = opc_packed_reason(path)
            rejected = reason is not None
            print(f"  {'REJECT' if rejected else 'ACCEPT'}  {label}"
                  + (f"  [{reason}]" if reason else ""))
            if rejected != want_rejected:
                failures.append(f"{label}: expected {'REJECT' if want_rejected else 'ACCEPT'}")

    # End-to-end positive control: a bogus file AT the CI artifact path must make
    # make_msix() raise, not silently fall back to the zipped layout and PASS.
    global REAL_MSIX
    saved = REAL_MSIX
    with tempfile.TemporaryDirectory() as tmp:
        REAL_MSIX = os.path.join(tmp, "Circuit.msix")
        with open(REAL_MSIX, "wb") as f:
            f.write(b"PK\x03\x04 truncated impostor")
        try:
            _, label = make_msix(tmp)
            failures.append(f"bogus artifact at the CI path was ACCEPTED as {label!r}")
            print(f"  ACCEPT  bogus file at CI artifact path -> {label}")
        except BogusArtifact as exc:
            print(f"  REFUSE  bogus file at CI artifact path  [{exc}]")
        finally:
            REAL_MSIX = saved

    if failures:
        print("OPC CLASSIFIER SELFTEST: FAIL")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"OPC CLASSIFIER SELFTEST: PASS ({len(cases)} classifier cases + "
          "1 end-to-end refusal, both directions exercised)")
    return 0


def prove_nonvacuous():
    """Sabotage the classifier and require selftest() to FAIL — a check that cannot
    fail proves nothing. rc=0 means the selftest is load-bearing."""
    import contextlib
    import io

    saved = globals()["opc_packed_reason"]
    globals()["opc_packed_reason"] = lambda path: None  # accept everything
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            rc = selftest()
    finally:
        globals()["opc_packed_reason"] = saved

    if rc == 0:
        print("NON-VACUITY PROOF: FAIL — selftest still PASSED with the classifier disabled")
        return 1
    print("NON-VACUITY PROOF: PASS — disabling the OPC classifier makes selftest FAIL")
    return 0


def gate():
    """Report the upstream preconditions for a CI-artifact dry-run. Always rc=0 (report mode)."""
    import subprocess

    circuit = os.path.expanduser("~/Circuit")

    def git(*args):
        try:
            return subprocess.run(("git", "-C", circuit) + args, capture_output=True,
                                  text=True, timeout=30).stdout
        except Exception:
            return ""

    tracked = len([l for l in git("ls-files", "windows").splitlines() if l.strip()])
    head_wf = git("show", "HEAD:.github/workflows/windows-spike.yml")
    head_makeappx = head_wf.count("makeappx")
    artifact_reason = opc_packed_reason(REAL_MSIX)

    checks = [
        (f"~/Circuit/windows/** tracked at HEAD (found {tracked} files)", tracked > 0),
        (f"makeappx job present at HEAD of windows-spike.yml ({head_makeappx} refs)", head_makeappx > 0),
        (f"makeappx-packed {REAL_MSIX} present"
         + (f" — {artifact_reason}" if artifact_reason else ""), artifact_reason is None),
    ]
    print("CI-ARTIFACT DRY-RUN PRECONDITIONS")
    for label, ok in checks:
        print(f"  [{'MET ' if ok else 'UNMET'}] {label}")
    met = all(ok for _, ok in checks)
    print(f"VERDICT: {'ALL PRECONDITIONS MET' if met else 'HOLD — upstream (circuit-engineer) gate unmet'}")
    return 0


if __name__ == "__main__":
    if "--prove-nonvacuous" in sys.argv:
        sys.exit(prove_nonvacuous())
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    if "--gate" in sys.argv:
        sys.exit(gate())
    sys.exit(main())
