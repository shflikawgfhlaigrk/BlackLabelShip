"""The b38 regression suite: the ship lane must never record a commit the packed bytes don't carry.

Sovereign b38 was notarized, stapled, correctly served, sha-matched in ships.jsonl — and still lied.
The ledger recorded 34569a1 while the bytes were built from 30e740f, because cmd_publish_staged read
`git rev-parse HEAD` at PUBLISH time against an artifact staged hours earlier. Every gate on the road
passed, because no gate connected the RECORDED COMMIT to the ACTUAL BYTES.

These tests plant exactly that: a stale artifact, and an unstamped one. The gate must exit non-zero.
"""
import json, os, plistlib, subprocess, sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ship


def _make_app(tmp_path, name="sovereign", exec_bytes=b"BUILT-FROM-34569a1"):
    """A minimal stand-in for a staged .app: work/<name>-stage/<App>.app"""
    stage = tmp_path / f"{name}-stage"
    app = stage / "Fake.app"
    (app / "Contents" / "MacOS").mkdir(parents=True)
    (app / "Contents" / "MacOS" / "Fake").write_bytes(exec_bytes)
    with open(app / "Contents" / "Info.plist", "wb") as f:
        plistlib.dump({"CFBundleExecutable": "Fake", "CFBundleVersion": "38",
                       "CFBundleShortVersionString": "1.0"}, f)
    return str(app)


def test_stamped_artifact_passes_and_returns_its_build_commit(tmp_path):
    app = _make_app(tmp_path)
    ship.stage_provenance(app, "sovereign", "34569a1")
    assert ship.gate_provenance(app, "sovereign") == "34569a1"


def test_planted_stale_artifact_is_refused(tmp_path):
    """Stamp the bytes, then swap them — the b38 failure mode, mechanised."""
    app = _make_app(tmp_path, exec_bytes=b"BUILT-FROM-34569a1")
    ship.stage_provenance(app, "sovereign", "34569a1")

    # Plant the stale artifact: same path, same stamp, OLDER bytes.
    exec_path = os.path.join(app, "Contents", "MacOS", "Fake")
    with open(exec_path, "wb") as f:
        f.write(b"BUILT-FROM-30e740f")

    with pytest.raises(SystemExit) as e:
        ship.gate_provenance(app, "sovereign")
    assert e.value.code != 0


def test_unstamped_artifact_is_refused_not_guessed_from_git_head(tmp_path):
    """The literal b38 bug: no provenance beside the bytes => the lane must STOP, not ask git."""
    app = _make_app(tmp_path)
    with pytest.raises(SystemExit) as e:
        ship.gate_provenance(app, "sovereign")
    assert e.value.code != 0


def test_tree_moving_during_the_build_is_refused(tmp_path):
    """Bytes built at 30e740f, HEAD now 34569a1 — record neither, fail loud."""
    app = _make_app(tmp_path)
    ship.stage_provenance(app, "sovereign", "30e740f")
    with pytest.raises(SystemExit) as e:
        ship.gate_provenance(app, "sovereign", expect_commit="34569a1")
    assert e.value.code != 0


def test_wrong_app_staged_is_refused(tmp_path):
    app = _make_app(tmp_path, name="sovereign")
    ship.stage_provenance(app, "sovereign", "34569a1")
    with pytest.raises(SystemExit) as e:
        ship.gate_provenance(app, "trading")
    assert e.value.code != 0


def test_publish_staged_no_longer_reads_git_head_for_the_ledger_commit():
    """Guard the root cause itself: the commit must come from the artifact, never from the repo."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ship.py")).read()
    body = src.split("def cmd_publish_staged")[1].split("\ndef ")[0]
    code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
    assert "rev-parse" not in code, "cmd_publish_staged must not derive the ledger commit from git HEAD"
    assert "gate_provenance" in code
