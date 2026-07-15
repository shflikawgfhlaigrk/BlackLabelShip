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


# ---------- the founder GO gate (CHARTER §3: publishing is owner-only) ----------

def _go_file(tmp_path, monkeypatch, name, word):
    apps = tmp_path / "apps"
    apps.mkdir(exist_ok=True)
    monkeypatch.setattr(ship, "APPS_DIR", str(apps))
    if word is not None:
        (apps / f"{name}.GO").write_text(word)
    return apps


def test_missing_go_refuses_to_publish(tmp_path, monkeypatch):
    """Absence of a GO is REFUSAL, not permission. The default answer is no."""
    _go_file(tmp_path, monkeypatch, "sovereign", None)
    with pytest.raises(SystemExit) as e:
        ship.gate_go("sovereign")
    assert e.value.code != 0


def test_empty_go_is_not_an_authorization(tmp_path, monkeypatch):
    """`touch sovereign.GO` must not be enough — an agent could do that. It needs his word."""
    _go_file(tmp_path, monkeypatch, "sovereign", "   \n\n  ")
    with pytest.raises(SystemExit) as e:
        ship.gate_go("sovereign")
    assert e.value.code != 0


def test_go_on_file_authorizes_and_is_recorded(tmp_path, monkeypatch):
    _go_file(tmp_path, monkeypatch, "sovereign", "GO — ship b39. Michael, 2026-07-12\nsecond line")
    assert ship.gate_go("sovereign", build="39").startswith("GO — ship b39")


def test_go_for_one_app_does_not_authorize_another(tmp_path, monkeypatch):
    """A GO is per-app. Authorizing academy must never let sovereign ride along."""
    _go_file(tmp_path, monkeypatch, "academy", "GO — ship b29. Michael")
    with pytest.raises(SystemExit) as e:
        ship.gate_go("sovereign")
    assert e.value.code != 0


# ---------- the build binding: a GO authorizes a BUILD, not a directory ----------
# The academy b29→b30→b31 drift: work/<app>-stage is mutable state, and no gate compared what was
# staged against what the founder actually authorized. gate_provenance proves the bytes carry their
# OWN commit; gate_build_number proves the number was not already shipped. Both go green on a build
# nobody approved. Only the GO knows which build Michael meant — so now it can say.

def test_a_go_bound_to_one_build_refuses_a_different_staged_build(tmp_path, monkeypatch):
    """The drift, mechanised: his word says b29, the stage dir holds b31. Nothing publishes."""
    _go_file(tmp_path, monkeypatch, "academy", "GO — ship b29. Michael, 2026-07-13")
    with pytest.raises(SystemExit) as e:
        ship.gate_go("academy", build="31")
    assert e.value.code != 0


def test_a_go_bound_to_a_build_passes_the_build_it_names(tmp_path, monkeypatch):
    _go_file(tmp_path, monkeypatch, "academy", "GO — ship b31. Michael, 2026-07-14")
    assert ship.gate_go("academy", build="31").startswith("GO — ship b31")


def test_a_go_naming_no_build_is_unbound_and_still_authorizes(tmp_path, monkeypatch):
    """Every GO Michael has already written names no build. Those must keep working."""
    _go_file(tmp_path, monkeypatch, "academy", "GO — ship it. Michael")
    assert ship.gate_go("academy", build="31") == "GO — ship it. Michael"


def test_a_go_naming_two_builds_is_ambiguous_and_refused(tmp_path, monkeypatch):
    """"b30 or b31" is not an authorization — the gate must not pick one."""
    _go_file(tmp_path, monkeypatch, "academy", "GO — ship b30, and b31 once it lands. Michael")
    with pytest.raises(SystemExit) as e:
        ship.gate_go("academy", build="31")
    assert e.value.code != 0


def test_a_publish_road_that_loses_its_build_binding_is_refused(tmp_path, monkeypatch):
    """A road that forgets to pass the staged build must NOT sail past a build-bound GO."""
    _go_file(tmp_path, monkeypatch, "academy", "GO — ship b31. Michael")
    with pytest.raises(SystemExit) as e:
        ship.gate_go("academy", build=None)
    assert e.value.code != 0


def test_a_buildless_lane_must_say_so_explicitly(tmp_path, monkeypatch):
    """Windows has no CFBundleVersion: "ship circuit windows b5" must not brick the road...

    ...but only for a lane that declares NO_BUILD. The sentinel is the whole point — it keeps the
    escape hatch out of the default path, where a Mac road could inherit it by accident.
    """
    _go_file(tmp_path, monkeypatch, "circuit-windows", "GO — ship circuit windows b5. Michael")
    assert ship.gate_go("circuit-windows", ship.NO_BUILD).startswith("GO — ship circuit windows b5")


def test_no_mac_publish_road_declares_itself_buildless():
    """NO_BUILD belongs to the Windows lane alone; on a Mac road it would disarm the binding."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ship.py")).read()
    for fn in ("cmd_ship", "cmd_publish_staged"):
        body = src.split(f"def {fn}")[1].split("\ndef ")[0]
        code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
        assert "NO_BUILD" not in code, f"{fn} claims to have no build number — it reads one from the bundle"


def test_build_tokens_read_his_words_not_every_number():
    """`b31` and `build 31` bind; prose numbers and sha-like strings must not."""
    assert ship.go_build_tokens("GO — ship b31. Michael") == [31]
    assert ship.go_build_tokens("GO — ship build 31") == [31]
    assert ship.go_build_tokens("GO — ship B31") == [31]
    assert ship.go_build_tokens("GO — ship it, fixes 3 bugs") == []
    assert ship.go_build_tokens("GO — ship commit b31abc4") == []
    assert ship.go_build_tokens("GO — ship b30 or b31") == [30, 31]


def test_both_mac_publish_paths_bind_the_go_to_the_staged_build():
    """A binding checked against the wrong number is no binding: pass the STAGED build, not a guess."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ship.py")).read()
    for fn in ("cmd_ship", "cmd_publish_staged"):
        body = src.split(f"def {fn}")[1].split("\ndef ")[0]
        code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
        assert "gate_go(name, build)" in code, \
            f"{fn} calls gate_go without the staged build — a build-bound GO cannot be checked"


# ---------- preflight: every configured test leg is a gate ----------
# Academy's preflight ran pytest ONLY, so the entire Swift side — reader, updater, and the whole
# trial/$30-mo entitlement machine — had no ship gate over it. test_cmd is now a list of legs, each
# fail-closed, and a leg whose runner is missing says so in its own words instead of arriving as an
# anonymous non-zero exit.

def test_academy_preflight_runs_the_xctest_leg_not_pytest_alone():
    cfg = ship.load_config(os.path.join(ship.APPS_DIR, "academy.toml"))
    legs = ship.test_cmds(cfg)
    assert any("pytest" in c for c in legs), "academy lost its pytest leg"
    assert any("xctest.sh" in c for c in legs), \
        "academy preflight runs pytest only — the Swift side ships ungated"


def test_a_string_test_cmd_is_still_one_leg():
    """Nine other configs still use the string form; they must be untouched."""
    assert ship.test_cmds({"test_cmd": "pytest -q"}) == ["pytest -q"]
    assert ship.test_cmds({}) == []


def test_a_missing_test_runner_fails_loudly(tmp_path):
    """The silent-pass hazard: a leg that runs nothing must never read as green."""
    with pytest.raises(SystemExit) as e:
        ship.gate_test_runner("bash tests/xctest.sh", str(tmp_path), "academy")
    assert e.value.code != 0


def test_a_present_test_runner_passes(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "xctest.sh").write_text("#!/bin/bash\nexit 0\n")
    ship.gate_test_runner("bash tests/xctest.sh", str(tmp_path), "academy")   # no raise


def _preflight_repo(tmp_path, monkeypatch, legs):
    monkeypatch.setattr(ship, "APPS_DIR", str(tmp_path / "apps"))
    (tmp_path / "apps").mkdir(exist_ok=True)
    return {"repo": str(tmp_path), "test_cmd": legs}


def test_every_configured_leg_actually_runs(tmp_path, monkeypatch):
    cfg = _preflight_repo(tmp_path, monkeypatch, ["touch leg1", "touch leg2"])
    ship.stage_preflight(cfg, "academy")
    assert (tmp_path / "leg1").exists() and (tmp_path / "leg2").exists(), \
        "a configured test leg was skipped — the pytest-only hole"


def test_a_failing_second_leg_stops_the_road(tmp_path, monkeypatch):
    """pytest green + xctest red must NOT reach the build. Fail-closed on every leg."""
    cfg = _preflight_repo(tmp_path, monkeypatch, ["touch leg1", "exit 1"])
    with pytest.raises(SystemExit) as e:
        ship.stage_preflight(cfg, "academy")
    assert e.value.code != 0
    assert (tmp_path / "leg1").exists(), "the first leg never ran — wrong failure"


def test_a_failing_xctest_leg_stops_the_road(tmp_path, monkeypatch):
    """The zero-test guard firing inside xctest.sh must take the whole preflight down."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "xctest.sh").write_text(
        "#!/bin/bash\necho 'FAIL: xcodebuild executed ZERO tests'\nexit 1\n")
    cfg = _preflight_repo(tmp_path, monkeypatch, ["true", "bash tests/xctest.sh"])
    with pytest.raises(SystemExit) as e:
        ship.stage_preflight(cfg, "academy")
    assert e.value.code != 0


def test_dry_run_never_writes_the_real_ledger(tmp_path, monkeypatch):
    """A REHEARSAL IS NOT A SHIP. ships.jsonl must be byte-identical after a dry run.

    This is the defect that forced the last train to archive 6 rows and hand-restore the ledger.
    """
    real = tmp_path / "ships.jsonl"
    real.write_text('{"app":"trading","build":"23"}\n')
    before = real.read_bytes()
    monkeypatch.setattr(ship, "LEDGER", str(real))
    monkeypatch.setattr(ship, "DRY_LEDGER", str(tmp_path / "ships-dryrun.jsonl"))

    ship.stage_ledger("sovereign", "3168563", "39", "abc123", "notary-1", True, "GO — Michael")

    assert real.read_bytes() == before, "a dry run wrote into the ship-of-record"
    assert json.loads((tmp_path / "ships-dryrun.jsonl").read_text())["dry_run"] is True


def test_a_real_ship_does_write_the_ledger_and_records_the_go(tmp_path, monkeypatch):
    real = tmp_path / "ships.jsonl"
    monkeypatch.setattr(ship, "LEDGER", str(real))
    monkeypatch.setattr(ship, "DRY_LEDGER", str(tmp_path / "ships-dryrun.jsonl"))

    ship.stage_ledger("sovereign", "3168563", "39", "abc123", "notary-1", False, "GO — Michael")

    row = json.loads(real.read_text())
    assert row["dry_run"] is False and row["commit"] == "3168563" and row["go"] == "GO — Michael"


# ---------- the build-number gate (an update nobody can install is not a ship) ----------

def _ledger(tmp_path, monkeypatch, *rows):
    led = tmp_path / "ships.jsonl"
    led.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(ship, "LEDGER", str(led))
    return led


def test_reshipping_a_shipped_build_number_with_new_bytes_is_refused(tmp_path, monkeypatch):
    """The live circuit case: b4 shipped from bd96996; 7b785bc has new code but still stamps 4.

    Every gate passes, the ledger says shipped — and the updater tells every b4 user they are
    current, so the fix reaches nobody.
    """
    _ledger(tmp_path, monkeypatch,
            {"app": "circuit", "build": "4", "commit": "bd96996", "sha256": "aaa", "dry_run": False})
    with pytest.raises(SystemExit) as e:
        ship.gate_build_number("circuit", "4", sha="bbb")   # new bytes, same number
    assert e.value.code != 0


def test_republishing_the_identical_bytes_is_allowed(tmp_path, monkeypatch):
    """Resuming a train that died after upload must still work — same number, SAME bytes."""
    _ledger(tmp_path, monkeypatch,
            {"app": "circuit", "build": "4", "commit": "bd96996", "sha256": "aaa", "dry_run": False})
    ship.gate_build_number("circuit", "4", sha="aaa")       # no raise


def test_a_fresh_build_number_passes(tmp_path, monkeypatch):
    _ledger(tmp_path, monkeypatch,
            {"app": "circuit", "build": "4", "commit": "bd96996", "sha256": "aaa", "dry_run": False})
    ship.gate_build_number("circuit", "5", sha="bbb")       # no raise


def test_a_rebuild_of_a_shipped_number_is_refused_before_notarize(tmp_path, monkeypatch):
    """The full-build road has no sha yet — rebuilt bytes are never the shipped bytes, so refuse."""
    _ledger(tmp_path, monkeypatch,
            {"app": "circuit", "build": "4", "commit": "bd96996", "sha256": "aaa", "dry_run": False})
    with pytest.raises(SystemExit) as e:
        ship.gate_build_number("circuit", "4")
    assert e.value.code != 0


def test_a_dry_run_row_does_not_reserve_a_build_number(tmp_path, monkeypatch):
    """Rehearsals must not block the real ship they were rehearsing."""
    _ledger(tmp_path, monkeypatch,
            {"app": "circuit", "build": "5", "commit": "7b785bc", "sha256": "aaa", "dry_run": True})
    ship.gate_build_number("circuit", "5", sha="bbb")       # no raise


def test_both_publish_paths_are_build_number_gated():
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ship.py")).read()
    for fn in ("cmd_ship", "cmd_publish_staged"):
        body = src.split(f"def {fn}")[1].split("\ndef ")[0]
        code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
        assert "gate_build_number" in code, f"{fn} can reship an already-shipped build number"


def test_both_publish_paths_are_go_gated():
    """NO road may reach a public upload or a ledger write without passing gate_go.

    cmd_ship_windows is the third road: its signed path uploads to the public R2 Windows key and
    appends to ships.jsonl (win_ship_ledger). It is unreachable while signing_identity==UNSIGNED,
    but the moment a cert lands it becomes a full publish — so it is held to the same owner-gate as
    the Mac roads. (The UNSIGNED path hard-stops to ships-staged and never publishes, so it needs no
    GO; only the signed path that actually goes public must carry one.)
    """
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ship.py")).read()
    for fn in ("cmd_ship", "cmd_publish_staged", "cmd_ship_windows"):
        body = src.split(f"def {fn}")[1].split("\ndef ")[0]
        code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
        assert "gate_go" in code, f"{fn} can publish without a founder GO"


def test_windows_signed_publish_is_go_gated_before_the_public_upload():
    """The signed Windows path must call gate_go BEFORE win_upload — no public bytes without a GO."""
    src = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ship.py")).read()
    body = src.split("def cmd_ship_windows")[1].split("\ndef ")[0]
    code = "\n".join(l for l in body.splitlines() if not l.lstrip().startswith("#"))
    assert "gate_go" in code and "win_upload" in code, "cmd_ship_windows must gate_go and upload"
    assert code.index("gate_go") < code.index("win_upload"), \
        "gate_go must run before win_upload — a public artifact must never precede the founder GO"
