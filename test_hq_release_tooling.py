import json
import os
import plistlib
import subprocess

import pytest

import ship


def _git(repo, *args):
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _git_repo(tmp_path, name="hq-source"):
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "ship-test@blacklabel.invalid")
    _git(repo, "config", "user.name", "Ship Test")
    (repo / "macos").mkdir()
    (repo / "macos" / "entitlements.plist").write_text("<plist><dict/></plist>\n")
    (repo / "source.txt").write_text("source\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "fixture")
    return repo


def _cfg(repo, app_name="Black Label HQ.app"):
    return {
        "repo": str(repo),
        "bundle_id": "com.blacklabel.hq",
        "app_name": app_name,
        "build_cmd": "true",
        "built_app_path": "macos/build/Black Label HQ.app",
        "arch": "universal2",
        "required_entitlements": [],
        "forbidden_entitlements": [],
        "ships_no_data_globs": [],
        "r2_dl_key": "hq.zip",
        "r2_updates_key": "updates/hq/{build}.zip",
        "manifest_endpoint": "/api/version/hq",
        "dl_url": "https://example.invalid/hq.zip",
    }


def _app(stage, payload=b"hq-executable", build="23", version="1.0"):
    app = stage / "Black Label HQ.app"
    executable = app / "Contents" / "MacOS" / "Black Label HQ"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(payload)
    with open(app / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump(
            {
                "CFBundleExecutable": "Black Label HQ",
                "CFBundleIdentifier": "com.blacklabel.hq",
                "CFBundleVersion": build,
                "CFBundleShortVersionString": version,
            },
            handle,
        )
    return app


def _trusted_provenance(app, repo):
    short = _git(repo, "rev-parse", "--short", "HEAD")
    ship.stage_provenance(str(app), "hq", short, source_repo=str(repo))
    ship.finalize_provenance(
        str(app),
        "hq",
        "notary-fixture-23",
        _cfg(repo),
        verify_staple=False,
    )
    return app.parent / ship.PROVENANCE


def _trust_external_tools(monkeypatch):
    monkeypatch.setattr(ship, "gate_seal", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_staple", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_gatekeeper", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_developer_id", lambda _app, _cfg=None: None)


def test_repo_override_selects_only_a_linked_clean_worktree(tmp_path):
    repo = _git_repo(tmp_path)
    worktree = tmp_path / "detached-hq"
    _git(repo, "worktree", "add", "--detach", str(worktree), "HEAD")

    selected = ship.resolve_repo_override("hq", _cfg(repo), str(worktree))

    assert selected == os.path.realpath(worktree)


def test_repo_override_refuses_an_unrelated_git_repository(tmp_path):
    repo = _git_repo(tmp_path, "configured")
    unrelated = _git_repo(tmp_path, "unrelated")

    with pytest.raises(SystemExit):
        ship.resolve_repo_override("hq", _cfg(repo), str(unrelated))


def test_repo_override_refuses_a_subdirectory_or_missing_path(tmp_path):
    repo = _git_repo(tmp_path)
    with pytest.raises(SystemExit):
        ship.resolve_repo_override("hq", _cfg(repo), str(repo / "macos"))
    with pytest.raises(SystemExit):
        ship.resolve_repo_override("hq", _cfg(repo), str(tmp_path / "missing"))


def test_repo_override_preserves_the_dirty_tree_gate(tmp_path):
    repo = _git_repo(tmp_path)
    worktree = tmp_path / "detached-hq"
    _git(repo, "worktree", "add", "--detach", str(worktree), "HEAD")
    (worktree / "source.txt").write_text("dirty\n")
    cfg = _cfg(repo)
    cfg["repo"] = ship.resolve_repo_override("hq", cfg, str(worktree))

    with pytest.raises(SystemExit):
        ship.stage_preflight(cfg, "hq")


def test_cli_repo_override_is_scoped_to_the_one_mac_invocation(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        ship,
        "cmd_ship",
        lambda name, dry_run, repo_override=None: calls.append(
            (name, dry_run, repo_override)
        ) or 0,
    )

    assert ship.main(["hq", "--repo", str(tmp_path), "--dry-run"]) == 0
    assert ship.main(["hq", "--dry-run"]) == 0
    assert calls == [("hq", True, str(tmp_path)), ("hq", True, None)]


def test_cli_repo_override_reaches_publish_staged_without_persisting(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(
        ship,
        "cmd_publish_staged",
        lambda name, notary_id, dry_run, repo_override=None: calls.append(
            (name, notary_id, dry_run, repo_override)
        ) or 0,
    )

    assert ship.main(
        [
            "--publish-staged",
            "hq",
            "--notary-id",
            "notary-23",
            "--repo",
            str(tmp_path),
            "--dry-run",
        ]
    ) == 0
    assert calls == [("hq", "notary-23", True, str(tmp_path))]


def test_provenance_binds_the_override_commit_tree_and_path(tmp_path):
    repo = _git_repo(tmp_path)
    worktree = tmp_path / "detached-hq"
    _git(repo, "worktree", "add", "--detach", str(worktree), "HEAD")
    app = _app(tmp_path / "hq-stage")
    short = _git(worktree, "rev-parse", "--short", "HEAD")

    data = ship.stage_provenance(
        str(app), "hq", short, source_repo=str(worktree)
    )

    assert data["source_repo"] == os.path.realpath(worktree)
    assert data["source_commit"] == _git(worktree, "rev-parse", "HEAD")
    assert data["source_tree"] == _git(worktree, "rev-parse", "HEAD^{tree}")
    assert data["source_commit"].startswith(data["commit"])


def test_publish_binding_refuses_provenance_from_a_different_worktree_path(tmp_path):
    repo = _git_repo(tmp_path)
    first = tmp_path / "first"
    second = tmp_path / "second"
    _git(repo, "worktree", "add", "--detach", str(first), "HEAD")
    _git(repo, "worktree", "add", "--detach", str(second), "HEAD")
    app = _app(tmp_path / "hq-stage")
    short = _git(first, "rev-parse", "--short", "HEAD")
    ship.stage_provenance(str(app), "hq", short, source_repo=str(first))

    with pytest.raises(SystemExit):
        ship.gate_provenance(
            str(app),
            "hq",
            expect_source_repo=str(second),
            expect_source_commit=_git(second, "rev-parse", "HEAD"),
        )


def test_publish_binding_refuses_a_tampered_source_tree(tmp_path):
    repo = _git_repo(tmp_path)
    app = _app(tmp_path / "hq-stage")
    short = _git(repo, "rev-parse", "--short", "HEAD")
    ship.stage_provenance(str(app), "hq", short, source_repo=str(repo))
    provenance = app.parent / ship.PROVENANCE
    data = json.loads(provenance.read_text())
    data["source_tree"] = "b" * 40
    provenance.write_text(json.dumps(data))

    with pytest.raises(SystemExit):
        ship.gate_provenance(
            str(app),
            "hq",
            expect_source_repo=str(repo),
            expect_source_commit=_git(repo, "rev-parse", "HEAD"),
            expect_source_tree=_git(repo, "rev-parse", "HEAD^{tree}"),
        )


def test_publish_staged_route_refuses_tampered_tree_before_go_or_upload(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    work = tmp_path / "work"
    app = _app(work / "hq-stage")
    short = _git(repo, "rev-parse", "--short", "HEAD")
    ship.stage_provenance(str(app), "hq", short, source_repo=str(repo))
    provenance = app.parent / ship.PROVENANCE
    data = json.loads(provenance.read_text())
    data["source_tree"] = "c" * 40
    provenance.write_text(json.dumps(data))
    monkeypatch.setattr(ship, "WORK_DIR", str(work))
    monkeypatch.setattr(
        ship,
        "load_mac_app_config",
        lambda name, repo_override=None: (_cfg(repo), "/tmp/hq.toml"),
    )
    monkeypatch.setattr(
        ship,
        "gate_go",
        lambda *_args, **_kwargs: pytest.fail("GO gate reached after bad source tree"),
    )

    with pytest.raises(SystemExit):
        ship.cmd_publish_staged(
            "hq", "notary-fixture-23", True, repo_override=str(repo)
        )


def test_cli_repo_requires_exactly_one_value():
    with pytest.raises(SystemExit):
        ship.main(["hq", "--repo"])
    with pytest.raises(SystemExit):
        ship.main(["hq", "--repo", "/one", "--repo", "/two"])


def test_repo_override_is_refused_instead_of_ignored_on_site_lane(monkeypatch):
    monkeypatch.setattr(ship, "cmd_site", lambda _dry: 0)
    with pytest.raises(SystemExit):
        ship.main(["site", "--repo", "/tmp/ignored", "--dry-run"])


@pytest.mark.parametrize(
    "argv",
    [
        ["hq", "unexpected"],
        ["hq", "--unknown"],
        ["hq", "--dry-run", "--dry-run"],
        ["hq", "--repo", "/tmp/hq", "extra"],
    ],
)
def test_build_cli_rejects_every_unconsumed_or_duplicate_token(argv, monkeypatch):
    monkeypatch.setattr(ship, "cmd_ship", lambda *_args, **_kwargs: 0)
    with pytest.raises(SystemExit):
        ship.main(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["--publish-staged", "hq", "--notary-id", "id", "unexpected"],
        ["--publish-staged", "hq", "--notary-id", "id", "--unknown"],
        ["--publish-staged", "hq", "--notary-id", "id", "--dry-run", "--dry-run"],
        ["--publish-staged", "hq", "--notary-id", "id", "--notary-id", "other"],
    ],
)
def test_publish_cli_rejects_every_unconsumed_or_duplicate_token(argv, monkeypatch):
    monkeypatch.setattr(ship, "cmd_publish_staged", lambda *_args, **_kwargs: 0)
    with pytest.raises(SystemExit):
        ship.main(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["--install-candidate", "hq", "--destination", "/tmp/HQ.app", "extra"],
        ["--install-candidate", "hq", "--destination", "/tmp/HQ.app", "--unknown"],
        ["--install-candidate", "hq", "--destination", "/one", "--destination", "/two"],
        ["--install-hq-candidate", "unexpected"],
        ["--install-hq-candidate", "--unknown"],
        ["--install-hq-candidate", "--candidate", "/one", "--candidate", "/two"],
    ],
)
def test_install_cli_rejects_every_unconsumed_or_duplicate_token(argv, monkeypatch):
    monkeypatch.setattr(ship, "cmd_install_candidate", lambda *_args, **_kwargs: 0)
    with pytest.raises(SystemExit):
        ship.main(argv)


def test_installer_copies_verified_candidate_keeps_backup_and_writes_receipt(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    stage = tmp_path / "work" / "hq-stage"
    candidate = _app(stage)
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    _app(destination.parent, payload=b"old-installed")
    evidence = tmp_path / "evidence" / "installs"
    monkeypatch.setattr(ship, "INSTALL_EVIDENCE_DIR", str(evidence))
    _trust_external_tools(monkeypatch)

    receipt_path = ship.install_candidate(
        "hq",
        _cfg(repo),
        str(candidate),
        str(provenance),
        str(destination),
        allow_applications=False,
    )

    receipt = json.loads(open(receipt_path).read())
    assert ship.sha256_tree(str(destination)) == ship.sha256_tree(str(candidate))
    assert receipt["status"] == "installed"
    assert receipt["source"]["commit"] == _git(repo, "rev-parse", "HEAD")
    assert receipt["source"]["tree"] == _git(repo, "rev-parse", "HEAD^{tree}")
    assert receipt["bundle"]["build"] == "23"
    assert receipt["candidate"]["bundle_sha256"] == receipt["installed"]["bundle_sha256"]
    assert receipt["signing"]["developer_id"] is True
    assert receipt["notary"]["submission_id"] == "notary-fixture-23"
    assert receipt["rollback"]["outcome"] == "not_required"
    assert receipt["replacement"]["mode"] == "atomic_exchange"
    assert receipt["replacement"]["destination_continuously_present"] is True
    assert os.path.isdir(receipt["backup"]["path"])
    assert receipt["backup"]["bundle_sha256"]
    assert receipt["backup"]["exec_sha256"]


def test_installer_refuses_provenance_from_an_unrelated_repo_before_mutation(
    tmp_path, monkeypatch
):
    configured = _git_repo(tmp_path, "configured")
    unrelated = _git_repo(tmp_path, "unrelated")
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, unrelated)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    _trust_external_tools(monkeypatch)

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq", _cfg(configured), str(candidate), str(provenance),
            str(destination), allow_applications=False,
        )

    assert not destination.exists()


@pytest.mark.parametrize("field,value", [("source_commit", "a" * 40), ("source_tree", "b" * 40)])
def test_installer_refuses_tampered_git_identity_before_mutation(
    field, value, tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    data = json.loads(provenance.read_text())
    data[field] = value
    provenance.write_text(json.dumps(data))
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    _trust_external_tools(monkeypatch)

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq", _cfg(repo), str(candidate), str(provenance),
            str(destination), allow_applications=False,
        )

    assert not destination.exists()


def test_installer_refuses_a_provenance_hash_mismatch_before_mutation(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    (candidate / "Contents" / "MacOS" / "Black Label HQ").write_bytes(b"tampered")
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    _trust_external_tools(monkeypatch)

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(candidate),
            str(provenance),
            str(destination),
            allow_applications=False,
        )

    assert not destination.exists()


def test_installer_refuses_a_symlink_candidate(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    real = _app(tmp_path / "real-stage")
    _trusted_provenance(real, repo)
    linked = tmp_path / "linked-stage" / "Black Label HQ.app"
    linked.parent.mkdir()
    linked.symlink_to(real, target_is_directory=True)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    _trust_external_tools(monkeypatch)

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(linked),
            str(real.parent / ship.PROVENANCE),
            str(destination),
            allow_applications=False,
        )

    assert not destination.exists()


def test_installer_refuses_untrusted_candidate_before_mutation(tmp_path, monkeypatch):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    monkeypatch.setattr(ship, "gate_seal", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_staple", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_gatekeeper", lambda _app, _cfg=None: None)
    monkeypatch.setattr(
        ship,
        "gate_developer_id",
        lambda _app, _cfg=None: "developer-id: wrong team",
    )

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(candidate),
            str(provenance),
            str(destination),
            allow_applications=False,
        )

    assert not destination.exists()


def test_installer_refuses_lexical_traversal_and_wrong_provenance_path(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    _trust_external_tools(monkeypatch)

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(candidate),
            str(provenance),
            str(tmp_path / "Applications" / ".." / "Black Label HQ.app"),
            allow_applications=False,
        )
    planted = tmp_path / "planted-provenance.json"
    planted.write_bytes(provenance.read_bytes())
    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(candidate),
            str(planted),
            str(destination),
            allow_applications=False,
        )


def test_staged_copy_gate_failure_does_not_touch_existing_destination(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    old = _app(destination.parent, payload=b"old-installed")
    old_hash = ship.sha256_tree(str(old))
    evidence = tmp_path / "evidence" / "installs"
    monkeypatch.setattr(ship, "INSTALL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setattr(ship, "gate_seal", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_staple", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_developer_id", lambda _app, _cfg=None: None)
    monkeypatch.setattr(
        ship,
        "gate_gatekeeper",
        lambda path, _cfg=None: "gatekeeper: staged copy rejected"
        if ".hq-install-" in path
        else None,
    )

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(candidate),
            str(provenance),
            str(destination),
            allow_applications=False,
        )

    assert ship.sha256_tree(str(destination)) == old_hash
    receipt = json.loads(next(evidence.glob("*.json")).read_text())
    assert receipt["rollback"] == {
        "attempted": False,
        "outcome": "destination_untouched",
    }


def test_post_install_gate_failure_rolls_back_the_previous_app_and_records_it(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    old = _app(destination.parent, payload=b"old-installed")
    old_hash = ship.sha256_tree(str(old))
    evidence = tmp_path / "evidence" / "installs"
    monkeypatch.setattr(ship, "INSTALL_EVIDENCE_DIR", str(evidence))
    monkeypatch.setattr(ship, "gate_seal", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_staple", lambda _app, _cfg=None: None)
    monkeypatch.setattr(ship, "gate_developer_id", lambda _app, _cfg=None: None)
    monkeypatch.setattr(
        ship,
        "gate_gatekeeper",
        lambda path, _cfg=None: "gatekeeper: installed copy rejected"
        if os.path.realpath(path) == os.path.realpath(destination)
        else None,
    )

    with pytest.raises(SystemExit):
        ship.install_candidate(
            "hq",
            _cfg(repo),
            str(candidate),
            str(provenance),
            str(destination),
            allow_applications=False,
        )

    assert ship.sha256_tree(str(destination)) == old_hash
    receipts = list(evidence.glob("*.json"))
    assert len(receipts) == 1
    receipt = json.loads(receipts[0].read_text())
    assert receipt["status"] == "rolled_back"
    assert receipt["rollback"]["outcome"] == "restored_backup"


def test_keyboard_interrupt_after_exchange_restores_old_destination_and_records_it(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    old = _app(destination.parent, payload=b"old-installed")
    old_hash = ship.sha256_tree(str(old))
    evidence = tmp_path / "evidence" / "installs"
    monkeypatch.setattr(ship, "INSTALL_EVIDENCE_DIR", str(evidence))
    _trust_external_tools(monkeypatch)
    real_verify = ship.verify_install_artifact
    calls = {"count": 0}

    def interrupt_installed(name, cfg, app_path, provenance_path):
        calls["count"] += 1
        if calls["count"] == 3:
            raise KeyboardInterrupt()
        return real_verify(name, cfg, app_path, provenance_path)

    monkeypatch.setattr(ship, "verify_install_artifact", interrupt_installed)

    with pytest.raises(KeyboardInterrupt):
        ship.install_candidate(
            "hq", _cfg(repo), str(candidate), str(provenance),
            str(destination), allow_applications=False,
        )

    assert destination.exists()
    assert ship.sha256_tree(str(destination)) == old_hash
    receipt = json.loads(next(evidence.glob("*.json")).read_text())
    assert receipt["status"] == "rolled_back"
    assert receipt["rollback"]["outcome"] == "restored_backup"


def test_interrupt_in_the_atomic_exchange_crash_window_restores_old_destination(
    tmp_path, monkeypatch
):
    repo = _git_repo(tmp_path)
    candidate = _app(tmp_path / "work" / "hq-stage")
    provenance = _trusted_provenance(candidate, repo)
    destination = tmp_path / "Applications" / "Black Label HQ.app"
    old = _app(destination.parent, payload=b"old-installed")
    old_hash = ship.sha256_tree(str(old))
    evidence = tmp_path / "evidence" / "installs"
    monkeypatch.setattr(ship, "INSTALL_EVIDENCE_DIR", str(evidence))
    _trust_external_tools(monkeypatch)
    real_exchange = ship.atomic_exchange_paths
    calls = {"count": 0}

    def interrupt_after_exchange(left, right):
        calls["count"] += 1
        real_exchange(left, right)
        if calls["count"] == 1:
            raise KeyboardInterrupt()

    monkeypatch.setattr(ship, "atomic_exchange_paths", interrupt_after_exchange)

    with pytest.raises(KeyboardInterrupt):
        ship.install_candidate(
            "hq", _cfg(repo), str(candidate), str(provenance),
            str(destination), allow_applications=False,
        )

    assert destination.exists()
    assert ship.sha256_tree(str(destination)) == old_hash
    receipt = json.loads(next(evidence.glob("*.json")).read_text())
    assert receipt["rollback"] == {
        "attempted": True,
        "outcome": "restored_backup",
    }


def test_production_replacement_refuses_when_atomic_exchange_is_unavailable(
    tmp_path, monkeypatch
):
    destination = _app(tmp_path / "Applications", payload=b"old")
    staged = _app(tmp_path / "stage", payload=b"new")
    old_hash = ship.sha256_tree(str(destination))
    monkeypatch.setattr(
        ship,
        "atomic_exchange_paths",
        lambda _left, _right: (_ for _ in ()).throw(
            ship.AtomicExchangeUnavailable("unsupported")
        ),
    )

    with pytest.raises(SystemExit):
        ship.replace_existing_destination(
            str(staged), str(destination), str(tmp_path / "backup.app"),
            allow_unsafe_test_fallback=False,
        )

    assert destination.exists()
    assert ship.sha256_tree(str(destination)) == old_hash
    assert staged.exists()


def test_gatekeeper_requires_zero_exit_and_exact_accepted_assessment(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "/tmp/HQ.app: accepted\n"

    monkeypatch.setattr(ship, "_run", lambda _cmd: Result())
    assert ship.gate_gatekeeper("/tmp/HQ.app") is not None
    Result.returncode = 0
    Result.stderr = "/tmp/HQ.app: not accepted\n"
    assert ship.gate_gatekeeper("/tmp/HQ.app") is not None
    Result.stderr = "/tmp/HQ.app: accepted\nsource=Notarized Developer ID\n"
    assert ship.gate_gatekeeper("/tmp/HQ.app") is None


def test_custom_installer_command_requires_destination_and_real_install_is_explicit(
    tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        ship,
        "cmd_install_candidate",
        lambda name, candidate_path=None, provenance_path=None, destination=None,
        allow_applications=False: calls.append(
            (name, candidate_path, provenance_path, destination, allow_applications)
        ) or 0,
    )

    with pytest.raises(SystemExit):
        ship.main(["--install-candidate", "hq"])
    custom = tmp_path / "Applications" / "Black Label HQ.app"
    assert ship.main(
        ["--install-candidate", "hq", "--destination", str(custom)]
    ) == 0
    assert ship.main(["--install-hq-candidate"]) == 0
    assert calls == [
        ("hq", None, None, str(custom), False),
        ("hq", None, None, "/Applications/Black Label HQ.app", True),
    ]


def test_developer_id_gate_requires_black_label_team(monkeypatch):
    class Result:
        returncode = 0
        stdout = ""
        stderr = (
            "Authority=Developer ID Application: Black Label (745ZPGFRA5)\n"
            "TeamIdentifier=745ZPGFRA5\n"
        )

    monkeypatch.setattr(ship, "_run", lambda _cmd: Result())
    assert ship.gate_developer_id("/tmp/Fake.app") is None

    Result.stderr = (
        "Authority=Developer ID Application: Someone Else (WRONGTEAM)\n"
        "TeamIdentifier=WRONGTEAM\n"
    )
    assert "WRONGTEAM" in ship.gate_developer_id("/tmp/Fake.app")
