from __future__ import annotations

import datetime as dt

import pytest

import healthcheck
from utah import alerts


@pytest.fixture
def alert_harness(monkeypatch, tmp_path):
    calls: list[dict] = []

    def capture(stream):
        def send(source, detail="", **kwargs):
            calls.append({
                "stream": stream,
                "source": source,
                "detail": detail,
                "kwargs": kwargs,
            })
            return {"sent": True, "gated": False, "request": f"push-{len(calls)}"}

        return send

    monkeypatch.setattr(healthcheck, "LOG", tmp_path / "healthcheck.log")
    monkeypatch.setattr(healthcheck, "INCIDENT_STATE", tmp_path / "healthcheck_incident.json", raising=False)
    monkeypatch.setattr(
        healthcheck,
        "_cloud_ops_status",
        lambda: {
            "ok": True,
            "health": {
                "monitorFresh": True,
                "realestateSmokeFresh": True,
            },
            "realestateSmoke": {"ok": True},
        },
    )
    monkeypatch.setattr(healthcheck, "_stripe_ok", lambda: True)
    monkeypatch.setattr(healthcheck, "_daemon_ok", lambda: True)
    monkeypatch.setattr(healthcheck, "_backup_fresh", lambda: True)
    monkeypatch.setattr(healthcheck, "_truth_fresh", lambda: True)
    monkeypatch.setattr(healthcheck, "_discord_feeds_ok", lambda: True)
    monkeypatch.setattr(healthcheck, "_automation_checks", lambda checks: None)
    monkeypatch.setattr(alerts, "critical", capture("critical"))
    monkeypatch.setattr(alerts, "ops", capture("ops"), raising=False)
    return calls


def test_identical_local_failure_opens_one_incident(alert_harness):
    healthcheck.run(force_fail=True)
    healthcheck.run(force_fail=True)

    assert len(alert_harness) == 1
    assert alert_harness[0]["stream"] == "ops"
    assert "SYNTHETIC forced-fail" in alert_harness[0]["detail"]


def test_local_incident_sends_one_recovery(alert_harness):
    healthcheck.run(force_fail=True)
    healthcheck.run(force_fail=False)
    healthcheck.run(force_fail=False)

    assert len(alert_harness) == 2
    assert "SYNTHETIC forced-fail" in alert_harness[0]["detail"]
    assert "RECOVERED" in alert_harness[1]["detail"]


def test_active_local_incident_reminds_only_after_six_hours(alert_harness):
    opened = dt.datetime(2026, 8, 10, 12, 0, tzinfo=dt.timezone.utc)
    healthcheck._sync_local_incident(["stripe API"], now=opened)
    healthcheck._sync_local_incident(
        ["stripe API"],
        now=opened + dt.timedelta(hours=5, minutes=59),
    )
    healthcheck._sync_local_incident(
        ["stripe API"],
        now=opened + dt.timedelta(hours=6),
    )

    assert len(alert_harness) == 2
    assert "OPEN" in alert_harness[0]["detail"]
    assert "REMINDER" in alert_harness[1]["detail"]


def test_fresh_cloud_incident_is_not_realerted_by_mac(alert_harness, monkeypatch):
    monkeypatch.setattr(
        healthcheck,
        "_cloud_ops_status",
        lambda: {
            "ok": False,
            "failureSignature": (
                "leads-api-public:404|realestate-api-public:404|"
                "realestate-onboarding-smoke:failed:api_stats,api_first_query"
            ),
            "health": {
                "monitorFresh": True,
                "realestateSmokeFresh": True,
            },
            "realestateSmoke": {"ok": False},
        },
    )

    result = healthcheck.run()

    assert result["failed"] == [
        "public sites and cloud APIs",
        "realestate onboarding smoke",
    ]
    assert alert_harness == []
