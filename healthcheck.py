#!/usr/bin/env python3
"""Black Label health check — pings the surfaces that must stay up and ALERTS Michael on
any failure (Pushover via utah.alerts, mirrored to email on critical). Idempotent, logged,
never raises. Registered as launchd com.blacklabel.healthcheck.

Checks: the Cloudflare public monitor is fresh and green, Stripe is reachable (read-only
key fetch), the Utah daemon deck is alive, and the off-machine backup ran within the last
26h. Run with --force-fail to inject a synthetic failure and PROVE the alert path end to end.

2026-07-06 deep-audit extension: every 30-min tick also regenerates the shared automation
status (ProjectUtah/ops/automation_doctor.py report --write) and checks the things whose
absence produced green fiction: reply/mailcheck ingestion freshness, Stripe EVENT-SYNC
freshness (distinct from API connectivity, distinct again from the utah.sales paid
mirror), launchd expected-vs-loaded drift, unwanted reboot resurrections, conductor
multiplicity, and orphaned critical daemons. When keep-list jobs are missing it attempts
ONE self-heal via `automation_doctor.py bootstrap-money-path --apply` and alerts if
anything is still missing — a stale/unreadable status file is itself a FAILURE, never
silently green.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path.home() / "ProjectUtah"))

CLOUD_OPS_URL = os.environ.get(
    "BLACKLABEL_CLOUD_OPS_URL",
    "https://blacklabel-cloud-ops.michael-070.workers.dev/health",
)
LOG = pathlib.Path.home() / ".utah" / "logs" / "healthcheck.log"
BACKUP_LOG = pathlib.Path.home() / ".utah" / "logs" / "backup-offsite.log"
DOCTOR = pathlib.Path.home() / "ProjectUtah" / "ops" / "automation_doctor.py"
STATUS = pathlib.Path.home() / ".utah" / "run" / "automation_status.json"


def _log(msg: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{dt.datetime.now(dt.timezone.utc).isoformat()}] {msg}"
    print(line)
    with LOG.open("a") as fh:
        fh.write(line + "\n")


def _cloud_ops_status(timeout: int = 20) -> dict | None:
    """Read Cloudflare's aggregate public monitor.

    A 503 still carries the truthful JSON failure state, so parse its body instead
    of discarding it. Missing, malformed, or unreachable state remains unknown and
    therefore red to callers.
    """
    req = urllib.request.Request(CLOUD_OPS_URL, headers={"User-Agent": "blb-healthcheck"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if exc.fp else b""
    except Exception:
        return None
    try:
        status = json.loads(body.decode("utf-8"))
        return status if isinstance(status, dict) else None
    except Exception:
        return None


def _stripe_ok() -> bool:
    try:
        from utah.product import stripe_sync as ss
        key = ss._secret_key()
        if not key:
            return False
        ss.fetch_charges(key, limit=1)  # transport reachable; raises on failure
        return True
    except Exception:
        return False


def _daemon_ok() -> bool:
    # The Utah deck serves :8766; a 2xx/3xx/4xx (anything answering) means the daemon is up.
    for url in ("http://127.0.0.1:8766/", "http://127.0.0.1:8766/truth"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:
                if r.status:
                    return True
        except urllib.error.HTTPError:
            return True  # answered (even 404) => process alive
        except Exception:
            continue
    return False


def _backup_fresh(max_age_h: int = 26) -> bool:
    """TWO off-machine lanes append to BACKUP_LOG: the daily encrypted state
    bundle (marker 'backup complete') and the restore-proven snapshot set
    (terminal marker 'OFF-SITE COMPLETE' or 'FINISHED WITH ERRORS'). Judge each
    lane by its own LAST marker line's embedded [timestamp].

    2026-08-02 fix: the old check grepped the final 2000 bytes for 'backup
    complete' — but the snapshot lane appends AFTER the daily marker, so even a
    fully healthy day scrolled the marker out of the window (permanent false
    FAIL), while drill runs' FATAL lines tripped the any-FATAL-after-marker
    clause. Content timestamps, never window position or file mtime."""
    try:
        if not BACKUP_LOG.exists():
            return False
        text = BACKUP_LOG.read_text()[-500_000:]  # bounded; ~2 days of runs
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        drills = ("0000-TEST", "TESTSTAMP", "snaptest")

        def last_epoch(needle: str, exclude: tuple = ()) -> float | None:
            for line in reversed(text.splitlines()):
                if needle in line and not any(x in line for x in exclude):
                    m = re.match(r"\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z\]", line)
                    return (dt.datetime.fromisoformat(m.group(1) + "+00:00").timestamp()
                            if m else None)
            return None

        # 1. daily state bundle went off-machine within budget
        ok_ts = last_epoch("backup complete")
        if ok_ts is None or (now - ok_ts) / 3600 > max_age_h:
            return False
        # 2. restore-proven snapshot lane: its last REAL terminal line must be a
        #    fresh success (an incomplete part-set is not a backup).
        done_ts = last_epoch("OFF-SITE COMPLETE", exclude=drills)
        err_ts = last_epoch("FINISHED WITH ERRORS", exclude=drills)
        if done_ts is None:
            return False
        if err_ts is not None and err_ts > done_ts:
            return False
        return (now - done_ts) / 3600 <= max_age_h + 2  # snapshot lane finishes later
    except Exception:
        return False


def _fresh_status(max_age_s: float = 3900) -> dict | None:
    """Regenerate + read the doctor's status JSON. None = missing/stale/unreadable —
    callers must treat that as a FAILURE (unknown is not green)."""
    try:
        subprocess.run([sys.executable, str(DOCTOR), "report", "--write"],
                       capture_output=True, timeout=120)
    except Exception:  # noqa: BLE001 — fall back to last written report below
        pass
    try:
        age = dt.datetime.now().timestamp() - STATUS.stat().st_mtime
        if age > max_age_s:
            return None
        return json.loads(STATUS.read_text())
    except Exception:  # noqa: BLE001
        return None


def _self_heal_money_path() -> str:
    """One bounded self-heal attempt: bootstrap unloaded keep-list jobs. Returns the
    doctor's stdout tail for the log; never raises."""
    try:
        proc = subprocess.run(
            [sys.executable, str(DOCTOR), "bootstrap-money-path", "--apply"],
            capture_output=True, text=True, timeout=120)
        return (proc.stdout or proc.stderr).strip()[-500:]
    except Exception as exc:  # noqa: BLE001
        return f"self-heal failed to run: {exc}"


def _automation_checks(checks: dict[str, bool]) -> None:
    """Fold the shared automation status into the pass/fail check set. Every source
    that cannot be verified fresh scores as a FAILURE."""
    status = _fresh_status()
    checks["automation status fresh"] = status is not None
    if status is None:
        return
    launchd = status.get("launchd") or {}
    missing = launchd.get("missing_expected") or []
    if missing:
        _log(f"self-heal: {len(missing)} keep-list job(s) missing ({', '.join(missing)}) — "
             "running bootstrap-money-path")
        _log("self-heal output: " + _self_heal_money_path())
        status = _fresh_status() or status
        launchd = status.get("launchd") or {}
        missing = launchd.get("missing_expected") or []
    checks["launchd keep-list loaded"] = not missing
    checks["no unwanted reboot resurrections"] = not (launchd.get("resurrect_risk") or [])
    checks["no dead-interpreter KeepAlive"] = not (launchd.get("missing_binary_keepalive") or [])
    inbound = status.get("inbound") or {}
    checks["replies ingestion fresh"] = (inbound.get("replies") or {}).get("status") == "ok"
    checks["mailcheck fresh"] = (inbound.get("mailcheck") or {}).get("status") == "ok"
    checks["stripe event-sync fresh"] = ((status.get("stripe") or {}).get("sync") or {}).get("status") == "ok"
    daemons = status.get("daemons") or {}
    checks["postgres managed"] = (daemons.get("postgres") or {}).get("status") == "managed"
    checks["utah supervisor managed"] = (daemons.get("utah_supervisor") or {}).get("status") == "managed"
    # A single live conductor is founder-gated work-in-progress; MULTIPLE live is the
    # dangerous state (three generations racing — the pre-Jul-4 failure mode).
    checks["conductor not multiple"] = (status.get("conductor") or {}).get("status") != "MULTIPLE"


def _truth_fresh(max_age_h: float = 2.0) -> bool:
    """STATE/truth.json regeneration lost its scheduler when com.blacklabel.watchdog
    was deliberately disabled (manifest: fleet re-bootstrap amplifier, 07-07).
    The healthcheck tick is the replacement writer: regenerate best-effort, then
    require freshness — a stale truth file is RED, never silent."""
    team = pathlib.Path.home() / "BlackLabel-Team"
    try:
        subprocess.run(["python3", str(team / "bin" / "truth.py")],
                       cwd=str(team), capture_output=True, timeout=120)
    except Exception:  # noqa: BLE001 — regen failure surfaces via the age check below
        pass
    try:
        truth = team / "STATE" / "truth.json"
        gen = json.loads(truth.read_text()).get("generated", "")
        age_h = (dt.datetime.now(dt.timezone.utc)
                 - dt.datetime.fromisoformat(gen)).total_seconds() / 3600
        return age_h <= max_age_h
    except Exception:
        return False


def _discord_feeds_ok(hooks_path: pathlib.Path | None = None,
                      expected_path: pathlib.Path | None = None) -> bool:
    """2026-07-12: all 8 utah Discord feed webhooks silently pointed at ONE channel
    (#ops-alerts), so the leads finder flooded the alert channel with 100 posts/day.
    Guard both failure modes: each webhook must still resolve to the channel pinned in
    discord_webhooks.expected.json (re-pin after any deliberate rewire), and no two
    feeds may share a channel. Missing files, missing keys, or dead webhooks are RED."""
    secrets = pathlib.Path.home() / ".utah" / "secrets"
    hooks_path = hooks_path or secrets / "discord_webhooks.json"
    expected_path = expected_path or secrets / "discord_webhooks.expected.json"
    try:
        hooks = json.loads(hooks_path.read_text())
        expected = json.loads(expected_path.read_text())
    except Exception:
        return False
    if not expected or set(hooks) != set(expected):
        return False
    seen: dict[str, str] = {}
    for key, url in hooks.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "blb-healthcheck"})
            with urllib.request.urlopen(req, timeout=20) as r:
                channel = json.load(r).get("channel_id", "")
        except Exception:
            return False  # deleted/unreachable webhook: posts vanish silently otherwise
        if channel != expected[key] or channel in seen:
            return False
        seen[channel] = key
    return True


def run(force_fail: bool = False) -> dict:
    checks: dict[str, bool] = {}
    cloud_ops = _cloud_ops_status()
    cloud_health = (cloud_ops or {}).get("health") or {}
    checks["cloud ops monitor fresh"] = bool(cloud_health.get("monitorFresh"))
    checks["public sites and cloud APIs"] = bool(cloud_ops and cloud_ops.get("ok"))
    checks["stripe API"] = _stripe_ok()
    checks["daemon :8766"] = _daemon_ok()
    checks["backup <26h"] = _backup_fresh()
    checks["truth.json <2h"] = _truth_fresh()
    checks["realestate onboarding smoke"] = bool(
        cloud_health.get("realestateSmokeFresh")
        and ((cloud_ops or {}).get("realestateSmoke") or {}).get("ok")
    )
    checks["discord feed routing"] = _discord_feeds_ok()
    _automation_checks(checks)
    if force_fail:
        checks["SYNTHETIC forced-fail (alert drill)"] = False

    failed = [name for name, ok in checks.items() if not ok]
    summary = " | ".join(f"{n}={'OK' if ok else 'FAIL'}" for n, ok in checks.items())
    _log(f"healthcheck: {summary}")

    if failed:
        detail = "DOWN: " + ", ".join(failed)
        try:
            from utah import alerts
            alerts.critical("healthcheck", detail, key="healthcheck-" + "-".join(sorted(failed)))
            _log(f"ALERT sent to Michael: {detail}")
        except Exception as exc:  # noqa: BLE001 — alert transport down: log it, never raise
            _log(f"ALERT FAILED to send ({exc}): {detail}")
    else:
        _log("all green")
    return {"checks": checks, "failed": failed}


if __name__ == "__main__":
    force = "--force-fail" in sys.argv
    result = run(force_fail=force)
    sys.exit(1 if result["failed"] and not force else 0)
