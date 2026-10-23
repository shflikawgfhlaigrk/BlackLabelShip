#!/usr/bin/env python3
"""Select the newest fresh completed local backup attempt for offsite upload.

Machine output: ready<TAB>snapshot-dir<TAB>manifest-name, wait, or failed.
No older success may mask a newer failed or running attempt.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import stat


MAX_AGE_SECONDS = 12 * 3600
STAMP = re.compile(r"[0-9]{8}T[0-9]{6}Z")


def parse_time(value: str) -> datetime:
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Naive attempt timestamp")
    return result.astimezone(timezone.utc)


def select(root: Path, now: datetime | None = None) -> tuple[str, str, str]:
    now = now or datetime.now(timezone.utc)
    if not root.is_dir() or root.is_symlink():
        return ("failed", "", "")
    candidates = []
    for path in root.glob("[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]/ATTEMPT.*.json"):
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            return ("failed", "", "")
        candidates.append(path)
    if not candidates:
        return ("wait", "", "")
    # The timestamp comes from the producer's immutable filename, not from a
    # possibly malformed JSON body or a copied file's filesystem mtime.
    candidates.sort(key=lambda path: path.name, reverse=True)
    path = candidates[0]
    try:
        data = json.loads(path.read_text())
        stamp = data["snapshot_stamp"]
        attempt_id = data["attempt_id"]
        started = parse_time(data["started_at"])
        status = data["status"]
        if data.get("schema") != "blacklabel.backup-attempt.v1":
            raise ValueError("Wrong attempt schema")
        if not STAMP.fullmatch(stamp) or not re.fullmatch(rf"{stamp}-[0-9]+", attempt_id):
            raise ValueError("Attempt identity mismatch")
        stamp_time = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        if path.name != f"ATTEMPT.{attempt_id}.json" or abs((started - stamp_time).total_seconds()) > 5:
            raise ValueError("Attempt filename and start time differ")
        age = (now - started).total_seconds()
        if age < -300 or age > MAX_AGE_SECONDS or started.date() != now.date():
            return ("failed", "", "")
        snapshot_dir = Path(data["snapshot_dir"])
        if snapshot_dir.resolve() != path.parent.resolve() or snapshot_dir.is_symlink():
            raise ValueError("Attempt snapshot path mismatch")
        if status == "running":
            return ("wait", "", "")
        if status != "complete" or data.get("exit_code") != 0 or data.get("snapshot_complete") is not True:
            return ("failed", "", "")
        manifest = f"SHA256SUMS.{stamp}"
        if data.get("checksum_manifest") != str(snapshot_dir / manifest):
            raise ValueError("Attempt manifest path mismatch")
        if any(ch in str(snapshot_dir) for ch in "\t\n\r") or not (snapshot_dir / manifest).is_file():
            raise ValueError("Attempt manifest missing or path unsafe")
        return ("ready", str(snapshot_dir), manifest)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return ("failed", "", "")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    print("\t".join(select(args.root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
