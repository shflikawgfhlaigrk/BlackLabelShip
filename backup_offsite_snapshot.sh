#!/bin/bash
# Client-side encrypted copy of the exact three-artifact company snapshot.
# All remote parts and the encrypted manifest are downloaded, authenticated and
# compared to source bytes before publishing encrypted-v1/LATEST.gpg.
# Legacy restore-proven objects are preserved until a verified migration retires them.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${BACKUP_PYTHON:-/usr/bin/python3}"
HELPER="$SCRIPT_DIR/tools/encrypted_snapshot.py"
BACKUPS_ROOT="${BACKUPS_ROOT:-$HOME/BlackLabelBackups}"
LOG="${OFFSITE_LOG:-$HOME/.utah/logs/backup-offsite.log}"
STATE_DIR="${SNAP_STATE_DIR:-$HOME/.utah/run/encrypted-backups}"
CHUNK_BYTES="${SNAP_CHUNK_BYTES:-67108864}"
KEYFILE="${BACKUP_KEYFILE:-$HOME/.utah/secrets/backup-key.txt}"
CREDENTIAL="${BACKUP_R2_CREDENTIAL_FILE:-$HOME/.wrangler/config/default.toml}"
WAIT_SECS="${SNAP_WAIT_SECS:-7200}"
POLL_SECS="${SNAP_POLL_SECS:-30}"
mkdir -p "$(dirname "$LOG")" "$STATE_DIR"

log() { echo "[$(date -u +%FT%TZ)] snapshot: $*" | tee -a "$LOG"; }
case "$WAIT_SECS:$POLL_SECS" in *[!0-9:]*|:*) log 'FATAL: invalid snapshot wait interval'; exit 1;; esac
[[ "$POLL_SECS" -gt 0 ]] || { log 'FATAL: poll interval must be positive'; exit 1; }
case "$CHUNK_BYTES" in ''|*[!0-9]*) log 'FATAL: invalid snapshot chunk size'; exit 1;; esac
[[ "$CHUNK_BYTES" -ge 1 && "$CHUNK_BYTES" -le 304087040 ]] || { log 'FATAL: snapshot chunk size out of range'; exit 1; }

manifest_ready() {
  SNAPDIR="$("$PYTHON" - "$BACKUPS_ROOT" <<'PY'
from pathlib import Path
import re, sys
root = Path(sys.argv[1])
dirs = sorted(p for p in root.glob('*') if p.is_dir() and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', p.name))
if dirs: print(dirs[-1])
PY
)"
  [[ -n "$SNAPDIR" ]] || return 1
  "$PYTHON" "$HELPER" inspect --snapshot-dir "$SNAPDIR" >/dev/null 2>&1
}

DEADLINE=$(( $(date +%s) + WAIT_SECS ))
until manifest_ready; do
  if (( $(date +%s) >= DEADLINE )); then
    log "FATAL: no exact complete snapshot manifest under $BACKUPS_ROOT after ${WAIT_SECS}s"
    exit 1
  fi
  log 'waiting on the complete three-artifact snapshot manifest'
  sleep "$POLL_SECS"
done

ARGS=(upload --snapshot-dir "$SNAPDIR" --key-file "$KEYFILE"
      --credential-file "$CREDENTIAL" --state-dir "$STATE_DIR"
      --chunk-bytes "$CHUNK_BYTES" --receipt "$STATE_DIR/last-upload.json")
# Explicit offline integration testing must never satisfy the production monitor.
if [[ -n "${BACKUP_LOCAL_TEST_STORE:-}" ]]; then
  ARGS+=(--local-store "$BACKUP_LOCAL_TEST_STORE")
fi
log "encrypting and verifying $SNAPDIR"
if "$PYTHON" "$HELPER" "${ARGS[@]}" 2>&1 | tee -a "$LOG"; then
  PREFIX="$("$PYTHON" -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r["status"] == "passed"; print(r["prefix"])' "$STATE_DIR/last-upload.json")"
  if [[ -n "${BACKUP_LOCAL_TEST_STORE:-}" ]]; then
    log "OFFLINE TEST COMPLETE: $PREFIX"
  else
    log "encrypted snapshot OFF-SITE COMPLETE: r2://blacklabel-backups/$PREFIX"
  fi
else
  log 'FATAL: encrypted snapshot incomplete; no successful completion claimed'
  exit 1
fi
