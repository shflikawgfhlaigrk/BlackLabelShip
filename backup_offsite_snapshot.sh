#!/bin/bash
# Off-machine copy of the RESTORE-PROVEN snapshot set into R2.
#
# The daily bin/backup.sh writes the irreplaceable local state to
# ~/BlackLabelBackups/<date>/ as byte-identical, restore-drilled artifacts:
#   blacklabel-<stamp>.dump   (pg17 custom dump, ~3.0 GB)
#   brain-state-<stamp>.tar.gz (company brain: STATE bus + ships.jsonl + memory.md)
#   utah-<stamp>.dump          (utah pg17 dump: mail_ledger, leads, owned_audience)
#   SHA256SUMS.<stamp>         (the integrity manifest of the three above)
# Those live on ONE disk. This lane lands them off-machine.
#
# wrangler r2 object put caps a single object at 300 MiB, so any artifact over
# 290 MiB is split into `<name>.parts/<name>.part.aa..` and reassembled on restore
# (cat parts in lexical order -> byte-identical original). A PARTS.txt manifest and
# the plaintext SHA256SUMS travel with the set so integrity is verifiable off-box.
#
# Bucket blacklabel-backups is private (Cloudflare-credential-gated) and R2 encrypts
# every object at rest (AES-256). Non-destructive, idempotent (re-put overwrites the
# same dated key), logged. Uses wrangler OAuth only — no new credentials, no API token.
set -uo pipefail

BUCKET="blacklabel-backups"
DEPLOY="$HOME/.blacklabelbots/_deploy"
LOG="$HOME/.utah/logs/backup-offsite.log"
CHUNK_MB=290
BACKUPS_ROOT="${BACKUPS_ROOT:-$HOME/BlackLabelBackups}"   # overridable for tests
WAIT_SECS="${SNAP_WAIT_SECS:-7200}"   # max wait for the dump lane to finish
POLL_SECS="${SNAP_POLL_SECS:-30}"
mkdir -p "$HOME/.utah/logs"

log() { echo "[$(date -u +%FT%TZ)] snapshot: $*" | tee -a "$LOG"; }

put() { # key localfile contenttype — retries transient API failures.
  # 2026-08-01 run lost 3 parts to one-off 401 (CF API auth blip) and 502
  # (gateway) responses over a ~90-min upload; a single failed part marks the
  # whole restore-proven set FINISHED WITH ERRORS. Each attempt is independent,
  # so retry with backoff instead of failing the set on one transient.
  local try
  for try in 1 2 3; do
    ( cd "$DEPLOY" && npx --yes wrangler r2 object put "$BUCKET/$1" \
        --file "$2" --remote --content-type "$3" >>"$LOG" 2>&1 ) && return 0
    [[ $try -lt 3 ]] && { log "RETRY $try/2 in $((try*20))s: $1"; sleep $((try*20)); }
  done
  return 1
}

# --- chain on dump COMPLETION, never the clock (fix 2026-08-01) ---------------
# bin/backup.sh (03:15) writes SHA256SUMS.<stamp> as its LAST step, so a COMPLETE
# manifest is the dump lane's completion sentinel. This lane starts at 03:30 and
# used to assume the dumps were done; when the utah dump grew 122MB->9.79GB the
# manifest stopped landing until ~03:46 and this script FATAL'd 4 straight days
# (07-29..08-01). Poll for the sentinel instead. "Complete" = the manifest's line
# count equals the dir's artifact count (shasum writes the file progressively, so
# mere presence is NOT completion).
manifest_ready() {
  SNAPDIR="$(ls -dt "$BACKUPS_ROOT"/[0-9]*/ 2>/dev/null | head -1)"
  [[ -n "$SNAPDIR" ]] || return 1
  SUMS="$(ls -t "$SNAPDIR"SHA256SUMS.* 2>/dev/null | head -1)"
  [[ -s "$SUMS" ]] || return 1
  local stamp lines arts
  stamp="$(basename "$SUMS" | sed 's/^SHA256SUMS\.//')"
  lines=$(wc -l < "$SUMS" | tr -d ' ')
  arts=$(ls "$SNAPDIR" 2>/dev/null | grep -c -- "-${stamp}\.")
  (( lines >= 3 && lines == arts ))
}

DEADLINE=$(( $(date +%s) + WAIT_SECS ))
until manifest_ready; do
  if (( $(date +%s) >= DEADLINE )); then
    log "FATAL: no complete SHA256SUMS manifest under $BACKUPS_ROOT after ${WAIT_SECS}s — dump lane (bin/backup.sh) did not finish"
    exit 1
  fi
  log "waiting on dump-completion sentinel (SHA256SUMS) in ${SNAPDIR:-<no snapshot dir yet>} ..."
  sleep "$POLL_SECS"
done
log "dump-completion sentinel found: $SUMS"
# ------------------------------------------------------------------------------

DATE="$(basename "${SNAPDIR%/}")"                 # 2026-07-12
STAMP="$(basename "$SUMS" | sed 's/^SHA256SUMS\.//')"  # 20260712T043855Z
PREFIX="restore-proven/$DATE/$STAMP"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

log "off-siting $SNAPDIR (stamp $STAMP) -> r2://$BUCKET/$PREFIX"

# 1. integrity manifest first — the sha256 reference must be off-machine too.
put "$PREFIX/SHA256SUMS" "$SUMS" "text/plain" \
  && log "UPLOADED $PREFIX/SHA256SUMS" || { log "FATAL: SHA256SUMS upload failed"; exit 1; }

# 2. each artifact named in the manifest (format: "<sha256>  ./<file>")
PARTS_MANIFEST="$WORK/PARTS.txt"; : > "$PARTS_MANIFEST"
rc=0
while read -r sha rel; do
  [[ -n "${sha:-}" ]] || continue
  base="$(basename "$rel")"
  f="$SNAPDIR$base"
  if [[ ! -s "$f" ]]; then log "MISSING artifact $f (in SHA256SUMS)"; rc=1; continue; fi
  sz=$(stat -f%z "$f")
  if (( sz <= CHUNK_MB*1024*1024 )); then
    if put "$PREFIX/$base" "$f" "application/octet-stream"; then
      log "UPLOADED single $base ($sz B sha256=$sha)"
      echo "$base|single|$sz|$sha|1" >> "$PARTS_MANIFEST"
    else log "FAIL upload $base"; rc=1; fi
  else
    log "SPLIT $base ($sz B) into ${CHUNK_MB}MiB parts"
    ( cd "$WORK" && split -b "${CHUNK_MB}m" "$f" "${base}.part." )
    n=0; ok=1
    for p in "$WORK/${base}.part."*; do
      if put "$PREFIX/$base.parts/$(basename "$p")" "$p" "application/octet-stream"; then
        log "UPLOADED $(basename "$p") ($(stat -f%z "$p") B)"; n=$((n+1))
      else log "FAIL upload $(basename "$p")"; ok=0; rc=1; fi
    done
    [[ $ok -eq 1 ]] && echo "$base|parts|$sz|$sha|$n" >> "$PARTS_MANIFEST"
    rm -f "$WORK/${base}.part."*
  fi
done < "$SUMS"

# 3. parts manifest last (its presence signals a complete set).
put "$PREFIX/PARTS.txt" "$PARTS_MANIFEST" "text/plain" && log "UPLOADED $PREFIX/PARTS.txt" || rc=1

if [[ $rc -eq 0 ]]; then
  log "restore-proven set OFF-SITE COMPLETE: r2://$BUCKET/$PREFIX"
else
  log "restore-proven set off-site FINISHED WITH ERRORS (rc=$rc)"
fi
# also drop a pointer to the newest off-sited stamp
echo "$PREFIX" > "$WORK/LATEST-RESTORE-PROVEN.txt"
put "restore-proven/LATEST.txt" "$WORK/LATEST-RESTORE-PROVEN.txt" "text/plain" \
  && log "UPLOADED restore-proven/LATEST.txt -> $PREFIX"
exit $rc
