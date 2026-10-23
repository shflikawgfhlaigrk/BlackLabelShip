#!/bin/zsh
# Off-machine encrypted backup of Black Label's irreplaceable local state -> R2.
# Closes the single biggest risk: the local-first stack has no off-box copy.
#
# Backs up: ships.jsonl (the ship ledger), ~/.utah/secrets (config+creds),
# ~/.utah/partner + ~/RUN-LOG.md + ~/ATLAS.md, and a D1 export of blacklabel-leads.
# Everything is AES-256 encrypted with the key at ~/.utah/secrets/backup-key.txt
# BEFORE it leaves the machine. Idempotent (dated object), logged, non-destructive.
set -uo pipefail

BUCKET="blacklabel-backups"
CONTENT_ROOT="${BACKUP_CONTENT_ROOT:-$HOME}"
DEPLOY="${OFFSITE_DEPLOY_ROOT:-$HOME/.blacklabelbots/_deploy}"
KEYFILE="${BACKUP_KEYFILE:-$HOME/.utah/secrets/backup-key.txt}"
LOG="${OFFSITE_LOG:-$HOME/.utah/logs/backup-offsite.log}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$(mktemp -d)"
mkdir -p "$(dirname "$LOG")"

log() { echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }

# 1. Backup encryption key (generate once, 600). Michael must ALSO store this off-machine.
if [[ ! -s "$KEYFILE" ]]; then
  openssl rand -base64 48 > "$KEYFILE"
  chmod 600 "$KEYFILE"
  log "generated new backup key at $KEYFILE (STORE THIS OFF-MACHINE)"
fi

# 2. Stage the irreplaceable state.
STAGE="$WORK/blacklabel-state"
mkdir -p "$STAGE"
cp "$CONTENT_ROOT/BlackLabelShip/ships.jsonl" "$STAGE/" 2>/dev/null && log "staged ships.jsonl"
cp -R "$CONTENT_ROOT/.utah/secrets" "$STAGE/secrets" 2>/dev/null && log "staged secrets/"
cp -R "$CONTENT_ROOT/.utah/partner" "$STAGE/partner" 2>/dev/null
cp "$CONTENT_ROOT/RUN-LOG.md" "$CONTENT_ROOT/ATLAS.md" "$STAGE/" 2>/dev/null

# 3. D1 export (best-effort — a slow/failed export must not sink the backup).
if ( cd "$DEPLOY" && npx --yes wrangler d1 export blacklabel-leads \
       --remote --output "$STAGE/blacklabel-leads.d1.sql" >>"$LOG" 2>&1 ); then
  log "D1 export blacklabel-leads OK ($(du -h "$STAGE/blacklabel-leads.d1.sql" 2>/dev/null | cut -f1))"
else
  log "WARN: D1 export blacklabel-leads failed/skipped (backup continues)"
fi

# 4. Manifest.
{ echo "backup: $STAMP"; echo "host: $(hostname)"; echo "contents:";
  ( cd "$STAGE" && find . -type f -exec du -h {} \; ); } > "$STAGE/MANIFEST.txt"

# 5. tar + AES-256 encrypt.
ARCHIVE="$WORK/blacklabel-backup-$STAMP.tar.gz"
ENC="$ARCHIVE.enc"
( cd "$WORK" && tar czf "$ARCHIVE" blacklabel-state ) || { log "FATAL: tar failed"; exit 1; }
openssl enc -aes-256-cbc -pbkdf2 -salt -in "$ARCHIVE" -out "$ENC" \
  -pass "file:$KEYFILE" || { log "FATAL: encrypt failed"; exit 1; }
SZ=$(du -h "$ENC" | cut -f1)
SHA=$(shasum -a 256 "$ENC" | awk '{print $1}')
log "encrypted archive $SZ sha256=$SHA"

# 6. Upload to R2 (dated key + a 'latest' pointer).
KEY="daily/blacklabel-backup-$STAMP.tar.gz.enc"
if ( cd "$DEPLOY" && npx --yes wrangler r2 object put "$BUCKET/$KEY" \
       --file "$ENC" --remote >>"$LOG" 2>&1 ); then
  log "UPLOADED r2://$BUCKET/$KEY"
  ( cd "$DEPLOY" && npx --yes wrangler r2 object put "$BUCKET/latest.tar.gz.enc" \
      --file "$ENC" --remote >>"$LOG" 2>&1 ) && log "UPLOADED r2://$BUCKET/latest.tar.gz.enc"
else
  log "FATAL: R2 upload failed"; rm -rf "$WORK"; exit 1
fi

rm -rf "$WORK"
log "state bundle complete: $KEY ($SZ)"

# 7. Off-site the restore-proven snapshot set (large pg dumps + brain-state).
#    The state-bundle receipt remains valid if this separate lane fails, but
#    the aggregate job must fail so monitoring cannot report a complete backup.
if [[ ! -x "$SCRIPT_DIR/backup_offsite_snapshot.sh" ]]; then
  log "FATAL: snapshot entrypoint missing; state bundle succeeded, overall backup incomplete"
  exit 1
fi
if bash "$SCRIPT_DIR/backup_offsite_snapshot.sh"; then
  log "encrypted snapshot off-site OK"
else
  log "FATAL: snapshot off-site failed; state bundle succeeded, overall backup incomplete"
  exit 1
fi
log "backup complete: $KEY ($SZ)"
