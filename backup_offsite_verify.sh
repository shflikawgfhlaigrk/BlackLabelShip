#!/bin/bash
# Verify the RESTORE-PROVEN set that backup_offsite_snapshot.sh landed in R2:
# pull every object back, reassemble any split artifacts, and prove sha256 matches
# the LOCAL SHA256SUMS. Emits an OFFSITE-VERIFY table (object | remote-bytes | sha256 | PASS/FAIL).
# Read-only against R2 (get only); writes only to a temp dir. Uses wrangler OAuth.
set -uo pipefail

BUCKET="blacklabel-backups"
DEPLOY="$HOME/.blacklabelbots/_deploy"
CHUNK_MB=290

SNAPDIR="$(ls -dt "$HOME"/BlackLabelBackups/[0-9]*/ 2>/dev/null | head -1)"
SUMS="$(ls -t "$SNAPDIR"SHA256SUMS.* 2>/dev/null | head -1)"
[[ -s "$SUMS" ]] || { echo "no local SHA256SUMS"; exit 1; }
DATE="$(basename "${SNAPDIR%/}")"
STAMP="$(basename "$SUMS" | sed 's/^SHA256SUMS\.//')"
PREFIX="restore-proven/$DATE/$STAMP"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

get() { # key destfile
  ( cd "$DEPLOY" && npx --yes wrangler r2 object get "$BUCKET/$1" --file "$2" --remote >/dev/null 2>&1 )
}

echo "OFFSITE-VERIFY prefix=r2://$BUCKET/$PREFIX"
printf '%-42s %14s %10s %s\n' OBJECT REMOTE_BYTES LOCAL_B RESULT

# manifest round-trips byte-identical?
get "$PREFIX/SHA256SUMS" "$WORK/SHA256SUMS.remote"
if cmp -s "$SUMS" "$WORK/SHA256SUMS.remote"; then mres=PASS; else mres=FAIL; fi
printf '%-42s %14s %10s %s\n' "SHA256SUMS(manifest)" "$(stat -f%z "$WORK/SHA256SUMS.remote" 2>/dev/null || echo -)" "$(stat -f%z "$SUMS")" "$mres"

fail=0
[[ "$mres" == PASS ]] || fail=1
while read -r sha rel; do
  [[ -n "${sha:-}" ]] || continue
  base="$(basename "$rel")"
  lf="$SNAPDIR$base"; lsz=$(stat -f%z "$lf")
  out="$WORK/$base"
  if (( lsz <= CHUNK_MB*1024*1024 )); then
    get "$PREFIX/$base" "$out"
  else
    # reassemble from parts (lexical order) — part keys are $base.parts/$base.part.aa..
    : > "$out"
    nparts=$(( (lsz + CHUNK_MB*1024*1024 - 1) / (CHUNK_MB*1024*1024) ))
    for suf in $(python3 -c "import string,sys;s=[a+b for a in string.ascii_lowercase for b in string.ascii_lowercase];print('\n'.join(s[:int(sys.argv[1])]))" "$nparts"); do
      pf="$WORK/part.$suf"
      get "$PREFIX/$base.parts/$base.part.$suf" "$pf" || { echo "  (missing part $suf)"; fail=1; break; }
      cat "$pf" >> "$out"; rm -f "$pf"
    done
  fi
  rsz=$(stat -f%z "$out" 2>/dev/null || echo 0)
  rsha=$(shasum -a 256 "$out" 2>/dev/null | awk '{print $1}')
  if [[ "$rsha" == "$sha" && "$rsz" == "$lsz" ]]; then res=PASS; else res=FAIL; fail=1; fi
  printf '%-42s %14s %10s %s\n' "$base" "$rsz" "$lsz" "$res"
  rm -f "$out"
done < "$SUMS"

echo "OFFSITE-VERIFY $([[ $fail -eq 0 ]] && echo ALL-PASS || echo FAILED) (local ref: $SUMS)"
exit $fail
