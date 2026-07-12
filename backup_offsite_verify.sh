#!/bin/bash
# Verify the RESTORE-PROVEN set that backup_offsite_snapshot.sh landed in R2:
# pull every object back, reassemble any split artifacts, and prove sha256 matches
# the LOCAL SHA256SUMS. Emits an OFFSITE-VERIFY table (object | remote-bytes | sha256 | PASS/FAIL).
#
# READS GO THROUGH AN R2 BINDING, NOT `wrangler r2 object get`.
# The CLI read serves STALE CACHED BYTES (proven 2026-07-12: it returned old-b6 bytes for a live-b7
# key and certified a DELETED object as present across four deletes and an overwrite — exit 0 every
# time). Every previous ALL-PASS from this script was therefore unsound: it could have been reading a
# cache while the bucket held nothing. A binding read has no CLI cache in the path.
#
# So we deploy a throwaway token-gated reader (tools/r2verify), read through it, and DELETE it in the
# trap — a reader that can serve encrypted backup objects must not outlive the run that needed it.
set -uo pipefail

BUCKET="blacklabel-backups"
DEPLOY="$HOME/.blacklabelbots/_deploy"
VERIFIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/tools/r2verify"
CHUNK_MB=290

SNAPDIR="$(ls -dt "$HOME"/BlackLabelBackups/[0-9]*/ 2>/dev/null | head -1)"
SUMS="$(ls -t "$SNAPDIR"SHA256SUMS.* 2>/dev/null | head -1)"
[[ -s "$SUMS" ]] || { echo "no local SHA256SUMS"; exit 1; }
DATE="$(basename "${SNAPDIR%/}")"
STAMP="$(basename "$SUMS" | sed 's/^SHA256SUMS\.//')"
PREFIX="restore-proven/$DATE/$STAMP"
WORK="$(mktemp -d)"

# --- stand up the binding reader (and guarantee it comes down) ---------------------------------
# The token is bound via a generated [vars] block, NOT `wrangler deploy --var` — that flag did not
# reach the Worker here, leaving env.TOKEN undefined so every request 403'd. (It failed CLOSED, which
# is the right direction, but it makes the whole verify useless.)
TOKEN="$(openssl rand -hex 24)"
DEPLOYDIR="$(mktemp -d)"
cp "$VERIFIER"/worker.js "$VERIFIER"/wrangler.toml "$DEPLOYDIR/"
printf '\n[vars]\nTOKEN = "%s"\n' "$TOKEN" >> "$DEPLOYDIR/wrangler.toml"

teardown() {
  ( cd "$DEPLOYDIR" && npx --yes wrangler delete --name bl-r2verify --force >/dev/null 2>&1 ) || true
  rm -rf "$WORK" "$DEPLOYDIR"
}
trap teardown EXIT

echo "OFFSITE-VERIFY deploying throwaway R2-binding reader (wrangler r2 object get is NOT trustworthy)…"
R2V_URL="$( cd "$DEPLOYDIR" && npx --yes wrangler deploy 2>&1 \
            | grep -oE 'https://[a-z0-9.-]*bl-r2verify[a-z0-9.-]*\.workers\.dev' | head -1 )"
[[ -n "$R2V_URL" ]] || { echo "OFFSITE-VERIFY FAILED: could not deploy the R2-binding reader"; exit 1; }
echo "OFFSITE-VERIFY reader: $R2V_URL (deleted on exit)"

# FULLY percent-encode the key. Encoding only the dots is not enough: the '/' separators in
# restore-proven/<date>/<stamp>/<obj> trip Cloudflare WAF rule 1104, the request never reaches the
# Worker, and the WAF's own error body lands in the output file — which reads as a corrupt/missing
# object and produces a FALSE FAIL. Encode everything (safe='').
enc() { python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$1"; }

get() { # key destfile -> non-zero if the object is genuinely absent
  local code
  code=$(curl -sS --fail-with-body -o "$2" -w '%{http_code}' "$R2V_URL/o?key=$(enc "$1")&t=$TOKEN" 2>/dev/null)
  [[ "$code" == "200" ]]
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
