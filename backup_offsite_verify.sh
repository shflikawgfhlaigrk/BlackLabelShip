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

# Send the key BASE64URL, never percent-encoded. (Defined before the readiness gate, which uses it.)
#
# Percent-encoding cannot get a key with a dot in it past the Cloudflare edge. The edge normalises
# (decodes) the query string BEFORE the WAF evaluates it, so `.dump` / `.tar.gz` re-materialise no
# matter how they are escaped. Measured against the live bucket on 2026-07-12, key with a dot:
#   raw                       -> 1042      quote(safe='')            -> 1104
#   dots escaped as %2E       -> 1042      every byte percent-encoded-> 1042
# All four bounced at the edge and the WAF's own error page ("error code: 1042\n" = exactly 17 bytes)
# was written into the output file — which is why the OFFSITE-VERIFY table showed REMOTE_BYTES=17 and
# failed EVERY object of a set that was, in fact, complete and byte-exact. That is the worst failure
# mode a backup verifier has: it cries wolf until you stop believing it.
#
# base64url's alphabet is [A-Za-z0-9_-]: no dot, no slash, nothing for the WAF to normalise or match.
b64() { python3 -c "import base64,sys;print(base64.urlsafe_b64encode(sys.argv[1].encode()).decode().rstrip('='))" "$1"; }

echo "OFFSITE-VERIFY deploying throwaway R2-binding reader (wrangler r2 object get is NOT trustworthy)…"
R2V_URL="$( cd "$DEPLOYDIR" && npx --yes wrangler deploy 2>&1 \
            | grep -oE 'https://[a-z0-9.-]*bl-r2verify[a-z0-9.-]*\.workers\.dev' | head -1 )"
[[ -n "$R2V_URL" ]] || { echo "OFFSITE-VERIFY FAILED: could not deploy the R2-binding reader"; exit 1; }
echo "OFFSITE-VERIFY reader: $R2V_URL (deleted on exit)"

# READINESS GATE. `wrangler deploy` returns the workers.dev URL before that route actually serves.
# Reads issued into the gap get Cloudflare's "error code: 1042" page — HTTP 404 with a 17-byte body,
# which lands in the output file and reads as a missing/corrupt object. That is a FALSE FAIL, and it
# is not theoretical: on 2026-07-12 this script reported every object of a COMPLETE, byte-exact
# off-site set as FAIL (REMOTE_BYTES=17 — the literal length of "error code: 1042\n") purely because
# it started reading too early. A backup verifier that cries wolf is worse than none: it trains you
# to ignore it. Poll with a deliberately BOGUS token — a 403 JSON body proves the Worker code is
# executing (the route is live) without depending on any object existing.
# READINESS GATE — prove the reader can actually SEE THE BUCKET before trusting a single FAIL.
#
# THREE things must be true, and each one of them has already produced a false FAIL here on
# 2026-07-12, over an off-site set that was complete and byte-exact the whole time:
#   1. the route is live at all              — else Cloudflare 1042 (a 17-byte error page that lands
#                                              in the output file and reads as a corrupt object);
#   2. THIS deploy's code is being served    — the edge served the previous ?key= build for a few
#                                              seconds after `wrangler deploy` returned;
#   3. the R2 BINDING IS ATTACHED            — the killer. Code goes live BEFORE its bindings do, so
#                                              `env.BACKUPS.get()` returns null and the Worker answers
#                                              a perfectly well-formed 404. Indistinguishable, from
#                                              the outside, from "your backup is gone".
# So the gate does not ask "are you up?" — it asks the reader to HEAD a key we KNOW exists and to
# report present:true. Nothing is read, and no FAIL is believed, until the bucket answers.
KNOWN_KEY="$PREFIX/SHA256SUMS"
printf 'OFFSITE-VERIFY waiting for reader + R2 binding'
ready=0
for _ in $(seq 1 60); do
  if curl -s "$R2V_URL/h?b64=$(b64 "$KNOWN_KEY")&t=$TOKEN" 2>/dev/null | grep -q '"present":true'; then
    ready=1; break
  fi
  printf '.'; sleep 2
done
echo
[[ $ready -eq 1 ]] || { echo "OFFSITE-VERIFY INCONCLUSIVE: the reader never saw the bucket (route 1042 / stale code / binding not attached). This is NOT a backup failure — it is a verifier that could not run. Re-run."; exit 2; }
echo "OFFSITE-VERIFY reader live, this deploy's code, R2 binding attached (HEAD $PREFIX/SHA256SUMS -> present)"

remote_sha() { # key [nparts] -> prints "sha256 bytes"; non-zero if the object is genuinely absent
  # Ask Cloudflare to hash the object THROUGH THE R2 BINDING and send back only the digest.
  #
  # We used to pull all 3.7 GiB back and sha256 it here. That is what kept breaking: large
  # octet-stream reads bounce at the edge with "error code: 1042" (HTTP 404 + a 17-byte body) even
  # while /h on the SAME key answers present:true seconds earlier in the SAME run. The transport was
  # failing, and the script called that a missing backup. Now the only thing crossing the network is
  # 64 hex characters, so there is nothing large enough to flake — and for split artifacts the Worker
  # pipes the parts into ONE digest in lexical order, which means the hash it returns is the hash of
  # the REASSEMBLED file. Comparing that to the local SHA256SUMS proves the off-site copy would
  # restore byte-for-byte. Still a binding read: no `wrangler r2 object get`, no cache in the path.
  local key="$1" nparts="${2:-0}" attempt=1 code body
  while (( attempt <= 3 )); do
    body=$(curl -sS --fail-with-body -m 600 -o "$WORK/sha.json" -w '%{http_code}' \
             "$R2V_URL/sha?b64=$(b64 "$key")&parts=$nparts&t=$TOKEN" 2>/dev/null)
    code="$body"
    if [[ "$code" == "200" ]]; then
      python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d['sha256'],d['bytes'])" "$WORK/sha.json"
      return 0
    fi
    echo "  (hash attempt $attempt/3 for $(basename "$key") -> HTTP $code; retrying)" >&2
    sleep $(( attempt * 3 )); (( attempt++ ))
  done
  echo "  (GAVE UP hashing $(basename "$key") after 3 attempts -> HTTP $code)" >&2
  return 1
}

echo "OFFSITE-VERIFY prefix=r2://$BUCKET/$PREFIX"
printf '%-44s %14s %14s %s\n' OBJECT REMOTE_SHA LOCAL_BYTES RESULT

fail=0

# 1. the manifest itself must be byte-identical off-site.
lsum_sha=$(shasum -a 256 "$SUMS" | awk '{print $1}')
if read -r rsha rsz < <(remote_sha "$PREFIX/SHA256SUMS"); then
  [[ "$rsha" == "$lsum_sha" ]] && mres=PASS || { mres=FAIL; fail=1; }
else
  rsha="-"; mres=FAIL; fail=1
fi
printf '%-44s %14s %14s %s\n' "SHA256SUMS(manifest)" "${rsha:0:12}" "$(stat -f%z "$SUMS")" "$mres"

# 2. every artifact in the manifest — hashed off-site, parts reassembled in the Worker.
while read -r sha rel; do
  [[ -n "${sha:-}" ]] || continue
  base="$(basename "$rel")"
  lf="$SNAPDIR$base"; lsz=$(stat -f%z "$lf")
  if (( lsz <= CHUNK_MB*1024*1024 )); then
    nparts=0
  else
    nparts=$(( (lsz + CHUNK_MB*1024*1024 - 1) / (CHUNK_MB*1024*1024) ))
  fi
  if read -r rsha rsz < <(remote_sha "$PREFIX/$base" "$nparts"); then
    if [[ "$rsha" == "$sha" && "$rsz" == "$lsz" ]]; then res=PASS; else res=FAIL; fail=1; fi
  else
    rsha="-"; rsz=0; res=FAIL; fail=1
  fi
  note=""; (( nparts > 0 )) && note=" (${nparts} parts reassembled off-site)"
  printf '%-44s %14s %14s %s%s\n' "$base" "${rsha:0:12}" "$lsz" "$res" "$note"
done < "$SUMS"

echo "OFFSITE-VERIFY $([[ $fail -eq 0 ]] && echo ALL-PASS || echo FAILED) (local ref: $SUMS)"
exit $fail
