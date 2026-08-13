#!/bin/bash
# build-suite.sh — Black-Label-Suite.pkg scripted lane (STAGING ONLY — NEVER publishes)
#
# Reconstructs the 2026-08-04 hand-run suite cut (~/BlackLabelHome/dist/
# Black-Label-Suite.pkg: identifier com.blacklabel.suite v1.0.0, one component pkg
# wrapping all 10 apps, install-location /Applications, auth=root,
# relocatable=false, signed "Developer ID Installer" A5F19162… CB0011…4CD2,
# notarized + stapled) as a repeatable one-command lane, with one deliberate
# structural upgrade: ONE COMPONENT PKG PER APP (pkgbuild x10 + productbuild
# --distribution) so per-app receipts exist and partial re-cuts stay possible.
# Product identity is preserved via <product id="com.blacklabel.suite">.
#
# Components come from the INSTALLED fleet — /Applications live, never a repo
# dist/ tree — so the lane always cuts exactly what this machine runs.
# Sunset nuance: b10 is installed while b11 sits staged in work/; the lane reads
# /Applications, so the day b11 (or any newer build) is swapped in, a re-run
# picks it up automatically with zero edits here.
#
# Fail-closed component gate: every app must be spctl-accepted AND signed
# Developer ID Application (team 745ZPGFRA5) or the lane aborts before pkgbuild.
#
# PUBLISH IS FORBIDDEN HERE (§3 owner gate): no R2 upload, no /dl manifest bump,
# no ships.jsonl write. The lane stages work/Black-Label-Suite-STAGED-<date>.pkg,
# appends ships-staged.jsonl {staged_only:true, uploaded:false,
# manifest_bumped:false}, and PRINTS the founder GO commands without running them.
#
# Usage: tools/build-suite.sh
#   env overrides: SUITE_VERSION (default 1.0.0 — parity with the live cut),
#   INSTALLER_IDENTITY, NOTARY_PROFILE, NOTARY_SECRETS, POLL_TIMEOUT_SECS
set -euo pipefail

SHIP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$SHIP_ROOT/work"
TS="$(date +%Y%m%d-%H%M%S)"
BUILD_DIR="$WORK_DIR/suite-build-$TS"
STAGE_DIR="$BUILD_DIR/stage"
PKG_DIR="$BUILD_DIR/components"
DIST_XML="$BUILD_DIR/distribution.xml"
PRODUCT_PKG="$BUILD_DIR/Black-Label-Suite.pkg"
STAGED_PKG="$WORK_DIR/Black-Label-Suite-STAGED-$(date +%Y-%m-%d).pkg"

SUITE_ID="com.blacklabel.suite"
SUITE_TITLE="Black Label Suite"
SUITE_VERSION="${SUITE_VERSION:-1.0.0}"
# Default = the exact cert that signed the live 08-04 pkg:
# Developer ID Installer (745ZPGFRA5), SHA-1 A5F19162…, SHA-256 CB0011…4CD2.
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-A5F191623F3CB26AC21C350190F93FE37DF301AF}"
TEAM_ID="745ZPGFRA5"
NOTARY_PROFILE="${NOTARY_PROFILE:-BL_NOTARY}"
NOTARY_SECRETS="${NOTARY_SECRETS:-$HOME/.utah/secrets/notary.json}"
POLL_TIMEOUT_SECS="${POLL_TIMEOUT_SECS:-2700}"
COVERAGE_GATE="$SHIP_ROOT/tools/notarization-coverage-gate.py"

# slug|installed app bundle|expected CFBundleIdentifier  (the 10 suite apps)
MANIFEST=(
  "trading|Black Label Trading.app|com.blacklabel.trading"
  "realestate|Black Label Real Estate.app|com.blacklabel.realestate"
  "ace|Ace.app|com.blacklabel.assistant"
  "sovereign|Black Label Sovereign.app|com.blacklabel.sovereign"
  "sunset|Sunset.app|com.blacklabel.sunset"
  "marketing|Black Label Marketing.app|com.blacklabel.marketing"
  "circuit|Circuit.app|com.blacklabel.circuit"
  "vigil|Vigil.app|com.blacklabel.homefront"
  "livewallpaper|Black Label Live Wallpaper.app|com.blacklabel.livewallpaper"
  "academy|Black Label Academy.app|com.blacklabel.academy"
)

STAGE="init"
LOCK=""
fail() { echo "build-suite: FAIL [$STAGE] $*" >&2; exit 1; }
cleanup() {
  rc=$?
  { [ -n "$LOCK" ] && rmdir "$LOCK" 2>/dev/null; } || true
  if [ $rc -ne 0 ]; then
    echo "build-suite: aborted at stage [$STAGE] rc=$rc (work kept: $BUILD_DIR)" >&2
  fi
}
trap cleanup EXIT

command -v python3 >/dev/null || fail "python3 missing"
xcrun --find notarytool >/dev/null 2>&1 || fail "xcrun notarytool missing"
[ -f "$COVERAGE_GATE" ] || fail "coverage gate missing: $COVERAGE_GATE"
security find-identity -v 2>/dev/null | grep -q "$INSTALLER_IDENTITY" \
  || fail "installer identity $INSTALLER_IDENTITY not in keychain"
mkdir -p "$WORK_DIR"

STAGE="lock"
LOCK_TRY="$WORK_DIR/.suite-lane.lock"
mkdir "$LOCK_TRY" 2>/dev/null || fail "another suite lane holds $LOCK_TRY"
LOCK="$LOCK_TRY"
mkdir -p "$STAGE_DIR" "$PKG_DIR"

# ---------- 1. component freshness gate (fail-closed, /Applications live) ----------
STAGE="freshness"
ROWS=()
BUILD_KV=()
for entry in "${MANIFEST[@]}"; do
  IFS='|' read -r slug app expid <<<"$entry"
  path="/Applications/$app"
  [ -d "$path" ] || fail "$slug: $path missing"
  bid=$(defaults read "$path/Contents/Info.plist" CFBundleIdentifier 2>/dev/null) \
    || fail "$slug: Info.plist unreadable"
  [ "$bid" = "$expid" ] || fail "$slug: bundle id '$bid' != expected '$expid'"
  sv=$(defaults read "$path/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo "?")
  bv=$(defaults read "$path/Contents/Info.plist" CFBundleVersion 2>/dev/null || echo "?")
  sp=$(spctl -a -vv -t exec "$path" 2>&1 || true)
  echo "$sp" | grep -q ": accepted" \
    || fail "$slug: spctl NOT accepted: $(echo "$sp" | tr '\n' ' ' | head -c 200)"
  echo "$sp" | grep -q "origin=Developer ID Application: .*($TEAM_ID)" \
    || fail "$slug: spctl origin is not our Developer ID Application: $(echo "$sp" | tr '\n' ' ' | head -c 200)"
  src=$(echo "$sp" | sed -n 's/^source=//p' | head -1)
  codesign --verify --deep --strict "$path" 2>/dev/null \
    || fail "$slug: codesign --verify --deep --strict failed"
  auth=$(codesign -dvv "$path" 2>&1 | sed -n 's/^Authority=//p' | head -1)
  case "$auth" in
    "Developer ID Application: "*"($TEAM_ID)") ;;
    *) fail "$slug: leaf authority '$auth' is not Developer ID Application ($TEAM_ID)" ;;
  esac
  team=$(codesign -dvv "$path" 2>&1 | sed -n 's/^TeamIdentifier=//p' | head -1)
  [ "$team" = "$TEAM_ID" ] || fail "$slug: TeamIdentifier '$team' != $TEAM_ID"
  ROWS+=("$(printf '%-13s %-32s %-33s %7s %6s  %s' "$slug" "$app" "$bid" "$sv" "b$bv" "$src")")
  BUILD_KV+=("$slug=$bv")
done
echo "build-suite: component freshness — 10/10 PASS (spctl accepted + Developer ID, fail-closed)"
printf '  %-13s %-32s %-33s %7s %6s  %s\n' slug app bundle-id ver build spctl-source
for r in "${ROWS[@]}"; do echo "  $r"; done

# ---------- 2. stage copies (quarantine-free, re-verified) ----------
STAGE="stage-copy"
for entry in "${MANIFEST[@]}"; do
  IFS='|' read -r slug app expid <<<"$entry"
  mkdir -p "$STAGE_DIR/$slug"
  ditto "/Applications/$app" "$STAGE_DIR/$slug/$app" \
    || fail "$slug: ditto to stage failed"
  xattr -dr com.apple.quarantine "$STAGE_DIR/$slug/$app" 2>/dev/null || true
  codesign --verify --deep --strict "$STAGE_DIR/$slug/$app" 2>/dev/null \
    || fail "$slug: staged copy failed codesign verify (copy corrupt?)"
done
echo "build-suite: staged 10 quarantine-free copies under $STAGE_DIR"

# ---------- 3. pkgbuild per component (relocation OFF) ----------
STAGE="pkgbuild"
for entry in "${MANIFEST[@]}"; do
  IFS='|' read -r slug app expid <<<"$entry"
  bv=$(defaults read "$STAGE_DIR/$slug/$app/Contents/Info.plist" CFBundleVersion)
  plist="$BUILD_DIR/$slug-component.plist"
  pkgbuild --analyze --root "$STAGE_DIR/$slug" "$plist" >/dev/null \
    || fail "$slug: pkgbuild --analyze failed"
  python3 - "$plist" <<'PY' || exit 1
import plistlib, sys
p = sys.argv[1]
with open(p, "rb") as f:
    d = plistlib.load(f)
def fix(items):
    for it in items:
        it["BundleIsRelocatable"] = False
        fix(it.get("ChildBundles") or [])
fix(d)
with open(p, "wb") as f:
    plistlib.dump(d, f)
PY
  pkgbuild --root "$STAGE_DIR/$slug" --component-plist "$plist" \
    --identifier "$SUITE_ID.$slug" --version "$bv" \
    --install-location /Applications "$PKG_DIR/$slug.pkg" >/dev/null \
    || fail "$slug: pkgbuild failed"
  echo "build-suite: pkgbuild $slug.pkg ($SUITE_ID.$slug v$bv)"
done

# ---------- 4. distribution + signed product ----------
STAGE="distribution"
SYNTH_ARGS=()
for entry in "${MANIFEST[@]}"; do
  IFS='|' read -r slug app expid <<<"$entry"
  SYNTH_ARGS+=(--package "$PKG_DIR/$slug.pkg")
done
productbuild --synthesize "${SYNTH_ARGS[@]}" "$DIST_XML" >/dev/null \
  || fail "productbuild --synthesize failed"
python3 - "$DIST_XML" "$SUITE_TITLE" "$SUITE_ID" "$SUITE_VERSION" <<'PY' || exit 1
import re, sys
p, title, sid, ver = sys.argv[1:5]
s = open(p).read()
ins = f'    <title>{title}</title>\n    <product id="{sid}" version="{ver}"/>\n'
s, n = re.subn(r'(<installer-gui-script[^>]*>\n)', r'\1' + ins, s, count=1)
assert n == 1, "installer-gui-script root tag not found"
if "<options" in s:
    if "customize=" not in s:
        s = s.replace("<options ", '<options customize="never" ', 1)
else:
    s = s.replace("</installer-gui-script>",
                  '    <options customize="never" require-scripts="false"/>\n'
                  "</installer-gui-script>")
open(p, "w").write(s)
PY

STAGE="productbuild-sign"
productbuild --distribution "$DIST_XML" --package-path "$PKG_DIR" \
  --sign "$INSTALLER_IDENTITY" --timestamp "$PRODUCT_PKG" \
  || fail "productbuild --distribution failed"
sig=$(pkgutil --check-signature "$PRODUCT_PKG" 2>&1 || true)
echo "$sig" | grep -q "Developer ID Installer: .*($TEAM_ID)" \
  || fail "product pkg not signed by Developer ID Installer ($TEAM_ID): $(echo "$sig" | head -3)"
echo "$sig" | grep -q "Status: signed by a developer certificate issued by Apple for distribution" \
  || fail "unexpected signature status: $(echo "$sig" | head -2)"
echo "build-suite: product signed — Developer ID Installer ($TEAM_ID), timestamped"

# ---------- 5. notarize (AC API key flow) + staple ----------
STAGE="notarize-auth"
if security find-generic-password -s "com.apple.gke.notary.tool.saved-creds.$NOTARY_PROFILE" >/dev/null 2>&1; then
  NOTARY_AUTH=(--keychain-profile "$NOTARY_PROFILE"); AUTH_LABEL="keychain:$NOTARY_PROFILE"
else
  NOTARY_LINES=$(python3 - "$NOTARY_SECRETS" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
k = os.path.expanduser(d["key_path"])
assert os.path.exists(k), "AC API key file missing"
assert d.get("key_id") and d.get("issuer"), "key_id/issuer missing"
print(k); print(d["key_id"]); print(d["issuer"])
PY
) || fail "no notary auth: keychain profile $NOTARY_PROFILE missing AND $NOTARY_SECRETS unusable"
  { read -r NKEY; read -r NKID; read -r NISS; } <<<"$NOTARY_LINES"
  NOTARY_AUTH=(--key "$NKEY" --key-id "$NKID" --issuer "$NISS"); AUTH_LABEL="inline-apikey"
fi
echo "build-suite: notarize auth via $AUTH_LABEL"

STAGE="notarize-submit"
SID=""
for attempt in 1 2 3; do
  out=$(xcrun notarytool submit "$PRODUCT_PKG" "${NOTARY_AUTH[@]}" --no-wait --output-format json 2>&1) \
    && SID=$(printf '%s' "$out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' 2>/dev/null) \
    || true
  [ -n "$SID" ] && break
  echo "build-suite: submit attempt $attempt failed ($(printf '%s' "$out" | tr '\n' ' ' | head -c 200)); retrying in 15s"
  sleep 15
done
[ -n "$SID" ] || fail "notarytool submit failed after 3 attempts"
echo "build-suite: submitted id=$SID; polling (timeout ${POLL_TIMEOUT_SECS}s)…"

STAGE="notarize-poll"
deadline=$(( $(date +%s) + POLL_TIMEOUT_SECS ))
status="In Progress"
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 30
  info=$(xcrun notarytool info "$SID" "${NOTARY_AUTH[@]}" --output-format json 2>/dev/null) \
    || { echo "build-suite: poll error (transient)"; continue; }
  status=$(printf '%s' "$info" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status","?"))' 2>/dev/null || echo "?")
  echo "build-suite: notarization status: $status"
  [ "$status" = "In Progress" ] || [ "$status" = "?" ] || break
done
if [ "$status" != "Accepted" ]; then
  xcrun notarytool log "$SID" "${NOTARY_AUTH[@]}" 2>&1 | head -c 1200 >&2 || true
  fail "notarization status=$status (not Accepted) id=$SID"
fi

STAGE="staple"
stapled=""
for attempt in 1 2 3 4 5; do
  if xcrun stapler staple "$PRODUCT_PKG" >/dev/null 2>&1; then stapled=1; break; fi
  echo "build-suite: staple attempt $attempt failed; retrying in 30s"
  sleep 30
done
[ -n "$stapled" ] || fail "stapler staple failed after 5 attempts"
xcrun stapler validate "$PRODUCT_PKG" >/dev/null 2>&1 || fail "stapler validate failed"
echo "build-suite: Accepted + stapled (id=$SID)"

# ---------- 6. notarization COVERAGE gate: 10 inner apps must hold tickets ----------
STAGE="coverage-gate"
gate_out=$(python3 "$COVERAGE_GATE" --submission-id "$SID" --artifact "$PRODUCT_PKG" 2>&1) \
  || { printf '%s\n' "$gate_out"; fail "coverage gate failed"; }
printf '%s\n' "$gate_out"
passes=$(printf '%s\n' "$gate_out" | grep -c "inner-app ticket PASS" || true)
[ "$passes" -eq 10 ] || fail "coverage gate ticketed $passes/10 inner apps (need 10/10)"
echo "build-suite: coverage gate 10/10 inner apps ticketed"

# ---------- 7. stage the artifact + ships-staged.jsonl receipt ----------
STAGE="stage-artifact"
cp "$PRODUCT_PKG" "$STAGED_PKG"
SHA=$(shasum -a 256 "$STAGED_PKG" | awk '{print $1}')
SIZE=$(stat -f%z "$STAGED_PKG")
COMMIT=$(git -C "$SHIP_ROOT" rev-parse --short HEAD 2>/dev/null || echo "?")
python3 - "$SHIP_ROOT/ships-staged.jsonl" "$SHA" "$SID" "$STAGED_PKG" "$SUITE_VERSION" "$COMMIT" "$SIZE" "${BUILD_KV[@]}" <<'PY' || exit 1
import datetime, json, os, sys
path, sha, sid, art, ver, commit, size, *kv = sys.argv[1:]
row = {
    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "app": "suite", "platform": "macos", "version": ver, "commit": commit,
    "sha256": sha, "size": int(size), "notarization_id": sid,
    "artifact": os.path.basename(art),
    "staged_only": True, "uploaded": False, "manifest_bumped": False,
    "method": "tools/build-suite.sh (10x pkgbuild from /Applications + productbuild --distribution; Developer ID Installer; notarized+stapled; coverage-gate 10/10)",
    "components": {p.split("=", 1)[0]: p.split("=", 1)[1] for p in kv},
}
with open(path, "a") as f:
    f.write(json.dumps(row) + "\n")
print("build-suite: ships-staged.jsonl += " + json.dumps(row))
PY
rm -rf "$STAGE_DIR"   # keep components/ + distribution.xml + pkg as receipts

# ---------- 8. founder GO commands — PRINTED, NEVER RUN ----------
cat <<EOF

================== FOUNDER GO — PUBLISH COMMANDS (NOT RUN; §3 owner gate) ==================
# Publishing replaces the live one-click installer for every buyer. Founder GO only.
cd $SHIP_ROOT
npx wrangler r2 object put sovereign-files/Black-Label-Suite.pkg --file '$STAGED_PKG' --remote
python3 tools/update-dl-manifest.py --r2key Black-Label-Suite.pkg --sha $SHA
curl -fsSL https://blacklabelbots.com/dl/suite.pkg | shasum -a 256      # must print $SHA
# promote the staged receipt to the real ships.jsonl row (staged flags dropped):
python3 - <<'PROMOTE'
import datetime, json
rows = [json.loads(l) for l in open("ships-staged.jsonl") if json.loads(l).get("app") == "suite"]
r = {k: v for k, v in rows[-1].items() if k not in ("staged_only", "uploaded", "manifest_bumped")}
r["ts"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
r["dl_url"] = "https://blacklabelbots.com/dl/suite.pkg"
r["published_by"] = "founder-GO (artifact staged by tools/build-suite.sh)"
open("ships.jsonl", "a").write(json.dumps(r) + "\n")
print("ships.jsonl += suite " + r["sha256"][:16])
PROMOTE
# finally: update '~/Desktop/Black Label HQ/APPS/_INDEX.md' suite line — sha $SHA,
# size $SIZE B, notarization $SID, and the component builds above.
============================================================================================

build-suite: DONE — STAGED ONLY, publish NOT performed; live /dl/suite.pkg untouched.
  staged:       $STAGED_PKG
  sha256:       $SHA
  size:         $SIZE bytes
  notarization: $SID (Accepted, stapled, coverage 10/10)
  receipts:     $BUILD_DIR (components/, distribution.xml)
EOF
