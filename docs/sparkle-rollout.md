# Sparkle 2.x fleet rollout — the per-app recipe

**Status:** PILOT LIVE (Sunset b11, 2026-08-13). This doc is the exact recipe to take the
other macOS apps onto Sparkle in-app auto-updates, one app at a time, without breaking a
single existing lane. Pilot evidence: `https://sunsetmixing.com/updates/appcast.xml` (200,
EdDSA-signed enclosure), archive streamed same-domain, b11 notarized+stapled
(submission `cff5bc56-d848-44df-9e94-2ab435088656`).

Reference implementation: **BlackLabelAcetate branch `sparkle-pilot-20260812`**
(commits `529f4d5` app/build lane, `b66de93` feed/web lane). Copy it, don't re-derive.

---

## 0. The one key (already minted — do NOT mint again)

ONE EdDSA key signs every app's feed (Sparkle's own recommendation: one key per team).

- Canonical: login keychain item **"Private key for signing Sparkle updates"** (minted 2026-08-13).
- Headless/CI lane: `~/.utah/secrets/sparkle/sunset-ed25519.key` (0600) via `--ed-key-file`.
- Public key (goes in every app's Info.plist `SUPublicEDKey`):
  `emM8hpgsp6z1H7S60W0Rd7eEVgW6nVbZLMs+wKxI3cU=`
- **FOREVER-KEY.** Losing it strands every installed user on manual re-download.
  BL-Archive copy pending next mount. Never print, never commit, never loosen 0600.

Tooling comes from the pinned vendor drop — `scripts/fetch-sparkle.sh` in the app repo
(Sparkle **2.9.5**, tarball SHA256 `015336b6…840d73cc`) → `Vendor/Sparkle/bin/{generate_appcast,sign_update,generate_keys}`
plus `Vendor/Sparkle/Sparkle.framework`. `Vendor/` stays out of git (2026-08-08 binary purge).

## 1. Per-product feed domains (brand isolation is NON-NEGOTIABLE)

A feed URL is user-visible surface (it's in the app bundle, in probes, in proxies). Every
feed + enclosure URL must live on the product's OWN brand domain; the storage layer
(R2 bucket names, blacklabelbots hosts) must never appear in any URL an app or buyer sees.

| App (bundle) | Brand surface | Feed URL | Archive serving |
|---|---|---|---|
| Sunset (`com.blacklabel.sunset`) | sunsetmixing.com | `https://sunsetmixing.com/updates/appcast.xml` | **LIVE** — Pages Function `/updates/archives/*` → R2 `sovereign-files` `sunset/updates/*` |
| Ace (`com.blacklabel.assistant`) | ace-bl.tech | `https://ace-bl.tech/updates/appcast.xml` | Pages `ace` — same pattern (Function + R2 binding) |
| Homefront/Vigil (`com.blacklabel.vigil`) | blvigil.com | `https://blvigil.com/updates/appcast.xml` | vigil `_deploy` worker lane — serve from its DOWNLOADS binding |
| Real Estate (`com.blacklabel.realestate`) | blbestate.com | `https://blbestate.com/updates/appcast.xml` | `blbestate-site` worker — R2-backed route |
| Academy (`com.blacklabel.academy`) | blacklabelbots.com (BL-suite brand) | `https://blacklabelbots.com/updates/academy/appcast.xml` | existing `blacklabelbots-site` worker `/updates/*` R2 lane |
| Marketing (`com.blacklabel.marketing`) | blacklabelbots.com | `https://blacklabelbots.com/updates/marketing/appcast.xml` | same |
| Trading (`com.blacklabel.trading`) | blacklabelbots.com | `https://blacklabelbots.com/updates/trading/appcast.xml` | same |
| Circuit (`com.blacklabel.circuit`) | blacklabelbots.com | `https://blacklabelbots.com/updates/circuit/appcast.xml` | same |
| Sovereign (`com.blacklabel.sovereign`) | blacklabelbots.com | `https://blacklabelbots.com/updates/sovereign/appcast.xml` | same |
| HQ (internal) | blacklabelbots.com | `https://blacklabelbots.com/updates/hq/appcast.xml` | same (internal population) |

Rules that fall out of the pilot:
- BL-suite apps phone their own brand (blacklabelbots.com) — that is brand-CORRECT.
  Standalone-brand apps (Sunset, Ace, Vigil, Estate) must NEVER phone blacklabelbots.com.
- Every site that gains `/updates/` extends its containment battery the way Sunset did
  (`SparkleFeedContainmentTests` in `tests/test_delivery_containment.py`): appcast exists,
  parses, enclosure signed + same-domain, every URL self-domain, zero cross-brand markers —
  and the post-deploy live-crawl greps the appcast too.
- **Policy fork to flag per app at rollout:** Sparkle enclosures are plain GETs. Sunset's
  updates are public (founder call 2026-08-06). The blacklabelbots `/updates/` lane today is
  entitlement-gated — putting BL-suite appcasts there means EITHER making those archive keys
  public (founder call per app) OR teaching the app to attach auth via
  `SPUUpdaterDelegate.updater(_:willSendRequest:)`. Do not silently flip a gated lane public.

## 2. Per-app wiring recipe (the raw-swiftc lane, ~30 min/app)

Copy from BlackLabelAcetate `sparkle-pilot-20260812`; every step below exists there.

1. **Vendor:** copy `scripts/fetch-sparkle.sh` into the repo (same pin+SHA). Add `Vendor/` to
   `.gitignore`.
2. **Info.plist:** add
   `SUFeedURL` (per table above) · `SUPublicEDKey` (above) · `SUEnableAutomaticChecks` `true`
   (skips the first-run permission prompt — required for headless proof) ·
   `SUScheduledCheckInterval` `86400`. Fix any stale `CFBundleVersion` while there
   (build script stays authoritative).
3. **build script:** mirror build.sh commits —
   - fetch vendor if missing;
   - swiftc: `-F Vendor/Sparkle -framework Sparkle -Xlinker -rpath -Xlinker "@executable_path/../Frameworks"`;
   - assemble: `ditto Vendor/Sparkle/Sparkle.framework <App>.app/Contents/Frameworks/Sparkle.framework`;
   - **nested sign deepest-first BEFORE the outer sign**, each with
     `codesign --force --options runtime --timestamp --preserve-metadata=entitlements --sign "$SIGN_ID"`:
     `Versions/B/XPCServices/Downloader.xpc` → `Installer.xpc` → `Versions/B/Autoupdate` →
     `Versions/B/Updater.app` → the framework root;
   - outer app sign **WITHOUT `--deep`** (deep re-signs would clobber the nested signing and
     stamp app entitlements onto Sparkle's helpers — the documented brick-at-install failure);
   - verify stays `codesign --verify --deep --strict`.
4. **App entry:** `import Sparkle`; hold
   `SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)`
   (create it AFTER any hermetic selftest early-exit); menu item
   `Button("Check for Updates…") { updaterController.checkForUpdates(nil) }`.
   If the app has a legacy custom updater (Academy-ported family), leave it compiled for its
   selftest lane but UNWIRE its live triggers — two updaters must never both prompt.
5. **project.yml parity:** version bump + embedded-framework dependency (see pilot commit).
6. **Sandbox check:** the Developer-ID fleet is non-sandboxed (forbidden_entitlements enforces
   it) — no XPC Info.plist edits needed. A sandboxed app would need Sparkle's sandboxing doc.
   MAS/iOS/Windows lanes: Sparkle does not apply.
7. **Prove before ship:** app's own test battery + `--selftest-updater` (where it exists) +
   nested `codesign -dvv` shows Developer ID + runtime + timestamp on all five Sparkle items +
   notarize → staple → `spctl --assess` accepted → **tools/notarization-coverage-gate.py** (the
   ticket must cover the nested Sparkle binaries — pilot showed 26 ticket entries).

## 3. Where it lands in ship.py: the `stage_upload` seam

`stage_upload(zip_path, cfg, name, build)` is the seam — it already puts the dl key + the
`updates/<name>/{build}.zip` key to R2 and re-signs the SHA256SUMS manifest. Sparkle bolts in
right after those puts, BEFORE `stage_manifest`:

```
# inside stage_upload, after the two r2 puts + dl-manifest re-sign:
#   1. keep a per-product archive cache (deltas + regen need the old zips):
#        ~/BlackLabelShip/work/sparkle/<name>/   ← copy zip_path in
#   2. generate the signed appcast over that cache:
#        Vendor bin: generate_appcast \
#          --ed-key-file ~/.utah/secrets/sparkle/sunset-ed25519.key \
#          --download-url-prefix "<product feed archive base>/" \
#          --maximum-versions 3 \
#          -o work/sparkle/<name>/appcast.xml work/sparkle/<name>/
#      (old archives present ⇒ generate_appcast emits binary DELTAS automatically — upload
#       the *.delta files beside the zips, same key prefix)
#   3. publish per product surface:
#        - worker-served domains (blacklabelbots/blvigil/blbestate): r2 put the appcast to the
#          product's updates prefix; worker serves it same-domain
#        - Pages-served brands (sunset, ace): write into the site repo's web/updates/ and run
#          THAT repo's gated deploy script (never a raw wrangler call — the brand gates live there)
# cfg additions per app toml:  sparkle_feed_url · sparkle_archive_url_prefix · sparkle_appcast_dest
```

`stage_manifest` (the legacy `/api/version/<product>` JSON) KEEPS RUNNING per app until that
app's pre-Sparkle population drains — the old field builds can only hear the old manifest.
Retire it per-app, by evidence (download counter on the old lane at zero), never fleet-wide.

## 4. The b12 round-trip — the proof that closes the pilot

b11 proved: wire, sign, notarize, feed live, signature verifies against the pinned public key,
scheduled-check runs. The one thing only a REAL second build can prove is the full swap:
**b11 installed → Sparkle sees b12 in the feed → downloads → verifies EdDSA → Installer.xpc
swaps the bundle → relaunch as b12.** Do not fake it; run it:

1. In BlackLabelAcetate: `BUILD_VERSION=12` (build.sh + Info.plist), build
   `ARCH=universal SIGN_ID=05494FC15FB97F422400BC32DF6D67FC2D28855B ./build.sh`,
   notarize (`--no-wait` + poll — `--wait` bus-errors on the beta host), staple,
   coverage-gate.
2. `ditto -c -k --keepParent` → `Sunset-1.0-b12.zip` → r2 put `sovereign-files/sunset/updates/`.
3. `generate_appcast` over a dir holding BOTH b11+b12 zips (first delta appears) →
   commit `web/updates/appcast.xml` → `scripts/deploy-web.sh` (gates + live crawl).
4. On the b11 machine: launch Sunset (or wait for the daily tick). Expected: Sparkle update
   sheet "Sunset 1.0 (12)" → Install & Relaunch.
5. **Receipts (§5.1):**
   - before/after `PlistBuddy -c 'Print :CFBundleVersion' /Applications/Sunset.app/Contents/Info.plist` → 11 → 12
   - `defaults read com.blacklabel.sunset SULastCheckTime` advanced
   - unified log: `log show --last 30m --predicate 'sender == "Sparkle"'` shows the
     download/extract/install sequence, zero signature complaints
   - post-swap `codesign --verify --deep --strict` + `spctl --assess` accepted on the swapped bundle
   - the old bundle auto-backed-up by Sparkle (plus our `/Applications/.fleet-bak/` copy)
6. Only after a green round-trip does an app graduate from "wired" to "auto-updating" in HQ.

## 5. Rollout order (risk-ascending)

1. ~~Sunset~~ — pilot live (this doc).
2. **Sunset b12 round-trip** (closes the proof; unblocks everything below).
3. Marketing (b80 lane freshest, same raw-swiftc shape).
4. Ace (own domain ready; ship with the Aug 19 delivery build so pre-order buyers
   start on an auto-updating build).
5. Academy / Trading / Circuit / Sovereign / HQ — after the blacklabelbots `/updates/`
   public-vs-gated policy call per §1.
6. Homefront/Vigil + Real Estate — their site lanes gain `/updates/` first (worker routes),
   then the app wiring.

Every step: single-writer lock on the product repo, worktree if dirty, gated deploys only,
receipts in the ship ledger.
