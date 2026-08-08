#!/usr/bin/env python3
"""Inject a buyer-facing README.txt beside the .app in each shipped zip, re-upload
to R2 (both keys), re-sync the /api/version manifest sha, and append an honest
ledger line. The notarized .app bundle itself is NEVER touched — Gatekeeper and
the in-app updater's notarization/TeamID checks still pass; only the zip sha
changes, which is why the manifest must be re-synced in the same pass.

Usage: python3 inject_readme.py [app ...]   (default: all seven)
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys

SHIP_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SHIP_ROOT)
import ship  # reuse parse_toml_lite + constants — single source of truth

WORK = os.path.join(SHIP_ROOT, "work")
STAGE = os.path.join(SHIP_ROOT, "work", "readme-stage")

SUPPORT = """YOUR ACCOUNT, UPDATES & SUPPORT
- Manage your subscription and downloads any time: https://blacklabelbots.com/dashboard
%(updates)s- Questions or trouble: info@blacklabelbots.com
- Community: https://discord.gg/UnmSggQXnD

LICENSE
One personal license per purchase. Please don't redistribute the app or your access key.

- Black Label Bots
"""

UPD_INAPP = "- The app updates itself in-app; every update is verified against Apple's notarization and our Developer ID signature before it installs.\n"
UPD_DASH = "- Updates: download the latest build free from your dashboard (link above).\n"

APPS = {
    "trading": {
        "title": "BLACK LABEL TRADING",
        "first_run": """FIRST RUN
1. Open the app. The data backend starts itself - nothing to launch separately.
2. Connect YOUR OWN platform login when prompted (WealthCharts, TopStep,
   or Tradovate). The app starts EMPTY
   until your feed connects - it ships with no market data and no history.
3. Signals appear once your live feed is flowing.

HONEST NOTES
- This app produces SIGNALS and analytics. It never places a trade unless you
  explicitly arm execution yourself (execution is OFF by default, paper-first,
  risk-gated). You stay in control of your broker account at all times.
- Signal quality is measured out-of-sample and shown in-app per engine/symbol.
  Nothing here promises profits, and past signals are not a track record.
""",
        "updates": UPD_INAPP,
    },
    "leads": {
        "title": "BLACK LABEL LEADS",
        "first_run": """FIRST RUN
1. Open the app.
2. Paste your access key (it's in your purchase email, and always available at
   https://blacklabelbots.com/dashboard) into Settings -> Access Key.
   Until a key is entered the app runs in limited preview mode.
3. Search the lead database, build lists, and enrich contacts.

HONEST NOTES
- Outreach sends from YOUR OWN mailbox, which you connect yourself - we never
  send email on your behalf and never see your mailbox credentials.
- The app ships with NO lead data inside; results stream from your subscription.
""",
        "updates": UPD_INAPP,
    },
    "sovereign": {
        "title": "BLACK LABEL SOVEREIGN",
        "first_run": """FIRST RUN
1. Open the app. A short setup does everything for you - it installs a free
   private assistant that runs on your own Mac. No account, no API key, and
   nothing to configure. (Optional, for the most powerful mode: connect your
   own Claude account later in Settings > Brain.)
2. Voice: grant microphone permission when macOS asks. During setup you name
   your assistant and say the name three times to train it - after that, just
   say the name to talk hands-free. Push-to-talk works too.
3. Calendar features ask for calendar permission the first time you use them.

HONEST NOTES
- Everything runs and stores locally on your Mac. This download contains no
  account, no memory, and no data from anyone else.
""",
        "updates": UPD_INAPP,
    },
    "realestate": {
        "title": "BLACK LABEL REAL ESTATE",
        "first_run": """FIRST RUN
1. Open the app.
2. Paste your access key (purchase email, or https://blacklabelbots.com/dashboard)
   when prompted. That unlocks the county public-records property index.
3. Search properties, score deals, and run comps/ARV calculators.

HONEST NOTES
- The index is built from public county records only. Where a county isn't
  covered yet the app says so honestly instead of inventing data.
- Skip-trace style enrichment happens on YOUR machine; we don't store or sell
  personal contact data server-side.
""",
        "updates": UPD_INAPP,
    },
    "marketing": {
        "title": "BLACK LABEL MARKETING",
        "first_run": """FIRST RUN
1. Open the app.
2. Point it at YOUR brand assets (logo, colors, clips) - everything it makes is
   generated locally from your own material.
3. Build reels, landing pages, funnels, and email spotlights from the sidebar.
4. Publishing to social networks uses Reel Relay: the app hands the finished
   reel to your iPhone (Handoff) and opens each network's native composer -
   your accounts, your logins, no passwords shared with us.

HONEST NOTES
- Analytics panels (GA, Ads) start EMPTY until you connect your own accounts.
""",
        "updates": UPD_INAPP,
    },
    "homefront": {
        "title": "VIGIL",
        "first_run": """FIRST RUN
1. Open Vigil. It runs on your Mac alone - no account, no cloud, and no
   hardware required to begin. Your Mac's own sensing powers Security presence
   right away.
2. Allow "Local Network" access when macOS asks - that's how Vigil finds the
   smart devices already on your Wi-Fi (nothing ever leaves your LAN).
3. Grant microphone/camera only if you turn on the room-sensing features that
   use them - they're clearly labeled in-app and stay off until you enable them.

HONEST NOTES
- The live house map and through-wall room sensing draw from optional Vigil
  sensor nodes (ESP32). Until a node is connected the app says so honestly and
  runs its Mac-only sensing - it never shows invented rooms, devices, or vitals.
- Room-sensing (sonar/pose) features are experimental and labeled as such.
- Nothing is uploaded anywhere; your home stays in your home.
""",
        "updates": UPD_DASH,
    },
    "academy": {
        "title": "BLACK LABEL ACADEMY",
        "first_run": """FIRST RUN
1. Open the app and start learning - the full lesson library is included and
   works offline. No account, no sign-in, no payment inside the app.
""",
        "updates": UPD_DASH,
    },
    "circuit": {
        "title": "CIRCUIT",
        "first_run": """FIRST RUN
1. Open the app.
2. Choose the repository you want Circuit to grade. A new install starts blank -
   it does not ship with any repo history, paths, or customer data.
3. Circuit starts a local grading server, opens the report in your default
   browser, and stops the server when you quit the app.

HONEST NOTES
- Circuit grades the code you select on your Mac. It does not upload your repo,
  include demo grades, or preload anyone else's project.
- This build requires Apple Silicon because the bundled Node runtime is arm64.
""",
        "updates": UPD_DASH,
    },
}

TEMPLATE = """%(title)s
%(rule)s
Thanks for being here. This is your copy - it runs on YOUR machine, on YOUR
data. This download contains no customer data, no credentials, and nothing
from anyone else's account.

INSTALL
1. Drag "%(app_name)s" into /Applications.
2. Open it. The app is Apple-notarized, so macOS should open it cleanly
   (if Gatekeeper asks the first time, choose Open).

%(first_run)s
%(support)s"""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"FAIL {' '.join(cmd)}: {(r.stderr or r.stdout)[:300]}")
    return r


def main():
    targets = sys.argv[1:] or list(APPS)
    os.makedirs(STAGE, exist_ok=True)
    results = {}
    for name in targets:
        meta = APPS[name]
        cfg = ship.parse_toml_lite(os.path.join(SHIP_ROOT, "apps", f"{name}.toml"))
        src_zip = os.path.join(WORK, f"{name}.zip")
        man_path = os.path.join(WORK, f"{name}-manifest.json")
        if not (os.path.exists(src_zip) and os.path.exists(man_path)):
            print(f"SKIP {name}: missing zip or manifest")
            continue
        manifest = json.load(open(man_path))
        build = str(manifest["latest_build"])

        # already injected? (README.txt at archive root)
        listing = subprocess.run(["unzip", "-l", src_zip], capture_output=True, text=True).stdout
        if "\n" in listing and " README.txt" in listing.split("\n\n")[0] or "  README.txt" in listing:
            print(f"{name}: README already present, re-syncing manifest only")
            staged = src_zip
        else:
            readme = TEMPLATE % {
                "title": meta["title"],
                "rule": "=" * len(meta["title"]),
                "app_name": cfg["app_name"],
                "first_run": meta["first_run"].rstrip(),
                "support": SUPPORT % {"updates": meta["updates"]},
            }
            rpath = os.path.join(STAGE, "README.txt")
            with open(rpath, "w") as f:
                f.write(readme)
            run(["zip", "-j", src_zip, rpath])   # append at archive root
            staged = src_zip
            print(f"{name}: README.txt injected")

        new_sha = sha256(staged)
        # upload both keys
        for key in (cfg["r2_dl_key"], cfg["r2_updates_key"].replace("{build}", build)):
            run(["npx", "wrangler", "r2", "object", "put", f"{ship.R2_BUCKET}/{key}",
                 "--file", staged, "--remote"], cwd=SHIP_ROOT)
            print(f"{name}: r2 {key} uploaded")
        # manifest re-sync
        manifest["sha256"] = new_sha
        manifest["published"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with open(man_path, "w") as f:
            json.dump(manifest, f, indent=2)
        run(["npx", "wrangler", "r2", "object", "put", f"{ship.R2_BUCKET}/version/{name}.json",
             "--file", man_path, "--remote"], cwd=SHIP_ROOT)
        # confirm live
        import urllib.request
        req = urllib.request.Request(f"{ship.SITE_URL}{cfg['manifest_endpoint']}",
                                     headers={"User-Agent": "Mozilla/5.0 (readme-inject confirm)"})
        live = json.load(urllib.request.urlopen(req, timeout=60))
        assert live.get("sha256") == new_sha, f"{name}: live manifest sha mismatch"
        print(f"{name}: manifest live, sha {new_sha[:12]} confirmed")
        # honest ledger line
        with open(ship.LEDGER, "a") as f:
            f.write(json.dumps({
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "app": name, "commit": "readme-inject", "build": build,
                "sha256": new_sha, "notarization_id": manifest.get("notarization_id"),
                "dry_run": False,
                "gates": ["readme_injected_app_bundle_untouched", "manifest_resynced", "live_sha_confirmed"],
            }) + "\n")
        results[name] = new_sha[:12]
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
