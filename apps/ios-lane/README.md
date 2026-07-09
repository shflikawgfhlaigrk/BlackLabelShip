# iOS App Store lane (shared, fail-closed)

Canonical, reusable GitHub Actions lane that clears the single shared root cause
behind all six INVALID_BINARY states: the **beta Xcode 26.6 / build 17F113 host
stamp**. The Mac workstation runs macOS 27 beta (`26A*`) with only Xcode 26.6
beta (`17F113`), so every locally-archived binary carries the Apple-rejected
`ITMS-90111/90301` fingerprint. A GitHub-hosted macOS runner ships Apple-ACCEPTED
RELEASE Xcodes; this lane selects one, proves it with the shared guard, archives,
and fails CLOSED on any beta toolchain.

## Files
| file | role |
|------|------|
| `ios-appstore.yml` | the workflow — copy to `<repo>/.github/workflows/` |
| `appstore_toolchain_guard.sh` | shared guard — copy to `<repo>/ci/` (verbatim from `~/BlackLabel-Submission`) |
| `ExportOptions-AppStore-iOS.plist` | AppStore export plist — copy to `<repo>/ci/` |
| `ios_lane.py` | local fail-closed decision core (mirrors `ship.py` Windows lane) — copy to `<repo>/ci/` |
| `test_ios_lane.py` | ship-contract test — copy to `<repo>/ci/` |

## Wiring a repo (Stage-2, per app)
1. `mkdir -p <repo>/.github/workflows <repo>/ci`
2. Copy `ios-appstore.yml` → `<repo>/.github/workflows/ios-appstore.yml`
3. Copy `appstore_toolchain_guard.sh`, `ExportOptions-AppStore-iOS.plist`,
   `ios_lane.py`, `test_ios_lane.py` → `<repo>/ci/`
4. Edit the four `env:` lines at the top of the workflow (`APP_NAME`, `SCHEME`,
   `PROJECT`, `ARTIFACT_SLUG`).
5. Commit + push. The `push` trigger (paths: workflow / `ci/**` / `project.yml` /
   `Sources/**`) runs it automatically; or `gh workflow run ios-appstore.yml`.

## Fail-closed contract
- guard rejects (beta / `Xcode 27.*` / `17F113` / macOS `26A`) → **job FAILS, no artifact**.
- no signing wired (default) → produce `<slug>-ios-UNSIGNED-STAGED-ONLY.ipa`,
  guard-check it, **STOP**. No upload, no `ships.jsonl`.
- signing wired (owner sets repo var `IOS_SIGNING_READY=true`) → export an
  upload-ready signed IPA and **STOP at the upload boundary**.
- transport to App Store Connect fires ONLY on the double owner gate
  (`IOS_SIGNING_READY=true` **and** `IOS_CONFIRM_UPLOAD=1`). The lane never
  auto-submits.

## Owner gates (Michael only)
- Distribution signing on CI: set repo variable `IOS_SIGNING_READY=true` and add
  secrets `ASC_API_KEY_ID`, `ASC_API_ISSUER`, `ASC_API_KEY_P8` (App Store Connect
  API key). Until then the lane stages unsigned by design.
- Submit for review: `IOS_CONFIRM_UPLOAD=1` (repo variable). App Privacy nutrition
  labels + the final "Submit for Review" remain human-only in App Store Connect.

## The empirical proof this lane exists to answer
The `Guard-check IPA + print DTXcodeBuild` step prints `DTXcodeBuild`,
`DTXcode`, `DTSDKBuild`, `BuildMachineOSBuild` for the produced IPA and writes
them to `provenance.txt` (bundled with the artifact). A `DTXcodeBuild` other than
`17F113` proves the Apple-rejected beta fingerprint is gone.
