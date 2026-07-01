# ship.toml schema — one file per app in `apps/<name>.toml`

Flat TOML subset: `key = "string"`, `key = ["array", "of", "strings"]`, `key = true|false`.
Loader tries stdlib `tomllib` (py3.11+), falls back to the built-in mini-parser (system py3.9-safe).
`ship.py --self-check` validates every config against this schema.

## Required keys

| key | type | meaning |
|---|---|---|
| `repo` | string | absolute path (~ ok) to the app's source repo, e.g. `~/BlackLabelSovereign` |
| `bundle_id` | string | CFBundleIdentifier, e.g. `com.blacklabel.sovereign` |
| `app_name` | string | built .app name, e.g. `Black Label Sovereign.app` |
| `build_cmd` | string | command run inside `repo` that produces the .app (repo's own script) |
| `built_app_path` | string | where `build_cmd` leaves the .app — relative to `repo` OR absolute/~ (e.g. `/tmp/bls-devid/Black Label Sovereign.app`) |
| `arch` | string | `universal2` or `arm64` (universal2 required for TRD/RE/ACA lanes) |
| `required_entitlements` | array | every entitlement that MUST be present post-sign (positive gate) |
| `forbidden_entitlements` | array | entitlements that must NOT appear (may be empty `[]`) |
| `ships_no_data_globs` | array | glob patterns that must match NOTHING inside the bundle (db/csv/tokens/pem/PII) |
| `r2_dl_key` | string | R2 object key for the storefront download, e.g. `sovereign.zip` (bucket `sovereign-files`) |
| `r2_updates_key` | string | R2 object key template for the updater channel, `{build}` substituted at ship time, e.g. `updates/sovereign/{build}.zip` (matches live realestate manifest convention) |
| `manifest_endpoint` | string | live manifest URL path, e.g. `/api/version/sovereign` |
| `dl_url` | string | full public download URL used by the live gate (with comp key `?k=…` if gated) |

## Optional keys

| key | type | meaning |
|---|---|---|
| `ports` | array | localhost ports the app binds (collision check in ACC-3), e.g. `["8787"]` |
| `test_cmd` | string | repo test suite command for preflight (skipped if absent, logged loudly) |
| `sign_identity` | string | Developer ID identity hash override (default: resolve by team 745ZPGFRA5) |
| `entitlements_file` | string | path to entitlements plist relative to repo (required if `required_entitlements` non-empty) |

## Invariants enforced by the spine (not per-app config)

- zip via `ditto -c -k --keepParent --norsrc --noqtn` (no AppleDouble `._*` sidecars)
- sign LAST (any post-sign mutation fails `gate_seal`)
- notarize `notarytool submit --no-wait` + poll (beta-host bus-error workaround), then `stapler`
- upload `wrangler r2 object put --remote` to BOTH keys
- live gate: fresh download from `dl_url`, sha256 == local, `spctl` on quarantine-tagged copy
- manifest bump only AFTER live gate; re-fetch confirms
- every ship appends a line to `ships.jsonl`
