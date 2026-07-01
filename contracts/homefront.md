# Homefront — live-page claim contract (HF-4)

Source of truth: https://blacklabelbots.com/homefront as of 2026-07-01, repo ~/BlackLabelHome @ b7ae5e8 (HF-1/2/4 pass).
Rule: every claim on the page is either TRUE-IN-BUILD (verifiable in the shipped artifact) or must be removed from the page.

| # | Live-page claim | Status | Verification |
|---|---|---|---|
| 1 | Smart-home control on your Mac, no cloud | TRUE-IN-BUILD | LAN-only control plane; no vendor-cloud endpoints in binary (`strings` clean of vendor APIs) |
| 2 | Discovers real devices via Bonjour / mDNS / SSDP | TRUE-IN-BUILD | Discovery engine in app; works when local network permission granted + supported devices present (page states the precondition) |
| 3 | Rooms, scenes, automations | TRUE-IN-BUILD | Automation/scenes engine shipped |
| 4 | Presence-based security via Mac mic + camera sensing | TRUE-IN-BUILD | Acoustic sonar + camera pose on-device; requires mic/camera entitlements (gate: required_entitlements in apps/homefront.toml) |
| 5 | Through-wall CSI is hardware-gated: bundled simulator first, compatible ESP32 node when ready | TRUE-IN-BUILD (honest gate) | CSI reader ships; sim mode bundled; no through-wall capability claimed without hardware — copy fixed under HF-4, do not regress |
| 6 | Vitals are accurate-or-nothing — never faked | TRUE-IN-BUILD | Render-time liveFrame gate (repo f6e845b); stale frames cannot show live vitals |
| 7 | Everything runs locally; nothing sent to a server | TRUE-IN-BUILD | ships_no_data gate + no telemetry endpoints |
| 8 | Ships empty — your home, your data | TRUE-IN-BUILD | ships_no_data_globs in apps/homefront.toml (known_nodes*, alerts*, db/csv/etc.) |
| 9 | Sensor line "Node tiers from $25 · no subscription" | PRE-ORDER COPY | Hardware pre-order, not in the .app; page labels it Pre-order — acceptable as long as labeled |
| 10 | Paid early access (no self-serve Stripe checkout) | TRUE | Product gated via worker product map (HF-3); Stripe SKU is Founder-veto, page CTA = request access |

Forbidden regressions: unqualified "through-wall" claims; any vitals/occupancy numbers not from live sensors; bundling any real home's data.
Intel/Apple-Silicon note: Swift binary universal2; bundled CPython sensing engine is arm64-only by design — disclosed on page FAQ (keep).
