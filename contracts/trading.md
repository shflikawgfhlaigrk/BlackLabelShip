# Trading — page-claim contract (verified against build 2026-07-01)

Every live-page claim maps to **TRUE-IN-BUILD** (keep) or **REWRITE/REMOVE** (WEB lane executes).
Source of truth: `~/BlackLabelTrading/backend` (`bltd_store.CONFIG_DEFAULTS`, `bltd_analytics`, `bltd_exec`).

## Numeric claims

| Live claim | Verdict | Truth in build | Action |
|---|---|---|---|
| "16 modules" / "16 signals" | **REWRITE** | 9 firing signal engines: meanrev, breakout, research, momentum, structure, regime, channel, context_a, context_b (`CONFIG_DEFAULTS["engines"]`, `_KNOWN_ENGINES`) | say **"9 signal engines"** |
| "8 timeframes" | **REWRITE** | ONE continuously-configurable bar size, `barSeconds` default 15s, range 1–3600s (`_CONFIG_RANGES`). Not 8 discrete timeframes. | say **"configurable bar interval (1s–1h)"** |
| implied "track record" / win-rate / equity curve | **REMOVE if present** | No proven live track record. Edge-gate proves per-(engine,symbol) OOS edge before a signal fires; that is a *gating* claim, not a P&L claim. NEVER restore 791,123 / 82.0% / 648W. | keep only the edge-gate description |

## Capability claims (TRUE-IN-BUILD — keep)

- **Live multi-platform capture** — WealthCharts + TopStep + Tradovate + MT5 + TradingView + cTrader parsers exist (`bltd_parsers`, `bltd_feeds`); the buyer connects their OWN logged-in charts via Chrome CDP. TRUE. (Feed liveness is a runtime/ACE-1 concern, not a page claim.)
- **ES family incl. MES micros** — capture accepts ES + MES (micro E-mini), the most-traded TopStep instrument (T-1 fix, `is_es_symbol`). TRUE.
- **Edge-gate** — a signal only fires for an (engine,symbol) cell with a proven out-of-sample edge (binomial + Benjamini-Hochberg FDR; `oosFrac`, `minTrades`, `fdrQ`). TRUE.
- **Real indicators** — ATR, EMA, SMA, RSI, Bollinger + momentum/regime/structure classifiers (`bltd_analytics`). TRUE. Do NOT claim CVD/VPIN/SMT/VWAP as live inputs — those are OHLC-close-only-limited and ship honest-absent.
- **Autonomous execution, paper-first** — broker execution exists but ships default-OFF, paper-first, risk-gated, with a kill switch; live requires arm + buyer's own broker creds (Keychain) + fresh OS-auth + a demo-validated path (`bltd_exec` RiskGateChain). Per-order human confirm is MANDATORY on every live order and cannot be disabled via `/api/config` (T-2). TRUE. Do NOT claim "places live trades out of the box."
- **Ships empty / own-login** — no bundled bars, ledger, or creds; SQLite store created empty at first run; buyer connects their own feed. TRUE.

## Platform / requirements

- **Runs on Apple Silicon AND Intel** — TRUE as of T-3: the app is universal2 (Swift binary + bundled CPython 3.11.15 both x86_64+arm64). The old "Apple Silicon required" caveat is now REMOVED. macOS 13.0+.

## Forbidden on the page (grep-enforced by bl-ship site gate)

`791,123` · `82.0%` · `648W` · `16-module` · `16 modules` · `8 timeframes` · any invented win-rate/P&L/equity figure.
