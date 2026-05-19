# Polymarket Autonomous Agent — Monitoring & Control Dashboard (Layer 9)

**Companion document to** `2026-05-19-polymarket-fair-value-agent-design.md`.
**Status:** Design — produced by the `ui-ux-designer` agent, 2026-05-19.
**Scope:** UI/UX plan for L9 of the trading agent. Wireframes and component
sketches only; not implementation.

---

## Component-Reuse Map from `financial_stochastic_sim.tsx`

Every component decision below is made through this lens.

**REUSE directly:**
- VaR/CVaR result display block: labeled value grid with VaR/CVaR lines and
  worst-/best-case rows — repurposed for the bankroll forward-simulation panel.
- Kupiec result display: the accept/reject chip with violation-rate readout —
  adopted into the Validation view's per-strategy zone widget.
- `riskAnalysis` / `backtesting` state-shape patterns: nested objects with
  `confidence`, `violations`, `violationRate`, `kupiecTest.{statistic,pValue,reject}`
  map cleanly onto L5/L7 data.
- Percentile-table pattern (p5/p25/p50/p75/p95 rows): reused in the MC bankroll
  fan panel.
- `grid-cols-*` layout scaffolding and card pattern: base structure adapted to
  the dark theme.

**REPURPOSE (keep the idea, swap implementation):**
- `drawPaths` canvas function → bankroll history chart, but rendered via
  `lightweight-charts` rather than raw canvas (gains hover, zoom, crosshair).
- Monte Carlo loop (`calculateMonteCarloVaR`) → moved to the Python backend (L5);
  the frontend only renders the percentile fan from the pushed payload.

**DROP entirely:**
- All four stochastic-model simulators (`simulateBlackScholes/Vasicek/Heston/JumpDiffusion`)
  — Polymarket is not a price-process problem.
- `blackScholesCall/Put`, Greeks, options state — Polymarket has no options layer.
- `calculateEfficientFrontier`, `solveMinVarianceWithReturn` — no multi-asset
  mean-variance optimization; there is one bankroll across binary bets.
- Benchmark/alpha/beta/Treynor/Jensen/information ratio — no benchmark index
  exists for a prediction-market book.
- Portfolio attribution (Brinson-Hood-Beebower) — contribution analysis is
  per-market-category, not per-asset-weight.
- Play/Pause/Reset animation controls, all model parameter sliders, scenario
  toggles, and the light-mode white background.

---

## 1 — Information Architecture

Single-page application, persistent top navigation, five primary tab views. No
drill-down routing beyond modal overlays and drawer panels.

```
[ POLYMARKET AGENT ]  [ LIVE • $94.20 ]  [ BANKROLL ████░ 94.2% ]  [ KILL SWITCH ]

  OVERVIEW   POSITIONS   SIGNALS   VALIDATION   AUDIT LOG
```

**Principles:** the global status bar (bankroll, live/dry-run badge, connection
freshness) and the KILL SWITCH are always visible regardless of active tab. Five
tabs, not a sidebar — single-operator tool.

**Views:**
- **OVERVIEW** (default) — continuous monitoring: bankroll + drawdown tile,
  connection/freshness banner, open positions, signal queue, per-strategy status
  strip, recent trades, live VaR tile.
- **POSITIONS** — full detail of open/resolved positions; category breakdown,
  mark-to-mid P&L, fill quality, resolution history.
- **SIGNALS** — the L3 research output queue; p̂ vs implied probability, edge,
  confidence, rationale, sources, Kelly sizing; approve/reject/defer in
  manual-override mode.
- **VALIDATION** — L7: per-strategy Kupiec zone, Brier trend, calibration curve,
  walk-forward summary, paper-trade track record for dormant strategies.
- **AUDIT LOG** — append-only structured log of every decision, order, fill,
  cancellation, strategy state change, kill-switch event, and manual override.

**Overlays:** position detail drawer, signal detail modal, strategy config
drawer, kill-switch confirmation overlay.

---

## 2 — Panel / Widget Inventory

### Global / persistent

| Widget | Purpose | Source | Cadence |
|---|---|---|---|
| Connection freshness bar | WS heartbeat, last-tick age | L1 WS | Real-time; amber at 5s, red at 15s, desaturates downstream widgets |
| Live/Dry-run badge | Mode indicator; drives viewport-border color | L8 | On change |
| Bankroll tile (compact) | Current bankroll $ and % of start | L5 | WS real-time |
| Kill-switch button | Halt all trading | L8 command endpoint | Action |

### OVERVIEW

| Widget | Purpose | Source | Cadence |
|---|---|---|---|
| Bankroll + drawdown tile | Balance, start, abs/pct drawdown, kill-trigger level | L5 | WS real-time |
| Bankroll history sparkline | 7-day balance in cents, resolution-annotated | L5 + L6 | WS; new point per fill/resolution |
| Drawdown level indicators | Warning/halt/catastrophic threshold lines | L5 config | Polled 60s |
| Strategy status strip | 4 cards: status, enable toggle, paper/live badge, bankroll-gate progress | L4 | WS on change |
| Open positions (compact) | Top 5 by notional; side, contracts, entry/mid, P&L, days-to-resolution | L6 + L1 | WS price ticks |
| Signal queue (compact) | 3 most recent: market, category, p̂ vs implied, edge, status | L3 | WS push |
| Recent trades feed | Last 5 fills: time, market, side, contracts, fill, slippage vs mid | L6 | WS push |
| VaR tile | 95% 1-day VaR + CVaR, last-computed time | L5 (MC backend) | Polled 5 min / on change |
| Alert rail | CRITICAL/WARNING/INFO; max 3 visible, expandable | L8 | WS push |

### POSITIONS

| Widget | Purpose | Source | Cadence |
|---|---|---|---|
| Open positions (full) | All positions + fill-quality score, resolution type | L6 + L1 | WS real-time |
| Category breakdown donut | Exposure % by category | L6 + L2 | Polled 30s |
| Position detail drawer | Fill history, order-book depth snapshot, entry rationale | L6 + L1 | On open |
| Resolved positions | Last 20: outcome, P&L, final p̂, Brier contribution | L6 + L7 | Polled 60s |
| Partial fill warning strip | Markets with last order <80% filled; slippage, pending qty | L6 | WS push |

### SIGNALS

| Widget | Purpose | Source | Cadence |
|---|---|---|---|
| Signal queue (full) | All pending: p̂, implied, edge, confidence, Kelly fraction, age | L3 | WS push |
| Signal detail modal | Rationale, sources, model breakdown, category assignment | L3 | On open |
| Manual override panel | Approve/reject/defer; only in manual-override mode | L8 | On action |
| Research activity indicator | Per-category last-run time and status (running/idle/error) | L3 | WS push |

### VALIDATION

| Widget | Purpose | Source | Cadence |
|---|---|---|---|
| Per-strategy Kupiec widget | Green(0-4)/orange(5-9)/red(10+) zone, exception count, rate, LR, accept/reject | L7 | Polled 5 min / on resolution |
| Brier score trend | Rolling Brier vs 0.25 random baseline; sample-size warning at N<30 | L7 | Polled 5 min |
| Reliability diagram | 10-bin predicted vs observed; sparse bins (n<5) shown as open circles | L7 | Polled 5 min |
| Walk-forward summary | Last backtest: period, markets, P&L, hit rate, Brier, max DD | L7 | Polled 5 min |
| Paper-trade cards | Dormant strategies: paper P&L, trade count, paper Brier, gate progress | L4 + L7 | Polled 60s |
| MC bankroll fan | 5th/50th/95th-percentile forward fan over 30 days | L5 | Polled 5 min |

### AUDIT LOG

| Widget | Purpose | Source | Cadence |
|---|---|---|---|
| Event stream table | Append-only: time, type, payload summary, triggered-by, severity | L8 | WS push + paginated REST |
| Filter bar | Event-type multiselect, severity, time range | Client | Instant |
| Export button | Download filtered log as JSON/CSV | REST | Action |

---

## 3 — Wireframes

### 3.1 OVERVIEW

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│ [●] POLYMARKET AGENT        $94.20  +94.20%   WS ● LIVE  14:23:07  [■ HALT TRADING]      │
│     ▲ LAST TICK 0.4s ago                      ████████████████████░░ 94.2% bankroll      │
└─────────────────────────────────────────────────────────────────────────────────────────┘
  ┌───────────────────────────────────────────────────────────────────────────────────────┐
  │ ▓▓ OVERVIEW    POSITIONS    SIGNALS    VALIDATION    AUDIT LOG                         │
  └───────────────────────────────────────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │ ! ALERT RAIL: [WARN] FAIR-VALUE signal for "US Election..." approaching expiry        │
  └─────────────────────────────────────────────────────────────────────────────────────┘
  ┌──────────────────────┐  ┌──────────────────────┐  ┌─────────────────────────────────┐
  │ BANKROLL             │  │ DRAWDOWN              │  │ RISK (VaR 95% / 1-day)          │
  │  $94.20              │  │  Current:  -$5.80     │  │  VaR:   -$3.14 (-3.3%)          │
  │  of $100.00 start    │  │           -5.8%       │  │  CVaR:  -$4.71 (-5.0%)          │
  │  [████████████░░]    │  │  L1 warn  ░░░░░░░░░░  │  │  Last calc: 14:20:01            │
  │   94.2% remaining    │  │  L2 halt  ░░░░░░░░░░  │  │  Based on 3 open positions      │
  │  7-day: ▁▂▃▂▄▃▃▄▅▃   │  │  L3 stop  ░░░░░░░░░░  │  │  [see MC fan chart →]           │
  └──────────────────────┘  └──────────────────────┘  └─────────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │ STRATEGY STATUS STRIP                                                                 │
  │ ┌─FAIR-VALUE────────┐ ┌─NEWS-REACTION─────┐ ┌─CROSS-MARKET ARB──┐ ┌─MARKET-MAKING──┐ │
  │ │ ● LIVE            │ │ ○ DORMANT         │ │ ○ DORMANT         │ │ ○ DORMANT      │ │
  │ │ ENABLED [●]       │ │ gate $94/$150     │ │ gate $94/$200     │ │ gate $94/$300  │ │
  │ │ 4 signals today   │ │ [██████░░░░░░]    │ │ [████░░░░░░░░]    │ │ [███░░░░░░░░]  │ │
  │ │ Kupiec: ● GREEN   │ │ Paper P&L +$2.14* │ │ Paper P&L -$0.43* │ │ Paper +$0.00*  │ │
  │ │ 0 exc / 250d      │ │ *simulated        │ │ *simulated        │ │ *simulated     │ │
  │ └───────────────────┘ └───────────────────┘ └───────────────────┘ └────────────────┘ │
  └─────────────────────────────────────────────────────────────────────────────────────┘
  ┌──────────────────────────────────────────────────┐  ┌─────────────────────────────┐
  │ OPEN POSITIONS                              3 of 3 │  │ SIGNAL QUEUE          2 new │
  │ MARKET             S  MID   ENTRY  P&L($)  P&L%    │  │ [POLITICS] Will X win       │
  │ US Pres > 270 EV   Y  0.64  0.58  +$0.36  +10.3%   │  │  p̂=0.71 mkt=0.64            │
  │ BTC > 80k Sep 30   N  0.38  0.41  -$0.09   -7.3%   │  │  edge=+7pp conf=MED         │
  │ Fed Cut Nov 7      Y  0.55  0.52  +$0.06   +5.8%   │  │  Kelly: $1.20 [PENDING]     │
  │ Notional $4.92  Mark P&L +$0.33 (+0.35% bankroll)  │  │ [CRYPTO] ETH > 3k ...       │
  └──────────────────────────────────────────────────┘  └─────────────────────────────┘
  ┌─────────────────────────────────────────────────────────────────────────────────────┐
  │ RECENT TRADES                                                                         │
  │ TIME      MARKET                SIDE  CTRS  FILL    MID@T   SLIP    STATUS             │
  │ 14:18:04  US Pres > 270 EV      BUY Y  10   0.581   0.580  +0.1¢   FILLED             │
  │ 13:22:30  WHO declares ...      BUY Y   8   0.201   0.205  -0.4¢   PART(6/8)          │
  └─────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Stale-data / disconnected overlay (any view)

```
╔═════════════════════════════════════════════════════════════════════════════════════╗
║  ⚠  WEBSOCKET DISCONNECTED — Last data received 47s ago                              ║
║  Displayed values may not reflect current market state. Agent is still running.      ║
║  Attempting reconnect... (attempt 3 of 5)              [FORCE RECONNECT]             ║
╚═════════════════════════════════════════════════════════════════════════════════════╝
[ all panel widgets below desaturated to ~30%, timestamps frozen, no ticks ]
```

The VALIDATION and SIGNALS wireframes are detailed in the agent transcript; the
key elements (Kupiec zone ruler, reliability diagram with sparse-bin markers,
research-engine status row) are reflected in the widget inventory above.

---

## 4 — Component Hierarchy

Nodes marked `[tsx]` descend from or adapt patterns in `financial_stochastic_sim.tsx`.

```
<AgentDashboard>                          ← root; WebSocket singleton
  <GlobalStatusBar>
    <ConnectionFreshnessPip>              ← drives stale-data cascade
    <BankrollCompact> <LiveModeBadge> <KillSwitchButton>
  <AlertRail> <AlertChip severity=...>
  <TabNav>
  <OverviewPanel>
    <MetricCardRow>
      <BankrollCard><BankrollSparkline>   ← adapted from drawPaths [tsx]
      <DrawdownCard><DrawdownLevelIndicator>
      <VaRCard><VaRValues>                ← reuses riskAnalysis shape [tsx]
    <StrategyStatusStrip>
      <StrategyCard><KupiecZonePip>       ← adapted from Kupiec display [tsx]
                    <BankrollGateBar>
    <OpenPositionsSummary><PositionRow>
    <SignalQueueSummary><SignalChip>
    <RecentTradesFeed><TradeRow>
  <PositionsPanel>
    <PositionTable><CategoryBreakdownDonut><PartialFillWarningStrip>
    <ResolvedPositionTable>
    <PositionDetailDrawer><FillHistory><OrderBookDepthSnap><EntryRationaleRef>
  <SignalsPanel>
    <ResearchEngineStatusBar>
    <SignalQueue><SignalCard><ProbabilityBar><EdgeBadge>
                              <RationaleBlock><SourcesList>
                              <ManualOverrideControls>
    <ActedSignalsFeed>
  <ValidationPanel>
    <KupiecZoneBoard><KupiecZoneWidget>   ← adapted from kupiecTest display [tsx]
    <CalibrationSection><ReliabilityDiagram><SparseBinLabel>
                        <BrierTrendSparkline>
    <WalkForwardSummary>
    <PaperTradeCards><MCBankrollFanChart><PercentileTable>  ← MC pattern [tsx]
  <AuditPanel><AuditFilterBar><AuditEventTable><ExportButton>
  <KillSwitchConfirmOverlay> <StrategyConfigDrawer>
  <SignalDetailModal> <PositionDetailDrawer>
```

---

## 5 — Kill-Switch & Control UX

**Chosen pattern: press-and-hold for 1.5 s** (configurable 0.8–3.0 s,
audit-logged). Rejected: typed confirmation (too slow under stress, 3–5 s);
two-click dialog (the "are you sure?" modal is itself misread under panic).
Press-and-hold is fast enough for emergencies yet impossible to trigger by an
accidental click or keyboard bounce, and gives progressive feedback.

The HALT button is top-right of the global status bar — always visible, never
disabled (halting dry-run is valid), never behind a menu.

```
ARMED:    [ ■ HALT TRADING / hold 1.5s to confirm ]   bg #b91c1c
FIRING:   [ ■ HALTING... ████░░░ / release to cancel ] fill bar + pulse
HALTED:   full-width banner, bg #78350f, [RE-ARM TRADING]
```

Re-arming requires a distinct single click (not a hold) plus a 1 s countdown —
the asymmetry is deliberate: emergency halt fast, re-arm deliberate. Global
shortcut `Ctrl+Shift+H` begins the hold timer; every invocation, including
aborted holds, is audit-logged.

**Per-strategy controls:** enable/disable toggle (confirmation tooltip noting
open positions are *not* auto-closed); dry-run/live toggle requires a 500 ms hold.

**Dry-run vs live indicator (high-consequence):** a 2 px viewport border —
red `#dc2626` when any strategy is live, blue `#1d4ed8` when all are paper. The
mode badge is never smaller than 14 px and is re-fetched from the backend on
every load and reconnect — never assumed from local state.

---

## 6 — State Design

- **Loading:** REST snapshot before WS opens; skeleton shimmer per card; the
  kill-switch is available immediately via its own REST endpoint.
- **Empty:** neutral factual copy only — never reassuring ("You're all set!"
  primes complacency). Calibration diagram explicitly shows `n=0`.
- **Error tiers:** (1) data error — red border, last-good value + timestamp;
  (2) stale warning — amber border, "No update for Ns"; (3) render error —
  React error boundary replaces the widget with a labeled error card.
- **Stale-data cascade** (the most dangerous state — frozen prices misread as a
  quiet market): 0–5 s normal; 5–15 s amber pip + amber widget borders;
  15 s+ red pip, widgets desaturate, non-dismissible banner; 30 s+ global red
  overlay, `[STALE]` superscripts; 60 s+ "AGENT MAY BE UNRESPONSIVE", kill-switch
  pulses. Every widget's last-update timestamp is always visible.

---

## 7 — Visual & Density Guidance

Dark-mode only (extended monitoring sessions; matches trading/aviation/SOC norms).

```
Viewport  #0f172a   Card #1e293b   Header/divider #334155   Row hover #1e3a5f
Primary text #f1f5f9   Secondary #94a3b8   Tertiary #64748b   Disabled #334155
```

**Color semantics — color carries meaning, never decoration:**
- P&L: profit `#22c55e`, loss `#ef4444` (text/icon only, never background).
- Kupiec zones: green `#16a34a`, orange `#d97706`, red `#dc2626`.
- Alerts: CRITICAL `#dc2626` `◆`, WARNING `#d97706` `▲`, INFO `#3b82f6` `●`.
- Strategy states: LIVE `#22c55e` `●`, DORMANT `#64748b` `○`, PAPER `#3b82f6` `◎`,
  error `#dc2626` `✕`.
- **Colorblind safety:** shape + color always paired; profit/loss values always
  carry `+`/`-` signs; Kupiec zones carry text labels; reliability bins use
  filled vs open circles. Test against Coblis before v1.

**Density:** everything needed for a go/no-go judgment visible without scrolling
at 1440 px. Primary values 28 px bold; no font below 11 px.

**Do NOT use:** rolling number counters, celebratory animations on profit,
ticker-tape marquees, scoreboard-style hero numbers (the $100 must not look
institutional), percentage bars as the primary metric.

**$100 framing:** every monetary display shows absolute `$` *and* `% of bankroll`
together — `$40` looks like a coffee; `40% of bankroll` is catastrophic.

---

## 8 — Tech Recommendations

- **Charting:** `lightweight-charts` (TradingView) for real-time time series
  (bankroll sparkline); `Recharts` for static/polled panels (reliability diagram,
  donut, Kupiec ruler, MC fan). No raw canvas in production.
- **State:** `Zustand` for real-time agent state (one store, slices);
  `TanStack Query` for polled REST snapshots. No Redux (single operator).
- **Transport:** FastAPI WebSocket with a `{seq, ts, type, payload}` envelope;
  `seq` detects dropped messages → reconnect + snapshot re-fetch. Server ping
  every 3 s; missing ping within 5 s triggers the stale cascade. SSE fallback
  for proxy-blocked environments.
- **Kill-switch is a separate REST `POST /api/v1/agent/halt`** — never a WS
  message, because WS delivery is not guaranteed during the disconnect events
  when you most need to halt. 500 ms timeout; on timeout the UI warns and offers
  retry.
- **Framework:** React 18 + TypeScript strict, Vite, Tailwind (palette registered
  as config tokens, not inline strings).

---

## 9 — Build Phasing

**v1 — $100 fair-value launch (build first, nothing else).** Global status bar +
kill-switch + dry-run/live border are non-negotiable day-1 items. Include:
bankroll/drawdown/VaR tiles, bankroll sparkline, strategy status strip (only
fair-value interactive), compact positions/signals/trades, audit log, VALIDATION
with fair-value Kupiec + Brier (sparse-data warning). **Defer:** reliability
diagram (until n≥30), MC fan chart, full POSITIONS/SIGNALS tabs, walk-forward
summary, paper-trade cards, category donut, audit export.

v1 build order: (1) status bar + kill-switch + mode border, (2) WS layer +
freshness cascade, (3) bankroll/drawdown/VaR tiles, (4) positions table,
(5) trades feed, (6) audit log, (7) strategy strip + Kupiec, (8) signal queue.

**v2 — dormant strategies activate** (bankroll gates: news $150, arb $200,
market-making $300): full SIGNALS tab + manual-approve, research-engine status,
per-strategy Kupiec, MC fan, category donut, reliability diagram, full POSITIONS
tab + detail drawer, partial-fill strip, paper-trade cards.

**v3 — post-launch maturation** (3+ months data): walk-forward summary, strategy
comparison, audit export, config drawer, alert-threshold tuning, P&L by category,
slippage analysis.

---

## Flagged UX Risks (autonomous real-money trading)

1. **Stale-feed-as-flat-market** (highest severity) — frozen prices read as "quiet
   market." The Section 6 cascade is v1 day-1 mandatory, not optional.
2. **Complacency from persistent green** — a calibrated agent shows green for
   days, training operators to stop scrutinizing. Kupiec widget always shows
   "0 of 4 maximum exceptions" — a fraction, never just "OK."
3. **Alert fatigue** — CRITICAL is reserved (kill-switch, drawdown crossings, WS
   reconnect failure, order rejection); everything else is WARNING/INFO; rail
   capped at 3.
4. **Dry-run vs live confusion** — viewport border + `[LIVE]`/`[PAPER]` badge on
   every audit-log order.
5. **Tiny-capital absolute-number trap** — `$2.50 VaR` reads trivial; `2.5% of
   bankroll` does not. Dual display everywhere.
6. **Brier/Kupiec noise at small n** — every calibration metric shows sample size
   and an explicit "unreliable at n<30" warning; sparse reliability bins use open
   circles and the word "sparse."
7. **Dormant vs paper vs live confusion** — three visually non-interchangeable
   states (icon + color + card tint); paper P&L must never look like real P&L.
8. **Confirmation anchoring on small balances** — signal cards always show Kelly
   fraction *and* absolute size side by side (`Kelly: 0.06 | Size: $5.64`).
