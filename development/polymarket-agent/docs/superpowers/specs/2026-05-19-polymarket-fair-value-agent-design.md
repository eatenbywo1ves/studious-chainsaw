# Polymarket Fair-Value Trading Agent — Design Spec

**Date:** 2026-05-19
**Status:** Design — awaiting user review before implementation planning.
**Companion:** `2026-05-19-polymarket-dashboard-design.md` (Layer 9 UI/UX).

---

## 1. Goal

Build an autonomous trading agent for Polymarket (https://polymarket.com) that
makes money by producing better-calibrated probability estimates than the
market price, for any specified market. The agent researches a market, estimates
a fair probability, sizes a position, and executes trades autonomously, governed
by hard risk limits.

The live account starts with **$100**. This is a proof-of-concept/learning
budget: the measure of success at this size is not absolute profit but a
**validated, well-calibrated model and correct execution plumbing** — the
prerequisites for later scaling capital into an already-proven system.

---

## 2. Context & Constraints

### 2.1 Regulatory / operational

Polymarket is a real-money prediction market with eligibility and jurisdiction
requirements (it operates in the US via its CFTC-regulated QCEX exchange with
KYC, as of late 2025). The agent assumes operation from an eligible, KYC'd
account. Compliance is the operator's responsibility; the design simply does not
attempt to evade any geographic or identity control.

### 2.2 The $100 capital reality

The $100 starting capital is a hard design constraint, not a detail:

- **Only the fair-value strategy is viable at this size.** The three other edge
  theses are mathematically dominated by costs at $100:
  - *Market-making* — spread capture on $100 of inventory earns cents per
    round-trip; one adverse fill erases weeks of it. Net-negative.
  - *News-reaction* — requires meaningful size placed fast; a ~$5 order competing
    with funded fast-traders earns a rounding error.
  - *Cross-market arbitrage* — typical arb spreads are 1–3%; on $100 that is
    $1–3 per opportunity before costs, and thin books cap the fill.
- **`orderMinSize` is the binding constraint.** Polymarket markets carry a
  per-market minimum order size and minimum tick. A fractional-Kelly position on
  a $100 bankroll can be smaller than the minimum legal order. When that happens
  the correct action is **PASS** — `PASS` is a first-class output of the sizing
  layer, not an error.
- **Honest expectation:** a genuine edge on $100 produces single-digit-dollar
  gains. The project "maximizes profit" by *validating the model cheaply* so
  capital can later be scaled into something already proven.

### 2.3 Scope decision: all four strategies, one spec

Per the locked decisions, this single spec describes all four edge theses as a
**modular architecture** — four pluggable strategy modules over shared
infrastructure. Only the fair-value module runs live at launch. The other three
are built and run in **paper mode**, and **auto-activate when the bankroll
crosses a per-strategy gate** (see §8). The implementation plan stages them; they
are not built in parallel.

### 2.4 The supplied options-trading document

`C:\Users\Corbin\Documents\Options trading documents\compass_artifact_*.md`
(two byte-identical copies) is **"Options Trading Validation Methodologies."** It
contains no trading alpha. It is a model-validation discipline — SR 11-7
governance, Basel III green/orange/red exception zones, Kupiec coverage tests,
Anderson-Darling tail tests, walk-forward validation, and anti-overfitting rules
(the "Rule of 5" parameter cap; Bonferroni correction — *100 tests at 5%
significance → 99.4% false-positive probability*).

Polymarket markets are not options (no Black-Scholes, no Greeks), but a
fair-value model *is* a probability forecast and forecast validation transfers
exactly. This document therefore becomes the **specification for Layer 7**, the
validation gate every strategy must pass before trading real money (see §7).

### 2.5 The supplied tool

`C:\Users\Corbin\Downloads\financial_stochastic_sim.tsx` is a React/TypeScript
educational component (stochastic price sims, portfolio optimization, Monte
Carlo, VaR/CVaR, Kupiec backtesting). Its contributions:

- The **Monte Carlo + VaR/CVaR + Kupiec-test logic** is a reference
  implementation to **port to Python** in the L5 risk layer and L7 validation.
- The **component itself** is the skeleton for the L9 dashboard.

The raw stochastic price models (GBM/Heston/jump-diffusion) do not apply to
binary markets generally — *except* for crypto price-target markets, where a
"BTC > $X by date" market is a barrier-hit probability computable from spot +
implied volatility. There those models are genuinely reused (see §6.3).

---

## 3. Locked Decisions

| Dimension | Decision |
|---|---|
| Automation | Fully autonomous execution, governed by hard risk limits |
| Edge theses | All 4 specced; **fair-value live**, news/arb/market-making built but dormant + bankroll-gated |
| Market scope | Category router → per-category research modules (politics, sports, crypto, econ, culture, tech) |
| Capital | $100, dedicated wallet; fractional-Kelly sizing with `PASS`-on-no-legal-fit |
| Stack | Python core + React/TypeScript dashboard |
| Orchestration | Monolithic async loop, queue-ready strategy interfaces |
| Validation | Options-doc methodology → Kupiec / walk-forward / calibration gates; nothing trades live unvalidated |
| `.tsx` tool | MC/VaR/Kupiec logic ported to Python; component → dashboard skeleton |

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  L9  OBSERVABILITY & CONTROL                                      │
│      React dashboard · kill switch · Telegram alerts · audit log  │
├─────────────────────────────────────────────────────────────────┤
│  L8  ORCHESTRATION  — monolithic async loop / scheduler           │
├──────────────┬──────────────┬──────────────┬─────────────────────┤
│ L3 RESEARCH  │ L4 STRATEGY  │ L5 RISK &    │  L6 EXECUTION        │
│ Fair-Value   │ MODULES (×4) │  SIZING      │  CLOB order mgmt     │
│ Engine       │ ▸fair-value  │ Kelly-frac   │  place/cancel/       │
│ per-category │  ●LIVE       │ hard limits  │  reconcile           │
│ modules      │ ▸news ○dorm  │ MC VaR/CVaR  │  tick/min-size aware │
│              │ ▸arb  ○dorm  │ kill switch  │                      │
│              │ ▸mkt-mk ○dorm│ ◀──────── L7 VALIDATION & BACKTEST   │
│              │  bankroll-   │   walk-forward · paper-trade engine  │
│              │  gated       │   Kupiec green/orange/red gates      │
├──────────────┴──────────────┴──────────────┴─────────────────────┤
│  L2  MARKET UNIVERSE & CATEGORY ROUTER                            │
│      liquidity/volume filter → classify → dispatch                │
├─────────────────────────────────────────────────────────────────┤
│  L1  DATA INGESTION                                               │
│      Polymarket Gamma/CLOB/Data APIs + WebSocket ·                │
│      external: polls · sportsbook odds · crypto feeds · news ·    │
│      local store (Postgres)                                       │
└─────────────────────────────────────────────────────────────────┘
```

The agent is a single Python `asyncio` process (L8) driving layers L1–L7, plus a
separate FastAPI process serving the L9 dashboard. The two processes share state
through the Postgres store and a WebSocket feed.

---

## 5. Layers L1–L2: Data & Routing

### L1 — Data Ingestion

- **Polymarket APIs** (base `https://clob.polymarket.com`, plus Gamma and Data
  APIs): market discovery/metadata, order book (`/book`), prices (`/price`,
  `/midpoint`), historical series (`/prices-history`, `/batch-prices-history` —
  intervals 1m/1h/6h/1d/1w/max), positions and trades via the Data API. Client:
  official `py-clob-client`. WebSocket feed for live book/price updates.
- **External per-category sources:** poll aggregators (politics/econ),
  consensus sportsbook odds APIs (sports), crypto spot + implied-vol feeds
  (crypto), news APIs (all categories). Each source sits behind an adapter
  interface so it can be swapped or mocked.
- **Local store:** Postgres — historical price snapshots, market metadata,
  research artifacts, signals, orders, fills, resolutions, audit log. This store
  is the single source of truth shared with the dashboard process.
- **Rate-limit-aware client:** Polymarket limits are generous (e.g. `POST /order`
  3,500/10 s burst); the client tracks budgets per endpoint group and backs off
  rather than relying on remote rejection.

### L2 — Market Universe & Category Router

- Periodically scans Polymarket for active markets and applies a **liquidity
  filter** (the options-doc "minimum volume thresholds" idea, translated): require
  `enableOrderBook = true`, minimum 24 h volume, minimum liquidity, and a
  bid-ask spread below a configured fraction of mid. Illiquid markets are
  excluded — the agent cannot get filled or exit them.
- **Classifies** each surviving market into a category (politics, sports, crypto,
  econ, culture/awards, tech/other) using market metadata + an LLM classifier
  fallback, and **dispatches** it to the matching L3 research module.
- Markets with no confident category, or in a category whose module returns
  low confidence, resolve to `PASS`.

---

## 6. Layer L3: Research / Fair-Value Engine

The core of the edge. Each per-category module consumes a market + its data and
emits a `FairValueEstimate`:

```
FairValueEstimate {
  market_id, category,
  p_hat: float            # estimated probability of YES
  confidence: enum LOW | MEDIUM | HIGH
  ci: (low, high)         # estimate interval
  rationale: str          # human-readable, shown on dashboard
  sources: list[Source]   # URLs / feeds / models used
  method: str             # which estimator produced it
  ts: datetime
}
```

### 6.1 Politics / econ

Poll aggregation, base rates, structured LLM research (via a research agent +
web search), historical analogues. Macro markets cross-checked against any
available external prediction-market line.

### 6.2 Sports

De-vig consensus sportsbook odds → implied probability (the cleanest external
benchmark available for this category); optionally a team-stats model. If the
de-vigged consensus and Polymarket agree, there is no edge → `PASS`.

### 6.3 Crypto

Price-target markets ("BTC > $X by date") are **barrier-hit probabilities**. This
is where the `.tsx` stochastic models genuinely apply: estimate the probability
from current spot, drift, and implied volatility via a bounded diffusion. A
binary market's price is a martingale on [0, 1] that must converge to 0 or 1 at
resolution, so a **Brownian-bridge-to-resolution** adaptation of the diffusion
code is the right model.

### 6.4 Culture / awards / tech

Structured LLM research plus base rates; lower baseline confidence — these
categories have the weakest external data and the module is expected to `PASS`
often.

### 6.5 Ensemble & calibration

When multiple estimators apply to one market, an aggregator combines them
(confidence-weighted). Every resolved market feeds the L7 calibration tracker
(Brier score, reliability curve) — calibration quality, not P&L, is the primary
health metric for this layer.

---

## 7. Layer L7: Validation & Backtest (the options-doc, operationalized)

No strategy — including fair-value — trades real money until it passes this gate.
This layer is the single most important defense of the $100.

- **Walk-forward backtest:** expanding-window backtests on `/prices-history` data,
  respecting temporal order (no look-ahead). Anti-overfitting rules from the
  options doc are enforced: the **"Rule of 5"** caps optimizable parameters;
  **Bonferroni / false-discovery correction** is applied whenever multiple
  strategy variants are compared.
- **Paper-trade engine:** runs every strategy against live prices placing no real
  orders, recording hypothetical fills (with a slippage model) and P&L. Dormant
  strategies live here permanently until their bankroll gate opens.
- **Kupiec exception zones:** the green (0–4) / orange (5–9) / red (10+)
  classification over a rolling window of resolved markets, with the Kupiec
  likelihood-ratio coverage test. Red zone forces a strategy back to paper mode.
- **Calibration gate:** a strategy is promotable from paper → live only when its
  Brier score beats a target over a minimum sample size **and** its Kupiec zone
  is green. Calibration metrics are reported with sample size; below n = 30 they
  are flagged unreliable.
- **Audit trail:** every decision, estimate, order, fill, resolution, and state
  transition is logged immutably (the options-doc governance requirement).

---

## 8. Layers L4–L6: Strategy, Risk, Execution

### L4 — Strategy modules

Four modules implement a common `Strategy` interface and emit a uniform
`TradeSignal` (market, side, target price, edge, confidence, source strategy).
The interface is **queue-ready** — a module can later be moved to an
event-driven worker without changing its contract.

- **Fair-value (LIVE):** compare `p_hat` against the market's implied probability;
  if `edge ≥ min_edge` and confidence is sufficient, emit a signal.
- **News-reaction (dormant):** event detection on news/social feeds → repricing
  signal. Bankroll gate: $150.
- **Cross-market arbitrage (dormant):** consistency scan across related markets
  and external books. Bankroll gate: $200.
- **Market-making (dormant):** two-sided quote generation. Bankroll gate: $300.

A dormant strategy activates only when **both** conditions hold: bankroll ≥ its
gate **and** it has passed its L7 validation gate. Until then it runs in paper
mode and its track record accumulates on the dashboard.

### L5 — Risk & Position Sizing

- **Sizing:** fractional Kelly (default ¼-Kelly) from edge, confidence, and
  bankroll. If the Kelly size is below the market's `orderMinSize`, output
  `PASS`. Tick size (`orderPriceMinTickSize`) is respected when forming the
  limit price.
- **Hard limits:** per-market cap (% of bankroll), per-category cap, total
  exposure cap, daily loss cap, per-strategy drawdown limit, global drawdown
  kill switch (multi-level: warn / halt / catastrophic).
- **Portfolio risk:** Monte Carlo simulation + VaR/CVaR across open correlated
  positions (logic ported from the `.tsx` tool). Pre-trade risk check gates
  every order; an order that would breach any limit is rejected and logged.

### L6 — Execution

- Translates an approved, sized signal into a CLOB order (GTC / FOK / GTD as
  appropriate), respecting tick and min-size.
- Order lifecycle management: place, monitor, cancel, re-quote; slippage/fill
  modeling; reconciliation against the Data API position state.
- **Idempotency:** every intended order carries a client-side key; on
  crash-restart the agent reconciles before acting so it never double-trades.

---

## 9. Layer L8: Orchestration

A single Python `asyncio` process runs the loop: scan universe (L2) → research
due markets (L3) → strategies emit signals (L4) → risk-check and size (L5) →
execute (L6) → record and reconcile → feed validation (L7). The fair-value loop
cadence is minutes-to-hours; there is no latency requirement at v1.

Strategy modules communicate through a clean in-process interface that mirrors a
message queue, so the news-reaction module can later be promoted to an
event-driven worker (Redis or similar) without rewriting the others.

---

## 10. Layer L9: Dashboard

Summarized here; full plan in the companion document
`2026-05-19-polymarket-dashboard-design.md`.

A dark-mode, single-operator React/TypeScript monitoring & control dashboard,
evolved from `financial_stochastic_sim.tsx`. Five views — Overview, Positions,
Signals, Validation, Audit Log. Real-time state over a FastAPI WebSocket
(`{seq, ts, type, payload}` envelope; sequence numbers detect dropped messages);
polled REST for snapshots. Key design commitments:

- A persistent **kill switch** (press-and-hold 1.5 s) on its own REST endpoint,
  never a WebSocket message — it must work during a disconnect.
- A **stale-data cascade** — frozen prices misread as a quiet market is the
  highest-severity UX risk; staleness desaturates widgets and escalates banners.
- A **viewport border** (red live / blue paper) so the operator can never
  mistake the trading mode.
- Every monetary value shown as **absolute $ and % of bankroll together** — at
  $100, `$40` looks trivial while `40% of bankroll` is catastrophic.

The dashboard ships in three phases tracking the agent's own rollout (§11).

---

## 11. Rollout Phases

The spec describes all four strategies; implementation is staged with a
paper-trade gate between phases.

| Phase | Deliverable | Gate to next phase |
|---|---|---|
| 0 | L1 data ingestion + L7 backtest harness + Postgres store | Backtest harness reproduces known historical prices |
| 1 | L3 fair-value research (category router + per-category modules) + L7 validation gate | Fair-value passes walk-forward + green Kupiec on backtest |
| 2 | L5 risk + L6 execution + L8 loop + L9 v1 dashboard → **go live with $100** | Paper-trade calibration target met; then live with hard limits |
| 3 | News / arbitrage / market-making modules running in paper mode | Each passes its L7 gate |
| 4 | Bankroll-gated activation of dormant strategies + L9 v2/v3 dashboard | — |

---

## 12. Tech Stack & Repository Layout

- **Core:** Python 3.12, `asyncio`, `py-clob-client`, `pydantic` (typed data
  models), `httpx`, `SQLAlchemy` + Postgres, `pytest`.
- **Dashboard backend:** FastAPI (WebSocket + REST).
- **Dashboard frontend:** React 18 + TypeScript strict, Vite, Tailwind,
  `lightweight-charts`, `Recharts`, `Zustand`, `TanStack Query`.

```
polymarket-agent/
  agent/            # Python core
    data/           # L1 ingestion + adapters
    universe/       # L2 scan + category router
    research/       # L3 per-category fair-value modules
    strategy/       # L4 strategy modules (fair-value live; 3 dormant)
    risk/           # L5 sizing + limits + MC/VaR (ported from .tsx)
    execution/      # L6 CLOB order management
    validation/     # L7 walk-forward + paper-trade + Kupiec gates
    orchestrator/   # L8 async loop
    store/          # Postgres models + migrations
  dashboard/
    backend/        # FastAPI WS + REST
    frontend/       # React app (evolved from financial_stochastic_sim.tsx)
  tests/
  docs/superpowers/specs/
```

---

## 13. Error Handling

- **API failures:** retry with exponential backoff; on sustained failure the affected layer
  degrades to `PASS` rather than acting on stale data. A dead WebSocket never
  produces trades — execution requires fresh book data.
- **Crash recovery:** on restart the agent reconciles open orders and positions
  against the Polymarket Data API before resuming (idempotency keys, §L6).
- **Risk-limit breach:** the order is rejected and logged; repeated breaches in a
  window escalate to the drawdown kill switch.
- **Bad/half-resolved markets:** UMA-disputed or ambiguously resolving markets
  are excluded by L2 and flagged.

---

## 14. Security

- **Dedicated wallet** funded with only the $100 — blast-radius containment; the
  agent never has access to more capital than it is authorized to risk.
- Wallet private key and API credentials in environment variables / a secret
  manager — never committed (per workspace security rules).
- Dry-run mode is the default; live trading requires an explicit, audited flag.
- All external inputs (API payloads, news text) validated against typed schemas
  before use.

---

## 15. Out of Scope (YAGNI)

- Options/Greeks modeling — Polymarket has no options layer.
- Multi-asset mean-variance portfolio optimization — there is one bankroll over
  binary bets, not a weighted asset portfolio.
- Multi-operator features, role-based access — single operator.
- Latency/co-location infrastructure — the live fair-value loop is low-frequency;
  revisit only if the news-reaction module is ever taken live at scale.
- Light-mode dashboard theme.

---

## 16. Open Risks

- **The edge is unproven.** The entire design assumes the fair-value model *can*
  beat Polymarket prices. L7 exists precisely to test that assumption cheaply
  before risking capital; if validation fails, the honest outcome is not to
  trade. This is a feature of the plan, not a flaw.
- **"Any market" is ambitious.** A research pipeline strong across all six
  categories is hard; expect culture/tech to `PASS` frequently at v1.
- **Small-n statistics.** At $100 with few resolved markets, Kupiec and Brier
  metrics are noisy for weeks. The dashboard flags this; the operator must not
  over-read early results.
- **Liquidity at scale.** If capital later grows, thin Polymarket order books
  will require slippage modeling and order-splitting not built at v1.
