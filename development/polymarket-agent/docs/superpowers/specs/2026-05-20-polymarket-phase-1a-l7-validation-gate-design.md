# Polymarket Agent — Phase 1A: L7 Validation Gate Infrastructure — Design Spec

**Date:** 2026-05-20
**Phase:** 1A (first sub-phase of Phase 1)
**Parent spec:** `2026-05-19-polymarket-fair-value-agent-design.md`
**Builds on:** Phase 0 (committed in PR #4, `feat/polymarket-phase-0`)

---

## 1. Goal & Scope

### 1.1 Goal

Build the L7 validation gate infrastructure so future fair-value research modules
(L3) can be evaluated against the design spec's "walk-forward + green Kupiec on
backtest" criterion. Phase 1A delivers the validation machinery itself; real
per-category L3 modules ship in Phase 1B+.

### 1.2 Decomposition rationale

Phase 1 in the parent spec covers L3 (four per-category research modules + ensemble)
PLUS L7 (validation gate). That is six+ subsystems — too large for one
implementation plan. The sub-phases:

- **Phase 1A (this spec):** L7 infrastructure + baseline models + stub L4 strategy.
- **Phase 1B:** First real L3 module (TBD: probably sports, since de-vigged consensus
  odds give the cleanest external benchmark).
- **Phase 1C:** Remaining L3 modules (politics, crypto, culture) + ensemble.

L7-first means every Phase 1B+ L3 module can be evaluated immediately against the
same gate. The baseline models in Phase 1A serve as L7's own acceptance test:
`last_traded_price` is a martingale and should produce green Kupiec by construction;
`constant_half` is miscalibrated for most markets and should produce a recognizably
worse result.

### 1.3 In scope (Phase 1A)

- L7 backtest core — walk-forward replay over Phase 0's stored history with Kupiec
  exception zones and Brier score.
- L7 paper-trade-live engine — same machinery running forward in time against live
  Polymarket prices.
- A market-resolution poller that detects when markets resolve via the Polymarket
  Gamma API.
- A stub L4 threshold-edge strategy (one rule:
  `if |p_hat - market_price| ≥ edge_threshold, emit a paper trade`).
- Baseline "models" implementing a new minimal `Prediction` contract:
  `last_traded_price` (martingale baseline) and `constant_half` (calibration straw
  man).
- A small CLI / module-level entrypoint to run a backtest or start paper-trade-live.

### 1.4 Out of scope (deferred)

- Real L3 per-category research modules — Phase 1B+.
- L7's audit trail (immutable decision/order log) — deferred until pre-go-live.
- L7's calibration gate / promotion-from-paper-to-live policy logic — deferred.
- Bonferroni / multi-strategy comparison correction — only meaningful when there
  are multiple strategies; deferred.
- Rule-of-5 parameter cap — only meaningful when models have optimizable
  parameters; baselines have none.
- L9 dashboard rendering of L7 metrics — Phase 2.

### 1.5 Completion gate

Phase 1A is complete when L7's math functions produce mathematically-correct outputs
against synthetic test cases with hand-computed reference values. The full
acceptance criteria are §5 below. The gate is **algorithmic** — no live-API
discrimination requirement, no operational-uptime requirement.

---

## 2. Architecture & Data Flow

### 2.1 Repository layout (extends Phase 0)

```
agent/
  validation/                    # L7 validation gate (extended from Phase 0)
    metrics.py                   # NEW: kupiec_test, brier_score, reliability_curve
    backtest.py                  # EXISTING: extend ReplayEngine with walk_forward_backtest
    paper_trade.py               # NEW: PaperTradeEngine (only stateful class)
    resolution_poller.py         # NEW: detect market resolution via Polymarket API
    types.py                     # NEW: Prediction, BacktestResult, KupiecResult, TradeSignal, etc.
  research/                      # NEW: where L3 modules will live (Phase 1B+)
    __init__.py
    baselines.py                 # NEW: last_traded_price, constant_half
  strategy/                      # NEW: where L4 modules will live (Phase 2)
    __init__.py
    threshold.py                 # NEW: stub L4 threshold-edge strategy
tests/
  validation/
    test_metrics.py              # NEW: hand-computed Kupiec + Brier reference values (THE GATE)
    test_backtest.py             # EXISTING: extend with walk_forward_backtest tests
    test_paper_trade.py          # NEW: PaperTradeEngine unit + respx-mocked integration
    test_resolution_poller.py    # NEW: respx-mocked resolution detection
  research/
    __init__.py
    test_baselines.py            # NEW: baseline-model correctness
  strategy/
    __init__.py
    test_threshold.py            # NEW: stub L4 threshold-rule correctness
```

`agent/validation/types.py` is new because Phase 0's `backtest.py` only had one
type (`ReplayEvent`). Phase 1A adds several — collecting them in one file keeps
cross-imports clean.

### 2.2 Backtest data flow (offline, against Phase 0 history)

```
PriceSnapshot rows (Phase 0 SQLite)
        │
        ▼
ReplayEngine.replay()      ──► (market_id, ts, price) events
        │
        ▼
baseline_model(event)      ──► Prediction(market_id, ts, p_hat)
        │
        ▼
walk_forward_backtest()    ──► pairs each Prediction with the eventual
                               market resolution (provided by caller)
        │
        ▼
metrics.{kupiec_test, brier_score, reliability_curve}() ──► BacktestResult
```

### 2.3 Paper-trade-live data flow (online, against current Polymarket)

```
ResolutionPoller (periodic httpx GET → Polymarket Gamma API)
        │
        ▼
Live (market_id, ts, market_price) events
        │
        ▼
baseline_model(event)              ──► Prediction
        │
        ▼
threshold_strategy(pred, price)    ──► Optional[TradeSignal]
        │
        ▼
PaperTradeEngine.record_signal()
   - stores hypothetical fills (slippage = 0 in Phase 1A)
   - on market resolution: computes paper P&L
        │
        ▼
metrics.{kupiec_test, brier_score}() ──► live PaperTradeResult
```

### 2.4 Key architectural properties

1. **Backtest and paper-trade-live share the metrics layer.** The same
   `kupiec_test()` and `brier_score()` functions are called from both paths.
   Tested once → trusted everywhere.
2. **No new database tables in Phase 1A.** Predictions and paper-trade fills live
   in memory during a run, written to a CSV/JSON report at the end. Persisting
   them needs schema design — defer to Phase 1B when there is a real model worth
   persisting predictions from.
3. **The resolution poller is the only new long-running component.** Backtest is
   one-shot. Paper-trade-live runs a polling loop.
4. **No coupling between `research/` and `strategy/`.** The baseline functions
   live in `research/`; the threshold strategy lives in `strategy/`. They
   communicate only through `Prediction` and `TradeSignal` dataclasses.
5. **Slippage is fixed at zero** in Phase 1A. `PaperTradeEngine` accepts a
   `slippage_model` parameter but defaults to zero — adding a realistic
   spread/impact model is a Phase 1B+ concern.

---

## 3. Data Model

All types are `@dataclass(frozen=True)` for immutability and hashability
(consistent with Phase 0's `ReplayEvent`).

### 3.1 Inputs (what flows IN to the validation layer)

```python
@dataclass(frozen=True)
class Prediction:
    """A model's estimate of P(market resolves YES) at a given time.

    Minimal subset of the spec's future FairValueEstimate.  L3 modules in
    Phase 1B+ may subclass to add confidence/CI/rationale/sources without
    breaking L7.
    """
    market_id: str
    ts: int                            # unix seconds
    p_hat: float                       # estimated P(YES) in [0, 1]


@dataclass(frozen=True)
class ResolvedOutcome:
    """The ground truth for a resolved market.  Phase 1A handles binary
    outcomes only."""
    market_id: str
    outcome: Literal[0, 1]             # 1 = YES, 0 = NO
    resolved_ts: int


@dataclass(frozen=True)
class PriceTick:
    """A live price observation for a market's YES token.  Emitted by
    ResolutionPoller between resolution checks."""
    market_id: str
    ts: int                            # unix seconds
    market_price: float                # YES token price in [0, 1]
```

### 3.2 Trading-layer types (consumed by paper-trade-live)

```python
@dataclass(frozen=True)
class TradeSignal:
    """A trading-rule decision to take a hypothetical paper position."""
    market_id: str
    ts: int
    side: Literal["YES", "NO"]
    target_price: float                # the limit we would trade at
    edge: float                        # |p_hat - market_price|
    rationale: str                     # human-readable, e.g. "p_hat=0.62 mkt=0.55"


@dataclass(frozen=True)
class PaperFill:
    """A hypothetical fill recorded by PaperTradeEngine."""
    market_id: str
    ts: int
    side: Literal["YES", "NO"]
    price: float                       # signal.target_price + slippage (0 in Phase 1A)
    size: float                        # position size in SHARES (max payoff = size * $1)
```

### 3.3 Outputs (what flows OUT of the validation layer)

```python
@dataclass(frozen=True)
class KupiecResult:
    """Output of the Kupiec unconditional-coverage test."""
    exceptions: int
    trials: int
    expected_rate: float               # model's claimed exception rate
    lr_statistic: float                # ~ chi^2 with 1 d.f.
    p_value: float
    zone: Literal["GREEN", "ORANGE", "RED"]


@dataclass(frozen=True)
class BacktestResult:
    """Output of walk_forward_backtest()."""
    model_name: str
    n_predictions: int
    n_resolved: int
    brier_score: float                 # mean (p_hat - outcome)^2
    reliability_curve: list[tuple[float, float] | tuple[None, None]]
                                       # (mean_predicted_p, observed_yes_freq) per decile bin
    kupiec: KupiecResult | None        # None if n_resolved < kupiec_window
    window_start_ts: int
    window_end_ts: int


@dataclass(frozen=True)
class PaperTradeResult:
    """Summary of a paper-trade-live session."""
    model_name: str
    started_ts: int
    ended_ts: int
    n_fills: int
    n_resolved: int
    paper_pnl: float                   # net hypothetical dollars won/lost
    backtest_metrics: BacktestResult   # same metrics, computed on this session's predictions
```

### 3.4 Contract decisions

1. **Kupiec's "exception" definition is the caller's responsibility, not
   `kupiec_test`'s.** The function takes `(exceptions: int, trials: int,
   expected_rate: float)` and computes the LR test. `walk_forward_backtest`
   decides what counts as an exception. Phase 1A's default: an "exception" is a
   prediction where the realized outcome disagrees with
   `argmax(p_hat, 1-p_hat)` — i.e., the model picked the wrong side. The zone
   thresholds (0–4 GREEN / 5–9 ORANGE / 10+ RED) are evaluated over a
   configurable rolling window (default 100 resolved markets).

2. **Reliability curve uses 10 fixed bins** (`[0,0.1), [0.1,0.2), …, [0.9,1.0]`).
   Each bin reports the count-weighted mean predicted probability and the
   observed YES-frequency. Bins with fewer than 5 observations report
   `(None, None)`.

---

## 4. Components

### 4.1 `agent/validation/metrics.py` — pure math

Three stateless functions, the heart of the algorithmic gate.

```python
def kupiec_test(
    exceptions: int, trials: int, expected_rate: float,
    *, green_max: int = 4, orange_max: int = 9,
) -> KupiecResult:
```

Computes Kupiec's unconditional-coverage LR test:
`LR = -2 * [x*ln(p) + (n-x)*ln(1-p) - x*ln(x/n) - (n-x)*ln((n-x)/n)]`
where `x = exceptions`, `n = trials`, `p = expected_rate`. Under H0 (observed
rate = expected rate), `LR ~ chi^2(1)`; `p_value = scipy.stats.chi2.sf(LR, 1)`.
Zone is determined by raw exception count vs the green/orange thresholds. Handles
edge cases: `exceptions=0` and `exceptions=trials` use the log-likelihood limit,
avoiding `log(0)`.

```python
def brier_score(pairs: Iterable[tuple[float, int]]) -> float:
```

Mean squared error: `sum((p_hat - outcome)^2) / n`. Outcomes are 0 or 1. Raises
`ValueError` on empty input.

```python
def reliability_curve(
    pairs: Iterable[tuple[float, int]],
    *, n_bins: int = 10, min_per_bin: int = 5,
) -> list[tuple[float, float] | tuple[None, None]]:
```

Bins predictions into `n_bins` evenly-spaced intervals over `[0, 1]`. Per bin:
`(mean_predicted_p, observed_yes_frequency)`. Bins with fewer than `min_per_bin`
observations report `(None, None)` so callers can skip plotting.

### 4.2 `agent/validation/backtest.py` — walk-forward orchestration

Extends Phase 0's `ReplayEngine` (which yields events in ts order) with the
walk-forward loop.

```python
def walk_forward_backtest(
    session: Session,
    model: Callable[[ReplayEvent], Prediction],
    resolutions: dict[str, ResolvedOutcome],
    *,
    market_ids: list[str] | None = None,
    kupiec_window: int = 100,
    model_name: str = "unnamed",
) -> BacktestResult:
```

Per market in `market_ids` (or all stored markets if `None`): iterates
`ReplayEngine(session).replay(...)` events in time order, calls `model(event)` to
get a `Prediction`, accumulates predictions paired with the market's resolution
(looked up in `resolutions`). After all markets: computes `brier_score`,
`reliability_curve`, and `kupiec_test` over the last `kupiec_window`
resolved-market predictions. Returns `BacktestResult` with `kupiec=None` if
`n_resolved < kupiec_window`.

**The walk-forward property is enforced by ReplayEngine yielding in strict ts
order and `model` being a function of one event (no peek-ahead).** Stateful
models in future phases can hold internal state across calls — the only contract
is "do not query the future."

### 4.3 `agent/validation/paper_trade.py` — the only stateful component

```python
class PaperTradeEngine:
    def __init__(
        self,
        model_name: str,
        position_size_shares: float = 1.0,
        slippage_model: Callable[..., float] = lambda **_: 0.0,
    ):
        self._fills: list[PaperFill] = []
        self._predictions: list[Prediction] = []
        self._open_positions: dict[str, PaperFill] = {}

    def record_prediction(self, prediction: Prediction) -> None: ...

    def record_signal(self, signal: TradeSignal) -> PaperFill: ...

    def on_resolved(self, outcome: ResolvedOutcome) -> float:
        """Closes any open position for outcome.market_id; returns realized P&L."""

    def result(self) -> PaperTradeResult:
        """Compute backtest_metrics over self._predictions, sum P&L over self._fills."""
```

Position size defaults to **1 share per trade** in Phase 1A. On Polymarket, 1
share costs the token's entry price (≤ $1) and pays $1 if that token resolves
to the winning side, so max loss per trade is bounded above by $1 — comfortable
against $100 of intended live capital. Slippage callable defaults to zero; a
real spread/impact model is Phase 1B.

### 4.4 `agent/validation/resolution_poller.py`

```python
class ResolutionPoller:
    def __init__(self, client: PolymarketClient, poll_interval_seconds: float = 60.0):
        ...

    async def stream_events(
        self, market_ids: list[str],
    ) -> AsyncIterator[PriceTick | ResolvedOutcome]:
        """Yields PriceTick(market_id, ts, market_price) updates AND
        ResolvedOutcome(market_id, outcome, ts) when a market resolves.
        Stops when all market_ids have resolved."""
```

Polls Polymarket's Gamma API for each market's `closed` flag + outcome at
`poll_interval_seconds`. Between polls, yields `PriceTick` events derived from
the current market YES-token price. When a market flips from `closed=False` to
`closed=True` AND has a resolved outcome (`outcomePrices = ["1","0"]` or
`["0","1"]`), yields one `ResolvedOutcome` then stops following that market.

Phase 1A defers handling of: market unresolution-flip-flop (rare API edge case),
invalid markets, and partial-resolution states.

### 4.5 `agent/research/baselines.py` — Phase 1A's stand-in for L3

```python
def last_traded_price(event: ReplayEvent) -> Prediction:
    """Predicts p_hat = current market price.  Martingale baseline — should
    produce GREEN Kupiec on real Polymarket data by construction."""
    return Prediction(market_id=event.market_id, ts=event.ts, p_hat=event.price)


def constant_half(event: ReplayEvent) -> Prediction:
    """Predicts p_hat = 0.5 for every market, every time.  Calibration
    straw man — for any market NOT genuinely 50/50, this is miscalibrated."""
    return Prediction(market_id=event.market_id, ts=event.ts, p_hat=0.5)
```

Two functions. Their algorithmic correctness is obvious-by-inspection; the gate
test is whether L7's math, given these predictions on synthetic outcomes,
produces the expected metrics.

### 4.6 `agent/strategy/threshold.py` — stub L4

```python
def threshold_strategy(
    prediction: Prediction,
    market_yes_price: float,
    *,
    edge_threshold: float = 0.05,
) -> TradeSignal | None:
    """Buy YES if p_hat - market_yes_price >= threshold;
       Buy NO if market_yes_price - p_hat >= threshold;
       Else None (no signal)."""
```

One function. The 5% default edge threshold is generous enough that
random-noise Polymarket-vs-baseline disagreement will not generate trades on
every poll.

---

## 5. Acceptance Criteria — the Algorithmic Gate

Phase 1A is complete when every test below passes.

### 5.1 Kupiec test reference cases

| Inputs | Expected output |
|---|---|
| `exceptions=0, trials=100, expected_rate=0.05` | `LR ≈ 10.2587`, `p_value ≈ 0.00136`, `zone=GREEN` |
| `exceptions=7, trials=100, expected_rate=0.05`  | `LR ≈ 0.7530`,  `p_value ≈ 0.3855`,  `zone=ORANGE` |
| `exceptions=15, trials=100, expected_rate=0.05` | `LR ≈ 14.0500`, `p_value ≈ 0.000178`, `zone=RED` |

All three values verified by hand-computation against the closed-form
`LR_uc = -2*[x*ln(p) + (n-x)*ln(1-p) - x*ln(x/n) - (n-x)*ln((n-x)/n)]` (with
`0*ln(0) = 0` convention for the x=0 and x=n edge cases) and the chi²(1)
survival function `chi2.sf(LR, 1) = erfc(sqrt(LR/2))`. Implementation tests
should match these reference values to within absolute tolerance `1e-4` for LR
and relative tolerance `1e-3` for `p_value`.

### 5.2 Brier score reference cases

| Predictions | Outcomes | Expected Brier |
|---|---|---|
| `[0.0]` | `[1]` | `1.0` |
| `[0.5, 0.5, 0.5]` | `[0, 0, 1]` | `0.25` |
| `[0.1, 0.9, 0.6]` | `[0, 1, 1]` | `(0.01 + 0.01 + 0.16) / 3 ≈ 0.06` |
| `[]` | `[]` | raises `ValueError` |

### 5.3 Reliability curve reference case

Given 100 predictions evenly spread across `[0,1]` (10 per decile bin) with
synthetic outcomes engineered so the model is exactly calibrated (predicted bin
midpoint == observed YES-frequency), the curve must return 10 bins with
`mean_predicted_p == bin_midpoint` (within float tolerance) and
`observed_yes_frequency == bin_midpoint`. (The 10/bin count is comfortably above
the `min_per_bin=5` default, so all bins are non-`None`.) A second reference
case with only 25 predictions evenly spread (2-3 per bin) asserts every bin
reports `(None, None)` under default `min_per_bin=5`.

### 5.4 walk_forward_backtest integration

In-memory SQLite (StaticPool, same fixture as Phase 0):
- 3 synthetic markets with 5 price ticks each ingested via Phase 0's repository.
- Resolutions provided directly: market 1 = YES, market 2 = NO, market 3 = YES.
- Run with `last_traded_price` baseline → expect `n_predictions=15`,
  `n_resolved=15`, deterministic Brier matching a hand-computed value.
- Run with `constant_half` → expect `brier_score=0.25` exactly.

### 5.5 PaperTradeEngine deterministic test

Direct unit test, no httpx:
- Construct an engine with default `position_size_shares=1.0` (one share per
  trade), feed it 3 synthetic `TradeSignal`s (2× YES at $0.40, 1× NO at $0.60)
  and 3 `ResolvedOutcome`s (markets 1 & 2 resolve YES, market 3 resolves YES →
  meaning the NO position loses).
- Per share: YES@$0.40 winning pays $1.00 → profit $0.60; NO@$0.60 losing pays
  $0.00 → loss $0.60.
- Expect: `n_fills=3`, `paper_pnl = 2*(1.00 - 0.40) - 1*0.60 = $0.60`,
  `backtest_metrics.kupiec=None` (n_resolved < window).

### 5.6 ResolutionPoller respx-mocked integration

`respx` mocks Gamma API responses across multiple poll cycles:
- Poll 1: market `active=True, closed=False, outcomePrices=["0.55","0.45"]` →
  yields `PriceTick(0.55)`.
- Poll 2: same → yields `PriceTick(0.55)`.
- Poll 3: `closed=True, outcomePrices=["1","0"]` → yields
  `ResolvedOutcome(outcome=1)`, then poller stops following that market.
- Total: 2 `PriceTick` events + 1 `ResolvedOutcome`.

### 5.7 Stub L4 threshold strategy unit tests

- `threshold_strategy(p_hat=0.6, market_yes_price=0.5, threshold=0.05)`
  → `TradeSignal(side=YES, edge=0.10, ...)`.
- `threshold_strategy(p_hat=0.5, market_yes_price=0.6, threshold=0.05)`
  → `TradeSignal(side=NO, edge=0.10, ...)`.
- `threshold_strategy(p_hat=0.52, market_yes_price=0.5, threshold=0.05)`
  → `None` (edge=0.02 < threshold).

### 5.8 Full-suite green

`pytest -v` from the project root: all Phase 0 tests (26) + all Phase 1A tests
(~22 estimated) = ~48 passing total.

**Gate result if all 5.1–5.8 pass:** Phase 1A complete. Ready for Phase 1B (real
L3 modules consuming this infra).

---

## 6. Open Risks

1. **Resolution data not in Phase 0 store.** `walk_forward_backtest` takes
   `resolutions: dict[str, ResolvedOutcome]` as input, so Phase 1A's gate test
   supplies them synthetically. Real backtests against Phase 0's stored history
   will require either re-querying Polymarket per market at backtest time, or a
   Phase 1B schema migration to add a `resolutions` table. Mitigation: defer
   to Phase 1B; document the gap.

2. **Kupiec "exception" definition is one choice among several.** Phase 1A uses
   "exception = prediction picked wrong side via `argmax(p_hat, 1-p_hat)`." This
   is reasonable but not canonical. Mitigation: `kupiec_test` takes pre-counted
   exceptions — the definition is the caller's choice, easy to swap.

3. **Phase 0's stored history may have too few resolved markets for a 100-window
   Kupiec.** Mitigation: function returns `kupiec=None` when
   `n_resolved < kupiec_window`; the report is honest about insufficient data.

4. **$1 paper position size is arbitrary.** Picked for 1%-of-$100 symmetry. The
   real position-sizing rule (fractional Kelly per spec) needs design before
   Phase 2 go-live. Mitigation: position size is a constructor parameter.

5. **Slippage = 0 papers over liquidity reality.** Polymarket low-cap markets
   routinely have 10–20% bid/ask spreads. Mitigation: `slippage_model` is an
   injectable callable; replace the zero-default with a spread-based model in
   Phase 1B.

6. **ResolutionPoller's 60-second cadence is arbitrary.** Markets that resolve
   and immediately become unavailable could be missed. Mitigation: poll interval
   is configurable.

---

## 7. Tech Stack Additions

Beyond Phase 0's stack, Phase 1A adds:

- **`scipy`** (`>=1.13`) for `scipy.stats.chi2.sf` (Kupiec p-value computation).
  Add to `pyproject.toml` core dependencies (not dev-only — paper-trade-live runs
  the test in production).

No other new dependencies. Async polling reuses Phase 0's `httpx` + `PolymarketClient`.

---

## 8. Plan Decomposition Path

The implementation plan (next document, via `writing-plans` skill) will
decompose Phase 1A into bite-sized TDD tasks. Anticipated task structure:

1. Add `scipy` to deps; create `agent/validation/types.py` with all dataclasses.
2. `metrics.kupiec_test` — TDD against the three reference cases in §5.1.
3. `metrics.brier_score` — TDD against §5.2.
4. `metrics.reliability_curve` — TDD against §5.3.
5. `research/baselines.py` — last_traded_price + constant_half.
6. `backtest.walk_forward_backtest` — TDD integration against §5.4.
7. `strategy/threshold.py` — threshold_strategy + §5.7 tests.
8. `paper_trade.PaperTradeEngine` — §5.5 deterministic test.
9. `resolution_poller.ResolutionPoller` — §5.6 respx-mocked test.
10. Full-suite gate test + CLI entrypoint.

Roughly 10 tasks. Same TDD discipline as Phase 0 (write failing test → implement
→ pass → commit per task). Subagent-driven execution recommended.
