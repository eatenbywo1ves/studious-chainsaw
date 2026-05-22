# Polymarket Agent — Phase 1B-C3a: Spot-Only Backtest Validation Harness — Design Spec

**Date:** 2026-05-21
**Phase:** 1B-C3a (first cut of Phase 1B-C3 — alpha test; spot-only, before the news stack)
**Parent specs:**
- `2026-05-19-polymarket-fair-value-agent-design.md` (overall project design)
- `2026-05-20-polymarket-phase-1a-l7-validation-gate-design.md` (L7 framework this extends)
- `2026-05-21-polymarket-phase-1b-c1-crypto-foundation-design.md` (math primitives)
- `2026-05-21-polymarket-phase-1b-c2-composite-crypto-model-design.md` (the model under test)

**Builds on:** Phase 1B-C2-A (branch `feat/polymarket-phase-1b-c2-a`, tip `dad67b58`, 187 tests green).

---

## 1. Goal & Scope

### 1.1 Goal

Measure whether the C2-A composition model — running on **spot-shock signals
only** (the `SpotOnlyShockDetector` placeholder; no news) — has a real,
cost-surviving, risk-adjusted edge over the Polymarket market price, on an
**unbiased exhaustive** set of historically-resolved crypto barrier markets.

This is the project's first honest answer to "is the alpha thesis true?"
before any further machinery is built. The harness produces a clear
**continue / stop** verdict that gates whether the multilingual news stack
(C2-B/C/D) is worth building.

### 1.2 Why spot-only, why now

C2-A produces predictions today using spot-shock detection alone. Validating
this cheap signal first tells us where the bottleneck is:
- If spot-only shows **no** Brier improvement over the market baseline, the
  bridge model itself lacks edge — news (C2-B/C/D) would not fix that, and we
  save ~3 weeks of news plumbing.
- If spot-only shows **promise**, news becomes a justified enhancement and we
  proceed to C2-B with evidence.

### 1.3 In scope (C3a)

- `agent/research/crypto/question_parser.py` — LLM-based extraction of
  `(symbol, barrier, direction, resolution_date, confidence)` from a market
  question, plus a validation layer and an on-disk cache for reproducibility.
- `agent/data/polymarket_history.py` — ingestion of resolved-market price
  history from Polymarket's CLOB `/prices-history` endpoint into `PriceSnapshot`.
- `agent/data/polymarket_enumerate.py` — enumerate all resolved crypto-category
  markets in a fixed window via the Gamma API.
- `agent/validation/pnl.py` — P&L simulator: positions → per-trade returns →
  compounding equity curve.
- `agent/validation/risk_metrics.py` — Sharpe, Sortino, max drawdown, win rate,
  profit factor, Brier skill score (vs a baseline Brier).
- `agent/validation/crypto_backtest.py` — orchestrator that wires enumeration,
  parsing, ingestion, the dual backtest run (model + baseline), and report
  generation.
- `agent/validation/baseline.py` — the market-price baseline model
  (`p_hat = event.price`).
- `agent/scripts/run_crypto_validation.py` — CLI entry producing the validation
  report (JSON + human-readable summary).
- Reuse (no changes beyond additive): `agent/validation/backtest.py`
  (`walk_forward_backtest`, `ReplayEngine`), `agent/validation/metrics.py`
  (`brier_score`, `reliability_curve`, `kupiec_test`).

### 1.4 Out of scope (deferred)

- News-based validation: requires C2-B/C/D. C3a is spot-only.
- Parameter tuning: C3a runs C2-A's pre-committed defaults
  (`spot_threshold_k=3.0`, half-Kelly, etc.). No fitting, so no holdout needed.
  A tuning pass with out-of-sample holdout is a follow-up justified only if
  C3a shows promise.
- Live/forward paper trading: C3a is historical backtest only. Forward
  paper-trade is a separate follow-up (uses existing `paper_trade.py`).
- Portfolio-correlation-aware sizing, regime-change gate, confidence-bounded
  fractional Kelly: these are the risk improvements C3a's results will help
  prioritize (Phase 2 L5 / C2.1). C3a sizes each market independently with the
  existing KellySizer — the backtest will reveal whether independent sizing's
  correlation blindness materially hurts the equity curve.

### 1.5 Completion gate (algorithmic)

C3a is complete when:
- `pytest -v` is green at ~210 tests (187 prior + ~25 C3a).
- `run_crypto_validation.py` executes end-to-end on the enumerated market set
  and emits a report containing every metric in §5, under all four cost
  scenarios (0/1/2/3%), with the coverage-honesty counts (§4.6).
- The report renders a clear **continue / stop** verdict per §6.

The *scientific* verdict (does the edge exist) is the report's output, not a
pass/fail of the harness. The harness is "done" when it can produce that
verdict reproducibly; the verdict itself is data.

---

## 2. Architecture & Module Structure

### 2.1 Repository layout (extends Phase 1A validation + C1/C2 crypto)

```
agent/
  data/
    polymarket_enumerate.py      # NEW: list resolved crypto markets in window (Gamma API)
    polymarket_history.py        # NEW: CLOB /prices-history -> PriceSnapshot ingestion
  research/
    crypto/
      question_parser.py         # NEW: LLM extraction + validation + on-disk cache
  validation/
    backtest.py                  # REUSE: walk_forward_backtest, ReplayEngine (no change)
    metrics.py                   # REUSE: brier_score, reliability_curve, kupiec_test (no change)
    baseline.py                  # NEW: market-price baseline model
    pnl.py                       # NEW: P&L simulator (equity curve from positions)
    risk_metrics.py              # NEW: Sharpe, Sortino, max drawdown, Brier skill score, etc.
    crypto_backtest.py           # NEW: orchestrator + report assembly
  scripts/
    run_crypto_validation.py     # NEW: CLI entry
tests/
  data/
    test_polymarket_enumerate.py # NEW: respx-mocked Gamma responses
    test_polymarket_history.py   # NEW: respx-mocked CLOB prices-history
  research/crypto/
    test_question_parser.py      # NEW: extraction validation + cache hit/miss + sanity-check rejection
  validation/
    test_baseline.py             # NEW
    test_pnl.py                   # NEW: equity curve + cost scenarios
    test_risk_metrics.py          # NEW: hand-computed Sharpe/Sortino/drawdown/skill-score
    test_crypto_backtest.py       # NEW: end-to-end on synthetic market set
```

### 2.2 Architectural seam

C3a consumes C2-A's `crypto_model` (via partial application into the
`Callable[[str, ReplayEvent], Prediction]` contract `walk_forward_backtest`
expects) and Phase 1A's `walk_forward_backtest`. It adds a parallel run with
`baseline.py`'s model for the skill-score comparison, then layers the P&L and
risk-metrics engines on top of the prediction stream. Nothing in C3a modifies
C2-A or Phase 1A code — it is purely additive.

### 2.3 Key structural decisions

1. **Extend, don't rebuild.** `ReplayEngine` and `walk_forward_backtest`
   already enforce the no-look-ahead walk-forward property and produce
   calibration metrics. C3a adds P&L/risk on top and a second (baseline) run;
   it does not reimplement replay or calibration.

2. **Reproducibility via extraction cache.** LLM question-parsing is
   non-deterministic. The harness extracts once, caches each mapping to disk
   keyed by `market_id`, and replays from the cache. Re-running the backtest
   never re-calls the LLM and yields identical results. The cache is committed
   to the repo (or stored under a known path) so the validation is auditable.

3. **Mis-parse exclusion, not guessing.** A parse that fails the validation
   layer (low confidence, implausible barrier, inconsistent direction,
   unparseable date) is excluded from the test and counted in the coverage
   report — never silently guessed. A validation harness must not be poisoned
   by a hallucinated barrier.

4. **No tuning → no overfitting → no holdout.** C3a runs pre-committed C2-A
   defaults. The verdict is an honest test of the model as built.

5. **Cost as a sensitivity sweep, not a single number.** Edge and risk metrics
   are reported at 0/1/2/3% round-trip cost so fragility to costs is visible.

6. **New dependency:** `openai>=1.0` (already anticipated in C2's spec for
   translation; used here for question extraction). Structured-output schema
   via the responses/JSON-mode API.

---

## 3. Question Parser (`question_parser.py`)

### 3.1 Extraction

```python
@dataclass(frozen=True)
class ParsedMarket:
    """Result of parsing one Polymarket question.  All fields populated only
    when status == 'ok'; otherwise reason explains the exclusion."""

    market_id: str
    status: Literal["ok", "low_confidence", "implausible_barrier",
                    "inconsistent_direction", "unparseable_date", "not_crypto_barrier"]
    symbol: str | None            # "BTCUSDT", "ETHUSDT", ...
    barrier: float | None
    direction: Literal["up", "down"] | None
    resolution_ts: int | None     # unix seconds
    confidence: float             # LLM-reported, in [0, 1]
    reason: str                   # human-readable explanation when excluded


def parse_question(
    market_id: str,
    question: str,
    *,
    llm_extract: Callable[[str], dict],   # injected for testing
    cache: ParseCache,
    confidence_threshold: float = 0.85,
) -> ParsedMarket:
    """Extract (symbol, barrier, direction, resolution_date) from a market
    question.  Cache-first: returns the cached ParsedMarket if present;
    otherwise calls llm_extract, validates, caches, and returns.

    The LLM is prompted for structured output:
      {symbol, barrier_usd, direction, resolution_date_iso, confidence,
       is_crypto_barrier_market}
    """
```

### 3.2 Validation layer (sanity checks before a parse is trusted)

```python
def validate_parse(
    raw: dict,
    *,
    underlying_price_range: tuple[float, float] | None,
    confidence_threshold: float,
) -> ParsedMarket:
    """Apply objective checks; downgrade status if any fail:
      - is_crypto_barrier_market is False        -> not_crypto_barrier
      - confidence < confidence_threshold        -> low_confidence
      - resolution_date_iso unparseable          -> unparseable_date
      - barrier <= 0 or NaN/inf                  -> implausible_barrier
      - barrier outside [0.1x, 10x] of the underlying's actual price range
        over the market lifetime (when range is known) -> implausible_barrier
      - direction inconsistent with barrier-vs-spot at market open
        (e.g., 'up' but barrier already below spot at open) -> inconsistent_direction
    Only status == 'ok' parses enter the backtest.
    """
```

The `underlying_price_range` is supplied after Binance OHLCV ingestion (§4.4),
so validation runs as a second pass once the underlying data is available. The
barrier-plausibility check is the key anti-hallucination guard: a "$8,000 BTC"
barrier in a market where BTC traded $60k-$100k is rejected.

### 3.3 Cache (`ParseCache`)

On-disk JSON keyed by `market_id`. `get(market_id) -> ParsedMarket | None`,
`put(parsed)`. Stored at `agent/research/crypto/parse_cache/` (committed so the
backtest is reproducible by anyone with the repo). A `--refresh` flag on the
CLI bypasses the cache for a specific market when re-extraction is needed.

---

## 4. Data Pipeline

### 4.1 Enumerate (`polymarket_enumerate.py`)

```python
async def enumerate_resolved_crypto_markets(
    client: PolymarketClient,
    *,
    window_start_iso: str,
    window_end_iso: str,
) -> list[MarketDTO]:
    """List every resolved market in the crypto category whose resolution
    falls in [window_start, window_end].  Uses the Gamma API with
    category/tag filters + closed=true.  No outcome-based filtering — this is
    the exhaustive population.  Pagination handled internally.
    """
```

Window default: `2024-01-01` to `2026-04-30` (configurable on the CLI). The
window is fixed and pre-committed (documented in the report) so the population
is reproducible.

### 4.2 Parse + validate (pass 1)

For each enumerated market, `parse_question(...)`. Markets with status
`not_crypto_barrier` or `low_confidence` or `unparseable_date` are dropped here
(barrier-plausibility check deferred to pass 2 after OHLCV ingestion).

### 4.3 Ingest Polymarket price history (`polymarket_history.py`)

```python
async def ingest_market_price_history(
    client: PolymarketClient,
    repository_save: Callable,
    session: Session,
    market: MarketDTO,
) -> int:
    """Fetch the YES-token price history from CLOB /prices-history and persist
    as PriceSnapshot rows.  Returns count inserted.  Idempotent (skip-existing
    by (market_id, token_id, ts)).
    """
```

### 4.4 Ingest contemporaneous Binance OHLCV

For each surviving market, use C1's `CryptoIngestService.ingest_history(symbol,
"1h", start_ts, end_ts)` over the market's lifetime (open → resolution). Then
run parse-validation **pass 2** (barrier-plausibility against the now-known
underlying price range; direction consistency).

### 4.5 Resolve outcomes

```python
def build_resolutions(markets: list[MarketDTO]) -> dict[str, ResolvedOutcome]:
    """Map each market_id to its ResolvedOutcome (0/1) from the Gamma
    resolution field (umaResolutionStatus / outcome).  Markets without a clean
    resolution are excluded and counted.
    """
```

### 4.6 Coverage honesty

The report records, as integer counts: enumerated, parsed-ok (pass 1),
passed-validation (pass 2), had-sufficient-OHLCV, had-clean-resolution,
**actually-tested**. This makes survivorship explicit — a verdict on 12 of 400
enumerated markets is weaker than on 380 of 400, and the report shows which.

---

## 5. P&L, Risk Metrics, and the Report

### 5.1 Baseline model (`baseline.py`)

```python
def market_price_model(market_id: str, event: ReplayEvent) -> Prediction:
    """Trivial forecaster: p_hat = event.price.  The benchmark crypto_model
    must beat on Brier to claim any edge."""
```

### 5.2 P&L simulator (`pnl.py`)

```python
@dataclass(frozen=True)
class Trade:
    market_id: str
    entry_ts: int
    direction: Literal["yes", "no"]
    entry_price: float           # YES price paid (or 1 - price for NO)
    fraction: float              # Kelly fraction of bankroll at entry
    outcome: int                 # 0/1 resolution
    round_trip_cost: float       # applied cost fraction


@dataclass(frozen=True)
class EquityCurve:
    timestamps: list[int]
    bankroll: list[float]        # compounding
    trades: list[Trade]


def simulate_pnl(
    predictions: list[Prediction],   # CryptoPredictions with position_size
    resolutions: dict[str, ResolvedOutcome],
    *,
    starting_bankroll: float = 100.0,
    round_trip_cost: float = 0.0,
    one_position_per_market: bool = True,
) -> EquityCurve:
    """Convert the prediction stream into a compounding equity curve.

    Entry: when a prediction has position_size > 0, open a position at the
    event price in the prediction's direction, staking `fraction * bankroll`.
    Cost: subtract round_trip_cost * stake at entry.
    Resolution: at the market's resolution, YES pays $1/share, NO pays $1 if
    outcome==0.  Realize P&L, compound into bankroll.
    one_position_per_market: take only the FIRST qualifying signal per market
    (avoids double-counting a market that signals on many ticks).
    """
```

The `one_position_per_market` default reflects that a barrier market is one bet,
not one-per-tick; the first qualifying signal is the entry.

### 5.3 Risk metrics (`risk_metrics.py`)

```python
def sharpe_ratio(returns: list[float], *, periods_per_year: float) -> float: ...
def sortino_ratio(returns: list[float], *, periods_per_year: float) -> float: ...
def max_drawdown(bankroll: list[float]) -> float: ...      # peak-to-trough fraction
def win_rate(trades: list[Trade]) -> float: ...
def profit_factor(trades: list[Trade]) -> float: ...        # gross win / gross loss
def brier_skill_score(model_brier: float, baseline_brier: float) -> float:
    """1 - model_brier / baseline_brier.  > 0 means the model beats the
    baseline; 0 means no improvement; < 0 means worse than the market price."""


def bootstrap_skill_ci(
    model_pairs: list[tuple[float, int]],
    baseline_pairs: list[tuple[float, int]],
    *,
    n_resamples: int = 10_000,
    alpha: float = 0.05,
    seed: int = 12345,
) -> tuple[float, float]:
    """Bootstrap confidence interval for the Brier skill score.

    Resamples markets (paired: same resampled index used for both model and
    baseline, so the comparison is on the same markets each draw), recomputes
    skill score per resample, returns the (lower, upper) percentile bounds at
    (alpha/2, 1 - alpha/2).  The lower bound answers "is the edge distinguishable
    from luck given this many markets?"  Deterministic given `seed`.

    With a finite market count a positive point-estimate skill score can be
    noise; CONTINUE requires the lower bound > 0 (see §6).
    """
```

Per-trade returns are computed on closed trades; Sharpe/Sortino annualization
uses the average holding period to derive `periods_per_year` (documented in the
report, since event-based returns aren't naturally periodic).

### 5.4 Orchestrator + report (`crypto_backtest.py`)

```python
@dataclass(frozen=True)
class ValidationReport:
    window: tuple[str, str]
    coverage: dict[str, int]              # §4.6 counts
    # Calibration (model vs baseline)
    model_brier: float
    baseline_brier: float
    brier_skill_score: float
    brier_skill_ci: tuple[float, float]   # bootstrap (lower, upper) at 95%
    reliability_curve: list[tuple[float, float] | tuple[None, None]]
    kupiec_zone: str | None
    # Risk-adjusted, per cost scenario {0.0, 0.01, 0.02, 0.03}
    by_cost: dict[float, "CostScenarioMetrics"]
    # Breakdowns
    per_market: list["MarketResult"]
    per_mode: dict[str, "ModeResult"]     # which composition mode contributed
    verdict: Literal["CONTINUE", "STOP", "INCONCLUSIVE"]
    verdict_rationale: str
```

The orchestrator runs `walk_forward_backtest` with `crypto_model` and with the
baseline, simulates P&L under each cost, assembles the report, and computes the
verdict (§6). The CLI writes the report as JSON plus a human-readable summary.

---

## 6. The Verdict (success criteria)

The report renders one of three verdicts from objective thresholds:

- **CONTINUE** — `brier_skill_score > 0` (beats market baseline) AND the
  **bootstrap skill-score CI lower bound > 0** (edge is distinguishable from
  luck at the 95% level) AND Sharpe > 0 survives at ≥1% round-trip cost AND
  `coverage.actually_tested >= 20`. Interpretation: spot-only has a
  statistically plausible edge; building C2-B news and/or a tuning pass is
  justified.
- **STOP** — `brier_skill_score <= 0` at 0% cost. Interpretation: the bridge
  model has no calibration edge over the market price even frictionless; news
  will not fix a bad fair-value estimate. Rethink the bridge before more work.
- **INCONCLUSIVE** — `coverage.actually_tested < 20`, or skill score positive
  point-estimate but bootstrap CI lower bound <= 0 (can't rule out luck), or
  Sharpe doesn't survive any cost. Interpretation: insufficient data or edge
  too thin to distinguish from noise; expand the window or proceed to forward
  paper-trade for a cleaner read.

The thresholds are pre-committed here so the verdict isn't rationalized after
seeing results.

---

## 7. Acceptance Criteria — the Algorithmic Gate

Reference tests with hand-computed values (carrying C1/C2 bug-defense
discipline).

### 7.1 `risk_metrics` hand-computed references

| Function | Input | Expected | Catches |
|---|---|---|---|
| `sharpe_ratio` | returns `[0.1, -0.05, 0.2, 0.0]`, periods_per_year=12 | hand-computed `mean/std * sqrt(12)` | annualization, std formula |
| `sortino_ratio` | same returns | hand-computed using downside deviation only | downside-only denominator |
| `max_drawdown` | bankroll `[100, 120, 90, 130, 80]` | `(130-80)/130 = 0.3846` | peak tracking after new high |
| `brier_skill_score` | model=0.18, baseline=0.25 | `1 - 0.18/0.25 = 0.28` | direction (positive = better) |
| `brier_skill_score` | model=0.30, baseline=0.25 | `1 - 0.30/0.25 = -0.20` | worse-than-baseline sign |
| `win_rate` | 3 wins of 5 | `0.6` | |
| `profit_factor` | wins sum 1.5, losses sum 0.5 | `3.0` | |
| `bootstrap_skill_ci` | model clearly better on a constructed 50-market set, fixed seed | lower bound > 0; deterministic across re-runs (same seed → same CI) | resample pairing, determinism, percentile bounds |
| `bootstrap_skill_ci` | model == baseline (identical pairs) | CI straddles 0 (lower < 0 < upper) | no-edge case not falsely flagged significant |

### 7.2 `simulate_pnl` references

- **Single winning YES trade, 0% cost:** bankroll 100, fraction 0.10, entry
  price 0.10, outcome 1 → stake $10 buys 100 shares, pays $100, profit $90,
  bankroll → $190. Hand-verify.
- **Same trade, 2% cost:** stake $10, cost $0.20, net entry $9.80 → fewer
  shares; hand-verify the bankroll.
- **Single losing trade:** outcome 0 → lose the stake; bankroll → $90.
- **one_position_per_market:** a market with 5 qualifying ticks produces
  exactly 1 Trade.
- **Compounding:** two sequential winning trades compound (second stake is a
  fraction of the grown bankroll).

### 7.3 `question_parser` references

- Valid BTC question → status ok, correct symbol/barrier/direction.
- Hallucinated barrier ($8,000 when underlying ranged $60k-$100k) → status
  `implausible_barrier`, excluded.
- Low LLM confidence (0.5 < threshold 0.85) → `low_confidence`, excluded.
- Non-crypto question → `not_crypto_barrier`, excluded.
- Cache hit: second `parse_question` for the same market_id does NOT call
  `llm_extract` (assert the injected mock's call count stays 1).
- Direction inconsistency (says "up" but barrier below open spot) →
  `inconsistent_direction`.

### 7.4 Enumeration + history ingestion (respx-mocked)

- Gamma enumeration parses a mocked multi-page response into MarketDTOs;
  pagination followed; only resolved+crypto returned.
- CLOB prices-history parses into PriceSnapshot rows; idempotent re-call
  inserts 0.

### 7.5 End-to-end `crypto_backtest` on synthetic set

Construct 3 synthetic resolved markets (1 where the model should beat baseline,
1 where it shouldn't, 1 borderline) with seeded OHLCV + price history +
resolutions + cached parses. Run the orchestrator. Assert:
- The report's coverage counts are correct.
- `brier_skill_score` matches an independently computed value.
- The verdict matches the constructed scenario (e.g., CONTINUE when the model
  clearly beats baseline and Sharpe survives cost).
- All four cost scenarios are present in `by_cost`.

---

## 8. Bug-Defense Discipline (carried forward)

1. **Hand-computed reference values** for every metric (§7.1, §7.2).
2. **Independent cross-checks** where a metric could be computed two ways
   (e.g., brier_skill_score in the e2e test is recomputed independently of the
   orchestrator, mirroring the blender test approach from C2-A).
3. **Structural unit-clarity:** `round_trip_cost` is a fraction in [0, 1] (not
   basis points); `fraction` is bankroll-fraction in [0, kelly_cap]; documented
   on the dataclasses.
4. **Anti-hallucination as a first-class control:** the parse validation layer
   is itself tested (§7.3) — the harness's integrity depends on rejecting bad
   parses, so that rejection is a tested behavior, not an afterthought.
5. **Coverage honesty:** the report cannot hide survivorship — the counts are
   mandatory fields, and the verdict refuses CONTINUE below 20 tested markets.
6. **Pre-committed verdict thresholds** (§6) prevent post-hoc rationalization.

---

## 9. Known Follow-ups and Open Questions (not blockers for C3a)

1. **Bootstrap significance testing — PULLED INTO CORE SCOPE (user approved).**
   `bootstrap_skill_ci` (§5.3) gives a 95% CI on the Brier skill score;
   CONTINUE requires the lower bound > 0 (§6). A future refinement could add a
   bootstrap CI on Sharpe too, and/or a permutation test as a second
   significance lens — those remain follow-ups, but the core skill-score
   significance gate is now in scope.

2. **Forward paper-trade confirmation.** A CONTINUE verdict from historical
   backtest should ideally be confirmed forward (no hindsight) before risking
   the $100. Uses the existing `paper_trade.py`. Separate sub-phase.

3. **Real historical spreads.** C3a uses a cost sensitivity sweep instead of
   real per-market spreads (which may be unavailable historically). If the
   CLOB book history turns out to be retrievable, real spreads would sharpen
   the edge-after-cost estimate.

4. **Correlation-aware portfolio sizing.** C3a sizes each market independently.
   If the equity curve shows clustered drawdowns (correlated BTC exposure), it
   confirms the need for the Phase 2 L5 portfolio-Kelly work.

5. **Parse-cache staleness.** Cached parses are committed for reproducibility;
   if the question text or mapping logic changes, the `--refresh` flag
   re-extracts. A cache-versioning scheme (hash of the prompt) is a possible
   refinement.

6. **LLM model choice and cost.** Default extraction model and per-call cost
   should be recorded in the report. Hundreds of cheap structured-output calls;
   monitor spend.

---
