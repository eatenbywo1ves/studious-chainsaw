# Polymarket Phase 1B-C3a: Spot-Only Validation Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the validation harness that measures whether C2-A's spot-only composition model has a real, cost-surviving, statistically-significant risk-adjusted edge over the Polymarket market price, on an unbiased exhaustive set of resolved crypto barrier markets — producing a pre-committed CONTINUE/STOP/INCONCLUSIVE verdict.

**Architecture:** Extend Phase 1A's `agent/validation/` framework (reuse `ReplayEngine`, `walk_forward_backtest`, `brier_score`, `reliability_curve`, `kupiec_test`). Add pure-function metric engines (risk metrics, P&L), a market-price baseline, an LLM question-parser with a validation layer + reproducible cache, a Gamma/CLOB data pipeline, and an orchestrator that assembles the report. Purely additive — no changes to C2-A or Phase 1A code.

**Tech Stack:** Python 3.12+, SQLAlchemy 2.0, pydantic v2, frozen dataclasses, pytest, respx (HTTP mocking), `openai>=1.0` (question extraction). Reuses C1's `CryptoIngestService`, C2-A's `crypto_model`.

**Parent spec:** `docs/superpowers/specs/2026-05-21-polymarket-phase-1b-c3a-spot-only-validation-design.md` (commit `89e8740f`).

---

## File Structure

| File | Responsibility |
|---|---|
| `agent/validation/risk_metrics.py` (new) | Sharpe, Sortino, max_drawdown, win_rate, profit_factor, brier_skill_score, bootstrap_skill_ci |
| `agent/validation/baseline.py` (new) | `market_price_model` (p_hat = event.price) |
| `agent/validation/pnl.py` (new) | `Trade`, `EquityCurve`, `simulate_pnl` (cost scenarios, compounding) |
| `agent/research/crypto/question_parser.py` (new) | `ParsedMarket`, `parse_question`, `validate_parse`, `ParseCache` |
| `agent/data/polymarket_enumerate.py` (new) | `enumerate_resolved_crypto_markets` (Gamma API) |
| `agent/data/polymarket_history.py` (new) | `ingest_market_price_history` (CLOB /prices-history) |
| `agent/validation/crypto_backtest.py` (new) | `ValidationReport`, orchestrator, verdict logic |
| `agent/scripts/run_crypto_validation.py` (new) | CLI entry; JSON + human-readable report |
| Test files mirror under `tests/` | One per source file |

**Execution order rationale:** pure-function engines first (risk_metrics, baseline, pnl) — fully testable in isolation with hand-computed values. Then the data layer (parser, enumerate, history) — respx-mocked. Then the orchestrator that ties everything together. Then the CLI + end-to-end gate.

---

## Pre-flight

- [ ] **Step P.1: Confirm branch + clean baseline**

Run:
```
git branch --show-current
.venv/Scripts/python.exe -m pytest -q
```
Expected: on `feat/polymarket-phase-1b-c2-a` (or a fresh `feat/polymarket-phase-1b-c3a` branched from it), 187 tests passing.

- [ ] **Step P.2: Create C3a branch**

```
git checkout -b feat/polymarket-phase-1b-c3a
```

- [ ] **Step P.3: Add openai dependency**

Edit `pyproject.toml` `[project] dependencies`, add `"openai>=1.0",` (alphabetical). Run `.venv/Scripts/python.exe -m pip install "openai>=1.0"`. Verify import.

---

## Task 1: `risk_metrics.py`

**Files:** Create `agent/validation/risk_metrics.py`, `tests/validation/test_risk_metrics.py`.

- [ ] **Step 1.1: Write failing tests (hand-computed references per spec §7.1)**

Create `tests/validation/test_risk_metrics.py`:
```python
import math

from agent.validation.risk_metrics import (
    bootstrap_skill_ci,
    brier_skill_score,
    max_drawdown,
    profit_factor,
    sharpe_ratio,
    sortino_ratio,
    win_rate,
)


def test_sharpe_ratio_hand_computed():
    returns = [0.1, -0.05, 0.2, 0.0]
    # mean = 0.0625; sample std (ddof=1): sqrt(sum((r-mean)^2)/3)
    mean = sum(returns) / len(returns)
    var = sum((r - mean) ** 2 for r in returns) / (len(returns) - 1)
    std = math.sqrt(var)
    expected = (mean / std) * math.sqrt(12)
    assert abs(sharpe_ratio(returns, periods_per_year=12) - expected) < 1e-9


def test_sortino_ratio_downside_only():
    returns = [0.1, -0.05, 0.2, 0.0]
    mean = sum(returns) / len(returns)
    downside = [min(r, 0.0) for r in returns]
    dd = math.sqrt(sum(d ** 2 for d in downside) / len(returns))
    expected = (mean / dd) * math.sqrt(12)
    assert abs(sortino_ratio(returns, periods_per_year=12) - expected) < 1e-9


def test_max_drawdown():
    bankroll = [100, 120, 90, 130, 80]
    # peak before final trough is 130; trough 80 -> (130-80)/130
    assert abs(max_drawdown(bankroll) - (130 - 80) / 130) < 1e-9


def test_brier_skill_score_positive():
    assert abs(brier_skill_score(0.18, 0.25) - 0.28) < 1e-9


def test_brier_skill_score_negative():
    assert abs(brier_skill_score(0.30, 0.25) - (-0.20)) < 1e-9


def test_win_rate():
    from agent.validation.pnl import Trade
    trades = [
        Trade("m1", 0, "yes", 0.1, 0.05, 1, 0.0),  # win
        Trade("m2", 0, "yes", 0.5, 0.05, 0, 0.0),  # loss
        Trade("m3", 0, "yes", 0.2, 0.05, 1, 0.0),  # win
        Trade("m4", 0, "no", 0.5, 0.05, 0, 0.0),   # win (NO, outcome 0)
        Trade("m5", 0, "yes", 0.3, 0.05, 0, 0.0),  # loss
    ]
    assert abs(win_rate(trades) - 0.6) < 1e-9


def test_bootstrap_skill_ci_clear_edge_is_significant_and_deterministic():
    # Model perfectly predicts; baseline is pure 0.5 guesses. 50 markets.
    model_pairs = [(1.0 if i % 2 == 0 else 0.0, i % 2 == 0) for i in range(50)]
    model_pairs = [(p, 1 if o else 0) for p, o in model_pairs]
    baseline_pairs = [(0.5, o) for _, o in model_pairs]
    lo1, hi1 = bootstrap_skill_ci(model_pairs, baseline_pairs, seed=42)
    lo2, hi2 = bootstrap_skill_ci(model_pairs, baseline_pairs, seed=42)
    assert (lo1, hi1) == (lo2, hi2)   # deterministic
    assert lo1 > 0                     # clear edge -> lower bound > 0


def test_bootstrap_skill_ci_no_edge_straddles_zero():
    # Model == baseline -> skill score 0 -> CI straddles 0.
    pairs = [(0.5, i % 2) for i in range(50)]
    lo, hi = bootstrap_skill_ci(pairs, pairs, seed=42)
    assert lo <= 0.0 <= hi
```

- [ ] **Step 1.2: Run; verify ImportError.**

```
.venv/Scripts/python.exe -m pytest tests/validation/test_risk_metrics.py -v
```

- [ ] **Step 1.3: Implement `risk_metrics.py`**

```python
"""Risk-adjusted return metrics for the C3a validation harness.

All pure functions.  Sharpe/Sortino annualize via an explicit periods_per_year
(event-based returns aren't naturally periodic; the caller derives this from
the average holding period and documents it in the report).
"""

import math
import random
from collections.abc import Sequence


def sharpe_ratio(returns: Sequence[float], *, periods_per_year: float) -> float:
    if len(returns) < 2:
        return 0.0
    mean = sum(returns) / len(returns)
    var = sum((r - mean) ** 2 for r in returns) / (len(returns) - 1)
    std = math.sqrt(var)
    if std == 0.0:
        return 0.0
    return (mean / std) * math.sqrt(periods_per_year)


def sortino_ratio(returns: Sequence[float], *, periods_per_year: float) -> float:
    if not returns:
        return 0.0
    mean = sum(returns) / len(returns)
    downside_sq = sum(min(r, 0.0) ** 2 for r in returns) / len(returns)
    dd = math.sqrt(downside_sq)
    if dd == 0.0:
        return 0.0
    return (mean / dd) * math.sqrt(periods_per_year)


def max_drawdown(bankroll: Sequence[float]) -> float:
    """Largest peak-to-trough decline as a fraction of the peak."""
    if not bankroll:
        return 0.0
    peak = bankroll[0]
    max_dd = 0.0
    for value in bankroll:
        if value > peak:
            peak = value
        if peak > 0:
            dd = (peak - value) / peak
            if dd > max_dd:
                max_dd = dd
    return max_dd


def win_rate(trades) -> float:
    if not trades:
        return 0.0
    wins = sum(1 for t in trades if _trade_is_win(t))
    return wins / len(trades)


def profit_factor(trades) -> float:
    gross_win = sum(_trade_pnl(t) for t in trades if _trade_pnl(t) > 0)
    gross_loss = -sum(_trade_pnl(t) for t in trades if _trade_pnl(t) < 0)
    if gross_loss == 0.0:
        return float("inf") if gross_win > 0 else 0.0
    return gross_win / gross_loss


def brier_skill_score(model_brier: float, baseline_brier: float) -> float:
    if baseline_brier == 0.0:
        return 0.0
    return 1.0 - model_brier / baseline_brier


def bootstrap_skill_ci(
    model_pairs: list[tuple[float, int]],
    baseline_pairs: list[tuple[float, int]],
    *,
    n_resamples: int = 10_000,
    alpha: float = 0.05,
    seed: int = 12345,
) -> tuple[float, float]:
    """Paired-resample bootstrap CI for the Brier skill score.

    The same resampled indices are used for both model and baseline each draw
    so the comparison is on the same markets.  Deterministic given seed.
    """
    n = len(model_pairs)
    if n == 0 or n != len(baseline_pairs):
        return (0.0, 0.0)
    rng = random.Random(seed)
    skills: list[float] = []
    for _ in range(n_resamples):
        idx = [rng.randrange(n) for _ in range(n)]
        m_sse = sum((model_pairs[i][0] - model_pairs[i][1]) ** 2 for i in idx) / n
        b_sse = sum((baseline_pairs[i][0] - baseline_pairs[i][1]) ** 2 for i in idx) / n
        skills.append(brier_skill_score(m_sse, b_sse))
    skills.sort()
    lo_idx = int((alpha / 2) * n_resamples)
    hi_idx = int((1 - alpha / 2) * n_resamples) - 1
    hi_idx = max(lo_idx, min(hi_idx, n_resamples - 1))
    return (skills[lo_idx], skills[hi_idx])


# --- helpers operating on pnl.Trade (imported lazily to avoid a cycle) ---

def _trade_pnl(t) -> float:
    """Realized P&L per $1 staked, net of round-trip cost.  Positive = win."""
    won = _trade_is_win(t)
    # entry_price is the per-share cost in [0,1]; payoff is $1 on win.
    if won:
        gross = (1.0 - t.entry_price) / t.entry_price
    else:
        gross = -1.0
    return gross - t.round_trip_cost


def _trade_is_win(t) -> bool:
    if t.direction == "yes":
        return t.outcome == 1
    return t.outcome == 0
```

NB: `_trade_pnl` returns P&L per $1 staked; the actual bankroll math lives in
`simulate_pnl` (Task 3). `win_rate`/`profit_factor` only need win/loss
classification and relative P&L, so this per-$1 form is sufficient.

- [ ] **Step 1.4: Run; expect 8 PASS.** (Note: `test_win_rate` imports `Trade` from pnl, built in Task 3 — if running before Task 3, that one test will error. Either implement Task 3's `Trade` dataclass first, or temporarily skip `test_win_rate`. RECOMMENDED: define the `Trade` dataclass in Task 3 before running the win_rate/profit_factor tests; run the other 6 risk-metric tests now.)**

```
.venv/Scripts/python.exe -m pytest tests/validation/test_risk_metrics.py -v -k "not win_rate"
```

- [ ] **Step 1.5: Commit**

```
git add agent/validation/risk_metrics.py tests/validation/test_risk_metrics.py
git commit -m "feat(polymarket-c3a): add risk_metrics (Sharpe/Sortino/drawdown/skill-score/bootstrap CI)"
```

---

## Task 2: `baseline.py`

**Files:** Create `agent/validation/baseline.py`, `tests/validation/test_baseline.py`.

- [ ] **Step 2.1: Write failing test**

```python
from agent.validation.backtest import ReplayEvent
from agent.validation.baseline import market_price_model


def test_market_price_model_returns_event_price_as_p_hat():
    event = ReplayEvent(ts=1000, token_id="tok", price=0.37)
    pred = market_price_model("0xMARKET", event)
    assert pred.p_hat == 0.37
    assert pred.market_id == "0xMARKET"
    assert pred.ts == 1000
```

- [ ] **Step 2.2: Run; ImportError.**

- [ ] **Step 2.3: Implement `baseline.py`**

```python
"""Market-price baseline model: the benchmark crypto_model must beat on Brier
to claim any edge.  p_hat = the last-traded YES price."""

from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def market_price_model(market_id: str, event: ReplayEvent) -> Prediction:
    return Prediction(market_id=market_id, ts=event.ts, p_hat=event.price)
```

NB: confirm `Prediction`'s constructor fields by reading `agent/validation/types.py`
(it is frozen; fields are at least `market_id`, `ts`, `p_hat`). Adjust if there
are additional required fields.

- [ ] **Step 2.4: Run; expect 1 PASS.**

- [ ] **Step 2.5: Commit**

```
git add agent/validation/baseline.py tests/validation/test_baseline.py
git commit -m "feat(polymarket-c3a): add market-price baseline model"
```

---

## Task 3: `pnl.py`

**Files:** Create `agent/validation/pnl.py`, `tests/validation/test_pnl.py`.

- [ ] **Step 3.1: Write failing tests (hand-computed per spec §7.2)**

```python
from agent.validation.pnl import Trade, EquityCurve, simulate_pnl
from agent.validation.types import Prediction, ResolvedOutcome


def _pred(market_id, ts, p_hat, position_size, direction):
    # CryptoPrediction-like: must expose market_id, ts, p_hat, position_size,
    # and a direction in diagnostics.  Use a lightweight stand-in.
    from agent.research.crypto.model import CryptoPrediction
    return CryptoPrediction(
        market_id=market_id, ts=ts, p_hat=p_hat,
        position_size=position_size,
        diagnostics={"kelly_direction": direction, "p_market": p_hat},
    )


def test_single_winning_yes_trade_zero_cost():
    preds = [_pred("m1", 100, 0.10, 0.10, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    # stake = 0.10 * 100 = $10 at price 0.10 -> 100 shares -> pays $100 -> profit $90
    assert abs(curve.bankroll[-1] - 190.0) < 1e-6


def test_single_losing_trade():
    preds = [_pred("m1", 100, 0.10, 0.10, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=0)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    assert abs(curve.bankroll[-1] - 90.0) < 1e-6  # lose the $10 stake


def test_cost_reduces_winning_pnl():
    preds = [_pred("m1", 100, 0.10, 0.10, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1)}
    curve0 = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    curve2 = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.02)
    assert curve2.bankroll[-1] < curve0.bankroll[-1]


def test_one_position_per_market():
    # 3 qualifying ticks on the same market -> exactly 1 Trade.
    preds = [
        _pred("m1", 100, 0.10, 0.10, "yes"),
        _pred("m1", 200, 0.12, 0.10, "yes"),
        _pred("m1", 300, 0.15, 0.10, "yes"),
    ]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0,
                         one_position_per_market=True)
    assert len(curve.trades) == 1


def test_compounding_two_sequential_wins():
    preds = [
        _pred("m1", 100, 0.50, 0.10, "yes"),
        _pred("m2", 200, 0.50, 0.10, "yes"),
    ]
    resolutions = {
        "m1": ResolvedOutcome(market_id="m1", outcome=1),
        "m2": ResolvedOutcome(market_id="m2", outcome=1),
    }
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    # Trade 1: stake $10 at 0.50 -> 20 shares -> $20 -> profit $10 -> bankroll 110.
    # Trade 2: stake 0.10*110 = $11 at 0.50 -> 22 shares -> $22 -> profit $11 -> 121.
    assert abs(curve.bankroll[-1] - 121.0) < 1e-6


def test_zero_position_size_no_trade():
    preds = [_pred("m1", 100, 0.10, 0.0, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    assert len(curve.trades) == 0
    assert curve.bankroll[-1] == 100.0
```

- [ ] **Step 3.2: Run; ImportError.**

- [ ] **Step 3.3: Implement `pnl.py`**

```python
"""P&L simulator: convert a CryptoPrediction stream into a compounding equity
curve under a given round-trip cost.

Binary-market mechanics: buying YES at price q for stake S buys S/q shares,
each paying $1 if outcome==1 (else $0).  Buying NO at price (1-q) is symmetric.
Round-trip cost is a fraction of the stake subtracted at entry.
"""

from dataclasses import dataclass, field
from typing import Literal

from agent.validation.types import ResolvedOutcome


@dataclass(frozen=True)
class Trade:
    market_id: str
    entry_ts: int
    direction: Literal["yes", "no"]
    entry_price: float        # per-share cost in [0,1] (YES price, or 1-YES for NO)
    fraction: float           # Kelly fraction of bankroll staked
    outcome: int              # 0/1
    round_trip_cost: float


@dataclass(frozen=True)
class EquityCurve:
    timestamps: list[int]
    bankroll: list[float]
    trades: list[Trade]


def simulate_pnl(
    predictions,
    resolutions: dict[str, ResolvedOutcome],
    *,
    starting_bankroll: float = 100.0,
    round_trip_cost: float = 0.0,
    one_position_per_market: bool = True,
) -> EquityCurve:
    ordered = sorted(predictions, key=lambda p: p.ts)
    bankroll = starting_bankroll
    timestamps = [0]
    curve = [starting_bankroll]
    trades: list[Trade] = []
    seen_markets: set[str] = set()

    for pred in ordered:
        if pred.position_size <= 0.0:
            continue
        if pred.market_id not in resolutions:
            continue
        if one_position_per_market and pred.market_id in seen_markets:
            continue
        seen_markets.add(pred.market_id)

        direction = pred.diagnostics.get("kelly_direction", "yes")
        yes_price = pred.diagnostics.get("p_market", pred.p_hat)
        entry_price = yes_price if direction == "yes" else (1.0 - yes_price)
        if entry_price <= 0.0 or entry_price >= 1.0:
            continue

        stake = pred.position_size * bankroll
        cost = round_trip_cost * stake
        net_stake = stake - cost
        shares = net_stake / entry_price
        outcome = resolutions[pred.market_id].outcome

        won = (direction == "yes" and outcome == 1) or (direction == "no" and outcome == 0)
        payoff = shares * 1.0 if won else 0.0
        bankroll = bankroll - stake + payoff

        trades.append(Trade(
            market_id=pred.market_id, entry_ts=pred.ts, direction=direction,
            entry_price=entry_price, fraction=pred.position_size, outcome=outcome,
            round_trip_cost=round_trip_cost,
        ))
        timestamps.append(pred.ts)
        curve.append(bankroll)

    return EquityCurve(timestamps=timestamps, bankroll=curve, trades=trades)
```

- [ ] **Step 3.4: Run pnl tests + the deferred win_rate test**

```
.venv/Scripts/python.exe -m pytest tests/validation/test_pnl.py tests/validation/test_risk_metrics.py -v
```
Expected: all PASS (pnl tests + the previously-deferred `test_win_rate`).

- [ ] **Step 3.5: Commit**

```
git add agent/validation/pnl.py tests/validation/test_pnl.py
git commit -m "feat(polymarket-c3a): add P&L simulator (compounding equity curve, cost scenarios)"
```

---

## Task 4: `question_parser.py`

**Files:** Create `agent/research/crypto/question_parser.py`, `tests/research/crypto/test_question_parser.py`.

- [ ] **Step 4.1: Write failing tests (spec §7.3)**

```python
import tempfile

import pytest

from agent.research.crypto.question_parser import (
    ParseCache,
    ParsedMarket,
    parse_question,
)


def _cache():
    d = tempfile.mkdtemp()
    return ParseCache(cache_dir=d)


def _extract_btc_up(_q):
    return {
        "symbol": "BTCUSDT", "barrier_usd": 80000.0, "direction": "up",
        "resolution_date_iso": "2026-06-30T00:00:00Z", "confidence": 0.95,
        "is_crypto_barrier_market": True,
    }


def test_valid_btc_question_parses_ok():
    calls = {"n": 0}
    def extract(q):
        calls["n"] += 1
        return _extract_btc_up(q)
    parsed = parse_question(
        "0xM1", "Will Bitcoin reach $80,000 by June 30, 2026?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
    )
    assert parsed.status == "ok"
    assert parsed.symbol == "BTCUSDT"
    assert parsed.barrier == 80000.0
    assert parsed.direction == "up"
    assert parsed.resolution_ts == 1782777600  # 2026-06-30T00:00:00Z


def test_hallucinated_barrier_rejected():
    def extract(_q):
        d = _extract_btc_up(_q); d["barrier_usd"] = 8000.0  # implausible vs 40k-110k
        return d
    parsed = parse_question(
        "0xM2", "Will Bitcoin reach $80,000 by June 30, 2026?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
    )
    assert parsed.status == "implausible_barrier"


def test_low_confidence_rejected():
    def extract(_q):
        d = _extract_btc_up(_q); d["confidence"] = 0.5
        return d
    parsed = parse_question(
        "0xM3", "Will Bitcoin maybe do something?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
    )
    assert parsed.status == "low_confidence"


def test_non_crypto_rejected():
    def extract(_q):
        return {"is_crypto_barrier_market": False, "confidence": 0.99}
    parsed = parse_question(
        "0xM4", "Will the Lakers win the title?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=None,
    )
    assert parsed.status == "not_crypto_barrier"


def test_cache_hit_does_not_recall_llm():
    calls = {"n": 0}
    def extract(q):
        calls["n"] += 1
        return _extract_btc_up(q)
    cache = _cache()
    parse_question("0xM5", "Will Bitcoin reach $80,000 by June 30, 2026?",
                   llm_extract=extract, cache=cache,
                   underlying_price_range=(40000.0, 110000.0))
    parse_question("0xM5", "Will Bitcoin reach $80,000 by June 30, 2026?",
                   llm_extract=extract, cache=cache,
                   underlying_price_range=(40000.0, 110000.0))
    assert calls["n"] == 1  # second call served from cache


def test_inconsistent_direction_rejected():
    # 'up' but barrier already below the bottom of the price range at open.
    def extract(_q):
        d = _extract_btc_up(_q); d["barrier_usd"] = 41000.0; d["direction"] = "down"
        return d
    # direction 'down' with barrier 41000 inside range is fine; make it inconsistent:
    def extract_bad(_q):
        d = _extract_btc_up(_q); d["barrier_usd"] = 105000.0; d["direction"] = "down"
        return d
    parsed = parse_question(
        "0xM6", "Will Bitcoin fall below $105,000?",
        llm_extract=extract_bad, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
        open_spot=50000.0,
    )
    # 'down' barrier 105000 is ABOVE open spot 50000 -> can't be a down-barrier
    assert parsed.status == "inconsistent_direction"
```

- [ ] **Step 4.2: Run; ImportError.**

- [ ] **Step 4.3: Implement `question_parser.py`**

```python
"""LLM-based extraction of (symbol, barrier, direction, resolution_date) from a
Polymarket crypto barrier-market question, with a validation layer and an
on-disk cache for reproducibility.

A parse that fails any validation check is EXCLUDED from the backtest (status
!= 'ok') and never guessed — the harness must not be poisoned by a hallucinated
barrier.
"""

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal


@dataclass(frozen=True)
class ParsedMarket:
    market_id: str
    status: Literal["ok", "low_confidence", "implausible_barrier",
                    "inconsistent_direction", "unparseable_date", "not_crypto_barrier"]
    symbol: str | None
    barrier: float | None
    direction: Literal["up", "down"] | None
    resolution_ts: int | None
    confidence: float
    reason: str


class ParseCache:
    """On-disk JSON cache keyed by market_id under cache_dir."""

    def __init__(self, cache_dir: str):
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, market_id: str) -> Path:
        safe = market_id.replace("/", "_")
        return self.dir / f"{safe}.json"

    def get(self, market_id: str) -> ParsedMarket | None:
        p = self._path(market_id)
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        return ParsedMarket(**data)

    def put(self, parsed: ParsedMarket) -> None:
        self._path(parsed.market_id).write_text(
            json.dumps(parsed.__dict__), encoding="utf-8"
        )


def _parse_iso(iso_str: str) -> int | None:
    try:
        s = iso_str[:-1] + "+00:00" if iso_str.endswith("Z") else iso_str
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


def validate_parse(
    market_id: str,
    raw: dict,
    *,
    underlying_price_range: tuple[float, float] | None,
    confidence_threshold: float,
    open_spot: float | None = None,
) -> ParsedMarket:
    conf = float(raw.get("confidence", 0.0))
    if not raw.get("is_crypto_barrier_market", False):
        return ParsedMarket(market_id, "not_crypto_barrier", None, None, None, None,
                            conf, "LLM flagged non-crypto-barrier")
    if conf < confidence_threshold:
        return ParsedMarket(market_id, "low_confidence", None, None, None, None,
                            conf, f"confidence {conf} < {confidence_threshold}")
    resolution_ts = _parse_iso(raw.get("resolution_date_iso", ""))
    if resolution_ts is None:
        return ParsedMarket(market_id, "unparseable_date", None, None, None, None,
                            conf, "resolution_date_iso unparseable")
    barrier = raw.get("barrier_usd")
    if barrier is None or not math.isfinite(barrier) or barrier <= 0:
        return ParsedMarket(market_id, "implausible_barrier", None, None, None, None,
                            conf, f"barrier {barrier} non-positive/non-finite")
    if underlying_price_range is not None:
        lo, hi = underlying_price_range
        if not (0.1 * lo <= barrier <= 10.0 * hi):
            return ParsedMarket(market_id, "implausible_barrier", None, None, None, None,
                                conf, f"barrier {barrier} outside plausible range")
    direction = raw.get("direction")
    if direction not in ("up", "down"):
        return ParsedMarket(market_id, "implausible_barrier", None, None, None, None,
                            conf, f"direction {direction} invalid")
    if open_spot is not None:
        if direction == "up" and barrier <= open_spot:
            return ParsedMarket(market_id, "inconsistent_direction", None, None, None, None,
                                conf, "up-barrier at/below open spot")
        if direction == "down" and barrier >= open_spot:
            return ParsedMarket(market_id, "inconsistent_direction", None, None, None, None,
                                conf, "down-barrier at/above open spot")
    return ParsedMarket(market_id, "ok", raw["symbol"], float(barrier), direction,
                        resolution_ts, conf, "")


def parse_question(
    market_id: str,
    question: str,
    *,
    llm_extract: Callable[[str], dict],
    cache: ParseCache,
    underlying_price_range: tuple[float, float] | None,
    confidence_threshold: float = 0.85,
    open_spot: float | None = None,
) -> ParsedMarket:
    cached = cache.get(market_id)
    if cached is not None:
        return cached
    raw = llm_extract(question)
    parsed = validate_parse(
        market_id, raw,
        underlying_price_range=underlying_price_range,
        confidence_threshold=confidence_threshold,
        open_spot=open_spot,
    )
    cache.put(parsed)
    return parsed
```

NB on the cache + validation interaction: the barrier-plausibility check uses
`underlying_price_range`, which is only known after OHLCV ingestion. The
orchestrator (Task 7) runs parsing in two passes — pass 1 with
`underlying_price_range=None` (catches non-crypto/low-confidence/bad-date),
pass 2 after OHLCV with the real range (catches implausible barriers). Because
the cache stores the final `ParsedMarket`, the orchestrator should pass
`open_spot`/range on the FIRST call per market that has the data, or use a
`--refresh` to re-validate. For C3a simplicity: parse pass-1 markets are
re-parsed in pass-2 with `cache` bypassed for the re-validation (the
orchestrator manages this; the cache is for cross-RUN reproducibility, not
within-run passes).

- [ ] **Step 4.4: Run; expect 6 PASS.**

- [ ] **Step 4.5: Commit**

```
git add agent/research/crypto/question_parser.py tests/research/crypto/test_question_parser.py
git commit -m "feat(polymarket-c3a): add LLM question parser with validation layer + reproducible cache"
```

---

## Task 5: `polymarket_enumerate.py`

**Files:** Create `agent/data/polymarket_enumerate.py`, `tests/data/test_polymarket_enumerate.py`.

- [ ] **Step 5.1: Inspect Phase 0's `PolymarketClient`** (read `agent/data/` for the existing client, its base URL, and how MarketDTO is built) so the enumerator reuses the established httpx + TokenBucket + DTO pattern.

- [ ] **Step 5.2: Write failing test (respx-mocked Gamma response)**

```python
import httpx
import pytest
import respx

from agent.data.polymarket_enumerate import enumerate_resolved_crypto_markets


@pytest.mark.asyncio
@respx.mock
async def test_enumerate_filters_resolved_crypto_and_paginates():
    # Page 1: 2 markets (1 crypto resolved, 1 non-crypto); Page 2: 1 crypto resolved; Page 3 empty.
    # Assert: only the 2 crypto resolved markets returned; pagination followed.
    ...  # implementer fills mocked routes per the real Gamma pagination shape
```

NB: the exact Gamma response shape and pagination (offset/limit vs cursor) must
be confirmed against Phase 0's existing client and the live API contract. The
implementer inspects `PolymarketClient` and mirrors its request style.

- [ ] **Step 5.3: Implement `enumerate_resolved_crypto_markets`** per spec §4.1 — paginated Gamma query filtered to `closed=true` + crypto category/tag, returning `list[MarketDTO]`, no outcome filtering.

- [ ] **Step 5.4: Run; expect PASS.**

- [ ] **Step 5.5: Commit**

```
git add agent/data/polymarket_enumerate.py tests/data/test_polymarket_enumerate.py
git commit -m "feat(polymarket-c3a): enumerate resolved crypto markets via Gamma API (exhaustive)"
```

---

## Task 6: `polymarket_history.py`

**Files:** Create `agent/data/polymarket_history.py`, `tests/data/test_polymarket_history.py`.

- [ ] **Step 6.1: Write failing test (respx-mocked CLOB prices-history + idempotency)**

```python
import pytest
import respx

# Mock CLOB /prices-history -> a series of {t, p} points.
# Assert: parsed into PriceSnapshot rows; idempotent re-call inserts 0.
```

- [ ] **Step 6.2: Implement `ingest_market_price_history`** per spec §4.3 — fetch YES-token price history from CLOB `/prices-history`, persist as `PriceSnapshot` (skip-existing dedup by (market_id, token_id, ts)), return count inserted.

- [ ] **Step 6.3: Run; expect PASS.**

- [ ] **Step 6.4: Commit**

```
git add agent/data/polymarket_history.py tests/data/test_polymarket_history.py
git commit -m "feat(polymarket-c3a): ingest resolved-market price history via CLOB prices-history"
```

---

## Task 7: `crypto_backtest.py` (orchestrator + verdict)

**Files:** Create `agent/validation/crypto_backtest.py`, `tests/validation/test_crypto_backtest.py`.

- [ ] **Step 7.1: Write the end-to-end synthetic test (spec §7.5)**

Construct 3 synthetic resolved markets (one where the model clearly beats
baseline, one where it doesn't, one borderline) with seeded CryptoBars +
PriceSnapshots + resolutions + pre-populated parse cache. Run the orchestrator.
Assert: coverage counts correct; `brier_skill_score` matches an INDEPENDENT
recomputation (non-circular, mirroring the C2-A blender test); all 4 cost
scenarios present in `by_cost`; verdict matches the constructed scenario.

```python
# Full setup per spec §7.5. Key assertions:
#   report.coverage["actually_tested"] == 3
#   independently-recomputed brier_skill_score == report.brier_skill_score (within 1e-9)
#   set(report.by_cost.keys()) == {0.0, 0.01, 0.02, 0.03}
#   report.verdict in {"CONTINUE","STOP","INCONCLUSIVE"} matching the scenario
```

- [ ] **Step 7.2: Implement `crypto_backtest.py`** — `ValidationReport` dataclass (spec §5.4, including `brier_skill_ci`), the orchestrator that:
  1. runs `walk_forward_backtest` with `crypto_model` (partial-applied) and with `market_price_model`,
  2. builds (p_hat, outcome) pairs for both,
  3. computes `brier_score` (reuse), `brier_skill_score`, `bootstrap_skill_ci`, `reliability_curve`, `kupiec_test`,
  4. for each cost in {0.0, 0.01, 0.02, 0.03}: `simulate_pnl` → `sharpe_ratio`/`sortino_ratio`/`max_drawdown`/`win_rate`/`profit_factor`,
  5. assembles per-market + per-mode breakdowns (per-mode from CryptoPrediction.diagnostics weights),
  6. computes the verdict per spec §6 (pre-committed thresholds, incl. CI lower bound > 0).

- [ ] **Step 7.3: Run; expect PASS.**

- [ ] **Step 7.4: Commit**

```
git add agent/validation/crypto_backtest.py tests/validation/test_crypto_backtest.py
git commit -m "feat(polymarket-c3a): add validation orchestrator + pre-committed CONTINUE/STOP/INCONCLUSIVE verdict"
```

---

## Task 8: `run_crypto_validation.py` (CLI) + full-pipeline gate

**Files:** Create `agent/scripts/run_crypto_validation.py`, `tests/validation/test_c3a_cli_smoke.py`.

- [ ] **Step 8.1: Implement the CLI** — argparse entry with `--window-start`, `--window-end`, `--db`, `--output`, `--refresh`. Wires: enumerate → parse (pass 1) → ingest Polymarket history → ingest Binance OHLCV (C1 `CryptoIngestService`) → parse (pass 2, barrier validation) → build resolutions → orchestrator → write JSON report + human-readable summary (print verdict prominently).

- [ ] **Step 8.2: Write a CLI smoke test** that runs the CLI's main against an in-memory DB pre-seeded with the synthetic 3-market set (mock the network clients), and asserts a report JSON is written with a verdict field. (Network calls are mocked; this is a wiring smoke test, not a live run.)

- [ ] **Step 8.3: Run full suite**

```
.venv/Scripts/python.exe -m pytest -q
```
Expected: 187 prior + ~27 C3a tests, all green.

- [ ] **Step 8.4: Commit**

```
git add agent/scripts/run_crypto_validation.py tests/validation/test_c3a_cli_smoke.py
git commit -m "feat(polymarket-c3a): CLI entry + full-pipeline smoke gate — C3a harness complete"
```

---

## C3a complete

The harness can produce the CONTINUE/STOP/INCONCLUSIVE verdict reproducibly.
The actual verdict on real markets is then a matter of RUNNING the CLI against
a live-data-populated DB (a one-time data-prep run, outside the test suite,
which makes real Gamma/CLOB/Binance calls and real LLM extraction). That run
is the answer to "is the alpha thesis true?" — and gates whether C2-B (news)
is worth building.

**Note on the live run:** it makes real API calls (Polymarket Gamma + CLOB,
Binance klines, OpenAI extraction). The operator runs it once; the parse cache
makes re-runs deterministic. Budget: hundreds of cheap LLM calls; Binance +
Polymarket are free public endpoints.

---

## Self-Review

(Run after drafting per writing-plans.)

1. **Spec coverage:** every spec §-component maps to a task — risk_metrics (T1), baseline (T2), pnl (T3), question_parser (T4), enumerate (T5), history (T6), orchestrator+verdict (T7), CLI+gate (T8). bootstrap_skill_ci (spec §5.3, core scope) → T1. Verdict (§6) → T7. Coverage counts (§4.6) → T7.
2. **Placeholder scan:** T5.2 and T6.1 test bodies are described rather than fully coded because they depend on the live Gamma/CLOB response shapes, which must be confirmed against Phase 0's `PolymarketClient` and the API contract at implementation time — flagged explicitly as implementer-inspects steps, not silent gaps.
3. **Type consistency:** `Trade`/`EquityCurve` (T3) used by risk_metrics helpers (T1) — `_trade_pnl`/`_trade_is_win` reference `Trade` fields defined in T3; T1's win_rate/profit_factor tests deferred until T3 defines `Trade` (called out in Step 1.4). `CryptoPrediction` (from C2-A) used in T3 tests + T7 — fields `market_id`, `ts`, `p_hat`, `position_size`, `diagnostics` confirmed against C2-A's model.py.
4. **Known open items:** the live Gamma/CLOB response shapes (T5/T6) are the main implementation-time unknowns; the implementer inspects Phase 0's client first. The two-pass parse/cache interaction (T4 NB) needs the orchestrator to manage within-run re-validation — documented in T4 and T7.

