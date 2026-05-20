# Polymarket Agent — Phase 1A: L7 Validation Gate Infrastructure — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the L7 validation gate infrastructure — walk-forward backtest, Kupiec/Brier/reliability metrics, paper-trade-live engine, market-resolution poller, two baseline "models", and a stub L4 threshold strategy — so future L3 modules can be evaluated against the design spec's "walk-forward + green Kupiec on backtest" criterion.

**Architecture:** Pure-functional metrics (`kupiec_test`, `brier_score`, `reliability_curve`) shared between two data paths (backtest replay over Phase 0 history, paper-trade-live polling against live Polymarket). Only `PaperTradeEngine` and `ResolutionPoller` carry state; everything else is stateless. Predictions follow a minimal-but-expandable `Prediction(market_id, ts, p_hat)` contract — a strict subset of the future `FairValueEstimate`.

**Tech Stack:** Python 3.13, `httpx`, `pydantic` v2, `SQLAlchemy` 2.0, `pytest`, `pytest-asyncio`, `respx`, **`scipy` (new)** for `chi2.sf` (the only new dep vs Phase 0).

**Plan context:** This is **Plan 2 of 5+**. It corresponds to Phase 1A of the parent design (`docs/superpowers/specs/2026-05-19-polymarket-fair-value-agent-design.md`) and is detailed in `docs/superpowers/specs/2026-05-20-polymarket-phase-1a-l7-validation-gate-design.md`. Its completion gate — the algorithmic gate in §5 of the Phase 1A spec — is verified by Tasks 2, 3, 4, 6, 7, 8, 10. Phase 1B+ (first real L3 module) is the next plan.

---

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | Add `scipy>=1.13` to core dependencies |
| `agent/validation/types.py` | Phase 1A dataclasses: `Prediction`, `ResolvedOutcome`, `PriceTick`, `TradeSignal`, `PaperFill`, `KupiecResult`, `BacktestResult`, `PaperTradeResult` |
| `agent/validation/metrics.py` | `kupiec_test`, `brier_score`, `reliability_curve` (pure functions) |
| `agent/validation/backtest.py` | EXISTING — extend with `walk_forward_backtest` function |
| `agent/validation/paper_trade.py` | `PaperTradeEngine` (the only stateful class) |
| `agent/validation/resolution_poller.py` | `ResolutionPoller` (async polling, yields `PriceTick \| ResolvedOutcome`) |
| `agent/data/models.py` | EXISTING — extend `MarketDTO` with `outcome_prices` field |
| `agent/data/polymarket_client.py` | EXISTING — add `get_market(market_id)` method |
| `agent/research/__init__.py` | Empty package marker |
| `agent/research/baselines.py` | `last_traded_price`, `constant_half` |
| `agent/strategy/__init__.py` | Empty package marker |
| `agent/strategy/threshold.py` | `threshold_strategy` (stub L4) |
| `agent/cli.py` | Minimal CLI: `backtest`, `paper-trade` subcommands |
| `tests/validation/test_metrics.py` | Hand-computed Kupiec + Brier + reliability reference cases — **the algorithmic gate** |
| `tests/validation/test_backtest.py` | EXISTING — extend with `walk_forward_backtest` integration test |
| `tests/validation/test_paper_trade.py` | `PaperTradeEngine` deterministic test |
| `tests/validation/test_resolution_poller.py` | respx-mocked resolution poller test |
| `tests/data/test_models.py` | EXISTING — add `outcome_prices` regression test |
| `tests/data/test_polymarket_client.py` | EXISTING — add `get_market` test |
| `tests/research/__init__.py` | Empty package marker |
| `tests/research/test_baselines.py` | Baseline-model correctness |
| `tests/strategy/__init__.py` | Empty package marker |
| `tests/strategy/test_threshold.py` | Stub L4 threshold-rule correctness |
| `tests/test_cli_smoke.py` | CLI subcommand smoke test |

---

### Task 1: Project Scaffold Additions — scipy dep, types module, package markers, smoke test

**Files:**
- Modify: `pyproject.toml` (add scipy)
- Create: `agent/validation/types.py`
- Create: `agent/research/__init__.py`, `agent/strategy/__init__.py`
- Create: `tests/research/__init__.py`, `tests/strategy/__init__.py`
- Create: `tests/validation/test_types.py`

- [ ] **Step 1: Write the failing smoke test**

Create `tests/validation/test_types.py`:

```python
from agent.validation.types import (
    BacktestResult,
    KupiecResult,
    PaperFill,
    PaperTradeResult,
    PriceTick,
    Prediction,
    ResolvedOutcome,
    TradeSignal,
)


def test_all_phase_1a_types_importable():
    """Smoke test: every Phase 1A type is importable from agent.validation.types."""
    assert Prediction.__name__ == "Prediction"
    assert ResolvedOutcome.__name__ == "ResolvedOutcome"
    assert PriceTick.__name__ == "PriceTick"
    assert TradeSignal.__name__ == "TradeSignal"
    assert PaperFill.__name__ == "PaperFill"
    assert KupiecResult.__name__ == "KupiecResult"
    assert BacktestResult.__name__ == "BacktestResult"
    assert PaperTradeResult.__name__ == "PaperTradeResult"


def test_prediction_is_frozen():
    p = Prediction(market_id="m1", ts=1, p_hat=0.5)
    raised = False
    try:
        p.p_hat = 0.6  # type: ignore[misc]
    except Exception:
        raised = True
    assert raised is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/validation/test_types.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.validation.types'`.

- [ ] **Step 3: Add scipy to pyproject.toml**

Modify `pyproject.toml` `[project]` dependencies block. Find:

```toml
dependencies = [
    "httpx>=0.27",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "sqlalchemy>=2.0",
]
```

Replace with:

```toml
dependencies = [
    "httpx>=0.27",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "scipy>=1.13",
    "sqlalchemy>=2.0",
]
```

Install: from the project dir with venv activated, run `pip install -e ".[dev]"`. Expected: scipy installs successfully (≈100 MB; this is the only large dep).

- [ ] **Step 4: Create the empty package markers**

Create empty files:
- `agent/research/__init__.py`
- `agent/strategy/__init__.py`
- `tests/research/__init__.py`
- `tests/strategy/__init__.py`

- [ ] **Step 5: Create `agent/validation/types.py`**

```python
"""Phase 1A dataclasses for the L7 validation gate.

All types are frozen for hashability and immutability, matching Phase 0's
ReplayEvent convention.
"""

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class Prediction:
    """A model's estimate of P(market resolves YES) at a given time.

    Minimal subset of the spec's future FairValueEstimate.  L3 modules in
    Phase 1B+ may subclass to add confidence/CI/rationale/sources without
    breaking L7.
    """

    market_id: str
    ts: int  # unix seconds
    p_hat: float  # estimated P(YES) in [0, 1]


@dataclass(frozen=True)
class ResolvedOutcome:
    """The ground truth for a resolved market.  Phase 1A handles binary
    outcomes only."""

    market_id: str
    outcome: Literal[0, 1]  # 1 = YES, 0 = NO
    resolved_ts: int


@dataclass(frozen=True)
class PriceTick:
    """A live price observation for a market's YES token.  Emitted by
    ResolutionPoller between resolution checks."""

    market_id: str
    ts: int
    market_price: float  # YES token price in [0, 1]


@dataclass(frozen=True)
class TradeSignal:
    """A trading-rule decision to take a hypothetical paper position."""

    market_id: str
    ts: int
    side: Literal["YES", "NO"]
    target_price: float
    edge: float
    rationale: str


@dataclass(frozen=True)
class PaperFill:
    """A hypothetical fill recorded by PaperTradeEngine."""

    market_id: str
    ts: int
    side: Literal["YES", "NO"]
    price: float  # signal.target_price + slippage (0 in Phase 1A)
    size: float  # position size in SHARES (max payoff = size * $1)


@dataclass(frozen=True)
class KupiecResult:
    """Output of the Kupiec unconditional-coverage test."""

    exceptions: int
    trials: int
    expected_rate: float
    lr_statistic: float
    p_value: float
    zone: Literal["GREEN", "ORANGE", "RED"]


@dataclass(frozen=True)
class BacktestResult:
    """Output of walk_forward_backtest()."""

    model_name: str
    n_predictions: int
    n_resolved: int
    brier_score: float
    reliability_curve: list[tuple[float, float] | tuple[None, None]] = field(
        default_factory=list
    )
    kupiec: KupiecResult | None = None
    window_start_ts: int = 0
    window_end_ts: int = 0


@dataclass(frozen=True)
class PaperTradeResult:
    """Summary of a paper-trade-live session."""

    model_name: str
    started_ts: int
    ended_ts: int
    n_fills: int
    n_resolved: int
    paper_pnl: float
    backtest_metrics: BacktestResult
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `pytest tests/validation/test_types.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 7: Run full suite to confirm nothing regressed**

Run: `pytest -v`
Expected: PASS — 28 passed (26 prior Phase 0 + 2 new).

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml agent/validation/types.py agent/research/__init__.py agent/strategy/__init__.py tests/research/__init__.py tests/strategy/__init__.py tests/validation/test_types.py
git commit -m "chore(phase1a): add scipy dep, validation types, package markers"
```

---

### Task 2: kupiec_test in metrics.py — THE ALGORITHMIC GATE

**Files:**
- Create: `agent/validation/metrics.py`
- Create: `tests/validation/test_metrics.py`

- [ ] **Step 1: Write the failing test**

Create `tests/validation/test_metrics.py`:

```python
import math

import pytest

from agent.validation.metrics import kupiec_test
from agent.validation.types import KupiecResult


def test_kupiec_zero_exceptions():
    """§5.1 Case 1: x=0, n=100, p=0.05 → LR ≈ 10.2587, p ≈ 0.00136, GREEN."""
    result = kupiec_test(exceptions=0, trials=100, expected_rate=0.05)

    assert isinstance(result, KupiecResult)
    assert result.exceptions == 0
    assert result.trials == 100
    assert result.expected_rate == 0.05
    assert math.isclose(result.lr_statistic, 10.2587, abs_tol=1e-3)
    assert math.isclose(result.p_value, 0.00136, rel_tol=1e-3)
    assert result.zone == "GREEN"


def test_kupiec_seven_exceptions():
    """§5.1 Case 2: x=7, n=100, p=0.05 → LR ≈ 0.7530, p ≈ 0.3855, ORANGE."""
    result = kupiec_test(exceptions=7, trials=100, expected_rate=0.05)

    assert math.isclose(result.lr_statistic, 0.7530, abs_tol=1e-3)
    assert math.isclose(result.p_value, 0.3855, rel_tol=1e-3)
    assert result.zone == "ORANGE"


def test_kupiec_fifteen_exceptions():
    """§5.1 Case 3: x=15, n=100, p=0.05 → LR ≈ 14.0500, p ≈ 0.000178, RED."""
    result = kupiec_test(exceptions=15, trials=100, expected_rate=0.05)

    assert math.isclose(result.lr_statistic, 14.0500, abs_tol=1e-3)
    assert math.isclose(result.p_value, 0.000178, rel_tol=1e-2)
    assert result.zone == "RED"


def test_kupiec_zone_boundaries():
    """Zone thresholds: green ≤ 4, orange 5-9, red ≥ 10 (defaults)."""
    assert kupiec_test(exceptions=4, trials=100, expected_rate=0.05).zone == "GREEN"
    assert kupiec_test(exceptions=5, trials=100, expected_rate=0.05).zone == "ORANGE"
    assert kupiec_test(exceptions=9, trials=100, expected_rate=0.05).zone == "ORANGE"
    assert kupiec_test(exceptions=10, trials=100, expected_rate=0.05).zone == "RED"


def test_kupiec_invalid_inputs():
    """Validation: trials must be positive, expected_rate in (0,1), exceptions in [0,trials]."""
    with pytest.raises(ValueError):
        kupiec_test(exceptions=0, trials=0, expected_rate=0.05)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=0, trials=100, expected_rate=0.0)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=0, trials=100, expected_rate=1.0)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=-1, trials=100, expected_rate=0.05)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=101, trials=100, expected_rate=0.05)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/validation/test_metrics.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.validation.metrics'`.

- [ ] **Step 3: Write the implementation**

Create `agent/validation/metrics.py`:

```python
"""Phase 1A metrics: stateless functions for L7 validation.

All three functions are pure: same input → same output, no side effects.
The Kupiec test uses math.erfc (equivalent to scipy.stats.chi2.sf(LR, 1))
to avoid pulling scipy into hot paths; for non-trivial chi^2 computations
elsewhere, prefer scipy.stats.chi2.
"""

import math
from collections.abc import Iterable
from typing import Literal

from agent.validation.types import KupiecResult


def _xlogy(x: float, y: float) -> float:
    """0 * log(0) = 0 convention; otherwise x * log(y).  Used in Kupiec
    formula to handle the x=0 and x=n edge cases without log(0)."""
    if x == 0:
        return 0.0
    return x * math.log(y)


def kupiec_test(
    exceptions: int,
    trials: int,
    expected_rate: float,
    *,
    green_max: int = 4,
    orange_max: int = 9,
) -> KupiecResult:
    """Kupiec's unconditional-coverage LR test.

    H0: observed exception rate equals expected_rate.
    LR_uc = -2 * [x*ln(p) + (n-x)*ln(1-p) - x*ln(x/n) - (n-x)*ln((n-x)/n)]
    Under H0, LR_uc ~ chi^2(1).  p_value = chi2.sf(LR, 1) = erfc(sqrt(LR/2)).

    Zone is classified by raw exception count:
      exceptions <= green_max:           GREEN
      green_max < exceptions <= orange_max: ORANGE
      exceptions > orange_max:           RED
    """
    if trials <= 0:
        raise ValueError(f"trials must be positive, got {trials}")
    if not (0 < expected_rate < 1):
        raise ValueError(f"expected_rate must be in (0, 1), got {expected_rate}")
    if not (0 <= exceptions <= trials):
        raise ValueError(
            f"exceptions must be in [0, {trials}], got {exceptions}"
        )

    x = exceptions
    n = trials
    p = expected_rate
    p_hat = x / n

    lr = -2 * (
        _xlogy(x, p)
        + _xlogy(n - x, 1 - p)
        - _xlogy(x, p_hat)
        - _xlogy(n - x, 1 - p_hat)
    )
    p_value = math.erfc(math.sqrt(lr / 2))

    zone: Literal["GREEN", "ORANGE", "RED"]
    if exceptions <= green_max:
        zone = "GREEN"
    elif exceptions <= orange_max:
        zone = "ORANGE"
    else:
        zone = "RED"

    return KupiecResult(
        exceptions=exceptions,
        trials=trials,
        expected_rate=expected_rate,
        lr_statistic=lr,
        p_value=p_value,
        zone=zone,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/validation/test_metrics.py -v`
Expected: PASS — 5 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 33 passed (28 prior + 5 new).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/metrics.py tests/validation/test_metrics.py
git commit -m "feat(phase1a): add kupiec_test (Phase 1A algorithmic gate, Case 1/2/3)"
```

---

### Task 3: brier_score in metrics.py

**Files:**
- Modify: `agent/validation/metrics.py`
- Modify: `tests/validation/test_metrics.py`

- [ ] **Step 1: Write the failing test** — append to `tests/validation/test_metrics.py`:

```python
from agent.validation.metrics import brier_score


def test_brier_perfect_miss():
    """§5.2 Case 1: pred=[0.0], outcome=[1] → Brier = 1.0 (worst case)."""
    assert brier_score([(0.0, 1)]) == 1.0


def test_brier_constant_half():
    """§5.2 Case 2: pred=[0.5]*3, outcome=[0,0,1] → Brier = 0.25."""
    assert math.isclose(
        brier_score([(0.5, 0), (0.5, 0), (0.5, 1)]),
        0.25,
        abs_tol=1e-10,
    )


def test_brier_mixed_calibration():
    """§5.2 Case 3: pred=[0.1,0.9,0.6], outcome=[0,1,1] → Brier = 0.06."""
    assert math.isclose(
        brier_score([(0.1, 0), (0.9, 1), (0.6, 1)]),
        0.06,
        abs_tol=1e-10,
    )


def test_brier_empty_raises():
    """§5.2 Case 4: empty input raises ValueError."""
    with pytest.raises(ValueError):
        brier_score([])
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/validation/test_metrics.py -v -k brier`
Expected: FAIL — `ImportError: cannot import name 'brier_score' from 'agent.validation.metrics'`.

- [ ] **Step 3: Write the implementation** — append to `agent/validation/metrics.py`:

```python
def brier_score(pairs: Iterable[tuple[float, int]]) -> float:
    """Mean squared error: sum((p_hat - outcome)^2) / n.

    Outcomes must be 0 or 1.  Raises ValueError on empty input.
    """
    pairs_list = list(pairs)
    if not pairs_list:
        raise ValueError("brier_score requires at least one (p_hat, outcome) pair")
    sse = sum((p - o) ** 2 for p, o in pairs_list)
    return sse / len(pairs_list)
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `pytest tests/validation/test_metrics.py -v -k brier`
Expected: PASS — 4 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 37 passed (33 prior + 4 new).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/metrics.py tests/validation/test_metrics.py
git commit -m "feat(phase1a): add brier_score metric"
```

---

### Task 4: reliability_curve in metrics.py

**Files:**
- Modify: `agent/validation/metrics.py`
- Modify: `tests/validation/test_metrics.py`

- [ ] **Step 1: Write the failing tests** — append to `tests/validation/test_metrics.py`:

```python
from agent.validation.metrics import reliability_curve


def test_reliability_curve_calibrated_200():
    """§5.3 main case: 200 predictions evenly across [0,1] (20 per decile bin)
    with synthetic outcomes engineered so predicted bin midpoint == observed
    yes-frequency.  All bins non-None and match midpoints exactly.

    Why 20 per bin (not 10): for any decile midpoint m, n_yes = m*20 is an
    integer (1, 3, 5, ..., 19) so obs_freq = n_yes/20 = m exactly.  A 10-per-bin
    construction would give n_yes = m*10 which is fractional for every decile
    midpoint and cannot match m as an obs_freq."""
    # 200 predictions: 20 per decile bin
    pairs: list[tuple[float, int]] = []
    for bin_idx in range(10):
        midpoint = (bin_idx + 0.5) / 10  # 0.05, 0.15, ..., 0.95
        n_yes = round(midpoint * 20)  # 1, 3, 5, ..., 19 — always integer
        for i in range(20):
            outcome = 1 if i < n_yes else 0
            pairs.append((midpoint, outcome))

    curve = reliability_curve(pairs)

    assert len(curve) == 10
    for bin_idx, (mean_p, obs_freq) in enumerate(curve):
        expected_mid = (bin_idx + 0.5) / 10
        assert mean_p is not None
        assert obs_freq is not None
        assert math.isclose(mean_p, expected_mid, abs_tol=1e-10)
        assert math.isclose(obs_freq, expected_mid, abs_tol=1e-10)


def test_reliability_curve_too_few_per_bin():
    """§5.3 edge case: 25 predictions spread across 10 bins → <5/bin → all (None, None)."""
    pairs = [(i / 25, i % 2) for i in range(25)]

    curve = reliability_curve(pairs)

    assert len(curve) == 10
    assert all(mean_p is None and obs_freq is None for mean_p, obs_freq in curve)


def test_reliability_curve_top_bin_includes_one():
    """Predictions equal to 1.0 fall in the last bin, not out of range."""
    pairs = [(1.0, 1)] * 5
    curve = reliability_curve(pairs)
    # Bin 9 (the [0.9, 1.0] bin) should have all 5 observations
    assert curve[9] == (1.0, 1.0)


def test_reliability_curve_invalid_p_hat():
    """p_hat outside [0,1] raises ValueError."""
    with pytest.raises(ValueError):
        reliability_curve([(1.5, 1)])
    with pytest.raises(ValueError):
        reliability_curve([(-0.1, 0)])


def test_reliability_curve_invalid_n_bins():
    """n_bins must be >= 1."""
    with pytest.raises(ValueError):
        reliability_curve([(0.5, 1)], n_bins=0)
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/validation/test_metrics.py -v -k reliability`
Expected: FAIL — `ImportError: cannot import name 'reliability_curve'`.

- [ ] **Step 3: Write the implementation** — append to `agent/validation/metrics.py`:

```python
def reliability_curve(
    pairs: Iterable[tuple[float, int]],
    *,
    n_bins: int = 10,
    min_per_bin: int = 5,
) -> list[tuple[float, float] | tuple[None, None]]:
    """Bin predictions into n_bins evenly-spaced intervals over [0, 1].

    Per bin: (mean_predicted_p, observed_yes_frequency).
    Bins with fewer than min_per_bin observations report (None, None).
    """
    if n_bins < 1:
        raise ValueError(f"n_bins must be >= 1, got {n_bins}")

    bin_predictions: list[list[float]] = [[] for _ in range(n_bins)]
    bin_outcomes: list[list[int]] = [[] for _ in range(n_bins)]

    for p_hat, outcome in pairs:
        if not (0.0 <= p_hat <= 1.0):
            raise ValueError(f"p_hat must be in [0, 1], got {p_hat}")
        # Bin index: floor(p_hat * n_bins), clamped so p_hat=1.0 lands in last bin
        idx = min(int(p_hat * n_bins), n_bins - 1)
        bin_predictions[idx].append(p_hat)
        bin_outcomes[idx].append(outcome)

    result: list[tuple[float, float] | tuple[None, None]] = []
    for preds, outs in zip(bin_predictions, bin_outcomes):
        if len(preds) < min_per_bin:
            result.append((None, None))
        else:
            mean_p = sum(preds) / len(preds)
            obs_freq = sum(outs) / len(outs)
            result.append((mean_p, obs_freq))
    return result
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `pytest tests/validation/test_metrics.py -v -k reliability`
Expected: PASS — 5 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 42 passed (37 prior + 5 new).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/metrics.py tests/validation/test_metrics.py
git commit -m "feat(phase1a): add reliability_curve metric"
```

---

### Task 5: Baseline Models — last_traded_price + constant_half

**Files:**
- Create: `agent/research/baselines.py`
- Create: `tests/research/test_baselines.py`

- [ ] **Step 1: Write the failing test**

Create `tests/research/test_baselines.py`:

```python
from agent.research.baselines import constant_half, last_traded_price
from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def _event(market_id: str = "m1", token_id: str = "t1", ts: int = 1000,
           price: float = 0.42) -> ReplayEvent:
    return ReplayEvent(ts=ts, token_id=token_id, price=price)


def test_last_traded_price_returns_market_price():
    """Predicts p_hat = current YES-token price."""
    event = _event(price=0.62)
    pred = last_traded_price(event)
    assert isinstance(pred, Prediction)
    assert pred.market_id == "m1"
    assert pred.ts == 1000
    assert pred.p_hat == 0.62


def test_last_traded_price_handles_extremes():
    """p_hat=0 and p_hat=1 are both valid baseline outputs."""
    assert last_traded_price(_event(price=0.0)).p_hat == 0.0
    assert last_traded_price(_event(price=1.0)).p_hat == 1.0


def test_constant_half_always_returns_one_half():
    """Predicts p_hat = 0.5 regardless of input."""
    pred1 = constant_half(_event(price=0.1))
    pred2 = constant_half(_event(price=0.9))
    pred3 = constant_half(_event(price=0.5))
    assert pred1.p_hat == 0.5
    assert pred2.p_hat == 0.5
    assert pred3.p_hat == 0.5
```

Note: `ReplayEvent` from Phase 0 has fields `(ts, token_id, price)` — NO `market_id` directly. The baseline functions need a `market_id` source. Two options: (a) include market_id in `ReplayEvent` (breaking Phase 0 change) or (b) pass it as a separate argument. Phase 1A goes with option (b): the walk-forward loop knows the current market_id and passes it.

Update the test signature accordingly — see implementation below.

- [ ] **Step 2: Update the test to match the actual baseline signature**

Replace `tests/research/test_baselines.py` with:

```python
from agent.research.baselines import constant_half, last_traded_price
from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def _event(token_id: str = "t1", ts: int = 1000, price: float = 0.42) -> ReplayEvent:
    return ReplayEvent(ts=ts, token_id=token_id, price=price)


def test_last_traded_price_returns_market_price():
    """Predicts p_hat = current YES-token price."""
    event = _event(price=0.62)
    pred = last_traded_price("m1", event)
    assert isinstance(pred, Prediction)
    assert pred.market_id == "m1"
    assert pred.ts == 1000
    assert pred.p_hat == 0.62


def test_last_traded_price_handles_extremes():
    """p_hat=0 and p_hat=1 are both valid baseline outputs."""
    assert last_traded_price("m1", _event(price=0.0)).p_hat == 0.0
    assert last_traded_price("m1", _event(price=1.0)).p_hat == 1.0


def test_constant_half_always_returns_one_half():
    """Predicts p_hat = 0.5 regardless of input."""
    pred1 = constant_half("m1", _event(price=0.1))
    pred2 = constant_half("m2", _event(price=0.9))
    pred3 = constant_half("m3", _event(price=0.5))
    assert pred1.p_hat == 0.5
    assert pred1.market_id == "m1"
    assert pred2.market_id == "m2"
    assert pred3.market_id == "m3"
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `pytest tests/research/test_baselines.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.research.baselines'`.

- [ ] **Step 4: Write the implementation**

Create `agent/research/baselines.py`:

```python
"""Phase 1A baseline 'models' — stand-ins for real L3 modules.

These two functions exist to validate the L7 infrastructure: last_traded_price
should produce GREEN Kupiec on real Polymarket data by construction (markets
are martingales); constant_half should produce a recognizably worse result on
any market not genuinely 50/50.

Phase 1B+ replaces these with real per-category research modules.
"""

from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def last_traded_price(market_id: str, event: ReplayEvent) -> Prediction:
    """Martingale baseline: predict P(YES) = current YES-token price.

    Polymarket prices are martingales on [0, 1] that converge to 0 or 1 at
    resolution; therefore this baseline is calibrated by construction.
    """
    return Prediction(market_id=market_id, ts=event.ts, p_hat=event.price)


def constant_half(market_id: str, event: ReplayEvent) -> Prediction:
    """Calibration straw man: predict 0.5 for every market, every time.

    For any market NOT genuinely 50/50, this is miscalibrated.  Serves as
    L7's negative-control baseline.
    """
    return Prediction(market_id=market_id, ts=event.ts, p_hat=0.5)
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/research/test_baselines.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 6: Run full suite**

Run: `pytest -v`
Expected: PASS — 45 passed (42 prior + 3 new).

- [ ] **Step 7: Commit**

```bash
git add agent/research/baselines.py tests/research/test_baselines.py
git commit -m "feat(phase1a): add last_traded_price and constant_half baseline models"
```

---

### Task 6: walk_forward_backtest in backtest.py

**Files:**
- Modify: `agent/validation/backtest.py` (add `walk_forward_backtest` function)
- Modify: `tests/validation/test_backtest.py` (add integration test)

- [ ] **Step 1: Write the failing test** — append to `tests/validation/test_backtest.py`:

```python
import math

from agent.research.baselines import constant_half, last_traded_price
from agent.store.repository import save_price_history, upsert_market
from agent.validation.backtest import walk_forward_backtest
from agent.validation.types import BacktestResult, ResolvedOutcome
from agent.data.models import MarketDTO, PriceHistory, PricePoint


def _setup_three_markets(session) -> None:
    """3 markets × 5 price ticks each, with deterministic constant prices.

    m1: outcome=YES, all ticks at 0.8 → last_traded_price contribution = 5×(0.8-1)² = 0.20
    m2: outcome=NO,  all ticks at 0.2 → last_traded_price contribution = 5×(0.2-0)² = 0.20
    m3: outcome=YES, all ticks at 0.6 → last_traded_price contribution = 5×(0.6-1)² = 0.80
    Total last_traded_price Brier = (0.20 + 0.20 + 0.80) / 15 = 0.08

    constant_half contribution per tick = 0.25 → 15 × 0.25 / 15 = 0.25
    """
    market_specs = [
        ("m1", "tok-m1-yes", 0.8),
        ("m2", "tok-m2-yes", 0.2),
        ("m3", "tok-m3-yes", 0.6),
    ]
    for mid, tid, price in market_specs:
        upsert_market(
            session,
            MarketDTO(
                id=mid,
                question=f"Q for {mid}",
                clob_token_ids=[tid, f"{tid}-no"],
                enable_order_book=True,
            ),
        )
        save_price_history(
            session,
            mid,
            PriceHistory(
                token_id=tid,
                history=[
                    PricePoint(t=1700000000 + i * 3600, p=price) for i in range(5)
                ],
            ),
        )
    session.commit()


def _three_market_resolutions() -> dict[str, ResolvedOutcome]:
    return {
        "m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=1700020000),
        "m2": ResolvedOutcome(market_id="m2", outcome=0, resolved_ts=1700020000),
        "m3": ResolvedOutcome(market_id="m3", outcome=1, resolved_ts=1700020000),
    }


def test_walk_forward_backtest_constant_half_brier(session):
    """§5.4 constant-half case: 15 predictions of 0.5 → Brier = 0.25 exactly."""
    _setup_three_markets(session)
    resolutions = _three_market_resolutions()

    result = walk_forward_backtest(
        session, constant_half, resolutions, model_name="constant_half"
    )

    assert isinstance(result, BacktestResult)
    assert result.model_name == "constant_half"
    assert result.n_predictions == 15
    assert result.n_resolved == 15
    assert math.isclose(result.brier_score, 0.25, abs_tol=1e-10)
    assert result.kupiec is None  # n_resolved=15 < kupiec_window=100


def test_walk_forward_backtest_last_traded_price_brier(session):
    """§5.4 last-traded-price case: Brier = 0.08 with the synthetic data above."""
    _setup_three_markets(session)
    resolutions = _three_market_resolutions()

    result = walk_forward_backtest(
        session, last_traded_price, resolutions, model_name="last_traded_price"
    )

    assert result.n_predictions == 15
    assert result.n_resolved == 15
    assert math.isclose(result.brier_score, 0.08, abs_tol=1e-10)
    assert result.kupiec is None


def test_walk_forward_backtest_unresolved_markets_excluded(session):
    """Markets without resolutions still produce predictions but don't count toward
    n_resolved or Brier."""
    _setup_three_markets(session)
    # Resolutions for only 2 of 3 markets
    resolutions = {
        "m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=1700020000),
        "m2": ResolvedOutcome(market_id="m2", outcome=0, resolved_ts=1700020000),
    }

    result = walk_forward_backtest(
        session, constant_half, resolutions, model_name="constant_half"
    )

    assert result.n_predictions == 15  # all 3 markets generate predictions
    assert result.n_resolved == 10  # only 2 markets × 5 ticks counted toward metrics


def test_walk_forward_backtest_empty_store(session):
    """No markets stored → 0 predictions, 0 resolved, Brier=0 (degenerate)."""
    result = walk_forward_backtest(
        session, constant_half, resolutions={}, model_name="constant_half"
    )

    assert result.n_predictions == 0
    assert result.n_resolved == 0
    assert result.brier_score == 0.0
    assert result.kupiec is None
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/validation/test_backtest.py -v -k walk_forward`
Expected: FAIL — `ImportError: cannot import name 'walk_forward_backtest'`.

- [ ] **Step 3: Write the implementation** — append to `agent/validation/backtest.py`:

```python
from collections.abc import Callable

from sqlalchemy.orm import Session

from agent.store.schema import Market
from agent.validation.metrics import brier_score, kupiec_test, reliability_curve
from agent.validation.types import (
    BacktestResult,
    Prediction,
    ResolvedOutcome,
)


def walk_forward_backtest(
    session: Session,
    model: Callable[[str, ReplayEvent], Prediction],
    resolutions: dict[str, ResolvedOutcome],
    *,
    market_ids: list[str] | None = None,
    kupiec_window: int = 100,
    model_name: str = "unnamed",
) -> BacktestResult:
    """Walk-forward backtest over Phase 0's stored history.

    Iterates ReplayEngine events in strict ts order per market, calls `model`
    on each event to get a Prediction, then computes metrics over (p_hat,
    outcome) pairs for markets present in `resolutions`.

    The walk-forward property is enforced by ReplayEngine yielding ascending
    by ts and `model` being a function of one event (no peek-ahead).  Stateful
    models in future phases hold internal state across calls — the only
    contract is "do not query the future."
    """
    if market_ids is None:
        market_ids = [m.id for m in session.query(Market).all()]

    engine = ReplayEngine(session)
    predictions: list[Prediction] = []

    for market_id in market_ids:
        market = session.get(Market, market_id)
        if market is None or not market.clob_token_ids:
            continue
        yes_token_id = market.clob_token_ids[0]  # convention: index 0 = YES
        for event in engine.replay(market_id, yes_token_id):
            predictions.append(model(market_id, event))

    # Pair predictions with resolutions where available
    pred_outcome_pairs: list[tuple[float, int]] = [
        (pred.p_hat, resolutions[pred.market_id].outcome)
        for pred in predictions
        if pred.market_id in resolutions
    ]

    n_predictions = len(predictions)
    n_resolved = len(pred_outcome_pairs)

    if n_resolved == 0:
        brier = 0.0
        curve: list[tuple[float, float] | tuple[None, None]] = [
            (None, None)
        ] * 10
        kupiec = None
    else:
        brier = brier_score(pred_outcome_pairs)
        curve = reliability_curve(pred_outcome_pairs)
        if n_resolved >= kupiec_window:
            window_pairs = pred_outcome_pairs[-kupiec_window:]
            exceptions = sum(
                1
                for p_hat, outcome in window_pairs
                if (p_hat >= 0.5 and outcome == 0) or (p_hat < 0.5 and outcome == 1)
            )
            expected_rate = sum(
                min(p_hat, 1 - p_hat) for p_hat, _ in window_pairs
            ) / len(window_pairs)
            # Clamp expected_rate away from 0 and 1 (Kupiec requires p in (0,1))
            expected_rate = max(1e-9, min(1 - 1e-9, expected_rate))
            kupiec = kupiec_test(exceptions, len(window_pairs), expected_rate)
        else:
            kupiec = None

    timestamps = [p.ts for p in predictions]
    window_start = min(timestamps) if timestamps else 0
    window_end = max(timestamps) if timestamps else 0

    return BacktestResult(
        model_name=model_name,
        n_predictions=n_predictions,
        n_resolved=n_resolved,
        brier_score=brier,
        reliability_curve=curve,
        kupiec=kupiec,
        window_start_ts=window_start,
        window_end_ts=window_end,
    )
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `pytest tests/validation/test_backtest.py -v -k walk_forward`
Expected: PASS — 4 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 49 passed (45 prior + 4 new).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/backtest.py tests/validation/test_backtest.py
git commit -m "feat(phase1a): add walk_forward_backtest with Kupiec/Brier/reliability"
```

---

### Task 7: Stub L4 threshold_strategy

**Files:**
- Create: `agent/strategy/threshold.py`
- Create: `tests/strategy/test_threshold.py`

- [ ] **Step 1: Write the failing test**

Create `tests/strategy/test_threshold.py`:

```python
from agent.strategy.threshold import threshold_strategy
from agent.validation.types import Prediction


def _pred(p_hat: float, market_id: str = "m1", ts: int = 1000) -> Prediction:
    return Prediction(market_id=market_id, ts=ts, p_hat=p_hat)


def test_threshold_strategy_yes_signal():
    """§5.7 Case 1: p_hat=0.6, market=0.5, threshold=0.05 → YES, edge=0.10."""
    signal = threshold_strategy(_pred(0.6), market_yes_price=0.5, edge_threshold=0.05)
    assert signal is not None
    assert signal.side == "YES"
    assert signal.market_id == "m1"
    assert signal.ts == 1000
    assert signal.edge == 0.10
    assert signal.target_price == 0.5


def test_threshold_strategy_no_signal():
    """§5.7 Case 2: p_hat=0.5, market=0.6, threshold=0.05 → NO, edge=0.10."""
    signal = threshold_strategy(_pred(0.5), market_yes_price=0.6, edge_threshold=0.05)
    assert signal is not None
    assert signal.side == "NO"
    assert signal.edge == 0.10
    # NO target price = 1 - YES_price
    assert signal.target_price == 0.4


def test_threshold_strategy_below_threshold_returns_none():
    """§5.7 Case 3: p_hat=0.52, market=0.5, threshold=0.05 → None (edge=0.02 < 0.05)."""
    assert threshold_strategy(_pred(0.52), market_yes_price=0.5, edge_threshold=0.05) is None


def test_threshold_strategy_exact_threshold_is_signal():
    """Edge exactly equal to threshold counts as a signal (>= boundary)."""
    signal = threshold_strategy(_pred(0.55), market_yes_price=0.5, edge_threshold=0.05)
    assert signal is not None
    assert signal.side == "YES"
    assert signal.edge == 0.05


def test_threshold_strategy_rationale_includes_values():
    """Rationale string mentions both p_hat and market price."""
    signal = threshold_strategy(_pred(0.60), market_yes_price=0.45, edge_threshold=0.05)
    assert signal is not None
    assert "0.6" in signal.rationale or "0.60" in signal.rationale
    assert "0.45" in signal.rationale
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/strategy/test_threshold.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.strategy.threshold'`.

- [ ] **Step 3: Write the implementation**

Create `agent/strategy/threshold.py`:

```python
"""Stub L4 strategy for Phase 1A.

A single trading rule: take a paper position when the model's prediction
disagrees with the market price by at least `edge_threshold`.  This exists
to give paper-trade-live something to consume in Phase 1A; real strategy
modules arrive in Phase 2.
"""

from agent.validation.types import Prediction, TradeSignal


def threshold_strategy(
    prediction: Prediction,
    market_yes_price: float,
    *,
    edge_threshold: float = 0.05,
) -> TradeSignal | None:
    """Buy YES if p_hat - market_yes_price >= threshold;
       Buy NO if market_yes_price - p_hat >= threshold;
       Else None (no signal).

    Target price for a YES signal is the current YES price (we would limit-buy
    at the current ask).  For a NO signal, target is `1 - market_yes_price`
    (the implied NO ask under Polymarket's binary token convention).
    """
    edge_yes = prediction.p_hat - market_yes_price
    edge_no = market_yes_price - prediction.p_hat

    if edge_yes >= edge_threshold:
        return TradeSignal(
            market_id=prediction.market_id,
            ts=prediction.ts,
            side="YES",
            target_price=market_yes_price,
            edge=edge_yes,
            rationale=(
                f"p_hat={prediction.p_hat:.3f} mkt_yes={market_yes_price:.3f}"
                f" edge={edge_yes:.3f}"
            ),
        )

    if edge_no >= edge_threshold:
        return TradeSignal(
            market_id=prediction.market_id,
            ts=prediction.ts,
            side="NO",
            target_price=1.0 - market_yes_price,
            edge=edge_no,
            rationale=(
                f"p_hat={prediction.p_hat:.3f} mkt_yes={market_yes_price:.3f}"
                f" edge={edge_no:.3f}"
            ),
        )

    return None
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/strategy/test_threshold.py -v`
Expected: PASS — 5 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 54 passed (49 prior + 5 new).

- [ ] **Step 6: Commit**

```bash
git add agent/strategy/threshold.py tests/strategy/test_threshold.py
git commit -m "feat(phase1a): add stub L4 threshold_strategy"
```

---

### Task 8: PaperTradeEngine

**Files:**
- Create: `agent/validation/paper_trade.py`
- Create: `tests/validation/test_paper_trade.py`

- [ ] **Step 1: Write the failing test**

Create `tests/validation/test_paper_trade.py`:

```python
import math

from agent.validation.paper_trade import PaperTradeEngine
from agent.validation.types import (
    PaperTradeResult,
    Prediction,
    ResolvedOutcome,
    TradeSignal,
)


def _signal(market_id: str, side: str, target_price: float, ts: int = 1000) -> TradeSignal:
    return TradeSignal(
        market_id=market_id,
        ts=ts,
        side=side,  # type: ignore[arg-type]
        target_price=target_price,
        edge=0.1,
        rationale="test",
    )


def _outcome(market_id: str, outcome: int, ts: int = 2000) -> ResolvedOutcome:
    return ResolvedOutcome(
        market_id=market_id, outcome=outcome, resolved_ts=ts  # type: ignore[arg-type]
    )


def test_paper_trade_engine_deterministic_pnl():
    """§5.5 reference case:
      - 2× YES at $0.40 winning resolves YES (+0.60 each = +1.20 total)
      - 1× NO at $0.60 losing (NO position when market resolves YES → loss = 0.60)
      - Net PnL = +0.60
    """
    engine = PaperTradeEngine(model_name="test")

    engine.record_signal(_signal("m1", "YES", 0.40))
    engine.record_signal(_signal("m2", "YES", 0.40))
    engine.record_signal(_signal("m3", "NO", 0.60))

    engine.on_resolved(_outcome("m1", 1))  # YES wins → +0.60
    engine.on_resolved(_outcome("m2", 1))  # YES wins → +0.60
    engine.on_resolved(_outcome("m3", 1))  # NO position, YES wins → -0.60

    result = engine.result()
    assert isinstance(result, PaperTradeResult)
    assert result.n_fills == 3
    assert result.n_resolved == 0  # n_resolved counts PREDICTIONS resolved; none recorded here
    assert math.isclose(result.paper_pnl, 0.60, abs_tol=1e-10)


def test_paper_trade_engine_records_predictions_for_metrics():
    """Predictions recorded separately feed the backtest_metrics inside result."""
    engine = PaperTradeEngine(model_name="test")

    engine.record_prediction(Prediction(market_id="m1", ts=1000, p_hat=0.5))
    engine.record_prediction(Prediction(market_id="m2", ts=1100, p_hat=0.5))
    engine.record_signal(_signal("m1", "YES", 0.40))
    engine.on_resolved(_outcome("m1", 1))
    engine.on_resolved(_outcome("m2", 0))

    result = engine.result()
    # n_resolved counts predictions whose market has a resolution
    assert result.n_resolved == 2
    # Brier on constant 0.5 with outcomes [1, 0] = (0.25 + 0.25) / 2 = 0.25
    assert math.isclose(result.backtest_metrics.brier_score, 0.25, abs_tol=1e-10)


def test_paper_trade_engine_no_signal_on_resolve_returns_zero_pnl():
    """on_resolved for a market with no open position contributes 0 PnL."""
    engine = PaperTradeEngine(model_name="test")
    pnl = engine.on_resolved(_outcome("m1", 1))
    assert pnl == 0.0
    result = engine.result()
    assert result.paper_pnl == 0.0
    assert result.n_fills == 0


def test_paper_trade_engine_share_size_scaling():
    """position_size_shares=2.0 doubles realized PnL."""
    engine = PaperTradeEngine(model_name="test", position_size_shares=2.0)
    engine.record_signal(_signal("m1", "YES", 0.40))
    engine.on_resolved(_outcome("m1", 1))
    result = engine.result()
    # 2 shares: profit = 2 * (1.0 - 0.40) = 1.20
    assert math.isclose(result.paper_pnl, 1.20, abs_tol=1e-10)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/validation/test_paper_trade.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.validation.paper_trade'`.

- [ ] **Step 3: Write the implementation**

Create `agent/validation/paper_trade.py`:

```python
"""Paper-trade-live engine for Phase 1A.

Stateful component that records hypothetical fills and computes realized P&L
on resolution.  Position size defaults to 1 share per trade (max payoff = $1
per position).  Slippage defaults to zero; a real spread/impact model is
Phase 1B.
"""

from collections.abc import Callable

from agent.validation.metrics import brier_score, reliability_curve
from agent.validation.types import (
    BacktestResult,
    PaperFill,
    PaperTradeResult,
    Prediction,
    ResolvedOutcome,
    TradeSignal,
)


class PaperTradeEngine:
    """Records paper trades and resolves them when markets close."""

    def __init__(
        self,
        model_name: str,
        position_size_shares: float = 1.0,
        slippage_model: Callable[..., float] = lambda **_: 0.0,
    ) -> None:
        self._model_name = model_name
        self._position_size = position_size_shares
        self._slippage = slippage_model
        self._fills: list[PaperFill] = []
        self._predictions: list[Prediction] = []
        self._open_positions: dict[str, PaperFill] = {}
        self._closed_outcomes: dict[str, ResolvedOutcome] = {}
        self._pnl: float = 0.0
        self._started_ts: int | None = None
        self._ended_ts: int | None = None

    def record_prediction(self, prediction: Prediction) -> None:
        """Record a model's prediction for later inclusion in backtest_metrics."""
        self._predictions.append(prediction)
        self._touch_ts(prediction.ts)

    def record_signal(self, signal: TradeSignal) -> PaperFill:
        """Take a paper position at signal.target_price + slippage.

        Phase 1A simplification: only one open position per market at a time;
        a subsequent signal for the same market replaces the open position.
        """
        slip = self._slippage(
            market_id=signal.market_id,
            side=signal.side,
            target_price=signal.target_price,
        )
        fill = PaperFill(
            market_id=signal.market_id,
            ts=signal.ts,
            side=signal.side,
            price=signal.target_price + slip,
            size=self._position_size,
        )
        self._fills.append(fill)
        self._open_positions[signal.market_id] = fill
        self._touch_ts(signal.ts)
        return fill

    def on_resolved(self, outcome: ResolvedOutcome) -> float:
        """Close any open position for outcome.market_id; return realized P&L.

        Returns 0.0 if no open position.  YES bought at price p pays $1*size if
        outcome=1 else $0; NO bought at price p pays $1*size if outcome=0 else $0.
        """
        self._closed_outcomes[outcome.market_id] = outcome
        fill = self._open_positions.pop(outcome.market_id, None)
        if fill is None:
            return 0.0
        if fill.side == "YES":
            payoff = 1.0 if outcome.outcome == 1 else 0.0
        else:  # NO
            payoff = 1.0 if outcome.outcome == 0 else 0.0
        pnl = (payoff - fill.price) * fill.size
        self._pnl += pnl
        self._touch_ts(outcome.resolved_ts)
        return pnl

    def result(self) -> PaperTradeResult:
        """Snapshot the engine state into a PaperTradeResult."""
        # Pair recorded predictions with resolved outcomes
        pairs: list[tuple[float, int]] = [
            (p.p_hat, self._closed_outcomes[p.market_id].outcome)
            for p in self._predictions
            if p.market_id in self._closed_outcomes
        ]
        n_resolved = len(pairs)

        if pairs:
            brier = brier_score(pairs)
            curve = reliability_curve(pairs)
        else:
            brier = 0.0
            curve = [(None, None)] * 10

        backtest = BacktestResult(
            model_name=self._model_name,
            n_predictions=len(self._predictions),
            n_resolved=n_resolved,
            brier_score=brier,
            reliability_curve=curve,
            kupiec=None,  # Phase 1A: paper-trade sessions are short; defer to Phase 1B
            window_start_ts=self._started_ts or 0,
            window_end_ts=self._ended_ts or 0,
        )
        return PaperTradeResult(
            model_name=self._model_name,
            started_ts=self._started_ts or 0,
            ended_ts=self._ended_ts or 0,
            n_fills=len(self._fills),
            n_resolved=n_resolved,
            paper_pnl=self._pnl,
            backtest_metrics=backtest,
        )

    def _touch_ts(self, ts: int) -> None:
        if self._started_ts is None or ts < self._started_ts:
            self._started_ts = ts
        if self._ended_ts is None or ts > self._ended_ts:
            self._ended_ts = ts
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/validation/test_paper_trade.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 58 passed (54 prior + 4 new).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/paper_trade.py tests/validation/test_paper_trade.py
git commit -m "feat(phase1a): add PaperTradeEngine"
```

---

### Task 9: Extend Phase 0 — MarketDTO.outcome_prices + PolymarketClient.get_market

**Files:**
- Modify: `agent/data/models.py` (add `outcome_prices` field to `MarketDTO`)
- Modify: `agent/data/polymarket_client.py` (add `get_market` method)
- Modify: `tests/data/test_models.py` (add regression for outcome_prices parsing)
- Modify: `tests/data/test_polymarket_client.py` (add `get_market` test)

- [ ] **Step 1: Write the failing tests**

Append to `tests/data/test_models.py`:

```python
def test_market_from_gamma_parses_outcome_prices_string():
    """outcomePrices comes as a stringified JSON array like '["0.55","0.45"]'."""
    raw = {
        "id": "1",
        "outcomePrices": '["0.55", "0.45"]',
    }
    dto = MarketDTO.from_gamma(raw)
    assert dto.outcome_prices == [0.55, 0.45]


def test_market_from_gamma_parses_outcome_prices_list():
    """outcomePrices may also come as an already-parsed list of floats or strings."""
    dto = MarketDTO.from_gamma({"id": "1", "outcomePrices": [0.55, 0.45]})
    assert dto.outcome_prices == [0.55, 0.45]
    dto2 = MarketDTO.from_gamma({"id": "1", "outcomePrices": ["1", "0"]})
    assert dto2.outcome_prices == [1.0, 0.0]


def test_market_from_gamma_missing_outcome_prices_defaults_empty():
    """When outcomePrices absent, dto.outcome_prices is []."""
    dto = MarketDTO.from_gamma({"id": "1"})
    assert dto.outcome_prices == []
```

Append to `tests/data/test_polymarket_client.py`:

```python
@respx.mock
async def test_get_market_returns_dto():
    """get_market(id) hits /markets/{id} on Gamma and returns a MarketDTO."""
    respx.get("https://gamma-api.polymarket.com/markets/42").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": "42",
                "question": "Will it rain?",
                "clobTokenIds": '["a","b"]',
                "outcomePrices": '["0.7","0.3"]',
                "closed": False,
                "active": True,
            },
        )
    )
    async with httpx.AsyncClient() as http:
        market = await _client(http).get_market("42")

    assert market is not None
    assert market.id == "42"
    assert market.outcome_prices == [0.7, 0.3]


@respx.mock
async def test_get_market_returns_none_on_404():
    """A 404 returns None rather than raising."""
    respx.get("https://gamma-api.polymarket.com/markets/missing").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    async with httpx.AsyncClient() as http:
        market = await _client(http).get_market("missing")

    assert market is None
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/data/test_models.py tests/data/test_polymarket_client.py -v -k "outcome_prices or get_market"`
Expected: FAIL — `AttributeError: ... 'outcome_prices'` and `AttributeError: ... 'get_market'`.

- [ ] **Step 3: Extend `MarketDTO` with outcome_prices**

In `agent/data/models.py`, modify the `MarketDTO` class. Find the existing field block:

```python
class MarketDTO(BaseModel):
    """A Polymarket market, normalized from the Gamma API payload."""

    id: str
    question: str = ""
    condition_id: str | None = None
    clob_token_ids: list[str] = Field(default_factory=list)
    category: str | None = None
    active: bool = False
    closed: bool = False
    enable_order_book: bool = False
    order_min_size: float | None = None
    order_price_min_tick_size: float | None = None
    volume_24hr: float | None = None
    liquidity: float | None = None
    end_date_iso: str | None = None
```

Add `outcome_prices` after `end_date_iso`:

```python
class MarketDTO(BaseModel):
    """A Polymarket market, normalized from the Gamma API payload."""

    id: str
    question: str = ""
    condition_id: str | None = None
    clob_token_ids: list[str] = Field(default_factory=list)
    category: str | None = None
    active: bool = False
    closed: bool = False
    enable_order_book: bool = False
    order_min_size: float | None = None
    order_price_min_tick_size: float | None = None
    volume_24hr: float | None = None
    liquidity: float | None = None
    end_date_iso: str | None = None
    outcome_prices: list[float] = Field(default_factory=list)
```

In the `from_gamma` classmethod, locate the `return cls(...)` block (after the existing field mappings) and add a new parser before it. Find:

```python
        return cls(
            id=str(raw["id"]),
            question=raw.get("question", "") or "",
            ...
            end_date_iso=raw.get("endDateIso") or raw.get("endDate"),
        )
```

Add the outcome_prices parsing just before `return cls(...)`:

```python
        outcome_prices_raw = raw.get("outcomePrices")
        if isinstance(outcome_prices_raw, str):
            try:
                outcome_prices_raw = json.loads(outcome_prices_raw)
            except json.JSONDecodeError:
                outcome_prices_raw = []
        outcome_prices = [
            float(x) for x in (outcome_prices_raw or [])
            if x is not None and x != ""
        ]
```

Then add `outcome_prices=outcome_prices,` as the last field in the `return cls(...)` call.

- [ ] **Step 4: Add `get_market` to PolymarketClient**

In `agent/data/polymarket_client.py`, append a new method to the `PolymarketClient` class (after `get_price_history`):

```python
    async def get_market(self, market_id: str) -> MarketDTO | None:
        """Fetch a single market by id from Gamma.  Returns None on 404."""
        await self._bucket.acquire()
        resp = await self._http.get(
            f"{self._settings.gamma_base_url}/markets/{market_id}"
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return MarketDTO.from_gamma(resp.json())
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `pytest tests/data/test_models.py tests/data/test_polymarket_client.py -v -k "outcome_prices or get_market"`
Expected: PASS — 5 passed.

- [ ] **Step 6: Run full suite to confirm no regression**

Run: `pytest -v`
Expected: PASS — 63 passed (58 prior + 5 new).

- [ ] **Step 7: Commit**

```bash
git add agent/data/models.py agent/data/polymarket_client.py tests/data/test_models.py tests/data/test_polymarket_client.py
git commit -m "feat(phase1a): extend Phase 0 with outcome_prices and get_market(id)"
```

---

### Task 10: ResolutionPoller

**Files:**
- Create: `agent/validation/resolution_poller.py`
- Create: `tests/validation/test_resolution_poller.py`

- [ ] **Step 1: Write the failing test**

Create `tests/validation/test_resolution_poller.py`:

```python
import asyncio

import httpx
import respx

from agent.config import Settings
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.validation.resolution_poller import ResolutionPoller
from agent.validation.types import PriceTick, ResolvedOutcome


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


@respx.mock
async def test_resolution_poller_yields_ticks_then_resolution():
    """§5.6 reference case:
       Poll 1: closed=False, outcomePrices=["0.55","0.45"] → PriceTick(0.55)
       Poll 2: same → PriceTick(0.55)
       Poll 3: closed=True, outcomePrices=["1","0"] → ResolvedOutcome(1), then stops.
    """
    # respx side_effect to vary response per call
    poll_responses = [
        httpx.Response(200, json={
            "id": "m1",
            "closed": False,
            "active": True,
            "outcomePrices": '["0.55","0.45"]',
        }),
        httpx.Response(200, json={
            "id": "m1",
            "closed": False,
            "active": True,
            "outcomePrices": '["0.55","0.45"]',
        }),
        httpx.Response(200, json={
            "id": "m1",
            "closed": True,
            "active": False,
            "outcomePrices": '["1","0"]',
        }),
    ]
    respx.get("https://gamma-api.polymarket.com/markets/m1").mock(
        side_effect=poll_responses
    )

    async with httpx.AsyncClient() as http:
        poller = ResolutionPoller(
            client=_client(http), poll_interval_seconds=0.001
        )
        events = []
        async for event in poller.stream_events(["m1"]):
            events.append(event)
            if len(events) >= 3:
                break

    assert len(events) == 3
    assert isinstance(events[0], PriceTick)
    assert events[0].market_id == "m1"
    assert events[0].market_price == 0.55
    assert isinstance(events[1], PriceTick)
    assert events[1].market_price == 0.55
    assert isinstance(events[2], ResolvedOutcome)
    assert events[2].outcome == 1


@respx.mock
async def test_resolution_poller_handles_404():
    """A 404 on a market id removes it from the pending set silently."""
    respx.get("https://gamma-api.polymarket.com/markets/missing").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    async with httpx.AsyncClient() as http:
        poller = ResolutionPoller(
            client=_client(http), poll_interval_seconds=0.001
        )
        events = []
        async for event in poller.stream_events(["missing"]):
            events.append(event)

    # Generator drained without yielding anything
    assert events == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/validation/test_resolution_poller.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.validation.resolution_poller'`.

- [ ] **Step 3: Write the implementation**

Create `agent/validation/resolution_poller.py`:

```python
"""Resolution poller for Phase 1A paper-trade-live.

Periodically polls Polymarket's Gamma API per market.  Yields PriceTick events
between polls while a market is open; yields a single ResolvedOutcome when the
market flips to closed=True with a definitive outcome (outcomePrices = [1,0]
or [0,1]).  Once all tracked markets have resolved, the generator finishes.
"""

import asyncio
import time
from collections.abc import AsyncIterator

from agent.data.models import MarketDTO
from agent.data.polymarket_client import PolymarketClient
from agent.validation.types import PriceTick, ResolvedOutcome


class ResolutionPoller:
    """Async polling loop over a fixed set of market_ids."""

    def __init__(
        self,
        client: PolymarketClient,
        poll_interval_seconds: float = 60.0,
    ) -> None:
        self._client = client
        self._interval = poll_interval_seconds

    async def stream_events(
        self,
        market_ids: list[str],
    ) -> AsyncIterator[PriceTick | ResolvedOutcome]:
        """Yield PriceTick and ResolvedOutcome events until all markets resolve."""
        remaining: set[str] = set(market_ids)
        while remaining:
            for mid in list(remaining):
                market = await self._client.get_market(mid)
                if market is None:
                    remaining.discard(mid)
                    continue

                now_ts = int(time.time())

                if market.closed:
                    outcome = _parse_definitive_outcome(market)
                    if outcome is not None:
                        yield ResolvedOutcome(
                            market_id=mid, outcome=outcome, resolved_ts=now_ts
                        )
                        remaining.discard(mid)
                    # Else: closed but indeterminate — keep polling
                else:
                    yes_price = _yes_token_price(market)
                    if yes_price is not None:
                        yield PriceTick(
                            market_id=mid, ts=now_ts, market_price=yes_price
                        )

            if remaining:
                await asyncio.sleep(self._interval)


def _yes_token_price(market: MarketDTO) -> float | None:
    """Convention: outcome_prices[0] is the YES price."""
    if not market.outcome_prices:
        return None
    return market.outcome_prices[0]


def _parse_definitive_outcome(market: MarketDTO) -> int | None:
    """Outcome is 1 (YES) if outcome_prices == [1, 0]; 0 (NO) if [0, 1]; else None."""
    op = market.outcome_prices
    if op == [1.0, 0.0]:
        return 1
    if op == [0.0, 1.0]:
        return 0
    return None
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/validation/test_resolution_poller.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 65 passed (63 prior + 2 new).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/resolution_poller.py tests/validation/test_resolution_poller.py
git commit -m "feat(phase1a): add ResolutionPoller for paper-trade-live"
```

---

### Task 11: Minimal CLI + Phase 1A Gate Test

**Files:**
- Create: `agent/cli.py`
- Create: `tests/test_cli_smoke.py`
- Modify: `pyproject.toml` (add CLI entrypoint)

- [ ] **Step 1: Write the failing test**

Create `tests/test_cli_smoke.py`:

```python
from agent import cli


def test_cli_module_exposes_main():
    """The cli module has a `main` callable usable as a console entrypoint."""
    assert callable(cli.main)


def test_cli_main_handles_unknown_subcommand(capsys):
    """An unknown subcommand exits non-zero with usage info on stderr."""
    rc = cli.main(["nonexistent"])
    assert rc != 0
    captured = capsys.readouterr()
    assert "usage" in captured.err.lower() or "usage" in captured.out.lower()


def test_cli_backtest_help(capsys):
    """`backtest --help` exits 0 with usage info."""
    rc = cli.main(["backtest", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "backtest" in combined.lower()


def test_cli_paper_trade_help(capsys):
    """`paper-trade --help` exits 0 with usage info."""
    rc = cli.main(["paper-trade", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "paper-trade" in combined.lower()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_cli_smoke.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.cli'`.

- [ ] **Step 3: Write the implementation**

Create `agent/cli.py`:

```python
"""Minimal CLI entrypoint for the polymarket-agent.

Phase 1A provides two subcommands as wireframes:
  - backtest   : run walk_forward_backtest with a chosen baseline
  - paper-trade: start a paper-trade-live session

Full subcommand implementations land in Phase 1B+ when there are real models
and operational workflows.  Phase 1A's CLI is a structural placeholder that
exists so the entrypoint contract is locked in.
"""

import argparse
import sys
from collections.abc import Sequence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymarket-agent",
        description="Autonomous Polymarket fair-value trading agent (Phase 1A: validation infra).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    backtest = sub.add_parser(
        "backtest",
        help="Run walk_forward_backtest against Phase 0 stored history.",
    )
    backtest.add_argument(
        "--model",
        choices=["last_traded_price", "constant_half"],
        default="last_traded_price",
        help="Baseline model to evaluate (Phase 1A only has baselines).",
    )

    paper_trade = sub.add_parser(
        "paper-trade",
        help="Start a paper-trade-live session against current Polymarket.",
    )
    paper_trade.add_argument(
        "--model",
        choices=["last_traded_price", "constant_half"],
        default="last_traded_price",
    )
    paper_trade.add_argument(
        "--market-id",
        action="append",
        default=[],
        help="Market id to follow (may be repeated).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.  Returns the process exit code.

    Phase 1A: parses args, prints a stub message, returns 0 for valid
    subcommands.  Phase 1B replaces these stubs with real implementations.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse calls sys.exit on --help (code 0) and on errors (code 2).
        return int(e.code) if e.code is not None else 0

    if args.command == "backtest":
        print(
            f"[stub] would run walk_forward_backtest with model={args.model}. "
            "Phase 1B will wire this up."
        )
        return 0
    if args.command == "paper-trade":
        print(
            f"[stub] would start paper-trade-live with model={args.model}, "
            f"markets={args.market_id}. Phase 1B will wire this up."
        )
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
```

- [ ] **Step 4: Add CLI entrypoint to pyproject.toml**

In `pyproject.toml`, after the `[tool.pytest.ini_options]` block, add:

```toml
[project.scripts]
polymarket-agent = "agent.cli:main"
```

Then reinstall to register the script: with venv activated, run `pip install -e ".[dev]"`. Expected: success; `which polymarket-agent` (or `where polymarket-agent` on Windows) now finds the script.

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/test_cli_smoke.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 6: Run the FULL Phase 1A gate — entire test suite green**

Run: `pytest -v`
Expected: PASS — **69 passed** (26 Phase 0 + 43 Phase 1A).

- [ ] **Step 7: Verify the algorithmic gate (§5 of the spec) by inspection**

Re-read `tests/validation/test_metrics.py` and confirm:
- §5.1: `test_kupiec_zero_exceptions`, `test_kupiec_seven_exceptions`, `test_kupiec_fifteen_exceptions` are GREEN.
- §5.2: `test_brier_perfect_miss`, `test_brier_constant_half`, `test_brier_mixed_calibration`, `test_brier_empty_raises` are GREEN.
- §5.3: `test_reliability_curve_calibrated_100`, `test_reliability_curve_too_few_per_bin` are GREEN.

In `tests/validation/test_backtest.py`:
- §5.4: `test_walk_forward_backtest_constant_half_brier`, `test_walk_forward_backtest_last_traded_price_brier` are GREEN.

In `tests/validation/test_paper_trade.py`:
- §5.5: `test_paper_trade_engine_deterministic_pnl` is GREEN.

In `tests/validation/test_resolution_poller.py`:
- §5.6: `test_resolution_poller_yields_ticks_then_resolution` is GREEN.

In `tests/strategy/test_threshold.py`:
- §5.7: `test_threshold_strategy_yes_signal`, `test_threshold_strategy_no_signal`, `test_threshold_strategy_below_threshold_returns_none` are GREEN.

§5.8: `pytest -v` exit code is 0. ✓

- [ ] **Step 8: Commit**

```bash
git add agent/cli.py tests/test_cli_smoke.py pyproject.toml
git commit -m "feat(phase1a): add minimal CLI entrypoint + close Phase 1A algorithmic gate"
```

---

## Phase 1A Completion Gate

Phase 1A is complete when `pytest -v` is fully green (**69 tests passing**) AND
all spec §5 reference cases are explicitly tested with the hand-computed values
above.  That verifies the design spec's Phase 1A gate — the L7 math functions
produce correct outputs against synthetic test cases with hand-computed
reference values.  Phase 1B (first real L3 module) is unblocked.

---

## Self-Review

**1. Spec coverage:**
- §1 Goal/scope — Tasks 1–11 collectively deliver every in-scope item.  Out-of-scope items (real L3 modules, audit trail, calibration gate logic, Bonferroni/Rule-of-5, L9 dashboard) explicitly not implemented. ✓
- §2 Architecture — Repository layout from §2.1 mapped 1:1 to the Files table at the top of this plan. ✓
- §3 Data Model — Task 1 creates all 8 types in `agent/validation/types.py`; later tasks use them by import. ✓
- §4 Components — every component (4.1 metrics, 4.2 walk_forward, 4.3 PaperTradeEngine, 4.4 ResolutionPoller, 4.5 baselines, 4.6 threshold) gets a dedicated task. ✓
- §5 Acceptance Criteria — every reference case (§5.1–§5.7) is a named test in the corresponding task. §5.8 is the final-suite gate in Task 11. ✓
- §6 Open Risks — risks are documented; no implementation needed (they're mitigations and forward-looking notes). ✓
- §7 Tech Stack — `scipy>=1.13` added to pyproject in Task 1. ✓
- §8 Plan decomposition path — this is that plan. ✓

**2. Placeholder scan:** No "TBD", "TODO", "implement later", "add error handling", "similar to Task N" patterns.  Every code step contains complete runnable code; every command has expected output.  ✓

**3. Type consistency:**
- `Prediction(market_id, ts, p_hat)` — defined Task 1, consumed by baselines (Task 5), walk_forward_backtest (Task 6), threshold_strategy (Task 7), PaperTradeEngine (Task 8). Signature unchanged throughout. ✓
- `ReplayEvent(ts, token_id, price)` — Phase 0 type; baseline signature in Task 5 confirms it has no `market_id` field, so baselines take `market_id` as a separate argument.  walk_forward_backtest in Task 6 calls `model(market_id, event)` consistent with that signature. ✓
- `TradeSignal(market_id, ts, side, target_price, edge, rationale)` — Task 1, produced by threshold_strategy in Task 7, consumed by PaperTradeEngine.record_signal in Task 8. Signature unchanged. ✓
- `PaperFill(market_id, ts, side, price, size)` — Task 1, produced by PaperTradeEngine in Task 8.  `size` is in shares (matches Task 1 docstring and Task 8 `position_size_shares` parameter). ✓
- `ResolvedOutcome(market_id, outcome, resolved_ts)` — Task 1, produced by ResolutionPoller in Task 10, consumed by walk_forward_backtest and PaperTradeEngine. ✓
- `PriceTick(market_id, ts, market_price)` — Task 1, produced by ResolutionPoller in Task 10.  No other consumers in Phase 1A; Phase 1B+ paper-trade-live driver will consume them. ✓
- `BacktestResult` / `KupiecResult` / `PaperTradeResult` — Task 1, produced by walk_forward_backtest (Task 6) and PaperTradeEngine.result (Task 8). Field-name consistency verified. ✓
- `MarketDTO` — Phase 0 type; extended in Task 9 with `outcome_prices`. ResolutionPoller in Task 10 reads `market.outcome_prices` consistent with that extension. ✓
- `PolymarketClient` — Phase 0 class; extended in Task 9 with `get_market(market_id)`. ResolutionPoller in Task 10 calls `self._client.get_market(mid)` consistent with that extension. ✓

No type drift identified.
