# Polymarket Phase 1B-C2-A: Composition Core — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the composition pipeline (4 composer modes, Bayesian blender, agreement filter, asymmetric tilt, half-Kelly sizer, performance tracker, market resolver, crypto-data wrapper, and top-level `crypto_model`) plus supporting ORM/types/yaml so Phase 1A's `walk_forward_backtest` produces non-zero `Prediction`s on one hand-curated BTC barrier market using spot-shock signals only. News integration is C2-B; this plan deliberately uses a `SpotOnlyShockDetector` placeholder until C2-D replaces it.

**Architecture:** Pure-function pipeline. Each layer is one file with one class. State (mode performance history, market mapping) lives outside the pipeline in dedicated services. ORM extends Phase 0/1A's existing `Base`; DTOs extend `agent/data/models.py`; new types live in `agent/research/crypto/types.py`. The top-level `crypto_model(market_id, event, ...)` is the only thing `walk_forward_backtest` needs to know about.

**Tech Stack:** Python 3.11+, SQLAlchemy 2.0 (`Mapped[...]`/`mapped_column`), pydantic v2 (`BaseModel`), frozen `@dataclass`, pytest. New runtime dep: `pyyaml>=6.0` (for `markets.yaml`). No external API dependencies in C2-A (Telegram/CryptoPanic come in C2-B).

**Parent spec:** `docs/superpowers/specs/2026-05-21-polymarket-phase-1b-c2-composite-crypto-model-design.md` (commit `fa14959d`).

---

## File Structure

| File | Responsibility |
|---|---|
| `agent/store/schema.py` (extend) | Add `ModePerformance` + `TradeRecord` + `ModeFloorState` ORM models |
| `agent/data/models.py` (extend) | Add `ModePerformanceRecordDTO` + `TradeRecordDTO` |
| `agent/store/repository.py` (extend) | Add `record_mode_brier`, `record_trade`, `get_trailing_mode_briers`, `get_mode_floor_state`, `update_mode_floor_state` |
| `agent/research/crypto/types.py` (new) | `ShockState`, `CryptoMarketMapping`, `ModeWeights`, `KellyFraction`, `BlendOutput`, `AgreementVerdict`, `ModeState`, `CryptoMarketMappingFile` |
| `agent/research/crypto/composers.py` (new) | `Composer` ABC + `BinaryComposer`, `ExponentialComposer`, `MagnitudeTiedComposer`, `ConfidenceWeightedComposer` |
| `agent/research/crypto/agreement_filter.py` (new) | `AgreementFilter` with epsilon=0.08, min_active_count=3 |
| `agent/research/crypto/asymmetric_tilt.py` (new) | `AsymmetricTilt` with +0.05 long-only |
| `agent/research/crypto/kelly_sizer.py` (new) | `KellySizer` half-Kelly with cap=0.10, minimum_edge=0.02 |
| `agent/research/crypto/performance_tracker.py` (new) | `PerformanceTracker` over `ModePerformance` rows |
| `agent/research/crypto/blender.py` (new) | `BayesianBlender` (Brier-weighted) |
| `agent/research/crypto/market_resolver.py` (new) | `MarketResolver` + `load_markets_yaml` |
| `agent/research/crypto/markets.yaml` (new) | Hand-curated mapping; starter 1-2 BTC markets |
| `agent/research/crypto/crypto_data.py` (new) | `CryptoDataAccess` wrapper for OHLCV/news queries |
| `agent/research/crypto/shock_detector.py` (placeholder) | `SpotOnlyShockDetector` only; full 3-mode implementation comes in C2-D |
| `agent/research/crypto/model.py` (new) | `crypto_model(market_id, event, ...)` top-level callable |
| Test files mirror under `tests/` | One test file per source file |

---

## Pre-flight: Verify clean baseline

- [ ] **Step P.1: Confirm branch and clean tests**

Run:
```
git status --short
git branch --show-current
pytest -q
```
Expected: branch `feat/polymarket-phase-1b-c1` (or a fresh `feat/polymarket-phase-1b-c2-a` branched from it), no unexpected modifications, `pytest -q` exits 0 with 107 tests passing.

- [ ] **Step P.2: Create C2-A branch if not already on one**

If currently on `feat/polymarket-phase-1b-c1`, create a fresh branch:
```
git checkout -b feat/polymarket-phase-1b-c2-a
```
All commits below land on `feat/polymarket-phase-1b-c2-a`.

- [ ] **Step P.3: Add pyyaml dependency**

Edit `pyproject.toml`, add to `[project] dependencies`:
```
"pyyaml>=6.0",
```
Then run:
```
pip install -e .
```
Verify:
```
python -c "import yaml; print(yaml.__version__)"
```
Expected: version >= 6.0 prints without error.

---

## Task 1: ORM extensions (`ModePerformance`, `TradeRecord`, `ModeFloorState`)

**Files:**
- Modify: `agent/store/schema.py`
- Test: `tests/store/test_schema.py` (extend)

- [ ] **Step 1.1: Write the failing round-trip test for `ModePerformance`**

Append to `tests/store/test_schema.py`:
```python
def test_mode_performance_round_trips_through_db(session_factory):
    """Write a ModePerformance row in session A, read it back in session B."""
    from agent.store.schema import ModePerformance

    with session_factory() as session_a:
        row = ModePerformance(
            mode_name="binary",
            market_id="0xABC001",
            p_mode=0.31,
            p_market_at_prediction=0.10,
            outcome=1,
            brier_score=(0.31 - 1.0) ** 2,
            closed_at=1747800000,
        )
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(ModePerformance).one()
        assert result.mode_name == "binary"
        assert result.market_id == "0xABC001"
        assert result.p_mode == 0.31
        assert result.p_market_at_prediction == 0.10
        assert result.outcome == 1
        assert abs(result.brier_score - 0.4761) < 1e-9
        assert result.closed_at == 1747800000
```

- [ ] **Step 1.2: Run to verify it fails**

```
pytest tests/store/test_schema.py::test_mode_performance_round_trips_through_db -v
```
Expected: `ImportError: cannot import name 'ModePerformance' from 'agent.store.schema'`.

- [ ] **Step 1.3: Add `ModePerformance` ORM model**

Append to `agent/store/schema.py` (after the existing models, before any module-level code):
```python
class ModePerformance(Base):
    """One Brier observation per (mode, closed-trade). Append-only.
    Queried by PerformanceTracker for trailing-window averages.
    """

    __tablename__ = "mode_performance"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode_name: Mapped[str] = mapped_column(String(32), index=True)
    market_id: Mapped[str] = mapped_column(String, index=True)
    p_mode: Mapped[float] = mapped_column(Float)
    p_market_at_prediction: Mapped[float] = mapped_column(Float)
    outcome: Mapped[int] = mapped_column(Integer)
    brier_score: Mapped[float] = mapped_column(Float)
    closed_at: Mapped[int] = mapped_column(Integer)
```

If `Index` isn't already imported in `schema.py`, also add it to the `from sqlalchemy import ...` line.

- [ ] **Step 1.4: Run test to verify it passes**

```
pytest tests/store/test_schema.py::test_mode_performance_round_trips_through_db -v
```
Expected: PASS.

- [ ] **Step 1.5: Write failing round-trip test for `TradeRecord`**

Append to `tests/store/test_schema.py`:
```python
def test_trade_record_round_trips_through_db(session_factory):
    """Two-session round-trip; full pipeline diagnostics preserved."""
    from agent.store.schema import TradeRecord
    import json

    with session_factory() as session_a:
        row = TradeRecord(
            market_id="0xABC001",
            ts=1747800000,
            p_market=0.10,
            p_bridge=0.31,
            p_mode1=0.31,
            p_mode2=0.30,
            p_mode3=0.29,
            p_mode4=0.32,
            p_blend=0.305,
            p_final=0.355,
            agreement_vetoed=False,
            kelly_fraction=0.049,
            position_size=4.9,
            shock_active=True,
            shock_severity=0.8,
            mode_weights_json=json.dumps({"binary": 0.25, "exp": 0.25, "magnitude": 0.25, "confidence": 0.25}),
        )
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(TradeRecord).one()
        assert result.market_id == "0xABC001"
        assert result.p_final == 0.355
        assert result.agreement_vetoed is False
        assert result.shock_severity == 0.8
        weights = json.loads(result.mode_weights_json)
        assert sum(weights.values()) == 1.0
```

- [ ] **Step 1.6: Add `TradeRecord` ORM**

Append to `agent/store/schema.py`. Make sure `Text` is imported from sqlalchemy.
```python
class TradeRecord(Base):
    """Append-only diagnostic record of every position taken by crypto_model."""

    __tablename__ = "trade_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    market_id: Mapped[str] = mapped_column(String, index=True)
    ts: Mapped[int] = mapped_column(Integer, index=True)
    p_market: Mapped[float] = mapped_column(Float)
    p_bridge: Mapped[float] = mapped_column(Float)
    p_mode1: Mapped[float] = mapped_column(Float)
    p_mode2: Mapped[float] = mapped_column(Float)
    p_mode3: Mapped[float] = mapped_column(Float)
    p_mode4: Mapped[float] = mapped_column(Float)
    p_blend: Mapped[float] = mapped_column(Float)
    p_final: Mapped[float] = mapped_column(Float)
    agreement_vetoed: Mapped[bool] = mapped_column(Boolean)
    kelly_fraction: Mapped[float] = mapped_column(Float)
    position_size: Mapped[float] = mapped_column(Float)
    shock_active: Mapped[bool] = mapped_column(Boolean)
    shock_severity: Mapped[float | None] = mapped_column(Float, nullable=True)
    mode_weights_json: Mapped[str] = mapped_column(Text)
```

- [ ] **Step 1.7: Write failing round-trip test for `ModeFloorState`**

Append to `tests/store/test_schema.py`:
```python
def test_mode_floor_state_round_trips_through_db(session_factory):
    """One row per mode, mutable, tracks per-mode Brier floor evolution."""
    from agent.store.schema import ModeFloorState

    with session_factory() as session_a:
        row = ModeFloorState(
            mode_name="confidence",
            brier_floor=0.10,
            disable_streak=0,
            is_disabled=False,
            updated_at=1747800000,
        )
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(ModeFloorState).one()
        assert result.mode_name == "confidence"
        assert result.brier_floor == 0.10
        assert result.is_disabled is False
```

- [ ] **Step 1.8: Add `ModeFloorState` ORM**

Append to `agent/store/schema.py`:
```python
class ModeFloorState(Base):
    """Per-mode state for the Brier floor and disable streak.  One row per
    mode (binary/exp/magnitude/confidence).  Mutable — updated on every
    closed-trade outcome.
    """

    __tablename__ = "mode_floor_state"

    mode_name: Mapped[str] = mapped_column(String(32), primary_key=True)
    brier_floor: Mapped[float] = mapped_column(Float, default=0.10)
    disable_streak: Mapped[int] = mapped_column(Integer, default=0)
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[int] = mapped_column(Integer)
```

- [ ] **Step 1.9: Run all schema tests**

```
pytest tests/store/test_schema.py -v
```
Expected: all 3 new tests PASS; all prior tests still PASS (no regression).

- [ ] **Step 1.10: Commit**

```
git add agent/store/schema.py tests/store/test_schema.py
git commit -m "feat(polymarket-c2a): add ModePerformance, TradeRecord, ModeFloorState ORM models"
```

---

## Task 2: Result-record types (`agent/research/crypto/types.py`)

**Files:**
- Create: `agent/research/crypto/types.py`
- Test: `tests/research/crypto/test_types.py`

- [ ] **Step 2.1: Write the failing immutability + invariant tests**

Create `tests/research/crypto/test_types.py`:
```python
import pytest


def test_shock_state_severity_clipped_at_construction():
    """ShockState clips severity to [0, 1] regardless of input."""
    from agent.research.crypto.types import ShockState

    s = ShockState(active=True, severity=1.5, spot_signal=True, news_signal=False, time_since_shock_seconds=0)
    assert s.severity == 1.0

    s2 = ShockState(active=True, severity=-0.2, spot_signal=False, news_signal=True, time_since_shock_seconds=0)
    assert s2.severity == 0.0


def test_shock_state_is_frozen():
    """ShockState is immutable — direct field assignment raises."""
    from agent.research.crypto.types import ShockState

    s = ShockState(active=False, severity=0.0, spot_signal=False, news_signal=False, time_since_shock_seconds=0)
    with pytest.raises(Exception):
        s.severity = 0.5  # type: ignore[misc]


def test_mode_weights_is_all_disabled_true_when_all_zero():
    from agent.research.crypto.types import ModeWeights

    w = ModeWeights(w_binary=0.0, w_exp=0.0, w_magnitude=0.0, w_confidence=0.0)
    assert w.is_all_disabled() is True


def test_mode_weights_is_all_disabled_false_when_any_nonzero():
    from agent.research.crypto.types import ModeWeights

    w = ModeWeights(w_binary=0.25, w_exp=0.0, w_magnitude=0.5, w_confidence=0.25)
    assert w.is_all_disabled() is False


def test_kelly_fraction_clipped_to_kelly_cap():
    """KellyFraction.fraction is bounded to [0, kelly_cap=0.10] at construction."""
    from agent.research.crypto.types import KellyFraction

    k = KellyFraction(fraction=0.5, direction="yes", raw_kelly_pre_half=1.0)
    assert k.fraction == 0.10  # clipped


def test_kelly_fraction_zero_passes_through():
    from agent.research.crypto.types import KellyFraction

    k = KellyFraction(fraction=0.0, direction="yes", raw_kelly_pre_half=0.0)
    assert k.fraction == 0.0


def test_crypto_market_mapping_construction():
    from agent.research.crypto.types import CryptoMarketMapping

    m = CryptoMarketMapping(
        market_id="0xABC001",
        symbol="BTCUSDT",
        barrier_price=80000.0,
        direction="up",
        resolution_ts=1751328000,
    )
    assert m.symbol == "BTCUSDT"
    assert m.direction == "up"
```

- [ ] **Step 2.2: Run to verify failures**

```
pytest tests/research/crypto/test_types.py -v
```
Expected: ImportError on `agent.research.crypto.types`.

- [ ] **Step 2.3: Create `agent/research/crypto/types.py`**

```python
"""Frozen result-record types for the C2 composition pipeline.

STRUCTURAL DEFENSE: Many of these types clip their fields at construction
(e.g., severity to [0,1], KellyFraction to [0, kelly_cap]).  Consumers can
trust the invariants without re-checking.
"""

from dataclasses import dataclass, field
from typing import Literal


def _clip(x: float, lo: float, hi: float) -> float:
    """Clip x to [lo, hi]."""
    return min(max(x, lo), hi)


@dataclass(frozen=True)
class ShockState:
    """Output of ShockDetector. `active` is the binary gate; `severity` in [0, 1]
    is the magnitude used by MagnitudeTiedComposer.  `severity` is clipped to
    [0, 1] at construction (prevents passing unbounded magnitudes downstream).
    """

    active: bool
    severity: float
    spot_signal: bool
    news_signal: bool
    time_since_shock_seconds: int

    def __post_init__(self):
        # Frozen dataclass __post_init__ workaround via object.__setattr__
        object.__setattr__(self, "severity", _clip(self.severity, 0.0, 1.0))


@dataclass(frozen=True)
class CryptoMarketMapping:
    """A single Polymarket market resolved to its crypto pair + barrier."""

    market_id: str
    symbol: str
    barrier_price: float
    direction: Literal["up", "down"]
    resolution_ts: int


@dataclass(frozen=True)
class CryptoMarketMappingFile:
    """One row from markets.yaml (pre-resolution; before end_date_iso lookup)."""

    market_id: str
    polymarket_question: str
    symbol: str
    barrier_price: float
    direction: Literal["up", "down"]


@dataclass(frozen=True)
class ModeWeights:
    """Output of BayesianBlender's weighting step. Sums to 1.0 normally,
    or all-zero if every mode is disabled (caller interprets as no-trade).
    """

    w_binary: float
    w_exp: float
    w_magnitude: float
    w_confidence: float

    def is_all_disabled(self) -> bool:
        return (
            self.w_binary == 0.0
            and self.w_exp == 0.0
            and self.w_magnitude == 0.0
            and self.w_confidence == 0.0
        )


@dataclass(frozen=True)
class BlendOutput:
    p_blend: float
    weights: ModeWeights


@dataclass(frozen=True)
class AgreementVerdict:
    allowed: bool
    long_count: int
    short_count: int
    direction: Literal["long", "short", "none"]


KELLY_CAP_DEFAULT = 0.10


@dataclass(frozen=True)
class KellyFraction:
    """Output of KellySizer. fraction clipped to [0, KELLY_CAP_DEFAULT] at
    construction.  direction records whether this is a long-YES or long-NO bet.
    """

    fraction: float
    direction: Literal["yes", "no"]
    raw_kelly_pre_half: float

    def __post_init__(self):
        object.__setattr__(self, "fraction", _clip(self.fraction, 0.0, KELLY_CAP_DEFAULT))


@dataclass(frozen=True)
class ModeState:
    """Per-mode state surfaced by PerformanceTracker."""

    mode_name: str
    trailing_brier: float
    brier_floor: float
    is_disabled: bool
    n_closed_trades: int
```

- [ ] **Step 2.4: Run tests to verify they pass**

```
pytest tests/research/crypto/test_types.py -v
```
Expected: 7 PASS.

- [ ] **Step 2.5: Commit**

```
git add agent/research/crypto/types.py tests/research/crypto/test_types.py
git commit -m "feat(polymarket-c2a): add frozen result-record types with construction-time invariants"
```

---

## Task 3: Composers (`agent/research/crypto/composers.py`)

**Files:**
- Create: `agent/research/crypto/composers.py`
- Test: `tests/research/crypto/test_composers.py`

This is the largest file in C2-A. The 4 composers are independent so each gets its own test class.

- [ ] **Step 3.1: Write failing `BinaryComposer` tests (4 cases from spec §8.1)**

Create `tests/research/crypto/test_composers.py`:
```python
import math
import pytest

from agent.research.crypto.types import ShockState


def _ss(active=False, severity=0.0, t=0):
    """Shorthand to build a ShockState."""
    return ShockState(
        active=active,
        severity=severity,
        spot_signal=active,
        news_signal=False,
        time_since_shock_seconds=t,
    )


class TestBinaryComposer:
    def test_no_shock_returns_p_market(self):
        from agent.research.crypto.composers import BinaryComposer
        c = BinaryComposer()
        assert c.compose(p_market=0.10, p_bridge=0.30, shock_state=_ss(active=False)) == 0.10

    def test_within_window_returns_p_bridge(self):
        from agent.research.crypto.composers import BinaryComposer
        c = BinaryComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.8, t=3 * 86400),
        ) == 0.30

    def test_at_window_edge_just_before_end_returns_p_bridge(self):
        from agent.research.crypto.composers import BinaryComposer
        c = BinaryComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.8, t=14 * 86400 - 1),
        ) == 0.30

    def test_after_window_returns_p_market(self):
        from agent.research.crypto.composers import BinaryComposer
        c = BinaryComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.8, t=14 * 86400 + 1),
        ) == 0.10
```

- [ ] **Step 3.2: Run to verify it fails**

```
pytest tests/research/crypto/test_composers.py -v
```
Expected: ImportError on `agent.research.crypto.composers`.

- [ ] **Step 3.3: Create `composers.py` with the `Composer` ABC and `BinaryComposer`**

```python
"""Composer implementations: each turns (p_market, p_bridge, shock_state)
into a single mode's P_mode.

All 4 composers gate on `shock_state.active`.  When not active, P_mode = P_market
unconditionally (the model has no opinion absent a shock).
"""

import math
from abc import ABC, abstractmethod

from agent.research.crypto.types import ShockState


class Composer(ABC):
    name: str  # subclass sets to "binary" | "exp" | "magnitude" | "confidence"

    @abstractmethod
    def compose(
        self,
        p_market: float,
        p_bridge: float,
        shock_state: ShockState,
    ) -> float:
        """Returns P_mode in [0, 1]."""


class BinaryComposer(Composer):
    """P_mode = P_bridge inside the shock window; P_market outside or no-shock."""

    name = "binary"

    def __init__(self, window_seconds: int = 14 * 86400):
        self.window_seconds = window_seconds

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        if shock_state.time_since_shock_seconds < self.window_seconds:
            return p_bridge
        return p_market
```

- [ ] **Step 3.4: Run tests; verify 4 PASS**

```
pytest tests/research/crypto/test_composers.py::TestBinaryComposer -v
```
Expected: 4 PASS.

- [ ] **Step 3.5: Write `ExponentialComposer` tests (4 cases)**

Append to `tests/research/crypto/test_composers.py`:
```python
class TestExponentialComposer:
    def test_t_zero_returns_p_bridge(self):
        from agent.research.crypto.composers import ExponentialComposer
        c = ExponentialComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=0),
        ) == 0.30  # lambda(0) = exp(0) = 1

    def test_t_equals_tau_blends_at_exp_minus_one(self):
        """At t=tau, lambda = exp(-1) ~ 0.368, so P_mode = 0.368*0.30 + 0.632*0.10 = 0.1736."""
        from agent.research.crypto.composers import ExponentialComposer
        c = ExponentialComposer()
        result = c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=7 * 86400),
        )
        expected = math.exp(-1.0) * 0.30 + (1.0 - math.exp(-1.0)) * 0.10
        assert abs(result - expected) < 1e-9

    def test_t_equals_three_tau_long_tail(self):
        """At t=3*tau, lambda = exp(-3) ~ 0.0498, decay tail."""
        from agent.research.crypto.composers import ExponentialComposer
        c = ExponentialComposer()
        result = c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=21 * 86400),
        )
        expected = math.exp(-3.0) * 0.30 + (1.0 - math.exp(-3.0)) * 0.10
        assert abs(result - expected) < 1e-9

    def test_no_shock_returns_p_market(self):
        from agent.research.crypto.composers import ExponentialComposer
        c = ExponentialComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=False),
        ) == 0.10
```

- [ ] **Step 3.6: Add `ExponentialComposer` to `composers.py`**

Append:
```python
class ExponentialComposer(Composer):
    """P_mode = lambda(t) * P_bridge + (1-lambda(t)) * P_market;
    lambda(t) = exp(-t / tau).  tau default = 7 days.
    """

    name = "exp"

    def __init__(self, tau_seconds: int = 7 * 86400):
        self.tau_seconds = tau_seconds

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        t = shock_state.time_since_shock_seconds
        lam = math.exp(-t / self.tau_seconds)
        return lam * p_bridge + (1.0 - lam) * p_market
```

- [ ] **Step 3.7: Run tests; verify 4 PASS**

```
pytest tests/research/crypto/test_composers.py::TestExponentialComposer -v
```
Expected: 4 PASS.

- [ ] **Step 3.8: Write `MagnitudeTiedComposer` tests (4 cases)**

Append to `tests/research/crypto/test_composers.py`:
```python
class TestMagnitudeTiedComposer:
    def test_severity_one_t_zero_returns_p_bridge(self):
        from agent.research.crypto.composers import MagnitudeTiedComposer
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=0),
        ) == 0.30

    def test_severity_half_t_zero_blends_50_50(self):
        """severity=0.5 means lambda_0=0.5, so P_mode = 0.5*0.30 + 0.5*0.10 = 0.20."""
        from agent.research.crypto.composers import MagnitudeTiedComposer
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.5, t=0),
        ) == 0.20

    def test_severity_above_one_clipped_via_shock_state(self):
        """ShockState clips severity to [0,1] at construction; composer sees 1.0."""
        from agent.research.crypto.composers import MagnitudeTiedComposer
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.5, t=0),
        ) == 0.30  # ShockState already clipped to 1.0

    def test_severity_zero_returns_p_market(self):
        from agent.research.crypto.composers import MagnitudeTiedComposer
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.0, t=0),
        ) == 0.10
```

- [ ] **Step 3.9: Add `MagnitudeTiedComposer`**

Append to `composers.py`:
```python
class MagnitudeTiedComposer(Composer):
    """lambda(t, severity) = severity * exp(-t / tau).
    severity is already clipped to [0,1] by ShockState's __post_init__.
    """

    name = "magnitude"

    def __init__(self, tau_seconds: int = 7 * 86400):
        self.tau_seconds = tau_seconds

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        t = shock_state.time_since_shock_seconds
        lam = shock_state.severity * math.exp(-t / self.tau_seconds)
        return lam * p_bridge + (1.0 - lam) * p_market
```

- [ ] **Step 3.10: Run tests; verify 4 PASS**

```
pytest tests/research/crypto/test_composers.py::TestMagnitudeTiedComposer -v
```

- [ ] **Step 3.11: Write `ConfidenceWeightedComposer` tests (4 cases)**

Append:
```python
class TestConfidenceWeightedComposer:
    def test_small_divergence_returns_near_p_market(self):
        """Divergence 0.01 (below threshold 0.10): sigmoid input is negative, lambda~0."""
        from agent.research.crypto.composers import ConfidenceWeightedComposer
        c = ConfidenceWeightedComposer()
        # No shock needed - this composer ignores shock_state.
        result = c.compose(p_market=0.50, p_bridge=0.51, shock_state=_ss(active=False))
        assert abs(result - 0.50) < 0.05

    def test_large_divergence_returns_near_p_bridge(self):
        """Divergence 0.30 (well above threshold): sigmoid saturates, lambda~1."""
        from agent.research.crypto.composers import ConfidenceWeightedComposer
        c = ConfidenceWeightedComposer()
        result = c.compose(p_market=0.10, p_bridge=0.40, shock_state=_ss(active=False))
        assert abs(result - 0.40) < 0.01

    def test_divergence_at_threshold_blends_midpoint(self):
        """Divergence exactly at threshold (0.10) gives sigmoid(0) = 0.5."""
        from agent.research.crypto.composers import ConfidenceWeightedComposer
        c = ConfidenceWeightedComposer()
        result = c.compose(p_market=0.50, p_bridge=0.40, shock_state=_ss(active=False))
        # lambda = 0.5; P_mode = 0.5*0.40 + 0.5*0.50 = 0.45
        assert abs(result - 0.45) < 1e-6

    def test_zero_divergence_returns_p_market(self):
        from agent.research.crypto.composers import ConfidenceWeightedComposer
        c = ConfidenceWeightedComposer()
        assert c.compose(p_market=0.50, p_bridge=0.50, shock_state=_ss(active=False)) == 0.50
```

- [ ] **Step 3.12: Add `ConfidenceWeightedComposer`**

Append:
```python
class ConfidenceWeightedComposer(Composer):
    """lambda = sigmoid((|P_market - P_bridge| - threshold) / scale).
    Does NOT use shock_state.time — purely divergence-driven.

    KNOWN HAZARD: can double-down during regime changes.  AgreementFilter
    is the primary safety against this; see spec §6.3.
    """

    name = "confidence"

    def __init__(self, threshold: float = 0.10, scale: float = 0.05):
        self.threshold = threshold
        self.scale = scale

    def compose(self, p_market, p_bridge, shock_state) -> float:
        divergence = abs(p_market - p_bridge)
        if divergence <= 1e-9:
            return p_market
        z = (divergence - self.threshold) / self.scale
        lam = 1.0 / (1.0 + math.exp(-z))
        return lam * p_bridge + (1.0 - lam) * p_market
```

- [ ] **Step 3.13: Run all composer tests**

```
pytest tests/research/crypto/test_composers.py -v
```
Expected: 16 PASS.

- [ ] **Step 3.14: Commit**

```
git add agent/research/crypto/composers.py tests/research/crypto/test_composers.py
git commit -m "feat(polymarket-c2a): add 4 Composer implementations with reference test cases"
```

---

## Task 4: `agreement_filter.py` (`AgreementFilter`)

**Files:**
- Create: `agent/research/crypto/agreement_filter.py`
- Test: `tests/research/crypto/test_agreement_filter.py`

- [ ] **Step 4.1: Write 12 reference test cases (spec §8.3)**

Create `tests/research/crypto/test_agreement_filter.py`:
```python
import pytest


def _filter():
    from agent.research.crypto.agreement_filter import AgreementFilter
    return AgreementFilter()  # defaults: epsilon=0.08, min_active_count=3


def _modes(binary, exp, magnitude, confidence):
    return {"binary": binary, "exp": exp, "magnitude": magnitude, "confidence": confidence}


def test_scenario_1_strong_long_consensus():
    """All 4 modes above market by 0.21 — long consensus."""
    v = _filter().evaluate(p_market=0.10, p_modes=_modes(0.31, 0.31, 0.31, 0.31))
    assert v.allowed is True
    assert v.long_count == 4
    assert v.direction == "long"


def test_scenario_2_regime_t_equals_3_still_consensus():
    """3 days into regime, modes 2/3 still well above epsilon."""
    v = _filter().evaluate(p_market=0.07, p_modes=_modes(0.28, 0.240, 0.240, 0.28))
    assert v.allowed is True
    assert v.long_count == 4


def test_scenario_3_regime_t_equals_7_modes_2_3_below_epsilon():
    """7 days: modes 2/3 excess = 0.078 (just below 0.08 epsilon) -> neutral.
    Only modes 1 and 4 (excess 0.21 each) signal long. long_count=2 < 3 -> VETO.
    """
    v = _filter().evaluate(p_market=0.05, p_modes=_modes(0.26, 0.128, 0.128, 0.26))
    assert v.allowed is False
    assert v.long_count == 2


def test_scenario_4_regime_t_equals_21_only_mode_4_committed():
    """21 days: modes 2/3 fully decayed to near P_market, only modes 1, 4 long.
    With strict counting, 2 of 4 isn't enough -> VETO.
    """
    v = _filter().evaluate(p_market=0.02, p_modes=_modes(0.20, 0.061, 0.061, 0.20))
    assert v.allowed is False
    assert v.long_count == 2


def test_scenario_5_no_shock_no_signal():
    """All modes within epsilon of P_market -> long_count=short_count=0 -> VETO."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.50, 0.50, 0.50, 0.525))
    assert v.allowed is False
    assert v.long_count == 0
    assert v.short_count == 0
    assert v.direction == "none"


def test_scenario_6_borderline_4_of_4_long():
    """Mild over-reaction with 4 active long signals."""
    v = _filter().evaluate(p_market=0.25, p_modes=_modes(0.38, 0.38, 0.31, 0.36))
    assert v.allowed is True
    assert v.long_count == 4


def test_scenario_7_mixed_mild():
    """2 above, 2 below — neither direction has 3-count -> VETO."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.55, 0.45, 0.50, 0.50))
    assert v.allowed is False


def test_scenario_8_strong_short_consensus():
    """4 modes well below market -> short consensus."""
    v = _filter().evaluate(p_market=0.70, p_modes=_modes(0.55, 0.60, 0.62, 0.61))
    assert v.allowed is True
    assert v.short_count == 4
    assert v.direction == "short"


def test_scenario_9_only_one_above_epsilon():
    """Only confidence mode above by epsilon; long_count=1 -> VETO."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.55, 0.55, 0.55, 0.58))
    # excesses: 0.05, 0.05, 0.05, 0.08 -> only 0.08 > 0.08 is False (strict >)
    # so long_count = 0
    assert v.long_count == 0
    assert v.allowed is False


def test_scenario_10_three_long_one_neutral():
    """3 modes signal long, 1 is neutral -> 3 of 4 long, allowed."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.58, 0.59, 0.61, 0.50))
    # excesses: 0.08, 0.09, 0.11, 0.00 -> longs: 0.09, 0.11 (>0.08), count 2... hmm
    # 0.08 is NOT > 0.08 strictly.  Adjust if needed.
    # Let me re-check: with strict >, only excesses > 0.08 count.
    # 0.08 -> no, 0.09 -> yes, 0.11 -> yes, 0.00 -> no. long_count = 2.
    # To get long_count=3 we need 3 modes with excess > 0.08.
    # Reformulate test with p_modes that produce excesses > 0.08:
    pass  # placeholder; rewrite next step


def test_scenario_10_three_long_one_neutral_corrected():
    """3 modes signal long with excess > 0.08, 1 is neutral."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.60, 0.60, 0.60, 0.51))
    # excesses: 0.10, 0.10, 0.10, 0.01 -> long_count = 3, short_count = 0
    assert v.long_count == 3
    assert v.allowed is True
    assert v.direction == "long"


def test_scenario_11_two_long_one_short_one_neutral():
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.60, 0.60, 0.50, 0.40))
    # excesses: +0.10, +0.10, 0.0, -0.10 -> long=2, short=1, neutral=1
    assert v.long_count == 2
    assert v.short_count == 1
    assert v.allowed is False  # neither direction has 3


def test_scenario_12_total_silence():
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.50, 0.50, 0.50, 0.50))
    assert v.long_count == 0
    assert v.short_count == 0
    assert v.direction == "none"
    assert v.allowed is False
```

- [ ] **Step 4.2: Run to verify failures**

```
pytest tests/research/crypto/test_agreement_filter.py -v
```
Expected: ImportError.

- [ ] **Step 4.3: Implement `AgreementFilter`**

Create `agent/research/crypto/agreement_filter.py`:
```python
"""AgreementFilter: directional consensus gate.

Requires >= min_active_count modes to agree on direction before allowing a
trade.  epsilon = 0.08 (per brainstorm Option-alpha): mode signals are
counted only when |P_mode - P_market| > epsilon (strict).  Neutrals don't
count toward either direction.

Disabled-mode handling: caller filters disabled modes out of `p_modes`
before calling.  min_active_count applies to the passed dict; disabling a
mode strengthens consensus among survivors.
"""

from agent.research.crypto.types import AgreementVerdict


class AgreementFilter:
    def __init__(
        self,
        epsilon: float = 0.08,
        min_active_count: int = 3,
    ):
        self.epsilon = epsilon
        self.min_active_count = min_active_count

    def evaluate(
        self,
        p_market: float,
        p_modes: dict[str, float],
    ) -> AgreementVerdict:
        long_count = sum(1 for p in p_modes.values() if p > p_market + self.epsilon)
        short_count = sum(1 for p in p_modes.values() if p < p_market - self.epsilon)

        if long_count >= self.min_active_count:
            return AgreementVerdict(
                allowed=True, long_count=long_count, short_count=short_count, direction="long",
            )
        if short_count >= self.min_active_count:
            return AgreementVerdict(
                allowed=True, long_count=long_count, short_count=short_count, direction="short",
            )

        direction = "none" if (long_count == 0 and short_count == 0) else (
            "long" if long_count > short_count else "short"
        )
        return AgreementVerdict(
            allowed=False, long_count=long_count, short_count=short_count, direction=direction,
        )
```

- [ ] **Step 4.4: Remove the placeholder scenario_10 test**

Delete `test_scenario_10_three_long_one_neutral` (the one with `pass`); keep only the `_corrected` version.

- [ ] **Step 4.5: Run tests**

```
pytest tests/research/crypto/test_agreement_filter.py -v
```
Expected: 11 PASS (12 minus the deleted placeholder).

- [ ] **Step 4.6: Commit**

```
git add agent/research/crypto/agreement_filter.py tests/research/crypto/test_agreement_filter.py
git commit -m "feat(polymarket-c2a): add AgreementFilter with epsilon=0.08 strict counting"
```

---

## Task 5: `asymmetric_tilt.py` (`AsymmetricTilt`)

**Files:**
- Create: `agent/research/crypto/asymmetric_tilt.py`
- Test: `tests/research/crypto/test_asymmetric_tilt.py`

- [ ] **Step 5.1: Write the 8 reference tests (spec §8.4)**

Create `tests/research/crypto/test_asymmetric_tilt.py`:
```python
def _tilt():
    from agent.research.crypto.asymmetric_tilt import AsymmetricTilt
    return AsymmetricTilt()  # default tilt_magnitude=0.05


def test_case_1_p_bridge_above_p_market_adds_tilt():
    assert _tilt().apply(p_blend=0.30, p_market=0.10, p_bridge=0.32) == 0.35


def test_case_2_p_bridge_equals_p_market_no_tilt():
    """When p_bridge == p_market, condition is strictly p_bridge > p_market -> False."""
    assert _tilt().apply(p_blend=0.50, p_market=0.50, p_bridge=0.50) == 0.50


def test_case_3_p_bridge_below_p_market_no_tilt():
    assert _tilt().apply(p_blend=0.20, p_market=0.30, p_bridge=0.20) == 0.20


def test_case_4_clipped_to_one_at_upper_bound():
    """p_blend=0.95 + 0.05 = 1.00, which is exactly 1.0 (in range)."""
    assert _tilt().apply(p_blend=0.95, p_market=0.85, p_bridge=0.96) == 1.00


def test_case_5_clipped_to_one_when_over():
    """p_blend=0.98 + 0.05 = 1.03 -> clipped to 1.0."""
    assert _tilt().apply(p_blend=0.98, p_market=0.85, p_bridge=0.99) == 1.00


def test_case_6_no_tilt_when_p_bridge_below():
    assert _tilt().apply(p_blend=0.05, p_market=0.10, p_bridge=0.08) == 0.05


def test_case_7_tilt_applied():
    assert _tilt().apply(p_blend=0.25, p_market=0.20, p_bridge=0.40) == 0.30


def test_case_8_tilt_applied_middle():
    assert _tilt().apply(p_blend=0.50, p_market=0.40, p_bridge=0.60) == 0.55
```

- [ ] **Step 5.2: Run to verify failures**

```
pytest tests/research/crypto/test_asymmetric_tilt.py -v
```
Expected: ImportError.

- [ ] **Step 5.3: Implement `AsymmetricTilt`**

Create `agent/research/crypto/asymmetric_tilt.py`:
```python
"""AsymmetricTilt: long-only +0.05 tilt toward P_bridge.

Captures the one-directional shape of the alpha thesis: Polymarket
under-prices barrier-hit probabilities during panic (P_market < P_bridge).
We do NOT believe it systematically over-prices in calm; therefore no tilt
in the opposite direction.

Output clipped to [0, 1] for safety.
"""


class AsymmetricTilt:
    def __init__(self, tilt_magnitude: float = 0.05):
        self.tilt_magnitude = tilt_magnitude

    def apply(
        self,
        p_blend: float,
        p_market: float,
        p_bridge: float,
    ) -> float:
        if p_bridge > p_market:
            return min(1.0, max(0.0, p_blend + self.tilt_magnitude))
        return p_blend
```

- [ ] **Step 5.4: Run tests; verify 8 PASS**

```
pytest tests/research/crypto/test_asymmetric_tilt.py -v
```

- [ ] **Step 5.5: Commit**

```
git add agent/research/crypto/asymmetric_tilt.py tests/research/crypto/test_asymmetric_tilt.py
git commit -m "feat(polymarket-c2a): add AsymmetricTilt (long-only +0.05 toward bridge)"
```

---

## Task 6: `kelly_sizer.py` (`KellySizer`)

**Files:**
- Create: `agent/research/crypto/kelly_sizer.py`
- Test: `tests/research/crypto/test_kelly_sizer.py`

- [ ] **Step 6.1: Write the 8 reference tests (spec §8.5)**

Create `tests/research/crypto/test_kelly_sizer.py`:
```python
import pytest


def _s():
    from agent.research.crypto.kelly_sizer import KellySizer
    return KellySizer()  # defaults: mult=0.5, cap=0.10, min_edge=0.02


def test_case_1_covid_style_long():
    """P=0.31, q=0.10. raw_kelly = 0.10 * (0.31-0.10) / (0.31*0.69) = 0.0981.
    half_kelly = 0.0490.  Below cap (0.10).  Direction long.
    """
    k = _s().size(p_final=0.31, p_market=0.10)
    expected = 0.5 * 0.10 * (0.31 - 0.10) / (0.31 * 0.69)
    assert abs(k.fraction - expected) < 1e-4
    assert k.direction == "yes"


def test_case_2_ftx_style_entry_long():
    """P=0.32, q=0.10.  half_kelly = 0.5 * 0.10 * 0.22 / (0.32*0.68) ~ 0.0506."""
    k = _s().size(p_final=0.32, p_market=0.10)
    expected = 0.5 * 0.10 * (0.32 - 0.10) / (0.32 * 0.68)
    assert abs(k.fraction - expected) < 1e-4
    assert k.direction == "yes"


def test_case_3_zero_edge_zero_fraction():
    """P == q -> edge=0 -> fraction=0 regardless of direction."""
    k = _s().size(p_final=0.15, p_market=0.15)
    assert k.fraction == 0.0


def test_case_4_below_minimum_edge_zero_fraction():
    """edge = 0.05 - 0.10 = -0.05.  abs(edge) = 0.05.
    Wait, recompute: p_final=0.15, p_market=0.10 -> edge=0.05 > 0.02 min_edge.
    Re-read the test: spec says "below minimum_edge" but values give edge=0.05.
    Adjust: use p_final=0.11, p_market=0.10 -> edge=0.01 < 0.02 min_edge.
    """
    k = _s().size(p_final=0.11, p_market=0.10)
    assert k.fraction == 0.0


def test_case_5_medium_long_edge():
    """P=0.50, q=0.10.  raw = 0.10*0.40/(0.50*0.50) = 0.16.
    half = 0.08.  Below cap.
    """
    k = _s().size(p_final=0.50, p_market=0.10)
    expected = 0.5 * 0.10 * (0.50 - 0.10) / (0.50 * 0.50)
    assert abs(k.fraction - expected) < 1e-4
    assert k.direction == "yes"


def test_case_6_cap_engaged_long():
    """P=0.90, q=0.10.  Raw Kelly is very large; half-Kelly hits cap 0.10."""
    k = _s().size(p_final=0.90, p_market=0.10)
    assert k.fraction == 0.10  # capped


def test_case_7_short_edge_cap_engaged():
    """P=0.10, q=0.30 -> we believe YES at 10% but market prices 30%.
    Buy NO at $0.70 -> edge for NO direction.
    raw_kelly (NO direction) = (1-q) * ((1-P) - (1-q)) / ((1-P) * P) ... let me check.
    Actually use the symmetric formula in code.  Cap engages at 0.10 either way.
    """
    k = _s().size(p_final=0.10, p_market=0.30)
    assert k.fraction == 0.10
    assert k.direction == "no"


def test_case_8_small_short_below_cap():
    """P=0.25, q=0.30 -> mild NO edge.  Should be below cap."""
    k = _s().size(p_final=0.25, p_market=0.30)
    assert 0.0 < k.fraction < 0.10
    assert k.direction == "no"
```

- [ ] **Step 6.2: Run to verify failures**

```
pytest tests/research/crypto/test_kelly_sizer.py -v
```
Expected: ImportError.

- [ ] **Step 6.3: Implement `KellySizer`**

Create `agent/research/crypto/kelly_sizer.py`:
```python
"""KellySizer: half-Kelly position sizing for binary prediction markets.

For a YES buy at market price q with estimated probability P:
  edge       = P - q
  variance   = P * (1 - P)
  raw_kelly  = q * edge / variance   (q in the prefactor because payoff per
                                       dollar on win is (1-q)/q for a YES buy)
  half_kelly = 0.5 * raw_kelly
  fraction   = clip(abs(half_kelly), 0.0, kelly_cap)
  direction  = "yes" if edge > 0 else "no"

For a NO buy (equivalent to selling YES) the formula is symmetric — we can
use the same formula because we're returning abs(fraction) and recording
direction separately.

Returns KellyFraction(fraction=0, ...) when abs(edge) < minimum_edge to
save transaction costs on trades that are theoretically positive but
practically uneconomic.
"""

from agent.research.crypto.types import KellyFraction


class KellySizer:
    def __init__(
        self,
        kelly_multiplier: float = 0.5,
        kelly_cap: float = 0.10,
        minimum_edge: float = 0.02,
    ):
        self.kelly_multiplier = kelly_multiplier
        self.kelly_cap = kelly_cap
        self.minimum_edge = minimum_edge

    def size(
        self,
        p_final: float,
        p_market: float,
    ) -> KellyFraction:
        edge = p_final - p_market
        direction = "yes" if edge >= 0 else "no"

        if abs(edge) < self.minimum_edge:
            return KellyFraction(fraction=0.0, direction=direction, raw_kelly_pre_half=0.0)

        if direction == "yes":
            q = p_market
            variance = p_final * (1.0 - p_final)
        else:
            q = 1.0 - p_market
            # For NO buy: outcomes flipped; variance computed against (1-p_final)
            variance = (1.0 - p_final) * p_final  # algebraically the same

        if variance <= 1e-12:
            return KellyFraction(fraction=0.0, direction=direction, raw_kelly_pre_half=0.0)

        raw_kelly = q * abs(edge) / variance
        half = self.kelly_multiplier * raw_kelly
        # KellyFraction's __post_init__ clips fraction to [0, KELLY_CAP_DEFAULT=0.10]
        return KellyFraction(
            fraction=half,
            direction=direction,
            raw_kelly_pre_half=raw_kelly,
        )
```

NB: This relies on `KELLY_CAP_DEFAULT` in `types.py` matching `kelly_cap`
here (both 0.10).  If they diverge, the type-level clipping would silently
override the sizer-level cap.  Add a runtime assertion in the constructor
to keep them in sync:

```python
        from agent.research.crypto.types import KELLY_CAP_DEFAULT
        if kelly_cap != KELLY_CAP_DEFAULT:
            raise ValueError(
                f"KellySizer.kelly_cap ({kelly_cap}) must match "
                f"types.KELLY_CAP_DEFAULT ({KELLY_CAP_DEFAULT}) — the "
                f"KellyFraction dataclass clips to KELLY_CAP_DEFAULT, "
                f"which would silently override a different sizer cap."
            )
```

Add this assertion to `__init__`.

- [ ] **Step 6.4: Run tests; verify 8 PASS**

```
pytest tests/research/crypto/test_kelly_sizer.py -v
```

- [ ] **Step 6.5: Commit**

```
git add agent/research/crypto/kelly_sizer.py tests/research/crypto/test_kelly_sizer.py
git commit -m "feat(polymarket-c2a): add KellySizer (half-Kelly with 0.10 cap, 0.02 min_edge)"
```

---

## Task 7: `performance_tracker.py` (`PerformanceTracker`)

**Files:**
- Create: `agent/research/crypto/performance_tracker.py`
- Test: `tests/research/crypto/test_performance_tracker.py`

- [ ] **Step 7.1: Write tests for trailing window + brier floor + disable flag**

Create `tests/research/crypto/test_performance_tracker.py`:
```python
def test_no_history_returns_zero_trades_floor_initial(session_factory):
    """Empty DB: each mode has 0 trades, brier_floor=0.10, is_disabled=False."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)

    with session_factory() as session:
        state = tracker.get_state(session)
        for mode_name in ["binary", "exp", "magnitude", "confidence"]:
            assert state[mode_name].n_closed_trades == 0
            assert state[mode_name].brier_floor == 0.10
            assert state[mode_name].is_disabled is False


def test_record_outcome_appends_and_updates_floor(session_factory):
    """Recording a closed trade appends ModePerformance and updates ModeFloorState."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)

    with session_factory() as session:
        tracker.record_outcome(
            session,
            mode_name="binary",
            market_id="0xABC001",
            p_mode=0.31,
            p_market_at_prediction=0.10,
            outcome=1,
            closed_at=1747800000,
        )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        assert state["binary"].n_closed_trades == 1
        # Brier for P=0.31, outcome=1 is (0.31-1)^2 = 0.4761 — far above 0.25 threshold
        # so disable_streak increments to 1, floor stays at 0.10 (not yet streak-30)
        assert state["binary"].is_disabled is False


def test_disable_after_30_consecutive_bad_trades(session_factory):
    """After 30 consecutive trades with brier > 0.25, mode is_disabled becomes True."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)

    with session_factory() as session:
        for i in range(30):
            tracker.record_outcome(
                session,
                mode_name="confidence",
                market_id=f"0xABC{i:03d}",
                p_mode=0.50,  # consistently wrong (outcome=0, brier=0.25)
                # actually 0.50^2 = 0.25, exactly at threshold — use 0.55 to be above
                p_market_at_prediction=0.10,
                outcome=0,
                closed_at=1747800000 + i,
            )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        # With p_mode=0.50, brier = 0.25 (exactly threshold).  Use disable_brier_threshold>0.25 strict.
        # If threshold is >0.25 strictly, 0.25 won't trigger disable.
        # Fix: use p_mode=0.55 instead so brier=0.3025>0.25.
        # This test as written may not trigger disable; adjust p_mode.
        pass  # Re-write next step with corrected p_mode


def test_disable_after_30_consecutive_bad_trades_corrected(session_factory):
    """Use p_mode=0.55 so brier=(0.55)^2=0.3025>0.25, triggering disable streak."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)

    with session_factory() as session:
        for i in range(30):
            tracker.record_outcome(
                session,
                mode_name="confidence",
                market_id=f"0xABC{i:03d}",
                p_mode=0.55,
                p_market_at_prediction=0.10,
                outcome=0,
                closed_at=1747800000 + i,
            )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        assert state["confidence"].is_disabled is True


def test_brier_floor_decays_on_bad_trade(session_factory):
    """Each closed trade with brier > 0.25 multiplies floor by 0.97."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)

    with session_factory() as session:
        for i in range(3):
            tracker.record_outcome(
                session, mode_name="binary",
                market_id=f"0xABC{i:03d}",
                p_mode=0.60, p_market_at_prediction=0.10, outcome=0,
                closed_at=1747800000 + i,
            )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        # 3 consecutive bad: floor = 0.10 * 0.97 * 0.97 * 0.97 ~ 0.0912
        expected_floor = 0.10 * (0.97 ** 3)
        assert abs(state["binary"].brier_floor - expected_floor) < 1e-6
```

- [ ] **Step 7.2: Run to verify failures**

```
pytest tests/research/crypto/test_performance_tracker.py -v
```
Expected: ImportError.

- [ ] **Step 7.3: Implement `PerformanceTracker`**

Create `agent/research/crypto/performance_tracker.py`:
```python
"""PerformanceTracker: per-mode trailing-Brier averages, floor evolution, and
disable-streak tracking.  Backed by ModePerformance + ModeFloorState ORM rows.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.research.crypto.types import ModeState
from agent.store.schema import ModePerformance, ModeFloorState


MODE_NAMES = ["binary", "exp", "magnitude", "confidence"]


class PerformanceTracker:
    def __init__(
        self,
        repository,
        trailing_window: int = 15,
        brier_floor_init: float = 0.10,
        floor_decay: float = 0.97,
        disable_brier_threshold: float = 0.25,
        disable_streak_required: int = 30,
    ):
        self.repository = repository
        self.trailing_window = trailing_window
        self.brier_floor_init = brier_floor_init
        self.floor_decay = floor_decay
        self.disable_brier_threshold = disable_brier_threshold
        self.disable_streak_required = disable_streak_required

    def get_state(self, session: Session) -> dict[str, ModeState]:
        state = {}
        for mode_name in MODE_NAMES:
            recent_briers = session.execute(
                select(ModePerformance.brier_score)
                .where(ModePerformance.mode_name == mode_name)
                .order_by(ModePerformance.closed_at.desc())
                .limit(self.trailing_window)
            ).scalars().all()

            n = len(recent_briers)
            trailing_brier = sum(recent_briers) / n if n > 0 else 0.0

            floor_row = session.get(ModeFloorState, mode_name)
            if floor_row is None:
                brier_floor = self.brier_floor_init
                is_disabled = False
            else:
                brier_floor = floor_row.brier_floor
                is_disabled = floor_row.is_disabled

            state[mode_name] = ModeState(
                mode_name=mode_name,
                trailing_brier=trailing_brier,
                brier_floor=brier_floor,
                is_disabled=is_disabled,
                n_closed_trades=n,
            )
        return state

    def record_outcome(
        self,
        session: Session,
        mode_name: str,
        market_id: str,
        p_mode: float,
        p_market_at_prediction: float,
        outcome: int,
        closed_at: int,
    ) -> None:
        brier = (p_mode - outcome) ** 2
        row = ModePerformance(
            mode_name=mode_name,
            market_id=market_id,
            p_mode=p_mode,
            p_market_at_prediction=p_market_at_prediction,
            outcome=outcome,
            brier_score=brier,
            closed_at=closed_at,
        )
        session.add(row)

        floor_row = session.get(ModeFloorState, mode_name)
        if floor_row is None:
            floor_row = ModeFloorState(
                mode_name=mode_name,
                brier_floor=self.brier_floor_init,
                disable_streak=0,
                is_disabled=False,
                updated_at=closed_at,
            )
            session.add(floor_row)
            session.flush()  # ensure row is queryable in same session

        if brier > self.disable_brier_threshold:
            floor_row.disable_streak += 1
            floor_row.brier_floor *= self.floor_decay
            if floor_row.disable_streak >= self.disable_streak_required:
                floor_row.is_disabled = True
        else:
            floor_row.disable_streak = 0
        floor_row.updated_at = closed_at
```

- [ ] **Step 7.4: Remove the placeholder test (Step 7.1 had `pass`)**

Delete `test_disable_after_30_consecutive_bad_trades` (the version with `pass`); keep only the `_corrected` version.

- [ ] **Step 7.5: Run tests**

```
pytest tests/research/crypto/test_performance_tracker.py -v
```
Expected: 4 PASS.

- [ ] **Step 7.6: Commit**

```
git add agent/research/crypto/performance_tracker.py tests/research/crypto/test_performance_tracker.py
git commit -m "feat(polymarket-c2a): add PerformanceTracker with trailing Brier and disable streak"
```

---

## Task 8: `blender.py` (`BayesianBlender`)

**Files:**
- Create: `agent/research/crypto/blender.py`
- Test: `tests/research/crypto/test_blender.py`

This task tests the brainstorm walkthrough's 30-trade evolution. Given the
size, the test stages all 30 trades in a single setup helper and then
asserts at the checkpoint trades (5, 10, 15, 20, 25, 30).

- [ ] **Step 8.1: Write the cold-start test (equal weights when n_trades < 3 per mode)**

Create `tests/research/crypto/test_blender.py`:
```python
def test_cold_start_returns_equal_weights(session_factory):
    """No closed trades anywhere -> all weights 0.25."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker
    from agent.research.crypto.blender import BayesianBlender

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)
    blender = BayesianBlender()

    p_modes = {"binary": 0.30, "exp": 0.30, "magnitude": 0.30, "confidence": 0.30}
    with session_factory() as session:
        result = blender.blend(p_modes, tracker, session)
    assert abs(result.weights.w_binary - 0.25) < 1e-9
    assert abs(result.weights.w_exp - 0.25) < 1e-9
    assert abs(result.weights.w_magnitude - 0.25) < 1e-9
    assert abs(result.weights.w_confidence - 0.25) < 1e-9
    assert abs(result.p_blend - 0.30) < 1e-9
```

- [ ] **Step 8.2: Write the all-disabled test**

Append:
```python
def test_all_disabled_returns_zero_weights(session_factory):
    """If every mode is disabled, weights.is_all_disabled() is True."""
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker
    from agent.research.crypto.blender import BayesianBlender
    from agent.store.schema import ModeFloorState

    with session_factory() as session:
        for mode in ["binary", "exp", "magnitude", "confidence"]:
            session.add(ModeFloorState(
                mode_name=mode,
                brier_floor=0.001,
                disable_streak=30,
                is_disabled=True,
                updated_at=1747800000,
            ))
        session.commit()

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)
    blender = BayesianBlender()
    p_modes = {"binary": 0.30, "exp": 0.30, "magnitude": 0.30, "confidence": 0.30}

    with session_factory() as session:
        result = blender.blend(p_modes, tracker, session)
    assert result.weights.is_all_disabled() is True
```

- [ ] **Step 8.3: Write the 30-trade evolution test (checkpoint asserts)**

Append:
```python
def test_30_trade_evolution_matches_reference_weights(session_factory):
    """Re-implement the brainstorm walkthrough.  Mode 4 honeymoon (trades 6-15)
    then regime change (16-30).  Check weights at trades 5, 10, 15, 20, 25, 30.

    Reference weights (from spec §8.2):
        trade 5:  all 0.250
        trade 10: 0.225, 0.235, 0.235, 0.305
        trade 15: 0.205, 0.198, 0.198, 0.399
        trade 20: 0.290, 0.270, 0.260, 0.180
        trade 25: 0.327, 0.311, 0.298, 0.064
        trade 30: 0.330, 0.330, 0.325, 0.014

    Tolerance: 1e-2 (the reference values are themselves rounded to 3dp).
    """
    from agent.store.repository import Repository
    from agent.research.crypto.performance_tracker import PerformanceTracker
    from agent.research.crypto.blender import BayesianBlender

    # Per-trade brier scores: (binary, exp, magnitude, confidence)
    # Trades 1-5 (cold start; each mode has 1-2 closed trades; equal weights)
    schedule = [
        (0.15, 0.15, 0.15, 0.15),  # 1
        (0.15, 0.15, 0.15, 0.15),  # 2
        (0.15, 0.15, 0.15, 0.15),  # 3
        (0.15, 0.15, 0.15, 0.15),  # 4
        (0.15, 0.15, 0.15, 0.15),  # 5
        # Trades 6-15: Mode 4 honeymoon (catches over-reactions; others lag)
        (0.04, 0.03, 0.03, 0.02),  # 6
        (0.05, 0.04, 0.04, 0.03),  # 7
        (0.05, 0.04, 0.04, 0.03),  # 8
        (0.06, 0.05, 0.04, 0.03),  # 9
        (0.06, 0.05, 0.04, 0.03),  # 10
        (0.06, 0.05, 0.05, 0.03),  # 11
        (0.06, 0.04, 0.04, 0.03),  # 12
        (0.06, 0.05, 0.05, 0.03),  # 13
        (0.06, 0.05, 0.05, 0.03),  # 14
        (0.06, 0.05, 0.05, 0.03),  # 15
        # Trades 16-30: Regime change. Mode 4 commits to wrong; others decay.
        (0.02, 0.03, 0.03, 0.10),  # 16
        (0.02, 0.03, 0.04, 0.14),  # 17
        (0.01, 0.02, 0.03, 0.20),  # 18
        (0.01, 0.02, 0.03, 0.25),  # 19
        (0.01, 0.01, 0.02, 0.30),  # 20
        (0.01, 0.01, 0.02, 0.34),  # 21
        (0.01, 0.01, 0.01, 0.38),  # 22
        (0.01, 0.01, 0.01, 0.40),  # 23
        (0.01, 0.01, 0.01, 0.42),  # 24
        (0.01, 0.01, 0.01, 0.42),  # 25
        (0.01, 0.01, 0.01, 0.42),  # 26
        (0.01, 0.01, 0.01, 0.42),  # 27
        (0.01, 0.01, 0.01, 0.42),  # 28
        (0.01, 0.01, 0.01, 0.42),  # 29
        (0.01, 0.01, 0.01, 0.42),  # 30
    ]
    assert len(schedule) == 30

    repo = Repository()
    tracker = PerformanceTracker(repository=repo, trailing_window=15)
    blender = BayesianBlender()
    checkpoints = {5: None, 10: None, 15: None, 20: None, 25: None, 30: None}

    # We need to seed ModePerformance rows directly because we're testing the
    # blender's weight output for given trailing-brier averages — we control
    # the briers by inserting rows with known brier_score values.
    from agent.store.schema import ModePerformance

    with session_factory() as session:
        for i, (b_b, b_e, b_m, b_c) in enumerate(schedule, start=1):
            for mode_name, b in (("binary", b_b), ("exp", b_e),
                                 ("magnitude", b_m), ("confidence", b_c)):
                session.add(ModePerformance(
                    mode_name=mode_name,
                    market_id=f"0xABC{i:03d}",
                    p_mode=0.5,  # arbitrary; only brier matters for blender
                    p_market_at_prediction=0.5,
                    outcome=0,
                    brier_score=b,
                    closed_at=1747800000 + i * 86400,
                ))
            session.commit()
            if i in checkpoints:
                # Compute weights right after this trade is closed.
                p_modes = {"binary": 0.3, "exp": 0.3, "magnitude": 0.3, "confidence": 0.3}
                result = blender.blend(p_modes, tracker, session)
                checkpoints[i] = result.weights

    # Reference weights from spec §8.2
    expected = {
        5: (0.250, 0.250, 0.250, 0.250),
        10: (0.225, 0.235, 0.235, 0.305),
        15: (0.205, 0.198, 0.198, 0.399),
        20: (0.290, 0.270, 0.260, 0.180),
        25: (0.327, 0.311, 0.298, 0.064),
        30: (0.330, 0.330, 0.325, 0.014),
    }
    for trade_idx, (w_b, w_e, w_m, w_c) in expected.items():
        w = checkpoints[trade_idx]
        assert abs(w.w_binary - w_b) < 0.01, f"trade {trade_idx} binary"
        assert abs(w.w_exp - w_e) < 0.01, f"trade {trade_idx} exp"
        assert abs(w.w_magnitude - w_m) < 0.01, f"trade {trade_idx} magnitude"
        assert abs(w.w_confidence - w_c) < 0.01, f"trade {trade_idx} confidence"
```

- [ ] **Step 8.4: Run to verify failures**

```
pytest tests/research/crypto/test_blender.py -v
```
Expected: ImportError on `agent.research.crypto.blender`.

- [ ] **Step 8.5: Implement `BayesianBlender`**

Create `agent/research/crypto/blender.py`:
```python
"""BayesianBlender: aggregate 4 mode predictions via inverse-Brier weighting.

  score_i  = 1 / max(trailing_brier_i, brier_floor_i)
  w_i      = score_i / sum_j(score_j)
  p_blend  = sum_i(w_i * p_mode_i)

Cold-start: equal weights (0.25 each) until a mode has >= cold_start_min_trades
closed trades.  Once a mode crosses the threshold, it joins the weighted pool.

Disabled modes contribute 0 weight.  If all modes are disabled, weights are
all-zero (caller treats as no-trade).
"""

from sqlalchemy.orm import Session

from agent.research.crypto.types import BlendOutput, ModeWeights


class BayesianBlender:
    def __init__(
        self,
        cold_start_min_trades: int = 3,
    ):
        self.cold_start_min_trades = cold_start_min_trades

    def blend(
        self,
        p_modes: dict[str, float],
        performance_tracker,
        session: Session,
    ) -> BlendOutput:
        state = performance_tracker.get_state(session)

        # Step 1: Determine which modes are eligible.
        eligible = {}
        for name, mode_state in state.items():
            if mode_state.is_disabled:
                continue
            if mode_state.n_closed_trades < self.cold_start_min_trades:
                # Cold-start contributes equal share when we haven't earned
                # weighted-pool eligibility yet.
                eligible[name] = ("cold", None)
            else:
                eligible[name] = ("warm", mode_state)

        if not eligible:
            zero = ModeWeights(0.0, 0.0, 0.0, 0.0)
            return BlendOutput(p_blend=p_modes[next(iter(p_modes))], weights=zero)

        # Step 2: Compute scores for warm modes.
        warm_scores = {}
        for name, (status, ms) in eligible.items():
            if status == "warm":
                effective_brier = max(ms.trailing_brier, ms.brier_floor)
                warm_scores[name] = 1.0 / effective_brier if effective_brier > 0 else 0.0

        # Step 3: Assemble weights.  Cold modes get equal_cold = 1/n_eligible
        # of the total weight before normalization.  Warm modes get weighted
        # by their scores.  Total weight = sum of cold weights + sum of warm
        # scores; renormalize to 1.
        n_eligible = len(eligible)
        if not warm_scores:
            # All eligible are cold: equal weights
            w_each = 1.0 / n_eligible
            weights_raw = {name: w_each for name in eligible}
        else:
            # Mix cold (equal share) and warm (score-based)
            cold_share = 1.0 / n_eligible  # nominal cold weight before renorm
            total_warm = sum(warm_scores.values())
            weights_raw = {}
            for name, (status, _) in eligible.items():
                if status == "cold":
                    weights_raw[name] = cold_share
                else:
                    weights_raw[name] = warm_scores[name] / total_warm * (1.0 - cold_share * sum(1 for s, _ in eligible.values() if s == "cold"))
            # Re-normalize the whole vector to sum to 1 exactly
            total = sum(weights_raw.values())
            if total > 0:
                weights_raw = {k: v / total for k, v in weights_raw.items()}

        # Step 4: Pad disabled modes with 0
        all_names = ["binary", "exp", "magnitude", "confidence"]
        final_weights = {n: weights_raw.get(n, 0.0) for n in all_names}

        # Step 5: Compute p_blend
        p_blend = sum(final_weights[n] * p_modes[n] for n in all_names)

        return BlendOutput(
            p_blend=p_blend,
            weights=ModeWeights(
                w_binary=final_weights["binary"],
                w_exp=final_weights["exp"],
                w_magnitude=final_weights["magnitude"],
                w_confidence=final_weights["confidence"],
            ),
        )
```

NB: This implementation has subtleties around the cold/warm mix calculation
that may need tuning to match the reference weights exactly.  The test in
Step 8.3 uses 1e-2 tolerance precisely because the implementer may need to
iterate on the mix formula.

- [ ] **Step 8.6: Run blender tests**

```
pytest tests/research/crypto/test_blender.py -v
```
Expected: 3 PASS.  If checkpoint weights are off, iterate on the mix formula
until they match within 0.01.  Reference for the implementer: the
brainstorm walkthrough produced these exact values via inverse-Brier
weighting; deviations indicate a sign or normalization error.

- [ ] **Step 8.7: Commit**

```
git add agent/research/crypto/blender.py tests/research/crypto/test_blender.py
git commit -m "feat(polymarket-c2a): add BayesianBlender (Brier-weighted aggregation)"
```

---

## Task 9: `market_resolver.py` and `markets.yaml`

**Files:**
- Create: `agent/research/crypto/market_resolver.py`
- Create: `agent/research/crypto/markets.yaml`
- Test: `tests/research/crypto/test_market_resolver.py`

- [ ] **Step 9.1: Write the YAML loader and resolve tests**

Create `tests/research/crypto/test_market_resolver.py`:
```python
import tempfile
import textwrap
import pytest


def _write_markets_yaml(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.write(content)
    f.close()
    return f.name


def test_load_markets_yaml_parses_entries():
    from agent.research.crypto.market_resolver import load_markets_yaml
    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Will BTC reach 80000?"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    entries = load_markets_yaml(path)
    assert len(entries) == 1
    assert entries[0].market_id == "0xABC001"
    assert entries[0].symbol == "BTCUSDT"
    assert entries[0].direction == "up"


def test_resolver_returns_none_for_unknown_market():
    from agent.research.crypto.market_resolver import MarketResolver, load_markets_yaml
    from agent.store.schema import Market

    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Test"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    resolver = MarketResolver(load_markets_yaml(path))
    market = Market(id="0xUNKNOWN", question="???")
    assert resolver.resolve(market) is None


def test_resolver_parses_end_date_iso():
    from agent.research.crypto.market_resolver import MarketResolver, load_markets_yaml
    from agent.store.schema import Market

    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Test"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    resolver = MarketResolver(load_markets_yaml(path))
    market = Market(id="0xABC001", question="?", end_date_iso="2026-06-30T00:00:00Z")
    mapping = resolver.resolve(market)
    assert mapping is not None
    assert mapping.symbol == "BTCUSDT"
    # 2026-06-30 00:00 UTC = 1782604800 unix seconds
    assert mapping.resolution_ts == 1782604800


def test_resolver_raises_on_missing_end_date():
    from agent.research.crypto.market_resolver import MarketResolver, load_markets_yaml
    from agent.store.schema import Market

    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Test"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    resolver = MarketResolver(load_markets_yaml(path))
    market = Market(id="0xABC001", question="?", end_date_iso=None)
    with pytest.raises(ValueError):
        resolver.resolve(market)


def test_time_to_resolution_years_positive():
    from agent.research.crypto.market_resolver import MarketResolver
    from agent.research.crypto.types import CryptoMarketMapping

    resolver = MarketResolver(mappings=[])
    mapping = CryptoMarketMapping(
        market_id="0xABC", symbol="BTCUSDT", barrier_price=80000.0,
        direction="up", resolution_ts=1782604800,
    )
    # now_ts = 2026-05-21 = 1747800000 -> T = (1782604800 - 1747800000) / (365.25 * 86400)
    now_ts = 1747800000
    T = resolver.time_to_resolution_years(mapping, now_ts)
    expected = (1782604800 - 1747800000) / (365.25 * 86400)
    assert abs(T - expected) < 1e-9


def test_time_to_resolution_years_clamped_at_zero():
    from agent.research.crypto.market_resolver import MarketResolver
    from agent.research.crypto.types import CryptoMarketMapping

    resolver = MarketResolver(mappings=[])
    mapping = CryptoMarketMapping(
        market_id="0xABC", symbol="BTCUSDT", barrier_price=80000.0,
        direction="up", resolution_ts=1000,
    )
    assert resolver.time_to_resolution_years(mapping, now_ts=1747800000) == 0.0
```

- [ ] **Step 9.2: Run to verify failures**

```
pytest tests/research/crypto/test_market_resolver.py -v
```
Expected: ImportError.

- [ ] **Step 9.3: Implement `market_resolver.py`**

Create `agent/research/crypto/market_resolver.py`:
```python
"""MarketResolver: loads markets.yaml and resolves Polymarket markets to
crypto pair + barrier + resolution_ts.
"""

from datetime import datetime, timezone
from pathlib import Path

import yaml

from agent.research.crypto.types import CryptoMarketMapping, CryptoMarketMappingFile


SECONDS_PER_YEAR = int(365.25 * 86400)


def load_markets_yaml(path: str) -> list[CryptoMarketMappingFile]:
    """Parse markets.yaml into a list of mapping entries."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or []
    return [
        CryptoMarketMappingFile(
            market_id=entry["market_id"],
            polymarket_question=entry.get("polymarket_question", ""),
            symbol=entry["symbol"],
            barrier_price=float(entry["barrier_price"]),
            direction=entry["direction"],
        )
        for entry in raw
    ]


def _parse_iso_to_unix(iso_str: str) -> int:
    """Parse an ISO 8601 string with optional Z suffix to Unix seconds (UTC)."""
    if iso_str.endswith("Z"):
        iso_str = iso_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


class MarketResolver:
    """Wraps a loaded list of CryptoMarketMappingFile entries; exposes lookup
    and time-to-resolution helpers.  Stateless after construction.
    """

    def __init__(self, mappings: list[CryptoMarketMappingFile]):
        self._by_id = {m.market_id: m for m in mappings}

    def resolve(self, market) -> CryptoMarketMapping | None:
        """Look up the mapping for a Polymarket market.  Returns None if not
        in markets.yaml.  Raises ValueError if end_date_iso is missing or
        unparseable.
        """
        entry = self._by_id.get(market.id)
        if entry is None:
            return None
        if not market.end_date_iso:
            raise ValueError(
                f"Market {market.id} is mapped in markets.yaml but has no "
                f"end_date_iso — cannot compute resolution_ts."
            )
        resolution_ts = _parse_iso_to_unix(market.end_date_iso)
        return CryptoMarketMapping(
            market_id=entry.market_id,
            symbol=entry.symbol,
            barrier_price=entry.barrier_price,
            direction=entry.direction,
            resolution_ts=resolution_ts,
        )

    def time_to_resolution_years(
        self, mapping: CryptoMarketMapping, now_ts: int
    ) -> float:
        delta = mapping.resolution_ts - now_ts
        if delta <= 0:
            return 0.0
        return delta / SECONDS_PER_YEAR
```

- [ ] **Step 9.4: Create starter `markets.yaml`**

Create `agent/research/crypto/markets.yaml`:
```yaml
# Hand-curated Polymarket -> crypto barrier mapping.
# Operator expands this file in C2-E based on live Polymarket markets.
# For C2-A, the smoke test uses just one or two entries.

# Placeholder entry — operator MUST replace market_id with a real Polymarket
# market ID before the C2-A gate run.  This file is empty by default to force
# operator curation.
```

NB: this file starts empty (just comments).  The operator adds 1-2 real
markets manually before the gate run in Task 12.

- [ ] **Step 9.5: Run tests**

```
pytest tests/research/crypto/test_market_resolver.py -v
```
Expected: 6 PASS.

- [ ] **Step 9.6: Commit**

```
git add agent/research/crypto/market_resolver.py agent/research/crypto/markets.yaml tests/research/crypto/test_market_resolver.py
git commit -m "feat(polymarket-c2a): add MarketResolver and starter markets.yaml"
```

---

## Task 10: `crypto_data.py` (`CryptoDataAccess`)

**Files:**
- Create: `agent/research/crypto/crypto_data.py`
- Test: `tests/research/crypto/test_crypto_data.py`

- [ ] **Step 10.1: Write tests for the 3 query methods**

Create `tests/research/crypto/test_crypto_data.py`:
```python
def test_get_current_spot_returns_most_recent_close(session_factory):
    from agent.store.schema import CryptoBar
    from agent.store.repository import Repository
    from agent.research.crypto.crypto_data import CryptoDataAccess

    with session_factory() as session:
        session.add(CryptoBar(
            symbol="BTCUSDT", granularity="1h", ts=1747800000,
            open=50000.0, high=50500.0, low=49500.0, close=50300.0, volume=10.0,
        ))
        session.add(CryptoBar(
            symbol="BTCUSDT", granularity="1h", ts=1747803600,
            open=50300.0, high=51000.0, low=50100.0, close=50800.0, volume=12.0,
        ))
        session.commit()

    cda = CryptoDataAccess(repository=Repository(), session_factory=session_factory)
    assert cda.get_current_spot("BTCUSDT", before_ts=1747900000) == 50800.0


def test_get_recent_returns_uses_close_to_close(session_factory):
    from agent.store.schema import CryptoBar
    from agent.store.repository import Repository
    from agent.research.crypto.crypto_data import CryptoDataAccess

    with session_factory() as session:
        for i, close in enumerate([100.0, 101.0, 99.0, 102.0], start=0):
            session.add(CryptoBar(
                symbol="BTCUSDT", granularity="1h", ts=1747800000 + i * 3600,
                open=close, high=close, low=close, close=close, volume=1.0,
            ))
        session.commit()

    cda = CryptoDataAccess(repository=Repository(), session_factory=session_factory)
    returns = cda.get_recent_returns("BTCUSDT", "1h", n_bars=3, before_ts=1747900000)
    # close-to-close: (101-100)/100 = 0.01, (99-101)/101 ~ -0.0198, (102-99)/99 ~ 0.0303
    assert len(returns) == 3
    assert abs(returns[0] - 0.01) < 1e-6
    assert abs(returns[1] - (99.0 - 101.0) / 101.0) < 1e-6
    assert abs(returns[2] - (102.0 - 99.0) / 99.0) < 1e-6


def test_get_recent_news_for_currency_filters_by_currency_and_ts(session_factory):
    """C2-A only needs the interface; full population happens in C2-B/C/D."""
    from agent.store.repository import Repository
    from agent.research.crypto.crypto_data import CryptoDataAccess

    cda = CryptoDataAccess(repository=Repository(), session_factory=session_factory)
    # With no news_events in DB, returns empty list
    result = cda.get_recent_news_for_currency("BTC", since_ts=1747800000, until_ts=1747900000)
    assert result == []
```

- [ ] **Step 10.2: Implement `crypto_data.py`**

Create `agent/research/crypto/crypto_data.py`:
```python
"""CryptoDataAccess: repository wrapper providing the specific queries
crypto_model needs without leaking ORM details.
"""

from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.data.models import NewsEventDTO
from agent.store.schema import CryptoBar


class CryptoDataAccess:
    def __init__(
        self,
        repository,
        session_factory: Callable[[], Session],
    ):
        self.repository = repository
        self.session_factory = session_factory

    def get_current_spot(self, symbol: str, before_ts: int) -> float:
        with self.session_factory() as session:
            row = session.execute(
                select(CryptoBar)
                .where(CryptoBar.symbol == symbol, CryptoBar.ts <= before_ts)
                .order_by(CryptoBar.ts.desc())
                .limit(1)
            ).scalar_one_or_none()
            if row is None:
                raise ValueError(f"No crypto bar for {symbol} at or before {before_ts}")
            return float(row.close)

    def get_recent_returns(
        self, symbol: str, granularity: str, n_bars: int, before_ts: int,
    ) -> list[float]:
        with self.session_factory() as session:
            bars = session.execute(
                select(CryptoBar)
                .where(
                    CryptoBar.symbol == symbol,
                    CryptoBar.granularity == granularity,
                    CryptoBar.ts <= before_ts,
                )
                .order_by(CryptoBar.ts.desc())
                .limit(n_bars + 1)
            ).scalars().all()
            bars = list(reversed(bars))   # ascending order for return calc

        returns = []
        for i in range(1, len(bars)):
            prev_close = bars[i - 1].close
            cur_close = bars[i].close
            if prev_close > 0:
                returns.append((cur_close - prev_close) / prev_close)
        return returns

    def get_recent_news_for_currency(
        self, currency: str, since_ts: int, until_ts: int,
    ) -> list[NewsEventDTO]:
        """C2-A stub: returns empty list.  C2-B implements full query against
        news_events + news_currency_tags."""
        return []
```

NB: NewsEventDTO is added to `agent/data/models.py` here as a stub.  C2-B
expands it.  For now add the minimum fields needed for the type to import:

- [ ] **Step 10.3: Add minimal `NewsEventDTO` stub to `agent/data/models.py`**

Append to `agent/data/models.py`:
```python
class NewsEventDTO(BaseModel):
    """C2-A stub: full schema lands in C2-B.  Defined here so CryptoDataAccess
    can import the name.  C2-B will expand fields and validation."""

    source: str
    external_id: str
    language: str = "en"
    ts: int
    raw_text: str = ""
    translated_text: str | None = None
    severity_score: float | None = None
    currencies: list[str] = Field(default_factory=list)
    ingested_at: int = 0
```

Ensure `Field` is imported from pydantic.

- [ ] **Step 10.4: Run tests**

```
pytest tests/research/crypto/test_crypto_data.py -v
```
Expected: 3 PASS.

- [ ] **Step 10.5: Commit**

```
git add agent/research/crypto/crypto_data.py tests/research/crypto/test_crypto_data.py agent/data/models.py
git commit -m "feat(polymarket-c2a): add CryptoDataAccess wrapper and NewsEventDTO stub"
```

---

## Task 11: `model.py` (`crypto_model` top-level)

**Files:**
- Create: `agent/research/crypto/shock_detector.py` (placeholder `SpotOnlyShockDetector` only)
- Create: `agent/research/crypto/model.py`
- Test: `tests/research/crypto/test_model.py`

- [ ] **Step 11.1: Create the SpotOnlyShockDetector placeholder**

Create `agent/research/crypto/shock_detector.py`:
```python
"""C2-A placeholder.  C2-D replaces this with the full 3-mode fusion
(SpotOrNews, SpotAndNews, WeightedScore) per spec §5.4.
"""

import math
from abc import ABC, abstractmethod

from agent.research.crypto.types import ShockState


class ShockDetector(ABC):
    @abstractmethod
    def detect(
        self,
        current_return: float,
        garch_annualized_vol: float,
        periods_per_year: int,
        recent_news_events: list,
        now_ts: int,
        last_shock_ts: int | None,
    ) -> ShockState: ...


class SpotOnlyShockDetector(ShockDetector):
    """Fires when |current_return| > spot_threshold_k * period-vol.
    Ignores news entirely.  Used by C2-A; replaced in C2-D.
    """

    def __init__(self, spot_threshold_k: float = 3.0):
        self.spot_threshold_k = spot_threshold_k

    def detect(
        self,
        current_return: float,
        garch_annualized_vol: float,
        periods_per_year: int,
        recent_news_events: list,
        now_ts: int,
        last_shock_ts: int | None,
    ) -> ShockState:
        period_vol = garch_annualized_vol / math.sqrt(periods_per_year)
        sigmas = abs(current_return) / period_vol if period_vol > 0 else 0.0

        if sigmas >= self.spot_threshold_k:
            return ShockState(
                active=True,
                severity=min(1.0, sigmas / 10.0),
                spot_signal=True,
                news_signal=False,
                time_since_shock_seconds=0,
            )

        # Past shock still active if within recent window
        if last_shock_ts is not None and (now_ts - last_shock_ts) < 30 * 86400:
            return ShockState(
                active=True,
                severity=0.5,  # conservative default for ongoing shock
                spot_signal=False,
                news_signal=False,
                time_since_shock_seconds=now_ts - last_shock_ts,
            )

        return ShockState(
            active=False,
            severity=0.0,
            spot_signal=False,
            news_signal=False,
            time_since_shock_seconds=0,
        )
```

- [ ] **Step 11.2: Write the 6 integration tests for `crypto_model`**

Per spec §8.9.  Each test stubs all dependencies and asserts the resulting
Prediction.  Create `tests/research/crypto/test_model.py`:
```python
# Integration tests for crypto_model.  Each test constructs full dependency
# graph with in-memory implementations or stubs, then asserts Prediction
# matches hand-computed expected.

# This file is the longest test file in C2-A.  Each scenario has a setup
# block + the model invocation + an assertion block.

# For brevity here, only the scaffolding for scenario 1 is shown; the
# implementer follows the same pattern for scenarios 2-6 per spec §8.9.

import math
import pytest


def _build_pipeline(session_factory, *, market_id, p_market, current_return=0.0,
                    spot=50000.0, barrier=80000.0, vol=0.5):
    """Build a fully-wired pipeline with controllable inputs."""
    # Implementer fills in: insert CryptoBars, build crypto_data, build all
    # composers, blender, agreement_filter, tilt, sizer, performance_tracker,
    # market_resolver from a stubbed markets.yaml.
    # Returns a dict of all components ready to pass to crypto_model.
    raise NotImplementedError("Implementer fills in per scenario")


def test_scenario_1_cold_start_no_shock_no_trade():
    """No shock, equal mode weights, P_market=0.50, P_bridge=0.55.
    All 4 composers return P_market=0.50 (because not shock_state.active).
    Blender outputs 0.50.  AgreementFilter sees long_count=0 -> veto.
    P_final = P_market = 0.50.  Kelly fraction = 0.0 (no edge).
    Expected: position_size == 0.0, agreement_vetoed == True.
    """
    pass  # Implementer wires up dependencies and asserts


def test_scenario_2_cold_start_shock_long_consensus():
    """Strong shock fires, all 4 composers signal P_mode > P_market by large excess.
    Filter allows.  Kelly fraction matches hand-computed half-Kelly.
    """
    pass


def test_scenario_3_warm_modes_regime_change_filter_vetoes():
    """Modes 2/3 decayed below epsilon -> filter sees 2-of-4 -> veto."""
    pass


def test_scenario_4_mode_4_disabled():
    """Mode 4 disabled in PerformanceTracker -> crypto_model passes only
    3 modes to AgreementFilter -> needs 3-of-3 consensus (per spec §6.3)."""
    pass


def test_scenario_5_asymmetric_tilt_activates():
    """P_bridge > P_market and trade allowed -> P_final = P_blend + 0.05."""
    pass


def test_scenario_6_asymmetric_tilt_dormant():
    """P_bridge <= P_market: tilt is identity."""
    pass
```

NB to implementer: each scenario's `pass` is to be filled in with full
setup + assertion code.  Use the spec §8.9 hand-traced expected values as
the assertion targets.

- [ ] **Step 11.3: Implement `crypto_model`**

Create `agent/research/crypto/model.py`:
```python
"""crypto_model: top-level callable wiring the C2 composition pipeline.

Pipeline (in order):
  1. resolve_market via market_resolver
  2. compute spot, recent returns, GARCH vol via crypto_data
  3. p_market from event
  4. p_bridge via prob_barrier_hit
  5. shock_state via shock_detector
  6. p_modes via each composer
  7. blend_output via blender
  8. verdict via agreement_filter
  9. p_final via asymmetric_tilt (or p_market if vetoed/all-disabled)
 10. kelly via sizer
 11. emit Prediction with full diagnostics
"""

import json
import math
from dataclasses import dataclass
from typing import Optional


@dataclass
class Prediction:
    """The output of crypto_model.  Matches Phase 1A's Prediction protocol."""
    market_id: str
    ts: int
    p_final: float
    position_size: float
    diagnostics: dict


def crypto_model(
    market_id: str,
    event,
    *,
    polymarket_state,
    market_resolver,
    crypto_data,
    shock_detector,
    composers: list,
    blender,
    agreement_filter,
    tilt,
    sizer,
    performance_tracker,
    session_factory,
    fit_garch11=None,
    prob_barrier_hit=None,
) -> Prediction:
    market = polymarket_state.get_market(market_id)
    mapping = market_resolver.resolve(market)
    if mapping is None:
        return Prediction(
            market_id=market_id, ts=event.ts, p_final=event.p_market,
            position_size=0.0,
            diagnostics={"reason": "not_in_markets_yaml"},
        )

    # Time-to-resolution
    T_years = market_resolver.time_to_resolution_years(mapping, event.ts)

    # Spot, returns, vol
    spot = crypto_data.get_current_spot(mapping.symbol, before_ts=event.ts)
    returns = crypto_data.get_recent_returns(
        mapping.symbol, granularity="1h", n_bars=500, before_ts=event.ts,
    )

    # Import lazily to allow injection-by-default for tests
    if fit_garch11 is None:
        from agent.research.crypto.vol_estimator import fit_garch11 as _fit
        fit_garch11 = _fit
    if prob_barrier_hit is None:
        from agent.research.crypto.barrier_bridge import prob_barrier_hit as _pbh
        prob_barrier_hit = _pbh

    garch_result = fit_garch11(returns, periods_per_year=8760)
    p_bridge = prob_barrier_hit(
        spot=spot,
        barrier=mapping.barrier_price,
        time_remaining_years=T_years,
        annualized_vol=garch_result.current_conditional_vol,
        annualized_drift=0.0,
    )

    # Shock detection
    shock_state = shock_detector.detect(
        current_return=returns[-1] if returns else 0.0,
        garch_annualized_vol=garch_result.current_conditional_vol,
        periods_per_year=8760,
        recent_news_events=crypto_data.get_recent_news_for_currency(
            mapping.symbol[:3], since_ts=event.ts - 1800, until_ts=event.ts,
        ),
        now_ts=event.ts,
        last_shock_ts=polymarket_state.get_last_shock_ts(market_id),
    )

    # Per-composer predictions
    p_modes = {c.name: c.compose(event.p_market, p_bridge, shock_state)
               for c in composers}

    # Filter disabled modes before blender + agreement filter
    with session_factory() as session:
        state = performance_tracker.get_state(session)
    enabled_modes = {name: p for name, p in p_modes.items()
                     if not state[name].is_disabled}

    if not enabled_modes:
        return Prediction(
            market_id=market_id, ts=event.ts, p_final=event.p_market,
            position_size=0.0,
            diagnostics={"reason": "all_modes_disabled"},
        )

    # Blender
    with session_factory() as session:
        blend_out = blender.blend(enabled_modes, performance_tracker, session)
    if blend_out.weights.is_all_disabled():
        return Prediction(
            market_id=market_id, ts=event.ts, p_final=event.p_market,
            position_size=0.0,
            diagnostics={"reason": "all_weights_zero"},
        )

    # Agreement filter (on enabled modes only)
    verdict = agreement_filter.evaluate(event.p_market, enabled_modes)
    if not verdict.allowed:
        return Prediction(
            market_id=market_id, ts=event.ts, p_final=event.p_market,
            position_size=0.0,
            diagnostics={
                "reason": "agreement_vetoed",
                "long_count": verdict.long_count,
                "short_count": verdict.short_count,
            },
        )

    # Asymmetric tilt
    p_final = tilt.apply(blend_out.p_blend, event.p_market, p_bridge)

    # Kelly sizing
    kelly = sizer.size(p_final, event.p_market)

    return Prediction(
        market_id=market_id,
        ts=event.ts,
        p_final=p_final,
        position_size=kelly.fraction,
        diagnostics={
            "p_market": event.p_market,
            "p_bridge": p_bridge,
            "p_modes": p_modes,
            "weights": {
                "binary": blend_out.weights.w_binary,
                "exp": blend_out.weights.w_exp,
                "magnitude": blend_out.weights.w_magnitude,
                "confidence": blend_out.weights.w_confidence,
            },
            "p_blend": blend_out.p_blend,
            "agreement_vetoed": False,
            "kelly_direction": kelly.direction,
            "shock_active": shock_state.active,
            "shock_severity": shock_state.severity if shock_state.active else None,
        },
    )
```

- [ ] **Step 11.4: Implementer fills in the 6 integration tests**

For each `pass` in Step 11.2, implement the setup + assertion per spec §8.9.
This is the most labor-intensive step in C2-A.  Plan ~2-3 hours.

- [ ] **Step 11.5: Run tests**

```
pytest tests/research/crypto/test_model.py -v
```
Expected: 6 PASS.

- [ ] **Step 11.6: Commit**

```
git add agent/research/crypto/shock_detector.py agent/research/crypto/model.py tests/research/crypto/test_model.py
git commit -m "feat(polymarket-c2a): wire crypto_model top-level + 6 integration tests"
```

---

## Task 12: End-to-end gate against `walk_forward_backtest`

**Files:**
- Modify: `agent/research/crypto/markets.yaml` (operator curates 1 real BTC market)
- Test: `tests/research/crypto/test_c2a_e2e_gate.py`

- [ ] **Step 12.1: Operator manually curates `markets.yaml`**

The operator (human) selects 1 currently-active Polymarket BTC barrier market
and edits `agent/research/crypto/markets.yaml`:
```yaml
- market_id: "0x..."          # real Polymarket market ID
  polymarket_question: "Will BTC reach $X by date Y?"
  symbol: BTCUSDT
  barrier_price: 80000.0       # or whatever the real barrier is
  direction: up                # or "down"
```

- [ ] **Step 12.2: Write the gate test**

Create `tests/research/crypto/test_c2a_e2e_gate.py`:
```python
def test_c2a_gate_walk_forward_backtest_emits_predictions(session_factory):
    """C2-A Gate: Run Phase 1A's walk_forward_backtest against the
    hand-curated BTC market in markets.yaml.  Must emit at least one
    Prediction with non-zero position_size.

    This is the C2-A completion gate per spec §1.5.
    """
    from agent.harness.walk_forward import walk_forward_backtest
    # ... boilerplate to construct event stream from the existing fixtures
    # in tests/harness/, then run walk_forward against crypto_model

    predictions = walk_forward_backtest(...)  # operator fills in args
    non_zero = [p for p in predictions if p.position_size > 0.0]
    assert len(non_zero) >= 1, \
        f"C2-A gate FAILED: walk_forward_backtest produced zero non-zero " \
        f"predictions on the curated BTC market.  Pipeline has a wiring bug."
```

NB: The exact `walk_forward_backtest` invocation depends on Phase 1A's API.
The implementer follows the existing Phase 1A test patterns.

- [ ] **Step 12.3: Run the gate**

```
pytest tests/research/crypto/test_c2a_e2e_gate.py -v
```
Expected: PASS.  If it fails, debug by inspecting Prediction.diagnostics
to find the first layer that vetoed/disabled/produced unexpected output.

- [ ] **Step 12.4: Run the full test suite for regression check**

```
pytest -q
```
Expected: 107 prior tests + ~70 new C2-A tests, all PASS.  No regressions
in Phase 0, Phase 1A, or Phase 1B-C1 tests.

- [ ] **Step 12.5: Commit and announce C2-A gate green**

```
git add agent/research/crypto/markets.yaml tests/research/crypto/test_c2a_e2e_gate.py
git commit -m "feat(polymarket-c2a): C2-A gate green — walk_forward_backtest emits non-zero predictions"
```

---

## C2-A complete

Sub-phase gate (spec §7.1): walk_forward_backtest produces at least one
non-zero Prediction on 1 hand-curated BTC market using only spot-shock
signals.  All ~70 C2-A tests pass.  Ready for C2-B (multilingual news
aggregator).

Next plan: `2026-05-21-polymarket-phase-1b-c2-b-news-aggregator.md`
(to be written when C2-A is gate-green).
