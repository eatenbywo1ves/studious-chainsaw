"""Integration tests for crypto_model (Task 11 of Phase 1B-C2-A).

Each test constructs a fully-wired pipeline using in-memory SQLite and
injectable stubs for fit_garch11 + prob_barrier_hit, then asserts the
resulting CryptoPrediction matches hand-traced expected values.

ADAPTATION NOTES (Phase 1A API vs. plan assumptions):
  - event.price replaces plan's event.p_market (ReplayEvent has no .p_market).
  - CryptoPrediction subclasses Prediction; p_hat == p_final.
  - No PolymarketState: get_market + get_last_shock_ts are plain Callables.
  - Single session block in model.py (plan had two separate context managers).

HAND-COMPUTATION DISCIPLINE:
  Each scenario's setup block contains comments deriving the expected values
  using the exact formulas from the spec.  A test that silently passes when
  the formula is wrong is not useful — every assertion is math-justified.
"""

import math
import pytest

from agent.research.crypto.agreement_filter import AgreementFilter
from agent.research.crypto.asymmetric_tilt import AsymmetricTilt
from agent.research.crypto.barrier_bridge import prob_barrier_hit as real_pbh
from agent.research.crypto.blender import BayesianBlender
from agent.research.crypto.composers import (
    BinaryComposer,
    ConfidenceWeightedComposer,
    ExponentialComposer,
    MagnitudeTiedComposer,
)
from agent.research.crypto.kelly_sizer import KellySizer
from agent.research.crypto.market_resolver import MarketResolver
from agent.research.crypto.model import CryptoPrediction, crypto_model
from agent.research.crypto.performance_tracker import PerformanceTracker
from agent.research.crypto.shock_detector import SpotOnlyShockDetector
from agent.research.crypto.types import (
    CryptoMarketMappingFile,
    ShockState,
)
from agent.store.schema import ModeFloorState
from agent.validation.backtest import ReplayEvent


# ---------------------------------------------------------------------------
# Helpers / shared stubs
# ---------------------------------------------------------------------------

_MARKET_ID = "0xTEST001"
_SYMBOL = "BTCUSDT"
_BARRIER = 80000.0
_SPOT = 50000.0

# Resolution 1 year from a fixed reference point (ts = 1_000_000_000 s)
_NOW_TS = 1_000_000_000
_RESOLUTION_TS = _NOW_TS + int(365.25 * 86400)  # exactly 1 year away


def _make_mapping_file() -> CryptoMarketMappingFile:
    """One markets.yaml entry for the test market."""
    return CryptoMarketMappingFile(
        market_id=_MARKET_ID,
        polymarket_question="Will BTC reach $80k?",
        symbol=_SYMBOL,
        barrier_price=_BARRIER,
        direction="up",
    )


def _make_resolver() -> MarketResolver:
    return MarketResolver([_make_mapping_file()])


def _make_market_orm_stub():
    """Lightweight stand-in for the Market ORM object.

    We don't need a real SQLAlchemy row — the resolver only reads .id and
    .end_date_iso.
    """
    class _Market:
        id = _MARKET_ID
        end_date_iso = "2101-09-09T00:00:00Z"  # matches _RESOLUTION_TS ~1 yr from _NOW_TS

    # Set end_date_iso to produce exactly _RESOLUTION_TS.
    import datetime
    dt = datetime.datetime.fromtimestamp(_RESOLUTION_TS, tz=datetime.timezone.utc)
    _Market.end_date_iso = dt.isoformat()
    return _Market()


def _get_market_fn(market_id: str):
    """Callable: returns the stub Market when asked for _MARKET_ID."""
    if market_id == _MARKET_ID:
        return _make_market_orm_stub()
    return None


def _get_last_shock_ts_none(_market_id: str) -> None:
    """No prior shock history (C2-A default)."""
    return None


def _make_composers():
    return [
        BinaryComposer(),
        ExponentialComposer(),
        MagnitudeTiedComposer(),
        ConfidenceWeightedComposer(),
    ]


class _FakeCryptoData:
    """Stub CryptoDataAccess returning controllable spot + returns + no news."""

    def __init__(self, spot: float = _SPOT, returns: list | None = None):
        self._spot = spot
        self._returns = returns if returns is not None else [0.001] * 2  # 2 minimal bars

    def get_current_spot(self, symbol: str, before_ts: int) -> float:
        return self._spot

    def get_recent_returns(
        self, symbol: str, granularity: str, n_bars: int, before_ts: int
    ) -> list[float]:
        return self._returns

    def get_recent_news_for_currency(
        self, currency: str, since_ts: int, until_ts: int
    ) -> list:
        return []


def _make_garch_stub(annualized_vol: float = 0.50):
    """Return a fake fit_garch11 that produces a GARCHResult-like object.

    Uses a namedtuple stand-in so we don't need arch installed in this test path.
    """
    from dataclasses import dataclass as _dc

    @_dc(frozen=True)
    class _GARCHResult:
        omega: float = 1e-6
        alpha: float = 0.05
        beta: float = 0.90
        persistence: float = 0.95
        n_obs: int = 500
        periods_per_year: int = 8760
        long_run_variance: float = 2e-5
        current_conditional_vol: float = annualized_vol

    result = _GARCHResult(current_conditional_vol=annualized_vol)

    def _fake_fit(returns, *, periods_per_year):
        return result

    return _fake_fit


def _build_pipeline_components(
    *,
    session_factory,
    annualized_vol: float = 0.50,
    spot: float = _SPOT,
    current_return: float = 0.001,  # small return → no new shock by default
):
    """Build all pipeline components with sensible defaults.

    Returns a dict of kwargs ready to spread into crypto_model(...).
    """
    return dict(
        get_market=_get_market_fn,
        get_last_shock_ts=_get_last_shock_ts_none,
        market_resolver=_make_resolver(),
        crypto_data=_FakeCryptoData(spot=spot, returns=[current_return] * 2),
        shock_detector=SpotOnlyShockDetector(spot_threshold_k=3.0),
        composers=_make_composers(),
        blender=BayesianBlender(),
        agreement_filter=AgreementFilter(epsilon=0.08, min_active_count=3),
        tilt=AsymmetricTilt(tilt_magnitude=0.05),
        sizer=KellySizer(),
        performance_tracker=PerformanceTracker(trailing_window=15),
        session_factory=session_factory,
        fit_garch11=_make_garch_stub(annualized_vol),
        prob_barrier_hit=real_pbh,
    )


def _make_event(price: float, ts: int = _NOW_TS) -> ReplayEvent:
    """Minimal ReplayEvent stub used to drive crypto_model."""
    return ReplayEvent(ts=ts, token_id="YES_TOKEN", price=price)


# ---------------------------------------------------------------------------
# Scenario 1: Cold start, no shock → agreement veto, no trade
# ---------------------------------------------------------------------------

def test_scenario_1_cold_start_no_shock_no_trade(session_factory):
    """No shock → all composers gate on shock_state.active=False → P_mode = P_market.

    HAND-TRACE:
      p_market = 0.50  (event.price)
      p_bridge is computed from real prob_barrier_hit with:
        spot=50000, barrier=80000, T=1yr, vol=0.50, drift=0
        b = log(80000/50000) = log(1.6) ≈ 0.4700
        ν = 0 - 0.5*(0.5^2) = -0.125
        v = 0.50 * sqrt(1) = 0.50
        up-barrier:
          term1 = N((ν*T - b)/v) = N((-0.125 - 0.4700)/0.50) = N(-1.190)
          prefactor = exp(2*ν*b / σ²) = exp(2*(-0.125)*0.4700 / 0.25)
                    = exp(-0.47) ≈ 0.6250
          term2 = 0.6250 * N((-ν*T - b)/v) = 0.6250 * N((0.125 - 0.4700)/0.50)
                                             = 0.6250 * N(-0.690)
        p_bridge is some value in (0,1); its exact value does NOT matter for
        this scenario because shock_state.active=False makes all composers
        return p_market regardless.

      shock detection:
        current_return = 0.001 (small)
        period_vol = 0.50 / sqrt(8760) ≈ 0.00534
        sigmas = 0.001 / 0.00534 ≈ 0.187 < spot_threshold_k=3.0 → no new shock
        last_shock_ts=None → no rolling-window activation
        → shock_state.active = False

      All 4 composers return p_market = 0.50 (short-circuit on not active).
      p_modes = {binary:0.50, exp:0.50, magnitude:0.50, confidence:0.50}

      Blender (cold start — no ModePerformance rows):
        All modes have n_closed_trades=0 < cold_start_min_trades=3 → score at floor.
        brier_floor_init = 0.10 → score = 1/0.10 = 10.0 for each.
        total = 40.0 → w = 0.25 each.
        p_blend = 0.50.

      AgreementFilter:
        |0.50 - 0.50| = 0 < epsilon=0.08 → all modes neutral.
        long_count = 0, short_count = 0 → veto (not 3-of-4).

      Expected: position_size == 0.0, diagnostics['reason'] == 'agreement_vetoed'.
    """
    event = _make_event(price=0.50)
    kwargs = _build_pipeline_components(
        session_factory=session_factory,
        current_return=0.001,   # small → no shock
    )

    result = crypto_model(_MARKET_ID, event, **kwargs)

    assert isinstance(result, CryptoPrediction)
    assert result.market_id == _MARKET_ID
    assert result.ts == _NOW_TS
    assert result.position_size == 0.0, (
        "Cold-start no-shock: AgreementFilter must veto → no trade"
    )
    assert result.diagnostics.get("reason") == "agreement_vetoed", (
        f"Expected agreement_vetoed, got: {result.diagnostics}"
    )
    # p_hat returned equals p_market when vetoed
    assert abs(result.p_hat - 0.50) < 1e-9, (
        f"p_hat should equal p_market=0.50 on veto, got {result.p_hat}"
    )


# ---------------------------------------------------------------------------
# Scenario 2: Cold start, strong shock, large divergence → trade
# ---------------------------------------------------------------------------

def test_scenario_2_cold_start_shock_long_consensus(session_factory):
    """Strong shock fires, all 4 composers signal well above p_market + epsilon.

    HAND-TRACE:
      p_market = 0.10, p_bridge = 0.55 (injected via fake_pbh).

      shock detection:
        current_return = 0.04  (well above 3-sigma)
        period_vol = 0.50 / sqrt(8760) ≈ 0.00534
        sigmas = 0.04 / 0.00534 ≈ 7.49 ≥ 3.0 → shock fires
        severity = min(1.0, 7.49/10.0) = 0.749  (clipped to [0,1] by ShockState)
        time_since_shock_seconds = 0

      Composers (shock active, time_since=0, severity=0.749, p_bridge=0.55):
        binary: time_since=0 < 14*86400 → p_bridge = 0.55
        exp:    lam = exp(-0/tau) = 1.0 → 1.0*0.55 + 0.0*0.10 = 0.55
        magnitude: lam = 0.749*exp(0) = 0.749 → 0.749*0.55 + 0.251*0.10 = 0.4370
        confidence: divergence = |0.10-0.55| = 0.45
                    z = (0.45-0.10)/0.05 = 7.0
                    lam = 1/(1+exp(-7)) ≈ 0.99909
                    p_mode ≈ 0.99909*0.55 + 0.00091*0.10 ≈ 0.5496

      Check all exceed p_market + epsilon = 0.18:
        binary:0.55 ✓, exp:0.55 ✓, magnitude:0.4370 ✓, confidence:0.5496 ✓
        long_count = 4 ≥ 3 → filter ALLOWS.

      Blender (cold start, equal weights 0.25):
        p_blend = 0.25*0.55 + 0.25*0.55 + 0.25*0.4370 + 0.25*0.5496
               = 0.1375 + 0.1375 + 0.10925 + 0.1374
               ≈ 0.5217

      Tilt: p_bridge(0.55) > p_market(0.10) → p_final = min(1, 0.5217+0.05) = 0.5717

      Kelly (p_final=0.5717, p_market=0.10):
        edge = 0.5717 - 0.10 = 0.4717
        direction = "yes"
        q = p_market = 0.10
        variance = 0.5717 * (1 - 0.5717) = 0.5717 * 0.4283 ≈ 0.24493
        raw_kelly = 0.10 * 0.4717 / 0.24493 ≈ 0.19258
        half_kelly = 0.5 * 0.19258 ≈ 0.09629
        fraction = clip(0.09629, 0, 0.10) = 0.09629

      Expected: position_size ≈ 0.09629 (< 0.10 so not capped).
    """
    # Injected p_bridge = 0.55 regardless of the real barrier formula.
    def _fake_pbh(spot, barrier, time_remaining_years, annualized_vol, annualized_drift=0.0):
        return 0.55

    event = _make_event(price=0.10)
    kwargs = _build_pipeline_components(
        session_factory=session_factory,
        annualized_vol=0.50,
        current_return=0.04,    # ≈7.5 sigma → shock fires, severity=min(1,0.749)
    )
    kwargs["prob_barrier_hit"] = _fake_pbh

    result = crypto_model(_MARKET_ID, event, **kwargs)

    assert isinstance(result, CryptoPrediction)
    assert result.position_size > 0.0, "Strong shock with large divergence must produce a trade"

    # Verify verdict was not vetoed
    assert result.diagnostics.get("reason") is None or result.diagnostics.get("reason") not in (
        "agreement_vetoed", "all_modes_disabled", "not_in_markets_yaml"
    ), f"Expected trade but got veto/bypass: {result.diagnostics}"

    # Hand-computed: p_final ≈ 0.5717.
    # Tolerance: minor floating-point in lam/confidence is fine ±0.005.
    assert abs(result.p_hat - 0.5717) < 0.005, (
        f"p_hat={result.p_hat:.6f}, expected ≈0.5717"
    )

    # Hand-computed half-Kelly: ≈ 0.09629 (< 0.10 cap).
    assert abs(result.position_size - 0.09629) < 0.005, (
        f"position_size={result.position_size:.6f}, expected ≈0.09629"
    )


# ---------------------------------------------------------------------------
# Scenario 3: Warm modes, 2-of-4 long consensus → filter veto
# ---------------------------------------------------------------------------

def test_scenario_3_warm_modes_regime_change_filter_vetoes(session_factory):
    """Shock active but only 2 modes signal long (below min_active_count=3).

    HAND-TRACE:
      p_market = 0.50, p_bridge = 0.60.

      Shock: injected via last_shock_ts so modes are active but we control
      which modes exceed epsilon.  We do this by choosing p_bridge values
      that only push binary and exp above epsilon.  Specifically:
        - binary: time_since << 14d → p_bridge = 0.60 > 0.50+0.08=0.58 ✓ long
        - exp:    lam from large elapsed time.  We set time_since = 3*86400 (3 days).
                  lam = exp(-3*86400 / 7*86400) = exp(-3/7) ≈ 0.6503
                  p_mode = 0.6503*0.60 + 0.3497*0.50 = 0.39018+0.17485 = 0.5650 > 0.58 ✓ long
        - magnitude: lam = severity*exp(-t/tau) = 0.5*exp(-3/7) ≈ 0.5*0.6503=0.3252
                     p_mode = 0.3252*0.60 + 0.6748*0.50 = 0.19512+0.33740 = 0.5325 < 0.58 ✗ neutral
        - confidence: divergence = |0.50-0.60|=0.10
                      z = (0.10-0.10)/0.05 = 0.0
                      lam = 1/(1+exp(0)) = 0.50
                      p_mode = 0.50*0.60+0.50*0.50 = 0.55 > 0.58? → 0.55 < 0.58 ✗ neutral

      long_count = 2 < min_active_count=3 → AgreementFilter VETOS.
      Expected: position_size == 0.0, reason == 'agreement_vetoed'.
    """
    # Use a past shock 3 days ago (within 30-day window) → shock active.
    _3_DAYS = 3 * 86400
    last_shock_ts = _NOW_TS - _3_DAYS

    def _fake_pbh(spot, barrier, time_remaining_years, annualized_vol, annualized_drift=0.0):
        return 0.60

    def _get_last_shock(market_id: str):
        return last_shock_ts

    event = _make_event(price=0.50)
    kwargs = _build_pipeline_components(
        session_factory=session_factory,
        current_return=0.001,   # below threshold → no new shock from spot
    )
    kwargs["prob_barrier_hit"] = _fake_pbh
    kwargs["get_last_shock_ts"] = _get_last_shock

    result = crypto_model(_MARKET_ID, event, **kwargs)

    assert result.position_size == 0.0, (
        f"2-of-4 consensus must be vetoed; position_size={result.position_size}"
    )
    assert result.diagnostics.get("reason") == "agreement_vetoed", (
        f"Expected agreement_vetoed, got: {result.diagnostics}"
    )


# ---------------------------------------------------------------------------
# Scenario 4: Mode "confidence" disabled → 3 enabled modes, 3-of-3 consensus
# ---------------------------------------------------------------------------

def test_scenario_4_mode_confidence_disabled(session_factory):
    """confidence mode disabled in DB → crypto_model filters it before filter.

    HAND-TRACE:
      p_market = 0.10, p_bridge = 0.55, shock active (fresh, time_since=0, severity=1.0).
      current_return = 0.04 → sigmas ≈ 7.5 → severity = min(1.0, 0.749) = 0.749.

      Enabled modes = {binary, exp, magnitude} (confidence disabled in DB).

      binary:    p_bridge = 0.55 > 0.10+0.08=0.18 ✓ long
      exp:       lam=1.0 → 0.55 ✓ long
      magnitude: lam=0.749*1.0=0.749 → 0.749*0.55+0.251*0.10 = 0.4370 > 0.18 ✓ long

      AgreementFilter sees 3 enabled modes, long_count=3 ≥ min_active_count=3 → ALLOWS.

      Blender (3 cold modes, floor=0.10, equal weights):
        score = 10.0 each; total=30; w=1/3 each.
        p_blend = (0.55+0.55+0.437)/3 ≈ 0.5123

      Tilt: p_bridge(0.55) > p_market(0.10) → p_final = 0.5123+0.05 = 0.5623

      Kelly (p_final=0.5623, p_market=0.10):
        edge = 0.4623, direction=yes, q=0.10
        variance = 0.5623*(1-0.5623) = 0.5623*0.4377 ≈ 0.24612
        raw_kelly = 0.10*0.4623/0.24612 ≈ 0.18783
        half_kelly ≈ 0.09391

      Expected: position_size ≈ 0.09391 > 0 and < 0.10.
    """
    # Insert a disabled ModeFloorState for "confidence" into the DB.
    with session_factory() as session:
        session.add(
            ModeFloorState(
                mode_name="confidence",
                brier_floor=0.10,
                disable_streak=30,
                is_disabled=True,
                updated_at=_NOW_TS - 86400,
            )
        )
        session.commit()

    def _fake_pbh(spot, barrier, time_remaining_years, annualized_vol, annualized_drift=0.0):
        return 0.55

    event = _make_event(price=0.10)
    kwargs = _build_pipeline_components(
        session_factory=session_factory,
        current_return=0.04,    # strong shock → severity ≈ 0.749, time_since=0
    )
    kwargs["prob_barrier_hit"] = _fake_pbh

    result = crypto_model(_MARKET_ID, event, **kwargs)

    assert result.position_size > 0.0, (
        "3-of-3 consensus on enabled modes must allow a trade"
    )
    assert result.diagnostics.get("reason") is None, (
        f"Unexpected early exit: {result.diagnostics}"
    )
    # Check confidence was filtered out
    enabled = result.diagnostics.get("enabled_modes", [])
    assert "confidence" not in enabled, (
        f"confidence should be disabled; enabled_modes={enabled}"
    )
    assert "binary" in enabled and "exp" in enabled and "magnitude" in enabled

    # Hand-computed: p_final ≈ 0.5623, position_size ≈ 0.09391.
    assert abs(result.p_hat - 0.5623) < 0.005, (
        f"p_hat={result.p_hat:.6f}, expected ≈0.5623"
    )
    assert abs(result.position_size - 0.09391) < 0.005, (
        f"position_size={result.position_size:.6f}, expected ≈0.09391"
    )


# ---------------------------------------------------------------------------
# Scenario 5: Asymmetric tilt activates (P_bridge > P_market)
# ---------------------------------------------------------------------------

def test_scenario_5_asymmetric_tilt_activates(session_factory):
    """P_bridge > P_market and verdict allowed → P_final = P_blend + 0.05.

    HAND-TRACE:
      p_market = 0.10, p_bridge = 0.55, shock active (fresh, time_since=0, severity=0.749).
      Same setup as scenario 2.

      p_blend ≈ 0.5217 (same as scenario 2 derivation).
      Tilt: p_bridge(0.55) > p_market(0.10) → p_final = p_blend + 0.05 ≈ 0.5717.

      Without tilt, p_final would be p_blend ≈ 0.5217.
      With tilt, p_final ≈ 0.5717.

      Expected: result.p_hat ≈ p_blend + 0.05 (NOT p_blend alone).
    """
    def _fake_pbh(spot, barrier, time_remaining_years, annualized_vol, annualized_drift=0.0):
        return 0.55

    event = _make_event(price=0.10)
    kwargs = _build_pipeline_components(
        session_factory=session_factory,
        current_return=0.04,
    )
    kwargs["prob_barrier_hit"] = _fake_pbh

    result = crypto_model(_MARKET_ID, event, **kwargs)

    # Reconstruct p_blend to verify tilt added exactly 0.05.
    # Because all composers are deterministic given (p_market, p_bridge, shock_state)
    # and we know shock_state.active=True, time_since=0, severity≈0.749:
    severity = min(1.0, (0.04 / (0.50 / math.sqrt(8760))) / 10.0)
    p_bridge = 0.55
    p_market = 0.10
    # binary: 0.55, exp: 0.55,
    # magnitude: severity*p_bridge + (1-severity)*p_market
    p_magnitude = severity * p_bridge + (1 - severity) * p_market
    # confidence: divergence=0.45, z=(0.45-0.10)/0.05=7.0
    lam_conf = 1.0 / (1.0 + math.exp(-7.0))
    p_confidence = lam_conf * p_bridge + (1 - lam_conf) * p_market
    # cold blender: equal weights 0.25
    expected_p_blend = 0.25 * (0.55 + 0.55 + p_magnitude + p_confidence)
    expected_p_final = min(1.0, expected_p_blend + 0.05)  # tilt by +0.05

    assert abs(result.p_hat - expected_p_final) < 1e-6, (
        f"Tilt should add 0.05: p_blend={expected_p_blend:.6f}, "
        f"expected p_final={expected_p_final:.6f}, got {result.p_hat:.6f}"
    )
    assert result.p_hat > expected_p_blend + 0.04, (
        "Tilt must have added ≈0.05 over p_blend"
    )


# ---------------------------------------------------------------------------
# Scenario 6: Asymmetric tilt dormant (P_bridge <= P_market)
# ---------------------------------------------------------------------------

def test_scenario_6_asymmetric_tilt_dormant(session_factory):
    """P_bridge <= P_market → tilt is identity (no tilt applied).

    HAND-TRACE:
      p_market = 0.60, p_bridge = 0.40.
      Shock active (fresh, time_since=0).
        current_return = 0.04 → sigmas ≈ 7.5 → active.
        severity = min(1.0, 7.5/10.0) = 0.749.

      Composers (shock active, time_since=0):
        binary:    p_bridge = 0.40
        exp:       lam=1.0 → 0.40
        magnitude: lam=0.749 → 0.749*0.40 + 0.251*0.60 = 0.2996+0.1506 = 0.4502
        confidence: divergence=|0.60-0.40|=0.20
                    z=(0.20-0.10)/0.05=2.0, lam=1/(1+e^-2)≈0.8808
                    p_mode = 0.8808*0.40 + 0.1192*0.60 = 0.35232+0.07152 = 0.4238

      AgreementFilter (p_market=0.60, epsilon=0.08, short threshold = 0.60-0.08=0.52):
        binary:0.40 < 0.52 ✓ short
        exp:0.40 < 0.52 ✓ short
        magnitude:0.4502 < 0.52 ✓ short
        confidence:0.4238 < 0.52 ✓ short
        short_count = 4 ≥ 3 → ALLOWS.

      p_blend = 0.25*(0.40+0.40+0.4502+0.4238) = 0.25*1.671 = 0.4178.

      Tilt: p_bridge(0.40) <= p_market(0.60) → identity → p_final = p_blend = 0.4178.

      Expected: result.p_hat ≈ 0.4178 (no tilt), NOT 0.4178+0.05.
    """
    def _fake_pbh(spot, barrier, time_remaining_years, annualized_vol, annualized_drift=0.0):
        return 0.40

    event = _make_event(price=0.60)
    kwargs = _build_pipeline_components(
        session_factory=session_factory,
        current_return=0.04,    # strong shock → active
    )
    kwargs["prob_barrier_hit"] = _fake_pbh

    result = crypto_model(_MARKET_ID, event, **kwargs)

    # Re-derive expected p_blend identically to the HAND-TRACE above.
    severity = min(1.0, (0.04 / (0.50 / math.sqrt(8760))) / 10.0)
    p_bridge = 0.40
    p_market = 0.60
    p_magnitude = severity * p_bridge + (1 - severity) * p_market
    lam_conf = 1.0 / (1.0 + math.exp(-2.0))
    p_confidence = lam_conf * p_bridge + (1 - lam_conf) * p_market
    expected_p_blend = 0.25 * (0.40 + 0.40 + p_magnitude + p_confidence)
    # Tilt: p_bridge <= p_market → identity
    expected_p_final = expected_p_blend  # NO +0.05

    assert abs(result.p_hat - expected_p_final) < 1e-6, (
        f"Tilt should be dormant: expected p_final={expected_p_final:.6f}, "
        f"got {result.p_hat:.6f}"
    )
    # Confirm tilt did NOT add 0.05
    assert abs(result.p_hat - (expected_p_blend + 0.05)) > 0.04, (
        "Tilt MUST NOT have fired when p_bridge <= p_market"
    )
    assert result.position_size > 0.0, "Short consensus should produce a non-zero position"
