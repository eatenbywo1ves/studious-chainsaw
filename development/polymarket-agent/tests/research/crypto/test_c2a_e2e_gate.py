"""C2-A end-to-end gate test: pipeline must emit at least one non-zero-position
CryptoPrediction using real fit_garch11 and real prob_barrier_hit.

Gate reference: spec §7.1 — "walk_forward_backtest produces non-zero
Prediction on 1 hand-curated Polymarket BTC market using only spot-shock
signals."

Design rationale (per plan Task 12):
  • Real-market alpha testing is deferred to C2-E.  For an automated CI gate,
    a self-contained synthetic BTC market is appropriate.
  • Uses REAL fit_garch11 (arch GARCH(1,1)) and REAL prob_barrier_hit
    (closed-form GBM one-touch) — NOT the stubs in test_model.py.  That
    distinguishes this gate from the unit-level scenarios in test_model.py.
  • Uses walk_forward_backtest via a capturing wrapper.  BacktestResult has no
    predictions field, so a thin list captures predictions in the closure.
  • Resolutions dict is empty — n_resolved==0 path is harmless and avoids
    needing a real outcome for the gate assertion.

Synthetic scenario design:
  • BTCUSDT, spot ≈ 50 000, barrier 80 000, 1-year time-to-resolution.
  • 101 hourly CryptoBar rows seeded at modest constant returns (~0.1 %/hr).
  • The FINAL bar has a -15 % return (deliberately large) so the shock
    detector fires: |r| = 0.15 >> 3 * period_vol ≈ 0.016.
  • p_market (event.price) = 0.10 — LOW, so p_bridge >> p_market.
    Real prob_barrier_hit(spot=50000, barrier=80000, T≈1yr, vol≈fitted) yields
    p_bridge ≈ 0.50-0.60 (depends on GARCH fit), easily above p_market + ε.
  • All 4 composers signal long → AgreementFilter allows → Kelly sizes > 0.
"""

from functools import partial

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
from agent.research.crypto.crypto_data import CryptoDataAccess
from agent.research.crypto.kelly_sizer import KellySizer
from agent.research.crypto.market_resolver import MarketResolver
from agent.research.crypto.model import CryptoPrediction, crypto_model
from agent.research.crypto.performance_tracker import PerformanceTracker
from agent.research.crypto.shock_detector import SpotOnlyShockDetector
from agent.research.crypto.types import CryptoMarketMappingFile
from agent.research.crypto.vol_estimator import fit_garch11 as real_fit_garch11
from agent.store.schema import CryptoBar, Market, PriceSnapshot
from agent.validation.backtest import ReplayEvent, walk_forward_backtest

# ---------------------------------------------------------------------------
# Synthetic market constants
# ---------------------------------------------------------------------------

_MARKET_ID = "0xSYNTH_BTC_GATE"
_TOKEN_ID = "SYNTH_YES_TOKEN"
_SYMBOL = "BTCUSDT"
# Spot ≈ 50 000; barrier at 80 000 ("Will BTC reach $80k?").
# With vol ≈ 0.50 and T ≈ 1yr, prob_barrier_hit ≈ 0.55 >> p_market=0.10.
_SPOT_PRICE = 50_000.0
_BARRIER = 80_000.0

# "now" for the event — Unix ts (arbitrary fixed point).
_NOW_TS = 1_748_000_000  # 2025-05-23 approx

# end_date_iso ~1 year in the future so t_years ≈ 1.
import datetime as _dt
_RESOLUTION_DT = _dt.datetime.fromtimestamp(
    _NOW_TS + int(365.25 * 86400), tz=_dt.timezone.utc
)
_RESOLUTION_ISO = _RESOLUTION_DT.isoformat()

# Bars: 101 hourly bars ending just before _NOW_TS.
# Bars 0-99: constant 0.001 return  → quiet; last bar (bar 100) is the shock.
_N_QUIET_BARS = 100           # bars with return 0.001
_SHOCK_RETURN = -0.15         # final bar: −15 % → fires 3-sigma shock
_BAR_INTERVAL_S = 3_600       # 1 hour in seconds

# The 102nd price is the "event" price (event.price = p_market on Polymarket).
_P_MARKET = 0.10  # Polymarket YES price — far below expected p_bridge


def _seed_synthetic_db(session_factory):
    """Populate the in-memory DB with:
      - 1 Market ORM row for the synthetic market.
      - 102 hourly CryptoBar rows for BTCUSDT (101 for returns, 1 anchor).
      - 1 PriceSnapshot for walk_forward_backtest.
    Returns the seeded session_factory (same object — just side-effects).
    """
    with session_factory() as session:
        # --- Market row ---
        market = Market(
            id=_MARKET_ID,
            question="Will BTC reach $80k before 2027? [SYNTH GATE]",
            end_date_iso=_RESOLUTION_ISO,
            clob_token_ids=[_TOKEN_ID],
            active=True,
            closed=False,
        )
        session.add(market)

        # --- CryptoBar rows ---
        # Build 102 bars: bar i at ts = _NOW_TS - (102 - i) * 3600.
        # Close prices:
        #   price[0] = _SPOT_PRICE (anchor, not used as a return)
        #   price[i] for i in 1..101 computed from returns.
        # Quiet returns: 0.001 for bars 1-100.
        # Shock return: -0.15 for bar 101 (most recent).

        prices = [_SPOT_PRICE]
        for i in range(1, 101):         # 100 quiet bars
            prices.append(prices[-1] * (1.0 + 0.001))
        prices.append(prices[-1] * (1.0 + _SHOCK_RETURN))  # bar 101: shock

        # bars[0] is the anchor (only used as prev_close for bar 1's return).
        # bars[1]..bars[101] are the actual bars we want; we generate 102 bars
        # total (indices 0-101 in the list).
        n_bars = len(prices)  # = 102
        base_ts = _NOW_TS - (n_bars - 1) * _BAR_INTERVAL_S

        for i, close in enumerate(prices):
            bar_ts = base_ts + i * _BAR_INTERVAL_S
            session.add(
                CryptoBar(
                    symbol=_SYMBOL,
                    granularity="1h",
                    ts=bar_ts,
                    open=close * 0.999,
                    high=close * 1.001,
                    low=close * 0.999,
                    close=close,
                    volume=100.0,
                )
            )

        # --- PriceSnapshot for walk_forward_backtest ---
        # walk_forward_backtest iterates PriceSnapshot rows for the market;
        # each row becomes a ReplayEvent(ts, token_id, price).
        session.add(
            PriceSnapshot(
                market_id=_MARKET_ID,
                token_id=_TOKEN_ID,
                ts=_NOW_TS,
                price=_P_MARKET,
            )
        )

        session.commit()


def _build_pipeline(session_factory):
    """Construct all pipeline components using real implementations."""
    mapping_file = CryptoMarketMappingFile(
        market_id=_MARKET_ID,
        polymarket_question="Will BTC reach $80k before 2027? [SYNTH GATE]",
        symbol=_SYMBOL,
        barrier_price=_BARRIER,
        direction="up",
    )
    resolver = MarketResolver([mapping_file])

    def get_market(market_id: str):
        """Return a Market-compatible object from the seeded DB."""
        with session_factory() as session:
            return session.get(Market, market_id)

    def get_last_shock_ts(market_id: str):
        """No prior shock recorded."""
        return None

    return dict(
        get_market=get_market,
        get_last_shock_ts=get_last_shock_ts,
        market_resolver=resolver,
        crypto_data=CryptoDataAccess(session_factory=session_factory),
        shock_detector=SpotOnlyShockDetector(spot_threshold_k=3.0),
        composers=[
            BinaryComposer(),
            ExponentialComposer(),
            MagnitudeTiedComposer(),
            ConfidenceWeightedComposer(),
        ],
        blender=BayesianBlender(),
        agreement_filter=AgreementFilter(epsilon=0.08, min_active_count=3),
        tilt=AsymmetricTilt(tilt_magnitude=0.05),
        sizer=KellySizer(),
        performance_tracker=PerformanceTracker(trailing_window=15),
        session_factory=session_factory,
        # REAL implementations — not stubs.  This is what makes the gate
        # meaningful vs. the unit-level scenarios in test_model.py.
        fit_garch11=real_fit_garch11,
        prob_barrier_hit=real_pbh,
    )


# ---------------------------------------------------------------------------
# C2-A gate test
# ---------------------------------------------------------------------------

def test_c2a_e2e_gate_pipeline_produces_nonzero_position(session_factory):
    """C2-A gate: all 12 pipeline steps execute end-to-end and produce at
    least one CryptoPrediction with position_size > 0.

    Walk-forward flow:
      1. Seed a synthetic BTCUSDT market in the in-memory DB.
      2. Bind crypto_model to all pipeline components via partial (except
         the positional market_id/event args).
      3. Wrap in a closure that captures each CryptoPrediction.
      4. Call walk_forward_backtest — it replays the single PriceSnapshot row.
      5. Assert captured prediction has position_size > 0.

    If this fails: inspect captured[0].diagnostics to see which layer vetoed:
      - "market_not_found"         → Market row not seeded correctly.
      - "not_in_markets_yaml"      → MarketResolver mapping missing.
      - "all_modes_disabled"       → All ModeFloorState rows marked disabled.
      - "all_weights_zero"         → Blender returned zero weights.
      - "agreement_vetoed"         → <3 composers signaled long; tune
                                     barrier/p_market/returns.
      - position_size == 0 (no key)→ Kelly edge below minimum_edge (0.02);
                                     widen p_market ↔ p_bridge gap.
    """
    # Step 1: Seed the synthetic DB.
    _seed_synthetic_db(session_factory)

    # Step 2: Build pipeline component dict (real GARCH + real barrier).
    pipeline_kwargs = _build_pipeline(session_factory)

    # Step 3: Build a capturing wrapper around crypto_model.
    captured: list[CryptoPrediction] = []

    def capturing_model(market_id: str, event: ReplayEvent) -> CryptoPrediction:
        pred = crypto_model(market_id, event, **pipeline_kwargs)
        captured.append(pred)
        return pred

    # Step 4: Run walk_forward_backtest over the synthetic market.
    # resolutions={} → n_resolved=0 (backtest metrics are not the gate criterion).
    with session_factory() as session:
        walk_forward_backtest(
            session=session,
            model=capturing_model,
            resolutions={},
            market_ids=[_MARKET_ID],
            model_name="c2a-gate",
        )

    # Step 5: Gate assertion.
    assert len(captured) >= 1, (
        "walk_forward_backtest produced 0 events — PriceSnapshot seeding failed."
    )

    nonzero = [p for p in captured if p.position_size > 0.0]

    # Surface diagnostics before asserting so failures are debuggable.
    if not nonzero:
        diagnostics_summary = "\n".join(
            f"  event {i}: position_size={p.position_size:.6f}  "
            f"diagnostics={p.diagnostics}"
            for i, p in enumerate(captured)
        )
        pytest.fail(
            f"C2-A gate FAILED: no prediction has position_size > 0.\n"
            f"Captured {len(captured)} prediction(s):\n{diagnostics_summary}\n\n"
            f"Tune: check p_bridge vs p_market divergence, shock detector "
            f"threshold, or AgreementFilter min_active_count."
        )

    # Primary gate assertion.
    assert len(nonzero) >= 1, "unreachable — pytest.fail above guards this"

    # Structural invariants on the winning prediction.
    pred = nonzero[0]
    assert isinstance(pred, CryptoPrediction), (
        f"Expected CryptoPrediction, got {type(pred)}"
    )
    assert pred.market_id == _MARKET_ID
    assert pred.ts == _NOW_TS
    assert 0.0 < pred.position_size <= 0.10, (
        f"position_size={pred.position_size:.6f} outside (0, 0.10]"
    )
    assert 0.0 < pred.p_hat <= 1.0, (
        f"p_hat={pred.p_hat:.6f} not in (0, 1]"
    )
    # Diagnostics must contain pipeline internals (p_bridge, p_modes, etc.).
    assert "p_bridge" in pred.diagnostics, (
        f"diagnostics missing p_bridge: {pred.diagnostics}"
    )
    assert "p_modes" in pred.diagnostics, (
        f"diagnostics missing p_modes: {pred.diagnostics}"
    )
    assert pred.diagnostics.get("shock_active") is True, (
        f"Expected shock to be active on the shock bar; diagnostics={pred.diagnostics}"
    )
