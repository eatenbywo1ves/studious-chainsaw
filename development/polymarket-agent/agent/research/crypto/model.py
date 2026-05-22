"""crypto_model: top-level callable wiring the C2 composition pipeline.

Pipeline (in order):
  1.  resolve_market via market_resolver
  2.  compute spot, recent returns, GARCH vol via crypto_data
  3.  p_market from event.price  (Phase 1A ReplayEvent uses .price, not .p_market)
  4.  p_bridge via prob_barrier_hit
  5.  shock_state via shock_detector
  6.  p_modes via each composer
  7.  filter out disabled modes (consult performance_tracker)
  8.  blend_output via blender (enabled modes only)
  9.  verdict via agreement_filter (enabled modes only)
 10.  p_final via asymmetric_tilt (or p_market if vetoed / all-disabled)
 11.  kelly via sizer
 12.  emit CryptoPrediction (subclasses Phase 1A Prediction; p_hat = p_final)

ADAPTATION FROM PLAN: Phase 1A's ReplayEvent has `.price` not `.p_market`.
Phase 1A's Prediction has `p_hat` not `p_final`.  CryptoPrediction subclasses
the frozen Prediction dataclass, mapping p_final → p_hat for compatibility.
There is no PolymarketState object — `get_market` and `get_last_shock_ts` are
passed as plain callables so the caller controls the look-up.
"""

from dataclasses import dataclass
from typing import Callable

from agent.validation.types import Prediction


@dataclass(frozen=True)
class CryptoPrediction(Prediction):
    """The output of crypto_model.

    Extends Phase 1A's Prediction so walk_forward_backtest can use it
    without modification:
      - p_hat (inherited): the model's P(YES) — same value as p_final.
      - ts (inherited): Unix seconds of the event.
      - market_id (inherited): Polymarket market ID.

    Additional fields:
      - position_size: half-Kelly fraction ∈ [0, 0.10] (0 = no trade).
      - diagnostics: dict with pipeline internals for debugging.
    """

    position_size: float
    diagnostics: dict


def crypto_model(
    market_id: str,
    event,
    *,
    get_market: Callable,
    get_last_shock_ts: Callable,
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
) -> CryptoPrediction:
    """Top-level crypto model function compatible with walk_forward_backtest.

    Adapts the C2 composition pipeline to Phase 1A's `(market_id, event)`
    call signature.  All heavy dependencies are injected as keyword arguments
    so partial-application produces a `Callable[[str, ReplayEvent], Prediction]`
    as required by walk_forward_backtest.

    Args:
        market_id: Polymarket market ID string.
        event: Phase 1A ReplayEvent; .price is the YES-token price in [0,1].
        get_market: Callable[[str], Market | None] — looks up the Market ORM row.
        get_last_shock_ts: Callable[[str], int | None] — returns last shock ts or None.
        market_resolver: MarketResolver instance.
        crypto_data: CryptoDataAccess instance.
        shock_detector: ShockDetector instance (SpotOnlyShockDetector in C2-A).
        composers: List[Composer] — exactly 4 composers in canonical order.
        blender: BayesianBlender instance.
        agreement_filter: AgreementFilter instance.
        tilt: AsymmetricTilt instance.
        sizer: KellySizer instance.
        performance_tracker: PerformanceTracker instance.
        session_factory: SQLAlchemy sessionmaker; opened internally per call.
        fit_garch11: Injectable override for testing (default: real fit_garch11).
        prob_barrier_hit: Injectable override for testing (default: real fn).

    Returns:
        CryptoPrediction with p_hat == p_final, position_size, and diagnostics.

    Raises:
        ValueError: Propagated from MarketResolver when end_date_iso is missing.
    """
    # ADAPTATION: event.price is P(YES) per Phase 1A ReplayEvent definition.
    p_market: float = event.price

    # Step 1: Resolve the market to a crypto mapping.
    market = get_market(market_id)
    if market is None:
        return CryptoPrediction(
            market_id=market_id,
            ts=event.ts,
            p_hat=p_market,
            position_size=0.0,
            diagnostics={"reason": "market_not_found"},
        )

    mapping = market_resolver.resolve(market)
    if mapping is None:
        return CryptoPrediction(
            market_id=market_id,
            ts=event.ts,
            p_hat=p_market,
            position_size=0.0,
            diagnostics={"reason": "not_in_markets_yaml"},
        )

    # Step 2: Time-to-resolution.
    t_years = market_resolver.time_to_resolution_years(mapping, event.ts)

    # Lazy-import real implementations (allows test injection without side-effects).
    if fit_garch11 is None:
        from agent.research.crypto.vol_estimator import fit_garch11 as _fit
        fit_garch11 = _fit
    if prob_barrier_hit is None:
        from agent.research.crypto.barrier_bridge import prob_barrier_hit as _pbh
        prob_barrier_hit = _pbh

    # Step 3: Spot, returns, GARCH vol.
    spot = crypto_data.get_current_spot(mapping.symbol, before_ts=event.ts)
    returns = crypto_data.get_recent_returns(
        mapping.symbol, granularity="1h", n_bars=500, before_ts=event.ts,
    )

    garch_result = fit_garch11(returns, periods_per_year=8760)

    # Step 4: Barrier-hit probability (P_bridge).
    p_bridge = prob_barrier_hit(
        spot=spot,
        barrier=mapping.barrier_price,
        time_remaining_years=t_years,
        annualized_vol=garch_result.current_conditional_vol,
        annualized_drift=0.0,
    )

    # Step 5: Shock detection.
    last_shock_ts = get_last_shock_ts(market_id)
    shock_state = shock_detector.detect(
        current_return=returns[-1] if returns else 0.0,
        garch_annualized_vol=garch_result.current_conditional_vol,
        periods_per_year=8760,
        recent_news_events=crypto_data.get_recent_news_for_currency(
            mapping.symbol[:3], since_ts=event.ts - 1800, until_ts=event.ts,
        ),
        now_ts=event.ts,
        last_shock_ts=last_shock_ts,
    )

    # Step 6: Per-composer mode predictions.
    p_modes: dict[str, float] = {
        c.name: c.compose(p_market, p_bridge, shock_state) for c in composers
    }

    # Step 7: Filter disabled modes BEFORE blender and agreement_filter.
    with session_factory() as session:
        tracker_state = performance_tracker.get_state(session)
        enabled_modes: dict[str, float] = {
            name: p for name, p in p_modes.items()
            if not tracker_state[name].is_disabled
        }

        if not enabled_modes:
            return CryptoPrediction(
                market_id=market_id,
                ts=event.ts,
                p_hat=p_market,
                position_size=0.0,
                diagnostics={"reason": "all_modes_disabled"},
            )

        # Step 8: Blend enabled modes.
        blend_out = blender.blend(enabled_modes, performance_tracker, session)

    if blend_out.weights.is_all_disabled():
        return CryptoPrediction(
            market_id=market_id,
            ts=event.ts,
            p_hat=p_market,
            position_size=0.0,
            diagnostics={"reason": "all_weights_zero"},
        )

    # Step 9: Agreement filter (on enabled modes only).
    verdict = agreement_filter.evaluate(p_market, enabled_modes)
    if not verdict.allowed:
        return CryptoPrediction(
            market_id=market_id,
            ts=event.ts,
            p_hat=p_market,
            position_size=0.0,
            diagnostics={
                "reason": "agreement_vetoed",
                "long_count": verdict.long_count,
                "short_count": verdict.short_count,
                "direction": verdict.direction,
            },
        )

    # Step 10: Asymmetric tilt.
    p_final = tilt.apply(blend_out.p_blend, p_market, p_bridge)

    # Step 11: Kelly sizing.
    kelly = sizer.size(p_final, p_market)

    # Step 12: Emit CryptoPrediction.
    return CryptoPrediction(
        market_id=market_id,
        ts=event.ts,
        p_hat=p_final,
        position_size=kelly.fraction,
        diagnostics={
            "p_market": p_market,
            "p_bridge": p_bridge,
            "p_modes": p_modes,
            "enabled_modes": list(enabled_modes.keys()),
            "weights": {
                "binary": blend_out.weights.w_binary,
                "exp": blend_out.weights.w_exp,
                "magnitude": blend_out.weights.w_magnitude,
                "confidence": blend_out.weights.w_confidence,
            },
            "p_blend": blend_out.p_blend,
            "p_final": p_final,
            "agreement_vetoed": False,
            "kelly_direction": kelly.direction,
            "shock_active": shock_state.active,
            "shock_severity": shock_state.severity if shock_state.active else None,
        },
    )
