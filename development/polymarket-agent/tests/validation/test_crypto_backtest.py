"""Tests for the C3a validation orchestrator + pre-committed verdict.

The MODEL is faked (controlled p_hats / position_size / diagnostics) so the
verdict scenarios are deterministic, but every metric (brier, bootstrap CI,
simulate_pnl, walk_forward_backtest) runs for real.  Each market is seeded with
exactly one PriceSnapshot, so walk_forward yields one ReplayEvent per market.
"""

from agent.research.crypto.model import CryptoPrediction
from agent.store.schema import Market, PriceSnapshot
from agent.validation.baseline import market_price_model
from agent.validation.crypto_backtest import run_validation
from agent.validation.types import ResolvedOutcome

_HOLD_SECONDS = 3600  # resolved_ts - entry_ts; must be > 0 for a real Sharpe.


def _seed(session, specs):
    """specs: list of (market_id, snapshot_price, outcome).
    Seeds one Market + one PriceSnapshot each, returns market_ids and a
    resolutions dict (resolved_ts strictly after the snapshot ts)."""
    market_ids = []
    resolutions = {}
    for i, (mid, price, outcome) in enumerate(specs):
        token = f"tok-{mid}"
        ts = 1_700_000_000 + i
        session.add(
            Market(id=mid, question=f"q-{mid}", clob_token_ids=[token])
        )
        session.add(
            PriceSnapshot(market_id=mid, token_id=token, ts=ts, price=price)
        )
        resolutions[mid] = ResolvedOutcome(
            market_id=mid, outcome=outcome, resolved_ts=ts + _HOLD_SECONDS
        )
        market_ids.append(mid)
    session.commit()
    return market_ids, resolutions


def _fake_model(p_hat_by_market, *, size=0.10, direction_by_market=None):
    """Fake crypto_model: dictated p_hat per market, fixed position size,
    diagnostics carrying kelly_direction + p_market (the YES price)."""

    def m(market_id, event):
        if direction_by_market is not None:
            direction = direction_by_market[market_id]
        else:
            direction = "yes"
        return CryptoPrediction(
            market_id=market_id,
            ts=event.ts,
            p_hat=p_hat_by_market[market_id],
            position_size=size,
            diagnostics={
                "kelly_direction": direction,
                "p_market": event.price,
            },
        )

    return m


_UPSTREAM = {
    "enumerated": 100,
    "parsed_ok": 80,
    "passed_validation": 60,
    "had_ohlcv": 50,
    "had_resolution": 40,
}
_WINDOW = ("2026-01-01", "2026-03-31")


def test_verdict_stop_when_no_skill(session):
    # Baseline price perfectly calibrated (= outcome); model badly wrong.
    specs = [
        ("m1", 1.0, 1),
        ("m2", 0.0, 0),
        ("m3", 1.0, 1),
    ]
    market_ids, resolutions = _seed(session, specs)
    # Model predicts the opposite of the (perfectly calibrated) baseline.
    model = _fake_model({"m1": 0.1, "m2": 0.9, "m3": 0.1})

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    assert report.model_brier > report.baseline_brier
    assert report.verdict == "STOP"


def test_verdict_inconclusive_low_coverage(session):
    # Model clearly beats baseline, but only 3 markets tested (< 20).
    specs = [
        ("m1", 0.5, 1),
        ("m2", 0.5, 0),
        ("m3", 0.5, 1),
    ]
    market_ids, resolutions = _seed(session, specs)
    model = _fake_model({"m1": 0.95, "m2": 0.05, "m3": 0.95})

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    assert report.verdict == "INCONCLUSIVE"
    assert report.coverage["actually_tested"] == 3
    assert "coverage" in report.verdict_rationale.lower()


def test_all_four_cost_scenarios_present(session):
    specs = [("m1", 0.5, 1), ("m2", 0.5, 0)]
    market_ids, resolutions = _seed(session, specs)
    model = _fake_model({"m1": 0.9, "m2": 0.1})

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    assert set(report.by_cost.keys()) == {0.0, 0.01, 0.02, 0.03}


def test_brier_skill_score_independently_recomputed(session):
    specs = [
        ("m1", 0.5, 1),
        ("m2", 0.4, 0),
        ("m3", 0.5, 1),
        ("m4", 0.6, 0),
    ]
    market_ids, resolutions = _seed(session, specs)
    model_p = {"m1": 0.9, "m2": 0.2, "m3": 0.8, "m4": 0.3}
    model = _fake_model(model_p)

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    # Recompute with RAW INLINE MATH — no risk_metrics import/call.
    model_pairs = [(model_p[mid], outcome) for mid, _, outcome in specs]
    baseline_pairs = [(price, outcome) for _, price, outcome in specs]
    m_sse = sum((p - o) ** 2 for p, o in model_pairs) / len(model_pairs)
    b_sse = sum((p - o) ** 2 for p, o in baseline_pairs) / len(baseline_pairs)
    expected = 1.0 - m_sse / b_sse

    assert abs(report.brier_skill_score - expected) < 1e-9


def test_verdict_continue_with_strong_edge_and_coverage(session):
    # 24 markets, alternating outcomes. Baseline price = 0.5 (uninformative).
    # Model: 0.9 when outcome=1, 0.1 when outcome=0. kelly_direction matches
    # the outcome so every trade wins -> positive Sharpe at every cost.
    specs = []
    model_p = {}
    directions = {}
    for i in range(24):
        outcome = i % 2  # 12 ones, 12 zeros
        mid = f"m{i}"
        specs.append((mid, 0.5, outcome))
        model_p[mid] = 0.9 if outcome == 1 else 0.1
        directions[mid] = "yes" if outcome == 1 else "no"
    market_ids, resolutions = _seed(session, specs)
    model = _fake_model(model_p, direction_by_market=directions)

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    assert report.coverage["actually_tested"] >= 20
    assert report.brier_skill_ci[0] > 0
    assert report.by_cost[0.01].sharpe > 0
    assert report.verdict == "CONTINUE"


def test_verdict_inconclusive_ci_straddles_zero(session):
    # 24 markets. Baseline price = 0.5. Model is only marginally better on
    # average with high per-market variance: most markets a small correct
    # tilt, a sizeable minority an equal-and-opposite wrong tilt. Point skill
    # comes out slightly positive but the bootstrap CI lower bound <= 0.
    specs = []
    model_p = {}
    for i in range(24):
        outcome = i % 2
        mid = f"m{i}"
        specs.append((mid, 0.5, outcome))
        # First 14 markets: small CORRECT tilt; last 10: small WRONG tilt.
        if i < 14:
            model_p[mid] = 0.6 if outcome == 1 else 0.4
        else:
            model_p[mid] = 0.4 if outcome == 1 else 0.6
    market_ids, resolutions = _seed(session, specs)
    model = _fake_model(model_p)

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    assert report.coverage["actually_tested"] >= 20
    assert report.brier_skill_score > 0
    assert report.brier_skill_ci[0] <= 0
    assert report.verdict == "INCONCLUSIVE"
    rationale = report.verdict_rationale.lower()
    assert "luck" in rationale or "ci" in rationale


def test_per_mode_empty_for_fake_models(session):
    # Fakes carry no "p_modes" diagnostics -> per_mode must be empty (not
    # fabricated).
    specs = [("m1", 0.5, 1), ("m2", 0.5, 0)]
    market_ids, resolutions = _seed(session, specs)
    model = _fake_model({"m1": 0.9, "m2": 0.1})

    report = run_validation(
        session,
        model=model,
        baseline_model=market_price_model,
        resolutions=resolutions,
        market_ids=market_ids,
        window=_WINDOW,
        upstream_coverage=_UPSTREAM,
    )

    assert report.per_mode == {}
