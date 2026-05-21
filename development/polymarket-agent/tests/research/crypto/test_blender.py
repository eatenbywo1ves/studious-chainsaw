"""Tests for BayesianBlender.

The 30-trade evolution test is NON-CIRCULAR: it cross-checks the blender's
weight output against an independent inverse-Brier reference function
(`_reference_weights_from_state`) that is written here, separately from
blender.py.  A bug in the blender's scoring or normalization produces a
mismatch.  It also asserts the qualitative regime-change property: the
confidence mode's weight collapses (relative to its peak and to the other
modes) during the regime-change phase (trades 16-30).

The earlier brainstorm sketch (40%->1% trajectory) is NOT used as a reference:
with floor=0.10, modes performing better than 0.10 Brier clamp to equal
weight by design, so that hand-drawn trajectory is not algorithmically
reproducible.  See spec §8.2.
"""

from agent.research.crypto.blender import BayesianBlender
from agent.research.crypto.performance_tracker import PerformanceTracker
from agent.research.crypto.types import ModeState
from agent.store.schema import ModeFloorState, ModePerformance


def _reference_weights_from_state(
    state: dict[str, ModeState],
    cold_start_min_trades: int = 3,
) -> dict[str, float]:
    """Independent inverse-Brier weight computation for cross-checking the
    blender.  Deliberately NOT imported from blender.py — re-derived from the
    ModeState dict so a bug in blender's scoring/normalization is caught.
    """
    scores: dict[str, float] = {}
    for name, ms in state.items():
        if ms.is_disabled:
            continue
        if ms.n_closed_trades < cold_start_min_trades:
            eff = ms.brier_floor
        else:
            eff = max(ms.trailing_brier, ms.brier_floor)
        scores[name] = 1.0 / eff if eff > 0 else 0.0
    total = sum(scores.values())
    if total <= 0:
        return {}
    return {name: s / total for name, s in scores.items()}


def test_cold_start_returns_equal_weights(session_factory):
    """No closed trades anywhere -> all weights 0.25."""
    tracker = PerformanceTracker(trailing_window=15)
    blender = BayesianBlender()

    p_modes = {"binary": 0.30, "exp": 0.30, "magnitude": 0.30, "confidence": 0.30}
    with session_factory() as session:
        result = blender.blend(p_modes, tracker, session)
    assert abs(result.weights.w_binary - 0.25) < 1e-9
    assert abs(result.weights.w_exp - 0.25) < 1e-9
    assert abs(result.weights.w_magnitude - 0.25) < 1e-9
    assert abs(result.weights.w_confidence - 0.25) < 1e-9
    assert abs(result.p_blend - 0.30) < 1e-9


def test_all_disabled_returns_zero_weights(session_factory):
    """If every mode is disabled, weights.is_all_disabled() is True."""
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

    tracker = PerformanceTracker(trailing_window=15)
    blender = BayesianBlender()
    p_modes = {"binary": 0.30, "exp": 0.30, "magnitude": 0.30, "confidence": 0.30}

    with session_factory() as session:
        result = blender.blend(p_modes, tracker, session)
    assert result.weights.is_all_disabled() is True


# Per-trade Brier scores: (binary, exp, magnitude, confidence).
# Trades 1-5: cold start (all modes still < 3 trades for the first 2; equal).
# Trades 6-15: honeymoon — confidence has the lowest Brier (best performer).
# Trades 16-30: regime change — confidence's Brier climbs to ~0.42 (worst).
_SCHEDULE = [
    (0.15, 0.15, 0.15, 0.15),  # 1
    (0.15, 0.15, 0.15, 0.15),  # 2
    (0.15, 0.15, 0.15, 0.15),  # 3
    (0.15, 0.15, 0.15, 0.15),  # 4
    (0.15, 0.15, 0.15, 0.15),  # 5
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


def test_30_trade_evolution_matches_independent_reference(session_factory):
    """Cross-check the blender against an independent inverse-Brier reference
    at checkpoints 5/10/15/20/25/30, and assert the qualitative regime-change
    collapse of the confidence mode.

    The seeded ModePerformance rows control the trailing Briers directly
    (p_mode is arbitrary; only brier_score matters for the blender's weights).
    """
    assert len(_SCHEDULE) == 30

    tracker = PerformanceTracker(trailing_window=15)
    blender = BayesianBlender()
    checkpoints = {5, 10, 15, 20, 25, 30}
    captured: dict[int, object] = {}

    p_modes = {"binary": 0.3, "exp": 0.3, "magnitude": 0.3, "confidence": 0.3}

    with session_factory() as session:
        for i, (b_b, b_e, b_m, b_c) in enumerate(_SCHEDULE, start=1):
            for mode_name, b in (("binary", b_b), ("exp", b_e),
                                 ("magnitude", b_m), ("confidence", b_c)):
                session.add(ModePerformance(
                    mode_name=mode_name,
                    market_id=f"0xABC{i:03d}",
                    p_mode=0.5,
                    p_market_at_prediction=0.5,
                    outcome=0,
                    brier_score=b,
                    closed_at=1747800000 + i * 86400,
                ))
            session.commit()
            if i in checkpoints:
                # Read the ModeState the blender will use, compute the
                # reference weights INDEPENDENTLY, then compare to the blender.
                state = tracker.get_state(session)
                expected = _reference_weights_from_state(state)
                result = blender.blend(p_modes, tracker, session)
                captured[i] = result.weights

                w = result.weights
                assert abs(w.w_binary - expected["binary"]) < 1e-9, f"trade {i} binary"
                assert abs(w.w_exp - expected["exp"]) < 1e-9, f"trade {i} exp"
                assert abs(w.w_magnitude - expected["magnitude"]) < 1e-9, f"trade {i} magnitude"
                assert abs(w.w_confidence - expected["confidence"]) < 1e-9, f"trade {i} confidence"

                # Weights sum to 1 at every checkpoint.
                total = w.w_binary + w.w_exp + w.w_magnitude + w.w_confidence
                assert abs(total - 1.0) < 1e-9, f"trade {i} weights don't sum to 1"

    # Qualitative regime-change property: confidence mode collapses.
    # At trade 15 (end of honeymoon) confidence is among the best;
    # by trade 30 (deep in regime change) it is the worst.
    conf_15 = captured[15].w_confidence
    conf_30 = captured[30].w_confidence
    assert conf_30 < conf_15, (
        f"confidence weight should collapse during regime change: "
        f"trade15={conf_15:.4f} trade30={conf_30:.4f}"
    )
    # By trade 30, confidence is the lowest-weighted of the four modes.
    w30 = captured[30]
    assert conf_30 < w30.w_binary
    assert conf_30 < w30.w_exp
    assert conf_30 < w30.w_magnitude
