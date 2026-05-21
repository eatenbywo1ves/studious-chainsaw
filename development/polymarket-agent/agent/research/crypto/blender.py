"""BayesianBlender: aggregate 4 mode predictions via inverse-Brier weighting.

  score_i  = 1 / max(trailing_brier_i, brier_floor_i)   (warm modes)
  score_i  = 1 / brier_floor_i                            (cold modes, < min trades)
  w_i      = score_i / sum_j(score_j)   over non-disabled modes
  p_blend  = sum_i(w_i * p_mode_i)

Cold-start: a mode with fewer than `cold_start_min_trades` closed trades scores
at the floor rate (1 / brier_floor), putting it on equal footing with a
floor-clamped warm mode.  This prevents a single early bad trade from
prematurely tanking a mode's weight before we have enough data to judge it.

Floor semantics (decision recorded in spec §8.2): `max(trailing_brier, floor)`
caps the MAXIMUM score (minimum effective Brier), preventing a near-zero-Brier
lucky mode from dominating.  With floor=0.10, all modes performing better than
0.10 Brier are weighted roughly equally; differentiation kicks in for modes
performing WORSE than the floor (e.g., a mode collapsing during a regime
change).  Fading of chronically-bad modes is handled by the disable-streak
mechanism in PerformanceTracker, not the floor.

Disabled modes contribute 0 weight.  If all modes are disabled, weights are
all-zero (caller treats as no-trade).
"""

from sqlalchemy.orm import Session

from agent.research.crypto.types import BlendOutput, ModeWeights


ALL_MODE_NAMES = ["binary", "exp", "magnitude", "confidence"]


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

        # Assign each non-disabled mode an inverse-Brier score.
        scores: dict[str, float] = {}
        for name, mode_state in state.items():
            if mode_state.is_disabled:
                continue
            if mode_state.n_closed_trades < self.cold_start_min_trades:
                # Cold mode: score at the floor rate (equal footing with a
                # floor-clamped warm mode).  Avoids judging on too little data.
                effective_brier = mode_state.brier_floor
            else:
                effective_brier = max(mode_state.trailing_brier, mode_state.brier_floor)
            scores[name] = 1.0 / effective_brier if effective_brier > 0 else 0.0

        if not scores or sum(scores.values()) == 0.0:
            zero = ModeWeights(0.0, 0.0, 0.0, 0.0)
            # p_blend is meaningless when no mode is active; echo P_market-ish
            # value (any p_mode) so callers reading p_blend don't see NaN.
            any_p = next(iter(p_modes.values())) if p_modes else 0.0
            return BlendOutput(p_blend=any_p, weights=zero)

        total = sum(scores.values())
        final_weights = {n: scores.get(n, 0.0) / total for n in ALL_MODE_NAMES}

        p_blend = sum(final_weights[n] * p_modes[n] for n in ALL_MODE_NAMES)

        return BlendOutput(
            p_blend=p_blend,
            weights=ModeWeights(
                w_binary=final_weights["binary"],
                w_exp=final_weights["exp"],
                w_magnitude=final_weights["magnitude"],
                w_confidence=final_weights["confidence"],
            ),
        )
