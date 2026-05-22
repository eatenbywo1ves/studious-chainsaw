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
    if won:
        gross = (1.0 - t.entry_price) / t.entry_price
    else:
        gross = -1.0
    return gross - t.round_trip_cost


def _trade_is_win(t) -> bool:
    if t.direction == "yes":
        return t.outcome == 1
    return t.outcome == 0
