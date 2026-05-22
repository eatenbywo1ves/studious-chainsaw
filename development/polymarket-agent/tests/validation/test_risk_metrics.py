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
    model_pairs = [(1.0 if i % 2 == 0 else 0.0, i % 2 == 0) for i in range(50)]
    model_pairs = [(p, 1 if o else 0) for p, o in model_pairs]
    baseline_pairs = [(0.5, o) for _, o in model_pairs]
    lo1, hi1 = bootstrap_skill_ci(model_pairs, baseline_pairs, seed=42)
    lo2, hi2 = bootstrap_skill_ci(model_pairs, baseline_pairs, seed=42)
    assert (lo1, hi1) == (lo2, hi2)
    assert lo1 > 0


def test_bootstrap_skill_ci_no_edge_straddles_zero():
    pairs = [(0.5, i % 2) for i in range(50)]
    lo, hi = bootstrap_skill_ci(pairs, pairs, seed=42)
    assert lo <= 0.0 <= hi
