"""C3a validation orchestrator: the central module that assembles every prior
piece into a single `ValidationReport` and emits a pre-committed
CONTINUE/STOP/INCONCLUSIVE verdict.

The verdict gates a real money/effort decision, so the priority order of the
gates (STOP dominates; coverage before CI before cost) is fixed and must not be
weakened.  All metric math is delegated to the already-tested Task 1-3 modules;
this module only wires them and applies the §6 thresholds.
"""

from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from agent.validation.backtest import ReplayEvent, walk_forward_backtest
from agent.validation.pnl import simulate_pnl
from agent.validation.risk_metrics import (
    bootstrap_skill_ci,
    brier_skill_score,
    max_drawdown,
    profit_factor,
    sharpe_ratio,
    sortino_ratio,
    win_rate,
)
from agent.validation.types import Prediction, ResolvedOutcome

_SECONDS_PER_YEAR = 365.25 * 86400


@dataclass(frozen=True)
class CostScenarioMetrics:
    round_trip_cost: float
    final_bankroll: float
    sharpe: float
    sortino: float
    max_drawdown: float
    win_rate: float
    profit_factor: float
    n_trades: int


@dataclass(frozen=True)
class MarketResult:
    market_id: str
    model_p_hat: float
    baseline_p_hat: float
    outcome: int


@dataclass(frozen=True)
class ModeResult:
    mode: str
    mean_weight: float
    n_predictions: int


@dataclass(frozen=True)
class ValidationReport:
    window: tuple[str, str]
    coverage: dict[str, int]
    model_brier: float
    baseline_brier: float
    brier_skill_score: float
    brier_skill_ci: tuple[float, float]
    reliability_curve: list
    kupiec_zone: str | None
    by_cost: dict[float, CostScenarioMetrics]
    per_market: list[MarketResult]
    per_mode: dict[str, ModeResult]
    verdict: str  # "CONTINUE" | "STOP" | "INCONCLUSIVE"
    verdict_rationale: str


def _capture(model):
    """Wrap a model so every Prediction it returns is appended to a list,
    in the order walk_forward_backtest calls it (== market_ids order)."""
    captured: list = []

    def wrapped(market_id, event):
        pred = model(market_id, event)
        captured.append(pred)
        return pred

    return wrapped, captured


def _cost_scenario(
    captured_model: list,
    resolutions: dict[str, ResolvedOutcome],
    *,
    starting_bankroll: float,
    cost: float,
) -> CostScenarioMetrics:
    curve = simulate_pnl(
        captured_model,
        resolutions,
        starting_bankroll=starting_bankroll,
        round_trip_cost=cost,
    )

    returns = [
        (curve.bankroll[i + 1] - curve.bankroll[i]) / curve.bankroll[i]
        for i in range(len(curve.bankroll) - 1)
        if curve.bankroll[i] != 0.0
    ]

    if curve.trades:
        holds = [
            resolutions[t.market_id].resolved_ts - t.entry_ts
            for t in curve.trades
        ]
        mean_hold_s = sum(holds) / len(holds)
    else:
        mean_hold_s = 0.0
    periods_per_year = (
        _SECONDS_PER_YEAR / mean_hold_s if mean_hold_s > 0 else 1.0
    )

    return CostScenarioMetrics(
        round_trip_cost=cost,
        final_bankroll=curve.bankroll[-1],
        sharpe=sharpe_ratio(returns, periods_per_year=periods_per_year),
        sortino=sortino_ratio(returns, periods_per_year=periods_per_year),
        max_drawdown=max_drawdown(curve.bankroll),
        win_rate=win_rate(curve.trades),
        profit_factor=profit_factor(curve.trades),
        n_trades=len(curve.trades),
    )


def _per_market(
    captured_model: list,
    captured_baseline: list,
    resolutions: dict[str, ResolvedOutcome],
) -> list[MarketResult]:
    results: list[MarketResult] = []
    seen: set[str] = set()
    for i, pred in enumerate(captured_model):
        mid = pred.market_id
        if mid not in resolutions or mid in seen:
            continue
        seen.add(mid)
        results.append(
            MarketResult(
                market_id=mid,
                model_p_hat=pred.p_hat,
                baseline_p_hat=captured_baseline[i].p_hat,
                outcome=resolutions[mid].outcome,
            )
        )
    return results


def _per_mode(captured_model: list) -> dict[str, ModeResult]:
    """Aggregate mean per-mode weight across predictions that expose
    `diagnostics["p_modes"]` (a mode_name -> value dict).  Predictions
    without mode info contribute nothing; if none have it, returns {}."""
    sums: dict[str, float] = {}
    counts: dict[str, int] = {}
    for pred in captured_model:
        diagnostics = getattr(pred, "diagnostics", None)
        if not isinstance(diagnostics, dict):
            continue
        p_modes = diagnostics.get("p_modes")
        if not isinstance(p_modes, dict):
            continue
        for mode_name, value in p_modes.items():
            sums[mode_name] = sums.get(mode_name, 0.0) + float(value)
            counts[mode_name] = counts.get(mode_name, 0) + 1
    return {
        name: ModeResult(
            mode=name,
            mean_weight=sums[name] / counts[name],
            n_predictions=counts[name],
        )
        for name in sums
    }


def _decide_verdict(
    *,
    skill: float,
    actually_tested: int,
    ci: tuple[float, float],
    sharpe_1pct: float,
) -> tuple[str, str]:
    """Pre-committed §6 verdict.  Priority order is fixed:
    STOP > coverage gate > CI gate > cost gate > CONTINUE."""
    if skill <= 0:
        return (
            "STOP",
            f"brier_skill_score <= 0 ({skill:.4f}): the model does not beat "
            f"the market-price baseline. Stop.",
        )
    if actually_tested < 20:
        return (
            "INCONCLUSIVE",
            f"insufficient coverage: only {actually_tested} markets actually "
            f"tested (need >= 20). Cannot draw a conclusion.",
        )
    if ci[0] <= 0:
        return (
            "INCONCLUSIVE",
            f"brier_skill_ci lower bound <= 0 (ci={ci[0]:.4f}..{ci[1]:.4f}, "
            f"point skill={skill:.4f}): cannot rule out luck.",
        )
    if sharpe_1pct <= 0:
        return (
            "INCONCLUSIVE",
            f"edge does not survive cost: Sharpe at 1% round-trip cost is "
            f"{sharpe_1pct:.4f} (<= 0). Skill={skill:.4f}, "
            f"ci={ci[0]:.4f}..{ci[1]:.4f}.",
        )
    return (
        "CONTINUE",
        f"skill={skill:.4f} (ci={ci[0]:.4f}..{ci[1]:.4f}, lower bound > 0), "
        f"{actually_tested} markets tested, Sharpe at 1% cost="
        f"{sharpe_1pct:.4f} (> 0). Edge survives. Continue.",
    )


def run_validation(
    session: Session,
    *,
    model: Callable[[str, ReplayEvent], Prediction],
    baseline_model: Callable[[str, ReplayEvent], Prediction],
    resolutions: dict[str, ResolvedOutcome],
    market_ids: list[str],
    window: tuple[str, str],
    upstream_coverage: dict[str, int],
    starting_bankroll: float = 100.0,
    costs: tuple[float, ...] = (0.0, 0.01, 0.02, 0.03),
) -> ValidationReport:
    """Assemble the full C3a validation report and emit the gating verdict.

    Both `model` and `baseline_model` are replayed over the SAME market_ids in
    the SAME order via capturing wrappers, so `captured_model[i]` and
    `captured_baseline[i]` describe the same ReplayEvent — making the bootstrap
    pairs index-aligned.
    """
    if 0.01 not in costs:
        raise ValueError("costs must include 0.01 for the cost-survival gate")

    wrapped_model, captured_model = _capture(model)
    wrapped_baseline, captured_baseline = _capture(baseline_model)

    model_result = walk_forward_backtest(
        session,
        wrapped_model,
        resolutions,
        market_ids=market_ids,
        model_name="crypto",
    )
    baseline_result = walk_forward_backtest(
        session,
        wrapped_baseline,
        resolutions,
        market_ids=market_ids,
        model_name="baseline",
    )

    # Index-aligned pairs over events whose market is resolved.  The SAME index
    # set is used for both lists since they replay the same event stream.
    resolved_idx = [
        i
        for i in range(len(captured_model))
        if captured_model[i].market_id in resolutions
    ]
    model_pairs = [
        (
            captured_model[i].p_hat,
            resolutions[captured_model[i].market_id].outcome,
        )
        for i in resolved_idx
    ]
    baseline_pairs = [
        (
            captured_baseline[i].p_hat,
            resolutions[captured_model[i].market_id].outcome,
        )
        for i in resolved_idx
    ]

    model_brier = model_result.brier_score
    baseline_brier = baseline_result.brier_score
    skill = brier_skill_score(model_brier, baseline_brier)
    ci = bootstrap_skill_ci(model_pairs, baseline_pairs)

    reliability_curve = model_result.reliability_curve
    kupiec_zone = model_result.kupiec.zone if model_result.kupiec else None

    actually_tested = len(
        {p.market_id for p in captured_model if p.market_id in resolutions}
    )
    coverage = {**upstream_coverage, "actually_tested": actually_tested}

    by_cost = {
        cost: _cost_scenario(
            captured_model,
            resolutions,
            starting_bankroll=starting_bankroll,
            cost=cost,
        )
        for cost in costs
    }

    per_market = _per_market(captured_model, captured_baseline, resolutions)
    per_mode = _per_mode(captured_model)

    sharpe_1pct = by_cost[0.01].sharpe
    verdict, rationale = _decide_verdict(
        skill=skill,
        actually_tested=actually_tested,
        ci=ci,
        sharpe_1pct=sharpe_1pct,
    )

    return ValidationReport(
        window=window,
        coverage=coverage,
        model_brier=model_brier,
        baseline_brier=baseline_brier,
        brier_skill_score=skill,
        brier_skill_ci=ci,
        reliability_curve=reliability_curve,
        kupiec_zone=kupiec_zone,
        by_cost=by_cost,
        per_market=per_market,
        per_mode=per_mode,
        verdict=verdict,
        verdict_rationale=rationale,
    )
