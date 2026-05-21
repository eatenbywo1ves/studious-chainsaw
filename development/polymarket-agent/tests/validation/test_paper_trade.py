import math

from agent.validation.paper_trade import PaperTradeEngine
from agent.validation.types import (
    PaperTradeResult,
    Prediction,
    ResolvedOutcome,
    TradeSignal,
)


def _signal(market_id: str, side: str, target_price: float, ts: int = 1000) -> TradeSignal:
    return TradeSignal(
        market_id=market_id,
        ts=ts,
        side=side,  # type: ignore[arg-type]
        target_price=target_price,
        edge=0.1,
        rationale="test",
    )


def _outcome(market_id: str, outcome: int, ts: int = 2000) -> ResolvedOutcome:
    return ResolvedOutcome(
        market_id=market_id, outcome=outcome, resolved_ts=ts  # type: ignore[arg-type]
    )


def test_paper_trade_engine_deterministic_pnl():
    """§5.5 reference case:
      - 2x YES at $0.40 winning resolves YES (+0.60 each = +1.20 total)
      - 1x NO at $0.60 losing (NO position when market resolves YES → loss = 0.60)
      - Net PnL = +0.60
    """
    engine = PaperTradeEngine(model_name="test")

    engine.record_signal(_signal("m1", "YES", 0.40))
    engine.record_signal(_signal("m2", "YES", 0.40))
    engine.record_signal(_signal("m3", "NO", 0.60))

    engine.on_resolved(_outcome("m1", 1))  # YES wins -> +0.60
    engine.on_resolved(_outcome("m2", 1))  # YES wins -> +0.60
    engine.on_resolved(_outcome("m3", 1))  # NO position, YES wins -> -0.60

    result = engine.result()
    assert isinstance(result, PaperTradeResult)
    assert result.n_fills == 3
    assert result.n_resolved == 0  # n_resolved counts PREDICTIONS resolved; none recorded here
    assert math.isclose(result.paper_pnl, 0.60, abs_tol=1e-10)


def test_paper_trade_engine_records_predictions_for_metrics():
    """Predictions recorded separately feed the backtest_metrics inside result."""
    engine = PaperTradeEngine(model_name="test")

    engine.record_prediction(Prediction(market_id="m1", ts=1000, p_hat=0.5))
    engine.record_prediction(Prediction(market_id="m2", ts=1100, p_hat=0.5))
    engine.record_signal(_signal("m1", "YES", 0.40))
    engine.on_resolved(_outcome("m1", 1))
    engine.on_resolved(_outcome("m2", 0))

    result = engine.result()
    assert result.n_resolved == 2
    # Brier on constant 0.5 with outcomes [1, 0] = (0.25 + 0.25) / 2 = 0.25
    assert math.isclose(result.backtest_metrics.brier_score, 0.25, abs_tol=1e-10)


def test_paper_trade_engine_no_signal_on_resolve_returns_zero_pnl():
    """on_resolved for a market with no open position contributes 0 PnL."""
    engine = PaperTradeEngine(model_name="test")
    pnl = engine.on_resolved(_outcome("m1", 1))
    assert pnl == 0.0
    result = engine.result()
    assert result.paper_pnl == 0.0
    assert result.n_fills == 0


def test_paper_trade_engine_share_size_scaling():
    """position_size_shares=2.0 doubles realized PnL."""
    engine = PaperTradeEngine(model_name="test", position_size_shares=2.0)
    engine.record_signal(_signal("m1", "YES", 0.40))
    engine.on_resolved(_outcome("m1", 1))
    result = engine.result()
    # 2 shares: profit = 2 * (1.0 - 0.40) = 1.20
    assert math.isclose(result.paper_pnl, 1.20, abs_tol=1e-10)
