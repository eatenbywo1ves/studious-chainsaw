from agent.research.baselines import constant_half, last_traded_price
from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def _event(token_id: str = "t1", ts: int = 1000, price: float = 0.42) -> ReplayEvent:
    return ReplayEvent(ts=ts, token_id=token_id, price=price)


def test_last_traded_price_returns_market_price():
    """Predicts p_hat = current YES-token price."""
    event = _event(price=0.62)
    pred = last_traded_price("m1", event)
    assert isinstance(pred, Prediction)
    assert pred.market_id == "m1"
    assert pred.ts == 1000
    assert pred.p_hat == 0.62


def test_last_traded_price_handles_extremes():
    """p_hat=0 and p_hat=1 are both valid baseline outputs."""
    assert last_traded_price("m1", _event(price=0.0)).p_hat == 0.0
    assert last_traded_price("m1", _event(price=1.0)).p_hat == 1.0


def test_constant_half_always_returns_one_half():
    """Predicts p_hat = 0.5 regardless of input."""
    pred1 = constant_half("m1", _event(price=0.1))
    pred2 = constant_half("m2", _event(price=0.9))
    pred3 = constant_half("m3", _event(price=0.5))
    assert pred1.p_hat == 0.5
    assert pred1.market_id == "m1"
    assert pred2.market_id == "m2"
    assert pred3.market_id == "m3"
