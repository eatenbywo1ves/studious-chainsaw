from agent.validation.backtest import ReplayEvent
from agent.validation.baseline import market_price_model


def test_market_price_model_returns_event_price_as_p_hat():
    event = ReplayEvent(ts=1000, token_id="tok", price=0.37)
    pred = market_price_model("0xMARKET", event)
    assert pred.p_hat == 0.37
    assert pred.market_id == "0xMARKET"
    assert pred.ts == 1000
