"""Market-price baseline model: the benchmark crypto_model must beat on Brier
to claim any edge.  p_hat = the last-traded YES price."""

from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def market_price_model(market_id: str, event: ReplayEvent) -> Prediction:
    return Prediction(market_id=market_id, ts=event.ts, p_hat=event.price)
