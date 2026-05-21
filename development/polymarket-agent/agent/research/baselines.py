"""Phase 1A baseline 'models' — stand-ins for real L3 modules.

These two functions exist to validate the L7 infrastructure: last_traded_price
should produce GREEN Kupiec on real Polymarket data by construction (markets
are martingales); constant_half should produce a recognizably worse result on
any market not genuinely 50/50.

Phase 1B+ replaces these with real per-category research modules.
"""

from agent.validation.backtest import ReplayEvent
from agent.validation.types import Prediction


def last_traded_price(market_id: str, event: ReplayEvent) -> Prediction:
    """Martingale baseline: predict P(YES) = current YES-token price.

    Polymarket prices are martingales on [0, 1] that converge to 0 or 1 at
    resolution; therefore this baseline is calibrated by construction.
    """
    return Prediction(market_id=market_id, ts=event.ts, p_hat=event.price)


def constant_half(market_id: str, event: ReplayEvent) -> Prediction:
    """Calibration straw man: predict 0.5 for every market, every time.

    For any market NOT genuinely 50/50, this is miscalibrated.  Serves as
    L7's negative-control baseline.
    """
    return Prediction(market_id=market_id, ts=event.ts, p_hat=0.5)
