"""Stub L4 strategy for Phase 1A.

A single trading rule: take a paper position when the model's prediction
disagrees with the market price by at least `edge_threshold`.  This exists
to give paper-trade-live something to consume in Phase 1A; real strategy
modules arrive in Phase 2.
"""

from agent.validation.types import Prediction, TradeSignal


def threshold_strategy(
    prediction: Prediction,
    market_yes_price: float,
    *,
    edge_threshold: float = 0.05,
) -> TradeSignal | None:
    """Buy YES if p_hat - market_yes_price >= threshold;
       Buy NO if market_yes_price - p_hat >= threshold;
       Else None (no signal).

    Target price for a YES signal is the current YES price (we would limit-buy
    at the current ask).  For a NO signal, target is `1 - market_yes_price`
    (the implied NO ask under Polymarket's binary token convention).
    """
    edge_yes = round(prediction.p_hat - market_yes_price, 10)
    edge_no = round(market_yes_price - prediction.p_hat, 10)

    if edge_yes >= edge_threshold:
        return TradeSignal(
            market_id=prediction.market_id,
            ts=prediction.ts,
            side="YES",
            target_price=market_yes_price,
            edge=edge_yes,
            rationale=(
                f"p_hat={prediction.p_hat:.3f} mkt_yes={market_yes_price:.3f}"
                f" edge={edge_yes:.3f}"
            ),
        )

    if edge_no >= edge_threshold:
        return TradeSignal(
            market_id=prediction.market_id,
            ts=prediction.ts,
            side="NO",
            target_price=1.0 - market_yes_price,
            edge=edge_no,
            rationale=(
                f"p_hat={prediction.p_hat:.3f} mkt_yes={market_yes_price:.3f}"
                f" edge={edge_no:.3f}"
            ),
        )

    return None
