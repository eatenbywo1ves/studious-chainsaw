from agent.strategy.threshold import threshold_strategy
from agent.validation.types import Prediction


def _pred(p_hat: float, market_id: str = "m1", ts: int = 1000) -> Prediction:
    return Prediction(market_id=market_id, ts=ts, p_hat=p_hat)


def test_threshold_strategy_yes_signal():
    """§5.7 Case 1: p_hat=0.6, market=0.5, threshold=0.05 → YES, edge=0.10."""
    signal = threshold_strategy(_pred(0.6), market_yes_price=0.5, edge_threshold=0.05)
    assert signal is not None
    assert signal.side == "YES"
    assert signal.market_id == "m1"
    assert signal.ts == 1000
    assert signal.edge == 0.10
    assert signal.target_price == 0.5


def test_threshold_strategy_no_signal():
    """§5.7 Case 2: p_hat=0.5, market=0.6, threshold=0.05 → NO, edge=0.10."""
    signal = threshold_strategy(_pred(0.5), market_yes_price=0.6, edge_threshold=0.05)
    assert signal is not None
    assert signal.side == "NO"
    assert signal.edge == 0.10
    # NO target price = 1 - YES_price
    assert signal.target_price == 0.4


def test_threshold_strategy_below_threshold_returns_none():
    """§5.7 Case 3: p_hat=0.52, market=0.5, threshold=0.05 → None (edge=0.02 < 0.05)."""
    assert threshold_strategy(_pred(0.52), market_yes_price=0.5, edge_threshold=0.05) is None


def test_threshold_strategy_exact_threshold_is_signal():
    """Edge exactly equal to threshold counts as a signal (>= boundary)."""
    signal = threshold_strategy(_pred(0.55), market_yes_price=0.5, edge_threshold=0.05)
    assert signal is not None
    assert signal.side == "YES"
    assert signal.edge == 0.05


def test_threshold_strategy_rationale_includes_values():
    """Rationale string mentions both p_hat and market price."""
    signal = threshold_strategy(_pred(0.60), market_yes_price=0.45, edge_threshold=0.05)
    assert signal is not None
    assert "0.6" in signal.rationale or "0.60" in signal.rationale
    assert "0.45" in signal.rationale
