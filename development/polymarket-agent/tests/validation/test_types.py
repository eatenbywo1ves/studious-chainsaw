from agent.validation.types import (
    BacktestResult,
    KupiecResult,
    PaperFill,
    PaperTradeResult,
    PriceTick,
    Prediction,
    ResolvedOutcome,
    TradeSignal,
)


def test_all_phase_1a_types_importable():
    """Smoke test: every Phase 1A type is importable from agent.validation.types."""
    assert Prediction.__name__ == "Prediction"
    assert ResolvedOutcome.__name__ == "ResolvedOutcome"
    assert PriceTick.__name__ == "PriceTick"
    assert TradeSignal.__name__ == "TradeSignal"
    assert PaperFill.__name__ == "PaperFill"
    assert KupiecResult.__name__ == "KupiecResult"
    assert BacktestResult.__name__ == "BacktestResult"
    assert PaperTradeResult.__name__ == "PaperTradeResult"


def test_prediction_is_frozen():
    p = Prediction(market_id="m1", ts=1, p_hat=0.5)
    raised = False
    try:
        p.p_hat = 0.6  # type: ignore[misc]
    except Exception:
        raised = True
    assert raised is True
