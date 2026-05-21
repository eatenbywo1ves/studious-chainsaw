import pytest


def test_shock_state_severity_clipped_at_construction():
    """ShockState clips severity to [0, 1] regardless of input."""
    from agent.research.crypto.types import ShockState

    s = ShockState(active=True, severity=1.5, spot_signal=True, news_signal=False, time_since_shock_seconds=0)
    assert s.severity == 1.0

    s2 = ShockState(active=True, severity=-0.2, spot_signal=False, news_signal=True, time_since_shock_seconds=0)
    assert s2.severity == 0.0


def test_shock_state_is_frozen():
    """ShockState is immutable — direct field assignment raises FrozenInstanceError."""
    from dataclasses import FrozenInstanceError
    from agent.research.crypto.types import ShockState

    s = ShockState(active=False, severity=0.0, spot_signal=False, news_signal=False, time_since_shock_seconds=0)
    with pytest.raises(FrozenInstanceError):
        s.severity = 0.5  # type: ignore[misc]


def test_mode_weights_is_all_disabled_true_when_all_zero():
    from agent.research.crypto.types import ModeWeights

    w = ModeWeights(w_binary=0.0, w_exp=0.0, w_magnitude=0.0, w_confidence=0.0)
    assert w.is_all_disabled() is True


def test_mode_weights_is_all_disabled_false_when_any_nonzero():
    from agent.research.crypto.types import ModeWeights

    w = ModeWeights(w_binary=0.25, w_exp=0.0, w_magnitude=0.5, w_confidence=0.25)
    assert w.is_all_disabled() is False


def test_kelly_fraction_clipped_to_kelly_cap():
    """KellyFraction.fraction is bounded to [0, kelly_cap=0.10] at construction."""
    from agent.research.crypto.types import KellyFraction

    k = KellyFraction(fraction=0.5, direction="yes", raw_kelly_pre_half=1.0)
    assert k.fraction == 0.10  # clipped


def test_kelly_fraction_zero_passes_through():
    from agent.research.crypto.types import KellyFraction

    k = KellyFraction(fraction=0.0, direction="yes", raw_kelly_pre_half=0.0)
    assert k.fraction == 0.0


def test_kelly_fraction_negative_clipped_to_zero():
    """KellyFraction clips negative raw fractions to 0.0 (under-range guard)."""
    from agent.research.crypto.types import KellyFraction

    k = KellyFraction(fraction=-0.5, direction="no", raw_kelly_pre_half=-1.0)
    assert k.fraction == 0.0


def test_crypto_market_mapping_construction():
    from agent.research.crypto.types import CryptoMarketMapping

    m = CryptoMarketMapping(
        market_id="0xABC001",
        symbol="BTCUSDT",
        barrier_price=80000.0,
        direction="up",
        resolution_ts=1751328000,
    )
    assert m.symbol == "BTCUSDT"
    assert m.direction == "up"
