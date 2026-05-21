import math
import pytest

from agent.research.crypto.composers import (
    BinaryComposer,
    ConfidenceWeightedComposer,
    ExponentialComposer,
    MagnitudeTiedComposer,
)
from agent.research.crypto.types import ShockState


def _ss(active=False, severity=0.0, t=0):
    """Shorthand to build a ShockState."""
    return ShockState(
        active=active,
        severity=severity,
        spot_signal=active,
        news_signal=False,
        time_since_shock_seconds=t,
    )


class TestBinaryComposer:
    def test_no_shock_returns_p_market(self):
        c = BinaryComposer()
        assert c.compose(p_market=0.10, p_bridge=0.30, shock_state=_ss(active=False)) == 0.10

    def test_within_window_returns_p_bridge(self):
        c = BinaryComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.8, t=3 * 86400),
        ) == 0.30

    def test_at_window_edge_just_before_end_returns_p_bridge(self):
        c = BinaryComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.8, t=14 * 86400 - 1),
        ) == 0.30

    def test_after_window_returns_p_market(self):
        c = BinaryComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.8, t=14 * 86400 + 1),
        ) == 0.10


class TestExponentialComposer:
    def test_t_zero_returns_p_bridge(self):
        c = ExponentialComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=0),
        ) == 0.30  # lambda(0) = exp(0) = 1

    def test_t_equals_tau_blends_at_exp_minus_one(self):
        """At t=tau, lambda = exp(-1) ~ 0.368, so P_mode = 0.368*0.30 + 0.632*0.10 = 0.1736."""
        c = ExponentialComposer()
        result = c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=7 * 86400),
        )
        expected = math.exp(-1.0) * 0.30 + (1.0 - math.exp(-1.0)) * 0.10
        assert abs(result - expected) < 1e-9

    def test_t_equals_three_tau_long_tail(self):
        """At t=3*tau, lambda = exp(-3) ~ 0.0498, decay tail."""
        c = ExponentialComposer()
        result = c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=21 * 86400),
        )
        expected = math.exp(-3.0) * 0.30 + (1.0 - math.exp(-3.0)) * 0.10
        assert abs(result - expected) < 1e-9

    def test_no_shock_returns_p_market(self):
        c = ExponentialComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=False),
        ) == 0.10


class TestMagnitudeTiedComposer:
    def test_severity_one_t_zero_returns_p_bridge(self):
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.0, t=0),
        ) == 0.30

    def test_severity_half_t_zero_blends_50_50(self):
        """severity=0.5 means lambda_0=0.5, so P_mode = 0.5*0.30 + 0.5*0.10 = 0.20."""
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.5, t=0),
        ) == 0.20

    def test_severity_above_one_clipped_via_shock_state(self):
        """ShockState clips severity to [0,1] at construction; composer sees 1.0."""
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=1.5, t=0),
        ) == 0.30  # ShockState already clipped to 1.0

    def test_severity_zero_returns_p_market(self):
        c = MagnitudeTiedComposer()
        assert c.compose(
            p_market=0.10, p_bridge=0.30,
            shock_state=_ss(active=True, severity=0.0, t=0),
        ) == 0.10


class TestConfidenceWeightedComposer:
    def test_small_divergence_returns_near_p_market(self):
        """Divergence 0.01 (below threshold 0.10): sigmoid input is negative, lambda~0."""
        c = ConfidenceWeightedComposer()
        # No shock needed - this composer ignores shock_state.
        result = c.compose(p_market=0.50, p_bridge=0.51, shock_state=_ss(active=False))
        # Loose tolerance: sigmoid at divergence=0.01 has lambda~0.135, not exactly 0
        assert abs(result - 0.50) < 0.05

    def test_large_divergence_returns_near_p_bridge(self):
        """Divergence 0.30 (well above threshold): sigmoid saturates, lambda~1."""
        c = ConfidenceWeightedComposer()
        result = c.compose(p_market=0.10, p_bridge=0.40, shock_state=_ss(active=False))
        # Sigmoid saturates by divergence=0.30 but not exactly to 1.0
        assert abs(result - 0.40) < 0.01

    def test_divergence_at_threshold_blends_midpoint(self):
        """Divergence exactly at threshold (0.10) gives sigmoid(0) = 0.5."""
        c = ConfidenceWeightedComposer()
        result = c.compose(p_market=0.50, p_bridge=0.40, shock_state=_ss(active=False))
        # lambda = 0.5; P_mode = 0.5*0.40 + 0.5*0.50 = 0.45
        # Sigmoid(0) is exactly 0.5 by IEEE 754; assertion can be tight
        assert abs(result - 0.45) < 1e-6

    def test_zero_divergence_returns_p_market(self):
        c = ConfidenceWeightedComposer()
        assert c.compose(p_market=0.50, p_bridge=0.50, shock_state=_ss(active=False)) == 0.50


def test_all_composers_have_correct_name_attributes():
    """Composer.name is used by BayesianBlender for keying weights; verify all
    four match the spec's mode_name strings ('binary', 'exp', 'magnitude',
    'confidence')."""
    assert BinaryComposer().name == "binary"
    assert ExponentialComposer().name == "exp"
    assert MagnitudeTiedComposer().name == "magnitude"
    assert ConfidenceWeightedComposer().name == "confidence"
