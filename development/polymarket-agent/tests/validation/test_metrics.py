import math

import pytest

from agent.validation.metrics import kupiec_test
from agent.validation.types import KupiecResult


def test_kupiec_zero_exceptions():
    """§5.1 Case 1: x=0, n=100, p=0.05 → LR ≈ 10.2587, p ≈ 0.00136, GREEN."""
    result = kupiec_test(exceptions=0, trials=100, expected_rate=0.05)

    assert isinstance(result, KupiecResult)
    assert result.exceptions == 0
    assert result.trials == 100
    assert result.expected_rate == 0.05
    assert math.isclose(result.lr_statistic, 10.2587, abs_tol=1e-3)
    assert math.isclose(result.p_value, 0.00136, rel_tol=1e-3)
    assert result.zone == "GREEN"


def test_kupiec_seven_exceptions():
    """§5.1 Case 2: x=7, n=100, p=0.05 → LR ≈ 0.7530, p ≈ 0.3855, ORANGE."""
    result = kupiec_test(exceptions=7, trials=100, expected_rate=0.05)

    assert math.isclose(result.lr_statistic, 0.7530, abs_tol=1e-3)
    assert math.isclose(result.p_value, 0.3855, rel_tol=1e-3)
    assert result.zone == "ORANGE"


def test_kupiec_fifteen_exceptions():
    """§5.1 Case 3: x=15, n=100, p=0.05 → LR ≈ 14.0500, p ≈ 0.000178, RED."""
    result = kupiec_test(exceptions=15, trials=100, expected_rate=0.05)

    assert math.isclose(result.lr_statistic, 14.0500, abs_tol=1e-3)
    assert math.isclose(result.p_value, 0.000178, rel_tol=1e-2)
    assert result.zone == "RED"


def test_kupiec_zone_boundaries():
    """Zone thresholds: green ≤ 4, orange 5-9, red ≥ 10 (defaults)."""
    assert kupiec_test(exceptions=4, trials=100, expected_rate=0.05).zone == "GREEN"
    assert kupiec_test(exceptions=5, trials=100, expected_rate=0.05).zone == "ORANGE"
    assert kupiec_test(exceptions=9, trials=100, expected_rate=0.05).zone == "ORANGE"
    assert kupiec_test(exceptions=10, trials=100, expected_rate=0.05).zone == "RED"


def test_kupiec_invalid_inputs():
    """Validation: trials must be positive, expected_rate in (0,1), exceptions in [0,trials]."""
    with pytest.raises(ValueError):
        kupiec_test(exceptions=0, trials=0, expected_rate=0.05)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=0, trials=100, expected_rate=0.0)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=0, trials=100, expected_rate=1.0)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=-1, trials=100, expected_rate=0.05)
    with pytest.raises(ValueError):
        kupiec_test(exceptions=101, trials=100, expected_rate=0.05)
