import math

import pytest

from agent.validation.metrics import brier_score, kupiec_test, reliability_curve
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


def test_brier_perfect_miss():
    """§5.2 Case 1: pred=[0.0], outcome=[1] → Brier = 1.0 (worst case)."""
    assert brier_score([(0.0, 1)]) == 1.0


def test_brier_constant_half():
    """§5.2 Case 2: pred=[0.5]*3, outcome=[0,0,1] → Brier = 0.25."""
    assert math.isclose(
        brier_score([(0.5, 0), (0.5, 0), (0.5, 1)]),
        0.25,
        abs_tol=1e-10,
    )


def test_brier_mixed_calibration():
    """§5.2 Case 3: pred=[0.1,0.9,0.6], outcome=[0,1,1] → Brier = 0.06."""
    assert math.isclose(
        brier_score([(0.1, 0), (0.9, 1), (0.6, 1)]),
        0.06,
        abs_tol=1e-10,
    )


def test_brier_empty_raises():
    """§5.2 Case 4: empty input raises ValueError."""
    with pytest.raises(ValueError):
        brier_score([])


def test_reliability_curve_calibrated_200():
    """§5.3 main case: 200 predictions evenly across [0,1] (20 per decile bin)
    with synthetic outcomes engineered so predicted bin midpoint == observed
    yes-frequency.  All bins non-None and match midpoints exactly.

    Why 20 per bin (not 10): for any decile midpoint m, n_yes = m*20 is an
    integer (1, 3, 5, ..., 19) so obs_freq = n_yes/20 = m exactly.  A 10-per-bin
    construction would give n_yes = m*10 which is fractional for every decile
    midpoint and cannot match m as an obs_freq.
    """
    pairs: list[tuple[float, int]] = []
    for bin_idx in range(10):
        midpoint = (bin_idx + 0.5) / 10  # 0.05, 0.15, ..., 0.95
        n_yes = round(midpoint * 20)  # 1, 3, 5, ..., 19 — always integer
        for i in range(20):
            outcome = 1 if i < n_yes else 0
            pairs.append((midpoint, outcome))

    curve = reliability_curve(pairs)

    assert len(curve) == 10
    for bin_idx, (mean_p, obs_freq) in enumerate(curve):
        expected_mid = (bin_idx + 0.5) / 10
        assert mean_p is not None
        assert obs_freq is not None
        assert math.isclose(mean_p, expected_mid, abs_tol=1e-10)
        assert math.isclose(obs_freq, expected_mid, abs_tol=1e-10)


def test_reliability_curve_too_few_per_bin():
    """§5.3 edge case: 25 predictions spread across 10 bins → <5/bin → all (None, None)."""
    pairs = [(i / 25, i % 2) for i in range(25)]

    curve = reliability_curve(pairs)

    assert len(curve) == 10
    assert all(mean_p is None and obs_freq is None for mean_p, obs_freq in curve)


def test_reliability_curve_top_bin_includes_one():
    """Predictions equal to 1.0 fall in the last bin, not out of range."""
    pairs = [(1.0, 1)] * 5
    curve = reliability_curve(pairs)
    # Bin 9 (the [0.9, 1.0] bin) should have all 5 observations
    assert curve[9] == (1.0, 1.0)


def test_reliability_curve_invalid_p_hat():
    """p_hat outside [0,1] raises ValueError."""
    with pytest.raises(ValueError):
        reliability_curve([(1.5, 1)])
    with pytest.raises(ValueError):
        reliability_curve([(-0.1, 0)])


def test_reliability_curve_invalid_n_bins():
    """n_bins must be >= 1."""
    with pytest.raises(ValueError):
        reliability_curve([(0.5, 1)], n_bins=0)


def test_reliability_curve_invalid_min_per_bin():
    """min_per_bin must be >= 1 — 0 or negative raises ValueError."""
    with pytest.raises(ValueError):
        reliability_curve([(0.5, 1)], min_per_bin=0)
    with pytest.raises(ValueError):
        reliability_curve([(0.5, 1)], min_per_bin=-1)
