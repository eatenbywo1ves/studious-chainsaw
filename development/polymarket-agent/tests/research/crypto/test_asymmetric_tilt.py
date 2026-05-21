from agent.research.crypto.asymmetric_tilt import AsymmetricTilt


def _tilt():
    return AsymmetricTilt()  # default tilt_magnitude=0.05


def test_case_1_p_bridge_above_p_market_adds_tilt():
    assert _tilt().apply(p_blend=0.30, p_market=0.10, p_bridge=0.32) == 0.35


def test_case_2_p_bridge_equals_p_market_no_tilt():
    """When p_bridge == p_market, condition is strictly p_bridge > p_market -> False."""
    assert _tilt().apply(p_blend=0.50, p_market=0.50, p_bridge=0.50) == 0.50


def test_case_3_p_bridge_below_p_market_no_tilt():
    assert _tilt().apply(p_blend=0.20, p_market=0.30, p_bridge=0.20) == 0.20


def test_case_4_clipped_to_one_at_upper_bound():
    """p_blend=0.95 + 0.05 = 1.00, which is exactly 1.0 (in range)."""
    assert _tilt().apply(p_blend=0.95, p_market=0.85, p_bridge=0.96) == 1.00


def test_case_5_clipped_to_one_when_over():
    """p_blend=0.98 + 0.05 = 1.03 -> clipped to 1.0."""
    assert _tilt().apply(p_blend=0.98, p_market=0.85, p_bridge=0.99) == 1.00


def test_case_6_no_tilt_when_p_bridge_below():
    assert _tilt().apply(p_blend=0.05, p_market=0.10, p_bridge=0.08) == 0.05


def test_case_7_tilt_applied():
    assert _tilt().apply(p_blend=0.25, p_market=0.20, p_bridge=0.40) == 0.30


def test_case_8_tilt_applied_middle():
    assert _tilt().apply(p_blend=0.50, p_market=0.40, p_bridge=0.60) == 0.55
