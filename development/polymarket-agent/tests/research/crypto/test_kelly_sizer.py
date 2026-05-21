import pytest


def _s():
    from agent.research.crypto.kelly_sizer import KellySizer
    return KellySizer()  # defaults: mult=0.5, cap=0.10, min_edge=0.02


def test_case_1_covid_style_long():
    """P=0.31, q=0.10. raw_kelly = 0.10 * (0.31-0.10) / (0.31*0.69) = 0.0981.
    half_kelly = 0.0490.  Below cap (0.10).  Direction long.
    """
    k = _s().size(p_final=0.31, p_market=0.10)
    expected = 0.5 * 0.10 * (0.31 - 0.10) / (0.31 * 0.69)
    assert abs(k.fraction - expected) < 1e-4
    assert k.direction == "yes"


def test_case_2_ftx_style_entry_long():
    """P=0.32, q=0.10.  half_kelly = 0.5 * 0.10 * 0.22 / (0.32*0.68) ~ 0.0506."""
    k = _s().size(p_final=0.32, p_market=0.10)
    expected = 0.5 * 0.10 * (0.32 - 0.10) / (0.32 * 0.68)
    assert abs(k.fraction - expected) < 1e-4
    assert k.direction == "yes"


def test_case_3_zero_edge_zero_fraction():
    """P == q -> edge=0 -> fraction=0 regardless of direction."""
    k = _s().size(p_final=0.15, p_market=0.15)
    assert k.fraction == 0.0


def test_case_4_below_minimum_edge_zero_fraction():
    """edge = 0.05 - 0.10 = -0.05.  abs(edge) = 0.05.
    Wait, recompute: p_final=0.15, p_market=0.10 -> edge=0.05 > 0.02 min_edge.
    Re-read the test: spec says "below minimum_edge" but values give edge=0.05.
    Adjust: use p_final=0.11, p_market=0.10 -> edge=0.01 < 0.02 min_edge.
    """
    k = _s().size(p_final=0.11, p_market=0.10)
    assert k.fraction == 0.0


def test_case_5_medium_long_edge():
    """P=0.50, q=0.10.  raw = 0.10*0.40/(0.50*0.50) = 0.16.
    half = 0.08.  Below cap.
    """
    k = _s().size(p_final=0.50, p_market=0.10)
    expected = 0.5 * 0.10 * (0.50 - 0.10) / (0.50 * 0.50)
    assert abs(k.fraction - expected) < 1e-4
    assert k.direction == "yes"


def test_case_6_cap_engaged_long():
    """P=0.90, q=0.10.  Raw Kelly is very large; half-Kelly hits cap 0.10."""
    k = _s().size(p_final=0.90, p_market=0.10)
    assert k.fraction == 0.10  # capped


def test_case_7_short_edge_cap_engaged():
    """P=0.10, q=0.30 -> we believe YES at 10% but market prices 30%.
    Buy NO at $0.70 -> edge for NO direction.
    raw_kelly (NO direction) = (1-q) * ((1-P) - (1-q)) / ((1-P) * P) ... let me check.
    Actually use the symmetric formula in code.  Cap engages at 0.10 either way.
    """
    k = _s().size(p_final=0.10, p_market=0.30)
    assert k.fraction == 0.10
    assert k.direction == "no"


def test_case_8_small_short_below_cap():
    """P=0.25, q=0.30 -> mild NO edge.  Should be below cap."""
    k = _s().size(p_final=0.25, p_market=0.30)
    assert 0.0 < k.fraction < 0.10
    assert k.direction == "no"
