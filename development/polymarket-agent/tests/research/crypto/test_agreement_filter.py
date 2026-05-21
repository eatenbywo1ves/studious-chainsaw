import pytest

from agent.research.crypto.agreement_filter import AgreementFilter


def _filter():
    return AgreementFilter()  # defaults: epsilon=0.08, min_active_count=3


def _modes(binary, exp, magnitude, confidence):
    return {"binary": binary, "exp": exp, "magnitude": magnitude, "confidence": confidence}


def test_scenario_1_strong_long_consensus():
    """All 4 modes above market by 0.21 — long consensus."""
    v = _filter().evaluate(p_market=0.10, p_modes=_modes(0.31, 0.31, 0.31, 0.31))
    assert v.allowed is True
    assert v.long_count == 4
    assert v.direction == "long"


def test_scenario_2_regime_t_equals_3_still_consensus():
    """3 days into regime, modes 2/3 still well above epsilon."""
    v = _filter().evaluate(p_market=0.07, p_modes=_modes(0.28, 0.240, 0.240, 0.28))
    assert v.allowed is True
    assert v.long_count == 4


def test_scenario_3_regime_t_equals_7_modes_2_3_below_epsilon():
    """7 days: modes 2/3 excess = 0.078 (just below 0.08 epsilon) -> neutral.
    Only modes 1 and 4 (excess 0.21 each) signal long. long_count=2 < 3 -> VETO.
    """
    v = _filter().evaluate(p_market=0.05, p_modes=_modes(0.26, 0.128, 0.128, 0.26))
    assert v.allowed is False
    assert v.long_count == 2


def test_scenario_4_regime_t_equals_21_only_mode_4_committed():
    """21 days: modes 2/3 fully decayed to near P_market, only modes 1, 4 long.
    With strict counting, 2 of 4 isn't enough -> VETO.
    """
    v = _filter().evaluate(p_market=0.02, p_modes=_modes(0.20, 0.061, 0.061, 0.20))
    assert v.allowed is False
    assert v.long_count == 2


def test_scenario_5_no_shock_no_signal():
    """All modes within epsilon of P_market -> long_count=short_count=0 -> VETO."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.50, 0.50, 0.50, 0.525))
    assert v.allowed is False
    assert v.long_count == 0
    assert v.short_count == 0
    assert v.direction == "none"


def test_scenario_6_borderline_4_of_4_long():
    """Mild over-reaction with 4 active long signals."""
    # Plan had 0.31 which fails strict > (0.25+0.08=0.33); corrected to 0.34 to match spec intent.
    v = _filter().evaluate(p_market=0.25, p_modes=_modes(0.38, 0.38, 0.34, 0.36))
    assert v.allowed is True
    assert v.long_count == 4


def test_scenario_7_mixed_mild():
    """2 above, 2 below — neither direction has 3-count -> VETO."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.55, 0.45, 0.50, 0.50))
    assert v.allowed is False


def test_scenario_8_strong_short_consensus():
    """4 modes well below market -> short consensus."""
    # Plan had 0.62 which fails strict < (0.70-0.08=0.62); corrected to 0.61 to match spec intent.
    v = _filter().evaluate(p_market=0.70, p_modes=_modes(0.55, 0.60, 0.61, 0.61))
    assert v.allowed is True
    assert v.short_count == 4
    assert v.direction == "short"


def test_scenario_9_only_one_above_epsilon():
    """Only confidence mode above by epsilon; long_count=1 -> VETO."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.55, 0.55, 0.55, 0.58))
    # excesses: 0.05, 0.05, 0.05, 0.08 -> only 0.08 > 0.08 is False (strict >)
    # so long_count = 0
    assert v.long_count == 0
    assert v.allowed is False


def test_scenario_10_three_long_one_neutral():
    """3 modes signal long with excess > 0.08, 1 is neutral."""
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.60, 0.60, 0.60, 0.51))
    # excesses: 0.10, 0.10, 0.10, 0.01 -> long_count = 3, short_count = 0
    assert v.long_count == 3
    assert v.allowed is True
    assert v.direction == "long"


def test_scenario_11_two_long_one_short_one_neutral():
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.60, 0.60, 0.50, 0.40))
    # excesses: +0.10, +0.10, 0.0, -0.10 -> long=2, short=1, neutral=1
    assert v.long_count == 2
    assert v.short_count == 1
    assert v.allowed is False  # neither direction has 3


def test_scenario_12_total_silence():
    v = _filter().evaluate(p_market=0.50, p_modes=_modes(0.50, 0.50, 0.50, 0.50))
    assert v.long_count == 0
    assert v.short_count == 0
    assert v.direction == "none"
    assert v.allowed is False
