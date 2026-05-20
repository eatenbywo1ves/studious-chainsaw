"""Phase 1A metrics: stateless functions for L7 validation.

All three functions are pure: same input → same output, no side effects.
The Kupiec test uses math.erfc (equivalent to scipy.stats.chi2.sf(LR, 1))
to avoid pulling scipy into hot paths; for non-trivial chi^2 computations
elsewhere, prefer scipy.stats.chi2.
"""

import math
from typing import Literal

from agent.validation.types import KupiecResult


def _xlogy(x: float, y: float) -> float:
    """0 * log(0) = 0 convention; otherwise x * log(y).  Used in Kupiec
    formula to handle the x=0 and x=n edge cases without log(0)."""
    if x == 0:
        return 0.0
    return x * math.log(y)


def kupiec_test(
    exceptions: int,
    trials: int,
    expected_rate: float,
    *,
    green_max: int = 4,
    orange_max: int = 9,
) -> KupiecResult:
    """Kupiec's unconditional-coverage LR test.

    H0: observed exception rate equals expected_rate.
    LR_uc = -2 * [x*ln(p) + (n-x)*ln(1-p) - x*ln(x/n) - (n-x)*ln((n-x)/n)]
    Under H0, LR_uc ~ chi^2(1).  p_value = chi2.sf(LR, 1) = erfc(sqrt(LR/2)).

    Zone is classified by raw exception count:
      exceptions <= green_max:           GREEN
      green_max < exceptions <= orange_max: ORANGE
      exceptions > orange_max:           RED
    """
    if trials <= 0:
        raise ValueError(f"trials must be positive, got {trials}")
    if not (0 < expected_rate < 1):
        raise ValueError(f"expected_rate must be in (0, 1), got {expected_rate}")
    if not (0 <= exceptions <= trials):
        raise ValueError(
            f"exceptions must be in [0, {trials}], got {exceptions}"
        )

    x = exceptions
    n = trials
    p = expected_rate
    p_hat = x / n

    lr = -2 * (
        _xlogy(x, p)
        + _xlogy(n - x, 1 - p)
        - _xlogy(x, p_hat)
        - _xlogy(n - x, 1 - p_hat)
    )
    p_value = math.erfc(math.sqrt(lr / 2))

    zone: Literal["GREEN", "ORANGE", "RED"]
    if exceptions <= green_max:
        zone = "GREEN"
    elif exceptions <= orange_max:
        zone = "ORANGE"
    else:
        zone = "RED"

    return KupiecResult(
        exceptions=exceptions,
        trials=trials,
        expected_rate=expected_rate,
        lr_statistic=lr,
        p_value=p_value,
        zone=zone,
    )
