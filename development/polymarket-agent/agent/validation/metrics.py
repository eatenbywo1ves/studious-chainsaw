"""Phase 1A metrics: stateless functions for L7 validation.

All three functions are pure: same input → same output, no side effects.
The Kupiec test uses math.erfc (equivalent to scipy.stats.chi2.sf(LR, 1))
to avoid pulling scipy into hot paths; for non-trivial chi^2 computations
elsewhere, prefer scipy.stats.chi2.
"""

import math
from collections.abc import Iterable
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


def brier_score(pairs: Iterable[tuple[float, int]]) -> float:
    """Mean squared error: sum((p_hat - outcome)^2) / n.

    Outcomes must be 0 or 1.  Raises ValueError on empty input.
    """
    pairs_list = list(pairs)
    if not pairs_list:
        raise ValueError("brier_score requires at least one (p_hat, outcome) pair")
    sse = sum((p - o) ** 2 for p, o in pairs_list)
    return sse / len(pairs_list)


def reliability_curve(
    pairs: Iterable[tuple[float, int]],
    *,
    n_bins: int = 10,
    min_per_bin: int = 5,
) -> list[tuple[float, float] | tuple[None, None]]:
    """Bin predictions into n_bins evenly-spaced intervals over [0, 1].

    Per bin: (mean_predicted_p, observed_yes_frequency).
    Bins with fewer than min_per_bin observations report (None, None).
    """
    if n_bins < 1:
        raise ValueError(f"n_bins must be >= 1, got {n_bins}")

    bin_predictions: list[list[float]] = [[] for _ in range(n_bins)]
    bin_outcomes: list[list[int]] = [[] for _ in range(n_bins)]

    for p_hat, outcome in pairs:
        if not (0.0 <= p_hat <= 1.0):
            raise ValueError(f"p_hat must be in [0, 1], got {p_hat}")
        # Bin index: floor(p_hat * n_bins), clamped so p_hat=1.0 lands in last bin
        idx = min(int(p_hat * n_bins), n_bins - 1)
        bin_predictions[idx].append(p_hat)
        bin_outcomes[idx].append(outcome)

    result: list[tuple[float, float] | tuple[None, None]] = []
    for preds, outs in zip(bin_predictions, bin_outcomes):
        if len(preds) < min_per_bin:
            result.append((None, None))
        else:
            mean_p = sum(preds) / len(preds)
            obs_freq = sum(outs) / len(outs)
            result.append((mean_p, obs_freq))
    return result
