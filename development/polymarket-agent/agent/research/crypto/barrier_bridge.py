"""Closed-form one-touch barrier-hit probability for GBM with constant vol.

Uses the reflection principle.  Caller must supply ANNUALIZED vol and drift;
the parameter names make this explicit (defense against unit-confusion bugs).
"""

import math
from math import erf, exp, log, sqrt


def _phi(x: float) -> float:
    """Standard normal CDF: 0.5·(1 + erf(x/√2))."""
    return 0.5 * (1.0 + erf(x / sqrt(2.0)))


def prob_barrier_hit(
    spot: float,
    barrier: float,
    time_remaining_years: float,
    annualized_vol: float,
    annualized_drift: float = 0.0,
) -> float:
    """Probability that GBM(annualized_drift, annualized_vol) starting at
    `spot` touches `barrier` at some point in [0, time_remaining_years].

    Uses the reflection principle.  Returns a value in [0, 1].

    Edge cases handled explicitly:
      - spot == barrier: returns 1.0 (already touching).
      - time_remaining_years <= 0 (and spot != barrier): returns 0.0.
      - annualized_vol <= 0 with no deterministic-drift hit: returns 0.0.

    Drift convention: annualized_drift=0.0 is the agnostic-on-direction
    default; we forecast vol regime via GARCH but don't claim a directional
    view on the underlying.
    """
    # --- Edge cases first (cheap, defensive) -------------------------------
    if spot == barrier:
        return 1.0
    if time_remaining_years <= 0.0:
        return 0.0
    if annualized_vol <= 0.0:
        # Deterministic dynamics: does drift carry spot past barrier in time?
        if annualized_drift > 0 and barrier > spot:
            return (
                1.0
                if spot * exp(annualized_drift * time_remaining_years) >= barrier
                else 0.0
            )
        if annualized_drift < 0 and barrier < spot:
            return (
                1.0
                if spot * exp(annualized_drift * time_remaining_years) <= barrier
                else 0.0
            )
        return 0.0

    # --- Closed-form one-touch via reflection principle --------------------
    nu = annualized_drift - 0.5 * annualized_vol ** 2   # log-drift
    b = log(barrier / spot)                              # log-distance to barrier
    v = annualized_vol * sqrt(time_remaining_years)      # total vol over horizon
    sigma2 = annualized_vol ** 2

    if barrier > spot:
        # Up-barrier (b > 0)
        # P = N((νT - b)/v) + exp(2νb/σ²) · N((-νT - b)/v)
        term1 = _phi((nu * time_remaining_years - b) / v)
        prefactor = exp(2.0 * nu * b / sigma2)
        term2 = prefactor * _phi((-nu * time_remaining_years - b) / v)
    else:
        # Down-barrier (b < 0)
        # P = N((b - νT)/v) + exp(2νb/σ²) · N((b + νT)/v)
        term1 = _phi((b - nu * time_remaining_years) / v)
        prefactor = exp(2.0 * nu * b / sigma2)
        term2 = prefactor * _phi((b + nu * time_remaining_years) / v)

    # Numerical safety: clamp to [0, 1].  The formula CAN produce values
    # slightly outside this range for extreme inputs due to floating-point
    # accumulation.
    return max(0.0, min(1.0, term1 + term2))
