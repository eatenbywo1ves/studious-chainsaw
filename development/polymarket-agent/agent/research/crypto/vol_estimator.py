"""GARCH(1,1) volatility estimator wrapping the `arch` package.

STRUCTURAL DEFENSE: `GARCHResult.current_conditional_vol` is annualized at
construction.  Period-vol is intentionally NOT exposed on the dataclass —
only annualized vol is reachable by consumers (e.g., barrier_bridge).
This prevents the unit-confusion bug class where a caller passes period-vol
to a function expecting annualized vol, silently producing answers off by
a factor of sqrt(periods_per_year) (~93x for hourly bars).
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass

from arch import arch_model


@dataclass(frozen=True)
class GARCHResult:
    """Fitted GARCH(1,1) parameters + diagnostic values.

    Field unit conventions:
      omega, alpha, beta: dimensionless variance-equation coefficients
      long_run_variance:  PERIOD units (ω / (1 - α - β))
      current_conditional_vol: ANNUALIZED (period-vol × sqrt(periods_per_year))

    The asymmetric annualization (vol annualized, variance not) is deliberate —
    it matches what downstream consumers (barrier_bridge.prob_barrier_hit)
    expect, and prevents accidental period-units passthrough.
    """

    omega: float
    alpha: float
    beta: float
    persistence: float
    n_obs: int
    periods_per_year: int
    long_run_variance: float
    current_conditional_vol: float  # ANNUALIZED (see docstring)


def fit_garch11(
    returns: Sequence[float],
    *,
    periods_per_year: int,
    rescale: bool = True,
) -> GARCHResult:
    """Fit GARCH(1,1) on a sequence of period returns.

    Wraps arch.arch_model(returns, vol='GARCH', p=1, q=1) with .fit(disp='off').

    Parameters:
      returns:           Sequence of period returns (simple, e.g.
                         (close_t - close_{t-1}) / close_{t-1}).
      periods_per_year:  Annualization factor.  8760 for hourly, 365 for daily.
      rescale:           arch's auto-rescaling helps optimizer convergence on
                         small returns.  Keep True unless debugging.

    Raises:
      ValueError if len(returns) < 100.
      ValueError if any return is NaN or inf.

    Note: arch's ConvergenceWarning is propagated as a warning, not raised.
    Caller can decide to retry with different start values or accept.
    """
    if len(returns) < 100:
        raise ValueError(
            f"fit_garch11 requires at least 100 observations, got {len(returns)}"
        )
    for i, r in enumerate(returns):
        if not math.isfinite(r):
            raise ValueError(
                f"fit_garch11 requires finite returns; index {i} is {r}"
            )

    model = arch_model(
        list(returns), vol="GARCH", p=1, q=1, rescale=rescale
    )
    fitted = model.fit(disp="off")

    # arch's params are named: "omega", "alpha[1]", "beta[1]"
    omega = float(fitted.params["omega"])
    alpha = float(fitted.params["alpha[1]"])
    beta = float(fitted.params["beta[1]"])

    # If rescale=True, arch returns rescaled params; un-rescale to original units
    if rescale and hasattr(fitted, "scale") and fitted.scale != 1.0:
        scale = fitted.scale
        # arch's rescaling multiplies returns by 'scale' before fitting;
        # variance scales by scale^2.  omega and long_run_variance are in
        # variance units, so divide by scale^2.  alpha and beta are
        # dimensionless ratios and don't rescale.
        omega = omega / (scale ** 2)

    persistence = alpha + beta
    long_run_variance = omega / (1.0 - persistence) if persistence < 1.0 else float("inf")

    # arch's conditional_volatility is a numpy array in scaled STDEV units;
    # take last value, un-scale, then annualize.
    last_cv_scaled = float(fitted.conditional_volatility[-1])
    if rescale and hasattr(fitted, "scale") and fitted.scale != 1.0:
        last_period_vol = last_cv_scaled / fitted.scale
    else:
        last_period_vol = last_cv_scaled
    current_conditional_vol = last_period_vol * math.sqrt(periods_per_year)

    return GARCHResult(
        omega=omega,
        alpha=alpha,
        beta=beta,
        persistence=persistence,
        n_obs=len(returns),
        periods_per_year=periods_per_year,
        long_run_variance=long_run_variance,
        current_conditional_vol=current_conditional_vol,
    )


def forecast_garch_annualized_vol(
    result: GARCHResult,
    horizon_periods: int,
) -> float:
    """Iterative GARCH(1,1) variance forecast `h` periods ahead, then annualized.

    σ²(t+h) = long_run_variance + persistence^h · (σ²(t+1) - long_run_variance)

    Returns the annualized vol at horizon h.  At h=1, returns the
    `current_conditional_vol` (already annualized).  As h → ∞, returns
    sqrt(long_run_variance · periods_per_year).

    Raises ValueError if horizon_periods <= 0.  Callers wanting h=0 should
    use result.current_conditional_vol directly.
    """
    if horizon_periods <= 0:
        raise ValueError(
            f"horizon_periods must be >= 1, got {horizon_periods}"
        )

    # Convert current_conditional_vol (annualized) back to period variance
    current_period_var = (
        result.current_conditional_vol ** 2
    ) / result.periods_per_year

    # Closed-form GARCH(1,1) multi-step recursion (textbook form):
    #   σ²(t+h|t) = σ²_∞ + ρ^(h-1) · (σ²(t+1|t) - σ²_∞)
    # At h=1, ρ^0 = 1, so this returns σ²(t+1) (the existing one-step-ahead).
    # As h → ∞, ρ^(h-1) → 0, so it converges to σ²_∞.
    period_var_at_h = (
        result.long_run_variance
        + (result.persistence ** (horizon_periods - 1))
        * (current_period_var - result.long_run_variance)
    )

    # Annualize and return as vol
    return math.sqrt(period_var_at_h * result.periods_per_year)
