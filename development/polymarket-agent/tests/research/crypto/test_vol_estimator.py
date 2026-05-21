import math
import random

import pytest

from agent.research.crypto.vol_estimator import (
    GARCHResult,
    fit_garch11,
    forecast_garch_annualized_vol,
)


def _generate_garch_series(
    omega: float, alpha: float, beta: float, n_obs: int, seed: int = 42,
) -> list[float]:
    """In-test GARCH(1,1) simulator with Gaussian innovations.

    Recursive variance: σ²_t = ω + α·ε²_{t-1} + β·σ²_{t-1}
    Initial variance: long-run variance ω/(1-α-β).
    Returns: ε_t ~ N(0, σ²_t).
    """
    rng = random.Random(seed)
    sigma2 = omega / (1.0 - alpha - beta)
    returns = []
    for _ in range(n_obs):
        epsilon = rng.gauss(0.0, math.sqrt(sigma2))
        returns.append(epsilon)
        sigma2 = omega + alpha * epsilon ** 2 + beta * sigma2
    return returns


def test_fit_garch11_recovers_known_parameters():
    """§5.2: 5000-sample synthetic series; GARCH MLE recovers (ω, α, β) within
    known wide CIs.  Beta most stable, omega noisiest."""
    TRUE_OMEGA = 1e-5
    TRUE_ALPHA = 0.05
    TRUE_BETA = 0.92
    N_OBS = 5000

    returns = _generate_garch_series(TRUE_OMEGA, TRUE_ALPHA, TRUE_BETA, N_OBS, seed=42)
    result = fit_garch11(returns, periods_per_year=8760)

    assert isinstance(result, GARCHResult)
    assert result.n_obs == N_OBS
    assert result.periods_per_year == 8760
    # Wide tolerances per GARCH MLE known variance:
    assert abs(result.beta - TRUE_BETA) / TRUE_BETA < 0.10
    assert abs(result.alpha - TRUE_ALPHA) / TRUE_ALPHA < 0.30
    assert abs(result.omega - TRUE_OMEGA) / TRUE_OMEGA < 0.50
    assert 0.0 < result.persistence < 1.0  # stationarity invariant
    assert result.persistence == result.alpha + result.beta


def test_fit_garch11_current_conditional_vol_is_annualized():
    """STRUCTURAL DEFENSE: current_conditional_vol must be in ANNUALIZED units.

    For hourly bars with periods_per_year=8760, period-vol ≈ 1% would
    annualize to ≈ 94%.  We verify the result's current_conditional_vol
    sits in the annualized range (>0.05), not the period-vol range (<0.05).
    """
    returns = _generate_garch_series(1e-5, 0.05, 0.92, 5000, seed=7)
    result = fit_garch11(returns, periods_per_year=8760)

    # Period vol on this synthetic series is small (~0.003); annualized is ~0.28.
    # The exact value depends on the seed.  Assert structural range only.
    assert result.current_conditional_vol > 0.05, (
        f"current_conditional_vol={result.current_conditional_vol} suspiciously "
        "small — did you forget to annualize by sqrt(periods_per_year)?"
    )
    # Conversely, also defend against accidentally squaring (annualizing twice)
    assert result.current_conditional_vol < 10.0, (
        f"current_conditional_vol={result.current_conditional_vol} suspiciously "
        "large — did you double-annualize?"
    )


def test_fit_garch11_too_few_observations_raises():
    """ValueError if len(returns) < 100."""
    with pytest.raises(ValueError):
        fit_garch11([0.01] * 50, periods_per_year=8760)


def test_fit_garch11_nan_input_raises():
    """ValueError if any return is NaN or inf."""
    returns = _generate_garch_series(1e-5, 0.05, 0.92, 500, seed=1)
    returns[10] = float("nan")
    with pytest.raises(ValueError):
        fit_garch11(returns, periods_per_year=8760)

    returns[10] = float("inf")
    with pytest.raises(ValueError):
        fit_garch11(returns, periods_per_year=8760)


def test_garch_result_is_frozen():
    """GARCHResult is immutable — consumers cannot mutate its fields."""
    result = GARCHResult(
        omega=1.0, alpha=0.05, beta=0.92, persistence=0.97,
        n_obs=5000, periods_per_year=8760,
        long_run_variance=0.001, current_conditional_vol=0.3,
    )
    raised = False
    try:
        result.current_conditional_vol = 0.5  # type: ignore[misc]
    except Exception:
        raised = True
    assert raised is True


def test_garch_result_period_units_consistency():
    """omega and long_run_variance are in period units; current_conditional_vol
    is annualized.  Verify by computing long_run_variance from omega/persistence
    and confirming they match.
    """
    result = GARCHResult(
        omega=1e-5, alpha=0.05, beta=0.92, persistence=0.97,
        n_obs=5000, periods_per_year=8760,
        long_run_variance=1e-5 / (1.0 - 0.97),  # period-units
        current_conditional_vol=0.3,             # annualized
    )
    # long_run_variance should equal omega / (1 - persistence)
    assert math.isclose(
        result.long_run_variance,
        result.omega / (1.0 - result.persistence),
        abs_tol=1e-10,
    )


def _result_for_forecast(current_vol_annualized: float = 0.30) -> GARCHResult:
    """Build a GARCHResult with known fields for forecast-recursion tests."""
    return GARCHResult(
        omega=1e-5,
        alpha=0.05,
        beta=0.92,
        persistence=0.97,
        n_obs=5000,
        periods_per_year=8760,
        long_run_variance=1e-5 / (1.0 - 0.97),  # period-units
        current_conditional_vol=current_vol_annualized,
    )


def test_forecast_garch_at_horizon_1_equals_current():
    """h=1 → the existing one-step-ahead conditional vol."""
    result = _result_for_forecast(current_vol_annualized=0.30)
    forecast = forecast_garch_annualized_vol(result, horizon_periods=1)
    assert math.isclose(forecast, 0.30, abs_tol=1e-10)


def test_forecast_garch_converges_to_long_run_vol():
    """h → ∞ → forecast converges to sqrt(long_run_variance · periods_per_year)."""
    result = _result_for_forecast(current_vol_annualized=0.30)
    long_run_annualized = math.sqrt(result.long_run_variance * result.periods_per_year)
    forecast = forecast_garch_annualized_vol(result, horizon_periods=10000)
    assert math.isclose(forecast, long_run_annualized, abs_tol=1e-4)


def test_forecast_garch_recursion_intermediate():
    """h=10 produces the closed-form recursion result.

    Standard GARCH(1,1) multi-step forecast (Bollerslev textbook form):
        σ²(t+h|t) = σ²_∞ + ρ^(h-1) · (σ²(t+1|t) - σ²_∞)

    Exponent is h-1 (not h) so that at h=1 we get σ²(t+1) exactly.
    """
    result = _result_for_forecast(current_vol_annualized=0.30)
    # Current period-variance from annualized vol
    current_period_var = (0.30 ** 2) / result.periods_per_year
    h = 10
    rho = result.persistence
    expected_period_var = (
        result.long_run_variance
        + (rho ** (h - 1)) * (current_period_var - result.long_run_variance)
    )
    expected_annualized_vol = math.sqrt(expected_period_var * result.periods_per_year)

    forecast = forecast_garch_annualized_vol(result, horizon_periods=h)
    assert math.isclose(forecast, expected_annualized_vol, abs_tol=1e-9)


def test_forecast_garch_horizon_zero_raises():
    """h=0 is invalid — callers should use current_conditional_vol directly."""
    result = _result_for_forecast()
    with pytest.raises(ValueError):
        forecast_garch_annualized_vol(result, horizon_periods=0)


def test_forecast_garch_negative_horizon_raises():
    """Negative h is invalid."""
    result = _result_for_forecast()
    with pytest.raises(ValueError):
        forecast_garch_annualized_vol(result, horizon_periods=-5)
