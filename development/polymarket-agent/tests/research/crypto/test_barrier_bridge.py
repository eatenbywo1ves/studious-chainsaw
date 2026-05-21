import math

import pytest

from agent.research.crypto.barrier_bridge import prob_barrier_hit


# === Reference cases (§5.1 of the spec) =====================================

def test_prob_barrier_hit_already_touching():
    """§5.1 Case 1: spot == barrier → returns 1.0 (already touching)."""
    p = prob_barrier_hit(
        spot=100.0, barrier=100.0,
        time_remaining_years=1.0, annualized_vol=0.3,
    )
    assert p == 1.0


def test_prob_barrier_hit_zero_time_up_barrier():
    """§5.1 Case 2: T=0 with barrier above spot → returns 0.0."""
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=0.0, annualized_vol=0.3,
    )
    assert p == 0.0


def test_prob_barrier_hit_zero_time_down_barrier():
    """§5.1 Case 3: T=0 with barrier below spot → returns 0.0."""
    p = prob_barrier_hit(
        spot=100.0, barrier=90.0,
        time_remaining_years=0.0, annualized_vol=0.3,
    )
    assert p == 0.0


def test_prob_barrier_hit_long_horizon_negative_log_drift():
    """§5.1 Case 4: T=1000, μ=0, σ=0.3 → ν = μ − σ²/2 = −0.045 < 0 → P → S₀/B.

    With annualized_drift=0 (physical μ=0), the LOG-drift is ν = μ − σ²/2 = −σ²/2,
    which is NEGATIVE.  The log-process drifts AWAY from an up-barrier.
    By Doob's optional-stopping on the exponential martingale exp(-2νX_t/σ²),
    the asymptotic up-barrier hit probability is:

        P(τ < ∞) = S₀ / B   (when ν < 0 and b > 0)

    For S₀=100, B=110: P → 100/110 ≈ 0.9091.

    THIS TEST CATCHES THE MISSING exp(2νb/σ²) PREFACTOR BUG.  Without that
    prefactor, the formula at T=1000 collapses to ≈ 0 (a single N(·) term
    deep in the left tail with argument ≈ -4.755).  WITH the prefactor, the
    formula gives ≈ 0.9091.  So "result ≈ 0 vs ≈ 0.909" is the discriminator.

    (Note: pure recurrence — P → 1 in the limit — requires ν = 0, which means
    drift = σ²/2.  That scenario is covered by Test 5.)
    """
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=1000.0, annualized_vol=0.3,
        annualized_drift=0.0,
    )
    # Martingale identity: P → S₀/B in the negative-log-drift limit.
    expected = 100.0 / 110.0
    assert math.isclose(p, expected, abs_tol=1e-3), (
        f"Negative-log-drift limit test failed: P={p} should be ≈{expected:.4f} "
        f"(= S₀/B).  Did you forget the exp(2νb/σ²) prefactor?  "
        f"Without it, this would give ≈ 0."
    )


def test_prob_barrier_hit_log_drift_zero_up_barrier():
    """§5.1 Case 5: drift = σ²/2 → log-drift ν = 0 → formula reduces to 2·N(-b/v).

    Hand-computation:
      ν = 0.045 - 0.3²/2 = 0
      b = ln(110/100) = ln(1.1) ≈ 0.0953102
      v = 0.3 · √1 = 0.3
      Term1 = N((0 - b)/v) = N(-0.3177)
      Term2 = exp(0) · N((-0 - b)/v) = N(-0.3177)
      P = 2 · N(-0.3177) ≈ 0.75066
    """
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=1.0, annualized_vol=0.3,
        annualized_drift=0.045,  # exactly σ²/2 = 0.09/2
    )
    expected = 2 * 0.5 * (1 + math.erf(-math.log(1.1) / 0.3 / math.sqrt(2)))
    assert math.isclose(p, expected, abs_tol=1e-9)
    # Sanity: also close to the pre-computed approximate value
    assert math.isclose(p, 0.7506, abs_tol=1e-3)


# === Monotonicity sanity tests ===============================================

def test_prob_barrier_hit_increases_with_time():
    """Longer horizon → higher P(touch), holding other things equal."""
    args = dict(spot=100.0, barrier=110.0, annualized_vol=0.3, annualized_drift=0.0)
    p_short = prob_barrier_hit(time_remaining_years=0.25, **args)
    p_med   = prob_barrier_hit(time_remaining_years=1.0, **args)
    p_long  = prob_barrier_hit(time_remaining_years=5.0, **args)
    assert p_short < p_med < p_long


def test_prob_barrier_hit_increases_with_vol():
    """Higher vol → higher P(touch), holding other things equal."""
    args = dict(
        spot=100.0, barrier=110.0,
        time_remaining_years=1.0, annualized_drift=0.0,
    )
    p_low  = prob_barrier_hit(annualized_vol=0.1, **args)
    p_med  = prob_barrier_hit(annualized_vol=0.3, **args)
    p_high = prob_barrier_hit(annualized_vol=0.6, **args)
    assert p_low < p_med < p_high


def test_prob_barrier_hit_decreases_with_distance_to_barrier():
    """Further barrier → lower P(touch), holding other things equal."""
    args = dict(
        spot=100.0,
        time_remaining_years=1.0, annualized_vol=0.3, annualized_drift=0.0,
    )
    p_close = prob_barrier_hit(barrier=105.0, **args)
    p_med   = prob_barrier_hit(barrier=120.0, **args)
    p_far   = prob_barrier_hit(barrier=150.0, **args)
    assert p_close > p_med > p_far


# === Edge cases ==============================================================

def test_prob_barrier_hit_zero_vol_no_drift():
    """σ=0, drift=0, spot ≠ barrier → no movement, P=0."""
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=1.0, annualized_vol=0.0,
    )
    assert p == 0.0


def test_prob_barrier_hit_returns_in_unit_interval():
    """For any plausible input, output must be in [0, 1]."""
    for spot, barrier, T, vol, drift in [
        (100, 105, 0.01, 0.5, 0.0),
        (100, 200, 0.1, 1.0, 0.5),
        (100, 50, 0.5, 0.8, -0.3),
        (100, 101, 0.001, 0.01, 0.0),
    ]:
        p = prob_barrier_hit(
            spot=spot, barrier=barrier,
            time_remaining_years=T, annualized_vol=vol,
            annualized_drift=drift,
        )
        assert 0.0 <= p <= 1.0, (
            f"P={p} out of [0,1] for spot={spot}, barrier={barrier}, "
            f"T={T}, vol={vol}, drift={drift}"
        )
