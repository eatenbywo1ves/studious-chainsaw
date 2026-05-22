from agent.validation.pnl import Trade, EquityCurve, simulate_pnl
from agent.validation.types import Prediction, ResolvedOutcome


def _pred(market_id, ts, p_hat, position_size, direction):
    from agent.research.crypto.model import CryptoPrediction
    return CryptoPrediction(
        market_id=market_id, ts=ts, p_hat=p_hat,
        position_size=position_size,
        diagnostics={"kelly_direction": direction, "p_market": p_hat},
    )


def test_single_winning_yes_trade_zero_cost():
    preds = [_pred("m1", 100, 0.10, 0.10, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=200)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    assert abs(curve.bankroll[-1] - 190.0) < 1e-6


def test_single_losing_trade():
    preds = [_pred("m1", 100, 0.10, 0.10, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=0, resolved_ts=200)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    assert abs(curve.bankroll[-1] - 90.0) < 1e-6


def test_cost_reduces_winning_pnl():
    preds = [_pred("m1", 100, 0.10, 0.10, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=200)}
    curve0 = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    curve2 = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.02)
    assert curve2.bankroll[-1] < curve0.bankroll[-1]


def test_one_position_per_market():
    preds = [
        _pred("m1", 100, 0.10, 0.10, "yes"),
        _pred("m1", 200, 0.12, 0.10, "yes"),
        _pred("m1", 300, 0.15, 0.10, "yes"),
    ]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=400)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0,
                         one_position_per_market=True)
    assert len(curve.trades) == 1


def test_compounding_two_sequential_wins():
    preds = [
        _pred("m1", 100, 0.50, 0.10, "yes"),
        _pred("m2", 200, 0.50, 0.10, "yes"),
    ]
    resolutions = {
        "m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=150),
        "m2": ResolvedOutcome(market_id="m2", outcome=1, resolved_ts=250),
    }
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    assert abs(curve.bankroll[-1] - 121.0) < 1e-6


def test_zero_position_size_no_trade():
    preds = [_pred("m1", 100, 0.10, 0.0, "yes")]
    resolutions = {"m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=200)}
    curve = simulate_pnl(preds, resolutions, starting_bankroll=100.0, round_trip_cost=0.0)
    assert len(curve.trades) == 0
    assert curve.bankroll[-1] == 100.0
