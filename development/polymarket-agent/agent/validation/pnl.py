"""P&L simulator: convert a CryptoPrediction stream into a compounding equity
curve under a given round-trip cost.

Binary-market mechanics: buying YES at price q for stake S buys S/q shares,
each paying $1 if outcome==1 (else $0).  Buying NO at price (1-q) is symmetric.
Round-trip cost is a fraction of the stake subtracted at entry.
"""

from dataclasses import dataclass
from typing import Literal

from agent.validation.types import ResolvedOutcome


@dataclass(frozen=True)
class Trade:
    market_id: str
    entry_ts: int
    direction: Literal["yes", "no"]
    entry_price: float        # per-share cost in [0,1] (YES price, or 1-YES for NO)
    fraction: float           # Kelly fraction of bankroll staked
    outcome: int              # 0/1
    round_trip_cost: float


@dataclass(frozen=True)
class EquityCurve:
    timestamps: list[int]
    bankroll: list[float]
    trades: list[Trade]


def simulate_pnl(
    predictions,
    resolutions: dict[str, ResolvedOutcome],
    *,
    starting_bankroll: float = 100.0,
    round_trip_cost: float = 0.0,
    one_position_per_market: bool = True,
) -> EquityCurve:
    ordered = sorted(predictions, key=lambda p: p.ts)
    bankroll = starting_bankroll
    timestamps = [0]
    curve = [starting_bankroll]
    trades: list[Trade] = []
    seen_markets: set[str] = set()

    for pred in ordered:
        if pred.position_size <= 0.0:
            continue
        if pred.market_id not in resolutions:
            continue
        if one_position_per_market and pred.market_id in seen_markets:
            continue
        seen_markets.add(pred.market_id)

        direction = pred.diagnostics.get("kelly_direction", "yes")
        yes_price = pred.diagnostics.get("p_market", pred.p_hat)
        entry_price = yes_price if direction == "yes" else (1.0 - yes_price)
        if entry_price <= 0.0 or entry_price >= 1.0:
            continue

        stake = pred.position_size * bankroll
        cost = round_trip_cost * stake
        net_stake = stake - cost
        shares = net_stake / entry_price
        outcome = resolutions[pred.market_id].outcome

        won = (direction == "yes" and outcome == 1) or (direction == "no" and outcome == 0)
        payoff = shares * 1.0 if won else 0.0
        bankroll = bankroll - stake + payoff

        trades.append(Trade(
            market_id=pred.market_id, entry_ts=pred.ts, direction=direction,
            entry_price=entry_price, fraction=pred.position_size, outcome=outcome,
            round_trip_cost=round_trip_cost,
        ))
        timestamps.append(pred.ts)
        curve.append(bankroll)

    return EquityCurve(timestamps=timestamps, bankroll=curve, trades=trades)
