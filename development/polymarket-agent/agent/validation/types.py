"""Phase 1A dataclasses for the L7 validation gate.

All types are frozen for hashability and immutability, matching Phase 0's
ReplayEvent convention.
"""

from dataclasses import dataclass, field
from typing import Literal


@dataclass(frozen=True)
class Prediction:
    """A model's estimate of P(market resolves YES) at a given time.

    Minimal subset of the spec's future FairValueEstimate.  L3 modules in
    Phase 1B+ may subclass to add confidence/CI/rationale/sources without
    breaking L7.
    """

    market_id: str
    ts: int  # unix seconds
    p_hat: float  # estimated P(YES) in [0, 1]


@dataclass(frozen=True)
class ResolvedOutcome:
    """The ground truth for a resolved market.  Phase 1A handles binary
    outcomes only."""

    market_id: str
    outcome: Literal[0, 1]  # 1 = YES, 0 = NO
    resolved_ts: int


@dataclass(frozen=True)
class PriceTick:
    """A live price observation for a market's YES token.  Emitted by
    ResolutionPoller between resolution checks."""

    market_id: str
    ts: int
    market_price: float  # YES token price in [0, 1]


@dataclass(frozen=True)
class TradeSignal:
    """A trading-rule decision to take a hypothetical paper position."""

    market_id: str
    ts: int
    side: Literal["YES", "NO"]
    target_price: float
    edge: float
    rationale: str


@dataclass(frozen=True)
class PaperFill:
    """A hypothetical fill recorded by PaperTradeEngine."""

    market_id: str
    ts: int
    side: Literal["YES", "NO"]
    price: float  # signal.target_price + slippage (0 in Phase 1A)
    size: float  # position size in SHARES (max payoff = size * $1)


@dataclass(frozen=True)
class KupiecResult:
    """Output of the Kupiec unconditional-coverage test."""

    exceptions: int
    trials: int
    expected_rate: float
    lr_statistic: float
    p_value: float
    zone: Literal["GREEN", "ORANGE", "RED"]


@dataclass(frozen=True)
class BacktestResult:
    """Output of walk_forward_backtest()."""

    model_name: str
    n_predictions: int
    n_resolved: int
    brier_score: float
    reliability_curve: list[tuple[float, float] | tuple[None, None]] = field(
        default_factory=list
    )
    kupiec: KupiecResult | None = None
    window_start_ts: int = 0
    window_end_ts: int = 0


@dataclass(frozen=True)
class PaperTradeResult:
    """Summary of a paper-trade-live session."""

    model_name: str
    started_ts: int
    ended_ts: int
    n_fills: int
    n_resolved: int
    paper_pnl: float
    backtest_metrics: BacktestResult
