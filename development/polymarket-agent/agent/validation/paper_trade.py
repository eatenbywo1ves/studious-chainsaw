"""Paper-trade-live engine for Phase 1A.

Stateful component that records hypothetical fills and computes realized P&L
on resolution.  Position size defaults to 1 share per trade (max payoff = $1
per position).  Slippage defaults to zero; a real spread/impact model is
Phase 1B.
"""

from collections.abc import Callable

from agent.validation.metrics import brier_score, reliability_curve
from agent.validation.types import (
    BacktestResult,
    PaperFill,
    PaperTradeResult,
    Prediction,
    ResolvedOutcome,
    TradeSignal,
)


class PaperTradeEngine:
    """Records paper trades and resolves them when markets close."""

    def __init__(
        self,
        model_name: str,
        position_size_shares: float = 1.0,
        slippage_model: Callable[..., float] = lambda **_: 0.0,
    ) -> None:
        self._model_name = model_name
        self._position_size = position_size_shares
        self._slippage = slippage_model
        self._fills: list[PaperFill] = []
        self._predictions: list[Prediction] = []
        self._open_positions: dict[str, PaperFill] = {}
        self._closed_outcomes: dict[str, ResolvedOutcome] = {}
        self._pnl: float = 0.0
        self._started_ts: int | None = None
        self._ended_ts: int | None = None

    def record_prediction(self, prediction: Prediction) -> None:
        """Record a model's prediction for later inclusion in backtest_metrics."""
        self._predictions.append(prediction)
        self._touch_ts(prediction.ts)

    def record_signal(self, signal: TradeSignal) -> PaperFill:
        """Take a paper position at signal.target_price + slippage.

        Phase 1A simplification: only one open position per market at a time;
        a subsequent signal for the same market replaces the open position.
        """
        slip = self._slippage(
            market_id=signal.market_id,
            side=signal.side,
            target_price=signal.target_price,
        )
        fill = PaperFill(
            market_id=signal.market_id,
            ts=signal.ts,
            side=signal.side,
            price=signal.target_price + slip,
            size=self._position_size,
        )
        self._fills.append(fill)
        self._open_positions[signal.market_id] = fill
        self._touch_ts(signal.ts)
        return fill

    def on_resolved(self, outcome: ResolvedOutcome) -> float:
        """Close any open position for outcome.market_id; return realized P&L.

        Returns 0.0 if no open position.  YES bought at price p pays $1*size if
        outcome=1 else $0; NO bought at price p pays $1*size if outcome=0 else $0.
        """
        self._closed_outcomes[outcome.market_id] = outcome
        fill = self._open_positions.pop(outcome.market_id, None)
        if fill is None:
            return 0.0
        if fill.side == "YES":
            payoff = 1.0 if outcome.outcome == 1 else 0.0
        else:  # NO
            payoff = 1.0 if outcome.outcome == 0 else 0.0
        pnl = (payoff - fill.price) * fill.size
        self._pnl += pnl
        self._touch_ts(outcome.resolved_ts)
        return pnl

    def result(self) -> PaperTradeResult:
        """Snapshot the engine state into a PaperTradeResult."""
        pairs: list[tuple[float, int]] = [
            (p.p_hat, self._closed_outcomes[p.market_id].outcome)
            for p in self._predictions
            if p.market_id in self._closed_outcomes
        ]
        n_resolved = len(pairs)

        if pairs:
            brier = brier_score(pairs)
            curve = reliability_curve(pairs)
        else:
            brier = 0.0
            curve = [(None, None)] * 10

        backtest = BacktestResult(
            model_name=self._model_name,
            n_predictions=len(self._predictions),
            n_resolved=n_resolved,
            brier_score=brier,
            reliability_curve=curve,
            kupiec=None,  # Phase 1A: paper-trade sessions are short; defer to Phase 1B
            window_start_ts=self._started_ts or 0,
            window_end_ts=self._ended_ts or 0,
        )
        return PaperTradeResult(
            model_name=self._model_name,
            started_ts=self._started_ts or 0,
            ended_ts=self._ended_ts or 0,
            n_fills=len(self._fills),
            n_resolved=n_resolved,
            paper_pnl=self._pnl,
            backtest_metrics=backtest,
        )

    def _touch_ts(self, ts: int) -> None:
        if self._started_ts is None or ts < self._started_ts:
            self._started_ts = ts
        if self._ended_ts is None or ts > self._ended_ts:
            self._ended_ts = ts
