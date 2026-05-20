from collections.abc import Callable, Iterator
from dataclasses import dataclass

from sqlalchemy.orm import Session

from agent.store.schema import PriceSnapshot


@dataclass(frozen=True)
class ReplayEvent:
    """A single point of a replayed historical price series."""

    ts: int
    token_id: str
    price: float


class ReplayEngine:
    """Replays stored price history in strict timestamp order.

    This is the foundation of the backtest harness: Phase 1+ strategies are
    fed `ReplayEvent`s and must make decisions using only data up to each
    event's timestamp (no look-ahead).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def replay(self, market_id: str, token_id: str) -> Iterator[ReplayEvent]:
        """Yield every stored snapshot for one token, ascending by timestamp."""
        rows = (
            self._session.query(PriceSnapshot)
            .filter_by(market_id=market_id, token_id=token_id)
            .order_by(PriceSnapshot.ts.asc())
        )
        for row in rows:
            yield ReplayEvent(
                ts=row.ts, token_id=row.token_id, price=row.price
            )


from agent.store.schema import Market  # noqa: E402
from agent.validation.metrics import brier_score, kupiec_test, reliability_curve  # noqa: E402
from agent.validation.types import (  # noqa: E402
    BacktestResult,
    Prediction,
    ResolvedOutcome,
)


def walk_forward_backtest(
    session: Session,
    model: Callable[[str, ReplayEvent], Prediction],
    resolutions: dict[str, ResolvedOutcome],
    *,
    market_ids: list[str] | None = None,
    kupiec_window: int = 100,
    model_name: str = "unnamed",
) -> BacktestResult:
    """Walk-forward backtest over Phase 0's stored history.

    Iterates ReplayEngine events in strict ts order per market, calls `model`
    on each event to get a Prediction, then computes metrics over (p_hat,
    outcome) pairs for markets present in `resolutions`.

    The walk-forward property is enforced by ReplayEngine yielding ascending
    by ts and `model` being a function of one event (no peek-ahead).  Stateful
    models in future phases hold internal state across calls — the only
    contract is "do not query the future."
    """
    if market_ids is None:
        market_ids = [m.id for m in session.query(Market).all()]

    engine = ReplayEngine(session)
    predictions: list[Prediction] = []

    for market_id in market_ids:
        market = session.get(Market, market_id)
        if market is None or not market.clob_token_ids:
            continue
        yes_token_id = market.clob_token_ids[0]  # convention: index 0 = YES
        for event in engine.replay(market_id, yes_token_id):
            predictions.append(model(market_id, event))

    pred_outcome_pairs: list[tuple[float, int]] = [
        (pred.p_hat, resolutions[pred.market_id].outcome)
        for pred in predictions
        if pred.market_id in resolutions
    ]

    n_predictions = len(predictions)
    n_resolved = len(pred_outcome_pairs)

    if n_resolved == 0:
        brier = 0.0
        curve: list[tuple[float, float] | tuple[None, None]] = [
            (None, None)
        ] * 10
        kupiec = None
    else:
        brier = brier_score(pred_outcome_pairs)
        curve = reliability_curve(pred_outcome_pairs)
        if n_resolved >= kupiec_window:
            window_pairs = pred_outcome_pairs[-kupiec_window:]
            exceptions = sum(
                1
                for p_hat, outcome in window_pairs
                if (p_hat >= 0.5 and outcome == 0) or (p_hat < 0.5 and outcome == 1)
            )
            expected_rate = sum(
                min(p_hat, 1 - p_hat) for p_hat, _ in window_pairs
            ) / len(window_pairs)
            expected_rate = max(1e-9, min(1 - 1e-9, expected_rate))
            kupiec = kupiec_test(exceptions, len(window_pairs), expected_rate)
        else:
            kupiec = None

    timestamps = [p.ts for p in predictions]
    window_start = min(timestamps) if timestamps else 0
    window_end = max(timestamps) if timestamps else 0

    return BacktestResult(
        model_name=model_name,
        n_predictions=n_predictions,
        n_resolved=n_resolved,
        brier_score=brier,
        reliability_curve=curve,
        kupiec=kupiec,
        window_start_ts=window_start,
        window_end_ts=window_end,
    )
