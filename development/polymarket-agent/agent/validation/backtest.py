from collections.abc import Iterator
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
