from sqlalchemy.orm import Session, sessionmaker

from agent.data.polymarket_client import PolymarketClient
from agent.store.repository import save_price_history, upsert_market


class IngestService:
    """Fetches data from Polymarket and persists it to the local store."""

    def __init__(
        self,
        client: PolymarketClient,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._client = client
        self._session_factory = session_factory

    async def ingest_markets(self, *, limit: int = 100) -> int:
        """Fetch one page of markets and upsert them. Return the count."""
        markets = await self._client.get_markets(limit=limit)
        with self._session_factory() as session:
            for dto in markets:
                upsert_market(session, dto)
            session.commit()
        return len(markets)

    async def ingest_price_history(
        self, market_id: str, token_id: str, *, interval: str = "1h"
    ) -> int:
        """Fetch a token's price history and persist new points.

        Return the count of newly-inserted snapshots.
        """
        history = await self._client.get_price_history(
            token_id, interval=interval
        )
        with self._session_factory() as session:
            added = save_price_history(session, market_id, history)
            session.commit()
        return added
