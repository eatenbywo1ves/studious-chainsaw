"""Backfill historical klines and incrementally append latest bars."""

from sqlalchemy.orm import Session, sessionmaker

from agent.data.crypto_client import BinanceClient
from agent.store.repository import save_crypto_bars


# Approximate seconds per bar by granularity.  Used for pagination cursor advance.
_SECONDS_PER_BAR = {
    "1h": 3600,
    "1d": 86400,
}


class CryptoIngestService:
    """Fetches klines from Binance and persists them to the local store."""

    def __init__(
        self,
        client: BinanceClient,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._client = client
        self._session_factory = session_factory

    async def ingest_history(
        self,
        symbol: str,
        granularity: str,
        start_ts: int,
        end_ts: int,
    ) -> int:
        """Paginate through Binance klines from start_ts to end_ts.

        Returns the count of newly-inserted bars (already-present bars
        skipped silently via save_crypto_bars).
        """
        seconds_per_bar = _SECONDS_PER_BAR[granularity]
        current_start = start_ts
        total_added = 0

        while current_start < end_ts:
            bars = await self._client.get_klines(
                symbol=symbol,
                interval=granularity,
                start_ts=current_start,
                end_ts=end_ts,
                limit=self._client.MAX_KLINES_PER_REQUEST,
            )
            if not bars:
                break

            with self._session_factory() as session:
                total_added += save_crypto_bars(session, bars)
                session.commit()

            # Advance start to one bar after the last received bar
            last_bar_ts = bars[-1].ts
            current_start = last_bar_ts + seconds_per_bar

            # If the page wasn't full, we've exhausted the range
            if len(bars) < self._client.MAX_KLINES_PER_REQUEST:
                break

        return total_added

    async def ingest_latest(
        self,
        symbol: str,
        granularity: str,
        limit: int = 100,
    ) -> int:
        """Fetch the most-recent `limit` bars (no time bounds) and upsert.

        Returns the count of newly-inserted bars.
        """
        bars = await self._client.get_klines(
            symbol=symbol, interval=granularity, limit=limit
        )
        with self._session_factory() as session:
            added = save_crypto_bars(session, bars)
            session.commit()
        return added
