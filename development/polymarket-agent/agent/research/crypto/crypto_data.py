"""CryptoDataAccess: repository wrapper providing the specific queries
crypto_model needs without leaking ORM details.
"""

from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.data.models import NewsEventDTO
from agent.store.schema import CryptoBar


class CryptoDataAccess:
    """Provides typed query methods over CryptoBar ORM rows and news stubs.

    Attributes:
        session_factory: Callable that returns a context-managed SQLAlchemy Session.

    Example:
        >>> cda = CryptoDataAccess(session_factory=session_factory)
        >>> spot = cda.get_current_spot("BTCUSDT", before_ts=1747900000)
    """

    def __init__(
        self,
        session_factory: Callable[[], Session],
    ):
        """Initialize CryptoDataAccess.

        Args:
            session_factory: Callable returning a context-managed SQLAlchemy Session.
        """
        self.session_factory = session_factory

    def get_current_spot(self, symbol: str, before_ts: int) -> float:
        """Return the most recent close price at or before before_ts.

        Args:
            symbol: Binance-convention trading symbol (e.g. "BTCUSDT").
            before_ts: Upper-bound timestamp (Unix seconds, inclusive).

        Returns:
            The close price of the most recent bar at or before before_ts.

        Raises:
            ValueError: If no bar exists for symbol at or before before_ts.
        """
        with self.session_factory() as session:
            row = session.execute(
                select(CryptoBar)
                .where(CryptoBar.symbol == symbol, CryptoBar.ts <= before_ts)
                .order_by(CryptoBar.ts.desc())
                .limit(1)
            ).scalar_one_or_none()
            if row is None:
                raise ValueError(
                    f"No crypto bar for {symbol} at or before {before_ts}"
                )
            return float(row.close)

    def get_recent_returns(
        self,
        symbol: str,
        granularity: str,
        n_bars: int,
        before_ts: int,
    ) -> list[float]:
        """Return close-to-close returns from the most recent n_bars bars.

        Fetches n_bars+1 bars (ascending) and computes n_bars returns as
        (cur_close - prev_close) / prev_close.

        Args:
            symbol: Binance-convention trading symbol (e.g. "BTCUSDT").
            granularity: Bar granularity string (e.g. "1h", "1d").
            n_bars: Number of returns to compute (requires n_bars+1 bars).
            before_ts: Upper-bound timestamp (Unix seconds, inclusive).

        Returns:
            List of n_bars close-to-close return floats in ascending time order.
            May be shorter than n_bars if insufficient bars exist.
        """
        with self.session_factory() as session:
            bars = session.execute(
                select(CryptoBar)
                .where(
                    CryptoBar.symbol == symbol,
                    CryptoBar.granularity == granularity,
                    CryptoBar.ts <= before_ts,
                )
                .order_by(CryptoBar.ts.desc())
                .limit(n_bars + 1)
            ).scalars().all()
            bars = list(reversed(bars))  # ascending order for return calc

        returns = []
        for i in range(1, len(bars)):
            prev_close = bars[i - 1].close
            cur_close = bars[i].close
            if prev_close > 0:
                returns.append((cur_close - prev_close) / prev_close)
        return returns

    def get_recent_news_for_currency(
        self,
        currency: str,
        since_ts: int,
        until_ts: int,
    ) -> list[NewsEventDTO]:
        """C2-A stub: returns empty list.  C2-B implements full query against
        news_events + news_currency_tags.

        Args:
            currency: Currency code (e.g. "BTC", "ETH").
            since_ts: Start of time window (Unix seconds, inclusive).
            until_ts: End of time window (Unix seconds, inclusive).

        Returns:
            Empty list (stub). C2-B will populate from the news_events table.
        """
        return []
