"""Async client for Binance's public klines endpoint.

Same architectural pattern as PolymarketClient: caller owns the
httpx.AsyncClient lifecycle and injects a TokenBucket for rate limiting.
"""

import httpx

from agent.data.models import CryptoBarDTO
from agent.data.rate_limiter import TokenBucket


class BinanceClient:
    """Read-only async client for /api/v3/klines."""

    BASE_URL = "https://api.binance.com"
    KLINES_PATH = "/api/v3/klines"
    MAX_KLINES_PER_REQUEST = 1000

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        rate_limit_bucket: TokenBucket | None = None,
    ) -> None:
        self._http = http_client
        # Binance IP weight limit is 1200/min; klines is 2 weight when limit > 500.
        # 60 capacity / 1 refill-per-second = 60/min sustainable, well under 600.
        self._bucket = rate_limit_bucket or TokenBucket(
            capacity=60, refill_per_second=1.0
        )

    async def get_klines(
        self,
        symbol: str,
        interval: str,
        *,
        start_ts: int | None = None,
        end_ts: int | None = None,
        limit: int = 1000,
    ) -> list[CryptoBarDTO]:
        """Fetch up to `limit` klines.  Times converted to ms internally
        for the Binance API.  Returns bars in ascending-ts order.

        `interval` examples: "1h", "1d".  `start_ts`/`end_ts` are unix seconds.
        """
        await self._bucket.acquire()
        params: dict[str, object] = {
            "symbol": symbol,
            "interval": interval,
            "limit": min(limit, self.MAX_KLINES_PER_REQUEST),
        }
        if start_ts is not None:
            params["startTime"] = start_ts * 1000  # seconds -> ms
        if end_ts is not None:
            params["endTime"] = end_ts * 1000
        resp = await self._http.get(
            f"{self.BASE_URL}{self.KLINES_PATH}", params=params
        )
        resp.raise_for_status()
        return [
            CryptoBarDTO.from_binance_kline(kline, symbol=symbol, granularity=interval)
            for kline in resp.json()
        ]
