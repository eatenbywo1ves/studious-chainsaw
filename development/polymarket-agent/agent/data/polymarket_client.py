import httpx

from agent.config import Settings
from agent.data.models import MarketDTO, PriceHistory, PricePoint
from agent.data.rate_limiter import TokenBucket


class PolymarketClient:
    """Read-only async client for the Polymarket Gamma and CLOB APIs."""

    def __init__(
        self,
        settings: Settings,
        http_client: httpx.AsyncClient,
        market_data_bucket: TokenBucket | None = None,
    ) -> None:
        self._settings = settings
        self._http = http_client
        # CLOB market-data limit is generous; 400 capacity / 40 rps is well under it.
        self._bucket = market_data_bucket or TokenBucket(
            capacity=400, refill_per_second=40
        )

    async def get_markets(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        active: bool = True,
        closed: bool = False,
    ) -> list[MarketDTO]:
        """Fetch a page of markets from the Gamma API."""
        await self._bucket.acquire()
        resp = await self._http.get(
            f"{self._settings.gamma_base_url}/markets",
            params={
                "limit": limit,
                "offset": offset,
                "active": str(active).lower(),
                "closed": str(closed).lower(),
            },
        )
        resp.raise_for_status()
        return [MarketDTO.from_gamma(item) for item in resp.json()]

    async def get_price_history(
        self,
        token_id: str,
        *,
        start_ts: int | None = None,
        end_ts: int | None = None,
        interval: str = "1h",
        fidelity: int = 60,
    ) -> PriceHistory:
        """Fetch historical prices for one CLOB token (asset id).

        The CLOB `/prices-history` endpoint names this parameter `market`,
        but it is the token/asset id, not the condition id.
        """
        await self._bucket.acquire()
        params: dict[str, object] = {
            "market": token_id,
            "interval": interval,
            "fidelity": fidelity,
        }
        if start_ts is not None:
            params["startTs"] = start_ts
        if end_ts is not None:
            params["endTs"] = end_ts
        resp = await self._http.get(
            f"{self._settings.clob_base_url}/prices-history", params=params
        )
        resp.raise_for_status()
        payload = resp.json()
        points = [
            PricePoint(t=int(pt["t"]), p=float(pt["p"]))
            for pt in payload.get("history", [])
        ]
        return PriceHistory(token_id=token_id, history=points)

    async def get_market(self, market_id: str) -> MarketDTO | None:
        """Fetch a single market by id from Gamma.  Returns None on 404."""
        await self._bucket.acquire()
        resp = await self._http.get(
            f"{self._settings.gamma_base_url}/markets/{market_id}"
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return MarketDTO.from_gamma(resp.json())
