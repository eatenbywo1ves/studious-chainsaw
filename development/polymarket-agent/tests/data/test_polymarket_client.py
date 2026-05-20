import httpx
import respx

from agent.config import Settings
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


@respx.mock
async def test_get_markets_parses_response():
    respx.get("https://gamma-api.polymarket.com/markets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "question": "Q1", "clobTokenIds": '["a","b"]',
                 "enableOrderBook": True},
                {"id": 2, "question": "Q2", "clobTokenIds": '["c","d"]'},
            ],
        )
    )
    async with httpx.AsyncClient() as http:
        markets = await _client(http).get_markets(limit=2)

    assert [m.id for m in markets] == ["1", "2"]
    assert markets[0].clob_token_ids == ["a", "b"]


@respx.mock
async def test_get_price_history_parses_response():
    route = respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(
            200, json={"history": [{"t": 1000, "p": 0.4}, {"t": 2000, "p": 0.55}]}
        )
    )
    async with httpx.AsyncClient() as http:
        history = await _client(http).get_price_history("tok-1", interval="1h")

    assert history.token_id == "tok-1"
    assert [(p.t, p.p) for p in history.history] == [(1000, 0.4), (2000, 0.55)]
    assert route.calls.last.request.url.params["market"] == "tok-1"


@respx.mock
async def test_get_price_history_raises_on_http_error():
    respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(500)
    )
    async with httpx.AsyncClient() as http:
        try:
            await _client(http).get_price_history("tok-1")
            raised = False
        except httpx.HTTPStatusError:
            raised = True

    assert raised is True
