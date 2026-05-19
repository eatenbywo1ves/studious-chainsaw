import httpx
import respx

from agent.config import Settings
from agent.data.ingest import IngestService
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.store.schema import Market, PriceSnapshot


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


@respx.mock
async def test_ingest_markets_persists_rows(session_factory, session):
    respx.get("https://gamma-api.polymarket.com/markets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "question": "Q1", "clobTokenIds": '["a","b"]'},
                {"id": 2, "question": "Q2", "clobTokenIds": '["c","d"]'},
            ],
        )
    )
    async with httpx.AsyncClient() as http:
        service = IngestService(_client(http), session_factory)
        count = await service.ingest_markets(limit=2)

    assert count == 2
    assert session.query(Market).count() == 2


@respx.mock
async def test_ingest_price_history_persists_snapshots(session_factory, session):
    session.add(Market(id="m1", question="Q"))
    session.commit()
    respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(
            200, json={"history": [{"t": 1000, "p": 0.4}, {"t": 2000, "p": 0.6}]}
        )
    )
    async with httpx.AsyncClient() as http:
        service = IngestService(_client(http), session_factory)
        added = await service.ingest_price_history("m1", "tok-1")

    assert added == 2
    assert session.query(PriceSnapshot).count() == 2
