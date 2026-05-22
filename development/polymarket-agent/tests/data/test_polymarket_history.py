import httpx
import respx

from agent.config import Settings
from agent.data.models import MarketDTO
from agent.data.polymarket_client import PolymarketClient
from agent.data.polymarket_history import ingest_market_price_history
from agent.data.rate_limiter import TokenBucket
from agent.store.repository import save_price_history
from agent.store.schema import Market, PriceSnapshot

_HISTORY_URL = "https://clob.polymarket.com/prices-history"

_THREE_POINTS = {
    "history": [
        {"t": 1000, "p": 0.40},
        {"t": 2000, "p": 0.55},
        {"t": 3000, "p": 0.70},
    ]
}


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=1000, refill_per_second=1000),
    )


@respx.mock
async def test_ingest_persists_yes_token_history(session):
    """Fetches YES-token (index 0) price history and inserts rows."""
    session.add(Market(id="m1", question="Q"))
    session.commit()

    respx.get(_HISTORY_URL).mock(
        return_value=httpx.Response(200, json=_THREE_POINTS)
    )

    market = MarketDTO(id="m1", clob_token_ids=["yesTok", "noTok"])

    async with httpx.AsyncClient() as http:
        count = await ingest_market_price_history(
            _client(http), save_price_history, session, market
        )

    assert count == 3
    assert session.query(PriceSnapshot).count() == 3
    # All snapshots must carry the YES token id (index 0), not the NO token.
    token_ids = {snap.token_id for snap in session.query(PriceSnapshot)}
    assert token_ids == {"yesTok"}


@respx.mock
async def test_ingest_is_idempotent(session):
    """A second call with the same data inserts 0 new rows."""
    session.add(Market(id="m1", question="Q"))
    session.commit()

    route = respx.get(_HISTORY_URL).mock(
        return_value=httpx.Response(200, json=_THREE_POINTS)
    )

    market = MarketDTO(id="m1", clob_token_ids=["yesTok", "noTok"])

    async with httpx.AsyncClient() as http:
        client = _client(http)
        first = await ingest_market_price_history(
            client, save_price_history, session, market
        )
        second = await ingest_market_price_history(
            client, save_price_history, session, market
        )

    assert first == 3
    assert second == 0
    # Total rows stay at 3 — no duplicates.
    assert session.query(PriceSnapshot).count() == 3
    # The function still made both HTTP calls; deduplication is at the repo layer.
    assert route.call_count == 2


@respx.mock
async def test_no_token_ids_returns_zero(session):
    """A MarketDTO with no CLOB token ids returns 0 and makes no HTTP call."""
    session.add(Market(id="m1", question="Q"))
    session.commit()

    route = respx.get(_HISTORY_URL).mock(
        return_value=httpx.Response(200, json=_THREE_POINTS)
    )

    market = MarketDTO(id="m1", clob_token_ids=[])

    async with httpx.AsyncClient() as http:
        count = await ingest_market_price_history(
            _client(http), save_price_history, session, market
        )

    assert count == 0
    assert route.call_count == 0
    assert session.query(PriceSnapshot).count() == 0
