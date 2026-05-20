import httpx
import respx

from agent.config import Settings
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.validation.resolution_poller import ResolutionPoller
from agent.validation.types import PriceTick, ResolvedOutcome


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


@respx.mock
async def test_resolution_poller_yields_ticks_then_resolution():
    """§5.6 reference case:
       Poll 1: closed=False, outcomePrices=["0.55","0.45"] -> PriceTick(0.55)
       Poll 2: same -> PriceTick(0.55)
       Poll 3: closed=True, outcomePrices=["1","0"] -> ResolvedOutcome(1), then stops.
    """
    poll_responses = [
        httpx.Response(200, json={
            "id": "m1",
            "closed": False,
            "active": True,
            "outcomePrices": '["0.55","0.45"]',
        }),
        httpx.Response(200, json={
            "id": "m1",
            "closed": False,
            "active": True,
            "outcomePrices": '["0.55","0.45"]',
        }),
        httpx.Response(200, json={
            "id": "m1",
            "closed": True,
            "active": False,
            "outcomePrices": '["1","0"]',
        }),
    ]
    respx.get("https://gamma-api.polymarket.com/markets/m1").mock(
        side_effect=poll_responses
    )

    async with httpx.AsyncClient() as http:
        poller = ResolutionPoller(
            client=_client(http), poll_interval_seconds=0.001
        )
        events = []
        async for event in poller.stream_events(["m1"]):
            events.append(event)
            if len(events) >= 3:
                break

    assert len(events) == 3
    assert isinstance(events[0], PriceTick)
    assert events[0].market_id == "m1"
    assert events[0].market_price == 0.55
    assert isinstance(events[1], PriceTick)
    assert events[1].market_price == 0.55
    assert isinstance(events[2], ResolvedOutcome)
    assert events[2].outcome == 1


@respx.mock
async def test_resolution_poller_handles_404():
    """A 404 on a market id removes it from the pending set silently."""
    respx.get("https://gamma-api.polymarket.com/markets/missing").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )
    async with httpx.AsyncClient() as http:
        poller = ResolutionPoller(
            client=_client(http), poll_interval_seconds=0.001
        )
        events = []
        async for event in poller.stream_events(["missing"]):
            events.append(event)

    # Generator drained without yielding anything
    assert events == []
