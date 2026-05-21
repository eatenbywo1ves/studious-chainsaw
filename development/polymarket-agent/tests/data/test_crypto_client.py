import httpx
import respx

from agent.data.crypto_client import BinanceClient
from agent.data.rate_limiter import TokenBucket


def _client(http: httpx.AsyncClient) -> BinanceClient:
    return BinanceClient(
        http_client=http,
        rate_limit_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


def _kline(open_time_ms: int, close_price: float) -> list:
    return [
        open_time_ms,
        f"{close_price}",       # open
        f"{close_price * 1.01}",  # high
        f"{close_price * 0.99}",  # low
        f"{close_price}",       # close
        "100.0",                # volume
        open_time_ms + 3599999, # close time
        "6000000",              # quote volume
        1500,                   # trades
        "50.0",                 # taker buy base
        "3000000",              # taker buy quote
        "0",                    # ignore
    ]


@respx.mock
async def test_get_klines_parses_three_bars():
    """Happy path: 3-bar response parses into 3 CryptoBarDTO instances."""
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=[
            _kline(1700000000000, 60000.0),
            _kline(1700003600000, 60200.0),
            _kline(1700007200000, 60100.0),
        ])
    )
    async with httpx.AsyncClient() as http:
        bars = await _client(http).get_klines(symbol="BTCUSDT", interval="1h", limit=3)

    assert [b.ts for b in bars] == [1700000000, 1700003600, 1700007200]
    assert bars[0].symbol == "BTCUSDT"
    assert bars[0].granularity == "1h"
    assert bars[0].close == 60000.0
    assert bars[1].close == 60200.0
    assert bars[2].close == 60100.0


@respx.mock
async def test_get_klines_passes_query_params():
    """Symbol, interval, limit, startTime, endTime are passed correctly."""
    route = respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=[])
    )
    async with httpx.AsyncClient() as http:
        await _client(http).get_klines(
            symbol="ETHUSDT", interval="1d",
            start_ts=1700000000, end_ts=1700086400, limit=500,
        )

    params = route.calls.last.request.url.params
    assert params["symbol"] == "ETHUSDT"
    assert params["interval"] == "1d"
    assert params["limit"] == "500"
    # Times converted to ms for Binance
    assert params["startTime"] == "1700000000000"
    assert params["endTime"] == "1700086400000"


@respx.mock
async def test_get_klines_raises_on_429():
    """Rate-limit response (429) propagates as HTTPStatusError."""
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(429, json={"code": -1003, "msg": "Too many requests"})
    )
    async with httpx.AsyncClient() as http:
        try:
            await _client(http).get_klines(symbol="BTCUSDT", interval="1h")
            raised = False
        except httpx.HTTPStatusError:
            raised = True

    assert raised is True
