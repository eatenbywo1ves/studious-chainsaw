import httpx
import respx

from agent.data.crypto_client import BinanceClient
from agent.data.crypto_ingest import CryptoIngestService
from agent.data.rate_limiter import TokenBucket
from agent.store.schema import CryptoBar


def _client(http: httpx.AsyncClient) -> BinanceClient:
    return BinanceClient(
        http_client=http,
        rate_limit_bucket=TokenBucket(capacity=1000, refill_per_second=1000),
    )


def _kline(open_time_ms: int) -> list:
    return [
        open_time_ms, "60000", "60100", "59900", "60050", "100",
        open_time_ms + 3599999, "6000000", 1500, "50", "3000000", "0",
    ]


@respx.mock
async def test_ingest_history_single_request(session_factory, session):
    """Range fits in one request: ~100 bars, one mocked response."""
    bars_payload = [_kline(1700000000000 + i * 3600000) for i in range(100)]
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=bars_payload)
    )
    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        count = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000, end_ts=1700000000 + 100 * 3600,
        )

    assert count == 100
    assert session.query(CryptoBar).filter_by(
        symbol="BTCUSDT", granularity="1h"
    ).count() == 100


@respx.mock
async def test_ingest_history_paginates_over_two_requests(session_factory, session):
    """Range spans two requests: 1000 + 500 bars across two paginated calls."""
    first_batch = [_kline(1700000000000 + i * 3600000) for i in range(1000)]
    second_batch = [_kline(1700000000000 + (1000 + i) * 3600000) for i in range(500)]

    respx.get("https://api.binance.com/api/v3/klines").mock(
        side_effect=[
            httpx.Response(200, json=first_batch),
            httpx.Response(200, json=second_batch),
        ]
    )

    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        count = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000,
            end_ts=1700000000 + 1500 * 3600,
        )

    assert count == 1500
    assert session.query(CryptoBar).filter_by(
        symbol="BTCUSDT", granularity="1h"
    ).count() == 1500


@respx.mock
async def test_ingest_history_is_idempotent(session_factory, session):
    """Second call with same range returns 0 added; row count unchanged."""
    bars_payload = [_kline(1700000000000 + i * 3600000) for i in range(50)]
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=bars_payload)
    )

    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        first = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000, end_ts=1700000000 + 50 * 3600,
        )
        second = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000, end_ts=1700000000 + 50 * 3600,
        )

    assert first == 50
    assert second == 0
    assert session.query(CryptoBar).count() == 50


@respx.mock
async def test_ingest_latest(session_factory, session):
    """ingest_latest fetches recent bars without an explicit range."""
    bars_payload = [_kline(1700000000000 + i * 3600000) for i in range(10)]
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=bars_payload)
    )
    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        count = await service.ingest_latest(symbol="BTCUSDT", granularity="1h")

    assert count == 10
