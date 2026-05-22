"""C3a CLI full-pipeline WIRING smoke test.

This is NOT a live run: the Gamma/CLOB network is mocked with respx, the LLM
extractor is an injected fake, and Binance OHLCV is injected via a fake
``crypto_ingest`` that seeds synthetic CryptoBar rows.  Everything else — the
parser, persistence, the resolver bridge, the REAL crypto_model pipeline, the
run_validation orchestrator, and JSON serialization — runs for real.

Goal: prove the entrypoint actually wires
    enumerate -> parse -> persist/ingest -> resolutions -> orchestrator -> file
and that the resulting report round-trips through json.load with the expected
keys and a valid verdict.

The seeded scenario mirrors the C2-A e2e gate so the real crypto_model emits a
non-zero position deterministically: BTCUSDT spot ~50k, barrier 80k, a final
shock bar, and a low Polymarket YES price.  ~111 bars are seeded so the real
GARCH(1,1) fit (which requires >= 100 return observations) succeeds.
"""

import json

import httpx
import respx

from agent.config import Settings
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.research.crypto.question_parser import ParseCache
from agent.scripts.run_crypto_validation import run_pipeline, write_report
from agent.store.schema import CryptoBar

_GAMMA_URL = "https://gamma-api.polymarket.com/markets"
_HISTORY_URL = "https://clob.polymarket.com/prices-history"

_SYMBOL = "BTCUSDT"
_SPOT = 50_000.0
_BARRIER = 80_000.0
_SHOCK_RETURN = -0.15
_BAR_INTERVAL_S = 3_600

# Window: resolution dates land inside this range.
_WINDOW_START = "2025-01-01T00:00:00Z"
_WINDOW_END = "2025-12-31T00:00:00Z"

# Each market's CLOB price history (the "event") timestamp.  The model reads
# bars at-or-before this ts, so it must sit at the END of the seeded bar range.
_EVENT_TS = 1_735_000_000  # ~2024-12-24; bars are seeded ending just before this
_RESOLUTION_ISO = "2025-06-15T00:00:00Z"

_P_MARKET = 0.10  # low YES price -> p_bridge >> p_market -> non-zero Kelly


def _gamma_market(market_id: str) -> dict:
    """A resolved crypto MarketDTO raw payload (YES won: outcomePrices [1,0])."""
    return {
        "id": market_id,
        "question": f"Will BTC reach $80k? [{market_id}]",
        "category": "Crypto",
        "closed": True,
        "active": False,
        "endDate": _RESOLUTION_ISO,
        "clobTokenIds": json.dumps([f"{market_id}-yes", f"{market_id}-no"]),
        "outcomePrices": json.dumps(["1", "0"]),
    }


def _price_history_payload() -> dict:
    """A few CLOB price points; the LAST is at the event ts the model replays."""
    return {
        "history": [
            {"t": _EVENT_TS - 7200, "p": _P_MARKET},
            {"t": _EVENT_TS - 3600, "p": _P_MARKET},
            {"t": _EVENT_TS, "p": _P_MARKET},
        ]
    }


def _fake_llm_extract(question: str) -> dict:
    """Deterministic stand-in for the OpenAI extractor."""
    return {
        "symbol": _SYMBOL,
        "barrier_usd": _BARRIER,
        "direction": "up",
        "resolution_date_iso": _RESOLUTION_ISO,
        "confidence": 0.95,
        "is_crypto_barrier_market": True,
    }


class _FakeCryptoIngest:
    """Stands in for CryptoIngestService.  On first call it seeds ~111 hourly
    BTCUSDT bars (100 quiet + 1 shock) ending just before the event ts, enough
    for the real GARCH fit and a firing shock detector.  Idempotent."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    async def ingest_history(self, symbol, granularity, start_ts, end_ts):
        with self._session_factory() as session:
            already = (
                session.query(CryptoBar)
                .filter(CryptoBar.symbol == symbol)
                .count()
            )
            if already:
                return 0

            prices = [_SPOT]
            for _ in range(100):  # 100 quiet bars (0.1% return)
                prices.append(prices[-1] * 1.001)
            prices.append(prices[-1] * (1.0 + _SHOCK_RETURN))  # final shock bar

            n = len(prices)  # 102 closes -> 102 bars
            # End the last bar one interval before the event ts so all bars
            # satisfy CryptoBar.ts <= event_ts in get_recent_returns.
            base_ts = _EVENT_TS - n * _BAR_INTERVAL_S
            added = 0
            for i, close in enumerate(prices):
                session.add(
                    CryptoBar(
                        symbol=symbol,
                        granularity=granularity,
                        ts=base_ts + i * _BAR_INTERVAL_S,
                        open=close * 0.999,
                        high=close * 1.001,
                        low=close * 0.999,
                        close=close,
                        volume=100.0,
                    )
                )
                added += 1
            session.commit()
            return added


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=10000, refill_per_second=10000),
    )


@respx.mock
async def test_c3a_cli_smoke_full_pipeline(session_factory, tmp_path):
    """End-to-end wiring: enumerate -> parse -> persist/ingest -> resolutions
    -> REAL crypto_model -> run_validation -> JSON report file."""
    market_ids = ["mkt-a", "mkt-b", "mkt-c"]

    # Gamma: a single page (< page size) of 3 resolved crypto markets.
    respx.get(_GAMMA_URL).mock(
        return_value=httpx.Response(
            200, json=[_gamma_market(mid) for mid in market_ids]
        )
    )
    # CLOB: every prices-history request returns the same 3-point series.
    respx.get(_HISTORY_URL).mock(
        return_value=httpx.Response(200, json=_price_history_payload())
    )

    parse_cache = ParseCache(str(tmp_path / "parse_cache"))

    async with httpx.AsyncClient() as http:
        report = await run_pipeline(
            settings=Settings(),
            session_factory=session_factory,
            polymarket_client=_client(http),
            crypto_ingest=_FakeCryptoIngest(session_factory),
            llm_extract=_fake_llm_extract,
            parse_cache=parse_cache,
            window_start_iso=_WINDOW_START,
            window_end_iso=_WINDOW_END,
        )

    # The real pipeline must have surfaced all 3 markets through every stage.
    assert report.coverage["enumerated"] == 3
    assert report.coverage["passed_validation_pass2"] == 3
    assert report.coverage["had_clean_resolution"] == 3

    output_path = tmp_path / "report.json"
    write_report(report, output_path)

    # --- File round-trips through json.load with the expected shape. ---
    assert output_path.exists()
    with open(output_path, encoding="utf-8") as f:
        loaded = json.load(f)

    assert loaded["verdict"] in {"CONTINUE", "STOP", "INCONCLUSIVE"}
    # 3 markets -> coverage < 20 -> expected INCONCLUSIVE (unless skill <= 0
    # forces STOP first); membership assertion above is the robust check.

    assert "actually_tested" in loaded["coverage"]
    # by_cost float keys must serialize as strings.
    for cost_key in ("0.0", "0.01", "0.02", "0.03"):
        assert cost_key in loaded["by_cost"], f"missing cost scenario {cost_key}"
        assert "final_bankroll" in loaded["by_cost"][cost_key]
