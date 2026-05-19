import httpx
import respx

from agent.config import Settings
from agent.data.ingest import IngestService
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.store.repository import save_price_history
from agent.data.models import PriceHistory, PricePoint
from agent.store.schema import Market
from agent.validation.backtest import ReplayEngine, ReplayEvent


def test_replay_yields_events_in_timestamp_order(session):
    session.add(Market(id="m1", question="Q"))
    # Deliberately insert out of order; replay must sort ascending by ts.
    save_price_history(
        session,
        "m1",
        PriceHistory(
            token_id="t1",
            history=[PricePoint(t=3000, p=0.7), PricePoint(t=1000, p=0.4),
                     PricePoint(t=2000, p=0.55)],
        ),
    )
    session.commit()

    events = list(ReplayEngine(session).replay("m1", "t1"))

    assert events == [
        ReplayEvent(ts=1000, token_id="t1", price=0.4),
        ReplayEvent(ts=2000, token_id="t1", price=0.55),
        ReplayEvent(ts=3000, token_id="t1", price=0.7),
    ]


def test_replay_isolates_by_token(session):
    session.add(Market(id="m1", question="Q"))
    save_price_history(
        session, "m1",
        PriceHistory(token_id="t1", history=[PricePoint(t=1, p=0.1)]),
    )
    save_price_history(
        session, "m1",
        PriceHistory(token_id="t2", history=[PricePoint(t=1, p=0.9)]),
    )
    session.commit()

    events = list(ReplayEngine(session).replay("m1", "t2"))

    assert [e.price for e in events] == [0.9]


@respx.mock
async def test_phase0_gate_replay_reproduces_ingested_prices(
    session_factory, session
):
    """PHASE 0 COMPLETION GATE: data ingested from the API, when replayed by
    the backtest harness, reproduces the source price series exactly."""
    source = [
        {"t": 1700000000, "p": 0.31},
        {"t": 1700003600, "p": 0.34},
        {"t": 1700007200, "p": 0.29},
        {"t": 1700010800, "p": 0.41},
    ]
    session.add(Market(id="mkt-gate", question="Gate market"))
    session.commit()
    respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(200, json={"history": source})
    )

    async with httpx.AsyncClient() as http:
        client = PolymarketClient(
            settings=Settings(),
            http_client=http,
            market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
        )
        added = await IngestService(client, session_factory).ingest_price_history(
            "mkt-gate", "tok-gate"
        )

    replayed = list(ReplayEngine(session).replay("mkt-gate", "tok-gate"))

    assert added == len(source)
    assert [(e.ts, e.price) for e in replayed] == [
        (row["t"], row["p"]) for row in source
    ]
