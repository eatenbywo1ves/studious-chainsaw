import math

import httpx
import respx

from agent.config import Settings
from agent.data.ingest import IngestService
from agent.data.models import MarketDTO, PriceHistory, PricePoint
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.research.baselines import constant_half, last_traded_price
from agent.store.repository import save_price_history, upsert_market
from agent.store.schema import Market
from agent.validation.backtest import ReplayEngine, ReplayEvent, walk_forward_backtest
from agent.validation.types import BacktestResult, ResolvedOutcome


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


def _setup_three_markets(session) -> None:
    """3 markets x 5 price ticks each, with deterministic constant prices.

    m1: outcome=YES, all ticks at 0.8 -> last_traded_price contribution = 5*(0.8-1)^2 = 0.20
    m2: outcome=NO,  all ticks at 0.2 -> last_traded_price contribution = 5*(0.2-0)^2 = 0.20
    m3: outcome=YES, all ticks at 0.6 -> last_traded_price contribution = 5*(0.6-1)^2 = 0.80
    Total last_traded_price Brier = (0.20 + 0.20 + 0.80) / 15 = 0.08
    """
    market_specs = [
        ("m1", "tok-m1-yes", 0.8),
        ("m2", "tok-m2-yes", 0.2),
        ("m3", "tok-m3-yes", 0.6),
    ]
    for mid, tid, price in market_specs:
        upsert_market(
            session,
            MarketDTO(
                id=mid,
                question=f"Q for {mid}",
                clob_token_ids=[tid, f"{tid}-no"],
                enable_order_book=True,
            ),
        )
        save_price_history(
            session,
            mid,
            PriceHistory(
                token_id=tid,
                history=[
                    PricePoint(t=1700000000 + i * 3600, p=price) for i in range(5)
                ],
            ),
        )
    session.commit()


def _three_market_resolutions() -> dict[str, ResolvedOutcome]:
    return {
        "m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=1700020000),
        "m2": ResolvedOutcome(market_id="m2", outcome=0, resolved_ts=1700020000),
        "m3": ResolvedOutcome(market_id="m3", outcome=1, resolved_ts=1700020000),
    }


def test_walk_forward_backtest_constant_half_brier(session):
    """§5.4 constant-half case: 15 predictions of 0.5 -> Brier = 0.25 exactly."""
    _setup_three_markets(session)
    resolutions = _three_market_resolutions()

    result = walk_forward_backtest(
        session, constant_half, resolutions, model_name="constant_half"
    )

    assert isinstance(result, BacktestResult)
    assert result.model_name == "constant_half"
    assert result.n_predictions == 15
    assert result.n_resolved == 15
    assert math.isclose(result.brier_score, 0.25, abs_tol=1e-10)
    assert result.kupiec is None  # n_resolved=15 < kupiec_window=100


def test_walk_forward_backtest_last_traded_price_brier(session):
    """§5.4 last-traded-price case: Brier = 0.08 with the synthetic data above."""
    _setup_three_markets(session)
    resolutions = _three_market_resolutions()

    result = walk_forward_backtest(
        session, last_traded_price, resolutions, model_name="last_traded_price"
    )

    assert result.n_predictions == 15
    assert result.n_resolved == 15
    assert math.isclose(result.brier_score, 0.08, abs_tol=1e-10)
    assert result.kupiec is None


def test_walk_forward_backtest_unresolved_markets_excluded(session):
    """Markets without resolutions still produce predictions but don't count toward
    n_resolved or Brier."""
    _setup_three_markets(session)
    resolutions = {
        "m1": ResolvedOutcome(market_id="m1", outcome=1, resolved_ts=1700020000),
        "m2": ResolvedOutcome(market_id="m2", outcome=0, resolved_ts=1700020000),
    }

    result = walk_forward_backtest(
        session, constant_half, resolutions, model_name="constant_half"
    )

    assert result.n_predictions == 15
    assert result.n_resolved == 10


def test_walk_forward_backtest_empty_store(session):
    """No markets stored -> 0 predictions, 0 resolved, Brier=0 (degenerate)."""
    result = walk_forward_backtest(
        session, constant_half, resolutions={}, model_name="constant_half"
    )

    assert result.n_predictions == 0
    assert result.n_resolved == 0
    assert result.brier_score == 0.0
    assert result.kupiec is None
