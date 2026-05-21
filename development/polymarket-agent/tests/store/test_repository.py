from agent.data.models import CryptoBarDTO, MarketDTO, PriceHistory, PricePoint
from agent.store.repository import save_crypto_bars, save_price_history, upsert_market
from agent.store.schema import CryptoBar, Market, PriceSnapshot


def _dto(market_id: str, question: str) -> MarketDTO:
    return MarketDTO(id=market_id, question=question, enable_order_book=True)


def test_upsert_market_inserts_then_updates(session):
    upsert_market(session, _dto("m1", "Original?"))
    session.commit()
    assert session.get(Market, "m1").question == "Original?"

    upsert_market(session, _dto("m1", "Updated?"))
    session.commit()

    assert session.get(Market, "m1").question == "Updated?"
    assert session.query(Market).count() == 1


def test_save_price_history_is_idempotent(session):
    upsert_market(session, _dto("m1", "Q"))
    session.commit()
    history = PriceHistory(
        token_id="tok-1",
        history=[PricePoint(t=1000, p=0.4), PricePoint(t=2000, p=0.5)],
    )

    added_first = save_price_history(session, "m1", history)
    session.commit()
    added_second = save_price_history(session, "m1", history)
    session.commit()

    assert added_first == 2
    assert added_second == 0
    assert session.query(PriceSnapshot).count() == 2


def test_upsert_market_persists_clob_token_ids(session):
    dto = MarketDTO(
        id="m-tokens", question="Q", enable_order_book=True,
        clob_token_ids=["tok-a", "tok-b"],
    )

    upsert_market(session, dto)
    session.commit()

    loaded = session.get(Market, "m-tokens")
    assert loaded.clob_token_ids == ["tok-a", "tok-b"]


def _bar(symbol: str, granularity: str, ts: int, close: float = 100.0) -> CryptoBarDTO:
    return CryptoBarDTO(
        symbol=symbol, granularity=granularity, ts=ts,  # type: ignore[arg-type]
        open=close, high=close, low=close, close=close, volume=1.0,
    )


def test_save_crypto_bars_inserts_new(session):
    """First call inserts all bars, returns count."""
    bars = [
        _bar("BTCUSDT", "1h", 1700000000),
        _bar("BTCUSDT", "1h", 1700003600),
        _bar("BTCUSDT", "1h", 1700007200),
    ]
    added = save_crypto_bars(session, bars)
    session.commit()

    assert added == 3
    assert session.query(CryptoBar).count() == 3


def test_save_crypto_bars_is_idempotent(session):
    """Re-saving same (symbol, granularity, ts) returns 0 added."""
    bars = [_bar("BTCUSDT", "1h", 1700000000)]

    first = save_crypto_bars(session, bars)
    session.commit()
    second = save_crypto_bars(session, bars)
    session.commit()

    assert first == 1
    assert second == 0
    assert session.query(CryptoBar).count() == 1


def test_save_crypto_bars_partial_overlap(session):
    """Mixed new-and-existing bars: only new ones counted."""
    save_crypto_bars(session, [_bar("BTCUSDT", "1h", 1700000000)])
    session.commit()

    added = save_crypto_bars(session, [
        _bar("BTCUSDT", "1h", 1700000000),  # already present
        _bar("BTCUSDT", "1h", 1700003600),  # new
        _bar("BTCUSDT", "1h", 1700007200),  # new
    ])
    session.commit()

    assert added == 2
    assert session.query(CryptoBar).count() == 3
