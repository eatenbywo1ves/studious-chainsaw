from agent.data.models import MarketDTO, PriceHistory, PricePoint
from agent.store.repository import save_price_history, upsert_market
from agent.store.schema import Market, PriceSnapshot


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
