from agent.store.schema import Market, PriceSnapshot


def test_can_persist_market_and_snapshot(session):
    market = Market(id="m1", question="Will it rain?", category="Weather")
    session.add(market)
    session.add(
        PriceSnapshot(market_id="m1", token_id="tok-1", ts=1000, price=0.42)
    )
    session.commit()

    loaded = session.get(Market, "m1")
    assert loaded.question == "Will it rain?"
    assert loaded.snapshots[0].price == 0.42


def test_snapshot_unique_constraint(session):
    session.add(Market(id="m1", question="Q"))
    session.add(PriceSnapshot(market_id="m1", token_id="t", ts=1, price=0.5))
    session.commit()

    session.add(PriceSnapshot(market_id="m1", token_id="t", ts=1, price=0.9))
    raised = False
    try:
        session.commit()
    except Exception:
        raised = True
        session.rollback()

    assert raised is True


def test_market_clob_token_ids_round_trips_through_db(session_factory):
    """JSON column survives a real DB round-trip (not just the identity map)."""
    with session_factory() as write_session:
        write_session.add(
            Market(id="m-json", question="Q", clob_token_ids=["a", "b"])
        )
        write_session.commit()

    with session_factory() as read_session:
        loaded = read_session.get(Market, "m-json")
        assert loaded.clob_token_ids == ["a", "b"]
