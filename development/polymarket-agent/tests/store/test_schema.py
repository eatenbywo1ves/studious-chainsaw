import json

from agent.store.schema import CryptoBar, Market, ModeFloorState, ModePerformance, PriceSnapshot, TradeRecord


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


def test_crypto_bar_round_trips_through_db(session_factory):
    """CryptoBar persists and reads back across separate sessions."""
    with session_factory() as write_session:
        bar = CryptoBar(
            symbol="BTCUSDT",
            granularity="1h",
            ts=1700000000,
            open=60000.0,
            high=60500.0,
            low=59800.0,
            close=60200.0,
            volume=1234.5,
        )
        write_session.add(bar)
        write_session.commit()

    with session_factory() as read_session:
        loaded = read_session.query(CryptoBar).filter_by(
            symbol="BTCUSDT", granularity="1h", ts=1700000000
        ).first()
        assert loaded is not None
        assert loaded.open == 60000.0
        assert loaded.high == 60500.0
        assert loaded.low == 59800.0
        assert loaded.close == 60200.0
        assert loaded.volume == 1234.5


def test_crypto_bar_unique_constraint_on_symbol_granularity_ts(session):
    """Duplicate (symbol, granularity, ts) raises IntegrityError."""
    from sqlalchemy.exc import IntegrityError

    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1h", ts=1700000000,
        open=1, high=1, low=1, close=1, volume=1,
    ))
    session.commit()

    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1h", ts=1700000000,
        open=2, high=2, low=2, close=2, volume=2,
    ))
    raised = False
    try:
        session.commit()
    except IntegrityError:
        raised = True
        session.rollback()
    assert raised is True


def test_crypto_bar_allows_different_granularities_same_ts(session):
    """Same (symbol, ts) is allowed across different granularities."""
    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1h", ts=1700000000,
        open=1, high=1, low=1, close=1, volume=1,
    ))
    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1d", ts=1700000000,
        open=1, high=1, low=1, close=1, volume=1,
    ))
    session.commit()  # must not raise

    assert session.query(CryptoBar).count() == 2


def test_mode_performance_round_trips_through_db(session_factory):
    """Write a ModePerformance row in session A, read it back in session B."""
    with session_factory() as session_a:
        row = ModePerformance(
            mode_name="binary",
            market_id="0xABC001",
            p_mode=0.31,
            p_market_at_prediction=0.10,
            outcome=1,
            brier_score=(0.31 - 1.0) ** 2,
            closed_at=1747800000,
        )
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(ModePerformance).one()
        assert result.mode_name == "binary"
        assert result.market_id == "0xABC001"
        assert result.p_mode == 0.31
        assert result.p_market_at_prediction == 0.10
        assert result.outcome == 1
        assert abs(result.brier_score - 0.4761) < 1e-9
        assert result.closed_at == 1747800000


def test_trade_record_round_trips_through_db(session_factory):
    """Two-session round-trip; full pipeline diagnostics preserved."""
    with session_factory() as session_a:
        row = TradeRecord(
            market_id="0xABC001",
            ts=1747800000,
            p_market=0.10,
            p_bridge=0.31,
            p_mode_binary=0.31,
            p_mode_exp=0.30,
            p_mode_magnitude=0.29,
            p_mode_confidence=0.32,
            p_blend=0.305,
            p_final=0.355,
            agreement_vetoed=False,
            kelly_fraction=0.049,
            position_size=4.9,
            shock_active=True,
            shock_severity=0.8,
            mode_weights_json=json.dumps({"binary": 0.25, "exp": 0.25, "magnitude": 0.25, "confidence": 0.25}),
        )
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(TradeRecord).one()
        assert result.market_id == "0xABC001"
        assert result.ts == 1747800000
        assert result.p_market == 0.10
        assert result.p_bridge == 0.31
        assert result.p_mode_binary == 0.31
        assert result.p_mode_exp == 0.30
        assert result.p_mode_magnitude == 0.29
        assert result.p_mode_confidence == 0.32
        assert result.p_blend == 0.305
        assert result.p_final == 0.355
        assert result.agreement_vetoed is False
        assert result.kelly_fraction == 0.049
        assert result.position_size == 4.9
        assert result.shock_active is True
        assert result.shock_severity == 0.8
        weights = json.loads(result.mode_weights_json)
        assert abs(sum(weights.values()) - 1.0) < 1e-9


def test_mode_floor_state_round_trips_through_db(session_factory):
    """One row per mode, mutable, tracks per-mode Brier floor evolution."""
    with session_factory() as session_a:
        row = ModeFloorState(
            mode_name="confidence",
            brier_floor=0.10,
            disable_streak=0,
            is_disabled=False,
            updated_at=1747800000,
        )
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(ModeFloorState).one()
        assert result.mode_name == "confidence"
        assert result.brier_floor == 0.10
        assert result.is_disabled is False


def test_mode_floor_state_defaults_applied_when_omitted(session_factory):
    """Default values for brier_floor, disable_streak, is_disabled apply
    when caller omits them (only mode_name and updated_at are required)."""
    with session_factory() as session_a:
        row = ModeFloorState(mode_name="exp", updated_at=1747800000)
        session_a.add(row)
        session_a.commit()

    with session_factory() as session_b:
        result = session_b.query(ModeFloorState).one()
        assert result.brier_floor == 0.10
        assert result.disable_streak == 0
        assert result.is_disabled is False
