from agent.store.schema import CryptoBar
from agent.research.crypto.crypto_data import CryptoDataAccess


def test_get_current_spot_returns_most_recent_close(session_factory):
    with session_factory() as session:
        session.add(CryptoBar(
            symbol="BTCUSDT", granularity="1h", ts=1747800000,
            open=50000.0, high=50500.0, low=49500.0, close=50300.0, volume=10.0,
        ))
        session.add(CryptoBar(
            symbol="BTCUSDT", granularity="1h", ts=1747803600,
            open=50300.0, high=51000.0, low=50100.0, close=50800.0, volume=12.0,
        ))
        session.commit()

    cda = CryptoDataAccess(session_factory=session_factory)
    assert cda.get_current_spot("BTCUSDT", before_ts=1747900000) == 50800.0


def test_get_recent_returns_uses_close_to_close(session_factory):
    with session_factory() as session:
        for i, close in enumerate([100.0, 101.0, 99.0, 102.0], start=0):
            session.add(CryptoBar(
                symbol="BTCUSDT", granularity="1h", ts=1747800000 + i * 3600,
                open=close, high=close, low=close, close=close, volume=1.0,
            ))
        session.commit()

    cda = CryptoDataAccess(session_factory=session_factory)
    returns = cda.get_recent_returns("BTCUSDT", "1h", n_bars=3, before_ts=1747900000)
    # close-to-close: (101-100)/100 = 0.01, (99-101)/101 ~ -0.0198, (102-99)/99 ~ 0.0303
    assert len(returns) == 3
    assert abs(returns[0] - 0.01) < 1e-6
    assert abs(returns[1] - (99.0 - 101.0) / 101.0) < 1e-6
    assert abs(returns[2] - (102.0 - 99.0) / 99.0) < 1e-6


def test_get_recent_news_for_currency_filters_by_currency_and_ts(session_factory):
    """C2-A only needs the interface; full population happens in C2-B/C/D."""
    cda = CryptoDataAccess(session_factory=session_factory)
    # With no news_events in DB, returns empty list (stub behavior)
    result = cda.get_recent_news_for_currency("BTC", since_ts=1747800000, until_ts=1747900000)
    assert result == []
