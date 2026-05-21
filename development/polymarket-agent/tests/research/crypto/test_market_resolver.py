import tempfile
import textwrap
import pytest


def _write_markets_yaml(content: str) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    f.write(content)
    f.close()
    return f.name


def test_load_markets_yaml_parses_entries():
    from agent.research.crypto.market_resolver import load_markets_yaml
    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Will BTC reach 80000?"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    entries = load_markets_yaml(path)
    assert len(entries) == 1
    assert entries[0].market_id == "0xABC001"
    assert entries[0].symbol == "BTCUSDT"
    assert entries[0].direction == "up"


def test_resolver_returns_none_for_unknown_market():
    from agent.research.crypto.market_resolver import MarketResolver, load_markets_yaml
    from agent.store.schema import Market

    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Test"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    resolver = MarketResolver(load_markets_yaml(path))
    market = Market(id="0xUNKNOWN", question="???")
    assert resolver.resolve(market) is None


def test_resolver_parses_end_date_iso():
    from agent.research.crypto.market_resolver import MarketResolver, load_markets_yaml
    from agent.store.schema import Market

    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Test"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    resolver = MarketResolver(load_markets_yaml(path))
    market = Market(id="0xABC001", question="?", end_date_iso="2026-06-30T00:00:00Z")
    mapping = resolver.resolve(market)
    assert mapping is not None
    assert mapping.symbol == "BTCUSDT"
    # 2026-06-30 00:00 UTC = 1782777600 unix seconds (verified: plan had 1782604800 which is wrong)
    assert mapping.resolution_ts == 1782777600


def test_resolver_raises_on_missing_end_date():
    from agent.research.crypto.market_resolver import MarketResolver, load_markets_yaml
    from agent.store.schema import Market

    path = _write_markets_yaml(textwrap.dedent("""\
        - market_id: "0xABC001"
          polymarket_question: "Test"
          symbol: BTCUSDT
          barrier_price: 80000.0
          direction: up
    """))
    resolver = MarketResolver(load_markets_yaml(path))
    market = Market(id="0xABC001", question="?", end_date_iso=None)
    with pytest.raises(ValueError):
        resolver.resolve(market)


def test_time_to_resolution_years_positive():
    from agent.research.crypto.market_resolver import MarketResolver
    from agent.research.crypto.types import CryptoMarketMapping

    resolver = MarketResolver(mappings=[])
    mapping = CryptoMarketMapping(
        market_id="0xABC", symbol="BTCUSDT", barrier_price=80000.0,
        direction="up", resolution_ts=1782777600,
    )
    # now_ts = 2026-05-21 = 1747800000 -> T = (1782777600 - 1747800000) / (365.25 * 86400)
    now_ts = 1747800000
    T = resolver.time_to_resolution_years(mapping, now_ts)
    expected = (1782777600 - 1747800000) / (365.25 * 86400)
    assert abs(T - expected) < 1e-9


def test_time_to_resolution_years_clamped_at_zero():
    from agent.research.crypto.market_resolver import MarketResolver
    from agent.research.crypto.types import CryptoMarketMapping

    resolver = MarketResolver(mappings=[])
    mapping = CryptoMarketMapping(
        market_id="0xABC", symbol="BTCUSDT", barrier_price=80000.0,
        direction="up", resolution_ts=1000,
    )
    assert resolver.time_to_resolution_years(mapping, now_ts=1747800000) == 0.0
