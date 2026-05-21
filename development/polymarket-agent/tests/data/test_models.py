from agent.data.models import MarketDTO, PriceHistory, PricePoint


def test_price_point_and_history():
    history = PriceHistory(
        token_id="tok-1",
        history=[PricePoint(t=1000, p=0.5), PricePoint(t=2000, p=0.6)],
    )

    assert history.token_id == "tok-1"
    assert history.history[1].p == 0.6


def test_market_from_gamma_parses_stringified_token_ids():
    raw = {
        "id": 42,
        "question": "Will it rain?",
        "conditionId": "0xabc",
        "clobTokenIds": '["tok-yes", "tok-no"]',
        "category": "Weather",
        "active": True,
        "closed": False,
        "enableOrderBook": True,
        "orderMinSize": "5",
        "orderPriceMinTickSize": "0.01",
        "volume24hr": "1234.5",
        "liquidityNum": 99.0,
        "endDateIso": "2026-12-31",
    }

    dto = MarketDTO.from_gamma(raw)

    assert dto.id == "42"
    assert dto.clob_token_ids == ["tok-yes", "tok-no"]
    assert dto.enable_order_book is True
    assert dto.order_min_size == 5.0
    assert dto.order_price_min_tick_size == 0.01
    assert dto.volume_24hr == 1234.5
    assert dto.liquidity == 99.0


def test_market_from_gamma_tolerates_missing_fields():
    dto = MarketDTO.from_gamma({"id": "7"})

    assert dto.id == "7"
    assert dto.question == ""
    assert dto.clob_token_ids == []
    assert dto.order_min_size is None


def test_market_from_gamma_preserves_zero_liquidity():
    """Regression: liquidityNum=0.0 must not silently fall back to liquidity."""
    raw = {"id": "1", "liquidityNum": 0.0, "liquidity": "50.0"}

    dto = MarketDTO.from_gamma(raw)

    assert dto.liquidity == 0.0


def test_market_from_gamma_falls_back_to_liquidity_when_liquidity_num_missing():
    """When liquidityNum is absent, liquidity field is used."""
    raw = {"id": "1", "liquidity": "50.0"}

    dto = MarketDTO.from_gamma(raw)

    assert dto.liquidity == 50.0


def test_market_from_gamma_parses_outcome_prices_string():
    """outcomePrices comes as a stringified JSON array like '["0.55","0.45"]'."""
    raw = {
        "id": "1",
        "outcomePrices": '["0.55", "0.45"]',
    }
    dto = MarketDTO.from_gamma(raw)
    assert dto.outcome_prices == [0.55, 0.45]


def test_market_from_gamma_parses_outcome_prices_list():
    """outcomePrices may also come as an already-parsed list of floats or strings."""
    dto = MarketDTO.from_gamma({"id": "1", "outcomePrices": [0.55, 0.45]})
    assert dto.outcome_prices == [0.55, 0.45]
    dto2 = MarketDTO.from_gamma({"id": "1", "outcomePrices": ["1", "0"]})
    assert dto2.outcome_prices == [1.0, 0.0]


def test_market_from_gamma_missing_outcome_prices_defaults_empty():
    """When outcomePrices absent, dto.outcome_prices is []."""
    dto = MarketDTO.from_gamma({"id": "1"})
    assert dto.outcome_prices == []


from agent.data.models import CryptoBarDTO


def test_crypto_bar_from_binance_kline_canonical():
    """Binance returns each kline as a 12-element array; we use indices 0-5."""
    kline = [
        1700000000000,        # open time ms
        "60000.00",            # open
        "60500.00",            # high
        "59800.00",            # low
        "60200.00",            # close
        "1234.5678",           # volume
        1700003599999,         # close time ms (ignored)
        "74321000.50",         # quote volume (ignored)
        1500,                  # trades count (ignored)
        "615.1234",            # taker buy base (ignored)
        "37050000.25",         # taker buy quote (ignored)
        "0",                   # ignore field
    ]
    dto = CryptoBarDTO.from_binance_kline(kline, symbol="BTCUSDT", granularity="1h")

    assert dto.symbol == "BTCUSDT"
    assert dto.granularity == "1h"
    assert dto.ts == 1700000000  # ms / 1000
    assert dto.open == 60000.00
    assert dto.high == 60500.00
    assert dto.low == 59800.00
    assert dto.close == 60200.00
    assert dto.volume == 1234.5678


def test_crypto_bar_handles_daily_granularity():
    """Granularity is a Literal['1h', '1d']."""
    kline = [
        1700000000000, "60000", "61000", "59000", "60500", "100",
        0, "0", 0, "0", "0", "0",
    ]
    dto = CryptoBarDTO.from_binance_kline(kline, symbol="ETHUSDT", granularity="1d")
    assert dto.granularity == "1d"
