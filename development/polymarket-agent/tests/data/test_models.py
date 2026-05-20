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
