import tempfile

import pytest

from agent.research.crypto.question_parser import (
    ParseCache,
    ParsedMarket,
    parse_question,
)


def _cache():
    d = tempfile.mkdtemp()
    return ParseCache(cache_dir=d)


def _extract_btc_up(_q):
    return {
        "symbol": "BTCUSDT", "barrier_usd": 80000.0, "direction": "up",
        "resolution_date_iso": "2026-06-30T00:00:00Z", "confidence": 0.95,
        "is_crypto_barrier_market": True,
    }


def test_valid_btc_question_parses_ok():
    calls = {"n": 0}
    def extract(q):
        calls["n"] += 1
        return _extract_btc_up(q)
    parsed = parse_question(
        "0xM1", "Will Bitcoin reach $80,000 by June 30, 2026?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
    )
    assert parsed.status == "ok"
    assert parsed.symbol == "BTCUSDT"
    assert parsed.barrier == 80000.0
    assert parsed.direction == "up"
    assert parsed.resolution_ts == 1782777600


def test_hallucinated_barrier_rejected():
    def extract(_q):
        d = _extract_btc_up(_q); d["barrier_usd"] = 8000.0
        return d
    parsed = parse_question(
        "0xM2", "Will Bitcoin reach $80,000 by June 30, 2026?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
    )
    assert parsed.status == "implausible_barrier"


def test_low_confidence_rejected():
    def extract(_q):
        d = _extract_btc_up(_q); d["confidence"] = 0.5
        return d
    parsed = parse_question(
        "0xM3", "Will Bitcoin maybe do something?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
    )
    assert parsed.status == "low_confidence"


def test_non_crypto_rejected():
    def extract(_q):
        return {"is_crypto_barrier_market": False, "confidence": 0.99}
    parsed = parse_question(
        "0xM4", "Will the Lakers win the title?",
        llm_extract=extract, cache=_cache(),
        underlying_price_range=None,
    )
    assert parsed.status == "not_crypto_barrier"


def test_cache_hit_does_not_recall_llm():
    calls = {"n": 0}
    def extract(q):
        calls["n"] += 1
        return _extract_btc_up(q)
    cache = _cache()
    parse_question("0xM5", "Will Bitcoin reach $80,000 by June 30, 2026?",
                   llm_extract=extract, cache=cache,
                   underlying_price_range=(40000.0, 110000.0))
    parse_question("0xM5", "Will Bitcoin reach $80,000 by June 30, 2026?",
                   llm_extract=extract, cache=cache,
                   underlying_price_range=(40000.0, 110000.0))
    assert calls["n"] == 1


def test_inconsistent_direction_rejected():
    def extract_bad(_q):
        d = _extract_btc_up(_q); d["barrier_usd"] = 105000.0; d["direction"] = "down"
        return d
    parsed = parse_question(
        "0xM6", "Will Bitcoin fall below $105,000?",
        llm_extract=extract_bad, cache=_cache(),
        underlying_price_range=(40000.0, 110000.0),
        open_spot=50000.0,
    )
    assert parsed.status == "inconsistent_direction"
