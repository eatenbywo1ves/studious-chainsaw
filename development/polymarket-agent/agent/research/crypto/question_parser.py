"""LLM-based extraction of (symbol, barrier, direction, resolution_date) from a
Polymarket crypto barrier-market question, with a validation layer and an
on-disk cache for reproducibility.

A parse that fails any validation check is EXCLUDED from the backtest (status
!= 'ok') and never guessed — the harness must not be poisoned by a hallucinated
barrier.
"""

import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal


@dataclass(frozen=True)
class ParsedMarket:
    market_id: str
    status: Literal["ok", "low_confidence", "implausible_barrier",
                    "inconsistent_direction", "unparseable_date", "not_crypto_barrier"]
    symbol: str | None
    barrier: float | None
    direction: Literal["up", "down"] | None
    resolution_ts: int | None
    confidence: float
    reason: str


class ParseCache:
    """On-disk JSON cache keyed by market_id under cache_dir."""

    def __init__(self, cache_dir: str):
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, market_id: str) -> Path:
        safe = market_id.replace("/", "_")
        return self.dir / f"{safe}.json"

    def get(self, market_id: str) -> ParsedMarket | None:
        p = self._path(market_id)
        if not p.exists():
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        return ParsedMarket(**data)

    def put(self, parsed: ParsedMarket) -> None:
        self._path(parsed.market_id).write_text(
            json.dumps(parsed.__dict__), encoding="utf-8"
        )


class RawExtractCache:
    """On-disk cache of the RAW llm_extract dict keyed by market_id.

    Caching the raw extraction (rather than the validated ParsedMarket) lets a
    consumer run the validation layer more than once for the same market — e.g.
    pass 1 without an underlying price range, then pass 2 with it — while
    calling the LLM at most ONCE per market.  This keeps the verdict
    reproducible across runs: a non-deterministic LLM cannot flip a market's
    inclusion between passes or between runs once its raw dict is on disk.
    """

    def __init__(self, cache_dir: str):
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, market_id: str) -> Path:
        safe = market_id.replace("/", "_")
        return self.dir / f"{safe}.raw.json"

    def extract(
        self, market_id: str, question: str, llm_extract: Callable[[str], dict]
    ) -> dict:
        p = self._path(market_id)
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        raw = llm_extract(question)
        p.write_text(json.dumps(raw), encoding="utf-8")
        return raw


def _parse_iso(iso_str: str) -> int | None:
    try:
        s = iso_str[:-1] + "+00:00" if iso_str.endswith("Z") else iso_str
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


def validate_parse(
    market_id: str,
    raw: dict,
    *,
    underlying_price_range: tuple[float, float] | None,
    confidence_threshold: float,
    open_spot: float | None = None,
) -> ParsedMarket:
    conf = float(raw.get("confidence", 0.0))
    if not raw.get("is_crypto_barrier_market", False):
        return ParsedMarket(market_id, "not_crypto_barrier", None, None, None, None,
                            conf, "LLM flagged non-crypto-barrier")
    if conf < confidence_threshold:
        return ParsedMarket(market_id, "low_confidence", None, None, None, None,
                            conf, f"confidence {conf} < {confidence_threshold}")
    resolution_ts = _parse_iso(raw.get("resolution_date_iso", ""))
    if resolution_ts is None:
        return ParsedMarket(market_id, "unparseable_date", None, None, None, None,
                            conf, "resolution_date_iso unparseable")
    barrier = raw.get("barrier_usd")
    if barrier is None or not math.isfinite(barrier) or barrier <= 0:
        return ParsedMarket(market_id, "implausible_barrier", None, None, None, None,
                            conf, f"barrier {barrier} non-positive/non-finite")
    if underlying_price_range is not None:
        lo, hi = underlying_price_range
        if not (0.5 * lo <= barrier <= 10.0 * hi):
            return ParsedMarket(market_id, "implausible_barrier", None, None, None, None,
                                conf, f"barrier {barrier} outside plausible range")
    direction = raw.get("direction")
    if direction not in ("up", "down"):
        return ParsedMarket(market_id, "implausible_barrier", None, None, None, None,
                            conf, f"direction {direction} invalid")
    if open_spot is not None:
        if direction == "up" and barrier <= open_spot:
            return ParsedMarket(market_id, "inconsistent_direction", None, None, None, None,
                                conf, "up-barrier at/below open spot")
        if direction == "down" and barrier >= open_spot:
            return ParsedMarket(market_id, "inconsistent_direction", None, None, None, None,
                                conf, "down-barrier at/above open spot")
    return ParsedMarket(market_id, "ok", raw["symbol"], float(barrier), direction,
                        resolution_ts, conf, "")


def parse_question(
    market_id: str,
    question: str,
    *,
    llm_extract: Callable[[str], dict],
    cache: ParseCache,
    underlying_price_range: tuple[float, float] | None,
    confidence_threshold: float = 0.85,
    open_spot: float | None = None,
) -> ParsedMarket:
    cached = cache.get(market_id)
    if cached is not None:
        return cached
    raw = llm_extract(question)
    parsed = validate_parse(
        market_id, raw,
        underlying_price_range=underlying_price_range,
        confidence_threshold=confidence_threshold,
        open_spot=open_spot,
    )
    cache.put(parsed)
    return parsed
