"""MarketResolver: loads markets.yaml and resolves Polymarket markets to
crypto pair + barrier + resolution_ts.
"""

from datetime import datetime, timezone
from pathlib import Path

import yaml

from agent.research.crypto.types import CryptoMarketMapping, CryptoMarketMappingFile


SECONDS_PER_YEAR = int(365.25 * 86400)


def load_markets_yaml(path: str) -> list[CryptoMarketMappingFile]:
    """Parse markets.yaml into a list of mapping entries."""
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or []
    return [
        CryptoMarketMappingFile(
            market_id=entry["market_id"],
            polymarket_question=entry.get("polymarket_question", ""),
            symbol=entry["symbol"],
            barrier_price=float(entry["barrier_price"]),
            direction=entry["direction"],
        )
        for entry in raw
    ]


def _parse_iso_to_unix(iso_str: str) -> int:
    """Parse an ISO 8601 string with optional Z suffix to Unix seconds (UTC)."""
    if iso_str.endswith("Z"):
        iso_str = iso_str[:-1] + "+00:00"
    dt = datetime.fromisoformat(iso_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


class MarketResolver:
    """Wraps a loaded list of CryptoMarketMappingFile entries; exposes lookup
    and time-to-resolution helpers.  Stateless after construction.
    """

    def __init__(self, mappings: list[CryptoMarketMappingFile]):
        self._by_id = {m.market_id: m for m in mappings}

    def resolve(self, market) -> CryptoMarketMapping | None:
        """Look up the mapping for a Polymarket market.  Returns None if not
        in markets.yaml.  Raises ValueError if end_date_iso is missing or
        unparseable.
        """
        entry = self._by_id.get(market.id)
        if entry is None:
            return None
        if not market.end_date_iso:
            raise ValueError(
                f"Market {market.id} is mapped in markets.yaml but has no "
                f"end_date_iso — cannot compute resolution_ts."
            )
        resolution_ts = _parse_iso_to_unix(market.end_date_iso)
        return CryptoMarketMapping(
            market_id=entry.market_id,
            symbol=entry.symbol,
            barrier_price=entry.barrier_price,
            direction=entry.direction,
            resolution_ts=resolution_ts,
        )

    def time_to_resolution_years(
        self, mapping: CryptoMarketMapping, now_ts: int
    ) -> float:
        delta = mapping.resolution_ts - now_ts
        if delta <= 0:
            return 0.0
        return delta / SECONDS_PER_YEAR
