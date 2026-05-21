import json
from typing import Literal

from pydantic import BaseModel, Field


def _as_float(value: object) -> float | None:
    """Coerce a string/number/None into a float or None."""
    if value is None or value == "":
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


class PricePoint(BaseModel):
    """A single (unix-second timestamp, price) observation."""

    t: int
    p: float


class PriceHistory(BaseModel):
    """An ordered price series for one CLOB token (asset id)."""

    token_id: str
    history: list[PricePoint] = Field(default_factory=list)


class MarketDTO(BaseModel):
    """A Polymarket market, normalized from the Gamma API payload."""

    id: str
    question: str = ""
    condition_id: str | None = None
    clob_token_ids: list[str] = Field(default_factory=list)
    category: str | None = None
    active: bool = False
    closed: bool = False
    enable_order_book: bool = False
    order_min_size: float | None = None
    order_price_min_tick_size: float | None = None
    volume_24hr: float | None = None
    liquidity: float | None = None
    end_date_iso: str | None = None
    outcome_prices: list[float] = Field(default_factory=list)

    @classmethod
    def from_gamma(cls, raw: dict) -> "MarketDTO":
        """Build a MarketDTO from a raw Gamma API market object."""
        token_ids = raw.get("clobTokenIds")
        if isinstance(token_ids, str):
            try:
                token_ids = json.loads(token_ids)
            except json.JSONDecodeError:
                token_ids = []
        outcome_prices_raw = raw.get("outcomePrices")
        if isinstance(outcome_prices_raw, str):
            try:
                outcome_prices_raw = json.loads(outcome_prices_raw)
            except json.JSONDecodeError:
                outcome_prices_raw = []
        outcome_prices = [
            float(x) for x in (outcome_prices_raw or [])
            if x is not None and x != ""
        ]
        return cls(
            id=str(raw["id"]),
            question=raw.get("question", "") or "",
            condition_id=raw.get("conditionId"),
            clob_token_ids=list(token_ids or []),
            category=raw.get("category"),
            active=bool(raw.get("active", False)),
            closed=bool(raw.get("closed", False)),
            enable_order_book=bool(raw.get("enableOrderBook", False)),
            order_min_size=_as_float(raw.get("orderMinSize")),
            order_price_min_tick_size=_as_float(raw.get("orderPriceMinTickSize")),
            volume_24hr=_as_float(raw.get("volume24hr")),
            liquidity=_as_float(
                raw.get("liquidityNum")
                if raw.get("liquidityNum") is not None
                else raw.get("liquidity")
            ),
            end_date_iso=(
                raw.get("endDateIso")
                if raw.get("endDateIso") is not None
                else raw.get("endDate")
            ),
            outcome_prices=outcome_prices,
        )


class CryptoBarDTO(BaseModel):
    """A crypto OHLCV bar, normalized from Binance's klines API."""

    symbol: str
    granularity: Literal["1h", "1d"]
    ts: int  # unix seconds (UTC)
    open: float
    high: float
    low: float
    close: float
    volume: float

    @classmethod
    def from_binance_kline(
        cls, kline: list, symbol: str, granularity: str
    ) -> "CryptoBarDTO":
        """Parse one element of Binance's /api/v3/klines response.

        Binance returns each bar as a 12-element array; we use indices 0-5:
            [0] open time in milliseconds (we convert to seconds)
            [1] open price (string -> float)
            [2] high price
            [3] low price
            [4] close price
            [5] base asset volume
        Trade count, quote-volume, taker-buy fields (indices 6-11) are ignored.
        """
        return cls(
            symbol=symbol,
            granularity=granularity,  # type: ignore[arg-type]
            ts=int(kline[0]) // 1000,
            open=float(kline[1]),
            high=float(kline[2]),
            low=float(kline[3]),
            close=float(kline[4]),
            volume=float(kline[5]),
        )
