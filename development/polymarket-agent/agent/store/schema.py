from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
)


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Market(Base):
    """A Polymarket market and its trading constraints."""

    __tablename__ = "markets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    question: Mapped[str] = mapped_column(String, default="")
    condition_id: Mapped[str | None] = mapped_column(String, nullable=True)
    category: Mapped[str | None] = mapped_column(String, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=False)
    closed: Mapped[bool] = mapped_column(Boolean, default=False)
    enable_order_book: Mapped[bool] = mapped_column(Boolean, default=False)
    order_min_size: Mapped[float | None] = mapped_column(Float, nullable=True)
    order_price_min_tick_size: Mapped[float | None] = mapped_column(
        Float, nullable=True
    )
    volume_24hr: Mapped[float | None] = mapped_column(Float, nullable=True)
    liquidity: Mapped[float | None] = mapped_column(Float, nullable=True)
    end_date_iso: Mapped[str | None] = mapped_column(String, nullable=True)
    clob_token_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )

    snapshots: Mapped[list["PriceSnapshot"]] = relationship(
        back_populates="market", cascade="all, delete-orphan"
    )


class PriceSnapshot(Base):
    """One historical price observation for one CLOB token of a market."""

    __tablename__ = "price_snapshots"
    __table_args__ = (
        UniqueConstraint("market_id", "token_id", "ts", name="uq_snapshot"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    market_id: Mapped[str] = mapped_column(ForeignKey("markets.id"))
    token_id: Mapped[str] = mapped_column(String)
    ts: Mapped[int] = mapped_column(Integer)
    price: Mapped[float] = mapped_column(Float)

    market: Mapped["Market"] = relationship(back_populates="snapshots")


class CryptoBar(Base):
    """One OHLCV bar for a crypto symbol at a given granularity.

    `symbol` follows Binance convention ("BTCUSDT", "ETHUSDT").
    `granularity` is one of "1h", "1d" in Phase 1B-C1 (extensible later).
    `ts` is the bar's open time in Unix seconds (UTC).
    """

    __tablename__ = "crypto_bars"
    __table_args__ = (
        UniqueConstraint(
            "symbol", "granularity", "ts", name="uq_crypto_bar"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    symbol: Mapped[str] = mapped_column(String, index=True)
    granularity: Mapped[str] = mapped_column(String)  # "1h" | "1d"
    ts: Mapped[int] = mapped_column(Integer)
    open: Mapped[float] = mapped_column(Float)
    high: Mapped[float] = mapped_column(Float)
    low: Mapped[float] = mapped_column(Float)
    close: Mapped[float] = mapped_column(Float)
    volume: Mapped[float] = mapped_column(Float)


class ModePerformance(Base):
    """One Brier observation per (mode, closed-trade). Append-only.
    Queried by PerformanceTracker for trailing-window averages.
    """

    __tablename__ = "mode_performance"
    __table_args__ = (
        Index("ix_mode_performance_mode_closed", "mode_name", "closed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode_name: Mapped[str] = mapped_column(String(32), index=True)
    market_id: Mapped[str] = mapped_column(String, index=True)
    p_mode: Mapped[float] = mapped_column(Float)
    p_market_at_prediction: Mapped[float] = mapped_column(Float)
    outcome: Mapped[int] = mapped_column(Integer)
    brier_score: Mapped[float] = mapped_column(Float)
    closed_at: Mapped[int] = mapped_column(Integer)


class TradeRecord(Base):
    """Append-only diagnostic record of every position taken by crypto_model."""

    __tablename__ = "trade_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    market_id: Mapped[str] = mapped_column(String, index=True)
    ts: Mapped[int] = mapped_column(Integer, index=True)
    p_market: Mapped[float] = mapped_column(Float)
    p_bridge: Mapped[float] = mapped_column(Float)
    p_mode1: Mapped[float] = mapped_column(Float)
    p_mode2: Mapped[float] = mapped_column(Float)
    p_mode3: Mapped[float] = mapped_column(Float)
    p_mode4: Mapped[float] = mapped_column(Float)
    p_blend: Mapped[float] = mapped_column(Float)
    p_final: Mapped[float] = mapped_column(Float)
    agreement_vetoed: Mapped[bool] = mapped_column(Boolean)
    kelly_fraction: Mapped[float] = mapped_column(Float)
    position_size: Mapped[float] = mapped_column(Float)
    shock_active: Mapped[bool] = mapped_column(Boolean)
    shock_severity: Mapped[float | None] = mapped_column(Float, nullable=True)
    mode_weights_json: Mapped[str] = mapped_column(Text)


class ModeFloorState(Base):
    """Per-mode state for the Brier floor and disable streak.  One row per
    mode (binary/exp/magnitude/confidence).  Mutable — updated on every
    closed-trade outcome.
    """

    __tablename__ = "mode_floor_state"

    mode_name: Mapped[str] = mapped_column(String(32), primary_key=True)
    brier_floor: Mapped[float] = mapped_column(Float, default=0.10)
    disable_streak: Mapped[int] = mapped_column(Integer, default=0)
    is_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[int] = mapped_column(Integer)
