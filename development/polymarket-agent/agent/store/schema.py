from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
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
