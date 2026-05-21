from collections.abc import Iterable

from sqlalchemy.orm import Session

from agent.data.models import CryptoBarDTO, MarketDTO, PriceHistory
from agent.store.schema import CryptoBar, Market, PriceSnapshot


def upsert_market(session: Session, dto: MarketDTO) -> Market:
    """Insert the market, or update it in place if it already exists.

    The caller is responsible for committing the session.
    """
    market = session.get(Market, dto.id)
    if market is None:
        market = Market(id=dto.id)
        session.add(market)
    market.question = dto.question
    market.condition_id = dto.condition_id
    market.category = dto.category
    market.active = dto.active
    market.closed = dto.closed
    market.enable_order_book = dto.enable_order_book
    market.order_min_size = dto.order_min_size
    market.order_price_min_tick_size = dto.order_price_min_tick_size
    market.volume_24hr = dto.volume_24hr
    market.liquidity = dto.liquidity
    market.end_date_iso = dto.end_date_iso
    market.clob_token_ids = list(dto.clob_token_ids)
    return market


def save_price_history(
    session: Session, market_id: str, history: PriceHistory
) -> int:
    """Persist new price points, skipping (token_id, ts) pairs already stored.

    Return the count of newly-inserted snapshots. The caller commits.
    """
    existing: set[tuple[str, int]] = {
        (snap.token_id, snap.ts)
        for snap in session.query(PriceSnapshot).filter_by(
            market_id=market_id, token_id=history.token_id
        )
    }
    added = 0
    for point in history.history:
        if (history.token_id, point.t) in existing:
            continue
        session.add(
            PriceSnapshot(
                market_id=market_id,
                token_id=history.token_id,
                ts=point.t,
                price=point.p,
            )
        )
        added += 1
    return added


def save_crypto_bars(
    session: Session, bars: Iterable[CryptoBarDTO]
) -> int:
    """Persist new bars; skip (symbol, granularity, ts) tuples already stored.

    Returns the count of newly-inserted bars.  Caller is responsible for
    committing the session (same convention as save_price_history).
    """
    bars_list = list(bars)
    if not bars_list:
        return 0

    # Query for any existing rows matching the requested symbols+granularities.
    existing: set[tuple[str, str, int]] = {
        (row.symbol, row.granularity, row.ts)
        for row in session.query(CryptoBar)
        .filter(
            CryptoBar.symbol.in_({b.symbol for b in bars_list}),
            CryptoBar.granularity.in_({b.granularity for b in bars_list}),
        )
        .all()
    }

    added = 0
    for b in bars_list:
        if (b.symbol, b.granularity, b.ts) in existing:
            continue
        session.add(CryptoBar(
            symbol=b.symbol,
            granularity=b.granularity,
            ts=b.ts,
            open=b.open,
            high=b.high,
            low=b.low,
            close=b.close,
            volume=b.volume,
        ))
        added += 1
    return added
