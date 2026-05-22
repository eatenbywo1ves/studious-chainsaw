"""Ingest a resolved market's YES-token price history from the CLOB API."""

from collections.abc import Callable

from sqlalchemy.orm import Session

from agent.data.models import MarketDTO
from agent.data.polymarket_client import PolymarketClient


async def ingest_market_price_history(
    client: PolymarketClient,
    repository_save: Callable,
    session: Session,
    market: MarketDTO,
) -> int:
    """Fetch the YES-token price history from CLOB /prices-history and persist
    as PriceSnapshot rows.  Returns count inserted.  Idempotent (skip-existing
    by (market_id, token_id, ts))."""
    if not market.clob_token_ids:
        return 0

    yes_token_id = market.clob_token_ids[0]
    history = await client.get_price_history(yes_token_id)
    inserted = repository_save(session, market.id, history)
    session.commit()
    return inserted
