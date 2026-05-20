"""Resolution poller for Phase 1A paper-trade-live.

Periodically polls Polymarket's Gamma API per market.  Yields PriceTick events
between polls while a market is open; yields a single ResolvedOutcome when the
market flips to closed=True with a definitive outcome (outcomePrices = [1,0]
or [0,1]).  Once all tracked markets have resolved, the generator finishes.
"""

import asyncio
import time
from collections.abc import AsyncIterator

from agent.data.models import MarketDTO
from agent.data.polymarket_client import PolymarketClient
from agent.validation.types import PriceTick, ResolvedOutcome


class ResolutionPoller:
    """Async polling loop over a fixed set of market_ids."""

    def __init__(
        self,
        client: PolymarketClient,
        poll_interval_seconds: float = 60.0,
    ) -> None:
        self._client = client
        self._interval = poll_interval_seconds

    async def stream_events(
        self,
        market_ids: list[str],
    ) -> AsyncIterator[PriceTick | ResolvedOutcome]:
        """Yield PriceTick and ResolvedOutcome events until all markets resolve."""
        remaining: set[str] = set(market_ids)
        while remaining:
            for mid in list(remaining):
                market = await self._client.get_market(mid)
                if market is None:
                    remaining.discard(mid)
                    continue

                now_ts = int(time.time())

                if market.closed:
                    outcome = _parse_definitive_outcome(market)
                    if outcome is not None:
                        yield ResolvedOutcome(
                            market_id=mid, outcome=outcome, resolved_ts=now_ts
                        )
                        remaining.discard(mid)
                    # Else: closed but indeterminate — keep polling
                else:
                    yes_price = _yes_token_price(market)
                    if yes_price is not None:
                        yield PriceTick(
                            market_id=mid, ts=now_ts, market_price=yes_price
                        )

            if remaining:
                await asyncio.sleep(self._interval)


def _yes_token_price(market: MarketDTO) -> float | None:
    """Convention: outcome_prices[0] is the YES price."""
    if not market.outcome_prices:
        return None
    return market.outcome_prices[0]


def _parse_definitive_outcome(market: MarketDTO) -> int | None:
    """Outcome is 1 (YES) if outcome_prices == [1, 0]; 0 (NO) if [0, 1]; else None."""
    op = market.outcome_prices
    if op == [1.0, 0.0]:
        return 1
    if op == [0.0, 1.0]:
        return 0
    return None
