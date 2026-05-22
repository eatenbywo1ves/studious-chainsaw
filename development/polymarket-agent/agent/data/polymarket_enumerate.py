"""Exhaustive population enumeration for resolved Polymarket crypto markets.

This module provides :func:`enumerate_resolved_crypto_markets`, which pages
through the Gamma API and returns every resolved market in the crypto category
whose resolution date falls within a caller-supplied window.

Design notes
------------
* Filtering is done client-side — the Gamma API does not support server-side
  category or date filtering.
* Pagination termination is based on the *raw* page length returned by the
  client, not the filtered length.  A page of 500 non-crypto markets is still
  a full page and must not halt pagination early.
* No outcome filtering is applied — both YES and NO resolved markets are part
  of the exhaustive population.  Downstream components (question parser, LLM)
  are responsible for further classification.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from agent.data.models import MarketDTO
from agent.data.polymarket_client import PolymarketClient

#: Number of markets requested per Gamma API call.
_PAGE_SIZE: int = 500


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _parse_iso_date(iso: str) -> date | None:
    """Parse an ISO-8601 datetime string to a :class:`date`, or return None.

    Handles trailing ``Z`` (UTC) by replacing it with ``+00:00`` before
    passing to :func:`datetime.fromisoformat`.  Returns ``None`` on any
    parse failure so callers can treat unparseable dates as "exclude".
    """
    if not iso:
        return None
    try:
        normalised = iso.replace("Z", "+00:00")
        return datetime.fromisoformat(normalised).date()
    except (ValueError, AttributeError):
        return None


def _resolution_in_window(
    end_date_iso: str | None,
    start_iso: str,
    end_iso: str,
) -> bool:
    """Return True iff ``end_date_iso`` resolves to a date within
    ``[start_iso, end_iso]`` inclusive (date-precision comparison).

    Markets whose ``end_date_iso`` is ``None`` or unparseable are excluded.
    """
    if end_date_iso is None:
        return False
    resolution = _parse_iso_date(end_date_iso)
    if resolution is None:
        return False
    window_start = _parse_iso_date(start_iso)
    window_end = _parse_iso_date(end_iso)
    if window_start is None or window_end is None:
        return False
    return window_start <= resolution <= window_end


def _is_crypto(market: MarketDTO) -> bool:
    """Coarse crypto-category check: category must contain 'crypto' (case-insensitive)."""
    return market.category is not None and "crypto" in market.category.lower()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def enumerate_resolved_crypto_markets(
    client: PolymarketClient,
    *,
    window_start_iso: str,
    window_end_iso: str,
) -> list[MarketDTO]:
    """List every resolved market in the crypto category whose resolution
    falls in [window_start, window_end].  closed=true, no outcome filtering
    (this is the exhaustive population).  Pagination handled internally.

    Parameters
    ----------
    client:
        An initialised :class:`~agent.data.polymarket_client.PolymarketClient`.
    window_start_iso:
        ISO-8601 datetime string for the inclusive start of the resolution window.
    window_end_iso:
        ISO-8601 datetime string for the inclusive end of the resolution window.

    Returns
    -------
    list[MarketDTO]
        All resolved crypto markets whose resolution date is within the window.
    """
    results: list[MarketDTO] = []
    offset = 0

    while True:
        page = await client.get_markets(
            limit=_PAGE_SIZE,
            offset=offset,
            active=False,
            closed=True,
        )

        # Empty page guard — stop even if page length never equalled _PAGE_SIZE.
        if not page:
            break

        for market in page:
            if _is_crypto(market) and _resolution_in_window(
                market.end_date_iso, window_start_iso, window_end_iso
            ):
                results.append(market)

        # Termination: raw page length (not filtered length) drives continuation.
        if len(page) < _PAGE_SIZE:
            break

        offset += _PAGE_SIZE

    return results
