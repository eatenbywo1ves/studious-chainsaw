"""Tests for agent.data.polymarket_enumerate.

Verifies:
- Pagination via offset-based paging (raw page length drives continuation).
- Crypto-category filter (coarse: "crypto" in category.lower()).
- Window filter (resolution DATE inclusive on both ends).
- Markets with null / missing end_date_iso are excluded.
- No outcome filtering — all resolved crypto markets in-window are kept.
"""

import json

import httpx
import respx

from agent.config import Settings
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.data.polymarket_enumerate import enumerate_resolved_crypto_markets, _PAGE_SIZE

_GAMMA_URL = "https://gamma-api.polymarket.com/markets"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=1000, refill_per_second=1000),
    )


def _market(
    *,
    id: str,
    category: str | None = "crypto",
    end_date: str | None = "2026-06-15T00:00:00Z",
    closed: bool = True,
) -> dict:
    """Build a minimal raw Gamma market dict."""
    return {
        "id": id,
        "question": f"Market {id}?",
        "category": category,
        "closed": closed,
        "endDate": end_date,  # from_gamma falls back to endDate when endDateIso is absent
        "clobTokenIds": json.dumps([f"tok-{id}-yes", f"tok-{id}-no"]),
        "outcomePrices": json.dumps(["1", "0"]),
    }


# ---------------------------------------------------------------------------
# Primary test: pagination + all filter cases
# ---------------------------------------------------------------------------

@respx.mock
async def test_enumerate_filters_resolved_crypto_and_paginates():
    """
    Two-page scenario.

    Page 1  — exactly _PAGE_SIZE items (triggers a second fetch):
      • (_PAGE_SIZE - 3) crypto markets resolving in-window  → all KEPT
      • 1 non-crypto market (Sports) in-window               → DROPPED
      • 1 crypto market resolving AFTER window_end           → DROPPED
      • 1 crypto market with null end_date                   → DROPPED

    Page 2  — short page (signals last page):
      • 1 crypto market resolving in-window                  → KEPT
      • 1 crypto market resolving BEFORE window_start        → DROPPED
      • 1 non-crypto market in-window                        → DROPPED
    """
    window_start = "2026-06-01T00:00:00Z"
    window_end   = "2026-06-30T00:00:00Z"

    # --- build page 1 (_PAGE_SIZE items) ---
    in_window_p1_ids = [f"p1-crypto-{i}" for i in range(_PAGE_SIZE - 3)]
    page1 = [
        _market(id=mid, category="crypto", end_date="2026-06-15T00:00:00Z")
        for mid in in_window_p1_ids
    ]
    # Non-crypto in-window → dropped
    page1.append(_market(id="p1-sports-drop", category="Sports", end_date="2026-06-15T00:00:00Z"))
    # Crypto out-of-window (after end) → dropped
    page1.append(_market(id="p1-crypto-late", category="crypto", end_date="2026-07-05T00:00:00Z"))
    # Crypto null end_date → dropped
    page1.append(_market(id="p1-crypto-null", category="crypto", end_date=None))
    assert len(page1) == _PAGE_SIZE, f"Page 1 must be exactly {_PAGE_SIZE} items"

    # --- build page 2 (short page) ---
    # One KEPT item on page 2 proves pagination is actually executed
    page2 = [
        _market(id="p2-crypto-kept", category="crypto", end_date="2026-06-30T00:00:00Z"),
        # Crypto before window_start → dropped (boundary: day before)
        _market(id="p2-crypto-early", category="crypto", end_date="2026-05-31T23:59:59Z"),
        # Non-crypto in-window → dropped
        _market(id="p2-politics-drop", category="Politics", end_date="2026-06-10T00:00:00Z"),
    ]
    assert len(page2) < _PAGE_SIZE

    route = respx.get(_GAMMA_URL).mock(
        side_effect=[
            httpx.Response(200, json=page1),
            httpx.Response(200, json=page2),
        ]
    )

    async with httpx.AsyncClient() as http:
        result = await enumerate_resolved_crypto_markets(
            _client(http),
            window_start_iso=window_start,
            window_end_iso=window_end,
        )

    # Pagination: both pages must have been fetched
    assert route.call_count == 2, "Expected exactly 2 GET /markets calls"

    # Collect returned ids
    returned_ids = {m.id for m in result}

    # All in-window crypto from page 1 are kept
    for mid in in_window_p1_ids:
        assert mid in returned_ids, f"{mid} should be kept"

    # The one kept market from page 2 is present
    assert "p2-crypto-kept" in returned_ids

    # Dropped markets are absent
    for dropped in (
        "p1-sports-drop",
        "p1-crypto-late",
        "p1-crypto-null",
        "p2-crypto-early",
        "p2-politics-drop",
    ):
        assert dropped not in returned_ids, f"{dropped} should be dropped"

    # Total count
    expected_count = len(in_window_p1_ids) + 1  # +1 for p2-crypto-kept
    assert len(result) == expected_count


# ---------------------------------------------------------------------------
# Secondary test: single page — no second fetch
# ---------------------------------------------------------------------------

@respx.mock
async def test_single_page_no_pagination():
    """When the first page is shorter than _PAGE_SIZE, no second call is made."""
    window_start = "2026-01-01T00:00:00Z"
    window_end   = "2026-12-31T00:00:00Z"

    page1 = [
        _market(id="s1", category="Crypto Markets", end_date="2026-03-01T00:00:00Z"),
        _market(id="s2", category="crypto",         end_date="2026-09-15T12:00:00Z"),
        _market(id="s3", category="Equities",       end_date="2026-06-01T00:00:00Z"),  # dropped
    ]
    assert len(page1) < _PAGE_SIZE

    route = respx.get(_GAMMA_URL).mock(
        return_value=httpx.Response(200, json=page1)
    )

    async with httpx.AsyncClient() as http:
        result = await enumerate_resolved_crypto_markets(
            _client(http),
            window_start_iso=window_start,
            window_end_iso=window_end,
        )

    assert route.call_count == 1, "Only one GET /markets call expected"
    assert {m.id for m in result} == {"s1", "s2"}
    assert len(result) == 2


# ---------------------------------------------------------------------------
# Boundary test: inclusive window edges
# ---------------------------------------------------------------------------

@respx.mock
async def test_window_boundaries_are_inclusive():
    """Markets on exactly window_start and window_end dates are included."""
    window_start = "2026-06-01T00:00:00Z"
    window_end   = "2026-06-30T00:00:00Z"

    page1 = [
        _market(id="on-start",      category="crypto", end_date="2026-06-01T00:00:00Z"),
        _market(id="on-end",        category="crypto", end_date="2026-06-30T23:59:59Z"),
        _market(id="before-start",  category="crypto", end_date="2026-05-31T23:59:59Z"),
        _market(id="after-end",     category="crypto", end_date="2026-07-01T00:00:00Z"),
    ]

    respx.get(_GAMMA_URL).mock(return_value=httpx.Response(200, json=page1))

    async with httpx.AsyncClient() as http:
        result = await enumerate_resolved_crypto_markets(
            _client(http),
            window_start_iso=window_start,
            window_end_iso=window_end,
        )

    ids = {m.id for m in result}
    assert "on-start" in ids
    assert "on-end" in ids
    assert "before-start" not in ids
    assert "after-end" not in ids
