# Polymarket Agent — Phase 1B-C1: Crypto Foundation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the building blocks for the crypto-category L3 module — persistent OHLCV ingestion via Binance public API, GARCH(1,1) vol estimator via the `arch` package, and a closed-form one-touch barrier-hit probability calculator — so Phase 1B-C2 can compose them into a Polymarket-consuming fair-value model.

**Architecture:** Three independent primitives with narrow interfaces. Data path (`BinanceClient` → `CryptoIngestService` → `save_crypto_bars` → `CryptoBar` ORM) mirrors Phase 0's `PolymarketClient` → `IngestService` → `save_price_history` → `PriceSnapshot` exactly. Math path (`fit_garch11` → `GARCHResult` → `prob_barrier_hit`) is pure-functional, takes returns/parameters in, produces a probability out. No coupling to Phase 1A's L7 framework yet — that integration happens in C2.

**Bug-defense priorities baked in (see spec §6 discussion):** (a) `prob_barrier_hit` gets 5 hand-computed reference cases + 3 monotonicity tests because the closed-form formula has many places to silently mess up; (b) `GARCHResult` annualizes `current_conditional_vol` at construction so period-vol is structurally inaccessible to consumers — prevents the "forgot to annualize" class of unit-confusion bugs; (c) `annualized_drift` parameter named explicitly to match `annualized_vol` and reduce caller-side unit ambiguity.

**Tech Stack:** Python 3.13, `httpx` (Phase 0), `pydantic` v2 (Phase 0), `SQLAlchemy` 2.0 (Phase 0), `pytest`/`pytest-asyncio`/`respx` (Phase 0), **new: `arch>=7.0`** (GARCH MLE), **new: `pandas>=2.0`** (transitive via arch).

**Plan context:** This is **Plan 3 of 5+**. It corresponds to Phase 1B-C1 of the parent design and is detailed in `docs/superpowers/specs/2026-05-21-polymarket-phase-1b-c1-crypto-foundation-design.md`. Its completion gate is verified by Tasks 4, 5, 6, 7, 8, 9. C2 (the composite crypto_model + shock detector + news) is the next plan.

---

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | Add `arch>=7.0` and `pandas>=2.0` to core dependencies |
| `agent/data/models.py` | EXTEND with `CryptoBarDTO` + `from_binance_kline` classmethod |
| `agent/data/crypto_client.py` | NEW: `BinanceClient` — async client for `/api/v3/klines` |
| `agent/data/crypto_ingest.py` | NEW: `CryptoIngestService` — pagination + dedup orchestration |
| `agent/store/schema.py` | EXTEND with `CryptoBar` ORM model |
| `agent/store/repository.py` | EXTEND with `save_crypto_bars` |
| `agent/research/crypto/__init__.py` | NEW empty package marker |
| `agent/research/crypto/barrier_bridge.py` | NEW: `prob_barrier_hit` — closed-form one-touch via reflection principle |
| `agent/research/crypto/vol_estimator.py` | NEW: `GARCHResult` dataclass + `fit_garch11` + `forecast_garch_annualized_vol` |
| `tests/data/test_models.py` | EXTEND with CryptoBarDTO parsing tests |
| `tests/store/test_schema.py` | EXTEND with CryptoBar round-trip + uniqueness tests |
| `tests/store/test_repository.py` | EXTEND with save_crypto_bars idempotency test |
| `tests/data/test_crypto_client.py` | NEW respx-mocked client tests |
| `tests/data/test_crypto_ingest.py` | NEW pagination + idempotency integration tests |
| `tests/research/crypto/__init__.py` | NEW empty package marker |
| `tests/research/crypto/test_barrier_bridge.py` | NEW: 5 reference cases + 3 monotonicity tests + edge cases |
| `tests/research/crypto/test_vol_estimator.py` | NEW: parameter recovery + annualization structural test + forecast recursion |

---

### Task 1: Add Dependencies + CryptoBarDTO

**Files:**
- Modify: `pyproject.toml`
- Modify: `agent/data/models.py`
- Modify: `tests/data/test_models.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/data/test_models.py`:

```python
from agent.data.models import CryptoBarDTO


def test_crypto_bar_from_binance_kline_canonical():
    """Binance returns each kline as a 12-element array; we use indices 0-5."""
    kline = [
        1700000000000,        # open time ms
        "60000.00",            # open
        "60500.00",            # high
        "59800.00",            # low
        "60200.00",            # close
        "1234.5678",           # volume
        1700003599999,         # close time ms (ignored)
        "74321000.50",         # quote volume (ignored)
        1500,                  # trades count (ignored)
        "615.1234",            # taker buy base (ignored)
        "37050000.25",         # taker buy quote (ignored)
        "0",                   # ignore field
    ]
    dto = CryptoBarDTO.from_binance_kline(kline, symbol="BTCUSDT", granularity="1h")

    assert dto.symbol == "BTCUSDT"
    assert dto.granularity == "1h"
    assert dto.ts == 1700000000  # ms / 1000
    assert dto.open == 60000.00
    assert dto.high == 60500.00
    assert dto.low == 59800.00
    assert dto.close == 60200.00
    assert dto.volume == 1234.5678


def test_crypto_bar_handles_daily_granularity():
    """Granularity is a Literal['1h', '1d']."""
    kline = [
        1700000000000, "60000", "61000", "59000", "60500", "100",
        0, "0", 0, "0", "0", "0",
    ]
    dto = CryptoBarDTO.from_binance_kline(kline, symbol="ETHUSDT", granularity="1d")
    assert dto.granularity == "1d"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_models.py -v -k crypto_bar`
Expected: FAIL — `ImportError: cannot import name 'CryptoBarDTO' from 'agent.data.models'`.

- [ ] **Step 3: Add scipy/arch/pandas to pyproject.toml**

In `pyproject.toml` core `dependencies`, find:

```toml
dependencies = [
    "httpx>=0.27",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "scipy>=1.13",
    "sqlalchemy>=2.0",
]
```

Replace with (alphabetical, adding `arch` and `pandas`):

```toml
dependencies = [
    "arch>=7.0",
    "httpx>=0.27",
    "pandas>=2.0",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "scipy>=1.13",
    "sqlalchemy>=2.0",
]
```

From the project dir with venv activated: `pip install -e ".[dev]"`. Expected: scipy/numpy already present; `arch` and `pandas` install in 1-3 minutes (~50 MB combined).

- [ ] **Step 4: Add CryptoBarDTO to `agent/data/models.py`**

Append to the file (after `MarketDTO`):

```python
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
```

Note: `Literal` is already imported in models.py (used by MarketDTO). No new imports needed for this addition.

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/data/test_models.py -v -k crypto_bar`
Expected: PASS — 2 passed.

- [ ] **Step 6: Run full suite**

Run: `pytest -v`
Expected: PASS — 73 passed (71 prior + 2 new).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml agent/data/models.py tests/data/test_models.py
git commit -m "chore(phase1b-c1): add arch/pandas deps and CryptoBarDTO"
```

---

### Task 2: CryptoBar ORM Model + Round-Trip Test

**Files:**
- Modify: `agent/store/schema.py`
- Modify: `tests/store/test_schema.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/store/test_schema.py`:

```python
from agent.store.schema import CryptoBar


def test_crypto_bar_round_trips_through_db(session_factory):
    """CryptoBar persists and reads back across separate sessions."""
    with session_factory() as write_session:
        bar = CryptoBar(
            symbol="BTCUSDT",
            granularity="1h",
            ts=1700000000,
            open=60000.0,
            high=60500.0,
            low=59800.0,
            close=60200.0,
            volume=1234.5,
        )
        write_session.add(bar)
        write_session.commit()

    with session_factory() as read_session:
        loaded = read_session.query(CryptoBar).filter_by(
            symbol="BTCUSDT", granularity="1h", ts=1700000000
        ).first()
        assert loaded is not None
        assert loaded.open == 60000.0
        assert loaded.high == 60500.0
        assert loaded.low == 59800.0
        assert loaded.close == 60200.0
        assert loaded.volume == 1234.5


def test_crypto_bar_unique_constraint_on_symbol_granularity_ts(session):
    """Duplicate (symbol, granularity, ts) raises IntegrityError."""
    from sqlalchemy.exc import IntegrityError

    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1h", ts=1700000000,
        open=1, high=1, low=1, close=1, volume=1,
    ))
    session.commit()

    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1h", ts=1700000000,
        open=2, high=2, low=2, close=2, volume=2,
    ))
    raised = False
    try:
        session.commit()
    except IntegrityError:
        raised = True
        session.rollback()
    assert raised is True


def test_crypto_bar_allows_different_granularities_same_ts(session):
    """Same (symbol, ts) is allowed across different granularities."""
    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1h", ts=1700000000,
        open=1, high=1, low=1, close=1, volume=1,
    ))
    session.add(CryptoBar(
        symbol="BTCUSDT", granularity="1d", ts=1700000000,
        open=1, high=1, low=1, close=1, volume=1,
    ))
    session.commit()  # must not raise

    assert session.query(CryptoBar).count() == 2
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/store/test_schema.py -v -k crypto_bar`
Expected: FAIL — `ImportError: cannot import name 'CryptoBar' from 'agent.store.schema'`.

- [ ] **Step 3: Add CryptoBar to `agent/store/schema.py`**

Append to the file (after `PriceSnapshot`):

```python
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
```

The `String`, `Integer`, `Float`, `UniqueConstraint`, `Mapped`, `mapped_column`, and `Base` imports are already in schema.py from Phase 0. No new imports needed.

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/store/test_schema.py -v -k crypto_bar`
Expected: PASS — 3 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 76 passed (73 prior + 3 new).

- [ ] **Step 6: Commit**

```bash
git add agent/store/schema.py tests/store/test_schema.py
git commit -m "feat(phase1b-c1): add CryptoBar ORM model with (symbol,granularity,ts) uniqueness"
```

---

### Task 3: save_crypto_bars Repository Function

**Files:**
- Modify: `agent/store/repository.py`
- Modify: `tests/store/test_repository.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/store/test_repository.py`:

```python
from agent.data.models import CryptoBarDTO
from agent.store.repository import save_crypto_bars
from agent.store.schema import CryptoBar


def _bar(symbol: str, granularity: str, ts: int, close: float = 100.0) -> CryptoBarDTO:
    return CryptoBarDTO(
        symbol=symbol, granularity=granularity, ts=ts,  # type: ignore[arg-type]
        open=close, high=close, low=close, close=close, volume=1.0,
    )


def test_save_crypto_bars_inserts_new(session):
    """First call inserts all bars, returns count."""
    bars = [
        _bar("BTCUSDT", "1h", 1700000000),
        _bar("BTCUSDT", "1h", 1700003600),
        _bar("BTCUSDT", "1h", 1700007200),
    ]
    added = save_crypto_bars(session, bars)
    session.commit()

    assert added == 3
    assert session.query(CryptoBar).count() == 3


def test_save_crypto_bars_is_idempotent(session):
    """Re-saving same (symbol, granularity, ts) returns 0 added."""
    bars = [_bar("BTCUSDT", "1h", 1700000000)]

    first = save_crypto_bars(session, bars)
    session.commit()
    second = save_crypto_bars(session, bars)
    session.commit()

    assert first == 1
    assert second == 0
    assert session.query(CryptoBar).count() == 1


def test_save_crypto_bars_partial_overlap(session):
    """Mixed new-and-existing bars: only new ones counted."""
    save_crypto_bars(session, [_bar("BTCUSDT", "1h", 1700000000)])
    session.commit()

    added = save_crypto_bars(session, [
        _bar("BTCUSDT", "1h", 1700000000),  # already present
        _bar("BTCUSDT", "1h", 1700003600),  # new
        _bar("BTCUSDT", "1h", 1700007200),  # new
    ])
    session.commit()

    assert added == 2
    assert session.query(CryptoBar).count() == 3
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/store/test_repository.py -v -k crypto_bars`
Expected: FAIL — `ImportError: cannot import name 'save_crypto_bars' from 'agent.store.repository'`.

- [ ] **Step 3: Add save_crypto_bars to `agent/store/repository.py`**

Append to the file:

```python
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

    # Group requested keys by symbol+granularity to minimize the existing-set query
    requested_keys = {(b.symbol, b.granularity, b.ts) for b in bars_list}

    # Query for any existing rows matching the requested keys.  In SQLite for
    # in-memory tests this is fast; for production we trade memory for clarity.
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
```

Add `CryptoBarDTO` to the existing imports at the top of repository.py:

```python
from agent.data.models import MarketDTO, PriceHistory, CryptoBarDTO
```

And `CryptoBar` to the schema import:

```python
from agent.store.schema import Market, PriceSnapshot, CryptoBar
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/store/test_repository.py -v -k crypto_bars`
Expected: PASS — 3 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 79 passed (76 prior + 3 new).

- [ ] **Step 6: Commit**

```bash
git add agent/store/repository.py tests/store/test_repository.py
git commit -m "feat(phase1b-c1): add idempotent save_crypto_bars repository function"
```

---

### Task 4: BinanceClient

**Files:**
- Create: `agent/data/crypto_client.py`
- Create: `tests/data/test_crypto_client.py`

- [ ] **Step 1: Write the failing test**

Create `tests/data/test_crypto_client.py`:

```python
import httpx
import respx

from agent.data.crypto_client import BinanceClient
from agent.data.rate_limiter import TokenBucket


def _client(http: httpx.AsyncClient) -> BinanceClient:
    return BinanceClient(
        http_client=http,
        rate_limit_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


def _kline(open_time_ms: int, close_price: float) -> list:
    return [
        open_time_ms,
        f"{close_price}",       # open
        f"{close_price * 1.01}",  # high
        f"{close_price * 0.99}",  # low
        f"{close_price}",       # close
        "100.0",                # volume
        open_time_ms + 3599999, # close time
        "6000000",              # quote volume
        1500,                   # trades
        "50.0",                 # taker buy base
        "3000000",              # taker buy quote
        "0",                    # ignore
    ]


@respx.mock
async def test_get_klines_parses_three_bars():
    """Happy path: 3-bar response parses into 3 CryptoBarDTO instances."""
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=[
            _kline(1700000000000, 60000.0),
            _kline(1700003600000, 60200.0),
            _kline(1700007200000, 60100.0),
        ])
    )
    async with httpx.AsyncClient() as http:
        bars = await _client(http).get_klines(symbol="BTCUSDT", interval="1h", limit=3)

    assert [b.ts for b in bars] == [1700000000, 1700003600, 1700007200]
    assert bars[0].symbol == "BTCUSDT"
    assert bars[0].granularity == "1h"
    assert bars[0].close == 60000.0
    assert bars[1].close == 60200.0
    assert bars[2].close == 60100.0


@respx.mock
async def test_get_klines_passes_query_params():
    """Symbol, interval, limit, startTime, endTime are passed correctly."""
    route = respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=[])
    )
    async with httpx.AsyncClient() as http:
        await _client(http).get_klines(
            symbol="ETHUSDT", interval="1d",
            start_ts=1700000000, end_ts=1700086400, limit=500,
        )

    params = route.calls.last.request.url.params
    assert params["symbol"] == "ETHUSDT"
    assert params["interval"] == "1d"
    assert params["limit"] == "500"
    # Times converted to ms for Binance
    assert params["startTime"] == "1700000000000"
    assert params["endTime"] == "1700086400000"


@respx.mock
async def test_get_klines_raises_on_429():
    """Rate-limit response (429) propagates as HTTPStatusError."""
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(429, json={"code": -1003, "msg": "Too many requests"})
    )
    async with httpx.AsyncClient() as http:
        try:
            await _client(http).get_klines(symbol="BTCUSDT", interval="1h")
            raised = False
        except httpx.HTTPStatusError:
            raised = True

    assert raised is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_crypto_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.data.crypto_client'`.

- [ ] **Step 3: Write the implementation**

Create `agent/data/crypto_client.py`:

```python
"""Async client for Binance's public klines endpoint.

Same architectural pattern as PolymarketClient: caller owns the
httpx.AsyncClient lifecycle and injects a TokenBucket for rate limiting.
"""

import httpx

from agent.data.models import CryptoBarDTO
from agent.data.rate_limiter import TokenBucket


class BinanceClient:
    """Read-only async client for /api/v3/klines."""

    BASE_URL = "https://api.binance.com"
    KLINES_PATH = "/api/v3/klines"
    MAX_KLINES_PER_REQUEST = 1000

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        rate_limit_bucket: TokenBucket | None = None,
    ) -> None:
        self._http = http_client
        # Binance IP weight limit is 1200/min; klines is 2 weight when limit > 500.
        # 60 capacity / 1 refill-per-second = 60/min sustainable, well under 600.
        self._bucket = rate_limit_bucket or TokenBucket(
            capacity=60, refill_per_second=1.0
        )

    async def get_klines(
        self,
        symbol: str,
        interval: str,
        *,
        start_ts: int | None = None,
        end_ts: int | None = None,
        limit: int = 1000,
    ) -> list[CryptoBarDTO]:
        """Fetch up to `limit` klines.  Times converted to ms internally
        for the Binance API.  Returns bars in ascending-ts order.

        `interval` examples: "1h", "1d".  `start_ts`/`end_ts` are unix seconds.
        """
        await self._bucket.acquire()
        params: dict[str, object] = {
            "symbol": symbol,
            "interval": interval,
            "limit": min(limit, self.MAX_KLINES_PER_REQUEST),
        }
        if start_ts is not None:
            params["startTime"] = start_ts * 1000  # seconds -> ms
        if end_ts is not None:
            params["endTime"] = end_ts * 1000
        resp = await self._http.get(
            f"{self.BASE_URL}{self.KLINES_PATH}", params=params
        )
        resp.raise_for_status()
        return [
            CryptoBarDTO.from_binance_kline(kline, symbol=symbol, granularity=interval)
            for kline in resp.json()
        ]
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/data/test_crypto_client.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 82 passed (79 prior + 3 new).

- [ ] **Step 6: Commit**

```bash
git add agent/data/crypto_client.py tests/data/test_crypto_client.py
git commit -m "feat(phase1b-c1): add async BinanceClient for klines endpoint"
```

---

### Task 5: CryptoIngestService

**Files:**
- Create: `agent/data/crypto_ingest.py`
- Create: `tests/data/test_crypto_ingest.py`

- [ ] **Step 1: Write the failing test**

Create `tests/data/test_crypto_ingest.py`:

```python
import httpx
import respx

from agent.data.crypto_client import BinanceClient
from agent.data.crypto_ingest import CryptoIngestService
from agent.data.rate_limiter import TokenBucket
from agent.store.schema import CryptoBar


def _client(http: httpx.AsyncClient) -> BinanceClient:
    return BinanceClient(
        http_client=http,
        rate_limit_bucket=TokenBucket(capacity=1000, refill_per_second=1000),
    )


def _kline(open_time_ms: int) -> list:
    return [
        open_time_ms, "60000", "60100", "59900", "60050", "100",
        open_time_ms + 3599999, "6000000", 1500, "50", "3000000", "0",
    ]


@respx.mock
async def test_ingest_history_single_request(session_factory, session):
    """Range fits in one request: ~100 bars, one mocked response."""
    bars_payload = [_kline(1700000000000 + i * 3600000) for i in range(100)]
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=bars_payload)
    )
    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        count = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000, end_ts=1700000000 + 100 * 3600,
        )

    assert count == 100
    assert session.query(CryptoBar).filter_by(
        symbol="BTCUSDT", granularity="1h"
    ).count() == 100


@respx.mock
async def test_ingest_history_paginates_over_two_requests(session_factory, session):
    """Range spans two requests: 1000 + 500 bars across two paginated calls."""
    # First batch: 1000 bars
    first_batch = [_kline(1700000000000 + i * 3600000) for i in range(1000)]
    # Second batch: 500 bars starting after the first
    second_batch = [_kline(1700000000000 + (1000 + i) * 3600000) for i in range(500)]

    respx.get("https://api.binance.com/api/v3/klines").mock(
        side_effect=[
            httpx.Response(200, json=first_batch),
            httpx.Response(200, json=second_batch),
        ]
    )

    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        count = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000,
            end_ts=1700000000 + 1500 * 3600,
        )

    assert count == 1500
    assert session.query(CryptoBar).filter_by(
        symbol="BTCUSDT", granularity="1h"
    ).count() == 1500


@respx.mock
async def test_ingest_history_is_idempotent(session_factory, session):
    """Second call with same range returns 0 added; row count unchanged."""
    bars_payload = [_kline(1700000000000 + i * 3600000) for i in range(50)]
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=bars_payload)
    )

    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        first = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000, end_ts=1700000000 + 50 * 3600,
        )
        second = await service.ingest_history(
            symbol="BTCUSDT", granularity="1h",
            start_ts=1700000000, end_ts=1700000000 + 50 * 3600,
        )

    assert first == 50
    assert second == 0
    assert session.query(CryptoBar).count() == 50


@respx.mock
async def test_ingest_latest(session_factory, session):
    """ingest_latest fetches recent bars without an explicit range."""
    bars_payload = [_kline(1700000000000 + i * 3600000) for i in range(10)]
    respx.get("https://api.binance.com/api/v3/klines").mock(
        return_value=httpx.Response(200, json=bars_payload)
    )
    async with httpx.AsyncClient() as http:
        service = CryptoIngestService(_client(http), session_factory)
        count = await service.ingest_latest(symbol="BTCUSDT", granularity="1h")

    assert count == 10
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_crypto_ingest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.data.crypto_ingest'`.

- [ ] **Step 3: Write the implementation**

Create `agent/data/crypto_ingest.py`:

```python
"""Backfill historical klines and incrementally append latest bars."""

from sqlalchemy.orm import Session, sessionmaker

from agent.data.crypto_client import BinanceClient
from agent.store.repository import save_crypto_bars


# Approximate seconds per bar by granularity.  Used to estimate "how many
# bars would the requested range hold" for pagination sizing.
_SECONDS_PER_BAR = {
    "1h": 3600,
    "1d": 86400,
}


class CryptoIngestService:
    """Fetches klines from Binance and persists them to the local store."""

    def __init__(
        self,
        client: BinanceClient,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._client = client
        self._session_factory = session_factory

    async def ingest_history(
        self,
        symbol: str,
        granularity: str,
        start_ts: int,
        end_ts: int,
    ) -> int:
        """Paginate through Binance klines from start_ts to end_ts.

        Returns the count of newly-inserted bars (already-present bars
        skipped silently via save_crypto_bars).
        """
        seconds_per_bar = _SECONDS_PER_BAR[granularity]
        current_start = start_ts
        total_added = 0

        while current_start < end_ts:
            bars = await self._client.get_klines(
                symbol=symbol,
                interval=granularity,
                start_ts=current_start,
                end_ts=end_ts,
                limit=self._client.MAX_KLINES_PER_REQUEST,
            )
            if not bars:
                break

            with self._session_factory() as session:
                total_added += save_crypto_bars(session, bars)
                session.commit()

            # Advance start to one bar after the last received bar
            last_bar_ts = bars[-1].ts
            current_start = last_bar_ts + seconds_per_bar

            # If the page wasn't full, we've exhausted the range
            if len(bars) < self._client.MAX_KLINES_PER_REQUEST:
                break

        return total_added

    async def ingest_latest(
        self,
        symbol: str,
        granularity: str,
        limit: int = 100,
    ) -> int:
        """Fetch the most-recent `limit` bars (no time bounds) and upsert.

        Returns the count of newly-inserted bars.
        """
        bars = await self._client.get_klines(
            symbol=symbol, interval=granularity, limit=limit
        )
        with self._session_factory() as session:
            added = save_crypto_bars(session, bars)
            session.commit()
        return added
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/data/test_crypto_ingest.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 86 passed (82 prior + 4 new).

- [ ] **Step 6: Commit**

```bash
git add agent/data/crypto_ingest.py tests/data/test_crypto_ingest.py
git commit -m "feat(phase1b-c1): add CryptoIngestService with pagination + idempotency"
```

---

### Task 6: barrier_bridge.prob_barrier_hit — THE MATH GATE

**Files:**
- Create: `agent/research/crypto/__init__.py` (empty)
- Create: `agent/research/crypto/barrier_bridge.py`
- Create: `tests/research/crypto/__init__.py` (empty)
- Create: `tests/research/crypto/test_barrier_bridge.py`

This task delivers the closed-form one-touch barrier-hit calculator. It is the most bug-prone component in C1 — the closed-form formula has at least 8 independent places to silently produce wrong outputs. The tests below are intentionally extensive: 5 hand-computed reference cases (each targeting a different class of bug) plus 3 monotonicity tests plus 2 edge-case tests.

- [ ] **Step 1: Write the failing tests**

Create `tests/research/crypto/__init__.py` (empty).

Create `tests/research/crypto/test_barrier_bridge.py`:

```python
import math

import pytest

from agent.research.crypto.barrier_bridge import prob_barrier_hit


# === Reference cases (§5.1 of the spec) =====================================

def test_prob_barrier_hit_already_touching():
    """§5.1 Case 1: spot == barrier → returns 1.0 (already touching)."""
    p = prob_barrier_hit(
        spot=100.0, barrier=100.0,
        time_remaining_years=1.0, annualized_vol=0.3,
    )
    assert p == 1.0


def test_prob_barrier_hit_zero_time_up_barrier():
    """§5.1 Case 2: T=0 with barrier above spot → returns 0.0."""
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=0.0, annualized_vol=0.3,
    )
    assert p == 0.0


def test_prob_barrier_hit_zero_time_down_barrier():
    """§5.1 Case 3: T=0 with barrier below spot → returns 0.0."""
    p = prob_barrier_hit(
        spot=100.0, barrier=90.0,
        time_remaining_years=0.0, annualized_vol=0.3,
    )
    assert p == 0.0


def test_prob_barrier_hit_long_horizon_negative_log_drift():
    """§5.1 Case 4: T=1000, μ=0, σ=0.3 → ν = μ − σ²/2 = −0.045 < 0 → P → S₀/B.

    With annualized_drift=0 (physical μ=0), the LOG-drift is ν = μ − σ²/2 = −σ²/2,
    which is NEGATIVE.  The log-process drifts AWAY from an up-barrier.
    By Doob's optional-stopping on the exponential martingale exp(-2νX_t/σ²),
    the asymptotic up-barrier hit probability is:

        P(τ < ∞) = S₀ / B   (when ν < 0 and b > 0)

    For S₀=100, B=110: P → 100/110 ≈ 0.9091.

    THIS TEST CATCHES THE MISSING exp(2νb/σ²) PREFACTOR BUG.  Without that
    prefactor, the formula at T=1000 collapses to ≈ 0 (a single N(·) term
    deep in the left tail with argument ≈ -4.755).  WITH the prefactor, the
    formula gives ≈ 0.9091.  So "result ≈ 0 vs ≈ 0.909" is the discriminator.

    (Note: pure recurrence — P → 1 in the limit — requires ν = 0, which means
    drift = σ²/2.  That scenario is covered by Test 5.)
    """
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=1000.0, annualized_vol=0.3,
        annualized_drift=0.0,
    )
    # Martingale identity: P → S₀/B in the negative-log-drift limit.
    expected = 100.0 / 110.0
    assert math.isclose(p, expected, abs_tol=1e-3), (
        f"Negative-log-drift limit test failed: P={p} should be ≈{expected:.4f} "
        f"(= S₀/B).  Did you forget the exp(2νb/σ²) prefactor?  "
        f"Without it, this would give ≈ 0."
    )


def test_prob_barrier_hit_log_drift_zero_up_barrier():
    """§5.1 Case 5: drift = σ²/2 → log-drift ν = 0 → formula reduces to 2·N(-b/v).

    Hand-computation:
      ν = 0.045 - 0.3²/2 = 0
      b = ln(110/100) = ln(1.1) ≈ 0.0953102
      v = 0.3 · √1 = 0.3
      Term1 = N((0 - b)/v) = N(-0.3177)
      Term2 = exp(0) · N((-0 - b)/v) = N(-0.3177)
      P = 2 · N(-0.3177) ≈ 2 · 0.37533 ≈ 0.75066

    This case verifies (a) the sign convention on ν, (b) the algebraic
    reduction when log-drift is zero, and (c) that the exp prefactor
    correctly evaluates to 1.0 here.
    """
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=1.0, annualized_vol=0.3,
        annualized_drift=0.045,  # exactly σ²/2 = 0.09/2
    )
    expected = 2 * 0.5 * (1 + math.erf(-math.log(1.1) / 0.3 / math.sqrt(2)))
    assert math.isclose(p, expected, abs_tol=1e-9)
    # Sanity: also close to the pre-computed approximate value
    assert math.isclose(p, 0.7506, abs_tol=1e-3)


# === Monotonicity sanity tests ===============================================

def test_prob_barrier_hit_increases_with_time():
    """Longer horizon → higher P(touch), holding other things equal."""
    args = dict(spot=100.0, barrier=110.0, annualized_vol=0.3, annualized_drift=0.0)
    p_short = prob_barrier_hit(time_remaining_years=0.25, **args)
    p_med   = prob_barrier_hit(time_remaining_years=1.0, **args)
    p_long  = prob_barrier_hit(time_remaining_years=5.0, **args)
    assert p_short < p_med < p_long


def test_prob_barrier_hit_increases_with_vol():
    """Higher vol → higher P(touch), holding other things equal."""
    args = dict(
        spot=100.0, barrier=110.0,
        time_remaining_years=1.0, annualized_drift=0.0,
    )
    p_low  = prob_barrier_hit(annualized_vol=0.1, **args)
    p_med  = prob_barrier_hit(annualized_vol=0.3, **args)
    p_high = prob_barrier_hit(annualized_vol=0.6, **args)
    assert p_low < p_med < p_high


def test_prob_barrier_hit_decreases_with_distance_to_barrier():
    """Further barrier → lower P(touch), holding other things equal."""
    args = dict(
        spot=100.0,
        time_remaining_years=1.0, annualized_vol=0.3, annualized_drift=0.0,
    )
    p_close = prob_barrier_hit(barrier=105.0, **args)
    p_med   = prob_barrier_hit(barrier=120.0, **args)
    p_far   = prob_barrier_hit(barrier=150.0, **args)
    assert p_close > p_med > p_far


# === Edge cases ==============================================================

def test_prob_barrier_hit_zero_vol_no_drift():
    """σ=0, drift=0, spot ≠ barrier → no movement, P=0."""
    p = prob_barrier_hit(
        spot=100.0, barrier=110.0,
        time_remaining_years=1.0, annualized_vol=0.0,
    )
    assert p == 0.0


def test_prob_barrier_hit_returns_in_unit_interval():
    """For any plausible input, output must be in [0, 1]."""
    for spot, barrier, T, vol, drift in [
        (100, 105, 0.01, 0.5, 0.0),
        (100, 200, 0.1, 1.0, 0.5),
        (100, 50, 0.5, 0.8, -0.3),
        (100, 101, 0.001, 0.01, 0.0),
    ]:
        p = prob_barrier_hit(
            spot=spot, barrier=barrier,
            time_remaining_years=T, annualized_vol=vol,
            annualized_drift=drift,
        )
        assert 0.0 <= p <= 1.0, (
            f"P={p} out of [0,1] for spot={spot}, barrier={barrier}, "
            f"T={T}, vol={vol}, drift={drift}"
        )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/research/crypto/test_barrier_bridge.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.research.crypto.barrier_bridge'`.

- [ ] **Step 3: Create empty package markers**

Create `agent/research/crypto/__init__.py` (empty).

- [ ] **Step 4: Write the implementation**

Create `agent/research/crypto/barrier_bridge.py`:

```python
"""Closed-form one-touch barrier-hit probability for GBM with constant vol.

Uses the reflection principle.  Caller must supply ANNUALIZED vol and drift;
the parameter names make this explicit (defense against unit-confusion bugs).
"""

import math
from math import erf, exp, log, sqrt


def _phi(x: float) -> float:
    """Standard normal CDF: 0.5·(1 + erf(x/√2))."""
    return 0.5 * (1.0 + erf(x / sqrt(2.0)))


def prob_barrier_hit(
    spot: float,
    barrier: float,
    time_remaining_years: float,
    annualized_vol: float,
    annualized_drift: float = 0.0,
) -> float:
    """Probability that GBM(annualized_drift, annualized_vol) starting at
    `spot` touches `barrier` at some point in [0, time_remaining_years].

    Uses the reflection principle.  Returns a value in [0, 1].

    Edge cases handled explicitly:
      - spot == barrier: returns 1.0 (already touching).
      - time_remaining_years <= 0 (and spot != barrier): returns 0.0.
      - annualized_vol <= 0 with no deterministic-drift hit: returns 0.0.

    Drift convention: annualized_drift=0.0 is the agnostic-on-direction
    default; we forecast vol regime via GARCH but don't claim a directional
    view on the underlying.
    """
    # --- Edge cases first (cheap, defensive) -------------------------------
    if spot == barrier:
        return 1.0
    if time_remaining_years <= 0.0:
        return 0.0
    if annualized_vol <= 0.0:
        # Deterministic dynamics: does drift carry spot past barrier in time?
        if annualized_drift > 0 and barrier > spot:
            return (
                1.0
                if spot * exp(annualized_drift * time_remaining_years) >= barrier
                else 0.0
            )
        if annualized_drift < 0 and barrier < spot:
            return (
                1.0
                if spot * exp(annualized_drift * time_remaining_years) <= barrier
                else 0.0
            )
        return 0.0

    # --- Closed-form one-touch via reflection principle --------------------
    nu = annualized_drift - 0.5 * annualized_vol ** 2   # log-drift
    b = log(barrier / spot)                              # log-distance to barrier
    v = annualized_vol * sqrt(time_remaining_years)      # total vol over horizon
    sigma2 = annualized_vol ** 2

    if barrier > spot:
        # Up-barrier (b > 0)
        # P = N((νT - b)/v) + exp(2νb/σ²) · N((-νT - b)/v)
        term1 = _phi((nu * time_remaining_years - b) / v)
        prefactor = exp(2.0 * nu * b / sigma2)
        term2 = prefactor * _phi((-nu * time_remaining_years - b) / v)
    else:
        # Down-barrier (b < 0)
        # P = N((b - νT)/v) + exp(2νb/σ²) · N((b + νT)/v)
        term1 = _phi((b - nu * time_remaining_years) / v)
        prefactor = exp(2.0 * nu * b / sigma2)
        term2 = prefactor * _phi((b + nu * time_remaining_years) / v)

    # Numerical safety: clamp to [0, 1].  The formula CAN produce values
    # slightly outside this range for extreme inputs due to floating-point
    # accumulation.
    return max(0.0, min(1.0, term1 + term2))
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `pytest tests/research/crypto/test_barrier_bridge.py -v`
Expected: PASS — 10 passed (5 reference cases + 3 monotonicity + 2 edge cases).

- [ ] **Step 6: Run full suite**

Run: `pytest -v`
Expected: PASS — 96 passed (86 prior + 10 new).

- [ ] **Step 7: Commit**

```bash
git add agent/research/crypto/__init__.py agent/research/crypto/barrier_bridge.py tests/research/crypto/__init__.py tests/research/crypto/test_barrier_bridge.py
git commit -m "feat(phase1b-c1): add prob_barrier_hit closed-form one-touch + 10 gate tests"
```

---

### Task 7: vol_estimator — GARCHResult + fit_garch11

**Files:**
- Create: `agent/research/crypto/vol_estimator.py`
- Create: `tests/research/crypto/test_vol_estimator.py`

This task delivers the GARCH(1,1) fitter. **Critical structural defense:** `GARCHResult.current_conditional_vol` is annualized at construction time. Period-vol is NOT exposed in the dataclass — only annualized vol is reachable from a consumer's perspective. This prevents the unit-confusion bug class (forgetting to multiply by sqrt(periods_per_year) before passing to barrier_bridge).

- [ ] **Step 1: Write the failing tests**

Create `tests/research/crypto/test_vol_estimator.py`:

```python
import math
import random

import pytest

from agent.research.crypto.vol_estimator import (
    GARCHResult,
    fit_garch11,
)


def _generate_garch_series(
    omega: float, alpha: float, beta: float, n_obs: int, seed: int = 42,
) -> list[float]:
    """In-test GARCH(1,1) simulator with Gaussian innovations.

    Recursive variance: σ²_t = ω + α·ε²_{t-1} + β·σ²_{t-1}
    Initial variance: long-run variance ω/(1-α-β).
    Returns: ε_t ~ N(0, σ²_t).
    """
    rng = random.Random(seed)
    sigma2 = omega / (1.0 - alpha - beta)
    returns = []
    for _ in range(n_obs):
        epsilon = rng.gauss(0.0, math.sqrt(sigma2))
        returns.append(epsilon)
        sigma2 = omega + alpha * epsilon ** 2 + beta * sigma2
    return returns


def test_fit_garch11_recovers_known_parameters():
    """§5.2: 5000-sample synthetic series; GARCH MLE recovers (ω, α, β) within
    known wide CIs.  Beta most stable, omega noisiest."""
    TRUE_OMEGA = 1e-5
    TRUE_ALPHA = 0.05
    TRUE_BETA = 0.92
    N_OBS = 5000

    returns = _generate_garch_series(TRUE_OMEGA, TRUE_ALPHA, TRUE_BETA, N_OBS, seed=42)
    result = fit_garch11(returns, periods_per_year=8760)

    assert isinstance(result, GARCHResult)
    assert result.n_obs == N_OBS
    assert result.periods_per_year == 8760
    # Wide tolerances per GARCH MLE known variance:
    assert abs(result.beta - TRUE_BETA) / TRUE_BETA < 0.10
    assert abs(result.alpha - TRUE_ALPHA) / TRUE_ALPHA < 0.30
    assert abs(result.omega - TRUE_OMEGA) / TRUE_OMEGA < 0.50
    assert 0.0 < result.persistence < 1.0  # stationarity invariant
    assert result.persistence == result.alpha + result.beta


def test_fit_garch11_current_conditional_vol_is_annualized():
    """STRUCTURAL DEFENSE: current_conditional_vol must be in ANNUALIZED units.

    For hourly bars with periods_per_year=8760, period-vol ≈ 1% would
    annualize to ≈ 94%.  We verify the result's current_conditional_vol
    sits in the annualized range (>0.1), not the period-vol range (<0.05).
    """
    returns = _generate_garch_series(1e-5, 0.05, 0.92, 5000, seed=7)
    result = fit_garch11(returns, periods_per_year=8760)

    # Period vol on this synthetic series is small (~0.003); annualized is ~0.28.
    # The exact value depends on the seed.  Assert structural range only.
    assert result.current_conditional_vol > 0.05, (
        f"current_conditional_vol={result.current_conditional_vol} suspiciously "
        "small — did you forget to annualize by sqrt(periods_per_year)?"
    )
    # Conversely, also defend against accidentally squaring (annualizing twice)
    assert result.current_conditional_vol < 10.0, (
        f"current_conditional_vol={result.current_conditional_vol} suspiciously "
        "large — did you double-annualize?"
    )


def test_fit_garch11_too_few_observations_raises():
    """ValueError if len(returns) < 100."""
    with pytest.raises(ValueError):
        fit_garch11([0.01] * 50, periods_per_year=8760)


def test_fit_garch11_nan_input_raises():
    """ValueError if any return is NaN or inf."""
    returns = _generate_garch_series(1e-5, 0.05, 0.92, 500, seed=1)
    returns[10] = float("nan")
    with pytest.raises(ValueError):
        fit_garch11(returns, periods_per_year=8760)

    returns[10] = float("inf")
    with pytest.raises(ValueError):
        fit_garch11(returns, periods_per_year=8760)


def test_garch_result_is_frozen():
    """GARCHResult is immutable — consumers cannot mutate its fields."""
    result = GARCHResult(
        omega=1.0, alpha=0.05, beta=0.92, persistence=0.97,
        n_obs=5000, periods_per_year=8760,
        long_run_variance=0.001, current_conditional_vol=0.3,
    )
    raised = False
    try:
        result.current_conditional_vol = 0.5  # type: ignore[misc]
    except Exception:
        raised = True
    assert raised is True


def test_garch_result_period_units_consistency():
    """omega and long_run_variance are in period units; current_conditional_vol
    is annualized.  Verify by computing long_run_variance from omega/persistence
    and confirming they match.
    """
    result = GARCHResult(
        omega=1e-5, alpha=0.05, beta=0.92, persistence=0.97,
        n_obs=5000, periods_per_year=8760,
        long_run_variance=1e-5 / (1.0 - 0.97),  # period-units
        current_conditional_vol=0.3,             # annualized
    )
    # long_run_variance should equal omega / (1 - persistence)
    assert math.isclose(
        result.long_run_variance,
        result.omega / (1.0 - result.persistence),
        abs_tol=1e-10,
    )
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/research/crypto/test_vol_estimator.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.research.crypto.vol_estimator'`.

- [ ] **Step 3: Write the implementation**

Create `agent/research/crypto/vol_estimator.py`:

```python
"""GARCH(1,1) volatility estimator wrapping the `arch` package.

STRUCTURAL DEFENSE: `GARCHResult.current_conditional_vol` is annualized at
construction.  Period-vol is intentionally NOT exposed on the dataclass —
only annualized vol is reachable by consumers (e.g., barrier_bridge).
This prevents the unit-confusion bug class where a caller passes period-vol
to a function expecting annualized vol, silently producing answers off by
a factor of sqrt(periods_per_year) (~93x for hourly bars).
"""

import math
from collections.abc import Sequence
from dataclasses import dataclass

from arch import arch_model


@dataclass(frozen=True)
class GARCHResult:
    """Fitted GARCH(1,1) parameters + diagnostic values.

    Field unit conventions:
      omega, alpha, beta: dimensionless variance-equation coefficients
      long_run_variance:  PERIOD units (ω / (1 - α - β))
      current_conditional_vol: ANNUALIZED (period-vol × sqrt(periods_per_year))

    The asymmetric annualization (vol annualized, variance not) is deliberate —
    it matches what downstream consumers (barrier_bridge.prob_barrier_hit)
    expect, and prevents accidental period-units passthrough.
    """

    omega: float
    alpha: float
    beta: float
    persistence: float
    n_obs: int
    periods_per_year: int
    long_run_variance: float
    current_conditional_vol: float  # ANNUALIZED (see docstring)


def fit_garch11(
    returns: Sequence[float],
    *,
    periods_per_year: int,
    rescale: bool = True,
) -> GARCHResult:
    """Fit GARCH(1,1) on a sequence of period returns.

    Wraps arch.arch_model(returns, vol='GARCH', p=1, q=1) with .fit(disp='off').

    Parameters:
      returns:           Sequence of period returns (simple, e.g.
                         (close_t - close_{t-1}) / close_{t-1}).
      periods_per_year:  Annualization factor.  8760 for hourly, 365 for daily.
      rescale:           arch's auto-rescaling helps optimizer convergence on
                         small returns.  Keep True unless debugging.

    Raises:
      ValueError if len(returns) < 100.
      ValueError if any return is NaN or inf.

    Note: arch's ConvergenceWarning is propagated as a warning, not raised.
    Caller can decide to retry with different start values or accept.
    """
    if len(returns) < 100:
        raise ValueError(
            f"fit_garch11 requires at least 100 observations, got {len(returns)}"
        )
    for i, r in enumerate(returns):
        if not math.isfinite(r):
            raise ValueError(
                f"fit_garch11 requires finite returns; index {i} is {r}"
            )

    model = arch_model(
        list(returns), vol="GARCH", p=1, q=1, rescale=rescale
    )
    fitted = model.fit(disp="off")

    # arch's params are named: "omega", "alpha[1]", "beta[1]"
    omega = float(fitted.params["omega"])
    alpha = float(fitted.params["alpha[1]"])
    beta = float(fitted.params["beta[1]"])

    # If rescale=True, arch returns rescaled params; un-rescale to original units
    if rescale and hasattr(fitted, "scale") and fitted.scale != 1.0:
        scale = fitted.scale
        # arch's rescaling multiplies returns by 'scale' before fitting;
        # variance scales by scale^2.  omega and long_run_variance are in
        # variance units, so divide by scale^2.  alpha and beta are
        # dimensionless ratios and don't rescale.
        omega = omega / (scale ** 2)

    persistence = alpha + beta
    long_run_variance = omega / (1.0 - persistence) if persistence < 1.0 else float("inf")

    # arch's conditional_volatility is in period STDEV units; take last value
    # and annualize.
    last_period_vol = float(fitted.conditional_volatility.iloc[-1])
    if rescale and hasattr(fitted, "scale") and fitted.scale != 1.0:
        last_period_vol = last_period_vol / fitted.scale
    current_conditional_vol = last_period_vol * math.sqrt(periods_per_year)

    return GARCHResult(
        omega=omega,
        alpha=alpha,
        beta=beta,
        persistence=persistence,
        n_obs=len(returns),
        periods_per_year=periods_per_year,
        long_run_variance=long_run_variance,
        current_conditional_vol=current_conditional_vol,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/research/crypto/test_vol_estimator.py -v`
Expected: PASS — 6 passed.

Note: the parameter-recovery test runs a real GARCH MLE optimization on 5000 samples; expect ~1-2 seconds runtime. If it fails on tolerance, check the seed — different seeds produce different sample paths and may need slightly looser tolerances.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 102 passed (96 prior + 6 new).

- [ ] **Step 6: Commit**

```bash
git add agent/research/crypto/vol_estimator.py tests/research/crypto/test_vol_estimator.py
git commit -m "feat(phase1b-c1): add fit_garch11 with structural annualization defense"
```

---

### Task 8: forecast_garch_annualized_vol Helper

**Files:**
- Modify: `agent/research/crypto/vol_estimator.py` (append helper)
- Modify: `tests/research/crypto/test_vol_estimator.py` (append tests)

- [ ] **Step 1: Write the failing tests**

Append to `tests/research/crypto/test_vol_estimator.py`:

```python
from agent.research.crypto.vol_estimator import (
    forecast_garch_annualized_vol,
)


def _result_for_forecast(current_vol_annualized: float = 0.30) -> GARCHResult:
    """Build a GARCHResult with known fields for forecast-recursion tests."""
    return GARCHResult(
        omega=1e-5,
        alpha=0.05,
        beta=0.92,
        persistence=0.97,
        n_obs=5000,
        periods_per_year=8760,
        long_run_variance=1e-5 / (1.0 - 0.97),  # period-units
        current_conditional_vol=current_vol_annualized,
    )


def test_forecast_garch_at_horizon_1_equals_current():
    """h=1 → the existing one-step-ahead conditional vol."""
    result = _result_for_forecast(current_vol_annualized=0.30)
    forecast = forecast_garch_annualized_vol(result, horizon_periods=1)
    assert math.isclose(forecast, 0.30, abs_tol=1e-10)


def test_forecast_garch_converges_to_long_run_vol():
    """h → ∞ → forecast converges to sqrt(long_run_variance · periods_per_year)."""
    result = _result_for_forecast(current_vol_annualized=0.30)
    long_run_annualized = math.sqrt(result.long_run_variance * result.periods_per_year)
    forecast = forecast_garch_annualized_vol(result, horizon_periods=10000)
    assert math.isclose(forecast, long_run_annualized, abs_tol=1e-4)


def test_forecast_garch_recursion_intermediate():
    """h=10 produces the closed-form recursion result.

    Standard GARCH(1,1) multi-step forecast (Bollerslev textbook form):
        σ²(t+h|t) = σ²_∞ + ρ^(h-1) · (σ²(t+1|t) - σ²_∞)

    Exponent is h-1 (not h) so that at h=1 we get σ²(t+1) exactly.
    """
    result = _result_for_forecast(current_vol_annualized=0.30)
    # Current period-variance from annualized vol
    current_period_var = (0.30 ** 2) / result.periods_per_year
    h = 10
    rho = result.persistence
    expected_period_var = (
        result.long_run_variance
        + (rho ** (h - 1)) * (current_period_var - result.long_run_variance)
    )
    expected_annualized_vol = math.sqrt(expected_period_var * result.periods_per_year)

    forecast = forecast_garch_annualized_vol(result, horizon_periods=h)
    assert math.isclose(forecast, expected_annualized_vol, abs_tol=1e-9)


def test_forecast_garch_horizon_zero_raises():
    """h=0 is invalid — callers should use current_conditional_vol directly."""
    result = _result_for_forecast()
    with pytest.raises(ValueError):
        forecast_garch_annualized_vol(result, horizon_periods=0)


def test_forecast_garch_negative_horizon_raises():
    """Negative h is invalid."""
    result = _result_for_forecast()
    with pytest.raises(ValueError):
        forecast_garch_annualized_vol(result, horizon_periods=-5)
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `pytest tests/research/crypto/test_vol_estimator.py -v -k forecast`
Expected: FAIL — `ImportError: cannot import name 'forecast_garch_annualized_vol'`.

- [ ] **Step 3: Append the implementation to `agent/research/crypto/vol_estimator.py`**

```python
def forecast_garch_annualized_vol(
    result: GARCHResult,
    horizon_periods: int,
) -> float:
    """Iterative GARCH(1,1) variance forecast `h` periods ahead, then annualized.

    Standard textbook recursion (Bollerslev form):
        σ²(t+h|t) = long_run_variance + persistence^(h-1) * (σ²(t+1|t) - long_run_variance)

    Exponent is h-1 (not h) so that at h=1 the formula returns σ²(t+1) exactly.

    Returns the annualized vol at horizon h.  At h=1, returns the
    `current_conditional_vol` (already annualized).  As h → ∞, returns
    sqrt(long_run_variance · periods_per_year).

    Raises ValueError if horizon_periods <= 0.  Callers wanting h=0 should
    use result.current_conditional_vol directly.
    """
    if horizon_periods <= 0:
        raise ValueError(
            f"horizon_periods must be >= 1, got {horizon_periods}"
        )

    # Convert current_conditional_vol (annualized) back to period variance
    current_period_var = (
        result.current_conditional_vol ** 2
    ) / result.periods_per_year

    # Closed-form GARCH(1,1) multi-step recursion (textbook form):
    #   σ²(t+h|t) = σ²_∞ + ρ^(h-1) · (σ²(t+1|t) - σ²_∞)
    # At h=1, ρ^0 = 1, so this returns σ²(t+1) (the existing one-step-ahead).
    # As h → ∞, ρ^(h-1) → 0, so it converges to σ²_∞.
    period_var_at_h = (
        result.long_run_variance
        + (result.persistence ** (horizon_periods - 1))
        * (current_period_var - result.long_run_variance)
    )

    # Annualize and return as vol
    return math.sqrt(period_var_at_h * result.periods_per_year)
```

- [ ] **Step 4: Run the new tests to verify they pass**

Run: `pytest tests/research/crypto/test_vol_estimator.py -v -k forecast`
Expected: PASS — 5 passed.

- [ ] **Step 5: Run full suite**

Run: `pytest -v`
Expected: PASS — 107 passed (102 prior + 5 new).

- [ ] **Step 6: Commit**

```bash
git add agent/research/crypto/vol_estimator.py tests/research/crypto/test_vol_estimator.py
git commit -m "feat(phase1b-c1): add forecast_garch_annualized_vol helper"
```

---

### Task 9: Phase 1B-C1 Gate — Full-Suite Verification

**Files:** None modified — this is a verification-only task that runs the entire suite and confirms every §5 reference test from the spec is GREEN.

- [ ] **Step 1: Run the full test suite**

Run: `pytest -v`
Expected: PASS — **107 passed** (71 prior Phase 0+1A + 36 Phase 1B-C1).

- [ ] **Step 2: Verify each §5 reference test by name**

Run: `pytest -v --collect-only 2>&1 | grep -E "(prob_barrier_hit|fit_garch11|forecast_garch|crypto_bar|save_crypto_bars|get_klines|ingest_history)"`

Expected: all the following test names appear and pass:

**§5.1 barrier_bridge:**
- `test_prob_barrier_hit_already_touching` (Case 1)
- `test_prob_barrier_hit_zero_time_up_barrier` (Case 2)
- `test_prob_barrier_hit_zero_time_down_barrier` (Case 3)
- `test_prob_barrier_hit_long_horizon_negative_log_drift` (Case 4 — catches missing exp prefactor via S₀/B asymptote)
- `test_prob_barrier_hit_log_drift_zero_up_barrier` (Case 5)
- `test_prob_barrier_hit_increases_with_time` (monotonicity)
- `test_prob_barrier_hit_increases_with_vol` (monotonicity)
- `test_prob_barrier_hit_decreases_with_distance_to_barrier` (monotonicity)
- `test_prob_barrier_hit_zero_vol_no_drift` (edge case)
- `test_prob_barrier_hit_returns_in_unit_interval` (edge case)

**§5.2 vol_estimator:**
- `test_fit_garch11_recovers_known_parameters`
- `test_fit_garch11_current_conditional_vol_is_annualized` (structural defense)
- `test_fit_garch11_too_few_observations_raises`
- `test_fit_garch11_nan_input_raises`
- `test_garch_result_is_frozen`
- `test_garch_result_period_units_consistency`

**§5.3 BinanceClient:**
- `test_get_klines_parses_three_bars`
- `test_get_klines_passes_query_params`
- `test_get_klines_raises_on_429`

**§5.4 CryptoIngestService:**
- `test_ingest_history_single_request`
- `test_ingest_history_paginates_over_two_requests`
- `test_ingest_history_is_idempotent`
- `test_ingest_latest`

**§5.5 save_crypto_bars:**
- `test_save_crypto_bars_inserts_new`
- `test_save_crypto_bars_is_idempotent`
- `test_save_crypto_bars_partial_overlap`

**§5.6 CryptoBar schema:**
- `test_crypto_bar_round_trips_through_db`
- `test_crypto_bar_unique_constraint_on_symbol_granularity_ts`
- `test_crypto_bar_allows_different_granularities_same_ts`

**§5.7 forecast_garch_annualized_vol:**
- `test_forecast_garch_at_horizon_1_equals_current`
- `test_forecast_garch_converges_to_long_run_vol`
- `test_forecast_garch_recursion_intermediate`
- `test_forecast_garch_horizon_zero_raises`
- `test_forecast_garch_negative_horizon_raises`

- [ ] **Step 3: Smoke-test the imports**

Run from the project dir with venv activated:

```bash
python -c "
from agent.data.crypto_client import BinanceClient
from agent.data.crypto_ingest import CryptoIngestService
from agent.data.models import CryptoBarDTO
from agent.research.crypto.barrier_bridge import prob_barrier_hit
from agent.research.crypto.vol_estimator import GARCHResult, fit_garch11, forecast_garch_annualized_vol
from agent.store.repository import save_crypto_bars
from agent.store.schema import CryptoBar
print('All C1 imports succeed')
print(f'prob_barrier_hit(100, 110, 1.0, 0.3) = {prob_barrier_hit(100, 110, 1.0, 0.3):.4f}')
"
```

Expected: `All C1 imports succeed` followed by a printed probability between 0 and 1 (likely ~0.5).

- [ ] **Step 4: Commit (verification-only, but commit to mark the gate)**

```bash
git commit --allow-empty -m "test(phase1b-c1): close Phase 1B-C1 algorithmic gate (107 tests green)"
```

---

## Phase 1B-C1 Completion Gate

C1 is complete when `pytest -v` is fully green at **107 tests** AND every §5
reference test from the spec is present and passing (verified by name in
Task 9 Step 2).  Phase 1B-C2 — composing `fit_garch11`, `prob_barrier_hit`,
and a shock detector into a `crypto_model(market_id, event) -> Prediction`
callable for Phase 1A's `walk_forward_backtest` — is unblocked.

---

## Self-Review

**1. Spec coverage (each §5 reference test from the spec mapped to a task):**
- §5.1 prob_barrier_hit Cases 1–5 + 3 monotonicity + 2 edge cases → Task 6 ✓
- §5.2 fit_garch11 parameter recovery + invalid-input tests → Task 7 ✓
- §5.3 BinanceClient happy path + params + 429 → Task 4 ✓
- §5.4 CryptoIngestService pagination + idempotency → Task 5 ✓
- §5.5 save_crypto_bars idempotency + partial overlap → Task 3 ✓
- §5.6 CryptoBar schema round-trip + uniqueness → Task 2 ✓
- §5.7 forecast_garch recursion + boundary → Task 8 ✓
- §5.8 full-suite green → Task 9 ✓

**Bug defenses from §6 of the spec / discussion:**
- Barrier formula correctness — 5 reference cases + 3 monotonicity + 2 edge cases in Task 6 ✓
- GARCHResult annualization at construction — Task 7 includes
  `test_fit_garch11_current_conditional_vol_is_annualized` as an explicit
  structural test ✓
- `annualized_drift` parameter naming — used throughout Task 6 ✓

**2. Placeholder scan:** No "TBD", "TODO", "implement later", "add error
handling", "similar to Task N" patterns.  Every code step contains complete
runnable code; every command has expected output.  ✓

**3. Type consistency:**
- `CryptoBarDTO(symbol, granularity, ts, open, high, low, close, volume)` —
  defined Task 1, consumed by save_crypto_bars (Task 3), BinanceClient (Task 4),
  CryptoIngestService (Task 5).  Signature unchanged. ✓
- `CryptoBar` ORM model fields match CryptoBarDTO fields. ✓
- `GARCHResult(omega, alpha, beta, persistence, n_obs, periods_per_year,
  long_run_variance, current_conditional_vol)` — defined Task 7,
  consumed by forecast_garch_annualized_vol (Task 8).  ✓
- `prob_barrier_hit(spot, barrier, time_remaining_years, annualized_vol,
  annualized_drift=0.0)` — defined Task 6.  Parameter names match the spec's
  §4.5 signature exactly. ✓
- `BinanceClient.get_klines(symbol, interval, *, start_ts, end_ts, limit)`
  signature in Task 4 matches `CryptoIngestService.ingest_history`'s
  call site in Task 5. ✓

No type drift identified.
