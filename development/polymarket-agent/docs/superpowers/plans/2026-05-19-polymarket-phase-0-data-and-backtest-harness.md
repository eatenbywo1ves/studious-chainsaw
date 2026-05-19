# Polymarket Agent — Phase 0: Data Ingestion & Backtest Harness — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundation layer of the Polymarket trading agent — a rate-limited Polymarket API client, a Postgres-compatible store, an ingestion service, and a backtest replay engine that provably reproduces stored historical prices.

**Architecture:** A Python package `agent/` with focused modules: `data/` (API client, rate limiter, DTOs, ingestion), `store/` (SQLAlchemy schema + repository), `validation/` (replay engine). The API client is async (`httpx`); the store is synchronous SQLAlchemy 2.0 (ingestion is not latency-critical). Unit tests mock HTTP with `respx` and use in-memory SQLite, so the suite runs with no Docker. The same SQLAlchemy models run on Postgres in production.

**Tech Stack:** Python 3.12, `httpx`, `pydantic` v2, `pydantic-settings`, `SQLAlchemy` 2.0, `pytest`, `pytest-asyncio`, `respx`.

**Plan context:** This is **Plan 1 of 5**. It corresponds to Phase 0 of the design spec (`docs/superpowers/specs/2026-05-19-polymarket-fair-value-agent-design.md`). Its completion gate — "the backtest harness reproduces known historical prices" — is verified by Task 9. Phases 1–4 (fair-value research, risk/execution/dashboard, dormant strategies, bankroll-gated activation) each get their own plan.

---

## File Structure

| File | Responsibility |
|---|---|
| `pyproject.toml` | Package metadata, dependencies, pytest config |
| `agent/__init__.py` | Package marker |
| `agent/config.py` | Env-based settings (`Settings`, `get_settings`) |
| `agent/data/rate_limiter.py` | `TokenBucket` — per-endpoint-group rate limiting |
| `agent/data/models.py` | API DTOs: `MarketDTO`, `PricePoint`, `PriceHistory` |
| `agent/data/polymarket_client.py` | `PolymarketClient` — async Gamma/CLOB reads |
| `agent/data/ingest.py` | `IngestService` — fetch + persist orchestration |
| `agent/store/schema.py` | SQLAlchemy ORM: `Market`, `PriceSnapshot` |
| `agent/store/db.py` | Engine/session factory, `init_db` |
| `agent/store/repository.py` | `upsert_market`, `save_price_history` |
| `agent/validation/backtest.py` | `ReplayEngine`, `ReplayEvent` |
| `tests/conftest.py` | Shared fixtures (`settings`, `engine`, `session_factory`, `session`) |
| `tests/...` | One test module per source module |

---

### Task 1: Project Scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `agent/__init__.py`
- Create: `agent/data/__init__.py`, `agent/store/__init__.py`, `agent/validation/__init__.py`
- Create: `tests/__init__.py`, `tests/test_smoke.py`

- [ ] **Step 1: Write the smoke test**

Create `tests/test_smoke.py`:

```python
def test_agent_package_importable():
    import agent

    assert agent is not None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_smoke.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent'` (or pytest not yet installed).

- [ ] **Step 3: Create `pyproject.toml`**

```toml
[project]
name = "polymarket-agent"
version = "0.0.1"
description = "Autonomous fair-value trading agent for Polymarket"
requires-python = ">=3.12"
dependencies = [
    "httpx>=0.27",
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "sqlalchemy>=2.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.2",
    "pytest-asyncio>=0.23",
    "respx>=0.21",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.setuptools.packages.find]
include = ["agent*"]
```

- [ ] **Step 4: Create the package marker files**

Create `agent/__init__.py`, `agent/data/__init__.py`, `agent/store/__init__.py`, `agent/validation/__init__.py`, and `tests/__init__.py` — each an empty file.

- [ ] **Step 5: Install and run the test to verify it passes**

Run: `pip install -e ".[dev]"` then `pytest tests/test_smoke.py -v`
Expected: PASS — 1 passed.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml agent tests
git commit -m "chore(phase0): scaffold polymarket-agent package"
```

---

### Task 2: Configuration Module

**Files:**
- Create: `agent/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_config.py`:

```python
from agent.config import Settings, get_settings


def test_settings_defaults():
    settings = Settings()

    assert settings.clob_base_url == "https://clob.polymarket.com"
    assert settings.gamma_base_url == "https://gamma-api.polymarket.com"
    assert settings.database_url.startswith("sqlite")
    assert settings.http_timeout_seconds == 30.0


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("PMA_DATABASE_URL", "postgresql://localhost/test")

    assert get_settings().database_url == "postgresql://localhost/test"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.config'`.

- [ ] **Step 3: Write the implementation**

Create `agent/config.py`:

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven configuration. Variables are prefixed PMA_."""

    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="PMA_", extra="ignore"
    )

    database_url: str = "sqlite:///./polymarket_agent.db"
    clob_base_url: str = "https://clob.polymarket.com"
    gamma_base_url: str = "https://gamma-api.polymarket.com"
    http_timeout_seconds: float = 30.0


def get_settings() -> Settings:
    """Return a freshly-loaded Settings instance."""
    return Settings()
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add agent/config.py tests/test_config.py
git commit -m "feat(phase0): add env-based settings module"
```

---

### Task 3: Token-Bucket Rate Limiter

**Files:**
- Create: `agent/data/rate_limiter.py`
- Test: `tests/data/__init__.py`, `tests/data/test_rate_limiter.py`

- [ ] **Step 1: Write the failing test**

Create `tests/data/__init__.py` (empty) and `tests/data/test_rate_limiter.py`:

```python
from agent.data.rate_limiter import TokenBucket


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_bucket_starts_full():
    bucket = TokenBucket(capacity=3, refill_per_second=1.0, clock=FakeClock())

    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True


def test_bucket_blocks_when_empty():
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=FakeClock())

    bucket.try_acquire()
    bucket.try_acquire()

    assert bucket.try_acquire() is False


def test_bucket_refills_over_time():
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=clock)
    bucket.try_acquire()
    bucket.try_acquire()
    assert bucket.try_acquire() is False

    clock.now = 1.0  # one second elapses -> one token refilled

    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False


def test_bucket_never_exceeds_capacity():
    clock = FakeClock()
    bucket = TokenBucket(capacity=2, refill_per_second=1.0, clock=clock)
    clock.now = 100.0  # long idle

    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is True
    assert bucket.try_acquire() is False
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_rate_limiter.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.data.rate_limiter'`.

- [ ] **Step 3: Write the implementation**

Create `agent/data/rate_limiter.py`:

```python
import asyncio
import time
from collections.abc import Callable


class TokenBucket:
    """A token-bucket rate limiter.

    `try_acquire` is synchronous and deterministic (inject `clock` for tests).
    `acquire` is an async wrapper that waits until a token is available.
    """

    def __init__(
        self,
        capacity: int,
        refill_per_second: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.capacity = capacity
        self.refill_per_second = refill_per_second
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._tokens = min(
            self.capacity, self._tokens + elapsed * self.refill_per_second
        )
        self._last = now

    def try_acquire(self, tokens: int = 1) -> bool:
        """Consume `tokens` if available. Return True on success."""
        self._refill()
        if self._tokens >= tokens:
            self._tokens -= tokens
            return True
        return False

    async def acquire(self, tokens: int = 1) -> None:
        """Wait until `tokens` can be consumed, then consume them."""
        while not self.try_acquire(tokens):
            await asyncio.sleep(1.0 / self.refill_per_second)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/data/test_rate_limiter.py -v`
Expected: PASS — 4 passed.

- [ ] **Step 5: Commit**

```bash
git add agent/data/rate_limiter.py tests/data
git commit -m "feat(phase0): add token-bucket rate limiter"
```

---

### Task 4: API Data Models (DTOs)

**Files:**
- Create: `agent/data/models.py`
- Test: `tests/data/test_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/data/test_models.py`:

```python
from agent.data.models import MarketDTO, PriceHistory, PricePoint


def test_price_point_and_history():
    history = PriceHistory(
        token_id="tok-1",
        history=[PricePoint(t=1000, p=0.5), PricePoint(t=2000, p=0.6)],
    )

    assert history.token_id == "tok-1"
    assert history.history[1].p == 0.6


def test_market_from_gamma_parses_stringified_token_ids():
    raw = {
        "id": 42,
        "question": "Will it rain?",
        "conditionId": "0xabc",
        "clobTokenIds": '["tok-yes", "tok-no"]',
        "category": "Weather",
        "active": True,
        "closed": False,
        "enableOrderBook": True,
        "orderMinSize": "5",
        "orderPriceMinTickSize": "0.01",
        "volume24hr": "1234.5",
        "liquidityNum": 99.0,
        "endDateIso": "2026-12-31",
    }

    dto = MarketDTO.from_gamma(raw)

    assert dto.id == "42"
    assert dto.clob_token_ids == ["tok-yes", "tok-no"]
    assert dto.enable_order_book is True
    assert dto.order_min_size == 5.0
    assert dto.order_price_min_tick_size == 0.01
    assert dto.volume_24hr == 1234.5
    assert dto.liquidity == 99.0


def test_market_from_gamma_tolerates_missing_fields():
    dto = MarketDTO.from_gamma({"id": "7"})

    assert dto.id == "7"
    assert dto.question == ""
    assert dto.clob_token_ids == []
    assert dto.order_min_size is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.data.models'`.

- [ ] **Step 3: Write the implementation**

Create `agent/data/models.py`:

```python
import json

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

    @classmethod
    def from_gamma(cls, raw: dict) -> "MarketDTO":
        """Build a MarketDTO from a raw Gamma API market object."""
        token_ids = raw.get("clobTokenIds")
        if isinstance(token_ids, str):
            try:
                token_ids = json.loads(token_ids)
            except json.JSONDecodeError:
                token_ids = []
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
        )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/data/test_models.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add agent/data/models.py tests/data/test_models.py
git commit -m "feat(phase0): add API data models"
```

---

### Task 5: Polymarket Async Client

**Files:**
- Create: `agent/data/polymarket_client.py`
- Test: `tests/data/test_polymarket_client.py`

- [ ] **Step 1: Write the failing test**

Create `tests/data/test_polymarket_client.py`:

```python
import httpx
import respx

from agent.config import Settings
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


@respx.mock
async def test_get_markets_parses_response():
    respx.get("https://gamma-api.polymarket.com/markets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "question": "Q1", "clobTokenIds": '["a","b"]',
                 "enableOrderBook": True},
                {"id": 2, "question": "Q2", "clobTokenIds": '["c","d"]'},
            ],
        )
    )
    async with httpx.AsyncClient() as http:
        markets = await _client(http).get_markets(limit=2)

    assert [m.id for m in markets] == ["1", "2"]
    assert markets[0].clob_token_ids == ["a", "b"]


@respx.mock
async def test_get_price_history_parses_response():
    route = respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(
            200, json={"history": [{"t": 1000, "p": 0.4}, {"t": 2000, "p": 0.55}]}
        )
    )
    async with httpx.AsyncClient() as http:
        history = await _client(http).get_price_history("tok-1", interval="1h")

    assert history.token_id == "tok-1"
    assert [(p.t, p.p) for p in history.history] == [(1000, 0.4), (2000, 0.55)]
    assert route.calls.last.request.url.params["market"] == "tok-1"


@respx.mock
async def test_get_price_history_raises_on_http_error():
    respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(500)
    )
    async with httpx.AsyncClient() as http:
        try:
            await _client(http).get_price_history("tok-1")
            raised = False
        except httpx.HTTPStatusError:
            raised = True

    assert raised is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_polymarket_client.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.data.polymarket_client'`.

- [ ] **Step 3: Write the implementation**

Create `agent/data/polymarket_client.py`:

```python
import httpx

from agent.config import Settings
from agent.data.models import MarketDTO, PriceHistory, PricePoint
from agent.data.rate_limiter import TokenBucket


class PolymarketClient:
    """Read-only async client for the Polymarket Gamma and CLOB APIs."""

    def __init__(
        self,
        settings: Settings,
        http_client: httpx.AsyncClient,
        market_data_bucket: TokenBucket | None = None,
    ) -> None:
        self._settings = settings
        self._http = http_client
        # CLOB market-data limit is generous; 400 capacity / 40 rps is well under it.
        self._bucket = market_data_bucket or TokenBucket(
            capacity=400, refill_per_second=40
        )

    async def get_markets(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        active: bool = True,
        closed: bool = False,
    ) -> list[MarketDTO]:
        """Fetch a page of markets from the Gamma API."""
        await self._bucket.acquire()
        resp = await self._http.get(
            f"{self._settings.gamma_base_url}/markets",
            params={
                "limit": limit,
                "offset": offset,
                "active": str(active).lower(),
                "closed": str(closed).lower(),
            },
        )
        resp.raise_for_status()
        return [MarketDTO.from_gamma(item) for item in resp.json()]

    async def get_price_history(
        self,
        token_id: str,
        *,
        start_ts: int | None = None,
        end_ts: int | None = None,
        interval: str = "1h",
        fidelity: int = 60,
    ) -> PriceHistory:
        """Fetch historical prices for one CLOB token (asset id).

        The CLOB `/prices-history` endpoint names this parameter `market`,
        but it is the token/asset id, not the condition id.
        """
        await self._bucket.acquire()
        params: dict[str, object] = {
            "market": token_id,
            "interval": interval,
            "fidelity": fidelity,
        }
        if start_ts is not None:
            params["startTs"] = start_ts
        if end_ts is not None:
            params["endTs"] = end_ts
        resp = await self._http.get(
            f"{self._settings.clob_base_url}/prices-history", params=params
        )
        resp.raise_for_status()
        payload = resp.json()
        points = [
            PricePoint(t=int(pt["t"]), p=float(pt["p"]))
            for pt in payload.get("history", [])
        ]
        return PriceHistory(token_id=token_id, history=points)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/data/test_polymarket_client.py -v`
Expected: PASS — 3 passed.

- [ ] **Step 5: Commit**

```bash
git add agent/data/polymarket_client.py tests/data/test_polymarket_client.py
git commit -m "feat(phase0): add async Polymarket API client"
```

---

### Task 6: Store Schema & Database Bootstrap

**Files:**
- Create: `agent/store/schema.py`
- Create: `agent/store/db.py`
- Test: `tests/conftest.py`, `tests/store/__init__.py`, `tests/store/test_schema.py`

- [ ] **Step 1: Write the shared fixtures and failing test**

Create `tests/conftest.py`:

```python
import pytest

from agent.config import Settings
from agent.store.db import init_db, make_engine, make_session_factory


@pytest.fixture
def settings() -> Settings:
    return Settings(database_url="sqlite:///:memory:")


@pytest.fixture
def engine():
    eng = make_engine("sqlite:///:memory:")
    init_db(eng)
    return eng


@pytest.fixture
def session_factory(engine):
    return make_session_factory(engine)


@pytest.fixture
def session(session_factory):
    with session_factory() as sess:
        yield sess
```

Create `tests/store/__init__.py` (empty) and `tests/store/test_schema.py`:

```python
from agent.store.schema import Market, PriceSnapshot


def test_can_persist_market_and_snapshot(session):
    market = Market(id="m1", question="Will it rain?", category="Weather")
    session.add(market)
    session.add(
        PriceSnapshot(market_id="m1", token_id="tok-1", ts=1000, price=0.42)
    )
    session.commit()

    loaded = session.get(Market, "m1")
    assert loaded.question == "Will it rain?"
    assert loaded.snapshots[0].price == 0.42


def test_snapshot_unique_constraint(session):
    session.add(Market(id="m1", question="Q"))
    session.add(PriceSnapshot(market_id="m1", token_id="t", ts=1, price=0.5))
    session.commit()

    session.add(PriceSnapshot(market_id="m1", token_id="t", ts=1, price=0.9))
    raised = False
    try:
        session.commit()
    except Exception:
        raised = True
        session.rollback()

    assert raised is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/store/test_schema.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.store.schema'`.

- [ ] **Step 3: Write the schema**

Create `agent/store/schema.py`:

```python
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
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
```

- [ ] **Step 4: Write the database bootstrap**

Create `agent/store/db.py`:

```python
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from agent.store.schema import Base

_IN_MEMORY = {"sqlite:///:memory:", "sqlite://"}


def make_engine(database_url: str) -> Engine:
    """Create an Engine. In-memory SQLite uses StaticPool so every session
    in a test shares one database."""
    if database_url in _IN_MEMORY:
        return create_engine(
            "sqlite://",
            future=True,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    return create_engine(database_url, future=True)


def init_db(engine: Engine) -> None:
    """Create all tables. Phase 0 uses create_all; Alembic migrations are
    introduced in a later phase when the schema first changes."""
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Return a sessionmaker bound to `engine`."""
    return sessionmaker(bind=engine, expire_on_commit=False, class_=Session)
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/store/test_schema.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 6: Commit**

```bash
git add agent/store/schema.py agent/store/db.py tests/conftest.py tests/store
git commit -m "feat(phase0): add store schema and database bootstrap"
```

---

### Task 7: Repository (Upsert Functions)

**Files:**
- Create: `agent/store/repository.py`
- Test: `tests/store/test_repository.py`

- [ ] **Step 1: Write the failing test**

Create `tests/store/test_repository.py`:

```python
from agent.data.models import MarketDTO, PriceHistory, PricePoint
from agent.store.repository import save_price_history, upsert_market
from agent.store.schema import Market, PriceSnapshot


def _dto(market_id: str, question: str) -> MarketDTO:
    return MarketDTO(id=market_id, question=question, enable_order_book=True)


def test_upsert_market_inserts_then_updates(session):
    upsert_market(session, _dto("m1", "Original?"))
    session.commit()
    assert session.get(Market, "m1").question == "Original?"

    upsert_market(session, _dto("m1", "Updated?"))
    session.commit()

    assert session.get(Market, "m1").question == "Updated?"
    assert session.query(Market).count() == 1


def test_save_price_history_is_idempotent(session):
    upsert_market(session, _dto("m1", "Q"))
    session.commit()
    history = PriceHistory(
        token_id="tok-1",
        history=[PricePoint(t=1000, p=0.4), PricePoint(t=2000, p=0.5)],
    )

    added_first = save_price_history(session, "m1", history)
    session.commit()
    added_second = save_price_history(session, "m1", history)
    session.commit()

    assert added_first == 2
    assert added_second == 0
    assert session.query(PriceSnapshot).count() == 2
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/store/test_repository.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.store.repository'`.

- [ ] **Step 3: Write the implementation**

Create `agent/store/repository.py`:

```python
from sqlalchemy.orm import Session

from agent.data.models import MarketDTO, PriceHistory
from agent.store.schema import Market, PriceSnapshot


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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/store/test_repository.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add agent/store/repository.py tests/store/test_repository.py
git commit -m "feat(phase0): add idempotent repository upserts"
```

---

### Task 8: Ingestion Service

**Files:**
- Create: `agent/data/ingest.py`
- Test: `tests/data/test_ingest.py`

- [ ] **Step 1: Write the failing test**

Create `tests/data/test_ingest.py`:

```python
import httpx
import respx

from agent.config import Settings
from agent.data.ingest import IngestService
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.store.schema import Market, PriceSnapshot


def _client(http: httpx.AsyncClient) -> PolymarketClient:
    return PolymarketClient(
        settings=Settings(),
        http_client=http,
        market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
    )


@respx.mock
async def test_ingest_markets_persists_rows(session_factory, session):
    respx.get("https://gamma-api.polymarket.com/markets").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "question": "Q1", "clobTokenIds": '["a","b"]'},
                {"id": 2, "question": "Q2", "clobTokenIds": '["c","d"]'},
            ],
        )
    )
    async with httpx.AsyncClient() as http:
        service = IngestService(_client(http), session_factory)
        count = await service.ingest_markets(limit=2)

    assert count == 2
    assert session.query(Market).count() == 2


@respx.mock
async def test_ingest_price_history_persists_snapshots(session_factory, session):
    session.add(Market(id="m1", question="Q"))
    session.commit()
    respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(
            200, json={"history": [{"t": 1000, "p": 0.4}, {"t": 2000, "p": 0.6}]}
        )
    )
    async with httpx.AsyncClient() as http:
        service = IngestService(_client(http), session_factory)
        added = await service.ingest_price_history("m1", "tok-1")

    assert added == 2
    assert session.query(PriceSnapshot).count() == 2
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/data/test_ingest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.data.ingest'`.

- [ ] **Step 3: Write the implementation**

Create `agent/data/ingest.py`:

```python
from sqlalchemy.orm import Session, sessionmaker

from agent.data.polymarket_client import PolymarketClient
from agent.store.repository import save_price_history, upsert_market


class IngestService:
    """Fetches data from Polymarket and persists it to the local store."""

    def __init__(
        self,
        client: PolymarketClient,
        session_factory: sessionmaker[Session],
    ) -> None:
        self._client = client
        self._session_factory = session_factory

    async def ingest_markets(self, *, limit: int = 100) -> int:
        """Fetch one page of markets and upsert them. Return the count."""
        markets = await self._client.get_markets(limit=limit)
        with self._session_factory() as session:
            for dto in markets:
                upsert_market(session, dto)
            session.commit()
        return len(markets)

    async def ingest_price_history(
        self, market_id: str, token_id: str, *, interval: str = "1h"
    ) -> int:
        """Fetch a token's price history and persist new points.

        Return the count of newly-inserted snapshots.
        """
        history = await self._client.get_price_history(
            token_id, interval=interval
        )
        with self._session_factory() as session:
            added = save_price_history(session, market_id, history)
            session.commit()
        return added
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `pytest tests/data/test_ingest.py -v`
Expected: PASS — 2 passed.

- [ ] **Step 5: Commit**

```bash
git add agent/data/ingest.py tests/data/test_ingest.py
git commit -m "feat(phase0): add ingestion service"
```

---

### Task 9: Backtest Replay Engine & Phase 0 Gate

**Files:**
- Create: `agent/validation/backtest.py`
- Test: `tests/validation/__init__.py`, `tests/validation/test_backtest.py`

- [ ] **Step 1: Write the failing tests (unit + the Phase 0 gate)**

Create `tests/validation/__init__.py` (empty) and `tests/validation/test_backtest.py`:

```python
import httpx
import respx

from agent.config import Settings
from agent.data.ingest import IngestService
from agent.data.polymarket_client import PolymarketClient
from agent.data.rate_limiter import TokenBucket
from agent.store.repository import save_price_history
from agent.data.models import PriceHistory, PricePoint
from agent.store.schema import Market
from agent.validation.backtest import ReplayEngine, ReplayEvent


def test_replay_yields_events_in_timestamp_order(session):
    session.add(Market(id="m1", question="Q"))
    # Deliberately insert out of order; replay must sort ascending by ts.
    save_price_history(
        session,
        "m1",
        PriceHistory(
            token_id="t1",
            history=[PricePoint(t=3000, p=0.7), PricePoint(t=1000, p=0.4),
                     PricePoint(t=2000, p=0.55)],
        ),
    )
    session.commit()

    events = list(ReplayEngine(session).replay("m1", "t1"))

    assert events == [
        ReplayEvent(ts=1000, token_id="t1", price=0.4),
        ReplayEvent(ts=2000, token_id="t1", price=0.55),
        ReplayEvent(ts=3000, token_id="t1", price=0.7),
    ]


def test_replay_isolates_by_token(session):
    session.add(Market(id="m1", question="Q"))
    save_price_history(
        session, "m1",
        PriceHistory(token_id="t1", history=[PricePoint(t=1, p=0.1)]),
    )
    save_price_history(
        session, "m1",
        PriceHistory(token_id="t2", history=[PricePoint(t=1, p=0.9)]),
    )
    session.commit()

    events = list(ReplayEngine(session).replay("m1", "t2"))

    assert [e.price for e in events] == [0.9]


@respx.mock
async def test_phase0_gate_replay_reproduces_ingested_prices(
    session_factory, session
):
    """PHASE 0 COMPLETION GATE: data ingested from the API, when replayed by
    the backtest harness, reproduces the source price series exactly."""
    source = [
        {"t": 1700000000, "p": 0.31},
        {"t": 1700003600, "p": 0.34},
        {"t": 1700007200, "p": 0.29},
        {"t": 1700010800, "p": 0.41},
    ]
    session.add(Market(id="mkt-gate", question="Gate market"))
    session.commit()
    respx.get("https://clob.polymarket.com/prices-history").mock(
        return_value=httpx.Response(200, json={"history": source})
    )

    async with httpx.AsyncClient() as http:
        client = PolymarketClient(
            settings=Settings(),
            http_client=http,
            market_data_bucket=TokenBucket(capacity=100, refill_per_second=100),
        )
        added = await IngestService(client, session_factory).ingest_price_history(
            "mkt-gate", "tok-gate"
        )

    replayed = list(ReplayEngine(session).replay("mkt-gate", "tok-gate"))

    assert added == len(source)
    assert [(e.ts, e.price) for e in replayed] == [
        (row["t"], row["p"]) for row in source
    ]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/validation/test_backtest.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.validation.backtest'`.

- [ ] **Step 3: Write the implementation**

Create `agent/validation/backtest.py`:

```python
from collections.abc import Iterator
from dataclasses import dataclass

from sqlalchemy.orm import Session

from agent.store.schema import PriceSnapshot


@dataclass(frozen=True)
class ReplayEvent:
    """A single point of a replayed historical price series."""

    ts: int
    token_id: str
    price: float


class ReplayEngine:
    """Replays stored price history in strict timestamp order.

    This is the foundation of the backtest harness: Phase 1+ strategies are
    fed `ReplayEvent`s and must make decisions using only data up to each
    event's timestamp (no look-ahead).
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def replay(self, market_id: str, token_id: str) -> Iterator[ReplayEvent]:
        """Yield every stored snapshot for one token, ascending by timestamp."""
        rows = (
            self._session.query(PriceSnapshot)
            .filter_by(market_id=market_id, token_id=token_id)
            .order_by(PriceSnapshot.ts.asc())
        )
        for row in rows:
            yield ReplayEvent(
                ts=row.ts, token_id=row.token_id, price=row.price
            )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/validation/test_backtest.py -v`
Expected: PASS — 3 passed (including `test_phase0_gate_replay_reproduces_ingested_prices`).

- [ ] **Step 5: Run the full suite**

Run: `pytest -v`
Expected: PASS — all tests from Tasks 1–9 pass (19 tests).

- [ ] **Step 6: Commit**

```bash
git add agent/validation/backtest.py tests/validation
git commit -m "feat(phase0): add backtest replay engine and Phase 0 gate test"
```

---

## Phase 0 Completion Gate

Phase 0 is complete when `pytest -v` is fully green and
`test_phase0_gate_replay_reproduces_ingested_prices` passes — proving the
ingestion → store → replay round-trip reproduces source prices exactly. That
verifies the spec's Phase 0 gate ("the backtest harness reproduces known
historical prices") and unblocks the **Phase 1 plan** (fair-value research +
validation gate).

---

## Self-Review

**1. Spec coverage (Phase 0 scope only):**
- L1 data ingestion — Tasks 4, 5, 8 (DTOs, client, ingest service). ✓
- Rate-limit-aware client (spec §L1) — Task 3 + Task 5. ✓
- Postgres-compatible store (spec §L1) — Tasks 6, 7. ✓ (SQLite for tests; same
  models run on Postgres via `DATABASE_URL` — `make_engine` branches on the URL.)
- L7 backtest harness subset (spec §11 Phase 0) — Task 9. ✓
- Phase 0 gate "reproduces known historical prices" — Task 9 Step 1 gate test. ✓
- Out of Phase 0 scope (correctly deferred): research modules, strategies, risk,
  execution, dashboard, live WebSocket feed, Alembic migrations.

**2. Placeholder scan:** No TBD/TODO/"handle edge cases" — every code step
contains complete, runnable code; every command has expected output. ✓

**3. Type consistency:** `MarketDTO`/`PricePoint`/`PriceHistory` (Task 4) are
consumed unchanged by the client (Task 5), repository (Task 7), and ingest
(Task 8). `PriceHistory.token_id` is used as the `token_id` argument throughout.
ORM `Market`/`PriceSnapshot` columns (Task 6) match the fields written by
`upsert_market`/`save_price_history` (Task 7). `ReplayEvent(ts, token_id, price)`
(Task 9) matches its test assertions. `make_session_factory` returns
`sessionmaker[Session]`, the type `IngestService` expects. ✓
