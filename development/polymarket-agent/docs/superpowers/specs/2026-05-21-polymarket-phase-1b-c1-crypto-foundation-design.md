# Polymarket Agent — Phase 1B-C1: Crypto Foundation (OHLCV + GARCH + Barrier-Bridge) — Design Spec

**Date:** 2026-05-21
**Phase:** 1B-C1 (first sub-plan of Phase 1B — crypto-category L3 module foundation)
**Parent specs:**
- `2026-05-19-polymarket-fair-value-agent-design.md` (overall project design)
- `2026-05-20-polymarket-phase-1a-l7-validation-gate-design.md` (validation framework this plugs into)

**Builds on:** Phase 1A (PR #5, branch `feat/polymarket-phase-1a`).

---

## 1. Goal & Scope

### 1.1 Goal

Build the foundation layer of the crypto-category L3 module for the Polymarket
fair-value trading agent: persistent crypto OHLCV ingestion, GARCH(1,1)
volatility estimator, and a closed-form one-touch barrier-hit probability
calculator. C1 delivers building blocks; C2 composes them into a Polymarket-
consuming model; C3 runs the alpha test against real markets.

### 1.2 Alpha thesis (set in Phase 1B brainstorming)

**Polymarket crypto barrier markets ("Will BTC reach $X by date Y?") over-react
to shocks in the underlying spot/vol, then mean-revert toward the rational
barrier-hit probability.** A vol-aware fair-value estimator that recomputes the
barrier-hit probability with current GARCH vol should outperform the
last-traded-price baseline immediately after shocks.

C1 builds the calculator. C2 builds the model around it. C3 tests the thesis.

### 1.3 In scope (C1)

- `agent/data/crypto_client.py` — async Binance public-API client (klines
  endpoint), same pattern as Phase 0's `PolymarketClient`. Reuses Phase 0's
  `TokenBucket` for rate limiting.
- `agent/data/crypto_ingest.py` — `CryptoIngestService` mirroring `IngestService`.
  Backfill + incremental fetch for both 1h and 1d bars.
- `agent/data/models.py` extension — add `CryptoBarDTO` with
  `from_binance_kline(...)` classmethod.
- `agent/store/schema.py` extension — new `CryptoBar` ORM model with
  `UniqueConstraint("symbol", "granularity", "ts")`.
- `agent/store/repository.py` extension — `save_crypto_bars(...)` mirroring
  `save_price_history`'s skip-existing dedup.
- `agent/research/crypto/vol_estimator.py` — `fit_garch11(...)` wrapping
  `arch.arch_model`, returning a frozen `GARCHResult` dataclass.
- `agent/research/crypto/barrier_bridge.py` — `prob_barrier_hit(...)` closed-form
  one-touch via the reflection principle.
- `forecast_garch_annualized_vol(...)` — module-level helper for multi-horizon
  GARCH forecasts.

### 1.4 Out of scope (deferred to C2 / later)

- Composite `crypto_model(market_id, event) -> Prediction` — that's the C2 task.
- Shock detector (spot-return-based and news-based) — C2.
- News-feed ingestion — C2.
- Monte Carlo barrier calculator — needed only if closed-form proves insufficient
  in C3.
- LSTM vol estimator — deferred extension if GARCH underperforms in C3.
- CLI subcommand additions — Phase 1A's CLI wireframes don't need crypto-specific
  subcommands until C2 has a model to backtest.

### 1.5 Completion gate (algorithmic, same discipline as Phase 1A §5)

C1 is complete when `pytest -v` is fully green at ~86 tests (71 prior +
~15 C1), and every §5 reference test passes:
- `prob_barrier_hit` matches hand-computed reference values for 5 cases.
- `fit_garch11` recovers true GARCH params from a 5000-sample synthetic series
  within stated tolerances.
- `BinanceClient` parses the canonical kline-array response and propagates
  HTTP errors.
- `CryptoIngestService` paginates correctly and is idempotent.
- `save_crypto_bars` enforces uniqueness and is idempotent.
- `CryptoBar` round-trips through a fresh session.
- `forecast_garch_annualized_vol` recursion converges to the long-run variance.

---

## 2. Architecture & Module Structure

### 2.1 Repository layout (extends Phase 0 + Phase 1A)

```
agent/
  data/
    crypto_client.py             # NEW: BinanceClient (httpx, public klines endpoint)
    crypto_ingest.py             # NEW: CryptoIngestService (backfill + incremental)
    models.py                    # EXTEND: add CryptoBarDTO
  store/
    schema.py                    # EXTEND: add CryptoBar ORM model
    repository.py                # EXTEND: add save_crypto_bars()
  research/
    crypto/                      # NEW: per-category research subpackage
      __init__.py
      vol_estimator.py           # NEW: fit_garch11() via arch.arch_model
      barrier_bridge.py          # NEW: prob_barrier_hit() closed-form one-touch
tests/
  data/
    test_crypto_client.py        # NEW: respx-mocked Binance klines responses
    test_crypto_ingest.py        # NEW: respx + in-memory SQLite integration
  store/
    test_schema.py               # EXTEND: CryptoBar round-trip + uniqueness
    test_repository.py           # EXTEND: save_crypto_bars idempotency
  research/
    crypto/
      __init__.py
      test_vol_estimator.py      # NEW: synthetic-GARCH-series parameter recovery
      test_barrier_bridge.py     # NEW: closed-form vs hand-computed references
```

### 2.2 Architectural seam to Phase 1B-C2

None of the Phase 1B-C1 components reference `Prediction`, `MarketDTO`, or the
L7 framework. C1 produces a vol estimator and a barrier calculator; C2 composes
them with Polymarket market data to produce `Prediction`s consumable by Phase 1A's
`walk_forward_backtest`. The seam is intentionally narrow — C1's outputs are pure
numerical functions, easy to test in isolation, easy to swap (e.g., LSTM-vol
replacing GARCH-vol) without touching the rest of the system.

### 2.3 Key structural decisions

1. **Crypto subpackage** (`agent/research/crypto/`) rather than flat
   `agent/research/crypto_vol.py + crypto_bridge.py`. Anticipates C2 adding
   `shock_detector.py` and `model.py` to the same subpackage; clean namespace.
2. **DTO mirrors ORM, both in same architectural layer** — same pattern as Phase 0's
   `MarketDTO` ↔ `Market`.
3. **Two new dependencies in `pyproject.toml`:** `arch>=7.0` (GARCH).
   `pandas>=2.0` will come transitively via `arch`. ~50 MB total.

---

## 3. Data Model

All ORM models use SQLAlchemy 2.0 `Mapped[...]` / `mapped_column`. All DTOs use
pydantic v2 `BaseModel`. All result records use `@dataclass(frozen=True)` —
consistent with Phase 1A's types.py convention.

### 3.1 ORM model (extends `agent/store/schema.py`)

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

The composite index on `(symbol, granularity, ts)` via the unique constraint
serves the common query `WHERE symbol = ? AND granularity = ? ORDER BY ts ASC`
directly.

### 3.2 DTO (extends `agent/data/models.py`)

```python
class CryptoBarDTO(BaseModel):
    """A crypto OHLCV bar, normalized from Binance's klines API."""

    symbol: str
    granularity: Literal["1h", "1d"]
    ts: int                            # unix seconds (UTC)
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

### 3.3 GARCH result (new in `agent/research/crypto/vol_estimator.py`)

```python
@dataclass(frozen=True)
class GARCHResult:
    """Fitted GARCH(1,1) parameters + diagnostic values.

    Convention: returns and conditional_vol are at the same granularity as the
    input (so 1h bars -> hourly returns -> hourly conditional vol).
    `periods_per_year` records the annualization factor so callers can convert
    period-vol to annualized vol consistently.
    """

    omega: float                       # variance-equation constant
    alpha: float                       # lagged squared-return coefficient
    beta: float                        # lagged variance coefficient
    persistence: float                 # alpha + beta (must be < 1 for stationarity)
    n_obs: int                         # number of returns the fit used
    periods_per_year: int              # 8760 for 1h bars, 365 for 1d bars
    long_run_variance: float           # omega / (1 - alpha - beta), period units
    current_conditional_vol: float     # next-period vol forecast, ANNUALIZED
                                       # (already multiplied by sqrt(periods_per_year))
```

Two contract decisions worth flagging:

1. **`current_conditional_vol` is annualized at construction time.** Phase 1A's
   barrier-bridge takes `annualized_vol`; we annualize once at the GARCH-result
   boundary so callers don't have to remember to do it. Period-unit
   `long_run_variance` remains available for diagnostics.

2. **No `conditional_vol_series` field in the frozen dataclass.** The full
   in-sample series (~4400 floats for 6 months of hourly bars) bloats the
   dataclass and isn't needed by C2's barrier-bridge consumer. If diagnostics
   need it, expose via a separate `fit_garch11_with_diagnostics(...)` function.

### 3.4 Multi-horizon forecast helper (module-level)

```python
def forecast_garch_annualized_vol(
    result: GARCHResult,
    horizon_periods: int,
) -> float:
    """Iterative GARCH(1,1) variance forecast `h` periods ahead, then annualized.

    σ²(t+h) = long_run_variance + persistence^h * (σ²(t+1) - long_run_variance)

    For the constant-vol barrier-bridge approximation, callers typically use:
      - horizon_periods=1 (most shock-reactive — recommended for our thesis)
      - horizon_periods = time_to_resolution / period_length (forward-looking
        "vol over the remaining horizon")

    Raises ValueError if horizon_periods <= 0.
    """
```

Module-level function rather than a method on the frozen dataclass: frozen-
dataclass methods can't cache computed values without violating the frozen
contract.

---

## 4. Components

### 4.1 `agent/data/crypto_client.py` — async Binance client

```python
class BinanceClient:
    """Read-only async client for Binance's public klines endpoint.

    Same architectural pattern as PolymarketClient: caller owns the
    httpx.AsyncClient lifecycle and injects a TokenBucket for rate limiting.
    """

    BASE_URL = "https://api.binance.com"
    KLINES_PATH = "/api/v3/klines"
    MAX_KLINES_PER_REQUEST = 1000   # Binance enforces; capped at 1000

    def __init__(
        self,
        http_client: httpx.AsyncClient,
        rate_limit_bucket: TokenBucket | None = None,
    ) -> None:
        self._http = http_client
        # Binance IP weight limit is 1200/min; klines is 2 weight when limit > 500.
        # 60 capacity, 1 refill/sec gives us 60/min sustainable — well under 600.
        self._bucket = rate_limit_bucket or TokenBucket(
            capacity=60, refill_per_second=1.0
        )

    async def get_klines(
        self,
        symbol: str,
        interval: str,            # "1h" | "1d"
        *,
        start_ts: int | None = None,   # unix seconds (UTC)
        end_ts: int | None = None,
        limit: int = 1000,
    ) -> list[CryptoBarDTO]:
        """Fetch up to `limit` klines.  Times are converted to milliseconds
        internally for the Binance API.  Returns bars in ascending-ts order."""
```

The 60/min sustainable rate is intentionally conservative — Binance's actual
public-IP limit is ~600 requests/min on the klines endpoint, but we don't need
that bandwidth for backfilling 6 months at 1h granularity (~5 paginated
requests per symbol).

### 4.2 `agent/data/crypto_ingest.py` — pagination + dedup orchestration

```python
class CryptoIngestService:
    """Backfill historical klines and incrementally append latest bars."""

    def __init__(
        self,
        client: BinanceClient,
        session_factory: sessionmaker[Session],
    ) -> None: ...

    async def ingest_history(
        self,
        symbol: str,
        granularity: str,         # "1h" | "1d"
        start_ts: int,
        end_ts: int,
    ) -> int:
        """Paginate through Binance klines from start_ts to end_ts,
        upserting via save_crypto_bars (idempotent).  Returns count of
        newly-inserted bars (already-present bars skipped silently).

        Pagination: 1000 bars per request; for 1h granularity that's
        ~41 days per request; for 1d, ~2.7 years.  Most backfills are
        one or two requests.
        """

    async def ingest_latest(
        self,
        symbol: str,
        granularity: str,
    ) -> int:
        """Fetch the most-recent ~100 bars and upsert.  For incremental
        updates after the initial backfill.  Returns count newly inserted."""
```

Sequential `await client.get_klines(...)` inside the loop — no concurrent
request fan-out in C1.

### 4.3 `agent/store/repository.py` — `save_crypto_bars` (extension)

```python
def save_crypto_bars(
    session: Session,
    bars: Iterable[CryptoBarDTO],
) -> int:
    """Persist new bars; skip (symbol, granularity, ts) tuples already stored.

    Returns the count of newly-inserted bars.  Caller is responsible for
    commit (same convention as save_price_history).
    """
```

Same skip-existing pattern as `save_price_history`: load existing `(symbol,
granularity, ts)` set into memory, iterate incoming bars, add only new ones,
return count.

### 4.4 `agent/research/crypto/vol_estimator.py` — `fit_garch11`

```python
def fit_garch11(
    returns: Sequence[float],
    *,
    periods_per_year: int,
    rescale: bool = True,
) -> GARCHResult:
    """Fit GARCH(1,1) on a sequence of period returns (simple percentage
    returns; arch's convention).

    Wraps `arch.arch_model(returns, vol='GARCH', p=1, q=1, rescale=rescale)`
    with .fit(disp='off').  Returns a GARCHResult with all fields populated.

    Parameters:
      returns:           Sequence of period returns (e.g., (close_t - close_{t-1}) / close_{t-1})
      periods_per_year:  Annualization factor.  8760 for 1h bars, 365 for 1d bars.
      rescale:           arch's auto-rescaling helps optimizer convergence on
                         small returns; keep True unless debugging.

    Raises:
      ValueError if len(returns) < 100 (GARCH needs reasonable sample size)
      ValueError if any return is NaN or inf

    Note: `arch.utility.exceptions.ConvergenceWarning` is propagated as a
    warning, NOT raised — caller can decide to retry or accept.
    """
```

Why `rescale=True`: crypto hourly returns are typically O(0.001-0.01); `arch`'s
optimizer struggles with small magnitudes unless they're scaled to roughly unit
variance during fitting. The `rescale` flag handles this internally and un-scales
the returned parameters — `GARCHResult.omega`, `.alpha`, `.beta`, and
`.long_run_variance` are in the original return's period units.
`.current_conditional_vol` is the only field that's annualized (multiplied by
`sqrt(periods_per_year)` at construction time per §3.3).

### 4.5 `agent/research/crypto/barrier_bridge.py` — `prob_barrier_hit`

```python
def prob_barrier_hit(
    spot: float,
    barrier: float,
    time_remaining_years: float,
    annualized_vol: float,
    annualized_drift: float = 0.0,
) -> float:
    """Closed-form probability that a GBM with given drift and vol touches
    `barrier` at any point in [0, time_remaining_years], starting from `spot`.

    Uses the reflection principle.  Let:
      nu = annualized_drift - annualized_vol**2 / 2      (log-drift)
      b  = ln(barrier / spot)                            (log-barrier distance)
      v  = annualized_vol * sqrt(time_remaining_years)   (total vol over horizon)

    For an UP-barrier (barrier > spot, b > 0):
      P = N((nu*T - b)/v) + exp(2*nu*b/annualized_vol**2) * N((-nu*T - b)/v)

    For a DOWN-barrier (barrier < spot, b < 0), the symmetric form:
      P = N((b - nu*T)/v) + exp(2*nu*b/annualized_vol**2) * N((b + nu*T)/v)

    N(x) is the standard normal CDF, computed via 0.5 * (1 + erf(x / sqrt(2))).

    Edge cases:
      - barrier == spot: returns 1.0 (already touching, by convention).
      - time_remaining_years <= 0: returns 1.0 if barrier already hit, else 0.0.
      - annualized_vol <= 0: returns 0.0 unless drift carries spot past barrier
        deterministically (then 1.0).

    Drift convention: annualized_drift = 0 for risk-neutral Polymarket pricing
    (our thesis is calibration relative to the market, not absolute fair value).
    Phase 1C may revisit if absolute-pricing edge becomes the strategy.
    """
```

Default `annualized_drift=0.0` reflects our agnostic stance: we're not claiming
to forecast BTC direction, only its volatility regime. The "alpha" comes from
comparing our vol-aware probability to Polymarket's price, not from a
directional bet.

---

## 5. Acceptance Criteria — the Algorithmic Gate

C1 is complete when every test below passes. Same discipline as Phase 1A §5.

### 5.1 `prob_barrier_hit` reference cases

| # | Case | Inputs | Expected |
|---|---|---|---|
| 1 | Already touching | `spot=100, barrier=100, T=1.0, vol=0.3` | `1.0` |
| 2 | Zero time, up-barrier above spot | `spot=100, barrier=110, T=0.0, vol=0.3` | `0.0` |
| 3 | Zero time, down-barrier below spot | `spot=100, barrier=90, T=0.0, vol=0.3` | `0.0` |
| 4 | Long horizon, μ=0 (NEGATIVE log-drift via ν = μ − σ²/2 = −0.045) | `spot=100, barrier=110, T=1000.0, vol=0.3, drift=0.0` | within `1e-3` of `S₀/B = 100/110 ≈ 0.9091` (Doob's martingale identity); catches missing exp prefactor (without prefactor → ≈ 0) |
| 5 | Log-drift-zero up-barrier (drift = σ²/2): formula reduces to `2·N(-b/v)` | `spot=100, barrier=110, T=1.0, vol=0.3, drift=0.045` | exact value of `2 * N(-ln(1.1)/0.3)` (≈ 0.7507) |

Plus **monotonicity sanity tests** (no specific values):
- `prob_barrier_hit` increases monotonically in `time_remaining_years`.
- `prob_barrier_hit` increases monotonically in `annualized_vol`.
- `prob_barrier_hit` decreases monotonically in `abs(ln(barrier/spot))`.

### 5.2 `fit_garch11` parameter-recovery test

Synthetic GARCH(1,1) series with known true parameters, generated in-test via
a 50-line simulator (not `arch` itself — we want the test to validate `arch`'s
output, not loop back to it):

```python
TRUE_OMEGA = 0.00001
TRUE_ALPHA = 0.05
TRUE_BETA  = 0.92      # persistence = 0.97, typical for crypto
N_OBS = 5000

returns = _generate_garch_series(TRUE_OMEGA, TRUE_ALPHA, TRUE_BETA, N_OBS, seed=42)

result = fit_garch11(returns, periods_per_year=8760)

# Tolerances are wide because GARCH MLE has known wide CIs.
# Beta is the most stably estimated; omega is the noisiest.
assert abs(result.beta  - TRUE_BETA)  / TRUE_BETA  < 0.10
assert abs(result.alpha - TRUE_ALPHA) / TRUE_ALPHA < 0.30
assert abs(result.omega - TRUE_OMEGA) / TRUE_OMEGA < 0.50
assert 0.0 < result.persistence < 1.0        # stationarity invariant
```

Plus a degenerate-input test: `fit_garch11(returns=[0.01]*5, periods_per_year=8760)`
raises `ValueError` (n_obs too small).

### 5.3 `BinanceClient.get_klines` respx-mocked test

Mock Binance returning a 3-bar response in the canonical kline-array shape
(12 fields per row, first 6 being the relevant ones). Assert:
- Request URL is `https://api.binance.com/api/v3/klines`.
- Query params include `symbol`, `interval`, `limit` (and `startTime`/`endTime`
  if provided as kwargs, with ms conversion).
- Returned list has 3 `CryptoBarDTO` instances.
- DTOs have correct fields, `ts` converted from ms → seconds.
- Bars are in ascending-ts order.

Plus error-path: 429 response (rate-limited) raises `httpx.HTTPStatusError`.

### 5.4 `CryptoIngestService` integration test (in-memory SQLite + respx)

Two synthetic-pagination scenarios:

1. **Range fits in one request:** start→end covers ~100 bars. One mocked
   response returns all. Assert ingest returns 100, repository has 100 rows.
2. **Range spans two requests:** 1500 bars. Two mocked responses, 1000 + 500.
   Assert ingest returns 1500, repository has 1500.

Plus idempotency: call `ingest_history` twice with the same range. Second call
returns 0 (all already present), row count unchanged.

### 5.5 `save_crypto_bars` direct test

Without HTTP: construct `CryptoBarDTO`s in-test, call `save_crypto_bars` twice
with same input. First returns N, second returns 0. Verify
`UniqueConstraint("symbol", "granularity", "ts")` enforced by attempting a
duplicate via raw `session.add(CryptoBar(...))` — must raise `IntegrityError`.

### 5.6 `CryptoBar` schema round-trip via fresh session

Same pattern as Phase 1A's `test_market_clob_token_ids_round_trips_through_db`:
write a `CryptoBar` in session A, read it back in session B (two-session
pattern via `session_factory`), assert all fields preserved.

### 5.7 `forecast_garch_annualized_vol` reference cases

Closed-form recursion: `σ²(t+h) = σ²_∞ + ρ^h · (σ²(t+1) − σ²_∞)`. Hand-checkable
for small h:

| Setup | `h` | Expected |
|---|---|---|
| `omega=0.01, alpha=0.1, beta=0.8`, current_conditional_vol (annualized) given | `h=1` | equal to `current_conditional_vol` |
| Same | `h=10` | computed value of σ²(t+10), annualized |
| Same | `h=10000` | converges to `sqrt(long_run_variance * periods_per_year)` within `1e-4` |

Plus invariants: `forecast_garch_annualized_vol(result, horizon_periods=0)`
raises `ValueError` (caller should use `current_conditional_vol` for h=0).

### 5.8 Full-suite green

`pytest -v` from project root: 71 prior (Phase 0 + 1A) + ~15 C1 = **~86 tests
total**, all passing.

**Gate result if 5.1–5.8 pass:** Phase 1B-C1 complete. C2 can compose
`vol_estimator + barrier_bridge + Polymarket data` into a `crypto_model`
callable.

---

## 6. Open Risks

1. **`arch` brings transitive `pandas` (~50 MB).** Acceptable — pandas is
   universally installed in Python data-science environments, and `arch`'s
   `pd.Series` return for conditional vol is convenient. Mitigation: none
   needed; flag in PR description.

2. **GARCH convergence failures on real crypto data.** `arch` may emit
   `ConvergenceWarning` on series with extreme outliers, regime changes, or
   non-stationarity. C1 propagates the warning rather than raising. Mitigation:
   C2 can implement retry-with-different-starting-values if real crypto data
   triggers convergence issues consistently.

3. **Closed-form constant-vol approximation breaks under time-varying vol.**
   The reflection-principle formula assumes σ is constant over the remaining
   horizon. Reality: GARCH says σ mean-reverts. Approximation is best for
   short horizons (days), worst for long horizons (months). Mitigation:
   documented in `prob_barrier_hit`'s docstring; Monte Carlo alternative is a
   future C-extension if C3 alpha-test reveals this is the bottleneck.

4. **Survivorship bias in Binance klines.** `/klines` only returns data for
   currently-listed pairs. Delisted pairs are invisible. Mitigation: BTC and
   ETH are not at delisting risk; if Phase 1C expands to altcoins, this
   becomes a real concern.

5. **Time-zone / timestamp alignment.** Binance returns open-time in ms UTC;
   Polymarket returns ts in seconds UTC. The CryptoBarDTO converter divides by
   1000 explicitly. Mitigation: tested via 5.3.

6. **No persisted `last_ingested_ts` per symbol.** `ingest_latest` always
   fetches the "most recent ~100 bars" rather than "everything since last
   successful ingest." Duplicate work on each call (mitigated by dedup), but
   no cursor table needed in C1. Mitigation: add a `crypto_ingest_state` table
   in C2 if incremental-ingest performance matters.

7. **GARCH on hourly returns may overfit to microstructure.** 1h returns
   include intra-period bid-ask bounce and liquidity-driven spikes.
   Mitigation: optional cleaning step (winsorize at ±5σ) can be added if vol
   estimates look noisy on real data. Not in C1 scope.

---

## 7. Tech Stack Additions

Beyond Phase 0 + Phase 1A's stack, C1 adds:

- **`arch>=7.0`** — GARCH(1,1) MLE estimation. Add to `pyproject.toml` core
  dependencies.
- **`pandas>=2.0`** — transitive via `arch`. Pin explicitly so the version is
  consistent across environments.

No other new dependencies. Async polling reuses Phase 0's `httpx` +
`TokenBucket` patterns.

---

## 8. Plan Decomposition Path

The implementation plan (next document, via `writing-plans`) will decompose
C1 into bite-sized TDD tasks. Anticipated structure:

1. Add `arch` + `pandas` to deps; add `CryptoBarDTO` to `models.py`.
2. Add `CryptoBar` ORM model to `schema.py` + uniqueness/round-trip tests.
3. Add `save_crypto_bars` to `repository.py` + idempotency test.
4. `BinanceClient.get_klines` with respx-mocked test (§5.3).
5. `CryptoIngestService` with respx + in-memory SQLite test (§5.4).
6. `barrier_bridge.prob_barrier_hit` — TDD against the 5 reference cases in
   §5.1, plus the 3 monotonicity tests.
7. `vol_estimator.GARCHResult` dataclass + `fit_garch11` — TDD against the
   parameter-recovery test (§5.2).
8. `forecast_garch_annualized_vol` helper — TDD against §5.7.
9. Final-suite gate test.

Roughly 9 tasks. Same TDD discipline as Phase 0 and Phase 1A (failing test →
implement → pass → commit per task). Subagent-driven execution recommended.
