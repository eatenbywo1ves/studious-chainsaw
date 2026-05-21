# Polymarket Agent — Phase 1B-C2: Composite Crypto Model (Shock Detector + News Aggregator + Composition Pipeline) — Design Spec

**Date:** 2026-05-21
**Phase:** 1B-C2 (second sub-plan of Phase 1B — crypto-category L3 module composition layer)
**Parent specs:**
- `2026-05-19-polymarket-fair-value-agent-design.md` (overall project design)
- `2026-05-20-polymarket-phase-1a-l7-validation-gate-design.md` (validation framework this plugs into)
- `2026-05-21-polymarket-phase-1b-c1-crypto-foundation-design.md` (math primitives this composes)

**Builds on:** Phase 1B-C1 (branch `feat/polymarket-phase-1b-c1`, tip `dc6c25a6`, 107 tests green).

---

## 1. Goal & Scope

### 1.1 Goal

Compose the Phase 1B-C1 math primitives (Binance OHLCV ingestion, GARCH(1,1)
vol estimator, closed-form barrier-hit calculator) into a callable
`crypto_model(market_id, event) -> Prediction` that Phase 1A's
`walk_forward_backtest` can consume on real Polymarket crypto barrier markets.

C2 builds three things in service of that goal:
1. A multilingual news aggregator that detects shocks in the underlying.
2. A shock detector that combines spot-return and news signals in three modes.
3. A consolidated composition pipeline (4 composer modes + Bayesian blender +
   agreement filter + asymmetric tilt + Kelly sizer) that turns `P_market` and
   `P_bridge` into a final `Prediction` with position size.

C3 then runs the alpha test against 5-20 real markets using the pipeline.

### 1.2 Alpha thesis (carried forward from Phase 1B brainstorming)

**Polymarket crypto barrier markets ("Will BTC reach $X by date Y?") over-react
to vol shocks in the underlying spot and confirming news, then mean-revert
toward the rational barrier-hit probability.** C1 built the rational
probability calculator. C2 detects shocks and composes the calculator with
the market price into a prediction that captures the over-reaction.

### 1.3 In scope (C2)

**Data layer additions:**
- `agent/data/news_client.py` — abstract `NewsClient` interface + four
  implementations: `CryptoPanicClient`, `RSSClient` (multi-source), `RedditClient`,
  `TelegramClient` (MTProto via telethon, 8-12 channels across RU/FA/ZH/DE/FR/EN).
- `agent/data/news_ingest.py` — `NewsIngestService` (paginated backfill + live
  polling + idempotent dedup), mirroring `CryptoIngestService` from C1.
- `agent/data/models.py` extension — add `NewsEventDTO`, `TradeRecordDTO`,
  `ModePerformanceRecordDTO`.
- `agent/store/schema.py` extension — `NewsEvent` + `NewsCurrencyTag` +
  `ModePerformance` + `TradeRecord` ORM models.
- `agent/store/repository.py` extension — `save_news_events`, `record_trade`,
  `record_mode_brier`, query helpers for trailing-window aggregates.

**Translation + severity layer:**
- `agent/research/crypto/news_filter.py` — `is_candidate(event)` returns
  True only if `(currency_mention AND any_shock_keyword)` in the event's
  native language. Pre-filter before translation.
- `agent/research/crypto/translator.py` — `Translator` interface +
  `OpenAITranslator` default implementation + on-disk cache.
- `agent/research/crypto/severity_scorer.py` — rule-based scoring of
  candidate events: `severity = source_weight * currency_count *
  keyword_strength * recency_factor`.
- `agent/research/crypto/shock_lexicons/{en,ru,fa,zh,de,fr}.yaml` — per-language
  shock-keyword dictionaries.

**Shock detector layer:**
- `agent/research/crypto/shock_detector.py` — abstract `ShockDetector` interface
  + three implementations: `SpotOrNewsShockDetector` (OR fusion),
  `SpotAndNewsShockDetector` (AND fusion), `WeightedScoreShockDetector` (linear blend).

**Composition pipeline (the consolidated design):**
- `agent/research/crypto/composers.py` — `Composer` interface + four
  implementations: `BinaryComposer` (window=14 days), `ExponentialComposer`
  (tau=7 days), `MagnitudeTiedComposer` (severity-scaled lambda_0, tau=7),
  `ConfidenceWeightedComposer` (sigmoid on divergence).
- `agent/research/crypto/blender.py` — `BayesianBlender` (Brier-weighted
  aggregation, 15-trade trailing window, 0.10 time-decayed floor, 3-trade
  cold-start, mode-disable at trailing Brier > 0.25).
- `agent/research/crypto/agreement_filter.py` — `AgreementFilter` (epsilon=0.08,
  3-of-4 directional agreement, strict counting).
- `agent/research/crypto/asymmetric_tilt.py` — `AsymmetricTilt` (+0.05 added
  to P_blend when `P_bridge > P_market`, identity otherwise).
- `agent/research/crypto/kelly_sizer.py` — `KellySizer` (half-Kelly,
  variance = `P_final * (1 - P_final)`, position size returned as fraction of
  available capital).
- `agent/research/crypto/performance_tracker.py` — `PerformanceTracker`
  (loads trailing-N closed trades per mode; computes trailing Brier averages;
  emits weights and disable-flags for the blender).
- `agent/research/crypto/model.py` — `crypto_model(market_id, event,
  *, polymarket_state, shock_detector, composers, blender,
  agreement_filter, tilt, sizer, performance_tracker) -> Prediction`.
  This is the top-level callable that walk_forward_backtest consumes.

**Market mapping:**
- `agent/research/crypto/markets.yaml` — hand-curated mapping from Polymarket
  market ID to `(symbol, barrier_price, direction, resolution_ts)`. Starts with
  5-20 BTC and ETH barrier markets.
- `agent/research/crypto/market_resolver.py` — loads `markets.yaml`, exposes
  `MarketResolver` class with `.resolve(market) -> CryptoMarketMapping | None`
  and `.time_to_resolution_years(mapping, now_ts) -> float`. Time-to-resolution
  computed from `Market.end_date_iso` parsed to Unix seconds.

**Config:**
- `agent/research/crypto/shock_config.yaml` — runtime selection of fusion
  mode (`or` | `and` | `weighted`) + thresholds (`spot_threshold_k`,
  `news_window_minutes`, weighted fusion's `w_spot`/`w_news`/`threshold`).

### 1.4 Out of scope (deferred to C3 or beyond)

- The alpha test itself: running the pipeline on real markets and producing
  edge/calibration statistics. That is C3.
- Multilingual news vendor backfill (LunarCrush, CryptoCompare): considered
  during brainstorm, deferred — backfill comes from Telegram MTProto scroll-back
  plus live-collection of the remaining sources from C2 deploy onward.
- Local-model translation (NLLB-200): not built in C2; OpenAI API used.
  Local-model swap deferred to C2.1 if API cost grows materially.
- L5 risk module from Phase 2: KellySizer in C2 handles its own position-size
  bounding via half-Kelly; broader risk policy (cross-market exposure caps,
  drawdown limits) is Phase 2's job.
- L6 execution / order routing: C2 produces `Prediction`s; the harness for
  feeding them to Polymarket fills is Phase 2.
- LSTM volatility estimator: deferred extension if GARCH underperforms in C3.
- News-shock detector by sentiment LLM: rule-based scoring in C2; LLM-based
  scoring is a C2.1 candidate.
- Mode 4 floor calibration via shorter trailing windows or Option-β outlier
  veto: known follow-up if C3 shows insufficient Mode-4 throttling.
- Composition Option-γ (separate entry vs. stay-in filters): tighter
  parameters (Option α) chosen in brainstorm. Option γ is a C2.1 candidate if
  C3 reveals filter still kicks in too slowly during regime changes.

### 1.5 Completion gate (algorithmic, same discipline as Phase 1A §5 and C1 §5)

C2 is complete when `pytest -v` is fully green at ~250 tests (107 prior +
~140 C2), and every §7 reference test passes:
- `is_candidate` and per-language shock lexicons correctly filter candidate
  vs. non-candidate news in 8 reference cases per language (48 total cases).
- `severity_scorer` matches hand-computed reference scores in 6 cases.
- `ShockDetector` produces correct shock states in 12 reference scenarios
  (4 per fusion mode covering positive, negative, threshold-boundary, and
  no-shock cases).
- Each of the 4 `Composer`s matches hand-computed `P_mode` in 4 reference
  scenarios (16 total).
- `BayesianBlender` weight evolution matches reference values across a 30-
  trade simulated sequence (Mode 4 honeymoon → regime change → recovery).
- `AgreementFilter` correctly allows/vetoes in 12 reference scenarios per
  the brainstorm walkthrough (entry-tick, mid-regime-change, no-shock, etc.).
- `AsymmetricTilt` returns identity outputs when `P_bridge <= P_market` in 4
  cases; adds exactly 0.05 (clipped to [0,1]) when `P_bridge > P_market` in 4
  cases.
- `KellySizer` matches hand-computed half-Kelly fractions in 8 reference cases
  including the COVID-style and FTX-style scenarios from the brainstorm
  walkthroughs.
- `crypto_model` produces correct `Prediction`s end-to-end in 6 integration
  scenarios.
- All ORM round-trips, idempotent ingest patterns, and unique-constraint
  enforcements (per §3) green.

---

## 2. Architecture & Module Structure

### 2.1 Repository layout (extends Phase 0 + Phase 1A + Phase 1B-C1)

```
agent/
  data/
    news_client.py               # NEW: NewsClient abstract + 4 implementations
    news_ingest.py               # NEW: NewsIngestService
    models.py                    # EXTEND: NewsEventDTO, TradeRecordDTO, ModePerformanceRecordDTO
  store/
    schema.py                    # EXTEND: NewsEvent, NewsCurrencyTag, ModePerformance, TradeRecord ORM
    repository.py                # EXTEND: save_news_events, record_trade, record_mode_brier, query helpers
  research/
    crypto/
      # ---- carried forward from C1 ----
      __init__.py
      vol_estimator.py
      barrier_bridge.py
      # ---- NEW in C2: market mapping ----
      markets.yaml               # NEW: hand-curated Polymarket -> (symbol, barrier, direction, resolution_ts)
      market_resolver.py         # NEW: loads markets.yaml; time-to-resolution helpers
      shock_config.yaml          # NEW: runtime fusion mode + thresholds
      # ---- NEW in C2: news filter + translation + severity ----
      news_filter.py             # NEW: is_candidate(event) gate
      translator.py              # NEW: Translator interface + OpenAITranslator + on-disk cache
      severity_scorer.py         # NEW: rule-based severity scoring
      shock_lexicons/
        en.yaml                  # NEW: English shock keywords
        ru.yaml                  # NEW: Russian shock keywords
        fa.yaml                  # NEW: Farsi shock keywords
        zh.yaml                  # NEW: Chinese shock keywords
        de.yaml                  # NEW: German shock keywords
        fr.yaml                  # NEW: French shock keywords
      # ---- NEW in C2: shock detector ----
      shock_detector.py          # NEW: ShockDetector abstract + 3 fusion modes
      # ---- NEW in C2: composition pipeline ----
      composers.py               # NEW: Composer abstract + 4 modes
      blender.py                 # NEW: BayesianBlender (Brier-weighted)
      agreement_filter.py        # NEW: AgreementFilter (epsilon-thresholded)
      asymmetric_tilt.py         # NEW: AsymmetricTilt (long-only, +0.05)
      kelly_sizer.py             # NEW: KellySizer (half-Kelly)
      performance_tracker.py     # NEW: PerformanceTracker (trailing Brier + weights)
      model.py                   # NEW: crypto_model(...) top-level callable
tests/
  data/
    test_news_client.py          # NEW: respx-mocked HTTP for CryptoPanic, RSS, Reddit; pytest-mock for Telegram MTProto
    test_news_ingest.py          # NEW: integration with in-memory SQLite + mocked clients
  store/
    test_schema.py               # EXTEND: NewsEvent/NewsCurrencyTag/ModePerformance/TradeRecord round-trips
    test_repository.py           # EXTEND: idempotency + uniqueness + trailing-window queries
  research/
    crypto/
      test_news_filter.py        # NEW: 48 per-language candidate-filter cases
      test_severity_scorer.py    # NEW: 6 reference scoring cases
      test_translator.py         # NEW: respx-mocked OpenAI API + cache hit/miss
      test_shock_detector.py     # NEW: 12 fusion-mode scenarios
      test_composers.py          # NEW: 16 mode-output reference cases
      test_blender.py            # NEW: 30-trade simulation matching reference weights
      test_agreement_filter.py   # NEW: 12 filter-decision scenarios
      test_asymmetric_tilt.py    # NEW: 8 tilt-output cases
      test_kelly_sizer.py        # NEW: 8 reference Kelly fractions
      test_performance_tracker.py # NEW: window-rotation + Brier-floor + disable-flag tests
      test_market_resolver.py    # NEW: YAML-load + time-to-resolution edge cases
      test_model.py              # NEW: 6 end-to-end Prediction integration tests
```

### 2.2 Architectural seam from C1 and to C3

**From C1:** C2 reads C1's outputs as pure inputs. Three contracts:

1. `GARCHResult.current_conditional_vol` is **annualized**. C2 passes it
   directly to `prob_barrier_hit(annualized_vol=...)` with no conversion.
2. `prob_barrier_hit(spot, barrier, T, vol, drift=0)` handles up- and
   down-barriers transparently via spot-vs-barrier comparison. C2 doesn't
   need conditional logic for direction.
3. `CryptoIngestService.ingest_history` is idempotent. C2 freely calls it
   without state tracking.

**To C3:** C2's deliverable is the `crypto_model(market_id, event, ...)` callable.
C3 plugs it into Phase 1A's `walk_forward_backtest(market_id, replay_event ->
prediction)` contract. The seam is intentionally narrow: C2 produces
`Prediction`s; C3 consumes them and produces edge/calibration statistics.

### 2.3 Key structural decisions

1. **Consolidated pipeline architecture, not winner-pick.** The brainstorm
   resolved that we always blend the 4 composers via the Bayesian blender
   rather than picking one mode per market. This converts the design from a
   selection problem (overfit risk) to an aggregation problem (well-studied,
   self-correcting). Every architectural choice flows from this.

2. **Pure-function pipeline.** Each layer of the composition pipeline
   (composer, blender, filter, tilt, sizer) is a pure function from typed
   inputs to typed outputs. State (mode performance history, market mapping)
   lives outside the pipeline in `PerformanceTracker` and `markets.yaml`.
   This makes each layer independently testable without spinning up the
   rest of the system.

3. **Three shock fusion modes selectable via config.** The shock detector's
   internal fusion (OR / AND / weighted) is runtime-selectable via
   `shock_config.yaml`. The brainstorm chose to expose all three modes
   because we genuinely don't know which is best — C3 will sweep them
   empirically and tune `spot_threshold_k` / `news_window_minutes` /
   weighted-fusion coefficients per mode.

4. **Pre-filter before translate.** Translation cost is the dominant
   operational expense (a $100-capital project can't sustain $50-200/day
   in OpenAI API calls). Per-language shock lexicons gate which events get
   translated, cutting volume ~100x. Lexicons live in YAML — both
   machine-readable and human-auditable.

5. **Telegram-heavy backfill, collect-now for others.** Backtest data gap
   resolved in brainstorm: Telegram MTProto scroll-back gives 6-12 months of
   history for free; CryptoPanic/RSS/Reddit start collecting from C2 deploy
   onward. C3's first alpha test runs with Telegram-only news signal, then
   broadens as other sources accumulate history.

6. **Bug-defense discipline carried forward from C1.** Every test case has
   hand-computed reference values where math is involved. Math-justified
   assertions catch missing prefactors, sign errors, unit confusions.
   Structural unit-clarity for new types (e.g., `Severity` is a frozen
   dataclass with `score: float in [0, 1]`, prevents accidentally treating
   it as a probability).

7. **New dependencies in `pyproject.toml`:**
   - `feedparser>=6.0` (RSS feed parsing)
   - `telethon>=1.34` (Telegram MTProto client)
   - `asyncpraw>=7.7` (async Reddit API)
   - `openai>=1.0` (translation backend; abstract `Translator` interface
     allows swap to local model later)
   - `langdetect>=1.0` (language detection)
   - `pyyaml>=6.0` (lexicons and market mapping)
   - Total addition: ~80 MB.

---

## 3. Data Model

All ORM models use SQLAlchemy 2.0 `Mapped[...]` / `mapped_column`. All DTOs use
pydantic v2 `BaseModel`. All result records use `@dataclass(frozen=True)` —
consistent with Phase 1A and C1 conventions.

### 3.1 ORM models (extend `agent/store/schema.py`)

```python
class NewsEvent(Base):
    """One news/social event from one source in one language.

    `source` is one of "cryptopanic", "rss:<feed>", "reddit:<subreddit>",
    "telegram:<channel>". `language` is the ISO 639-1 code as detected by
    langdetect. `raw_text` is the original-language text; `translated_text`
    is populated lazily by Translator (NULL until first translation).
    `severity_score` is populated by SeverityScorer (NULL until scored).
    """

    __tablename__ = "news_events"
    __table_args__ = (
        UniqueConstraint(
            "source", "external_id", name="uq_news_event"
        ),
        Index("ix_news_events_ts", "ts"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String, index=True)
    external_id: Mapped[str] = mapped_column(String)
    language: Mapped[str] = mapped_column(String(8))
    ts: Mapped[int] = mapped_column(Integer)        # unix seconds (UTC)
    raw_text: Mapped[str] = mapped_column(Text)
    translated_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ingested_at: Mapped[int] = mapped_column(Integer)


class NewsCurrencyTag(Base):
    """Many-to-many: which currencies does this event reference.

    Tag emitted by NewsFilter when (currency_mention AND any_shock_keyword)
    is detected. One event may tag multiple currencies (e.g., a regulatory
    article about both BTC and ETH).
    """

    __tablename__ = "news_currency_tags"
    __table_args__ = (
        UniqueConstraint(
            "news_event_id", "currency", name="uq_news_currency_tag"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    news_event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("news_events.id", ondelete="CASCADE"), index=True
    )
    currency: Mapped[str] = mapped_column(String(16), index=True)  # "BTC", "ETH", ...


class ModePerformance(Base):
    """One record per (mode_name, closed_trade) capturing Brier and outcome.

    Used by PerformanceTracker to compute trailing-window Brier averages.
    Rows are append-only; PerformanceTracker queries the most-recent N rows
    per mode.
    """

    __tablename__ = "mode_performance"
    __table_args__ = (
        Index("ix_mode_performance_mode_closed", "mode_name", "closed_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mode_name: Mapped[str] = mapped_column(String(32), index=True)  # "binary", "exp", "magnitude", "confidence"
    market_id: Mapped[str] = mapped_column(String, index=True)
    p_mode: Mapped[float] = mapped_column(Float)
    p_market_at_prediction: Mapped[float] = mapped_column(Float)
    outcome: Mapped[int] = mapped_column(Integer)   # 0 or 1
    brier_score: Mapped[float] = mapped_column(Float)
    closed_at: Mapped[int] = mapped_column(Integer)   # unix seconds


class TradeRecord(Base):
    """Append-only record of every position taken by crypto_model.

    Includes pre-trade pipeline diagnostics so we can audit any losing
    trade end-to-end without re-running the pipeline.
    """

    __tablename__ = "trade_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    market_id: Mapped[str] = mapped_column(String, index=True)
    ts: Mapped[int] = mapped_column(Integer, index=True)
    p_market: Mapped[float] = mapped_column(Float)
    p_bridge: Mapped[float] = mapped_column(Float)
    p_mode_binary: Mapped[float] = mapped_column(Float)
    p_mode_exp: Mapped[float] = mapped_column(Float)
    p_mode_magnitude: Mapped[float] = mapped_column(Float)
    p_mode_confidence: Mapped[float] = mapped_column(Float)
    p_blend: Mapped[float] = mapped_column(Float)
    p_final: Mapped[float] = mapped_column(Float)
    agreement_vetoed: Mapped[bool] = mapped_column(Boolean)
    kelly_fraction: Mapped[float] = mapped_column(Float)
    position_size: Mapped[float] = mapped_column(Float)
    shock_active: Mapped[bool] = mapped_column(Boolean)
    shock_severity: Mapped[float | None] = mapped_column(Float, nullable=True)
    mode_weights_json: Mapped[str] = mapped_column(Text)   # JSON dict of mode weights at trade time
```

### 3.2 DTOs (extend `agent/data/models.py`)

```python
class NewsEventDTO(BaseModel):
    """A news/social event, normalized across all news sources."""

    source: str
    external_id: str
    language: str
    ts: int
    raw_text: str
    translated_text: str | None = None
    severity_score: float | None = None
    currencies: list[str] = Field(default_factory=list)
    ingested_at: int


class TradeRecordDTO(BaseModel):
    """A trade decision with full pipeline diagnostics."""

    market_id: str
    ts: int
    p_market: float
    p_bridge: float
    p_mode_binary: float
    p_mode_exp: float
    p_mode_magnitude: float
    p_mode_confidence: float
    p_blend: float
    p_final: float
    agreement_vetoed: bool
    kelly_fraction: float
    position_size: float
    shock_active: bool
    shock_severity: float | None
    mode_weights: dict[str, float]


class ModePerformanceRecordDTO(BaseModel):
    """One closed-trade Brier observation per mode."""

    mode_name: Literal["binary", "exp", "magnitude", "confidence"]
    market_id: str
    p_mode: float
    p_market_at_prediction: float
    outcome: Literal[0, 1]
    brier_score: float
    closed_at: int
```

### 3.3 Result records (`agent/research/crypto/types.py`)

```python
@dataclass(frozen=True)
class ShockState:
    """Output of ShockDetector. `active` is the binary gate; `severity` in [0, 1]
    is the magnitude used by MagnitudeTiedComposer.

    STRUCTURAL DEFENSE: `severity` is a clipped float, NOT a probability.
    It must not be confused with P_market or P_bridge by downstream consumers.
    """

    active: bool
    severity: float            # in [0, 1]; clipped at construction
    spot_signal: bool          # which sub-signals fired (for diagnostics)
    news_signal: bool
    time_since_shock_seconds: int  # 0 when active fires now; grows as shock ages


@dataclass(frozen=True)
class CryptoMarketMapping:
    """One row from markets.yaml resolved to a usable mapping."""

    market_id: str
    symbol: str                # "BTCUSDT" etc.
    barrier_price: float
    direction: Literal["up", "down"]   # is barrier above (up) or below (down) current spot at mapping time
    resolution_ts: int         # unix seconds; computed from Market.end_date_iso


@dataclass(frozen=True)
class ModeWeights:
    """Output of BayesianBlender's weighting step. Always sums to 1.0
    (or all-zero if every mode is disabled — caller treats as 'no-trade').
    """

    w_binary: float
    w_exp: float
    w_magnitude: float
    w_confidence: float

    def is_all_disabled(self) -> bool:
        return self.w_binary == 0.0 and self.w_exp == 0.0 \
            and self.w_magnitude == 0.0 and self.w_confidence == 0.0


@dataclass(frozen=True)
class KellyFraction:
    """Output of KellySizer. `fraction` in [0, 1] is the fraction of available
    capital to bet. `direction` records whether this is a long-YES or long-NO bet.

    STRUCTURAL DEFENSE: `fraction` is bounded to [0, kelly_cap] at
    construction. kelly_cap defaults to 0.10 (10% per trade max) regardless
    of what raw Kelly suggests — additional safety.
    """

    fraction: float
    direction: Literal["yes", "no"]
    raw_kelly_pre_half: float   # pre-half-Kelly multiplier value; for diagnostics
```

---

## 4. Data Layer — News Aggregation

### 4.1 `NewsClient` abstract interface (`agent/data/news_client.py`)

```python
class NewsClient(ABC):
    """Abstract interface to a news source. All implementations return a
    uniform stream of NewsEventDTO regardless of source quirks.

    History-backfill capability varies by source:
      - TelegramClient.backfill_history(): full channel scrollback (free).
      - CryptoPanicClient.backfill_history(): NotImplementedError (~3-5 day API window).
      - RSSClient.backfill_history(): NotImplementedError (most feeds expose 20-50 items).
      - RedditClient.backfill_history(): partial via PRAW top-of-subreddit (~3 months).
    """

    @abstractmethod
    async def fetch_latest(self, since_ts: int) -> list[NewsEventDTO]:
        """Fetch events emitted after `since_ts`. Idempotent re-call returns
        the same events (caller dedups by source + external_id).
        """

    @abstractmethod
    async def backfill_history(
        self, start_ts: int, end_ts: int
    ) -> AsyncIterator[NewsEventDTO]:
        """Stream historical events in [start_ts, end_ts]. Raises
        NotImplementedError if this source lacks historical backfill.
        """
```

### 4.2 `TelegramClient` — primary historical source

```python
class TelegramClient(NewsClient):
    """Telegram public-channel client via telethon (MTProto).

    Channels configured in agent/research/crypto/telegram_channels.yaml.
    Backfill via `iter_messages` scrollback supports 6-12 months easily.

    No API key beyond telethon's session file (one-time setup via telethon's
    interactive `start()` — the operator authenticates a Telegram account,
    session is reused thereafter).
    """

    def __init__(
        self,
        session_path: str,
        channels_yaml_path: str = "agent/research/crypto/telegram_channels.yaml",
    ): ...

    async def fetch_latest(self, since_ts: int) -> list[NewsEventDTO]:
        """Live polling. Per-channel since-ts tracked internally; batch-flushes
        every 30 seconds to limit MTProto round-trips.
        """

    async def backfill_history(
        self, start_ts: int, end_ts: int
    ) -> AsyncIterator[NewsEventDTO]:
        """telethon.client.TelegramClient.iter_messages(channel,
        offset_date=end_ts, reverse=True) until ts < start_ts.
        """
```

Initial channel list (in `telegram_channels.yaml`):

```yaml
# 8-12 channels across languages.  Curatable; add/remove without code change.
- channel: "@forklog"           # ru, mainstream crypto news
  language: ru
  weight: 1.0
- channel: "@bwenews"            # en, real-time market wire (Binance-aligned)
  language: en
  weight: 1.0
- channel: "@whalealert"         # en, on-chain whale movements
  language: en
  weight: 0.7   # high frequency; lower per-message weight
- channel: "@cryptocompare"      # en, structured news
  language: en
  weight: 0.8
- channel: "@8btc_news"          # zh, China-focused crypto news
  language: zh
  weight: 1.0
- channel: "@cryptopanic_news"   # en, mirrors CryptoPanic
  language: en
  weight: 0.6   # redundant with CryptoPanicClient; deduped at storage
- channel: "@btcecho_news"       # de, German crypto coverage (if exists)
  language: de
  weight: 0.7
- channel: "@journalducoin"      # fr, French crypto news (if exists)
  language: fr
  weight: 0.7
# Iran/Russia further channels can be added in C2-B based on operator research
# before C2 deploy.  C2 ships with 5+ channels minimum; the rest are
# discoverable via the YAML config without code changes.
```

### 4.3 `CryptoPanicClient`, `RSSClient`, `RedditClient`

Each implements the `NewsClient` interface; details elided here for spec
brevity but follow the same pattern: `httpx.AsyncClient` (or `asyncpraw`)
+ `TokenBucket` from Phase 0 + DTO normalization + `external_id` derivation
for dedup. RSSClient takes a list of feed URLs in
`rss_feeds.yaml`; default feed list covers CoinDesk EN, 8btc ZH, BTC-Echo DE,
LeJournalDuCoin FR — all curatable via YAML.

### 4.4 `NewsIngestService` — backfill + live loop

```python
class NewsIngestService:
    """Orchestrates news clients into the store. Mirrors CryptoIngestService
    from C1 in shape (idempotent, paginated, batched).

    Pre-translation: events are stored with raw_text only. Translation runs
    lazily — Translator is invoked when severity_scorer or downstream consumer
    accesses translated_text.
    """

    def __init__(
        self,
        clients: list[NewsClient],
        repository: Repository,
        session_factory: Callable[[], Session],
    ): ...

    async def backfill_history(
        self, start_ts: int, end_ts: int
    ) -> dict[str, int]:
        """For each client that supports backfill, stream + save.  Returns
        per-client newly-inserted counts.  Sources without backfill are
        silently skipped (no-op, not an error).
        """

    async def poll_latest(self) -> dict[str, int]:
        """One pass over all clients' fetch_latest(since_ts=last_ts_seen).
        Saves new events. Returns per-client counts. Caller schedules this
        every N minutes via the L8 loop (Phase 2).
        """
```

---

## 5. Translation, Severity, and Shock Detection

### 5.1 `news_filter.py` — pre-translation candidate gate

```python
def is_candidate(event: NewsEventDTO, lexicons: dict[str, Lexicon]) -> bool:
    """Returns True only when both conditions hold in the event's native language:
      1. The text contains at least one currency mention from `lexicons[lang].currencies`.
      2. The text contains at least one shock keyword from `lexicons[lang].shock_keywords`.

    When the language is unknown or has no lexicon, fall back to the English
    lexicon (charitable default — better to over-translate than miss a real shock).

    Currency mentions and shock keywords are case-folded ASCII-normalized
    where possible, then matched as whole-word tokens.  Substring matching is
    avoided to prevent false positives (e.g., "BTC" should not match inside
    "BTCUSDT" futures-pair tickers from market data accidentally included).
    """
```

The lexicons are loaded once at startup from
`agent/research/crypto/shock_lexicons/*.yaml`:

```yaml
# en.yaml (English)
currencies:
  - bitcoin
  - btc
  - ethereum
  - eth
  # ... extensible per market mapping coverage
shock_keywords:
  - hack
  - exploit
  - ban
  - sec
  - halt
  - delist
  - fork
  - crash
  - liquidation
  - bankrupt
  # ... ~30-50 entries
```

```yaml
# ru.yaml (Russian)
currencies:
  - биткоин
  - биткойн
  - btc
  - эфириум
  - eth
shock_keywords:
  - взлом         # hack
  - эксплойт      # exploit
  - запрет        # ban
  - остановка     # halt
  - форк          # fork
  - обвал         # crash
  - ликвидация    # liquidation
  - банкротство   # bankruptcy
  # ... iteratively expanded as operator reviews missed events
```

Same shape for `fa`, `zh`, `de`, `fr`. Lexicons are versioned in git so
expansion history is auditable.

### 5.2 `translator.py` — lazy translation with on-disk cache

```python
class Translator(ABC):
    @abstractmethod
    async def translate(self, text: str, source_lang: str) -> str:
        """Translate to English. Returns the original if source_lang == 'en'."""


class OpenAITranslator(Translator):
    """Default implementation: gpt-4o-mini via openai>=1.0.
    Cache: ~/.cache/polymarket-agent/translations.sqlite keyed by sha256(text)."""

    def __init__(
        self,
        cache_path: str = "~/.cache/polymarket-agent/translations.sqlite",
        model: str = "gpt-4o-mini",
        max_retries: int = 3,
    ): ...

    async def translate(self, text: str, source_lang: str) -> str: ...
```

Caching is sha256(text)-keyed so re-translating identical events (e.g., the
same Telegram message reposted in multiple channels) is free. Cache lives
outside the project's main database to avoid bloating it.

### 5.3 `severity_scorer.py` — rule-based event severity

```python
def score_severity(
    event: NewsEventDTO,
    *,
    source_weights: dict[str, float],
    keyword_strengths: dict[str, float],
    now_ts: int,
) -> float:
    """Compute severity in [0, 1] from event attributes.

    Formula:
      raw = source_weight * (currency_count ** 0.5)
            * sum(keyword_strengths[k] for k in matching_keywords)
            * recency_factor(event.ts, now_ts)
      severity = clip(raw / NORMALIZATION_CONSTANT, 0.0, 1.0)

    Where:
      - source_weight comes from telegram_channels.yaml or per-source defaults
        (CryptoPanic=1.0, Reddit=0.6, RSS=0.8, Telegram per-channel weight).
      - currency_count = how many currencies the event tags (per NewsCurrencyTag).
        sqrt damping prevents N-currency events from saturating.
      - keyword_strengths comes from shock_lexicons; each keyword has a weight
        (default 1.0; high-impact keywords like "hack"/"bankrupt" can be set
        higher).
      - recency_factor = exp(-(now_ts - event.ts) / 3600) — events older than
        an hour decay rapidly.
      - NORMALIZATION_CONSTANT is calibrated so a typical "BTC hacked" event
        from a high-weight source scores ~0.7-0.9.

    Severity is NEVER computed against a probability; it's a magnitude on its
    own scale.  Consumers (MagnitudeTiedComposer, WeightedScoreShockDetector)
    treat it as an input, never compare it to P_market/P_bridge directly.
    """
```

### 5.4 `shock_detector.py` — three fusion modes

```python
class ShockDetector(ABC):
    """Combines spot-shock signal (from GARCH-vol comparison) and news-shock
    signal (from severity scorer) into a ShockState.
    """

    @abstractmethod
    def detect(
        self,
        current_return: float,
        garch_annualized_vol: float,
        period_per_year: int,
        recent_news_events: list[NewsEventDTO],
        now_ts: int,
        last_shock_ts: int | None,
    ) -> ShockState: ...


class SpotOrNewsShockDetector(ShockDetector):
    """Shock fires if EITHER spot move > k * garch-vol OR severity in last
    news_window_minutes >= news_threshold. (OR fusion.)

    Severity for the shock state is max(spot_signal_magnitude, news_severity).
    """

    def __init__(
        self,
        spot_threshold_k: float = 3.0,
        news_window_minutes: int = 30,
        news_threshold: float = 0.5,
    ): ...


class SpotAndNewsShockDetector(ShockDetector):
    """Shock fires ONLY when both signals fire. (AND fusion.)
    Severity = (spot_signal_magnitude + news_severity) / 2.
    """

    def __init__(
        self,
        spot_threshold_k: float = 3.0,
        news_window_minutes: int = 30,
        news_threshold: float = 0.5,
    ): ...


class WeightedScoreShockDetector(ShockDetector):
    """shock_score = w_spot * spot_signal + w_news * news_signal.
    Active when shock_score >= threshold. (Weighted blend.)
    Severity = shock_score (clipped to [0, 1]).
    """

    def __init__(
        self,
        w_spot: float = 0.6,
        w_news: float = 0.4,
        threshold: float = 0.5,
        news_window_minutes: int = 30,
    ): ...
```

The active fusion mode is read from `shock_config.yaml` at startup.
`spot_signal_magnitude` is `abs(current_return) / (garch_annualized_vol /
sqrt(period_per_year))` — number of period-sigmas the return represents.
`news_severity` is the max severity score among events in the news window
that tag a currency relevant to the market under consideration.

---

## 6. Composition Pipeline

The pipeline is a chain of pure functions. Each layer's output is the next
layer's input. State (mode performance, market mapping) flows in via injected
services. The top-level entry point is `crypto_model(...)`; downstream layers
are described in §6.1-§6.6 below in dataflow order.

### 6.1 `composers.py` — four Composer implementations

```python
class Composer(ABC):
    """Produces a single mode's P_mode prediction from inputs."""

    name: str  # "binary" | "exp" | "magnitude" | "confidence"

    @abstractmethod
    def compose(
        self,
        p_market: float,
        p_bridge: float,
        shock_state: ShockState,
    ) -> float:
        """Returns P_mode in [0, 1]."""


class BinaryComposer(Composer):
    """P_mode = P_bridge inside the shock window; P_mode = P_market outside."""

    name = "binary"

    def __init__(self, window_seconds: int = 14 * 86400): ...

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        if shock_state.time_since_shock_seconds < self.window_seconds:
            return p_bridge
        return p_market


class ExponentialComposer(Composer):
    """P_mode = lambda(t) * P_bridge + (1 - lambda(t)) * P_market,
    lambda(t) = exp(-t / tau).  tau = 7 days.
    """

    name = "exp"

    def __init__(self, tau_seconds: int = 7 * 86400): ...

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        t = shock_state.time_since_shock_seconds
        lam = math.exp(-t / self.tau_seconds)
        return lam * p_bridge + (1.0 - lam) * p_market


class MagnitudeTiedComposer(Composer):
    """lambda(t, severity) = clip(severity, 0, 1) * exp(-t / tau).
    Same tau as ExponentialComposer; different lambda_0 scaling.
    """

    name = "magnitude"

    def __init__(self, tau_seconds: int = 7 * 86400): ...

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        t = shock_state.time_since_shock_seconds
        lam = min(max(shock_state.severity, 0.0), 1.0) \
            * math.exp(-t / self.tau_seconds)
        return lam * p_bridge + (1.0 - lam) * p_market


class ConfidenceWeightedComposer(Composer):
    """lambda = sigmoid((|P_market - P_bridge| - threshold) / scale).
    Does NOT use shock_state.time — purely divergence-driven.
    KNOWN HAZARD: can double-down during regime changes.  AgreementFilter is
    the primary safety mechanism (see §6.3); this composer is included
    deliberately so empirical C3 evidence can falsify or confirm the
    over-reaction thesis at extreme divergences.
    """

    name = "confidence"

    def __init__(self, threshold: float = 0.10, scale: float = 0.05): ...

    def compose(self, p_market, p_bridge, shock_state) -> float:
        divergence = abs(p_market - p_bridge)
        if divergence <= 1e-9:
            return p_market
        z = (divergence - self.threshold) / self.scale
        lam = 1.0 / (1.0 + math.exp(-z))
        return lam * p_bridge + (1.0 - lam) * p_market
```

### 6.2 `blender.py` — Bayesian (Brier-weighted) aggregation

```python
@dataclass(frozen=True)
class BlendOutput:
    p_blend: float
    weights: ModeWeights


class BayesianBlender:
    """Aggregates 4 P_mode values into one P_blend using inverse-Brier
    weighting from trailing performance.  Implements:

      score_i = 1 / max(trailing_brier_i, brier_floor_i)
      w_i     = score_i / sum_j(score_j)
      p_blend = sum_i(w_i * p_mode_i)

    Initial weights (cold start): equal 0.25 each until a mode has >= 3
    closed trades.  Once a mode crosses 3 trades, it joins the weighted
    pool while modes with < 3 stay at 0.25 (averaged into the others).

    Brier floor starts at 0.10 (cap any one mode's weight at ~10x of best).
    On each closed trade where a mode's running trailing-Brier exceeds 0.25,
    floor is multiplied by 0.97 for that mode (time-decay toward zero).
    Once a mode's trailing Brier exceeds 0.25 for 30+ consecutive
    closed-trade observations, mode is permanently DISABLED (weight = 0
    forever).
    """

    def __init__(
        self,
        trailing_window: int = 15,
        brier_floor_init: float = 0.10,
        floor_decay: float = 0.97,
        cold_start_min_trades: int = 3,
        disable_brier_threshold: float = 0.25,
        disable_streak_required: int = 30,
    ): ...

    def blend(
        self,
        p_modes: dict[str, float],   # {"binary": ..., "exp": ..., "magnitude": ..., "confidence": ...}
        tracker: PerformanceTracker,
    ) -> BlendOutput:
        """Returns blended probability and the weights used.
        If all modes disabled, weights.is_all_disabled() returns True
        and crypto_model interprets as no-trade (returns P_market).
        """
```

### 6.3 `agreement_filter.py` — directional consensus gate

```python
@dataclass(frozen=True)
class AgreementVerdict:
    allowed: bool
    long_count: int   # how many modes signal long (P_mode > P_market + epsilon)
    short_count: int  # how many modes signal short (P_mode < P_market - epsilon)
    direction: Literal["long", "short", "none"]


class AgreementFilter:
    """Requires >= min_active_count modes to agree on direction before allowing
    a trade.

    epsilon = 0.08 (per brainstorm Option-alpha): mode signals are counted
    only when |P_mode - P_market| > epsilon.  Neutrals don't count toward
    either direction.

    Strict counting: need 3 active longs OR 3 active shorts among the 4
    modes.  Neutrals neither help nor block (they just don't contribute).

    Disabled-mode handling: `p_modes` is passed as a dict of CURRENTLY ENABLED
    modes only (the caller — `crypto_model` — filters out disabled modes
    before calling).  `min_active_count` applies to the dict as passed.  In
    the normal 4-mode case, min_active_count=3 means "3 of 4."  If Mode 4 is
    disabled, only 3 modes pass through, and min_active_count=3 implicitly
    becomes "3 of 3" (full consensus among remaining modes).  This is a
    deliberate property: disabling a mode strengthens the consensus
    requirement among the survivors.
    """

    def __init__(
        self,
        epsilon: float = 0.08,
        min_active_count: int = 3,
    ): ...

    def evaluate(
        self,
        p_market: float,
        p_modes: dict[str, float],   # enabled modes only
    ) -> AgreementVerdict: ...
```

### 6.4 `asymmetric_tilt.py` — long-only +0.05 tilt

```python
class AsymmetricTilt:
    """Adds a constant tilt toward P_bridge ONLY when P_bridge > P_market.
    Otherwise identity. Captures the alpha thesis's one-directional shape:
    we believe Polymarket under-prices barrier-hit probabilities during
    panic, but we do NOT believe it over-prices them in calm.

    Output is clipped to [0, 1] for safety (sum could exceed 1 if P_blend
    is near 1; clipping defends against accidental tilt-into-arbitrage).
    """

    def __init__(self, tilt_magnitude: float = 0.05): ...

    def apply(
        self,
        p_blend: float,
        p_market: float,
        p_bridge: float,
    ) -> float:
        if p_bridge > p_market:
            return min(1.0, max(0.0, p_blend + self.tilt_magnitude))
        return p_blend
```

### 6.5 `kelly_sizer.py` — half-Kelly position sizing

```python
class KellySizer:
    """Computes position size as a fraction of available capital using
    half-Kelly with hard cap.

    For a YES-buy at market price q with our estimate P:
      edge       = P - q                     (positive => buy YES, negative => buy NO)
      variance   = P * (1 - P)               (Bernoulli variance of our estimate)
      raw_kelly  = q * edge / variance       (full Kelly fraction)
      half_kelly = 0.5 * raw_kelly
      fraction   = clip(abs(half_kelly), 0.0, kelly_cap)
      direction  = "yes" if edge > 0 else "no"

    For a NO-buy at price (1-q) with same P, the formula is symmetric.

    kelly_cap defaults to 0.10 — no single trade exceeds 10% of available
    capital regardless of how strong Kelly says the edge is.  This is a hard
    safety, not a tuning parameter.

    Returns KellyFraction(fraction=0.0, ...) when edge magnitude is below
    minimum_edge (default 0.02 — 2 percentage points).  Saves transaction
    cost on trades that are theoretically positive but practically
    uneconomic after slippage.
    """

    def __init__(
        self,
        kelly_multiplier: float = 0.5,
        kelly_cap: float = 0.10,
        minimum_edge: float = 0.02,
    ): ...

    def size(
        self,
        p_final: float,
        p_market: float,
    ) -> KellyFraction: ...
```

### 6.6 `performance_tracker.py` — trailing Brier per mode

```python
class PerformanceTracker:
    """Loads each mode's trailing-N closed trades from ModePerformance and
    computes (trailing_brier, brier_floor, is_disabled).

    Brier floor evolves per mode:
      - Starts at 0.10 (per Blender config).
      - On each new closed trade, if mode's trailing_brier > 0.25,
        floor *= 0.97 for that mode.
      - Tracked across sessions via a separate ModeFloorState table
        (or computed on-demand from the disable-streak length).

    Disable flag:
      - is_disabled = True when mode has >= 30 consecutive closed trades
        with trailing_brier > 0.25.

    NB: 'consecutive' counts closed trades, not calendar days. A disabled
    mode stays disabled until manually re-enabled via CLI (a deliberate
    operator action — we don't auto-recover disabled modes).
    """

    def __init__(
        self,
        trailing_window: int = 15,
        disable_brier_threshold: float = 0.25,
        disable_streak_required: int = 30,
    ): ...

    def get_state(
        self,
        session: Session,
    ) -> dict[str, ModeState]:
        """Returns per-mode (trailing_brier, brier_floor, is_disabled,
        n_closed_trades).
        """

    def record_outcome(
        self,
        session: Session,
        mode_name: str,
        market_id: str,
        p_mode: float,
        p_market_at_prediction: float,
        outcome: int,
        closed_at: int,
    ) -> None:
        """Append a ModePerformance row (and update ModeFloorState as needed)."""
```

### 6.7 `market_resolver.py` — Polymarket → crypto mapping

```python
@dataclass(frozen=True)
class CryptoMarketMappingFile:
    """Loaded from markets.yaml. One entry per Polymarket market we trade."""

    market_id: str
    polymarket_question: str   # for human review only; not used in code paths
    symbol: str
    barrier_price: float
    direction: Literal["up", "down"]


def load_markets_yaml(path: str) -> list[CryptoMarketMappingFile]: ...


class MarketResolver:
    """Wraps a loaded list of CryptoMarketMappingFile entries; exposes lookup
    and time-to-resolution helpers.

    Constructed once at app startup from markets.yaml; injected into
    crypto_model.  Stateless after construction (the YAML list is the only
    state; mutations require restart).
    """

    def __init__(self, mappings: list[CryptoMarketMappingFile]): ...

    def resolve(self, market: Market) -> CryptoMarketMapping | None:
        """Look up the mapping for a Polymarket market.  Returns None if the
        market isn't in markets.yaml (caller treats as 'skip — not a market
        we model').

        resolution_ts is parsed from market.end_date_iso (ISO 8601 ->
        Unix seconds). Raises ValueError if end_date_iso is missing or
        unparseable.
        """

    def time_to_resolution_years(
        self, mapping: CryptoMarketMapping, now_ts: int
    ) -> float:
        """Returns (resolution_ts - now_ts) / SECONDS_PER_YEAR, clamped at 0.

        SECONDS_PER_YEAR = 365.25 * 86400 (calendar year, not trading year —
        crypto markets trade 24/7 so we use calendar time).
        """
```

`markets.yaml` starting content (curated by operator; expanded in C2-E):

```yaml
# Each entry maps one Polymarket market we model to its crypto pair + barrier.
# Resolution_ts is NOT stored here — it comes from Market.end_date_iso at runtime
# (so this file doesn't go stale as markets resolve).

- market_id: "0xABC...001"
  polymarket_question: "Will Bitcoin reach $80,000 by June 30, 2026?"
  symbol: "BTCUSDT"
  barrier_price: 80000.0
  direction: up

- market_id: "0xABC...002"
  polymarket_question: "Will Ethereum trade below $2,500 by June 15, 2026?"
  symbol: "ETHUSDT"
  barrier_price: 2500.0
  direction: down

# ... 5-20 entries curated by operator before C3 alpha test
```

### 6.8 `model.py` — `crypto_model` top-level callable

```python
def crypto_model(
    market_id: str,
    event: ReplayEvent,        # from Phase 1A's walk_forward_backtest contract
    *,
    polymarket_state: PolymarketState,
    market_resolver: MarketResolver,
    crypto_data: CryptoDataAccess,   # wraps repository for OHLCV + news queries (see §6.9)
    shock_detector: ShockDetector,
    composers: list[Composer],
    blender: BayesianBlender,
    agreement_filter: AgreementFilter,
    tilt: AsymmetricTilt,
    sizer: KellySizer,
    performance_tracker: PerformanceTracker,
) -> Prediction:
    """End-to-end pipeline: event -> Prediction.

    Pipeline (in order):
      1. resolve_market: market_id -> (symbol, barrier, resolution_ts, direction)
      2. compute spot, returns, GARCH-vol from crypto_data
      3. p_market from event (last-trade price)
      4. p_bridge from prob_barrier_hit(spot, barrier, T, vol)
      5. shock_state from shock_detector(returns, vol, news, ...)
      6. p_modes from each composer in composers
      7. blend_output from blender.blend(p_modes, performance_tracker)
      8. verdict from agreement_filter.evaluate(p_market, p_modes)
      9. if verdict.allowed and not blend_output.weights.is_all_disabled():
            p_final = tilt.apply(blend_output.p_blend, p_market, p_bridge)
         else:
            p_final = p_market    # no-trade signal
        10. kelly = sizer.size(p_final, p_market)
        11. emit Prediction(p_final, position_size=kelly.fraction,
                            diagnostics={...full pipeline state...})

    Errors raised by any layer are propagated (not silently caught) — caller
    decides retry/abort policy.  Diagnostics dict is written to TradeRecord
    for post-hoc analysis of any losing trade.
    """
```

The dependency-injected services (the keyword-only args) are constructed
once at app startup; `crypto_model` itself is invoked per-event by the L8
loop or by `walk_forward_backtest` during C3.

### 6.9 `crypto_data.py` — repository wrapper for pipeline queries

```python
class CryptoDataAccess:
    """Thin wrapper around the store providing the specific queries
    crypto_model needs without leaking ORM details into the model file.

    Each method takes a Session and returns plain values (floats, lists,
    DTOs) — model.py never touches ORM objects directly.
    """

    def __init__(self, session_factory: Callable[[], Session]): ...

    def get_recent_returns(
        self, symbol: str, granularity: str, n_bars: int, before_ts: int
    ) -> list[float]:
        """Last n_bars period returns (close-to-close) up to before_ts."""

    def get_current_spot(self, symbol: str, before_ts: int) -> float:
        """Most recent close at or before before_ts."""

    def get_recent_news_for_currency(
        self, currency: str, since_ts: int, until_ts: int
    ) -> list[NewsEventDTO]:
        """News events tagged with currency in [since_ts, until_ts]."""
```

---

## 7. Sub-phase Decomposition and Acceptance Gates

C2 is broken into 5 sub-phases. Each ends with an algorithmic gate; the next
sub-phase only starts once the prior gate is green. Engineering days are
guidelines, not commitments — the gate gates progression, not calendar time.

### 7.1 C2-A: Composition core (3 days)

**Scope:** Composers, Blender, AgreementFilter, AsymmetricTilt, KellySizer,
PerformanceTracker, MarketResolver, model.py top-level wiring. No news. Shock
detector built as `SpotOnlyShockDetector` placeholder (spot signal only;
news always silent).

**Files created:**
- `agent/research/crypto/composers.py` + tests
- `agent/research/crypto/blender.py` + tests
- `agent/research/crypto/agreement_filter.py` + tests
- `agent/research/crypto/asymmetric_tilt.py` + tests
- `agent/research/crypto/kelly_sizer.py` + tests
- `agent/research/crypto/performance_tracker.py` + tests
- `agent/research/crypto/market_resolver.py` + tests
- `agent/research/crypto/model.py` + integration tests
- `agent/research/crypto/markets.yaml` (starter: 1-2 BTC markets)
- ORM extensions for `ModePerformance` + `TradeRecord` + tests

**Gate:** `pytest -v` green; `walk_forward_backtest` produces non-zero
`Prediction`s on 1 hand-curated Polymarket BTC market using only spot-shock
signals; all reference values in §8.1-§8.5 match.

### 7.2 C2-B: Multilingual news aggregator (6 days)

**Scope:** All `NewsClient` implementations; `NewsIngestService`; ORM for
`NewsEvent` + `NewsCurrencyTag`; Telegram MTProto session bootstrap.

**Files created:**
- `agent/data/news_client.py` (abstract + 4 implementations)
- `agent/data/news_ingest.py`
- ORM extensions for `NewsEvent` + `NewsCurrencyTag`
- `agent/research/crypto/telegram_channels.yaml`
- `agent/research/crypto/rss_feeds.yaml`
- Tests with respx-mocked HTTP + pytest-mock for telethon

**Gate:** Live 24h smoke test — start `news_ingest.poll_latest()` on a loop,
verify events flow in from all 4 source types in their native languages.
Minimum acceptance: at least 1 event from each source type within 24 hours.
Run via `python -m agent.scripts.run_news_ingest` (CLI script created here).

### 7.3 C2-C: Translation + severity pipeline (4 days)

**Scope:** Per-language lexicons (en, ru, fa, zh, de, fr); `news_filter.py`;
`translator.py` with OpenAI backend + cache; `severity_scorer.py`.

**Files created:**
- `agent/research/crypto/shock_lexicons/{en,ru,fa,zh,de,fr}.yaml`
- `agent/research/crypto/news_filter.py` + tests
- `agent/research/crypto/translator.py` + tests
- `agent/research/crypto/severity_scorer.py` + tests
- CLI script: `agent/scripts/backfill_telegram_severity.py` for one-shot
  historical scoring.

**Gate:** Replay 30 days of historical Telegram messages (from C2-B's
backfill); severity scores must satisfy:
- At least 3 events score >= 0.7 (high-severity events visible in the period).
- The distribution of severity scores is heavy-tailed (most events near 0;
  thin tail above 0.5).
- Manually-flagged known shocks from the period (operator picks 2-3 events
  pre-test from news archives) all score >= 0.6.

Translation cache hit rate >= 30% after one full backfill pass (re-runs
should be fast).

### 7.4 C2-D: Shock detector + 3-mode fusion + full pipeline integration (3 days)

**Scope:** All three `ShockDetector` implementations; `shock_config.yaml`;
wire shock detector into `crypto_model`; replace SpotOnlyShockDetector
placeholder from C2-A.

**Files created/modified:**
- `agent/research/crypto/shock_detector.py` + tests (3 fusion modes, 12
  reference scenarios per §8.6)
- `agent/research/crypto/shock_config.yaml`
- `agent/research/crypto/model.py` (re-wire to use real shock detector)

**Gate:** End-to-end backtest against Phase 1A's `walk_forward_backtest` on 1
real BTC market using each of the three fusion modes. Pipeline must:
- Run without runtime errors.
- Produce at least 5 trade signals in the test period.
- Diagnostic TradeRecord rows populated with all per-mode predictions.

### 7.5 C2-E: Multi-market expansion + calibration report (2 days)

**Scope:** Expand `markets.yaml` to 5-20 markets (operator curates). Run full
pipeline across all markets in all 3 fusion modes. Emit calibration report.

**Files created:**
- Expanded `markets.yaml` (5-20 entries)
- `agent/scripts/generate_calibration_report.py`

**Gate:** Calibration report contains, per (market × fusion-mode):
- Number of trades signaled.
- Empirical hit rate of trades.
- Brier score per mode at the end of the period.
- Veto rate (% of would-be trades blocked by AgreementFilter).
- Aggregate edge (P_final - P_market) and aggregate P&L (simulated, no
  fills required at this stage).

The C3 alpha test starts from this report — it picks the best-performing
fusion mode by aggregate edge and proceeds to live evaluation.

---

## 8. Acceptance Criteria — the Algorithmic Gate

Reference tests for every layer. Each test has hand-computed expected values.
Math-justified assertions catch the bug classes called out in C1 §5 plus
new ones specific to C2.

### 8.1 `Composer` reference cases (§6.1)

For each of 4 composers, 4 reference scenarios = 16 tests total.
Inputs: `(p_market, p_bridge, shock_active, severity, time_since_shock_seconds)`.

| Composer | Scenario | Inputs | Expected P_mode | Catches |
|---|---|---|---|---|
| BinaryComposer | No shock | `(0.10, 0.30, False, 0.0, 0)` | `0.10` | wrong default behavior |
| BinaryComposer | Within window | `(0.10, 0.30, True, 0.8, 3*86400)` | `0.30` | windowing logic |
| BinaryComposer | At window edge | `(0.10, 0.30, True, 0.8, 14*86400 - 1)` | `0.30` | off-by-one |
| BinaryComposer | After window | `(0.10, 0.30, True, 0.8, 14*86400 + 1)` | `0.10` | exit timing |
| ExponentialComposer | t=0 | `(0.10, 0.30, True, 1.0, 0)` | `0.30` | lambda(0)=1 |
| ExponentialComposer | t=tau | `(0.10, 0.30, True, 1.0, 7*86400)` | within 1e-6 of `exp(-1)*0.30 + (1-exp(-1))*0.10 = 0.1736` | decay math |
| ExponentialComposer | t=3*tau | `(0.10, 0.30, True, 1.0, 21*86400)` | within 1e-6 of `exp(-3)*0.30 + (1-exp(-3))*0.10 = 0.1100` | long-tail |
| ExponentialComposer | No shock | `(0.10, 0.30, False, 0.0, 0)` | `0.10` | gate |
| MagnitudeTiedComposer | severity=1, t=0 | `(0.10, 0.30, True, 1.0, 0)` | `0.30` | full saturation |
| MagnitudeTiedComposer | severity=0.5, t=0 | `(0.10, 0.30, True, 0.5, 0)` | within 1e-6 of `0.5*0.30 + 0.5*0.10 = 0.20` | scaling |
| MagnitudeTiedComposer | severity clipped above 1 | `(0.10, 0.30, True, 1.5, 0)` | `0.30` | clipping invariant |
| MagnitudeTiedComposer | severity=0, t=0 | `(0.10, 0.30, True, 0.0, 0)` | `0.10` | zero-severity |
| ConfidenceWeightedComposer | small div | `(0.50, 0.51, False, 0.0, 0)` | very close to `0.50` (lambda~0 because divergence below threshold) | divergence gate |
| ConfidenceWeightedComposer | large div | `(0.10, 0.40, False, 0.0, 0)` | very close to `0.40` (lambda~1 because divergence well above threshold) | sigmoid saturation |
| ConfidenceWeightedComposer | div=threshold | `(0.50, 0.40, False, 0.0, 0)` | within 1e-3 of `0.5*0.40 + 0.5*0.50 = 0.45` | midpoint of sigmoid |
| ConfidenceWeightedComposer | zero div | `(0.50, 0.50, False, 0.0, 0)` | `0.50` | identity at zero |

### 8.2 `BayesianBlender` reference: 30-trade evolution sequence

The blender's 30-trade test runs the same Brier schedule the brainstorm
walkthrough used (cold start trades 1-5; confidence-mode honeymoon trades
6-15; regime-change collapse trades 16-30) but verifies the blender
**non-circularly** rather than against fixed numbers:

1. **Independent reference cross-check.** The test re-derives expected
   inverse-Brier weights from first principles in a separate
   `_reference_weights_from_state` function (NOT imported from `blender.py`),
   reading the `ModeState` the blender consumes, and asserts the blender
   matches within `1e-9`. A scoring or normalization bug in `blender.py`
   produces a mismatch.
2. **Qualitative regime-change property.** Asserts the confidence mode's
   weight at trade 30 is below its weight at trade 15 (collapse) AND below
   every other mode's weight at trade 30 (it is the worst performer by the
   end).
3. **Normalization invariant.** Weights sum to 1.0 (±`1e-9`) at every
   checkpoint.

**Why no fixed reference table.** The brainstorm's illustrative table (a
40%→1% confidence-weight trajectory) is **not algorithmically reproducible**
with `brier_floor = 0.10`. By design, any mode performing better than 0.10
Brier clamps to `effective_brier = floor`, so all "good" modes weight equally
— the floor's real job is capping runaway weights from near-zero Brier, while
fading of chronically-bad modes is handled by the disable-streak mechanism
(not the floor). With the floor retained, the real trajectory is: confidence
≈ equal weight through the honeymoon, then collapses to the lowest weight
during the regime change (≈0.25 → ≈0.09 in this schedule). The qualitative
collapse — the property the safety story actually depends on — is what the
test pins.

Plus a cold-start test: with fewer than 3 closed trades per mode, weights
must be equal-25%. Plus a mode-disable test: 30 consecutive closed trades
above `disable_brier_threshold` permanently sets that mode's weight to 0.

### 8.3 `AgreementFilter` reference scenarios

12 cases covering the brainstorm walkthrough's archetypes (Scenarios A, B, C,
D from §5/§6 of the brainstorm):

| # | p_market | p_modes (dict) | Expected verdict |
|---|---|---|---|
| 1 | 0.10 | all 4 = 0.31 | allow, long, long_count=4 |
| 2 | 0.10 | 0.31, 0.31, 0.31, 0.31 (regime t=3) | allow, long_count=4 |
| 3 | 0.05 | 0.26, 0.128, 0.128, 0.26 (regime t=7) | veto, long_count=2 |
| 4 | 0.02 | 0.20, 0.061, 0.061, 0.20 (regime t=21) | veto, long_count=2 |
| 5 | 0.50 | 0.50, 0.50, 0.50, 0.525 (no-shock) | veto, long_count=0 |
| 6 | 0.25 | 0.38, 0.38, 0.31, 0.36 (borderline) | allow, long_count=4 |
| 7 | 0.50 | 0.55, 0.45, 0.50, 0.50 (mixed mild) | veto |
| 8 | 0.70 | 0.55, 0.60, 0.62, 0.61 (short consensus) | allow, short_count=4 |
| 9 | 0.50 | 0.58 only above epsilon (rest within ±0.05) | veto, long_count=1 |
| 10 | 0.50 | 0.58, 0.59, 0.61, 0.50 (3 long, 1 neutral) | allow, long_count=3 |
| 11 | 0.50 | 0.58, 0.59, 0.50, 0.42 (2 long, 1 neutral, 1 short) | veto |
| 12 | 0.50 | 0.50, 0.50, 0.50, 0.50 (no signal anywhere) | veto, direction="none" |

### 8.4 `AsymmetricTilt` reference cases

8 cases. Identity preserved for 4 cases where `P_bridge <= P_market`; +0.05
applied for 4 cases where `P_bridge > P_market`:

| # | p_blend | p_market | p_bridge | Expected p_final |
|---|---|---|---|---|
| 1 | 0.30 | 0.10 | 0.32 | 0.35 |
| 2 | 0.50 | 0.50 | 0.50 | 0.50 (identity, p_bridge == p_market) |
| 3 | 0.20 | 0.30 | 0.20 | 0.20 (p_bridge < p_market) |
| 4 | 0.95 | 0.85 | 0.96 | 1.00 (clipped to [0, 1]) |
| 5 | 0.05 | 0.10 | 0.08 | 0.05 (p_bridge < p_market) |
| 6 | 0.25 | 0.20 | 0.40 | 0.30 |
| 7 | 0.50 | 0.40 | 0.60 | 0.55 |
| 8 | 0.99 | 0.50 | 0.99 | 1.00 (clipped) |

### 8.5 `KellySizer` reference cases

8 cases including the COVID and FTX scenarios from the brainstorm:

| # | p_final | p_market | Expected fraction | Direction | Catches |
|---|---|---|---|---|---|
| 1 | 0.31 | 0.10 | within 1e-4 of `0.5 * 0.10 * (0.31 - 0.10) / (0.31 * 0.69) = 0.0490` | yes | COVID-style |
| 2 | 0.32 | 0.10 | within 1e-4 of `0.5 * 0.10 * (0.32 - 0.10) / (0.32 * 0.68) = 0.0506` | yes | FTX-style entry |
| 3 | 0.15 | 0.15 | 0.0 | yes | zero edge |
| 4 | 0.15 | 0.10 | 0.0 | yes | below minimum_edge (0.02) |
| 5 | 0.50 | 0.10 | within 1e-4 of `clip(0.5*0.10*(0.50-0.10)/(0.50*0.50), 0, 0.10) = 0.080` | yes | medium edge |
| 6 | 0.90 | 0.10 | `0.10` (kelly_cap) | yes | cap engagement |
| 7 | 0.10 | 0.30 | within 1e-4 of `0.5 * 0.30 * (0.30 - 0.10) / (0.10 * 0.90) = 0.333` clipped to `0.10` | no | short direction + cap |
| 8 | 0.25 | 0.30 | within 1e-4 of computed value, direction=no | no | small short |

### 8.6 `ShockDetector` reference scenarios

12 scenarios across 3 fusion modes (4 each): clear-shock, no-shock, spot-only,
news-only:

| Detector | Scenario | spot_return | vol_annual | news_severity | active | severity |
|---|---|---|---|---|---|---|
| SpotOrNews | Both strong | -0.10 | 0.50 | 0.8 | True | 0.85 |
| SpotOrNews | Spot only | -0.10 | 0.50 | 0.0 | True | 0.5+ |
| SpotOrNews | News only | -0.01 | 0.50 | 0.8 | True | 0.8 |
| SpotOrNews | Neither | -0.01 | 0.50 | 0.0 | False | 0.0 |
| SpotAndNews | Both | -0.10 | 0.50 | 0.8 | True | medium |
| SpotAndNews | Spot only | -0.10 | 0.50 | 0.0 | False | 0.0 |
| SpotAndNews | News only | -0.01 | 0.50 | 0.8 | False | 0.0 |
| SpotAndNews | Neither | -0.01 | 0.50 | 0.0 | False | 0.0 |
| Weighted | Strong both (score>=0.5) | -0.10 | 0.50 | 0.8 | True | clipped(score) |
| Weighted | Weak both (score<0.5) | -0.04 | 0.50 | 0.3 | False | 0.0 |
| Weighted | Spot-heavy (w_spot=0.6 dominates) | -0.10 | 0.50 | 0.0 | True | ~0.6 |
| Weighted | News-heavy (w_news=0.4) | -0.01 | 0.50 | 0.9 | False (0.4*0.9 < 0.5) | 0.0 |

### 8.7 `news_filter.is_candidate` reference cases (per language)

Per language (en, ru, fa, zh, de, fr): 8 cases per language = 48 total:
- Currency mention + shock keyword → True (4 positive cases per language)
- Currency mention only → False (1 case per language)
- Shock keyword only → False (1 case per language)
- Neither → False (1 case per language)
- Substring-not-whole-word should NOT match (1 case per language; e.g.,
  English "BTCUSDT" substring should not count as "BTC" currency mention).

### 8.8 `severity_scorer.score_severity` reference cases

6 cases with hand-computed scores:

| # | source | currencies | keywords | event_age_min | Expected severity |
|---|---|---|---|---|---|
| 1 | telegram:@forklog (weight=1.0) | [BTC] | [hack, exploit] | 0 | hand-computed |
| 2 | telegram:@whalealert (weight=0.7) | [ETH] | [liquidation] | 5 | hand-computed |
| 3 | cryptopanic (weight=1.0) | [BTC, ETH] | [ban, sec] | 0 | hand-computed (sqrt damping visible) |
| 4 | rss:coindesk (weight=0.8) | [BTC] | [hack] | 90 | hand-computed (recency decay) |
| 5 | reddit:r/bitcoin (weight=0.6) | [BTC] | [crash] | 0 | hand-computed |
| 6 | unknown source (weight=0.5 default) | [BTC] | [bankrupt] | 0 | hand-computed |

### 8.9 `crypto_model` end-to-end integration tests

6 scenarios constructed as fully-stubbed end-to-end pipeline runs. Each
scenario fixes `(p_market, spot, barrier, T_years, vol, news_events,
mode_history)` and asserts the resulting `Prediction.p_final` and
`Prediction.position_size` match hand-traced expected values:

1. **Cold start, no shock:** equal mode weights, no shock detected, P_market=0.50,
   P_bridge=0.55. All 4 composers return P_market (because `not shock_state.active`),
   so all 4 P_mode = 0.50, blend = 0.50, divergence from P_market = 0 ⇒
   AgreementFilter long_count = 0 ⇒ verdict=veto ⇒ P_final = P_market = 0.50.
   Expected: `Prediction.position_size == 0.0`, `agreement_vetoed == True`.
2. **Cold start, strong shock, large divergence:** all 4 modes signal long
   → expected: trade, half-Kelly sizing, position size hand-computed.
3. **Warm modes, shock, regime change detected (3 of 4 modes weakened):**
   → expected: filter veto, no trade.
4. **Mode 4 disabled:** Mode 4 disabled in PerformanceTracker; crypto_model
   filters it out before calling AgreementFilter (per §6.3 disabled-mode
   handling). Remaining 3 modes all signal long with strong consensus
   (excesses > epsilon). Expected: filter allows (3-of-3 consensus among
   enabled modes), trade taken, position size hand-computed via KellySizer.
5. **Asymmetric tilt activates (P_bridge > P_market):** mild long edge
   → expected: P_final adds 0.05 over P_blend.
6. **Asymmetric tilt does NOT activate (P_bridge <= P_market):** any short edge
   → expected: identity, no tilt added.

### 8.10 Storage round-trips and idempotency

For each new ORM model (`NewsEvent`, `NewsCurrencyTag`, `ModePerformance`,
`TradeRecord`):
- Two-session round-trip: write in session A, read in session B, all fields
  preserved (same pattern as Phase 1A's `test_market_clob_token_ids_round_trips_through_db`).
- Unique constraint enforced where applicable (NewsEvent on (source, external_id);
  NewsCurrencyTag on (news_event_id, currency)).
- Idempotent insert: `save_news_events` called twice with same input returns
  N then 0.

---

## 9. Bug-Defense Discipline (carrying forward from C1)

Every new type, function, and test in C2 inherits the same discipline that
caught three plan bugs during C1 implementation. Explicitly:

1. **Hand-computed reference values for every math-bearing test.** No
   approximate or "looks reasonable" assertions. Where the math is complex
   (Kelly formula, Brier weighting, exponential decay), the expected value
   is derived in a comment with the formula written out.

2. **Math-justified assertions.** A passing test should fail when the bug
   class it targets is introduced. For example, the Kelly test for
   `q*edge/variance` will fail if a developer accidentally drops the `q`
   prefactor; the test comment documents which bug class it catches.

3. **Structural unit-clarity for new types.** Every new dataclass carries
   docstring annotations of unit conventions. `ShockState.severity` is
   documented as `in [0, 1]; clipped at construction`. `KellyFraction.fraction`
   is documented as `bounded to [0, kelly_cap] at construction`. Where a unit
   could be confused with another (severity vs. probability, period-vol vs.
   annualized-vol), the type is named explicitly to prevent accidental
   substitution.

4. **Parameter naming conventions.** Every function with a vol parameter
   uses `annualized_vol` (never just `vol`). Every function with a time
   parameter uses `time_remaining_years` (never just `T` or `t`). New
   conventions for C2: every probability parameter is named with `p_`
   prefix (`p_market`, `p_bridge`, `p_mode`, `p_blend`, `p_final`); every
   weight is named `w_`.

5. **Edge cases enumerated in docstrings.** Each public function lists its
   edge cases (zero inputs, boundary values, sign reversals) in the
   docstring; corresponding tests exist for each enumerated case.

6. **Two-stage review per subagent-driven-development workflow.** When C2
   moves to execution, every task gets (a) spec compliance review and (b)
   code quality review per the brainstorm-chosen execution mode. Three
   real plan bugs were caught in C1 by this process; we expect at least as
   many in C2 given the larger surface area.

---

## 10. Known Follow-ups and Risks (not blockers for C2)

These items are identified during the brainstorm or anticipated from C1's
follow-up list. None block C2 completion; all are candidates for C2.1 or
later.

1. **Mode 4 floor calibration.** The 0.10 starting Brier-floor with 0.97
   time-decay may still leave Mode 4 too influential during regime changes.
   If C3 alpha test shows Mode 4 is the dominant loss source despite the
   floor mechanism, candidates for C2.1: shorter floor decay constant
   (0.90), lower starting floor (0.05), or move to Option β (outlier veto)
   from the brainstorm.

2. **Option γ (separate entry vs. stay-in filters).** Considered during
   brainstorm; Option α (tighter parameters) chosen for simpler architecture.
   If C3 shows AgreementFilter still kicks in too slowly (>2 trades of
   regime-change exposure before veto), revisit Option γ in C2.1.

3. **Translation cost monitoring.** OpenAI API spend should be monitored.
   If daily cost exceeds $5 sustained for >1 week post-deploy, switch
   `Translator` to local NLLB-200 model. The `Translator` interface is
   designed for swap.

4. **Lexicon evolution.** Per-language shock lexicons start ~30-50 entries
   each but will need ongoing curation as missed events are discovered.
   Lexicons are versioned in git so audit trail is preserved. A
   `scripts/analyze_missed_events.py` helper to surface candidate keyword
   additions is a C2.1 candidate.

5. **Per-market vol regime classification.** Markets with structurally
   different vol regimes (e.g., short-tenor near-the-barrier markets vs.
   long-tenor far-from-barrier markets) may benefit from different
   shock_threshold_k values. Currently one global value; per-market
   thresholds in markets.yaml is a C2.1 candidate if C3 shows uniform
   thresholds are miscalibrated.

6. **Newer NewsClient sources.** X/Twitter API ($5000/month) deliberately
   omitted; Discord channel scraping deliberately omitted. If C3 shows
   meaningful alpha and capital scales beyond $100, these sources become
   economically tractable.

7. **Anomaly/regime-change detector as a separate signal.** The brainstorm
   raised the possibility of a dedicated regime-change detector that would
   set `kelly_cap = 0` when active (refuse to trade during regime
   uncertainty). Not included in C2; candidate for C2.1 or Phase 2's L5
   risk module.

8. **arch dependency type stability** (carried forward from C1's
   follow-ups). `conditional_volatility` returns numpy in arch 8.0; older
   arch returned pandas. C1's implementation uses index-based `[-1]` which
   works on both; future arch releases may break this. Add an arch version
   pin if a regression is observed in C2.

9. **Translation cache portability.** Default cache path is
   `~/.cache/polymarket-agent/translations.sqlite`. Multi-machine
   deployment (e.g., separate ingest box and analysis box) would need
   shared cache or per-machine caches with cross-population. Single-machine
   C2/C3 doesn't hit this; Phase 2's multi-process L8 loop may.

10. **Walk-forward gating granularity.** PerformanceTracker computes
    trailing Brier on closed trades (resolution-event granularity).
    Polymarket barrier markets resolve in days-to-weeks; finer-grained
    "intermediate Brier" (e.g., score predictions hourly against
    contemporaneous market price as a proxy) is a C2.1 candidate for
    faster feedback loops.

---

## 11. Decision Log (the 11 brainstorm decisions, for traceability)

For audit purposes, the 11 architectural decisions made during the C2
brainstorm are reproduced here:

| # | Decision | Choice |
|---|---|---|
| 1 | Polymarket-to-crypto market mapping | Hand-curated YAML (`markets.yaml`) |
| 2 | Shock detector fusion modes | All 3 (OR / AND / Weighted) selectable at runtime |
| 3 | News source breadth | Full multilingual aggregator (CryptoPanic + RSS + Reddit + Telegram across 6 languages) |
| 4 | Backtest data strategy | Telegram-heavy historical backfill + collect-now for the rest |
| 5 | Translation approach | Pre-filter by per-language lexicon; translate only candidates |
| 6 | Composition modes | All 4 (binary / exp / magnitude / confidence) |
| 7 | Composition architecture | Consolidated pipeline: Blender + Agreement + Tilt + Kelly (not per-mode selection) |
| 8 | Blender parameters | Brier-weighted, 15-trade trailing window, 0.10 starting Brier-floor with 0.97 time-decay, 3-trade cold-start, mode-disable at 30 consecutive >0.25-Brier trades |
| 9 | AgreementFilter parameters | epsilon=0.08, tau=7d (ExponentialComposer), Mode-1 window=14d, 3-of-4 strict directional agreement |
| 10 | Asymmetric tilt | +0.05 long-only (added when `P_bridge > P_market`) |
| 11 | Kelly sizing | Half-Kelly (multiplier 0.5), variance = `P_final * (1 - P_final)`, kelly_cap = 0.10, minimum_edge = 0.02 |

Each decision has its rationale recorded in the brainstorm transcript and
is reflected in the corresponding section of this spec.

---
