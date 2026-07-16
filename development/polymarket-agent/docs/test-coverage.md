# Test Coverage Analysis — polymarket-agent

> **2026-07-15: now execution-verified.** The suite has been run under coverage for the
> first time — **289 passed / 1 skipped / 0 failed, 94% line coverage**. The "static
> read-through" disclaimer below was accurate when written but is now superseded; see the
> **2026-07-15 update** just above "Highest-priority gaps" for executed per-module numbers.
> Key correction: execution caught a _failing_ assertion inside a file this doc had marked
> CLOSED (item #1).

Static analysis (no test execution — `pytest`/`python` invocation was blocked in this
environment, so this is a manual read-through comparing every `agent/**/*.py` module
against its `tests/**` counterpart). ~186 concrete gaps found across 33 source files.
Skeletons below are intentionally minimal (`...` bodies) — fill in fixtures/assertions
per each test file's existing conventions (check `tests/conftest.py` for shared fixtures
first: `settings`/`engine`/`session_factory`/`session` on in-memory SQLite).

Refreshed 2026-07-04 against HEAD (`f296bd44`): re-verified every "highest-priority" item
below still holds, and re-derived the `question_parser.py` section from scratch since
commits `82c46ffc`/`f296bd44` (RawExtractCache, pass-2 direction check) landed after the
original pass and had closed some of its previously-listed gaps.

**2026-07-07 update:** `tests/store/test_db.py` and
`tests/research/crypto/test_shock_detector.py` now exist and have real assertions (items
#1 and #2 below are closed). Note for future passes over this doc: both files were found
in this repo in a _skeleton_ state first — real setup/fixture code, but every assertion
was either a no-op (`assert result is not None`, always true since `detect()` never
returns `None`) or, in `test_db.py`, entirely commented-out TODOs (empty function bodies
that trivially pass under pytest). A skeleton test file collects and passes without
verifying anything, so it reads as "gap closed" in a diff/PR while providing zero actual
coverage — treat any new test file with no execution-only asserts as suspect, not just
files with "TODO" in them.

**2026-07-08 update:** uncommitted working-tree changes (not yet committed) add real
assertions to three existing test files, closing former item #4 below plus all 4
`agent/cli.py` gaps and 2 of 3 remaining `crypto_backtest.py` gaps — see the per-file
sections for what's now closed vs. still open. Verified by reading `git diff` for these
files directly (not re-run, since this environment still can't invoke `pytest`).

**2026-07-08 update (2):** a new untracked file `tests/scripts/test_run_crypto_validation.py`
now exists (evidenced by its own `__pycache__` entry, so it has been collected/run at some
point), but it is a **skeleton in the exact sense flagged above**: every one of its ~20 test
functions is either `pass` or a `# TODO:` comment with no executable assertion. It does not
close the `agent/scripts/run_crypto_validation.py` gap below — treat that section as still
fully open. Do not count this file as coverage until real assertions land.

**2026-07-09 update:** re-verified against HEAD (still `f296bd44`) plus the current working
tree — `git diff` confirms the three files in the "closed (uncommitted, 2026-07-08)" notes
above (`tests/test_cli_smoke.py`, `tests/validation/test_c3a_cli_smoke.py`,
`tests/validation/test_crypto_backtest.py`) are unchanged since that pass and still uncommitted;
no `agent/**` source changed. Found one gap in this **document**, not the code: `agent/store/schema.py`
had no section at all (38 `###` headings vs. 39 real non-`__init__` source files) despite having
a real, non-skeleton test file — added its section below. `pytest`/coverage execution is still
blocked in this environment (git commands work; `python -m pytest`, `.venv/Scripts/python.exe`,
and `uv run pytest` all require interactive approval that wasn't granted), so this remains a
manual read-through, not an executed-coverage report.

**2026-07-09 update (2):** independently re-derived this entire analysis from scratch via four
parallel agents (one each over `agent/data/`+`cli.py`+`config.py`, `agent/research/crypto/`,
`agent/store/`+`agent/strategy/`+`baselines.py`, `agent/validation/`+`run_crypto_validation.py`),
each reading every source/test pair directly rather than consulting this doc. Result: near-total
agreement with everything above — every "highest-priority" item, the `barrier_bridge.py`
deterministic-drift branch, the `run_crypto_validation.py` skeleton-test problem, and all of
`risk_metrics.py`'s untested functions were independently rediscovered verbatim. Two corrections
and a set of genuinely new items surfaced; both folded in below:

- **Correction:** the `agent/cli.py` "CLOSED" note (2026-07-08) is inaccurate — the listed test
  names only cover `backtest`'s `--model` choice, not `paper-trade`'s. See the file's own section
  below for the 2 gaps this leaves open.
- **New (not previously listed):** `agent/config.py` malformed-numeric-env-var case;
  `agent/data/rate_limiter.py` zero/negative-`tokens`, `refill_per_second=0`, and `capacity=0`
  constructions; `crypto_ingest.py`'s untested `"1d"` granularity path and mid-pagination HTTP
  error; `ingest.py`'s price-history idempotency-on-second-call and a market→price-history
  chained-integration test; `store/repository.py`'s partial-overlap dedup and cross-market dedup
  scoping; `store/schema.py`'s FK-enforcement-pinning and composite-index query tests; a
  store→baseline→strategy end-to-end smoke test (no such chain exists anywhere, `test_smoke.py`
  only checks `import agent`); `crypto_backtest.py`'s `kupiec_zone` non-`None` branch (needs
  ≥100 resolved markets, never set up) and `report.window`/`upstream_coverage`-passthrough
  assertion; and three integration-level gaps in `agent/research/crypto/`: `question_parser.py`
  output is never fed into `market_resolver.py`/`crypto_model` in any test (the two
  market-identification pathways — markets.yaml vs. LLM parsing — are never connected), real
  `fit_garch11`'s `ValueError` on <100 bars is never exercised end-to-end through `crypto_model`,
  and no test drives an expired/near-term-resolution market through the real pipeline to hit
  `prob_barrier_hit`'s `time_remaining_years<=0` branch outside of unit tests.

**2026-07-15 update — FIRST EXECUTED COVERAGE RUN** (supersedes every "static
read-through" disclaimer above). `pytest` execution is no longer blocked; the full suite
was run with `.venv/Scripts/python.exe -m pytest --cov=agent --cov-report=term-missing`:

- **Result:** 288 passed, **1 failed**, 1 skipped; **94% line coverage** (98 of 1626
  statements uncovered).
- **The 1 failure was a real bug in a file this doc marked CLOSED:**
  `tests/store/test_db.py::test_corrupted_db_file_raises_on_query` expected
  `OperationalError`, but a malformed SQLite file raises the parent `DatabaseError` ("file
  is not a database") — `OperationalError` is a subclass, so it could never match. The file
  was also **untracked** (never committed) until now. Fixed the assertion and committed
  (`64507261`); suite is now **289 passed, 1 skipped, 0 failed**. See item #1 below.
- **Coverage vs. this ledger — the key reconciliation:** 94% line coverage alongside ~186
  listed gaps proves the two measure different things. The large majority of listed gaps are
  _under-asserted covered lines_ (edge / NaN / integration cases on lines the happy-path
  already executes) — invisible to line coverage, only findable by read-through. Only a
  minority are _uncovered lines_. **Do not read 94% as "nearly done."**
- **The one true coverage hole:** `agent/scripts/run_crypto_validation.py` — **76%, 47
  uncovered lines** (main pipeline 417-496). **48% of all missing statements sit in this one
  skeleton-tested script** — hard confirmation of the skeleton-test warnings above.

Modules below 100% line coverage (executed 2026-07-15); all other `agent/**` modules are at
100%:

| Module                                         | Cover   | Miss   | Uncovered lines                                                     |
| ---------------------------------------------- | ------- | ------ | ------------------------------------------------------------------- |
| `agent/scripts/run_crypto_validation.py`       | 76%     | 47     | 75,80,82-83,104-105,108-112,166,190,199,265,327,417-439,444-496,500 |
| `agent/research/crypto/model.py`               | 81%     | 8      | 105,115,128-129,131-132,178,190                                     |
| `agent/data/polymarket_enumerate.py`           | 85%     | 6      | 43,47-48,65,69,120                                                  |
| `agent/validation/resolution_poller.py`        | 88%     | 5      | 50,66,75-77                                                         |
| `agent/data/models.py`                         | 91%     | 6      | 13-14,56-57,62-63                                                   |
| `agent/research/crypto/kelly_sizer.py`         | 91%     | 2      | 61,102                                                              |
| `agent/research/crypto/question_parser.py`     | 92%     | 7      | 90,92-93,113,117,126,130                                            |
| `agent/research/crypto/barrier_bridge.py`      | 93%     | 2      | 45,51                                                               |
| `agent/data/polymarket_client.py`              | 94%     | 2      | 67,69                                                               |
| `agent/cli.py`                                 | 96%     | 1      | 79                                                                  |
| `agent/data/rate_limiter.py`                   | 96%     | 1      | 44                                                                  |
| `agent/research/crypto/crypto_data.py`         | 96%     | 1      | 57                                                                  |
| `agent/data/crypto_ingest.py`                  | 97%     | 1      | 52                                                                  |
| `agent/research/crypto/market_resolver.py`     | 97%     | 1      | 39                                                                  |
| `agent/validation/risk_metrics.py`             | 97%     | 2      | 20,38                                                               |
| `agent/research/crypto/performance_tracker.py` | 98%     | 1      | 100                                                                 |
| `agent/research/crypto/vol_estimator.py`       | 98%     | 1      | 104                                                                 |
| `agent/store/repository.py`                    | 98%     | 1      | 72                                                                  |
| `agent/validation/backtest.py`                 | 98%     | 1      | 77                                                                  |
| `agent/validation/pnl.py`                      | 98%     | 1      | 52                                                                  |
| `agent/validation/crypto_backtest.py`          | 99%     | 1      | 165                                                                 |
| **TOTAL**                                      | **94%** | **98** | —                                                                   |

## Highest-priority gaps (fix these first)

1. ~~**`agent/store/db.py` has no test file at all.**~~ **CLOSED 2026-07-07** —
   `tests/store/test_db.py` now covers the non-in-memory `create_engine` branch and
   `init_db` table creation with real assertions.
   **Correction (2026-07-15, executed):** this "CLOSED" was declared from a static read;
   the first coverage run found `test_corrupted_db_file_raises_on_query` in this very file
   _failing_ (expected `OperationalError`, corrupt-DB raises the parent `DatabaseError`), and
   the file was untracked. Now genuinely fixed + committed (`64507261`) — a reminder that a
   test file passing collection ≠ its assertions passing.
2. ~~**`agent/research/crypto/shock_detector.py` has no test file at all.**~~ **CLOSED
   2026-07-07** — `tests/research/crypto/test_shock_detector.py` now covers the
   zero/negative-vol guard, the 30-day rolling shock window boundaries, and threshold
   clipping with real assertions. The same-signed-future-timestamp edge case
   (`last_shock_ts` in the future relative to `now_ts`) is still untested — see follow-up
   below.
3. **`TokenBucket.acquire()`** (the async method actually used in production by both API
   clients) **is never tested** — only the synchronous `try_acquire` is exercised.
4. ~~**`_decide_verdict`'s cost-survival gate** (`crypto_backtest.py`, Sharpe@1%cost ≤ 0 →
   INCONCLUSIVE) **is never independently tested**~~ **CLOSED (uncommitted, 2026-07-08)** —
   `test_verdict_inconclusive_when_edge_does_not_survive_cost` in
   `tests/validation/test_crypto_backtest.py` now isolates this gate with a real assertion.
5. **Likely real bug, not just a test gap:** `agent/scripts/run_crypto_validation.py`'s
   `--refresh` CLI flag is parsed but never read anywhere in `main()` or `run_pipeline` —
   appears to be a dead no-op that silently ignores cache-refresh requests.
6. **`AsymmetricTilt.apply()`'s no-tilt path returns `p_blend` unclamped**, contradicting
   its own docstring's claim of `[0,1]`-clipped output — a real correctness/safety gap.
7. **`pnl.py → risk_metrics.py` are never chained end-to-end** in any test — each is unit
   tested against hand-built fixtures, never against the other's real output. Same for
   `paper_trade.py` ↔ `resolution_poller.py`.
8. Several **division-by-zero / NaN edge cases are unguarded and untested** across the
   quant modules: `composers.ExponentialComposer`/`ConfidenceWeightedComposer` (zero
   `tau_seconds`/`scale`), `crypto_data.get_recent_returns` (zero `prev_close`, guarded but
   untested), `kelly_sizer` (`p_final` exactly 0 or 1), `risk_metrics.brier_skill_score`
   (zero baseline Brier).

---

## agent/data/

### agent/data/crypto_client.py — 4 gaps

- Default `TokenBucket(capacity=60, refill_per_second=1.0)` when no bucket injected — untested.
- `limit > 1000` capping to `MAX_KLINES_PER_REQUEST` — untested.
- `start_ts`/`end_ts=None` → params omitted entirely — not asserted.
- No test that `get_klines` actually calls `self._bucket.acquire()`.

```python
async def test_get_klines_defaults_rate_limit_bucket_when_none_given():
    ...  # BinanceClient(http_client=http) with no bucket arg still works

async def test_get_klines_caps_limit_at_max_per_request():
    ...  # limit=5000 -> outgoing query param "limit"=="1000"

async def test_get_klines_omits_time_params_when_not_provided():
    ...  # no start_ts/end_ts -> "startTime"/"endTime" absent from params
```

### agent/data/crypto_ingest.py — 3 gaps

- `_SECONDS_PER_BAR[granularity]` KeyError for unsupported granularity — untested.
- Empty page mid-pagination (`if not bars: break`) — untested.
- `start_ts >= end_ts` short-circuit (zero HTTP calls) — untested.

```python
async def test_ingest_history_raises_on_unsupported_granularity(session_factory):
    ...  # granularity="5m" raises KeyError

async def test_ingest_history_start_after_end_returns_zero_without_http_call(session_factory):
    ...  # no HTTP call made, returns 0

async def test_ingest_history_stops_on_empty_page(session_factory, session):
    ...  # Binance returns [] mid-range -> loop breaks cleanly
```

### agent/data/ingest.py — 3 gaps

- Empty Gamma response (0 markets) — untested.
- No integration test that a second `ingest_markets` call upserts rather than duplicates.
- `httpx.HTTPStatusError` propagation from the client — untested.

```python
@respx.mock
async def test_ingest_markets_empty_response_returns_zero(session_factory, session):
    ...

@respx.mock
async def test_ingest_markets_upserts_on_second_call(session_factory, session):
    ...

@respx.mock
async def test_ingest_markets_propagates_http_error(session_factory):
    ...
```

### agent/data/models.py — 6 gaps

- `_as_float`'s `except (TypeError, ValueError)` branch (non-numeric string) — untested.
- Malformed (non-JSON) `clobTokenIds` string — untested fallback behavior.
- Malformed (non-JSON) `outcomePrices` string — untested.
- Mixed `None`/`""` entries filtered from `outcomePrices` list — untested.
- Missing `"id"` key raises `KeyError` — not confirmed by a test.
- **`NewsEventDTO` has zero test coverage anywhere.**

```python
def test_as_float_returns_none_for_non_numeric_string():
    ...

def test_market_from_gamma_malformed_clob_token_ids_json_defaults_empty():
    ...

def test_market_from_gamma_malformed_outcome_prices_json_defaults_empty():
    ...

def test_market_from_gamma_outcome_prices_filters_none_and_empty_string():
    ...

def test_market_from_gamma_missing_id_raises_key_error():
    ...

def test_news_event_dto_defaults():
    ...  # language=="en", raw_text=="", translated_text is None, severity_score is None, currencies==[], ingested_at==0
```

### agent/data/polymarket_client.py — 4 gaps

- `offset`/`active`/`closed` forwarded as query params — never asserted.
- `get_markets` error path (`raise_for_status`) — untested (only get_market/get_price_history have error tests).
- `get_market`'s general 500 error path (only 404 special-case tested).
- `start_ts`/`end_ts`/`fidelity` params on `get_price_history` — never asserted.

```python
@respx.mock
async def test_get_markets_passes_filter_and_pagination_params():
    ...

@respx.mock
async def test_get_markets_raises_on_http_error():
    ...

@respx.mock
async def test_get_market_raises_on_non_404_http_error():
    ...

@respx.mock
async def test_get_price_history_passes_start_end_ts_and_fidelity():
    ...
```

### agent/data/polymarket_enumerate.py — 4 gaps

- `_is_crypto` with `category=None` — untested.
- `_parse_iso_date`'s `except (ValueError, AttributeError)` branch (malformed non-empty date string) — untested.
- `_resolution_in_window` with unparseable window bounds — untested.
- Fully empty first page (zero markets) — untested.

```python
@respx.mock
async def test_is_crypto_false_when_category_none():
    ...

@respx.mock
async def test_enumerate_excludes_market_with_malformed_end_date():
    ...

async def test_enumerate_handles_completely_empty_first_page():
    ...
```

### agent/data/polymarket_history.py — 2 gaps

- Empty `history.history` (API returns `{"history": []}`) — untested distinct-from-no-token-ids case.
- `httpx.HTTPStatusError` propagation — untested.

```python
@respx.mock
async def test_ingest_returns_zero_when_history_is_empty(session):
    ...

@respx.mock
async def test_ingest_propagates_http_error_from_client(session):
    ...
```

### agent/data/rate_limiter.py — 2 gaps

- **`acquire()` (the async poll/wait method) has zero coverage** — production code path, untested.
- `try_acquire(tokens=N)` with `tokens > 1` — untested.

```python
async def test_acquire_returns_immediately_when_tokens_available():
    ...

async def test_acquire_waits_until_bucket_refills(monkeypatch):
    ...

def test_try_acquire_with_multiple_tokens_at_once():
    ...
```

### agent/store/db.py — CLOSED (verified 2026-07-09)

All 4 previously-listed gaps (non-in-memory `create_engine` branch, `init_db` creating all
6 tables, `make_session_factory`'s `expire_on_commit=False`, `StaticPool` connection sharing)
are covered with real assertions in `tests/store/test_db.py`, which also goes beyond the
original list: two-independent-in-memory-engines isolation, missing-parent-dir /
corrupted-file / empty-url error paths, `create_engine` fallthrough for non-sqlite URLs, and
concurrent-thread visibility on a file-based engine. No open items remain in this file.

### agent/store/schema.py — 2 gaps (previously missing from this doc entirely)

Every table has a real round-trip test in `tests/store/test_schema.py` (including unique
constraints and `ModeFloorState`'s scalar defaults), so this is low-risk — but two things
slip through:

- `Market`'s boolean-default columns (`active`, `closed`, `enable_order_book`, all
  `default=False`) are never asserted when the constructor omits them — every existing
  `Market(...)` in the test suite passes `question=`/`category=` only incidentally, never
  checks the resulting defaults.
- `Market.snapshots`' `cascade="all, delete-orphan"` is declared but never exercised —
  no test deletes a `Market` and confirms its `PriceSnapshot` rows are cascade-deleted
  (or orphaned rows removed when detached from `market.snapshots`).

```python
def test_market_boolean_defaults_when_omitted(session):
    ...  # Market(id="m1", question="Q") -> active is False, closed is False,
    ...  # enable_order_book is False

def test_deleting_market_cascades_to_snapshots(session):
    ...  # add Market + 2 PriceSnapshots, session.delete(market), commit ->
    ...  # session.query(PriceSnapshot).count() == 0
```

### agent/store/repository.py — 4 gaps

- `save_crypto_bars([])` short-circuit — untested.
- `save_price_history` with 0 points from the start — untested (only "already exists" case covered).
- `upsert_market` updating fields beyond `question`/`clob_token_ids` on a second call — untested.
- Multiple symbols/granularities in one `save_crypto_bars` call — disambiguation untested.

```python
def test_save_crypto_bars_empty_iterable_returns_zero(session):
    ...

def test_save_price_history_empty_points_returns_zero(session):
    ...

def test_upsert_market_updates_all_scalar_fields_on_second_call(session):
    ...

def test_save_crypto_bars_disambiguates_multiple_symbols_and_granularities(session):
    ...
```

### agent/config.py — 4 gaps

- Only `PMA_DATABASE_URL` override tested; `clob_base_url`/`gamma_base_url`/`http_timeout_seconds` overrides untested.
- Unprefixed env var (e.g. `DATABASE_URL`) correctly ignored — untested.
- Unknown `PMA_`-prefixed var tolerated (`extra="ignore"`) — untested.
- Malformed numeric env value (e.g. `PMA_HTTP_TIMEOUT_SECONDS="abc"`) should raise a
  pydantic `ValidationError` — untested (new 2026-07-09).

```python
def test_settings_env_override_all_fields(monkeypatch):
    ...

def test_settings_ignores_unprefixed_env_var(monkeypatch):
    ...

def test_settings_ignores_unknown_prefixed_env_var(monkeypatch):
    ...

def test_settings_invalid_timeout_raises_validation_error(monkeypatch):
    ...  # PMA_HTTP_TIMEOUT_SECONDS="not-a-number" -> pydantic ValidationError
```

### agent/cli.py — mostly closed (uncommitted, 2026-07-08); 2 gaps remain (correction, 2026-07-09)

The 2026-07-08 "CLOSED" note was inaccurate: the listed test names
(`test_cli_backtest_respects_explicit_model_choice`, `test_cli_backtest_rejects_invalid_model_choice`)
only cover `backtest`'s `--model` argument, not `paper-trade`'s equivalent argument — those two
branches of the parser are still unexercised. `main(argv=None)` (the real `sys.argv` fallback,
as opposed to always passing an explicit list) is also still untested. Everything else (real
`backtest`/`paper-trade` stub execution, repeated `--market-id` accumulation, invalid `--model`
choice for `backtest`, `main([])` with no subcommand) has real assertions in
`tests/test_cli_smoke.py`:
`test_cli_backtest_runs_stub_with_default_model`,
`test_cli_backtest_respects_explicit_model_choice`,
`test_cli_backtest_rejects_invalid_model_choice`,
`test_cli_paper_trade_runs_stub_with_repeated_market_id`,
`test_cli_paper_trade_defaults_market_id_to_empty_list`,
`test_cli_main_no_subcommand_exits_two`. These are uncommitted working-tree changes —
confirm they land before treating this section as closed in committed history.

```python
def test_cli_paper_trade_respects_explicit_model_choice(capsys):
    ...  # paper-trade --model constant_half selects the non-default choice

def test_cli_paper_trade_rejects_invalid_model_choice(capsys):
    ...  # paper-trade --model nope -> exits 2 via argparse choices

def test_cli_main_defaults_to_sys_argv(monkeypatch, capsys):
    ...  # main() with no argv arg falls back to sys.argv
```

---

## agent/research/

### agent/research/baselines.py — no meaningful gaps

Pure pass-throughs, already covered at both boundaries.

### agent/research/crypto/agreement_filter.py — 4 gaps

- Custom `epsilon`/`min_active_count` constructor args — untested (all tests use defaults).
- Tie-break when `long_count == short_count > 0` (falls to `"short"` via `else`) — untested.
- Both directions simultaneously clearing `min_active_count` (long checked first, silently wins) — untested.
- Empty `p_modes` dict — untested.

```python
def test_custom_epsilon_and_min_active_count_are_honored():
    ...

def test_tie_break_defaults_to_short_direction():
    ...

def test_both_directions_clear_threshold_long_wins():
    ...

def test_empty_p_modes_dict_is_no_signal():
    ...
```

### agent/research/crypto/asymmetric_tilt.py — 3 gaps

- Lower-bound clip (`max(0.0, ...)`) never exercised — no test drives the sum below 0.
- **No-tilt path (`p_bridge <= p_market`) returns `p_blend` unclamped**, contradicting the module's own "[0,1] clipped for safety" docstring — real gap in source + tests.
- Custom `tilt_magnitude` constructor arg — untested.

```python
def test_lower_bound_clip_when_tilt_pushes_negative():
    ...

def test_no_tilt_path_does_not_clip_out_of_range_p_blend():
    ...  # documents/exposes the missing clamp

def test_custom_tilt_magnitude_is_honored():
    ...
```

### agent/research/crypto/barrier_bridge.py — 6 gaps (highest-risk file in this batch)

Only `vol=0, drift=0` is tested (falls through to the final `return 0.0` catch-all). The
entire deterministic-drift branch (`annualized_vol <= 0`, nonzero drift) is untested.

```python
def test_prob_barrier_hit_deterministic_up_barrier_reached():
    ...  # vol<=0, drift>0, barrier>spot, drift*T sufficient -> 1.0

def test_prob_barrier_hit_deterministic_up_barrier_not_reached():
    ...  # same setup, drift*T insufficient -> 0.0

def test_prob_barrier_hit_deterministic_down_barrier_reached():
    ...  # vol<=0, drift<0, barrier<spot, sufficient -> 1.0

def test_prob_barrier_hit_deterministic_down_barrier_not_reached():
    ...  # insufficient -> 0.0

def test_prob_barrier_hit_deterministic_direction_mismatch_returns_zero():
    ...  # vol<=0, drift>0, barrier<spot -> falls to 0.0 catch-all

def test_prob_barrier_hit_strictly_negative_vol_and_time():
    ...  # vol=-0.1 and time_remaining_years=-1.0, not just ==0.0 boundary
```

### agent/research/crypto/shock_detector.py — mostly closed (verified 2026-07-09); 3 gaps remain

`tests/research/crypto/test_shock_detector.py` is real (18 tests, no skeletons) and covers:
threshold firing (above/exactly-at/below), severity scaling and its 1.0 clip, sign-independence
via `abs()`, the zero-vol div-by-zero guard, the 30-day rolling window (active/exactly-at-boundary/
just-past-boundary), new-shock-vs-stale-window priority, news-events-ignored, custom
`spot_threshold_k`, and the ABC contract. Three edge cases from the original list are still open:

- Negative `garch_annualized_vol` (only the `== 0.0` guard is tested, not `< 0`) — unclear
  whether it should behave like zero or raise.
- `current_return = float("nan")` — NaN comparisons are always `False` in Python, so this
  should fall through to the past-shock/inactive branch, but that's never asserted.
- `last_shock_ts` in the future relative to `now_ts` (negative `time_since_shock_seconds`) —
  flagged in the 2026-07-07 update above as a genuine follow-up, still untested.

```python
def test_detect_negative_garch_vol_treated_as_non_positive():
    ...  # garch_annualized_vol=-0.5 -> same guarded path as 0.0, no ZeroDivisionError/negative sigmas

def test_detect_nan_current_return_falls_through_to_inactive():
    ...  # current_return=float("nan") -> sigmas comparison is False -> inactive absent a rolling shock

def test_detect_last_shock_ts_in_future_yields_negative_elapsed():
    ...  # last_shock_ts > now_ts -> pins down current (surprising) behavior, doesn't assert "should"
```

### agent/research/crypto/types.py — 6 gaps

`BlendOutput`, `AgreementVerdict`, `CryptoMarketMappingFile`, `ModeState` are never
constructed/asserted anywhere. `ShockState.severity`/`KellyFraction.fraction` exact
boundary values (0.0, 1.0, cap) untested (only out-of-range clipping is tested).

```python
def test_blend_output_construction():
    ...

def test_agreement_verdict_allowed_long():
    ...

def test_crypto_market_mapping_file_construction():
    ...

def test_mode_state_construction():
    ...

def test_shock_state_severity_exact_boundaries_unchanged():
    ...

def test_kelly_fraction_exactly_at_cap_unchanged():
    ...
```

### agent/research/crypto/vol_estimator.py — 3 gaps

- `persistence >= 1.0` (non-stationary/integrated GARCH) → `long_run_variance == inf` — the module's key numerical edge case, completely unexercised.
- `forecast_garch_annualized_vol` behavior with `long_run_variance=inf` — undocumented by any test.
- `rescale=False` path never exercised (every test uses the default `rescale=True`).

```python
def test_fit_garch11_integrated_series_gives_infinite_long_run_variance():
    ...

def test_forecast_garch_with_infinite_long_run_variance_at_finite_horizon():
    ...

def test_fit_garch11_rescale_false_still_returns_valid_result():
    ...
```

### agent/research/crypto/blender.py — 3 gaps

- `brier_floor == 0.0` division guard (`else 0.0`) — untested; a mode could silently score 0 without being `is_disabled`.
- Partial disable (1-of-4, not all-4) renormalization — untested.
- `p_modes` missing a (disabled) mode's key — untested despite the source comment anticipating it.

```python
def test_brier_floor_zero_gives_zero_score_not_disabled(session_factory):
    ...

def test_partial_disable_renormalizes_remaining_modes(session_factory):
    ...

def test_p_modes_missing_disabled_mode_key_does_not_raise(session_factory):
    ...
```

### agent/research/crypto/composers.py — 5 gaps

- `BinaryComposer` exact window boundary (`t == window_seconds`, strict `<`) — untested.
- `ExponentialComposer` with `tau_seconds <= 0` → unguarded `ZeroDivisionError` — untested.
- `MagnitudeTiedComposer` with severity<1 AND t>0 combined (all existing tests hold t=0) — untested.
- `ConfidenceWeightedComposer`'s `1e-9` epsilon boundary — only exact 0.0 tested.
- `ConfidenceWeightedComposer` with `scale <= 0` → unguarded `ZeroDivisionError` — untested.

```python
class TestBinaryComposer:
    def test_at_window_exact_boundary_returns_p_market(self):
        ...

class TestExponentialComposer:
    def test_tau_zero_raises_zero_division_error(self):
        ...

class TestMagnitudeTiedComposer:
    def test_severity_half_at_tau_combines_severity_and_decay(self):
        ...

class TestConfidenceWeightedComposer:
    def test_divergence_just_below_epsilon_returns_p_market(self):
        ...

    def test_scale_zero_raises_zero_division_error(self):
        ...
```

**Integration gap:** `test_c2a_e2e_gate.py` chains real composers → real blender for a
single all-agree golden path only; composer _disagreement_ feeding the blender, and a
multi-trade sequence using real (not hand-scripted) composer outputs, are untested.

### agent/research/crypto/crypto_data.py — 4 gaps

- `get_current_spot`'s `ValueError` (empty DB / `before_ts` earlier than all bars) — untested.
- `get_recent_returns`'s `prev_close > 0` guard (zero/negative price) — untested.
- `get_recent_returns` requesting more bars than exist (shorter-than-requested result) — untested.
- `get_recent_returns` on an empty series — untested.

```python
def test_get_current_spot_raises_value_error_when_no_bar_exists(session_factory):
    ...

def test_get_recent_returns_skips_zero_or_negative_prev_close(session_factory):
    ...

def test_get_recent_returns_with_insufficient_bars_returns_shorter_list(session_factory):
    ...

def test_get_recent_returns_empty_db_returns_empty_list(session_factory):
    ...
```

### agent/research/crypto/kelly_sizer.py — 6 gaps

- `kelly_cap` constructor mismatch → `ValueError` — untested.
- `p_final == 1.0` and `p_final == 0.0` (zero-variance guard, `variance <= 1e-12`) — both untested; core Kelly edge cases.
- `p_market == 0.0` (YES direction zero-odds) and `p_market == 1.0` (NO direction zero-odds) — untested.
- `abs(edge) == minimum_edge` exact boundary (should proceed to sizing, not zero out) — untested.

```python
def test_kelly_cap_mismatch_raises_value_error():
    ...

def test_p_final_equals_one_zero_variance_returns_zero_fraction():
    ...

def test_p_final_equals_zero_zero_variance_returns_zero_fraction():
    ...

def test_p_market_zero_yes_direction_zero_fraction():
    ...

def test_p_market_one_no_direction_zero_fraction():
    ...

def test_edge_exactly_at_minimum_edge_boundary_not_zeroed():
    ...
```

### agent/research/crypto/market_resolver.py — 5 gaps

- `_parse_iso_to_unix`'s naive-datetime branch (no `Z`/offset) — untested.
- `resolve()` raising `ValueError` for an _unparseable_ (not just missing) `end_date_iso` — untested.
- `load_markets_yaml` default for missing `polymarket_question` key, and empty-file case — untested.
- `time_to_resolution_years`'s exact `delta == 0` boundary — untested.
- `resolve()`'s missing-end-date guard with `end_date_iso=""` (vs `None`) — untested.

```python
def test_parse_iso_naive_string_assumed_utc():
    ...

def test_resolver_raises_on_unparseable_end_date_string():
    ...

def test_load_markets_yaml_defaults_missing_polymarket_question():
    ...

def test_load_markets_yaml_empty_file_returns_empty_list():
    ...

def test_time_to_resolution_years_exact_zero_boundary():
    ...
```

### agent/research/crypto/model.py — 7 gaps

None of the four early-exit diagnostic branches are ever triggered by any test:

```python
def test_market_not_found_returns_p_market_no_trade(session_factory):
    ...  # diagnostics["reason"]=="market_not_found"

def test_market_not_in_markets_yaml_returns_p_market_no_trade(session_factory):
    ...  # diagnostics["reason"]=="not_in_markets_yaml"

def test_all_four_modes_disabled_short_circuits(session_factory):
    ...  # diagnostics["reason"]=="all_modes_disabled"

def test_all_weights_zero_short_circuits(session_factory):
    ...  # diagnostics["reason"]=="all_weights_zero"

def test_empty_recent_returns_defaults_current_return_to_zero(session_factory):
    ...

def test_crypto_model_uses_real_default_fit_garch11_and_prob_barrier_hit(session_factory):
    ...  # exercises the lazy-import defaults instead of always-injected stubs

def test_crypto_model_propagates_valueerror_on_missing_end_date_iso(session_factory):
    ...
```

### agent/research/crypto/performance_tracker.py — 5 gaps

- Trailing-window truncation (`.limit(trailing_window)`) with more records than the window — untested.
- `trailing_brier`'s actual computed average — never asserted (only `n_closed_trades`/`is_disabled` are).
- `disable_streak` resetting to 0 after a good trade — untested.
- `brier == disable_brier_threshold` exact boundary (should NOT count as bad) — untested.
- "Sticky disable" — once disabled, never re-enabled — untested.

```python
def test_trailing_brier_only_uses_most_recent_window(session_factory):
    ...

def test_trailing_brier_computes_correct_average(session_factory):
    ...

def test_disable_streak_resets_after_good_trade(session_factory):
    ...

def test_brier_exactly_at_threshold_does_not_count_as_bad(session_factory):
    ...

def test_disabled_mode_stays_disabled_after_good_trade(session_factory):
    ...
```

### agent/research/crypto/question_parser.py — 6 gaps (refreshed 2026-07-04 post-82c46ffc/f296bd44)

`RawExtractCache` reuse-across-passes/instances and the **down**-direction inconsistency
case (`test_inconsistent_direction_rejected`) are now covered. Still untested: NaN/negative/
zero/`None` barrier values (all fall into the same `implausible_barrier` non-finite/
non-positive branch, `question_parser.py:116`), invalid `direction`, unparseable resolution
date, the **up**-barrier-at-or-below-open*spot half of the inconsistent-direction check
(`question_parser.py:129-131` — only the down-branch at line 132-134 has a test), and the
upper-bound half of the plausible-range check (existing hallucination test only exercises
the \_below*-lower-bound branch, barrier=8000 vs range (40000,110000); barrier > `10*hi` is
never hit).

```python
def test_nan_or_non_positive_barrier_rejected():
    ...  # barrier_usd in (float("nan"), -1.0, 0.0, None) -> implausible_barrier

def test_invalid_direction_rejected():
    ...  # direction="sideways" -> implausible_barrier

def test_unparseable_resolution_date_rejected():
    ...  # resolution_date_iso="not-a-date" -> unparseable_date

def test_up_barrier_at_or_below_open_spot_rejected():
    ...  # direction="up", barrier <= open_spot -> inconsistent_direction (only down-branch tested today)

def test_barrier_above_upper_bound_rejected():
    ...  # barrier > 10 * hi -> implausible_barrier (only below-lower-bound is covered)
```

---

## agent/validation/ and agent/strategy/

### agent/validation/backtest.py — 6 gaps

```python
def test_walk_forward_backtest_skips_missing_market_id(session):
    ...

def test_walk_forward_backtest_skips_market_with_no_clob_tokens(session):
    ...

def test_walk_forward_backtest_empty_store_reliability_curve_and_window(session):
    ...  # reliability_curve == [(None,None)]*10, window_start_ts==window_end_ts==0

def test_replay_empty_for_unknown_token(session):
    ...

def test_walk_forward_backtest_expected_rate_clamped_at_extreme_predictions(session):
    ...  # p_hat in {0.0, 1.0} -> expected_rate stays in [1e-9, 1-1e-9]
```

### agent/validation/baseline.py — 1 gap

```python
def test_market_price_model_passes_through_boundary_prices():
    ...  # price=0.0 and price=1.0, no clamping
```

### agent/validation/crypto_backtest.py — 3 gaps remaining (the C3a verdict orchestrator)

**Closed (uncommitted, 2026-07-08)** in `tests/validation/test_crypto_backtest.py`:
`test_run_validation_requires_one_percent_cost_in_costs` (costs missing 0.01 → ValueError),
`test_verdict_inconclusive_when_edge_does_not_survive_cost` (the cost-survival gate), and
`test_per_mode_aggregates_mean_weight_across_predictions` (real, non-empty `p_modes`
aggregation with a mode missing from one market's dict).

Still open:

```python
def test_verdict_boundary_exactly_twenty_markets_passes_coverage_gate(session):
    ...

def test_per_market_contents_match_predictions_and_resolutions(session):
    ...

def test_cost_scenario_zero_trades_uses_fallback_periods_per_year(session):
    ...
```

### agent/validation/metrics.py — 4 gaps

```python
def test_kupiec_all_exceptions_are_trials():
    ...  # 100% exception rate, high-side boundary

def test_reliability_curve_exact_min_per_bin_boundary():
    ...

def test_reliability_curve_single_bin():
    ...  # n_bins=1
```

### agent/validation/pnl.py — 7 gaps

```python
def test_entry_price_at_boundary_skips_trade():
    ...  # p_market exactly 0.0 or 1.0

def test_unresolved_market_is_skipped():
    ...

def test_no_direction_winning_and_losing_trades():
    ...  # direction="no" is never tested anywhere in the file

def test_one_position_per_market_false_allows_multiple_entries():
    ...

def test_negative_position_size_no_trade():
    ...

def test_missing_diagnostics_keys_use_defaults():
    ...

def test_simulate_pnl_feeds_risk_metrics_end_to_end():
    ...  # real integration: pnl.py output -> risk_metrics.py input
```

### agent/validation/risk_metrics.py — 8 gaps

```python
def test_profit_factor_mixed_trades():
    ...  # imported by test file but never called anywhere

def test_profit_factor_all_wins_is_inf():
    ...

def test_profit_factor_no_trades_is_zero():
    ...

def test_sharpe_ratio_insufficient_data_returns_zero():
    ...

def test_sharpe_ratio_zero_variance_returns_zero():
    ...

def test_sortino_ratio_empty_and_no_downside():
    ...

def test_max_drawdown_empty_and_nonpositive_start():
    ...

def test_win_rate_empty_trades_is_zero():
    ...

def test_brier_skill_score_zero_baseline():
    ...  # baseline_brier==0.0 guard against division by zero

def test_bootstrap_skill_ci_empty_or_mismatched_returns_zero_tuple():
    ...
```

### agent/validation/paper_trade.py — 7 gaps

```python
def test_paper_trade_engine_replaces_open_position_on_second_signal():
    ...

def test_paper_trade_engine_no_side_wins_pays_off():
    ...  # NO position winning is never tested anywhere

def test_paper_trade_engine_result_empty_pairs_defaults():
    ...

def test_paper_trade_engine_touch_ts_tracks_min_max():
    ...

def test_paper_trade_engine_custom_slippage_model_shifts_fill_price():
    ...  # only the always-zero default slippage is ever exercised

def test_paper_trade_engine_double_resolve_does_not_double_count_pnl():
    ...

def test_paper_trade_engine_unresolved_prediction_excluded_from_metrics():
    ...
```

### agent/validation/resolution_poller.py — 5 gaps

- **No try/except around `get_market()`** — a transient HTTP error kills the whole poll
  generator for every tracked market, not just the failing one. Untested and looks like
  a real robustness gap.

```python
@respx.mock
async def test_resolution_poller_propagates_http_error():
    ...

@respx.mock
async def test_resolution_poller_indeterminate_closed_market_keeps_polling():
    ...  # closed=True but outcomePrices like [0.5, 0.5] -> risk of unbounded polling

@respx.mock
async def test_resolution_poller_empty_outcome_prices_yields_no_tick():
    ...

@respx.mock
async def test_resolution_poller_tracks_multiple_markets_independently():
    ...

@respx.mock
async def test_resolution_poller_stream_exhausts_naturally_when_all_resolved():
    ...
```

### agent/validation/types.py — 3 gaps

```python
def test_resolved_outcome_and_trade_signal_are_frozen():
    ...  # only Prediction has a mutation test; others don't

def test_backtest_result_defaults():
    ...

def test_backtest_result_is_not_hashable_due_to_list_field():
    ...  # frozen=True but a mutable list default field breaks hashability; worth documenting
```

### agent/strategy/threshold.py — 4 gaps

```python
def test_threshold_strategy_zero_threshold_fires_on_zero_edge():
    ...  # edge_threshold=0.0 never tested; only the default 0.05 is exercised

def test_threshold_strategy_float_rounding_at_boundary():
    ...  # regression test for the round(...,10) defensive rounding

def test_threshold_strategy_market_price_at_zero_boundary():
    ...
```

### agent/scripts/run_crypto_validation.py — test file exists but is a skeleton (still fully open)

`main()` is entirely untested — not even a `--help` smoke test exists, unlike `agent/cli.py`.
An untracked `tests/scripts/test_run_crypto_validation.py` has since appeared with ~20
well-named test functions covering `_iso_to_unix`, `build_resolutions`,
`_symbol_price_range`/`_earliest_snapshot_ts`/`_open_spot_for_market`, `write_report`, and
`main()` itself (including the missing-`--refresh`-wiring bug from item #5 above, via
`test_main_applies_defaults_for_db_output_cache_dir`) — but every body is `pass` or a
`# TODO:` comment with no real assertion. It collects and passes under pytest today while
verifying nothing. Treat all 6 gaps below as still open until real bodies replace the TODOs;
the skeleton file is a good worklist (it already names the right fixtures and exact expected
values) but is not itself evidence of coverage.

```python
def test_run_crypto_validation_main_requires_window_args(capsys):
    ...  # --window-start/--window-end are required=True

def test_build_resolutions_counts_unclean_markets():
    ...

def test_iso_to_unix_handles_malformed_input():
    ...  # _iso_to_unix("") / ("not-a-date") both return None
```

---

## Cross-cutting integration gaps

1. `pnl.py` → `risk_metrics.py` never chained end-to-end (each unit-tested against hand-built fixtures only).
2. `paper_trade.py` ↔ `resolution_poller.py` never wired together in any test, despite the poller's docstring implying it feeds a paper-trading consumer.
3. ~~`_decide_verdict`'s cost-survival gate (Sharpe@1%cost ≤ 0) is the one priority-ordered gate never independently isolated~~ **CLOSED (uncommitted, 2026-07-08)**.
4. `run_crypto_validation.py`'s `main()` (CLI wiring, required args, the apparently-dead `--refresh` flag) has zero coverage, even though the pipeline logic it calls (`run_pipeline`) is well covered by proxy through `tests/validation/test_c3a_cli_smoke.py`.
5. `tests/validation/test_c3a_cli_smoke.py` only ever drives 1-3 synthetic markets — nowhere near the `actually_tested >= 20` coverage gate, so by the test's own admission (in-file comment) the verdict can never be observed as a real CONTINUE or STOP, only "a valid enum member."
