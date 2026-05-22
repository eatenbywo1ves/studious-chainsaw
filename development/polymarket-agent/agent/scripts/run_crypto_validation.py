"""C3a spot-only validation harness — CLI entrypoint.

Wires the whole pipeline end-to-end:

    enumerate resolved crypto markets (Gamma)
      -> parse question (LLM) pass 1
      -> persist Market rows + ingest CLOB price history
      -> ingest Binance OHLCV over each market's lifetime
      -> parse question pass 2 (now with a real underlying price range)
      -> build a parse-backed MarketResolver (the pipeline->model bridge)
      -> build resolutions from settled outcome prices
      -> run_validation orchestrator -> ValidationReport
      -> write JSON report + human-readable summary with the VERDICT.

`run_pipeline` takes every external dependency by keyword so the smoke test
can drive the real pipeline with injected fakes (no network / no LLM).  The
production `main()` builds the real dependencies (httpx, Binance, OpenAI).
"""

from __future__ import annotations

import argparse
import asyncio
import functools
import json
from dataclasses import asdict
from datetime import datetime, timezone

from agent.data.crypto_ingest import CryptoIngestService
from agent.data.models import MarketDTO
from agent.data.polymarket_enumerate import enumerate_resolved_crypto_markets
from agent.data.polymarket_history import ingest_market_price_history
from agent.research.crypto.agreement_filter import AgreementFilter
from agent.research.crypto.asymmetric_tilt import AsymmetricTilt
from agent.research.crypto.barrier_bridge import prob_barrier_hit
from agent.research.crypto.blender import BayesianBlender
from agent.research.crypto.composers import (
    BinaryComposer,
    ConfidenceWeightedComposer,
    ExponentialComposer,
    MagnitudeTiedComposer,
)
from agent.research.crypto.crypto_data import CryptoDataAccess
from agent.research.crypto.kelly_sizer import KellySizer
from agent.research.crypto.market_resolver import MarketResolver
from agent.research.crypto.model import crypto_model
from agent.research.crypto.performance_tracker import PerformanceTracker
from agent.research.crypto.question_parser import RawExtractCache, validate_parse
from agent.research.crypto.shock_detector import SpotOnlyShockDetector
from agent.research.crypto.types import CryptoMarketMappingFile
from agent.research.crypto.vol_estimator import fit_garch11
from agent.store.repository import save_price_history, upsert_market
from agent.store.schema import CryptoBar, PriceSnapshot
from agent.validation.baseline import market_price_model
from agent.validation.crypto_backtest import ValidationReport, run_validation
from agent.validation.types import ResolvedOutcome

# Statuses excluded after parse pass 1 (cheap, range-free filter).  A market
# rejected here is not even worth ingesting OHLCV for.
_PASS1_REJECT = {"not_crypto_barrier", "low_confidence", "unparseable_date"}

# How far before the resolution ts to start the OHLCV backfill when no CLOB
# price history exists yet.  ~120 days of hourly bars comfortably exceeds the
# 100-observation GARCH(1,1) floor in fit_garch11.
_OHLCV_LOOKBACK_SECONDS = 120 * 86400


def _iso_to_unix(iso_str: str) -> int | None:
    """Parse an ISO-8601 string (optional trailing Z) to Unix seconds (UTC).

    Returns None on any parse failure so callers can treat the market as
    having no clean resolution timestamp.
    """
    if not iso_str:
        return None
    try:
        s = iso_str[:-1] + "+00:00" if iso_str.endswith("Z") else iso_str
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError):
        return None


def build_resolutions(
    markets: list[MarketDTO],
) -> tuple[dict[str, ResolvedOutcome], int]:
    """Build the ground-truth resolutions dict from settled outcome prices.

    A cleanly-resolved binary market has ``outcome_prices`` settled to
    ``[1.0, 0.0]`` (YES won) or ``[0.0, 1.0]`` (NO won).  Anything else
    (still-trading prices, missing prices, malformed) has no clean resolution
    and is excluded + counted.

    Returns ``(resolutions, n_unclean)``.
    """
    resolutions: dict[str, ResolvedOutcome] = {}
    n_unclean = 0
    for market in markets:
        prices = market.outcome_prices
        resolved_ts = _iso_to_unix(market.end_date_iso or "")
        if len(prices) < 1 or resolved_ts is None:
            n_unclean += 1
            continue
        if prices[0] == 1.0:
            outcome = 1
        elif prices[0] == 0.0:
            outcome = 0
        else:
            n_unclean += 1
            continue
        resolutions[market.id] = ResolvedOutcome(
            market_id=market.id,
            outcome=outcome,
            resolved_ts=resolved_ts,
        )
    return resolutions, n_unclean


def _build_pipeline_kwargs(session_factory, resolver: MarketResolver) -> dict:
    """Construct the crypto_model component set (mirrors the C2-A e2e gate)
    using real implementations, bound to a parse-backed MarketResolver."""
    from agent.store.schema import Market

    def get_market(market_id: str):
        with session_factory() as session:
            return session.get(Market, market_id)

    def get_last_shock_ts(market_id: str):
        return None

    return dict(
        get_market=get_market,
        get_last_shock_ts=get_last_shock_ts,
        market_resolver=resolver,
        crypto_data=CryptoDataAccess(session_factory=session_factory),
        shock_detector=SpotOnlyShockDetector(spot_threshold_k=3.0),
        composers=[
            BinaryComposer(),
            ExponentialComposer(),
            MagnitudeTiedComposer(),
            ConfidenceWeightedComposer(),
        ],
        blender=BayesianBlender(),
        agreement_filter=AgreementFilter(epsilon=0.08, min_active_count=3),
        tilt=AsymmetricTilt(tilt_magnitude=0.05),
        sizer=KellySizer(),
        performance_tracker=PerformanceTracker(trailing_window=15),
        session_factory=session_factory,
        fit_garch11=fit_garch11,
        prob_barrier_hit=prob_barrier_hit,
    )


def _symbol_price_range(
    session_factory, symbol: str
) -> tuple[float, float] | None:
    """Return (min low, max high) over all stored bars for ``symbol``, or None
    if no bars exist for it."""
    with session_factory() as session:
        rows = (
            session.query(CryptoBar).filter(CryptoBar.symbol == symbol).all()
        )
    if not rows:
        return None
    return (min(r.low for r in rows), max(r.high for r in rows))


def _earliest_snapshot_ts(session_factory, market_id: str) -> int | None:
    with session_factory() as session:
        row = (
            session.query(PriceSnapshot)
            .filter(PriceSnapshot.market_id == market_id)
            .order_by(PriceSnapshot.ts.asc())
            .first()
        )
    return row.ts if row is not None else None


async def run_pipeline(
    *,
    settings,
    session_factory,
    polymarket_client,
    crypto_ingest: CryptoIngestService,
    llm_extract,
    raw_cache: RawExtractCache,
    window_start_iso: str,
    window_end_iso: str,
    model_override=None,
) -> ValidationReport:
    """Execute the full validation pipeline and return the ValidationReport.

    `model_override` is for tests only: when provided it replaces the real
    crypto_model partial passed to run_validation.  Production callers leave
    it None so the real pipeline is exercised.
    """
    # 1. Enumerate the resolved crypto-market population.
    dtos = await enumerate_resolved_crypto_markets(
        polymarket_client,
        window_start_iso=window_start_iso,
        window_end_iso=window_end_iso,
    )
    n_enumerated = len(dtos)

    # 2. Parse pass 1 — no price range yet; cheap reject of obvious non-targets.
    #    The raw LLM dict is cached here so pass 2 reuses it (LLM called once
    #    per market) and the verdict stays reproducible across runs.
    pass1: list[tuple[MarketDTO, object]] = []
    for dto in dtos:
        raw = raw_cache.extract(dto.id, dto.question, llm_extract)
        parsed = validate_parse(
            dto.id,
            raw,
            underlying_price_range=None,
            confidence_threshold=0.85,
        )
        if parsed.status not in _PASS1_REJECT:
            pass1.append((dto, parsed))
    n_parsed_ok_pass1 = len(pass1)

    # 3. Persist Market rows + ingest CLOB YES-token price history.
    for dto, _parsed in pass1:
        with session_factory() as session:
            upsert_market(session, dto)
            session.commit()
        await ingest_market_price_history(
            polymarket_client, save_price_history, session_factory(), dto
        )

    # 4. Ingest Binance OHLCV across each kept market's lifetime.
    had_ohlcv_symbols: set[str] = set()
    for dto, parsed in pass1:
        symbol = parsed.symbol
        resolution_ts = parsed.resolution_ts
        if symbol is None or resolution_ts is None:
            continue
        earliest = _earliest_snapshot_ts(session_factory, dto.id)
        start_ts = (
            earliest
            if earliest is not None
            else resolution_ts - _OHLCV_LOOKBACK_SECONDS
        )
        start_ts = min(start_ts, resolution_ts - _OHLCV_LOOKBACK_SECONDS)
        await crypto_ingest.ingest_history(symbol, "1h", start_ts, resolution_ts)
        if _symbol_price_range(session_factory, symbol) is not None:
            had_ohlcv_symbols.add(symbol)

    # 5. Parse pass 2 — re-validate with a real underlying price range derived
    #    from the ingested bars.  Reuses the SAME raw LLM dict cached in pass 1
    #    (no second LLM call), so a market's pass-2 admission is deterministic
    #    and reproducible across runs.
    surviving: list[tuple[MarketDTO, object]] = []
    for dto, parsed in pass1:
        symbol = parsed.symbol
        price_range = (
            _symbol_price_range(session_factory, symbol)
            if symbol is not None
            else None
        )
        raw = raw_cache.extract(dto.id, dto.question, llm_extract)
        reparsed = validate_parse(
            dto.id,
            raw,
            underlying_price_range=price_range,
            confidence_threshold=0.85,
        )
        if reparsed.status == "ok":
            surviving.append((dto, reparsed))
    n_passed_validation_pass2 = len(surviving)

    # 6. Build the parse-backed MarketResolver (pipeline -> model bridge).
    mappings = [
        CryptoMarketMappingFile(
            market_id=dto.id,
            polymarket_question=dto.question,
            symbol=parsed.symbol,
            barrier_price=parsed.barrier,
            direction=parsed.direction,
        )
        for dto, parsed in surviving
    ]
    resolver = MarketResolver(mappings)
    surviving_dtos = [dto for dto, _ in surviving]
    surviving_ids = [dto.id for dto in surviving_dtos]

    # 7. Ground-truth resolutions from settled outcome prices.
    resolutions, _n_unclean = build_resolutions(surviving_dtos)
    n_had_clean_resolution = len(resolutions)

    # 8. Build the crypto_model partial (or use the injected test override).
    if model_override is not None:
        model = model_override
    else:
        pipeline_kwargs = _build_pipeline_kwargs(session_factory, resolver)
        model = functools.partial(crypto_model, **pipeline_kwargs)

    baseline = market_price_model

    # 9. Upstream coverage funnel.
    upstream_coverage = {
        "enumerated": n_enumerated,
        "parsed_ok_pass1": n_parsed_ok_pass1,
        "passed_validation_pass2": n_passed_validation_pass2,
        "had_ohlcv": len(
            [
                1
                for dto, parsed in surviving
                if parsed.symbol in had_ohlcv_symbols
            ]
        ),
        "had_clean_resolution": n_had_clean_resolution,
    }

    # 10. Orchestrate.
    window = (window_start_iso, window_end_iso)
    with session_factory() as session:
        report = run_validation(
            session,
            model=model,
            baseline_model=baseline,
            resolutions=resolutions,
            market_ids=surviving_ids,
            window=window,
            upstream_coverage=upstream_coverage,
        )
    return report


def write_report(report: ValidationReport, output_path) -> dict:
    """Serialize the report to JSON (handling float by_cost keys and tuples)
    and print a human-readable summary.  Returns the serialized dict."""
    payload = {
        "window": list(report.window),
        "coverage": dict(report.coverage),
        "model_brier": report.model_brier,
        "baseline_brier": report.baseline_brier,
        "brier_skill_score": report.brier_skill_score,
        "brier_skill_ci": list(report.brier_skill_ci),
        "reliability_curve": [list(pt) for pt in report.reliability_curve],
        "kupiec_zone": report.kupiec_zone,
        # by_cost has FLOAT keys -> JSON requires string keys.
        "by_cost": {
            str(cost): asdict(metrics)
            for cost, metrics in report.by_cost.items()
        },
        "per_market": [asdict(m) for m in report.per_market],
        "per_mode": {
            mode: asdict(result) for mode, result in report.per_mode.items()
        },
        "verdict": report.verdict,
        "verdict_rationale": report.verdict_rationale,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print("=" * 70)
    print("C3a SPOT-ONLY VALIDATION REPORT")
    print("=" * 70)
    print(f"Window: {report.window[0]} .. {report.window[1]}")
    print("Coverage funnel:")
    for stage, count in report.coverage.items():
        print(f"  {stage:>28}: {count}")
    print(f"Model Brier:    {report.model_brier:.4f}")
    print(f"Baseline Brier: {report.baseline_brier:.4f}")
    print(
        f"Brier skill:    {report.brier_skill_score:.4f} "
        f"(CI {report.brier_skill_ci[0]:.4f} .. {report.brier_skill_ci[1]:.4f})"
    )
    print()
    print(f"  >>> VERDICT: {report.verdict} <<<")
    print(f"  {report.verdict_rationale}")
    print("=" * 70)

    return payload


def _real_llm_extract(question: str) -> dict:
    """Production LLM extractor: ask OpenAI (JSON mode) for the structured
    fields the question parser expects.  Imported lazily so the test path
    never touches the openai SDK."""
    import os

    from openai import OpenAI

    client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    system = (
        "You extract structured fields from a Polymarket crypto barrier "
        "question. Respond with a JSON object with exactly these keys: "
        "symbol (Binance pair like 'BTCUSDT'), barrier_usd (number), "
        "direction ('up' or 'down'), resolution_date_iso (ISO-8601 string), "
        "confidence (0..1 float), is_crypto_barrier_market (bool). If the "
        "question is not a crypto barrier market, set is_crypto_barrier_market "
        "to false and confidence to 0."
    )
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": question},
        ],
    )
    return json.loads(resp.choices[0].message.content)


def main(argv=None) -> None:
    """CLI entrypoint: build real dependencies and run the full pipeline."""
    import httpx

    from agent.config import Settings
    from agent.data.crypto_client import BinanceClient
    from agent.data.polymarket_client import PolymarketClient
    from agent.store.db import init_db, make_engine, make_session_factory

    parser = argparse.ArgumentParser(
        description="Run the C3a spot-only Polymarket validation harness."
    )
    parser.add_argument("--window-start", required=True, dest="window_start")
    parser.add_argument("--window-end", required=True, dest="window_end")
    parser.add_argument(
        "--db", default="sqlite:///crypto_validation.db", dest="db"
    )
    parser.add_argument(
        "--output", default="crypto_validation_report.json", dest="output"
    )
    parser.add_argument(
        "--cache-dir", default=".parse_cache", dest="cache_dir"
    )
    parser.add_argument("--refresh", action="store_true", dest="refresh")
    args = parser.parse_args(argv)

    settings = Settings(database_url=args.db)
    engine = make_engine(args.db)
    init_db(engine)
    session_factory = make_session_factory(engine)

    async def _run() -> ValidationReport:
        async with httpx.AsyncClient(
            timeout=settings.http_timeout_seconds
        ) as http:
            polymarket_client = PolymarketClient(
                settings=settings, http_client=http
            )
            binance_client = BinanceClient(http_client=http)
            crypto_ingest = CryptoIngestService(
                binance_client, session_factory
            )
            return await run_pipeline(
                settings=settings,
                session_factory=session_factory,
                polymarket_client=polymarket_client,
                crypto_ingest=crypto_ingest,
                llm_extract=_real_llm_extract,
                raw_cache=RawExtractCache(args.cache_dir),
                window_start_iso=args.window_start,
                window_end_iso=args.window_end,
            )

    report = asyncio.run(_run())
    write_report(report, args.output)


if __name__ == "__main__":
    main()
