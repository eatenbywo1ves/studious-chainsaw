"""Minimal CLI entrypoint for the polymarket-agent.

Phase 1A provides two subcommands as wireframes:
  - backtest   : run walk_forward_backtest with a chosen baseline
  - paper-trade: start a paper-trade-live session

Full subcommand implementations land in Phase 1B+ when there are real models
and operational workflows.  Phase 1A's CLI is a structural placeholder that
exists so the entrypoint contract is locked in.
"""

import argparse
import sys
from collections.abc import Sequence


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="polymarket-agent",
        description="Autonomous Polymarket fair-value trading agent (Phase 1A: validation infra).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    backtest = sub.add_parser(
        "backtest",
        help="Run walk_forward_backtest against Phase 0 stored history.",
    )
    backtest.add_argument(
        "--model",
        choices=["last_traded_price", "constant_half"],
        default="last_traded_price",
        help="Baseline model to evaluate (Phase 1A only has baselines).",
    )

    paper_trade = sub.add_parser(
        "paper-trade",
        help="Start a paper-trade-live session against current Polymarket.",
    )
    paper_trade.add_argument(
        "--model",
        choices=["last_traded_price", "constant_half"],
        default="last_traded_price",
    )
    paper_trade.add_argument(
        "--market-id",
        action="append",
        default=[],
        help="Market id to follow (may be repeated).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point.  Returns the process exit code.

    Phase 1A: parses args, prints a stub message, returns 0 for valid
    subcommands.  Phase 1B replaces these stubs with real implementations.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse calls sys.exit on --help (code 0) and on errors (code 2).
        return int(e.code) if e.code is not None else 0

    if args.command == "backtest":
        print(
            f"[stub] would run walk_forward_backtest with model={args.model}. "
            "Phase 1B will wire this up."
        )
        return 0
    if args.command == "paper-trade":
        print(
            f"[stub] would start paper-trade-live with model={args.model}, "
            f"markets={args.market_id}. Phase 1B will wire this up."
        )
        return 0
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
