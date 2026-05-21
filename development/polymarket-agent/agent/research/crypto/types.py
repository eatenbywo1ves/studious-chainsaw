"""Frozen result-record types for the C2 composition pipeline.

STRUCTURAL DEFENSE: Many of these types clip their fields at construction
(e.g., severity to [0,1], KellyFraction to [0, kelly_cap]).  Consumers can
trust the invariants without re-checking.
"""

from dataclasses import dataclass, field
from typing import Literal


def _clip(x: float, lo: float, hi: float) -> float:
    """Clip x to [lo, hi]."""
    return min(max(x, lo), hi)


@dataclass(frozen=True)
class ShockState:
    """Output of ShockDetector. `active` is the binary gate; `severity` in [0, 1]
    is the magnitude used by MagnitudeTiedComposer.  `severity` is clipped to
    [0, 1] at construction (prevents passing unbounded magnitudes downstream).
    """

    active: bool
    severity: float
    spot_signal: bool
    news_signal: bool
    time_since_shock_seconds: int

    def __post_init__(self):
        # Frozen dataclass __post_init__ workaround via object.__setattr__
        object.__setattr__(self, "severity", _clip(self.severity, 0.0, 1.0))


@dataclass(frozen=True)
class CryptoMarketMapping:
    """A single Polymarket market resolved to its crypto pair + barrier."""

    market_id: str
    symbol: str
    barrier_price: float
    direction: Literal["up", "down"]
    resolution_ts: int


@dataclass(frozen=True)
class CryptoMarketMappingFile:
    """One row from markets.yaml (pre-resolution; before end_date_iso lookup)."""

    market_id: str
    polymarket_question: str
    symbol: str
    barrier_price: float
    direction: Literal["up", "down"]


@dataclass(frozen=True)
class ModeWeights:
    """Output of BayesianBlender's weighting step. Sums to 1.0 normally,
    or all-zero if every mode is disabled (caller interprets as no-trade).
    """

    w_binary: float
    w_exp: float
    w_magnitude: float
    w_confidence: float

    def is_all_disabled(self) -> bool:
        return (
            self.w_binary == 0.0
            and self.w_exp == 0.0
            and self.w_magnitude == 0.0
            and self.w_confidence == 0.0
        )


@dataclass(frozen=True)
class BlendOutput:
    p_blend: float
    weights: ModeWeights


@dataclass(frozen=True)
class AgreementVerdict:
    allowed: bool
    long_count: int
    short_count: int
    direction: Literal["long", "short", "none"]


KELLY_CAP_DEFAULT = 0.10


@dataclass(frozen=True)
class KellyFraction:
    """Output of KellySizer. fraction clipped to [0, KELLY_CAP_DEFAULT] at
    construction.  direction records whether this is a long-YES or long-NO bet.
    """

    fraction: float
    direction: Literal["yes", "no"]
    raw_kelly_pre_half: float

    def __post_init__(self):
        object.__setattr__(self, "fraction", _clip(self.fraction, 0.0, KELLY_CAP_DEFAULT))


@dataclass(frozen=True)
class ModeState:
    """Per-mode state surfaced by PerformanceTracker."""

    mode_name: str
    trailing_brier: float
    brier_floor: float
    is_disabled: bool
    n_closed_trades: int
