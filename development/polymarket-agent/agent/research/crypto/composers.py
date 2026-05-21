"""Composer implementations: each turns (p_market, p_bridge, shock_state)
into a single mode's P_mode.

All 4 composers gate on `shock_state.active`.  When not active, P_mode = P_market
unconditionally (the model has no opinion absent a shock).
"""

import math
from abc import ABC, abstractmethod

from agent.research.crypto.types import ShockState


class Composer(ABC):
    name: str  # subclass sets to "binary" | "exp" | "magnitude" | "confidence"

    @abstractmethod
    def compose(
        self,
        p_market: float,
        p_bridge: float,
        shock_state: ShockState,
    ) -> float:
        """Returns P_mode in [0, 1]."""


class BinaryComposer(Composer):
    """P_mode = P_bridge inside the shock window; P_market outside or no-shock."""

    name = "binary"

    def __init__(self, window_seconds: int = 14 * 86400):
        self.window_seconds = window_seconds

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        if shock_state.time_since_shock_seconds < self.window_seconds:
            return p_bridge
        return p_market


class ExponentialComposer(Composer):
    """P_mode = lambda(t) * P_bridge + (1-lambda(t)) * P_market;
    lambda(t) = exp(-t / tau).  tau default = 7 days.
    """

    name = "exp"

    def __init__(self, tau_seconds: int = 7 * 86400):
        self.tau_seconds = tau_seconds

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        t = shock_state.time_since_shock_seconds
        lam = math.exp(-t / self.tau_seconds)
        return lam * p_bridge + (1.0 - lam) * p_market


class MagnitudeTiedComposer(Composer):
    """lambda(t, severity) = severity * exp(-t / tau).
    severity is already clipped to [0,1] by ShockState's __post_init__.
    """

    name = "magnitude"

    def __init__(self, tau_seconds: int = 7 * 86400):
        self.tau_seconds = tau_seconds

    def compose(self, p_market, p_bridge, shock_state) -> float:
        if not shock_state.active:
            return p_market
        t = shock_state.time_since_shock_seconds
        lam = shock_state.severity * math.exp(-t / self.tau_seconds)
        return lam * p_bridge + (1.0 - lam) * p_market


class ConfidenceWeightedComposer(Composer):
    """lambda = sigmoid((|P_market - P_bridge| - threshold) / scale).
    Does NOT use shock_state.time — purely divergence-driven.

    KNOWN HAZARD: can double-down during regime changes.  AgreementFilter
    is the primary safety against this; see spec §6.3.
    """

    name = "confidence"

    def __init__(self, threshold: float = 0.10, scale: float = 0.05):
        self.threshold = threshold
        self.scale = scale

    def compose(self, p_market, p_bridge, shock_state) -> float:
        divergence = abs(p_market - p_bridge)
        if divergence <= 1e-9:
            return p_market
        z = (divergence - self.threshold) / self.scale
        lam = 1.0 / (1.0 + math.exp(-z))
        return lam * p_bridge + (1.0 - lam) * p_market
