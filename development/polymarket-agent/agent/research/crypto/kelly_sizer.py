"""KellySizer: half-Kelly position sizing for binary prediction markets.

For a YES buy at market price q with estimated probability P:
  edge       = P - q
  variance   = P * (1 - P)
  raw_kelly  = q * edge / variance   (q in the prefactor because payoff per
                                       dollar on win is (1-q)/q for a YES buy)
  half_kelly = 0.5 * raw_kelly
  fraction   = clip(abs(half_kelly), 0.0, kelly_cap)
  direction  = "yes" if edge > 0 else "no"

For a NO buy (equivalent to selling YES) the formula is symmetric — we can
use the same formula because we're returning abs(fraction) and recording
direction separately.

Returns KellyFraction(fraction=0, ...) when abs(edge) < minimum_edge to
save transaction costs on trades that are theoretically positive but
practically uneconomic.
"""

from agent.research.crypto.types import KELLY_CAP_DEFAULT, KellyFraction


class KellySizer:
    """Half-Kelly position sizer for binary prediction markets.

    Attributes:
        kelly_multiplier: Fraction of full Kelly to use (default 0.5).
        kelly_cap: Maximum fraction of bankroll to allocate (default 0.10).
        minimum_edge: Minimum |edge| required to size a position (default 0.02).

    Note:
        kelly_cap MUST equal KELLY_CAP_DEFAULT from types.py (currently 0.10).
        KellyFraction.__post_init__ clips fraction to KELLY_CAP_DEFAULT, so a
        divergent sizer-level cap would be silently overridden by the type.

    Example:
        >>> sizer = KellySizer()
        >>> result = sizer.size(p_final=0.31, p_market=0.10)
        >>> result.direction
        'yes'
    """

    def __init__(
        self,
        kelly_multiplier: float = 0.5,
        kelly_cap: float = 0.10,
        minimum_edge: float = 0.02,
    ):
        """Initialize KellySizer.

        Args:
            kelly_multiplier: Multiplier applied to raw Kelly fraction (default 0.5).
            kelly_cap: Maximum position size as fraction of bankroll (default 0.10).
            minimum_edge: Minimum absolute edge required to open a position (default 0.02).

        Raises:
            ValueError: If kelly_cap does not match KELLY_CAP_DEFAULT from types.py.
        """
        if kelly_cap != KELLY_CAP_DEFAULT:
            raise ValueError(
                f"KellySizer.kelly_cap ({kelly_cap}) must match "
                f"types.KELLY_CAP_DEFAULT ({KELLY_CAP_DEFAULT}) — the "
                f"KellyFraction dataclass clips to KELLY_CAP_DEFAULT, "
                f"which would silently override a different sizer cap."
            )
        self.kelly_multiplier = kelly_multiplier
        self.kelly_cap = kelly_cap
        self.minimum_edge = minimum_edge

    def size(
        self,
        p_final: float,
        p_market: float,
    ) -> KellyFraction:
        """Compute half-Kelly position size for a binary market trade.

        Args:
            p_final: Model's final probability estimate for YES outcome.
            p_market: Current market price for YES (probability implied by market).

        Returns:
            KellyFraction with fraction clipped to [0, kelly_cap], direction
            indicating "yes" (buy YES) or "no" (buy NO), and raw_kelly_pre_half
            for diagnostics.
        """
        edge = p_final - p_market
        direction = "yes" if edge >= 0 else "no"

        if abs(edge) < self.minimum_edge:
            return KellyFraction(fraction=0.0, direction=direction, raw_kelly_pre_half=0.0)

        if direction == "yes":
            q = p_market
            variance = p_final * (1.0 - p_final)
        else:
            q = 1.0 - p_market
            # For NO buy: outcomes flipped; variance computed against (1-p_final)
            variance = (1.0 - p_final) * p_final  # algebraically the same

        if variance <= 1e-12:
            return KellyFraction(fraction=0.0, direction=direction, raw_kelly_pre_half=0.0)

        raw_kelly = q * abs(edge) / variance
        half = self.kelly_multiplier * raw_kelly
        # KellyFraction's __post_init__ clips fraction to [0, KELLY_CAP_DEFAULT=0.10]
        return KellyFraction(
            fraction=half,
            direction=direction,
            raw_kelly_pre_half=raw_kelly,
        )
