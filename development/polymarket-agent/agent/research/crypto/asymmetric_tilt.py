"""AsymmetricTilt: long-only +0.05 tilt toward P_bridge.

Captures the one-directional shape of the alpha thesis: Polymarket
under-prices barrier-hit probabilities during panic (P_market < P_bridge).
We do NOT believe it systematically over-prices in calm; therefore no tilt
in the opposite direction.

Output clipped to [0, 1] for safety.
"""


class AsymmetricTilt:
    def __init__(self, tilt_magnitude: float = 0.05):
        self.tilt_magnitude = tilt_magnitude

    def apply(
        self,
        p_blend: float,
        p_market: float,
        p_bridge: float,
    ) -> float:
        if p_bridge > p_market:
            return min(1.0, max(0.0, p_blend + self.tilt_magnitude))
        return p_blend
