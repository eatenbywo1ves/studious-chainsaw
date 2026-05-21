"""AgreementFilter: directional consensus gate.

Requires >= min_active_count modes to agree on direction before allowing a
trade.  epsilon = 0.08 (per brainstorm Option-alpha): mode signals are
counted only when |P_mode - P_market| > epsilon (strict).  Neutrals don't
count toward either direction.

Disabled-mode handling: caller filters disabled modes out of `p_modes`
before calling.  min_active_count applies to the passed dict; disabling a
mode strengthens consensus among survivors.
"""

from agent.research.crypto.types import AgreementVerdict


class AgreementFilter:
    def __init__(
        self,
        epsilon: float = 0.08,
        min_active_count: int = 3,
    ):
        self.epsilon = epsilon
        self.min_active_count = min_active_count

    def evaluate(
        self,
        p_market: float,
        p_modes: dict[str, float],
    ) -> AgreementVerdict:
        long_count = sum(1 for p in p_modes.values() if p > p_market + self.epsilon)
        short_count = sum(1 for p in p_modes.values() if p < p_market - self.epsilon)

        if long_count >= self.min_active_count:
            return AgreementVerdict(
                allowed=True, long_count=long_count, short_count=short_count, direction="long",
            )
        if short_count >= self.min_active_count:
            return AgreementVerdict(
                allowed=True, long_count=long_count, short_count=short_count, direction="short",
            )

        direction = "none" if (long_count == 0 and short_count == 0) else (
            "long" if long_count > short_count else "short"
        )
        return AgreementVerdict(
            allowed=False, long_count=long_count, short_count=short_count, direction=direction,
        )
