"""C2-A placeholder.  C2-D replaces this with the full 3-mode fusion
(SpotOrNews, SpotAndNews, WeightedScore) per spec §5.4.
"""

import math
from abc import ABC, abstractmethod

from agent.research.crypto.types import ShockState


class ShockDetector(ABC):
    """Abstract base for shock detectors.

    All implementations return a ShockState given the current return,
    GARCH vol, news events, current timestamp, and the last known shock
    timestamp.  The ABC is here so C2-D can swap in the 3-mode fusion
    implementation without changing model.py.
    """

    @abstractmethod
    def detect(
        self,
        current_return: float,
        garch_annualized_vol: float,
        periods_per_year: int,
        recent_news_events: list,
        now_ts: int,
        last_shock_ts: int | None,
    ) -> ShockState:
        """Detect whether a shock is active.

        Args:
            current_return: Most recent period return (close-to-close).
            garch_annualized_vol: GARCH-fitted annualized conditional
                volatility from GARCHResult.current_conditional_vol.
            periods_per_year: Annualization factor (8760 for hourly bars).
            recent_news_events: List of NewsEventDTO (unused by SpotOnly).
            now_ts: Current Unix timestamp in seconds.
            last_shock_ts: Unix timestamp of the last detected shock, or
                None if no previous shock is recorded.

        Returns:
            ShockState describing whether a shock is active and its severity.
        """
        ...


class SpotOnlyShockDetector(ShockDetector):
    """Fires when |current_return| > spot_threshold_k * period-vol.

    Ignores news entirely.  Used by C2-A; replaced in C2-D.

    period_vol = garch_annualized_vol / sqrt(periods_per_year)

    severity = min(1.0, sigmas / 10.0) where sigmas = |return| / period_vol.

    Also keeps a shock ACTIVE (with conservative severity=0.5) when
    last_shock_ts is within the 30-day rolling window, even if the current
    bar does not independently cross the threshold.

    Attributes:
        spot_threshold_k: Multiple of period-vol above which a shock fires
            (default 3.0 = 3-sigma).
    """

    def __init__(self, spot_threshold_k: float = 3.0):
        """Initialize SpotOnlyShockDetector.

        Args:
            spot_threshold_k: Threshold in units of period-vol (default 3.0).
        """
        self.spot_threshold_k = spot_threshold_k

    def detect(
        self,
        current_return: float,
        garch_annualized_vol: float,
        periods_per_year: int,
        recent_news_events: list,
        now_ts: int,
        last_shock_ts: int | None,
    ) -> ShockState:
        """Detect shock from spot return only.

        Args:
            current_return: Most recent period return.
            garch_annualized_vol: Annualized GARCH conditional vol.
            periods_per_year: Annualization factor (e.g. 8760 for hourly).
            recent_news_events: Ignored by this implementation.
            now_ts: Current Unix timestamp in seconds.
            last_shock_ts: Unix timestamp of last shock, or None.

        Returns:
            ShockState: active=True with time_since_shock_seconds=0 when a new
            shock fires; active=True with elapsed seconds when within the
            30-day window of a prior shock; active=False otherwise.
        """
        # Derive period-vol from annualized vol
        period_vol = garch_annualized_vol / math.sqrt(periods_per_year)
        sigmas = abs(current_return) / period_vol if period_vol > 0 else 0.0

        if sigmas >= self.spot_threshold_k:
            return ShockState(
                active=True,
                severity=min(1.0, sigmas / 10.0),
                spot_signal=True,
                news_signal=False,
                time_since_shock_seconds=0,
            )

        # Past shock still active if within 30-day rolling window
        _THIRTY_DAYS_SECONDS = 30 * 86400
        if last_shock_ts is not None and (now_ts - last_shock_ts) < _THIRTY_DAYS_SECONDS:
            return ShockState(
                active=True,
                severity=0.5,  # conservative default for ongoing shock
                spot_signal=False,
                news_signal=False,
                time_since_shock_seconds=now_ts - last_shock_ts,
            )

        return ShockState(
            active=False,
            severity=0.0,
            spot_signal=False,
            news_signal=False,
            time_since_shock_seconds=0,
        )
