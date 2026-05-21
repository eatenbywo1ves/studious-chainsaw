"""PerformanceTracker: per-mode trailing-Brier averages, floor evolution, and
disable-streak tracking.  Backed by ModePerformance + ModeFloorState ORM rows.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from agent.research.crypto.types import ModeState
from agent.store.schema import ModePerformance, ModeFloorState


MODE_NAMES = ["binary", "exp", "magnitude", "confidence"]


class PerformanceTracker:
    def __init__(
        self,
        trailing_window: int = 15,
        brier_floor_init: float = 0.10,
        floor_decay: float = 0.97,
        disable_brier_threshold: float = 0.25,
        disable_streak_required: int = 30,
    ):
        self.trailing_window = trailing_window
        self.brier_floor_init = brier_floor_init
        self.floor_decay = floor_decay
        self.disable_brier_threshold = disable_brier_threshold
        self.disable_streak_required = disable_streak_required

    def get_state(self, session: Session) -> dict[str, ModeState]:
        state = {}
        for mode_name in MODE_NAMES:
            recent_briers = session.execute(
                select(ModePerformance.brier_score)
                .where(ModePerformance.mode_name == mode_name)
                .order_by(ModePerformance.closed_at.desc())
                .limit(self.trailing_window)
            ).scalars().all()

            n = len(recent_briers)
            trailing_brier = sum(recent_briers) / n if n > 0 else 0.0

            floor_row = session.get(ModeFloorState, mode_name)
            if floor_row is None:
                brier_floor = self.brier_floor_init
                is_disabled = False
            else:
                brier_floor = floor_row.brier_floor
                is_disabled = floor_row.is_disabled

            state[mode_name] = ModeState(
                mode_name=mode_name,
                trailing_brier=trailing_brier,
                brier_floor=brier_floor,
                is_disabled=is_disabled,
                n_closed_trades=n,
            )
        return state

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
        brier = (p_mode - outcome) ** 2
        row = ModePerformance(
            mode_name=mode_name,
            market_id=market_id,
            p_mode=p_mode,
            p_market_at_prediction=p_market_at_prediction,
            outcome=outcome,
            brier_score=brier,
            closed_at=closed_at,
        )
        session.add(row)

        floor_row = session.get(ModeFloorState, mode_name)
        if floor_row is None:
            floor_row = ModeFloorState(
                mode_name=mode_name,
                brier_floor=self.brier_floor_init,
                disable_streak=0,
                is_disabled=False,
                updated_at=closed_at,
            )
            session.add(floor_row)
            session.flush()  # ensure row is queryable in same session

        if brier > self.disable_brier_threshold:
            floor_row.disable_streak += 1
            floor_row.brier_floor *= self.floor_decay
            if floor_row.disable_streak >= self.disable_streak_required:
                floor_row.is_disabled = True
        else:
            floor_row.disable_streak = 0
        floor_row.updated_at = closed_at
