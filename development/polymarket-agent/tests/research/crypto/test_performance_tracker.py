from agent.store.schema import ModeFloorState
from agent.research.crypto.performance_tracker import PerformanceTracker


def test_no_history_returns_zero_trades_floor_initial(session_factory):
    """Empty DB: each mode has 0 trades, brier_floor=0.10, is_disabled=False."""
    tracker = PerformanceTracker(trailing_window=15)

    with session_factory() as session:
        state = tracker.get_state(session)
        for mode_name in ["binary", "exp", "magnitude", "confidence"]:
            assert state[mode_name].n_closed_trades == 0
            assert state[mode_name].brier_floor == 0.10
            assert state[mode_name].is_disabled is False


def test_record_outcome_appends_and_updates_floor(session_factory):
    """Recording a closed trade appends ModePerformance and updates ModeFloorState."""
    tracker = PerformanceTracker(trailing_window=15)

    with session_factory() as session:
        tracker.record_outcome(
            session,
            mode_name="binary",
            market_id="0xABC001",
            p_mode=0.31,
            p_market_at_prediction=0.10,
            outcome=1,
            closed_at=1747800000,
        )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        assert state["binary"].n_closed_trades == 1
        # Brier for P=0.31, outcome=1 is (0.31-1)^2 = 0.4761 — far above 0.25 threshold
        # so disable_streak increments to 1, floor stays at 0.10 (not yet streak-30)
        assert state["binary"].is_disabled is False


def test_disable_after_30_consecutive_bad_trades(session_factory):
    """Use p_mode=0.55 so brier=(0.55)^2=0.3025>0.25, triggering disable streak."""
    tracker = PerformanceTracker(trailing_window=15)

    with session_factory() as session:
        for i in range(30):
            tracker.record_outcome(
                session,
                mode_name="confidence",
                market_id=f"0xABC{i:03d}",
                p_mode=0.55,
                p_market_at_prediction=0.10,
                outcome=0,
                closed_at=1747800000 + i,
            )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        assert state["confidence"].is_disabled is True


def test_brier_floor_decays_on_bad_trade(session_factory):
    """Each closed trade with brier > 0.25 multiplies floor by 0.97."""
    tracker = PerformanceTracker(trailing_window=15)

    with session_factory() as session:
        for i in range(3):
            tracker.record_outcome(
                session, mode_name="binary",
                market_id=f"0xABC{i:03d}",
                p_mode=0.60, p_market_at_prediction=0.10, outcome=0,
                closed_at=1747800000 + i,
            )
        session.commit()

    with session_factory() as session:
        state = tracker.get_state(session)
        # 3 consecutive bad: floor = 0.10 * 0.97 * 0.97 * 0.97 ~ 0.0912
        expected_floor = 0.10 * (0.97 ** 3)
        assert abs(state["binary"].brier_floor - expected_floor) < 1e-6
