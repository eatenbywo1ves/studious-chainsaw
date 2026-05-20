"""
Tests for Redis Circuit Breaker
Validates fault tolerance and graceful degradation behavior
"""

import pytest
import time
from unittest.mock import Mock
from redis.exceptions import ConnectionError

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from application.redis_circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
)


class TestCircuitBreakerBasics:
    """Test basic circuit breaker functionality"""

    def test_circuit_breaker_initialization(self):
        """Test circuit breaker initializes in CLOSED state"""
        breaker = CircuitBreaker()

        assert breaker.state == CircuitState.CLOSED
        assert breaker.is_closed
        assert not breaker.is_open
        assert not breaker.is_half_open

    def test_successful_call_returns_result(self):
        """Test successful function call returns expected result"""
        breaker = CircuitBreaker()

        def successful_func():
            return "success"

        result = breaker.call(successful_func)
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED

    def test_failed_call_raises_exception(self):
        """Test failed call raises original exception"""
        breaker = CircuitBreaker()

        def failing_func():
            raise ValueError("test error")

        with pytest.raises(ValueError, match="test error"):
            breaker.call(failing_func)

    def test_metrics_tracking(self):
        """Test metrics are tracked correctly"""
        breaker = CircuitBreaker()

        # Successful call
        breaker.call(lambda: "success")

        metrics = breaker.get_metrics()
        assert metrics["total_calls"] == 1
        assert metrics["success_count"] == 1
        assert metrics["failure_count"] == 0
        assert metrics["rejected_calls"] == 0


class TestCircuitBreakerStateTransitions:
    """Test circuit breaker state transitions"""

    def test_opens_after_threshold_failures(self):
        """Test circuit opens after failure threshold exceeded"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            failure_timeout=10.0,
            reset_timeout=5.0,
        )
        breaker = CircuitBreaker(config)

        def failing_func():
            raise ConnectionError("Connection failed")

        # Should stay closed for first 2 failures
        for i in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(failing_func)
            assert breaker.state == CircuitState.CLOSED

        # 3rd failure should open circuit
        with pytest.raises(ConnectionError):
            breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN
        assert breaker.is_open

    def test_rejects_calls_when_open(self):
        """Test circuit rejects calls when in OPEN state"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=10.0,
        )
        breaker = CircuitBreaker(config)

        # Force circuit open with failures
        def failing_func():
            raise ConnectionError("test")

        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(failing_func)

        # Circuit should be open
        assert breaker.is_open

        # Next call should be rejected without executing function
        with pytest.raises(CircuitBreakerOpenError):
            breaker.call(lambda: "should not execute")

        metrics = breaker.get_metrics()
        assert metrics["rejected_calls"] > 0

    def test_transitions_to_half_open_after_timeout(self):
        """Test circuit transitions to HALF_OPEN after reset timeout"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=0.5,  # 500ms
        )
        breaker = CircuitBreaker(config)

        # Open circuit
        def failing_func():
            raise ConnectionError("test")

        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(failing_func)

        assert breaker.is_open

        # Wait for reset timeout
        time.sleep(0.6)

        # Next call should transition to HALF_OPEN and execute
        def successful_func():
            return "recovery"

        result = breaker.call(successful_func)
        assert result == "recovery"
        # After one successful call in half-open, might still be half-open
        assert breaker.state in [CircuitState.HALF_OPEN, CircuitState.CLOSED]

    def test_closes_after_success_threshold_in_half_open(self):
        """Test circuit closes after consecutive successes in HALF_OPEN state"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=0.1,
            success_threshold=2,
        )
        breaker = CircuitBreaker(config)

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        assert breaker.is_open

        # Wait for reset
        time.sleep(0.15)

        # Make successful calls to close circuit
        for i in range(2):
            result = breaker.call(lambda: "success")
            assert result == "success"

        # Circuit should be closed after success_threshold successes
        assert breaker.state == CircuitState.CLOSED

    def test_reopens_on_failure_in_half_open(self):
        """Test circuit reopens immediately on failure in HALF_OPEN state"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=0.1,
        )
        breaker = CircuitBreaker(config)

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        assert breaker.is_open

        # Wait for reset
        time.sleep(0.15)

        # First call transitions to HALF_OPEN
        breaker.call(lambda: "success")

        # Failure in HALF_OPEN should immediately reopen
        with pytest.raises(ConnectionError):
            breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("fail again")))

        assert breaker.is_open


class TestCircuitBreakerCallbacks:
    """Test circuit breaker callbacks"""

    def test_state_change_callback_invoked(self):
        """Test state change callback is invoked on transitions"""
        state_changes = []

        def on_state_change(old_state, new_state):
            state_changes.append((old_state, new_state))

        config = CircuitBreakerConfig(
            failure_threshold=2,
            on_state_change=on_state_change,
        )
        breaker = CircuitBreaker(config)

        # Trigger state change
        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        assert len(state_changes) == 1
        assert state_changes[0] == (CircuitState.CLOSED, CircuitState.OPEN)

    def test_failure_callback_invoked(self):
        """Test failure callback is invoked on each failure"""
        failures = []

        def on_failure(exception):
            failures.append(exception)

        config = CircuitBreakerConfig(
            failure_threshold=3,
            on_failure=on_failure,
        )
        breaker = CircuitBreaker(config)

        # Trigger failures
        for _ in range(2):
            with pytest.raises(ValueError):
                breaker.call(lambda: (_ for _ in ()).throw(ValueError("test")))

        assert len(failures) == 2
        assert all(isinstance(e, ValueError) for e in failures)

    def test_success_callback_invoked(self):
        """Test success callback is invoked on each success"""
        successes = []

        def on_success():
            successes.append(True)

        config = CircuitBreakerConfig(on_success=on_success)
        breaker = CircuitBreaker(config)

        # Trigger successes
        for _ in range(3):
            breaker.call(lambda: "success")

        assert len(successes) == 3


class TestCircuitBreakerManualControl:
    """Test manual circuit breaker control"""

    def test_manual_reset(self):
        """Test manual reset closes circuit"""
        config = CircuitBreakerConfig(failure_threshold=2)
        breaker = CircuitBreaker(config)

        # Open circuit
        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        assert breaker.is_open

        # Manual reset
        breaker.reset()

        assert breaker.is_closed
        assert breaker.metrics.consecutive_failures == 0

    def test_force_open(self):
        """Test forcing circuit open"""
        breaker = CircuitBreaker()
        assert breaker.is_closed

        # Force open
        breaker.force_open()

        assert breaker.is_open

        # Calls should be rejected
        with pytest.raises(CircuitBreakerOpenError):
            breaker.call(lambda: "should not execute")


class TestCircuitBreakerMetrics:
    """Test circuit breaker metrics"""

    def test_metrics_include_state(self):
        """Test metrics include current state"""
        breaker = CircuitBreaker()
        metrics = breaker.get_metrics()

        assert "state" in metrics
        assert metrics["state"] == "closed"

    def test_metrics_track_calls(self):
        """Test metrics track total and rejected calls"""
        config = CircuitBreakerConfig(failure_threshold=1)
        breaker = CircuitBreaker(config)

        # Successful call
        breaker.call(lambda: "success")

        # Open circuit
        with pytest.raises(ConnectionError):
            breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        # Rejected call
        with pytest.raises(CircuitBreakerOpenError):
            breaker.call(lambda: "rejected")

        metrics = breaker.get_metrics()
        assert metrics["total_calls"] == 3
        assert metrics["rejected_calls"] == 1
        assert metrics["success_count"] == 1
        assert metrics["failure_count"] == 1

    def test_metrics_track_consecutive_counts(self):
        """Test metrics track consecutive successes and failures"""
        breaker = CircuitBreaker()

        # Consecutive successes
        for _ in range(3):
            breaker.call(lambda: "success")

        metrics = breaker.get_metrics()
        assert metrics["consecutive_successes"] == 3
        assert metrics["consecutive_failures"] == 0

        # Single failure resets consecutive successes
        with pytest.raises(ValueError):
            breaker.call(lambda: (_ for _ in ()).throw(ValueError("fail")))

        metrics = breaker.get_metrics()
        assert metrics["consecutive_successes"] == 0
        assert metrics["consecutive_failures"] == 1


class TestCircuitBreakerSlidingWindow:
    """Test sliding window failure tracking"""

    def test_failures_outside_window_ignored(self):
        """Test old failures don't count toward threshold"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            failure_timeout=0.5,  # 500ms window
        )
        breaker = CircuitBreaker(config)

        # First failure
        with pytest.raises(ConnectionError):
            breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        # Wait for window to expire
        time.sleep(0.6)

        # Two more failures within new window
        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))

        # Should still be closed (first failure expired)
        assert breaker.is_closed

    def test_failures_within_window_trigger_open(self):
        """Test failures within window trigger circuit open"""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            failure_timeout=2.0,
        )
        breaker = CircuitBreaker(config)

        # Three failures within window
        for _ in range(3):
            with pytest.raises(ConnectionError):
                breaker.call(lambda: (_ for _ in ()).throw(ConnectionError("test")))
            time.sleep(0.1)  # Small delay but within window

        # Circuit should be open
        assert breaker.is_open


@pytest.fixture
def mock_redis_client():
    """Create mock Redis client for testing"""
    client = Mock()
    client.get = Mock(return_value="test_value")
    client.set = Mock(return_value=True)
    client.ping = Mock(return_value=True)
    return client


class TestCircuitBreakerIntegration:
    """Integration tests with mock Redis"""

    def test_protects_redis_operations(self, mock_redis_client):
        """Test circuit breaker protects Redis operations"""
        breaker = CircuitBreaker(CircuitBreakerConfig(failure_threshold=2))

        # Successful operations
        result = breaker.call(mock_redis_client.get, "key")
        assert result == "test_value"
        assert mock_redis_client.get.call_count == 1

        # Failing operations
        mock_redis_client.get.side_effect = ConnectionError("Redis down")

        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(mock_redis_client.get, "key")

        # Circuit should be open
        assert breaker.is_open

        # Next call should be rejected without calling Redis
        call_count_before = mock_redis_client.get.call_count
        with pytest.raises(CircuitBreakerOpenError):
            breaker.call(mock_redis_client.get, "key")

        assert mock_redis_client.get.call_count == call_count_before  # No additional call

    def test_recovers_after_redis_healthy(self, mock_redis_client):
        """Test circuit breaker recovers after Redis becomes healthy"""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            reset_timeout=0.2,
            success_threshold=2,
        )
        breaker = CircuitBreaker(config)

        # Open circuit with failures
        mock_redis_client.ping.side_effect = ConnectionError("Redis down")

        for _ in range(2):
            with pytest.raises(ConnectionError):
                breaker.call(mock_redis_client.ping)

        assert breaker.is_open

        # Wait for reset
        time.sleep(0.25)

        # Redis becomes healthy
        mock_redis_client.ping.side_effect = None
        mock_redis_client.ping.return_value = True

        # Successful calls should close circuit
        for _ in range(2):
            result = breaker.call(mock_redis_client.ping)
            assert result is True

        assert breaker.is_closed


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
