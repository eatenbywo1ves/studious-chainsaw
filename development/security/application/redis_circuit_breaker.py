"""
Redis Circuit Breaker Implementation
Provides fault tolerance and graceful degradation for Redis failures
"""

import time
import logging
from typing import Optional, Callable, TypeVar
from enum import Enum
from dataclasses import dataclass
from threading import Lock
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation, requests pass through
    OPEN = "open"  # Circuit broken, fast-fail all requests
    HALF_OPEN = "half_open"  # Testing if service has recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior"""

    # Failure threshold
    failure_threshold: int = 5  # Number of failures before opening circuit
    failure_timeout: float = 60.0  # Seconds to track failures (sliding window)

    # Success threshold for recovery
    success_threshold: int = 2  # Consecutive successes needed to close circuit

    # Timeout for open state
    reset_timeout: float = 60.0  # Seconds before attempting recovery (HALF_OPEN)

    # Half-open state settings
    half_open_max_calls: int = 3  # Max calls to test in HALF_OPEN state

    # Monitoring
    enable_metrics: bool = True

    # Callbacks
    on_state_change: Optional[Callable[[CircuitState, CircuitState], None]] = None
    on_failure: Optional[Callable[[Exception], None]] = None
    on_success: Optional[Callable[[], None]] = None


@dataclass
class CircuitBreakerMetrics:
    """Metrics for circuit breaker monitoring"""

    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    consecutive_successes: int = 0
    consecutive_failures: int = 0
    last_failure_time: Optional[float] = None
    last_success_time: Optional[float] = None
    total_calls: int = 0
    rejected_calls: int = 0
    state_changes: int = 0
    time_in_open_state: float = 0.0
    last_state_change: Optional[float] = None

    def to_dict(self) -> dict:
        """Convert metrics to dictionary for reporting"""
        return {
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "consecutive_successes": self.consecutive_successes,
            "consecutive_failures": self.consecutive_failures,
            "total_calls": self.total_calls,
            "rejected_calls": self.rejected_calls,
            "state_changes": self.state_changes,
            "time_in_open_state": round(self.time_in_open_state, 2),
            "uptime_percent": round(
                ((self.total_calls - self.rejected_calls) / self.total_calls * 100)
                if self.total_calls > 0 else 100.0,
                2
            ),
        }


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is in OPEN state"""
    pass


class CircuitBreaker:
    """
    Circuit breaker implementation for Redis connections

    Prevents cascading failures by:
    1. Monitoring failure rates
    2. Opening circuit when threshold exceeded
    3. Periodically testing recovery
    4. Gradually closing circuit when service recovers

    Usage:
        breaker = CircuitBreaker(config)

        try:
            result = breaker.call(redis_client.get, "key")
        except CircuitBreakerOpenError:
            # Circuit is open, use fallback
            result = fallback_value
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """
        Initialize circuit breaker

        Args:
            config: Circuit breaker configuration
        """
        self.config = config or CircuitBreakerConfig()
        self._lock = Lock()

        # State management
        self._state = CircuitState.CLOSED
        self._opened_at: Optional[float] = None

        # Failure tracking (sliding window)
        self._failure_window = deque(maxlen=self.config.failure_threshold * 2)

        # Metrics
        self.metrics = CircuitBreakerMetrics()

        # Half-open state tracking
        self._half_open_calls = 0

        logger.info(
            f"Circuit breaker initialized: "
            f"failure_threshold={self.config.failure_threshold}, "
            f"reset_timeout={self.config.reset_timeout}s"
        )

    @property
    def state(self) -> CircuitState:
        """Get current circuit state"""
        return self._state

    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)"""
        return self._state == CircuitState.CLOSED

    @property
    def is_open(self) -> bool:
        """Check if circuit is open (failure mode)"""
        return self._state == CircuitState.OPEN

    @property
    def is_half_open(self) -> bool:
        """Check if circuit is half-open (testing recovery)"""
        return self._state == CircuitState.HALF_OPEN

    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """
        Execute function through circuit breaker

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpenError: If circuit is open
            Exception: Original exception from func if circuit allows call
        """
        with self._lock:
            self.metrics.total_calls += 1

            # Check if we should attempt call
            if not self._should_attempt_call():
                self.metrics.rejected_calls += 1
                raise CircuitBreakerOpenError(
                    f"Circuit breaker is {self._state.value}. "
                    f"Opened at: {datetime.fromtimestamp(self._opened_at) if self._opened_at else 'N/A'}"
                )

            # Track half-open calls
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_calls += 1

        # Execute function outside lock to avoid blocking
        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure(e)
            raise

    def _should_attempt_call(self) -> bool:
        """Determine if call should be attempted based on circuit state"""

        if self._state == CircuitState.CLOSED:
            return True

        if self._state == CircuitState.OPEN:
            # Check if reset timeout has elapsed
            if self._opened_at and (time.time() - self._opened_at) >= self.config.reset_timeout:
                self._transition_to_half_open()
                return True
            return False

        if self._state == CircuitState.HALF_OPEN:
            # Allow limited calls in half-open state
            return self._half_open_calls < self.config.half_open_max_calls

        return False

    def _on_success(self):
        """Handle successful call"""
        with self._lock:
            self.metrics.success_count += 1
            self.metrics.consecutive_successes += 1
            self.metrics.consecutive_failures = 0
            self.metrics.last_success_time = time.time()

            # Invoke success callback
            if self.config.on_success:
                try:
                    self.config.on_success()
                except Exception as e:
                    logger.error(f"Error in success callback: {e}")

            # State transitions based on successes
            if self._state == CircuitState.HALF_OPEN:
                if self.metrics.consecutive_successes >= self.config.success_threshold:
                    self._close_circuit()

            logger.debug(
                f"Circuit breaker success: "
                f"state={self._state.value}, "
                f"consecutive_successes={self.metrics.consecutive_successes}"
            )

    def _on_failure(self, exception: Exception):
        """Handle failed call"""
        with self._lock:
            current_time = time.time()

            self.metrics.failure_count += 1
            self.metrics.consecutive_failures += 1
            self.metrics.consecutive_successes = 0
            self.metrics.last_failure_time = current_time

            # Add failure to sliding window
            self._failure_window.append(current_time)

            # Invoke failure callback
            if self.config.on_failure:
                try:
                    self.config.on_failure(exception)
                except Exception as e:
                    logger.error(f"Error in failure callback: {e}")

            # State transitions based on failures
            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open immediately opens circuit
                self._open_circuit()
            elif self._state == CircuitState.CLOSED:
                # Check if failure threshold exceeded in time window
                recent_failures = self._count_recent_failures()
                if recent_failures >= self.config.failure_threshold:
                    self._open_circuit()

            logger.warning(
                f"Circuit breaker failure: "
                f"state={self._state.value}, "
                f"consecutive_failures={self.metrics.consecutive_failures}, "
                f"exception={type(exception).__name__}: {str(exception)}"
            )

    def _count_recent_failures(self) -> int:
        """Count failures within the failure timeout window"""
        current_time = time.time()
        cutoff_time = current_time - self.config.failure_timeout

        # Remove old failures
        while self._failure_window and self._failure_window[0] < cutoff_time:
            self._failure_window.popleft()

        return len(self._failure_window)

    def _open_circuit(self):
        """Transition to OPEN state"""
        if self._state != CircuitState.OPEN:
            old_state = self._state
            self._state = CircuitState.OPEN
            self._opened_at = time.time()
            self._half_open_calls = 0
            self.metrics.state_changes += 1
            self.metrics.last_state_change = self._opened_at

            logger.error(
                f"🔴 Circuit breaker opened: "
                f"{old_state.value} → {self._state.value} | "
                f"Failures: {self.metrics.consecutive_failures} | "
                f"Will attempt recovery in {self.config.reset_timeout}s"
            )

            self._invoke_state_change_callback(old_state, self._state)

    def _transition_to_half_open(self):
        """Transition to HALF_OPEN state"""
        if self._state == CircuitState.OPEN:
            old_state = self._state
            self._state = CircuitState.HALF_OPEN
            self._half_open_calls = 0

            # Track time in open state
            if self._opened_at:
                self.metrics.time_in_open_state += (time.time() - self._opened_at)

            self.metrics.state_changes += 1
            self.metrics.last_state_change = time.time()

            logger.warning(
                f"🟡 Circuit breaker half-open: "
                f"{old_state.value} → {self._state.value} | "
                f"Testing recovery with {self.config.half_open_max_calls} calls"
            )

            self._invoke_state_change_callback(old_state, self._state)

    def _close_circuit(self):
        """Transition to CLOSED state"""
        if self._state != CircuitState.CLOSED:
            old_state = self._state
            self._state = CircuitState.CLOSED
            self._opened_at = None
            self._half_open_calls = 0
            self.metrics.consecutive_failures = 0
            self.metrics.state_changes += 1
            self.metrics.last_state_change = time.time()

            logger.info(
                f"🟢 Circuit breaker closed: "
                f"{old_state.value} → {self._state.value} | "
                f"Recovery successful | "
                f"Consecutive successes: {self.metrics.consecutive_successes}"
            )

            self._invoke_state_change_callback(old_state, self._state)

    def _invoke_state_change_callback(self, old_state: CircuitState, new_state: CircuitState):
        """Invoke state change callback if configured"""
        if self.config.on_state_change:
            try:
                self.config.on_state_change(old_state, new_state)
            except Exception as e:
                logger.error(f"Error in state change callback: {e}")

    def reset(self):
        """Manually reset circuit breaker to CLOSED state"""
        with self._lock:
            old_state = self._state
            self._state = CircuitState.CLOSED
            self._opened_at = None
            self._half_open_calls = 0
            self._failure_window.clear()
            self.metrics.consecutive_failures = 0
            self.metrics.consecutive_successes = 0

            if old_state != CircuitState.CLOSED:
                self.metrics.state_changes += 1
                self.metrics.last_state_change = time.time()
                logger.info(f"Circuit breaker manually reset: {old_state.value} → CLOSED")
                self._invoke_state_change_callback(old_state, self._state)

    def force_open(self):
        """Manually force circuit to OPEN state (for testing/maintenance)"""
        with self._lock:
            if self._state != CircuitState.OPEN:
                old_state = self._state
                self._state = CircuitState.OPEN
                self._opened_at = time.time()
                self.metrics.state_changes += 1
                self.metrics.last_state_change = self._opened_at
                logger.warning(f"Circuit breaker manually opened: {old_state.value} → OPEN")
                self._invoke_state_change_callback(old_state, self._state)

    def get_metrics(self) -> dict:
        """Get current circuit breaker metrics"""
        with self._lock:
            metrics_dict = self.metrics.to_dict()
            metrics_dict["config"] = {
                "failure_threshold": self.config.failure_threshold,
                "failure_timeout": self.config.failure_timeout,
                "reset_timeout": self.config.reset_timeout,
                "success_threshold": self.config.success_threshold,
            }

            if self._opened_at and self._state == CircuitState.OPEN:
                time_until_halfopen = max(
                    0,
                    self.config.reset_timeout - (time.time() - self._opened_at)
                )
                metrics_dict["time_until_recovery_test"] = round(time_until_halfopen, 2)

            return metrics_dict
