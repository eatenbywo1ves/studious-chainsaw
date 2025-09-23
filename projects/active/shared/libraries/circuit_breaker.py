"""
Circuit Breaker Pattern Implementation
Provides fault tolerance and stability for distributed services
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class CircuitState(Enum):
    """Circuit breaker states"""

    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Circuit is open, failing fast
    HALF_OPEN = "half_open"  # Testing if service is back


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""

    failure_threshold: int = 5  # Number of failures to open circuit
    timeout: int = 60  # Time in seconds before trying half-open
    success_threshold: int = 3  # Successful calls needed in half-open to close
    window_size: int = 100  # Size of rolling window for failure rate
    minimum_calls: int = 10  # Minimum calls before calculating failure rate
    failure_rate_threshold: float = 0.5  # 50% failure rate threshold
    slow_call_threshold: float = 5.0  # Slow call threshold in seconds
    slow_call_rate_threshold: float = 0.5  # 50% slow calls threshold


@dataclass
class CallResult:
    """Result of a service call"""

    success: bool
    duration: float
    timestamp: datetime
    error: Optional[str] = None
    response: Optional[Any] = None


class CircuitBreakerException(Exception):
    """Exception raised when circuit breaker is open"""


class CircuitBreaker:
    """Circuit breaker implementation"""

    def __init__(self, name: str, config: Optional[CircuitBreakerConfig] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.call_history: List[CallResult] = []
        self.logger = self._setup_logging()
        self.state_change_callbacks: List[Callable] = []

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger(f"CircuitBreaker-{self.name}")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "CircuitBreaker", '
                '"service": "' + self.name + '", "level": "%(levelname)s", '
                '"message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def add_state_change_callback(self, callback: Callable):
        """Add callback for state changes"""
        self.state_change_callbacks.append(callback)

    def _change_state(self, new_state: CircuitState, reason: str = ""):
        """Change circuit breaker state"""
        old_state = self.state
        self.state = new_state

        self.logger.info(
            f"State change: {old_state.value} -> {new_state.value}. {reason}"
        )

        # Trigger callbacks
        for callback in self.state_change_callbacks:
            try:
                callback(self.name, old_state, new_state, reason)
            except Exception as e:
                self.logger.error(f"State change callback error: {e}")

    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset from open to half-open"""
        if self.state != CircuitState.OPEN:
            return False

        if not self.last_failure_time:
            return False

        time_since_failure = (datetime.now() - self.last_failure_time).total_seconds()
        return time_since_failure >= self.config.timeout

    def _record_success(self, duration: float):
        """Record successful call"""
        result = CallResult(success=True, duration=duration, timestamp=datetime.now())

        self._add_to_history(result)

        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.failure_count = 0
                self.success_count = 0
                self._change_state(
                    CircuitState.CLOSED, "Success threshold reached in half-open state"
                )
        elif self.state == CircuitState.CLOSED:
            self.failure_count = 0  # Reset failure count on success

    def _record_failure(self, error: str, duration: float = 0.0):
        """Record failed call"""
        result = CallResult(
            success=False, duration=duration, timestamp=datetime.now(), error=error
        )

        self._add_to_history(result)
        self.last_failure_time = datetime.now()

        if self.state == CircuitState.HALF_OPEN:
            # Go back to open on any failure in half-open
            self._change_state(
                CircuitState.OPEN, f"Failure in half-open state: {error}"
            )
            self.success_count = 0
        elif self.state == CircuitState.CLOSED:
            self.failure_count += 1

            # Check if we should open the circuit
            if self._should_open_circuit():
                self._change_state(
                    CircuitState.OPEN,
                    f"Failure threshold exceeded: {self.failure_count}/{self.config.failure_threshold}",
                )

    def _add_to_history(self, result: CallResult):
        """Add result to call history with windowing"""
        self.call_history.append(result)

        # Maintain rolling window
        if len(self.call_history) > self.config.window_size:
            self.call_history.pop(0)

    def _should_open_circuit(self) -> bool:
        """Determine if circuit should be opened"""
        # Simple threshold check
        if self.failure_count >= self.config.failure_threshold:
            return True

        # Failure rate check (only if we have enough data)
        if len(self.call_history) >= self.config.minimum_calls:
            recent_calls = self.call_history[-self.config.minimum_calls :]
            failures = sum(1 for call in recent_calls if not call.success)
            failure_rate = failures / len(recent_calls)

            if failure_rate >= self.config.failure_rate_threshold:
                return True

        # Slow call rate check
        if len(self.call_history) >= self.config.minimum_calls:
            recent_calls = self.call_history[-self.config.minimum_calls :]
            slow_calls = sum(
                1
                for call in recent_calls
                if call.duration >= self.config.slow_call_threshold
            )
            slow_call_rate = slow_calls / len(recent_calls)

            if slow_call_rate >= self.config.slow_call_rate_threshold:
                return True

        return False

    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        # Check if we should attempt reset
        if self._should_attempt_reset():
            self._change_state(CircuitState.HALF_OPEN, "Attempting reset after timeout")

        # Fast fail if circuit is open
        if self.state == CircuitState.OPEN:
            raise CircuitBreakerException(f"Circuit breaker '{self.name}' is OPEN")

        start_time = time.time()

        try:
            # Execute the function
            if asyncio.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)

            duration = time.time() - start_time
            self._record_success(duration)

            return result

        except Exception as e:
            duration = time.time() - start_time
            error_msg = str(e)
            self._record_failure(error_msg, duration)
            raise

    def get_state(self) -> CircuitState:
        """Get current circuit state"""
        return self.state

    def get_statistics(self) -> Dict[str, Any]:
        """Get circuit breaker statistics"""
        recent_window = (
            self.call_history[-self.config.window_size :] if self.call_history else []
        )

        total_calls = len(recent_window)
        successful_calls = sum(1 for call in recent_window if call.success)
        failed_calls = total_calls - successful_calls
        slow_calls = sum(
            1
            for call in recent_window
            if call.duration >= self.config.slow_call_threshold
        )

        avg_duration = (
            sum(call.duration for call in recent_window) / total_calls
            if total_calls > 0
            else 0
        )
        failure_rate = failed_calls / total_calls if total_calls > 0 else 0
        slow_call_rate = slow_calls / total_calls if total_calls > 0 else 0

        return {
            "name": self.name,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "total_calls": total_calls,
            "successful_calls": successful_calls,
            "failed_calls": failed_calls,
            "slow_calls": slow_calls,
            "failure_rate": failure_rate,
            "slow_call_rate": slow_call_rate,
            "average_duration": avg_duration,
            "last_failure_time": (
                self.last_failure_time.isoformat() if self.last_failure_time else None
            ),
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "timeout": self.config.timeout,
                "success_threshold": self.config.success_threshold,
            },
        }

    def reset(self):
        """Manually reset circuit breaker to closed state"""
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self._change_state(CircuitState.CLOSED, "Manual reset")


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers"""

    def __init__(self):
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        self.logger = self._setup_logging()
        self.global_callbacks: List[Callable] = []

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("CircuitBreakerRegistry")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "CircuitBreakerRegistry", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def register(
        self, name: str, config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Register a new circuit breaker"""
        if name in self.circuit_breakers:
            return self.circuit_breakers[name]

        circuit_breaker = CircuitBreaker(name, config)

        # Add global callbacks
        for callback in self.global_callbacks:
            circuit_breaker.add_state_change_callback(callback)

        self.circuit_breakers[name] = circuit_breaker
        self.logger.info(f"Registered circuit breaker: {name}")

        return circuit_breaker

    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        return self.circuit_breakers.get(name)

    def get_or_create(
        self, name: str, config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get existing circuit breaker or create new one"""
        if name not in self.circuit_breakers:
            return self.register(name, config)
        return self.circuit_breakers[name]

    def add_global_callback(self, callback: Callable):
        """Add callback that will be called for all circuit breaker state changes"""
        self.global_callbacks.append(callback)

        # Add to existing circuit breakers
        for cb in self.circuit_breakers.values():
            cb.add_state_change_callback(callback)

    def get_all_statistics(self) -> Dict[str, Any]:
        """Get statistics for all circuit breakers"""
        stats = {}
        total_open = 0
        total_half_open = 0
        total_closed = 0

        for name, cb in self.circuit_breakers.items():
            cb_stats = cb.get_statistics()
            stats[name] = cb_stats

            if cb_stats["state"] == "open":
                total_open += 1
            elif cb_stats["state"] == "half_open":
                total_half_open += 1
            else:
                total_closed += 1

        return {
            "circuit_breakers": stats,
            "summary": {
                "total": len(self.circuit_breakers),
                "open": total_open,
                "half_open": total_half_open,
                "closed": total_closed,
            },
        }

    def reset_all(self):
        """Reset all circuit breakers"""
        for cb in self.circuit_breakers.values():
            cb.reset()
        self.logger.info("Reset all circuit breakers")

    def health_check(self) -> Dict[str, Any]:
        """Overall health check"""
        stats = self.get_all_statistics()
        unhealthy_services = []

        for name, cb_stats in stats["circuit_breakers"].items():
            if cb_stats["state"] == "open":
                unhealthy_services.append(name)

        is_healthy = len(unhealthy_services) == 0

        return {
            "healthy": is_healthy,
            "unhealthy_services": unhealthy_services,
            "summary": stats["summary"],
        }


# Decorator for automatic circuit breaker protection
def circuit_breaker(name: str, config: Optional[CircuitBreakerConfig] = None):
    """Decorator to add circuit breaker protection to functions"""

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            registry = get_circuit_breaker_registry()
            cb = registry.get_or_create(name, config)

            if asyncio.iscoroutinefunction(func):
                return cb.call(func, *args, **kwargs)
            else:
                # For sync functions, we need to handle differently
                async def async_wrapper():
                    return await cb.call(func, *args, **kwargs)

                # If we're in an async context, return the coroutine
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        return async_wrapper()
                except RuntimeError:
                    pass

                # Otherwise run sync
                return asyncio.run(async_wrapper())

        return wrapper

    return decorator


# Singleton registry
_registry_instance: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    """Get singleton circuit breaker registry"""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = CircuitBreakerRegistry()
    return _registry_instance


# Integration with existing services
class ServiceCircuitBreakers:
    """Circuit breakers for common service patterns"""

    def __init__(self, registry: Optional[CircuitBreakerRegistry] = None):
        self.registry = registry or get_circuit_breaker_registry()
        self._setup_service_breakers()

    def _setup_service_breakers(self):
        """Setup circuit breakers for common services"""
        # API Gateway circuit breakers
        self.api_gateway = self.registry.register(
            "api_gateway",
            CircuitBreakerConfig(failure_threshold=10, timeout=30, success_threshold=5),
        )

        # Database circuit breakers
        self.database = self.registry.register(
            "database",
            CircuitBreakerConfig(
                failure_threshold=5, timeout=60, slow_call_threshold=2.0
            ),
        )

        # External API circuit breakers
        self.external_api = self.registry.register(
            "external_api",
            CircuitBreakerConfig(
                failure_threshold=3, timeout=120, slow_call_threshold=10.0
            ),
        )

        # MCP Server circuit breakers
        self.mcp_server = self.registry.register(
            "mcp_server",
            CircuitBreakerConfig(failure_threshold=5, timeout=45, success_threshold=3),
        )

        # Message Queue circuit breakers
        self.message_queue = self.registry.register(
            "message_queue",
            CircuitBreakerConfig(
                failure_threshold=8, timeout=30, slow_call_threshold=5.0
            ),
        )

    async def protected_api_call(self, func: Callable, *args, **kwargs):
        """Make API call with circuit breaker protection"""
        return await self.api_gateway.call(func, *args, **kwargs)

    async def protected_db_call(self, func: Callable, *args, **kwargs):
        """Make database call with circuit breaker protection"""
        return await self.database.call(func, *args, **kwargs)

    async def protected_external_call(self, func: Callable, *args, **kwargs):
        """Make external service call with circuit breaker protection"""
        return await self.external_api.call(func, *args, **kwargs)

    async def protected_mcp_call(self, func: Callable, *args, **kwargs):
        """Make MCP server call with circuit breaker protection"""
        return await self.mcp_server.call(func, *args, **kwargs)

    async def protected_queue_operation(self, func: Callable, *args, **kwargs):
        """Make message queue operation with circuit breaker protection"""
        return await self.message_queue.call(func, *args, **kwargs)


# Convenience functions
async def with_circuit_breaker(name: str, func: Callable, *args, **kwargs):
    """Execute function with circuit breaker protection"""
    registry = get_circuit_breaker_registry()
    cb = registry.get_or_create(name)
    return await cb.call(func, *args, **kwargs)


def get_service_circuit_breakers() -> ServiceCircuitBreakers:
    """Get service circuit breakers instance"""
    return ServiceCircuitBreakers()
