"""
Resilient Redis Connection Pool with Circuit Breaker
Production-grade Redis client with fault tolerance and graceful degradation
"""

import os
import logging
from typing import Optional, Dict, Any, Callable
from contextlib import contextmanager
from functools import wraps
import redis
from redis.exceptions import RedisError, ConnectionError, TimeoutError

from .redis_pool_protocol import DeploymentEnvironment, PoolConfiguration
from .redis_pool_implementation import OptimizedRedisPool, RedisConnectionConfig
from .redis_circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerOpenError, CircuitState

logger = logging.getLogger(__name__)


class ResilientRedisPool:
    """
    Production-grade Redis pool with:
    - Circuit breaker for fault tolerance
    - Graceful degradation with fallbacks
    - Automatic recovery
    - Comprehensive monitoring
    - Configurable retry policies

    Usage:
        pool = ResilientRedisPool()

        # With automatic fallback
        value = pool.get_with_fallback("key", default="fallback_value")

        # With explicit circuit breaker handling
        try:
            value = pool.get("key")
        except CircuitBreakerOpenError:
            # Circuit is open, use alternative strategy
            value = fetch_from_cache()
    """

    def __init__(
        self,
        environment: Optional[DeploymentEnvironment] = None,
        connection_config: Optional[RedisConnectionConfig] = None,
        pool_config: Optional[PoolConfiguration] = None,
        circuit_breaker_config: Optional[CircuitBreakerConfig] = None,
        enable_circuit_breaker: bool = True,
        enable_monitoring: bool = True,
        fallback_mode: str = "warn",  # "silent", "warn", "error"
    ):
        """
        Initialize resilient Redis pool

        Args:
            environment: Deployment environment
            connection_config: Redis connection configuration
            pool_config: Pool configuration
            circuit_breaker_config: Circuit breaker configuration
            enable_circuit_breaker: Enable circuit breaker protection
            enable_monitoring: Enable metrics collection
            fallback_mode: How to handle fallbacks ("silent", "warn", "error")
        """
        # Auto-detect environment
        if environment is None:
            env_str = os.getenv("DEPLOYMENT_ENV", "production").lower()
            environment = DeploymentEnvironment(env_str)

        self.environment = environment
        self.enable_circuit_breaker = enable_circuit_breaker
        self.enable_monitoring = enable_monitoring
        self.fallback_mode = fallback_mode

        # Create connection and pool config
        self.connection_config = connection_config or RedisConnectionConfig()
        self.pool_config = pool_config or PoolConfiguration.for_environment(environment)

        # Initialize base Redis pool
        try:
            self._base_pool = OptimizedRedisPool(
                connection_config=self.connection_config,
                pool_config=self.pool_config,
                environment=environment,
                enable_monitoring=enable_monitoring,
            )
            self._available = self._base_pool.is_available
        except Exception as e:
            logger.error(f"Failed to initialize base Redis pool: {e}")
            self._base_pool = None
            self._available = False

        # Initialize circuit breaker
        self._circuit_breaker: Optional[CircuitBreaker] = None
        if enable_circuit_breaker:
            breaker_config = circuit_breaker_config or self._create_default_circuit_breaker_config()
            self._circuit_breaker = CircuitBreaker(breaker_config)
            logger.info("Circuit breaker enabled for Redis operations")

        # Metrics
        self._fallback_count = 0
        self._circuit_open_count = 0

    def _create_default_circuit_breaker_config(self) -> CircuitBreakerConfig:
        """Create default circuit breaker configuration based on environment"""

        # Environment-specific settings
        configs = {
            DeploymentEnvironment.DEVELOPMENT: {
                "failure_threshold": 3,
                "failure_timeout": 30.0,
                "reset_timeout": 30.0,
                "success_threshold": 2,
            },
            DeploymentEnvironment.STAGING: {
                "failure_threshold": 5,
                "failure_timeout": 60.0,
                "reset_timeout": 60.0,
                "success_threshold": 2,
            },
            DeploymentEnvironment.PRODUCTION: {
                "failure_threshold": 5,
                "failure_timeout": 60.0,
                "reset_timeout": 120.0,
                "success_threshold": 3,
            },
        }

        env_config = configs.get(self.environment, configs[DeploymentEnvironment.PRODUCTION])

        def on_state_change(old_state: CircuitState, new_state: CircuitState):
            """Callback for circuit state changes"""
            logger.warning(
                f"Redis circuit breaker state change: {old_state.value} → {new_state.value} | "
                f"Environment: {self.environment.value}"
            )

            if new_state == CircuitState.OPEN:
                self._circuit_open_count += 1

        def on_failure(exception: Exception):
            """Callback for operation failures"""
            logger.debug(f"Redis operation failed: {type(exception).__name__}: {str(exception)}")

        return CircuitBreakerConfig(
            **env_config,
            enable_metrics=self.enable_monitoring,
            on_state_change=on_state_change,
            on_failure=on_failure,
        )

    @property
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self._available and (self._base_pool is not None) and self._base_pool.is_available

    @property
    def client(self) -> redis.Redis:
        """Get Redis client (without circuit breaker protection)"""
        if not self.is_available:
            raise ConnectionError("Redis is not available")
        return self._base_pool.client

    def _execute_with_circuit_breaker(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute Redis operation with circuit breaker protection

        Args:
            func: Function to execute
            *args: Positional arguments
            **kwargs: Keyword arguments

        Returns:
            Function result

        Raises:
            CircuitBreakerOpenError: If circuit is open
            Exception: Original exception from func
        """
        if not self.is_available:
            raise ConnectionError("Redis is not available")

        if self.enable_circuit_breaker and self._circuit_breaker:
            return self._circuit_breaker.call(func, *args, **kwargs)
        else:
            return func(*args, **kwargs)

    # ========================================================================
    # REDIS OPERATIONS WITH CIRCUIT BREAKER
    # ========================================================================

    def get(self, key: str) -> Optional[str]:
        """Get value with circuit breaker protection"""
        return self._execute_with_circuit_breaker(self.client.get, key)

    def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """Set value with circuit breaker protection"""
        return self._execute_with_circuit_breaker(self.client.set, key, value, ex=ex)

    def delete(self, *keys: str) -> int:
        """Delete keys with circuit breaker protection"""
        return self._execute_with_circuit_breaker(self.client.delete, *keys)

    def exists(self, *keys: str) -> int:
        """Check if keys exist with circuit breaker protection"""
        return self._execute_with_circuit_breaker(self.client.exists, *keys)

    def setex(self, key: str, time: int, value: str) -> bool:
        """Set with expiration with circuit breaker protection"""
        return self._execute_with_circuit_breaker(self.client.setex, key, time, value)

    def ping(self) -> bool:
        """Ping Redis with circuit breaker protection"""
        return self._execute_with_circuit_breaker(self.client.ping)

    # ========================================================================
    # GRACEFUL DEGRADATION METHODS
    # ========================================================================

    def get_with_fallback(self, key: str, default: Any = None) -> Any:
        """
        Get value with automatic fallback on failure

        Args:
            key: Redis key
            default: Fallback value if Redis unavailable

        Returns:
            Value from Redis or fallback
        """
        try:
            result = self.get(key)
            return result if result is not None else default
        except CircuitBreakerOpenError:
            self._handle_fallback("Circuit breaker open", "get", key)
            return default
        except Exception as e:
            self._handle_fallback(f"Error: {e}", "get", key)
            return default

    def set_with_fallback(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        """
        Set value with automatic fallback on failure

        Args:
            key: Redis key
            value: Value to set
            ex: Expiration in seconds

        Returns:
            True if successful, False if fallback used
        """
        try:
            return self.set(key, value, ex=ex)
        except CircuitBreakerOpenError:
            self._handle_fallback("Circuit breaker open", "set", key)
            return False
        except Exception as e:
            self._handle_fallback(f"Error: {e}", "set", key)
            return False

    def _handle_fallback(self, reason: str, operation: str, key: str):
        """Handle fallback logic with configured behavior"""
        self._fallback_count += 1

        message = f"Redis fallback used: {operation}({key}) - {reason}"

        if self.fallback_mode == "silent":
            logger.debug(message)
        elif self.fallback_mode == "warn":
            logger.warning(message)
        elif self.fallback_mode == "error":
            logger.error(message)

    @contextmanager
    def with_fallback(self, default_value: Any = None):
        """
        Context manager for graceful degradation

        Usage:
            with pool.with_fallback(default_value={}):
                data = pool.get("key")
                # If any exception, returns default_value
        """
        try:
            yield
        except (CircuitBreakerOpenError, RedisError, ConnectionError, TimeoutError) as e:
            logger.warning(f"Redis operation failed, using fallback: {e}")
            return default_value

    # ========================================================================
    # MONITORING AND HEALTH
    # ========================================================================

    def health_check(self) -> bool:
        """Perform health check (bypasses circuit breaker)"""
        if not self._base_pool:
            return False
        return self._base_pool.health_check()

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status including circuit breaker metrics"""
        status = {
            "available": self.is_available,
            "environment": self.environment.value,
            "circuit_breaker_enabled": self.enable_circuit_breaker,
            "fallback_count": self._fallback_count,
            "circuit_open_count": self._circuit_open_count,
        }

        # Add base pool status
        if self._base_pool:
            status["pool"] = self._base_pool.get_pool_status()

        # Add circuit breaker metrics
        if self._circuit_breaker:
            status["circuit_breaker"] = self._circuit_breaker.get_metrics()

        return status

    def get_circuit_state(self) -> Optional[CircuitState]:
        """Get current circuit breaker state"""
        if self._circuit_breaker:
            return self._circuit_breaker.state
        return None

    def reset_circuit_breaker(self):
        """Manually reset circuit breaker to CLOSED state"""
        if self._circuit_breaker:
            self._circuit_breaker.reset()
            logger.info("Circuit breaker manually reset")

    def force_circuit_open(self):
        """Manually open circuit breaker (for testing/maintenance)"""
        if self._circuit_breaker:
            self._circuit_breaker.force_open()
            logger.warning("Circuit breaker manually opened")

    def close(self):
        """Close Redis connection pool gracefully"""
        if self._base_pool:
            self._base_pool.close()
            logger.info("Resilient Redis pool closed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# ============================================================================
# DECORATOR FOR REDIS OPERATIONS
# ============================================================================


def with_redis_fallback(default_value: Any = None, fallback_mode: str = "warn"):
    """
    Decorator for Redis operations with automatic fallback

    Args:
        default_value: Value to return on failure
        fallback_mode: How to handle fallback ("silent", "warn", "error")

    Usage:
        @with_redis_fallback(default_value={})
        def get_user_data(redis_pool, user_id):
            return redis_pool.get(f"user:{user_id}")
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except (CircuitBreakerOpenError, RedisError, ConnectionError, TimeoutError) as e:
                message = f"Redis operation failed in {func.__name__}: {e}"

                if fallback_mode == "silent":
                    logger.debug(message)
                elif fallback_mode == "warn":
                    logger.warning(message)
                elif fallback_mode == "error":
                    logger.error(message)

                return default_value

        return wrapper
    return decorator
