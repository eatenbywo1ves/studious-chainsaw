"""
Redis Connection Manager
Provides dependency injection and lifecycle management for Redis pools
"""

import os
import logging
from typing import Optional
from functools import lru_cache

from .redis_pool_protocol import DeploymentEnvironment, PoolConfiguration, RedisPoolProtocol
from .redis_pool_implementation import OptimizedRedisPool, RedisConnectionConfig

logger = logging.getLogger(__name__)


class RedisConnectionManager:
    """
    Manages Redis pool lifecycle with dependency injection support.

    Benefits:
    - Lazy initialization
    - Environment-aware configuration
    - Easy testing and mocking
    - No global state pollution
    """

    def __init__(
        self,
        environment: Optional[DeploymentEnvironment] = None,
        connection_config: Optional[RedisConnectionConfig] = None,
        pool_config: Optional[PoolConfiguration] = None,
        enable_monitoring: bool = True,
    ):
        """
        Initialize Redis connection manager

        Args:
            environment: Deployment environment (auto-detected if None)
            connection_config: Custom connection config (uses env vars if None)
            pool_config: Custom pool config (uses environment default if None)
            enable_monitoring: Enable metrics collection
        """
        # Auto-detect environment if not provided
        if environment is None:
            env_str = os.getenv("DEPLOYMENT_ENV", "production").lower()
            environment = DeploymentEnvironment(env_str)

        self.environment = environment
        self.enable_monitoring = enable_monitoring

        # Create connection config
        self.connection_config = connection_config or RedisConnectionConfig()

        # Create pool config
        self.pool_config = pool_config or PoolConfiguration.for_environment(environment)

        # Pool instance (lazy initialized)
        self._pool: Optional[RedisPoolProtocol] = None

    def get_pool(self) -> RedisPoolProtocol:
        """
        Get or create Redis pool (lazy initialization)

        Returns:
            Redis pool instance
        """
        if self._pool is None:
            self._pool = OptimizedRedisPool(
                connection_config=self.connection_config,
                pool_config=self.pool_config,
                environment=self.environment,
                enable_monitoring=self.enable_monitoring,
            )

        return self._pool

    def reset_pool(self):
        """Reset pool (useful for testing or reconfiguration)"""
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def health_check(self) -> bool:
        """Perform health check on Redis connection"""
        try:
            pool = self.get_pool()
            return pool.health_check()
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            return False

    def get_status(self) -> dict:
        """Get detailed status of Redis connection"""
        try:
            pool = self.get_pool()
            return pool.get_pool_status()
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "environment": self.environment.value,
            }

    def close(self):
        """Close Redis connection pool"""
        if self._pool is not None:
            self._pool.close()
            self._pool = None

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# ============================================================================
# DEPENDENCY INJECTION HELPERS
# ============================================================================

# Global instance for simple use cases (can be replaced for testing)
_default_manager: Optional[RedisConnectionManager] = None


@lru_cache(maxsize=1)
def get_default_redis_manager() -> RedisConnectionManager:
    """
    Get default Redis connection manager (cached singleton pattern).

    This is a compromise between pure DI and convenience:
    - Uses caching instead of global mutable state
    - Can be cleared for testing: get_default_redis_manager.cache_clear()
    - Environment-aware initialization

    Returns:
        RedisConnectionManager instance
    """
    return RedisConnectionManager()


def get_redis_pool() -> RedisPoolProtocol:
    """
    Convenience function to get Redis pool from default manager.

    For dependency injection in FastAPI:

    ```python
    from fastapi import Depends

    async def get_redis(
        manager: RedisConnectionManager = Depends(get_default_redis_manager)
    ):
        return manager.get_pool()

    @app.get("/status")
    async def status(redis_pool = Depends(get_redis)):
        return redis_pool.get_pool_status()
    ```

    Returns:
        Redis pool instance
    """
    manager = get_default_redis_manager()
    return manager.get_pool()


# ============================================================================
# MONITORING HELPERS
# ============================================================================


def log_pool_metrics(pool: RedisPoolProtocol):
    """
    Log connection pool metrics for monitoring

    Args:
        pool: Redis pool instance
    """
    status = pool.get_pool_status()

    logger.info(
        f"Redis Pool Status: {status['status']} | "
        f"Utilization: {status.get('utilization_percent', 0)}% | "
        f"In-Use: {status.get('in_use_connections', 0)}/"
        f"{status.get('max_connections', 0)}"
    )

    if "warnings" in status:
        for warning in status["warnings"]:
            logger.warning(f"Redis Pool Warning: {warning}")

    return status


def create_test_manager(
    environment: DeploymentEnvironment = DeploymentEnvironment.DEVELOPMENT, **kwargs
) -> RedisConnectionManager:
    """
    Create a Redis manager for testing

    Args:
        environment: Test environment configuration
        **kwargs: Additional configuration overrides

    Returns:
        RedisConnectionManager configured for testing
    """
    return RedisConnectionManager(environment=environment, enable_monitoring=True, **kwargs)
