"""
Optimized Redis Connection Pool Implementation
Clean implementation with dependency injection support
"""

import os
import logging
from typing import Optional, Dict, Any
import redis
from redis.connection import ConnectionPool
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from redis.retry import Retry
from redis.backoff import ExponentialBackoff

from .redis_pool_protocol import PoolConfiguration, PoolMetrics, DeploymentEnvironment

logger = logging.getLogger(__name__)


class RedisConnectionConfig:
    """Connection configuration - separate from pool configuration"""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: int = 0,
        password: Optional[str] = None,
    ):
        self.host = host or os.getenv("REDIS_HOST", "localhost")
        self.port = port or int(os.getenv("REDIS_PORT", "6379"))
        self.db = db
        self.password = password or os.getenv("REDIS_PASSWORD")


class OptimizedRedisPool:
    """
    Optimized Redis connection pool with clean architecture:
    - Dependency injection ready
    - Separated concerns (config, metrics, connection)
    - Immutable configuration
    - Testable and mockable
    """

    def __init__(
        self,
        connection_config: RedisConnectionConfig,
        pool_config: PoolConfiguration,
        environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION,
        enable_monitoring: bool = True,
    ):
        """
        Initialize optimized Redis connection pool

        Args:
            connection_config: Redis connection configuration
            pool_config: Pool sizing and behavior configuration
            environment: Deployment environment
            enable_monitoring: Enable metrics collection
        """
        self.connection_config = connection_config
        self.pool_config = pool_config
        self.environment = environment
        self.enable_monitoring = enable_monitoring

        # Initialize metrics tracker
        self.metrics = PoolMetrics() if enable_monitoring else None

        # Pool state
        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._available = False

        # Initialize connection pool
        self._initialize()

    def _initialize(self):
        """Initialize optimized Redis connection pool"""
        try:
            logger.info(f"Initializing Redis pool for {self.environment.value} environment")
            logger.info(
                f"Target: {self.pool_config.target_users} users, "
                f"{self.pool_config.workers} workers, "
                f"{self.pool_config.max_connections} connections "
                f"({self.pool_config.connections_per_worker()} per worker)"
            )

            # Build connection pool parameters
            pool_params = self._build_pool_params()

            # Create connection pool
            self._pool = ConnectionPool(**pool_params)

            # Create Redis client
            self._client = redis.Redis(connection_pool=self._pool)

            # Test connection
            self._client.ping()
            self._available = True

            logger.info(
                f"✅ Redis pool initialized: {self.connection_config.host}:"
                f"{self.connection_config.port} "
                f"({self.pool_config.max_connections} connections)"
            )

        except (ConnectionError, TimeoutError, RedisError) as e:
            self._available = False
            logger.error(f"❌ Redis pool initialization failed: {e}")
            if self.metrics:
                self.metrics.increment("connection_errors")
            raise

    def _build_pool_params(self) -> Dict[str, Any]:
        """Build connection pool parameters from configuration"""
        pool_params = {
            "host": self.connection_config.host,
            "port": self.connection_config.port,
            "db": self.connection_config.db,
            "max_connections": self.pool_config.max_connections,
            # Timeout configuration
            "socket_timeout": self.pool_config.socket_timeout,
            "socket_connect_timeout": self.pool_config.socket_connect_timeout,
            "socket_keepalive": True,
            "socket_keepalive_options": {
                1: 1,  # TCP_KEEPIDLE
                2: 1,  # TCP_KEEPINTVL
                3: 3,  # TCP_KEEPCNT
            },
            # Health check interval
            "health_check_interval": self.pool_config.health_check_interval,
            # Retry logic with exponential backoff
            "retry_on_timeout": True,
            "retry_on_error": [ConnectionError, TimeoutError],
            "retry": Retry(
                ExponentialBackoff(
                    base=self.pool_config.retry_base_backoff, cap=self.pool_config.retry_max_backoff
                ),
                retries=self.pool_config.retry_attempts,
            ),
            # Connection pool behavior
            "decode_responses": True,
        }

        # Only add password if set
        if self.connection_config.password:
            pool_params["password"] = self.connection_config.password

        return pool_params

    @property
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self._available

    @property
    def client(self) -> redis.Redis:
        """Get Redis client"""
        if not self._available:
            raise ConnectionError("Redis is not available")
        return self._client

    def health_check(self) -> bool:
        """Perform health check on Redis connection"""
        try:
            result = self._client.ping()
            if result:
                logger.debug("Redis health check: OK")
                return True
            else:
                if self.metrics:
                    self.metrics.increment("health_check_failures")
                logger.warning("Redis health check: FAILED (ping returned False)")
                return False
        except Exception as e:
            if self.metrics:
                self.metrics.increment("health_check_failures")
            logger.error(f"Redis health check: FAILED ({e})")
            return False

    def get_pool_status(self) -> Dict[str, Any]:
        """Get detailed pool status for monitoring"""
        if not self._pool:
            return {"status": "unavailable", "error": "Pool not initialized"}

        created = self._pool._created_connections
        available = len(self._pool._available_connections)
        in_use = created - available
        max_conn = self._pool.max_connections

        utilization = (in_use / max_conn) * 100 if max_conn > 0 else 0

        status = {
            "status": "healthy" if self._available else "degraded",
            "environment": self.environment.value,
            "max_connections": max_conn,
            "created_connections": created,
            "available_connections": available,
            "in_use_connections": in_use,
            "utilization_percent": round(utilization, 2),
        }

        # Add metrics if monitoring enabled
        if self.metrics:
            status["metrics"] = self.metrics.get_all()

        # Add warnings
        warnings = []
        if utilization > 80:
            warnings.append(
                f"High pool utilization: {utilization:.1f}% (consider increasing pool size)"
            )
        if self.metrics:
            pool_exhausted = self.metrics.get_all().get("pool_exhausted_count", 0)
            if pool_exhausted > 0:
                warnings.append(f"Pool exhausted {pool_exhausted} times")

            health_failures = self.metrics.get_all().get("health_check_failures", 0)
            if health_failures > 0:
                warnings.append(f"Health checks failed {health_failures} times")

        if warnings:
            status["warnings"] = warnings

        return status

    def close(self):
        """Close Redis connection pool gracefully"""
        if self._pool:
            self._pool.disconnect()
            logger.info("Redis pool closed")
            self._available = False

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    def __del__(self):
        """Cleanup on deletion"""
        try:
            self.close()
        except Exception:
            pass
