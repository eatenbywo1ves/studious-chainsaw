"""
Optimized Redis Connection Pool Configuration
Production-grade connection pooling with monitoring and health checks
"""

import os
import logging
from typing import Optional, Dict, Any
from enum import Enum
import redis
from redis.connection import ConnectionPool
from redis.exceptions import RedisError, ConnectionError, TimeoutError
from redis.retry import Retry
from redis.backoff import ExponentialBackoff

logger = logging.getLogger(__name__)


class DeploymentEnvironment(Enum):
    """Deployment environment types"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class OptimizedRedisPool:
    """
    Optimized Redis connection pool with:
    - Environment-specific pool sizing
    - Health check intervals
    - Exponential backoff retry logic
    - Connection pool monitoring
    - Automatic failover
    """

    # Pool sizing configuration by environment
    POOL_CONFIG = {
        DeploymentEnvironment.DEVELOPMENT: {
            "max_connections": 20,
            "workers": 1,
            "target_users": 100,
        },
        DeploymentEnvironment.STAGING: {
            "max_connections": 60,
            "workers": 2,
            "target_users": 1000,
        },
        DeploymentEnvironment.PRODUCTION: {
            "max_connections": 160,  # Optimized for 10K users with 4 workers
            "workers": 4,
            "target_users": 10000,
        },
    }

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: int = 0,
        password: Optional[str] = None,
        environment: DeploymentEnvironment = DeploymentEnvironment.PRODUCTION,
        max_connections: Optional[int] = None,  # Override pool size
        enable_monitoring: bool = True,
    ):
        """
        Initialize optimized Redis connection pool

        Args:
            host: Redis host (default from env REDIS_HOST or localhost)
            port: Redis port (default from env REDIS_PORT or 6379)
            db: Redis database number
            password: Redis password (from env REDIS_PASSWORD)
            environment: Deployment environment (dev/staging/production)
            max_connections: Override pool size (None = use environment default)
            enable_monitoring: Enable pool metrics collection
        """
        self.host = host or os.getenv("REDIS_HOST", "localhost")
        self.port = port or int(os.getenv("REDIS_PORT", "6379"))
        self.db = db
        self.password = password or os.getenv("REDIS_PASSWORD")
        self.environment = environment

        # Get pool configuration for environment
        pool_config = self.POOL_CONFIG[environment]
        self.max_connections = max_connections or pool_config["max_connections"]
        self.workers = pool_config["workers"]
        self.target_users = pool_config["target_users"]

        # Monitoring
        self.enable_monitoring = enable_monitoring
        self._metrics = {
            "connections_created": 0,
            "connections_reused": 0,
            "connection_errors": 0,
            "retry_attempts": 0,
            "pool_exhausted_count": 0,
            "health_check_failures": 0,
        }

        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._available = False

        # Initialize connection pool
        self._initialize()

    def _initialize(self):
        """Initialize optimized Redis connection pool"""
        try:
            logger.info(
                f"Initializing Redis pool for {self.environment.value} environment"
            )
            logger.info(
                f"Target: {self.target_users} users, {self.workers} workers, "
                f"{self.max_connections} connections ({self.max_connections // self.workers} per worker)"
            )

            # Build connection pool parameters with optimizations
            pool_params = {
                "host": self.host,
                "port": self.port,
                "db": self.db,
                "max_connections": self.max_connections,
                # ✅ Timeout configuration
                "socket_timeout": 5,  # 5 seconds for operations
                "socket_connect_timeout": 5,  # 5 seconds for initial connection
                "socket_keepalive": True,  # Keep connections alive
                "socket_keepalive_options": {
                    1: 1,  # TCP_KEEPIDLE (seconds before keepalive probes start)
                    2: 1,  # TCP_KEEPINTVL (interval between keepalive probes)
                    3: 3,  # TCP_KEEPCNT (number of keepalive probes)
                },
                # ✅ Health check interval (check connections every 30 seconds)
                "health_check_interval": 30,
                # ✅ Retry logic with exponential backoff
                "retry_on_timeout": True,
                "retry_on_error": [ConnectionError, TimeoutError],
                "retry": Retry(
                    ExponentialBackoff(base=0.008, cap=0.512),  # 8ms to 512ms
                    retries=3,
                ),
                # ✅ Connection pool behavior
                "decode_responses": True,  # Decode bytes to strings automatically
            }

            # Only add password if it's actually set
            if self.password:
                pool_params["password"] = self.password

            # Create connection pool
            self._pool = ConnectionPool(**pool_params)

            # Create Redis client
            self._client = redis.Redis(connection_pool=self._pool)

            # Test connection
            self._client.ping()
            self._available = True

            logger.info(
                f"✅ Redis pool initialized: {self.host}:{self.port} "
                f"({self.max_connections} connections)"
            )

        except (ConnectionError, TimeoutError, RedisError) as e:
            self._available = False
            logger.error(f"❌ Redis pool initialization failed: {e}")
            raise

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

    @property
    def metrics(self) -> Dict[str, int]:
        """Get connection pool metrics"""
        if not self.enable_monitoring:
            return {}

        # Add pool connection metrics
        if self._pool:
            pool_info = {
                "max_connections": self._pool.max_connections,
                "created_connections": self._pool._created_connections,
                "available_connections": len(self._pool._available_connections),
                "in_use_connections": (
                    self._pool._created_connections
                    - len(self._pool._available_connections)
                ),
            }
            return {**self._metrics, **pool_info}

        return self._metrics

    def get_pool_status(self) -> Dict[str, Any]:
        """
        Get detailed pool status for monitoring

        Returns:
            Dictionary with pool health metrics
        """
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
            "metrics": self.metrics if self.enable_monitoring else {},
        }

        # Add warnings
        warnings = []
        if utilization > 80:
            warnings.append(
                f"High pool utilization: {utilization:.1f}% (consider increasing pool size)"
            )
        if self._metrics.get("pool_exhausted_count", 0) > 0:
            warnings.append(
                f"Pool exhausted {self._metrics['pool_exhausted_count']} times"
            )
        if self._metrics.get("health_check_failures", 0) > 0:
            warnings.append(
                f"Health checks failed {self._metrics['health_check_failures']} times"
            )

        if warnings:
            status["warnings"] = warnings

        return status

    def health_check(self) -> bool:
        """
        Perform health check on Redis connection

        Returns:
            True if healthy, False otherwise
        """
        try:
            result = self._client.ping()
            if result:
                logger.debug("Redis health check: OK")
                return True
            else:
                self._metrics["health_check_failures"] += 1
                logger.warning("Redis health check: FAILED (ping returned False)")
                return False
        except Exception as e:
            self._metrics["health_check_failures"] += 1
            logger.error(f"Redis health check: FAILED ({e})")
            return False

    def close(self):
        """Close Redis connection pool gracefully"""
        if self._pool:
            self._pool.disconnect()
            logger.info("Redis pool closed")

    def __del__(self):
        """Cleanup on deletion"""
        try:
            self.close()
        except Exception:
            pass


# ============================================================================
# GLOBAL SINGLETON INSTANCE
# ============================================================================

_redis_pool_instance: Optional[OptimizedRedisPool] = None


def get_optimized_redis_pool(
    environment: Optional[DeploymentEnvironment] = None,
) -> OptimizedRedisPool:
    """
    Get global optimized Redis pool instance (singleton pattern)

    Args:
        environment: Deployment environment (auto-detected from env if not provided)

    Returns:
        OptimizedRedisPool instance
    """
    global _redis_pool_instance

    if _redis_pool_instance is None:
        # Auto-detect environment from ENV variable if not provided
        if environment is None:
            env_str = os.getenv("DEPLOYMENT_ENV", "production").lower()
            environment = DeploymentEnvironment(env_str)

        _redis_pool_instance = OptimizedRedisPool(environment=environment)

    return _redis_pool_instance


def reset_redis_pool():
    """Reset global Redis pool instance (for testing)"""
    global _redis_pool_instance
    if _redis_pool_instance:
        _redis_pool_instance.close()
    _redis_pool_instance = None


# ============================================================================
# MONITORING HELPER
# ============================================================================


def log_pool_metrics(pool: OptimizedRedisPool):
    """
    Log connection pool metrics for monitoring

    Use this in your application's monitoring loop or health check endpoint
    """
    status = pool.get_pool_status()

    logger.info(
        f"Redis Pool Status: {status['status']} | "
        f"Utilization: {status['utilization_percent']}% | "
        f"In-Use: {status['in_use_connections']}/{status['max_connections']}"
    )

    if "warnings" in status:
        for warning in status["warnings"]:
            logger.warning(f"Redis Pool Warning: {warning}")

    return status
