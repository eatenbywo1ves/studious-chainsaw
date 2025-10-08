"""
Redis Connection Pool Protocol and Interfaces
Defines contracts for pool implementations with clean separation of concerns
"""

from typing import Protocol, Dict, Any
from enum import Enum
import redis


class DeploymentEnvironment(Enum):
    """Deployment environment types"""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class PoolMetrics:
    """Metrics tracker for connection pools - separated from pool logic"""

    def __init__(self):
        self._metrics: Dict[str, int] = {
            "connections_created": 0,
            "connections_reused": 0,
            "connection_errors": 0,
            "retry_attempts": 0,
            "pool_exhausted_count": 0,
            "health_check_failures": 0,
        }

    def increment(self, metric_name: str, value: int = 1):
        """Increment a metric counter"""
        if metric_name in self._metrics:
            self._metrics[metric_name] += value

    def get_all(self) -> Dict[str, int]:
        """Get all metrics"""
        return self._metrics.copy()

    def reset(self):
        """Reset all metrics to zero"""
        for key in self._metrics:
            self._metrics[key] = 0


class RedisPoolProtocol(Protocol):
    """
    Protocol defining the contract for Redis connection pools.
    Any pool implementation must satisfy this interface.
    """

    @property
    def is_available(self) -> bool:
        """Check if Redis connection is available"""
        ...

    @property
    def client(self) -> redis.Redis:
        """Get Redis client instance"""
        ...

    def health_check(self) -> bool:
        """Perform health check on connection"""
        ...

    def get_pool_status(self) -> Dict[str, Any]:
        """Get detailed pool status"""
        ...

    def close(self):
        """Close pool gracefully"""
        ...


class PoolConfiguration:
    """Configuration for Redis connection pools - immutable after creation"""

    def __init__(
        self,
        max_connections: int,
        workers: int,
        target_users: int,
        socket_timeout: int = 5,
        socket_connect_timeout: int = 5,
        health_check_interval: int = 30,
        retry_attempts: int = 3,
        retry_base_backoff: float = 0.008,
        retry_max_backoff: float = 0.512,
    ):
        self.max_connections = max_connections
        self.workers = workers
        self.target_users = target_users
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.health_check_interval = health_check_interval
        self.retry_attempts = retry_attempts
        self.retry_base_backoff = retry_base_backoff
        self.retry_max_backoff = retry_max_backoff

    @classmethod
    def for_environment(cls, environment: DeploymentEnvironment) -> "PoolConfiguration":
        """Factory method to create configuration for specific environment"""
        configs = {
            DeploymentEnvironment.DEVELOPMENT: cls(
                max_connections=20,
                workers=1,
                target_users=100,
            ),
            DeploymentEnvironment.STAGING: cls(
                max_connections=60,
                workers=2,
                target_users=1000,
            ),
            DeploymentEnvironment.PRODUCTION: cls(
                max_connections=160,
                workers=4,
                target_users=10000,
            ),
        }
        return configs[environment]

    def connections_per_worker(self) -> int:
        """Calculate connections per worker"""
        return self.max_connections // self.workers if self.workers > 0 else self.max_connections
