"""
Redis Connection Manager
Provides connection pooling, failover, and health checking for Redis
"""

import os
import logging
from typing import Optional, Any
from contextlib import contextmanager
import redis
from redis.connection import ConnectionPool
from redis.exceptions import RedisError, ConnectionError, TimeoutError

logger = logging.getLogger(__name__)


class RedisConnectionManager:
    """
    Manages Redis connections with pooling and failover support
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        db: int = 0,
        password: Optional[str] = None,
        max_connections: int = 50,
        socket_timeout: int = 5,
        socket_connect_timeout: int = 5,
        decode_responses: bool = True,
        enable_fallback: bool = True  # Fallback to in-memory for dev
    ):
        """
        Initialize Redis connection manager

        Args:
            host: Redis host (default from env REDIS_HOST or localhost)
            port: Redis port (default from env REDIS_PORT or 6379)
            db: Redis database number
            password: Redis password (from env REDIS_PASSWORD)
            max_connections: Maximum connections in pool
            socket_timeout: Socket timeout in seconds
            socket_connect_timeout: Connection timeout in seconds
            decode_responses: Decode responses to strings
            enable_fallback: Enable in-memory fallback if Redis unavailable
        """
        self.host = host or os.getenv("REDIS_HOST", "localhost")
        self.port = port or int(os.getenv("REDIS_PORT", "6379"))
        self.db = db
        self.password = password or os.getenv("REDIS_PASSWORD")
        self.max_connections = max_connections
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.decode_responses = decode_responses
        self.enable_fallback = enable_fallback

        self._pool: Optional[ConnectionPool] = None
        self._client: Optional[redis.Redis] = None
        self._available = False
        self._fallback_storage: dict = {}  # In-memory fallback

        # Initialize connection
        self._initialize()

    def _initialize(self):
        """Initialize Redis connection pool"""
        try:
            # Build connection pool parameters
            pool_params = {
                "host": self.host,
                "port": self.port,
                "db": self.db,
                "max_connections": self.max_connections,
                "socket_timeout": self.socket_timeout,
                "socket_connect_timeout": self.socket_connect_timeout,
                "decode_responses": self.decode_responses
            }

            # Only add password if it's actually set
            if self.password:
                pool_params["password"] = self.password

            self._pool = ConnectionPool(**pool_params)

            self._client = redis.Redis(connection_pool=self._pool)

            # Test connection
            self._client.ping()
            self._available = True
            logger.info(f"Redis connection established: {self.host}:{self.port}")

        except (ConnectionError, TimeoutError, RedisError) as e:
            self._available = False
            if self.enable_fallback:
                logger.warning(
                    f"Redis connection failed ({e}), using in-memory fallback. "
                    "This is NOT suitable for production!"
                )
            else:
                logger.error(f"Redis connection failed: {e}")
                raise

    @property
    def is_available(self) -> bool:
        """Check if Redis is available"""
        return self._available

    @property
    def client(self) -> redis.Redis:
        """Get Redis client"""
        if not self._available:
            if not self.enable_fallback:
                raise ConnectionError("Redis is not available and fallback is disabled")
        return self._client

    def get(self, key: str) -> Optional[str]:
        """Get value from Redis with fallback"""
        if self._available:
            try:
                return self._client.get(key)
            except RedisError as e:
                logger.error(f"Redis GET error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to in-memory
        return self._fallback_storage.get(key)

    def set(
        self,
        key: str,
        value: Any,
        ex: Optional[int] = None,
        px: Optional[int] = None,
        nx: bool = False,
        xx: bool = False
    ) -> bool:
        """Set value in Redis with fallback"""
        if self._available:
            try:
                return self._client.set(key, value, ex=ex, px=px, nx=nx, xx=xx)
            except RedisError as e:
                logger.error(f"Redis SET error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to in-memory (simplified - doesn't handle all options)
        if nx and key in self._fallback_storage:
            return False
        if xx and key not in self._fallback_storage:
            return False

        self._fallback_storage[key] = value
        # Note: In-memory fallback doesn't support TTL
        return True

    def setex(self, key: str, time: int, value: Any) -> bool:
        """Set value with expiration"""
        return self.set(key, value, ex=time)

    def delete(self, *keys: str) -> int:
        """Delete keys from Redis with fallback"""
        if self._available:
            try:
                return self._client.delete(*keys)
            except RedisError as e:
                logger.error(f"Redis DELETE error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to in-memory
        count = 0
        for key in keys:
            if key in self._fallback_storage:
                del self._fallback_storage[key]
                count += 1
        return count

    def exists(self, *keys: str) -> int:
        """Check if keys exist"""
        if self._available:
            try:
                return self._client.exists(*keys)
            except RedisError as e:
                logger.error(f"Redis EXISTS error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to in-memory
        return sum(1 for key in keys if key in self._fallback_storage)

    def incr(self, key: str, amount: int = 1) -> int:
        """Increment value"""
        if self._available:
            try:
                return self._client.incr(key, amount)
            except RedisError as e:
                logger.error(f"Redis INCR error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to in-memory
        current = int(self._fallback_storage.get(key, 0))
        new_value = current + amount
        self._fallback_storage[key] = str(new_value)
        return new_value

    def decr(self, key: str, amount: int = 1) -> int:
        """Decrement value"""
        if self._available:
            try:
                return self._client.decr(key, amount)
            except RedisError as e:
                logger.error(f"Redis DECR error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback to in-memory
        current = int(self._fallback_storage.get(key, 0))
        new_value = current - amount
        self._fallback_storage[key] = str(new_value)
        return new_value

    def expire(self, key: str, time: int) -> bool:
        """Set expiration on key"""
        if self._available:
            try:
                return self._client.expire(key, time)
            except RedisError as e:
                logger.error(f"Redis EXPIRE error: {e}")
                if not self.enable_fallback:
                    raise

        # In-memory fallback doesn't support TTL
        logger.warning("Expire not supported in fallback mode")
        return key in self._fallback_storage

    def ttl(self, key: str) -> int:
        """Get time to live for key"""
        if self._available:
            try:
                return self._client.ttl(key)
            except RedisError as e:
                logger.error(f"Redis TTL error: {e}")
                if not self.enable_fallback:
                    raise

        # In-memory fallback doesn't track TTL
        return -1 if key in self._fallback_storage else -2

    def hget(self, name: str, key: str) -> Optional[str]:
        """Get hash field value"""
        if self._available:
            try:
                return self._client.hget(name, key)
            except RedisError as e:
                logger.error(f"Redis HGET error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback: hash stored as dict in dict
        hash_dict = self._fallback_storage.get(f"hash:{name}", {})
        return hash_dict.get(key) if isinstance(hash_dict, dict) else None

    def hset(self, name: str, key: str, value: Any) -> int:
        """Set hash field value"""
        if self._available:
            try:
                return self._client.hset(name, key, value)
            except RedisError as e:
                logger.error(f"Redis HSET error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback: store hash as dict
        hash_key = f"hash:{name}"
        if hash_key not in self._fallback_storage:
            self._fallback_storage[hash_key] = {}

        hash_dict = self._fallback_storage[hash_key]
        is_new = key not in hash_dict
        hash_dict[key] = value
        return 1 if is_new else 0

    def hgetall(self, name: str) -> dict:
        """Get all hash fields"""
        if self._available:
            try:
                return self._client.hgetall(name)
            except RedisError as e:
                logger.error(f"Redis HGETALL error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback
        hash_dict = self._fallback_storage.get(f"hash:{name}", {})
        return hash_dict if isinstance(hash_dict, dict) else {}

    def hdel(self, name: str, *keys: str) -> int:
        """Delete hash fields"""
        if self._available:
            try:
                return self._client.hdel(name, *keys)
            except RedisError as e:
                logger.error(f"Redis HDEL error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback
        hash_key = f"hash:{name}"
        if hash_key not in self._fallback_storage:
            return 0

        hash_dict = self._fallback_storage[hash_key]
        count = 0
        for key in keys:
            if key in hash_dict:
                del hash_dict[key]
                count += 1
        return count

    def ping(self) -> bool:
        """Ping Redis server"""
        if self._available:
            try:
                return self._client.ping()
            except RedisError:
                return False
        return False

    def info(self) -> dict:
        """Get Redis server info"""
        if self._available:
            try:
                return self._client.info()
            except RedisError as e:
                logger.error(f"Redis INFO error: {e}")
                return {"error": str(e)}
        return {"mode": "fallback", "available": False}

    @contextmanager
    def pipeline(self):
        """Context manager for Redis pipeline"""
        if self._available:
            pipe = self._client.pipeline()
            try:
                yield pipe
                pipe.execute()
            except RedisError as e:
                logger.error(f"Redis pipeline error: {e}")
                if not self.enable_fallback:
                    raise
        else:
            # Fallback doesn't support pipelines
            logger.warning("Pipeline not supported in fallback mode")
            yield None

    # Sorted Set Operations (for DDoS protection and rate limiting)
    def zadd(self, name: str, mapping: dict, nx: bool = False, xx: bool = False) -> int:
        """Add members to sorted set with scores"""
        if self._available:
            try:
                return self._client.zadd(name, mapping, nx=nx, xx=xx)
            except RedisError as e:
                logger.error(f"Redis ZADD error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback: sorted set stored as list of (score, member) tuples
        sorted_set_key = f"zset:{name}"
        if sorted_set_key not in self._fallback_storage:
            self._fallback_storage[sorted_set_key] = []

        sorted_set = self._fallback_storage[sorted_set_key]
        added = 0
        for member, score in mapping.items():
            exists = any(m == member for s, m in sorted_set)
            if nx and exists:
                continue
            if xx and not exists:
                continue

            # Remove existing member
            sorted_set[:] = [(s, m) for s, m in sorted_set if m != member]
            # Add new member with score
            sorted_set.append((score, member))
            added += 1

        # Keep sorted
        sorted_set.sort()
        return added

    def zremrangebyscore(self, name: str, min_score: Any, max_score: Any) -> int:
        """Remove members with scores in range"""
        if self._available:
            try:
                return self._client.zremrangebyscore(name, min_score, max_score)
            except RedisError as e:
                logger.error(f"Redis ZREMRANGEBYSCORE error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback
        sorted_set_key = f"zset:{name}"
        if sorted_set_key not in self._fallback_storage:
            return 0

        sorted_set = self._fallback_storage[sorted_set_key]
        # Handle '-inf' and '+inf'
        if min_score == '-inf':
            min_score = float('-inf')
        if max_score == '+inf':
            max_score = float('inf')

        original_len = len(sorted_set)
        sorted_set[:] = [(s, m) for s, m in sorted_set if not (min_score <= s <= max_score)]
        return original_len - len(sorted_set)

    def zrange(self, name: str, start: int, end: int, withscores: bool = False) -> list:
        """Get members in sorted set by index range"""
        if self._available:
            try:
                return self._client.zrange(name, start, end, withscores=withscores)
            except RedisError as e:
                logger.error(f"Redis ZRANGE error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback
        sorted_set_key = f"zset:{name}"
        if sorted_set_key not in self._fallback_storage:
            return []

        sorted_set = self._fallback_storage[sorted_set_key]
        # Handle negative indices
        if end == -1:
            end = len(sorted_set)
        else:
            end = end + 1

        result = sorted_set[start:end]
        if withscores:
            return result  # Returns list of (score, member) tuples
        else:
            return [m for s, m in result]

    def zcount(self, name: str, min_score: Any, max_score: Any) -> int:
        """Count members with scores in range"""
        if self._available:
            try:
                return self._client.zcount(name, min_score, max_score)
            except RedisError as e:
                logger.error(f"Redis ZCOUNT error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback
        sorted_set_key = f"zset:{name}"
        if sorted_set_key not in self._fallback_storage:
            return 0

        sorted_set = self._fallback_storage[sorted_set_key]
        # Handle '-inf' and '+inf'
        if min_score == '-inf':
            min_score = float('-inf')
        if max_score == '+inf':
            max_score = float('inf')

        return sum(1 for s, m in sorted_set if min_score <= s <= max_score)

    def zcard(self, name: str) -> int:
        """Get cardinality (number of members) of sorted set"""
        if self._available:
            try:
                return self._client.zcard(name)
            except RedisError as e:
                logger.error(f"Redis ZCARD error: {e}")
                if not self.enable_fallback:
                    raise

        # Fallback
        sorted_set_key = f"zset:{name}"
        if sorted_set_key not in self._fallback_storage:
            return 0

        return len(self._fallback_storage[sorted_set_key])

    def close(self):
        """Close Redis connection"""
        if self._pool:
            self._pool.disconnect()
            logger.info("Redis connection closed")

    def __del__(self):
        """Cleanup on deletion"""
        try:
            self.close()
        except Exception:
            # Silently ignore cleanup errors on deletion
            pass


# Global Redis instance (singleton pattern)
_redis_instance: Optional[RedisConnectionManager] = None


def get_redis() -> RedisConnectionManager:
    """Get global Redis instance"""
    global _redis_instance
    if _redis_instance is None:
        _redis_instance = RedisConnectionManager()
    return _redis_instance


def reset_redis():
    """Reset global Redis instance (for testing)"""
    global _redis_instance
    if _redis_instance:
        _redis_instance.close()
    _redis_instance = None
