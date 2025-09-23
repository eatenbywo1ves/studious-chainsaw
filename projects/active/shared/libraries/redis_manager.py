"""
Redis Manager for Caching and Pub/Sub
Provides centralized Redis functionality for caching, session management, and pub/sub messaging
"""

import json
import asyncio
import logging
from typing import Dict, Any, Optional, List, Callable, Union
from dataclasses import dataclass
from datetime import datetime
import redis.asyncio as redis
from contextlib import asynccontextmanager
import pickle


@dataclass
class CacheConfig:
    """Cache configuration"""

    host: str = "localhost"
    port: int = 6379
    db: int = 0
    password: Optional[str] = None
    default_ttl: int = 300  # 5 minutes
    max_connections: int = 10
    key_prefix: str = "mcp:"


@dataclass
class PubSubConfig:
    """Pub/Sub configuration"""

    host: str = "localhost"
    port: int = 6379
    db: int = 1
    password: Optional[str] = None
    max_connections: int = 20


class RedisConnectionPool:
    """Redis connection pool manager"""

    def __init__(self, config: Union[CacheConfig, PubSubConfig]):
        self.config = config
        self.pool: Optional[redis.ConnectionPool] = None
        self.client: Optional[redis.Redis] = None

    async def initialize(self):
        """Initialize Redis connection pool"""
        self.pool = redis.ConnectionPool(
            host=self.config.host,
            port=self.config.port,
            db=self.config.db,
            password=self.config.password,
            max_connections=self.config.max_connections,
            decode_responses=True,
        )
        self.client = redis.Redis(connection_pool=self.pool)

    async def close(self):
        """Close Redis connections"""
        if self.pool:
            await self.pool.disconnect()

    @asynccontextmanager
    async def get_client(self):
        """Get Redis client context manager"""
        if not self.client:
            await self.initialize()
        try:
            yield self.client
        except Exception as e:
            logging.error(f"Redis operation failed: {e}")
            raise


class CacheManager:
    """Redis-based caching manager"""

    def __init__(self, config: Optional[CacheConfig] = None):
        self.config = config or CacheConfig()
        self.pool = RedisConnectionPool(self.config)
        self.logger = self._setup_logging()
        self.serializers = {
            "json": (json.dumps, json.loads),
            "pickle": (pickle.dumps, pickle.loads),
            "str": (str, str),
        }

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("CacheManager")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "CacheManager", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _make_key(self, key: str) -> str:
        """Create prefixed cache key"""
        return f"{self.config.key_prefix}{key}"

    async def get(self, key: str, serializer: str = "json") -> Optional[Any]:
        """Get value from cache"""
        try:
            cache_key = self._make_key(key)
            async with self.pool.get_client() as client:
                value = await client.get(cache_key)

                if value is None:
                    self.logger.debug(f"Cache miss for key: {key}")
                    return None

                # Deserialize value
                _, deserialize = self.serializers.get(
                    serializer, self.serializers["json"]
                )

                if serializer == "pickle":
                    return pickle.loads(value.encode("latin1"))
                else:
                    return deserialize(value)

        except Exception as e:
            self.logger.error(f"Cache get failed for key {key}: {e}")
            return None

    async def set(
        self, key: str, value: Any, ttl: Optional[int] = None, serializer: str = "json"
    ) -> bool:
        """Set value in cache"""
        try:
            cache_key = self._make_key(key)
            cache_ttl = ttl or self.config.default_ttl

            # Serialize value
            serialize, _ = self.serializers.get(serializer, self.serializers["json"])

            if serializer == "pickle":
                serialized_value = pickle.dumps(value).decode("latin1")
            else:
                serialized_value = serialize(value)

            async with self.pool.get_client() as client:
                await client.setex(cache_key, cache_ttl, serialized_value)
                self.logger.debug(f"Cache set for key: {key}, ttl: {cache_ttl}")
                return True

        except Exception as e:
            self.logger.error(f"Cache set failed for key {key}: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            cache_key = self._make_key(key)
            async with self.pool.get_client() as client:
                result = await client.delete(cache_key)
                return result > 0

        except Exception as e:
            self.logger.error(f"Cache delete failed for key {key}: {e}")
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        try:
            cache_key = self._make_key(key)
            async with self.pool.get_client() as client:
                return await client.exists(cache_key) > 0

        except Exception as e:
            self.logger.error(f"Cache exists check failed for key {key}: {e}")
            return False

    async def increment(self, key: str, amount: int = 1) -> Optional[int]:
        """Increment counter in cache"""
        try:
            cache_key = self._make_key(key)
            async with self.pool.get_client() as client:
                return await client.incrby(cache_key, amount)

        except Exception as e:
            self.logger.error(f"Cache increment failed for key {key}: {e}")
            return None

    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for existing key"""
        try:
            cache_key = self._make_key(key)
            async with self.pool.get_client() as client:
                return await client.expire(cache_key, ttl)

        except Exception as e:
            self.logger.error(f"Cache expire failed for key {key}: {e}")
            return False

    async def get_pattern(self, pattern: str) -> List[str]:
        """Get keys matching pattern"""
        try:
            cache_pattern = self._make_key(pattern)
            async with self.pool.get_client() as client:
                keys = await client.keys(cache_pattern)
                # Remove prefix from keys
                prefix_len = len(self.config.key_prefix)
                return [key[prefix_len:] for key in keys]

        except Exception as e:
            self.logger.error(f"Cache pattern search failed for {pattern}: {e}")
            return []

    async def flush_all(self) -> bool:
        """Clear all cache entries"""
        try:
            async with self.pool.get_client() as client:
                await client.flushdb()
                self.logger.info("Cache flushed successfully")
                return True

        except Exception as e:
            self.logger.error(f"Cache flush failed: {e}")
            return False


class PubSubManager:
    """Redis-based pub/sub messaging"""

    def __init__(self, config: Optional[PubSubConfig] = None):
        self.config = config or PubSubConfig()
        self.pool = RedisConnectionPool(self.config)
        self.logger = self._setup_logging()
        self.subscribers: Dict[str, List[Callable]] = {}
        self.running = False
        self.tasks: List[asyncio.Task] = []

    def _setup_logging(self) -> logging.Logger:
        """Setup structured logging"""
        logger = logging.getLogger("PubSubManager")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "component": "PubSubManager", '
                '"level": "%(levelname)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def publish(
        self, channel: str, message: Any, serializer: str = "json"
    ) -> int:
        """Publish message to channel"""
        try:
            # Serialize message
            if serializer == "json":
                serialized_message = json.dumps(
                    {
                        "data": message,
                        "timestamp": datetime.now().isoformat(),
                        "serializer": serializer,
                    }
                )
            else:
                serialized_message = str(message)

            async with self.pool.get_client() as client:
                subscribers = await client.publish(channel, serialized_message)
                self.logger.debug(f"Published to {channel}, {subscribers} subscribers")
                return subscribers

        except Exception as e:
            self.logger.error(f"Publish failed for channel {channel}: {e}")
            return 0

    def subscribe(self, channel: str, callback: Callable[[str, Any], None]):
        """Subscribe to channel with callback"""
        if channel not in self.subscribers:
            self.subscribers[channel] = []
        self.subscribers[channel].append(callback)
        self.logger.info(f"Subscribed to channel: {channel}")

    def unsubscribe(self, channel: str, callback: Optional[Callable] = None):
        """Unsubscribe from channel"""
        if channel in self.subscribers:
            if callback:
                self.subscribers[channel] = [
                    cb for cb in self.subscribers[channel] if cb != callback
                ]
            else:
                del self.subscribers[channel]
        self.logger.info(f"Unsubscribed from channel: {channel}")

    async def start_listening(self):
        """Start listening for messages"""
        self.running = True
        self.logger.info("Starting pub/sub listener")

        async with self.pool.get_client() as client:
            pubsub = client.pubsub()

            # Subscribe to all channels
            for channel in self.subscribers.keys():
                await pubsub.subscribe(channel)

            # Listen for messages
            async for message in pubsub.listen():
                if not self.running:
                    break

                if message["type"] == "message":
                    await self._handle_message(message)

    async def _handle_message(self, message: Dict[str, Any]):
        """Handle incoming message"""
        try:
            channel = message["channel"]
            data = message["data"]

            # Deserialize message
            try:
                parsed_data = json.loads(data)
                payload = parsed_data.get("data")
                parsed_data.get("timestamp")
            except json.JSONDecodeError:
                payload = data
                datetime.now().isoformat()

            # Call all subscribers for this channel
            for callback in self.subscribers.get(channel, []):
                try:
                    await asyncio.create_task(
                        self._run_callback(callback, channel, payload)
                    )
                except Exception as e:
                    self.logger.error(f"Callback error for {channel}: {e}")

        except Exception as e:
            self.logger.error(f"Message handling error: {e}")

    async def _run_callback(self, callback: Callable, channel: str, payload: Any):
        """Run callback function safely"""
        if asyncio.iscoroutinefunction(callback):
            await callback(channel, payload)
        else:
            callback(channel, payload)

    async def stop_listening(self):
        """Stop listening for messages"""
        self.running = False
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.logger.info("Stopped pub/sub listener")


class SessionManager:
    """Redis-based session management"""

    def __init__(self, cache_manager: CacheManager):
        self.cache = cache_manager
        self.session_prefix = "session:"
        self.default_ttl = 3600  # 1 hour

    async def create_session(
        self, session_id: str, data: Dict[str, Any], ttl: Optional[int] = None
    ) -> bool:
        """Create new session"""
        session_key = f"{self.session_prefix}{session_id}"
        return await self.cache.set(session_key, data, ttl=ttl or self.default_ttl)

    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        session_key = f"{self.session_prefix}{session_id}"
        return await self.cache.get(session_key)

    async def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data"""
        session_key = f"{self.session_prefix}{session_id}"
        existing = await self.get_session(session_id)
        if existing:
            existing.update(data)
            return await self.cache.set(session_key, existing)
        return False

    async def delete_session(self, session_id: str) -> bool:
        """Delete session"""
        session_key = f"{self.session_prefix}{session_id}"
        return await self.cache.delete(session_key)

    async def extend_session(self, session_id: str, ttl: int) -> bool:
        """Extend session TTL"""
        session_key = f"{self.session_prefix}{session_id}"
        return await self.cache.expire(session_key, ttl)


# Singleton instances
_cache_manager_instance: Optional[CacheManager] = None
_pubsub_manager_instance: Optional[PubSubManager] = None


def get_cache_manager() -> CacheManager:
    """Get singleton cache manager instance"""
    global _cache_manager_instance
    if _cache_manager_instance is None:
        _cache_manager_instance = CacheManager()
    return _cache_manager_instance


def get_pubsub_manager() -> PubSubManager:
    """Get singleton pub/sub manager instance"""
    global _pubsub_manager_instance
    if _pubsub_manager_instance is None:
        _pubsub_manager_instance = PubSubManager()
    return _pubsub_manager_instance


# Convenience functions
async def cache_get(key: str, **kwargs) -> Optional[Any]:
    """Get value from cache"""
    return await get_cache_manager().get(key, **kwargs)


async def cache_set(key: str, value: Any, **kwargs) -> bool:
    """Set value in cache"""
    return await get_cache_manager().set(key, value, **kwargs)


async def publish(channel: str, message: Any, **kwargs) -> int:
    """Publish message to channel"""
    return await get_pubsub_manager().publish(channel, message, **kwargs)


def subscribe(channel: str, callback: Callable):
    """Subscribe to channel"""
    return get_pubsub_manager().subscribe(channel, callback)
