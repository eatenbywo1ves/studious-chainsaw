"""
Advanced Rate Limiting with Redis-backed Distributed State
FIXES CRITICAL SECURITY ISSUE: Distributed rate limiting for production
"""

import time
import hashlib
import asyncio
from typing import Dict, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import logging
import redis.asyncio as redis

logger = logging.getLogger(__name__)


class LimitType(Enum):
    PER_IP = "per_ip"
    PER_USER = "per_user"
    PER_ENDPOINT = "per_endpoint"
    GLOBAL = "global"


class RateLimitStrategy(Enum):
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"


@dataclass
class RateLimit:
    requests: int
    window_seconds: int
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    burst_allowance: int = 0
    description: str = ""


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_time: float
    retry_after: Optional[int] = None
    limit_type: Optional[LimitType] = None


class AdvancedRateLimiter:
    """
    Advanced Rate Limiting with Redis-backed Distributed State

    D3FEND Techniques Implemented:
    - D3-RAC (Resource Access Control)
    - D3-AET (Authentication Event Thresholding)
    """

    def __init__(
        self,
        redis_client: redis.Redis,  # ✅ REQUIRED: Redis for distributed state
        enable_ddos_protection: bool = True,
        suspicious_threshold: int = 1000,
        block_duration_minutes: int = 60,
    ):
        self.redis_client = redis_client  # ✅ Use Redis for all state
        self.enable_ddos_protection = enable_ddos_protection
        self.suspicious_threshold = suspicious_threshold
        self.block_duration_minutes = block_duration_minutes

        # ✅ FIXED: All state now in Redis (distributed, persistent)
        # No more in-memory dictionaries!

        # Rate limit configurations
        self.rate_limits: Dict[str, Dict[LimitType, RateLimit]] = {
            # API endpoints
            "/api/auth/login": {
                LimitType.PER_IP: RateLimit(
                    5, 300, RateLimitStrategy.SLIDING_WINDOW, description="Login attempts per IP"
                ),
                LimitType.PER_USER: RateLimit(
                    3, 300, RateLimitStrategy.SLIDING_WINDOW, description="Login attempts per user"
                ),
            },
            "/api/auth/register": {
                LimitType.PER_IP: RateLimit(
                    3,
                    3600,
                    RateLimitStrategy.FIXED_WINDOW,
                    description="Registrations per IP per hour",
                )
            },
            "/api/auth/forgot-password": {
                LimitType.PER_IP: RateLimit(
                    3, 3600, RateLimitStrategy.SLIDING_WINDOW, description="Password reset per IP"
                ),
                LimitType.PER_USER: RateLimit(
                    2, 3600, RateLimitStrategy.SLIDING_WINDOW, description="Password reset per user"
                ),
            },
            "/api/catalytic/compute": {
                LimitType.PER_USER: RateLimit(
                    100,
                    3600,
                    RateLimitStrategy.TOKEN_BUCKET,
                    burst_allowance=20,
                    description="Compute requests per user per hour",
                ),
                LimitType.GLOBAL: RateLimit(
                    10000, 3600, RateLimitStrategy.TOKEN_BUCKET, description="Global compute limit"
                ),
            },
            "/api/stripe/webhooks": {
                LimitType.PER_IP: RateLimit(
                    1000, 3600, RateLimitStrategy.SLIDING_WINDOW, description="Webhook calls per IP"
                )
            },
            "default": {
                LimitType.PER_IP: RateLimit(
                    1000,
                    3600,
                    RateLimitStrategy.TOKEN_BUCKET,
                    burst_allowance=100,
                    description="Default per IP",
                ),
                LimitType.PER_USER: RateLimit(
                    5000,
                    3600,
                    RateLimitStrategy.TOKEN_BUCKET,
                    burst_allowance=500,
                    description="Default per user",
                ),
            },
        }

        logger.info("Advanced rate limiter initialized with Redis backend")

    async def check_rate_limit(
        self,
        identifier: str,
        endpoint: str,
        limit_type: LimitType,
        ip_address: Optional[str] = None,
    ) -> RateLimitResult:
        """
        Check if request is within rate limits

        ✅ FIXED: Uses Redis for distributed rate limiting
        """
        # Check if IP is blocked due to DDoS protection (Redis-backed)
        if ip_address and await self._is_ip_blocked(ip_address):
            blocked_until = await self.redis_client.get(f"blocked:ip:{ip_address}")
            blocked_until_time = float(blocked_until) if blocked_until else time.time()

            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=blocked_until_time,
                retry_after=int(blocked_until_time - time.time()),
                limit_type=limit_type,
            )

        # Get rate limit configuration
        rate_limit = self._get_rate_limit(endpoint, limit_type)
        if not rate_limit:
            return RateLimitResult(allowed=True, remaining=1000, reset_time=time.time() + 3600)

        # Apply rate limiting based on strategy (all using Redis)
        if rate_limit.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return await self._check_token_bucket_redis(identifier, rate_limit)
        elif rate_limit.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return await self._check_sliding_window_redis(identifier, rate_limit)
        elif rate_limit.strategy == RateLimitStrategy.FIXED_WINDOW:
            return await self._check_fixed_window_redis(identifier, rate_limit)
        else:
            return RateLimitResult(allowed=True, remaining=1000, reset_time=time.time() + 3600)

    def _get_rate_limit(self, endpoint: str, limit_type: LimitType) -> Optional[RateLimit]:
        """Get rate limit configuration for endpoint and type"""
        if endpoint in self.rate_limits and limit_type in self.rate_limits[endpoint]:
            return self.rate_limits[endpoint][limit_type]
        elif "default" in self.rate_limits and limit_type in self.rate_limits["default"]:
            return self.rate_limits["default"][limit_type]
        return None

    async def _check_token_bucket_redis(
        self, identifier: str, rate_limit: RateLimit
    ) -> RateLimitResult:
        """
        Token bucket algorithm using Redis

        ✅ FIXED: Distributed token bucket with Redis atomic operations
        """
        key = f"ratelimit:bucket:{identifier}"
        now = time.time()

        try:
            # Use Redis Lua script for atomic token bucket operation
            lua_script = """
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refill_rate = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local window_seconds = tonumber(ARGV[4])

            local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
            local tokens = tonumber(bucket[1]) or capacity
            local last_refill = tonumber(bucket[2]) or now

            -- Refill tokens based on elapsed time
            local elapsed = now - last_refill
            local new_tokens = math.min(capacity, tokens + (elapsed * refill_rate))

            -- Try to consume 1 token
            if new_tokens >= 1 then
                new_tokens = new_tokens - 1
                redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
                redis.call('EXPIRE', key, window_seconds)
                return {1, math.floor(new_tokens)}  -- allowed, remaining
            else
                redis.call('HMSET', key, 'tokens', new_tokens, 'last_refill', now)
                redis.call('EXPIRE', key, window_seconds)
                return {0, 0}  -- not allowed, 0 remaining
            end
            """

            capacity = rate_limit.requests + rate_limit.burst_allowance
            refill_rate = rate_limit.requests / rate_limit.window_seconds

            result = await self.redis_client.eval(
                lua_script, 1, key, capacity, refill_rate, now, rate_limit.window_seconds
            )

            allowed = bool(result[0])
            remaining = int(result[1])

            reset_time = now + rate_limit.window_seconds

            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                retry_after=None if allowed else int((1 / refill_rate) if refill_rate > 0 else 60),
                limit_type=LimitType.PER_USER,
            )

        except Exception as e:
            logger.error(f"Token bucket error: {e}")
            # Fail open (allow request) on Redis error
            return RateLimitResult(allowed=True, remaining=100, reset_time=now + 3600)

    async def _check_sliding_window_redis(
        self, identifier: str, rate_limit: RateLimit
    ) -> RateLimitResult:
        """
        Sliding window algorithm using Redis sorted sets

        ✅ FIXED: Distributed sliding window with Redis
        """
        key = f"ratelimit:window:{identifier}"
        now = time.time()
        window_start = now - rate_limit.window_seconds

        try:
            pipe = self.redis_client.pipeline()

            # Remove old entries outside the window
            pipe.zremrangebyscore(key, 0, window_start)

            # Add current request with timestamp as score
            request_id = f"{now}:{hashlib.md5(str(now).encode()).hexdigest()[:8]}"
            pipe.zadd(key, {request_id: now})

            # Count requests in window
            pipe.zcard(key)

            # Set expiry
            pipe.expire(key, rate_limit.window_seconds)

            results = await pipe.execute()
            request_count = results[2]  # zcard result

            allowed = request_count <= rate_limit.requests
            remaining = max(0, rate_limit.requests - request_count)

            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=now + rate_limit.window_seconds,
                retry_after=None if allowed else int(rate_limit.window_seconds),
                limit_type=LimitType.PER_IP,
            )

        except Exception as e:
            logger.error(f"Sliding window error: {e}")
            return RateLimitResult(
                allowed=True, remaining=100, reset_time=now + rate_limit.window_seconds
            )

    async def _check_fixed_window_redis(
        self, identifier: str, rate_limit: RateLimit
    ) -> RateLimitResult:
        """
        Fixed window algorithm using Redis

        ✅ FIXED: Distributed fixed window with Redis
        """
        now = time.time()
        window_id = int(now / rate_limit.window_seconds)
        key = f"ratelimit:fixed:{identifier}:{window_id}"

        try:
            # Increment counter atomically
            current = await self.redis_client.incr(key)

            # Set expiry on first request in window
            if current == 1:
                await self.redis_client.expire(key, rate_limit.window_seconds)

            allowed = current <= rate_limit.requests
            remaining = max(0, rate_limit.requests - current)

            window_end = (window_id + 1) * rate_limit.window_seconds

            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=window_end,
                retry_after=None if allowed else int(window_end - now),
                limit_type=LimitType.PER_IP,
            )

        except Exception as e:
            logger.error(f"Fixed window error: {e}")
            return RateLimitResult(
                allowed=True, remaining=100, reset_time=now + rate_limit.window_seconds
            )

    async def _is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if IP is blocked (DDoS protection)

        ✅ FIXED: Uses Redis for distributed IP blocking
        """
        try:
            blocked = await self.redis_client.exists(f"blocked:ip:{ip_address}")
            return bool(blocked)
        except Exception as e:
            logger.error(f"Error checking IP block: {e}")
            return False

    async def block_ip(self, ip_address: str, duration_minutes: Optional[int] = None) -> bool:
        """
        Block an IP address

        ✅ Uses Redis for distributed IP blocking
        """
        try:
            duration = duration_minutes or self.block_duration_minutes
            blocked_until = time.time() + (duration * 60)

            await self.redis_client.setex(f"blocked:ip:{ip_address}", duration * 60, blocked_until)

            logger.warning(f"IP {ip_address} blocked for {duration} minutes")
            return True

        except Exception as e:
            logger.error(f"Error blocking IP: {e}")
            return False

    async def record_suspicious_activity(self, ip_address: str) -> int:
        """
        Record suspicious activity for DDoS detection

        ✅ Uses Redis for distributed DDoS detection
        """
        if not self.enable_ddos_protection:
            return 0

        try:
            key = f"suspicious:ip:{ip_address}"

            # Add timestamp to sorted set
            pipe = self.redis_client.pipeline()
            pipe.zadd(key, {str(time.time()): time.time()})
            pipe.zremrangebyscore(key, 0, time.time() - 60)  # Keep last minute
            pipe.zcard(key)
            pipe.expire(key, 300)  # 5 minute expiry

            results = await pipe.execute()
            count = results[2]

            # Block if exceeds threshold
            if count > self.suspicious_threshold:
                await self.block_ip(ip_address, self.block_duration_minutes)
                logger.critical(f"DDoS detected from {ip_address}: {count} requests/min")

            return count

        except Exception as e:
            logger.error(f"Error recording suspicious activity: {e}")
            return 0

    async def get_rate_limit_stats(self, identifier: str) -> Dict[str, any]:
        """Get current rate limit statistics for an identifier"""
        try:
            stats = {}

            # Check all rate limit keys for this identifier
            pattern = f"ratelimit:*:{identifier}*"
            keys = []
            async for key in self.redis_client.scan_iter(match=pattern):
                keys.append(key)

            for key in keys:
                key_str = key.decode() if isinstance(key, bytes) else key
                key_type = await self.redis_client.type(key)

                if key_type == b"zset":
                    count = await self.redis_client.zcard(key)
                    stats[key_str] = {"type": "sliding_window", "count": count}
                elif key_type == b"string":
                    count = await self.redis_client.get(key)
                    stats[key_str] = {"type": "fixed_window", "count": int(count) if count else 0}
                elif key_type == b"hash":
                    data = await self.redis_client.hgetall(key)
                    stats[key_str] = {"type": "token_bucket", "data": data}

            return stats

        except Exception as e:
            logger.error(f"Error getting rate limit stats: {e}")
            return {}

    async def reset_rate_limit(self, identifier: str) -> bool:
        """Reset rate limits for an identifier"""
        try:
            pattern = f"ratelimit:*:{identifier}*"
            deleted = 0

            async for key in self.redis_client.scan_iter(match=pattern):
                await self.redis_client.delete(key)
                deleted += 1

            logger.info(f"Reset {deleted} rate limit keys for {identifier}")
            return True

        except Exception as e:
            logger.error(f"Error resetting rate limits: {e}")
            return False


# Example usage with Redis
async def example_usage():
    """Example: Using Rate Limiter with Redis"""
    import redis.asyncio as redis

    # Initialize Redis connection
    redis_client = await redis.from_url("redis://localhost:6379")

    # Initialize rate limiter with Redis
    limiter = AdvancedRateLimiter(
        redis_client=redis_client,  # ✅ Pass Redis client
        enable_ddos_protection=True,
    )

    # Check rate limit
    result = await limiter.check_rate_limit(
        identifier="user_12345", endpoint="/api/catalytic/compute", limit_type=LimitType.PER_USER
    )

    print(f"Request allowed: {result.allowed}")
    print(f"Remaining: {result.remaining}")
    print(f"Reset time: {datetime.fromtimestamp(result.reset_time)}")

    # Simulate multiple requests to test limits
    for i in range(105):
        result = await limiter.check_rate_limit(
            identifier="user_12345",
            endpoint="/api/catalytic/compute",
            limit_type=LimitType.PER_USER,
        )
        if not result.allowed:
            print(f"✅ Rate limit enforced after {i} requests")
            break

    # Clean up
    await redis_client.close()


if __name__ == "__main__":
    import asyncio

    asyncio.run(example_usage())
