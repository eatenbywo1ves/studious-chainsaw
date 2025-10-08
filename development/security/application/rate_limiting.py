"""
Advanced Rate Limiting and DDoS Protection
Implements multiple rate limiting strategies and DDoS protection mechanisms
"""

import time
import hashlib
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import logging
import ipaddress
from datetime import datetime

# Import Redis manager for distributed rate limiting
try:
    from .redis_manager import RedisConnectionManager, get_redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

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

@dataclass
class TokenBucket:
    capacity: int
    tokens: float
    last_refill: float
    refill_rate: float  # tokens per second

@dataclass
class SlidingWindow:
    requests: deque = field(default_factory=deque)
    window_seconds: int = 60

class AdvancedRateLimiter:
    """
    Advanced rate limiting with multiple strategies and DDoS protection
    """

    def __init__(
        self,
        redis_client: Optional['RedisConnectionManager'] = None,
        enable_ddos_protection: bool = True,
        suspicious_threshold: int = 1000,  # requests per minute
        block_duration_minutes: int = 60
    ):
        # Initialize Redis for distributed rate limiting
        if REDIS_AVAILABLE:
            self.redis_client = redis_client or get_redis()
            self.use_redis = self.redis_client.is_available
            if self.use_redis:
                logger.info("Using Redis for distributed rate limiting")
            else:
                logger.warning("Redis unavailable, using in-memory rate limiting (NOT for production!)")
        else:
            self.redis_client = None
            self.use_redis = False
            logger.warning("Redis module not available, using in-memory rate limiting (NOT for production!)")

        self.enable_ddos_protection = enable_ddos_protection
        self.suspicious_threshold = suspicious_threshold
        self.block_duration_minutes = block_duration_minutes

        # Fallback: In-memory storage (only used if Redis unavailable)
        self.token_buckets: Dict[str, TokenBucket] = {}
        self.sliding_windows: Dict[str, SlidingWindow] = {}
        self.fixed_windows: Dict[str, Dict[int, int]] = defaultdict(dict)
        self.blocked_ips: Dict[str, float] = {}
        self.suspicious_ips: Dict[str, List[float]] = defaultdict(list)

        # Rate limit configurations
        self.rate_limits: Dict[str, Dict[LimitType, RateLimit]] = {
            # API endpoints
            "/api/auth/login": {
                LimitType.PER_IP: RateLimit(5, 300, RateLimitStrategy.SLIDING_WINDOW, description="Login attempts per IP"),
                LimitType.PER_USER: RateLimit(3, 300, RateLimitStrategy.SLIDING_WINDOW, description="Login attempts per user")
            },
            "/api/auth/register": {
                LimitType.PER_IP: RateLimit(3, 3600, RateLimitStrategy.FIXED_WINDOW, description="Registrations per IP per hour")
            },
            "/api/auth/forgot-password": {
                LimitType.PER_IP: RateLimit(3, 3600, RateLimitStrategy.SLIDING_WINDOW, description="Password reset per IP"),
                LimitType.PER_USER: RateLimit(2, 3600, RateLimitStrategy.SLIDING_WINDOW, description="Password reset per user")
            },
            "/api/catalytic/compute": {
                LimitType.PER_USER: RateLimit(100, 3600, RateLimitStrategy.TOKEN_BUCKET, burst_allowance=20, description="Compute requests per user per hour"),
                LimitType.GLOBAL: RateLimit(10000, 3600, RateLimitStrategy.TOKEN_BUCKET, description="Global compute limit")
            },
            "/api/stripe/webhooks": {
                LimitType.PER_IP: RateLimit(1000, 3600, RateLimitStrategy.SLIDING_WINDOW, description="Webhook calls per IP")
            },
            # Default limits
            "default": {
                LimitType.PER_IP: RateLimit(1000, 3600, RateLimitStrategy.TOKEN_BUCKET, burst_allowance=100, description="Default per IP"),
                LimitType.PER_USER: RateLimit(5000, 3600, RateLimitStrategy.TOKEN_BUCKET, burst_allowance=500, description="Default per user")
            }
        }

        logger.info("Advanced rate limiter initialized")

    def set_rate_limit(self, endpoint: str, limit_type: LimitType, rate_limit: RateLimit):
        """
        Dynamically set or override rate limit for an endpoint (useful for testing)
        """
        if endpoint not in self.rate_limits:
            self.rate_limits[endpoint] = {}
        self.rate_limits[endpoint][limit_type] = rate_limit
        logger.debug(f"Set rate limit for {endpoint} ({limit_type.value}): {rate_limit.requests}/{rate_limit.window_seconds}s")

    async def check_rate_limit(
        self,
        identifier: str,
        endpoint: str,
        limit_type: LimitType,
        ip_address: Optional[str] = None
    ) -> RateLimitResult:
        """
        Check if request is within rate limits
        """
        # Check if IP is blocked due to DDoS protection
        if ip_address and self._is_ip_blocked(ip_address):
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=self.blocked_ips[ip_address],
                retry_after=int(self.blocked_ips[ip_address] - time.time()),
                limit_type=limit_type
            )

        # Get rate limit configuration
        rate_limit = self._get_rate_limit(endpoint, limit_type)
        if not rate_limit:
            return RateLimitResult(allowed=True, remaining=1000, reset_time=time.time() + 3600)

        # Apply rate limiting based on strategy
        if rate_limit.strategy == RateLimitStrategy.TOKEN_BUCKET:
            return await self._check_token_bucket(identifier, rate_limit)
        elif rate_limit.strategy == RateLimitStrategy.SLIDING_WINDOW:
            return await self._check_sliding_window(identifier, rate_limit)
        elif rate_limit.strategy == RateLimitStrategy.FIXED_WINDOW:
            return await self._check_fixed_window(identifier, rate_limit)
        else:
            return RateLimitResult(allowed=True, remaining=1000, reset_time=time.time() + 3600)

    def _get_rate_limit(self, endpoint: str, limit_type: LimitType) -> Optional[RateLimit]:
        """
        Get rate limit configuration for endpoint and type
        """
        if endpoint in self.rate_limits and limit_type in self.rate_limits[endpoint]:
            return self.rate_limits[endpoint][limit_type]
        elif limit_type in self.rate_limits["default"]:
            return self.rate_limits["default"][limit_type]
        return None

    async def _check_token_bucket(self, identifier: str, rate_limit: RateLimit) -> RateLimitResult:
        """
        Token bucket algorithm implementation (distributed with Redis)
        """
        now = time.time()

        if self.use_redis:
            # Use Redis hash for atomic token bucket operations
            key = f"ratelimit:bucket:{identifier}"
            capacity = rate_limit.requests + rate_limit.burst_allowance
            refill_rate = rate_limit.requests / rate_limit.window_seconds

            # Get current bucket state from Redis
            bucket_data = self.redis_client.hgetall(key)

            if bucket_data:
                tokens = float(bucket_data.get('tokens', capacity))
                last_refill = float(bucket_data.get('last_refill', now))
            else:
                # Initialize new bucket
                tokens = float(capacity)
                last_refill = now

            # Refill tokens
            time_passed = now - last_refill
            tokens = min(capacity, tokens + (time_passed * refill_rate))

            # Check if request can be processed
            if tokens >= 1.0:
                tokens -= 1.0
                # Update Redis atomically
                self.redis_client.hset(key, 'tokens', str(tokens))
                self.redis_client.hset(key, 'last_refill', str(now))
                self.redis_client.expire(key, rate_limit.window_seconds * 2)  # Auto-cleanup

                remaining = int(tokens)
                reset_time = now + ((capacity - tokens) / refill_rate)
                return RateLimitResult(allowed=True, remaining=remaining, reset_time=reset_time)
            else:
                # Update last_refill even on failure
                self.redis_client.hset(key, 'tokens', str(tokens))
                self.redis_client.hset(key, 'last_refill', str(now))
                self.redis_client.expire(key, rate_limit.window_seconds * 2)

                retry_after = int((1.0 - tokens) / refill_rate)
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=now + retry_after,
                    retry_after=retry_after
                )
        else:
            # Fallback to in-memory implementation
            # Get or create bucket
            if identifier not in self.token_buckets:
                self.token_buckets[identifier] = TokenBucket(
                    capacity=rate_limit.requests + rate_limit.burst_allowance,
                    tokens=float(rate_limit.requests + rate_limit.burst_allowance),
                    last_refill=now,
                    refill_rate=rate_limit.requests / rate_limit.window_seconds
                )

            bucket = self.token_buckets[identifier]

            # Refill tokens
            time_passed = now - bucket.last_refill
            bucket.tokens = min(
                bucket.capacity,
                bucket.tokens + (time_passed * bucket.refill_rate)
            )
            bucket.last_refill = now

            # Check if request can be processed
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                remaining = int(bucket.tokens)
                reset_time = now + ((bucket.capacity - bucket.tokens) / bucket.refill_rate)
                return RateLimitResult(allowed=True, remaining=remaining, reset_time=reset_time)
            else:
                retry_after = int((1.0 - bucket.tokens) / bucket.refill_rate)
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=now + retry_after,
                    retry_after=retry_after
                )

    async def _check_sliding_window(self, identifier: str, rate_limit: RateLimit) -> RateLimitResult:
        """
        Sliding window algorithm implementation (distributed with Redis sorted sets)
        """
        now = time.time()
        window_start = now - rate_limit.window_seconds

        if self.use_redis:
            # Use Redis sorted set for time-windowed counting
            key = f"ratelimit:window:{identifier}"

            # Remove old requests outside the window
            self.redis_client.zremrangebyscore(key, '-inf', window_start)

            # Count requests in current window
            current_count = self.redis_client.zcard(key)

            # Check if within limit
            if current_count < rate_limit.requests:
                # Add current request with timestamp as score and unique member
                member = f"{now}:{hashlib.md5(str(now).encode()).hexdigest()}"
                self.redis_client.zadd(key, {member: now})
                self.redis_client.expire(key, rate_limit.window_seconds * 2)  # Auto-cleanup

                remaining = rate_limit.requests - current_count - 1

                # Get oldest request for reset time
                oldest = self.redis_client.zrange(key, 0, 0, withscores=True)
                reset_time = oldest[0][1] + rate_limit.window_seconds if oldest else now

                return RateLimitResult(allowed=True, remaining=remaining, reset_time=reset_time)
            else:
                # Get oldest request
                oldest = self.redis_client.zrange(key, 0, 0, withscores=True)
                if oldest:
                    oldest_time = oldest[0][1]
                    retry_after = int(oldest_time + rate_limit.window_seconds - now)
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=oldest_time + rate_limit.window_seconds,
                        retry_after=retry_after
                    )
                else:
                    # No oldest request found (shouldn't happen but handle gracefully)
                    return RateLimitResult(
                        allowed=False,
                        remaining=0,
                        reset_time=now + rate_limit.window_seconds,
                        retry_after=rate_limit.window_seconds
                    )
        else:
            # Fallback to in-memory implementation
            # Get or create window
            if identifier not in self.sliding_windows:
                self.sliding_windows[identifier] = SlidingWindow(
                    requests=deque(),
                    window_seconds=rate_limit.window_seconds
                )

            window = self.sliding_windows[identifier]

            # Remove old requests
            while window.requests and window.requests[0] < window_start:
                window.requests.popleft()

            # Check if within limit
            if len(window.requests) < rate_limit.requests:
                window.requests.append(now)
                remaining = rate_limit.requests - len(window.requests)
                reset_time = window.requests[0] + rate_limit.window_seconds if window.requests else now
                return RateLimitResult(allowed=True, remaining=remaining, reset_time=reset_time)
            else:
                oldest_request = window.requests[0]
                retry_after = int(oldest_request + rate_limit.window_seconds - now)
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    reset_time=oldest_request + rate_limit.window_seconds,
                    retry_after=retry_after
                )

    async def _check_fixed_window(self, identifier: str, rate_limit: RateLimit) -> RateLimitResult:
        """
        Fixed window algorithm implementation
        """
        now = time.time()
        window_start = int(now // rate_limit.window_seconds) * rate_limit.window_seconds

        # Get current count for this window
        if identifier not in self.fixed_windows:
            self.fixed_windows[identifier] = {}

        current_count = self.fixed_windows[identifier].get(window_start, 0)

        if current_count < rate_limit.requests:
            self.fixed_windows[identifier][window_start] = current_count + 1
            remaining = rate_limit.requests - current_count - 1
            reset_time = window_start + rate_limit.window_seconds
            return RateLimitResult(allowed=True, remaining=remaining, reset_time=reset_time)
        else:
            reset_time = window_start + rate_limit.window_seconds
            retry_after = int(reset_time - now)
            return RateLimitResult(
                allowed=False,
                remaining=0,
                reset_time=reset_time,
                retry_after=retry_after
            )

    def _is_ip_blocked(self, ip_address: str) -> bool:
        """
        Check if IP address is currently blocked
        """
        if ip_address in self.blocked_ips:
            if time.time() < self.blocked_ips[ip_address]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[ip_address]
        return False

    async def check_ddos_protection(self, ip_address: str) -> bool:
        """
        Check for potential DDoS attacks and block suspicious IPs (distributed with Redis)
        """
        if not self.enable_ddos_protection:
            return True

        now = time.time()
        minute_ago = now - 60

        if self.use_redis:
            # Use Redis sorted set for time-windowed request counting
            requests_key = f"ddos:requests:{ip_address}"
            block_key = f"ddos:blocked:{ip_address}"

            # Check if IP is already blocked
            if self.redis_client.exists(block_key):
                block_until = float(self.redis_client.get(block_key))
                logger.warning(f"IP {ip_address} is blocked until {datetime.fromtimestamp(block_until)}")
                return False

            # Remove old requests outside the 1-minute window
            self.redis_client.zremrangebyscore(requests_key, '-inf', minute_ago)

            # Add current request with timestamp as score and unique member
            member = f"{now}:{hashlib.md5(str(now).encode()).hexdigest()}"
            self.redis_client.zadd(requests_key, {member: now})

            # Count requests in the last minute
            request_count = self.redis_client.zcard(requests_key)

            # Set TTL to auto-cleanup
            self.redis_client.expire(requests_key, 120)  # 2 minutes

            # Check if over threshold
            if request_count > self.suspicious_threshold:
                # Block the IP
                block_until = now + (self.block_duration_minutes * 60)
                self.redis_client.setex(block_key, self.block_duration_minutes * 60, str(block_until))

                logger.warning(f"IP {ip_address} blocked for DDoS protection until {datetime.fromtimestamp(block_until)} ({request_count} requests/min)")
                return False

            return True
        else:
            # Fallback to in-memory implementation
            # Clean old entries
            if ip_address in self.suspicious_ips:
                self.suspicious_ips[ip_address] = [
                    timestamp for timestamp in self.suspicious_ips[ip_address]
                    if timestamp > minute_ago
                ]

            # Add current request
            self.suspicious_ips[ip_address].append(now)

            # Check if over threshold
            if len(self.suspicious_ips[ip_address]) > self.suspicious_threshold:
                # Block the IP
                block_until = now + (self.block_duration_minutes * 60)
                self.blocked_ips[ip_address] = block_until

                logger.warning(f"IP {ip_address} blocked for DDoS protection until {datetime.fromtimestamp(block_until)}")
                return False

            return True

    def is_trusted_ip(self, ip_address: str) -> bool:
        """
        Check if IP address is in trusted networks (whitelist)
        """
        trusted_networks = [
            "127.0.0.0/8",      # Localhost
            "10.0.0.0/8",       # Private network
            "172.16.0.0/12",    # Private network
            "192.168.0.0/16",   # Private network
            # Add your trusted networks here
        ]

        try:
            ip = ipaddress.ip_address(ip_address)
            for network in trusted_networks:
                if ip in ipaddress.ip_network(network):
                    return True
        except ValueError:
            pass

        return False

    async def record_request(self, ip_address: str, endpoint: str, user_id: Optional[str] = None):
        """
        Record request for analytics and monitoring
        """
        # In production, send to monitoring system
        logger.debug(f"Request recorded: IP={ip_address}, endpoint={endpoint}, user={user_id}")

    def get_rate_limit_headers(self, result: RateLimitResult, rate_limit: RateLimit) -> Dict[str, str]:
        """
        Generate rate limit headers for HTTP response
        """
        headers = {
            "X-RateLimit-Limit": str(rate_limit.requests),
            "X-RateLimit-Remaining": str(result.remaining),
            "X-RateLimit-Reset": str(int(result.reset_time)),
            "X-RateLimit-Window": str(rate_limit.window_seconds),
        }

        if result.retry_after:
            headers["Retry-After"] = str(result.retry_after)

        return headers

    async def cleanup_old_data(self):
        """
        Cleanup old rate limiting data to prevent memory leaks
        """
        now = time.time()

        # Clean up old sliding windows
        for identifier, window in list(self.sliding_windows.items()):
            window_start = now - window.window_seconds
            while window.requests and window.requests[0] < window_start:
                window.requests.popleft()

            # Remove empty windows
            if not window.requests:
                del self.sliding_windows[identifier]

        # Clean up old fixed windows
        for identifier, windows in list(self.fixed_windows.items()):
            self.fixed_windows[identifier] = {
                window_start: count
                for window_start, count in windows.items()
                if now - window_start < 3600  # Keep last hour
            }

            if not self.fixed_windows[identifier]:
                del self.fixed_windows[identifier]

        # Clean up expired blocks
        self.blocked_ips = {
            ip: block_time
            for ip, block_time in self.blocked_ips.items()
            if now < block_time
        }

        logger.debug("Rate limiter cleanup completed")

# FastAPI middleware integration
class RateLimitMiddleware:
    """
    FastAPI middleware for rate limiting
    """

    def __init__(self, rate_limiter: AdvancedRateLimiter):
        self.rate_limiter = rate_limiter

    async def __call__(self, request, call_next):
        # Extract client information
        ip_address = self._get_client_ip(request)
        endpoint = request.url.path
        user_id = self._get_user_id(request)

        # Check DDoS protection first
        if not self.rate_limiter.is_trusted_ip(ip_address):
            if not await self.rate_limiter.check_ddos_protection(ip_address):
                return self._create_error_response(429, "Rate limit exceeded - IP blocked")

        # Check rate limits
        limits_to_check = [
            (ip_address, LimitType.PER_IP),
            (user_id if user_id else f"anon_{ip_address}", LimitType.PER_USER),
            (endpoint, LimitType.PER_ENDPOINT),
            ("global", LimitType.GLOBAL)
        ]

        for identifier, limit_type in limits_to_check:
            if identifier:
                result = await self.rate_limiter.check_rate_limit(
                    identifier, endpoint, limit_type, ip_address
                )

                if not result.allowed:
                    rate_limit = self.rate_limiter._get_rate_limit(endpoint, limit_type)
                    headers = self.rate_limiter.get_rate_limit_headers(result, rate_limit)
                    return self._create_error_response(429, "Rate limit exceeded", headers)

        # Record request
        await self.rate_limiter.record_request(ip_address, endpoint, user_id)

        # Process request
        response = await call_next(request)
        return response

    def _get_client_ip(self, request) -> str:
        """Extract client IP from request"""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    def _get_user_id(self, request) -> Optional[str]:
        """Extract user ID from request (from JWT or session)"""
        # This would be implemented based on your authentication system
        # For JWT, you'd decode the token from Authorization header
        return getattr(request.state, 'user_id', None)

    def _create_error_response(self, status_code: int, message: str, headers: Dict[str, str] = None):
        """Create error response"""
        from fastapi.responses import JSONResponse

        response = JSONResponse(
            status_code=status_code,
            content={"error": message, "timestamp": datetime.utcnow().isoformat()}
        )

        if headers:
            for key, value in headers.items():
                response.headers[key] = value

        return response
