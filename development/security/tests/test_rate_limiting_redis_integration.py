#!/usr/bin/env python3
"""
Integration tests for Rate Limiting with Redis backend
Tests the critical fix for distributed rate limiting
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import redis.asyncio as redis
from application.rate_limiting_redis import AdvancedRateLimiter, RateLimit, RateLimitAlgorithm


class TestResults:
    """Track test results for reporting"""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def add_pass(self, name: str):
        self.passed += 1
        self.tests.append((name, "PASS", None))
        print(f"[OK] {name}")

    def add_fail(self, name: str, error: str):
        self.failed += 1
        self.tests.append((name, "FAIL", error))
        print(f"[FAIL] {name}: {error}")

    def summary(self):
        total = self.passed + self.failed
        print("\n" + "=" * 70)
        print(f"Test Results: {self.passed}/{total} passed ({self.failed} failed)")
        print("=" * 70)

        if self.failed > 0:
            print("\nFailed tests:")
            for name, status, error in self.tests:
                if status == "FAIL":
                    print(f"  - {name}: {error}")


async def test_redis_connection(redis_client: redis.Redis, results: TestResults):
    """Test 1: Verify Redis connection works"""
    try:
        pong = await redis_client.ping()
        if pong:
            results.add_pass("Redis connection")
        else:
            results.add_fail("Redis connection", "PING did not return PONG")
    except Exception as e:
        results.add_fail("Redis connection", str(e))


async def test_rate_limiter_initialization(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 2: Verify rate limiter initializes with Redis"""
    try:
        if limiter.redis_client is not None:
            results.add_pass("Rate limiter initialization with Redis")
        else:
            results.add_fail("Rate limiter initialization with Redis", "redis_client is None")
    except Exception as e:
        results.add_fail("Rate limiter initialization with Redis", str(e))


async def test_token_bucket_algorithm(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 3: Verify token bucket algorithm works"""
    try:
        rate_limit = RateLimit(
            requests=5, window_seconds=10, algorithm=RateLimitAlgorithm.TOKEN_BUCKET
        )

        identifier = "test_token_bucket_user"
        allowed_count = 0
        denied_count = 0

        # Make 7 requests (should allow 5, deny 2)
        for i in range(7):
            result = await limiter.check_rate_limit(identifier, rate_limit)
            if result.allowed:
                allowed_count += 1
            else:
                denied_count += 1

        if allowed_count == 5 and denied_count == 2:
            results.add_pass("Token bucket algorithm")
        else:
            results.add_fail(
                "Token bucket algorithm", f"Allowed {allowed_count}/5, Denied {denied_count}/2"
            )

    except Exception as e:
        results.add_fail("Token bucket algorithm", str(e))


async def test_sliding_window_algorithm(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 4: Verify sliding window algorithm works"""
    try:
        rate_limit = RateLimit(
            requests=3, window_seconds=5, algorithm=RateLimitAlgorithm.SLIDING_WINDOW
        )

        identifier = "test_sliding_window_user"

        # Make 3 requests (should all be allowed)
        for i in range(3):
            result = await limiter.check_rate_limit(identifier, rate_limit)
            if not result.allowed:
                results.add_fail("Sliding window algorithm", f"Request {i + 1}/3 was denied")
                return

        # 4th request should be denied
        result = await limiter.check_rate_limit(identifier, rate_limit)
        if not result.allowed:
            results.add_pass("Sliding window algorithm")
        else:
            results.add_fail(
                "Sliding window algorithm", "4th request was allowed (should be denied)"
            )

    except Exception as e:
        results.add_fail("Sliding window algorithm", str(e))


async def test_fixed_window_algorithm(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 5: Verify fixed window algorithm works"""
    try:
        rate_limit = RateLimit(
            requests=10, window_seconds=60, algorithm=RateLimitAlgorithm.FIXED_WINDOW
        )

        identifier = "test_fixed_window_user"
        allowed_count = 0

        # Make 12 requests (should allow 10, deny 2)
        for i in range(12):
            result = await limiter.check_rate_limit(identifier, rate_limit)
            if result.allowed:
                allowed_count += 1

        if allowed_count == 10:
            results.add_pass("Fixed window algorithm")
        else:
            results.add_fail("Fixed window algorithm", f"Allowed {allowed_count}/10 requests")

    except Exception as e:
        results.add_fail("Fixed window algorithm", str(e))


async def test_distributed_rate_limiting(redis_client: redis.Redis, results: TestResults):
    """Test 6: Verify rate limits work across multiple limiter instances (simulating multiple servers)"""
    try:
        # Create two separate limiter instances (simulating two servers)
        limiter_1 = AdvancedRateLimiter(redis_client=redis_client, enable_ddos_protection=False)

        limiter_2 = AdvancedRateLimiter(redis_client=redis_client, enable_ddos_protection=False)

        rate_limit = RateLimit(
            requests=5, window_seconds=10, algorithm=RateLimitAlgorithm.TOKEN_BUCKET
        )

        identifier = "distributed_test_user"

        # Make 3 requests on server 1
        for i in range(3):
            await limiter_1.check_rate_limit(identifier, rate_limit)

        # Make 3 requests on server 2 (should allow 2, deny 1)
        allowed_count = 0
        denied_count = 0

        for i in range(3):
            result = await limiter_2.check_rate_limit(identifier, rate_limit)
            if result.allowed:
                allowed_count += 1
            else:
                denied_count += 1

        # Total requests: 6 (3 from server 1 + 3 from server 2)
        # Limit: 5
        # Expected: 5 allowed, 1 denied
        if allowed_count == 2 and denied_count == 1:
            results.add_pass("Distributed rate limiting (multi-server)")
        else:
            results.add_fail(
                "Distributed rate limiting (multi-server)",
                f"Server 2 allowed {allowed_count}/2, denied {denied_count}/1",
            )

    except Exception as e:
        results.add_fail("Distributed rate limiting (multi-server)", str(e))


async def test_ip_blocking(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 7: Verify IP blocking works"""
    try:
        ip_address = "192.168.1.100"

        # Block the IP
        await limiter.block_ip(ip_address, duration_minutes=1)

        # Check if IP is blocked
        is_blocked = await limiter._is_ip_blocked(ip_address)

        if is_blocked:
            results.add_pass("IP blocking")
        else:
            results.add_fail("IP blocking", "IP not blocked after block_ip() call")

    except Exception as e:
        results.add_fail("IP blocking", str(e))


async def test_ddos_detection(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 8: Verify DDoS detection works"""
    try:
        # Enable DDoS protection
        limiter_ddos = AdvancedRateLimiter(
            redis_client=limiter.redis_client,
            enable_ddos_protection=True,
            suspicious_threshold=10,
            block_duration_minutes=1,
        )

        ip_address = "10.0.0.1"

        # Record suspicious activity (11 events, threshold is 10)
        for i in range(11):
            await limiter_ddos.record_suspicious_activity(ip_address)

        # IP should be automatically blocked
        is_blocked = await limiter_ddos._is_ip_blocked(ip_address)

        if is_blocked:
            results.add_pass("DDoS detection and auto-blocking")
        else:
            results.add_fail(
                "DDoS detection and auto-blocking", "IP not blocked after exceeding threshold"
            )

    except Exception as e:
        results.add_fail("DDoS detection and auto-blocking", str(e))


async def test_burst_handling(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 9: Verify burst handling in token bucket"""
    try:
        rate_limit = RateLimit(
            requests=10, window_seconds=10, algorithm=RateLimitAlgorithm.TOKEN_BUCKET
        )

        identifier = "burst_test_user"

        # Make 10 requests rapidly (burst)
        allowed_count = 0
        for i in range(10):
            result = await limiter.check_rate_limit(identifier, rate_limit)
            if result.allowed:
                allowed_count += 1

        # Should allow all 10 (burst capacity)
        if allowed_count == 10:
            results.add_pass("Burst handling (token bucket)")
        else:
            results.add_fail(
                "Burst handling (token bucket)", f"Only {allowed_count}/10 requests allowed"
            )

    except Exception as e:
        results.add_fail("Burst handling (token bucket)", str(e))


async def test_rate_limit_headers(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 10: Verify rate limit headers are returned correctly"""
    try:
        rate_limit = RateLimit(
            requests=5, window_seconds=60, algorithm=RateLimitAlgorithm.FIXED_WINDOW
        )

        identifier = "headers_test_user"

        result = await limiter.check_rate_limit(identifier, rate_limit)

        # Check if headers are present
        if (
            hasattr(result, "remaining")
            and hasattr(result, "reset_time")
            and hasattr(result, "limit")
        ):
            if result.limit == 5 and result.remaining <= 5:
                results.add_pass("Rate limit headers")
            else:
                results.add_fail(
                    "Rate limit headers",
                    f"Invalid values: limit={result.limit}, remaining={result.remaining}",
                )
        else:
            results.add_fail("Rate limit headers", "Missing header fields")

    except Exception as e:
        results.add_fail("Rate limit headers", str(e))


async def test_redis_ttl_expiry(
    limiter: AdvancedRateLimiter, redis_client: redis.Redis, results: TestResults
):
    """Test 11: Verify Redis keys have TTL set"""
    try:
        rate_limit = RateLimit(
            requests=5, window_seconds=30, algorithm=RateLimitAlgorithm.FIXED_WINDOW
        )

        identifier = "ttl_test_user"

        # Make a request
        await limiter.check_rate_limit(identifier, rate_limit)

        # Check for keys with TTL
        keys = await redis_client.keys("ratelimit:*")

        if not keys:
            results.add_fail("Redis TTL on rate limit keys", "No rate limit keys found")
            return

        # Check TTL on first key
        ttl = await redis_client.ttl(keys[0])

        # TTL should be positive (key will expire)
        if ttl > 0:
            results.add_pass("Redis TTL on rate limit keys")
        else:
            results.add_fail("Redis TTL on rate limit keys", f"TTL is {ttl} (should be positive)")

    except Exception as e:
        results.add_fail("Redis TTL on rate limit keys", str(e))


async def test_token_refill(limiter: AdvancedRateLimiter, results: TestResults):
    """Test 12: Verify token bucket refills over time"""
    try:
        rate_limit = RateLimit(
            requests=3,
            window_seconds=6,  # 0.5 tokens/second refill rate
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
        )

        identifier = "refill_test_user"

        # Consume all 3 tokens
        for i in range(3):
            await limiter.check_rate_limit(identifier, rate_limit)

        # Next request should be denied
        result = await limiter.check_rate_limit(identifier, rate_limit)
        if result.allowed:
            results.add_fail("Token bucket refill", "4th request allowed immediately")
            return

        # Wait 3 seconds (should refill ~1.5 tokens, enough for 1 request)
        await asyncio.sleep(3)

        # Now should allow 1 request
        result = await limiter.check_rate_limit(identifier, rate_limit)

        if result.allowed:
            results.add_pass("Token bucket refill over time")
        else:
            results.add_fail(
                "Token bucket refill over time", "Request denied after waiting for refill"
            )

    except Exception as e:
        results.add_fail("Token bucket refill over time", str(e))


async def cleanup_redis(redis_client: redis.Redis):
    """Clean up test data from Redis"""
    try:
        # Delete all rate limit keys
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match="ratelimit:*", count=100)
            if keys:
                await redis_client.delete(*keys)
            if cursor == 0:
                break

        # Delete blocked IP keys
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match="blocked:ip:*", count=100)
            if keys:
                await redis_client.delete(*keys)
            if cursor == 0:
                break

        # Delete suspicious activity keys
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match="suspicious:ip:*", count=100)
            if keys:
                await redis_client.delete(*keys)
            if cursor == 0:
                break

        print("\n[CLEANUP] Test data removed from Redis")
    except Exception as e:
        print(f"\n[WARN] Cleanup failed: {e}")


async def main():
    """Main test runner"""
    print("=" * 70)
    print("Rate Limiting Redis Integration Tests - Critical Security Fix Verification")
    print("=" * 70)
    print()

    results = TestResults()
    redis_client = None
    limiter = None

    try:
        # Initialize Redis connection
        print("[INFO] Connecting to Redis at localhost:6379...")
        redis_client = await redis.from_url("redis://localhost:6379", decode_responses=False)

        # Test Redis connection
        await test_redis_connection(redis_client, results)

        # Initialize rate limiter
        print("[INFO] Initializing Advanced Rate Limiter with Redis...")
        limiter = AdvancedRateLimiter(
            redis_client=redis_client,
            enable_ddos_protection=True,
            suspicious_threshold=1000,
            block_duration_minutes=60,
        )

        # Run tests
        print("[INFO] Running integration tests...\n")

        await test_rate_limiter_initialization(limiter, results)
        await test_token_bucket_algorithm(limiter, results)
        await test_sliding_window_algorithm(limiter, results)
        await test_fixed_window_algorithm(limiter, results)
        await test_distributed_rate_limiting(redis_client, results)
        await test_ip_blocking(limiter, results)
        await test_ddos_detection(limiter, results)
        await test_burst_handling(limiter, results)
        await test_rate_limit_headers(limiter, results)
        await test_redis_ttl_expiry(limiter, redis_client, results)
        await test_token_refill(limiter, results)

        # Print results
        results.summary()

        # Return exit code
        return 0 if results.failed == 0 else 1

    except Exception as e:
        print(f"\n[ERROR] Test suite failed: {e}")
        import traceback

        traceback.print_exc()
        return 1

    finally:
        # Cleanup
        if redis_client:
            await cleanup_redis(redis_client)
            await redis_client.close()


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
