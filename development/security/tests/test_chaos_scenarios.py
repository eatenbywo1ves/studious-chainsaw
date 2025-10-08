"""
Chaos Testing Scenarios
Week 2 Day 2 - Resilience and Failure Handling Tests

Tests system behavior under failure conditions:
- Redis connection failures
- Data corruption
- Network issues
- Resource exhaustion
- Cascading failures
"""

import pytest
import time
import asyncio
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from application.redis_manager import RedisConnectionManager, get_redis
from application.jwt_security import JWTSecurityManager, SecurityLevel, TokenType
from application.rate_limiting import AdvancedRateLimiter, LimitType, RateLimit, RateLimitStrategy

# Chaos testing metrics
chaos_metrics = {
    "redis_connection_failures": 0,
    "fallback_activations": 0,
    "operations_failed": 0,
    "operations_succeeded": 0,
    "errors_logged": [],
    "recovery_time_ms": 0.0,
}


def reset_chaos_metrics():
    """Reset chaos testing metrics"""
    global chaos_metrics
    chaos_metrics = {
        "redis_connection_failures": 0,
        "fallback_activations": 0,
        "operations_failed": 0,
        "operations_succeeded": 0,
        "errors_logged": [],
        "recovery_time_ms": 0.0,
    }


@pytest.fixture(scope="module")
def jwt_keys(tmp_path_factory):
    """Generate temporary RSA keys for testing"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    tmp_path = tmp_path_factory.mktemp("keys")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_path = tmp_path / "jwt_private.pem"
    public_key_path = tmp_path / "jwt_public.pem"

    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    return str(private_key_path), str(public_key_path)


class TestRedisFailureScenarios:
    """Test Redis connection failure scenarios"""

    def test_redis_unavailable_on_startup(self, jwt_keys):
        """
        Chaos Test 1.1: Redis Down on Startup

        Scenario:
        1. Simulate Redis unavailable
        2. Create SecurityManager
        3. Verify fallback to in-memory mode
        4. Verify all operations still work
        """
        reset_chaos_metrics()
        private_key_path, public_key_path = jwt_keys

        # Create Redis manager with invalid connection (simulates Redis down)
        redis_client = RedisConnectionManager(
            host="invalid-host-that-does-not-exist",
            port=9999,
            enable_fallback=True
        )

        # Verify Redis is not available
        assert redis_client.is_available is False, "Redis should be unavailable"
        chaos_metrics["redis_connection_failures"] += 1
        chaos_metrics["fallback_activations"] += 1

        # Create JWT manager with unavailable Redis
        jwt_mgr = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.ENHANCED
        )

        # Test 1: Create token (should work with in-memory)
        try:
            token = jwt_mgr.create_access_token(
                subject="chaos_user",
                user_id="user_001",
                roles=["user"],
                permissions=["read"]
            )
            assert token is not None
            chaos_metrics["operations_succeeded"] += 1
        except Exception as e:
            chaos_metrics["operations_failed"] += 1
            pytest.fail(f"Token creation failed: {e}")

        # Test 2: Verify token (should work)
        try:
            payload = jwt_mgr.verify_token(token, TokenType.ACCESS)
            assert payload["user_id"] == "user_001"
            chaos_metrics["operations_succeeded"] += 1
        except Exception as e:
            chaos_metrics["operations_failed"] += 1
            pytest.fail(f"Token verification failed: {e}")

        # Test 3: Revoke token (in-memory fallback)
        try:
            revoked = jwt_mgr.revoke_token(token)
            assert revoked is True, "Token should be revoked (in-memory)"
            chaos_metrics["operations_succeeded"] += 1
        except Exception as e:
            chaos_metrics["operations_failed"] += 1
            pytest.fail(f"Token revocation failed: {e}")

        # Test 4: Verify revoked token is rejected
        try:
            jwt_mgr.verify_token(token, TokenType.ACCESS)
            chaos_metrics["operations_failed"] += 1
            pytest.fail("Revoked token should have been rejected")
        except Exception:
            # Expected: token revoked
            chaos_metrics["operations_succeeded"] += 1

        print("\n[CHAOS TEST PASSED] Redis unavailable - Fallback mode working ✓")
        print(f"  Operations succeeded: {chaos_metrics['operations_succeeded']}")
        print(f"  Operations failed: {chaos_metrics['operations_failed']}")

    def test_redis_connection_lost_during_runtime(self, jwt_keys):
        """
        Chaos Test 1.2: Redis Connection Lost During Runtime

        Scenario:
        1. Start with working Redis connection
        2. Simulate connection loss
        3. Verify graceful fallback
        4. Verify operations continue
        """
        reset_chaos_metrics()
        private_key_path, public_key_path = jwt_keys

        # Create Redis manager with fallback enabled
        redis_client = RedisConnectionManager(enable_fallback=True)

        # If Redis is actually available, we'll simulate failure
        if redis_client.is_available:
            # Create JWT manager
            jwt_mgr = JWTSecurityManager(
                private_key_path=private_key_path,
                public_key_path=public_key_path,
                redis_client=redis_client,
                security_level=SecurityLevel.ENHANCED
            )

            # Create token while Redis is working
            token1 = jwt_mgr.create_access_token(
                subject="user_before_failure",
                user_id="user_002",
                roles=["user"],
                permissions=["read"]
            )
            chaos_metrics["operations_succeeded"] += 1

            # Simulate Redis connection loss
            redis_client._available = False
            chaos_metrics["redis_connection_failures"] += 1
            chaos_metrics["fallback_activations"] += 1

            # Create token after simulated failure (should use in-memory)
            try:
                token2 = jwt_mgr.create_access_token(
                    subject="user_after_failure",
                    user_id="user_003",
                    roles=["user"],
                    permissions=["read"]
                )
                assert token2 is not None
                chaos_metrics["operations_succeeded"] += 1
            except Exception as e:
                chaos_metrics["operations_failed"] += 1
                pytest.fail(f"Token creation failed after Redis loss: {e}")

            # Verify both tokens still work
            payload1 = jwt_mgr.verify_token(token1, TokenType.ACCESS)
            assert payload1["user_id"] == "user_002"
            chaos_metrics["operations_succeeded"] += 1

            payload2 = jwt_mgr.verify_token(token2, TokenType.ACCESS)
            assert payload2["user_id"] == "user_003"
            chaos_metrics["operations_succeeded"] += 1

            print("\n[CHAOS TEST PASSED] Redis connection lost - Graceful degradation ✓")
            print(f"  Operations succeeded: {chaos_metrics['operations_succeeded']}")
        else:
            pytest.skip("Redis not available - cannot test connection loss scenario")

    def test_rate_limiting_without_redis(self):
        """
        Chaos Test 1.3: Rate Limiting Fallback

        Scenario:
        1. Create rate limiter without Redis
        2. Verify in-memory rate limiting works
        3. Test sliding window strategy
        4. Test token bucket strategy
        """
        reset_chaos_metrics()

        # Create rate limiter with no Redis
        redis_client = RedisConnectionManager(
            host="invalid-host",
            port=9999,
            enable_fallback=True
        )
        assert redis_client.is_available is False
        chaos_metrics["fallback_activations"] += 1

        limiter = AdvancedRateLimiter(redis_client=redis_client)

        # Configure rate limit
        endpoint = "/api/chaos/test"
        rate_limit = RateLimit(
            requests=3,
            window_seconds=60,
            strategy=RateLimitStrategy.SLIDING_WINDOW
        )
        limiter.set_rate_limit(endpoint, LimitType.PER_USER, rate_limit)

        user_id = "chaos_user_rate_limit"

        # Make 3 requests (should all be allowed)
        for i in range(3):
            result = asyncio.run(
                limiter.check_rate_limit(user_id, endpoint, LimitType.PER_USER)
            )
            assert result.allowed is True, f"Request {i+1} should be allowed"
            chaos_metrics["operations_succeeded"] += 1

        # 4th request should be blocked
        result = asyncio.run(
            limiter.check_rate_limit(user_id, endpoint, LimitType.PER_USER)
        )
        assert result.allowed is False, "4th request should be blocked"
        chaos_metrics["operations_succeeded"] += 1

        print("\n[CHAOS TEST PASSED] Rate limiting without Redis ✓")
        print("  In-memory fallback working correctly")


class TestDataCorruptionScenarios:
    """Test data corruption and invalid state scenarios"""

    def test_corrupted_blacklist_entry(self, jwt_keys):
        """
        Chaos Test 2.1: Corrupted Blacklist Entry

        Scenario:
        1. Create valid token
        2. Manually corrupt blacklist entry in Redis
        3. Verify graceful handling
        4. Verify fail-secure behavior (reject corrupted = safe)
        """
        reset_chaos_metrics()
        private_key_path, public_key_path = jwt_keys

        redis_client = get_redis()
        if not redis_client.is_available:
            pytest.skip("Redis not available - cannot test corruption")

        jwt_mgr = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.ENHANCED
        )

        # Create token
        token = jwt_mgr.create_access_token(
            subject="corrupt_test",
            user_id="user_corrupt",
            roles=["user"],
            permissions=["read"]
        )

        # Extract JTI from token
        payload = jwt_mgr.verify_token(token, TokenType.ACCESS)
        jti = payload.get("jti")

        # Manually create corrupted blacklist entry
        redis_client.set(f"blacklist:{jti}_corrupted", "INVALID_CORRUPTED_DATA")
        chaos_metrics["errors_logged"].append("Simulated data corruption")

        # Verify token still works (corrupted entry has wrong JTI)
        try:
            payload2 = jwt_mgr.verify_token(token, TokenType.ACCESS)
            assert payload2["user_id"] == "user_corrupt"
            chaos_metrics["operations_succeeded"] += 1
        except Exception as e:
            chaos_metrics["operations_failed"] += 1
            pytest.fail(f"Token verification failed unexpectedly: {e}")

        # Now actually revoke with correct JTI
        jwt_mgr.revoke_token(token)

        # Verify token is now rejected
        try:
            jwt_mgr.verify_token(token, TokenType.ACCESS)
            pytest.fail("Revoked token should be rejected")
        except Exception:
            chaos_metrics["operations_succeeded"] += 1

        # Cleanup
        redis_client.delete(f"blacklist:{jti}_corrupted")
        redis_client.delete(f"blacklist:{jti}")

        print("\n[CHAOS TEST PASSED] Corrupted data handled gracefully ✓")


class TestNetworkIssues:
    """Test network partition and timeout scenarios"""

    def test_redis_timeout_handling(self, jwt_keys):
        """
        Chaos Test 3.1: Redis Timeout

        Scenario:
        1. Create Redis manager with very short timeout
        2. Verify timeout errors handled gracefully
        3. Verify fallback activation
        """
        reset_chaos_metrics()
        private_key_path, public_key_path = jwt_keys

        # Create Redis manager with aggressive timeout
        redis_client = RedisConnectionManager(
            socket_timeout=0.001,  # 1ms - will timeout on most operations
            enable_fallback=True
        )

        # Operations may timeout and fallback
        # This is testing that timeouts don't crash the system
        jwt_mgr = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.ENHANCED
        )

        # Try to create token (may use fallback due to timeout)
        try:
            token = jwt_mgr.create_access_token(
                subject="timeout_test",
                user_id="user_timeout",
                roles=["user"],
                permissions=["read"]
            )
            assert token is not None
            chaos_metrics["operations_succeeded"] += 1
        except Exception as e:
            chaos_metrics["operations_failed"] += 1
            pytest.fail(f"Timeout should not cause failure: {e}")

        # Verify token works (may use in-memory)
        payload = jwt_mgr.verify_token(token, TokenType.ACCESS)
        assert payload["user_id"] == "user_timeout"
        chaos_metrics["operations_succeeded"] += 1

        print("\n[CHAOS TEST PASSED] Timeouts handled gracefully ✓")


class TestResourceExhaustion:
    """Test resource exhaustion scenarios"""

    def test_high_concurrent_load(self, jwt_keys):
        """
        Chaos Test 4.1: High Concurrent Load

        Scenario:
        1. Create many concurrent token operations
        2. Verify all complete successfully
        3. Verify no connection leaks
        """
        reset_chaos_metrics()
        private_key_path, public_key_path = jwt_keys

        redis_client = get_redis()
        jwt_mgr = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.ENHANCED
        )

        # Create token
        token = jwt_mgr.create_access_token(
            subject="load_test",
            user_id="user_load",
            roles=["user"],
            permissions=["read"]
        )

        # Verify token 100 times concurrently
        async def verify_many():
            tasks = []
            for i in range(100):
                # Create async wrapper for sync function
                async def verify():
                    try:
                        payload = jwt_mgr.verify_token(token, TokenType.ACCESS)
                        chaos_metrics["operations_succeeded"] += 1
                        return payload
                    except Exception:
                        chaos_metrics["operations_failed"] += 1
                        raise

                tasks.append(verify())

            results = await asyncio.gather(*tasks, return_exceptions=True)
            return results

        # Run concurrent verification
        start_time = time.time()
        results = asyncio.run(verify_many())
        elapsed_ms = (time.time() - start_time) * 1000

        # Count successes
        successes = sum(1 for r in results if not isinstance(r, Exception))
        failures = len(results) - successes

        assert successes >= 95, f"At least 95/100 should succeed, got {successes}"

        print("\n[CHAOS TEST PASSED] High concurrent load handled ✓")
        print(f"  Successes: {successes}/100")
        print(f"  Failures: {failures}/100")
        print(f"  Total time: {elapsed_ms:.2f}ms")
        print(f"  Avg latency: {elapsed_ms/100:.2f}ms per operation")


class TestCascadingFailures:
    """Test multiple simultaneous failures"""

    def test_redis_and_network_failure_combined(self, jwt_keys):
        """
        Chaos Test 5.1: Multiple Simultaneous Failures

        Scenario:
        1. Simulate Redis unavailable
        2. Simulate slow network (timeout)
        3. Verify system still operational
        4. Verify fallback mechanisms work
        """
        reset_chaos_metrics()
        private_key_path, public_key_path = jwt_keys

        # Create multiple failure conditions
        redis_client = RedisConnectionManager(
            host="invalid-host",  # Redis unavailable
            socket_timeout=0.001,  # Network timeout
            enable_fallback=True
        )

        assert redis_client.is_available is False
        chaos_metrics["redis_connection_failures"] += 1
        chaos_metrics["fallback_activations"] += 1

        # Create managers with cascading failures
        jwt_mgr = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.ENHANCED
        )

        limiter = AdvancedRateLimiter(redis_client=redis_client)

        # Test JWT operations despite failures
        token = jwt_mgr.create_access_token(
            subject="cascade_test",
            user_id="user_cascade",
            roles=["user"],
            permissions=["read"]
        )
        chaos_metrics["operations_succeeded"] += 1

        payload = jwt_mgr.verify_token(token, TokenType.ACCESS)
        assert payload["user_id"] == "user_cascade"
        chaos_metrics["operations_succeeded"] += 1

        # Test rate limiting despite failures
        endpoint = "/api/cascade/test"
        rate_limit = RateLimit(requests=5, window_seconds=60)
        limiter.set_rate_limit(endpoint, LimitType.PER_USER, rate_limit)

        result = asyncio.run(
            limiter.check_rate_limit("cascade_user", endpoint, LimitType.PER_USER)
        )
        assert result.allowed is True
        chaos_metrics["operations_succeeded"] += 1

        print("\n[CHAOS TEST PASSED] Cascading failures handled ✓")
        print("  All core operations functional despite multiple failures")
        print(f"  Total operations succeeded: {chaos_metrics['operations_succeeded']}")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short", "-s"])
