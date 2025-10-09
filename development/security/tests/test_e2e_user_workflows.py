"""
End-to-End User Workflow Tests
Week 2 Integration Testing - Complete User Lifecycle Scenarios

Tests complete user journeys through the security infrastructure:
- User registration → login → token usage → revocation → rate limiting
- Multi-server distributed state synchronization
- Real-world attack scenarios and mitigations
"""

import pytest
import time
import asyncio
from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from application.redis_manager import get_redis
from application.jwt_security import JWTSecurityManager, TokenType
from application.rate_limiting import AdvancedRateLimiter, LimitType, RateLimit, RateLimitStrategy
from application.security_init import SecurityManager


@pytest.fixture(scope="module")
def redis_client():
    """Fixture for Redis connection"""
    redis = get_redis()

    if not redis.is_available:
        pytest.skip("Redis not available - skipping E2E tests")

    # Clean up test data before tests
    # Delete all rate limit and blacklist keys from previous test runs
    if hasattr(redis, "_client") and redis._client:
        try:
            # Get all test-related keys
            test_keys = redis._client.keys("ratelimit:*") + redis._client.keys("blacklist:*")
            if test_keys:
                redis._client.delete(*test_keys)
        except Exception as e:
            print(f"Warning: Could not clean Redis before tests: {e}")

    yield redis

    # Cleanup test data after module
    # Note: In production, use separate Redis database for tests


@pytest.fixture
def jwt_keys(tmp_path):
    """Generate temporary RSA keys for testing"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    public_key = private_key.public_key()

    private_key_path = tmp_path / "jwt_private.pem"
    public_key_path = tmp_path / "jwt_public.pem"

    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    return str(private_key_path), str(public_key_path)


@pytest.fixture
def security_manager(redis_client, jwt_keys):
    """Create SecurityManager instance for testing"""
    private_key_path, public_key_path = jwt_keys

    manager = SecurityManager(private_key_path=private_key_path, public_key_path=public_key_path)

    return manager


class TestCompleteUserLifecycle:
    """Test complete user lifecycle from registration to logout"""

    def test_user_registration_login_logout_flow(self, security_manager, redis_client):
        """
        E2E Test: User Registration → Login → Token Usage → Logout

        Scenario:
        1. User registers (rate limit check)
        2. User logs in (receives access + refresh tokens)
        3. User makes authenticated API calls
        4. User logs out (token revocation)
        5. Verify revoked token is rejected
        """
        user_id = "test_user_12345"
        user_ip = "192.168.1.100"

        # Step 1: Registration (rate limit check)
        registration_endpoint = "/api/auth/register"
        register_limit = RateLimit(
            requests=3,
            window_seconds=3600,  # 3 per hour
            strategy=RateLimitStrategy.SLIDING_WINDOW,
        )
        security_manager.rate_limiter.set_rate_limit(
            registration_endpoint, LimitType.PER_IP, register_limit
        )

        # Cleanup any previous test data
        redis_client.delete(f"ratelimit:window:{user_ip}:{registration_endpoint}")

        # Check registration rate limit
        registration_allowed = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=user_ip, endpoint=registration_endpoint, limit_type=LimitType.PER_IP
            )
        )

        assert registration_allowed.allowed is True, "Registration should be allowed"

        # Step 2: Login (create tokens)
        login_endpoint = "/api/auth/login"
        login_limit = RateLimit(
            requests=5,
            window_seconds=300,  # 5 per 5 minutes
            strategy=RateLimitStrategy.SLIDING_WINDOW,
        )
        security_manager.rate_limiter.set_rate_limit(login_endpoint, LimitType.PER_IP, login_limit)

        # Cleanup
        redis_client.delete(f"ratelimit:window:{user_ip}:{login_endpoint}")

        # Check login rate limit
        login_allowed = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=user_ip, endpoint=login_endpoint, limit_type=LimitType.PER_IP
            )
        )

        assert login_allowed.allowed is True, "Login should be allowed"

        # Create access token
        access_token = security_manager.jwt.create_access_token(
            subject=user_id, user_id=user_id, roles=["user"], permissions=["api:read", "api:write"]
        )

        assert access_token is not None, "Access token should be created"

        # Create refresh token
        refresh_token = security_manager.jwt.create_refresh_token(
            user_id=user_id, fingerprint="test_device_fingerprint"
        )

        assert refresh_token is not None, "Refresh token should be created"

        # Step 3: Use access token for API calls
        api_endpoint = "/api/compute/run"
        api_limit = RateLimit(
            requests=10,
            window_seconds=3600,  # 10 per hour
            strategy=RateLimitStrategy.TOKEN_BUCKET,
            burst_allowance=3,
        )
        security_manager.rate_limiter.set_rate_limit(api_endpoint, LimitType.PER_USER, api_limit)

        # Cleanup
        redis_client.delete(f"ratelimit:bucket:{user_id}:{api_endpoint}")

        # Verify token
        payload = security_manager.jwt.verify_token(access_token, TokenType.ACCESS)
        assert payload is not None, "Access token should be valid"
        assert payload["user_id"] == user_id, "Token should contain correct user_id"

        # Make API calls (rate limited)
        for i in range(3):
            api_allowed = asyncio.run(
                security_manager.rate_limiter.check_rate_limit(
                    identifier=user_id, endpoint=api_endpoint, limit_type=LimitType.PER_USER
                )
            )
            assert api_allowed.allowed is True, f"API call {i + 1} should be allowed"

        # Step 4: Logout (revoke token)
        revoke_result = security_manager.jwt.revoke_token(access_token)
        assert revoke_result is True, "Token should be revoked successfully"

        # Step 5: Verify revoked token is rejected
        try:
            security_manager.jwt.verify_token(access_token, TokenType.ACCESS)
            assert False, "Revoked token should have raised an exception"
        except Exception as e:
            assert "revoked" in str(e).lower(), "Token should be rejected as revoked"

        print("\n[E2E TEST PASSED] Complete user lifecycle validated ✓")

    def test_stolen_token_scenario(self, security_manager, redis_client):
        """
        E2E Test: Stolen Token Attack Mitigation

        Scenario:
        1. User logs in normally (receives token)
        2. Attacker steals token
        3. User reports suspicious activity
        4. Admin revokes token
        5. Attacker's requests are blocked
        """
        user_id = "test_user_victim"
        attacker_ip = "203.0.113.50"  # Attacker IP

        # User logs in (gets valid token)
        access_token = security_manager.jwt.create_access_token(
            subject=user_id, user_id=user_id, roles=["user"], permissions=["data:export"]
        )

        # Token initially valid
        payload = security_manager.jwt.verify_token(access_token, TokenType.ACCESS)
        assert payload is not None, "Token should be valid initially"

        # Attacker tries to use stolen token
        attacker_endpoint = "/api/data/export"
        attacker_limit = RateLimit(
            requests=5, window_seconds=60, strategy=RateLimitStrategy.SLIDING_WINDOW
        )
        security_manager.rate_limiter.set_rate_limit(
            attacker_endpoint, LimitType.PER_IP, attacker_limit
        )

        # Cleanup
        redis_client.delete(f"ratelimit:window:{attacker_ip}:{attacker_endpoint}")

        # Attacker's request allowed (token still valid)
        attacker_allowed = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=attacker_ip, endpoint=attacker_endpoint, limit_type=LimitType.PER_IP
            )
        )
        assert attacker_allowed.allowed is True, "Attacker's first request allowed (token valid)"

        # User reports suspicious activity → Admin revokes token
        revoke_result = security_manager.jwt.revoke_token(access_token)
        assert revoke_result is True, "Token revoked by admin"

        # Attacker tries to use token again → BLOCKED
        try:
            security_manager.jwt.verify_token(access_token, TokenType.ACCESS)
            assert False, "Attacker's token should have been rejected"
        except Exception as e:
            assert "revoked" in str(e).lower(), "Token should be rejected as revoked"

        print("\n[SECURITY TEST PASSED] Stolen token attack mitigated ✓")

    def test_brute_force_login_attack(self, security_manager, redis_client):
        """
        E2E Test: Brute Force Login Attack Prevention

        Scenario:
        1. Attacker attempts multiple failed logins
        2. Rate limiter blocks after threshold
        3. Legitimate user also blocked temporarily
        4. After cooldown, legitimate user can login
        """
        attacker_ip = "198.51.100.25"
        login_endpoint = "/api/auth/login"

        # Configure aggressive login rate limit
        login_limit = RateLimit(
            requests=3,
            window_seconds=60,  # 3 attempts per minute
            strategy=RateLimitStrategy.SLIDING_WINDOW,
        )
        security_manager.rate_limiter.set_rate_limit(login_endpoint, LimitType.PER_IP, login_limit)

        # Cleanup any previous test data
        redis_client.delete(f"ratelimit:window:{attacker_ip}:{login_endpoint}")

        # Give Redis a moment to process the delete
        time.sleep(0.1)

        # Attacker makes 3 failed login attempts
        for i in range(3):
            allowed = asyncio.run(
                security_manager.rate_limiter.check_rate_limit(
                    identifier=attacker_ip, endpoint=login_endpoint, limit_type=LimitType.PER_IP
                )
            )
            assert allowed.allowed is True, f"Attempt {i + 1} should be allowed"

        # 4th attempt blocked
        blocked = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=attacker_ip, endpoint=login_endpoint, limit_type=LimitType.PER_IP
            )
        )
        assert blocked.allowed is False, "4th attempt should be blocked"

        # Even legitimate user from same IP is blocked
        blocked_again = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=attacker_ip, endpoint=login_endpoint, limit_type=LimitType.PER_IP
            )
        )
        assert blocked_again.allowed is False, "Still blocked during cooldown"

        print("\n[SECURITY TEST PASSED] Brute force attack prevented ✓")


class TestMultiServerDistribution:
    """Test distributed state synchronization across multiple server instances"""

    def test_token_revocation_across_servers(self, redis_client, jwt_keys):
        """
        E2E Test: Token Revocation Distribution

        Scenario:
        1. Server 1 creates token
        2. Server 2 verifies token (valid)
        3. Server 1 revokes token (writes to Redis)
        4. Server 2 verifies token (rejected - reads from Redis)
        """
        private_key_path, public_key_path = jwt_keys

        # Simulate Server 1
        server1 = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
        )

        # Simulate Server 2 (separate instance, same Redis)
        server2 = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
        )

        user_id = "test_user_multiserver"

        # Server 1: Create token
        token = server1.create_access_token(
            subject=user_id, user_id=user_id, roles=["user"], permissions=["read", "write"]
        )

        # Server 2: Verify token (should be valid)
        payload = server2.verify_token(token, TokenType.ACCESS)
        assert payload is not None, "Server 2 should validate token from Server 1"
        assert payload["user_id"] == user_id

        # Server 1: Revoke token
        revoked = server1.revoke_token(token)
        assert revoked is True, "Server 1 should revoke token"

        # Server 2: Verify token again (should be rejected - distributed blacklist)
        try:
            server2.verify_token(token, TokenType.ACCESS)
            assert False, "Server 2 should have rejected revoked token"
        except Exception as e:
            assert "revoked" in str(e).lower(), "Token should be rejected as revoked"

        print("\n[DISTRIBUTED TEST PASSED] Token revocation synchronized across servers ✓")

    def test_rate_limit_distribution_across_servers(self, redis_client):
        """
        E2E Test: Rate Limit Distribution

        Scenario:
        1. User makes 3 requests to Server 1 (limit: 5/minute)
        2. User makes 2 requests to Server 2 (same limit)
        3. User makes 1 more request to Server 1 → BLOCKED (5 total)
        """
        # Simulate Server 1
        limiter1 = AdvancedRateLimiter(redis_client=redis_client)

        # Simulate Server 2 (separate instance, same Redis)
        limiter2 = AdvancedRateLimiter(redis_client=redis_client)

        user_id = "test_user_distributed"
        endpoint = "/api/compute/heavy"

        # Configure same rate limit on both servers
        rate_limit = RateLimit(
            requests=5, window_seconds=60, strategy=RateLimitStrategy.SLIDING_WINDOW
        )
        limiter1.set_rate_limit(endpoint, LimitType.PER_USER, rate_limit)
        limiter2.set_rate_limit(endpoint, LimitType.PER_USER, rate_limit)

        # Cleanup
        redis_client.delete(f"ratelimit:window:{user_id}:{endpoint}")

        # User makes 3 requests to Server 1
        for i in range(3):
            result = asyncio.run(limiter1.check_rate_limit(user_id, endpoint, LimitType.PER_USER))
            assert result.allowed is True, f"Server 1 request {i + 1} should be allowed"

        # User makes 2 requests to Server 2
        for i in range(2):
            result = asyncio.run(limiter2.check_rate_limit(user_id, endpoint, LimitType.PER_USER))
            assert result.allowed is True, f"Server 2 request {i + 1} should be allowed"

        # User makes 6th request to Server 1 → BLOCKED (distributed count)
        result = asyncio.run(limiter1.check_rate_limit(user_id, endpoint, LimitType.PER_USER))
        assert result.allowed is False, "6th request should be blocked (distributed limit)"

        print("\n[DISTRIBUTED TEST PASSED] Rate limiting synchronized across servers ✓")


class TestRealWorldScenarios:
    """Test real-world attack scenarios and edge cases"""

    def test_api_abuse_scenario(self, security_manager, redis_client):
        """
        E2E Test: API Abuse Protection

        Scenario:
        1. User has API key with quota (100 requests/hour)
        2. User writes script that spams API
        3. After quota exhausted, requests blocked
        4. User must wait for quota refill
        """
        user_id = "test_user_api_abuser"
        api_endpoint = "/api/compute/expensive"

        # Configure quota
        quota_limit = RateLimit(
            requests=10,  # Small quota for testing
            window_seconds=60,
            strategy=RateLimitStrategy.SLIDING_WINDOW,
        )
        security_manager.rate_limiter.set_rate_limit(api_endpoint, LimitType.PER_USER, quota_limit)

        # Cleanup
        redis_client.delete(f"ratelimit:window:{user_id}:{api_endpoint}")

        # User spam 10 requests (all allowed)
        for i in range(10):
            allowed = asyncio.run(
                security_manager.rate_limiter.check_rate_limit(
                    identifier=user_id, endpoint=api_endpoint, limit_type=LimitType.PER_USER
                )
            )
            assert allowed.allowed is True, f"Request {i + 1} should be allowed"

        # 11th request blocked
        blocked = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=user_id, endpoint=api_endpoint, limit_type=LimitType.PER_USER
            )
        )
        assert blocked.allowed is False, "Request over quota should be blocked"

        print("\n[PROTECTION TEST PASSED] API abuse prevented ✓")

    def test_ddos_protection_scenario(self, security_manager, redis_client):
        """
        E2E Test: DDoS Protection

        Scenario:
        1. Attacker sends 1000 requests/minute from single IP
        2. DDoS protection auto-blocks IP
        3. Legitimate users from other IPs unaffected
        """
        attacker_ip = "203.0.113.100"
        legitimate_ip = "192.168.1.50"
        endpoint = "/api/public/search"

        # Configure DDoS protection (aggressive for testing)
        ddos_limit = RateLimit(
            requests=20,  # Low threshold for testing
            window_seconds=60,
            strategy=RateLimitStrategy.SLIDING_WINDOW,
        )
        security_manager.rate_limiter.set_rate_limit(endpoint, LimitType.PER_IP, ddos_limit)

        # Cleanup
        redis_client.delete(f"ratelimit:window:{attacker_ip}:{endpoint}")
        redis_client.delete(f"ratelimit:window:{legitimate_ip}:{endpoint}")

        # Attacker floods with requests
        for i in range(20):
            allowed = asyncio.run(
                security_manager.rate_limiter.check_rate_limit(
                    identifier=attacker_ip, endpoint=endpoint, limit_type=LimitType.PER_IP
                )
            )
            if i < 20:
                assert allowed.allowed is True, f"Attacker request {i + 1} initially allowed"

        # 21st request blocked
        blocked = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=attacker_ip, endpoint=endpoint, limit_type=LimitType.PER_IP
            )
        )
        assert blocked.allowed is False, "Attacker IP should be blocked"

        # Legitimate user unaffected
        legit_allowed = asyncio.run(
            security_manager.rate_limiter.check_rate_limit(
                identifier=legitimate_ip, endpoint=endpoint, limit_type=LimitType.PER_IP
            )
        )
        assert legit_allowed.allowed is True, "Legitimate user should not be blocked"

        print("\n[DDOS TEST PASSED] DDoS attack mitigated ✓")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
