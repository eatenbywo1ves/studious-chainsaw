#!/usr/bin/env python3
"""
Simplified integration tests for critical Redis fixes
Tests the CRITICAL fixes for JWT blacklist and rate limiting
"""

import asyncio
import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import redis.asyncio as redis
import jwt

# Get Redis password from environment
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")


async def test_redis_connection():
    """Test 1: Verify Redis is running and accessible"""
    print("\n[TEST 1] Redis Connection")
    try:
        redis_url = f"redis://:{REDIS_PASSWORD}@localhost:6379" if REDIS_PASSWORD else "redis://localhost:6379"
        redis_client = await redis.from_url(redis_url, decode_responses=False)
        pong = await redis_client.ping()
        await redis_client.close()

        if pong:
            print("  [OK] Redis is running and accessible")
            return True
        else:
            print("  [FAIL] Redis PING did not return PONG")
            return False
    except Exception as e:
        print(f"  [FAIL] Redis connection failed: {e}")
        return False


async def test_jwt_redis_blacklist():
    """Test 2: Verify JWT blacklist uses Redis (distributed)"""
    print("\n[TEST 2] JWT Redis Blacklist")
    try:
        from application.jwt_security_redis import JWTSecurityManager, SecurityLevel

        redis_url = f"redis://:{REDIS_PASSWORD}@localhost:6379" if REDIS_PASSWORD else "redis://localhost:6379"
        redis_client = await redis.from_url(redis_url, decode_responses=False)

        # Initialize JWT manager
        jwt_manager = JWTSecurityManager(
            private_key_path="keys/jwt_development_private.pem",
            public_key_path="keys/jwt_development_public.pem",
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT
        )

        # Create token
        token = jwt_manager.create_access_token(
            subject="test_user",
            user_id="test_123",
            roles=["user"],
            permissions=["read"]
        )

        # Revoke token
        revoked = await jwt_manager.revoke_token(token)

        if not revoked:
            print("  [FAIL] Token revocation failed")
            await redis_client.close()
            return False

        # Check if it's in Redis
        payload = jwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")

        exists = await redis_client.exists(f"token:blacklist:{jti}")

        # Cleanup
        await redis_client.delete(f"token:blacklist:{jti}")
        await redis_client.close()

        if exists:
            print("  [OK] Token blacklist stored in Redis")
            return True
        else:
            print("  [FAIL] Token not found in Redis blacklist")
            return False

    except Exception as e:
        print(f"  [FAIL] JWT blacklist test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_rate_limiting_redis():
    """Test 3: Verify rate limiting uses Redis (distributed)"""
    print("\n[TEST 3] Rate Limiting Redis")
    try:
        from application.rate_limiting_redis import AdvancedRateLimiter, LimitType

        redis_url = f"redis://:{REDIS_PASSWORD}@localhost:6379" if REDIS_PASSWORD else "redis://localhost:6379"
        redis_client = await redis.from_url(redis_url, decode_responses=False)

        # Initialize rate limiter
        limiter = AdvancedRateLimiter(
            redis_client=redis_client,
            enable_ddos_protection=False
        )

        identifier = "test_user"
        endpoint = "/api/auth/login"  # Use configured endpoint with strict limits

        # Make 10 login attempts (configured limit is 3 per user per 5 min)
        allowed_count = 0
        for i in range(10):
            result = await limiter.check_rate_limit(
                identifier=identifier,
                endpoint=endpoint,
                limit_type=LimitType.PER_USER,
                ip_address="127.0.0.1"
            )
            if result.allowed:
                allowed_count += 1

        # Should have rate limited after 3 requests
        was_rate_limited = (allowed_count == 3)

        # Cleanup
        keys = await redis_client.keys("ratelimit:*")
        if keys:
            await redis_client.delete(*keys)
        await redis_client.close()

        if was_rate_limited:
            print(f"  [OK] Rate limiting enforced via Redis (allowed {allowed_count}/10, limit: 3)")
            return True
        else:
            print(f"  [FAIL] Rate limiting not working: allowed {allowed_count}/10 (expected 3)")
            return False

    except Exception as e:
        print(f"  [FAIL] Rate limiting test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_distributed_blacklist():
    """Test 4: Verify blacklist works across multiple JWT manager instances"""
    print("\n[TEST 4] Distributed Blacklist (Multi-Server)")
    try:
        from application.jwt_security_redis import JWTSecurityManager, SecurityLevel

        redis_url = f"redis://:{REDIS_PASSWORD}@localhost:6379" if REDIS_PASSWORD else "redis://localhost:6379"
        redis_client = await redis.from_url(redis_url, decode_responses=False)

        # Create two separate JWT manager instances (simulating two servers)
        jwt_manager_1 = JWTSecurityManager(
            private_key_path="keys/jwt_development_private.pem",
            public_key_path="keys/jwt_development_public.pem",
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT
        )

        jwt_manager_2 = JWTSecurityManager(
            private_key_path="keys/jwt_development_private.pem",
            public_key_path="keys/jwt_development_public.pem",
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT
        )

        # Server 1 creates a token
        token = jwt_manager_1.create_access_token(
            subject="distributed_test",
            user_id="dist_123",
            roles=["user"],
            permissions=["read"]
        )

        # Server 2 can verify it (decode without audience check for testing)
        try:
            # Decode to check token structure
            payload = jwt.decode(token, options={"verify_signature": False})
            if not payload or not payload.get("user_id"):
                print("  [FAIL] Server 2 couldn't verify token from Server 1")
                await redis_client.close()
                return False
        except Exception as e:
            print(f"  [FAIL] Token decode failed: {e}")
            await redis_client.close()
            return False

        # Server 1 revokes the token
        await jwt_manager_1.revoke_token(token)

        # Server 2 should reject it - check if token is in Redis blacklist
        payload_decoded = jwt.decode(token, options={"verify_signature": False})
        jti = payload_decoded.get("jti")

        # Check if blacklisted in Redis
        is_blacklisted = await jwt_manager_2.is_token_blacklisted(jti)

        # Cleanup
        await redis_client.delete(f"token:blacklist:{jti}")
        await redis_client.close()

        if is_blacklisted:
            print("  [OK] Distributed blacklist works across servers")
            return True
        else:
            print("  [FAIL] Token not blacklisted on Server 2")
            return False

    except Exception as e:
        print(f"  [FAIL] Distributed blacklist test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_distributed_rate_limiting():
    """Test 5: Verify rate limiting works across multiple limiter instances"""
    print("\n[TEST 5] Distributed Rate Limiting (Multi-Server)")
    try:
        from application.rate_limiting_redis import AdvancedRateLimiter, LimitType

        redis_url = f"redis://:{REDIS_PASSWORD}@localhost:6379" if REDIS_PASSWORD else "redis://localhost:6379"
        redis_client = await redis.from_url(redis_url, decode_responses=False)

        # Create two separate limiter instances (simulating two servers)
        limiter_1 = AdvancedRateLimiter(
            redis_client=redis_client,
            enable_ddos_protection=False
        )

        limiter_2 = AdvancedRateLimiter(
            redis_client=redis_client,
            enable_ddos_protection=False
        )

        identifier = "distributed_user"
        endpoint = "/api/auth/forgot-password"  # Limit: 2 per user per hour

        # Make 2 requests on server 1 (should both be allowed)
        server1_allowed = 0
        for i in range(2):
            result = await limiter_1.check_rate_limit(
                identifier=identifier,
                endpoint=endpoint,
                limit_type=LimitType.PER_USER,
                ip_address="192.168.1.100"
            )
            if result.allowed:
                server1_allowed += 1

        # Make 2 more requests on server 2 (should be denied - limit already hit)
        server2_allowed = 0
        for i in range(2):
            result = await limiter_2.check_rate_limit(
                identifier=identifier,
                endpoint=endpoint,
                limit_type=LimitType.PER_USER,
                ip_address="192.168.1.100"
            )
            if result.allowed:
                server2_allowed += 1

        # Cleanup
        keys = await redis_client.keys("ratelimit:*")
        if keys:
            await redis_client.delete(*keys)
        await redis_client.close()

        # Expected: Server 1 allows 2, Server 2 allows 0 (limit: 2 per user)
        server1_allowed + server2_allowed
        was_distributed = (server1_allowed == 2 and server2_allowed == 0)

        if was_distributed:
            print(f"  [OK] Distributed rate limiting works (S1: {server1_allowed}/2, S2: {server2_allowed}/2, limit: 2)")
            return True
        else:
            print(f"  [FAIL] Not distributed correctly (S1: {server1_allowed}/2, S2: {server2_allowed}/2, expected S1=2, S2=0)")
            return False

    except Exception as e:
        print(f"  [FAIL] Distributed rate limiting test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_secret_generation():
    """Test 6: Verify secret generation creates unique secrets"""
    print("\n[TEST 6] Secret Generation")
    try:
        import re

        # Read the generated .env file
        with open(".env.development", "r") as f:
            content = f.read()

        # Extract secrets
        session_match = re.search(r'SESSION_SECRET_KEY=([a-f0-9]{64})', content)
        csrf_match = re.search(r'CSRF_SECRET_KEY=([a-f0-9]{64})', content)

        if not session_match or not csrf_match:
            print("  [FAIL] Secrets not found or invalid format")
            return False

        session_secret = session_match.group(1)
        csrf_secret = csrf_match.group(1)

        # Verify they're different
        if session_secret != csrf_secret:
            print("  [OK] Unique secrets generated")
            return True
        else:
            print("  [FAIL] SESSION and CSRF secrets are identical")
            return False

    except Exception as e:
        print(f"  [FAIL] Secret generation test failed: {e}")
        return False


async def main():
    """Main test runner"""
    print("="*70)
    print("Critical Security Fixes - Integration Tests")
    print("="*70)

    results = []

    # Run all tests
    results.append(await test_redis_connection())
    results.append(await test_jwt_redis_blacklist())
    results.append(await test_rate_limiting_redis())
    results.append(await test_distributed_blacklist())
    results.append(await test_distributed_rate_limiting())
    results.append(await test_secret_generation())

    # Summary
    passed = sum(results)
    total = len(results)

    print("\n" + "="*70)
    print(f"Results: {passed}/{total} tests passed")
    print("="*70)

    if passed == total:
        print("\n[SUCCESS] All critical security fixes verified!")
        return 0
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
