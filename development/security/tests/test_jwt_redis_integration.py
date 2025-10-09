#!/usr/bin/env python3
"""
Integration tests for JWT Security with Redis backend
Tests the critical fix for distributed token blacklist
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import redis.asyncio as redis
import jwt
from application.jwt_security_redis import JWTSecurityManager, SecurityLevel, TokenType


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


async def test_jwt_redis_connection(redis_client: redis.Redis, results: TestResults):
    """Test 1: Verify Redis connection works"""
    try:
        pong = await redis_client.ping()
        if pong:
            results.add_pass("Redis connection")
        else:
            results.add_fail("Redis connection", "PING did not return PONG")
    except Exception as e:
        results.add_fail("Redis connection", str(e))


async def test_jwt_initialization(jwt_manager: JWTSecurityManager, results: TestResults):
    """Test 2: Verify JWT manager initializes with Redis"""
    try:
        if jwt_manager.redis_client is not None:
            results.add_pass("JWT manager initialization with Redis")
        else:
            results.add_fail("JWT manager initialization with Redis", "redis_client is None")
    except Exception as e:
        results.add_fail("JWT manager initialization with Redis", str(e))


async def test_token_creation(jwt_manager: JWTSecurityManager, results: TestResults):
    """Test 3: Verify token creation works"""
    try:
        token = jwt_manager.create_access_token(
            user_id="test_user_001", additional_claims={"role": "admin"}
        )

        if token and len(token) > 0:
            results.add_pass("Token creation")
            return token
        else:
            results.add_fail("Token creation", "Empty token returned")
            return None
    except Exception as e:
        results.add_fail("Token creation", str(e))
        return None


async def test_token_verification(
    jwt_manager: JWTSecurityManager, token: str, results: TestResults
):
    """Test 4: Verify token validation works"""
    try:
        payload = await jwt_manager.verify_token(token, TokenType.ACCESS)

        if payload and payload.get("user_id") == "test_user_001":
            results.add_pass("Token verification")
            return payload
        else:
            results.add_fail("Token verification", f"Invalid payload: {payload}")
            return None
    except Exception as e:
        results.add_fail("Token verification", str(e))
        return None


async def test_token_revocation(jwt_manager: JWTSecurityManager, token: str, results: TestResults):
    """Test 5: Verify token can be revoked and stored in Redis"""
    try:
        # Revoke the token
        revoked = await jwt_manager.revoke_token(token)

        if not revoked:
            results.add_fail("Token revocation", "revoke_token returned False")
            return

        # Verify it's in Redis
        payload = jwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")

        exists = await jwt_manager.redis_client.exists(f"token:blacklist:{jti}")

        if exists:
            results.add_pass("Token revocation (stored in Redis)")
        else:
            results.add_fail(
                "Token revocation (stored in Redis)", "Token not found in Redis blacklist"
            )
    except Exception as e:
        results.add_fail("Token revocation (stored in Redis)", str(e))


async def test_blacklist_check(jwt_manager: JWTSecurityManager, token: str, results: TestResults):
    """Test 6: Verify blacklisted tokens are rejected"""
    try:
        # Try to verify revoked token
        try:
            await jwt_manager.verify_token(token, TokenType.ACCESS)
            results.add_fail("Blacklist enforcement", "Revoked token was accepted")
        except Exception as e:
            if "blacklisted" in str(e).lower() or "revoked" in str(e).lower():
                results.add_pass("Blacklist enforcement")
            else:
                results.add_fail("Blacklist enforcement", f"Wrong error: {e}")
    except Exception as e:
        results.add_fail("Blacklist enforcement", str(e))


async def test_distributed_blacklist(redis_client: redis.Redis, results: TestResults):
    """Test 7: Verify blacklist works across multiple JWT manager instances (simulating multiple servers)"""
    try:
        # Create two separate JWT manager instances (simulating two servers)
        private_key_path = "keys/jwt_development_private.pem"
        public_key_path = "keys/jwt_development_public.pem"

        jwt_manager_1 = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT,
        )

        jwt_manager_2 = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT,
        )

        # Server 1 creates a token
        token = jwt_manager_1.create_access_token(user_id="distributed_test_user")

        # Server 2 can verify it
        payload = await jwt_manager_2.verify_token(token, TokenType.ACCESS)
        if not payload:
            results.add_fail(
                "Distributed blacklist", "Server 2 couldn't verify token from Server 1"
            )
            return

        # Server 1 revokes the token
        await jwt_manager_1.revoke_token(token)

        # Server 2 should reject it
        try:
            await jwt_manager_2.verify_token(token, TokenType.ACCESS)
            results.add_fail(
                "Distributed blacklist", "Server 2 accepted revoked token from Server 1"
            )
        except Exception as e:
            if "blacklisted" in str(e).lower() or "revoked" in str(e).lower():
                results.add_pass("Distributed blacklist (multi-server)")
            else:
                results.add_fail("Distributed blacklist", f"Wrong error: {e}")

    except Exception as e:
        results.add_fail("Distributed blacklist (multi-server)", str(e))


async def test_user_level_revocation(jwt_manager: JWTSecurityManager, results: TestResults):
    """Test 8: Verify user-level token revocation works"""
    try:
        user_id = "user_revocation_test"

        # Create multiple tokens for the same user
        token1 = jwt_manager.create_access_token(user_id=user_id)
        token2 = jwt_manager.create_access_token(user_id=user_id)

        # Both should work
        await jwt_manager.verify_token(token1, TokenType.ACCESS)
        await jwt_manager.verify_token(token2, TokenType.ACCESS)

        # Revoke all tokens for this user
        revocation_time = await jwt_manager.revoke_all_user_tokens(user_id)

        if revocation_time == 0:
            results.add_fail("User-level revocation", "revoke_all_user_tokens returned 0")
            return

        # Both tokens should now be rejected
        rejected_count = 0
        for token in [token1, token2]:
            try:
                await jwt_manager.verify_token(token, TokenType.ACCESS)
            except Exception:
                rejected_count += 1

        if rejected_count == 2:
            results.add_pass("User-level token revocation")
        else:
            results.add_fail(
                "User-level token revocation", f"Only {rejected_count}/2 tokens rejected"
            )

    except Exception as e:
        results.add_fail("User-level token revocation", str(e))


async def test_account_locking(jwt_manager: JWTSecurityManager, results: TestResults):
    """Test 9: Verify account locking after failed attempts"""
    try:
        user_id = "account_lock_test"

        # Record 5 failed attempts
        for i in range(5):
            await jwt_manager.record_failed_attempt(user_id)

        # Account should be locked
        is_locked = await jwt_manager.is_account_locked(user_id)

        if is_locked:
            results.add_pass("Account locking after failed attempts")
        else:
            results.add_fail(
                "Account locking after failed attempts", "Account not locked after 5 failures"
            )

    except Exception as e:
        results.add_fail("Account locking after failed attempts", str(e))


async def test_ttl_expiry(
    jwt_manager: JWTSecurityManager, redis_client: redis.Redis, results: TestResults
):
    """Test 10: Verify Redis TTL is set correctly on blacklisted tokens"""
    try:
        # Create a short-lived token (1 minute)
        token = jwt_manager.create_access_token(user_id="ttl_test_user", custom_expiry_minutes=1)

        # Revoke it
        await jwt_manager.revoke_token(token)

        # Check TTL in Redis
        payload = jwt.decode(token, options={"verify_signature": False})
        jti = payload.get("jti")

        ttl = await redis_client.ttl(f"token:blacklist:{jti}")

        # TTL should be around 60 seconds (give or take a few seconds for processing)
        if 50 <= ttl <= 70:
            results.add_pass("Redis TTL on blacklisted tokens")
        else:
            results.add_fail("Redis TTL on blacklisted tokens", f"TTL is {ttl}, expected ~60")

    except Exception as e:
        results.add_fail("Redis TTL on blacklisted tokens", str(e))


async def test_persistence_across_restart(redis_client: redis.Redis, results: TestResults):
    """Test 11: Verify blacklist persists (simulating server restart)"""
    try:
        private_key_path = "keys/jwt_development_private.pem"
        public_key_path = "keys/jwt_development_public.pem"

        # Create first JWT manager instance
        jwt_manager_1 = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT,
        )

        # Create and revoke a token
        token = jwt_manager_1.create_access_token(user_id="persistence_test")
        await jwt_manager_1.revoke_token(token)

        # Simulate server restart by creating new instance
        jwt_manager_2 = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT,
        )

        # Token should still be blacklisted
        try:
            await jwt_manager_2.verify_token(token, TokenType.ACCESS)
            results.add_fail("Blacklist persistence", "Token accepted after simulated restart")
        except Exception as e:
            if "blacklisted" in str(e).lower() or "revoked" in str(e).lower():
                results.add_pass("Blacklist persistence (survives restart)")
            else:
                results.add_fail("Blacklist persistence", f"Wrong error: {e}")

    except Exception as e:
        results.add_fail("Blacklist persistence (survives restart)", str(e))


async def cleanup_redis(redis_client: redis.Redis):
    """Clean up test data from Redis"""
    try:
        # Delete all test keys
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match="token:*", count=100)
            if keys:
                await redis_client.delete(*keys)
            if cursor == 0:
                break

        # Delete user revocation keys
        cursor = 0
        while True:
            cursor, keys = await redis_client.scan(cursor, match="user:*", count=100)
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
    print("JWT Redis Integration Tests - Critical Security Fix Verification")
    print("=" * 70)
    print()

    results = TestResults()
    redis_client = None
    jwt_manager = None

    try:
        # Initialize Redis connection
        print("[INFO] Connecting to Redis at localhost:6379...")
        redis_client = await redis.from_url("redis://localhost:6379", decode_responses=False)

        # Test Redis connection
        await test_jwt_redis_connection(redis_client, results)

        # Initialize JWT manager
        print("[INFO] Initializing JWT Security Manager with Redis...")
        private_key_path = "keys/jwt_development_private.pem"
        public_key_path = "keys/jwt_development_public.pem"

        jwt_manager = JWTSecurityManager(
            private_key_path=private_key_path,
            public_key_path=public_key_path,
            redis_client=redis_client,
            security_level=SecurityLevel.STRICT,
        )

        # Run tests
        print("[INFO] Running integration tests...\n")

        await test_jwt_initialization(jwt_manager, results)

        token = await test_token_creation(jwt_manager, results)
        if token:
            payload = await test_token_verification(jwt_manager, token, results)
            if payload:
                await test_token_revocation(jwt_manager, token, results)
                await test_blacklist_check(jwt_manager, token, results)

        await test_distributed_blacklist(redis_client, results)
        await test_user_level_revocation(jwt_manager, results)
        await test_account_locking(jwt_manager, results)
        await test_ttl_expiry(jwt_manager, redis_client, results)
        await test_persistence_across_restart(redis_client, results)

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
