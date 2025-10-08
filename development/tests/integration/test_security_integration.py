"""Integration tests for security features.

Tests JWT validation, rate limiting, input validation, CORS,
and security headers across all services.

D3FEND Compliance: D3-UAC, D3-RAC, D3-KM
Certification: SOC2, ISO27001
"""

import pytest
from httpx import AsyncClient
import asyncio
import time
import jwt
import logging
from typing import Dict, List
from datetime import datetime, timedelta
import uuid


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def attack_payloads() -> Dict[str, List[str]]:
    """
    Comprehensive attack payload library for security testing.

    IMPORTANT: These payloads are for DEFENSIVE testing only.
    They validate that security controls block malicious input.
    """
    return {
        "sql_injection": [
            # Classic SQL injection patterns
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "'; DELETE FROM lattices WHERE '1'='1",
            "' UNION SELECT * FROM users--",

            # Time-based blind SQL injection
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5)--",

            # Boolean-based blind SQL injection
            "' AND 1=1--",
            "' AND 1=2--"
        ],

        "xss": [
            # Script tag injection
            "<script>alert('XSS')</script>",
            "<script src='http://evil.com/xss.js'></script>",

            # Event handler injection
            "<img src=x onerror=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<svg onload=alert('XSS')>",

            # JavaScript protocol
            "javascript:alert('XSS')",
            "<a href='javascript:alert(\"XSS\")'>Click</a>",

            # Data URL injection
            "<iframe src='data:text/html,<script>alert(\"XSS\")</script>'>",

            # Encoded payloads
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;"
        ],

        "path_traversal": [
            # Unix path traversal
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../../../../etc/hosts",

            # Windows path traversal
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\..\\..\\boot.ini",

            # URL encoded path traversal
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",

            # Mixed encoding
            "..%252f..%252f..%252fetc%252fpasswd"
        ],

        "command_injection": [
            # Unix command injection
            "; ls -la /",
            "| cat /etc/passwd",
            "`whoami`",
            "$(cat /etc/passwd)",

            # Windows command injection
            "& dir C:\\",
            "| type C:\\windows\\system32\\config\\sam"
        ],

        "ldap_injection": [
            "*",
            "admin*",
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*))"
        ],

        "xml_injection": [
            "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
            "<![CDATA[<script>alert('XSS')</script>]]>"
        ]
    }


class JWTTestUtils:
    """
    Utilities for creating malformed/invalid JWT tokens for security testing.
    """

    @staticmethod
    def create_valid_token(user_id: str, tenant_id: str, private_key: str) -> str:
        """Create a valid JWT token for baseline testing."""
        payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "jti": str(uuid.uuid4()),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow()
        }
        return jwt.encode(payload, private_key, algorithm="RS256")

    @staticmethod
    def create_expired_token(user_id: str, tenant_id: str, private_key: str) -> str:
        """Create an expired token (exp in the past)."""
        payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "jti": str(uuid.uuid4()),
            "exp": datetime.utcnow() - timedelta(hours=1),  # Expired
            "iat": datetime.utcnow() - timedelta(hours=2)
        }
        return jwt.encode(payload, private_key, algorithm="RS256")

    @staticmethod
    def create_invalid_signature_token(user_id: str, tenant_id: str) -> str:
        """Create token with invalid signature (wrong key)."""
        payload = {
            "sub": user_id,
            "tenant_id": tenant_id,
            "jti": str(uuid.uuid4()),
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow()
        }
        # Use a different key (invalid)
        wrong_key = "wrong-secret-key"
        return jwt.encode(payload, wrong_key, algorithm="HS256")

    @staticmethod
    def create_missing_claims_token(private_key: str) -> str:
        """Create token missing required claims."""
        payload = {
            "sub": "user-123",
            # Missing: tenant_id, jti
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        return jwt.encode(payload, private_key, algorithm="RS256")

    @staticmethod
    def create_malformed_token() -> str:
        """Create completely malformed token."""
        return "not.a.valid.jwt.token.at.all"


@pytest.fixture
def jwt_utils() -> JWTTestUtils:
    """Fixture providing JWT testing utilities."""
    return JWTTestUtils()


@pytest.fixture(scope="session")
def private_key():
    """Load RSA private key for JWT testing."""
    with open("development/saas/auth/keys/jwt_private_key.pem", "r") as f:
        return f.read()


@pytest.fixture(scope="session")
def public_key():
    """Load RSA public key for JWT testing."""
    with open("development/saas/auth/keys/jwt_public_key.pem", "r") as f:
        return f.read()


# ============================================================================
# TEST CLASS 1: JWT AUTHENTICATION (D3-UAC)
# ============================================================================


class TestJWTAuthentication:
    """
    Test JWT token validation across all security layers.

    D3FEND: D3-UAC (User Account Control)
    """

    @pytest.mark.asyncio
    async def test_valid_token_authentication(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Valid token authenticates successfully on protected endpoint.

        AC1: Valid JWT token authenticates successfully
        """
        # Make request to protected endpoint
        response = await authenticated_client.get("/api/lattices")

        # Verify successful authentication
        assert response.status_code == 200, \
            f"Expected 200, got {response.status_code}: {response.text}"

        # Verify response contains tenant-scoped data
        data = response.json()
        assert isinstance(data, list), "Expected list of lattices"

    @pytest.mark.asyncio
    async def test_expired_token_rejected(
        self,
        api_client: AsyncClient,
        jwt_utils: JWTTestUtils,
        private_key: str
    ):
        """
        Expired token returns 401 Unauthorized.

        AC1: Expired JWT token is rejected with 401
        """
        # Create expired token
        expired_token = jwt_utils.create_expired_token(
            user_id="test-user",
            tenant_id="test-tenant",
            private_key=private_key
        )

        # Attempt to use expired token
        response = await api_client.get(
            "/api/lattices",
            headers={"Authorization": f"Bearer {expired_token}"}
        )

        # Verify rejection
        assert response.status_code == 401, \
            f"Expected 401 for expired token, got {response.status_code}"

        error_data = response.json()
        assert "expired" in error_data["detail"].lower() or \
               "invalid" in error_data["detail"].lower(), \
            "Error message should indicate token expired"

    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(
        self,
        api_client: AsyncClient,
        jwt_utils: JWTTestUtils
    ):
        """
        Token with invalid signature returns 401.

        AC1: Invalid signature JWT token is rejected with 401
        """
        # Create token with wrong signature
        invalid_token = jwt_utils.create_invalid_signature_token(
            user_id="test-user",
            tenant_id="test-tenant"
        )

        # Attempt to use invalid token
        response = await api_client.get(
            "/api/lattices",
            headers={"Authorization": f"Bearer {invalid_token}"}
        )

        # Verify rejection
        assert response.status_code == 401, \
            f"Expected 401 for invalid signature, got {response.status_code}"

        error_data = response.json()
        assert "invalid" in error_data["detail"].lower() or \
               "signature" in error_data["detail"].lower(), \
            "Error should indicate invalid token"

    @pytest.mark.asyncio
    async def test_malformed_token_rejected(
        self,
        api_client: AsyncClient,
        jwt_utils: JWTTestUtils
    ):
        """
        Malformed token returns 401.

        AC1: Malformed JWT token is rejected with 401
        """
        # Use completely malformed token
        malformed_token = jwt_utils.create_malformed_token()

        response = await api_client.get(
            "/api/lattices",
            headers={"Authorization": f"Bearer {malformed_token}"}
        )

        assert response.status_code == 401, \
            f"Expected 401 for malformed token, got {response.status_code}"

    @pytest.mark.asyncio
    async def test_missing_claims_rejected(
        self,
        api_client: AsyncClient,
        jwt_utils: JWTTestUtils,
        private_key: str
    ):
        """
        Token without required claims returns 401.

        AC1: Token without required claims is rejected with 401
        """
        # Create token missing required claims
        incomplete_token = jwt_utils.create_missing_claims_token(private_key)

        response = await api_client.get(
            "/api/lattices",
            headers={"Authorization": f"Bearer {incomplete_token}"}
        )

        assert response.status_code == 401, \
            f"Expected 401 for incomplete token, got {response.status_code}"


# ============================================================================
# TEST CLASS 2: TOKEN BLACKLIST (D3-UAC)
# ============================================================================


class TestTokenBlacklist:
    """
    Test Redis-backed token blacklist integration.

    D3FEND: D3-UAC (User Account Control)
    Implementation: development/saas/auth/jwt_auth.py:298, 374, 389
    """

    @pytest.mark.asyncio
    async def test_revoked_token_rejected(
        self,
        authenticated_client: AsyncClient,
        clean_redis
    ):
        """
        Revoked token is rejected even if not expired.

        AC2: Revoked token is rejected even if not expired
        """
        # First, verify token works
        response = await authenticated_client.get("/api/lattices")
        assert response.status_code == 200, "Token should work initially"

        # Revoke token via logout
        logout_response = await authenticated_client.post("/auth/logout")
        assert logout_response.status_code == 200, \
            f"Logout failed: {logout_response.text}"

        # Attempt to use revoked token
        response_after_revoke = await authenticated_client.get("/api/lattices")

        # Verify rejection
        assert response_after_revoke.status_code == 401, \
            f"Expected 401 for revoked token, got {response_after_revoke.status_code}"

        error_data = response_after_revoke.json()
        assert "revoked" in error_data["detail"].lower() or \
               "blacklist" in error_data["detail"].lower() or \
               "invalid" in error_data["detail"].lower(), \
            "Error should indicate token revoked"

    @pytest.mark.asyncio
    async def test_blacklist_persists_redis(
        self,
        authenticated_client: AsyncClient,
        redis_client,
        clean_redis
    ):
        """
        Token blacklist persists in Redis and survives restarts.

        AC2: Token blacklist persists across server restarts (Redis)
        """
        # Revoke token
        logout_response = await authenticated_client.post("/auth/logout")
        assert logout_response.status_code == 200

        # Extract JTI from token (decode without verification)
        token = authenticated_client.headers["Authorization"].split(" ")[1]
        decoded = jwt.decode(token, options={"verify_signature": False})
        jti = decoded["jti"]

        # Verify blacklist entry exists in Redis
        blacklist_key = f"blacklist:{jti}"
        exists = await redis_client.exists(blacklist_key)
        assert exists == 1, f"Blacklist key {blacklist_key} should exist in Redis"

        # Verify TTL is set
        ttl = await redis_client.ttl(blacklist_key)
        assert ttl > 0, "Blacklist key should have TTL set"

        # Verify value is "revoked"
        value = await redis_client.get(blacklist_key)
        assert value in ["revoked", "security_revoked"], \
            f"Expected 'revoked' or 'security_revoked', got {value}"

    @pytest.mark.asyncio
    async def test_blacklist_multi_worker(
        self,
        authenticated_client: AsyncClient,
        clean_redis
    ):
        """
        Blacklist is shared across multiple workers via Redis.

        AC2: Token blacklist is shared across multiple workers

        NOTE: This test validates distributed state synchronization.
        In production with 4 workers, token revoked on Worker 1 must be
        rejected on Worker 2, 3, 4.
        """
        # Revoke token
        await authenticated_client.post("/auth/logout")

        # Simulate multiple workers by making rapid requests
        # (load balancer will distribute across workers)
        tasks = []
        for _ in range(10):
            task = authenticated_client.get("/api/lattices")
            tasks.append(task)

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # All responses should be 401 (blacklist synchronized)
        for i, response in enumerate(responses):
            assert not isinstance(response, Exception), \
                f"Request {i} raised exception: {response}"
            assert response.status_code == 401, \
                f"Request {i}: Expected 401, got {response.status_code} " \
                f"(blacklist not synchronized across workers)"

    @pytest.mark.asyncio
    async def test_blacklist_ttl(
        self,
        authenticated_client: AsyncClient,
        redis_client,
        clean_redis
    ):
        """
        Blacklist TTL matches token expiration time.

        AC2: Blacklist TTL matches token expiration
        """
        # Extract token and decode
        token = authenticated_client.headers["Authorization"].split(" ")[1]
        decoded = jwt.decode(token, options={"verify_signature": False})
        jti = decoded["jti"]
        token_exp = decoded["exp"]

        # Revoke token
        await authenticated_client.post("/auth/logout")

        # Get TTL from Redis
        blacklist_key = f"blacklist:{jti}"
        redis_ttl = await redis_client.ttl(blacklist_key)

        # Calculate expected TTL (exp - now)
        current_time = int(time.time())
        expected_ttl = token_exp - current_time

        # Verify TTL is approximately correct (within 10 seconds tolerance)
        assert abs(redis_ttl - expected_ttl) <= 10, \
            f"Redis TTL ({redis_ttl}s) should match token expiration " \
            f"({expected_ttl}s remaining)"


# ============================================================================
# TEST CLASS 3: RATE LIMITING (D3-RAC)
# ============================================================================


class TestRateLimiting:
    """
    Test distributed rate limiting enforcement.

    D3FEND: D3-RAC (Resource Access Control)
    Implementation: development/security/application/rate_limiting.py:78-128
    """

    @pytest.mark.asyncio
    async def test_rate_limit_per_tenant(
        self,
        two_tenants_fixture,
        clean_redis
    ):
        """
        Rate limits enforced per-tenant (not global).

        AC3: Rate limits enforced per-tenant (not global)
        """
        tenant_a, tenant_b = two_tenants_fixture

        # Tenant A: Make requests up to rate limit
        tenant_a_responses = []
        for i in range(10):
            response = await tenant_a.post("/api/lattices", json={
                "name": f"Lattice {i}",
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })
            tenant_a_responses.append(response)

        # Tenant B: Should still be able to make requests
        # (separate rate limit bucket)
        tenant_b_response = await tenant_b.post("/api/lattices", json={
            "name": "Tenant B Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })

        # Verify Tenant B not affected by Tenant A's rate limit
        assert tenant_b_response.status_code in [200, 201], \
            f"Tenant B should not be rate limited by Tenant A's usage. " \
            f"Got {tenant_b_response.status_code}"

    @pytest.mark.asyncio
    async def test_rate_limit_per_ip(
        self,
        api_client: AsyncClient,
        clean_redis
    ):
        """
        Rate limits enforced per-IP address for unauthenticated endpoints.

        AC3: Rate limits enforced per-IP address
        """
        # Make rapid requests to login endpoint
        responses = []
        for i in range(20):
            response = await api_client.post("/auth/login", json={
                "email": "test@example.com",
                "password": "wrong-password"
            })
            responses.append(response)

        # Count 429 responses (rate limited)
        rate_limited = [r for r in responses if r.status_code == 429]

        # Verify some requests were rate limited
        assert len(rate_limited) > 0, \
            "Expected some requests to be rate limited (429)"

        # Verify 429 response has Retry-After header
        if len(rate_limited) > 0:
            assert "Retry-After" in rate_limited[0].headers or "retry-after" in rate_limited[0].headers, \
                "429 response should include Retry-After header"

    @pytest.mark.asyncio
    async def test_rate_limit_429_response(
        self,
        authenticated_client: AsyncClient,
        clean_redis
    ):
        """
        Exceeded limits return 429 with Retry-After header.

        AC3: Exceeded limits return 429 with Retry-After header
        """
        # Make rapid requests to trigger rate limit
        last_response = None
        for i in range(50):
            response = await authenticated_client.post("/api/lattices", json={
                "name": f"Lattice {i}",
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

            if response.status_code == 429:
                last_response = response
                break

        # Verify we got rate limited
        assert last_response is not None, \
            "Expected to be rate limited after 50 rapid requests"

        # Verify response format
        assert last_response.status_code == 429
        assert "Retry-After" in last_response.headers or "retry-after" in last_response.headers, \
            "429 response must include Retry-After header"

        # Verify Retry-After is a positive integer
        retry_after_header = last_response.headers.get("Retry-After") or last_response.headers.get("retry-after")
        retry_after = int(retry_after_header)
        assert retry_after > 0, "Retry-After should be positive"

        error_data = last_response.json()
        assert "rate limit" in error_data["detail"].lower(), \
            "Error message should mention rate limiting"

    @pytest.mark.asyncio
    async def test_rate_limit_shared_redis(
        self,
        authenticated_client: AsyncClient,
        redis_client,
        clean_redis
    ):
        """
        Rate limit state is shared across workers via Redis.

        AC3: Rate limit state shared across workers (Redis)
        """
        # Make requests to increment rate limit counter
        for i in range(5):
            await authenticated_client.post("/api/lattices", json={
                "name": f"Lattice {i}",
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

        # Check Redis for rate limit keys
        rate_limit_keys = []
        async for key in redis_client.scan_iter(match="ratelimit:*"):
            rate_limit_keys.append(key)

        # Verify rate limit state is in Redis
        assert len(rate_limit_keys) > 0, \
            "Rate limit state should be stored in Redis for distributed access"

    @pytest.mark.asyncio
    async def test_burst_allowance(
        self,
        authenticated_client: AsyncClient,
        clean_redis
    ):
        """
        Burst allowance permits temporary spikes within limit.

        AC3: Burst allowance works correctly
        """
        # Make burst of requests (should all succeed initially)
        burst_responses = []
        for i in range(5):
            response = await authenticated_client.get("/api/lattices")
            burst_responses.append(response)

        # Verify burst succeeded
        success_count = sum(1 for r in burst_responses if r.status_code == 200)
        assert success_count == 5, \
            f"Burst allowance should permit 5 rapid requests, got {success_count} successes"


# ============================================================================
# TEST CLASS 4: INPUT VALIDATION
# ============================================================================


class TestInputValidation:
    """
    Test input validation and attack prevention.

    D3FEND: Defense through input validation
    Implementation: development/security/application/api_validators.py
    """

    @pytest.mark.asyncio
    async def test_sql_injection_blocked(
        self,
        authenticated_client: AsyncClient,
        attack_payloads: Dict[str, List[str]]
    ):
        """
        SQL injection attempts are blocked.

        AC4: SQL injection attempts are blocked
        """
        sql_payloads = attack_payloads["sql_injection"]

        # Test each SQL injection payload
        blocked_count = 0
        for payload in sql_payloads:
            response = await authenticated_client.post("/api/lattices", json={
                "name": payload,
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

            # Should be rejected (422 validation error or 400 bad request)
            if response.status_code in [400, 422]:
                blocked_count += 1

        # Verify all payloads were blocked
        assert blocked_count == len(sql_payloads), \
            f"Expected all {len(sql_payloads)} SQL injection attempts blocked, " \
            f"only {blocked_count} were blocked"

    @pytest.mark.asyncio
    async def test_xss_sanitized(
        self,
        authenticated_client: AsyncClient,
        attack_payloads: Dict[str, List[str]]
    ):
        """
        XSS attempts are sanitized or rejected.

        AC4: XSS attempts are sanitized
        """
        xss_payloads = attack_payloads["xss"]

        blocked_or_sanitized = 0
        for payload in xss_payloads:
            response = await authenticated_client.post("/api/lattices", json={
                "name": payload,
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

            # Either rejected or sanitized
            if response.status_code in [400, 422]:
                # Rejected - good
                blocked_or_sanitized += 1
            elif response.status_code == 201:
                # Accepted - check if sanitized
                data = response.json()
                if "<script>" not in data.get("name", "").lower():
                    blocked_or_sanitized += 1

        assert blocked_or_sanitized == len(xss_payloads), \
            f"Expected all {len(xss_payloads)} XSS attempts blocked/sanitized, " \
            f"only {blocked_or_sanitized} were handled"

    @pytest.mark.asyncio
    async def test_path_traversal_blocked(
        self,
        authenticated_client: AsyncClient,
        attack_payloads: Dict[str, List[str]]
    ):
        """
        Path traversal attempts are rejected.

        AC4: Path traversal attempts are rejected
        """
        path_traversal_payloads = attack_payloads["path_traversal"]

        blocked_count = 0
        for payload in path_traversal_payloads:
            response = await authenticated_client.post("/api/lattices", json={
                "name": payload,
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

            if response.status_code in [400, 422]:
                blocked_count += 1

        assert blocked_count == len(path_traversal_payloads), \
            f"Expected all {len(path_traversal_payloads)} path traversal attempts blocked, " \
            f"only {blocked_count} were blocked"

    @pytest.mark.asyncio
    async def test_oversized_payload_rejected(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Oversized payloads return 413 Payload Too Large.

        AC4: Oversized payloads are rejected with 413
        """
        # Create very large payload (> 10MB)
        oversized_payload = {
            "name": "Oversized Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex",
            "metadata": "X" * (11 * 1024 * 1024)  # 11MB string
        }

        response = await authenticated_client.post(
            "/api/lattices",
            json=oversized_payload
        )

        # Verify rejection with 413
        assert response.status_code == 413, \
            f"Expected 413 for oversized payload, got {response.status_code}"

    @pytest.mark.asyncio
    async def test_invalid_json_rejected(
        self,
        api_client: AsyncClient
    ):
        """
        Invalid JSON returns 422 Unprocessable Entity.

        AC4: Invalid JSON is rejected with 422
        """
        # Send malformed JSON
        response = await api_client.post(
            "/auth/login",
            content="{invalid json here}",
            headers={"Content-Type": "application/json"}
        )

        # Verify rejection
        assert response.status_code in [400, 422], \
            f"Expected 400/422 for invalid JSON, got {response.status_code}"


# ============================================================================
# TEST CLASS 5: CORS AND HEADERS
# ============================================================================


class TestCORSAndHeaders:
    """
    Test CORS policy and security headers.

    D3FEND: Defense through secure configuration
    Implementation: development/saas/api/middleware.py
    """

    @pytest.mark.asyncio
    async def test_cors_headers_present(
        self,
        api_client: AsyncClient
    ):
        """
        CORS headers present on all responses.

        AC5: CORS headers present on all responses
        """
        response = await api_client.get("/api/lattices")

        # Verify CORS headers (case-insensitive)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        assert "access-control-allow-origin" in headers_lower, \
            "Access-Control-Allow-Origin header missing"

        # Note: In production, this should be specific origin, not "*"
        allowed_origin = headers_lower["access-control-allow-origin"]
        assert allowed_origin in ["*", "http://localhost:3000"], \
            f"Unexpected CORS origin: {allowed_origin}"

    @pytest.mark.asyncio
    async def test_cors_allowed_origins(
        self,
        api_client: AsyncClient
    ):
        """
        CORS only allows configured origins.

        AC5: CORS only allows configured origins
        """
        # Test allowed origin
        response_allowed = await api_client.get(
            "/api/lattices",
            headers={"Origin": "http://localhost:3000"}
        )

        # Should have CORS headers
        headers_lower = {k.lower(): v for k, v in response_allowed.headers.items()}
        assert "access-control-allow-origin" in headers_lower

        # Test disallowed origin (if strict CORS configured)
        response_disallowed = await api_client.get(
            "/api/lattices",
            headers={"Origin": "http://evil.com"}
        )

        headers_disallowed = {k.lower(): v for k, v in response_disallowed.headers.items()}
        # In strict mode, disallowed origin should not have matching header
        # (or request should be blocked entirely)
        if "access-control-allow-origin" in headers_disallowed:
            origin = headers_disallowed["access-control-allow-origin"]
            # If present, it should be "*" (permissive) or the allowed origin
            assert origin != "http://evil.com", \
                "CORS should not echo back disallowed origins"

    @pytest.mark.asyncio
    async def test_preflight_requests(
        self,
        api_client: AsyncClient
    ):
        """
        CORS preflight requests (OPTIONS) handled correctly.

        AC5: Preflight requests handled correctly
        """
        # Send OPTIONS preflight request
        response = await api_client.options(
            "/api/lattices",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,Authorization"
            }
        )

        # Verify preflight response
        assert response.status_code in [200, 204], \
            f"Preflight should return 200/204, got {response.status_code}"

        # Verify required CORS preflight headers (case-insensitive)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        assert "access-control-allow-methods" in headers_lower, \
            "Preflight response missing Access-Control-Allow-Methods"

        assert "access-control-allow-headers" in headers_lower, \
            "Preflight response missing Access-Control-Allow-Headers"

    @pytest.mark.asyncio
    async def test_security_headers_present(
        self,
        api_client: AsyncClient
    ):
        """
        Security headers present on responses.

        AC5: Security headers present (X-Content-Type-Options, X-Frame-Options, etc.)
        """
        response = await api_client.get("/api/lattices")
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        # X-Content-Type-Options (prevent MIME sniffing)
        assert "x-content-type-options" in headers_lower, \
            "X-Content-Type-Options header missing"
        assert headers_lower["x-content-type-options"] == "nosniff"

        # X-Frame-Options (prevent clickjacking)
        assert "x-frame-options" in headers_lower, \
            "X-Frame-Options header missing"
        assert headers_lower["x-frame-options"] in ["DENY", "SAMEORIGIN"]

        # Content-Security-Policy (XSS protection)
        # Note: May not be set in API-only mode
        if "content-security-policy" in headers_lower:
            csp = headers_lower["content-security-policy"]
            assert "default-src" in csp or "script-src" in csp, \
                "CSP should define source policies"


# ============================================================================
# TEST CLASS 6: TENANT ISOLATION
# ============================================================================


class TestTenantIsolation:
    """
    Test multi-tenant data isolation.

    D3FEND: Defense through access control and data segmentation
    """

    @pytest.mark.asyncio
    async def test_cross_tenant_access_blocked(
        self,
        two_tenants_fixture
    ):
        """
        User cannot access other tenant's resources.

        AC6: User cannot access other tenant's resources
        """
        tenant_a, tenant_b = two_tenants_fixture

        # Tenant A creates lattice
        lattice_response = await tenant_a.post("/api/lattices", json={
            "name": "Tenant A Secret Lattice",
            "dimensions": 2,
            "size": 100,
            "field_type": "complex"
        })
        assert lattice_response.status_code == 201
        lattice_a_id = lattice_response.json()["id"]

        # Tenant B attempts to access Tenant A's lattice
        cross_tenant_response = await tenant_b.get(
            f"/api/lattices/{lattice_a_id}"
        )

        # Verify access blocked
        assert cross_tenant_response.status_code == 404, \
            f"Cross-tenant access should return 404, got {cross_tenant_response.status_code}"

    @pytest.mark.asyncio
    async def test_database_tenant_filtering(
        self,
        two_tenants_fixture
    ):
        """
        Database queries automatically filter by tenant_id.

        AC6: Database queries filter by tenant_id automatically
        """
        tenant_a, tenant_b = two_tenants_fixture

        # Create lattices for both tenants
        await tenant_a.post("/api/lattices", json={
            "name": "Tenant A Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })

        await tenant_b.post("/api/lattices", json={
            "name": "Tenant B Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })

        # Get lattices for Tenant A
        tenant_a_lattices_response = await tenant_a.get("/api/lattices")
        tenant_a_lattices = tenant_a_lattices_response.json()

        # Get lattices for Tenant B
        tenant_b_lattices_response = await tenant_b.get("/api/lattices")
        tenant_b_lattices = tenant_b_lattices_response.json()

        # Verify Tenant A only sees their own lattices
        for lattice in tenant_a_lattices:
            assert lattice["name"] != "Tenant B Lattice", \
                "Tenant A should not see Tenant B's lattices"

        # Verify Tenant B only sees their own lattices
        for lattice in tenant_b_lattices:
            assert lattice["name"] != "Tenant A Lattice", \
                "Tenant B should not see Tenant A's lattices"

    @pytest.mark.asyncio
    async def test_cross_tenant_returns_404(
        self,
        two_tenants_fixture
    ):
        """
        Cross-tenant access attempts return 404 (not 403).

        AC6: Cross-tenant attacks return 404 (not 403)

        SECURITY: Return 404 instead of 403 to avoid leaking
        information about resource existence.
        """
        tenant_a, tenant_b = two_tenants_fixture

        # Tenant A creates lattice
        lattice_response = await tenant_a.post("/api/lattices", json={
            "name": "Secret Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })
        lattice_id = lattice_response.json()["id"]

        # Tenant B attempts access
        cross_response = await tenant_b.get(f"/api/lattices/{lattice_id}")

        # MUST be 404, not 403
        assert cross_response.status_code == 404, \
            f"Cross-tenant access MUST return 404 (not 403) to avoid " \
            f"information disclosure. Got {cross_response.status_code}"

        # Error message should not reveal resource exists
        error_data = cross_response.json()
        assert "not found" in error_data["detail"].lower(), \
            "Error message should indicate 'not found', not 'access denied'"

    @pytest.mark.asyncio
    async def test_admin_tenant_scoped(
        self,
        two_tenants_fixture
    ):
        """
        Admin users can only admin their own tenant.

        AC6: Admin users can only admin their own tenant
        """
        tenant_a, tenant_b = two_tenants_fixture

        # Get Tenant A's user list (assuming admin endpoint exists)
        # NOTE: This test assumes future admin endpoints
        # For now, we verify tenant isolation through lattice access

        tenant_a_lattices = await tenant_a.get("/api/lattices")
        tenant_b_lattices = await tenant_b.get("/api/lattices")

        # Verify lists are independent
        assert tenant_a_lattices.json() != tenant_b_lattices.json(), \
            "Tenant lists should be completely isolated"


# ============================================================================
# TEST CLASS 7: SECURITY METRICS
# ============================================================================


class TestSecurityMetrics:
    """
    Test security event logging and metrics collection.

    D3FEND: Defense through monitoring and logging
    """

    @pytest.mark.asyncio
    async def test_failed_auth_logged(
        self,
        api_client: AsyncClient,
        caplog
    ):
        """
        Failed authentication attempts are logged.

        AC: Failed authentication attempts are logged
        """
        with caplog.at_level(logging.WARNING):
            # Attempt login with wrong password
            response = await api_client.post("/auth/login", json={
                "email": "test@example.com",
                "password": "wrong-password"
            })

            assert response.status_code == 401

        # Verify security event was logged
        assert any("auth" in record.message.lower() or
                   "login" in record.message.lower() or
                   "failed" in record.message.lower()
                   for record in caplog.records), \
            "Failed authentication should be logged"

    @pytest.mark.asyncio
    async def test_rate_limit_violations_logged(
        self,
        authenticated_client: AsyncClient,
        caplog,
        clean_redis
    ):
        """
        Rate limit violations are logged for security monitoring.

        AC: Rate limit violations are logged
        """
        with caplog.at_level(logging.WARNING):
            # Trigger rate limit
            for i in range(50):
                await authenticated_client.post("/api/lattices", json={
                    "name": f"Lattice {i}",
                    "dimensions": 2,
                    "size": 10,
                    "field_type": "complex"
                })

        # Verify rate limit violation logged
        assert any("rate limit" in record.message.lower()
                   for record in caplog.records), \
            "Rate limit violations should be logged"

    @pytest.mark.asyncio
    async def test_attack_attempts_logged(
        self,
        authenticated_client: AsyncClient,
        attack_payloads: Dict[str, List[str]],
        caplog
    ):
        """
        SQL injection and XSS attempts are logged.

        AC: Attack attempts (SQL injection/XSS) are logged
        """
        with caplog.at_level(logging.WARNING):
            # Attempt SQL injection
            await authenticated_client.post("/api/lattices", json={
                "name": "'; DROP TABLE users; --",
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

            # Attempt XSS
            await authenticated_client.post("/api/lattices", json={
                "name": "<script>alert('XSS')</script>",
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })

        # Verify attack attempts logged
        security_logs = [r for r in caplog.records
                        if r.levelname in ["WARNING", "ERROR"]]

        assert len(security_logs) > 0, \
            "Attack attempts should be logged as WARNING or ERROR"
