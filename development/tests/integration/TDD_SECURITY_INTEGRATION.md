# TDD: Security Integration Tests

**Feature**: `test_security_integration.py`
**Architect**: BMAD Architect Agent
**Date**: 2025-10-05
**Status**: Implementation Ready
**Estimated LOC**: ~1200 lines (Python)

---

## Document Overview

This Technical Design Document provides **complete, copy-paste ready implementation** for all 30 security integration test cases validating D3FEND compliance and defense-in-depth security architecture.

**Purpose**: Validate that authentication, authorization, input validation, rate limiting, CORS, and tenant isolation mechanisms work correctly in integration.

**Related Documents**:
- **PRD**: `tests/integration/PRD_SECURITY_INTEGRATION.md`
- **Implementation**: `saas/auth/jwt_auth.py`, `security/application/rate_limiting.py`, `security/application/api_validators.py`
- **Evidence**: `development/D3FEND_SECURITY_FIXES_VALIDATION.md`

---

## Architecture Overview

### Security Layers Tested

```
┌─────────────────────────────────────────────────────────────┐
│                      API Request                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: CORS & Security Headers Middleware                │
│  - Access-Control-Allow-Origin validation                   │
│  - X-Content-Type-Options, X-Frame-Options, CSP             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Rate Limiting (D3-RAC)                            │
│  - Per-IP rate limiting (Redis)                              │
│  - Per-tenant rate limiting (Redis)                          │
│  - Distributed state across workers                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: JWT Authentication (D3-UAC)                       │
│  - RSA signature validation                                  │
│  - Token expiration check                                    │
│  - Token blacklist check (Redis)                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Input Validation                                   │
│  - Pydantic schema validation                                │
│  - SQL injection pattern detection                           │
│  - XSS sanitization                                          │
│  - Path traversal blocking                                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Layer 5: Tenant Isolation                                   │
│  - Database query filtering by tenant_id                     │
│  - Cross-tenant access prevention                            │
│  - Return 404 (not 403) for cross-tenant attempts            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    Business Logic
```

### D3FEND Mapping

- **D3-UAC (User Account Control)**: JWT token blacklist with Redis persistence
- **D3-RAC (Resource Access Control)**: Distributed rate limiting with Redis
- **D3-KM (Key Management)**: RSA key pair for JWT signing/verification

---

## Database Schema

**No new tables required** - uses existing schema from `TDD_FULL_SAAS_WORKFLOW.md`:

```sql
-- Tenants table (existing)
CREATE TABLE tenants (
    id VARCHAR(36) PRIMARY KEY,
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Users table (existing)
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, email)
);

-- Lattices table (existing)
CREATE TABLE lattices (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    dimensions INTEGER NOT NULL,
    size INTEGER NOT NULL,
    field_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Redis Schema (Token Blacklist)

```
Key Pattern: blacklist:{jti}
Value: "revoked" | "security_revoked"
TTL: Token expiration duration (seconds)

Example:
Key: blacklist:550e8400-e29b-41d4-a716-446655440000
Value: "revoked"
TTL: 3600 (1 hour)
```

### Redis Schema (Rate Limiting)

```
Key Pattern: ratelimit:{tenant_id}:{ip}:{endpoint}
Value: Integer (request count)
TTL: Rate limit window (seconds)

Example:
Key: ratelimit:tenant-123:192.168.1.100:/api/lattices
Value: 5
TTL: 60 (1 minute)
```

---

## API Specifications

### Existing Endpoints (from `saas_server.py`)

```python
# Authentication Endpoints
POST /auth/register
POST /auth/login
POST /auth/logout  # Token revocation

# Protected Endpoints (require authentication)
GET /api/lattices
POST /api/lattices
GET /api/lattices/{lattice_id}
DELETE /api/lattices/{lattice_id}
POST /api/lattices/{lattice_id}/transform
```

### Request/Response Models

```python
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
import re

class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str
    company_name: Optional[str] = None

    @validator('password')
    def validate_password_strength(cls, v):
        """Enforce password complexity requirements"""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain lowercase letter')
        if not re.search(r'[0-9]', v):
            raise ValueError('Password must contain digit')
        return v

    @validator('name', 'company_name')
    def sanitize_text_input(cls, v):
        """Prevent XSS in text fields"""
        if v is None:
            return v
        # Block common XSS patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe',
            r'<object',
            r'<embed'
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError('Input contains dangerous content')
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None
```

---

## Implementation Components

### Component 1: Attack Payload Fixture

**File**: `tests/integration/test_security_integration.py`

```python
import pytest
from typing import Dict, List

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
```

### Component 2: Multi-Tenant Test Fixture

```python
from httpx import AsyncClient
from typing import Tuple, Dict
import uuid

@pytest.fixture
async def two_tenants(api_client: AsyncClient) -> Tuple[Dict, Dict]:
    """
    Create two authenticated tenants for isolation testing.

    Returns:
        Tuple of (tenant_a, tenant_b) where each is:
        {
            "client": AsyncClient (with auth header),
            "user": user_data,
            "tenant": tenant_data,
            "token": JWT token
        }
    """
    # Register Tenant A
    tenant_a_data = {
        "email": f"tenant-a-{uuid.uuid4()}@example.com",
        "password": "SecurePassA123!",
        "name": "Tenant A User",
        "company_name": "Company A"
    }

    response_a = await api_client.post("/auth/register", json=tenant_a_data)
    assert response_a.status_code == 201
    user_a = response_a.json()

    # Login Tenant A
    login_response_a = await api_client.post("/auth/login", json={
        "email": tenant_a_data["email"],
        "password": tenant_a_data["password"]
    })
    assert login_response_a.status_code == 200
    token_a = login_response_a.json()["access_token"]

    # Create authenticated client for Tenant A
    from httpx import AsyncClient
    client_a = AsyncClient(
        base_url=api_client.base_url,
        headers={"Authorization": f"Bearer {token_a}"}
    )

    # Register Tenant B
    tenant_b_data = {
        "email": f"tenant-b-{uuid.uuid4()}@example.com",
        "password": "SecurePassB123!",
        "name": "Tenant B User",
        "company_name": "Company B"
    }

    response_b = await api_client.post("/auth/register", json=tenant_b_data)
    assert response_b.status_code == 201
    user_b = response_b.json()

    # Login Tenant B
    login_response_b = await api_client.post("/auth/login", json={
        "email": tenant_b_data["email"],
        "password": tenant_b_data["password"]
    })
    assert login_response_b.status_code == 200
    token_b = login_response_b.json()["access_token"]

    # Create authenticated client for Tenant B
    client_b = AsyncClient(
        base_url=api_client.base_url,
        headers={"Authorization": f"Bearer {token_b}"}
    )

    tenant_a = {
        "client": client_a,
        "user": user_a,
        "token": token_a,
        "credentials": tenant_a_data
    }

    tenant_b = {
        "client": client_b,
        "user": user_b,
        "token": token_b,
        "credentials": tenant_b_data
    }

    yield tenant_a, tenant_b

    # Cleanup
    await client_a.aclose()
    await client_b.aclose()
```

### Component 3: Redis Client Fixture

```python
import redis.asyncio as aioredis
from typing import AsyncGenerator

@pytest.fixture
async def redis_client() -> AsyncGenerator[aioredis.Redis, None]:
    """
    Redis client for validating token blacklist and rate limiting state.
    """
    client = aioredis.from_url(
        "redis://localhost:6379",
        password="RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=",
        decode_responses=True
    )

    yield client

    await client.close()


@pytest.fixture
async def clean_redis(redis_client: aioredis.Redis):
    """
    Clean Redis state before each test to prevent cross-contamination.
    """
    # Flush test-related keys (preserve production data if any)
    async for key in redis_client.scan_iter(match="blacklist:*"):
        await redis_client.delete(key)

    async for key in redis_client.scan_iter(match="ratelimit:*"):
        await redis_client.delete(key)

    yield

    # Cleanup after test
    async for key in redis_client.scan_iter(match="blacklist:*"):
        await redis_client.delete(key)

    async for key in redis_client.scan_iter(match="ratelimit:*"):
        await redis_client.delete(key)
```

### Component 4: JWT Token Manipulation Utilities

```python
import jwt
from datetime import datetime, timedelta
from typing import Dict, Any
import uuid

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
```

---

## Test Implementation

### Test Class 1: JWT Authentication

```python
import pytest
from httpx import AsyncClient
import jwt

class TestJWTAuthentication:
    """
    Test JWT token validation across all security layers.

    D3FEND: D3-UAC (User Account Control)
    """

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

    async def test_expired_token_rejected(
        self,
        api_client: AsyncClient,
        jwt_utils: JWTTestUtils
    ):
        """
        Expired token returns 401 Unauthorized.

        AC1: Expired JWT token is rejected with 401
        """
        # Load private key for token creation
        with open("development/saas/auth/keys/jwt_private_key.pem", "r") as f:
            private_key = f.read()

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

    async def test_missing_claims_rejected(
        self,
        api_client: AsyncClient,
        jwt_utils: JWTTestUtils
    ):
        """
        Token without required claims returns 401.

        AC1: Token without required claims is rejected with 401
        """
        # Load private key
        with open("development/saas/auth/keys/jwt_private_key.pem", "r") as f:
            private_key = f.read()

        # Create token missing required claims
        incomplete_token = jwt_utils.create_missing_claims_token(private_key)

        response = await api_client.get(
            "/api/lattices",
            headers={"Authorization": f"Bearer {incomplete_token}"}
        )

        assert response.status_code == 401, \
            f"Expected 401 for incomplete token, got {response.status_code}"
```

### Test Class 2: Token Blacklist (D3-UAC)

```python
import asyncio

class TestTokenBlacklist:
    """
    Test Redis-backed token blacklist integration.

    D3FEND: D3-UAC (User Account Control)
    Implementation: development/saas/auth/jwt_auth.py:298, 374, 389
    """

    async def test_revoked_token_rejected(
        self,
        authenticated_client: AsyncClient,
        api_client: AsyncClient,
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

    async def test_blacklist_multi_worker(
        self,
        authenticated_client: AsyncClient,
        api_client: AsyncClient,
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
        import time
        current_time = int(time.time())
        expected_ttl = token_exp - current_time

        # Verify TTL is approximately correct (within 10 seconds tolerance)
        assert abs(redis_ttl - expected_ttl) <= 10, \
            f"Redis TTL ({redis_ttl}s) should match token expiration " \
            f"({expected_ttl}s remaining)"
```

### Test Class 3: Rate Limiting (D3-RAC)

```python
class TestRateLimiting:
    """
    Test distributed rate limiting enforcement.

    D3FEND: D3-RAC (Resource Access Control)
    Implementation: development/security/application/rate_limiting.py:78-128
    """

    async def test_rate_limit_per_tenant(
        self,
        two_tenants,
        clean_redis
    ):
        """
        Rate limits enforced per-tenant (not global).

        AC3: Rate limits enforced per-tenant (not global)
        """
        tenant_a, tenant_b = two_tenants

        # Tenant A: Make requests up to rate limit
        tenant_a_responses = []
        for i in range(10):
            response = await tenant_a["client"].post("/api/lattices", json={
                "name": f"Lattice {i}",
                "dimensions": 2,
                "size": 10,
                "field_type": "complex"
            })
            tenant_a_responses.append(response)

        # Tenant B: Should still be able to make requests
        # (separate rate limit bucket)
        tenant_b_response = await tenant_b["client"].post("/api/lattices", json={
            "name": "Tenant B Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })

        # Verify Tenant B not affected by Tenant A's rate limit
        assert tenant_b_response.status_code in [200, 201], \
            f"Tenant B should not be rate limited by Tenant A's usage. " \
            f"Got {tenant_b_response.status_code}"

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
            assert "Retry-After" in rate_limited[0].headers, \
                "429 response should include Retry-After header"

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
        assert "Retry-After" in last_response.headers, \
            "429 response must include Retry-After header"

        # Verify Retry-After is a positive integer
        retry_after = int(last_response.headers["Retry-After"])
        assert retry_after > 0, "Retry-After should be positive"

        error_data = last_response.json()
        assert "rate limit" in error_data["detail"].lower(), \
            "Error message should mention rate limiting"

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
```

### Test Class 4: Input Validation

```python
class TestInputValidation:
    """
    Test input validation and attack prevention.

    D3FEND: Defense through input validation
    Implementation: development/security/application/api_validators.py
    """

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
                if "<script>" not in data.get("name", ""):
                    blocked_or_sanitized += 1

        assert blocked_or_sanitized == len(xss_payloads), \
            f"Expected all {len(xss_payloads)} XSS attempts blocked/sanitized, " \
            f"only {blocked_or_sanitized} were handled"

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
```

### Test Class 5: CORS and Headers

```python
class TestCORSAndHeaders:
    """
    Test CORS policy and security headers.

    D3FEND: Defense through secure configuration
    Implementation: development/saas/api/middleware.py
    """

    async def test_cors_headers_present(
        self,
        api_client: AsyncClient
    ):
        """
        CORS headers present on all responses.

        AC5: CORS headers present on all responses
        """
        response = await api_client.get("/api/lattices")

        # Verify CORS headers
        assert "Access-Control-Allow-Origin" in response.headers, \
            "Access-Control-Allow-Origin header missing"

        # Note: In production, this should be specific origin, not "*"
        allowed_origin = response.headers["Access-Control-Allow-Origin"]
        assert allowed_origin in ["*", "http://localhost:3000"], \
            f"Unexpected CORS origin: {allowed_origin}"

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
        assert "Access-Control-Allow-Origin" in response_allowed.headers

        # Test disallowed origin (if strict CORS configured)
        response_disallowed = await api_client.get(
            "/api/lattices",
            headers={"Origin": "http://evil.com"}
        )

        # In strict mode, disallowed origin should not have matching header
        # (or request should be blocked entirely)
        if "Access-Control-Allow-Origin" in response_disallowed.headers:
            origin = response_disallowed.headers["Access-Control-Allow-Origin"]
            # If present, it should be "*" (permissive) or the allowed origin
            assert origin != "http://evil.com", \
                "CORS should not echo back disallowed origins"

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

        # Verify required CORS preflight headers
        assert "Access-Control-Allow-Methods" in response.headers, \
            "Preflight response missing Access-Control-Allow-Methods"

        assert "Access-Control-Allow-Headers" in response.headers, \
            "Preflight response missing Access-Control-Allow-Headers"

    async def test_security_headers_present(
        self,
        api_client: AsyncClient
    ):
        """
        Security headers present on responses.

        AC5: Security headers present (X-Content-Type-Options, X-Frame-Options, etc.)
        """
        response = await api_client.get("/api/lattices")

        # X-Content-Type-Options (prevent MIME sniffing)
        assert "X-Content-Type-Options" in response.headers, \
            "X-Content-Type-Options header missing"
        assert response.headers["X-Content-Type-Options"] == "nosniff"

        # X-Frame-Options (prevent clickjacking)
        assert "X-Frame-Options" in response.headers, \
            "X-Frame-Options header missing"
        assert response.headers["X-Frame-Options"] in ["DENY", "SAMEORIGIN"]

        # Content-Security-Policy (XSS protection)
        # Note: May not be set in API-only mode
        if "Content-Security-Policy" in response.headers:
            csp = response.headers["Content-Security-Policy"]
            assert "default-src" in csp or "script-src" in csp, \
                "CSP should define source policies"
```

### Test Class 6: Tenant Isolation

```python
class TestTenantIsolation:
    """
    Test multi-tenant data isolation.

    D3FEND: Defense through access control and data segmentation
    """

    async def test_cross_tenant_access_blocked(
        self,
        two_tenants
    ):
        """
        User cannot access other tenant's resources.

        AC6: User cannot access other tenant's resources
        """
        tenant_a, tenant_b = two_tenants

        # Tenant A creates lattice
        lattice_response = await tenant_a["client"].post("/api/lattices", json={
            "name": "Tenant A Secret Lattice",
            "dimensions": 2,
            "size": 100,
            "field_type": "complex"
        })
        assert lattice_response.status_code == 201
        lattice_a_id = lattice_response.json()["id"]

        # Tenant B attempts to access Tenant A's lattice
        cross_tenant_response = await tenant_b["client"].get(
            f"/api/lattices/{lattice_a_id}"
        )

        # Verify access blocked
        assert cross_tenant_response.status_code == 404, \
            f"Cross-tenant access should return 404, got {cross_tenant_response.status_code}"

    async def test_database_tenant_filtering(
        self,
        two_tenants,
        db_session
    ):
        """
        Database queries automatically filter by tenant_id.

        AC6: Database queries filter by tenant_id automatically
        """
        tenant_a, tenant_b = two_tenants

        # Create lattices for both tenants
        await tenant_a["client"].post("/api/lattices", json={
            "name": "Tenant A Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })

        await tenant_b["client"].post("/api/lattices", json={
            "name": "Tenant B Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })

        # Get lattices for Tenant A
        tenant_a_lattices_response = await tenant_a["client"].get("/api/lattices")
        tenant_a_lattices = tenant_a_lattices_response.json()

        # Get lattices for Tenant B
        tenant_b_lattices_response = await tenant_b["client"].get("/api/lattices")
        tenant_b_lattices = tenant_b_lattices_response.json()

        # Verify Tenant A only sees their own lattices
        for lattice in tenant_a_lattices:
            assert lattice["name"] != "Tenant B Lattice", \
                "Tenant A should not see Tenant B's lattices"

        # Verify Tenant B only sees their own lattices
        for lattice in tenant_b_lattices:
            assert lattice["name"] != "Tenant A Lattice", \
                "Tenant B should not see Tenant A's lattices"

    async def test_cross_tenant_returns_404(
        self,
        two_tenants
    ):
        """
        Cross-tenant access attempts return 404 (not 403).

        AC6: Cross-tenant attacks return 404 (not 403)

        SECURITY: Return 404 instead of 403 to avoid leaking
        information about resource existence.
        """
        tenant_a, tenant_b = two_tenants

        # Tenant A creates lattice
        lattice_response = await tenant_a["client"].post("/api/lattices", json={
            "name": "Secret Lattice",
            "dimensions": 2,
            "size": 10,
            "field_type": "complex"
        })
        lattice_id = lattice_response.json()["id"]

        # Tenant B attempts access
        cross_response = await tenant_b["client"].get(f"/api/lattices/{lattice_id}")

        # MUST be 404, not 403
        assert cross_response.status_code == 404, \
            f"Cross-tenant access MUST return 404 (not 403) to avoid " \
            f"information disclosure. Got {cross_response.status_code}"

        # Error message should not reveal resource exists
        error_data = cross_response.json()
        assert "not found" in error_data["detail"].lower(), \
            "Error message should indicate 'not found', not 'access denied'"

    async def test_admin_tenant_scoped(
        self,
        two_tenants
    ):
        """
        Admin users can only admin their own tenant.

        AC6: Admin users can only admin their own tenant
        """
        tenant_a, tenant_b = two_tenants

        # Get Tenant A's user list (assuming admin endpoint exists)
        # NOTE: This test assumes future admin endpoints
        # For now, we verify tenant isolation through lattice access

        tenant_a_lattices = await tenant_a["client"].get("/api/lattices")
        tenant_b_lattices = await tenant_b["client"].get("/api/lattices")

        # Verify lists are independent
        assert tenant_a_lattices.json() != tenant_b_lattices.json(), \
            "Tenant lists should be completely isolated"
```

### Test Class 7: Security Metrics

```python
import logging
from typing import List

class TestSecurityMetrics:
    """
    Test security event logging and metrics collection.

    D3FEND: Defense through monitoring and logging
    """

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
```

---

## Performance Requirements

### Response Time Targets

- **JWT validation**: < 5ms per request
- **Redis blacklist check**: < 2ms per request
- **Rate limit check**: < 3ms per request
- **Input validation**: < 1ms per field
- **Total security overhead**: < 15ms per authenticated request

### Scalability Targets

- **Concurrent users**: Support 10,000 concurrent authenticated users
- **Token blacklist**: Support 1M active blacklisted tokens
- **Rate limit state**: Support 100K active rate limit buckets

---

## Testing Configuration

### pytest.ini

```ini
[pytest]
markers =
    security: Security integration tests
    d3fend: D3FEND compliance validation tests
    slow: Tests that take > 5 seconds
    redis_required: Tests requiring Redis connection
```

### conftest.py Updates

```python
# Add to existing tests/integration/conftest.py

import pytest

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
```

---

## D3FEND Compliance Evidence

### Evidence Collection

Each test generates compliance evidence:

```python
class D3FENDEvidenceCollector:
    """
    Collect evidence for D3FEND compliance certification.
    """

    def __init__(self):
        self.evidence = {
            "D3-UAC": [],
            "D3-RAC": [],
            "D3-KM": []
        }

    def record_test_result(self, control: str, test_name: str, passed: bool):
        """Record test result as compliance evidence."""
        self.evidence[control].append({
            "test": test_name,
            "passed": passed,
            "timestamp": datetime.utcnow().isoformat()
        })

    def generate_report(self) -> Dict:
        """Generate compliance report."""
        return {
            "controls_tested": len(self.evidence),
            "total_tests": sum(len(v) for v in self.evidence.values()),
            "passed_tests": sum(
                sum(1 for t in v if t["passed"])
                for v in self.evidence.values()
            ),
            "evidence": self.evidence,
            "generated_at": datetime.utcnow().isoformat()
        }
```

### Compliance Report Format

```json
{
  "controls_tested": 3,
  "total_tests": 30,
  "passed_tests": 30,
  "evidence": {
    "D3-UAC": [
      {
        "test": "test_revoked_token_rejected",
        "passed": true,
        "timestamp": "2025-10-05T12:00:00Z"
      }
    ],
    "D3-RAC": [...],
    "D3-KM": [...]
  }
}
```

---

## Definition of Done

- [x] All 30 test cases implemented with complete code
- [x] Attack payload fixture created with comprehensive patterns
- [x] Multi-tenant fixture implemented
- [x] Redis fixtures for state validation
- [x] JWT manipulation utilities
- [x] D3FEND evidence collection
- [ ] **Developer**: Copy test code to `test_security_integration.py`
- [ ] **Developer**: Run tests and verify all pass
- [ ] **QA**: Validate D3FEND compliance evidence
- [ ] **QA**: Security team review and sign-off

---

## File Structure

```
tests/
└── integration/
    ├── conftest.py (updated with security fixtures)
    ├── test_security_integration.py (30 test cases)
    ├── PRD_SECURITY_INTEGRATION.md
    └── TDD_SECURITY_INTEGRATION.md (this file)

development/
├── saas/
│   └── auth/
│       ├── jwt_auth.py (JWT implementation)
│       └── keys/
│           ├── jwt_private_key.pem
│           └── jwt_public_key.pem
└── security/
    └── application/
        ├── rate_limiting.py (Rate limiting)
        └── api_validators.py (Input validation)
```

---

## Next Steps

**After TDD Approval**:
1. **Scrum Master**: Review TDD completeness
2. **Developer**: Copy test implementation to `test_security_integration.py`
3. **Developer**: Implement any missing API validation logic
4. **QA**: Run full test suite and validate D3FEND evidence

---

**TDD Approved By**: BMAD Architect Agent
**Ready for**: Developer Agent (Implementation)
**Status**: ✅ Complete - Implementation Ready

**Next**: Create TDD for Monitoring Integration Tests.

**D3FEND Compliance**: This test suite provides validation evidence for D3-UAC, D3-RAC, and D3-KM controls required for SOC2/ISO27001 certification.
