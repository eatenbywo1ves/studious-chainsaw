# PRD: Security Integration Tests

**Feature**: `test_security_integration.py`
**Product Manager**: BMAD Product Manager Agent
**Date**: 2025-10-05
**Priority**: CRITICAL (D3FEND Compliance)
**Effort Estimate**: Medium (4-6 hours)

---

## User Story

As a **SaaS security engineer**, I want **comprehensive integration tests validating all security mechanisms work together** so that I can **achieve D3FEND compliance and prevent security breaches in production**.

---

## Business Context

The multi-tenant SaaS platform implements **multiple security layers**:
- JWT authentication with RSA signing
- Redis-backed token blacklist (D3-UAC)
- Distributed rate limiting (D3-RAC)
- Input validation pipeline
- CORS and security headers
- Tenant isolation at database level

**Current State**:
- Individual security components have unit tests
- Load testing validated Redis integration @ 10K users
- **Gap**: No integration tests validating security layers work together

**Compliance Requirement**: D3FEND compliance requires validated security controls working in production.

---

## Acceptance Criteria

### AC1: JWT Token Validation Across All Services
- [ ] Valid JWT token authenticates successfully
- [ ] Expired JWT token is rejected with 401
- [ ] Invalid signature JWT token is rejected with 401
- [ ] Malformed JWT token is rejected with 401
- [ ] Token without required claims is rejected with 401
- [ ] Token validation works across all API endpoints

### AC2: Token Blacklist Integration (D3-UAC)
- [ ] Revoked token is rejected even if not expired
- [ ] Token blacklist persists across server restarts (Redis)
- [ ] Token blacklist is shared across multiple workers
- [ ] Blacklist check happens before endpoint authorization
- [ ] Blacklist TTL matches token expiration

### AC3: Rate Limiting Enforcement (D3-RAC)
- [ ] Rate limits enforced per-tenant (not global)
- [ ] Rate limits enforced per-IP address
- [ ] Exceeded limits return 429 with Retry-After header
- [ ] Rate limit state shared across workers (Redis)
- [ ] Burst allowance works correctly
- [ ] Rate limits reset after window expires

### AC4: Input Validation Pipeline
- [ ] SQL injection attempts are blocked
- [ ] XSS attempts are sanitized
- [ ] Path traversal attempts are rejected
- [ ] Oversized payloads are rejected with 413
- [ ] Invalid JSON is rejected with 422
- [ ] Schema validation errors provide helpful messages

### AC5: CORS and Security Headers
- [ ] CORS headers present on all responses
- [ ] CORS only allows configured origins
- [ ] Preflight requests handled correctly
- [ ] Security headers present (X-Content-Type-Options, X-Frame-Options, etc.)
- [ ] CSP header configured appropriately

### AC6: Tenant Isolation
- [ ] User cannot access other tenant's resources
- [ ] Database queries filter by tenant_id automatically
- [ ] Cross-tenant attacks return 404 (not 403)
- [ ] Admin users can only admin their own tenant
- [ ] API keys are scoped to tenant

---

## Technical Requirements

### Security Components Tested

**Authentication** (`saas/auth/jwt_auth.py`):
- RSA key pair loading
- Token generation with proper claims
- Token validation and expiration
- Token blacklist check

**Rate Limiting** (`security/application/rate_limiting.py`):
- Per-IP rate limiting
- Per-user rate limiting
- Per-endpoint rate limiting
- DDoS protection

**Input Validation** (`security/application/api_validators.py`):
- Pydantic schema validation
- SQL injection prevention
- XSS sanitization
- Path traversal blocking

**Middleware** (`saas/api/middleware.py`):
- CORS handling
- Security headers
- Request logging

### API Endpoints Tested

**Authentication Endpoints**:
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout` (token revocation)
- `POST /api/v1/auth/refresh`

**Protected Endpoints** (all require auth):
- `GET /api/v1/lattices`
- `POST /api/v1/lattices`
- `GET /api/v1/lattices/{id}`
- `POST /api/v1/lattices/{id}/transform`

### Test Scenarios

#### Scenario 1: JWT Lifecycle
1. User registers and receives token
2. Token used to access protected endpoint (success)
3. Token revoked via logout
4. Revoked token rejected on next request (401)
5. Blacklist persists across requests

#### Scenario 2: Rate Limit Attack
1. User makes 100 rapid requests to login endpoint
2. First 5 requests succeed
3. Requests 6-100 return 429
4. Retry-After header indicates wait time
5. After window, requests succeed again

#### Scenario 3: SQL Injection Attempt
```python
malicious_input = "'; DROP TABLE users; --"
response = await client.post("/api/v1/lattices", json={
    "name": malicious_input
})
assert response.status_code == 422  # Validation error
# Verify users table still exists
```

#### Scenario 4: Cross-Tenant Access
1. Tenant A creates lattice (ID: abc123)
2. Tenant B attempts to access lattice abc123
3. Request returns 404 (not 403, don't leak existence)
4. Database query filtered by tenant_id

#### Scenario 5: CORS Preflight
```python
response = await client.options("/api/v1/lattices", headers={
    "Origin": "https://allowed-origin.com",
    "Access-Control-Request-Method": "POST"
})
assert "Access-Control-Allow-Origin" in response.headers
```

### Security Metrics Collected

- Failed authentication attempts per IP
- Rate limit violations per tenant
- Blocked SQL injection attempts
- Cross-tenant access attempts blocked
- CORS violations

---

## Edge Cases

### EC1: Token Replay Attack
**Scenario**: Attacker intercepts valid token and reuses it
**Expected**: Token works until revoked or expired (HTTPS prevents interception in production)

### EC2: Race Condition in Token Revocation
**Scenario**: User logs out while concurrent request is in-flight
**Expected**: In-flight request may complete, subsequent requests blocked

### EC3: Rate Limit Bypass via Multiple IPs
**Scenario**: Attacker uses multiple IP addresses to bypass per-IP rate limit
**Expected**: Per-user rate limit still enforced

### EC4: Malformed Security Headers
**Scenario**: Client sends malformed CORS headers
**Expected**: Request rejected or headers ignored, no server crash

### EC5: Very Large Token Claims
**Scenario**: JWT token with unusually large claims payload
**Expected**: Token rejected if exceeds size limit

---

## Success Metrics

### Security Posture
- **Target**: 100% of security controls validated
- **Measure**: All acceptance criteria passing

### Attack Prevention
- **Target**: 100% of attack scenarios blocked
- **Measure**: SQL injection, XSS, path traversal attempts fail

### D3FEND Compliance
- **Target**: D3-UAC and D3-RAC validated in integration
- **Measure**: Token blacklist and rate limiting working

### Performance
- **Target**: Security checks add < 10ms latency
- **Measure**: Request timing with security vs. without

---

## Test Structure

```python
# tests/integration/test_security_integration.py

import pytest
from httpx import AsyncClient


class TestJWTAuthentication:
    """Test JWT token validation across services"""

    async def test_valid_token_authentication(authenticated_client):
        """Valid token authenticates successfully"""
        pass

    async def test_expired_token_rejected(api_client):
        """Expired token returns 401"""
        pass

    async def test_invalid_signature_rejected(api_client):
        """Token with invalid signature returns 401"""
        pass

    async def test_malformed_token_rejected(api_client):
        """Malformed token returns 401"""
        pass

    async def test_missing_claims_rejected(api_client):
        """Token missing required claims returns 401"""
        pass


class TestTokenBlacklist:
    """Test Redis-backed token blacklist (D3-UAC)"""

    async def test_revoked_token_rejected(authenticated_client):
        """Revoked token rejected even if not expired"""
        pass

    async def test_blacklist_persists_redis(authenticated_client, redis_client):
        """Blacklist persists in Redis"""
        pass

    async def test_blacklist_multi_worker(authenticated_client):
        """Blacklist shared across workers"""
        pass

    async def test_blacklist_ttl(authenticated_client, redis_client):
        """Blacklist TTL matches token expiration"""
        pass


class TestRateLimiting:
    """Test distributed rate limiting (D3-RAC)"""

    async def test_rate_limit_per_tenant(authenticated_client):
        """Rate limits enforced per-tenant"""
        pass

    async def test_rate_limit_per_ip(api_client):
        """Rate limits enforced per-IP"""
        pass

    async def test_rate_limit_429_response(api_client):
        """Exceeded limits return 429 with Retry-After"""
        pass

    async def test_rate_limit_shared_redis(authenticated_client):
        """Rate limit state shared across workers"""
        pass

    async def test_burst_allowance(authenticated_client):
        """Burst allowance works correctly"""
        pass


class TestInputValidation:
    """Test input validation and sanitization"""

    async def test_sql_injection_blocked(authenticated_client):
        """SQL injection attempts blocked"""
        pass

    async def test_xss_sanitized(authenticated_client):
        """XSS attempts sanitized"""
        pass

    async def test_path_traversal_blocked(authenticated_client):
        """Path traversal attempts rejected"""
        pass

    async def test_oversized_payload_rejected(authenticated_client):
        """Oversized payloads return 413"""
        pass

    async def test_invalid_json_rejected(api_client):
        """Invalid JSON returns 422"""
        pass


class TestCORSAndHeaders:
    """Test CORS and security headers"""

    async def test_cors_headers_present(api_client):
        """CORS headers present on responses"""
        pass

    async def test_cors_allowed_origins(api_client):
        """CORS only allows configured origins"""
        pass

    async def test_preflight_requests(api_client):
        """Preflight requests handled correctly"""
        pass

    async def test_security_headers_present(api_client):
        """Security headers present (X-Content-Type-Options, etc.)"""
        pass


class TestTenantIsolation:
    """Test tenant isolation enforcement"""

    async def test_cross_tenant_access_blocked(authenticated_client):
        """User cannot access other tenant's resources"""
        pass

    async def test_database_tenant_filtering(authenticated_client, db_session):
        """Database queries filter by tenant_id"""
        pass

    async def test_cross_tenant_returns_404(authenticated_client):
        """Cross-tenant attempts return 404 (not 403)"""
        pass

    async def test_admin_tenant_scoped(authenticated_client):
        """Admin users only admin their own tenant"""
        pass


class TestSecurityMetrics:
    """Test security event logging and metrics"""

    async def test_failed_auth_logged(api_client):
        """Failed authentication attempts are logged"""
        pass

    async def test_rate_limit_violations_logged(api_client):
        """Rate limit violations are logged"""
        pass

    async def test_attack_attempts_logged(authenticated_client):
        """SQL injection/XSS attempts are logged"""
        pass
```

### Estimated Test Count

- JWT Authentication: 5 tests
- Token Blacklist: 4 tests
- Rate Limiting: 5 tests
- Input Validation: 5 tests
- CORS and Headers: 4 tests
- Tenant Isolation: 4 tests
- Security Metrics: 3 tests

**Total**: 30 test cases

---

## Dependencies

### Infrastructure
- Redis (token blacklist and rate limiting)
- PostgreSQL (tenant data)
- Multi-worker deployment (for distributed state testing)

### Python Packages
- pytest
- pytest-asyncio
- httpx
- redis
- cryptography (JWT RSA keys)
- pydantic (validation)

### Existing Code
- `saas/auth/jwt_auth.py` - JWT implementation
- `security/application/rate_limiting.py` - Rate limiting
- `security/application/api_validators.py` - Input validation
- `saas/api/middleware.py` - CORS and security headers

---

## Test Fixtures Required

### Multi-Tenant Fixture
```python
@pytest.fixture
async def two_tenants(api_client):
    """Create two tenants for isolation testing"""
    tenant_a = await create_tenant(api_client, "tenant-a@example.com")
    tenant_b = await create_tenant(api_client, "tenant-b@example.com")
    return tenant_a, tenant_b
```

### Attack Payloads Fixture
```python
@pytest.fixture
def attack_payloads():
    """Common attack payloads for testing"""
    return {
        "sql_injection": [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--"
        ],
        "xss": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd"
        ]
    }
```

---

## Out of Scope

- Penetration testing (covered separately)
- Security audit (covered separately)
- SSL/TLS testing (infrastructure level)
- DDoS mitigation testing (covered in load tests)
- Intrusion detection system testing

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| False positives in attack detection | Medium | Low | Use known attack patterns, validate carefully |
| Race conditions in distributed state | Medium | High | Use proper async fixtures, clean Redis |
| Flaky rate limit tests | High | Medium | Use deterministic timing, clean state |
| Tenant data leakage in tests | Low | Critical | Clean database thoroughly between tests |

---

## D3FEND Compliance Validation

This test suite validates:

### D3-UAC (User Account Control)
- ✅ Token revocation (blacklist)
- ✅ Multi-worker synchronization
- ✅ TTL expiration

### D3-RAC (Resource Access Control)
- ✅ Distributed rate limiting
- ✅ Per-tenant enforcement
- ✅ Burst handling

### D3-KM (Key Management)
- ✅ RSA key usage for JWT
- ✅ Secure token generation

**Compliance Report**: Tests will generate evidence for D3FEND certification

---

## Timeline

- **Day 1 AM**: Design security test architecture (TDD creation)
- **Day 1 PM**: Implement JWT and blacklist tests
- **Day 2 AM**: Implement rate limiting and validation tests
- **Day 2 PM**: Implement CORS and tenant isolation tests
- **Day 3**: Security metrics and compliance documentation

---

## Definition of Done

- [ ] All 30 test cases implemented
- [ ] All security controls validated
- [ ] D3FEND compliance evidence generated
- [ ] No security vulnerabilities found
- [ ] Attack scenarios all blocked
- [ ] Documentation complete
- [ ] Code reviewed by QA agent
- [ ] Security team sign-off

---

## Related Documents

- **D3FEND_SECURITY_FIXES_VALIDATION.md**: Security implementation evidence
- **WEEK3_DAY2-3_REDIS_INTEGRATION_COMPLETE.md**: Redis load testing
- **saas/auth/jwt_auth.py**: JWT implementation
- **security/application/rate_limiting.py**: Rate limiting implementation

---

**PRD Approved By**: BMAD Product Manager Agent
**Ready for**: Architect Agent (TDD Creation)
**Status**: ✅ Ready for Implementation Planning

**D3FEND Compliance**: This test suite provides validation evidence for SOC2/ISO27001 certification.
