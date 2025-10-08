# PRD: Full SaaS Workflow Integration Tests

**Feature**: `test_full_saas_workflow.py`
**Product Manager**: BMAD Product Manager Agent
**Date**: 2025-10-05
**Priority**: CRITICAL
**Effort Estimate**: Medium (4-6 hours)

---

## User Story

As a **SaaS platform developer**, I want **comprehensive integration tests for the complete user workflow** so that I can **confidently deploy to production knowing all systems work together correctly**.

---

## Business Context

The multi-tenant SaaS platform combines:
- User authentication (JWT + Redis)
- Catalytic lattice computing (GPU-accelerated)
- Rate limiting and security
- Webhook delivery system

Currently, each component has unit tests, but there are **no end-to-end tests** validating the complete workflow. This creates risk for production deployment.

---

## Acceptance Criteria

### AC1: User Registration and Authentication Flow
- [ ] User can register with email and password
- [ ] Registration creates tenant and user in database
- [ ] User can login and receive valid JWT token
- [ ] Token can be used to authenticate API requests
- [ ] Invalid credentials are rejected with 401
- [ ] Token expiration is enforced

### AC2: Lattice Creation and Management
- [ ] Authenticated user can create a KA Lattice
- [ ] Lattice is associated with correct tenant
- [ ] Lattice creation returns lattice ID and metadata
- [ ] User can retrieve lattice details by ID
- [ ] User cannot access other tenant's lattices (isolation)
- [ ] Invalid lattice parameters are rejected with 422

### AC3: Lattice Transformations
- [ ] User can perform XOR transformation on lattice
- [ ] Transformation returns results with execution metadata
- [ ] GPU-enabled transformation uses GPU when available
- [ ] CPU fallback works when GPU unavailable
- [ ] Concurrent transformations are handled correctly

### AC4: Rate Limiting Integration
- [ ] Rate limits are enforced across workflow
- [ ] Exceeded limits return 429 with retry-after header
- [ ] Rate limits are per-tenant (not global)
- [ ] Burst allowance works correctly

### AC5: Webhook Delivery
- [ ] Webhook events are triggered for lattice creation
- [ ] Webhook events are triggered for transformations
- [ ] Webhook payloads include correct data
- [ ] Failed webhooks are retried appropriately

### AC6: Complete Workflow End-to-End
- [ ] Register → Login → Create Lattice → Transform → Get Results workflow succeeds
- [ ] Workflow completes in < 5 seconds (performance target)
- [ ] All security checks pass throughout workflow
- [ ] Audit logs are created for all operations

---

## Technical Requirements

### API Endpoints Tested

**Authentication**:
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/refresh`

**Lattice Management**:
- `POST /api/v1/lattices`
- `GET /api/v1/lattices/{lattice_id}`
- `GET /api/v1/lattices` (list)
- `DELETE /api/v1/lattices/{lattice_id}`

**Transformations**:
- `POST /api/v1/lattices/{lattice_id}/transform`
- `GET /api/v1/lattices/{lattice_id}/transformations` (history)

### Test Data Requirements

**Test User**:
```json
{
  "email": "test_workflow@example.com",
  "password": "SecureTestPass123!",
  "name": "Workflow Test User"
}
```

**Test Lattice**:
```json
{
  "name": "Integration Test Lattice",
  "dimensions": 2,
  "size": 100,
  "field_type": "complex",
  "geometry": "euclidean"
}
```

**Test Transformation**:
```json
{
  "transformation_type": "xor",
  "parameters": {
    "key": "test_key_12345",
    "iterations": 1
  }
}
```

### Database State Verification

- Tenant created with correct slug
- User created with hashed password
- Lattice created with tenant_id association
- Transformation history recorded
- Audit logs created

### Security Requirements

- All requests require valid JWT (except registration/login)
- Tenant isolation enforced at database level
- Rate limits enforced per-tenant
- Input validation on all endpoints
- CORS headers present on responses

### Performance Requirements

- Complete workflow: < 5 seconds
- User registration: < 1 second
- Lattice creation: < 2 seconds
- Transformation (100-size lattice): < 2 seconds
- Database queries: < 100ms each

---

## Edge Cases

### EC1: Duplicate User Registration
**Scenario**: User tries to register with existing email
**Expected**: 409 Conflict with message "Email already registered"

### EC2: Expired Token
**Scenario**: User makes request with expired JWT token
**Expected**: 401 Unauthorized with message "Token has expired"

### EC3: Lattice Creation with Invalid Dimensions
**Scenario**: User tries to create lattice with dimensions > 10
**Expected**: 422 Validation Error with detailed message

### EC4: Cross-Tenant Access Attempt
**Scenario**: User tries to access another tenant's lattice
**Expected**: 404 Not Found (don't reveal lattice exists)

### EC5: Rate Limit Exceeded
**Scenario**: User exceeds transformation rate limit
**Expected**: 429 Too Many Requests with Retry-After header

### EC6: GPU Unavailable
**Scenario**: Transformation requested but GPU unavailable
**Expected**: Successful fallback to CPU with metadata indicating CPU usage

---

## Success Metrics

### Test Coverage
- **Target**: 100% of main workflow paths
- **Measure**: pytest coverage report

### Test Reliability
- **Target**: < 5% flake rate on repeated runs
- **Measure**: Run tests 20 times, track failures

### Test Performance
- **Target**: Full suite completes in < 30 seconds
- **Measure**: pytest duration report

### Bug Detection
- **Target**: Catch integration issues before production
- **Measure**: Number of bugs found in testing vs. production

---

## Test Structure

### Test File Organization

```python
# tests/integration/test_full_saas_workflow.py

class TestUserAuthenticationFlow:
    """Test user registration and authentication"""
    async def test_user_registration_success()
    async def test_user_registration_duplicate_email()
    async def test_user_login_success()
    async def test_user_login_invalid_credentials()
    async def test_token_authentication()
    async def test_token_expiration()

class TestLatticeManagement:
    """Test lattice CRUD operations"""
    async def test_create_lattice_authenticated()
    async def test_create_lattice_unauthenticated()
    async def test_get_lattice_by_id()
    async def test_get_lattice_cross_tenant_isolation()
    async def test_list_lattices_filtered_by_tenant()
    async def test_delete_lattice()

class TestLatticeTransformations:
    """Test lattice transformation operations"""
    async def test_xor_transformation_gpu()
    async def test_xor_transformation_cpu_fallback()
    async def test_concurrent_transformations()
    async def test_transformation_history()

class TestRateLimiting:
    """Test rate limiting integration"""
    async def test_rate_limit_enforcement()
    async def test_rate_limit_per_tenant()
    async def test_burst_allowance()

class TestWebhookIntegration:
    """Test webhook delivery"""
    async def test_webhook_on_lattice_creation()
    async def test_webhook_on_transformation()
    async def test_webhook_retry_on_failure()

class TestCompleteWorkflow:
    """Test end-to-end workflows"""
    async def test_complete_user_journey()
    async def test_multi_user_concurrent_workflows()
```

### Estimated Test Count

- Authentication: 6 tests
- Lattice Management: 6 tests
- Transformations: 4 tests
- Rate Limiting: 3 tests
- Webhooks: 3 tests
- Complete Workflow: 2 tests

**Total**: 24 test cases

---

## Dependencies

### Infrastructure
- PostgreSQL test database (localhost:5433)
- Redis test instance (localhost:6380)
- SaaS API server (localhost:8001)
- GPU availability (optional, test CPU fallback)

### Python Packages
- pytest
- pytest-asyncio
- httpx (async HTTP client)
- sqlalchemy
- redis
- pytest-cov (coverage reporting)

### Existing Code
- `conftest.py` - Test fixtures (already exists)
- `saas/api/saas_server.py` - API endpoints
- `saas/auth/jwt_auth.py` - Authentication
- `saas/database/models.py` - Database models

---

## Out of Scope

- Load testing (covered in separate test suite)
- Performance optimization (accept current performance)
- UI/Frontend testing (API-only)
- External service mocking (use real Redis/PostgreSQL)
- Security penetration testing (covered separately)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Flaky tests due to async timing | Medium | High | Use proper async fixtures, timeouts |
| Database state conflicts | Medium | Medium | Clean database before each test |
| GPU availability variations | High | Low | Test both GPU and CPU paths |
| Network timeouts | Low | Medium | Use appropriate timeout values |

---

## Timeline

- **Day 1 AM**: Design test architecture (TDD creation)
- **Day 1 PM**: Implement authentication and lattice tests
- **Day 2 AM**: Implement transformation and rate limiting tests
- **Day 2 PM**: Implement webhook and complete workflow tests
- **Day 3**: Bug fixing and test stabilization

---

## Definition of Done

- [ ] All 24 test cases implemented
- [ ] All tests passing consistently (< 5% flake rate)
- [ ] Code coverage report generated
- [ ] Test documentation complete
- [ ] CI/CD integration configured
- [ ] Code reviewed by QA agent
- [ ] No linting errors (ruff check)
- [ ] Type hints present (mypy passes)

---

## Related Documents

- **NEXT_STEPS_PLAN_2025-10-03.md**: Original requirements
- **conftest.py**: Existing test fixtures
- **saas/api/saas_server.py**: API implementation

---

**PRD Approved By**: BMAD Product Manager Agent
**Ready for**: Architect Agent (TDD Creation)
**Status**: ✅ Ready for Implementation Planning
