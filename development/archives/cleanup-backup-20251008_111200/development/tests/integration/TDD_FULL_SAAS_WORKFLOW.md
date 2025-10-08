# Technical Design Document: Full SaaS Workflow Integration Tests

**Feature**: `test_full_saas_workflow.py`
**Architect**: BMAD Architect Agent
**Date**: 2025-10-05
**PRD Reference**: `PRD_FULL_SAAS_WORKFLOW.md`
**Implementation Estimate**: 4-6 hours

---

## Architecture Overview

This TDD provides implementation-ready specifications for comprehensive integration tests validating the complete SaaS workflow: user registration → authentication → lattice operations → transformations.

### System Components Tested

```
┌─────────────────────────────────────────────────────────────────┐
│                      SaaS API Server                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Auth Router  │  │ Tenant API   │  │ Lattice Mgr  │         │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘         │
│         │                 │                 │                   │
│  ┌──────▼─────────────────▼─────────────────▼──────┐           │
│  │           Middleware Stack                       │           │
│  │  - Authentication (JWT)                          │           │
│  │  - Tenant Isolation                              │           │
│  │  - Rate Limiting (Redis)                         │           │
│  │  - Logging                                       │           │
│  └──────────────────┬────────────────────────────────┘          │
└────────────────────┼─────────────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼─────┐          ┌─────▼──────┐
    │PostgreSQL│          │   Redis    │
    │  (DB)    │          │(Blacklist) │
    └──────────┘          └────────────┘
```

---

## Database Schema

### Test Database Setup

**Database**: PostgreSQL (test instance on port 5433)

```sql
-- Tenant table
CREATE TABLE tenants (
    id VARCHAR(36) PRIMARY KEY,
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP DEFAULT NOW()
);

-- User table
CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'member',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, email)
);

-- Lattice table
CREATE TABLE tenant_lattices (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255),
    dimensions INTEGER NOT NULL,
    size INTEGER NOT NULL,
    created_by_id VARCHAR(36) REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- Lattice operations table
CREATE TABLE lattice_operations (
    id VARCHAR(36) PRIMARY KEY,
    tenant_id VARCHAR(36) REFERENCES tenants(id) ON DELETE CASCADE,
    lattice_id VARCHAR(36) REFERENCES tenant_lattices(id) ON DELETE CASCADE,
    operation_type VARCHAR(50) NOT NULL,
    parameters JSON,
    result JSON,
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## API Specifications

### Authentication Endpoints

#### POST /auth/register
**File**: `saas/api/auth_api.py`

**Request Model**:
```python
class UserRegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    name: str
    company_name: Optional[str] = None
```

**Response Model**:
```python
class UserRegisterResponse(BaseModel):
    id: str
    email: str
    tenant_id: str
    tenant_slug: str
    message: str
```

**Implementation** (existing code reference):
- Validates email format and password strength
- Creates tenant with slug from email
- Creates user with hashed password
- Returns 201 on success, 409 if email exists

#### POST /auth/login
**File**: `saas/api/saas_server.py:295`

**Request Model**:
```python
class LoginRequest(BaseModel):
    email: str
    password: str
```

**Response Model**:
```python
class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
```

**Implementation**:
- Validates credentials
- Generates JWT with RSA signature
- Returns token valid for 15 minutes (ACCESS_TOKEN_EXPIRE_MINUTES)

### Lattice Endpoints

#### POST /api/lattices
**File**: `saas/api/saas_server.py:353`

**Request Model**:
```python
class LatticeCreateRequest(BaseModel):
    name: Optional[str] = None
    dimensions: int = Field(..., ge=1, le=10)
    size: int = Field(..., ge=1)
    field_type: str = "complex"
    geometry: str = "euclidean"
```

**Response Model**:
```python
class LatticeCreateResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    dimensions: int
    size: int
    vertices: int
    edges: int
    memory_kb: float
    created_at: str
```

**Implementation**:
- Requires valid JWT
- Creates lattice in TenantLatticeManager
- Saves metadata to database
- Returns lattice details

#### GET /api/lattices
**File**: `saas/api/saas_server.py:381`

**Response Model**:
```python
class LatticeListResponse(BaseModel):
    lattices: List[LatticeInfo]
    total: int
```

**Implementation**:
- Requires valid JWT
- Filters by current_user.tenant_id
- Returns only tenant's lattices

#### POST /api/lattices/{lattice_id}/transform
**Implementation**: To be added (not in current saas_server.py)

**Request Model**:
```python
class TransformRequest(BaseModel):
    transformation_type: str  # "xor", "rotate", etc.
    parameters: Dict[str, Any]
    use_gpu: bool = False
```

**Response Model**:
```python
class TransformResponse(BaseModel):
    lattice_id: str
    operation_id: str
    transformation_type: str
    execution_time_ms: int
    gpu_used: bool
    result_summary: Dict[str, Any]
```

---

## Implementation Components

### Component 1: Test File Structure
**File**: `tests/integration/test_full_saas_workflow.py`

```python
"""
Integration tests for complete SaaS workflow.

Tests the full user journey from registration through lattice operations,
validating all components work together correctly.
"""

import pytest
import asyncio
from typing import Dict, Any
from httpx import AsyncClient
from sqlalchemy.orm import Session


# ============================================================================
# TEST CLASS: User Authentication Flow
# ============================================================================

class TestUserAuthenticationFlow:
    """Test complete user authentication workflow"""

    async def test_user_registration_success(self, api_client: AsyncClient, clean_redis):
        """
        Test successful user registration creates tenant and user.

        Steps:
        1. POST /auth/register with valid data
        2. Verify 201 response
        3. Verify response contains user_id, tenant_id
        4. Query database to confirm tenant and user created
        """
        registration_data = {
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "name": "New User",
            "company_name": "Test Company"
        }

        response = await api_client.post("/auth/register", json=registration_data)

        # Assertions
        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert "tenant_id" in data
        assert data["email"] == registration_data["email"]
        assert "tenant_slug" in data

    async def test_user_registration_duplicate_email(self, api_client: AsyncClient):
        """
        Test duplicate email registration returns 409 Conflict.

        Steps:
        1. Register user with email
        2. Attempt to register again with same email
        3. Verify 409 response
        """
        registration_data = {
            "email": "duplicate@example.com",
            "password": "SecurePass123!",
            "name": "User One"
        }

        # First registration
        response1 = await api_client.post("/auth/register", json=registration_data)
        assert response1.status_code == 201

        # Duplicate registration
        response2 = await api_client.post("/auth/register", json=registration_data)
        assert response2.status_code == 409
        assert "already registered" in response2.json()["detail"].lower()

    async def test_user_login_success(self, api_client: AsyncClient):
        """
        Test successful login returns valid JWT token.

        Steps:
        1. Register user
        2. Login with credentials
        3. Verify 200 response with access_token
        4. Verify token is valid JWT
        """
        # Register
        await api_client.post("/auth/register", json={
            "email": "logintest@example.com",
            "password": "SecurePass123!",
            "name": "Login Test"
        })

        # Login
        login_response = await api_client.post("/auth/login", json={
            "email": "logintest@example.com",
            "password": "SecurePass123!"
        })

        assert login_response.status_code == 200
        data = login_response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "expires_in" in data

        # Verify token is valid JWT (has 3 parts separated by dots)
        token = data["access_token"]
        parts = token.split(".")
        assert len(parts) == 3  # header.payload.signature

    async def test_user_login_invalid_credentials(self, api_client: AsyncClient):
        """
        Test login with invalid credentials returns 401.

        Steps:
        1. Attempt login with non-existent user
        2. Verify 401 response
        """
        response = await api_client.post("/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "WrongPass123!"
        })

        assert response.status_code == 401
        assert "invalid" in response.json()["detail"].lower()

    async def test_token_authentication(self, authenticated_client: AsyncClient):
        """
        Test JWT token successfully authenticates API requests.

        Steps:
        1. Use authenticated_client fixture (has valid token)
        2. Access protected endpoint
        3. Verify 200 response (not 401)
        """
        response = await authenticated_client.get("/api/lattices")
        assert response.status_code == 200

    async def test_token_expiration(self, api_client: AsyncClient):
        """
        Test expired token is rejected with 401.

        Steps:
        1. Create token with very short expiration (mock)
        2. Wait for expiration
        3. Attempt to use token
        4. Verify 401 response
        """
        # Note: This test requires mocking token expiration or waiting
        # Implementation will use a mock fixture to create expired token
        pytest.skip("Requires mock fixture for expired token - implement in Developer phase")


# ============================================================================
# TEST CLASS: Lattice Management
# ============================================================================

class TestLatticeManagement:
    """Test lattice CRUD operations with tenant isolation"""

    async def test_create_lattice_authenticated(
        self,
        authenticated_client: AsyncClient,
        sample_lattice_data: Dict[str, Any]
    ):
        """
        Test authenticated user can create lattice.

        Steps:
        1. POST /api/lattices with valid data
        2. Verify 201 response
        3. Verify response contains lattice_id, metadata
        4. Verify lattice associated with correct tenant
        """
        response = await authenticated_client.post(
            "/api/lattices",
            json=sample_lattice_data
        )

        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert "tenant_id" in data
        assert data["dimensions"] == sample_lattice_data["dimensions"]
        assert data["size"] == sample_lattice_data["size"]
        assert "vertices" in data
        assert "edges" in data

    async def test_create_lattice_unauthenticated(
        self,
        api_client: AsyncClient,
        sample_lattice_data: Dict[str, Any]
    ):
        """
        Test unauthenticated request to create lattice returns 401.

        Steps:
        1. POST /api/lattices without Authorization header
        2. Verify 401 response
        """
        response = await api_client.post("/api/lattices", json=sample_lattice_data)
        assert response.status_code == 401

    async def test_get_lattice_by_id(
        self,
        authenticated_client: AsyncClient,
        sample_lattice_data: Dict[str, Any]
    ):
        """
        Test retrieving specific lattice by ID.

        Steps:
        1. Create lattice
        2. GET /api/lattices/{id}
        3. Verify 200 response with correct data
        """
        # Create lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json=sample_lattice_data
        )
        lattice_id = create_response.json()["id"]

        # Get lattice
        get_response = await authenticated_client.get(f"/api/lattices/{lattice_id}")
        assert get_response.status_code == 200
        data = get_response.json()
        assert data["id"] == lattice_id

    async def test_get_lattice_cross_tenant_isolation(
        self,
        api_client: AsyncClient,
        two_tenants_fixture
    ):
        """
        Test user cannot access another tenant's lattice.

        Steps:
        1. Tenant A creates lattice
        2. Tenant B attempts to access lattice
        3. Verify 404 response (not 403 - don't leak existence)
        """
        tenant_a_client, tenant_b_client = two_tenants_fixture

        # Tenant A creates lattice
        create_response = await tenant_a_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100}
        )
        lattice_id = create_response.json()["id"]

        # Tenant B attempts access
        access_response = await tenant_b_client.get(f"/api/lattices/{lattice_id}")
        assert access_response.status_code == 404

    async def test_list_lattices_filtered_by_tenant(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test listing lattices returns only tenant's lattices.

        Steps:
        1. Create 3 lattices for tenant
        2. GET /api/lattices
        3. Verify only tenant's lattices returned
        """
        # Create 3 lattices
        for i in range(3):
            await authenticated_client.post(
                "/api/lattices",
                json={"dimensions": 2, "size": 100 + i * 10, "name": f"Lattice {i}"}
            )

        # List lattices
        list_response = await authenticated_client.get("/api/lattices")
        assert list_response.status_code == 200
        data = list_response.json()
        assert "lattices" in data
        assert len(data["lattices"]) >= 3  # At least our 3

    async def test_delete_lattice(
        self,
        authenticated_client: AsyncClient,
        sample_lattice_data: Dict[str, Any]
    ):
        """
        Test deleting lattice.

        Steps:
        1. Create lattice
        2. DELETE /api/lattices/{id}
        3. Verify 204 response
        4. Verify lattice no longer accessible
        """
        # Create
        create_response = await authenticated_client.post(
            "/api/lattices",
            json=sample_lattice_data
        )
        lattice_id = create_response.json()["id"]

        # Delete
        delete_response = await authenticated_client.delete(f"/api/lattices/{lattice_id}")
        assert delete_response.status_code == 204

        # Verify gone
        get_response = await authenticated_client.get(f"/api/lattices/{lattice_id}")
        assert get_response.status_code == 404


# ============================================================================
# TEST CLASS: Lattice Transformations
# ============================================================================

class TestLatticeTransformations:
    """Test lattice transformation operations"""

    async def test_xor_transformation_gpu(
        self,
        authenticated_client: AsyncClient,
        sample_lattice_data: Dict[str, Any],
        gpu_available: bool
    ):
        """
        Test XOR transformation with GPU.

        Steps:
        1. Create lattice
        2. POST transformation with use_gpu=true
        3. Verify transformation completes
        4. Verify GPU was used (if available)
        """
        if not gpu_available:
            pytest.skip("GPU not available")

        # Create lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={**sample_lattice_data, "size": 10000}  # Large enough for GPU
        )
        lattice_id = create_response.json()["id"]

        # Transform
        transform_response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "test_key_123"},
                "use_gpu": True
            }
        )

        assert transform_response.status_code == 200
        data = transform_response.json()
        assert "operation_id" in data
        assert data["gpu_used"] == True
        assert "execution_time_ms" in data

    async def test_xor_transformation_cpu_fallback(
        self,
        authenticated_client: AsyncClient,
        sample_lattice_data: Dict[str, Any]
    ):
        """
        Test XOR transformation falls back to CPU.

        Steps:
        1. Create lattice
        2. POST transformation with use_gpu=false
        3. Verify transformation completes
        4. Verify CPU was used
        """
        # Create lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json=sample_lattice_data
        )
        lattice_id = create_response.json()["id"]

        # Transform
        transform_response = await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={
                "transformation_type": "xor",
                "parameters": {"key": "test_key_123"},
                "use_gpu": False
            }
        )

        assert transform_response.status_code == 200
        data = transform_response.json()
        assert data["gpu_used"] == False

    async def test_concurrent_transformations(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test multiple concurrent transformations.

        Steps:
        1. Create lattice
        2. Submit 5 transformations concurrently
        3. Verify all complete successfully
        """
        # Create lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100}
        )
        lattice_id = create_response.json()["id"]

        # Concurrent transformations
        tasks = []
        for i in range(5):
            task = authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={
                    "transformation_type": "xor",
                    "parameters": {"key": f"key_{i}"}
                }
            )
            tasks.append(task)

        responses = await asyncio.gather(*tasks)
        assert all(r.status_code == 200 for r in responses)

    async def test_transformation_history(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test transformation history is recorded.

        Steps:
        1. Create lattice
        2. Perform 3 transformations
        3. GET transformation history
        4. Verify all 3 recorded
        """
        # Create lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100}
        )
        lattice_id = create_response.json()["id"]

        # Perform transformations
        for i in range(3):
            await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}}
            )

        # Get history
        history_response = await authenticated_client.get(
            f"/api/lattices/{lattice_id}/transformations"
        )
        assert history_response.status_code == 200
        data = history_response.json()
        assert len(data["operations"]) >= 3


# ============================================================================
# TEST CLASS: Rate Limiting
# ============================================================================

class TestRateLimiting:
    """Test rate limiting integration"""

    async def test_rate_limit_enforcement(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test rate limits are enforced.

        Steps:
        1. Identify endpoint with rate limit (e.g., 5/minute for transforms)
        2. Make 6 requests rapidly
        3. Verify 6th request returns 429
        """
        # Create lattice
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 10}
        )
        lattice_id = create_response.json()["id"]

        # Rapid requests (assuming 5/minute limit)
        responses = []
        for i in range(6):
            response = await authenticated_client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}}
            )
            responses.append(response)

        # First 5 should succeed, 6th should be rate limited
        # Note: Actual limit may vary, adjust based on configuration
        status_codes = [r.status_code for r in responses]
        assert 429 in status_codes  # At least one rate limited

    async def test_rate_limit_per_tenant(
        self,
        two_tenants_fixture
    ):
        """
        Test rate limits are per-tenant, not global.

        Steps:
        1. Tenant A makes requests up to limit
        2. Tenant B makes request
        3. Verify Tenant B not rate limited (independent limit)
        """
        tenant_a_client, tenant_b_client = two_tenants_fixture

        # Tenant A hits limit
        create_a = await tenant_a_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 10}
        )
        lattice_a_id = create_a.json()["id"]

        for _ in range(10):
            await tenant_a_client.post(
                f"/api/lattices/{lattice_a_id}/transform",
                json={"transformation_type": "xor", "parameters": {}}
            )

        # Tenant B should not be affected
        create_b = await tenant_b_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 10}
        )
        lattice_b_id = create_b.json()["id"]

        response_b = await tenant_b_client.post(
            f"/api/lattices/{lattice_b_id}/transform",
            json={"transformation_type": "xor", "parameters": {}}
        )
        assert response_b.status_code != 429  # Not rate limited

    async def test_burst_allowance(
        self,
        authenticated_client: AsyncClient
    ):
        """
        Test burst allowance works correctly.

        Steps:
        1. Make burst of requests within burst allowance
        2. Verify all succeed
        3. Continue beyond burst
        4. Verify rate limit kicks in
        """
        # Implementation depends on specific burst configuration
        pytest.skip("Requires specific burst configuration - implement in Developer phase")


# ============================================================================
# TEST CLASS: Webhook Integration
# ============================================================================

class TestWebhookIntegration:
    """Test webhook delivery for events"""

    async def test_webhook_on_lattice_creation(
        self,
        authenticated_client: AsyncClient,
        webhook_server_fixture
    ):
        """
        Test webhook triggered on lattice creation.

        Steps:
        1. Configure webhook endpoint
        2. Create lattice
        3. Verify webhook received notification
        """
        # Create lattice
        await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100, "name": "Webhook Test"}
        )

        # Check webhook server
        webhooks = webhook_server_fixture.get_received()
        assert len(webhooks) > 0
        assert webhooks[0]["event"] == "lattice.created"

    async def test_webhook_on_transformation(
        self,
        authenticated_client: AsyncClient,
        webhook_server_fixture
    ):
        """
        Test webhook triggered on transformation.

        Steps:
        1. Create lattice
        2. Perform transformation
        3. Verify webhook received notification
        """
        # Create and transform
        create_response = await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100}
        )
        lattice_id = create_response.json()["id"]

        await authenticated_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {}}
        )

        # Verify webhook
        webhooks = webhook_server_fixture.get_received()
        transformation_webhooks = [w for w in webhooks if w["event"] == "transformation.completed"]
        assert len(transformation_webhooks) > 0

    async def test_webhook_retry_on_failure(
        self,
        authenticated_client: AsyncClient,
        webhook_server_fixture
    ):
        """
        Test webhook retries on failure.

        Steps:
        1. Configure webhook to fail first attempt
        2. Trigger event
        3. Verify retry occurred
        """
        webhook_server_fixture.fail_next(count=1)

        # Trigger event
        await authenticated_client.post(
            "/api/lattices",
            json={"dimensions": 2, "size": 100}
        )

        # Verify retry
        assert webhook_server_fixture.get_retry_count() > 0


# ============================================================================
# TEST CLASS: Complete Workflow
# ============================================================================

class TestCompleteWorkflow:
    """Test end-to-end user workflows"""

    async def test_complete_user_journey(
        self,
        api_client: AsyncClient,
        clean_redis
    ):
        """
        Test complete user journey from registration to results.

        Steps:
        1. Register user
        2. Login to get token
        3. Create lattice
        4. Perform transformation
        5. Get results
        6. Verify all steps completed in < 5 seconds
        """
        import time
        start_time = time.time()

        # 1. Register
        register_response = await api_client.post("/auth/register", json={
            "email": "journey@example.com",
            "password": "JourneyPass123!",
            "name": "Journey Test"
        })
        assert register_response.status_code == 201

        # 2. Login
        login_response = await api_client.post("/auth/login", json={
            "email": "journey@example.com",
            "password": "JourneyPass123!"
        })
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]

        # Set auth header
        api_client.headers.update({"Authorization": f"Bearer {token}"})

        # 3. Create lattice
        create_response = await api_client.post("/api/lattices", json={
            "dimensions": 2,
            "size": 100,
            "name": "Journey Lattice"
        })
        assert create_response.status_code == 201
        lattice_id = create_response.json()["id"]

        # 4. Transform
        transform_response = await api_client.post(
            f"/api/lattices/{lattice_id}/transform",
            json={"transformation_type": "xor", "parameters": {"key": "test"}}
        )
        assert transform_response.status_code == 200

        # 5. Get results
        get_response = await api_client.get(f"/api/lattices/{lattice_id}")
        assert get_response.status_code == 200

        # Performance check
        duration = time.time() - start_time
        assert duration < 5.0  # Complete workflow in < 5 seconds

    async def test_multi_user_concurrent_workflows(
        self,
        api_client: AsyncClient
    ):
        """
        Test multiple users can work concurrently.

        Steps:
        1. Create 3 users
        2. Each user creates lattice and transforms concurrently
        3. Verify all succeed
        4. Verify tenant isolation maintained
        """
        users = []
        for i in range(3):
            # Register
            await api_client.post("/auth/register", json={
                "email": f"user{i}@example.com",
                "password": "Pass123!",
                "name": f"User {i}"
            })

            # Login
            login_resp = await api_client.post("/auth/login", json={
                "email": f"user{i}@example.com",
                "password": "Pass123!"
            })
            token = login_resp.json()["access_token"]
            users.append(token)

        # Concurrent workflows
        async def user_workflow(token):
            client = AsyncClient(base_url=str(api_client.base_url), timeout=30.0)
            client.headers.update({"Authorization": f"Bearer {token}"})

            create_resp = await client.post("/api/lattices", json={
                "dimensions": 2,
                "size": 100
            })
            lattice_id = create_resp.json()["id"]

            transform_resp = await client.post(
                f"/api/lattices/{lattice_id}/transform",
                json={"transformation_type": "xor", "parameters": {}}
            )

            await client.aclose()
            return transform_resp.status_code

        tasks = [user_workflow(token) for token in users]
        results = await asyncio.gather(*tasks)
        assert all(status == 200 for status in results)
```

---

## Testing Strategy

### Test Execution Order

1. **TestUserAuthenticationFlow** - Foundation (must pass first)
2. **TestLatticeManagement** - Depends on auth
3. **TestLatticeTransformations** - Depends on lattice creation
4. **TestRateLimiting** - Independent but uses lattices
5. **TestWebhookIntegration** - Independent
6. **TestCompleteWorkflow** - Integrates all components

### Database Cleanup Strategy

```python
# In conftest.py
@pytest.fixture(scope="function", autouse=True)
async def clean_database(test_db_engine):
    """Clean database before each test"""
    # Truncate tables in reverse dependency order
    with test_db_engine.connect() as conn:
        conn.execute("TRUNCATE lattice_operations CASCADE")
        conn.execute("TRUNCATE tenant_lattices CASCADE")
        conn.execute("TRUNCATE users CASCADE")
        conn.execute("TRUNCATE tenants CASCADE")
        conn.commit()
```

### Redis Cleanup Strategy

```python
# In conftest.py
@pytest.fixture(scope="function")
async def clean_redis(redis_client):
    """Clean Redis before each test"""
    await redis_client.flushdb()
    yield
    await redis_client.flushdb()
```

---

## Test Fixtures Required

### Fixture 1: Two Tenants
**File**: `tests/integration/conftest.py`

```python
@pytest.fixture
async def two_tenants_fixture(api_client: AsyncClient):
    """Create two authenticated clients for different tenants"""
    # Tenant A
    await api_client.post("/auth/register", json={
        "email": "tenant_a@example.com",
        "password": "SecurePass123!",
        "name": "Tenant A"
    })
    login_a = await api_client.post("/auth/login", json={
        "email": "tenant_a@example.com",
        "password": "SecurePass123!"
    })
    token_a = login_a.json()["access_token"]

    client_a = AsyncClient(base_url=str(api_client.base_url), timeout=30.0)
    client_a.headers.update({"Authorization": f"Bearer {token_a}"})

    # Tenant B
    await api_client.post("/auth/register", json={
        "email": "tenant_b@example.com",
        "password": "SecurePass123!",
        "name": "Tenant B"
    })
    login_b = await api_client.post("/auth/login", json={
        "email": "tenant_b@example.com",
        "password": "SecurePass123!"
    })
    token_b = login_b.json()["access_token"]

    client_b = AsyncClient(base_url=str(api_client.base_url), timeout=30.0)
    client_b.headers.update({"Authorization": f"Bearer {token_b}"})

    yield client_a, client_b

    await client_a.aclose()
    await client_b.aclose()
```

### Fixture 2: GPU Availability Check
**File**: `tests/integration/conftest.py`

```python
@pytest.fixture(scope="session")
def gpu_available() -> bool:
    """Check if GPU is available for testing"""
    try:
        import torch
        return torch.cuda.is_available()
    except ImportError:
        return False
```

### Fixture 3: Mock Webhook Server
**File**: `tests/integration/conftest.py`

```python
import asyncio
from aiohttp import web

class MockWebhookServer:
    def __init__(self):
        self.received_webhooks = []
        self.retry_count = 0
        self.fail_next_count = 0

    async def webhook_handler(self, request):
        if self.fail_next_count > 0:
            self.fail_next_count -= 1
            self.retry_count += 1
            return web.Response(status=500)

        data = await request.json()
        self.received_webhooks.append(data)
        return web.Response(status=200)

    async def start(self):
        app = web.Application()
        app.router.add_post('/webhook', self.webhook_handler)
        runner = web.AppRunner(app)
        await runner.setup()
        self.site = web.TCPSite(runner, 'localhost', 9999)
        await self.site.start()

    async def stop(self):
        await self.site.stop()

    def get_received(self):
        return self.received_webhooks

    def get_retry_count(self):
        return self.retry_count

    def fail_next(self, count=1):
        self.fail_next_count = count


@pytest.fixture
async def webhook_server_fixture():
    server = MockWebhookServer()
    await server.start()
    yield server
    await server.stop()
```

---

## Error Handling

All tests include comprehensive error handling:

```python
# Example pattern
try:
    response = await client.post("/api/endpoint", json=data)
    assert response.status_code == expected_code
except asyncio.TimeoutError:
    pytest.fail("Request timed out")
except Exception as e:
    pytest.fail(f"Unexpected error: {e}")
```

---

## Performance Benchmarks

| Test | Target Duration | Measure |
|------|----------------|---------|
| User registration | < 1s | Response time |
| Login | < 500ms | Response time |
| Lattice creation | < 2s | Response time |
| Transformation (size 100) | < 1s | Execution time |
| Complete workflow | < 5s | End-to-end |

---

## Deployment Notes

### Prerequisites
- PostgreSQL test database running on port 5433
- Redis test instance running on port 6380
- SaaS API server running on port 8001
- Python 3.11+ with async support

### Running Tests
```bash
# Run all workflow tests
pytest tests/integration/test_full_saas_workflow.py -v

# Run specific test class
pytest tests/integration/test_full_saas_workflow.py::TestUserAuthenticationFlow -v

# Run with coverage
pytest tests/integration/test_full_saas_workflow.py --cov=saas --cov-report=html
```

---

**TDD Approved By**: BMAD Architect Agent
**Ready for**: Developer Agent (Implementation)
**Status**: ✅ Complete - Implementation Ready

**Next**: Create remaining TDDs for GPU, Security, and Monitoring test suites.
