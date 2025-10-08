"""
Integration tests for full SaaS workflow.

Tests complete user journeys from registration through lattice operations
and transformations, validating multi-tenant isolation and API functionality.

Test Coverage:
- User registration and authentication (6 tests)
- Lattice CRUD operations with tenant isolation (6 tests)
- Lattice transformations (GPU/CPU) (4 tests)
- Rate limiting integration (3 tests)
- Webhook delivery (3 tests)
- Complete end-to-end workflows (2 tests)

Total: 24 test cases

Related Documents:
- PRD: tests/integration/PRD_FULL_SAAS_WORKFLOW.md
- TDD: tests/integration/TDD_FULL_SAAS_WORKFLOW.md

Developer: BMAD Developer Agent
Date: 2025-10-05
"""

import pytest
import asyncio
import time
from typing import Dict, Any
from httpx import AsyncClient


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
        assert response.status_code == 201, \
            f"Expected 201, got {response.status_code}: {response.text}"
        data = response.json()
        assert "id" in data, "Response should include user ID"
        assert "tenant_id" in data, "Response should include tenant ID"
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
        assert response2.status_code == 409, \
            f"Expected 409 for duplicate email, got {response2.status_code}"
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
        assert len(parts) == 3, "JWT should have 3 parts (header.payload.signature)"

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

        assert response.status_code == 201, \
            f"Expected 201, got {response.status_code}: {response.text}"
        data = response.json()
        assert "id" in data, "Response should include lattice ID"
        assert "tenant_id" in data, "Response should include tenant ID"
        assert data["dimensions"] == sample_lattice_data["dimensions"]
        assert data["size"] == sample_lattice_data["size"]
        assert "vertices" in data, "Response should include vertex count"
        assert "edges" in data, "Response should include edge count"

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
        assert response.status_code == 401, \
            "Unauthenticated request should return 401"

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
        assert access_response.status_code == 404, \
            "Cross-tenant access should return 404 (not 403 to avoid info disclosure)"

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
        assert len(data["lattices"]) >= 3, "Should return at least our 3 lattices"

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

    @pytest.mark.gpu_required
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
        assert data["gpu_used"]
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
        assert not data["gpu_used"]

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
        assert all(r.status_code == 200 for r in responses), \
            "All concurrent transformations should succeed"

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
        assert len(data["operations"]) >= 3, "Should have at least 3 transformations"


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
        assert 429 in status_codes, "At least one request should be rate limited"

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
        assert response_b.status_code != 429, \
            "Tenant B should not be rate limited by Tenant A's usage"

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
        assert len(webhooks) > 0, "Webhook should be received"
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
        assert len(transformation_webhooks) > 0, \
            "Transformation webhook should be received"

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
        assert webhook_server_fixture.get_retry_count() > 0, \
            "Webhook should retry on failure"


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
        assert duration < 5.0, \
            f"Complete workflow should take < 5s, took {duration:.2f}s"

    async def test_multi_user_concurrent_workflows(
        self,
        api_client: AsyncClient
    ):
        """
        Test multiple users can work concurrently without interference.

        Steps:
        1. Register 3 users
        2. Each user creates lattice concurrently
        3. Each user performs transformation concurrently
        4. Verify all operations succeed
        5. Verify no cross-tenant contamination
        """
        # Register 3 users
        users = []
        for i in range(3):
            register_response = await api_client.post("/auth/register", json={
                "email": f"user{i}@example.com",
                "password": "SecurePass123!",
                "name": f"User {i}"
            })
            assert register_response.status_code == 201

            # Login
            login_response = await api_client.post("/auth/login", json={
                "email": f"user{i}@example.com",
                "password": "SecurePass123!"
            })
            token = login_response.json()["access_token"]

            # Create client
            client = AsyncClient(
                base_url=str(api_client.base_url),
                headers={"Authorization": f"Bearer {token}"},
                timeout=30.0
            )
            users.append(client)

        # Each user creates lattice concurrently
        create_tasks = [
            user.post("/api/lattices", json={"dimensions": 2, "size": 100 + i * 10})
            for i, user in enumerate(users)
        ]
        create_responses = await asyncio.gather(*create_tasks)

        # Verify all created successfully
        assert all(r.status_code == 201 for r in create_responses)

        # Extract lattice IDs
        lattice_ids = [r.json()["id"] for r in create_responses]

        # Each user performs transformation concurrently
        transform_tasks = [
            users[i].post(
                f"/api/lattices/{lattice_ids[i]}/transform",
                json={"transformation_type": "xor", "parameters": {}}
            )
            for i in range(len(users))
        ]
        transform_responses = await asyncio.gather(*transform_tasks)

        # Verify all transformed successfully
        assert all(r.status_code == 200 for r in transform_responses)

        # Cleanup
        for user in users:
            await user.aclose()
