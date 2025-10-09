"""Pytest fixtures and configuration for E2E tests."""

import os
import asyncio
import pytest
from typing import AsyncGenerator, Dict, Any
from httpx import AsyncClient
import time

# E2E test environment configuration
E2E_API_URL = os.getenv("E2E_API_URL", "http://localhost:8000")
E2E_TIMEOUT = int(os.getenv("E2E_TIMEOUT", "60"))  # 60 second timeout for E2E operations


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async E2E tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def e2e_client() -> AsyncGenerator[AsyncClient, None]:
    """Create HTTP client for E2E testing with extended timeout."""
    async with AsyncClient(
        base_url=E2E_API_URL, timeout=E2E_TIMEOUT, follow_redirects=True
    ) as client:
        yield client


@pytest.fixture(scope="function")
async def new_tenant(e2e_client: AsyncClient) -> Dict[str, Any]:
    """
    Create a new tenant for E2E testing.

    Returns complete tenant context including:
    - tenant_id, user_id
    - access_token, refresh_token
    - email, password (for re-login)
    """
    timestamp = int(time.time() * 1000)  # Millisecond timestamp for uniqueness

    tenant_data = {
        "company_name": f"E2E Test Corp {timestamp}",
        "email": f"e2e_test_{timestamp}@example.com",
        "password": "E2ETestPassword123!",
        "first_name": "E2E",
        "last_name": "Tester",
        "plan_code": "pro",  # Use Pro plan for E2E tests
    }

    # Register tenant
    response = await e2e_client.post("/api/auth/register", json=tenant_data)
    assert response.status_code == 201, f"Tenant registration failed: {response.text}"

    registration_result = response.json()

    # Return complete context
    return {
        "tenant_id": registration_result.get("tenant_id"),
        "user_id": registration_result.get("user_id"),
        "access_token": registration_result.get("access_token"),
        "refresh_token": registration_result.get("refresh_token"),
        "email": tenant_data["email"],
        "password": tenant_data["password"],
        "company_name": tenant_data["company_name"],
    }


@pytest.fixture(scope="function")
async def authenticated_e2e_client(
    e2e_client: AsyncClient, new_tenant: Dict[str, Any]
) -> AsyncGenerator[AsyncClient, None]:
    """Create authenticated HTTP client with tenant context."""
    e2e_client.headers.update({"Authorization": f"Bearer {new_tenant['access_token']}"})

    # Attach tenant context to client for easy access in tests
    e2e_client.tenant_context = new_tenant

    yield e2e_client


@pytest.fixture(scope="function")
def sample_lattice_small():
    """Small lattice data for quick E2E tests."""
    return {
        "name": "E2E Small Lattice",
        "dimensions": 2,
        "size": 50,
        "field_type": "complex",
        "geometry": "euclidean",
        "enable_gpu": False,
    }


@pytest.fixture(scope="function")
def sample_lattice_large():
    """Large lattice data for GPU E2E tests."""
    return {
        "name": "E2E Large Lattice",
        "dimensions": 3,
        "size": 2000,
        "field_type": "complex",
        "geometry": "euclidean",
        "enable_gpu": True,
    }


@pytest.fixture(scope="function")
async def cleanup_lattices(authenticated_e2e_client: AsyncClient):
    """Cleanup fixture that runs after test to delete created lattices."""
    created_lattice_ids = []

    # Yield control to test
    yield created_lattice_ids

    # Cleanup after test
    for lattice_id in created_lattice_ids:
        try:
            await authenticated_e2e_client.delete(f"/api/lattices/{lattice_id}")
        except Exception:
            pass  # Best effort cleanup


@pytest.fixture(scope="session")
def e2e_test_config():
    """E2E test configuration."""
    return {
        "api_url": E2E_API_URL,
        "timeout": E2E_TIMEOUT,
        "max_retries": 3,
        "retry_delay": 2,  # seconds
        "slow_test_threshold": 10,  # seconds
    }
