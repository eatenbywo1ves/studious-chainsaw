"""Pytest fixtures and configuration for integration tests."""

import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from httpx import AsyncClient
from sqlalchemy import create_engine
import redis.asyncio as aioredis

# Test database configuration
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL", "postgresql://postgres:postgres@localhost:5433/test_saas"
)

# Test Redis configuration
TEST_REDIS_HOST = os.getenv("TEST_REDIS_HOST", "localhost")
TEST_REDIS_PORT = int(os.getenv("TEST_REDIS_PORT", "6380"))
TEST_REDIS_PASSWORD = os.getenv("TEST_REDIS_PASSWORD", "test_redis_password")

# Test API base URL
TEST_API_URL = os.getenv("TEST_API_URL", "http://localhost:8001")


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_db_engine():
    """Create test database engine."""
    engine = create_engine(TEST_DATABASE_URL, echo=False)
    yield engine
    engine.dispose()


@pytest_asyncio.fixture(scope="session")
async def redis_client() -> AsyncGenerator:
    """Create test Redis client."""
    client = await aioredis.from_url(
        f"redis://:{TEST_REDIS_PASSWORD}@{TEST_REDIS_HOST}:{TEST_REDIS_PORT}",
        encoding="utf-8",
        decode_responses=True,
    )
    yield client
    await client.close()


@pytest_asyncio.fixture(scope="function")
async def api_client() -> AsyncGenerator:
    """Create HTTP client for API testing."""
    async with AsyncClient(base_url=TEST_API_URL, timeout=30.0) as client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def authenticated_client(api_client: AsyncClient) -> AsyncGenerator:
    """Create authenticated HTTP client with JWT token."""
    # Register test user
    register_response = await api_client.post(
        "/auth/register",
        json={
            "email": f"test_{os.urandom(4).hex()}@example.com",
            "password": "TestPassword123!",
            "name": "Test User",
        },
    )
    assert register_response.status_code == 201

    # Login to get token
    login_response = await api_client.post(
        "/auth/login",
        json={"email": register_response.json()["email"], "password": "TestPassword123!"},
    )
    assert login_response.status_code == 200

    token = login_response.json()["access_token"]
    api_client.headers.update({"Authorization": f"Bearer {token}"})

    yield api_client


@pytest_asyncio.fixture(scope="function")
async def clean_redis(redis_client):
    """Clean Redis before each test."""
    await redis_client.flushdb()
    yield
    await redis_client.flushdb()


@pytest.fixture(scope="function")
def sample_lattice_data():
    """Sample KA Lattice creation data."""
    return {
        "name": "Test Lattice",
        "dimensions": 2,
        "size": 100,
        "field_type": "complex",
        "geometry": "euclidean",
    }


# ============================================================================
# CUSTOM FIXTURES FOR COMPREHENSIVE INTEGRATION TESTS
# ============================================================================


@pytest_asyncio.fixture
async def two_tenants_fixture(api_client: AsyncClient):
    """
    Create two authenticated clients for different tenants.

    Used for testing multi-tenant isolation and cross-tenant security.

    Returns:
        Tuple of (tenant_a_client, tenant_b_client) where each is an
        authenticated AsyncClient for independent tenants.
    """
    # Tenant A - Register and Login
    email_a = f"tenant_a_{os.urandom(4).hex()}@example.com"
    await api_client.post(
        "/auth/register",
        json={"email": email_a, "password": "SecurePass123!", "name": "Tenant A User"},
    )

    login_a = await api_client.post(
        "/auth/login", json={"email": email_a, "password": "SecurePass123!"}
    )
    token_a = login_a.json()["access_token"]

    # Create independent client for Tenant A
    client_a = AsyncClient(
        base_url=str(api_client.base_url),
        headers={"Authorization": f"Bearer {token_a}"},
        timeout=30.0,
    )

    # Tenant B - Register and Login
    email_b = f"tenant_b_{os.urandom(4).hex()}@example.com"
    await api_client.post(
        "/auth/register",
        json={"email": email_b, "password": "SecurePass123!", "name": "Tenant B User"},
    )

    login_b = await api_client.post(
        "/auth/login", json={"email": email_b, "password": "SecurePass123!"}
    )
    token_b = login_b.json()["access_token"]

    # Create independent client for Tenant B
    client_b = AsyncClient(
        base_url=str(api_client.base_url),
        headers={"Authorization": f"Bearer {token_b}"},
        timeout=30.0,
    )

    yield client_a, client_b

    # Cleanup
    await client_a.aclose()
    await client_b.aclose()


@pytest.fixture(scope="session")
def gpu_available() -> bool:
    """
    Check if GPU is available for testing.

    Session-scoped to avoid repeated GPU detection.
    Tests marked with @pytest.mark.gpu_required will skip if GPU unavailable.

    Returns:
        bool: True if CUDA-capable GPU available, False otherwise.
    """
    try:
        import torch

        return torch.cuda.is_available()
    except ImportError:
        try:
            import cupy as cp

            # Attempt simple GPU operation
            cp.arange(10)
            return True
        except Exception:
            return False


# ============================================================================
# MOCK WEBHOOK SERVER FIXTURE
# ============================================================================


class MockWebhookServer:
    """
    Mock webhook server for testing webhook delivery.

    Runs an aiohttp server on localhost:8888 that records all received
    webhook POST requests for validation in tests.
    """

    def __init__(self, port: int = 8888):
        self.port = port
        self.received_webhooks = []
        self.retry_count = 0
        self.should_fail_next = 0
        self.app = None
        self.runner = None
        self.site = None

    async def webhook_handler(self, request):
        """Handle incoming webhook POST requests."""
        from aiohttp import web

        data = await request.json()
        self.received_webhooks.append(data)

        # Simulate failure if configured
        if self.should_fail_next > 0:
            self.should_fail_next -= 1
            self.retry_count += 1
            return web.Response(status=500, text="Simulated failure")

        return web.Response(status=200, text="OK")

    async def start(self):
        """Start the webhook server."""
        from aiohttp import web

        self.app = web.Application()
        self.app.router.add_post("/webhook", self.webhook_handler)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(self.runner, "localhost", self.port)
        await self.site.start()

    async def stop(self):
        """Stop the webhook server."""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    def get_received(self):
        """Get all received webhooks."""
        return self.received_webhooks

    def get_retry_count(self):
        """Get number of failed requests (for retry testing)."""
        return self.retry_count

    def fail_next(self, count: int = 1):
        """Configure server to fail next N requests."""
        self.should_fail_next = count

    def reset(self):
        """Reset server state."""
        self.received_webhooks = []
        self.retry_count = 0
        self.should_fail_next = 0


@pytest_asyncio.fixture
async def webhook_server_fixture():
    """
    Fixture providing mock webhook server.

    Automatically starts server before test and stops after test.
    Server runs on localhost:8888 and records all webhook deliveries.

    Usage:
        async def test_webhook(webhook_server_fixture):
            # Trigger event that sends webhook
            await api_client.post("/api/lattices", json={...})

            # Verify webhook received
            webhooks = webhook_server_fixture.get_received()
            assert len(webhooks) > 0
    """
    server = MockWebhookServer(port=8888)
    await server.start()

    # Wait for server to be ready
    await asyncio.sleep(0.5)

    yield server

    await server.stop()
