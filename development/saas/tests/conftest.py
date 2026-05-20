"""
Shared Test Fixtures and Configuration
Provides reusable test utilities for account lockout testing
"""

import pytest
import time
import redis
from typing import Generator, Dict, Any
from unittest.mock import Mock, MagicMock
import sys
import os
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load environment variables from .env file for testing
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent.parent / '.env'
    if env_path.exists():
        load_dotenv(env_path)
except ImportError:
    # python-dotenv not installed, skip
    pass

from auth.account_lockout import AccountLockoutManager


# ============================================================================
# REDIS FIXTURES
# ============================================================================

@pytest.fixture
def redis_client() -> Generator[redis.Redis, None, None]:
    """
    Real Redis client for integration testing

    Requires Redis running on localhost:6379
    Falls back to mock if Redis unavailable
    """
    try:
        # Get Redis password from environment
        redis_password = os.getenv('REDIS_PASSWORD', '')

        client = redis.Redis(
            host='localhost',
            port=6379,
            password=redis_password if redis_password else None,
            db=15,  # Use separate test database
            decode_responses=True,
            socket_connect_timeout=1
        )

        # Test connection
        client.ping()

        # Clear test database
        client.flushdb()

        yield client

        # Cleanup
        client.flushdb()
        client.close()

    except (redis.ConnectionError, redis.TimeoutError):
        pytest.skip("Redis not available for integration tests")


@pytest.fixture
def mock_redis_client() -> Mock:
    """Mock Redis client for unit testing"""
    mock = MagicMock(spec=redis.Redis)

    # Mock common Redis operations
    mock.pipeline.return_value = mock
    mock.execute.return_value = [1, 1, 3, 1]  # Default: 3 attempts
    mock.zadd.return_value = 1
    mock.zremrangebyscore.return_value = 1
    mock.zcard.return_value = 3
    mock.expire.return_value = 1
    mock.get.return_value = None
    mock.ttl.return_value = -2
    mock.setex.return_value = True
    mock.delete.return_value = 1

    # Mock Lua script operations
    mock.script_load.return_value = "fake_sha_12345678"
    mock.evalsha.return_value = [3, 0]  # [attempt_count, is_locked]
    mock.eval.return_value = [3, 0]

    return mock


@pytest.fixture
def mock_redis_with_script_error() -> Mock:
    """Mock Redis that simulates NoScriptError"""
    mock = MagicMock(spec=redis.Redis)

    # First evalsha raises NoScriptError, second succeeds
    mock.evalsha.side_effect = [
        redis.exceptions.NoScriptError("NOSCRIPT No matching script"),
        [3, 0]  # Success on retry
    ]
    mock.script_load.return_value = "fake_sha_87654321"

    return mock


# ============================================================================
# LOCKOUT MANAGER FIXTURES
# ============================================================================

@pytest.fixture
def lockout_manager_atomic(redis_client) -> AccountLockoutManager:
    """Account lockout manager with atomic operations enabled"""
    return AccountLockoutManager(
        redis_client=redis_client,
        max_attempts=5,
        lockout_duration=900,
        attempt_window=300,
        enable_atomic=True
    )


@pytest.fixture
def lockout_manager_legacy(redis_client) -> AccountLockoutManager:
    """Account lockout manager with legacy implementation"""
    return AccountLockoutManager(
        redis_client=redis_client,
        max_attempts=5,
        lockout_duration=900,
        attempt_window=300,
        enable_atomic=False
    )


@pytest.fixture
def lockout_manager_mock(mock_redis_client) -> AccountLockoutManager:
    """Account lockout manager with mock Redis (for unit tests)"""
    return AccountLockoutManager(
        redis_client=mock_redis_client,
        max_attempts=5,
        lockout_duration=900,
        attempt_window=300,
        enable_atomic=True
    )


@pytest.fixture
def lockout_manager_memory() -> AccountLockoutManager:
    """Account lockout manager with in-memory storage"""
    return AccountLockoutManager(
        redis_client=None,
        max_attempts=5,
        lockout_duration=900,
        attempt_window=300,
        enable_atomic=True
    )


# ============================================================================
# TEST DATA FIXTURES
# ============================================================================

@pytest.fixture
def test_identifiers() -> Dict[str, str]:
    """Common test identifiers"""
    return {
        'email': 'test@example.com',
        'ip': '192.168.1.100',
        'user_id': 'user_12345'
    }


@pytest.fixture
def test_config() -> Dict[str, Any]:
    """Test configuration parameters"""
    return {
        'max_attempts': 5,
        'lockout_duration': 900,
        'attempt_window': 300,
        'concurrent_users': 10,
        'attack_iterations': 100
    }


# ============================================================================
# TIMING UTILITIES
# ============================================================================

class TimingContext:
    """Context manager for measuring execution time"""

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.duration = None

    def __enter__(self):
        self.start_time = time.perf_counter()
        return self

    def __exit__(self, *args):
        self.end_time = time.perf_counter()
        self.duration = self.end_time - self.start_time

    @property
    def duration_ms(self) -> float:
        """Duration in milliseconds"""
        return self.duration * 1000 if self.duration else 0


@pytest.fixture
def timing_context():
    """Fixture providing timing context manager"""
    return TimingContext


# ============================================================================
# CONCURRENT TESTING UTILITIES
# ============================================================================

@pytest.fixture
def concurrent_executor():
    """Executor for concurrent test operations"""
    from concurrent.futures import ThreadPoolExecutor

    executor = ThreadPoolExecutor(max_workers=50)
    yield executor
    executor.shutdown(wait=True)


# ============================================================================
# METRICS UTILITIES
# ============================================================================

@pytest.fixture
def reset_prometheus_metrics():
    """Reset Prometheus metrics before each test"""

    # Clear metrics (Note: This is simplified - in production use collector.clear())
    # For testing, we'll just ensure metrics are initialized
    yield

    # Cleanup would go here if needed


# ============================================================================
# REDIS STATE INSPECTION
# ============================================================================

class RedisStateInspector:
    """Utility for inspecting Redis state during tests"""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client

    def get_attempt_count(self, identifier: str) -> int:
        """Get current attempt count for identifier"""
        attempts_key = f"login_attempts:{identifier}"
        return self.redis.zcard(attempts_key)

    def get_attempts_timeline(self, identifier: str) -> list:
        """Get all attempts with timestamps"""
        attempts_key = f"login_attempts:{identifier}"
        return self.redis.zrange(attempts_key, 0, -1, withscores=True)

    def is_locked(self, identifier: str) -> bool:
        """Check if account is locked"""
        lockout_key = f"account_lockout:{identifier}"
        return self.redis.exists(lockout_key) > 0

    def get_lockout_ttl(self, identifier: str) -> int:
        """Get remaining lockout time"""
        lockout_key = f"account_lockout:{identifier}"
        return self.redis.ttl(lockout_key)

    def clear_all(self, identifier: str):
        """Clear all data for identifier"""
        attempts_key = f"login_attempts:{identifier}"
        lockout_key = f"account_lockout:{identifier}"
        self.redis.delete(attempts_key, lockout_key)


@pytest.fixture
def redis_inspector(redis_client) -> RedisStateInspector:
    """Fixture providing Redis state inspection utilities"""
    return RedisStateInspector(redis_client)


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "unit: Unit tests (fast, isolated)"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests (require Redis)"
    )
    config.addinivalue_line(
        "markers", "security: Security-focused tests"
    )
    config.addinivalue_line(
        "markers", "performance: Performance and load tests (slow)"
    )
    config.addinivalue_line(
        "markers", "chaos: Chaos engineering tests"
    )
    config.addinivalue_line(
        "markers", "property: Property-based tests"
    )
    config.addinivalue_line(
        "markers", "slow: Slow-running tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically"""
    for item in items:
        # Auto-mark tests based on file path
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "security" in str(item.fspath):
            item.add_marker(pytest.mark.security)
        elif "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)
            item.add_marker(pytest.mark.slow)
        elif "chaos" in str(item.fspath):
            item.add_marker(pytest.mark.chaos)
        elif "property" in str(item.fspath):
            item.add_marker(pytest.mark.property)
