"""
Pytest Configuration and Shared Fixtures
Provides common test utilities and fixtures for all test modules
"""

import pytest
import tempfile
import shutil
import os
import sys
from pathlib import Path
from typing import Generator, Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch
import numpy as np
import json
import asyncio
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import application modules
sys.path.insert(0, str(Path(__file__).parent.parent / ".config"))
try:
    from settings import Settings, load_testing_config
    from logging_config import setup_logging
except ImportError:
    # Create mock implementations if config modules don't exist yet
    class Settings:
        def __init__(self):
            pass
    def load_testing_config():
        return Settings()
    def setup_logging(**kwargs):
        pass

from libs.utils.exceptions import CatalyticException
from libs.constants.constants import (
    DEFAULT_DIMENSIONS,
    DEFAULT_LATTICE_SIZE,
    DEFAULT_AUX_MEMORY_MB
)


# === Pytest Configuration ===

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "performance: Performance tests")
    config.addinivalue_line("markers", "gpu: Tests requiring GPU")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line("markers", "benchmark: Benchmark tests")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on path"""
    for item in items:
        # Add markers based on test location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "performance" in str(item.fspath):
            item.add_marker(pytest.mark.performance)


# === Session Fixtures ===

@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment for entire session"""
    # Setup logging for tests
    setup_logging(
        level="DEBUG",
        enable_console=True,
        enable_file=False,
        environment="testing"
    )
    
    # Set test environment variables
    os.environ["APP_ENV"] = "testing"
    os.environ["DEBUG"] = "true"
    
    yield
    
    # Cleanup after all tests
    # No cleanup needed for session


@pytest.fixture(scope="session")
def test_config() -> Settings:
    """Provide test configuration for entire session"""
    return load_testing_config()


# === Function Fixtures ===

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """
    Create a temporary directory for test files
    
    Yields:
        Path to temporary directory
    """
    temp_path = Path(tempfile.mkdtemp(prefix="test_catalytic_"))
    
    yield temp_path
    
    # Cleanup
    if temp_path.exists():
        shutil.rmtree(temp_path)


@pytest.fixture
def sample_lattice_params() -> Dict[str, Any]:
    """
    Provide sample lattice parameters
    
    Returns:
        Dictionary of lattice parameters
    """
    return {
        "dimensions": DEFAULT_DIMENSIONS,
        "size": DEFAULT_LATTICE_SIZE,
        "auxiliary_memory": DEFAULT_AUX_MEMORY_MB,
        "algorithm": "dijkstra"
    }


@pytest.fixture
def sample_coordinates() -> Dict[str, Any]:
    """
    Provide sample coordinate data
    
    Returns:
        Dictionary with coordinate lists
    """
    return {
        "2d": [5, 5],
        "3d": [3, 4, 5],
        "4d": [2, 3, 4, 5],
        "invalid": [999, -1, 0]
    }


@pytest.fixture
def sample_webhook_config() -> Dict[str, Any]:
    """
    Provide sample webhook configuration
    
    Returns:
        Dictionary of webhook config
    """
    return {
        "url": "https://example.com/webhook",
        "events": ["lattice.created", "computation.completed"],
        "secret": "test_secret_key_16_chars_minimum",
        "active": True,
        "retry_count": 3,
        "timeout": 30
    }


@pytest.fixture
def mock_gpu_device():
    """
    Mock GPU device for testing without actual GPU
    
    Returns:
        Mock GPU device object
    """
    mock_device = MagicMock()
    mock_device.name = "Mock GPU"
    mock_device.compute_capability = (7, 5)
    mock_device.total_memory_mb = 8192
    mock_device.free_memory_mb = 6144
    mock_device.max_threads_per_block = 1024
    mock_device.multiprocessor_count = 68
    mock_device.cuda_cores = 2176
    
    return mock_device


@pytest.fixture
def numpy_arrays() -> Dict[str, np.ndarray]:
    """
    Provide various numpy arrays for testing
    
    Returns:
        Dictionary of numpy arrays
    """
    np.random.seed(42)  # For reproducibility
    
    return {
        "small_1d": np.random.randn(100),
        "medium_2d": np.random.randn(100, 100),
        "large_3d": np.random.randn(50, 50, 50),
        "uint8_data": np.random.randint(0, 256, size=1000, dtype=np.uint8),
        "float32_data": np.random.randn(1000).astype(np.float32),
        "sparse": np.random.choice([0, 1], size=1000, p=[0.9, 0.1])
    }


# === Async Fixtures ===

@pytest.fixture
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def async_client():
    """
    Create async HTTP client for API testing
    
    Returns:
        Async HTTP client
    """
    import httpx
    
    async with httpx.AsyncClient(base_url="http://localhost:8080") as client:
        yield client


# === Mock Fixtures ===

@pytest.fixture
def mock_database():
    """
    Mock database connection
    
    Returns:
        Mock database object
    """
    mock_db = MagicMock()
    mock_db.execute.return_value = MagicMock()
    mock_db.fetchone.return_value = {"id": 1, "status": "success"}
    mock_db.fetchall.return_value = [
        {"id": 1, "name": "test1"},
        {"id": 2, "name": "test2"}
    ]
    
    return mock_db


@pytest.fixture
def mock_redis():
    """
    Mock Redis connection
    
    Returns:
        Mock Redis client
    """
    mock_redis_client = MagicMock()
    mock_redis_client.get.return_value = None
    mock_redis_client.set.return_value = True
    mock_redis_client.delete.return_value = 1
    mock_redis_client.exists.return_value = False
    
    return mock_redis_client


@pytest.fixture
def mock_api_response():
    """
    Mock API response factory
    
    Returns:
        Function to create mock responses
    """
    def _create_response(
        status_code: int = 200,
        json_data: Optional[Dict] = None,
        text: str = "",
        headers: Optional[Dict] = None
    ):
        response = MagicMock()
        response.status_code = status_code
        response.json.return_value = json_data or {}
        response.text = text
        response.headers = headers or {}
        response.raise_for_status = MagicMock()
        
        if status_code >= 400:
            response.raise_for_status.side_effect = Exception(f"HTTP {status_code}")
        
        return response
    
    return _create_response


# === Benchmark Fixtures ===

@pytest.fixture
def benchmark_data() -> Dict[str, Any]:
    """
    Provide data for benchmark tests
    
    Returns:
        Dictionary of benchmark test data
    """
    return {
        "small_size": 100,
        "medium_size": 1000,
        "large_size": 10000,
        "iterations": 100,
        "timeout_seconds": 5.0
    }


@pytest.fixture
def performance_tracker():
    """
    Track performance metrics during tests
    
    Returns:
        Performance tracking object
    """
    class PerformanceTracker:
        def __init__(self):
            self.metrics = []
        
        def record(self, operation: str, time_ms: float, memory_mb: float = 0):
            self.metrics.append({
                "operation": operation,
                "time_ms": time_ms,
                "memory_mb": memory_mb,
                "timestamp": datetime.now()
            })
        
        def get_summary(self):
            if not self.metrics:
                return {}
            
            times = [m["time_ms"] for m in self.metrics]
            return {
                "count": len(self.metrics),
                "total_time_ms": sum(times),
                "avg_time_ms": sum(times) / len(times),
                "min_time_ms": min(times),
                "max_time_ms": max(times)
            }
    
    return PerformanceTracker()


# === Helper Fixtures ===

@pytest.fixture
def json_file(temp_dir) -> Generator[Path, None, None]:
    """
    Create a temporary JSON file
    
    Yields:
        Path to JSON file
    """
    file_path = temp_dir / "test_data.json"
    test_data = {
        "test": True,
        "value": 42,
        "items": ["a", "b", "c"]
    }
    
    with open(file_path, "w") as f:
        json.dump(test_data, f)
    
    yield file_path
    
    # File is cleaned up with temp_dir


@pytest.fixture
def captured_logs():
    """
    Capture log messages during tests
    
    Returns:
        List to collect log records
    """
    import logging
    
    class LogCapture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []
        
        def emit(self, record):
            self.records.append(record)
    
    handler = LogCapture()
    logger = logging.getLogger()
    logger.addHandler(handler)
    
    yield handler.records
    
    logger.removeHandler(handler)


@pytest.fixture
def mock_time():
    """
    Mock time functions for deterministic tests
    
    Returns:
        Mock time object
    """
    with patch("time.time") as mock_time_func:
        mock_time_func.return_value = 1234567890.0
        
        with patch("time.perf_counter") as mock_perf_counter:
            counter = [0.0]
            
            def increment_counter():
                counter[0] += 0.001
                return counter[0]
            
            mock_perf_counter.side_effect = increment_counter
            
            yield {
                "time": mock_time_func,
                "perf_counter": mock_perf_counter
            }


# === Parameterized Fixtures ===

@pytest.fixture(params=[1, 2, 3, 4, 5])
def dimensions(request):
    """Parameterized fixture for testing different dimensions"""
    return request.param


@pytest.fixture(params=[2, 5, 10, 20])
def lattice_size(request):
    """Parameterized fixture for testing different lattice sizes"""
    return request.param


@pytest.fixture(params=["dijkstra", "catalytic", "bfs", "dfs"])
def algorithm(request):
    """Parameterized fixture for testing different algorithms"""
    return request.param


# === Cleanup Fixtures ===

@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment after each test"""
    original_env = os.environ.copy()
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture(autouse=True)
def cleanup_gpu():
    """Cleanup GPU resources after tests"""
    yield
    
    # Clean GPU memory if available
    try:
        import cupy as cp
        cp.get_default_memory_pool().free_all_blocks()
    except ImportError:
        pass


# === Test Utilities ===

class TestHelpers:
    """Collection of test helper functions"""
    
    @staticmethod
    def assert_valid_lattice(lattice_obj):
        """Assert that a lattice object is valid"""
        assert lattice_obj is not None
        assert hasattr(lattice_obj, "dimensions")
        assert hasattr(lattice_obj, "size")
        assert hasattr(lattice_obj, "n_points")
        assert lattice_obj.n_points == lattice_obj.size ** lattice_obj.dimensions
    
    @staticmethod
    def assert_valid_path(path: list, start: int, end: int):
        """Assert that a path is valid"""
        assert isinstance(path, list)
        assert len(path) > 0
        assert path[0] == start
        assert path[-1] == end
    
    @staticmethod
    def create_test_exception(message: str = "Test error"):
        """Create a test exception"""
        return CatalyticException(message)
    
    @staticmethod
    def measure_time(func, *args, **kwargs):
        """Measure execution time of a function"""
        import time
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000
        return result, elapsed


@pytest.fixture
def helpers():
    """Provide test helper utilities"""
    return TestHelpers()


# Export fixtures for IDE autocomplete
__all__ = [
    "setup_test_environment",
    "test_config",
    "temp_dir",
    "sample_lattice_params",
    "sample_coordinates",
    "sample_webhook_config",
    "mock_gpu_device",
    "numpy_arrays",
    "event_loop",
    "async_client",
    "mock_database",
    "mock_redis",
    "mock_api_response",
    "benchmark_data",
    "performance_tracker",
    "json_file",
    "captured_logs",
    "mock_time",
    "dimensions",
    "lattice_size",
    "algorithm",
    "reset_environment",
    "cleanup_gpu",
    "helpers"
]