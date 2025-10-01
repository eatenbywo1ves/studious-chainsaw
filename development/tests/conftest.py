"""
Pytest configuration and fixtures for the development environment test suite.
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)

@pytest.fixture
def mock_gpu_env(monkeypatch):
    """Mock GPU environment variables for testing without GPU."""
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    monkeypatch.setenv("NVIDIA_VISIBLE_DEVICES", "0")

@pytest.fixture
def sample_data():
    """Sample data for testing."""
    return {
        "matrix_2d": [[1, 2], [3, 4]],
        "vector": [1, 2, 3, 4, 5],
        "lattice_config": {
            "dimensions": 3,
            "size": 10,
            "name": "test_lattice"
        }
    }

@pytest.fixture
def database_url():
    """Test database URL."""
    return "postgresql://test:test@localhost:5432/test_db"

@pytest.fixture
def redis_url():
    """Test Redis URL."""
    return "redis://localhost:6379/1"

@pytest.fixture
def sample_config():
    """Provide sample SSH monitor configuration for tests"""
    return {
        "device": {
            "name": "Test Device",
            "tailscale_hostname": "test-device",
            "ssh_port": 8022,
            "ssh_user": "testuser"
        },
        "monitoring": {
            "check_interval_seconds": 30,
            "connection_timeout_seconds": 10,
            "max_retry_attempts": 5,
            "exponential_backoff": True,
            "backoff_multiplier": 2,
            "max_backoff_seconds": 300
        },
        "reconnection": {
            "enabled": True,
            "restart_sshd_command": "sshd",
            "restart_tailscale_command": None
        },
        "notifications": {
            "log_to_file": False,
            "console_output": False,
            "notify_on_failure": True,
            "notify_on_recovery": True
        }
    }

@pytest.fixture
def mock_gpu_available():
    """Mock GPU availability for tests"""
    from unittest.mock import patch
    with patch('torch.cuda.is_available', return_value=True):
        yield

@pytest.fixture
def mock_gpu_unavailable():
    """Mock GPU unavailability for tests"""
    from unittest.mock import patch
    with patch('torch.cuda.is_available', return_value=False):
        yield

# Skip GPU tests if CUDA is not available
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "gpu: mark test as requiring GPU hardware"
    )

def pytest_collection_modifyitems(config, items):
    """Skip GPU tests if no GPU is available."""
    try:
        import torch
        gpu_available = torch.cuda.is_available()
    except ImportError:
        gpu_available = False
    
    if not gpu_available:
        skip_gpu = pytest.mark.skip(reason="GPU not available")
        for item in items:
            if "gpu" in item.keywords:
                item.add_marker(skip_gpu)