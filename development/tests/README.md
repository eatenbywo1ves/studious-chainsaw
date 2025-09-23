# Catalytic Computing System - Test Suite Documentation

## Overview

Comprehensive test suite for the Catalytic Computing System, providing unit, integration, performance, and end-to-end testing with >90% code coverage.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── core/               # Core interface and implementation tests
│   ├── gpu/                # GPU abstraction and backend tests
│   ├── config/             # Configuration management tests
│   ├── storage/            # Storage layer tests
│   └── exceptions/         # Error handling tests
├── integration/            # Integration tests for component interactions
│   ├── api/               # API endpoint integration tests
│   ├── gpu/               # GPU backend integration tests
│   └── workflows/         # End-to-end workflow tests
├── performance/           # Performance and benchmark tests
├── e2e/                  # End-to-end system tests
├── conftest.py           # Shared fixtures and configuration
└── run_tests.py          # Test runner script
```

## Running Tests

### Quick Start

```bash
# Run all tests with coverage
python tests/run_tests.py

# Run specific test suite
python tests/run_tests.py unit          # Unit tests only
python tests/run_tests.py integration   # Integration tests
python tests/run_tests.py performance   # Performance tests
python tests/run_tests.py e2e          # End-to-end tests

# Run with markers
python tests/run_tests.py -m gpu       # GPU tests only
python tests/run_tests.py -m "not slow" # Skip slow tests

# Run specific test file
python tests/run_tests.py -t tests/unit/gpu/test_gpu_manager.py

# Quick check (fast unit tests only)
python tests/run_tests.py quick
```

### Advanced Options

```bash
# Run CI suite (all checks)
python tests/run_tests.py ci

# Run with verbose output
python tests/run_tests.py -v

# Skip coverage reporting
python tests/run_tests.py --no-coverage

# Generate coverage report only
python tests/run_tests.py coverage
```

## Test Categories

### Unit Tests (`tests/unit/`)

Fast, isolated tests for individual components:

- **GPU Tests** (`gpu/`): Test GPU manager, factory, and backend implementations
- **Config Tests** (`config/`): Test settings validation and environment variables
- **Core Tests** (`core/`): Test interfaces and base implementations
- **Storage Tests** (`storage/`): Test storage backends and abstractions

### Integration Tests (`tests/integration/`)

Tests for component interactions:

- **API Integration** (`api/`): Test REST API endpoints with real components
- **GPU Integration** (`gpu/`): Test GPU backend selection and fallbacks
- **Workflow Tests** (`workflows/`): Test complete processing pipelines

### Performance Tests (`tests/performance/`)

Benchmark and performance validation:

- Memory efficiency tests (validate 200x reduction claim)
- GPU acceleration benchmarks
- Scaling tests with various lattice sizes
- Concurrent operation stress tests

### End-to-End Tests (`tests/e2e/`)

Complete system tests simulating production usage:

- Production deployment scenarios
- Failover and recovery testing
- Real-world computational workflows

## Test Markers

Tests are marked with pytest markers for selective execution:

- `@pytest.mark.unit` - Unit tests (fast, isolated)
- `@pytest.mark.integration` - Integration tests
- `@pytest.mark.performance` - Performance benchmarks
- `@pytest.mark.gpu` - Tests requiring GPU hardware
- `@pytest.mark.slow` - Long-running tests (>5 seconds)
- `@pytest.mark.benchmark` - Benchmark tests

## Test Fixtures

Common fixtures are provided in `conftest.py`:

```python
# Configuration fixtures
test_config           # Test configuration instance
sample_lattice_params # Sample lattice parameters

# GPU fixtures
mock_gpu_device      # Mock GPU device for testing
gpu_manager         # GPU manager instance

# Data fixtures
numpy_arrays        # Various numpy arrays for testing
sample_coordinates  # Sample coordinate data

# Infrastructure fixtures
temp_dir           # Temporary directory (auto-cleanup)
mock_database      # Mock database connection
mock_redis         # Mock Redis client
async_client       # Async HTTP client for API testing

# Utilities
performance_tracker # Track performance metrics
captured_logs      # Capture log messages
helpers            # Test helper utilities
```

## Writing Tests

### Test Naming Convention

```python
# Unit tests
def test_<component>_<behavior>_<expected_result>():
    """Test that component behaves correctly with expected result."""
    pass

# Integration tests
def test_integration_<workflow>_<scenario>():
    """Test integration workflow for specific scenario."""
    pass

# Performance tests
def test_performance_<operation>_<metric>():
    """Test performance of operation measuring specific metric."""
    pass
```

### Example Test

```python
import pytest
from unittest.mock import Mock, patch
import numpy as np

class TestGPUManager:
    """Test GPU Manager functionality"""

    @pytest.fixture
    def manager(self):
        """Create GPU manager instance"""
        from apps.catalytic.gpu.manager import GPUManager
        return GPUManager()

    def test_singleton_instance(self, manager):
        """Test that GPUManager returns singleton instance"""
        from apps.catalytic.gpu.manager import GPUManager

        manager2 = GPUManager()
        assert manager is manager2

    @pytest.mark.gpu
    def test_device_detection(self, manager):
        """Test GPU device detection"""
        devices = manager.get_all_devices()

        if manager.is_gpu_available():
            assert len(devices) > 0
            assert devices[0].total_memory_mb > 0
        else:
            pytest.skip("No GPU available")

    @pytest.mark.benchmark
    def test_memory_allocation_performance(self, manager, benchmark):
        """Benchmark memory allocation"""
        result = benchmark(manager.allocate_memory, 100.0)
        assert result is True
```

## Coverage Requirements

- **Overall**: >80% coverage
- **Core modules**: >90% coverage
- **GPU abstraction**: >85% coverage
- **API endpoints**: 100% coverage
- **Critical paths**: 100% coverage

View coverage reports:
```bash
# Terminal report
coverage report

# HTML report
coverage html
open htmlcov/index.html
```

## CI/CD Integration

Tests are automatically run in CI/CD pipeline:

1. **Pre-commit**: Quick unit tests
2. **Pull Request**: Full test suite
3. **Main Branch**: Full suite + performance tests
4. **Release**: Full suite + e2e tests

### GitHub Actions Configuration

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-test.txt

    - name: Run tests
      run: python tests/run_tests.py ci

    - name: Upload coverage
      uses: codecov/codecov-action@v3
```

## Test Data

Test data is organized as follows:

- **Fixtures**: Small test data in `conftest.py`
- **Files**: Test files in `tests/data/`
- **Generators**: Data generators in `tests/utils/`

## Performance Baselines

Performance tests validate against these baselines:

| Metric | Baseline | Target |
|--------|----------|--------|
| Memory Reduction | 100x | 200x |
| GPU Speedup | 10x | 50x |
| Path Finding (1000 vertices) | 100ms | 50ms |
| XOR Transform (1MB) | 10ms | 5ms |
| API Response Time | 500ms | 200ms |

## Troubleshooting

### Common Issues

1. **GPU Tests Failing**
   ```bash
   # Skip GPU tests if no hardware available
   pytest -m "not gpu"
   ```

2. **Import Errors**
   ```bash
   # Ensure project is in Python path
   export PYTHONPATH=$PYTHONPATH:/path/to/development
   ```

3. **Slow Tests**
   ```bash
   # Run only fast tests
   pytest -m "not slow"
   ```

4. **Coverage Not Generated**
   ```bash
   # Install coverage package
   pip install pytest-cov coverage
   ```

## Best Practices

1. **Keep tests fast**: Unit tests should run in <1 second
2. **Use fixtures**: Share common setup across tests
3. **Mock external dependencies**: Don't rely on external services
4. **Test edge cases**: Include boundary conditions
5. **Document complex tests**: Add comments for clarity
6. **Use meaningful assertions**: Be specific about expectations
7. **Clean up resources**: Use fixtures with cleanup
8. **Parameterize tests**: Test multiple inputs efficiently

## Contributing

When adding new features:

1. Write tests first (TDD approach)
2. Ensure >90% coverage for new code
3. Add appropriate test markers
4. Update this documentation
5. Run full test suite before committing

## Test Reports

Test reports are generated in:

- `htmlcov/` - HTML coverage reports
- `test-results/` - JUnit XML reports
- `.coverage` - Coverage database

## Contact

For test-related questions or issues:
- Create an issue in the repository
- Tag with `testing` label
- Include test output and environment details