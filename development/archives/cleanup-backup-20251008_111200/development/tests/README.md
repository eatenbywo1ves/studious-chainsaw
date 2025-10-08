# Test Suite Documentation

## Overview

This test suite provides comprehensive testing for the Catalytic Computing development environment, including unit tests, integration tests, and performance benchmarks.

## Test Structure

```
tests/
├── unit/                  # Fast, isolated unit tests
│   ├── apps/             # Application-specific tests
│   │   └── test_catalytic.py
│   ├── services/         # Service-specific tests
│   └── test_gpu_libraries.py
├── integration/          # Integration tests with dependencies
│   └── test_saas_platform.py
├── performance/          # Performance benchmarks
│   └── test_benchmarks.py
├── conftest.py          # Shared test configuration
└── README.md           # This file
```

## Test Categories

### Unit Tests (`pytest tests/unit/`)
- **GPU Libraries**: PyTorch, CuPy, Numba functionality
- **Catalytic Computing**: Core algorithms and memory efficiency
- **GPU Acceleration**: Backend factory and implementations
- **KA Lattice**: Knowledge-augmented lattice functionality

### Integration Tests (`pytest tests/integration/`)
- **SaaS Platform**: API endpoints and workflows
- **Database**: PostgreSQL connectivity and schema
- **Redis**: Caching and session management
- **Docker**: Container orchestration
- **End-to-End**: Complete user workflows

### Performance Tests (`pytest tests/performance/`)
- **GPU Performance**: Matrix operations and memory transfer
- **Catalytic Performance**: Lattice creation and path finding
- **Scalability**: Performance across different problem sizes
- **Comparative**: CPU vs GPU, Catalytic vs Traditional

## Running Tests

### Quick Test Run
```bash
# Run all unit tests
pytest tests/unit/ -v

# Run specific test file
pytest tests/unit/test_gpu_libraries.py -v

# Run tests with specific markers
pytest -m "not gpu" -v  # Skip GPU tests
```

### Full Test Suite
```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=apps --cov=services --cov-report=html

# Run performance benchmarks
pytest tests/performance/ --benchmark-only
```

### GPU Tests
```bash
# Run only GPU tests (requires GPU hardware)
pytest -m gpu -v

# Run GPU tests with performance benchmarks
pytest -m "gpu and performance" --benchmark-only
```

### Integration Tests
```bash
# Run integration tests (requires running services)
pytest tests/integration/ -v

# Run with specific service requirements
pytest -m database -v  # Database tests only
pytest -m redis -v     # Redis tests only
```

## Test Markers

- `unit`: Fast, isolated unit tests
- `integration`: Tests requiring external services
- `performance`: Performance and benchmark tests
- `gpu`: Tests requiring GPU hardware
- `slow`: Long-running tests
- `database`: Tests requiring PostgreSQL
- `redis`: Tests requiring Redis
- `docker`: Tests requiring Docker

## Configuration

### pytest.ini
Contains test configuration including:
- Test discovery patterns
- Output formatting
- Coverage settings
- Marker definitions
- Timeout settings

### conftest.py
Provides shared fixtures:
- `temp_dir`: Temporary directory
- `mock_gpu_env`: Mock GPU environment
- `sample_data`: Test data
- `database_url`: Test database URL
- `redis_url`: Test Redis URL

## Requirements

### Basic Testing
```bash
pip install -r requirements-dev.txt
```

### GPU Testing
- NVIDIA GPU with CUDA support
- PyTorch with CUDA
- CuPy for CUDA 12.x
- Numba with CUDA support

### Integration Testing
- PostgreSQL server
- Redis server
- Docker and Docker Compose (for containerized tests)

## Performance Baselines

### Expected GPU Performance (GTX 1080)
- **PyTorch**: >6.0 TFLOPS matrix multiplication
- **CuPy**: >6.0 TFLOPS matrix multiplication
- **Memory Transfer**: <10ms for 1M elements

### Expected Catalytic Performance
- **Memory Efficiency**: >100x reduction vs traditional
- **Path Finding**: <1ms for small lattices
- **Scalability**: Linear or near-linear scaling

## Troubleshooting

### GPU Tests Failing
1. Check GPU availability: `nvidia-smi`
2. Verify CUDA installation
3. Test GPU libraries individually
4. Check memory usage: `gpustat`

### Integration Tests Failing
1. Verify services are running: `docker-compose ps`
2. Check network connectivity
3. Validate service configurations
4. Review service logs

### Performance Tests Slow
1. Check system resources
2. Close unnecessary applications
3. Use GPU monitoring: `nvidia-smi -l 1`
4. Verify thermal throttling

## Continuous Integration

Tests are automatically run in CI/CD pipeline:
- **Development Workflow**: Quick validation on feature branches
- **CI/CD Pipeline**: Full test suite on main branch
- **GPU Performance**: Scheduled weekly performance monitoring

### GitHub Actions Workflows
- `development.yml`: Quick checks for development
- `ci-cd.yml`: Full CI/CD pipeline
- `gpu-performance.yml`: GPU performance monitoring

## Adding New Tests

### Unit Tests
```python
def test_new_functionality():
    # Arrange
    input_data = "test input"
    
    # Act
    result = function_under_test(input_data)
    
    # Assert
    assert result == expected_output
```

### Performance Tests
```python
@pytest.mark.performance
def test_performance_benchmark(benchmark):
    result = benchmark(function_to_benchmark)
    assert result is not None
```

### GPU Tests
```python
@pytest.mark.gpu
def test_gpu_functionality():
    torch = pytest.importorskip("torch")
    if not torch.cuda.is_available():
        pytest.skip("GPU not available")
    # Test GPU functionality
```

## Best Practices

1. **Fast Unit Tests**: Keep unit tests fast (<1s each)
2. **Isolated Tests**: Each test should be independent
3. **Clear Assertions**: Use descriptive assertion messages
4. **Proper Cleanup**: Clean up resources in teardown
5. **Skip When Needed**: Skip tests when dependencies unavailable
6. **Performance Baselines**: Set realistic performance expectations
7. **Error Messages**: Provide helpful error messages for failures