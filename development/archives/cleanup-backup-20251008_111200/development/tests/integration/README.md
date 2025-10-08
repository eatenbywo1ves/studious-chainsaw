# Integration Test Suite

**Status:** ✅ Complete  
**Coverage:** Full SaaS workflow, GPU integration, Security, Monitoring  
**Test Count:** 30+ comprehensive integration tests

---

## Overview

This integration test suite validates the complete SaaS platform across all services:

- **Full SaaS Workflow** - User registration → JWT auth → Lattice operations
- **GPU Integration** - GPU acceleration, fallback, concurrent usage, memory management
- **Security** - JWT validation, rate limiting, input validation, multi-tenancy
- **Monitoring** - Prometheus metrics, health checks, alerting

---

## Quick Start

### 1. Start Test Environment

```bash
cd C:/Users/Corbin/development/tests/integration
docker compose -f docker-compose.test.yml up -d
```

Wait for services to be healthy (~30 seconds):

```bash
docker compose -f docker-compose.test.yml ps
```

### 2. Run All Tests

```bash
# Run all integration tests
pytest tests/integration/ -v

# Run with coverage
pytest tests/integration/ -v --cov=saas --cov=apps/catalytic --cov-report=html

# Run specific test file
pytest tests/integration/test_full_saas_workflow.py -v

# Run specific test
pytest tests/integration/test_full_saas_workflow.py::TestFullSaaSWorkflow::test_user_registration_to_lattice_creation -v
```

### 3. View Results

```bash
# View coverage report
open htmlcov/index.html  # macOS/Linux
start htmlcov/index.html  # Windows
```

---

## Test Files

### `test_full_saas_workflow.py` (8 tests)
Complete user journey validation:
- ✅ User registration → login → lattice creation workflow
- ✅ Concurrent user operations (10 simultaneous users)
- ✅ JWT token lifecycle (creation, validation, blacklist, expiry)
- ✅ Invalid authentication scenarios
- ✅ Rate limiting enforcement
- ✅ Input validation (SQL injection, XSS, type validation)

**Key Test:**
```python
test_user_registration_to_lattice_creation()
# 1. Register user
# 2. Login and get JWT
# 3. Create KA Lattice
# 4. Perform lattice operations
# 5. Validate results
# 6. Check rate limiting
# 7. Verify audit logs
```

### `test_gpu_saas_integration.py` (6 tests)
GPU acceleration validation:
- ✅ Large lattice GPU processing (>1000 elements)
- ✅ CPU fallback when GPU unavailable
- ✅ Concurrent GPU requests (5 simultaneous)
- ✅ GPU memory management (allocation/deallocation)
- ✅ CPU vs GPU performance tracking
- ✅ GPU batch operations

**Key Test:**
```python
test_concurrent_gpu_requests()
# Creates 5 GPU-enabled lattices simultaneously
# Validates GPU queue management
# Verifies no memory leaks
```

### `test_security_integration.py` (10 tests)
Security feature validation:
- ✅ JWT validation across all services
- ✅ Rate limiting (10 req/min enforcement)
- ✅ SQL injection prevention
- ✅ XSS attack prevention
- ✅ CORS and security headers (HSTS, CSP, X-Frame-Options)
- ✅ Password complexity requirements
- ✅ Token blacklist functionality
- ✅ Multi-tenant data isolation
- ✅ Brute force protection

**Key Test:**
```python
test_multi_tenant_data_isolation()
# User 1 creates lattice
# User 2 attempts to access User 1's lattice
# Verifies 403/404 (access denied)
# Validates Row-Level Security (RLS)
```

### `test_monitoring_integration.py` (12 tests)
Observability validation:
- ✅ Prometheus metrics endpoint
- ✅ Custom application metrics
- ✅ Health check endpoints
- ✅ Readiness and liveness probes
- ✅ Error rate tracking
- ✅ Latency percentile tracking (p50, p95, p99)
- ✅ Database connection pool metrics
- ✅ Redis metrics
- ✅ GPU utilization metrics
- ✅ Alert condition triggering
- ✅ Trace ID propagation
- ✅ Metrics cardinality limits

**Key Test:**
```python
test_prometheus_scrapes_metrics()
# Validates /metrics endpoint
# Verifies Prometheus format
# Checks for standard HTTP metrics
```

---

## Test Environment

### Services

| Service | Port | Health Check |
|---------|------|--------------|
| PostgreSQL | 5433 | `pg_isready -U postgres` |
| Redis | 6380 | `redis-cli -a test_redis_password ping` |
| SaaS API | 8001 | `http://localhost:8001/health` |

### Environment Variables

```bash
# Database
TEST_DATABASE_URL=postgresql://postgres:postgres@localhost:5433/test_saas

# Redis
TEST_REDIS_HOST=localhost
TEST_REDIS_PORT=6380
TEST_REDIS_PASSWORD=test_redis_password

# API
TEST_API_URL=http://localhost:8001
```

### Docker Network

All services run on `test-network` bridge network for isolated testing.

---

## Test Fixtures

### `conftest.py` Fixtures

**Session-scoped:**
- `event_loop` - Async event loop
- `test_db_engine` - SQLAlchemy engine
- `redis_client` - Redis async client

**Function-scoped:**
- `api_client` - HTTP client for API testing
- `authenticated_client` - HTTP client with JWT token
- `clean_redis` - Flushes Redis before each test
- `sample_lattice_data` - Sample KA Lattice payload

**Usage Example:**
```python
@pytest.mark.asyncio
async def test_example(authenticated_client: AsyncClient, sample_lattice_data):
    response = await authenticated_client.post("/lattices", json=sample_lattice_data)
    assert response.status_code == 201
```

---

## Performance Targets

Integration tests validate these performance targets:

| Metric | Target | Test |
|--------|--------|------|
| API Latency (p95) | <500ms | `test_latency_percentile_tracking` |
| Concurrent Users | 10+ | `test_concurrent_user_operations` |
| Rate Limit | 10 req/min | `test_rate_limiting_enforcement` |
| GPU Concurrency | 5+ | `test_concurrent_gpu_requests` |

---

## Success Criteria

**Integration tests PASS when:**
- ✅ All user workflows complete successfully
- ✅ JWT authentication works across all services
- ✅ Rate limiting enforces configured limits
- ✅ Input validation prevents SQL injection and XSS
- ✅ Multi-tenant isolation prevents cross-tenant access
- ✅ GPU acceleration works (or gracefully falls back to CPU)
- ✅ Prometheus metrics are exposed and valid
- ✅ Health checks return 200 OK

---

## Troubleshooting

### Tests Fail: "Connection refused"

**Cause:** Services not running  
**Fix:**
```bash
docker compose -f docker-compose.test.yml up -d
docker compose -f docker-compose.test.yml ps  # Verify all healthy
```

### Tests Fail: "Database does not exist"

**Cause:** PostgreSQL not initialized  
**Fix:**
```bash
docker compose -f docker-compose.test.yml down -v  # Remove volumes
docker compose -f docker-compose.test.yml up -d    # Recreate
```

### Tests Fail: "Redis connection error"

**Cause:** Redis not accepting connections  
**Fix:**
```bash
docker compose -f docker-compose.test.yml restart redis-test
```

### Tests Timeout

**Cause:** Services not healthy yet  
**Fix:**
```bash
# Wait for health checks to pass
docker compose -f docker-compose.test.yml ps

# Check logs
docker compose -f docker-compose.test.yml logs saas-api-test
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Integration Tests

on: [push, pull_request]

jobs:
  integration-tests:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.13'
      
      - name: Install dependencies
        run: |
          pip install pytest pytest-asyncio httpx
      
      - name: Start test environment
        run: |
          cd tests/integration
          docker compose -f docker-compose.test.yml up -d
          sleep 30  # Wait for services
      
      - name: Run integration tests
        run: |
          pytest tests/integration/ -v --tb=short
      
      - name: Cleanup
        run: |
          cd tests/integration
          docker compose -f docker-compose.test.yml down -v
```

---

## Next Steps

1. **Add More Tests**
   - Webhook delivery tests
   - File upload/download tests
   - Subscription and billing tests

2. **Performance Testing**
   - Add load tests (see `tests/load/`)
   - Measure p99 latency under load
   - Test database connection pool limits

3. **Chaos Testing**
   - Network partition tests
   - Service failure recovery
   - Database connection loss

4. **E2E Testing**
   - Browser-based UI tests
   - Mobile app integration tests
   - Third-party API integration tests

---

## Resources

- **Pytest Docs:** https://docs.pytest.org/
- **pytest-asyncio:** https://github.com/pytest-dev/pytest-asyncio
- **HTTPX:** https://www.python-httpx.org/
- **Docker Compose:** https://docs.docker.com/compose/

---

**Created:** October 5, 2025  
**Last Updated:** October 5, 2025  
**Maintainer:** Claude Code + SaaS Platform Team
