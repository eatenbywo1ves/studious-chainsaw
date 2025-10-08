# End-to-End (E2E) Testing Framework

**Status:** ✅ Complete  
**Test Count:** 10+ comprehensive E2E tests  
**Coverage:** Complete user journeys, GPU workflows, webhook delivery

---

## Overview

E2E tests validate complete user workflows through the entire application stack:

- **User Journeys**: Registration → Login → Lattice Operations → Cleanup → Logout
- **GPU Workflows**: Large lattice processing, performance comparison, concurrency
- **Webhook Delivery**: Event triggering, retry logic, payload validation

Unlike integration tests (which test component interactions), E2E tests simulate **real user behavior** through the complete system.

---

## Quick Start

### 1. Start E2E Environment

```bash
cd C:/Users/Corbin/development/tests/e2e
docker compose -f docker-compose.e2e.yml up -d
```

Wait 40 seconds for all services to initialize.

### 2. Run E2E Tests

#### Windows
```cmd
run_e2e_tests.bat
```

#### Linux/Mac
```bash
chmod +x run_e2e_tests.sh
./run_e2e_tests.sh
```

#### Manual (using pytest)
```bash
# Set environment
set E2E_API_URL=http://localhost:8002  # Windows
export E2E_API_URL=http://localhost:8002  # Linux/Mac

# Run all E2E tests
pytest tests/e2e/ -v

# Run specific test file
pytest tests/e2e/test_user_journey.py -v

# Run specific test
pytest tests/e2e/test_user_journey.py::TestCompleteUserJourney::test_complete_user_workflow -v
```

### 3. View Results

E2E tests provide detailed step-by-step output:

```
[STEP 1] Registering new tenant...
✓ Tenant created: 550e8400-e29b-41d4-a716-446655440000

[STEP 2] Email verification (mocked)...
✓ Email verified

[STEP 3] Testing re-login...
✓ Re-login successful

[STEP 4] Creating first lattice...
✓ First lattice created: 123e4567-e89b-12d3-a456-426614174000

...

============================================================
✓ COMPLETE USER JOURNEY TEST PASSED
============================================================
```

---

## Test Files

### `test_user_journey.py` (4 tests)

Complete user workflow validation:

#### 1. `test_complete_user_workflow()`
**12-step workflow:**
1. Register new tenant
2. Email verification (mocked)
3. Re-login to verify credentials
4. Create first lattice
5. Create GPU-enabled lattice
6. List all lattices
7. Get specific lattice details
8. Test lattice operations
9. Delete one lattice
10. Verify lattice count
11. Cleanup remaining lattices
12. Logout and verify token blacklist

**Duration:** ~5-10 seconds  
**Validates:** Complete platform functionality

#### 2. `test_new_user_onboarding_flow()`
**Simulates:** First-time user experience
- Registration
- Tutorial lattice creation (small, guided)
- Exploration
- Cleanup

#### 3. `test_power_user_workflow()`
**Simulates:** Advanced user creating 10 lattices
- Rapid lattice creation
- Batch operations
- List validation
- Individual access verification

#### 4. `test_user_session_persistence()`
**Simulates:** Long session with 20 consecutive operations
- Session maintenance across operations
- Token validity throughout
- No session timeouts
- Data consistency

---

### `test_gpu_workflow.py` (4 tests)

GPU acceleration validation:

#### 1. `test_large_lattice_gpu_processing()`
**5-step GPU workflow:**
1. Create 2000-element GPU lattice
2. Verify GPU utilization
3. Validate data integrity
4. Test operations
5. Check for memory leaks

**Validates:** GPU acceleration, memory management

#### 2. `test_gpu_cpu_performance_comparison()`
**Compares:** CPU vs GPU for 1000-element lattice
- Creates identical lattices on CPU and GPU
- Measures creation time
- Calculates speedup factor
- Reports performance delta

**Example Output:**
```
PERFORMANCE COMPARISON
Lattice Size: 1000 elements
CPU Time:     2.145s
GPU Time:     0.101s
GPU Speedup:  21.24x faster
```

#### 3. `test_concurrent_gpu_operations()`
**Validates:** Multiple simultaneous GPU operations
- Creates 5 GPU lattices concurrently
- Verifies all complete successfully
- Checks average processing time
- Validates individual lattice access

#### 4. `test_gpu_fallback_graceful_degradation()`
**Validates:** CPU fallback when GPU unavailable
- Requests GPU with fallback enabled
- Should succeed regardless of GPU status
- Verifies lattice functionality
- Documents actual execution path (GPU vs CPU)

---

### `test_webhook_workflow.py` (4 tests)

Webhook event delivery (specification-driven):

#### 1. `test_webhook_event_delivery()`
**5-step webhook workflow:**
1. Register webhook for events
2. Trigger event (create lattice)
3. Wait for async delivery
4. Check delivery logs
5. Cleanup webhook

**Note:** Tests serve as specification if webhooks not yet implemented

#### 2. `test_webhook_retry_logic()`
**Validates:** Retry mechanism for failed deliveries
- Registers webhook to invalid endpoint
- Triggers event (fails to deliver)
- Waits for retry attempts
- Verifies retry count >= 1

#### 3. `test_webhook_payload_validation()`
**Documents:** Expected webhook payload structure
```json
{
  "event": "lattice.created",
  "timestamp": "2025-10-05T20:00:00Z",
  "data": {
    "lattice_id": "uuid",
    "tenant_id": "uuid",
    "name": "string",
    "dimensions": "int",
    "size": "int"
  },
  "signature": "hmac-sha256-signature"
}
```

#### 4. `test_multiple_webhook_subscriptions()`
**Validates:** Multiple webhooks for same event
- Registers 3 webhooks for `lattice.created`
- Triggers single event
- Verifies all 3 webhooks receive notification

---

## E2E Environment

### Docker Services

| Service | Port | Purpose |
|---------|------|---------|
| **postgres-e2e** | 5434 | PostgreSQL 16 database |
| **redis-e2e** | 6381 | Redis 7 (token blacklist, cache) |
| **saas-api-e2e** | 8002 | FastAPI SaaS server (2 workers) |
| **webhook-mock** | 1080 | MockServer for webhook testing |

### Environment Variables

```bash
# API endpoint
E2E_API_URL=http://localhost:8002

# Test timeout
E2E_TIMEOUT=60  # seconds

# Database
DATABASE_URL=postgresql://e2e_user:e2e_password@localhost:5434/e2e_saas

# Redis
REDIS_HOST=localhost
REDIS_PORT=6381
REDIS_PASSWORD=e2e_redis_pass
```

### Configuration Differences from Integration Tests

| Feature | Integration Tests | E2E Tests |
|---------|------------------|-----------|
| **Port** | 8001 | 8002 |
| **Database** | test_saas (5433) | e2e_saas (5434) |
| **Redis** | 6380 | 6381 |
| **Workers** | 1 | 2 |
| **Rate Limit** | 60/min | 1000/min |
| **GPU** | Optional | Disabled (tested separately) |
| **Timeout** | 30s | 60s |

---

## Test Fixtures

### Session-Scoped
- `event_loop` - Async event loop
- `e2e_test_config` - Test configuration

### Function-Scoped
- `e2e_client` - HTTP client with 60s timeout
- `new_tenant` - Fresh tenant with Pro plan
- `authenticated_e2e_client` - Pre-authenticated client with tenant context
- `sample_lattice_small` - 50-element lattice
- `sample_lattice_large` - 2000-element GPU lattice
- `cleanup_lattices` - Auto-cleanup fixture

### Usage Example

```python
@pytest.mark.asyncio
async def test_my_e2e_scenario(
    authenticated_e2e_client: AsyncClient,
    sample_lattice_small,
    cleanup_lattices
):
    # Create lattice
    response = await authenticated_e2e_client.post(
        "/api/lattices",
        json=sample_lattice_small
    )
    assert response.status_code == 201
    
    lattice_id = response.json()["id"]
    cleanup_lattices.append(lattice_id)  # Auto-cleanup after test
    
    # Test operations...
```

---

## Running Options

### Run All E2E Tests
```bash
pytest tests/e2e/ -v
```

### Run Specific Test File
```bash
pytest tests/e2e/test_user_journey.py -v
```

### Run with HTML Report
```bash
pytest tests/e2e/ -v --html=e2e_report.html --self-contained-html
```

### Run Filtered Tests
```bash
# Only GPU tests
pytest tests/e2e/ -v -k "gpu"

# Only journey tests
pytest tests/e2e/ -v -k "journey"

# Exclude webhook tests
pytest tests/e2e/ -v -k "not webhook"
```

### Run with Verbose Output
```bash
pytest tests/e2e/ -vv -s  # -s shows print statements
```

### Run in Parallel
```bash
pytest tests/e2e/ -v -n auto  # Auto-detect CPU count
pytest tests/e2e/ -v -n 4     # Use 4 workers
```

---

## Troubleshooting

### Tests Fail: "Connection refused"

**Cause:** E2E environment not running  
**Fix:**
```bash
docker compose -f docker-compose.e2e.yml up -d
sleep 40  # Wait for initialization
docker compose -f docker-compose.e2e.yml ps  # Verify healthy
```

### Tests Timeout

**Cause:** Services not ready yet  
**Fix:** Increase wait time or check service logs
```bash
docker compose -f docker-compose.e2e.yml logs saas-api-e2e
```

### Database Connection Errors

**Cause:** PostgreSQL not initialized  
**Fix:**
```bash
docker compose -f docker-compose.e2e.yml down -v  # Remove volumes
docker compose -f docker-compose.e2e.yml up -d
```

### Port Already in Use

**Cause:** Previous E2E environment still running  
**Fix:**
```bash
docker compose -f docker-compose.e2e.yml down
# Or change ports in docker-compose.e2e.yml
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  e2e-tests:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.13'
      
      - name: Install dependencies
        run: pip install -r tests/e2e/requirements.txt
      
      - name: Start E2E environment
        run: |
          cd tests/e2e
          docker compose -f docker-compose.e2e.yml up -d
          sleep 40
      
      - name: Run E2E tests
        env:
          E2E_API_URL: http://localhost:8002
          E2E_TIMEOUT: 60
        run: pytest tests/e2e/ -v --html=e2e_report.html
      
      - name: Upload test report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: e2e-test-report
          path: e2e_report.html
      
      - name: Cleanup
        if: always()
        run: |
          cd tests/e2e
          docker compose -f docker-compose.e2e.yml down -v
```

---

## Success Criteria

E2E tests **PASS** when:
- ✅ Complete user workflow succeeds (12 steps)
- ✅ GPU workflows complete without errors
- ✅ Session persists across 20+ operations
- ✅ Concurrent operations succeed
- ✅ Data consistency maintained throughout
- ✅ Token blacklist enforced after logout
- ✅ All created resources cleaned up

---

## Performance Benchmarks

| Test | Expected Duration | Max Duration |
|------|------------------|--------------|
| `test_complete_user_workflow` | 5-10s | 15s |
| `test_large_lattice_gpu_processing` | 3-7s | 10s |
| `test_power_user_workflow` (10 lattices) | 8-12s | 20s |
| `test_user_session_persistence` (20 ops) | 10-15s | 30s |

**Total E2E Suite:** ~60-90 seconds

---

## Next Steps

1. **Add More Scenarios**
   - Multi-user collaboration
   - Subscription upgrade/downgrade
   - Payment processing workflows
   - Admin user management

2. **Visual Regression Testing**
   - Add Playwright for UI testing
   - Screenshot comparison
   - Cross-browser validation

3. **Load Testing Integration**
   - Combine E2E scenarios with load testing
   - Stress test complete workflows
   - Validate under high concurrency

---

## Resources

- **Integration Tests**: `../integration/README.md`
- **API Documentation**: `../../docs/API_DOCUMENTATION.md`
- **Systematic Plan**: `../../SYSTEMATIC_EXECUTION_PLAN_2025-10-05.md`
- **Docker Compose**: `docker-compose.e2e.yml`

---

**Created:** October 5, 2025  
**Status:** Production Ready  
**Phase 3 (Days 6-8):** ✅ Complete
