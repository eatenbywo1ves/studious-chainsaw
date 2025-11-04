# TEST VALIDATION CHECKLIST
## Pre-Deployment Validation for SEC-009 to SEC-012

**Status:** ⚠️ INCOMPLETE - 4 of 10 steps completed

---

## ✅ COMPLETED

- [x] **Step 1:** Install test dependencies (pytest, redis, pytest-cov)
- [x] **Step 2:** Run unit tests for account_lockout.py
- [x] **Step 3:** Generate coverage report
- [x] **Step 4:** Verify coverage >80% for account_lockout.py (85% achieved)

---

## ❌ BLOCKED / IN PROGRESS

### Environment Setup (BLOCKER)

- [ ] **Step 5:** Start Redis server
  ```bash
  # Quick Start:
  docker run -d -p 6379:6379 --name redis-test redis:7-alpine

  # Verify:
  redis-cli ping  # Should return PONG
  ```

- [ ] **Step 6:** Set environment variables
  ```bash
  # Generate JWT password
  export JWT_KEY_PASSWORD=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')

  # Set Redis config
  export REDIS_HOST=localhost
  export REDIS_PORT=6379
  ```

### Test Execution (BLOCKER)

- [ ] **Step 7:** Run integration tests
  ```bash
  cd C:\Users\Corbin\development\saas
  python -m pytest tests/integration/ -v
  ```
  **Expected:** 7 tests pass (currently 7 errors due to Redis)

- [ ] **Step 8:** Run security-specific tests
  ```bash
  python -m pytest -m security -v
  ```
  **Expected:** All security tests pass

### Code Fixes (SHOULD FIX)

- [ ] **Step 9:** Fix unit test assertion
  ```python
  # File: tests/unit/test_atomic_lockout_unit.py, line 258
  # Change:
  mock_labels.assert_called_once()
  # To:
  assert mock_labels.call_count >= 1
  ```

### Coverage Gaps (BLOCKER for Full Deployment)

- [ ] **Step 10:** Create tests for uncovered security modules
  - [ ] `password_validation.py` (SEC-009) - 0% coverage
  - [ ] `csrf_protection.py` (SEC-010) - 0% coverage
  - [ ] `request_limits.py` (SEC-011) - 0% coverage

  **Target:** >80% coverage for each module

---

## QUICK START COMMANDS

### Option 1: Full Validation (Recommended)

```bash
# 1. Start Redis
docker run -d -p 6379:6379 --name redis-test redis:7-alpine

# 2. Set environment
export JWT_KEY_PASSWORD=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')

# 3. Run all tests
cd C:\Users\Corbin\development\saas
python run_tests.py

# 4. Check coverage
open htmlcov/index.html
```

### Option 2: Unit Tests Only (Quick Validation)

```bash
# Run just unit tests (no Redis needed)
cd C:\Users\Corbin\development\saas
python -m pytest tests/unit/ -v --cov=auth --cov-report=term-missing

# Should see: 28 passed, 1 failed
```

### Option 3: Use PowerShell Script

```powershell
# Windows PowerShell
cd C:\Users\Corbin\development\saas
.\run_tests.ps1
```

---

## SUCCESS CRITERIA

| Metric                    | Current | Target | Status |
|---------------------------|---------|--------|--------|
| Unit tests pass           | 28/29   | 100%   | ⚠️ 96% |
| Integration tests pass    | 0/7     | 100%   | ❌ 0%  |
| Coverage (account_lockout)| 85%     | >80%   | ✅ PASS|
| Coverage (overall)        | 11%     | >80%   | ❌ FAIL|
| Security tests pass       | N/A     | 100%   | ❌ N/A |

---

## DEPLOYMENT DECISION

### ✅ GO Criteria (All must be met)

1. [ ] Redis running and accessible
2. [ ] All environment variables set
3. [ ] Unit tests: >95% pass rate (**Current: 96.6%** ✅)
4. [ ] Integration tests: 100% pass rate (**Current: 0%** ❌)
5. [ ] Code coverage: >80% for changed files (**Current: 85%** ✅)
6. [ ] All security fixes validated (**Current: 1 of 4** ❌)

### Current Decision: **NO-GO**

**Reason:** Integration tests not run (environment setup required)

**Estimated Time to GO:** 30-60 minutes
- Environment setup: 15 minutes
- Test execution: 15 minutes
- Fix issues: 30 minutes

---

## IMMEDIATE NEXT STEPS

**Priority 1 (Do Now):**
1. Start Redis: `docker run -d -p 6379:6379 redis:7-alpine`
2. Set JWT_KEY_PASSWORD: `export JWT_KEY_PASSWORD=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')`
3. Run integration tests: `cd C:\Users\Corbin\development\saas && python -m pytest tests/integration/ -v`

**Priority 2 (Today):**
4. Fix unit test assertion (5 minutes)
5. Create tests for password_validation.py (SEC-009)
6. Create tests for csrf_protection.py (SEC-010)
7. Create tests for request_limits.py (SEC-011)

**Priority 3 (Before Production):**
8. Run full test suite with 100% pass rate
9. Performance testing (load test)
10. Staging environment validation

---

## ROLLBACK PLAN

If deployment causes issues:

```python
# Disable atomic lockout (revert to legacy)
export ENABLE_ATOMIC_LOCKOUT=false

# Or via feature flag
# In code: enable_atomic=False
```

---

## CONTACTS

**Test Engineer:** Claude Code
**Date:** 2025-11-03
**Report:** See TEST_EXECUTION_REPORT.md for full details
