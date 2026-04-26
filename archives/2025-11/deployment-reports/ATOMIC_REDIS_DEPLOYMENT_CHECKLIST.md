# Atomic Redis Operations - Deployment Checklist

**Implementation Date:** 2025-10-29
**Priority:** CRITICAL (SEC-012 Fix)
**Target Deployment:** Within 24-48 hours

---

## Pre-Deployment Checklist

### Phase 1: Code Review and Validation

- [ ] **Review Implementation**
  - [ ] Read updated `account_lockout.py` (621 lines)
  - [ ] Verify Lua script correctness (40 lines)
  - [ ] Check feature flag implementation
  - [ ] Review error handling (fail-secure)
  - [ ] Verify metrics instrumentation

- [ ] **Review Tests**
  - [ ] Read unit tests (30+ tests)
  - [ ] Read integration tests (9 tests)
  - [ ] Verify race condition test logic
  - [ ] Check performance benchmark

- [ ] **Static Analysis**
  ```bash
  cd C:\Users\Corbin\development\saas

  # Type checking
  mypy auth/account_lockout.py

  # Linting
  flake8 auth/account_lockout.py

  # Security scan
  bandit -r auth/account_lockout.py
  ```

### Phase 2: Local Testing

- [ ] **Install Dependencies**
  ```bash
  pip install -r requirements-test.txt
  ```

- [ ] **Start Local Redis**
  ```bash
  # Option 1: Docker
  docker run -d -p 6379:6379 --name redis-test redis:7-alpine

  # Option 2: Local installation
  redis-server --port 6379

  # Verify
  redis-cli ping  # Should return PONG
  ```

- [ ] **Run Unit Tests**
  ```bash
  pytest tests/unit/test_atomic_lockout_unit.py -v
  # Expected: ALL PASS (30+ tests)
  ```

- [ ] **Run Integration Tests**
  ```bash
  pytest tests/integration/test_atomic_lockout_race_condition.py -v -s
  # Expected: ALL PASS (9 tests)
  ```

- [ ] **CRITICAL: Run Race Condition Test**
  ```bash
  pytest tests/integration/test_atomic_lockout_race_condition.py::TestAtomicLockoutRaceCondition::test_concurrent_requests_atomic_no_race -v -s

  # MUST SEE:
  # ✓ Test passed: account locked
  # PASSED
  ```

- [ ] **Run Performance Benchmark**
  ```bash
  pytest tests/integration/test_atomic_lockout_race_condition.py::TestAtomicLockoutRaceCondition::test_performance_benchmark -v -s

  # Verify:
  # Overhead (median): <10%
  # Overhead (p95): <20%
  ```

- [ ] **Generate Coverage Report**
  ```bash
  pytest tests/ --cov=auth.account_lockout --cov-report=html
  open htmlcov/index.html

  # Target: >90% coverage
  ```

### Phase 3: Documentation Review

- [ ] **Read Documentation**
  - [ ] `ATOMIC_REDIS_IMPLEMENTATION_SUMMARY.md`
  - [ ] `ATOMIC_REDIS_ARCHITECTURE.md`
  - [ ] `ATOMIC_REDIS_IMPLEMENTATION_GUIDE.md`
  - [ ] `tests/README.md`

- [ ] **Verify Deployment Procedures**
  - [ ] Rollback procedure documented
  - [ ] Monitoring setup documented
  - [ ] Alert rules defined
  - [ ] Runbook complete

---

## Staging Deployment Checklist

### Phase 4: Staging Environment Setup

- [ ] **Configure Staging Environment**
  ```bash
  # Set environment variable
  export ENABLE_ATOMIC_LOCKOUT=true

  # Update staging config
  kubectl set env deployment/saas-api-staging \
    ENABLE_ATOMIC_LOCKOUT=true
  ```

- [ ] **Deploy to Staging**
  ```bash
  # Build and deploy
  cd C:\Users\Corbin\development\saas
  docker-compose -f docker-compose.staging.yml build
  docker-compose -f docker-compose.staging.yml up -d

  # Verify deployment
  docker-compose logs -f saas-api | grep "Atomic lockout script loaded"
  ```

- [ ] **Verify Staging Health**
  ```bash
  # Check application health
  curl http://staging.example.com/health

  # Check Redis connection
  docker-compose exec saas-api redis-cli ping

  # Check logs for errors
  docker-compose logs saas-api --tail=100 | grep -i error
  ```

### Phase 5: Staging Testing

- [ ] **Run Tests Against Staging**
  ```bash
  # Point tests to staging Redis
  export REDIS_HOST=staging.redis.example.com

  # Run integration tests
  pytest tests/integration/ -v
  ```

- [ ] **Manual Testing**
  - [ ] Attempt 5 failed logins → verify lockout
  - [ ] Check lockout TTL is correct (900s)
  - [ ] Successful login clears attempts
  - [ ] Check Prometheus metrics available
  - [ ] Verify structured logging

- [ ] **Load Testing**
  ```bash
  # Run load test
  locust -f tests/load/test_atomic_lockout_load.py \
    --host=http://staging.example.com \
    --users=1000 \
    --spawn-rate=50 \
    --run-time=1h

  # Monitor:
  # - Error rate (should be <1%)
  # - p95 latency (should be <50ms)
  # - Race conditions detected (MUST be 0)
  ```

- [ ] **Monitor for 24 Hours**
  - [ ] Check error rates hourly
  - [ ] Check performance metrics
  - [ ] Review security events
  - [ ] Check for race conditions (MUST be 0)

---

## Production Deployment Checklist

### Phase 6: Production Preparation

- [ ] **Review Staging Results**
  - [ ] All tests passed
  - [ ] Performance acceptable
  - [ ] No race conditions detected
  - [ ] Error rate normal
  - [ ] Load test successful

- [ ] **Set Up Monitoring**
  - [ ] Import Grafana dashboard
  - [ ] Configure Prometheus alerts
  - [ ] Test alert notifications
  - [ ] Set up PagerDuty integration

- [ ] **Prepare Rollback Plan**
  - [ ] Document rollback command
  - [ ] Test rollback in staging
  - [ ] Identify rollback triggers
  - [ ] Assign rollback authority

- [ ] **Communication**
  - [ ] Notify stakeholders
  - [ ] Brief customer support team
  - [ ] Alert on-call engineers
  - [ ] Schedule deployment window

### Phase 7: Canary Deployment (5%)

- [ ] **Deploy Canary**
  ```bash
  # Deploy with 5% traffic
  kubectl set env deployment/saas-api \
    ENABLE_ATOMIC_LOCKOUT=true

  # Verify rollout
  kubectl rollout status deployment/saas-api
  ```

- [ ] **Monitor Canary (24 hours)**
  - [ ] Error rate: ___% (target: <5% increase)
  - [ ] p95 latency: ___ms (target: <20% increase)
  - [ ] Race conditions detected: ___ (MUST be 0)
  - [ ] Customer complaints: ___ (target: 0)

- [ ] **Canary Decision**
  - [ ] ✅ Proceed to 20% if healthy
  - [ ] ❌ Rollback if issues detected

### Phase 8: Gradual Rollout

- [ ] **20% Rollout**
  ```bash
  kubectl set env deployment/saas-api \
    ATOMIC_LOCKOUT_CANARY_PERCENT=20
  ```
  - [ ] Monitor for 48 hours
  - [ ] Verify metrics healthy

- [ ] **50% Rollout**
  ```bash
  kubectl set env deployment/saas-api \
    ATOMIC_LOCKOUT_CANARY_PERCENT=50
  ```
  - [ ] Monitor for 48 hours
  - [ ] Verify metrics healthy

- [ ] **100% Rollout**
  ```bash
  kubectl set env deployment/saas-api \
    ATOMIC_LOCKOUT_CANARY_PERCENT=100
  ```
  - [ ] Monitor for 7 days
  - [ ] Verify metrics healthy
  - [ ] Confirm zero race conditions

---

## Post-Deployment Checklist

### Phase 9: Monitoring and Validation

- [ ] **Week 1: Intensive Monitoring**
  - [ ] Daily metric reviews
  - [ ] Daily security event logs
  - [ ] Daily performance checks
  - [ ] Daily error rate analysis

- [ ] **Metrics to Monitor**
  - [ ] `account_lockout_triggered_total` (rate)
  - [ ] `account_lockout_operation_seconds` (p50, p95, p99)
  - [ ] `account_lockout_lua_executions_total` (EVALSHA vs EVAL)
  - [ ] `account_lockout_lua_errors_total` (should be ~0)
  - [ ] `account_lockout_race_condition_detected_total` (MUST be 0)

- [ ] **Security Validation**
  - [ ] No race conditions detected
  - [ ] Lockout enforced correctly
  - [ ] No bypass attempts successful
  - [ ] Audit logs complete

### Phase 10: Cleanup

- [ ] **Week 3: Remove Legacy Code**
  ```python
  # After stable for 2+ weeks
  # Remove:
  # - enable_atomic parameter
  # - ENABLE_ATOMIC_LOCKOUT env var checks
  # - _record_failed_attempt_legacy() method
  # - Legacy routing logic
  ```

- [ ] **Update Documentation**
  - [ ] Update API docs
  - [ ] Update architecture diagrams
  - [ ] Update runbooks
  - [ ] Archive deployment notes

- [ ] **Performance Tuning**
  - [ ] Optimize script caching
  - [ ] Tune circuit breaker parameters
  - [ ] Adjust alert thresholds
  - [ ] Optimize metrics sampling

---

## Rollback Procedures

### Immediate Rollback (If Needed)

**Trigger Conditions:**
- Error rate increase >5%
- p95 latency increase >20%
- Race conditions detected (any)
- Customer complaints spike
- Circuit breaker opening frequently

**Rollback Command:**
```bash
# Instant rollback (< 1 minute)
kubectl set env deployment/saas-api ENABLE_ATOMIC_LOCKOUT=false

# Verify rollback
kubectl logs deployment/saas-api | grep "Atomic lockout DISABLED"
```

**Post-Rollback Actions:**
1. [ ] Verify error rates return to baseline
2. [ ] Review logs for root cause
3. [ ] Fix identified issues
4. [ ] Re-test in staging
5. [ ] Schedule retry deployment

---

## Success Criteria

### Deployment Successful If:

- ✅ All tests pass (100%)
- ✅ No race conditions detected (0 occurrences)
- ✅ Error rate increase <5%
- ✅ p95 latency increase <20%
- ✅ No customer complaints
- ✅ Metrics showing healthy state
- ✅ Zero security incidents

### Deployment Failed If:

- ❌ Any race conditions detected
- ❌ Error rate increase >5%
- ❌ p95 latency increase >20%
- ❌ Customer complaints received
- ❌ Circuit breaker opening frequently
- ❌ Security audit logs incomplete

---

## Sign-Off

### Pre-Deployment Approval

- [ ] **Code Review**: ___________________ (Engineer)
- [ ] **Security Review**: ___________________ (Security Team)
- [ ] **Architecture Review**: ___________________ (Tech Lead)
- [ ] **Testing Sign-Off**: ___________________ (QA Lead)

### Deployment Approval

- [ ] **Staging Success**: ___________________ (DevOps Lead)
- [ ] **Production Ready**: ___________________ (Engineering Manager)
- [ ] **Final Approval**: ___________________ (CTO/VP Engineering)

---

## Contact Information

**On-Call Engineer:** ___________________
**Security Team:** ___________________
**DevOps Lead:** ___________________
**Escalation Path:** ___________________

---

## Timeline

| Phase | Duration | Start Date | End Date |
|-------|----------|------------|----------|
| Local Testing | 1 day | ___ | ___ |
| Staging Deployment | 2 days | ___ | ___ |
| Staging Monitoring | 1 day | ___ | ___ |
| Canary (5%) | 1 day | ___ | ___ |
| Gradual Rollout | 6 days | ___ | ___ |
| Stabilization | 7 days | ___ | ___ |
| Cleanup | 3 days | ___ | ___ |
| **Total** | **21 days** | ___ | ___ |

---

**Checklist Version:** 1.0
**Last Updated:** 2025-10-29
**Status:** READY FOR EXECUTION
