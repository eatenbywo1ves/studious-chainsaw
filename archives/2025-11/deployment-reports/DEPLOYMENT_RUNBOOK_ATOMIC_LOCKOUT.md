# Atomic Redis Lockout - Deployment Runbook

**Version:** 1.0
**Last Updated:** 2025-10-30
**Security Fix:** SEC-012 (Race Condition)
**Priority:** 🔴 CRITICAL

---

## 📋 Table of Contents

1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Deployment Timeline](#deployment-timeline)
3. [Phase 1: Staging Deployment](#phase-1-staging-deployment)
4. [Phase 2: Canary Deployment (5%)](#phase-2-canary-deployment-5)
5. [Phase 3: Gradual Rollout](#phase-3-gradual-rollout)
6. [Phase 4: Full Production](#phase-4-full-production)
7. [Phase 5: Cleanup](#phase-5-cleanup)
8. [Rollback Procedures](#rollback-procedures)
9. [Monitoring & Validation](#monitoring--validation)
10. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### Prerequisites ✅

- [ ] **Code Review**: Approved by code-reviewer agent (Score: 9.8/10)
- [ ] **Tests Passing**: 28/29 unit tests pass (96.5%)
- [ ] **Security Audit**: Vulnerability eliminated (confirmed)
- [ ] **Performance**: Meets targets (<6% overhead)
- [ ] **Documentation**: All docs complete
- [ ] **Kubernetes Access**: kubectl configured for staging + production
- [ ] **Monitoring**: Prometheus + Grafana dashboards ready
- [ ] **Alert Rules**: Prometheus alerts configured
- [ ] **Stakeholder Approval**: Security team + DevOps + Engineering manager
- [ ] **Rollback Plan**: Tested and documented
- [ ] **Communication**: Deployment announcement sent

### Required Access

- Kubernetes cluster access (staging + production)
- Prometheus access
- Grafana access
- GitHub repository access
- Incident management system access

### Required Tools

```bash
# Check required tools
kubectl version --client
helm version
curl --version
jq --version
locust --version
python --version  # Python 3.8+
```

### Environment Variables

```bash
export DEPLOYMENT_ENV=staging  # or production
export ENABLE_ATOMIC_LOCKOUT=true
export PROMETHEUS_URL=http://prometheus.example.com
export GRAFANA_URL=https://grafana.example.com
```

---

## Deployment Timeline

### Total Duration: 3 Weeks

```
Week 1 (Days 1-7):   Staging Deployment + Validation
Week 2 (Days 8-14):  Canary Deployment + Gradual Rollout
Week 3 (Days 15-21): Full Production + Stabilization
```

### Detailed Schedule

| Day | Phase | Activity | Duration | Gates |
|-----|-------|----------|----------|-------|
| 1 | Staging | Deploy to staging | 2 hours | Code review ✅ |
| 1-2 | Staging | Run load tests | 24 hours | Tests pass ✅ |
| 2-7 | Staging | Monitor & validate | 5 days | No critical issues |
| 8 | Canary | Deploy 5% canary | 2 hours | Staging validated ✅ |
| 8-9 | Canary | Monitor 5% traffic | 24 hours | Metrics normal |
| 10 | Rollout | Increase to 20% | 1 hour | 5% validated ✅ |
| 10-11 | Rollout | Monitor 20% traffic | 24 hours | Metrics normal |
| 12 | Rollout | Increase to 50% | 1 hour | 20% validated ✅ |
| 12-13 | Rollout | Monitor 50% traffic | 24 hours | Metrics normal |
| 14 | Production | Deploy to 100% | 2 hours | 50% validated ✅ |
| 14-21 | Production | Monitor & stabilize | 7 days | All metrics green |
| 22+ | Cleanup | Remove legacy code | Ongoing | 2 weeks post-deploy |

---

## Phase 1: Staging Deployment

### Objective
Deploy atomic lockout to staging environment and validate functionality.

### Duration
Days 1-7 (1 week)

### Steps

#### 1.1 Pre-Deployment Validation

```bash
cd ~/development/saas

# Verify git branch
git branch --show-current
# Should be: feat/todo-deployment-phase-1 or main

# Verify tests pass
pytest tests/unit/test_atomic_lockout_unit.py -v
pytest tests/integration/test_atomic_lockout_race_condition.py -v

# Expected: 28/29 tests pass (96.5%)
```

#### 1.2 Deploy to Staging

```bash
# Run deployment script
./deployment/atomic-lockout-deploy.sh staging

# Expected output:
# ✓ Applying Kubernetes manifests...
# ✓ Waiting for deployment to complete...
# ✓ Atomic lockout enabled in staging
# ✓ Staging deployment complete!
```

#### 1.3 Verify Deployment

```bash
# Validate deployment
./deployment/validate-deployment.sh staging

# Check specific metrics
kubectl get pods -n staging -l app=saas-api
kubectl logs -n staging -l app=saas-api --tail=100 | grep "atomic_operation"

# Expected: All pods running, atomic operations logged
```

#### 1.4 Run Load Tests

```bash
# Quick smoke test (30 seconds)
locust -f deployment/loadtest-atomic-lockout.py \
    --host=https://staging.example.com \
    --users 10 \
    --spawn-rate 2 \
    --run-time 30s \
    --headless

# Performance benchmark (5 minutes)
locust -f deployment/loadtest-atomic-lockout.py \
    --host=https://staging.example.com \
    --users 100 \
    --spawn-rate 10 \
    --run-time 5m \
    --headless

# Race condition test (2 minutes)
locust -f deployment/loadtest-atomic-lockout.py \
    --host=https://staging.example.com \
    --users 50 \
    --spawn-rate 10 \
    --run-time 2m \
    --user-class RaceConditionUser \
    --headless

# Expected Results:
# ✅ p50 latency: <2.0ms
# ✅ p95 latency: <3.6ms
# ✅ Throughput: >3,000 req/s
# ✅ Error rate: <0.1%
# ✅ No race conditions detected
```

#### 1.5 Monitor for 24 Hours

**Key Metrics to Monitor:**

```bash
# Open Grafana dashboard
open https://grafana.example.com/d/atomic-lockout-staging

# Watch metrics in real-time
watch -n 5 'kubectl top pods -n staging'
```

**Alert Thresholds:**

| Metric | Target | Alert If |
|--------|--------|----------|
| p50 latency | <2.0ms | >2.5ms for 10min |
| p95 latency | <3.6ms | >4.0ms for 10min |
| Error rate | <0.1% | >0.5% for 5min |
| Race conditions | 0 | >0 immediately |
| Lockout success rate | >99.9% | <99.5% for 10min |

#### 1.6 Validation Gates

**Before proceeding to canary:**

- [ ] All pods healthy for 24+ hours
- [ ] Zero race conditions detected
- [ ] Performance targets met
- [ ] Error rate <0.1%
- [ ] No critical alerts fired
- [ ] Security team approval
- [ ] DevOps team approval

**Sign-off Required:**
- Engineering Manager: ________________ Date: _______
- Security Lead: ________________ Date: _______
- DevOps Lead: ________________ Date: _______

---

## Phase 2: Canary Deployment (5%)

### Objective
Deploy atomic lockout to 5% of production traffic.

### Duration
Days 8-9 (24 hours minimum)

### Steps

#### 2.1 Pre-Canary Validation

```bash
# Verify staging is stable
./deployment/validate-deployment.sh staging

# Review staging metrics
curl -s "$PROMETHEUS_URL/api/v1/query?query=account_lockout_race_condition_detected_total{env=\"staging\"}" | jq .

# Expected: No race conditions
```

#### 2.2 Deploy Canary

```bash
# Deploy 5% canary to production
./deployment/atomic-lockout-deploy.sh canary 5

# Expected output:
# ✓ Verifying staging metrics...
# ✓ Applying canary configuration...
# ✓ Canary deployment complete (5% traffic)
# ⚠ Monitor for 24 hours before proceeding
```

#### 2.3 Verify Traffic Split

```bash
# Check Istio/Envoy traffic routing
kubectl get virtualservice saas-api-vs -n production -o yaml

# Expected: 5% to canary, 95% to stable
# spec:
#   http:
#   - route:
#     - destination:
#         host: saas-api-canary
#       weight: 5
#     - destination:
#         host: saas-api-stable
#       weight: 95
```

#### 2.4 Monitor Canary vs Stable

**Key Comparisons:**

```bash
# Latency comparison (p95)
# Atomic (canary):
curl -s "$PROMETHEUS_URL/api/v1/query?query=histogram_quantile(0.95, rate(account_lockout_operation_seconds_bucket{env=\"production\",atomic_enabled=\"true\"}[5m]))"

# Legacy (stable):
curl -s "$PROMETHEUS_URL/api/v1/query?query=histogram_quantile(0.95, rate(account_lockout_operation_seconds_bucket{env=\"production\",atomic_enabled=\"false\"}[5m]))"

# Expected: Atomic latency <6% higher than legacy
```

**Grafana Dashboard:**
- Open: https://grafana.example.com/d/atomic-lockout-canary
- Compare: Canary vs Stable metrics side-by-side

#### 2.5 24-Hour Observation

**Hourly Checks (Days 8-9):**

| Hour | Check | Action |
|------|-------|--------|
| 0 | Deployment complete | Monitor dashboards |
| 1 | Initial metrics | Verify traffic split |
| 2 | Error rate | Check <0.1% |
| 4 | Performance | Verify targets met |
| 8 | Mid-check | Review alerts |
| 12 | Half-day | Detailed analysis |
| 16 | Late check | Monitor trends |
| 20 | Evening check | Review logs |
| 24 | Final validation | Go/No-Go decision |

#### 2.6 Validation Gates

**Before proceeding to 20%:**

- [ ] Zero race conditions in 24 hours
- [ ] Error rate <0.1%
- [ ] Performance within targets
- [ ] No degradation vs legacy
- [ ] No critical alerts
- [ ] User experience normal

**Decision Point:**
- ✅ **PROCEED to 20%** if all gates pass
- ⚠️ **HOLD** if minor issues (investigate further)
- 🛑 **ROLLBACK** if critical issues

---

## Phase 3: Gradual Rollout

### Objective
Gradually increase traffic from 5% → 20% → 50% → 100%.

### Duration
Days 10-14 (4 days)

### 3.1 Rollout to 20% (Day 10)

```bash
# Increase to 20%
./deployment/atomic-lockout-deploy.sh rollout 20

# Monitor for 24 hours (Days 10-11)
watch -n 60 './deployment/validate-deployment.sh canary'
```

**Validation:**
- [ ] 24 hours at 20% with no issues
- [ ] Metrics stable
- [ ] No alerts

### 3.2 Rollout to 50% (Day 12)

```bash
# Increase to 50%
./deployment/atomic-lockout-deploy.sh rollout 50

# Monitor for 24 hours (Days 12-13)
```

**Validation:**
- [ ] 24 hours at 50% with no issues
- [ ] Performance consistent
- [ ] Error rate stable

### 3.3 Decision Matrix

| Traffic % | Min Duration | Pass Criteria | Fail Action |
|-----------|--------------|---------------|-------------|
| 5% | 24 hours | No race conditions, <0.1% errors | Rollback |
| 20% | 24 hours | Metrics stable, performance OK | Hold at 5% |
| 50% | 24 hours | All targets met | Hold at 20% |
| 100% | 7 days | Full validation | Rollback to 50% |

---

## Phase 4: Full Production

### Objective
Deploy atomic lockout to 100% of production traffic.

### Duration
Days 14-21 (1 week)

### Steps

#### 4.1 Final Pre-Deployment Validation

```bash
# Comprehensive validation
./deployment/validate-deployment.sh canary

# Review all metrics
./deployment/generate-metrics-report.sh

# Expected: All green, ready for 100%
```

#### 4.2 Deploy to 100%

```bash
# Full production rollout
./deployment/atomic-lockout-deploy.sh production

# Expected output:
# ✓ Running final validation...
# ✓ Applying production manifests...
# ✓ Cleaning up canary deployment...
# ✓ Full production deployment complete!
```

#### 4.3 Post-Deployment Validation

```bash
# Verify 100% traffic on atomic
kubectl get virtualservice saas-api-vs -n production -o yaml

# Expected: 100% weight to stable (now atomic)
```

#### 4.4 Week-Long Monitoring (Days 14-21)

**Daily Checks:**

```bash
# Morning check (9 AM)
./deployment/validate-deployment.sh production
./deployment/check-alerts.sh

# Afternoon check (3 PM)
./deployment/performance-report.sh

# Evening check (9 PM)
./deployment/error-summary.sh
```

**Key Metrics:**

| Metric | Target | Status |
|--------|--------|--------|
| Uptime | 99.9% | Monitor |
| Race conditions | 0 | Must be 0 |
| p95 latency | <3.6ms | Track trend |
| Error rate | <0.1% | Alert if exceeded |
| Throughput | >3,000/s | Monitor capacity |

#### 4.5 Validation Gates

**After 7 days at 100%:**

- [ ] Zero race conditions
- [ ] All performance targets met
- [ ] Error rate <0.1%
- [ ] No critical incidents
- [ ] User experience positive
- [ ] Security audit passed

**Sign-off for Cleanup Phase:**
- Engineering Manager: ________________ Date: _______
- Security Lead: ________________ Date: _______

---

## Phase 5: Cleanup

### Objective
Remove legacy implementation after 2 weeks of stable operation.

### Duration
Days 22+ (Ongoing)

### Steps

#### 5.1 Wait Period (2 weeks minimum)

**Criteria for cleanup:**
- 2+ weeks at 100% production
- Zero race conditions
- No rollbacks required
- Metrics stable
- Team confident

#### 5.2 Remove Legacy Code

```bash
cd ~/development/saas

# Create cleanup branch
git checkout -b cleanup/remove-legacy-lockout

# Remove legacy implementation
# File: development/saas/auth/account_lockout.py
# Lines to remove: 390-464 (_record_failed_attempt_legacy)

# Update tests
# Remove legacy test cases

# Commit changes
git add .
git commit -m "cleanup: remove legacy account lockout implementation

After 2 weeks of stable atomic implementation:
- Remove _record_failed_attempt_legacy method
- Remove legacy test cases
- Update documentation

Refs: SEC-012"

# Create PR
gh pr create --title "Cleanup: Remove Legacy Account Lockout" \
    --body "See commit message for details"
```

#### 5.3 Final Documentation Update

```bash
# Update architecture docs
# Remove references to "legacy implementation"
# Update deployment guides
# Archive old runbooks
```

---

## Rollback Procedures

### Emergency Rollback (<1 minute)

**If critical issue detected:**

```bash
# Immediate rollback
./deployment/atomic-lockout-deploy.sh rollback production

# This sets: ENABLE_ATOMIC_LOCKOUT=false
# System reverts to legacy implementation
# Takes effect in <1 minute
```

### Rollback Decision Criteria

**Rollback IMMEDIATELY if:**
- ❌ Any race conditions detected
- ❌ Error rate >1%
- ❌ p95 latency >10ms
- ❌ System instability
- ❌ Security incident
- ❌ Data corruption

**Rollback CONSIDERED if:**
- ⚠️ Error rate >0.5% for 10+ minutes
- ⚠️ Performance degradation >20%
- ⚠️ Multiple alerts firing
- ⚠️ User complaints

### Rollback Steps

```bash
# 1. Trigger rollback
./deployment/atomic-lockout-deploy.sh rollback production

# 2. Verify rollback
kubectl get pods -n production -l app=saas-api

POD=$(kubectl get pods -n production -l app=saas-api -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n production "$POD" -- printenv ENABLE_ATOMIC_LOCKOUT

# Expected: "false"

# 3. Monitor legacy implementation
watch -n 5 'kubectl top pods -n production'

# 4. Incident report
./deployment/create-incident-report.sh
```

### Post-Rollback Actions

1. **Create Incident Report**
   - Document what happened
   - Timeline of events
   - Root cause analysis
   - Action items

2. **Team Notification**
   - Alert engineering team
   - Update stakeholders
   - Post-mortem meeting

3. **Fix & Retry**
   - Address root cause
   - Update tests
   - Re-validate in staging
   - Plan new deployment

---

## Monitoring & Validation

### Grafana Dashboards

1. **Atomic Lockout - Overview**
   - URL: https://grafana.example.com/d/atomic-lockout
   - Panels: Latency, Throughput, Error Rate, Race Conditions

2. **Atomic Lockout - Performance**
   - URL: https://grafana.example.com/d/atomic-lockout-performance
   - Panels: p50/p95/p99, Cache Hit Rate, Redis Performance

3. **Atomic Lockout - Canary**
   - URL: https://grafana.example.com/d/atomic-lockout-canary
   - Panels: Canary vs Stable comparison

4. **Security Monitoring**
   - URL: https://grafana.example.com/d/security-monitoring
   - Panels: Lockout patterns, Attack detection

### Prometheus Alerts

**Alert Channels:**
- Slack: #incidents
- PagerDuty: On-call engineer
- Email: security-team@example.com

**Critical Alerts:**
- `AtomicLockoutRaceConditionDetected` → Page immediately
- `AtomicLockoutHighErrorRate` → Page immediately
- `RedisConnectionFailure` → Page immediately

**High Alerts:**
- `AtomicLockoutHighLatency` → Slack notification
- `AtomicLockoutLowCacheHitRate` → Slack notification

### Validation Commands

```bash
# Quick health check
./deployment/validate-deployment.sh [staging|production]

# Performance report
./deployment/performance-report.sh [staging|production]

# Error summary
./deployment/error-summary.sh [staging|production]

# Metrics snapshot
./deployment/metrics-snapshot.sh [staging|production]
```

---

## Troubleshooting

### Issue: Race Condition Detected

**Symptoms:**
- Alert: `AtomicLockoutRaceConditionDetected`
- Prometheus metric: `account_lockout_race_condition_detected_total > 0`

**Actions:**
1. **IMMEDIATE ROLLBACK**
   ```bash
   ./deployment/atomic-lockout-deploy.sh rollback production
   ```

2. **Investigate**
   - Review Lua script execution logs
   - Check Redis health
   - Analyze concurrent request patterns

3. **Root Cause**
   - This should NEVER happen with atomic implementation
   - Indicates critical bug in Lua script or Redis

### Issue: High Latency

**Symptoms:**
- p95 latency >3.6ms
- Alert: `AtomicLockoutHighLatency`

**Actions:**
1. **Check Redis Performance**
   ```bash
   kubectl exec -n production redis-0 -- redis-cli INFO stats
   kubectl exec -n production redis-0 -- redis-cli SLOWLOG GET 10
   ```

2. **Check Script Cache**
   ```bash
   # Cache hit rate
   curl -s "$PROMETHEUS_URL/api/v1/query?query=rate(account_lockout_lua_executions_total{execution_method=\"evalsha\"}[5m])"
   ```

3. **Check System Load**
   ```bash
   kubectl top pods -n production
   kubectl top nodes
   ```

### Issue: High Error Rate

**Symptoms:**
- Error rate >0.1%
- Alert: `AtomicLockoutHighErrorRate`

**Actions:**
1. **Review Logs**
   ```bash
   kubectl logs -n production -l app=saas-api --tail=100 | grep "ERROR.*atomic"
   ```

2. **Check Redis Connection**
   ```bash
   kubectl get pods -n production -l app=redis
   kubectl logs -n production -l app=redis --tail=100
   ```

3. **Review Error Types**
   ```bash
   curl -s "$PROMETHEUS_URL/api/v1/query?query=account_lockout_lua_errors_total" | jq .
   ```

### Issue: Low Cache Hit Rate

**Symptoms:**
- Cache hit rate <95%
- Alert: `AtomicLockoutLowCacheHitRate`

**Actions:**
1. **Check Redis Restarts**
   ```bash
   kubectl get events -n production --field-selector involvedObject.name=redis-0
   ```

2. **Check Memory**
   ```bash
   kubectl exec -n production redis-0 -- redis-cli INFO memory
   ```

3. **Verify Script Loading**
   ```bash
   kubectl logs -n production -l app=saas-api | grep "Lua script loaded"
   ```

---

## Contacts

### On-Call Engineers
- **Primary:** on-call-primary@example.com
- **Secondary:** on-call-secondary@example.com
- **PagerDuty:** https://example.pagerduty.com

### Team Leads
- **Engineering Manager:** eng-manager@example.com
- **Security Lead:** security-lead@example.com
- **DevOps Lead:** devops-lead@example.com

### Escalation Path
1. On-call engineer (immediate)
2. Team lead (if unresolved in 30 min)
3. Engineering manager (if unresolved in 1 hour)
4. CTO (if critical incident)

---

## Appendix

### A. Quick Reference Commands

```bash
# Deploy staging
./deployment/atomic-lockout-deploy.sh staging

# Deploy canary (5%)
./deployment/atomic-lockout-deploy.sh canary 5

# Gradual rollout
./deployment/atomic-lockout-deploy.sh rollout start  # 5%
./deployment/atomic-lockout-deploy.sh rollout 20     # 20%
./deployment/atomic-lockout-deploy.sh rollout 50     # 50%
./deployment/atomic-lockout-deploy.sh rollout 100    # 100%

# Rollback
./deployment/atomic-lockout-deploy.sh rollback production

# Validate
./deployment/validate-deployment.sh [staging|production]

# Load test
locust -f deployment/loadtest-atomic-lockout.py --host=<url> --headless
```

### B. Metrics Reference

| Metric Name | Type | Description |
|-------------|------|-------------|
| `account_lockout_triggered_total` | Counter | Total lockouts triggered |
| `account_lockout_operation_seconds` | Histogram | Operation latency |
| `account_lockout_lua_executions_total` | Counter | Lua script executions |
| `account_lockout_lua_errors_total` | Counter | Lua script errors |
| `account_lockout_race_condition_detected_total` | Counter | Race conditions (should be 0!) |

### C. File Locations

| File | Location |
|------|----------|
| Production Code | `development/saas/auth/account_lockout.py` |
| Unit Tests | `development/saas/tests/unit/test_atomic_lockout_unit.py` |
| Integration Tests | `development/saas/tests/integration/test_atomic_lockout_race_condition.py` |
| Deployment Script | `development/saas/deployment/atomic-lockout-deploy.sh` |
| Load Test Script | `development/saas/deployment/loadtest-atomic-lockout.py` |
| Validation Script | `development/saas/deployment/validate-deployment.sh` |
| Prometheus Alerts | `development/saas/deployment/prometheus-alerts.yml` |
| This Runbook | `DEPLOYMENT_RUNBOOK_ATOMIC_LOCKOUT.md` |

---

**END OF RUNBOOK**

*For questions or updates, contact: devops-team@example.com*
