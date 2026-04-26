# Phase 5: Monitoring Deployment Plan

**Date:** 2025-11-04
**Objective:** Deploy comprehensive monitoring for SEC-011 streaming validation
**Environment:** Development/Staging (Kubernetes + Local)
**Estimated Time:** 1-2 hours

---

## Executive Summary

Phase 5 will deploy monitoring infrastructure to track the SEC-011 (Request Size Bypass) security fix implemented in Phase 4. This includes:

1. **Prometheus Metrics** for request size monitoring
2. **Alerting Rules** for size limit violations
3. **Grafana Dashboard Panels** for visualization
4. **Validation Scripts** for end-to-end testing

---

## Current Infrastructure Analysis

### Existing Monitoring Stack

**Kubernetes-based:**
- **Prometheus Operator** (kube-prometheus-stack)
- **Grafana** on port 3000
- **Alertmanager** on port 9093
- **ServiceMonitors** for automatic service discovery

**Files Found:**
1. `development/monitoring/prometheus.yml` - Prometheus configuration
2. `development/monitoring/prometheus-alerts.yaml` - Alert rules
3. `development/monitoring/grafana-circuit-breaker-dashboard.json` - Dashboard
4. `development/monitoring/MONITORING_SETUP.md` - Setup documentation
5. `development/monitoring/QUICK_START.md` - Quick start guide

**Current Metrics Collected:**
- `http_requests_total` - HTTP request counter
- `http_request_duration_seconds` - Request latency histogram
- `circuit_breaker_state` - Circuit breaker status
- `circuit_breaker_failures` - Failure counts

### Gap Analysis

**Missing for SEC-011:**
- ❌ `request_size_limit_exceeded_total` - Size rejection counter
- ❌ `request_body_bytes` - Body size distribution
- ❌ Alert rules for high rejection rates
- ❌ Dashboard panels for size monitoring
- ❌ Validation tests for metrics

---

## Implementation Strategy

### Phase 5A: Add Prometheus Metrics to Application (30 minutes)

**File:** `development/saas/auth/request_limits.py`

**Metrics to Add:**
```python
from prometheus_client import Counter, Histogram

# Request size rejections
request_size_exceeded = Counter(
    'request_size_limit_exceeded_total',
    'Requests rejected due to size limit',
    ['method', 'path', 'limit_type', 'rejection_type']
)

# Request body size distribution
request_body_bytes = Histogram(
    'request_body_bytes',
    'Distribution of request body sizes',
    ['method', 'limit_type'],
    buckets=[
        1024,           # 1KB
        10*1024,        # 10KB
        100*1024,       # 100KB
        1*1024*1024,    # 1MB
        10*1024*1024,   # 10MB
        100*1024*1024,  # 100MB
        1000*1024*1024  # 1GB
    ]
)
```

**Integration Points:**
1. **Fast-path rejection** (Content-Length too large):
   - Increment `request_size_exceeded` with `rejection_type="content_length"`

2. **Streaming rejection** (body too large):
   - Increment `request_size_exceeded` with `rejection_type="streaming"`

3. **Successful request** (within limits):
   - Observe `request_body_bytes` with actual size

### Phase 5B: Create Alert Rules (20 minutes)

**File:** `development/monitoring/prometheus-alerts-sec011.yaml`

**Alert Rules:**
1. **HighRequestSizeRejection** - Many requests being rejected
2. **UnusualRequestSizeDistribution** - Anomalous upload patterns
3. **RequestSizeAttack** - Possible DoS attack detected

```yaml
- alert: HighRequestSizeRejection
  expr: rate(request_size_limit_exceeded_total[5m]) > 10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High rate of request size rejections"
    description: "{{ $value }} requests/sec being rejected due to size limits"

- alert: UnusualRequestSizeDistribution
  expr: |
    request_body_bytes{quantile="0.99"} > 50*1024*1024
    and
    rate(request_size_limit_exceeded_total[5m]) > 1
  for: 10m
  labels:
    severity: info
  annotations:
    summary: "Unusual request size distribution detected"
    description: "p99 request size is {{ $value }}MB with ongoing rejections"

- alert: RequestSizeAttack
  expr: rate(request_size_limit_exceeded_total[1m]) > 50
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "Possible request size DoS attack"
    description: "{{ $value }} rejections/sec detected - possible attack"
```

### Phase 5C: Extend Grafana Dashboard (20 minutes)

**File:** `development/monitoring/grafana-sec011-panels.json`

**New Dashboard Panels:**

1. **Request Size Rejections (Counter)**
   - Query: `rate(request_size_limit_exceeded_total[5m])`
   - Type: Graph
   - Shows rejections/second over time

2. **Rejection Type Breakdown (Pie Chart)**
   - Query: `sum by (rejection_type) (request_size_limit_exceeded_total)`
   - Type: Pie chart
   - Shows fast-path vs streaming rejections

3. **Request Body Size Distribution (Heatmap)**
   - Query: `rate(request_body_bytes_bucket[5m])`
   - Type: Heatmap
   - Shows body size distribution over time

4. **Current Request Size Stats (Stat Panel)**
   - Queries:
     - p50: `histogram_quantile(0.50, request_body_bytes)`
     - p95: `histogram_quantile(0.95, request_body_bytes)`
     - p99: `histogram_quantile(0.99, request_body_bytes)`
   - Type: Stat (3 panels)

5. **Rejection Rate vs Success Rate (Graph)**
   - Queries:
     - Success: `rate(http_requests_total{status=~"2.."}[5m])`
     - Rejected: `rate(request_size_limit_exceeded_total[5m])`
   - Type: Graph (stacked)

6. **Largest Rejected Requests (Table)**
   - Query: `topk(10, request_size_limit_exceeded_total)`
   - Type: Table
   - Shows paths with most rejections

### Phase 5D: Create Validation Scripts (10 minutes)

**File:** `development/monitoring/validate-sec011-metrics.sh`

**Validation Tests:**
1. Check metrics endpoint is accessible
2. Verify SEC-011 metrics are registered
3. Send test requests to trigger metrics
4. Query Prometheus to verify data collection
5. Check alert rules are loaded

---

## Deployment Steps

### Step 1: Add Metrics to Application

```bash
# Edit request_limits.py
cd /c/Users/Corbin/development/saas/auth

# Add imports at top
# Add metric definitions after imports
# Instrument code at rejection points
# Instrument code at success points
```

### Step 2: Deploy Alert Rules

```bash
cd /c/Users/Corbin/development/monitoring

# For Kubernetes deployment:
kubectl apply -f prometheus-alerts-sec011.yaml

# For local development:
# Rules will be loaded via prometheus.yml rule_files
```

### Step 3: Import Grafana Panels

```bash
# Port-forward Grafana
kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80

# Import via UI:
# 1. Navigate to http://localhost:3000
# 2. Login (admin/admin)
# 3. Open existing circuit breaker dashboard
# 4. Click "Add panel"
# 5. Add SEC-011 panels
```

### Step 4: Validate Metrics Collection

```bash
cd /c/Users/Corbin/development/monitoring

# Run validation script
bash validate-sec011-metrics.sh

# Expected output:
# ✓ Metrics endpoint accessible
# ✓ SEC-011 metrics registered
# ✓ Test requests successful
# ✓ Prometheus collecting data
# ✓ Alert rules loaded
```

---

## Success Criteria

### Metrics Collection

| Metric | Status | Data Points | Validation |
|--------|--------|-------------|------------|
| `request_size_limit_exceeded_total` | ⏳ | 0+ | Send oversized request |
| `request_body_bytes` | ⏳ | 100+ | Send various request sizes |

### Alert Rules

| Alert | Status | Threshold | Test Trigger |
|-------|--------|-----------|--------------|
| HighRequestSizeRejection | ⏳ | 10/sec | Send 15 oversized/sec for 6 min |
| UnusualRequestSizeDistribution | ⏳ | p99 > 50MB | Send large requests + rejections |
| RequestSizeAttack | ⏳ | 50/sec | Send 60 oversized/sec for 3 min |

### Dashboard Panels

| Panel | Status | Data Source | Query Working |
|-------|--------|-------------|---------------|
| Request Size Rejections | ⏳ | Prometheus | TBD |
| Rejection Type Breakdown | ⏳ | Prometheus | TBD |
| Body Size Distribution | ⏳ | Prometheus | TBD |
| Request Size Stats | ⏳ | Prometheus | TBD |
| Rejection vs Success Rate | ⏳ | Prometheus | TBD |
| Largest Rejected Requests | ⏳ | Prometheus | TBD |

---

## Testing Strategy

### Unit Tests (Application Level)

**Test:** Verify metrics are incremented correctly

```python
def test_request_size_exceeded_metric():
    """Test that rejections increment metric"""
    from auth.request_limits import request_size_exceeded

    initial = request_size_exceeded._value.get()

    # Send oversized request
    response = client.post("/api/test", content=b"A" * 10MB)
    assert response.status_code == 413

    final = request_size_exceeded._value.get()
    assert final > initial
```

### Integration Tests (End-to-End)

**Test 1: Fast-path rejection metric**
```bash
# Send request with large Content-Length
curl -X POST http://localhost:8000/api/test \
  -H "Content-Length: 100000000" \
  --data-binary "@/dev/zero"

# Check metric increased
curl http://localhost:8000/metrics | grep request_size_limit_exceeded
```

**Test 2: Streaming rejection metric**
```bash
# Send streaming request exceeding limit
curl -X POST http://localhost:8000/api/test \
  --data-binary "@large_file.bin"

# Check metric increased
curl http://localhost:8000/metrics | grep request_size_limit_exceeded
```

**Test 3: Body size histogram**
```bash
# Send requests of various sizes
for size in 1KB 10KB 100KB 1MB; do
  head -c $size /dev/urandom | curl -X POST http://localhost:8000/api/test --data-binary @-
done

# Check histogram buckets
curl http://localhost:8000/metrics | grep request_body_bytes_bucket
```

### Prometheus Query Tests

**Test queries in Prometheus UI:**

1. **Total rejections:**
   ```promql
   request_size_limit_exceeded_total
   ```

2. **Rejection rate:**
   ```promql
   rate(request_size_limit_exceeded_total[5m])
   ```

3. **Body size percentiles:**
   ```promql
   histogram_quantile(0.95, request_body_bytes_bucket)
   ```

4. **Rejections by type:**
   ```promql
   sum by (rejection_type) (request_size_limit_exceeded_total)
   ```

---

## Rollback Plan

### If Metrics Break Application

1. **Immediate action:**
   ```python
   # Comment out metric instrumentation
   # request_size_exceeded.labels(...).inc()
   ```

2. **Restart application:**
   ```bash
   kubectl rollout restart deployment/saas-api -n catalytic-staging
   ```

3. **Verify no metrics:**
   ```bash
   curl http://localhost:8000/metrics | grep -v request_size
   ```

### If Alert Rules Spam

1. **Adjust thresholds:**
   ```yaml
   # Increase threshold or duration
   expr: rate(request_size_limit_exceeded_total[5m]) > 100  # was 10
   for: 10m  # was 5m
   ```

2. **Re-apply rules:**
   ```bash
   kubectl apply -f prometheus-alerts-sec011.yaml
   ```

### If Dashboard Breaks

1. **Revert to previous version:**
   ```bash
   # Export current dashboard (backup)
   # Restore previous version from git
   ```

2. **Reimport:**
   ```bash
   # Via Grafana UI
   ```

---

## Timeline

| Task | Duration | Dependencies | Assignee |
|------|----------|--------------|----------|
| Add metrics to app | 30 min | Phase 4 complete | This session |
| Create alert rules | 20 min | Metrics added | This session |
| Extend dashboard | 20 min | Metrics added | This session |
| Create validation scripts | 10 min | All above | This session |
| **Total** | **80 min** | | |

---

## Files to Create/Modify

### New Files (5 files)

1. `development/monitoring/prometheus-alerts-sec011.yaml` - Alert rules
2. `development/monitoring/grafana-sec011-panels.json` - Dashboard panels
3. `development/monitoring/validate-sec011-metrics.sh` - Validation script
4. `development/monitoring/test-sec011-metrics.py` - Python test script
5. `PHASE_5_MONITORING_DEPLOYMENT_COMPLETE.md` - Completion report

### Modified Files (1 file)

1. `development/saas/auth/request_limits.py` - Add Prometheus metrics

---

## Next Steps After Phase 5

**Phase 6: Final Validation** (1 hour)
1. Performance benchmarking
2. Load testing
3. Security scan
4. Production readiness sign-off

**Production Deployment** (After Phase 6)
1. Rotate Redis passwords
2. Update CI/CD secrets
3. Deploy to production
4. Monitor for 48 hours

---

**Created:** 2025-11-04
**Status:** READY TO IMPLEMENT
**Estimated Completion:** This session (80 minutes)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
