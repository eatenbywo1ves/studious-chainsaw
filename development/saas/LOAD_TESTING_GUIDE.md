# SaaS Platform Load Testing Guide

**Purpose:** Validate production readiness under concurrent load
**Status:** ✅ Ready to Execute
**Duration:** 15-20 minutes total
**Success Criteria:** P95 < 200ms, Success Rate > 99%

---

## 🎯 **Quick Start**

### **Step 1: Start the SaaS API Server**

```bash
# Terminal 1: Start API server
cd C:/Users/Corbin/development/saas
python -m uvicorn api.saas_server:app --host 0.0.0.0 --port 8000 --workers 4

# Wait for: "Application startup complete"
# Verify: curl http://localhost:8000/health
```

### **Step 2: Run Load Tests**

```bash
# Terminal 2: Run load tests (choose one)

# Option A: PowerShell (Windows)
cd C:/Users/Corbin/development/saas
powershell -ExecutionPolicy Bypass -File .\run_load_tests.ps1 -TestType both

# Option B: Bash (Git Bash / WSL / Linux)
cd C:/Users/Corbin/development/saas
bash run_load_tests.sh both

# Option C: Manual with Locust
cd C:/Users/Corbin/development/saas/tests/performance
locust -f locustfile.py --users 1000 --spawn-rate 100 --run-time 5m --host http://localhost:8000 --headless
```

---

## 📊 **Test Scenarios**

### **Baseline Test (100 users, 2 min)**
- Purpose: Establish performance baseline
- Users: 100 concurrent
- Duration: 2 minutes
- Expected: P95 < 50ms, 100% success

### **1K Users Test (5 min)**
- Purpose: Typical production load
- Users: 1,000 concurrent
- Duration: 5 minutes
- Expected: P95 < 200ms, >99% success

### **10K Users Test (5 min)**
- Purpose: Traffic spike / peak load
- Users: 10,000 concurrent
- Duration: 5 minutes
- Expected: P95 < 200ms, >99% success

---

## ✅ **Success Criteria**

### **Performance Targets**

| Metric | Target | Notes |
|--------|--------|-------|
| **P95 Response Time** | < 200ms | 95th percentile latency |
| **P99 Response Time** | < 500ms | 99th percentile latency |
| **Success Rate** | > 99% | HTTP 200/201 responses |
| **Error Rate** | < 1% | Failed requests |
| **Connection Pool** | No exhaustion | Check logs for pool errors |

### **What to Check**

✅ **In HTML Report:**
- Response time percentiles (P50, P95, P99)
- Requests per second (RPS)
- Failure percentage
- Response time chart trends

✅ **In Server Logs:**
```bash
# Check for errors
tail -f logs/saas_server.log | grep ERROR

# Check connection pool (should stay healthy)
grep "connection pool" logs/saas_server.log

# Check for authentication failures
grep "401" logs/saas_server.log
```

✅ **In Database:**
```bash
# PostgreSQL connection count (should not exceed pool_size + max_overflow)
psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# Pool statistics
psql $DATABASE_URL -c "SELECT * FROM pg_stat_database WHERE datname='catalytic_saas';"
```

---

## 🔧 **Troubleshooting**

### **Server Won't Start**

```bash
# Check if port is already in use
netstat -ano | findstr ":8000"

# Kill existing process (Windows)
taskkill /PID <PID> /F

# Kill existing process (Linux/Mac)
kill -9 $(lsof -t -i:8000)
```

### **Low Success Rate (<99%)**

**Common Causes:**
1. **Authentication failures** - Check JWT token generation
2. **Connection pool exhaustion** - Increase pool_size in database/connection.py
3. **Database deadlocks** - Check PostgreSQL logs
4. **Redis unavailable** - Verify Redis is running

**Solutions:**
```bash
# Increase connection pool (database/connection.py)
pool_size=30  # from 20
max_overflow=60  # from 40

# Check Redis
redis-cli -a $REDIS_PASSWORD PING

# Check PostgreSQL
psql $DATABASE_URL -c "SELECT 1;"
```

### **High Response Times (P95 > 200ms)**

**Common Causes:**
1. **Database queries not optimized** - Add indexes
2. **N+1 query problem** - Use eager loading
3. **No caching** - Implement Redis caching
4. **CPU/memory constraints** - Scale vertically

**Quick Fixes:**
```python
# Add database indexes
CREATE INDEX idx_tenants_email ON tenants(email);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);

# Enable SQLAlchemy query caching
engine = create_engine(DATABASE_URL,
    pool_size=30,
    max_overflow=60,
    pool_pre_ping=True,
    query_cache_size=1000  # Add this
)
```

---

## 📈 **Interpreting Results**

### **Good Results Example**

```
Total Requests: 50,000
Success Rate: 99.8%
RPS: 166.67
P50: 45ms
P95: 120ms
P99: 380ms
Failures: 100 (0.2%)

✅ PASS - All criteria met!
```

### **Concerning Results Example**

```
Total Requests: 50,000
Success Rate: 94.2%
RPS: 120
P50: 250ms
P95: 1200ms
P99: 3500ms
Failures: 2900 (5.8%)

❌ FAIL - Needs optimization before production
```

---

## 🚀 **After Load Testing**

### **If Tests Pass (✅ Success Rate > 99%, P95 < 200ms)**

**Next Steps:**
1. ✅ Mark load testing complete
2. ⏭️ Proceed to staging deployment
3. ⏭️ Run staging smoke tests
4. ⏭️ Schedule production deployment

### **If Tests Fail (❌ Success Rate < 99% or P95 > 200ms)**

**Actions Required:**
1. 🔍 Analyze failure patterns in HTML report
2. 🔍 Review server logs for errors
3. 🛠️ Apply fixes (connection pool, indexes, caching)
4. 🔄 Re-run load tests
5. 📝 Document improvements made

---

## 📝 **Load Test Report Template**

After each test run, document results:

```markdown
## Load Test Results - [Date]

### Configuration
- Users: [1000 / 10000]
- Duration: [5 minutes]
- Spawn Rate: [100/sec]
- Host: [http://localhost:8000]

### Results
- Total Requests: [X]
- Success Rate: [X%]
- Failures: [X]
- RPS: [X]
- P50: [X ms]
- P95: [X ms]
- P99: [X ms]

### Status
- [ ] P95 < 200ms: [PASS / FAIL]
- [ ] Success Rate > 99%: [PASS / FAIL]
- [ ] No connection errors: [PASS / FAIL]
- [ ] No auth failures: [PASS / FAIL]

### Overall
[✅ PASS - Ready for staging] / [❌ FAIL - Needs optimization]

### Notes
[Any observations, errors encountered, or improvements needed]
```

---

## 🎯 **Production Readiness Validation**

Use this checklist after successful load tests:

- [ ] **Baseline test (100 users):** PASS
- [ ] **1K users test:** PASS (P95 < 200ms, >99% success)
- [ ] **10K users test:** PASS (P95 < 200ms, >99% success)
- [ ] **No connection pool errors** in logs
- [ ] **No authentication failures** in metrics
- [ ] **Database connection count** stays within limits
- [ ] **Redis memory usage** remains healthy
- [ ] **Server logs** show no critical errors
- [ ] **Test reports** generated and saved

**If all checked:** ✅ **APPROVED FOR STAGING DEPLOYMENT**

---

## 📚 **Additional Resources**

- **Locust Documentation:** https://docs.locust.io/
- **Load Test Script:** [tests/performance/locustfile.py](tests/performance/locustfile.py)
- **Runner Scripts:**
  - PowerShell: [run_load_tests.ps1](run_load_tests.ps1)
  - Bash: [run_load_tests.sh](run_load_tests.sh)
- **Technical Debt Fixes:** [SAAS_PRODUCTION_READINESS_STATUS.md](SAAS_PRODUCTION_READINESS_STATUS.md)

---

**Created:** 2025-10-21
**Author:** Claude Code
**Status:** Ready for Execution
