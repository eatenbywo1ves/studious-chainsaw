# Load Testing Suite for Catalytic Computing Security Framework

This directory contains comprehensive load testing scenarios using Locust to validate the security framework can handle production-scale traffic (10,000+ concurrent users).

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the API Server

```bash
# From development/saas/api directory
python saas_server.py

# Or with specific configuration
ENVIRONMENT=staging python saas_server.py
```

### 3. Run Load Tests

**Option A: Web UI (Recommended for initial testing)**

```bash
locust -f locustfile.py --host http://localhost:8000
```

Then open http://localhost:8089 in your browser.

**Option B: Headless (Recommended for automated testing)**

```bash
# Basic load test: 1,000 users, 5-minute duration
locust -f locustfile.py --host http://localhost:8000 \
       --users 1000 --spawn-rate 50 --run-time 5m --headless

# Full stress test: 10,000 users, 15-minute duration
locust -f locustfile.py --host http://localhost:8000 \
       --users 10000 --spawn-rate 100 --run-time 15m --headless
```

---

## Test Scenarios

### Scenario 1: Authentication Load Test
**Tag:** `authentication`, `login`
**Target:** 10,000 concurrent users
**Focus:** Login/logout workflow performance

```bash
locust -f locustfile.py --host http://localhost:8000 \
       --tags authentication \
       --users 10000 --spawn-rate 100 --run-time 15m --headless
```

**Metrics:**
- Login success rate (target: > 99%)
- p95 response time (target: < 500ms)
- Rate limit enforcement effectiveness

---

### Scenario 2: Token Verification Load Test
**Tag:** `verification`, `performance`
**Target:** 10,000 concurrent users making 200,000+ verifications
**Focus:** Token verification latency

```bash
locust -f locustfile.py --host http://localhost:8000 \
       --tags verification \
       --users 10000 --spawn-rate 100 --run-time 15m --headless
```

**Metrics:**
- Verification throughput (target: > 1,000 RPS)
- p95 response time (target: < 200ms)
- Token signature verification performance

---

### Scenario 3: Rate Limiting Stress Test
**Tag:** `rate-limiting`, `ddos`, `stress`
**Target:** 10,000 concurrent attackers (DDoS simulation)
**Focus:** Rate limiting effectiveness under attack

```bash
locust -f locustfile.py --host http://localhost:8000 \
       --tags rate-limiting \
       --users 10000 --spawn-rate 200 --run-time 10m --headless
```

**Metrics:**
- Rate limit blocks per second
- Automatic IP blocking effectiveness
- System stability during attack
- False positive rate (target: 0%)

---

### Scenario 4: Token Revocation Load Test
**Tag:** `revocation`, `blacklist`
**Target:** 10,000 concurrent revocations
**Focus:** Distributed blacklist synchronization

```bash
locust -f locustfile.py --host http://localhost:8000 \
       --tags revocation \
       --users 10000 --spawn-rate 100 --run-time 10m --headless
```

**Metrics:**
- Revocation success rate (target: 100%)
- Blacklist synchronization time (target: < 100ms)
- Redis memory usage
- Cross-worker consistency

---

### Scenario 5: Mixed Workload Test (Realistic Production)
**Tag:** `mixed`, `production`, `realistic`
**Target:** 10,000 concurrent users, 30-minute sustained load
**Focus:** Realistic production traffic simulation

**Traffic Mix:**
- 10% login attempts
- 70% API requests (with valid tokens)
- 15% token refresh
- 5% logout

```bash
locust -f locustfile.py --host http://localhost:8000 \
       --tags mixed \
       --users 10000 --spawn-rate 100 --run-time 30m --headless
```

**Metrics:**
- Overall system throughput
- p95 response time across all endpoints
- System stability over 30 minutes
- Memory leak detection

---

## Load Testing Best Practices

### Ramp-Up Strategy

Always use gradual ramp-up to avoid overwhelming the system:

```bash
# Good: Gradual ramp-up (100 users/second)
locust -f locustfile.py --users 10000 --spawn-rate 100

# Bad: Instant ramp-up (all users at once)
locust -f locustfile.py --users 10000 --spawn-rate 10000  # DON'T DO THIS
```

**Recommended Ramp-Up Rates:**
- **Baseline testing (100-1,000 users):** 20-50 users/second
- **Stress testing (5,000-10,000 users):** 50-100 users/second
- **Max capacity testing (10,000+ users):** 100-200 users/second

---

### Monitoring During Load Tests

**Required Monitoring:**
1. **Locust Web UI** (http://localhost:8089) - Request metrics
2. **System Resources** - CPU, memory, network
3. **Redis Metrics** - Connection count, memory usage
4. **Database Metrics** - Connection pool, query performance

**Commands to run in separate terminals:**

```bash
# Terminal 1: Monitor system resources
watch -n 2 'ps aux | grep python | grep -v grep'

# Terminal 2: Monitor Redis
watch -n 2 'redis-cli INFO stats | grep -E "total_commands|connected_clients"'

# Terminal 3: Monitor API server logs
tail -f /path/to/api/logs/server.log
```

---

## Interpreting Results

### Success Criteria

| Metric | Target | Critical? |
|--------|--------|-----------|
| **10,000 concurrent users** | Handled successfully | ✅ Critical |
| **p50 response time** | < 100ms | ⚠️ Important |
| **p95 response time** | < 500ms | ✅ Critical |
| **p99 response time** | < 1,000ms | ⚠️ Important |
| **Failure rate** | < 1% | ✅ Critical |
| **Memory stability** | No leaks (stable over 30 min) | ✅ Critical |

### Reading Locust Output

**Example Output:**
```
Type     Name                                  # reqs      # fails  Avg  Min  Max    Med   |   req/s failures/s
--------|--------------------------------------|---------|----------|----- ---- ------|-------|--------|----------
POST     /auth/login                           50234         45     82   34   1203    75   |   167.4      0.15
GET      /api/protected                       151203         12     45   12    876    41   |   504.0      0.04
POST     /auth/logout                          10045          3     67   23    543    62   |    33.5      0.01
--------|--------------------------------------|---------|----------|----- ---- ------|-------|--------|----------
         Aggregated                           211482         60     58   12   1203    49   |   704.9      0.20
```

**Key Metrics:**
- **# reqs:** Total requests sent
- **# fails:** Failed requests (target: < 1% of total)
- **Avg:** Average response time (ms)
- **Med:** Median (p50) response time
- **req/s:** Throughput (requests per second)
- **failures/s:** Failure rate (target: < 1/sec)

### Percentile Interpretation

Locust reports percentiles in the web UI. Here's how to interpret them:

- **p50 (Median):** 50% of users experience this or better
- **p95:** 95% of users experience this or better (5% experience worse)
- **p99:** 99% of users experience this or better (1% experience worse)
- **p100 (Max):** Worst case experienced by any user

**Target Percentiles:**
- p50 < 100ms (most users have great experience)
- p95 < 500ms (95% of users have good experience)
- p99 < 1,000ms (even worst case is acceptable)

---

## Troubleshooting

### Problem: High failure rate (> 5%)

**Symptoms:**
- Locust shows high # fails
- Many 500 Internal Server Error responses

**Diagnosis:**
1. Check API server logs for errors
2. Monitor CPU usage (may be saturated)
3. Check database connection pool

**Solutions:**
- Reduce spawn rate (slower ramp-up)
- Increase uvicorn workers
- Increase database connection pool size
- Optimize slow queries

---

### Problem: Response times increase linearly with load

**Symptoms:**
- p95 starts at 100ms, increases to 2,000ms as users increase
- CPU usage > 90%

**Diagnosis:**
- CPU saturation (bottleneck)

**Solutions:**
- Increase uvicorn workers: `--workers 8`
- Optimize cryptographic operations (cache public keys)
- Consider horizontal scaling (multiple servers)

---

### Problem: Sudden spike in failures after initial success

**Symptoms:**
- First 5 minutes: 0% failures
- After 5 minutes: 50%+ failures
- Error: "Too many connections"

**Diagnosis:**
- Connection pool exhaustion (database or Redis)

**Solutions:**
```python
# Increase database pool
engine = create_engine(
    DATABASE_URL,
    pool_size=100,        # Increase from 50
    max_overflow=200      # Increase from 100
)

# Increase Redis connections
redis_client = RedisConnectionManager(
    max_connections=200   # Increase from 100
)
```

---

### Problem: Memory usage grows continuously

**Symptoms:**
- Memory starts at 500MB, grows to 5GB over 30 minutes
- Eventually crashes with OOM (Out of Memory)

**Diagnosis:**
- Memory leak in application code

**Solutions:**
1. Profile with `memory_profiler`:
```bash
python -m memory_profiler saas_server.py
```

2. Check for unclosed connections
3. Review in-memory caches (implement LRU eviction)
4. Monitor with:
```bash
watch -n 5 'ps aux | grep python | awk "{print \$6/1024 \" MB\"}"'
```

---

## Advanced Load Testing

### Distributed Load Testing

For testing > 50,000 concurrent users, use distributed mode:

**Master Node:**
```bash
locust -f locustfile.py --master --host http://localhost:8000
```

**Worker Nodes (run on multiple machines):**
```bash
locust -f locustfile.py --worker --master-host=<master-ip>
```

Locust will aggregate results from all workers.

---

### Custom Metrics Export

Locust automatically exports metrics to CSV files:
- `load_test_stats.csv` - Request statistics
- `load_test_stats_history.csv` - Time-series data
- `load_test_failures.csv` - Failure details

**Custom Metrics:**

The `load_test_metrics` object tracks additional metrics:
- Login success rate
- Token verification success rate
- Rate limit blocks
- Token revocations

These are exported to JSON at test completion:
```bash
load_test_metrics_20251003_143022.json
```

---

## Production Deployment Checklist

Before deploying to production based on load test results:

- [ ] **10,000+ concurrent users handled successfully**
- [ ] **p95 response time < 500ms**
- [ ] **Failure rate < 1%**
- [ ] **No memory leaks detected (30-minute stability test)**
- [ ] **Redis failover tested (chaos + load scenario)**
- [ ] **Database connection pool stable**
- [ ] **Rate limiting effective (DDoS scenario passed)**
- [ ] **Monitoring stack deployed (Prometheus + Grafana)**
- [ ] **Alerting configured (performance degradation alerts)**
- [ ] **Capacity planning documented (max users, scaling strategy)**

---

## References

- **Locust Documentation:** https://docs.locust.io/
- **Load Testing Specification:** `../WEEK3_LOAD_TESTING_SPECIFICATION.md`
- **Framework Capability Assessment:** `../../FRAMEWORK_CAPABILITY_ASSESSMENT.md`
- **Week 2 Integration Testing:** `../WEEK2_COMPLETE_SUMMARY.md`

---

## Support

For issues with load testing:
1. Check troubleshooting section above
2. Review Locust logs (stderr output)
3. Review API server logs
4. Monitor system resources during test
5. Reduce load and re-test

**Questions or improvements?** Document findings in Week 3 completion reports.

---

**Last Updated:** 2025-10-03
**Status:** ✅ Load Testing Suite Complete
**Next:** Execute load tests and analyze results
