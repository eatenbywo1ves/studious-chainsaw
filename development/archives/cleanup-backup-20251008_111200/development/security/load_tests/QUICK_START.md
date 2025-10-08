# Redis Pool Optimization - Quick Start Guide

**Last Updated:** 2025-10-05
**Status:** ✅ Ready for Load Testing

---

## What Was Optimized

✅ **Connection Pool**: 100 → 160 connections (60% increase)
✅ **Per-Worker Allocation**: 25 → 40 connections/worker (60% increase)
✅ **Health Checks**: None → 30-second intervals
✅ **Retry Logic**: Basic timeout → Exponential backoff (3 attempts)
✅ **Monitoring**: None → Full pool metrics tracking

**Expected Impact:**
- Failure rate: **43.85% → <1%** (98% reduction)
- p95 latency: **23,000ms → <500ms** (98% reduction)

---

## Quick Start (3 Steps)

### Step 1: Start the Optimized Server

```bash
cd C:\Users\Corbin\development\security\load_tests
start-optimized-server.bat
```

**Expected Output:**
```
[OK] Redis is running
[OK] Port 8000 is available
Environment:     production
Target Users:    10,000 concurrent
Workers:         4
Pool Size:       160 connections (40 per worker)
```

### Step 2: Verify Pool Status

```bash
# In a new terminal
check-pool-status.bat
```

**Expected Output:**
```json
{
  "healthy": true,
  "pool": {
    "status": "healthy",
    "max_connections": 160,
    "utilization_percent": 0.0
  },
  "recommendations": [
    "Pool operating optimally."
  ]
}
```

### Step 3: Run Load Tests

```bash
# In a new terminal
run-load-tests.bat
```

This will run all three tests automatically:
1. **Baseline** (1,000 users) - 3 minutes
2. **Stress** (5,000 users) - 5 minutes
3. **Ultimate** (10,000 users) - 5 minutes

**Total Duration:** ~15 minutes

---

## Manual Testing (Optional)

### Test Individual Scenarios

**Baseline Test (1,000 users):**
```bash
locust -f locustfile.py AuthenticationLoadTest ^
    --host http://localhost:8000 ^
    --users 1000 ^
    --spawn-rate 50 ^
    --run-time 3m ^
    --headless ^
    --csv=results/baseline_1000
```

**Stress Test (5,000 users):**
```bash
locust -f locustfile.py AuthenticationLoadTest ^
    --host http://localhost:8000 ^
    --users 5000 ^
    --spawn-rate 100 ^
    --run-time 5m ^
    --headless ^
    --csv=results/stress_5000
```

**Ultimate Test (10,000 users):**
```bash
locust -f locustfile.py AuthenticationLoadTest ^
    --host http://localhost:8000 ^
    --users 10000 ^
    --spawn-rate 100 ^
    --run-time 5m ^
    --headless ^
    --csv=results/ultimate_10000
```

---

## Monitoring During Tests

### Check Pool Metrics

```bash
# Pool health + recommendations
curl http://localhost:8000/health/redis

# Redis + pool statistics
curl http://localhost:8000/redis/stats

# Continuous monitoring (every 5 seconds)
while ($true) { curl http://localhost:8000/health/redis; Start-Sleep 5 }
```

### Check Redis Server Stats

```bash
"C:\Program Files\Memurai\memurai-cli.exe" -a "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=" INFO stats
```

**Key Metrics to Watch:**
- `total_commands_processed`: Total Redis operations
- `instantaneous_ops_per_sec`: Current operations/second
- `rejected_connections`: Should be **0**
- `connected_clients`: Current client connections

---

## Expected Results

### Baseline (1,000 users)

| Metric | Target | Previous |
|--------|--------|----------|
| **p50 Response Time** | <15ms | 14ms ✅ |
| **p95 Response Time** | <200ms | 180ms ✅ |
| **Failure Rate** | <0.5% | 0.11% ✅ |
| **Pool Utilization** | <20% | N/A |

### Stress (5,000 users)

| Metric | Target | Previous (Single-Thread) |
|--------|--------|--------------------------|
| **p50 Response Time** | <50ms | 1,300ms |
| **p95 Response Time** | <300ms | 33,000ms |
| **Failure Rate** | <0.5% | 3.76% |
| **Pool Utilization** | <40% | N/A |

### Ultimate (10,000 users)

| Metric | Target | Previous (Multi-Worker, No Redis) |
|--------|--------|-----------------------------------|
| **p50 Response Time** | <100ms | N/A |
| **p95 Response Time** | <500ms | 23,000ms |
| **Failure Rate** | <1% | 43.85% |
| **Pool Utilization** | 40-60% | N/A |

---

## Troubleshooting

### Server Won't Start

**Error:** `Redis not responding`
```bash
# Start Memurai
net start Memurai

# Verify
"C:\Program Files\Memurai\memurai-cli.exe" -a "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo=" PING
# Should return: PONG
```

**Error:** `Port 8000 is already in use`
```bash
# Find process using port 8000
netstat -ano | findstr :8000

# Kill the process (replace PID)
taskkill /PID <PID> /F
```

### High Pool Utilization (>80%)

**Symptoms:** Pool utilization >80% in `/health/redis`

**Solution:**
```python
# Edit redis_connection_pool_optimized.py
POOL_CONFIG[DeploymentEnvironment.PRODUCTION]["max_connections"] = 200
```

### Load Test Errors

**Error:** `Locust not installed`
```bash
pip install locust
```

**Error:** `locustfile.py not found`
```bash
# Make sure you're in the correct directory
cd C:\Users\Corbin\development\security\load_tests
```

---

## Files Created

| File | Purpose |
|------|---------|
| `mock_auth_server_redis_optimized.py` | Optimized server with pool monitoring |
| `start-optimized-server.bat` | **One-click server startup** |
| `run-load-tests.bat` | **Automated test suite** |
| `check-pool-status.bat` | **Pool metrics checker** |
| `QUICK_START.md` | This guide |

---

## Results Location

All test results are saved to:
```
C:\Users\Corbin\development\security\load_tests\results\
```

**Files Generated:**
- `optimized_baseline_1000users_stats.csv` - CSV statistics
- `optimized_baseline_1000users.html` - Interactive HTML report
- `optimized_stress_5000users_stats.csv`
- `optimized_stress_5000users.html`
- `optimized_ultimate_10000users_stats.csv`
- `optimized_ultimate_10000users.html`

---

## Next Steps After Testing

1. **Review HTML Reports**
   - Open `results/*.html` in browser
   - Check response time charts
   - Analyze failure distribution

2. **Compare to Baseline**
   - Load Week 3 Day 1 results
   - Calculate improvement percentages
   - Document in REDIS_POOL_OPTIMIZATION_GUIDE.md

3. **Generate Performance Report**
   - Create comparison charts
   - Update framework rating
   - Document production readiness

4. **Production Deployment**
   - Update `jwt_auth.py` to use `OptimizedRedisPool`
   - Deploy to staging first
   - Validate with real traffic
   - Deploy to production

---

## Support

**Documentation:**
- Full guide: `C:\Users\Corbin\development\REDIS_POOL_OPTIMIZATION_GUIDE.md`
- Integration examples: `security\application\redis_pool_integration_example.py`

**Monitoring:**
- Pool health: `http://localhost:8000/health/redis`
- Redis stats: `http://localhost:8000/redis/stats`

**Redis CLI:**
```bash
"C:\Program Files\Memurai\memurai-cli.exe" -a "RLr5E73KjlPcAghcLXjBEdWJzqFVeV3EQ1GyQzqoOxo="
```

---

**Ready to test!** Run `start-optimized-server.bat` to begin. 🚀
