# Chaos Testing Specification - Security Infrastructure

**Project:** Catalytic Computing Security Infrastructure
**Phase:** Week 2 Day 2 - Chaos Engineering
**Date:** 2025-10-03
**Objective:** Validate resilience and graceful degradation under failure conditions

---

## Executive Summary

This specification defines **systematic chaos testing scenarios** to validate the security infrastructure's resilience to failures. We will inject controlled failures and verify:

1. **Graceful Degradation:** System continues operating with reduced functionality
2. **No Security Compromises:** Failures never weaken security posture
3. **Automatic Recovery:** System self-heals when failures resolve
4. **Data Consistency:** No data loss or corruption during failures

---

## Chaos Testing Principles

### 1. Failure Injection Strategy

**Progressive Severity:**
```
Level 1: Component Degradation (slow responses, timeouts)
Level 2: Component Failure (service down, connection lost)
Level 3: Data Corruption (invalid state, key corruption)
Level 4: Cascading Failures (multiple simultaneous failures)
```

### 2. Safety First

**Pre-Test Checklist:**
- [ ] Run on isolated test environment (not production)
- [ ] Backup all critical data before tests
- [ ] Document rollback procedures
- [ ] Set maximum test duration (timeout: 5 minutes per scenario)
- [ ] Monitor system health continuously

### 3. Success Criteria

**For Each Scenario:**
- ✅ System does not crash or hang
- ✅ Security is maintained or strengthened (fail-secure)
- ✅ Graceful fallback to degraded mode
- ✅ Clear error messages and logging
- ✅ Automatic recovery when failure resolves

---

## Chaos Test Scenarios

### Scenario 1: Redis Connection Failure

**Objective:** Validate fallback to in-memory storage when Redis is unavailable

#### Test 1.1: Redis Down on Startup

**Failure Injection:**
```bash
# Stop Redis before starting application
net stop Memurai
# or
sudo systemctl stop redis
```

**Expected Behavior:**
```
[1] Application starts successfully
[2] Redis connection fails (logged warning)
[3] Automatic fallback to in-memory mode
[4] JWT blacklist uses in-memory set
[5] Rate limiting uses in-memory storage
[6] Warning logged: "Redis unavailable, using in-memory fallback (NOT for production!)"
```

**Validation Tests:**
- Create access token → should succeed
- Verify token → should succeed
- Revoke token → should succeed (in-memory)
- Verify revoked token → should fail (rejected)
- Check rate limit → should succeed (in-memory)

**Success Criteria:**
- ✅ No crashes or exceptions
- ✅ All security operations functional
- ✅ Clear warning about fallback mode
- ✅ Token revocation works (locally only)

**Limitations in Fallback Mode:**
- ⚠️ Token blacklist NOT distributed across servers
- ⚠️ Rate limits NOT shared across servers
- ⚠️ Data lost on restart (no persistence)

---

#### Test 1.2: Redis Connection Lost During Runtime

**Failure Injection:**
```python
# Application running normally with Redis
# Simulate network failure
import time
redis_client._available = False  # Simulate connection loss
# Or: net stop Memurai (from command line)
```

**Expected Behavior:**
```
[1] Application running normally with Redis
[2] Redis connection lost (network failure)
[3] Next Redis operation fails
[4] Automatic fallback to in-memory mode
[5] Operations continue with degraded functionality
[6] Error logged: "Redis operation failed, using fallback"
```

**Validation Tests:**
- Create token after failure → should succeed
- Revoke token after failure → should succeed (in-memory)
- Rate limit check after failure → should succeed (in-memory)
- Previously blacklisted tokens (Redis) → may not be blocked (data loss)

**Success Criteria:**
- ✅ No crashes or hangs
- ✅ Graceful transition to fallback mode
- ✅ Errors logged appropriately
- ⚠️ Accept data loss (Redis blacklist unavailable)

---

#### Test 1.3: Redis Reconnection After Failure

**Failure Injection:**
```bash
# Step 1: Stop Redis
net stop Memurai

# Step 2: Application runs in fallback mode

# Step 3: Restart Redis
net start Memurai
```

**Expected Behavior:**
```
[1] Redis stops → application in fallback mode
[2] Redis restarts
[3] Next operation attempts Redis connection
[4] Connection succeeds
[5] Application switches back to Redis mode
[6] Info logged: "Redis connection restored"
```

**Validation Tests:**
- Create token before Redis restart → in-memory
- Restart Redis
- Create token after Redis restart → should use Redis
- Verify distributed blacklist works again
- Verify distributed rate limiting works again

**Success Criteria:**
- ✅ Automatic reconnection
- ✅ No manual intervention required
- ✅ Distributed features restored
- ⚠️ Data created during fallback NOT migrated to Redis

---

### Scenario 2: Redis Data Corruption

**Objective:** Validate handling of corrupted or invalid Redis data

#### Test 2.1: Corrupted Blacklist Entry

**Failure Injection:**
```python
# Manually corrupt a blacklist entry
redis_client.set("blacklist:invalid_jti", "CORRUPTED_DATA")
redis_client.expire("blacklist:invalid_jti", 9999)  # Won't expire soon
```

**Expected Behavior:**
```
[1] Token verification attempts to check blacklist
[2] Finds corrupted entry
[3] Logs warning: "Invalid blacklist entry"
[4] Assumes token NOT blacklisted (fail-open for availability)
   OR assumes token IS blacklisted (fail-secure for security)
[5] Continues operation
```

**Validation Tests:**
- Verify token with JTI matching corrupted entry
- Check error logging
- Verify no crash or exception propagation

**Success Criteria:**
- ✅ No crashes
- ✅ Documented fail-open vs fail-secure behavior
- ✅ Warning logged
- ✅ System continues operating

**Design Decision Required:**
- **Fail-Open:** Allow token (prioritize availability)
- **Fail-Secure:** Reject token (prioritize security) ← **RECOMMENDED**

---

#### Test 2.2: Invalid Rate Limit Data

**Failure Injection:**
```python
# Corrupt rate limit sorted set
redis_client.zadd("ratelimit:window:user123:/api/test", {"invalid": "not_a_score"})
```

**Expected Behavior:**
```
[1] Rate limit check attempts to read sorted set
[2] Encounters invalid score
[3] Catches exception (Redis error)
[4] Falls back to in-memory or allows request
[5] Logs error: "Rate limit data corruption"
```

**Validation Tests:**
- Make request with corrupted rate limit data
- Verify graceful handling
- Check error logging

**Success Criteria:**
- ✅ No crashes
- ✅ Either fallback or allow request (documented)
- ✅ Error logged with details

---

### Scenario 3: Network Partitions

**Objective:** Validate behavior during network issues (timeouts, slow responses)

#### Test 3.1: Redis Timeout (Slow Network)

**Failure Injection:**
```python
# Simulate slow Redis responses
redis_client.socket_timeout = 0.001  # 1ms timeout (very aggressive)
# Or use network throttling tools (tc, wondershaper)
```

**Expected Behavior:**
```
[1] Redis operation times out
[2] TimeoutError raised
[3] Caught by exception handler
[4] Falls back to in-memory
[5] Warning logged: "Redis timeout, using fallback"
```

**Validation Tests:**
- Make multiple requests during timeout condition
- Verify all complete within reasonable time (no hanging)
- Check fallback mode activation

**Success Criteria:**
- ✅ Timeouts handled gracefully
- ✅ No hanging requests
- ✅ Fallback activated within 1 second

---

#### Test 3.2: Partial Network Partition (Some Servers Reach Redis, Others Don't)

**Failure Injection:**
```bash
# Server 1: Can reach Redis
# Server 2: Cannot reach Redis (firewall block)
iptables -A OUTPUT -p tcp --dport 6379 -j DROP  # Linux
# Or: Windows Firewall rule blocking port 6379
```

**Expected Behavior:**
```
[SERVER 1]
├─ Redis available
└─ Uses distributed blacklist

[SERVER 2]
├─ Redis unavailable (network blocked)
└─ Uses in-memory blacklist (NOT distributed)

[CONSISTENCY ISSUE]
└─ Token revoked on Server 1 → NOT revoked on Server 2
```

**Validation Tests:**
- Revoke token on Server 1
- Verify token on Server 2 → **may still be valid** (expected inconsistency)
- Document this as known limitation during network partitions

**Success Criteria:**
- ✅ Both servers continue operating
- ✅ No crashes
- ⚠️ **Accept temporary inconsistency** (documented trade-off)
- ✅ Recovery when network restored

---

### Scenario 4: Resource Exhaustion

**Objective:** Validate behavior under resource constraints

#### Test 4.1: Redis Connection Pool Exhaustion

**Failure Injection:**
```python
# Exhaust all connections in pool
max_connections = 50  # Default pool size
for i in range(100):
    # Create 100 concurrent operations (exceeds pool)
    asyncio.create_task(security_manager.jwt.verify_token(token))
```

**Expected Behavior:**
```
[1] First 50 connections acquired from pool
[2] Connections 51-100 wait for available connection
[3] Operations queued (blocking or timeout)
[4] Warning logged: "Connection pool exhausted"
[5] Operations complete as connections released
```

**Validation Tests:**
- Verify no connection leaks
- Check all operations eventually complete
- Monitor connection pool metrics

**Success Criteria:**
- ✅ No connection leaks
- ✅ Queuing behavior works correctly
- ✅ All operations complete (may be slow)

---

#### Test 4.2: Redis Memory Limit Exceeded

**Failure Injection:**
```bash
# Set very low memory limit in redis.conf
maxmemory 10mb
maxmemory-policy allkeys-lru  # Evict oldest keys
```

**Expected Behavior:**
```
[1] Redis reaches memory limit
[2] Starts evicting old keys (LRU)
[3] Some blacklisted tokens may be evicted
[4] Some rate limit data may be evicted
[5] Application continues (degraded security)
```

**Validation Tests:**
- Fill Redis with data until limit reached
- Verify eviction policy works
- Check if critical security data protected

**Success Criteria:**
- ✅ Redis doesn't crash
- ✅ Application continues operating
- ⚠️ **Security degradation accepted** (evicted blacklist = tokens become valid again)

**Mitigation:**
- Use separate Redis instance for security data
- Set higher memory limits for production
- Monitor memory usage and alert before limit

---

### Scenario 5: Cascading Failures

**Objective:** Validate behavior when multiple failures occur simultaneously

#### Test 5.1: Redis + Database Failure

**Failure Injection:**
```bash
# Stop both Redis and database
net stop Memurai
net stop PostgreSQL  # Or MySQL, etc.
```

**Expected Behavior:**
```
[1] Redis fails → fallback to in-memory
[2] Database fails → authentication/authorization fails
[3] Application enters degraded mode
[4] Read-only mode or service unavailable
[5] Clear error messages to users
```

**Validation Tests:**
- Attempt user login → should fail gracefully
- Attempt token verification → should work (in-memory)
- Check error responses (HTTP 503 Service Unavailable)

**Success Criteria:**
- ✅ No crashes
- ✅ Clear error messages
- ✅ Some operations still work (token verification)

---

#### Test 5.2: Redis Failure During High Load

**Failure Injection:**
```python
# Generate high load (1000 req/sec)
# Then stop Redis mid-test
async def generate_load():
    tasks = [verify_token(token) for _ in range(1000)]
    await asyncio.gather(*tasks)

# During execution:
# net stop Memurai
```

**Expected Behavior:**
```
[1] High load processing normally
[2] Redis fails mid-operation
[3] Some operations fail (in-flight)
[4] New operations use fallback
[5] Errors logged but no crashes
[6] Load continues at reduced capacity
```

**Validation Tests:**
- Count successful operations before failure
- Count failures during transition
- Count successful operations after fallback
- Verify no data corruption

**Success Criteria:**
- ✅ Most operations succeed
- ✅ < 5% error rate during transition
- ✅ Full recovery to fallback mode within 1 second

---

## Chaos Testing Implementation Plan

### Phase 1: Test Framework Setup (Day 2 Morning)

**Tasks:**
1. Create `test_chaos_scenarios.py` test file
2. Implement helper functions:
   - `stop_redis()` / `start_redis()`
   - `corrupt_redis_key(key, corruption_type)`
   - `simulate_network_timeout()`
   - `monitor_system_health()`
3. Set up test fixtures with cleanup

**Estimated Time:** 2 hours

---

### Phase 2: Basic Failure Tests (Day 2 Afternoon)

**Scenarios to Implement:**
- Scenario 1.1: Redis down on startup
- Scenario 1.2: Redis connection lost during runtime
- Scenario 1.3: Redis reconnection

**Estimated Time:** 3 hours

---

### Phase 3: Advanced Failure Tests (Day 3 Morning)

**Scenarios to Implement:**
- Scenario 2: Data corruption
- Scenario 3: Network issues
- Scenario 4: Resource exhaustion

**Estimated Time:** 3 hours

---

### Phase 4: Cascading Failure Tests (Day 3 Afternoon)

**Scenarios to Implement:**
- Scenario 5: Multiple simultaneous failures
- Load testing during failures

**Estimated Time:** 2 hours

---

## Monitoring and Observability

### Metrics to Track During Chaos Tests

```python
chaos_metrics = {
    "redis_connection_failures": 0,
    "fallback_activations": 0,
    "operations_failed": 0,
    "operations_succeeded": 0,
    "average_latency_ms": 0.0,
    "errors_logged": [],
    "recovery_time_ms": 0.0,
}
```

### Health Check Dashboard

**Real-Time Monitoring:**
- Redis connection status (up/down)
- Active connections in pool
- Fallback mode status (Redis/in-memory)
- Error rate (errors per second)
- Operation latency (p50, p95, p99)

---

## Expected Results Summary

### Failure Mode Matrix

| Scenario | Expected Behavior | Security Impact | Availability Impact |
|----------|------------------|----------------|---------------------|
| **Redis Down** | Fallback to in-memory | ⚠️ No distributed blacklist | ✅ Full functionality |
| **Redis Timeout** | Retry then fallback | ⚠️ Temporary delay | ✅ Graceful degradation |
| **Data Corruption** | Skip corrupted, log error | ⚠️ Fail-secure (reject) | ✅ Continue operating |
| **Network Partition** | Split-brain mode | ⚠️ Inconsistency across servers | ✅ Each server operational |
| **Connection Exhaustion** | Queue operations | ✅ No impact | ⚠️ Slower responses |
| **Memory Limit** | Evict old keys (LRU) | ⚠️ Old blacklist entries lost | ✅ Continue operating |
| **Cascading Failures** | Multiple fallbacks | ⚠️⚠️ Severe degradation | ⚠️ Partial unavailability |

---

## Risk Assessment

### Acceptable Risks

✅ **Temporary inconsistency during network partitions** (CAP theorem trade-off)
✅ **Data loss when falling back to in-memory** (ephemeral by design)
✅ **Slower responses during connection pool exhaustion** (queuing is correct behavior)

### Unacceptable Risks

❌ **System crashes or hangs** (must handle all failures gracefully)
❌ **Security weakening** (e.g., accepting invalid tokens)
❌ **Silent failures** (all errors must be logged)
❌ **Data corruption** (Redis data must remain valid or be discarded)

---

## Rollback Procedures

### If Chaos Test Causes Production Issue

```bash
# 1. Immediate rollback
git revert <commit-hash>
docker-compose restart

# 2. Restore Redis from backup
redis-cli --rdb /backup/dump.rdb

# 3. Verify system health
curl http://localhost:8000/health

# 4. Check logs for errors
tail -f /var/log/security/*.log
```

---

## Success Criteria Summary

**Chaos Testing Complete When:**
- ✅ All 10+ scenarios tested and documented
- ✅ 100% of tests have defined expected behavior
- ✅ All failures handled gracefully (no crashes)
- ✅ Recovery procedures validated
- ✅ Monitoring and alerting configured
- ✅ Documentation updated with failure modes

---

## Deliverables

1. **Test Suite:** `security/tests/test_chaos_scenarios.py` (500+ lines)
2. **Test Report:** `CHAOS_TESTING_RESULTS.md`
3. **Failure Mode Documentation:** `FAILURE_MODES_AND_RECOVERY.md`
4. **Monitoring Dashboard:** Grafana dashboard JSON
5. **Runbook:** `INCIDENT_RESPONSE_RUNBOOK.md`

---

**Specification Prepared By:** Claude Code (Anthropic)
**Date:** 2025-10-03
**Status:** ✅ **READY FOR IMPLEMENTATION**
**Next Step:** Implement chaos test framework

---

*This specification provides a systematic approach to chaos engineering for the security infrastructure, ensuring resilience and graceful degradation under all failure conditions.*
