# Performance Baselines - Catalytic Computing SaaS Platform

This document defines expected performance baselines and targets for the Catalytic Computing SaaS platform under various load conditions.

## Performance Targets

### Primary Targets

| Metric | Target | Critical? | Notes |
|--------|--------|-----------|-------|
| **API Latency (p50)** | <100ms | Important | Median user experience |
| **API Latency (p95)** | <500ms | **Critical** | 95% of users |
| **API Latency (p99)** | <1000ms | Important | 99% of users |
| **Throughput** | >1000 req/s | **Critical** | Minimum sustained throughput |
| **Error Rate** | <1% | **Critical** | Failed requests / total requests |
| **Availability** | >99.9% | **Critical** | Uptime target (8.76 hours downtime/year) |

### Resource Utilization Targets

| Resource | Normal Load | High Load | Critical Threshold |
|----------|-------------|-----------|-------------------|
| **CPU Usage** | <50% | <70% | 90% |
| **Memory Usage** | <60% | <80% | 95% |
| **Database Connections** | <50% pool | <75% pool | 90% pool |
| **Redis Memory** | <40% max | <60% max | 80% max |
| **Disk I/O** | <50% capacity | <70% capacity | 90% capacity |

---

## Baseline Performance by Scenario

### 1. Baseline Test (100 Users)

**Expected Performance:**

| Metric | Target | Acceptable Range |
|--------|--------|------------------|
| p50 Latency | <50ms | 30-80ms |
| p95 Latency | <200ms | 150-300ms |
| p99 Latency | <500ms | 400-700ms |
| Throughput | >500 req/s | 400-800 req/s |
| Error Rate | <0.1% | 0-0.5% |
| CPU Usage | <30% | 20-40% |
| Memory Usage | <40% | 30-50% |

**Operations Mix:**
- Registration: ~5%
- Login/Auth: ~10%
- Lattice Create: ~15%
- Lattice List: ~45%
- Lattice Get: ~20%
- Lattice Delete: ~5%

**Expected Results:**
- Smooth, consistent performance
- Minimal resource utilization
- Zero failures (or <1 per 1000 requests)
- Stable memory usage over time

---

### 2. Stress Test (500 Users)

**Expected Performance:**

| Metric | Target | Acceptable Range |
|--------|--------|------------------|
| p50 Latency | <100ms | 80-150ms |
| p95 Latency | <500ms | 400-700ms |
| p99 Latency | <1000ms | 800-1500ms |
| Throughput | >1000 req/s | 800-1500 req/s |
| Error Rate | <1% | 0-2% |
| CPU Usage | <70% | 60-80% |
| Memory Usage | <70% | 60-80% |

**Stress Indicators:**
- Response times increase by 2-3x vs baseline
- CPU utilization increases significantly
- Database query queue builds slightly
- Some rate limiting may activate

**Expected Results:**
- System remains stable
- No cascading failures
- Performance degrades gracefully
- Quick recovery after load reduction

---

### 3. Spike Test (0→1000 Users)

**Expected Performance:**

| Metric | Target | Acceptable Range |
|--------|--------|------------------|
| p50 Latency | <150ms | 100-250ms |
| p95 Latency | <1000ms | 700-1500ms |
| p99 Latency | <2000ms | 1500-3000ms |
| Throughput | >800 req/s | 500-1200 req/s |
| Error Rate | <5% | 0-10% |
| Recovery Time | <60s | 30-120s |

**Spike Response:**
- Initial surge handled with degradation
- Rate limiting activates appropriately
- Some requests queued/delayed
- System recovers within 60 seconds
- Performance returns to normal after spike

**Expected Results:**
- No permanent degradation
- No system crashes
- Error rate elevated during spike only
- Fast recovery to baseline

---

### 4. Soak Test (50 Users, 4 Hours)

**Expected Performance:**

| Metric | Hour 1 | Hour 2 | Hour 3 | Hour 4 |
|--------|--------|--------|--------|--------|
| p50 Latency | <50ms | <50ms | <50ms | <50ms |
| p95 Latency | <200ms | <200ms | <200ms | <200ms |
| p99 Latency | <500ms | <500ms | <500ms | <500ms |
| Throughput | >200 req/s | >200 req/s | >200 req/s | >200 req/s |
| Error Rate | <0.1% | <0.1% | <0.1% | <0.1% |
| Memory Usage | ~40% | ~40% | ~40% | ~40% |

**Stability Indicators:**
- No memory leaks (stable memory over 4 hours)
- Consistent response times (no degradation)
- No connection pool exhaustion
- No resource leaks
- Database performance remains stable

**Expected Results:**
- Flat memory usage graph
- Consistent latency throughout
- No errors or failures
- Clean shutdown without OOM

---

### 5. Mixed Workload Test (200 Users)

**Expected Performance:**

| Metric | Target | Acceptable Range |
|--------|--------|------------------|
| p50 Latency | <80ms | 60-120ms |
| p95 Latency | <400ms | 300-600ms |
| p99 Latency | <800ms | 600-1200ms |
| Throughput | >600 req/s | 500-900 req/s |
| Error Rate | <0.5% | 0-1% |

**Traffic Distribution:**
- 15% Authentication operations
- 60% Read operations (list/get)
- 20% Write operations (create)
- 5% Delete operations

**Expected Results:**
- Balanced performance across operation types
- Read operations: <100ms p95
- Write operations: <500ms p95
- Auth operations: <300ms p95
- Realistic production baseline

---

## Performance by Endpoint

### Authentication Endpoints

| Endpoint | p50 | p95 | p99 | Throughput |
|----------|-----|-----|-----|------------|
| POST /api/auth/register | <100ms | <300ms | <500ms | >200 req/s |
| POST /api/auth/login | <50ms | <150ms | <300ms | >500 req/s |
| POST /api/auth/refresh | <30ms | <100ms | <200ms | >1000 req/s |
| POST /api/auth/logout | <30ms | <100ms | <200ms | >1000 req/s |

### Lattice Endpoints

| Endpoint | p50 | p95 | p99 | Throughput |
|----------|-----|-----|-----|------------|
| POST /api/lattices | <200ms | <800ms | <1500ms | >100 req/s |
| GET /api/lattices | <50ms | <200ms | <400ms | >1000 req/s |
| GET /api/lattices/{id} | <50ms | <200ms | <400ms | >800 req/s |
| DELETE /api/lattices/{id} | <50ms | <150ms | <300ms | >500 req/s |

### System Endpoints

| Endpoint | p50 | p95 | p99 | Throughput |
|----------|-----|-----|-----|------------|
| GET /health | <10ms | <30ms | <50ms | >5000 req/s |
| GET /metrics | <20ms | <50ms | <100ms | >2000 req/s |

---

## Database Performance Baselines

### Query Performance

| Query Type | Target | Max Acceptable |
|------------|--------|----------------|
| Simple SELECT | <5ms | 10ms |
| JOIN (2-3 tables) | <20ms | 50ms |
| Complex JOIN (4+ tables) | <50ms | 100ms |
| INSERT | <10ms | 30ms |
| UPDATE | <10ms | 30ms |
| DELETE | <10ms | 30ms |

### Connection Pool

| Metric | Normal | High Load | Critical |
|--------|--------|-----------|----------|
| Active Connections | <20 | <50 | <80 |
| Pool Size | 50 | 100 | 100 |
| Max Overflow | 50 | 100 | 100 |
| Connection Wait | <10ms | <50ms | <100ms |

---

## Redis Performance Baselines

### Operation Latency

| Operation | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| GET | <1ms | <3ms | <5ms |
| SET | <1ms | <3ms | <5ms |
| DEL | <1ms | <3ms | <5ms |
| EXPIRE | <1ms | <3ms | <5ms |
| KEYS (avoid!) | - | - | - |

### Memory Usage

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| Used Memory | <128MB | >192MB | >240MB |
| Max Memory | 256MB | 256MB | 256MB |
| Eviction Policy | allkeys-lru | - | - |
| Fragmentation Ratio | 1.0-1.5 | 1.5-2.0 | >2.0 |

---

## GPU Performance Baselines (Large Lattices)

### Lattice Operations with GPU

| Lattice Size | CPU Time | GPU Time | Speedup |
|--------------|----------|----------|---------|
| 1000 elements | ~100ms | ~5ms | 20x |
| 5000 elements | ~500ms | ~25ms | 20x |
| 10000 elements | ~1000ms | ~50ms | 20x |

**Expected GPU Utilization:**
- Large lattices (>1000 elements): GPU preferred
- Small lattices (<1000 elements): CPU acceptable
- Fallback to CPU if GPU unavailable
- No performance degradation on GPU failure

---

## Scaling Characteristics

### Horizontal Scaling (API Servers)

| Servers | Expected Throughput | Max Users |
|---------|-------------------|-----------|
| 1 | ~1000 req/s | ~500 users |
| 2 | ~2000 req/s | ~1000 users |
| 4 | ~4000 req/s | ~2000 users |
| 8 | ~8000 req/s | ~4000 users |

**Scaling Efficiency:**
- Expected: 80-90% linear scaling
- Bottlenecks: Database, Redis, network

### Vertical Scaling (Resources)

| CPU Cores | Memory | Expected Throughput |
|-----------|--------|-------------------|
| 2 cores | 4GB | ~500 req/s |
| 4 cores | 8GB | ~1000 req/s |
| 8 cores | 16GB | ~2000 req/s |
| 16 cores | 32GB | ~4000 req/s |

---

## Performance Degradation Thresholds

### Warning Thresholds

- p95 latency > 400ms
- Error rate > 0.5%
- CPU usage > 70%
- Memory usage > 70%
- Database connections > 75% pool

**Action:** Monitor closely, prepare to scale

### Critical Thresholds

- p95 latency > 1000ms
- Error rate > 2%
- CPU usage > 90%
- Memory usage > 90%
- Database connections > 90% pool

**Action:** Immediate scaling or load shedding required

### Emergency Thresholds

- p95 latency > 5000ms
- Error rate > 10%
- CPU usage sustained at 100%
- Memory usage > 95%
- Service unavailable

**Action:** Emergency response, potential service degradation

---

## Capacity Planning

### Current Capacity (Single Server)

- **Max Concurrent Users:** 500
- **Max Requests/Second:** 1000
- **Max Daily Active Users:** 10,000
- **Max Monthly Requests:** 100M

### Growth Targets

| Timeline | Users | Req/s | Servers | Database | Redis |
|----------|-------|-------|---------|----------|-------|
| **Month 1** | 500 | 1K | 1 | 1 | 1 |
| **Month 3** | 2K | 4K | 2 | 1 | 1 |
| **Month 6** | 5K | 10K | 4 | 2 (replica) | 2 (cluster) |
| **Month 12** | 20K | 40K | 16 | 4 (sharded) | 4 (cluster) |

---

## Testing Checklist

Before declaring performance baseline established:

- [ ] Baseline test passes (<500ms p95, <1% error)
- [ ] Stress test passes (system stable at 500 users)
- [ ] Spike test passes (recovery <60s)
- [ ] Soak test passes (4 hours, no memory leaks)
- [ ] Mixed workload test passes (realistic traffic)
- [ ] All endpoints meet individual targets
- [ ] Database queries optimized (<50ms p95)
- [ ] Redis performance validated (<5ms p99)
- [ ] GPU acceleration validated (20x speedup)
- [ ] Horizontal scaling tested (2+ servers)
- [ ] Monitoring and alerting configured
- [ ] Capacity plan documented
- [ ] Degradation thresholds defined
- [ ] Emergency procedures documented

---

## Historical Performance Data

### Baseline Runs

**2025-10-06 - Initial Baseline**

| Scenario | p95 Latency | Throughput | Error Rate | Pass/Fail |
|----------|-------------|------------|------------|-----------|
| Baseline | TBD | TBD | TBD | ⏳ Pending |
| Stress | TBD | TBD | TBD | ⏳ Pending |
| Spike | TBD | TBD | TBD | ⏳ Pending |
| Soak | TBD | TBD | TBD | ⏳ Pending |
| Mixed | TBD | TBD | TBD | ⏳ Pending |

**Update this section after running initial load tests.**

---

## Performance Optimization Roadmap

### Phase 1: Core Optimization (Current)
- ✅ Database indexing
- ✅ Redis caching
- ✅ Connection pooling
- ✅ GPU acceleration
- ⏳ Load test validation

### Phase 2: Scaling (Next)
- [ ] Horizontal scaling (2+ API servers)
- [ ] Database read replicas
- [ ] Redis clustering
- [ ] CDN for static assets
- [ ] Load balancer configuration

### Phase 3: Advanced (Future)
- [ ] Database sharding
- [ ] Microservices architecture
- [ ] Edge computing
- [ ] Auto-scaling
- [ ] Multi-region deployment

---

## References

- [Load Testing README](README.md)
- [Locust Documentation](https://docs.locust.io/)
- [API Documentation](../../docs/API_DOCUMENTATION.md)
- [Systematic Execution Plan](../../SYSTEMATIC_EXECUTION_PLAYBOOK.md)

---

**Last Updated:** 2025-10-06
**Status:** Initial Baseline - Pending First Test Runs
**Next:** Execute load tests and populate historical data
