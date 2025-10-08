# Alert Runbook: High API Latency

## Alert Details

- **Alert Name**: HighAPILatency
- **Severity**: Warning
- **Threshold**: p95 latency > 500ms
- **Duration**: 5 minutes
- **Category**: Performance

## Description

This alert fires when the 95th percentile (p95) API response time exceeds 500 milliseconds for more than 5 consecutive minutes. This indicates that at least 5% of requests are experiencing degraded performance.

## Impact

- Poor user experience
- Potential timeout errors in client applications
- Increased server resource consumption
- May indicate underlying system issues

## Symptoms

Users may report:
- Slow page loads
- Timeouts in API requests
- Delayed responses from the application
- Intermittent connection issues

## Diagnosis

### Step 1: Check Current Latency Metrics

```bash
# Query current p95 and p99 latency
curl -s 'http://localhost:9090/api/v1/query?query=api:latency:p95' | jq
curl -s 'http://localhost:9090/api/v1/query?query=api:latency:p99' | jq
```

**Grafana Dashboard**: Security Overview > API Response Time panel

### Step 2: Identify Slow Endpoints

```bash
# Find slowest endpoints
curl -s 'http://localhost:9090/api/v1/query?query=histogram_quantile(0.95,rate(http_request_duration_seconds_bucket[5m]))by(endpoint)' | jq
```

Look for specific endpoints that are significantly slower than others.

### Step 3: Check Database Query Performance

```bash
# Check database query latency
curl -s 'http://localhost:9090/api/v1/query?query=rate(database_query_duration_seconds_sum[5m])/rate(database_query_duration_seconds_count[5m])' | jq
```

If database queries are slow (>100ms average), investigate database performance.

### Step 4: Check System Resources

```bash
# Check CPU usage
curl -s 'http://localhost:9090/api/v1/query?query=100-(avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))*100)' | jq

# Check memory usage
curl -s 'http://localhost:9090/api/v1/query?query=(1-(node_memory_MemAvailable_bytes/node_memory_MemTotal_bytes))*100' | jq
```

High CPU or memory usage can cause latency issues.

### Step 5: Check External Dependencies

- **Redis Cache**: Check cache hit rate and connection pool
- **Database**: Check connection pool utilization
- **External APIs**: Check if external API calls are timing out

```bash
# Cache hit rate
curl -s 'http://localhost:9090/api/v1/query?query=rate(cache_hits_total[5m])/(rate(cache_hits_total[5m])+rate(cache_misses_total[5m]))' | jq
```

## Resolution

### Immediate Actions (< 5 minutes)

1. **Check for Obvious Issues**
   - Look for recent deployments or configuration changes
   - Check for DDoS or unusual traffic patterns
   - Verify external services are responding

2. **Enable Response Caching** (if not already enabled)
   ```bash
   # Update cache TTL for frequently accessed endpoints
   # This is application-specific
   ```

3. **Increase Server Resources** (if resource constrained)
   - Scale horizontally (add more instances)
   - Scale vertically (increase CPU/memory)

### Short-term Actions (< 1 hour)

1. **Optimize Slow Endpoints**
   - Add database indexes for slow queries
   - Implement query result caching
   - Optimize N+1 query patterns

2. **Review Database Performance**
   ```bash
   # Connect to database and check slow query log
   # PostgreSQL example:
   docker exec -it catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT * FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
   ```

3. **Check Connection Pools**
   - Ensure database connection pool is sized appropriately
   - Verify Redis connection pool settings
   - Check for connection leaks

### Long-term Actions (< 1 week)

1. **Implement Performance Monitoring**
   - Add detailed tracing for slow endpoints
   - Implement application performance monitoring (APM)
   - Set up automated performance testing

2. **Optimize Application Code**
   - Profile slow code paths
   - Implement lazy loading where appropriate
   - Add background job processing for heavy operations

3. **Database Optimization**
   - Review and optimize database schema
   - Implement read replicas for read-heavy workloads
   - Consider database caching layer (Redis)

4. **Implement CDN** (for static assets)
   - Offload static content to CDN
   - Implement edge caching

## Escalation

### When to Escalate

- Latency continues to increase despite mitigation efforts
- p99 latency exceeds 2 seconds
- User-facing errors increase
- System resources are at capacity

### Escalation Path

1. **Level 1**: On-call engineer (initial response)
2. **Level 2**: Backend team lead (if database-related)
3. **Level 3**: Infrastructure team (if resource-related)
4. **Level 4**: CTO (if service degradation continues)

### Contact Information

- Backend Team Slack: #backend-team
- Infrastructure Team Slack: #infrastructure
- On-call Engineer: PagerDuty rotation
- Emergency Hotline: [CONFIGURE IN PRODUCTION]

## Prevention

1. **Set up Performance Budgets**
   - Define acceptable latency thresholds per endpoint
   - Implement automated performance testing in CI/CD
   - Reject deployments that degrade performance

2. **Regular Performance Reviews**
   - Weekly review of latency metrics
   - Monthly capacity planning
   - Quarterly performance optimization sprints

3. **Implement Auto-scaling**
   - Configure horizontal pod autoscaling (Kubernetes)
   - Set up auto-scaling based on latency metrics
   - Implement circuit breakers for degraded services

4. **Database Maintenance**
   - Regular VACUUM and ANALYZE (PostgreSQL)
   - Index maintenance and optimization
   - Query plan reviews

## Related Alerts

- `DatabaseConnectionPoolExhaustion`: Check if database connections are maxed out
- `HighCPUUsage`: High CPU can cause increased latency
- `HighMemoryUsage`: Memory pressure can degrade performance
- `RedisCacheMissRateHigh`: Poor cache hit rate increases latency

## Additional Resources

- [Grafana Dashboard]: http://localhost:3000/d/catalytic-security-overview
- [Prometheus Alerts]: http://localhost:9090/alerts
- [Application Logs]: `docker logs catalytic-api`
- [Performance Tuning Guide]: docs/performance_tuning.md

## Changelog

- 2025-10-06: Initial runbook creation
