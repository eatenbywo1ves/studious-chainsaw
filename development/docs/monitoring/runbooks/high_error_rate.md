# Alert Runbook: High Error Rate

## Alert Details

- **Alert Name**: HighErrorRate
- **Severity**: Critical
- **Threshold**: Error rate > 1% of total requests
- **Duration**: 5 minutes
- **Category**: Availability

## Description

This alert fires when more than 1% of API requests result in 5xx server errors over a 5-minute period. This indicates a serious problem with the application that is affecting users.

## Impact

- Service degradation or outage
- Data loss or corruption risk
- Poor user experience
- Potential security implications
- Business impact (lost revenue, reputation damage)

## Symptoms

Users may report:
- "Internal Server Error" messages
- Failed transactions
- Lost data
- Application crashes
- Inability to access certain features

## Diagnosis

### Step 1: Check Current Error Rate

```bash
# Query current error rate
curl -s 'http://localhost:9090/api/v1/query?query=rate(http_requests_total{status=~"5.."}[5m])/rate(http_requests_total[5m])*100' | jq
```

**Grafana Dashboard**: Security Overview > HTTP Status Code Distribution

### Step 2: Identify Error Types

```bash
# Break down by status code
curl -s 'http://localhost:9090/api/v1/query?query=sum(rate(http_requests_total{status=~"5.."}[5m]))by(status)' | jq

# Break down by endpoint
curl -s 'http://localhost:9090/api/v1/query?query=sum(rate(http_requests_total{status=~"5.."}[5m]))by(endpoint)' | jq
```

Common error codes:
- **500**: Internal Server Error (application bug)
- **502**: Bad Gateway (upstream service down)
- **503**: Service Unavailable (overload or maintenance)
- **504**: Gateway Timeout (slow upstream service)

### Step 3: Check Application Logs

```bash
# Get recent error logs
docker logs --tail 100 catalytic-api 2>&1 | grep -i error

# Get recent exception traces
docker logs --tail 500 catalytic-api 2>&1 | grep -A 10 "Traceback"
```

Look for:
- Stack traces
- Unhandled exceptions
- Database connection errors
- External API failures

### Step 4: Check Database Connectivity

```bash
# Check database connection pool
curl -s 'http://localhost:9090/api/v1/query?query=database_connections_active' | jq

# Test database connection
docker exec catalytic-api python -c "from saas.database import engine; print(engine.execute('SELECT 1').scalar())"
```

### Step 5: Check Redis Connectivity

```bash
# Check Redis connection
docker exec catalytic-redis redis-cli ping

# Check Redis memory
curl -s 'http://localhost:9090/api/v1/query?query=redis_memory_used_bytes/redis_memory_max_bytes*100' | jq
```

### Step 6: Check System Resources

```bash
# Check if application container is healthy
docker ps --filter name=catalytic-api

# Check container resources
docker stats catalytic-api --no-stream
```

## Resolution

### Immediate Actions (< 2 minutes)

1. **Determine Severity**
   - If error rate > 50%: CRITICAL - Consider emergency rollback
   - If error rate 10-50%: HIGH - Investigate and fix urgently
   - If error rate 1-10%: MEDIUM - Investigate specific failing endpoints

2. **Check for Recent Changes**
   ```bash
   # Check recent deployments
   git log -5 --oneline

   # Check recent configuration changes
   git diff HEAD~5 -- *.yml *.yaml *.json
   ```

3. **Rollback if Needed**
   ```bash
   # If recent deployment caused the issue
   git revert HEAD
   docker-compose down && docker-compose up -d --build
   ```

### Short-term Actions (< 15 minutes)

1. **Fix Database Connection Issues**
   ```bash
   # Restart database if unresponsive
   docker restart catalytic-postgres

   # Check for blocking queries
   docker exec catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT pid, query, state FROM pg_stat_activity WHERE state = 'active';"
   ```

2. **Fix Redis Issues**
   ```bash
   # Restart Redis if needed
   docker restart catalytic-redis

   # Clear cache if corrupted
   docker exec catalytic-redis redis-cli FLUSHALL
   ```

3. **Scale Application**
   ```bash
   # Add more application instances if overloaded
   docker-compose up -d --scale api=3
   ```

4. **Fix Application Bugs**
   - If specific endpoint is failing, disable or fix it
   - Add error handling for unhandled exceptions
   - Implement circuit breaker for failing external services

### Long-term Actions (< 24 hours)

1. **Root Cause Analysis**
   - Review error logs and stack traces
   - Identify code path causing errors
   - Reproduce issue in development environment
   - Write test case to prevent regression

2. **Implement Proper Error Handling**
   ```python
   # Add try-except blocks
   try:
       result = risky_operation()
   except SpecificException as e:
       logger.error(f"Operation failed: {e}")
       return {"error": "User-friendly message"}, 500
   ```

3. **Add Circuit Breakers**
   ```python
   # For external API calls
   from circuitbreaker import circuit

   @circuit(failure_threshold=5, recovery_timeout=60)
   def call_external_api():
       response = requests.get("https://api.external.com/data")
       response.raise_for_status()
       return response.json()
   ```

4. **Implement Retry Logic**
   ```python
   # For transient failures
   from tenacity import retry, stop_after_attempt, wait_exponential

   @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
   def database_operation():
       return db.execute(query)
   ```

5. **Improve Monitoring**
   - Add detailed error tracking (Sentry, Rollbar)
   - Implement distributed tracing (Jaeger, Zipkin)
   - Add custom error metrics per endpoint
   - Set up error rate alerts per endpoint

## Escalation

### When to Escalate

- Error rate exceeds 10%
- Service completely unavailable
- Data corruption detected
- Unable to identify root cause within 15 minutes
- Rollback unsuccessful

### Escalation Path

1. **Level 1**: On-call engineer (0-5 minutes)
2. **Level 2**: Backend team lead (5-15 minutes)
3. **Level 3**: Engineering manager (15-30 minutes)
4. **Level 4**: CTO + Incident commander (30+ minutes)

### Communication

1. **Internal Updates**
   - Post in #incidents Slack channel every 10 minutes
   - Create incident ticket in Jira/Linear
   - Update status page

2. **External Communication**
   - Update status page (status.example.com)
   - Send email to affected customers (if applicable)
   - Post on Twitter/social media (if public outage)

### Contact Information

- Backend Team Slack: #backend-team
- Incidents Channel: #incidents
- On-call Engineer: PagerDuty rotation
- Emergency Hotline: [CONFIGURE IN PRODUCTION]

## Prevention

1. **Comprehensive Testing**
   - Unit tests with >80% coverage
   - Integration tests for critical paths
   - End-to-end tests in staging
   - Load testing before deployment

2. **Gradual Rollouts**
   - Deploy to canary environment first
   - Monitor error rates during deployment
   - Use feature flags for risky changes
   - Implement automatic rollback on error spike

3. **Error Handling Standards**
   - All external API calls must have timeouts
   - All database calls must have error handling
   - All background jobs must have retry logic
   - All user input must be validated

4. **Monitoring Improvements**
   ```python
   # Add error tracking to all endpoints
   from prometheus_client import Counter

   errors_counter = Counter(
       'application_errors_total',
       'Total application errors',
       ['endpoint', 'error_type']
   )

   @app.errorhandler(Exception)
   def handle_error(error):
       errors_counter.labels(
           endpoint=request.path,
           error_type=type(error).__name__
       ).inc()
       logger.exception("Unhandled exception")
       return {"error": "Internal server error"}, 500
   ```

5. **Regular Chaos Testing**
   - Kill random services
   - Introduce network latency
   - Simulate database failures
   - Test disaster recovery procedures

## Common Root Causes

### Application Issues
- Unhandled exceptions in new code
- Memory leaks causing OOM errors
- Infinite loops or deadlocks
- Race conditions in concurrent code

### Database Issues
- Connection pool exhaustion
- Long-running queries blocking other queries
- Database server out of memory
- Disk full on database server

### External Dependencies
- Third-party API down or rate limiting
- Network connectivity issues
- DNS resolution failures
- SSL certificate expiration

### Infrastructure Issues
- Container running out of memory
- Disk full on application server
- CPU throttling
- Network partition

## Related Alerts

- `DatabaseConnectionPoolExhaustion`: Check if DB connections maxed out
- `HighMemoryUsage`: OOM can cause errors
- `HighCPUUsage`: CPU exhaustion can cause timeouts
- `RedisMemoryHigh`: Cache issues can cause errors

## Additional Resources

- [Grafana Dashboard]: http://localhost:3000/d/catalytic-security-overview
- [Prometheus Alerts]: http://localhost:9090/alerts
- [Application Logs]: `docker logs -f catalytic-api`
- [Error Tracking]: [Configure Sentry URL]
- [Incident Response Playbook]: docs/incident_response.md

## Changelog

- 2025-10-06: Initial runbook creation
