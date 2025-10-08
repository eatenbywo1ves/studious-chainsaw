# Alert Runbook: Service Unavailable

## Alert Details

- **Alert Name**: ServiceUnavailable
- **Severity**: Critical
- **Threshold**: Health check failures
- **Duration**: 2 minutes
- **Category**: Availability

## Description

The service health check endpoint is returning errors or timing out, indicating the service may be completely down or severely degraded.

## Impact

- Service completely unavailable to users
- All API requests failing
- Business operations halted
- Data access blocked
- Severe business impact

## Diagnosis

### Check Service Status

```bash
# Check container status
docker ps --filter name=catalytic-api

# Check health endpoint
curl -f http://localhost:8000/health || echo "Health check failed"

# Check application logs
docker logs --tail 100 catalytic-api
```

### Check Dependencies

```bash
# Check database
docker exec catalytic-postgres psql -U postgres -c "SELECT 1"

# Check Redis
docker exec catalytic-redis redis-cli ping

# Check all containers
docker-compose ps
```

### Check System Resources

```bash
# Check container resources
docker stats --no-stream

# Check disk space
df -h

# Check memory
free -h
```

## Resolution

### Immediate Actions

1. **Restart Service**
   ```bash
   docker-compose restart api
   ```

2. **Check for Port Conflicts**
   ```bash
   netstat -tuln | grep 8000
   ```

3. **Restart All Services**
   ```bash
   docker-compose down
   docker-compose up -d
   ```

### Recovery Actions

1. **Check Application Logs**
   ```bash
   docker logs catalytic-api --tail 500 | grep -i error
   ```

2. **Verify Configuration**
   ```bash
   # Check environment variables
   docker exec catalytic-api env | grep -E "DATABASE|REDIS|SECRET"
   ```

3. **Test Dependencies**
   ```bash
   # Test database connection
   docker exec catalytic-api python -c "from saas.database import engine; print(engine.execute('SELECT 1').scalar())"

   # Test Redis connection
   docker exec catalytic-api python -c "import redis; r=redis.Redis(host='redis'); print(r.ping())"
   ```

4. **Rebuild if Needed**
   ```bash
   docker-compose down
   docker-compose build --no-cache api
   docker-compose up -d
   ```

## Prevention

1. **Implement proper health checks**
2. **Set up auto-restart policies**
3. **Monitor resource usage**
4. **Regular deployment testing**
5. **Implement circuit breakers**

## Escalation

- Level 1: On-call engineer (immediate)
- Level 2: Team lead (5 minutes)
- Level 3: CTO (15 minutes)
- Communication: Update status page immediately

## Related Alerts

- `HighErrorRate`
- `DatabaseConnectionPoolExhaustion`
- `HighMemoryUsage`
- `DiskSpaceLow`

## Changelog

- 2025-10-06: Initial runbook creation
