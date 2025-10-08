# Alert Runbook: Database Connection Pool Exhaustion

## Alert Details

- **Alert Name**: DatabaseConnectionPoolExhaustion
- **Severity**: Critical
- **Threshold**: Active connections > 90% of max pool size
- **Duration**: 5 minutes
- **Category**: Security/Performance

## Description

This alert fires when the database connection pool utilization exceeds 90% of the maximum pool size for more than 5 minutes. This indicates that the application is running out of database connections, which will cause new requests to fail or hang.

## Impact

- New requests will fail with "connection pool exhausted" errors
- Application performance degradation
- Timeouts and 500 errors for users
- Potential service outage
- May indicate connection leak or DDoS attack

## Symptoms

Users may experience:
- "Connection timeout" errors
- "Database connection pool exhausted" errors
- Slow application response times
- Failed transactions
- Application hanging or freezing

## Diagnosis

### Step 1: Check Connection Pool Status

```bash
# Check current connection pool utilization
curl -s 'http://localhost:9090/api/v1/query?query=database_connections_active/database_connections_max*100' | jq

# Check connection pool metrics
curl -s 'http://localhost:9090/api/v1/query?query=database_connections_active' | jq
curl -s 'http://localhost:9090/api/v1/query?query=database_connections_max' | jq
curl -s 'http://localhost:9090/api/v1/query?query=database_connections_idle' | jq
```

**Grafana Dashboard**: System Metrics > Database Connection Pool panel

### Step 2: Check Database Active Connections

```bash
# Check PostgreSQL active connections
docker exec catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';"

# List all connections by state
docker exec catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT state, count(*) FROM pg_stat_activity GROUP BY state;"

# Show long-running queries
docker exec catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT pid, now() - query_start as duration, state, query FROM pg_stat_activity WHERE state = 'active' AND now() - query_start > interval '1 minute' ORDER BY duration DESC;"
```

### Step 3: Identify Connection Leaks

```bash
# Check application logs for unclosed connections
docker logs --tail 500 catalytic-api 2>&1 | grep -i "connection"

# Check for database connection warnings
docker logs --tail 500 catalytic-api 2>&1 | grep -i "pool"
```

Look for patterns like:
- Connections not being returned to pool
- Exceptions during database operations
- Unclosed cursors or sessions

### Step 4: Check for DDoS or Traffic Spike

```bash
# Check request rate
curl -s 'http://localhost:9090/api/v1/query?query=rate(http_requests_total[5m])*60' | jq

# Compare to baseline
curl -s 'http://localhost:9090/api/v1/query?query=api:request_rate:avg1h' | jq
```

If request rate is significantly higher than baseline, it may be a DDoS attack.

### Step 5: Check for Slow Queries

```bash
# Find slow queries in PostgreSQL
docker exec catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT query, mean_exec_time, calls FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
```

Slow queries can hold connections for extended periods.

## Resolution

### Immediate Actions (< 2 minutes)

1. **Increase Connection Pool Size** (temporary fix)
   ```bash
   # Edit application configuration
   # Increase SQLALCHEMY_POOL_SIZE and SQLALCHEMY_MAX_OVERFLOW
   # Restart application
   docker-compose restart api
   ```

2. **Kill Long-Running Queries**
   ```bash
   # Identify query PID from step 2
   # Kill the query
   docker exec catalytic-postgres psql -U postgres -d catalytic_db -c "SELECT pg_terminate_backend(PID);"
   ```

3. **Restart Application** (if connection leak suspected)
   ```bash
   docker-compose restart api
   ```

### Short-term Actions (< 30 minutes)

1. **Fix Connection Leaks**

   Common causes and fixes:

   **a) Not closing connections in exception handlers**
   ```python
   # BAD - connection may leak on exception
   def get_user(user_id):
       conn = engine.connect()
       result = conn.execute("SELECT * FROM users WHERE id = %s", user_id)
       return result.fetchone()

   # GOOD - connection always closed
   def get_user(user_id):
       with engine.connect() as conn:
           result = conn.execute("SELECT * FROM users WHERE id = %s", user_id)
           return result.fetchone()
   ```

   **b) Not committing/rolling back transactions**
   ```python
   # BAD - transaction may hang
   def update_user(user_id, data):
       session = Session()
       user = session.query(User).get(user_id)
       user.update(data)

   # GOOD - transaction properly handled
   def update_user(user_id, data):
       session = Session()
       try:
           user = session.query(User).get(user_id)
           user.update(data)
           session.commit()
       except Exception as e:
           session.rollback()
           raise
       finally:
           session.close()
   ```

   **c) Not using context managers**
   ```python
   # Use Flask-SQLAlchemy's scoped session
   from flask_sqlalchemy import SQLAlchemy

   db = SQLAlchemy(app)

   @app.teardown_appcontext
   def shutdown_session(exception=None):
       db.session.remove()
   ```

2. **Optimize Connection Pool Settings**
   ```python
   # In application config
   SQLALCHEMY_POOL_SIZE = 20  # Base pool size
   SQLALCHEMY_MAX_OVERFLOW = 10  # Additional connections beyond pool_size
   SQLALCHEMY_POOL_TIMEOUT = 30  # Seconds to wait for connection
   SQLALCHEMY_POOL_RECYCLE = 3600  # Recycle connections after 1 hour
   SQLALCHEMY_POOL_PRE_PING = True  # Test connections before using
   ```

3. **Implement Connection Pool Monitoring**
   ```python
   from sqlalchemy import event
   from prometheus_client import Gauge

   pool_size_gauge = Gauge('db_pool_size', 'Database pool size')
   pool_checked_out = Gauge('db_pool_checked_out', 'Checked out connections')

   @event.listens_for(Engine, "connect")
   def receive_connect(dbapi_conn, connection_record):
       pool_size_gauge.set(engine.pool.size())
       pool_checked_out.set(engine.pool.checkedout())
   ```

### Long-term Actions (< 1 week)

1. **Implement Read Replicas**
   ```python
   # Separate read and write operations
   SQLALCHEMY_DATABASE_URI = 'postgresql://user:pass@master:5432/db'
   SQLALCHEMY_BINDS = {
       'read_replica': 'postgresql://user:pass@replica:5432/db'
   }

   # Use bind for read-only queries
   users = User.query.options(db.with_bind('read_replica')).all()
   ```

2. **Implement Connection Pooling at Database Level**
   ```bash
   # Install PgBouncer
   docker run -d --name pgbouncer \
     -e DB_HOST=postgres \
     -e DB_PORT=5432 \
     -e DB_USER=postgres \
     -e DB_PASSWORD=postgres \
     -e POOL_MODE=transaction \
     -e MAX_CLIENT_CONN=1000 \
     -e DEFAULT_POOL_SIZE=25 \
     pgbouncer/pgbouncer

   # Update application to connect through PgBouncer
   SQLALCHEMY_DATABASE_URI = 'postgresql://user:pass@pgbouncer:6432/db'
   ```

3. **Add Query Timeout**
   ```python
   # Set statement timeout
   from sqlalchemy import event

   @event.listens_for(Engine, "connect")
   def set_query_timeout(dbapi_conn, connection_record):
       cursor = dbapi_conn.cursor()
       cursor.execute("SET statement_timeout = '30s'")
       cursor.close()
   ```

4. **Implement Caching**
   ```python
   # Cache frequent queries
   from flask_caching import Cache

   cache = Cache(app, config={'CACHE_TYPE': 'redis'})

   @cache.memoize(timeout=300)
   def get_user(user_id):
       return User.query.get(user_id)
   ```

5. **Regular Connection Auditing**
   ```bash
   # Create monitoring script
   # File: scripts/monitor_connections.sh

   #!/bin/bash
   while true; do
       docker exec catalytic-postgres psql -U postgres -c "
         SELECT
           count(*) as total_connections,
           count(*) FILTER (WHERE state = 'active') as active,
           count(*) FILTER (WHERE state = 'idle') as idle,
           count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction
         FROM pg_stat_activity
         WHERE datname = 'catalytic_db';
       "
       sleep 60
   done
   ```

## Escalation

### When to Escalate

- Connection pool exhaustion persists after immediate fixes
- Database server itself is unresponsive
- Data corruption suspected
- Unable to identify root cause within 15 minutes
- Multiple services affected

### Escalation Path

1. **Level 1**: On-call engineer (0-5 minutes)
2. **Level 2**: Database administrator (5-15 minutes)
3. **Level 3**: Infrastructure team lead (15-30 minutes)
4. **Level 4**: CTO (30+ minutes or data corruption)

### Contact Information

- Backend Team Slack: #backend-team
- Database Team Slack: #database-team
- Infrastructure Team: #infrastructure
- On-call DBA: PagerDuty rotation
- Emergency Hotline: [CONFIGURE IN PRODUCTION]

## Prevention

1. **Code Review Checklist**
   - [ ] All database connections use context managers
   - [ ] All transactions properly committed/rolled back
   - [ ] All cursors properly closed
   - [ ] Exception handlers don't leak connections
   - [ ] Sessions removed at end of request

2. **Automated Testing**
   ```python
   # Test for connection leaks
   def test_connection_pool_no_leak():
       initial_connections = engine.pool.checkedout()

       for i in range(100):
           with engine.connect() as conn:
               conn.execute("SELECT 1")

       final_connections = engine.pool.checkedout()
       assert initial_connections == final_connections
   ```

3. **Connection Pool Monitoring Dashboard**
   - Current pool utilization
   - Peak utilization per hour
   - Average connection lifetime
   - Connection wait time
   - Idle connection count

4. **Regular Load Testing**
   ```bash
   # Use Locust or similar tool
   locust -f load_test.py --users 1000 --spawn-rate 10
   ```

5. **Database Capacity Planning**
   - Monitor trends in connection usage
   - Plan for traffic growth
   - Regular performance reviews

## Common Root Causes

### Application Issues
- Connection leaks (not closing connections)
- Long-running transactions
- Not using connection pooling
- Synchronous blocking operations
- N+1 query problem

### Database Issues
- Slow queries holding connections
- Lock contention
- Vacuum processes blocking queries
- Replication lag

### Configuration Issues
- Pool size too small
- Timeout too long
- No connection recycling
- Missing pre-ping checks

### Traffic Issues
- DDoS attack
- Legitimate traffic spike
- Bot traffic
- Retry storms

## Related Alerts

- `HighDatabaseQueryLatency`: Slow queries can hold connections
- `HighAPILatency`: Connection exhaustion causes high latency
- `HighErrorRate`: Connection failures cause errors
- `AnomalousAPIUsage`: Traffic spike can exhaust pool

## Additional Resources

- [Grafana Dashboard]: http://localhost:3000/d/catalytic-security-overview
- [Prometheus Alerts]: http://localhost:9090/alerts
- [Database Logs]: `docker logs catalytic-postgres`
- [SQLAlchemy Connection Pooling]: https://docs.sqlalchemy.org/en/14/core/pooling.html
- [PostgreSQL Connection Management]: https://www.postgresql.org/docs/current/runtime-config-connection.html

## Changelog

- 2025-10-06: Initial runbook creation
