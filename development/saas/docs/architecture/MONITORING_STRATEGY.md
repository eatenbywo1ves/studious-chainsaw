# Monitoring & Observability Strategy - Catalytic Computing SaaS

## Executive Summary

**Goal:** Achieve full-stack observability with proactive alerting and performance insights.

**Stack:**
- **Metrics**: Prometheus + Grafana
- **Logs**: Structured logging (JSON) + Loki (optional)
- **Traces**: OpenTelemetry (optional, Phase 2)
- **Alerts**: Alertmanager → PagerDuty/Slack

**Key Metrics:**
- API response times (p50, p95, p99)
- Database query performance
- Cache hit rates
- Error rates
- Resource utilization (CPU, memory, disk)
- Business metrics (signups, API usage, revenue)

---

## Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                        │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐           │
│  │  FastAPI   │  │  Workers   │  │  Celery    │           │
│  │  /metrics  │  │  /metrics  │  │  /metrics  │           │
│  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘           │
│         │                │                │                 │
│         └────────────────┴────────────────┘                 │
│                          │                                   │
└──────────────────────────┼───────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PROMETHEUS                               │
│  - Scrapes /metrics endpoints every 15s                    │
│  - Stores time-series data (15 day retention)              │
│  - Evaluates alert rules                                   │
│  - Sends alerts to Alertmanager                            │
└──────────────┬────────────────────┬─────────────────────────┘
               │                    │
               ▼                    ▼
┌──────────────────────┐  ┌────────────────────────────────┐
│     GRAFANA          │  │      ALERTMANAGER              │
│  - Dashboards        │  │  - Alert routing               │
│  - Visualizations    │  │  - Deduplication               │
│  - Queries           │  │  - Notifications               │
└──────────────────────┘  └──────────┬─────────────────────┘
                                     │
                                     ▼
                          ┌────────────────────┐
                          │  NOTIFICATIONS     │
                          │  - Slack           │
                          │  - PagerDuty       │
                          │  - Email           │
                          └────────────────────┘
```

---

## Key Metrics to Track

### 1. Application Metrics (Golden Signals)

#### Latency (Response Time)
```prometheus
# API endpoint response times
http_request_duration_seconds{endpoint="/api/lattices", method="GET"}

# Histogram buckets: 0.1s, 0.5s, 1s, 2s, 5s
# Track: p50, p95, p99
```

**Thresholds:**
- **p50 < 100ms**: Good
- **p95 < 500ms**: Acceptable
- **p99 < 1s**: Warning
- **p99 > 2s**: Critical

#### Traffic (Request Rate)
```prometheus
# Requests per second
rate(http_requests_total[5m])

# By endpoint
rate(http_requests_total{endpoint="/api/lattices"}[5m])
```

**Thresholds:**
- **Normal**: 10-100 req/sec
- **High**: 100-500 req/sec (scale consideration)
- **Critical**: > 500 req/sec (scale immediately)

#### Errors (Error Rate)
```prometheus
# Error rate percentage
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) * 100

# Error count
sum(rate(http_requests_total{status=~"5.."}[5m]))
```

**Thresholds:**
- **< 0.1%**: Excellent
- **0.1-1%**: Good
- **1-5%**: Warning
- **> 5%**: Critical

#### Saturation (Resource Usage)
```prometheus
# CPU usage
process_cpu_usage_percent

# Memory usage
process_memory_usage_bytes / process_memory_limit_bytes * 100

# Database connections
db_connection_pool_active / db_connection_pool_size * 100
```

**Thresholds:**
- **CPU > 80%**: Warning
- **Memory > 85%**: Warning
- **DB connections > 90%**: Critical

### 2. Database Metrics

#### Query Performance
```prometheus
# Query duration by operation
pg_query_duration_seconds{operation="SELECT"}

# Slow queries (> 1 second)
pg_slow_queries_total

# Active connections
pg_stat_database_numbackends{datname="catalytic_saas"}

# Transaction rate
rate(pg_stat_database_xact_commit{datname="catalytic_saas"}[5m])
```

**Thresholds:**
- **Query p95 < 100ms**: Good
- **Slow queries > 10/min**: Warning
- **Active connections > 80% pool**: Critical

#### Table Statistics
```prometheus
# Table size growth
pg_table_size_bytes{tablename="api_logs"}

# Index usage
pg_stat_user_indexes_idx_scan{indexname="idx_users_email"}

# Sequential scans (should be low)
pg_stat_user_tables_seq_scan{tablename="tenants"}
```

#### Partition Health
```prometheus
# Active partition count
pg_partitions_active_count{table="api_logs"}

# Oldest partition age (days)
pg_partition_oldest_age_days{table="api_logs"}
```

**Alerts:**
- **Oldest partition > 100 days**: Run archival
- **No future partitions**: Create next month's partition

### 3. Redis Cache Metrics

#### Cache Performance
```prometheus
# Cache hit rate
redis_keyspace_hits_total / (redis_keyspace_hits_total + redis_keyspace_misses_total) * 100

# Cache operations per second
rate(redis_commands_processed_total[5m])

# Memory usage
redis_memory_used_bytes / redis_memory_max_bytes * 100

# Connected clients
redis_connected_clients
```

**Thresholds:**
- **Hit rate > 80%**: Good
- **Hit rate < 50%**: Review cache strategy
- **Memory > 80%**: Warning (may evict keys)
- **Clients > 100**: Investigate connection leaks

#### Cache Latency
```prometheus
# Cache operation duration
cache_operation_duration_seconds{operation="get"}
cache_operation_duration_seconds{operation="set"}
```

**Thresholds:**
- **p95 < 5ms**: Excellent
- **p95 > 20ms**: Investigate Redis performance

### 4. Business Metrics

#### User Activity
```prometheus
# Active tenants (API calls in last hour)
count(increase(usage_api_calls_total[1h]) > 0)

# New tenant signups (per day)
increase(tenant_created_total[24h])

# API calls per tenant
rate(usage_api_calls_total{tenant_id="..."}[5m])
```

#### Usage & Limits
```prometheus
# Tenants near limit (> 90% of quota)
count(usage_api_calls_current / usage_api_calls_limit > 0.9)

# Limit exceeded events
rate(limit_exceeded_total[5m])
```

#### Revenue Metrics
```prometheus
# Active subscriptions by plan
count(subscription_active{plan="professional"})

# Monthly recurring revenue (MRR)
sum(subscription_mrr_dollars)

# Churn rate (cancellations)
rate(subscription_cancelled_total[30d])
```

---

## Prometheus Configuration

### prometheus.yml

```yaml
global:
  scrape_interval: 15s      # Scrape every 15 seconds
  evaluation_interval: 15s  # Evaluate rules every 15 seconds
  external_labels:
    environment: 'production'
    cluster: 'catalytic-saas'

# Alertmanager configuration
alerting:
  alertmanagers:
    - static_configs:
        - targets:
            - 'localhost:9093'

# Load alert rules
rule_files:
  - 'alerts/*.yml'

# Scrape configurations
scrape_configs:
  # FastAPI application
  - job_name: 'fastapi'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'

  # PostgreSQL exporter
  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']

  # Redis exporter
  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']

  # Node exporter (system metrics)
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']

  # Prometheus itself
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
```

---

## Alert Rules

### alerts/database.yml

```yaml
groups:
  - name: database_alerts
    interval: 30s
    rules:
      # High database connection usage
      - alert: DatabaseConnectionPoolHigh
        expr: |
          (pg_stat_database_numbackends / pg_settings_max_connections) > 0.8
        for: 5m
        labels:
          severity: warning
          component: database
        annotations:
          summary: "Database connection pool usage is high"
          description: "Connection pool is at {{ $value | humanizePercentage }} capacity"

      # Slow queries detected
      - alert: SlowQueriesDetected
        expr: |
          rate(pg_slow_queries_total[5m]) > 0.1
        for: 10m
        labels:
          severity: warning
          component: database
        annotations:
          summary: "Slow queries detected"
          description: "{{ $value | humanize }} slow queries per second in last 5 minutes"

      # Database replication lag (if using replicas)
      - alert: DatabaseReplicationLag
        expr: |
          pg_replication_lag_seconds > 60
        for: 5m
        labels:
          severity: critical
          component: database
        annotations:
          summary: "Database replication lag is high"
          description: "Replication lag is {{ $value }} seconds"

      # Partition archival needed
      - alert: PartitionArchivalNeeded
        expr: |
          pg_partition_oldest_age_days{table="api_logs"} > 100
        for: 1h
        labels:
          severity: info
          component: database
        annotations:
          summary: "Old partitions need archival"
          description: "Oldest api_logs partition is {{ $value }} days old"

      # Index not being used
      - alert: UnusedIndexDetected
        expr: |
          pg_stat_user_indexes_idx_scan == 0 and
          time() - pg_stat_user_indexes_last_analyzed > 604800  # 7 days
        for: 24h
        labels:
          severity: info
          component: database
        annotations:
          summary: "Unused index detected"
          description: "Index {{ $labels.indexname }} has not been used in 7+ days"
```

### alerts/application.yml

```yaml
groups:
  - name: application_alerts
    interval: 15s
    rules:
      # High error rate
      - alert: HighErrorRate
        expr: |
          (
            rate(http_requests_total{status=~"5.."}[5m]) /
            rate(http_requests_total[5m])
          ) > 0.05
        for: 5m
        labels:
          severity: critical
          component: api
        annotations:
          summary: "High API error rate"
          description: "Error rate is {{ $value | humanizePercentage }} (threshold: 5%)"

      # High latency
      - alert: HighAPILatency
        expr: |
          histogram_quantile(0.99,
            rate(http_request_duration_seconds_bucket[5m])
          ) > 2
        for: 10m
        labels:
          severity: warning
          component: api
        annotations:
          summary: "High API latency detected"
          description: "p99 latency is {{ $value }}s (threshold: 2s)"

      # Application down
      - alert: ApplicationDown
        expr: |
          up{job="fastapi"} == 0
        for: 1m
        labels:
          severity: critical
          component: api
        annotations:
          summary: "Application is down"
          description: "FastAPI application is not responding"

      # High CPU usage
      - alert: HighCPUUsage
        expr: |
          process_cpu_usage_percent > 80
        for: 10m
        labels:
          severity: warning
          component: system
        annotations:
          summary: "High CPU usage"
          description: "CPU usage is {{ $value }}%"

      # Memory usage high
      - alert: HighMemoryUsage
        expr: |
          (
            process_memory_usage_bytes /
            process_memory_limit_bytes
          ) > 0.85
        for: 5m
        labels:
          severity: warning
          component: system
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value | humanizePercentage }}"
```

### alerts/redis.yml

```yaml
groups:
  - name: redis_alerts
    interval: 30s
    rules:
      # Low cache hit rate
      - alert: LowCacheHitRate
        expr: |
          (
            rate(redis_keyspace_hits_total[5m]) /
            (rate(redis_keyspace_hits_total[5m]) + rate(redis_keyspace_misses_total[5m]))
          ) < 0.5
        for: 15m
        labels:
          severity: warning
          component: cache
        annotations:
          summary: "Low Redis cache hit rate"
          description: "Cache hit rate is {{ $value | humanizePercentage }} (threshold: 50%)"

      # High memory usage
      - alert: RedisMemoryHigh
        expr: |
          (redis_memory_used_bytes / redis_memory_max_bytes) > 0.85
        for: 5m
        labels:
          severity: warning
          component: cache
        annotations:
          summary: "Redis memory usage is high"
          description: "Memory usage is {{ $value | humanizePercentage }}"

      # Redis down
      - alert: RedisDown
        expr: |
          up{job="redis"} == 0
        for: 1m
        labels:
          severity: critical
          component: cache
        annotations:
          summary: "Redis is down"
          description: "Redis server is not responding"

      # Too many connections
      - alert: RedisHighConnectionCount
        expr: |
          redis_connected_clients > 100
        for: 10m
        labels:
          severity: warning
          component: cache
        annotations:
          summary: "High Redis connection count"
          description: "{{ $value }} clients connected (investigate connection leaks)"
```

### alerts/business.yml

```yaml
groups:
  - name: business_alerts
    interval: 5m
    rules:
      # Many tenants hitting limits
      - alert: MultipleTenantsHittingLimits
        expr: |
          count(
            usage_api_calls_current / usage_api_calls_limit > 0.9
          ) > 10
        for: 30m
        labels:
          severity: info
          component: business
        annotations:
          summary: "Multiple tenants near API limits"
          description: "{{ $value }} tenants are at >90% of their API quota"

      # Low signup rate (potential issue)
      - alert: LowSignupRate
        expr: |
          increase(tenant_created_total[24h]) < 1
        for: 24h
        labels:
          severity: info
          component: business
        annotations:
          summary: "Low tenant signup rate"
          description: "Only {{ $value }} signups in last 24 hours"

      # High churn rate
      - alert: HighChurnRate
        expr: |
          (
            rate(subscription_cancelled_total[30d]) /
            count(subscription_active)
          ) > 0.1
        for: 1h
        labels:
          severity: warning
          component: business
        annotations:
          summary: "High subscription churn rate"
          description: "Churn rate is {{ $value | humanizePercentage }} (threshold: 10%)"
```

---

## Grafana Dashboards

### Main Dashboard (Overview)

See: `monitoring/grafana/dashboards/main_dashboard.json`

**Panels:**
1. **System Health** (top row)
   - API Status (up/down)
   - Database Status
   - Redis Status
   - Total Requests/sec

2. **Performance** (second row)
   - API Latency (p50, p95, p99)
   - Database Query Time
   - Cache Hit Rate
   - Error Rate

3. **Resources** (third row)
   - CPU Usage
   - Memory Usage
   - Disk Usage
   - Database Connections

4. **Business Metrics** (fourth row)
   - Active Tenants
   - API Calls (24h)
   - Active Subscriptions
   - MRR

### Database Dashboard

**Panels:**
1. Query Performance
   - Slow queries (> 1s)
   - Queries per second
   - Query duration histogram

2. Connections
   - Active connections
   - Idle connections
   - Connection pool utilization

3. Tables
   - Table sizes
   - Row counts
   - Sequential scans (anti-pattern)

4. Indexes
   - Index usage stats
   - Unused indexes
   - Index sizes

5. Partitions
   - Active partitions by table
   - Partition sizes
   - Oldest partition age

### Redis Dashboard

**Panels:**
1. Cache Performance
   - Hit rate percentage
   - Hits/misses per second
   - Operations per second

2. Memory
   - Used memory
   - Peak memory
   - Evicted keys

3. Connections
   - Connected clients
   - Blocked clients
   - Commands per second

4. Keys
   - Total keys
   - Keys by type
   - Keys with TTL

---

## Implementation Steps

### 1. Install Exporters

```bash
# PostgreSQL exporter
docker run -d \
  --name postgres_exporter \
  -p 9187:9187 \
  -e DATA_SOURCE_NAME="postgresql://postgres:password@localhost:5432/catalytic_saas?sslmode=disable" \
  prometheuscommunity/postgres-exporter

# Redis exporter
docker run -d \
  --name redis_exporter \
  -p 9121:9121 \
  oliver006/redis_exporter \
  --redis.addr redis://localhost:6379

# Node exporter (system metrics)
docker run -d \
  --name node_exporter \
  -p 9100:9100 \
  prom/node-exporter
```

### 2. Add Prometheus Metrics to FastAPI

```python
# In your FastAPI app
from prometheus_client import Counter, Histogram, Gauge, generate_latest

# Define metrics
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

http_request_duration_seconds = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint'],
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)

# Middleware to track requests
@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time

    http_requests_total.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()

    http_request_duration_seconds.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)

    return response

# Metrics endpoint
@app.get("/metrics")
async def metrics():
    return Response(
        content=generate_latest(),
        media_type="text/plain"
    )
```

### 3. Deploy Prometheus

```bash
# Download Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.45.0/prometheus-2.45.0.linux-amd64.tar.gz

# Extract and configure
tar xvfz prometheus-*.tar.gz
cd prometheus-*

# Copy your prometheus.yml
cp ~/development/saas/monitoring/prometheus.yml .

# Run Prometheus
./prometheus --config.file=prometheus.yml
```

### 4. Deploy Grafana

```bash
# Using Docker
docker run -d \
  --name=grafana \
  -p 3000:3000 \
  -v grafana-storage:/var/lib/grafana \
  grafana/grafana-oss

# Access at http://localhost:3000
# Default credentials: admin/admin
```

### 5. Import Dashboards

1. Login to Grafana (http://localhost:3000)
2. Add Prometheus data source (http://localhost:9090)
3. Import dashboards from `monitoring/grafana/dashboards/*.json`
4. Configure alerts

---

## Monitoring Checklist

- [ ] Install Prometheus
- [ ] Install exporters (PostgreSQL, Redis, Node)
- [ ] Add /metrics endpoint to FastAPI
- [ ] Configure Prometheus scrape targets
- [ ] Set up alert rules
- [ ] Deploy Grafana
- [ ] Import dashboards
- [ ] Configure Alertmanager
- [ ] Set up notification channels (Slack/PagerDuty)
- [ ] Test alerts (trigger intentionally)
- [ ] Document runbooks for common alerts

---

## Runbooks

### Alert: HighErrorRate

**Severity:** Critical

**Possible Causes:**
1. Database connection failures
2. Redis unavailable
3. Application bug (recent deployment)
4. External API dependency failure

**Investigation Steps:**
1. Check application logs: `tail -f /var/log/catalytic/app.log`
2. Check error distribution by endpoint: Grafana → API Dashboard
3. Test database connection: `psql -U catalytic -d catalytic_saas -c "SELECT 1"`
4. Test Redis: `redis-cli ping`
5. Check recent deployments: `git log --oneline -5`

**Resolution:**
- If database issue: Restart PostgreSQL, check connections
- If Redis issue: Restart Redis, check memory
- If application bug: Rollback deployment
- If external API: Implement circuit breaker

---

## Next Steps

1. Review and approve monitoring strategy
2. Deploy Prometheus and exporters
3. Import Grafana dashboards
4. Set up alert notifications
5. Test alert firing and resolution
6. Create runbooks for common scenarios

**Files to Create:**
- `monitoring/prometheus.yml` - Prometheus configuration
- `monitoring/alerts/*.yml` - Alert rule files
- `monitoring/grafana/dashboards/*.json` - Grafana dashboards
- `monitoring/install.sh` - Automated setup script