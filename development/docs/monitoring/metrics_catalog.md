# Metrics Catalog

## Overview

This document catalogs all metrics exposed by the Catalytic SaaS platform, their meaning, and how to use them.

## Metric Naming Convention

Metrics follow Prometheus naming conventions:
- **Counters**: `*_total` suffix (always increasing)
- **Gauges**: Current value (can go up or down)
- **Histograms**: `*_bucket`, `*_sum`, `*_count` suffixes
- **Summaries**: `*_sum`, `*_count` suffixes with quantiles

## Application Metrics

### HTTP Request Metrics

#### `http_requests_total`

**Type**: Counter
**Description**: Total number of HTTP requests processed
**Labels**:
- `method`: HTTP method (GET, POST, PUT, DELETE, etc.)
- `endpoint`: API endpoint path
- `status`: HTTP status code

**Usage**:
```promql
# Request rate per second
rate(http_requests_total[5m])

# Requests by status code
sum(rate(http_requests_total[5m])) by (status)

# Requests by endpoint
sum(rate(http_requests_total[5m])) by (endpoint)

# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])
```

**Alerts**: Used in error rate and traffic anomaly alerts

---

#### `http_request_duration_seconds`

**Type**: Histogram
**Description**: HTTP request latency in seconds
**Labels**:
- `method`: HTTP method
- `endpoint`: API endpoint

**Buckets**: 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0

**Usage**:
```promql
# p95 latency
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# p99 latency
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))

# Average latency
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])

# Latency by endpoint
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, endpoint))
```

**Alerts**: Used in high latency alerts

---

### Security Metrics

#### `encryption_errors_total`

**Type**: Counter
**Description**: Total number of encryption operation failures
**Labels**:
- `operation`: Type of encryption operation (encrypt_field, encrypt_column, etc.)

**Usage**:
```promql
# Encryption error rate
rate(encryption_errors_total[5m])

# Total encryption errors
sum(encryption_errors_total)
```

**Alerts**: `EncryptionFailureRate` - Critical security alert

---

#### `decryption_errors_total`

**Type**: Counter
**Description**: Total number of decryption operation failures
**Labels**:
- `operation`: Type of decryption operation

**Usage**:
```promql
# Decryption error rate
rate(decryption_errors_total[5m])
```

**Alerts**: `DecryptionFailureRate` - Critical security alert

---

#### `input_validation_failures_total`

**Type**: Counter
**Description**: Total number of input validation failures
**Labels**:
- `type`: Type of validation failure (sql_injection, xss, invalid_format, etc.)
- `field`: Field that failed validation

**Usage**:
```promql
# Validation failure rate
rate(input_validation_failures_total[5m])

# SQL injection attempts
rate(input_validation_failures_total{type="sql_injection"}[5m])

# Failures by field
sum(rate(input_validation_failures_total[5m])) by (field)
```

**Alerts**: `HighInputValidationFailures`, `SQLInjectionAttempt`

---

### Database Metrics

#### `database_query_duration_seconds`

**Type**: Histogram
**Description**: Database query execution time in seconds
**Labels**:
- `query_type`: Type of query (SELECT, INSERT, UPDATE, DELETE)
- `table`: Database table (if applicable)

**Usage**:
```promql
# Average query time
rate(database_query_duration_seconds_sum[5m]) / rate(database_query_duration_seconds_count[5m])

# Slow queries (>1s)
rate(database_query_duration_seconds_bucket{le="1.0"}[5m])
```

**Alerts**: `HighDatabaseQueryLatency`

---

#### `database_connections_active`

**Type**: Gauge
**Description**: Number of active database connections

**Usage**:
```promql
# Current active connections
database_connections_active

# Connection pool utilization
database_connections_active / database_connections_max * 100
```

**Alerts**: `DatabaseConnectionPoolExhaustion`

---

#### `database_connections_idle`

**Type**: Gauge
**Description**: Number of idle database connections in pool

---

#### `database_connections_max`

**Type**: Gauge
**Description**: Maximum number of database connections allowed

---

### Cache Metrics

#### `cache_requests_total`

**Type**: Counter
**Description**: Total number of cache requests
**Labels**:
- `cache_name`: Name of cache (redis, local, etc.)
- `operation`: Operation type (get, set, delete)

**Usage**:
```promql
# Cache request rate
rate(cache_requests_total[5m])
```

---

#### `cache_hits_total`

**Type**: Counter
**Description**: Total number of cache hits
**Labels**:
- `cache_name`: Name of cache

**Usage**:
```promql
# Cache hit rate
rate(cache_hits_total[5m]) / rate(cache_requests_total{operation="get"}[5m]) * 100
```

---

#### `cache_misses_total`

**Type**: Counter
**Description**: Total number of cache misses
**Labels**:
- `cache_name`: Name of cache

**Usage**:
```promql
# Cache miss rate
rate(cache_misses_total[5m]) / rate(cache_requests_total{operation="get"}[5m]) * 100
```

**Alerts**: `RedisCacheMissRateHigh`

---

## Redis Metrics (from redis_exporter)

### `redis_memory_used_bytes`

**Type**: Gauge
**Description**: Total memory used by Redis in bytes

**Usage**:
```promql
# Memory usage in MB
redis_memory_used_bytes / 1024 / 1024

# Memory utilization percentage
redis_memory_used_bytes / redis_memory_max_bytes * 100
```

**Alerts**: `RedisMemoryHigh`

---

### `redis_memory_max_bytes`

**Type**: Gauge
**Description**: Maximum memory allowed for Redis

---

### `redis_connected_clients`

**Type**: Gauge
**Description**: Number of connected Redis clients

---

### `redis_keyspace_hits_total`

**Type**: Counter
**Description**: Total number of successful Redis key lookups

---

### `redis_keyspace_misses_total`

**Type**: Counter
**Description**: Total number of failed Redis key lookups

**Usage**:
```promql
# Redis hit rate
rate(redis_keyspace_hits_total[5m]) / (rate(redis_keyspace_hits_total[5m]) + rate(redis_keyspace_misses_total[5m])) * 100
```

---

## PostgreSQL Metrics (from postgres_exporter)

### `pg_up`

**Type**: Gauge
**Description**: PostgreSQL server status (1 = up, 0 = down)

---

### `pg_stat_database_numbackends`

**Type**: Gauge
**Description**: Number of backends (connections) to the database
**Labels**:
- `datname`: Database name

---

### `pg_stat_database_xact_commit`

**Type**: Counter
**Description**: Number of transactions committed

---

### `pg_stat_database_xact_rollback`

**Type**: Counter
**Description**: Number of transactions rolled back

**Usage**:
```promql
# Rollback rate (should be low)
rate(pg_stat_database_xact_rollback[5m]) / rate(pg_stat_database_xact_commit[5m]) * 100
```

---

## System Metrics (from node_exporter)

### `node_cpu_seconds_total`

**Type**: Counter
**Description**: CPU time spent in different modes
**Labels**:
- `mode`: CPU mode (idle, user, system, iowait, etc.)
- `cpu`: CPU core number

**Usage**:
```promql
# CPU usage percentage
100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Per-core CPU usage
100 - (rate(node_cpu_seconds_total{mode="idle"}[5m]) * 100)
```

**Alerts**: `HighCPUUsage`

---

### `node_memory_MemTotal_bytes`

**Type**: Gauge
**Description**: Total system memory in bytes

---

### `node_memory_MemAvailable_bytes`

**Type**: Gauge
**Description**: Available system memory in bytes

**Usage**:
```promql
# Memory usage percentage
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Available memory in GB
node_memory_MemAvailable_bytes / 1024 / 1024 / 1024
```

**Alerts**: `HighMemoryUsage`

---

### `node_filesystem_size_bytes`

**Type**: Gauge
**Description**: Filesystem size in bytes
**Labels**:
- `mountpoint`: Filesystem mount point

---

### `node_filesystem_avail_bytes`

**Type**: Gauge
**Description**: Filesystem available space in bytes

**Usage**:
```promql
# Disk usage percentage
(1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes)) * 100
```

**Alerts**: `DiskSpaceLow`

---

### `node_network_receive_bytes_total`

**Type**: Counter
**Description**: Network bytes received
**Labels**:
- `device`: Network interface

---

### `node_network_transmit_bytes_total`

**Type**: Counter
**Description**: Network bytes transmitted

**Usage**:
```promql
# Network receive rate in MB/s
rate(node_network_receive_bytes_total[5m]) / 1024 / 1024

# Network transmit rate in MB/s
rate(node_network_transmit_bytes_total[5m]) / 1024 / 1024
```

---

## Recording Rules

### `security:failed_logins:rate5m`

**Type**: Recording Rule
**Expression**: `rate(http_requests_total{endpoint="/auth/login",status="401"}[5m])`
**Description**: Pre-computed failed login rate for compliance reporting

---

### `security:unauthorized_access:rate5m`

**Type**: Recording Rule
**Expression**: `rate(http_requests_total{status="403"}[5m])`
**Description**: Pre-computed unauthorized access rate

---

### `security:rate_limited:rate5m`

**Type**: Recording Rule
**Expression**: `rate(http_requests_total{status="429"}[5m])`
**Description**: Pre-computed rate limiting activity

---

### `api:request_rate:avg1h`

**Type**: Recording Rule
**Expression**: `avg_over_time(rate(http_requests_total[5m])[1h:5m])`
**Description**: 1-hour average request rate baseline

---

### `api:latency:p95`

**Type**: Recording Rule
**Expression**: `histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))`
**Description**: Pre-computed p95 latency

---

### `api:latency:p99`

**Type**: Recording Rule
**Expression**: `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))`
**Description**: Pre-computed p99 latency

---

## Custom Application Metrics

### Adding New Metrics

Example using Prometheus Python client:

```python
from prometheus_client import Counter, Histogram, Gauge

# Counter for events
login_attempts = Counter(
    'login_attempts_total',
    'Total login attempts',
    ['status', 'method']
)

# Usage
login_attempts.labels(status='success', method='password').inc()

# Histogram for timings
request_duration = Histogram(
    'request_processing_seconds',
    'Time spent processing request',
    ['endpoint']
)

# Usage
with request_duration.labels(endpoint='/api/users').time():
    process_request()

# Gauge for current values
active_sessions = Gauge(
    'active_sessions',
    'Number of active user sessions'
)

# Usage
active_sessions.set(len(session_store))
```

## Best Practices

### Metric Design

1. **Use counters for cumulative values** (requests, errors)
2. **Use gauges for instantaneous values** (connections, memory)
3. **Use histograms for distributions** (latency, sizes)
4. **Keep cardinality low**: Avoid high-cardinality labels (user IDs, IPs)
5. **Use consistent naming**: Follow Prometheus conventions

### Labels

**Good labels**:
- `method`: Limited values (GET, POST, etc.)
- `status`: Limited values (200, 404, 500)
- `endpoint`: Templated paths (/api/users/:id, not /api/users/123)

**Bad labels**:
- User ID (unbounded cardinality)
- IP address (unbounded cardinality)
- Timestamp (unbounded cardinality)

### Querying

1. **Use rate() for counters**: `rate(metric_total[5m])`
2. **Use increase() for count over time**: `increase(metric_total[1h])`
3. **Use irate() for volatile metrics**: `irate(metric_total[5m])`
4. **Aggregate before rate**: `sum(rate(metric[5m])) by (label)`

## Changelog

- 2025-10-06: Initial metrics catalog creation
