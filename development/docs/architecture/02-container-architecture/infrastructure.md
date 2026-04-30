# Infrastructure Containers

**C4 Model Level 2: Supporting Infrastructure**

## Overview

This document covers the infrastructure containers that support the Catalytic Computing Platform: databases, caching, monitoring, and secrets management.

---

## Container Summary

| Container | Technology | Port | Purpose |
|-----------|-----------|------|---------|
| PostgreSQL | PostgreSQL 15 Alpine | 5432 | Primary database |
| Redis | Redis 7 Alpine | 6379 | Cache, sessions, rate limiting |
| Prometheus | Prometheus | 9090 | Metrics collection |
| Grafana | Grafana | 3000 | Metrics visualization |
| Vault | HashiCorp Vault | 8200 | Secrets management |
| Nginx | Nginx Alpine | 80/443 | Reverse proxy, load balancer |

---

## PostgreSQL

### Specifications

| Attribute | Value |
|-----------|-------|
| **Version** | 15 Alpine |
| **Port** | 5432 |
| **Storage** | 100 GB (production) |
| **Replication** | Streaming (async) |

### Key Features

1. **Row-Level Security (RLS)**
   - Database-enforced multi-tenancy
   - Policies based on `org_id` from JWT
   - Impossible to bypass at application layer

2. **Connection Pooling**
   - Dev: 20 connections
   - Staging: 60 connections
   - Production: 160 connections

3. **Optimized Indexes**
   - B-tree for equality queries
   - GiST for range queries
   - Partial indexes for hot data

### Configuration

```yaml
postgres:
  image: postgres:15-alpine
  environment:
    POSTGRES_DB: catalytic
    POSTGRES_USER: catalytic
    POSTGRES_PASSWORD_FILE: /run/secrets/db_password
  volumes:
    - postgres_data:/var/lib/postgresql/data
    - ./init.sql:/docker-entrypoint-initdb.d/init.sql
  deploy:
    resources:
      limits:
        cpus: '8'
        memory: 32G
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U catalytic"]
    interval: 10s
    timeout: 5s
    retries: 5
```

### RLS Example

```sql
-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their org's data
CREATE POLICY users_org_isolation ON users
  FOR ALL
  USING (org_id = current_setting('app.current_org_id')::uuid);

-- Set org context (done by application)
SET app.current_org_id = 'org-uuid-here';
```

### Backup Strategy

- **Daily Full Backup**: `pg_dump` at 2:00 AM UTC
- **Continuous WAL Archiving**: Every 5 minutes
- **Retention**: 90 days (active), 7 years (archive)
- **Recovery**: Point-in-time to any second

---

## Redis

### Specifications

| Attribute | Value |
|-----------|-------|
| **Version** | 7 Alpine |
| **Port** | 6379 |
| **Memory** | 8 GB (production) |
| **Persistence** | AOF + RDB |

### Use Cases

| Use Case | Database | TTL | Pattern |
|----------|----------|-----|---------|
| JWT Blacklist | 0 | Token expiry | `blacklist:{jti}` |
| Session Cache | 1 | 24 hours | `session:{user_id}` |
| Rate Limiting | 2 | 1 minute | `ratelimit:{ip}:{endpoint}` |
| Result Cache | 3 | 1 hour | `cache:{hash}` |
| Distributed Locks | 4 | 30 seconds | `lock:{resource}` |

### Configuration

```yaml
redis:
  image: redis:7-alpine
  command: >
    redis-server
    --appendonly yes
    --maxmemory 8gb
    --maxmemory-policy allkeys-lru
    --save 900 1
    --save 300 10
    --save 60 10000
  volumes:
    - redis_data:/data
  deploy:
    resources:
      limits:
        cpus: '4'
        memory: 10G
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 10s
    timeout: 5s
    retries: 5
```

### Rate Limiting (Lua Script)

```lua
-- Sliding window rate limiter
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)

if count < limit then
    redis.call('ZADD', key, now, now)
    redis.call('EXPIRE', key, window)
    return 1  -- Allowed
else
    return 0  -- Rate limited
end
```

---

## Prometheus

### Specifications

| Attribute | Value |
|-----------|-------|
| **Version** | Latest |
| **Port** | 9090 |
| **Retention** | 15 days |
| **Scrape Interval** | 30 seconds |

### Scrape Targets

```yaml
scrape_configs:
  - job_name: 'saas-api'
    static_configs:
      - targets: ['saas-api:8000']
    metrics_path: '/metrics'

  - job_name: 'catalytic-api'
    static_configs:
      - targets: ['catalytic-api:8080']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_request_duration_seconds` | Histogram | API latency |
| `http_requests_total` | Counter | Total requests |
| `db_connections_active` | Gauge | Active DB connections |
| `redis_keyspace_hits_total` | Counter | Cache hits |
| `catalytic_memory_efficiency_ratio` | Gauge | Lattice efficiency |

### Alert Rules

```yaml
groups:
  - name: critical
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.01
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: DatabaseDown
        expr: pg_up == 0
        for: 1m
        labels:
          severity: critical
```

### Configuration

```yaml
prometheus:
  image: prom/prometheus:latest
  ports:
    - "9090:9090"
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
    - ./alerts.yml:/etc/prometheus/alerts.yml
    - prometheus_data:/prometheus
  command:
    - '--config.file=/etc/prometheus/prometheus.yml'
    - '--storage.tsdb.retention.time=15d'
    - '--web.enable-lifecycle'
```

---

## Grafana

### Specifications

| Attribute | Value |
|-----------|-------|
| **Version** | Latest |
| **Port** | 3000 |
| **Data Sources** | Prometheus |

### Dashboards

1. **System Dashboard**
   - API latency (p50, p95, p99)
   - Error rate
   - Database connections
   - Redis cache hit rate
   - Container resource usage

2. **Business Dashboard**
   - User registrations
   - MRR/ARR
   - Churn rate
   - Trial conversions
   - Payment success rate

3. **GPU Dashboard** (Catalytic)
   - GPU utilization
   - VRAM usage
   - TFLOPS
   - Temperature

### Configuration

```yaml
grafana:
  image: grafana/grafana:latest
  ports:
    - "3000:3000"
  environment:
    GF_SECURITY_ADMIN_PASSWORD__FILE: /run/secrets/grafana_password
    GF_INSTALL_PLUGINS: grafana-clock-panel,grafana-piechart-panel
  volumes:
    - grafana_data:/var/lib/grafana
    - ./dashboards:/etc/grafana/provisioning/dashboards
    - ./datasources:/etc/grafana/provisioning/datasources
```

---

## HashiCorp Vault

### Specifications

| Attribute | Value |
|-----------|-------|
| **Version** | Latest |
| **Port** | 8200 |
| **Backend** | Raft (3-node cluster) |
| **Seal** | AWS KMS (auto-unseal) |

### Secrets Stored

| Path | Contents | Rotation |
|------|----------|----------|
| `secret/jwt` | JWT signing keys | Quarterly |
| `secret/database` | PostgreSQL credentials | Monthly |
| `secret/redis` | Redis password | Monthly |
| `secret/stripe` | Stripe API key | On-demand |
| `secret/sendgrid` | SendGrid API key | On-demand |

### Policies

```hcl
# SaaS API policy
path "secret/data/jwt/*" {
  capabilities = ["read"]
}

path "secret/data/database" {
  capabilities = ["read"]
}

path "secret/data/stripe" {
  capabilities = ["read"]
}

path "secret/data/sendgrid" {
  capabilities = ["read"]
}
```

### Configuration

```yaml
vault:
  image: hashicorp/vault:latest
  ports:
    - "8200:8200"
  environment:
    VAULT_ADDR: http://127.0.0.1:8200
    VAULT_API_ADDR: http://vault:8200
  volumes:
    - ./vault.hcl:/vault/config/vault.hcl
    - vault_data:/vault/data
  cap_add:
    - IPC_LOCK
  command: server
```

### AppRole Authentication

```python
# Application authentication
import hvac

client = hvac.Client(url='https://vault:8200')
client.auth.approle.login(
    role_id=os.environ['VAULT_ROLE_ID'],
    secret_id=os.environ['VAULT_SECRET_ID']
)

# Retrieve secrets
jwt_key = client.secrets.kv.read_secret_version(
    path='jwt/private_key'
)['data']['data']['key']
```

---

## Nginx

### Specifications

| Attribute | Value |
|-----------|-------|
| **Version** | Alpine |
| **Ports** | 80 (HTTP), 443 (HTTPS) |
| **TLS** | 1.3 |

### Responsibilities

1. **Reverse Proxy**: Route to backend services
2. **TLS Termination**: Handle HTTPS
3. **Rate Limiting**: Request throttling
4. **Load Balancing**: Distribute traffic

### Configuration

```nginx
upstream saas_api {
    server saas-api:8000;
    keepalive 32;
}

upstream catalytic_api {
    server catalytic-api:8080;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name api.catalytic.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.3;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    limit_req zone=api burst=200 nodelay;

    location /api/v1/ {
        proxy_pass http://saas_api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /compute/ {
        proxy_pass http://catalytic_api/;
        proxy_read_timeout 600s;  # Long-running GPU ops
    }

    location /health {
        return 200 'OK';
        add_header Content-Type text/plain;
    }
}
```

---

## Network Topology

```
Internet
    │
    ▼
┌──────────────────┐
│      Nginx       │ ← TLS termination, rate limiting
│   (80/443)       │
└────────┬─────────┘
         │
    ┌────┴────────────────────────┐
    │                             │
    ▼                             ▼
┌──────────┐              ┌──────────────┐
│ SaaS API │              │ Catalytic API│
│  (8000)  │              │    (8080)    │
└────┬─────┘              └──────┬───────┘
     │                           │
     │    ┌──────────────────────┤
     │    │                      │
     ▼    ▼                      ▼
┌──────────────┐          ┌──────────┐
│  PostgreSQL  │          │  Redis   │
│   (5432)     │          │  (6379)  │
└──────────────┘          └──────────┘
         │
         ▼
┌──────────────────────────────────────┐
│          Monitoring Network           │
├──────────────────────────────────────┤
│ Prometheus (9090) ← Grafana (3000)   │
└──────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│      Vault       │ ← Secrets management
│     (8200)       │
└──────────────────┘
```

---

## Resource Summary

### Development

| Container | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| PostgreSQL | 2 | 4 GB | 20 GB |
| Redis | 1 | 2 GB | 5 GB |
| Prometheus | 1 | 2 GB | 20 GB |
| Grafana | 0.5 | 1 GB | 5 GB |
| Vault | 0.5 | 512 MB | 1 GB |
| Nginx | 0.5 | 256 MB | - |
| **Total** | **5.5** | **9.8 GB** | **51 GB** |

### Production

| Container | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| PostgreSQL | 8 | 32 GB | 500 GB |
| Redis | 4 | 16 GB | 50 GB |
| Prometheus | 2 | 8 GB | 200 GB |
| Grafana | 1 | 2 GB | 10 GB |
| Vault (3x) | 2 | 4 GB | 10 GB |
| Nginx | 2 | 2 GB | - |
| **Total** | **19** | **64 GB** | **770 GB** |

---

## Related Documentation

- [Container Overview](container-overview.md)
- [Deployment Architecture](../06-deployment-architecture/)
- [Disaster Recovery](../05-cross-cutting-concerns/disaster-recovery.md)
- [Observability](../05-cross-cutting-concerns/observability.md)
- [Vault Integration](../08-integration-architecture/vault-integration.md)

---

**Last Updated**: November 2025
