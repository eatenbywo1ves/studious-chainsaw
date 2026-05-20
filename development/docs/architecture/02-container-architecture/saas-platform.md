# SaaS Platform Container

**C4 Model Level 2: Container Detail**

## Overview

The SaaS Platform is the multi-tenant API backbone of the Catalytic Computing Platform, handling authentication, user management, subscription billing, and tenant isolation.

---

## Container Specifications

| Attribute | Value |
|-----------|-------|
| **Name** | SaaS API |
| **Technology** | FastAPI (Python 3.11+) |
| **Port** | 8000 |
| **Protocol** | HTTP/HTTPS (REST API) |
| **Replicas** | 4-20 (HPA auto-scaling) |
| **Image** | `catalytic/saas-api:latest` |

---

## Responsibilities

1. **Authentication & Authorization**
   - JWT RS256 token issuance and validation
   - Token blacklist management (Redis-backed)
   - Account lockout (5 failed attempts → 15-min lock)
   - Password policy enforcement (12+ chars, complexity)

2. **Multi-Tenant User Management**
   - Organization CRUD operations
   - User provisioning within organizations
   - Role-based access control (RBAC)
   - Row-Level Security (RLS) enforcement via org_id

3. **Subscription & Billing**
   - Stripe Checkout session creation
   - Subscription lifecycle management
   - Usage tracking and quota enforcement
   - Invoice and payment history

4. **API Gateway Functions**
   - Request validation (Pydantic models)
   - Rate limiting (per-user, per-IP)
   - CORS policy enforcement
   - OpenAPI documentation generation

---

## Key Dependencies

### Internal Dependencies

| Dependency | Purpose | Protocol |
|------------|---------|----------|
| PostgreSQL | Primary data store | TCP/5432 (SQL) |
| Redis | Cache, sessions, blacklist | TCP/6379 |
| Vault | JWT keys, API secrets | HTTPS/8200 |

### External Dependencies

| Dependency | Purpose | Protocol |
|------------|---------|----------|
| Stripe | Payment processing | HTTPS (REST) |
| SendGrid | Email delivery | HTTPS (REST) |

---

## API Endpoints Summary

### Authentication (`/auth/*`)
```
POST /auth/register     - User registration
POST /auth/login        - JWT token issuance
POST /auth/logout       - Token revocation (blacklist)
POST /auth/refresh      - Token refresh
POST /auth/reset-password - Password reset flow
```

### Users (`/users/*`)
```
GET  /users/me          - Current user profile
PUT  /users/me          - Update profile
GET  /users/{id}        - Get user (admin only)
GET  /users             - List users in org
```

### Organizations (`/orgs/*`)
```
GET  /orgs/me           - Current organization
PUT  /orgs/me           - Update organization
GET  /orgs/{id}/users   - List org members
```

### Subscriptions (`/subscriptions/*`)
```
GET  /subscriptions/current  - Current subscription
POST /subscriptions/checkout - Create Stripe checkout
POST /subscriptions/cancel   - Cancel subscription
GET  /subscriptions/invoices - Invoice history
```

### Health (`/health/*`)
```
GET  /health            - Basic health check
GET  /health/ready      - Readiness probe (DB + Redis)
GET  /health/live       - Liveness probe
```

---

## Configuration

### Environment Variables

```bash
# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/catalytic
DATABASE_POOL_SIZE=20  # dev: 20, staging: 60, prod: 160

# Redis
REDIS_URL=redis://redis:6379/0
REDIS_POOL_SIZE=20

# Authentication
JWT_PRIVATE_KEY_PATH=/secrets/jwt_private.pem
JWT_PUBLIC_KEY_PATH=/secrets/jwt_public.pem
JWT_ALGORITHM=RS256
JWT_EXPIRY_MINUTES=30
JWT_REFRESH_EXPIRY_DAYS=7

# Vault
VAULT_ADDR=https://vault:8200
VAULT_ROLE_ID=<role-id>
VAULT_SECRET_ID=<secret-id>

# Stripe
STRIPE_API_KEY=<from-vault>
STRIPE_WEBHOOK_SECRET=<from-vault>

# SendGrid
SENDGRID_API_KEY=<from-vault>
SENDGRID_FROM_EMAIL=noreply@catalytic.com

# Rate Limiting
RATE_LIMIT_PER_MINUTE=100
RATE_LIMIT_PER_HOUR=1000
```

### Docker Compose Configuration

```yaml
saas_api:
  image: catalytic/saas-api:latest
  ports:
    - "8000:8000"
  environment:
    - DATABASE_URL=postgresql://...
    - REDIS_URL=redis://redis:6379/0
  depends_on:
    postgres:
      condition: service_healthy
    redis:
      condition: service_healthy
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
    interval: 30s
    timeout: 10s
    retries: 3
  deploy:
    resources:
      limits:
        cpus: '4'
        memory: 8G
      reservations:
        cpus: '2'
        memory: 4G
```

---

## Security Controls

### Authentication
- ✅ JWT RS256 (asymmetric signing)
- ✅ Token blacklist on logout (Redis)
- ✅ Account lockout after 5 failures
- ✅ Password hashing (bcrypt, 12 rounds)
- ✅ CSRF protection on state-changing operations

### Multi-Tenancy
- ✅ PostgreSQL Row-Level Security (RLS)
- ✅ org_id injected from JWT claims
- ✅ Database-enforced isolation (cannot bypass)
- ✅ Tenant context in all queries

### API Security
- ✅ Rate limiting (sliding window)
- ✅ Input validation (Pydantic)
- ✅ CORS whitelist
- ✅ HTTPS only (TLS 1.3)
- ✅ Security headers (HSTS, X-Frame-Options, etc.)

---

## Performance Characteristics

### Latency Targets

| Endpoint | p50 | p95 | p99 |
|----------|-----|-----|-----|
| `/auth/login` | 50ms | 150ms | 300ms |
| `/users/me` | 20ms | 50ms | 100ms |
| `/subscriptions/*` | 100ms | 300ms | 500ms |
| Overall API | <100ms | <500ms | <1s |

### Throughput

- **Sustained**: 1,000 req/s per replica
- **Peak**: 2,500 req/s per replica
- **With 4 replicas**: 4,000-10,000 req/s

### Load Testing Results

| Concurrent Users | Success Rate | Avg Latency |
|------------------|--------------|-------------|
| 100 | 100% | 45ms |
| 1,000 | 100% | 78ms |
| 10,000 | 99.29% | 245ms |

---

## Scaling Strategy

### Horizontal Scaling (Primary)
```yaml
# Kubernetes HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: saas-api-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: saas-api
  minReplicas: 4
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
```

### Connection Pooling
- **PostgreSQL**: 20 (dev) → 60 (staging) → 160 (production)
- **Redis**: 20 (dev) → 60 (staging) → 160 (production)

### Caching Strategy
- JWT public key: Cached in memory (5-min TTL)
- User profiles: Redis cache (15-min TTL)
- Subscription data: Redis cache (5-min TTL)
- Rate limit counters: Redis (sliding window)

---

## Monitoring

### Prometheus Metrics

```python
# Custom metrics exposed at /metrics
http_request_duration_seconds  # Histogram: request latency
http_requests_total            # Counter: total requests by endpoint
auth_login_attempts_total      # Counter: login attempts
auth_login_failures_total      # Counter: failed logins
jwt_tokens_issued_total        # Counter: tokens issued
jwt_tokens_revoked_total       # Counter: tokens revoked (logout)
db_connections_active          # Gauge: active DB connections
redis_connections_active       # Gauge: active Redis connections
```

### Health Endpoints

```bash
# Basic health (always returns 200 if process running)
GET /health
{"status": "healthy"}

# Readiness (checks DB and Redis)
GET /health/ready
{"status": "ready", "postgres": "connected", "redis": "connected"}

# Liveness (for K8s liveness probe)
GET /health/live
{"status": "alive", "uptime_seconds": 3600}
```

### Alerting Rules

```yaml
# Critical: API error rate > 1%
- alert: SaaSAPIHighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.01
  for: 2m
  labels:
    severity: critical

# Warning: Latency > 500ms p95
- alert: SaaSAPIHighLatency
  expr: histogram_quantile(0.95, http_request_duration_seconds) > 0.5
  for: 5m
  labels:
    severity: warning
```

---

## Disaster Recovery

### Backup
- Database: Part of PostgreSQL backup (daily full, continuous WAL)
- No stateful data in container (stateless design)

### Failover
- K8s automatically restarts failed pods
- Load balancer removes unhealthy pods
- New pods ready in <30 seconds

### Recovery Time
- **RTO**: 2 minutes (new pod startup)
- **RPO**: 0 (stateless, all state in DB/Redis)

---

## Related Documentation

- [Container Overview](container-overview.md)
- [Authentication Flow](../03-component-architecture/authentication-flow.puml)
- [PostgreSQL RLS ADR](../10-adrs/002-postgresql-rls-multitenancy.md)
- [JWT RS256 ADR](../10-adrs/003-jwt-rs256-asymmetric.md)
- [Stripe Integration](../08-integration-architecture/stripe-integration.md)

---

**Last Updated**: November 2025
