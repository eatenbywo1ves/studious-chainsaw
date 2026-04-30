# 8. Cross-Cutting Concepts

## 8.1 Domain Model

```
┌───────────────────────────────────────────────────────────────────────┐
│                         Domain Model                                   │
│                                                                        │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────────────┐   │
│  │   Tenant    │──────│    User     │──────│   Subscription     │   │
│  │             │ 1  * │             │ 1  1 │                     │   │
│  │ - id        │      │ - id        │      │ - id                │   │
│  │ - name      │      │ - email     │      │ - stripe_id         │   │
│  │ - plan      │      │ - tenant_id │      │ - status            │   │
│  └─────────────┘      └──────┬──────┘      │ - current_period_end│   │
│                              │             └─────────────────────┘   │
│                              │ 1                                      │
│                              │                                        │
│                              │ *                                      │
│                       ┌──────▼──────┐      ┌─────────────────────┐   │
│                       │    Job      │──────│     Result          │   │
│                       │             │ 1  1 │                     │   │
│                       │ - id        │      │ - id                │   │
│                       │ - user_id   │      │ - job_id            │   │
│                       │ - status    │      │ - data (JSONB)      │   │
│                       │ - type      │      │ - created_at        │   │
│                       └─────────────┘      └─────────────────────┘   │
│                                                                        │
└───────────────────────────────────────────────────────────────────────┘
```

## 8.2 Security Concepts

### Authentication & Authorization

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Architecture                         │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Authentication                         │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │  │
│  │  │ JWT RS256  │  │  Bcrypt    │  │ Token Blacklist    │ │  │
│  │  │ (30min)    │  │ (cost=12)  │  │ (Redis)            │ │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Authorization                          │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │  │
│  │  │ PostgreSQL │  │   RBAC     │  │ Subscription Tiers │ │  │
│  │  │    RLS     │  │ (Roles)    │  │  (Feature Flags)   │ │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Data Protection                        │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │  │
│  │  │ TLS 1.3    │  │ AES-256    │  │ Vault Encryption   │ │  │
│  │  │ (Transit)  │  │ (At Rest)  │  │ (Secrets)          │ │  │
│  │  └────────────┘  └────────────┘  └────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### D3FEND Techniques Implemented

| ID | Technique | Implementation |
|----|-----------|---------------|
| D3-SPP | Strong Password Policy | 12+ chars, complexity, common list |
| D3-AL | Account Locking | 5 failures → 15min lockout |
| D3-ACA | Access Control Analysis | PostgreSQL RLS |
| D3-NTA | Network Traffic Analysis | Rate limiting |
| D3-CA | Certificate Analysis | TLS 1.3 |
| D3-EAL | Execution Allow Listing | Container capabilities |
| D3-FE | File Encryption | Vault, AES-256 |
| D3-SE | Session Expiration | JWT 30min TTL |
| D3-SBV | Service Binary Verification | Image signing |
| D3-SDM | Software Dependency Mgmt | Vulnerability scanning |
| D3-SDN | Software-Defined Networking | K8s network policies |
| D3-LA | Log Analysis | Structured logging |

## 8.3 Persistence Concepts

### Database Strategy

```
┌─────────────────────────────────────────────────────────────────┐
│                    Persistence Strategy                          │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    PostgreSQL                             │  │
│  │                                                           │  │
│  │  • Primary data store for all business entities          │  │
│  │  • Row-Level Security for multi-tenant isolation         │  │
│  │  • JSONB for semi-structured data (results, metadata)    │  │
│  │  • Indexes: B-tree (equality), GIN (JSONB), GiST (geo)  │  │
│  │  • Replication: Streaming replication to read replica    │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                       Redis                               │  │
│  │                                                           │  │
│  │  • DB 0: JWT blacklist (token hash → expiry)            │  │
│  │  • DB 1: Session cache (user_id → session data)         │  │
│  │  • DB 2: Rate limiting (key → ZSET of timestamps)       │  │
│  │  • DB 3: Result cache (job_id → serialized result)      │  │
│  │  • Persistence: AOF + RDB snapshots                      │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   File Storage                            │  │
│  │                                                           │  │
│  │  • Binary uploads: /storage/binaries/{tenant}/{id}       │  │
│  │  • Analysis results: /storage/results/{job_id}/          │  │
│  │  • ML models: /storage/models/{model_id}/                │  │
│  │  • Retention: 90 days for results, 30 days for uploads   │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## 8.4 User Interface Concepts

### API Design Principles

| Principle | Application |
|-----------|-------------|
| RESTful | Resource-oriented URLs |
| JSON:API | Consistent response format |
| HATEOAS | Links for discoverability |
| Versioning | URL path (`/api/v1/`) |
| Pagination | Cursor-based with `limit` |

### Error Response Format

```json
{
  "error": {
    "code": "AUTH_001",
    "message": "Invalid credentials",
    "details": {
      "field": "email",
      "reason": "not_found"
    }
  },
  "request_id": "req_abc123",
  "timestamp": "2024-10-15T10:30:00Z"
}
```

## 8.5 Operational Concepts

### Observability Stack

```
┌─────────────────────────────────────────────────────────────────┐
│                    Observability                                 │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │     Metrics      │  │     Logging      │  │   Tracing    │  │
│  │                  │  │                  │  │              │  │
│  │  Prometheus      │  │  Structured JSON │  │  OpenTelem   │  │
│  │  + Grafana       │  │  + Log Aggr      │  │  (future)    │  │
│  │                  │  │                  │  │              │  │
│  │  • Request rate  │  │  • Access logs   │  │  • Spans     │  │
│  │  • Latency P50   │  │  • Error logs    │  │  • Context   │  │
│  │  • Error rate    │  │  • Audit logs    │  │  • Deps      │  │
│  │  • GPU util      │  │  • Security logs │  │              │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Health Check Strategy

| Check Type | Endpoint | Frequency | Timeout |
|------------|----------|-----------|---------|
| Liveness | `/health` | 30s | 5s |
| Readiness | `/health` | 10s | 3s |
| Startup | `/health` | 5s | 60s |

### Backup Strategy

| Data | Frequency | Retention | Method |
|------|-----------|-----------|--------|
| PostgreSQL | Every 6 hours | 30 days | pg_dump + WAL |
| Redis | Every hour | 7 days | RDB snapshot |
| Binaries | On upload | 90 days | Object storage |

## 8.6 Development Concepts

### Code Quality Gates

| Gate | Tool | Threshold |
|------|------|-----------|
| Formatting | Black | Must pass |
| Linting | Ruff | 0 errors |
| Type checking | mypy | 0 errors |
| Test coverage | pytest-cov | 80% |
| Security scan | Bandit | 0 high |

### CI/CD Pipeline

```
┌────────┐   ┌────────┐   ┌────────┐   ┌────────┐   ┌─────────┐
│  Push  │──►│  Lint  │──►│  Test  │──►│ Build  │──►│ Deploy  │
└────────┘   └────────┘   └────────┘   └────────┘   └─────────┘
                │             │            │             │
                ▼             ▼            ▼             ▼
           Black, Ruff    pytest      Docker       Staging/Prod
           mypy          Coverage     Image         K8s Apply
           Bandit                     Push
```

---
**Last Updated**: 2024-10-15
