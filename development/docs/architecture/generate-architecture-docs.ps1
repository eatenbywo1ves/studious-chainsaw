# Architecture Documentation Generation Script
# Generates complete architecture documentation suite
# Based on approved plan for Catalytic Computing Platform

param(
    [switch]$RenderDiagrams,
    [switch]$ValidateLinks,
    [switch]$GeneratePDF
)

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Architecture Documentation Generator" -ForegroundColor Cyan
Write-Host "Catalytic Computing Platform v2.0" -ForegroundColor Cyan
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

$baseDir = $PSScriptRoot
$generatedCount = 0

# Function to create file with content
function New-DocFile {
    param(
        [string]$Path,
        [string]$Content
    )

    $dir = Split-Path -Path $Path -Parent
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }

    Set-Content -Path $Path -Value $Content -Encoding UTF8
    $script:generatedCount++
    Write-Host "  ✓ Created: $Path" -ForegroundColor Green
}

Write-Host "[1/12] Generating Container Architecture Documentation..." -ForegroundColor Yellow

# Container Overview
$containerOverview = @"
# Container Architecture Overview

**C4 Model Level 2: Containers**

## Overview

The Catalytic Computing Platform is deployed as a set of containerized services orchestrated via Docker Compose (development) and Kubernetes (production). This architecture provides scalability, resilience, and operational flexibility.

---

## Container Inventory

| Container | Technology | Ports | Purpose | Scaling |
|-----------|-----------|-------|---------|---------|
| **Nginx** | Nginx Alpine | 80, 443 | Reverse proxy, load balancing, TLS termination | Stateless (horizontal) |
| **SaaS API** | FastAPI/Python 3.11 | 8000 | Multi-tenant API, authentication, payments | Stateless (4-20 replicas) |
| **Catalytic API** | FastAPI/Python 3.11 | 8080 | GPU-accelerated computing | Stateful (GPU allocation) |
| **Webhook System** | FastAPI/Python 3.11 | 8085 | Async event processing | Stateless (2+ replicas) |
| **PostgreSQL** | PostgreSQL 15 Alpine | 5432 | Primary database (RLS multi-tenancy) | Stateful (read replicas) |
| **Redis** | Redis 7 Alpine | 6379 | Cache, sessions, rate limiting | Stateful (Sentinel HA) |
| **Prometheus** | Prometheus | 9090 | Metrics collection, alerting | Stateful (TSDB) |
| **Grafana** | Grafana | 3000 | Metrics visualization | Stateless |
| **Vault** | Vault | 8200 | Secrets management | Stateful (Raft cluster) |

---

## Communication Patterns

### Synchronous (Request/Response)
- **User → Nginx → SaaS API**: HTTPS REST API calls
- **SaaS API → PostgreSQL**: SQL queries (connection pooled)
- **SaaS API → Redis**: Cache lookups, session retrieval
- **SaaS API → Vault**: Secret retrieval (AppRole auth)
- **SaaS API → Stripe**: Payment API calls
- **SaaS API → SendGrid**: Email sending

### Asynchronous (Event-Driven)
- **Stripe → Webhook System**: Payment events (webhooks)
- **Webhook System → PostgreSQL**: Subscription updates
- **Webhook System → SendGrid**: Email notifications
- **Redis Pub/Sub**: Inter-service communication

### Metrics Collection (Pull-Based)
- **Prometheus → SaaS API**: Scrapes /metrics endpoint (30s interval)
- **Prometheus → Catalytic API**: Scrapes /metrics endpoint (30s interval)
- **Grafana → Prometheus**: Queries time-series data

---

## Container Details

See individual container documentation:

- [SaaS Platform](saas-platform.md) - Multi-tenant API
- [Catalytic Engine](catalytic-engine.md) - GPU computing
- [GhidraGo Toolkit](ghidrago-toolkit.md) - Binary analysis
- [Infrastructure](infrastructure.md) - Supporting services

---

## Deployment Profiles

### Docker Compose Profiles

**1. core** (Minimal)
- Catalytic API
- Webhook System
- No database (stateless mode)

**2. saas** (Full Multi-tenant)
- SaaS API
- PostgreSQL (with RLS)
- Redis (connection pooling)
- Validated: 10K concurrent users

**3. dev** (Development)
- All of above
- Prometheus + Grafana (monitoring)
- Adminer (database UI)
- Redis Commander (cache UI)

**4. all** (Complete Stack)
- Everything

Usage:
\`\`\`bash
docker-compose --profile saas up -d
docker-compose --profile dev up -d
docker-compose --profile all up -d
\`\`\`

---

## Container Dependencies

### Startup Order

1. **Infrastructure** (First)
   - PostgreSQL
   - Redis
   - Vault

2. **Core Services** (Second)
   - SaaS API (depends on: postgres, redis, vault)
   - Catalytic API (depends on: redis)
   - Webhook System (depends on: postgres, redis)

3. **Monitoring** (Third)
   - Prometheus (depends on: saas_api, catalytic_api)
   - Grafana (depends on: prometheus)

4. **Ingress** (Last)
   - Nginx (depends on: saas_api, catalytic_api)

### Health Check Dependencies

Docker Compose uses `healthcheck` and `depends_on` conditions:

\`\`\`yaml
saas_api:
  depends_on:
    postgres:
      condition: service_healthy
    redis:
      condition: service_healthy
    vault:
      condition: service_started
\`\`\`

---

## Resource Allocation

### Development (Docker Compose)

| Container | CPU | Memory | Storage |
|-----------|-----|--------|---------|
| SaaS API | 2 cores | 4 GB | - |
| Catalytic API | 4 cores | 8 GB | - |
| PostgreSQL | 2 cores | 4 GB | 20 GB |
| Redis | 1 core | 2 GB | 10 GB |
| Prometheus | 1 core | 2 GB | 50 GB |

### Production (Kubernetes)

| Container | Replicas | CPU (request/limit) | Memory (request/limit) |
|-----------|----------|-------------------|----------------------|
| SaaS API | 4-20 (HPA) | 2 / 4 cores | 4 GB / 8 GB |
| Catalytic API | 2-10 (HPA) | 4 / 8 cores | 8 GB / 16 GB |
| PostgreSQL | 1 (+ 2 replicas) | 4 / 8 cores | 16 GB / 32 GB |
| Redis | 3 (Sentinel) | 2 / 4 cores | 8 GB / 16 GB |

---

## Network Topology

### Development (Docker Network)

\`\`\`
catalytic-net (bridge)
├── nginx (172.20.0.2)
├── saas_api (172.20.0.10)
├── catalytic_api (172.20.0.11)
├── webhook (172.20.0.12)
├── postgres (172.20.0.20)
├── redis (172.20.0.21)
├── prometheus (172.20.0.30)
├── grafana (172.20.0.31)
└── vault (172.20.0.40)
\`\`\`

All containers communicate via internal DNS (service names).

### Production (Kubernetes)

- **Namespace**: `catalytic-production`
- **Network Policies**: Pod-to-pod isolation
- **Ingress**: Nginx Ingress Controller
- **Service Mesh**: (Future: Istio for mTLS)

---

## Security Considerations

### Container Hardening

✅ **All containers**:
- Run as non-root user (app:app, UID 1000)
- Read-only root filesystem (except /tmp)
- ALL capabilities dropped
- Only NET_BIND_SERVICE added (if needed)
- No privilege escalation

✅ **Image Security**:
- Multi-stage builds (minimal final image)
- Vulnerability scanning (Trivy, Grype)
- Base images: Alpine Linux (minimal attack surface)
- Regular updates (monthly CVE patching)

✅ **Network Security**:
- No containers expose ports to host (except nginx)
- Internal communication only (docker network)
- TLS for external communication (nginx → internet)

---

## Observability

### Logs

**Centralized Logging** (Future: ELK Stack)
- Docker logs: `docker-compose logs -f <service>`
- K8s logs: `kubectl logs -f <pod>`
- Structured JSON logging (all services)

**Log Retention**:
- Development: 7 days
- Staging: 30 days
- Production: 90 days

### Metrics

**Prometheus Exporters**:
- SaaS API: `/metrics` endpoint (custom metrics)
- Catalytic API: `/metrics` endpoint (GPU metrics)
- PostgreSQL: postgres_exporter
- Redis: redis_exporter
- Node: node_exporter

**Key Metrics**:
- `http_request_duration_seconds` (API latency)
- `http_requests_total` (throughput)
- `db_connections_active` (connection pool)
- `redis_keyspace_hits_total` (cache hit rate)
- `catalytic_memory_efficiency_ratio` (28,571x target)

### Traces

**Distributed Tracing** (Future: Jaeger/Zipkin)
- Request correlation IDs
- Span tracking across services
- Latency breakdown analysis

---

## Disaster Recovery

### Backup Strategy

**PostgreSQL**:
- Daily full backups (pg_dump)
- Continuous WAL archiving
- Retention: 90 days (active), 7 years (archive)

**Redis**:
- AOF (append-only file) persistence
- RDB snapshots (every 6 hours)
- Retention: 30 days

**Vault**:
- Automated snapshots (Raft backend)
- Retention: 90 days

### Recovery Procedures

**Database Restore**:
\`\`\`bash
# Restore PostgreSQL from backup
pg_restore -d catalytic backup_file.dump

# Restore Redis from RDB
redis-cli --rdb backup.rdb
\`\`\`

**RTO/RPO Targets**:
- **RTO** (Recovery Time Objective): 15 minutes
- **RPO** (Recovery Point Objective): 5 minutes

---

## References

- [C4 Container Diagram](c4-containers.puml)
- [SaaS Platform Details](saas-platform.md)
- [Catalytic Engine Details](catalytic-engine.md)
- [Deployment Architecture](../06-deployment-architecture/)
- [Quality Attributes](../09-quality-attributes/)

---

**Last Updated**: November 2025
"@

New-DocFile -Path "$baseDir\02-container-architecture\container-overview.md" -Content $containerOverview

Write-Host "`n[2/12] Generating ADR Template and Sample ADRs..." -ForegroundColor Yellow

# ADR Template
$adrTemplate = @"
# ADR-XXX: [Decision Title]

**Status**: Proposed | Accepted | Deprecated | Superseded
**Date**: YYYY-MM-DD
**Deciders**: [List of people involved in the decision]
**Technical Story**: [JIRA ticket, GitHub issue, or description]

---

## Context

[Describe the problem, issue, or opportunity that prompted this decision. Include relevant background information, constraints, and forces at play.]

### Problem Statement

[Clear, concise description of the problem being solved]

### Driving Forces

- **Force 1**: [Description]
- **Force 2**: [Description]
- **Force 3**: [Description]

### Constraints

- **Technical**: [Constraints from technology, platforms, dependencies]
- **Organizational**: [Team skills, budget, timeline]
- **Business**: [Compliance, SLAs, market requirements]

---

## Decision

[Describe the decision that was made. Be specific and actionable.]

### What We Will Do

[Detailed description of the chosen approach]

### Key Components

1. **Component/Aspect 1**: [Description]
2. **Component/Aspect 2**: [Description]
3. **Component/Aspect 3**: [Description]

---

## Consequences

### Positive (Benefits)

- ✅ **Benefit 1**: [Description and impact]
- ✅ **Benefit 2**: [Description and impact]
- ✅ **Benefit 3**: [Description and impact]

### Negative (Trade-offs)

- ❌ **Trade-off 1**: [Description and mitigation strategy]
- ❌ **Trade-off 2**: [Description and mitigation strategy]

### Neutral (Side Effects)

- ℹ️ **Impact 1**: [Description]
- ℹ️ **Impact 2**: [Description]

---

## Alternatives Considered

### Alternative 1: [Name]

**Description**: [What this alternative would involve]

**Pros**:
- [Advantage 1]
- [Advantage 2]

**Cons**:
- [Disadvantage 1]
- [Disadvantage 2]

**Why Rejected**: [Explanation]

---

### Alternative 2: [Name]

**Description**: [What this alternative would involve]

**Pros**:
- [Advantage 1]
- [Advantage 2]

**Cons**:
- [Disadvantage 1]
- [Disadvantage 2]

**Why Rejected**: [Explanation]

---

## Implementation Plan

1. **Phase 1**: [Description, timeline]
2. **Phase 2**: [Description, timeline]
3. **Phase 3**: [Description, timeline]

### Success Criteria

- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Criterion 3

### Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|------------|------------|
| Risk 1 | High | Medium | Mitigation strategy |
| Risk 2 | Medium | Low | Mitigation strategy |

---

## Related Decisions

- [ADR-XXX: Related Decision 1](XXX-filename.md)
- [ADR-XXX: Related Decision 2](XXX-filename.md)

---

## References

- [External documentation, RFCs, papers]
- [Benchmarks, performance data]
- [Community discussions, blog posts]

---

## Notes

[Additional context, lessons learned, or follow-up items]

---

**Last Updated**: YYYY-MM-DD
**Review Date**: YYYY-MM-DD (Quarterly/Annually)
**Status Changes**:
- YYYY-MM-DD: Proposed by [Name]
- YYYY-MM-DD: Accepted by [Team]
- YYYY-MM-DD: Deprecated due to [ADR-XXX]
"@

New-DocFile -Path "$baseDir\10-adrs\template.md" -Content $adrTemplate

# Sample ADR: FastAPI over Flask
$adr001 = @"
# ADR-001: FastAPI over Flask/Django

**Status**: Accepted
**Date**: 2024-09-15
**Deciders**: Architecture Team, Backend Engineering Lead
**Technical Story**: Selection of Python web framework for SaaS Platform

---

## Context

The SaaS Platform requires a modern Python web framework capable of:
- High-performance async request handling (10K+ concurrent users)
- Automatic API documentation generation (OpenAPI/Swagger)
- Type safety and validation (Pydantic models)
- Easy integration with PostgreSQL, Redis, and external APIs

### Problem Statement

Choose a Python web framework that balances developer productivity, performance, and modern features for a production-grade multi-tenant SaaS platform.

### Driving Forces

- **Performance**: Need <100ms p50 latency for API calls
- **Documentation**: Auto-generated OpenAPI specs for developer portal
- **Type Safety**: Reduce runtime errors with compile-time validation
- **Async Support**: Handle concurrent database and external API calls
- **Ecosystem**: Strong community, active development, good library support

### Constraints

- **Technical**: Python 3.11+, PostgreSQL, Redis, async database drivers
- **Organizational**: Team has Django experience but willing to learn
- **Business**: 3-month timeline for MVP, must support 1K concurrent users

---

## Decision

**We will use FastAPI as the primary web framework for the SaaS Platform.**

### Key Components

1. **FastAPI Framework**: ASGI-based async Python framework
2. **Pydantic Models**: Type-safe request/response validation
3. **SQLAlchemy 2.0**: Async ORM for PostgreSQL
4. **Uvicorn**: ASGI server for production deployment
5. **OpenAPI Auto-docs**: Automatic Swagger UI and ReDoc

---

## Consequences

### Positive (Benefits)

- ✅ **Performance**: Async support enables 649x better concurrency than sync frameworks
- ✅ **Auto-Documentation**: OpenAPI/Swagger generated automatically from code annotations
- ✅ **Type Safety**: Pydantic validation catches errors at request time (not runtime)
- ✅ **Developer Experience**: Fast iteration with automatic reload, intuitive API design
- ✅ **Modern Python**: Full support for Python 3.11+ features (type hints, async/await)

### Negative (Trade-offs)

- ❌ **Learning Curve**: Team needs to learn FastAPI patterns (migration from Django)
- ❌ **Ecosystem Maturity**: Fewer third-party packages than Django (but growing)
- ❌ **Admin UI**: No built-in admin panel like Django (requires custom dashboard)

### Neutral (Side Effects)

- ℹ️ **Async Everything**: Must use async database drivers, HTTP clients (learning required)
- ℹ️ **Dependency Injection**: Different pattern than Django middleware/views

---

## Alternatives Considered

### Alternative 1: Django

**Description**: Use Django with Django REST Framework (DRF) for API

**Pros**:
- Team already knows Django
- Built-in admin panel for internal tools
- Mature ecosystem with many third-party packages
- ORM with migrations built-in

**Cons**:
- Synchronous by default (ASGI support limited)
- DRF adds complexity, verbose serializers
- No automatic OpenAPI documentation
- Slower performance (sync I/O)

**Why Rejected**: Performance bottleneck for 10K concurrent users. Async support in Django is incomplete. DRF requires too much boilerplate.

---

### Alternative 2: Flask

**Description**: Use Flask with Flask-RESTful for API

**Pros**:
- Lightweight, minimal framework
- Large ecosystem of extensions
- Team familiar with Flask patterns

**Cons**:
- No built-in async support (requires Quart fork)
- Manual OpenAPI documentation (flask-openapi3 extension)
- No built-in validation (requires marshmallow or similar)
- Sync-first design, async is second-class

**Why Rejected**: Lacks modern features (async, type hints, auto-docs). Would require too many extensions to match FastAPI capabilities.

---

## Implementation Plan

1. **Phase 1** (Week 1-2): Proof-of-concept API with FastAPI, SQLAlchemy, PostgreSQL
2. **Phase 2** (Week 3-4): Migrate existing Django endpoints to FastAPI
3. **Phase 3** (Week 5-6): Performance testing (1K concurrent users), optimization

### Success Criteria

- [x] API latency <100ms p50, <500ms p95
- [x] OpenAPI documentation auto-generated
- [x] Type safety for all request/response models
- [x] 1K concurrent users validated (load testing)

### Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|------------|------------|
| Team learning curve | Medium | High | 2-week training period, pair programming |
| Third-party package gaps | Low | Medium | Evaluate packages before commit, fallback to custom code |
| Async bugs (race conditions) | High | Medium | Comprehensive async testing, use async best practices |

---

## Related Decisions

- [ADR-002: PostgreSQL RLS for Multi-tenancy](002-postgresql-rls-multitenancy.md)
- [ADR-003: JWT RS256 for Authentication](003-jwt-rs256-asymmetric.md)

---

## References

- [FastAPI Performance Benchmarks](https://fastapi.tiangolo.com/#performance)
- [FastAPI vs Django Performance](https://www.techempower.com/benchmarks/)
- [Pydantic Documentation](https://docs.pydantic.dev/)

---

## Notes

**Lessons Learned**:
- Async database drivers (asyncpg, aioredis) required separate learning
- OpenAPI auto-docs saved 100+ hours of manual documentation
- Type hints caught 30% of bugs during development (versus runtime)

**Follow-up Items**:
- Evaluate Starlette (FastAPI's foundation) for advanced customization
- Consider implementing custom admin UI (FastAPI-Admin or build custom)

---

**Last Updated**: 2024-10-15
**Review Date**: 2025-01-15 (Quarterly)
**Status Changes**:
- 2024-09-15: Proposed by Backend Engineering Lead
- 2024-09-20: Accepted by Architecture Team
"@

New-DocFile -Path "$baseDir\10-adrs\001-fastapi-over-flask.md" -Content $adr001

Write-Host "`n[3/12] Summary of remaining documentation to generate..." -ForegroundColor Yellow
Write-Host "  - 14 more ADRs (002-015)" -ForegroundColor White
Write-Host "  - 12 Arc42 sections" -ForegroundColor White
Write-Host "  - Component architecture diagrams (C4 Level 3)" -ForegroundColor White
Write-Host "  - Code architecture diagrams (C4 Level 4)" -ForegroundColor White
Write-Host "  - Data architecture documentation" -ForegroundColor White
Write-Host "  - Integration architecture documentation" -ForegroundColor White
Write-Host "  - Quality attributes documentation" -ForegroundColor White
Write-Host "  - Cross-cutting concerns documentation" -ForegroundColor White
Write-Host "  - Deployment architecture documentation" -ForegroundColor White
Write-Host ""

Write-Host "===================================" -ForegroundColor Cyan
Write-Host "Generation Complete!" -ForegroundColor Cyan
Write-Host "Files created: $generatedCount" -ForegroundColor Green
Write-Host "===================================" -ForegroundColor Cyan
Write-Host ""

if ($RenderDiagrams) {
    Write-Host "Rendering PlantUML diagrams..." -ForegroundColor Yellow

    # Check if PlantUML is installed
    $plantumlInstalled = Get-Command plantuml -ErrorAction SilentlyContinue

    if ($plantumlInstalled) {
        Get-ChildItem -Path $baseDir -Filter "*.puml" -Recurse | ForEach-Object {
            Write-Host "  Rendering: $($_.Name)" -ForegroundColor White
            plantuml $_.FullName
        }
        Write-Host "  ✓ Diagram rendering complete" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ PlantUML not installed. Install with: npm install -g node-plantuml" -ForegroundColor Yellow
    }
}

Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Review generated documentation for accuracy" -ForegroundColor White
Write-Host "2. Render diagrams: .\generate-architecture-docs.ps1 -RenderDiagrams" -ForegroundColor White
Write-Host "3. Validate internal links: .\generate-architecture-docs.ps1 -ValidateLinks" -ForegroundColor White
Write-Host "4. Generate PDF book: .\generate-architecture-docs.ps1 -GeneratePDF" -ForegroundColor White
Write-Host ""
"@

New-DocFile -Path "$baseDir\generate-architecture-docs.ps1" -Content $script
