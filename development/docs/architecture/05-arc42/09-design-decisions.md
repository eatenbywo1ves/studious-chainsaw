# 9. Architecture Decisions

## 9.1 Decision Log

All significant architecture decisions are documented as Architecture Decision Records (ADRs) in the `/10-adrs/` directory.

### Summary of Key Decisions

| ADR | Decision | Status | Impact |
|-----|----------|--------|--------|
| [001](../10-adrs/001-fastapi-over-flask.md) | FastAPI over Flask | Accepted | High |
| [002](../10-adrs/002-postgresql-rls-multi-tenancy.md) | PostgreSQL RLS | Accepted | Critical |
| [003](../10-adrs/003-jwt-rs256-asymmetric.md) | JWT RS256 | Accepted | High |
| [004](../10-adrs/004-pytorch-gpu-acceleration.md) | PyTorch for GPU | Accepted | High |
| [005](../10-adrs/005-docker-compose-profiles.md) | Docker Compose Profiles | Accepted | Medium |
| [006](../10-adrs/006-hashicorp-vault-secrets.md) | HashiCorp Vault | Accepted | High |
| [007](../10-adrs/007-prometheus-grafana-monitoring.md) | Prometheus + Grafana | Accepted | Medium |
| [008](../10-adrs/008-redis-caching-rate-limiting.md) | Redis Caching | Accepted | High |
| [009](../10-adrs/009-stripe-payment-processing.md) | Stripe Payments | Accepted | High |
| [010](../10-adrs/010-d3fend-security-framework.md) | D3FEND Framework | Accepted | High |
| [011](../10-adrs/011-kubernetes-production-orchestration.md) | Kubernetes | Accepted | Critical |
| [012](../10-adrs/012-cupy-gpu-numpy.md) | CuPy for NumPy | Accepted | Medium |
| [013](../10-adrs/013-ghidra-framework-integration.md) | Ghidra Integration | Accepted | High |
| [014](../10-adrs/014-sendgrid-email-delivery.md) | SendGrid Email | Accepted | Medium |
| [015](../10-adrs/015-numba-jit-compilation.md) | Numba JIT | Accepted | Medium |

## 9.2 Decision Categories

### Infrastructure Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| Container Orchestration | Kubernetes | Industry standard, HPA, ecosystem |
| Secret Management | HashiCorp Vault | Dynamic secrets, rotation |
| Monitoring | Prometheus + Grafana | Cloud-native, OSS |
| Load Balancing | Nginx | Performance, familiarity |

### Security Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| Multi-tenancy | PostgreSQL RLS | Database-level isolation |
| Authentication | JWT RS256 | Stateless, asymmetric |
| Password Storage | Bcrypt (cost=12) | Proven, adjustable cost |
| Framework | D3FEND | Systematic, auditable |

### Application Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| API Framework | FastAPI | Async, OpenAPI, type hints |
| GPU Stack | PyTorch + CuPy + Numba | Coverage, performance |
| Cache | Redis | Speed, Lua scripting |
| RE Framework | Ghidra | Open source, extensible |

### Business Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| Payments | Stripe | PCI compliance, SDKs |
| Email | SendGrid | Deliverability, templates |
| Hosting | Cloud (K8s) | GPU availability, scaling |

## 9.3 Pending Decisions

| Area | Options | Timeline | Owner |
|------|---------|----------|-------|
| Distributed Tracing | Jaeger vs Zipkin | Q1 2025 | DevOps |
| Message Queue | Redis Streams vs RabbitMQ | Q1 2025 | Architecture |
| ML Platform | Custom vs MLflow | Q2 2025 | ML Team |

## 9.4 Decision-Making Process

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Proposal   │────►│  Analysis   │────►│   Review    │
│             │     │             │     │             │
│ - Context   │     │ - Options   │     │ - Team      │
│ - Problem   │     │ - Trade-offs│     │ - Stakeholder│
│ - Options   │     │ - PoC       │     │ - Approval  │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Document   │◄────│  Implement  │◄────│   Decide    │
│             │     │             │     │             │
│ - ADR       │     │ - Code      │     │ - Select    │
│ - README    │     │ - Config    │     │ - Record    │
│ - Runbook   │     │ - Test      │     │ - Announce  │
└─────────────┘     └─────────────┘     └─────────────┘
```

## 9.5 Technology Radar

### Adopt (Use in Production)

- FastAPI, PostgreSQL, Redis
- PyTorch, CuPy, Numba
- Kubernetes, Docker
- Prometheus, Grafana

### Trial (Experimental)

- OpenTelemetry tracing
- Redis Streams for queues
- Dask for distributed compute

### Assess (Evaluate)

- WebAssembly for browser compute
- eBPF for observability
- SQLite for edge caching

### Hold (Do Not Use)

- Flask (replaced by FastAPI)
- MongoDB (PostgreSQL preferred)
- Custom auth solutions

---
**Last Updated**: 2024-10-15
