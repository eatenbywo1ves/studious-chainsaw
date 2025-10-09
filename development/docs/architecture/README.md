# Architecture & Design Documentation

Comprehensive system design and architecture documentation.

## System Overview

### [System Overview](./system-overview.md)
High-level architecture of the entire platform including all major components and their interactions.

---

## Component Architectures

### [SaaS Architecture](./saas-architecture.md)
Multi-tenant SaaS platform design including:
- Authentication & authorization (JWT)
- Database design (PostgreSQL)
- Caching strategy (Redis)
- API gateway architecture
- Subscription management (Stripe)

### [GhidraGo Design](./ghidrago-design.md)
Golang binary analyzer implementation:
- Ghidra integration
- Go runtime analysis
- Type recovery algorithms
- Decompilation workflows

### [Security Architecture](./security-architecture.md)
D3FEND-compliant defensive security system:
- Agent-based architecture
- Threat modeling
- Detection strategies
- Security monitoring

---

## Design Principles

Our architecture follows these core principles:

1. **Modularity** - Components are loosely coupled and independently deployable
2. **Scalability** - Horizontal scaling for all services
3. **Observability** - Comprehensive metrics, logs, and traces
4. **Security** - Defense in depth, zero trust principles
5. **Reliability** - Fault tolerance and graceful degradation

---

## Component Walkthroughs

Detailed technical walkthroughs of key components:

- [GPU Baseline Walkthrough](../COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md)
- [ML Container Walkthrough](../COMPONENT_WALKTHROUGH_2_ML_CONTAINER.md)
- [Deployment Security Walkthrough](../COMPONENT_WALKTHROUGH_3_DEPLOYMENT_SECURITY.md)

---

## Technology Stack

### Core Technologies
- **Languages:** Python 3.11+, Java (Ghidra)
- **Frameworks:** FastAPI, SQLAlchemy, Pydantic
- **Databases:** PostgreSQL, Redis, SQLite (dev)
- **Infrastructure:** Docker, Kubernetes (planned)

### Specialized Technologies
- **GPU Computing:** CUDA, PyTorch, CuPy
- **Reverse Engineering:** Ghidra 11.4+
- **Monitoring:** Prometheus, Grafana
- **Security:** D3FEND ontology

---

## Architecture Diagrams

Key diagrams and visualizations:

```
┌─────────────────────────────────────────────────┐
│           API Gateway (FastAPI)                 │
├─────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │  Auth    │  │  Tenant  │  │Subscription│     │
│  │ Service  │  │ Service  │  │  Service   │     │
│  └──────────┘  └──────────┘  └──────────┘     │
└──────┬──────────────┬──────────────┬───────────┘
       │              │              │
   ┌───▼────┐    ┌───▼────┐    ┌───▼────┐
   │ Redis  │    │Postgres│    │ Stripe │
   │ Cache  │    │   DB   │    │  API   │
   └────────┘    └────────┘    └────────┘
```

---

## Related Documentation

- [Deployment Guide](../PRODUCTION_DEPLOYMENT_GUIDE.md) - How to deploy this architecture
- [API Reference](../api/) - API endpoints and schemas
- [Monitoring](../monitoring/) - Observability setup
- [Specifications](../specifications/) - Detailed technical specs

---

**Navigation:** [← Back to Index](../INDEX.md) | [Development Root](../../)
