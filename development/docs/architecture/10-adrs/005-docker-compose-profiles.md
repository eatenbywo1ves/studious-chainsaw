# ADR-005: Docker Compose Profiles for Deployment

**Status**: Accepted
**Date**: 2024-09-25
**Deciders**: DevOps Team, Architecture Team
**Technical Story**: Flexible local and staging deployment

---

## Context

Need flexible deployment configurations for development, testing, and staging environments.

### Problem Statement

Create deployment configurations that support different environments without duplicating Docker Compose files.

---

## Decision

**Use Docker Compose profiles to define four deployment configurations: core, saas, dev, and all.**

### Profiles

| Profile | Services | Use Case |
|---------|----------|----------|
| **core** | Catalytic API, Webhook | Minimal, stateless testing |
| **saas** | + PostgreSQL, Redis, SaaS API | Full multi-tenant platform |
| **dev** | + Prometheus, Grafana, Admin tools | Local development with monitoring |
| **all** | Everything | Full integration testing |

### Usage

```bash
docker-compose --profile saas up -d
docker-compose --profile dev up -d
docker-compose --profile all up -d
```

---

## Consequences

### Positive
- ✅ Single compose file (no duplication)
- ✅ Selective service startup
- ✅ Environment-specific configs
- ✅ Easy CI/CD integration

### Negative
- ❌ Profile complexity can confuse newcomers
- ❌ Some services need multiple profiles listed

---

## Alternatives Considered

### Multiple Compose Files
**Why Rejected**: Duplication, sync issues between files

### Environment Variables Only
**Why Rejected**: Less readable, harder to understand what's running

---

## Related Decisions

- [ADR-011: Kubernetes Production](011-kubernetes-production-orchestration.md)

---

**Last Updated**: 2024-10-15
