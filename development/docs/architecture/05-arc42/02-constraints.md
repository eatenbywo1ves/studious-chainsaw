# 2. Architecture Constraints

## 2.1 Technical Constraints

| Constraint | Background | Consequence |
|------------|------------|-------------|
| **Python 3.11+** | Performance improvements, type hints | All services use Python 3.11 |
| **PostgreSQL 15+** | RLS, JSONB, performance | Primary data store |
| **NVIDIA GPUs** | CUDA ecosystem, PyTorch | GPU compute requires NVIDIA |
| **Docker/K8s** | Container orchestration standard | All services containerized |
| **Linux Containers** | GPU driver compatibility | No Windows containers |

### Technology Mandates

| Category | Required Technology | Rationale |
|----------|-------------------|-----------|
| API Framework | FastAPI | Async support, OpenAPI |
| Database | PostgreSQL 15+ | RLS, JSONB, reliability |
| Cache | Redis 7+ | Pub/sub, Lua scripting |
| GPU | CUDA 12+ | Latest features, drivers |
| Secrets | HashiCorp Vault | Industry standard |
| Monitoring | Prometheus + Grafana | Cloud-native standard |

## 2.2 Organizational Constraints

| Constraint | Background | Consequence |
|------------|------------|-------------|
| **Small Team** | 3-5 developers | Automation prioritized |
| **Open Source First** | Cost constraints | Prefer OSS solutions |
| **Cloud-Native** | Deployment flexibility | K8s-compatible design |
| **Security First** | Enterprise customers | D3FEND compliance |

## 2.3 Conventions

### Coding Standards
- **Python**: Black formatter, Ruff linter, mypy type checking
- **SQL**: Lowercase keywords, snake_case naming
- **API**: RESTful conventions, OpenAPI 3.0 spec
- **Git**: Conventional commits, feature branches

### Documentation Standards
- Architecture: Arc42 + C4 Model
- API: OpenAPI/Swagger auto-generated
- Runbooks: Markdown in `/docs/runbooks`
- ADRs: Numbered, immutable records

### Security Standards
- **OWASP Top 10**: All items addressed
- **D3FEND**: 12+ techniques implemented
- **Zero Trust**: No implicit trust between services
- **Least Privilege**: Minimal permissions by default

## 2.4 Cost Constraints

| Resource | Budget | Implication |
|----------|--------|-------------|
| Cloud GPU | $5,000/month | Efficient scheduling critical |
| Storage | $500/month | Data retention policies |
| Bandwidth | $200/month | CDN for static assets |
| Monitoring | $0 | Self-hosted Prometheus |

## 2.5 Time Constraints

| Milestone | Date | Deliverable |
|-----------|------|-------------|
| MVP | Q4 2024 | Core compute + auth |
| Beta | Q1 2025 | Billing + GhidraGo |
| GA | Q2 2025 | Full platform |

---
**Last Updated**: 2024-10-15
