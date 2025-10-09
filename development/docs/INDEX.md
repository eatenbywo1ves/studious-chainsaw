# Documentation Index

**Welcome to the Catalytic Computing Development Documentation!**

This is your starting point for all technical documentation. Choose your path below based on what you need.

---

## 🚀 New Here? Start Here

| I want to... | Go to |
|--------------|-------|
| Get started in 5 minutes | [Quick Start Guides](#-quick-start-guides) |
| Understand the system architecture | [Architecture Docs](#-architecture--design) |
| Deploy to production | [Deployment Guide](./PRODUCTION_DEPLOYMENT_GUIDE.md) |
| Find API documentation | [API Reference](#-reference--api) |
| Troubleshoot an issue | [Guides & Tutorials](#-guides--tutorials) |

---

## 📂 Documentation Structure

```
docs/
├── INDEX.md (you are here)          # Navigation hub
├── quickstart/                      # 5-minute getting started guides
├── architecture/                    # System design & architecture
├── guides/                          # How-to tutorials
├── reference/                       # API docs, configs
├── deployment/                      # Production deployment
├── monitoring/                      # Observability & metrics
├── reports/                         # Technical reports & analysis
└── archive/                         # Historical documentation
```

---

## 🏃 Quick Start Guides

**Get up and running in 5 minutes:**

- [SaaS Platform (5 min)](./quickstart/saas-5min.md) - Authentication, payments, multi-tenant system
- [GhidraGo (5 min)](./quickstart/ghidrago-5min.md) - Golang binary analyzer
- [Security Tools (5 min)](./quickstart/security-tools-5min.md) - Defensive security agents
- [GPU Computing (5 min)](./quickstart/gpu-5min.md) - CUDA acceleration setup

---

## 🏗️ Architecture & Design

**Understand how the system is built:**

- [System Overview](./architecture/system-overview.md) - High-level architecture
- [SaaS Architecture](./architecture/saas-architecture.md) - Multi-tenant platform design
- [GhidraGo Design](./architecture/ghidrago-design.md) - Binary analyzer implementation
- [Security Architecture](./architecture/security-architecture.md) - D3FEND compliance

**Component Walkthroughs:**
- [GPU Baseline](./COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md)
- [ML Container](./COMPONENT_WALKTHROUGH_2_ML_CONTAINER.md)
- [Deployment Security](./COMPONENT_WALKTHROUGH_3_DEPLOYMENT_SECURITY.md)

---

## 📚 Guides & Tutorials

**Step-by-step instructions:**

### Deployment & Infrastructure
- [Production Deployment Guide](./PRODUCTION_DEPLOYMENT_GUIDE.md)
- [Environment Configuration](./guides/ENV_CONFIGURATION_GUIDE.md)
- [B-MAD Master Guide](./guides/BMAD_MASTER_GUIDE.md)
- [Kubernetes Deployment](./guides/ka-lattice-deployment-guide.md)
- [NVIDIA B-MAD Deployment](./guides/NVIDIA_BMAD_DEPLOYMENT_PLAN.md)

### Performance & Optimization
- [Redis Pool Optimization](./guides/REDIS_POOL_OPTIMIZATION_GUIDE.md)
- [GPU Acceleration Guide](./guides/GPU_ACCELERATION_GUIDE.md)
- [Redis Production Guide](./guides/REDIS_PRODUCTION_GUIDE.md)

### Security & SSH
- [Fold 7 SSH Setup](./guides/FOLD7_SSH_SETUP.md)
- [SSH App Identification](./guides/IDENTIFY_YOUR_SSH_APP.md)
- [Responsible Security Research](./guides/RESPONSIBLE_SECURITY_RESEARCH_GUIDE.md)

### Integration
- [Stripe & Email Integration](./guides/STRIPE_EMAIL_INTEGRATION_GUIDE.md)
- [SaaS Deployment Guide](./guides/saas-deployment-guide.md)

---

## 📖 Reference & API

**Technical specifications and API documentation:**

- [API Documentation](./api/README.md)
- [OpenAPI Specification](./openapi.yaml)
- [Configuration Reference](./reference/config-reference.md) *(coming soon)*
- [Environment Variables](./deployment/ENVIRONMENT_VARIABLES.md)

**Status Reports:**
- [GPU Acceleration Status](./GPU_ACCELERATION_STATUS.md)
- [MCP Integration Status](./MCP_INTEGRATION_STATUS.md)

---

## 🚀 Production Deployment

**Everything you need for production:**

- [**Production Deployment Guide**](./PRODUCTION_DEPLOYMENT_GUIDE.md) ⭐ Start here
- [Deployment Checklist](./deployment/PRODUCTION_READINESS_CHECKLIST.md)
- [B-MAD Deployment Guide](./deployment/BMAD_DEPLOYMENT_GUIDE.md)
- [Database Migrations](./deployment/DATABASE_MIGRATIONS.md)
- [Rollback Procedures](./deployment/ROLLBACK_PROCEDURES.md)
- [Disaster Recovery](./deployment/DISASTER_RECOVERY.md)

---

## 📊 Monitoring & Observability

**Track system health and performance:**

- [Monitoring Overview](./monitoring/README.md)
- [Dashboard Guide](./monitoring/dashboard_guide.md)
- [Metrics Catalog](./monitoring/metrics_catalog.md)
- [Grafana Dashboards](./reports/GRAFANA_DASHBOARDS_SUMMARY.md)

### Runbooks (When Things Go Wrong)
- [High API Latency](./monitoring/runbooks/high_api_latency.md)
- [High Error Rate](./monitoring/runbooks/high_error_rate.md)
- [Service Unavailable](./monitoring/runbooks/service_unavailable.md)
- [Database Connection Pool](./monitoring/runbooks/database_connection_pool.md)
- [Redis Memory Pressure](./monitoring/runbooks/redis_memory_pressure.md)
- [GPU Memory Exhaustion](./monitoring/runbooks/gpu_memory_exhaustion.md)

---

## 📝 Technical Reports & Specifications

**In-depth analysis and design documents:**

### Performance Reports
- [Redis Pool Performance](./guides/REDIS_POOL_PERFORMANCE_REPORT.md)
- [Production Ready Report](./reports/PRODUCTION_READY_REPORT.md)
- [Final Test Report](./reports/FINAL_TEST_REPORT.md)
- [Linting Report](./reports/LINTING_REPORT.md)
- [Refactoring Summary](./reports/REFACTORING_SUMMARY.md)

### Specifications
- [GhidraGo Specification](./specifications/GHIDRAGO_SPECIFICATION.md)
- [GhidrAssist Analysis](./specifications/GHIDRASSIST_ANALYSIS.md)
- [Ghidra Extensions Summary](./specifications/GHIDRA_EXTENSIONS_SUMMARY.md)
- [JWT Consolidation Analysis](./specifications/JWT_CONSOLIDATION_ANALYSIS.md)
- [Configuration Audit Report](./specifications/CONFIGURATION_AUDIT_REPORT.md)
- [Defensive Security Agent Architecture](./specifications/DEFENSIVE_SECURITY_AGENT_ARCHITECTURE.md)
- [Wiz Zeroday Cloud Defense Strategy](./specifications/WIZ_ZERODAY_CLOUD_2025_DEFENSE_STRATEGY.md)

---

## 🗂️ Archive

**Historical documentation (reference only):**

- [2025-Q4 Archive](./archive/2025-Q4/) - Completed project reports, historical plans
- [Phase Reports](./archive/phase-reports/) - Phase 3, 4, 5 planning docs

---

## 🔍 Finding What You Need

**Search by topic:**

| Topic | Relevant Docs |
|-------|---------------|
| **Authentication** | [SaaS Architecture](./architecture/saas-architecture.md), [JWT Analysis](./specifications/JWT_CONSOLIDATION_ANALYSIS.md) |
| **Redis** | [Pool Optimization](./guides/REDIS_POOL_OPTIMIZATION_GUIDE.md), [Production Guide](./guides/REDIS_PRODUCTION_GUIDE.md), [Performance Report](./guides/REDIS_POOL_PERFORMANCE_REPORT.md) |
| **GPU/CUDA** | [GPU Guide](./guides/GPU_ACCELERATION_GUIDE.md), [GPU Status](./GPU_ACCELERATION_STATUS.md), [GPU Walkthrough](./COMPONENT_WALKTHROUGH_1_GPU_BASELINE.md) |
| **Ghidra** | [GhidraGo Quick Start](./quickstart/ghidrago-5min.md), [GhidraGo Spec](./specifications/GHIDRAGO_SPECIFICATION.md), [Extensions](./specifications/GHIDRA_EXTENSIONS_SUMMARY.md) |
| **Security** | [Security Tools](./quickstart/security-tools-5min.md), [Defense Strategy](./specifications/WIZ_ZERODAY_CLOUD_2025_DEFENSE_STRATEGY.md), [D3FEND Architecture](./specifications/DEFENSIVE_SECURITY_AGENT_ARCHITECTURE.md) |
| **Monitoring** | [Monitoring Overview](./monitoring/README.md), [Dashboards](./monitoring/dashboard_guide.md), [Runbooks](./monitoring/runbooks/) |
| **Deployment** | [Production Guide](./PRODUCTION_DEPLOYMENT_GUIDE.md), [B-MAD Deployment](./deployment/BMAD_DEPLOYMENT_GUIDE.md), [Rollback](./deployment/ROLLBACK_PROCEDURES.md) |

---

## 🆘 Need Help?

**Common questions:**

- **"How do I get started?"** → See [Quick Start Guides](#-quick-start-guides)
- **"How does this work?"** → See [Architecture & Design](#-architecture--design)
- **"Something is broken!"** → See [Monitoring Runbooks](#runbooks-when-things-go-wrong)
- **"How do I deploy this?"** → See [Production Deployment](#-production-deployment)
- **"Where's the API docs?"** → See [Reference & API](#-reference--api)

---

## 📈 Documentation Status

**Last Updated:** 2025-10-08
**Documentation Version:** 2.0 (Reorganized)
**Active Projects:** SaaS Platform, GhidraGo, Security Tools, GPU Computing

**Maintenance Schedule:**
- Weekly: Update status reports
- Monthly: Review for accuracy
- Quarterly: Archive outdated docs

---

## 🎯 Quick Links (Most Used)

1. [Production Deployment Guide](./PRODUCTION_DEPLOYMENT_GUIDE.md) ⭐
2. [Redis Pool Optimization](./guides/REDIS_POOL_OPTIMIZATION_GUIDE.md)
3. [API Documentation](./api/README.md)
4. [Monitoring Dashboard Guide](./monitoring/dashboard_guide.md)
5. [GhidraGo Specification](./specifications/GHIDRAGO_SPECIFICATION.md)

---

**Navigation:** [README](../README.md) | [Development Root](../)

---

*This documentation follows the One-Page Rule: Each project has one landing page with links to detailed docs.*
