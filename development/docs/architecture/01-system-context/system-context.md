# System Context - Catalytic Computing Platform

**C4 Model Level 1: System Context**

## Overview

The Catalytic Computing Platform operates within a rich ecosystem of external systems, users, and services. This document describes the system boundary, external dependencies, and key stakeholder interactions.

---

## System Boundary

### What's Inside the Boundary?
The Catalytic Computing Platform consists of three major subsystems:

1. **SaaS Platform**: Multi-tenant API with authentication, payments, and user management
2. **Catalytic Engine**: GPU-accelerated computing with lattice structures
3. **GhidraGo Toolkit**: Reverse engineering and binary analysis tools

### What's Outside the Boundary?
External systems and services that the platform integrates with:

- **Payment Processing**: Stripe (PCI DSS Level 1 compliant)
- **Email Delivery**: SendGrid (transactional emails, templates)
- **Secrets Management**: HashiCorp Vault (rotation, audit)
- **Reverse Engineering**: Ghidra Framework (NSA toolkit)
- **Monitoring**: Prometheus (metrics), Grafana (visualization)

---

## External Actors (Stakeholders)

### 1. **Developers**
**Role**: API consumers, integration partners

**Interactions**:
- Consume REST APIs (SaaS Platform)
- Integrate payment flows (Stripe webhooks)
- Build custom tools using MCP servers
- Monitor API performance (Grafana dashboards)

**Primary Interface**: REST API over HTTPS (port 8000)

**Authentication**: JWT tokens (RS256 asymmetric signing)

**Key Needs**:
- API documentation (OpenAPI/Swagger)
- SDKs and code examples
- Sandbox environment for testing
- Webhook debugging tools

---

### 2. **Security Analysts**
**Role**: Binary analysis, malware research, threat hunting

**Interactions**:
- Analyze binaries using GhidraGo
- Write custom analysis scripts (Python/Java)
- Extract IOCs (Indicators of Compromise)
- Perform static and dynamic analysis

**Primary Interface**: CLI tools, Python scripts, Ghidra UI

**Key Needs**:
- Binary analysis tools (GhidraGo, extensions)
- Custom script support (Ghidrathon)
- ARM/MIPS/x86 architecture support
- Malware analysis workflows

---

### 3. **Enterprise Customers**
**Role**: Multi-tenant SaaS users (end customers)

**Interactions**:
- Access platform via web UI
- Manage subscriptions and billing (Stripe)
- Receive transactional emails (SendGrid)
- Monitor usage and quotas

**Primary Interface**: Web UI over HTTPS

**Authentication**: JWT-based session management

**Key Needs**:
- Multi-tenant data isolation (RLS)
- Subscription management
- Usage analytics
- 99.9% uptime SLA

---

### 4. **DevOps Engineers**
**Role**: Platform operators, SRE, monitoring

**Interactions**:
- Deploy infrastructure (Docker Compose, Kubernetes)
- Monitor metrics (Prometheus, Grafana)
- Manage secrets (Vault)
- Perform disaster recovery (backups, failover)

**Primary Interface**: Prometheus (:9090), Grafana (:3000), K8s API

**Key Needs**:
- Real-time metrics and alerting
- Deployment automation (CI/CD)
- Disaster recovery procedures
- Capacity planning data

---

### 5. **Compliance Auditors**
**Role**: Security assessment, compliance verification

**Interactions**:
- Audit security controls (D3FEND)
- Review architecture documentation
- Verify PCI DSS compliance (Stripe)
- Assess multi-tenant isolation (RLS)

**Primary Interface**: API audit logs, documentation, compliance reports

**Key Needs**:
- D3FEND compliance matrix
- Threat model (STRIDE analysis)
- Security control evidence
- Incident response procedures

---

## External Systems

### 1. **Stripe** (Payment Processing)

**Purpose**: Payment processing, subscription management, invoicing

**Communication Protocol**: HTTPS (REST API), Webhooks (inbound)

**Data Exchanged**:
- **Outbound**: Checkout sessions, subscription updates, customer data
- **Inbound**: Payment events (invoice.paid, subscription.created, etc.)

**Security**:
- API keys stored in Vault (rotated monthly)
- Webhook signatures validated (HMAC-SHA256)
- No card data stored (PCI Level 1 compliance via Stripe)

**Availability**: 99.99% SLA (Stripe guarantees)

**Failure Mode**: Graceful degradation (payment retries, queue webhooks)

**ADR**: [ADR-009: Stripe Payment Processing](../10-adrs/009-stripe-payment-processing.md)

---

### 2. **SendGrid** (Email Delivery)

**Purpose**: Transactional email delivery (registration, password reset, payment confirmations)

**Communication Protocol**: HTTPS (REST API), SMTP (alternative)

**Data Exchanged**:
- **Outbound**: Email templates, recipient data, personalization vars
- **Inbound**: Delivery status (bounce, open, click events)

**Security**:
- API keys stored in Vault
- SPF/DKIM configured for domain authentication
- Unsubscribe links required (CAN-SPAM compliance)

**Availability**: 99.9% uptime guarantee

**Failure Mode**: Retry logic with exponential backoff, dead letter queue

**ADR**: [ADR-014: SendGrid Email Delivery](../10-adrs/014-sendgrid-email-delivery.md)

---

### 3. **HashiCorp Vault** (Secrets Management)

**Purpose**: Centralized secrets storage, rotation, and audit logging

**Communication Protocol**: HTTPS (REST API), AppRole authentication

**Data Stored**:
- JWT signing keys (private/public keypair)
- Database credentials (PostgreSQL, Redis)
- API keys (Stripe, SendGrid)
- Encryption keys (data-at-rest)

**Security**:
- TLS mutual authentication (mTLS)
- AppRole authentication (machine identity)
- Audit logging (all access logged)
- Auto-unseal (AWS KMS)

**Availability**: 3-node Raft cluster (99.95% SLA)

**Failure Mode**: Cached secrets used (15-minute TTL), alerts triggered

**ADR**: [ADR-006: Vault Secrets Management](../10-adrs/006-vault-secrets-management.md)

---

### 4. **Ghidra Framework** (Reverse Engineering)

**Purpose**: Binary analysis, decompilation, disassembly

**Communication Protocol**: Java API, Python API (Ghidrathon)

**Integration Points**:
- Custom loaders (GolangLoader for Go binaries)
- Extensions (GhidraCtrlP, GhidrAssist, etc.)
- Script API (Python via Ghidrathon)
- Analysis pipelines (automated processing)

**Version**: 11.4.2 (NSA public release)

**Deployment**: Standalone (analyst workstations), headless (automation)

**ADR**: [ADR-013: Ghidra Framework Integration](../10-adrs/013-ghidra-framework-integration.md)

---

### 5. **Prometheus** (Metrics Collection)

**Purpose**: Time-series metrics collection, alerting

**Communication Protocol**: HTTP scraping (/metrics endpoint), Push Gateway (alternative)

**Metrics Collected**:
- **Business Metrics**: User registration, MRR/ARR, churn, retention
- **System Metrics**: API latency (p50/p95/p99), error rates, throughput
- **Infrastructure**: CPU, memory, GPU utilization, disk I/O
- **Custom**: Lattice efficiency (28,571x target), cache hit rate (80%+)

**Retention**: 15 days (high-resolution), 90 days (downsampled)

**Alerting**: AlertManager integration (PagerDuty, Slack, email)

**ADR**: [ADR-007: Prometheus + Grafana Monitoring](../10-adrs/007-prometheus-grafana-monitoring.md)

---

### 6. **Grafana** (Metrics Visualization)

**Purpose**: Dashboard visualization, alerting UI

**Communication Protocol**: HTTP (web UI), Prometheus data source (HTTP)

**Dashboards**:
1. **System Dashboard**: API performance, DB connections, Redis cache
2. **Business Dashboard**: User growth, revenue, retention, conversion
3. **GPU Dashboard**: CUDA utilization, TFLOPS, memory bandwidth

**Alerting**: Visual alerts, annotations, notification channels

**Access Control**: Role-based access (admin, viewer)

**ADR**: [ADR-007: Prometheus + Grafana Monitoring](../10-adrs/007-prometheus-grafana-monitoring.md)

---

## Communication Protocols

### Inbound Traffic

| Source | Destination | Protocol | Port | Purpose |
|--------|-------------|----------|------|---------|
| Developers | SaaS API | HTTPS | 8000 | REST API calls |
| Customers | SaaS API | HTTPS | 8000 | Web UI access |
| Stripe | Webhook System | HTTPS | 8085 | Payment events |
| DevOps | Prometheus | HTTPS | 9090 | Metrics queries |
| DevOps | Grafana | HTTPS | 3000 | Dashboard access |

### Outbound Traffic

| Source | Destination | Protocol | Port | Purpose |
|--------|-------------|----------|------|---------|
| SaaS API | Stripe | HTTPS | 443 | Payment processing |
| SaaS API | SendGrid | HTTPS | 443 | Email delivery |
| SaaS API | Vault | HTTPS | 8200 | Secret retrieval |
| Prometheus | SaaS API | HTTP | 8000 | Metrics scraping |
| Prometheus | Catalytic API | HTTP | 8080 | Metrics scraping |
| Grafana | Prometheus | HTTP | 9090 | Data source queries |

---

## Data Flow at System Boundary

### 1. **User Authentication Flow**
```
Developer → Nginx (rate limit) → SaaS API (JWT decode) →
Vault (fetch public key) → Redis (blacklist check) →
PostgreSQL (fetch user, RLS enforced) → Response
```

### 2. **Payment Webhook Flow**
```
Stripe → Webhook System (HMAC verify) →
PostgreSQL (update subscription) →
SendGrid (send confirmation email) → Customer
```

### 3. **Metrics Collection Flow**
```
SaaS API → Prometheus (scrape /metrics) →
Grafana (query Prometheus) → DevOps (view dashboard)
```

---

## Security Considerations

### 1. **External System Authentication**

| System | Authentication Method | Credential Storage |
|--------|----------------------|-------------------|
| Stripe | API Key (Bearer token) | Vault (rotated monthly) |
| SendGrid | API Key (Bearer token) | Vault (rotated monthly) |
| Vault | AppRole (client ID + secret) | K8s Secret (injected at runtime) |
| Prometheus | None (internal network) | N/A (network policy) |
| Grafana | Username/Password (admin) | Vault |

### 2. **Network Segmentation**

- **Public Internet**: Nginx (WAF, rate limiting, TLS termination)
- **Application Layer**: SaaS API, Catalytic API, Webhook System (internal network)
- **Data Layer**: PostgreSQL, Redis (internal network, no public access)
- **Management Plane**: Vault, Prometheus, Grafana (VPN/bastion required)

### 3. **Trust Boundaries**

**High Trust**:
- Internal application network (Docker/K8s)
- Vault-managed secrets

**Medium Trust**:
- External integrations (Stripe, SendGrid) - authenticated, encrypted
- Monitoring systems (Prometheus, Grafana) - internal access only

**Low Trust**:
- Public API endpoints (rate-limited, WAF-protected)
- Webhook receivers (signature validation required)

---

## Operational Considerations

### 1. **External Dependency Risks**

| System | Failure Impact | Mitigation |
|--------|---------------|------------|
| Stripe | Payments blocked | Queue transactions, retry logic, manual processing |
| SendGrid | Emails delayed | Queue with dead letter, retry exponential backoff |
| Vault | Secrets unavailable | Cached secrets (15-min TTL), alerts, failover to replica |
| Ghidra | Analysis blocked | Local installation, no cloud dependency |
| Prometheus | Monitoring blind | Local metrics cache, multiple Prometheus instances |

### 2. **Compliance Requirements**

**PCI DSS**:
- Stripe handles all card data (Level 1 compliant)
- Platform never stores card numbers, CVV, or magnetic stripe data

**GDPR** (if applicable):
- Data retention policies (90-day active, 7-year archive)
- Right to erasure (delete user API)
- Data portability (export API)

**SOC 2** (if pursuing certification):
- Access control (RBAC, least privilege)
- Audit logging (all sensitive operations)
- Encryption (data-at-rest, data-in-transit)

---

## Future Integrations (Planned)

1. **Auth0/Okta**: SSO for enterprise customers (SAML, OAuth)
2. **AWS S3**: Binary storage for large analysis artifacts
3. **Datadog**: Enhanced APM (application performance monitoring)
4. **PagerDuty**: On-call incident management
5. **GitHub**: OAuth login, webhook integrations

---

## References

- [C4 Context Diagram](c4-context.puml)
- [Stakeholder Details](stakeholders.md)
- [Container Architecture](../02-container-architecture/)
- [Integration Architecture](../08-integration-architecture/)
- [Security Architecture](../05-cross-cutting-concerns/security-architecture.md)

---

**Last Updated**: November 2025
**Review Frequency**: Quarterly
**Next Review**: February 2026
