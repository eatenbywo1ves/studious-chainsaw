# 3. System Scope and Context

## 3.1 Business Context

```
                    ┌─────────────────────────────────────┐
                    │                                     │
   ┌──────────┐     │     Catalytic Computing Platform    │     ┌──────────┐
   │Developer │────►│                                     │────►│  Stripe  │
   │   API    │     │  ┌───────────┐  ┌───────────────┐  │     │ Payments │
   └──────────┘     │  │  SaaS API │  │ Catalytic GPU │  │     └──────────┘
                    │  └───────────┘  └───────────────┘  │
   ┌──────────┐     │                                     │     ┌──────────┐
   │ Security │────►│  ┌───────────┐  ┌───────────────┐  │────►│ SendGrid │
   │ Analyst  │     │  │ GhidraGo  │  │Infrastructure │  │     │  Email   │
   └──────────┘     │  └───────────┘  └───────────────┘  │     └──────────┘
                    │                                     │
   ┌──────────┐     │                                     │     ┌──────────┐
   │Enterprise│────►│                                     │────►│  Vault   │
   │ Customer │     │                                     │     │ Secrets  │
   └──────────┘     └─────────────────────────────────────┘     └──────────┘
```

### Communication Partners

| Partner | Input | Output | Protocol |
|---------|-------|--------|----------|
| Developer | Code/binaries for analysis | Analysis results, metrics | HTTPS REST |
| Security Analyst | Binaries for RE | Decompiled code, types | HTTPS REST |
| Enterprise | Compute jobs | Results, invoices | HTTPS REST |
| Stripe | Webhook events | Payment intents | HTTPS |
| SendGrid | - | Transactional emails | HTTPS |
| Vault | - | Secrets, credentials | HTTPS |

## 3.2 Technical Context

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Internet                                     │
└────────────────────────────┬────────────────────────────────────────┘
                             │ HTTPS (TLS 1.3)
                             │
┌────────────────────────────▼────────────────────────────────────────┐
│                      Load Balancer (Nginx)                           │
│                      Rate Limiting, SSL Termination                  │
└───┬─────────────┬─────────────────────┬────────────────────┬────────┘
    │             │                     │                    │
    ▼             ▼                     ▼                    ▼
┌───────────┐ ┌───────────────┐ ┌───────────────┐ ┌──────────────────┐
│ SaaS API  │ │Catalytic Engine│ │   GhidraGo   │ │   Static/Docs    │
│ :8000     │ │    :8001       │ │    :8002     │ │     :80          │
└─────┬─────┘ └───────┬───────┘ └───────┬───────┘ └──────────────────┘
      │               │                 │
      │               │                 │
      ▼               ▼                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Internal Network (Docker/K8s)                     │
├─────────────┬─────────────────┬───────────────────┬─────────────────┤
│ PostgreSQL  │     Redis       │    Prometheus     │     Vault       │
│   :5432     │     :6379       │      :9090        │     :8200       │
└─────────────┴─────────────────┴───────────────────┴─────────────────┘
```

### Technical Interfaces

| Interface | Technology | Purpose |
|-----------|------------|---------|
| External API | HTTPS REST + JSON | Client access |
| WebSocket | WSS | Real-time updates |
| Database | PostgreSQL wire protocol | Data persistence |
| Cache | Redis protocol (RESP3) | Caching, pub/sub |
| Metrics | Prometheus scrape | Monitoring |
| Secrets | Vault HTTP API | Credential management |

### Network Segmentation

| Zone | Components | Exposure |
|------|------------|----------|
| DMZ | Load balancer | Internet |
| Application | API services | Internal + LB |
| Data | PostgreSQL, Redis | Internal only |
| Management | Vault, Prometheus | Internal only |

## 3.3 External Interfaces

### Stripe API
- **Direction**: Bidirectional
- **Protocol**: HTTPS REST
- **Auth**: API key (secret)
- **Events**: Webhooks with signature verification
- **Rate Limit**: 100 req/s

### SendGrid API
- **Direction**: Outbound only
- **Protocol**: HTTPS REST
- **Auth**: API key
- **Templates**: Dynamic templates with personalization
- **Rate Limit**: 600 emails/min

### Vault API
- **Direction**: Application → Vault
- **Protocol**: HTTPS REST
- **Auth**: AppRole + token renewal
- **Secrets**: Dynamic database credentials
- **Lease**: 1 hour TTL

---
**Last Updated**: 2024-10-15
