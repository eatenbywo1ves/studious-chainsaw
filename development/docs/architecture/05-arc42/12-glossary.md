# 12. Glossary

## Domain Terms

| Term | Definition |
|------|------------|
| **Analysis Job** | A unit of work submitted to the platform for GPU computation or binary analysis |
| **Backend** | A compute engine (PyTorch, CuPy, or Numba) that executes GPU operations |
| **Binary Analysis** | The process of examining executable files to understand their structure and behavior |
| **Decompilation** | Converting machine code back to high-level pseudocode |
| **Tenant** | An organization or individual customer with isolated data and resources |
| **Type Cache** | Persistent storage of decompiled data types for faster repeated analysis |

## Technical Terms

| Term | Definition |
|------|------------|
| **ADR** | Architecture Decision Record - documented architecture decisions |
| **AOF** | Append Only File - Redis persistence method |
| **C4 Model** | Context, Container, Component, Code - architecture visualization framework |
| **Circuit Breaker** | Pattern to prevent cascade failures in distributed systems |
| **CUDA** | NVIDIA's parallel computing platform for GPU programming |
| **cuFFT** | CUDA Fast Fourier Transform library |
| **D3FEND** | MITRE framework for defensive cybersecurity techniques |
| **HPA** | Horizontal Pod Autoscaler - Kubernetes auto-scaling resource |
| **JIT** | Just-In-Time compilation - compiling code at runtime |
| **JSONB** | PostgreSQL binary JSON type with indexing support |
| **JWT** | JSON Web Token - compact token format for authentication |
| **P-Code** | Ghidra's processor-independent intermediate representation |
| **RLS** | Row-Level Security - PostgreSQL feature for data isolation |
| **RS256** | RSA Signature with SHA-256 - asymmetric JWT signing algorithm |
| **SLEIGH** | Ghidra's processor specification language |
| **TFLOPS** | Tera Floating Point Operations Per Second |
| **WAL** | Write-Ahead Log - PostgreSQL durability mechanism |

## Acronyms

| Acronym | Expansion |
|---------|-----------|
| API | Application Programming Interface |
| AWS | Amazon Web Services |
| CDN | Content Delivery Network |
| CI/CD | Continuous Integration / Continuous Deployment |
| CLI | Command Line Interface |
| CORS | Cross-Origin Resource Sharing |
| CPU | Central Processing Unit |
| CSP | Content Security Policy |
| DDoS | Distributed Denial of Service |
| DNS | Domain Name System |
| E2E | End-to-End |
| FFT | Fast Fourier Transform |
| GPU | Graphics Processing Unit |
| HTTPS | Hypertext Transfer Protocol Secure |
| IDE | Integrated Development Environment |
| K8s | Kubernetes |
| ML | Machine Learning |
| MVC | Model-View-Controller |
| MTBF | Mean Time Between Failures |
| MTTR | Mean Time To Recovery |
| OWASP | Open Web Application Security Project |
| PCI DSS | Payment Card Industry Data Security Standard |
| PE | Portable Executable (Windows binary format) |
| PoC | Proof of Concept |
| RBAC | Role-Based Access Control |
| RE | Reverse Engineering |
| REST | Representational State Transfer |
| SaaS | Software as a Service |
| SDK | Software Development Kit |
| SLA | Service Level Agreement |
| SOC 2 | Service Organization Control Type 2 |
| SQL | Structured Query Language |
| SRE | Site Reliability Engineering |
| SSL/TLS | Secure Sockets Layer / Transport Layer Security |
| SSO | Single Sign-On |
| TTL | Time To Live |
| UI/UX | User Interface / User Experience |
| UUID | Universally Unique Identifier |
| VPC | Virtual Private Cloud |
| WebSocket | Full-duplex communication protocol |
| YAML | YAML Ain't Markup Language |

## Platform-Specific Terms

| Term | Definition |
|------|------------|
| **Catalytic Engine** | The GPU computation service handling PyTorch/CuPy/Numba operations |
| **GhidraGo** | Custom Ghidra wrapper providing REST APIs and type caching |
| **SaaS API** | The main API service handling authentication, billing, and user management |

## External Services

| Service | Purpose | Documentation |
|---------|---------|---------------|
| **Ghidra** | NSA's open-source reverse engineering tool | [ghidra-sre.org](https://ghidra-sre.org/) |
| **Grafana** | Metrics visualization and dashboards | [grafana.com/docs](https://grafana.com/docs/) |
| **HashiCorp Vault** | Secrets management and encryption | [vaultproject.io](https://www.vaultproject.io/) |
| **Prometheus** | Time-series metrics and alerting | [prometheus.io/docs](https://prometheus.io/docs/) |
| **Redis** | In-memory data store | [redis.io/docs](https://redis.io/docs/) |
| **SendGrid** | Email delivery service | [docs.sendgrid.com](https://docs.sendgrid.com/) |
| **Stripe** | Payment processing | [stripe.com/docs](https://stripe.com/docs) |

## Version Information

| Component | Version | Notes |
|-----------|---------|-------|
| Python | 3.11+ | Required for performance features |
| PostgreSQL | 15+ | Required for RLS improvements |
| Redis | 7+ | Required for RESP3 protocol |
| CUDA | 12.1+ | Required for latest GPU features |
| Ghidra | 11.x | Latest stable release |
| Kubernetes | 1.28+ | Required for HPA v2 |

---
**Last Updated**: 2024-10-15
