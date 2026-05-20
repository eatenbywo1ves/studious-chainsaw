# ADR-010: D3FEND Security Framework

**Status**: Accepted | **Date**: 2024-10-08 | **Deciders**: Security Team

## Decision
Adopt **MITRE D3FEND** framework for systematic defensive architecture.

## Implemented Techniques (12)

| D3FEND ID | Technique | Implementation |
|-----------|-----------|----------------|
| D3-SPP | Strong Password Policy | 12+ chars, bcrypt |
| D3-AL | Account Locking | 5 failures → 15min lock |
| D3-ACA | Access Control Analysis | PostgreSQL RLS |
| D3-NTA | Network Traffic Analysis | Rate limiting |
| D3-CA | Certificate Analysis | TLS 1.3, cert pinning |
| D3-EAL | Execution Allow Listing | Container capabilities |
| D3-FE | File Encryption | Vault, AES-256 |
| D3-SE | Session Expiration | JWT 30min TTL |
| D3-SBV | Service Binary Verification | Image signing |
| D3-SDM | Software Dependency Management | Vulnerability scanning |
| D3-SDN | Software-Defined Networking | K8s network policies |
| D3-LA | Log Analysis | Structured logging |

## Benefits
- ✅ Systematic security (not ad-hoc)
- ✅ Compliance-friendly documentation
- ✅ Clear gaps identification
- ✅ Industry-standard framework

---
**Last Updated**: 2024-10-15
