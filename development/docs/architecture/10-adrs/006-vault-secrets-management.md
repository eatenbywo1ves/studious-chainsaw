# ADR-006: HashiCorp Vault for Secrets Management

**Status**: Accepted
**Date**: 2024-09-28
**Deciders**: Security Team, Architecture Team
**Technical Story**: Enterprise secrets management with rotation

---

## Context

The platform handles sensitive credentials (API keys, database passwords, JWT keys) that must be securely stored, rotated, and audited.

### Problem Statement

Implement secrets management that provides secure storage, automatic rotation, and comprehensive audit logging.

---

## Decision

**Use HashiCorp Vault with AppRole authentication for centralized secrets management.**

### Implementation

```python
import hvac

# AppRole authentication
client = hvac.Client(url='https://vault:8200')
client.auth.approle.login(role_id=ROLE_ID, secret_id=SECRET_ID)

# Retrieve secrets
db_creds = client.secrets.kv.read_secret_version(path='database')
jwt_key = client.secrets.kv.read_secret_version(path='jwt/private_key')
```

### Secrets Stored

| Path | Contents | Rotation |
|------|----------|----------|
| `secret/jwt/*` | JWT signing keys | Quarterly |
| `secret/database` | PostgreSQL credentials | Monthly |
| `secret/stripe` | Stripe API keys | On-demand |
| `secret/sendgrid` | SendGrid API keys | On-demand |

---

## Consequences

### Positive
- ✅ **Centralized**: Single source of truth for all secrets
- ✅ **Audit Trail**: All access logged
- ✅ **Rotation**: Automatic credential rotation
- ✅ **Access Control**: Fine-grained policies
- ✅ **Encryption**: At-rest and in-transit

### Negative
- ❌ **Complexity**: Additional infrastructure component
- ❌ **Availability**: Vault unavailability blocks app startup
- ❌ **Learning Curve**: Team needs Vault training

---

## Alternatives Considered

### AWS Secrets Manager
**Why Rejected**: AWS lock-in, less flexible policies

### Environment Variables
**Why Rejected**: No rotation, no audit, insecure at scale

### Kubernetes Secrets
**Why Rejected**: Not encrypted at rest by default, no rotation

---

## Related Decisions

- [ADR-003: JWT RS256](003-jwt-rs256-asymmetric.md)

---

**Last Updated**: 2024-10-15
