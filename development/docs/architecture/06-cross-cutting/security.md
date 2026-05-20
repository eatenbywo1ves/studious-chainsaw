# Cross-Cutting Concerns: Security

## Overview
Security is implemented as a cross-cutting concern across all platform layers using the D3FEND framework.

## Authentication Architecture

### JWT Token Flow
```
┌────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client   │────►│  Auth API   │────►│ JWT Manager │
│            │     │             │     │             │
│            │     │ /auth/login │     │ RS256 sign  │
└────────────┘     └─────────────┘     └─────────────┘
                          │
                          ▼
┌────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client   │◄────│ Token Pair  │     │   Redis     │
│            │     │             │     │  Blacklist  │
│            │     │access+refresh│     │             │
└────────────┘     └─────────────┘     └─────────────┘
```

### Token Structure
```json
{
  "header": {
    "alg": "RS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_id (UUID)",
    "tenant_id": "tenant_id (UUID)",
    "type": "access|refresh",
    "iat": 1697356800,
    "exp": 1697358600,
    "iss": "catalytic-platform"
  }
}
```

### Password Security
- **Algorithm**: bcrypt with cost factor 12
- **Minimum Length**: 12 characters
- **Requirements**: Upper, lower, digit, special character
- **Common Password Check**: 10,000+ entry blocklist
- **Salt**: Unique per password (bcrypt built-in)

## Authorization Architecture

### Role-Based Access Control
```
┌─────────────────────────────────────────────────────────────┐
│                        RBAC Model                            │
│                                                              │
│  ┌─────────┐     ┌──────────┐     ┌──────────────────────┐ │
│  │  User   │────►│   Role   │────►│    Permissions       │ │
│  └─────────┘     └──────────┘     └──────────────────────┘ │
│                                                              │
│  Roles:                                                      │
│  • admin: Full access                                        │
│  • user: Standard access                                     │
│  • readonly: View only                                       │
│  • billing_admin: Subscription management                    │
└─────────────────────────────────────────────────────────────┘
```

### Row-Level Security
```sql
-- All tenant-scoped tables have this policy
CREATE POLICY tenant_isolation ON table_name
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
```

## Network Security

### TLS Configuration
- **Protocol**: TLS 1.3 only
- **Ciphers**: AEAD ciphers (AES-GCM, ChaCha20-Poly1305)
- **Certificate**: Let's Encrypt with auto-renewal
- **HSTS**: Enabled with 1-year max-age

### Rate Limiting
```
┌─────────────────────────────────────────────────────────────┐
│                    Rate Limiting Strategy                    │
│                                                              │
│  Endpoint Type        │ Limit        │ Window               │
│  ─────────────────────┼──────────────┼────────────────────  │
│  Authentication       │ 5 requests   │ 1 minute             │
│  API (authenticated)  │ 1000 requests│ 1 hour               │
│  Compute jobs         │ 100 jobs     │ 1 hour               │
│  Webhook receivers    │ 100 requests │ 1 minute             │
└─────────────────────────────────────────────────────────────┘
```

### Network Policies (Kubernetes)
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-policy
spec:
  podSelector:
    matchLabels:
      app: saas-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: nginx-ingress
    ports:
    - port: 8000
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgres
    - podSelector:
        matchLabels:
          app: redis
```

## Data Security

### Encryption at Rest
| Data Type | Encryption | Key Management |
|-----------|------------|----------------|
| Database | AES-256 (storage) | Cloud KMS |
| Redis AOF | Encrypted volume | Cloud KMS |
| File storage | AES-256 | Vault transit |
| Backups | AES-256 | Vault transit |

### Encryption in Transit
- All internal traffic over TLS
- Service mesh mTLS (future)
- VPN for management access

### Secret Management
```
┌─────────────────────────────────────────────────────────────┐
│                    Vault Integration                         │
│                                                              │
│  Secret Type          │ Path                │ TTL            │
│  ─────────────────────┼─────────────────────┼──────────────  │
│  Database credentials │ database/creds/app  │ 1 hour         │
│  API keys             │ secret/api-keys/*   │ Static         │
│  JWT signing key      │ secret/jwt/private  │ Static         │
│  Stripe secret        │ secret/stripe/*     │ Static         │
└─────────────────────────────────────────────────────────────┘
```

## Security Monitoring

### Audit Logging
```json
{
  "timestamp": "2024-10-15T10:30:00Z",
  "event_type": "auth.login.success",
  "user_id": "uuid",
  "tenant_id": "uuid",
  "ip_address": "x.x.x.x",
  "user_agent": "...",
  "request_id": "req_abc123"
}
```

### Security Alerts
| Alert | Condition | Action |
|-------|-----------|--------|
| Brute force | 10+ failed logins/min | Block IP |
| RLS violation | Any cross-tenant access | Page security |
| Suspicious activity | Unusual API patterns | Alert + review |
| Secret access | Vault unusual access | Alert + audit |

## D3FEND Coverage Matrix

| D3FEND ID | Technique | Implementation Status |
|-----------|-----------|----------------------|
| D3-SPP | Strong Password Policy | ✅ Implemented |
| D3-AL | Account Locking | ✅ Implemented |
| D3-ACA | Access Control Analysis | ✅ Implemented |
| D3-NTA | Network Traffic Analysis | ✅ Implemented |
| D3-CA | Certificate Analysis | ✅ Implemented |
| D3-EAL | Execution Allow Listing | ✅ Implemented |
| D3-FE | File Encryption | ✅ Implemented |
| D3-SE | Session Expiration | ✅ Implemented |
| D3-SBV | Service Binary Verification | ✅ Implemented |
| D3-SDM | Software Dependency Management | ✅ Implemented |
| D3-SDN | Software-Defined Networking | ✅ Implemented |
| D3-LA | Log Analysis | ✅ Implemented |

---
**Last Updated**: 2024-10-15
