# ADR-003: JWT RS256 Asymmetric Signing

**Status**: Accepted
**Date**: 2024-09-20
**Deciders**: Architecture Team, Security Lead
**Technical Story**: Implement secure, scalable authentication

---

## Context

The platform needs stateless authentication that scales horizontally without shared session storage for auth validation.

### Problem Statement

Choose a JWT signing algorithm that provides strong security, supports key rotation, and enables distributed validation.

### Driving Forces

- **Security**: Must be resistant to key compromise
- **Scalability**: Multiple services must validate tokens independently
- **Key Rotation**: Must support rotation without downtime
- **Performance**: Validation must be fast (<10ms)

### Constraints

- Must work with HashiCorp Vault for key management
- Must support token revocation (logout)
- Must be compatible with standard JWT libraries

---

## Decision

**We will use RS256 (RSA with SHA-256) asymmetric signing for JWT tokens.**

### Implementation

1. **Private Key**: Stored in Vault, used only by auth service to sign tokens
2. **Public Key**: Distributed to all services for token validation
3. **Key Rotation**: Quarterly rotation with overlap period

### Key Details

```python
# Token generation (auth service only)
import jwt

token = jwt.encode(
    payload={
        'sub': user_id,
        'org_id': org_id,
        'aud': 'catalytic-api',
        'iss': 'catalytic-auth',
        'exp': datetime.utcnow() + timedelta(minutes=30),
        'jti': str(uuid4())  # For revocation
    },
    key=private_key,
    algorithm='RS256'
)

# Token validation (any service)
payload = jwt.decode(
    token,
    key=public_key,
    algorithms=['RS256'],
    audience='catalytic-api',
    issuer='catalytic-auth'
)
```

---

## Consequences

### Positive (Benefits)

- ✅ **Key Isolation**: Private key never leaves auth service
- ✅ **Distributed Validation**: Any service can validate with public key
- ✅ **Key Rotation**: Can rotate without coordinating all services
- ✅ **Industry Standard**: Well-understood, audited algorithm
- ✅ **Vault Compatible**: Easy to store and rotate in Vault

### Negative (Trade-offs)

- ❌ **Token Size**: ~3x larger than HS256 (2KB vs 600B)
- ❌ **CPU Cost**: Signing is slower than HS256 (but validation is fast)
- ❌ **Key Management**: Requires infrastructure for key distribution
- ❌ **Complexity**: More moving parts than symmetric signing

### Neutral

- ℹ️ Public key can be cached (long TTL)
- ℹ️ Requires Redis for token blacklist (logout)

---

## Alternatives Considered

### Alternative 1: HS256 (Symmetric)

**Description**: Use shared secret for both signing and validation.

**Pros**:
- Simpler (one key)
- Smaller tokens
- Faster signing

**Cons**:
- Secret must be shared with all services (larger blast radius)
- Key rotation requires coordinated deployment
- Compromised key = full token forgery

**Why Rejected**: Secret sharing is a security risk. Key rotation is operationally complex.

### Alternative 2: ES256 (ECDSA)

**Description**: Use elliptic curve cryptography.

**Pros**:
- Smaller keys than RSA
- Smaller signatures
- Fast validation

**Cons**:
- Less mature library support
- Some edge cases in implementations
- Vault ES256 support less mature

**Why Rejected**: RS256 has better ecosystem support and is more battle-tested.

### Alternative 3: Session-Based Auth

**Description**: Traditional server-side sessions with session IDs.

**Pros**:
- Immediate revocation (delete session)
- No token size concerns
- Simple mental model

**Cons**:
- Requires shared session store (Redis)
- All requests hit session store
- Horizontal scaling more complex

**Why Rejected**: JWT allows stateless validation, better for microservices.

---

## Token Revocation Strategy

Since JWTs are stateless, we implement revocation via blacklist:

```python
# On logout: Add token JTI to blacklist
redis.setex(f"blacklist:{jti}", ttl=token_remaining_lifetime, value="1")

# On validation: Check blacklist
if redis.exists(f"blacklist:{jti}"):
    raise TokenRevoked()
```

---

## Key Rotation Procedure

1. **Generate new key pair** in Vault
2. **Deploy public key** to all services (allow both old and new)
3. **Wait 30 minutes** (token max lifetime)
4. **Switch signing** to new private key
5. **Wait 30 more minutes**
6. **Remove old public key** from validation

---

## Related Decisions

- [ADR-002: PostgreSQL RLS](002-postgresql-rls-multitenancy.md)
- [ADR-006: Vault Secrets Management](006-vault-secrets-management.md)

---

## References

- [RFC 7519: JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [Auth0: RS256 vs HS256](https://auth0.com/blog/rs256-vs-hs256-whats-the-difference/)
- [JWT Best Practices](https://curity.io/resources/learn/jwt-best-practices/)

---

**Last Updated**: 2024-10-15
**Review Date**: 2025-01-15
